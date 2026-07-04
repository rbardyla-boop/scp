// Trial 1c — Deterministic Simulator Send Path: Runtime Vitality Oracle Wiring
//
// Permitted claim (after proof):
//   In the SCP simulator runtime path, the designated simulator send operation
//   automatically consults bilateral vitality evidence, applies explicit
//   scenario-provided vitality controls under one deterministic evaluation clock,
//   and enforces the resulting computed vitality state before creating a new
//   encrypted burst.
//
// All wiring-claim tests enter through FlashSession::open_and_send_sim().
// No wiring-claim test constructs RecipientState directly.
// Every consent_hash is derived from a real bilateral tunnel consent registration.
//
// Transition boundaries under standard controls (i = 1.0, r = 1.0, p = 0.0):
//   Active → Warm:       t = 578_388 (Active) / 578_389 (Warm)
//   Warm → Dormant:      t = 1_796_637 (Warm)  / 1_796_638 (Dormant)
//   Dormant → Suspended: t = 4_171_663 (Dormant) / 4_171_664 (Suspended)
//
// Explicit non-claims:
//   - production CLI runtime vitality wiring
//   - production sources for i, r, or p
//   - production reaffirmation protocol
//   - receive-side vitality gating
//   - relay mailbox delivery or routing privacy policy
//   - LAN, desktop, or hardware readiness

use scp_cryptography::keys::KeyPair;
use scp_cryptography::x25519_generate_keypair;
use scp_ledger_substrate::{HandshakeEphemeral, SubstrateLedger, TunnelConsent, tunnel_consent_hash};
use scp_relay_cache::WarmCache;
use scp_relay_perturbation::PerturbationEngine;
use scp_transport::corridor;
use scp_transport::flash::{FlashSession, TransportError};
use scp_vitality::{SimVitalityContextError, SimVitalityEvaluationContext, VitalityEvidenceStore, VitalityState};
use scp_wire_format::signing::handshake_sig_message;
use std::time::Duration;

// ── Test helpers ───────────────────────────────────────────────────────────────

/// Register bilateral tunnel consent between two keypairs and return the
/// canonical consent hash. Both parties sign over the hash as required by
/// the ledger's signature verification.
fn register_bilateral_consent(ledger: &SubstrateLedger, kp_a: &KeyPair, kp_b: &KeyPair) -> [u8; 32] {
    let ch = tunnel_consent_hash(&kp_a.public, &kp_b.public);
    let consent = TunnelConsent {
        party_a: kp_a.public,
        party_b: kp_b.public,
        sig_a: kp_a.sign(&ch).to_vec(),
        sig_b: kp_b.sign(&ch).to_vec(),
    };
    ledger.register_tunnel(consent).expect("bilateral tunnel registration must succeed");
    ch
}

/// Publish a fresh X25519 handshake ephemeral for `ops_kp` valid at `sim_now`.
///
/// Sets `published_at = sim_now` and `expires_at = sim_now + 3_600` so the
/// ledger's retrieval filter (`expires_at > now`) passes when queried at `sim_now`.
/// Returns the private ephemeral key for use with `corridor::receive()`.
fn publish_ephemeral_at(ledger: &SubstrateLedger, ops_kp: &KeyPair, sim_now: u64) -> [u8; 32] {
    let (eph_secret, eph_pub) = x25519_generate_keypair();
    let expires_at = sim_now + 3_600;
    let sig: [u8; 64] = ops_kp.sign(&handshake_sig_message(&eph_pub, expires_at));
    let eph = HandshakeEphemeral {
        pub_key:      eph_pub,
        sig:          sig.to_vec(),
        published_at: sim_now,
        expires_at,
    };
    ledger
        .publish_handshake_ephemeral(&ops_kp.public, eph)
        .expect("ephemeral publish must succeed");
    eph_secret
}

/// Build a standard simulator context with default acceptance-test controls
/// (i = 1.0, r = 1.0, p = 0.0). Panics if the hash or now are pathological
/// (they never are in these tests).
fn std_ctx(consent_hash: [u8; 32], now: u64) -> SimVitalityEvaluationContext {
    SimVitalityEvaluationContext::new(consent_hash, now, 1.0, 1.0, 0.0)
        .expect("standard controls must be valid")
}

fn warm_cache() -> WarmCache { WarmCache::new(Duration::from_secs(600)) }
fn passthrough() -> PerturbationEngine { PerturbationEngine::passthrough() }

// ── T1: Fresh initialized bilateral relationship computes Active and send succeeds ──

#[tokio::test]
async fn runtime_active_relationship_permits_send() {
    let ledger = SubstrateLedger::new();
    let alice  = KeyPair::generate();
    let bob    = KeyPair::generate();
    let ch = register_bilateral_consent(&ledger, &alice, &bob);

    let mut store = VitalityEvidenceStore::new();
    let t0 = 0_u64;
    store.initialize_at(ch, t0);
    // Publish Bob's ephemeral valid at t0.
    publish_ephemeral_at(&ledger, &bob, t0);

    let ctx = std_ctx(ch, t0);
    let result = FlashSession::open_and_send_sim(
        &ledger, &store, &ctx, &bob.public, b"t1-payload", &warm_cache(), &passthrough(),
    )
    .await;

    assert!(result.is_ok(), "Active relationship at t0 must permit send");
}

// ── T2: Relationship past Suspended threshold blocks send with VitalityInsufficient ──

#[tokio::test]
async fn runtime_suspended_relationship_blocks_send() {
    let ledger = SubstrateLedger::new();
    let alice  = KeyPair::generate();
    let bob    = KeyPair::generate();
    let ch = register_bilateral_consent(&ledger, &alice, &bob);

    let mut store = VitalityEvidenceStore::new();
    store.initialize_at(ch, 0);

    let t_suspended = 4_171_664_u64;
    // Publish fresh ephemeral at t_suspended so vitality is the only failure cause.
    publish_ephemeral_at(&ledger, &bob, t_suspended);

    let ctx = std_ctx(ch, t_suspended);
    let result = FlashSession::open_and_send_sim(
        &ledger, &store, &ctx, &bob.public, b"t2-payload", &warm_cache(), &passthrough(),
    )
    .await;

    assert!(
        matches!(result, Err(TransportError::VitalityInsufficient(VitalityState::Suspended))),
        "past Suspended threshold must produce VitalityInsufficient(Suspended)"
    );
}

// ── T3: Explicit reaffirmation restores relationship to Active and send succeeds ──

#[tokio::test]
async fn runtime_reaffirmation_restores_send() {
    let ledger = SubstrateLedger::new();
    let alice  = KeyPair::generate();
    let bob    = KeyPair::generate();
    let ch = register_bilateral_consent(&ledger, &alice, &bob);

    let mut store = VitalityEvidenceStore::new();
    store.initialize_at(ch, 0);

    let t_suspended = 4_171_664_u64;
    // Verify Suspended precondition.
    assert_eq!(
        store.compute_state(ch, t_suspended, 1.0, 1.0, 0.0),
        VitalityState::Suspended,
        "precondition: must be Suspended before reaffirmation"
    );

    // Reaffirm and publish a fresh ephemeral at the reaffirmation timestamp.
    store.record_reaffirmation(ch, t_suspended);
    publish_ephemeral_at(&ledger, &bob, t_suspended);

    let ctx = std_ctx(ch, t_suspended);
    let result = FlashSession::open_and_send_sim(
        &ledger, &store, &ctx, &bob.public, b"t3-payload", &warm_cache(), &passthrough(),
    )
    .await;

    assert!(result.is_ok(), "Active state after reaffirmation must permit send");
}

// ── T4: Missing vitality evidence fails closed during simulator runtime send ──

#[tokio::test]
async fn runtime_missing_evidence_fails_closed() {
    let ledger = SubstrateLedger::new();
    let alice  = KeyPair::generate();
    let bob    = KeyPair::generate();
    // Register consent so hash is real, but never initialize evidence.
    let ch = register_bilateral_consent(&ledger, &alice, &bob);
    publish_ephemeral_at(&ledger, &bob, 0);

    let store = VitalityEvidenceStore::new(); // no evidence initialized
    let ctx = std_ctx(ch, 0);
    let result = FlashSession::open_and_send_sim(
        &ledger, &store, &ctx, &bob.public, b"t4-payload", &warm_cache(), &passthrough(),
    )
    .await;

    assert!(
        matches!(result, Err(TransportError::VitalityInsufficient(VitalityState::Suspended))),
        "missing evidence must fail closed: VitalityInsufficient(Suspended)"
    );
}

// ── T5: A↔B suspended, A↔C active — sends are relationship-isolated ──

#[tokio::test]
async fn runtime_relationship_isolation_ab_vs_ac() {
    let ledger = SubstrateLedger::new();
    let alice = KeyPair::generate();
    let bob   = KeyPair::generate();
    let carol = KeyPair::generate();

    let ch_ab = register_bilateral_consent(&ledger, &alice, &bob);
    let ch_ac = register_bilateral_consent(&ledger, &alice, &carol);

    // Sanity: hashes must differ.
    assert_ne!(ch_ab, ch_ac, "AB and AC consent hashes must be distinct");

    let mut store = VitalityEvidenceStore::new();
    store.initialize_at(ch_ab, 0);
    store.initialize_at(ch_ac, 0);

    let t_eval = 4_171_664_u64;
    // Reaffirm AC only — AB becomes Suspended.
    store.record_reaffirmation(ch_ac, t_eval);

    // Publish fresh ephemerals at t_eval for both recipients.
    publish_ephemeral_at(&ledger, &bob,   t_eval);
    publish_ephemeral_at(&ledger, &carol, t_eval);

    let ctx_ab = std_ctx(ch_ab, t_eval);
    let ctx_ac = std_ctx(ch_ac, t_eval);

    let result_ab = FlashSession::open_and_send_sim(
        &ledger, &store, &ctx_ab, &bob.public,   b"t5-ab", &warm_cache(), &passthrough(),
    ).await;
    let result_ac = FlashSession::open_and_send_sim(
        &ledger, &store, &ctx_ac, &carol.public, b"t5-ac", &warm_cache(), &passthrough(),
    ).await;

    assert!(
        matches!(result_ab, Err(TransportError::VitalityInsufficient(VitalityState::Suspended))),
        "AB: must be blocked — Suspended"
    );
    assert!(result_ac.is_ok(), "AC: must be permitted — Active after reaffirmation");
}

// ── T6: Successful simulator send does not implicitly reaffirm evidence ──

#[tokio::test]
async fn runtime_send_does_not_refresh_evidence() {
    let ledger = SubstrateLedger::new();
    let alice  = KeyPair::generate();
    let bob    = KeyPair::generate();
    let ch = register_bilateral_consent(&ledger, &alice, &bob);

    let mut store = VitalityEvidenceStore::new();
    let t0 = 0_u64;
    store.initialize_at(ch, t0);
    publish_ephemeral_at(&ledger, &bob, t0);

    // Permitted send at t0.
    let ctx_t0 = std_ctx(ch, t0);
    FlashSession::open_and_send_sim(
        &ledger, &store, &ctx_t0, &bob.public, b"t6-send", &warm_cache(), &passthrough(),
    )
    .await
    .expect("Active at t0 must permit send");

    // Re-evaluate at Active→Warm boundary: state must be Warm, not Active.
    // If the send had refreshed evidence the timestamp would be t0 and state
    // would still be Active at t0 + 578_389.
    let t_check = t0 + 578_389;
    let state_after = store.compute_state(ch, t_check, 1.0, 1.0, 0.0);
    assert_eq!(
        state_after,
        VitalityState::Warm,
        "vitality must decay from original t0 — send must not have refreshed the evidence timestamp"
    );
}

// ── T7: retrieve_state_sim consults evidence; retrieve_state returns hardcoded Active ──

#[tokio::test]
async fn retrieve_state_sim_bypasses_hardcoded_active() {
    let ledger = SubstrateLedger::new();
    let alice  = KeyPair::generate();
    let bob    = KeyPair::generate();
    // Register consent but intentionally do not initialize evidence.
    let ch = register_bilateral_consent(&ledger, &alice, &bob);
    publish_ephemeral_at(&ledger, &bob, 0);

    let store = VitalityEvidenceStore::new(); // no evidence
    let ctx   = std_ctx(ch, 0);

    // Production path returns hardcoded Active regardless of evidence.
    let prod_state = FlashSession::retrieve_state(&ledger, &bob.public)
        .await
        .expect("retrieve_state must not error");
    assert_eq!(
        prod_state.vitality,
        VitalityState::Active,
        "retrieve_state must return hardcoded Active (Phase 9 deferral intact)"
    );

    // Simulator path consults evidence and fails closed to Suspended.
    let sim_state = FlashSession::retrieve_state_sim(&ledger, &bob.public, &store, &ctx)
        .await
        .expect("retrieve_state_sim must not error");
    assert_eq!(
        sim_state.vitality,
        VitalityState::Suspended,
        "retrieve_state_sim with no evidence must return Suspended (fails closed)"
    );
}

// ── T8: corridor::receive() is not vitality-gated ─────────────────────────────

#[tokio::test]
async fn corridor_receive_unaffected_after_suspension() {
    let ledger = SubstrateLedger::new();
    let alice  = KeyPair::generate();
    let bob    = KeyPair::generate();
    let ch = register_bilateral_consent(&ledger, &alice, &bob);

    let mut store = VitalityEvidenceStore::new();
    let t0 = 0_u64;
    store.initialize_at(ch, t0);

    // Publish ephemeral at t0 and keep the private key for receive().
    let bob_eph_secret = publish_ephemeral_at(&ledger, &bob, t0);

    let ctx = std_ctx(ch, t0);
    let (_, envelope) = FlashSession::open_and_send_sim(
        &ledger, &store, &ctx, &bob.public, b"t8-secret-message", &warm_cache(), &passthrough(),
    )
    .await
    .expect("Active at t0 must permit send");

    // Relationship is now effectively Suspended (no reaffirmation recorded).
    // corridor::receive() must still decrypt the already-sent envelope.
    let plaintext = corridor::receive(&envelope, &bob_eph_secret)
        .expect("receive must succeed — receive path is not vitality-gated");
    assert_eq!(plaintext, b"t8-secret-message");
}

// ── T9: Non-default i, r, p controls shift computed state correctly ────────────
//
// At t = 1_796_638 (half-life of the exponential decay ≈ TAU * ln2):
//   Standard controls (i=1.0, r=1.0, p=0.0): V ≈ 0.500 → Dormant (is_open = true)
//   Reduced controls (i=0.3, r=0.5, p=0.0):  V ≈ 0.500 * sqrt(0.15) ≈ 0.194 → Suspended
//
// The reduced-control send must be blocked; the standard-control send must succeed.
// This proves declared controls are propagated through open_and_send_sim() and are
// not silently replaced with inactivity-test defaults.

#[tokio::test]
async fn scenario_controls_i_r_p_are_explicit() {
    let ledger = SubstrateLedger::new();
    let alice  = KeyPair::generate();
    let bob    = KeyPair::generate();
    let ch = register_bilateral_consent(&ledger, &alice, &bob);

    let mut store = VitalityEvidenceStore::new();
    store.initialize_at(ch, 0);

    let t_half_life = 1_796_638_u64;
    // Publish fresh ephemerals so ephemeral expiry is not a confound.
    publish_ephemeral_at(&ledger, &bob, t_half_life);

    // Reduced controls — formula gives V ≈ 0.194 → Suspended → blocked.
    let ctx_reduced = SimVitalityEvaluationContext::new(ch, t_half_life, 0.3, 0.5, 0.0)
        .expect("reduced controls are valid");
    let result_reduced = FlashSession::open_and_send_sim(
        &ledger, &store, &ctx_reduced, &bob.public, b"t9-reduced", &warm_cache(), &passthrough(),
    )
    .await;
    assert!(
        matches!(result_reduced, Err(TransportError::VitalityInsufficient(VitalityState::Suspended))),
        "i=0.3, r=0.5 at t_half_life must yield Suspended — formula boundary must shift"
    );

    // Standard controls — formula gives V ≈ 0.500 → Dormant → is_open = true → permitted.
    let ctx_standard = std_ctx(ch, t_half_life);
    // Publish a second ephemeral for the standard-control send.
    publish_ephemeral_at(&ledger, &bob, t_half_life);
    let result_standard = FlashSession::open_and_send_sim(
        &ledger, &store, &ctx_standard, &bob.public, b"t9-standard", &warm_cache(), &passthrough(),
    )
    .await;
    assert!(
        result_standard.is_ok(),
        "i=1.0, r=1.0 at t_half_life must yield Dormant (open) — standard controls must permit send"
    );
}

// ── T10: Invalid simulator controls are rejected at context construction ─────

#[test]
fn sim_context_rejects_invalid_controls() {
    let hash = [0u8; 32]; // arbitrary for construction tests — not used in a send

    // i below 0.0
    assert_eq!(
        SimVitalityEvaluationContext::new(hash, 0, -0.01, 1.0, 0.0).unwrap_err(),
        SimVitalityContextError::InvalidI(-0.01),
        "i below 0.0 must be rejected"
    );
    // i above 1.0
    assert_eq!(
        SimVitalityEvaluationContext::new(hash, 0, 1.01, 1.0, 0.0).unwrap_err(),
        SimVitalityContextError::InvalidI(1.01),
        "i above 1.0 must be rejected"
    );
    // r is NaN
    let nan = f64::NAN;
    assert!(
        matches!(
            SimVitalityEvaluationContext::new(hash, 0, 1.0, nan, 0.0).unwrap_err(),
            SimVitalityContextError::InvalidR(_)
        ),
        "NaN for r must be rejected"
    );
    // p is +infinity
    let inf = f64::INFINITY;
    assert!(
        matches!(
            SimVitalityEvaluationContext::new(hash, 0, 1.0, 1.0, inf).unwrap_err(),
            SimVitalityContextError::InvalidP(_)
        ),
        "positive infinity for p must be rejected"
    );
    // p is -infinity
    let neg_inf = f64::NEG_INFINITY;
    assert!(
        matches!(
            SimVitalityEvaluationContext::new(hash, 0, 1.0, 1.0, neg_inf).unwrap_err(),
            SimVitalityContextError::InvalidP(_)
        ),
        "negative infinity for p must be rejected"
    );
    // All valid — must construct successfully
    assert!(
        SimVitalityEvaluationContext::new(hash, 0, 0.0, 0.0, 0.0).is_ok(),
        "boundary [0.0, 0.0, 0.0] must be valid"
    );
    assert!(
        SimVitalityEvaluationContext::new(hash, 0, 1.0, 1.0, 1.0).is_ok(),
        "boundary [1.0, 1.0, 1.0] must be valid"
    );
}

// ── T11: Simulated time controls ephemeral expiry independently of wall-clock ──
//
// An ephemeral with expires_at = t_sim must be rejected at ctx.now = t_sim + 1,
// but accepted at ctx.now = t_sim - 1. This proves that ctx.now governs expiry
// inside open_and_send_sim, not SystemTime::now().

#[tokio::test]
async fn simulated_time_controls_ephemeral_expiry() {
    let ledger  = SubstrateLedger::new();
    let alice   = KeyPair::generate();
    let bob     = KeyPair::generate();
    let ch = register_bilateral_consent(&ledger, &alice, &bob);

    let mut store = VitalityEvidenceStore::new();
    // Initialize evidence far in the past so vitality is Active at any reasonable now.
    // We want ephemeral expiry to be the tested boundary, not vitality.
    let t_sim = 100_000_u64;
    store.initialize_at(ch, t_sim);

    // Publish ephemeral with expires_at = t_sim + 3_600.
    // The ledger's expiry is t_sim + 3600.
    let _secret = publish_ephemeral_at(&ledger, &bob, t_sim);

    let eph_expires_at = t_sim + 3_600;

    // ctx.now = eph_expires_at - 1: ephemeral is still valid → Active → send succeeds.
    let ctx_before_expiry = std_ctx(ch, eph_expires_at - 1);
    // Need a fresh ephemeral still valid at eph_expires_at - 1.
    // The published one has expires_at = t_sim + 3600 = eph_expires_at, and
    // get_handshake_ephemeral filters on expires_at > now, so at now = eph_expires_at - 1
    // it's still valid.
    let result_before = FlashSession::open_and_send_sim(
        &ledger, &store, &ctx_before_expiry, &bob.public,
        b"t11-before", &warm_cache(), &passthrough(),
    )
    .await;
    assert!(
        result_before.is_ok(),
        "ctx.now just before ephemeral expiry must succeed"
    );

    // ctx.now = eph_expires_at: ledger returns None (expires_at > now fails when equal),
    // so retrieve_state_sim returns handshake_ephemeral = None → v1 fallback → open_and_send_sim
    // returns V1PathNotReceivable (since sim path requires v2).
    let ctx_at_expiry = std_ctx(ch, eph_expires_at);
    let result_at = FlashSession::open_and_send_sim(
        &ledger, &store, &ctx_at_expiry, &bob.public,
        b"t11-at", &warm_cache(), &passthrough(),
    )
    .await;
    assert!(
        matches!(result_at, Err(TransportError::V1PathNotReceivable)),
        "ctx.now at exact ephemeral expiry must produce V1PathNotReceivable \
         (no valid ephemeral → v1 fallback → sim requires v2)"
    );
}

// ── T12 (formerly T11 in plan): Production open_and_send path is unaffected ───
//
// Proves that the open_and_send_core refactoring (to delegate through
// open_and_send_core_at) did not alter production-path behavior.

#[tokio::test]
async fn production_send_path_unaffected() {
    use scp_cryptography::keys::KeyPair as CryptoKeyPair;
    use scp_transport::flash::{PublishedHandshakeKey, RecipientState};
    use std::time::{SystemTime, UNIX_EPOCH};

    let ops_kp = CryptoKeyPair::generate();
    let (_, eph_pub) = x25519_generate_keypair();
    let expires_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 3_600;
    let sig: [u8; 64] = ops_kp.sign(&handshake_sig_message(&eph_pub, expires_at));

    // Construct RecipientState directly — production path does not consult evidence.
    let state = RecipientState {
        ops_pub:             ops_kp.public,
        vitality:            VitalityState::Active,
        routing_hints:       vec![],
        handshake_ephemeral: Some(PublishedHandshakeKey { pub_key: eph_pub, sig, expires_at }),
    };

    let result = FlashSession::open_and_send(state, b"t12-production", &warm_cache(), &passthrough())
        .await;
    assert!(
        result.is_ok(),
        "production open_and_send must still work after open_and_send_core refactoring"
    );
}
