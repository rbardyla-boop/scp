// Trial 3 — Provider-Failure Telemetry and Vitality Authorization Orthogonality Proof
//
// Permitted claim (after verification):
//   Under deterministic concurrent simulation, provider-failure telemetry can change
//   observably while bilateral vitality evidence and vitality-controlled send authorization
//   remain unchanged unless the scenario explicitly changes vitality evidence or vitality
//   inputs.
//
// This proves that encrypted vitality-governed communication and provider-failure observation
// coexist in the simulator without secretly becoming one control system.
//
// Explicit non-claims:
//   - provider telemetry should influence vitality
//   - kappa, liveness_weighted_kappa, or response/selection totals should populate
//     SimVitalityEvaluationContext.p
//   - provider degradation should suspend a corridor
//   - telemetry should trigger send rejection
//   - telemetry should trigger automatic rotation policy
//   - TOLS κ policy integration
//   - production vitality-input measurement
//   - production reaffirmation protocol
//   - relay routing or mailbox delivery
//   - localhost, LAN, desktop, or hardware readiness
//
// Vitality transition boundaries under standard controls (i=1.0, r=1.0, p=0.0), t0=0:
//   Active → Warm:       t = 578_388 (Active) / 578_389 (Warm)
//   Warm → Dormant:      t = 1_796_637 (Warm)  / 1_796_638 (Dormant)
//   Dormant → Suspended: t = 4_171_663 (Dormant) / 4_171_664 (Suspended)
//
// Evidence-timestamp invariant proof technique:
//   After any scenario operation, assert compute_state at the two Active→Warm
//   boundary points: Active at t0+578_388, Warm at t0+578_389.
//   If the stored timestamp were altered, at least one assertion would produce a
//   different VitalityState than expected, catching any coupling.

use rand::rngs::StdRng;
use rand::SeedableRng;
use scp_cryptography::keys::KeyPair;
use scp_cryptography::x25519_generate_keypair;
use scp_ledger_substrate::{
    tunnel_consent_hash, HandshakeEphemeral, SubstrateLedger, TunnelConsent,
};
use scp_provider_pool::{EpochPhase, ProviderPool, SamplingStrategy};
use scp_relay_cache::WarmCache;
use scp_relay_perturbation::PerturbationEngine;
use scp_transport::flash::{FlashSession, TransportError};
use scp_vitality::{SimVitalityEvaluationContext, VitalityEvidenceStore, VitalityState};
use scp_wire_format::signing::handshake_sig_message;
use std::time::Duration;

// ── Helpers ───────────────────────────────────────────────────────────────────
// Redeclared locally per the test-helper boundary: may assemble deterministic
// scenarios but must not duplicate telemetry formulas, reproduce send-gating
// rules, or bypass open_and_send_sim() for send-path assertions.

fn pid(byte: u8) -> [u8; 32] {
    [byte; 32]
}

/// Deterministic RNG with fixed seed 0. Produces the same selection trace on every run.
fn seeded() -> StdRng {
    StdRng::seed_from_u64(0)
}

/// Register bilateral tunnel consent between two keypairs and return the canonical consent hash.
fn register_bilateral_consent(
    ledger: &SubstrateLedger,
    kp_a: &KeyPair,
    kp_b: &KeyPair,
) -> [u8; 32] {
    let ch = tunnel_consent_hash(&kp_a.public, &kp_b.public);
    let consent = TunnelConsent {
        party_a: kp_a.public,
        party_b: kp_b.public,
        sig_a: kp_a.sign(&ch).to_vec(),
        sig_b: kp_b.sign(&ch).to_vec(),
    };
    ledger
        .register_tunnel(consent)
        .expect("bilateral tunnel registration must succeed");
    ch
}

/// Publish a fresh X25519 handshake ephemeral for `ops_kp` valid at `sim_now`.
///
/// Sets `published_at = sim_now` and `expires_at = sim_now + 3_600` so the
/// ledger's retrieval filter (`expires_at > now`) passes when queried at `sim_now`.
fn publish_ephemeral_at(ledger: &SubstrateLedger, ops_kp: &KeyPair, sim_now: u64) -> [u8; 32] {
    let (eph_secret, eph_pub) = x25519_generate_keypair();
    let expires_at = sim_now + 3_600;
    let sig: [u8; 64] = ops_kp.sign(&handshake_sig_message(&eph_pub, expires_at));
    let eph = HandshakeEphemeral {
        pub_key: eph_pub,
        sig: sig.to_vec(),
        published_at: sim_now,
        expires_at,
    };
    ledger
        .publish_handshake_ephemeral(&ops_kp.public, eph)
        .expect("ephemeral publish must succeed");
    eph_secret
}

/// Build a standard simulator context with default acceptance-test controls (i=1.0, r=1.0, p=0.0).
fn std_ctx(consent_hash: [u8; 32], now: u64) -> SimVitalityEvaluationContext {
    SimVitalityEvaluationContext::new(consent_hash, now, 1.0, 1.0, 0.0)
        .expect("standard controls must be valid")
}

fn warm_cache() -> WarmCache {
    WarmCache::new(Duration::from_secs(600))
}
fn passthrough() -> PerturbationEngine {
    PerturbationEngine::passthrough()
}

// ── T1: Healthy telemetry with Active vitality permits send ───────────────────
//
// ProviderPool trace: 4 providers, 16 samples (→ Steady), 4 responses per provider.
//
// Healthy telemetry derivation:
//   liveness_weighted_kappa = 1 − log₂(4)/log₂(4) = 0.0  (uniform 4-provider response)
//   response_total = 16, selection_total = 16
//   recent_reported_response_ratio = Some(1.0)
//   kappa: derived from seeded selection trace via exposure_estimate()
//
// Evidence timestamp: proven exact via Active→Warm boundary check before and after send.

#[tokio::test]
async fn t1_healthy_telemetry_active_vitality_permits_send() {
    let ledger = SubstrateLedger::new();
    let alice = KeyPair::generate();
    let bob = KeyPair::generate();
    let ch = register_bilateral_consent(&ledger, &alice, &bob);

    let mut store = VitalityEvidenceStore::new();
    let t0 = 0_u64;
    store.initialize_at(ch, t0);
    let _ = publish_ephemeral_at(&ledger, &bob, t0);

    // Healthy fixed trace: 16 samples, 4 responses per provider
    let mut rng = seeded();
    let mut pool = ProviderPool::new(SamplingStrategy::RandomK(1));
    for i in 1u8..=4 {
        pool.add(pid(i), SubstrateLedger::new());
    }
    for _ in 0..16 {
        let _ = pool.sample(&mut rng);
    }
    for i in 1u8..=4 {
        for _ in 0..4 {
            pool.record_response(pid(i));
        }
    }

    // — Expected healthy telemetry snapshot —
    let snap = pool.operational_telemetry();
    assert_eq!(snap.active_n, 4);
    assert_eq!(
        snap.current_epoch_phase,
        EpochPhase::Steady,
        "16 samples with 4 active providers must reach Steady phase"
    );
    assert!(snap.survivor_surface_evaluable);
    assert!(snap.liveness_surface_evaluable);
    assert!(snap.availability_evaluable);
    // Exact: uniform 4-provider response → response_entropy = log₂(4) → lwk = 0.0
    assert_eq!(
        snap.liveness_weighted_kappa, 0.0,
        "4 equal responses across 4 providers → response entropy = log₂(4) → lwk = 0.0"
    );
    assert_eq!(snap.response_total, 16);
    assert_eq!(snap.selection_total, 16);
    assert_eq!(snap.recent_reported_response_ratio(), Some(1.0));
    // kappa: derived from exact seeded selection trace via proven exposure_estimate() API
    let est = pool.exposure_estimate();
    let expected_kappa = (1.0 - est.selection_entropy_bits / (4_f64).log2()).clamp(0.0, 1.0);
    assert!(
        (snap.kappa - expected_kappa).abs() < 1e-12,
        "kappa must match value derived from seeded selection trace"
    );

    // — Exact initial vitality evidence timestamp (proven via Active→Warm boundary) —
    assert_eq!(
        store.compute_state(ch, t0 + 578_388, 1.0, 1.0, 0.0),
        VitalityState::Active,
        "timestamp=t0: Active at t0+578_388"
    );
    assert_eq!(
        store.compute_state(ch, t0 + 578_389, 1.0, 1.0, 0.0),
        VitalityState::Warm,
        "timestamp=t0: Warm at t0+578_389 proves exact boundary"
    );

    // — send succeeds —
    let ctx = std_ctx(ch, t0);
    let result = FlashSession::open_and_send_sim(
        &ledger,
        &store,
        &ctx,
        &bob.public,
        b"t1-payload",
        &warm_cache(),
        &passthrough(),
    )
    .await;
    assert!(result.is_ok(), "Active at t0 must permit send");

    // — evidence timestamp remains unchanged after send —
    assert_eq!(
        store.compute_state(ch, t0 + 578_388, 1.0, 1.0, 0.0),
        VitalityState::Active,
        "send must not refresh evidence: still Active at t0+578_388"
    );
    assert_eq!(
        store.compute_state(ch, t0 + 578_389, 1.0, 1.0, 0.0),
        VitalityState::Warm,
        "send must not refresh evidence: still Warm at t0+578_389"
    );
}

// ── T2: Explicit provider degradation changes telemetry but not Active send authorization ──
//
// Provider-failure trace: pid(2) fails twice → dead (consecutive_failures ≥ 2).
// 4 samples → only pid(1) selected → kappa=1.0, lwk=1.0 (exact, derived from Trial 2 T2).
//
// Vitality: Active; ctx.p = 0.0; evidence timestamp unchanged.
// Send: succeeds despite degraded telemetry — no coupling exists.

#[tokio::test]
async fn t2_provider_degradation_changes_telemetry_not_send_authorization() {
    let ledger = SubstrateLedger::new();
    let alice = KeyPair::generate();
    let bob = KeyPair::generate();
    let ch = register_bilateral_consent(&ledger, &alice, &bob);

    let mut store = VitalityEvidenceStore::new();
    let t0 = 0_u64;
    store.initialize_at(ch, t0);
    let _ = publish_ephemeral_at(&ledger, &bob, t0);

    // Explicit provider-failure trace: pid(2) dead → only pid(1) in pool observations
    let mut rng = seeded();
    let mut pool = ProviderPool::new(SamplingStrategy::RandomK(1)).with_liveness(2, u64::MAX);
    pool.add(pid(1), SubstrateLedger::new());
    pool.add(pid(2), SubstrateLedger::new());
    pool.record_failure(pid(2));
    pool.record_failure(pid(2)); // consecutive_failures = 2 → dead
    for _ in 0..4 {
        let _ = pool.sample(&mut rng);
    } // pid(2) filtered → only pid(1)
    for _ in 0..4 {
        pool.record_response(pid(1));
    }

    // — Telemetry changes to exact degraded output —
    let snap = pool.operational_telemetry();
    assert_eq!(
        snap.kappa, 1.0,
        "dead pid(2) → only pid(1) selected → entropy=0 bits → kappa=1.0"
    );
    assert_eq!(
        snap.liveness_weighted_kappa, 1.0,
        "only pid(1) responded → response_entropy=0 bits → lwk=1.0"
    );
    assert_eq!(snap.selection_total, 4);
    assert_eq!(snap.response_total, 4);
    assert!(snap.survivor_surface_evaluable);
    assert!(snap.liveness_surface_evaluable);

    // — Vitality evidence timestamp unchanged —
    assert_eq!(
        store.compute_state(ch, t0 + 578_388, 1.0, 1.0, 0.0),
        VitalityState::Active,
        "pool failure trace must not alter evidence timestamp"
    );
    assert_eq!(
        store.compute_state(ch, t0 + 578_389, 1.0, 1.0, 0.0),
        VitalityState::Warm
    );

    // — ctx.p unchanged (0.0); computed vitality remains Active under fixed context —
    let ctx = std_ctx(ch, t0); // p = 0.0
    assert_eq!(
        store.compute_state(ch, t0, 1.0, 1.0, 0.0),
        VitalityState::Active,
        "computed vitality must remain Active at t0 with standard controls"
    );

    // — Send still succeeds —
    let result = FlashSession::open_and_send_sim(
        &ledger,
        &store,
        &ctx,
        &bob.public,
        b"t2-payload",
        &warm_cache(),
        &passthrough(),
    )
    .await;
    assert!(
        result.is_ok(),
        "Active vitality must permit send despite degraded provider telemetry"
    );
}

// ── T3: Silent failure changes telemetry without mutating vitality ─────────────
//
// Silent failure: pid(2) is in the active pool and may be selected by sample(),
// but record_response() is only called for pid(1).
//
// Exact lwk = 1.0 (only pid(1) in responses → response_entropy = 0 bits).
// kappa: derived from seeded selection trace via exposure_estimate().
// If pid(2) was selected (selection_entropy > 0): lwk > kappa — the distinction is explicit.
//
// Vitality evidence timestamp and ctx.p are unchanged by pool trace operations.

#[tokio::test]
async fn t3_silent_failure_changes_telemetry_not_vitality() {
    let ledger = SubstrateLedger::new();
    let alice = KeyPair::generate();
    let bob = KeyPair::generate();
    let ch = register_bilateral_consent(&ledger, &alice, &bob);

    let mut store = VitalityEvidenceStore::new();
    let t0 = 0_u64;
    store.initialize_at(ch, t0);
    let _ = publish_ephemeral_at(&ledger, &bob, t0);

    // Silent-failure trace: pid(2) selected but never responds
    let mut rng = seeded();
    let mut pool = ProviderPool::new(SamplingStrategy::RandomK(1));
    pool.add(pid(1), SubstrateLedger::new());
    pool.add(pid(2), SubstrateLedger::new()); // selected but silent
    for _ in 0..8 {
        let _ = pool.sample(&mut rng);
    }
    for _ in 0..8 {
        pool.record_response(pid(1));
    } // only pid(1) responds

    // — Exact expected telemetry distinction —
    let snap = pool.operational_telemetry();
    let est = pool.exposure_estimate();
    // lwk = 1.0: only pid(1) in responses → response_entropy = 0 bits
    assert_eq!(
        snap.liveness_weighted_kappa, 1.0,
        "only pid(1) in responses → response_entropy=0 bits → lwk=1.0"
    );
    assert!(
        snap.liveness_surface_evaluable,
        "response_total=8 > 0 AND selection_total=8 > 0 → evaluable"
    );
    assert_eq!(snap.selection_total, 8);
    assert_eq!(snap.response_total, 8);
    // kappa derived from seeded selection trace (not reimplemented — from proven exposure_estimate API)
    let expected_kappa = (1.0 - est.selection_entropy_bits / (2_f64).log2()).clamp(0.0, 1.0);
    assert!(
        (snap.kappa - expected_kappa).abs() < 1e-12,
        "kappa must match value derived from seeded selection trace"
    );
    // Silent-failure distinction: lwk ≥ kappa always; strictly > when pid(2) selected
    assert!(
        snap.liveness_weighted_kappa >= snap.kappa,
        "response entropy cannot exceed selection entropy"
    );
    if est.selection_entropy_bits > 0.0 {
        assert!(
            snap.liveness_weighted_kappa > snap.kappa,
            "pid(2) selected but silent → liveness surface rises above selection surface"
        );
    }

    // — Vitality evidence timestamp unchanged —
    assert_eq!(
        store.compute_state(ch, t0 + 578_388, 1.0, 1.0, 0.0),
        VitalityState::Active,
        "silent failure trace must not alter evidence timestamp"
    );
    assert_eq!(
        store.compute_state(ch, t0 + 578_389, 1.0, 1.0, 0.0),
        VitalityState::Warm
    );

    // — Send governed only by unchanged Active vitality context —
    let ctx = std_ctx(ch, t0); // p = 0.0 unchanged
    let result = FlashSession::open_and_send_sim(
        &ledger,
        &store,
        &ctx,
        &bob.public,
        b"t3-payload",
        &warm_cache(),
        &passthrough(),
    )
    .await;
    assert!(
        result.is_ok(),
        "Active vitality must permit send despite silent provider failure"
    );
}

// ── T4: Partial degradation remains observational only ───────────────────────
//
// Partial-degradation trace: 4 providers; pid(1) and pid(2) respond, pid(3) and pid(4) silent.
//
// Exact lwk derivation (n = 4 active):
//   response_appearances = {pid(1): 4, pid(2): 4}   total = 8
//   response_entropy = −2 × (0.5 × log₂(0.5)) = 1.0 bit
//   liveness_weighted_kappa = 1 − 1.0 / log₂(4) = 0.5
//
// No vitality evidence mutation; no change to scenario controls; Active vitality permits send.

#[tokio::test]
async fn t4_partial_degradation_remains_observational_only() {
    let ledger = SubstrateLedger::new();
    let alice = KeyPair::generate();
    let bob = KeyPair::generate();
    let ch = register_bilateral_consent(&ledger, &alice, &bob);

    let mut store = VitalityEvidenceStore::new();
    let t0 = 0_u64;
    store.initialize_at(ch, t0);
    let _ = publish_ephemeral_at(&ledger, &bob, t0);

    // Partial-degradation trace: only pid(1) and pid(2) respond
    let mut rng = seeded();
    let mut pool = ProviderPool::new(SamplingStrategy::RandomK(1));
    for i in 1u8..=4 {
        pool.add(pid(i), SubstrateLedger::new());
    }
    for _ in 0..16 {
        let _ = pool.sample(&mut rng);
    }
    for _ in 0..4 {
        pool.record_response(pid(1));
    }
    for _ in 0..4 {
        pool.record_response(pid(2));
    }
    // pid(3) and pid(4) are silent

    // — Exact intermediate telemetry output —
    let snap = pool.operational_telemetry();
    assert_eq!(snap.active_n, 4);
    assert!(snap.liveness_surface_evaluable);
    assert!(snap.availability_evaluable);
    // −2 × (4/8 × log₂(4/8)) = 1.0 bit → 1 − 1.0/log₂(4) = 0.5
    assert_eq!(
        snap.liveness_weighted_kappa, 0.5,
        "2 of 4 providers responding uniformly → response_entropy=1.0 bit → lwk=0.5"
    );
    assert_eq!(
        snap.response_total, 8,
        "4 + 4 responses; pid(3) and pid(4) are silent"
    );
    assert_eq!(snap.selection_total, 16);

    // — No vitality evidence mutation —
    assert_eq!(
        store.compute_state(ch, t0 + 578_388, 1.0, 1.0, 0.0),
        VitalityState::Active,
        "partial-degradation trace must not alter evidence timestamp"
    );
    assert_eq!(
        store.compute_state(ch, t0 + 578_389, 1.0, 1.0, 0.0),
        VitalityState::Warm
    );

    // — ctx.p unchanged (0.0); Active vitality still permits send —
    let ctx = std_ctx(ch, t0);
    let result = FlashSession::open_and_send_sim(
        &ledger,
        &store,
        &ctx,
        &bob.public,
        b"t4-payload",
        &warm_cache(),
        &passthrough(),
    )
    .await;
    assert!(
        result.is_ok(),
        "Active vitality must permit send despite partial provider degradation"
    );
}

// ── T5: Suspended vitality rejects send while telemetry remains healthy ───────
//
// ProviderPool trace: healthy (16 samples, 4 uniform responses → lwk=0.0, ratio=1.0).
// Vitality: initialized at t0=0, now = 4_171_664 → Suspended (no reaffirmation).
//
// The rejection is caused exclusively by vitality state; the provider pool is healthy.
// After the send attempt, pool telemetry is unchanged — no provider-failure event occurred.

#[tokio::test]
async fn t5_suspended_vitality_rejects_send_telemetry_remains_healthy() {
    let ledger = SubstrateLedger::new();
    let alice = KeyPair::generate();
    let bob = KeyPair::generate();
    let ch = register_bilateral_consent(&ledger, &alice, &bob);

    let mut store = VitalityEvidenceStore::new();
    store.initialize_at(ch, 0);

    let t_suspended = 4_171_664_u64;
    let _ = publish_ephemeral_at(&ledger, &bob, t_suspended);

    // Healthy provider pool trace
    let mut rng = seeded();
    let mut pool = ProviderPool::new(SamplingStrategy::RandomK(1));
    for i in 1u8..=4 {
        pool.add(pid(i), SubstrateLedger::new());
    }
    for _ in 0..16 {
        let _ = pool.sample(&mut rng);
    }
    for i in 1u8..=4 {
        for _ in 0..4 {
            pool.record_response(pid(i));
        }
    }

    // — Telemetry remains at healthy expected snapshot —
    let snap = pool.operational_telemetry();
    assert_eq!(
        snap.liveness_weighted_kappa, 0.0,
        "healthy pool: uniform 4-provider response → lwk=0.0"
    );
    assert_eq!(snap.response_total, 16);
    assert_eq!(snap.selection_total, 16);
    assert_eq!(snap.recent_reported_response_ratio(), Some(1.0));

    // — Send blocked with VitalityInsufficient(Suspended) —
    let ctx = std_ctx(ch, t_suspended);
    let result = FlashSession::open_and_send_sim(
        &ledger,
        &store,
        &ctx,
        &bob.public,
        b"t5-payload",
        &warm_cache(),
        &passthrough(),
    )
    .await;
    assert!(
        matches!(
            result,
            Err(TransportError::VitalityInsufficient(
                VitalityState::Suspended
            ))
        ),
        "Suspended vitality must block send with VitalityInsufficient(Suspended)"
    );

    // — Rejection occurred without any provider-failure telemetry event —
    let snap_after = pool.operational_telemetry();
    assert_eq!(
        snap_after.liveness_weighted_kappa, 0.0,
        "healthy pool telemetry must be unchanged after vitality-blocked send attempt"
    );
    assert_eq!(snap_after.selection_total, 16);
    assert_eq!(snap_after.response_total, 16);
}

// ── T6: Reaffirmation restores send without changing provider telemetry ───────
//
// Starting condition: Suspended vitality (initialized at t0=0, now=t_suspended) with
// a fixed healthy provider snapshot.
//
// Operation: explicit bilateral reaffirmation via VitalityEvidenceStore.record_reaffirmation().
//
// After reaffirmation at t_suspended:
//   - Provider telemetry is exactly unchanged (same pool object, no new observations).
//   - Vitality evidence timestamp advances to t_suspended (new Active→Warm boundaries).
//   - Send succeeds with the restored Active context.

#[tokio::test]
async fn t6_reaffirmation_restores_send_without_changing_provider_telemetry() {
    let ledger = SubstrateLedger::new();
    let alice = KeyPair::generate();
    let bob = KeyPair::generate();
    let ch = register_bilateral_consent(&ledger, &alice, &bob);

    let mut store = VitalityEvidenceStore::new();
    store.initialize_at(ch, 0);

    let t_suspended = 4_171_664_u64;

    // Fixed healthy provider snapshot — captured before reaffirmation
    let mut rng = seeded();
    let mut pool = ProviderPool::new(SamplingStrategy::RandomK(1));
    for i in 1u8..=4 {
        pool.add(pid(i), SubstrateLedger::new());
    }
    for _ in 0..16 {
        let _ = pool.sample(&mut rng);
    }
    for i in 1u8..=4 {
        for _ in 0..4 {
            pool.record_response(pid(i));
        }
    }

    let snap_before = pool.operational_telemetry();
    assert_eq!(
        snap_before.liveness_weighted_kappa, 0.0,
        "healthy baseline before reaffirmation"
    );
    assert_eq!(snap_before.selection_total, 16);
    assert_eq!(snap_before.response_total, 16);

    // — Perform explicit bilateral reaffirmation through the existing evidence-store API —
    store.record_reaffirmation(ch, t_suspended);

    // Publish a fresh ephemeral valid at t_suspended
    let _ = publish_ephemeral_at(&ledger, &bob, t_suspended);

    // — Construct restored Active simulator context —
    let ctx = std_ctx(ch, t_suspended);
    assert_eq!(
        store.compute_state(ch, t_suspended, 1.0, 1.0, 0.0),
        VitalityState::Active,
        "precondition after reaffirmation: Active at t_suspended"
    );

    // — Send succeeds —
    let result = FlashSession::open_and_send_sim(
        &ledger,
        &store,
        &ctx,
        &bob.public,
        b"t6-payload",
        &warm_cache(),
        &passthrough(),
    )
    .await;
    assert!(
        result.is_ok(),
        "Active state after reaffirmation must permit send"
    );

    // — Provider telemetry remains exactly unchanged from the healthy trace —
    let snap_after = pool.operational_telemetry();
    assert_eq!(
        snap_after.liveness_weighted_kappa, snap_before.liveness_weighted_kappa,
        "reaffirmation must not alter provider telemetry"
    );
    assert_eq!(snap_after.selection_total, snap_before.selection_total);
    assert_eq!(snap_after.response_total, snap_before.response_total);
    assert_eq!(snap_after.kappa, snap_before.kappa);

    // — Only the vitality evidence timestamp changed (to t_suspended) —
    // New Active→Warm boundaries now relative to t_suspended
    assert_eq!(
        store.compute_state(ch, t_suspended + 578_388, 1.0, 1.0, 0.0),
        VitalityState::Active,
        "timestamp now = t_suspended: Active at t_suspended+578_388"
    );
    assert_eq!(
        store.compute_state(ch, t_suspended + 578_389, 1.0, 1.0, 0.0),
        VitalityState::Warm,
        "timestamp now = t_suspended: Warm at t_suspended+578_389"
    );
}

// ── T7: Provider recovery changes telemetry without refreshing vitality ───────
//
// Phase 1 (degradation trace): pid(2) dead → only pid(1) → lwk=1.0.
// Phase 2 (recovery trace): record_response(pid(2)) × 4 resets consecutive_failures=0.
//   response_appearances = {pid(1): 4, pid(2): 4} → response_entropy=log₂(2)=1 bit → lwk=0.0.
//
// Throughout both phases, vitality evidence timestamp is unchanged.
// No reaffirmation occurs. Active send eligibility arises from unchanged vitality evidence.

#[tokio::test]
async fn t7_provider_recovery_changes_telemetry_not_vitality() {
    let ledger = SubstrateLedger::new();
    let alice = KeyPair::generate();
    let bob = KeyPair::generate();
    let ch = register_bilateral_consent(&ledger, &alice, &bob);

    let mut store = VitalityEvidenceStore::new();
    let t0 = 0_u64;
    store.initialize_at(ch, t0);

    // Phase 1: degradation trace
    let mut rng = seeded();
    let mut pool = ProviderPool::new(SamplingStrategy::RandomK(1)).with_liveness(2, u64::MAX);
    pool.add(pid(1), SubstrateLedger::new());
    pool.add(pid(2), SubstrateLedger::new());
    pool.record_failure(pid(2));
    pool.record_failure(pid(2)); // dead
    for _ in 0..4 {
        let _ = pool.sample(&mut rng);
    }
    for _ in 0..4 {
        pool.record_response(pid(1));
    }

    // Telemetry changes exactly according to ProviderPool semantics
    let snap_degraded = pool.operational_telemetry();
    assert_eq!(
        snap_degraded.liveness_weighted_kappa, 1.0,
        "degraded: lwk=1.0"
    );

    // Evidence timestamp unchanged after Phase 1
    assert_eq!(
        store.compute_state(ch, t0 + 578_388, 1.0, 1.0, 0.0),
        VitalityState::Active,
        "degradation trace must not alter evidence timestamp"
    );

    // Phase 2: recovery via record_response(pid(2)) — resets consecutive_failures=0
    for _ in 0..4 {
        pool.record_response(pid(2));
    }

    // Telemetry changes exactly per ProviderPool semantics after recovery
    let snap_recovered = pool.operational_telemetry();
    // response_appearances = {pid(1): 4, pid(2): 4} → entropy=1 bit → lwk=0.0
    assert_eq!(
        snap_recovered.liveness_weighted_kappa, 0.0,
        "recovered: equal responses → response_entropy=log₂(2) → lwk=0.0"
    );
    assert_eq!(
        snap_recovered.response_total, 8,
        "4 (phase-1) + 4 (phase-2) = 8 total responses"
    );
    assert!(snap_recovered.liveness_surface_evaluable);

    // Vitality evidence timestamp unchanged throughout both phases
    assert_eq!(
        store.compute_state(ch, t0 + 578_388, 1.0, 1.0, 0.0),
        VitalityState::Active,
        "recovery trace must not alter evidence timestamp"
    );
    assert_eq!(
        store.compute_state(ch, t0 + 578_389, 1.0, 1.0, 0.0),
        VitalityState::Warm,
        "timestamp is still t0: Warm at t0+578_389 boundary"
    );

    // Active send eligibility arises from unchanged vitality evidence and controls
    let _ = publish_ephemeral_at(&ledger, &bob, t0);
    let ctx = std_ctx(ch, t0);
    let result = FlashSession::open_and_send_sim(
        &ledger,
        &store,
        &ctx,
        &bob.public,
        b"t7-payload",
        &warm_cache(),
        &passthrough(),
    )
    .await;
    assert!(
        result.is_ok(),
        "Active vitality (unchanged) must permit send after provider recovery"
    );
}

// ── T8: Simultaneous pressure trace preserves orthogonality boundary ──────────
//
// Central orthogonality proof. In one scenario function:
//   1. Construct valid Active bilateral corridor.
//   2. Capture vitality evidence timestamp (Active→Warm boundary check).
//   3. Run deterministic provider-degradation trace (pid(2) dead → kappa=1.0, lwk=1.0).
//   4. Capture degraded telemetry snapshot.
//   5. Perform send through open_and_send_sim() using unchanged Active vitality context.
//   6. Read vitality evidence again — timestamp unchanged.
//   7. Inspect accessible rotation/epoch state — epoch_count=0.
//
// Assert:
//   - provider telemetry reflects degradation exactly;
//   - send succeeds because vitality remained Active;
//   - vitality evidence timestamp is unchanged;
//   - ctx.p is unchanged (0.0);
//   - epoch_count = 0 (no rotation triggered by any operation).

#[tokio::test]
async fn t8_simultaneous_pressure_preserves_orthogonality_boundary() {
    // 1. Construct valid Active bilateral corridor
    let ledger = SubstrateLedger::new();
    let alice = KeyPair::generate();
    let bob = KeyPair::generate();
    let ch = register_bilateral_consent(&ledger, &alice, &bob);

    let mut store = VitalityEvidenceStore::new();
    let t0 = 0_u64;
    store.initialize_at(ch, t0);
    let _ = publish_ephemeral_at(&ledger, &bob, t0);

    // 2. Capture vitality evidence timestamp via Active→Warm boundary
    assert_eq!(
        store.compute_state(ch, t0 + 578_388, 1.0, 1.0, 0.0),
        VitalityState::Active,
        "precondition: timestamp is t0 → Active at t0+578_388"
    );
    assert_eq!(
        store.compute_state(ch, t0 + 578_389, 1.0, 1.0, 0.0),
        VitalityState::Warm,
        "precondition: timestamp is t0 → Warm at t0+578_389"
    );

    // 3. Run deterministic provider-degradation trace
    let mut rng = seeded();
    let mut pool = ProviderPool::new(SamplingStrategy::RandomK(1)).with_liveness(2, u64::MAX);
    pool.add(pid(1), SubstrateLedger::new());
    pool.add(pid(2), SubstrateLedger::new());
    pool.record_failure(pid(2));
    pool.record_failure(pid(2)); // dead
    for _ in 0..4 {
        let _ = pool.sample(&mut rng);
    }
    for _ in 0..4 {
        pool.record_response(pid(1));
    }

    // 4. Capture degraded telemetry snapshot
    let snap_degraded = pool.operational_telemetry();
    assert_eq!(
        snap_degraded.kappa, 1.0,
        "degraded trace: only pid(1) selected → entropy=0 → kappa=1.0"
    );
    assert_eq!(
        snap_degraded.liveness_weighted_kappa, 1.0,
        "degraded trace: only pid(1) responded → response_entropy=0 → lwk=1.0"
    );
    assert_eq!(snap_degraded.selection_total, 4);
    assert_eq!(snap_degraded.response_total, 4);
    assert!(snap_degraded.survivor_surface_evaluable);
    assert!(snap_degraded.liveness_surface_evaluable);

    // 5. Perform send through open_and_send_sim() using the unchanged Active vitality context
    let ctx = std_ctx(ch, t0); // p = 0.0; vitality context is unchanged
    let result = FlashSession::open_and_send_sim(
        &ledger,
        &store,
        &ctx,
        &bob.public,
        b"t8-payload",
        &warm_cache(),
        &passthrough(),
    )
    .await;
    // Send succeeds because vitality remained Active
    assert!(
        result.is_ok(),
        "Active vitality must permit send despite simultaneous provider degradation"
    );

    // 6. Read vitality evidence again — timestamp unchanged
    assert_eq!(
        store.compute_state(ch, t0 + 578_388, 1.0, 1.0, 0.0),
        VitalityState::Active,
        "vitality evidence timestamp unchanged: still Active at t0+578_388 after send"
    );
    assert_eq!(
        store.compute_state(ch, t0 + 578_389, 1.0, 1.0, 0.0),
        VitalityState::Warm,
        "vitality evidence timestamp unchanged: still Warm at t0+578_389 after send"
    );

    // ctx.p unchanged (0.0) — verified structurally: standard controls at t0 yield Active
    assert_eq!(
        store.compute_state(ch, t0, 1.0, 1.0, 0.0),
        VitalityState::Active,
        "ctx.p=0.0 unchanged: standard controls at t0 still yield Active"
    );

    // 7. Inspect accessible rotation/epoch state
    assert_eq!(
        pool.epoch_count(),
        0,
        "no operation must have triggered rotation: epoch_count=0"
    );

    // Provider telemetry reflects degradation exactly and is unchanged from captured snapshot
    let snap_after = pool.operational_telemetry();
    assert_eq!(snap_after.kappa, snap_degraded.kappa);
    assert_eq!(
        snap_after.liveness_weighted_kappa,
        snap_degraded.liveness_weighted_kappa
    );
    assert_eq!(snap_after.selection_total, snap_degraded.selection_total);
    assert_eq!(snap_after.response_total, snap_degraded.response_total);
}
