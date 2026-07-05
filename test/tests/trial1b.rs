// Trial 1b — Vitality Evidence Store and Send Gate Composition
//
// Permitted claim:
//   A relationship-scoped VitalityEvidenceStore deterministically computes
//   inactivity and reaffirmation transitions, and its computed VitalityState
//   composes correctly with the already-proven FlashSession send enforcement gate.
//
// Explicit non-claims:
//   - runtime retrieve_state() automatically consults vitality evidence
//   - the vitality oracle is wired into ordinary FlashSession recipient retrieval
//   - a production reaffirmation protocol exists
//   - receive-side decryption is vitality-gated
//   - relay mailbox delivery or routing privacy behavior
//   - localhost, LAN, desktop, or hardware readiness
//
// Trial 1b controls: i = 1.0, r = 1.0, p = 0.0.
//
// Correct transition boundaries under these controls:
//   Active → Warm:       t = 578_388 (Active) / 578_389 (Warm)
//   Warm → Dormant:      t = 1_796_637 (Warm)  / 1_796_638 (Dormant)
//   Dormant → Suspended: t = 4_171_663 (Dormant) / 4_171_664 (Suspended)

use scp_cryptography::keys::{hash, KeyPair};
use scp_cryptography::x25519_generate_keypair;
use scp_relay_cache::WarmCache;
use scp_relay_perturbation::PerturbationEngine;
use scp_transport::flash::{FlashSession, PublishedHandshakeKey, RecipientState, TransportError};
use scp_vitality::{VitalityEvidenceStore, VitalityState};
use scp_wire_format::signing::handshake_sig_message;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

// ── Shared helpers ─────────────────────────────────────────────────────────────

fn consent_hash(seed: &[u8]) -> [u8; 32] {
    hash(seed)
}

/// Build a v2-capable RecipientState with the given vitality.
/// Required for tests where Active state must permit open_and_send to complete.
fn make_v2_recipient(vitality: VitalityState) -> RecipientState {
    let ops_kp = KeyPair::generate();
    let (_, eph_pub) = x25519_generate_keypair();
    let expires_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 3600;
    let sig: [u8; 64] = ops_kp.sign(&handshake_sig_message(&eph_pub, expires_at));
    RecipientState {
        ops_pub: ops_kp.public,
        vitality,
        routing_hints: vec![],
        handshake_ephemeral: Some(PublishedHandshakeKey {
            pub_key: eph_pub,
            sig,
            expires_at,
        }),
    }
}

/// Build a bare RecipientState (no handshake ephemeral) with the given vitality.
/// Sufficient for non-open state tests — the vitality gate fires before the
/// ephemeral is examined, so the absence of an ephemeral does not affect rejection.
fn make_bare_recipient(vitality: VitalityState) -> RecipientState {
    RecipientState {
        ops_pub: KeyPair::generate().public,
        vitality,
        routing_hints: vec![],
        handshake_ephemeral: None,
    }
}

// ── Test 1: Newly initialized relationship is Active and permits send ──────────

#[tokio::test]
async fn evidence_initialized_at_establishment_is_active_and_permits_send() {
    let mut store = VitalityEvidenceStore::new();
    let hash_ab = consent_hash(b"trial1b-t1-relationship-ab");
    let t0 = 1_000_000_u64;

    store.initialize_at(hash_ab, t0);

    let state = store.compute_state(hash_ab, t0, 1.0, 1.0, 0.0);
    assert_eq!(
        state,
        VitalityState::Active,
        "at establishment time elapsed = 0s, V = 1.0, state must be Active"
    );

    let cache = WarmCache::new(Duration::from_secs(600));
    let engine = PerturbationEngine::passthrough();
    let result = FlashSession::open_and_send(
        make_v2_recipient(state),
        b"trial1b-t1-send",
        &cache,
        &engine,
    )
    .await;
    assert!(
        result.is_ok(),
        "Active computed state must permit open_and_send"
    );
}

// ── Test 2: Missing evidence fails closed to Suspended ─────────────────────────

#[test]
fn evidence_missing_fails_closed_to_suspended() {
    let store = VitalityEvidenceStore::new();
    let hash = consent_hash(b"trial1b-t2-unknown");

    let state = store.compute_state(hash, 9_999_999, 1.0, 1.0, 0.0);
    assert_eq!(
        state,
        VitalityState::Suspended,
        "unknown consent hash must fail closed to Suspended — \
         not derived from a zero-epoch timestamp"
    );
}

// ── Test 3: initialize_at is write-once ────────────────────────────────────────

#[test]
fn evidence_initialize_at_is_write_once() {
    let mut store = VitalityEvidenceStore::new();
    let hash = consent_hash(b"trial1b-t3-write-once");
    let t0 = 1_000_000_u64;
    let t1 = 9_000_000_u64;

    let first = store.initialize_at(hash, t0);
    assert!(first, "first initialization must return true");

    let second = store.initialize_at(hash, t1);
    assert!(
        !second,
        "second initialization must return false — write-once"
    );

    // Evidence must still be anchored at t0, not t1.
    let state_at_t0 = store.compute_state(hash, t0, 1.0, 1.0, 0.0);
    assert_eq!(
        state_at_t0,
        VitalityState::Active,
        "state at establishment time must be Active — original anchor preserved"
    );

    // t0 + 578_389 crosses the Active→Warm boundary from t0; if t1 had overwritten
    // t0, elapsed would be 0 and this would still be Active.
    let state_after_active = store.compute_state(hash, t0 + 578_389, 1.0, 1.0, 0.0);
    assert_eq!(
        state_after_active,
        VitalityState::Warm,
        "decay must proceed from the original t0 anchor, \
         not from the rejected re-initialization timestamp"
    );
}

// ── Test 4: record_reaffirmation rejects an uninitialized consent hash ─────────

#[test]
fn evidence_reaffirmation_rejects_uninitialized_hash() {
    let mut store = VitalityEvidenceStore::new();
    let hash = consent_hash(b"trial1b-t4-uninitialized");
    let now = 5_000_000_u64;

    let result = store.record_reaffirmation(hash, now);
    assert!(
        !result,
        "record_reaffirmation must return false for uninitialized hash"
    );

    let state = store.compute_state(hash, now, 1.0, 1.0, 0.0);
    assert_eq!(
        state,
        VitalityState::Suspended,
        "after rejected reaffirmation, hash must still have no evidence — fails closed to Suspended"
    );
}

// ── Test 5: Active→Warm boundary at t = 578_388 / 578_389 ────────────────────

#[test]
fn evidence_active_warm_boundary() {
    let mut store = VitalityEvidenceStore::new();
    let hash = consent_hash(b"trial1b-t5-active-warm");
    store.initialize_at(hash, 0);

    assert_eq!(
        store.compute_state(hash, 578_388, 1.0, 1.0, 0.0),
        VitalityState::Active,
        "t = 578_388 must remain Active"
    );
    assert_eq!(
        store.compute_state(hash, 578_389, 1.0, 1.0, 0.0),
        VitalityState::Warm,
        "t = 578_389 must become Warm"
    );
}

// ── Test 6: Warm→Dormant boundary at t = 1_796_637 / 1_796_638 ───────────────

#[test]
fn evidence_warm_dormant_boundary() {
    let mut store = VitalityEvidenceStore::new();
    let hash = consent_hash(b"trial1b-t6-warm-dormant");
    store.initialize_at(hash, 0);

    assert_eq!(
        store.compute_state(hash, 1_796_637, 1.0, 1.0, 0.0),
        VitalityState::Warm,
        "t = 1_796_637 must remain Warm"
    );
    assert_eq!(
        store.compute_state(hash, 1_796_638, 1.0, 1.0, 0.0),
        VitalityState::Dormant,
        "t = 1_796_638 must become Dormant"
    );
}

// ── Test 7: Dormant→Suspended boundary at t = 4_171_663 / 4_171_664 ──────────

#[test]
fn evidence_dormant_suspended_boundary() {
    let mut store = VitalityEvidenceStore::new();
    let hash = consent_hash(b"trial1b-t7-dormant-suspended");
    store.initialize_at(hash, 0);

    assert_eq!(
        store.compute_state(hash, 4_171_663, 1.0, 1.0, 0.0),
        VitalityState::Dormant,
        "t = 4_171_663 must remain Dormant"
    );
    assert_eq!(
        store.compute_state(hash, 4_171_664, 1.0, 1.0, 0.0),
        VitalityState::Suspended,
        "t = 4_171_664 must become Suspended"
    );
}

// ── Test 8: Suspended state composes with send gate → VitalityInsufficient ────

#[tokio::test]
async fn evidence_suspended_composes_with_send_gate_as_vitality_insufficient() {
    let mut store = VitalityEvidenceStore::new();
    let hash = consent_hash(b"trial1b-t8-suspended-gate");
    store.initialize_at(hash, 0);

    let state = store.compute_state(hash, 4_171_664, 1.0, 1.0, 0.0);
    assert_eq!(
        state,
        VitalityState::Suspended,
        "precondition: must be Suspended"
    );

    let cache = WarmCache::new(Duration::from_secs(600));
    let engine = PerturbationEngine::passthrough();
    let result = FlashSession::open_and_send(
        make_bare_recipient(state),
        b"trial1b-t8-suspended-send",
        &cache,
        &engine,
    )
    .await;

    assert!(
        matches!(
            result,
            Err(TransportError::VitalityInsufficient(
                VitalityState::Suspended
            ))
        ),
        "computed Suspended must compose with send gate as VitalityInsufficient(Suspended)"
    );
}

// ── Test 9: Reaffirmation after suspension restores Active and permits send ────

#[tokio::test]
async fn evidence_reaffirmation_after_suspension_restores_active_and_permits_send() {
    let mut store = VitalityEvidenceStore::new();
    let hash = consent_hash(b"trial1b-t9-reaffirm-restore");
    store.initialize_at(hash, 0);

    let t_suspended = 4_171_664_u64;
    let suspended = store.compute_state(hash, t_suspended, 1.0, 1.0, 0.0);
    assert_eq!(
        suspended,
        VitalityState::Suspended,
        "precondition: must be Suspended"
    );

    let ok = store.record_reaffirmation(hash, t_suspended);
    assert!(
        ok,
        "record_reaffirmation must succeed on an initialized hash"
    );

    let restored = store.compute_state(hash, t_suspended, 1.0, 1.0, 0.0);
    assert_eq!(
        restored,
        VitalityState::Active,
        "elapsed = 0 after reaffirmation at t_suspended must yield Active"
    );

    let cache = WarmCache::new(Duration::from_secs(600));
    let engine = PerturbationEngine::passthrough();
    let result = FlashSession::open_and_send(
        make_v2_recipient(restored),
        b"trial1b-t9-restored-send",
        &cache,
        &engine,
    )
    .await;
    assert!(
        result.is_ok(),
        "Active state after reaffirmation must permit send"
    );
}

// ── Test 10: Successful send does not implicitly update evidence timestamp ─────

#[tokio::test]
async fn evidence_successful_send_does_not_implicitly_refresh_vitality() {
    let mut store = VitalityEvidenceStore::new();
    let hash = consent_hash(b"trial1b-t10-no-implicit-refresh");
    let t0 = 0_u64;
    store.initialize_at(hash, t0);

    let active = store.compute_state(hash, t0, 1.0, 1.0, 0.0);
    assert_eq!(
        active,
        VitalityState::Active,
        "precondition: must be Active at t0"
    );

    let cache = WarmCache::new(Duration::from_secs(600));
    let engine = PerturbationEngine::passthrough();
    FlashSession::open_and_send(
        make_v2_recipient(active),
        b"trial1b-t10-send",
        &cache,
        &engine,
    )
    .await
    .expect("Active vitality must permit send");

    // The send did not call record_reaffirmation — timestamp is still t0.
    // Elapsed at t0 + 578_389 = 578_389s → Warm, not Active.
    let after = store.compute_state(hash, t0 + 578_389, 1.0, 1.0, 0.0);
    assert_eq!(
        after,
        VitalityState::Warm,
        "vitality must continue decaying from t0 — send must not have refreshed the timestamp"
    );
}

// ── Test 11: Relationship isolation ───────────────────────────────────────────

#[tokio::test]
async fn evidence_relationship_isolation() {
    let mut store = VitalityEvidenceStore::new();
    let hash_ab = consent_hash(b"trial1b-t11-relationship-AB");
    let hash_ac = consent_hash(b"trial1b-t11-relationship-AC");
    let t0 = 0_u64;

    store.initialize_at(hash_ab, t0);
    store.initialize_at(hash_ac, t0);

    // Advance past Dormant→Suspended threshold; reaffirm AC only.
    let t_eval = 4_171_664_u64;
    store.record_reaffirmation(hash_ac, t_eval);

    let state_ab = store.compute_state(hash_ab, t_eval, 1.0, 1.0, 0.0);
    let state_ac = store.compute_state(hash_ac, t_eval, 1.0, 1.0, 0.0);

    assert_eq!(
        state_ab,
        VitalityState::Suspended,
        "AB: 4_171_664s without reaffirmation — must be Suspended"
    );
    assert_eq!(
        state_ac,
        VitalityState::Active,
        "AC: reaffirmed at t_eval, elapsed = 0 — must be Active"
    );

    let cache = WarmCache::new(Duration::from_secs(600));
    let engine = PerturbationEngine::passthrough();

    let result_ab = FlashSession::open_and_send(
        make_bare_recipient(state_ab),
        b"trial1b-t11-ab-send",
        &cache,
        &engine,
    )
    .await;
    assert!(
        matches!(
            result_ab,
            Err(TransportError::VitalityInsufficient(
                VitalityState::Suspended
            ))
        ),
        "AB send must be rejected: VitalityInsufficient(Suspended)"
    );

    let result_ac = FlashSession::open_and_send(
        make_v2_recipient(state_ac),
        b"trial1b-t11-ac-send",
        &cache,
        &engine,
    )
    .await;
    assert!(
        result_ac.is_ok(),
        "AC send must be permitted: Active vitality"
    );
}
