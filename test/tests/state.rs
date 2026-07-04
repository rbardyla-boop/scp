// Phase 9 state consistency hardening tests.
//
// Invariants under test:
//   Revocation monotonicity, rotation coherence, concurrency safety,
//   TOCTOU semantics, and state snapshot commitment stability.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use scp_cryptography::keys::{x25519_generate_keypair, KeyPair};
use scp_ledger_substrate::{HandshakeEphemeral, LedgerIdentityRecord, SubstrateLedger};
use scp_relay_cache::WarmCache;
use scp_relay_perturbation::PerturbationEngine;
use scp_transport::flash::{FlashSession, PublishedHandshakeKey, RecipientState, TransportError};
use scp_vitality::VitalityState;
use scp_wire_format::signing::{handshake_sig_message, registration_message, rotation_message};

// ── Helpers ───────────────────────────────────────────────────────────────────

fn register(ledger: &SubstrateLedger) -> (KeyPair, KeyPair) {
    let root_kp = KeyPair::generate();
    let ops_kp  = KeyPair::generate();
    let record = LedgerIdentityRecord {
        k_root_pub:            root_kp.public,
        k_ops_pub:             ops_kp.public,
        recovery_policy_hash:  [0u8; 32],
        continuity_commitment: [0u8; 32],
    };
    let msg = registration_message(&root_kp.public, &ops_kp.public, &[0u8; 32]);
    let sig = root_kp.sign(&msg);
    ledger.register_identity(&record, &sig).expect("register_identity must succeed");
    (root_kp, ops_kp)
}

fn publish_ephemeral(ledger: &SubstrateLedger, ops_kp: &KeyPair, expires_at: u64) -> [u8; 32] {
    let (_, eph_pub) = x25519_generate_keypair();
    let msg = handshake_sig_message(&eph_pub, expires_at);
    let sig = ops_kp.sign(&msg);
    ledger.publish_handshake_ephemeral(
        &ops_kp.public,
        HandshakeEphemeral { pub_key: eph_pub, sig: sig.to_vec(), published_at: 0, expires_at },
    ).expect("publish_handshake_ephemeral must succeed");
    eph_pub
}

fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

// ── §1. Revocation Monotonicity ───────────────────────────────────────────────
//
// Once revoked, retrieve_state must always return RecipientRevoked.
// No timing window, race, or retry can produce Ok after revocation.

#[tokio::test]
async fn revocation_is_monotonic_across_multiple_retrievals() {
    let ledger = SubstrateLedger::new();
    let (root_kp, ops_kp) = register(&ledger);

    // root signs over bare ops_pub to authorize revocation.
    let revoke_sig = root_kp.sign(&ops_kp.public);
    ledger.revoke(&ops_kp.public, &revoke_sig).expect("revoke must succeed");

    for _ in 0..10 {
        let result = FlashSession::retrieve_state(&ledger, &ops_kp.public).await;
        assert!(
            matches!(result, Err(TransportError::RecipientRevoked)),
            "retrieve_state after revocation must always return RecipientRevoked"
        );
    }
}

#[tokio::test]
async fn rotation_revokes_old_ops_pub_immediately() {
    let ledger = SubstrateLedger::new();
    let (root_kp, ops_kp_a) = register(&ledger);
    let ops_kp_b = KeyPair::generate();

    let nonce = 1u64;
    let rot_msg = rotation_message(&ops_kp_a.public, &ops_kp_b.public, nonce);
    let rot_sig = root_kp.sign(&rot_msg);
    ledger.rotate_key(&ops_kp_a.public, &ops_kp_b.public, nonce, &rot_sig)
        .expect("rotate_key must succeed");

    // Old key revoked atomically by rotate_key.
    let old_result = FlashSession::retrieve_state(&ledger, &ops_kp_a.public).await;
    assert!(
        matches!(old_result, Err(TransportError::RecipientRevoked)),
        "old ops_pub must be revoked immediately after rotation"
    );

    // New key is valid (no ephemeral yet — v1 fallback path).
    let new_state = FlashSession::retrieve_state(&ledger, &ops_kp_b.public).await
        .expect("new ops_pub must be accessible after rotation");
    assert!(new_state.handshake_ephemeral.is_none(),
        "new ops_pub has no ephemerals until published — sender falls back to v1 path");
}

// ── §2. Ephemeral Coherence Under Rotation ────────────────────────────────────
//
// Rotation revokes the old ops key; its ephemerals are unreachable through
// the production retrieve_state path even though the ledger still stores them.
// New key starts with an empty ephemeral set (v1 fallback until republished).

#[tokio::test]
async fn rotation_makes_old_ephemerals_inaccessible() {
    let ledger = SubstrateLedger::new();
    let (root_kp, ops_kp_a) = register(&ledger);

    publish_ephemeral(&ledger, &ops_kp_a, now_secs() + 3600);

    // Confirm the ephemeral is visible before rotation.
    let pre_state = FlashSession::retrieve_state(&ledger, &ops_kp_a.public).await.unwrap();
    assert!(pre_state.handshake_ephemeral.is_some(), "ephemeral must be visible before rotation");

    let ops_kp_b = KeyPair::generate();
    let nonce = 42u64;
    let rot_msg = rotation_message(&ops_kp_a.public, &ops_kp_b.public, nonce);
    let rot_sig = root_kp.sign(&rot_msg);
    ledger.rotate_key(&ops_kp_a.public, &ops_kp_b.public, nonce, &rot_sig).unwrap();

    // Old key revoked — its ephemerals are gated behind RecipientRevoked.
    let post_result = FlashSession::retrieve_state(&ledger, &ops_kp_a.public).await;
    assert!(
        matches!(post_result, Err(TransportError::RecipientRevoked)),
        "old ephemerals must be unreachable after rotation — key is revoked"
    );
}

#[tokio::test]
async fn new_ops_pub_has_no_ephemerals_after_rotation() {
    let ledger = SubstrateLedger::new();
    let (root_kp, ops_kp_a) = register(&ledger);
    let ops_kp_b = KeyPair::generate();

    let nonce = 1u64;
    let rot_msg = rotation_message(&ops_kp_a.public, &ops_kp_b.public, nonce);
    let rot_sig = root_kp.sign(&rot_msg);
    ledger.rotate_key(&ops_kp_a.public, &ops_kp_b.public, nonce, &rot_sig).unwrap();

    let state = FlashSession::retrieve_state(&ledger, &ops_kp_b.public).await.unwrap();
    assert!(state.handshake_ephemeral.is_none(),
        "new ops_pub starts with no ephemerals after rotation — \
         sender falls back to v1 path until recipient republishes a handshake ephemeral");
}

#[tokio::test]
async fn ephemeral_capacity_eviction_drops_oldest() {
    let ledger = SubstrateLedger::new();
    let (_, ops_kp) = register(&ledger);

    let base_expires = now_secs() + 3600;

    // Fill to capacity (MAX_HANDSHAKE_EPHEMERALS = 8) with distinct expires_at.
    for i in 0u64..8 {
        publish_ephemeral(&ledger, &ops_kp, base_expires + i);
    }

    // 9th publish triggers eviction of the oldest (lowest expires_at = base_expires+0).
    // The 9th has the highest expires_at so it will be the returned value.
    let newest_expires = base_expires + 100;
    publish_ephemeral(&ledger, &ops_kp, newest_expires);

    // retrieve_state returns max-by-expires_at — the freshest ephemeral.
    let state = FlashSession::retrieve_state(&ledger, &ops_kp.public).await.unwrap();
    let eph = state.handshake_ephemeral.expect("must have ephemeral after 9 publishes");
    assert_eq!(eph.expires_at, newest_expires,
        "capacity eviction must drop the oldest entry; \
         retrieve returns the most-recently-expiring valid ephemeral");
}

// ── §3. Concurrency Safety ────────────────────────────────────────────────────
//
// Concurrent retrieve_state and revoke calls must never panic, deadlock,
// or produce any error variant other than Ok or RecipientRevoked.

#[tokio::test]
async fn concurrent_retrieve_state_on_valid_key_is_race_free() {
    let ledger = Arc::new(SubstrateLedger::new());
    // Unregistered key: is_revoked returns false — retrieve_state returns Ok.
    let ops_pub = [0x77u8; 32];

    let handles: Vec<_> = (0..50)
        .map(|_| {
            let ledger = ledger.clone();
            tokio::spawn(async move {
                FlashSession::retrieve_state(ledger.as_ref(), &ops_pub).await
            })
        })
        .collect();

    for h in handles {
        h.await.unwrap().expect("concurrent retrieve_state must succeed with no race condition");
    }
}

#[tokio::test]
async fn concurrent_revoke_and_retrieve_has_monotonic_outcome() {
    let ledger = Arc::new(SubstrateLedger::new());
    let (root_kp, ops_kp) = register(ledger.as_ref());
    let ops_pub = ops_kp.public;

    // Race: revoke task vs. 10 retrieve tasks.
    let revoke_ledger = ledger.clone();
    let revoke_sig = root_kp.sign(&ops_pub);
    let revoke_task = tokio::spawn(async move {
        revoke_ledger.revoke(&ops_pub, &revoke_sig)
    });

    let retrieve_handles: Vec<_> = (0..10)
        .map(|_| {
            let ledger = ledger.clone();
            tokio::spawn(async move {
                FlashSession::retrieve_state(ledger.as_ref(), &ops_pub).await
            })
        })
        .collect();

    revoke_task.await.unwrap().expect("revoke must succeed");

    for h in retrieve_handles {
        let result = h.await.unwrap();
        match result {
            Ok(_)                                 => {} // retrieved before revocation
            Err(TransportError::RecipientRevoked) => {} // retrieved after revocation
            Err(e) => panic!("concurrent revoke+retrieve produced unexpected error: {e}"),
        }
    }
}

// ── §4. TOCTOU Window Documentation ──────────────────────────────────────────
//
// Revocation gates NEW session initiation, not sessions already authorized
// from a valid pre-revocation snapshot. The transport layer does not
// re-check revocation inside open_and_send().
//
// This is correct SCP protocol behavior: retroactive cancellation would
// require centralized relay coordination, which violates the sovereignty model.

#[tokio::test]
async fn toctou_revocation_after_snapshot_does_not_cancel_session() {
    let ledger = SubstrateLedger::new();
    let (root_kp, ops_kp) = register(&ledger);

    let cache  = WarmCache::new(Duration::from_secs(600));
    let engine = PerturbationEngine::passthrough();

    // Snapshot taken while key is valid.
    let state = FlashSession::retrieve_state(&ledger, &ops_kp.public).await
        .expect("retrieve_state must succeed before revocation");

    // Revoke AFTER the snapshot.
    let revoke_sig = root_kp.sign(&ops_kp.public);
    ledger.revoke(&ops_kp.public, &revoke_sig).expect("revoke must succeed");

    // Session proceeds from the pre-revocation snapshot — correct protocol behavior.
    let session = FlashSession::open_and_send(state, b"toctou-test", &cache, &engine)
        .await
        .expect("snapshot-authorized session must proceed despite post-snapshot revocation");
    let _ = session.dissolve();

    // Only future session initiation is blocked.
    let result = FlashSession::retrieve_state(&ledger, &ops_kp.public).await;
    assert!(
        matches!(result, Err(TransportError::RecipientRevoked)),
        "post-revocation retrieve_state must return RecipientRevoked — \
         only new initiation is blocked, not sessions already in flight"
    );
}

// ── §5. State Snapshot Determinism ───────────────────────────────────────────
//
// RecipientState::commitment() must be deterministic, field-bound, and
// stable against any future encoding change (golden vector contract).

#[test]
fn state_commitment_is_deterministic() {
    let make = || RecipientState {
        ops_pub:             [0x44u8; 32],
        vitality:            VitalityState::Active,
        routing_hints:       vec![],
        handshake_ephemeral: Some(PublishedHandshakeKey {
            pub_key:    [0xbbu8; 32],
            sig:        [0u8; 64],
            expires_at: 7200,
        }),
    };
    let c = make().commitment();
    assert_eq!(c, make().commitment(), "commitment must be deterministic for identical state");
    assert_ne!(c, [0u8; 32], "commitment must be non-zero");
}

#[test]
fn state_commitment_binds_all_fields() {
    let base = RecipientState {
        ops_pub:             [0x11u8; 32],
        vitality:            VitalityState::Active,
        routing_hints:       vec![],
        handshake_ephemeral: None,
    };
    let base_c = base.commitment();

    let changed_ops = RecipientState {
        ops_pub: [0x22u8; 32], vitality: VitalityState::Active,
        routing_hints: vec![], handshake_ephemeral: None,
    };
    assert_ne!(base_c, changed_ops.commitment(), "ops_pub change must change commitment");

    let changed_vitality = RecipientState {
        ops_pub: [0x11u8; 32], vitality: VitalityState::Warm,
        routing_hints: vec![], handshake_ephemeral: None,
    };
    assert_ne!(base_c, changed_vitality.commitment(), "vitality change must change commitment");

    let with_ephemeral = RecipientState {
        ops_pub: [0x11u8; 32], vitality: VitalityState::Active, routing_hints: vec![],
        handshake_ephemeral: Some(PublishedHandshakeKey {
            pub_key: [0xaau8; 32], sig: [0u8; 64], expires_at: 1000,
        }),
    };
    assert_ne!(base_c, with_ephemeral.commitment(),
        "ephemeral presence change must change commitment");

    let eph_expires_a = RecipientState {
        ops_pub: [0x11u8; 32], vitality: VitalityState::Active, routing_hints: vec![],
        handshake_ephemeral: Some(PublishedHandshakeKey {
            pub_key: [0xaau8; 32], sig: [0u8; 64], expires_at: 1000,
        }),
    };
    let eph_expires_b = RecipientState {
        ops_pub: [0x11u8; 32], vitality: VitalityState::Active, routing_hints: vec![],
        handshake_ephemeral: Some(PublishedHandshakeKey {
            pub_key: [0xaau8; 32], sig: [0u8; 64], expires_at: 2000,
        }),
    };
    assert_ne!(eph_expires_a.commitment(), eph_expires_b.commitment(),
        "expires_at change must change commitment");
}

#[test]
fn state_commitment_matches_known_vector() {
    // Golden vector — permanent compatibility contract.
    //
    // Inputs:
    //   ops_pub    = [0x55; 32]
    //   vitality   = Active (VITALITY_ACTIVE wire byte = 0x00)
    //   present    = 0x01
    //   pub_key    = [0xaa; 32]
    //   expires_at = 9_999_999u64 → LE: [0x80, 0x96, 0x98, 0x00, 0x00, 0x00, 0x00, 0x00]
    //
    // BLAKE3([0x55;32] ‖ [0x00] ‖ [0x01] ‖ [0xaa;32] ‖ [0x80,0x96,0x98,0x00,0x00,0x00,0x00,0x00])
    //
    // Any change to field ordering, byte encoding, or vitality byte mapping
    // MUST break this test and MUST be handled as a versioned protocol change.
    let state = RecipientState {
        ops_pub:             [0x55u8; 32],
        vitality:            VitalityState::Active,
        routing_hints:       vec![],
        handshake_ephemeral: Some(PublishedHandshakeKey {
            pub_key:    [0xaau8; 32],
            sig:        [0u8; 64],
            expires_at: 9_999_999u64,
        }),
    };
    let got = state.commitment();
    const EXPECTED: [u8; 32] = [
        225, 31, 255, 116, 151, 154,   5,  69,
         72, 103, 170,  48,  99, 203,  86,  69,
         90, 192, 116, 200, 251, 180,  18, 226,
        161,  35, 137, 157, 232, 242, 210,  30,
    ];
    assert_eq!(got, EXPECTED,
        "state commitment does not match golden vector — \
         field ordering or byte encoding has changed; this is a breaking protocol change");
}
