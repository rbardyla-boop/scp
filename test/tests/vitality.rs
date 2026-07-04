// Trial 1a — Static Vitality Enforcement Gate
//
// Claim permitted after these tests pass:
//   Given a sender-visible RecipientState whose vitality is non-open,
//   FlashSession rejects creation of a new encrypted burst with
//   TransportError::VitalityInsufficient. The enforcement gate fires before
//   any key derivation, path selection, or BurstEnvelope construction.
//
// Claims explicitly NOT proven by these tests:
//   - Inactivity causes vitality to drop
//   - Reaffirmation restores vitality
//   - Vitality evidence is persisted anywhere
//   - Vitality is owned by any specific object (identity, corridor, session)
//   - Receive-side decryption is blocked by vitality state
//   - Relay delivery, asynchronous transport, localhost, LAN, or hardware behavior

use scp_cryptography::keys::KeyPair;
use scp_cryptography::x25519_generate_keypair;
use scp_relay_cache::WarmCache;
use scp_relay_perturbation::PerturbationEngine;
use scp_transport::flash::{FlashSession, PublishedHandshakeKey, RecipientState, TransportError};
use scp_vitality::VitalityState;
use scp_wire_format::signing::handshake_sig_message;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

// ── Shared setup ──────────────────────────────────────────────────────────────

/// Construct a RecipientState with Active vitality and a valid, signed handshake
/// ephemeral — the minimal state needed for the v2 path to succeed.
fn make_active_state() -> RecipientState {
    let ops_kp = KeyPair::generate();
    let (_, eph_pub) = x25519_generate_keypair();
    let expires_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 3600;
    let sig: [u8; 64] = ops_kp.sign(&handshake_sig_message(&eph_pub, expires_at));

    RecipientState {
        ops_pub:             ops_kp.public,
        vitality:            VitalityState::Active,
        routing_hints:       vec![],
        handshake_ephemeral: Some(PublishedHandshakeKey { pub_key: eph_pub, sig, expires_at }),
    }
}

/// Construct a RecipientState with the given non-open vitality and no handshake
/// ephemeral. The vitality check fires before the ephemeral is examined, so
/// the absence of an ephemeral does not affect the rejection behavior being tested.
fn make_state_with_vitality(vitality: VitalityState) -> RecipientState {
    RecipientState {
        ops_pub:             KeyPair::generate().public,
        vitality,
        routing_hints:       vec![],
        handshake_ephemeral: None,
    }
}

// ── Test 1: Active vitality permits the full send path ────────────────────────

#[tokio::test]
async fn vitality_active_state_permits_send_and_produces_envelope() {
    let cache  = WarmCache::new(Duration::from_secs(600));
    let engine = PerturbationEngine::passthrough();

    let result = FlashSession::open_and_send_with_envelope(
        make_active_state(),
        b"vitality-active-send",
        &cache,
        &engine,
    )
    .await;

    let (_, envelope) = result.expect(
        "Active vitality must permit send and return a BurstEnvelope on the v2 path",
    );
    assert_eq!(
        envelope.protocol_version, 2,
        "envelope must carry protocol_version = 2"
    );
}

// ── Test 2: Suspended vitality rejects send ───────────────────────────────────

#[tokio::test]
async fn vitality_suspended_rejects_send_with_vitality_insufficient() {
    let cache  = WarmCache::new(Duration::from_secs(600));
    let engine = PerturbationEngine::passthrough();

    let result = FlashSession::open_and_send(
        make_state_with_vitality(VitalityState::Suspended),
        b"suspended-payload",
        &cache,
        &engine,
    )
    .await;

    assert!(
        matches!(result, Err(TransportError::VitalityInsufficient(VitalityState::Suspended))),
        "Suspended vitality must produce VitalityInsufficient(Suspended)"
    );
}

// ── Test 3: Severed vitality rejects send ─────────────────────────────────────

#[tokio::test]
async fn vitality_severed_rejects_send_with_vitality_insufficient() {
    let cache  = WarmCache::new(Duration::from_secs(600));
    let engine = PerturbationEngine::passthrough();

    let result = FlashSession::open_and_send(
        make_state_with_vitality(VitalityState::Severed),
        b"severed-payload",
        &cache,
        &engine,
    )
    .await;

    assert!(
        matches!(result, Err(TransportError::VitalityInsufficient(VitalityState::Severed))),
        "Severed vitality must produce VitalityInsufficient(Severed)"
    );
}

// ── Test 4: Burned vitality rejects send ──────────────────────────────────────

#[tokio::test]
async fn vitality_burned_rejects_send_with_vitality_insufficient() {
    let cache  = WarmCache::new(Duration::from_secs(600));
    let engine = PerturbationEngine::passthrough();

    let result = FlashSession::open_and_send(
        make_state_with_vitality(VitalityState::Burned),
        b"burned-payload",
        &cache,
        &engine,
    )
    .await;

    assert!(
        matches!(result, Err(TransportError::VitalityInsufficient(VitalityState::Burned))),
        "Burned vitality must produce VitalityInsufficient(Burned)"
    );
}

// ── Test 5: Rejection fires before path selection — no envelope is produced ───

#[tokio::test]
async fn vitality_rejection_fires_before_path_selection_and_produces_no_envelope() {
    let cache  = WarmCache::new(Duration::from_secs(600));
    let engine = PerturbationEngine::passthrough();

    // open_and_send_with_envelope is used deliberately: if path selection ran
    // before the vitality check, the error would be V1PathNotReceivable (because
    // handshake_ephemeral is None). If key derivation ran, the error would be
    // DecryptionFailed or HandshakeKeyInvalid. The expected error is
    // VitalityInsufficient, proving the check fires first.
    let result = FlashSession::open_and_send_with_envelope(
        make_state_with_vitality(VitalityState::Suspended),
        b"no-envelope-payload",
        &cache,
        &engine,
    )
    .await;

    assert!(
        matches!(result, Err(TransportError::VitalityInsufficient(VitalityState::Suspended))),
        "vitality check must fire before path selection (not V1PathNotReceivable) \
         and before key derivation (not DecryptionFailed) — no BurstEnvelope is produced"
    );
}
