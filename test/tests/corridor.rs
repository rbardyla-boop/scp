// Phase 41 — Trial 0: Direct In-Process Burst Decrypt Roundtrip
//
// Claim permitted after these tests pass:
//   Given an envelope produced from A's real sender-side cryptographic state,
//   B can reconstruct the same session key and decrypt the original plaintext
//   in-process.
//
// Claims explicitly NOT proven by these tests:
//   - relay mailbox delivery
//   - relay routing metadata policy
//   - asynchronous transport
//   - localhost networking
//   - LAN networking
//   - desktop hardware readiness

use scp_cryptography::keys::KeyPair;
use scp_cryptography::x25519_generate_keypair;
use scp_ledger_substrate::{HandshakeEphemeral, SubstrateLedger};
use scp_relay_cache::WarmCache;
use scp_relay_perturbation::PerturbationEngine;
use scp_transport::corridor;
use scp_transport::flash::{FlashSession, TransportError};
use scp_transport::session::RouteId;
use scp_vitality::VitalityState;
use scp_wire_format::signing::handshake_sig_message;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

// ── Shared setup ─────────────────────────────────────────────────────────────

struct TrialActors {
    /// B's X25519 handshake private key — used by `corridor::receive`.
    eph_secret_b: [u8; 32],
    ledger: SubstrateLedger,
    ops_pub_b: [u8; 32],
}

fn setup_actors() -> TrialActors {
    let ops_kp_b = KeyPair::generate();
    let (eph_secret_b, eph_pub_b) = x25519_generate_keypair();

    // Sign B's handshake public key with B's ops key.
    let expires_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 3600;
    let sig_msg = handshake_sig_message(&eph_pub_b, expires_at);
    let sig = ops_kp_b.sign(&sig_msg);

    let ledger = SubstrateLedger::new();
    ledger
        .publish_handshake_ephemeral(
            &ops_kp_b.public,
            HandshakeEphemeral {
                pub_key:      eph_pub_b,
                sig:          sig.to_vec(),
                published_at: 0,
                expires_at,
            },
        )
        .expect("handshake ephemeral publication must succeed");

    TrialActors {
        eph_secret_b,
        ledger,
        ops_pub_b: ops_kp_b.public,
    }
}

async fn sender_envelope(
    actors: &TrialActors,
    payload: &[u8],
) -> corridor::BurstEnvelope {
    let cache  = WarmCache::new(Duration::from_secs(600));
    let engine = PerturbationEngine::passthrough();

    let state = FlashSession::retrieve_state(&actors.ledger, &actors.ops_pub_b)
        .await
        .expect("retrieve_state must succeed");

    let (_session, envelope) =
        FlashSession::open_and_send_with_envelope(state, payload, &cache, &engine)
            .await
            .expect("open_and_send_with_envelope must succeed on v2 path");

    envelope
}

// ── Test 1: correct A→B roundtrip recovers identical plaintext ──────────────

#[tokio::test]
async fn corridor_trial0_ab_roundtrip_recovers_plaintext() {
    let actors = setup_actors();
    let payload = b"trial-0-direct-decrypt-roundtrip";

    let envelope = sender_envelope(&actors, payload).await;

    let plaintext = corridor::receive(&envelope, &actors.eph_secret_b)
        .expect("receive must succeed on correct envelope");

    assert_eq!(
        plaintext.as_slice(),
        payload.as_slice(),
        "decrypted plaintext must match original payload"
    );
}

// ── Test 2: modified ciphertext causes decryption failure ───────────────────

#[tokio::test]
async fn corridor_modified_ciphertext_fails() {
    let actors = setup_actors();
    let mut envelope = sender_envelope(&actors, b"secret payload").await;

    // Flip a bit in the ciphertext — auth tag check must catch this.
    envelope.ciphertext[0] ^= 0xff;

    assert!(
        corridor::receive(&envelope, &actors.eph_secret_b).is_err(),
        "modified ciphertext must cause decryption failure"
    );
}

// ── Test 3: modified enc_nonce causes decryption failure ────────────────────

#[tokio::test]
async fn corridor_modified_enc_nonce_fails() {
    let actors = setup_actors();
    let mut envelope = sender_envelope(&actors, b"nonce test payload").await;

    // Flip a bit in the 12-byte ChaCha20-Poly1305 nonce.
    envelope.enc_nonce[0] ^= 0x01;

    assert!(
        corridor::receive(&envelope, &actors.eph_secret_b).is_err(),
        "modified enc_nonce must cause decryption failure"
    );
}

// ── Test 4: modified sender ephemeral public key causes failure ──────────────

#[tokio::test]
async fn corridor_modified_sender_ephemeral_pub_fails() {
    let actors = setup_actors();
    let mut envelope = sender_envelope(&actors, b"ephemeral pub test").await;

    // Replace sender's ephemeral pub with a random key — wrong DH + wrong transcript.
    let (_, wrong_pub) = x25519_generate_keypair();
    envelope.sender_ephemeral_pub = wrong_pub;

    assert!(
        corridor::receive(&envelope, &actors.eph_secret_b).is_err(),
        "wrong sender_ephemeral_pub must cause decryption failure (wrong DH and wrong transcript hash)"
    );
}

// ── Test 5: modified transcript-bound metadata (route_id) causes failure ─────

#[tokio::test]
async fn corridor_modified_route_id_fails() {
    let actors = setup_actors();
    let mut envelope = sender_envelope(&actors, b"transcript binding test").await;

    // Flip a bit in the route_id — changes the transcript hash → wrong session key.
    envelope.route_id = RouteId([0xffu8; 16]);

    assert!(
        corridor::receive(&envelope, &actors.eph_secret_b).is_err(),
        "modified route_id must cause decryption failure (transcript hash mismatch)"
    );
}

// ── Test 6: wrong recipient ephemeral secret causes failure ──────────────────

#[tokio::test]
async fn corridor_wrong_recipient_eph_secret_fails() {
    let actors = setup_actors();
    let envelope = sender_envelope(&actors, b"wrong secret test").await;

    // Use a different private key — DH output differs → wrong session key.
    let (wrong_secret, _) = x25519_generate_keypair();

    assert!(
        corridor::receive(&envelope, &wrong_secret).is_err(),
        "wrong recipient eph_secret must cause decryption failure (wrong DH output)"
    );
}

// ── Test 7: unsupported protocol version is rejected explicitly ───────────────

#[tokio::test]
async fn corridor_protocol_version_v1_is_rejected() {
    let actors = setup_actors();
    let mut envelope = sender_envelope(&actors, b"version boundary test").await;

    // Set protocol_version to 1 — the v1 path cannot be decrypted by a recipient.
    // This must fail with V1PathNotReceivable, not enter the v2 decrypt path.
    envelope.protocol_version = 1;

    assert!(
        matches!(
            corridor::receive(&envelope, &actors.eph_secret_b),
            Err(TransportError::V1PathNotReceivable)
        ),
        "protocol_version != 2 must be rejected with V1PathNotReceivable"
    );
}

// ── Test 8: modified recipient_ops_pub causes decryption failure ──────────────

#[tokio::test]
async fn corridor_modified_recipient_ops_pub_fails() {
    let actors = setup_actors();
    let mut envelope = sender_envelope(&actors, b"recipient binding test").await;

    // Flip a bit in recipient_ops_pub — changes both the transcript hash and the
    // key material recipient_binding, producing a completely different session key.
    envelope.recipient_ops_pub[0] ^= 0x01;

    assert!(
        corridor::receive(&envelope, &actors.eph_secret_b).is_err(),
        "modified recipient_ops_pub must cause decryption failure (transcript and key binding mismatch)"
    );
}

// ── Test 9: modified vitality_snapshot causes decryption failure ──────────────

#[tokio::test]
async fn corridor_modified_vitality_snapshot_fails() {
    let actors = setup_actors();
    let mut envelope = sender_envelope(&actors, b"vitality snapshot binding test").await;

    // Replace with a vitality state that differs from what the sender captured,
    // so the transcript hash mismatches and produces a different session key.
    envelope.vitality_snapshot = if envelope.vitality_snapshot == VitalityState::Active {
        VitalityState::Dormant
    } else {
        VitalityState::Active
    };

    assert!(
        corridor::receive(&envelope, &actors.eph_secret_b).is_err(),
        "modified vitality_snapshot must cause decryption failure (transcript hash mismatch)"
    );
}
