use crate::flash::TransportError;
use crate::session::{FreshnessNonce, RouteId};
use crate::transcript::{FlashTranscriptV2, TransportKeyMaterial};
use scp_cryptography::keys::{x25519_dh, SessionKey as CryptoSessionKey};
use scp_cryptography::{scp_derive_key, DomainLabel};
use scp_vitality::VitalityState;

/// All receiver-required fields for reconstructing the session key and decrypting.
///
/// Produced by the sender-side v2 path. Fields the receiver cannot derive
/// locally (`sender_ephemeral_pub`, `enc_nonce`, `ciphertext`) must travel via
/// this struct. Fields the receiver already knows (`recipient_ops_pub`,
/// `protocol_version`) are included so `receive()` is self-contained.
///
/// # Simulator-only boundary
///
/// `BurstEnvelope` is an in-process simulator exchange artifact for corridor
/// trials. Its fields — in particular `recipient_ops_pub` — do **not** constitute
/// an approved production relay-visible wire contract or routing/privacy policy.
/// The presence of `recipient_ops_pub` in this struct is acceptable for simulated
/// in-process receipt and must not silently become a production routing decision.
pub struct BurstEnvelope {
    /// Sender's X25519 ephemeral public key — required for DH reconstruction.
    pub sender_ephemeral_pub: [u8; 32],
    /// Session route identifier — bound into the v2 transcript hash.
    pub route_id:             RouteId,
    /// Freshness nonce — bound into the v2 transcript hash.
    pub nonce:                FreshnessNonce,
    /// Vitality state at send time — bound into the v2 transcript hash.
    pub vitality_snapshot:    VitalityState,
    /// ChaCha20-Poly1305 ciphertext with authentication tag (pre-normalization).
    pub ciphertext:           Vec<u8>,
    /// 12-byte ChaCha20-Poly1305 encryption nonce.
    pub enc_nonce:            [u8; 12],
    /// Recipient's operational public key — bound into transcript and key material.
    pub recipient_ops_pub:    [u8; 32],
    /// Protocol version — must be 2. v1 envelopes cannot be decrypted by a recipient.
    pub protocol_version:     u8,
}

/// Reconstruct the session key from a [`BurstEnvelope`] and decrypt the payload.
///
/// `eph_secret` is the private X25519 key corresponding to the handshake
/// ephemeral public key B published to the ledger before the sender called
/// [`FlashSession::open_and_send_with_envelope`].
///
/// Derivation mirrors the sender path exactly:
/// 1. `dh_output = x25519_dh(eph_secret, sender_ephemeral_pub)` — symmetric with sender
/// 2. Reconstruct `FlashTranscriptV2` with envelope fields → `transcript_hash`
/// 3. `session_key = scp_derive_key(Transport, dh_output ‖ transcript_hash ‖ recipient_ops_pub)`
/// 4. `SessionKey::decrypt(ciphertext, enc_nonce)`
pub fn receive(
    envelope: &BurstEnvelope,
    eph_secret: &[u8; 32],
) -> Result<Vec<u8>, TransportError> {
    if envelope.protocol_version != 2 {
        return Err(TransportError::V1PathNotReceivable);
    }

    // Step 1: symmetric DH — produces the same output as the sender's
    //   x25519_dh(&sender_secret, &recipient_handshake_pub).
    let dh_output = x25519_dh(eph_secret, &envelope.sender_ephemeral_pub);

    // Step 2: rebuild the exact transcript the sender constructed.
    let transcript = FlashTranscriptV2 {
        route_id:             envelope.route_id.clone(),
        nonce:                envelope.nonce.clone(),
        recipient_ops_pub:    envelope.recipient_ops_pub,
        vitality_snapshot:    envelope.vitality_snapshot.clone(),
        protocol_version:     envelope.protocol_version,
        sender_ephemeral_pub: envelope.sender_ephemeral_pub,
    };
    let transcript_hash = transcript.hash();

    // Step 3: derive the same session key — identical layout to sender's key_material.
    let key_material = TransportKeyMaterial {
        ephemeral_seed:    dh_output,
        transcript_hash,
        recipient_binding: envelope.recipient_ops_pub,
    };
    let session_key =
        CryptoSessionKey(scp_derive_key(DomainLabel::Transport, &key_material.as_bytes()));

    // Step 4: decrypt with the reconstructed key.
    session_key
        .decrypt(&envelope.ciphertext, &envelope.enc_nonce)
        .map_err(|_| TransportError::DecryptionFailed)
}
