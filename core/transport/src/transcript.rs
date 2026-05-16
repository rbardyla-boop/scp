use crate::session::{FreshnessNonce, RouteId};
use scp_cryptography::domains::{scp_derive_key, DomainLabel};
use scp_vitality::VitalityState;

/// Transcript of a flash session — a single binding object for HKDF, replay
/// logic, and audit verification.
///
/// FlashTranscript v1 serialization format (63 bytes, fixed):
///   [4]  magic  = "SCPt"
///   [1]  format = 0x01
///   [16] route_id
///   [8]  nonce (little-endian u64)
///   [32] recipient_ops_pub
///   [1]  vitality_byte (0=Active 1=Warm 2=Dormant 3=Suspended 4=Severed 5=Burned)
///   [1]  protocol_version
///
/// This format is protocol-stable. New fields MUST be added in a new format
/// version (format byte 0x02+) to preserve cross-client reproducibility.
pub struct FlashTranscript {
    pub route_id:          RouteId,
    pub nonce:             FreshnessNonce,
    pub recipient_ops_pub: [u8; 32],
    pub vitality_snapshot: VitalityState,
    /// SCP protocol version — 1 for Phase 4 through Phase 7.
    pub protocol_version:  u8,
}

impl FlashTranscript {
    /// Hash this transcript using domain-separated BLAKE3.
    ///
    /// The output is suitable as input to `scp_derive_key(DomainLabel::Transport, ...)`.
    /// Identical field values always produce an identical hash — this property
    /// must be preserved across all future refactors (see `transcript_serialization_is_stable`).
    pub fn hash(&self) -> [u8; 32] {
        let vitality_byte: u8 = match &self.vitality_snapshot {
            VitalityState::Active    => 0,
            VitalityState::Warm      => 1,
            VitalityState::Dormant   => 2,
            VitalityState::Suspended => 3,
            VitalityState::Severed   => 4,
            VitalityState::Burned    => 5,
        };

        let mut data = [0u8; 63];
        data[0..4].copy_from_slice(b"SCPt");
        data[4]   = 0x01;  // v1 format
        data[5..21].copy_from_slice(&self.route_id.0);
        data[21..29].copy_from_slice(&self.nonce.0.to_le_bytes());
        data[29..61].copy_from_slice(&self.recipient_ops_pub);
        data[61]  = vitality_byte;
        data[62]  = self.protocol_version;

        scp_derive_key(DomainLabel::Transcript, &data)
    }
}

/// Structured key material for transport session key derivation.
///
/// Using a named struct (rather than raw byte concatenation) makes the
/// derivation input auditable, stable across refactors, and self-documenting.
///
/// Phase 5: replace `ephemeral_seed` with the X25519 DH output computed
/// against the recipient's published ephemeral public key, completing
/// the forward-secrecy guarantee.
pub struct TransportKeyMaterial {
    /// Random 32 bytes per session — provides forward secrecy for Phase 4.
    pub ephemeral_seed:    [u8; 32],
    /// Output of FlashTranscript::hash() — binds key to route/nonce/recipient/vitality.
    pub transcript_hash:   [u8; 32],
    /// Recipient's operational public key — ensures key is recipient-specific.
    pub recipient_binding: [u8; 32],
}

impl TransportKeyMaterial {
    /// Serialise to 96 bytes in a canonical order for `scp_derive_key`.
    ///
    /// Field order: ephemeral_seed | transcript_hash | recipient_binding.
    /// This order is protocol-stable.
    pub fn as_bytes(&self) -> [u8; 96] {
        let mut out = [0u8; 96];
        out[0..32].copy_from_slice(&self.ephemeral_seed);
        out[32..64].copy_from_slice(&self.transcript_hash);
        out[64..96].copy_from_slice(&self.recipient_binding);
        out
    }
}
