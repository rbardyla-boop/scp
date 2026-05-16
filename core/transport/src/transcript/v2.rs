use crate::session::{FreshnessNonce, RouteId};
use scp_cryptography::domains::{scp_derive_key, DomainLabel};
use scp_vitality::VitalityState;

/// Transcript of a flash session — v2 (Phase 6+, bilateral X25519 DH).
///
/// Extends v1 by binding the sender's handshake ephemeral public key so the
/// session key is jointly owned: neither party can reconstruct it without the
/// other's contribution.
///
/// Serialization format (95 bytes, fixed):
///   [4]  magic  = "SCPt"
///   [1]  format = 0x02
///   [16] route_id
///   [8]  nonce (little-endian u64)
///   [32] recipient_ops_pub
///   [1]  vitality_byte
///   [1]  protocol_version
///   [32] sender_ephemeral_pub  ← X25519 public key (sender contribution)
///
/// This format is protocol-stable. New fields require format byte 0x03+.
pub struct FlashTranscriptV2 {
    pub route_id:              RouteId,
    pub nonce:                 FreshnessNonce,
    pub recipient_ops_pub:     [u8; 32],
    pub vitality_snapshot:     VitalityState,
    pub protocol_version:      u8,
    /// Sender's X25519 handshake ephemeral public key.
    /// Binds the sender's contribution to the transcript, making the session
    /// key jointly ephemeral — possession of either long-term key alone reveals
    /// nothing about session content after dissolution.
    pub sender_ephemeral_pub:  [u8; 32],
}

impl FlashTranscriptV2 {
    pub fn hash(&self) -> [u8; 32] {
        let vitality_byte: u8 = match &self.vitality_snapshot {
            VitalityState::Active    => 0,
            VitalityState::Warm      => 1,
            VitalityState::Dormant   => 2,
            VitalityState::Suspended => 3,
            VitalityState::Severed   => 4,
            VitalityState::Burned    => 5,
        };

        let mut data = [0u8; 95];
        data[0..4].copy_from_slice(b"SCPt");
        data[4]      = 0x02;
        data[5..21].copy_from_slice(&self.route_id.0);
        data[21..29].copy_from_slice(&self.nonce.0.to_le_bytes());
        data[29..61].copy_from_slice(&self.recipient_ops_pub);
        data[61]     = vitality_byte;
        data[62]     = self.protocol_version;
        data[63..95].copy_from_slice(&self.sender_ephemeral_pub);

        scp_derive_key(DomainLabel::Transcript, &data)
    }
}
