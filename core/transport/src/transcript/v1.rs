use crate::session::{FreshnessNonce, RouteId};
use scp_cryptography::domains::{scp_derive_key, DomainLabel};
use scp_vitality::VitalityState;
use scp_wire_format::transcript::transcript_v1_bytes;

/// Transcript of a flash session — v1 (Phase 4 through Phase 5).
///
/// Serialization format (63 bytes, fixed):
///   [4]  magic  = "SCPt"
///   [1]  format = 0x01
///   [16] route_id
///   [8]  nonce (little-endian u64)
///   [32] recipient_ops_pub
///   [1]  vitality_byte (0=Active 1=Warm 2=Dormant 3=Suspended 4=Severed 5=Burned)
///   [1]  protocol_version
///
/// This format is protocol-stable. Use FlashTranscriptV2 for sessions that
/// include bilateral X25519 DH (format byte 0x02).
pub struct FlashTranscript {
    pub route_id: RouteId,
    pub nonce: FreshnessNonce,
    pub recipient_ops_pub: [u8; 32],
    pub vitality_snapshot: VitalityState,
    pub protocol_version: u8,
}

impl FlashTranscript {
    /// Hash using domain-separated BLAKE3.
    ///
    /// Identical field values always produce an identical hash (see
    /// `transcript_serialization_is_stable`). This property must be
    /// preserved across all future refactors.
    pub fn hash(&self) -> [u8; 32] {
        let vitality_byte: u8 = match &self.vitality_snapshot {
            VitalityState::Active => 0,
            VitalityState::Warm => 1,
            VitalityState::Dormant => 2,
            VitalityState::Suspended => 3,
            VitalityState::Severed => 4,
            VitalityState::Burned => 5,
        };

        let data = transcript_v1_bytes(
            &self.route_id.0,
            self.nonce.0,
            &self.recipient_ops_pub,
            vitality_byte,
            self.protocol_version,
        );
        scp_derive_key(DomainLabel::Transcript, &data)
    }
}
