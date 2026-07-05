use crate::constants::{
    TRANSCRIPT_MAGIC, TRANSCRIPT_V1_FORMAT, TRANSCRIPT_V1_LEN, TRANSCRIPT_V2_FORMAT,
    TRANSCRIPT_V2_LEN,
};

/// Serialize a v1 transcript to its canonical 63-byte form.
///
/// Field layout (protocol-stable):
///   [4]  TRANSCRIPT_MAGIC ("SCPt")
///   [1]  TRANSCRIPT_V1_FORMAT (0x01)
///   [16] route_id
///   [8]  nonce (u64, little-endian)
///   [32] recipient_ops_pub
///   [1]  vitality_byte (use VITALITY_* constants)
///   [1]  protocol_version
pub fn transcript_v1_bytes(
    route_id: &[u8; 16],
    nonce: u64,
    recipient_ops_pub: &[u8; 32],
    vitality_byte: u8,
    protocol_version: u8,
) -> [u8; TRANSCRIPT_V1_LEN] {
    let mut data = [0u8; TRANSCRIPT_V1_LEN];
    data[0..4].copy_from_slice(TRANSCRIPT_MAGIC);
    data[4] = TRANSCRIPT_V1_FORMAT;
    data[5..21].copy_from_slice(route_id);
    data[21..29].copy_from_slice(&nonce.to_le_bytes());
    data[29..61].copy_from_slice(recipient_ops_pub);
    data[61] = vitality_byte;
    data[62] = protocol_version;
    data
}

/// Serialize a v2 transcript to its canonical 95-byte form.
///
/// Field layout (protocol-stable):
///   [63] Same as v1 but format byte = TRANSCRIPT_V2_FORMAT (0x02)
///   [32] sender_ephemeral_pub (X25519 public key)
pub fn transcript_v2_bytes(
    route_id: &[u8; 16],
    nonce: u64,
    recipient_ops_pub: &[u8; 32],
    vitality_byte: u8,
    protocol_version: u8,
    sender_ephemeral_pub: &[u8; 32],
) -> [u8; TRANSCRIPT_V2_LEN] {
    let mut data = [0u8; TRANSCRIPT_V2_LEN];
    data[0..4].copy_from_slice(TRANSCRIPT_MAGIC);
    data[4] = TRANSCRIPT_V2_FORMAT;
    data[5..21].copy_from_slice(route_id);
    data[21..29].copy_from_slice(&nonce.to_le_bytes());
    data[29..61].copy_from_slice(recipient_ops_pub);
    data[61] = vitality_byte;
    data[62] = protocol_version;
    data[63..95].copy_from_slice(sender_ephemeral_pub);
    data
}
