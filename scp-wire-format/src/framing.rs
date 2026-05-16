use crate::constants::{NOISE_FRAME_HEADER_LEN, TCP_FRAME_HEADER_LEN};

/// Encode a payload into a TCP relay frame.
///
/// Frame format (protocol-stable):
///   [4] payload length as u32 little-endian
///   [N] payload bytes
///
/// Note: TCP uses LE u32; Noise uses BE u16. Inconsistency preserved to avoid
/// a breaking protocol change. Unification is planned for Phase 9.
pub fn encode_tcp_frame(payload: &[u8]) -> Vec<u8> {
    let len = payload.len() as u32;
    let mut frame = Vec::with_capacity(TCP_FRAME_HEADER_LEN + payload.len());
    frame.extend_from_slice(&len.to_le_bytes());
    frame.extend_from_slice(payload);
    frame
}

/// Parse the payload length from a TCP frame header.
pub fn decode_tcp_length(header: &[u8; 4]) -> usize {
    u32::from_le_bytes(*header) as usize
}

/// Encode a Noise message into a length-prefixed frame.
///
/// Frame format (Noise standard, protocol-stable):
///   [2] message length as u16 big-endian
///   [N] message bytes
///
/// Note: TCP uses LE u32; Noise uses BE u16. Inconsistency preserved to avoid
/// a breaking protocol change. Unification is planned for Phase 9.
pub fn encode_noise_frame(msg: &[u8]) -> Vec<u8> {
    let len = msg.len() as u16;
    let mut frame = Vec::with_capacity(NOISE_FRAME_HEADER_LEN + msg.len());
    frame.extend_from_slice(&len.to_be_bytes());
    frame.extend_from_slice(msg);
    frame
}

/// Parse the message length from a Noise frame header.
pub fn decode_noise_length(header: &[u8; 2]) -> usize {
    u16::from_be_bytes(*header) as usize
}
