pub mod constants;
pub mod framing;
pub mod signing;
pub mod transcript;
pub mod version;

#[cfg(test)]
mod tests {
    use super::*;

    // ── Transcript ────────────────────────────────────────────────────────────

    #[test]
    fn transcript_v1_bytes_is_63_bytes() {
        let data = transcript::transcript_v1_bytes(&[0u8; 16], 0, &[0u8; 32], 0, 1);
        assert_eq!(data.len(), constants::TRANSCRIPT_V1_LEN);
        assert_eq!(&data[0..4], constants::TRANSCRIPT_MAGIC.as_slice());
        assert_eq!(data[4], constants::TRANSCRIPT_V1_FORMAT);
    }

    #[test]
    fn transcript_v2_bytes_is_95_bytes() {
        let data = transcript::transcript_v2_bytes(&[0u8; 16], 0, &[0u8; 32], 0, 2, &[0u8; 32]);
        assert_eq!(data.len(), constants::TRANSCRIPT_V2_LEN);
        assert_eq!(data[4], constants::TRANSCRIPT_V2_FORMAT);
    }

    #[test]
    fn transcript_v1_nonce_at_positions_21_to_28() {
        let data = transcript::transcript_v1_bytes(&[0u8; 16], 1u64, &[0u8; 32], 0, 1);
        assert_eq!(&data[21..29], &1u64.to_le_bytes());
        // nonce=256 places 0x00,0x01,... at byte 21 — must differ from nonce=1
        let data256 = transcript::transcript_v1_bytes(&[0u8; 16], 256u64, &[0u8; 32], 0, 1);
        assert_ne!(
            &data[21..29],
            &data256[21..29],
            "nonce endianness must produce distinct bytes"
        );
    }

    #[test]
    fn transcript_v1_v2_differ_in_format_byte_only_for_identical_input() {
        let v1 = transcript::transcript_v1_bytes(&[0u8; 16], 0, &[0u8; 32], 0, 1);
        let v2 = transcript::transcript_v2_bytes(&[0u8; 16], 0, &[0u8; 32], 0, 1, &[0u8; 32]);
        assert_eq!(&v1[0..4], &v2[0..4], "magic must be identical");
        assert_eq!(v1[4], 0x01);
        assert_eq!(v2[4], 0x02);
        assert_ne!(v1[4], v2[4], "format byte must differ between v1 and v2");
    }

    // ── Signing ───────────────────────────────────────────────────────────────

    #[test]
    fn handshake_sig_message_is_67_bytes() {
        let msg = signing::handshake_sig_message(&[0u8; 32], 0);
        assert_eq!(msg.len(), 67);
    }

    #[test]
    fn handshake_sig_message_prefix_is_canonical() {
        let msg = signing::handshake_sig_message(&[0u8; 32], 0);
        assert_eq!(&msg[0..27], constants::HANDSHAKE_SIG_PREFIX.as_slice());
    }

    #[test]
    fn handshake_sig_message_expires_at_is_little_endian() {
        let msg = signing::handshake_sig_message(&[0u8; 32], 999u64);
        assert_eq!(&msg[59..67], &999u64.to_le_bytes());
    }

    #[test]
    fn registration_message_is_96_bytes() {
        let msg = signing::registration_message(&[0u8; 32], &[0u8; 32], &[0u8; 32]);
        assert_eq!(msg.len(), 96);
    }

    #[test]
    fn rotation_message_is_72_bytes() {
        let msg = signing::rotation_message(&[0u8; 32], &[0u8; 32], 0);
        assert_eq!(msg.len(), 72);
    }

    #[test]
    fn rotation_message_nonce_is_little_endian() {
        let nonce = 0x0102030405060708u64;
        let msg = signing::rotation_message(&[0u8; 32], &[0u8; 32], nonce);
        assert_eq!(&msg[64..72], &nonce.to_le_bytes());
    }

    // ── Framing ───────────────────────────────────────────────────────────────

    #[test]
    fn encode_tcp_frame_prepends_le_u32_length() {
        let payload = b"hello";
        let frame = framing::encode_tcp_frame(payload);
        assert_eq!(&frame[0..4], &(5u32).to_le_bytes());
        assert_eq!(&frame[4..], payload.as_slice());
    }

    #[test]
    fn decode_tcp_length_roundtrips_with_encode() {
        let payload = b"test payload";
        let frame = framing::encode_tcp_frame(payload);
        let len = framing::decode_tcp_length(frame[0..4].try_into().unwrap());
        assert_eq!(len, payload.len());
    }

    #[test]
    fn encode_noise_frame_prepends_be_u16_length() {
        let msg = b"noise";
        let frame = framing::encode_noise_frame(msg);
        assert_eq!(&frame[0..2], &(5u16).to_be_bytes());
        assert_eq!(&frame[2..], msg.as_slice());
    }

    #[test]
    fn decode_noise_length_roundtrips_with_encode() {
        let msg = b"noise msg";
        let frame = framing::encode_noise_frame(msg);
        let len = framing::decode_noise_length(frame[0..2].try_into().unwrap());
        assert_eq!(len, msg.len());
    }

    #[test]
    fn tcp_and_noise_frame_headers_are_different_lengths() {
        // TCP: 4-byte LE u32; Noise: 2-byte BE u16.
        // Inconsistency preserved — unification deferred to Phase 9.
        assert_eq!(constants::TCP_FRAME_HEADER_LEN, 4);
        assert_eq!(constants::NOISE_FRAME_HEADER_LEN, 2);
        assert_ne!(
            constants::TCP_FRAME_HEADER_LEN,
            constants::NOISE_FRAME_HEADER_LEN
        );
    }

    // ── Version ───────────────────────────────────────────────────────────────

    #[test]
    fn wire_version_negotiate_returns_min() {
        use version::WireVersion;
        assert_eq!(
            WireVersion::negotiate(WireVersion::V1, WireVersion::V1),
            WireVersion::V1
        );
    }

    #[test]
    fn wire_version_current_is_v1() {
        assert_eq!(version::WireVersion::current(), version::WireVersion::V1);
    }
}
