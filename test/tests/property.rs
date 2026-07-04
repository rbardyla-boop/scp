// Phase 10 property-based tests.
//
// Invariants verified for all inputs, not just handpicked examples:
//   Wire format length guarantees, transcript layout doctrine,
//   ReplayWindow bitmap arithmetic, framing roundtrip identity,
//   and state commitment sensitivity.

use proptest::prelude::*;
use proptest::collection::vec as prop_vec;
use scp_transport::{flash::{PublishedHandshakeKey, RecipientState}, ReplayWindow};
use scp_vitality::VitalityState;
use scp_wire_format::{
    framing::{decode_noise_length, decode_tcp_length, encode_noise_frame, encode_tcp_frame},
    signing::{handshake_sig_message, registration_message, rotation_message},
    transcript::{transcript_v1_bytes, transcript_v2_bytes},
};

fn vitality_from_byte(b: u8) -> VitalityState {
    match b % 6 {
        0 => VitalityState::Active,
        1 => VitalityState::Warm,
        2 => VitalityState::Dormant,
        3 => VitalityState::Suspended,
        4 => VitalityState::Severed,
        _ => VitalityState::Burned,
    }
}

// ── §1. Wire Format Length Invariants ─────────────────────────────────────────
//
// These tests assert that fixed-length wire format functions return
// exactly the documented byte count for any input — not just fixed examples.

proptest! {
    #[test]
    fn transcript_v1_length_is_always_63(
        route_id in any::<[u8; 16]>(),
        nonce in any::<u64>(),
        ops_pub in any::<[u8; 32]>(),
        vitality in any::<u8>(),
        version in any::<u8>(),
    ) {
        let bytes = transcript_v1_bytes(&route_id, nonce, &ops_pub, vitality, version);
        prop_assert_eq!(bytes.len(), 63);
    }
}

proptest! {
    #[test]
    fn transcript_v1_header_bytes_are_fixed(
        route_id in any::<[u8; 16]>(),
        nonce in any::<u64>(),
        ops_pub in any::<[u8; 32]>(),
        vitality in any::<u8>(),
        version in any::<u8>(),
    ) {
        let bytes = transcript_v1_bytes(&route_id, nonce, &ops_pub, vitality, version);
        prop_assert_eq!(&bytes[0..4], b"SCPt", "magic bytes must always be 'SCPt'");
        prop_assert_eq!(bytes[4], 0x01u8, "v1 format byte must always be 0x01");
    }
}

proptest! {
    #[test]
    fn transcript_v2_length_is_always_95(
        route_id in any::<[u8; 16]>(),
        nonce in any::<u64>(),
        ops_pub in any::<[u8; 32]>(),
        vitality in any::<u8>(),
        version in any::<u8>(),
        sender_ephemeral_pub in any::<[u8; 32]>(),
    ) {
        let bytes = transcript_v2_bytes(
            &route_id, nonce, &ops_pub, vitality, version, &sender_ephemeral_pub,
        );
        prop_assert_eq!(bytes.len(), 95);
    }
}

proptest! {
    #[test]
    fn transcript_v2_format_byte_differs_from_v1(
        route_id in any::<[u8; 16]>(),
        nonce in any::<u64>(),
        ops_pub in any::<[u8; 32]>(),
        vitality in any::<u8>(),
        version in any::<u8>(),
    ) {
        let v1 = transcript_v1_bytes(&route_id, nonce, &ops_pub, vitality, version);
        let v2 = transcript_v2_bytes(&route_id, nonce, &ops_pub, vitality, version, &[0u8; 32]);
        prop_assert_eq!(v1[4], 0x01u8, "v1 format byte must be 0x01");
        prop_assert_eq!(v2[4], 0x02u8, "v2 format byte must be 0x02");
        prop_assert_ne!(v1.as_slice(), &v2[..63],
            "v1 and v2 must differ at format byte for any input");
    }
}

proptest! {
    #[test]
    fn signing_message_lengths_are_always_correct(
        a in any::<[u8; 32]>(),
        b in any::<[u8; 32]>(),
        c in any::<[u8; 32]>(),
        nonce in any::<u64>(),
    ) {
        prop_assert_eq!(handshake_sig_message(&a, nonce).len(), 67);
        prop_assert_eq!(registration_message(&a, &b, &c).len(), 96);
        prop_assert_eq!(rotation_message(&a, &b, nonce).len(), 72);
    }
}

// ── §2. ReplayWindow Invariants ───────────────────────────────────────────────
//
// The replay window uses a 64-position bitmap. These properties hold for
// any nonce values, not just the fixed examples in adversarial.rs.

proptest! {
    #[test]
    fn replay_window_accepts_strictly_increasing_nonces(
        start in 0u64..(u64::MAX - 100),
        count in 1usize..=20,
    ) {
        let mut window = ReplayWindow::new();
        for i in 0u64..count as u64 {
            prop_assert!(
                window.check_and_insert(start + i),
                "strictly increasing nonce {} must be accepted", start + i
            );
        }
    }
}

proptest! {
    #[test]
    fn replay_window_rejects_immediate_replay(nonce in any::<u64>()) {
        let mut window = ReplayWindow::new();
        prop_assert!(window.check_and_insert(nonce), "first insertion must be accepted");
        prop_assert!(!window.check_and_insert(nonce), "immediate replay must be rejected");
    }
}

proptest! {
    #[test]
    fn replay_window_boundary_holds_for_arbitrary_base(base in 64u64..u64::MAX) {
        // Offset 63 (last valid slot) — must be accepted.
        let mut window_in = ReplayWindow::new();
        prop_assert!(window_in.check_and_insert(base));
        prop_assert!(window_in.check_and_insert(base - 63),
            "nonce at offset 63 (last valid slot) must be accepted for base {base}");

        // Offset 64 (first stale slot) — must be rejected.
        let mut window_out = ReplayWindow::new();
        prop_assert!(window_out.check_and_insert(base));
        prop_assert!(!window_out.check_and_insert(base - 64),
            "nonce at offset 64 (first stale slot) must be rejected for base {base}");
    }
}

// ── §3. Transcript Semantic Extension Invariant ───────────────────────────────
//
// V2 must be a strict semantic extension of V1: all shared semantic fields
// occupy the identical byte offsets in both versions. This prevents future
// contributors from accidentally diverging shared field ordering.

proptest! {
    #[test]
    fn transcript_v1_is_prefix_of_v2_except_format_byte(
        route_id in any::<[u8; 16]>(),
        nonce in any::<u64>(),
        ops_pub in any::<[u8; 32]>(),
        vitality in any::<u8>(),
        version in any::<u8>(),
        sender_ephemeral_pub in any::<[u8; 32]>(),
    ) {
        let v1 = transcript_v1_bytes(&route_id, nonce, &ops_pub, vitality, version);
        let v2 = transcript_v2_bytes(
            &route_id, nonce, &ops_pub, vitality, version, &sender_ephemeral_pub,
        );
        // Magic bytes are shared.
        prop_assert_eq!(&v1[0..4], &v2[0..4], "magic bytes must agree between v1 and v2");
        // Format bytes must differ (this encodes the version distinction).
        prop_assert_eq!(v1[4], 0x01u8);
        prop_assert_eq!(v2[4], 0x02u8);
        // All shared semantic fields (route_id, nonce, ops_pub, vitality, version)
        // must occupy identical byte offsets in both formats.
        prop_assert_eq!(&v1[5..63], &v2[5..63],
            "shared semantic fields must be byte-for-byte identical across v1 and v2");
        // V2 extension field (sender_ephemeral_pub) is at the exact documented offset.
        prop_assert_eq!(&v2[63..95], &sender_ephemeral_pub[..],
            "v2 extension field must be at bytes [63..95]");
    }
}

// ── §4. Framing Roundtrip Identity ────────────────────────────────────────────
//
// encode → decode must recover the original payload for any byte sequence.
// This locks the encode/decode contract against future endian or length drift.

proptest! {
    #[test]
    fn wire_tcp_frame_roundtrip(payload in prop_vec(any::<u8>(), 0..=1000)) {
        let frame = encode_tcp_frame(&payload);
        prop_assert_eq!(frame.len(), 4 + payload.len(),
            "TCP frame length must equal 4-byte header + payload");
        let header: [u8; 4] = frame[..4].try_into().unwrap();
        let decoded_len = decode_tcp_length(&header);
        prop_assert_eq!(decoded_len, payload.len(),
            "TCP decoded length must match original payload length");
        prop_assert_eq!(&frame[4..], payload.as_slice(),
            "TCP payload bytes must be preserved verbatim after the header");
    }
}

proptest! {
    #[test]
    fn wire_noise_frame_roundtrip(payload in prop_vec(any::<u8>(), 0..=1000)) {
        let frame = encode_noise_frame(&payload);
        prop_assert_eq!(frame.len(), 2 + payload.len(),
            "Noise frame length must equal 2-byte header + payload");
        let header: [u8; 2] = frame[..2].try_into().unwrap();
        let decoded_len = decode_noise_length(&header);
        prop_assert_eq!(decoded_len, payload.len(),
            "Noise decoded length must match original payload length");
        prop_assert_eq!(&frame[2..], payload.as_slice(),
            "Noise payload bytes must be preserved verbatim after the header");
    }
}

// ── §5. Commitment Properties ─────────────────────────────────────────────────
//
// RecipientState::commitment() must be non-zero for any valid state, and
// must change when any meaningful field changes.

proptest! {
    #[test]
    fn commitment_is_always_nonzero(
        ops_pub in any::<[u8; 32]>(),
        vitality_byte in any::<u8>(),
        has_ephemeral in any::<bool>(),
        eph_pub in any::<[u8; 32]>(),
        eph_expires in any::<u64>(),
    ) {
        let state = RecipientState {
            ops_pub,
            vitality: vitality_from_byte(vitality_byte),
            routing_hints: vec![],
            handshake_ephemeral: if has_ephemeral {
                Some(PublishedHandshakeKey { pub_key: eph_pub, sig: [0u8; 64], expires_at: eph_expires })
            } else {
                None
            },
        };
        prop_assert_ne!(state.commitment(), [0u8; 32],
            "commitment must be non-zero for any valid RecipientState");
    }
}

proptest! {
    #[test]
    fn commitment_changes_when_ops_pub_changes(
        ops_pub_a in any::<[u8; 32]>(),
        mutation_index in 0usize..32,
        mutation_xor in 1u8..=255u8,
    ) {
        let mut ops_pub_b = ops_pub_a;
        ops_pub_b[mutation_index] ^= mutation_xor; // always a different value (xor ≥ 1)

        let state_a = RecipientState {
            ops_pub: ops_pub_a, vitality: VitalityState::Active,
            routing_hints: vec![], handshake_ephemeral: None,
        };
        let state_b = RecipientState {
            ops_pub: ops_pub_b, vitality: VitalityState::Active,
            routing_hints: vec![], handshake_ephemeral: None,
        };
        prop_assert_ne!(state_a.commitment(), state_b.commitment(),
            "any single-byte mutation in ops_pub must change the commitment");
    }
}
