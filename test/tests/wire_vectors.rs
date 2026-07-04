// Phase 10 canonical wire compatibility vectors.
//
// These tests are the objective compatibility target for any future independent
// SCP implementation. Each test anchors the exact byte output for fixed, human-readable
// inputs. Any change to field ordering, endian encoding, or field insertion is a
// breaking protocol change that MUST update these vectors.
//
// Standard input pattern (all vectors):
//   route_id              = [0x01; 16]
//   nonce                 = 0x0102030405060708u64
//   ops_pub / k_ops_pub   = [0x02; 32]
//   k_root_pub            = [0x01; 32]
//   recovery_policy_hash  = [0x03; 32]
//   sender_ephemeral_pub  = [0x03; 32]
//   old_ops_pub           = [0x01; 32]
//   new_ops_pub           = [0x02; 32]
//   pub_key (handshake)   = [0x01; 32]
//   expires_at            = 2000u64 (0x00000000000007D0)
//   vitality_byte         = 0x00 (VITALITY_ACTIVE)
//   protocol_version      = 0x01

use scp_wire_format::{
    framing::{decode_noise_length, decode_tcp_length, encode_noise_frame, encode_tcp_frame},
    signing::{handshake_sig_message, registration_message, rotation_message},
    transcript::{transcript_v1_bytes, transcript_v2_bytes},
};

// ── Transcript vectors ────────────────────────────────────────────────────────

#[test]
fn wire_transcript_v1_canonical_bytes() {
    // Layout (63 bytes):
    //   [0..4]   magic            = "SCPt" = [83, 67, 80, 116]
    //   [4]      format           = 0x01
    //   [5..21]  route_id         = [0x01; 16]
    //   [21..29] nonce            = 0x0102030405060708 LE = [8,7,6,5,4,3,2,1]
    //   [29..61] recipient_ops_pub = [0x02; 32]
    //   [61]     vitality_byte    = 0x00
    //   [62]     protocol_version = 0x01
    let got = transcript_v1_bytes(
        &[0x01u8; 16],
        0x0102030405060708u64,
        &[0x02u8; 32],
        0x00,
        0x01,
    );
    const EXPECTED: [u8; 63] = [
         83,  67,  80, 116,   1,   // magic + format
          1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,  // route_id
          8,   7,   6,   5,   4,   3,   2,   1,               // nonce LE
          2,   2,   2,   2,   2,   2,   2,   2,   2,   2,   2,   2,   2,   2,   2,   2,
          2,   2,   2,   2,   2,   2,   2,   2,   2,   2,   2,   2,   2,   2,   2,   2,  // ops_pub
          0,   1,                                               // vitality + version
    ];
    assert_eq!(got, EXPECTED,
        "transcript_v1 canonical bytes do not match — field ordering or encoding has changed");
}

#[test]
fn wire_transcript_v2_canonical_bytes() {
    // Layout (95 bytes): V1 layout with format byte 0x02 at [4], then
    //   [63..95] sender_ephemeral_pub = [0x03; 32]
    let got = transcript_v2_bytes(
        &[0x01u8; 16],
        0x0102030405060708u64,
        &[0x02u8; 32],
        0x00,
        0x01,
        &[0x03u8; 32],
    );
    const EXPECTED: [u8; 95] = [
         83,  67,  80, 116,   2,   // magic + v2 format byte
          1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,  // route_id
          8,   7,   6,   5,   4,   3,   2,   1,               // nonce LE
          2,   2,   2,   2,   2,   2,   2,   2,   2,   2,   2,   2,   2,   2,   2,   2,
          2,   2,   2,   2,   2,   2,   2,   2,   2,   2,   2,   2,   2,   2,   2,   2,  // ops_pub
          0,   1,                                               // vitality + version
          3,   3,   3,   3,   3,   3,   3,   3,   3,   3,   3,   3,   3,   3,   3,   3,
          3,   3,   3,   3,   3,   3,   3,   3,   3,   3,   3,   3,   3,   3,   3,   3,  // sender_ephemeral_pub
    ];
    assert_eq!(got, EXPECTED,
        "transcript_v2 canonical bytes do not match — field ordering or encoding has changed");
}

// ── Signing message vectors ───────────────────────────────────────────────────

#[test]
fn wire_handshake_sig_message_canonical_bytes() {
    // Layout (67 bytes):
    //   [0..27]  prefix     = "scp:handshake-ephemeral:v1:"  (27 ASCII bytes)
    //   [27..59] pub_key    = [0x01; 32]
    //   [59..67] expires_at = 2000 LE = [208, 7, 0, 0, 0, 0, 0, 0]
    let got = handshake_sig_message(&[0x01u8; 32], 2000u64);
    const EXPECTED: [u8; 67] = [
        // "scp:handshake-ephemeral:v1:"
        115, 99, 112, 58, 104, 97, 110, 100, 115, 104, 97, 107, 101, 45,
        101, 112, 104, 101, 109, 101, 114, 97, 108, 58, 118, 49, 58,
        // pub_key = [0x01; 32]
          1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,
          1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,
        // expires_at = 2000 LE
        208,   7,   0,   0,   0,   0,   0,   0,
    ];
    assert_eq!(got, EXPECTED,
        "handshake_sig_message canonical bytes do not match — \
         prefix string or encoding has changed");
}

#[test]
fn wire_registration_message_canonical_bytes() {
    // Layout (96 bytes):
    //   [0..32]  k_root_pub           = [0x01; 32]
    //   [32..64] k_ops_pub            = [0x02; 32]
    //   [64..96] recovery_policy_hash = [0x03; 32]
    let got = registration_message(&[0x01u8; 32], &[0x02u8; 32], &[0x03u8; 32]);
    const EXPECTED: [u8; 96] = [
          1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,
          1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,  // k_root_pub
          2,   2,   2,   2,   2,   2,   2,   2,   2,   2,   2,   2,   2,   2,   2,   2,
          2,   2,   2,   2,   2,   2,   2,   2,   2,   2,   2,   2,   2,   2,   2,   2,  // k_ops_pub
          3,   3,   3,   3,   3,   3,   3,   3,   3,   3,   3,   3,   3,   3,   3,   3,
          3,   3,   3,   3,   3,   3,   3,   3,   3,   3,   3,   3,   3,   3,   3,   3,  // recovery_policy_hash
    ];
    assert_eq!(got, EXPECTED,
        "registration_message canonical bytes do not match — field ordering has changed");
}

#[test]
fn wire_rotation_message_canonical_bytes() {
    // Layout (72 bytes):
    //   [0..32]  old_ops_pub = [0x01; 32]
    //   [32..64] new_ops_pub = [0x02; 32]
    //   [64..72] nonce       = 0x0102030405060708 LE = [8,7,6,5,4,3,2,1]
    let got = rotation_message(&[0x01u8; 32], &[0x02u8; 32], 0x0102030405060708u64);
    const EXPECTED: [u8; 72] = [
          1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,
          1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,  // old_ops_pub
          2,   2,   2,   2,   2,   2,   2,   2,   2,   2,   2,   2,   2,   2,   2,   2,
          2,   2,   2,   2,   2,   2,   2,   2,   2,   2,   2,   2,   2,   2,   2,   2,  // new_ops_pub
          8,   7,   6,   5,   4,   3,   2,   1,                                           // nonce LE
    ];
    assert_eq!(got, EXPECTED,
        "rotation_message canonical bytes do not match — field ordering or nonce encoding has changed");
}

// ── RNG-injection + derived-output golden vectors (Phase 8) ─────────────────
//
// Tests 1-2 verify the new `_with_rng` API. Tests 3-5 pin the derived output
// layer (KDF, commitment hash, raw DH) against fixed constant inputs.
// Any encoding change surfaces as a golden vector failure requiring an explicit
// protocol version bump.

// File-private zero-fill RNG for deterministic testing.
struct ZeroRng;
impl rand_core::RngCore for ZeroRng {
    fn next_u32(&mut self) -> u32 { 0 }
    fn next_u64(&mut self) -> u64 { 0 }
    fn fill_bytes(&mut self, dest: &mut [u8]) { dest.fill(0); }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        dest.fill(0);
        Ok(())
    }
}

#[test]
fn route_id_with_zero_rng_is_all_zeros() {
    // ZeroRng::fill_bytes writes all 0x00 — no hidden entropy source in generate_with_rng.
    use scp_transport::session::RouteId;
    let id = RouteId::generate_with_rng(&mut ZeroRng);
    assert_eq!(id.0, [0u8; 16],
        "RouteId::generate_with_rng with a zero-output RNG must produce [0u8;16] — \
         no hidden entropy injection");
}

#[test]
fn freshness_nonce_with_zero_rng_is_zero() {
    // ZeroRng::next_u64 returns 0 — FreshnessNonce delegates directly to next_u64.
    use scp_transport::session::FreshnessNonce;
    let nonce = FreshnessNonce::generate_with_rng(&mut ZeroRng);
    assert_eq!(nonce.0, 0,
        "FreshnessNonce::generate_with_rng with a zero-output RNG must produce 0 — \
         the value is exactly next_u64() with no extra transformation");
}

#[test]
fn transport_key_material_kdf_golden() {
    // Pins the exact 32-byte output of scp_derive_key(Transport, material)
    // for the canonical all-distinct input pattern.
    //
    // Input layout (96 bytes):
    //   [0..32]  ephemeral_seed    = [0x01; 32]
    //   [32..64] transcript_hash   = [0x02; 32]
    //   [64..96] recipient_binding = [0x03; 32]
    //
    // KDF: blake3::derive_key("scp:transport:v1:", &material)
    use scp_cryptography::{scp_derive_key, DomainLabel};
    let mut material = [0u8; 96];
    material[0..32].fill(0x01);
    material[32..64].fill(0x02);
    material[64..96].fill(0x03);
    let actual = scp_derive_key(DomainLabel::Transport, &material);
    const EXPECTED: [u8; 32] = [
         79,  77, 161,  42,  61, 167,  56,  16,  84, 171, 108, 162, 138, 130, 251,  39,
         15, 245, 136, 247, 101,  18,   2,   6, 210, 121, 187,  66,  30,  78,  36,  97,
    ];
    assert_eq!(actual, EXPECTED,
        "transport key derivation golden vector changed — any diff is a breaking KDF change \
         requiring an explicit protocol version bump");
}

#[test]
fn recipient_state_commitment_golden() {
    // Pins the BLAKE3 commitment of a canonical RecipientState.
    //
    // Encoding (v0):
    //   ops_pub(32)       = [0x01; 32]
    //   vitality_byte(1)  = 0x00 (VITALITY_ACTIVE)
    //   ephemeral_present = 0x00 (None)
    use scp_transport::flash::RecipientState;
    use scp_vitality::VitalityState;
    let state = RecipientState {
        ops_pub:             [0x01; 32],
        vitality:            VitalityState::Active,
        routing_hints:       vec![],
        handshake_ephemeral: None,
    };
    let actual = state.commitment();
    const EXPECTED: [u8; 32] = [
        173, 236, 206, 177, 209,  40, 240, 251,  47, 199, 158,  38,  80,   3, 142, 116,
        202, 129,  61,  65,  72,  82, 113, 204, 206, 237,  12,  56,  48,  99,   1, 208,
    ];
    assert_eq!(actual, EXPECTED,
        "RecipientState commitment golden vector changed — any diff is a breaking change to \
         the state commitment encoding (ops_pub | vitality_byte | ephemeral_present)");
}

#[test]
fn x25519_dh_golden_with_known_keys() {
    // Pins the raw X25519 DH output for a fixed (secret, public) pair.
    // The secret is clamped by the X25519 scalar multiply; this is the canonical
    // output before any KDF is applied.
    //
    // secret_bytes = [0x40; 32]  (non-zero, avoids low-order subgroup issues)
    // public_bytes = [0x09, 0x00, ..., 0x00]  (standard curve basepoint)
    use scp_cryptography::x25519_dh;
    let secret = [0x40u8; 32];
    let public = {
        let mut p = [0u8; 32];
        p[0] = 0x09; // standard basepoint u-coordinate
        p
    };
    let actual = x25519_dh(&secret, &public);
    const EXPECTED: [u8; 32] = [
        215, 181, 232,  29,  51, 110,  87, 139,  19, 184, 215,   6, 232,  45,   6,  30,
         48,  56, 201, 107, 206, 102, 205, 207,  80, 213, 102, 185, 109, 219, 186,  16,
    ];
    assert_eq!(actual, EXPECTED,
        "X25519 DH golden vector changed — the raw DH output for this key pair must be stable \
         across implementations for differential testing; any diff indicates a curve or clamping change");
}

// ── Framing vectors ───────────────────────────────────────────────────────────

#[test]
fn wire_tcp_frame_canonical_bytes() {
    // TCP frame: u32 LE length prefix + payload.
    // encode_tcp_frame(b"scp:v1"):
    //   length = 6 → LE u32: [0x06, 0x00, 0x00, 0x00]
    //   payload "scp:v1": [0x73, 0x63, 0x70, 0x3a, 0x76, 0x31]
    let payload = b"scp:v1";
    let frame = encode_tcp_frame(payload);
    const EXPECTED: &[u8] = &[6, 0, 0, 0, 0x73, 0x63, 0x70, 0x3a, 0x76, 0x31];
    assert_eq!(frame.as_slice(), EXPECTED,
        "TCP frame canonical bytes: 4-byte LE u32 length prefix + payload");

    let header: [u8; 4] = frame[..4].try_into().unwrap();
    assert_eq!(decode_tcp_length(&header), payload.len());
    assert_eq!(&frame[4..], payload.as_slice());
}

#[test]
fn wire_noise_frame_canonical_bytes() {
    // Noise frame: u16 BE length prefix + payload (Noise Protocol Framework standard).
    // encode_noise_frame(b"scp:v1"):
    //   length = 6 → BE u16: [0x00, 0x06]
    //   payload "scp:v1": [0x73, 0x63, 0x70, 0x3a, 0x76, 0x31]
    //
    // Note: TCP uses LE u32; Noise uses BE u16. This inconsistency is preserved.
    let payload = b"scp:v1";
    let frame = encode_noise_frame(payload);
    const EXPECTED: &[u8] = &[0, 6, 0x73, 0x63, 0x70, 0x3a, 0x76, 0x31];
    assert_eq!(frame.as_slice(), EXPECTED,
        "Noise frame canonical bytes: 2-byte BE u16 length prefix + payload");

    let header: [u8; 2] = frame[..2].try_into().unwrap();
    assert_eq!(decode_noise_length(&header), payload.len());
    assert_eq!(&frame[2..], payload.as_slice());
}
