use crate::constants::{
    HANDSHAKE_SIG_MSG_LEN, HANDSHAKE_SIG_PREFIX, REGISTRATION_MSG_LEN, ROTATION_MSG_LEN,
};

/// Canonical signing message for a published handshake ephemeral (67 bytes).
///
/// Format (protocol-stable):
///   [27] "scp:handshake-ephemeral:v1:"
///   [32] pub_key (X25519 public key)
///   [8]  expires_at (u64, little-endian)
pub fn handshake_sig_message(pub_key: &[u8; 32], expires_at: u64) -> [u8; HANDSHAKE_SIG_MSG_LEN] {
    let mut msg = [0u8; HANDSHAKE_SIG_MSG_LEN];
    msg[0..27].copy_from_slice(HANDSHAKE_SIG_PREFIX);
    msg[27..59].copy_from_slice(pub_key);
    msg[59..67].copy_from_slice(&expires_at.to_le_bytes());
    msg
}

/// Canonical message for identity registration (96 bytes).
///
/// Format (protocol-stable):
///   [32] k_root_pub
///   [32] k_ops_pub
///   [32] recovery_policy_hash
pub fn registration_message(
    k_root_pub: &[u8; 32],
    k_ops_pub: &[u8; 32],
    recovery_policy_hash: &[u8; 32],
) -> [u8; REGISTRATION_MSG_LEN] {
    let mut msg = [0u8; REGISTRATION_MSG_LEN];
    msg[0..32].copy_from_slice(k_root_pub);
    msg[32..64].copy_from_slice(k_ops_pub);
    msg[64..96].copy_from_slice(recovery_policy_hash);
    msg
}

/// Canonical message for key rotation (72 bytes).
///
/// Format (protocol-stable):
///   [32] old_ops_pub
///   [32] new_ops_pub
///   [8]  nonce (u64, little-endian)
pub fn rotation_message(
    old_ops_pub: &[u8; 32],
    new_ops_pub: &[u8; 32],
    nonce: u64,
) -> [u8; ROTATION_MSG_LEN] {
    let mut msg = [0u8; ROTATION_MSG_LEN];
    msg[0..32].copy_from_slice(old_ops_pub);
    msg[32..64].copy_from_slice(new_ops_pub);
    msg[64..72].copy_from_slice(&nonce.to_le_bytes());
    msg
}

/// Input bytes for tunnel consent hash — caller applies BLAKE3.
///
/// Parties sorted lexicographically (a ≤ b) before concatenation.
/// Format: "scp:tunnel:v1:" || lo_pub || hi_pub
pub fn tunnel_consent_input(a: &[u8; 32], b: &[u8; 32]) -> Vec<u8> {
    let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
    let mut msg = b"scp:tunnel:v1:".to_vec();
    msg.extend_from_slice(lo);
    msg.extend_from_slice(hi);
    msg
}
