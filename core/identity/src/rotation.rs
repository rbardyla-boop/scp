use serde::{Deserialize, Serialize};

/// Signals that an operational key rotation should occur.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotationEvent {
    /// The public key being retired.
    pub old_ops_pub: [u8; 32],
    /// The new operational public key.
    pub new_ops_pub: [u8; 32],
    /// Root-key signature (Ed25519, 64 bytes) over (old_ops_pub || new_ops_pub || timestamp_nonce).
    pub root_sig: Vec<u8>,
    /// Monotonic timestamp nonce to prevent replay.
    pub nonce: u64,
}

impl RotationEvent {
    /// Produce a signed rotation event using the root keypair from the enclave.
    pub fn sign(_old_ops_pub: [u8; 32], _new_ops_pub: [u8; 32]) -> Result<Self, RotationError> {
        todo!("Phase 0: root-signed operational key rotation")
    }

    /// Verify this event's root signature.
    pub fn verify(&self, _root_pub: &[u8; 32]) -> bool {
        todo!("Phase 0: verify rotation event signature")
    }
}

#[derive(Debug, thiserror::Error)]
pub enum RotationError {
    #[error("enclave signing failed")]
    EnclaveFailed,
}
