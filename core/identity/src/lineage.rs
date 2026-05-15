use serde::{Deserialize, Serialize};

/// Cryptographic proof that an operational key descends from a root anchor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContinuityProof {
    pub root_pub: [u8; 32],
    /// Ordered chain of rotation events (root → ... → current ops key). Each entry is a 64-byte Ed25519 signature.
    pub rotation_chain: Vec<Vec<u8>>,
    pub current_ops_pub: [u8; 32],
}

impl ContinuityProof {
    /// Verify the entire rotation chain from root to the current operational key.
    pub fn verify(&self) -> bool {
        todo!("Phase 1: lineage chain verification")
    }
}
