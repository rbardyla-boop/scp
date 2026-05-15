use crate::rotation::RotationEvent;
use serde::{Deserialize, Serialize};

/// Cryptographic proof that an operational key descends from a root anchor.
///
/// Verification checks:
/// 1. Every RotationEvent in the chain is signed by root_pub.
/// 2. The chain is contiguous (event[i].new_ops_pub == event[i+1].old_ops_pub).
/// 3. The final event's new_ops_pub matches current_ops_pub.
///
/// Proving the genesis link (that chain[0].old_ops_pub was the original ops key)
/// requires a ledger lookup — this struct verifies internal consistency only.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContinuityProof {
    pub root_pub: [u8; 32],
    /// Ordered rotation events from the earliest rotation to the most recent.
    pub rotation_chain: Vec<RotationEvent>,
    pub current_ops_pub: [u8; 32],
}

impl ContinuityProof {
    /// Verify internal consistency of the rotation chain.
    ///
    /// Returns `false` for an empty chain (no rotations → no proof; use the
    /// ledger genesis record directly to verify the initial ops key).
    pub fn verify(&self) -> bool {
        if self.rotation_chain.is_empty() {
            return false;
        }

        let mut expected_next_old: Option<[u8; 32]> = None;

        for event in &self.rotation_chain {
            // Every event must be signed by root_pub.
            if !event.verify(&self.root_pub) {
                return false;
            }

            // Chain must be contiguous.
            if let Some(expected) = expected_next_old {
                if event.old_ops_pub != expected {
                    return false;
                }
            }

            expected_next_old = Some(event.new_ops_pub);
        }

        // Final key in chain must match the claimed current ops key.
        let last = self.rotation_chain.last().unwrap();
        last.new_ops_pub == self.current_ops_pub
    }
}
