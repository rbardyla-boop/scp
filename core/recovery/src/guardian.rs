use serde::{Deserialize, Serialize};

/// A guardian is identified only by their operational public key.
/// Guardians must never learn the user's relationship graph or recovery semantics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Guardian {
    pub ops_pub: [u8; 32],
}

/// Event triggering guardian binding (Identity::GuardianBind).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuardianBind {
    pub guardians: Vec<Guardian>,
    /// Minimum number of guardians required for threshold recovery (3–7).
    pub threshold: u8,
}

impl GuardianBind {
    /// Bind guardians and distribute blinded shards.
    /// Guardians receive encrypted opaque blobs — they cannot learn what they hold.
    pub fn execute(guardians: Vec<Guardian>, _threshold: u8) -> Result<Self, RecoveryError> {
        assert!(
            (3..=7).contains(&(guardians.len() as u8)),
            "SCP requires 3–7 guardians"
        );
        todo!("Phase 4: blinded shard distribution to guardians")
    }
}

#[derive(Debug, thiserror::Error)]
pub enum RecoveryError {
    #[error("insufficient guardians: need at least {0}")]
    BelowThreshold(u8),
    #[error("shard reconstruction failed")]
    ReconstructionFailed,
    #[error("identity shedding failed")]
    SheddingFailed,
}
