use crate::guardian::RecoveryError;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// An encrypted, blinded shard of the recovery secret.
/// Guardians hold this without knowing its meaning or origin.
#[derive(Debug, Clone, Serialize, Deserialize, Zeroize)]
#[zeroize(drop)]
pub struct BlindedShard(pub Vec<u8>);

/// Reconstruct an identity from threshold-many blinded shards.
///
/// Recovery flow (spec §8.3):
/// 1. Generate temporary recovery identity
/// 2. Publish blinded continuity claim
/// 3. Guardians release encrypted shards
/// 4. Threshold reconstruction
/// 5. Identity shedding triggered
pub fn reconstruct(shards: Vec<BlindedShard>) -> Result<RecoveredIdentity, RecoveryError> {
    todo!("Phase 4: Shamir / threshold reconstruction from guardian shards")
}

/// The output of a successful recovery — operational keys ready for rotation.
#[derive(Zeroize)]
#[zeroize(drop)]
pub struct RecoveredIdentity {
    pub k_ops_pub: [u8; 32],
    pub k_ops_priv: [u8; 32],
}
