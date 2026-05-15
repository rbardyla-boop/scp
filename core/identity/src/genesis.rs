use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// Trigger to generate a new sovereign identity.
pub struct IdentityGenesis;

/// All artifacts produced during Identity::Genesis.
///
/// Root keys never leave the hardware enclave after genesis.
/// Operational keys are derived for active communication.
#[derive(Zeroize)]
#[zeroize(drop)]
pub struct GenesisArtifacts {
    pub k_root_pub: [u8; 32],
    pub k_root_priv: [u8; 32],
    pub k_ops_pub: [u8; 32],
    pub k_ops_priv: [u8; 32],
    pub recovery_policy_hash: [u8; 32],
    pub continuity_commitment: [u8; 32],
}

/// Serializable public portion of a genesis (safe to persist / publish).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityRecord {
    pub k_root_pub: [u8; 32],
    pub k_ops_pub: [u8; 32],
    pub recovery_policy_hash: [u8; 32],
    pub continuity_commitment: [u8; 32],
}

impl IdentityGenesis {
    /// Run the full genesis flow — enclave key generation, derivation, policy hash.
    pub fn execute() -> Result<GenesisArtifacts, IdentityError> {
        todo!("Phase 0: secure-enclave genesis flow")
    }
}

#[derive(Debug, thiserror::Error)]
pub enum IdentityError {
    #[error("enclave key generation failed")]
    EnclaveFailure,
    #[error("derivation error")]
    DerivationError,
}
