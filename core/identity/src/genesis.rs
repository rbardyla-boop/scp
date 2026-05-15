use scp_cryptography::keys::{hash, KeyPair};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// Trigger to generate a new sovereign identity.
pub struct IdentityGenesis;

/// All artifacts produced during Identity::Genesis.
///
/// Root keys must be stored in the hardware enclave immediately after genesis.
/// Operational keys rotate frequently; root keys only sign lineage continuity.
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

/// Serializable public portion of a genesis (safe to publish to the ledger).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityRecord {
    pub k_root_pub: [u8; 32],
    pub k_ops_pub: [u8; 32],
    pub recovery_policy_hash: [u8; 32],
    pub continuity_commitment: [u8; 32],
}

impl IdentityGenesis {
    /// Run the full genesis flow:
    /// 1. Generate root keypair (stays in enclave after production deployment)
    /// 2. Generate independent operational keypair
    /// 3. Hash the default recovery policy
    /// 4. Compute continuity commitment = BLAKE3(root_pub || ops_pub || recovery_policy_hash)
    pub fn execute() -> Result<GenesisArtifacts, IdentityError> {
        let root = KeyPair::generate();
        let ops = KeyPair::generate();

        let recovery_policy_hash = hash(b"scp:recovery:3-of-5:v1");

        let mut commitment_input = Vec::with_capacity(96);
        commitment_input.extend_from_slice(&root.public);
        commitment_input.extend_from_slice(&ops.public);
        commitment_input.extend_from_slice(&recovery_policy_hash);
        let continuity_commitment = hash(&commitment_input);

        Ok(GenesisArtifacts {
            k_root_pub: root.public,
            k_root_priv: root.secret,
            k_ops_pub: ops.public,
            k_ops_priv: ops.secret,
            recovery_policy_hash,
            continuity_commitment,
        })
    }
}

#[derive(Debug, thiserror::Error)]
pub enum IdentityError {
    #[error("enclave key generation failed")]
    EnclaveFailure,
    #[error("derivation error")]
    DerivationError,
}
