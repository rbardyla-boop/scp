use serde::{Deserialize, Serialize};

/// Substrate pallet adapter for the SCP state layer.
///
/// Stores: identity lineage, consent state, tunnel authorization, revocations.
/// Does NOT store: messages, files, social graphs, payloads.
pub struct SubstrateLedger;

/// Minimal on-chain identity record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LedgerIdentityRecord {
    pub k_root_pub: [u8; 32],
    pub k_ops_pub: [u8; 32],
    pub continuity_commitment: [u8; 32],
}

impl SubstrateLedger {
    pub fn new() -> Self {
        Self
    }

    /// Publish a new identity record to the ledger.
    pub fn register_identity(&self, _record: &LedgerIdentityRecord) -> Result<(), LedgerError> {
        todo!("Phase 1: Substrate extrinsic — register identity")
    }

    /// Publish a key rotation event.
    pub fn rotate_key(&self, _old_ops_pub: &[u8; 32], _new_ops_pub: &[u8; 32], _root_sig: &[u8; 64]) -> Result<(), LedgerError> {
        todo!("Phase 1: Substrate extrinsic — rotate operational key")
    }

    /// Revoke an identity or tunnel authorization.
    pub fn revoke(&self, _k_ops_pub: &[u8; 32], _root_sig: &[u8; 64]) -> Result<(), LedgerError> {
        todo!("Phase 1: Substrate extrinsic — revoke identity")
    }

    /// Query current operational key for a root public key.
    pub fn query_current_ops_key(&self, _k_root_pub: &[u8; 32]) -> Result<[u8; 32], LedgerError> {
        todo!("Phase 1: Substrate storage query")
    }
}

#[derive(Debug, thiserror::Error)]
pub enum LedgerError {
    #[error("identity not found")]
    NotFound,
    #[error("invalid signature")]
    InvalidSignature,
    #[error("ledger connection failed")]
    ConnectionFailed,
}
