use serde::{Deserialize, Serialize};

/// Cosmos SDK module adapter for the SCP state layer.
/// Implements the same interface as SubstrateLedger — backend-agnostic by design (spec §8).
pub struct CosmosLedger;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LedgerIdentityRecord {
    pub k_root_pub: [u8; 32],
    pub k_ops_pub: [u8; 32],
    pub continuity_commitment: [u8; 32],
}

impl CosmosLedger {
    pub fn new() -> Self {
        Self
    }

    pub fn register_identity(&self, _record: &LedgerIdentityRecord) -> Result<(), LedgerError> {
        todo!("Phase 1: Cosmos SDK tx — register identity")
    }

    pub fn rotate_key(&self, _old_ops_pub: &[u8; 32], _new_ops_pub: &[u8; 32], _root_sig: &[u8; 64]) -> Result<(), LedgerError> {
        todo!("Phase 1: Cosmos SDK tx — rotate operational key")
    }

    pub fn revoke(&self, _k_ops_pub: &[u8; 32], _root_sig: &[u8; 64]) -> Result<(), LedgerError> {
        todo!("Phase 1: Cosmos SDK tx — revoke identity")
    }

    pub fn query_current_ops_key(&self, _k_root_pub: &[u8; 32]) -> Result<[u8; 32], LedgerError> {
        todo!("Phase 1: Cosmos SDK query")
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
