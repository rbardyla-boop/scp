use scp_cryptography::keys::{hash, PublicKey};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};

// ── Public types (identical interface to scp-ledger-substrate) ──────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LedgerIdentityRecord {
    pub k_root_pub: [u8; 32],
    pub k_ops_pub: [u8; 32],
    pub recovery_policy_hash: [u8; 32],
    pub continuity_commitment: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunnelConsent {
    pub party_a: [u8; 32],
    pub party_b: [u8; 32],
    pub sig_a: Vec<u8>,
    pub sig_b: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TunnelState {
    Active,
    Revoked,
    Unknown,
}

// ── Internal state ──────────────────────────────────────────────────────────

#[derive(Default)]
struct LedgerState {
    identities: HashMap<[u8; 32], LedgerIdentityRecord>,
    ops_keys: HashMap<[u8; 32], [u8; 32]>,
    revoked_ops: HashSet<[u8; 32]>,
    tunnels: HashMap<[u8; 32], TunnelConsent>,
    revoked_tunnels: HashSet<[u8; 32]>,
}

// ── CosmosLedger ────────────────────────────────────────────────────────────

/// Cosmos SDK module adapter for the SCP state layer.
///
/// Phase 1: in-memory implementation (same logic as SubstrateLedger).
/// Phase 8: replace `state` with a real Cosmos gRPC client.
#[derive(Clone, Default)]
pub struct CosmosLedger {
    state: Arc<RwLock<LedgerState>>,
}

impl CosmosLedger {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register_identity(
        &self,
        record: &LedgerIdentityRecord,
        root_sig: &[u8; 64],
    ) -> Result<(), LedgerError> {
        let msg = registration_message(record);
        if !PublicKey(record.k_root_pub).verify(&msg, root_sig) {
            return Err(LedgerError::InvalidSignature);
        }
        let mut st = self.state.write().unwrap();
        if st.identities.contains_key(&record.k_root_pub) {
            return Err(LedgerError::AlreadyRegistered);
        }
        st.ops_keys.insert(record.k_root_pub, record.k_ops_pub);
        st.identities.insert(record.k_root_pub, record.clone());
        Ok(())
    }

    pub fn rotate_key(
        &self,
        old_ops_pub: &[u8; 32],
        new_ops_pub: &[u8; 32],
        nonce: u64,
        root_sig: &[u8; 64],
    ) -> Result<(), LedgerError> {
        let mut st = self.state.write().unwrap();
        let root_pub = st
            .ops_keys
            .iter()
            .find_map(|(root, ops)| {
                if ops == old_ops_pub {
                    Some(*root)
                } else {
                    None
                }
            })
            .ok_or(LedgerError::NotFound)?;
        let msg = rotation_message(old_ops_pub, new_ops_pub, nonce);
        if !PublicKey(root_pub).verify(&msg, root_sig) {
            return Err(LedgerError::InvalidSignature);
        }
        st.ops_keys.insert(root_pub, *new_ops_pub);
        if let Some(rec) = st.identities.get_mut(&root_pub) {
            rec.k_ops_pub = *new_ops_pub;
        }
        st.revoked_ops.insert(*old_ops_pub);
        Ok(())
    }

    pub fn revoke(&self, ops_pub: &[u8; 32], root_sig: &[u8; 64]) -> Result<(), LedgerError> {
        let mut st = self.state.write().unwrap();
        let root_pub = st
            .ops_keys
            .iter()
            .find_map(|(root, ops)| if ops == ops_pub { Some(*root) } else { None })
            .ok_or(LedgerError::NotFound)?;
        if !PublicKey(root_pub).verify(ops_pub, root_sig) {
            return Err(LedgerError::InvalidSignature);
        }
        st.revoked_ops.insert(*ops_pub);
        Ok(())
    }

    pub fn query_current_ops_key(&self, k_root_pub: &[u8; 32]) -> Result<[u8; 32], LedgerError> {
        self.state
            .read()
            .unwrap()
            .ops_keys
            .get(k_root_pub)
            .copied()
            .ok_or(LedgerError::NotFound)
    }

    pub fn is_revoked(&self, ops_pub: &[u8; 32]) -> bool {
        self.state.read().unwrap().revoked_ops.contains(ops_pub)
    }

    pub fn register_tunnel(&self, consent: TunnelConsent) -> Result<(), LedgerError> {
        let ch = tunnel_consent_hash(&consent.party_a, &consent.party_b);
        let sig_a: [u8; 64] = consent.sig_a[..]
            .try_into()
            .map_err(|_| LedgerError::InvalidSignature)?;
        let sig_b: [u8; 64] = consent.sig_b[..]
            .try_into()
            .map_err(|_| LedgerError::InvalidSignature)?;
        if !PublicKey(consent.party_a).verify(&ch, &sig_a) {
            return Err(LedgerError::InvalidSignature);
        }
        if !PublicKey(consent.party_b).verify(&ch, &sig_b) {
            return Err(LedgerError::InvalidSignature);
        }
        self.state.write().unwrap().tunnels.insert(ch, consent);
        Ok(())
    }

    pub fn query_tunnel(&self, a: &[u8; 32], b: &[u8; 32]) -> TunnelState {
        let ch = tunnel_consent_hash(a, b);
        let st = self.state.read().unwrap();
        if st.revoked_tunnels.contains(&ch) {
            TunnelState::Revoked
        } else if st.tunnels.contains_key(&ch) {
            TunnelState::Active
        } else {
            TunnelState::Unknown
        }
    }

    pub fn revoke_tunnel(
        &self,
        ops_pub: &[u8; 32],
        ops_sig: &[u8; 64],
        partner_ops_pub: &[u8; 32],
    ) -> Result<(), LedgerError> {
        let ch = tunnel_consent_hash(ops_pub, partner_ops_pub);
        {
            let st = self.state.read().unwrap();
            if !st.tunnels.contains_key(&ch) {
                return Err(LedgerError::NotFound);
            }
        }
        if !PublicKey(*ops_pub).verify(&ch, ops_sig) {
            return Err(LedgerError::InvalidSignature);
        }
        self.state.write().unwrap().revoked_tunnels.insert(ch);
        Ok(())
    }
}

// ── Helpers ─────────────────────────────────────────────────────────────────

fn registration_message(r: &LedgerIdentityRecord) -> Vec<u8> {
    let mut msg = Vec::with_capacity(96);
    msg.extend_from_slice(&r.k_root_pub);
    msg.extend_from_slice(&r.k_ops_pub);
    msg.extend_from_slice(&r.recovery_policy_hash);
    msg
}

fn rotation_message(old: &[u8; 32], new: &[u8; 32], nonce: u64) -> Vec<u8> {
    let mut msg = Vec::with_capacity(72);
    msg.extend_from_slice(old);
    msg.extend_from_slice(new);
    msg.extend_from_slice(&nonce.to_le_bytes());
    msg
}

pub fn tunnel_consent_hash(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
    let mut msg = b"scp:tunnel:v1:".to_vec();
    msg.extend_from_slice(lo);
    msg.extend_from_slice(hi);
    hash(&msg)
}

#[derive(Debug, thiserror::Error)]
pub enum LedgerError {
    #[error("identity not found")]
    NotFound,
    #[error("identity already registered")]
    AlreadyRegistered,
    #[error("invalid signature")]
    InvalidSignature,
    #[error("ledger connection failed")]
    ConnectionFailed,
}
