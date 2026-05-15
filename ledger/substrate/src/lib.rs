use scp_cryptography::keys::{hash, PublicKey};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};

// ── Public types ────────────────────────────────────────────────────────────

/// Minimal on-chain identity record (public portion only).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LedgerIdentityRecord {
    pub k_root_pub: [u8; 32],
    pub k_ops_pub: [u8; 32],
    pub recovery_policy_hash: [u8; 32],
    pub continuity_commitment: [u8; 32],
}

/// Bilateral tunnel consent — both parties must sign.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunnelConsent {
    /// Lexicographically smaller operational public key.
    pub party_a: [u8; 32],
    /// Lexicographically larger operational public key.
    pub party_b: [u8; 32],
    /// party_a's Ed25519 signature over the consent hash.
    pub sig_a: Vec<u8>,
    /// party_b's Ed25519 signature over the consent hash.
    pub sig_b: Vec<u8>,
}

/// Observed state of a tunnel between two operational identities.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TunnelState {
    /// Bilateral consent is on record and neither party has revoked.
    Active,
    /// One or both parties have revoked consent.
    Revoked,
    /// No consent record exists for this pair.
    Unknown,
}

// ── Internal state ──────────────────────────────────────────────────────────

#[derive(Default)]
struct LedgerState {
    /// root_pub → identity record
    identities: HashMap<[u8; 32], LedgerIdentityRecord>,
    /// Current ops key per root identity (updated on rotation)
    ops_keys: HashMap<[u8; 32], [u8; 32]>,
    /// Revoked ops public keys
    revoked_ops: HashSet<[u8; 32]>,
    /// consent_hash → consent (Active tunnels)
    tunnels: HashMap<[u8; 32], TunnelConsent>,
    /// Revoked tunnel consent hashes
    revoked_tunnels: HashSet<[u8; 32]>,
}

// ── SubstrateLedger ─────────────────────────────────────────────────────────

/// Substrate pallet adapter for the SCP state layer.
///
/// Phase 1: in-memory implementation with full signature verification.
/// Phase 8: replace `state` with a real Substrate RPC client.
#[derive(Clone, Default)]
pub struct SubstrateLedger {
    state: Arc<RwLock<LedgerState>>,
}

impl SubstrateLedger {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a new sovereign identity on the ledger.
    ///
    /// `root_sig` must be an Ed25519 signature by `record.k_root_pub` over
    /// `BLAKE3(k_root_pub || k_ops_pub || recovery_policy_hash)`.
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

    /// Rotate the operational key for an identity.
    ///
    /// `root_sig` must cover `old_ops_pub || new_ops_pub || nonce` — the same
    /// message format used by `RotationEvent::sign`.
    pub fn rotate_key(
        &self,
        old_ops_pub: &[u8; 32],
        new_ops_pub: &[u8; 32],
        nonce: u64,
        root_sig: &[u8; 64],
    ) -> Result<(), LedgerError> {
        let mut st = self.state.write().unwrap();

        // Find the root key that owns old_ops_pub.
        let root_pub = st
            .ops_keys
            .iter()
            .find_map(|(root, ops)| if ops == old_ops_pub { Some(*root) } else { None })
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

    /// Revoke an operational key. The root key signs over the revoked ops key.
    pub fn revoke(
        &self,
        ops_pub: &[u8; 32],
        root_sig: &[u8; 64],
    ) -> Result<(), LedgerError> {
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

    /// Query the current operational public key for a root identity.
    pub fn query_current_ops_key(&self, k_root_pub: &[u8; 32]) -> Result<[u8; 32], LedgerError> {
        let st = self.state.read().unwrap();
        st.ops_keys.get(k_root_pub).copied().ok_or(LedgerError::NotFound)
    }

    /// Returns true if an operational key has been revoked.
    pub fn is_revoked(&self, ops_pub: &[u8; 32]) -> bool {
        self.state.read().unwrap().revoked_ops.contains(ops_pub)
    }

    /// Register bilateral tunnel consent.
    ///
    /// Both signatures must cover `tunnel_consent_hash(party_a, party_b)`.
    pub fn register_tunnel(&self, consent: TunnelConsent) -> Result<(), LedgerError> {
        let ch = tunnel_consent_hash(&consent.party_a, &consent.party_b);

        let sig_a: [u8; 64] = consent.sig_a[..].try_into().map_err(|_| LedgerError::InvalidSignature)?;
        let sig_b: [u8; 64] = consent.sig_b[..].try_into().map_err(|_| LedgerError::InvalidSignature)?;

        if !PublicKey(consent.party_a).verify(&ch, &sig_a) {
            return Err(LedgerError::InvalidSignature);
        }
        if !PublicKey(consent.party_b).verify(&ch, &sig_b) {
            return Err(LedgerError::InvalidSignature);
        }

        let mut st = self.state.write().unwrap();
        st.tunnels.insert(ch, consent);
        Ok(())
    }

    /// Query tunnel state between two operational identities.
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

    /// Revoke tunnel consent. Either party may revoke unilaterally.
    /// `ops_pub` must be one of the two parties; `ops_sig` covers the consent hash.
    pub fn revoke_tunnel(
        &self,
        ops_pub: &[u8; 32],
        ops_sig: &[u8; 64],
        partner_ops_pub: &[u8; 32],
    ) -> Result<(), LedgerError> {
        let ch = tunnel_consent_hash(ops_pub, partner_ops_pub);

        let st_r = self.state.read().unwrap();
        if !st_r.tunnels.contains_key(&ch) {
            return Err(LedgerError::NotFound);
        }
        drop(st_r);

        if !PublicKey(*ops_pub).verify(&ch, ops_sig) {
            return Err(LedgerError::InvalidSignature);
        }

        let mut st = self.state.write().unwrap();
        st.revoked_tunnels.insert(ch);
        Ok(())
    }
}

// ── Shared helpers ──────────────────────────────────────────────────────────

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

/// Canonical tunnel consent hash — parties sorted so A ≤ B lexicographically.
pub fn tunnel_consent_hash(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
    let mut msg = b"scp:tunnel:v1:".to_vec();
    msg.extend_from_slice(lo);
    msg.extend_from_slice(hi);
    hash(&msg)
}

// ── Error type ──────────────────────────────────────────────────────────────

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
