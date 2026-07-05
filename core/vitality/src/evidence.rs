use crate::function::{compute, VitalityParams};
use crate::state::VitalityState;
use std::collections::HashMap;

/// Relationship-scoped store for vitality reaffirmation timestamps.
///
/// Keyed by bilateral consent hash (`tunnel_consent_hash(party_a, party_b)`).
/// The store is the sole source of truth for elapsed-time computation; nothing
/// else — sends, receives, or queries — updates the stored timestamp.
pub struct VitalityEvidenceStore {
    evidence: HashMap<[u8; 32], u64>,
}

impl Default for VitalityEvidenceStore {
    fn default() -> Self {
        Self::new()
    }
}

impl VitalityEvidenceStore {
    pub fn new() -> Self {
        Self {
            evidence: HashMap::new(),
        }
    }

    /// Establish vitality evidence for a new bilateral consent relationship.
    ///
    /// Returns `true` on first call for `consent_hash`. Returns `false` if
    /// evidence already exists — the stored timestamp is never overwritten.
    pub fn initialize_at(&mut self, consent_hash: [u8; 32], established_at: u64) -> bool {
        if self.evidence.contains_key(&consent_hash) {
            return false;
        }
        self.evidence.insert(consent_hash, established_at);
        true
    }

    /// Record an explicit bilateral reaffirmation for an initialized relationship.
    ///
    /// Returns `true` on success. Returns `false` if `consent_hash` has no
    /// initialized evidence — no record is created and no state changes.
    pub fn record_reaffirmation(&mut self, consent_hash: [u8; 32], now: u64) -> bool {
        match self.evidence.get_mut(&consent_hash) {
            Some(ts) => {
                *ts = now;
                true
            }
            None => false,
        }
    }

    /// Derive the current `VitalityState` for a relationship.
    ///
    /// `now` is caller-supplied Unix seconds — deterministic for testing.
    /// `i`, `r`, `p` are the vitality formula inputs.
    ///
    /// Returns `VitalityState::Suspended` for unknown consent hashes (fails closed).
    pub fn compute_state(
        &self,
        consent_hash: [u8; 32],
        now: u64,
        i: f64,
        r: f64,
        p: f64,
    ) -> VitalityState {
        match self.evidence.get(&consent_hash) {
            None => VitalityState::Suspended,
            Some(&last_reaffirmed_at) => {
                let t = now.saturating_sub(last_reaffirmed_at) as f64;
                let score = compute(VitalityParams { t, i, r, p });
                VitalityState::from_score(score)
            }
        }
    }
}
