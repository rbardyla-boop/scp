use std::collections::HashMap;

use scp_transport::quorum::EquivocationEvidence;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum SemanticClassId {
    Monotonic,
    SoftState,
    ConsensusRelevant,
}

#[derive(Debug, Clone, Default)]
pub struct ClassReputation {
    pub equivocations: u32,
    pub last_equivocation_at: u64,
}

pub struct ProviderReputation {
    pub(crate) records: HashMap<([u8; 32], SemanticClassId), ClassReputation>,
    pub(crate) half_life_secs: Option<u64>,
}

impl ProviderReputation {
    pub fn new() -> Self {
        Self {
            records: HashMap::new(),
            half_life_secs: None,
        }
    }

    pub fn record_equivocation(&mut self, evidence: &EquivocationEvidence) {
        let now = crate::now_secs();
        for id in [evidence.provider_a_id, evidence.provider_b_id] {
            let rep = self
                .records
                .entry((id, SemanticClassId::ConsensusRelevant))
                .or_default();
            rep.equivocations += 1;
            rep.last_equivocation_at = now;
        }
    }

    pub fn query(&self, provider_id: &[u8; 32], class: &SemanticClassId) -> ClassReputation {
        self.records
            .get(&(*provider_id, class.clone()))
            .cloned()
            .unwrap_or_default()
    }

    pub fn equivocation_count(&self, provider_id: &[u8; 32], class: &SemanticClassId) -> u32 {
        self.query(provider_id, class).equivocations
    }

    /// Effective equivocation count at an explicit timestamp, applying optional half-life decay.
    ///
    /// Result = `equivocations * 0.5^(age_secs / half_life_secs)`.
    /// Returns the raw count (as `f64`) when no decay is configured or `half_life == 0`.
    pub fn effective_equivocation_count_at(
        &self,
        provider_id: &[u8; 32],
        class: &SemanticClassId,
        now: u64,
    ) -> f64 {
        let rep = self.query(provider_id, class);
        if rep.equivocations == 0 {
            return 0.0;
        }
        match self.half_life_secs {
            None | Some(0) => rep.equivocations as f64,
            Some(half_life) => {
                let age = now.saturating_sub(rep.last_equivocation_at);
                let decay = 0.5f64.powf(age as f64 / half_life as f64);
                rep.equivocations as f64 * decay
            }
        }
    }

    /// Effective equivocation count at the current wall-clock time.
    pub fn effective_equivocation_count(
        &self,
        provider_id: &[u8; 32],
        class: &SemanticClassId,
    ) -> f64 {
        self.effective_equivocation_count_at(provider_id, class, crate::now_secs())
    }
}

impl Default for ProviderReputation {
    fn default() -> Self {
        Self::new()
    }
}
