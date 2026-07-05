use std::collections::HashMap;

use crate::admission::AdmissionError;
use crate::reputation::SemanticClassId;

// ── EvictionError ─────────────────────────────────────────────────────────────

/// Errors returned by `ProviderPool::evict()`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvictionError {
    /// `provider_id` was not found in the active or dormant set.
    NotFound,
    /// Removing this dormant provider would leave `dormant.len() < active_window`,
    /// making future rotation impossible. [POOL-5]
    WouldViolateDormantFloor,
    /// Eviction gate not configured; call `.with_eviction()` on the pool builder.
    NotConfigured,
}

// ── EvictionReason ────────────────────────────────────────────────────────────

/// Why a provider was permanently removed from the pool.
#[derive(Debug, Clone)]
pub enum EvictionReason {
    /// Provider equivocated on a Consensus-Relevant state claim.
    /// `count` matches the reputation record at the time of eviction.
    Equivocation {
        semantic_class: SemanticClassId,
        count: u32,
    },
    /// Provider exceeded the liveness failure threshold.
    LivenessExhausted,
    /// Operator-initiated permanent ban. Not time-limited.
    /// Can only be lifted by `lift_ban()`.
    OperatorBan,
}

// ── EvictionRecord ────────────────────────────────────────────────────────────

/// Per-provider eviction metadata, persisted for the pool's lifetime.
pub struct EvictionRecord {
    /// Unix timestamp when the eviction was recorded.
    pub evicted_at_secs: u64,
    /// Why the provider was evicted.
    pub reason: EvictionReason,
    /// How many times the provider has been re-admitted after prior evictions.
    /// Incremented by `record_readmission()`; never reset on re-eviction.
    pub re_admission_count: u32,
}

// ── EvictionConfig ────────────────────────────────────────────────────────────

/// Pool-level configuration for eviction and re-admission limits.
pub struct EvictionConfig {
    /// Seconds a `LivenessExhausted` provider must wait before re-applying.
    /// Default: 300 (5 minutes).
    pub liveness_cooldown_secs: u64,
    /// Seconds an `Equivocation` provider must wait before re-applying.
    /// Default: 3600 (1 hour).
    pub equivocation_cooldown_secs: u64,
    /// Maximum total re-admissions across the provider's lifetime in this pool.
    /// Once reached, further re-admission is permanently denied.
    /// Default: 3.
    pub max_re_admissions: u32,
}

impl Default for EvictionConfig {
    fn default() -> Self {
        Self {
            liveness_cooldown_secs: 300,
            equivocation_cooldown_secs: 3600,
            max_re_admissions: 3,
        }
    }
}

// ── EvictionState ─────────────────────────────────────────────────────────────

/// Runtime eviction state stored on `ProviderPool`.
pub(crate) struct EvictionState {
    pub(crate) records: HashMap<[u8; 32], EvictionRecord>,
    pub(crate) config: EvictionConfig,
}

impl EvictionState {
    pub(crate) fn new(config: EvictionConfig) -> Self {
        Self {
            records: HashMap::new(),
            config,
        }
    }

    /// Check whether a provider is eligible to request admission.
    ///
    /// Returns `None` if eligible, or the blocking `AdmissionError` if not.
    /// Called at the TOP of `request_admission()`, before budget is claimed —
    /// eviction-gate rejections must never consume the admission budget.
    pub(crate) fn check_admission(
        &self,
        provider_id: &[u8; 32],
        now_secs: u64,
    ) -> Option<AdmissionError> {
        let record = self.records.get(provider_id)?;

        // OperatorBan: permanent regardless of elapsed time or counter.
        if matches!(record.reason, EvictionReason::OperatorBan) {
            return Some(AdmissionError::Banned);
        }

        // Lifetime re-admission counter exhausted (applies to all non-ban reasons).
        if record.re_admission_count >= self.config.max_re_admissions {
            return Some(AdmissionError::MaxReAdmissionsExceeded);
        }

        // Reason-specific cooldown.
        let cooldown_secs = match &record.reason {
            EvictionReason::LivenessExhausted => self.config.liveness_cooldown_secs,
            EvictionReason::Equivocation { .. } => self.config.equivocation_cooldown_secs,
            EvictionReason::OperatorBan => unreachable!(), // handled above
        };

        let elapsed = now_secs.saturating_sub(record.evicted_at_secs);
        if elapsed < cooldown_secs {
            let eligible_at_secs = record.evicted_at_secs.saturating_add(cooldown_secs);
            return Some(AdmissionError::EvictionCooldown { eligible_at_secs });
        }

        None
    }

    /// Create or update an eviction record for a provider.
    ///
    /// If the provider has been evicted before, the timestamp and reason are
    /// refreshed but `re_admission_count` is preserved — it is a lifetime counter.
    pub(crate) fn record_eviction(
        &mut self,
        provider_id: [u8; 32],
        reason: EvictionReason,
        evicted_at_secs: u64,
    ) {
        let entry = self.records.entry(provider_id).or_insert(EvictionRecord {
            evicted_at_secs,
            reason: reason.clone(),
            re_admission_count: 0,
        });
        // Refresh time and reason; preserve the lifetime re-admission counter.
        entry.evicted_at_secs = evicted_at_secs;
        entry.reason = reason;
    }

    /// Increment the re-admission counter after `complete_admission()` succeeds.
    pub(crate) fn record_readmission(&mut self, provider_id: &[u8; 32]) {
        if let Some(record) = self.records.get_mut(provider_id) {
            record.re_admission_count = record.re_admission_count.saturating_add(1);
        }
    }

    /// Lift an `OperatorBan` by removing the eviction record entirely.
    ///
    /// Returns `true` if a ban record was found and removed, `false` otherwise.
    pub(crate) fn lift_ban(&mut self, provider_id: &[u8; 32]) -> bool {
        match self.records.get(provider_id) {
            Some(r) if matches!(r.reason, EvictionReason::OperatorBan) => {
                self.records.remove(provider_id);
                true
            }
            _ => false,
        }
    }

    /// Inspect a provider's eviction record. Returns `None` if never evicted.
    pub(crate) fn record(&self, provider_id: &[u8; 32]) -> Option<&EvictionRecord> {
        self.records.get(provider_id)
    }
}
