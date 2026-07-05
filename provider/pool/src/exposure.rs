use std::collections::HashMap;

// ── Admissible surface types ──────────────────────────────────────────────────

/// Opaque receipt returned by `sample_with_receipts()`. Required argument for
/// `record_admissible_response()` and `record_admissible_failure()`.
///
/// Binds provider identity, selection-event identity, and epoch boundary in a
/// single structure that must be presented to close the paired-outcome accounting.
/// At most one terminal outcome is accepted per receipt. After consumption the
/// receipt's `observation_id` is removed from the outstanding map; re-presentation
/// returns `AdmissibilityError::UnknownReceipt`.
///
/// The `epoch_count` field enables stale-epoch rejection without a wall-clock
/// timeout. Any receipt issued during epoch N is invalid in epoch N+1 — the epoch
/// boundary that `do_rotate()` crosses is the event that terminates eligibility.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelectionReceipt {
    /// Value of `pool.rotation.epoch_count` at the moment `sample_with_receipts()` was called.
    pub(crate) epoch_count: u32,
    /// Monotone per-pool counter. Unique within the pool's lifetime across all
    /// `sample_with_receipts()` calls. Incremented once per selected provider per call.
    /// Never reused. Not reset on epoch rotation.
    pub(crate) observation_id: u64,
    /// Identity of the provider selected in this event.
    pub(crate) provider_id: [u8; 32],
}

impl SelectionReceipt {
    /// The epoch counter value at the moment this receipt was issued.
    pub fn epoch_count(&self) -> u32 {
        self.epoch_count
    }

    /// The monotone observation ID for this selection event.
    pub fn observation_id(&self) -> u64 {
        self.observation_id
    }

    /// The provider ID encoded in this receipt.
    pub fn provider_id(&self) -> [u8; 32] {
        self.provider_id
    }

    /// Returns a modified copy of this receipt with a different provider_id.
    ///
    /// Used in tests to simulate a tampered receipt (wrong-provider scenario).
    /// Only usable in tests — callers outside the crate can call this to construct
    /// a receipt that will fail the ProviderMismatch admissibility check.
    pub fn with_provider_id(mut self, provider_id: [u8; 32]) -> Self {
        self.provider_id = provider_id;
        self
    }
}

/// Errors returned by `record_admissible_response()`, `record_admissible_failure()`,
/// and `sample_with_receipts()` (capacity refusal path).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdmissibilityError {
    /// Admissible tracking was not configured via `with_admissible_tracking()`.
    NotConfigured,
    /// The receipt's `epoch_count` does not match the current epoch.
    /// The receipt was drained on the last rotation.
    StaleEpoch,
    /// The `observation_id` is not present in the outstanding map.
    /// Covers: never issued, already consumed (by response or failure), or forged.
    UnknownReceipt,
    /// The `observation_id` is present but the `provider_id` encoded in the receipt
    /// does not match the `provider_id` stored at issuance.
    ProviderMismatch,
    /// The `observation_id` counter overflowed `u64::MAX`. Effectively unreachable.
    CounterExhausted,
    /// The outstanding receipt count is at the configured finite bound.
    ///
    /// Returned by `sample_with_receipts()` when `outstanding.len() >= max_outstanding_receipts`.
    /// The entire receipt-bearing sample is refused: no provider selection occurs, no raw
    /// selection accounting changes, and no new receipts are created. Capacity is restored
    /// one unit at a time as existing receipts are consumed by terminal outcomes or drained
    /// by epoch rotation.
    ReceiptCapacityExhausted,
}

/// Admissible paired-outcome tracker. Held as `Option<AdmissibleExposureTracker>`
/// inside `ProviderPool`. Only active when `with_admissible_tracking()` was called.
pub(crate) struct AdmissibleExposureTracker {
    /// Maximum number of outstanding (unresolved) receipts permitted at any instant.
    ///
    /// `issue_receipt()` returns `Err(ReceiptCapacityExhausted)` when
    /// `outstanding.len() >= max_outstanding_receipts` before any new receipt
    /// is created. Capacity is restored one unit at a time as receipts are consumed
    /// by `record_admissible_response()`, `record_admissible_failure()`, or cleared
    /// in bulk by `drain_epoch()` on rotation.
    ///
    /// Invariant: `outstanding.len() <= max_outstanding_receipts` at all times.
    pub(crate) max_outstanding_receipts: usize,
    /// Outstanding receipts: observation_id → provider_id.
    ///
    /// A receipt stays in this map from issuance until the first of:
    /// 1. `record_admissible_response()` passes all admissibility checks.
    /// 2. `record_admissible_failure()` passes all admissibility checks.
    /// 3. `drain_epoch()` is called on epoch rotation (clears the entire map).
    ///
    /// Bounded above by `max_outstanding_receipts` — `issue_receipt()` refuses to
    /// add a new entry when `outstanding.len() >= max_outstanding_receipts`.
    pub(crate) outstanding: HashMap<u64, [u8; 32]>,
    /// Monotone counter for observation IDs. Incremented per selected provider per call.
    /// Never decremented, never reset — see Decision 2.
    pub(crate) next_observation_id: u64,
    /// Current epoch counter (mirrors `PoolRotation::epoch_count` after each drain).
    pub(crate) current_epoch_count: u32,
    /// Total admissible responses accepted (receipt-paired, passing all checks).
    pub(crate) admissible_response_total: u64,
    /// Total admissible failures accepted (receipt-paired, passing all checks).
    pub(crate) admissible_failure_total: u64,
    /// Total admissible selections: incremented once per issued receipt.
    pub(crate) admissible_selection_total: u64,
    /// Per-provider admissible response appearances.
    pub(crate) admissible_appearances: HashMap<[u8; 32], u64>,
    /// The reset policy, copied from the pool, to mirror raw tracker reset behavior.
    pub(crate) reset_policy: crate::rotation::ExposureResetPolicy,
}

impl AdmissibleExposureTracker {
    pub(crate) fn new(
        reset_policy: crate::rotation::ExposureResetPolicy,
        max_outstanding_receipts: usize,
    ) -> Self {
        Self {
            max_outstanding_receipts,
            outstanding: HashMap::new(),
            next_observation_id: 0,
            current_epoch_count: 0,
            admissible_response_total: 0,
            admissible_failure_total: 0,
            admissible_selection_total: 0,
            admissible_appearances: HashMap::new(),
            reset_policy,
        }
    }

    /// Issue a receipt for a provider selected in `sample_with_receipts()`.
    ///
    /// Returns `Err(ReceiptCapacityExhausted)` when outstanding receipts are at the
    /// configured finite bound — checked before any state mutation. On this error:
    /// - no provider selection has occurred (caller ensures pre-selection check)
    /// - `outstanding` is unchanged
    /// - `next_observation_id` is unchanged
    /// - `admissible_selection_total` is unchanged
    ///
    /// Returns `Err(CounterExhausted)` on u64 overflow (unreachable in practice).
    pub(crate) fn issue_receipt(
        &mut self,
        epoch_count: u32,
        provider_id: [u8; 32],
    ) -> Result<SelectionReceipt, AdmissibilityError> {
        // Capacity check FIRST — before any state mutation.
        if self.outstanding.len() >= self.max_outstanding_receipts {
            return Err(AdmissibilityError::ReceiptCapacityExhausted);
        }
        let oid = self.next_observation_id;
        self.next_observation_id = self
            .next_observation_id
            .checked_add(1)
            .ok_or(AdmissibilityError::CounterExhausted)?;
        self.outstanding.insert(oid, provider_id);
        self.admissible_selection_total += 1;
        Ok(SelectionReceipt {
            epoch_count,
            observation_id: oid,
            provider_id,
        })
    }

    /// Record an admissible response. All four admissibility conditions must hold.
    pub(crate) fn record_admissible_response(
        &mut self,
        receipt: &SelectionReceipt,
    ) -> Result<(), AdmissibilityError> {
        // Condition 1: epoch not stale.
        if receipt.epoch_count != self.current_epoch_count {
            return Err(AdmissibilityError::StaleEpoch);
        }
        // Condition 2: receipt in outstanding map.
        let stored_pid = self
            .outstanding
            .get(&receipt.observation_id)
            .copied()
            .ok_or(AdmissibilityError::UnknownReceipt)?;
        // Condition 3: provider identity matches.
        if stored_pid != receipt.provider_id {
            return Err(AdmissibilityError::ProviderMismatch);
        }
        // Condition 4: atomically remove (at-most-once).
        self.outstanding.remove(&receipt.observation_id);
        self.admissible_response_total += 1;
        *self
            .admissible_appearances
            .entry(receipt.provider_id)
            .or_insert(0) += 1;
        Ok(())
    }

    /// Record an admissible failure. Same admissibility conditions as response.
    pub(crate) fn record_admissible_failure(
        &mut self,
        receipt: &SelectionReceipt,
    ) -> Result<(), AdmissibilityError> {
        if receipt.epoch_count != self.current_epoch_count {
            return Err(AdmissibilityError::StaleEpoch);
        }
        let stored_pid = self
            .outstanding
            .get(&receipt.observation_id)
            .copied()
            .ok_or(AdmissibilityError::UnknownReceipt)?;
        if stored_pid != receipt.provider_id {
            return Err(AdmissibilityError::ProviderMismatch);
        }
        self.outstanding.remove(&receipt.observation_id);
        self.admissible_failure_total += 1;
        Ok(())
    }

    /// Called inside `do_rotate()` after `epoch_count` is incremented.
    /// Clears all outstanding receipts unconditionally. Optionally resets counters
    /// based on the reset policy (matching raw tracker behavior).
    pub(crate) fn drain_epoch(&mut self, new_epoch_count: u32) {
        self.outstanding.clear();
        self.current_epoch_count = new_epoch_count;

        let should_reset = match &self.reset_policy {
            crate::rotation::ExposureResetPolicy::Never => false,
            crate::rotation::ExposureResetPolicy::OnRotation => true,
            crate::rotation::ExposureResetPolicy::AfterEpochs { n } => {
                new_epoch_count.is_multiple_of(*n)
            }
        };
        if should_reset {
            self.admissible_response_total = 0;
            self.admissible_failure_total = 0;
            self.admissible_selection_total = 0;
            self.admissible_appearances.clear();
            // next_observation_id is intentionally NOT reset — see Decision 2.
        }
    }
}

/// Snapshot of observed provider selection exposure for a pool.
///
/// Computed from the pool's internal `ExposureTracker`, which records which
/// providers appeared in `sample()` quorums and how often. All rates are
/// fractions of sample() calls, not individual provider appearances.
pub struct ExposureEstimate {
    /// Shannon entropy (bits) of the observed provider selection distribution.
    /// Higher = more uniform = more privacy-preserving.
    /// Theoretical maximum = log2(active_set_size) for uniform selection.
    pub selection_entropy_bits: f64,

    /// EWMA-smoothed entropy (bits). Lags behind `selection_entropy_bits` by
    /// `1/ewma_alpha` samples. Preserved across `reset()` calls to prevent
    /// `EntropyTriggered` from re-firing immediately after a reset (anti-thrashing).
    pub smoothed_selection_entropy_bits: f64,

    /// Fraction of `sample()` calls in which the most-selected provider appeared.
    /// In an n-provider uniform pool: ~1/n. Lower = harder to infer membership.
    pub max_selection_rate: f64,

    /// Total `sample()` calls recorded. Zero means no samples yet.
    pub total_samples: u64,

    /// Confidence-weighted total samples after applying exponential decay.
    ///
    /// Equal to `total_samples` when no decay is configured. Decays toward
    /// zero with half-life `decay_half_life_secs` as time passes since the
    /// last `sample()` call. Ratio-based fields (`selection_entropy_bits`,
    /// `max_selection_rate`) are unaffected by decay.
    pub effective_total_samples: f64,

    /// Shannon entropy (bits) of the observed provider *response* distribution.
    ///
    /// Computed from `record_response()` calls rather than selection events.
    /// Dead providers contribute 0 to response entropy regardless of how often they are
    /// selected, so this value falls below `selection_entropy_bits` when providers are silent.
    pub response_entropy_bits: f64,

    /// EWMA-smoothed response entropy. Preserved across `reset()` — anti-thrashing.
    pub smoothed_response_entropy_bits: f64,

    /// Total `record_response()` calls recorded. Zero means no responses yet.
    pub response_total_samples: u64,
}

impl ExposureEstimate {
    /// Probability that an adversary correctly identifies the most-exposed
    /// provider as a pool member after observing `n` independent `sample()` quorums.
    ///
    /// Model: the most-exposed provider appears in each sample with probability
    /// `max_selection_rate`. After n samples, the adversary observes it at least
    /// once with probability `1 - (1 - max_selection_rate)^n`.
    pub fn membership_confidence_after(&self, n: u64) -> f64 {
        if self.max_selection_rate <= 0.0 || n == 0 {
            return 0.0;
        }
        1.0 - (1.0 - self.max_selection_rate).powi(n as i32)
    }
}

/// Per-provider selection probability distribution, normalized to sum ≤ 1.0.
///
/// Each entry is `(provider_id, probability)` where probability = appearances[i] / sum(appearances).
/// Returns empty Vec when no samples have been recorded.
pub struct ExposureDistribution {
    pub rates: Vec<([u8; 32], f64)>,
}

pub(crate) struct ExposureTracker {
    pub(crate) appearances: HashMap<[u8; 32], u64>,
    pub(crate) total_samples: u64,
    pub(crate) smoothed_entropy: f64, // EWMA; NOT zeroed by reset() — anti-thrashing
    pub(crate) ewma_alpha: f64,       // default 1.0 = no smoothing (smoothed == raw)
    pub(crate) decay_half_life_secs: Option<u64>, // None = no decay
    pub(crate) last_record_secs: u64, // wall-clock of most recent record() call
    pub(crate) response_appearances: HashMap<[u8; 32], u64>,
    pub(crate) response_total: u64,
    pub(crate) response_smoothed_entropy: f64, // EWMA; NOT zeroed by reset() — anti-thrashing
}

impl ExposureTracker {
    pub(crate) fn new() -> Self {
        Self {
            appearances: HashMap::new(),
            total_samples: 0,
            smoothed_entropy: 0.0,
            ewma_alpha: 1.0,
            decay_half_life_secs: None,
            last_record_secs: 0,
            response_appearances: HashMap::new(),
            response_total: 0,
            response_smoothed_entropy: 0.0,
        }
    }

    pub(crate) fn reset(&mut self) {
        self.appearances.clear();
        self.total_samples = 0;
        self.response_appearances.clear();
        self.response_total = 0;
        // smoothed_entropy and response_smoothed_entropy intentionally NOT reset —
        // prevents EntropyTriggered from re-firing immediately after a reset.
    }

    pub(crate) fn record(&mut self, provider_ids: &[[u8; 32]]) {
        self.total_samples += 1;
        for id in provider_ids {
            *self.appearances.entry(*id).or_insert(0) += 1;
        }
        self.last_record_secs = crate::now_secs();
        let raw = self.estimate_raw_entropy();
        self.smoothed_entropy =
            self.ewma_alpha * raw + (1.0 - self.ewma_alpha) * self.smoothed_entropy;
    }

    pub(crate) fn record_response(&mut self, provider_id: &[u8; 32]) {
        self.response_total += 1;
        *self.response_appearances.entry(*provider_id).or_insert(0) += 1;
        let raw = self.estimate_raw_response_entropy();
        self.response_smoothed_entropy =
            self.ewma_alpha * raw + (1.0 - self.ewma_alpha) * self.response_smoothed_entropy;
    }

    pub(crate) fn rate(&self, pid: &[u8; 32]) -> f64 {
        if self.total_samples == 0 {
            return 0.0;
        }
        *self.appearances.get(pid).unwrap_or(&0) as f64 / self.total_samples as f64
    }

    fn estimate_raw_entropy(&self) -> f64 {
        if self.total_samples == 0 {
            return 0.0;
        }
        let n = self.total_samples as f64;
        self.appearances
            .values()
            .map(|&c| {
                let p = c as f64 / n;
                if p > 0.0 {
                    -p * p.log2()
                } else {
                    0.0
                }
            })
            .sum()
    }

    fn estimate_raw_response_entropy(&self) -> f64 {
        if self.response_total == 0 {
            return 0.0;
        }
        let n = self.response_total as f64;
        self.response_appearances
            .values()
            .map(|&c| {
                let p = c as f64 / n;
                if p > 0.0 {
                    -p * p.log2()
                } else {
                    0.0
                }
            })
            .sum()
    }

    pub(crate) fn estimate_at(&self, now: u64) -> ExposureEstimate {
        let raw = self.estimate_raw_entropy();
        let max_rate = if self.total_samples == 0 {
            0.0
        } else {
            let n = self.total_samples as f64;
            self.appearances
                .values()
                .map(|&c| c as f64 / n)
                .fold(0.0f64, f64::max)
        };
        let effective = match self.decay_half_life_secs {
            None => self.total_samples as f64,
            Some(hl) => {
                let elapsed = now.saturating_sub(self.last_record_secs) as f64;
                self.total_samples as f64 * 0.5_f64.powf(elapsed / hl as f64)
            }
        };
        ExposureEstimate {
            selection_entropy_bits: raw,
            smoothed_selection_entropy_bits: self.smoothed_entropy,
            max_selection_rate: max_rate,
            total_samples: self.total_samples,
            effective_total_samples: effective,
            response_entropy_bits: self.estimate_raw_response_entropy(),
            smoothed_response_entropy_bits: self.response_smoothed_entropy,
            response_total_samples: self.response_total,
        }
    }

    pub(crate) fn estimate(&self) -> ExposureEstimate {
        self.estimate_at(crate::now_secs())
    }

    pub(crate) fn distribution(&self) -> ExposureDistribution {
        let total_appearances: u64 = self.appearances.values().sum();
        if total_appearances == 0 {
            return ExposureDistribution { rates: Vec::new() };
        }
        let n = total_appearances as f64;
        let rates = self
            .appearances
            .iter()
            .map(|(id, &c)| (*id, c as f64 / n))
            .collect();
        ExposureDistribution { rates }
    }
}
