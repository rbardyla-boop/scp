pub mod admission;
pub(crate) mod dummy;
pub(crate) mod eviction;
pub(crate) mod exposure;
pub(crate) mod liveness;
pub mod metrics;
pub(crate) mod reputation;
pub(crate) mod rotation;
pub(crate) mod sampling;

pub use admission::{admission_challenge_message, AdmissionConfig, AdmissionError};
pub use dummy::{DUMMY_QUERY_PROBABILITY, MAX_DUMMY_QUERIES_PER_MINUTE};
pub use eviction::{EvictionConfig, EvictionError, EvictionReason, EvictionRecord};
pub use exposure::{AdmissibilityError, ExposureDistribution, ExposureEstimate, SelectionReceipt};
pub use metrics::{
    epoch_similarity, exposure_divergence, ConvergencePressure, EpochPhase,
    OperationalTelemetrySnapshot,
};
pub use reputation::{ClassReputation, ProviderReputation, SemanticClassId};
pub use rotation::{
    ActivationStrategy, ChurnBudget, DeferralReason, ExposureResetPolicy, PoolRotationPolicy,
    RotationCooldown, RotationOutcome,
};
pub use sampling::SamplingStrategy;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use rand_core::RngCore;
use scp_transport::quorum::EquivocationEvidence;
use scp_transport::{ProviderQuorum, StateProvider};

use dummy::DummyQueryBudget;
use eviction::EvictionState;
use exposure::{AdmissibleExposureTracker, ExposureTracker};
use liveness::{LivenessConfig, LivenessState};
use rotation::PoolRotation;

// ── Internal helpers ─────────────────────────────────────────────────────────

/// Panics if `IntegralTriggered` with `max_accumulated_pressure < 1.0` is used without a
/// non-zero cooldown. A missing cooldown creates a rotation loop: κ=1.0 after reset →
/// accumulated exceeds threshold on the first call → rotation → reset → repeat.
fn assert_integral_safety(policy: &PoolRotationPolicy, cooldown: &Option<RotationCooldown>) {
    if let PoolRotationPolicy::IntegralTriggered {
        max_accumulated_pressure,
    } = policy
    {
        if *max_accumulated_pressure < 1.0 {
            assert!(
                cooldown
                    .as_ref()
                    .is_some_and(|cd| cd.min_duration > Duration::ZERO),
                "IntegralTriggered with max_accumulated_pressure < 1.0 requires a \
                 non-zero cooldown to prevent rotation loops; call .with_cooldown(duration)"
            );
        }
    }
}

/// True when `policy` may fire given the current `EpochPhase`.
///
/// PostReset: nothing is admissible (estimator invalid).
/// Reconverging: only estimator-independent policies (QueryCount, TimeBased, etc.).
/// Steady: all policies are admissible.
fn is_admissible(phase: EpochPhase, policy: &PoolRotationPolicy) -> bool {
    match phase {
        EpochPhase::PostReset => false,
        EpochPhase::Reconverging => !matches!(
            policy,
            PoolRotationPolicy::EntropyTriggered { .. }
                | PoolRotationPolicy::JsdTriggered { .. }
                | PoolRotationPolicy::ConvergenceTriggered { .. }
                | PoolRotationPolicy::VelocityTriggered { .. }
                | PoolRotationPolicy::IntegralTriggered { .. }
                | PoolRotationPolicy::BurstTriggered { .. }
        ),
        EpochPhase::Steady => true,
    }
}

/// log₂(C(n, k)) computed iteratively for numerical stability.
///
/// Uses symmetry C(n,k)=C(n,n-k) to reduce the iteration count.
/// Returns 0.0 for k=0, k=n, or k>n (log₂(1)=0 and edge-case guard).
fn log2_binom(n: usize, k: usize) -> f64 {
    if k == 0 || k > n {
        return 0.0;
    }
    let k = k.min(n - k);
    (0..k)
        .map(|i| ((n - i) as f64 / (i + 1) as f64).log2())
        .sum()
}

/// Lemire's nearly-divisionless uniform integer in [0, range).
fn lemire_uniform(rng: &mut impl RngCore, range: u64) -> u64 {
    let mut x = rng.next_u64();
    let mut m = (x as u128) * (range as u128);
    let mut l = m as u64;
    if l < range {
        let t = range.wrapping_neg() % range;
        while l < t {
            x = rng.next_u64();
            m = (x as u128) * (range as u128);
            l = m as u64;
        }
    }
    (m >> 64) as u64
}

pub(crate) fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// ── ProviderPool ─────────────────────────────────────────────────────────────

/// Durable provider universe that constructs disposable `ProviderQuorum` instances.
///
/// Two-tier architecture:
/// - **Active**: current rotation window; `sample()` draws from here.
/// - **Dormant**: universe members outside the active window.
///
/// `active_window = usize::MAX` (default): all providers go to active, rotation
/// is a no-op, and behavior is identical to Phase 12–13.
pub struct ProviderPool<P> {
    active: Vec<([u8; 32], P)>,
    dormant: Vec<([u8; 32], P)>,
    active_window: usize,
    strategy: SamplingStrategy,
    rotation: PoolRotation,
    reputation: ProviderReputation,
    dummy_budget: Arc<Mutex<DummyQueryBudget>>,
    exposure_tracker: Arc<Mutex<ExposureTracker>>,
    liveness: HashMap<[u8; 32], LivenessState>,
    liveness_config: LivenessConfig,
    tick_jitter_max: Duration,
    tick_next_deadline: Instant,
    admission: Option<admission::AdmissionState>,
    eviction: Option<EvictionState>,
    /// Opt-in admissible paired-outcome tracker. `None` by default.
    /// Populated only after `with_admissible_tracking()` is called.
    admissible_tracker: Option<AdmissibleExposureTracker>,
}

impl<P> ProviderPool<P> {
    pub fn new(strategy: SamplingStrategy) -> Self {
        Self {
            active: Vec::new(),
            dormant: Vec::new(),
            active_window: usize::MAX,
            strategy,
            rotation: PoolRotation {
                policy: PoolRotationPolicy::Manual,
                budget: ChurnBudget {
                    min_churn: 1,
                    max_churn: 1,
                },
                query_count: 0,
                last_rotation: Instant::now(),
                activation: ActivationStrategy::Uniform,
                reset_policy: ExposureResetPolicy::Never,
                epoch_count: 0,
                previous_distribution: None,
                previous_kappa: None,
                last_churn: None,
                accumulated_kappa: 0.0,
                cooldown: None,
                burst_response_deadline: None,
            },
            reputation: ProviderReputation::new(),
            dummy_budget: Arc::new(Mutex::new(DummyQueryBudget::new())),
            exposure_tracker: Arc::new(Mutex::new(ExposureTracker::new())),
            liveness: HashMap::new(),
            liveness_config: LivenessConfig {
                max_consecutive_failures: u32::MAX,
                max_silence_secs: u64::MAX,
            },
            tick_jitter_max: Duration::ZERO,
            tick_next_deadline: Instant::now(),
            admission: None,
            eviction: None,
            admissible_tracker: None,
        }
    }

    pub fn with_active_window(mut self, n: usize) -> Self {
        self.active_window = n;
        self
    }

    pub fn with_rotation(mut self, policy: PoolRotationPolicy, budget: ChurnBudget) -> Self {
        self.rotation.policy = policy;
        self.rotation.budget = budget;
        self
    }

    pub fn with_activation_strategy(mut self, strategy: ActivationStrategy) -> Self {
        self.rotation.activation = strategy;
        self
    }

    /// Reset the `ExposureTracker` on every rotation (backward-compat shim).
    pub fn with_exposure_reset(self) -> Self {
        self.with_exposure_reset_policy(ExposureResetPolicy::OnRotation)
    }

    /// Set the exposure reset policy. Default is `Never`.
    pub fn with_exposure_reset_policy(mut self, policy: ExposureResetPolicy) -> Self {
        self.rotation.reset_policy = policy;
        self
    }

    /// Gate auto-rotations: after each rotation, `maybe_rotate()` is silenced for
    /// `min_duration`. `force_rotate()` always bypasses the gate.
    pub fn with_cooldown(mut self, min_duration: Duration) -> Self {
        self.rotation.cooldown = Some(RotationCooldown { min_duration });
        self
    }

    /// Enable inter-call timing jitter on `tick()`.
    ///
    /// After each live `tick()` call, a random deadline in `[now, now + max)` is set.
    /// Subsequent immediate calls return `false` until the deadline passes.
    /// Randomizes the observation window without within-call blocking.
    /// `max = Duration::ZERO` (default) disables jitter — `tick()` always proceeds.
    pub fn with_tick_jitter(mut self, max: Duration) -> Self {
        self.tick_jitter_max = max;
        self.tick_next_deadline = Instant::now();
        self
    }

    /// Set the EWMA alpha for exposure entropy smoothing.
    ///
    /// `alpha = 1.0` (default): no smoothing — `smoothed_entropy == raw_entropy`.
    /// `alpha = 0.01`: heavy smoothing, lags ~100 samples behind raw entropy.
    /// `EntropyTriggered` uses the smoothed value, so a low alpha prevents
    /// thrashing when rotation resets the raw distribution to zero.
    pub fn with_entropy_smoothing(self, alpha: f64) -> Self {
        self.exposure_tracker.lock().unwrap().ewma_alpha = alpha;
        self
    }

    /// Configure liveness thresholds for the sampling filter.
    ///
    /// A provider is dead when `consecutive_failures >= max_consecutive_failures`
    /// OR `now - last_seen_secs >= max_silence_secs`. Dead providers are excluded
    /// from `sample()` until `record_response()` is called.
    pub fn with_liveness(mut self, max_consecutive_failures: u32, max_silence_secs: u64) -> Self {
        self.liveness_config = LivenessConfig {
            max_consecutive_failures,
            max_silence_secs,
        };
        self
    }

    /// Enable provider admission control: challenge-response gate + time-windowed budget.
    ///
    /// When configured, `add()` panics (developer error). Use `request_admission()` to
    /// issue a challenge, then `complete_admission()` after the candidate returns a
    /// valid Ed25519 signature over `admission_challenge_message(provider_id, challenge)`.
    pub fn with_admission(mut self, config: AdmissionConfig) -> Self {
        self.admission = Some(admission::AdmissionState::new(config));
        self
    }

    /// Enable eviction control: re-admission cooldowns, lifetime counter, and operator bans.
    ///
    /// When configured, `evict()` records an `EvictionRecord` that gates future
    /// `request_admission()` calls for the same provider.  Must be paired with
    /// `with_admission()` for re-admission gating to take effect.
    pub fn with_eviction(mut self, config: eviction::EvictionConfig) -> Self {
        self.eviction = Some(EvictionState::new(config));
        self
    }

    /// Opt in to admissible paired-outcome telemetry with a finite outstanding-receipt bound.
    ///
    /// `max_outstanding_receipts` is the maximum number of unresolved receipts that may
    /// exist simultaneously. When `sample_with_receipts()` is called and the outstanding
    /// count is already at this bound, the entire call fails with
    /// `Err(AdmissibilityError::ReceiptCapacityExhausted)` — provider selection does not
    /// occur, raw selection accounting is unchanged, and no new receipt is created.
    ///
    /// Capacity is restored one unit at a time as receipts are consumed by terminal outcomes
    /// (`record_admissible_response` / `record_admissible_failure`) or cleared in bulk by
    /// epoch rotation (`drain_epoch`).
    ///
    /// A value of `0` means no receipts may ever be outstanding (all receipt-bearing samples
    /// immediately return `ReceiptCapacityExhausted`). Use a positive bound that fits the
    /// expected in-flight request window for the deployment.
    ///
    /// Without this call, `sample_with_receipts()` returns an empty receipt `Vec`,
    /// and `record_admissible_response()` / `record_admissible_failure()` return
    /// `Err(AdmissibilityError::NotConfigured)`.
    ///
    /// The admissible tracker inherits the pool's current exposure reset policy.
    pub fn with_admissible_tracking(mut self, max_outstanding_receipts: usize) -> Self {
        let reset_policy = self.rotation.reset_policy.clone();
        self.admissible_tracker = Some(AdmissibleExposureTracker::new(
            reset_policy,
            max_outstanding_receipts,
        ));
        self
    }

    /// Request admission for a candidate provider.
    ///
    /// Returns a 32-byte random challenge to send to the candidate. The candidate must
    /// sign `admission_challenge_message(&provider_id, &challenge)` with the private key
    /// corresponding to `provider_id` and return the signature for `complete_admission()`.
    ///
    /// Budget is decremented on each successful call. Expired or failed challenges do not
    /// refund the budget — this prevents retry flooding within a window.
    pub fn request_admission(&mut self, provider_id: [u8; 32]) -> Result<[u8; 32], AdmissionError> {
        use rand_core::RngCore;

        if self.admission.is_none() {
            return Err(AdmissionError::NotConfigured);
        }

        // Eviction check runs FIRST — before budget is claimed.
        // Rejected providers must never consume a budget slot. [POOL-10]
        if let Some(eviction) = &self.eviction {
            if let Some(err) = eviction.check_admission(&provider_id, now_secs()) {
                return Err(err);
            }
        }

        // Duplicate check against current pool contents (immutable borrows of different fields).
        if self.active.iter().any(|(id, _)| id == &provider_id)
            || self.dormant.iter().any(|(id, _)| id == &provider_id)
        {
            return Err(AdmissionError::AlreadyInPool);
        }
        let admission = self.admission.as_mut().unwrap();
        if admission.pending.contains_key(&provider_id) {
            return Err(AdmissionError::PendingChallenge);
        }
        if !admission.check_and_claim_budget() {
            return Err(AdmissionError::BudgetExhausted);
        }
        let mut challenge = [0u8; 32];
        rand_core::OsRng.fill_bytes(&mut challenge);
        admission.pending.insert(
            provider_id,
            admission::PendingAdmission {
                challenge,
                issued_at: std::time::Instant::now(),
            },
        );
        Ok(challenge)
    }

    /// Verify a signed challenge response and admit the provider into the pool.
    ///
    /// `sig` must be an Ed25519 signature of
    /// `admission_challenge_message(&provider_id, &challenge)` by the key corresponding
    /// to `provider_id`.
    ///
    /// On success, calls the internal add path (bypassing the admission gate assertion).
    /// On failure, the pending challenge is preserved until TTL expires.
    pub fn complete_admission(
        &mut self,
        provider_id: [u8; 32],
        sig: &[u8; 64],
        provider: P,
    ) -> Result<(), AdmissionError> {
        // Verification phase — immutable borrow of self.admission.
        {
            let admission = self
                .admission
                .as_ref()
                .ok_or(AdmissionError::NotConfigured)?;
            admission.verify(&provider_id, sig)?;
        }
        // Remove the consumed challenge.
        self.admission
            .as_mut()
            .unwrap()
            .pending
            .remove(&provider_id);
        // If the provider was previously evicted, increment the lifetime re-admission counter.
        if let Some(eviction) = self.eviction.as_mut() {
            eviction.record_readmission(&provider_id);
        }
        // Admit into pool (bypasses the add() assertion by going directly to the tier logic).
        if self.active.len() < self.active_window {
            self.active.push((provider_id, provider));
        } else {
            self.dormant.push((provider_id, provider));
        }
        Ok(())
    }

    /// Permanently remove a provider from the active or dormant set.
    ///
    /// Records an `EvictionRecord` so that future `request_admission()` calls for the same
    /// `provider_id` are gated by cooldown and re-admission limits.
    ///
    /// # Errors
    ///
    /// - `EvictionError::NotConfigured` — `with_eviction()` was not called on this pool.
    /// - `EvictionError::NotFound` — provider is not in active or dormant.
    /// - `EvictionError::WouldViolateDormantFloor` — removing from dormant would leave
    ///   `dormant.len() < active_window`, making future rotation impossible. [POOL-5]
    pub fn evict(
        &mut self,
        provider_id: &[u8; 32],
        reason: eviction::EvictionReason,
    ) -> Result<(), eviction::EvictionError> {
        if self.eviction.is_none() {
            return Err(eviction::EvictionError::NotConfigured);
        }

        let in_active = self.active.iter().position(|(id, _)| id == provider_id);
        let in_dormant = if in_active.is_none() {
            self.dormant.iter().position(|(id, _)| id == provider_id)
        } else {
            None
        };

        if in_active.is_none() && in_dormant.is_none() {
            return Err(eviction::EvictionError::NotFound);
        }

        // Floor gate [POOL-5]: only applies when removing from dormant and rotation is
        // configured (active_window != usize::MAX means rotation is a real constraint).
        if in_dormant.is_some()
            && self.active_window != usize::MAX
            && self.dormant.len().saturating_sub(1) < self.active_window
        {
            return Err(eviction::EvictionError::WouldViolateDormantFloor);
        }

        // Remove from whichever tier holds the provider.
        if let Some(idx) = in_active {
            self.active.swap_remove(idx);
        } else if let Some(idx) = in_dormant {
            self.dormant.swap_remove(idx);
        }

        // Clear liveness state — provider is no longer in the universe.
        self.liveness.remove(provider_id);

        // Record the eviction.
        self.eviction
            .as_mut()
            .unwrap()
            .record_eviction(*provider_id, reason, now_secs());

        Ok(())
    }

    /// Lift an `OperatorBan` by removing the eviction record.
    ///
    /// Returns `true` if a ban record was found and removed, `false` if no ban exists
    /// or eviction is not configured. After lifting, `request_admission()` may proceed.
    pub fn lift_eviction_ban(&mut self, provider_id: &[u8; 32]) -> bool {
        self.eviction
            .as_mut()
            .is_some_and(|e| e.lift_ban(provider_id))
    }

    /// Inspect a provider's eviction record. Returns `None` if the provider has never
    /// been evicted or eviction is not configured.
    pub fn eviction_record(&self, provider_id: &[u8; 32]) -> Option<&eviction::EvictionRecord> {
        self.eviction.as_ref()?.record(provider_id)
    }

    /// Configure exponential half-life decay on reputation-derived equivocation weights.
    ///
    /// After `half_life_secs` seconds, a provider's effective equivocation count is
    /// halved. The floor constraint in `WeightedByReputation` remains absolute.
    pub fn with_reputation_decay(mut self, half_life_secs: u64) -> Self {
        self.reputation.half_life_secs = Some(half_life_secs);
        self
    }

    /// Record a successful response from a provider. Resets consecutive failure count.
    pub fn record_response(&mut self, provider_id: [u8; 32]) {
        let entry = self.liveness.entry(provider_id).or_insert(LivenessState {
            last_seen_secs: 0,
            consecutive_failures: 0,
        });
        entry.last_seen_secs = now_secs();
        entry.consecutive_failures = 0;
        self.exposure_tracker
            .lock()
            .unwrap()
            .record_response(&provider_id);
    }

    /// Record a failed or unresponsive query to a provider.
    pub fn record_failure(&mut self, provider_id: [u8; 32]) {
        let entry = self.liveness.entry(provider_id).or_insert(LivenessState {
            last_seen_secs: now_secs(),
            consecutive_failures: 0,
        });
        entry.consecutive_failures = entry.consecutive_failures.saturating_add(1);
    }

    /// Record a response against a valid `SelectionReceipt` on the admissible surface.
    ///
    /// TELEMETRY-ONLY — not authorized for any automatic policy action.
    ///
    /// Does NOT update the raw `response_total` counter. The two surfaces are orthogonal.
    /// If the orchestration layer also wants the raw surface updated, call `record_response()`
    /// separately in addition to this method.
    ///
    /// Returns `Ok(())` when the receipt passes all admissibility conditions.
    /// Returns `Err(AdmissibilityError::NotConfigured)` when `with_admissible_tracking()`
    /// was not called on this pool.
    pub fn record_admissible_response(
        &mut self,
        receipt: &SelectionReceipt,
    ) -> Result<(), AdmissibilityError> {
        match self.admissible_tracker.as_mut() {
            None => Err(AdmissibilityError::NotConfigured),
            Some(adm) => adm.record_admissible_response(receipt),
        }
    }

    /// Record a failure against a valid `SelectionReceipt` on the admissible surface.
    ///
    /// TELEMETRY-ONLY — not authorized for any automatic policy action.
    ///
    /// Does NOT update raw liveness counters. Call `record_failure()` separately if needed.
    ///
    /// Returns `Ok(())` when the receipt passes all admissibility conditions.
    /// Returns `Err(AdmissibilityError::NotConfigured)` when `with_admissible_tracking()`
    /// was not called on this pool.
    pub fn record_admissible_failure(
        &mut self,
        receipt: &SelectionReceipt,
    ) -> Result<(), AdmissibilityError> {
        match self.admissible_tracker.as_mut() {
            None => Err(AdmissibilityError::NotConfigured),
            Some(adm) => adm.record_admissible_failure(receipt),
        }
    }

    /// Effective equivocation count at an explicit timestamp (for testing decay formulas).
    pub fn effective_equivocation_count_at(
        &self,
        provider_id: [u8; 32],
        class: &SemanticClassId,
        now: u64,
    ) -> f64 {
        self.reputation
            .effective_equivocation_count_at(&provider_id, class, now)
    }

    fn is_live(&self, provider_id: &[u8; 32]) -> bool {
        match self.liveness.get(provider_id) {
            None => true,
            Some(state) => {
                state.consecutive_failures < self.liveness_config.max_consecutive_failures
                    && now_secs().saturating_sub(state.last_seen_secs)
                        < self.liveness_config.max_silence_secs
            }
        }
    }

    pub fn add(&mut self, provider_id: [u8; 32], provider: P) {
        assert!(
            self.admission.is_none(),
            "ProviderPool has admission configured; use complete_admission() to add providers"
        );
        if self.active.len() < self.active_window {
            self.active.push((provider_id, provider));
        } else {
            self.dormant.push((provider_id, provider));
        }
    }

    /// Total universe size (active + dormant).
    pub fn len(&self) -> usize {
        self.active.len() + self.dormant.len()
    }

    pub fn is_empty(&self) -> bool {
        self.active.is_empty() && self.dormant.is_empty()
    }

    pub fn active_len(&self) -> usize {
        self.active.len()
    }

    /// Number of rotations since pool creation.
    pub fn epoch_count(&self) -> u32 {
        self.rotation.epoch_count
    }

    pub fn record_equivocation(&mut self, evidence: &EquivocationEvidence) {
        self.reputation.record_equivocation(evidence);
    }

    /// Enable continuous exposure decay with the given half-life in seconds.
    ///
    /// After `half_life_secs` seconds since the last `sample()` call,
    /// `effective_total_samples` halves. Ratio-based fields (entropy, max_rate)
    /// are unaffected. Default: no decay.
    pub fn with_exposure_decay(self, half_life_secs: u64) -> Self {
        self.exposure_tracker.lock().unwrap().decay_half_life_secs = Some(half_life_secs);
        self
    }

    /// Return a snapshot of the observed provider selection exposure.
    ///
    /// Useful for monitoring and external rotation policy decisions.
    pub fn exposure_estimate(&self) -> ExposureEstimate {
        self.exposure_tracker.lock().unwrap().estimate()
    }

    /// Return the exposure estimate as of an explicit wall-clock timestamp.
    ///
    /// Useful for testing decay behavior without waiting for real time to pass.
    /// Pass `now_secs() + N` to observe what the estimate would look like `N`
    /// seconds after the last `sample()` call.
    pub fn exposure_estimate_at(&self, now: u64) -> ExposureEstimate {
        self.exposure_tracker.lock().unwrap().estimate_at(now)
    }

    /// Returns the IDs of currently active providers.
    ///
    /// Used with `epoch_similarity` to measure active-set diversity across epochs.
    pub fn active_set_snapshot(&self) -> Vec<[u8; 32]> {
        self.active.iter().map(|(id, _)| *id).collect()
    }

    /// Returns the per-provider selection probability distribution.
    ///
    /// Normalized by total appearances so the distribution is proper for any k.
    /// Returns empty rates when no samples have been recorded.
    pub fn exposure_distribution(&self) -> ExposureDistribution {
        self.exposure_tracker.lock().unwrap().distribution()
    }

    /// Convergence-pressure snapshot for the current pool state.
    ///
    /// Normalizes the raw `ExposureEstimate` by pool capacity so that thresholds
    /// transfer across pool sizes. See `ConvergencePressure` for field semantics.
    pub fn convergence_pressure(&self) -> ConvergencePressure {
        let n = self.active.len();
        let (estimate, distribution) = {
            let tracker = self.exposure_tracker.lock().unwrap();
            (tracker.estimate(), tracker.distribution())
        };
        let r = estimate.max_selection_rate;
        let kappa = if n <= 1 {
            1.0
        } else {
            (1.0 - estimate.selection_entropy_bits / (n as f64).log2()).clamp(0.0, 1.0)
        };
        let smoothed_kappa = if n <= 1 {
            1.0
        } else {
            (1.0 - estimate.smoothed_selection_entropy_bits / (n as f64).log2()).clamp(0.0, 1.0)
        };
        let liveness_weighted_kappa = if n <= 1 {
            1.0
        } else {
            (1.0 - estimate.response_entropy_bits / (n as f64).log2()).clamp(0.0, 1.0)
        };
        let smoothed_liveness_weighted_kappa = if n <= 1 {
            1.0
        } else {
            (1.0 - estimate.smoothed_response_entropy_bits / (n as f64).log2()).clamp(0.0, 1.0)
        };
        let uniform_rate = if n == 0 { 0.0 } else { 1.0 / n as f64 };
        let spectral_concentration = (r - uniform_rate).max(0.0);
        let confidence_growth_rate = r * (1.0 - r).powf(estimate.total_samples as f64);
        let samples_to_saturation = if r <= 0.0 {
            None
        } else {
            let current_confidence = 1.0 - (1.0 - r).powf(estimate.total_samples as f64);
            if current_confidence >= 0.5 {
                Some(0u64)
            } else {
                let n_total = ((1.0_f64 - 0.5).ln() / (1.0 - r).ln()).ceil() as u64;
                Some(n_total.saturating_sub(estimate.total_samples))
            }
        };
        let epoch_divergence = self
            .rotation
            .previous_distribution
            .as_ref()
            .map(|prev| exposure_divergence(&distribution.rates, prev));
        let kappa_velocity = self.rotation.previous_kappa.map(|pk| kappa - pk);
        let d = self.dormant.len();
        let transition_entropy = if n == 0 || d == 0 {
            None
        } else {
            let k_mean =
                (self.rotation.budget.min_churn + self.rotation.budget.max_churn) as f64 / 2.0;
            let k = (k_mean.round() as usize).min(n).min(d);
            Some(log2_binom(n, k) + log2_binom(d, k))
        };
        let active_set_halflife_epochs = self.rotation.last_churn.map(|k| {
            if k == 0 || n == 0 {
                f64::INFINITY
            } else if k >= n {
                0.0
            } else {
                -std::f64::consts::LN_2 / (1.0 - k as f64 / n as f64).ln()
            }
        });
        let accumulated_pressure = self.rotation.accumulated_kappa;
        ConvergencePressure {
            active_n: n,
            kappa,
            smoothed_kappa,
            spectral_concentration,
            confidence_growth_rate,
            samples_to_saturation,
            epoch_divergence,
            kappa_velocity,
            transition_entropy,
            active_set_halflife_epochs,
            accumulated_pressure,
            liveness_weighted_kappa,
            smoothed_liveness_weighted_kappa,
            total_samples: estimate.total_samples,
            current_epoch_phase: EpochPhase::for_pool(estimate.total_samples, n),
        }
    }

    /// Returns an operator-readable snapshot covering all three liveness surfaces.
    ///
    /// No composite health score. Each surface carries its own evidence context and
    /// evaluability flag. Surface 2 (liveness_weighted_kappa) and Surface 3 (absolute
    /// availability) are TELEMETRY-ONLY — they do not drive any automatic policy action.
    pub fn operational_telemetry(&self) -> OperationalTelemetrySnapshot {
        let estimate = {
            let tracker = self.exposure_tracker.lock().unwrap();
            tracker.estimate()
        };
        let n = self.active.len();
        let kappa = if n <= 1 {
            1.0
        } else {
            (1.0 - estimate.selection_entropy_bits / (n as f64).log2()).clamp(0.0, 1.0)
        };
        let liveness_weighted_kappa = if n <= 1 {
            1.0
        } else {
            (1.0 - estimate.response_entropy_bits / (n as f64).log2()).clamp(0.0, 1.0)
        };
        let selection_total = estimate.total_samples;
        let response_total = estimate.response_total_samples;
        let epoch_phase = EpochPhase::for_pool(selection_total, n);
        let (admissible_response_total, admissible_failure_total, admissible_selection_total) =
            match &self.admissible_tracker {
                Some(adm) => (
                    adm.admissible_response_total,
                    adm.admissible_failure_total,
                    adm.admissible_selection_total,
                ),
                None => (0, 0, 0),
            };

        OperationalTelemetrySnapshot {
            kappa,
            survivor_surface_evaluable: epoch_phase != EpochPhase::PostReset,
            liveness_weighted_kappa,
            liveness_surface_evaluable: response_total > 0 && selection_total > 0,
            response_total,
            selection_total,
            availability_evaluable: selection_total > 0,
            current_epoch_phase: epoch_phase,
            active_n: n,
            admissible_response_total,
            admissible_failure_total,
            admissible_selection_total,
        }
    }

    pub fn maybe_rotate(&mut self, rng: &mut impl RngCore) -> RotationOutcome {
        assert_integral_safety(&self.rotation.policy, &self.rotation.cooldown);
        let n = self.active.len();
        if self.dormant.is_empty() {
            return RotationOutcome::Deferred(DeferralReason::DormantEmpty);
        }
        if self.active_window > 0 && self.dormant.len() < self.active_window {
            return RotationOutcome::Deferred(DeferralReason::DormantBelowFloor);
        }
        if let Some(ref cd) = self.rotation.cooldown {
            if self.rotation.last_rotation.elapsed() < cd.min_duration {
                return RotationOutcome::Deferred(DeferralReason::Cooldown);
            }
        }
        let epoch_phase = {
            let ts = self
                .exposure_tracker
                .lock()
                .unwrap()
                .estimate()
                .total_samples;
            EpochPhase::for_pool(ts, n)
        };
        if !is_admissible(epoch_phase, &self.rotation.policy) {
            return RotationOutcome::Deferred(DeferralReason::EstimatorNotConverged);
        }
        let should = match &self.rotation.policy {
            PoolRotationPolicy::Manual => false,
            PoolRotationPolicy::QueryCount(n) => {
                self.rotation.query_count += 1;
                self.rotation.query_count >= *n
            }
            PoolRotationPolicy::TimeBased(d) => self.rotation.last_rotation.elapsed() >= *d,
            PoolRotationPolicy::Hybrid {
                query_count,
                max_age,
            } => {
                self.rotation.query_count += 1;
                self.rotation.query_count >= *query_count
                    || self.rotation.last_rotation.elapsed() >= *max_age
            }
            PoolRotationPolicy::EntropyTriggered { min_entropy_bits } => {
                // Use smoothed entropy to prevent thrashing after a reset.
                self.exposure_tracker
                    .lock()
                    .unwrap()
                    .estimate()
                    .smoothed_selection_entropy_bits
                    < *min_entropy_bits
            }
            PoolRotationPolicy::JitteredTimeBased {
                base,
                jitter_fraction,
            } => {
                let elapsed = self.rotation.last_rotation.elapsed();
                let jitter_secs = base.as_secs_f64()
                    * jitter_fraction
                    * (rng.next_u64() as f64 / u64::MAX as f64);
                let threshold = *base + Duration::from_secs_f64(jitter_secs);
                elapsed >= threshold
            }
            PoolRotationPolicy::JsdTriggered { min_divergence } => {
                let current = self.exposure_tracker.lock().unwrap().distribution();
                match &self.rotation.previous_distribution {
                    None => false,
                    Some(prev) => exposure_divergence(&current.rates, prev) < *min_divergence,
                }
            }
            PoolRotationPolicy::ConvergenceTriggered { max_kappa } => {
                self.convergence_pressure().kappa > *max_kappa
            }
            PoolRotationPolicy::VelocityTriggered { max_velocity } => self
                .convergence_pressure()
                .kappa_velocity
                .is_some_and(|v| v > *max_velocity),
            PoolRotationPolicy::IntegralTriggered {
                max_accumulated_pressure,
            } => {
                let max = *max_accumulated_pressure;
                let kappa = self.convergence_pressure().kappa;
                self.rotation.accumulated_kappa += kappa;
                self.rotation.accumulated_kappa > max
            }
            PoolRotationPolicy::BurstTriggered {
                min_burst_magnitude,
                response_jitter_max,
            } => {
                let pressure = self.convergence_pressure();
                let burst = pressure.kappa - pressure.smoothed_kappa;
                let max_jitter = *response_jitter_max;

                if burst > *min_burst_magnitude {
                    match self.rotation.burst_response_deadline {
                        None if max_jitter > Duration::ZERO => {
                            let frac = rng.next_u64() as f64 / u64::MAX as f64;
                            let delay_ns = (frac * max_jitter.as_nanos() as f64) as u64;
                            self.rotation.burst_response_deadline =
                                Some(Instant::now() + Duration::from_nanos(delay_ns));
                            false
                        }
                        Some(deadline) if Instant::now() < deadline => false,
                        _ => {
                            self.rotation.burst_response_deadline = None;
                            true
                        }
                    }
                } else {
                    self.rotation.burst_response_deadline = None;
                    false
                }
            }
        };
        if should {
            self.do_rotate(rng);
            RotationOutcome::Rotated
        } else {
            RotationOutcome::Deferred(DeferralReason::PolicyThresholdNotMet)
        }
    }

    pub fn force_rotate(&mut self, rng: &mut impl RngCore) {
        if self.dormant.is_empty() {
            return;
        }
        self.do_rotate(rng);
    }

    /// Protocol-facing rotation trigger. Returns `true` iff a rotation occurred.
    ///
    /// Coarsened wrapper around `maybe_rotate()` — callers at the protocol boundary
    /// receive a boolean; `DeferralReason` is never exposed at this surface.
    /// Performs constant-work pressure computation regardless of EpochPhase (34C),
    /// then applies the timing-jitter gate (34B) before invoking `maybe_rotate()`.
    pub fn tick(&mut self, rng: &mut impl RngCore) -> bool {
        let _ = self.convergence_pressure();
        if Instant::now() < self.tick_next_deadline {
            return false;
        }
        let result = matches!(self.maybe_rotate(rng), RotationOutcome::Rotated);
        if self.tick_jitter_max > Duration::ZERO {
            let frac = rng.next_u64() as f64 / u64::MAX as f64;
            let jitter_ns = (frac * self.tick_jitter_max.as_nanos() as f64) as u64;
            self.tick_next_deadline = Instant::now() + Duration::from_nanos(jitter_ns);
        }
        result
    }

    /// Number of providers in the active window.
    pub fn active_count(&self) -> usize {
        self.active.len()
    }

    /// Number of providers in the dormant tier.
    pub fn dormant_count(&self) -> usize {
        self.dormant.len()
    }

    /// Current normalized convergence pressure κ ∈ [0.0, 1.0].
    ///
    /// Bounded diagnostic — discloses κ without exposing `EpochPhase` or `DeferralReason`.
    pub fn kappa(&self) -> f64 {
        self.convergence_pressure().kappa
    }

    fn do_rotate(&mut self, rng: &mut impl RngCore) {
        let max_possible = self
            .rotation
            .budget
            .max_churn
            .min(self.active.len())
            .min(self.dormant.len());
        let min_possible = self.rotation.budget.min_churn.min(max_possible);
        let spread = (max_possible - min_possible) as u64;
        let n = min_possible
            + if spread == 0 {
                0
            } else {
                lemire_uniform(rng, spread + 1) as usize
            };

        // Record actual churn and end-of-epoch κ for trajectory metrics in the next epoch.
        self.rotation.last_churn = Some(n);
        self.rotation.previous_kappa = Some(self.convergence_pressure().kappa);

        // Two-phase swap: collect all evictions first, then activate from the
        // original dormant set. Prevents a just-evicted provider from being
        // immediately re-selected as an activation.
        let mut evicted = Vec::with_capacity(n);
        for _ in 0..n {
            let i = lemire_uniform(rng, self.active.len() as u64) as usize;
            evicted.push(self.active.swap_remove(i));
        }
        for _ in 0..n {
            let j = match &self.rotation.activation {
                ActivationStrategy::Uniform => {
                    lemire_uniform(rng, self.dormant.len() as u64) as usize
                }
                ActivationStrategy::WeightedByReputation { influence, floor } => {
                    let (influence, floor) = (*influence, *floor);
                    let weights: Vec<f64> = self
                        .dormant
                        .iter()
                        .map(|(pid, _)| {
                            let eq = self.reputation.effective_equivocation_count(
                                pid,
                                &SemanticClassId::ConsensusRelevant,
                            );
                            (1.0 / (1.0 + influence * eq)).max(floor)
                        })
                        .collect();
                    let total: f64 = weights.iter().sum();
                    let u = (rng.next_u64() as f64 / u64::MAX as f64) * total;
                    let mut cumulative = 0.0f64;
                    let mut sel = self.dormant.len() - 1;
                    for (idx, &w) in weights.iter().enumerate() {
                        cumulative += w;
                        if u < cumulative {
                            sel = idx;
                            break;
                        }
                    }
                    sel
                }
                ActivationStrategy::WeightedComposite {
                    influence,
                    floor,
                    liveness_discount,
                } => {
                    let (influence, floor, liveness_discount) =
                        (*influence, *floor, *liveness_discount);
                    let weights: Vec<f64> = self
                        .dormant
                        .iter()
                        .map(|(pid, _)| {
                            let eq = self.reputation.effective_equivocation_count(
                                pid,
                                &SemanticClassId::ConsensusRelevant,
                            );
                            let rep_weight = (1.0 / (1.0 + influence * eq)).max(floor);
                            let lf = if self.is_live(pid) {
                                1.0
                            } else {
                                liveness_discount
                            };
                            rep_weight * lf
                        })
                        .collect();
                    let total: f64 = weights.iter().sum();
                    // If all weights are zero (all dead, discount=0), fall back to uniform.
                    if total <= 0.0 {
                        lemire_uniform(rng, self.dormant.len() as u64) as usize
                    } else {
                        let u = (rng.next_u64() as f64 / u64::MAX as f64) * total;
                        let mut cumulative = 0.0f64;
                        let mut sel = self.dormant.len() - 1;
                        for (idx, &w) in weights.iter().enumerate() {
                            cumulative += w;
                            if u < cumulative {
                                sel = idx;
                                break;
                            }
                        }
                        sel
                    }
                }
                ActivationStrategy::VisibilityCapped {
                    max_visibility_ratio,
                    floor,
                } => {
                    let (cap, floor) = (*max_visibility_ratio, *floor);
                    // Lock tracker, collect rates, then release before weighted selection.
                    let rates: Vec<f64> = {
                        let tracker = self.exposure_tracker.lock().unwrap();
                        self.dormant
                            .iter()
                            .map(|(pid, _)| tracker.rate(pid))
                            .collect()
                    };
                    let weights: Vec<f64> = rates
                        .iter()
                        .map(|&rate| (cap / rate.max(cap * 1e-6)).min(1.0).max(floor))
                        .collect();
                    let total: f64 = weights.iter().sum();
                    let u = (rng.next_u64() as f64 / u64::MAX as f64) * total;
                    let mut cumulative = 0.0f64;
                    let mut sel = self.dormant.len() - 1;
                    for (idx, &w) in weights.iter().enumerate() {
                        cumulative += w;
                        if u < cumulative {
                            sel = idx;
                            break;
                        }
                    }
                    sel
                }
            };
            self.active.push(self.dormant.swap_remove(j));
        }
        self.dormant.extend(evicted);

        // Snapshot distribution before optional reset, for JsdTriggered baseline in next epoch.
        {
            let dist = self.exposure_tracker.lock().unwrap().distribution();
            self.rotation.previous_distribution = Some(dist.rates);
        }

        self.rotation.query_count = 0;
        self.rotation.last_rotation = Instant::now();
        self.rotation.epoch_count = self.rotation.epoch_count.saturating_add(1);

        let should_reset = match &self.rotation.reset_policy {
            ExposureResetPolicy::Never => false,
            ExposureResetPolicy::OnRotation => true,
            ExposureResetPolicy::AfterEpochs { n } => self.rotation.epoch_count.is_multiple_of(*n),
        };
        if should_reset {
            self.exposure_tracker.lock().unwrap().reset();
        }

        // Drain all outstanding admissible receipts on epoch rotation.
        // This MUST happen after epoch_count is incremented (Condition C from gate §11).
        if let Some(ref mut adm) = self.admissible_tracker {
            adm.drain_epoch(self.rotation.epoch_count);
        }

        self.rotation.accumulated_kappa = 0.0;
        self.rotation.burst_response_deadline = None;
    }
}

/// Raw selected (id, provider) pairs alongside their issued `SelectionReceipt`s,
/// as returned by `sample_selected_with_receipts()`.
pub type SelectionWithReceipts<P> = (Vec<([u8; 32], P)>, Vec<SelectionReceipt>);

// Option 2 (multi-relay routing) note: `sample_inner` lives here, in a
// StateProvider-free block, because it calls no StateProvider method — the
// StateProvider bound below exists only to package results into a
// ProviderQuorum<P>. This split is what lets a real (non-StateProvider)
// delivery endpoint reuse the pool's selection/liveness/exposure engine via
// `sample_selected()` / `sample_selected_with_receipts()` without being forced
// to answer state-consistency questions it has no opinion on. See
// docs/architecture/PROVIDERPOOL_MULTIRELAY_ARCHITECTURE_DESIGN.md §1.
impl<P: Clone> ProviderPool<P> {
    /// Shared selection logic used by both `sample()` and `sample_with_receipts()`.
    ///
    /// Applies the configured `SamplingStrategy`, calls `ExposureTracker::record(&ids)`
    /// exactly once (raw accounting), and returns the selected providers.
    /// Both `sample()` and `sample_with_receipts()` call this — never both at once,
    /// so raw accounting is incremented exactly once per user-facing call.
    fn sample_inner(&self, rng: &mut impl RngCore) -> Vec<([u8; 32], P)> {
        // Filter to live active providers before applying any strategy.
        let live_indices: Vec<usize> = (0..self.active.len())
            .filter(|&i| self.is_live(&self.active[i].0))
            .collect();
        let n = live_indices.len();

        let selected: Vec<([u8; 32], P)> = match &self.strategy {
            SamplingStrategy::RandomK(k) => {
                if n == 0 {
                    return Vec::new();
                }
                let k = (*k).min(n);
                let mut live = live_indices.clone();
                for i in 0..k {
                    let j = i + lemire_uniform(rng, (n - i) as u64) as usize;
                    live.swap(i, j);
                }
                live[..k]
                    .iter()
                    .map(|&i| (self.active[i].0, self.active[i].1.clone()))
                    .collect()
            }

            SamplingStrategy::WeightedByReputation {
                k,
                influence,
                floor,
            } => {
                if n == 0 {
                    return Vec::new();
                }
                let k = (*k).min(n);
                let (influence, floor) = (*influence, *floor);
                let mut available: Vec<(usize, f64)> = live_indices
                    .iter()
                    .map(|&i| {
                        let (pid, _) = &self.active[i];
                        let eq = self
                            .reputation
                            .effective_equivocation_count(pid, &SemanticClassId::ConsensusRelevant);
                        (i, (1.0 / (1.0 + influence * eq)).max(floor))
                    })
                    .collect();

                let mut selected = Vec::with_capacity(k);
                for _ in 0..k {
                    let total: f64 = available.iter().map(|(_, w)| w).sum();
                    let u = (rng.next_u64() as f64 / u64::MAX as f64) * total;
                    let mut cumulative = 0.0;
                    let mut sel = available.len() - 1;
                    for (j, (_, w)) in available.iter().enumerate() {
                        cumulative += w;
                        if u < cumulative {
                            sel = j;
                            break;
                        }
                    }
                    let (provider_idx, _) = available.swap_remove(sel);
                    selected.push((
                        self.active[provider_idx].0,
                        self.active[provider_idx].1.clone(),
                    ));
                }
                selected
            }

            SamplingStrategy::Threshold { min_k, max_k } => {
                if n == 0 {
                    return Vec::new();
                }
                let k = (*max_k).min(n).max((*min_k).min(n));
                let mut live = live_indices.clone();
                for i in 0..k {
                    let j = i + lemire_uniform(rng, (n - i) as u64) as usize;
                    live.swap(i, j);
                }
                live[..k]
                    .iter()
                    .map(|&i| (self.active[i].0, self.active[i].1.clone()))
                    .collect()
            }

            SamplingStrategy::WeightedComposite {
                k,
                influence,
                floor,
                liveness_discount,
            } => {
                // Does NOT pre-filter to live_indices — all active providers compete.
                // Dead providers receive weight multiplied by liveness_discount.
                let total_active = self.active.len();
                if total_active == 0 {
                    return Vec::new();
                }
                let k = (*k).min(total_active);
                let (influence, floor, ld) = (*influence, *floor, *liveness_discount);
                if k == 0 {
                    return Vec::new();
                }

                let mut available: Vec<(usize, f64)> = (0..total_active)
                    .map(|i| {
                        let (pid, _) = &self.active[i];
                        let eq = self
                            .reputation
                            .effective_equivocation_count(pid, &SemanticClassId::ConsensusRelevant);
                        let rep_w = (1.0 / (1.0 + influence * eq)).max(floor);
                        let lf = if self.is_live(pid) { 1.0 } else { ld };
                        (i, rep_w * lf)
                    })
                    .collect();

                let mut s = Vec::with_capacity(k);
                for _ in 0..k {
                    let total: f64 = available.iter().map(|(_, w)| w).sum();
                    if total <= 0.0 {
                        break;
                    }
                    let u = (rng.next_u64() as f64 / u64::MAX as f64) * total;
                    let mut cumulative = 0.0;
                    let mut sel = available.len() - 1;
                    for (j, (_, w)) in available.iter().enumerate() {
                        cumulative += w;
                        if u < cumulative {
                            sel = j;
                            break;
                        }
                    }
                    let (provider_idx, _) = available.swap_remove(sel);
                    s.push((
                        self.active[provider_idx].0,
                        self.active[provider_idx].1.clone(),
                    ));
                }
                s
            }
        };

        // Raw selection accounting — called exactly once per sample_inner() invocation.
        let ids: Vec<[u8; 32]> = selected.iter().map(|(id, _)| *id).collect();
        self.exposure_tracker.lock().unwrap().record(&ids);

        selected
    }

    /// StateProvider-free selection. Returns the raw selected (id, endpoint)
    /// pairs WITHOUT packaging them into a ProviderQuorum. This is the seam
    /// a real delivery-routing consumer (e.g. DeliveryPool, provider/delivery
    /// crate) uses — it reuses the full selection / liveness-filter /
    /// weighted-strategy / exposure-accounting path with no duplication, and
    /// with no StateProvider bound on `P`.
    pub fn sample_selected(&self, rng: &mut impl RngCore) -> Vec<([u8; 32], P)> {
        self.sample_inner(rng)
    }

    /// StateProvider-free receipt-issuing selection — the admissible-surface
    /// analog of `sample_selected()`. Identical logic to `sample_with_receipts()`
    /// (same capacity check, same `sample_inner()` call, same receipt-issuance
    /// loop), minus `ProviderQuorum` packaging, which is the only part requiring
    /// `StateProvider`. See `sample_with_receipts()` below for the full contract
    /// (capacity refusal, no-tracking-configured, counter-exhaustion behavior) —
    /// this method preserves it exactly.
    pub fn sample_selected_with_receipts(
        &mut self,
        rng: &mut impl RngCore,
    ) -> Result<SelectionWithReceipts<P>, AdmissibilityError> {
        if let Some(adm) = self.admissible_tracker.as_ref() {
            if adm.outstanding.len() >= adm.max_outstanding_receipts {
                return Err(AdmissibilityError::ReceiptCapacityExhausted);
            }
        }

        let selected = self.sample_inner(rng);
        if selected.is_empty() {
            return Ok((Vec::new(), Vec::new()));
        }

        let receipts = match self.admissible_tracker.as_mut() {
            None => Vec::new(),
            Some(adm) => {
                let epoch_count = adm.current_epoch_count;
                let mut rs = Vec::with_capacity(selected.len());
                for (pid, _) in &selected {
                    match adm.issue_receipt(epoch_count, *pid) {
                        Ok(r) => rs.push(r),
                        Err(_) => break, // CounterExhausted — stop issuing, return partial
                    }
                }
                rs
            }
        };

        Ok((selected, receipts))
    }
}

impl<P: Clone + StateProvider> ProviderPool<P> {
    pub fn sample(&self, rng: &mut impl RngCore) -> ProviderQuorum<P> {
        let selected = self.sample_selected(rng);
        if selected.is_empty() {
            ProviderQuorum::new()
        } else {
            ProviderQuorum::from_providers(selected)
        }
    }

    /// Sample providers and issue `SelectionReceipt` tokens for admissible accounting.
    ///
    /// Calls the same internal selection logic as `sample()` — raw `ExposureTracker`
    /// accounting is performed exactly once (no double-counting). Additionally issues
    /// one `SelectionReceipt` per selected provider for use with
    /// `record_admissible_response()` / `record_admissible_failure()`.
    ///
    /// ## Capacity refusal
    ///
    /// When `with_admissible_tracking(max_outstanding_receipts)` was called and the
    /// current outstanding count equals the configured bound, the entire call returns
    /// `Err(AdmissibilityError::ReceiptCapacityExhausted)`. In this case:
    /// - provider selection does NOT occur
    /// - raw selection accounting is unchanged
    /// - no receipt is created
    /// - no admissible accounting changes
    ///
    /// This is the only error returned; it is distinct from provider-selection and
    /// outcome-validation failures so tests can distinguish it deterministically.
    ///
    /// ## No tracking configured
    ///
    /// When `with_admissible_tracking()` was not called, the receipt `Vec` is empty
    /// and `Ok` is returned (callers that ignore receipts are unaffected).
    ///
    /// ## Counter exhaustion
    ///
    /// On `AdmissibilityError::CounterExhausted` (u64 overflow; unreachable in practice),
    /// selection has already occurred but receipt issuance stops early; partial receipts
    /// are returned inside `Ok`.
    ///
    /// Rewritten in terms of `sample_selected_with_receipts()` — identical behavior
    /// (same capacity check, same `sample_inner()` call, same receipt-issuance loop),
    /// now with `ProviderQuorum` packaging factored out into this StateProvider-bound
    /// wrapper. See docs/architecture/PROVIDERPOOL_MULTIRELAY_ARCHITECTURE_DESIGN.md §1.3.
    pub fn sample_with_receipts(
        &mut self,
        rng: &mut impl RngCore,
    ) -> Result<(ProviderQuorum<P>, Vec<SelectionReceipt>), AdmissibilityError> {
        let (selected, receipts) = self.sample_selected_with_receipts(rng)?;
        let quorum = if selected.is_empty() {
            ProviderQuorum::new()
        } else {
            ProviderQuorum::from_providers(selected)
        };
        Ok((quorum, receipts))
    }

    pub fn maybe_issue_dummy_query(&self, rng: &mut impl RngCore) {
        if !self.should_emit_dummy(rng) {
            return;
        }
        if !self.dummy_budget.lock().unwrap().can_emit() {
            return;
        }
        let quorum = self.sample(rng);
        let mut dummy_ops_pub = [0u8; 32];
        rng.fill_bytes(&mut dummy_ops_pub);
        let _ = quorum.get_commitment_quorum(&dummy_ops_pub);
    }

    /// Adaptive dummy query probability that scales with observed exposure pressure.
    ///
    /// When the most-exposed provider dominates samples (`max_selection_rate → 1.0`),
    /// dummy probability triples to mask that signal. Clamped to `[0.01, 0.20]`.
    pub fn effective_dummy_probability(&self) -> f64 {
        let max_rate = self
            .exposure_tracker
            .lock()
            .unwrap()
            .estimate()
            .max_selection_rate;
        (DUMMY_QUERY_PROBABILITY * (1.0 + 2.0 * max_rate)).clamp(0.01, 0.20)
    }

    fn should_emit_dummy(&self, rng: &mut impl RngCore) -> bool {
        let p = self.effective_dummy_probability();
        (rng.next_u64() as f64 / u64::MAX as f64) < p
    }
}
