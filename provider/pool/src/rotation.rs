use std::time::{Duration, Instant};

/// When `ProviderPool` automatically rotates its active provider window.
pub enum PoolRotationPolicy {
    /// Caller triggers rotation explicitly via `force_rotate()`.
    Manual,
    /// Rotate after every N calls to `maybe_rotate()`.
    QueryCount(u64),
    /// Rotate when the active window has been live for at least this duration.
    TimeBased(Duration),
    /// Rotate on whichever condition fires first.
    Hybrid { query_count: u64, max_age: Duration },
    /// Rotate when the observed selection entropy falls below this threshold (bits).
    ///
    /// Uses `smoothed_selection_entropy_bits` rather than raw entropy, so the
    /// feedback loop is damped by the EWMA and does not thrash after a reset.
    EntropyTriggered { min_entropy_bits: f64 },
    /// Like `TimeBased` but with per-check random jitter.
    ///
    /// Fires when `elapsed >= base + U(0, base * jitter_fraction)`, where the
    /// jitter is redrawn fresh at every `maybe_rotate()` call. Prevents an
    /// observer from predicting rotation cadence from a fixed timer.
    /// When `base = Duration::ZERO`, fires on every call.
    JitteredTimeBased {
        base: Duration,
        jitter_fraction: f64,
    },
    /// Rotate when consecutive epoch distributions are too similar (JSD below threshold).
    ///
    /// Fires when `JSD(current_distribution, previous_epoch_distribution) < min_divergence`.
    /// Low JSD means probability mass has not shifted — the adversary's predictive advantage
    /// accumulates. `min_divergence = 0.0` never fires (JSD ≥ 0.0 always).
    /// No rotation on the first epoch (no previous baseline exists yet).
    JsdTriggered { min_divergence: f64 },
    /// Rotate when normalized convergence pressure κ(t) exceeds the threshold.
    ///
    /// κ(t) = 1 - entropy_bits / log2(active_n). Unlike `EntropyTriggered`, this threshold
    /// is pool-size-agnostic: `max_kappa = 0.2` carries the same meaning for a 2-provider
    /// pool and a 64-provider pool.
    /// `max_kappa = 0.0` fires whenever κ > 0 (any non-uniform distribution).
    /// `max_kappa = 1.0` never fires (κ ∈ [0.0, 1.0] always).
    /// When `active_n <= 1`, κ = 1.0 (defined), so fires for any `max_kappa < 1.0`.
    ConvergenceTriggered { max_kappa: f64 },
    /// Rotate when κ(t) is increasing faster than `max_velocity` per epoch.
    ///
    /// Fires when `kappa_velocity > max_velocity` where `kappa_velocity = κ_current − κ_prev`.
    /// Derivative-based: detects a worsening trajectory before κ itself becomes critical.
    /// `max_velocity = 0.0` fires whenever κ is increasing at all.
    /// `max_velocity = 1.0` never fires (velocity is bounded in [−1.0, 1.0]).
    /// Never fires on the first epoch (no previous κ baseline exists yet).
    VelocityTriggered { max_velocity: f64 },
    /// Rotate when the sum of κ(t) across `maybe_rotate()` calls exceeds the threshold.
    ///
    /// Fires when `accumulated_kappa > max_accumulated_pressure`.
    /// `accumulated_kappa` increments by the current κ on every `maybe_rotate()` call
    /// and resets to 0.0 on each rotation. Detects sustained moderate pressure
    /// that P and D control miss: pressure that never peaks but never resolves.
    /// `max_accumulated_pressure = 0.0` fires on the very first call (κ ≥ 0 always).
    IntegralTriggered { max_accumulated_pressure: f64 },
    /// Rotate when raw κ(t) exceeds the EWMA-smoothed baseline by `min_burst_magnitude`.
    ///
    /// Fires when `kappa - smoothed_kappa > min_burst_magnitude`. The gap measures
    /// the EWMA lag: a sudden concentration spike raises raw κ while smoothed κ lags.
    /// Distinct from `VelocityTriggered` (single-step Δκ): BurstTriggered integrates over
    /// burst duration and requires sustained elevation above the smoothed baseline.
    ///
    /// `response_jitter_max = Duration::ZERO`: rotate immediately on detection (no forced-trajectory resistance).
    /// `response_jitter_max > Duration::ZERO`: on first detection, draw a random response delay
    /// in `[0, response_jitter_max)` and rotate only after that delay passes. Decouples
    /// burst timing from rotation timing, raising forced-trajectory attack cost.
    ///
    /// Estimator-dependent: not admissible in PostReset or Reconverging.
    BurstTriggered {
        min_burst_magnitude: f64,
        response_jitter_max: Duration,
    },
}

/// Bounds on per-rotation provider replacement count.
///
/// Actual churn count is drawn uniformly in `[min_churn, max_churn]`.
/// Randomizing the count prevents the rotation rate itself from becoming fingerprintable.
pub struct ChurnBudget {
    pub min_churn: usize,
    pub max_churn: usize,
}

/// How `do_rotate` selects dormant providers for activation into the active window.
pub enum ActivationStrategy {
    /// Select uniformly at random. Default; preserves Phase 14–15 behavior.
    Uniform,
    /// Prefer dormant providers with lower equivocation counts.
    ///
    /// Weight = `max(1 / (1 + influence * equivocations), floor)`.
    /// The floor guarantees minimum activation probability for all dormant
    /// providers — no provider is permanently frozen out of the active window.
    /// Eviction remains uniform; bad providers cycle out slowly but can return.
    WeightedByReputation { influence: f64, floor: f64 },
    /// Combines reputation weight with a liveness-aware discount factor.
    ///
    /// Weight = `max(1 / (1 + influence * equivocations), floor) * liveness_factor`,
    /// where `liveness_factor = 1.0` for live providers and `liveness_discount`
    /// for dead providers. `liveness_discount = 0.0` means dead dormant providers
    /// are never activated; `liveness_discount = 1.0` is identical to
    /// `WeightedByReputation`.
    WeightedComposite {
        influence: f64,
        floor: f64,
        liveness_discount: f64,
    },
    /// Damps activation probability of dormant providers over-exposed above `max_visibility_ratio`.
    ///
    /// Weight = `max(floor, min(1.0, cap / rate))` where `cap = max_visibility_ratio`.
    /// Providers with `rate = 0` (never seen) get `weight = 1.0`.
    /// No provider reaches `weight = 0` because `floor > 0`.
    /// This discourages re-activating providers that already dominate the exposure
    /// distribution, reducing long-horizon posterior convergence.
    VisibilityCapped {
        max_visibility_ratio: f64,
        floor: f64,
    },
}

/// When (and whether) `do_rotate` resets the `ExposureTracker`.
///
/// Epoch counter is incremented on every rotation regardless of policy.
/// `smoothed_entropy` is never zeroed — it persists across epochs to prevent
/// `EntropyTriggered` from immediately re-firing after a reset.
#[derive(Clone, Debug)]
pub enum ExposureResetPolicy {
    /// Never reset the tracker. Full history accumulates across all epochs.
    Never,
    /// Reset on every rotation. Entropy reflects the current epoch only.
    OnRotation,
    /// Reset every `n` rotations. Resets at epoch counts divisible by `n`.
    AfterEpochs { n: u32 },
}

/// Minimum time that must elapse between two consecutive auto-rotations.
///
/// Applies as a gate on `maybe_rotate()` only. `force_rotate()` always bypasses it —
/// both paths go through `do_rotate()`, which resets `last_rotation`, so the cooldown
/// clock restarts after any rotation (including forced ones).
/// `Duration::ZERO` is equivalent to no cooldown: the gate never blocks.
/// `Duration::MAX` blocks all auto-rotations indefinitely.
pub struct RotationCooldown {
    pub min_duration: Duration,
}

/// Outcome of a `maybe_rotate()` call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RotationOutcome {
    /// Rotation was performed; active set changed.
    Rotated,
    /// Rotation was not performed.
    Deferred(DeferralReason),
}

/// Why `maybe_rotate()` deferred rotation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeferralReason {
    /// No dormant providers available to rotate in.
    DormantEmpty,
    /// Cooldown period has not elapsed since the last rotation.
    Cooldown,
    /// T4 gate: estimator has insufficient history for this policy.
    ///
    /// Fires when `EpochPhase` is `PostReset` (no policies admissible) or `Reconverging`
    /// and the policy is estimator-dependent. No state was mutated — `accumulated_kappa`
    /// was not incremented, `query_count` was not incremented.
    EstimatorNotConverged,
    /// Dormant pool is smaller than the active window.
    ///
    /// `dormant.len() < active_window` prevents full active-set diversification on rotation.
    /// The pool needs at least `2 × active_window` total providers (dormant ≥ active_window).
    /// Self-resolving only through `pool.add()` calls. Does not fire when `active_window == 0`.
    DormantBelowFloor,
    /// Policy threshold not met; no rotation warranted.
    PolicyThresholdNotMet,
}

pub(crate) struct PoolRotation {
    pub(crate) policy: PoolRotationPolicy,
    pub(crate) budget: ChurnBudget,
    pub(crate) query_count: u64,
    pub(crate) last_rotation: Instant,
    pub(crate) activation: ActivationStrategy,
    pub(crate) reset_policy: ExposureResetPolicy,
    pub(crate) epoch_count: u32,
    pub(crate) previous_distribution: Option<Vec<([u8; 32], f64)>>,
    pub(crate) previous_kappa: Option<f64>,
    pub(crate) last_churn: Option<usize>,
    pub(crate) accumulated_kappa: f64,
    pub(crate) cooldown: Option<RotationCooldown>,
    pub(crate) burst_response_deadline: Option<Instant>,
}
