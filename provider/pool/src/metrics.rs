use std::collections::{HashMap, HashSet};

/// Adversarial epoch lifecycle phase, derived from tracker sample count vs active pool size.
///
/// Determines which rotation policies are estimator-admissible. T1–T3 stability surfaces
/// assume T4 (Steady phase) is satisfied — they should not be evaluated during PostReset
/// or Reconverging. Policies that do not depend on entropy estimates (QueryCount, TimeBased,
/// Hybrid) remain admissible during Reconverging.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EpochPhase {
    /// `total_samples < active_n`: estimator invalid.
    ///
    /// Raw counts are insufficient for law-of-large-numbers. κ = 1.0 reflects absent
    /// data, not genuine convergence pressure. No rotation policies are admissible.
    PostReset,
    /// `active_n ≤ total_samples < 4 * active_n`: estimator partially trustworthy.
    ///
    /// Each provider has been observed on average fewer than 4 times. Entropy-derived
    /// policies are not admissible; estimator-independent policies (QueryCount, TimeBased)
    /// remain admissible.
    Reconverging,
    /// `total_samples ≥ 4 * active_n`: estimator asymptotically reliable.
    ///
    /// All policies are admissible. T1–T3 margins are interpretable.
    Steady,
}

impl EpochPhase {
    /// Classify the current epoch phase from tracker sample count and active pool size.
    pub fn for_pool(total_samples: u64, active_n: usize) -> Self {
        let n = active_n as u64;
        if total_samples < n {
            EpochPhase::PostReset
        } else if total_samples < 4 * n {
            EpochPhase::Reconverging
        } else {
            EpochPhase::Steady
        }
    }
}

/// Jaccard similarity between two active-set snapshots.
///
/// Returns `1.0` for identical sets, `0.0` for disjoint sets, and `1.0`
/// when both slices are empty. Use with `ProviderPool::active_set_snapshot()`
/// to measure how much the active window has diversified across epochs.
pub fn epoch_similarity(a: &[[u8; 32]], b: &[[u8; 32]]) -> f64 {
    if a.is_empty() && b.is_empty() {
        return 1.0;
    }
    let set_a: HashSet<[u8; 32]> = a.iter().copied().collect();
    let set_b: HashSet<[u8; 32]> = b.iter().copied().collect();
    let intersection = set_a.intersection(&set_b).count();
    let union = set_a.union(&set_b).count();
    if union == 0 {
        1.0
    } else {
        intersection as f64 / union as f64
    }
}

/// Jensen-Shannon divergence between two provider selection distributions.
///
/// JSD(P||Q) = 0.5·KL(P||M) + 0.5·KL(Q||M) where M = 0.5·(P+Q).
/// Uses log base 2, so JSD ∈ [0.0, 1.0].
/// Returns 0.0 for identical distributions. Returns 1.0 when supports are disjoint.
/// Both empty: returns 0.0.
pub fn exposure_divergence(a: &[([u8; 32], f64)], b: &[([u8; 32], f64)]) -> f64 {
    if a.is_empty() && b.is_empty() {
        return 0.0;
    }
    let map_a: HashMap<[u8; 32], f64> = a.iter().copied().collect();
    let map_b: HashMap<[u8; 32], f64> = b.iter().copied().collect();
    let all_ids: HashSet<[u8; 32]> = map_a.keys().chain(map_b.keys()).copied().collect();
    let mut jsd = 0.0f64;
    for id in &all_ids {
        let p = *map_a.get(id).unwrap_or(&0.0);
        let q = *map_b.get(id).unwrap_or(&0.0);
        let m = 0.5 * (p + q);
        if p > 0.0 && m > 0.0 {
            jsd += 0.5 * p * (p / m).log2();
        }
        if q > 0.0 && m > 0.0 {
            jsd += 0.5 * q * (q / m).log2();
        }
    }
    jsd.clamp(0.0, 1.0)
}

/// Convergence-pressure snapshot for the current pool epoch.
///
/// Normalizes absolute metrics (entropy bits, max selection rate) by pool capacity so
/// that thresholds transfer across pool sizes. κ = 0 means maximum achievable diversity;
/// κ = 1 means the adversary has a fully concentrated posterior.
pub struct ConvergencePressure {
    /// Active provider count at snapshot time.
    pub active_n: usize,
    /// κ(t): normalized entropy deficit in [0.0, 1.0].
    ///
    /// Defined as `1 - entropy_bits / log2(active_n)`.
    /// 0.0 = fully uniform (no pressure). 1.0 = fully concentrated (maximum pressure).
    /// Returns 1.0 when `active_n <= 1` (no diversity achievable).
    pub kappa: f64,
    /// κ_s(t): EWMA-smoothed convergence pressure in [0.0, 1.0].
    ///
    /// Computed from `smoothed_selection_entropy_bits` rather than raw entropy.
    /// Responds more slowly than `kappa` to sudden distribution changes.
    /// `kappa - smoothed_kappa` is the EWMA lag: positive when a burst has spiked
    /// raw entropy but EWMA has not yet propagated the change.
    /// `EntropyTriggered` and `VelocityTriggered` fire on smoothed state;
    /// a future `BurstTriggered` policy would fire on this gap.
    pub smoothed_kappa: f64,
    /// Spectral concentration: `max_selection_rate - 1/active_n`.
    ///
    /// 0.0 = perfectly uniform; grows as one provider dominates.
    /// Bounded in [0.0, 1.0 - 1/active_n]. Returns 0.0 when `active_n == 0`.
    pub spectral_concentration: f64,
    /// Marginal adversary confidence gain per additional sample at current sample count.
    ///
    /// `= max_rate * (1 - max_rate)^total_samples`.
    /// High when observations are recent and concentrated; approaches zero as confidence
    /// saturates. Represents ∂confidence/∂n at the current observation count.
    pub confidence_growth_rate: f64,
    /// Remaining samples until adversary membership confidence exceeds 0.5.
    ///
    /// `None` when `max_selection_rate == 0` (confidence never accumulates).
    /// `Some(0)` when confidence has already exceeded the threshold.
    /// Derived by solving `1 - (1 - max_rate)^n > 0.5` for `n`.
    pub samples_to_saturation: Option<u64>,
    /// JSD between the current epoch distribution and the previous epoch's baseline.
    ///
    /// `None` when no rotation has occurred yet (no previous baseline).
    /// Low JSD means the distribution is stagnating — the adversary's model is converging.
    pub epoch_divergence: Option<f64>,
    /// Net displacement of κ since the pre-rotation baseline: κ_current − κ_pre_rotation.
    ///
    /// Records how much convergence pressure has changed since the last rotation event
    /// captured a new κ baseline. It is NOT an epoch-by-epoch gradient.
    ///
    /// Positive = κ has risen above the pre-rotation level (burst or reset spike).
    /// Near-zero = κ has returned to the pre-rotation baseline (recovery complete).
    /// `None` before the first rotation (no prior baseline exists).
    ///
    /// To measure current convergence direction across epochs, use `kappa_slope()`
    /// computed by OLS regression over a `PoolSimulator` trace — not this field.
    /// See also `kappa_displacement_since_rotation()`, the semantic alias for this field.
    pub kappa_velocity: Option<f64>,
    /// Estimated H(active_set_{t+1} | active_set_t): Markov transition entropy in bits.
    ///
    /// Computed as log₂(C(n, k̄)) + log₂(C(d, k̄)) where n = active_n, d = dormant count,
    /// and k̄ = round((min_churn + max_churn) / 2). Higher = more unpredictable transitions.
    /// `None` when dormant is empty (no rotation possible) or active_n = 0.
    pub transition_entropy: Option<f64>,
    /// Expected epochs until 50% of the current active set turns over.
    ///
    /// Derived from the actual churn k used in the last rotation and current active_n:
    /// `half_life = −ln(2) / ln(1 − k/n)`.
    /// `0.0` when k ≥ n (full replacement in one epoch).
    /// `None` when no rotation has occurred yet (no last_churn recorded).
    pub active_set_halflife_epochs: Option<f64>,
    /// Sum of κ(t) accumulated since the last rotation (or since pool creation).
    ///
    /// Incremented by the current κ on every `maybe_rotate()` call when policy
    /// is `IntegralTriggered`. For all other policies this field is always 0.0
    /// (accumulation is policy-internal and not globally maintained).
    /// Reset to 0.0 at each rotation. Starts at 0.0 before the first rotation.
    pub accumulated_pressure: f64,
    /// κ_L(t): liveness-weighted convergence pressure in [0.0, 1.0].
    ///
    /// Computed as `1 - response_entropy_bits / log2(active_n)`.
    /// Equal to `kappa` when all active providers respond. Rises above `kappa` when
    /// one or more providers are selected but never return responses (silently dead),
    /// since dead providers contribute 0 to response entropy while still occupying
    /// active-set slots in the denominator `log2(active_n)`.
    /// Returns 1.0 when no responses have been recorded or `active_n <= 1`.
    pub liveness_weighted_kappa: f64,
    /// κ_Ls(t): EWMA-smoothed liveness-weighted κ in [0.0, 1.0].
    ///
    /// Computed from `smoothed_response_entropy_bits`. Lags behind `liveness_weighted_kappa`.
    pub smoothed_liveness_weighted_kappa: f64,
    /// Total sample calls recorded in the exposure tracker since the last reset.
    ///
    /// With `ExposureResetPolicy::OnRotation`, resets to 0 on each rotation.
    /// With `ExposureResetPolicy::Never`, accumulates for the pool lifetime.
    /// Used to determine whether the tracker has sufficient history for reliable
    /// entropy estimation. The T4 stability margin is computed from this field:
    /// low values indicate the system is in the post-reset initialization window.
    pub total_samples: u64,
    /// Current epoch lifecycle phase derived from `total_samples` and `active_n`.
    ///
    /// Determines estimator admissibility. Entropy-derived rotation policies should not be
    /// evaluated unless `current_epoch_phase == EpochPhase::Steady`. `maybe_rotate()` enforces
    /// this automatically via the T4 admissibility gate.
    pub current_epoch_phase: EpochPhase,
}

impl ConvergencePressure {
    /// Semantic alias for `kappa_velocity`.
    ///
    /// `kappa_velocity` measures net displacement of κ from the pre-rotation baseline
    /// to the current snapshot — not an epoch-by-epoch gradient.
    /// Use `kappa_slope()` on a `PoolSimulator` trace for current convergence direction.
    pub fn kappa_displacement_since_rotation(&self) -> Option<f64> {
        self.kappa_velocity
    }
}

/// Operator-readable telemetry snapshot covering all three distinct liveness surfaces.
///
/// Each surface is independently observable and carries its own evidence context.
/// No composite health score is provided — operators must interpret each surface separately.
///
/// ## Surface 1 — Survivor concentration (κ / T1)
///
/// Policy-authoritative. Existing T1 threshold and meaning unchanged. Detects catastrophic
/// active-set collapse: κ > 0.5 iff s < √n (survivor-set collapse to near-single-provider).
///
/// ## Surface 2 — Relative liveness distortion (κ_L / liveness_weighted_κ)
///
/// TELEMETRY-ONLY. Non-authoritative for eviction, rotation, or admission.
/// Detects asymmetric silent provider failure: rises above `kappa` when one or more providers
/// are selected uniformly but never return responses.
///
/// ## Surface 3 — Absolute availability
///
/// TELEMETRY-ONLY. Non-authoritative for eviction, rotation, or admission.
/// Detects symmetric global response degradation that leaves both entropy surfaces near zero.
/// Derived from real `sample()` opportunities and `record_response()` observations in the
/// current window. Bounded by `ExposureResetPolicy` reset semantics. Not a stand-alone
/// health probe — numerator and denominator both come from protocol traffic, not a synthetic
/// ping. Response injection can inflate the numerator; see §S64.
pub struct OperationalTelemetrySnapshot {
    // ── Surface 1: Survivor concentration ────────────────────────────────────
    /// κ(t): normalized selection entropy deficit in [0.0, 1.0].
    /// 0 = fully uniform (no pressure). 1 = fully concentrated (maximum pressure).
    /// Policy-authoritative: existing T1 threshold and meaning unchanged.
    pub kappa: f64,
    /// True when `current_epoch_phase != PostReset` (total_samples ≥ active_n).
    ///
    /// When false, κ may read as 1.0 due to absent selection data — indistinguishable
    /// from genuine survivor-set collapse without this guard. T1 classification must
    /// not be applied when this flag is false.
    pub survivor_surface_evaluable: bool,

    // ── Surface 2: Relative liveness distortion ───────────────────────────────
    /// κ_L(t): liveness-weighted convergence pressure in [0.0, 1.0].
    /// Rises above `kappa` when one or more providers are silently absent.
    /// TELEMETRY-ONLY: non-authoritative for any automatic policy action.
    pub liveness_weighted_kappa: f64,
    /// True when at least one `record_response()` call and one `sample()` call have been
    /// recorded in the current window.
    /// False → surface is unevaluable; must not be read as "healthy."
    pub liveness_surface_evaluable: bool,

    // ── Surface 3: Absolute availability ──────────────────────────────────────
    /// Total `record_response()` calls in the current observation window.
    /// Bounded by `ExposureResetPolicy` reset semantics.
    pub response_total: u64,
    /// Total `sample()` calls in the current observation window (observation opportunities).
    /// This is the window bound — also bounded by `ExposureResetPolicy`.
    pub selection_total: u64,
    /// True when `selection_total > 0`.
    /// False → no observations recorded; unevaluable and must not be read as "healthy."
    pub availability_evaluable: bool,

    // ── Evidence context ──────────────────────────────────────────────────────
    /// Current epoch lifecycle phase (PostReset / Reconverging / Steady).
    pub current_epoch_phase: EpochPhase,
    /// Active provider count at snapshot time.
    pub active_n: usize,

    // ── Surface 4: Admissible paired-outcome (opt-in; zero/None when tracker absent) ──
    /// Total `record_admissible_response()` calls accepted against valid receipts
    /// in the current window. Zero when admissible tracking is not configured.
    ///
    /// TELEMETRY-ONLY — not authorized for any automatic policy action.
    /// See Trial 5B gate document §6 (Decision 6) for non-authorization statement.
    pub admissible_response_total: u64,
    /// Total `record_admissible_failure()` calls accepted against valid receipts
    /// in the current window. Zero when admissible tracking is not configured.
    ///
    /// TELEMETRY-ONLY — not authorized for any automatic policy action.
    pub admissible_failure_total: u64,
    /// Total receipts issued by `sample_with_receipts()` in the current window.
    /// Incremented at issuance, not at outcome recording.
    /// Zero when admissible tracking is not configured.
    ///
    /// TELEMETRY-ONLY — not authorized for any automatic policy action.
    pub admissible_selection_total: u64,
}

impl OperationalTelemetrySnapshot {
    /// Reported-response ratio: `response_total / selection_total` in the current window.
    ///
    /// TELEMETRY-ONLY — unverified. The numerator is incremented by every
    /// `record_response()` call; those calls are not causally bound to actual
    /// selected relay attempts. An adversary or buggy caller can inflate this value
    /// arbitrarily (see §S64, §S69). Do not derive automatic policy from this metric
    /// until responses are bound to specific selected attempts with at-most-once
    /// accounting and unmatched-response rejection.
    ///
    /// Returns `None` when `availability_evaluable` is false (no sample opportunities
    /// recorded yet, or window was just reset).
    pub fn recent_reported_response_ratio(&self) -> Option<f64> {
        if !self.availability_evaluable {
            None
        } else {
            Some(self.response_total as f64 / self.selection_total as f64)
        }
    }

    /// Alias for `recent_reported_response_ratio()`.
    ///
    /// The name "success_rate" overstates verification: `record_response()` calls are
    /// not bound to actual relay attempts and can be injected, inflating the numerator
    /// without any real relay success (see §S64). Prefer `recent_reported_response_ratio()`
    /// to make the integrity limitation explicit at the call site.
    pub fn recent_response_success_rate(&self) -> Option<f64> {
        self.recent_reported_response_ratio()
    }

    /// Admissible-response ratio: `admissible_response_total / admissible_selection_total`.
    ///
    /// TELEMETRY-ONLY — not authorized for any automatic policy action.
    /// Only populated when `with_admissible_tracking()` was called on the pool.
    ///
    /// Returns `None` when `admissible_selection_total == 0` (no receipts issued yet,
    /// or the window was just reset with the first receipt pending).
    ///
    /// Unlike `recent_reported_response_ratio()`, this ratio counts only outcomes
    /// that were paired with a valid `SelectionReceipt` — unpaired `record_response()`
    /// calls do not contribute to the numerator or denominator.
    pub fn recent_admissible_response_ratio(&self) -> Option<f64> {
        if self.admissible_selection_total == 0 {
            None
        } else {
            Some(self.admissible_response_total as f64 / self.admissible_selection_total as f64)
        }
    }
}
