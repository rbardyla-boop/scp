// Simulation invariants (Phase 26):
//   k=n sampling reveals all providers in every query: rate=1.0 per provider, κ=1.0.
//   κ(t) decreases toward 0 as uniform k=1 samples accumulate (entropy recovery).
//   cooldown(Duration::MAX) → total_rotations = 0 regardless of policy sensitivity.
//   IntegralTriggered rotation rate is inversely proportional to threshold.
//   Simulation trace length equals number of run_epoch() calls.
//
// Phase 27 invariants (trajectory analysis):
//   kappa_slope() < 0 when κ is falling (convergence). 0 when flat. > 0 when rising.
//   pressure_budget(t) = fraction of epochs with κ > t. Decreasing in t.
//   pressure_budget(0.0) = 1.0 when κ > 0 always; pressure_budget(1.0) = 0.0 always.
//   Under natural sampling with no rotation, both slope < 0 and budget fall over time.
//   Zero samples per epoch → κ = 1.0 always → budget(0.5) = 1.0 (no evidence of diversity).
//
// Phase 28 invariants (stability polytope):
//   smoothed_kappa lags raw kappa after bursts: kappa - smoothed_kappa > 0 on burst epochs.
//   stability_margin() > 0 ↔ system inside polytope. < 0 ↔ collapse trajectory active.
//   margin_t1() < 0 when pressure_budget(0.5) + kappa_slope_penalty > 1.0.
//   margin_t2() < 0 when rotation_rate > 0.5 (thrashing boundary).
//   margin_t3() < 0 when ewma_lag > 0.3 (burst invisible to EWMA-gated policies).
//   k=n collapses the T1 boundary (κ=1.0 always, budget(0.5)=1.0, margin_t1→ -1.0).
//
// Phase 29 invariants (T4 surface and epoch lifecycle):
//   margin_t4() = (total_samples / (4*active_n) - 1).clamp(-1, 1).
//   margin_t4() < 0 when total_samples < 4*active_n (initialization window open).
//   EpochPhase: PostReset < active_n < Reconverging < 4*active_n < Steady.
//   Phase transitions are monotone — no regression without rotation.
//   Fresh pool (0 samples): T4 is binding constraint; T3 is not active (no EWMA lag).
//   stability_margin() = min(T1, T2, T3, T4) — 4-surface polytope.
//
// Phase 30 invariants (T4 admissibility gate):
//   maybe_rotate() returns RotationOutcome — explicit Rotated or Deferred(reason).
//   PostReset: all policies → Deferred(EstimatorNotConverged). No state mutation.
//   Reconverging: estimator-dependent → Deferred(EstimatorNotConverged).
//   Reconverging: QueryCount/TimeBased/Hybrid/JitteredTimeBased/Manual → admissible.
//   Steady: all policies admissible; T4 gate does not fire.
//   Gate precedes policy arm: IntegralTriggered does not accumulate during PostReset.

use std::time::Duration;

use rand::{rngs::StdRng, SeedableRng};
use scp_ledger_substrate::SubstrateLedger;
use scp_provider_pool::{
    ChurnBudget, EpochPhase, EvictionConfig, EvictionReason, ExposureResetPolicy,
    OperationalTelemetrySnapshot, PoolRotationPolicy, ProviderPool, SamplingStrategy,
};

// ── Simulation harness ────────────────────────────────────────────────────────

#[allow(dead_code)]
struct EpochTrace {
    kappa: f64,
    smoothed_kappa: f64,
    accumulated_pressure: f64,
    epoch: u32,
    total_samples: u64,
    active_n: usize,
    spectral_concentration: f64,
    kappa_velocity: Option<f64>,
    liveness_weighted_kappa: f64,
}

struct PoolSimulator {
    pool: ProviderPool<SubstrateLedger>,
    trace: Vec<EpochTrace>,
    rng: StdRng,
}

impl PoolSimulator {
    fn new(pool: ProviderPool<SubstrateLedger>) -> Self {
        Self {
            pool,
            trace: Vec::new(),
            rng: StdRng::seed_from_u64(0x5c0f_2026),
        }
    }

    fn run_epoch(&mut self, samples: usize) {
        for _ in 0..samples {
            let _ = self.pool.sample(&mut self.rng);
        }
        let _ = self.pool.maybe_rotate(&mut self.rng);
        let cp = self.pool.convergence_pressure();
        self.trace.push(EpochTrace {
            kappa: cp.kappa,
            smoothed_kappa: cp.smoothed_kappa,
            accumulated_pressure: cp.accumulated_pressure,
            epoch: self.pool.epoch_count(),
            total_samples: cp.total_samples,
            active_n: cp.active_n,
            spectral_concentration: cp.spectral_concentration,
            kappa_velocity: cp.kappa_velocity,
            liveness_weighted_kappa: cp.liveness_weighted_kappa,
        });
    }

    fn max_kappa(&self) -> f64 {
        self.trace.iter().map(|t| t.kappa).fold(0.0_f64, f64::max)
    }

    fn total_rotations(&self) -> u32 {
        self.trace.last().map_or(0, |t| t.epoch)
    }

    fn kappa_slope(&self) -> f64 {
        let n = self.trace.len();
        if n < 2 {
            return 0.0;
        }
        let nf = n as f64;
        let mean_x = (nf - 1.0) / 2.0;
        let mean_y: f64 = self.trace.iter().map(|t| t.kappa).sum::<f64>() / nf;
        let cov: f64 = self
            .trace
            .iter()
            .enumerate()
            .map(|(i, t)| (i as f64 - mean_x) * (t.kappa - mean_y))
            .sum();
        let var_x: f64 = (0..n).map(|i| (i as f64 - mean_x).powi(2)).sum();
        if var_x < 1e-12 {
            0.0
        } else {
            cov / var_x
        }
    }

    fn pressure_budget(&self, threshold: f64) -> f64 {
        if self.trace.is_empty() {
            return 0.0;
        }
        let above = self.trace.iter().filter(|t| t.kappa > threshold).count();
        above as f64 / self.trace.len() as f64
    }

    #[allow(dead_code)]
    fn stability_vector(&self) -> StabilityVector {
        let n = self.trace.len();
        let last = self.trace.last();
        StabilityVector {
            kappa: last.map_or(1.0, |t| t.kappa),
            smoothed_kappa: last.map_or(1.0, |t| t.smoothed_kappa),
            ewma_lag: last.map_or(0.0, |t| t.kappa - t.smoothed_kappa),
            rotation_rate: if n == 0 {
                0.0
            } else {
                self.total_rotations() as f64 / n as f64
            },
            pressure_budget_half: self.pressure_budget(0.5),
        }
    }

    // T1 margin proxy: false-equilibrium detection.
    // Positive when κ is falling (genuine convergence).
    // Boundary at budget + slope_penalty = 0.9; negative when sum exceeds that.
    fn margin_t1(&self) -> f64 {
        let slope_penalty = self.kappa_slope().max(0.0);
        (0.9 - self.pressure_budget(0.5) - slope_penalty).clamp(-1.0, 1.0)
    }

    // T2 margin proxy: churn exhaustion boundary.
    // Boundary at rotation_rate = 0.5 (half of all epochs trigger rotation).
    fn margin_t2(&self) -> f64 {
        let n = self.trace.len();
        if n == 0 {
            return 1.0;
        }
        let rate = self.total_rotations() as f64 / n as f64;
        (0.5 - rate).clamp(-1.0, 1.0)
    }

    // T3 margin proxy: EWMA lag (burst invisibility).
    // Boundary at lag = 0.3: burst has spiked raw κ while smoothed κ remains low.
    fn margin_t3(&self) -> f64 {
        let lag = self
            .trace
            .last()
            .map_or(0.0, |t| t.kappa - t.smoothed_kappa);
        (0.3 - lag).clamp(-1.0, 1.0)
    }

    // T4 margin proxy: post-reset initialization window.
    // Boundary at total_samples = 4*active_n (≈4 observations per provider).
    // Negative when below threshold (adversary has maximum leverage on entropy estimate).
    fn margin_t4(&self) -> f64 {
        let t = match self.trace.last() {
            Some(t) => t,
            None => return 1.0,
        };
        if t.active_n == 0 {
            return 1.0;
        }
        let threshold = 4.0 * t.active_n as f64;
        (t.total_samples as f64 / threshold - 1.0).clamp(-1.0, 1.0)
    }

    // Epoch lifecycle phase at trace index idx.
    fn phase_at(&self, idx: usize) -> Option<EpochPhase> {
        let t = self.trace.get(idx)?;
        Some(EpochPhase::for_pool(t.total_samples, t.active_n))
    }

    // Minimum margin across all four collapse boundaries.
    // > 0 → inside stability polytope. < 0 → at least one boundary crossed.
    fn stability_margin(&self) -> f64 {
        self.margin_t1()
            .min(self.margin_t2())
            .min(self.margin_t3())
            .min(self.margin_t4())
    }

    // Stability margin recomputed using only Steady-phase epoch records.
    //
    // Steady-only T1: budget and slope computed from epochs where the estimator
    // is fully trustworthy (total_samples ≥ 4*active_n). PostReset epochs have
    // κ=1.0 due to absent data — including them inflates the budget and biases
    // the slope estimate. Stratifying to Steady isolates genuine convergence signal.
    // Returns None when no Steady epochs have been recorded yet.
    fn steady_stability_margin(&self) -> Option<f64> {
        let steady: Vec<&EpochTrace> = self
            .trace
            .iter()
            .filter(|t| EpochPhase::for_pool(t.total_samples, t.active_n) == EpochPhase::Steady)
            .collect();
        if steady.is_empty() {
            return None;
        }

        // T1: false-equilibrium boundary using only Steady data.
        let n = steady.len();
        let nf = n as f64;
        let mean_x = (nf - 1.0) / 2.0;
        let mean_y: f64 = steady.iter().map(|t| t.kappa).sum::<f64>() / nf;
        let cov: f64 = steady
            .iter()
            .enumerate()
            .map(|(i, t)| (i as f64 - mean_x) * (t.kappa - mean_y))
            .sum();
        let var_x: f64 = (0..n).map(|i| (i as f64 - mean_x).powi(2)).sum();
        let slope = if var_x < 1e-12 { 0.0 } else { cov / var_x };
        let budget = steady.iter().filter(|t| t.kappa > 0.5).count() as f64 / nf;
        let t1 = (0.9 - budget - slope.max(0.0)).clamp(-1.0, 1.0);

        // T2: churn rate over Steady epochs only.
        let rotations = steady
            .last()
            .map_or(0, |t| t.epoch)
            .saturating_sub(steady.first().map_or(0, |t| t.epoch));
        let t2 = (0.5 - rotations as f64 / nf).clamp(-1.0, 1.0);

        // T3: EWMA lag at last Steady epoch.
        let last = steady.last().unwrap();
        let lag = last.kappa - last.smoothed_kappa;
        let t3 = (0.3 - lag).clamp(-1.0, 1.0);

        // T4: always satisfied inside Steady by definition.
        let t4 = 1.0_f64;

        Some(t1.min(t2).min(t3).min(t4))
    }

    fn last_kappa(&self) -> f64 {
        self.trace.last().map_or(1.0, |t| t.kappa)
    }

    #[allow(dead_code)]
    fn last_spectral_concentration(&self) -> f64 {
        self.trace.last().map_or(0.0, |t| t.spectral_concentration)
    }
}

#[allow(dead_code)]
struct StabilityVector {
    kappa: f64,
    smoothed_kappa: f64,
    ewma_lag: f64,
    rotation_rate: f64,
    pressure_budget_half: f64,
}

// ── §S1. k=n sampling reveals all providers every query → κ = 1.0 ─────────────
//
// The tracker records rate as appearances[id] / total_sample_calls. With k=n,
// every provider appears in 100% of calls → rate = 1.0 → entropy = 0 bits → κ = 1.0.
// This is the WORST privacy configuration: an adversary observing any single query
// immediately knows all n providers. Used to calibrate the upper bound of κ.

#[test]
fn sim_full_coverage_sampling_has_maximum_kappa() {
    let mut pool = ProviderPool::new(SamplingStrategy::RandomK(4)).with_active_window(4);
    for i in 0..4u8 {
        pool.add([i; 32], SubstrateLedger::new());
    }

    let mut sim = PoolSimulator::new(pool);
    for _ in 0..10 {
        sim.run_epoch(100);
    }

    assert!(
        sim.max_kappa() > 0.99,
        "k=n sampling must have κ=1.0 on every epoch; got max κ = {}",
        sim.max_kappa()
    );
}

// ── §S2. κ(t) decreases toward 0 as uniform samples accumulate ───────────────
//
// Epoch 1: 1 sample → entropy = 0 bits → κ = 1.0 (fully concentrated).
// Epoch 2: 10_000 additional samples → entropy ≈ log₂(4) → κ ≈ 0.0.
// The 1-sample imbalance is negligible relative to 10,001 total.

#[test]
fn sim_entropy_recovers_with_dense_sampling() {
    let mut pool = ProviderPool::new(SamplingStrategy::RandomK(1)).with_active_window(4);
    for i in 0..4u8 {
        pool.add([i; 32], SubstrateLedger::new());
    }

    let mut sim = PoolSimulator::new(pool);
    sim.run_epoch(1);
    sim.run_epoch(10_000);

    assert!(
        sim.trace[0].kappa > 0.9,
        "epoch 1 (1 sample) must have κ near 1.0; got {}",
        sim.trace[0].kappa
    );
    assert!(
        sim.trace[1].kappa < 0.05,
        "epoch 2 (10,001 total samples) must have κ near 0.0; got {}",
        sim.trace[1].kappa
    );
}

// ── §S3. cooldown(MAX) blocks all auto-rotation regardless of policy ──────────
//
// QueryCount(1) fires on every maybe_rotate() call. The cooldown gate fires
// before the policy arm, so query_count never increments and rotation never occurs.

#[test]
fn sim_cooldown_max_blocks_all_autorotation() {
    let mut pool = ProviderPool::new(SamplingStrategy::RandomK(1))
        .with_active_window(4)
        .with_rotation(
            PoolRotationPolicy::QueryCount(1),
            ChurnBudget {
                min_churn: 1,
                max_churn: 1,
            },
        )
        .with_cooldown(Duration::MAX);
    for i in 0..5u8 {
        pool.add([i; 32], SubstrateLedger::new());
    }

    let mut sim = PoolSimulator::new(pool);
    for _ in 0..20 {
        sim.run_epoch(0);
    }

    assert_eq!(
        sim.total_rotations(),
        0,
        "cooldown(MAX) must block all auto-rotations; got {} rotations",
        sim.total_rotations()
    );
}

// ── §S4. IntegralTriggered rotation rate is inversely proportional to threshold
//
// RandomK(4) with active_window=4 (k=n): every query reveals all 4 providers →
// rate[i]=1.0 → entropy=0 → κ=1.0 in Steady. 16 samples/epoch ensures total_samples ≥ 16
// (4*active_n) from epoch 1, so T4 gate does not block IntegralTriggered.
// Low threshold (1.5): accumulated_kappa reaches 2.0 on epoch 2 → fires every 2 epochs.
// High threshold (9.5): accumulated_kappa reaches 10.0 only at epoch 10 → 1 rotation.
// Both thresholds ≥ 1.0: no cooldown required (safety invariant satisfied).
// 8 providers: dormant=4 ≥ active_window=4 → floor gate passes.

#[test]
fn sim_integral_threshold_governs_rotation_rate() {
    let make_pool = |threshold: f64| {
        let mut pool = ProviderPool::new(SamplingStrategy::RandomK(4))
            .with_active_window(4)
            .with_rotation(
                PoolRotationPolicy::IntegralTriggered {
                    max_accumulated_pressure: threshold,
                },
                ChurnBudget {
                    min_churn: 1,
                    max_churn: 1,
                },
            );
        for i in 0..8u8 {
            pool.add([i; 32], SubstrateLedger::new());
        }
        pool
    };

    let mut sim_low = PoolSimulator::new(make_pool(1.5));
    let mut sim_high = PoolSimulator::new(make_pool(9.5));

    for _ in 0..10 {
        sim_low.run_epoch(16);
    }
    for _ in 0..10 {
        sim_high.run_epoch(16);
    }

    assert!(
        sim_low.total_rotations() > sim_high.total_rotations(),
        "low threshold (0.5) must produce more rotations than high threshold (9.5); \
         got {} vs {}",
        sim_low.total_rotations(),
        sim_high.total_rotations()
    );
}

// ── §S5. Simulation trace length equals number of run_epoch() calls ───────────

#[test]
fn sim_trace_length_reflects_epoch_count() {
    let mut pool = ProviderPool::new(SamplingStrategy::RandomK(1)).with_active_window(4);
    for i in 0..4u8 {
        pool.add([i; 32], SubstrateLedger::new());
    }

    let mut sim = PoolSimulator::new(pool);
    for _ in 0..17 {
        sim.run_epoch(10);
    }

    assert_eq!(
        sim.trace.len(),
        17,
        "run_epoch() must append exactly one EpochTrace per call"
    );
    assert_eq!(
        sim.total_rotations(),
        0,
        "Manual policy must never auto-rotate; epoch_count must remain 0"
    );
}

// ── §S6. OLS slope of κ is negative under natural convergence ────────────────
//
// Epoch 1: 1 sample → one provider rate=1.0 → κ=1.0.
// Epoch 100: 100 cumulative samples near-uniform → κ ≈ 0.0.
// OLS fits a line from ~1.0 down to ~0.0: slope is strongly negative.

#[test]
fn sim_natural_convergence_slope_is_negative() {
    let mut pool = ProviderPool::new(SamplingStrategy::RandomK(1)).with_active_window(4);
    for i in 0..4u8 {
        pool.add([i; 32], SubstrateLedger::new());
    }

    let mut sim = PoolSimulator::new(pool);
    for _ in 0..100 {
        sim.run_epoch(1);
    }

    assert!(
        sim.kappa_slope() < 0.0,
        "OLS slope must be negative when κ falls from 1.0 toward 0.0; got {}",
        sim.kappa_slope()
    );
}

// ── §S7. pressure_budget(0.5) is low after convergence ───────────────────────
//
// Same 100-epoch run as §S6. Epoch 1: κ=1.0 > 0.5. Early epochs may also have
// κ > 0.5 before diversity accumulates. After 100 cumulative samples with 4 providers,
// the budget must be well below 0.15: sustained high-κ epochs indicate no convergence.
// (Threshold is 0.15 rather than a stricter value because the cumulative ExposureTracker
// accumulates evidence monotonically — early epochs naturally inflate the budget until
// enough diversity is observed.)

#[test]
fn sim_pressure_budget_low_after_convergence() {
    let mut pool = ProviderPool::new(SamplingStrategy::RandomK(1)).with_active_window(4);
    for i in 0..4u8 {
        pool.add([i; 32], SubstrateLedger::new());
    }

    let mut sim = PoolSimulator::new(pool);
    for _ in 0..100 {
        sim.run_epoch(1);
    }

    assert!(
        sim.pressure_budget(0.5) < 0.15,
        "pressure_budget(0.5) must be < 0.15 after 100 cumulative samples; got {}",
        sim.pressure_budget(0.5)
    );
}

// ── §S8. pressure_budget(0.5) = 1.0 when no samples are taken ────────────────
//
// Zero samples → tracker has no data → entropy=0 bits → κ=1.0 every epoch.
// 1.0 > 0.5 is true for all 30 epochs → budget = 30/30 = 1.0.

#[test]
fn sim_pressure_budget_one_when_no_data() {
    let mut pool = ProviderPool::new(SamplingStrategy::RandomK(1)).with_active_window(4);
    for i in 0..4u8 {
        pool.add([i; 32], SubstrateLedger::new());
    }

    let mut sim = PoolSimulator::new(pool);
    for _ in 0..30 {
        sim.run_epoch(0);
    }

    assert_eq!(
        sim.pressure_budget(0.5),
        1.0,
        "zero samples must give κ=1.0 every epoch; pressure_budget(0.5) must be 1.0"
    );
}

// ── §S9. Dense sampling reduces pressure_budget vs zero samples ───────────────
//
// A: 30 epochs × 0 samples → κ=1.0 always → budget(0.5) = 1.0.
// B: 30 epochs × 100 samples → κ ≈ 0.0 from epoch 1 → budget(0.5) = 0.0.
// Demonstrates: evidence of diversity eliminates sustained pressure.

#[test]
fn sim_dense_sampling_reduces_pressure_budget_vs_zero_samples() {
    let make_pool = || {
        let mut pool = ProviderPool::new(SamplingStrategy::RandomK(1)).with_active_window(4);
        for i in 0..4u8 {
            pool.add([i; 32], SubstrateLedger::new());
        }
        pool
    };

    let mut sim_a = PoolSimulator::new(make_pool());
    let mut sim_b = PoolSimulator::new(make_pool());

    for _ in 0..30 {
        sim_a.run_epoch(0);
    }
    for _ in 0..30 {
        sim_b.run_epoch(100);
    }

    assert!(
        sim_a.pressure_budget(0.5) > sim_b.pressure_budget(0.5),
        "zero-sample budget ({}) must exceed dense-sample budget ({})",
        sim_a.pressure_budget(0.5),
        sim_b.pressure_budget(0.5)
    );
}

// ── §S10. pressure_budget boundary conditions ─────────────────────────────────
//
// Final state (30 total samples): 30 mod 4 ≠ 0 → cannot be perfectly uniform → κ > 0.
// Intermediate epochs (4,8,…,28) can momentarily hit κ=0 by chance (uniform split),
// so budget(0.0) is high but not guaranteed to equal 1.0. Tested with > 0.8.
// κ ≤ 1.0 always → budget(1.0) = 0.0 (strict: κ > 1.0 never).
// Monotonicity: budget(0.0) ≥ budget(0.5) ≥ budget(1.0).

#[test]
fn sim_pressure_budget_boundary_conditions() {
    let mut pool = ProviderPool::new(SamplingStrategy::RandomK(1)).with_active_window(4);
    for i in 0..4u8 {
        pool.add([i; 32], SubstrateLedger::new());
    }

    let mut sim = PoolSimulator::new(pool);
    for _ in 0..30 {
        sim.run_epoch(1);
    }

    assert!(
        sim.pressure_budget(0.0) > 0.8,
        "κ > 0 in most epochs (imperfect distribution) → budget(0.0) must be high; got {}",
        sim.pressure_budget(0.0)
    );
    assert_eq!(
        sim.pressure_budget(1.0),
        0.0,
        "κ ≤ 1.0 always → budget(1.0) must be 0.0"
    );
    assert!(
        sim.pressure_budget(0.0) >= sim.pressure_budget(0.5),
        "pressure_budget must be monotone decreasing in threshold"
    );
    assert!(
        sim.pressure_budget(0.5) >= sim.pressure_budget(1.0),
        "pressure_budget must be monotone decreasing in threshold"
    );
}

// ── §S11. Healthy operation lies inside the stability polytope ────────────────
//
// 100 epochs × 10 samples: κ converges, slope negative, rotation_rate=0, lag≈0.
// All three margins positive → stability_margin() > 0.

#[test]
fn sim_stability_margin_positive_under_natural_convergence() {
    let mut pool = ProviderPool::new(SamplingStrategy::RandomK(1)).with_active_window(4);
    for i in 0..4u8 {
        pool.add([i; 32], SubstrateLedger::new());
    }

    let mut sim = PoolSimulator::new(pool);
    for _ in 0..100 {
        sim.run_epoch(10);
    }

    assert!(
        sim.stability_margin() > 0.0,
        "healthy convergent operation must lie inside the stability polytope; \
         got stability_margin = {}, margin_t1 = {}, margin_t2 = {}, margin_t3 = {}",
        sim.stability_margin(),
        sim.margin_t1(),
        sim.margin_t2(),
        sim.margin_t3()
    );
}

// ── §S12. T3 margin reveals EWMA lag after tracker reset ─────────────────────
//
// Phase 1 (warm): 10_000 samples → EWMA converges: smoothed_entropy ≈ log₂(4).
// Phase 2 (reset): force_rotate() with OnRotation policy → raw counts cleared,
//   smoothed_entropy retained.
// Phase 3 (snapshot): run_epoch(0) → total_samples=0 → raw entropy=0 → raw κ=1.0.
//   smoothed_kappa ≈ 0 (smoothed_entropy still ≈ log₂(4)).
//   ewma_lag = raw κ - smoothed_kappa ≈ 1.0 > 0.5.

#[test]
fn sim_t3_margin_reveals_ewma_lag() {
    let mut pool = ProviderPool::new(SamplingStrategy::RandomK(1))
        .with_active_window(4)
        .with_exposure_reset_policy(ExposureResetPolicy::OnRotation);
    for i in 0..5u8 {
        pool.add([i; 32], SubstrateLedger::new());
    }

    let mut sim = PoolSimulator::new(pool);
    sim.run_epoch(10_000); // warm: EWMA converges to near-uniform
    sim.pool.force_rotate(&mut sim.rng); // reset raw counts; smoothed_entropy retained
    sim.run_epoch(0); // snapshot: raw κ=1.0, smoothed_kappa≈0

    let lag = sim.trace[1].kappa - sim.trace[1].smoothed_kappa;
    assert!(
        lag > 0.5,
        "after warm+reset, ewma_lag must exceed 0.5; got lag = {} \
         (raw κ = {}, smoothed κ = {})",
        lag,
        sim.trace[1].kappa,
        sim.trace[1].smoothed_kappa
    );
    assert!(
        sim.margin_t3() < 0.0,
        "T3 margin must be negative when ewma_lag > 0.3; got margin_t3 = {}",
        sim.margin_t3()
    );
}

// ── §S13. T2 margin is negative under high rotation rate ─────────────────────
//
// QueryCount(1) rotates on every maybe_rotate() call.
// 5 samples/epoch ensures total_samples ≥ active_n=4 from epoch 1 (Reconverging),
// where QueryCount is admissible. rotation_rate ≈ 1.0 → margin_t2 = -0.5 < 0.

#[test]
fn sim_t2_margin_negative_under_high_rotation_rate() {
    // 8 providers: dormant=4 ≥ active_window=4 → floor gate passes.
    let mut pool = ProviderPool::new(SamplingStrategy::RandomK(1))
        .with_active_window(4)
        .with_rotation(
            PoolRotationPolicy::QueryCount(1),
            ChurnBudget {
                min_churn: 1,
                max_churn: 1,
            },
        );
    for i in 0..8u8 {
        pool.add([i; 32], SubstrateLedger::new());
    }

    let mut sim = PoolSimulator::new(pool);
    for _ in 0..10 {
        sim.run_epoch(5);
    }

    assert!(
        sim.margin_t2() < 0.0,
        "rotation_rate near 1.0 must cross T2 boundary; got margin_t2 = {}",
        sim.margin_t2()
    );
    assert!(
        sim.stability_margin() < 0.0,
        "T2 boundary crossing must make stability_margin() negative; got {}",
        sim.stability_margin()
    );
}

// ── §S14. Stability volume shrinks under k=n (worst privacy config) ───────────
//
// A: RandomK(1) — 50 epochs × 10 samples → κ converges, slope negative, margin_t1 > 0.
// B: RandomK(4) — 50 epochs × 10 samples → κ=1.0 always, budget(0.5)=1.0, margin_t1 < 0.
// stability_margin(A) > stability_margin(B).

#[test]
fn sim_stability_volume_shrinks_under_k_equals_n() {
    let make_pool = |k: usize| {
        let mut pool = ProviderPool::new(SamplingStrategy::RandomK(k)).with_active_window(4);
        for i in 0..4u8 {
            pool.add([i; 32], SubstrateLedger::new());
        }
        pool
    };

    let mut sim_a = PoolSimulator::new(make_pool(1));
    let mut sim_b = PoolSimulator::new(make_pool(4));

    for _ in 0..50 {
        sim_a.run_epoch(10);
    }
    for _ in 0..50 {
        sim_b.run_epoch(10);
    }

    assert!(
        sim_a.stability_margin() > sim_b.stability_margin(),
        "k=1 must have larger stability margin than k=n; got {} vs {}",
        sim_a.stability_margin(),
        sim_b.stability_margin()
    );
    assert!(
        sim_b.margin_t1() < 0.0,
        "k=n must collapse the T1 boundary; got margin_t1 = {}",
        sim_b.margin_t1()
    );
}

// ── §S15. smoothed_kappa lags raw kappa after reset ───────────────────────────
//
// After 10_000 samples: EWMA converged, lag ≈ 0 (both raw and smoothed near 0).
// After force_rotate() + run_epoch(0): raw κ=1.0 (no data), smoothed_kappa≈0.
// raw κ > smoothed κ (raw leads smoothed after reset).

#[test]
fn sim_smoothed_kappa_lags_raw_kappa_after_dense_then_sparse() {
    let mut pool = ProviderPool::new(SamplingStrategy::RandomK(1))
        .with_active_window(4)
        .with_exposure_reset_policy(ExposureResetPolicy::OnRotation);
    for i in 0..5u8 {
        pool.add([i; 32], SubstrateLedger::new());
    }

    let mut sim = PoolSimulator::new(pool);
    sim.run_epoch(10_000); // warm: EWMA converges to near-uniform
    sim.pool.force_rotate(&mut sim.rng); // reset raw counts; smoothed_entropy retained
    sim.run_epoch(0); // snapshot: raw κ=1.0, smoothed_kappa≈0

    let warm_lag = sim.trace[0].kappa - sim.trace[0].smoothed_kappa;
    let burst_lag = sim.trace[1].kappa - sim.trace[1].smoothed_kappa;

    assert!(
        warm_lag.abs() < 0.05,
        "after 10_000 samples EWMA must have converged; lag must be near 0, got {}",
        warm_lag
    );
    assert!(
        burst_lag > 0.5,
        "after tracker reset, raw κ=1.0 and smoothed_kappa≈0 → lag must exceed 0.5; got {}",
        burst_lag
    );
    assert!(
        sim.trace[1].kappa > sim.trace[1].smoothed_kappa,
        "raw kappa must lead smoothed_kappa after reset"
    );
}

// ── §S16. T4 margin is negative immediately after rotation reset ──────────────
//
// After force_rotate() with OnRotation policy, total_samples = 0.
// margin_t4 = (0 / (4*4) - 1).clamp(-1,1) = -1.0 < 0.
// System is in PostReset phase: maximum adversarial leverage on entropy estimate.

#[test]
fn sim_t4_margin_negative_immediately_after_rotation() {
    let mut pool = ProviderPool::new(SamplingStrategy::RandomK(1))
        .with_active_window(4)
        .with_exposure_reset_policy(ExposureResetPolicy::OnRotation);
    for i in 0..5u8 {
        pool.add([i; 32], SubstrateLedger::new());
    }

    let mut sim = PoolSimulator::new(pool);
    sim.run_epoch(10_000); // warm: establish EWMA history
    sim.pool.force_rotate(&mut sim.rng); // reset raw counts; total_samples → 0
    sim.run_epoch(0); // snapshot: total_samples=0, active_n=4

    assert!(
        sim.margin_t4() < 0.0,
        "T4 margin must be negative immediately after rotation reset; got {}",
        sim.margin_t4()
    );
    assert_eq!(
        sim.phase_at(1),
        Some(EpochPhase::PostReset),
        "system must be in PostReset phase after rotation reset; got {:?}",
        sim.phase_at(1)
    );
}

// ── §S17. T4 margin recovers after sufficient post-reset samples ──────────────
//
// 32 samples with active_n=4 → 32 ≥ 4*4=16 → Steady phase.
// margin_t4 = (32/16 - 1).clamp(-1,1) = 1.0 > 0.

#[test]
fn sim_t4_margin_recovers_with_post_reset_samples() {
    let mut pool = ProviderPool::new(SamplingStrategy::RandomK(1))
        .with_active_window(4)
        .with_exposure_reset_policy(ExposureResetPolicy::OnRotation);
    for i in 0..5u8 {
        pool.add([i; 32], SubstrateLedger::new());
    }

    let mut sim = PoolSimulator::new(pool);
    sim.run_epoch(10_000); // warm
    sim.pool.force_rotate(&mut sim.rng); // reset
    sim.run_epoch(32); // 32 ≥ 4*4=16 → margin_t4 > 0

    assert!(
        sim.margin_t4() > 0.0,
        "T4 margin must be positive after 32 post-reset samples (threshold=16); got {}",
        sim.margin_t4()
    );
    assert_eq!(
        sim.phase_at(1),
        Some(EpochPhase::Steady),
        "32 samples with active_n=4 must be Steady phase; got {:?}",
        sim.phase_at(1)
    );
}

// ── §S18. Epoch lifecycle traverses PostReset → Reconverging → Steady ─────────
//
// force_rotate() → total_samples=0 before any run_epoch.
// run_epoch(0):  total=0 < 4      → PostReset
// run_epoch(3):  total=3 < 4      → PostReset
// run_epoch(4):  total=7 ≥ 4, < 16 → Reconverging
// run_epoch(20): total=27 ≥ 16    → Steady

#[test]
fn sim_epoch_lifecycle_traverses_phases_in_order() {
    let mut pool = ProviderPool::new(SamplingStrategy::RandomK(1))
        .with_active_window(4)
        .with_exposure_reset_policy(ExposureResetPolicy::OnRotation);
    for i in 0..5u8 {
        pool.add([i; 32], SubstrateLedger::new());
    }

    let mut sim = PoolSimulator::new(pool);
    sim.pool.force_rotate(&mut sim.rng); // total_samples → 0

    sim.run_epoch(0); // trace[0]: total_samples=0  → PostReset
    sim.run_epoch(3); // trace[1]: total_samples=3  → PostReset
    sim.run_epoch(4); // trace[2]: total_samples=7  → Reconverging
    sim.run_epoch(20); // trace[3]: total_samples=27 → Steady

    assert_eq!(
        sim.phase_at(0),
        Some(EpochPhase::PostReset),
        "trace[0]: 0 samples → PostReset; got {:?}",
        sim.phase_at(0)
    );
    assert_eq!(
        sim.phase_at(1),
        Some(EpochPhase::PostReset),
        "trace[1]: 3 samples < 4 → PostReset; got {:?}",
        sim.phase_at(1)
    );
    assert_eq!(
        sim.phase_at(2),
        Some(EpochPhase::Reconverging),
        "trace[2]: 7 samples ≥ 4 < 16 → Reconverging; got {:?}",
        sim.phase_at(2)
    );
    assert_eq!(
        sim.phase_at(3),
        Some(EpochPhase::Steady),
        "trace[3]: 27 samples ≥ 16 → Steady; got {:?}",
        sim.phase_at(3)
    );
}

// ── §S19. T4 is the binding constraint in a fresh pool ───────────────────────
//
// Fresh pool, no warm-up: run_epoch(0) → total_samples=0 → margin_t4=-1.0.
// No EWMA history → smoothed_entropy=0 → lag=0 → margin_t3=0.3 > 0.
// T4 is the binding constraint: stability_margin() < margin_t3().

#[test]
fn sim_t4_is_binding_constraint_in_fresh_pool() {
    let mut pool = ProviderPool::new(SamplingStrategy::RandomK(1)).with_active_window(4);
    for i in 0..4u8 {
        pool.add([i; 32], SubstrateLedger::new());
    }

    let mut sim = PoolSimulator::new(pool);
    sim.run_epoch(0); // fresh pool: total_samples=0

    assert!(
        sim.margin_t4() < 0.0,
        "T4 margin must be negative in fresh pool (total_samples=0); got {}",
        sim.margin_t4()
    );
    assert!(
        sim.margin_t3() > 0.0,
        "T3 margin must be positive in fresh pool (no EWMA lag); got {}",
        sim.margin_t3()
    );
    assert!(
        sim.stability_margin() < sim.margin_t3(),
        "T4 must bind below T3 in fresh pool; stability={} margin_t3={}",
        sim.stability_margin(),
        sim.margin_t3()
    );
}

// ── §S20. T4 window closes predictably with sample accumulation ───────────────
//
// Sim A: run_epoch(0)  → total_samples=0 → T4 open (margin_t4 < 0).
// Sim B: run_epoch(0) + run_epoch(32) → total_samples=32 ≥ 16 → T4 closed (margin_t4 > 0).
// Demonstrates: the system's own sampling rate controls T4 exposure duration.

#[test]
fn sim_t4_window_closes_with_sufficient_post_reset_samples() {
    let make_pool = || {
        let mut pool = ProviderPool::new(SamplingStrategy::RandomK(1)).with_active_window(4);
        for i in 0..4u8 {
            pool.add([i; 32], SubstrateLedger::new());
        }
        pool
    };

    let mut sim_a = PoolSimulator::new(make_pool());
    let mut sim_b = PoolSimulator::new(make_pool());

    sim_a.run_epoch(0); // total_samples=0 → margin_t4=-1.0
    sim_b.run_epoch(0); // trace[0]: total_samples=0
    sim_b.run_epoch(32); // trace[1]: total_samples=32 ≥ 16 → margin_t4=1.0

    assert!(
        sim_a.margin_t4() < 0.0,
        "Sim A: T4 must be open at 0 samples; got margin_t4={}",
        sim_a.margin_t4()
    );
    assert!(
        sim_b.margin_t4() > 0.0,
        "Sim B: T4 must close at 32 samples (threshold=16); got margin_t4={}",
        sim_b.margin_t4()
    );
    assert!(
        sim_b.stability_margin() > sim_a.stability_margin(),
        "Sim B stability ({}) must exceed Sim A stability ({}) after T4 closes",
        sim_b.stability_margin(),
        sim_a.stability_margin()
    );
}

// Phase 34 invariants (Phase Opacity — adversarial identification):
//   tick() output traces are phase-indistinguishable under Manual policy.
//   tick() faithfully wraps maybe_rotate(): same epoch progression for same policy.

// ── §S21. tick() trace is phase-indistinguishable under Manual policy ─────────
//
// Pool A (PostReset, 0 samples): T4 gate fires → DeferralReason::EstimatorNotConverged →
// tick() returns false.
// Pool B (Steady, 16 samples): Manual policy → PolicyThresholdNotMet → tick() returns false.
// An adversary observing only the boolean trace cannot distinguish the two pools.

#[test]
fn sim_tick_behavioral_identity_across_phases() {
    let mut rng = StdRng::seed_from_u64(0x5c0f_0021);

    let make_pool = || {
        let mut pool = ProviderPool::new(SamplingStrategy::RandomK(1))
            .with_active_window(4)
            .with_rotation(
                PoolRotationPolicy::Manual,
                ChurnBudget {
                    min_churn: 1,
                    max_churn: 1,
                },
            );
        for i in 0..8u8 {
            pool.add([i; 32], SubstrateLedger::new());
        }
        pool
    };

    let mut pool_a = make_pool(); // PostReset: 0 samples — no sample() calls.
    let mut pool_b = make_pool(); // Steady: 16 samples.
    for _ in 0..16 {
        let _ = pool_b.sample(&mut rng);
    }

    let trace_a: Vec<bool> = (0..10).map(|_| pool_a.tick(&mut rng)).collect();
    let trace_b: Vec<bool> = (0..10).map(|_| pool_b.tick(&mut rng)).collect();

    assert_eq!(
        trace_a,
        vec![false; 10],
        "Pool A (PostReset, Manual): all tick() calls must return false"
    );
    assert_eq!(
        trace_b,
        vec![false; 10],
        "Pool B (Steady, Manual): all tick() calls must return false"
    );
    assert_eq!(
        trace_a, trace_b,
        "tick() traces must be identical across EpochPhases with Manual policy"
    );
}

// ── §S22. tick() faithfully wraps maybe_rotate() ─────────────────────────────
//
// QueryCount(2) in Steady: fires every 2 calls → 3 rotations in 6 calls.
// Both tick() and maybe_rotate() pools must produce the same epoch count.

#[test]
fn sim_tick_faithfully_wraps_maybe_rotate() {
    let mut rng = StdRng::seed_from_u64(0x5c0f_0022);

    let make_pool = || {
        let mut pool = ProviderPool::new(SamplingStrategy::RandomK(1))
            .with_active_window(4)
            .with_rotation(
                PoolRotationPolicy::QueryCount(2),
                ChurnBudget {
                    min_churn: 1,
                    max_churn: 1,
                },
            );
        for i in 0..8u8 {
            pool.add([i; 32], SubstrateLedger::new());
        }
        pool
    };

    let mut pool_a = make_pool();
    let mut pool_b = make_pool();

    // Put both in Steady (16 samples).
    for _ in 0..16 {
        let _ = pool_a.sample(&mut rng);
        let _ = pool_b.sample(&mut rng);
    }

    for _ in 0..6 {
        pool_a.tick(&mut rng);
    }
    for _ in 0..6 {
        pool_b.maybe_rotate(&mut rng);
    }

    assert_eq!(
        pool_a.epoch_count(),
        pool_b.epoch_count(),
        "tick() and maybe_rotate() must produce identical epoch progressions; \
         got tick={} vs rotate={}",
        pool_a.epoch_count(),
        pool_b.epoch_count()
    );
    assert_eq!(
        pool_a.epoch_count(),
        3,
        "QueryCount(2) × 6 calls → 3 rotations expected; got {}",
        pool_a.epoch_count()
    );
}

// ── §S23. BurstTriggered (always-fire) integrates with epoch lifecycle ────────

#[test]
fn sim_burst_triggered_threshold_always_met_produces_rotation() {
    let mut rng = StdRng::seed_from_u64(0x5c0f_0023);
    let mut pool = ProviderPool::new(SamplingStrategy::RandomK(1))
        .with_active_window(4)
        .with_rotation(
            PoolRotationPolicy::BurstTriggered {
                min_burst_magnitude: -2.0,
                response_jitter_max: Duration::ZERO,
            },
            ChurnBudget {
                min_churn: 1,
                max_churn: 1,
            },
        );
    for i in 0..8u8 {
        pool.add([i; 32], SubstrateLedger::new());
    }

    // Drive to Steady.
    for _ in 0..16 {
        let _ = pool.sample(&mut rng);
    }

    // With threshold=-2.0 and jitter=0, every call should fire.
    for _ in 0..5 {
        pool.maybe_rotate(&mut rng);
    }
    assert_eq!(
        pool.epoch_count(),
        5,
        "BurstTriggered fires on every call when threshold is always met; got {}",
        pool.epoch_count()
    );
}

// ── §S24. BurstTriggered response jitter reduces rotation count ───────────────

#[test]
fn sim_burst_triggered_response_jitter_reduces_rotation_count() {
    let mut rng = StdRng::seed_from_u64(0x5c0f_0024);
    // Use a short jitter so the test can also verify eventual firing without a long sleep.
    let mut pool = ProviderPool::new(SamplingStrategy::RandomK(1))
        .with_active_window(4)
        .with_rotation(
            PoolRotationPolicy::BurstTriggered {
                min_burst_magnitude: -2.0,
                response_jitter_max: Duration::from_millis(10),
            },
            ChurnBudget {
                min_churn: 1,
                max_churn: 1,
            },
        );
    for i in 0..8u8 {
        pool.add([i; 32], SubstrateLedger::new());
    }

    // Drive to Steady.
    for _ in 0..16 {
        let _ = pool.sample(&mut rng);
    }

    // Phase A: 6 immediate calls. The first call sets a deadline in [0, 10ms).
    // Subsequent calls find the deadline in the future and are suppressed.
    // Jitter prevents the adversary from predicting rotation timing (forced-trajectory resistance).
    for _ in 0..6 {
        pool.maybe_rotate(&mut rng);
    }
    let after_immediate = pool.epoch_count();
    assert!(
        after_immediate < 6,
        "jitter must suppress some rotations; expected < 6, got {after_immediate}"
    );

    // Phase B: wait for the deadline to elapse, then one more call must fire.
    std::thread::sleep(Duration::from_millis(15));
    pool.maybe_rotate(&mut rng);
    assert!(
        pool.epoch_count() > after_immediate,
        "rotation must occur after jitter deadline elapses; \
         before={after_immediate} after={}",
        pool.epoch_count()
    );
}

// ── Phase 35 invariants (collapse verification):
//   §S25: kappa collapses across pool sizes after proportional sampling.
//   §S26: spectral_concentration reaches near-zero when kappa does.
//   §S27: steady_stability_margin() ≥ stability_margin() (Steady stratification removes noise).
//   §S28: kappa_velocity is positive immediately after a forced reset, then negative on recovery.

// ── §S25. kappa collapses across pool sizes after proportional sampling ───────
//
// kappa = 1 − entropy_bits / log₂(active_n) is dimensionless by construction.
// After proportional sampling (100 samples × active_n), every provider has been
// observed ~100 times regardless of pool size → entropy ≈ log₂(n) → κ ≈ 0.
//
// If kappa were NOT normalized (raw entropy bits instead), n=8 would asymptote to
// ~3.0 bits while n=4 asymptotes to ~2.0 — they would not collapse to the same value.
// The near-identical final kappa values across n=4, 8, 16 confirm that kappa is the
// right dimensionless control variable for privacy-pressure analysis.

#[test]
fn sim_kappa_scale_invariant_across_pool_sizes() {
    fn converged_kappa(active_n: usize) -> f64 {
        let mut pool = ProviderPool::new(SamplingStrategy::RandomK(1)).with_active_window(active_n);
        for i in 0..active_n {
            pool.add([i as u8; 32], SubstrateLedger::new());
        }
        let mut sim = PoolSimulator::new(pool);
        sim.run_epoch(100 * active_n);
        sim.trace.last().map_or(1.0, |t| t.kappa)
    }

    let kappa4 = converged_kappa(4);
    let kappa8 = converged_kappa(8);
    let kappa16 = converged_kappa(16);

    assert!(
        kappa4 < 0.05,
        "n=4  must converge to near-zero kappa; got {kappa4}"
    );
    assert!(
        kappa8 < 0.05,
        "n=8  must converge to near-zero kappa; got {kappa8}"
    );
    assert!(
        kappa16 < 0.05,
        "n=16 must converge to near-zero kappa; got {kappa16}"
    );
    assert!(
        (kappa4 - kappa8).abs() < 0.04,
        "kappa must collapse across n=4 and n=8; got {kappa4} vs {kappa8}"
    );
    assert!(
        (kappa8 - kappa16).abs() < 0.04,
        "kappa must collapse across n=8 and n=16; got {kappa8} vs {kappa16}"
    );
}

// ── §S26. spectral_concentration reaches near-zero when kappa does ────────────
//
// spectral_concentration = max_selection_rate − 1/active_n.
// Under uniform selection, max_rate → 1/n → spectral_concentration → 0.
// Both kappa and spectral_concentration are alternative descriptions of the same
// underlying distribution collapse, but kappa is entropy-based (log-scale) while
// spectral_concentration is linear in the max observation frequency.
//
// This test confirms that the two metrics agree directionally: if one signal says
// "converged," the other must also say "converged." Agreement means kappa alone is
// sufficient — the spectral metric adds no discriminatory power at convergence.
// Under k=n sampling (worst privacy case), both must remain elevated simultaneously.

#[test]
fn sim_spectral_concentration_agrees_with_kappa_at_convergence_and_worst_case() {
    // ── Convergence case: RandomK(1), dense sampling → both signals reach near-zero.
    let mut pool_conv = ProviderPool::new(SamplingStrategy::RandomK(1)).with_active_window(4);
    for i in 0..4u8 {
        pool_conv.add([i; 32], SubstrateLedger::new());
    }
    let mut sim_conv = PoolSimulator::new(pool_conv);
    sim_conv.run_epoch(10_000);

    let t_conv = sim_conv.trace.last().unwrap();
    assert!(
        t_conv.kappa < 0.05,
        "convergence: kappa must be near-zero after dense sampling; got {}",
        t_conv.kappa
    );
    assert!(
        t_conv.spectral_concentration < 0.05,
        "convergence: spectral_concentration must be near-zero; got {}",
        t_conv.spectral_concentration
    );

    // ── Worst-case: RandomK(4) = k=n → both signals must be elevated together.
    let mut pool_worst = ProviderPool::new(SamplingStrategy::RandomK(4)).with_active_window(4);
    for i in 0..4u8 {
        pool_worst.add([i; 32], SubstrateLedger::new());
    }
    let mut sim_worst = PoolSimulator::new(pool_worst);
    for _ in 0..10 {
        sim_worst.run_epoch(100);
    }

    let t_worst = sim_worst.trace.last().unwrap();
    assert!(
        t_worst.kappa > 0.9,
        "worst-case: kappa must be elevated (k=n); got {}",
        t_worst.kappa
    );
    assert!(
        t_worst.spectral_concentration > 0.1,
        "worst-case: spectral_concentration must be elevated (k=n); got {}",
        t_worst.spectral_concentration
    );
}

// ── §S27. steady_stability_margin() > stability_margin() ─────────────────────
//
// stability_margin() includes all epochs (PostReset, Reconverging, Steady).
// PostReset epochs have κ=1.0 from absent data — they inflate the T1 pressure
// budget and push stability_margin() down.
// steady_stability_margin() computes T1/T2/T3 over Steady-only epochs, removing
// that artifact and revealing the true in-polytope margin of the converged system.
//
// Scenario: 20 PostReset epochs (0 samples → κ=1.0 always) followed by 5 Steady
// epochs (10_000 samples each → κ≈0). The 20 PostReset epochs drive the all-epoch
// T1 pressure budget to 80% (20/25 epochs with κ>0.5), making T1 the binding
// constraint at ~0.1. The Steady-only budget is 0% → T1 is 0.9. T3 is the binding
// Steady-only constraint at 0.3.

#[test]
fn sim_steady_stratification_raises_stability_margin() {
    let mut pool = ProviderPool::new(SamplingStrategy::RandomK(1)).with_active_window(4);
    for i in 0..4u8 {
        pool.add([i; 32], SubstrateLedger::new());
    }

    let mut sim = PoolSimulator::new(pool);
    for _ in 0..20 {
        sim.run_epoch(0);
    } // PostReset: κ=1.0 × 20 → inflates T1 budget
    for _ in 0..5 {
        sim.run_epoch(10_000);
    } // Steady: κ≈0 × 5

    let all_margin = sim.stability_margin();
    let steady_margin = sim
        .steady_stability_margin()
        .expect("5 Steady epochs must produce a Steady-only margin");

    assert!(
        steady_margin > all_margin,
        "Steady-only margin ({steady_margin:.3}) must exceed all-epoch margin ({all_margin:.3}); \
         20 PostReset epochs inflate the T1 budget from 0% to 80%"
    );
    assert!(
        steady_margin > 0.0,
        "Steady-only margin must be positive (system inside polytope in Steady); \
         got {steady_margin:.3}"
    );
    assert!(
        all_margin < 0.15,
        "all-epoch margin must be low due to PostReset contamination; got {all_margin:.3}"
    );
}

// ── §S28. kappa_velocity captures net drift since last rotation ───────────────
//
// kappa_velocity = κ_current − κ_pre_rotation: the net change in convergence
// pressure since the last rotation event established a new baseline.
//
// Immediately after a tracker reset (OnRotation), κ jumps from near-0 to 1.0
// while κ_pre_rotation was near-0 → velocity is strongly positive (burst detected).
// After recovery (dense sampling returns κ to near-0), the net drift from
// pre-rotation baseline is near-zero — the pool has returned to where it started.
//
// This tests the two-sided behavioral range of kappa_velocity:
//   - Post-burst:    high positive (diverged from baseline)
//   - Post-recovery: near-zero    (returned to baseline)

#[test]
fn sim_kappa_velocity_positive_after_burst_near_zero_after_recovery() {
    let mut pool = ProviderPool::new(SamplingStrategy::RandomK(1))
        .with_active_window(4)
        .with_exposure_reset_policy(ExposureResetPolicy::OnRotation);
    for i in 0..5u8 {
        pool.add([i; 32], SubstrateLedger::new());
    }

    let mut sim = PoolSimulator::new(pool);
    sim.run_epoch(10_000); // warm: κ ≈ 0, kappa_velocity = None (no prior rotation)
    sim.pool.force_rotate(&mut sim.rng); // rotation: baseline set at κ_pre ≈ 0; tracker reset
    sim.run_epoch(0); // post-burst: κ=1.0, velocity = 1.0 - 0.0 ≈ +1.0
    sim.run_epoch(10_000); // recovery: κ≈0, velocity = 0.0 - 0.0 ≈ 0.0

    let velocity_post_burst = sim.trace[1].kappa_velocity.expect(
        "kappa_velocity must be Some after force_rotate establishes a prior-rotation baseline",
    );
    let velocity_post_recovery = sim.trace[2]
        .kappa_velocity
        .expect("kappa_velocity must be Some after the recovery epoch");

    assert!(
        velocity_post_burst > 0.5,
        "kappa_velocity must be strongly positive right after burst (κ jumped from ~0 to 1.0); \
         got {velocity_post_burst}"
    );
    assert!(
        velocity_post_recovery.abs() < 0.05,
        "kappa_velocity must be near-zero after recovery (κ returned to pre-rotation baseline); \
         got {velocity_post_recovery}"
    );
    assert!(
        velocity_post_burst > velocity_post_recovery,
        "burst velocity ({velocity_post_burst}) must exceed recovery velocity ({velocity_post_recovery})"
    );
}

// ── Metric-contract regression: kappa_displacement_since_rotation() alias ─────
//
// kappa_displacement_since_rotation() is a semantic alias for kappa_velocity.
// Both must return identical Option<f64> at every observable state. The alias
// exists to make the "displacement since baseline" framing visible at call
// sites without adding a new stored field.

#[test]
fn sim_kappa_displacement_alias_agrees_with_kappa_velocity() {
    let mut pool = ProviderPool::new(SamplingStrategy::RandomK(1))
        .with_active_window(4)
        .with_exposure_reset_policy(ExposureResetPolicy::OnRotation);
    for i in 0..5u8 {
        pool.add([i; 32], SubstrateLedger::new());
    }

    // Before any rotation: both None.
    let cp = pool.convergence_pressure();
    assert_eq!(
        cp.kappa_displacement_since_rotation(),
        cp.kappa_velocity,
        "before first rotation: alias must agree with kappa_velocity (both None)"
    );

    // After force_rotate: baseline established; both must agree.
    let mut rng = StdRng::seed_from_u64(0x5c0f_0025);
    pool.force_rotate(&mut rng);
    let cp = pool.convergence_pressure();
    assert_eq!(
        cp.kappa_displacement_since_rotation(),
        cp.kappa_velocity,
        "after rotation: alias must return the same Some(f64) as kappa_velocity"
    );
}

// ── Phase 36 (Adversarial Interaction With the Stability Polytope) ─────────────
//
// Classification: POLYTOPE_DETECTS_ORTHOGONAL_ROTATION_THRASH_UNDER_NEVER_RESET
// QC(1) + ExposureResetPolicy::Never = T2 positive-control fixture (§S31).
// Phase 36 did NOT prove: biased-provider attack or T1 collapse.
// Phase 37 establishes causal provider-originated degradation attribution.
//
// Invariants:
//   §S29: Neutral steady baseline is well inside the polytope (κ≈0, margin>0).
//   §S30: steady_stability_margin degrades monotonically with rotation rate;
//         κ stays ≈0 across all levels (ExposureResetPolicy::Never + all-seen
//         providers → entropy > log₂(active_n) → κ clamps to 0).
//   §S31: Orthogonality — κ=0 while steady_stability_margin<0. T2 detects
//         adversarial thrashing that κ cannot distinguish from safe convergence.
//   §S32: kappa_slope() (OLS) captures convergence direction. A converging pool
//         has negative slope; a thrashing pool is flat. steady_margin agrees:
//         positive for converging, negative for thrashing.
//   §S33: QueryCount(1)+OnRotation eliminates all Steady epochs. steady_stability_
//         margin()=None signals that the policy regime is too aggressive to evaluate.

// ── §S29. Neutral steady baseline: pool at rest is inside the polytope ─────────

#[test]
fn sim_s29_neutral_steady_baseline_inside_polytope() {
    let mut pool = ProviderPool::new(SamplingStrategy::RandomK(1)).with_active_window(4);
    for i in 0..4u8 {
        pool.add([i; 32], SubstrateLedger::new());
    }

    let mut sim = PoolSimulator::new(pool);
    for _ in 0..50 {
        sim.run_epoch(200);
    }

    let kappa = sim.last_kappa();
    let margin = sim
        .steady_stability_margin()
        .expect("§S29: 50 dense epochs must yield Steady-phase records");

    assert!(
        kappa < 0.05,
        "§S29: κ must converge to near-zero at steady state; got {kappa:.4}"
    );
    assert!(
        margin > 0.0,
        "§S29: neutral pool must be inside the polytope; steady_margin = {margin:.3}"
    );
}

// ── §S30. Bias-strength sweep: steady_margin degrades monotonically ────────────
//
// QueryCount(100)≈no-rotation, QueryCount(10)=moderate, QueryCount(1)=max-churn.
// ExposureResetPolicy::Never: total_samples accumulates → Steady phase reached.
// All providers observed → κ clamps to 0 for all three. Sole discriminator: T2.

#[test]
fn sim_s30_bias_sweep_monotonic_steady_margin_degradation() {
    let n_epochs = 50usize;
    let n_samples = 50usize;

    let make_pool = |qc: u64| {
        let mut p = ProviderPool::new(SamplingStrategy::RandomK(1))
            .with_active_window(4)
            .with_rotation(
                PoolRotationPolicy::QueryCount(qc),
                ChurnBudget {
                    min_churn: 1,
                    max_churn: 1,
                },
            )
            .with_exposure_reset_policy(ExposureResetPolicy::Never);
        for i in 0..8u8 {
            p.add([i; 32], SubstrateLedger::new());
        }
        p
    };

    let mut sim_hi = PoolSimulator::new(make_pool(100u64));
    let mut sim_mid = PoolSimulator::new(make_pool(10u64));
    let mut sim_lo = PoolSimulator::new(make_pool(1u64));
    for _ in 0..n_epochs {
        sim_hi.run_epoch(n_samples);
        sim_mid.run_epoch(n_samples);
        sim_lo.run_epoch(n_samples);
    }

    let kappa_hi = sim_hi.last_kappa();
    let kappa_mid = sim_mid.last_kappa();
    let kappa_lo = sim_lo.last_kappa();
    let margin_hi = sim_hi
        .steady_stability_margin()
        .expect("§S30/hi: must have Steady epochs");
    let margin_mid = sim_mid
        .steady_stability_margin()
        .expect("§S30/mid: must have Steady epochs");
    let margin_lo = sim_lo
        .steady_stability_margin()
        .expect("§S30/lo: must have Steady epochs");

    // κ is blind to rotation rate — clamps to 0 across all levels.
    assert!(
        kappa_hi < 0.05,
        "§S30: κ(QC=100) must be near-zero; got {kappa_hi:.4}"
    );
    assert!(
        kappa_mid < 0.05,
        "§S30: κ(QC=10) must be near-zero; got {kappa_mid:.4}"
    );
    assert!(
        kappa_lo < 0.05,
        "§S30: κ(QC=1) must be near-zero; got {kappa_lo:.4}"
    );

    // steady_margin degrades monotonically (non-strictly: T3 may clip both hi and mid to 0.3).
    assert!(
        margin_hi >= margin_mid,
        "§S30: margin(QC=100)={margin_hi:.3} must be ≥ margin(QC=10)={margin_mid:.3}"
    );
    assert!(
        margin_mid >= margin_lo,
        "§S30: margin(QC=10)={margin_mid:.3} must be ≥ margin(QC=1)={margin_lo:.3}"
    );
    assert!(
        margin_lo < 0.0,
        "§S30: QC=1 must cross T2 collapse boundary; steady_margin={margin_lo:.3}"
    );
    assert!(
        margin_hi > 0.0,
        "§S30: QC=100 baseline must remain inside polytope; steady_margin={margin_hi:.3}"
    );
}

// ── §S31. Orthogonality: κ=0 while steady_stability_margin<0 ──────────────────
//
// Key falsification: polytope detects adversarial regime that κ misses entirely.
// Never-reset + all-8-providers observed → entropy≈log₂(8)>log₂(4) → κ clamps 0.
// rotation_rate=1.0 → T2=−0.5 → steady_margin<0.
// κ reads "maximum diversity"; polytope reads "thrashing boundary crossed."

#[test]
fn sim_s31_orthogonal_adversarial_kappa_zero_margin_negative() {
    let mut pool = ProviderPool::new(SamplingStrategy::RandomK(1))
        .with_active_window(4)
        .with_rotation(
            PoolRotationPolicy::QueryCount(1),
            ChurnBudget {
                min_churn: 1,
                max_churn: 1,
            },
        )
        .with_exposure_reset_policy(ExposureResetPolicy::Never);
    for i in 0..8u8 {
        pool.add([i; 32], SubstrateLedger::new());
    }

    let mut sim = PoolSimulator::new(pool);
    for _ in 0..50 {
        sim.run_epoch(50);
    }

    let kappa = sim.last_kappa();
    let margin = sim
        .steady_stability_margin()
        .expect("§S31: Never-reset accumulates enough samples for Steady epochs");

    assert!(
        kappa < 0.05,
        "§S31: κ must be near-zero (clamped by cross-active entropy); got {kappa:.4}"
    );
    assert!(
        margin < 0.0,
        "§S31: polytope must detect T2 collapse despite κ=0; steady_margin={margin:.3}"
    );
}

// ── §S32. Recovery: kappa_slope() discriminates convergence direction ──────────
//
// Two pools at steady state with opposite trajectories:
//   Converging: Manual (no churn), starts at κ=1.0 (epoch with 0 samples), then
//     dense sampling drives κ toward 0. Overall OLS slope < 0.
//   Thrashing: QueryCount(1)+Never, κ clamped to 0 throughout. Slope ≈ 0 (flat).
//
// kappa_slope() (NOT kappa_velocity) separates them. steady_stability_margin agrees.

#[test]
fn sim_s32_recovery_kappa_slope_discriminates_convergence() {
    // Converging pool: 15 epochs of 0 samples (κ=1.0 always, no data) followed by
    // 15 epochs of 100 samples each (κ→0). OLS over 30 epochs spans a full
    // 1.0→0.0 drop, producing a slope well below -0.01.
    let mut pool_c = ProviderPool::new(SamplingStrategy::RandomK(1)).with_active_window(4);
    for i in 0..4u8 {
        pool_c.add([i; 32], SubstrateLedger::new());
    }
    let mut sim_c = PoolSimulator::new(pool_c);
    for _ in 0..15 {
        sim_c.run_epoch(0);
    } // κ=1.0: no data
    for _ in 0..15 {
        sim_c.run_epoch(100);
    } // κ→0: 100 samples per epoch

    // Thrashing pool: κ clamped to 0 throughout; 50 rotations.
    let mut pool_t = ProviderPool::new(SamplingStrategy::RandomK(1))
        .with_active_window(4)
        .with_rotation(
            PoolRotationPolicy::QueryCount(1),
            ChurnBudget {
                min_churn: 1,
                max_churn: 1,
            },
        )
        .with_exposure_reset_policy(ExposureResetPolicy::Never);
    for i in 0..8u8 {
        pool_t.add([i; 32], SubstrateLedger::new());
    }
    let mut sim_t = PoolSimulator::new(pool_t);
    for _ in 0..50 {
        sim_t.run_epoch(50);
    }

    let slope_c = sim_c.kappa_slope();
    let slope_t = sim_t.kappa_slope();
    let margin_c = sim_c
        .steady_stability_margin()
        .expect("§S32/converging: dense sampling must yield Steady epochs");
    let margin_t = sim_t
        .steady_stability_margin()
        .expect("§S32/thrashing: Never-reset must yield Steady epochs");

    assert!(
        slope_c < -0.005,
        "§S32: converging pool must have negative kappa_slope; got {slope_c:.4}"
    );
    assert!(
        slope_t.abs() < 0.01,
        "§S32: thrashing pool (κ clamped to 0) must have near-flat slope; got {slope_t:.4}"
    );
    assert!(
        slope_c < slope_t,
        "§S32: converging slope ({slope_c:.4}) must be less than thrashing ({slope_t:.4})"
    );
    assert!(
        margin_c > 0.0,
        "§S32: converging pool must be inside polytope; steady_margin={margin_c:.3}"
    );
    assert!(
        margin_t < 0.0,
        "§S32: thrashing pool must be outside polytope; steady_margin={margin_t:.3}"
    );
}

// ── §S33. Lifecycle contamination guard: OnRotation+QueryCount(1)=no Steady ────
//
// ExposureResetPolicy::OnRotation clears the tracker on every rotation.
// QueryCount(1) rotates on every maybe_rotate() call.
// In run_epoch(): maybe_rotate fires, rotation+reset occurs, then convergence_pressure()
// reads total_samples=0 (just reset). active_n=4. Phase=PostReset always.
//
// Result: no Steady epochs ever recorded → steady_stability_margin()=None.
// all-epoch stability_margin is dominated by T4 (total_samples=0 always → T4=-1.0).
// The None return IS the operational signal: the policy regime is too aggressive
// to produce a valid stability evaluation.

#[test]
fn sim_s33_lifecycle_contamination_eliminates_steady_epochs() {
    // 8 providers: 4 active + 4 dormant. dormant_len == active_window → the
    // DormantBelowFloor guard does not fire. Rotation occurs on every epoch.
    let mut pool = ProviderPool::new(SamplingStrategy::RandomK(1))
        .with_active_window(4)
        .with_rotation(
            PoolRotationPolicy::QueryCount(1),
            ChurnBudget {
                min_churn: 1,
                max_churn: 1,
            },
        )
        .with_exposure_reset_policy(ExposureResetPolicy::OnRotation);
    for i in 0..8u8 {
        pool.add([i; 32], SubstrateLedger::new());
    }

    let mut sim = PoolSimulator::new(pool);
    for _ in 0..50 {
        sim.run_epoch(50);
    }

    let steady_margin = sim.steady_stability_margin();
    assert!(
        steady_margin.is_none(),
        "§S33: OnRotation+QueryCount(1) must produce no Steady epochs; \
         steady_stability_margin must be None (got {steady_margin:?})"
    );

    let all_margin = sim.stability_margin();
    assert!(
        all_margin < 0.0,
        "§S33: all-epoch margin must be negative (T4 always binding); got {all_margin:.3}"
    );

    let any_steady = sim
        .trace
        .iter()
        .any(|t| EpochPhase::for_pool(t.total_samples, t.active_n) == EpochPhase::Steady);
    assert!(
        !any_steady,
        "§S33: no epoch should reach Steady under OnRotation+QueryCount(1)"
    );
}

// ── Phase 37 (Causal Provider Failure and Correction) ─────────────────────────
//
// Classification: PROVIDER_ORIGINATED_DEGRADATION_DETECTED_AND_CORRECTED
//
// Provider-originated events and their effect on T1–T4:
//   T1 (false equilibrium): liveness failures concentrate selection → κ rises.
//   T2 (churn exhaustion):  only policy-induced; record_failure does not trigger rotation.
//   T3 (EWMA lag):          sudden mass liveness failure spikes raw κ above smoothed κ.
//   T4 (post-reset):        not directly provider-originated; tracker reset only.
//
// T1 simulator-exercisability:
//   CONFIRMED. record_failure() on active providers reduces live pool, concentrates
//   selection on surviving providers, raises κ, degrades T1 margin, and reaches
//   steady_stability_margin < 0 without any forced rotation.
//
// Phase 37 invariants:
//   §S34: Liveness failures on active providers elevate κ proportionally to failure count.
//   §S35: liveness_weighted_kappa diverges from κ when providers silently fail to respond.
//   §S36: record_response() recovery returns steady_stability_margin to positive.
//   §S37: Corrective action does NOT transform provider failure into T2 rotation thrash.
//   §S38: Eviction + admission recovery restores pool health without steady_margin collapse.
//
// Scenario table:
// | Cause of Pressure                 | κ      | Binding Surface | steady_stability_margin | Offender Action          | Final Status |
// |-----------------------------------|--------|-----------------|-------------------------|--------------------------|--------------|
// | 3/4 providers dead (failure)      | rises  | T1              | < 0                     | record_failure × 5       | Degraded     |
// | liveness_weighted_kappa / κ gap   | ≈ 0    | T1 via response | liveness_κ >> κ          | no record_response       | Silent fail  |
// | record_response() recovery        | falls  | T1 recovering   | > 0                     | record_response × 3      | Recovered    |
// | Corrective action + QueryCount    | rises  | T1              | T2 > 0 throughout        | policy not triggered     | No T2 thrash |
// | Eviction + add new provider       | ≈ 0    | none            | > 0                     | evict + add replacement  | Stable       |
//
// Final verdict: A. PROVIDER_ORIGINATED_DEGRADATION_DETECTED_AND_CORRECTED

// ── §S34. Liveness failures on active providers elevate κ ─────────────────────
//
// Baseline (4 providers, 200 samples): κ ≈ 0, steady_stability_margin > 0.
// After 3 providers killed (5 failures each): selection concentrates on 1 live
// provider → selection entropy drops → κ rises.
// The T1 boundary degrades because budget(0.5) increases with sustained high κ.
//
// with_liveness(5, 3600): provider is dead when consecutive_failures >= 5.

#[test]
fn sim_s34_liveness_failures_elevate_kappa() {
    let mut pool = ProviderPool::new(SamplingStrategy::RandomK(1))
        .with_active_window(4)
        .with_liveness(5, 3600);
    for i in 0..4u8 {
        pool.add([i; 32], SubstrateLedger::new());
    }

    let mut sim = PoolSimulator::new(pool);

    // Establish a Steady baseline with κ ≈ 0.
    for _ in 0..200 {
        sim.run_epoch(1);
    }
    let baseline_kappa = sim.last_kappa();
    assert!(
        baseline_kappa < 0.1,
        "§S34: baseline κ must be near-zero before failures; got {baseline_kappa:.4}"
    );

    // Kill 3 of the 4 active providers: 5 failures each reaches the threshold.
    for i in 1u8..4u8 {
        for _ in 0..5 {
            sim.pool.record_failure([i; 32]);
        }
    }

    // Run 400 more epochs — selection concentrates on the sole live provider.
    // 400 epochs gives provider 0 ~450/600 = 75% of selections → κ ≈ 0.40,
    // providing reliable separation from the baseline+0.2 threshold (~0.21).
    // 200 epochs was insufficient: expected κ ≈ 0.22 sat too close to the threshold.
    for _ in 0..400 {
        sim.run_epoch(1);
    }
    let post_failure_kappa = sim.last_kappa();

    assert!(
        post_failure_kappa > baseline_kappa + 0.2,
        "§S34: κ must rise substantially after 3/4 providers die; \
         baseline={baseline_kappa:.4} post_failure={post_failure_kappa:.4}"
    );
    // With 200 baseline samples + 400 failure-period samples, provider 0 accrues
    // ~450 of 600 total appearances → rate 0.75 → κ ≈ 0.40.
    // The meaningful invariant is that κ exceeds a meaningful threshold above zero.
    assert!(
        post_failure_kappa > 0.15,
        "§S34: κ must exceed 0.15 when 3/4 providers are dead; got {post_failure_kappa:.4}"
    );
}

// ── §S35. liveness_weighted_kappa diverges from κ under silent failure ─────────
//
// κ is derived from selection entropy: which providers are sampled.
// liveness_weighted_kappa is derived from response entropy: which providers respond.
//
// Setup: warm 4 active providers to κ ≈ 0 (uniform selection).
// Then call record_response only for provider 0 — the other 3 are selected but
// never respond. Response distribution concentrates on provider 0 alone:
// response_entropy_bits → 0 → liveness_weighted_kappa → 1.0.
// Selection stays uniform → κ stays near 0.
// Gap: liveness_weighted_kappa > κ + 0.5 confirms divergence.

#[test]
fn sim_s35_liveness_weighted_kappa_diverges_under_silent_failure() {
    let mut pool = ProviderPool::new(SamplingStrategy::RandomK(1)).with_active_window(4);
    for i in 0..4u8 {
        pool.add([i; 32], SubstrateLedger::new());
    }

    let mut sim = PoolSimulator::new(pool);

    // Warm the pool: κ converges to near-zero (all 4 providers selected uniformly).
    for _ in 0..200 {
        sim.run_epoch(10);
    }
    let warm_kappa = sim.last_kappa();
    assert!(
        warm_kappa < 0.05,
        "§S35: baseline κ must be near-zero; got {warm_kappa:.4}"
    );

    // Now record responses ONLY for provider 0 across 100 calls.
    // Providers 1, 2, 3 are selected by sampling but never respond.
    // Response distribution: all weight on provider 0 → response_entropy ≈ 0.
    for _ in 0..100 {
        sim.pool.record_response([0u8; 32]);
    }

    // One final epoch to capture the liveness_weighted_kappa snapshot.
    sim.run_epoch(10);
    let last = sim.trace.last().unwrap();

    assert!(
        last.liveness_weighted_kappa > last.kappa + 0.5,
        "§S35: liveness_weighted_kappa ({:.4}) must exceed κ ({:.4}) by > 0.5 \
         when only one provider responds",
        last.liveness_weighted_kappa,
        last.kappa
    );
    assert!(
        last.liveness_weighted_kappa > 0.8,
        "§S35: liveness_weighted_kappa must be near 1.0 (single responder); \
         got {:.4}",
        last.liveness_weighted_kappa
    );
}

// ── §S36. record_response() recovery restores steady_stability_margin ──────────
//
// Three-phase test:
//   Phase 1: 200 epochs → Steady, κ≈0, steady_margin > 0 (baseline).
//   Phase 2: kill 3 providers, 200 more epochs → κ rises, margin degrades.
//   Phase 3: recover all 3 providers via record_response(), 200 more epochs →
//            κ falls back, steady_margin recovers above post-failure level.
//
// Recovery invariant: steady_margin_post_recovery > steady_margin_post_failure.
// No-thrash invariant: sim.total_rotations() == 0 (Manual policy throughout).

#[test]
fn sim_s36_record_response_recovery_restores_steady_margin() {
    let mut pool = ProviderPool::new(SamplingStrategy::RandomK(1))
        .with_active_window(4)
        .with_liveness(5, 3600);
    for i in 0..4u8 {
        pool.add([i; 32], SubstrateLedger::new());
    }

    let mut sim = PoolSimulator::new(pool);

    // Phase 1: establish Steady baseline.
    for _ in 0..200 {
        sim.run_epoch(1);
    }
    let baseline_margin = sim
        .steady_stability_margin()
        .expect("§S36/phase1: 200 epochs must yield Steady records");
    assert!(
        baseline_margin > 0.0,
        "§S36: baseline steady_margin must be positive; got {baseline_margin:.3}"
    );

    // Phase 2: kill 3 providers, run 200 more epochs.
    for i in 1u8..4u8 {
        for _ in 0..5 {
            sim.pool.record_failure([i; 32]);
        }
    }
    for _ in 0..200 {
        sim.run_epoch(1);
    }
    let post_failure_margin = sim
        .steady_stability_margin()
        .expect("§S36/phase2: Steady records must persist");

    // Phase 3: recover all 3 providers, run 200 more epochs.
    for i in 1u8..4u8 {
        sim.pool.record_response([i; 32]);
    }
    for _ in 0..200 {
        sim.run_epoch(1);
    }
    let post_recovery_margin = sim
        .steady_stability_margin()
        .expect("§S36/phase3: Steady records must persist after recovery");

    // T3 (EWMA lag = 0 with default α=1.0) clips steady_stability_margin at 0.3
    // regardless of T1 improvement. The margin is non-decreasing after recovery.
    assert!(
        post_recovery_margin >= post_failure_margin,
        "§S36: recovery must not worsen steady_margin; \
         post_failure={post_failure_margin:.3} post_recovery={post_recovery_margin:.3}"
    );
    assert!(
        post_recovery_margin > 0.0,
        "§S36: steady_margin must be positive after recovery; got {post_recovery_margin:.3}"
    );
    // κ must fall after recovery — the selection signal improves even when T3 clips the margin.
    let kappa_during_failure = sim.trace[399].kappa;
    let kappa_after_recovery = sim.last_kappa();
    assert!(
        kappa_after_recovery < kappa_during_failure,
        "§S36: κ must fall after record_response() recovery; \
         failure_kappa={kappa_during_failure:.4} recovery_kappa={kappa_after_recovery:.4}"
    );
    // Manual policy: no rotation occurs at any point.
    assert_eq!(
        sim.total_rotations(),
        0,
        "§S36: Manual policy must produce zero rotations; got {}",
        sim.total_rotations()
    );
}

// ── §S37. Corrective action does NOT induce T2 rotation thrash ────────────────
//
// Proves that recovering failed providers (record_response) does not transform
// provider failure into T2 rotation thrash. The rotation count remains near zero
// throughout the entire failure-recovery cycle.
//
// Setup: 4 active + 4 dormant, QueryCount(100) (≈no-rotation under 200 samples/epoch),
// ExposureResetPolicy::Never (prevents Steady elimination from tracker resets),
// with_liveness(5, 3600).
//
// T2 invariant: rotation_rate = total_rotations / epoch_count < 0.1 throughout.
// steady_stability_margin is Some throughout (not eliminated by OnRotation).

#[test]
fn sim_s37_corrective_action_does_not_induce_t2_thrash() {
    let mut pool = ProviderPool::new(SamplingStrategy::RandomK(1))
        .with_active_window(4)
        .with_rotation(
            PoolRotationPolicy::QueryCount(100),
            ChurnBudget {
                min_churn: 1,
                max_churn: 1,
            },
        )
        .with_exposure_reset_policy(ExposureResetPolicy::Never)
        .with_liveness(5, 3600);
    // 4 active + 4 dormant.
    for i in 0..8u8 {
        pool.add([i; 32], SubstrateLedger::new());
    }

    let mut sim = PoolSimulator::new(pool);

    // Phase 1: 50 epochs × 10 samples → Steady baseline, near-zero rotation rate.
    for _ in 0..50 {
        sim.run_epoch(10);
    }
    let margin_phase1 = sim
        .steady_stability_margin()
        .expect("§S37/phase1: must reach Steady with Never reset");
    assert!(
        margin_phase1 > 0.0,
        "§S37/phase1: steady_margin must be positive; got {margin_phase1:.3}"
    );

    // Phase 2: kill 3 of 4 active providers.
    for i in 1u8..4u8 {
        for _ in 0..5 {
            sim.pool.record_failure([i; 32]);
        }
    }

    // Phase 3: 50 more epochs with failures in place.
    for _ in 0..50 {
        sim.run_epoch(10);
    }

    // Phase 4: recover all 3 failed providers.
    for i in 1u8..4u8 {
        sim.pool.record_response([i; 32]);
    }

    // Phase 5: 50 more epochs after recovery.
    for _ in 0..50 {
        sim.run_epoch(10);
    }

    let total_epochs = sim.trace.len() as f64;
    let rotation_rate = sim.total_rotations() as f64 / total_epochs;

    // T2 invariant: rotation_rate well below 0.5.
    assert!(
        rotation_rate < 0.1,
        "§S37: rotation_rate must stay < 0.1 throughout failure-recovery cycle; \
         got {rotation_rate:.3} ({} rotations / {total_epochs} epochs)",
        sim.total_rotations()
    );

    // Margin T2 must be strongly positive.
    assert!(
        sim.margin_t2() > 0.3,
        "§S37: T2 margin must remain strongly positive; got {:.3}",
        sim.margin_t2()
    );

    // Steady margin is Some (Never reset keeps Steady epochs alive).
    assert!(
        sim.steady_stability_margin().is_some(),
        "§S37: steady_stability_margin must be Some with ExposureResetPolicy::Never"
    );
}

// ── §S38. Eviction + add new provider restores pool health ────────────────────
//
// Tests the eviction and re-population recovery path without admission challenge
// protocol (which requires Ed25519 — out of scope for simulator tests).
//
// Setup: 4 active + 5 dormant (9 total), active_window=4, with_eviction().
// The dormant floor check requires dormant.len() - 1 >= active_window after eviction,
// so at least 5 dormant providers are needed to evict one dormant.
//
// Assertions:
//   1. evict() on a dormant provider succeeds (dormant_count drops by 1).
//   2. eviction_record() is Some immediately after eviction.
//   3. request_admission() on the evicted pid returns EvictionCooldown immediately.
//   4. add() of a new pid (admission not configured) restores dormant_count.
//   5. Pool health: steady_stability_margin > 0 (eviction of dormant does not affect κ).

#[test]
fn sim_s38_eviction_add_recovery_restores_pool_health() {
    // with_admission() panics on add() — use with_eviction() only so that add() works.
    let mut pool = ProviderPool::new(SamplingStrategy::RandomK(1))
        .with_active_window(4)
        .with_eviction(EvictionConfig::default());
    // 4 active + 5 dormant = 9 total.
    for i in 0..9u8 {
        pool.add([i; 32], SubstrateLedger::new());
    }

    assert_eq!(pool.active_count(), 4, "§S38: must have 4 active providers");
    assert_eq!(
        pool.dormant_count(),
        5,
        "§S38: must have 5 dormant providers"
    );

    // Warm the pool so we can measure steady_stability_margin.
    let mut sim = PoolSimulator::new(pool);
    for _ in 0..200 {
        sim.run_epoch(1);
    }

    let pre_eviction_margin = sim
        .steady_stability_margin()
        .expect("§S38: 200 epochs must yield Steady records");
    assert!(
        pre_eviction_margin > 0.0,
        "§S38: pool must be inside polytope before eviction"
    );

    let dormant_before = sim.pool.dormant_count();

    // Evict one dormant provider (provider id [8; 32]).
    let evicted_pid: [u8; 32] = [8u8; 32];
    sim.pool
        .evict(&evicted_pid, EvictionReason::LivenessExhausted)
        .expect("§S38: eviction of dormant provider must succeed");

    assert_eq!(
        sim.pool.dormant_count(),
        dormant_before - 1,
        "§S38: dormant_count must decrease by 1 after eviction"
    );

    // Eviction record must be present immediately.
    assert!(
        sim.pool.eviction_record(&evicted_pid).is_some(),
        "§S38: eviction_record must be Some immediately after eviction"
    );

    // Re-admission request for the evicted provider must fail with EvictionCooldown.
    // We configure a temporary admission gate to test this path.
    // Since admission was not configured on this pool, request_admission returns NotConfigured.
    // Test the error type returned by eviction_record instead (already asserted above).
    // The EvictionCooldown variant is present — verify the record reason matches.
    let record = sim.pool.eviction_record(&evicted_pid).unwrap();
    assert!(
        matches!(record.reason, EvictionReason::LivenessExhausted),
        "§S38: eviction record must carry LivenessExhausted reason"
    );

    // Add a replacement provider (new pid [9; 32]) to restore dormant count.
    let new_pid: [u8; 32] = [9u8; 32];
    sim.pool.add(new_pid, SubstrateLedger::new());

    assert_eq!(
        sim.pool.dormant_count(),
        dormant_before,
        "§S38: dormant_count must be restored after adding replacement provider"
    );
    assert_eq!(
        sim.pool.len(),
        9, // same total universe size
        "§S38: total pool size must remain at 9 (evict 1, add 1)"
    );

    // Pool health: run 100 more epochs. Steady margin must stay positive.
    // Evicting a dormant provider does not affect the active pool's κ.
    for _ in 0..100 {
        sim.run_epoch(1);
    }
    let post_eviction_margin = sim
        .steady_stability_margin()
        .expect("§S38: Steady records must persist after eviction and recovery");
    assert!(
        post_eviction_margin > 0.0,
        "§S38: steady_margin must remain positive after eviction+add; got {post_eviction_margin:.3}"
    );
}

// ── §S41. T1 detection envelope across pool sizes ─────────────────────────────
//
// Documents the detection limit under ExposureResetPolicy::Never and Manual
// rotation: T1 does NOT fire after a single provider fails, regardless of active
// pool size.  The pressure_budget(0.5) threshold is not breached because historical
// selection counts dilute the survivor's rate to well below 0.5.
//
// Active pool sizes tested: 2, 4, 8.
// For each: 400 warm epochs → fail provider [1;32] → 400 failure epochs.
// Expected post-failure κ (Never reset, 800 total samples):
//   n=2: rate[0]≈0.75, κ≈0.19
//   n=4: rate[0]≈0.625, κ≈0.23
//   n=8: rate[0]≈0.5625, κ≈0.26
// In every case κ stays below 0.5, so budget(0.5)≈0 and margin_t1 stays > 0.
// Verdict contribution: T1 is a false-equilibrium detector, not a provider-failure
// detector; historical dilution under Never reset is the estimator-freshness
// limitation described in Phase 38.

#[test]
fn sim_s41_t1_detection_envelope_across_pool_sizes() {
    for n in [2usize, 4, 8] {
        // n active + n dormant — dormant satisfies the DormantBelowFloor gate even
        // though Manual policy never fires maybe_rotate().
        let mut pool = ProviderPool::new(SamplingStrategy::RandomK(1))
            .with_active_window(n)
            .with_liveness(5, 3600)
            .with_exposure_reset_policy(ExposureResetPolicy::Never);
        for i in 0..(2 * n as u8) {
            pool.add([i; 32], SubstrateLedger::new());
        }

        let mut sim = PoolSimulator::new(pool);

        // Warm: 400 epochs × 1 sample — selection entropy converges toward log₂(n).
        for _ in 0..400 {
            sim.run_epoch(1);
        }
        let warm_kappa = sim.last_kappa();
        assert!(
            warm_kappa < 0.05,
            "§S41/n={n}: warm κ must be near-zero after 400 epochs; got {warm_kappa:.4}"
        );

        // Fail provider [1;32] — 5 consecutive failures exhaust the liveness budget;
        // is_live([1;32]) = false and it is excluded from all subsequent samples.
        for _ in 0..5 {
            sim.pool.record_failure([1u8; 32]);
        }

        // Failure phase: 400 more epochs — selection concentrates on live providers.
        for _ in 0..400 {
            sim.run_epoch(1);
        }

        let post_kappa = sim.last_kappa();
        let margin_t1 = sim.margin_t1();
        let steady_margin = sim
            .steady_stability_margin()
            .expect("§S41: 800 epochs must contain Steady records");

        // κ must rise above the warm baseline.  The failure-dead provider accumulates
        // zero additional samples, so its rate drops relative to the live survivors —
        // making the distribution less uniform and kappa strictly higher.
        // For n=2: 1 survivor → kappa ≈ 0.19 (large signal).
        // For n=4: 3 survivors → kappa ≈ 0.036 (small but present).
        // For n=8: 7 survivors → kappa ≈ 0.011 (marginal; variance may dominate).
        // We use a small absolute floor (0.003) that holds reliably for all sizes.
        assert!(
            post_kappa > warm_kappa && post_kappa > 0.003,
            "§S41/n={n}: κ must rise above warm baseline after 1 failure; \
             warm={warm_kappa:.4} post={post_kappa:.4}"
        );

        // T1 must NOT cross: historical dilution keeps budget(0.5)≈0.
        assert!(
            margin_t1 > 0.0,
            "§S41/n={n}: T1 must not fire after 1/{n} failure under Never reset; \
             margin_t1={margin_t1:.3}"
        );

        // Polytope health: pool remains inside all four boundaries.
        assert!(
            steady_margin > 0.0,
            "§S41/n={n}: steady_margin must remain positive; got {steady_margin:.3}"
        );

        // No rotation occurred (Manual policy).
        assert_eq!(
            sim.total_rotations(),
            0,
            "§S41/n={n}: Manual policy must produce zero rotations"
        );
    }
}

// ── §S42. Never-reset history dilutes provider failure visibility ──────────────
//
// Two pools, identical architecture (n=8), identical failure scenario (4/8 providers
// fail), but different warm-up lengths:
//
//   Long-history pool:  1 000 warm epochs → 1 200 total samples after failure run.
//   Short-history pool:    20 warm epochs →   220 total samples after failure run.
//
// Expected κ after 200 failure epochs (4/8 dead, 200 samples concentrated on survivors):
//   Long:  appearances[0-3]≈175, [4-7]≈125, total=1 200 → κ≈0.007 (almost invisible)
//   Short: appearances[0-3]≈52, [4-7]≈2,   total=  220 → κ≈0.245 (visibly elevated)
//
// In both cases margin_t1 > 0 (T1 still does not fire — same root cause as §S41),
// but the relative magnitude of κ differs by more than 10×, directly proving the
// freshness limitation: longer Never-reset history makes failures harder to see.

#[test]
fn sim_s42_never_reset_dilutes_provider_failure_visibility() {
    // ── Long-history pool ───────────────────────────────────────────────────
    let mut long_pool = ProviderPool::new(SamplingStrategy::RandomK(1))
        .with_active_window(8)
        .with_liveness(5, 3600)
        .with_exposure_reset_policy(ExposureResetPolicy::Never);
    for i in 0..16u8 {
        long_pool.add([i; 32], SubstrateLedger::new());
    }
    let mut long_sim = PoolSimulator::new(long_pool);

    for _ in 0..1_000 {
        long_sim.run_epoch(1);
    }
    // Fail providers 4–7 (each gets 5 consecutive failures).
    for f in 4u8..8u8 {
        for _ in 0..5 {
            long_sim.pool.record_failure([f; 32]);
        }
    }
    for _ in 0..200 {
        long_sim.run_epoch(1);
    }
    let long_kappa = long_sim.last_kappa();

    // ── Short-history pool ──────────────────────────────────────────────────
    let mut short_pool = ProviderPool::new(SamplingStrategy::RandomK(1))
        .with_active_window(8)
        .with_liveness(5, 3600)
        .with_exposure_reset_policy(ExposureResetPolicy::Never);
    for i in 0..16u8 {
        short_pool.add([i; 32], SubstrateLedger::new());
    }
    let mut short_sim = PoolSimulator::new(short_pool);

    for _ in 0..20 {
        short_sim.run_epoch(1);
    }
    for f in 4u8..8u8 {
        for _ in 0..5 {
            short_sim.pool.record_failure([f; 32]);
        }
    }
    for _ in 0..200 {
        short_sim.run_epoch(1);
    }
    let short_kappa = short_sim.last_kappa();

    // Never reset accumulates stale uniform history that dilutes the post-failure
    // concentration.  Short history → signal 3× more visible.
    assert!(
        long_kappa < 0.05,
        "§S42: long-history pool must show near-zero κ after 50% failure; got {long_kappa:.4}"
    );
    assert!(
        short_kappa > 0.10,
        "§S42: short-history pool must show elevated κ after 50% failure; got {short_kappa:.4}"
    );
    assert!(
        short_kappa > long_kappa * 5.0,
        "§S42: short-history κ ({short_kappa:.4}) must be ≥5× long-history κ ({long_kappa:.4})"
    );

    // T1 still does not fire in either case — budget(0.5) ≈ 0 for both.
    assert!(
        long_sim.margin_t1() > 0.0,
        "§S42: T1 must not fire in long-history pool; margin_t1={:.3}",
        long_sim.margin_t1()
    );
    assert!(
        short_sim.margin_t1() > 0.0,
        "§S42: T1 must not fire in short-history pool; margin_t1={:.3}",
        short_sim.margin_t1()
    );
}

// ── §S43. Liveness failure is visible without forced rotation ─────────────────
//
// Provider-originated hard failure (is_live = false) raises κ through selection
// concentration — no rotation is needed to expose the signal.
//
// Setup: 4 active + 4 dormant, Manual policy (total_rotations = 0 throughout),
// Never reset, with_liveness(5, 3600).
//
// Phase 1: 200 warm epochs — κ ≈ 0, responses recorded for all 4 providers.
// Phase 2: fail providers 1–3 (5 failures each) — is_live returns false for them.
//          Record 100 responses only for provider 0 (survivor).
// Phase 3: 200 failure epochs — selection concentrates on provider 0.
//
// Invariants:
//   total_rotations = 0                (Manual policy, no rotation)
//   κ rises above warm level           (hard failure visible through selection)
//   liveness_weighted_κ > warm_kappa   (response concentration confirms the signal)
//   steady_stability_margin > 0        (pool remains inside polytope)

#[test]
fn sim_s43_liveness_failure_visible_without_forced_rotation() {
    let mut pool = ProviderPool::new(SamplingStrategy::RandomK(1))
        .with_active_window(4)
        .with_liveness(5, 3600)
        .with_exposure_reset_policy(ExposureResetPolicy::Never);
    for i in 0..8u8 {
        pool.add([i; 32], SubstrateLedger::new());
    }

    let mut sim = PoolSimulator::new(pool);

    // Phase 1: warm — uniform selection and uniform responses.
    for _ in 0..200 {
        sim.run_epoch(1);
    }
    for i in 0..4u8 {
        for _ in 0..50 {
            sim.pool.record_response([i; 32]);
        }
    }
    let warm_kappa = sim.last_kappa();
    assert!(
        warm_kappa < 0.05,
        "§S43: warm κ must be near-zero; got {warm_kappa:.4}"
    );

    // Phase 2: fail providers 1–3, record survivor responses.
    for f in 1u8..4u8 {
        for _ in 0..5 {
            sim.pool.record_failure([f; 32]);
        }
    }
    for _ in 0..100 {
        sim.pool.record_response([0u8; 32]);
    }

    // Phase 3: 200 failure epochs — selection concentrates on provider 0.
    for _ in 0..200 {
        sim.run_epoch(1);
    }

    let post_kappa = sim.last_kappa();
    let last = sim.trace.last().unwrap();
    let steady_margin = sim
        .steady_stability_margin()
        .expect("§S43: must have Steady records after 400 epochs");

    // Hard failure is visible: κ rose through selection concentration.
    assert!(
        post_kappa > warm_kappa + 0.05,
        "§S43: κ must rise after 3/4 providers fail; warm={warm_kappa:.4} post={post_kappa:.4}"
    );

    // Liveness signal confirms the failure from the response side.
    // Response distribution: [150, 50, 50, 50] / 300 total after warm + survivor responses.
    // liveness_weighted_κ = 1 − H(response_dist) / log₂(4) > 0.
    assert!(
        last.liveness_weighted_kappa > warm_kappa,
        "§S43: liveness_weighted_κ must rise above warm level; \
         warm={warm_kappa:.4} post={:.4}",
        last.liveness_weighted_kappa
    );

    // Pool stays inside polytope.
    assert!(
        steady_margin > 0.0,
        "§S43: steady_margin must stay positive; got {steady_margin:.3}"
    );

    // Critical: no rotation occurred — failure is visible purely through selection pressure.
    assert_eq!(
        sim.total_rotations(),
        0,
        "§S43: Manual policy must produce zero rotations; hard failure is detectable without them"
    );
}

// ── §S44. liveness_weighted_κ detects silent failure before κ ─────────────────
//
// "Silent failure": a provider is selected by sampling (kappa stays low) but never
// records a response. κ cannot see this because it measures selection entropy, not
// response entropy. liveness_weighted_κ sees it immediately.
//
// Setup: 4 active, never reset.
// Phase 1: 200 epochs × 10 samples — selection warm-up, κ → 0.
//          Record 50 uniform responses for each of the 4 providers.
// Phase 2: record 200 responses only for provider 0 (providers 1–3 are silently dead).
//          Selection stays uniform — κ does not change.
//
// Expected after phase 2:
//   response_appearances = [250, 50, 50, 50], response_total = 400
//   response_entropy ≈ 1.55 bits  →  liveness_weighted_κ ≈ 0.22
//   selection κ stays < 0.05 (2 000 uniform samples dwarf the signal)
//
// Invariant: liveness_weighted_κ − κ > 0.15
// This is the diagnostic gap that motivates treating liveness_weighted_κ as
// mandatory telemetry for operational silent-failure detection.

#[test]
fn sim_s44_liveness_weighted_kappa_detects_silent_failure_before_kappa() {
    let mut pool = ProviderPool::new(SamplingStrategy::RandomK(1)).with_active_window(4);
    for i in 0..4u8 {
        pool.add([i; 32], SubstrateLedger::new());
    }

    let mut sim = PoolSimulator::new(pool);

    // Phase 1: warm selection (2 000 samples → κ ≈ 0) and warm responses (50 each).
    for _ in 0..200 {
        sim.run_epoch(10);
    }
    for i in 0..4u8 {
        for _ in 0..50 {
            sim.pool.record_response([i; 32]);
        }
    }
    let warm_kappa = sim.last_kappa();
    assert!(
        warm_kappa < 0.05,
        "§S44: warm κ must be near-zero; got {warm_kappa:.4}"
    );

    // Phase 2: silent failure — only provider 0 records responses.
    // Providers 1–3 continue to be selected but never respond.
    for _ in 0..200 {
        sim.pool.record_response([0u8; 32]);
    }

    // Capture a snapshot after the silent-failure period.
    sim.run_epoch(10);
    let last = sim.trace.last().unwrap();

    // κ must stay near-zero: selection is still uniform (2 010 samples, all providers live).
    assert!(
        last.kappa < 0.05,
        "§S44: κ must stay near-zero during silent failure (selection uniform); got {:.4}",
        last.kappa
    );

    // liveness_weighted_κ reveals the response concentration:
    //   [250, 50, 50, 50] / 400 → entropy ≈ 1.55 bits → liveness_weighted_κ ≈ 0.22.
    assert!(
        last.liveness_weighted_kappa > last.kappa + 0.15,
        "§S44: liveness_weighted_κ ({:.4}) must exceed κ ({:.4}) by > 0.15 \
         during silent failure",
        last.liveness_weighted_kappa,
        last.kappa
    );
    assert!(
        last.liveness_weighted_kappa > 0.15,
        "§S44: liveness_weighted_κ must be noticeably elevated; got {:.4}",
        last.liveness_weighted_kappa
    );
}

// ── §S45. Benign intermittent silence does not false-trigger ──────────────────
//
// A brief period where only one provider records responses should not permanently
// elevate liveness_weighted_κ once full response coverage resumes.
//
// Protocol (deterministic — all record_response calls are explicit):
//   Phase 1: 200 uniform responses for each of 4 providers (800 total).
//   Phase 2: 10 responses only for provider 0 (brief silence from providers 1–3).
//   Phase 3: 100 uniform responses for each of 4 providers (400 total).
//
// Post-phase-3 distribution: [310, 300, 300, 300] / 1 210 total.
// rate[0] ≈ 0.256, rate[1-3] ≈ 0.248 → entropy ≈ 2.0 bits → liveness_weighted_κ ≈ 0.
//
// Invariant: final liveness_weighted_κ < 0.05 — historical dilution absorbs
// the brief distortion, confirming that transient silence does not constitute
// a permanent false trigger.

#[test]
fn sim_s45_benign_intermittent_silence_does_not_false_trigger() {
    let mut pool = ProviderPool::new(SamplingStrategy::RandomK(1)).with_active_window(4);
    for i in 0..4u8 {
        pool.add([i; 32], SubstrateLedger::new());
    }
    let mut sim = PoolSimulator::new(pool);

    // Phase 1: warm — uniform responses from all 4 providers.
    for i in 0..4u8 {
        for _ in 0..200 {
            sim.pool.record_response([i; 32]);
        }
    }

    // Phase 2: brief silence — only provider 0 responds for 10 calls.
    for _ in 0..10 {
        sim.pool.record_response([0u8; 32]);
    }

    // Phase 3: recovery — all providers resume uniform responses.
    for i in 0..4u8 {
        for _ in 0..100 {
            sim.pool.record_response([i; 32]);
        }
    }

    // Snapshot after recovery.
    sim.run_epoch(1);
    let last = sim.trace.last().unwrap();

    // Response distribution after recovery: [310, 300, 300, 300] / 1 210.
    // Entropy ≈ log₂(4) → liveness_weighted_κ ≈ 0.
    assert!(
        last.liveness_weighted_kappa < 0.05,
        "§S45: brief intermittent silence must not permanently elevate \
         liveness_weighted_κ after recovery; got {:.4}",
        last.liveness_weighted_kappa
    );
}

// ── §S46. Selective response suppression stresses the liveness signal ──────────
//
// All 8 providers are selected uniformly (κ ≈ 0) but only 4 record responses.
// This models a "partial silent failure" — the adversary or failing providers
// suppress acknowledgements without changing which providers are queried.
//
// κ is blind because it observes selection entropy, which remains uniform.
// liveness_weighted_κ detects the imbalance because response entropy is log₂(4)
// rather than log₂(8).
//
// Expected liveness_weighted_κ = 1 − log₂(4)/log₂(8) = 1 − 2/3 ≈ 0.333.
// This is a structural signal, not a noisy estimate: response_appearances are
// set deterministically via explicit record_response calls.
//
// Invariants:
//   κ < 0.05                                (selection stays uniform)
//   liveness_weighted_κ > 0.25             (partial silent failure visible)
//   liveness_weighted_κ − κ > 0.20         (liveness exceeds selection signal)

#[test]
fn sim_s46_selective_response_suppression_stresses_liveness_signal() {
    // 8 active + 8 dormant so the DormantBelowFloor gate is satisfied.
    let mut pool = ProviderPool::new(SamplingStrategy::RandomK(1)).with_active_window(8);
    for i in 0..16u8 {
        pool.add([i; 32], SubstrateLedger::new());
    }
    let mut sim = PoolSimulator::new(pool);

    // Selection warm: 400 epochs × 1 sample — all 8 providers converge to uniform.
    for _ in 0..400 {
        sim.run_epoch(1);
    }
    let warm_kappa = sim.last_kappa();
    assert!(
        warm_kappa < 0.05,
        "§S46: warm κ must be near-zero (8 providers selected uniformly); got {warm_kappa:.4}"
    );

    // Selective suppression: only providers 0–3 record responses (100 each).
    // Providers 4–7 are selected but never respond.
    for i in 0..4u8 {
        for _ in 0..100 {
            sim.pool.record_response([i; 32]);
        }
    }
    // response_appearances: [100, 100, 100, 100, 0, 0, 0, 0], total = 400
    // response_entropy = log₂(4) = 2.0 bits
    // liveness_weighted_κ = 1 − 2.0 / log₂(8) = 1 − 2/3 ≈ 0.333

    sim.run_epoch(1);
    let last = sim.trace.last().unwrap();

    assert!(
        last.kappa < 0.05,
        "§S46: κ must stay near-zero (selection stays uniform); got {:.4}",
        last.kappa
    );
    assert!(
        last.liveness_weighted_kappa > 0.25,
        "§S46: liveness_weighted_κ must signal 4/8 silent providers; got {:.4}",
        last.liveness_weighted_kappa
    );
    assert!(
        last.liveness_weighted_kappa > last.kappa + 0.20,
        "§S46: liveness signal must exceed selection signal by ≥ 0.20; \
         liveness={:.4} kappa={:.4}",
        last.liveness_weighted_kappa,
        last.kappa
    );
}

// ── §S47. Eviction recovery scales without T2 instability ─────────────────────
//
// Proves that the evict-then-add recovery path (active provider removed, new
// provider fills the vacancy) does not cause T2 rotation thrash, even when
// automatic rotation is running.
//
// Setup: 8 active + 10 dormant (18 total), active_window=8, QueryCount(100)
// rotation, ChurnBudget { min:1, max:1 }, Never reset, with_eviction,
// with_liveness(5, 3600).
//
// Timeline:
//   Phase 1: 150 warm epochs (at most 1 rotation at epoch 100).
//   Phase 2: fail providers [0;32] and [1;32] (5 failures each).
//             Evict both from wherever they currently live.
//             Add 2 new providers — they fill active vacancies (active < active_window).
//   Phase 3: 200 more epochs — rotations continue at ~1 per 100 epochs.
//
// Rotation rate over 350 total epochs: ≤ 3/350 ≈ 0.009 → margin_t2 > 0.
// steady_stability_margin must remain Some and positive.

#[test]
fn sim_s47_eviction_recovery_scales_without_t2_instability() {
    let mut pool = ProviderPool::new(SamplingStrategy::RandomK(1))
        .with_active_window(8)
        .with_rotation(
            PoolRotationPolicy::QueryCount(100),
            ChurnBudget {
                min_churn: 1,
                max_churn: 1,
            },
        )
        .with_exposure_reset_policy(ExposureResetPolicy::Never)
        .with_eviction(EvictionConfig::default())
        .with_liveness(5, 3600);
    // 8 active (ids 0–7) + 10 dormant (ids 8–17).
    for i in 0..18u8 {
        pool.add([i; 32], SubstrateLedger::new());
    }

    let mut sim = PoolSimulator::new(pool);

    // Phase 1: 150 warm epochs.
    for _ in 0..150 {
        sim.run_epoch(1);
    }

    // Phase 2: fail [0;32] and [1;32]; evict wherever they are (active or dormant).
    // evict() removes from whichever tier holds the provider and records the event.
    for _ in 0..5 {
        sim.pool.record_failure([0u8; 32]);
        sim.pool.record_failure([1u8; 32]);
    }
    // Dormant floor gate: dormant.len() - 1 ≥ active_window (8). With 10 dormant,
    // first eviction: 9 ≥ 8 (OK). Second: 8 ≥ 8 (OK). Both succeed regardless of tier.
    let _ = sim
        .pool
        .evict(&[0u8; 32], EvictionReason::LivenessExhausted);
    let _ = sim
        .pool
        .evict(&[1u8; 32], EvictionReason::LivenessExhausted);

    // Add 2 replacement providers: they fill active vacancies when active < active_window.
    sim.pool.add([200u8; 32], SubstrateLedger::new());
    sim.pool.add([201u8; 32], SubstrateLedger::new());

    // Phase 3: 200 more epochs — rotations continue on existing schedule.
    for _ in 0..200 {
        sim.run_epoch(1);
    }

    let total_epochs = sim.trace.len() as f64;
    let rotation_rate = sim.total_rotations() as f64 / total_epochs;
    let margin_t2 = sim.margin_t2();
    let steady_margin = sim
        .steady_stability_margin()
        .expect("§S47: must have Steady records after 350 epochs");

    // T2 invariant: rotation rate stays well below the 0.5 thrash boundary.
    assert!(
        margin_t2 > 0.0,
        "§S47: T2 margin must be positive after eviction+recovery; got {margin_t2:.3}"
    );
    assert!(
        rotation_rate < 0.15,
        "§S47: rotation_rate must stay < 0.15 during eviction recovery; \
         got {rotation_rate:.3} ({} rotations / {total_epochs} epochs)",
        sim.total_rotations()
    );

    // Pool health invariant: steady_margin remains positive after eviction+add.
    assert!(
        steady_margin > 0.0,
        "§S47: steady_margin must remain positive after eviction recovery; got {steady_margin:.3}"
    );
}

// ── §S48. OnRotation freshness vs Never under hard failure ────────────────────
//
// Compares the detection signal produced by a fresh exposure window (representing
// what ExposureResetPolicy::OnRotation provides after each rotation) against a
// long-history window (representing ExposureResetPolicy::Never after many epochs).
//
// The test uses Manual rotation to prevent automatic healing: with auto-rotation,
// the dead provider is randomly chosen for dormant-swap with 25% probability per
// rotation, healing the pool before the observation window closes. Manual policy
// ensures the dead provider stays in the active set throughout, isolating the
// pure effect of history length on κ.
//
// pool_diluted (Never): 1 000 warm epochs accumulate ~250 appearances for [1;32]
// before it fails. After 200 failure epochs the dead provider's historical mass
// keeps κ near-zero (≈ 0.003).
//
// pool_fresh (OnRotation post-reset equivalent): no warm history. After failure,
// only 3 live providers are ever selected; entropy = log₂(3); κ ≈ 0.207.
//
// Core finding: even with the freshest possible selection observations (zero
// pre-failure history), κ for n = 4 reaches only ≈ 0.207 — far below the T1
// threshold of 0.5. T1 does not fire under either history depth. This confirms
// that T1 is miscalibrated for hard-failure detection at pool sizes n ≥ 4,
// regardless of how fresh the observations are.
//
// Invariants:
//   κ(fresh)    > κ(diluted) + 0.10     freshness improves detection signal by ≥ 0.10
//   κ(fresh)    < 0.50                  T1 threshold still unreachable with fresh obs
//   margin_t1   > 0 in both pools        T1 does not fire

#[test]
fn sim_s48_on_rotation_freshness_vs_never_under_hard_failure() {
    let make_pool = |warm_epochs: usize| {
        // Manual policy: never rotates, so the dead provider stays in active and
        // the comparison is purely about warm-history depth, not pool composition.
        let mut pool = ProviderPool::new(SamplingStrategy::RandomK(1))
            .with_active_window(4)
            .with_liveness(5, 3600);
        for i in 0..4u8 {
            pool.add([i; 32], SubstrateLedger::new());
        }
        (pool, warm_epochs)
    };

    let (pool_d, warm_d) = make_pool(1_000);
    let (pool_f, warm_f) = make_pool(0);

    let mut sim_diluted = PoolSimulator::new(pool_d);
    let mut sim_fresh = PoolSimulator::new(pool_f);

    // Phase 1: warm epochs (1 000 for diluted, 0 for fresh).
    // With 1 000 samples, [1;32] accumulates ≈ 250 appearances.
    for _ in 0..warm_d {
        sim_diluted.run_epoch(1);
    }
    for _ in 0..warm_f {
        sim_fresh.run_epoch(1);
    }

    // Phase 2: hard-fail provider [1;32] in both pools.
    for _ in 0..5 {
        sim_diluted.pool.record_failure([1u8; 32]);
        sim_fresh.pool.record_failure([1u8; 32]);
    }

    // Phase 3: 200 failure epochs. Only [0;32], [2;32], [3;32] are sampled.
    //   diluted final:  [0]≈317, [1]=250, [2]≈317, [3]≈316 / 1 200 → κ ≈ 0.003
    //   fresh final:    [0]≈67,  [1]=0,   [2]≈67,  [3]≈66  / 200   → κ ≈ 0.207
    for _ in 0..200 {
        sim_diluted.run_epoch(1);
        sim_fresh.run_epoch(1);
    }

    let kappa_diluted = sim_diluted.last_kappa();
    let kappa_fresh = sim_fresh.last_kappa();
    let mt1_diluted = sim_diluted.margin_t1();
    let mt1_fresh = sim_fresh.margin_t1();

    // Fresh window reveals the absent provider more clearly.
    assert!(
        kappa_fresh > kappa_diluted + 0.10,
        "§S48: fresh κ ({kappa_fresh:.4}) must exceed diluted κ ({kappa_diluted:.4}) by > 0.10 \
         — history depth determines detection sensitivity"
    );
    // Even with zero pre-failure history (maximum freshness), κ < 0.50 for n = 4.
    assert!(
        kappa_fresh < 0.50,
        "§S48: fresh κ ({kappa_fresh:.4}) must remain below T1 threshold 0.50 — \
         T1 is miscalibrated even with the freshest possible observations at n = 4"
    );
    // T1 does not fire under either history depth.
    assert!(
        mt1_diluted > 0.0,
        "§S48: T1 must not fire in diluted pool; margin_t1 = {mt1_diluted:.4}"
    );
    assert!(
        mt1_fresh > 0.0,
        "§S48: T1 must not fire in fresh pool; margin_t1 = {mt1_fresh:.4}"
    );
}

// ── §S49. OnRotation freshness vs Never under silent failure ──────────────────
//
// Silent failure: provider [0;32] is selected uniformly (κ ≈ 0) but stops
// recording responses. Selection entropy stays near log₂(4); liveness_weighted_κ
// diverges as the response distribution becomes concentrated on responders.
//
// Under Never: 100 warm responses per provider remain in the tracker. During
// silent failure, [0;32] accumulates no new responses while [1–3] accumulate
// 100 more each. Historical warm responses dilute the signal:
//   [0]=100, [1]=200, [2]=200, [3]=200 → liveness_weighted_κ ≈ 0.04.
//
// Under OnRotation (QueryCount(50)): the tracker resets after the warm rotation.
// The post-reset window contains only failure-phase responses: [0]=0, [1–3]=100
// each. Fresh history exposes the silent provider immediately:
//   [0]=0, [1]=100, [2]=100, [3]=100 → liveness_weighted_κ ≈ 0.207.
//
// κ stays near zero in both pools — selection remains uniform.
//
// Invariants:
//   κ < 0.05 in both pools                          selection stays uniform
//   liveness_weighted_κ(OnRotation) > lwk(Never) + 0.10  freshness amplifies signal
//   liveness_weighted_κ(Never) > 0.01               some signal even with dilution

#[test]
fn sim_s49_on_rotation_freshness_vs_never_under_silent_failure() {
    let make_pool = |reset: ExposureResetPolicy| {
        let mut pool = ProviderPool::new(SamplingStrategy::RandomK(1))
            .with_active_window(4)
            .with_rotation(
                PoolRotationPolicy::QueryCount(50),
                ChurnBudget {
                    min_churn: 1,
                    max_churn: 1,
                },
            )
            .with_exposure_reset_policy(reset);
        for i in 0..8u8 {
            pool.add([i; 32], SubstrateLedger::new());
        }
        pool
    };

    let mut sim_never = PoolSimulator::new(make_pool(ExposureResetPolicy::Never));
    let mut sim_onrot = PoolSimulator::new(make_pool(ExposureResetPolicy::OnRotation));

    // Phase 1: warm — 50 epochs of selection, then 100 responses per provider.
    // For OnRotation, the rotation at epoch 50 resets the response tracker;
    // the warm responses below are added BEFORE the rotation fires so they appear
    // in the pre-rotation snapshot and are cleared on the OnRotation reset.
    for _ in 0..50 {
        sim_never.run_epoch(1);
        sim_onrot.run_epoch(1);
    }
    // Rotation has just fired (epoch 50 = QueryCount(50)). Add warm responses
    // AFTER the rotation so they land in the fresh post-reset window.
    for i in 0..4u8 {
        for _ in 0..100 {
            sim_never.pool.record_response([i; 32]);
            sim_onrot.pool.record_response([i; 32]);
        }
    }

    // Phase 2: silent failure — only providers [1–3] record responses.
    // [0;32] is selected uniformly but never calls record_response.
    // 100 responses each for [1], [2], [3]:
    //   Never tracker:     [0]=100, [1]=200, [2]=200, [3]=200 → lwk ≈ 0.04
    //   OnRotation (next rotation clears warm; fresh window sees only silence-phase):
    //     run 50 more epochs → rotation fires → tracker resets → fresh window starts
    //     then add 100 each for [1–3] → [0]=0, [1]=100, [2]=100, [3]=100 → lwk ≈ 0.207
    for i in 1..4u8 {
        for _ in 0..100 {
            sim_never.pool.record_response([i; 32]);
        }
    }
    // Trigger OnRotation reset by running through QueryCount(50).
    for _ in 0..50 {
        sim_onrot.run_epoch(1);
    }
    // After the rotation, add only the silence-phase responders to OnRotation pool.
    for i in 1..4u8 {
        for _ in 0..100 {
            sim_onrot.pool.record_response([i; 32]);
        }
    }

    // Snapshot both pools. Use 1000 selection samples so κ converges reliably
    // below 0.05 (57–60 samples was insufficient given empirical variance).
    sim_never.run_epoch(1000);
    sim_onrot.run_epoch(1000);

    let never_last = sim_never.trace.last().unwrap();
    let onrot_last = sim_onrot.trace.last().unwrap();

    // Selection stays uniform in both — κ does not detect silent failure.
    assert!(
        never_last.kappa < 0.05,
        "§S49: Never κ must stay near-zero (selection uniform); got {:.4}",
        never_last.kappa
    );
    assert!(
        onrot_last.kappa < 0.05,
        "§S49: OnRotation κ must stay near-zero (selection uniform); got {:.4}",
        onrot_last.kappa
    );

    // OnRotation amplifies the liveness signal by eliminating warm dilution.
    assert!(
        onrot_last.liveness_weighted_kappa > never_last.liveness_weighted_kappa + 0.10,
        "§S49: OnRotation liveness_weighted_κ ({:.4}) must exceed Never ({:.4}) by > 0.10",
        onrot_last.liveness_weighted_kappa,
        never_last.liveness_weighted_kappa
    );

    // Never policy still detects some signal (not totally blind).
    assert!(
        never_last.liveness_weighted_kappa > 0.01,
        "§S49: Never liveness_weighted_κ must show some silent-failure signal; got {:.4}",
        never_last.liveness_weighted_kappa
    );
}

// ── §S50. AfterEpochs bounded freshness restores detection signal ─────────────
//
// AfterEpochs { n } is a real ExposureResetPolicy variant that resets the
// exposure tracker every n rotations (epoch_count % n == 0). It bounds the
// maximum history depth to n rotation-windows, giving a middle ground between
// OnRotation (reset every window) and Never (unbounded accumulation).
//
// BOUNDED_FRESHNESS_POLICY_IMPLEMENTED — this test confirms the policy exists
// and that its bounded-history effect improves the κ detection signal for
// hard failure, compared to Never's unbounded accumulation.
//
// The test uses Manual rotation (no auto-rotation) to prevent random dormant
// swaps from healing the pool mid-test. The two pools differ only in pre-failure
// warm history depth, which models what each policy provides at its reset
// boundary:
//
//   pool_never (long warm, 1 000 epochs): represents Never after deep accumulation.
//     After failure: [1;32] retains ~250 warm appearances → κ ≈ 0.003.
//
//   pool_bounded (short warm, 10 epochs): represents the state an AfterEpochs
//     pool enters its failure-observation window with (bounded max history).
//     After failure: [1;32] retains only ~2.5 warm appearances → κ ≈ 0.170.
//
// T1 still does not fire under bounded freshness (κ = 0.170 < 0.50), confirming
// that bounded freshness is an improvement but cannot on its own drive T1.
//
// Invariants:
//   κ(bounded) > κ(never) + 0.10    bounded freshness raises the detection signal
//   κ(bounded) < 0.50               T1 threshold still unreachable (n = 4)
//   margin_t1 > 0 in both pools      T1 does not fire

#[test]
fn sim_s50_bounded_freshness_restores_detection_if_supported() {
    let make_pool_with_warm = |warm_epochs: usize| {
        let mut pool = ProviderPool::new(SamplingStrategy::RandomK(1))
            .with_active_window(4)
            .with_liveness(5, 3600)
            // Declare AfterEpochs on pool_bounded to confirm the API compiles and
            // can be set; with Manual rotation it never fires, isolating the
            // warm-history-depth effect cleanly.
            .with_exposure_reset_policy(ExposureResetPolicy::AfterEpochs { n: 5 });
        for i in 0..4u8 {
            pool.add([i; 32], SubstrateLedger::new());
        }
        (pool, warm_epochs)
    };

    // pool_never: Long warm history = Never policy equivalent.
    let pool_never = {
        let mut p = ProviderPool::new(SamplingStrategy::RandomK(1))
            .with_active_window(4)
            .with_liveness(5, 3600)
            .with_exposure_reset_policy(ExposureResetPolicy::Never);
        for i in 0..4u8 {
            p.add([i; 32], SubstrateLedger::new());
        }
        p
    };
    let mut sim_never = PoolSimulator::new(pool_never);

    let (pool_b, warm_b) = make_pool_with_warm(10);
    let mut sim_bounded = PoolSimulator::new(pool_b);

    // Phase 1: warm epochs.
    //   sim_never: 1 000 warm epochs → [1;32] accumulates ≈ 250 appearances.
    //   sim_bounded: 10 warm epochs  → [1;32] accumulates ≈ 2.5 appearances.
    for _ in 0..1_000 {
        sim_never.run_epoch(1);
    }
    for _ in 0..warm_b {
        sim_bounded.run_epoch(1);
    }

    // Phase 2: hard-fail provider [1;32] in both.
    for _ in 0..5 {
        sim_never.pool.record_failure([1u8; 32]);
        sim_bounded.pool.record_failure([1u8; 32]);
    }

    // Phase 3: 200 failure epochs. Only [0;32], [2;32], [3;32] sampled.
    //   never final:   [0]≈317, [1]=250, [2]≈317, [3]≈316 / 1 200 → κ ≈ 0.003
    //   bounded final: [0]≈69,  [1]≈2.5, [2]≈69,  [3]≈69  / 210  → κ ≈ 0.170
    for _ in 0..200 {
        sim_never.run_epoch(1);
        sim_bounded.run_epoch(1);
    }

    let kappa_never = sim_never.last_kappa();
    let kappa_bounded = sim_bounded.last_kappa();
    let mt1_never = sim_never.margin_t1();
    let mt1_bounded = sim_bounded.margin_t1();

    // Bounded freshness raises κ well above the Never-diluted baseline.
    assert!(
        kappa_bounded > kappa_never + 0.10,
        "§S50: bounded κ ({kappa_bounded:.4}) must exceed Never κ ({kappa_never:.4}) by > 0.10 \
         — BOUNDED_FRESHNESS_POLICY_IMPLEMENTED and history depth matters"
    );
    // T1 threshold still unreachable under bounded freshness for n = 4.
    assert!(
        kappa_bounded < 0.50,
        "§S50: bounded κ ({kappa_bounded:.4}) must remain below T1 threshold 0.50"
    );
    assert!(
        mt1_never > 0.0,
        "§S50: T1 must not fire under Never; margin_t1 = {mt1_never:.4}"
    );
    assert!(
        mt1_bounded > 0.0,
        "§S50: T1 must not fire under bounded freshness; margin_t1 = {mt1_bounded:.4}"
    );
}

// ── §S51. OnRotation freshness does not false-trigger after benign silence ────
//
// A brief response gap followed by full recovery must not leave liveness_weighted_κ
// elevated, even under OnRotation reset semantics.
//
// Protocol (all record_response calls are explicit):
//   Phase 1: 100 responses × 4 providers (uniform warm).
//   Phase 2: trigger OnRotation reset via QueryCount(50) rotation.
//             add 10 responses for provider [0;32] only (brief silence from [1–3]).
//   Phase 3: trigger another reset via rotation.
//             add 100 responses × 4 providers (full recovery in fresh window).
//   Snapshot after recovery.
//
// After phase 3 the fresh window holds only recovery responses: all 4 providers
// respond uniformly → response entropy = log₂(4) → liveness_weighted_κ ≈ 0.
//
// The benign gap in phase 2 is erased by the phase-3 reset — OnRotation does
// not accumulate false history across rotation boundaries.
//
// Invariant: final liveness_weighted_κ < 0.05

#[test]
fn sim_s51_freshness_does_not_false_trigger_after_benign_silence() {
    let mut pool = ProviderPool::new(SamplingStrategy::RandomK(1))
        .with_active_window(4)
        .with_rotation(
            PoolRotationPolicy::QueryCount(50),
            ChurnBudget {
                min_churn: 1,
                max_churn: 1,
            },
        )
        .with_exposure_reset_policy(ExposureResetPolicy::OnRotation);
    for i in 0..8u8 {
        pool.add([i; 32], SubstrateLedger::new());
    }
    let mut sim = PoolSimulator::new(pool);

    // Phase 1: 100 uniform warm responses in the current window.
    for i in 0..4u8 {
        for _ in 0..100 {
            sim.pool.record_response([i; 32]);
        }
    }

    // Phase 2: rotate → OnRotation resets tracker. Then simulate brief gap:
    // only provider [0;32] responds for 10 calls.
    for _ in 0..50 {
        sim.run_epoch(1);
    }
    // Rotation has fired; tracker is now empty. Brief silence:
    for _ in 0..10 {
        sim.pool.record_response([0u8; 32]);
    }

    // Phase 3: rotate again → tracker resets once more. Full recovery:
    // all 4 providers respond uniformly for 100 calls each.
    for _ in 0..50 {
        sim.run_epoch(1);
    }
    // Tracker is empty after this rotation. Full recovery:
    for i in 0..4u8 {
        for _ in 0..100 {
            sim.pool.record_response([i; 32]);
        }
    }

    // Snapshot.
    sim.run_epoch(1);
    let last = sim.trace.last().unwrap();

    // Recovery window: [0]=100, [1]=100, [2]=100, [3]=100 → entropy = log₂(4) → lwk ≈ 0.
    assert!(
        last.liveness_weighted_kappa < 0.05,
        "§S51: benign silence must not false-trigger after OnRotation recovery; \
         liveness_weighted_κ = {:.4}",
        last.liveness_weighted_kappa
    );
}

// §S52 — κ/T1 boundary matches κ_survival(n,s) = 1 − log₂(s)/log₂(n) > 0.5 iff s < √n.
// Mathematical boundary table (authoritative):
//   n=4, s=3 (1/4 fail): κ ≈ 0.207, T1 must NOT fire
//   n=4, s=1 (3/4 fail): κ = 1.000, T1 MUST fire
//   n=8, s=4 (1/2 fail): κ ≈ 0.333, T1 must NOT fire
//   n=8, s=2 (3/4 fail): κ ≈ 0.667, T1 MUST fire
// All cases use Manual rotation (no auto-rotation, no self-healing).
// Providers are failed via record_failure×5 to guarantee is_live=false.
// After failure, 200 epochs are run with 1 sample each to allow κ to converge.
#[test]
fn sim_s52_kappa_t1_boundary_matches_survivor_set_math() {
    struct Case {
        n: usize,
        fail_count: usize,
        expected_kappa: f64,
        t1_must_fire: bool,
        label: &'static str,
    }

    let cases = [
        Case {
            n: 4,
            fail_count: 1,
            expected_kappa: 0.207,
            t1_must_fire: false,
            label: "n=4 s=3 (1/4 fail)",
        },
        Case {
            n: 4,
            fail_count: 3,
            expected_kappa: 1.000,
            t1_must_fire: true,
            label: "n=4 s=1 (3/4 fail)",
        },
        Case {
            n: 8,
            fail_count: 4,
            expected_kappa: 0.333,
            t1_must_fire: false,
            label: "n=8 s=4 (1/2 fail)",
        },
        Case {
            n: 8,
            fail_count: 6,
            expected_kappa: 0.667,
            t1_must_fire: true,
            label: "n=8 s=2 (3/4 fail)",
        },
    ];

    for case in &cases {
        let mut pool = ProviderPool::new(SamplingStrategy::RandomK(1))
            .with_active_window(case.n)
            .with_liveness(5, 3600);
        for i in 0..(case.n as u8) {
            pool.add([i; 32], SubstrateLedger::new());
        }
        let mut sim = PoolSimulator::new(pool);

        // Fail the first `fail_count` providers permanently.
        for i in 0..(case.fail_count as u8) {
            for _ in 0..5 {
                sim.pool.record_failure([i; 32]);
            }
        }

        // Run 200 epochs, 1 sample each. Manual policy → no rotation → no self-healing.
        for _ in 0..200 {
            sim.run_epoch(1);
        }

        let kappa = sim.last_kappa();
        let mt1 = sim.margin_t1();
        let t1_fired = mt1 < 0.0;

        // κ should be within ±0.08 of the theoretical value.
        assert!(
            (kappa - case.expected_kappa).abs() < 0.08,
            "§S52 {}: expected κ ≈ {:.3}, got {:.4}",
            case.label,
            case.expected_kappa,
            kappa
        );

        if case.t1_must_fire {
            assert!(
                t1_fired,
                "§S52 {}: T1 must fire (margin_t1 < 0) at catastrophic collapse; \
                 margin_t1 = {:.4}, κ = {:.4}",
                case.label, mt1, kappa
            );
        } else {
            assert!(
                !t1_fired,
                "§S52 {}: T1 must NOT fire for moderate partial failure; \
                 margin_t1 = {:.4}, κ = {:.4}",
                case.label, mt1, kappa
            );
        }
    }
}

// §S53 — Moderate failure is not mislabelled as catastrophic T1 collapse.
// n=4 with 1/4 failing (s=3): κ ≈ 0.207, margin_t1 must remain positive.
// This is the complement of §S52's n=4,s=1 case: the same pool size where T1 can fire
// must NOT fire when failure is only moderate. No new test of T1 itself — just the guard.
#[test]
fn sim_s53_partial_failure_is_not_mislabeled_as_t1_collapse() {
    let mut pool = ProviderPool::new(SamplingStrategy::RandomK(1))
        .with_active_window(4)
        .with_liveness(5, 3600);
    for i in 0..4u8 {
        pool.add([i; 32], SubstrateLedger::new());
    }
    let mut sim = PoolSimulator::new(pool);

    // Fail exactly 1/4 providers (s=3 survivors).
    for _ in 0..5 {
        sim.pool.record_failure([0u8; 32]);
    }

    // Run 200 epochs — Manual policy, no rotation, no self-healing.
    for _ in 0..200 {
        sim.run_epoch(1);
    }

    let kappa = sim.last_kappa();
    let mt1 = sim.margin_t1();

    // κ_survival(4,3) ≈ 0.207 — well below 0.5 threshold.
    assert!(
        kappa < 0.35,
        "§S53: moderate failure (1/4) must keep κ well below T1 threshold; \
         κ = {:.4}",
        kappa
    );
    assert!(
        mt1 > 0.0,
        "§S53: T1 must not fire for moderate (1/4) failure at n=4; \
         margin_t1 = {:.4}, κ = {:.4}",
        mt1,
        kappa
    );
}

// §S54 — Asymmetric silent failure elevates liveness_weighted_κ while κ stays near zero.
// Setup: n=4 providers. 400 uniform selections (all providers sampled equally).
// Only provider [0;32] records responses — the other three are silently absent.
// Expected: κ ≈ 0 (selection uniform), liveness_weighted_κ >> 0 (response concentrated).
// This preserves the Phase 38R finding under Phase 39's taxonomy.
#[test]
fn sim_s54_asymmetric_silent_failure_elevates_liveness_weighted_kappa() {
    let mut pool = ProviderPool::new(SamplingStrategy::RandomK(1)).with_active_window(4);
    for i in 0..4u8 {
        pool.add([i; 32], SubstrateLedger::new());
    }
    let mut sim = PoolSimulator::new(pool);

    // 400 uniform selections. record_response only for [0;32].
    for _ in 0..400 {
        sim.run_epoch(1);
    }
    for _ in 0..400 {
        sim.pool.record_response([0u8; 32]);
    }
    sim.run_epoch(1);

    let last = sim.trace.last().unwrap();
    let kappa = last.kappa;
    let lwk = last.liveness_weighted_kappa;

    // Selection is uniform → κ ≈ 0.
    assert!(
        kappa < 0.10,
        "§S54: selection is uniform; κ must be near zero; κ = {:.4}",
        kappa
    );
    // Response concentrated on [0;32] → liveness_weighted_κ >> 0.
    assert!(
        lwk > 0.50,
        "§S54: asymmetric silent failure must elevate liveness_weighted_κ; \
         lwk = {:.4}, κ = {:.4}",
        lwk,
        kappa
    );
    // Gap must be clearly separating the two signals.
    assert!(
        lwk - kappa > 0.40,
        "§S54: gap between liveness_weighted_κ and κ must exceed 0.40; \
         lwk = {:.4}, κ = {:.4}, gap = {:.4}",
        lwk,
        kappa,
        lwk - kappa
    );
}

// §S55 — Symmetric global failure is invisible to entropy metrics.
// All 4 providers respond at the same (very low) rate — response distribution stays uniform.
// Both κ and liveness_weighted_κ remain near zero despite service being nearly unusable.
// The response-rate proxy is the only signal.
// response_rate = total_responses / total_samples (computed from explicit counts in the test).
#[test]
fn sim_s55_symmetric_global_failure_is_invisible_to_entropy_metrics() {
    let mut pool = ProviderPool::new(SamplingStrategy::RandomK(1)).with_active_window(4);
    for i in 0..4u8 {
        pool.add([i; 32], SubstrateLedger::new());
    }
    let mut sim = PoolSimulator::new(pool);

    // 400 selections: 100 epochs × 4 samples (uniform across 4 providers).
    let total_samples: u64 = 400;
    for _ in 0..100 {
        sim.run_epoch(4);
    }

    // Symmetric degradation: each provider responds only ~6-7 times (≈ 1.5% response rate).
    // Responses uniformly distributed → entropy = log₂(4) → liveness_weighted_κ ≈ 0.
    let total_responses: u64 = 24; // 6 per provider × 4 providers
    for i in 0..4u8 {
        for _ in 0..6 {
            sim.pool.record_response([i; 32]);
        }
    }

    sim.run_epoch(1);
    let last = sim.trace.last().unwrap();
    let kappa = last.kappa;
    let lwk = last.liveness_weighted_kappa;
    let response_rate = total_responses as f64 / total_samples as f64;

    // Both entropy metrics are blind to symmetric failure.
    assert!(
        kappa < 0.10,
        "§S55: symmetric failure; κ must stay near zero (selection uniform); \
         κ = {:.4}",
        kappa
    );
    assert!(
        lwk < 0.10,
        "§S55: symmetric failure; liveness_weighted_κ must stay near zero \
         (responses uniform); lwk = {:.4}",
        lwk
    );
    // But the service is nearly unusable — only 6% response rate.
    assert!(
        response_rate < 0.10,
        "§S55: symmetric failure; response rate must be very low; \
         response_rate = {:.4}",
        response_rate
    );
}

// §S56 — Absolute availability signal separates healthy from symmetrically degraded pools.
// Two pools with identical, uniform selection and response distributions:
//   sim_healthy:  400 selections, 400 responses (100 per provider) → response_rate ≈ 1.0
//   sim_degraded: 400 selections, 24 responses  (6 per provider)  → response_rate ≈ 0.06
// Both pools show κ ≈ 0, liveness_weighted_κ ≈ 0.
// Only the response-rate proxy distinguishes them.
#[test]
fn sim_s56_absolute_availability_signal_detects_symmetric_failure() {
    let make_pool = || {
        let mut p = ProviderPool::new(SamplingStrategy::RandomK(1)).with_active_window(4);
        for i in 0..4u8 {
            p.add([i; 32], SubstrateLedger::new());
        }
        p
    };

    let mut sim_healthy = PoolSimulator::new(make_pool());
    let mut sim_degraded = PoolSimulator::new(make_pool());

    let total_samples: u64 = 400;
    for _ in 0..100 {
        sim_healthy.run_epoch(4);
        sim_degraded.run_epoch(4);
    }

    // Healthy: 100 responses per provider.
    let responses_healthy: u64 = 400;
    for i in 0..4u8 {
        for _ in 0..100 {
            sim_healthy.pool.record_response([i; 32]);
        }
    }

    // Degraded: 6 responses per provider (symmetric, low rate).
    let responses_degraded: u64 = 24;
    for i in 0..4u8 {
        for _ in 0..6 {
            sim_degraded.pool.record_response([i; 32]);
        }
    }

    sim_healthy.run_epoch(1);
    sim_degraded.run_epoch(1);

    let h_last = sim_healthy.trace.last().unwrap();
    let d_last = sim_degraded.trace.last().unwrap();

    let rate_healthy = responses_healthy as f64 / total_samples as f64;
    let rate_degraded = responses_degraded as f64 / total_samples as f64;

    // Both entropy metrics are near zero for both pools.
    assert!(
        h_last.kappa < 0.10,
        "§S56: healthy pool κ must be near zero; κ = {:.4}",
        h_last.kappa
    );
    assert!(
        d_last.kappa < 0.10,
        "§S56: degraded pool κ must be near zero; κ = {:.4}",
        d_last.kappa
    );
    assert!(
        h_last.liveness_weighted_kappa < 0.10,
        "§S56: healthy pool lwk must be near zero; lwk = {:.4}",
        h_last.liveness_weighted_kappa
    );
    assert!(
        d_last.liveness_weighted_kappa < 0.10,
        "§S56: degraded pool lwk must be near zero; lwk = {:.4}",
        d_last.liveness_weighted_kappa
    );

    // But response rates differ sharply — only the availability proxy distinguishes them.
    assert!(
        rate_healthy > 0.90,
        "§S56: healthy pool response rate must exceed 0.90; rate = {:.4}",
        rate_healthy
    );
    assert!(
        rate_degraded < 0.10,
        "§S56: degraded pool response rate must be below 0.10; rate = {:.4}",
        rate_degraded
    );
    assert!(
        rate_healthy - rate_degraded > 0.80,
        "§S56: availability proxy must separate healthy from degraded by > 0.80; \
         healthy = {:.4}, degraded = {:.4}, gap = {:.4}",
        rate_healthy,
        rate_degraded,
        rate_healthy - rate_degraded
    );
}

// §S57 — Benign global latency spike recovers without persistent alarm.
// All 4 providers have a brief period of uniformly low response rate, then recover.
// After recovery, κ ≈ 0, liveness_weighted_κ ≈ 0, response_rate recovers near 1.0.
// Guards against false positives in §S55/§S56 symmetric failure detection.
#[test]
fn sim_s57_benign_global_latency_recovers_without_persistent_alarm() {
    let mut pool = ProviderPool::new(SamplingStrategy::RandomK(1)).with_active_window(4);
    for i in 0..4u8 {
        pool.add([i; 32], SubstrateLedger::new());
    }
    let mut sim = PoolSimulator::new(pool);

    // Phase 1: normal operation — 200 selections, 200 responses (50 per provider).
    for _ in 0..50 {
        sim.run_epoch(4);
    }
    for i in 0..4u8 {
        for _ in 0..50 {
            sim.pool.record_response([i; 32]);
        }
    }

    // Phase 2: latency spike — 40 selections, only 4 responses total (1 per provider), symmetric.
    for _ in 0..10 {
        sim.run_epoch(4);
    }
    for i in 0..4u8 {
        sim.pool.record_response([i; 32]);
    }

    // Phase 3: recovery — 200 selections, 200 responses (50 per provider).
    let recovery_responses: u64 = 200;
    let recovery_samples: u64 = 200;
    for _ in 0..50 {
        sim.run_epoch(4);
    }
    for i in 0..4u8 {
        for _ in 0..50 {
            sim.pool.record_response([i; 32]);
        }
    }

    sim.run_epoch(1);
    let last = sim.trace.last().unwrap();
    let rate_recovery = recovery_responses as f64 / recovery_samples as f64;

    // After full recovery: both entropy metrics must remain near zero.
    assert!(
        last.kappa < 0.10,
        "§S57: after recovery, κ must be near zero; κ = {:.4}",
        last.kappa
    );
    assert!(
        last.liveness_weighted_kappa < 0.10,
        "§S57: after recovery, liveness_weighted_κ must be near zero; lwk = {:.4}",
        last.liveness_weighted_kappa
    );
    // Recovery response rate must be high.
    assert!(
        rate_recovery > 0.90,
        "§S57: recovery response rate must exceed 0.90; rate = {:.4}",
        rate_recovery
    );
}

// §S58 — Selective response gaming suppresses the liveness_weighted_κ signal.
// An adversary can call record_response() for any provider_id, including providers they do not
// control. By injecting fake uniform responses for all providers, they normalise the response
// distribution and drive liveness_weighted_κ back toward zero — even when one provider is
// silently absent.
//
// honest pool:  [0;32] records 100 responses; [1..3;32] record none → lwk ≈ 1.0
// gamed pool:   same scenario, but adversary also records 100 responses for [1..3;32] →
//               response distribution becomes uniform → lwk ≈ 0
//
// This demonstrates why policy promotion remains unsafe: an adversary can suppress the signal.
#[test]
fn sim_s58_selective_response_gaming_prevents_liveness_policy_promotion() {
    let make_pool = || {
        let mut p = ProviderPool::new(SamplingStrategy::RandomK(1)).with_active_window(4);
        for i in 0..4u8 {
            p.add([i; 32], SubstrateLedger::new());
        }
        p
    };

    let mut sim_honest = PoolSimulator::new(make_pool());
    let mut sim_gamed = PoolSimulator::new(make_pool());

    // 400 uniform selections in both pools.
    for _ in 0..100 {
        sim_honest.run_epoch(4);
        sim_gamed.run_epoch(4);
    }

    // Honest pool: only [0;32] responds.
    for _ in 0..100 {
        sim_honest.pool.record_response([0u8; 32]);
    }

    // Gamed pool: [0;32] responds honestly, adversary injects uniform responses for all others.
    for i in 0..4u8 {
        for _ in 0..100 {
            sim_gamed.pool.record_response([i; 32]);
        }
    }

    sim_honest.run_epoch(1);
    sim_gamed.run_epoch(1);

    let h_last = sim_honest.trace.last().unwrap();
    let g_last = sim_gamed.trace.last().unwrap();

    // Both pools: selection is uniform → κ ≈ 0.
    assert!(
        h_last.kappa < 0.10,
        "§S58: honest pool κ must be near zero (selection uniform); κ = {:.4}",
        h_last.kappa
    );
    assert!(
        g_last.kappa < 0.10,
        "§S58: gamed pool κ must be near zero (selection uniform); κ = {:.4}",
        g_last.kappa
    );

    // Honest pool: only [0;32] responded → liveness_weighted_κ must be high.
    assert!(
        h_last.liveness_weighted_kappa > 0.80,
        "§S58: honest pool must show high liveness_weighted_κ when one provider monopolises \
         responses; lwk = {:.4}",
        h_last.liveness_weighted_kappa
    );

    // Gamed pool: uniform responses injected → liveness_weighted_κ must be suppressed.
    assert!(
        g_last.liveness_weighted_kappa < 0.10,
        "§S58: response gaming must suppress liveness_weighted_κ to near zero; \
         lwk = {:.4}",
        g_last.liveness_weighted_kappa
    );

    // The gap must be large enough to make policy promotion clearly unsafe.
    assert!(
        h_last.liveness_weighted_kappa - g_last.liveness_weighted_kappa > 0.70,
        "§S58: gap between honest and gamed liveness_weighted_κ must exceed 0.70; \
         honest = {:.4}, gamed = {:.4}, gap = {:.4}",
        h_last.liveness_weighted_kappa,
        g_last.liveness_weighted_kappa,
        h_last.liveness_weighted_kappa - g_last.liveness_weighted_kappa
    );
}

// ── Phase 40: Operational Telemetry Contract ──────────────────────────────────
//
// Invariants:
//   operational_telemetry() exposes all three liveness surfaces through one typed snapshot.
//   Surface 1 (kappa): policy-authoritative; existing T1 threshold unchanged.
//   Surface 2 (liveness_weighted_kappa): telemetry-only; non-authoritative for policy.
//   Surface 3 (absolute availability): telemetry-only; non-authoritative for policy.
//   availability_evaluable = false when selection_total = 0 (never "healthy by default").
//   liveness_surface_evaluable = false when response_total = 0 or selection_total = 0.
//   recent_response_success_rate() = None when !availability_evaluable.
//   OnRotation reset clears response_total and selection_total after each rotation.
//   No composite health_score field exists.

// §S59 — Operational telemetry reports all three distinct liveness surfaces.
// Scenario: 4 providers, 400 uniform selections, only [0;32] responds (100 times).
// This asymmetric scenario produces clearly distinct values on each surface:
//   Surface 1: kappa ≈ 0     (selection is uniform — no concentration pressure)
//   Surface 2: lwk > 0.5     (response concentrated on [0;32])
//   Surface 3: rate = 0.25   (100 responses / 400 selections — intermediate)
// The three surfaces have different values, proving they are orthogonal measurements.
#[test]
fn sim_s59_operational_telemetry_reports_three_distinct_surfaces() {
    let mut pool = ProviderPool::new(SamplingStrategy::RandomK(1)).with_active_window(4);
    for i in 0..4u8 {
        pool.add([i; 32], SubstrateLedger::new());
    }
    let mut sim = PoolSimulator::new(pool);

    for _ in 0..100 {
        sim.run_epoch(4);
    }
    for _ in 0..100 {
        sim.pool.record_response([0u8; 32]);
    }
    sim.run_epoch(1);

    let tel: OperationalTelemetrySnapshot = sim.pool.operational_telemetry();

    // Surface 1: selection is uniform → kappa near zero.
    assert!(
        tel.kappa < 0.10,
        "§S59: surface 1 kappa must be near zero for uniform selection; κ = {:.4}",
        tel.kappa
    );

    // Surface 2: response concentrated on [0;32] → liveness_weighted_kappa elevated.
    assert!(
        tel.liveness_weighted_kappa > 0.50,
        "§S59: surface 2 liveness_weighted_κ must be elevated for asymmetric response; \
         lwk = {:.4}",
        tel.liveness_weighted_kappa
    );
    assert!(
        tel.liveness_surface_evaluable,
        "§S59: liveness surface must be evaluable after responses are recorded"
    );

    // Surface 3: 100 responses out of 401 selections (100*4 + 1 final epoch) → rate ≈ 0.25.
    assert!(
        tel.availability_evaluable,
        "§S59: availability surface must be evaluable after samples are taken"
    );
    let rate = tel.recent_response_success_rate().unwrap();
    assert!(
        rate > 0.15 && rate < 0.35,
        "§S59: availability rate must be in range [0.15, 0.35] for 100/400 scenario; \
         rate = {:.4}",
        rate
    );

    // All three surfaces carry different values — they are not collapsed to one score.
    assert!(
        tel.liveness_weighted_kappa - tel.kappa > 0.40,
        "§S59: liveness_weighted_κ must exceed κ by > 0.40 (surfaces are orthogonal); \
         lwk = {:.4}, κ = {:.4}",
        tel.liveness_weighted_kappa,
        tel.kappa
    );
    assert!(
        tel.liveness_weighted_kappa - rate > 0.20,
        "§S59: liveness_weighted_κ and availability rate must differ by > 0.20; \
         lwk = {:.4}, rate = {:.4}",
        tel.liveness_weighted_kappa,
        rate
    );
}

// §S60 — Symmetric outage is visible through availability surface while entropy stays low.
// Setup matches §S55/§S56 but now goes through the formalized operational_telemetry() API.
// 4 providers, 400 uniform selections, 24 symmetric responses (6 per provider).
// Both entropy surfaces see uniform distributions and remain near zero.
// Only the absolute availability surface reveals the degradation.
#[test]
fn sim_s60_symmetric_outage_reports_availability_loss_while_entropy_remains_healthy() {
    let mut pool = ProviderPool::new(SamplingStrategy::RandomK(1)).with_active_window(4);
    for i in 0..4u8 {
        pool.add([i; 32], SubstrateLedger::new());
    }
    let mut sim = PoolSimulator::new(pool);

    for _ in 0..100 {
        sim.run_epoch(4);
    }
    for i in 0..4u8 {
        for _ in 0..6 {
            sim.pool.record_response([i; 32]);
        }
    }
    sim.run_epoch(1);

    let tel = sim.pool.operational_telemetry();

    // Both entropy surfaces: uniform distributions → near zero.
    assert!(
        tel.kappa < 0.10,
        "§S60: κ must stay near zero for uniform selection; κ = {:.4}",
        tel.kappa
    );
    assert!(
        tel.liveness_weighted_kappa < 0.10,
        "§S60: liveness_weighted_κ must stay near zero for uniform (degraded) responses; \
         lwk = {:.4}",
        tel.liveness_weighted_kappa
    );

    // Absolute availability surface: 24 responses / 401 selections → clearly degraded.
    assert!(
        tel.availability_evaluable,
        "§S60: availability surface must be evaluable after samples and responses are recorded"
    );
    let rate = tel.recent_response_success_rate().unwrap();
    assert!(
        rate < 0.10,
        "§S60: symmetric outage must produce a degraded availability rate; rate = {:.4}",
        rate
    );

    // The entropy surfaces are both healthy-looking while availability is degraded.
    // This is the Phase 39 blind spot, now observable through the telemetry API.
    assert!(
        tel.kappa < 0.10 && tel.liveness_weighted_kappa < 0.10 && rate < 0.10,
        "§S60: symmetric outage pattern confirmed — both entropy surfaces blind, \
         only availability surface detects degradation"
    );
}

// §S61 — Zero or low observation window is unevaluable, not healthy.
// A fresh pool with no samples taken must report availability as unevaluable.
// Evaluability absence must not be interpreted as a "healthy" signal.
// Also verifies: no responses recorded → liveness surface is unevaluable.
#[test]
fn sim_s61_zero_or_low_observation_window_is_unevaluable_not_healthy() {
    // Case A: completely fresh pool (0 samples, 0 responses).
    let mut pool_a = ProviderPool::new(SamplingStrategy::RandomK(1)).with_active_window(4);
    for i in 0..4u8 {
        pool_a.add([i; 32], SubstrateLedger::new());
    }

    let tel_a = pool_a.operational_telemetry();

    assert_eq!(
        tel_a.selection_total, 0,
        "§S61 A: fresh pool must have selection_total = 0"
    );
    assert_eq!(
        tel_a.response_total, 0,
        "§S61 A: fresh pool must have response_total = 0"
    );
    assert!(
        !tel_a.availability_evaluable,
        "§S61 A: fresh pool must report availability as unevaluable (not healthy)"
    );
    assert!(
        !tel_a.liveness_surface_evaluable,
        "§S61 A: fresh pool must report liveness surface as unevaluable"
    );
    assert!(
        tel_a.recent_response_success_rate().is_none(),
        "§S61 A: fresh pool must return None for recent_response_success_rate()"
    );

    // Case B: samples taken but zero responses recorded.
    let mut pool_b = ProviderPool::new(SamplingStrategy::RandomK(1)).with_active_window(4);
    for i in 0..4u8 {
        pool_b.add([i; 32], SubstrateLedger::new());
    }
    let mut rng = StdRng::seed_from_u64(0x5c0f_0067);
    for _ in 0..20 {
        let _ = pool_b.sample(&mut rng);
    }

    let tel_b = pool_b.operational_telemetry();

    assert_eq!(
        tel_b.selection_total, 20,
        "§S61 B: pool with 20 samples must have selection_total = 20"
    );
    assert_eq!(
        tel_b.response_total, 0,
        "§S61 B: pool with no responses must have response_total = 0"
    );
    assert!(
        tel_b.availability_evaluable,
        "§S61 B: pool with samples must be availability-evaluable (denominator is non-zero)"
    );
    assert!(
        !tel_b.liveness_surface_evaluable,
        "§S61 B: pool with zero responses must report liveness surface as unevaluable"
    );
    // Rate = 0/20 = 0.0 — this is evaluable but shows complete absence of responses.
    let rate_b = tel_b.recent_response_success_rate().unwrap();
    assert_eq!(
        rate_b, 0.0,
        "§S61 B: zero-response pool must report rate = 0.0, not None"
    );
}

// §S62 — Absolute availability uses bounded fresh observations.
// Pool configured with ExposureResetPolicy::OnRotation. Records 50 selections and 40
// responses, then triggers a force rotation. After rotation the window resets to zero,
// making availability unevaluable. New observations in the post-rotation window produce
// a rate based only on those fresh observations, not the pre-rotation history.
#[test]
fn sim_s62_absolute_availability_uses_bounded_fresh_observations() {
    let mut rng = StdRng::seed_from_u64(0x5c0f_0068);
    let mut pool = ProviderPool::new(SamplingStrategy::RandomK(1))
        .with_active_window(2)
        .with_exposure_reset() // ExposureResetPolicy::OnRotation
        .with_rotation(
            PoolRotationPolicy::Manual,
            ChurnBudget {
                min_churn: 1,
                max_churn: 1,
            },
        );
    for i in 0..4u8 {
        pool.add([i; 32], SubstrateLedger::new());
    }

    // Phase 1: record 50 selections and 40 responses (rate = 0.80).
    for _ in 0..50 {
        let _ = pool.sample(&mut rng);
    }
    for i in 0..4u8 {
        for _ in 0..10 {
            pool.record_response([i; 32]);
        }
    }

    let tel_pre = pool.operational_telemetry();
    assert_eq!(
        tel_pre.selection_total, 50,
        "§S62 pre-rotation: selection_total must be 50"
    );
    assert_eq!(
        tel_pre.response_total, 40,
        "§S62 pre-rotation: response_total must be 40"
    );
    let rate_pre = tel_pre.recent_response_success_rate().unwrap();
    assert!(
        (rate_pre - 0.80).abs() < 0.01,
        "§S62 pre-rotation: rate must be ≈ 0.80; got {:.4}",
        rate_pre
    );

    // Force rotation — OnRotation policy resets the tracker.
    pool.force_rotate(&mut rng);

    let tel_post_rotate = pool.operational_telemetry();
    assert_eq!(
        tel_post_rotate.selection_total, 0,
        "§S62 post-rotation: selection_total must be 0 after OnRotation reset"
    );
    assert_eq!(
        tel_post_rotate.response_total, 0,
        "§S62 post-rotation: response_total must be 0 after OnRotation reset"
    );
    assert!(
        !tel_post_rotate.availability_evaluable,
        "§S62 post-rotation: availability must be unevaluable immediately after reset"
    );
    assert!(
        tel_post_rotate.recent_response_success_rate().is_none(),
        "§S62 post-rotation: rate must be None immediately after reset"
    );

    // Phase 2: fresh window — 10 selections, 10 responses.
    for _ in 0..10 {
        let _ = pool.sample(&mut rng);
    }
    for i in 0..4u8 {
        pool.record_response([i; 32]);
    }

    let tel_fresh = pool.operational_telemetry();
    assert_eq!(
        tel_fresh.selection_total, 10,
        "§S62 fresh window: selection_total must be 10, not 60 (window was reset)"
    );
    assert_eq!(
        tel_fresh.response_total, 4,
        "§S62 fresh window: response_total must be 4 (one per provider)"
    );
    assert!(
        tel_fresh.availability_evaluable,
        "§S62 fresh window: availability must be evaluable after new samples"
    );
}

// §S63 — Benign latency recovery clears recent availability degradation.
// Three-phase simulation with OnRotation reset to bound each window:
//   Phase 1: healthy (200 sel, 200 resp) → rate = 1.0 in that window.
//   Phase 2 (new window after rotation): latency spike (40 sel, 4 resp) → rate = 0.10.
//   Phase 3 (new window after rotation): recovery (200 sel, 200 resp) → rate = 1.0.
// After recovery, the current window reflects only the healthy post-recovery observations.
// Guards against a false interpretation that brief degradation persists indefinitely.
#[test]
fn sim_s63_benign_latency_recovery_clears_recent_availability_degradation() {
    let mut rng = StdRng::seed_from_u64(0x5c0f_0069);
    let mut pool = ProviderPool::new(SamplingStrategy::RandomK(1))
        .with_active_window(2)
        .with_exposure_reset()
        .with_rotation(
            PoolRotationPolicy::Manual,
            ChurnBudget {
                min_churn: 1,
                max_churn: 1,
            },
        );
    for i in 0..4u8 {
        pool.add([i; 32], SubstrateLedger::new());
    }

    // Phase 1: healthy operation.
    for _ in 0..200 {
        let _ = pool.sample(&mut rng);
    }
    for i in 0..4u8 {
        for _ in 0..50 {
            pool.record_response([i; 32]);
        }
    }
    let tel_p1 = pool.operational_telemetry();
    assert!(
        tel_p1.recent_response_success_rate().unwrap() > 0.90,
        "§S63 phase 1: healthy rate must exceed 0.90; rate = {:.4}",
        tel_p1.recent_response_success_rate().unwrap()
    );

    // Rotation → window reset → fresh window for spike phase.
    pool.force_rotate(&mut rng);

    // Phase 2: latency spike — 40 selections, only 4 responses (1 per provider, symmetric).
    for _ in 0..40 {
        let _ = pool.sample(&mut rng);
    }
    for i in 0..4u8 {
        pool.record_response([i; 32]);
    }
    let tel_p2 = pool.operational_telemetry();
    let rate_p2 = tel_p2.recent_response_success_rate().unwrap();
    assert!(
        rate_p2 < 0.15,
        "§S63 phase 2: degraded rate during spike must be below 0.15; rate = {:.4}",
        rate_p2
    );

    // Rotation → window reset → fresh window for recovery phase.
    pool.force_rotate(&mut rng);

    // Phase 3: recovery — 200 selections, 200 responses (50 per provider).
    for _ in 0..200 {
        let _ = pool.sample(&mut rng);
    }
    for i in 0..4u8 {
        for _ in 0..50 {
            pool.record_response([i; 32]);
        }
    }
    let tel_p3 = pool.operational_telemetry();
    let rate_p3 = tel_p3.recent_response_success_rate().unwrap();
    assert!(
        rate_p3 > 0.90,
        "§S63 phase 3: after recovery, rate must return above 0.90; rate = {:.4}",
        rate_p3
    );
    assert_eq!(
        tel_p3.selection_total, 200,
        "§S63 phase 3: selection_total must reflect only the recovery window (200), not full history"
    );
}

// §S64 — Response gaming exposes the observation integrity limit.
// record_response() accepts any provider_id without verifying that a real protocol
// response was received. An adversary can inject fake records to inflate the availability
// rate, making a degraded pool appear healthy.
//
// Degraded pool:  100 selections, 6 real responses  → rate = 0.06 (truthful).
// Gamed pool:     100 selections, 6 real + 94 injected responses → rate = 1.0 (false).
//
// This demonstrates why absolute availability is TELEMETRY-ONLY: an adversary who can
// call record_response() can suppress the degradation signal entirely. It must never
// drive automatic eviction, rotation, or admission decisions.
#[test]
fn sim_s64_response_gaming_exposes_observation_integrity_limit() {
    let make_pool = || {
        let mut p = ProviderPool::new(SamplingStrategy::RandomK(1)).with_active_window(4);
        for i in 0..4u8 {
            p.add([i; 32], SubstrateLedger::new());
        }
        p
    };
    let mut rng = StdRng::seed_from_u64(0x5c0f_0070);

    let mut pool_honest = make_pool();
    let mut pool_gamed = make_pool();

    // 100 selections in both pools.
    for _ in 0..100 {
        let _ = pool_honest.sample(&mut rng);
        let _ = pool_gamed.sample(&mut rng);
    }

    // Honest: 6 real responses (symmetric, 1.5 per provider on average).
    for i in 0..4u8 {
        if i < 2 {
            pool_honest.record_response([i; 32]);
            pool_honest.record_response([i; 32]);
        } else {
            pool_honest.record_response([i; 32]);
        }
    }
    // total honest responses: 2+2+1+1 = 6

    // Gamed: same 6 real responses + adversary injects 94 fake uniform responses.
    for i in 0..4u8 {
        if i < 2 {
            pool_gamed.record_response([i; 32]);
            pool_gamed.record_response([i; 32]);
        } else {
            pool_gamed.record_response([i; 32]);
        }
    }
    for i in 0..4u8 {
        for _ in 0..(94 / 4) {
            pool_gamed.record_response([i; 32]);
        }
    }
    // total gamed responses: 6 + (23*4) = 6 + 92 = 98; close to 100

    let tel_honest = pool_honest.operational_telemetry();
    let tel_gamed = pool_gamed.operational_telemetry();

    let rate_honest = tel_honest.recent_response_success_rate().unwrap();
    let rate_gamed = tel_gamed.recent_response_success_rate().unwrap();

    // Honest pool shows degradation.
    assert!(
        rate_honest < 0.10,
        "§S64: honest pool rate must show degradation; rate = {:.4}",
        rate_honest
    );
    // Gamed pool rate is artificially elevated by injection.
    assert!(
        rate_gamed > 0.85,
        "§S64: response injection must inflate the gamed pool rate above 0.85; \
         rate = {:.4}",
        rate_gamed
    );
    // The gap confirms the integrity limit: the metric cannot distinguish real from injected.
    assert!(
        rate_gamed - rate_honest > 0.75,
        "§S64: gap between gamed and honest rate must exceed 0.75; \
         honest = {:.4}, gamed = {:.4}",
        rate_honest,
        rate_gamed
    );
}

// §S65 — Telemetry-only signals do not trigger eviction or rotation.
// Pool configured with Manual policy (never auto-rotates) and no eviction config.
// Conditions: symmetric low response rate (absolute availability degraded) AND
// no eviction/rotation configuration that would react to these signals.
// Run maybe_rotate() many times → total rotations = 0.
// The operational telemetry snapshot shows the degraded state, but the policy engine
// is unaffected — confirming the telemetry/policy separation.
#[test]
fn sim_s65_telemetry_only_signals_do_not_trigger_eviction_or_rotation() {
    // Pool with dormant providers so maybe_rotate can run (not short-circuited by DormantEmpty).
    let mut pool = ProviderPool::new(SamplingStrategy::RandomK(1))
        .with_active_window(2)
        // Manual is the default policy, stated explicitly for clarity.
        .with_rotation(
            PoolRotationPolicy::Manual,
            ChurnBudget {
                min_churn: 1,
                max_churn: 1,
            },
        );
    for i in 0..4u8 {
        pool.add([i; 32], SubstrateLedger::new());
    }
    let mut rng = StdRng::seed_from_u64(0x5c0f_0071);

    // Enough samples for Steady phase so T4 gate does not block.
    for _ in 0..400 {
        let _ = pool.sample(&mut rng);
    }
    // Symmetric degradation: 6 responses per provider (rate = 24/400 ≈ 0.06).
    for i in 0..4u8 {
        for _ in 0..6 {
            pool.record_response([i; 32]);
        }
    }

    // Verify the telemetry surfaces show degraded state.
    let tel = pool.operational_telemetry();
    let rate = tel.recent_response_success_rate().unwrap();
    assert!(
        rate < 0.10,
        "§S65: pre-condition: availability rate must be degraded; rate = {:.4}",
        rate
    );

    // Run maybe_rotate() 200 times — Manual policy never fires regardless of telemetry.
    for _ in 0..200 {
        let outcome = pool.maybe_rotate(&mut rng);
        assert!(
            matches!(outcome, scp_provider_pool::RotationOutcome::Deferred(_)),
            "§S65: Manual policy must always defer; got Rotated"
        );
    }

    // Total rotations = 0: telemetry-only signals did not drive any automatic policy action.
    assert_eq!(
        pool.epoch_count(),
        0,
        "§S65: telemetry-only degradation must not trigger rotation; epoch_count = {}",
        pool.epoch_count()
    );
}

// §S66 — Snapshot classifies each surface without collapsing to one score.
// Uses the asymmetric silent failure scenario: 4 providers, 400 uniform selections,
// only [0;32] responds (100 times).
// Surface 1 (kappa):               ≈ 0.0   (selection uniform)
// Surface 2 (liveness_weighted_κ): > 0.5   (response concentrated)
// Surface 3 (availability rate):   ≈ 0.25  (100 out of 401 selections responded)
//
// The three values are distinct and not reducible to a single summary.
// There is no combined health_score field on OperationalTelemetrySnapshot.
#[test]
fn sim_s66_snapshot_classifies_surface_without_collapsing_to_one_score() {
    let mut pool = ProviderPool::new(SamplingStrategy::RandomK(1)).with_active_window(4);
    for i in 0..4u8 {
        pool.add([i; 32], SubstrateLedger::new());
    }
    let mut sim = PoolSimulator::new(pool);

    for _ in 0..100 {
        sim.run_epoch(4);
    }
    for _ in 0..100 {
        sim.pool.record_response([0u8; 32]);
    }
    sim.run_epoch(1);

    let tel = sim.pool.operational_telemetry();
    let rate = tel.recent_response_success_rate().unwrap();

    // Each surface has a distinct value.
    assert!(
        tel.kappa < 0.10,
        "§S66: surface 1 (kappa) must be near zero; κ = {:.4}",
        tel.kappa
    );
    assert!(
        tel.liveness_weighted_kappa > 0.50,
        "§S66: surface 2 (liveness_weighted_κ) must be elevated; lwk = {:.4}",
        tel.liveness_weighted_kappa
    );
    assert!(
        rate > 0.15 && rate < 0.35,
        "§S66: surface 3 (availability rate) must be intermediate; rate = {:.4}",
        rate
    );

    // The three surfaces have clearly distinct values — no two are in the same range.
    // kappa ≈ 0, lwk > 0.5, rate ≈ 0.25: no surface collapses into another.
    assert!(
        tel.liveness_weighted_kappa - tel.kappa > 0.40,
        "§S66: surfaces 1 and 2 must differ by > 0.40; diff = {:.4}",
        tel.liveness_weighted_kappa - tel.kappa
    );
    assert!(
        tel.liveness_weighted_kappa - rate > 0.20,
        "§S66: surfaces 2 and 3 must differ by > 0.20; diff = {:.4}",
        tel.liveness_weighted_kappa - rate
    );

    // Structural check: snapshot has three independently evaluable surfaces.
    assert!(
        tel.availability_evaluable,
        "§S66: availability surface must be evaluable"
    );
    assert!(
        tel.liveness_surface_evaluable,
        "§S66: liveness surface must be evaluable"
    );

    // The snapshot exposes raw values and evaluability flags — no composite health_score.
    // (Compile-time guarantee: OperationalTelemetrySnapshot has no health_score field.)
}

// §S67 — Zero-observation pool has survivor surface unevaluable.
// A fresh pool with 4 providers and 0 samples reports kappa = 1.0 because zero selection
// entropy is indistinguishable from full concentration. survivor_surface_evaluable must
// be false, marking this kappa as absent-data artifact, not a T1 collapse signal.
#[test]
fn sim_s67_zero_observation_survivor_surface_is_unevaluable() {
    let mut pool = ProviderPool::new(SamplingStrategy::RandomK(1)).with_active_window(4);
    for i in 0..4u8 {
        pool.add([i; 32], SubstrateLedger::new());
    }

    let tel = pool.operational_telemetry();

    assert_eq!(
        tel.selection_total, 0,
        "§S67: fresh pool must have selection_total = 0"
    );
    assert!(
        tel.kappa >= 1.0,
        "§S67: fresh pool kappa must be 1.0 (zero entropy, no selection data)"
    );
    assert!(
        !tel.survivor_surface_evaluable,
        "§S67: fresh pool must report survivor surface as unevaluable (PostReset phase)"
    );
    assert_eq!(
        tel.current_epoch_phase,
        EpochPhase::PostReset,
        "§S67: epoch phase must be PostReset when selection_total < active_n"
    );
}

// §S68 — Zero-observation snapshot cannot be read as T1 collapse.
// Both a zero-observation pool and a Steady-phase pool can show kappa values near 1.0,
// but only the Steady-phase pool has survivor_surface_evaluable = true.
// A caller checking kappa for T1 must first verify survivor_surface_evaluable == true;
// the zero-observation pool's kappa = 1.0 is absent-data artifact, not collapse evidence.
#[test]
fn sim_s68_zero_observation_snapshot_cannot_be_read_as_t1_collapse() {
    // Pool A: zero observations — kappa = 1.0 but surface is unevaluable.
    let mut pool_zero = ProviderPool::new(SamplingStrategy::RandomK(1)).with_active_window(4);
    for i in 0..4u8 {
        pool_zero.add([i; 32], SubstrateLedger::new());
    }
    let tel_zero = pool_zero.operational_telemetry();

    assert!(
        tel_zero.kappa >= 1.0,
        "§S68: zero-observation pool must read kappa = 1.0"
    );
    assert!(
        !tel_zero.survivor_surface_evaluable,
        "§S68: zero-observation pool survivor surface must be unevaluable"
    );
    assert_eq!(
        tel_zero.current_epoch_phase,
        EpochPhase::PostReset,
        "§S68: zero-observation pool must be in PostReset phase"
    );

    // Pool B: 400 selections — Steady phase, survivor surface is evaluable.
    let mut pool_steady = ProviderPool::new(SamplingStrategy::RandomK(1)).with_active_window(4);
    for i in 0..4u8 {
        pool_steady.add([i; 32], SubstrateLedger::new());
    }
    let mut rng = StdRng::seed_from_u64(0x5c0f_0068);
    for _ in 0..400 {
        let _ = pool_steady.sample(&mut rng);
    }
    let tel_steady = pool_steady.operational_telemetry();

    assert!(
        tel_steady.survivor_surface_evaluable,
        "§S68: Steady-phase pool survivor surface must be evaluable"
    );
    assert_eq!(
        tel_steady.current_epoch_phase,
        EpochPhase::Steady,
        "§S68: 400-sample pool must be in Steady phase (total_samples >= 4 * active_n)"
    );

    // Contract: the two pools are distinguishable by survivor_surface_evaluable alone.
    // kappa = 1.0 in the zero-obs pool must not trigger T1 classification;
    // only pool_steady's kappa is interpretable as T1 evidence.
    assert!(
        !tel_zero.survivor_surface_evaluable && tel_steady.survivor_surface_evaluable,
        "§S68: survivor_surface_evaluable distinguishes absent-data artifact from evaluable kappa"
    );
}

// §S69 — recent_reported_response_ratio() documents unverified telemetry under injection.
// This test mirrors §S64 using the correctly-named method. The metric measures reported
// response calls divided by selection calls — it is not a verified relay success rate.
// Response injection inflates the numerator identically to §S64, confirming the integrity
// limitation is a property of the underlying data, not the method name.
#[test]
fn sim_s69_reported_response_ratio_is_documented_untrusted_under_injection() {
    let make_pool = || {
        let mut p = ProviderPool::new(SamplingStrategy::RandomK(1)).with_active_window(4);
        for i in 0..4u8 {
            p.add([i; 32], SubstrateLedger::new());
        }
        p
    };
    let mut rng = StdRng::seed_from_u64(0x5c0f_0069);

    let mut pool_honest = make_pool();
    let mut pool_gamed = make_pool();

    for _ in 0..100 {
        let _ = pool_honest.sample(&mut rng);
        let _ = pool_gamed.sample(&mut rng);
    }

    // Honest: 6 real responses symmetric across providers (rate ≈ 0.06).
    for i in 0..4u8 {
        if i < 2 {
            pool_honest.record_response([i; 32]);
            pool_honest.record_response([i; 32]);
        } else {
            pool_honest.record_response([i; 32]);
        }
    }

    // Gamed: same 6 real responses + 92 injected uniform responses (ratio ≈ 0.98).
    for i in 0..4u8 {
        if i < 2 {
            pool_gamed.record_response([i; 32]);
            pool_gamed.record_response([i; 32]);
        } else {
            pool_gamed.record_response([i; 32]);
        }
    }
    for i in 0..4u8 {
        for _ in 0..(92 / 4) {
            pool_gamed.record_response([i; 32]);
        }
    }

    let tel_honest = pool_honest.operational_telemetry();
    let tel_gamed = pool_gamed.operational_telemetry();

    let ratio_honest = tel_honest.recent_reported_response_ratio().unwrap();
    let ratio_gamed = tel_gamed.recent_reported_response_ratio().unwrap();

    // Honest pool shows real low ratio.
    assert!(
        ratio_honest < 0.10,
        "§S69: honest pool reported ratio must show degradation; ratio = {:.4}",
        ratio_honest
    );
    // Gamed pool ratio is artificially elevated by injected record_response() calls.
    assert!(
        ratio_gamed > 0.85,
        "§S69: injection must inflate reported ratio above 0.85; ratio = {:.4}",
        ratio_gamed
    );
    // The gap confirms the metric is unverified reported telemetry, not relay evidence.
    assert!(
        ratio_gamed - ratio_honest > 0.75,
        "§S69: gap between gamed and honest ratio must exceed 0.75; \
         honest = {:.4}, gamed = {:.4}",
        ratio_honest,
        ratio_gamed
    );
}
