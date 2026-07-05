// Trial 2 — Provider-Failure Observability Proof
//
// Permitted claim (after verification):
//   Under deterministic scripted provider-failure scenarios, SCP's existing
//   OperationalTelemetrySnapshot surfaces expose the expected degradation signals
//   without automatically changing corridor vitality, send authorization,
//   rotation policy, or relay behavior.
//
// Telemetry field names confirmed from provider/pool/src/metrics.rs:
//
//   Surface 1 — Survivor concentration:
//     kappa                      κ(t): selection entropy deficit [0,1]
//     survivor_surface_evaluable true when total_samples >= active_n
//
//   Surface 2 — Relative liveness distortion:
//     liveness_weighted_kappa    κ_L(t): response entropy deficit [0,1]
//     liveness_surface_evaluable true when response_total > 0 AND selection_total > 0
//
//   Surface 3 — Absolute availability:
//     response_total             total record_response() calls in window
//     selection_total            total sample() calls in window
//     availability_evaluable     true when selection_total > 0
//     recent_reported_response_ratio()  response_total / selection_total, or None
//
// All tests use fixed scripted observation sequences: either seeded deterministic
// RNG or direct record_response() / record_failure() calls with exact counts.
// No test infers authorization, rotation, or policy meaning from a numeric change.
//
// Explicit non-claims:
//   - degraded telemetry triggers any policy action
//   - liveness_weighted_kappa is safe for automatic routing or rotation decisions
//   - provider failure modifies SimVitalityEvaluationContext.p
//   - provider failure suspends a corridor
//   - transport behavior during provider degradation
//   - relay, localhost, LAN, desktop, or hardware readiness

use rand::rngs::StdRng;
use rand::SeedableRng;

use scp_ledger_substrate::SubstrateLedger;
use scp_provider_pool::{EpochPhase, ProviderPool, SamplingStrategy};
use scp_vitality::{VitalityEvidenceStore, VitalityState};

// ── Helpers ────────────────────────────────────────────────────────────────────

fn pid(byte: u8) -> [u8; 32] {
    [byte; 32]
}

/// Deterministic RNG with a fixed seed. Produces the same selection trace on
/// every test run — no statistical convergence, no RNG-dependent assertions.
fn seeded() -> StdRng {
    StdRng::seed_from_u64(0)
}

// ── T1: Healthy baseline ───────────────────────────────────────────────────────
//
// 4 providers, 16 samples (→ Steady phase: 16 ≥ 4 × active_n), 4 responses per
// provider. All three surfaces are evaluable. Exact assertions:
//
//   Surface 2: uniform 4-provider response distribution →
//     response_entropy = −4 × (0.25 × log₂(0.25)) = 2.0 bits
//     liveness_weighted_kappa = 1 − 2.0 / log₂(4) = 0.0
//
//   Surface 3: response_total = 16, selection_total = 16
//     recent_reported_response_ratio() = Some(1.0)
//
//   Surface 1: kappa derived from exact selection trace via exposure_estimate().
//              No range-only assertion; computed from the same observation seam.

#[test]
fn t1_healthy_baseline_snapshot_fields_are_exact() {
    let mut rng = seeded();
    let mut pool = ProviderPool::new(SamplingStrategy::RandomK(1));
    for i in 1u8..=4 {
        pool.add(pid(i), SubstrateLedger::new());
    }

    // Fixed selection trace: 16 samples, seeded RNG → deterministic appearances.
    for _ in 0..16 {
        let _ = pool.sample(&mut rng);
    }

    // Fixed response trace: 4 responses per provider = uniform distribution.
    for i in 1u8..=4 {
        for _ in 0..4 {
            pool.record_response(pid(i));
        }
    }

    let snap = pool.operational_telemetry();

    // — Evidence context ——————————————————————————————————————————————————
    assert_eq!(snap.active_n, 4);
    assert_eq!(
        snap.current_epoch_phase,
        EpochPhase::Steady, // 16 ≥ 4 × 4
        "16 samples with 4 active providers must reach Steady phase"
    );

    // — Surface 1: evaluability ———————————————————————————————————————————
    assert!(
        snap.survivor_surface_evaluable,
        "16 samples ≥ active_n=4 → epoch_phase ≠ PostReset → evaluable"
    );

    // — Surface 1: kappa derived from exact trace ————————————————————————
    let est = pool.exposure_estimate();
    let expected_kappa = (1.0 - est.selection_entropy_bits / (4_f64).log2()).clamp(0.0, 1.0);
    assert!(
        (snap.kappa - expected_kappa).abs() < 1e-12,
        "kappa must match value derived from seeded selection trace (entropy={:.4} bits)",
        est.selection_entropy_bits
    );

    // — Surface 2 ————————————————————————————————————————————————————————
    assert!(
        snap.liveness_surface_evaluable,
        "response_total > 0 AND selection_total > 0 → liveness surface evaluable"
    );

    // Exact: −4 × (4/16 × log₂(4/16)) = 2.0 bits → lwk = 1 − 2.0/2.0 = 0.0
    assert_eq!(
        snap.liveness_weighted_kappa, 0.0,
        "4 equal responses across 4 providers → response entropy = log₂(4) → lwk = 0.0"
    );

    // — Surface 3 ————————————————————————————————————————————————————————
    assert_eq!(snap.selection_total, 16);
    assert_eq!(snap.response_total, 16);
    assert!(snap.availability_evaluable);
    assert_eq!(
        snap.recent_reported_response_ratio(),
        Some(1.0),
        "16 responses / 16 selections = 1.0"
    );
}

// ── T2: Explicit failure concentrates selection surface ────────────────────────
//
// record_failure() is the explicit failure seam. With max_consecutive_failures=2,
// two calls to record_failure(pid(2)) render it dead, excluding it from future
// sample() calls. Subsequent samples are deterministically single-provider.
//
// With only pid(1) appearing in selections (entropy = 0 bits) and only pid(1)
// responding (response entropy = 0 bits), both kappa and liveness_weighted_kappa
// are exactly 1.0 — the maximum degradation signal for 2 active providers.
//
// Exact derivations (n = 2 active):
//   appearances  = {pid(1): 4, pid(2): 0}  →  selection_entropy = 0 bits
//   kappa        = 1 − 0 / log₂(2) = 1.0
//   responses    = {pid(1): 4}              →  response_entropy  = 0 bits
//   lwk          = 1 − 0 / log₂(2) = 1.0

#[test]
fn t2_explicit_failure_concentrates_selection_surface() {
    let mut rng = seeded();
    let mut pool = ProviderPool::new(SamplingStrategy::RandomK(1)).with_liveness(2, u64::MAX); // dead when consecutive_failures ≥ 2
    pool.add(pid(1), SubstrateLedger::new()); // healthy
    pool.add(pid(2), SubstrateLedger::new()); // will fail

    // Explicit failure: 2 calls → consecutive_failures = 2 → is_live = (2 < 2) = false.
    pool.record_failure(pid(2));
    pool.record_failure(pid(2));

    // Fixed selection trace: 4 samples — pid(2) filtered → only pid(1) selected.
    for _ in 0..4 {
        let _ = pool.sample(&mut rng);
    }

    // Fixed response trace: pid(1) responds each time, pid(2) is silent.
    for _ in 0..4 {
        pool.record_response(pid(1));
    }

    let snap = pool.operational_telemetry();

    // — Evidence context ———————————————————————————————————————————————————
    assert_eq!(
        snap.active_n, 2,
        "both providers remain in pool; dead provider is filtered from sample, not removed"
    );

    // — Surface 1: exact concentration ————————————————————————————————————
    assert!(
        snap.survivor_surface_evaluable,
        "4 samples ≥ active_n=2 → epoch_phase ≠ PostReset"
    );
    assert_eq!(
        snap.kappa, 1.0,
        "dead pid(2) excluded → only pid(1) in selections → entropy=0 → kappa=1.0"
    );

    // — Surface 2: exact concentration ————————————————————————————————————
    assert!(snap.liveness_surface_evaluable);
    assert_eq!(
        snap.liveness_weighted_kappa, 1.0,
        "only pid(1) responded → response_entropy=0 → liveness_weighted_kappa=1.0"
    );

    // — Surface 3 ————————————————————————————————————————————————————————
    assert_eq!(snap.selection_total, 4);
    assert_eq!(snap.response_total, 4);
    assert_eq!(snap.recent_reported_response_ratio(), Some(1.0));
}

// ── T3: Silent failure distinguishes liveness surface from selection surface ───
//
// "Silent failure" = provider selected by sample() but never calls record_response().
// This creates a detectable divergence between the selection distribution (Surface 1)
// and the response distribution (Surface 2).
//
// pid(2) is in the active pool and may be selected, but record_response() is only
// ever called for pid(1). With only pid(1) in the response distribution:
//
//   response_entropy = −(1.0 × log₂(1.0)) = 0 bits
//   liveness_weighted_kappa = 1 − 0 / log₂(2) = 1.0   (exact)
//
// Selection kappa is derived from the actual seeded trace via exposure_estimate().
//
// Key invariant: liveness_weighted_kappa ≥ kappa
//   because response_entropy (0 bits) ≤ selection_entropy (≥ 0 bits).
// When pid(2) is selected at least once (selection_entropy > 0):
//   liveness_weighted_kappa (1.0) > kappa (< 1.0) — the distinction is explicit.

#[test]
fn t3_silent_failure_distinguishes_liveness_from_selection_surface() {
    let mut rng = seeded();
    let mut pool = ProviderPool::new(SamplingStrategy::RandomK(1));
    pool.add(pid(1), SubstrateLedger::new());
    pool.add(pid(2), SubstrateLedger::new()); // selected but will never respond

    // Fixed selection trace: 8 samples with seeded RNG (deterministic).
    for _ in 0..8 {
        let _ = pool.sample(&mut rng);
    }

    // Fixed response trace: only pid(1) responds — pid(2) is silently absent.
    for _ in 0..8 {
        pool.record_response(pid(1));
    }

    let snap = pool.operational_telemetry();
    let est = pool.exposure_estimate();

    // — Surface 2: exact ———————————————————————————————————————————————————
    assert_eq!(
        snap.liveness_weighted_kappa, 1.0,
        "only pid(1) in responses → response_entropy=0 bits → liveness_weighted_kappa=1.0"
    );
    assert!(
        snap.liveness_surface_evaluable,
        "response_total=8 > 0 AND selection_total=8 > 0 → liveness surface evaluable"
    );

    // — Surface 3 ————————————————————————————————————————————————————————
    assert_eq!(snap.selection_total, 8);
    assert_eq!(snap.response_total, 8);

    // — Surface 1: kappa derived from actual seeded trace ————————————————
    let expected_kappa = (1.0 - est.selection_entropy_bits / (2_f64).log2()).clamp(0.0, 1.0);
    assert!(
        (snap.kappa - expected_kappa).abs() < 1e-12,
        "kappa must match value derived from seeded selection trace"
    );

    // — Silent-failure distinction ————————————————————————————————————————
    // response_entropy (0) ≤ selection_entropy (≥ 0) → lwk ≥ kappa always.
    assert!(
        snap.liveness_weighted_kappa >= snap.kappa,
        "liveness_weighted_kappa ({:.4}) must be ≥ kappa ({:.4}): \
         response entropy cannot exceed selection entropy when only a subset responds",
        snap.liveness_weighted_kappa,
        snap.kappa
    );

    // If pid(2) was selected at least once, selection entropy > 0 → kappa < 1.0
    // and the distinction is strict (lwk > kappa).
    if est.selection_entropy_bits > 0.0 {
        assert!(
            snap.liveness_weighted_kappa > snap.kappa,
            "pid(2) selected but silent → liveness surface (lwk=1.0) rises above \
             selection surface (kappa={:.4} < 1.0): silent-failure distinction is observable",
            snap.kappa
        );
    }
}

// ── T4: Partial degradation shows intermediate liveness_weighted_kappa ─────────
//
// Half the active providers respond; the other half are silent. The response
// distribution is partially concentrated, yielding an intermediate lwk.
//
// 4 providers: pid(1) and pid(2) respond 4 times each; pid(3) and pid(4) are silent.
//
// Exact derivation (n = 4 active):
//   response_appearances = {pid(1): 4, pid(2): 4}   total = 8
//   response_entropy = −2 × (0.5 × log₂(0.5)) = 1.0 bit
//   liveness_weighted_kappa = 1 − 1.0 / log₂(4) = 1 − 0.5 = 0.5
//
// This value sits strictly between T1 (lwk=0.0, all healthy) and
// T2/T3 (lwk=1.0, fully concentrated) — the partial-degradation gradient.

#[test]
fn t4_partial_degradation_shows_intermediate_liveness_kappa() {
    let mut rng = seeded();
    let mut pool = ProviderPool::new(SamplingStrategy::RandomK(1));
    for i in 1u8..=4 {
        pool.add(pid(i), SubstrateLedger::new());
    }

    // Fixed selection trace: 16 samples → Steady phase.
    for _ in 0..16 {
        let _ = pool.sample(&mut rng);
    }

    // Fixed response trace: only pid(1) and pid(2) respond, 4 times each.
    for _ in 0..4 {
        pool.record_response(pid(1));
    }
    for _ in 0..4 {
        pool.record_response(pid(2));
    }
    // pid(3) and pid(4) are silent.

    let snap = pool.operational_telemetry();

    // — Evidence context ————————————————————————————————————————————————————
    assert_eq!(snap.active_n, 4);
    assert!(snap.liveness_surface_evaluable);
    assert!(snap.availability_evaluable);

    // — Surface 2: exact intermediate value ————————————————————————————————
    // −2 × (4/8 × log₂(4/8)) = −2 × (0.5 × (−1)) = 1.0 bit; 1 − 1.0/2.0 = 0.5
    assert_eq!(
        snap.liveness_weighted_kappa, 0.5,
        "2 of 4 providers responding uniformly → response_entropy=1.0 bit → lwk=0.5"
    );

    // — Surface 3 ————————————————————————————————————————————————————————
    assert_eq!(
        snap.response_total, 8,
        "4 + 4 responses, pid(3) and pid(4) are silent"
    );
    assert_eq!(snap.selection_total, 16);
}

// ── T5: Recovery via record_response() resets failure state ────────────────────
//
// Recovery semantics: record_response() resets consecutive_failures to 0,
// restoring a dead provider to live status. The effect is directly observable
// through the response surface.
//
// Phase 1 (before recovery):
//   pid(2) dead → only pid(1) responds → response_entropy=0 → lwk=1.0 (exact)
//
// Phase 2 (after recovery — record_response(pid(2)) called 4 times):
//   response_appearances = {pid(1): 4, pid(2): 4}
//   response_entropy = 1.0 bit → lwk = 1 − 1.0/log₂(2) = 0.0 (exact)
//
// The shift 1.0 → 0.0 proves that recovery is modeled and observable
// through the liveness surface without requiring a policy decision.

#[test]
fn t5_recovery_via_record_response_resets_failure_state() {
    let mut rng = seeded();
    let mut pool = ProviderPool::new(SamplingStrategy::RandomK(1)).with_liveness(2, u64::MAX);
    pool.add(pid(1), SubstrateLedger::new()); // always healthy
    pool.add(pid(2), SubstrateLedger::new()); // fails, then recovers

    // Phase 1: make pid(2) dead.
    pool.record_failure(pid(2));
    pool.record_failure(pid(2)); // consecutive_failures=2 → NOT live

    // Fixed selection + response trace before recovery.
    for _ in 0..4 {
        let _ = pool.sample(&mut rng);
    } // only pid(1) selected
    for _ in 0..4 {
        pool.record_response(pid(1));
    }

    let pre_snap = pool.operational_telemetry();
    // response_appearances = {pid(1): 4}, response_entropy = 0 bits, lwk = 1.0
    assert_eq!(
        pre_snap.liveness_weighted_kappa, 1.0,
        "pre-recovery: only pid(1) responded → response_entropy=0 → lwk=1.0"
    );

    // Phase 2: recovery — each record_response() call resets consecutive_failures=0.
    // After the first call, pid(2) is live again; subsequent calls build response history.
    for _ in 0..4 {
        pool.record_response(pid(2));
    }

    let post_snap = pool.operational_telemetry();
    // response_appearances = {pid(1): 4, pid(2): 4}, total=8
    // response_entropy = −2 × (0.5 × log₂(0.5)) = 1.0 bit
    // lwk = 1 − 1.0 / log₂(2) = 1 − 1.0 = 0.0
    assert_eq!(
        post_snap.liveness_weighted_kappa, 0.0,
        "post-recovery: equal responses → response_entropy=log₂(2) → lwk=0.0"
    );
    assert_eq!(
        post_snap.response_total, 8,
        "4 (phase-1) + 4 (phase-2) = 8 total responses"
    );
    assert!(post_snap.liveness_surface_evaluable);
}

// ── T6: Provider isolation — failure must not corrupt sibling telemetry ─────────
//
// record_failure() is scoped to the named provider's liveness state only.
// It must not inject phantom entries into any other provider's observation record.
//
// Trace: 4 providers, 4 samples.
//   record_failure × 5 for pid(3) and pid(4) respectively.
//   record_response × 4 for pid(1) and pid(2).
//
// Exact isolation assertion: response_total = 8.
//   If failures leaked into the response tracker, response_total would exceed 8.
//
// Exact lwk derivation (n = 4 active):
//   response_appearances = {pid(1): 4, pid(2): 4}   total = 8
//   response_entropy = 1.0 bit → lwk = 1 − 1.0/log₂(4) = 0.5

#[test]
fn t6_provider_isolation_failure_does_not_corrupt_sibling_telemetry() {
    let mut rng = seeded();
    let mut pool = ProviderPool::new(SamplingStrategy::RandomK(1));
    for i in 1u8..=4 {
        pool.add(pid(i), SubstrateLedger::new());
    }

    // Fixed selection trace for evaluability.
    for _ in 0..4 {
        let _ = pool.sample(&mut rng);
    }

    // pid(1) and pid(2) respond uniformly.
    for _ in 0..4 {
        pool.record_response(pid(1));
    }
    for _ in 0..4 {
        pool.record_response(pid(2));
    }

    // pid(3) and pid(4) explicitly fail — these must not affect sibling response tracking.
    for _ in 0..5 {
        pool.record_failure(pid(3));
    }
    for _ in 0..5 {
        pool.record_failure(pid(4));
    }

    let snap = pool.operational_telemetry();

    // — Isolation: response_total must be exactly 8 ———————————————————————
    assert_eq!(
        snap.response_total, 8,
        "10 record_failure() calls for pid(3)/pid(4) must not create phantom responses; \
         response_total must remain exactly 8"
    );

    // — Exact lwk: 2-provider uniform response out of 4 active ————————————
    // −2 × (4/8 × log₂(4/8)) = 1.0 bit; 1 − 1.0/log₂(4) = 0.5
    assert_eq!(
        snap.liveness_weighted_kappa, 0.5,
        "pid(1)+pid(2) respond equally → response_entropy=1.0 bit → lwk=0.5 \
         (failures for pid(3)/pid(4) must not alter this value)"
    );

    assert_eq!(snap.active_n, 4);
    assert!(snap.liveness_surface_evaluable);
}

// ── T7: Observability must not couple to vitality or send authorization ─────────
//
// OperationalTelemetrySnapshot is constructed by reading from the ExposureTracker
// inside ProviderPool. It shares no state with VitalityEvidenceStore, FlashSession,
// RotationOutcome, or any relay surface.
//
// Structural boundary: scp-provider-pool does not depend on scp-vitality, and
// VitalityEvidenceStore does not hold a reference to ProviderPool or ExposureTracker.
//
// Runtime proof: driving pool telemetry observations (sample, record_response,
// record_failure, operational_telemetry) must not alter VitalityEvidenceStore state
// or trigger pool rotation.
//
// Initial vitality: initialized at t=0 → Active at t=1_000 (well within threshold).
// Assertion: state at t=1_000 is unchanged after all pool telemetry operations.

#[test]
fn t7_telemetry_observation_does_not_couple_to_vitality_or_send() {
    // — Vitality baseline ——————————————————————————————————————————————————
    let consent_hash = [7u8; 32]; // arbitrary distinct value
    let mut store = VitalityEvidenceStore::new();
    store.initialize_at(consent_hash, 0);

    let state_before = store.compute_state(consent_hash, 1_000, 1.0, 1.0, 0.0);
    assert_eq!(
        state_before,
        VitalityState::Active,
        "precondition: consent_hash initialized at t=0 must be Active at t=1_000"
    );

    // — Drive pool telemetry ———————————————————————————————————————————————
    let mut rng = seeded();
    let mut pool = ProviderPool::new(SamplingStrategy::RandomK(1));
    for i in 1u8..=4 {
        pool.add(pid(i), SubstrateLedger::new());
    }

    for _ in 0..16 {
        let _ = pool.sample(&mut rng);
    }
    for i in 1u8..=4 {
        for _ in 0..4 {
            pool.record_response(pid(i));
        }
    }
    for _ in 0..3 {
        pool.record_failure(pid(1));
    }
    let _snap = pool.operational_telemetry(); // observation under test

    // — Vitality state must be unchanged ———————————————————————————————————
    let state_after = store.compute_state(consent_hash, 1_000, 1.0, 1.0, 0.0);
    assert_eq!(
        state_after,
        VitalityState::Active,
        "driving pool telemetry must not alter VitalityEvidenceStore state"
    );

    // — Pool must not have auto-rotated during telemetry observation —————————
    // operational_telemetry() is a read-only snapshot; it must not invoke maybe_rotate().
    assert_eq!(
        pool.epoch_count(),
        0,
        "operational_telemetry() must not trigger rotation: epoch_count must remain 0"
    );
}
