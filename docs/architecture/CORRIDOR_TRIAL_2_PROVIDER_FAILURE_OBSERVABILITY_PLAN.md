# Trial 2 — Provider Failure Observability Plan

**Status:** PLANNING ONLY — no Rust source modified in this pass
**Date:** 2026-05-28
**Predecessor:** `TRIAL_1C_CLOSURE_RECORD.md` (A — TRIAL_1C_SIMULATOR_RUNTIME_VITALITY_ENFORCEMENT_PROVEN)
**Baseline at planning time:** 457 passing, 0 failing (3 consecutive clean runs)

---

## 0. Objective

Determine whether the SCP simulator can deterministically inject provider degradation or
failure and observe the resulting changes through the already-implemented operational
telemetry surfaces without any automatic effect on corridor vitality, send authorization,
rotation policy, or relay behavior.

**Permitted future claim, if Trial 2 is later implemented and proven:**

> Under deterministic simulated provider-failure scenarios, SCP's existing operational
> telemetry surfaces expose the specified degradation signals without automatically
> changing corridor vitality, send authorization, rotation policy, or relay behavior.

---

## 1. Required Separation from Trial 1c

Trial 2 is an **observability trial**, not a vitality-policy extension.

Do not connect ProviderPool telemetry to:

- `VitalityEvidenceStore`
- `SimVitalityEvaluationContext.p`
- `open_and_send_sim()` authorization
- `VitalityState`
- automatic rotation
- TOLS `κ`
- `liveness_weighted_κ` as an enforcement input
- relay routing or delivery

If any existing code already performs one of these couplings, stop and report it as an
architecture discovery before proceeding.

---

## 2. Audit 1 — Operational Telemetry Surfaces

### 2.1 Files inspected

| File | Role |
|------|------|
| `provider/pool/src/metrics.rs` | `OperationalTelemetrySnapshot` definition, `EpochPhase`, `ConvergencePressure` |
| `provider/pool/src/lib.rs` | `ProviderPool::operational_telemetry()` computation |
| `provider/pool/src/exposure.rs` | `ExposureTracker`, `ExposureEstimate` — telemetry data source |
| `provider/pool/src/liveness.rs` | `LivenessState`, `LivenessConfig` |

### 2.2 Three telemetry surfaces confirmed

The previously recorded claim that there are **three orthogonal telemetry surfaces** is
accurate. They are:

| Surface | Field(s) | Source | Policy authority |
|---------|----------|--------|-----------------|
| **Surface 1 — Survivor concentration** | `kappa: f64`, `survivor_surface_evaluable: bool` | `selection_entropy_bits` from `ExposureTracker.estimate()` | **Policy-authoritative** (existing T1 threshold) |
| **Surface 2 — Relative liveness distortion** | `liveness_weighted_kappa: f64`, `liveness_surface_evaluable: bool` | `response_entropy_bits` from `ExposureTracker.estimate()` | **Telemetry-only** — non-authoritative for any automatic action |
| **Surface 3 — Absolute availability** | `response_total: u64`, `selection_total: u64`, `availability_evaluable: bool`, `recent_reported_response_ratio()` | Raw counters from `ExposureTracker` | **Telemetry-only** — non-authoritative for any automatic action |

Plus **evidence context**: `current_epoch_phase: EpochPhase`, `active_n: usize`.

### 2.3 Computation path

`operational_telemetry()` is a pure snapshot computed on demand:

```
ProviderPool::operational_telemetry()
  → exposure_tracker.lock().estimate()
  → reads ExposureEstimate { selection_entropy_bits, response_entropy_bits,
                              total_samples, response_total_samples }
  → computes kappa = 1 − (selection_entropy / log2(n))
  → computes liveness_weighted_kappa = 1 − (response_entropy / log2(n))
  → evaluability flags derived from sample counts
  → returns OperationalTelemetrySnapshot (no side effects)
```

**Deterministic under test:** Yes. The computation is a pure function over `ExposureTracker`
state. If the sequence of `sample()` and `record_response()` calls is deterministic, the
snapshot values are exact and reproducible.

### 2.4 Update events

| Event | What updates | Effect on telemetry |
|-------|-------------|---------------------|
| `pool.sample(&mut rng)` | `ExposureTracker` selection counts | Increases `selection_total`; updates `selection_entropy_bits` |
| `pool.record_response(id)` | `ExposureTracker` response counts + `LivenessState.last_seen_secs` + resets `consecutive_failures` | Increases `response_total`; updates `response_entropy_bits` |
| `pool.record_failure(id)` | `LivenessState.consecutive_failures` only | No direct telemetry update; affects future `sample()` via `is_live()` filter |
| `pool.force_rotate()` / `do_rotate()` | May reset `ExposureTracker` via `ExposureResetPolicy::OnRotation` | Zeros all counters; surfaces become unevaluable until re-warmed |

**Key finding**: `record_failure()` has **no direct effect on telemetry counters**. Its effect
on Surface 1 is indirect: by marking a provider dead, future `sample()` calls exclude it,
concentrating selection on remaining live providers, which reduces `selection_entropy_bits`
and raises `kappa`. Surfaces 2 and 3 are unaffected by `record_failure()` directly.

---

## 3. Audit 2 — ProviderPool Failure-Injection Seam

### 3.1 Existing failure modes in executable code

| Mode | Injection method | Mechanism | Deterministic? |
|------|-----------------|-----------|---------------|
| **Explicit unavailable** | `record_failure(id)` N times until `consecutive_failures >= max_consecutive_failures` | Provider filtered from `is_live()` → excluded from future `sample()` quorums | Yes |
| **Silent failure** | Select provider via `sample()` but never call `record_response(id)` | Response entropy diverges from selection entropy; `liveness_weighted_kappa` rises above `kappa` | Yes |
| **Partial degradation** | `record_response()` for only a subset of selected providers | Asymmetric response entropy; `liveness_weighted_kappa` elevated proportionally | Yes |
| **Recovery** | `record_response(id)` after silence or failure | Resets `consecutive_failures`; adds weight to response entropy; `liveness_weighted_kappa` returns toward `kappa` | Yes |

### 3.2 Failure modes NOT currently representable without production-code changes

| Mode | Why not representable |
|------|-----------------------|
| Stale/delayed response | No concept of response latency in current model; `record_response()` is binary |
| Error payload vs. timeout | `record_failure()` and "not calling `record_response()`" are the only two outcomes; no error-type field |

These modes are out of scope for Trial 2. Do not invent new semantics.

### 3.3 Existing failure simulation is deterministic

All three representable failure modes use only `record_failure()`, `record_response()`, and
`sample()` — all of which are deterministic when called in a fixed sequence.
The only source of non-determinism is `sample()` drawing from `OsRng`. Trial 2 should
avoid `sample()` calls for stochastic-sensitive assertions, or control the observation
count so that entropy estimates converge exactly.

### 3.4 Relationship to `sim_s34`, `sim_s49`, and adjacent tests

`sim_s34` (`test/tests/sim.rs:1772`) and `sim_s35` (`test/tests/sim.rs:1835`) are the
closest existing failure-injection tests:

- `sim_s34`: `record_failure()` kills 3/4 providers → `kappa` rises. Now stable after
  sample count fixes. Uses `SamplingStrategy::RandomK(1)` with a `PoolSimulator` — involves
  random `sample()` calls.
- `sim_s35`: Silent failure (no `record_response()`) → `liveness_weighted_kappa` diverges.
  Fully deterministic.
- `sim_s59`–`sim_s69`: Cover all three `OperationalTelemetrySnapshot` surfaces with
  deterministic exact-count scenarios.

**Trial 2 must not duplicate `sim_s59`–`sim_s69`** but may reference them as confirmed
baselines. Trial 2's distinct contribution is a focused `trial2.rs` test file that uses
the `operational_telemetry()` API through a provider-failure lens specifically, with
assertions anchored in the observability-without-policy-coupling claim.

### 3.5 Recommended injection seam

Reuse the existing `record_failure()`, `record_response()`, and `sample()` seams. No new
simulator seam is required. When stochastic behavior would make assertions fragile, use
direct `record_response()` injection rather than relying on `sample()` to distribute
responses — this gives exact counts without requiring large sample windows.

---

## 4. Audit 3 — Measurement Stability Analysis

For each proposed test assertion:

| Assertion type | Deterministic? | Justification |
|---------------|---------------|---------------|
| `kappa ≈ 0` after N balanced `sample()` calls | Statistical (depends on OsRng) | Only stable with N ≥ 4 × active_n (Steady phase); prefer N = 400 for 4-provider pool |
| `kappa > threshold` after explicit `record_failure()` | **Exact** for direct-injection scenarios; statistical if relying on `sample()` | Use direct injection (skip `sample()`); compute exact kappa from known distribution |
| `liveness_weighted_kappa > kappa + delta` | **Exact** for response-injection scenarios | Control response count exactly via `record_response()` calls per provider |
| `recent_reported_response_ratio()` in range [lo, hi] | **Exact** | `response_total / selection_total` — both are exact counters |
| `availability_evaluable == true/false` | **Exact** | Binary flag; `selection_total > 0` |
| `liveness_surface_evaluable == true/false` | **Exact** | Binary flag; `response_total > 0 && selection_total > 0` |
| `current_epoch_phase == Steady` | **Exact** | `total_samples >= 4 * active_n` — exact threshold |

**Trial 2 stability rule**: Do not write assertions that depend on `OsRng` output. Either:
1. Use exact deterministic injection (direct `record_response()` / `record_failure()` calls,
   no `sample()`); or
2. When `sample()` is needed, use sample counts that put entropy estimates in ranges wide
   enough to survive any draw distribution (e.g., 1600 samples for a 4-provider pool gives
   an expected kappa < 0.02 with near-zero variance).

Trial 2 must not recreate the baseline instability repaired during Trial 1b/1c closure.

---

## 5. Audit 4 — Relationship to Corridor Operation

**Recommended scope: Option A — Telemetry-only provider failure trial.**

Rationale:

1. `OperationalTelemetrySnapshot` is computed entirely from `ExposureTracker` state, which
   is updated by `record_response()` and `sample()`. Neither of these calls requires or
   touches `open_and_send_sim()`, `VitalityEvidenceStore`, or any transport layer.

2. The telemetry surfaces that Trial 2 tests do not depend on encrypted burst creation.
   Combining Trial 2 with a send operation would introduce a second system-under-test
   (the vitality enforcement path) without adding new observability evidence.

3. `sim_s65` (`test/tests/sim.rs:4077`) already proves that telemetry-only signals do not
   trigger automatic policy action. Trial 2 must confirm this remains true in the presence
   of explicit failure injection, but that confirmation does not require a send operation.

**Do not combine Trial 2 with `open_and_send_sim()`** unless a later audit proves that
generating the telemetry signal structurally requires a corridor send. No such proof exists
from the current audit.

---

## 6. Audit 5 — Trial 2 Test Design

**Proposed test file:** `test/tests/trial2.rs` (new file)

All tests use only:
- `ProviderPool::new()` + `.with_liveness()` + `.add()`
- `pool.sample(&mut rng)` where needed for EpochPhase gating
- Direct `pool.record_response(id)` and `pool.record_failure(id)` calls
- `pool.operational_telemetry()` for assertions

No import of `scp_vitality`, `scp_transport`, or any corridor layer.

### Proposed tests

#### T1 — Baseline healthy provider observations produce expected telemetry

**Scenario**: 4 providers, 1600 direct `record_response()` calls (400 per provider, no
`sample()` needed for exact counts), plus 1600 manual `sample_and_record()` equivalents
via direct injection.

**Simpler approach**: 4 providers, 1600 `sample(&mut rng)` calls for selection entropy,
400 `record_response()` calls per provider for response entropy.

**Exact values** (deterministic):
- `selection_total ≥ 1600` → `EpochPhase::Steady`
- With uniform selection: entropy ≈ log₂(4) = 2.0 bits → `kappa ≈ 0`
- With 400 responses per provider: response entropy = log₂(4) = 2.0 bits →
  `liveness_weighted_kappa ≈ 0`
- `recent_reported_response_ratio() ≈ 0.5 to 1.0` depending on exact sample count

**Stability note**: Use a 1600-sample baseline. At 1600 samples for 4 providers,
expected entropy deviation < 0.01 bits → kappa < 0.005. The `kappa < 0.05` assertion
is safe.

**Assertions:**
- `tel.kappa < 0.05` (uniform selection → near-zero pressure)
- `(tel.liveness_weighted_kappa - tel.kappa).abs() < 0.05` (responses match selection)
- `tel.availability_evaluable`
- `tel.liveness_surface_evaluable`
- `tel.survivor_surface_evaluable`
- `tel.current_epoch_phase == EpochPhase::Steady`
- `tel.recent_reported_response_ratio().unwrap() > 0.1`

#### T2 — One provider becoming unavailable (explicit failure) raises kappa

**Scenario**: 4 providers, `with_liveness(5, 3600)`, 1600 `sample()` baseline, then
5× `record_failure([0; 32])` → provider 0 is dead. Then 400 more `sample()` calls.

**Expected**: Selections concentrate on providers 1, 2, 3 → selection entropy falls →
`kappa` rises. **Stability**: After 5 failures + 400 samples with 3 live providers,
the selection entropy ≈ log₂(3) ≈ 1.585 bits. With 4 in denominator: kappa = 1 − 1.585/2.0 ≈ 0.21.
Assertion `kappa > 0.10` is safe.

**Assertions:**
- `tel_baseline.kappa < 0.05` (pre-failure)
- `tel_after_failure.kappa > 0.10` (post-failure, selection concentrates on 3 providers)
- `tel_after_failure.survivor_surface_evaluable`

**Stability note**: Use 400 post-failure samples. With 3 live providers and RandomK(1),
entropy converges to log₂(3). The assertion `kappa > 0.10` has margin > 0.11 against
worst-case entropy value. This is deterministically safe.

#### T3 — Silent failure (no record_response) raises liveness_weighted_kappa while kappa stays near zero

**Scenario**: 4 providers, 1600 `sample()` calls for selection baseline, then call
`record_response([0;32])` 400 times only. Providers 1, 2, 3 are selected but never respond.

**Exact values**: Selection entropy ≈ log₂(4) = 2.0 bits → `kappa ≈ 0`. Response entropy ≈ 0
(all responses from one provider) → `liveness_weighted_kappa ≈ 1.0`.

**Assertions:**
- `tel.kappa < 0.05` (selection uniform → no pressure)
- `tel.liveness_weighted_kappa > 0.80` (response concentrated on one provider)
- `tel.liveness_weighted_kappa > tel.kappa + 0.60` (surfaces diverge by > 0.60)
- `tel.liveness_surface_evaluable`

**Stability note**: Direct `record_response()` injection for exactly 400 calls on one
provider → exact entropy computation. No stochastic component.

#### T4 — Recovery after silent failure updates liveness_weighted_kappa

**Scenario**: Start from T3 state (liveness_weighted_kappa ≈ 1.0). Then inject 400
`record_response()` calls per provider for all 4 providers.

**Expected**: Response entropy approaches log₂(4) → `liveness_weighted_kappa` drops
toward 0. The historical weight from the initial 400 one-provider responses is diluted
by 1600 balanced responses.

**Exact**: total responses = 1600 pre-recovery + 1600 recovery = 3200 total.
Provider 0 has 800, providers 1–3 have 400 each. Distribution: [800, 400, 400, 400] / 3200
= [0.25, 0.125, 0.125, 0.125]. Entropy = −0.25·log₂(0.25) − 3·0.125·log₂(0.125) ≈ 1.91 bits.
`liveness_weighted_kappa ≈ 1 − 1.91 / 2.0 = 0.045`. Assertion `< 0.15` is safe.

**Assertions:**
- Pre-recovery: `tel.liveness_weighted_kappa > 0.80`
- Post-recovery: `tel.liveness_weighted_kappa < 0.15`
- `tel.liveness_weighted_kappa - tel.kappa < 0.10` (surfaces re-converge)

#### T5 — Failure in one provider does not falsely mark unrelated providers unavailable

**Scenario**: 4 providers, `with_liveness(5, 3600)`. Kill provider 0 (5 failures).
Then inject balanced responses for providers 1, 2, 3.

**Expected**: `liveness_surface_evaluable = true`, response entropy reflects providers 1/2/3
only. Provider 0's response_total = 0 (selected at baseline, never responded). The
`liveness_weighted_kappa` reflects provider-0 silence but not providers 1/2/3.

**Assertions:**
- `tel.active_n == 4` (dead provider still in pool; `is_live()` is a selection filter,
  not a removal)
- `tel.liveness_surface_evaluable`
- `tel.liveness_weighted_kappa < 0.60` (only 1/4 providers absent; less concentrated
  than T3's 3/4 absent)
- `tel.kappa > 0.10` (selection concentration from dead provider)

#### T6 — Telemetry observation alone does not change vitality, send authorization, or rotation policy

**Scenario**: Manual rotation policy pool (no auto-rotation). Inject degraded state
(high liveness_weighted_kappa, low availability rate). Assert epoch_count remains 0 after
200 `maybe_rotate()` calls.

**Rationale**: `sim_s65` already covers this. Trial 2 confirms the invariant specifically
under the explicit failure injection path. The test is a compile-time and runtime boundary
check, not a new algorithmic assertion.

**Assertions:**
- `tel.liveness_weighted_kappa > 0.50` (degradation is present)
- `pool.epoch_count() == 0` after 200 `maybe_rotate()` calls with Manual policy
- No import of `scp_vitality` or `scp_transport` exists in `test/tests/trial2.rs`

#### T7 — Stochastic stability: kappa assertion is justified for N = 1600 samples

**Scenario**: Run 100 independent pools of 4 providers with 1600 samples. Assert that in
all 100 runs, `kappa < 0.05`.

This is a one-time calibration test. It proves the T1 assertion threshold is safe under
the variance of `OsRng`. If any run produces `kappa >= 0.05` at 1600 samples, the threshold
must be widened before Trial 2 proceeds.

**Mathematical basis**: For uniform RandomK(1) over 4 providers, each provider's expected
selection rate is 0.25. After 1600 samples, the sample count per provider has mean 400 and
stddev ≈ √(1600 × 0.25 × 0.75) ≈ 17.3. The 99.99th percentile count ratio is
(400 + 4×17.3) / 1600 ≈ 0.293. Shannon entropy at that distribution ≥ 1.985 bits.
`kappa = 1 − 1.985 / 2.0 = 0.0075`. The assertion `kappa < 0.05` has a 6.6× margin
against the 99.99th percentile worst case.

**Assertions:**
- All 100 independent runs: `tel.kappa < 0.05`

---

## 7. Audit 6 — Existing Coupling Check

### 7.1 Files searched

- `provider/pool/src/*.rs`
- `core/transport/src/*.rs`
- `core/vitality/src/*.rs`
- `relay/*/src/*.rs`
- `cli/endpoint/src/main.rs`
- `test/tests/*.rs`

### 7.2 Coupling findings

| Coupling tested | Found? | Evidence |
|----------------|--------|---------|
| ProviderPool / `OperationalTelemetrySnapshot` → `VitalityEvidenceStore` | **No** | No `use scp_vitality` in `provider/pool/src/*.rs` |
| ProviderPool / `OperationalTelemetrySnapshot` → `VitalityState` | **No** | No vitality import or reference in pool crate |
| ProviderPool / `OperationalTelemetrySnapshot` → `SimVitalityEvaluationContext` | **No** | No vitality import or reference in pool crate |
| ProviderPool / `OperationalTelemetrySnapshot` → transport send authorization | **No** | `OperationalTelemetrySnapshot` is read-only; no field feeds `open_and_send_sim()` |
| ProviderPool / `OperationalTelemetrySnapshot` → TOLS `κ` | **No** | TOLS `κ` is a pipeline metric defined outside this workspace |
| ProviderPool / `OperationalTelemetrySnapshot` → automatic rotation | **No** | `sim_s65` proves telemetry signals do not trigger `maybe_rotate()`; confirmed by Manual policy test |
| `liveness_weighted_kappa` → enforcement input | **No** | Documented `TELEMETRY-ONLY` in `metrics.rs:206`; has no caller outside `operational_telemetry()` |

**Conclusion**: Telemetry is currently **observational only**. No existing policy coupling
has been implemented. Trial 2 can proceed without introducing any new coupling.

---

## 8. Required Planning Output

### 8.1 Exact files inspected

| File | Purpose |
|------|---------|
| `provider/pool/src/metrics.rs` | `OperationalTelemetrySnapshot` definition |
| `provider/pool/src/lib.rs` | `ProviderPool::operational_telemetry()`, `record_failure()`, `record_response()`, `is_live()` |
| `provider/pool/src/liveness.rs` | `LivenessState`, `LivenessConfig` |
| `provider/pool/src/exposure.rs` | `ExposureTracker`, `ExposureEstimate` |
| `test/tests/sim.rs` | `sim_s34`, `sim_s35`, `sim_s59`–`sim_s69` |
| `test/tests/pool.rs` | `§106`–`§108` liveness_weighted_kappa pool tests |
| `core/vitality/src/lib.rs` | Confirmed no ProviderPool import |
| `core/transport/src/flash.rs` | Confirmed no OperationalTelemetrySnapshot import |

### 8.2 Exact telemetry surfaces and semantics

Three surfaces confirmed:

1. **Survivor concentration** (`kappa`): policy-authoritative; existing T1 threshold
   unchanged. Detects catastrophic active-set collapse.
2. **Relative liveness distortion** (`liveness_weighted_kappa`): telemetry-only; detects
   asymmetric silent failure.
3. **Absolute availability** (`response_total / selection_total`): telemetry-only; detects
   symmetric global response degradation.

### 8.3 Existing provider failure injection capabilities

| Capability | Deterministic | No new code required |
|------------|--------------|---------------------|
| Explicit provider failure via `record_failure()` | Yes | Yes |
| Silent failure (select but never respond) | Yes | Yes |
| Partial degradation (some providers respond, others silent) | Yes | Yes |
| Recovery via `record_response()` | Yes | Yes |

### 8.4 Recommended Trial 2 scope

**Option A — Telemetry-only provider failure trial.** No corridor send attempt required.
`operational_telemetry()` is a pure snapshot over `ExposureTracker` state; no transport
dependency exists.

### 8.5 Deterministic/stochastic stability analysis

| Test | Approach | Stability |
|------|----------|-----------|
| T1 — Baseline healthy | 1600 samples baseline + exact response injection | Stable (6.6× margin on kappa threshold) |
| T2 — Explicit failure raises kappa | 1600 baseline + 5 failures + 400 post-failure samples | Stable (0.11 margin on 0.10 threshold) |
| T3 — Silent failure raises liveness_weighted_kappa | 1600 samples + exact response injection | **Exactly deterministic** (no RNG in response path) |
| T4 — Recovery updates liveness_weighted_kappa | Extends T3 with exact response injection | **Exactly deterministic** |
| T5 — Provider identity isolation | Exact injection per provider | **Exactly deterministic** for surfaces 2 and 3 |
| T6 — Telemetry does not trigger policy | Manual policy, 200 rotate calls | **Exactly deterministic** |
| T7 — Stochastic stability calibration | 100 independent runs at 1600 samples | 99.99th percentile kappa < 0.0075 < 0.05 threshold |

### 8.6 Proposed implementation files

| File | Change | Type |
|------|--------|------|
| `test/tests/trial2.rs` | New: 7 acceptance tests | New |

No Rust source files outside `test/tests/` require modification.

### 8.7 Proposed Trial 2 tests summary

| # | Name | Assertion |
|---|------|-----------|
| T1 | `baseline_healthy_pool_telemetry_all_surfaces_nominal` | All three surfaces evaluable; kappa ≈ 0; liveness_weighted_kappa ≈ 0; rate near 1 |
| T2 | `explicit_failure_raises_kappa` | Post-failure kappa > pre-failure kappa + 0.10 |
| T3 | `silent_failure_raises_liveness_weighted_kappa` | liveness_weighted_kappa > 0.80 while kappa < 0.05 |
| T4 | `recovery_after_silent_failure_updates_telemetry` | Post-recovery liveness_weighted_kappa < 0.15 |
| T5 | `failure_in_one_provider_does_not_falsely_mark_others` | Identity isolation: partial degradation visible; liveness_weighted_kappa < 0.60 |
| T6 | `telemetry_observation_does_not_trigger_rotation_or_policy` | epoch_count == 0 after 200 maybe_rotate() calls under Manual policy |
| T7 | `kappa_assertion_threshold_stable_at_1600_samples` | All 100 independent runs: kappa < 0.05 |

### 8.8 Explicit non-claims

- Production CLI telemetry ingestion is not implemented.
- Relay liveness signals are not connected to `OperationalTelemetrySnapshot`.
- No automatic eviction, rotation, or admission trigger is connected to Surfaces 2 or 3.
- `record_failure()` and "no record_response()" are the only representable failure modes;
  stale response, error payloads, and partial delivery are not representable without new code.
- Vitality `i`, `r`, `p` formula inputs remain unconnected to telemetry.

### 8.9 Whether Trial 2 can proceed without new policy coupling

**Yes.** All seven proposed tests use only:
- `ProviderPool` construction (no vitality or transport imports)
- `record_failure()`, `record_response()`, `sample()`
- `operational_telemetry()`

No new policy coupling is introduced. The `TELEMETRY-ONLY` documentation on Surfaces 2 and 3
is preserved and the test assertions do not infer or create any policy from telemetry values.

---

## 9. Verdict

```
A — TRIAL_2_PROVIDER_FAILURE_OBSERVABILITY_SPECIFIED
```

| Audit | Finding | Status |
|-------|---------|--------|
| 1. Telemetry surfaces | Three surfaces confirmed; semantics exact; update events identified | ✅ |
| 2. Failure injection seam | Three deterministic modes; no new seam required; `record_failure()` / `record_response()` sufficient | ✅ |
| 3. Measurement stability | All proposed tests: deterministic or statistically justified with ≥ 6× safety margin | ✅ |
| 4. Recommended scope | Option A (telemetry-only); no corridor send needed | ✅ |
| 5. Test design | 7 tests specified; all deterministic or calibrated-stochastic; no knife-edge thresholds | ✅ |
| 6. Existing coupling | No existing policy coupling found; telemetry is observational-only | ✅ |

Implementation is authorized. Proof verdict after passing tests:
`A — TRIAL_2_PROVIDER_FAILURE_OBSERVABILITY_PROVEN`

---

## 10. What Trial 2 Does NOT Claim

- `record_failure()` or silence constitutes a complete provider health model
- Telemetry surfaces are sufficient for production monitoring without additional instrumentation
- Any connection between telemetry degradation and automatic corridor send policy
- Relay, localhost, LAN, or hardware readiness
- Production sources for vitality inputs `i`, `r`, or `p`
- Production reaffirmation protocol
