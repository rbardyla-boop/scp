# Corridor Trial 4 — Selective Response Suppression Manipulability Characterization

**Status:** Planning only. No Rust source files modified.
**Predecessor:** Trial 3 (`A — TRIAL_3_ORTHOGONALITY_PROVEN`, baseline 472 passing)
**Authorized baseline:** 472 passing × 3 clean runs

---

## Objective

Determine whether the existing provider telemetry surfaces can be manipulated by an
adversarial response strategy in which a provider responds selectively rather than
simply remaining healthy or failing uniformly.

Target permitted claim (once proven):

> Under deterministic scripted selective-response scenarios, the SCP simulator
> characterizes how existing provider telemetry surfaces react to strategically
> omitted responses, without connecting those observations to automatic vitality,
> send, rotation, or routing policy.

Trial 4 is an adversarial measurement-characterization trial. It is not a policy trial.

---

## Non-Negotiable Boundary

No Trial 4 observation may be connected to:

- `VitalityEvidenceStore`
- `SimVitalityEvaluationContext.p`
- `VitalityState`
- `open_and_send_sim()` authorization
- Automatic provider rotation
- TOLS κ control
- Relay behavior
- Networking or hardware execution

---

## Audit 1 — Existing Selective-Response Representation

### Files Inspected

| File | Purpose |
|------|---------|
| `provider/pool/src/lib.rs` | `ProviderPool`: `sample()`, `record_response()`, `record_failure()` |
| `provider/pool/src/metrics.rs` | `OperationalTelemetrySnapshot`, `recent_reported_response_ratio()`, `ConvergencePressure` |
| `provider/pool/src/exposure.rs` | `ExposureTracker`: `record()` (selection), `record_response()` (response), entropy computations |
| `test/tests/trial2.rs` | Established provider-failure trace patterns |
| `test/tests/trial3.rs` | Established healthy + degradation trace patterns |

### Existing Adversary Representation

The following adversarial traces are fully expressible through existing public operations
without any new seam:

| Adversary pattern | Scripted using existing operations | Status |
|-------------------|------------------------------------|--------|
| Healthy: all selected providers respond | `pool.sample()` + `pool.record_response(pid)` for each selected | Expressible |
| Explicit failure: `record_failure()` increments `consecutive_failures` → marks dead | `pool.record_failure(pid)` × max_consecutive_failures | Expressible |
| Total silent failure: selected but no response/failure recorded | `pool.sample()` only; no `record_response()` or `record_failure()` | Expressible |
| Asymmetric selective suppression: one provider suppresses, peers respond | `record_response(pid_1..N-1)` but not `record_response(pid_N)` | Expressible |
| Alternating suppression: every other query suppressed | Interleave `record_response()` / no-call per selection | Expressible |
| Symmetric suppression: all providers suppress at equal rate | `record_response()` only on subset of selections, uniformly across pids | Expressible |
| Suppression that preserves selection balance | `pool.sample()` with no `record_response()` on any provider | Expressible |
| Recovery after suppression | Resume `record_response()` after suppression window | Expressible |

**No new production seam is required for Trial 4.**

---

## Audit 2 — Metrics Under Manipulation

### Metric Source Definitions

| Metric | Source | What it measures |
|--------|--------|-----------------|
| `kappa` | `selection_entropy_bits` from `ExposureTracker::record()` calls | Selection distribution balance — unaffected by whether responses occur |
| `liveness_weighted_kappa` | `response_entropy_bits` from `ExposureTracker::record_response()` calls | Response distribution balance — only counts providers that actually respond |
| `response_total` | Count of `record_response()` calls in window | Absolute response volume |
| `selection_total` | Count of `sample()` calls (aggregated selections) in window | Absolute selection volume |
| `recent_reported_response_ratio()` | `response_total / selection_total` | Response rate — explicitly documented as unverified |
| `survivor_surface_evaluable` | `current_epoch_phase != PostReset` | Guards kappa from being read before sufficient selections |
| `liveness_surface_evaluable` | `response_total > 0 && selection_total > 0` | Guards liveness_weighted_kappa from unevaluable state |

### Expected Telemetry for Proposed Scripted Traces

Setup for all scenarios: 4 providers (`pid(1)`–`pid(4)`), `StdRng::seed_from_u64(0)`,
`SamplingStrategy::RandomK(1)`, no liveness config (no dead-marking). Active vitality
context untouched throughout (all tests assert vitality independently from pool telemetry).

---

**Scenario T4-1: Healthy baseline**

Trace: 16 calls to `pool.sample()` + `pool.record_response(pid(i))` for the selected provider
each time. All 4 providers selected approximately uniformly by seeded RNG.

| Metric | Expected value |
|--------|---------------|
| `kappa` | ~0.0 (uniform selection distribution, Steady phase) |
| `liveness_weighted_kappa` | ~0.0 (uniform response distribution) |
| `response_total` | 16 |
| `selection_total` | 16 |
| `recent_reported_response_ratio()` | `Some(1.0)` |
| `survivor_surface_evaluable` | true |
| `liveness_surface_evaluable` | true |

What it demonstrates: healthy baseline where kappa ≈ liveness_weighted_kappa ≈ 0.

---

**Scenario T4-2: Total silent failure baseline**

Trace: 16 `pool.sample()` calls, no `record_response()` calls for any provider.

| Metric | Expected value |
|--------|---------------|
| `kappa` | ~0.0 (selection still uniform; seeded RNG) |
| `liveness_weighted_kappa` | 1.0 (no responses recorded; response entropy = 0; `liveness_surface_evaluable = false` → `recent_reported_response_ratio() = None`) |
| `response_total` | 0 |
| `selection_total` | 16 |
| `recent_reported_response_ratio()` | `None` (`liveness_surface_evaluable = false`) |
| `liveness_surface_evaluable` | false |

What it demonstrates: total suppression is immediately detectable via
`liveness_surface_evaluable = false` and `response_total = 0`.

---

**Scenario T4-3: Asymmetric selective suppression (one provider suppresses)**

Setup: 4 providers. Trace: 16 `pool.sample()` calls using seeded RNG.
For each selection: if `pid(1)` is selected → no `record_response()`.
If any other provider is selected → `record_response(that_pid)`.

| Metric | Expected value |
|--------|---------------|
| `kappa` | ~0.0 (selection distribution uniform) |
| `liveness_weighted_kappa` | > 0.0, elevated above kappa (pid(1) contributes 0 to response entropy; reduces response distribution's uniformity) |
| `response_total` | < 16 (pid(1) selections not counted) |
| `selection_total` | 16 |
| `recent_reported_response_ratio()` | `Some(< 1.0)` |

What it demonstrates: asymmetric suppression is distinguishable — `liveness_weighted_kappa`
rises above `kappa`, forming a non-zero `lwk - kappa` gap.

---

**Scenario T4-4: Alternating suppression (every other selection suppressed for one provider)**

Setup: Same 4-provider pool. Trace: 16 samples; pid(1) selections alternate between
`record_response()` and suppression (every other selection from pid(1) has no response).

| Metric | Expected value |
|--------|---------------|
| `kappa` | ~0.0 (unchanged selection distribution) |
| `liveness_weighted_kappa` | Elevated above T4-1 but less than T4-3 (pid(1) has partial response) |
| `response_total` | Between T4-1 and T4-3 values |
| `recent_reported_response_ratio()` | `Some(between 0.75 and 1.0)` |

What it demonstrates: partial/alternating suppression produces intermediate telemetry
between healthy and full-suppression — the surface is graded, not binary.

---

**Scenario T4-5: Symmetric suppression preserving selection balance**

Trace: 16 `pool.sample()` calls using seeded RNG.
For EVERY selection: no `record_response()` called for ANY provider.
(Equivalent to T4-2 but framed as "uniform suppression across all providers".)

| Metric | Expected value |
|--------|---------------|
| `kappa` | ~0.0 (selection distribution uniform) |
| `liveness_weighted_kappa` | 1.0 — `liveness_surface_evaluable = false` |
| `response_total` | 0 |
| `selection_total` | 16 |
| `recent_reported_response_ratio()` | `None` |

What it demonstrates: uniform suppression is indistinguishable from total silence on
Surface 2 alone, but Surface 3 (`response_total = 0`) flags it unambiguously.

**Key finding**: `liveness_weighted_kappa` alone cannot distinguish healthy silence
(very recent window start) from malicious uniform suppression. Surface 3 is required.

---

**Scenario T4-6: Symmetric partial suppression (all providers suppress at equal 50% rate)**

Trace: 32 samples; for each provider, approximately half of its selections receive
`record_response()`, the other half suppressed. Selection distribution remains uniform.

| Metric | Expected value |
|--------|---------------|
| `kappa` | ~0.0 (selection uniform) |
| `liveness_weighted_kappa` | ~0.0 (response distribution ALSO uniform — all providers respond at same partial rate) |
| `response_total` | ~16 (≈ 50% of 32 selections) |
| `selection_total` | 32 |
| `recent_reported_response_ratio()` | `Some(~0.5)` |

**Critical finding**: Symmetric partial suppression at a uniform rate produces
`liveness_weighted_kappa ≈ 0` (healthy-looking on Surface 2) while
`recent_reported_response_ratio() ≈ 0.5` (degraded on Surface 3).
Surface 2 ALONE cannot detect symmetric partial suppression.

---

**Scenario T4-7: Telemetry manipulation does not alter vitality evidence or p**

Same setup as T4-3 (asymmetric suppression). Before and after pool operations:
assert `VitalityEvidenceStore.compute_state()` at Active→Warm boundary points unchanged.
Assert `SimVitalityEvaluationContext.p` unchanged (standard 0.0).

| Assertion | Expected |
|-----------|---------|
| `compute_state(ch, t0+578_388, 1.0, 1.0, 0.0)` | `Active` — before and after |
| `compute_state(ch, t0+578_389, 1.0, 1.0, 0.0)` | `Warm` — before and after |
| Pool operations change evidence timestamp | No |

What it demonstrates: manipulated telemetry does not leak into vitality evidence.
(Structural: pool and vitality stores share no state.)

---

**Scenario T4-8: Telemetry manipulation does not change send authorization**

Same setup as T4-6 (symmetric partial suppression). With Active vitality context,
after running the suppression trace, `open_and_send_sim()` must return `Ok(...)`.
The suppressed telemetry does not trigger `VitalityInsufficient`.

What it demonstrates: even the most "damaging" (symmetric) suppression trace does not
independently change send authorization. Vitality governs send; pool telemetry does not.

---

**Scenario T4-9: No automatic rotation through suppression observation path**

Setup: Pool with `PoolRotationPolicy::QueryCount(8)` and a dormant tier.
Run T4-3 (asymmetric suppression trace, 16 samples). Assert `pool.epoch_count() == 0`
after the trace — the rotation policy was not triggered by the telemetry observation
itself, only by actual `maybe_rotate()` / `sample()` calls.

Wait — actually `QueryCount` is incremented inside `maybe_rotate()`, not inside `sample()`.
The suppression trace does not call `maybe_rotate()`. So `epoch_count() == 0` simply
because no rotation was explicitly requested. This test confirms the suppression-observation
path does not have a hidden side channel into the rotation counter.

---

## Audit 3 — Distinguishability Matrix

| Scenario | kappa | lwk | response_total | response_ratio | Distinguishable from healthy? |
|----------|-------|-----|---------------|---------------|-------------------------------|
| T4-1 Healthy | ~0 | ~0 | = selection_total | ~1.0 | Baseline |
| T4-2 Total silence | ~0 | 1.0* | 0 | None | Yes — via response_total=0 and liveness_surface_evaluable=false |
| T4-3 Asymmetric suppression | ~0 | > kappa | < selection_total | < 1.0 | Yes — lwk rises above kappa |
| T4-4 Alternating suppression | ~0 | intermediate | < selection_total | < 1.0 | Yes — graded signal |
| T4-5 Uniform full suppression | ~0 | 1.0* | 0 | None | Yes — Surface 3 |
| T4-6 Uniform partial suppression | ~0 | ~0 | = ~50% of selection | ~0.5 | **Partially** — Surface 2 misleads; Surface 3 detects |

\* liveness_surface_evaluable = false when response_total = 0

**Key finding — Audit 3**:

> Asymmetric selective suppression is detectable by Surface 2 (`liveness_weighted_kappa`
> rises above `kappa`). Symmetric selective suppression that preserves response-distribution
> uniformity while reducing response volume is NOT detectable by Surface 2 alone but IS
> detectable by Surface 3 (`response_total / selection_total < 1.0`).

---

## Audit 4 — Manipulability and Policy Risk

| Telemetry field | Manipulation scenario | Misleading direction | Observable counter-signal | Safe for automatic policy now? |
|-----------------|----------------------|---------------------|--------------------------|-------------------------------|
| `kappa` | Uniform selection among suppressing providers | Low kappa (looks healthy) | `liveness_weighted_kappa` > kappa | Not applicable (kappa is policy-authoritative for T1 collapse detection only) |
| `liveness_weighted_kappa` | Symmetric uniform suppression | Low lwk (looks healthy) | `response_total` < `selection_total` | **NO** |
| `recent_reported_response_ratio()` | Suppress responses + inject via `record_response()` (see §S64, §S69) | High ratio (looks healthy despite omission) | No counter-signal in current surfaces | **NO** |
| `response_total` | Suppress responses + inject | Inflated numerator | No counter-signal in current surfaces | **NO** |
| `selection_total` | Cannot be inflated without calling `sample()` (observable as pool load) | N/A | N/A | Counter-signal only |

**Critical finding — Audit 4**:

`recent_reported_response_ratio()` is explicitly documented in `metrics.rs` (§S64, §S69):
> "An adversary or buggy caller can inflate this value arbitrarily. Do not derive automatic
> policy from this metric until responses are bound to specific selected attempts with
> at-most-once accounting and unmatched-response rejection."

This is the fundamental manipulability boundary for all three surfaces under the
combined injection-and-suppression threat. Trial 4 (suppression characterization)
and §S69 (injection characterization) together define the full manipulation envelope.

**Default position**: Observability does not yet justify automatic policy use.

---

## Audit 5 — Proposed Deterministic Tests (trial4.rs)

**File**: `test/tests/trial4.rs`

**Test inventory**:

| Test | Scenario | What it proves |
|------|----------|----------------|
| `t1_healthy_baseline` | T4-1 | kappa ≈ lwk ≈ 0; response_ratio ≈ 1.0 |
| `t2_total_silent_failure_baseline` | T4-2 | liveness_surface_evaluable=false; response_total=0 |
| `t3_asymmetric_selective_suppression` | T4-3 | lwk > kappa; response_ratio < 1.0 |
| `t4_alternating_suppression_graded_signal` | T4-4 | Intermediate lwk; graded signal confirmed |
| `t5_symmetric_suppression_preserves_selection_balance` | T4-5/T4-6 | lwk stays low; response_ratio drops; Surface 2 alone insufficient |
| `t6_recovery_resumes_normal_telemetry` | Resume `record_response()` after T4-3 | lwk decreases back toward kappa; ratio recovers |
| `t7_suppression_does_not_mutate_vitality_evidence` | T4-7 | Active→Warm boundary proves evidence timestamp unchanged |
| `t8_suppression_does_not_change_send_authorization` | T4-8 | `open_and_send_sim()` returns Ok(…) with Active vitality |
| `t9_no_automatic_rotation_through_suppression_path` | T4-9 | epoch_count() == 0 after suppression trace with no explicit rotation call |

**No random traces. No wall-clock timing. No threshold assertions based on undersampled probability.**

All 9 tests use `StdRng::seed_from_u64(0)` for deterministic RNG state.

---

## Audit 6 — Test-Only Feasibility

**Finding**: Trial 4 is test-only.

No new production source file is required. The full adversarial trace can be expressed
through the existing `ProviderPool` public API:
- `pool.add(pid, provider)`
- `pool.sample(&mut rng)` — records selection in ExposureTracker
- `pool.record_response(pid)` — records response in ExposureTracker and resets liveness
- `pool.record_failure(pid)` — increments consecutive_failures (not used in most T4 scenarios)
- `pool.operational_telemetry()` — returns `OperationalTelemetrySnapshot`
- `pool.epoch_count()` — rotation counter assertion

All vitality assertions use `VitalityEvidenceStore` and `open_and_send_sim()` exactly
as in Trial 3. No new vitality surface is required.

---

## Required Planning Output Summary

**1. Exact files inspected**

| File | Role |
|------|------|
| `provider/pool/src/lib.rs` | ProviderPool public API: sample, record_response, record_failure |
| `provider/pool/src/metrics.rs` | OperationalTelemetrySnapshot, recent_reported_response_ratio |
| `provider/pool/src/exposure.rs` | ExposureTracker record/record_response/entropy |
| `test/tests/trial3.rs` | Reference trace patterns |
| `test/tests/trial2.rs` | Reference trace patterns |

**2. Current executable selective-response representation**

Fully expressible. No new production seam required. See Audit 1.

**3. Exact telemetry outputs for proposed scripted traces**

See Audit 2 trace table (T4-1 through T4-9).

**4. Whether selective suppression is distinguishable from ordinary failure**

- Asymmetric suppression: **Distinguishable** (lwk rises above kappa).
- Symmetric suppression: **Distinguishable via Surface 3** only; Surface 2 alone misleads.
- Combined suppression + injection: **Not distinguishable** with current surfaces.

**5. Whether any metric appears manipulable or unsafe for automated policy**

`recent_reported_response_ratio()` — explicitly unsafe. See metrics.rs §S64/§S69 documentation.
`liveness_weighted_kappa` — unsafe under symmetric suppression alone.

**6. Proposed tests**

9 tests in `test/tests/trial4.rs`. See Audit 5.

**7. Expected file changes**

| File | Action |
|------|--------|
| `test/tests/trial4.rs` | Create (9 new tests, test-only) |
| `docs/architecture/CORRIDOR_TRIAL_4_SELECTIVE_RESPONSE_SUPPRESSION_PLAN.md` | Created (this document) |

No production source changes.

**8. Permitted claim and non-claims**

Permitted claim (after implementation):

> Under deterministic scripted selective-response scenarios, the SCP simulator
> characterizes how existing provider telemetry surfaces react to strategically
> omitted responses, without connecting those observations to automatic vitality,
> send, rotation, or routing policy.

Non-claims:
- Response suppression should trigger automatic vitality suspension
- `liveness_weighted_kappa` alone is sufficient to detect all suppression patterns
- `recent_reported_response_ratio()` is safe for automatic policy
- Any telemetry field should feed `SimVitalityEvaluationContext.p`
- Trial 4 establishes a complete adversary model for production routing
- LAN, relay, hardware, or production reaffirmation paths are proven

**9. Whether implementation is test-only**

**Yes.** Trial 4 requires no production source changes.

---

## Verdict Vocabulary

Pending implementation:

`A — TRIAL_4_SELECTIVE_SUPPRESSION_CHARACTERIZATION_SPECIFIED`

---

## Predecessor Chain

| Trial | Verdict | New baseline |
|-------|---------|-------------|
| Trial 1c | `A — TRIAL_1C_SIMULATOR_RUNTIME_VITALITY_ENFORCEMENT_PROVEN` | 12 tests |
| Trial 2 | `A — TRIAL_2_PROVIDER_FAILURE_OBSERVABILITY_PROVEN` | 7 tests |
| Trial 3 | `A — TRIAL_3_ORTHOGONALITY_PROVEN` | 8 tests |
| Trial 4 | Pending | +9 tests target |
