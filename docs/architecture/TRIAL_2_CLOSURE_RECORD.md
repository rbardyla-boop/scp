# Trial 2 Closure Record — Provider-Failure Observability

**Verdict**: `A — TRIAL_2_PROVIDER_FAILURE_OBSERVABILITY_PROVEN`
**Date**: 2026-05-28
**Predecessor**: `TRIAL_1C_CLOSURE_RECORD.md`
  (`A — TRIAL_1C_SIMULATOR_RUNTIME_VITALITY_ENFORCEMENT_PROVEN`, baseline 457 / 457 / 457)

---

## 1. Verdict Summary

| Dimension | Result |
|-----------|--------|
| Telemetry field names confirmed from production source | CONFIRMED |
| T1 — Healthy baseline snapshot fields exact | PROVEN |
| T2 — Explicit failure concentrates selection surface | PROVEN |
| T3 — Silent failure distinguishes liveness from selection surface | PROVEN |
| T4 — Partial degradation shows intermediate liveness_weighted_kappa | PROVEN |
| T5 — Recovery via record_response() resets failure state | PROVEN |
| T6 — Provider isolation: failure does not corrupt sibling telemetry | PROVEN |
| T7 — Observability does not couple to vitality or send authorization | PROVEN |
| No production source modified | CONFIRMED |
| Telemetry remains observational only | CONFIRMED |
| Full workspace baseline (3 consecutive clean runs) | **464 / 464 / 464** |

---

## 2. Accepted Pre-Trial-2 Baseline

| Item | Value |
|------|-------|
| Trial 1c verdict | `A — TRIAL_1C_SIMULATOR_RUNTIME_VITALITY_ENFORCEMENT_PROVEN` |
| Prior full-workspace total | 457 passing, 0 failing |
| New tests added by Trial 2 | 7 |
| Expected new total | 457 + 7 = **464** |
| Actual new total | **464** |

---

## 3. Exact Files Modified

**Created (1 file):**
- `test/tests/trial2.rs`

**No production source files were modified.** All seven tests use only the
public API of `scp-provider-pool` and `scp-vitality` crates as dev-dependencies.

---

## 4. Telemetry Fields Exercised

All field names confirmed directly from `provider/pool/src/metrics.rs`.

### `OperationalTelemetrySnapshot` — three surfaces

| Field | Surface | Type | Tests |
|-------|---------|------|-------|
| `kappa` | 1 — Survivor concentration | `f64` | T1, T2, T3 |
| `survivor_surface_evaluable` | 1 | `bool` | T1, T2, T3 |
| `liveness_weighted_kappa` | 2 — Relative liveness distortion | `f64` | T1–T6 |
| `liveness_surface_evaluable` | 2 | `bool` | T1–T6 |
| `response_total` | 3 — Absolute availability | `u64` | T1–T6 |
| `selection_total` | 3 | `u64` | T1–T4, T6 |
| `availability_evaluable` | 3 | `bool` | T1, T2, T4 |
| `recent_reported_response_ratio()` | 3 (derived) | `Option<f64>` | T1, T2 |
| `current_epoch_phase` | Evidence context | `EpochPhase` | T1 |
| `active_n` | Evidence context | `usize` | T1–T3, T6, T7 |

### Observation seams used

| Seam | Purpose | Tests |
|------|---------|-------|
| `ProviderPool::sample()` | Drives selection surface (appearances tracker) | T1–T6 |
| `ProviderPool::record_response()` | Drives response surface; resets failure state (recovery) | T1–T6 |
| `ProviderPool::record_failure()` | Explicit failure seam; increments consecutive_failures | T2, T5, T6 |
| `ProviderPool::with_liveness()` | Configures liveness dead-threshold for failure filtering | T2, T5 |
| `ProviderPool::operational_telemetry()` | Returns OperationalTelemetrySnapshot | T1–T7 |
| `ProviderPool::exposure_estimate()` | Returns raw entropy for kappa cross-check | T1, T3 |
| `ProviderPool::epoch_count()` | Verifies no auto-rotation from telemetry observation | T7 |
| `VitalityEvidenceStore::initialize_at()` | Sets vitality baseline for T7 isolation check | T7 |
| `VitalityEvidenceStore::compute_state()` | Reads vitality state before/after pool telemetry | T7 |

---

## 5. Scripted Failure Traces and Assertions

### T1 — Healthy baseline

**Trace:** 4 providers added. 16 `sample()` calls (seeded `StdRng::seed_from_u64(0)`).
`record_response()` 4 times for each of pid(1)–pid(4) = 16 total responses.

**Exact assertions derived from trace:**
- `liveness_weighted_kappa = 0.0`
  (response_entropy = −4×(0.25×log₂(0.25)) = 2.0 bits; lwk = 1 − 2.0/log₂(4) = 0.0)
- `selection_total = 16`, `response_total = 16`
- `recent_reported_response_ratio() = Some(1.0)`
- `current_epoch_phase = EpochPhase::Steady` (16 ≥ 4×active_n)
- `kappa` = 1 − selection_entropy / log₂(4), cross-checked via `exposure_estimate()`

### T2 — Explicit failure

**Trace:** 2 providers, `with_liveness(max_consecutive_failures=2)`.
`record_failure(pid(2))` twice → dead. 4 `sample()` calls → only pid(1) selected.
`record_response(pid(1))` 4 times.

**Exact assertions derived from trace:**
In this scripted trace, pid(2) is excluded from `sample()` by the liveness gate,
so only pid(1) accumulates selection appearances. The resulting snapshot reflects
that single-provider concentration.
- `kappa = 1.0` (appearances={pid(1):4, pid(2):0}; entropy=0; kappa=1−0/log₂(2)=1.0)
- `liveness_weighted_kappa = 1.0` (responses={pid(1):4}; entropy=0; lwk=1.0)
- `active_n = 2` (dead provider remains in pool, only filtered from sample())
- `selection_total = 4`, `response_total = 4`

**Wording note:** This test does not claim that failure alone causes κ concentration.
It claims that the explicit-failure scripted trace produces exactly these telemetry
output values through the existing observational surfaces.

### T3 — Silent failure distinction

**Trace:** 2 providers. 8 `sample()` calls (seeded). `record_response(pid(1))` 8 times.
pid(2) never calls record_response().

**Exact assertions derived from trace:**
- `liveness_weighted_kappa = 1.0` (responses={pid(1):8}; entropy=0)
- `kappa` = 1 − selection_entropy / log₂(2), derived from `exposure_estimate()`
- `liveness_weighted_kappa ≥ kappa` (response entropy 0 ≤ selection entropy)
- When `selection_entropy_bits > 0`: `liveness_weighted_kappa > kappa` (strict inequality)

### T4 — Partial degradation

**Trace:** 4 providers. 16 `sample()` calls (seeded). `record_response(pid(1))` 4 times
and `record_response(pid(2))` 4 times. pid(3) and pid(4) are silent.

**Exact assertions derived from trace:**
- `liveness_weighted_kappa = 0.5`
  (responses={pid(1):4, pid(2):4}, total=8; entropy=1.0 bit; lwk=1−1.0/log₂(4)=0.5)
- `response_total = 8`, `selection_total = 16`

### T5 — Recovery

**Trace:** 2 providers, `with_liveness(2)`. `record_failure(pid(2))` twice.
4 `sample()` calls. `record_response(pid(1))` 4 times.
Intermediate snapshot: `liveness_weighted_kappa = 1.0`.
`record_response(pid(2))` 4 times (first call resets consecutive_failures=0).

**Exact assertions derived from trace:**
- Pre-recovery: `liveness_weighted_kappa = 1.0` (only pid(1) in responses)
- Post-recovery: `liveness_weighted_kappa = 0.0`
  (responses={pid(1):4, pid(2):4}; entropy=1.0 bit; lwk=1−1.0/log₂(2)=0.0)
- `response_total = 8` (4 phase-1 + 4 phase-2)

### T6 — Provider isolation

**Trace:** 4 providers. 4 `sample()` calls (seeded). `record_response(pid(1))` 4 times,
`record_response(pid(2))` 4 times. `record_failure(pid(3))` 5 times,
`record_failure(pid(4))` 5 times.

**Exact assertions derived from trace:**
- `response_total = 8` (10 record_failure calls must not inject phantom responses)
- `liveness_weighted_kappa = 0.5`
  (responses={pid(1):4, pid(2):4}; same as T4; failures do not alter this value)
- `active_n = 4`

### T7 — Observability-only boundary

**Trace:** VitalityEvidenceStore initialized at (consent_hash=[7u8;32], t=0).
State at t=1_000 asserted Active (pre-condition). Pool driven with 16 samples,
16 record_response calls, 3 record_failure calls, then `operational_telemetry()` called.

**Structural proof (crate boundary):**
`scp-provider-pool` does not depend on `scp-vitality`. `VitalityEvidenceStore` does not
hold any reference to `ProviderPool` or `ExposureTracker`. No shared state path exists.

**Runtime assertion:**
- `VitalityEvidenceStore.compute_state(consent_hash, 1_000) = Active` after all pool operations.
  The Trial 2 observation path did not mutate the tested `VitalityEvidenceStore` state.
- `pool.epoch_count() = 0` after `operational_telemetry()`: no observed rotation-state
  change triggered by the Trial 2 observation path.

**Wording note:** This test proves the Trial 2 observation path did not mutate the
tested `VitalityEvidenceStore` state or trigger observed rotation-state change within
the accessible trial scope. It does not claim that no future coupling is possible or
that every production path is isolated beyond what was directly exercised.

---

## 6. Full Workspace Totals — Three Consecutive Clean Runs

All runs performed immediately after writing `test/tests/trial2.rs` with no
intervening source changes.

| Run | Passing | Failing |
|-----|---------|---------|
| 1 | **464** | 0 |
| 2 | **464** | 0 |
| 3 | **464** | 0 |

Count reconciliation: 457 (Trial 1c baseline) + 7 (Trial 2) = **464** ✓

---

## 7. Confirmation: No Production Source Files Changed

The following files are **unchanged** from their pre-Trial-2 state:

| File | Status |
|------|--------|
| `provider/pool/src/metrics.rs` | Unchanged |
| `provider/pool/src/lib.rs` | Unchanged |
| `provider/pool/src/exposure.rs` | Unchanged |
| `provider/pool/src/liveness.rs` | Unchanged |
| `core/vitality/src/` (all files) | Unchanged |
| `core/transport/src/flash.rs` | Unchanged |
| `core/transport/src/corridor.rs` | Unchanged |
| All relay, ledger, CLI, localhost, LAN files | Unchanged |

The only new file is `test/tests/trial2.rs` (test target, dev-only).

---

## 8. Confirmation: Telemetry Remains Observational Only

`OperationalTelemetrySnapshot` is a read-only value struct with no method that
writes to `VitalityEvidenceStore`, invokes `open_and_send_sim()` authorization,
changes `PoolRotationPolicy` behavior, or triggers relay routing.

`operational_telemetry()` reads from `ExposureTracker` via an immutable lock
and constructs the snapshot. It does not call `do_rotate()`, `maybe_rotate()`,
`force_rotate()`, or any variant of `open_and_send`.

T7 confirms this at runtime: `epoch_count() = 0` after telemetry observation,
and `VitalityEvidenceStore` state is unchanged.

---

## 9. Explicit Non-Claims

Trial 2 does **not** prove:

- Degraded telemetry should trigger any policy action
- `liveness_weighted_kappa` is safe for automatic routing or rotation decisions
- `liveness_weighted_kappa` should populate `SimVitalityEvaluationContext.p`
- Provider failure should suspend a corridor
- Provider failure should modify encrypted send authorization
- Provider failure should trigger automatic provider rotation
- Transport behavior during provider degradation
- Relay routing, mailbox delivery, or routing privacy under failure
- Localhost, LAN, desktop, or hardware readiness
- Production provider orchestration or real network failure semantics
