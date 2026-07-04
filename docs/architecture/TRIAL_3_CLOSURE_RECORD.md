# Trial 3 Closure Record

## Verdict

`A — TRIAL_3_ORTHOGONALITY_PROVEN`

---

## Files Created or Modified

| Action | File |
|--------|------|
| Created | `test/tests/trial3.rs` |
| Created | `docs/architecture/TRIAL_3_CLOSURE_RECORD.md` |

No production source files were modified.
No Trial 1c or Trial 2 source surfaces were modified.

---

## Baseline Accounting

| Metric | Value |
|--------|-------|
| Prior baseline | 464 passing, 0 failing |
| New Trial 3 tests | 8 |
| New baseline | **472 passing, 0 failing** |
| Run 1 | 472 / 472 |
| Run 2 | 472 / 472 |
| Run 3 | 472 / 472 |

---

## Test Inventory

| Test | Description |
|------|-------------|
| `t1_healthy_telemetry_active_vitality_permits_send` | Healthy pool trace + Active vitality → send succeeds, evidence timestamp unchanged |
| `t2_provider_degradation_changes_telemetry_not_send_authorization` | Degraded trace → kappa=lwk=1.0 but Active send still succeeds |
| `t3_silent_failure_changes_telemetry_not_vitality` | Silent provider → lwk>kappa distinction observed; send governed by unchanged Active context |
| `t4_partial_degradation_remains_observational_only` | Partial degradation → lwk=0.5; Active vitality still permits send |
| `t5_suspended_vitality_rejects_send_telemetry_remains_healthy` | Healthy pool, Suspended vitality → VitalityInsufficient; pool telemetry unchanged |
| `t6_reaffirmation_restores_send_without_changing_provider_telemetry` | Reaffirmation restores send; pool telemetry exactly unchanged |
| `t7_provider_recovery_changes_telemetry_not_vitality` | Provider recovery → lwk shifts 1.0→0.0; evidence timestamp unchanged throughout |
| `t8_simultaneous_pressure_preserves_orthogonality_boundary` | Central proof: degraded pool + Active vitality → send succeeds; no coupling observable |

---

## Fixed Traces Used

### Provider Pool Traces

**Healthy trace** (T1, T5, T6):
- 4 providers: `pid(1)` through `pid(4)` each `[byte; 32]`
- `StdRng::seed_from_u64(0)`, `SamplingStrategy::RandomK(1)`
- 16 calls to `pool.sample()` → Steady phase (16 ≥ 4×4)
- 4 calls to `pool.record_response(pid(i))` for each `i ∈ {1,2,3,4}`
- Result: `liveness_weighted_kappa = 0.0`, `response_total = 16`, `selection_total = 16`

**Explicit-failure trace** (T2, T8):
- 2 providers: `pid(1)`, `pid(2)`, `.with_liveness(2, u64::MAX)`
- 2 calls to `pool.record_failure(pid(2))` → `consecutive_failures=2` → dead
- `StdRng::seed_from_u64(0)`, 4 samples (only `pid(1)` selected)
- 4 calls to `pool.record_response(pid(1))`
- Result: `kappa = 1.0`, `liveness_weighted_kappa = 1.0`, `selection_total = 4`, `response_total = 4`

**Silent-failure trace** (T3):
- 2 providers: `pid(1)`, `pid(2)`
- `StdRng::seed_from_u64(0)`, 8 samples (both in pool, seeded selection)
- 8 calls to `pool.record_response(pid(1))` only
- Result: `liveness_weighted_kappa = 1.0`, `kappa` derived from seeded trace via `exposure_estimate()`

**Partial-degradation trace** (T4):
- 4 providers, `StdRng::seed_from_u64(0)`, 16 samples
- 4 responses for `pid(1)`, 4 responses for `pid(2)`, none for `pid(3)` or `pid(4)`
- Result: `liveness_weighted_kappa = 0.5`, `response_total = 8`, `selection_total = 16`

**Recovery trace** (T7):
- Phase 1 (degradation): pid(2) dead, only pid(1) in selections/responses → `lwk = 1.0`
- Phase 2 (recovery): 4 calls to `pool.record_response(pid(2))` → consecutive_failures reset
- Post-recovery: `liveness_weighted_kappa = 0.0`, `response_total = 8`

### Vitality Scenarios

**Active at t0=0** (T1, T2, T3, T4, T7, T8):
- `store.initialize_at(ch, 0)`, `ctx.now = 0`, standard controls `i=1.0, r=1.0, p=0.0`
- Ephemeral published at `sim_now=0`, `expires_at=3600`

**Suspended at t_suspended=4_171_664** (T5, T6):
- `store.initialize_at(ch, 0)` without reaffirmation → Suspended at `t_suspended`
- T5: no reaffirmation → send blocked
- T6: `store.record_reaffirmation(ch, t_suspended)` → Active restored

---

## Telemetry Fields Asserted

| Field | Used in Tests |
|-------|---------------|
| `kappa` | T1, T2, T3, T8 |
| `liveness_weighted_kappa` | All 8 tests |
| `survivor_surface_evaluable` | T1, T2, T8 |
| `liveness_surface_evaluable` | T1, T2, T3, T4, T7, T8 |
| `availability_evaluable` | T1, T4 |
| `response_total` | T1, T2, T3, T4, T5, T6, T7, T8 |
| `selection_total` | T1, T2, T3, T4, T5, T6, T7, T8 |
| `active_n` | T1, T4 |
| `current_epoch_phase` | T1 |
| `recent_reported_response_ratio()` | T1, T5 |
| `pool.exposure_estimate().selection_entropy_bits` | T1, T3 |
| `pool.epoch_count()` | T8 |

---

## Vitality Evidence Invariants Asserted

**Active→Warm boundary proof technique**: For every test where vitality should be
unchanged, the following two assertions are made before and after pool operations:

```rust
assert_eq!(store.compute_state(ch, t0 + 578_388, 1.0, 1.0, 0.0), VitalityState::Active);
assert_eq!(store.compute_state(ch, t0 + 578_389, 1.0, 1.0, 0.0), VitalityState::Warm);
```

These two checks together prove the stored timestamp is exactly `t0`. Any mutation of the
evidence timestamp during pool operations or a send would cause at least one assertion to
produce a different `VitalityState`.

For T6, after reaffirmation at `t_suspended`, the equivalent boundary check is:
```rust
assert_eq!(store.compute_state(ch, t_suspended + 578_388, ...), Active);
assert_eq!(store.compute_state(ch, t_suspended + 578_389, ...), Warm);
```
proving the new timestamp is exactly `t_suspended`.

---

## Send Assertions

All send assertions entered through `FlashSession::open_and_send_sim()`.

No wiring-claim test constructed `RecipientState` directly.
No alternative path was used to bypass the vitality gate.

| Test | Expected result |
|------|----------------|
| T1 | `Ok(...)` — Active at t0 |
| T2 | `Ok(...)` — Active at t0 despite degraded pool |
| T3 | `Ok(...)` — Active at t0 despite silent failure |
| T4 | `Ok(...)` — Active at t0 despite partial degradation |
| T5 | `Err(VitalityInsufficient(Suspended))` |
| T6 | `Ok(...)` — Active after reaffirmation |
| T7 | `Ok(...)` — Active at t0 despite provider recovery sequence |
| T8 | `Ok(...)` — Active at t0 despite simultaneous pool degradation |

---

## Confirmation: No Production Source Changed

No production Rust files were modified. The complete list of changes:
- `test/tests/trial3.rs` — created (new test-only file)
- `docs/architecture/TRIAL_3_CLOSURE_RECORD.md` — created (this record)

---

## Permitted Claim (Verbatim)

> Under deterministic concurrent simulation, provider-failure telemetry can change
> observably while bilateral vitality evidence and vitality-controlled send authorization
> remain unchanged unless the scenario explicitly changes vitality evidence or vitality inputs.

---

## Explicit Non-Claims

Trial 3 does **not** prove:

- provider telemetry should influence vitality
- `kappa`, `liveness_weighted_kappa`, or response/selection totals should populate `SimVitalityEvaluationContext.p`
- provider degradation should suspend a corridor
- telemetry should trigger send rejection
- telemetry should trigger automatic rotation policy
- TOLS κ policy integration
- production vitality-input measurement
- production reaffirmation protocol
- relay routing or mailbox delivery
- localhost, LAN, desktop, or hardware readiness

---

## No Telemetry-to-Vitality or Telemetry-to-Send-Policy Bridge

No test reads a telemetry value and passes it to `SimVitalityEvaluationContext`.
No test checks a telemetry value to predict a send outcome.
Pool telemetry operations (`sample`, `record_response`, `record_failure`,
`operational_telemetry`) share no state with `VitalityEvidenceStore` or
`FlashSession::open_and_send_sim()`.

The boundary is structural:
- `scp-provider-pool` does not depend on `scp-vitality`
- `VitalityEvidenceStore` does not hold a reference to `ProviderPool` or `ExposureTracker`
- `FlashSession::open_and_send_sim()` consults `VitalityEvidenceStore` and `SimVitalityEvaluationContext`, not `OperationalTelemetrySnapshot`

Trial 3 proves that no accidental runtime coupling was introduced between these
structurally separate systems.

---

## Predecessor Trials

| Trial | Verdict | Baseline |
|-------|---------|---------|
| Trial 1c | `A — TRIAL_1C_SIMULATOR_RUNTIME_VITALITY_ENFORCEMENT_PROVEN` | 12 tests |
| Trial 2 | `A — TRIAL_2_PROVIDER_FAILURE_OBSERVABILITY_PROVEN` | 7 tests |
| Trial 3 | `A — TRIAL_3_ORTHOGONALITY_PROVEN` | 8 tests |
