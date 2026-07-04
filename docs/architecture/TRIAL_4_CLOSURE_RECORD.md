# Trial 4 Closure Record

## Verdict

`A — TRIAL_4_SELECTIVE_SUPPRESSION_CHARACTERIZED`

---

## Files Created or Modified

| Action | File |
|--------|------|
| Created | `test/tests/trial4.rs` |
| Created | `docs/architecture/TRIAL_4_CLOSURE_RECORD.md` |

No production source files were modified.
No provider-pool, vitality, transport, relay, ledger, TOLS κ, rotation policy,
CLI, localhost, LAN, desktop, or hardware surfaces were modified.

---

## Baseline Accounting

| Metric | Value |
|--------|-------|
| Prior baseline (Trial 3 verified) | 472 passing, 0 failing |
| New Trial 4 tests | 9 |
| New baseline | **481 passing, 0 failing** |
| Run 1 | 481 / 481 |
| Run 2 | 481 / 481 |
| Run 3 | 481 / 481 |

---

## Test Inventory

| Test | Function | Description |
|------|----------|-------------|
| T1 | `t1_healthy_fixed_response_baseline` | 4 providers × 4 responses each; exact Surface 1/2/3 healthy snapshot; epoch_count = 0 |
| T2 | `t2_total_silent_failure_baseline` | 4 providers × 0 responses; liveness_surface_evaluable=false; lwk=1.0; ratio=Some(0.0) |
| T3 | `t3_asymmetric_selective_suppression` | pid(4) silent; lwk > 0 and lwk ≥ kappa; distinguishable from healthy baseline |
| T4 | `t4_alternating_selective_suppression` | pid(2) gets 2/4 responses; lwk intermediate (0.0, 1.0); distinguishable from both extremes |
| T5 | `t5_symmetric_partial_suppression_defeats_surface2` | Symmetric 50% suppression; lwk = 0.0 (Surface 2 defeated); ratio = 0.5 |
| T6 | `t6_response_ratio_detects_symmetric_suppression_absent_injection` | Same trace; exact ratio = 0.5 confirmed as limited counter-signal |
| T7 | `t7_response_injection_masks_suppression_accounting` | 8 injected record_response() without sample() inflates ratio 0.5→1.0; lwk stays 0.0 |
| T8 | `t8_manipulated_telemetry_disconnected_from_vitality_and_send` | Asymmetric suppression + Active vitality → send succeeds; evidence timestamp unchanged |
| T9 | `t9_no_automatic_rotation_from_manipulation_trace` | Strongest injection trace; epoch_count = 0 (no rotation triggered) |

---

## Scripted Traces

### T1 — Healthy baseline

- 4 providers: `pid(1)`–`pid(4)` (each `[byte; 32]`)
- `StdRng::seed_from_u64(0)`, `SamplingStrategy::RandomK(1)`
- 16 calls to `pool.sample()` → `EpochPhase::Steady`
- `pool.record_response(pid(i))` × 4 for each `i ∈ {1,2,3,4}`
- **Surface 2**: `liveness_weighted_kappa = 0.0` (exact: log₂(4)/log₂(4) = 1.0 → 1.0 − 1.0 = 0.0)
- **Surface 3**: `response_total = 16`, `selection_total = 16`, `ratio = Some(1.0)`

### T2 — Total silent failure

- Same 4 providers, 16 seeded samples, zero `record_response()` calls
- **Surface 2**: `liveness_weighted_kappa = 1.0` (no responses → response_entropy = 0.0)
- `liveness_surface_evaluable = false` (response_total = 0)
- **Surface 3**: `response_total = 0`, `selection_total = 16`, `ratio = Some(0.0)`

### T3 — Asymmetric selective suppression

- 4 providers, 16 seeded samples
- `pool.record_response(pid(i))` × 4 for `i ∈ {1,2,3}`; `pid(4)` silent
- `response_total = 12`, `selection_total = 16`
- **Surface 2**: `liveness_weighted_kappa = 1.0 − log₂(3)/log₂(4)` (derived from `exposure_estimate().response_entropy_bits / log₂(4)`)
- `liveness_weighted_kappa > 0.0` (not healthy)
- `liveness_weighted_kappa ≥ kappa`; strictly `>` if pid(4) was selected (confirmed by seeded trace entropy > 0)

### T4 — Alternating selective suppression

- 2 providers, 8 seeded samples
- `pool.record_response(pid(1))` × 4; `pool.record_response(pid(2))` × 2
- `response_total = 6`, `selection_total = 8`
- **Surface 2**: `liveness_weighted_kappa = 1.0 − response_entropy_bits / log₂(2)` (derived from `exposure_estimate().response_entropy_bits`)
  - Analytical value: `response_entropy = −(2/3·log₂(2/3) + 1/3·log₂(1/3))` ≈ 0.918 → lwk ≈ 0.082
- `liveness_weighted_kappa ∈ (0.0, 1.0)`: intermediate, distinguishable from both healthy (0.0) and fully silent (1.0)

### T5 — Symmetric partial suppression

- 4 providers, 16 seeded samples
- `pool.record_response(pid(i))` × 2 for each `i ∈ {1,2,3,4}`
- **Surface 2**: `liveness_weighted_kappa = 0.0` (exact: response distribution remains uniform {1/4 each} → response_entropy = log₂(4) → lwk = 0.0)
- **Surface 3**: `response_total = 8`, `selection_total = 16`, `ratio = Some(0.5)`
- **Explicit record**: Balanced liveness weighting does not imply healthy participation when suppression is symmetric.

### T6 — Symmetric suppression, Surface 3 counter-signal

- Identical trace to T5
- **Exact output**: `response_total = 8`, `selection_total = 16`, `ratio = Some(0.5)` (limited counter-signal absent injection)

### T7 — Response injection

- Start: T5/T6 trace (8 responses from 16 selections, ratio = 0.5)
- **Injection (documented seam)**: `pool.record_response(pid(i))` × 2 for each `i ∈ {1,2,3,4}` — no `pool.sample()` call
  - `record_response()` increments `response_total` without requiring a prior `sample()` call
  - Numerator is freely inflateable (§S64, §S69 in `metrics.rs` docstring)
- **After injection**: `response_total = 16`, `selection_total = 16` (unchanged), `ratio = Some(1.0)` (masked)
- **Surface 2**: `liveness_weighted_kappa = 0.0` (injected calls restore uniform distribution)
- Both surfaces are masked; underlying 50% suppression is concealed

### T8 — Vitality orthogonality under asymmetric suppression

- Active bilateral corridor: `t0 = 0`, standard controls `(i=1.0, r=1.0, p=0.0)`
- Pool trace: T3 asymmetric suppression (pid(4) silent, 12 responses from 16 selections)
- **Evidence timestamp invariant**: `Active` at `t0+578_388`, `Warm` at `t0+578_389` — before and after send
- **Send**: `FlashSession::open_and_send_sim()` with unchanged `ctx.p = 0.0` → `Ok(())`
- **Orthogonality**: manipulated telemetry (`lwk > 0`) does not affect `ctx.p`, evidence timestamp, or send authorization
- **epoch_count = 0**

### T9 — No rotation from strongest injection trace

- Pool trace: T7 injection scenario (ratio masked to 1.0, lwk = 0.0 despite underlying 50% suppression)
- **epoch_count = 0**: strongest available manipulation does not trigger rotation through tested observation path
- Claim scoped to current implementation; does not preclude future policy additions

---

## Distinguishability Findings

| Scenario | Surface 1 (kappa) | Surface 2 (lwk) | Surface 3 (ratio) | Distinguishable from healthy? |
|----------|:-----------------:|:---------------:|:-----------------:|:-----------------------------:|
| Healthy (T1) | low (seeded) | **0.0** | **1.0** | baseline |
| Total silence (T2) | low (seeded) | 1.0 | 0.0 | ✓ (both surfaces) |
| Asymmetric (T3) | low (seeded) | **> 0.0** | 0.75 | ✓ (Surface 2 rises above kappa) |
| Alternating (T4) | low (seeded) | **~0.08** | 0.75 | ✓ (Surface 2 intermediate) |
| Symmetric 50% (T5/T6) | low (seeded) | **0.0** ← masked | **0.5** | ✓ only via Surface 3 |
| Symmetric + injection (T7) | low (seeded) | **0.0** ← masked | **1.0** ← masked | ✗ no surface detects it |

---

## Manipulability Finding

`record_response()` does not require a prior `sample()` call. The `response_total`
numerator in `recent_reported_response_ratio()` is freely inflateable by calling
`record_response()` without any relay attempt. After injecting 8 extra calls into a
50%-suppressed trace (8 genuine from 16 selections), the ratio inflates from `0.5` to `1.0`
and `liveness_weighted_kappa` remains `0.0`. Both Surface 2 and Surface 3 are masked
simultaneously.

This is the documented behavior noted in `OperationalTelemetrySnapshot::recent_reported_response_ratio()`:
> *"An adversary or buggy caller can inflate this value arbitrarily (see §S64, §S69)."*

---

## Authorized Policy Statement

No currently proven telemetry surface — individually or naively combined — is authorized for:

- automatic vitality changes
- send authorization or rejection
- rotation policy triggers
- relay routing decisions
- mailbox or corridor policy

This is confirmed structurally by T8 (send governed by Active vitality despite manipulated telemetry)
and T9 (no rotation triggered by strongest available manipulation trace).

---

## Production Source Modifications

None. The following production surfaces were not touched:

- `provider/pool/` — no source changes
- `core/vitality/` — no source changes
- `scp-transport/` — no source changes
- `relay/` — no source changes
- `ledger/` — no source changes
- TOLS κ behavior — unchanged
- Rotation policy — unchanged
- CLI, localhost, LAN, desktop, or hardware surfaces — unchanged
