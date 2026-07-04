# Trial 5C — Closure Record

**Status**: PROVEN
**Date**: 2026-05-28
**Verdict**: `A — TRIAL_5C_ADMISSIBLE_SURFACE_ADVERSARIALLY_VALIDATED`
**Predecessor gate**: `CORRIDOR_TRIAL_5C_ADMISSIBLE_SURFACE_ADVERSARIAL_VALIDATION_PLAN.md`
**Predecessor baseline**: 506 passing, 0 failing (3 clean runs — Trial 5B-R re-closure)
**Final count**: 517 passing (506 + 11 new Trial 5C tests) — 3 clean runs confirmed

---

## Permitted Claim (earned)

> Under deterministic adversarial reporting and issuance traces, raw telemetry remains
> manipulable as already characterized in Trials 2–4, while the bounded admissible
> paired-outcome surface excludes invalid terminal outcomes, preserves causal accounting
> under the tested manipulation classes, and remains disconnected from automatic policy.

---

## Pre-Work: Trial 5B Closure Record Fix

Before writing any tests, the Trial 5B closure record at
`docs/architecture/TRIAL_5B_CLOSURE_RECORD.md` was audited for self-consistency.

**Defect found**: The §Reopening corrective tests entry described "12 corrective tests
(RB1–RB11, where RB5 has two sub-tests a and b)" but the phrase "RB1–RB11" visually
implies 11 items. A reader could mis-count.

**Fix applied**: The row was updated to read "12 corrective tests:
RB1–RB4, RB5a, RB5b, RB6–RB11 (RB5 splits into two sub-tests; identifiers RB1–RB11
name 12 distinct test functions)" and a comment was added to the section heading to
make the arithmetic self-evident. No test counts or code were changed.

---

## Adversarial Class Coverage (after Trial 5C)

| Adversarial class | Proven by | Status |
|---|---|---|
| Valid paired response | T1, TC4 | Fully proven |
| Valid paired failure | T5 | Fully proven |
| Unpaired response injection | T2, T11, TC5 (failure injection variant) | Fully proven |
| Unpaired failure injection | T6, **TC5** | **Fully proven** (dual-surface comparison added) |
| Duplicate response | T3, **TC6** | **Fully proven** (raw vs admissible comparison added) |
| Duplicate failure | **TC1** | **Fully proven** (new class) |
| Response after accepted failure | T7 | Fully proven |
| Failure after accepted response | **TC2** | **Fully proven** (new class) |
| Wrong-provider response | T4 | Fully proven |
| Wrong-provider failure | **TC3** | **Fully proven** (new class) |
| Stale receipt after epoch rotation | T8, **TC7** | **Fully proven** (raw vs admissible comparison added) |
| Symmetric selective suppression | T10, **TC4** | **Fully proven** (dual-surface comparison added) |
| Raw masking through injected responses | T11, **TC11** | Fully proven (injection trace in policy-bridge test) |
| Outstanding-receipt exhaustion/bound | RB1–RB11 (corrective), **TC8, TC9, TC10** | **Fully proven** |
| No policy bridge | T13, RB10, **TC11** | Fully proven |

---

## Files Modified

| File | Change type | Summary |
|------|-------------|---------|
| `test/tests/trial5c.rs` | New file | 11 adversarial validation tests (TC1–TC11) |
| `docs/architecture/TRIAL_5B_CLOSURE_RECORD.md` | Correction | Corrective tests entry made unambiguous (RB5a/RB5b split documented explicitly) |

No production source was modified. All changes are additive.

---

## 11 Trial 5C Tests

| # | Test name | Category | What it proves |
|---|-----------|----------|----------------|
| TC1 | `tc1_duplicate_failure_rejected` | A | `Err(UnknownReceipt)` on 2nd failure for same receipt; `admissible_failure_total = 1` |
| TC2 | `tc2_failure_after_accepted_response_rejected` | A | `Err(UnknownReceipt)` when failure attempted after response consumed receipt; `admissible_failure_total = 0` |
| TC3 | `tc3_wrong_provider_failure_rejected` | A | `Err(ProviderMismatch)` for wrong-provider failure; `admissible_failure_total = 0`; original receipt still outstanding |
| TC4 | `tc4_symmetric_suppression_raw_vs_admissible` | B | Both raw and admissible surfaces report `Some(0.5)` on honest partial reporting; agreement without manipulation |
| TC5 | `tc5_unpaired_failure_injection_raw_vs_admissible` | B | 4 raw `record_failure()` calls leave `admissible_failure_total = 0`; admissible is unreachable by unpaired failures |
| TC6 | `tc6_duplicate_response_raw_vs_admissible` | B | Raw `response_total = 2`; admissible `response_total = 1`; raw inflated, admissible protected |
| TC7 | `tc7_stale_epoch_raw_vs_admissible` | B | `Err(StaleEpoch)` on admissible; raw `record_response()` unaffected by epoch; dual-surface discrepancy |
| TC8 | `tc8_outstanding_accumulates_until_bound` | C | 20 receipts fill bound; 21st returns `ReceiptCapacityExhausted`; raw counters exact; epoch unchanged |
| TC9 | `tc9_drain_epoch_clears_all_outstanding` | C | `drain_epoch()` restores capacity; stale receipts return `Err(StaleEpoch)`; `next_observation_id` preserved (≥3) |
| TC10 | `tc10_outstanding_bounded_by_max_not_automatic_eviction` | C | 10 issuances succeed; 11th fails at exact bound; no automatic eviction before bound; policy unchanged |
| TC11 | `tc11_admissible_surface_read_only_after_injection_trace` | D | Full injection trace (8 receipts, 4 admissible responses, 8 raw injections, 4 raw failures); `epoch_count = 0`; `p = 0.0` declared constant; admissible ratio `0.5`, raw ratio `1.0`; `ConvergencePressure` has no admissible field |

---

## Diagnostic Limitation Boundary (preserved)

1. Rejected inadmissible events are not separately counted — no rejection counter exists in
   the implementation. Tests TC1, TC2, TC3, TC6 prove counters are not inflated; they do not
   claim a separate rejection count is visible.

2. `UnknownReceipt` cannot distinguish "never issued" from "already consumed" at the API level.
   TC1 and TC2 acknowledge this explicitly: both duplicate-terminal and post-consumption attempts
   return `UnknownReceipt`; tests prove only the absence of inflation, not the reason category.

3. Tests prove invalid events do NOT inflate admissible accounting — see TC1–TC3, TC6–TC7.

4. Tests do NOT claim finer-grained rejection observability than the API provides.

---

## No Policy Coupling Confirmed

| Capability | Evidence in Trial 5C |
|---|---|
| `epoch_count` unchanged by any injection trace | TC8, TC10, TC11: `epoch_count = 0` throughout |
| `SimVitalityEvaluationContext.p` not pool-derived | TC11: `p_declared = 0.0` literal constant |
| `ConvergencePressure` has no admissible_* field | TC11: structural proof via successful compilation |
| Raw liveness state (`record_failure`) does not reach admissible surface | TC5: `admissible_failure_total = 0` after 4 raw failures |
| Rotation not triggered by admissible or raw injection | TC11: `epoch_count = 0` after full injection trace |

---

## Three Full-Suite Clean Run Totals (post-Trial 5C)

All runs: `cargo test --workspace`

| Run | Total passing | Failing |
|-----|--------------|---------|
| Run 1 | 517 | 0 |
| Run 2 | 517 | 0 |
| Run 3 | 517 | 0 |

Delta from predecessor: +11 tests (TC1–TC11 in `test/tests/trial5c.rs`).

---

## Raw Telemetry Compatibility — Trials 2–4 Unchanged

Verified after Trial 5C implementation:

- `cargo test --test trial2`: 7/7 passed
- `cargo test --test trial3`: 8/8 passed
- `cargo test --test trial4`: 9/9 passed
- `cargo test --test trial5b`: 13/13 passed
- `cargo test --test trial5b_receipt_bound`: 12/12 passed

No line of any prior trial test file was modified.
