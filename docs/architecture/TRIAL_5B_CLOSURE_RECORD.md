# Trial 5B — Closure Record

**Status**: PROVEN (reopened and re-closed; see §Reopening below)
**Date**: 2026-05-28 (original) / 2026-05-28 (reopened and re-closed same session)
**Verdict**: `A — TRIAL_5B_ADMISSIBLE_SURFACE_BOUNDED_AND_PROVEN`
**Predecessor gate**: `CORRIDOR_TRIAL_5B_ADMISSIBLE_SURFACE_IMPLEMENTATION_GATE.md`
**Baseline**: 481 passing (3 clean runs confirmed before original implementation)
**Corrective baseline**: 494 passing (original 13 tests) — confirmed before corrective work
**Final count**: 506 passing (494 + 12 new corrective tests) — 3 clean runs confirmed

---

## §Reopening — Discovered Defect and Corrective Action

After the original closure was recorded, an audit revealed that `AdmissibleExposureTracker`
had no finite automatic outstanding-receipt bound. Under `PoolRotationPolicy::Manual` with
no rotation, a caller could issue receipt-bearing selections indefinitely without terminal
outcomes or rotation, causing unbounded memory growth in `outstanding: HashMap<u64, [u8; 32]>`.

**Defect**: the original `with_admissible_tracking()` took no arguments, and the tracker
had no `max_outstanding_receipts` field. The `issue_receipt()` method inserted into
`outstanding` unconditionally.

**Verdicts during open period**:
- `B — TRIAL_5B_OUTSTANDING_RECEIPT_BOUND_UNRESOLVED`
- `B — TRIAL_5C_RECEIPT_RESOURCE_BOUND_INSUFFICIENT` (Trial 5C was blocked)

**Corrective changes** (all additive; no raw-surface, vitality, relay, or policy changes):

| File | Change |
|------|--------|
| `provider/pool/src/exposure.rs` | Added `ReceiptCapacityExhausted` variant to `AdmissibilityError`; added `max_outstanding_receipts: usize` field to `AdmissibleExposureTracker`; updated `new()` to accept the bound; updated `issue_receipt()` to check `outstanding.len() >= max_outstanding_receipts` BEFORE any state mutation |
| `provider/pool/src/lib.rs` | Changed `with_admissible_tracking()` to `with_admissible_tracking(max_outstanding_receipts: usize)`; changed `sample_with_receipts()` return type from `(ProviderQuorum<P>, Vec<SelectionReceipt>)` to `Result<(ProviderQuorum<P>, Vec<SelectionReceipt>), AdmissibilityError>`; added pre-selection capacity check before `sample_inner()` |
| `test/tests/trial5b.rs` | Updated `with_admissible_tracking()` calls to `with_admissible_tracking(1024)`; updated `sample_with_receipts()` call sites to `.unwrap()` the Result |
| `test/tests/trial5b_receipt_bound.rs` | New file — 12 corrective tests: RB1–RB4, RB5a, RB5b, RB6–RB11 (RB5 splits into two sub-tests; identifiers RB1–RB11 name 12 distinct test functions) |

**Re-closure condition**: all 12 corrective bound tests pass; all 13 original Trial 5B tests
remain green; Trials 2–4 remain green; 506 passing in 3 consecutive full-workspace runs.

---

## Files Modified (complete list including original and corrective)

| File | Change type | Summary |
|------|-------------|---------|
| `provider/pool/src/exposure.rs` | Additive | Added `SelectionReceipt`, `AdmissibilityError` (including `ReceiptCapacityExhausted`), `AdmissibleExposureTracker` with `max_outstanding_receipts` field and capacity-checking `issue_receipt()` |
| `provider/pool/src/metrics.rs` | Additive | Added `admissible_response_total`, `admissible_failure_total`, `admissible_selection_total` fields to `OperationalTelemetrySnapshot`; added `recent_admissible_response_ratio()` method |
| `provider/pool/src/lib.rs` | Additive | Added `admissible_tracker: Option<AdmissibleExposureTracker>` field; added `with_admissible_tracking(max_outstanding_receipts)` builder; refactored `sample()` to call `sample_inner()`; added `sample_with_receipts()` (returns `Result`), `record_admissible_response()`, `record_admissible_failure()`; updated `operational_telemetry()` to populate admissible fields; updated `do_rotate()` to call `drain_epoch()` |
| `test/tests/trial5b.rs` | Modified | Updated `with_admissible_tracking()` calls to pass bound `1024`; updated `sample_with_receipts()` call sites to unwrap Result |
| `test/tests/trial5b_receipt_bound.rs` | New file | 12 corrective bound tests |

No changes to: `provider/pool/src/sampling.rs`, `provider/pool/src/rotation.rs`, `provider/pool/src/liveness.rs`, `provider/pool/src/reputation.rs`, `provider/pool/src/admission.rs`, `provider/pool/src/eviction.rs`, `provider/pool/src/dummy.rs`, any crate outside `scp-provider-pool`, raw telemetry semantics, vitality modules, transport/corridor modules, relay or ledger modules, send authorization, TOLS policy.

---

## Raw Telemetry Compatibility — Trials 2–4 Unchanged

Trials 2, 3, and 4 were run without modification and passed identically after both the
original implementation and the corrective changes:

- `cargo test --test trial2`: 7/7 passed
- `cargo test --test trial3`: 8/8 passed
- `cargo test --test trial4`: 9/9 passed

Compatibility is guaranteed by five properties from the gate document §8:

1. Raw API signatures unchanged: `sample()`, `record_response()`, `record_failure()`, `operational_telemetry()` retain their exact current signatures.
2. Raw counters accumulate identically: `ExposureTracker::record()` and `ExposureTracker::record_response()` are unchanged.
3. Admissible tracker is opt-in: `Option<AdmissibleExposureTracker>` is `None` by default; all trial 2–4 pools do not call `with_admissible_tracking()`.
4. Trial 4 T7/T8 manipulability evidence is preserved on the raw surface.
5. All new tests are in `test/tests/trial5b.rs` and `test/tests/trial5b_receipt_bound.rs`; no line of any trial 2–4 test file was modified.

---

## New Admissible Surfaces

### `SelectionReceipt` (in `exposure.rs`, public via `lib.rs`)

Opaque receipt returned by `sample_with_receipts()`. Binds `epoch_count` (u32), `observation_id` (u64), and `provider_id` ([u8; 32]). Fields are `pub(crate)`; public accessor methods `epoch_count()`, `observation_id()`, `provider_id()`, and `with_provider_id()` are exposed for test usage.

### `AdmissibilityError` (in `exposure.rs`, public via `lib.rs`)

Enum with variants: `NotConfigured`, `StaleEpoch`, `UnknownReceipt`, `ProviderMismatch`, `CounterExhausted`, **`ReceiptCapacityExhausted`** (added in corrective pass).

`ReceiptCapacityExhausted` is returned by `sample_with_receipts()` when outstanding receipts
equal the configured `max_outstanding_receipts` bound. It is structurally distinct from all
other variants and can be deterministically matched by callers.

### `AdmissibleExposureTracker` (in `exposure.rs`, `pub(crate)`)

Internal tracker holding: `max_outstanding_receipts: usize`, `outstanding: HashMap<u64, [u8; 32]>` (bounded by `max_outstanding_receipts`), `next_observation_id: u64`, `current_epoch_count: u32`, `admissible_response_total: u64`, `admissible_failure_total: u64`, `admissible_selection_total: u64`, `admissible_appearances: HashMap<[u8; 32], u64>`, `reset_policy`.

**Invariant**: `outstanding.len() <= max_outstanding_receipts` at all times.

### New `OperationalTelemetrySnapshot` fields (in `metrics.rs`)

- `admissible_response_total: u64` — zero when tracker absent
- `admissible_failure_total: u64` — zero when tracker absent
- `admissible_selection_total: u64` — zero when tracker absent

### New `OperationalTelemetrySnapshot` method (in `metrics.rs`)

- `recent_admissible_response_ratio() -> Option<f64>` — `None` when `admissible_selection_total == 0`

### New `ProviderPool` builder and methods (in `lib.rs`)

- `with_admissible_tracking(max_outstanding_receipts: usize)` — opt-in builder; enables the tracker with the given finite bound
- `sample_with_receipts(&mut self, rng) -> Result<(ProviderQuorum<P>, Vec<SelectionReceipt>), AdmissibilityError>` — returns `Err(ReceiptCapacityExhausted)` before selection when outstanding count is at bound; calls `sample_inner()` for raw accounting only when selection proceeds (no double-counting)
- `record_admissible_response(&mut self, receipt) -> Result<(), AdmissibilityError>`
- `record_admissible_failure(&mut self, receipt) -> Result<(), AdmissibilityError>`

---

## Receipt Lifecycle

1. **Pre-selection capacity check**: `sample_with_receipts()` checks `outstanding.len() >= max_outstanding_receipts` BEFORE calling `sample_inner()`. On failure: returns `Err(ReceiptCapacityExhausted)` with no state change.

2. **Issuance**: `sample_inner()` performs raw `ExposureTracker::record()` exactly once. Then `AdmissibleExposureTracker::issue_receipt()` is called per provider. Each call re-checks capacity (for multi-provider quorums where partial issuance may occur), increments `next_observation_id`, inserts into `outstanding`, and increments `admissible_selection_total`.

3. **Terminal outcome (response path)**: `record_admissible_response(receipt)` checks four conditions: (1) epoch not stale, (2) `observation_id` in outstanding map, (3) stored `provider_id` matches receipt's `provider_id`, (4) `outstanding.remove()` succeeds atomically. On success: `admissible_response_total++`, `admissible_appearances[pid]++`. On failure: returns appropriate `AdmissibilityError`. Outstanding count decrements by 1, restoring one unit of capacity.

4. **Terminal outcome (failure path)**: same four conditions as response; on success: `admissible_failure_total++`. Outstanding count decrements by 1.

5. **Epoch drain**: `do_rotate()` calls `adm.drain_epoch(new_epoch_count)` after `epoch_count` is incremented. `outstanding.clear()` removes all pending receipts, restoring full capacity. `current_epoch_count` is updated. If `ExposureResetPolicy` dictates a reset, admissible counters (but NOT `next_observation_id`) are cleared.

---

## Outstanding Receipt Bound

**Bound invariant**: `outstanding.len() <= max_outstanding_receipts` at all times.

**Enforcement**: `issue_receipt()` checks `outstanding.len() >= max_outstanding_receipts` before inserting. `sample_with_receipts()` also checks before calling `sample_inner()` to ensure provider selection never occurs when the entire quorum would be refused.

**Capacity restoration**:
- One unit per `record_admissible_response()` that passes all checks (outstanding.remove)
- One unit per `record_admissible_failure()` that passes all checks (outstanding.remove)
- Full restoration via `drain_epoch()` on epoch rotation

**Bound configuration**: callers must pass a positive `usize` to `with_admissible_tracking()`. A value of `0` means no receipts may ever be outstanding. A value matching the expected maximum in-flight request window is the recommended configuration.

**`next_observation_id` is never reset**: it accumulates for the pool lifetime. This ensures no ID reuse after drain (stale receipts are rejected by epoch check before ID lookup). Counter exhaustion at u64::MAX returns `Err(CounterExhausted)`.

**Reset policy mirroring**: when `ExposureResetPolicy::OnRotation` fires, admissible counters (`admissible_response_total`, `admissible_failure_total`, `admissible_selection_total`, `admissible_appearances`) are cleared to match raw tracker behavior.

---

## 13 Original Deterministic Tests (trial5b.rs)

| # | Test name | What it proves |
|---|-----------|----------------|
| 1 | `t1_valid_paired_response_is_admissible` | `admissible_response_total = 1`; `admissible_selection_total = 1`; `recent_admissible_response_ratio() = Some(1.0)`; raw `response_total = 0` |
| 2 | `t2_response_without_receipt_excluded_from_admissible` | `admissible_response_total = 0`; Option C discrepancy visible |
| 3 | `t3_duplicate_response_for_one_receipt_rejected` | `Err(UnknownReceipt)` on second presentation; `admissible_response_total = 1` |
| 4 | `t4_wrong_provider_response_rejected` | `Err(ProviderMismatch)`; original receipt still outstanding |
| 5 | `t5_valid_paired_failure_is_admissible` | `admissible_failure_total = 1`; receipt consumed |
| 6 | `t6_failure_without_receipt_excluded_from_admissible` | `admissible_failure_total = 0` |
| 7 | `t7_response_after_failure_for_same_receipt_rejected` | `Err(UnknownReceipt)` after failure consumes receipt |
| 8 | `t8_stale_epoch_receipt_rejected` | `Err(StaleEpoch)`; `epoch_count = 1` |
| 9 | `t9_multi_provider_receipts_are_distinct` | 3 distinct observation_ids; all three accepted |
| 10 | `t10_symmetric_suppression_visible_in_admissible_ratio` | `recent_admissible_response_ratio() = Some(0.5)` |
| 11 | `t11_injection_masks_raw_cannot_mask_admissible` | raw ratio `1.0`; admissible ratio `0.5` — injection masking demonstrated |
| 12 | `t12_admissible_tracker_opt_in_inactive_by_default` | `Err(NotConfigured)` without `with_admissible_tracking()` |
| 13 | `t13_vitality_send_rotation_policy_untouched` | `epoch_count = 0`; `p = 0.0` declared constant; no admissible field on `ConvergencePressure` |

---

## 12 Corrective Bound Tests (trial5b_receipt_bound.rs)
<!-- RB1–RB11 names 11 identifiers; RB5 splits into RB5a and RB5b = 12 test functions total. -->

| # | Test name | What it proves |
|---|-----------|----------------|
| RB1 | `rb1_accept_below_bound_refuse_at_bound` | 3 successful issuances below bound; 4th returns `ReceiptCapacityExhausted`; `admissible_selection_total = 3`; `selection_total = 3` |
| RB2 | `rb2_capacity_failure_before_raw_accounting` | Raw `selection_total` unchanged after capacity refusal — selection did not occur |
| RB3 | `rb3_terminal_response_restores_capacity` | Valid response consumes receipt; `admissible_response_total = 1`; next sample succeeds |
| RB4 | `rb4_terminal_failure_restores_capacity` | Valid failure consumes receipt; `admissible_failure_total = 1`; next sample succeeds |
| RB5a | `rb5a_duplicate_response_does_not_free_extra_capacity` | `Err(UnknownReceipt)` on duplicate; `admissible_response_total = 1`; capacity restored correctly |
| RB5b | `rb5b_provider_mismatch_does_not_free_capacity` | `Err(ProviderMismatch)` does not remove outstanding entry; capacity still full; original valid |
| RB6 | `rb6_rotation_drain_restores_capacity_stale_receipts_inadmissible` | `drain_epoch()` restores capacity; old receipt returns `Err(StaleEpoch)` not `Err(ReceiptCapacityExhausted)` |
| RB7 | `rb7_raw_only_sampling_unchanged` | `sample()` unaffected by admissible tracking; `admissible_selection_total = 0`; `selection_total = 5` |
| RB8 | `rb8_bound_zero_refuses_all_receipt_bearing_samples` | Bound=0 immediately refuses all receipt-bearing samples; `sample()` works normally |
| RB9 | `rb9_capacity_error_distinct_from_other_admissibility_errors` | All 6 `AdmissibilityError` variants structurally distinguishable via exhaustive match |
| RB10 | `rb10_no_policy_coupling_from_capacity_refusal` | 10 refused calls leave `epoch_count = 0`; no rotation triggered |
| RB11 | `rb11_multi_provider_quorum_partial_receipt_at_near_bound` | k=3, bound=3: partial quorum issued when only 2 slots remain; `admissible_selection_total = 5` |

---

## Three Full-Suite Clean Run Totals (post-corrective)

All runs: `cargo test --workspace`

| Run | Total passing | Failing |
|-----|--------------|---------|
| Run 1 (post-corrective) | 506 | 0 |
| Run 2 | 506 | 0 |
| Run 3 | 506 | 0 |

Corrective delta: +12 tests (RB1–RB11 in `trial5b_receipt_bound.rs`; RB5 has two sub-tests a and b = 12 total).

---

## No Policy Coupling

- No admissible surface field populates `SimVitalityEvaluationContext.p`. Verified in T13.
- No admissible surface field triggers `maybe_rotate()` or `force_rotate()`. Verified: `epoch_count = 0` after injection trace in T13; `epoch_count = 0` after 10 capacity-refused calls in RB10.
- No admissible surface field gates sends, relay decisions, routing, TOLS policy, or admission/eviction.
- `ConvergencePressure` has no `admissible_*` field — structural proof via successful compilation.
- All new admissible surface fields and methods contain the word `admissible` in their name.
- Capacity refusal (`ReceiptCapacityExhausted`) does not trigger any rotation or policy change.

## `SimVitalityEvaluationContext.p` Not Populated

Confirmed: `SimVitalityEvaluationContext` is constructed in T13 with `p = 0.0` — a literal constant, not derived from any pool telemetry field. No code path from `operational_telemetry()`, `convergence_pressure()`, `record_admissible_response()`, `record_admissible_failure()`, or `sample_with_receipts()` touches any vitality type.
