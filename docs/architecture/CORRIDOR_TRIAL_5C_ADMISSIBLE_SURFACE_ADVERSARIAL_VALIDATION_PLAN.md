# Trial 5C — Admissible Surface Adversarial Validation Plan

**Status**: BLOCKED — `B — TRIAL_5C_RECEIPT_RESOURCE_BOUND_INSUFFICIENT` (superseded by re-resolution below)
**Current status**: BLOCKED — awaiting authorization after `A — TRIAL_5B_ADMISSIBLE_SURFACE_BOUNDED_AND_PROVEN`
**Authorized by**: Split-decision adjudication 2026-05-28
**Predecessor gate**: `TRIAL_5B_CLOSURE_RECORD.md` (re-closed after corrective bound implementation)
**Branch**: no branch yet — planning pass only
**Predecessor baseline**: 506 passing, 0 failing (3 clean runs after corrective implementation)
**Objective**: Determine whether the new admissible paired-outcome telemetry surface remains accurate under the full family of deterministic manipulation traces already shown to mislead raw telemetry.

> **Blocking history**: Trial 5C was initially authorized on 2026-05-28 with predecessor baseline
> 494 passing. A post-closure audit of Trial 5B discovered that `AdmissibleExposureTracker` had
> no finite automatic outstanding-receipt bound, producing verdict
> `B — TRIAL_5C_RECEIPT_RESOURCE_BOUND_INSUFFICIENT`. Trial 5C was blocked until Trial 5B
> earned `A — TRIAL_5B_ADMISSIBLE_SURFACE_BOUNDED_AND_PROVEN` through the corrective
> `with_admissible_tracking(max_outstanding_receipts)` implementation. Trial 5C may now be
> authorized with the corrected predecessor baseline of 506 passing.

> **Scope constraint**: Trial 5C is a validation trial for the new measurement surface. It is not a policy integration trial. No production source modifications are authorized during or after Trial 5C.

---

## Permitted claim for Trial 5C (if earned)

> Under deterministic adversarial response-reporting scenarios, raw provider telemetry may remain manipulable while the additive admissible paired-outcome surface excludes unpaired, duplicate, mismatched, and stale outcomes without triggering any automatic policy.

---

## Audit 1 — Inventory of what Trial 5B already proved

The 13 Trial 5B tests map to the adversarial class table as follows:

| Adversarial class | Trial 5B test | Status | Additional Trial 5C proof needed? |
|---|---|---|---|
| Valid paired response | T1 `t1_valid_paired_response_is_admissible` | **Proven** | No — dual-surface accounting already shown (raw `response_total = 0`, admissible = 1) |
| Valid paired failure | T5 `t5_valid_paired_failure_is_admissible` | **Proven** | No |
| Unpaired response injection | T2 `t2_response_without_receipt_excluded_from_admissible`, T11 `t11_injection_masks_raw_cannot_mask_admissible` | **Proven** | T11 already provides the dual-surface injection comparison. No additional needed. |
| Unpaired failure injection | T6 `t6_failure_without_receipt_excluded_from_admissible` | **Partial** | T6 shows admissible `failure_total = 0` for raw failure call, but does not show the raw surface comparison. A dual-surface composition proof for failure injection is needed. |
| Duplicate response | T3 `t3_duplicate_response_for_one_receipt_rejected` | **Proven** | No — `admissible_response_total = 1`, not 2; `Err(UnknownReceipt)` returned |
| Duplicate failure | _(none)_ | **Missing** | Yes — must prove `Err(UnknownReceipt)` on second failure for same receipt; `admissible_failure_total = 1`, not 2 |
| Response after accepted failure | T7 `t7_response_after_failure_for_same_receipt_rejected` | **Proven** | No |
| Failure after accepted response | _(none)_ | **Missing** | Yes — must prove `Err(UnknownReceipt)` when failure presented after the receipt's response path already succeeded |
| Wrong-provider receipt use | T4 `t4_wrong_provider_response_rejected` | **Partial** | T4 shows `Err(ProviderMismatch)` for wrong-provider response. No dual-surface comparison for failure path. Trial 5C should add wrong-provider failure. |
| Stale receipt after epoch rotation | T8 `t8_stale_epoch_receipt_rejected` | **Proven** | No |
| Symmetric selective suppression | T10 `t10_symmetric_suppression_visible_in_admissible_ratio` | **Partial** | T10 shows admissible ratio 0.5 for 2/4 responses. Raw surface not compared in T10. A raw-versus-admissible comparison for symmetric suppression is needed. |
| Raw masking through injected responses | T11 `t11_injection_masks_raw_cannot_mask_admissible` | **Proven** | No — this is the strongest dual-surface test; raw ratio 1.0, admissible ratio 0.5 |
| Outstanding-receipt exhaustion/bound behavior | _(none)_ | **Missing** | Yes — must characterize the bound and test behavior at the boundary |

**Summary**: 6 of 13 classes are fully proven. 4 are partially proven with a missing dual-surface comparison or failure-path variant. 3 are entirely unproven in Trial 5B.

---

## Audit 2 — Raw-versus-admissible comparison traces

The following deterministic sequences must be proven in Trial 5C, comparing both surfaces for each scenario.

### Scenario 1 — Healthy paired baseline

Setup: use `sample_with_receipts()`, present all receipts to `record_admissible_response()`, also call `record_response()` for each (raw path parallel).

| Surface | Expected result | What this proves |
|---|---|---|
| Raw `recent_reported_response_ratio()` | `Some(1.0)` | Raw responds to its own API |
| Admissible `recent_admissible_response_ratio()` | `Some(1.0)` | Both surfaces agree on healthy behavior |

*Note*: Partial proof already exists in T1 and T9. T9 is the closest — it tests admissible only. This scenario should add explicit raw comparison to T9's trace.

### Scenario 2 — Symmetric partial suppression without injection

Setup: 4 receipts issued via `sample_with_receipts()`. 2 admissible responses presented. 2 raw `record_response()` calls also made (raw half-response). No injected unpaired raw responses.

| Surface | Expected result | What this proves |
|---|---|---|
| Raw `recent_reported_response_ratio()` | `Some(0.5)` | Raw and admissible agree on honest partial reporting |
| Admissible `recent_admissible_response_ratio()` | `Some(0.5)` | Admissible is consistent with raw when there is no manipulation |

*Note*: T10 proves the admissible side only. This scenario adds the raw side to T10's trace.

### Scenario 3 — Symmetric partial suppression plus injected unpaired responses

Setup: 4 receipts issued. 2 admissible responses presented. 8 additional raw `record_response()` injections. (Reproduces T11 family with symmetric suppression as the baseline, not zero-receipt scenario.)

| Surface | Expected result | What this proves |
|---|---|---|
| Raw `recent_reported_response_ratio()` | inflated toward `Some(1.0)` | Raw can be masked by injection even when underlying admissible ratio is suppressed |
| Admissible `recent_admissible_response_ratio()` | `Some(0.5)` unchanged | Admissible is immune to raw injection; suppression remains visible |

*Note*: T11 is the partial proof of this. T11 uses zero-receipt pool as baseline. This scenario should prove the pattern also holds when the pool is already responding on both surfaces, not just from zero.

### Scenario 4 — Duplicate-response inflation attempt

Setup: 1 receipt issued. `record_admissible_response()` called twice with same receipt. Raw `record_response()` called twice.

| Surface | Expected result | What this proves |
|---|---|---|
| Raw `response_total` | 2 (counts both raw calls) | Raw can be inflated by duplicate recording |
| Admissible `admissible_response_total` | 1 (second call returns `Err(UnknownReceipt)`) | Admissible cannot be inflated by presenting the same receipt twice |
| Admissible `admissible_selection_total` | 1 | Selection count unaffected by duplicate outcome attempts |

### Scenario 5 — Wrong-provider outcome attempt

Setup: pool with 2 providers A and B. Receipt for A issued. `record_admissible_response()` called with receipt but `provider_id` field swapped to B.

| Surface | Expected result | What this proves |
|---|---|---|
| Admissible `record_admissible_response` result | `Err(ProviderMismatch)` | Cross-provider outcome cannot inflate admissible |
| Admissible `admissible_response_total` | 0 | Wrong-provider rejection is total |
| Receipt is still outstanding after rejection | Yes | Receipt not consumed by rejected attempt; can be re-presented with correct provider |

*Note*: Extends T4 to verify the receipt remains outstanding after ProviderMismatch. T4 already proves the error variant and zero count.

### Scenario 6 — Stale-epoch outcome attempt after rotation

Setup: receipt issued in epoch 0. `do_rotate()` called (epoch 1). `record_admissible_response()` called with the stale receipt.

| Surface | Expected result | What this proves |
|---|---|---|
| Admissible `record_admissible_response` result | `Err(StaleEpoch)` | Epoch boundary is enforced before observation-ID lookup |
| Admissible `admissible_response_total` | 0 | Stale outcome cannot inflate admissible |
| Raw surface after rotation | Unaffected — rotation increments epoch but does not alter raw `response_total` | Raw and admissible epoch semantics are independent |

*Note*: T8 proves most of this. This scenario adds the raw comparison.

### Scenario 7 — Bounded outstanding-receipt exhaustion attempt

Setup: issue N receipts via `sample_with_receipts()` without calling any `record_admissible_response()` or `record_admissible_failure()`. Measure HashMap size. Then call `do_rotate()`. Verify drain.

| Observable | Expected behavior | What this proves |
|---|---|---|
| `outstanding.len()` before rotation | Grows proportionally to number of `sample_with_receipts()` calls | No automatic per-call eviction exists |
| `admissible_selection_total` | Increases monotonically | Selection counter is not blocked by outstanding growth |
| Raw selection telemetry | Continues to update | Outstanding HashMap growth does not block raw telemetry |
| `outstanding.len()` after `do_rotate()` | 0 | `drain_epoch()` is the only mechanism clearing the outstanding set |
| Any issuance refused before rotation | NO — `issue_receipt()` succeeds until `CounterExhausted` at `u64::MAX` | There is no per-call capacity limit; the bound is u64 overflow, not HashMap size |

---

## Audit 3 — Rejected-event visibility

Based on the Trial 5B implementation (`exposure.rs` and the closure record):

### What the API exposes for inadmissible events

`record_admissible_response()` and `record_admissible_failure()` return `Result<(), AdmissibilityError>`. The error variants are:

| Error variant | When returned |
|---|---|
| `NotConfigured` | Admissible tracker not enabled (`with_admissible_tracking()` not called) |
| `StaleEpoch` | Receipt's `epoch_count` does not match the tracker's `current_epoch_count` |
| `UnknownReceipt` | `observation_id` not found in the outstanding map |
| `ProviderMismatch` | `observation_id` found but stored `provider_id` does not match receipt's `provider_id` |
| `CounterExhausted` | `next_observation_id` overflowed `u64::MAX` (unreachable in practice) |

### Are rejected/unpaired attempts counted?

**No.** A `Result::Err` return means the admissible counter was not incremented. There is no separate "rejected attempts" counter in the current implementation.

**Consequence for Trial 5C**: Trial 5C must not claim that the admissible surface exposes a count of rejected events. It does not.

### Are rejection reasons distinguishable?

**Yes**, with one ambiguity:
- `StaleEpoch` vs `UnknownReceipt` vs `ProviderMismatch` are structurally distinct.
- **Ambiguity**: `UnknownReceipt` is returned both for a receipt that was never issued AND for a receipt that was already consumed (duplicate terminal outcome). The caller cannot distinguish "never seen" from "already consumed" via the error variant alone. Both return `Err(UnknownReceipt)`.

This is a diagnosed diagnostic gap: **duplicate terminal outcome rejection is indistinguishable from unknown-receipt rejection** at the API level. Trial 5C tests should acknowledge this.

### Does a rejected admissible event still affect raw telemetry?

**No.** Raw telemetry is updated by completely separate API calls:
- `record_response()` (raw) — untouched by `record_admissible_response()` (admissible)
- `record_failure()` (raw) — untouched by `record_admissible_failure()` (admissible)
- Raw selection is recorded by `sample()` or `sample_inner()` at selection time, not at outcome time.

An `Err` return from an admissible call has zero effect on raw counters. This is structurally guaranteed by the absence of any `record_response()` or `record_failure()` call inside `record_admissible_response()` / `record_admissible_failure()`.

---

## Audit 4 — Resource-bound adversary

The outstanding-receipt set is a `HashMap<u64, [u8; 32]>`. The following characterizes its behavior under adversarial use:

### Step 1: Create selections without terminal outcomes

An adversary who calls `sample_with_receipts()` repeatedly without calling `record_admissible_response()` or `record_admissible_failure()` will cause `outstanding` to grow by one entry per provider per call. There is no automatic eviction.

**Bound**: There is no capacity limit. The HashMap grows until:
- `drain_epoch()` is called (via rotation)
- `u64::MAX` overflows `next_observation_id` → `CounterExhausted` (effectively unreachable)

### Step 2: Behavior at the "bound"

There is no "bound reached" rejection for HashMap size. The implementation continues to issue receipts as long as `next_observation_id` can be incremented. The documented "bound" is epoch rotation, not a size guard.

**Adversarial implication**: Under `PoolRotationPolicy::Manual` with no `force_rotate()` calls, a pool with the admissible tracker enabled accumulates `outstanding` entries indefinitely. This is a potential unbounded-memory attack surface if the adversary controls the selection rate.

**Documented**: This scenario is recorded in the `AdmissibleExposureTracker::outstanding` field comment in `exposure.rs`: "Bounded by epoch rotation — operator must call `force_rotate()` periodically."

**Trial 5C must confirm**: No automatic size guard exists at the `issue_receipt()` level; only rotation bounds the set. This is a documented operator responsibility, not a protocol invariant.

### Step 3: Raw selection telemetry under adversarial issuance

`sample_with_receipts()` calls `sample_inner()` which updates the raw `ExposureTracker`. Raw selection telemetry continues to accumulate regardless of outstanding HashMap growth. The two are independent.

### Step 4: Rotation behavior

`do_rotate()` calls `adm.drain_epoch(new_epoch_count)` which:
1. Calls `outstanding.clear()` — unconditionally removes all pending receipts
2. Updates `current_epoch_count`
3. If `ExposureResetPolicy` indicates a counter reset: clears admissible totals (NOT `next_observation_id`)

After rotation, any pre-rotation receipts return `Err(StaleEpoch)` before the `outstanding` lookup even runs (epoch check fires first). There is no window where a drained receipt could be re-accepted.

### Summary of resource-bound finding

| Property | Value |
|---|---|
| Automatic per-call capacity limit | **None** |
| Effective bound mechanism | `drain_epoch()` on every rotation |
| Behavior at u64 observation_id overflow | `Err(CounterExhausted)` |
| Memory growth pattern | Linear in `k × (calls between rotations)` |
| Adversarial worst case | `PoolRotationPolicy::Manual` + no `force_rotate()` = unbounded |
| `next_observation_id` after drain | **Preserved** — not reset; prevents ID reuse after drain |

---

## Audit 5 — No policy bridge

The following search confirms that neither raw nor admissible telemetry currently feeds policy.

### Admissible surface read sites in production code

From `grep` of `admissible_response_total`, `admissible_failure_total`, `recent_admissible_response_ratio`, `record_admissible_response`, `record_admissible_failure` in `provider/pool/src/`:

| Read site | File | Purpose | Feeds policy? |
|---|---|---|---|
| `admissible_response_total` field | `exposure.rs`, `metrics.rs` | Stored in tracker; copied to `OperationalTelemetrySnapshot` | **No** |
| `admissible_failure_total` field | `exposure.rs`, `metrics.rs` | Stored in tracker; copied to `OperationalTelemetrySnapshot` | **No** |
| `recent_admissible_response_ratio()` | `metrics.rs` | Computes ratio from snapshot fields; returns `Option<f64>` | **No** — read-only observable, never passed to rotation/send/vitality |
| `record_admissible_response()` call site | `lib.rs:469` | Returns `Result` to caller; no side-effect on pool state beyond tracker counters | **No** |
| `record_admissible_failure()` call site | `lib.rs:485` | Same | **No** |

### What admissible fields do NOT touch

| Capability | Evidence |
|---|---|
| `SimVitalityEvaluationContext.p` | T13 structural proof: `p = 0.0` is a test literal; no pool method sets it |
| `maybe_rotate()` / `force_rotate()` | Neither `record_admissible_response` nor `record_admissible_failure` calls these |
| `open_and_send_sim()` authorization | No admissible field gates send |
| Provider admission / eviction | `admission.rs` and `eviction.rs` not modified in Trial 5B |
| Route selection | No admissible field in routing path |
| Relay behavior | No admissible field in relay path |
| TOLS κ | `ConvergencePressure` struct has no `admissible_*` field (verified at compile time in T13) |

### Conclusion for Audit 5

No policy bridge exists in the current codebase. Admissible telemetry is observational only.

---

## Proposed implementation scope

**Target file**: `test/tests/trial5c.rs`

**No production source modifications** should be necessary to prove the permitted claim. If tests reveal a missing diagnostic or an API gap (e.g., no way to distinguish duplicate from unknown-receipt), stop and report the gap rather than adding production code.

If any test requires exposing additional fields or methods not present in the current Trial 5B API, raise that as a `B` finding before proceeding.

---

## Proposed test categories

Tests required in Trial 5C that are not already fully covered by Trial 5B:

### Category A — Missing adversarial class coverage

| Proposed test name | What it proves | Trial 5B gap |
|---|---|---|
| `tc1_duplicate_failure_rejected` | Second `record_admissible_failure()` for same receipt returns `Err(UnknownReceipt)`; `admissible_failure_total = 1` | Duplicate failure class unproven |
| `tc2_failure_after_accepted_response_rejected` | After response accepted for receipt, `record_admissible_failure()` returns `Err(UnknownReceipt)`; `admissible_failure_total = 0` | Failure-after-response class unproven |
| `tc3_wrong_provider_failure_rejected` | `record_admissible_failure()` with wrong `provider_id` returns `Err(ProviderMismatch)`; `admissible_failure_total = 0` | Wrong-provider failure class unproven |

### Category B — Dual-surface comparison for partially proven classes

| Proposed test name | What it proves | Trial 5B gap |
|---|---|---|
| `tc4_symmetric_suppression_raw_vs_admissible` | 4 receipts, 2 responses; raw ratio `Some(0.5)` (from 2 raw calls), admissible ratio `Some(0.5)`; both surfaces agree on honest suppression | T10 admissible-only; no raw side |
| `tc5_unpaired_failure_injection_raw_vs_admissible` | Raw `record_failure()` calls do not touch `admissible_failure_total`; admissible stays 0 while raw `failure_total` grows | T6 admissible-only |
| `tc6_duplicate_response_raw_vs_admissible` | Raw `response_total` can be incremented twice for one pair; admissible stays at 1 | T3 admissible-only |
| `tc7_stale_epoch_raw_vs_admissible` | Stale receipt rejected; raw `response_total` unchanged by the rejection; admissible `response_total` stays 0 | T8 admissible-only |

### Category C — Resource-bound characterization

| Proposed test name | What it proves | New |
|---|---|---|
| `tc8_outstanding_accumulates_without_rotation` | N receipts issued without outcomes; `admissible_selection_total = N`; raw selection telemetry also `= N`; outstanding set has N entries | Resource bound unproven |
| `tc9_drain_epoch_clears_all_outstanding` | After `do_rotate()`, stale receipts return `Err(StaleEpoch)`; `outstanding.len() = 0` after drain; `next_observation_id` is NOT reset | Drain behavior unproven as standalone |
| `tc10_outstanding_not_bounded_between_rotations` | Explicit documentation test: issues 100+ receipts without rotation; confirms no automatic eviction occurs; confirms `CounterExhausted` is NOT returned at realistic counts | Memory-bound finding |

### Category D — No-policy-bridge regression

| Proposed test name | What it proves | Extends |
|---|---|---|
| `tc11_admissible_surface_read_only_after_injection_trace` | After a full injection trace (T11-style), `epoch_count` remains 0; `SimVitalityEvaluationContext.p = 0.0`; no rotation triggered | Extends T13 to include a full injection trace |

---

## Verdict vocabulary

Return exactly one after implementation:

- `A — TRIAL_5C_ADMISSIBLE_SURFACE_ADVERSARIAL_VALIDATION_SPECIFIED`
- `B — TRIAL_5C_REQUIRES_REJECTED_EVENT_DIAGNOSTIC_SURFACE`
- `B — TRIAL_5C_RECEIPT_RESOURCE_BOUND_INSUFFICIENT`
- `B — TRIAL_5C_EXISTING_POLICY_COUPLING_FOUND`

---

## Planning verdict

```
A — TRIAL_5C_ADMISSIBLE_SURFACE_ADVERSARIAL_VALIDATION_SPECIFIED
```

**Rationale**: All five audits are complete. The adversarial class inventory identifies 6 fully proven classes, 4 partially proven (dual-surface comparison missing), and 3 entirely unproven. The proposed 11 tests (Categories A–D) cover the gaps without modifying production source. One structural finding is raised: the `UnknownReceipt` variant does not distinguish "never issued" from "already consumed" — Trial 5C tests must acknowledge this and must not claim finer-grained rejection visibility than the API provides. One resource-bound finding is raised: the outstanding-receipt set is unbounded between rotations under `PoolRotationPolicy::Manual` with no rotation calls; Trial 5C tests must document this as an operator responsibility, not an automatic invariant.
