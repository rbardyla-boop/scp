# Corridor Trial 5A — Event Provenance Model Decision

**Status**: `B — TRIAL_5_REQUIRES_EVENT_PROVENANCE_MODEL` accepted  
**Date**: 2026-05-28  
**Predecessor**: `TRIAL_4_CLOSURE_RECORD.md` — 481 passing × 3 clean runs  
**Authorized baseline**: 481 passing  
**Scope**: Architecture decision only. No Rust source files modified.

---

## Accepted Verdict

`B — TRIAL_5_REQUIRES_EVENT_PROVENANCE_MODEL`

The Trial 5 planning audit established that the provider-pool model contains no causal
event-provenance infrastructure capable of supporting admissible response claims. The
`record_response()` seam is public-API-reachable without a prior `sample()` call, and
this gap is explicitly documented as provisional in the production docstrings. A dual-
surface provenance architecture (Option C) is required before any current telemetry
surface can be considered for automatic policy.

This verdict does not weaken Trials 2–4. It sharpens their meaning.

---

## Preserved Trial Closures

The following verdicts remain exactly valid and are not reopened by this decision:

| Trial | Verdict | Preserved claim |
|-------|---------|----------------|
| Trial 2 | `A — TRIAL_2_PROVIDER_FAILURE_OBSERVABILITY_PROVEN` | Surfaces 1/2/3 observably respond to scripted provider-failure traces; structural separation from vitality and send confirmed |
| Trial 3 | `A — TRIAL_3_CONCURRENT_PRESSURE_ORTHOGONALITY_PROVEN` | Provider-failure telemetry changes while vitality remains orthogonally unchanged; no accidental runtime coupling |
| Trial 4 | `A — TRIAL_4_SELECTIVE_SUPPRESSION_CHARACTERIZED` | Selective response suppression is characterizable through existing surfaces; `record_response()` does not require a prior `sample()` call; response numerator is freely inflateable |

### Refined interpretation of Trial 4

> Trial 4 demonstrated that the existing raw reported-response telemetry surface is
> manipulable through unpaired response injection. Trial 5 planning established that the
> provider-pool model contains no causal event-provenance infrastructure capable of
> defining admissible paired outcomes. No production caller of `record_response()` was
> found in the relay, transport, CLI, or orchestration layers; therefore the gap is
> model/API-level and simulator-demonstrated, not a proven live production exploitation
> path.

The honest claim is:

> SCP has a demonstrated response-accounting admissibility gap in its public
> provider-pool API and simulator-accessible seam. A live production exploit path has
> not been demonstrated because no production layer currently invokes the seam.

---

## Audit 1 — Exact Current Production/Model Surface

### Files Inspected

| File | Purpose |
|------|---------|
| `provider/pool/src/lib.rs` | `ProviderPool` public API: `sample()`, `record_response()`, `record_failure()`, `operational_telemetry()`, `convergence_pressure()` |
| `provider/pool/src/exposure.rs` | `ExposureTracker`: `record()`, `record_response()`, entropy computations, `response_total` |
| `provider/pool/src/metrics.rs` | `OperationalTelemetrySnapshot`, `recent_reported_response_ratio()`, §S64/§S69 docstrings |
| `provider/pool/src/liveness.rs` | `LivenessState`, `LivenessConfig` |
| `provider/pool/src/sampling.rs` | `SamplingStrategy` enum |
| `test/tests/trial4.rs` | T7 injection scenario; established manipulation trace |
| `test/tests/trial2.rs` | `record_response()` call sites in Trial 2 |
| `test/tests/trial3.rs` | `record_response()` call sites in Trial 3 |

### Symbol Table

| Symbol | File | Signature | Callers | Prior selection required? | Caller type |
|--------|------|-----------|---------|--------------------------|-------------|
| `ExposureTracker::record()` | `exposure.rs:107` | Records one sample; increments `total_samples` and `appearances[id]` per quorum provider | `ProviderPool::sample()` only | N/A — IS the selection call | Production |
| `ExposureTracker::record_response()` | `exposure.rs:118` | Increments `response_total` and `response_appearances[id]`; updates EWMA | `ProviderPool::record_response()` | **No** — takes only `&[u8; 32]`, no selection token | Production (called by production method) |
| `ProviderPool::sample()` | `lib.rs:924` | Draws live active providers per strategy; calls `ExposureTracker::record(&ids)` | Tests; no current relay/transport/CLI/LAN caller found | N/A | Production signature, test-only caller |
| `ProviderPool::record_response()` | `lib.rs:417` | Resets `consecutive_failures`, updates `last_seen_secs`, calls `ExposureTracker::record_response()` | `test/tests/trial2.rs`, `trial3.rs`, `trial4.rs` only | **No** | **Public production API, test-only caller** |
| `ProviderPool::record_failure()` | `lib.rs:428` | Increments `consecutive_failures` | `test/tests/trial4.rs` only | No | Public production API, test-only caller |
| `ProviderPool::operational_telemetry()` | `lib.rs:625` | Read-only snapshot of all three liveness surfaces | Tests | No — read only | Production |
| `OperationalTelemetrySnapshot::recent_reported_response_ratio()` | `metrics.rs:273` | `response_total / selection_total`; `None` when `!availability_evaluable` | Tests | No — derived | Production |
| `OperationalTelemetrySnapshot::recent_response_success_rate()` | `metrics.rs:287` | Deprecated alias for `recent_reported_response_ratio()` | Tests | No | Production (deprecated) |
| `ProviderPool::convergence_pressure()` | `lib.rs:536` | Returns `ConvergencePressure` including `liveness_weighted_kappa` | Tests, `maybe_rotate()`, `tick()` | No | Production |

### Gap Classification: **Public-But-Unused in Production**

`ProviderPool::record_response()` and `record_failure()` are:

- **Public API** (`pub fn`) with no guard or token requirement preventing production use.
- **Callable without a prior `sample()`** — no pending-selection map, no selection token, no at-most-once constraint, no ordering guarantee relative to `sample()`.
- **Not currently called** by any relay, transport, CLI, orchestration, LAN, or desktop layer. All callers are in `test/tests/`.

Any future orchestration layer can call `record_response()` without a source change to `ProviderPool` itself.

### Admissibility Properties of Current Model

| Property | Current state |
|----------|---------------|
| Response recorded without prior selection | ✓ possible — no guard exists |
| Response recorded twice for same event | ✓ possible — no at-most-once constraint |
| Response recorded against the wrong provider | ✓ possible — any `[u8; 32]` accepted |
| Response recorded after failure for same event | ✓ possible — `record_failure()` does not gate `record_response()` |
| Response replayed indefinitely | ✓ possible — no deduplication |
| Selection token returned by `sample()` | ✗ absent |
| Outstanding-request map | ✗ absent |
| At-most-once constraint | ✗ absent |
| Duplicate detection | ✗ absent |
| Provider-identity binding between selection and response | ✗ absent |

### Docstring Evidence (§S64 / §S69)

`metrics.rs:265–269` states for `recent_reported_response_ratio()`:

> "TELEMETRY-ONLY — unverified. The numerator is incremented by every
> `record_response()` call; those calls are not causally bound to actual
> selected relay attempts. An adversary or buggy caller can inflate this
> value arbitrarily (see §S64, §S69). Do not derive automatic policy from
> this metric **until** responses are bound to specific selected attempts
> with at-most-once accounting and unmatched-response rejection."

The word "until" signals that the current state is **provisional** and a provenance-
paired model is the anticipated resolution. The injection seam is a **documented
provisional gap**, not an intentional adversarial design feature.

---

## Audit 2 — Candidate Event-Token Model

### Minimum viable token: `SelectionReceipt`

```rust
/// Opaque receipt returned by `sample_with_receipts()`. Required argument for
/// `record_admissible_response()` and `record_admissible_failure()`.
///
/// Binds provider identity, selection-event identity, and epoch boundary.
/// At most one terminal outcome is accepted per receipt.
#[must_use]
pub struct SelectionReceipt {
    epoch_count:    u32,     // pool.rotation.epoch_count at time of sample_with_receipts()
    observation_id: u64,     // monotone per-pool sequence number; unique per provider-selection event
    provider_id:   [u8; 32], // provider selected in this event
}
```

### 1. Where it is created

`sample_with_receipts()` generates one `SelectionReceipt` per selected provider inside
`ProviderPool`, after the selection logic completes. The `observation_id` is a
monotone counter incremented atomically per pool. The `epoch_count` is copied from
`self.rotation.epoch_count` at call time.

`sample()` (existing method) is unchanged. `sample_with_receipts()` is a new parallel
method. Callers that do not need the admissible surface continue using `sample()`.

### 2. Whether `sample()` can return it without changing provider-selection policy

Yes. The selection logic (lemire_uniform, liveness filter, weighted strategies,
`ExposureTracker::record()`) is unchanged. The receipt is an additional return value
that does not influence which providers are drawn. Proposed signature:

```rust
pub fn sample_with_receipts(&mut self, rng: &mut impl RngCore)
    -> (ProviderQuorum<P>, Vec<SelectionReceipt>)
```

The original `sample(&self, ...)` signature is preserved. `record_response()` continues
to feed the raw reported surface.

### 3. Where outstanding receipts are tracked

A new `AdmissibleExposureTracker` within `provider/pool/src/exposure.rs`:

```rust
struct AdmissibleExposureTracker {
    next_observation_id:       u64,
    outstanding:               HashMap<u64, [u8; 32]>,  // observation_id → provider_id
    admissible_response_total: u64,
    admissible_failure_total:  u64,
    admissible_selection_total: u64,
    admissible_appearances:    HashMap<[u8; 32], u64>,
}
```

Receipts are inserted into `outstanding` on `sample_with_receipts()`. They are removed
on the first accepted terminal outcome. Epoch rotation drains all outstanding receipts
(receipts with a stale `epoch_count` are rejected with `StaleEpoch`).

### 4. Whether consumption is one-time

Yes. The receipt is removed from `outstanding` on the first accepted call to
`record_admissible_response(receipt)` or `record_admissible_failure(receipt)`.
Subsequent calls with the same receipt return:

```
AdmissibilityError::ReceiptAlreadyConsumed
```

### 5. How mismatched provider outcomes are rejected

The receipt encodes `provider_id`. On acceptance:

```rust
match self.outstanding.get(&receipt.observation_id) {
    None =>
        Err(AdmissibilityError::UnknownReceipt),
    Some(&pid) if pid != receipt.provider_id =>
        Err(AdmissibilityError::ProviderMismatch),
    Some(_) => {
        self.outstanding.remove(&receipt.observation_id);
        // record admissible outcome
        Ok(())
    }
}
```

### 6. Whether raw reported telemetry remains able to observe rejected/unpaired reports (Option C)

Yes. Under Option C, `record_response()` and `ExposureTracker::record_response()` are
unchanged. Raw `response_total` and `liveness_weighted_kappa` continue to count every
`record_response()` call. If the orchestration layer calls `record_response()` without
a receipt, the event is counted in the raw surface and absent from the admissible
surface. The discrepancy `(response_total − admissible_response_total) > 0` is itself
an observable signal of unpaired reporting.

### 7. Whether epoch/rotation/reset affects outstanding receipts

Yes. When `do_rotate()` fires, all outstanding admissible receipts from the prior epoch
MUST be invalidated. A receipt from epoch N is not accepted as a terminal outcome in
epoch N+1. The `epoch_count` field in `SelectionReceipt` enforces this:

```rust
if receipt.epoch_count != self.current_epoch_count {
    return Err(AdmissibilityError::StaleEpoch);
}
```

`ExposureResetPolicy::OnRotation` and `AfterEpochs` resets clear the `AdmissibleExposureTracker`
state. `ExposureResetPolicy::Never` requires explicit epoch boundary tracking.

---

## Audit 3 — Surface Naming and Semantic Separation

Under Option C, the following naming must be used consistently. No name may be
repurposed to imply stronger invariants than it currently encodes.

| Concept | Field / method | Meaning | May rename? |
|---------|----------------|---------|-------------|
| Raw reported response count | `response_total` (unchanged) | Every `record_response()` call; includes unpaired and injected events; manipulable | No |
| Raw reported response ratio | `recent_reported_response_ratio()` (unchanged) | `response_total / selection_total`; "unverified" in docstring | No — must retain "reported" |
| Liveness-weighted kappa (raw) | `liveness_weighted_kappa` (unchanged) | Derived from raw response appearances; manipulable | No |
| Admissible paired response count | `admissible_response_total` (NEW) | Counts only outcomes accepted via `SelectionReceipt`; at-most-once per event | — |
| Admissible paired failure count | `admissible_failure_total` (NEW) | Counts failures accepted via `SelectionReceipt` | — |
| Admissible selection count | `admissible_selection_total` (NEW) | Counts `sample_with_receipts()` calls (receipt issuances); denominator for admissible ratio | — |
| Admissible response ratio | `recent_admissible_response_ratio()` (NEW) | `admissible_response_total / admissible_selection_total`; manipulation-resistant | — |

**Prohibited rename**: The existing `recent_reported_response_ratio()` must NOT be
renamed to anything containing "admissible" or implying causal pairing. Renaming it
would silently reinterpret accepted Trial 4 evidence (T7, T8, T9) and break the
historical manipulability record.

**Prohibited conflation**: The admissible ratio and the raw ratio must never be
combined into a single field or returned through a shared code path without explicit
labeling. A reader of `OperationalTelemetrySnapshot` must be able to distinguish which
surface they are reading from the field name alone.

---

## Audit 4 — Backward Compatibility with Trials 2–4

| Trial | Current claim remains valid? | Existing tests retained unchanged? | New supplementary tests required? |
|-------|-----------------------------|------------------------------------|-----------------------------------|
| Trial 2 | **Yes** | **Yes** — `record_response()` and `operational_telemetry()` semantics unchanged; existing tests assert on raw surface | Future: assert admissible surface also observes valid paired traces (additive, not replacing) |
| Trial 3 | **Yes** | **Yes** — orthogonality proof does not depend on admissibility; no coupling introduced | None required; structural separation is unchanged by Option C |
| Trial 4 | **Yes** | **Yes** — T7 (injection masks raw surfaces) remains valid as historical characterization; the injection seam still exists on the raw surface under Option C | T9: dual-surface comparison directly proves raw surface is manipulable while admissible surface is not |

**Target rule**: Existing raw-telemetry trials remain historically valid and unchanged.
A future admissible-surface trial must be additive — it introduces a new surface and
proves it is manipulation-resistant. It must not reinterpret any metric or assertion
from Trials 2–4.

---

## Audit 5 — Security and Policy Boundary

### Explicit policy non-authorization statement

The following surfaces are **not authorized** for any automatic policy action:

| Surface | Non-authorized uses |
|---------|---------------------|
| `kappa` | Vitality decisions, send rejection, rotation triggers (exception: T1 catastrophic-collapse signal s<√n, authorized in prior phases exclusively for that signal) |
| `liveness_weighted_kappa` | Any automatic policy: eviction, rotation, vitality, send, relay, routing |
| `response_total` | Any automatic policy |
| `selection_total` | Any automatic policy (counter-signal only, not causal) |
| `recent_reported_response_ratio()` | Any automatic policy |
| `recent_response_success_rate()` | Any automatic policy (deprecated alias) |
| Any derived combination of the above | Any automatic policy |

The following future surfaces, even if implemented, are also not yet authorized:

| Proposed surface | Pre-authorization requirements |
|-----------------|-------------------------------|
| `admissible_response_total` | (1) Implementation reviewed and approved. (2) New architecture gate opened. (3) New Trial demonstrating the admissible surface resists all 10 adversarial traces in Audit 6. (4) Explicit update to this statement. |
| `recent_admissible_response_ratio()` | Same as above |
| `admissible_failure_total` | Same as above |

**This non-authorization is not scope-limited to adversarial scenarios.** Even absent
active injection, the raw surfaces lack provenance pairing and cannot certify that a
counted response corresponds to a completed relay attempt.

No current or future telemetry surface is approved for:
- automatic vitality input
- automatic send rejection
- provider rotation, routing, relay, or TOLS policy

even in combination with other signals, until a new architecture gate is explicitly
opened and separately proven.

---

## Audit 6 — Future Deterministic Test List

Proposed tests for `test/tests/trial5a.rs` (gated by a future implementation approval):

| # | Test name | What it proves |
|---|-----------|----------------|
| 1 | `t1_valid_selection_then_matching_response_is_admissible` | Valid receipt → `record_admissible_response()` → `admissible_response_total = 1`; raw surface unaffected |
| 2 | `t2_response_without_receipt_excluded_from_admissible` | No prior `sample_with_receipts()` → `record_response()` increments raw only; `admissible_response_total = 0`; under Option C raw `response_total = 1` is still visible |
| 3 | `t3_duplicate_response_for_one_receipt_rejected` | Second `record_admissible_response()` for the same receipt → `ReceiptAlreadyConsumed`; `admissible_response_total = 1` (not 2) |
| 4 | `t4_wrong_provider_response_token_mismatch_rejected` | Receipt issued for provider A; `record_admissible_response()` called with provider B encoded in receipt → `ProviderMismatch` error |
| 5 | `t5_valid_selection_then_failure_is_admissible` | Valid receipt → `record_admissible_failure()` → `admissible_failure_total = 1`; receipt consumed |
| 6 | `t6_failure_without_receipt_excluded_from_admissible` | `record_failure()` called without receipt → raw `consecutive_failures` incremented; `admissible_failure_total = 0` |
| 7 | `t7_response_after_failure_for_same_receipt_rejected` | Receipt consumed by `record_admissible_failure()` → subsequent `record_admissible_response()` for same receipt → `ReceiptAlreadyConsumed` |
| 8 | `t8_symmetric_suppression_visible_in_admissible_ratio` | T5/T6 trace from Trial 4 reproduced as paired events: 4 providers × 2 paired responses each → `recent_admissible_response_ratio() = Some(0.5)` (manipulation-resistant; contrast: raw ratio also 0.5 but for different reason — no injection present) |
| 9 | `t9_injection_masks_raw_cannot_mask_admissible` | T7 trace from Trial 4: 8 unpaired `record_response()` calls inflate raw ratio 0.5→1.0; admissible ratio remains `Some(0.5)`; dual-surface comparison directly demonstrates manipulation-resistance |
| 10 | `t10_vitality_send_rotation_policy_untouched` | Strongest available injection trace (T7 equivalent) → `epoch_count = 0`; `operational_telemetry()` admissible fields unchanged; vitality active, send succeeds; no rotation triggered through any current policy path |

All tests use `StdRng::seed_from_u64(0)` for any `sample()` calls. No wall-clock
timing. All assertions exact or within 1e-12 tolerance for floating-point values.
Tests 1–7 and 10 are independent of Option C dual-surface. Tests 8–9 require both
surfaces active simultaneously (Option C only).

---

## Analysis of Options A, B, C

### Option A — Raw Reported Telemetry Only

Accept `record_response()` as an intentionally limited "reported" signal. No production
source change.

**Advantages**: Zero source changes; Trials 1–4 remain exactly valid.  
**Disadvantages**: Operators have no manipulation-resistant participation metric; future
policy work starts from the same gap; injection remains silently possible.  
**Compatibility with §S64/§S69**: Consistent with the "TELEMETRY-ONLY — unverified"
framing. Conflicts with "until responses are bound..." — that word implies a future
binding is the intended endpoint, not that the current state is final.  
**Verdict**: Appropriate for characterization without remediation commitment. Does not
satisfy the "until" condition in the docstring.

### Option B — Replace Current Accounting with Paired-Only Accounting

Require a `SelectionReceipt` for `record_response()`. Remove unpaired calling ability.
Existing test callers must change signature.

**Advantages**: Closes the injection seam entirely on the single accounting surface.  
**Disadvantages**: Breaking API change; all Trial 2–4 test callers of `record_response()`
must update; changes semantic meaning of accepted trial metrics; introduces
transport-to-pool coupling; non-trivial production risk on the critical path.  
**Verdict on Trial compatibility**: Would silently reinterpret accepted Trial 4 evidence
(T7 proved injection is possible; Option B removes the seam that T7 measured). **Not
recommended.**

### Option C — Dual-Surface Model (Recommended)

Preserve raw reported telemetry unchanged. Add a parallel admissible surface backed by
`SelectionReceipt`-paired accounting.

**Advantages**: Backward compatible (no existing callers change); raw surface preserves
the Trial 4 manipulability evidence (injection IS observable in raw-only context as a
comparison to the admissible surface); admissible surface provides manipulation-resistant
metric; T9 trace directly demonstrates the gap by comparing both surfaces simultaneously.  
**Disadvantages**: Two parallel accounting paths; admissible surface requires new
infrastructure; larger total production change than Option A.  
**Verdict**: Strongest long-term position. Preserves all prior evidence. Extends with a
trustworthy surface. Enables future policy work without invalidating historical evidence.

---

## Recommended Architecture Decision

**Option C, staged.**

**Stage 1 (this pass — no code)**: Record this ADR. Declare all current surfaces
non-authoritative. Preserve all trial closures unchanged. No production source
modification.

**Stage 2 (future, separate gate)**: Implement the admissible surface as described
in Audit 2. Before Stage 2 opens:

1. Selection-token infrastructure design reviewed and approved.
2. Transport-to-pool threading plan documented (if token must reach the relay layer to
   be returned with actual relay responses).
3. A new architecture gate opened as a successor to this document.

---

## Production Files Requiring Modification (Stage 2, future)

| File | Change | Scope |
|------|--------|-------|
| `provider/pool/src/lib.rs` | Add `sample_with_receipts() -> (ProviderQuorum<P>, Vec<SelectionReceipt>)`; add `record_admissible_response(receipt)`, `record_admissible_failure(receipt)`; extend `operational_telemetry()` output | Provider pool public API |
| `provider/pool/src/exposure.rs` | Add `AdmissibleExposureTracker`; implement receipt issuance, consumption, `StaleEpoch` rejection, epoch-boundary drain | Exposure tracking internals |
| `provider/pool/src/metrics.rs` | Extend `OperationalTelemetrySnapshot` with `admissible_response_total`, `admissible_failure_total`, `admissible_selection_total`; add `recent_admissible_response_ratio()` | Telemetry snapshot |
| `test/tests/trial5a.rs` | All 10 deterministic tests from Audit 6 | Test only — no production change |

No other production crates require modification in Stage 2 unless selection-token
threading into the transport layer is separately authorized.

---

## Migration Strategy

1. **Preserve all existing callers**: `sample()`, `record_response()`, `record_failure()`,
   `operational_telemetry()`, and all derived ratio methods retain current signatures and
   semantics. No existing test file requires modification.

2. **Add parallel paths**: `sample_with_receipts()`, `record_admissible_response()`, and
   `record_admissible_failure()` are new methods. `OperationalTelemetrySnapshot` gains new
   fields that are `None` when the admissible tracker is not configured.

3. **Admissible tracker is opt-in**: `ProviderPool::with_admissible_tracking()` enables
   the admissible surface. Default behavior is unchanged (admissible fields return `None`).

4. **Trials 2–4 evidence is unaffected**: `trial2.rs`, `trial3.rs`, and `trial4.rs` use
   `record_response()` and `operational_telemetry()` exclusively. Their assertions remain
   valid against the raw surface and require no modification.

---

## Successor Document

The architecture gate for Stage 2 implementation should be named:

```
docs/architecture/CORRIDOR_TRIAL_5B_ADMISSIBLE_SURFACE_IMPLEMENTATION_GATE.md
```

That document must resolve:
- Selection-token threading plan (does the token cross the transport boundary?)
- Timeout/expiry semantics for outstanding receipts (currently deferred)
- Whether `record_admissible_failure()` is in scope for Stage 2 or deferred separately

---

## Verdict

`B — TRIAL_5_REQUIRES_EVENT_PROVENANCE_MODEL`

The provider-pool model contains no causal event-provenance infrastructure capable of
supporting admissible response claims. The recommended path is **Option C (dual-surface),
staged**, with Stage 2 gated by `CORRIDOR_TRIAL_5B_ADMISSIBLE_SURFACE_IMPLEMENTATION_GATE.md`.
No production source files have been modified by this pass.
