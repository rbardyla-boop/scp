# Corridor Trial 5B — Admissible Surface Implementation Gate

**Status**: Implementation gate. No Rust source files modified by this pass.  
**Date**: 2026-05-28  
**Predecessor**: `CORRIDOR_TRIAL_5A_EVENT_PROVENANCE_MODEL_DECISION.md`  
**Authorized baseline**: 481 passing × 3 clean runs  
**Scope**: Resolve all six implementation decisions for the admissible paired-outcome
surface and produce a verdict authorizing or blocking production Rust implementation.

---

## Trial Chain and Verdict History

| Trial | Verdict | Summary |
|-------|---------|---------|
| Trial 5 | `B — TRIAL_5_REQUIRES_EVENT_PROVENANCE_MODEL` | Provider-pool model contains no causal event-provenance infrastructure. All three telemetry surfaces are non-authoritative for automatic policy. The injection seam is a documented provisional gap, not an intentional design feature. |
| Trial 5A | `A — TRIAL_5A_DUAL_SURFACE_PROVENANCE_MODEL_SPECIFIED` | Option C (dual-surface) architecture decision recorded. Raw surfaces frozen by name and semantics. Admissible surface infrastructure designed. Stage 2 gated by this document. |
| Trial 5B | **See §11 — Verdict** | This document. |

---

## Architecture Decision Preserved from Trial 5A

The following decisions are frozen by Trial 5A and must not be reopened by this gate:

**Frozen: Option C, dual-surface model.**

- The existing raw reported telemetry surface is preserved unchanged.
  `response_total`, `recent_reported_response_ratio()`, and `liveness_weighted_kappa`
  retain their exact current names, signatures, semantics, and docstrings. They are
  the canonical record of what an unverified observer counts — including adversarial
  injection. They must not be renamed to anything implying causal pairing.

- A new parallel admissible surface is added alongside the raw surface. It is backed
  by `SelectionReceipt`-paired accounting and tracks only outcomes that pass all
  admissibility conditions.

- All new admissible-surface fields must include the word `admissible` in their name.

- The two surfaces must not share a code path or be combined into a single field.
  A reader of `OperationalTelemetrySnapshot` must be able to identify which surface
  they are reading from the field name alone.

- The Trial 4 manipulability finding (T7, T8: injection masks raw surfaces) remains
  historically valid. Option C preserves the observational record. The new admissible
  surface extends it — it does not replace or reinterpret it.

---

## Codebase Findings: Current State

All findings in this section are from direct inspection of production Rust source.
No files were modified.

### Provider selection (`sample()`)

`ProviderPool::sample()` is defined at `provider/pool/src/lib.rs:924`. It:

- Filters active providers to the live set via `is_live()`.
- Applies one of four `SamplingStrategy` variants (RandomK, WeightedByReputation,
  Threshold, WeightedComposite) using Lemire's nearly-divisionless uniform integer.
- Calls `self.exposure_tracker.lock().unwrap().record(&ids)` — this increments
  `total_samples` by 1 and increments `appearances[id]` for each selected provider.
- Returns `ProviderQuorum<P>` — a `Clone + StateProvider` bounded collection.
- Signature: `pub fn sample(&self, rng: &mut impl RngCore) -> ProviderQuorum<P>`
  (`&self` — immutable receiver; the exposure tracker is interior-mutable via `Arc<Mutex>`).

There is no selection token returned. There is no per-call sequence number. There is
no receipt or outstanding-request map. The raw selection accounting is performed
entirely inside `sample()` via `ExposureTracker::record()`.

### Epoch / rotation state

`PoolRotation` is defined at `provider/pool/src/rotation.rs:169`. The field:

```rust
pub(crate) epoch_count: u32,
```

is a monotone counter incremented by `do_rotate()` at
`provider/pool/src/lib.rs:907`:

```rust
self.rotation.epoch_count = self.rotation.epoch_count.saturating_add(1);
```

It is accessible via the public method `ProviderPool::epoch_count() -> u32` at
`lib.rs:483`. It is never reset — it accumulates across all rotations for the
lifetime of the pool. The `ExposureTracker::reset()` call (when configured via
`ExposureResetPolicy::OnRotation`) clears selection and response counters but does
not touch `epoch_count`.

`do_rotate()` also sets `rotation.accumulated_kappa = 0.0` and records
`rotation.previous_kappa` and `rotation.last_churn` for next-epoch pressure metrics.

### Existing telemetry structures

`OperationalTelemetrySnapshot` is defined at `provider/pool/src/metrics.rs:220`.
Current production fields:

```rust
pub struct OperationalTelemetrySnapshot {
    // Surface 1 — Survivor concentration
    pub kappa: f64,
    pub survivor_surface_evaluable: bool,
    // Surface 2 — Relative liveness distortion
    pub liveness_weighted_kappa: f64,
    pub liveness_surface_evaluable: bool,
    // Surface 3 — Absolute availability
    pub response_total: u64,
    pub selection_total: u64,
    pub availability_evaluable: bool,
    // Evidence context
    pub current_epoch_phase: EpochPhase,
    pub active_n: usize,
}
```

`recent_reported_response_ratio()` at `metrics.rs:273` returns `Option<f64>`:
`response_total as f64 / selection_total as f64` when `availability_evaluable`,
`None` otherwise.

`ExposureTracker` at `provider/pool/src/exposure.rs:71` contains:
```rust
pub(crate) response_appearances: HashMap<[u8; 32], u64>,
pub(crate) response_total: u64,
```

These are the internal counters feeding `response_total` in the snapshot. They are
incremented by `ExposureTracker::record_response()` at `exposure.rs:118`, which is
called by `ProviderPool::record_response()` at `lib.rs:417`. No selection token or
receipt is involved.

### Selection accounting

`ExposureTracker::record()` at `exposure.rs:107`:
- Increments `self.total_samples += 1` (one per `sample()` call, not per provider)
- Increments `self.appearances[id]` for each selected provider
- Updates the EWMA `smoothed_entropy`

This is the only place where selection events are recorded. `sample()` calls
`record(&ids)` after the provider draw completes.

### Existing receipt / observation-ID infrastructure

**None exists.** Direct search across all `.rs` files for the strings
`observation_id`, `SelectionReceipt`, `sample_with_receipt`, `AdmissibleExposure`,
`admissible_response`, `admissible_failure`, `admissible_selection`,
`record_admissible` returned zero results. The admissible surface exists only in
the Trial 5A architecture document — it has not been implemented.

There is no:
- Per-call sequence counter of any kind inside `ProviderPool`
- `HashMap` of outstanding selections
- Token returned from `sample()`
- `record_admissible_response()` or `record_admissible_failure()` method
- `AdmissibleExposureTracker` struct

### Production files requiring additive modification

| File | What changes (additive only) |
|------|------------------------------|
| `provider/pool/src/lib.rs` | Add `sample_with_receipts()` method; add `record_admissible_response()` and `record_admissible_failure()` methods; extend `operational_telemetry()` to populate new admissible fields; add `with_admissible_tracking()` builder method to opt in |
| `provider/pool/src/exposure.rs` | Add `SelectionReceipt` struct; add `AdmissibleExposureTracker` struct; implement receipt issuance, consumption, and all rejection paths |
| `provider/pool/src/metrics.rs` | Add `admissible_response_total`, `admissible_failure_total`, `admissible_selection_total` fields to `OperationalTelemetrySnapshot`; add `recent_admissible_response_ratio()` method |
| `test/tests/trial5b.rs` | All 13 deterministic tests (new file, no existing test modified) |

No changes to: `provider/pool/src/sampling.rs`, `provider/pool/src/rotation.rs`,
`provider/pool/src/liveness.rs`, `provider/pool/src/reputation.rs`,
`provider/pool/src/admission.rs`, `provider/pool/src/eviction.rs`,
`provider/pool/src/dummy.rs`, any crate outside `scp-provider-pool`, any existing
test file.

---

## Proposed `SelectionReceipt` Structure

```rust
/// Opaque receipt returned by `sample_with_receipts()`. Required argument for
/// `record_admissible_response()` and `record_admissible_failure()`.
///
/// Binds provider identity, selection-event identity, and epoch boundary in a
/// single structure that must be presented to close the paired-outcome accounting.
/// At most one terminal outcome is accepted per receipt. After consumption the
/// receipt's `observation_id` is removed from the outstanding map; re-presentation
/// returns `AdmissibilityError::ReceiptAlreadyConsumed`.
///
/// The `epoch_count` field enables stale-epoch rejection without a wall-clock
/// timeout. Any receipt issued during epoch N is invalid in epoch N+1 — the epoch
/// boundary that `do_rotate()` crosses is the event that terminates eligibility.
///
/// `#[must_use]` is not enforced at the type level here, but callers should treat
/// a receipt as a resource: either consume it with a terminal outcome call or
/// accept that the corresponding event is never credited to the admissible surface.
/// Unconsumed receipts are drained silently on the next epoch rotation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelectionReceipt {
    /// Value of `pool.rotation.epoch_count` at the moment `sample_with_receipts()` was called.
    /// Receipts with a mismatched epoch_count are rejected with `StaleEpoch`.
    pub(crate) epoch_count: u32,
    /// Monotone per-pool counter. Unique within a single epoch across all concurrent
    /// `sample_with_receipts()` calls. Incremented by one per selected provider per
    /// call, so a single call selecting k providers issues k distinct observation_ids.
    /// Never reused. Resets only on explicit `AdmissibleExposureTracker::reset()`,
    /// which occurs on epoch rotation (when `ExposureResetPolicy::OnRotation` is set)
    /// or never (when `ExposureResetPolicy::Never` is set).
    pub(crate) observation_id: u64,
    /// Identity of the provider selected in this event. The accepting terminal-outcome
    /// call validates that `receipt.provider_id == outstanding[receipt.observation_id]`.
    pub(crate) provider_id: [u8; 32],
}
```

**Field evaluation:**

- `epoch_count: u32` — correct. Copied directly from `self.rotation.epoch_count`
  (a `u32` in `PoolRotation`). Enables epoch-boundary stale rejection without any
  wall-clock or timeout machinery. The field uses the same type as the production
  counter, preventing silent truncation.

- `observation_id: u64` — correct. A `u64` monotone counter stored in
  `AdmissibleExposureTracker::next_observation_id` and incremented atomically
  per selected provider per `sample_with_receipts()` call. Within a single call
  selecting k providers, the implementation must increment the counter k times and
  issue k distinct receipts (one per provider). This guarantees:
    - No collision when the same provider appears twice (impossible without replacement
      in `RandomK`/`Threshold`, but possible with future strategies — the counter
      increment is per slot, not per provider-id, so it is safe regardless).
    - No replay: once a receipt is consumed the `observation_id` is removed from the
      outstanding map and never reinserted.
    - No reuse after epoch rotation: `AdmissibleExposureTracker::drain_epoch()` clears
      the outstanding map; any `observation_id` that was in it cannot re-appear because
      the counter is monotone and never decremented.

- `provider_id: [u8; 32]` — correct. Copied from `self.active[i].0` at the time of
  selection, exactly as `sample()` already does. Used at acceptance time to verify
  that the terminal-outcome call refers to the same provider that was selected.
  Using `[u8; 32]` (the type already used throughout the pool) avoids new type
  dependencies.

---

## Terminal-Outcome Lifecycle State Machine

A receipt, from the moment of issuance to termination, moves through exactly two
states:

```
                          sample_with_receipts()
                                   │
                           [issue receipt]
                           outstanding.insert(observation_id, provider_id)
                                   │
                                   ▼
                            OUTSTANDING
                           ─────────────
                         Inserted in the
                         outstanding map.
                         Not yet resolved.
                         Eligible for one
                         terminal outcome.
                                   │
          ┌────────────────────────┼────────────────────────┐
          │                        │                         │
record_admissible_response()  record_admissible_failure()  epoch rotation
   (admissibility checks pass)  (admissibility checks pass)  (do_rotate())
          │                        │                         │
    response_total++          failure_total++         [all outstanding receipts
    appearances[pid]++         appearances[pid]++      drained silently; no
    outstanding.remove(id)    outstanding.remove(id)   terminal outcome recorded]
          │                        │                         │
          └────────────────────────┼─────────────────────────┘
                                   ▼
                              CONSUMED
                             ──────────
                         observation_id
                         permanently absent
                         from outstanding.
                         Re-presentation
                         returns ReceiptAlreadyConsumed.
                         (Unless id was re-issued in a
                          later epoch — impossible because
                          next_observation_id is monotone
                          and never decremented.)
```

**Admissibility conditions for transitioning OUTSTANDING → CONSUMED (response path):**

1. `receipt.epoch_count == adm_tracker.current_epoch_count` — epoch not stale.
2. `outstanding.contains_key(&receipt.observation_id)` — receipt was genuinely issued.
3. `outstanding[receipt.observation_id] == receipt.provider_id` — provider identity matches.
4. (Implicit) `outstanding.remove()` succeeds — atomically removes, enforcing at-most-once.

All four conditions must hold. Failure of condition 1 returns `StaleEpoch`. Failure of
condition 2 returns `UnknownReceipt` (covers both never-issued and already-consumed
cases — deliberately unified so a caller cannot distinguish consumed from forged). Failure
of condition 3 returns `ProviderMismatch`.

**Admissibility conditions for failure path:** same as above. The CONSUMED state is
indistinguishable from consumed-by-response vs consumed-by-failure at the receipt level.
Only the counters differ.

---

## Implementation Decisions

### Decision 1: Receipt issuance and raw accounting

**Question**: Does `sample_with_receipts()` perform the raw selection accounting itself,
or does it wrap existing `sample()` without duplicate accounting?

**Answer: `sample_with_receipts()` MUST call the same `ExposureTracker::record(&ids)`
path as `sample()`, exactly once per call, and must NOT call `sample()` internally.**

**Rationale from codebase inspection:**

`sample()` at `lib.rs:924–1044` has four branches (one per `SamplingStrategy`). Each
branch builds `selected: Vec<([u8; 32], P)>`, collects `ids: Vec<[u8; 32]>` from it,
calls `self.exposure_tracker.lock().unwrap().record(&ids)`, and returns the quorum.
The `record()` call is the only place raw selection accounting happens — it increments
`total_samples` once and `appearances[id]` for each selected provider.

`sample_with_receipts()` must duplicate the selection logic from `sample()` (or factor
the shared body into a private `sample_inner()` helper) so that:
- `ExposureTracker::record(&ids)` is called exactly once — raw surface is updated.
- The receipt issuance loop runs after the draw completes — one receipt per provider.
- No second call to `ExposureTracker::record()` occurs — no double-counting.

`sample_with_receipts()` cannot be implemented by calling `self.sample(rng)` and then
attaching receipts, because `sample()` takes `&self` (immutable receiver via interior
mutability on `exposure_tracker`) and the receipt issuance requires a mutable counter
on `AdmissibleExposureTracker`. The cleanest implementation extracts a `sample_inner()`
private helper that both `sample()` and `sample_with_receipts()` call.

The new method must also guard `AdmissibleExposureTracker` being configured:
if `with_admissible_tracking()` was not called, `sample_with_receipts()` returns an
empty `Vec<SelectionReceipt>` alongside the normal quorum (receipts are silently
absent; callers that do not check are unaffected).

### Decision 2: Observation ID construction

**Answer: monotone global counter per pool, incremented once per selected provider
per `sample_with_receipts()` call; `u64`; never reset.**

**Specification:**

`AdmissibleExposureTracker` holds `next_observation_id: u64`, initialized to 0.
On each `sample_with_receipts()` call, after the provider draw completes, for each
provider in the selected set, in order:

```rust
let oid = self.adm_tracker.next_observation_id;
self.adm_tracker.next_observation_id += 1;  // saturating_add for production hardening
receipt = SelectionReceipt { epoch_count, observation_id: oid, provider_id: pid };
self.adm_tracker.outstanding.insert(oid, pid);
```

**Why this construction satisfies all four requirements:**

- *Deterministic*: derived from a counter, not from random bytes or from provider-id.
  Two identical call sequences on two pool instances produce identical observation IDs.
  This is intentional: tests can reason about specific ID values.

- *Unique within an epoch*: the counter increments per provider per call, so no two
  receipts in an outstanding map share an `observation_id`. A quorum of k=3 providers
  issued in calls with counter starting at 7 produces IDs 7, 8, 9 — all distinct.

- *No collision on same-provider-twice*: if `WeightedComposite` is extended in the
  future to re-select a provider (which `RandomK`/`Threshold` prevent by design but
  `WeightedComposite` without-replacement tracking might not), the counter increment
  is per-slot, not per-provider-id, so two slots for the same provider get distinct IDs.
  The outstanding map maps `observation_id → provider_id`, not `provider_id → _`, so
  no collision occurs.

- *No replay*: `outstanding.remove(&oid)` on consumption permanently removes the key.
  The counter never decrements, so `oid` is never reissued in the same pool instance.

- *No reuse after epoch rotation*: `drain_epoch()` clears `outstanding` (all keys
  removed) but does NOT reset `next_observation_id`. After a rotation, new receipts
  get fresh IDs that are numerically higher than any previously issued ID. A stale
  receipt with `epoch_count < current_epoch_count` is rejected by the epoch check
  before `outstanding.contains_key()` is evaluated — the ID space overlap is harmless
  because the epoch mismatch is caught first.

**Overflow**: `u64` allows ~1.8 × 10^19 receipts per pool instance before saturating.
At 10,000 selections per second, this exhausts in approximately 58,000 years.
`saturating_add` rather than wrapping add is required; overflow must return an error
rather than silently reusing IDs (an `Err(AdmissibilityError::CounterExhausted)` from
`sample_with_receipts()` is the correct response, leaving the quorum usable but the
admissible tracker disabled for that call).

### Decision 3: Outstanding receipt storage and bounds

**Data structure**: `HashMap<u64, [u8; 32]>` mapping `observation_id → provider_id`.
Located inside `AdmissibleExposureTracker` in `provider/pool/src/exposure.rs`.

**Ownership**: field of `AdmissibleExposureTracker`, which is an `Option<AdmissibleExposureTracker>`
inside `ProviderPool` — the pool owns it exclusively; no `Arc`/`Mutex` needed unless
the pool itself is shared across threads (currently it is not; `sample_with_receipts()`
requires `&mut self`, matching the existing `force_rotate()` pattern).

**Retention rule**: a receipt stays in `outstanding` from the moment of issuance until
the first of:
1. `record_admissible_response(receipt)` is called and passes all admissibility checks.
2. `record_admissible_failure(receipt)` is called and passes all admissibility checks.
3. `drain_epoch()` is called on epoch rotation — all outstanding receipts for the
   rotating epoch are drained in O(n) by clearing the entire map.

**Epoch reset behavior**:
- `ExposureResetPolicy::OnRotation`: `drain_epoch()` is called inside `do_rotate()`
  after `epoch_count` is incremented. The outstanding map is cleared. `next_observation_id`
  is NOT reset (see Decision 2 rationale). `admissible_response_total`,
  `admissible_failure_total`, `admissible_selection_total`, and `admissible_appearances`
  are cleared (matching `ExposureTracker::reset()` behavior — the admissible tracker
  follows the same reset policy as the raw tracker).
- `ExposureResetPolicy::Never`: `drain_epoch()` still clears `outstanding` (stale
  receipts cannot remain valid across epoch boundaries), but the admissible counters
  accumulate for the pool lifetime, matching raw tracker behavior.
- `ExposureResetPolicy::AfterEpochs { n }`: `drain_epoch()` always clears `outstanding`;
  admissible counters reset only when `epoch_count % n == 0`, matching raw.

**Memory bound**: the outstanding map is bounded by the maximum number of receipts
that can be issued between epoch rotations. In the worst case, every `sample_with_receipts()`
call in an epoch contributes k receipts (k = quorum size). For the worst-case realistic
configuration (k=10, 1 call/second, epoch lasts 1 hour), this is 10 × 3600 = 36,000
entries. Each entry is `(u64, [u8; 32])` = 40 bytes, so 36,000 × 40 = ~1.4 MB per
pool. This is bounded and predictable.

**Unbounded-growth prevention rule (required)**: if `ExposureResetPolicy::Never`
is set AND the epoch never rotates (e.g., `PoolRotationPolicy::Manual` with no
`force_rotate()` call), outstanding receipts accumulate without being drained. This
is the only scenario where the map can grow without bound. The implementation MUST
document this interaction in a code comment on `AdmissibleExposureTracker::outstanding`:

> "When ExposureResetPolicy::Never and PoolRotationPolicy::Manual are combined without
> any explicit force_rotate() calls, outstanding receipts accumulate unboundedly.
> Operators must call force_rotate() periodically or use a time-based rotation policy
> to bound memory. The admissible tracker does not enforce a maximum outstanding count —
> that is a deployment configuration responsibility."

This is sufficient documentation. No automatic eviction of old receipts is required
for Stage 2 — the constraint is clearly stated and enforced by operator configuration.

### Decision 4: Raw vs admissible outcome recording for all 8 event types

For each event, three columns describe what happens to:
- **Raw surface**: `response_total`, `liveness_weighted_kappa`, `recent_reported_response_ratio()`
- **Admissible surface**: `admissible_response_total`, `admissible_selection_total`, `recent_admissible_response_ratio()`
- **Rejected evidence**: what the return value / error encodes

| # | Event type | Raw surface | Admissible surface | Rejected/error path |
|---|------------|-------------|-------------------|---------------------|
| 1 | **Valid paired response**: `sample_with_receipts()` → correct provider → `record_admissible_response(receipt)` | Unchanged — `record_response()` would still update raw if called separately; if caller does not call `record_response()`, raw counters do NOT change for this event | `admissible_response_total++`; `admissible_appearances[pid]++`; receipt removed from outstanding; `admissible_selection_total` was incremented at issuance | `Ok(())` |
| 2 | **Valid paired failure**: `sample_with_receipts()` → correct provider → `record_admissible_failure(receipt)` | Unchanged — raw failure counter (consecutive_failures) is updated only if `record_failure()` is separately called | `admissible_failure_total++`; receipt removed from outstanding | `Ok(())` |
| 3 | **Response without receipt**: `record_response(pid)` called with no prior `sample_with_receipts()` | `response_total++`; `response_appearances[pid]++`; `liveness_weighted_kappa` shifts; raw surface counts the event as-is | No change. `admissible_response_total`, `admissible_selection_total`, `admissible_appearances` all unchanged | No error on raw path; admissible path not invoked |
| 4 | **Failure without receipt**: `record_failure(pid)` called with no prior `sample_with_receipts()` | `consecutive_failures[pid]++`; raw liveness state updated | No change to any admissible counter | No error on raw path; admissible path not invoked |
| 5 | **Duplicate response (same receipt, second call)**: `record_admissible_response(receipt)` called after receipt already consumed | Raw surface: depends on whether `record_response()` was also called; the duplicate admissible call does not touch raw counters | No change — admissible counters are NOT incremented again; receipt is no longer in outstanding | `Err(AdmissibilityError::UnknownReceipt)` (consumed receipts are removed from outstanding; the error is the same as for a forged receipt — callers cannot distinguish) |
| 6 | **Response after accepted failure (same receipt)**: `record_admissible_failure(receipt)` consumed the receipt; then `record_admissible_response(receipt)` is attempted | Raw surface unchanged | No change — receipt is absent from outstanding | `Err(AdmissibilityError::UnknownReceipt)` — same path as duplicate response case; consumed-by-failure and consumed-by-response produce the same observable error |
| 7 | **Wrong-provider outcome**: `sample_with_receipts()` issued receipt for provider A; caller presents the receipt but modifies `provider_id` to provider B in the struct before calling `record_admissible_response()` | Raw surface unchanged | No change | `Err(AdmissibilityError::ProviderMismatch)` — `outstanding[receipt.observation_id]` is A, but `receipt.provider_id` is B; rejected before any counter update |
| 8 | **Stale-epoch outcome**: receipt was issued in epoch N; `do_rotate()` fired (epoch now N+1); caller presents old receipt | Raw surface unchanged (raw accounting is epoch-agnostic) | No change — receipt was drained from outstanding by `drain_epoch()` | `Err(AdmissibilityError::StaleEpoch)` — checked first, before outstanding lookup; stale-epoch path is disjoint from unknown-receipt path so callers can distinguish them |

**Clarifying notes on event 3 and the dual-surface interpretation:**

Under Option C, `record_admissible_response(receipt)` does NOT automatically call
`record_response(pid)` internally. The two paths are orthogonal. If an orchestration
layer wants the raw surface updated, it calls `record_response()` separately. If it
wants only the admissible surface updated, it calls only `record_admissible_response()`.
The discrepancy `response_total - admissible_response_total > 0` is a valid and
observable signal of unpaired reporting — it must remain computable.

**`AdmissibilityError` enum (to be defined in `exposure.rs` or `metrics.rs`):**

```rust
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdmissibilityError {
    /// Admissible tracking was not configured via `with_admissible_tracking()`.
    NotConfigured,
    /// The receipt's epoch_count does not match the current epoch.
    /// The receipt was drained on the last rotation.
    StaleEpoch,
    /// The observation_id is not present in the outstanding map.
    /// Covers: never issued, already consumed (by response or failure), or forged.
    UnknownReceipt,
    /// The observation_id is present but the provider_id encoded in the receipt
    /// does not match the provider_id stored at issuance.
    ProviderMismatch,
    /// The observation_id counter overflowed u64::MAX. Effectively unreachable.
    CounterExhausted,
}
```

### Decision 5: Rotation/reset interaction with outstanding receipts

**Answer: epoch rotation MUST drain all outstanding receipts unconditionally. This
is not configurable.**

**Specification:**

Inside `do_rotate()` in `provider/pool/src/lib.rs`, after `epoch_count` is
incremented (line 907), the admissible tracker drain must be called:

```rust
if let Some(ref mut adm) = self.admissible_tracker {
    adm.drain_epoch(new_epoch_count);
}
```

`AdmissibleExposureTracker::drain_epoch(new_epoch_count)`:
1. Clears `self.outstanding` — all pending receipts become unredeemable.
2. Sets `self.current_epoch_count = new_epoch_count`.
3. If `ExposureResetPolicy` dictates a reset for this epoch, also clears:
   `admissible_response_total`, `admissible_failure_total`, `admissible_selection_total`,
   `admissible_appearances` (matching the raw tracker's `reset()` behavior).
   Note: `next_observation_id` is NOT cleared — see Decision 2.

**Ordering constraint**: `drain_epoch()` must be called after `epoch_count` is
incremented and before any new `sample_with_receipts()` call returns. Since `do_rotate()`
holds `&mut self` throughout and `sample_with_receipts()` also requires `&mut self`,
Rust's borrow checker enforces this ordering without additional synchronization.

**What happens to outstanding receipts on drain:**

They are silently dropped. No error is returned to the issuing caller — the caller
has already received the receipt and moved on. If the caller subsequently presents
the stale receipt via `record_admissible_response()` or `record_admissible_failure()`,
it gets `Err(AdmissibilityError::StaleEpoch)` — the epoch check fires before the
outstanding map lookup.

**Why this rule is non-negotiable:**

If a receipt from epoch N were accepted in epoch N+1, the `provider_id` it encodes
may refer to a provider that was evicted from the active set during rotation. The
admissible surface would then credit a response to a provider no longer in the pool,
corrupting the `admissible_appearances` map and the derived ratio. The epoch boundary
is the only natural, unambiguous seam at which to terminate all outstanding eligibility.

### Decision 6: No policy authorization

**Explicit statement: No new admissible surface field, no new method, and no
combination of new and existing fields introduced by this implementation gate is
authorized for automatic policy of any kind.**

The prohibition covers:
- Populating `SimVitalityEvaluationContext.p` (perturbation pressure) from any
  admissible or raw surface field. `p` is a simulator-only scenario control declared
  at `core/vitality/src/sim_context.rs:47`; it must remain a test-declared constant,
  never derived from pool telemetry.
- Blocking or rejecting sends based on `admissible_response_total`,
  `admissible_failure_total`, `admissible_selection_total`, or
  `recent_admissible_response_ratio()`.
- Triggering `maybe_rotate()` or `force_rotate()` based on any admissible surface field.
- Routing or relay decisions based on any admissible surface field.
- TOLS (any variant) policy inputs derived from any admissible surface field.
- Admission or eviction decisions based on any admissible surface field.

This non-authorization is NOT scope-limited to adversarial scenarios. Even in the
absence of active injection, the admissible surface does not constitute a certified
relay success. It proves only that a `record_admissible_response()` call was accepted
against a valid receipt. It does not prove that the underlying relay actually delivered
a message — it proves that the pool layer's accounting received a properly paired
outcome report.

Authorization of the admissible surface for any automatic policy requires:
1. A new architecture gate document (a successor to this one).
2. A demonstration that the admissible surface resists all 13 adversarial test traces
   from §9 of this document under actual relay-layer threading.
3. A transport-layer threading plan reviewed and approved separately (the question of
   whether the `SelectionReceipt` must cross the transport boundary to be returned
   with actual relay responses is deferred to that gate).
4. An explicit update to this non-authorization statement by name.

---

## Raw/Admissible/Rejected Accounting Table

Full accounting for all 8 event types across all three surfaces:

| # | Event | raw `response_total` | raw `liveness_weighted_kappa` | raw ratio | `admissible_response_total` | `admissible_selection_total` | admissible ratio | Error |
|---|-------|---------------------|-------------------------------|-----------|----------------------------|------------------------------|-----------------|-------|
| 1 | Valid paired response | Unchanged (raw path not invoked) | Unchanged | Unchanged | +1 | Unchanged (was +1 at issuance) | numerator+1 | `Ok(())` |
| 2 | Valid paired failure | Unchanged | Unchanged | Unchanged | Unchanged | Unchanged | Unchanged | `Ok(())` |
| 3 | Response without receipt | +1 | shifts | shifts | 0 | 0 | unchanged | (none — raw path, no error) |
| 4 | Failure without receipt | Unchanged | Unchanged | Unchanged | 0 | 0 | unchanged | (none — raw path, no error) |
| 5 | Duplicate response (same receipt) | Unchanged | Unchanged | Unchanged | 0 | 0 | unchanged | `UnknownReceipt` |
| 6 | Response after accepted failure | Unchanged | Unchanged | Unchanged | 0 | 0 | unchanged | `UnknownReceipt` |
| 7 | Wrong-provider outcome | Unchanged | Unchanged | Unchanged | 0 | 0 | unchanged | `ProviderMismatch` |
| 8 | Stale-epoch outcome | Unchanged | Unchanged | Unchanged | 0 | 0 | unchanged | `StaleEpoch` |

Notes:
- `admissible_selection_total` is incremented at issuance (inside `sample_with_receipts()`),
  not at outcome recording. This is correct: a call that issues a receipt counts as one
  admissible selection opportunity regardless of whether the receipt is ever presented.
  One call selecting k providers increments `admissible_selection_total` by k (one per receipt).
- Rows 3 and 4 show events that reach only the raw path. Under Option C these are fully
  visible in the raw surface and completely invisible to the admissible surface. The
  discrepancy `response_total - admissible_response_total` accumulates and is readable.
- Row 1: the raw surface is unchanged by a `record_admissible_response()` call. If the
  orchestration layer also wants the raw surface updated, it must explicitly call
  `record_response(pid)` in addition to `record_admissible_response(receipt)`. This
  orthogonality is intentional — it preserves the comparison signal.

---

## Backward-Compatibility Proof for Trials 2–4

The following properties guarantee that no existing test assertion on any trial
from 2 through 4 becomes invalid after Stage 2 implementation:

**Property 1 — Raw API signatures unchanged.**
`ProviderPool::sample()`, `record_response()`, `record_failure()`, and
`operational_telemetry()` retain their current signatures. `OperationalTelemetrySnapshot`
gains new fields (`admissible_*`) but all existing fields (`kappa`, `liveness_weighted_kappa`,
`response_total`, `selection_total`, `survivor_surface_evaluable`, `liveness_surface_evaluable`,
`availability_evaluable`, `current_epoch_phase`, `active_n`) are structurally unchanged.
Existing code that reads these fields by name continues to compile and continues to
observe the same values.

**Property 2 — Raw counters accumulate identically.**
`ExposureTracker::record()` and `ExposureTracker::record_response()` are unchanged.
The raw `response_total` counter is incremented by exactly the same calls as before.
No new code path touches these counters.

**Property 3 — Admissible tracker is opt-in.**
If `with_admissible_tracking()` is not called on the pool (which is the case for all
existing trial test pools), the `Option<AdmissibleExposureTracker>` is `None`. All
admissible fields in `OperationalTelemetrySnapshot` return `None` or `0` (see field
specs in Decision 3). No existing test calls `sample_with_receipts()`, so no receipt
infrastructure activates.

**Property 4 — Trial 4 T7/T8 evidence is preserved.**
The injection seam on the raw surface (`record_response()` callable without a
receipt) remains open. Trial 4 T7 (injection masks raw surfaces) remains valid as a
current behavioral fact: even after Stage 2 implementation, calling `record_response()`
without a receipt continues to increment `response_total`. The raw surface is still
manipulable. The admissible surface proves the manipulation is detectable by comparison.

**Property 5 — Test file independence.**
All new tests are in `test/tests/trial5b.rs`, a new file. No line of
`trial2.rs`, `trial3.rs`, or `trial4.rs` is modified.

---

## 13 Required Future Deterministic Tests

All tests reside in `test/tests/trial5b.rs`. All tests use `StdRng::seed_from_u64(0)`
for any `sample()` or `sample_with_receipts()` calls. No wall-clock timing. All
floating-point assertions use `(value - expected).abs() < 1e-12` tolerance where
applicable. Integer counter assertions are exact.

| # | Test name | Scenario | What it proves |
|---|-----------|---------|----------------|
| 1 | `t1_valid_paired_response_is_admissible` | `sample_with_receipts()` → receipt for selected provider → `record_admissible_response(receipt)` | `admissible_response_total = 1`; `admissible_selection_total = 1`; `recent_admissible_response_ratio() = Some(1.0)`; raw surface counters unchanged by the admissible call |
| 2 | `t2_response_without_receipt_excluded_from_admissible` | `record_response(pid)` called with no prior `sample_with_receipts()` | `admissible_response_total = 0`; `admissible_selection_total = 0`; `recent_admissible_response_ratio() = None`; raw `response_total = 1`; proves Option C discrepancy is visible |
| 3 | `t3_duplicate_response_for_one_receipt_rejected` | `sample_with_receipts()` → `record_admissible_response(receipt)` → `record_admissible_response(receipt)` again | First call: `Ok(())`; second call: `Err(UnknownReceipt)`; `admissible_response_total = 1` (not 2) |
| 4 | `t4_wrong_provider_response_rejected` | Receipt issued for provider A; struct's `provider_id` field mutated to provider B before calling `record_admissible_response()` | `Err(ProviderMismatch)`; `admissible_response_total = 0`; receipt still absent from outstanding after rejection |
| 5 | `t5_valid_paired_failure_is_admissible` | `sample_with_receipts()` → receipt for selected provider → `record_admissible_failure(receipt)` | `admissible_failure_total = 1`; receipt consumed; subsequent `record_admissible_response(same_receipt)` returns `Err(UnknownReceipt)` |
| 6 | `t6_failure_without_receipt_excluded_from_admissible` | `record_failure(pid)` called with no prior `sample_with_receipts()` | `admissible_failure_total = 0`; raw `consecutive_failures` incremented normally |
| 7 | `t7_response_after_failure_for_same_receipt_rejected` | `record_admissible_failure(receipt)` consumes receipt → `record_admissible_response(same_receipt)` | `Err(UnknownReceipt)`; `admissible_response_total = 0`; `admissible_failure_total = 1` |
| 8 | `t8_stale_epoch_receipt_rejected` | `sample_with_receipts()` → `force_rotate()` → `record_admissible_response(old_receipt)` | `Err(StaleEpoch)`; `admissible_response_total = 0`; `epoch_count` advanced; all old receipts drained |
| 9 | `t9_multi_provider_receipts_are_distinct` | `sample_with_receipts()` with k=3 → three receipts with distinct `observation_id` values → all three accepted | `admissible_response_total = 3`; `admissible_selection_total = 3`; observation IDs are consecutive; verifies per-provider-per-call issuance |
| 10 | `t10_symmetric_suppression_visible_in_admissible_ratio` | 4 providers; `sample_with_receipts()` × 4 calls (each selecting one provider); only 2 responses presented via receipts | `admissible_response_total = 2`; `admissible_selection_total = 4`; `recent_admissible_response_ratio() = Some(0.5)`; demonstrates manipulation-resistant suppression signal |
| 11 | `t11_injection_masks_raw_cannot_mask_admissible` | T7 trace from Trial 4: 4 paired responses → 4 unpaired `record_response()` injections to inflate raw ratio to 1.0 | `recent_reported_response_ratio() = Some(1.0)` (raw, manipulated); `recent_admissible_response_ratio() = Some(0.5)` (admissible, intact); dual-surface comparison demonstrates manipulation-resistance |
| 12 | `t12_admissible_tracker_opt_in_inactive_by_default` | Pool constructed without `with_admissible_tracking()`; `record_admissible_response()` called | `Err(AdmissibilityError::NotConfigured)`; all admissible fields in `operational_telemetry()` are `None`/0 |
| 13 | `t13_vitality_send_rotation_policy_untouched` | Strongest injection trace (T7-equivalent) against a pool with admissible tracking configured; inject 8 unpaired `record_response()` calls | `epoch_count = 0` (no rotation triggered); `SimVitalityEvaluationContext` constructed with declared `p = 0.0` (not derived from any telemetry field); all existing vitality, send, and rotation surfaces unaffected; no admissible field influences `ConvergencePressure.kappa` or any `PoolRotationPolicy` threshold |

---

## Explicit Policy Non-Authorization Statement

The following fields of `OperationalTelemetrySnapshot` — both existing and proposed —
are **not authorized** for any automatic policy action in the SCP system:

**Existing fields (from Trials 2–4, non-authorization unchanged):**

| Field / method | Non-authorized uses |
|----------------|---------------------|
| `kappa` | Vitality decisions, send rejection, rotation triggers beyond the T1 catastrophic-collapse signal (s < √n) authorized in prior phases |
| `liveness_weighted_kappa` | Any automatic policy: eviction, rotation, vitality, send, relay, routing |
| `response_total` | Any automatic policy |
| `selection_total` | Any automatic policy (counter-signal only) |
| `recent_reported_response_ratio()` | Any automatic policy |
| `recent_response_success_rate()` | Any automatic policy (deprecated alias) |

**Proposed new fields (not authorized even after Stage 2 implementation):**

| Field / method | Non-authorized uses | Pre-authorization requirements |
|----------------|---------------------|-------------------------------|
| `admissible_response_total` | Any automatic policy | New architecture gate; transport threading plan; all 13 tests passing; explicit update to this statement |
| `admissible_failure_total` | Any automatic policy | Same as above |
| `admissible_selection_total` | Any automatic policy | Same as above |
| `recent_admissible_response_ratio()` | Any automatic policy | Same as above |
| Any derived combination of the above | Any automatic policy | Same as above |

No new surface introduced in Stage 2 may:
- Set or influence `SimVitalityEvaluationContext.p`
- Block or permit sends
- Trigger `maybe_rotate()` or `force_rotate()`
- Influence relay routing or relay selection
- Feed any TOLS variant (v1, v2, v3, or future)
- Gate admission or eviction decisions

---

## Verdict

`A — TRIAL_5B_ADMISSIBLE_SURFACE_IMPLEMENTATION_SPECIFIED`

**Rationale:**

All six implementation decisions are resolved with specificity from direct codebase
inspection, and no blocking condition was found:

1. **Receipt issuance and raw accounting** (D1): `sample_with_receipts()` factored from
   a shared private `sample_inner()` to avoid double-counting. Decision is unambiguous.

2. **Observation ID construction** (D2): `u64` monotone counter per pool, incremented
   per provider per call, never reset; proven collision-free, replay-free, and
   stale-epoch-safe by argument.

3. **Outstanding receipt storage and bounds** (D3): `HashMap<u64, [u8; 32]>`, bounded
   by epoch rotation, with explicit documentation of the one unbounded-growth scenario
   (Manual policy + Never reset + no rotation). The bound is operator-enforced via
   rotation policy, which is a deployment configuration responsibility, not a code defect.
   The memory bound question is RESOLVED — this document specifies the exact bound rule.

4. **Raw/admissible/rejected accounting** (D4): all 8 event types fully specified with
   exact counter behavior, error path, and orthogonality between raw and admissible paths.

5. **Rotation/reset interaction** (D5): epoch rotation unconditionally drains outstanding
   receipts; ordering constraint is enforced by Rust borrow semantics; behavior under all
   three `ExposureResetPolicy` variants is specified.

6. **No policy authorization** (D6): explicit prohibition covering all surfaces, all
   policy types, and specifically `SimVitalityEvaluationContext.p`.

**Backward compatibility proof (§8):** existing raw API signatures unchanged; admissible
tracker is opt-in; existing trial tests require zero modification; Trial 4 T7/T8
manipulability evidence is preserved on the raw surface.

**Implementation is authorized to proceed** on the production files listed in §4, with
the following conditions at implementation time:

- Condition A: The raw accounting path in `sample_with_receipts()` must call
  `ExposureTracker::record(&ids)` exactly once — confirmed not to double-count.
- Condition B: The admissible tracker must be an `Option<AdmissibleExposureTracker>`
  inside `ProviderPool`; it must be `None` by default and only populated after
  `with_admissible_tracking()` is called — this ensures zero behavioral change for
  any pool that does not opt in.
- Condition C: `drain_epoch()` must be called inside `do_rotate()` after `epoch_count`
  is incremented and before control returns to any caller.

**The 13 tests in `test/tests/trial5b.rs` are required.** Implementation is not
complete until all 13 pass alongside the existing 481-test baseline (494 total).
