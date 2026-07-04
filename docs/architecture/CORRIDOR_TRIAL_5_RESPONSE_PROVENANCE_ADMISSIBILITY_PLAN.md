# Corridor Trial 5 — Response Provenance and Admissibility Decision

**Status:** Planning only. No Rust source files modified.
**Predecessor:** Trial 4 (`A — TRIAL_4_SELECTIVE_SUPPRESSION_CHARACTERIZED`, baseline 481 passing)
**Authorized baseline:** 481 passing × 3 clean runs

---

## Purpose

Trial 4 established that `record_response()` can be called without a prior `sample()`,
and that this unpaired injection allows an adversary to inflate both Surface 2
(`liveness_weighted_kappa`) and Surface 3 (`recent_reported_response_ratio()`) arbitrarily.
This renders all three current telemetry surfaces unauthorized for automatic policy use.

Trial 5 must decide: is the `record_response()` seam a deliberately modeled limitation
(Option A) or an invariant gap to fix (Option B), and does the answer require both surfaces
(Option C)?

---

## Audit 1 — Response-Accounting Call Graph

### Files Inspected

| File | Purpose |
|------|---------|
| `provider/pool/src/lib.rs` | `ProviderPool` public API: `sample()`, `record_response()`, `record_failure()`, `operational_telemetry()` |
| `provider/pool/src/exposure.rs` | `ExposureTracker`: `record()`, `record_response()`, entropy computations, `response_total` |
| `provider/pool/src/metrics.rs` | `OperationalTelemetrySnapshot`, `recent_reported_response_ratio()`, `ConvergencePressure`, `OperationalTelemetrySnapshot` docstrings §S64/§S69 |
| `provider/pool/src/liveness.rs` | `LivenessState`, `LivenessConfig` |
| `provider/pool/src/sampling.rs` | `SamplingStrategy` enum |
| `test/tests/trial4.rs` | T7 injection scenario; established manipulation trace |
| `test/tests/trial2.rs` | Reference: all `record_response()` call sites in Trial 2 |
| `test/tests/trial3.rs` | Reference: all `record_response()` call sites in Trial 3 |

### Response-Accounting Call Graph Table

| Symbol | Defined in | Signature / Description | Caller | Prior selection required? | Production or test-only? |
|--------|-----------|------------------------|--------|--------------------------|--------------------------|
| `ExposureTracker::record()` | `exposure.rs:107` | Records one sample; increments `total_samples` and `appearances[id]` for each provider in quorum | `ProviderPool::sample()` | N/A — this IS the selection call | Production |
| `ExposureTracker::record_response()` | `exposure.rs:118` | Increments `response_total` and `response_appearances[id]`; updates EWMA | `ProviderPool::record_response()` | **No** — takes only `&[u8; 32]` provider ID, no selection token | Production |
| `ProviderPool::sample()` | `lib.rs:924` | Draws live active providers per strategy; calls `ExposureTracker::record(&ids)` | Tests, future orchestration | N/A | Production |
| `ProviderPool::record_response()` | `lib.rs:417` | Resets `consecutive_failures`, updates `last_seen_secs`, calls `ExposureTracker::record_response()` | Tests only (no relay/transport/CLI caller found) | **No** | Production signature, test-only caller |
| `ProviderPool::record_failure()` | `lib.rs:428` | Increments `consecutive_failures` | Tests only | No | Production signature, test-only caller |
| `ProviderPool::operational_telemetry()` | `lib.rs:625` | Read-only snapshot; locks `ExposureTracker`; returns `OperationalTelemetrySnapshot` | Tests | No — read only | Production |
| `OperationalTelemetrySnapshot::recent_reported_response_ratio()` | `metrics.rs:273` | `response_total / selection_total`; returns `None` when `!availability_evaluable` | Tests | No — derived field | Production |
| `OperationalTelemetrySnapshot::recent_response_success_rate()` | `metrics.rs:287` | Alias for `recent_reported_response_ratio()`; deprecated name | Tests | No | Production |
| `ProviderPool::convergence_pressure()` | `lib.rs:536` | Returns `ConvergencePressure` including `liveness_weighted_kappa` and `response_entropy_bits` | Tests, `maybe_rotate()`, `tick()` | No | Production |

### Key Finding: Unpaired `record_response()` Reachability

`ProviderPool::record_response()` takes a bare `[u8; 32]` provider ID with no selection
token, quorum reference, route ID, epoch ID, or outstanding-request record. There is no
map of pending selections that gates whether a response is counted. There is no
at-most-once constraint. There is no ordering guarantee relative to `sample()`.

In the current production codebase, no relay, transport, CLI, or orchestration layer
calls `record_response()`. The call sites found are exclusively in test files
(`trial2.rs`, `trial3.rs`, `trial4.rs`). This means:

**The unpaired `record_response()` seam is production-reachable in principle** (the method
is `pub` with no guard), **but has no production caller at present**. It is callable by any
future orchestration layer without requiring a source change to `ProviderPool` itself.

---

## Audit 2 — Intended Semantics of the Injection Seam

### Comments in `metrics.rs` (§S64 and §S69)

The docstring for `OperationalTelemetrySnapshot` (Surface 3 description) states at line 219:

> "Response injection can inflate the numerator; see §S64."

The docstring for `recent_reported_response_ratio()` at lines 265–269 states:

> "TELEMETRY-ONLY — unverified. The numerator is incremented by every `record_response()`
> call; those calls are not causally bound to actual selected relay attempts. An adversary
> or buggy caller can inflate this value arbitrarily (see §S64, §S69). Do not derive
> automatic policy from this metric until responses are bound to specific selected attempts
> with at-most-once accounting and unmatched-response rejection."

The docstring for `recent_response_success_rate()` (the deprecated alias) at lines 283–285 states:

> "The name 'success_rate' overstates verification: `record_response()` calls are not bound
> to actual relay attempts and can be injected, inflating the numerator without any real relay
> success (see §S64)."

**Interpretation**: The documentation explicitly names the injection gap and explicitly states
what would be required to close it ("responses bound to specific selected attempts with
at-most-once accounting and unmatched-response rejection"). This framing treats injection as
a **known limitation of the current model**, not as a desired design invariant. The word
"until" in the docstring ("Do not derive automatic policy... **until** responses are
bound...") signals that a future binding is anticipated and the current state is provisional.

**Finding — Audit 2**: The injection seam is framed as a **documented provisional gap**, not
as an intentional adversarial feature of the model. The documentation explicitly describes
the condition under which the gap would be closed: pairing with at-most-once accounting and
unmatched-response rejection.

---

## Audit 3 — Available Provenance Keys

### What currently exists

| Key type | Available in current code | Notes |
|----------|--------------------------|-------|
| Provider ID (`[u8; 32]`) | Yes — in `sample()` return, in `record_response()` call | Used to associate response with provider, but not with specific selection event |
| Selection/request ID | **No** | No per-sample token is generated or returned |
| Epoch ID | **No** | `epoch_count` is a pool-level counter, not per-sample |
| Route/attempt ID | **No** | `RouteId` exists in transport layer but is not threaded to `ProviderPool` |
| Outstanding request record | **No** | No pending-selection map exists |
| One-response-per-selection constraint | **No** | `record_response()` can be called N times for the same provider without limit |
| Replay/duplicate detection | **No** | No deduplication of responses |
| Ordering guarantee | **No** | Responses are counted whenever `record_response()` is called |

### What would be required for admissibility

A provenance-complete model would require at minimum:
1. Each `sample()` call to generate a unique selection token (e.g., a nonce or sequence number).
2. That token to be threaded to the relay/transport layer and returned with the response.
3. `record_response()` to accept the token and reject calls for tokens not in an outstanding-request map.
4. The outstanding-request map to enforce at-most-once: a token removed on first response or failure.

None of these structures exist in the current code.

**Finding — Audit 3**: There is **insufficient provenance infrastructure** to pair responses
with eligible prior selection events. Production source changes would be required to implement
any response-admissibility model beyond the current unverified counter.

---

## Audit 4 — Adversarial Cases and Proposed Deterministic Tests

The following traces form the proposed test suite for `test/tests/trial5.rs`.

| Test ID | Trace description | What it distinguishes |
|---------|------------------|-----------------------|
| T1 | One selection, one response for the selected provider | Baseline: valid paired sequence |
| T2 | One response without any prior selection | Documents injection seam: response counted with no selection event |
| T3 | Two responses for the same provider after one selection | Documents numerator inflation: at-most-once not enforced |
| T4 | Response for provider B after only provider A was selected | Provider mismatch: response accepted regardless of which provider was selected |
| T5 | Selection for A, then selection for B, then response for A | Delayed response: response accepted regardless of selection ordering or staleness |
| T6 | Selection, `record_failure()`, then `record_response()` for same provider | Response after recorded failure: failure does not gate subsequent response acceptance |
| T7 | Symmetric suppression (T5/T6 trace from Trial 4) absent injection | Surface 3 counter-signal (ratio < 1.0) still detects suppression |
| T8 | Symmetric suppression plus injected responses (T7 trace from Trial 4) | Both Surface 2 and Surface 3 masked; no counter-signal available |
| T9 (Option C) | Same trace presented on two separate fields: raw reported and a hypothetical paired/admissible surface | Would demonstrate that only the admissible surface is manipulation-resistant |

**Note on T9**: T9 is contingent on Option C (maintaining dual surfaces). Under Options A or B
alone, T9 may be deferred or reformulated. T1–T8 are independent of which option is selected.

---

## Audit 5 — Impact on Existing Trial Findings

### Option A — Untrusted Reported-Response Model

Under Option A, injection is intentionally modeled as an adversarial limitation: the
`recent_reported_response_ratio()` and `liveness_weighted_kappa` surfaces are openly
untrusted. No production source change is made. Documentation remains as-is.

| Trial claim | Impact under Option A |
|-------------|----------------------|
| Trial 2 observability proof | **Valid**. The six proof tests observe genuine telemetry changes under scripted traces. Option A does not invalidate the surface-existence proof. |
| Trial 3 orthogonality proof | **Valid**. The structural separation of pool telemetry from vitality and send authorization is unchanged. Option A does not introduce coupling. |
| Trial 4 manipulability finding | **Valid and the motivating finding**. Option A treats T7 (injection masks surfaces) as a confirmed limitation, not a defect to repair. |
| `OperationalTelemetrySnapshot` semantics | **Unchanged**. All fields remain telemetry-only. The docstring already says "TELEMETRY-ONLY — unverified." Option A formalizes this status. |

### Option B — Eligible-Response Accounting Model

Under Option B, injection is treated as an invariant gap to fix. A production source change
adds a pending-selection map; `record_response()` is modified to require a prior selection
token; unmatched calls are rejected.

| Trial claim | Impact under Option B |
|-------------|----------------------|
| Trial 2 observability proof | **Preserved in spirit**, but the test traces would need to pass a selection token to `record_response()`. If the seam signature changes, tests must be updated. The proof itself remains: surfaces observe telemetry changes. |
| Trial 3 orthogonality proof | **Valid and strengthened**. Closing the injection gap does not create coupling between pool telemetry and vitality. |
| Trial 4 manipulability finding | **Partially superseded**. T7 (injection masks surfaces) would no longer be achievable through `record_response()` without a valid selection token. The test would document the pre-fix state. |
| `OperationalTelemetrySnapshot` semantics | **Changed**. The `response_total` field would become admissible (paired) rather than reported (unverified). The `recent_reported_response_ratio()` docstring warning would need updating. |

Option B requires non-trivial production source changes and would affect the test API.

### Option C — Both Surfaces Maintained

Under Option C, the existing unverified surface is preserved alongside a new admissible
surface backed by selection-paired accounting.

| Trial claim | Impact under Option C |
|-------------|----------------------|
| Trial 2 observability proof | **Valid**. The raw reported surface remains. The new admissible surface provides an additional proof point. |
| Trial 3 orthogonality proof | **Valid**. Structural separation is unchanged. |
| Trial 4 manipulability finding | **Valid and motivating**. T7 proves the raw surface is manipulable; the new admissible surface would prove manipulation is detectable by comparison. |
| `OperationalTelemetrySnapshot` semantics | **Extended**. New fields for `admissible_response_total` and derived ratio. Existing fields unchanged. |

Option C requires the most production source changes but provides the richest future proof
surface.

---

## Audit 6 — Policy Safety Conclusion

**No current telemetry field is authorized for automatic policy.**

This conclusion is grounded in the following chain:

1. `kappa` (Surface 1) is policy-authoritative exclusively for the T1 catastrophic-collapse
   signal (s < √n). It does not reflect response behavior.

2. `liveness_weighted_kappa` (Surface 2) is documented as TELEMETRY-ONLY. Trial 4 T5 proves
   that symmetric suppression can preserve `liveness_weighted_kappa = 0.0` while response
   participation falls by 50%. Trial 4 T7 proves that injection can restore
   `liveness_weighted_kappa = 0.0` even over a genuinely suppressed trace.

3. `recent_reported_response_ratio()` (Surface 3) is documented as TELEMETRY-ONLY with an
   explicit "unverified" qualifier and §S64/§S69 references. Trial 4 T7 proves that injection
   can inflate this ratio from 0.5 to 1.0 without any actual relay attempt.

4. The underlying `response_total` and `selection_total` counters are the raw inputs to
   Surface 3. Neither is protected by provenance pairing, at-most-once accounting, or
   unmatched-response rejection.

5. No provenance infrastructure (selection token, outstanding-request map, duplicate
   detector) exists in the current codebase.

**Conclusion**: Automatic use of any current surface for vitality decisions, send
authorization, provider rotation, relay routing, or TOLS policy remains unauthorized.

---

## Analysis of Options A, B, C

### Option A — Untrusted Reported-Response Model

**Summary**: Accept the current surface as an intentionally limited "reported" signal.
Operators are warned; telemetry is observational only. No production change.

**Advantages**:
- Zero production source changes; no test API breaks.
- Consistent with the existing §S64/§S69 docstring framing ("until responses are bound...").
- Trials 1–4 closure records remain exactly valid.

**Disadvantages**:
- Operators have no manipulation-resistant participation metric.
- Future policy work must start from the same gap.
- Does not close the seam; injection remains silently possible.

**Suitability**: Appropriate if the primary goal is characterization without commitment
to a production remediation timeline.

---

### Option B — Eligible-Response Accounting Model

**Summary**: Treat the missing invariant as a defect. Close the unpaired-response seam
by adding a pending-selection map and requiring a token for `record_response()`.

**Advantages**:
- Removes the injection seam entirely.
- Makes `recent_reported_response_ratio()` eligible for future policy consideration.
- Strengthens the contract for all future callers.

**Disadvantages**:
- Non-trivial production source changes to `ProviderPool`, `ExposureTracker`, and `record_response()`.
- All existing test callers of `record_response()` must change signature.
- Trials 2–4 test suites require updating.
- Selection token threading from transport layer to pool is architecturally new coupling.
- Risk of introducing new bugs in the provider-pool critical path.

**Suitability**: Appropriate when automated policy relying on response participation is
imminent and the engineering cost of the seam closure is acceptable.

---

### Option C — Both Surfaces Needed (Raw Reported + Admissible/Paired)

**Summary**: Preserve the existing unverified `response_total` / `liveness_weighted_kappa`
as the "raw reported" surface (unchanged API); add a parallel "admissible" surface backed
by selection-paired accounting.

**Advantages**:
- Backward compatible — existing tests and callers unchanged.
- Raw surface documents what callers actually observe (including adversarial injection).
- Admissible surface provides a manipulation-resistant parallel metric.
- T9 trace (from Audit 4) can directly compare the two surfaces on the same manipulation trace.

**Disadvantages**:
- Larger production change than Option A, smaller than Option B in terms of API breakage.
- Two parallel accounting paths increase internal complexity.
- The admissible surface still requires selection token infrastructure.

**Suitability**: Appropriate when both observational fidelity (what the raw surface shows,
including under adversarial injection) and policy safety (the admissible surface) are needed.

---

## Recommended Response-Admissibility Model

**Recommended: Option C, staged.**

Stage 1 (current): Formalize Option A by writing `TRIAL_5_CLOSURE_RECORD.md` that explicitly
names the provenance gap, documents the existing raw-reported semantics, and declares all
surfaces non-authoritative. No production source changes.

Stage 2 (future, gated by a separate architecture gate): Implement the admissible surface as
a new `AdmissibleResponseTracker` alongside the existing `ExposureTracker`. The admissible
tracker would require a selection token (returned by `sample()`) to be passed to a
`record_admissible_response(token, provider_id)` method. The raw `record_response()` would
remain available for backward compatibility and for scenarios where injection modeling is
desired.

Stage 2 is authorized only after:
1. A selection-token infrastructure design is reviewed and approved.
2. The transport-to-pool threading plan is documented.
3. A new architecture gate is opened.

**Reasoning**: Option B alone breaks existing callers and closes the observational seam that
Trial 4 was specifically designed to document. Option C preserves that observational record
while providing a path to policy-safe accounting. The staged approach defers the production
risk to a separately gated phase.

---

## Would Production Source Changes Be Required?

- **Option A (Stage 1 only)**: No production source changes.
- **Option B / Option C Stage 2**: Yes. The minimum viable change is:
  1. `sample()` returns a selection token in addition to the `ProviderQuorum`.
  2. `record_admissible_response(token, provider_id)` added to `ProviderPool`.
  3. Internal `AdmissibleExposureTracker` with at-most-once token map.
  4. `OperationalTelemetrySnapshot` extended with `admissible_response_total`,
     `admissible_selection_total`, and `recent_admissible_response_ratio()`.
  5. Tests for all nine adversarial cases from Audit 4.

These changes affect `provider/pool/src/lib.rs`, `provider/pool/src/exposure.rs`,
and `provider/pool/src/metrics.rs`. No other production crates are modified in Stage 2
unless selection-token threading into the transport layer is also authorized.

---

## Proposed Future Deterministic Tests (from Audit 4)

These are the proposed Trial 5 tests for `test/tests/trial5.rs`:

| Test function | Scenario | Assertion target |
|---------------|---------|-----------------|
| `t1_valid_paired_sequence` | One selection, one response for selected provider | Documents minimum valid paired sequence; both surfaces show healthy |
| `t2_response_without_selection` | `record_response()` called before any `sample()` | Proves injection: `response_total = 1`, `selection_total = 0`, `availability_evaluable = false` (Surface 3 unevaluable) |
| `t3_two_responses_one_selection` | Two `record_response()` calls after one `sample()` | Proves numerator inflation: `response_total = 2`, `selection_total = 1`, ratio = `Some(2.0)` |
| `t4_response_for_wrong_provider` | Select provider A, record response for provider B | Documents provider mismatch: both response and selection totals increment regardless |
| `t5_delayed_response_after_later_selection` | Select A, select B, record response for A | Documents ordering: response counted with no staleness guard |
| `t6_response_after_failure` | Select, `record_failure()`, `record_response()` for same provider | Documents failure does not gate response: `consecutive_failures` reset to 0, `response_total` incremented |
| `t7_symmetric_suppression_absent_injection` | T5/T6 trace from Trial 4 (ratio = 0.5) | Confirms Surface 3 counter-signal present absent injection |
| `t8_symmetric_suppression_plus_injection` | T7 trace from Trial 4 (ratio masked to 1.0) | Confirms both surfaces masked simultaneously |

Test T9 (Option C dual-surface comparison) deferred pending Stage 2 implementation.

All tests use `StdRng::seed_from_u64(0)` for any `sample()` calls. No wall-clock timing.
No threshold assertions on probabilistic distributions. All assertions are exact or within
1e-12 tolerance for floating-point derived values.

---

## Impact on Trials 2–4 Closure Claims

| Claim | Remains valid? | Notes |
|-------|---------------|-------|
| Trial 2: "surfaces expose expected degradation signals" | Yes | The existence proof of Surface 1/2/3 observability is unchanged. The surfaces exist and respond to scripted traces as documented. |
| Trial 2: "without automatically changing vitality, rotation, or relay" | Yes | Structural separation is unchanged. |
| Trial 3: "provider-failure telemetry can change observably while vitality remains unchanged" | Yes | Orthogonality proof does not depend on admissibility of the telemetry. |
| Trial 3: "no accidental runtime coupling was introduced" | Yes | No coupling exists. |
| Trial 4: "record_response() does not require a prior sample() call" | Yes | This is a structural fact about the current implementation. |
| Trial 4: "response_total numerator is freely inflateable" | Yes | Trial 5 T2–T3 reconfirm this with additional precision. |
| Trial 4: "no current surface is authorized for automatic policy" | Yes and extended | Trial 5 formally documents the provenance gap that underlies this conclusion. |

No Trial 2, 3, or 4 closure record requires amendment. Trial 5 adds specificity to the
manipulability finding without invalidating any prior observability or orthogonality proof.

---

## Explicit Policy Non-Authorization Statement

The following fields of `OperationalTelemetrySnapshot` are **not authorized** for automatic
policy of any kind:

| Field | Non-authorized uses |
|-------|---------------------|
| `kappa` | Vitality decisions, send rejection, rotation triggers (exception: T1 catastrophic-collapse classification, which was authorized in prior phases) |
| `liveness_weighted_kappa` | Any automatic policy: eviction, rotation, vitality, send, relay, routing |
| `response_total` | Any automatic policy |
| `selection_total` | Any automatic policy (counter-signal only, not causal) |
| `recent_reported_response_ratio()` | Any automatic policy |
| `recent_response_success_rate()` | Any automatic policy (deprecated alias) |
| Derived combinations of the above | Any automatic policy |

This non-authorization is not scope-limited to "adversarial" scenarios. Even in the absence
of active injection, the surfaces lack provenance pairing and therefore cannot certify that
a counted response corresponds to a completed relay attempt.

Authorization of any surface for automatic policy requires:
1. Provenance pairing (at-most-once, selection-token-gated `record_response()`).
2. A new architecture gate document.
3. A new Trial demonstrating that the admissible surface resists all nine adversarial traces
   from Audit 4.
4. An explicit update to this non-authorization statement.

---

## Verdict

`B — TRIAL_5_REQUIRES_EVENT_PROVENANCE_MODEL`

**Rationale**: The documentation (§S64, §S69) uses the word "until" to signal that the
current state is provisional and a provenance-paired model is the anticipated resolution.
The gap is not an intentional design decision — it is a tracked limitation. The recommended
path (Option C, staged) requires a future production source change to close the unpaired-
response seam before any current surface can be considered for automatic policy. Until that
gate is opened and proven, all telemetry surfaces remain observational only.
