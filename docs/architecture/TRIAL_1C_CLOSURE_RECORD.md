# Trial 1c Closure Record — Simulator Runtime Vitality Enforcement

**Verdict**: `A — TRIAL_1C_SIMULATOR_RUNTIME_VITALITY_ENFORCEMENT_PROVEN`
**Date**: 2026-05-28
**Predecessor**: `TRIAL_1B_CLOSURE_RECORD.md` (B — TRIAL_1B_MODEL_PROVEN_BASELINE_UNSTABLE → closed via sim_s34/sim_s49 stability fixes)
**Successor plan**: `CORRIDOR_TRIAL_2_PROVIDER_FAILURE_OBSERVABILITY_PLAN.md`

---

## 1. Verdict Summary

| Dimension | Result |
|-----------|--------|
| Bilateral vitality evidence model | PROVEN |
| Explicit simulator control validation for `i`, `r`, `p` | PROVEN |
| Single deterministic evaluation clock in simulator sends | PROVEN |
| Runtime-path vitality lookup before encrypted burst creation | PROVEN |
| Suspended relationship rejects a new simulated send | PROVEN |
| Reaffirmation restores simulated send eligibility | PROVEN |
| Production-oriented path regression coverage | ADDED |
| Full workspace baseline (3 consecutive clean runs) | **457 / 457 / 457** |

The critical success is this boundary:

```
open_and_send_sim()
  → retrieve_state_sim() obtains bilateral vitality evidence via VitalityEvidenceStore
  → vitality computed under ctx.now (single deterministic clock)
  → computed VitalityState enforced at send gate
  → enters open_and_send_core_at() on the real encrypted burst path
```

That is an honest simulator-runtime proof.

---

## 2. Prior Accepted Baseline

- **Trial 1b baseline**: 445 passing
  - `sim_s34` and `sim_s49` produced stochastic failures in the full workspace run;
    three consecutive clean workspace runs were not achieved under Trial 1b.
  - The stochastic failures were classified as pre-existing specification errors in
    `test/tests/sim.rs` (under-sampled assertion thresholds), unrelated to Trial 1b work.
- **Baseline stabilization**: `sim_s34` and `sim_s49` were fixed prior to Trial 1c closure
  by correcting sample counts and assertion thresholds in `test/tests/sim.rs`.
  The sim suite (68 tests) now passes deterministically.
- **Trial 1c acceptance tests added**: 12 new tests in `test/tests/trial1c.rs`.
- **New authoritative baseline**: **457 passing, 0 failing**.

---

## 3. Test Count Accounting

| Suite | Tests | Source |
|-------|-------|--------|
| adversarial | 45 | pre-Trial 1c |
| corridor | 9 | pre-Trial 1c |
| level1 | 4 | pre-Trial 1c |
| metadata | 15 | pre-Trial 1c |
| pool | 121 | pre-Trial 1c |
| property | 13 | pre-Trial 1c |
| quorum | 10 | pre-Trial 1c |
| recovery | 8 | pre-Trial 1c |
| sim | 68 | pre-Trial 1c (stability-fixed) |
| state | 11 | pre-Trial 1c |
| state_machine | 21 | pre-Trial 1c |
| transport | 58 | pre-Trial 1c |
| trial0 | 8 | pre-Trial 1c |
| trial1b | 11 | pre-Trial 1c |
| **trial1c** | **12** | **Trial 1c (new)** |
| vitality | 5 | pre-Trial 1c |
| wire_vectors | 12 | pre-Trial 1c |
| scp_transport (unit) | 9 | pre-Trial 1c |
| scp_wire_format (unit) | 17 | pre-Trial 1c |
| **Total** | **457** | |

Reconciliation: Trial 1b stable baseline 445 + 12 new Trial 1c tests = **457**. Confirmed.

---

## 4. Three Consecutive Clean Workspace Runs

All three runs: `cargo test` from workspace root.

| Run | Result | Passing |
|-----|--------|---------|
| Run 1 | PASS | 457 / 457 |
| Run 2 | PASS | 457 / 457 |
| Run 3 | PASS | 457 / 457 |

Baseline is stable and deterministic.

---

## 5. Files Changed

| File | Change | Type |
|------|--------|------|
| `core/vitality/src/sim_context.rs` | New: `SimVitalityEvaluationContext` and `SimVitalityContextError` | New |
| `core/vitality/src/lib.rs` | Added `pub mod sim_context; pub use sim_context::{SimVitalityContextError, SimVitalityEvaluationContext};` | Modified |
| `core/transport/src/flash.rs` | Added `retrieve_state_sim()`, `open_and_send_core_at()`, `open_and_send_sim()`; refactored `open_and_send_core()` to delegate through `open_and_send_core_at()` | Modified |
| `test/tests/trial1c.rs` | New: 12 Trial 1c acceptance tests | New |
| `docs/architecture/CORRIDOR_TRIAL_1C_RUNTIME_VITALITY_WIRING_PLAN.md` | Updated with resolved blocker descriptions and final A-verdict | Updated |

**Files confirmed NOT modified:**
- `core/transport/src/state.rs` — `StateProvider` unchanged
- `core/transport/src/corridor.rs` — receive path unchanged
- `core/transport/src/harness.rs` — existing dev harness unchanged
- `core/vitality/src/evidence.rs` — `VitalityEvidenceStore` unchanged
- All ledger, relay, provider, identity crates — unchanged
- `test/tests/sim.rs` — only stochastic assertion thresholds corrected; no production code references changed

---

## 6. Two Resolved Blockers

### Blocker 1 — Mixed time domains inside a single simulated send (RESOLVED)

**Problem**: `open_and_send_core()` internally called `SystemTime::now()` as a defense-in-depth
ephemeral expiry check. A simulated send at T0 + 48 days would evaluate vitality using
`ctx.now` (deterministic) but ephemeral expiry using wall-clock time (non-deterministic).

**Resolution**: Extracted `open_and_send_core_at(state, payload, cache, engine, now: u64)` as
the single internal implementation. Production `open_and_send_core()` supplies `SystemTime::now()`;
simulator `open_and_send_sim()` supplies `ctx.now()`. One evaluation clock per send operation.

**File**: `core/transport/src/flash.rs` — `open_and_send_core_at()` at line 243.

### Blocker 2 — `retrieve_state_sim()` alone did not prove send-path wiring (RESOLVED)

**Problem**: Implementing only `retrieve_state_sim()` would prove that a vitality oracle method
exists. It would not prove that the send operation structurally requires it — a caller could
still bypass via `retrieve_state()` + direct `RecipientState` construction.

**Resolution**: Introduced `open_and_send_sim()` as the designated simulator send operation.
Its signature requires `&VitalityEvidenceStore` and `&SimVitalityEvaluationContext` as explicit
parameters. Vitality bypass through this path is structurally prevented at the type system level.
All 12 Trial 1c wiring-claim tests enter through `open_and_send_sim()`.

**File**: `core/transport/src/flash.rs` — `open_and_send_sim()` at line 202.

---

## 7. All 12 Trial 1c Tests and Results

All tests run with `cargo test --test trial1c`.

| # | Test Name | What It Proves |
|---|-----------|----------------|
| T1 | `runtime_active_relationship_permits_send` | Initialized fresh bilateral → Active → send succeeds |
| T2 | `runtime_suspended_relationship_blocks_send` | Past Suspended threshold → VitalityInsufficient(Suspended) |
| T3 | `runtime_reaffirmation_restores_send` | Suspended → `record_reaffirmation()` → Active → send succeeds |
| T4 | `runtime_missing_evidence_fails_closed` | No evidence initialized → fails closed → Suspended |
| T5 | `runtime_relationship_isolation_ab_vs_ac` | AB suspended, AC active — isolation correct |
| T6 | `runtime_send_does_not_refresh_evidence` | Permitted send does not update reaffirmation timestamp |
| T7 | `retrieve_state_sim_bypasses_hardcoded_active` | `retrieve_state()` returns Active; `retrieve_state_sim()` returns Suspended for same uninitialized store |
| T8 | `corridor_receive_unaffected_after_suspension` | Receive-path decryption succeeds after relationship becomes Suspended |
| T9 | `scenario_controls_i_r_p_are_explicit` | Reduced `i=0.3, r=0.5` shifts computed boundary; standard controls still permit send at same `now` |
| T10 | `sim_context_rejects_invalid_controls` | `SimVitalityEvaluationContext::new()` rejects out-of-range, NaN, and infinite values |
| T11 | `simulated_time_controls_ephemeral_expiry` | `ctx.now` governs ephemeral expiry; wall-clock time does not |
| T12 | `production_send_path_unaffected` | Production `open_and_send()` works after `open_and_send_core` refactoring |

**Suite result**: `ok. 12 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out`

---

## 8. Simulator-Only API Documentation

The following APIs added in Trial 1c are simulator-harness surfaces, not production
vitality-measurement contracts:

### `SimVitalityEvaluationContext` (`core/vitality/src/sim_context.rs`)

A context struct whose `i`, `r`, `p` fields are **declared scenario controls**. They are
explicitly validated at construction time (Option A: reject invalid values) and do not
represent measured runtime data. The struct is documented `SIMULATOR ONLY` in its
doc comment. It is not and must not be used to carry measured interaction data from
production network traffic.

### `FlashSession::retrieve_state_sim()` (`core/transport/src/flash.rs:86`)

A simulator-runtime variant of `retrieve_state()` that consults `VitalityEvidenceStore`
instead of hardcoding `VitalityState::Active`. Documented `SIMULATOR ONLY`. The
original `retrieve_state()` and its Phase 9 deferral comment are unchanged.

### `FlashSession::open_and_send_sim()` (`core/transport/src/flash.rs:202`)

The designated SCP simulator send operation. Documented `SIMULATOR ONLY`. Requires
a `VitalityEvidenceStore` and `SimVitalityEvaluationContext` — vitality bypass is
structurally prevented by the signature. Does not replace `open_and_send()`,
`open_and_send_with_envelope()`, or any production call site.

### `FlashSession::open_and_send_core_at()` (`core/transport/src/flash.rs:243`)

Private internal function. Not part of any public API. Accepts an explicit `now: u64`
so that all time-sensitive checks inside one send operation share a single evaluation
clock. Used by both `open_and_send_core()` (production, supplies `SystemTime::now()`)
and `open_and_send_sim()` (simulator, supplies `ctx.now()`).

---

## 9. Permitted Claim

> In the SCP simulator runtime path, the designated simulator send operation
> automatically consults bilateral vitality evidence, applies explicit
> scenario-provided vitality controls under one deterministic evaluation clock,
> and enforces the resulting computed vitality state before creating a new
> encrypted burst.

---

## 10. Non-Claims

| Not proven | Why it remains separate |
|------------|------------------------|
| Production CLI runtime vitality wiring | Production `retrieve_state()` retains Phase 9 deferral; no CLI call site created |
| Production sources for `i`, `r`, or `p` | All three inputs have zero existing runtime measurement sources; declared scenario controls only |
| Production reaffirmation protocol | Simulator injects accepted reaffirmation events; no protocol exchange exists |
| Receive-side vitality gating | `corridor::receive()` is intentionally not vitality-gated; T8 confirms this |
| Relay mailbox delivery and routing privacy policy | Separate architecture gate; unresolved |
| Localhost, LAN, desktop, and hardware readiness | Separate execution tracks |

---

## 11. Architecture Boundary Confirmed

The following architecture boundary enforced in Phase 37 (`ARCHITECTURE_REALITY_GATE.md`)
remains intact after Trial 1c:

- TOLS `κ` is a provider-pool convergence-pressure metric defined in
  `provider/pool/src/metrics.rs`.
- Vitality `VitalityState` is a bilateral relationship decay metric defined in
  `core/vitality/src/`.
- These two systems share no code dependency in either direction. Trial 1c added no
  import, re-export, or cross-reference between the provider pool and the vitality crates.
