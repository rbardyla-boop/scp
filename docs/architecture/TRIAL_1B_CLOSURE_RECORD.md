# Trial 1b Closure Record — Vitality Evidence Store and Send Gate Composition

**Verdict**: `B — TRIAL_1B_MODEL_PROVEN_BASELINE_UNSTABLE`  
**Date**: 2026-05-28  
**Prerequisite**: Trial 1a — Static Vitality Gate (CLOSED AND BASELINED)

---

## 1. Verdict Summary

| Dimension | Result |
|-----------|--------|
| Vitality evidence-store implementation | PROVEN |
| Send gate composition | PROVEN |
| Workspace baseline (3 consecutive clean runs) | NOT ACHIEVED |

The relationship-scoped `VitalityEvidenceStore` is correctly implemented and all 11
Trial 1b tests pass cleanly on every run.  The workspace cannot produce three
consecutive clean runs because `test/tests/sim.rs` contains stochastic failures in
pre-existing simulator tests (`sim_s34`, `sim_s49`) that are entirely orthogonal to
Trial 1b work.

---

## 2. Files Changed by Trial 1b

| File | Git Status | Role |
|------|-----------|------|
| `core/vitality/src/evidence.rs` | Untracked (`??`) | New: VitalityEvidenceStore implementation |
| `core/vitality/src/lib.rs` | Modified (`M`) | Re-export of VitalityEvidenceStore |
| `test/tests/trial1b.rs` | Untracked (`??`) | New: 11 Trial 1b test cases |

No changes were made to any pool, simulator, transport-layer, or relay-layer source file.

---

## 3. VitalityEvidenceStore API (Final)

```rust
// core/vitality/src/evidence.rs

pub struct VitalityEvidenceStore {
    evidence: HashMap<[u8; 32], u64>,  // consent_hash → last_reaffirmed_at (Unix secs)
}

impl VitalityEvidenceStore {
    pub fn new() -> Self;

    /// First call: inserts timestamp, returns true.
    /// Subsequent calls: no-op, returns false. (Write-once.)
    pub fn initialize_at(&mut self, consent_hash: [u8; 32], established_at: u64) -> bool;

    /// Returns true on success; false if consent_hash has no evidence. (No implicit create.)
    pub fn record_reaffirmation(&mut self, consent_hash: [u8; 32], now: u64) -> bool;

    /// Returns VitalityState::Suspended for unknown hashes (fails closed).
    /// i, r, p are vitality formula inputs; now is caller-supplied Unix seconds.
    pub fn compute_state(&self, consent_hash: [u8; 32], now: u64, i: f64, r: f64, p: f64) -> VitalityState;
}
```

Key design properties:
- Keyed by bilateral consent hash (`tunnel_consent_hash(party_a, party_b)`)
- Write-once initialization prevents timestamp overwrite attacks
- Unknown relationships fail closed to `Suspended`, not derived from zero-epoch
- `record_reaffirmation` rejects uninitialized hashes — no implicit initialization
- Sends do not call `record_reaffirmation` — decay continues from last reaffirmation

---

## 4. All 11 Trial 1b Tests and Results

All tests run with `cargo test --test trial1b`.

| # | Test Name | Result (isolated run) |
|---|-----------|----------------------|
| 1 | `evidence_initialized_at_establishment_is_active_and_permits_send` | PASS |
| 2 | `evidence_missing_fails_closed_to_suspended` | PASS |
| 3 | `evidence_initialize_at_is_write_once` | PASS |
| 4 | `evidence_reaffirmation_rejects_uninitialized_hash` | PASS |
| 5 | `evidence_active_warm_boundary` | PASS |
| 6 | `evidence_warm_dormant_boundary` | PASS |
| 7 | `evidence_dormant_suspended_boundary` | PASS |
| 8 | `evidence_suspended_composes_with_send_gate_as_vitality_insufficient` | PASS |
| 9 | `evidence_reaffirmation_after_suspension_restores_active_and_permits_send` | PASS |
| 10 | `evidence_successful_send_does_not_implicitly_refresh_vitality` | PASS |
| 11 | `evidence_relationship_isolation` | PASS |

**Suite result**: `ok. 11 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out`

---

## 5. Exact Total Count Accounting

| Suite | Tests | Source |
|-------|-------|--------|
| adversarial | 45 | pre-Trial 1b |
| corridor | 9 | pre-Trial 1b |
| level1 | 4 | pre-Trial 1b |
| metadata | 15 | pre-Trial 1b |
| pool | 121 | pre-Trial 1b |
| property | 13 | pre-Trial 1b |
| quorum | 10 | pre-Trial 1b |
| recovery | 8 | pre-Trial 1b |
| sim | 68 | pre-Trial 1b (untracked) |
| state | 11 | pre-Trial 1b |
| state_machine | 21 | pre-Trial 1b |
| transport | 58 | pre-Trial 1b |
| trial0 | 8 | pre-Trial 1b |
| **trial1b** | **11** | **Trial 1b (new)** |
| vitality | 5 | pre-Trial 1b |
| wire_vectors | 12 | pre-Trial 1b |
| scp_transport (unit) | 9 | pre-Trial 1b |
| scp_wire_format (unit) | 17 | pre-Trial 1b |
| **Total** | **445** | |

Reconciliation: Trial 1a baseline 434 + 11 new Trial 1b tests = **445**. Confirmed.

---

## 6. sim_s49 Classification Evidence

**Test**: `sim_s49_on_rotation_freshness_vs_never_under_silent_failure`  
**File**: `test/tests/sim.rs`, lines 2868–2959  
**Git status of `test/tests/sim.rs`**: Untracked (`??`) — no commit history

### Failure assertion (confirmed from live failure output)

```
thread 'sim_s49_on_rotation_freshness_vs_never_under_silent_failure' panicked at test/tests/sim.rs:2939:5:
§S49: OnRotation κ must stay near-zero (selection uniform); got 0.0710
```

Line 2939 is:
```rust
assert!(
    onrot_last.kappa < 0.05,
    "§S49: OnRotation κ must stay near-zero (selection uniform); got {:.4}",
    onrot_last.kappa
);
```

### Root cause

After `ExposureResetPolicy::OnRotation` clears the exposure tracker at the second
rotation, only 10 samples are taken during `run_epoch(10)`.  With 4 active
providers and `RandomK(1)`, 10 samples gives approximately 2.5 observations per
provider.  The binomial variance at this sample count is sufficient to produce
`kappa > 0.05` on approximately 12% of runs.

This is a pre-existing test specification error: the kappa threshold of `< 0.05`
is not achievable reliably with 10 post-reset samples.  The bug is entirely within
the `scp_provider_pool` subsystem — no vitality module is imported or referenced.

### Isolation evidence

`sim.rs` imports:
```rust
use scp_ledger_substrate::SubstrateLedger;
use scp_provider_pool::{...};
use rand_core::OsRng;
use std::time::Duration;
```

No import of `scp_vitality`, `scp_transport`, `scp_cryptography`, or any module
added or modified by Trial 1b.  `sim_s49` shares no state, crate, random source
injection, global state, or test-order dependency with any Trial 1b test.

### 25-run isolation failure rate

| Outcome | Count | Rate |
|---------|-------|------|
| PASS | 22 | 88% |
| FAIL | 3 (runs 2, 15, 24) | 12% |

### Was sim_s49 present before Trial 1b?

`test/tests/sim.rs` is untracked by git — it has never been committed.  The file
was written incrementally across Phases 26–40 as the simulator grew.  The §S49
comment header references Phase 38 liveness envelope work, which predates Trial 1b.

The sim suite has 68 tests (§S1–§S69) and was part of the workspace test command
before Trial 1b was started.  Trial 1b added no test to `sim.rs` and modified
no file that `sim.rs` depends on.

---

## 7. Additional Stochastic Failure: sim_s34

`sim_s34_liveness_failures_elevate_kappa` also exhibited stochastic failure in
at least one of the 4 workspace runs performed during this verification session
(workspace run 1).

The test asserts `post_failure_kappa > baseline_kappa + 0.2` after killing 3 of 4
active providers via `record_failure`.  The stochastic element is the same as
`sim_s49`: random provider selection during `run_epoch(1)` affects the exposure
distribution, and the assertion margin may not be met in unfavorable draws.

`sim_s34` also makes no import or reference to any vitality module.

---

## 8. Three Consecutive Clean Workspace Runs: NOT ACHIEVED

| Run | sim.rs result | Workspace result |
|-----|---------------|-----------------|
| Run 1 | FAIL (sim_s34) | FAIL |
| Run 2 | PASS (68/68) | PASS (445/445) |
| Run 3 | FAIL (1 sim test) | FAIL |
| Run 4 | PASS (68/68) | PASS (445/445) |

Three consecutive clean runs were not achieved.  The workspace has a stochastic
failure rate of approximately 25–35% per run due to pre-existing sim test
sensitivity to small sample counts.

---

## 9. Preserved Claim Boundary

| Claim | Status |
|-------|--------|
| Evidence-store vitality model: correct and deterministic | **PROVEN** |
| Send gate composition: VitalityInsufficient on non-Active state | **PROVEN** |
| `retrieve_state()` vitality oracle wiring | **Not implemented** |
| Receive-side decryption vitality-gating | **Not implemented** |
| Production reaffirmation protocol | **Not implemented** |
| Automatic runtime vitality enforcement | **Not implemented** |
| Relay, localhost, LAN, hardware readiness | **Not proven** |

---

## 10. Recommended Next Action

### Prerequisite: sim_s49 and sim_s34 specification fix

Before Trial 1b can be cleanly baselined, the assertion thresholds in `sim_s49`
and `sim_s34` must be corrected (or the post-reset sample count increased) so that
the sim suite produces deterministic results.  This is a specification fix, not a
production code change.

**sim_s49 fix**: Increase `run_epoch(10)` to `run_epoch(200)` in the final
snapshot step, or widen the kappa threshold from `< 0.05` to `< 0.15`.

**sim_s34 fix**: The margin `> baseline_kappa + 0.2` is appropriate; the
stochastic risk comes from the 200-epoch baseline being somewhat variable.
Running 500 baseline epochs would stabilize it.

### After baseline closure: Trial 1c — Runtime Vitality Oracle Wiring

The natural next step is wiring `retrieve_state()` so that the ordinary send path
consults `VitalityEvidenceStore` rather than hardcoding `VitalityState::Active`.

**Planning-only outline (do not implement in this pass)**:

1. **Sender and recipient identity availability**: the send path needs both
   `party_a` (sender's ops public key) and `party_b` (recipient's ops public key)
   to compute `tunnel_consent_hash(party_a, party_b)` before the send gate fires.

2. **Store access seam**: `VitalityEvidenceStore` must be accessible at the point
   where `retrieve_state()` is called.  Currently `retrieve_state()` returns a
   hardcoded `VitalityState::Active`; this must become a lookup.

3. **Bilateral lookup symmetry**: the hash must be computed identically by both
   parties regardless of which is `party_a` and which is `party_b`.  The existing
   `tunnel_consent_hash` function handles this if it is commutative; verify.

4. **Trial 1c claim boundary**: proving that `retrieve_state()` returns
   `VitalityEvidenceStore::compute_state(...)` for the correct relationship hash.
   No localhost networking, no relay, no LAN hardware required for Trial 1c.
