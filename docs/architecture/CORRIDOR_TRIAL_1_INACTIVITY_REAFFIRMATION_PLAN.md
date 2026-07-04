# Corridor Trial 1 — Inactivity and Reaffirmation Plan

**Status**: Planning complete. Verdict: B (see §7).  
**Date**: 2026-05-28  
**Prerequisite**: Trial 0 — Direct In-Process Burst Decrypt Roundtrip (Phase 41, CLOSED AND BASELINED)

---

## 1. Trial 1 Permitted Claim and Explicit Non-Claims

### Permitted claim (if implementation reaches A verdict)

> Under deterministic simulated time, a corridor participant whose vitality state
> falls below the open threshold is blocked from sending, and a corridor participant
> whose vitality state is restored by a reaffirmation event can send again — using
> the exact existing vitality semantics.

### Claims explicitly NOT permitted by Trial 1

- Real wall-clock inactivity measurement
- Relay mailbox delivery
- Relay routing metadata policy
- Asynchronous transport, localhost networking, LAN networking
- Desktop or hardware readiness
- Any new vitality semantics or thresholds
- Any Human Vocabulary V1.2 label changes

---

## 2. Current Vitality Behavior Audit

### 2.1 VitalityFunction (`core/vitality/src/function.rs`)

```rust
pub fn compute(params: VitalityParams) -> f64
// VitalityParams { t: f64, i: f64, r: f64, p: f64 }
// V = exp(-t / TAU) * sqrt(i * r) * (1 - PERTURBATION_WEIGHT * p)
```

**Key facts:**
- **Entirely pure** — no `SystemTime::now()`, no global state
- `t` is the caller's responsibility: seconds since last reaffirmation event
- `TAU_SECS` = 30 days (2,592,000 s)
- No time injection needed in this function; it already accepts `t` as a parameter

**Already tested** in `test/tests/state_machine.rs` (6 tests covering decay, entropy, perturbation, band boundaries).

### 2.2 VitalityState (`core/vitality/src/state.rs`)

```rust
pub fn from_score(score: f64) -> Self { ... }
pub fn is_open(&self) -> bool { matches!(Active | Warm | Dormant) }
```

**Band thresholds** (hardcoded, permanent wire-format contract):

| Score range | State | is_open() |
|---|---|---|
| ≥ 0.80 | Active | true |
| ≥ 0.50 | Warm | true |
| ≥ 0.20 | Dormant | true |
| < 0.20 | Suspended | false |
| (explicit) | Severed | false |
| (explicit) | Burned | false |

**Already tested** in `test/tests/state_machine.rs` (band tests, open state tests).

### 2.3 `retrieve_state` in `core/transport/src/flash.rs`

```rust
// flash.rs:58-75
pub async fn retrieve_state(provider, recipient_ops_pub) -> Result<RecipientState, TransportError> {
    if provider.is_revoked(recipient_ops_pub) { ... }
    let now = SystemTime::now()...; // used ONLY for ephemeral expiry filtering
    Ok(RecipientState {
        ops_pub: *recipient_ops_pub,
        vitality: VitalityState::Active, // Phase 9: vitality oracle — HARDCODED
        routing_hints: vec![],
        handshake_ephemeral: provider.get_handshake_ephemeral(recipient_ops_pub, now),
    })
}
```

**Critical finding**: `vitality` is **hardcoded to `VitalityState::Active`**. The code comment explicitly marks this as "Phase 9: vitality oracle." The vitality oracle — reading last-exchange time, calling `VitalityFunction::compute()`, mapping through `from_score()` — does **not exist**.

The two `SystemTime::now()` calls in `flash.rs` (lines 65 and 181) are both for **ephemeral key expiry** checking, not vitality.

### 2.4 Enforcement in `open_and_send_core` (`core/transport/src/flash.rs`)

```rust
// flash.rs:166-168
if !state.vitality.is_open() {
    return Err(TransportError::VitalityInsufficient(state.vitality));
}
```

**This enforcement IS real and executable.** Any `RecipientState` with `vitality: Suspended | Severed | Burned` will cause `open_and_send` and `open_and_send_with_envelope` to fail immediately with `VitalityInsufficient`. This has never been triggered in practice because `retrieve_state` always returns `Active`.

### 2.5 Transcript binding

`FlashTranscriptV2` binds `vitality_snapshot` into the 95-byte transcript hash. **Already proven** by corridor test 9 (`corridor_modified_vitality_snapshot_fails`): changing the vitality snapshot in `BurstEnvelope` causes decryption failure.

### 2.6 SubstrateLedger vitality API

`SubstrateLedger` public API (from `ledger/substrate/src/lib.rs`):
- `register_identity`, `rotate_key`, `revoke`
- `register_tunnel`, `revoke_tunnel`, `query_tunnel`
- `publish_handshake_ephemeral`, `get_handshake_ephemeral`
- `is_revoked`, `query_current_ops_key`

**Zero vitality-related methods.** The ledger stores no last-exchange timestamps, no vitality scores, no reaffirmation events.

### 2.7 Reaffirmation

`VitalityParams.t` is documented as "seconds elapsed since the last successful reaffirmation event." `VitalityState::Dormant` says "reaffirmation suggested." These are the only two references.

**There is no reaffirmation API anywhere in the codebase.** No method to record an exchange event. No storage for last-exchange time. No mechanism to reset `t` to 0.

---

## 3. Gap Table: What Trial 1 as Specified Requires

| Required component | Status | Source evidence |
|---|---|---|
| `VitalityFunction::compute()` — pure function | IMPLEMENTED | `function.rs`, 6 tests in `state_machine.rs` |
| `VitalityState::from_score()` — band mapping | IMPLEMENTED | `state.rs`, `state_machine.rs` |
| `VitalityState::is_open()` — threshold gate | IMPLEMENTED | `state.rs`, `state_machine.rs` |
| `VitalityInsufficient` enforcement in `open_and_send_core` | IMPLEMENTED | `flash.rs:166-168` |
| Vitality oracle: `retrieve_state` computes score from time | **MISSING — Phase 9 deferred** | `flash.rs:71`: `Active // Phase 9` |
| Last-exchange timestamp storage | **MISSING** | Not in ledger, WarmCache, or any module |
| Reaffirmation recording API | **MISSING** | No method exists anywhere |
| Deterministic time seam | **N/A (pure function takes `t`)** | `function.rs` takes `t: f64` directly |

---

## 4. What IS Provable Now Without Policy Decisions

A narrow sub-trial — **Trial 1a — Enforcement Gate** — is executable today by directly constructing `RecipientState` with specific vitality states:

```rust
// Directly construct a non-open state — does not require oracle wiring
let state = RecipientState {
    ops_pub:             actors.ops_pub_b,
    vitality:            VitalityState::Suspended,
    routing_hints:       vec![],
    handshake_ephemeral: Some(...),
};
let result = FlashSession::open_and_send(state, payload, &cache, &engine).await;
assert!(matches!(result, Err(TransportError::VitalityInsufficient(VitalityState::Suspended))));
```

This proves the enforcement gate is real. It does NOT prove that inactivity causes the state to drop — because the oracle is missing.

**Trial 1a would verify:**
- Suspended state blocks sends with `VitalityInsufficient(Suspended)`
- Severed state blocks sends with `VitalityInsufficient(Severed)`  
- Burned state blocks sends with `VitalityInsufficient(Burned)`
- Dormant state allows sends (score ≥ 0.20, is_open = true)
- Warm state allows sends
- Active state allows sends (current default)
- All six `VitalityState` variants exercise the threshold boundary

Trial 1a requires zero new implementation. It IS NOT the same as the full inactivity/reaffirmation Trial 1.

---

## 5. Policy Decisions Required Before Full Trial 1

The following three decisions are not implementation questions — they define what the protocol does. They cannot be invented in the simulator; they must be specified.

### Decision 1: Where does `t` come from in production?

`VitalityFunction::compute(t, i, r, p)` needs `t = seconds_since_last_reaffirmation`. This value must be persisted somewhere. Options:

**A)** Store last-exchange Unix timestamp in `SubstrateLedger`, update on each successful send.  
**B)** Store it in a separate vitality store (a new module) accessed by `retrieve_state`.  
**C)** Pass it as a parameter to `retrieve_state`, making callers responsible for supplying it.  
**D)** A vitality oracle is a separate async RPC service (Phase 9 vision).

None of these is implemented. The choice determines where the time seam lives and what files change.

### Decision 2: What constitutes a reaffirmation event?

The doc says "seconds since last reaffirmation." But what counts?

**Option A**: Any successful `open_and_send` call resets `t`.  
**Option B**: Any successful `corridor::receive` call on the recipient side resets `t`.  
**Option C**: Reaffirmation is a bilateral explicit protocol step (both parties must confirm).  
**Option D**: Only explicit `reaffirm()` API calls count; passive traffic does not.

These have different security and liveness implications. Without a decision, no test can validate "reaffirmation restores vitality" because there is nothing to call.

### Decision 3: What are `i` (interaction entropy) and `r` (reciprocal participation) in a simulator?

`compute(t, i, r, p)` uses all four parameters. Current tests use `i = 1.0, r = 1.0` (perfect conditions) or `i = 0.0, r = 0.0` (zero conditions). In a real corridor:
- `i` = diversity and richness of recent exchanges — requires exchange history
- `r` = symmetry of engagement — requires bilateral exchange tracking

For a simulator trial, these could be fixed at `1.0, 1.0` (simplification for Trial 1). This would be an explicit simulation assumption documented in the trial, not a production policy change.

---

## 6. Deterministic Time Seam Recommendation (for when Decision 1 is made)

Since `VitalityFunction::compute()` is already a pure function taking `t: f64`, **no clock injection is needed in the function itself**. The seam needed is in how `t` reaches `compute()`.

**Recommended approach**: Add a `last_reaffirmed_at: u64` field to `SubstrateLedger` (or a new vitality store) and a `now: u64` parameter at the oracle boundary. The test supplies `now` directly rather than calling `SystemTime::now()`.

Conceptually:
```rust
// In StateProvider trait (change needed):
fn vitality_score(&self, ops_pub: &[u8; 32], now: u64) -> VitalityState;

// In retrieve_state (change needed):
let now = // TEST: injected timestamp | PROD: SystemTime::now()
vitality: provider.vitality_score(recipient_ops_pub, now),
```

This follows the pattern already established: `get_handshake_ephemeral(ops_pub, now: u64)` already takes `now` as a parameter (see `state.rs:11-15`). The same pattern applies to vitality.

**Scope**: This pattern is minimal — one additional method on `StateProvider`, one timestamp field in the store, one parameter propagation site. It does not alter vitality semantics, thresholds, or transcript binding.

---

## 7. Verdict

**B — TRIAL_1_REQUIRES_VITALITY_POLICY_DECISION**

Full Trial 1 — Inactivity and Reaffirmation — requires three decisions (§5) that are not implementation questions. The vitality oracle, last-exchange timestamp storage, and reaffirmation API are all absent. These are policy boundaries that must be specified before code can prove the correct behavior.

The enforcement gate (that non-open states block sends) IS proven by direct `RecipientState` construction and IS executable without new code — this is Trial 1a scope, not full Trial 1.

The two `SystemTime::now()` calls in `flash.rs` are for ephemeral key expiry only. There is no wall-clock call related to vitality anywhere in the current codebase. Vitality time injection is a new seam, not a refactor of an existing one.

### What to do next

**Option A — Proceed with Trial 1a (enforcement only)**:  
Implement tests that directly construct `RecipientState` with each of the six `VitalityState` variants and verify enforcement. Zero new implementation needed. Claim limited to: enforcement gate correctly blocks non-open states.

**Option B — Make the three policy decisions, then proceed to full Trial 1**:  
Requires explicit specification of oracle architecture, reaffirmation semantics, and simulation assumptions for `i` and `r`. After decisions are documented, return to this plan for the full implementation path.

Do not choose Option B by inventing defaults. The decisions must be stated explicitly before any vitality oracle code is written.

---

## 8. Files That Would Change (Full Trial 1 Implementation — after decisions)

| File | Type | Change |
|---|---|---|
| `core/transport/src/state.rs` | MODIFY | Add `vitality_score(ops_pub, now: u64) -> VitalityState` to `StateProvider` |
| `ledger/substrate/src/lib.rs` | MODIFY | Add `record_reaffirmation(ops_pub, timestamp)` and `last_reaffirmed_at(ops_pub)` |
| `core/transport/src/flash.rs` | MODIFY | Wire oracle into `retrieve_state` using `StateProvider::vitality_score()` |
| `test/tests/trial1.rs` | NEW | 8+ integration tests (enforcement + time-advance + reaffirmation) |
| `docs/architecture/CORRIDOR_SCENARIO_HARNESS_PLAN.md` | UPDATE | §5 Trial 1 steps updated with actual executable behavior |

**Files that must NOT change during Trial 1:**
- `core/vitality/src/function.rs` — pure function, already correct
- `core/vitality/src/state.rs` — thresholds and enum values, permanent wire contract
- `core/transport/src/corridor.rs` — Trial 0 primitive, frozen
- `ARCHITECTURE_REALITY_GATE.md` — human vocabulary gate
- Any provider pool, TOLS κ, or dynamical criticality code

---

## 9. Full-Suite Baseline at Planning Time

```
Pre-Phase-41 tracked integration tests: 399
Phase 41 closure adds:                   +9 (corridor.rs, 9 tests)
Current tracked integration baseline:   408
Current full workspace baseline:         425 passing, 0 failing, 0 ignored
Two consecutive clean verification runs confirmed.
```

This baseline must be re-verified before any Trial 1 implementation begins.
