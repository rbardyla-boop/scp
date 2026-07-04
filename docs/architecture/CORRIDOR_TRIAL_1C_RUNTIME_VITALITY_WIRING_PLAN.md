# Trial 1c — Runtime Vitality Oracle Wiring Plan

**Status:** IMPLEMENTATION AUTHORIZED — A verdict issued  
**Date:** 2026-05-28  
**Predecessor:** `TRIAL_1B_CLOSURE_RECORD.md` (A — TRIAL_1B_CLOSED_AND_BASELINED)  
**Verdict:** `A — TRIAL_1C_DETERMINISTIC_SIMULATOR_SEND_PATH_SPECIFIED`

---

## 0. Why B, Not A

Two blockers prevent authorization. Both are narrow and correctable without
discarding the accepted design decisions in §1.

### Blocker 1 — Mixed time domains inside a single simulated send

The plan previously accepted a two-clock table:

| Clock site | Source | Deterministic? |
|-----------|--------|---------------|
| `retrieve_state_sim()` expiry check | `ctx.now` | Yes |
| `retrieve_state_sim()` vitality input | `ctx.now` | Yes |
| `open_and_send_core()` defense-in-depth expiry | `SystemTime::now()` | **No** |

This is **not acceptable**. Trial 1c must simulate through at least:

```
T0 + 4_171_664 seconds   ≈ 48.3 days
```

(the Suspended transition boundary). Handshake ephemerals expire after 3,600 seconds.
A simulated send at T0 + 48 days cannot succeed under the production wall-clock expiry
check — the registered ephemeral is long expired by real time.

The deeper problem: one simulated send operation would validate its state against two
different notions of "now". A test could pass or fail depending on when it happens to
run. That violates the deterministic simulator boundary proven in Trial 1b.

**Required correction:** Introduce a single `now: u64` parameter through the send core
so that all time-sensitive checks in one simulated operation share one evaluation clock.
See §8.3.

### Blocker 2 — `retrieve_state_sim()` alone does not prove send-path wiring

Implementing only `retrieve_state_sim()` proves that a simulator retrieval method
can compute vitality. It does not prove that the simulator send operation uses that
method. A caller could still do:

```
retrieve_state()       // returns hardcoded Active
open_and_send(...)
```

and bypass the oracle entirely. The claim:

> In the SCP simulator runtime path, ordinary corridor send creation automatically
> consults bilateral vitality evidence.

requires a **designated simulator send path** that cannot accidentally bypass vitality
lookup. See §8.4.

---

## 1. Accepted Architectural Decisions

These decisions are preserved from the original plan review and must not be rolled back:

1. Trial 1c is simulator-runtime wiring only. Production-network readiness is not
   claimed.
2. Vitality is addressed by a caller-supplied canonical `consent_hash: [u8; 32]`.
3. The scenario layer derives that hash from an actual bilateral tunnel consent via the
   existing ledger path. Transport does not recompute identity relationships.
4. `VitalityEvidenceStore` is long-lived at scenario/runtime level and is borrowed by
   the send path as `&VitalityEvidenceStore`.
5. `StateProvider` is not extended with bilateral vitality semantics.
6. `i`, `r`, and `p` are explicit simulator scenario controls because no executable
   runtime sources currently exist.
7. Production `retrieve_state()` remains untouched and continues to carry the Phase 9
   oracle deferral comment.
8. `corridor::receive()` remains unchanged.

---

## 2. Objective

Replace the dormant hardcoded `VitalityState::Active` in `FlashSession::retrieve_state()`
with a real bilateral consultation inside a clearly scoped simulator entry point. The
permitted future claim, once implementation is authorized and proven:

> In the SCP simulator runtime path, ordinary corridor send creation automatically
> consults bilateral vitality evidence and enforces the resulting computed vitality state.

This is simulator-runtime wiring only.

---

## 3. Source Files Inspected

| File | Role |
|------|------|
| `core/transport/src/flash.rs` | `FlashSession`, `retrieve_state()`, `open_and_send_core()`, `RecipientState` |
| `core/transport/src/state.rs` | `StateProvider` trait, `StubStateProvider`, `SubstrateLedger` impl |
| `core/transport/src/corridor.rs` | `receive()`, `BurstEnvelope` (receive path — not to be changed) |
| `core/transport/src/harness.rs` | Existing simulator-only harness code (pattern precedent) |
| `core/transport/src/session.rs` | `SessionKey`, `RouteId`, `FreshnessNonce` |
| `core/transport/Cargo.toml` | Confirms `scp-vitality` already a dependency |
| `core/vitality/src/evidence.rs` | `VitalityEvidenceStore::compute_state()` |
| `core/vitality/src/function.rs` | `VitalityParams`, `compute()`, `i`/`r`/`p` definitions |
| `core/vitality/src/state.rs` | `VitalityState`, `from_score()`, `is_open()` |
| `core/vitality/src/lib.rs` | Re-exports |
| `core/cryptography/src/domains.rs` | `DomainLabel::Tunnel`, context strings |
| `scp-wire-format/src/signing.rs` | `tunnel_consent_input()` (canonical bilateral sort) |
| `ledger/substrate/src/lib.rs` | `tunnel_consent_hash()` (authoritative), `TunnelConsent` |
| `docs/architecture/VITALITY_ORACLE_POLICY_DECISION.md` | Decision 0 (bilateral ownership accepted) |
| `test/tests/trial1b.rs` | Current test entry point — manual `RecipientState` construction |

---

## 4. Audit 1 — Current Call Graph

### 4.1 The hardcoded `Active` location

**File:** `core/transport/src/flash.rs:71`

```
FlashSession::retrieve_state(provider, recipient_ops_pub)
  ├─ provider.is_revoked(recipient_ops_pub)    → reject if revoked
  ├─ SystemTime::now()                          → used for ephemeral validation only
  └─ Ok(RecipientState {
         ops_pub: *recipient_ops_pub,
         vitality: VitalityState::Active,  ← HARDCODE ("Phase 9: vitality oracle")
         routing_hints: vec![],
         handshake_ephemeral: provider.get_handshake_ephemeral(recipient_ops_pub, now),
     })
```

### 4.2 Downstream enforcement path (already proven by Trial 1a)

```
FlashSession::open_and_send(state, payload, cache, engine)
  └─ open_and_send_core(state, payload, cache, engine)
       ├─ if !state.vitality.is_open()          ← Gate fires here (flash.rs:166)
       │    return Err(VitalityInsufficient)
       └─ ... key derivation, encrypt, transmit
```

### 4.3 Call sites of `retrieve_state()`

`retrieve_state()` has no production callers today outside tests. All Trial 1b tests
bypass it and construct `RecipientState` directly via `make_v2_recipient()` /
`make_bare_recipient()`. The CLI (`cli/endpoint/src/main.rs`) would be the production
call site when Phase 9 arrives, but that is out of scope for Trial 1c.

### 4.4 Additional hardcoded `Active` in `harness.rs`

`harness::send_harness_direct()` also hardcodes `VitalityState::Active` at line 188.
This is an existing dev-harness-only artifact. Trial 1c does not touch it — it is
outside the ordinary `FlashSession::retrieve_state()` path.

---

## 5. Audit 2 — Bilateral Identity Availability

### Questions and answers

**Q1: Does `FlashSession` already know the sender's operations public key?**
No. `retrieve_state(provider, recipient_ops_pub)` takes only the recipient key.
`FlashSession` holds no sender identity.

**Q2: Can it safely receive the sender key at construction time?**
`FlashSession` is constructed only at the end of `open_and_send_core()`. Threading the
sender key there is possible but widens `FlashSession`'s surface unnecessarily —
`FlashSession` is a transport artifact, not an identity artifact.

**Q3: Is there an existing tunnel-consent handle or hash?**
Yes. `tunnel_consent_hash(a, b)` in `ledger/substrate/src/lib.rs:322` produces a
canonical 32-byte key from the two ops pubs, sorted lexicographically. This is
already the key used by `VitalityEvidenceStore`. The hash is the correct identifier:
committing the pre-computed hash into the evaluation context means the caller
assembles bilateral identity once and passes a fixed-size token.

**Q4: Would threading the bilateral hash directly preserve the accepted relationship ownership model?**
Yes. Decision 0 in `VITALITY_ORACLE_POLICY_DECISION.md` ruled that vitality is
scoped to the bilateral consent hash, not to either participant's `ops_pub` alone.
The caller pre-computes `tunnel_consent_hash(sender_ops_pub, recipient_ops_pub)` and
passes the result. Transport does not import or call `tunnel_consent_hash()` — it
receives the already-computed key.

**Q5: Does any option improperly make transport responsible for ledger authorization?**
Threading the hash as a declared context parameter does not. Transport receives a
`[u8; 32]` token and looks it up in the evidence store without any ledger reference.
No new ledger dependency enters transport.

**Conclusion:** Pass `consent_hash: [u8; 32]` as part of a `SimVitalityEvaluationContext`
into a new `retrieve_state_sim()` function. Do not pass raw ops pubs to transport.

---

## 6. Audit 3 — Oracle / Store Ownership and Lifetime

### Constraints

`VitalityEvidenceStore` must survive flash-session rotation. `FlashSession` is
disposable (dissolved after a burst). The store cannot live inside `FlashSession`.

### Candidate locations

| Location | Assessment |
|----------|------------|
| `FlashSession` field | **Rejected**: FlashSession is disposable |
| `RecipientState` field | **Rejected**: RecipientState is also per-send |
| `StateProvider` extension | **Rejected**: StateProvider concerns ledger/key retrieval, not bilateral evidence |
| New `VitalityProvider` trait | **Viable** but adds unnecessary indirection for simulator scope |
| Scenario harness / test context | **Accepted**: long-lived at test/scenario level, passed by reference |
| New `core/transport/src/sim.rs` | **Accepted**: parallel to `harness.rs`; store passed by `&` borrow |

### Accepted ownership model

The `VitalityEvidenceStore` is owned by the **test scenario**. It is passed as
`&VitalityEvidenceStore` to `retrieve_state_sim()` for a read-only query.
`retrieve_state_sim()` does not own or mutate the store's lifetime.

### Why not extend `StateProvider`?

`StateProvider` is a ledger/key interface (`is_revoked`, `get_handshake_ephemeral`).
Adding `compute_vitality` to it would cross concerns: the ledger knows about key
registration and revocation; `VitalityEvidenceStore` knows about reaffirmation
timestamps. These are independent subsystems. A separate query seam is cleaner and
matches the structure already used in Trial 1b.

A `VitalityProvider` trait is not needed for Trial 1c. The concrete
`VitalityEvidenceStore` is sufficient for the simulator scope.

---

## 7. Audit 4 — Deterministic Time Boundary (BLOCKER 1 SCOPE)

### Current state

`retrieve_state()` calls `SystemTime::now()` internally (line 65) for handshake
ephemeral expiry validation. `open_and_send_core()` also calls `SystemTime::now()`
(line 181) as a defense-in-depth re-check.

### Why the previous "two clocks accepted" ruling is wrong

Trial 1c must simulate through at least `T0 + 4_171_664 seconds` (≈ 48.3 days).
Handshake ephemerals are valid for only 3,600 seconds. In any test that advances
simulated time past the Suspended threshold:

- `retrieve_state_sim()` will validate the ephemeral as current (using `ctx.now`,
  set to a value far past the ephemeral's wall-clock registration)
- `open_and_send_core()` will check the same ephemeral using `SystemTime::now()`,
  which reflects actual execution time — and the ephemeral was registered during
  test setup, seconds ago

The second check would pass only because the ephemeral was registered moments before
in real execution time, not because the simulated time model is correct. That is not
a deterministic guarantee; it is accidental success depending on test execution speed.

A test that happens to run slowly (CI queue, loaded machine) could publish the
ephemeral, sleep or yield, and then fail the wall-clock check. More subtly, a test
that publishes an ephemeral with `expires_at = u64::MAX` to avoid this would be
lying about expiry semantics, not actually resolving the problem.

**Invariant:** A simulated send must not evaluate one part of its authorization state
against `ctx.now` and another part against `SystemTime::now()`.

### Required correction

See §8.3 for the required seam design. The short form:

```rust
open_and_send_core_at(..., now: u64)    // internal — single time parameter

open_and_send_core(...)                  // production wrapper — supplies SystemTime::now()
open_and_send_sim(...)                   // simulator wrapper — supplies ctx.now
```

The production function signature is unchanged; no production behavior changes.

---

## 8. Audit 5 — Runtime Sources for `i`, `r`, `p`

### Definitions (from `core/vitality/src/function.rs`)

- `i`: interaction entropy — diversity and richness of recent exchanges, in [0.0, 1.0]
- `r`: reciprocal participation quality — symmetry of engagement, in [0.0, 1.0]
- `p`: protocol perturbation factor injected by the relay layer, in [0.0, 1.0]

### Audit table

| Input | Formula meaning | Existing executable source | Safe Trial 1c source |
|-------|----------------|---------------------------|---------------------|
| `i` | Interaction entropy diversity | **None** | Declared constant in `SimVitalityEvaluationContext` |
| `r` | Reciprocal participation symmetry | **None** | Declared constant in `SimVitalityEvaluationContext` |
| `p` | Relay perturbation pressure | `PerturbationEngine` exists but exposes no `p ∈ [0,1]` getter | Declared constant in `SimVitalityEvaluationContext` |

All three inputs have zero existing runtime sources. In Trial 1c they are **explicit
declared controls** supplied by the test scenario through `SimVitalityEvaluationContext`.
They must never be silently defaulted inside transport code.

### Input-range behavior

The plan must state one of the following and implement accordingly:

**Option A — Reject at context construction:**  
`SimVitalityEvaluationContext::new()` returns `Err` if any of `i`, `r`, `p` falls
outside `[0.0, 1.0]`.

**Option B — Delegate to existing vitality clamping:**  
Values outside `[0.0, 1.0]` are passed through to `VitalityFunction::compute()`,
which clamps them silently. The context constructor does not validate.

Either is acceptable if consistent with existing `VitalityParams` semantics. The
plan must record the choice explicitly. Do not imply validation while relying on
clamping, or vice versa.

---

## 9. Proposed Architecture

### 9.1 New type: `SimVitalityEvaluationContext`

**Location:** `core/vitality/src/sim_context.rs` (new file)  
**Re-exported via:** `core/vitality/src/lib.rs`

```rust
/// Explicit vitality evaluation context for simulator runtime tests.
///
/// SIMULATOR ONLY. All three formula inputs (i, r, p) are declared scenario
/// controls, not production measurements. Do not substitute real network
/// interaction data through this type.
pub struct SimVitalityEvaluationContext {
    /// Pre-computed tunnel consent hash — `tunnel_consent_hash(sender, recipient)`.
    /// Caller is responsible for bilateral identity assembly. Must be derived
    /// from a real bilateral tunnel consent registered in the ledger; must not
    /// be an arbitrary [0u8; 32] or fabricated value.
    pub consent_hash: [u8; 32],
    /// Evaluation timestamp (Unix seconds). Deterministic — not SystemTime::now().
    /// Governs both ephemeral expiry and vitality computation.
    pub now: u64,
    /// Declared interaction entropy control [0.0, 1.0].
    pub i: f64,
    /// Declared reciprocal participation control [0.0, 1.0].
    pub r: f64,
    /// Declared perturbation pressure control [0.0, 1.0].
    pub p: f64,
}
```

### 9.2 New method: `FlashSession::retrieve_state_sim()`

**Location:** `core/transport/src/flash.rs` — added as a new `impl FlashSession` method

```rust
/// Simulator-runtime retrieve_state with explicit vitality oracle.
///
/// Replaces the hardcoded VitalityState::Active with a computed value from the
/// provided VitalityEvidenceStore and SimVitalityEvaluationContext.
///
/// Differs from retrieve_state() in three ways:
///   1. Uses ctx.now for handshake ephemeral validation (deterministic).
///   2. Consults vitality_store instead of hardcoding Active.
///   3. Requires caller-supplied bilateral consent hash — transport does not
///      call tunnel_consent_hash().
///
/// SIMULATOR ONLY: ctx.i, ctx.r, ctx.p are declared scenario controls.
pub async fn retrieve_state_sim(
    provider: &impl StateProvider,
    recipient_ops_pub: &[u8; 32],
    vitality_store: &VitalityEvidenceStore,
    ctx: &SimVitalityEvaluationContext,
) -> Result<RecipientState, TransportError>
```

**Body logic:**
1. `provider.is_revoked(recipient_ops_pub)` → `Err(RecipientRevoked)` if true
2. `handshake_ephemeral = provider.get_handshake_ephemeral(recipient_ops_pub, ctx.now)`
3. `vitality = vitality_store.compute_state(ctx.consent_hash, ctx.now, ctx.i, ctx.r, ctx.p)`
4. Return `Ok(RecipientState { ops_pub, vitality, routing_hints: vec![], handshake_ephemeral })`

The original `retrieve_state()` is **unchanged**. Its `VitalityState::Active` hardcode
and `// Phase 9: vitality oracle` comment remain intact.

### 9.3 Required seam: `open_and_send_core_at()` (Blocker 1 correction)

**Location:** `core/transport/src/flash.rs`

Extract a private internal function that accepts an explicit `now: u64`:

```rust
// Internal implementation — one evaluation clock governs all time checks.
async fn open_and_send_core_at(
    state: RecipientState,
    payload: &[u8],
    cache: &SessionCache,
    engine: &CryptoEngine,
    now: u64,
) -> Result<BurstEnvelope, TransportError>
```

Provide two callers:

```rust
// Production path — unchanged external signature.
pub async fn open_and_send_core(
    state: RecipientState,
    payload: &[u8],
    cache: &SessionCache,
    engine: &CryptoEngine,
) -> Result<BurstEnvelope, TransportError> {
    let now = unix_now(); // SystemTime::now() → u64
    open_and_send_core_at(state, payload, cache, engine, now).await
}

// Simulator path — caller supplies deterministic time.
pub async fn open_and_send_core_sim(
    state: RecipientState,
    payload: &[u8],
    cache: &SessionCache,
    engine: &CryptoEngine,
    now: u64,
) -> Result<BurstEnvelope, TransportError> {
    open_and_send_core_at(state, payload, cache, engine, now).await
}
```

This is a legitimate, narrow refactor. No production behavior changes.

### 9.4 Required: designated simulator send path (Blocker 2 correction)

Trial 1c must introduce `open_and_send_sim()` as the single official simulator send
workflow. This path cannot accidentally bypass vitality retrieval because it accepts
the vitality store and context as required parameters:

```rust
/// Designated SCP simulator send operation.
///
/// Automatically consults bilateral vitality evidence before creating an
/// encrypted burst. Cannot be called without supplying a VitalityEvidenceStore
/// and SimVitalityEvaluationContext.
///
/// Internally:
///   1. Retrieves ephemeral/session state using ctx.now.
///   2. Obtains vitality from vitality_store using ctx.consent_hash.
///   3. Builds RecipientState.
///   4. Invokes open_and_send_core_at() using the same ctx.now.
///
/// SIMULATOR ONLY. Does not replace open_and_send() for production use.
pub async fn open_and_send_sim(
    provider: &impl StateProvider,
    vitality_store: &VitalityEvidenceStore,
    ctx: &SimVitalityEvaluationContext,
    recipient_ops_pub: &[u8; 32],
    payload: &[u8],
    cache: &SessionCache,
    engine: &CryptoEngine,
) -> Result<BurstEnvelope, TransportError>
```

All Trial 1c acceptance tests proving the wiring claim must enter through
`open_and_send_sim()`. Direct calls to `open_and_send()` + manual `RecipientState`
construction do not satisfy the wiring claim.

### 9.5 New dependency

`scp-vitality` is **already** in `core/transport/Cargo.toml`. No workspace dependency
changes are needed. The transport crate imports
`use scp_vitality::{VitalityEvidenceStore, SimVitalityEvaluationContext}`.

---

## 10. Relationship Authenticity Guardrail for Tests

Do not populate `consent_hash` with arbitrary `[u8; 32]` values in acceptance tests.

Each Trial 1c relationship test must:

1. Create or register a real bilateral tunnel consent through the existing ledger path.
2. Derive the canonical `tunnel_consent_hash(A, B)` from that consent.
3. Initialize evidence for that specific hash in `VitalityEvidenceStore`.
4. Pass that hash into `SimVitalityEvaluationContext`.

This preserves the policy statement that vitality belongs to an authorized bilateral
relationship, not to an arbitrary byte string. Tests T1–T8 are affected; T7 is the
one test that intentionally leaves evidence uninitialized and must still derive its
hash from a real consent (then simply skip evidence initialization).

---

## 11. Trial 1c Test List

**File:** `test/tests/trial1c.rs` (new file)

All wiring-claim tests must enter through `open_and_send_sim()`. No wiring-claim test
may construct `RecipientState` directly; vitality must flow through the designated
simulator send path. `consent_hash` in each test must be derived from a real bilateral
tunnel consent (see §10).

| # | Name (proposed) | What it proves |
|---|-----------------|----------------|
| T1 | `runtime_active_relationship_permits_send` | Initialized, freshly reaffirmed bilateral: `open_and_send_sim()` → Active → succeeds |
| T2 | `runtime_suspended_relationship_blocks_send` | Relationship past Suspended threshold: `open_and_send_sim()` → Suspended → `VitalityInsufficient` |
| T3 | `runtime_reaffirmation_restores_send` | Suspended → `record_reaffirmation()` → `open_and_send_sim()` → Active → succeeds again |
| T4 | `runtime_missing_evidence_fails_closed` | No initialized evidence: `open_and_send_sim()` → Suspended → `VitalityInsufficient` |
| T5 | `runtime_relationship_isolation_ab_vs_ac` | AB suspended, AC active; `open_and_send_sim()` with AB context rejects; with AC context permits |
| T6 | `runtime_send_does_not_refresh_evidence` | After a permitted send, re-evaluate at `ctx.now + 578_389s` → Warm, not Active; send did not refresh timestamp |
| T7 | `retrieve_state_sim_bypasses_hardcoded_active` | Uninitialized evidence + direct `retrieve_state()` returns Active; `retrieve_state_sim()` with same provider returns Suspended — proves sim path consults evidence |
| T8 | `corridor_receive_unaffected` | Receive-path decryption of a prior Active-sent burst succeeds after relationship is Suspended — receive is not vitality-gated |
| T9 | `scenario_controls_i_r_p_are_explicit` | With `i = 0.3, r = 0.5, p = 0.0`: verify computed state boundary shifts match the formula; declared controls propagate correctly through `open_and_send_sim()` |

---

## 12. Required Implementation File List (when authorized)

| File | Change | Type |
|------|--------|------|
| `core/vitality/src/sim_context.rs` | New: `SimVitalityEvaluationContext` struct with input-range behavior per §8 | New |
| `core/vitality/src/lib.rs` | Add `pub mod sim_context; pub use sim_context::SimVitalityEvaluationContext;` | Modify (2 lines) |
| `core/transport/src/flash.rs` | Add `retrieve_state_sim()`, `open_and_send_core_at()`, `open_and_send_core_sim()`, `open_and_send_sim()` | Modify |
| `test/tests/trial1c.rs` | New: 9 acceptance tests via `open_and_send_sim()` | New |
| `docs/architecture/CORRIDOR_TRIAL_1C_RUNTIME_VITALITY_WIRING_PLAN.md` | This document — updated with amended design | Updated |

**Files not touched:**
- `core/transport/src/state.rs` — `StateProvider` unchanged
- `core/transport/src/corridor.rs` — receive path unchanged
- `core/transport/src/harness.rs` — existing dev harness unchanged
- `core/vitality/src/evidence.rs` — `VitalityEvidenceStore` unchanged
- All ledger, relay, provider, identity crates — unchanged

---

## 13. What Trial 1c Does NOT Claim

- `retrieve_state()` (the original function) is wired — it is not
- `i`, `r`, `p` are measured at runtime from real interaction data
- `corridor::receive()` is vitality-gated
- The relay mailbox or routing layer consults vitality
- Production reaffirmation protocol exists
- LAN, desktop, or hardware readiness

---

## 14. Input-Range Behavior Decision — Option A Accepted

**Decision: Option A — reject invalid `i`, `r`, `p` at construction time.**

`SimVitalityEvaluationContext::new()` returns `Err(SimVitalityContextError)` if any
control value is:
- less than `0.0`
- greater than `1.0`
- `NaN`
- positive or negative infinity

Valid values are finite and within the inclusive range `[0.0, 1.0]`.

`VitalityFunction::compute()` retains its existing clamping behavior as
defense-in-depth for the general formula surface. The simulator context validates
declared scenario inputs before they reach the formula. These are independent layers
and neither modifies the other.

**Why Option A:** `SimVitalityEvaluationContext` is a declared scenario input, not a
raw observation pipe. Invalid scenario controls must fail visibly rather than being
silently normalized. This preserves the invariant:
> Simulator scenario controls are validated. The underlying vitality formula is not
> redesigned. Production vitality-input policy remains undefined and unclaimed.

---

## 15. Verdict

```
A — TRIAL_1C_DETERMINISTIC_SIMULATOR_SEND_PATH_SPECIFIED
```

| Audit | Finding | Status |
|-------|---------|--------|
| 1. Call graph | Hardcode at `flash.rs:71`; gate at `flash.rs:166`; no production callers | ✅ Resolved |
| 2. Bilateral identity | Pre-computed `consent_hash` via context; transport does not call `tunnel_consent_hash()` | ✅ Resolved |
| 3. Store ownership | Scenario-level; passed as `&VitalityEvidenceStore` borrow; no lifetime contamination | ✅ Resolved |
| 4. Deterministic time | `open_and_send_core_at(now)` seam unifies all time checks under one clock | ✅ Resolved |
| 5. i/r/p sources | All three are named declared controls; Option A validation at construction | ✅ Resolved |
| 6. Send-path wiring | `open_and_send_sim()` designated path requires vitality store and context | ✅ Resolved |

Implementation authorized. Proof verdict after passing tests:
`A — TRIAL_1C_SIMULATOR_RUNTIME_VITALITY_ENFORCEMENT_PROVEN`
