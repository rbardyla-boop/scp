# Trial 1c — Runtime Vitality Oracle Wiring Plan

**Status:** PLAN ONLY — no Rust implementation authorized yet  
**Date:** 2026-05-28  
**Predecessor:** `TRIAL_1B_CLOSURE_RECORD.md` (A — TRIAL_1B_CLOSED_AND_BASELINED)  
**Verdict:** `A — TRIAL_1C_SIMULATOR_RUNTIME_WIRING_SPECIFIED`

---

## 1. Objective

Replace the dormant hardcoded `VitalityState::Active` in `FlashSession::retrieve_state()` with a
real bilateral consultation inside a clearly scoped simulator entry point. The permitted future
claim, if implementation is authorized and proven:

> In the SCP simulator runtime path, ordinary corridor send creation automatically consults
> bilateral vitality evidence and enforces the resulting computed vitality state.

This is simulator-runtime wiring only. Production-network readiness is not claimed.

---

## 2. Source Files Inspected

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

## 3. Audit 1 — Current Call Graph

### 3.1 The hardcoded `Active` location

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

### 3.2 Downstream enforcement path (already proven by Trial 1a)

```
FlashSession::open_and_send(state, payload, cache, engine)
  └─ open_and_send_core(state, payload, cache, engine)
       ├─ if !state.vitality.is_open()          ← Gate fires here (flash.rs:166)
       │    return Err(VitalityInsufficient)
       └─ ... key derivation, encrypt, transmit
```

### 3.3 Call sites of `retrieve_state()`

`retrieve_state()` has no production callers today outside tests. All Trial 1b tests
bypass it and construct `RecipientState` directly via `make_v2_recipient()` / `make_bare_recipient()`.
The CLI (`cli/endpoint/src/main.rs`) would be the production call site when Phase 9 arrives, but
that is out of scope for Trial 1c.

### 3.4 Additional hardcoded `Active` in `harness.rs`

`harness::send_harness_direct()` also hardcodes `VitalityState::Active` at line 188.
This is an existing dev-harness-only artifact. Trial 1c does not touch it — it is
outside the ordinary `FlashSession::retrieve_state()` path.

---

## 4. Audit 2 — Bilateral Identity Availability

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

## 5. Audit 3 — Oracle / Store Ownership and Lifetime

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

The `VitalityEvidenceStore` is owned by the **test scenario**. It is passed as `&VitalityEvidenceStore`
to `retrieve_state_sim()` for a read-only query. `retrieve_state_sim()` does not own or
mutate the store's lifetime.

### Why not extend `StateProvider`?

`StateProvider` is a ledger/key interface (`is_revoked`, `get_handshake_ephemeral`).
Adding `compute_vitality` to it would cross concerns: the ledger knows about key registration
and revocation; `VitalityEvidenceStore` knows about reaffirmation timestamps. These are
independent subsystems. A separate query seam is cleaner and matches the structure
already used in Trial 1b.

A `VitalityProvider` trait is not needed for Trial 1c. The concrete `VitalityEvidenceStore`
is sufficient for the simulator scope.

---

## 6. Audit 4 — Deterministic Time Boundary

### Current state

`retrieve_state()` calls `SystemTime::now()` internally (line 65) for handshake ephemeral
expiry validation. `open_and_send_core()` also calls `SystemTime::now()` (line 181) as a
defense-in-depth re-check.

### Trial 1c seam

`retrieve_state_sim()` uses `ctx.now` (a `u64` Unix seconds value declared in
`SimVitalityEvaluationContext`) for both:
1. Handshake ephemeral expiry check (replacing the `SystemTime::now()` call)
2. Input to `VitalityEvidenceStore::compute_state()`

This makes the state-retrieval path fully deterministic. The defense-in-depth expiry
check in `open_and_send_core()` still uses `SystemTime::now()` — this is acceptable
because tests set `expires_at = SystemTime::now() + 3600s`, so the check always passes
within any reasonable test window. No wall-clock sleeps are introduced.

**Two clocks accepted:**

| Clock site | Source | Deterministic? |
|-----------|--------|---------------|
| `retrieve_state_sim()` expiry check | `ctx.now` | Yes |
| `retrieve_state_sim()` vitality input | `ctx.now` | Yes |
| `open_and_send_core()` defense-in-depth expiry | `SystemTime::now()` | No (wall-clock) |

The defense-in-depth clock does not affect test determinism: it merely enforces that
the ephemeral hasn't expired since `retrieve_state_sim()` retrieved it, which is always
true within a test run.

---

## 7. Audit 5 — Runtime Sources for `i`, `r`, `p`

### Definitions (from `core/vitality/src/function.rs`)

- `i`: interaction entropy — diversity and richness of recent exchanges, in [0.0, 1.0]
- `r`: reciprocal participation quality — symmetry of engagement, in [0.0, 1.0]
- `p`: protocol perturbation factor injected by the relay layer, in [0.0, 1.0]

### Audit table

| Input | Formula meaning | Existing executable source | Existing storage | Safe Trial 1c source | Future production gap |
|-------|----------------|---------------------------|-----------------|---------------------|-----------------------|
| `i` | Interaction entropy diversity | **None** | **None** | Declared constant in `SimVitalityEvaluationContext` | Requires an interaction tracking subsystem (sends/receives per window, diversity metric) — does not yet exist |
| `r` | Reciprocal participation symmetry | **None** | **None** | Declared constant in `SimVitalityEvaluationContext` | Requires bidirectional engagement measurement — does not yet exist |
| `p` | Relay perturbation pressure | `PerturbationEngine` exists but exposes no `p ∈ [0,1]` getter; it normalizes payloads and adds jitter | **None** | Declared constant in `SimVitalityEvaluationContext` | Requires `PerturbationEngine::pressure()` or equivalent — not implemented |

**All three inputs have zero existing runtime sources.** In Trial 1c they are
**explicit declared controls** supplied by the test scenario through `SimVitalityEvaluationContext`.
They must never be silently defaulted inside transport code.

Trial 1b used `i = 1.0, r = 1.0, p = 0.0` as isolated scenario controls.
Trial 1c uses the same values by default in the acceptance tests, and must expose them
as named fields so future tests can vary them deliberately.

---

## 8. Proposed Architecture

### 8.1 New type: `SimVitalityEvaluationContext`

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
    /// Caller is responsible for bilateral identity assembly.
    pub consent_hash: [u8; 32],
    /// Evaluation timestamp (Unix seconds). Deterministic — not SystemTime::now().
    pub now: u64,
    /// Declared interaction entropy control [0.0, 1.0].
    pub i: f64,
    /// Declared reciprocal participation control [0.0, 1.0].
    pub r: f64,
    /// Declared perturbation pressure control [0.0, 1.0].
    pub p: f64,
}
```

### 8.2 New method: `FlashSession::retrieve_state_sim()`

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
/// Do not call this function with production identity measurements.
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

The original `retrieve_state()` is **unchanged**. Its `VitalityState::Active` hardcode and
`// Phase 9: vitality oracle` comment remain intact.

### 8.3 New dependency

`scp-vitality` is **already** in `core/transport/Cargo.toml`. No workspace dependency changes.

`SimVitalityEvaluationContext` must be exported from `scp_vitality`. The transport crate
imports `use scp_vitality::{VitalityEvidenceStore, SimVitalityEvaluationContext}`.

---

## 9. Trial 1c Test List

**File:** `test/tests/trial1c.rs` (new file)

All tests use `retrieve_state_sim()` as the entry point. No test constructs `RecipientState`
directly — the vitality must flow through `retrieve_state_sim()` to satisfy the claim.

| # | Name (proposed) | What it proves |
|---|-----------------|----------------|
| T1 | `runtime_active_relationship_permits_send` | Initialized, freshly reaffirmed bilateral: `retrieve_state_sim()` → Active → `open_and_send()` succeeds |
| T2 | `runtime_suspended_relationship_blocks_send` | Relationship past Suspended threshold: `retrieve_state_sim()` → Suspended → `VitalityInsufficient` |
| T3 | `runtime_reaffirmation_restores_send` | Suspended → `record_reaffirmation()` → `retrieve_state_sim()` → Active → `open_and_send()` succeeds again |
| T4 | `runtime_missing_evidence_fails_closed` | No initialized evidence: `retrieve_state_sim()` → Suspended → `VitalityInsufficient` |
| T5 | `runtime_relationship_isolation_ab_vs_ac` | AB suspended, AC active; `retrieve_state_sim()` with AB hash rejects; with AC hash permits |
| T6 | `runtime_send_does_not_refresh_evidence` | After a permitted send, re-evaluate at `now + 578_389s` → Warm, not Active; send did not refresh timestamp |
| T7 | `retrieve_state_sim_bypasses_hardcoded_active` | Uninitialized evidence + direct call to `retrieve_state()` returns Active; `retrieve_state_sim()` with same provider returns Suspended — proves the sim path consults evidence, not the hardcode |
| T8 | `corridor_receive_unaffected` | Receive-path decryption of a prior Active-sent burst succeeds after relationship is Suspended — receive is not vitality-gated |
| T9 | `scenario_controls_i_r_p_are_explicit` | With `i = 0.3, r = 0.5, p = 0.0`: verify computed state boundary shifts match the formula; declared controls propagate correctly |

---

## 10. Exact Future Implementation File List

Changes needed when implementation is authorized:

| File | Change | Type |
|------|--------|------|
| `core/vitality/src/sim_context.rs` | New file: `SimVitalityEvaluationContext` struct | New |
| `core/vitality/src/lib.rs` | Add `pub mod sim_context; pub use sim_context::SimVitalityEvaluationContext;` | Modify (2 lines) |
| `core/transport/src/flash.rs` | Add `retrieve_state_sim()` method (~15 lines) and `use scp_vitality::SimVitalityEvaluationContext;` import | Modify |
| `test/tests/trial1c.rs` | New file: 9 tests | New |

**Files not touched:**
- `core/transport/src/state.rs` — `StateProvider` unchanged
- `core/transport/src/corridor.rs` — receive path unchanged
- `core/transport/src/harness.rs` — existing dev harness unchanged
- `core/vitality/src/evidence.rs` — `VitalityEvidenceStore` unchanged
- All ledger, relay, provider, identity crates — unchanged

---

## 11. Whether Implementation Can Proceed Without Inventing Unapproved Semantics

**Answer: Yes**, with one required discipline.

The only unapproved inputs are `i`, `r`, and `p`. The plan:
- Explicitly names all three as **declared scenario controls**
- Requires them to appear as named fields in `SimVitalityEvaluationContext`, not hidden defaults
- Prohibits any code path inside transport from silently assigning them
- Ensures test T9 verifies that different declared values produce correspondingly different outputs

Production use of real `i`, `r`, `p` measurements remains a future gap and is out of scope
for Trial 1c. The absence of real measurement sources is documented here and must not be
papered over by choosing convenient unit-valued defaults inside a production function.

---

## 12. What Trial 1c Does NOT Claim

- `retrieve_state()` (the original function) is wired — it is not
- `i`, `r`, `p` are measured at runtime from real interaction data
- `corridor::receive()` is vitality-gated
- The relay mailbox or routing layer consults vitality
- Production reaffirmation protocol exists
- LAN, desktop, or hardware readiness

---

## 13. Verdict

```
A — TRIAL_1C_SIMULATOR_RUNTIME_WIRING_SPECIFIED
```

All five audits resolved cleanly:

| Audit | Finding | Resolved |
|-------|---------|---------|
| 1. Call graph | Hardcode at `flash.rs:71`; gate at `flash.rs:166`; no production callers | ✅ |
| 2. Bilateral identity | Pre-computed `consent_hash` passed via context; transport does not call `tunnel_consent_hash()` | ✅ |
| 3. Store ownership | Scenario-level; passed as `&VitalityEvidenceStore` borrow; no lifetime contamination | ✅ |
| 4. Deterministic time | `ctx.now` used throughout `retrieve_state_sim()`; wall-clock only in defense-in-depth check | ✅ |
| 5. i/r/p sources | All three absent from production code; all three are named declared controls in `SimVitalityEvaluationContext` | ✅ |

Implementation is authorized to proceed once this plan is accepted.
