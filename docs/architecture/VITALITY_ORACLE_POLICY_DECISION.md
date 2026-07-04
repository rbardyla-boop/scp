# Vitality Oracle Policy Decision

**Status**: DECISIONS ACCEPTED — implementation authorized for Trial 1b.  
**Date adjudicated**: 2026-05-28  
**Date accepted**: 2026-05-28  
**Context**: Trial 1a (static enforcement gate) is proven and closed. This document resolves all six decisions required before Trial 1b implementation begins.

---

## Arithmetic correction from prior plan

The `CORRIDOR_TRIAL_1_INACTIVITY_REAFFIRMATION_PLAN.md` stated the Active→Warm transition at `t ≈ 5.7 days`. That figure is incorrect. The correct thresholds under `V = exp(-t / TAU_SECS)` with `TAU_SECS = 2,592,000s` are:

| Transition | Threshold condition | Last second in upper state | First second in lower state | Correct `t` (days) |
|---|---|---|---|---|
| Active → Warm | V drops below 0.80 | 578,388 s | **578,389 s** | **≈ 6.694 days** |
| Warm → Dormant | V drops below 0.50 | 1,796,637 s | **1,796,638 s** | **≈ 20.794 days** |
| Dormant → Suspended | V drops below 0.20 | 4,171,663 s | **4,171,664 s** | **≈ 48.283 days** |

Any reference to Active→Warm at approximately 5.7 days must be removed before Trial 1b tests are written.

---

## Decision 0 — Vitality ownership

### Status: **ACCEPTED**

### Ruling

> Vitality is scoped to the bilateral relationship identified by the existing `tunnel_consent_hash(party_a, party_b)` key. It is not globally scoped to `recipient_ops_pub` and does not belong to a flash session.

### Code evidence

| Symbol | File | Evidence |
|---|---|---|
| `TunnelConsent { party_a, party_b }` | `ledger/substrate/src/lib.rs:46–55` | Bilateral pair; both parties must sign |
| `tunnel_consent_hash(a, b) -> [u8; 32]` | `ledger/substrate/src/lib.rs:322–324` | Canonical order-independent key: `BLAKE3("scp:tunnel:v1:" ‖ lo_pub ‖ hi_pub)` |
| `LedgerState.tunnels: HashMap<[u8; 32], TunnelConsent>` | `ledger/substrate/src/lib.rs:79` | Consent records already keyed by consent hash |
| `retrieve_state(provider, recipient_ops_pub)` | `core/transport/src/flash.rs:58–75` | Only receives recipient identity — noted Phase 9 gap |

### Mandatory question answered

Under identity scope, B's corridor to C would be blocked by B→A inactivity. Under TunnelConsent hash scope, `hash(A,B)` and `hash(A,C)` are independent keys; inactivity in one has zero effect on the other.

### Architecture gap (Phase 9, not Trial 1b blocker)

`retrieve_state` takes only `recipient_ops_pub`. Bilateral vitality lookup requires both parties. Trial 1b bypasses `retrieve_state` entirely and queries the evidence store directly — the same approach Trial 1a used to directly construct `RecipientState.vitality`.

---

## Decision 1 — Definition and storage of `t`

### Status: **ACCEPTED** (initialization rule resolved in Decision 5)

### Ruling

> `t` is elapsed seconds since the most recent accepted reaffirmation event for the bilateral relationship. Store raw `last_reaffirmed_at: u64` (Unix epoch seconds) per corridor. Compute vitality at evaluation time: `t = (now - last_reaffirmed_at) as f64`. Supply `now: u64` from the caller (tests: integer literal; production: `SystemTime::now()`).

### Code evidence

| Symbol | File | Evidence |
|---|---|---|
| `VitalityParams { t: f64 }` | `core/vitality/src/function.rs:5` | Documented: "Seconds elapsed since the last successful reaffirmation event." |
| `TAU_SECS: f64 = 2_592_000.0` | `core/vitality/src/function.rs:19` | 30 days |
| `HandshakeEphemeral { published_at: u64, expires_at: u64 }` | `ledger/substrate/src/lib.rs:27` | Codebase convention: `u64` Unix epoch seconds |
| `get_handshake_ephemeral(ops_pub, now: u64)` | `core/transport/src/state.rs:11` | Existing deterministic time seam pattern |
| `SystemTime::now()` at lines 65 and 181 | `core/transport/src/flash.rs` | Both for ephemeral key **expiry** — entirely unrelated to vitality |

### Storage location

New `VitalityEvidenceStore`, not `SubstrateLedger`. The ledger holds authorization state (who may communicate). The evidence store holds relationship health state (when they last exchanged). These concerns are distinct; mixing them would complicate the Phase 8 RPC migration.

---

## Decision 2 — What constitutes reaffirmation

### Status: **ACCEPTED**

### Ruling

> Reaffirmation is an explicit bilateral authenticated relationship event. Ordinary unilateral send or receive traffic does not automatically refresh vitality.

For simulator trials, directly injecting a validated reaffirmation event (`evidence_store.record_reaffirmation(consent_hash, now)`) is allowed as a simulator abstraction. This must not be claimed as a production reaffirmation protocol proof.

### Adversarial question answered

Under unilateral-send semantics, Alice could send one message per 5 days to keep the corridor permanently Active regardless of Bob's participation. This makes `r` (reciprocal participation) structurally irrelevant. The explicit bilateral event rule prevents this: neither party can sustain a corridor the other has abandoned.

### What this rules out

- `open_and_send_core` must NOT call `record_reaffirmation`. The send path is not a reaffirmation event.
- `corridor::receive` must NOT call `record_reaffirmation`. Same logic from the receiver side.

---

## Decision 3 — Trial 1b control values and corrected boundaries

### Status: **ACCEPTED**

### Ruling

> Trial 1b isolates inactivity by holding `i = 1.0`, `r = 1.0`, and `p = 0.0`, while varying only `t`.

### Formula evidence

```
V = exp(-t / TAU) * sqrt(i * r) * (1 - 0.20 * p)
```

| Input | Why this value | Risk if changed |
|---|---|---|
| `i = 1.0` | engagement factor = sqrt(1.0 × 1.0) = 1.0; any lower value independently suppresses V | `i = 0` collapses V to zero regardless of t |
| `r = 1.0` | same as `i`; symmetry in formula | `r = 0` collapses V to zero regardless of t |
| `p = 0.0` | V starts at 1.0; `p = 1.0` at t=0 gives V = 0.80 — exactly the Active→Warm boundary, corrupting the observation | `p = 1.0` would make the test start at a transition point |

### Corrected exact integer-second boundaries

| Transition | Last second Active/Warm/Dormant | First second Warm/Dormant/Suspended |
|---|---|---|
| Active → Warm | 578,388 s | 578,389 s |
| Warm → Dormant | 1,796,637 s | 1,796,638 s |
| Dormant → Suspended | 4,171,663 s | 4,171,664 s |

No probabilistic assertions. No wall-clock sleeps. All `t` values supplied as integer literals.

---

## Decision 4 — Enforcement scope

### Status: **ACCEPTED**

### Ruling

> Trial 1b enforces vitality only when creating new sends. It does not add receive-side blocking and does not retroactively invalidate an authenticated envelope created while vitality was open.

### Code evidence

| Code location | Existing behavior |
|---|---|
| `open_and_send_core()` lines 166–168 | Rejects new burst if `!state.vitality.is_open()` — proven by Trial 1a |
| `corridor::receive()` (`corridor.rs:52–88`) | Pure function; takes only `(envelope, eph_secret)`; no vitality oracle dependency |
| `BurstEnvelope.vitality_snapshot` | Send-time vitality bound into transcript hash; tampering causes decryption failure (corridor test 9); this is a send-time assertion, not a receive-time gate |

### Mandatory question answered

Rejecting decryption of a validly created envelope because vitality has since fallen would be a new policy invention. The current design assigns sender responsibility: the sender checks vitality before creating a burst. Receive-side blocking would require defining "delivery time" in a store-and-forward relay model, which is undefined in the current protocol.

---

## Decision 5 — Initial vitality state for a newly consented relationship

### Status: **ACCEPTED**

### The problem

A `VitalityEvidenceStore` with `HashMap<[u8; 32], u64>` has no entry for a newly registered consent hash until something writes to it. The naive default `evidence.get(hash).copied().unwrap_or(0)` is wrong: at any realistic Unix timestamp, `t = now - 0` (epoch 1970) produces elapsed ≈ 55 years ≈ 1.74 billion seconds, giving V ≈ exp(-672) ≈ 0, making every uninitialized corridor appear permanently Suspended.

Three options were evaluated:

| Option | Meaning | Risk |
|---|---|---|
| A. Consent creation seeds `last_reaffirmed_at` | New corridor begins Active at consent time | Treats authorization as initial bilateral proof of life |
| B. Consented corridor non-operational until explicit reaffirmation | Stronger — forces activation ceremony | Prevents immediate use of a newly authorized relationship |
| C. Missing evidence defaults to Suspended (fail-closed) | Safe default | Requires explicit activation before any send |

### Ruling

> Creating valid bilateral tunnel consent seeds the initial `last_reaffirmed_at` at consent-establishment time, allowing the newly authorized relationship to begin Active. After initialization, only an explicit bilateral reaffirmation event refreshes vitality; ordinary sends and receives do not.

Rationale: bilateral tunnel consent already requires both parties' signatures. The consent event IS a bilateral proof of life. Treating it as the initial reaffirmation seed allows a newly authorized relationship to be used immediately without an additional activation ceremony. This is consistent with Decision 2: the consent event IS an explicit bilateral event; ongoing traffic is not.

### Missing-record behavior

For any consent hash with no entry in the evidence store, `compute_state` returns `VitalityState::Suspended`. This is the fail-closed behavior for a corridor that has never been initialized. The `unwrap_or(0)` fallback must **not** be used.

```
None in evidence store → Suspended (not a computed V)
Some(last_reaffirmed_at) → V = exp(-t/TAU) × i×r term × perturbation term → state band
```

### API design — two distinct methods

The store requires two semantically distinct operations:

| Method | When called | Semantics | Idempotent? |
|---|---|---|---|
| `initialize_at(consent_hash, established_at)` | Once, on consent registration | Seeds the initial timestamp; the bilateral consent IS the first reaffirmation | Write-once: no-op if already initialized |
| `record_reaffirmation(consent_hash, now)` | On each explicit bilateral event | Updates the timestamp; always overwrites | Always updates |

Both operations write a `u64` timestamp to the same field. Their distinction is semantic and documented in the API, not in storage structure. `initialize_at` is write-once to enforce the invariant that initialization happens exactly once. `record_reaffirmation` always overwrites to allow ongoing refresh.

### How Trial 1b seeds corridors without modifying SubstrateLedger

Trial 1b tests explicitly call `initialize_at(hash, T0)` in test setup for each corridor under test. The test controls the consent hash (derived from known key pairs), so it can compute the same hash the ledger would use. This represents "consent established at T0" without any hooking into `register_tunnel`. This is a documented simulator abstraction; in production, consent registration would trigger the initial `initialize_at`.

No changes to `SubstrateLedger` are required for Trial 1b.

---

## Permitted Trial 1b proof claim

Because `retrieve_state()` still hardcodes `VitalityState::Active` and the evidence store is not wired into runtime state retrieval, Trial 1b must not claim that the normal `FlashSession` runtime automatically evaluates vitality.

### Permitted claim

> Trial 1b proves that a relationship-scoped `VitalityEvidenceStore` deterministically computes inactivity and reaffirmation transitions, and that its computed `VitalityState` composes correctly with the already-proven `FlashSession` send enforcement gate.

### Explicit non-claims

- `retrieve_state()` oracle wiring is not implemented; it still hardcodes `VitalityState::Active`
- The runtime `FlashSession` path does not dynamically consult vitality evidence
- Dynamic vitality is not automatically enforced during ordinary sender retrieval
- Production reaffirmation protocol is not implemented
- Receive-side decryption gating is not implemented
- Relay, localhost, LAN, and hardware behavior are not proven

---

## Proposed minimal vitality state/data model

```rust
// core/vitality/src/evidence.rs (new file)

use crate::function::{compute, VitalityParams};
use crate::state::VitalityState;
use std::collections::HashMap;

pub struct VitalityEvidenceStore {
    evidence: HashMap<[u8; 32], u64>,  // consent_hash → last_reaffirmed_at (unix epoch secs)
}

impl VitalityEvidenceStore {
    pub fn new() -> Self

    /// Seed the initial reaffirmation timestamp at consent-establishment time.
    /// Write-once: no-op if already initialized (consent registers exactly once).
    pub fn initialize_at(&mut self, consent_hash: &[u8; 32], established_at: u64)

    /// Record an explicit bilateral reaffirmation event. Always overwrites.
    pub fn record_reaffirmation(&mut self, consent_hash: &[u8; 32], now: u64)

    /// Compute vitality state for a corridor at evaluation time `now`.
    /// Returns Suspended for any uninitialized corridor (no entry in store).
    /// `i`, `r`, `p` are supplied by the caller; Trial 1b uses 1.0, 1.0, 0.0.
    pub fn compute_state(
        &self,
        consent_hash: &[u8; 32],
        now: u64,
        i: f64, r: f64, p: f64,
    ) -> VitalityState
}
```

Three public methods. No unsafe. No async. No clock calls. `compute_state` calls the existing pure `VitalityFunction::compute()`.

---

## Trial 1b event sequence

`T0 = 0` (arbitrary epoch-relative anchor). Simulator control values: `i=1.0, r=1.0, p=0.0`.

| Step | Action | `now` | hash_AB elapsed | hash_AC elapsed | hash_AB state | hash_AC state | Send result |
|---|---|---|---|---|---|---|---|
| 1 | `initialize_at(hash_AB, T0)` | T0 | — | — | — | — | — |
| 2 | `initialize_at(hash_AC, T0)` | T0 | — | — | — | — | — |
| 3 | Compute + feed AB to send seam | T0 | 0 | — | Active | — | **Ok** |
| 4 | Compute AB | T0 + 578,389 | 578,389 | — | Warm | — | **Ok** (is_open) |
| 5 | Compute AB (exact boundary) | T0 + 578,388 | 578,388 | — | **Active** | — | — |
| 6 | Compute AB (first Warm second) | T0 + 578,389 | 578,389 | — | **Warm** | — | — |
| 7 | Compute AB | T0 + 1,796,638 | 1,796,638 | — | Dormant | — | **Ok** (is_open) |
| 8 | Compute AB | T0 + 4,171,664 | 4,171,664 | — | Suspended | — | **VitalityInsufficient(Suspended)** |
| 9 | `record_reaffirmation(hash_AB, T0 + 4,171,664)` | T0 + 4,171,664 | 0 relative | — | — | — | — |
| 10 | Compute + feed AB to send seam | T0 + 4,171,664 | 0 | — | Active | — | **Ok** |
| 11 | Confirm send did not mutate evidence store | T0 + 5,000,000 | 828,336 | — | Active (≈ V=0.724 Warm) | — | **Ok** (Warm is open) |
| 12 | **Isolation**: `record_reaffirmation(hash_AC, T0 + 4,171,664)` | T0 + 4,171,664 | — | 0 | — | — | — |
| 13 | Evaluate AB with no further reaffirm | T0 + 4,171,664 | 4,171,664 | — | Suspended | — | **VitalityInsufficient** |
| 14 | Evaluate AC (just reaffirmed) | T0 + 4,171,664 | — | 0 | — | Active | **Ok** |
| 15 | Verify missing-record returns Suspended | any `now` | — | — | — | — | — |

Note: step 11 demonstrates that a successful send did not call `record_reaffirmation` — vitality continues decaying under the send interval, proving Decision 2.

---

## Proposed file modification list for Trial 1b

| File | Action | Purpose |
|---|---|---|
| `core/vitality/src/evidence.rs` | **CREATE** | `VitalityEvidenceStore` with `initialize_at`, `record_reaffirmation`, `compute_state` |
| `core/vitality/src/lib.rs` | **MODIFY** | Add `pub mod evidence; pub use evidence::VitalityEvidenceStore;` |
| `test/tests/trial1b.rs` | **CREATE** | 9 integration tests (see below) |
| `core/vitality/src/function.rs` | **DO NOT TOUCH** | Pure function is correct |
| `core/vitality/src/state.rs` | **DO NOT TOUCH** | Wire-format contract |
| `core/transport/src/flash.rs` | **DO NOT TOUCH** | `retrieve_state` oracle wiring deferred to Phase 9 |
| `core/transport/src/state.rs` | **DO NOT TOUCH** | `StateProvider` unchanged for Trial 1b |
| `ledger/substrate/src/lib.rs` | **DO NOT TOUCH** | Evidence store is separate from ledger |
| `core/transport/src/corridor.rs` | **DO NOT TOUCH** | Trial 0 primitive, frozen |

---

## Proposed Trial 1b test list

All tests reside in `test/tests/trial1b.rs`. All use `i=1.0, r=1.0, p=0.0`.

| # | Test name | What it proves |
|---|---|---|
| 1 | `inactivity_at_t0_is_active` | Fresh initialization → elapsed = 0 → V=1.0 → Active; send succeeds |
| 2 | `inactivity_at_exact_active_warm_boundary` | elapsed=578,388 → Active; elapsed=578,389 → Warm; boundary is a sharp integer transition |
| 3 | `inactivity_warm_state_send_permitted` | elapsed=578,389 → Warm; is_open() = true; send gate does not reject |
| 4 | `inactivity_at_exact_warm_dormant_boundary` | elapsed=1,796,637 → Warm; elapsed=1,796,638 → Dormant; boundary is sharp |
| 5 | `inactivity_dormant_state_send_permitted` | elapsed=1,796,638 → Dormant; is_open() = true; send gate does not reject |
| 6 | `inactivity_past_suspended_threshold_rejects_send` | elapsed=4,171,664 → Suspended; send → `VitalityInsufficient(Suspended)` |
| 7 | `reaffirmation_restores_vitality_to_active` | `record_reaffirmation` at Suspended point; elapsed=0 → Active; send succeeds |
| 8 | `send_does_not_implicitly_reaffirm` | Successful send does not update evidence store; state continues decaying; demonstrates Decision 2 |
| 9 | `corridor_isolation_prevents_contamination` | Seed hash_AB and hash_AC at T0; advance AB past Suspended with no reaffirm; `record_reaffirmation(hash_AC, T0+4,171,664)`; evaluate both at T0+4,171,664: AB → Suspended, AC → Active; feed both states to send seam: AB rejected, AC succeeds |

Test 9 explicitly seeds both corridors at T0 (no undefined missing-record behavior is used).

Missing-record behavior (fail-closed → Suspended) is enforced internally by `compute_state` and proven by the implementation; no separate test is required to verify a sentinel, but the behavior is documented in the API.

---

## Decision Status

| Decision | Status | Ruling |
|---|---|---|
| 0 — Vitality ownership | **ACCEPTED** | `tunnel_consent_hash(a, b)` bilateral key |
| 1 — Storage of `t` | **ACCEPTED** | Raw `last_reaffirmed_at: u64`; compute at query time with `now: u64` |
| 2 — Reaffirmation event | **ACCEPTED** | Explicit bilateral authenticated event; sends do not refresh |
| 3 — `i`, `r`, `p` controls | **ACCEPTED** | i=1.0, r=1.0, p=0.0; corrected boundary values above |
| 4 — Enforcement scope | **ACCEPTED** | Send-side only; `corridor::receive()` unchanged |
| 5 — Initialization | **ACCEPTED** | Consent creation seeds `initialize_at(hash, established_at)`; missing record → Suspended |

---

## Contradictions between accepted rulings and existing architecture

| Issue | Nature | Trial 1b blocker? | Resolution path |
|---|---|---|---|
| `retrieve_state` takes only `recipient_ops_pub`; bilateral vitality requires both parties | API gap | **No** — Trial 1b queries oracle directly, bypassing `retrieve_state` | Phase 9: add `sender_ops_pub` param or thread `VitalityProvider` separately |
| `StateProvider` has no `vitality_state` method | Trait gap | **No** — `VitalityEvidenceStore` is standalone for Trial 1b | Phase 9: define `VitalityProvider` trait when oracle is wired into send path |
| `open_and_send_core` does not call `record_reaffirmation` | Design confirmation (intentional) | No — this is correct per Decision 2 | Nothing to change |
| `retrieve_state` still hardcodes `VitalityState::Active` | Deliberate deferral | **No** — Trial 1b permitted claim explicitly excludes this | Phase 9: wire oracle into `retrieve_state` |
| Prior plan document stated Active→Warm at 5.7 days | Arithmetic error (corrected above) | No — never implemented; no code depends on it | Correct in any plan that references it |

---

## Verdict

`A — VITALITY_POLICY_READY_FOR_IMPLEMENTATION`

All six decisions have accepted rulings grounded in code evidence. The four Trial 1b blockers are cleared:

1. Vitality ownership: `tunnel_consent_hash` (existing key, no new type)
2. Evidence model: `VitalityEvidenceStore` with `initialize_at` / `record_reaffirmation` / `compute_state`
3. Initialization: consent establishment seeds `initialize_at`; missing record → Suspended (fail-closed)
4. Proof claim: narrowed to oracle chain composition, not automatic runtime wiring

Two files, ~120 lines total. No existing files modified.

**Implementation is authorized. Begin with `core/vitality/src/evidence.rs`, then `test/tests/trial1b.rs`.**
