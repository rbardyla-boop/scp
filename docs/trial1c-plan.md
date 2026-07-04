# Trial 1c — Runtime Vitality Oracle Wiring (Planning)

**Status:** HOLD — depends on Trial 1b closure  
**Prerequisite verdict:** `A — TRIAL_1B_CLOSED_AND_BASELINED`  
**Trial 1b controls:** i = 1.0, r = 1.0, p = 0.0 (all carry forward)

---

## What Trial 1c Claims

Trial 1c wires the already-proven `VitalityEvidenceStore` (Trial 1b) into the
runtime send path so that `retrieve_state()` computes vitality from evidence
instead of returning the hardcoded `VitalityState::Active`.

**Claim (Trial 1c):**  
When `retrieve_state()` is called with a sender-recipient pair whose consent
relationship is initialized in a `VitalityEvidenceStore`, the returned
`RecipientState.vitality` reflects the relationship's actual computed state,
and the existing `open_and_send()` send gate enforces it exactly as in Trial 1b.

**Explicit non-claims (carry forward from Trial 1b):**
- A production reaffirmation protocol exists
- Vitality parameters (i, r, p) are sourced dynamically from protocol state
- Receive-side decryption is vitality-gated
- Relay mailbox delivery or routing privacy behavior
- Localhost, LAN, desktop, or hardware readiness

---

## Gap Analysis

### What exists

| Component | Location | Status |
|-----------|----------|--------|
| `VitalityEvidenceStore.compute_state()` | `core/vitality/src/evidence.rs` | Proven, Trial 1b |
| `VitalityState` variants + send gate | `core/vitality/src/state.rs` | Proven, Trial 1b |
| `FlashSession::open_and_send()` vitality check | `core/transport/src/flash.rs` | Proven, Trial 1b |
| `tunnel_consent_hash(a, b)` | `ledger/substrate/src/lib.rs:322` | Exists |
| `retrieve_state()` | `core/transport/src/flash.rs:58` | **Stub** — hardcoded `VitalityState::Active` |

### What `retrieve_state()` currently lacks

1. **Sender identity** — function signature takes only `recipient_ops_pub`; sender is not passed.
2. **Access to `VitalityEvidenceStore`** — the store is not accessible from the `StateProvider` trait or the current signature.
3. **Consent hash computation** — requires both sender and recipient keys to call `tunnel_consent_hash`.

---

## Proposed Signature Change

```rust
// Before (core/transport/src/flash.rs:58)
pub async fn retrieve_state(
    provider: &impl StateProvider,
    recipient_ops_pub: &[u8; 32],
) -> Result<RecipientState, TransportError>

// After
pub async fn retrieve_state(
    provider: &impl StateProvider,
    vitality_store: &VitalityEvidenceStore,
    sender_ops_pub: &[u8; 32],
    recipient_ops_pub: &[u8; 32],
) -> Result<RecipientState, TransportError>
```

Rationale: explicit parameters are preferred over trait extension. The
`VitalityEvidenceStore` is a distinct concern from the `StateProvider` (which
handles key lookup and revocation). Mixing them would force all current
`StateProvider` implementors to carry vitality state, coupling unrelated layers.

---

## Implementation Blueprint

### Step 1 — Extend `retrieve_state()` body

```rust
pub async fn retrieve_state(
    provider: &impl StateProvider,
    vitality_store: &VitalityEvidenceStore,
    sender_ops_pub: &[u8; 32],
    recipient_ops_pub: &[u8; 32],
) -> Result<RecipientState, TransportError> {
    if provider.is_revoked(recipient_ops_pub) {
        return Err(TransportError::RecipientRevoked);
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let consent_hash = tunnel_consent_hash(sender_ops_pub, recipient_ops_pub);
    let vitality = vitality_store.compute_state(consent_hash, now, 1.0, 1.0, 0.0);
    Ok(RecipientState {
        ops_pub: *recipient_ops_pub,
        vitality,
        routing_hints: vec![],
        handshake_ephemeral: provider.get_handshake_ephemeral(recipient_ops_pub, now),
    })
}
```

Required imports to add in `flash.rs`:
```rust
use scp_cryptography::keys::hash;         // already imported via keys::hash
use scp_ledger_substrate::tunnel_consent_hash;
use scp_vitality::VitalityEvidenceStore;
```

### Step 2 — Update all callers of `retrieve_state()`

Search: `grep -rn "retrieve_state" test/ core/`

Each call site must supply:
- a `&VitalityEvidenceStore` — callers either own one or receive one injected
- `sender_ops_pub` — from the sender's loaded identity (ops key)

In tests using `StubStateProvider`, pair with a fresh `VitalityEvidenceStore::new()`
with the relationship pre-initialized as needed.

### Step 3 — No changes to `open_and_send()` or `VitalityEvidenceStore`

The send gate (`open_and_send`) already enforces the vitality field in
`RecipientState` — this is the Trial 1b guarantee. Trial 1c only changes how
that field is populated.

---

## Trial 1c Test Coverage

Tests live in a new file `test/tests/trial1c.rs`.

**Required behavioral proofs:**

| Test | Setup | Expected outcome |
|------|-------|-----------------|
| `vitality_uninitialized_pair_fails_closed` | No `initialize_at`; call `retrieve_state` | Returns Suspended; `open_and_send` → `VitalityInsufficient` |
| `vitality_active_pair_permits_send` | `initialize_at(hash, now)`; `retrieve_state` at now | Returns Active; `open_and_send` → Ok |
| `vitality_decayed_pair_blocks_send` | `initialize_at(hash, 0)`; `retrieve_state` at t > 4_171_664 | Returns Suspended; `open_and_send` → `VitalityInsufficient` |
| `vitality_send_does_not_refresh_evidence` | Active send; then query at now + 578_389 | State is Warm (decay continues from initial anchor, not from send time) |
| `vitality_relationship_isolation_in_runtime_path` | Two pairs AB, AC; AC reaffirmed; AB not | AB → Suspended; AC → Active; enforcement is per-pair |

All 5 tests must exercise the `retrieve_state()` → `open_and_send()` path end-to-end
(not the store alone). The store was proven in isolation in Trial 1b; Trial 1c proves
the integrated pipeline.

---

## Build-order Notes

1. `core/vitality` — no changes needed
2. `ledger/substrate` — no changes needed (`tunnel_consent_hash` already exported)
3. `core/transport` — `flash.rs` changes: signature + body of `retrieve_state()`
4. `test/tests/trial1c.rs` — new test file
5. Any existing callers of `retrieve_state()` in other test files — update signatures

---

## Vitality Parameter Source

Trial 1c uses fixed controls i = 1.0, r = 1.0, p = 0.0 (same as Trial 1b).
Dynamic sourcing of vitality formula parameters (from protocol configuration or
per-relationship negotiation) is explicitly deferred and is not part of this trial.

---

## What Must NOT Change During Trial 1c

- `VitalityEvidenceStore` API
- `VitalityState` variants
- `open_and_send()` gate logic
- Existing Trial 1b tests (all 11 must continue to pass)
- Any production module other than `core/transport/src/flash.rs`
