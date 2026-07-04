# Option 2 Closure Record — Pool-Liveness-Gated Multi-Relay Routing

**Verdict**: `A — PROVIDERPOOL_MULTIRELAY_ROUTING_SEAM_PROVEN`
**Date**: 2026-07-04
**Predecessors**:
- `PROVIDERPOOL_REAL_NETWORK_LIVENESS_TRIAL_PLAN.md` (Option 1, PROVEN — real-network observation, localhost + live mesh)
- `PROVIDERPOOL_MULTIRELAY_ARCHITECTURE_DESIGN.md` (architecture + ADR, verdict `B — OPTION_2_ROUTING_SEAM_AUTHORIZED`, admissible-surface sub-decision)

---

## 1. Verdict Summary

| Dimension | Result |
|---|---|
| Phase 1 — pool seam relocation (`sample_selected`/`sample_selected_with_receipts`), behavior-preserving | PROVEN (rust-reviewer approved) |
| Phase 2 — `provider/delivery` crate (`DeliveryEndpoint`, `DeliveryPool`, `RelayEndpoint`) | PROVEN (security-reviewer approved, 2 findings fixed) |
| Phase 3 — CLI routing seam (`select_relay_routes`, THE boundary crossing) | PROVEN (security-reviewer approved, 3 findings fixed: 1 HIGH, 2 MEDIUM) |
| Phase 4 — localhost 2-relay failover (replicate-store, poll-any-dedup, real kill) | PROVEN |
| Phase 5 — live Tailscale-mesh 2-relay failover (real SSH-triggered kill of a real remote relay) | PROVEN |
| ADR carve-outs preserved (vitality, send authorization, corridor suspension, state-provider rotation, TOLS) | CONFIRMED unbroken at every phase |
| Full workspace regression baseline | **546 passing, 0 failed, 2 ignored** |
| Backward compatibility (single-relay usage) | CONFIRMED — `level1.rs`, `lan_liveness_trial.rs` pass unchanged |

---

## 2. Accepted Pre-Option-2 Baseline

| Item | Value |
|---|---|
| Option 1 verdict | `A` — both Step 1 (localhost) and Step 2 (live mesh) real-network observation trials PROVEN |
| Prior full-workspace total | 520 passing, 0 failed, 1 ignored |
| New tests added by Option 2 (Phases 1–5) | 27 (26 passing + 1 `#[ignore]`d) |
| Expected new total | 520 + 26 passing = **546**; 1 + 1 ignored = **2** |
| Actual new total | **546 passing, 2 ignored** |

---

## 3. Exact Files Created or Modified

**Created:**
- `provider/delivery/Cargo.toml`, `provider/delivery/src/lib.rs` (new crate, 15 tests)
- `test/tests/pool_delivery_seam.rs` (4 tests)
- `test/tests/multirelay_failover.rs` (4 tests, 1 `#[ignore]`d)
- `docs/architecture/PROVIDERPOOL_MULTIRELAY_ARCHITECTURE_DESIGN.md`
- `docs/architecture/OPTION_2_MULTIRELAY_CLOSURE_RECORD.md` (this file)

**Modified:**
- `provider/pool/src/lib.rs` — `sample_inner` relocated to `impl<P: Clone>`; `sample_selected()`/`sample_selected_with_receipts()` added; `sample()`/`sample_with_receipts()` rewritten as thin wrappers. Behavior-preserving (verified).
- `cli/endpoint/src/main.rs` — `cmd_send`/`cmd_receive` rewritten for repeatable `--relay`, R1 replicate-store/poll-any-dedup, routed through `DeliveryPool<RelayEndpoint>` via the single `select_relay_routes()` seam.
- `Cargo.toml` — added `provider/delivery` workspace member.
- `cli/endpoint/Cargo.toml`, `provider/delivery/Cargo.toml` — new dependencies (`scp-provider-pool`, `scp-provider-delivery`, `rand_core`, dev: `rand`, `tokio` with `test-util`).

**Not modified**: `relay/daemon/src/main.rs` (confirmed independent per-process state — no change needed for multi-relay coexistence). Corridor Trial track (1–5C). `VitalityEvidenceStore`, corridor/state-provider rotation logic.

---

## 4. The Single Audited Boundary Crossing

`select_relay_routes()` in `cli/endpoint/src/main.rs` is the **sole** place `ProviderPool`/`DeliveryPool` liveness state influences real behavior — verified by an independent `security-reviewer` pass (exactly one definition, exactly two call sites, no other pool/liveness reference anywhere in the file). It gates *routing selection only*: which live relay(s) a real, already-encrypted, already-authorized burst is attempted against. It never influences whether a burst is authorized, encrypted, or considered deliverable — cryptographic authorization (`send_harness_direct`, `receive_harness`) fully resolves before the pool is ever consulted.

---

## 5. Security Findings Fixed (independent reviews, not self-assessed)

### Phase 1 (rust-reviewer)
- `clippy::type_complexity` on `sample_selected_with_receipts`'s return type → fixed with a `SelectionWithReceipts<P>` type alias.
- 3 unnecessary `mut` bindings in `pool_delivery_seam.rs` → removed.

### Phase 2 (security-reviewer)
- **Admissible-surface-only telemetry never gated routing.** `record_admissible_response/failure()` are documented as telemetry-only and never touch the raw liveness counters `is_live()`/`sample_inner()` read. Caught by a genuinely failing test, not inspection. Fixed: `DeliveryPool::record_delivery_success/failure()` now call the admissible method first (receipt validation gate) and only then the raw method using the same already-validated `receipt.provider_id()` — satisfies the ADR (the receipt is what prevents forged/replayed/never-selected outcomes) while making routing actually responsive to liveness.
- **`endpoint_id` random-tag requirement had zero enforcement.** Fixed with pinning tests proving the tag is independent of the relay address.
- Documented (not fixed, scoped acceptable): unresolved routes permanently consume receipt capacity — bounded because `DeliveryPool` is constructed fresh per short-lived CLI invocation, not reused across a long-running process.

### Phase 3 (security-reviewer)
- **HIGH — dedup-before-verification let one malicious relay silently suppress a legitimate message.** `route_id` dedup ran on the raw, unauthenticated field before AEAD verification; a hostile relay in the configured set could forge a blob sharing a real burst's `route_id` (visible in plaintext on the wire) and win the dedup race. Fixed: dedup now runs only after `receive_harness()` verification succeeds.
- **MEDIUM — no I/O timeouts.** A relay that accepted a connection and never responded stalled the entire failover attempt indefinitely. Fixed: `RelayEndpoint`'s wire client wraps every attempt in a 10s `tokio::time::timeout` (tested with virtual time).
- **MEDIUM — unbounded allocation from an untrusted relay's poll response.** `count`/`len` headers were trusted with no bound. Fixed: both capped (mirroring the relay daemon's own `MAX_BURST_BYTES`), regression-tested against a real TCP server sending crafted oversized headers.

### Pre-existing, out of scope, flagged not fixed
`core/transport::harness::hex_decode()` panics on adversarial multi-byte-UTF-8 input (reachable from a malicious `--recipient` contact-card file). Predates Option 2 entirely; recommend a separate fix.

---

## 6. Confirmation: ADR Carve-Outs Remain Unbroken

- `VitalityEvidenceStore` — untouched by any Option 2 code path; no import, no reference.
- Send authorization — a burst to any live relay is authorized identically regardless of liveness state; liveness changes WHERE, never WHETHER (verified: crypto verification precedes pool consultation in `cmd_send`).
- Corridor suspension — no Option 2 code references corridor state.
- Rotation of state-consistency providers — `ProviderQuorum`/`StateProvider` machinery is structurally unreachable from `DeliveryPool` (`RelayEndpoint` does not implement `StateProvider`; the compiler rejects any attempt to route it into `sample()`/`get_commitment_quorum()`).
- TOLS — no reference anywhere in Phases 1–5.

---

## 7. Explicit Non-Claims

Option 2, even fully implemented and tested, does **not** provide:

- Metadata-resistant relay addressing (a network-position observer still sees which relay IPs a client connects to — unchanged limitation from Level 2, and R1 replication widens this surface by design, as documented in the architecture doc §3.2).
- Mailbox replication or persistence (relays remain independent, in-memory, non-replicated — R1 achieves failover via client-side fan-out, not server-side durability).
- Protection of the sender↔recipient graph from a global passive network adversary.
- Production readiness of `ProviderPool`/`DeliveryPool` at scale.
- Any authorization for pool telemetry to influence vitality, send authorization, corridor state, or state-consistency-provider rotation — those remain frozen exactly as Trial 2 and Trial 5A established.
- A fix for the pre-existing `hex_decode()` panic (flagged, not addressed here).
- A general-purpose reclaim mechanism for abandoned `SelectionReceipt`s in a long-running (non-CLI) consumer of `provider/delivery`.

---

## 8. Post-Option-2 Sequencing

```
Trial 0:   in-process encrypted exchange                       PROVEN
Level 1:   multi-process localhost dev-harness                 PROVEN
Level 2:   three-machine LAN/mesh dev-harness                   PROVEN
Option 1:  ProviderPool real-network liveness observation       PROVEN (localhost + live mesh)
Option 2:  pool-liveness-gated multi-relay routing              PROVEN (localhost + live mesh)  ← current
```

No further Option-2-adjacent work is scoped or authorized. Any future initiative building on this (a third relay, admission-gated relay onboarding, config-file relay lists, a reclaim mechanism for long-running consumers) requires its own scope pass, per the same discipline this initiative followed.
