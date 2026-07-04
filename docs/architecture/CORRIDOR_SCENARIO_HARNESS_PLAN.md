# Corridor Scenario Harness Plan — Phase 41

**Status**: Planning complete. Implementation verdict: A (see §6).
**Date**: 2026-05-28
**Scope**: In-process deterministic scenario harness for Trial 0–2. No UI, no hardware, no user-facing vocabulary.

---

## 1. Existing Usable Components

All components below were inspected at their current source paths. No component was assumed from prior descriptions; each was read from Rust source.

### 1.1 Identity generation

**File**: `core/identity/src/genesis.rs`

`IdentityGenesis::execute()` produces a `GenesisArtifacts` containing:
- `k_root_pub` / `k_root_priv` — Ed25519 root keypair
- `k_ops_pub` / `k_ops_priv` — Ed25519 operational keypair
- `recovery_policy_hash`, `continuity_commitment`

The return is `Result<GenesisArtifacts, IdentityError>`. Both fields zeroize on drop. **Directly usable** for creating Endpoint A and Endpoint B identities in a scenario.

### 1.2 Bilateral DH / session key derivation

**Files**: `core/cryptography/src/keys.rs`, `core/transport/src/transcript/v2.rs`

The v2 session key derivation is:

```
dh_output     = x25519_dh(sender_secret, recipient_handshake_pub)
transcript_v2 = FlashTranscriptV2 { route_id, nonce, recipient_ops_pub,
                                     vitality_snapshot, protocol_version: 2,
                                     sender_ephemeral_pub }
session_key   = scp_derive_key(Transport,
                  dh_output ‖ transcript_v2.hash() ‖ recipient_ops_pub)
```

The DH is symmetric: `x25519_dh(sender_secret, B_eph_pub) == x25519_dh(B_eph_secret, sender_pub)`. This is proven by the existing test `x25519_raw_dh_is_symmetric` in `test/tests/transport.rs`.

**Recipient can reconstruct session_key if given**: `sender_ephemeral_pub`, `route_id`, `nonce`, `vitality_snapshot`. All other fields (recipient_ops_pub, protocol version) are locally known.

### 1.3 FlashSession sender lifecycle

**File**: `core/transport/src/flash.rs`

`FlashSession::retrieve_state(provider, &recipient_ops_pub)` — fetches RecipientState including optional published handshake ephemeral.

`FlashSession::open_and_send(state, payload, cache, engine)` — full sender path:
1. Verifies vitality is open
2. Generates route_id and nonce
3. v2: verifies handshake sig, generates sender ephemeral, computes DH
4. Encrypts: `let (ciphertext, enc_nonce) = crypto_sk.encrypt(payload)`
5. Perturbs: normalize → jitter → relay select → transmit via `route_burst()`
6. Retains session_key in warm cache
7. Returns `FlashSession { route, session_key, nonce, vitality, lifecycle }`

**Gap**: `enc_nonce`, `sender_ephemeral_pub`, and `ciphertext` are **not exposed** in the returned `FlashSession`. They are used internally and not stored in any retrievable location. This is the primary implementation gap for Trial 0 (see §2).

### 1.4 Wire burst structure

**Files**: `scp-wire-format/src/framing.rs`, `scp-wire-format/src/constants.rs`, `scp-wire-format/src/transcript.rs`

Two framing formats:
- TCP: 4-byte LE length prefix + payload
- Noise: 2-byte BE length prefix + message

The payload passed to the relay is `engine.normalize_payload(&ciphertext)` — the SCP ciphertext (with padding). The relay receives opaque bytes and **cannot decrypt** them (relay has no session key). **The relay intentionally drops payload after ACK** (`drop(payload)` in `relay/mesh/src/lib.rs:273`).

`spawn_relay_listener()` and `spawn_noise_relay_listener()` — both usable for in-process relay simulation. Both bind to `127.0.0.1:0` and return the bound address.

### 1.5 Relay mesh forwarding primitive

**File**: `relay/mesh/src/lib.rs`

`route_burst(payload, relays)` — forwards to `relays[0].blind_relay().forward(&payload)`.

`BlindRelay::local()` — forwards without any network I/O, always returns `Ok(())`. **Available for in-process simulation without TCP setup.**

`RelayNode { id: [u8; 16], endpoint: String }` — `endpoint = "local://..."` uses the local path.

The relay is enforceably blind: it has no API for a recipient to retrieve payload. There is no inbox, no addressable mailbox, no store-and-forward. This is not a bug in the relay; it is the intended design. The receiver-side receive path must be implemented in the harness at the sender layer (see §2).

### 1.6 Vitality / state components

**Files**: `core/vitality/src/state.rs`, `core/vitality/src/function.rs`

`VitalityState` enum: `Active`, `Warm`, `Dormant`, `Suspended`, `Severed`, `Burned`. `is_open()` returns true for Active / Warm / Dormant.

`VitalityState::from_score(f64)` — maps a score in [0, 1] to a state band.

`SubstrateLedger::register_tunnel(TunnelConsent)` — bilateral consent requires both parties' Ed25519 signatures over `tunnel_consent_hash(party_a, party_b)`.

### 1.7 Provider pool simulation and OperationalTelemetrySnapshot

**Files**: `provider/pool/src/lib.rs`, `provider/pool/src/metrics.rs`

`ProviderPool::operational_telemetry()` returns `OperationalTelemetrySnapshot` with three orthogonal surfaces:
- **Surface 1** — Survivor concentration (κ / T1): guards against rotation thrash hiding collapse
- **Surface 2** — Relative liveness distortion (κ_L): compares liveness-weighted κ against raw κ
- **Surface 3** — Absolute availability: reports_absolute_fraction of providers responding

`survivor_surface_evaluable` and `liveness_surface_evaluable` — boolean guards preventing false reads when observation count is too low.

This subsystem is complete and can be injected into Trial 2 once Trial 0 passes.

---

## 2. Exact Receiver-Side Gap

### 2.1 Fields the sender generates but does not expose

Inside `FlashSession::open_and_send()`, the following are computed but not returned to the caller and not stored in any external structure:

| Field | Where it exists | B needs it |
|-------|-----------------|------------|
| `enc_nonce: [u8; 12]` | local variable, line ~173 `flash.rs` | Yes — required for `SessionKey::decrypt()` |
| `sender_ephemeral_pub: [u8; 32]` | inside v2 branch, line ~131 `flash.rs` | Yes — required for B to reconstruct DH |
| `ciphertext: Vec<u8>` | normalized and passed to relay, then dropped | Yes — required for decryption |
| `dh_output: [u8; 32]` | used as `ephemeral_seed` for key derivation | No — B reconstructs this from their eph_secret + sender_pub |

### 2.2 Relay does not retain payload

`relay/mesh/src/lib.rs:273`:
```rust
drop(payload); // intentionally blind
```

The relay's design is correct for its role. It is not the relay's responsibility to store content for recipients. The relay is a transport intermediary, not a mailbox.

### 2.3 What B needs to reconstruct session_key (v2 path)

B holds `eph_secret` (the private X25519 key corresponding to their published `handshake_ephemeral.pub_key`).

Given a `BurstEnvelope` containing `{ sender_ephemeral_pub, route_id, nonce, vitality_snapshot }`, B can:

1. `dh_output = x25519_dh(&eph_secret, &sender_ephemeral_pub)` — symmetric with sender
2. Construct `FlashTranscriptV2 { route_id, nonce, recipient_ops_pub: B.ops_pub, vitality_snapshot, protocol_version: 2, sender_ephemeral_pub }`
3. `transcript_hash = transcript_v2.hash()`
4. `key_material = TransportKeyMaterial { ephemeral_seed: dh_output, transcript_hash, recipient_binding: B.ops_pub }`
5. `session_key = scp_derive_key(DomainLabel::Transport, &key_material.as_bytes())`
6. `session_key.decrypt(&ciphertext, &enc_nonce)` using `scp_cryptography::keys::SessionKey::decrypt()`

**All primitives for steps 1–6 are already implemented.** `SessionKey::decrypt()` exists at `core/cryptography/src/keys.rs:102`. No new crypto decisions are required.

### 2.4 Missing decrypt / reassembly APIs

There is no:
- `BurstEnvelope` struct
- `FlashSession::receive()` or equivalent recipient-side function
- Any API on the relay or warm cache that delivers payload to B

None of these require a protocol decision. The derivation is fully specified by the existing v2 key derivation code. What is missing is the implementation of the receive side.

### 2.5 Trial 0 blocker type

The relay does not need to change. For the in-process scenario harness, the sender can directly hand the `BurstEnvelope` to B's in-process actor rather than routing through the relay's networking path. The relay's TCP path is for Layer 3 (multi-process); the harness needs only the in-process actor model.

The implementation gap does not require a new protocol decision. The spec is implied in the existing sender code: the sender knows all the fields B needs; they just aren't assembled or exposed.

---

## 3. Scenario Architecture

The harness runs in a single Tokio runtime as a Rust integration test or binary under `test/scenarios/`.

### 3.1 Three logical actors

```
┌─────────────────────────────────────────────────────────────────────┐
│  In-process scenario runner (single Tokio runtime)                   │
│                                                                       │
│  ┌─────────────┐    BurstEnvelope    ┌─────────────┐                │
│  │  Endpoint A │ ─────────────────▶ │    Relay     │                │
│  │             │                     │  (simulated) │                │
│  │ - identity  │                     │  inbox by    │                │
│  │ - ledger    │                     │  ops_pub     │                │
│  │ - eph key   │                     └──────┬───────┘                │
│  └─────────────┘                            │ retrieve(B.ops_pub)    │
│                                             ▼                        │
│                                    ┌─────────────┐                   │
│                                    │  Endpoint B │                   │
│                                    │             │                   │
│                                    │ - identity  │                   │
│                                    │ - eph_secret│                   │
│                                    │ - decrypt   │                   │
│                                    └─────────────┘                   │
└─────────────────────────────────────────────────────────────────────┘
```

### 3.2 Actor definitions

**Endpoint A**
- Holds: `GenesisArtifacts` (ops keypair), `SubstrateLedger` reference
- Role: generates payload, creates `RecipientState` from ledger, calls sender path, exposes `BurstEnvelope` to scenario relay

**ScenarioRelay** (harness-internal, not scp-relay-mesh)
- Holds: `HashMap<[u8;32], Vec<BurstEnvelope>>` keyed by recipient `ops_pub`
- Role: store-and-forward for the harness. Does not replace the real `BlindRelay`; runs alongside it for harness observability.
- For Trial 0: A deposits envelope directly here after `open_and_send`
- For Trial 2: the existing provider pool observation seam is connected here

**Endpoint B**
- Holds: `GenesisArtifacts` (ops keypair), `eph_secret: [u8; 32]`, `ReplayWindow`
- Role: retrieves envelope from `ScenarioRelay`, reconstructs session_key, decrypts, returns plaintext

### 3.3 Deterministic inputs

For Trial 0 only, jitter should be zero:
- Use `PerturbationEngine::passthrough()` (already exists)
- Use deterministic fixed payload: `b"trial-0-payload"`
- Use `BlindRelay::local()` for the actual `route_burst()` call (no TCP connection needed)
- Clock is system time; no need to override for Trial 0

### 3.4 File locations

| File | Purpose |
|------|---------|
| `test/scenarios/mod.rs` | Scenario runner harness entry |
| `test/scenarios/trial_0.rs` | Single encrypted exchange scenario |
| `test/scenarios/trial_1.rs` | Inactivity and reaffirmation (after Trial 0 passes) |
| `test/scenarios/trial_2.rs` | Provider failure injection (after Trial 0 passes) |
| `core/transport/src/corridor.rs` | `BurstEnvelope` struct + `receive()` function |

### 3.5 Cargo.toml additions

`test/Cargo.toml` already imports all workspace crates. Only the new `corridor` module in `scp-transport` needs to be wired. No new dependencies.

---

## 4. Neutral Trace Vocabulary

The scenario runner emits neutral event tokens. No user-facing labels appear in scenario output.

### 4.1 Permitted events

| Token | Meaning |
|-------|---------|
| `identity_created` | `IdentityGenesis::execute()` completed for one actor |
| `handshake_ephemeral_published` | X25519 handshake key registered in ledger |
| `tunnel_consent_registered` | Bilateral tunnel consent signed and recorded |
| `session_established` | `FlashSession::open_and_send()` returned Ok |
| `burst_deposited` | Sender deposited BurstEnvelope to ScenarioRelay |
| `burst_retrieved` | Recipient retrieved BurstEnvelope from ScenarioRelay |
| `payload_decrypted` | Recipient reconstructed session_key and decrypted payload |
| `exchange_complete` | Decrypted bytes match original plaintext |
| `inactivity_threshold_reached` | Deterministic time advance crossed vitality boundary |
| `reaffirmation_required` | VitalityState transitioned below Active |
| `reaffirmation_recorded` | Bilateral exchange brought vitality above threshold |
| `provider_observation_degraded` | ProviderPool received a failed observation |
| `telemetry_surface_captured` | OperationalTelemetrySnapshot recorded for comparison |

### 4.2 Forbidden in scenario output

The following are human-facing label candidates under the separate ARCHITECTURE_REALITY_GATE.md human validation gate. They must not appear as emitted event tokens or scenario pass/fail criteria:

`Active`, `Warm`, `Dormant`, `Suspended`, `Severed`, `Burned`

The underlying `VitalityState` enum values may appear in Rust code as type values. They must not appear in the scenario's emitted trace strings.

---

## 5. Trial Ladder

### Trial 0 — Direct In-Process Burst Decrypt Roundtrip

**Status**: PROVEN — Phase 41 implementation complete. All 6 integration tests pass (`test/tests/corridor.rs`).

**Claim permitted**: Given an envelope produced from A's real sender-side cryptographic state, B can reconstruct the same session key and decrypt the original plaintext in-process.

**Claims NOT proven by Trial 0** (and must not be asserted):
- Relay mailbox delivery — the relay drops payload after ACK by design; no delivery path to a recipient exists yet
- Relay routing metadata policy — the open question about whether a dev-harness relay may observe plaintext `recipient_ops_pub` is unresolved and remains blocked at `ARCHITECTURE_REALITY_GATE.md`
- Asynchronous transport — Trial 0 passes the envelope directly in-process; no async delivery channel is exercised
- Localhost networking — no TCP socket, no network I/O of any kind
- LAN networking — out of scope until Phase 43
- Desktop hardware readiness — no hardware was involved

**Precondition**: none.

**Steps**:
1. Create identity A via `IdentityGenesis::execute()`; emit `identity_created`
2. Create identity B via `IdentityGenesis::execute()`; emit `identity_created`
3. B generates X25519 handshake keypair `(eph_secret, eph_pub)`, signs `eph_pub` with B's ops key, publishes to shared `SubstrateLedger`; emit `handshake_ephemeral_published`
4. A registers bilateral tunnel consent with B on ledger; emit `tunnel_consent_registered`
5. A calls `FlashSession::retrieve_state(&ledger, &B.ops_pub)` — must return `RecipientState` with `handshake_ephemeral: Some(...)`
6. A calls `open_and_send_with_envelope(state, payload, cache, engine)` — calls the real sender path AND returns `BurstEnvelope`; emit `session_established`
7. A passes `BurstEnvelope` directly to B (in-process — no relay, no network); emit `burst_deposited`
8. B calls `corridor::receive(&envelope, &eph_secret)`; emit `payload_decrypted`
9. Assert decrypted bytes == original payload; emit `exchange_complete`

**Pass criterion**: steps 1–9 complete without error; plaintext matches.

**If this fails at step 8**: the exact error from `SessionKey::decrypt()` or transcript mismatch identifies the implementation gap. Trial 0 does not silently pass or skip.

### Trial 1 — Inactivity and reaffirmation

**Precondition**: Trial 0 passes.

**Steps**:
1. Complete Trial 0
2. Advance a deterministic vitality clock (wall-clock substitution in VitalityFunction, or direct score manipulation via `VitalityState::from_score()`)
3. Assert vitality state has changed to a below-Active band (internal enum value only — not emitted as label); emit `inactivity_threshold_reached`
4. Assert `vitality.is_open()` still returns true (still recoverable)
5. Simulate reaffirmation exchange (second Trial 0 exchange); emit `reaffirmation_recorded`
6. Assert vitality transitions back toward Active-equivalent score

**Note**: `VitalityFunction` (`core/vitality/src/function.rs`) must expose a deterministic time-advance path. If it only uses `SystemTime::now()`, a thin wrapper struct or injection interface is needed — this is the only likely secondary implementation task.

### Trial 2 — Provider failure injection

**Precondition**: Trial 0 passes.

**Steps**:
1. Complete Trial 0 (establishes a corridor with real session traffic)
2. Create a `ProviderPool` with N providers; connect it to the scenario so that relay burst events feed provider observations
3. Inject one of three failure scenarios via existing `ProviderPool` observation API:
   - Asymmetric silence: one provider stops responding while others continue
   - Symmetric outage: all providers fail simultaneously
   - Rotation thrash: provider pool rotates faster than observation windows can stabilize
4. Capture `OperationalTelemetrySnapshot` at each step; emit `telemetry_surface_captured`
5. Assert Surface 1 (survivor concentration) and Surface 3 (absolute availability) respond differently to symmetric vs asymmetric scenarios (already proven by provider pool tests)
6. Assert `survivor_surface_evaluable` and `liveness_surface_evaluable` guard flags are set correctly
7. Assert no automatic policy change occurs from telemetry alone — harness must not act on snapshot values

---

## 6. Implementation Verdict

**Verdict: A — TRIAL_0_DIRECT_DECRYPT_PROVEN** (Phase 41 complete)

The receive/decrypt path was fully specified by the existing v2 key derivation code. The DH is symmetric. `SessionKey::decrypt()` was already implemented. The transcript hash inputs were already structured. No new protocol decisions were required.

The implementation consisted of three additions (all complete):

### Addition 1: `BurstEnvelope` struct

**New file**: `core/transport/src/corridor.rs`

```rust
/// All fields B needs to reconstruct the session key and decrypt the payload.
pub struct BurstEnvelope {
    pub sender_ephemeral_pub: [u8; 32],
    pub route_id:             RouteId,
    pub nonce:                FreshnessNonce,
    pub vitality_snapshot:    VitalityState,
    pub ciphertext:           Vec<u8>,
    pub enc_nonce:            [u8; 12],
    pub recipient_ops_pub:    [u8; 32],
    pub protocol_version:     u8,
}
```

### Addition 2: `receive()` function

In the same `corridor.rs`, a pure function that reconstructs the session key and decrypts:

```rust
pub fn receive(
    envelope: &BurstEnvelope,
    eph_secret: &[u8; 32],
) -> Result<Vec<u8>, TransportError> { ... }
```

Implementation: steps 1–6 of §2.3 above. All primitives (`x25519_dh`, `FlashTranscriptV2`, `TransportKeyMaterial`, `scp_derive_key`, `SessionKey::decrypt`) exist today.

### Addition 3: `open_and_send_with_envelope` + `open_and_send_core` refactor

**Implemented in** `core/transport/src/flash.rs`:

- `open_and_send_core` (private) — the single sender implementation, returns `(FlashSession, Option<BurstEnvelope>)`. The v2 branch populates the envelope; the v1 branch returns `None`.
- `open_and_send` (unchanged public API) — delegates to `open_and_send_core`, drops the envelope. Existing callers and tests are unaffected.
- `open_and_send_with_envelope` (new public API) — delegates to `open_and_send_core`, returns the envelope or errors with `V1PathNotReceivable` if the v1 path was taken.

Two new `TransportError` variants added: `DecryptionFailed` and `V1PathNotReceivable`.

---

## 7. Hardware Transition Gate

**Do not install Linux or Claude Code on spare desktops during Phase 41.**

The transition sequence is:

1. **Phase 41 current**: Trial 0 passes in-process → harness is the reference trace
2. **Phase 42 (multi-process localhost)**: split Endpoint A, ScenarioRelay, Endpoint B into three processes on the same machine; use `BlindRelay::tcp()` for A→relay forwarding; relay process must be written to store-and-forward rather than drop (first real relay server)
3. **Phase 43 (LAN)**: move processes to laptop + Desktop 1 + Desktop 2; relay runs on Desktop 2; A and B run on laptop and Desktop 1; use the Phase 41 in-process trace as the reference oracle

**Only after Phase 42 localhost passes** should Desktop 1 and Desktop 2 be prepared for OS installation.

---

## 8. Do Not Modify

The following are outside Phase 41 scope and must not be changed:

- `docs/architecture/ARCHITECTURE_REALITY_GATE.md` — human vocabulary gate remains active
- `docs/architecture/CORRIDOR_*` — V1.2 human test packet is frozen
- `provider/pool/` — ProviderPool metric semantics and telemetry authority
- VitalityState enum values — used internally in implementation; not renamed
- TOLS κ integration — separate system, separate gate
- Dynamical criticality work — blocked by ARCHITECTURE_REALITY_GATE.md §7

---

## 9. Recommended First Coding Task

Given verdict A, the smallest coding task that moves Trial 0 from blocked to executable:

**Task**: Implement `core/transport/src/corridor.rs` with `BurstEnvelope` and `receive()`.

Files to create or modify:
1. Create `core/transport/src/corridor.rs` (new)
2. Add `pub mod corridor;` and `pub use corridor::{BurstEnvelope, receive};` to `core/transport/src/lib.rs`
3. Add a single integration test in `test/scenarios/trial_0.rs` (new file under `test/tests/` or `test/scenarios/`) that wires up both endpoints against a shared ledger and asserts `exchange_complete`

This is entirely additive. No existing file is broken. All existing 400+ tests remain passing.

**Estimated scope**: ~120 lines of Rust across two new files and one import line.
