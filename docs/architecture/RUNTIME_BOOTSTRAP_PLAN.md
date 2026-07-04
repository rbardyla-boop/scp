# SCP Runtime Bootstrap Plan

**Status**: AUTHORIZED — scope gate verdict A recorded; see Section 6.
**Constraint**: No user-facing vitality labels. Machine-event language only.
**Does not touch**: Version 1.2 human-test packet, provider pool simulator, user-facing UI.

---

## 1. Receiver-Side Decrypt Gap

### 1.1 What the sender already does (existing code)

`FlashSession::open_and_send()` in `core/transport/src/flash.rs`:

1. Derives a session key via one of two paths:
   - **v2 (bilateral DH)**: `session_key = scp_derive_key(Transport, dh_output || transcript_v2_hash || recipient_ops_pub)` where `dh_output = X25519(sender_ephemeral_secret, recipient_handshake_pub)`.
   - **v1 (OsRng seed)**: `session_key = scp_derive_key(Transport, ose_seed || transcript_v1_hash || recipient_ops_pub)` — seed is never transmitted.
2. Encrypts: `(ciphertext, enc_nonce) = ChaCha20Poly1305(session_key).encrypt(payload)`
3. **Discards** `enc_nonce`: `let (ciphertext, _enc_nonce) = crypto_sk.encrypt(payload);`
4. Sends `normalized(ciphertext)` through the relay.

**The relay receives opaque bytes and drops them**: both `spawn_relay_listener()` and `handle_noise_connection()` explicitly discard the inner payload.

### 1.2 What the receiver needs to decrypt

For v2 bilateral DH, the receiver can reconstruct the session key:

```
recipient_dh_output = X25519(recipient_handshake_priv, sender_ephemeral_pub)
# This equals sender's dh_output because DH is commutative.

transcript_v2_hash = scp_derive_key(Transcript, transcript_v2_bytes(
    route_id, freshness_nonce, recipient_ops_pub,
    vitality_byte, protocol_version=2, sender_ephemeral_pub
))

session_key = scp_derive_key(Transport,
    recipient_dh_output || transcript_v2_hash || recipient_ops_pub
)
```

Then: `plaintext = ChaCha20Poly1305(session_key).decrypt(ciphertext, enc_nonce)`

The receiver needs all of these fields — none are currently transmitted.

### 1.3 What is missing from the wire payload

| Field | Size | Currently transmitted? | Needed by receiver |
|-------|------|------------------------|--------------------|
| `sender_ephemeral_pub` | 32 bytes | No | Yes — for DH |
| `route_id` | 16 bytes | No | Yes — for transcript |
| `freshness_nonce` | 8 bytes | No | Yes — for transcript |
| `vitality_byte` | 1 byte | No | Yes — for transcript |
| `protocol_version` | 1 byte | No | Yes — for transcript |
| `enc_nonce` | 12 bytes | **No (discarded)** | Yes — for decrypt |
| `ciphertext` | variable | Yes (padded) | Yes |

**Total per-burst overhead**: 70 bytes (fixed) + padded ciphertext.

### 1.4 v1 path status

The v1 fallback uses `OsRng.fill_bytes(&mut seed)`. The seed is generated locally and never transmitted — it is structurally impossible for a recipient to recover it without a separate out-of-band channel. **The v1 path is incompatible with asynchronous multi-process delivery and must be disabled in the dev harness.** All dev-harness endpoints must publish a handshake ephemeral to the ledger before sending.

This is not a new constraint — the v1 path was always described as a fallback for in-process or warm-cache scenarios. For cross-process exchange it has never been viable.

### 1.5 Proposed receiver-decrypt implementation

A new function (no protocol decision required for v2 path):

```rust
// In core/transport/src/flash.rs or a new core/transport/src/receive.rs

pub struct DevHarnessBurst {
    pub sender_ephemeral_pub: [u8; 32],
    pub route_id:             RouteId,
    pub freshness_nonce:      FreshnessNonce,
    pub vitality_byte:        u8,
    pub protocol_version:     u8,
    pub enc_nonce:             [u8; 12],
    pub ciphertext:            Vec<u8>,
}

pub fn receive_and_decrypt(
    recipient_handshake_priv: &[u8; 32],
    recipient_ops_pub:        &[u8; 32],
    burst:                    &DevHarnessBurst,
) -> Result<Vec<u8>, TransportError> {
    if burst.protocol_version != 2 {
        return Err(TransportError::V1PathNotSupported);
    }

    let dh_output = x25519_dh(recipient_handshake_priv, &burst.sender_ephemeral_pub);

    let transcript = FlashTranscriptV2 {
        route_id:             burst.route_id.clone(),
        nonce:                burst.freshness_nonce.clone(),
        recipient_ops_pub:    *recipient_ops_pub,
        vitality_snapshot:    vitality_from_byte(burst.vitality_byte)?,
        protocol_version:     2,
        sender_ephemeral_pub: burst.sender_ephemeral_pub,
    };
    let transcript_hash = transcript.hash();

    let key_material = TransportKeyMaterial {
        ephemeral_seed:    dh_output,
        transcript_hash,
        recipient_binding: *recipient_ops_pub,
    };

    let session_key = SessionKey(scp_derive_key(DomainLabel::Transport, &key_material.as_bytes()));
    let crypto_sk = CryptoSessionKey(session_key.0);
    crypto_sk.decrypt(&burst.ciphertext, &burst.enc_nonce)
        .map_err(|_| TransportError::DecryptionFailed)
}
```

No new protocol decisions required. The session key derivation path is already fully specified. This is a receive-side mirror of the existing send path.

**Sender changes required**: `open_and_send()` must retain `enc_nonce` and serialize all `DevHarnessBurst` fields into the transmitted payload. Currently `_enc_nonce` is discarded — that must change.

---

## 2. Identity Persistence

### 2.1 What genesis produces

`IdentityGenesis::execute()` returns `GenesisArtifacts` containing:
- `k_root_pub`, `k_root_priv` (Ed25519)
- `k_ops_pub`, `k_ops_priv` (Ed25519)
- `recovery_policy_hash`, `continuity_commitment`

`GenesisArtifacts` is `Zeroize` + `Drop` — it is wiped from memory when dropped. There is no filesystem persistence today.

### 2.2 Dev-harness format

For the dev harness, persist to a directory (e.g. `~/.scp-dev/<identity-name>/`):

```
identity.json        — public fields only (safe to share)
ops.key              — ops private key (32 bytes, mode 0600)
root.key             — root private key (32 bytes, mode 0600)
handshake.key        — current X25519 handshake private key (32 bytes, mode 0600)
```

`identity.json` schema:
```json
{
  "k_root_pub": "<hex>",
  "k_ops_pub": "<hex>",
  "recovery_policy_hash": "<hex>",
  "continuity_commitment": "<hex>",
  "handshake_pub": "<hex>",
  "handshake_expires_at": <unix_seconds>
}
```

**Security caveats (must be stated in CLI output on creation)**:
- This is a development identity. Root and ops private keys are stored unencrypted on disk.
- Do not use this format for any real communication. A production identity requires hardware enclave storage for root keys.
- Restrict key file permissions to owner-read-only (0600). The CLI must enforce this at creation.

**No keychain integration, no passphrase encryption, no HSM claims.** The dev harness is explicitly a Level 1/2 proof, not a production keystore.

### 2.3 Handshake ephemeral rotation

A handshake ephemeral is an X25519 keypair separate from the ops keypair. It is signed by the ops key and published to the ledger with a TTL.

For the dev harness:
- Generate one handshake ephemeral at identity creation. TTL: 24 hours.
- Sign with ops key and publish to ledger.
- `receive` CLI uses `handshake.key` to decrypt received bursts.
- Rotation is manual for the dev harness: `scp-dev keygen --rotate-handshake`.

---

## 3. Relay Daemon

### 3.1 Current relay behavior

Both `spawn_relay_listener()` (TCP) and `spawn_noise_relay_listener()` (Noise XX) accept bursts and **drop the inner payload**:

```rust
drop(payload); // intentionally blind
// and:
let _ = &plain[..plen]; // Intentionally blind: payload is decrypted to verify integrity, then dropped.
```

The relay sends an ACK and discards. There is no mailbox, no recipient routing, no queuing.

### 3.2 The relay blindness question — DECIDED

The spec says relays are "blind" AND responsible for "Temporary encrypted packet retention." These are compatible only if the relay can route without reading the inner payload.

**REJECTED — Plaintext `recipient_ops_pub` routing header (Option A)**:
Wrapping each burst with an unencrypted `recipient_ops_pub` field creates a stable identity metadata graph at the relay. Every burst delivery links sender timing to a public identity key. This violates SCP's core purpose even in a dev harness, because the linking metadata is structurally present and would persist if any relay log were retained.

**APPROVED — Harness-only opaque `DevMailboxId` (Option B-dev)**:
The receiver generates a `DevMailboxId`: a random 32-byte token **not derived from any identity key, session key, or payload content**. The receiver shares this token with the sender out-of-band (printed to stdout by `scp-dev mailbox-new`, pasted to the sender). The relay stores `{DevMailboxId → [inner_bursts]}` and sees only an opaque byte string. It cannot link the token to any identity.

Wire protocol (decided):
```
Store cmd  → [1 = 0x01][32 mailbox_id][4 len LE][N DevHarnessBurst CBOR]
             ← [1 ack = 0x00]

Poll cmd   → [1 = 0x02][32 mailbox_id]
             ← [4 count LE][for each burst: [4 len LE][N DevHarnessBurst CBOR]]
```

**Accepted limitation**: the relay can correlate multiple bursts routed to the same token during the token's lifetime, and an adversary who observes both the relay and the out-of-band token exchange could link bursts to parties. This is explicitly documented as a dev-harness shortcut. A production relay uses a cryptographic blind-token scheme derived from a sender–receiver key agreement; that is out of scope for this sprint.

**Accepted limitation recorded**: the relay learns the existence of a mailbox token and can observe burst timing, count, and approximate size per token. It does not learn sender or recipient identity, payload content, or session keys.

### 3.3 Minimal relay daemon design

A standalone binary `scp-relay` that:
1. Binds on a configurable TCP address (default `0.0.0.0:7700`).
2. Accepts a store command with a `DevMailboxId` + serialized `DevHarnessBurst` from a sender.
3. Stores bursts in a per-token in-memory mailbox (max 100 bursts per token, oldest evicted on overflow).
4. Accepts a poll command from a recipient: recipient sends their `DevMailboxId` token.
5. Returns and clears all queued bursts for that token.
6. Logs `relay_listening`, `burst_forwarded`, `mailbox_drained` to stdout (no identity fields).

**Mailbox access**: any process holding the `DevMailboxId` token may drain that mailbox. There is no cryptographic authentication of the poller — the token itself is the capability. This is sufficient for Level 1/2 where token confidentiality is enforced by out-of-band sharing between the two parties.

**No Noise encryption required for Level 1** (localhost). The existing `BlindRelay::tcp()` path and `spawn_relay_listener()` can be extended, or a new standalone daemon can be written without modifying the existing relay library.

**Noise XX** (`BlindRelay::noise()` + `spawn_noise_relay_listener()`) should be used for Level 2 (LAN deployment) to protect bursts in transit from relay to endpoint. The mailbox model is unchanged.

### 3.4 Can the current relay be extended without architecture changes?

Yes. `spawn_relay_listener()` already reads the full burst. The minimal change is:
- Parse the routing header (32-byte ops_pub prefix)
- Store in a mailbox HashMap instead of `drop(payload)`
- Add a second TCP listener or multiplexed command for mailbox poll

No changes to `BlindRelay`, `route_burst()`, or `PerturbationEngine`. The relay mailbox is a new standalone binary `scp-relay`, not a change to the library.

---

## 4. Endpoint CLI

### 4.1 Minimal command set

All output is machine-readable (JSON or structured log lines). No vitality label output.

```
scp-dev keygen [--identity <name>] [--out-dir <path>]
  → generates genesis, persists to disk, publishes handshake ephemeral to ledger
  → stdout: { "event": "identity_created", "ops_pub": "<hex>", "handshake_pub": "<hex>" }

scp-dev public-key [--identity <name>]
  → stdout: { "ops_pub": "<hex>", "handshake_pub": "<hex>", "handshake_expires_at": <ts> }

scp-dev mailbox-new [--relay <host:port>]
  → generates a random 32-byte DevMailboxId, registers with relay
  → stdout: { "event": "mailbox_created", "mailbox_id": "<hex>" }
  → operator copies this token and shares with sender out-of-band

scp-dev send --mailbox <mailbox_id_hex> --to <recipient_handshake_pub_hex>
             --relay <host:port> --payload <text|@file> [--identity <name>]
  → looks up recipient handshake ephemeral from relay-hosted ledger
  → performs full open_and_send() flow; serializes DevHarnessBurst; stores at relay
  → stdout: { "event": "burst_forwarded", "route_id": "<hex>", "mailbox_id": "<hex>" }

scp-dev receive --mailbox <mailbox_id_hex> --relay <host:port> [--identity <name>]
  → polls relay mailbox by token, decrypts each DevHarnessBurst
  → stdout (one line per message):
    { "event": "payload_received", "route_id": "<hex>", "plaintext": "<text>" }
  → on decrypt failure:
    { "event": "decrypt_failed", "route_id": "<hex>", "reason": "..." }
```

No `Active`, `Warm`, `Dormant`, `Suspended`, `Severed`, or `Burned` in any output.

### 4.2 Ledger management (dev harness)

For Level 1/2, the ledger is a local in-memory `SubstrateLedger` instance shared between processes via a lightweight relay-hosted endpoint, or serialized to disk between invocations.

Simplest Level 1 approach: relay process also hosts the ledger in memory. Both sender and receiver connect to the relay to register identities and publish handshake ephemerals. This is a dev convenience — not a production architecture claim.

### 4.3 What the CLI must NOT do

- Output `Active`, `Warm`, `Dormant`, `Suspended`, `Severed`, or `Burned`.
- Claim or imply messages were "sent securely" or that the corridor is "trusted."
- Store or display any message history.
- Require or suggest installation steps beyond `cargo build`.

---

## 5. Proof Ladder

### Level 0 — Existing workspace tests remain green

```bash
cd scp && cargo test --workspace
```

All tests must pass before and after each step. No regressions permitted.

### Level 1 — Multi-process localhost exchange

Three processes on one machine:

```
Process 1: scp-relay --bind 127.0.0.1:7700
Process 2: scp-dev keygen --identity alice
           scp-dev send --to <bob_ops_pub> --relay 127.0.0.1:7700 --payload "hello"
Process 3: scp-dev keygen --identity bob
           scp-dev receive --relay 127.0.0.1:7700 --identity bob
```

**Pass condition**: Process 3 stdout contains:
```json
{"event":"payload_received","route_id":"...","plaintext":"hello"}
```

And `cargo test --workspace` still passes.

This earns: `LEVEL_1_LOCALHOST_MULTI_PROCESS_EXCHANGE_PROVEN`

### Level 2 — Clean LAN deployment

Three machines:

| Machine | Role | OS requirement |
|---------|------|----------------|
| Laptop (dev) | Endpoint A + build controller | Current dev OS |
| Desktop 1 | Endpoint B | Fresh Linux + Rust toolchain |
| Desktop 2 | Relay daemon | Fresh Linux + Rust toolchain |

Desktop requirements: Linux, Rust stable toolchain, cloned SCP repo, `cargo build --release`.

**Pass condition**: Laptop successfully exchanges plaintext "hello" with Desktop 1 through relay on Desktop 2. All three machines confirm via log output.

This earns: `B — RUNNABLE_DEV_HARNESS_EXISTS_NOT_DISTRIBUTABLE`

**Do not install Claude Code on Desktops 1 or 2.** They exist to test whether SCP can be deployed by following documented build instructions.

### Level 3 — Packaged install

Out of scope for this sprint.

---

## 6. Scope Gate

**Before writing any implementation code, this verdict must be recorded and approved.**

### Findings

**Finding 1 — enc_nonce discard**
`core/transport/src/flash.rs` line ~173: `let (ciphertext, _enc_nonce) = crypto_sk.encrypt(payload);`
The 12-byte ChaCha20-Poly1305 nonce is discarded. The receiver cannot decrypt without it.
**Fix**: retain `enc_nonce` and include it in `DevHarnessBurst`.
This is a sender-side implementation stub fix, not a new protocol decision.

**Finding 2 — Wire payload missing receiver fields**
The transmitted payload contains only the padded ciphertext. The sender's ephemeral pub,
route_id, freshness_nonce, vitality_byte, and protocol_version are computed locally but not serialized into the wire payload. The receiver cannot reconstruct the session key without them.
**Fix**: serialize `DevHarnessBurst` (see Section 1.5) as the transmitted payload.
This requires a new struct but no new protocol cryptographic decisions — the key derivation is already fully specified in `FlashTranscriptV2`.

**Finding 3 — Relay drops all inner payloads**
Current relay behavior is intentionally "drop payload." A store-and-forward relay requires
a delivery model decision: what addressing information may the relay see?
**Decided**: harness-only opaque `DevMailboxId` — random 32-byte token, not derived from
identity. See Section 3.2. Plaintext `recipient_ops_pub` routing header was explicitly
rejected because it creates a stable identity metadata graph at the relay.

**Finding 4 — v1 path incompatibility**
v1 OsRng seed cannot be recovered by a recipient. v1 must be disabled for dev-harness send.
**Fix**: require published handshake ephemeral; error if none found.
This is a dev-harness constraint, not a protocol change.

### Verdict

```
A — TRIAL_0_IMPLEMENTATION_AUTHORIZED_WITH_HARNESS_ONLY_OPAQUE_MAILBOX_ROUTING
```

**Reason**: Finding 3 (relay delivery model) has been decided. Plaintext `recipient_ops_pub`
routing was rejected; harness-only opaque `DevMailboxId` was approved (see Section 3.2).
Findings 1, 2, and 4 are implementation stub fixes with no remaining protocol decisions.
Trial 0 implementation is fully authorized.

**Accepted production gap**: `DevMailboxId` is a dev-harness shortcut. Production relay
addressing uses a cryptographic blind-token scheme derived from a sender–receiver key
agreement. That design is out of scope for this sprint.

**Scope of authorization**: headless two-endpoint exchange. Two endpoint identities,
temporary opaque mailbox routing token, encrypted fixed payload, relay delivery of opaque
burst, recipient retrieval and decryption, vocabulary-neutral trace events only.

---

## 7. Files to Create or Modify

### New files

| File | Purpose |
|------|---------|
| `core/transport/src/harness.rs` | `DevMailboxId`, `DevHarnessBurst`, `send_harness()`, `receive_harness()`, `HarnessError` |
| `relay/daemon/src/main.rs` | `scp-relay` standalone binary (new crate) |
| `cli/endpoint/src/main.rs` | `scp-dev` CLI binary (new crate) |

### Modified files

| File | Change |
|------|--------|
| `core/transport/src/flash.rs` | Retain `enc_nonce`; serialize `DevHarnessBurst` into wire payload |
| `Cargo.toml` | Add `relay/daemon` and `cli/endpoint` workspace members |

### Not modified

- `provider/pool/` — no changes
- `test/tests/sim.rs` — no changes
- Human-test packet (`CORRIDOR_*.md`) — no changes
- `ARCHITECTURE_REALITY_GATE.md` §1–10 — no changes (§11 already added)

---

## 8. Implementation Order (after scope gate approval)

| Step | File | What it adds |
|------|------|-------------|
| 1 | `core/transport/src/harness.rs` | `DevMailboxId`, `DevHarnessBurst`, `send_harness()`, `receive_harness()`, `HarnessError` |
| 2 | `core/transport/src/flash.rs` | Retain `enc_nonce`; populate `DevHarnessBurst`; disable v1 path for harness |
| 3 | `core/transport/src/lib.rs` | Export `harness` module |
| 4 | Unit tests for steps 1–3 | Level 0 verification; existing tests must remain green |
| 5 | `relay/daemon/src/main.rs` | TCP relay with opaque mailbox (DevMailboxId store + poll) |
| 6 | `Cargo.toml` (workspace) | Add `relay/daemon`, `cli/endpoint`; add `serde_cbor`, `clap` |
| 7 | `cli/endpoint/src/main.rs` | `keygen`, `public-key`, `mailbox-new`, `send`, `receive` |
| 8 | Localhost integration test | Level 1 proof |
| 9 | Desktop LAN deployment | Level 2 proof |

Do not proceed to step 5 before step 4 (unit tests) passes.
Do not proceed to step 8 before step 7 (Level 1) passes.

---

## 9. Trial 0 Harness Limitations (mandatory disclosure)

The following properties hold for the dev harness mailbox model. None are bugs.
All must be stated explicitly. No production delivery security claim is made from Trial 0.

### Mailbox token possession is the authorization

Whoever holds the `DevMailboxId` token may drain that mailbox. There is no
cryptographic authentication of the poller — token possession is the capability.
This is intentional for Level 0/1: token confidentiality is enforced by the
out-of-band channel used to share the token between A and B.

A production relay uses a blind-token scheme derived from a sender–receiver key
agreement so neither sender nor relay can impersonate the recipient. That design
is out of scope for this sprint.

### Relay can link bursts using the same token

During the lifetime of a `DevMailboxId` token, the relay can observe that multiple
bursts arrived for the same token and can measure their timing, count, and approximate
size. It cannot link this to any identity (no ops_pub, no session key is ever routed
to the relay), but token-level correlation is possible.

### Mailbox injection is not guarded

Any process knowing the `DevMailboxId` token may store arbitrary bytes into that
mailbox. Injection resistance requires recipient-side burst authentication beyond
the AEAD tag. This is not implemented in Trial 0.

### Explicitly out of scope for Trial 0

- Mailbox authentication (cryptographic proof of sender identity)
- Injection resistance beyond AEAD tag
- Relay-side burst authentication
- Discovery (how A learns B's mailbox token)
- Key persistence on disk
- Handshake ephemeral rotation
- Multi-process or TCP delivery (Level 1 is next)
- Production metadata-resistant addressing
