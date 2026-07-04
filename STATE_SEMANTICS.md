# SCP State Semantics Classification (v0)

This document classifies every protocol artifact by its consistency semantics.
It is a prerequisite for federation, equivocation detection, and any design
involving multiple state providers. Before introducing `ProviderQuorum` or any
multi-provider abstraction, every state type here must be assigned to a class.

A "state type" is anything stored, queried, or propagated by an SCP implementation.
A "semantic class" is the consistency contract that governs that state.

---

## Semantic Class Definitions

### Monotonic

**Contract:** Once true, always true. No provider may legitimately return `false`
after having returned `true`.

**Equivocation signature:** Provider A says revoked; Provider B says not revoked.
This is a hard equivocation — one of them is wrong or lying.

**Implication for federation:** A quorum of `n` providers should return `true` if
*any* member returns true. A single revocation claim suffices. The query is `any()`,
not `majority()`.

**Why:** The security model assumes revocation is a ratchet. A single honest provider
seeing a revocation is sufficient grounds to deny transport.

---

### Snapshot-Consistent

**Contract:** State is valid at a point in time. Queries return a consistent
snapshot; subsequent changes do not retroactively invalidate the snapshot.

**Equivocation signature:** Two snapshots for the same key at the same logical
time disagree. This is a soft equivocation — replication lag is permitted, but
forking is not.

**Implication for federation:** The most recent snapshot wins, subject to a bounded
staleness window. Providers must include a `snapshot_at` timestamp. Queries use
`latest_by(snapshot_at)`.

**Why:** This is the TOCTOU semantics encoded in Phase 9. A transport session opened
from a valid snapshot is not cancelled by subsequent revocation — the snapshot is the
contract, not the current state.

---

### Soft-State

**Contract:** State has a finite validity window. It expires if not refreshed. The
absence of a value means "expired or not published," not "false."

**Equivocation signature:** Provider A has an ephemeral with `expires_at = T+100`;
Provider B has an ephemeral with `expires_at = T-1` (already expired). This is not
equivocation — it is replication lag. Resolution: take the later `expires_at`.

**Implication for federation:** Queries use `latest_valid(now)`. A provider returning
`None` (expired) does not override a provider returning `Some(valid_ephemeral)`.
Absence is weakly negative.

**Why:** Handshake ephemerals and vitality scores have natural freshness windows.
Forcing them to be Monotonic would require perpetual storage of tombstones.

---

### Bilateral

**Contract:** State is established by agreement between two specific parties and
is not meaningful outside that relationship. Neither party can unilaterally assert
it on behalf of the other.

**Equivocation signature:** Provider claims a bilateral state that requires
cryptographic consent from both parties, but only one party's signature is present.
This is always a hard equivocation.

**Implication for federation:** Bilateral state requires both parties' signatures to
be valid before any provider may propagate it. Federation does not help here —
quorum over unverified bilateral claims is meaningless.

**Why:** Recovery shards and tunnel consent are only valid when both signatories
agree. A quorum of providers asserting a bilateral state without valid dual-signature
proofs is an equivocation attack surface.

---

### Local-Only

**Contract:** State is meaningful only within a single node's runtime. It must never
be propagated, federated, or treated as evidence of anything by external parties.

**Equivocation signature:** N/A — by definition this state does not cross trust
boundaries. If it appears in a propagation path, that is a protocol violation.

**Implication for federation:** Never include in any quorum query. If a provider
attempts to serve Local-Only state to a remote query, that provider is misbehaving.

**Why:** Dummy traffic schedules, per-session nonce windows, and local perturbation
entropy are all internal implementation details. Exposing them leaks traffic analysis
surface.

---

### Consensus-Relevant

**Contract:** State must be identical across all honest providers for any given
logical time. Any disagreement is a hard fork and is evidence of byzantine behavior.

**Equivocation signature:** Two providers return different commitment hashes for
the same `ops_pub` at the same block height. This is the strongest equivocation
signal in the system.

**Implication for federation:** Queries use `all_agree()` — all `n` providers must
return the same commitment. A single disagreement should surface to the caller as
`Equivocation`. Never take majority here; the minority may be the honest node.

**Why:** State commitments are the anchor for audit proofs, zk-attestations, and
future cross-chain verification. A soft disagreement here corrupts all downstream
consumers.

---

## Protocol Artifact Classification

| Artifact | Semantic Class | Storage Layer | Propagation | Notes |
|----------|---------------|---------------|-------------|-------|
| Key revocation | **Monotonic** | Ledger | Broadcast | Any positive claim suffices; single revocation gates transport |
| Registration record | **Monotonic** | Ledger | Broadcast | Once registered, always registered; rotation is additive, not replacement |
| Vitality score | **Soft-State** | Ledger | Gossip | `expires_at` implicit in measurement; absence = stale, not dead |
| Handshake ephemeral | **Soft-State** | Ledger | On-demand | Explicit `expires_at`; `None` from one provider does not override valid `Some` from another |
| State commitment (`commitment()`) | **Consensus-Relevant** | Ledger | Block-anchored | BLAKE3 over canonical fields; all providers must agree per logical time |
| Session snapshot (RecipientState) | **Snapshot-Consistent** | In-memory (transport) | None | TOCTOU boundary; valid at initiation time; not re-checked mid-session |
| Recovery shard | **Bilateral** | Ledger | Threshold | Requires root + recovery key dual signature; quorum over unverified shards is unsafe |
| Tunnel consent hash | **Bilateral** | In-memory | Per-session | BLAKE3 over sorted `(a, b)` pubkeys; both parties must compute independently |
| Rotation nonce | **Monotonic** | Ledger | Broadcast | Prevents replay of old rotation ops; must advance |
| Replay window bitmap | **Local-Only** | In-memory (transport) | Never | Per-session nonce dedup; must never cross session boundary |
| Dummy traffic schedule | **Local-Only** | In-memory (relay) | Never | Perturbation entropy; propagation would defeat its purpose |
| Routing hints | **Soft-State** | Ledger | Gossip | Best-effort; `None` is acceptable degradation; stale hints cause relay miss, not security failure |
| Noise session state (keys, h, ck) | **Local-Only** | In-memory (transport) | Never | Derived from handshake; never persisted or propagated |

---

## Equivocation Detection Matrix

When a `ProviderQuorum` receives disagreeing responses, resolution depends on
the semantic class:

| Class | Resolution rule | Equivocation? |
|-------|----------------|---------------|
| Monotonic | `any(true)` wins | Hard if any disagrees with `any(true)` result |
| Snapshot-Consistent | `latest_by(snapshot_at)` | Soft if within staleness window; hard if forked |
| Soft-State | `latest_valid(now)` | Soft (lag); hard only if timestamps are forged |
| Bilateral | `require_dual_sig()` | Hard if sig missing or invalid; quorum doesn't help |
| Local-Only | Never queried | Hard protocol violation if a provider serves it |
| Consensus-Relevant | `all_agree()` | Hard if any provider disagrees |

---

## Implications for `ProviderQuorum` Design

A future `ProviderQuorum<P: StateProvider>` must dispatch differently per query:

```rust
// Sketch — not yet implemented
impl ProviderQuorum {
    // Monotonic: safe to gate on any() — a single honest provider seeing
    // revocation is sufficient. Never require all().
    fn is_revoked(&self, ops_pub: &[u8; 32]) -> QuorumResult<bool>;

    // Soft-State: return the most recent valid ephemeral across providers.
    // Absence from one provider does not override presence in another.
    fn get_handshake_ephemeral(
        &self,
        ops_pub: &[u8; 32],
        now: u64,
    ) -> QuorumResult<Option<PublishedHandshakeKey>>;

    // Consensus-Relevant: require agreement across all providers.
    // Surface Equivocation if any disagree.
    fn get_commitment(
        &self,
        ops_pub: &[u8; 32],
    ) -> QuorumResult<[u8; 32]>;
}

enum QuorumResult<T> {
    Agree(T),
    Equivocation(EquivocationEvidence),
    Unavailable,
}
```

The `ProviderQuorum` must never conflate semantic classes. Applying `all_agree()` to
a Soft-State query (ephemerals) would make the system unusable under replication lag.
Applying `any()` to a Consensus-Relevant query (commitments) would permit a byzantine
provider to inject a false commitment.

---

## Governance

Any new protocol artifact must be classified here before being added to any API.
Classification determines:
1. Whether the artifact may be federated
2. Which quorum rule applies
3. What constitutes equivocation
4. Whether providers may serve it to remote queries

This document is the prerequisite for `FEDERATION.md`.

Any re-classification of an existing artifact is a breaking semantic change and must
be treated with the same weight as a wire encoding change in `ENCODING.md`.
