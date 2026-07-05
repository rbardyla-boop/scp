# SCP as an Agent-Communication Substrate — Fork Record

**Status**: Entered planning fork. Logged 2026-07-05. No agent-substrate code
has been authorized or written yet.
**Decision**: Build the private fleet-agent bus path before the human Corridor
Preview, while keeping the same dev-harness honesty line.
**Deployment authorization**: Not granted. Same dev-harness honesty line as all SCP planning.

This is a decision record and scope guard. It exists so a genuinely promising
direction is not lost, without pretending SCP is already an agent protocol.

## The idea (one line)

Use SCP's corridor as a **private-by-default message bus between AI agents** — agent-to-agent
messaging where the *communication graph* (who talks to whom) is hidden, for parties who want
to collaborate across trust boundaries.

## Why it may be a better first user than the human messenger

The manual key / card / token / relay mechanics that make a *consumer messenger* hard —
QR pairing, plain-language UI, accountless human discovery — are **just an API to an agent.**
Agents tolerate developer-grade plumbing that humans reject. An agent-facing SDK therefore
skips the hardest UX gaps in `CONSUMER_FACING_PRODUCT_PLAN.md`.

## What SCP already gives this fork

- Async token-mailbox = a natural agent inbox (agents go offline; store-and-forward fits).
  Proven across the 3-machine mesh.
- Keypair identity + signed cards = agent identity with no platform account.
- Blind relay + exposure metrics = the differentiator: agents talking without exposing the
  comms graph. Almost nothing in the agent-comms space does this.
- Multi-relay replicate/poll = no single relay can drop or suppress a live message.

## What it needs before it is more than "agents using the dev harness"

Honest gap list (must NOT be hand-waved):
- **Durable relay** — opt-in `scp-relay --store-dir PATH` now survives restart
  and no longer writes raw mailbox tokens as filenames. Still open: TTL/expiry,
  global storage bounds, at-most-once delivery on crash-during-send, and
  queue existence/size/mtime metadata at rest.
- **Message schemas** — SCP moves opaque bytes. "Communicate / task-share" needs an
  application protocol on top (task/RPC/capability semantics). SCP is the private pipe *under*
  something like A2A/MCP, not a replacement for them.
- **Discovery** — agents cannot find each other; only manual card exchange today.
- **Key storage** — plaintext dev key files; needs a keystore.
- **Internet transport** — LAN/Tailscale only; "anyone can join over the internet" needs
  NAT/transport work.
- **Open-membership abuse** — Sybil/spam defense beyond the existing Ed25519 admission challenge.

**Out of scope entirely:** "inference sharing" is federated *compute* (routing inference to
GPUs, accounting, verifying results). SCP has none of that. It could *carry* the request/response
messages; it does not *do* the compute-sharing. Do not conflate the two.

## Differentiator and honest demand caveat

Differentiator: **private-by-default messaging between agents owned by different parties**
(hidden communication graph across trust boundaries). Rhymes with the field-team vector — the
agents are the "team." Caveat: **demand is unproven.** Most people building agent systems today
do not (yet) care about hiding the comms graph. Niche, genuinely novel, speculative pull.

## Shared foundation already shipped

Milestone A (trace format + Exposure Meter + relay-status replay) is needed by **both** forks:
- Human-facing: the operator Console needs it.
- Agent-facing: an agent bus needs the same observability/trace surface.

Milestone A is shipped. The durable-relay gut-check is also shipped as an opt-in
dev-harness capability. The next work is no longer abstract foundation; it is
the smallest authenticated agent-envelope experiment.

## Revisit trigger

After Milestone A shipped, the Milestone B decision became a small fork in the road:
- **B-human**: Local human Corridor Preview (per `CONSUMER_FACING_PRODUCT_PLAN.md`), or
- **B-agent**: a private fleet-agent bus preview (SCP as the message bus between the operator's
  own 3-machine fleet agents — a real dogfood workload; honest caveat: the fleet already uses
  SSH+HTTP as its bus, so this earns its place only if the hidden-graph property matters or as
  a way to battle-test SCP with real traffic).

Operator chose **B-agent first** on 2026-07-05.

## Do-not-do-yet

Do not build discovery, an open network, an SDK, inference sharing, or a generic
agent protocol. The only authorized shape is the smallest private fleet-bus
slice: one authenticated envelope over the existing corridor, then one real
dogfood task if the envelope proves clean.

---

## FORK ENTERED — 2026-07-05

Operator chose **private fleet-agent bus FIRST**, then human Corridor Preview. Rationale: dogfood
the real corridor with controlled traffic; avoid the human-UX swamp; expose whether durable relay,
message semantics, and operator telemetry hold under actual use.

**Honesty framing:** this is *dogfooding SCP with a real workload* — NOT a claim that SCP is the
best fleet bus. For pure fleet messaging the already-planned file-inbox-over-Syncthing bus is
simpler. SCP earns it here as (a) a real test workload and (b) validation of the hidden-comms-graph
property. Say that plainly; don't pretend SCP beats the file-inbox for generic messaging.

### First slice — tiny authenticated agent message envelope

Minimum v0 fields:

- `schema_version`
- `task_id` — idempotency key
- `kind`
- `from` — sender public card or sender ops public key plus card reference
- `reply_to` — explicit reply mailbox/relay address, not just a task id
- `created_at`
- `ttl` — receiver-enforced until relay TTL exists
- `body`
- `sig` — sender signature over the canonical envelope fields except `sig`

No discovery, no open network, no inference marketplace. Two fleet agents send
one durable async work message through the corridor.

### Pre-build design review (catch now, cheap)

- **SHARPEST GAP — no sender authentication.** The current CLI send path (`cmd_send` →
  `send_harness_direct`, `cli/endpoint/src/main.rs`) encrypts *to* the recipient but does NOT
  authenticate the *sender* (`_identity` is loaded but unused for signing). For a *work* bus
  (messages that trigger actions), anyone holding B's mailbox token + card can inject a task B
  can't distinguish from A's. FIX: add `from` (sender ops_pub/card) + `sig` (signature over the
  canonical envelope), verified against A's known card — OR use SCP's authenticated corridor path
  instead of the harness shortcut. Bonus: `from` is also required to *reply* (you need the sender's
  card to encrypt a reply), so `reply_to` alone is insufficient anyway.
- **`ttl` is advisory, not relay-enforced.** Durable relay has no TTL (open list). The *receiving
  agent* must enforce ttl; an unpolled message otherwise sits until depth-eviction. Don't imply the
  relay expires it.
- **`reply_to` implies a mailbox-management model** — must be a real address (relay + mailbox), and
  the replier needs the sender's card. This is the start of a small session/mailbox lifecycle
  (who allocates reply mailboxes, their TTL). Name it, don't hand-wave.
- **Nits:** add `schema_version` (evolvability); treat `task_id` as the idempotency key (replicated
  relays can deliver a burst more than once — deduped after AEAD at transport, but app should dedup
  on task_id too).
- **Honesty-positive:** all envelope fields live INSIDE the encrypted burst body → NOT relay-visible.
  The envelope adds no new relay-observable metadata. Consistent with the honesty line.

### Scope discipline for slice 1

Envelope type + a thin send/receive adapter proving ONE durable async work message flows
agent → durable-relay → agent between two fleet nodes. Wiring it to real agent tasks (so it's a
workload, not another demo) is the immediate follow-on, NOT slice 1.

### Slice 1 done when

- The envelope is signed by the sender and verified by the receiver before any
  work action is considered.
- The sender card/public key needed for replies is available inside the
  decrypted envelope or through a pinned local card.
- Expired envelopes are rejected by the receiving agent.
- Duplicate `task_id` values are idempotent at the receiver.
- Relay-visible bytes remain opaque bursts; envelope fields do not appear in
  relay logs, durable filenames, or trace telemetry.
