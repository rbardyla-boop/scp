# SCP Product Wedge — the "Corridor Console"

**Status**: Design artifact only. Not an implementation authorization, not a production claim.
**Date**: 2026-07-05
**Mode**: Builder (showcase-first), upgraded with startup awareness — a *bridge* toward the field-team vector in `docs/PRODUCT_VECTOR_SCALE_POSTMORTEM.md`.
**Method**: YC office-hours skill + two grounding subagents (capability inventory over the real code; divergent wedge generation).

---

## Problem

We have a genuinely differentiated secure-corridor system that just proved a real 3-node
relay exchange over a Tailscale mesh (verdict A, 546 tests, build gate green) — but it is a
**dev harness with no public face**. The operator's question: *how do we show off this
system's power to the general public and peak interest, with a wedge that's easy to try,
without lying about what's production-ready?*

Sharpened by the diagnostic: the honest tension is that "usable product for the general
public" pulls toward a **messenger** (which collides with the hard gaps), while what is
actually **real, demoable, and honest today** is an **instrument** — a live view of the
system's own behavior. The chosen resolution is a **bridge**: build the instrument now as
the public hook, and architect it as the operator console the real product will need anyway.

## Evidence

**What's real (verified against code, not doc comments — see capability inventory):**
- `provider/pool` + `provider/delivery` are the genuine differentiator: real, tested
  entropy/κ/exposure/reputation math, and **real multi-relay failover over real TCP**
  (`DeliveryPool`, `RelayEndpoint::attempt_store/poll`). Failover is **HIGH demo-ability**.
- The proven 3-node corridor (laptop → blind relay → receiver) over Tailscale, re-run
  2026-07-05 with current binaries. All 9 evidence items passed.
- Solid table-stakes: X25519/Ed25519/ChaCha20-Poly1305/BLAKE3, replay window, Noise_XX
  relay hop (real via `snow`), wire-format versioning with golden vectors.

**Demand evidence: thin and honest about it.** This is an *interest-generation* wedge, not
a validated-demand product. There are no users building workflows around this yet. The
wedge's job is to convert the one genuinely novel asset — a *measurable* "how observable am
I" number plus visible suppression-resistance — into a "whoa" that produces inbound
curiosity. That interest is a hypothesis to test, not established demand.

**What is NOT real (must never be claimed publicly — these break the honesty line):**
- **Guardian/social recovery `todo!()` — panics.** Identity does *not* survive total device
  loss today; only controlled key rotation (root key must survive).
- **Vitality is not wired into production** — the live send path hardcodes `Active`
  ("Phase 9"); Severed/Burned states are never programmatically triggered. It's a
  designed, unit-tested *concept*, not live behavior.
- **Ledger is an in-memory mock** duplicated under two chain names — not "blockchain-backed."
- **No post-quantum code** (enum stub). **No QUIC** anywhere.

## Premises (agreed / adjusted)

1. **Honesty label on every surface** — AGREED. Every public surface carries
   "dev-harness; measures relay diversity — not a real-world anonymity guarantee." The
   integrity of the whole wedge depends on this line.
2. ~~Sell legibility, not protection~~ — ADJUSTED. Operator declined to be boxed into
   legibility-only. Resolution: legibility is what we *show now*; the bridge keeps a path
   to a protective, usable product **without pretending the gaps are closed today**.
3. ~~Instrument, not a messenger~~ — ADJUSTED. Operator declined "just a dashboard."
   Resolution: ship the instrument now, but architect it as the **operator console** of the
   real corridor product (which the postmortem's "Initial Product Shape" already lists as
   "operator telemetry that reports health without exposing identity graphs"). Instrument
   now → product component later, same artifact.

## Alternatives considered

| | Approach | Effort | Risk | Reuses | Defers |
|---|---|---|---|---|---|
| A | **Instrument showcase only** — live exposure meter + kill-a-relay failover, read-only over real metrics | S–M | Low | Everything real; builds nothing in core | ALL productization (rejected: it's the "just a dashboard" the operator unchecked) |
| B | **Usable corridor product** — installable 2-person corridor for non-experts | L–XL | Med–High | transport/CLI/relay | metadata resistance, audit, Internet/NAT (rejected now: honesty ice is thinnest here) |
| **C** ✅ | **Bridge** — ship A now as the public hook AND the operator console for B, with a named gap-closing backlog queued behind it | M now + roadmap | Low now | all of A's real code, on the B trajectory | gap-closing is *sequenced and labeled*, not faked |

**RECOMMENDATION: C (Bridge)** — chosen. It delivers a public "whoa" in days-to-weeks over
real code, keeps "usable product" honestly in scope, and every deferred gap is queued as
explicit work rather than pretended solved.

## Recommended approach — the "Corridor Console"

A live console driving the already-proven corridor, with a zero-install explainer as its
top-of-funnel. Three panels, in honesty-priority order:

- **Panel 1 — Exposure Meter (flagship).** Renders the REAL `provider/pool` signals as live
  dials: selection entropy, κ convergence pressure, exposure estimate,
  `membership_confidence_after(n)`, per-relay reputation/liveness. A scripted scenario
  concentrates traffic onto one relay (needle spikes) then diversifies (needle relaxes).
  *This is the novel asset nobody else shows: a speedometer for your own observability.*
- **Panel 2 — Suppression-resistance drama.** N blind relays, replicate-store; a "kill
  relay" control; watch failover deliver anyway and the liveness/reputation signals react.
  Scoped claim: *"no single relay can suppress a **live** message"* — NOT durable delivery
  (relay is ephemeral; restart = loss).
- **Panel 3 — Identity continuity (second-tier, labeled "designed concept").** Controlled
  key rotation; the relationship survives. Explicitly **not** device-loss (recovery is a
  stub). Optional for v1.

**Distribution (the zero-install funnel):** a self-contained web explainer ("Metadata
X-Ray") with canned traces + real GIFs captured from a live run, so the idea reaches people
who will never run a binary. Funnel: explainer/GIF (curiosity, zero install) → run-it-yourself
Console (the "whoa") → identity-continuity demo ("and it's a real system").

**Why this is the bridge, not a toy:** Panels 1–2 read the exact telemetry a real operator
of the field-team product needs ("health without exposing identity graphs"). Building the
Console *is* building that product component. No wasted motion.

## Distribution: GitHub Pages

GitHub Pages is the natural home for the zero-install layer of this wedge, but
only for that layer. Pages is static hosting: no backend, no running relay, no
real TCP. It must therefore host the explainer/replay funnel, not a live
corridor.

### Static Demo Tiers

| Tier | Demo | Claim boundary | Status |
|------|------|----------------|--------|
| 1 | **Recorded showcase**: "Metadata X-Ray" page with the relay-kill GIF, run excerpts, and honesty banner | Real captured run, not live network | Immediate Pages artifact |
| 2 | **Interactive replay**: client-side TS replays real JSON traces and animates the Exposure Meter / relay-failure scenario | Interactive replay of captured traces, not synthetic anonymity proof | Sweet spot after metrics-egress exists |
| 3 | **Pure-metrics WASM**: compile only the provider/pool math path to WASM and feed it scripted scenarios | Real Rust math in-browser; transport still simulated | Defer until appetite exists |

Tier 2 is the bridge target. The Pages demo and the real operator Console should
share one trace contract emitted by the metrics-egress surface in §Implied Tasks.
That avoids building a throwaway visualization: the static replay consumes the
same aggregate telemetry the operator console will consume.

### Trace Contract Note

The Pages replay trace must be aggregate-only and bounded-diagnostics-compatible.
It may include:

- scenario metadata: run id, commit, timestamp, topology label, honesty label
- per-tick aggregate metrics: selection entropy, `kappa`, exposure estimate,
  `membership_confidence_after(n)`, delivery success/failure counts
- per-relay display identifiers that are random/operator-assigned, not derived
  from addresses, mailbox ids, contacts, or identity material
- event annotations: relay killed, relay restored, burst stored, payload decrypted

It must not include identity graphs, raw contact cards, mailbox ids, private key
paths, IP-derived long-lived identifiers, or any field that lets the replay
become an address book in disguise.

### Pages Deploy Sketch

This is a planning sketch only; do not add the workflow until the static demo
exists and the repository owner has chosen the Pages source.

```yaml
name: pages

on:
  push:
    branches: [master]
    paths:
      - "client/desktop/**"
      - "docs/design/corridor-console-validation/**"
      - ".github/workflows/pages.yml"

permissions:
  contents: read
  pages: write
  id-token: write

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 22
          cache: npm
          cache-dependency-path: client/desktop/package-lock.json
      - run: npm ci
        working-directory: client/desktop
      - run: npm run build
        working-directory: client/desktop
      - uses: actions/configure-pages@v5
      - uses: actions/upload-pages-artifact@v3
        with:
          path: client/desktop/dist
      - uses: actions/deploy-pages@v4
```

If the Pages demo becomes a sibling Vite app instead of extending
`client/desktop`, the same workflow shape applies; only the working directory
and artifact path change.

## Distribution & Discovery

The demo should be built as one strong launch moment plus a durable discovery
loop, not as a generic growth funnel.

### Repo and Page as One Discovery System

- README hero: embed the relay-kill GIF, one sentence, and the Pages link.
- Pages site: link back to the repo, evidence log, and design caveats.
- GitHub topics: `privacy`, `metadata`, `rust`, `noise-protocol`, `secure-communication`,
  `relay`, `cryptography`, `vite`.
- The GIF must be downloadable/shareable; the artifact itself is the hook.

The headline that travels:

> A speedometer for your own metadata exposure.

The honesty line that must travel with it:

> Dev-harness replay over Tailscale/WireGuard; measures relay diversity, not a
> real-world anonymity guarantee.

### Launch Sequencing

Do not launch broad first. Complete the 5-person named technical reaction test
from §The Assignment, then lead the public launch with whichever moment actually
caused people to lean in: the relay-kill survival or the exposure needle.

Broad launch channels are one-shot spikes, not a faucet:

- Show HN
- Lobsters
- r/rust
- r/privacy
- one Bluesky/X thread centered on the GIF

The same communities that can spread this will also correctly stress-test the
claims. The honesty banner is therefore not just ethics; it is distribution
survival. If the page implies a live anonymity service, the launch becomes a
takedown thread.

### Launch Asset Drafts

README hero block:

```md
![SCP relay-kill failover demo](docs/design/corridor-console-validation/relay-kill-failover-live-2026-07-05.gif)

**SCP is building a speedometer for metadata exposure.** This demo replays a
real dev-harness relay-kill run: one blind relay dies, the message still arrives
through the survivor, and the output stays vocabulary-neutral.

Demo scope: dev-harness over Tailscale/WireGuard. This is not production
transport security, NAT traversal, or a real-world anonymity guarantee.

Live demo: <GitHub Pages URL>
Evidence log: `docs/design/corridor-console-validation/relay-kill-failover-live-2026-07-05.log`
```

Show HN title options:

- `Show HN: A meter for how observable your messaging metadata is (dev harness)`
- `Show HN: I built a relay-kill demo for metadata exposure telemetry`
- `Show HN: Visualizing relay diversity and failover in a secure corridor dev harness`

Show HN post draft:

```text
Hi HN, this is an early dev-harness demo for SCP, a secure-corridor project.

The short version: I wanted a way to show metadata exposure as an instrument,
not a slogan. The demo replays a real run over a Tailscale mesh: two blind relays
are configured, one relay is killed, send/receive still succeeds through the
survivor, and the run emits aggregate telemetry that will drive an Exposure
Meter.

Important caveat: this is not a production anonymity service. The current
harness uses plaintext dev key files, in-memory relay mailboxes, manual card
exchange, and Tailscale/WireGuard for the network. The page is a replay of real
captured runs, not a live relay service.

What I am testing: whether "a speedometer for your own metadata exposure" is a
useful way to explain the system to technical people.
```

Bluesky/X thread draft:

```text
1/ I am testing a small idea: privacy tools should show a meter for metadata
exposure, not just say "trust us."

2/ Here is a real dev-harness run: two blind relays configured, one relay killed,
message still arrives through the survivor.

3/ The honest caveat matters: this is a static replay over Tailscale/WireGuard,
not a production anonymity guarantee.

4/ The product wedge is the instrument: an Exposure Meter for relay diversity,
liveness, entropy, and concentration.

5/ I am showing this to technical people before building the Console. If the
needle does not make people lean in, the wedge is wrong.
```

## Current limitations (what the wedge must route around or explicitly label)

**Hard gaps (structural — bound the honest claim):**
- Relay mailbox is harness-only, in-memory, **ephemeral** (restart = message loss); it is
  **not** production metadata resistance.
- Keys are **plaintext files** — no keystore/hardware backing.
- Proven only over **Tailscale/WireGuard** (mesh scale). No Internet-scale transport, no NAT
  traversal, no QUIC.
- No independent crypto audit; no installer (binary copy); manual identity/card exchange;
  24h card TTL.

**Capability landmines (present as roadmap, never as shipped):**
- Guardian/social recovery: unimplemented (`todo!()`, panics).
- Vitality: not wired to production; 2 of 6 states unreachable.
- Ledger: in-memory mock, not chain-anchored.
- Post-quantum: no code. QUIC: absent.

**The one honesty invariant:** the Exposure Meter measures **relay diversity in a dev
harness**. It must never be presented as a real-world unobservability guarantee. That single
distinction is what makes this safe to ship publicly at dev-harness maturity.

## Implied tasks & needed features

### Showcase-blocking (to ship the Console honestly) — the near-term build
1. **Metrics egress surface** — a read-only stream/JSON of the already-computed
   `provider/pool` + `DeliveryPool` signals (κ, entropy, exposure estimate, membership
   confidence, per-relay liveness/reputation, selection events). Must reuse the existing
   **bounded-diagnostics** discipline (Phase 34D) so it exposes aggregates, not identity graphs.
2. **Scenario driver** — scripted send patterns that move the needle on cue
   (concentrate/diversify; kill/restore relay) for a repeatable demo.
3. **Console UI** — self-contained web (or TUI); can extend the existing `client/desktop`
   shell. Compositor-friendly, screenshot/GIF-able.
4. **Honesty-label component** — persistent banner + per-metric tooltips stating scope.
5. **Zero-install explainer** — microsite with canned traces + real GIFs from a live run.

### Product-bridge backlog (sequenced behind the showcase — the path to "usable")
6. **Encrypted keystore** — replace plaintext `.key` (OS keychain / age-at-rest).
7. **Durable relay** — persistence + at-least-once delivery (removes the ephemeral-loss caveat).
8. **Packaging/installer** — one-command per-node install; kill the binary-copy step.
9. **Identity/card exchange UX** — replace manual `scp` of card+token (QR / short code / rendezvous).
10. **Card TTL/renewal UX** — 24h TTL is too short for real use.
11. **Transport productization** — either NAT/Internet transport, or a productized
    "bring-your-own WireGuard/Tailscale" dependency with honest framing.
12. **Recovery** — implement guardian/shard, or remove it from the identity-continuity story.
13. **Vitality production wiring** + Severed/Burned triggers — only if the relationship-state
    story is to be live.
14. **Independent crypto review** — gate before ANY protection (vs legibility) claim.

## What I noticed (founder signals)

- **Pushed back on premises with implied reasoning** — declined "instrument-only" and
  "legibility-only," which is exactly the useful founder move (attachment to a *usable
  product*, not just a demo). That pushback produced the bridge framing.
- **Ruthless honesty discipline** — the whole engagement has been gated on "no production
  claims," and this wedge was selected specifically because it's honest at dev-harness
  maturity. That discipline is an asset for a *trust* product; it's also the thing that will
  make the Exposure Meter credible where competitors' "trust us, we're private" is not.
- **Agency** — building and proving (ran the real 3-node trial), not just planning.

## The Assignment

**Before building the Console, test whether the "whoa" is real — with named people, not a
category.** You can already produce Panel 2 with **zero new code**: on the live Tailscale
mesh, record a 60-second screen capture of killing a relay mid-send and the message arriving
anyway. Show it to **5 specific technical people you can name** (not "the HN crowd") and
*watch which moment they lean into* — the relay-kill, or the idea of a needle for their own
exposure. Whichever makes them lean in is the panel you build first. If neither lands with
5 people who should care, the wedge is wrong before you've spent a week on it.

### Assignment Capture Artifact (2026-07-05)

The relay-kill GIF capture step is complete:

- GIF: `docs/design/corridor-console-validation/relay-kill-failover-live-2026-07-05.gif`
- Raw log: `docs/design/corridor-console-validation/relay-kill-failover-live-2026-07-05.log`
- Subtitle/storyboard source:
  `docs/design/corridor-console-validation/relay-kill-failover-live-2026-07-05.ass`

What the capture proves: with both relay addresses still configured, the
`ryan-desktop` relay was killed for real, `send` succeeded via the surviving
`wowserver` relay (`burst_replicated count=1`), and `receive` decrypted the exact
payload through the survivor (`exchange_complete count=1`). Both relays were restored
to reachable state afterward.

Honesty boundary: this is still a dev-harness/Tailscale demonstration. It is a
validation asset for the product wedge, not production evidence. The external
5-person reaction test remains pending and must be completed before Console
implementation is prioritized.

---

**Completion status: DONE_WITH_CONCERNS.** Approach approved (Bridge). Open items: demand is
hypothesized, not validated (the Assignment tests it); Panel-1 metrics egress must respect
bounded-diagnostics to avoid leaking identity graphs; keep every deferred gap in §Implied
Tasks labeled roadmap, never shipped.
