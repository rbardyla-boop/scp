# SCP Consumer-Facing Product Plan

**Status**: Planning artifact only.
**Deployment authorization**: Not granted.
**Current public surface**: GitHub Pages recorded dev-harness demo.
**Target**: A person can try SCP without the builder manually operating the run.

This plan defines the path from the current public demo to a consumer-facing
product surface without overclaiming production privacy. The goal is not to
become a mass-market messenger first. The goal is to make the corridor usable
by a normal technical person, then by a small trusted group, while closing the
hard gaps in the right order.

## Correctness Gate

This plan is correct if:

- It removes manual builder involvement from the trial path.
- It keeps production privacy claims blocked until keystore, durable relay,
  transport, metadata, and audit gaps are closed.
- It prioritizes a simple app-shaped experience over terminal choreography.
- It names the smallest useful product slice.
- It separates demo polish from security hardening.

This plan is wrong if:

- It sells SCP as a finished secure messenger.
- It depends on users copying plaintext key files by hand.
- It requires a user to understand every internal trial document before trying it.
- It exposes identity graphs through telemetry.
- It adds social recovery, vitality UI, blockchain claims, PQ claims, or QUIC claims
  before those systems are actually wired and tested.

## Product Definition

Consumer-facing means:

1. A user can land on the Pages site or repo and understand what SCP is.
2. A user can download or run one thing.
3. A user can create an identity without seeing raw key files.
4. A user can pair with another person without manual `scp` of card files.
5. A user can send a small message through configured relays.
6. A user can see corridor health/exposure telemetry in plain language.
7. The app labels exactly what is dev preview, what is real, and what is not proven.

The first consumer-facing version is therefore:

> **SCP Corridor Preview**: a desktop app for a two-person dev-preview corridor
> with honest relay-health telemetry and no production anonymity claim.

## Non-Negotiables

- **No account system first.** Account creation is a trap. Identity is local.
- **No hosted network promise first.** Start with local/dev relays and
  bring-your-own Tailscale/WireGuard until transport is productized.
- **No raw `.key` UX.** Plaintext file keys may remain internally during early
  development, but the app surface must not teach users to pass key files around.
- **No vitality labels in public send/receive UX yet.** Vitality remains a
  designed concept until production wiring and human validation exist.
- **No recovery story until recovery works.** Controlled key rotation is allowed;
  total device-loss recovery is not.
- **No anonymity guarantee.** The Exposure Meter measures harness/operator relay
  diversity and concentration pressure, not real-world unobservability.

## Product Slices

### Slice 0 — Public Showcase

**Current state**: Done.

- GitHub Pages demo is live.
- README front door points to the demo and evidence log.
- Honesty boundary is visible.

This is not enough for product use. It is the storefront and proof artifact.

### Slice 1 — Interactive Replay

**Goal**: Let visitors touch the concept without installing anything.

Build a client-side replay on the Pages site:

- play/pause/scrub the relay-kill trace
- show an Exposure Meter from aggregate trace data
- show relay liveness/reputation changes over time
- show the exact honesty label beside the meter

This does not need live networking. It needs the trace format that the real
Console will later consume.

**Done when:**

- The replay consumes JSON traces, not hardcoded DOM state.
- The trace contains aggregate metrics only.
- The page still works as static GitHub Pages.
- A visitor can understand the wedge in under 60 seconds.

### Slice 2 — Local Corridor Preview

**Goal**: One person can run a local two-endpoint demo without manual command
choreography.

Ship a desktop shell that can:

- create two local preview identities
- start a local relay process
- send a message from A to B
- show decrypted receipt
- show "relay restarted means message loss" as an explicit limitation

This is still a local preview, but it teaches the app workflow.

**Done when:**

- One command starts the preview app.
- No user handles card files or mailbox hex directly.
- The app can reset its preview state.
- The UI names it "Local Preview", not "secure messenger".

### Slice 3 — Two-Machine Dev Preview

**Goal**: Two people on a known private network can try SCP without the builder.

Use bring-your-own Tailscale/WireGuard initially:

- one user runs endpoint app
- one user runs endpoint app
- a relay is selected from a simple config or bundled local relay mode
- pairing uses QR or short-code export/import
- send/receive works through the dev relay path

**Done when:**

- Setup docs fit on one screen.
- Pairing does not require manual `scp`.
- Secrets stay local.
- The app reports whether the relay is reachable.
- The UI says "Dev Preview over your private mesh".

### Slice 4 — Product-Candidate Kit

**Goal**: Small trusted groups can run a corridor pilot with explicit operator
control.

Required before this slice:

- encrypted local keystore or OS keychain integration
- durable relay storage with bounded queues and expiry
- production mailbox/routing privacy design replacing `DevMailboxId`
- installer/package for endpoint and relay
- pairing/card renewal UX
- privacy-preserving telemetry export
- threat model update
- independent crypto review plan started

**Done when:**

- A small group can install endpoint + relay without building from source.
- Relay restart does not silently erase live messages.
- Operators can see aggregate health without identity graphs.
- The app can rotate local identity material in a controlled flow.

### Slice 5 — Real Consumer Product

**Goal**: A non-expert can use SCP without understanding relays.

This is not the next step. It requires decisions that should not be rushed:

- managed relay service vs operator-run relays
- abuse handling
- accountless discovery or invitation flow
- mobile clients
- recovery that survives device loss
- clear human language for consent/vitality states
- security audit results
- long-term update and compatibility policy

## Workstreams In Order

### 1. Trace Contract and Replay

Build the aggregate trace shape first because it feeds both Pages and Console.

Minimum trace fields:

- `run_id`
- `commit`
- `scenario`
- `honesty_label`
- `tick`
- `relay_count`
- `live_relay_count`
- `delivery_success_count`
- `delivery_failure_count`
- `selection_entropy_bits`
- `kappa`
- `exposure_estimate`
- `membership_confidence`
- `events`

Do not include:

- private key paths
- raw mailbox ids
- contact cards
- IP-derived stable identifiers
- relationship graph edges

### 2. Console UI

Turn `client/desktop` from a static showcase into a real replay surface:

- timeline
- Exposure Meter
- relay status strip
- event log
- honesty banner

Keep the controls boring and obvious. The UI should feel like an instrument
panel, not a marketing page.

### 3. Secret Storage

Replace user-visible plaintext key handling:

- first pass: app-owned profile directory with strict permissions
- next pass: OS keychain or encrypted-at-rest key file
- later: hardware-backed storage where available

No consumer-facing build should ask a user to copy a `.key` file.

### 4. Pairing UX

Replace manual card movement:

- QR code for public card and relay invitation
- copyable invite text
- import preview that shows what will be trusted
- card TTL/renewal flow

The user should understand "I am pairing with this person", not
"I am moving a JSON file."

### 5. Durable Relay

Replace in-memory mailbox loss:

- persisted burst queue
- expiry/TTL
- max queue depth
- replay/dedup behavior documented
- restart survival test

This is the biggest line between demo and usable.

### 6. Installer and Releases

Make releases boring:

- GitHub Releases with endpoint and relay binaries
- checksums
- one-page install/run guide
- later: Tauri desktop bundles

No one should need to clone the repo to try the preview.

### 7. Transport Productization

Choose one honest first transport story:

- **Bring-your-own mesh**: SCP Preview runs over Tailscale/WireGuard, clearly labeled.
- **Internet transport**: implement and validate NAT/QUIC/Noise path before claiming it.

Do not blur these. A labeled mesh preview is better than a fake Internet product.

## First Three Build Milestones

### Milestone A — Replay Demo Upgrade

Deliver:

- JSON trace file for the relay-kill run
- Pages replay UI
- Exposure Meter with static/recorded values
- README link updated from "recorded GIF" to "interactive replay"

Why first: no security risk, high public value, feeds the real Console.

### Milestone B — Local Preview App

Deliver:

- desktop app starts a local relay
- creates local preview identities
- sends one message
- displays receipt and limitation labels

Why second: it becomes a real app without pretending to be production.

### Milestone C — Two-Machine Preview Kit

Deliver:

- packaged CLI/desktop build
- QR/copy invite
- private-mesh setup guide
- relay health panel
- no manual key/card file movement

Why third: this is the first "someone else can try it" version.

## Cut List

Do not work on these next:

- mobile app polish
- social recovery UI
- vitality state UX
- blockchain-backed ledger language
- post-quantum branding
- managed hosting
- viral invite loops
- account system

They can matter later. Right now they slow down the first usable surface.

## Next Recommended Work Item

Start with **Milestone A: Replay Demo Upgrade**.

It is the cleanest bridge from what is already live to something consumer-facing:
it improves the public artifact, builds the data contract for the operator
Console, and does not require pretending the network is production-ready.

Concrete first ticket:

> Create `docs/design/corridor-console-validation/relay-kill-failover-live-2026-07-05.trace.json`
> from the existing log/GIF evidence, then render it in the Pages app as a
> timeline with an Exposure Meter and relay status strip.

Success criterion:

> A visitor can press play and understand: two relays configured, one relay
> killed, delivery survives, exposure/relay-health metrics update, and the
> caveat remains impossible to miss.
