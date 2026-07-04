# ProviderPool Real-Network Liveness Trial — Scope Gate Plan

**Status**: SCOPE GATE PENDING — no Rust source modified in this pass.
**Predecessor**: `LAN_DEV_HARNESS_RUNBOOK.md`, verdict `A — LEVEL_2_LAN_DEV_HARNESS_PROVEN` (2026-07-04).
**Constraint**: No user-facing vitality labels. Machine-event language only.
**Does not touch**: Version 1.2 human-test packet, Corridor Trial track (1–5C, already closed), production relay/CLI source, unless explicitly approved below.

---

## 0. Why this document exists

The Level 2 LAN/mesh trial proved a real two-endpoint, one-relay message path
over a live Tailscale mesh. The natural next question — "can we now inject
real ProviderPool/liveness failure into that traffic?" — turns out **not** to
be a small next step. This document is a scope gate: a grounded findings
report plus a set of decisions that must be approved *before* any
implementation, in the same style `RUNTIME_BOOTSTRAP_PLAN.md` §6 used for the
LAN trial itself.

**Naming note**: this document deliberately avoids calling itself "Trial 2,"
"Trial 3", etc. The Corridor simulator track already owns `TRIAL_2_CLOSURE_RECORD.md`
through `TRIAL_5C_CLOSURE_RECORD.md` (all closed, verdict A, unrelated to LAN
transport). A prior loose reference to "Trial 2" in `LAN_DEV_HARNESS_RUNBOOK.md`
§9 was this assistant's own forward-looking phrasing, not a pre-existing
authorized plan, and collided with the closed Corridor Trial 2 name. This plan
supersedes that phrase.

---

## 1. Current-State Findings (grounded in source, not assumption)

### Finding 1 — `ProviderPool` has zero coupling to the real transport/relay path today

- `core/transport/Cargo.toml`, `relay/daemon/Cargo.toml`, and `cli/endpoint/Cargo.toml`
  do not depend on `scp-provider-pool`. `relay/daemon` depends on `tokio` alone.
- `grep -rn "ProviderPool" core/transport/ relay/daemon/ cli/endpoint/` returns zero matches.
- `provider/pool` is listed only under `test/Cargo.toml`'s `[dev-dependencies]`,
  and its concrete struct `ProviderPool<P>` is referenced only inside
  `provider/pool/src/*.rs` and `test/tests/{sim,pool,trial2,trial3,trial4,trial5b,trial5b_receipt_bound,trial5c,level1}.rs`.
- The dependency direction is the **reverse** of what "inject failure into
  corridor traffic" implies: `provider/pool/src/lib.rs` imports
  `ProviderQuorum`/`StateProvider` *from* `core/transport::quorum`, and builds
  `ProviderPool<P>` generically on top of it. `core/transport` does not know
  `ProviderPool` exists.

**Implication**: there is no existing seam to plug real relay liveness into
`ProviderPool`. One has to be designed, not just wired up.

### Finding 2 — `core/transport::quorum::ProviderQuorum<P>` is a state-consistency dispatcher, not a message-delivery selector

`quorum.rs` (new/untracked, Phase 11) implements `ProviderQuorum<P: StateProvider>`
with three resolution rules — `is_revoked_quorum()` (Monotonic: `any()` wins),
`get_handshake_ephemeral_quorum()` (Soft-State: latest-valid wins), and
`get_commitment_quorum()` (Consensus-Relevant: `all_agree()`, else
`QuorumResult::Equivocation`). These map directly to the class taxonomy in
`STATE_SEMANTICS.md`, which states explicitly:

> "Before introducing `ProviderQuorum` or any multi-provider abstraction, every
> state type here must be assigned to a class."

A network relay that stores-and-forwards opaque bursts is not a "state
provider" in this sense — it doesn't hold revocation, handshake-ephemeral, or
commitment state. Forcing a real relay endpoint to implement `StateProvider`
just to be sampled by `ProviderPool<P>` would be a type-level misuse: it would
answer "is this key revoked?"-shaped queries with a service that has no
opinion on revocation. **This is the central architectural trap this scope
gate exists to avoid.**

### Finding 3 — `core/transport::corridor::BurstEnvelope` is explicitly in-process-only

`corridor.rs` (new/untracked, Phase 41 "Trial 0" artifact) has no provider or
relay-selection concept at all. Its own doc comment states it is an
"in-process simulator exchange artifact for corridor trials" and "does not
constitute an approved production relay-visible wire contract or routing/privacy
policy... must not silently become a production routing decision." It cannot
be the basis for a real-network trial without violating its own documented
scope.

### Finding 4 — The real LAN relay path is single-endpoint, end-to-end, with no failover seam

- `relay/daemon/src/main.rs` (~134 lines) binds one `TcpListener` on one
  `--bind` address, holds one in-memory `HashMap<DevMailboxId, Vec<Burst>>`,
  and has no concept of relay identity, multiple nodes, or liveness tracking.
- `cli/endpoint/src/main.rs`'s `relay_store()`/`relay_poll()` each do a single
  `TcpStream::connect(addr)` with no retry, no failover, no alternate address.
- `core/transport::harness` (`DevMailboxId`, `DevHarnessBurst`,
  `send_harness_direct()`, `receive_harness()`) is pure crypto/serialization —
  no function takes a relay list, an endpoint identifier, or reports
  success/failure of a send attempt.
- A separate, pre-existing scaffold — `relay/mesh` (`RelayNode`,
  `discover_relays()`, `route_burst()`) — has a `Vec<RelayNode>` shape, but (a)
  is wired only into the **simulator** `FlashSession` path via `flash.rs`, not
  into `harness.rs`/`relay/daemon`/`cli/endpoint`; (b) `route_burst()` only
  ever uses `route[0]`, no failover implemented; (c) `discover_relays()`
  defaults to a single hardcoded `"local://loopback"` node; (d) shares no
  types with `provider/pool`.

**Implication**: injecting liveness failure "into corridor traffic" on the
real mesh cannot reuse an existing multi-relay abstraction — none of the three
candidates (`ProviderQuorum`, `corridor::BurstEnvelope`, `relay/mesh`) fit
without either a type misuse (Finding 2) or a scope violation (Finding 3) or
missing wiring entirely (Finding 4).

### Finding 5 — Corridor Trial 2 already set the discipline this must not violate

`TRIAL_2_CLOSURE_RECORD.md` (verdict A, 2026-05-28) proved that `ProviderPool`
telemetry surfaces (`kappa`, `liveness_weighted_kappa`, etc.) respond correctly
to **scripted, synthetic** `record_failure()`/`record_response()` traces,
while explicitly proving (T7) that observing telemetry does not mutate
`VitalityEvidenceStore` or trigger rotation. Its non-claims list is explicit:
transport behavior, relay routing, and "real network failure semantics" were
all named as **not proven** by that trial. Any new trial that drives
`ProviderPool` from real network events must preserve that same
observation-only boundary unless this scope gate explicitly approves crossing it.

---

## 2. What "inject real ProviderPool/liveness failure into corridor traffic" could actually mean

Two genuinely different projects hide behind that one sentence. They must not
be conflated — picking between them (or a staged combination) is the actual
decision this scope gate exists to make.

### Option 1 — Real-network-driven observation (recommended minimum viable trial)

Extend Corridor Trial 2's discipline from a **scripted** failure trace to a
**real** one, without touching production code:

- New dev-only test/harness code (e.g. `test/tests/trial_lan_liveness.rs` or a
  small standalone binary under `cli/` used only for this trial) performs real
  TCP store/poll cycles against the already-proven live relay on wowserver.
- It deliberately kills and restarts the real relay process (exactly as
  already done for the Level 2 relay-restart negative test) and/or points at
  a nonexistent address to produce a real `ConnectionRefused`/timeout.
- Each real success/failure is fed into a `ProviderPool<P>` instance's
  `record_response()`/`record_failure()` **side-by-side** with the real
  attempt — not wired into `cli/endpoint` or `relay/daemon` production code.
- Confirms `operational_telemetry()` responds correctly to *real* signals
  (connection refused, timeout, successful roundtrip) instead of a synthetic
  script, while proving (mirroring Trial 2's T7) that this observation still
  does not touch `VitalityEvidenceStore`, rotation, or send authorization.
- Requires **zero new production dependencies** — `P` in this trial can be a
  minimal dev-only marker type implementing `StateProvider` trivially (e.g.
  always returning "no opinion"), since the trial is about liveness telemetry
  from real network attempts, not about `ProviderQuorum`'s actual state-class
  resolution logic.
- Single relay (wowserver) is sufficient — no new mesh topology needed. The
  "failure" is temporal (relay down vs. up), not selection-among-many.

**This is the direct, low-risk analog of what Level 2's negative tests already
did**, just now feeding the real outcome into `ProviderPool` telemetry instead
of only asserting `count == 0`.

### Option 2 — Real multi-provider selection and failover (large scope, separate initiative)

Actually wire `ProviderPool` into the send/receive path so the CLI selects
among **multiple real relay endpoints**, fails over on liveness failure, and
production code's routing decisions are influenced by pool state. This requires,
at minimum, all of the following **new** protocol decisions — none currently exist:

1. A new trait (not `StateProvider` — see Finding 2) representing a
   real delivery endpoint, e.g. `DeliveryProvider { attempt_store(), attempt_poll() }`,
   and a decision on whether `ProviderPool<P>` should be generalized to accept
   it or whether a **separate** pool type should be built reusing `ProviderPool`'s
   algorithms (liveness, rotation, exposure) by composition rather than by
   forcing today's `StateProvider`-bound `ProviderPool<P>` to serve two
   unrelated semantic purposes.
2. A real second relay endpoint on the mesh — the current 3-machine topology
   (laptop=A, wowserver=relay, ryan-desktop=B) has exactly one relay. Meaningful
   selection/failover needs ≥2, which means either running a second `scp-relay`
   process on an existing machine or a genuine 4th-node decision.
3. CLI protocol changes: `--relay` currently accepts one address
   (`cli/endpoint/src/main.rs:166,211`); multi-relay requires either multiple
   `--relay` flags, a discovery mechanism, or a config file — a new decision
   surface with privacy implications (does a client leak its full relay list
   to an observer? does relay selection itself become a side channel?).
4. A decision on whether real routing decisions being influenced by
   `ProviderPool` state violates the "observational only" boundary Trial 2 and
   `TRIAL_5B/5C` (admissible surface) established — this would need its own
   ADR, comparable in weight to `CORRIDOR_TRIAL_5A_EVENT_PROVENANCE_MODEL_DECISION.md`.

**This is not a next trial — it is a multi-week feature initiative** with its
own scope gates at each of the four points above. It should not be started
opportunistically off the back of Level 2's success without a dedicated
planning pass.

### Recommendation

Approve **Option 1** as the immediately viable next trial. Treat **Option 2**
as explicitly out of scope for this pass, to be planned separately if desired
— flagged here so it isn't silently assumed to be "the next trial" again.

---

## 3. Proposed Proof Ladder for Option 1

### Step 0 — Baseline

`cargo test --workspace -- --test-threads=1` green (currently 517 passing, per
Level 2 pre-flight). No regressions permitted before or after.

### Step 1 — Dev-only harness code

New file, e.g. `test/tests/lan_liveness_trial.rs` (or a small helper module
under `test/` shared by it). Performs:
- Real TCP store against the live wowserver relay (reusing the already-proven
  binaries and Tailscale addresses) → `pool.record_response(relay_provider_id)`.
- Real TCP poll against a deliberately-killed relay (`ConnectionRefused`) →
  `pool.record_failure(relay_provider_id)`.
- Reads `pool.operational_telemetry()` after each phase and asserts the
  expected `kappa`/`liveness_weighted_kappa`/`response_total` values, mirroring
  Trial 2's assertion style but driven by real sockets.
- Asserts `VitalityEvidenceStore` state and `pool.epoch_count()` are unchanged
  by the observation (T7-equivalent check).

**Pass condition**: deterministic real-network-driven telemetry values,
0 regressions in the existing 517-test baseline, no vitality-vocabulary output,
no coupling to send authorization or rotation.

This earns: `A — PROVIDERPOOL_REAL_NETWORK_LIVENESS_OBSERVATION_PROVEN`

### Step 2 (optional stretch, still Option 1 scope)

Repeat using the already-proven Level 2 relay-restart procedure live on the
mesh (kill wowserver's `scp-relay`, restart it) instead of a local throwaway
relay, to confirm the same telemetry behavior holds against the actual
3-machine Tailscale topology, not just localhost sockets.

---

## 4. Scope Gate — Decision Required Before Any Code

**Before writing any implementation code, one of the following must be recorded:**

| Verdict | Meaning |
|---------|---------|
| `A — OPTION_1_REAL_NETWORK_OBSERVATION_AUTHORIZED` | Proceed with the dev-only, observation-only trial in §3. Option 2 remains unscoped and unauthorized. |
| `B — OPTION_2_MULTI_PROVIDER_INITIATIVE_REQUESTED` | Defer Option 1; instead produce a full separate planning document for real multi-relay selection (the four sub-decisions in §2 Option 2), before any code. |
| `C — NEITHER_AUTHORIZED_YET` | Stop here; Level 2 verdict A remains the most recent proven state. |

No implementation work should begin until this table is filled in by the
operator (this is a planning document only — the assistant that wrote it
should not self-approve its own scope gate, per the self-correction doctrine's
independent-verification principle).

### Recorded Verdict (2026-07-04)

**`A — OPTION_1_REAL_NETWORK_OBSERVATION_AUTHORIZED`**, approved by operator.
Option 2 (multi-provider selection/failover) remains unscoped and unauthorized.

### Step 1 Result: `A — PROVIDERPOOL_REAL_NETWORK_LIVENESS_OBSERVATION_PROVEN`

Implemented in `test/tests/lan_liveness_trial.rs` (3 new tests, all against real
`scp-relay`/`scp-cli` OS processes on localhost, real TCP, real process kill):

| Test | Real-network event | Trial 2 shape reproduced |
|------|--------------------|--------------------------|
| `real_network_explicit_failure_matches_trial2_t2_shape` | 2 real `receive` attempts against a really-killed relay (`ConnectionRefused`) → `record_failure()`; 4 real successful attempts against a live relay → `record_response()` | Exact T2 numbers: `kappa=1.0`, `liveness_weighted_kappa=1.0`, `active_n=2`, `selection_total=4`, `response_total=4`. Also folds in a T7-equivalent isolation check (`VitalityEvidenceStore` state and `epoch_count()` unchanged). |
| `real_network_healthy_baseline_matches_trial2_uniform_shape` | 4+4 real successful attempts split across two live relays | `liveness_weighted_kappa=0.0`, `selection_total=8`, `response_total=8`, uniform-2-provider shape (T1/T5-recovery analog). |
| `real_network_liveness_trial_produces_no_vocabulary_labels` | real success + real killed-relay failure | No vitality vocabulary in any output. |

Full workspace baseline: **520 passing, 0 failed** (517 + 3 new tests, 0 regressions),
`cargo test --workspace -- --test-threads=1`. No production source files modified —
only the new test file. `ProviderPool` consumed strictly read-only via its existing
public API, exactly as `test/tests/trial2.rs` already does.

### Step 2 Result: `A — PROVIDERPOOL_REAL_MESH_LIVENESS_OBSERVATION_PROVEN`

Added a 4th test, `real_mesh_explicit_failure_matches_trial2_t2_shape`, marked
`#[ignore]` (depends on the live 3-machine Tailscale mesh + passwordless SSH to
`wowserver`; not run by default `cargo test --workspace`, run manually with
`cargo test --test lan_liveness_trial -- --ignored --test-threads=1`):

- Local control relay (always healthy) as pid(1); the **real wowserver relay
  on the live Tailscale mesh** (`100.72.12.57:7700`) as pid(2).
- One real successful roundtrip over the actual mesh proves live reachability.
- pid(2) killed for real via `ssh wowserver "pkill -f './scp-relay'"` — an
  actual remote process, not a local child process.
- Two real failed `receive` attempts against the now-dead remote relay feed
  `record_failure(pid(2))`; four real successful attempts against the local
  control relay feed `record_response(pid(1))`.
- Reproduces the exact same T2 numbers as Step 1's localhost version:
  `kappa=1.0`, `liveness_weighted_kappa=1.0`, `active_n=2`,
  `selection_total=4`, `response_total=4`.
- Relay restarted via SSH at the end, leaving wowserver as found (confirmed
  running post-test: `ps aux`/`ss -tlnp` on wowserver).

**Engineering note**: the first attempt hung — `ssh`'s local client did not
close its channel promptly after the remote command backgrounded a long-lived
process (`nohup setsid ... & disown`), even though the remote side executed
correctly (confirmed via direct `ps aux` on wowserver while the local `ssh`
was still hung). Fixed with a bounded local timeout
(`run_ssh_with_timeout()`, 5s) that kills the local `ssh` client if it doesn't
return in time — the remote command has always already executed by then.
This is a test-harness robustness fix, not a protocol or transport finding.

Full workspace baseline after Step 2 unchanged: **520 passing, 0 failed** (the
new test is `#[ignore]`d and does not run in the default suite). Manual run:
`1 passed; 0 failed` in 5.38s.

This completes both the required Step 1 and the optional Step 2 stretch goal
from §3. Option 1 is now fully proven at both localhost and live-mesh scope.

---

## 5. Files To Create (Option 1 only, upon approval)

| File | Purpose |
|------|---------|
| `test/tests/lan_liveness_trial.rs` | Real-socket-driven `ProviderPool` observation test |

### Explicitly not modified

- `core/transport/src/harness.rs`, `relay/daemon/src/main.rs`, `cli/endpoint/src/main.rs` — no production wiring in Option 1.
- `provider/pool/` — no changes; consumed read-only via its existing public API (§6 of the Explore findings, reproduced below for reference).
- Corridor Trial track (`TRIAL_2_CLOSURE_RECORD.md` through `TRIAL_5C_CLOSURE_RECORD.md`) — unaffected, unrelated.

---

## 6. Reference — `ProviderPool<P>` Public API Surface (as of 2026-07-04)

Captured for precision when writing Step 1's harness code. Method list from
`provider/pool/src/lib.rs` (line numbers as of this pass):

`new()`, `with_active_window()`, `with_rotation()`, `with_activation_strategy()`,
`with_exposure_reset()` / `with_exposure_reset_policy()`, `with_cooldown()`,
`with_tick_jitter()`, `with_entropy_smoothing()`, `with_liveness(max_consecutive_failures, max_silence_secs)`,
`with_admission()`, `with_eviction()`, `with_admissible_tracking()`,
`request_admission()`, `complete_admission()`, `evict()`, `lift_eviction_ban()`,
`eviction_record()`, `with_reputation_decay()`, `record_response(provider_id)`,
`record_failure(provider_id)`, `record_admissible_response()`, `record_admissible_failure()`,
`add(provider_id, provider)`, `len()`, `is_empty()`, `active_len()`, `epoch_count()`,
`record_equivocation()`, `exposure_estimate()` / `exposure_estimate_at()`,
`active_set_snapshot()`, `exposure_distribution()`, `convergence_pressure()`,
`operational_telemetry()`, `maybe_rotate()`, `force_rotate()`, `tick()`,
`active_count()`, `dormant_count()`, `kappa()`, `sample()` (requires `P: Clone + StateProvider`),
`sample_with_receipts()`, `maybe_issue_dummy_query()`, `effective_dummy_probability()`.

`P`'s only bound across most methods is none; `sample()`/`sample_with_receipts()`
require `P: Clone + StateProvider` — this is the exact constraint Finding 2
identifies as a potential type-misuse trap if `P` is forced to be a real relay
endpoint. For Option 1's Step 1, `P` should be a trivial dev-only marker type,
not a real `StateProvider` implementation for the relay.

---

## 7. Explicit Non-Claims (mandatory disclosure, mirrors Trial 2 §9)

Even if Option 1 is approved and proven, it will **not** show:

- Real multi-relay selection or failover (that is Option 2, unscoped).
- Any change to production send/receive authorization based on liveness.
- Any coupling between real relay liveness and `VitalityEvidenceStore`.
- Metadata-resistant relay addressing (unchanged from Level 2's accepted `DevMailboxId` limitations).
- Production readiness of `ProviderPool` for real network conditions at scale (single relay, single failure mode only).
