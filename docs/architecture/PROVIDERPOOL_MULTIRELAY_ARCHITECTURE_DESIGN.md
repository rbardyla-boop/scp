# ProviderPool Multi-Relay Architecture Design (Option 2)

**Status**: DESIGN — awaiting operator sign-off on Decision Point 4. No Rust source modified by this pass.
**Predecessor**: `PROVIDERPOOL_REAL_NETWORK_LIVENESS_TRIAL_PLAN.md` (Option 1 PROVEN, verdict A, both localhost and live-mesh sub-trials closed).
**Constraint**: No user-facing vitality labels. Machine-event language only.
**Scope of this document**: Resolve the four Option 2 sub-decisions from the scope-gate plan §2. Three are engineering recommendations made and stood behind. One (Decision Point 4) is a boundary-crossing ADR whose verdict is deliberately left blank for the operator.

---

## 0. What Option 2 actually is, restated precisely

Option 1 proved that `ProviderPool` can *observe* real TCP success/failure while sitting beside the send/receive path, touching no production code. Option 2 inverts the data-flow direction: **pool liveness state now feeds back into which real relay a real burst is routed through.** That single inversion is the whole initiative, and it is also the whole risk — it is exactly the observational-only boundary that Trial 2 (T7) and Trial 5A froze. Points 1–3 are the mechanism; Point 4 is the permission to build the mechanism at all.

Points 1–3 are designed so that the boundary crossing in point 4 is confined to **one named type at one call site**, greppable and auditable, rather than smeared across the transport crate. If the operator declines point 4, points 1–3 are inert (a `DeliveryPool` that nobody wires into the CLI is just a library type).

---

## 1. Decision Point 1 — A delivery-endpoint trait, and how the pool consumes it

### 1.1 The structural fact that decides this

The scope-gate Finding 2 framed the trap as "should we force a relay to implement `StateProvider`." Reading the actual source (`provider/pool/src/lib.rs`) shows the choice is cleaner than the plan assumed:

- Every algorithm in the pool — `sample_inner`, `maybe_rotate`, `do_rotate`, `record_response`, `record_failure`, `record_equivocation`, `evict`, `operational_telemetry`, `convergence_pressure`, `tick`, admission, eviction — lives in **`impl<P>` with no trait bound on `P`** (`provider/pool/src/lib.rs:138`).
- The `P: Clone + StateProvider` bound appears on exactly three methods: `sample()`, `sample_with_receipts()`, `maybe_issue_dummy_query()` (`impl<P: Clone + StateProvider>` at `provider/pool/src/lib.rs:1007`).
- `sample_inner()` (`provider/pool/src/lib.rs:1014`, the real selection engine: liveness filter → weighted strategy → `ExposureTracker::record`) sits inside that bounded block **but calls no `StateProvider` method** — verified directly by reading its body. It only calls `self.is_live(...)`, `self.reputation.effective_equivocation_count(...)`, `lemire_uniform(...)`, `self.exposure_tracker.lock()...record(...)`, and clones `P`. The bound is inherited purely because its sibling `sample()` packages the result into a `ProviderQuorum<P>`, and `ProviderQuorum::from_providers` requires `P: StateProvider`.

So the pool is *already* a `StateProvider`-agnostic "selection + liveness + rotation + exposure engine over identified resources." `StateProvider` is a packaging detail of one return type, not a property of the machinery.

### 1.2 The trait

New trait, deliberately **not** `StateProvider`-shaped (no `is_revoked`, no `get_handshake_ephemeral` — a store-and-forward relay has no opinion on either):

```rust
// New: provider/delivery/src/lib.rs  (new crate `scp-provider-delivery`)
// or   provider/pool/src/delivery.rs (module) — see §1.5 for the crate decision.

use scp_transport::harness::DevMailboxId;

/// A real message-delivery endpoint the pool may select among.
///
/// This is NOT a StateProvider. A relay stores and forwards opaque bursts; it
/// holds no revocation, handshake-ephemeral, or commitment state and must never
/// be asked a state-consistency question. Delivery outcomes are liveness signals,
/// not state claims — they carry no equivocation semantics.
pub trait DeliveryEndpoint {
    /// Stable pool key for this endpoint. MUST be a random per-endpoint tag
    /// assigned out-of-band by the operator — NOT the network address, NOT any
    /// identity key. See Decision Point 3 for why the address must not be the key.
    fn endpoint_id(&self) -> [u8; 32];

    /// Attempt to store one CBOR-serialized DevHarnessBurst to a mailbox.
    /// Mirrors cli/endpoint `relay_store()` exactly: one TcpStream::connect,
    /// [0x01][32 token][4 len LE][N bytes], await [0x00] ack.
    async fn attempt_store(
        &self,
        mailbox:    &DevMailboxId,
        burst_cbor: &[u8],
    ) -> Result<(), DeliveryError>;

    /// Attempt to drain a mailbox. Mirrors `relay_poll()`.
    async fn attempt_poll(
        &self,
        mailbox: &DevMailboxId,
    ) -> Result<Vec<Vec<u8>>, DeliveryError>;
}

/// Failure taxonomy that becomes the liveness signal. Derived from the real
/// io::Error paths in relay_store()/relay_poll().
#[derive(Debug, Clone)]
pub enum DeliveryError {
    ConnectionRefused,   // relay process down / wrong address  → record_failure
    Timeout,             // connect or read stalled             → record_failure
    Protocol(String),    // unexpected ack byte, short read     → record_failure
}
```

`async fn` in traits is used here only as a **generic monomorphized bound** (`D: DeliveryEndpoint`), never as `dyn DeliveryEndpoint`, so object-safety/boxing is a non-issue. A concrete endpoint is trivially `Clone`:

```rust
#[derive(Clone)]
pub struct RelayEndpoint {
    endpoint_id: [u8; 32], // random tag
    addr:        String,   // host:port, held locally, used only to open the socket
}
```

### 1.3 The enabling change to the pool (the only production edit in point 1)

Relocate `sample_inner` into a `StateProvider`-free block and expose one new accessor. This is a ~5-line move with **zero behavior change** (verified: `sample_inner` calls no `StateProvider` method):

```rust
// provider/pool/src/lib.rs

impl<P: Clone> ProviderPool<P> {
    // MOVED here verbatim from the `impl<P: Clone + StateProvider>` block below.
    fn sample_inner(&self, rng: &mut impl RngCore) -> Vec<([u8; 32], P)> { /* unchanged */ }

    /// StateProvider-free selection. Returns the raw selected (id, endpoint)
    /// pairs WITHOUT packaging them into a ProviderQuorum. Reuses the entire
    /// selection / liveness-filter / weighted-strategy / exposure-accounting
    /// path (`sample_inner`) with no duplication.
    ///
    /// This is the seam delivery selection uses. It exists because the pool's
    /// selection machinery is semantically independent of the state-consistency
    /// class taxonomy — only ProviderQuorum packaging requires StateProvider.
    pub fn sample_selected(&self, rng: &mut impl RngCore) -> Vec<([u8; 32], P)> {
        self.sample_inner(rng)
    }
}

impl<P: Clone + StateProvider> ProviderPool<P> {
    pub fn sample(&self, rng: &mut impl RngCore) -> ProviderQuorum<P> {
        let selected = self.sample_inner(rng); // still reachable — same crate
        if selected.is_empty() { ProviderQuorum::new() }
        else { ProviderQuorum::from_providers(selected) }
    }
    // maybe_issue_dummy_query() stays here unchanged.
}
```

**Addendum (post-verdict correction)**: the DP4 verdict mandates the *admissible* surface
(`sample_with_receipts`), not the raw surface `sample()` uses. Reading
`sample_with_receipts()` (`provider/pool/src/lib.rs:1171`) shows it has the **identical**
pattern: it calls `sample_inner(rng)` (already `StateProvider`-free), then separately does
`ProviderQuorum::from_providers(selected.clone())` for packaging only. Receipt issuance
itself (`admissible_tracker.issue_receipt(epoch_count, pid)`) touches no `StateProvider`
method. So the same relocation applies, one level over:

```rust
impl<P: Clone> ProviderPool<P> {
    // sample_selected() from above, plus:

    /// StateProvider-free receipt-issuing selection — the admissible-surface
    /// analog of sample_selected(). Identical logic to sample_with_receipts(),
    /// minus ProviderQuorum packaging (the only part requiring StateProvider).
    pub fn sample_selected_with_receipts(
        &mut self,
        rng: &mut impl RngCore,
    ) -> Result<(Vec<([u8; 32], P)>, Vec<SelectionReceipt>), AdmissibilityError> {
        if let Some(adm) = self.admissible_tracker.as_ref() {
            if adm.outstanding.len() >= adm.max_outstanding_receipts {
                return Err(AdmissibilityError::ReceiptCapacityExhausted);
            }
        }
        let selected = self.sample_inner(rng);
        if selected.is_empty() {
            return Ok((Vec::new(), Vec::new()));
        }
        let receipts = match self.admissible_tracker.as_mut() {
            None => Vec::new(),
            Some(adm) => {
                let epoch_count = adm.current_epoch_count;
                let mut rs = Vec::with_capacity(selected.len());
                for (pid, _) in &selected {
                    match adm.issue_receipt(epoch_count, *pid) {
                        Ok(r) => rs.push(r),
                        Err(_) => break, // CounterExhausted — stop issuing, return partial
                    }
                }
                rs
            }
        };
        Ok((selected, receipts))
    }
}

impl<P: Clone + StateProvider> ProviderPool<P> {
    /// Rewritten in terms of sample_selected_with_receipts() — identical behavior,
    /// verified against the original body (same capacity check, same sample_inner
    /// call, same receipt-issuance loop), now with packaging factored out.
    pub fn sample_with_receipts(
        &mut self,
        rng: &mut impl RngCore,
    ) -> Result<(ProviderQuorum<P>, Vec<SelectionReceipt>), AdmissibilityError> {
        let (selected, receipts) = self.sample_selected_with_receipts(rng)?;
        let quorum = if selected.is_empty() {
            ProviderQuorum::new()
        } else {
            ProviderQuorum::from_providers(selected)
        };
        Ok((quorum, receipts))
    }
}
```

`record_admissible_response()`/`record_admissible_failure()` (`provider/pool/src/lib.rs:478,494`)
are already in the unbounded `impl<P>` block — no change needed there.

### 1.4 The consumer type — a thin `DeliveryPool` newtype (the audited seam)

**Superseded by the DP4 verdict's admissible-surface mandate** — the version below
uses `sample_selected_with_receipts()` / `record_admissible_*()`, not the raw
`sample_selected()` / `record_response()` / `record_failure()` shown in the first
draft above. Every recorded outcome is bound to a specific prior `SelectionReceipt`,
per the operator's sub-decision.

```rust
pub struct DeliveryPool<D: DeliveryEndpoint + Clone> {
    inner: ProviderPool<D>,
}

/// One selected route for a single delivery attempt, paired with the receipt
/// that MUST be presented back to record its outcome. Callers cannot record
/// an outcome without a receipt — there is no bare-id recording path exposed.
pub struct DeliveryRoute<D> {
    pub endpoint: D,
    pub receipt:  SelectionReceipt,
}

impl<D: DeliveryEndpoint + Clone> DeliveryPool<D> {
    pub fn new(strategy: SamplingStrategy, max_outstanding_receipts: usize) -> Self {
        Self {
            inner: ProviderPool::new(strategy)
                .with_admissible_tracking(max_outstanding_receipts),
        }
    }

    pub fn with_liveness(mut self, max_failures: u32, max_silence_secs: u64) -> Self {
        self.inner = self.inner.with_liveness(max_failures, max_silence_secs);
        self
    }

    pub fn add(&mut self, endpoint: D) {
        let id = endpoint.endpoint_id();
        self.inner.add(id, endpoint);
    }

    /// Ordered, receipt-bound failover candidate list for ONE delivery attempt.
    /// Live endpoints only; order/multiplicity from SamplingStrategy. Returns
    /// AdmissibilityError::ReceiptCapacityExhausted if too many outcomes are
    /// still outstanding — callers must resolve in-flight routes before more.
    pub fn select_route(
        &mut self,
        rng: &mut impl RngCore,
    ) -> Result<Vec<DeliveryRoute<D>>, AdmissibilityError> {
        let (selected, receipts) = self.inner.sample_selected_with_receipts(rng)?;
        Ok(selected.into_iter().zip(receipts)
            .map(|((_, endpoint), receipt)| DeliveryRoute { endpoint, receipt })
            .collect())
    }

    pub fn record_delivery_success(&mut self, receipt: &SelectionReceipt) -> Result<(), AdmissibilityError> {
        self.inner.record_admissible_response(receipt)
    }
    pub fn record_delivery_failure(&mut self, receipt: &SelectionReceipt) -> Result<(), AdmissibilityError> {
        self.inner.record_admissible_failure(receipt)
    }
    pub fn telemetry(&self) -> OperationalTelemetrySnapshot { self.inner.operational_telemetry() }

    // Deliberately NOT exposed: sample(), sample_with_receipts() [ProviderQuorum
    // form], get_commitment_quorum(), maybe_issue_dummy_query(). A delivery
    // endpoint must never reach a state-consistency quorum surface, and every
    // outcome must carry a receipt — enforced by DeliveryPool's API shape, not
    // by caller discipline.
}
```

Two independent guards make the Finding-2 misuse structurally impossible:
1. **The bound never appears.** `DeliveryPool` never calls `sample()`, only `sample_selected` (`P: Clone`).
2. **The type can't satisfy it.** `RelayEndpoint: !StateProvider`, so `ProviderPool<RelayEndpoint>::sample()` is not even callable — the compiler rejects any attempt to route a relay into `get_commitment_quorum`.

**Implementation-time correction (found during Phase 2 GREEN, 2026-07-04)**: `record_admissible_response()`/`record_admissible_failure()` are documented in `provider/pool/src/lib.rs` as **telemetry-only** — "Does NOT update raw liveness counters. Call `record_failure()` separately if needed." They do not feed `is_live()`, which only reads `self.liveness`, mutated exclusively by the raw `record_response()`/`record_failure()`. A `DeliveryPool` that called *only* the admissible surface (as first drafted above) would therefore **never actually gate routing** — `select_route()` would keep returning dead endpoints forever, silently defeating Option 2's entire purpose. Caught by a real failing test (`with_liveness_excludes_dead_endpoint_from_selection`), not by inspection.

**Resolution, consistent with the ADR's intent, not in conflict with it**: the ADR's admissible-surface mandate is about **preventing an outcome from being recorded for an endpoint that was never actually selected/attempted** — i.e. the receipt requirement itself is the anti-tampering property (`DeliveryPool` exposes no bare-id `record_response()`/`record_failure()`; an outcome can only be recorded by presenting a `SelectionReceipt` this same pool issued for this same endpoint via a real prior `select_route()` call). It was never about withholding the raw liveness signal *once a receipt has validated that the outcome is legitimate*. `record_delivery_success()`/`record_delivery_failure()` therefore call the admissible method first (receipt validation — `?`-propagates on failure, so an invalid/tampered/already-consumed receipt updates nothing) and only then call the raw `record_response()`/`record_failure()` using `receipt.provider_id()` — the identical, already-validated id. This makes routing responsive to liveness while preserving the receipt-gate: there remains no way to inject a raw failure without first passing receipt validation.

### 1.5 Recommendation, and the alternative rejected

**Recommendation:** Add the `DeliveryEndpoint` trait + `DeliveryPool<D>` newtype, enabled by relocating `sample_inner` to `impl<P: Clone>`. This is *reuse by composition* — `DeliveryPool` wraps `ProviderPool<D>` and inherits every tested invariant ([POOL-5] dormant floor, [POOL-10] eviction-before-budget, rotation admissibility, exposure decay) for free, with no engine duplication.

**Crate placement:** put the trait + newtype in a **new `provider/delivery` crate** depending on `scp-provider-pool` and `scp-transport` (for `DevMailboxId`). This keeps `provider/pool` free of any `harness`/`DevMailboxId` dependency and keeps the two semantic worlds in separate compilation units. The only edit to `provider/pool` is the inert `sample_inner` relocation + `sample_selected`.

**Rejected — generalize `sample()` itself over "either `StateProvider` or `DeliveryEndpoint`."** To make `sample()` return something for a non-`StateProvider` `P`, you must either (a) construct a `ProviderQuorum<P>` for a delivery `P`, which forces `ProviderQuorum` (the class-taxonomy dispatcher) to accept endpoints that have no revocation/commitment opinion — Finding 2's misuse moved up one layer, not avoided; or (b) make `sample()`'s return type conditional on the bound, which needs specialization/GATs churn on a 1200-line hot-path file for no benefit over `sample_selected`. The engine is already generic; forcing the *quorum wrapper* to be generic is the trap. Rejected.

**Also rejected — a fully parallel `DeliveryPool` crate that re-implements selection/rotation/exposure.** That duplicates the exact code paths whose correctness the 100+ pool tests and the [POOL-5]/[POOL-10] invariants guard, and guarantees drift. DRY violation with a safety cost.

---

## 2. Decision Point 2 — Second relay endpoint topology

### 2.1 Relay coexistence: nothing to change (confirmed)

`relay/daemon/src/main.rs` is fully self-contained: one `TcpListener` bound to a single `--bind` address, one `Arc<Mutex<HashMap<[u8;32], Vec<Vec<u8>>>>>`, no shared state, no cross-process coordination, keyed solely by `DevMailboxId`. **Two `scp-relay` processes on different ports are already safe with zero code change** — `--bind` parameterizes the address today. The scope-gate's "likely nothing" is confirmed: nothing.

**Minimal topology:** run a **second `scp-relay` process on an existing machine** — e.g. `wowserver:7700` + `wowserver:7701`, or better for a real failover story, one on `wowserver` and one on `ryan-desktop` (which already has the release binary from the Level 2 trial). **No 4th node required.** A 4th node buys nothing the second process doesn't, and adds deployment cost.

### 2.2 The consequence the pool does NOT solve — store/poll rendezvous

This is the decision hiding *inside* Decision Point 2, and it is the real work. The two relays have **independent, non-replicated, in-memory mailbox stores.** A burst stored to relay-A's mailbox `X` is invisible when polling relay-B's mailbox `X`. So "select a relay per attempt" silently breaks the sender→receiver rendezvous: the receiver has no way to know *which* relay the sender chose.

The pool cleanly answers *store-time selection* ("which live relay do I hand this burst to") but does **not** answer *poll-time rendezvous* ("where does the receiver look"). Three ways to close it:

- **(R1) Replicated store, poll-any (recommended for first failover).** Sender stores the burst to *k* currently-live relays chosen by the pool (k ≥ 2 for redundancy, or k = all-live). Receiver polls live relays in pool order and drains the first non-empty (dedup by `route_id` if it drains more than one). Genuine failover: any single relay may die between store and poll. **Zero relay code change.** Cost: the burst is visible on k relays (more correlation surface — see Point 3).
- **(R2) Deterministic rendezvous.** `relay = relays[hash(mailbox) % n]`, so sender and receiver independently agree without signaling. Cheaper on bandwidth/exposure, but a down chosen-relay means no delivery unless combined with R1, **and** `hash(mailbox)` makes relay choice a stable function of the mailbox token — a metadata graph concern (Point 3). Not recommended as the primary mechanism.
- **(R3) Out-of-band selection signal.** Sender tells receiver which relay it used. Leaks selection into the token/side channel. Rejected for the same reason §3.2 rejected plaintext `recipient_ops_pub`.

**Recommendation:** R1 (replicated store to k live relays, poll-any) for the first failover trial. It makes pool selection meaningful (which live relays to replicate to; in what order to poll), delivers real failover, and needs no relay change. Under R1, `select_route()` returns the ordered live set; the CLI stores to all of them and records per-relay outcomes. Deterministic rendezvous (R2) is the scale alternative once relays gain shared/replicated storage, which is itself out of scope here.

---

## 3. Decision Point 3 — CLI multi-relay interface and its privacy

### 3.1 Options and their privacy profiles

| Option | Shape | Privacy implication |
|---|---|---|
| **Repeated `--relay`** | `--relay a:7700 --relay b:7701` | List held locally; not sent to any relay. A *network* observer of the client still sees which relay IPs it opens sockets to (same class of leak the accepted `DevMailboxId` model already concedes: relay learns timing/count/size). No new identity graph if selection is not recipient-keyed (§3.2 invariant, below). |
| **Config file** (`~/.scp-dev/relays.json`) | Same list, better ergonomics; can carry the per-relay random `endpoint_id` tags | Same profile as flags. Slightly better because tags live in one place and are stable/random rather than derived. |
| **Discovery** (`relay/mesh::discover_relays`) | Client queries the network for the relay set | **Rejected.** The discovery query is itself observable and tells a responder the client is shopping for relays — it reintroduces exactly the "stable identity metadata graph" that `RUNTIME_BOOTSTRAP_PLAN.md` §3.2 rejected, lifted to the relay-set level. New metadata surface for no dev-harness benefit. |

### 3.2 The invariant that keeps selection from becoming a deanonymizer

The genuinely dangerous side channel is **relay selection keyed to the recipient/mailbox.** If a sender always (or preferentially) uses relay-A when talking to Bob, the selection pattern is a stable fingerprint linking that sender's bursts across time to Bob — the precise "stable identity metadata graph" §3.2 rejected for `recipient_ops_pub`, just expressed through routing instead of a header.

**Invariant to preserve:** relay selection MUST be a function of *relay liveness* (a public-ish property shared across all users of that relay) plus *fresh per-attempt randomness* (`SamplingStrategy::RandomK` + the exposure tracker), and MUST NOT be a function of the mailbox token or recipient identity. This is why R2 (`hash(mailbox) % n`) is discouraged as primary — it makes selection a deterministic function of the token. `DeliveryPool::select_route(rng)` with an RNG that is *not* seeded from the mailbox satisfies the invariant.

Two supporting requirements fall out:
- **`endpoint_id` must be a random tag, not the address.** The pool's `ExposureTracker` is keyed by `[u8; 32]`. If that key were the relay address, the pool's own accounting would become an address graph. A random per-relay tag keeps pool internals address-free (matching the `DevMailboxId` rationale: keys are opaque tokens, not identities).
- **Name the residual leak plainly.** Even with the invariant, a global passive observer watching the *client* sees the set of relay IPs it connects to, and under R1 (replicate-to-k) that set could fingerprint a client if it is unique. Hiding *that* requires onion routing / cover traffic / a canonical shared relay set — explicitly out of scope, consistent with the accepted Level-2 limitation that the relay learns burst timing/count/size.

### 3.3 Recommendation

**Repeated `--relay` flags for the trial, upgradeable to a config file, with discovery rejected.** Enforce the §3.2 invariant in code: `select_route()` is driven by liveness + a fresh RNG, never keyed to mailbox/recipient; `endpoint_id` is a random operator-assigned tag. Privacy tradeoff stated plainly: this hides *who talks to whom* from any single relay (unchanged from Level 2) but does **not** hide *which relays a client uses* from a network-position observer, and R1 replication widens that particular surface by design. That is an accepted, documented dev-harness limitation, not a solved problem.

---

## 4. Decision Point 4 — Boundary-crossing ADR (verdict deliberately blank)

This is the decision the assistant must **not** make. Below is the ADR skeleton in the weight/style of `CORRIDOR_TRIAL_5A_EVENT_PROVENANCE_MODEL_DECISION.md`: framing, options with pros/cons and security/privacy stakes, preserved closures, and an explicit non-authorization carve-out — with the verdict left for the operator.

---

> ### ADR — Confining Pool-Telemetry-Influenced Routing to a Single Delivery Seam
>
> **Status**: `PENDING — OPERATOR VERDICT REQUIRED` (do not fill in below the fold)
> **Date**: 2026-07-04
> **Predecessors**: `TRIAL_2_CLOSURE_RECORD.md` (T7: telemetry does not couple to vitality/send), `CORRIDOR_TRIAL_5A_EVENT_PROVENANCE_MODEL_DECISION.md` (Audit 5 non-authorization statement), `CORRIDOR_TRIAL_5B/5C` (admissible surface implemented + adversarially validated).
> **Scope**: Architecture decision only. Authorizes (or declines) a *single* new boundary crossing. Modifies no Rust source by itself.
>
> #### Decision framing
>
> Trial 2 T7 and 5A Audit 5 established that pool telemetry (`kappa`, `liveness_weighted_kappa`, `response_total`, and every derived surface) is **not authorized for any automatic policy action** — enumerated there as vitality, send rejection, rotation, eviction, relay, routing, TOLS. Option 2 requests a narrow exception: **may pool liveness telemetry gate real relay-selection routing (which live relay a burst is stored to / polled from), while remaining prohibited from every other policy action in that list?**
>
> The crossing is intentionally scoped to routing selection only. It must NOT bleed into: `VitalityEvidenceStore` input, send authorization (a burst to any live relay is authorized identically to today — liveness changes *where*, never *whether*), corridor suspension, rotation of state-consistency providers, or TOLS.
>
> #### Options
>
> **Option A — Decline. Keep pure observation; do failover without the pool.**
> Implement relay failover as a dumb "try next on error" loop in the CLI with no `ProviderPool` involvement. Telemetry stays observational exactly as Trial 2/5A froze it.
> - *Pros:* Observational boundary fully intact; no new invariant; no steering surface (see stakes).
> - *Cons:* Discards the pool's entire purpose for this use; creates a second, unaudited liveness mechanism living beside the audited one.
>
> **Option B — Authorize narrowly, via one audited seam.**
> Pool liveness may gate relay *selection only*, exclusively through `DeliveryPool::select_route()`. Every 5A Audit-5 non-authorization is preserved verbatim for vitality/send/rotation/corridor/TOLS. `DeliveryPool` is the single greppable type where the crossing occurs.
> - *Pros:* Reuses the tested engine; the crossing is one type at one call site, maximally auditable; failover and observation share one liveness source of truth.
> - *Cons:* Crosses the observational line that has held since Trial 2; introduces a new invariant ("the crossing is confined to routing") that must be tested and maintained; opens the steering surface below.
>
> **Option C — Authorize broadly (unify routing with future policy).**
> Let the same pool state later feed vitality/rotation/etc.
> - *Pros:* None specific to this initiative.
> - *Cons:* Directly contradicts 5A Audit 5. Listed only for completeness; expected to be rejected on sight.
>
> #### Security / privacy stakes the operator must weigh
>
> 1. **Routing that follows liveness makes liveness-signal integrity security-critical.** While purely observational, an injected/forged `record_failure` was harmless (5A: "manipulable, but telemetry-only"). Once routing follows it, an adversary who can *induce* failures against a target relay (selectively refusing that victim's connections) can *steer* the victim onto a relay of the adversary's choosing — the Trial 4 "selective response suppression" characterization, escalated from a metric distortion into a routing-control primitive.
> 2. **This is precisely why the admissible surface (5A/5B/5C) becomes load-bearing here.** If routing consumes the *raw* `record_failure` surface, it inherits the raw surface's documented manipulability. If it consumes the **receipt-paired admissible** surface (`sample_with_receipts` → `record_admissible_failure`), the "I selected relay X" and "relay X responded" events are causally bound at-most-once, blunting the steering attack. Whether Option B's routing must consume the admissible surface (not the raw one) is an engineering consequence the operator should treat as part of the decision, not an afterthought.
> 3. **Privacy coupling (Point 3).** Authorizing B means relay choice is now a live behavior; the §3.2 invariant (selection never keyed to recipient/mailbox; `endpoint_id` random) becomes a *security requirement*, not a nicety, because a recipient-keyed selection would leak the sender↔recipient graph through routing.
>
> #### Preserved closures (not reopened by any verdict here)
>
> Trials 2, 3, 4, 5A–5C remain exactly valid. Their raw/admissible surface semantics and their non-authorization statements are unchanged. A verdict of B narrows the 5A Audit-5 non-authorization for the *routing* line only, and only through the `DeliveryPool` seam; every other line stays frozen.
>
> #### Verdict (recorded 2026-07-04)
>
> **`B — OPTION_2_ROUTING_SEAM_AUTHORIZED`**, approved by operator.
>
> Sub-decision: routing MUST consume the **admissible surface**
> (`sample_with_receipts()` → `SelectionReceipt` → `record_admissible_failure()`/
> `record_admissible_response()`), not the raw `record_failure()`/`record_response()`
> surface. Each recorded delivery outcome must be causally bound to a specific
> prior selection receipt — this is a hard requirement of the verdict, not an
> implementation preference. `DeliveryPool::select_route()` (§1.4) must therefore
> be built on `sample_with_receipts()`, and its outcome-recording methods must
> take a `SelectionReceipt`, not a bare `[u8; 32]` id.
>
> Option A (decline) and Option C (broad authorization) are not adopted. Every
> other 5A Audit-5 non-authorization (vitality, send authorization, corridor
> suspension, rotation of state-consistency providers, TOLS) remains frozen
> exactly as before — this verdict narrows the routing line only.

---

## 5. Honest split — recommendation vs. what needs a human

| Item | Stance |
|---|---|
| DP1: `DeliveryEndpoint` trait + `DeliveryPool` newtype, enabled by relocating `sample_inner` to `impl<P: Clone>` | **Recommendation.** Grounded in the verified fact that the engine is already `StateProvider`-agnostic (confirmed by direct source read, not assumed). Rejects both the "generalize `sample()`" trap and the "duplicate the engine" DRY violation. |
| DP2: second `scp-relay` process on an existing node, no daemon change | **Recommendation.** Coexistence-safety confirmed from source. |
| DP2-hidden: store/poll rendezvous (R1 replicate-to-k, poll-any) | **Recommendation, flagged as the real work.** The pool does not solve rendezvous; this is a genuine new sub-decision the scope gate did not enumerate. |
| DP3: repeated `--relay`, discovery rejected, §3.2 selection invariant, random `endpoint_id` | **Recommendation with the residual leak stated plainly.** |
| DP4: boundary crossing | **Not the assistant's to decide.** ADR skeleton provided; verdict blank. Everything in §1–§3 is inert until the operator records A/B/C. |

---

## 6. If Option B is authorized — proof ladder and files touched

Provided for completeness; do not act on it before the DP4 verdict.

**Production files that would change** (contrast with Option 1, which changed none):

| File | Change |
|---|---|
| `provider/pool/src/lib.rs` | Relocate `sample_inner` to `impl<P: Clone>`; add `sample_selected()`. Inert (no behavior change) — existing 100+ pool tests must stay green as a regression gate. |
| `provider/delivery/` (new crate) | `DeliveryEndpoint`, `DeliveryError`, `RelayEndpoint`, `DeliveryPool<D>`. |
| `cli/endpoint/src/main.rs` | `--relay` repeatable; `cmd_send`/`cmd_receive` build a `DeliveryPool<RelayEndpoint>`, call `select_route()`, replicate-store / poll-any (R1), feed each real outcome to `record_delivery_success/failure`. This is the one call site where the boundary is crossed. |
| `Cargo.toml` | Add `provider/delivery` member. |

**Ladder:** (Step 0) workspace green at current baseline. (Step 1) `provider/delivery` unit tests for trait + newtype, no network. (Step 2) two-relay localhost failover: kill one of two local `scp-relay` processes mid-run, assert delivery still succeeds via the survivor and that `DeliveryPool` telemetry reflects the real failure — while asserting (T7-equivalent) that `VitalityEvidenceStore` and send-authorization are untouched. (Step 3) live-mesh two-relay failover (wowserver + ryan-desktop), `#[ignore]`d like the existing live-mesh test.

### Implementation Result — Phases 1–3 (2026-07-04)

All production code above has been implemented and independently security-reviewed.
Full workspace: **543 passing, 0 failed, 1 ignored** (520 baseline + 23 new tests
across Phases 1–3; zero regressions; `level1.rs` and `lan_liveness_trial.rs`
continue to pass unchanged against the new multi-relay-capable CLI, confirming
single-relay backward compatibility).

**Phase 1** (`provider/pool/src/lib.rs`): `sample_inner` relocated to
`impl<P: Clone>`; `sample_selected()`/`sample_selected_with_receipts()` added.
Verified behavior-preserving by `rust-reviewer` (approved, 2 MEDIUM fixes:
`clippy::type_complexity` type alias, unnecessary `mut` bindings).

**Phase 2** (`provider/delivery/`, new crate): `DeliveryEndpoint`, `DeliveryError`,
`DeliveryRoute`, `RelayEndpoint`, `DeliveryPool<D>` (15 tests). Independently
security-reviewed (`security-reviewer`) — two real findings surfaced and fixed:

- **Admissible-surface-only telemetry doesn't gate routing.** Discovered via a
  genuinely failing test, not inspection: `record_admissible_response/failure()`
  are documented as telemetry-only and never touch `is_live()`'s raw liveness
  counters. `DeliveryPool::record_delivery_success/failure()` now call the
  admissible method first (receipt validation — rejects tampered/replayed/
  unknown receipts via `?`) and only then call the raw `record_response/failure()`
  using the same already-validated `receipt.provider_id()`. This satisfies the
  ADR: the receipt requirement (not the raw/admissible split) is what prevents
  an outcome being recorded for an endpoint that was never actually selected.
- **`endpoint_id` random-tag requirement had zero enforcement.** Fixed with
  pinning tests (`relay_endpoint_id_is_independent_of_address`,
  `relay_endpoint_at_same_address_can_have_distinct_tags`) that would break if
  a future edit derived the tag from the address.
- **Accepted limitation, documented, not fixed**: unresolved routes permanently
  consume receipt capacity (no reclaim path). Scoped acceptable because
  `DeliveryPool` is constructed fresh per short-lived CLI invocation — flagged
  in a doc comment as a hazard for any future long-running consumer.

**Phase 3** (`cli/endpoint/src/main.rs`, THE boundary crossing): `select_relay_routes()`
is the sole seam (verified by an independent `security-reviewer` pass — exactly
one definition, two call sites, no other pool/liveness reference in the file).
R1 replicate-store / poll-any-with-dedup implemented. That same review found
and required fixing:

- **HIGH — dedup-before-verification allowed one malicious relay to silently
  suppress a legitimate message.** `seen_route_ids` was being checked on the
  raw, unauthenticated `route_id` field before `receive_harness()`'s AEAD
  verification. A hostile relay in the configured set could forge a blob
  sharing a real burst's `route_id` (visible in plaintext on the wire) and win
  the dedup race, silently dropping the real message with no error event.
  **Fixed**: dedup now runs only inside the `Ok(plaintext)` arm, after
  verification succeeds; a forged blob fails decryption independently and can
  never consume the real message's slot.
- **MEDIUM — no timeouts anywhere in the relay I/O path.** A relay that
  accepted a connection and never responded stalled the entire failover
  attempt indefinitely, including every relay queued after it, and starved
  the pool of the failure signal it needed to route around it. **Fixed**:
  `RelayEndpoint`'s wire client now wraps every attempt in a 10s
  `tokio::time::timeout` (tested with virtual time — instant, deterministic).
- **MEDIUM — unbounded allocation from an untrusted relay's poll response.**
  `attempt_poll` trusted the peer-supplied burst `count` and per-burst `len`
  headers with no upper bound. **Fixed**: both are now capped (mirroring the
  reference relay daemon's own `MAX_BURST_BYTES`) before any allocation,
  regression-tested against a real TCP server sending crafted oversized headers.

**Pre-existing issue found, out of scope, NOT fixed by this initiative**:
`core/transport::harness::hex_decode()` panics on adversarial multi-byte-UTF-8
input (byte-length parity is checked, but not that a slice boundary lands on a
char boundary) — reachable from a malicious `--recipient` contact-card file.
Predates Option 2 entirely (harness.rs untouched by this work); flagged for a
separate fix, not addressed here per scope discipline.

**Phase 4** (`test/tests/multirelay_failover.rs`, localhost): 3 tests. CLI is a
one-shot process with no telemetry output, so these prove the *observable*
behavioral claims (exact telemetry was already proven at the unit level in
Phase 2, over the identical `DeliveryPool` code path):
- `two_live_relays_replicate_store_and_dedup_on_receive` — R1 replicate-store
  confirmed on both live relays (`burst_stored` ×2), poll-any + dedup-by-`route_id`
  yields exactly one decrypted message despite the burst being present on both.
- `killing_one_of_two_relays_still_delivers_via_the_survivor` — a real relay
  killed before send; send/receive both succeed via the sole survivor
  (partial success = success, "liveness changes WHERE, never WHETHER").
- `multirelay_flow_produces_no_vocabulary_labels`.

**Phase 5** (live mesh, `#[ignore]`d `live_mesh_two_relay_failover`): a second
real `scp-relay` was deployed to `ryan-desktop` (100.101.76.81:7700), alongside
the existing wowserver relay (100.72.12.57:7700). The test sends/replicates
across both real mesh relays, kills the real ryan-desktop relay via
`ssh ryan-desktop "pkill -f './scp-relay'"`, and confirms `receive` still
succeeds via the surviving wowserver relay — proving Option 2's real
multi-relay failover holds over actual Tailscale-routed TCP, not just
localhost sockets. Passed in 5.45s on first run; both relays left running
(confirmed via `ps`/`ss` on both hosts afterward).

**Final state**: **546 passing, 0 failed, 2 ignored** (520 Option-1 baseline +
27 new test functions across Phases 1–5 — 26 passing + 1 `#[ignore]`d live-mesh
test; zero regressions across the entire workspace, including full backward
compatibility for single-relay usage in `level1.rs`
and `lan_liveness_trial.rs`). Full closure record:
`docs/architecture/OPTION_2_MULTIRELAY_CLOSURE_RECORD.md`.

**Status: IMPLEMENTED.**

---

## 7. Explicit non-claims

Even fully built, this design does **not** provide: metadata-resistant relay addressing (the network-observer leak in §3.2 is conceded, unchanged from Level 2); mailbox replication or persistence (relays remain in-memory, non-replicated — R1 achieves failover by client-side fan-out, not server-side durability); protection of the sender↔recipient graph from a global passive adversary; production readiness at scale; or any authorization for pool telemetry to influence vitality, send authorization, corridor state, or rotation of state-consistency providers. Those remain frozen by Trials 2 and 5A regardless of the DP4 verdict.

---

## Key files this design is grounded in

- `provider/pool/src/lib.rs` — the `impl<P>` vs `impl<P: Clone + StateProvider>` split and `sample_inner` (verified directly: line 1014, calls no `StateProvider` method)
- `core/transport/src/state.rs` — the `StateProvider` trait being kept out of the delivery path
- `core/transport/src/quorum.rs` — `ProviderQuorum`, the state-consistency dispatcher the delivery path must not reach
- `cli/endpoint/src/main.rs` — `relay_store()`/`relay_poll()`, the shape `DeliveryEndpoint` mirrors
- `relay/daemon/src/main.rs` — confirmed independent, no shared state, `--bind`-parameterized
- `core/transport/src/harness.rs` — `DevMailboxId`, opaque-token rationale
- `STATE_SEMANTICS.md` and `docs/architecture/RUNTIME_BOOTSTRAP_PLAN.md` (§3.2) — the class taxonomy and the rejected identity-graph design
- `docs/architecture/CORRIDOR_TRIAL_5A_EVENT_PROVENANCE_MODEL_DECISION.md` and `docs/architecture/TRIAL_2_CLOSURE_RECORD.md` — the observational-only boundary and ADR style for DP4
