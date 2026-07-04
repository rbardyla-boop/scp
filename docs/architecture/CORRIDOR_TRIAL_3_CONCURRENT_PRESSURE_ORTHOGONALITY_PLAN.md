# Trial 3 Plan — Corridor Operation Under Observed Provider Failure

**Status**: `A — TRIAL_3_ORTHOGONALITY_PROOF_SPECIFIED`
**Date**: 2026-05-28
**Predecessor**: `TRIAL_2_CLOSURE_RECORD.md` (464 passing × 3 clean runs)

---

## 1. Trial 3 Objective

Determine whether the SCP simulator can compose:

* the proven vitality-aware encrypted send path from Trial 1c; and
* the proven provider-failure telemetry observation path from Trial 2;

in one deterministic scenario while preserving their current architectural separation.

**Target permitted claim after successful implementation:**

> Under deterministic concurrent simulation, provider-failure telemetry can change
> observably while bilateral vitality evidence and vitality-controlled send authorization
> remain unchanged unless the scenario explicitly changes vitality inputs or evidence.

Trial 3 is an **orthogonality/composition proof**. It is not a telemetry-driven policy
trial. No existing coupling from pool telemetry to vitality or send authorization is
expected; finding one would be a `B — EXISTING_PROVIDER_VITALITY_COUPLING_FOUND` verdict.

---

## 2. Non-Negotiable Policy Boundary

The following connections must **not** be made during Trial 3:

- provider pool output → `SimVitalityEvaluationContext.p`
- provider pool output → `VitalityEvidenceStore`
- provider pool output → `VitalityState`
- provider pool output → `open_and_send_sim()` authorization decisions
- provider pool output → automatic rotation
- provider pool output → TOLS κ policy
- provider pool output → relay behavior

If any such connection is found in existing code: **stop and report**.
If any such connection would need to be created to make a test pass: **stop and report**.

---

## 3. Audit Results

### Audit 1 — Composition feasibility

**Result: Trial 3 can be implemented as a test-only composition using existing seams.**

No production source changes are required.

| Component | Source | API already proven |
|-----------|--------|-------------------|
| `open_and_send_sim()` | `core/transport/src/flash.rs:202` | Trial 1c (trial1c.rs) |
| `VitalityEvidenceStore` | `core/vitality/src/evidence.rs` | Trial 1b, Trial 1c |
| `SimVitalityEvaluationContext` | `core/vitality/src/sim_context.rs` | Trial 1c |
| `ProviderPool::operational_telemetry()` | `provider/pool/src/lib.rs:625` | Trial 2 |
| `ProviderPool::record_failure()` | `provider/pool/src/lib.rs:428` | Trial 2 |
| `ProviderPool::record_response()` | `provider/pool/src/lib.rs:417` | Trial 2 |
| `ProviderPool::sample()` | `provider/pool/src/lib.rs:924` | Trial 2 |

A single test function can construct both a `ProviderPool` and a `VitalityEvidenceStore`,
drive them independently, and assert on both outputs without any shared state.

### Audit 2 — Orthogonality evidence table

The following observations define what "concurrent simulation" must prove:

| Observation | Before provider degradation | After provider degradation |
|-------------|----------------------------|-----------------------------|
| `OperationalTelemetrySnapshot.liveness_weighted_kappa` | Expected healthy value | Changed to expected degraded value |
| `VitalityEvidenceStore` last-reaffirmation timestamp | Exact initialized value | **Unchanged** |
| `VitalityEvidenceStore.compute_state()` under fixed ctx | Active | **Unchanged: Active** |
| `SimVitalityEvaluationContext.p()` | Declared scenario value | **Unchanged** (immutable after construction) |
| `SimVitalityEvaluationContext.i()` | Declared scenario value | **Unchanged** |
| `open_and_send_sim()` result (vitality still open) | `Ok(...)` | **Still `Ok(...)`** |
| `pool.epoch_count()` after `operational_telemetry()` | 0 | **Still 0** |

### Audit 3 — Suspended-control scenario

A complementary control case must also be proven:

1. Provider pool telemetry: healthy (all providers responding, lwk ≈ 0)
2. Bilateral vitality: initialized at t=0, evaluated at t=4_171_664 (Suspended threshold)
3. `open_and_send_sim()` must reject with `VitalityInsufficient(Suspended)`
4. **Pool telemetry must be unchanged by the vitality rejection**

This proves the two pressure dimensions are independently controllable:

- Provider degradation is observable without causing vitality rejection
- Vitality rejection occurs without provider degradation

### Audit 4 — Hidden coupling search

All searches run against the production source tree.

**Search 1:** vitality types in provider-pool crate

```
grep -rn "VitalityState|VitalityEvidenceStore|SimVitality" provider/pool/src/
→ CLEAN: no matches
```

**Search 2:** pool types in vitality crate

```
grep -rn "kappa|OperationalTelemetry|record_response|record_failure|ProviderPool" core/vitality/src/
→ CLEAN: no matches
```

**Search 3:** pool types in transport crate

```
grep -rn "kappa|OperationalTelemetry|ExposureTracker|ProviderPool" core/transport/src/
→ CLEAN: no matches
```

**Search 4:** `scp-provider-pool` dependency graph

```
grep -rn "scp-provider-pool" --include="Cargo.toml"
→ Only in: Cargo.toml (workspace), test/Cargo.toml, provider/pool/Cargo.toml
```

`scp-provider-pool` is **not** a dependency of `scp-vitality`, `scp-transport`,
`relay/mesh`, `relay/perturbation`, `relay/cache`, `relay/daemon`, or `cli/endpoint`.

**Search 5:** `SimVitalityEvaluationContext.p` is immutable

`SimVitalityEvaluationContext` has private fields and no `set_p()` method.
`p()` returns a `f64` copy. No mutable access exists outside the constructor.

**Verdict: No hidden coupling found.** The two systems share no state path.

### Audit 5 — Proposed tests

Eight deterministic tests covering the full orthogonality surface:

| Test | Scenario | Key invariant |
|------|----------|---------------|
| T1 | Healthy pool + Active vitality | `open_and_send_sim()` succeeds; pool telemetry unchanged after send |
| T2 | Degraded pool telemetry + Active vitality | Send still succeeds; vitality evidence unchanged after pool failures |
| T3 | Silent provider failure + Active vitality | `lwk > kappa`; `VitalityEvidenceStore` timestamp unchanged |
| T4 | Explicit pool failures + fixed `ctx.p` | `ctx.p()` same before/after; `compute_state()` same before/after |
| T5 | Healthy pool + Suspended vitality | Send rejected; pool telemetry unchanged by rejection |
| T6 | Degraded pool + reaffirmation restores vitality | Send transitions fail→succeed; pool kappa unchanged throughout |
| T7 | Pool recovery changes telemetry; vitality unchanged | `lwk` 1.0→0.0; `evidence_timestamp` unchanged |
| T8 | Both surfaces observed simultaneously | `epoch_count = 0`; `evidence_timestamp` unchanged after full exercise |

### Audit 6 — Scope decision

**Recommendation: Option A — Test-only composition.** No orchestration architecture needed.

The test file is a straightforward composition of helpers already proven in
`test/tests/trial1c.rs` and `test/tests/trial2.rs`. No new seams are required.

---

## 4. API Reuse from Trial 1c and Trial 2

The following helpers from `trial1c.rs` are reused verbatim in `trial3.rs`:

```rust
fn register_bilateral_consent(ledger, kp_a, kp_b) -> [u8; 32]
fn publish_ephemeral_at(ledger, ops_kp, sim_now) -> [u8; 32]  // eph_secret
fn std_ctx(consent_hash, now) -> SimVitalityEvaluationContext  // i=1.0, r=1.0, p=0.0
fn warm_cache() -> WarmCache
fn passthrough() -> PerturbationEngine
```

The following helpers from `trial2.rs` are reused verbatim in `trial3.rs`:

```rust
fn pid(byte: u8) -> [u8; 32]
fn seeded() -> StdRng  // StdRng::seed_from_u64(0)
```

---

## 5. Deterministic Scenario Sequence

Each test follows this structure:

```
1. Set up identity:
   - alice_kp = KeyPair::generate()
   - bob_kp   = KeyPair::generate()
   - ledger   = SubstrateLedger::new()
   - ch       = register_bilateral_consent(&ledger, &alice_kp, &bob_kp)

2. Set up vitality:
   - store = VitalityEvidenceStore::new()
   - store.initialize_at(ch, t_init)   // fixed t_init, typically 0

3. Set up transport:
   - publish_ephemeral_at(&ledger, &bob_kp, sim_now)  // fresh ephemeral
   - ctx = std_ctx(ch, sim_now)

4. Set up provider pool:
   - pool = ProviderPool::new(SamplingStrategy::RandomK(1))
   - pool.add(pid(1), SubstrateLedger::new())
   - pool.add(pid(2), SubstrateLedger::new())
   (optional) pool.with_liveness(...)

5. Drive pool trace (deterministic):
   - fixed sample(), record_response(), record_failure() sequence

6. Snapshot telemetry:
   - snap_pre = pool.operational_telemetry()  (optional, before perturbation)
   - snap = pool.operational_telemetry()

7. Invoke send path (where relevant):
   - result = FlashSession::open_and_send_sim(&ledger, &store, &ctx, &bob_kp.public, ...)

8. Snapshot vitality state:
   - vitality_state = store.compute_state(ch, sim_now, 1.0, 1.0, 0.0)

9. Assert exact expected values from the fixed trace (see §6 below)
```

All clocks use `sim_now` (a declared `u64` constant per test), not `SystemTime::now()`.
All pool traces use `seeded()` for sample() or direct `record_*()` calls.

---

## 6. Proposed Test Specifications

### T1 — `t1_healthy_pool_and_active_vitality_compose_without_interference`

**Setup:** 4 providers, 4 sample() calls (seeded), 4 record_response() per provider.
Vitality initialized at t=0, evaluated at t=0 (Active).

**Exact assertions:**
- `snap.liveness_weighted_kappa = 0.0` (uniform 4-provider response; exact from Trial 2 T1)
- `send_result.is_ok()` (Active → send permitted)
- `store.compute_state(ch, 0, 1.0, 1.0, 0.0) = VitalityState::Active`
- `pool.epoch_count() = 0`

---

### T2 — `t2_degraded_pool_telemetry_does_not_block_vitality_open_send`

**Setup:** 2 providers, `with_liveness(2, u64::MAX)`. `record_failure(pid(2))` × 2 → dead.
4 sample() calls → only pid(1) selected. `record_response(pid(1))` × 4.
Vitality initialized at t=0, evaluated at t=0 (Active).

**Exact assertions:**
- `snap.kappa = 1.0` (exact: only pid(1) in selections)
- `snap.liveness_weighted_kappa = 1.0` (exact: only pid(1) in responses)
- `send_result.is_ok()` (degraded pool does NOT block Active vitality send)
- `store.compute_state(ch, 0, 1.0, 1.0, 0.0) = VitalityState::Active` (evidence unchanged)

---

### T3 — `t3_silent_pool_failure_leaves_vitality_evidence_timestamp_unchanged`

**Setup:** 2 providers. 8 sample() calls (seeded). `record_response(pid(1))` × 8. pid(2) silent.
Vitality initialized at t=0, evaluated at t=1_000.

**Exact assertions:**
- `snap.liveness_weighted_kappa = 1.0` (exact: only pid(1) in responses)
- `snap.liveness_weighted_kappa >= snap.kappa` (silent-failure distinction; from Trial 2 T3)
- `store.compute_state(ch, 1_000, 1.0, 1.0, 0.0) = VitalityState::Active` (evidence timestamp unchanged; t=1000 << Active→Warm threshold)

---

### T4 — `t4_explicit_pool_failure_does_not_alter_vitality_context_controls`

**Setup:** 4 providers. Declare `ctx = SimVitalityEvaluationContext::new(ch, 0, 1.0, 1.0, 0.5)`.
Drive `record_failure(pid(i))` × 5 for all 4 providers.

**Exact assertions:**
- `ctx.p() = 0.5` (SimVitalityEvaluationContext is immutable; field is private; no pool method can change it)
- `ctx.i() = 1.0`
- `ctx.r() = 1.0`
- `store.compute_state(ch, 0, ctx.i(), ctx.r(), ctx.p()) = VitalityState::Active` (state computed with same controls as before failures)
- Pool failures and vitality evaluation both produce expected values independently

---

### T5 — `t5_suspended_vitality_rejects_send_while_pool_telemetry_healthy`

**Setup:** 4 providers, 4 sample() calls (seeded), 4 record_response() per provider.
Vitality initialized at t=0, evaluated at t=4_171_664 (past Suspended threshold).

**Exact assertions:**
- `snap.liveness_weighted_kappa = 0.0` (healthy pool; exact from Trial 1 T1 derivation)
- `send_result = Err(TransportError::VitalityInsufficient(VitalityState::Suspended))`
- `snap_after_rejection.liveness_weighted_kappa = 0.0` (send rejection does NOT alter pool)
- `pool.epoch_count() = 0` (no rotation from the rejection path)

---

### T6 — `t6_reaffirmation_restores_send_without_altering_pool_telemetry`

**Setup:** 2 providers, pid(2) dead (record_failure × 2), 4 sample() calls, record_response(pid(1)) × 4.
Vitality: initialized at t=0, first evaluated at t=4_171_664 (Suspended).
Reaffirmation: `store.record_reaffirmation(ch, 4_171_664)`.
Second evaluation: same t=4_171_664, fresh ephemeral.

**Exact assertions:**
- `snap.kappa = 1.0` (exact: dead pid(2) excluded throughout)
- `first_send_result = Err(TransportError::VitalityInsufficient(VitalityState::Suspended))`
- `second_send_result.is_ok()` (Active after reaffirmation)
- `snap_after_reaffirm.kappa = 1.0` (pool state unchanged by reaffirmation)

---

### T7 — `t7_pool_recovery_changes_telemetry_without_refreshing_vitality_evidence`

**Setup:** 2 providers, `with_liveness(2, u64::MAX)`. pid(2) → dead (record_failure × 2).
4 sample() calls (pid(1) only). record_response(pid(1)) × 4.
Intermediate snapshot: `lwk = 1.0`.
Recovery: `record_response(pid(2))` × 4 (first call resets consecutive_failures=0).
Vitality initialized at t=0.

**Exact assertions:**
- Pre-recovery: `snap_pre.liveness_weighted_kappa = 1.0` (exact)
- Post-recovery: `snap_post.liveness_weighted_kappa = 0.0` (exact: equal responses)
- `store.compute_state(ch, 1_000, 1.0, 1.0, 0.0) = VitalityState::Active`
  (vitality evidence timestamp still at t=0; pool recovery does not write to evidence store)

---

### T8 — `t8_full_orthogonality_both_surfaces_exercised_simultaneously`

**Setup:** 2 providers, `with_liveness(2, u64::MAX)`. pid(2) → dead (record_failure × 2).
4 sample() calls. record_response(pid(1)) × 4.
Vitality initialized at t=0, evaluated at t=0.

**Exact assertions:**
- `snap.kappa = 1.0`, `snap.liveness_weighted_kappa = 1.0` (degraded pool)
- `send_result.is_ok()` (Active vitality, degraded pool; independently true)
- `store.compute_state(ch, 0, 1.0, 1.0, 0.0) = VitalityState::Active` (evidence unchanged)
- `pool.epoch_count() = 0` (no rotation from any path in this test)

---

## 7. Files to Create

**Created by implementation (1 file):**
- `test/tests/trial3.rs` — 8 deterministic tests

**Updated by closure (1 file):**
- `docs/architecture/TRIAL_3_CLOSURE_RECORD.md` — created after successful verification

**Modified during planning (0 files):**
Production source is not modified during this trial.

---

## 8. Expected Test Count

| Source | Count |
|--------|-------|
| Current workspace baseline (Trial 2) | 464 |
| New Trial 3 tests | 8 |
| Expected new total | **472** |

Three consecutive clean runs at 472 / 472 / 472 required for verdict A.

---

## 9. Permitted Claim and Non-Claims

### Permitted claim after successful Trial 3

> Under deterministic concurrent simulation, provider-failure telemetry changes
> observably while bilateral vitality evidence and vitality-controlled send
> authorization remain unchanged unless the scenario explicitly changes vitality
> inputs or evidence. The two systems compose without interference in the proven
> simulator paths.

### Explicit non-claims

Trial 3 does **not** prove:

- Provider degradation should alter `SimVitalityEvaluationContext.p` automatically
- Telemetry thresholds should control `VitalityEvidenceStore` updates
- Provider failure should suspend a corridor or block a send
- Provider telemetry should feed the vitality formula as a production input
- TOLS κ integration with provider-pool κ
- `liveness_weighted_kappa` is safe for automatic policy decisions
- Relay routing, mailbox delivery, or relay privacy under failure
- Localhost, LAN, desktop, or hardware readiness
- Production provider orchestration or real network failure semantics

---

## 10. Pre-Implementation Checkpoint

Before writing `trial3.rs`, confirm:

- [ ] Helper functions from trial1c.rs and trial2.rs will be re-declared locally
      (test files are independent binaries; cross-test imports are not available)
- [ ] All `pub use` exports needed: `OperationalTelemetrySnapshot`, `EpochPhase`,
      `ProviderPool`, `SamplingStrategy` from `scp_provider_pool`; and all
      trial1c helpers from `scp_transport`, `scp_vitality`, `scp_ledger_substrate`
- [ ] No policy decision is required — this is a composition proof
- [ ] No authorization, routing, rotation, or relay semantics are tested

---

## 11. Verdict

```
A — TRIAL_3_ORTHOGONALITY_PROOF_SPECIFIED
```

Trial 3 is implementable as test-only using existing public and test-accessible seams.
No production source change is required. No policy decision is needed before
implementation. The audit found no hidden coupling. The proposed tests fully cover
the orthogonality surface defined in the Trial 3 objective.
