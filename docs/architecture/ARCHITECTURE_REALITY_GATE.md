# Architecture Reality Gate

**Status**: Active gate. Pre-conditions listed in Section 7 must be satisfied before gated work proceeds.

This document gates a set of SCP architectural assumptions that are analytically coherent but not yet empirically validated. It identifies two classes of concern: (1) operator and user mental models that require real-traffic or real-user validation before they can be treated as authoritative, and (2) a system boundary violation that must be prevented before integration work begins.

---

## 1. OPERATOR_DOCTRINE Pre-Operative Status

`OPERATOR_DOCTRINE.md` is currently a complete and internally consistent document. It is not disputed on technical grounds.

It is pre-operative. All guidance in OPERATOR_DOCTRINE.md assumes relay mesh traffic exists and has been reviewed by an operator. As of this writing, no relay traffic data exists. The document describes a control loop interpretation framework for a system that has not yet been exercised under real load.

**Mandatory revision trigger**: OPERATOR_DOCTRINE.md must be reviewed and revised after the first meaningful real-traffic sample set is collected. Meaningful is defined as: at least 100 relay sessions processed by a mesh with two or more nodes. Until that revision occurs, operators must treat OPERATOR_DOCTRINE.md as a theoretical framework, not empirically validated guidance.

The signal classification table in Section 3 of OPERATOR_DOCTRINE.md is particularly affected. The five signal classes — Self-resolving, Adaptive, Operational, Structural, Suspicious — and their per-signal assignments were derived analytically from the control model. They were not derived from observed failure mode distributions. The class assignments may be correct; they have not been confirmed against real failure data. Operators who act on the Section 3 table are acting on an unvalidated prior.

---

## 2. Minimal Human-Facing Corridor Test

The six vitality words (Active, Warm, Dormant, Suspended, Severed, Burned) must be tested with real users before they become UX law. The following protocol defines the minimum acceptable test.

### Setup

In-person bilateral setup. Two users who know each other, each holding a device with a registered SCP identity. No remote or asynchronous setup. Both parties must be physically present for the duration of the test session.

### State Transitions to Test

1. Active to Warm: simulate time passage or a reduced exchange rate until the vitality score drops below the Active threshold.
2. Warm to Dormant: extend the quiet period until the vitality score drops below the Warm threshold.
3. Dormant recovery via reaffirmation: one party sends a contact attempt. Reaffirmation is defined as a bilateral exchange that brings the vitality score above the Dormant threshold. Both parties must participate; a unilateral message does not constitute reaffirmation.

### Capture Question

After each state transition, ask each user independently: "What is the status of your connection with [other party]?"

Record whether the user correctly interprets the state:

- Active: both parties are actively and recently exchanging
- Warm: the connection is stable and healthy, but quiet
- Dormant: the connection needs attention and can be recovered
- Suspended: one party has deliberately stepped back
- Severed: the connection has been formally and permanently closed
- Burned: a security incident has been detected on this corridor

Users are not coached on state meanings before the session. Interpretation is evaluated against the definitions above.

### Pass Criterion

At least 80% of participants correctly interpret each state without coaching,
AND no participant produces a critical misinterpretation for that state.

A critical misinterpretation is a response that could cause unsafe trust behaviour
and is plausibly caused by the label itself. It vetoes a term even if the 80% threshold
is otherwise met. Specific veto triggers per term are documented in `CORRIDOR_SCORING_RUBRIC.md` Part A.
Ambiguous responses count as Not Correct for the 80% calculation.

### Minimum Sample

Five bilateral pairs (ten users) before any vitality state label is considered UX-validated. Testing fewer than five pairs does not satisfy this gate regardless of pass rate.

---

## 3. Vitality Words Requiring Validation

All six words are drawn from `core/vitality/src/state.rs`.

| Word | Current definition | Validation question |
|------|--------------------|---------------------|
| Active | High vitality — recent, reciprocal exchange | Do users understand this means both parties are actively engaged? |
| Warm | Stable low-frequency trust — corridor is healthy but quiet | Do users understand "warm" implies health, not degradation? |
| Dormant | Cooling — no recent exchange; reaffirmation suggested | Do users read "dormant" as fixable rather than broken? |
| Suspended | Reduced visibility — contact suspended by one party | Do users correctly attribute "suspended" to a deliberate act by one party? |
| Severed | Explicit revocation — corridor formally closed | Do users understand Severed is permanent and intentional? |
| Burned | Security distrust — cryptographic incident detected | Do users understand Burned implies a security incident, not just a broken connection? |

Warm and Dormant carry the highest risk of misinterpretation. In everyday usage, "warm" can imply something that is declining from hot, and "dormant" commonly implies something that is as good as dead. The SCP intent is the opposite: Warm is healthy, Dormant is recoverable. These two words must clear the 80% threshold before any user-facing surface uses them without an explicit inline explanation.

---

## 4. TOLS Boundary and Nomenclature Collision

### Nomenclature Collision

Two quantities in the SCP codebase share the symbol κ. They are different mathematical objects.

**SCP κ** is entropy-based provider convergence pressure, defined as `1 - entropy_bits / log₂(active_n)`. It is implemented in `provider/pool/src/metrics.rs`. It measures how concentrated the adversary's posterior over active-set membership is. A value of 0 indicates fully uniform provider selection; a value of 1 indicates fully concentrated selection.

**TOLS κ** is the Gram-matrix condition number over stored patterns. It is a linear algebra quantity measuring the ill-conditioning of the pattern storage matrix. It has no relationship to entropy, provider selection, or adversarial posterior estimation.

These are different mathematical objects that share a Greek letter. This is a nomenclature collision, not a conceptual overlap. Future documentation and code must use "SCP κ" and "TOLS κ" explicitly whenever both systems are in scope. The unqualified symbol κ is ambiguous and must not be used in any cross-system context.

### Production Integration Prohibition

No production TOLS integration is authorized. TOLS must not be wired into any of the following:

- `ProviderPool` or any component in `provider/`
- Vitality scoring in `core/vitality/`
- Perturbation generation in any relay or corridor code
- Relay mesh coordination code

SCP routing and TOLS token routing solve different problems. SCP routing selects providers under adversarial pressure to minimize posterior concentration. TOLS token routing organizes latent representations for retrieval. These are not the same problem. Architectural similarity at the routing level does not imply integration is safe or meaningful.

### Artifact Lens Relocation Recommendation

The Artifact Lens project currently resides at `tolsv3/artifact_lens_project/` within the SCP repository. This placement creates an implicit dependency signal that does not reflect the actual production dependency, which is zero.

The recommended action is to move Artifact Lens and the entire `tolsv3/` directory out of the SCP repository into a dedicated `tols-research` repository with no import path into SCP production code.

If a future isolated TOLS research or incubation crate is created within the SCP workspace, it may exist only under the constraint that it carries no dependency path into production relay code. That constraint must be enforced at the Cargo workspace level, not by convention.

---

## 5. What Must Not Proceed Yet

The following specific claims and work items are blocked. The project is not globally blocked —
see Section 11 for the authorized Runtime Bootstrap Sprint lane.

**Blocked:**
- Dynamical criticality analysis — blocked pending estimator-validity closure (Phase 38 verdict: LIVENESS_WEIGHTED_KAPPA_REQUIRED_AS_TELEMETRY_FOR_SILENT_FAILURE) and the remaining reality-gate criteria below. Phase 37's causal-attribution criterion is satisfied, but dynamical criticality remains blocked until the full gate is cleared.
- Promoting liveness_weighted_kappa into automatic policy — blocked until noise and adversarial manipulability are characterised. It is approved for telemetry-only use as established by Phase 38.
- TOLS integration into SCP runtime behaviour — blocked permanently unless explicit authorization is granted and documented in this file.
- Treating OPERATOR_DOCTRINE.md as empirically validated guidance — blocked until the first real-traffic revision is complete.
- Treating any vitality word as UX law — blocked until Stage H1 (10-person formal gate) passes for that word.
- Hardcoding vitality vocabulary (Active, Warm, Dormant, Suspended, Severed, Burned) into any user-facing UI or onboarding flow — blocked until Stage H1 passes.
- Adding any additional simulator-only analytical control layer.
- Claiming SCP is installable or multi-device ready until a runnable surface at Level 1 or above (see Section 11) exists.

**Not blocked:**
- Headless runtime bootstrap work per Section 11.
- Stage H0 smoke test with 3 individuals using the frozen Version 1.2 wireframe packet.
- Documentation and architecture planning that does not introduce new vocabulary claims.

---

## 6. Gate Completion Criteria — Human Lane

### Staged corridor test (replaces previous single-stage requirement)

**Stage H0 — Smoke test** (3 individuals, exploratory):
- [ ] Run Version 1.2 wireframe with 3 individuals who have not been briefed on SCP.
- [ ] Record verbatim responses. No pass/fail threshold — purpose is to catch obviously
      dangerous misinterpretations before the formal gate.
- [ ] If ≥ 2 of 3 misread the same term, or any blame/betrayal framing appears, treat
      that term or flow as suspect and revise before Stage H1.
- H0 authorizes continuation of headless runtime work regardless of outcome.

**Stage H1 — Formal gate** (10 individuals, gate-quality):
- [ ] Run with 10 individuals not briefed on SCP. Must reach ≥ 8/10 Correct per term
      with no critical-misinterpretation veto.
- [ ] Must be satisfied before any vitality vocabulary is hardened in a user-facing client,
      onboarding flow, or client-facing demo.

(The original requirement of "5 bilateral pairs" corresponds to Stage H1. H0 is a new
pre-filter. Participants in H0 may not be reused in H1 — they have seen the instrument.)

## 6a. Gate Completion Criteria — Phase Ledger

- [x] Phase 37 PROVIDER_ORIGINATED_DEGRADATION_DETECTED_AND_CORRECTED verdict delivered
      Satisfied: §S34–§S38 tests pass. POLYTOPE_DETECTS_ORTHOGONAL_ROTATION_THRASH_UNDER_NEVER_RESET
      classification confirmed. T1 is simulator-exercisable through provider-originated liveness failure
      (active_window=2). Eviction + replacement restores health without inducing T2 thrash.
      EvictionCooldown blocks immediate offender readmission.
- [x] Phase 38/38R estimator-validity closure: liveness_weighted_kappa noise and adversarial
      manipulability characterised before promotion to policy
      Satisfied (with Phase 39 closure): §S41–§S58 establish the telemetry role, detection
      envelope, reset-policy comparison, adversarial gaming scenario (§S58), and symmetric
      failure blind spot (§S55). Promotion remains blocked — gaming confirmed.
      Phase 38R verdict: B+C — T1_IS_A_CATASTROPHIC_SURVIVING_SET_COLLAPSE_SIGNAL_NOT_A_PARTIAL_PROVIDER_FAILURE_SIGNAL;
      LIVENESS_WEIGHTED_KAPPA_DETECTS_ASYMMETRIC_SILENT_FAILURE_BUT_POLICY_PROMOTION_REMAINS_UNSAFE. See §8 for full ledger.
- [x] Phase 39 liveness observability decomposition: catastrophic diversity collapse (κ/T1),
      asymmetric silent failure (liveness_weighted_κ), and symmetric availability loss
      separated into distinct, falsifiable observability surfaces.
      Satisfied: §S52–§S58 pass. Adversarial gaming confirmed (§S58) — liveness_weighted_κ
      promotion remains blocked. Symmetric failure blind spot confirmed (§S55–§S56).
      Verdict: A+C — THREE_ORTHOGONAL_LIVENESS_SURFACES_REQUIRED;
      ABSOLUTE_AVAILABILITY_BLIND_SPOT_CONFIRMED; RESPONSE-RATE TELEMETRY IDENTIFIED
      BUT NOT YET FORMALIZED OR TRUSTED FOR POLICY. See §9.
- [x] Phase 40 operational telemetry contract: OperationalTelemetrySnapshot formalizes all
      three liveness surfaces as a single typed, operator-readable snapshot with evidence context,
      evaluability flags, and no composite health score. absolute_availability surface derived
      from real sample() opportunities and record_response() observations. Bounded by
      ExposureResetPolicy. Both Surface 2 and Surface 3 remain TELEMETRY-ONLY.
      Satisfied: §S59–§S66 pass (388 → 396 total). See §10.
- [ ] First real-traffic relay session set collected (minimum 100 sessions, minimum 2 mesh nodes)
- [ ] OPERATOR_DOCTRINE.md reviewed and revised post-traffic
- [ ] Corridor test executed with a minimum of 5 bilateral pairs (10 users)
- [ ] All 6 vitality words validated at 80% or higher correct interpretation rate
      with no critical misinterpretations (veto overrides percentage — see §2)
- [ ] Artifact Lens moved out of the SCP repository, or explicitly retained with a documented rationale appended to this section

---

## 7. Phase 38 Status

**Phase**: 38 — T1 Detection Envelope and Estimator Freshness
**Verdict**: C — LIVENESS_WEIGHTED_KAPPA_REQUIRED_AS_TELEMETRY_FOR_SILENT_FAILURE
**Tests added**: §S41–§S47 (7 tests, 370 → 377 total passing)
**Date satisfied**: 2026-05-27

### Detection-Envelope Table

| active_n | failed | reset policy | forced rotation | margin_t1 | liveness_weighted_κ detects | classification |
|----------|--------|--------------|-----------------|-----------|-----------------------------|-|
| 2 | 1/2 | Never | No | > 0 (no fire) | yes (silent failure) | T1 blind; liveness required |
| 4 | 1/4 | Never | No | > 0 (no fire) | yes | T1 blind; liveness required |
| 8 | 1/8 | Never | No | > 0 (no fire) | yes | T1 blind; liveness required |
| 8 | 4/8 | Never (long) | No | > 0 (no fire) | yes | T1 blind; diluted by history |
| 8 | 4/8 | Never (short) | No | > 0 (no fire) | yes | T1 marginal; κ elevated |
| 4 | 3/4 | Never | No | > 0 | yes (§S43) | hard failure visible via κ without rotation |
| 8 | 4/8 | Never | No | > 0 | yes (§S46) | selective suppression: κ blind, liveness detects |

### Key Findings

1. **T1 is a false-equilibrium detector, not a provider-failure detector.** It fires when
   pressure_budget(0.5) is high — requiring κ > 0.5 most of the time. Provider failure raises
   κ to 0.036–0.19 (for pool sizes 4–2), never reaching the 0.5 threshold in the tested
   observation windows under Never reset.

2. **Never-reset history dilutes failure visibility.** A 1 000-epoch warm pool with 4/8 providers
   failing shows κ ≈ 0.007, versus κ ≈ 0.25 for a 20-epoch warm pool with identical failure.
   The ratio exceeds 30× (§S42). T1 does not fire in either case.

3. **Hard failure is visible without forced rotation.** Selection concentrates on surviving
   providers after liveness eviction; κ rises and liveness_weighted_κ rises independently
   of rotation policy (§S43). total_rotations = 0 confirmed throughout.

4. **liveness_weighted_κ detects silent failure that κ cannot see.** When providers are selected
   uniformly but only one records responses, liveness_weighted_κ rises above 0.15 while
   κ < 0.05 — a gap of > 0.15 (§S44). For 4/8 selective suppression on n=8, the gap
   exceeds 0.20 (§S46). This makes liveness_weighted_κ indispensable as telemetry.

5. **Benign intermittent silence does not false-trigger.** A 10-call gap in responses followed
   by 400 uniform responses keeps liveness_weighted_κ < 0.05 due to Never-reset accumulation
   absorbing the distortion (§S45).

6. **Eviction recovery does not cause T2 instability.** Evicting 2 of 18 providers and adding
   2 replacements, with QueryCount(100) rotation, yields rotation_rate ≈ 0.01 and
   margin_t2 > 0 throughout the recovery phase (§S47).

### Explicit Statements Required by Phase 38 Specification

**Is failure observable without forced rotation?**
Yes. Hard failure (is_live = false) is observable through κ rising due to selection
concentration, with total_rotations = 0 confirmed (§S43). Silent failure is observable
through liveness_weighted_κ diverging from κ, also without any rotation (§S44).

**Are Never-reset semantics safe for provider-failure detection?**
With qualifications. Never-reset accumulates historical exposure that dilutes the κ signal —
a 1 000-epoch warm pool shows 30× less κ elevation than a 20-epoch warm pool for identical
failure rates (§S42). For hard failure detection via κ alone, Never-reset is insufficient
when the warm history is long relative to the failure observation window. For liveness-based
detection (liveness_weighted_κ), Never-reset dilutes the response-distribution signal by
the same mechanism. **Bounded freshness or OnRotation reset is required for κ-based T1
detection to remain valid at operational observation timescales.**

---

## 8. Phase 38R Status

**Phase**: 38R — Ledger Reconciliation and Freshness Closure
**Verdict**: B+C — T1_IS_A_CATASTROPHIC_SURVIVING_SET_COLLAPSE_SIGNAL_NOT_A_PARTIAL_PROVIDER_FAILURE_SIGNAL;
             LIVENESS_WEIGHTED_KAPPA_DETECTS_ASYMMETRIC_SILENT_FAILURE_BUT_POLICY_PROMOTION_REMAINS_UNSAFE
**Tests added**: §S48–§S51 (4 tests, 377 → 381 total passing)
**Date satisfied**: 2026-05-27

### Test Ledger Reconciliation

Phase 37 recorded "Before: 378, After: 391, Delta: +13" in memory. This was incorrect.

**Authoritative ledger — verified by `cargo test --workspace`:**

| Phase | Before | After | Delta | Note |
|-------|--------|-------|-------|------|
| Pre-Phase-36 baseline | — | 370 | — | actual workspace count before any §S2x tests |
| Phase 37 (§S29–§S38 + alias) | 370 | 370 | 0 | Claimed +13, but actual delta was +0 at workspace level |
| Phase 38 (§S41–§S47) | 370 | 377 | +7 | Confirmed |
| Phase 38R (§S48–§S51) | 377 | 381 | +4 | Confirmed |

**Explanation of the 391 discrepancy:** Phase 37 memory claimed sim_s39 and sim_s40 as delivered
tests. Neither exists in `scp/test/tests/sim.rs`. The gap between sim_s38 (line 2072) and sim_s41
(line 2182) confirms this. The Phase 37 session counted planned-but-unwritten tests and reported
them as delivered. The actual workspace count before Phase 38 was 370, not 391.

The authoritative count after Phase 38R is **381 total tests, 0 failures**.

### Phase 38R Freshness Comparison Results

| scenario | pool history | κ at end | liveness_weighted_κ | T1 fires? | classification |
|----------|-------------|----------|---------------------|-----------|----------------|
| n=4 hard fail, 1000 warm (Never equiv.) | deep | ≈ 0.003 | n/a | no | diluted — T1 blind |
| n=4 hard fail, 0 warm (OnRotation equiv.) | fresh | ≈ 0.207 | n/a | no | fresh — T1 still blind |
| n=4 hard fail, 10 warm (AfterEpochs equiv.) | bounded | ≈ 0.170 | n/a | no | bounded — T1 still blind |
| n=4 silent fail, Never | deep | ≈ 0 | low (≈ 0.04) | no | diluted liveness signal |
| n=4 silent fail, OnRotation | fresh | ≈ 0 | high (≈ 0.207) | no | fresh liveness signal |
| n=4 benign gap + recovery, OnRotation | fresh window | ≈ 0 | < 0.05 | no | no false trigger |

### Key Findings

1. **T1 is a catastrophic surviving-set collapse signal, not a partial provider failure signal.**
   The mathematical boundary is κ_survival(n,s) = 1 − log₂(s)/log₂(n) > 0.5 iff s < √n.
   For n=4 with 1/4 failing (s=3): κ ≈ 0.207 — T1 does not fire. For n=4 with 3/4 failing
   (s=1): κ = 1.0 — T1 fires. With zero pre-failure warm history (the maximally fresh OnRotation
   state), κ still reaches only ≈ 0.207 for moderate failure at n=4 — T1 does not fire regardless
   of history depth until collapse is catastrophic (§S48, §S52, §S53).

2. **Bounded freshness (AfterEpochs) is implemented and improves the κ signal.** A 10-epoch max
   history yields κ ≈ 0.170 vs κ ≈ 0.003 for Never after 1 000 warm epochs. The detection
   signal is meaningfully better, but the T1 threshold remains unreachable (§S50).
   BOUNDED_FRESHNESS_POLICY_IMPLEMENTED confirmed.

3. **OnRotation amplifies liveness_weighted_κ for silent failure.** Fresh response windows
   show only responders; silent providers appear immediately with liveness_weighted_κ ≈ 0.207
   vs ≈ 0.04 under Never with warm dilution (§S49). The signal is 5× stronger.

4. **OnRotation does not false-trigger after benign silence.** A response gap that is erased
   by the next rotation reset does not accumulate into a permanent false positive (§S51).

5. **Auto-rotation heals hard failure without explicit eviction.** With ChurnBudget{1,1} and
   QueryCount(n), a dead provider is randomly selected for dormant-swap with probability 1/active_n
   per rotation. After 7 rotations, P(still dead in active) ≈ (3/4)^7 ≈ 0.13. Hard failure
   self-heals through rotation before the detection window closes — this limits the operational
   usefulness of κ-based hard failure detection in pools with active auto-rotation.

### Explicit Statements Required by Phase 38R

**What does T1 actually detect?**
T1 is a catastrophic surviving-set collapse signal. The κ_survival formula is:
κ_survival(n,s) = 1 − log₂(s)/log₂(n), where s = number of live providers.
T1 fires (κ > 0.5) iff s < √n. For n=4: fires only when s < 2, i.e., 3/4 or more fail.
For n=8: fires only when s < 2.83, i.e., 6/8 or more fail (s ≤ 2). Moderate partial failure
never crosses the threshold. T1 is not a partial provider failure detector — it is a signal
that the active set has catastrophically collapsed to near-single-provider concentration (verdict B).

**Does any existing freshness policy make T1 fire for moderate failure?**
No. All three policies (Never, OnRotation, AfterEpochs) leave T1 silent for moderate failure
at pool sizes n ≥ 4. The fundamental limit is κ_survival(n,s): even with s = n−1 (one failure),
maximum κ for n=4 is ≈ 0.207, far below 0.5. This is not a calibration error — it is the
correct mathematical boundary for catastrophic collapse detection (verdict B continued).

**Is liveness_weighted_κ still required after freshness characterisation?**
Yes. For silent failure (provider selected but not responding), liveness_weighted_κ is the
only signal visible to the system regardless of reset policy. κ stays near zero because
selection remains uniform. liveness_weighted_κ detects the imbalance in response history.
This role is unaffected by reset policy (verdict C).

**Can liveness_weighted_κ be promoted to automatic policy now?**
No. Adversarial manipulability remains uncharacterised. Policy promotion is blocked until
that characterisation is complete. liveness_weighted_κ remains telemetry-only (verdict C).

---

## 9. Phase 39 Status

**Phase**: 39 — Liveness Observability Decomposition
**Verdict**: A+C — THREE_ORTHOGONAL_LIVENESS_SURFACES_REQUIRED;
             ABSOLUTE_AVAILABILITY_BLIND_SPOT_CONFIRMED;
             RESPONSE-RATE TELEMETRY IDENTIFIED BUT NOT YET FORMALIZED OR TRUSTED FOR POLICY
**Tests added**: §S52–§S58 (7 tests, 381 → 388 total passing)
**Date satisfied**: 2026-05-27

### Objective

Separate catastrophic diversity collapse, asymmetric silent failure, and symmetric availability
loss into distinct, falsifiable observability surfaces. Demonstrate that:

1. κ/T1 signals catastrophic collapse (s < √n) but is blind to moderate partial failure
2. liveness_weighted_κ detects asymmetric silent failure but is blind to symmetric global degradation
3. A response-rate proxy (absolute availability) detects symmetric degradation that both
   entropy metrics miss

### The Symmetric Failure Blind Spot

Phase 38R proved liveness_weighted_κ detects asymmetric silent failure. It does not detect
symmetric global failure: when all providers degrade equally (same response rate, same latency
degradation), the response distribution remains uniform. Both κ and liveness_weighted_κ remain
near zero. The service may be unusable while all three entropy metrics report healthy.

### Required Tests

| Test | Scenario | Key assertion |
|------|----------|---------------|
| sim_s52 | κ/T1 boundary matches κ_survival math | n=4,s=3: no fire; n=4,s=1: fires; n=8,s=4: no fire; n=8,s=2: fires |
| sim_s53 | Moderate failure not labelled as collapse | margin_t1 > 0 for moderate failure at n≥4 |
| sim_s54 | Asymmetric silent failure elevates liveness_weighted_κ | lwk >> 0, κ ≈ 0 |
| sim_s55 | Symmetric global failure invisible to entropy metrics | κ ≈ 0, lwk ≈ 0, response_rate << 1 |
| sim_s56 | Availability proxy detects symmetric failure | response_rate_healthy >> response_rate_degraded |
| sim_s57 | Benign global latency recovers without alarm | no false positive after full recovery |
| sim_s58 | Response gaming suppresses liveness signal | adversary normalises lwk; promotion unsafe |

### Implementation Constraints

- Do not lower the existing T1 kappa threshold in this phase.
- Do not promote liveness_weighted_kappa into automatic eviction, rotation, or admission policy.
- Adding a telemetry-only absolute availability metric is allowed if no existing metric captures
  symmetric global degradation.
- Keep any new telemetry observational, deterministic, and testable.
- Do not begin dynamical criticality.
- Do not integrate TOLS into production SCP paths.

### Verdict Options

- **A**: THREE_ORTHOGONAL_LIVENESS_SURFACES_REQUIRED — all three surfaces are needed; no two collapse into one
- **B**: EXISTING_METRICS_ALREADY_CAPTURE_ABSOLUTE_AVAILABILITY — tests show an existing metric
  already captures symmetric failure; no new metric needed
- **C**: ABSOLUTE_AVAILABILITY_BLIND_SPOT_CONFIRMED_BUT_METRIC_NOT_YET_AVAILABLE — blind spot
  demonstrated, availability proxy computable in tests but not yet a built-in pool API
- **D**: LIVENESS_WEIGHTED_KAPPA_SAFE_FOR_POLICY_PROMOTION — adversarial gaming fully
  characterised and mitigated (do not issue this verdict unless §S58 is conclusively closed)

---

## 10. Phase 40 Status

**Phase**: 40 — Operational Telemetry Contract and Observation Integrity
**Verdict**: OPERATIONAL_TELEMETRY_CONTRACT_DELIVERED;
             ABSOLUTE_AVAILABILITY_FORMALIZED_AS_TELEMETRY_ONLY;
             OBSERVATION_INTEGRITY_LIMIT_CONFIRMED
**Tests added**: §S59–§S66 (8 tests, 388 → 396 total passing)
**Date satisfied**: 2026-05-28

### Objective

Formalize all three liveness surfaces into a single operator-readable, telemetry-only
observation contract: `OperationalTelemetrySnapshot` in `provider/pool/src/metrics.rs`.
Expose it through `ProviderPool::operational_telemetry()`. Carry evidence context on each
surface. Add no automatic policy. Confirm the observation integrity limit.

### OperationalTelemetrySnapshot Fields

| Field | Surface | Policy-authoritative? |
|-------|---------|----------------------|
| `kappa` | 1 — Survivor concentration | Yes (T1 margin unchanged) |
| `liveness_weighted_kappa` | 2 — Relative liveness distortion | No — TELEMETRY-ONLY |
| `liveness_surface_evaluable` | 2 evidence context | — |
| `response_total` | 3 — Absolute availability | No — TELEMETRY-ONLY |
| `selection_total` | 3 evidence context (window bound) | — |
| `availability_evaluable` | 3 evidence context | — |
| `current_epoch_phase` | Shared evidence context | — |
| `active_n` | Shared evidence context | — |
| `recent_response_success_rate()` | 3 derived rate | No — TELEMETRY-ONLY |

No composite health score field exists on the struct.

### Test Ledger

| Test | Proves |
|------|--------|
| §S59 | Three surfaces have distinct values; orthogonality confirmed |
| §S60 | Symmetric outage detected by Surface 3 while κ and lwk remain near zero |
| §S61 | Zero window is unevaluable; must not be read as "healthy" |
| §S62 | OnRotation reset bounds the observation window; post-rotation window is fresh |
| §S63 | Benign latency recovery clears the bounded-window availability rate |
| §S64 | Response injection inflates Surface 3; observation integrity limit confirmed |
| §S65 | Degraded telemetry does not trigger rotation or eviction (Manual policy) |
| §S66 | Snapshot has three independently varying fields; no single-score collapse |

### Scenario Coverage Table

| Scenario | κ | κ_L | Availability rate | Evaluable | Policy action | Operator-visible degradation |
|----------|---|-----|-------------------|-----------|---------------|------------------------------|
| Healthy uniform pool | ≈ 0 | ≈ 0 | ≈ 1.0 | yes | none | none warranted |
| Asymmetric silent failure | ≈ 0 | > 0.5 | low (≈ 0.25) | yes | none | yes — Surface 2 elevated |
| Symmetric global outage | ≈ 0 | ≈ 0 | < 0.10 | yes | none | yes — Surface 3 only |
| Survivor-set collapse | > 0.5 | any | any | yes | T1 fires | yes — Surface 1 fires |
| Benign temporary latency | ≈ 0 | ≈ 0 | recovers to ≈ 1.0 | yes | none | none after recovery |
| Response-gaming | ≈ 0 | suppressed | inflated | yes | none | integrity limit exposed |
| Zero observations | 1.0 | 1.0 | None | no | none | unevaluable, not healthy |

### Explicit Constraint Confirmations

- T1 threshold NOT lowered or retuned.
- `liveness_weighted_kappa` NOT promoted to automatic policy.
- Absolute availability Surface 3 NOT promoted to automatic policy.
- Dynamical criticality NOT started.
- TOLS production integration NOT performed.
- No automatic eviction, rotation, or admission triggered by Surface 2 or Surface 3.

### Remaining Blocks

The following remain blocked after Phase 40:

- **Dynamical criticality analysis** — blocked until corridor test passes (Section 2) and
  first real-traffic session set is collected (Section 6, bullet 4).
- **liveness_weighted_κ policy promotion** — blocked until adversarial gaming is fully
  characterised and §S64 integrity limit is closed by a cryptographic verification path.
- **Absolute availability policy promotion** — blocked for the same reason: §S64 confirms
  the metric can be gamed by response injection; policy use requires authentication of
  the response record.
- **TOLS production integration** — permanently blocked unless explicit authorization is
  documented in this file.
- **Treating OPERATOR_DOCTRINE.md as empirically validated** — blocked until first real
  traffic revision.
- **Treating any vitality word as UX law** — blocked until corridor test passes.

**After Phase 40, do not proceed to another simulator-only analytical phase until actual
corridor-test results are recorded.** See Section 2 for the corridor test protocol.

The Runtime Bootstrap Sprint (Section 11) is explicitly authorized in parallel with the
human corridor test. It must not encode user-facing vitality labels.

---

## 11. Runtime Bootstrap Sprint — AUTHORIZED

**Status**: Authorized in parallel with Stage H0 corridor test. Scope gate verdict A recorded.
**Scope gate verdict**: `A — TRIAL_0_IMPLEMENTATION_AUTHORIZED_WITH_HARNESS_ONLY_OPAQUE_MAILBOX_ROUTING`
**Constraint**: This sprint must not expose or hardcode user-facing vitality labels.
Use machine-event language only (`identity_created`, `relay_listening`, `payload_received`,
`payload_decrypted`, `exchange_complete`). No Active, Warm, Dormant, Suspended, Severed,
or Burned in any CLI output until Stage H1 human gate passes.

### Objective

Build the smallest headless vertical slice that demonstrates two processes can exchange
an SCP-encrypted payload through a relay daemon and produce verifiable log evidence.

### Authorized work

- Receiver-side decrypt path (after scope gate verdict A)
- Test-only identity persistence (file-based, dev harness, NOT production keystore claims)
- Standalone relay daemon with mailbox delivery
- Headless endpoint CLI: `keygen`, `send`, `receive`/`listen`
- Localhost multi-process integration test (Level 1)
- Clean LAN deployment across laptop + two desktops (Level 2, after Level 1 passes)

### Proof ladder

| Level | What it proves | Required before |
|-------|---------------|-----------------|
| 0 | Existing workspace tests green | Always required |
| 1 | Multi-process localhost end-to-end exchange | Level 2 |
| 2 | Clean LAN deployment: laptop + 2 desktops | Hardware lab useful |
| 3 | Packaged install | Out of scope this sprint |

### What this sprint does NOT authorize

- User-facing UI or vocabulary in CLI output
- Claims of installability or production readiness
- Dynamical criticality analysis
- Additional simulator-only analytical phases
- TOLS production integration
- Desktop Linux OS installation (not useful until Level 1 passes)

### Scope gate

Before any implementation code is written, `docs/architecture/RUNTIME_BOOTSTRAP_PLAN.md`
must be complete and its scope gate verdict must be:
- **A — TRIAL_0_IMPLEMENTATION_AUTHORIZED_WITH_HARNESS_ONLY_OPAQUE_MAILBOX_ROUTING**: ✓ ISSUED — coding authorized. Protocol decision on relay addressing resolved; plaintext `recipient_ops_pub` routing rejected; harness-only opaque `DevMailboxId` approved.
- **B — RECEIVER_DECRYPT_REQUIRES_PROTOCOL_DECISION**: resolved; see verdict A above.
- **C — RELAY_ARCHITECTURE_BLOCKS_VERTICAL_SLICE**: not triggered.

