# SCP Operator Doctrine

This document governs how operators interpret SCP's observability surface, what actions are safe
or destabilizing under each system state, and what the signals explicitly do and do not mean.

SCP's control mechanics are correct by construction and verified by test. The remaining failure
mode is interpretation: the operator receives valid signals and responds in ways that destabilize
the control loop from the outside. This document exists to prevent that class of failure.

---

## 1. The Three Failure Classes

SCP can fail operationally in three distinct ways:

| Class | Description | Who handles it |
|-------|-------------|----------------|
| Mechanical failure | The controller produces incorrect outputs given valid inputs. | Tests and implementation. |
| Estimator failure | Signals are structurally invalid because the estimator lacks sufficient history. | Self-resolving. Operator waits. |
| Interpretation failure | Signals are valid. The operator's response is wrong. | This document. |

This document governs Class 3. It is the only failure class that is not self-correcting.
Interpretation failures compound: a wrong action produces a wrong state, which produces a
wrong signal, which prompts another wrong action. Doctrine breaks that loop.

---

## 2. Observability Surface

All operator-visible signals are exposed through `convergence_pressure()` and `exposure_estimate()`.
They are grouped here by what they measure.

### Convergence layer (selection distribution)

These signals are derived from the history of `sample()` calls.

| Field | Range | What it measures |
|-------|-------|-----------------|
| `kappa` | [0.0, 1.0] | Normalized entropy deficit. 0 = fully uniform selection. 1 = fully concentrated. Defined as `1 − entropy_bits / log₂(active_n)`. |
| `smoothed_kappa` | [0.0, 1.0] | EWMA-lagged κ. Responds slowly to sudden changes. Lags raw κ by approximately `1/α` samples. Used by `EntropyTriggered`, `VelocityTriggered`, `BurstTriggered`. |
| `kappa_velocity` | [-1.0, 1.0] | κ_current − κ_prev across the epoch boundary. Positive = pressure worsening. None before first rotation. |
| `accumulated_pressure` | [0.0, ∞) | Integral of κ(t) since the last rotation. Non-zero only when policy is `IntegralTriggered`. |
| `spectral_concentration` | [0.0, 1.0) | `max_selection_rate − 1/active_n`. Zero when perfectly uniform. Grows as one provider dominates selections. |
| `confidence_growth_rate` | [0.0, 1.0] | Marginal adversary confidence gain per additional sample at the current observation count. Approaches zero as confidence saturates. |
| `samples_to_saturation` | `Option<u64>` | Remaining samples until adversary membership confidence for the most-exposed provider exceeds 0.5. `None` when max rate is zero. |
| `epoch_divergence` | `Option<f64>` | JSD between the current and previous epoch's selection distributions. Low = stagnation. `None` before first rotation. |

### Liveness layer (response distribution)

These signals are derived from the history of `record_response()` calls.

| Field | Range | What it measures |
|-------|-------|-----------------|
| `liveness_weighted_kappa` | [0.0, 1.0] | `1 − response_entropy_bits / log₂(active_n)`. Rises above `kappa` when providers are selected but not responding. 1.0 when no responses recorded. |
| `smoothed_liveness_weighted_kappa` | [0.0, 1.0] | EWMA-lagged liveness κ. Lags behind `liveness_weighted_kappa`. |

### Structural layer (pool topology)

These signals are derived from the pool's own configuration and history.

| Field | Range | What it measures |
|-------|-------|-----------------|
| `active_n` | usize | Active provider count at snapshot time. |
| `transition_entropy` | `Option<f64>` | `log₂(C(active_n, k̄)) + log₂(C(dormant, k̄))`. Higher = rotation is harder to predict. `None` when dormant is empty. |
| `active_set_halflife_epochs` | `Option<f64>` | Expected epochs until 50% of the current active set has been replaced. `None` before first rotation. |
| `total_samples` | u64 | Sample calls recorded since the last tracker reset. Primary input to the T4 estimator gate. |
| `current_epoch_phase` | `EpochPhase` | PostReset / Reconverging / Steady. Governs which rotation policies are admissible. |

### ExposureEstimate (raw tracker fields)

| Field | What it measures |
|-------|-----------------|
| `selection_entropy_bits` | Raw Shannon entropy of the selection distribution. |
| `response_entropy_bits` | Shannon entropy of the response distribution. Dead providers contribute 0. |
| `response_total_samples` | Total `record_response()` calls since the last reset. |

---

## 3. Signal Classification

Every signal falls into one of five classes. The class determines the correct operator response.

| Class | Meaning | Correct operator response |
|-------|---------|--------------------------|
| **Self-resolving** | Clears without intervention. The system is in a transient but expected state. | Wait. Do not act. |
| **Adaptive** | The controller will respond if policy is correctly configured. | Verify policy configuration. Do not force. |
| **Operational** | Requires human inspection of provider availability or topology. | Inspect. Do not tune thresholds. |
| **Structural** | Requires topology change: add providers or expand the dormant reserve. | Add capacity. |
| **Suspicious** | Possible adversarial pressure. Pattern warrants investigation. | Alert and inspect. Do not lower thresholds. |

Per-signal classification:

| Signal | Class | Notes |
|--------|-------|-------|
| `current_epoch_phase == PostReset` | Self-resolving | Clears after `active_n` sample calls. κ = 1.0 here is correct and expected. Never disable the T4 gate. |
| `current_epoch_phase == Reconverging` | Self-resolving | Clears after `4 × active_n` samples. Entropy thresholds are not yet meaningful. |
| `DeferralReason::Cooldown` | Self-resolving | Auto-clears after `min_duration`. No action needed. |
| `DeferralReason::EstimatorNotConverged` | Self-resolving | T4 gate fired correctly. Clears when Steady phase is reached. |
| `DeferralReason::PolicyThresholdNotMet` | Adaptive | Controller is functioning. Policy condition not yet met. Wait. |
| `DeferralReason::DormantEmpty` | Structural | No providers available for rotation. Add providers. |
| `DeferralReason::DormantBelowFloor` | Structural | Pool too small for full diversification. Target `total ≥ 2 × active_window`. |
| `kappa` rising | Adaptive | Controller will respond if an entropy-sensitive policy is configured and Steady phase is active. |
| `kappa_velocity > 0` sustained across multiple epochs | Suspicious | Diversification is regressing. Possible topology compromise or passive Sybil accumulation. |
| `liveness_weighted_kappa >> kappa` | Operational | Providers selected but not responding. Inspect availability. Do not remove providers immediately. |
| `smoothed_liveness_weighted_kappa` persistently rising | Operational | Liveness degradation is not transient. Sustained inspection warranted. |
| `epoch_divergence` persistently low | Suspicious | Active-set distribution is stagnating across epochs. Patient adversary convergence is possible. |
| `samples_to_saturation` approaching zero | Informational | Adversary confidence is accumulating for the most-exposed provider. Rotation should fire if policy is configured. |
| Repeated `BurstTriggered` events | Suspicious | Possible forced-trajectory attack. Inspect. Do not lower `min_burst_magnitude`. |
| `accumulated_pressure` growing slowly | Adaptive | `IntegralTriggered` is accumulating. Will fire at threshold. Wait. |

---

## 4. Joint-State Semantics

`kappa` and `liveness_weighted_kappa` are orthogonal signals. They must be read together.
Reducing them to a single scalar destroys the information the dual-channel model was built to provide.

| κ | liveness_κ | State | Meaning | Operator action |
|---|-----------|-------|---------|-----------------|
| low | low | **Healthy** | Selection is uniform. Providers are responding. | No action. |
| high | high | **Concentrated + degraded** | Selection is concentrated and providers are failing. | Rotation should be firing. Inspect topology and admission history. |
| low | high | **Silent degradation** | Selection appears uniform but providers are not responding. Routing is operationally impaired. | Inspect provider availability. The controller will **not** self-correct this without a liveness-aware policy. |
| high | low | **Adversarial pressure, routing intact** | Selection is concentrated but providers are responding. Possible Sybil accumulation or passive observation. | Rotation should be firing. Inspect admission history. |

**The (low κ, high liveness_κ) quadrant is the most dangerous state.**

It is the only state in which SCP reports healthy selection metrics while routing is materially
degraded. This is the classic observer failure: the measurement is technically correct, but the
system is not functioning as intended. κ cannot detect this alone. That is precisely why
`liveness_weighted_kappa` was introduced as a separate signal.

Operators who observe this quadrant must inspect provider availability before taking any other
action. The correct response is not tuning — it is inspection.

---

## 5. EpochPhase Semantics

The estimator is not always valid. `current_epoch_phase` classifies the current estimator state
and determines which rotation policies the controller will accept.

| Phase | Condition | Estimator status | Admissible policies |
|-------|-----------|-----------------|---------------------|
| **PostReset** | `total_samples < active_n` | Invalid. κ = 1.0 by construction. | None. All policies deferred. |
| **Reconverging** | `active_n ≤ total_samples < 4 × active_n` | Partial. Insufficient samples for entropy-derived policies. | `QueryCount`, `TimeBased`, `Hybrid`, `JitteredTimeBased`. |
| **Steady** | `total_samples ≥ 4 × active_n` | Reliable. Law of large numbers applies. | All policies. |

### What operators must understand about EpochPhase

**PostReset is expected and correct.** It occurs immediately after pool creation and after every
rotation when `ExposureResetPolicy::OnRotation` is configured. κ = 1.0 during PostReset is not
an error. It is the mathematically correct output of an entropy computation over an empty sample
history. Do not interpret it. Do not retune.

**The T4 admissibility gate is not a bug.** When `maybe_rotate()` returns
`Deferred(EstimatorNotConverged)`, the gate is functioning correctly. Entropy-dependent policies
blocked during PostReset or Reconverging would fire on meaningless estimator state, producing
rotation behavior decoupled from actual distribution pressure.

**Critical rule: never retune thresholds based on metrics observed during PostReset or
Reconverging.** Calibration performed on invalid estimator state will not reflect steady-state
behavior. The resulting configuration will be wrong in ways that are not immediately detectable
but will misfire consistently once the pool reaches Steady phase.

---

## 6. Deferral Reason Guide

When `maybe_rotate()` returns `RotationOutcome::Deferred(reason)`, the reason specifies exactly
why rotation did not occur. Each reason has a distinct correct and incorrect response.

| DeferralReason | What it means | Correct response | Wrong response |
|---------------|---------------|-----------------|----------------|
| `DormantEmpty` | No providers available to rotate in. Terminal until `add()` or `complete_admission()` is called. | Add providers to the dormant reserve. | Call `force_rotate()`. It will not help — DormantEmpty blocks `force_rotate()` too. |
| `DormantBelowFloor` | Dormant count is below `active_window`. Full diversification requires `dormant ≥ active_window`. | Add providers. Target `total ≥ 2 × active_window`. | Lower `active_window` to paper over the shortage. This reduces diversity, not the problem. |
| `Cooldown` | The rate-limiting window is active. Will auto-clear after `min_duration`. | Wait. | Bypass with `force_rotate()`. This defeats the rate limit and risks T2. |
| `EstimatorNotConverged` | The T4 gate blocked an entropy-dependent policy during PostReset or Reconverging. | Wait for sample accumulation. Steady phase will be reached automatically. | Call `force_rotate()` as a workaround, or retune thresholds. Both are wrong. |
| `PolicyThresholdNotMet` | The policy's trigger condition has not been reached. Controller is working. | Wait. The threshold will be crossed when pressure builds. | Call `force_rotate()` to preemptively rotate. This bypasses the control loop. |

**`force_rotate()` bypasses Cooldown and PolicyThresholdNotMet. It does not bypass DormantEmpty
or DormantBelowFloor.** Repeated `force_rotate()` calls are the primary mechanism by which
operators manually induce T2 (churn exhaustion): the dormant reserve is depleted faster than
it is replenished, until rotation becomes structurally impossible.

---

## 7. Safe and Unsafe Operator Actions

| Action | Safety | Reason |
|--------|--------|--------|
| Adding providers to the dormant reserve | **Safe** | Expands the entropy reserve. Always beneficial. |
| Waiting during PostReset or Reconverging | **Safe** | Estimator self-clears. No action required. |
| Calling `maybe_rotate()` on a regular schedule | **Safe** | Correct usage pattern. |
| Calling `force_rotate()` once to seed an initial epoch | **Conditionally safe** | Only when the dormant reserve is populated and the pool has never rotated. |
| Disabling or bypassing the T4 estimator gate | **Unsafe** | Entropy-dependent policies fire on invalid estimator state, producing rotation behavior unmoored from actual distribution pressure. |
| Retuning thresholds during PostReset or Reconverging | **Unsafe** | Calibration on invalid estimator state produces wrong configuration that misfires consistently in Steady phase. |
| Calling `force_rotate()` repeatedly | **Unsafe** | Induces T2. Depletes the dormant reserve. Rotation becomes structurally impossible. |
| Lowering rotation thresholds in response to repeated burst detections | **Unsafe** | `min_burst_magnitude` is a signal gate. Lowering it in response to frequent triggers increases the system's sensitivity to a signal that may itself be adversarially manipulated. |
| Removing providers in response to liveness divergence alone | **Unsafe** | Conflates availability degradation with adversarial presence. Reduces the dormant reserve and may accelerate the problem. |
| Globally synchronizing thresholds across independent pools | **Unsafe** | Couples epistemically independent failure modes. Creates a common-mode attack surface: an adversary who learns the shared threshold can optimize against all pools simultaneously. |
| Exporting full-fidelity diagnostics externally | **Unsafe** | Converts bounded diagnostic signals into adversarial information. DeferralReason sequences, exact κ trajectories, and burst timestamps reveal control-loop timing. Export only coarse aggregate health indicators. |
| Adjusting EWMA alpha (smoothing parameter) frequently | **Unsafe** | The anti-thrashing properties of smoothed signals depend on α stability across epochs. Frequent adjustment resets the smoothing memory and may re-trigger recently suppressed policies. |
| Manually clearing exposure history outside of a rotation | **Dangerous** | Restarts the PostReset window. `total_samples` drops to zero. All entropy-dependent policies are deferred until Steady phase is reached again. |

---

## 8. Escalation Semantics

| Severity | Meaning | Example signals | Response |
|----------|---------|-----------------|----------|
| **Informational** | Expected dynamics. No action required. | PostReset after rotation, Cooldown active, samples accumulating, `kappa_velocity` fluctuating around zero. | Monitor only. |
| **Warning** | Approaching a boundary. Inspection warranted but action not yet required. | `samples_to_saturation < 100`, `liveness_weighted_kappa − kappa > 0.1` for one epoch, `kappa_velocity > 0` for two consecutive epochs. | Inspect. Do not tune. |
| **Critical** | Bounded survivability is threatened. Human action is required. | `DormantBelowFloor` persists after adding sample capacity, `epoch_divergence` persistently below 0.1, (low κ, high liveness_κ) sustained across multiple epochs. | Increase dormant reserve or inspect provider availability. Do not force-rotate. |
| **Existential** | The control loop cannot self-correct. Operator intervention is required immediately. | `DormantEmpty`, multiple providers simultaneously failing liveness checks, repeated burst detections concurrent with rising `kappa_velocity`. | Switch to `Manual` policy. Halt all forced rotations. Inspect admission history. Diagnose before restarting actuation. |

**At Existential severity, the correct first action is to reduce actuation, not increase it.**

The instinct under pressure is to act. But at Existential severity the system is in a state where
automatic responses are as likely to amplify the problem as to resolve it. Stop. Diagnose. Restart
controlled actuation only after the cause is understood.

---

## 9. Operator Non-Goals

The following actions are explicitly prohibited regardless of system state. They represent the
most common pathways from valid observation to self-induced instability.

**1. Manually optimize κ toward zero.**
Low κ is not a performance target. It is a measurement. κ near zero during PostReset is estimator
invalidity, not success. κ near zero with high liveness_κ is silent routing degradation, not
health. Optimizing κ in isolation produces a metric that looks good while the system degrades.

**2. Maximize rotation frequency.**
The dormant reserve is finite. Rotation velocity beyond what the control loop prescribes depletes
the reserve faster than it is replenished. The controller already responds to pressure with
appropriate rotation velocity. Additional forced rotations compound the structural constraint
rather than resolving the pressure that prompted them.

**3. Globally synchronize thresholds across pools.**
Each pool operates on a local, independent epoch. Shared thresholds couple failure modes and
create a single adversarial target. An attacker who learns a shared threshold can optimize
against all pools simultaneously. Pools must remain epistemically independent.

**4. Force uniform provider participation.**
The weighting subsystem (reputation, liveness) exists to discount providers that are
adversarially active, unreliable, or overrepresented. Manually overriding weights to restore
apparent uniformity defeats the resistance those weights provide. Let the controller weight.

**5. Export full-fidelity diagnostics externally.**
DeferralReason sequences, exact κ trajectories, and burst detection timestamps are bounded
diagnostic signals. External export converts them into adversarial information. A patient observer
with access to full diagnostic telemetry can reconstruct control-loop timing, infer active-set
transitions, and design forcing attacks. Export only coarse aggregate indicators.

**6. Retune thresholds during estimator invalidity.**
Any threshold calibration performed while `current_epoch_phase != Steady` will be wrong. The
estimator does not yet reflect steady-state distribution behavior. The resulting configuration
will misfire in ways that are not immediately visible but will be consistent and hard to diagnose.

**7. Treat `liveness_weighted_κ` as a rotation actuator.**
As of this writing, `liveness_weighted_kappa` is a telemetry signal. Its noise profile, adversarial
manipulability (selective response suppression), and interaction with T1–T4 have not been fully
characterized. Connecting it to automatic rotation before that characterization is complete would
introduce a new adversarial forcing surface of the same class as T2. Liveness_κ must mature as
telemetry before it becomes policy.

---

## 10. Epistemic Boundaries

What SCP signals mean, may mean, and must not be interpreted as.

---

### `κ ≈ 0` (low convergence pressure)

- **DOES mean:** The selection distribution is approximately uniform over the active set.
- **MAY mean:** The adversary's posterior over active-set membership is diffuse, under the
  uniform selection assumption.
- **DOES NOT mean:** The adversary is not observing traffic.
- **DOES NOT mean:** Providers are honest.
- **DOES NOT mean:** The relay layer is diverse.
- **DOES NOT mean:** The pool is resistant to Sybil attack.
- **DOES NOT mean:** Providers are reachable. Selection diversity and routing liveness are
  orthogonal. See `liveness_weighted_kappa`.

---

### `liveness_weighted_κ >> κ` (liveness gap)

- **DOES mean:** Providers are being selected but are not returning responses to
  `record_response()` calls.
- **MAY mean:** Provider availability is degraded (network, process, or hardware failure).
- **MAY mean:** The liveness signal is being adversarially manipulated through selective
  response suppression.
- **DOES NOT mean:** The system has been compromised.
- **DOES NOT mean:** Providers should be removed immediately. Removal reduces the dormant
  reserve and may accelerate the structural problem.
- **DOES NOT mean:** κ-based rotation policies will self-correct this. They will not, because
  they do not observe the response distribution.

---

### `EpochPhase::PostReset` with `κ = 1.0`

- **DOES mean:** The estimator has insufficient sample history. `κ = 1.0` is the
  mathematically correct output of `1 − 0 / log₂(active_n)` when entropy is zero.
- **DOES NOT mean:** The active set is compromised or concentrated.
- **DOES NOT mean:** Thresholds are too high.
- **DOES NOT mean:** Rotation failed or the controller is broken.

---

### `DeferralReason::EstimatorNotConverged`

- **DOES mean:** The T4 admissibility gate correctly blocked an entropy-dependent policy
  because the estimator is not yet in Steady phase.
- **DOES NOT mean:** The rotation system is broken.
- **DOES NOT mean:** `force_rotate()` is the correct workaround.
- **DOES NOT mean:** The policy thresholds should be lowered to make the policy fire sooner.

---

### Repeated `BurstTriggered` events

- **DOES mean:** Raw κ is spiking above smoothed_κ by more than `min_burst_magnitude`,
  repeatedly.
- **MAY mean:** A forced-trajectory attack is underway: the adversary is inducing bursts to
  predict rotation timing.
- **MAY mean:** Natural distribution variance is triggering the detector during a low-sample
  epoch.
- **DOES NOT mean:** `min_burst_magnitude` should be raised (which would blind the detector)
  or lowered (which would increase sensitivity to adversarial manipulation).
- **DOES NOT mean:** The `BurstTriggered` policy should be disabled.

---

### `epoch_divergence` persistently low

- **DOES mean:** The selection distribution is not changing much across epoch boundaries.
  The current active set produces a distribution that closely resembles the previous epoch's.
- **MAY mean:** The active set has stabilized in a configuration that is observable by a
  patient adversary — the adversary's membership model is converging.
- **DOES NOT mean:** Rotation is broken. Rotation may have occurred, but the newly activated
  providers happen to produce a similar distribution.
- **DOES NOT mean:** Churn should be increased. Higher churn without expanded dormant reserve
  accelerates T2.

---

## 11. Rotation Policy Selection Guide

Choosing the wrong policy for an environment is a common source of operational failure. This
table maps deployment contexts to appropriate policies.

| Context | Recommended policy | Avoid |
|---------|--------------------|-------|
| Unknown environment, first deployment | `Manual` + periodic `force_rotate()` | Any entropy-dependent policy until Steady phase is observed |
| Time-sensitive privacy requirements | `JitteredTimeBased` | `TimeBased` — predictable cadence leaks rotation timing |
| Reactive to distribution pressure | `EntropyTriggered` | `QueryCount` alone — does not respond to distribution shape |
| Detecting gradual adversarial drift | `VelocityTriggered` | `ConvergenceTriggered` alone — reacts to level, not trajectory |
| Detecting sustained moderate pressure | `IntegralTriggered` | `ConvergenceTriggered` — responds to peaks, not accumulated area |
| Resisting forced-trajectory attacks | `BurstTriggered` with non-zero `response_jitter_max` | `BurstTriggered` with `response_jitter_max = 0` — zero jitter makes rotation timing predictable |
| Defense-in-depth, multi-threat model | `Hybrid` combining time + entropy | Relying on a single policy for orthogonal failure modes |
| Mobile or clock-hostile environments | `QueryCount` or `JitteredTimeBased` | `TimeBased`, `IntegralTriggered` — both depend on monotonic wall-clock accuracy |
| Embedded or resource-constrained | `QueryCount` | Any EWMA-dependent policy — smoothing requires stable alpha across epochs |

### Policy admissibility during estimator lifecycle

All entropy-dependent policies — `EntropyTriggered`, `JsdTriggered`, `ConvergenceTriggered`,
`VelocityTriggered`, `IntegralTriggered`, `BurstTriggered` — are blocked during PostReset and
Reconverging by the T4 admissibility gate. This behavior is correct and intentional.

`QueryCount`, `TimeBased`, `Hybrid`, and `JitteredTimeBased` remain admissible during
Reconverging. They are the correct choices for environments where rotation must occur before
the estimator has reached Steady phase.

Do not attempt to disable or route around the T4 gate. It exists because entropy estimates
computed over fewer than `4 × active_n` samples are not statistically reliable, and rotation
decisions made on unreliable entropy estimates will not match the distribution conditions that
motivated configuring those policies.

---

## Governance

This document covers `ProviderPool<P>` as implemented in `provider/pool/src/`. Any new
rotation policy, deferral reason, or observability field introduced to the pool must be
classified in Section 3 and, if it introduces new operator-facing semantics, addressed in
Sections 4–10 before the implementation is merged.

Operator non-goals in Section 9 are prohibitions, not suggestions. They encode failure modes
that have been reasoned about explicitly. Relaxing any prohibition requires understanding the
failure mode it guards against and demonstrating that the relaxation does not reintroduce it.

This document is the operational prerequisite for `FORMAL_SURFACE_TAXONOMY.md` and the
deployment-environment work in `ENVIRONMENTAL_SURVIVABILITY.md`.
