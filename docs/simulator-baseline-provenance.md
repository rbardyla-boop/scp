# Simulator Baseline Provenance Record

**Date:** 2026-05-28  
**Phase:** Simulator Baseline Stabilization Pass (pre-repair snapshot)

## Purpose

This document preserves the authoritative pre-repair state of `test/tests/sim.rs` before
test-specification fixes are applied to `sim_s49` and `sim_s34`. It satisfies the Stage 2
provenance requirement: the simulator test surface must be frozen with reproducible
provenance before any specification change.

---

## Test Count Reconciliation (Stage 1)

Full workspace run (2026-05-28), all 445 tests passing:

| Test target              | File                              | Git tracked? | Passed |
|--------------------------|-----------------------------------|:------------:|-------:|
| adversarial              | test/tests/adversarial.rs         | No (??)      |     45 |
| corridor                 | test/tests/corridor.rs            | No (??)      |      9 |
| level1                   | test/tests/level1.rs              | No (??)      |      4 |
| metadata                 | test/tests/metadata.rs            | Yes          |     15 |
| pool                     | test/tests/pool.rs                | No (??)      |    121 |
| property                 | test/tests/property.rs            | No (??)      |     13 |
| quorum                   | test/tests/quorum.rs              | No (??)      |     10 |
| recovery                 | test/tests/recovery.rs            | Yes          |      8 |
| sim                      | test/tests/sim.rs                 | No (??)      |     68 |
| state                    | test/tests/state.rs               | No (??)      |     11 |
| state_machine            | test/tests/state_machine.rs       | Yes          |     21 |
| transport                | test/tests/transport.rs           | Yes          |     58 |
| trial0                   | test/tests/trial0.rs              | No (??)      |      8 |
| trial1b                  | test/tests/trial1b.rs             | No (??)      |     11 |
| vitality                 | test/tests/vitality.rs            | No (??)      |      5 |
| wire_vectors             | test/tests/wire_vectors.rs        | No (??)      |     12 |
| scp_transport (unit)     | core/transport/src/lib.rs         | Yes          |      9 |
| scp_wire_format (unit)   | scp-wire-format/src/lib.rs        | Yes          |     17 |
| **Total**                |                                   |              | **445**|

**Reconciliation of prior reported breakdown:**

| Category              | Prior report | Corrected |
|-----------------------|:------------:|:---------:|
| Trial 1b              |      11      |     11    |
| sim                   |      68      |     68    |
| Unit suites           |      26      |     26    |
| Other integration     |     362      |    340    |
| **Total**             |   **467**    |  **445**  |

The prior "other integration" count of 362 was inconsistent. The correct figure is
445 − 11 − 68 − 26 = **340**. No test count was artificially inflated; the 22-test
discrepancy was a reporting error.

---

## Pre-repair sim.rs Provenance

```
File:        test/tests/sim.rs
SHA-256:     e39dc7b872938cbbcecb4cbb76312b6ba0db348031286d9d7204b036c6f4666e
Git status:  ?? (untracked at time of capture)
```

**Historical provenance statement:**

> The simulator failure is demonstrably reproducible and no interaction with Trial 1b
> was found; historical pre-Trial-1b provenance is unavailable because the defining
> file was untracked at capture time.

---

## Observed Instability (100-run isolation studies)

### sim_s49 (`sim_s49_on_rotation_freshness_vs_never_under_silent_failure`)

- **Failure rate:** 15 / 100 isolated runs
- **Failing assertion:** `κ < 0.05` on either the Never pool or the OnRotation pool
- **Observed failing values:** 0.051 – 0.100
- **liveness_weighted_κ assertion:** Never failed in 100 runs

**Root cause:**
The Never pool accumulates 50 Phase-1 selection samples + 10 snapshot samples = 60 total.
The OnRotation pool accumulates ~47 post-rotation selection samples + 10 snapshot samples = ~57 total.
With 4 active providers and RandomK(1), the empirical selection entropy at 57–60 samples
has sufficient variance to push κ above 0.05 in ~15% of runs. The 0.05 threshold is too
tight for this sample depth.

**Dependency on Trial 1b:**
`sim_s49` imports `scp_provider_pool` and `scp_ledger_substrate`. It has no `scp_vitality`
import and no shared state with Trial 1b tests. No causal interaction found.

### sim_s34 (`sim_s34_liveness_failures_elevate_kappa`)

- **Failure rate:** 11 / 100 isolated runs
- **Failing assertion:** `post_failure_kappa > baseline_kappa + 0.2`
- **Observed failing values:** post_failure 0.190–0.210 (expected ~0.22); baseline 0.004–0.015

**Root cause:**
200 failure-period epochs × 1 sample each gives expected post_failure κ ≈ 0.22
(provider 0 at ~250/400 = 62.5% → κ ≈ 0.226). With random variance, post_failure
lands in the 0.19–0.23 range. Meanwhile, baseline κ (200 uniform samples) varies
from ~0.004 to ~0.015. The combination creates a relative threshold `baseline + 0.2`
ranging from ~0.204 to ~0.215 — a knife-edge against the ~0.22 median. When post_failure
falls below that knife-edge, the assertion fires.

**Dependency on Trial 1b:**
`sim_s34` uses only liveness-related pool APIs (`record_failure`, `with_liveness`).
No `scp_vitality` import. No shared state with Trial 1b. No causal interaction found.

---

## Authorized Repair Directions

Both repairs are test-specification changes only. No production source files change.

**sim_s49:** Increase the final snapshot `run_epoch(10)` to `run_epoch(1000)` for both
pools. This gives 1050 total selection samples for Never and ~1047 for OnRotation
(post-rotation), driving κ to << 0.01 reliably. The liveness_weighted_κ calculation
is unaffected (driven by `record_response()` calls, not selection).

**sim_s34:** Increase failure-period epochs from 200 to 400. Provider 0 then accrues
~450/600 = 75% of all selections, expected κ ≈ 0.40 (well above any plausible
`baseline + 0.2 ≈ 0.21` threshold). The property under test — that κ rises substantially
when 3/4 providers die — is preserved with greater statistical power.
