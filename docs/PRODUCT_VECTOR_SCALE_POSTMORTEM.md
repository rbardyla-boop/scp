# Product Vector, Scale Path, and One-Year Post-Mortem

**Status**: Planning artifact only.
**Deployment authorization**: Not granted.
**Scope**: Product strategy for SCP after the technical and human-validation gates clear.

## Correctness Gate

This output is correct if:
- It names one concrete product vector rather than a vague market category.
- It explains why SCP's Noise/QUIC transport, relay-selection entropy metrics, and
  identity/consent state machines matter for that vector.
- It gives a staged scalability path with measurable technical and adoption gates.
- It defines a one-year failure post-mortem with thresholds, diagnostic questions, and
  pivot choices.

This output is wrong if a reviewer sees:
- A production launch claim before audits and human gates are complete.
- Growth goals with no measurable thresholds.
- Scaling plans that depend on the current dev-harness mailbox or unencrypted file keys.
- A post-mortem that preserves the original vector regardless of evidence.

## Chosen Product Vector

SCP should initially target **high-trust field-team communication for small organizations
operating under adversarial infrastructure pressure**.

The first buyers or sponsors are likely to be organizations that already understand why
ordinary messaging metadata is a liability:

- investigative journalism teams
- human-rights and legal-defense groups
- incident-response teams handling sensitive breach coordination
- small research or policy groups that need consentful relationship continuity

The product is not "another chat app." The wedge is a **relationship-continuity and
delivery substrate** for teams that need cryptographic identity continuity, explicit consent
state, and relay diversity under hostile or unreliable network conditions.

## Why This Vector Fits SCP

| SCP capability | Product value |
|----------------|---------------|
| Noise/QUIC transport | Gives a modern encrypted transport path suitable for intermittent field networks after production hardening. |
| Entropy-based relay selection | Reduces concentration on a small relay set and gives operators a measurable adversarial-pressure signal. |
| Identity lineage and rotation | Lets a relationship survive device replacement and controlled key rotation without treating infrastructure accounts as identity. |
| Consent/vitality state machines | Makes relationship state explicit instead of burying revocation, dormancy, and recovery in UI convention. |
| Dev-harness relay/mailbox model | Useful for proving flows, but must be replaced before production claims. |

## Initial Product Shape

The first production candidate should be an **operator-run secure corridor kit**:

- a hardened endpoint CLI and minimal desktop shell for closed pilots
- a relay daemon with production-grade routing privacy, quotas, and abuse controls
- an auditable identity package with hardware-backed or OS-keystore-backed key storage
- explicit import/export and recovery flows
- operator telemetry that reports health without exposing identity graphs

This shape avoids a premature consumer network. It lets SCP prove itself where trust,
auditability, and operator control matter more than viral growth.

## Scalability Plan

Stage 0: Dev-harness closure.
- Pass the full build gate in `docs/architecture/PRODUCTION_READINESS_BUILD_PLAN.md`.
- Keep dev mailbox, file keys, and harness identity formats labeled as non-production.
- Maintain deterministic adversarial and metadata-resistance tests.

Stage 1: Production-candidate protocol hardening.
- Replace harness mailbox routing with a production privacy design.
- Complete independent cryptography and threat-model review.
- Add fuzzing for wire framing, transcript parsing, relay mailbox commands, and consent-state transitions.
- Add dependency audit, SBOM generation, and reproducible release-build instructions.
- Define performance budgets for relay CPU, memory, queue depth, and burst latency.

Stage 2: Closed pilot readiness.
- Run with 2 to 3 trusted pilot organizations, only after explicit authorization.
- Require at least 2 relay operators per pilot and at least 3 relays per pilot mesh.
- Measure active corridors, successful delivery rate, recovery flow success, support load,
  relay concentration, and user comprehension of consent state.
- Keep telemetry observational until provenance gaps are closed.

Stage 3: Operator-network scaling.
- Support horizontal relay expansion with bounded queue growth and privacy-preserving rate limits.
- Add relay admission policy and revocation for abusive or unhealthy relays.
- Add migration tooling for identity storage and corridor continuity.
- Publish compatibility and upgrade windows for endpoint and relay versions.

Stage 4: Ecosystem expansion.
- Offer an SDK only after the reference implementation has passed audits and pilot gates.
- Prefer open operator documentation and interoperability tests over a single hosted service.
- Treat managed hosting as a later option, not the default growth mechanism.

## One-Year Growth Metrics

Measure one year from the first explicitly authorized production-candidate pilot, not from
the current dev-harness date.

The vector is healthy if at least three of these are true:

- 5 or more pilot organizations have completed a 60-day trial.
- 100 or more active corridors are used in a trailing 30-day window.
- 3 or more independent relay operators run compatible relays.
- Median successful delivery latency meets the pilot SLO under normal network conditions.
- At least 60 percent of pilot users correctly understand consent/recovery state in a
  follow-up comprehension check.
- At least 2 pilot organizations request expanded usage after the first trial.

The vector is failing if at least two of these are true:

- Fewer than 3 pilot organizations complete a 60-day trial.
- Fewer than 50 active corridors exist in the trailing 30-day window.
- Relay operation requires too much manual support for non-core operators.
- Users cannot correctly understand consent/recovery state without repeated coaching.
- Security review blocks the core relay or identity model rather than finding bounded fixes.
- The product is mainly used as a generic chat replacement instead of the relationship-continuity substrate.

## One-Year Failure Post-Mortem

If the vector fails to grow after one year, run a blameless post-mortem with this structure:

1. Restate the original hypothesis.
   - High-trust field teams need consentful identity continuity and adversarial relay diversity enough to adopt SCP despite operational complexity.

2. Compare evidence to thresholds.
   - Adoption: pilots completed, active corridors, retained teams.
   - Technical: delivery success, relay concentration, failure rates, recovery success.
   - Human: comprehension of consent state, support tickets, onboarding time.
   - Trust: audit findings, operator confidence, unresolved security blockers.

3. Identify the primary failure mode.
   - Market pain too rare or too expensive to reach.
   - Product surface too complex for field operators.
   - Cryptographic trust story not credible enough without deeper audit.
   - Relay operation too heavy for small organizations.
   - Consent/state vocabulary fails human validation.
   - Existing secure messengers satisfy enough of the job.

4. Decide the next vector.
   - Narrow to an SDK for audited relationship-continuity and key-rotation workflows.
   - Pivot to an incident-response corridor appliance for temporary, high-stakes coordination.
   - Pivot to relay-diversity telemetry for existing secure communication systems.
   - Pause productization and return to research if the identity/relay model fails audit.

5. Retire invalid assumptions.
   - Remove any roadmap item whose premise failed.
   - Keep only validated technical assets.
   - Update the architecture gate before any new product vector is pursued.

## Strict Reviewer Checklist

- [ ] One concrete vector is named.
- [ ] SCP-specific capabilities map to that vector.
- [ ] Scaling stages do not depend on dev-harness shortcuts.
- [ ] One-year success and failure thresholds are measurable.
- [ ] The post-mortem can end in narrowing, pivoting, pausing, or retiring the vector.
- [ ] No section claims production deployment is currently authorized.
