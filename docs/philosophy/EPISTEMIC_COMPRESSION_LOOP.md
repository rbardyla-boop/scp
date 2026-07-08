# The Epistemic Compression Loop (ECL)

A review protocol for converting vague intuition into compressed, testable, falsifiable,
replayable models. It is a cognitive compiler: raw perception in, auditable record out.

This is a **review/verifier protocol**, not runtime behavior. Nothing in the SCP runtime
depends on it. It governs how ideas — doctrines, architectural leaps, invariant claims,
trial interpretations — earn maturity before being acted on.

Runnable procedure: [.claude/skills/epistemic-compression/SKILL.md](../../.claude/skills/epistemic-compression/SKILL.md)
Record schema: [ecl-record.schema.json](./ecl-record.schema.json)
Schema consistency test: `test/tests/ecl_schema.rs`

## Production rule

> An idea is not mature until it can be **defined**, **compressed**, **tested**,
> **falsified**, **replayed**, and **compared against variants**.

## Falsifier for the protocol itself

> If the process produces more confidence without producing clearer definitions,
> testable claims, falsifiers, replay steps, or better error detection, it is
> **performative cognition**, not intelligence.

Every ECL record carries a `performative_cognition_flag`. A pass that raises confidence
while adding none of the above must set it to `true`, and its decision is capped at
`testable`.

## Pipeline

Eleven stages, run in order. Each stage produces a named field of the record.

| # | Stage | Produces | Stage passes when |
|---|-------|----------|-------------------|
| 1 | Perception | `raw_perception` | The intuition is written down verbatim, unimproved. |
| 2 | Definition | `working_definition` | A stranger could classify examples as in/out of the definition. |
| 3 | Analogy | `nearest_analogies` | Each analogy names both the resemblance and the divergence. |
| 4 | Value | `value_claim` | It says who benefits, how, and by roughly how much if true. |
| 5 | Compression | `compressed_model` | Shorter than the perception; nothing load-bearing lost. |
| 6 | Test | `testable_claims` | Each claim names an observable, conditions, and a predicted outcome. |
| 7 | Falsification | `falsifiers` | Each falsifier is runnable/observable by someone other than the proposer. |
| 8 | Replay | `replay_steps` | A stranger with repo access can reproduce the reasoning or result. |
| 9 | Assumption Audit | `hidden_assumptions` | For each claim: "what must be true for this to even make sense?" answered. |
| 10 | Formalization | `formalization` | Variables, relations, constraints written explicitly (may be sparse, not empty-by-neglect). |
| 11 | Variant Search | `variants` | ≥3 structural alternatives, each with a discriminating test. |

## Maturity score (0–6)

One point per gate, mirroring the production rule. Gates are binary; no partial credit.

| Gate | Point awarded when |
|------|--------------------|
| Defined | `working_definition` is precise and non-circular (stage 2 passes). |
| Compressed | `compressed_model` passes stage 5. |
| Testable | ≥1 entry in `testable_claims` passes stage 6. |
| Falsifiable | ≥1 entry in `falsifiers` passes stage 7. |
| Replayable | `replay_steps` pass stage 8. |
| Variant-compared | ≥3 entries in `variants`, each with a discriminating test, and a comparison verdict recorded. |

## Decision rules

| Decision | Requires |
|----------|----------|
| `rejected` | A falsifier fires on available evidence, or a variant strictly dominates the original. Any score. |
| `immature` | Score ≤ 2, or the Defined gate failed. |
| `testable` | Testable + Falsifiable + Replayable gates passed; some gate still open, or `performative_cognition_flag` is true. |
| `provisionally_valid` | All six gates passed (score = 6), ≥3 variants compared, ≥1 hidden assumption surfaced, flag false, no fired falsifier. |

`provisionally_valid` is not `true`. It means: survives its own falsifiers so far, and
survived comparison against at least three structural alternatives. It remains open to
rejection by any listed falsifier.

The rubric is stable within a pass: gates may not be reworded mid-loop to let a failing
idea through. Relaxing a gate requires an explicit operator decision recorded in the
record itself.

## When to run it in this repo

- Before adding or amending a doctrine in [DOCTRINES.md](./DOCTRINES.md) or
  `OPERATOR_DOCTRINE.md`.
- When a review or design discussion is about to conclude on intuition — in particular,
  the "Caitlin leap" architectural moves that `.claude/claude.md` encourages at the
  strategy phase. ECL is the counterweight: the leap is welcome, but it enters the
  record as `immature` until it clears the gates.
- When interpreting trial results (`docs/architecture/TRIAL_*_CLOSURE_RECORD.md`):
  the interpretation, not the raw data, is the idea under review.
- Whenever confidence in a claim rises across sessions without new tests, falsifiers,
  or replays appearing — that is the performative-cognition signature.

Not needed for: mechanical edits, claims already covered by passing tests, or facts
directly checkable in under a minute.

## Record format and storage

A record is a single JSON object validating against
[ecl-record.schema.json](./ecl-record.schema.json). Embed it in the document, PR
description, or review it supports (fenced ```json block), or store it as
`docs/philosophy/ecl-records/<slug>.json` when it needs to stand alone.

The schema enforces the protocol's teeth: `testable`/`provisionally_valid` require
non-empty testable claims, falsifiers, and replay steps; `provisionally_valid`
additionally requires ≥3 variants, ≥1 hidden assumption, score exactly 6, and
`performative_cognition_flag: false`. `test/tests/ecl_schema.rs` keeps this file and
the skill's contract from drifting apart.
