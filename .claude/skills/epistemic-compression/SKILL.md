---
name: epistemic-compression
description: Run the Epistemic Compression Loop — an 11-stage review protocol that converts a vague intuition or design claim into a compressed, testable, falsifiable, replayable model with a scored maturity verdict. Use when a design/doctrine claim rests on intuition, when a review is about to conclude "this feels right", when confidence in an idea is rising without new tests, or when asked to "run ECL" / "compress this idea".
---

# Epistemic Compression Loop

You are running a cognitive compiler. Input: a vague intuition or claim. Output: one ECL
record (JSON) plus a short verdict. The protocol spec lives at
`docs/philosophy/EPISTEMIC_COMPRESSION_LOOP.md`; the record schema at
`docs/philosophy/ecl-record.schema.json`. Follow this file to execute; consult the spec
for rationale.

**Production rule:** an idea is not mature until it can be defined, compressed, tested,
falsified, replayed, and compared against variants.

**Falsifier for the loop itself:** if a pass produces more confidence without producing
clearer definitions, testable claims, falsifiers, replay steps, or better error
detection, it is performative cognition, not intelligence — flag it.

## Procedure

Run the eleven stages in order. Do not skip a stage; if a stage genuinely yields nothing,
record why in that field rather than leaving it silently thin.

1. **Perception** → `raw_perception`: write the intuition down verbatim. Do not improve
   it. This is the audit anchor for everything that follows.
2. **Definition** → `working_definition`: define the idea precisely and non-circularly.
   Test: could a stranger use this definition to classify borderline examples as in/out?
   If not, iterate here before proceeding.
3. **Analogy** → `nearest_analogies`: list existing concepts/systems/results this
   resembles. Each entry must name the resemblance AND the divergence. An analogy with
   no stated divergence is decoration.
4. **Value** → `value_claim`: what becomes possible, cheaper, or safer if this is true?
   Who benefits, by how much? "It's interesting" is not a value claim.
5. **Compression** → `compressed_model`: restate at minimum length without losing
   load-bearing content. If the compressed form and the raw perception differ in
   consequences, the compression is wrong — fix it or the definition.
6. **Test** → `testable_claims`: predictions with concrete observables. Each claim names
   what is measured, under what conditions, and the predicted outcome. **Required:
   at least one, or the decision cannot exceed `immature`.**
7. **Falsification** → `falsifiers`: what observation would kill this idea? Each
   falsifier must be runnable or observable by someone other than the proposer.
   **Required: at least one.** "Nothing could falsify it" ⇒ decision `immature`, and say
   so — the idea is not yet an empirical claim.
8. **Replay** → `replay_steps`: ordered steps by which a stranger with repo access
   reproduces the reasoning or the result — commands, file paths, inputs, expected
   outputs. **Required: at least one.** "Reread my argument" is not a replay step.
9. **Assumption Audit** → `hidden_assumptions`: for each testable claim ask "what must
   be true for this to even make sense?" Surface at least one assumption or explicitly
   justify why there are none (rare; be suspicious of yourself here).
10. **Formalization** → `formalization`: name `variables`, state `relations`
    (equations/inequalities/monotonicity), list `constraints` (domains, invariants).
    Sparse is fine; empty-by-neglect is not.
11. **Variant Search** → `variants`: generate structural alternatives — different
    mechanism, different causal direction, weaker/stronger scope. Each variant needs
    `name`, `differs_by` (the single structural change), and `discriminating_test`
    (an observation that would tell it apart from the original). **Required: at least
    three variants before the idea may be accepted as mature.** If a variant survives
    the discriminating tests better than the original, the original is `rejected`.

## Scoring (0–6, one point per gate, binary)

| Gate | Point when |
|------|-----------|
| Defined | Stage 2 passes the stranger-classification test. |
| Compressed | Stage 5 loses nothing load-bearing. |
| Testable | ≥1 valid testable claim. |
| Falsifiable | ≥1 valid falsifier. |
| Replayable | Replay steps executable by a stranger. |
| Variant-compared | ≥3 variants, each with a discriminating test, comparison verdict recorded. |

## Decision

- `rejected` — a falsifier fires on evidence already available, or a variant dominates.
- `immature` — score ≤ 2 or the Defined gate failed.
- `testable` — Testable + Falsifiable + Replayable gates passed, but not all six, **or**
  the performative-cognition flag is true.
- `provisionally_valid` — all six gates (score exactly 6), ≥3 variants compared, ≥1
  hidden assumption surfaced, flag false, no fired falsifier.

Never reword a gate mid-pass to let a failing idea through. If a gate seems wrong,
finish the pass under the current gates and note the objection in the record.

## Performative-cognition check (mandatory, last step before emitting)

Compare this pass against the prior state of the idea (previous record, or the raw
perception if this is the first pass). Set `performative_cognition_flag: true` if
confidence rose (stronger value claim, upgraded decision, more assertive language)
while the pass added **none** of: a sharper working definition, a new testable claim, a
new falsifier, an executable replay step, a newly surfaced hidden assumption, or a new
discriminating test. A true flag caps the decision at `testable`. Report the flag in
your verdict — do not bury it.

## Output contract

Emit exactly this object (all fourteen keys, schema-valid against
`docs/philosophy/ecl-record.schema.json`):

```json
{
  "raw_perception": "...",
  "working_definition": "...",
  "nearest_analogies": ["..."],
  "value_claim": "...",
  "compressed_model": "...",
  "testable_claims": ["..."],
  "falsifiers": ["..."],
  "replay_steps": ["..."],
  "hidden_assumptions": ["..."],
  "formalization": { "variables": [], "relations": [], "constraints": [] },
  "variants": [
    { "name": "...", "differs_by": "...", "discriminating_test": "...", "verdict": "undetermined" }
  ],
  "maturity_score": 0,
  "decision": "immature | testable | provisionally_valid | rejected",
  "performative_cognition_flag": false
}
```

Then give a three-line verdict: decision + score, the single strongest falsifier, and
the next cheapest action that would move the score. Embed the record in the document or
review it supports, or write it to `docs/philosophy/ecl-records/<slug>.json` if asked
to persist it standalone.
