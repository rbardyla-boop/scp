// Epistemic Compression Loop record-schema consistency.
//
// The ECL is a review/verifier protocol (docs/philosophy/EPISTEMIC_COMPRESSION_LOOP.md);
// nothing in the SCP runtime depends on it. These tests keep the three artifacts that
// define it — the skill contract (.claude/skills/epistemic-compression/SKILL.md), the
// protocol spec, and the JSON schema (docs/philosophy/ecl-record.schema.json) — from
// drifting apart.
//
// Invariants:
//   The schema is valid JSON and requires exactly the 14 record fields of the contract.
//   maturity_score is bounded to [0, 6]; decision is the 4-value protocol enum.
//   A golden provisionally_valid record passes the maturity gates.
//   provisionally_valid with <3 variants, a true performative flag, or score != 6
//   violates the gates (the ≥3-variants rule and the performative-cognition cap).

use serde_json::Value;

const SCHEMA: &str = include_str!("../../docs/philosophy/ecl-record.schema.json");

const CONTRACT_FIELDS: [&str; 14] = [
    "raw_perception",
    "working_definition",
    "nearest_analogies",
    "value_claim",
    "compressed_model",
    "testable_claims",
    "falsifiers",
    "replay_steps",
    "hidden_assumptions",
    "formalization",
    "variants",
    "maturity_score",
    "decision",
    "performative_cognition_flag",
];

fn schema() -> Value {
    serde_json::from_str(SCHEMA).expect("ecl-record.schema.json must be valid JSON")
}

/// Checks a record against the protocol's maturity gates. Returns the violations;
/// empty means the record is internally consistent with the ECL decision rules.
fn maturity_gate_violations(record: &Value) -> Vec<String> {
    let mut violations = Vec::new();

    for field in CONTRACT_FIELDS {
        if record.get(field).is_none() {
            violations.push(format!("missing required field: {field}"));
        }
    }

    let score = record["maturity_score"].as_i64().unwrap_or(-1);
    if !(0..=6).contains(&score) {
        violations.push(format!("maturity_score {score} outside [0, 6]"));
    }

    let decision = record["decision"].as_str().unwrap_or("");
    let flag = record["performative_cognition_flag"]
        .as_bool()
        .unwrap_or(true);
    let len_of = |field: &str| record[field].as_array().map_or(0, |a| a.len());

    match decision {
        "immature" | "rejected" => {}
        "testable" | "provisionally_valid" => {
            for field in ["testable_claims", "falsifiers", "replay_steps"] {
                if len_of(field) == 0 {
                    violations.push(format!("decision {decision} requires non-empty {field}"));
                }
            }
            if decision == "provisionally_valid" {
                if len_of("variants") < 3 {
                    violations.push("provisionally_valid requires >= 3 variants".into());
                }
                if len_of("hidden_assumptions") == 0 {
                    violations.push("provisionally_valid requires >= 1 hidden assumption".into());
                }
                if score != 6 {
                    violations.push("provisionally_valid requires maturity_score == 6".into());
                }
                if flag {
                    violations.push("performative_cognition_flag caps decision at testable".into());
                }
            }
        }
        other => violations.push(format!("unknown decision: {other}")),
    }

    violations
}

fn golden_record() -> Value {
    serde_json::json!({
        "raw_perception": "Rotating the active provider set on a cooldown feels like it should stop rotation thrashing.",
        "working_definition": "Rotation thrashing: >0.5 rotations per epoch sustained over a window, driven by policy feedback rather than adversarial pressure.",
        "nearest_analogies": [
            "TCP congestion-control backoff — resembles: negative feedback with a floor; diverges: no adversary shaping the signal",
            "Debounce in UI event handling — resembles: minimum interval between actions; diverges: no correctness invariant at stake"
        ],
        "value_claim": "If true, a fixed cooldown bounds churn cost per epoch without weakening entropy recovery, cutting rotation overhead for every pool operator.",
        "compressed_model": "A minimum inter-rotation interval converts the rotation policy from a proportional controller into a bounded-rate controller; thrash rate <= 1/cooldown.",
        "testable_claims": [
            "With cooldown C epochs, measured rotation rate never exceeds 1/C in PoolSimulator traces regardless of policy sensitivity."
        ],
        "falsifiers": [
            "A PoolSimulator trace with cooldown C where total_rotations/epochs > 1/C.",
            "A forced-trajectory run where the cooldown delays an entropy-triggered rotation long enough that kappa exceeds its pre-cooldown peak."
        ],
        "replay_steps": [
            "cargo test -p scp-tests --test sim -- --nocapture",
            "Inspect EpochTrace rotation counts against the configured RotationCooldown in test/tests/sim.rs."
        ],
        "hidden_assumptions": [
            "Epoch length is stationary — a cooldown in wall-clock time does not bound per-epoch rotation rate if epochs shrink."
        ],
        "formalization": {
            "variables": ["C: cooldown in epochs", "r: rotations per epoch", "kappa: spectral concentration"],
            "relations": ["r <= 1/C", "d(kappa)/dt during deferral >= 0 under sustained k=n sampling"],
            "constraints": ["C >= 1", "pool has non-empty dormant set"]
        },
        "variants": [
            { "name": "jittered-cooldown", "differs_by": "cooldown drawn from a jittered interval instead of fixed", "discriminating_test": "autocorrelation of rotation timestamps: fixed C shows a spectral line at 1/C, jitter does not", "verdict": "undetermined" },
            { "name": "pressure-scaled-cooldown", "differs_by": "cooldown shrinks as accumulated kappa pressure grows", "discriminating_test": "under burst pressure, rotation latency falls below C while steady-state rate stays <= 1/C", "verdict": "undetermined" },
            { "name": "no-cooldown-integral-gate", "differs_by": "replace the cooldown with an integral-threshold gate alone", "discriminating_test": "with threshold < 1.0 and no cooldown, rotation rate becomes unbounded in adversarial traces", "verdict": "dominated" }
        ],
        "maturity_score": 6,
        "decision": "provisionally_valid",
        "performative_cognition_flag": false
    })
}

#[test]
fn ecl_schema_requires_exactly_the_contract_fields() {
    let schema = schema();
    let required: Vec<&str> = schema["required"]
        .as_array()
        .expect("schema must list required fields")
        .iter()
        .map(|v| v.as_str().expect("required entries are strings"))
        .collect();

    for field in CONTRACT_FIELDS {
        assert!(
            required.contains(&field),
            "schema is missing required contract field: {field}"
        );
    }
    assert_eq!(
        required.len(),
        CONTRACT_FIELDS.len(),
        "schema requires fields outside the ECL contract: {required:?}"
    );

    let formalization_required: Vec<&str> = schema["properties"]["formalization"]["required"]
        .as_array()
        .expect("formalization must list required sub-fields")
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert_eq!(
        formalization_required,
        vec!["variables", "relations", "constraints"]
    );
}

#[test]
fn ecl_schema_bounds_maturity_score_and_decision_enum() {
    let schema = schema();
    let score = &schema["properties"]["maturity_score"];
    assert_eq!(score["minimum"], 0);
    assert_eq!(score["maximum"], 6);

    let decisions: Vec<&str> = schema["properties"]["decision"]["enum"]
        .as_array()
        .expect("decision must be an enum")
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert_eq!(
        decisions,
        vec!["immature", "testable", "provisionally_valid", "rejected"]
    );
}

#[test]
fn golden_provisionally_valid_record_passes_maturity_gates() {
    let violations = maturity_gate_violations(&golden_record());
    assert!(
        violations.is_empty(),
        "golden record violates gates: {violations:?}"
    );
}

#[test]
fn maturity_requires_three_variants() {
    let mut record = golden_record();
    record["variants"].as_array_mut().unwrap().truncate(2);
    let violations = maturity_gate_violations(&record);
    assert!(
        violations.iter().any(|v| v.contains(">= 3 variants")),
        "two variants must block provisionally_valid, got: {violations:?}"
    );
}

#[test]
fn performative_cognition_flag_caps_the_decision() {
    let mut record = golden_record();
    record["performative_cognition_flag"] = Value::Bool(true);
    let violations = maturity_gate_violations(&record);
    assert!(
        violations
            .iter()
            .any(|v| v.contains("performative_cognition_flag")),
        "a true flag must block provisionally_valid, got: {violations:?}"
    );
}

#[test]
fn maturity_requires_full_score_and_evidence_fields() {
    let mut record = golden_record();
    record["maturity_score"] = Value::from(5);
    record["falsifiers"] = serde_json::json!([]);
    let violations = maturity_gate_violations(&record);
    assert!(
        violations.iter().any(|v| v.contains("maturity_score == 6")),
        "score 5 must block provisionally_valid, got: {violations:?}"
    );
    assert!(
        violations.iter().any(|v| v.contains("falsifiers")),
        "empty falsifiers must block provisionally_valid, got: {violations:?}"
    );
}
