// Phase 1: State Machine Layer tests
// Covers: vitality scoring, lineage chain verification, ledger state machine

use scp_cryptography::keys::KeyPair;
use scp_identity::{genesis::IdentityGenesis, lineage::ContinuityProof, rotation::RotationEvent};
use scp_ledger_cosmos::CosmosLedger;
use scp_ledger_substrate::{
    tunnel_consent_hash, LedgerIdentityRecord, SubstrateLedger, TunnelConsent, TunnelState,
};
use scp_vitality::{
    function::{compute, VitalityParams},
    state::VitalityState,
};

// ── Vitality function ───────────────────────────────────────────────────────

#[test]
fn vitality_perfect_conditions_is_active() {
    let v = compute(VitalityParams {
        t: 0.0,
        i: 1.0,
        r: 1.0,
        p: 0.0,
    });
    assert_eq!(VitalityState::from_score(v), VitalityState::Active);
    assert!((v - 1.0).abs() < 1e-9);
}

#[test]
fn vitality_decays_with_time() {
    let seven_days = 7.0 * 24.0 * 3600.0;
    let fourteen_days = 14.0 * 24.0 * 3600.0;
    let v7 = compute(VitalityParams {
        t: seven_days,
        i: 1.0,
        r: 1.0,
        p: 0.0,
    });
    let v14 = compute(VitalityParams {
        t: fourteen_days,
        i: 1.0,
        r: 1.0,
        p: 0.0,
    });
    assert!(v7 > v14, "vitality must decay with time");
    assert!(v7 > 0.0 && v14 > 0.0, "vitality must remain positive");
}

#[test]
fn vitality_zero_interaction_entropy_scores_zero() {
    let v = compute(VitalityParams {
        t: 0.0,
        i: 0.0,
        r: 1.0,
        p: 0.0,
    });
    assert_eq!(v, 0.0, "zero interaction entropy must yield zero vitality");
}

#[test]
fn vitality_one_sided_participation_is_warm_or_lower() {
    let v = compute(VitalityParams {
        t: 0.0,
        i: 1.0,
        r: 0.0,
        p: 0.0,
    });
    assert_eq!(
        v, 0.0,
        "zero reciprocal participation must yield zero vitality"
    );
}

#[test]
fn vitality_perturbation_reduces_score() {
    let base = compute(VitalityParams {
        t: 0.0,
        i: 1.0,
        r: 1.0,
        p: 0.0,
    });
    let perturbed = compute(VitalityParams {
        t: 0.0,
        i: 1.0,
        r: 1.0,
        p: 1.0,
    });
    assert!(perturbed < base, "perturbation must reduce vitality score");
    assert!(
        perturbed > 0.0,
        "max perturbation must not zero out vitality entirely"
    );
}

#[test]
fn vitality_state_bands_are_consistent() {
    assert_eq!(VitalityState::from_score(1.00), VitalityState::Active);
    assert_eq!(VitalityState::from_score(0.80), VitalityState::Active);
    assert_eq!(VitalityState::from_score(0.79), VitalityState::Warm);
    assert_eq!(VitalityState::from_score(0.50), VitalityState::Warm);
    assert_eq!(VitalityState::from_score(0.49), VitalityState::Dormant);
    assert_eq!(VitalityState::from_score(0.20), VitalityState::Dormant);
    assert_eq!(VitalityState::from_score(0.19), VitalityState::Suspended);
    assert_eq!(VitalityState::from_score(0.00), VitalityState::Suspended);
}

#[test]
fn vitality_open_states() {
    assert!(VitalityState::Active.is_open());
    assert!(VitalityState::Warm.is_open());
    assert!(VitalityState::Dormant.is_open());
    assert!(!VitalityState::Suspended.is_open());
    assert!(!VitalityState::Severed.is_open());
    assert!(!VitalityState::Burned.is_open());
}

// ── Lineage chain verification ──────────────────────────────────────────────

#[test]
fn continuity_proof_empty_chain_fails() {
    let root = KeyPair::generate();
    let ops = KeyPair::generate();
    let proof = ContinuityProof {
        root_pub: root.public,
        rotation_chain: vec![],
        current_ops_pub: ops.public,
    };
    assert!(!proof.verify(), "empty chain must not verify");
}

#[test]
fn continuity_proof_single_rotation_verifies() {
    let root = KeyPair::generate();
    let ops1 = KeyPair::generate();
    let ops2 = KeyPair::generate();

    let event = RotationEvent::sign(ops1.public, ops2.public, &root).unwrap();
    let proof = ContinuityProof {
        root_pub: root.public,
        rotation_chain: vec![event],
        current_ops_pub: ops2.public,
    };
    assert!(proof.verify());
}

#[test]
fn continuity_proof_chain_of_three_verifies() {
    let root = KeyPair::generate();
    let ops = [
        KeyPair::generate(),
        KeyPair::generate(),
        KeyPair::generate(),
        KeyPair::generate(),
    ];

    let chain = vec![
        RotationEvent::sign(ops[0].public, ops[1].public, &root).unwrap(),
        RotationEvent::sign(ops[1].public, ops[2].public, &root).unwrap(),
        RotationEvent::sign(ops[2].public, ops[3].public, &root).unwrap(),
    ];

    let proof = ContinuityProof {
        root_pub: root.public,
        rotation_chain: chain,
        current_ops_pub: ops[3].public,
    };
    assert!(proof.verify());
}

#[test]
fn continuity_proof_broken_chain_fails() {
    let root = KeyPair::generate();
    let ops1 = KeyPair::generate();
    let ops2 = KeyPair::generate();
    let ops3 = KeyPair::generate();
    let unrelated = KeyPair::generate();

    // event1: ops1 → ops2, event2: ops3 → ops3 (gap — ops2 ≠ ops3)
    let event1 = RotationEvent::sign(ops1.public, ops2.public, &root).unwrap();
    let event2 = RotationEvent::sign(unrelated.public, ops3.public, &root).unwrap();

    let proof = ContinuityProof {
        root_pub: root.public,
        rotation_chain: vec![event1, event2],
        current_ops_pub: ops3.public,
    };
    assert!(!proof.verify(), "gap in chain must not verify");
}

#[test]
fn continuity_proof_wrong_current_ops_fails() {
    let root = KeyPair::generate();
    let ops1 = KeyPair::generate();
    let ops2 = KeyPair::generate();
    let ops3 = KeyPair::generate();

    let event = RotationEvent::sign(ops1.public, ops2.public, &root).unwrap();
    let proof = ContinuityProof {
        root_pub: root.public,
        rotation_chain: vec![event],
        current_ops_pub: ops3.public, // wrong — should be ops2
    };
    assert!(!proof.verify(), "wrong current_ops_pub must not verify");
}

// ── Ledger: identity lifecycle ───────────────────────────────────────────────

fn make_record_and_root_sig() -> (LedgerIdentityRecord, [u8; 64], KeyPair) {
    let genesis = IdentityGenesis::execute().unwrap();
    let root_kp = KeyPair {
        public: genesis.k_root_pub,
        secret: genesis.k_root_priv,
    };

    let record = LedgerIdentityRecord {
        k_root_pub: genesis.k_root_pub,
        k_ops_pub: genesis.k_ops_pub,
        recovery_policy_hash: genesis.recovery_policy_hash,
        continuity_commitment: genesis.continuity_commitment,
    };

    // Registration message: root_pub || ops_pub || recovery_policy_hash
    let mut msg = Vec::new();
    msg.extend_from_slice(&record.k_root_pub);
    msg.extend_from_slice(&record.k_ops_pub);
    msg.extend_from_slice(&record.recovery_policy_hash);
    let root_sig = root_kp.sign(&msg);

    (record, root_sig, root_kp)
}

#[test]
fn ledger_register_and_query_identity() {
    let ledger = SubstrateLedger::new();
    let (record, sig, _) = make_record_and_root_sig();

    ledger
        .register_identity(&record, &sig)
        .expect("registration must succeed");
    let ops = ledger.query_current_ops_key(&record.k_root_pub).unwrap();
    assert_eq!(ops, record.k_ops_pub);
}

#[test]
fn ledger_duplicate_registration_fails() {
    let ledger = SubstrateLedger::new();
    let (record, sig, _) = make_record_and_root_sig();
    ledger.register_identity(&record, &sig).unwrap();
    assert!(ledger.register_identity(&record, &sig).is_err());
}

#[test]
fn ledger_bad_signature_rejected() {
    let ledger = SubstrateLedger::new();
    let (record, mut sig, _) = make_record_and_root_sig();
    sig[0] ^= 0xff;
    assert!(ledger.register_identity(&record, &sig).is_err());
}

#[test]
fn ledger_rotate_key_updates_record() {
    let ledger = SubstrateLedger::new();
    let (record, reg_sig, root_kp) = make_record_and_root_sig();
    ledger.register_identity(&record, &reg_sig).unwrap();

    let new_ops = KeyPair::generate();
    let rot = RotationEvent::sign(record.k_ops_pub, new_ops.public, &root_kp).unwrap();
    let rot_sig: [u8; 64] = rot.root_sig.try_into().unwrap();

    ledger
        .rotate_key(&record.k_ops_pub, &new_ops.public, rot.nonce, &rot_sig)
        .unwrap();

    let current = ledger.query_current_ops_key(&record.k_root_pub).unwrap();
    assert_eq!(current, new_ops.public);
    assert!(
        ledger.is_revoked(&record.k_ops_pub),
        "old ops key must be revoked after rotation"
    );
}

#[test]
fn ledger_revoke_marks_key_revoked() {
    let ledger = SubstrateLedger::new();
    let (record, reg_sig, root_kp) = make_record_and_root_sig();
    ledger.register_identity(&record, &reg_sig).unwrap();

    assert!(!ledger.is_revoked(&record.k_ops_pub));
    let revoke_sig = root_kp.sign(&record.k_ops_pub);
    ledger.revoke(&record.k_ops_pub, &revoke_sig).unwrap();
    assert!(ledger.is_revoked(&record.k_ops_pub));
}

// ── Ledger: tunnel consent ───────────────────────────────────────────────────

#[test]
fn ledger_tunnel_consent_lifecycle() {
    let ledger = SubstrateLedger::new();

    let alice = KeyPair::generate();
    let bob = KeyPair::generate();
    let ch = tunnel_consent_hash(&alice.public, &bob.public);

    assert_eq!(
        ledger.query_tunnel(&alice.public, &bob.public),
        TunnelState::Unknown
    );

    let consent = TunnelConsent {
        party_a: alice.public,
        party_b: bob.public,
        sig_a: alice.sign(&ch).to_vec(),
        sig_b: bob.sign(&ch).to_vec(),
    };
    ledger
        .register_tunnel(consent)
        .expect("tunnel registration must succeed");
    assert_eq!(
        ledger.query_tunnel(&alice.public, &bob.public),
        TunnelState::Active
    );
    // Symmetric query
    assert_eq!(
        ledger.query_tunnel(&bob.public, &alice.public),
        TunnelState::Active
    );
}

#[test]
fn ledger_tunnel_revocation_by_either_party() {
    let ledger = SubstrateLedger::new();
    let alice = KeyPair::generate();
    let bob = KeyPair::generate();
    let ch = tunnel_consent_hash(&alice.public, &bob.public);

    let consent = TunnelConsent {
        party_a: alice.public,
        party_b: bob.public,
        sig_a: alice.sign(&ch).to_vec(),
        sig_b: bob.sign(&ch).to_vec(),
    };
    ledger.register_tunnel(consent).unwrap();

    // Alice revokes unilaterally.
    let revoke_sig = alice.sign(&ch);
    ledger
        .revoke_tunnel(&alice.public, &revoke_sig, &bob.public)
        .unwrap();
    assert_eq!(
        ledger.query_tunnel(&alice.public, &bob.public),
        TunnelState::Revoked
    );
}

#[test]
fn ledger_tunnel_bad_consent_signature_rejected() {
    let ledger = SubstrateLedger::new();
    let alice = KeyPair::generate();
    let bob = KeyPair::generate();
    let ch = tunnel_consent_hash(&alice.public, &bob.public);

    let consent = TunnelConsent {
        party_a: alice.public,
        party_b: bob.public,
        sig_a: alice.sign(&ch).to_vec(),
        sig_b: alice.sign(&ch).to_vec(), // wrong signer for party_b
    };
    assert!(ledger.register_tunnel(consent).is_err());
}

// ── Cosmos ledger: smoke test (same logic, different adapter) ────────────────

#[test]
fn cosmos_ledger_register_and_query() {
    let ledger = CosmosLedger::new();
    let genesis = IdentityGenesis::execute().unwrap();
    let root_kp = scp_cryptography::keys::KeyPair {
        public: genesis.k_root_pub,
        secret: genesis.k_root_priv,
    };
    let record = scp_ledger_cosmos::LedgerIdentityRecord {
        k_root_pub: genesis.k_root_pub,
        k_ops_pub: genesis.k_ops_pub,
        recovery_policy_hash: genesis.recovery_policy_hash,
        continuity_commitment: genesis.continuity_commitment,
    };
    let mut msg = Vec::new();
    msg.extend_from_slice(&record.k_root_pub);
    msg.extend_from_slice(&record.k_ops_pub);
    msg.extend_from_slice(&record.recovery_policy_hash);
    let sig = root_kp.sign(&msg);

    ledger.register_identity(&record, &sig).unwrap();
    assert_eq!(
        ledger.query_current_ops_key(&genesis.k_root_pub).unwrap(),
        genesis.k_ops_pub
    );
}
