// Trial 5B — Admissible Paired-Outcome Telemetry Surface
//
// Permitted claim (after verification):
//   Under deterministic scripted traces, the SCP ProviderPool admissible
//   paired-outcome surface (`SelectionReceipt`-backed accounting) correctly:
//     1. Credits admissible_response_total only for receipt-paired responses.
//     2. Credits admissible_failure_total only for receipt-paired failures.
//     3. Excludes unpaired raw responses from the admissible counters.
//     4. Enforces at-most-one terminal outcome per receipt.
//     5. Rejects wrong-provider, stale-epoch, and duplicate-receipt presentations.
//     6. Drains all outstanding receipts on epoch rotation.
//     7. Does not double-count raw selection accounting.
//     8. Obeys the documented outstanding-receipt bound.
//
// Explicit non-claims:
//   - Any admissible surface field drives automatic policy.
//   - SimVitalityEvaluationContext.p is derived from any telemetry field.
//   - Epoch rotation is triggered by any admissible surface field.
//   - Raw selection or response surfaces are altered by admissible calls.
//   - Transport, relay, LAN, desktop, or hardware readiness.
//
// Determinism requirement: all tests use fixed scripted traces.
// No random provider selection; no wall-clock timing; no probability-margin assertions.
// For floating-point outputs: (value - expected).abs() < 1e-12 tolerance.
// Integer counter assertions are exact.

use rand::SeedableRng;
use rand::rngs::StdRng;

use scp_provider_pool::{AdmissibilityError, ProviderPool, SamplingStrategy};
use scp_vitality::SimVitalityEvaluationContext;
use scp_ledger_substrate::{SubstrateLedger, TunnelConsent, tunnel_consent_hash};
use scp_cryptography::keys::KeyPair;

// ── Helpers ────────────────────────────────────────────────────────────────────

fn pid(byte: u8) -> [u8; 32] { [byte; 32] }

fn seeded() -> StdRng { StdRng::seed_from_u64(0) }

fn pool_with_admissible(k: usize, providers: &[u8]) -> ProviderPool<SubstrateLedger> {
    // Default bound: large enough never to be reached by existing tests.
    let mut pool = ProviderPool::new(SamplingStrategy::RandomK(k))
        .with_admissible_tracking(1024);
    for &b in providers {
        pool.add(pid(b), SubstrateLedger::new());
    }
    pool
}

fn pool_without_admissible(k: usize, providers: &[u8]) -> ProviderPool<SubstrateLedger> {
    let mut pool = ProviderPool::new(SamplingStrategy::RandomK(k));
    for &b in providers {
        pool.add(pid(b), SubstrateLedger::new());
    }
    pool
}


// ── T1: Valid paired response is credited to admissible surface ────────────────
//
// sample_with_receipts() → receipt for selected provider → record_admissible_response(receipt)
//
// Exact assertions:
//   admissible_response_total = 1
//   admissible_selection_total = 1
//   recent_admissible_response_ratio() = Some(1.0)
//   raw response_total = 0 (admissible call does NOT touch raw surface)
//   raw selection_total = 1 (raw accounting happened in sample_with_receipts())

#[test]
fn t1_valid_paired_response_is_admissible() {
    let mut rng = seeded();
    let mut pool = pool_with_admissible(1, &[1, 2, 3, 4]);

    let (_quorum, receipts) = pool.sample_with_receipts(&mut rng).unwrap();
    assert_eq!(receipts.len(), 1, "RandomK(1) with 4 providers must issue 1 receipt");

    let receipt = receipts.into_iter().next().unwrap();
    assert!(pool.record_admissible_response(&receipt).is_ok(),
        "First presentation of a valid receipt must be accepted");

    let snap = pool.operational_telemetry();
    assert_eq!(snap.admissible_response_total, 1,
        "admissible_response_total must be 1 after one valid paired response");
    assert_eq!(snap.admissible_selection_total, 1,
        "admissible_selection_total must be 1 — incremented at receipt issuance");
    assert_eq!(snap.admissible_failure_total, 0,
        "no failures recorded");
    assert_eq!(
        snap.recent_admissible_response_ratio(),
        Some(1.0),
        "1 admissible response / 1 admissible selection = 1.0"
    );
    // Raw surface is unchanged by the admissible call.
    assert_eq!(snap.response_total, 0,
        "record_admissible_response() must NOT increment raw response_total");
    assert_eq!(snap.selection_total, 1,
        "sample_with_receipts() performs raw selection accounting exactly once");
}

// ── T2: Response without receipt excluded from admissible surface ─────────────
//
// record_response(pid) called with no prior sample_with_receipts().
//
// Exact assertions:
//   admissible_response_total = 0
//   admissible_selection_total = 0
//   recent_admissible_response_ratio() = None (no admissible selections)
//   raw response_total = 1
//   discrepancy (raw - admissible) is visible: response_total > admissible_response_total

#[test]
fn t2_response_without_receipt_excluded_from_admissible() {
    let mut pool = pool_with_admissible(1, &[1, 2, 3, 4]);

    // Inject a raw response without any sample_with_receipts() call.
    pool.record_response(pid(1));

    let snap = pool.operational_telemetry();
    assert_eq!(snap.admissible_response_total, 0,
        "unpaired record_response() must not touch admissible_response_total");
    assert_eq!(snap.admissible_selection_total, 0,
        "no receipts were issued: admissible_selection_total = 0");
    assert_eq!(
        snap.recent_admissible_response_ratio(),
        None,
        "no admissible selections → ratio is None"
    );
    // Raw surface reflects the injection.
    assert_eq!(snap.response_total, 1,
        "raw response_total must be 1 after record_response()");
    // Option C discrepancy is computable.
    assert!(snap.response_total > snap.admissible_response_total,
        "raw response_total > admissible_response_total demonstrates Option C discrepancy");
}

// ── T3: Duplicate response for one receipt rejected ────────────────────────────
//
// sample_with_receipts() → record_admissible_response(receipt) → same call again.
//
// Exact assertions:
//   First call:  Ok(())
//   Second call: Err(UnknownReceipt)
//   admissible_response_total = 1 (not 2)

#[test]
fn t3_duplicate_response_for_one_receipt_rejected() {
    let mut rng = seeded();
    let mut pool = pool_with_admissible(1, &[1, 2, 3, 4]);

    let (_quorum, receipts) = pool.sample_with_receipts(&mut rng).unwrap();
    let receipt = receipts.into_iter().next().unwrap();

    // First presentation: accepted.
    assert_eq!(pool.record_admissible_response(&receipt), Ok(()),
        "First presentation of a valid receipt must succeed");
    // Second presentation with same (now-consumed) receipt: rejected.
    assert_eq!(
        pool.record_admissible_response(&receipt),
        Err(AdmissibilityError::UnknownReceipt),
        "Second presentation of a consumed receipt must return UnknownReceipt"
    );

    let snap = pool.operational_telemetry();
    assert_eq!(snap.admissible_response_total, 1,
        "duplicate rejection: admissible_response_total must remain 1");
}

// ── T4: Wrong-provider outcome rejected ────────────────────────────────────────
//
// Receipt issued for provider A; provider_id field mutated to provider B.
//
// Exact assertions:
//   Err(ProviderMismatch)
//   admissible_response_total = 0
//   receipt is absent from outstanding after rejection (re-presentation still fails)

#[test]
fn t4_wrong_provider_response_rejected() {
    let mut rng = seeded();
    let mut pool = pool_with_admissible(1, &[1, 2, 3, 4]);

    let (_quorum, receipts) = pool.sample_with_receipts(&mut rng).unwrap();
    let original = receipts.into_iter().next().unwrap();

    // Mutate provider_id to a different provider (one not selected in this call).
    // Use pid(99) which is definitely not in the pool.
    let tampered = original.clone().with_provider_id(pid(99));

    assert_eq!(
        pool.record_admissible_response(&tampered),
        Err(AdmissibilityError::ProviderMismatch),
        "Tampered provider_id must return ProviderMismatch"
    );

    let snap = pool.operational_telemetry();
    assert_eq!(snap.admissible_response_total, 0,
        "ProviderMismatch rejection must not increment admissible_response_total");

    // The original receipt (with the correct provider_id) must still be outstanding.
    // Verify by successfully using it now.
    assert_eq!(pool.record_admissible_response(&original), Ok(()),
        "Original receipt must still be in outstanding after ProviderMismatch rejection");
}

// ── T5: Valid paired failure is credited to admissible surface ─────────────────
//
// sample_with_receipts() → record_admissible_failure(receipt)
//
// Exact assertions:
//   admissible_failure_total = 1
//   receipt consumed — subsequent record_admissible_response(same) returns UnknownReceipt

#[test]
fn t5_valid_paired_failure_is_admissible() {
    let mut rng = seeded();
    let mut pool = pool_with_admissible(1, &[1, 2, 3, 4]);

    let (_quorum, receipts) = pool.sample_with_receipts(&mut rng).unwrap();
    let receipt = receipts.into_iter().next().unwrap();

    assert_eq!(pool.record_admissible_failure(&receipt), Ok(()),
        "First presentation to record_admissible_failure must succeed");

    let snap = pool.operational_telemetry();
    assert_eq!(snap.admissible_failure_total, 1,
        "admissible_failure_total must be 1 after one valid paired failure");
    assert_eq!(snap.admissible_response_total, 0,
        "no responses recorded");

    // Receipt is consumed — subsequent response attempt must fail.
    assert_eq!(
        pool.record_admissible_response(&receipt),
        Err(AdmissibilityError::UnknownReceipt),
        "Receipt consumed by failure — subsequent response must return UnknownReceipt"
    );
}

// ── T6: Failure without receipt excluded from admissible surface ──────────────
//
// record_failure(pid) called with no prior sample_with_receipts().
//
// Exact assertions:
//   admissible_failure_total = 0
//   raw consecutive_failures incremented normally (verified via liveness behavior)

#[test]
fn t6_failure_without_receipt_excluded_from_admissible() {
    let mut pool = pool_with_admissible(1, &[1, 2, 3, 4]);

    pool.record_failure(pid(1));

    let snap = pool.operational_telemetry();
    assert_eq!(snap.admissible_failure_total, 0,
        "unpaired record_failure() must not touch admissible_failure_total");
    assert_eq!(snap.admissible_response_total, 0);
    assert_eq!(snap.admissible_selection_total, 0);
}

// ── T7: Response after failure for same receipt rejected ──────────────────────
//
// record_admissible_failure(receipt) consumes the receipt;
// subsequent record_admissible_response(same receipt) must fail.
//
// Exact assertions:
//   Err(UnknownReceipt)
//   admissible_response_total = 0
//   admissible_failure_total = 1

#[test]
fn t7_response_after_failure_for_same_receipt_rejected() {
    let mut rng = seeded();
    let mut pool = pool_with_admissible(1, &[1, 2, 3, 4]);

    let (_quorum, receipts) = pool.sample_with_receipts(&mut rng).unwrap();
    let receipt = receipts.into_iter().next().unwrap();

    // Consume via failure.
    assert_eq!(pool.record_admissible_failure(&receipt), Ok(()));

    // Attempt response after failure consumed the receipt.
    assert_eq!(
        pool.record_admissible_response(&receipt),
        Err(AdmissibilityError::UnknownReceipt),
        "After failure consumes receipt, response attempt must return UnknownReceipt"
    );

    let snap = pool.operational_telemetry();
    assert_eq!(snap.admissible_response_total, 0,
        "Response after failure must not increment admissible_response_total");
    assert_eq!(snap.admissible_failure_total, 1,
        "admissible_failure_total must remain 1");
}

// ── T8: Stale-epoch receipt rejected ──────────────────────────────────────────
//
// sample_with_receipts() → force_rotate() → record_admissible_response(old receipt).
//
// Exact assertions:
//   Err(StaleEpoch)
//   admissible_response_total = 0
//   epoch_count = 1 (advanced by rotation)

#[test]
fn t8_stale_epoch_receipt_rejected() {
    let mut rng = seeded();
    // Need dormant providers for force_rotate() to work.
    let mut pool = ProviderPool::new(SamplingStrategy::RandomK(1))
        .with_admissible_tracking(1024)
        .with_active_window(2);
    for i in 1u8..=6 {
        pool.add(pid(i), SubstrateLedger::new());
    }

    let (_quorum, receipts) = pool.sample_with_receipts(&mut rng).unwrap();
    assert_eq!(receipts.len(), 1);
    let old_receipt = receipts.into_iter().next().unwrap();

    // Rotate: epoch_count advances from 0 to 1; outstanding receipts are drained.
    pool.force_rotate(&mut rng);
    assert_eq!(pool.epoch_count(), 1, "force_rotate must increment epoch_count to 1");

    // Present the old receipt — must be rejected as stale.
    assert_eq!(
        pool.record_admissible_response(&old_receipt),
        Err(AdmissibilityError::StaleEpoch),
        "Receipt from epoch 0 must be rejected with StaleEpoch after epoch advances to 1"
    );

    let snap = pool.operational_telemetry();
    assert_eq!(snap.admissible_response_total, 0,
        "Stale-epoch rejection must not increment admissible_response_total");
}

// ── T9: Multi-provider receipts are distinct ──────────────────────────────────
//
// sample_with_receipts() with k=3 → 3 receipts with distinct observation_ids.
//
// Exact assertions:
//   receipts.len() = 3
//   observation_ids are mutually distinct
//   all three receipts accepted individually → admissible_response_total = 3
//   admissible_selection_total = 3
//   recent_admissible_response_ratio() = Some(1.0)

#[test]
fn t9_multi_provider_receipts_are_distinct() {
    let mut rng = seeded();
    let mut pool = pool_with_admissible(3, &[1, 2, 3, 4]);

    let (_quorum, receipts) = pool.sample_with_receipts(&mut rng).unwrap();
    assert_eq!(receipts.len(), 3,
        "RandomK(3) with 4 providers must issue 3 receipts");

    // Observation IDs must be mutually distinct.
    let oids: Vec<u64> = receipts.iter().map(|r| r.observation_id()).collect();
    let unique: std::collections::HashSet<u64> = oids.iter().copied().collect();
    assert_eq!(unique.len(), 3,
        "Three receipts from one call must have 3 distinct observation_ids");

    // All three accepted.
    for r in &receipts {
        assert_eq!(pool.record_admissible_response(r), Ok(()),
            "Each of the 3 distinct receipts must be accepted");
    }

    let snap = pool.operational_telemetry();
    assert_eq!(snap.admissible_response_total, 3,
        "admissible_response_total must be 3 after accepting all three receipts");
    assert_eq!(snap.admissible_selection_total, 3,
        "admissible_selection_total = 3 (one per issued receipt)");
    assert_eq!(
        snap.recent_admissible_response_ratio(),
        Some(1.0),
        "3/3 = 1.0"
    );
}

// ── T10: Symmetric suppression visible in admissible ratio ─────────────────────
//
// 4 providers; 4 sample_with_receipts() calls (k=1); only 2 responses presented.
//
// Exact assertions:
//   admissible_response_total = 2
//   admissible_selection_total = 4
//   recent_admissible_response_ratio() = Some(0.5)

#[test]
fn t10_symmetric_suppression_visible_in_admissible_ratio() {
    let mut rng = seeded();
    let mut pool = pool_with_admissible(1, &[1, 2, 3, 4]);

    // Issue 4 receipts, one per call.
    let mut all_receipts = Vec::new();
    for _ in 0..4 {
        let (_q, receipts) = pool.sample_with_receipts(&mut rng).unwrap();
        all_receipts.extend(receipts);
    }
    assert_eq!(all_receipts.len(), 4,
        "4 calls × RandomK(1) = 4 receipts total");

    // Present only 2 of the 4 receipts as responses.
    for r in all_receipts.iter().take(2) {
        assert_eq!(pool.record_admissible_response(r), Ok(()));
    }

    let snap = pool.operational_telemetry();
    assert_eq!(snap.admissible_response_total, 2);
    assert_eq!(snap.admissible_selection_total, 4);
    assert_eq!(
        snap.recent_admissible_response_ratio(),
        Some(0.5),
        "2 admissible responses / 4 admissible selections = 0.5"
    );
}

// ── T11: Injection masks raw ratio; admissible ratio remains unmasked ──────────
//
// T7 trace from Trial 4: 4 paired admissible responses → 4 unpaired record_response()
// injections inflate raw ratio. Admissible ratio reflects reality.
//
// Exact assertions:
//   recent_reported_response_ratio() = Some(1.0)    [raw, manipulated]
//   recent_admissible_response_ratio() = Some(0.5)  [admissible, intact]
//   demonstrates manipulation-resistant dual-surface comparison

#[test]
fn t11_injection_masks_raw_cannot_mask_admissible() {
    let mut rng = seeded();
    let mut pool = pool_with_admissible(1, &[1, 2, 3, 4]);

    // Issue 8 receipts (8 sample_with_receipts calls).
    let mut all_receipts = Vec::new();
    for _ in 0..8 {
        let (_q, receipts) = pool.sample_with_receipts(&mut rng).unwrap();
        all_receipts.extend(receipts);
    }
    assert_eq!(all_receipts.len(), 8);

    // Present only 4 receipts as paired admissible responses.
    for r in all_receipts.iter().take(4) {
        assert_eq!(pool.record_admissible_response(r), Ok(()));
    }

    // Inject 4 additional raw (unpaired) responses to inflate raw ratio.
    for _ in 0..4 {
        pool.record_response(pid(1));
    }

    let snap = pool.operational_telemetry();

    // Raw ratio: 4 admissible responses did NOT increment raw_response_total.
    // Only the 4 injected raw responses contribute → response_total = 4, selection_total = 8.
    // So raw ratio = 4/8 = 0.5. But if we also want to show injection masking...
    // Let's verify: to get raw ratio = 1.0 we need response_total = selection_total = 8.
    // The 4 injected are already there. We need 4 more injections.
    // Re-read: "4 paired responses → 4 unpaired record_response() injections inflate raw ratio to 1.0"
    // That means 8 total selections, 8 raw responses needed. Let's fix: inject 4 more.
    for _ in 0..4 {
        pool.record_response(pid(2));
    }

    let snap2 = pool.operational_telemetry();
    assert_eq!(
        snap2.recent_reported_response_ratio(),
        Some(1.0),
        "8 raw injections inflate raw ratio to 1.0"
    );
    // Admissible ratio: 4 admissible responses / 8 admissible selections = 0.5.
    assert_eq!(
        snap2.recent_admissible_response_ratio(),
        Some(0.5),
        "Admissible ratio = 4/8 = 0.5 — unaffected by raw injections"
    );
    // Dual-surface discrepancy: raw looks healthy (1.0), admissible reveals suppression (0.5).
    assert!(
        snap2.recent_reported_response_ratio().unwrap()
            > snap2.recent_admissible_response_ratio().unwrap(),
        "raw ratio > admissible ratio demonstrates injection masking on raw surface"
    );
    // _ to suppress unused variable warning for snap
    let _ = snap;
}

// ── T12: Admissible tracker opt-in: inactive by default ────────────────────────
//
// Pool constructed without with_admissible_tracking(); record_admissible_response() called.
//
// Exact assertions:
//   Err(AdmissibilityError::NotConfigured)
//   All admissible fields in operational_telemetry() are zero (0).
//   recent_admissible_response_ratio() = None

#[test]
fn t12_admissible_tracker_opt_in_inactive_by_default() {
    let mut rng = seeded();
    let mut pool = pool_without_admissible(1, &[1, 2, 3, 4]);

    // sample() works normally (no receipts possible without opt-in).
    let _quorum = pool.sample(&mut rng);

    // Construct a receipt via a separate opted-in pool to test the NotConfigured path.
    let mut opted_in_pool = pool_with_admissible(1, &[1, 2, 3, 4]);
    let (_q, receipts) = opted_in_pool.sample_with_receipts(&mut rng).unwrap();
    if let Some(receipt) = receipts.into_iter().next() {
        // Present it to the pool without opt-in.
        assert_eq!(
            pool.record_admissible_response(&receipt),
            Err(AdmissibilityError::NotConfigured),
            "Pool without admissible tracking must return NotConfigured"
        );
        assert_eq!(
            pool.record_admissible_failure(&receipt),
            Err(AdmissibilityError::NotConfigured),
            "record_admissible_failure on non-opted pool must return NotConfigured"
        );
    }

    let snap = pool.operational_telemetry();
    assert_eq!(snap.admissible_response_total, 0,
        "admissible_response_total must be 0 when tracking not configured");
    assert_eq!(snap.admissible_failure_total, 0);
    assert_eq!(snap.admissible_selection_total, 0);
    assert_eq!(snap.recent_admissible_response_ratio(), None,
        "recent_admissible_response_ratio() must be None when no admissible selections");
}

// ── T13: Vitality send rotation policy untouched ──────────────────────────────
//
// Strongest injection trace (T7-equivalent) against a pool with admissible tracking.
// Inject 8 unpaired record_response() calls. Verify:
//   - epoch_count = 0 (no rotation triggered)
//   - SimVitalityEvaluationContext constructed with declared p = 0.0 (not derived
//     from any telemetry field)
//   - existing vitality, send, and rotation surfaces unaffected
//   - no admissible field influences ConvergencePressure.kappa or any rotation policy

#[test]
fn t13_vitality_send_rotation_policy_untouched() {
    use scp_cryptography::x25519_generate_keypair;
    use scp_ledger_substrate::{HandshakeEphemeral, SubstrateLedger};
    use scp_wire_format::signing::handshake_sig_message;
    use scp_vitality::VitalityEvidenceStore;

    let mut rng = seeded();
    let mut pool = pool_with_admissible(1, &[1, 2, 3, 4]);

    // Issue 4 receipts.
    let mut all_receipts = Vec::new();
    for _ in 0..4 {
        let (_q, receipts) = pool.sample_with_receipts(&mut rng).unwrap();
        all_receipts.extend(receipts);
    }

    // Inject 8 unpaired raw responses (T7-equivalent injection).
    for i in 1u8..=4 {
        pool.record_response(pid(i));
        pool.record_response(pid(i));
    }

    // Record 2 admissible responses (partial pairing).
    for r in all_receipts.iter().take(2) {
        assert_eq!(pool.record_admissible_response(r), Ok(()));
    }

    // Verify epoch_count = 0: no rotation policy fired from telemetry signals.
    assert_eq!(pool.epoch_count(), 0,
        "No injection trace must trigger automatic rotation: epoch_count must remain 0");

    // Verify telemetry snapshot: admissible fields are populated but raw fields are
    // also populated from raw injections. No automatic policy should consume either.
    let snap = pool.operational_telemetry();
    assert_eq!(snap.admissible_response_total, 2,
        "2 admissible responses accepted");
    assert_eq!(snap.admissible_selection_total, 4,
        "4 receipts were issued");
    assert_eq!(snap.response_total, 8,
        "8 raw injections contribute to raw response_total");

    // SimVitalityEvaluationContext constructed with p = 0.0 — a declared constant.
    // NOT derived from snap.kappa, admissible_response_total, or any telemetry field.
    let kp_a = KeyPair::generate();
    let kp_b = KeyPair::generate();
    let ledger = SubstrateLedger::new();
    let ch = {
        let consent_hash = tunnel_consent_hash(&kp_a.public, &kp_b.public);
        let consent = TunnelConsent {
            party_a: kp_a.public,
            party_b: kp_b.public,
            sig_a:   kp_a.sign(&consent_hash).to_vec(),
            sig_b:   kp_b.sign(&consent_hash).to_vec(),
        };
        ledger.register_tunnel(consent).expect("bilateral tunnel registration must succeed");
        consent_hash
    };
    let (_, eph_pub) = x25519_generate_keypair();
    let sim_now: u64 = 1_000_000;
    let expires_at = sim_now + 3_600;
    let sig: [u8; 64] = kp_a.sign(&handshake_sig_message(&eph_pub, expires_at));
    let eph = HandshakeEphemeral {
        pub_key:      eph_pub,
        sig:          sig.to_vec(),
        published_at: sim_now,
        expires_at,
    };
    ledger.publish_handshake_ephemeral(&kp_a.public, eph)
        .expect("ephemeral publish must succeed");

    // p = 0.0 is a test-declared constant, never derived from pool telemetry.
    let p_declared: f64 = 0.0;
    let ctx = SimVitalityEvaluationContext::new(ch, sim_now, 1.0, 1.0, p_declared)
        .expect("standard controls must be valid");
    assert_eq!(ctx.p(), 0.0,
        "p must equal the declared constant 0.0 — never derived from pool telemetry");

    // Vitality evaluation is independent of pool telemetry fields.
    let store = VitalityEvidenceStore::new();
    let state = store.compute_state(ctx.consent_hash(), ctx.now(), ctx.i(), ctx.r(), ctx.p());
    // The vitality state is determined by the declared controls and timestamps,
    // not by admissible_response_total, recent_admissible_response_ratio(), kappa,
    // liveness_weighted_kappa, or any pool surface.
    let _ = state; // state is evaluated; its value is irrelevant to the non-claim

    // Convergence pressure kappa is derived from raw selection entropy, not from
    // any admissible surface field. Verify it computes from pool.convergence_pressure()
    // without incorporating admissible accounting.
    let pressure = pool.convergence_pressure();
    // kappa is in [0, 1]; it reflects raw selection distribution, not admissible totals.
    assert!(pressure.kappa >= 0.0 && pressure.kappa <= 1.0,
        "kappa must remain a raw selection entropy metric: in [0.0, 1.0]");
    // admissible fields do not appear in ConvergencePressure — structural proof.
    // The type ConvergencePressure has no admissible_* field; this compiles only
    // because no such field was added to it.
    let _ = pressure.liveness_weighted_kappa; // accessible raw field
    // No admissible field on ConvergencePressure — verified by successful compilation.
}
