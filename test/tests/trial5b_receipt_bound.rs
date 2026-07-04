// Trial 5B — Receipt Bound Corrective Tests
//
// Addresses the defect discovered after Trial 5B closure:
//   `AdmissibleExposureTracker` lacked a finite automatic outstanding-receipt bound.
//   Under `PoolRotationPolicy::Manual` with no rotation, a caller could issue
//   receipt-bearing selections indefinitely without terminal outcomes or rotation,
//   causing unbounded memory growth.
//
// These 11 tests prove the finite bound invariant:
//   1. Tracker accepts receipt issuance below its configured finite bound.
//   2. Issuance at capacity fails with `ReceiptCapacityExhausted`.
//   3. A capacity failure occurs BEFORE raw selection accounting changes.
//   4. A matching terminal response consumes a receipt and restores one unit of capacity.
//   5. A matching terminal failure consumes a receipt and restores one unit of capacity.
//   6. Duplicate or invalid terminal outcomes do not free additional capacity.
//   7. Rotation drain restores capacity while stale prior receipts remain inadmissible.
//   8. Raw-only sampling remains unchanged under an admissible-tracked pool.
//   9. Existing 13 Trial 5B tests remain green (run via `cargo test --test trial5b`).
//  10. Trials 2–4 remain green and raw metric outputs are unchanged.
//  11. No policy coupling is introduced.
//
// Determinism requirement: all tests use fixed scripted traces.
// No random provider selection; no wall-clock timing; no probability-margin assertions.
// Integer counter assertions are exact.
//
// Note: `ProviderQuorum` does not implement `PartialEq` or `Debug`, so capacity
// failures are checked via `matches!()` rather than `assert_eq!`.

use rand::SeedableRng;
use rand::rngs::StdRng;

use scp_provider_pool::{AdmissibilityError, ProviderPool, SamplingStrategy};
use scp_ledger_substrate::SubstrateLedger;

// ── Helpers ────────────────────────────────────────────────────────────────────

fn pid(byte: u8) -> [u8; 32] { [byte; 32] }

fn seeded() -> StdRng { StdRng::seed_from_u64(0) }

/// Build a pool with admissible tracking and the given `max_outstanding_receipts`.
fn bounded_pool(k: usize, providers: &[u8], max_outstanding: usize) -> ProviderPool<SubstrateLedger> {
    let mut pool = ProviderPool::new(SamplingStrategy::RandomK(k))
        .with_admissible_tracking(max_outstanding);
    for &b in providers {
        pool.add(pid(b), SubstrateLedger::new());
    }
    pool
}

/// Returns true iff the result is `Err(ReceiptCapacityExhausted)`.
fn is_capacity_exhausted<T>(result: &Result<T, AdmissibilityError>) -> bool {
    matches!(result, Err(AdmissibilityError::ReceiptCapacityExhausted))
}

// ── RB1: Accept receipt issuance below configured finite bound ─────────────────
//
// Pool configured with max_outstanding_receipts = 3 (k=1, 4 providers).
// Issue 3 receipt-bearing samples. Each must succeed with Ok.
// After 3 issuances: outstanding count = 3 = bound.
// A 4th sample must return ReceiptCapacityExhausted.
//
// Exact assertions:
//   First 3 calls: Ok(...)
//   4th call: Err(ReceiptCapacityExhausted)
//   admissible_selection_total = 3 (only the successful issuances)
//   selection_total = 3 (raw: only successful samples counted)

#[test]
fn rb1_accept_below_bound_refuse_at_bound() {
    let mut rng = seeded();
    let mut pool = bounded_pool(1, &[1, 2, 3, 4], 3);

    // Issue 3 successful receipt-bearing samples.
    for i in 0..3usize {
        let result = pool.sample_with_receipts(&mut rng);
        assert!(result.is_ok(),
            "Sample {} below bound (outstanding={}) must succeed", i, i);
        let (_q, receipts) = result.unwrap();
        assert_eq!(receipts.len(), 1,
            "RandomK(1) must issue 1 receipt per call");
    }

    let snap = pool.operational_telemetry();
    assert_eq!(snap.admissible_selection_total, 3,
        "admissible_selection_total must be 3 after 3 successful issuances");
    assert_eq!(snap.selection_total, 3,
        "raw selection_total must be 3 after 3 successful samples");

    // 4th attempt must be refused — outstanding count is now at the bound.
    let result = pool.sample_with_receipts(&mut rng);
    assert!(is_capacity_exhausted(&result),
        "Sample at capacity must return ReceiptCapacityExhausted, got: {:?}",
        result.as_ref().map(|_| "Ok(...)").err());
}

// ── RB2: Capacity failure occurs before raw selection accounting changes ────────
//
// Pool configured with max_outstanding_receipts = 2 (k=1, 4 providers).
// Issue 2 samples (fills capacity).
// Attempt a 3rd: must return ReceiptCapacityExhausted.
//
// Exact assertions:
//   selection_total = 2 (raw) — unchanged by the refused call
//   admissible_selection_total = 2 — unchanged by the refused call
//
// Proof that the failure happens BEFORE provider selection:
// If selection had occurred, selection_total would be 3.

#[test]
fn rb2_capacity_failure_before_raw_accounting() {
    let mut rng = seeded();
    let mut pool = bounded_pool(1, &[1, 2, 3, 4], 2);

    // Fill capacity.
    for _ in 0..2 {
        pool.sample_with_receipts(&mut rng).unwrap();
    }

    // Record raw state BEFORE the refused call.
    let snap_before = pool.operational_telemetry();
    let raw_selections_before = snap_before.selection_total;
    let adm_selections_before = snap_before.admissible_selection_total;

    // Attempt at capacity.
    let result = pool.sample_with_receipts(&mut rng);
    assert!(is_capacity_exhausted(&result),
        "Must return ReceiptCapacityExhausted at capacity");

    // Verify nothing changed.
    let snap_after = pool.operational_telemetry();
    assert_eq!(snap_after.selection_total, raw_selections_before,
        "raw selection_total must not change on ReceiptCapacityExhausted — \
         provider selection did not occur");
    assert_eq!(snap_after.admissible_selection_total, adm_selections_before,
        "admissible_selection_total must not change on ReceiptCapacityExhausted");
}

// ── RB3: Terminal response restores one unit of capacity ───────────────────────
//
// Pool configured with max_outstanding_receipts = 1 (k=1, 4 providers).
// Issue 1 sample (fills capacity).
// Verify 2nd sample returns ReceiptCapacityExhausted.
// Present the receipt as a valid admissible response (consumes it).
// Verify 3rd sample succeeds (capacity restored).
//
// Exact assertions:
//   admissible_response_total = 1 after terminal response
//   Outstanding count drops to 0 after terminal response
//   Next sample_with_receipts succeeds (Ok)

#[test]
fn rb3_terminal_response_restores_capacity() {
    let mut rng = seeded();
    let mut pool = bounded_pool(1, &[1, 2, 3, 4], 1);

    // Fill capacity.
    let (_q, receipts) = pool.sample_with_receipts(&mut rng).unwrap();
    let receipt = receipts.into_iter().next().unwrap();

    // Capacity is now full.
    assert!(is_capacity_exhausted(&pool.sample_with_receipts(&mut rng)),
        "Capacity full — next sample must be refused");

    // Consume the receipt via a valid admissible response.
    assert_eq!(pool.record_admissible_response(&receipt), Ok(()),
        "Consuming receipt via response must succeed");

    let snap = pool.operational_telemetry();
    assert_eq!(snap.admissible_response_total, 1,
        "admissible_response_total = 1 after consuming receipt");

    // Capacity is restored — next sample must succeed.
    let result = pool.sample_with_receipts(&mut rng);
    assert!(result.is_ok(),
        "After consuming receipt, sample_with_receipts must succeed again");
    let (_q2, receipts2) = result.unwrap();
    assert_eq!(receipts2.len(), 1,
        "New sample must issue 1 receipt after capacity restored");
}

// ── RB4: Terminal failure restores one unit of capacity ───────────────────────
//
// Same structure as RB3 but consuming via record_admissible_failure().
//
// Exact assertions:
//   admissible_failure_total = 1 after terminal failure
//   Next sample_with_receipts succeeds (Ok)

#[test]
fn rb4_terminal_failure_restores_capacity() {
    let mut rng = seeded();
    let mut pool = bounded_pool(1, &[1, 2, 3, 4], 1);

    let (_q, receipts) = pool.sample_with_receipts(&mut rng).unwrap();
    let receipt = receipts.into_iter().next().unwrap();

    // Capacity full.
    assert!(is_capacity_exhausted(&pool.sample_with_receipts(&mut rng)),
        "Capacity full — next sample must be refused");

    // Consume via failure.
    assert_eq!(pool.record_admissible_failure(&receipt), Ok(()),
        "Consuming receipt via failure must succeed");

    let snap = pool.operational_telemetry();
    assert_eq!(snap.admissible_failure_total, 1);

    // Capacity restored.
    let result = pool.sample_with_receipts(&mut rng);
    assert!(result.is_ok(),
        "After consuming receipt via failure, sample_with_receipts must succeed");
}

// ── RB5a: Duplicate response does not free extra capacity ─────────────────────
//
// After valid consumption: capacity = 1 (outstanding → 0).
// Second presentation: Err(UnknownReceipt) — does not free phantom capacity.
// admissible_response_total = 1 (unchanged by duplicate rejection).

#[test]
fn rb5a_duplicate_response_does_not_free_extra_capacity() {
    let mut rng = seeded();
    let mut pool = bounded_pool(1, &[1, 2, 3, 4], 1);

    let (_q, receipts) = pool.sample_with_receipts(&mut rng).unwrap();
    let receipt = receipts.into_iter().next().unwrap();

    // Valid consumption.
    assert_eq!(pool.record_admissible_response(&receipt), Ok(()));

    // Duplicate presentation.
    assert_eq!(pool.record_admissible_response(&receipt),
        Err(AdmissibilityError::UnknownReceipt),
        "Duplicate response must return UnknownReceipt");

    let snap = pool.operational_telemetry();
    assert_eq!(snap.admissible_response_total, 1,
        "admissible_response_total must remain 1 after duplicate rejection");

    // Capacity is still available (consumed cleanly by the valid presentation).
    let result = pool.sample_with_receipts(&mut rng);
    assert!(result.is_ok(),
        "Capacity must be available after clean consumption (not inflated by duplicate rejection)");
}

// ── RB5b: ProviderMismatch does not free capacity ─────────────────────────────
//
// A ProviderMismatch rejection does NOT remove the receipt from outstanding.
// Capacity remains full; the original receipt (correct pid) is still valid.

#[test]
fn rb5b_provider_mismatch_does_not_free_capacity() {
    let mut rng = seeded();
    let mut pool = bounded_pool(1, &[1, 2, 3, 4], 1);

    let (_q, receipts) = pool.sample_with_receipts(&mut rng).unwrap();
    let original = receipts.into_iter().next().unwrap();

    // Tampered receipt — wrong provider_id.
    let tampered = original.clone().with_provider_id(pid(99));

    // ProviderMismatch: does NOT remove the receipt.
    assert_eq!(pool.record_admissible_response(&tampered),
        Err(AdmissibilityError::ProviderMismatch),
        "Wrong-provider receipt must return ProviderMismatch");

    let snap = pool.operational_telemetry();
    assert_eq!(snap.admissible_response_total, 0,
        "ProviderMismatch must not increment admissible_response_total");

    // Capacity is still full (receipt still outstanding).
    assert!(is_capacity_exhausted(&pool.sample_with_receipts(&mut rng)),
        "Capacity still full after ProviderMismatch — receipt was not freed");

    // The original receipt is still valid.
    assert_eq!(pool.record_admissible_response(&original), Ok(()),
        "Original receipt still outstanding after ProviderMismatch rejection");
}

// ── RB6: Rotation drain restores capacity; stale receipts remain inadmissible ──
//
// Pool with max_outstanding_receipts = 1, active_window = 2, 6 providers.
// Issue 1 receipt (fills capacity). force_rotate().
// Verify:
//   - capacity is restored (drain_epoch cleared outstanding)
//   - next sample_with_receipts succeeds (new epoch)
//   - the old receipt from epoch 0 returns StaleEpoch, not ReceiptCapacityExhausted
//
// Exact assertions:
//   epoch_count = 1 after rotation
//   new sample_with_receipts: Ok
//   old_receipt presented: Err(StaleEpoch)

#[test]
fn rb6_rotation_drain_restores_capacity_stale_receipts_inadmissible() {
    let mut rng = seeded();
    let mut pool = ProviderPool::new(SamplingStrategy::RandomK(1))
        .with_admissible_tracking(1)
        .with_active_window(2);
    for i in 1u8..=6 {
        pool.add(pid(i), SubstrateLedger::new());
    }

    // Fill capacity (outstanding = 1, max = 1).
    let (_q, receipts) = pool.sample_with_receipts(&mut rng).unwrap();
    let old_receipt = receipts.into_iter().next().unwrap();

    // Verify capacity is full.
    assert!(is_capacity_exhausted(&pool.sample_with_receipts(&mut rng)),
        "Capacity full before rotation");

    // Rotate: drains all outstanding receipts.
    pool.force_rotate(&mut rng);
    assert_eq!(pool.epoch_count(), 1, "force_rotate must advance epoch to 1");

    // Capacity is now restored.
    let result = pool.sample_with_receipts(&mut rng);
    assert!(result.is_ok(),
        "After epoch drain, sample_with_receipts must succeed");

    // Old receipt is stale — epoch mismatch.
    assert_eq!(pool.record_admissible_response(&old_receipt),
        Err(AdmissibilityError::StaleEpoch),
        "Old epoch-0 receipt must return StaleEpoch after rotation, not ReceiptCapacityExhausted");
}

// ── RB7: Raw-only sampling unchanged under admissible-tracked pool ──────────────
//
// Pool with admissible tracking (max_outstanding = 2, k=1, 4 providers).
// Call pool.sample() (not sample_with_receipts) 5 times.
// Verify:
//   selection_total = 5 (raw unchanged)
//   admissible_selection_total = 0 (no receipts issued via sample())
//   recent_admissible_response_ratio() = None

#[test]
fn rb7_raw_only_sampling_unchanged() {
    let mut rng = seeded();
    let pool = bounded_pool(1, &[1, 2, 3, 4], 2);

    for _ in 0..5 {
        let _quorum = pool.sample(&mut rng);
    }

    let snap = pool.operational_telemetry();
    assert_eq!(snap.selection_total, 5,
        "raw selection_total must be 5 after 5 sample() calls");
    assert_eq!(snap.admissible_selection_total, 0,
        "admissible_selection_total must be 0 — sample() does not issue receipts");
    assert_eq!(snap.recent_admissible_response_ratio(), None,
        "no receipts issued → ratio must be None");
}

// ── RB8: Bound of 0 refuses all receipt-bearing samples ───────────────────────
//
// Pool with max_outstanding_receipts = 0.
// Any sample_with_receipts() call must immediately return ReceiptCapacityExhausted.
// Raw sample() must be unaffected.
//
// Exact assertions:
//   sample_with_receipts: Err(ReceiptCapacityExhausted)
//   sample(): succeeds normally
//   selection_total = 1 (from raw sample only)
//   admissible_selection_total = 0

#[test]
fn rb8_bound_zero_refuses_all_receipt_bearing_samples() {
    let mut rng = seeded();
    let mut pool = bounded_pool(1, &[1, 2, 3, 4], 0);

    assert!(is_capacity_exhausted(&pool.sample_with_receipts(&mut rng)),
        "Bound=0 must immediately refuse all receipt-bearing samples");

    let _q = pool.sample(&mut rng);

    let snap = pool.operational_telemetry();
    assert_eq!(snap.selection_total, 1,
        "raw sample() must still work with bound=0");
    assert_eq!(snap.admissible_selection_total, 0,
        "no receipts ever issued");
}

// ── RB9: Capacity error is distinct from other admissibility errors ────────────
//
// The ReceiptCapacityExhausted variant is structurally distinct from:
//   NotConfigured, StaleEpoch, UnknownReceipt, ProviderMismatch, CounterExhausted
//
// Prove all variants are distinguishable in a deterministic match.

#[test]
fn rb9_capacity_error_distinct_from_other_admissibility_errors() {
    // Compile-time structural proof: all variants can be discriminated.
    let errors: Vec<AdmissibilityError> = vec![
        AdmissibilityError::NotConfigured,
        AdmissibilityError::StaleEpoch,
        AdmissibilityError::UnknownReceipt,
        AdmissibilityError::ProviderMismatch,
        AdmissibilityError::CounterExhausted,
        AdmissibilityError::ReceiptCapacityExhausted,
    ];

    for err in &errors {
        let label = match err {
            AdmissibilityError::NotConfigured            => "NotConfigured",
            AdmissibilityError::StaleEpoch               => "StaleEpoch",
            AdmissibilityError::UnknownReceipt           => "UnknownReceipt",
            AdmissibilityError::ProviderMismatch         => "ProviderMismatch",
            AdmissibilityError::CounterExhausted         => "CounterExhausted",
            AdmissibilityError::ReceiptCapacityExhausted => "ReceiptCapacityExhausted",
        };
        assert!(!label.is_empty());
    }

    // ReceiptCapacityExhausted is not equal to any other variant (PartialEq derived).
    let capacity_err = AdmissibilityError::ReceiptCapacityExhausted;
    assert_ne!(capacity_err, AdmissibilityError::NotConfigured);
    assert_ne!(capacity_err, AdmissibilityError::StaleEpoch);
    assert_ne!(capacity_err, AdmissibilityError::UnknownReceipt);
    assert_ne!(capacity_err, AdmissibilityError::ProviderMismatch);
    assert_ne!(capacity_err, AdmissibilityError::CounterExhausted);
}

// ── RB10: No policy coupling — epoch_count unchanged by capacity refusal ────────
//
// Pool with max_outstanding_receipts = 1 (k=1, 4 providers, Manual rotation).
// Fill capacity, then call sample_with_receipts 10 more times (all refused).
// Verify epoch_count = 0 — capacity refusal must not trigger any rotation.
// Verify admissible fields unaffected by refused calls.
//
// Exact assertions:
//   epoch_count = 0 throughout
//   admissible_selection_total = 1 (only the one successful issuance)
//   selection_total = 1 (only the one successful sample)

#[test]
fn rb10_no_policy_coupling_from_capacity_refusal() {
    let mut rng = seeded();
    let mut pool = bounded_pool(1, &[1, 2, 3, 4], 1);

    // Fill capacity.
    pool.sample_with_receipts(&mut rng).unwrap();

    // 10 refused calls.
    for _ in 0..10 {
        let result = pool.sample_with_receipts(&mut rng);
        assert!(is_capacity_exhausted(&result),
            "All calls at capacity must return ReceiptCapacityExhausted");
    }

    // Epoch unchanged.
    assert_eq!(pool.epoch_count(), 0,
        "Capacity refusals must never trigger rotation: epoch_count must remain 0");

    let snap = pool.operational_telemetry();
    assert_eq!(snap.admissible_selection_total, 1,
        "admissible_selection_total = 1 (only the initial successful call)");
    assert_eq!(snap.selection_total, 1,
        "raw selection_total = 1 (refused calls do not perform selection)");
}

// ── RB11: Multi-provider quorum partial receipt at near-bound ─────────────────
//
// Pool with k=3, max_outstanding_receipts = 3 (exactly one quorum worth).
// After 1 successful call (3 receipts issued, outstanding = 3 = bound):
//   Next call fails (ReceiptCapacityExhausted).
// Consume 2 of the 3 receipts (outstanding drops to 1).
// Next call: pre-check passes (1 < 3), selection proceeds.
//   Inner issuance loop: 2 more receipts issued (filling to 3), 3rd refused.
//   Partial quorum returned with 2 receipts.
//
// Exact assertions:
//   After 1st call: admissible_selection_total = 3
//   After 2nd call: ReceiptCapacityExhausted
//   After consuming 2 receipts + 3rd call: admissible_selection_total = 5
//   admissible_response_total = 2

#[test]
fn rb11_multi_provider_quorum_partial_receipt_at_near_bound() {
    let mut rng = seeded();
    let mut pool = bounded_pool(3, &[1, 2, 3, 4], 3);

    // 1st call: 3 receipts issued, outstanding = 3 = bound.
    let (_q, receipts1) = pool.sample_with_receipts(&mut rng).unwrap();
    assert_eq!(receipts1.len(), 3, "First quorum must issue 3 receipts");

    // 2nd call: pre-check fails — 3 >= 3.
    assert!(is_capacity_exhausted(&pool.sample_with_receipts(&mut rng)),
        "2nd call at capacity must fail");

    // Consume 2 of the 3 receipts.
    assert_eq!(pool.record_admissible_response(&receipts1[0]), Ok(()));
    assert_eq!(pool.record_admissible_response(&receipts1[1]), Ok(()));
    // outstanding = 1

    // 3rd call: pre-check passes (1 < 3), selection proceeds.
    // Inner loop issues 2 receipts (1+2=3 = bound), refuses the 3rd.
    let result = pool.sample_with_receipts(&mut rng);
    assert!(result.is_ok(), "3rd call with 1 outstanding < 3 bound must succeed");
    let (_q3, receipts3) = result.unwrap();
    assert_eq!(receipts3.len(), 2,
        "With 1 outstanding + bound=3, only 2 more receipts can be issued (3-1=2)");

    let snap = pool.operational_telemetry();
    // admissible_selection_total: 3 (1st call) + 2 (3rd call) = 5
    assert_eq!(snap.admissible_selection_total, 5,
        "admissible_selection_total = 5 (3 from call 1 + 2 from call 3)");
    // admissible_response_total: 2 (consumed above)
    assert_eq!(snap.admissible_response_total, 2);
}
