// Pool Delivery Seam — Phase 1 equivalence tests (Option 2, multi-relay design)
//
// See docs/architecture/PROVIDERPOOL_MULTIRELAY_ARCHITECTURE_DESIGN.md §1.3.
//
// `sample_inner()` (provider/pool/src/lib.rs) is relocated from
// `impl<P: Clone + StateProvider>` to `impl<P: Clone>`, and two new
// StateProvider-free accessors are added: `sample_selected()` and
// `sample_selected_with_receipts()`. This file proves the relocation is
// behavior-preserving: the new accessors produce identical observable state
// (telemetry, receipt provider-binding) to the existing `sample()` /
// `sample_with_receipts()` under an identical seeded trace.
//
// Explicit non-claims: this file does not exercise DeliveryPool, DeliveryEndpoint,
// or any real network I/O — those are Phase 2+.

use rand::rngs::StdRng;
use rand::SeedableRng;

use scp_ledger_substrate::SubstrateLedger;
use scp_provider_pool::{ProviderPool, SamplingStrategy};

fn pid(byte: u8) -> [u8; 32] {
    [byte; 32]
}
fn seeded() -> StdRng {
    StdRng::seed_from_u64(0)
}

fn fresh_pool(k: usize) -> ProviderPool<SubstrateLedger> {
    let mut pool = ProviderPool::new(SamplingStrategy::RandomK(k));
    for i in 1u8..=4 {
        pool.add(pid(i), SubstrateLedger::new());
    }
    pool
}

// ── sample_selected() vs sample(): identical telemetry from identical seed ────
//
// Both call the same relocated sample_inner() — the only difference is
// packaging (Vec<(id,P)> vs ProviderQuorum<P>). Twin fresh pools, identical
// seed, identical setup: exposure-tracker accounting (which sample_inner
// performs exactly once per call) must be byte-for-byte identical.

#[test]
fn sample_selected_matches_sample_telemetry() {
    let mut rng_a = seeded();
    let pool_a = fresh_pool(2);
    let selected = pool_a.sample_selected(&mut rng_a);
    assert_eq!(
        selected.len(),
        2,
        "RandomK(2) over 4 providers must select 2"
    );

    let mut rng_b = seeded();
    let pool_b = fresh_pool(2);
    let _quorum = pool_b.sample(&mut rng_b);

    let snap_a = pool_a.operational_telemetry();
    let snap_b = pool_b.operational_telemetry();
    assert_eq!(
        snap_a.selection_total, snap_b.selection_total,
        "sample_selected() and sample() must perform identical raw selection accounting"
    );
    assert_eq!(
        snap_a.kappa, snap_b.kappa,
        "identical seed + identical setup must yield identical kappa"
    );
    assert_eq!(snap_a.active_n, snap_b.active_n);
    assert!(snap_a.survivor_surface_evaluable == snap_b.survivor_surface_evaluable);
}

// Selected ids must be a subset of the pool's known provider ids, and RandomK(4)
// over exactly 4 providers must select all 4 (deterministic boundary case that
// does not depend on the Lemire RNG trace internals).
#[test]
fn sample_selected_returns_all_providers_when_k_equals_pool_size() {
    let mut rng = seeded();
    let pool = fresh_pool(4);
    let mut selected = pool.sample_selected(&mut rng);
    selected.sort_by_key(|(id, _)| *id);
    let expected: Vec<[u8; 32]> = (1u8..=4).map(pid).collect();
    let got: Vec<[u8; 32]> = selected.iter().map(|(id, _)| *id).collect();
    assert_eq!(
        got, expected,
        "RandomK(4) over 4 providers must select exactly all 4, in id order once sorted"
    );
}

// ── sample_selected_with_receipts() vs sample_with_receipts(): identical ──────
// admissible accounting and identical provider<->receipt binding.

#[test]
fn sample_selected_with_receipts_matches_sample_with_receipts_admissible_accounting() {
    let mut rng_a = seeded();
    let mut pool_a = ProviderPool::new(SamplingStrategy::RandomK(1)).with_admissible_tracking(16);
    for i in 1u8..=4 {
        pool_a.add(pid(i), SubstrateLedger::new());
    }
    let (selected, receipts) = pool_a.sample_selected_with_receipts(&mut rng_a).unwrap();
    assert_eq!(selected.len(), 1);
    assert_eq!(
        receipts.len(),
        1,
        "one provider selected → one receipt issued"
    );
    assert_eq!(
        selected[0].0,
        receipts[0].provider_id(),
        "the receipt must be bound to the exact provider sample_inner selected"
    );

    let mut rng_b = seeded();
    let mut pool_b = ProviderPool::new(SamplingStrategy::RandomK(1)).with_admissible_tracking(16);
    for i in 1u8..=4 {
        pool_b.add(pid(i), SubstrateLedger::new());
    }
    let (_quorum, receipts_b) = pool_b.sample_with_receipts(&mut rng_b).unwrap();
    assert_eq!(receipts_b.len(), 1);
    assert_eq!(
        receipts_b[0].provider_id(),
        receipts[0].provider_id(),
        "sample_with_receipts() must bind its receipt to the identical provider id"
    );

    // Both perform raw selection accounting exactly once (trial5b.rs T1 invariant).
    let snap_a = pool_a.operational_telemetry();
    let snap_b = pool_b.operational_telemetry();
    assert_eq!(snap_a.selection_total, 1);
    assert_eq!(snap_b.selection_total, 1);
    assert_eq!(
        snap_a.admissible_selection_total,
        snap_b.admissible_selection_total
    );
}

// ── sample_selected_with_receipts() respects the capacity-refusal contract ────
// (trial5b.rs documents ReceiptCapacityExhausted must block selection AND
// accounting entirely — the relocated version must preserve this exactly.)

#[test]
fn sample_selected_with_receipts_capacity_refusal_blocks_selection_and_accounting() {
    let mut rng = seeded();
    let mut pool = ProviderPool::new(SamplingStrategy::RandomK(1)).with_admissible_tracking(1);
    for i in 1u8..=4 {
        pool.add(pid(i), SubstrateLedger::new());
    }

    let (first, _) = pool.sample_selected_with_receipts(&mut rng).unwrap();
    assert_eq!(first.len(), 1);

    // Capacity (1) now exhausted by the one outstanding receipt.
    let result = pool.sample_selected_with_receipts(&mut rng);
    assert!(
        result.is_err(),
        "second call must be refused: capacity bound is 1 and one receipt is outstanding"
    );

    let snap = pool.operational_telemetry();
    assert_eq!(snap.selection_total, 1,
        "refused call must NOT perform raw selection accounting — same contract as sample_with_receipts()");
}
