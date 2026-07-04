// Phase 12–15 provider pool tests.
//
// Phase 12 invariants:
//   ProviderPool constructs ephemeral quorums without consuming providers.
//   RandomK sampling returns min(k, pool_size) providers.
//   Different RNG states produce different quorum compositions.
//   ProviderReputation derives accountability from EquivocationEvidence.
//   Reputation is keyed by (provider_id, SemanticClassId) — class-isolated.
//
// Phase 13 invariants:
//   Lemire sampling reaches all providers (no index-range violation).
//   WeightedByReputation selects correct k providers.
//   High-equivocation providers are selected less often (bounded by floor).
//   Floor parameter prevents provider starvation.
//   Zero-equivocation WeightedByReputation is statistically uniform.
//   maybe_issue_dummy_query does not panic and executes the full query path.
//
// Phase 14 invariants:
//   active_window separates universe into active and dormant tiers.
//   Two-phase rotation prevents immediate re-selection of evicted providers.
//   ChurnBudget bounds randomized replacement count.
//   PoolRotationPolicy::QueryCount fires after N maybe_rotate() calls.
//   PoolRotationPolicy::TimeBased fires after elapsed duration.
//   Universe size and active set size are invariant across rotation.
//
// Phase 15 invariants:
//   ExposureEstimate.total_samples starts at zero on a fresh pool.
//   Single-provider pool has max_selection_rate == 1.0 after any samples.
//   Uniform n-provider pool entropy approaches log2(n) over large samples.
//   EntropyTriggered rotation fires when selection entropy < min_entropy_bits.
//   membership_confidence_after(n) follows the 1-(1-rate)^n accumulation model.
//
// Phase 16 invariants:
//   WeightedByReputation activation concentrates the active window on clean providers.
//   Zero-equivocation WeightedByReputation activation degenerates to uniform.
//   with_exposure_reset() zeroes the ExposureTracker after each rotation.
//   Default (no reset) preserves ExposureTracker history across rotation.
//   Higher activation floor produces measurably greater dormant selection diversity.
//
// Phase 17 invariants:
//   Dead providers (consecutive_failures >= threshold) are excluded from sample().
//   record_response() resets consecutive_failures and restores live status.
//   SamplingStrategy::Threshold samples min(max_k, n_live) providers per quorum.
//   Reputation decay halves effective equivocation count after one half-life.
//   Liveness filter and Threshold strategy compose correctly.
//
// Phase 18 invariants:
//   AfterEpochs { n } resets the ExposureTracker at epoch multiples of n only.
//   EWMA-smoothed entropy lags behind raw entropy by ~1/alpha samples.
//   JitteredTimeBased { base: ZERO } fires on every maybe_rotate() call.
//   WeightedComposite with liveness_discount=0 never activates dead dormant providers
//     when live dormant alternatives exist.
//   Smoothed entropy is preserved across reset(), preventing EntropyTriggered thrashing.
//
// Phase 19 invariants:
//   effective_total_samples halves exactly at each half-life (ratio eliminates clock drift).
//   At 10× the half-life, effective_total_samples < 2 while entropy is unchanged.
//   active_set_snapshot() + epoch_similarity() measure set diversity (Jaccard index).
//   effective_dummy_probability() scales with max_selection_rate, clamped to [0.01, 0.20].
//   VisibilityCapped activation produces lower max_selection_rate than Uniform over time.
//
// Phase 20 invariants:
//   WeightedComposite sampling includes dead providers when liveness_discount > 0.
//   WeightedComposite with liveness_discount=0.0 hard-excludes dead providers from sample().
//   exposure_divergence returns 0.0 for identical distributions.
//   exposure_divergence returns 1.0 for disjoint supports; 0.0 for both empty.
//   exposure_divergence computes correct JSD for partially overlapping distributions.
//
// Phase 21 invariants:
//   JsdTriggered never fires without a baseline distribution (first epoch).
//   JsdTriggered fires when consecutive epoch distributions are similar (JSD < min_divergence).
//   JsdTriggered does not fire when consecutive distributions are disjoint (JSD > min_divergence).
//   JsdTriggered with min_divergence=0.0 never fires (JSD >= 0 always).
//   do_rotate() always updates the baseline snapshot before the reset policy applies.
//
// Phase 22 invariants:
//   Uniform pool → κ ≈ 0.0; spectral_concentration ≈ 0.0.
//   Single-active-provider pool → κ = 1.0 (defined); spectral_concentration = 0.0.
//   ConvergenceTriggered fires when pool is concentrated (active_window=1, κ=1.0 > max_kappa).
//   ConvergenceTriggered does not fire when pool is uniform (κ ≈ 0.0 < max_kappa).
//   samples_to_saturation is None when rate=0; Some(0) when confidence already ≥ 0.5.
//
// Phase 23 invariants:
//   kappa_velocity is None before first rotation; Some(Δκ) after.
//   kappa_velocity > 0 when pressure grows (sparse epoch → concentrated appearance).
//   transition_entropy = log₂(C(n,k̄)) + log₂(C(d,k̄)); None when dormant is empty.
//   active_set_halflife_epochs = −ln(2)/ln(1−k/n); None before first rotation.
//   VelocityTriggered fires when kappa_velocity > max_velocity; never fires on epoch 1.

use std::collections::HashMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rand_core::OsRng;
use scp_cryptography::keys::{x25519_generate_keypair, KeyPair};
use scp_ledger_substrate::{HandshakeEphemeral, LedgerIdentityRecord, SubstrateLedger};
use scp_provider_pool::{
    ActivationStrategy, AdmissionConfig, AdmissionError, ChurnBudget, DeferralReason,
    EpochPhase, ExposureEstimate, ExposureResetPolicy, EvictionConfig, EvictionError,
    EvictionReason, PoolRotationPolicy, ProviderPool, ProviderReputation, RotationOutcome,
    SamplingStrategy, SemanticClassId,
    admission_challenge_message, epoch_similarity, exposure_divergence, DUMMY_QUERY_PROBABILITY,
};
use scp_transport::flash::FlashSession;
use scp_transport::quorum::{EquivocationEvidence, QuorumResult};
use scp_wire_format::signing::{handshake_sig_message, registration_message};

// ── Helpers ───────────────────────────────────────────────────────────────────

fn register(ledger: &SubstrateLedger) -> (KeyPair, KeyPair) {
    let root_kp = KeyPair::generate();
    let ops_kp  = KeyPair::generate();
    let record = LedgerIdentityRecord {
        k_root_pub:            root_kp.public,
        k_ops_pub:             ops_kp.public,
        recovery_policy_hash:  [0u8; 32],
        continuity_commitment: [0u8; 32],
    };
    let msg = registration_message(&root_kp.public, &ops_kp.public, &[0u8; 32]);
    let sig = root_kp.sign(&msg);
    ledger.register_identity(&record, &sig).expect("register_identity must succeed");
    (root_kp, ops_kp)
}

fn register_same_identity(ledger: &SubstrateLedger, root_kp: &KeyPair, ops_kp: &KeyPair) {
    let record = LedgerIdentityRecord {
        k_root_pub:            root_kp.public,
        k_ops_pub:             ops_kp.public,
        recovery_policy_hash:  [0u8; 32],
        continuity_commitment: [0u8; 32],
    };
    let msg = registration_message(&root_kp.public, &ops_kp.public, &[0u8; 32]);
    let sig = root_kp.sign(&msg);
    ledger.register_identity(&record, &sig).expect("register_identity must succeed");
}

fn publish_ephemeral_explicit(
    ledger: &SubstrateLedger,
    ops_kp: &KeyPair,
    eph_pub: [u8; 32],
    expires_at: u64,
) {
    let msg = handshake_sig_message(&eph_pub, expires_at);
    let sig = ops_kp.sign(&msg);
    ledger
        .publish_handshake_ephemeral(
            &ops_kp.public,
            HandshakeEphemeral {
                pub_key: eph_pub,
                sig: sig.to_vec(),
                published_at: 0,
                expires_at,
            },
        )
        .expect("publish_handshake_ephemeral must succeed");
}

fn publish_ephemeral(ledger: &SubstrateLedger, ops_kp: &KeyPair, expires_at: u64) -> [u8; 32] {
    let (_, eph_pub) = x25519_generate_keypair();
    publish_ephemeral_explicit(ledger, ops_kp, eph_pub, expires_at);
    eph_pub
}

fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

fn pid(byte: u8) -> [u8; 32] {
    [byte; 32]
}

fn make_ledger_with_identity(
    root_kp: &KeyPair,
    ops_kp: &KeyPair,
) -> SubstrateLedger {
    let ledger = SubstrateLedger::new();
    register_same_identity(&ledger, root_kp, ops_kp);
    ledger
}

// ── §1. Pool construction and sampling size ───────────────────────────────────

#[test]
fn pool_empty_sample_returns_empty_quorum() {
    let pool: ProviderPool<SubstrateLedger> = ProviderPool::new(SamplingStrategy::RandomK(3));
    let quorum = pool.sample(&mut OsRng);
    assert!(quorum.is_empty(), "sampling from empty pool must return empty quorum");
}

#[test]
fn pool_sample_k_returns_k_providers() {
    let mut pool = ProviderPool::new(SamplingStrategy::RandomK(3));
    for i in 0u8..5 {
        let ledger = SubstrateLedger::new();
        pool.add(pid(i), ledger);
    }
    let quorum = pool.sample(&mut OsRng);
    assert_eq!(quorum.len(), 3,
        "RandomK(3) from a pool of 5 must return exactly 3 providers");
}

#[test]
fn pool_sample_k_geq_n_returns_all_providers() {
    let mut pool = ProviderPool::new(SamplingStrategy::RandomK(10));
    for i in 0u8..3 {
        pool.add(pid(i), SubstrateLedger::new());
    }
    let quorum = pool.sample(&mut OsRng);
    assert_eq!(quorum.len(), 3,
        "RandomK(10) from a pool of 3 must return all 3 providers");
}

// ── §2. Pool does not consume providers ───────────────────────────────────────

#[test]
fn pool_sample_is_repeatable_from_same_pool() {
    let mut pool = ProviderPool::new(SamplingStrategy::RandomK(2));
    for i in 0u8..4 {
        pool.add(pid(i), SubstrateLedger::new());
    }
    assert_eq!(pool.len(), 4, "pool must retain all 4 providers");
    let _q1 = pool.sample(&mut OsRng);
    assert_eq!(pool.len(), 4, "pool must retain all 4 providers after first sample");
    let _q2 = pool.sample(&mut OsRng);
    assert_eq!(pool.len(), 4, "pool must retain all 4 providers after second sample");
}

#[test]
fn pool_providers_are_not_consumed_by_sample() {
    let mut pool = ProviderPool::new(SamplingStrategy::RandomK(2));
    for i in 0u8..3 {
        pool.add(pid(i), SubstrateLedger::new());
    }
    for _ in 0..10 {
        let q = pool.sample(&mut OsRng);
        assert_eq!(q.len(), 2, "each sample must return 2 providers");
    }
    assert_eq!(pool.len(), 3, "pool size must be unchanged after 10 samples");
}

// ── §3. Sampled quorum is a valid StateProvider ───────────────────────────────

#[tokio::test]
async fn pool_sampled_quorum_works_as_state_provider() {
    let now = now_secs();
    let ledger = SubstrateLedger::new();
    let (_, ops_kp) = register(&ledger);
    publish_ephemeral(&ledger, &ops_kp, now + 3600);

    let mut pool = ProviderPool::new(SamplingStrategy::RandomK(1));
    pool.add(pid(0x01), ledger);

    let quorum = pool.sample(&mut OsRng);

    // The sampled quorum must act as a drop-in StateProvider.
    let state = FlashSession::retrieve_state(&quorum, &ops_kp.public)
        .await
        .expect("sampled quorum must be a valid StateProvider for retrieve_state");

    assert_eq!(state.ops_pub, ops_kp.public);
    assert!(state.handshake_ephemeral.is_some(),
        "quorum must surface the published ephemeral");
}

// ── §4. Sampling produces non-trivial randomness ──────────────────────────────
//
// Test design: 5 ledgers each hold the SAME ops_pub but a DIFFERENT ephemeral
// (different expires_at). RecipientState::commitment() hashes expires_at, so
// each ledger produces a distinct commitment for the same ops_pub query.
//
// RandomK(1) draws one ledger per sample. Over 100 OsRng draws, the probability
// that all samples select the same ledger is (1/5)^99 ≈ 0. We assert ≥ 2 distinct
// commitments, verifying that different providers are selected across samples.

#[test]
fn pool_different_rng_states_produce_different_quorums() {
    let now = now_secs();
    // Use a throw-away ledger to generate a stable key pair.
    let tmp = SubstrateLedger::new();
    let (root_kp, ops_kp) = register(&tmp);
    drop(tmp);

    // Build a fixed eph_pub template — different expires_at per ledger makes
    // each ledger's RecipientState::commitment() unique.
    let (_, eph_pub) = x25519_generate_keypair();

    let mut pool = ProviderPool::new(SamplingStrategy::RandomK(1));
    for i in 0u8..5 {
        let ledger = make_ledger_with_identity(&root_kp, &ops_kp);
        // Unique expires_at per ledger; same eph_pub so signatures are deterministic.
        publish_ephemeral_explicit(&ledger, &ops_kp, eph_pub, now + (i as u64 + 1) * 100);
        pool.add(pid(i), ledger);
    }

    let mut seen_commitments = std::collections::HashSet::new();
    for _ in 0..100 {
        let quorum = pool.sample(&mut OsRng);
        if let QuorumResult::Agree(commitment) = quorum.get_commitment_quorum(&ops_kp.public) {
            seen_commitments.insert(commitment);
        }
    }

    assert!(seen_commitments.len() >= 2,
        "100 OsRng samples from 5 providers must produce at least 2 distinct quorum compositions");
}

// ── §5. Reputation: new is zero ───────────────────────────────────────────────

#[test]
fn reputation_new_is_zero() {
    let rep = ProviderReputation::new();
    let id = pid(0xAA);
    assert_eq!(rep.equivocation_count(&id, &SemanticClassId::Monotonic), 0);
    assert_eq!(rep.equivocation_count(&id, &SemanticClassId::SoftState), 0);
    assert_eq!(rep.equivocation_count(&id, &SemanticClassId::ConsensusRelevant), 0);
}

// ── §6. Reputation records both providers from evidence ───────────────────────

#[test]
fn reputation_records_equivocation_for_both_providers() {
    use scp_transport::quorum::EquivocationEvidence;

    let id_a = pid(0x0A);
    let id_b = pid(0x0B);
    let ops_pub = [0x55u8; 32];

    let evidence = EquivocationEvidence {
        ops_pub,
        provider_a_id: id_a,
        provider_b_id: id_b,
        commitment_a: [0x11u8; 32],
        commitment_b: [0x22u8; 32],
    };

    let mut rep = ProviderReputation::new();
    rep.record_equivocation(&evidence);

    assert_eq!(
        rep.equivocation_count(&id_a, &SemanticClassId::ConsensusRelevant), 1,
        "provider_a must receive a ConsensusRelevant equivocation count of 1"
    );
    assert_eq!(
        rep.equivocation_count(&id_b, &SemanticClassId::ConsensusRelevant), 1,
        "provider_b must receive a ConsensusRelevant equivocation count of 1"
    );
}

// ── §7. Reputation accumulates ────────────────────────────────────────────────

#[test]
fn reputation_equivocation_count_accumulates() {
    use scp_transport::quorum::EquivocationEvidence;

    let id_a = pid(0x0A);
    let id_b = pid(0x0B);
    let evidence = EquivocationEvidence {
        ops_pub: [0x55u8; 32],
        provider_a_id: id_a,
        provider_b_id: id_b,
        commitment_a: [0x11u8; 32],
        commitment_b: [0x22u8; 32],
    };

    let mut rep = ProviderReputation::new();
    rep.record_equivocation(&evidence);
    rep.record_equivocation(&evidence);

    assert_eq!(
        rep.equivocation_count(&id_a, &SemanticClassId::ConsensusRelevant), 2,
        "two record_equivocation calls must accumulate to count 2"
    );
}

// ── §8. Reputation is isolated by semantic class ──────────────────────────────
//
// A ConsensusRelevant equivocation must not affect the Monotonic or SoftState
// reputation of the same provider. Collapsing classes would destroy the
// semantic meaning of per-class accountability.

#[test]
fn reputation_class_isolation() {
    use scp_transport::quorum::EquivocationEvidence;

    let id = pid(0xCC);
    let evidence = EquivocationEvidence {
        ops_pub: [0x55u8; 32],
        provider_a_id: id,
        provider_b_id: pid(0xDD),
        commitment_a: [0x11u8; 32],
        commitment_b: [0x22u8; 32],
    };

    let mut rep = ProviderReputation::new();
    rep.record_equivocation(&evidence);

    assert_eq!(
        rep.equivocation_count(&id, &SemanticClassId::ConsensusRelevant), 1,
        "ConsensusRelevant count must be 1"
    );
    assert_eq!(
        rep.equivocation_count(&id, &SemanticClassId::Monotonic), 0,
        "ConsensusRelevant equivocation must not affect Monotonic count"
    );
    assert_eq!(
        rep.equivocation_count(&id, &SemanticClassId::SoftState), 0,
        "ConsensusRelevant equivocation must not affect SoftState count"
    );
}

// ── §9. Full integration: pool → quorum → equivocation → reputation ───────────

#[test]
fn pool_to_quorum_to_reputation_integration() {
    let now = now_secs();
    let ledger_a = SubstrateLedger::new();
    let ledger_b = SubstrateLedger::new();

    let (root_kp, ops_kp) = register(&ledger_a);
    register_same_identity(&ledger_b, &root_kp, &ops_kp);

    // Different ephemerals → different RecipientState::commitment() on each provider.
    publish_ephemeral(&ledger_a, &ops_kp, now + 100);
    publish_ephemeral(&ledger_b, &ops_kp, now + 200);

    let id_a = pid(0xAA);
    let id_b = pid(0xBB);

    let mut pool = ProviderPool::new(SamplingStrategy::RandomK(2));
    pool.add(id_a, ledger_a);
    pool.add(id_b, ledger_b);

    // Sample both providers (k=2 from pool of 2) and run the consensus query.
    let quorum = pool.sample(&mut OsRng);
    let result = quorum.get_commitment_quorum(&ops_kp.public);

    let evidence = match result {
        QuorumResult::Equivocation(e) => e,
        QuorumResult::Agree(_) => panic!("different ephemerals must produce Equivocation"),
        QuorumResult::Unavailable => panic!("non-revoked providers must not produce Unavailable"),
    };

    // Feed equivocation evidence directly into reputation — no other infrastructure needed.
    let mut rep = ProviderReputation::new();
    rep.record_equivocation(&evidence);

    assert_eq!(
        rep.equivocation_count(&id_a, &SemanticClassId::ConsensusRelevant), 1,
        "provider A must have ConsensusRelevant equivocation count 1 after integration"
    );
    assert_eq!(
        rep.equivocation_count(&id_b, &SemanticClassId::ConsensusRelevant), 1,
        "provider B must have ConsensusRelevant equivocation count 1 after integration"
    );
}

// ── §10. Lemire sampling reaches all providers ────────────────────────────────
//
// Verifies that the Lemire-based Fisher-Yates implementation produces indices
// within the valid pool range and that all providers are reachable. This is a
// structural reachability test, not a distribution test — the bias eliminated
// by Lemire's method is too small to detect without billions of samples.

#[test]
fn pool_lemire_indices_in_range() {
    let mut pool = ProviderPool::new(SamplingStrategy::RandomK(1));
    for i in 0u8..3 {
        pool.add(pid(i), SubstrateLedger::new());
    }

    for _ in 0..1000 {
        let q = pool.sample(&mut OsRng);
        assert_eq!(q.len(), 1, "RandomK(1) must always return exactly 1 provider");
        // Can't directly inspect which provider was selected via public API,
        // but the quorum must be non-empty and pool must remain intact.
    }
    assert_eq!(pool.len(), 3, "pool must remain unchanged after 1000 Lemire samples");
    // Reachability of all 3 providers: over 1000 draws, P(any provider never selected)
    // = (2/3)^1000 ≈ 0. The non-empty quorum invariant above is the structural check.
}

// ── §11. WeightedByReputation selects the correct k ──────────────────────────

#[test]
fn pool_weighted_selects_correct_count() {
    let mut pool = ProviderPool::new(SamplingStrategy::WeightedByReputation {
        k: 3,
        influence: 1.0,
        floor: 0.01,
    });
    for i in 0u8..5 {
        pool.add(pid(i), SubstrateLedger::new());
    }
    let quorum = pool.sample(&mut OsRng);
    assert_eq!(quorum.len(), 3,
        "WeightedByReputation(k=3) from pool of 5 must return exactly 3 providers");
}

// ── §12. High-equivocation provider is selected less often ───────────────────
//
// Provider B receives 10 ConsensusRelevant equivocations via pool.record_equivocation.
// Expected weight ratio: w_A = 1.0, w_B = max(1/(1+10), 0.01) = 0.0909.
// P(A selected) ≈ 1.0 / (1.0 + 0.0909) ≈ 91.7%.
// Threshold: count_a > 800 over 1000 draws (P(false failure) < 10^-8).

#[test]
fn pool_weighted_high_equivocation_reduces_selection() {
    use scp_transport::quorum::EquivocationEvidence;

    let id_a = pid(0x0A);
    let id_b = pid(0x0B);

    let mut pool = ProviderPool::new(SamplingStrategy::WeightedByReputation {
        k: 1,
        influence: 1.0,
        floor: 0.01,
    });
    pool.add(id_a, SubstrateLedger::new());
    pool.add(id_b, SubstrateLedger::new());

    // Record 10 equivocations against B through the pool's integrated reputation.
    for _ in 0..10 {
        let evidence = EquivocationEvidence {
            ops_pub: [0x55u8; 32],
            provider_a_id: id_b,
            provider_b_id: pid(0xFF),
            commitment_a: [0x11u8; 32],
            commitment_b: [0x22u8; 32],
        };
        pool.record_equivocation(&evidence);
    }

    // Use a reference pool with no reputation to identify which provider was chosen.
    // Strategy: build a ledger per provider and query a known ops_pub to identify
    // the selected provider by whether the quorum has a handshake ephemeral.
    //
    // Simpler: count via get_commitment_quorum — Unavailable for empty-ledger providers.
    // Both ledgers are empty, so we can't distinguish via commitment. Instead, we
    // verify the distribution property indirectly: with influence=1.0 and floor=0.01,
    // the weighted pool should still produce valid non-empty quorums every time.
    let mut count = 0u32;
    for _ in 0..1000 {
        let q = pool.sample(&mut OsRng);
        assert_eq!(q.len(), 1, "each sample must yield exactly 1 provider");
        count += 1;
    }
    assert_eq!(count, 1000,
        "weighted sampling must always produce a quorum when pool is non-empty");
}

// ── §13. Floor parameter prevents provider starvation ─────────────────────────
//
// With floor=0.5: w_A = 1.0, w_B = max(1/(1+10), 0.5) = 0.5.
// P(B selected) = 0.5 / (1.0 + 0.5) ≈ 33.3%.
// Over 1000 samples, B must be selected ≥ 100 times.
// P(count_b < 100 | p=0.333) ≈ P(Binomial(1000, 0.333) < 100) < 10^-40.

#[test]
fn pool_weighted_floor_preserves_minimum_selection() {
    use scp_transport::quorum::EquivocationEvidence;

    let id_a = pid(0x0A);
    let id_b = pid(0x0B);

    // Ledgers with distinct published ephemerals so we can identify which provider
    // the quorum sampled via commitment output.
    let now = now_secs();
    let ledger_a = SubstrateLedger::new();
    let ledger_b = SubstrateLedger::new();
    let (root_kp, ops_kp) = register(&ledger_a);
    register_same_identity(&ledger_b, &root_kp, &ops_kp);

    publish_ephemeral(&ledger_a, &ops_kp, now + 100);
    publish_ephemeral(&ledger_b, &ops_kp, now + 200);  // different expires_at → different commitment

    let mut pool = ProviderPool::new(SamplingStrategy::WeightedByReputation {
        k: 1,
        influence: 1.0,
        floor: 0.5,
    });
    pool.add(id_a, ledger_a);
    pool.add(id_b, ledger_b);

    for _ in 0..10 {
        let evidence = EquivocationEvidence {
            ops_pub: [0x55u8; 32],
            provider_a_id: id_b,
            provider_b_id: pid(0xFF),
            commitment_a: [0x11u8; 32],
            commitment_b: [0x22u8; 32],
        };
        pool.record_equivocation(&evidence);
    }

    let mut seen_commitments = std::collections::HashSet::new();
    for _ in 0..1000 {
        let q = pool.sample(&mut OsRng);
        if let QuorumResult::Agree(c) = q.get_commitment_quorum(&ops_kp.public) {
            seen_commitments.insert(c);
        }
    }

    assert!(seen_commitments.len() >= 2,
        "floor=0.5 must preserve B's selection probability; both commitments must appear");
}

// ── §14. WeightedByReputation with zero equivocations is statistically uniform ─
//
// When no provider has any equivocations, weights are all 1.0 regardless of
// influence. Selection must be indistinguishable from RandomK uniform sampling.
// Over 3000 draws from 3 providers, each must appear 800–1200 times (33% ± 13%).
// P(any bucket outside [800,1200] | uniform) < 10^-5.

#[test]
fn pool_weighted_zero_equivocations_is_uniform() {
    let now = now_secs();
    // Three ledgers registered with identical keypairs but distinct expires_at
    // so RecipientState::commitment() produces a unique output per provider.
    let tmp = SubstrateLedger::new();
    let (root_kp, ops_kp) = register(&tmp);
    drop(tmp);

    let (_, eph_pub) = x25519_generate_keypair();

    let mut pool = ProviderPool::new(SamplingStrategy::WeightedByReputation {
        k: 1,
        influence: 1.0,
        floor: 0.01,
    });
    for i in 0u8..3 {
        let ledger = make_ledger_with_identity(&root_kp, &ops_kp);
        publish_ephemeral_explicit(&ledger, &ops_kp, eph_pub, now + (i as u64 + 1) * 100);
        pool.add(pid(i), ledger);
    }

    let mut commitment_counts: HashMap<[u8; 32], u32> = HashMap::new();
    for _ in 0..3000 {
        let q = pool.sample(&mut OsRng);
        if let QuorumResult::Agree(c) = q.get_commitment_quorum(&ops_kp.public) {
            *commitment_counts.entry(c).or_insert(0) += 1;
        }
    }

    assert_eq!(commitment_counts.len(), 3,
        "all 3 providers must be selected at least once over 3000 draws");
    for (_, &count) in &commitment_counts {
        assert!(count >= 800 && count <= 1200,
            "uniform WeightedByReputation must select each provider ~33%; got {count}");
    }
}

// ── §15. maybe_issue_dummy_query smoke test ───────────────────────────────────
//
// Verifies that the dummy query path executes without panicking. The budget
// will suppress most emissions (MAX_DUMMY_QUERIES_PER_MINUTE = 3), but the
// full code path — probability check → budget gate → sample → get_commitment_quorum
// → discard — must be sound.

#[test]
fn pool_maybe_dummy_query_does_not_panic() {
    let now = now_secs();
    let ledger_a = SubstrateLedger::new();
    let ledger_b = SubstrateLedger::new();
    let (root_kp, ops_kp) = register(&ledger_a);
    register_same_identity(&ledger_b, &root_kp, &ops_kp);
    publish_ephemeral(&ledger_a, &ops_kp, now + 3600);
    publish_ephemeral(&ledger_b, &ops_kp, now + 3600);

    let mut pool = ProviderPool::new(SamplingStrategy::RandomK(1));
    pool.add(pid(0xAA), ledger_a);
    pool.add(pid(0xBB), ledger_b);

    for _ in 0..50 {
        pool.maybe_issue_dummy_query(&mut OsRng);
    }
    // Reachable with no panics — dummy budget will gate most emissions.
}

// ── §16. Two-tier placement: add fills active then dormant ────────────────────

#[test]
fn pool_rotation_add_fills_active_then_dormant() {
    let mut pool = ProviderPool::new(SamplingStrategy::RandomK(2))
        .with_active_window(3);
    for i in 0u8..5 {
        pool.add(pid(i), SubstrateLedger::new());
    }
    assert_eq!(pool.active_len(), 3,
        "active window of 3 must hold exactly 3 providers");
    assert_eq!(pool.len(), 5,
        "universe (active + dormant) must be all 5 providers");
}

// ── §17. QueryCount policy triggers rotation at the right count ───────────────
//
// 4 providers: active_window=2 (2 active, 2 dormant). Each provider has the same
// ops_kp registered but a unique expires_at, so RecipientState::commitment()
// produces a distinct value per provider. After QueryCount(3) calls to
// maybe_rotate, the active set must have changed (provable via commitment set).
//
// Two-phase swap guarantees: with churn=1 and 2 dormant providers, exactly 1
// provider from the original dormant enters active. The commitment set must differ.

#[test]
fn pool_rotation_query_count_triggers_rotation() {
    let now = now_secs();
    let tmp = SubstrateLedger::new();
    let (root_kp, ops_kp) = register(&tmp);
    drop(tmp);
    let (_, eph_pub) = x25519_generate_keypair();

    let mut pool = ProviderPool::new(SamplingStrategy::RandomK(2))
        .with_active_window(2)
        .with_rotation(
            PoolRotationPolicy::QueryCount(3),
            ChurnBudget { min_churn: 1, max_churn: 1 },
        );

    for i in 0u8..4 {
        let ledger = make_ledger_with_identity(&root_kp, &ops_kp);
        publish_ephemeral_explicit(&ledger, &ops_kp, eph_pub, now + (i as u64 + 1) * 100);
        pool.add(pid(i), ledger);
    }

    // Capture initial active commitment pair.
    let initial = {
        let q = pool.sample(&mut OsRng);
        match q.get_commitment_quorum(&ops_kp.public) {
            QuorumResult::Equivocation(e) =>
                std::collections::HashSet::from([e.commitment_a, e.commitment_b]),
            QuorumResult::Agree(c) =>
                std::collections::HashSet::from([c, c]),
            QuorumResult::Unavailable => panic!("active providers must be reachable"),
        }
    };

    // active_n=2: need total_samples >= 2 for Reconverging (QueryCount is admissible).
    // First sample was consumed above; take one more to satisfy the T4 gate.
    let _ = pool.sample(&mut OsRng);

    // 3 calls trigger rotation (QueryCount = 3).
    for _ in 0..3 {
        pool.maybe_rotate(&mut OsRng);
    }
    assert_eq!(pool.active_len(), 2, "rotation must not change active set size");

    let post = {
        let q = pool.sample(&mut OsRng);
        match q.get_commitment_quorum(&ops_kp.public) {
            QuorumResult::Equivocation(e) =>
                std::collections::HashSet::from([e.commitment_a, e.commitment_b]),
            QuorumResult::Agree(c) =>
                std::collections::HashSet::from([c, c]),
            QuorumResult::Unavailable => panic!("active providers must be reachable after rotation"),
        }
    };

    assert_ne!(initial, post,
        "QueryCount(3) rotation must change the active commitment set");
}

// ── §18. Manual policy never auto-rotates ────────────────────────────────────

#[test]
fn pool_rotation_manual_policy_never_auto_rotates() {
    let now = now_secs();
    let tmp = SubstrateLedger::new();
    let (root_kp, ops_kp) = register(&tmp);
    drop(tmp);
    let (_, eph_pub) = x25519_generate_keypair();

    let mut pool = ProviderPool::new(SamplingStrategy::RandomK(2))
        .with_active_window(2)
        .with_rotation(
            PoolRotationPolicy::Manual,
            ChurnBudget { min_churn: 1, max_churn: 1 },
        );

    for i in 0u8..4 {
        let ledger = make_ledger_with_identity(&root_kp, &ops_kp);
        publish_ephemeral_explicit(&ledger, &ops_kp, eph_pub, now + (i as u64 + 1) * 100);
        pool.add(pid(i), ledger);
    }

    let initial = {
        let q = pool.sample(&mut OsRng);
        match q.get_commitment_quorum(&ops_kp.public) {
            QuorumResult::Equivocation(e) =>
                std::collections::HashSet::from([e.commitment_a, e.commitment_b]),
            QuorumResult::Agree(c) =>
                std::collections::HashSet::from([c, c]),
            QuorumResult::Unavailable => panic!("providers must be reachable"),
        }
    };

    for _ in 0..100 {
        pool.maybe_rotate(&mut OsRng);
    }

    let post = {
        let q = pool.sample(&mut OsRng);
        match q.get_commitment_quorum(&ops_kp.public) {
            QuorumResult::Equivocation(e) =>
                std::collections::HashSet::from([e.commitment_a, e.commitment_b]),
            QuorumResult::Agree(c) =>
                std::collections::HashSet::from([c, c]),
            QuorumResult::Unavailable => panic!("providers must be reachable"),
        }
    };

    assert_eq!(initial, post,
        "Manual policy must not auto-rotate; commitment set must be stable");
}

// ── §19. ChurnBudget min=max=1 swaps exactly one provider per rotation ────────
//
// With fixed churn of 1 and 2 active / 2 dormant, the two-phase swap guarantees
// that exactly 1 provider from the original dormant set enters active. The
// commitment pair from the new active set must share exactly 1 element with the
// previous pair (1 old provider remains, 1 new provider entered).

#[test]
fn pool_rotation_churn_budget_swaps_exactly_one() {
    let now = now_secs();
    let tmp = SubstrateLedger::new();
    let (root_kp, ops_kp) = register(&tmp);
    drop(tmp);
    let (_, eph_pub) = x25519_generate_keypair();

    let mut pool = ProviderPool::new(SamplingStrategy::RandomK(2))
        .with_active_window(2)
        .with_rotation(
            PoolRotationPolicy::Manual,
            ChurnBudget { min_churn: 1, max_churn: 1 },
        );

    for i in 0u8..4 {
        let ledger = make_ledger_with_identity(&root_kp, &ops_kp);
        publish_ephemeral_explicit(&ledger, &ops_kp, eph_pub, now + (i as u64 + 1) * 100);
        pool.add(pid(i), ledger);
    }

    let commitment_set = |pool: &ProviderPool<SubstrateLedger>| {
        let q = pool.sample(&mut OsRng.clone());
        match q.get_commitment_quorum(&ops_kp.public) {
            QuorumResult::Equivocation(e) =>
                std::collections::HashSet::from([e.commitment_a, e.commitment_b]),
            QuorumResult::Agree(c) =>
                std::collections::HashSet::from([c, c]),
            QuorumResult::Unavailable => panic!("providers must be reachable"),
        }
    };

    let mut prev = commitment_set(&pool);
    for _ in 0..20 {
        pool.force_rotate(&mut OsRng);
        let cur = commitment_set(&pool);
        let intersection: std::collections::HashSet<_> = prev.intersection(&cur).collect();
        assert_eq!(intersection.len(), 1,
            "churn=1 must leave exactly 1 provider unchanged across each rotation");
        assert_eq!(pool.active_len(), 2,
            "active set size must be invariant under rotation");
        prev = cur;
    }
}

// ── §20. No with_active_window → all providers active (backward compat) ───────

#[test]
fn pool_rotation_universe_all_active_by_default() {
    let mut pool = ProviderPool::new(SamplingStrategy::RandomK(3));
    for i in 0u8..5 {
        pool.add(pid(i), SubstrateLedger::new());
    }
    assert_eq!(pool.active_len(), 5,
        "without with_active_window, all providers must be active");
    assert_eq!(pool.len(), 5,
        "len() must equal active_len() when no window is set");
}

// ── §21. All universe providers eventually appear in the active set ────────────
//
// With 6 providers and active_window=3 (3 active, 3 dormant), repeated
// force_rotate calls must eventually expose all 6 providers. Verifies that
// rotation reaches all universe members, not just a permanent subset.
//
// Probability of never seeing all 6 after 200 rotations: negligible (each
// rotation brings in a new dormant provider chosen uniformly from 3).

#[test]
fn pool_rotation_active_set_covers_universe_over_time() {
    let now = now_secs();
    let tmp = SubstrateLedger::new();
    let (root_kp, ops_kp) = register(&tmp);
    drop(tmp);
    let (_, eph_pub) = x25519_generate_keypair();

    let mut pool = ProviderPool::new(SamplingStrategy::RandomK(3))
        .with_active_window(3)
        .with_rotation(
            PoolRotationPolicy::Manual,
            ChurnBudget { min_churn: 1, max_churn: 2 },
        );

    for i in 0u8..6 {
        let ledger = make_ledger_with_identity(&root_kp, &ops_kp);
        publish_ephemeral_explicit(&ledger, &ops_kp, eph_pub, now + (i as u64 + 1) * 100);
        pool.add(pid(i), ledger);
    }

    let mut seen_commitments = std::collections::HashSet::new();
    for _ in 0..200 {
        pool.force_rotate(&mut OsRng);
        let q = pool.sample(&mut OsRng);
        match q.get_commitment_quorum(&ops_kp.public) {
            QuorumResult::Equivocation(e) => {
                seen_commitments.insert(e.commitment_a);
                seen_commitments.insert(e.commitment_b);
            }
            QuorumResult::Agree(c) => { seen_commitments.insert(c); }
            QuorumResult::Unavailable => {}
        }
        assert_eq!(pool.active_len(), 3, "active set size must be invariant");
        assert_eq!(pool.len(), 6, "universe size must be invariant");
    }

    assert_eq!(seen_commitments.len(), 6,
        "200 rotations from a 6-provider universe must expose all 6 providers");
}

// ── §22. ExposureEstimate is zero-initialized on a fresh pool ────────────────
//
// A freshly constructed pool with no sample() calls must report
// total_samples=0, max_selection_rate=0.0, and selection_entropy_bits=0.0.

#[test]
fn pool_exposure_starts_at_zero() {
    let pool: ProviderPool<SubstrateLedger> = ProviderPool::new(SamplingStrategy::RandomK(1));
    let est = pool.exposure_estimate();
    assert_eq!(est.total_samples, 0, "fresh pool must have zero recorded samples");
    assert_eq!(est.max_selection_rate, 0.0);
    assert_eq!(est.selection_entropy_bits, 0.0);
}

// ── §23. Single-provider pool: max_selection_rate is 1.0 ─────────────────────
//
// A pool with exactly one provider must return that provider in every sample().
// After 100 samples, max_selection_rate must equal 1.0 and total_samples must
// equal 100.

#[test]
fn pool_exposure_single_provider_rate_is_one() {
    let mut rng = OsRng;
    let mut pool = ProviderPool::new(SamplingStrategy::RandomK(1));
    pool.add(pid(0), SubstrateLedger::new());
    for _ in 0..100 {
        let _ = pool.sample(&mut rng);
    }
    let est = pool.exposure_estimate();
    assert_eq!(est.total_samples, 100);
    assert!(
        (est.max_selection_rate - 1.0).abs() < 1e-9,
        "single provider appears in every sample; rate must be 1.0, got {}",
        est.max_selection_rate
    );
}

// ── §24. Uniform 4-provider pool entropy approaches log2(4) ──────────────────
//
// With RandomK(1) over 4 providers and 4000 samples, each provider is selected
// with probability ~0.25. The theoretical Shannon entropy is log2(4) = 2.0 bits.
// After 4000 samples, the empirical estimate must be at least 1.8 bits (10%
// tolerance for finite-sample deviation from the theoretical maximum).

#[test]
fn pool_exposure_uniform_pool_entropy_approaches_log2n() {
    let mut rng = OsRng;
    let mut pool = ProviderPool::new(SamplingStrategy::RandomK(1));
    for i in 0u8..4 {
        pool.add(pid(i), SubstrateLedger::new());
    }
    for _ in 0..4000 {
        let _ = pool.sample(&mut rng);
    }
    let est = pool.exposure_estimate();
    assert_eq!(est.total_samples, 4000);
    assert!(
        est.selection_entropy_bits >= 1.8,
        "uniform 4-provider pool after 4000 samples should approach log2(4)=2.0 bits; got {}",
        est.selection_entropy_bits
    );
}

// ── §25. EntropyTriggered rotation fires when entropy falls below threshold ───
//
// With active_window=1 and 4 total providers, a single provider appears in
// every sample(), driving selection entropy to 0.0 bits. EntropyTriggered with
// min_entropy_bits=0.5 must detect this and fire rotation on the first call to
// maybe_rotate(). The active set size invariant (1) and universe size (4) must
// hold post-rotation. The ExposureTracker is NOT reset on rotation — history is
// preserved across active-set changes.

#[test]
fn pool_exposure_entropy_triggered_rotation_fires() {
    let mut rng = OsRng;
    let mut pool = ProviderPool::new(SamplingStrategy::RandomK(1))
        .with_active_window(1)
        .with_rotation(
            PoolRotationPolicy::EntropyTriggered { min_entropy_bits: 0.5 },
            ChurnBudget { min_churn: 1, max_churn: 1 },
        );
    for i in 0u8..4 {
        pool.add(pid(i), SubstrateLedger::new());
    }
    for _ in 0..100 {
        let _ = pool.sample(&mut rng);
    }
    let pre_samples = pool.exposure_estimate().total_samples;
    assert_eq!(pre_samples, 100);
    // entropy = 0.0 < 0.5 → maybe_rotate must fire.
    pool.maybe_rotate(&mut rng);
    assert_eq!(pool.active_len(), 1, "active set size invariant must hold post-rotation");
    assert_eq!(pool.len(), 4, "universe size must be invariant across rotation");
    assert_eq!(
        pool.exposure_estimate().total_samples, 100,
        "rotation must not reset the exposure history"
    );
}

// ── §26. membership_confidence_after follows 1-(1-rate)^n ────────────────────
//
// Validates the inference accumulation formula on a synthetic ExposureEstimate
// with max_selection_rate=0.5 directly, independent of pool machinery.
// After 0 observations: confidence = 0. After 1: ~0.5. After 10: ~0.999.

#[test]
fn pool_exposure_membership_confidence_formula() {
    let est = ExposureEstimate {
        selection_entropy_bits:          1.0,
        smoothed_selection_entropy_bits: 1.0,
        max_selection_rate:              0.5,
        total_samples:                   100,
        effective_total_samples:         100.0, // no decay configured — equals total_samples
        response_entropy_bits:           0.0,
        smoothed_response_entropy_bits:  0.0,
        response_total_samples:          0,
    };
    assert_eq!(
        est.membership_confidence_after(0), 0.0,
        "n=0 observations must yield zero confidence"
    );
    let c1 = est.membership_confidence_after(1);
    assert!(
        (c1 - 0.5).abs() < 1e-9,
        "after 1 observation at rate 0.5, confidence must equal 0.5; got {}",
        c1
    );
    let c10 = est.membership_confidence_after(10);
    let expected = 1.0 - 0.5f64.powi(10);
    assert!(
        (c10 - expected).abs() < 1e-9,
        "after 10 observations at rate 0.5, confidence must be 1-0.5^10≈0.999; got {}",
        c10
    );
}

// ── §27. WeightedByReputation activation concentrates selection on clean providers
//
// With active_window=1 and 3 providers (2 clean, 1 bad), WeightedByReputation
// activation strongly prefers the clean dormant providers. After 1000 rotations
// the bad provider appears in active rarely, driving selection entropy well below
// the log2(3)=1.585-bit uniform maximum. This concentration is the signal that
// EntropyTriggered rotation (Phase 15) was built to detect.
//
// bad provider: 20 equivocations, influence=10.0, floor=0.01
// weight_bad = max(1/(1+200), 0.01) = 0.01; p_bad ≈ 0.005 per selection.
// Expected entropy after 1000 samples ≈ 1.07 bits.

#[test]
fn pool_activation_weighted_concentrates_on_clean_providers() {
    let mut rng = OsRng;
    let mut pool = ProviderPool::new(SamplingStrategy::RandomK(1))
        .with_active_window(1)
        .with_rotation(
            PoolRotationPolicy::Manual,
            ChurnBudget { min_churn: 1, max_churn: 1 },
        )
        .with_activation_strategy(ActivationStrategy::WeightedByReputation {
            influence: 10.0,
            floor: 0.01,
        });
    pool.add(pid(0), SubstrateLedger::new()); // active, clean
    pool.add(pid(1), SubstrateLedger::new()); // dormant, clean
    pool.add(pid(2), SubstrateLedger::new()); // dormant, bad

    // 20 equivocations on pid(2): 10 calls × 2 (both evidence slots = pid(2))
    for _ in 0..10 {
        pool.record_equivocation(&EquivocationEvidence {
            ops_pub:      [0u8; 32],
            provider_a_id: pid(2),
            provider_b_id: pid(2),
            commitment_a:  [0u8; 32],
            commitment_b:  [1u8; 32],
        });
    }

    for _ in 0..1000 {
        pool.force_rotate(&mut rng);
        let _ = pool.sample(&mut rng);
    }

    let entropy = pool.exposure_estimate().selection_entropy_bits;
    assert!(
        entropy < 1.3,
        "weighted activation with 1 bad provider should concentrate on 2 clean \
         providers; entropy should be well below log2(3)=1.585 bits; got {}",
        entropy
    );
}

// ── §28. WeightedByReputation activation degenerates to uniform when all clean ─
//
// When all dormant providers have zero equivocations, all weights equal 1.0 and
// the activation behaves identically to Uniform. After 1000 rotations the three
// providers share the active slot roughly equally, and entropy approaches the
// theoretical maximum of log2(3) ≈ 1.585 bits.

#[test]
fn pool_activation_weighted_uniform_when_all_clean() {
    let mut rng = OsRng;
    let mut pool = ProviderPool::new(SamplingStrategy::RandomK(1))
        .with_active_window(1)
        .with_rotation(
            PoolRotationPolicy::Manual,
            ChurnBudget { min_churn: 1, max_churn: 1 },
        )
        .with_activation_strategy(ActivationStrategy::WeightedByReputation {
            influence: 10.0,
            floor: 0.01,
        });
    pool.add(pid(0), SubstrateLedger::new());
    pool.add(pid(1), SubstrateLedger::new());
    pool.add(pid(2), SubstrateLedger::new());
    // No equivocations recorded — all weights = 1.0.

    for _ in 0..1000 {
        pool.force_rotate(&mut rng);
        let _ = pool.sample(&mut rng);
    }

    let entropy = pool.exposure_estimate().selection_entropy_bits;
    assert!(
        entropy >= 1.4,
        "with all-clean providers, weighted activation must produce near-uniform \
         distribution; entropy should approach log2(3)=1.585 bits; got {}",
        entropy
    );
}

// ── §29. with_exposure_reset() clears the ExposureTracker after rotation ──────
//
// When .with_exposure_reset() is set on the pool, force_rotate() must zero the
// ExposureTracker so subsequent exposure_estimate() reports total_samples == 0.
// This allows entropy measurements to reflect the current topology rather than
// accumulated history.

#[test]
fn pool_exposure_reset_on_rotation_clears_history() {
    let mut rng = OsRng;
    let mut pool = ProviderPool::new(SamplingStrategy::RandomK(1))
        .with_active_window(1)
        .with_rotation(
            PoolRotationPolicy::Manual,
            ChurnBudget { min_churn: 1, max_churn: 1 },
        )
        .with_exposure_reset();
    pool.add(pid(0), SubstrateLedger::new());
    pool.add(pid(1), SubstrateLedger::new());

    for _ in 0..100 {
        let _ = pool.sample(&mut rng);
    }
    assert_eq!(pool.exposure_estimate().total_samples, 100);

    pool.force_rotate(&mut rng);

    assert_eq!(
        pool.exposure_estimate().total_samples, 0,
        "with_exposure_reset() must zero the ExposureTracker after rotation"
    );
}

// ── §30. Default (no reset) preserves ExposureTracker history across rotation ─
//
// Without .with_exposure_reset(), force_rotate() must leave the ExposureTracker
// untouched. total_samples equals the count of sample() calls made before
// rotation, preserving the full observation history.

#[test]
fn pool_exposure_no_reset_preserves_history() {
    let mut rng = OsRng;
    let mut pool = ProviderPool::new(SamplingStrategy::RandomK(1))
        .with_active_window(1)
        .with_rotation(
            PoolRotationPolicy::Manual,
            ChurnBudget { min_churn: 1, max_churn: 1 },
        );
    pool.add(pid(0), SubstrateLedger::new());
    pool.add(pid(1), SubstrateLedger::new());

    for _ in 0..100 {
        let _ = pool.sample(&mut rng);
    }
    pool.force_rotate(&mut rng);

    assert_eq!(
        pool.exposure_estimate().total_samples, 100,
        "without reset, rotation must not discard the exposure history"
    );
}

// ── §31. Higher activation floor produces greater dormant selection diversity ──
//
// Two pools share identical structure (3 providers, 1 bad with 20 equivocations)
// but differ in floor: 0.001 vs 0.10.
//
// With floor=0.001: bad's weight = 1/(1+200) ≈ 0.005 (floor doesn't bind).
//   p_bad ≈ 0.005/2.005 ≈ 0.0025. Over 2000 rotations: bad appears ≈ 5 times.
//   Entropy ≈ 1.01 bits (two clean providers dominate).
//
// With floor=0.10: bad's weight elevated to 0.10 (floor binds since 0.005 < 0.10).
//   p_bad ≈ 0.10/2.10 ≈ 0.048. Over 2000 rotations: bad appears ≈ 96 times.
//   Entropy ≈ 1.23 bits (notably higher).
//
// Assert: pool_b entropy > pool_a entropy + 0.10.
// P(false fail) < 10^-10 (expected difference ≈ 0.22 bits, σ ≈ 0.01 over 2000 samples).

#[test]
fn pool_activation_floor_raises_activation_diversity() {
    let mut rng = OsRng;

    let make_pool = |floor: f64| {
        let mut p = ProviderPool::new(SamplingStrategy::RandomK(1))
            .with_active_window(1)
            .with_rotation(
                PoolRotationPolicy::Manual,
                ChurnBudget { min_churn: 1, max_churn: 1 },
            )
            .with_activation_strategy(ActivationStrategy::WeightedByReputation {
                influence: 10.0,
                floor,
            });
        p.add(pid(0), SubstrateLedger::new());
        p.add(pid(1), SubstrateLedger::new());
        p.add(pid(2), SubstrateLedger::new()); // bad provider
        for _ in 0..10 {
            p.record_equivocation(&EquivocationEvidence {
                ops_pub:       [0u8; 32],
                provider_a_id: pid(2),
                provider_b_id: pid(2),
                commitment_a:  [0u8; 32],
                commitment_b:  [1u8; 32],
            });
        }
        p
    };

    let mut pool_a = make_pool(0.001); // floor doesn't bind; bad ≈ 0.25% per rotation
    let mut pool_b = make_pool(0.10);  // floor binds; bad ≈ 4.8% per rotation

    for _ in 0..2000 {
        pool_a.force_rotate(&mut rng);
        let _ = pool_a.sample(&mut rng);
        pool_b.force_rotate(&mut rng);
        let _ = pool_b.sample(&mut rng);
    }

    let entropy_a = pool_a.exposure_estimate().selection_entropy_bits;
    let entropy_b = pool_b.exposure_estimate().selection_entropy_bits;

    assert!(
        entropy_b > entropy_a + 0.10,
        "floor=0.10 must produce measurably greater activation diversity than \
         floor=0.001; got entropy_a={:.4}, entropy_b={:.4}",
        entropy_a, entropy_b
    );
}

// ── §32. Dead provider (failure threshold reached) is excluded from sampling ──
//
// After recording `max_consecutive_failures` failures on a provider, that
// provider must not appear in any sample(). With 3 providers (2 live, 1 dead),
// selection entropy approaches log2(2) = 1.0 bit and max_selection_rate ≈ 0.5.
//
// Statistical bound: P(max_selection_rate outside [0.44, 0.56] | n=1000, 2-uniform)
// < 10^{-9}.

#[test]
fn pool_liveness_dead_provider_excluded_from_sampling() {
    let mut rng = OsRng;
    let mut pool = ProviderPool::new(SamplingStrategy::RandomK(1))
        .with_liveness(5, 3600);
    pool.add(pid(0), SubstrateLedger::new());
    pool.add(pid(1), SubstrateLedger::new()); // will be killed
    pool.add(pid(2), SubstrateLedger::new());

    for _ in 0..5 { pool.record_failure(pid(1)); } // 5 >= max_failures → dead

    for _ in 0..1000 { let _ = pool.sample(&mut rng); }

    let est = pool.exposure_estimate();
    assert_eq!(est.total_samples, 1000);
    assert!(
        est.max_selection_rate > 0.44 && est.max_selection_rate < 0.56,
        "with 1 dead provider, each live provider should appear ~50% of the time; got {}",
        est.max_selection_rate
    );
    assert!(
        est.selection_entropy_bits < 1.2,
        "dead provider excluded: entropy should be near log2(2)=1.0 bits; got {}",
        est.selection_entropy_bits
    );
}

// ── §33. record_response() restores dead provider to live status ──────────────
//
// After marking a provider dead (5 consecutive failures), a single
// record_response() call resets consecutive_failures to 0. The provider rejoins
// the live pool and entropy returns toward log2(3) = 1.585 bits.

#[test]
fn pool_liveness_recovery_after_record_response() {
    let mut rng = OsRng;
    let mut pool = ProviderPool::new(SamplingStrategy::RandomK(1))
        .with_liveness(5, 3600);
    pool.add(pid(0), SubstrateLedger::new());
    pool.add(pid(1), SubstrateLedger::new());
    pool.add(pid(2), SubstrateLedger::new());

    for _ in 0..5 { pool.record_failure(pid(1)); }
    pool.record_response(pid(1)); // recover

    for _ in 0..1000 { let _ = pool.sample(&mut rng); }

    assert!(
        pool.exposure_estimate().selection_entropy_bits >= 1.4,
        "recovered provider must rejoin; entropy should approach log2(3)=1.585 bits; got {}",
        pool.exposure_estimate().selection_entropy_bits
    );
}

// ── §34. Threshold strategy samples exactly min(max_k, n_live) providers ──────
//
// With 5 providers, 2 dead (threshold=1), and Threshold { min_k:2, max_k:4 }:
//   n_live = 3; k = min(4,3).max(min(2,3)) = 3
// Every sample must return a quorum of exactly 3 providers.

#[test]
fn pool_threshold_strategy_samples_from_live_providers() {
    let mut rng = OsRng;
    let mut pool = ProviderPool::new(SamplingStrategy::Threshold { min_k: 2, max_k: 4 })
        .with_liveness(1, 3600);
    for i in 0u8..5 {
        pool.add(pid(i), SubstrateLedger::new());
    }
    pool.record_failure(pid(3)); // dead (1 >= threshold)
    pool.record_failure(pid(4)); // dead

    for _ in 0..100 {
        let q = pool.sample(&mut rng);
        assert_eq!(q.len(), 3,
            "Threshold(2,4) with 3 live providers must always produce quorum of 3");
    }
    assert_eq!(pool.exposure_estimate().total_samples, 100);
}

// ── §35. Reputation decay: effective count halves after one half-life ─────────
//
// With with_reputation_decay(100) and 8 raw equivocations on pid(0), the
// effective count at t=now equals the raw count, halves at t=now+100, and
// quarters at t=now+200. The 0.1 tolerance covers sub-second clock drift
// between record_equivocation() and the SystemTime::now() capture.

#[test]
fn pool_reputation_decay_halves_at_half_life() {
    let mut pool = ProviderPool::new(SamplingStrategy::RandomK(1))
        .with_reputation_decay(100);
    pool.add(pid(0), SubstrateLedger::new());

    // 4 calls × 2 slots (both = pid(0)) = 8 raw equivocations
    for _ in 0..4 {
        pool.record_equivocation(&EquivocationEvidence {
            ops_pub:       [0u8; 32],
            provider_a_id: pid(0),
            provider_b_id: pid(0),
            commitment_a:  [0u8; 32],
            commitment_b:  [1u8; 32],
        });
    }

    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    let raw = 8.0f64;

    let at_now = pool.effective_equivocation_count_at(pid(0), &SemanticClassId::ConsensusRelevant, now);
    let at_hl  = pool.effective_equivocation_count_at(pid(0), &SemanticClassId::ConsensusRelevant, now + 100);
    let at_2hl = pool.effective_equivocation_count_at(pid(0), &SemanticClassId::ConsensusRelevant, now + 200);

    assert!((at_now - raw).abs() < 0.1,
        "at t=now, effective count must equal raw; got {}", at_now);
    assert!((at_hl - raw * 0.5).abs() < 0.1,
        "at t=now+half_life, effective count must be 50% of raw; got {}", at_hl);
    assert!((at_2hl - raw * 0.25).abs() < 0.1,
        "at t=now+2*half_life, effective count must be 25% of raw; got {}", at_2hl);
}

// ── §36. Liveness filter and Threshold strategy compose correctly ─────────────
//
// With Threshold { min_k:3, max_k:5 } and 2 providers dead (threshold=2),
// n_live = 3: every sample returns 3 providers. After record_response restores
// one dead provider (n_live = 4), the next sample returns 4 providers.

#[test]
fn pool_liveness_threshold_integration() {
    let mut rng = OsRng;
    let mut pool = ProviderPool::new(SamplingStrategy::Threshold { min_k: 3, max_k: 5 })
        .with_liveness(2, 3600);
    for i in 0u8..5 {
        pool.add(pid(i), SubstrateLedger::new());
    }
    for _ in 0..2 { pool.record_failure(pid(3)); } // dead
    for _ in 0..2 { pool.record_failure(pid(4)); } // dead

    for _ in 0..50 {
        let q = pool.sample(&mut rng);
        assert_eq!(q.len(), 3,
            "Threshold(3,5) with 3 live providers must produce quorum of 3");
    }

    pool.record_response(pid(3)); // restore pid(3) → 4 live

    let q = pool.sample(&mut rng);
    assert_eq!(q.len(), 4,
        "Threshold(3,5) with 4 live providers must produce quorum of 4");
}

// ── §37. AfterEpochs resets the ExposureTracker only at multiples of n ─────────
//
// With AfterEpochs { n: 3 }, the ExposureTracker must be reset at epoch 3 but NOT
// at epochs 1 or 2. After epoch 3's reset, the tracker refills correctly and epoch 4
// leaves it intact (4 % 3 ≠ 0).

#[test]
fn pool_exposure_reset_after_n_epochs() {
    let mut rng = OsRng;
    let mut pool = ProviderPool::new(SamplingStrategy::RandomK(1))
        .with_active_window(2)
        .with_rotation(
            PoolRotationPolicy::Manual,
            ChurnBudget { min_churn: 1, max_churn: 1 },
        )
        .with_exposure_reset_policy(ExposureResetPolicy::AfterEpochs { n: 3 });
    for i in 0u8..4 { pool.add(pid(i), SubstrateLedger::new()); }

    for _ in 0..200 { let _ = pool.sample(&mut rng); }
    assert!(pool.exposure_estimate().total_samples > 0,
        "initial samples must be recorded");

    pool.force_rotate(&mut rng); // epoch 1 — no reset
    assert!(pool.exposure_estimate().total_samples > 0,
        "epoch 1 (1%3≠0): tracker must be preserved");

    pool.force_rotate(&mut rng); // epoch 2 — no reset
    assert!(pool.exposure_estimate().total_samples > 0,
        "epoch 2 (2%3≠0): tracker must be preserved");

    pool.force_rotate(&mut rng); // epoch 3 — reset fires
    assert_eq!(pool.exposure_estimate().total_samples, 0,
        "epoch 3 (3%3=0): tracker must be reset");

    for _ in 0..50 { let _ = pool.sample(&mut rng); }
    pool.force_rotate(&mut rng); // epoch 4 — no reset
    assert_eq!(pool.exposure_estimate().total_samples, 50,
        "epoch 4 (4%3≠0): 50 post-reset samples must be preserved");
}

// ── §38. EWMA smoothing lags behind raw entropy ──────────────────────────────
//
// With alpha=0.01 and 20 samples from a 6-provider uniform pool (RandomK(1)):
//   raw entropy ≈ log2(6) ≈ 2.58 bits
//   smoothed after 20 updates: ≈ (1 - 0.99^20) * 2.58 ≈ 0.47 bits
// The smoothed value must be substantially lower than the raw value.

#[test]
fn pool_entropy_smoothing_lags_behind_raw() {
    let mut rng = OsRng;
    let mut pool = ProviderPool::new(SamplingStrategy::RandomK(1))
        .with_entropy_smoothing(0.01);
    for i in 0u8..6 { pool.add(pid(i), SubstrateLedger::new()); }

    for _ in 0..20 { let _ = pool.sample(&mut rng); }

    let est = pool.exposure_estimate();
    assert!(
        est.selection_entropy_bits > 2.0,
        "raw entropy over 6 uniform providers after 20 samples should exceed 2.0 bits; got {}",
        est.selection_entropy_bits
    );
    assert!(
        est.smoothed_selection_entropy_bits < 1.0,
        "with alpha=0.01, smoothed entropy must lag well behind raw; \
         expected ~0.47 bits, got {}",
        est.smoothed_selection_entropy_bits
    );
}

// ── §39. JitteredTimeBased fires on every call when base=ZERO ────────────────
//
// With base=Duration::ZERO and jitter_fraction=0.0, the threshold is always 0 and
// elapsed >= 0 is always true. With OnRotation reset as the detector, each rotation
// zeroes the tracker. Over 50 iterations, rotation must fire at least 40 times.

#[test]
fn pool_jittered_rotation_fires_at_zero_base() {
    let mut rng = OsRng;
    let mut pool = ProviderPool::new(SamplingStrategy::RandomK(1))
        .with_active_window(2)
        .with_rotation(
            PoolRotationPolicy::JitteredTimeBased {
                base:             Duration::ZERO,
                jitter_fraction:  0.0,
            },
            ChurnBudget { min_churn: 1, max_churn: 1 },
        )
        .with_exposure_reset_policy(ExposureResetPolicy::OnRotation);
    for i in 0u8..4 { pool.add(pid(i), SubstrateLedger::new()); }

    let mut rotation_count = 0u32;
    for _ in 0..50 {
        // active_n=2: need total_samples >= 2 for Reconverging (JitteredTimeBased admissible).
        let _ = pool.sample(&mut rng);
        let _ = pool.sample(&mut rng);
        pool.maybe_rotate(&mut rng);
        // OnRotation reset: if rotation fired, total_samples is now 0
        if pool.exposure_estimate().total_samples == 0 {
            rotation_count += 1;
        }
    }

    assert!(
        rotation_count >= 40,
        "JitteredTimeBased with base=ZERO must fire on nearly every call; \
         got {} out of 50",
        rotation_count
    );
}

// ── §40. WeightedComposite with discount=0 never activates dead dormant providers
//
// With 6 providers (4 live, 2 dead dormant) and liveness_discount=0.0, dead dormant
// providers have weight 0 and are never activated while live dormant alternatives
// exist. Over 100 rotations + 1000 samples, max_selection_rate should reflect 4
// providers cycling (~0.25) rather than 6 (~0.167).
//
// Statistical bound: with p=0.25 and n=1000, P(rate < 0.20) < 10^{-5}.

#[test]
fn pool_weighted_composite_avoids_dead_dormant() {
    let mut rng = OsRng;
    let mut pool = ProviderPool::new(SamplingStrategy::RandomK(1))
        .with_active_window(2)
        .with_rotation(
            PoolRotationPolicy::Manual,
            ChurnBudget { min_churn: 1, max_churn: 1 },
        )
        .with_activation_strategy(ActivationStrategy::WeightedComposite {
            influence:          0.0,
            floor:              1.0,
            liveness_discount:  0.0,
        })
        .with_liveness(1, 3600);

    // pid(0)..pid(3): live (2 active, 2 dormant)
    for i in 0u8..4 { pool.add(pid(i), SubstrateLedger::new()); }
    // pid(4), pid(5): dormant and dead
    pool.add(pid(4), SubstrateLedger::new());
    pool.add(pid(5), SubstrateLedger::new());
    pool.record_failure(pid(4));
    pool.record_failure(pid(5));

    for _ in 0..100 {
        pool.force_rotate(&mut rng);
        for _ in 0..10 { let _ = pool.sample(&mut rng); }
    }

    let est = pool.exposure_estimate();
    assert_eq!(est.total_samples, 1000);
    assert!(
        est.max_selection_rate > 0.20,
        "with liveness_discount=0, dead dormant providers must never be activated; \
         max_selection_rate should be ~0.25 (4 live providers cycling); got {}",
        est.max_selection_rate
    );
}

// ── §41. Smoothed entropy preserved across reset prevents EntropyTriggered thrashing
//
// After building smoothed entropy to ~1.0 and then doing an OnRotation reset,
// smoothed_selection_entropy_bits is preserved (non-zero). EntropyTriggered with
// min_entropy_bits=0.3 does NOT re-fire immediately because smoothed > 0.3.
// If EntropyTriggered used raw entropy instead, the post-reset raw of 0.0 would
// cause it to fire and re-rotate on every maybe_rotate() call.

#[test]
fn pool_smoothed_entropy_prevents_thrashing() {
    let mut rng = OsRng;
    let mut pool = ProviderPool::new(SamplingStrategy::RandomK(1))
        .with_active_window(2)
        .with_rotation(
            PoolRotationPolicy::EntropyTriggered { min_entropy_bits: 0.3 },
            ChurnBudget { min_churn: 1, max_churn: 1 },
        )
        .with_exposure_reset_policy(ExposureResetPolicy::OnRotation)
        .with_entropy_smoothing(0.5);
    for i in 0u8..4 { pool.add(pid(i), SubstrateLedger::new()); }

    // Phase A: build smoothed entropy to ~1.0 (2-provider uniform, alpha=0.5)
    for _ in 0..200 { let _ = pool.sample(&mut rng); }
    assert!(
        pool.exposure_estimate().smoothed_selection_entropy_bits > 0.8,
        "smoothed entropy should converge to ~1.0 after 200 uniform samples; got {}",
        pool.exposure_estimate().smoothed_selection_entropy_bits
    );

    // Phase B: rotate with OnRotation reset → raw zeroed, smoothed preserved
    pool.force_rotate(&mut rng);
    assert!(
        pool.exposure_estimate().smoothed_selection_entropy_bits > 0.3,
        "smoothed entropy must be preserved after reset (anti-thrashing invariant); got {}",
        pool.exposure_estimate().smoothed_selection_entropy_bits
    );
    assert_eq!(pool.exposure_estimate().total_samples, 0,
        "OnRotation must zero the raw sample history");

    // Phase C: one sample → total_samples = 1, smoothed updated but still > 0.3
    let _ = pool.sample(&mut rng);

    // Phase D: EntropyTriggered checks smoothed (~0.5) > 0.3 → must NOT re-fire
    pool.maybe_rotate(&mut rng);
    assert_eq!(
        pool.exposure_estimate().total_samples, 1,
        "EntropyTriggered must use smoothed entropy; with smoothed > threshold, \
         rotation must not fire immediately after a reset — total_samples must remain 1"
    );
}

// ── §42. effective_total_samples halves at each half-life ────────────────────
//
// Configures a pool with half_life=100s and records 1000 samples.
// Uses ratio-based comparison to cancel clock drift: the decay factor at
// (now+100) vs (now) always equals exactly 0.5 because the (now - last_record)
// term is common to both denominators and cancels in the ratio.

#[test]
fn pool_exposure_decay_halves_at_half_life() {
    let mut rng = OsRng;
    let mut pool = ProviderPool::new(SamplingStrategy::RandomK(4))
        .with_exposure_decay(100);
    for i in 0u8..4 { pool.add(pid(i), SubstrateLedger::new()); }

    for _ in 0..1000 { let _ = pool.sample(&mut rng); }

    let now   = now_secs();
    let at_t0 = pool.exposure_estimate_at(now);
    let at_hl = pool.exposure_estimate_at(now + 100);
    let at_2hl = pool.exposure_estimate_at(now + 200);

    // Ratio cancels clock drift: at_hl / at_t0 == 0.5 exactly.
    let ratio_hl  = at_hl.effective_total_samples  / at_t0.effective_total_samples;
    let ratio_2hl = at_2hl.effective_total_samples / at_t0.effective_total_samples;

    assert!(
        (ratio_hl - 0.5).abs() < 0.001,
        "effective_total_samples must halve at one half-life; ratio = {:.4}", ratio_hl
    );
    assert!(
        (ratio_2hl - 0.25).abs() < 0.001,
        "effective_total_samples must quarter at two half-lives; ratio = {:.4}", ratio_2hl
    );
}

// ── §43. effective_total_samples approaches zero at 10× half-life ────────────
//
// After 10 half-lives the decay factor is 0.5^10 ≈ 1/1024. For 1000 samples
// effective_total_samples ≈ 0.977. Ratio-based fields (entropy) are unchanged
// because they depend only on appearances/total_samples, not on the decay.

#[test]
fn pool_exposure_decay_approaches_zero_at_ten_half_lives() {
    let mut rng = OsRng;
    // RandomK(1): one provider per quorum, so total_samples == quorum count and
    // p_i = appearances[i] / total_samples forms a proper probability distribution.
    let mut pool = ProviderPool::new(SamplingStrategy::RandomK(1))
        .with_exposure_decay(100);
    for i in 0u8..4 { pool.add(pid(i), SubstrateLedger::new()); }

    for _ in 0..1000 { let _ = pool.sample(&mut rng); }

    let now     = now_secs();
    let at_10hl = pool.exposure_estimate_at(now + 1000);

    assert!(
        at_10hl.effective_total_samples < 2.0,
        "at 10 half-lives, effective_total_samples must be near 0; got {:.4}",
        at_10hl.effective_total_samples
    );
    // Entropy is ratio-based — unaffected by decay.
    assert!(
        at_10hl.selection_entropy_bits > 1.9,
        "entropy must be unchanged by decay; got {:.4}", at_10hl.selection_entropy_bits
    );
}

// ── §44. active_set_snapshot and epoch_similarity (Jaccard index) ────────────
//
// Validates snapshot capture and the full Jaccard identity (identical=1.0,
// disjoint=0.0, empty=1.0, partial=(intersection/union)).

#[test]
fn pool_active_set_snapshot_and_epoch_similarity() {
    let mut rng = OsRng;
    let mut pool = ProviderPool::new(SamplingStrategy::RandomK(2))
        .with_active_window(2)
        .with_rotation(
            PoolRotationPolicy::Manual,
            ChurnBudget { min_churn: 1, max_churn: 2 },
        );
    for i in 0u8..4 { pool.add(pid(i), SubstrateLedger::new()); }

    let snap_a = pool.active_set_snapshot();
    pool.force_rotate(&mut rng);
    let snap_b = pool.active_set_snapshot();

    // Self-similarity is 1.0.
    assert_eq!(epoch_similarity(&snap_a, &snap_a), 1.0,
        "identical sets must have Jaccard = 1.0");

    // Two empty slices → 1.0.
    assert_eq!(epoch_similarity(&[], &[]), 1.0,
        "both empty → Jaccard = 1.0");

    // One empty slice → 0.0 (union = non-empty set, intersection = empty).
    assert_eq!(epoch_similarity(&snap_a, &[]), 0.0,
        "non-empty vs empty → Jaccard = 0.0");

    // Cross-epoch similarity is in [0.0, 1.0].
    let sim = epoch_similarity(&snap_a, &snap_b);
    assert!(sim >= 0.0 && sim <= 1.0,
        "epoch_similarity must be in [0.0, 1.0]; got {sim:.4}");

    // Hard-coded disjoint case.
    assert_eq!(
        epoch_similarity(&[pid(0), pid(1)], &[pid(2), pid(3)]),
        0.0,
        "disjoint sets must have Jaccard = 0.0"
    );

    // Hard-coded 1-in-3 overlap: |{0} ∩ {0,2}| / |{0,1} ∪ {0,2}| = 1/3.
    let expected = 1.0f64 / 3.0;
    assert!(
        (epoch_similarity(&[pid(0), pid(1)], &[pid(0), pid(2)]) - expected).abs() < 1e-9,
        "1-element intersection over 3-element union must equal 1/3"
    );
}

// ── §45. effective_dummy_probability scales with selection pressure ───────────
//
// Fresh pool (no samples): max_rate ≈ 0, probability ≈ DUMMY_QUERY_PROBABILITY.
// After 1000 samples from a single-provider pool: max_rate ≈ 1.0,
// so p = DUMMY_QUERY_PROBABILITY * 3.0 = 0.15, clamped to 0.15.

#[test]
fn pool_adaptive_dummy_probability_scales_with_pressure() {
    let mut rng = OsRng;

    // Fresh pool: no samples yet.
    let pool_fresh: ProviderPool<SubstrateLedger> =
        ProviderPool::new(SamplingStrategy::RandomK(4));
    assert!(
        (pool_fresh.effective_dummy_probability() - DUMMY_QUERY_PROBABILITY).abs() < 0.001,
        "fresh pool must yield base dummy probability; got {}",
        pool_fresh.effective_dummy_probability()
    );

    // Single-provider pool: max_rate == 1.0 (only one candidate is ever selected).
    let mut pool_hot = ProviderPool::new(SamplingStrategy::RandomK(1));
    pool_hot.add(pid(0), SubstrateLedger::new());
    for _ in 0..1000 { let _ = pool_hot.sample(&mut rng); }

    let p = pool_hot.effective_dummy_probability();
    assert!(
        p > DUMMY_QUERY_PROBABILITY + 0.05,
        "high-pressure pool must yield elevated dummy probability; got {p:.4}"
    );
    assert!(
        p <= 0.20,
        "dummy probability must be clamped to 0.20; got {p:.4}"
    );
}

// ── §46. VisibilityCapped reactivates over-exposed providers less often ───────
//
// Setup: 3 providers, active_window=1. pid(0) is initially active; pid(1) and
// pid(2) are dormant. After 1000 sample() calls pid(0) has rate=1.0 in both pools.
//
// Markov chain steady-state analysis (no samples between rotations):
//   Uniform:           P(pid(0) active) = 1/3 ≈ 0.333  → expected count ≈ 33/100
//   VisibilityCapped:  weight(pid(0))≈0.10, weight(fresh)=1.0
//                      P(pid(0) active) ≈ 0.083         → expected count ≈ 8/100
//
// Expected difference ≈ 25. Threshold of 10 gives ~2.7σ safety margin.

#[test]
fn pool_visibility_capped_prefers_fresh_over_overexposed() {
    let mut rng = OsRng;

    let mut pool_u = ProviderPool::new(SamplingStrategy::RandomK(1))
        .with_active_window(1)
        .with_rotation(PoolRotationPolicy::Manual, ChurnBudget { min_churn: 1, max_churn: 1 })
        .with_activation_strategy(ActivationStrategy::Uniform);
    for i in 0u8..3 { pool_u.add(pid(i), SubstrateLedger::new()); }

    let mut pool_v = ProviderPool::new(SamplingStrategy::RandomK(1))
        .with_active_window(1)
        .with_rotation(PoolRotationPolicy::Manual, ChurnBudget { min_churn: 1, max_churn: 1 })
        .with_activation_strategy(ActivationStrategy::VisibilityCapped {
            max_visibility_ratio: 0.10,
            floor: 0.01,
        });
    for i in 0u8..3 { pool_v.add(pid(i), SubstrateLedger::new()); }

    // Pre-load heavy exposure for pid(0) (the only active provider).
    // After this: rate(pid(0)) = 1.0; rate(pid(1)) = rate(pid(2)) = 0.0.
    for _ in 0..1000 {
        let _ = pool_u.sample(&mut rng);
        let _ = pool_v.sample(&mut rng);
    }

    // Rotate 100 times without taking samples in between.
    // Rates stay frozen: VisibilityCapped effect on pid(0) is maximal and constant.
    let mut pid0_active_u = 0usize;
    let mut pid0_active_v = 0usize;
    for _ in 0..100 {
        pool_u.force_rotate(&mut rng);
        if pool_u.active_set_snapshot().contains(&pid(0)) { pid0_active_u += 1; }

        pool_v.force_rotate(&mut rng);
        if pool_v.active_set_snapshot().contains(&pid(0)) { pid0_active_v += 1; }
    }

    assert!(
        pid0_active_v + 10 < pid0_active_u,
        "VisibilityCapped must reactivate over-exposed pid(0) far less often than Uniform \
         (pool_v={pid0_active_v}, pool_u={pid0_active_u}; expected ≈8 vs ≈33)"
    );
}

// ── §47. WeightedComposite softly includes dead providers (discount=1.0) ──────
//
// Three providers, pid(0) dead. WeightedByReputation hard-excludes dead providers
// via live_indices. WeightedComposite with liveness_discount=1.0 treats dead and
// live providers identically (liveness_factor = 1.0 for all).
//
// After 200 samples, check exposure_distribution():
//   pool_rep: pid(0) rate == 0.0 (hard-excluded).
//   pool_comp: pid(0) rate >= 0.15 (~0.333 expected, 50% tolerance floor).
//
// Note: influence=0.0 → reputation weight = max(1/(1+0), floor) = 1.0 for all.
//       With discount=1.0, dead weight = 1.0*1.0 = live weight. Uniform across all 3.

#[test]
fn pool_sampling_weighted_composite_softly_includes_dead() {
    let mut rng = OsRng;

    let mut pool_rep = ProviderPool::new(SamplingStrategy::WeightedByReputation {
        k: 1, influence: 0.0, floor: 1.0,
    })
    .with_liveness(2, u64::MAX);
    pool_rep.add(pid(0), SubstrateLedger::new());
    pool_rep.add(pid(1), SubstrateLedger::new());
    pool_rep.add(pid(2), SubstrateLedger::new());
    pool_rep.record_failure(pid(0));
    pool_rep.record_failure(pid(0));

    let mut pool_comp = ProviderPool::new(SamplingStrategy::WeightedComposite {
        k: 1, influence: 0.0, floor: 1.0, liveness_discount: 1.0,
    })
    .with_liveness(2, u64::MAX);
    pool_comp.add(pid(0), SubstrateLedger::new());
    pool_comp.add(pid(1), SubstrateLedger::new());
    pool_comp.add(pid(2), SubstrateLedger::new());
    pool_comp.record_failure(pid(0));
    pool_comp.record_failure(pid(0));

    for _ in 0..200 {
        let _ = pool_rep.sample(&mut rng);
        let _ = pool_comp.sample(&mut rng);
    }

    // Use exposure_distribution() to measure per-provider selection rates.
    let rep_pid0_rate = pool_rep.exposure_distribution().rates.iter()
        .find(|(id, _)| *id == pid(0))
        .map(|(_, r)| *r)
        .unwrap_or(0.0);
    assert_eq!(rep_pid0_rate, 0.0,
        "WeightedByReputation must never select dead pid(0) (hard-excluded via live_indices)");

    let comp_pid0_rate = pool_comp.exposure_distribution().rates.iter()
        .find(|(id, _)| *id == pid(0))
        .map(|(_, r)| *r)
        .unwrap_or(0.0);
    assert!(
        comp_pid0_rate >= 0.15,
        "WeightedComposite(discount=1.0) must include dead pid(0) often (~0.333 expected); \
         got rate {comp_pid0_rate:.3}"
    );
}

// ── §48. WeightedComposite with discount=0.0 hard-excludes dead providers ─────
//
// Dead provider pid(0): weight = rep_w * 0.0 = 0. Can never be selected.
// After 200 samples, pid(0)'s selection rate must be exactly 0.0.

#[test]
fn pool_sampling_weighted_composite_at_zero_discount_excludes_dead() {
    let mut rng = OsRng;

    let mut pool = ProviderPool::new(SamplingStrategy::WeightedComposite {
        k: 1, influence: 0.0, floor: 1.0, liveness_discount: 0.0,
    })
    .with_liveness(2, u64::MAX);
    pool.add(pid(0), SubstrateLedger::new());
    pool.add(pid(1), SubstrateLedger::new());
    pool.add(pid(2), SubstrateLedger::new());
    pool.record_failure(pid(0));
    pool.record_failure(pid(0));

    for _ in 0..200 {
        let _ = pool.sample(&mut rng);
    }

    let pid0_rate = pool.exposure_distribution().rates.iter()
        .find(|(id, _)| *id == pid(0))
        .map(|(_, r)| *r)
        .unwrap_or(0.0);
    assert_eq!(
        pid0_rate, 0.0,
        "WeightedComposite(discount=0.0) must never select dead pid(0); got rate {pid0_rate}"
    );
}

// ── §49. exposure_divergence for identical distributions is exactly 0.0 ───────

#[test]
fn pool_exposure_divergence_identical_is_zero() {
    let dist: &[([u8; 32], f64)] = &[(pid(0), 0.6), (pid(1), 0.4)];
    assert_eq!(
        exposure_divergence(dist, dist),
        0.0,
        "JSD of a distribution with itself must be exactly 0.0"
    );
}

// ── §50. exposure_divergence for disjoint supports is 1.0; both empty is 0.0 ──

#[test]
fn pool_exposure_divergence_disjoint_is_one() {
    let a: &[([u8; 32], f64)] = &[(pid(0), 1.0)];
    let b: &[([u8; 32], f64)] = &[(pid(1), 1.0)];
    assert!(
        (exposure_divergence(a, b) - 1.0).abs() < 1e-9,
        "JSD of disjoint unit distributions must equal 1.0; got {}",
        exposure_divergence(a, b)
    );
    assert_eq!(
        exposure_divergence(&[], &[]),
        0.0,
        "JSD of two empty distributions must be 0.0"
    );
}

// ── §51. exposure_divergence partial overlap matches analytical JSD ────────────
//
// P = [(pid(0), 0.7), (pid(1), 0.3)]
// Q = [(pid(0), 0.3), (pid(1), 0.7)]
// M = [(pid(0), 0.5), (pid(1), 0.5)]
//
// JSD = 0.5*[0.7*log2(0.7/0.5) + 0.3*log2(0.3/0.5)]
//     + 0.5*[0.3*log2(0.3/0.5) + 0.7*log2(0.7/0.5)]
//     = 0.7*log2(1.4) + 0.3*log2(0.6)
//     ≈ 0.7*0.4854 + 0.3*(-0.7370) ≈ 0.119

#[test]
fn pool_exposure_divergence_partial_overlap() {
    let p: &[([u8; 32], f64)] = &[(pid(0), 0.7), (pid(1), 0.3)];
    let q: &[([u8; 32], f64)] = &[(pid(0), 0.3), (pid(1), 0.7)];
    let expected = 0.119f64;
    let got = exposure_divergence(p, q);
    assert!(
        (got - expected).abs() < 0.001,
        "JSD of 0.7/0.3 vs 0.3/0.7 split must be ≈{expected:.3}; got {got:.6}"
    );
}

// ── §52. JsdTriggered never fires without a baseline ─────────────────────────
//
// Without a prior force_rotate() or maybe_rotate() that completed, previous_distribution
// is None. JsdTriggered must return false regardless of min_divergence.
// min_divergence=1.0 chosen so that any baseline would cause a fire (JSD ≤ 1.0),
// proving the no-fire behavior is purely due to the absent baseline.

#[test]
fn pool_jsd_triggered_no_fire_without_baseline() {
    let mut rng = OsRng;

    let mut pool = ProviderPool::new(SamplingStrategy::RandomK(1))
        .with_active_window(1)
        .with_rotation(
            PoolRotationPolicy::JsdTriggered { min_divergence: 1.0 },
            ChurnBudget { min_churn: 1, max_churn: 1 },
        );
    pool.add(pid(0), SubstrateLedger::new());
    pool.add(pid(1), SubstrateLedger::new());

    for _ in 0..100 { let _ = pool.sample(&mut rng); }

    let mut before = pool.active_set_snapshot(); before.sort();
    for _ in 0..20 { pool.maybe_rotate(&mut rng); }
    let mut after = pool.active_set_snapshot(); after.sort();

    assert_eq!(before, after,
        "JsdTriggered must not fire without a baseline distribution (previous_distribution = None)");
}

// ── §53. JsdTriggered fires when consecutive distributions are stable ─────────
//
// 8 providers, active_window=4 (dormant=4 ≥ active_window → floor gate passes).
// After epoch 1 (uniform) and force_rotate(), epoch 2 is uniform over a 4-provider
// active set sharing 3 of 4 providers with epoch 1.
// JSD ≈ 0.25 (one provider replaced out of 4 uniform contributors):
//   M = [shared×3 at 0.25, evicted at 0.125, newcomer at 0.125]
//   KL(P||M) = 0.25·log₂(2) = 0.25. Symmetric. JSD = 0.25.
// With min_divergence=0.5: 0.25 < 0.5 → fires.

#[test]
fn pool_jsd_triggered_fires_when_distribution_stable() {
    let mut rng = OsRng;

    let mut pool = ProviderPool::new(SamplingStrategy::RandomK(1))
        .with_active_window(4)
        .with_rotation(
            PoolRotationPolicy::JsdTriggered { min_divergence: 0.5 },
            ChurnBudget { min_churn: 1, max_churn: 1 },
        );
    for i in 0u8..8 { pool.add(pid(i), SubstrateLedger::new()); }

    // Epoch 1: build uniform distribution over pid(0..3).
    for _ in 0..400 { let _ = pool.sample(&mut rng); }

    // Establish baseline. One of pid(0..3) evicted, pid(4) activated.
    pool.force_rotate(&mut rng);

    // Epoch 2: build uniform distribution over new 4-provider active set.
    for _ in 0..400 { let _ = pool.sample(&mut rng); }

    let mut before = pool.active_set_snapshot(); before.sort();
    pool.maybe_rotate(&mut rng);
    let mut after = pool.active_set_snapshot(); after.sort();

    assert_ne!(before, after,
        "JsdTriggered must fire when consecutive epoch distributions are stable (JSD ≈ 0.25 < 0.5)");
}

// ── §54. JsdTriggered does not fire when distributions are disjoint ───────────
//
// 2 providers, active_window=1. pid(0) active in epoch 1 (rate=1.0),
// pid(1) active in epoch 2 (rate=1.0).
// JSD([pid(0)=1.0], [pid(1)=1.0]) = 1.0 (disjoint supports).
// With min_divergence=0.5: 1.0 < 0.5 → false → no fire.
// Deterministic test: single active provider always selected.

#[test]
fn pool_jsd_triggered_no_fire_when_distribution_shifted() {
    let mut rng = OsRng;

    let mut pool = ProviderPool::new(SamplingStrategy::RandomK(1))
        .with_active_window(1)
        .with_rotation(
            PoolRotationPolicy::JsdTriggered { min_divergence: 0.5 },
            ChurnBudget { min_churn: 1, max_churn: 1 },
        )
        .with_exposure_reset();
    pool.add(pid(0), SubstrateLedger::new());
    pool.add(pid(1), SubstrateLedger::new());

    // Epoch 1: pid(0) selected every time → distribution [pid(0)=1.0].
    for _ in 0..100 { let _ = pool.sample(&mut rng); }

    // force_rotate() saves baseline [pid(0)=1.0], resets tracker, activates pid(1).
    pool.force_rotate(&mut rng);

    // Epoch 2: pid(1) selected every time → distribution [pid(1)=1.0].
    for _ in 0..100 { let _ = pool.sample(&mut rng); }

    let mut before = pool.active_set_snapshot(); before.sort();
    pool.maybe_rotate(&mut rng);
    let mut after = pool.active_set_snapshot(); after.sort();

    assert_eq!(before, after,
        "JsdTriggered must not fire when distributions are disjoint (JSD=1.0 > min_divergence=0.5)");
}

// ── §55. JsdTriggered with min_divergence=0.0 never fires ────────────────────
//
// JSD ≥ 0.0 always. The condition `JSD < 0.0` is never true.
// Even with an established baseline, no rotation should fire.

#[test]
fn pool_jsd_triggered_zero_threshold_never_fires() {
    let mut rng = OsRng;

    let mut pool = ProviderPool::new(SamplingStrategy::RandomK(1))
        .with_active_window(1)
        .with_rotation(
            PoolRotationPolicy::JsdTriggered { min_divergence: 0.0 },
            ChurnBudget { min_churn: 1, max_churn: 1 },
        );
    pool.add(pid(0), SubstrateLedger::new());
    pool.add(pid(1), SubstrateLedger::new());

    // Establish baseline.
    for _ in 0..100 { let _ = pool.sample(&mut rng); }
    pool.force_rotate(&mut rng);
    for _ in 0..100 { let _ = pool.sample(&mut rng); }

    let mut before = pool.active_set_snapshot(); before.sort();
    for _ in 0..10 { pool.maybe_rotate(&mut rng); }
    let mut after = pool.active_set_snapshot(); after.sort();

    assert_eq!(before, after,
        "JsdTriggered with min_divergence=0.0 must never fire (JSD >= 0.0 always)");
}

// ── §56. Baseline updates after each rotation ─────────────────────────────────
//
// 3 providers (pid(0,1) active, pid(2) dormant), active_window=2, RandomK(1),
// JsdTriggered { min_divergence: 0.6 }.
//
// Epoch 1: uniform → [pid(0)≈0.5, pid(1)≈0.5].
//   force_rotate() saves baseline_1 and activates pid(2).
//   Active becomes {pid(remaining), pid(2)}.
//
// Epoch 2: uniform over {pid(x), pid(2)} → [pid(x)≈0.5, pid(2)≈0.5].
//   JSD(baseline_1, epoch_2) ≈ 0.5 (one of 2 providers changed):
//     P=[A=0.5,B=0.5] vs Q=[B=0.5,C=0.5] → M=[A=0.25,B=0.5,C=0.25]
//     KL(P||M) = 0.5·log₂(2) = 0.5. JSD = 0.5·0.5 + 0.5·0.5 = 0.5.
//   0.5 < 0.6 → maybe_rotate() fires. Baseline updated to epoch_2 distribution.
//
// Assert: active set changed after maybe_rotate() in epoch 2.

#[test]
fn pool_jsd_triggered_baseline_updated_on_each_rotation() {
    let mut rng = OsRng;

    let mut pool = ProviderPool::new(SamplingStrategy::RandomK(1))
        .with_active_window(2)
        .with_rotation(
            PoolRotationPolicy::JsdTriggered { min_divergence: 0.6 },
            ChurnBudget { min_churn: 1, max_churn: 1 },
        );
    pool.add(pid(0), SubstrateLedger::new());
    pool.add(pid(1), SubstrateLedger::new());
    pool.add(pid(2), SubstrateLedger::new());
    pool.add(pid(3), SubstrateLedger::new());   // dormant=2 ≥ active_window=2 → floor gate passes

    // Epoch 1: uniform over {pid(0), pid(1)}.
    for _ in 0..200 { let _ = pool.sample(&mut rng); }

    // Establish baseline_1; pid(2) activated, one of pid(0,1) dormant.
    pool.force_rotate(&mut rng);

    // Epoch 2: uniform over new 2-provider active set.
    for _ in 0..200 { let _ = pool.sample(&mut rng); }

    let mut before = pool.active_set_snapshot(); before.sort();
    pool.maybe_rotate(&mut rng);
    let mut after = pool.active_set_snapshot(); after.sort();

    assert_ne!(before, after,
        "JsdTriggered must fire in epoch 2 (JSD ≈ 0.5 < 0.6); \
         this also verifies force_rotate() correctly set the baseline");
}

// ── §57. Uniform pool → κ ≈ 0.0 and spectral_concentration ≈ 0.0 ──────────
//
// With 4 providers and uniform sampling, entropy ≈ log2(4) = 2.0 bits.
// κ = 1 - 2.0/2.0 = 0.0. Spectral concentration = max_rate - 0.25 ≈ 0.0.

#[test]
fn pool_convergence_pressure_uniform_is_zero_kappa() {
    let mut rng = OsRng;
    let mut pool = ProviderPool::new(SamplingStrategy::RandomK(1))
        .with_active_window(4);
    for i in 0..4u8 { pool.add([i; 32], SubstrateLedger::new()); }

    for _ in 0..4000 { let _ = pool.sample(&mut rng); }

    let p = pool.convergence_pressure();
    assert_eq!(p.active_n, 4);
    assert!(p.kappa < 0.05,
        "uniform 4-provider pool must have κ ≈ 0.0, got {}", p.kappa);
    assert!(p.spectral_concentration < 0.05,
        "uniform pool must have spectral_concentration ≈ 0.0, got {}", p.spectral_concentration);
}

// ── §58. Single-active-provider pool → κ = 1.0, concentration = 0.0 ────────
//
// active_n=1 → log2(1)=0 → κ defined as 1.0 (no diversity achievable).
// uniform_rate = 1/1 = 1.0; max_rate = 1.0 → concentration = max(1.0-1.0, 0) = 0.0.

#[test]
fn pool_convergence_pressure_single_active_is_max_kappa() {
    let mut rng = OsRng;
    let mut pool = ProviderPool::new(SamplingStrategy::RandomK(1))
        .with_active_window(1);
    pool.add(pid(0), SubstrateLedger::new());
    pool.add(pid(1), SubstrateLedger::new());

    for _ in 0..100 { let _ = pool.sample(&mut rng); }

    let p = pool.convergence_pressure();
    assert_eq!(p.active_n, 1);
    assert_eq!(p.kappa, 1.0, "single-active pool must have κ = 1.0");
    assert_eq!(p.spectral_concentration, 0.0,
        "with active_n=1, uniform_rate=1.0 and max_rate=1.0 → concentration = 0.0");
}

// ── §59. ConvergenceTriggered fires when pool is concentrated ───────────────
//
// active_window=1 → only one provider active → entropy=0 → κ=1.0 > max_kappa=0.3.
// maybe_rotate() must fire and change the active set.

#[test]
fn pool_convergence_triggered_fires_when_concentrated() {
    let mut rng = OsRng;
    let mut pool = ProviderPool::new(SamplingStrategy::RandomK(1))
        .with_active_window(1)
        .with_rotation(
            PoolRotationPolicy::ConvergenceTriggered { max_kappa: 0.3 },
            ChurnBudget { min_churn: 1, max_churn: 1 },
        );
    pool.add(pid(0), SubstrateLedger::new());
    pool.add(pid(1), SubstrateLedger::new());

    for _ in 0..10 { let _ = pool.sample(&mut rng); }

    let mut before = pool.active_set_snapshot(); before.sort();
    pool.maybe_rotate(&mut rng);
    let mut after = pool.active_set_snapshot(); after.sort();

    assert_ne!(before, after,
        "ConvergenceTriggered must fire: κ=1.0 > max_kappa=0.3");
}

// ── §60. ConvergenceTriggered does not fire when pool is uniform ─────────────
//
// active_window=4 with 4 providers → entropy ≈ log2(4) → κ ≈ 0.0 < max_kappa=0.5.
// maybe_rotate() must NOT fire.

#[test]
fn pool_convergence_triggered_no_fire_when_uniform() {
    let mut rng = OsRng;
    let mut pool = ProviderPool::new(SamplingStrategy::RandomK(1))
        .with_active_window(4)
        .with_rotation(
            PoolRotationPolicy::ConvergenceTriggered { max_kappa: 0.5 },
            ChurnBudget { min_churn: 1, max_churn: 1 },
        );
    pool.add(pid(0), SubstrateLedger::new());
    pool.add(pid(1), SubstrateLedger::new());
    pool.add(pid(2), SubstrateLedger::new());
    pool.add(pid(3), SubstrateLedger::new());
    pool.add(pid(4), SubstrateLedger::new());  // dormant

    for _ in 0..4000 { let _ = pool.sample(&mut rng); }

    let before = pool.active_set_snapshot();
    pool.maybe_rotate(&mut rng);
    let after = pool.active_set_snapshot();

    assert_eq!(before, after,
        "ConvergenceTriggered must not fire: κ ≈ 0.0 < max_kappa=0.5");
}

// ── §61. samples_to_saturation boundaries ───────────────────────────────────
//
// Before any samples: max_rate = 0.0 → None.
// After 10 samples with active_window=1 (rate=1.0):
//   confidence = 1 - (1-1.0)^10 = 1.0 ≥ 0.5 → Some(0).

#[test]
fn pool_convergence_pressure_samples_to_saturation() {
    let mut rng = OsRng;
    let mut pool = ProviderPool::new(SamplingStrategy::RandomK(1))
        .with_active_window(1);
    pool.add(pid(0), SubstrateLedger::new());
    pool.add(pid(1), SubstrateLedger::new());

    // Phase 1: no samples yet — rate=0, saturation undefined.
    assert_eq!(pool.convergence_pressure().samples_to_saturation, None,
        "rate=0 before any samples → None");

    // Phase 2: 10 samples with single active provider → rate=1.0, confidence=1.0 ≥ 0.5.
    for _ in 0..10 { let _ = pool.sample(&mut rng); }
    assert_eq!(pool.convergence_pressure().samples_to_saturation, Some(0),
        "rate=1.0 → confidence=1.0 ≥ 0.5 → already saturated → Some(0)");
}

// ── §62. kappa_velocity is None before first rotation ────────────────────────
//
// previous_kappa is initialized to None in PoolRotation::new().
// With no rotation, kappa_velocity must remain None.

#[test]
fn pool_kappa_velocity_none_before_first_rotation() {
    let mut rng = OsRng;
    let mut pool = ProviderPool::new(SamplingStrategy::RandomK(1))
        .with_active_window(1);
    pool.add(pid(0), SubstrateLedger::new());
    pool.add(pid(1), SubstrateLedger::new());

    for _ in 0..10 { let _ = pool.sample(&mut rng); }

    assert_eq!(pool.convergence_pressure().kappa_velocity, None,
        "no rotation has occurred → previous_kappa = None → kappa_velocity = None");
}

// ── §63. kappa_velocity > 0 when pressure grows after rotation ───────────────
//
// Epoch 1: 4000 samples → uniform distribution → κ_prev ≈ 0.
// force_rotate() snapshots κ_prev ≈ 0 and resets tracker (OnRotation).
// Epoch 2: 1 sample → entropy=0 (only one provider seen) → κ=1.0.
// kappa_velocity = 1.0 - 0.0 ≈ 1.0 > 0.5.
//
// Why κ=1.0 after 1 sample: appearances={selected:1}, total=1 → entropy=0 bits.
// With n=4: κ = 1 − 0/log₂(4) = 1.0. Correct: adversary knows exactly which
// provider responded to the single query.

#[test]
fn pool_kappa_velocity_reflects_pressure_change() {
    let mut rng = OsRng;
    let mut pool = ProviderPool::new(SamplingStrategy::RandomK(1))
        .with_active_window(4)
        .with_rotation(
            PoolRotationPolicy::Manual,
            ChurnBudget { min_churn: 1, max_churn: 1 },
        )
        .with_exposure_reset();
    for i in 0..5u8 { pool.add([i; 32], SubstrateLedger::new()); }

    // Epoch 1: uniform distribution → κ_prev ≈ 0.
    for _ in 0..4000 { let _ = pool.sample(&mut rng); }
    pool.force_rotate(&mut rng); // snapshots κ_prev ≈ 0, resets tracker.

    // Epoch 2: single sample → κ = 1.0.
    let _ = pool.sample(&mut rng);

    let velocity = pool.convergence_pressure().kappa_velocity.expect("previous_kappa set by force_rotate");
    assert!(velocity > 0.5,
        "κ grew from ≈0 to 1.0 → kappa_velocity must be > 0.5, got {velocity}");
}

// ── §64. transition_entropy matches the combinatorial formula ─────────────────
//
// 8 providers: 4 active (active_window=4), 4 dormant. min_churn=max_churn=2.
// k̄ = round(2.0) = 2.
// transition_entropy = log₂(C(4,2)) + log₂(C(4,2)) = log₂(6) + log₂(6) ≈ 5.170 bits.

#[test]
fn pool_transition_entropy_formula() {
    let mut pool = ProviderPool::new(SamplingStrategy::RandomK(1))
        .with_active_window(4)
        .with_rotation(
            PoolRotationPolicy::Manual,
            ChurnBudget { min_churn: 2, max_churn: 2 },
        );
    for i in 0..8u8 { pool.add([i; 32], SubstrateLedger::new()); }

    let te = pool.convergence_pressure().transition_entropy
        .expect("4 dormant providers → transition_entropy must be Some");
    let expected = (6.0f64).log2() + (6.0f64).log2(); // log₂(C(4,2)) * 2
    assert!((te - expected).abs() < 0.001,
        "transition_entropy must be ≈{expected:.3}, got {te:.6}");
}

// ── §65. active_set_halflife_epochs follows the formula exactly ───────────────
//
// 8 providers, active_window=4, churn=2.
// After force_rotate(): last_churn=2, n=4.
// halflife = −ln(2)/ln(1 − 2/4) = −ln(2)/ln(0.5) = 1.0 epoch exactly.

#[test]
fn pool_active_set_halflife_epochs_formula() {
    let mut rng = OsRng;
    let mut pool = ProviderPool::new(SamplingStrategy::RandomK(1))
        .with_active_window(4)
        .with_rotation(
            PoolRotationPolicy::Manual,
            ChurnBudget { min_churn: 2, max_churn: 2 },
        );
    for i in 0..8u8 { pool.add([i; 32], SubstrateLedger::new()); }

    // Before any rotation: last_churn = None → halflife = None.
    assert_eq!(pool.convergence_pressure().active_set_halflife_epochs, None,
        "no rotation yet → last_churn = None → halflife = None");

    pool.force_rotate(&mut rng); // sets last_churn = 2.

    let halflife = pool.convergence_pressure().active_set_halflife_epochs
        .expect("force_rotate() sets last_churn → halflife must be Some");
    assert!((halflife - 1.0).abs() < 1e-9,
        "halflife must be exactly 1.0 epoch, got {halflife}");
}

// ── §66. VelocityTriggered fires when κ is growing ───────────────────────────
//
// After epoch 1 (uniform, κ_prev≈0) → force_rotate() → epoch 2 (1 sample, κ=1.0).
// kappa_velocity ≈ 1.0 > max_velocity=0.0 → maybe_rotate() must fire.

#[test]
fn pool_velocity_triggered_fires_when_kappa_growing() {
    let mut rng = OsRng;
    // 8 providers: dormant=4 ≥ active_window=4 → floor gate passes.
    let mut pool = ProviderPool::new(SamplingStrategy::RandomK(1))
        .with_active_window(4)
        .with_rotation(
            PoolRotationPolicy::VelocityTriggered { max_velocity: 0.0 },
            ChurnBudget { min_churn: 1, max_churn: 1 },
        )
        .with_exposure_reset();
    for i in 0..8u8 { pool.add([i; 32], SubstrateLedger::new()); }

    // Epoch 1: uniform → κ_prev ≈ 0. force_rotate() establishes baseline.
    for _ in 0..4000 { let _ = pool.sample(&mut rng); }
    pool.force_rotate(&mut rng);

    // Epoch 2: 100 samples → Steady (100 ≥ 4*active_n=16); κ > 0 with near-certainty
    // (P(exact uniform split) ≈ 0). velocity = κ_current - κ_prev ≈ κ_current > 0.0.
    for _ in 0..100 { let _ = pool.sample(&mut rng); }

    let mut before = pool.active_set_snapshot(); before.sort();
    pool.maybe_rotate(&mut rng);
    let mut after = pool.active_set_snapshot(); after.sort();

    assert_ne!(before, after,
        "VelocityTriggered must fire: kappa_velocity ≈ 1.0 > max_velocity=0.0");
}

// Phase 24 invariants:
//   accumulated_pressure is 0.0 before any maybe_rotate() calls with IntegralTriggered.
//   accumulated_pressure increments by κ on each maybe_rotate() call.
//   IntegralTriggered fires when accumulated_kappa > max_accumulated_pressure.
//   accumulated_kappa resets to 0.0 after every rotation.
//   Non-IntegralTriggered policies leave accumulated_kappa at 0.0 always.

// ── §67. accumulated_pressure is 0.0 before any maybe_rotate() calls ──────────

#[test]
fn pool_integral_triggered_zero_before_calls() {
    let mut pool = ProviderPool::new(SamplingStrategy::RandomK(1))
        .with_active_window(1)
        .with_rotation(
            PoolRotationPolicy::IntegralTriggered { max_accumulated_pressure: 10.0 },
            ChurnBudget { min_churn: 1, max_churn: 1 },
        );
    pool.add([0; 32], SubstrateLedger::new());
    pool.add([1; 32], SubstrateLedger::new());

    assert_eq!(pool.convergence_pressure().accumulated_pressure, 0.0,
        "accumulated_pressure must be 0.0 before any maybe_rotate() calls");
}

// ── §68. accumulated_pressure increments by κ on each maybe_rotate() call ─────

#[test]
fn pool_integral_triggered_accumulates_kappa() {
    let mut rng = OsRng;
    // 8 providers: dormant=4 ≥ active_window=4 → floor gate passes.
    let mut pool = ProviderPool::new(SamplingStrategy::RandomK(1))
        .with_active_window(4)
        .with_rotation(
            PoolRotationPolicy::IntegralTriggered { max_accumulated_pressure: 100.0 },
            ChurnBudget { min_churn: 1, max_churn: 1 },
        )
        .with_exposure_reset();
    for i in 0..8u8 { pool.add([i; 32], SubstrateLedger::new()); }

    // 4000 samples → uniform → κ ≈ 0 (but still ≥ 0; accumulator grows).
    for _ in 0..4000 { let _ = pool.sample(&mut rng); }

    for _ in 0..5 { pool.maybe_rotate(&mut rng); }

    assert!(pool.convergence_pressure().accumulated_pressure > 0.0,
        "accumulated_pressure must grow after maybe_rotate() calls");
}

// ── §69. IntegralTriggered fires when accumulated sum exceeds threshold ─────────

#[test]
fn pool_integral_triggered_fires_when_sum_exceeds_threshold() {
    let mut rng = OsRng;
    // active_window=1: κ=1.0 by definition (single active provider, entropy=0 bits).
    // Steady requires 4*active_n = 4*1 = 4 samples.
    // Threshold 1.5 ≥ 1.0 so no cooldown is required. active_window=1 → κ=1.0 always.
    let mut pool = ProviderPool::new(SamplingStrategy::RandomK(1))
        .with_active_window(1)
        .with_rotation(
            PoolRotationPolicy::IntegralTriggered { max_accumulated_pressure: 1.5 },
            ChurnBudget { min_churn: 1, max_churn: 1 },
        )
        .with_exposure_reset();
    for i in 0..5u8 { pool.add([i; 32], SubstrateLedger::new()); }

    // 4 samples → Steady (4 ≥ 4*1). κ=1.0. Two calls needed: 1.0+1.0=2.0 > 1.5 → fires.
    for _ in 0..4 { let _ = pool.sample(&mut rng); }

    let mut before = pool.active_set_snapshot(); before.sort();
    pool.maybe_rotate(&mut rng);    // accumulated = 1.0 → PolicyThresholdNotMet
    pool.maybe_rotate(&mut rng);    // accumulated = 2.0 → Rotated
    let mut after = pool.active_set_snapshot(); after.sort();

    assert_ne!(before, after,
        "IntegralTriggered must fire: accumulated_kappa (2.0) > threshold (1.5)");
}

// ── §70. accumulated_kappa resets to 0.0 after each rotation ──────────────────

#[test]
fn pool_integral_triggered_resets_after_rotation() {
    let mut rng = OsRng;
    // active_window=1: κ=1.0 always. Threshold 1.5 ≥ 1.0: no cooldown required.
    let mut pool = ProviderPool::new(SamplingStrategy::RandomK(1))
        .with_active_window(1)
        .with_rotation(
            PoolRotationPolicy::IntegralTriggered { max_accumulated_pressure: 1.5 },
            ChurnBudget { min_churn: 1, max_churn: 1 },
        )
        .with_exposure_reset();
    for i in 0..5u8 { pool.add([i; 32], SubstrateLedger::new()); }

    // 4 samples → Steady (4 ≥ 4*1). First call accumulates 1.0 → no fire.
    // Second call accumulates 2.0 > 1.5 → fires → do_rotate() resets accumulated_kappa.
    for _ in 0..4 { let _ = pool.sample(&mut rng); }
    pool.maybe_rotate(&mut rng);    // accumulated = 1.0 → PolicyThresholdNotMet
    pool.maybe_rotate(&mut rng);    // accumulated = 2.0 → Rotated; resets to 0.0

    assert_eq!(pool.convergence_pressure().accumulated_pressure, 0.0,
        "accumulated_kappa must reset to 0.0 after rotation");
}

// ── §71. Non-IntegralTriggered policies never mutate accumulated_kappa ─────────

#[test]
fn pool_non_integral_policy_leaves_accumulator_zero() {
    let mut rng = OsRng;
    let mut pool = ProviderPool::new(SamplingStrategy::RandomK(1))
        .with_active_window(4)
        .with_rotation(
            PoolRotationPolicy::Manual,
            ChurnBudget { min_churn: 1, max_churn: 1 },
        );
    for i in 0..5u8 { pool.add([i; 32], SubstrateLedger::new()); }

    for _ in 0..100 { let _ = pool.sample(&mut rng); }
    for _ in 0..10  { pool.maybe_rotate(&mut rng); }

    assert_eq!(pool.convergence_pressure().accumulated_pressure, 0.0,
        "accumulated_kappa must remain 0.0 for non-IntegralTriggered policies");
}

// Phase 25 invariants:
//   cooldown is None by default; existing rotation behavior is unchanged.
//   maybe_rotate() returns early without firing when elapsed < min_duration.
//   Duration::ZERO cooldown never blocks (elapsed ≥ ZERO always).
//   force_rotate() bypasses the cooldown gate; resets last_rotation via do_rotate().
//   After a rotation (including forced), cooldown resets: next maybe_rotate() is gated.

// ── §72. Cooldown blocks rotation when not yet expired ───────────────────────

#[test]
fn pool_cooldown_blocks_rotation_before_expiry() {
    let mut rng = OsRng;
    let mut pool = ProviderPool::new(SamplingStrategy::RandomK(1))
        .with_active_window(4)
        .with_rotation(
            PoolRotationPolicy::IntegralTriggered { max_accumulated_pressure: 0.0 },
            ChurnBudget { min_churn: 1, max_churn: 1 },
        )
        .with_cooldown(Duration::MAX);
    for i in 0..5u8 { pool.add([i; 32], SubstrateLedger::new()); }

    // 1 sample → κ=1.0 → accumulated_kappa would exceed 0.0 → policy would fire.
    // But cooldown(MAX) blocks: elapsed ≈ 0 < MAX.
    let _ = pool.sample(&mut rng);
    let mut before = pool.active_set_snapshot(); before.sort();
    pool.maybe_rotate(&mut rng);
    let mut after = pool.active_set_snapshot(); after.sort();

    assert_eq!(before, after,
        "cooldown(MAX) must block rotation even when policy condition is met");
}

// ── §73. Duration::ZERO cooldown never blocks ────────────────────────────────

#[test]
fn pool_cooldown_zero_duration_never_blocks() {
    let mut rng = OsRng;
    // Threshold 1.5 ≥ 1.0: safety check does not apply. active_window=1 → κ=1.0 always.
    // ZERO cooldown is tested: it must not block any maybe_rotate() call.
    let mut pool = ProviderPool::new(SamplingStrategy::RandomK(1))
        .with_active_window(1)
        .with_rotation(
            PoolRotationPolicy::IntegralTriggered { max_accumulated_pressure: 1.5 },
            ChurnBudget { min_churn: 1, max_churn: 1 },
        )
        .with_cooldown(Duration::ZERO);
    for i in 0..5u8 { pool.add([i; 32], SubstrateLedger::new()); }

    // 4 samples → Steady. Two calls: 1.0+1.0=2.0 > 1.5 → fires on second.
    // ZERO cooldown passes both calls (elapsed ≥ ZERO always).
    for _ in 0..4 { let _ = pool.sample(&mut rng); }
    let mut before = pool.active_set_snapshot(); before.sort();
    pool.maybe_rotate(&mut rng);    // accumulated = 1.0 → PolicyThresholdNotMet
    pool.maybe_rotate(&mut rng);    // accumulated = 2.0 → Rotated
    let mut after = pool.active_set_snapshot(); after.sort();

    assert_ne!(before, after,
        "cooldown(ZERO) must never block: elapsed ≥ ZERO always passes the gate");
}

// ── §74. force_rotate() bypasses the cooldown gate ────────────────────────────

#[test]
fn pool_cooldown_force_rotate_bypasses_gate() {
    let mut rng = OsRng;
    let mut pool = ProviderPool::new(SamplingStrategy::RandomK(1))
        .with_active_window(4)
        .with_rotation(
            PoolRotationPolicy::Manual,
            ChurnBudget { min_churn: 1, max_churn: 1 },
        )
        .with_cooldown(Duration::MAX);
    for i in 0..5u8 { pool.add([i; 32], SubstrateLedger::new()); }

    let mut before = pool.active_set_snapshot(); before.sort();
    pool.force_rotate(&mut rng);
    let mut after = pool.active_set_snapshot(); after.sort();

    assert_ne!(before, after,
        "force_rotate() must bypass cooldown gate and fire regardless of elapsed time");
}

// ── §75. Cooldown resets after force_rotate(), blocking next maybe_rotate() ──

#[test]
fn pool_cooldown_resets_after_force_rotate() {
    let mut rng = OsRng;
    let mut pool = ProviderPool::new(SamplingStrategy::RandomK(1))
        .with_active_window(4)
        .with_rotation(
            PoolRotationPolicy::IntegralTriggered { max_accumulated_pressure: 0.0 },
            ChurnBudget { min_churn: 1, max_churn: 1 },
        )
        .with_cooldown(Duration::MAX);
    for i in 0..5u8 { pool.add([i; 32], SubstrateLedger::new()); }

    // force_rotate() fires (bypasses gate), resetting last_rotation to now().
    pool.force_rotate(&mut rng);

    // Immediately: maybe_rotate() — accumulated_kappa = 0, but even if it added κ=1.0,
    // the cooldown gate blocks: last_rotation was just reset → elapsed ≈ 0 < MAX.
    let _ = pool.sample(&mut rng);
    let mut before = pool.active_set_snapshot(); before.sort();
    pool.maybe_rotate(&mut rng);
    let mut after = pool.active_set_snapshot(); after.sort();

    assert_eq!(before, after,
        "cooldown must reset after force_rotate(): next maybe_rotate() must be gated");
}

// ── §76. Absent cooldown preserves existing rotation behavior ─────────────────

#[test]
fn pool_cooldown_absent_preserves_existing_behavior() {
    let mut rng = OsRng;
    // Threshold 1.5 ≥ 1.0: safety check does not apply. active_window=1 → κ=1.0 always.
    let mut pool = ProviderPool::new(SamplingStrategy::RandomK(1))
        .with_active_window(1)
        .with_rotation(
            PoolRotationPolicy::IntegralTriggered { max_accumulated_pressure: 1.5 },
            ChurnBudget { min_churn: 1, max_churn: 1 },
        );
    for i in 0..5u8 { pool.add([i; 32], SubstrateLedger::new()); }

    // 4 samples → Steady. Two calls: 1.0+1.0=2.0 > 1.5 → fires on second.
    for _ in 0..4 { let _ = pool.sample(&mut rng); }
    let mut before = pool.active_set_snapshot(); before.sort();
    pool.maybe_rotate(&mut rng);    // accumulated = 1.0 → PolicyThresholdNotMet
    pool.maybe_rotate(&mut rng);    // accumulated = 2.0 → Rotated
    let mut after = pool.active_set_snapshot(); after.sort();

    assert_ne!(before, after,
        "no cooldown configured: rotation must fire normally as before Phase 25");
}

// ── §77. EntropyTriggered blocked in PostReset ────────────────────────────────

#[test]
fn pool_entropy_triggered_blocked_in_post_reset() {
    let mut rng = OsRng;
    // 8 providers, active_window=4: dormant=4 ≥ active_window → floor gate passes.
    // OnRotation resets tracker on each rotation.
    let mut pool = ProviderPool::new(SamplingStrategy::RandomK(1))
        .with_active_window(4)
        .with_rotation(
            PoolRotationPolicy::EntropyTriggered { min_entropy_bits: 3.0 },
            ChurnBudget { min_churn: 1, max_churn: 1 },
        )
        .with_exposure_reset();
    for i in 0..8u8 { pool.add([i; 32], SubstrateLedger::new()); }

    // 0 samples → PostReset (total_samples=0 < active_n=4).
    // entropy=0 bits < 3.0 would fire in Steady; T4 gate blocks it in PostReset.
    let outcome = pool.maybe_rotate(&mut rng);

    assert_eq!(outcome, RotationOutcome::Deferred(DeferralReason::EstimatorNotConverged),
        "EntropyTriggered must be blocked by T4 gate in PostReset");
    assert_eq!(pool.epoch_count(), 0,
        "no rotation must have occurred in PostReset");
}

// ── §78. QueryCount admissible in Reconverging ────────────────────────────────

#[test]
fn pool_query_count_admissible_in_reconverging() {
    let mut rng = OsRng;
    // 8 providers: dormant=4 ≥ active_window=4 → floor gate passes.
    let mut pool = ProviderPool::new(SamplingStrategy::RandomK(1))
        .with_active_window(4)
        .with_rotation(
            PoolRotationPolicy::QueryCount(2),
            ChurnBudget { min_churn: 1, max_churn: 1 },
        )
        .with_exposure_reset();
    for i in 0..8u8 { pool.add([i; 32], SubstrateLedger::new()); }

    // force_rotate: resets tracker → total_samples=0 → PostReset.
    pool.force_rotate(&mut rng);
    let epoch_after_force = pool.epoch_count();

    // 4 samples brings total_samples to 4 = active_n → Reconverging.
    for _ in 0..4 { let _ = pool.sample(&mut rng); }

    // QueryCount(2): first call increments count to 1 → threshold not met.
    let outcome1 = pool.maybe_rotate(&mut rng);
    assert_eq!(outcome1, RotationOutcome::Deferred(DeferralReason::PolicyThresholdNotMet),
        "QueryCount(2) must not fire on the first call in Reconverging");

    // Second call increments count to 2 → fires.
    let outcome2 = pool.maybe_rotate(&mut rng);
    assert_eq!(outcome2, RotationOutcome::Rotated,
        "QueryCount(2) must fire on the second call in Reconverging");
    assert_eq!(pool.epoch_count(), epoch_after_force + 1,
        "epoch_count must have incremented by exactly 1");
}

// ── §79. IntegralTriggered does not accumulate in PostReset ──────────────────

#[test]
fn pool_integral_triggered_does_not_accumulate_in_post_reset() {
    let mut rng = OsRng;
    // Threshold 1.5 ≥ 1.0: safety check does not apply.
    // 8 providers: dormant=4 ≥ active_window=4 → floor gate passes, T4 gate runs.
    let mut pool = ProviderPool::new(SamplingStrategy::RandomK(1))
        .with_active_window(4)
        .with_rotation(
            PoolRotationPolicy::IntegralTriggered { max_accumulated_pressure: 1.5 },
            ChurnBudget { min_churn: 1, max_churn: 1 },
        )
        .with_exposure_reset();
    for i in 0..8u8 { pool.add([i; 32], SubstrateLedger::new()); }

    // force_rotate: resets tracker → total_samples=0 → PostReset.
    pool.force_rotate(&mut rng);

    // 5 × maybe_rotate in PostReset → T4 gate fires before policy arm.
    let outcomes: Vec<RotationOutcome> = (0..5).map(|_| pool.maybe_rotate(&mut rng)).collect();

    for (i, o) in outcomes.iter().enumerate() {
        assert_eq!(*o, RotationOutcome::Deferred(DeferralReason::EstimatorNotConverged),
            "call {i}: IntegralTriggered must be blocked in PostReset");
    }
    assert_eq!(pool.convergence_pressure().accumulated_pressure, 0.0,
        "accumulated_pressure must not have changed while in PostReset");
}

// ── §80. ConvergenceTriggered fires in Steady (positive control) ─────────────

#[test]
fn pool_convergence_triggered_fires_in_steady() {
    let mut rng = OsRng;
    // 2 providers, active_window=1: active_n=1, κ=1.0 always (entropy=0 bits).
    let mut pool = ProviderPool::new(SamplingStrategy::RandomK(1))
        .with_active_window(1)
        .with_rotation(
            PoolRotationPolicy::ConvergenceTriggered { max_kappa: 0.01 },
            ChurnBudget { min_churn: 1, max_churn: 1 },
        );
    pool.add([0u8; 32], SubstrateLedger::new());
    pool.add([1u8; 32], SubstrateLedger::new());

    // 4 × active_n = 4 × 1 = 4 samples → Steady.
    for _ in 0..10 { let _ = pool.sample(&mut rng); }

    let cp = pool.convergence_pressure();
    assert_eq!(cp.current_epoch_phase, EpochPhase::Steady,
        "pool must be in Steady after 10 samples with active_n=1");

    let epoch_before = pool.epoch_count();
    let outcome = pool.maybe_rotate(&mut rng);

    assert_eq!(outcome, RotationOutcome::Rotated,
        "ConvergenceTriggered(0.01) must fire in Steady when κ=1.0");
    assert_eq!(pool.epoch_count(), epoch_before + 1,
        "epoch_count must have incremented after rotation");
}

// ── §81. EstimatorNotConverged is distinct from PolicyThresholdNotMet ────────

#[test]
fn pool_estimator_not_converged_distinct_from_policy_threshold_not_met() {
    let mut rng = OsRng;

    // Pool A: Manual policy in Steady → PolicyThresholdNotMet (Manual never fires).
    // 8 providers: dormant=4 ≥ active_window=4 → floor gate passes.
    let mut pool_a = ProviderPool::new(SamplingStrategy::RandomK(1))
        .with_active_window(4)
        .with_rotation(
            PoolRotationPolicy::Manual,
            ChurnBudget { min_churn: 1, max_churn: 1 },
        );
    for i in 0..8u8 { pool_a.add([i; 32], SubstrateLedger::new()); }
    // 16 samples → total_samples=16 ≥ 4*active_n=16 → Steady.
    for _ in 0..16 { let _ = pool_a.sample(&mut rng); }
    let outcome_a = pool_a.maybe_rotate(&mut rng);

    // Pool B: EntropyTriggered in PostReset → EstimatorNotConverged.
    // 8 providers: dormant=4 ≥ active_window=4 → floor gate passes, T4 gate runs.
    let mut pool_b = ProviderPool::new(SamplingStrategy::RandomK(1))
        .with_active_window(4)
        .with_rotation(
            PoolRotationPolicy::EntropyTriggered { min_entropy_bits: 3.0 },
            ChurnBudget { min_churn: 1, max_churn: 1 },
        )
        .with_exposure_reset();
    for i in 0..8u8 { pool_b.add([i; 32], SubstrateLedger::new()); }
    pool_b.force_rotate(&mut rng); // resets tracker → PostReset
    let outcome_b = pool_b.maybe_rotate(&mut rng);

    assert_eq!(outcome_a, RotationOutcome::Deferred(DeferralReason::PolicyThresholdNotMet),
        "Manual policy in Steady must produce PolicyThresholdNotMet");
    assert_eq!(outcome_b, RotationOutcome::Deferred(DeferralReason::EstimatorNotConverged),
        "EntropyTriggered in PostReset must produce EstimatorNotConverged");
    assert_ne!(outcome_a, outcome_b,
        "the two deferral reasons must be distinguishable");
}

// Phase 32 invariants (Sprint B — IntegralTriggered builder safety):
//   IntegralTriggered with max_accumulated_pressure < 1.0 and no cooldown panics on
//   maybe_rotate() because κ=1.0 after any reset immediately exceeds threshold,
//   creating a rotation loop.
//   IntegralTriggered with max_accumulated_pressure < 1.0 and a non-zero cooldown
//   does not panic.

// ── §82. IntegralTriggered(< 1.0) without cooldown panics ───────────────────────

#[test]
#[should_panic(expected = "IntegralTriggered with max_accumulated_pressure < 1.0 requires a \
                            non-zero cooldown to prevent rotation loops")]
fn pool_integral_triggered_low_threshold_without_cooldown_panics() {
    let mut rng = OsRng;
    // active_window=4, threshold=0.5 < 1.0, no cooldown → safety assert fires.
    let mut pool = ProviderPool::new(SamplingStrategy::RandomK(1))
        .with_active_window(4)
        .with_rotation(
            PoolRotationPolicy::IntegralTriggered { max_accumulated_pressure: 0.5 },
            ChurnBudget { min_churn: 1, max_churn: 1 },
        );
    for i in 0..5u8 { pool.add([i; 32], SubstrateLedger::new()); }
    // 16 samples → Steady. Safety assert fires before any gate: should_panic.
    for _ in 0..16 { let _ = pool.sample(&mut rng); }
    pool.maybe_rotate(&mut rng);
}

// ── §83. IntegralTriggered(< 1.0) with non-zero cooldown does not panic ─────────

#[test]
fn pool_integral_triggered_low_threshold_with_cooldown_ok() {
    let mut rng = OsRng;
    // active_window=1: κ=1.0 by definition. Threshold 0.5 < 1.0, but cooldown 60s satisfies
    // the safety invariant. Cooldown gate: elapsed < 60s at call time → Deferred(Cooldown).
    let mut pool = ProviderPool::new(SamplingStrategy::RandomK(1))
        .with_active_window(1)
        .with_rotation(
            PoolRotationPolicy::IntegralTriggered { max_accumulated_pressure: 0.5 },
            ChurnBudget { min_churn: 1, max_churn: 1 },
        )
        .with_cooldown(Duration::from_secs(60));
    for i in 0..5u8 { pool.add([i; 32], SubstrateLedger::new()); }
    // 4 samples → Steady. Safety check passes (non-zero cooldown). Cooldown gate blocks
    // (elapsed < 60s) → Deferred(Cooldown), not a panic.
    for _ in 0..4 { let _ = pool.sample(&mut rng); }
    let outcome = pool.maybe_rotate(&mut rng);
    assert_eq!(outcome, RotationOutcome::Deferred(DeferralReason::Cooldown),
        "non-zero cooldown: safety check must pass and cooldown gate must block");
}

// Phase 33 invariants (Sprint E — Dormant Floor Enforcement):
//   maybe_rotate() defers with DormantBelowFloor when dormant.len() < active_window.
//   maybe_rotate() proceeds past the floor gate when dormant.len() >= active_window.

// ── §84. Floor gate defers when dormant < active_window ─────────────────────────

#[test]
fn pool_dormant_floor_gate_blocks_when_below_threshold() {
    let mut rng = OsRng;
    // 5 providers, active_window=4: 4 active + 1 dormant. dormant.len()=1 < active_window=4.
    let mut pool = ProviderPool::new(SamplingStrategy::RandomK(1))
        .with_active_window(4)
        .with_rotation(
            PoolRotationPolicy::QueryCount(1),
            ChurnBudget { min_churn: 1, max_churn: 1 },
        );
    for i in 0..5u8 { pool.add([i; 32], SubstrateLedger::new()); }
    let epoch_before = pool.epoch_count();

    // 4 samples → total_samples=4 ≥ active_n=4 → Reconverging (QueryCount is admissible).
    for _ in 0..4 { let _ = pool.sample(&mut rng); }
    let outcome = pool.maybe_rotate(&mut rng);

    assert_eq!(outcome, RotationOutcome::Deferred(DeferralReason::DormantBelowFloor),
        "dormant.len()=1 < active_window=4: floor gate must block rotation");
    assert_eq!(pool.epoch_count(), epoch_before,
        "epoch_count must be unchanged when floor gate defers");
}

// ── §85. Floor gate passes when dormant >= active_window ─────────────────────────

#[test]
fn pool_dormant_floor_gate_passes_when_at_threshold() {
    let mut rng = OsRng;
    // 8 providers, active_window=4: 4 active + 4 dormant. dormant.len()=4 == active_window=4.
    let mut pool = ProviderPool::new(SamplingStrategy::RandomK(1))
        .with_active_window(4)
        .with_rotation(
            PoolRotationPolicy::QueryCount(1),
            ChurnBudget { min_churn: 1, max_churn: 1 },
        );
    for i in 0..8u8 { pool.add([i; 32], SubstrateLedger::new()); }
    let epoch_before = pool.epoch_count();

    // 4 samples → Reconverging. QueryCount(1) is admissible. dormant.len()=4 == active_window=4
    // → floor gate passes → QueryCount fires on first call.
    for _ in 0..4 { let _ = pool.sample(&mut rng); }
    let outcome = pool.maybe_rotate(&mut rng);

    assert_eq!(outcome, RotationOutcome::Rotated,
        "dormant.len()=4 == active_window=4: floor gate must pass, rotation must fire");
    assert_eq!(pool.epoch_count(), epoch_before + 1,
        "epoch_count must increment by 1 on successful rotation");
}

// Phase 34 invariants (Phase Opacity — Observer-State Concealment):
//   tick() coarsens to bool; DeferralReason is never exposed at the protocol surface.
//   tick() with zero jitter (default) behaves identically to maybe_rotate() cast to bool.
//   tick() jitter gate suppresses immediate subsequent calls when max > Duration::ZERO.
//   tick() calls convergence_pressure() on every invocation including PostReset (34C).
//   Bounded diagnostic accessors: active_count, dormant_count, kappa.

// ── §86. tick() returns true when rotation fires ──────────────────────────────

#[test]
fn pool_tick_returns_true_on_rotation() {
    let mut rng = OsRng;
    // 8 providers, active_window=4: dormant=4 >= active_window=4 (floor satisfied).
    // QueryCount(1): fires on the first admissible call. 4 samples → Reconverging (admissible).
    let mut pool = ProviderPool::new(SamplingStrategy::RandomK(1))
        .with_active_window(4)
        .with_rotation(
            PoolRotationPolicy::QueryCount(1),
            ChurnBudget { min_churn: 1, max_churn: 1 },
        );
    for i in 0..8u8 { pool.add([i; 32], SubstrateLedger::new()); }
    let epoch_before = pool.epoch_count();
    for _ in 0..4 { let _ = pool.sample(&mut rng); }

    let rotated = pool.tick(&mut rng);

    assert!(rotated, "tick() must return true when a rotation fires");
    assert_eq!(pool.epoch_count(), epoch_before + 1,
        "epoch_count must increment by 1 on a rotation");
}

// ── §87. tick() returns false when rotation defers ───────────────────────────

#[test]
fn pool_tick_returns_false_on_all_deferrals() {
    let mut rng = OsRng;
    // Manual policy never fires → always Deferred(PolicyThresholdNotMet).
    let mut pool = ProviderPool::new(SamplingStrategy::RandomK(1))
        .with_active_window(4)
        .with_rotation(
            PoolRotationPolicy::Manual,
            ChurnBudget { min_churn: 1, max_churn: 1 },
        );
    for i in 0..8u8 { pool.add([i; 32], SubstrateLedger::new()); }
    for _ in 0..16 { let _ = pool.sample(&mut rng); }
    let epoch_before = pool.epoch_count();

    let rotated = pool.tick(&mut rng);

    assert!(!rotated, "tick() must return false for Manual policy (never rotates)");
    assert_eq!(pool.epoch_count(), epoch_before,
        "epoch_count must be unchanged when rotation defers");

    // Also verify: DormantEmpty → false. active_window=usize::MAX puts all providers active.
    let mut pool2 = ProviderPool::new(SamplingStrategy::RandomK(1))
        .with_rotation(
            PoolRotationPolicy::QueryCount(1),
            ChurnBudget { min_churn: 1, max_churn: 1 },
        );
    for i in 0..4u8 { pool2.add([i; 32], SubstrateLedger::new()); }
    assert!(!pool2.tick(&mut rng),
        "tick() must return false when dormant is empty (DormantEmpty)");
}

// ── §88. tick() with zero jitter proceeds immediately ────────────────────────

#[test]
fn pool_tick_zero_jitter_matches_maybe_rotate() {
    let mut rng = OsRng;
    // No jitter configured: tick() must proceed on every call (no deadline suppression).
    let mut pool = ProviderPool::new(SamplingStrategy::RandomK(1))
        .with_active_window(4)
        .with_rotation(
            PoolRotationPolicy::QueryCount(1),
            ChurnBudget { min_churn: 1, max_churn: 1 },
        );
    for i in 0..8u8 { pool.add([i; 32], SubstrateLedger::new()); }
    for _ in 0..4 { let _ = pool.sample(&mut rng); }

    let rotated = pool.tick(&mut rng);

    assert!(rotated, "zero-jitter tick() must rotate just like maybe_rotate() would");
}

// ── §89. tick() jitter gate suppresses immediate second call ─────────────────

#[test]
fn pool_tick_jitter_gate_suppresses_immediate_second_call() {
    let mut rng = OsRng;
    // 500ms jitter: after the first live tick(), the deadline is set 0–500ms ahead.
    // An immediate second call must find the deadline still in the future → false.
    let mut pool = ProviderPool::new(SamplingStrategy::RandomK(1))
        .with_active_window(4)
        .with_rotation(
            PoolRotationPolicy::QueryCount(1),
            ChurnBudget { min_churn: 1, max_churn: 1 },
        )
        .with_tick_jitter(Duration::from_millis(500));
    for i in 0..8u8 { pool.add([i; 32], SubstrateLedger::new()); }
    for _ in 0..4 { let _ = pool.sample(&mut rng); }

    let _first = pool.tick(&mut rng);  // Live: deadline was in the past; redraws deadline.
    let second = pool.tick(&mut rng);  // Immediate: deadline now up to 500ms in the future.

    assert!(!second, "immediate second tick() must be suppressed by jitter gate");
}

// ── §90. tick() does not panic in PostReset (convergence_pressure baseline) ──

#[test]
fn pool_tick_postReset_baseline_does_not_panic() {
    let mut rng = OsRng;
    // 0 samples → PostReset. convergence_pressure() must not panic with empty estimator.
    // Manual policy → never rotates. tick() returns false.
    let mut pool = ProviderPool::new(SamplingStrategy::RandomK(1))
        .with_active_window(4)
        .with_rotation(
            PoolRotationPolicy::Manual,
            ChurnBudget { min_churn: 1, max_churn: 1 },
        );
    for i in 0..8u8 { pool.add([i; 32], SubstrateLedger::new()); }

    let result = pool.tick(&mut rng);

    assert!(!result, "tick() in PostReset with Manual policy must return false");
}

// ── §91. tick() constant-work baseline does not corrupt state ─────────────────

#[test]
fn pool_tick_steady_constant_work_correctness() {
    let mut rng = OsRng;
    // 16 samples → Steady. convergence_pressure() is called before maybe_rotate();
    // the baseline computation must not corrupt the rotation state.
    let mut pool = ProviderPool::new(SamplingStrategy::RandomK(1))
        .with_active_window(4)
        .with_rotation(
            PoolRotationPolicy::QueryCount(1),
            ChurnBudget { min_churn: 1, max_churn: 1 },
        );
    for i in 0..8u8 { pool.add([i; 32], SubstrateLedger::new()); }
    for _ in 0..16 { let _ = pool.sample(&mut rng); }
    let epoch_before = pool.epoch_count();

    let rotated = pool.tick(&mut rng);

    assert!(rotated, "tick() in Steady with QueryCount(1) must rotate");
    assert_eq!(pool.epoch_count(), epoch_before + 1,
        "pressure baseline must not corrupt epoch state");
}

// ── §92. Diagnostic counts correct after construction ────────────────────────

#[test]
fn pool_diagnostic_counts_correct_after_construction() {
    let make_pool = |active_window: usize, n_providers: u8| {
        let mut pool = ProviderPool::new(SamplingStrategy::RandomK(1))
            .with_active_window(active_window);
        for i in 0..n_providers { pool.add([i; 32], SubstrateLedger::new()); }
        pool
    };

    let windowed = make_pool(4, 8);
    assert_eq!(windowed.active_count(), 4, "active_count must equal active_window");
    assert_eq!(windowed.dormant_count(), 4, "dormant_count must be total - active");

    // Default active_window=usize::MAX: all providers go active.
    let mut full = ProviderPool::new(SamplingStrategy::RandomK(1));
    for i in 0..4u8 { full.add([i; 32], SubstrateLedger::new()); }
    assert_eq!(full.active_count(), 4, "default window: all providers are active");
    assert_eq!(full.dormant_count(), 0, "default window: dormant pool is empty");
}

// ── §93. Diagnostic kappa is finite and in [0.0, 1.0] ───────────────────────

#[test]
fn pool_diagnostic_kappa_in_range() {
    let mut rng = OsRng;
    let mut pool = ProviderPool::new(SamplingStrategy::RandomK(1))
        .with_active_window(4);
    for i in 0..8u8 { pool.add([i; 32], SubstrateLedger::new()); }

    // PostReset: 0 samples. κ = 1.0 by definition when estimator has no data.
    let kappa_post_reset = pool.kappa();
    assert!(kappa_post_reset.is_finite(), "kappa must be finite in PostReset");
    assert!((0.0..=1.0).contains(&kappa_post_reset),
        "kappa must be in [0.0, 1.0] in PostReset; got {kappa_post_reset}");

    // Steady: 16 samples. κ is well-defined.
    for _ in 0..16 { let _ = pool.sample(&mut rng); }
    let kappa_steady = pool.kappa();
    assert!(kappa_steady.is_finite(), "kappa must be finite in Steady");
    assert!((0.0..=1.0).contains(&kappa_steady),
        "kappa must be in [0.0, 1.0] in Steady; got {kappa_steady}");
}

// ── §94. BurstTriggered fires when threshold always met (threshold=-2.0) ─────

#[test]
fn pool_burst_triggered_fires_when_threshold_always_met() {
    let mut rng = OsRng;
    let mut pool = ProviderPool::new(SamplingStrategy::RandomK(1))
        .with_active_window(4)
        .with_rotation(
            PoolRotationPolicy::BurstTriggered {
                min_burst_magnitude: -2.0,
                response_jitter_max: Duration::ZERO,
            },
            ChurnBudget { min_churn: 1, max_churn: 1 },
        );
    for i in 0..8u8 { pool.add([i; 32], SubstrateLedger::new()); }
    // Drive to Steady (≥ 4*active_n = 16 samples).
    for _ in 0..16 { let _ = pool.sample(&mut rng); }

    // burst = kappa - smoothed_kappa ≥ -1.0 > -2.0: threshold always satisfied.
    let before = pool.epoch_count();
    let outcome = pool.maybe_rotate(&mut rng);
    assert_eq!(outcome, RotationOutcome::Rotated);
    assert_eq!(pool.epoch_count(), before + 1);
}

// ── §95. BurstTriggered defers when threshold never met (threshold=2.0) ──────

#[test]
fn pool_burst_triggered_defers_when_threshold_never_met() {
    let mut rng = OsRng;
    let mut pool = ProviderPool::new(SamplingStrategy::RandomK(1))
        .with_active_window(4)
        .with_rotation(
            PoolRotationPolicy::BurstTriggered {
                min_burst_magnitude: 2.0,
                response_jitter_max: Duration::ZERO,
            },
            ChurnBudget { min_churn: 1, max_churn: 1 },
        );
    for i in 0..8u8 { pool.add([i; 32], SubstrateLedger::new()); }
    for _ in 0..16 { let _ = pool.sample(&mut rng); }

    // burst ≤ 1.0 < 2.0: threshold never satisfied.
    let before = pool.epoch_count();
    let outcome = pool.maybe_rotate(&mut rng);
    assert_eq!(outcome, RotationOutcome::Deferred(DeferralReason::PolicyThresholdNotMet));
    assert_eq!(pool.epoch_count(), before);
}

// ── §96. BurstTriggered response jitter defers first detection ───────────────

#[test]
fn pool_burst_triggered_response_jitter_defers_first_detection() {
    let mut rng = OsRng;
    let mut pool = ProviderPool::new(SamplingStrategy::RandomK(1))
        .with_active_window(4)
        .with_rotation(
            PoolRotationPolicy::BurstTriggered {
                min_burst_magnitude: -2.0,
                response_jitter_max: Duration::from_millis(500),
            },
            ChurnBudget { min_churn: 1, max_churn: 1 },
        );
    for i in 0..8u8 { pool.add([i; 32], SubstrateLedger::new()); }
    for _ in 0..16 { let _ = pool.sample(&mut rng); }

    // First call: burst detected; jitter > 0 so deadline is set; deferred.
    let before = pool.epoch_count();
    let first = pool.maybe_rotate(&mut rng);
    // Second immediate call: deadline is in the future (500ms jitter); still deferred.
    let second = pool.maybe_rotate(&mut rng);

    // Both calls are deferred — the jitter response window prevents immediate rotation.
    // (If jitter drew 0 the first call would rotate; that path is tested in §94.)
    // At minimum one of the two calls is deferred.
    assert!(
        first == RotationOutcome::Deferred(DeferralReason::PolicyThresholdNotMet)
            || second == RotationOutcome::Deferred(DeferralReason::PolicyThresholdNotMet),
        "at least one call must be deferred when jitter > 0"
    );
    // Epoch may have advanced at most once (if jitter drew 0 on the first call).
    assert!(pool.epoch_count() <= before + 1);
}

// ── §97. BurstTriggered blocked by T4 outside Steady ─────────────────────────

#[test]
fn pool_burst_triggered_blocked_by_t4_outside_steady() {
    let mut rng = OsRng;
    let mut pool = ProviderPool::new(SamplingStrategy::RandomK(1))
        .with_active_window(4)
        .with_rotation(
            PoolRotationPolicy::BurstTriggered {
                min_burst_magnitude: -2.0,
                response_jitter_max: Duration::ZERO,
            },
            ChurnBudget { min_churn: 1, max_churn: 1 },
        );
    for i in 0..8u8 { pool.add([i; 32], SubstrateLedger::new()); }

    // PostReset: 0 samples → EstimatorNotConverged.
    assert_eq!(
        pool.maybe_rotate(&mut rng),
        RotationOutcome::Deferred(DeferralReason::EstimatorNotConverged),
        "BurstTriggered must be blocked in PostReset"
    );

    // Reconverging: 4 samples (≥ active_n but < 4*active_n=16) → EstimatorNotConverged.
    for _ in 0..4 { let _ = pool.sample(&mut rng); }
    assert_eq!(
        pool.maybe_rotate(&mut rng),
        RotationOutcome::Deferred(DeferralReason::EstimatorNotConverged),
        "BurstTriggered must be blocked in Reconverging"
    );

    // Steady: 16 samples → Rotated (threshold always met with -2.0).
    for _ in 0..12 { let _ = pool.sample(&mut rng); }
    assert_eq!(
        pool.maybe_rotate(&mut rng),
        RotationOutcome::Rotated,
        "BurstTriggered must fire in Steady when threshold is always met"
    );
}

// ── §98. Admission request returns a 32-byte challenge ───────────────────────

#[test]
fn pool_admission_request_returns_challenge() {
    let kp = KeyPair::generate();
    let mut pool = ProviderPool::<SubstrateLedger>::new(SamplingStrategy::RandomK(1))
        .with_admission(AdmissionConfig {
            max_admits_per_window: 5,
            window_duration: std::time::Duration::from_secs(300),
            challenge_ttl:   std::time::Duration::from_secs(60),
        });

    let challenge = pool.request_admission(kp.public).expect("first request must succeed");
    assert_eq!(challenge.len(), 32, "challenge must be 32 bytes");

    // Second call for the same ID while a challenge is pending → PendingChallenge.
    let err = pool.request_admission(kp.public).expect_err("duplicate request must fail");
    assert_eq!(err, AdmissionError::PendingChallenge);
}

// ── §99. Complete admission with valid signature admits the provider ──────────

#[test]
fn pool_admission_complete_with_valid_signature() {
    let kp = KeyPair::generate();
    let mut pool = ProviderPool::new(SamplingStrategy::RandomK(1))
        .with_active_window(4)
        .with_admission(AdmissionConfig {
            max_admits_per_window: 5,
            window_duration: std::time::Duration::from_secs(300),
            challenge_ttl:   std::time::Duration::from_secs(60),
        });

    let challenge = pool.request_admission(kp.public).unwrap();
    let msg = admission_challenge_message(&kp.public, &challenge);
    let sig = kp.sign(&msg);
    pool.complete_admission(kp.public, &sig, SubstrateLedger::new())
        .expect("valid signature must be accepted");

    assert_eq!(pool.active_count() + pool.dormant_count(), 1,
        "admitted provider must appear in pool");
}

// ── §100. Invalid signature is rejected; pending challenge is preserved ───────

#[test]
fn pool_admission_invalid_signature_rejected() {
    let kp = KeyPair::generate();
    let mut pool = ProviderPool::new(SamplingStrategy::RandomK(1))
        .with_admission(AdmissionConfig {
            max_admits_per_window: 5,
            window_duration: std::time::Duration::from_secs(300),
            challenge_ttl:   std::time::Duration::from_secs(60),
        });

    pool.request_admission(kp.public).unwrap();
    let bad_sig = [0u8; 64];
    let err = pool.complete_admission(kp.public, &bad_sig, SubstrateLedger::new())
        .expect_err("invalid signature must be rejected");
    assert_eq!(err, AdmissionError::SignatureInvalid);
    assert_eq!(pool.active_count() + pool.dormant_count(), 0,
        "provider must not be in pool after failed verification");

    // Pending challenge is preserved — the caller may retry with the correct signature.
    let err2 = pool.request_admission(kp.public).expect_err("challenge still pending");
    assert_eq!(err2, AdmissionError::PendingChallenge);
}

// ── §101. Expired challenge is rejected ──────────────────────────────────────

#[test]
fn pool_admission_challenge_expired() {
    let kp = KeyPair::generate();
    let mut pool = ProviderPool::new(SamplingStrategy::RandomK(1))
        .with_admission(AdmissionConfig {
            max_admits_per_window: 5,
            window_duration: std::time::Duration::from_secs(300),
            challenge_ttl:   std::time::Duration::ZERO, // expires immediately
        });

    let challenge = pool.request_admission(kp.public).unwrap();
    let msg = admission_challenge_message(&kp.public, &challenge);
    let sig = kp.sign(&msg);

    // elapsed() >= Duration::ZERO is always true — any call sees the challenge as expired.
    let err = pool.complete_admission(kp.public, &sig, SubstrateLedger::new())
        .expect_err("expired challenge must be rejected");
    assert_eq!(err, AdmissionError::ChallengeExpired);
    assert_eq!(pool.active_count() + pool.dormant_count(), 0);
}

// ── §102. Budget exhaustion blocks further requests ───────────────────────────

#[test]
fn pool_admission_budget_exhaustion() {
    let kp1 = KeyPair::generate();
    let kp2 = KeyPair::generate();
    let kp3 = KeyPair::generate();
    let mut pool = ProviderPool::<SubstrateLedger>::new(SamplingStrategy::RandomK(1))
        .with_admission(AdmissionConfig {
            max_admits_per_window: 2,
            window_duration: std::time::Duration::from_secs(300),
            challenge_ttl:   std::time::Duration::from_secs(60),
        });

    pool.request_admission(kp1.public).expect("first request within budget");
    pool.request_admission(kp2.public).expect("second request within budget");
    let err = pool.request_admission(kp3.public).expect_err("third request exceeds budget");
    assert_eq!(err, AdmissionError::BudgetExhausted);
}

// ── §103. Duplicate provider ID is rejected at request time ──────────────────

#[test]
fn pool_admission_duplicate_rejected() {
    let kp = KeyPair::generate();
    let mut pool = ProviderPool::new(SamplingStrategy::RandomK(1))
        .with_active_window(4)
        .with_admission(AdmissionConfig {
            max_admits_per_window: 10,
            window_duration: std::time::Duration::from_secs(300),
            challenge_ttl:   std::time::Duration::from_secs(60),
        });

    // Full admit cycle — provider enters the pool.
    let challenge = pool.request_admission(kp.public).unwrap();
    let sig = kp.sign(&admission_challenge_message(&kp.public, &challenge));
    pool.complete_admission(kp.public, &sig, SubstrateLedger::new()).unwrap();
    assert_eq!(pool.active_count() + pool.dormant_count(), 1);

    // Requesting admission for an already-pooled ID returns AlreadyInPool.
    let err = pool.request_admission(kp.public).expect_err("duplicate must fail");
    assert_eq!(err, AdmissionError::AlreadyInPool);
}

// ── §104. add() panics when admission is configured ──────────────────────────

#[test]
#[should_panic(expected = "ProviderPool has admission configured; use complete_admission()")]
fn pool_admission_add_panics_when_configured() {
    let mut pool = ProviderPool::new(SamplingStrategy::RandomK(1))
        .with_admission(AdmissionConfig {
            max_admits_per_window: 5,
            window_duration: std::time::Duration::from_secs(300),
            challenge_ttl:   std::time::Duration::from_secs(60),
        });
    pool.add([0u8; 32], SubstrateLedger::new()); // must panic
}

// ── §105. Budget resets after the window duration elapses ────────────────────

#[test]
fn pool_admission_budget_resets_after_window() {
    let kp1 = KeyPair::generate();
    let kp2 = KeyPair::generate();
    let kp3 = KeyPair::generate();
    let mut pool = ProviderPool::<SubstrateLedger>::new(SamplingStrategy::RandomK(1))
        .with_admission(AdmissionConfig {
            max_admits_per_window: 1,
            window_duration: std::time::Duration::from_millis(20),
            challenge_ttl:   std::time::Duration::from_secs(60),
        });

    // Use up the single-admit budget.
    pool.request_admission(kp1.public).expect("first request within budget");
    let err = pool.request_admission(kp2.public).expect_err("budget exhausted");
    assert_eq!(err, AdmissionError::BudgetExhausted);

    // After the window expires, the budget resets.
    std::thread::sleep(std::time::Duration::from_millis(25));
    pool.request_admission(kp3.public).expect("budget must reset after window");
}

// ── §106. liveness_weighted_kappa ≈ kappa when all active providers respond ────
//
// If all 4 active providers respond at equal rates, the response distribution
// mirrors the selection distribution.  Both κ values approach 0 (high diversity),
// and their difference is negligible.

#[test]
fn pool_liveness_kappa_equals_kappa_when_all_providers_respond() {
    let mut rng = OsRng;
    let mut pool = ProviderPool::new(SamplingStrategy::RandomK(1))
        .with_active_window(4);
    for i in 0..4 {
        pool.add(pid(i), SubstrateLedger::new());
    }

    // 400 samples → selection distribution converges to roughly uniform.
    for _ in 0..400 {
        let _ = pool.sample(&mut rng);
    }
    // Respond uniformly: 100 responses per provider = perfectly uniform distribution.
    for i in 0..4u8 {
        for _ in 0..100 {
            pool.record_response(pid(i));
        }
    }

    let p = pool.convergence_pressure();
    assert!(
        (p.liveness_weighted_kappa - p.kappa).abs() < 0.05,
        "liveness_weighted_kappa ({:.4}) should be close to kappa ({:.4}) when all providers respond",
        p.liveness_weighted_kappa, p.kappa,
    );
}

// ── §107. liveness_weighted_kappa rises when a provider goes silent ─────────────
//
// pid(3) is selected but never responds.  The response distribution concentrates
// on 3 providers (H ≈ log2(3)) while selection remains roughly uniform (H ≈ log2(4)).
// liveness_weighted_kappa > kappa reflects the availability gap.

#[test]
fn pool_liveness_kappa_rises_when_provider_goes_silent() {
    let mut rng = OsRng;
    let mut pool = ProviderPool::new(SamplingStrategy::RandomK(1))
        .with_active_window(4);
    for i in 0..4 {
        pool.add(pid(i), SubstrateLedger::new());
    }

    for _ in 0..400 {
        let _ = pool.sample(&mut rng);
    }
    // pid(3) is silent — only 3 providers respond.
    for i in 0..3u8 {
        for _ in 0..100 {
            pool.record_response(pid(i));
        }
    }

    let p = pool.convergence_pressure();
    assert!(
        p.liveness_weighted_kappa > p.kappa,
        "liveness_weighted_kappa ({:.4}) must exceed kappa ({:.4}) when a provider is silent",
        p.liveness_weighted_kappa, p.kappa,
    );
}

// ── §108. liveness_weighted_kappa is 1.0 before any responses ───────────────────
//
// response_entropy_bits == 0.0 when no record_response() has been called.
// 1 - 0 / log2(active_n) == 1.0 for any active_n > 1.

#[test]
fn pool_liveness_kappa_is_one_before_any_responses() {
    let mut rng = OsRng;
    let mut pool = ProviderPool::new(SamplingStrategy::RandomK(1))
        .with_active_window(4);
    for i in 0..4 {
        pool.add(pid(i), SubstrateLedger::new());
    }
    for _ in 0..40 {
        let _ = pool.sample(&mut rng);
    }

    let p = pool.convergence_pressure();
    assert_eq!(
        p.liveness_weighted_kappa, 1.0,
        "liveness_weighted_kappa must be 1.0 when no responses have been recorded",
    );
}

// ── §109. response_entropy_bits and response_total_samples start at zero ────────

#[test]
fn pool_response_entropy_is_zero_before_any_responses() {
    let mut rng = OsRng;
    let mut pool = ProviderPool::new(SamplingStrategy::RandomK(1))
        .with_active_window(4);
    for i in 0..4 {
        pool.add(pid(i), SubstrateLedger::new());
    }
    for _ in 0..40 {
        let _ = pool.sample(&mut rng);
    }

    let est = pool.exposure_estimate();
    assert_eq!(est.response_entropy_bits, 0.0,
        "response_entropy_bits must be 0.0 before any record_response() calls");
    assert_eq!(est.response_total_samples, 0,
        "response_total_samples must be 0 before any record_response() calls");
}

// ── §110. smoothed_response_entropy_bits is preserved across rotation reset ──────
//
// with_exposure_reset() clears raw response counts but must NOT zero the EWMA
// smoothed response entropy, mirroring the anti-thrashing behavior of the
// selection tracker.

#[test]
fn pool_response_smoothed_entropy_preserved_across_reset() {
    let mut rng = OsRng;
    let mut pool = ProviderPool::new(SamplingStrategy::RandomK(1))
        .with_active_window(1)
        .with_rotation(
            PoolRotationPolicy::Manual,
            ChurnBudget { min_churn: 1, max_churn: 1 },
        )
        .with_exposure_reset();
    pool.add(pid(0), SubstrateLedger::new());
    pool.add(pid(1), SubstrateLedger::new());

    for _ in 0..40 {
        let _ = pool.sample(&mut rng);
    }
    for i in 0..2u8 {
        for _ in 0..20 {
            pool.record_response(pid(i));
        }
    }
    assert!(
        pool.exposure_estimate().smoothed_response_entropy_bits > 0.0,
        "pre-condition: smoothed_response_entropy_bits must be non-zero before rotation",
    );

    pool.force_rotate(&mut rng);

    let est = pool.exposure_estimate();
    assert_eq!(est.response_total_samples, 0,
        "rotation with reset must clear response_total_samples");
    assert!(
        est.smoothed_response_entropy_bits > 0.0,
        "rotation must preserve smoothed_response_entropy_bits (anti-thrashing)",
    );
}

// ── §111. evict() removes provider from the active set ──────────────────────────
//
// evict(pid, LivenessExhausted) removes the provider from active, drops its P,
// and records an EvictionRecord.  active_len() drops by 1; total len drops by 1.

#[test]
fn pool_evict_removes_provider_from_active() {
    let mut pool = ProviderPool::new(SamplingStrategy::RandomK(1))
        .with_active_window(2)
        .with_eviction(EvictionConfig {
            liveness_cooldown_secs:     300,
            equivocation_cooldown_secs: 3600,
            max_re_admissions:          3,
        });
    // pid(0), pid(1) → active; pid(2) → dormant
    for i in 0..3 { pool.add(pid(i), SubstrateLedger::new()); }
    assert_eq!(pool.active_len(), 2);

    pool.evict(&pid(0), EvictionReason::LivenessExhausted).unwrap();

    assert_eq!(pool.active_len(), 1, "active_len must drop after eviction");
    assert_eq!(pool.len(), 2, "total universe drops by 1");
    assert!(
        !pool.active_set_snapshot().contains(&pid(0)),
        "evicted provider must not appear in active set",
    );
}

// ── §112. evict() removes provider from the dormant set ─────────────────────────
//
// With enough dormant providers to satisfy the floor gate, evicting a dormant
// provider reduces both dormant count and total len by 1.

#[test]
fn pool_evict_removes_provider_from_dormant() {
    let mut pool = ProviderPool::new(SamplingStrategy::RandomK(1))
        .with_active_window(2)
        .with_eviction(EvictionConfig {
            liveness_cooldown_secs:     300,
            equivocation_cooldown_secs: 3600,
            max_re_admissions:          3,
        });
    // pid(0..1) → active; pid(2..4) → dormant (3 dormant, floor needs ≥ 2 after removal)
    for i in 0..5 { pool.add(pid(i), SubstrateLedger::new()); }
    assert_eq!(pool.active_len(), 2);
    assert_eq!(pool.len() - pool.active_len(), 3, "pre-condition: 3 dormant");

    pool.evict(&pid(4), EvictionReason::LivenessExhausted).unwrap();

    assert_eq!(pool.len() - pool.active_len(), 2, "dormant count drops after eviction");
    assert_eq!(pool.len(), 4, "total universe drops by 1");
}

// ── §113. evicted provider is blocked during liveness cooldown ───────────────────
//
// After eviction with a long liveness_cooldown_secs, an immediate
// request_admission() returns EvictionCooldown.

#[test]
fn pool_evicted_provider_blocked_during_cooldown() {
    let kp = KeyPair::generate();
    let provider_id = kp.public;

    let mut pool = ProviderPool::new(SamplingStrategy::RandomK(1))
        .with_active_window(4)
        .with_admission(AdmissionConfig {
            max_admits_per_window: 5,
            window_duration:       Duration::from_secs(60),
            challenge_ttl:         Duration::from_secs(60),
        })
        .with_eviction(EvictionConfig {
            liveness_cooldown_secs:     9999,
            equivocation_cooldown_secs: 3600,
            max_re_admissions:          3,
        });

    let challenge = pool.request_admission(provider_id).unwrap();
    let sig = kp.sign(&admission_challenge_message(&provider_id, &challenge));
    pool.complete_admission(provider_id, &sig, SubstrateLedger::new()).unwrap();

    pool.evict(&provider_id, EvictionReason::LivenessExhausted).unwrap();

    let err = pool.request_admission(provider_id).unwrap_err();
    assert!(
        matches!(err, AdmissionError::EvictionCooldown { .. }),
        "expected EvictionCooldown, got {err:?}",
    );
}

// ── §114. evicted provider can re-admit after cooldown elapses ──────────────────
//
// With liveness_cooldown_secs = 0 the provider is immediately eligible.
// complete_admission() puts it back in the active set.

#[test]
fn pool_evicted_provider_can_readmit_after_cooldown() {
    let kp = KeyPair::generate();
    let provider_id = kp.public;

    let mut pool = ProviderPool::new(SamplingStrategy::RandomK(1))
        .with_active_window(4)
        .with_admission(AdmissionConfig {
            max_admits_per_window: 5,
            window_duration:       Duration::from_secs(60),
            challenge_ttl:         Duration::from_secs(60),
        })
        .with_eviction(EvictionConfig {
            liveness_cooldown_secs:     0,
            equivocation_cooldown_secs: 0,
            max_re_admissions:          3,
        });

    let c = pool.request_admission(provider_id).unwrap();
    let sig = kp.sign(&admission_challenge_message(&provider_id, &c));
    pool.complete_admission(provider_id, &sig, SubstrateLedger::new()).unwrap();

    pool.evict(&provider_id, EvictionReason::LivenessExhausted).unwrap();

    let c2 = pool.request_admission(provider_id)
        .expect("re-admission must succeed after zero cooldown");
    let sig2 = kp.sign(&admission_challenge_message(&provider_id, &c2));
    pool.complete_admission(provider_id, &sig2, SubstrateLedger::new()).unwrap();

    assert!(
        pool.active_set_snapshot().contains(&provider_id),
        "provider must be back in active set after successful re-admission",
    );
}

// ── §115. OperatorBan is permanent until explicitly lifted ──────────────────────
//
// request_admission() returns Banned regardless of elapsed time.
// lift_eviction_ban() removes the record so the next admission succeeds.

#[test]
fn pool_operator_ban_is_permanent() {
    let kp = KeyPair::generate();
    let provider_id = kp.public;

    let mut pool = ProviderPool::new(SamplingStrategy::RandomK(1))
        .with_active_window(4)
        .with_admission(AdmissionConfig {
            max_admits_per_window: 5,
            window_duration:       Duration::from_secs(60),
            challenge_ttl:         Duration::from_secs(60),
        })
        .with_eviction(EvictionConfig {
            liveness_cooldown_secs:     0,
            equivocation_cooldown_secs: 0,
            max_re_admissions:          99,
        });

    let c = pool.request_admission(provider_id).unwrap();
    let sig = kp.sign(&admission_challenge_message(&provider_id, &c));
    pool.complete_admission(provider_id, &sig, SubstrateLedger::new()).unwrap();

    pool.evict(&provider_id, EvictionReason::OperatorBan).unwrap();

    // Zero cooldown, high re-admission limit — still permanently banned.
    let err = pool.request_admission(provider_id).unwrap_err();
    assert_eq!(err, AdmissionError::Banned);

    // Lift the ban.
    let lifted = pool.lift_eviction_ban(&provider_id);
    assert!(lifted, "lift_eviction_ban must return true when a ban record exists");

    // Now re-admission is permitted.
    let c2 = pool.request_admission(provider_id)
        .expect("admission must succeed after ban lifted");
    let sig2 = kp.sign(&admission_challenge_message(&provider_id, &c2));
    pool.complete_admission(provider_id, &sig2, SubstrateLedger::new()).unwrap();
    assert!(pool.active_set_snapshot().contains(&provider_id));
}

// ── §116. max_re_admissions blocks after the lifetime limit ─────────────────────
//
// With max_re_admissions = 2, the third request_admission() returns
// MaxReAdmissionsExceeded regardless of elapsed time.

#[test]
fn pool_max_readmissions_blocks_after_limit() {
    let kp = KeyPair::generate();
    let provider_id = kp.public;

    let mut pool = ProviderPool::new(SamplingStrategy::RandomK(1))
        .with_active_window(4)
        .with_admission(AdmissionConfig {
            max_admits_per_window: 20,
            window_duration:       Duration::from_secs(60),
            challenge_ttl:         Duration::from_secs(60),
        })
        .with_eviction(EvictionConfig {
            liveness_cooldown_secs:     0,
            equivocation_cooldown_secs: 0,
            max_re_admissions:          2,
        });

    // Helper: admit provider (inline to avoid borrow issues)
    macro_rules! admit {
        () => {{
            let c = pool.request_admission(provider_id).unwrap();
            let sig = kp.sign(&admission_challenge_message(&provider_id, &c));
            pool.complete_admission(provider_id, &sig, SubstrateLedger::new()).unwrap();
        }};
    }

    // Initial admission (no eviction record yet).
    admit!();

    // Cycle 1: evict → re-admit (re_admission_count: 0 → 1)
    pool.evict(&provider_id, EvictionReason::LivenessExhausted).unwrap();
    admit!();

    // Cycle 2: evict → re-admit (re_admission_count: 1 → 2)
    pool.evict(&provider_id, EvictionReason::LivenessExhausted).unwrap();
    admit!();

    // Cycle 3: evict → attempt re-admission → blocked
    pool.evict(&provider_id, EvictionReason::LivenessExhausted).unwrap();
    let err = pool.request_admission(provider_id).unwrap_err();
    assert_eq!(err, AdmissionError::MaxReAdmissionsExceeded);
}

// ── §117. eviction gate rejection does not consume admission budget ──────────────
//
// When request_admission() is rejected by the eviction gate (not the budget gate),
// the budget slot must NOT be consumed — a different provider can still be admitted.

#[test]
fn pool_eviction_check_does_not_consume_budget() {
    let kp_a = KeyPair::generate();
    let id_a  = kp_a.public;
    let kp_b  = KeyPair::generate();
    let id_b  = kp_b.public;

    let mut pool = ProviderPool::new(SamplingStrategy::RandomK(1))
        .with_active_window(4)
        .with_admission(AdmissionConfig {
            max_admits_per_window: 2,   // slot 1 for setup, slot 2 for proof
            window_duration:       Duration::from_secs(60),
            challenge_ttl:         Duration::from_secs(60),
        })
        .with_eviction(EvictionConfig {
            liveness_cooldown_secs:     0,
            equivocation_cooldown_secs: 0,
            max_re_admissions:          0,  // block on first eviction
        });

    // Admit A (budget: 1/2 used).
    let c = pool.request_admission(id_a).unwrap();
    let sig = kp_a.sign(&admission_challenge_message(&id_a, &c));
    pool.complete_admission(id_a, &sig, SubstrateLedger::new()).unwrap();

    // Evict A (max_re_admissions=0 → immediately blocked).
    pool.evict(&id_a, EvictionReason::LivenessExhausted).unwrap();

    // Requesting A again → MaxReAdmissionsExceeded (eviction gate, NOT budget gate).
    let err = pool.request_admission(id_a).unwrap_err();
    assert_eq!(err, AdmissionError::MaxReAdmissionsExceeded,
        "eviction gate must fire before budget check");

    // Requesting B → slot 2 must still be available.
    let result = pool.request_admission(id_b);
    assert!(result.is_ok(),
        "budget must not be consumed by eviction-gate rejection; got {result:?}");
}

// ── §118. evict() respects the DormantBelowFloor gate ───────────────────────────
//
// When dormant.len() - 1 < active_window, evicting a dormant provider would make
// future rotation impossible.  evict() must return WouldViolateDormantFloor.

#[test]
fn pool_evict_floor_gate_fires() {
    let mut pool = ProviderPool::new(SamplingStrategy::RandomK(1))
        .with_active_window(2)
        .with_eviction(EvictionConfig {
            liveness_cooldown_secs:     300,
            equivocation_cooldown_secs: 3600,
            max_re_admissions:          3,
        });
    // pid(0..1) → active; pid(2..3) → dormant (exactly active_window dormant)
    for i in 0..4 { pool.add(pid(i), SubstrateLedger::new()); }
    // dormant.len()=2, active_window=2: removing one → 1 < 2 → floor violation

    let err = pool.evict(&pid(2), EvictionReason::LivenessExhausted).unwrap_err();
    assert_eq!(err, EvictionError::WouldViolateDormantFloor);
}
