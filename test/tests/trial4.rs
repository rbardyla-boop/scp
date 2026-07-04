// Trial 4 — Selective Response Suppression and Telemetry Manipulability Characterization
//
// Permitted claim (after verification):
//   Under deterministic scripted selective-response and response-injection scenarios,
//   the SCP simulator characterizes how existing provider telemetry surfaces can reveal
//   or fail to reveal manipulated liveness behavior, without connecting those observations
//   to automatic vitality, send, rotation, routing, or relay policy.
//
// Critical interpretation boundary:
//   1. Asymmetric selective suppression is observable when liveness_weighted_kappa
//      diverges from kappa (T3).
//   2. Symmetric partial suppression can leave balance/concentration metrics looking
//      healthy while total response participation degrades (T5).
//   3. Response/selection accounting may expose symmetric suppression in the absence
//      of injection (T6).
//   4. recent_reported_response_ratio() is itself manipulable when response injection
//      can inflate the numerator (T7).
//   5. No currently proven telemetry surface, alone or naively combined, is authorized
//      for automated policy use.
//
// Explicit non-claims (confirmed by T8–T9):
//   - provider telemetry should influence vitality
//   - kappa, liveness_weighted_kappa, or response/selection totals should populate
//     SimVitalityEvaluationContext.p
//   - any manipulation scenario should trigger automatic vitality change, send rejection,
//     rotation, routing, or relay policy
//   - TOLS κ policy integration
//   - production vitality-input measurement or reaffirmation protocol
//   - relay routing or mailbox delivery
//   - localhost, LAN, desktop, or hardware readiness
//
// Vitality transition boundaries under standard controls (i=1.0, r=1.0, p=0.0), t0=0:
//   Active → Warm:       t = 578_388 (Active) / 578_389 (Warm)
//
// Determinism requirement: all tests use fixed scripted traces.
// No random provider selection; no wall-clock timing; no loose thresholds.
// For floating-point outputs: assert exact derived values or use 1e-12 tolerance.
// For boundary values (0.0, 1.0, 0.5): assert_eq! for exact match.

use rand::SeedableRng;
use rand::rngs::StdRng;
use scp_cryptography::keys::KeyPair;
use scp_cryptography::x25519_generate_keypair;
use scp_ledger_substrate::{HandshakeEphemeral, SubstrateLedger, TunnelConsent, tunnel_consent_hash};
use scp_provider_pool::{EpochPhase, ProviderPool, SamplingStrategy};
use scp_relay_cache::WarmCache;
use scp_relay_perturbation::PerturbationEngine;
use scp_transport::flash::FlashSession;
use scp_vitality::{SimVitalityEvaluationContext, VitalityEvidenceStore, VitalityState};
use scp_wire_format::signing::handshake_sig_message;
use std::time::Duration;

// ── Helpers ────────────────────────────────────────────────────────────────────
// Redeclared locally per the test-helper boundary: may assemble deterministic
// scenarios but must not duplicate telemetry formulas, reproduce send-gating
// rules, or bypass open_and_send_sim() for send-path assertions.

fn pid(byte: u8) -> [u8; 32] { [byte; 32] }

/// Deterministic RNG with fixed seed 0. Produces the same selection trace on every run.
fn seeded() -> StdRng { StdRng::seed_from_u64(0) }

fn register_bilateral_consent(ledger: &SubstrateLedger, kp_a: &KeyPair, kp_b: &KeyPair) -> [u8; 32] {
    let ch = tunnel_consent_hash(&kp_a.public, &kp_b.public);
    let consent = TunnelConsent {
        party_a: kp_a.public,
        party_b: kp_b.public,
        sig_a:   kp_a.sign(&ch).to_vec(),
        sig_b:   kp_b.sign(&ch).to_vec(),
    };
    ledger.register_tunnel(consent).expect("bilateral tunnel registration must succeed");
    ch
}

fn publish_ephemeral_at(ledger: &SubstrateLedger, ops_kp: &KeyPair, sim_now: u64) {
    let (_, eph_pub) = x25519_generate_keypair();
    let expires_at = sim_now + 3_600;
    let sig: [u8; 64] = ops_kp.sign(&handshake_sig_message(&eph_pub, expires_at));
    let eph = HandshakeEphemeral {
        pub_key:      eph_pub,
        sig:          sig.to_vec(),
        published_at: sim_now,
        expires_at,
    };
    ledger.publish_handshake_ephemeral(&ops_kp.public, eph)
        .expect("ephemeral publish must succeed");
}

fn std_ctx(consent_hash: [u8; 32], now: u64) -> SimVitalityEvaluationContext {
    SimVitalityEvaluationContext::new(consent_hash, now, 1.0, 1.0, 0.0)
        .expect("standard controls must be valid")
}

fn warm_cache() -> WarmCache { WarmCache::new(Duration::from_secs(600)) }
fn passthrough() -> PerturbationEngine { PerturbationEngine::passthrough() }

// ── T1: Healthy fixed-response baseline ──────────────────────────────────────
//
// ProviderPool trace: 4 providers, 16 seeded samples (→ Steady), 4 responses per provider.
//
// Exact telemetry derivation:
//   response_appearances = {pid(1):4, pid(2):4, pid(3):4, pid(4):4}   total = 16
//   response_entropy = log₂(4) = 2.0 bits  →  lwk = 1 − 2.0/2.0 = 0.0
//   response_total = 16, selection_total = 16, ratio = Some(1.0)
//   kappa: derived from seeded selection trace via proven exposure_estimate() API
//
// No rotation or policy action; epoch_count = 0.

#[test]
fn t1_healthy_fixed_response_baseline() {
    let mut rng = seeded();
    let mut pool = ProviderPool::new(SamplingStrategy::RandomK(1));
    for i in 1u8..=4 { pool.add(pid(i), SubstrateLedger::new()); }
    for _ in 0..16 { let _ = pool.sample(&mut rng); }
    for i in 1u8..=4 { for _ in 0..4 { pool.record_response(pid(i)); } }

    let snap = pool.operational_telemetry();
    let est  = pool.exposure_estimate();

    // Surface 1 — survivor concentration
    assert_eq!(snap.active_n, 4);
    assert_eq!(snap.current_epoch_phase, EpochPhase::Steady,
        "16 samples with 4 active providers must reach Steady phase");
    assert!(snap.survivor_surface_evaluable,
        "Steady phase → survivor surface evaluable");
    let expected_kappa = (1.0_f64 - est.selection_entropy_bits / 4_f64.log2()).clamp(0.0, 1.0);
    assert!((snap.kappa - expected_kappa).abs() < 1e-12,
        "kappa must match value derived from seeded selection trace");

    // Surface 2 — relative liveness distortion
    assert!(snap.liveness_surface_evaluable,
        "16 responses and 16 selections → liveness surface evaluable");
    assert_eq!(snap.liveness_weighted_kappa, 0.0,
        "uniform 4-provider response: response_entropy = log₂(4) = 2.0 bits → lwk = 0.0");

    // Surface 3 — absolute availability
    assert!(snap.availability_evaluable);
    assert_eq!(snap.selection_total, 16);
    assert_eq!(snap.response_total, 16);
    assert_eq!(snap.recent_reported_response_ratio(), Some(1.0),
        "all selections responded → ratio = 1.0 (no degradation)");

    // No rotation or policy action
    assert_eq!(pool.epoch_count(), 0,
        "no operation must have triggered rotation: epoch_count = 0");
}

// ── T2: Total silent-failure baseline ────────────────────────────────────────
//
// ProviderPool trace: 4 providers, 16 seeded samples, NO responses recorded.
//
// Exact telemetry derivation:
//   response_total = 0 → response_entropy = 0.0 bits → lwk = 1.0
//   liveness_surface_evaluable = false (response_total = 0)
//   availability_evaluable = true (selection_total = 16 > 0)
//   recent_reported_response_ratio() = Some(0.0)
//
// Silence is an observed trace only; malicious intent is not inferred.

#[test]
fn t2_total_silent_failure_baseline() {
    let mut rng = seeded();
    let mut pool = ProviderPool::new(SamplingStrategy::RandomK(1));
    for i in 1u8..=4 { pool.add(pid(i), SubstrateLedger::new()); }
    for _ in 0..16 { let _ = pool.sample(&mut rng); }
    // No record_response() calls — total silence

    let snap = pool.operational_telemetry();
    let est  = pool.exposure_estimate();

    // Surface 1 — survivor concentration (selection trace is identical to T1)
    assert_eq!(snap.active_n, 4);
    assert_eq!(snap.current_epoch_phase, EpochPhase::Steady,
        "16 samples → Steady regardless of response trace");
    assert!(snap.survivor_surface_evaluable);
    let expected_kappa = (1.0_f64 - est.selection_entropy_bits / 4_f64.log2()).clamp(0.0, 1.0);
    assert!((snap.kappa - expected_kappa).abs() < 1e-12,
        "kappa is determined by the seeded selection trace, not the response trace");

    // Surface 2 — relative liveness distortion: unevaluable with 0 responses
    assert!(!snap.liveness_surface_evaluable,
        "response_total = 0 → liveness surface unevaluable");
    assert_eq!(snap.liveness_weighted_kappa, 1.0,
        "no responses: response_entropy = 0.0 bits → lwk = 1.0");

    // Surface 3 — absolute availability: degraded to zero
    assert!(snap.availability_evaluable,
        "selection_total = 16 > 0 → availability surface evaluable");
    assert_eq!(snap.selection_total, 16);
    assert_eq!(snap.response_total, 0);
    assert_eq!(snap.recent_reported_response_ratio(), Some(0.0),
        "0 responses / 16 selections = 0.0 (maximally degraded ratio)");

    assert_eq!(pool.epoch_count(), 0);
}

// ── T3: Asymmetric selective suppression ─────────────────────────────────────
//
// ProviderPool trace: 4 providers, 16 seeded samples; pid(4) silent.
//
// Exact telemetry derivation:
//   response_appearances = {pid(1):4, pid(2):4, pid(3):4}  total = 12
//   Each responding provider has proportion 1/3:
//     response_entropy = log₂(3) bits
//   liveness_weighted_kappa = 1.0 − log₂(3)/log₂(4)   (derived from exposure_estimate)
//   liveness_weighted_kappa ≥ kappa (response entropy ≤ selection entropy always)
//   liveness_weighted_kappa > kappa iff pid(4) was selected (seeded trace confirms this)
//
// Distinguishability claim: the asymmetric trace IS observable on Surface 2
// because lwk > 0 and lwk > kappa.

#[test]
fn t3_asymmetric_selective_suppression() {
    let mut rng = seeded();
    let mut pool = ProviderPool::new(SamplingStrategy::RandomK(1));
    for i in 1u8..=4 { pool.add(pid(i), SubstrateLedger::new()); }
    for _ in 0..16 { let _ = pool.sample(&mut rng); }
    // pid(4) is silent — selected but never responds
    for _ in 0..4 { pool.record_response(pid(1)); }
    for _ in 0..4 { pool.record_response(pid(2)); }
    for _ in 0..4 { pool.record_response(pid(3)); }

    let snap = pool.operational_telemetry();
    let est  = pool.exposure_estimate();

    assert!(snap.liveness_surface_evaluable,
        "12 responses and 16 selections → liveness surface evaluable");
    assert_eq!(snap.response_total, 12);
    assert_eq!(snap.selection_total, 16);

    // Exact kappa from seeded selection trace (same selection distribution as T1)
    let expected_kappa = (1.0_f64 - est.selection_entropy_bits / 4_f64.log2()).clamp(0.0, 1.0);
    assert!((snap.kappa - expected_kappa).abs() < 1e-12,
        "kappa must match value derived from the seeded selection trace");

    // Exact liveness_weighted_kappa from response entropy: derived from exposure_estimate
    let expected_lwk = (1.0_f64 - est.response_entropy_bits / 4_f64.log2()).clamp(0.0, 1.0);
    assert!((snap.liveness_weighted_kappa - expected_lwk).abs() < 1e-12,
        "liveness_weighted_kappa must match derivation from response entropy estimate");

    // lwk > 0: pid(4) silent → response entropy < log₂(4) → lwk > 0 (not healthy)
    assert!(snap.liveness_weighted_kappa > 0.0,
        "asymmetric suppression: one silent provider → lwk > 0 (distinguishable from healthy)");

    // lwk ≥ kappa: response entropy cannot exceed selection entropy
    assert!(snap.liveness_weighted_kappa >= snap.kappa,
        "response entropy ≤ selection entropy → lwk ≥ kappa always");

    // lwk > kappa iff pid(4) was selected — confirmed if seeded selection has entropy > 0
    if est.selection_entropy_bits > 0.0 {
        assert!(snap.liveness_weighted_kappa > snap.kappa,
            "pid(4) selected but silent → response entropy < selection entropy → lwk > kappa");
    }

    assert_eq!(pool.epoch_count(), 0);
}

// ── T4: Alternating selective suppression ────────────────────────────────────
//
// ProviderPool trace: 2 providers, 8 seeded samples; pid(2) alternates — responds
// for only half of its selections.
//
// Exact telemetry derivation (controlled response counts):
//   record_response(pid(1)) × 4, record_response(pid(2)) × 2
//   response_appearances = {pid(1):4, pid(2):2}  total = 6
//   proportions: p1 = 4/6 = 2/3, p2 = 2/6 = 1/3
//   response_entropy = −(2/3·log₂(2/3) + 1/3·log₂(1/3))  [< log₂(2) = 1.0]
//   liveness_weighted_kappa = 1.0 − response_entropy / log₂(2) = 1.0 − response_entropy
//     (since log₂(2) = 1.0 exactly in IEEE 754)
//   lwk > 0.0 (alternating trace distinguishable from healthy balance)
//   lwk < 1.0 (both providers contribute some responses)

#[test]
fn t4_alternating_selective_suppression() {
    let mut rng = seeded();
    let mut pool = ProviderPool::new(SamplingStrategy::RandomK(1));
    pool.add(pid(1), SubstrateLedger::new());
    pool.add(pid(2), SubstrateLedger::new());
    for _ in 0..8 { let _ = pool.sample(&mut rng); }
    // pid(2) responds for only half of its selections (alternating)
    for _ in 0..4 { pool.record_response(pid(1)); }
    for _ in 0..2 { pool.record_response(pid(2)); }

    let snap = pool.operational_telemetry();
    let est  = pool.exposure_estimate();

    assert!(snap.liveness_surface_evaluable);
    assert_eq!(snap.response_total, 6);
    assert_eq!(snap.selection_total, 8);

    // Exact lwk from exposure_estimate: log₂(2) = 1.0 exactly in IEEE 754
    let expected_lwk = (1.0_f64 - est.response_entropy_bits / 2_f64.log2()).clamp(0.0, 1.0);
    assert!((snap.liveness_weighted_kappa - expected_lwk).abs() < 1e-12,
        "liveness_weighted_kappa must match derivation from response entropy estimate");

    // Distinguishability from both boundary cases
    assert!(snap.liveness_weighted_kappa > 0.0,
        "alternating suppression: response entropy < log₂(2) → lwk > 0 (not healthy)");
    assert!(snap.liveness_weighted_kappa < 1.0,
        "both providers contribute responses → response entropy > 0 → lwk < 1.0");

    // The alternating trace produces a strictly intermediate lwk between healthy (0.0) and
    // total silent failure (1.0), confirming metric distinguishability of partial suppression.
    assert_eq!(pool.epoch_count(), 0);
}

// ── T5: Symmetric partial suppression defeats Surface 2 ──────────────────────
//
// ProviderPool trace: 4 providers, 16 seeded samples; EACH provider gets exactly
// 2 responses (50% suppression, applied symmetrically).
//
// Exact telemetry derivation:
//   response_appearances = {pid(1):2, pid(2):2, pid(3):2, pid(4):2}  total = 8
//   Each provider has proportion 2/8 = 1/4 → uniform distribution
//   response_entropy = log₂(4) = 2.0 bits  →  lwk = 1 − 2.0/2.0 = 0.0
//   Surface 2 reads identical to healthy baseline despite 50% participation drop.
//
// Surface 3 shows degradation: ratio = 8/16 = 0.5.
//
// EXPLICIT RECORD:
//   Balanced liveness weighting does not imply healthy participation when suppression
//   is symmetric. Surface 2 (liveness_weighted_kappa) cannot distinguish a 50% symmetric
//   participation drop from a fully healthy trace when the response distribution remains
//   uniform across all active providers.

#[test]
fn t5_symmetric_partial_suppression_defeats_surface2() {
    let mut rng = seeded();
    let mut pool = ProviderPool::new(SamplingStrategy::RandomK(1));
    for i in 1u8..=4 { pool.add(pid(i), SubstrateLedger::new()); }
    for _ in 0..16 { let _ = pool.sample(&mut rng); }
    // Symmetric 50% suppression: each provider responds exactly half as often
    for i in 1u8..=4 { for _ in 0..2 { pool.record_response(pid(i)); } }

    let snap = pool.operational_telemetry();

    // Surface 2 looks identical to healthy — symmetric suppression defeats it
    assert_eq!(snap.liveness_weighted_kappa, 0.0,
        "symmetric partial suppression with uniform response distribution: \
         response_entropy = log₂(4) = 2.0 bits → lwk = 0.0 (Surface 2 cannot distinguish)");
    assert!(snap.liveness_surface_evaluable);

    // Surface 3 reveals the participation drop
    assert_eq!(snap.response_total, 8,
        "4 providers × 2 responses = 8 (half of healthy 16)");
    assert_eq!(snap.selection_total, 16);
    assert_eq!(snap.recent_reported_response_ratio(), Some(0.5),
        "Surface 3: response/selection = 8/16 = 0.5 (50% degradation visible)");

    // EXPLICIT RECORD: Balanced liveness weighting does not imply healthy participation
    // when suppression is symmetric.
    assert_eq!(pool.epoch_count(), 0);
}

// ── T6: Response ratio detects symmetric suppression only absent injection ────
//
// ProviderPool trace: identical to T5 — 4 providers, 16 seeded samples, 2 responses each.
//
// Exact Surface 3 output:
//   response_total = 8, selection_total = 16, ratio = Some(0.5)
//
// This establishes the limited counter-signal: Surface 3 can detect symmetric
// suppression ONLY when record_response() calls accurately reflect actual relay
// attempts. If the numerator can be injected, this counter-signal is itself
// unreliable (demonstrated in T7).

#[test]
fn t6_response_ratio_detects_symmetric_suppression_absent_injection() {
    let mut rng = seeded();
    let mut pool = ProviderPool::new(SamplingStrategy::RandomK(1));
    for i in 1u8..=4 { pool.add(pid(i), SubstrateLedger::new()); }
    for _ in 0..16 { let _ = pool.sample(&mut rng); }
    for i in 1u8..=4 { for _ in 0..2 { pool.record_response(pid(i)); } }

    let snap = pool.operational_telemetry();

    // Exact degraded Surface 3 output
    assert_eq!(snap.response_total, 8,
        "underlying suppressed trace: 8 responses in 16 selections");
    assert_eq!(snap.selection_total, 16);
    assert!(snap.availability_evaluable);
    assert_eq!(snap.recent_reported_response_ratio(), Some(0.5),
        "exact degraded ratio = 0.5: Surface 3 detects 50% symmetric suppression");

    // Limited counter-signal: this value is accurate only absent injection.
    // record_response() calls are NOT causally bound to actual relay attempts
    // (see recent_reported_response_ratio() docstring §S64, §S69).
}

// ── T7: Response injection masks suppression accounting ──────────────────────
//
// Underlying trace: symmetric 50% suppression (same as T6 — 8 responses from 16 selections,
// ratio = 0.5, Surface 3 detects degradation).
//
// Injection seam: record_response() accepts any provider_id and increments
// response_total without requiring a prior sample() call. The numerator of
// recent_reported_response_ratio() is therefore freely inflateable.
//
// Injection: 8 additional record_response() calls (2 per provider) without sample().
// After injection:
//   response_total = 16, selection_total = 16 (unchanged — no new samples)
//   response_distribution = {pid(i): 4/16 = 1/4 each} = uniform
//   liveness_weighted_kappa = 0.0 (Surface 2 still reads healthy)
//   recent_reported_response_ratio() = Some(1.0)  (Surface 3 masked to "healthy")
//
// Both Surface 2 and Surface 3 are masked by injection.
// The underlying 50% suppression behavior exists in the trace setup but is concealed.

#[test]
fn t7_response_injection_masks_suppression_accounting() {
    let mut rng = seeded();
    let mut pool = ProviderPool::new(SamplingStrategy::RandomK(1));
    for i in 1u8..=4 { pool.add(pid(i), SubstrateLedger::new()); }
    for _ in 0..16 { let _ = pool.sample(&mut rng); }
    // Underlying suppressed trace: 2 responses per provider (50% suppression)
    for i in 1u8..=4 { for _ in 0..2 { pool.record_response(pid(i)); } }

    // Confirm degraded baseline before injection (replicates T6)
    let snap_before = pool.operational_telemetry();
    assert_eq!(snap_before.response_total, 8,
        "pre-injection: underlying suppressed trace has 8 responses");
    assert_eq!(snap_before.selection_total, 16);
    assert_eq!(snap_before.recent_reported_response_ratio(), Some(0.5),
        "pre-injection: Surface 3 detects 50% suppression → ratio = 0.5");

    // Injection via documented seam: record_response() without prior sample()
    // record_response() does not require a corresponding sample() call;
    // the response_total numerator is freely inflateable (§S64, §S69).
    for i in 1u8..=4 { for _ in 0..2 { pool.record_response(pid(i)); } }

    let snap_after = pool.operational_telemetry();

    // The underlying suppression behavior existed in the trace (8 genuine responses)
    // but is now concealed by the injected 8 calls.

    // selection_total is unchanged: injection does not require sample() calls
    assert_eq!(snap_after.selection_total, 16,
        "injection does not call sample() → selection_total unchanged at 16");

    // response_total is inflated: 8 genuine + 8 injected = 16
    assert_eq!(snap_after.response_total, 16,
        "injected record_response() calls inflate response_total from 8 to 16");

    // Surface 3 masked: ratio appears fully healthy after injection
    assert_eq!(snap_after.recent_reported_response_ratio(), Some(1.0),
        "injected responses inflate ratio from 0.5 to 1.0 — Surface 3 masked (§S64, §S69)");

    // Surface 2 also reads healthy: injected calls restore uniform response distribution
    assert_eq!(snap_after.liveness_weighted_kappa, 0.0,
        "injected calls restore uniform response distribution → lwk = 0.0 (Surface 2 masked)");

    // Both surfaces are now masked by injection despite the underlying suppressed trace.
}

// ── T8: Manipulated telemetry remains disconnected from vitality and send ─────
//
// Using an Active bilateral vitality context:
//   1. Apply asymmetric selective-suppression trace (pid(4) silent).
//   2. Observe that Surface 2 shows a changed, non-zero liveness_weighted_kappa.
//   3. Perform a send through open_and_send_sim() with unchanged vitality evidence
//      and unchanged ctx.p = 0.0.
//
// Assert:
//   - vitality evidence timestamp unchanged (Active→Warm boundary invariant);
//   - ctx.p unchanged (0.0 in standard controls);
//   - send succeeds because Active vitality governs, not provider telemetry;
//   - epoch_count = 0 (no rotation triggered).

#[tokio::test]
async fn t8_manipulated_telemetry_disconnected_from_vitality_and_send() {
    let ledger = SubstrateLedger::new();
    let alice  = KeyPair::generate();
    let bob    = KeyPair::generate();
    let ch = register_bilateral_consent(&ledger, &alice, &bob);

    let mut store = VitalityEvidenceStore::new();
    let t0 = 0_u64;
    store.initialize_at(ch, t0);
    publish_ephemeral_at(&ledger, &bob, t0);

    // Asymmetric selective-suppression trace: pid(4) selected but silent
    let mut rng = seeded();
    let mut pool = ProviderPool::new(SamplingStrategy::RandomK(1));
    for i in 1u8..=4 { pool.add(pid(i), SubstrateLedger::new()); }
    for _ in 0..16 { let _ = pool.sample(&mut rng); }
    for _ in 0..4 { pool.record_response(pid(1)); }
    for _ in 0..4 { pool.record_response(pid(2)); }
    for _ in 0..4 { pool.record_response(pid(3)); }
    // pid(4) is silent

    // Verify changed, non-zero telemetry on Surface 2
    let snap = pool.operational_telemetry();
    assert!(snap.liveness_weighted_kappa > 0.0,
        "asymmetric suppression: lwk > 0 (Surface 2 detects manipulation)");
    assert!(snap.liveness_weighted_kappa >= snap.kappa,
        "response entropy ≤ selection entropy → lwk ≥ kappa");

    // Vitality evidence timestamp must be unchanged by pool operations
    assert_eq!(store.compute_state(ch, t0 + 578_388, 1.0, 1.0, 0.0), VitalityState::Active,
        "pool trace must not alter evidence timestamp: Active at t0+578_388");
    assert_eq!(store.compute_state(ch, t0 + 578_389, 1.0, 1.0, 0.0), VitalityState::Warm,
        "pool trace must not alter evidence timestamp: Warm at t0+578_389");

    // Send through open_and_send_sim() with unchanged Active vitality context (ctx.p = 0.0)
    let ctx = std_ctx(ch, t0); // p = 0.0 unchanged
    let result = FlashSession::open_and_send_sim(
        &ledger, &store, &ctx, &bob.public, b"t8-payload", &warm_cache(), &passthrough(),
    ).await;
    assert!(result.is_ok(),
        "Active vitality must permit send despite manipulated provider telemetry");

    // Vitality evidence timestamp unchanged after send
    assert_eq!(store.compute_state(ch, t0 + 578_388, 1.0, 1.0, 0.0), VitalityState::Active,
        "send must not refresh evidence: still Active at t0+578_388");
    assert_eq!(store.compute_state(ch, t0 + 578_389, 1.0, 1.0, 0.0), VitalityState::Warm,
        "send must not refresh evidence: still Warm at t0+578_389");

    // ctx.p unchanged (0.0): standard controls at t0 still yield Active
    assert_eq!(store.compute_state(ch, t0, 1.0, 1.0, 0.0), VitalityState::Active,
        "ctx.p = 0.0 unchanged: standard controls at t0 still yield Active");

    // No rotation triggered by manipulation trace or send
    assert_eq!(pool.epoch_count(), 0,
        "no operation must have triggered rotation: epoch_count = 0");
}

// ── T9: No automatic rotation or control action from manipulation trace ───────
//
// Exercise the strongest manipulable telemetry trace available through existing seams:
// response injection that masks both Surface 2 (lwk) and Surface 3 (ratio) by inflating
// response_total without corresponding sample() calls.
//
// Assert:
//   - the manipulation trace can be constructed through existing public seams;
//   - epoch_count = 0 (no rotation triggered by any manipulation operation);
//   - no automatic control action from the tested observation path.
//
// This claim is scoped to the tested current observation path only.

#[test]
fn t9_no_automatic_rotation_from_manipulation_trace() {
    let mut rng = seeded();
    // Strongest manipulable trace: injection scenario from T7
    let mut pool = ProviderPool::new(SamplingStrategy::RandomK(1));
    for i in 1u8..=4 { pool.add(pid(i), SubstrateLedger::new()); }
    for _ in 0..16 { let _ = pool.sample(&mut rng); }
    // Underlying suppressed trace
    for i in 1u8..=4 { for _ in 0..2 { pool.record_response(pid(i)); } }
    // Injection: inflate response_total via record_response() without sample()
    for i in 1u8..=4 { for _ in 0..2 { pool.record_response(pid(i)); } }

    let snap = pool.operational_telemetry();

    // Confirm the strongest manipulation trace is in effect
    assert_eq!(snap.recent_reported_response_ratio(), Some(1.0),
        "injection masks Surface 3: ratio = 1.0 despite 50% underlying suppression");
    assert_eq!(snap.liveness_weighted_kappa, 0.0,
        "injection masks Surface 2: lwk = 0.0 despite underlying suppression");

    // No automatic rotation triggered by manipulation trace
    assert_eq!(pool.epoch_count(), 0,
        "strongest manipulation trace must not trigger rotation: epoch_count = 0");

    // No automatic policy action through the tested observation path.
    // This claim is scoped to the current implementation only; it does not claim
    // future architecture cannot introduce policy coupling.
}
