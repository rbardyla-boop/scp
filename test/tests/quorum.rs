// Phase 11 quorum tests: ProviderQuorum multi-provider dispatcher.
//
// Invariants under test:
//   Empty quorum → Unavailable for all methods.
//   Single provider semantics match direct StateProvider.
//   Monotonic: any() wins for revocation; one revocation claim suffices.
//   Soft-state: latest expires_at wins; absence does not override presence.
//   Consensus-relevant: all_agree() required; disagreement = Equivocation.
//   ProviderQuorum<P> implements StateProvider as a drop-in.

use std::time::{SystemTime, UNIX_EPOCH};

use scp_cryptography::keys::{x25519_generate_keypair, KeyPair};
use scp_ledger_substrate::{HandshakeEphemeral, LedgerIdentityRecord, SubstrateLedger};
use scp_transport::flash::FlashSession;
use scp_transport::quorum::{ProviderQuorum, QuorumResult};
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

/// Register the same identity (same root_kp/ops_kp pair) on a second independent ledger.
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

/// Publish an ephemeral with a caller-provided eph_pub.
///
/// Used in the "all agree" test where both ledgers must hold the byte-identical
/// ephemeral to produce identical RecipientState::commitment() outputs.
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

/// Publish a fresh random ephemeral. Returns the generated eph_pub.
fn publish_ephemeral(ledger: &SubstrateLedger, ops_kp: &KeyPair, expires_at: u64) -> [u8; 32] {
    let (_, eph_pub) = x25519_generate_keypair();
    publish_ephemeral_explicit(ledger, ops_kp, eph_pub, expires_at);
    eph_pub
}

fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

fn provider_id(byte: u8) -> [u8; 32] {
    [byte; 32]
}

// ── §1. Empty quorum → Unavailable ───────────────────────────────────────────

#[test]
fn quorum_empty_providers_returns_unavailable() {
    let q: ProviderQuorum<SubstrateLedger> = ProviderQuorum::new();
    let ops_pub = [0x01u8; 32];
    let now = now_secs();

    assert!(
        matches!(q.is_revoked_quorum(&ops_pub), QuorumResult::Unavailable),
        "is_revoked_quorum on empty quorum must return Unavailable"
    );
    assert!(
        matches!(q.get_handshake_ephemeral_quorum(&ops_pub, now), QuorumResult::Unavailable),
        "get_handshake_ephemeral_quorum on empty quorum must return Unavailable"
    );
    assert!(
        matches!(q.get_commitment_quorum(&ops_pub), QuorumResult::Unavailable),
        "get_commitment_quorum on empty quorum must return Unavailable"
    );
}

// ── §2. Single provider — not revoked ────────────────────────────────────────

#[test]
fn quorum_single_provider_not_revoked() {
    let ledger = SubstrateLedger::new();
    let (_, ops_kp) = register(&ledger);

    let mut q = ProviderQuorum::new();
    q.add(provider_id(0x01), ledger);

    match q.is_revoked_quorum(&ops_kp.public) {
        QuorumResult::Agree(false) => {}
        QuorumResult::Agree(true) => panic!("registered but unrevoked key must not be seen as revoked"),
        _ => panic!("expected Agree(false) for unrevoked key"),
    }
}

// ── §3. Single provider — revoked ────────────────────────────────────────────

#[test]
fn quorum_single_provider_revoked() {
    let ledger = SubstrateLedger::new();
    let (root_kp, ops_kp) = register(&ledger);

    let revoke_sig = root_kp.sign(&ops_kp.public);
    ledger.revoke(&ops_kp.public, &revoke_sig).expect("revoke must succeed");

    let mut q = ProviderQuorum::new();
    q.add(provider_id(0x01), ledger);

    match q.is_revoked_quorum(&ops_kp.public) {
        QuorumResult::Agree(true) => {}
        QuorumResult::Agree(false) => panic!("revoked key must be seen as revoked"),
        _ => panic!("expected Agree(true) for revoked key"),
    }
}

// ── §4. Monotonic: any revocation wins ───────────────────────────────────────

#[test]
fn quorum_monotonic_any_revocation_wins() {
    // 3 providers; only provider B has processed the revocation.
    let ledger_a = SubstrateLedger::new();
    let ledger_b = SubstrateLedger::new();
    let ledger_c = SubstrateLedger::new();

    let (root_kp, ops_kp) = register(&ledger_a);
    register_same_identity(&ledger_b, &root_kp, &ops_kp);
    register_same_identity(&ledger_c, &root_kp, &ops_kp);

    let revoke_sig = root_kp.sign(&ops_kp.public);
    ledger_b.revoke(&ops_kp.public, &revoke_sig).expect("revoke must succeed");

    let mut q = ProviderQuorum::new();
    q.add(provider_id(0x0a), ledger_a); // not yet revoked (lagging)
    q.add(provider_id(0x0b), ledger_b); // revoked
    q.add(provider_id(0x0c), ledger_c); // not yet revoked (lagging)

    match q.is_revoked_quorum(&ops_kp.public) {
        QuorumResult::Agree(true) => {}
        QuorumResult::Agree(false) => {
            panic!("a single revocation claim must cause the quorum to return revoked=true")
        }
        _ => panic!("expected Agree(true) from monotonic any() rule"),
    }
}

// ── §5. Soft-state: latest ephemeral wins ────────────────────────────────────

#[test]
fn quorum_soft_state_latest_ephemeral_wins() {
    let now = now_secs();
    let ledger_a = SubstrateLedger::new();
    let ledger_b = SubstrateLedger::new();

    let (root_kp, ops_kp) = register(&ledger_a);
    register_same_identity(&ledger_b, &root_kp, &ops_kp);

    let expires_a = now + 100;
    let expires_b = now + 200; // later — must win
    publish_ephemeral(&ledger_a, &ops_kp, expires_a);
    publish_ephemeral(&ledger_b, &ops_kp, expires_b);

    let mut q = ProviderQuorum::new();
    q.add(provider_id(0x0a), ledger_a);
    q.add(provider_id(0x0b), ledger_b);

    match q.get_handshake_ephemeral_quorum(&ops_kp.public, now) {
        QuorumResult::Agree(Some(eph)) => {
            assert_eq!(
                eph.expires_at, expires_b,
                "the ephemeral with the latest expires_at must be returned"
            );
        }
        QuorumResult::Agree(None) => panic!("must return Some — both providers have valid ephemerals"),
        _ => panic!("expected Agree(Some(_))"),
    }
}

// ── §6. Soft-state: absence does not override presence ───────────────────────

#[test]
fn quorum_soft_state_absent_does_not_override_present() {
    let now = now_secs();
    let ledger_a = SubstrateLedger::new();
    let ledger_b = SubstrateLedger::new(); // no ephemeral published

    let (root_kp, ops_kp) = register(&ledger_a);
    register_same_identity(&ledger_b, &root_kp, &ops_kp);

    let expires_a = now + 300;
    publish_ephemeral(&ledger_a, &ops_kp, expires_a);

    let mut q = ProviderQuorum::new();
    q.add(provider_id(0x0a), ledger_a);
    q.add(provider_id(0x0b), ledger_b); // returns None

    match q.get_handshake_ephemeral_quorum(&ops_kp.public, now) {
        QuorumResult::Agree(Some(eph)) => {
            assert_eq!(
                eph.expires_at, expires_a,
                "provider B returning None must not suppress provider A's valid ephemeral"
            );
        }
        QuorumResult::Agree(None) => {
            panic!("None from one provider must not override Some from another")
        }
        _ => panic!("expected Agree(Some(_))"),
    }
}

// ── §7. Consensus-relevant: all agree ────────────────────────────────────────

#[test]
fn quorum_commitment_all_agree() {
    let now = now_secs();
    let ledger_a = SubstrateLedger::new();
    let ledger_b = SubstrateLedger::new();

    let (root_kp, ops_kp) = register(&ledger_a);
    register_same_identity(&ledger_b, &root_kp, &ops_kp);

    // Publish the SAME ephemeral (same pub_key bytes + expires_at) to both ledgers.
    // Ed25519 is deterministic: same key + same message → same signature bytes.
    // RecipientState::commitment() hashes pub_key + expires_at (not sig), so the
    // commitment is byte-identical on both ledgers.
    let (_, shared_eph_pub) = x25519_generate_keypair();
    let shared_expires = now + 500;
    publish_ephemeral_explicit(&ledger_a, &ops_kp, shared_eph_pub, shared_expires);
    publish_ephemeral_explicit(&ledger_b, &ops_kp, shared_eph_pub, shared_expires);

    let mut q = ProviderQuorum::new();
    q.add(provider_id(0x0a), ledger_a);
    q.add(provider_id(0x0b), ledger_b);

    match q.get_commitment_quorum(&ops_kp.public) {
        QuorumResult::Agree(commitment) => {
            assert_ne!(commitment, [0u8; 32], "commitment must be non-zero");
        }
        QuorumResult::Equivocation(_) => {
            panic!("identical state on both providers must not produce Equivocation")
        }
        QuorumResult::Unavailable => {
            panic!("non-revoked providers with valid state must not produce Unavailable")
        }
    }
}

// ── §8. Consensus-relevant: equivocation detected ────────────────────────────

#[test]
fn quorum_commitment_equivocation_detected() {
    let now = now_secs();
    let ledger_a = SubstrateLedger::new();
    let ledger_b = SubstrateLedger::new();

    let (root_kp, ops_kp) = register(&ledger_a);
    register_same_identity(&ledger_b, &root_kp, &ops_kp);

    // Different ephemerals (different pub_key, different expires_at) → different
    // RecipientState::commitment() on each provider → Equivocation.
    publish_ephemeral(&ledger_a, &ops_kp, now + 100);
    publish_ephemeral(&ledger_b, &ops_kp, now + 200);

    let mut q = ProviderQuorum::new();
    q.add(provider_id(0x0a), ledger_a);
    q.add(provider_id(0x0b), ledger_b);

    match q.get_commitment_quorum(&ops_kp.public) {
        QuorumResult::Equivocation(evidence) => {
            assert_ne!(
                evidence.commitment_a, evidence.commitment_b,
                "equivocation evidence must contain distinct commitments"
            );
            assert_ne!(evidence.commitment_a, [0u8; 32]);
            assert_ne!(evidence.commitment_b, [0u8; 32]);
        }
        QuorumResult::Agree(_) => {
            panic!("different ephemerals must produce Equivocation, not Agree")
        }
        QuorumResult::Unavailable => {
            panic!("non-revoked providers must not produce Unavailable")
        }
    }
}

// ── §9. Equivocation evidence contains correct provider IDs ──────────────────

#[test]
fn quorum_equivocation_evidence_contains_provider_ids() {
    let now = now_secs();
    let ledger_a = SubstrateLedger::new();
    let ledger_b = SubstrateLedger::new();

    let (root_kp, ops_kp) = register(&ledger_a);
    register_same_identity(&ledger_b, &root_kp, &ops_kp);

    publish_ephemeral(&ledger_a, &ops_kp, now + 100);
    publish_ephemeral(&ledger_b, &ops_kp, now + 200);

    let id_a = provider_id(0xAA);
    let id_b = provider_id(0xBB);

    let mut q = ProviderQuorum::new();
    q.add(id_a, ledger_a);
    q.add(id_b, ledger_b);

    match q.get_commitment_quorum(&ops_kp.public) {
        QuorumResult::Equivocation(evidence) => {
            // The evidence must carry the IDs assigned at construction time.
            assert!(
                evidence.provider_a_id == id_a || evidence.provider_a_id == id_b,
                "provider_a_id must match a constructed provider ID"
            );
            assert!(
                evidence.provider_b_id == id_a || evidence.provider_b_id == id_b,
                "provider_b_id must match a constructed provider ID"
            );
            assert_ne!(
                evidence.provider_a_id, evidence.provider_b_id,
                "the two provider IDs in evidence must be distinct"
            );
            assert_eq!(
                evidence.ops_pub, ops_kp.public,
                "evidence ops_pub must match the queried operational key"
            );
        }
        _ => panic!("expected Equivocation from providers with different state"),
    }
}

// ── §10. ProviderQuorum implements StateProvider — drop-in ───────────────────

#[tokio::test]
async fn quorum_implements_state_provider_in_retrieve_state() {
    let now = now_secs();
    let ledger = SubstrateLedger::new();
    let (_, ops_kp) = register(&ledger);
    publish_ephemeral(&ledger, &ops_kp, now + 3600);

    let mut q: ProviderQuorum<SubstrateLedger> = ProviderQuorum::new();
    q.add(provider_id(0x01), ledger);

    // ProviderQuorum<SubstrateLedger> must be accepted anywhere a StateProvider is
    // expected — this is the federation drop-in contract.
    let state = FlashSession::retrieve_state(&q, &ops_kp.public)
        .await
        .expect("ProviderQuorum must be a valid StateProvider for FlashSession::retrieve_state");

    assert_eq!(state.ops_pub, ops_kp.public);
    assert!(
        state.handshake_ephemeral.is_some(),
        "quorum must surface the published ephemeral through the StateProvider interface"
    );
}
