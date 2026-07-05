// Phase 0 cryptographic core tests.
// Phase 2 transport tests: RouteId, WarmCache, FlashSession lifecycle.

use rand_core::OsRng;
use scp_cryptography::algorithms::{negotiate, AlgorithmSuite};
use scp_cryptography::keys::{hash, KeyPair, PublicKey, SessionKey};
use scp_identity::genesis::IdentityGenesis;
use scp_identity::rotation::RotationEvent;
use x25519_dalek::StaticSecret;

// --- KeyPair: sign / verify ---

#[test]
fn keypair_sign_verify_roundtrip() {
    let kp = KeyPair::generate();
    let msg = b"sovereign communication protocol";
    let sig = kp.sign(msg);

    let pk = PublicKey(kp.public);
    assert!(pk.verify(msg, &sig), "valid signature must verify");

    let mut bad_msg = *msg;
    bad_msg[0] ^= 0xff;
    assert!(
        !pk.verify(&bad_msg, &sig),
        "tampered message must not verify"
    );
}

#[test]
fn wrong_pubkey_does_not_verify() {
    let kp1 = KeyPair::generate();
    let kp2 = KeyPair::generate();
    let sig = kp1.sign(b"test");
    assert!(!PublicKey(kp2.public).verify(b"test", &sig));
}

// --- SessionKey: encrypt / decrypt ---

#[test]
fn session_key_encrypt_decrypt_roundtrip() {
    let key_bytes = hash(b"test-session-key");
    let sk = SessionKey(key_bytes);

    let plaintext = b"flash burst payload: sovereign, ephemeral, encrypted";
    let (ct, nonce) = sk.encrypt(plaintext);

    assert_ne!(
        ct.as_slice(),
        plaintext.as_slice(),
        "ciphertext must differ from plaintext"
    );

    let recovered = sk.decrypt(&ct, &nonce).expect("decryption must succeed");
    assert_eq!(recovered, plaintext);
}

#[test]
fn decrypt_with_wrong_key_fails() {
    let sk1 = SessionKey(hash(b"key-one"));
    let sk2 = SessionKey(hash(b"key-two"));
    let (ct, nonce) = sk1.encrypt(b"secret");
    assert!(
        sk2.decrypt(&ct, &nonce).is_err(),
        "wrong key must not decrypt"
    );
}

#[test]
fn decrypt_with_tampered_ciphertext_fails() {
    let sk = SessionKey(hash(b"key"));
    let (mut ct, nonce) = sk.encrypt(b"data");
    ct[0] ^= 0xff;
    assert!(sk.decrypt(&ct, &nonce).is_err());
}

// --- X25519 ECDH: symmetric shared secret ---

#[test]
fn x25519_ecdh_symmetric() {
    // Alice generates X25519 secret; Bob generates X25519 secret.
    let alice_secret: [u8; 32] = StaticSecret::random_from_rng(OsRng).to_bytes();
    let bob_secret: [u8; 32] = StaticSecret::random_from_rng(OsRng).to_bytes();

    let alice_pub: [u8; 32] =
        x25519_dalek::PublicKey::from(&StaticSecret::from(alice_secret)).to_bytes();
    let bob_pub: [u8; 32] =
        x25519_dalek::PublicKey::from(&StaticSecret::from(bob_secret)).to_bytes();

    let alice_key = SessionKey::derive_x25519(&alice_secret, &bob_pub);
    let bob_key = SessionKey::derive_x25519(&bob_secret, &alice_pub);

    assert_eq!(
        alice_key.0, bob_key.0,
        "ECDH must produce the same shared key on both sides"
    );
}

// --- BLAKE3 hash ---

#[test]
fn hash_deterministic() {
    let h1 = hash(b"scp");
    let h2 = hash(b"scp");
    let h3 = hash(b"SCP");
    assert_eq!(h1, h2, "same input must produce same digest");
    assert_ne!(h1, h3, "different input must produce different digest");
}

#[test]
fn hash_non_zero_output() {
    let h = hash(b"test");
    assert_ne!(h, [0u8; 32]);
}

// --- Algorithm negotiation ---

#[test]
fn negotiate_upgrades_when_both_support_pq() {
    assert_eq!(
        negotiate(&AlgorithmSuite::PqMigration, &AlgorithmSuite::PqMigration),
        AlgorithmSuite::PqMigration
    );
}

#[test]
fn negotiate_falls_back_to_current() {
    assert_eq!(
        negotiate(&AlgorithmSuite::Current, &AlgorithmSuite::PqMigration),
        AlgorithmSuite::Current
    );
    assert_eq!(
        negotiate(&AlgorithmSuite::Current, &AlgorithmSuite::Current),
        AlgorithmSuite::Current
    );
}

// --- IdentityGenesis ---

#[test]
fn genesis_artifacts_complete() {
    let a = IdentityGenesis::execute().expect("genesis must succeed");

    assert_ne!(a.k_root_pub, [0u8; 32], "root public key must be non-zero");
    assert_ne!(
        a.k_root_priv, [0u8; 32],
        "root private key must be non-zero"
    );
    assert_ne!(a.k_ops_pub, [0u8; 32], "ops public key must be non-zero");
    assert_ne!(a.k_ops_priv, [0u8; 32], "ops private key must be non-zero");
    assert_ne!(a.recovery_policy_hash, [0u8; 32]);
    assert_ne!(a.continuity_commitment, [0u8; 32]);
    assert_ne!(a.k_root_pub, a.k_ops_pub, "root and ops keys must differ");
}

#[test]
fn genesis_produces_unique_keys_each_time() {
    let a = IdentityGenesis::execute().unwrap();
    let b = IdentityGenesis::execute().unwrap();
    assert_ne!(a.k_root_pub, b.k_root_pub);
    assert_ne!(a.k_ops_pub, b.k_ops_pub);
}

// --- RotationEvent ---

#[test]
fn rotation_sign_verify_roundtrip() {
    let root_kp = KeyPair::generate();
    let old_ops = KeyPair::generate();
    let new_ops = KeyPair::generate();

    let event = RotationEvent::sign(old_ops.public, new_ops.public, &root_kp)
        .expect("rotation sign must succeed");

    assert!(
        event.verify(&root_kp.public),
        "rotation must verify with root pub"
    );
}

#[test]
fn rotation_verify_fails_with_wrong_root_key() {
    let root_kp = KeyPair::generate();
    let wrong_kp = KeyPair::generate();
    let old_ops = KeyPair::generate();
    let new_ops = KeyPair::generate();

    let event = RotationEvent::sign(old_ops.public, new_ops.public, &root_kp).unwrap();
    assert!(!event.verify(&wrong_kp.public));
}

#[test]
fn rotation_verify_fails_on_tampered_nonce() {
    let root_kp = KeyPair::generate();
    let old_ops = KeyPair::generate();
    let new_ops = KeyPair::generate();

    let mut event = RotationEvent::sign(old_ops.public, new_ops.public, &root_kp).unwrap();
    event.nonce ^= 1; // flip one bit
    assert!(
        !event.verify(&root_kp.public),
        "tampered nonce must not verify"
    );
}

// --- FreshnessNonce ---

#[test]
fn freshness_nonce_unique() {
    use scp_transport::session::FreshnessNonce;
    use std::collections::HashSet;

    let nonces: HashSet<u64> = (0..100).map(|_| FreshnessNonce::generate().0).collect();
    assert_eq!(nonces.len(), 100, "all 100 nonces must be distinct");
}

// ── Phase 2: RouteId ────────────────────────────────────────────────────────

#[test]
fn route_id_generate_is_unique() {
    use scp_transport::session::RouteId;
    use std::collections::HashSet;

    let ids: HashSet<[u8; 16]> = (0..100).map(|_| RouteId::generate().0).collect();
    assert_eq!(ids.len(), 100, "all 100 route IDs must be distinct");
}

// ── Phase 2: WarmCache ──────────────────────────────────────────────────────

#[test]
fn warm_cache_retain_and_retrieve() {
    use scp_relay_cache::WarmCache;
    use std::time::Duration;

    let cache = WarmCache::new(Duration::from_secs(600));
    let route_id = [1u8; 16];
    let key = [2u8; 32];

    cache.retain(&route_id, &key);
    assert_eq!(
        cache.get(&route_id),
        Some(key),
        "warm entry must be retrievable before expiry"
    );
}

#[test]
fn warm_cache_expired_entry_is_none() {
    use scp_relay_cache::WarmCache;
    use std::time::Duration;

    let cache = WarmCache::new(Duration::ZERO);
    let route_id = [3u8; 16];
    let key = [4u8; 32];

    cache.retain(&route_id, &key);
    // Duration::ZERO means expires == Instant::now() at insert time;
    // any subsequent get sees Instant::now() >= expires → evicted.
    assert_eq!(
        cache.get(&route_id),
        None,
        "zero-TTL entry must be immediately expired"
    );
}

#[test]
fn warm_cache_purge_clears_all() {
    use scp_relay_cache::WarmCache;
    use std::time::Duration;

    let cache = WarmCache::new(Duration::from_secs(600));
    for i in 0u8..5 {
        cache.retain(&[i; 16], &[i; 32]);
    }
    cache.purge();
    for i in 0u8..5 {
        assert_eq!(
            cache.get(&[i; 16]),
            None,
            "all entries must be gone after purge"
        );
    }
}

// ── Phase 2: FlashSession lifecycle ────────────────────────────────────────

#[tokio::test]
async fn flash_session_full_lifecycle() {
    use scp_relay_cache::WarmCache;
    use scp_relay_perturbation::PerturbationEngine;
    use scp_transport::flash::{FlashSession, FlashSessionLifecycle};
    use scp_transport::StubStateProvider;
    use std::time::Duration;

    let cache = WarmCache::new(Duration::from_secs(600));
    let engine = PerturbationEngine::passthrough();
    let recipient_pub = [7u8; 32];

    // Step 1: retrieve state.
    let state = FlashSession::retrieve_state(&StubStateProvider, &recipient_pub)
        .await
        .expect("retrieve_state must succeed");
    assert!(state.vitality.is_open(), "simulated recipient must be open");

    // Steps 2–4: open session and transmit.
    let session = FlashSession::open_and_send(state, b"sovereign payload", &cache, &engine)
        .await
        .expect("open_and_send must succeed");

    // Capture fields before consuming session in dissolve.
    let route_id = session.route.0;
    let key_bytes = session.session_key.0;
    assert!(
        matches!(session.lifecycle, FlashSessionLifecycle::WarmCache { .. }),
        "lifecycle must be WarmCache after open_and_send"
    );

    // Verify warm cache was populated.
    let cached = cache.get(&route_id);
    assert!(
        cached.is_some(),
        "session key must be in warm cache after open_and_send"
    );
    assert_eq!(
        cached.unwrap(),
        key_bytes,
        "cached key must match session key"
    );

    // Step 5: dissolve (consumes session; SessionKey zeroized on drop).
    let proof = session.dissolve();
    assert_eq!(
        proof.route.0, route_id,
        "dissolved proof must carry the session's route ID"
    );
}

#[tokio::test]
async fn flash_session_rejects_closed_vitality() {
    use scp_relay_cache::WarmCache;
    use scp_relay_perturbation::PerturbationEngine;
    use scp_transport::flash::{FlashSession, RecipientState, TransportError};
    use scp_vitality::VitalityState;
    use std::time::Duration;

    let cache = WarmCache::new(Duration::from_secs(600));
    let engine = PerturbationEngine::passthrough();

    for vitality in [
        VitalityState::Suspended,
        VitalityState::Severed,
        VitalityState::Burned,
    ] {
        let state = RecipientState {
            ops_pub: [1u8; 32],
            vitality,
            routing_hints: vec![],
            handshake_ephemeral: None,
        };
        let result = FlashSession::open_and_send(state, b"blocked payload", &cache, &engine).await;
        assert!(
            matches!(result, Err(TransportError::VitalityInsufficient(_))),
            "closed vitality state must reject transmission — transport must obey consent state"
        );
    }
}

// ── Phase 3: protocol domains ───────────────────────────────────────────────

#[test]
fn domain_constants_are_all_distinct() {
    use scp_cryptography::domains::{
        SCP_DOMAIN_RECOVERY, SCP_DOMAIN_RELAY, SCP_DOMAIN_TRANSPORT, SCP_DOMAIN_TUNNEL,
        SCP_DOMAIN_VITALITY,
    };

    let constants: &[&[u8]] = &[
        SCP_DOMAIN_TRANSPORT,
        SCP_DOMAIN_RELAY,
        SCP_DOMAIN_RECOVERY,
        SCP_DOMAIN_VITALITY,
        SCP_DOMAIN_TUNNEL,
    ];
    for i in 0..constants.len() {
        for j in (i + 1)..constants.len() {
            assert_ne!(
                constants[i], constants[j],
                "domain constants must all be distinct to prevent cross-context reuse"
            );
        }
    }
}

// ── Phase 3: BlindRelay — local and TCP ────────────────────────────────────

#[tokio::test]
async fn blind_relay_local_accepts_opaque_bytes() {
    use scp_relay_mesh::{route_burst, RelayNode};

    let relay = RelayNode {
        id: [0u8; 16],
        endpoint: "local://loopback".to_string(),
    };
    let result = route_burst(
        b"opaque burst - relay must not inspect this".to_vec(),
        vec![relay],
    )
    .await;
    assert!(
        result.is_ok(),
        "local blind relay must accept any opaque payload"
    );
}

#[tokio::test]
async fn tcp_relay_burst_delivers_and_disconnects() {
    use scp_relay_mesh::{route_burst, spawn_relay_listener, RelayNode};

    let addr = spawn_relay_listener()
        .await
        .expect("relay listener must bind");
    let relay = RelayNode {
        id: [1u8; 16],
        endpoint: addr.to_string(),
    };

    let result = route_burst(b"sovereign burst payload".to_vec(), vec![relay]).await;
    assert!(
        result.is_ok(),
        "real TCP relay must accept and ACK the burst"
    );
}

// ── Phase 3: DissolvedProof ─────────────────────────────────────────────────

#[tokio::test]
async fn dissolved_proof_captures_route_id() {
    use scp_relay_cache::WarmCache;
    use scp_relay_perturbation::PerturbationEngine;
    use scp_transport::flash::FlashSession;
    use scp_transport::StubStateProvider;
    use std::time::Duration;

    let cache = WarmCache::new(Duration::from_secs(600));
    let engine = PerturbationEngine::passthrough();
    let state = FlashSession::retrieve_state(&StubStateProvider, &[9u8; 32])
        .await
        .unwrap();
    let session = FlashSession::open_and_send(state, b"payload", &cache, &engine)
        .await
        .unwrap();

    let expected_route = session.route.0;
    let proof = session.dissolve();

    assert_eq!(
        proof.route.0, expected_route,
        "DissolvedProof must carry the exact RouteId of the dissolved session"
    );
}

#[tokio::test]
async fn dissolved_proof_route_differs_across_sessions() {
    use scp_relay_cache::WarmCache;
    use scp_relay_perturbation::PerturbationEngine;
    use scp_transport::flash::FlashSession;
    use scp_transport::StubStateProvider;
    use std::time::Duration;

    let cache = WarmCache::new(Duration::from_secs(600));
    let engine = PerturbationEngine::passthrough();

    let s1 = FlashSession::open_and_send(
        FlashSession::retrieve_state(&StubStateProvider, &[1u8; 32])
            .await
            .unwrap(),
        b"first",
        &cache,
        &engine,
    )
    .await
    .unwrap();
    let s2 = FlashSession::open_and_send(
        FlashSession::retrieve_state(&StubStateProvider, &[2u8; 32])
            .await
            .unwrap(),
        b"second",
        &cache,
        &engine,
    )
    .await
    .unwrap();

    let p1 = s1.dissolve();
    let p2 = s2.dissolve();

    assert_ne!(
        p1.route.0, p2.route.0,
        "each dissolved session must have a distinct route ID — routes must never be reused"
    );
}

// ── Phase 4: FlashTranscript ────────────────────────────────────────────────

#[test]
fn transcript_hash_is_route_bound() {
    use scp_transport::session::{FreshnessNonce, RouteId};
    use scp_transport::transcript::FlashTranscript;
    use scp_vitality::VitalityState;

    let base = FlashTranscript {
        route_id: RouteId([0x01; 16]),
        nonce: FreshnessNonce(0xdeadbeef),
        recipient_ops_pub: [0xaa; 32],
        vitality_snapshot: VitalityState::Active,
        protocol_version: 1,
    };
    let different_route = FlashTranscript {
        route_id: RouteId([0x02; 16]),
        ..FlashTranscript {
            route_id: RouteId([0x02; 16]),
            nonce: FreshnessNonce(0xdeadbeef),
            recipient_ops_pub: [0xaa; 32],
            vitality_snapshot: VitalityState::Active,
            protocol_version: 1,
        }
    };
    assert_ne!(
        base.hash(),
        different_route.hash(),
        "transcript hash must differ when route_id differs"
    );
}

#[test]
fn transcript_hash_is_nonce_bound() {
    use scp_transport::session::{FreshnessNonce, RouteId};
    use scp_transport::transcript::FlashTranscript;
    use scp_vitality::VitalityState;

    let t1 = FlashTranscript {
        route_id: RouteId([0x01; 16]),
        nonce: FreshnessNonce(1000),
        recipient_ops_pub: [0xbb; 32],
        vitality_snapshot: VitalityState::Active,
        protocol_version: 1,
    };
    let t2 = FlashTranscript {
        route_id: RouteId([0x01; 16]),
        nonce: FreshnessNonce(1001), // differs by one
        recipient_ops_pub: [0xbb; 32],
        vitality_snapshot: VitalityState::Active,
        protocol_version: 1,
    };
    assert_ne!(
        t1.hash(),
        t2.hash(),
        "transcript hash must differ when nonce differs"
    );
}

#[test]
fn transcript_serialization_is_stable() {
    use scp_transport::session::{FreshnessNonce, RouteId};
    use scp_transport::transcript::FlashTranscript;
    use scp_vitality::VitalityState;

    // Identical construction must always produce identical hashes — field order,
    // byte encoding, and domain must never drift silently.
    let t1 = FlashTranscript {
        route_id: RouteId([0x42; 16]),
        nonce: FreshnessNonce(0xdeadbeefcafe1234),
        recipient_ops_pub: [0xab; 32],
        vitality_snapshot: VitalityState::Active,
        protocol_version: 1,
    };
    let t2 = FlashTranscript {
        route_id: RouteId([0x42; 16]),
        nonce: FreshnessNonce(0xdeadbeefcafe1234),
        recipient_ops_pub: [0xab; 32],
        vitality_snapshot: VitalityState::Active,
        protocol_version: 1,
    };
    assert_eq!(
        t1.hash(),
        t2.hash(),
        "identical transcripts must always produce identical hashes"
    );
    assert_ne!(t1.hash(), [0u8; 32], "transcript hash must be non-zero");
}

#[test]
fn session_key_is_transcript_bound() {
    use rand_core::{OsRng, RngCore};
    use scp_cryptography::{scp_derive_key, DomainLabel};
    use scp_transport::session::{FreshnessNonce, RouteId};
    use scp_transport::transcript::{FlashTranscript, TransportKeyMaterial};
    use scp_vitality::VitalityState;

    let mut seed = [0u8; 32];
    OsRng.fill_bytes(&mut seed);
    let ops_pub = [0x55u8; 32];

    let make_key = |nonce: u64| {
        let t = FlashTranscript {
            route_id: RouteId([0xf0; 16]),
            nonce: FreshnessNonce(nonce),
            recipient_ops_pub: ops_pub,
            vitality_snapshot: VitalityState::Warm,
            protocol_version: 1,
        };
        let km = TransportKeyMaterial {
            ephemeral_seed: seed,
            transcript_hash: t.hash(),
            recipient_binding: ops_pub,
        };
        scp_derive_key(DomainLabel::Transport, &km.as_bytes())
    };

    let key_a = make_key(100);
    let key_b = make_key(101);

    assert_ne!(
        key_a, key_b,
        "different nonces must produce different session keys"
    );
}

// ── Phase 4: Noise relay ────────────────────────────────────────────────────

#[tokio::test]
async fn noise_relay_burst_delivers_and_disconnects() {
    use scp_relay_mesh::{route_burst, spawn_noise_relay_listener, RelayNode};

    let (addr, _relay_pub) = spawn_noise_relay_listener()
        .await
        .expect("noise relay must bind");
    let relay = RelayNode {
        id: [2u8; 16],
        endpoint: format!("noise://{}", addr),
    };

    let result = route_burst(b"noise-encrypted sovereign burst".to_vec(), vec![relay]).await;
    assert!(
        result.is_ok(),
        "Noise-encrypted relay must accept, decrypt, and ACK the burst"
    );
}

#[tokio::test]
async fn noise_relay_fresh_identity_per_listener() {
    use scp_relay_mesh::spawn_noise_relay_listener;

    let (_addr1, pub1) = spawn_noise_relay_listener()
        .await
        .expect("first relay must bind");
    let (_addr2, pub2) = spawn_noise_relay_listener()
        .await
        .expect("second relay must bind");

    assert_ne!(
        pub1, pub2,
        "each relay listener must have a distinct Noise static key — no persistent transport identity"
    );
}

// ── Phase 5: ReplayWindow ───────────────────────────────────────────────────

#[test]
fn replay_window_accepts_fresh_nonce() {
    use scp_transport::ReplayWindow;

    let mut w = ReplayWindow::new();
    assert!(w.check_and_insert(42), "first nonce must be accepted");
    assert!(
        w.check_and_insert(99),
        "second distinct nonce must be accepted"
    );
    // Window is [36, 99]; nonce 80 is within range and novel.
    assert!(
        w.check_and_insert(80),
        "novel nonce within 64-slot window must be accepted"
    );
}

#[test]
fn replay_window_rejects_duplicate() {
    use scp_transport::ReplayWindow;

    let mut w = ReplayWindow::new();
    assert!(w.check_and_insert(100));
    assert!(
        !w.check_and_insert(100),
        "duplicate nonce must be rejected as replay"
    );
}

#[test]
fn replay_window_rejects_stale() {
    use scp_transport::ReplayWindow;

    let mut w = ReplayWindow::new();
    // Advance window well past nonce 1 so it becomes stale.
    assert!(w.check_and_insert(1));
    assert!(w.check_and_insert(100)); // advances window by 99
    assert!(
        !w.check_and_insert(1),
        "nonce older than 64 positions must be rejected as stale"
    );
}

#[test]
fn replay_window_handles_out_of_order_within_window() {
    use scp_transport::ReplayWindow;

    let mut w = ReplayWindow::new();
    // Accept nonces out of order within the 64-slot window.
    assert!(w.check_and_insert(50));
    assert!(w.check_and_insert(10)); // below max_seen but within window [0, 50]
    assert!(w.check_and_insert(63)); // advances window to [0, 63]
    assert!(
        !w.check_and_insert(10),
        "nonce seen before window advanced must be rejected"
    );
    assert!(w.check_and_insert(11)); // novel, still in window
    assert!(w.check_and_insert(49)); // novel, still in window
    assert!(
        !w.check_and_insert(50),
        "nonce 50 was the first accepted — must be rejected as replay"
    );
}

#[test]
fn replay_window_full_advance_clears_history() {
    use scp_transport::ReplayWindow;

    let mut w = ReplayWindow::new();
    assert!(w.check_and_insert(0));
    // Advance by exactly 64 — old history is cleared.
    assert!(w.check_and_insert(64));
    // Nonce 0 is now outside the window; it's stale, not a replay detection.
    assert!(
        !w.check_and_insert(0),
        "stale nonce after full window advance must be rejected"
    );
}

// ── Phase 5: PerturbationEngine ────────────────────────────────────────────

#[test]
fn perturbation_normalizes_to_bucket() {
    use scp_relay_perturbation::{PerturbationEngine, MIN_PAYLOAD_BUCKET};
    use std::time::Duration;

    let engine = PerturbationEngine::new(Duration::ZERO);

    // Empty payload → one full bucket.
    let out = engine.normalize_payload(&[]);
    assert_eq!(
        out.len(),
        MIN_PAYLOAD_BUCKET,
        "empty payload must be padded to one bucket"
    );

    // Payload of exactly one bucket → no padding.
    let exact = vec![0xabu8; MIN_PAYLOAD_BUCKET];
    let out = engine.normalize_payload(&exact);
    assert_eq!(
        out.len(),
        MIN_PAYLOAD_BUCKET,
        "exact-bucket payload must not be padded"
    );

    // One byte over → two buckets.
    let over = vec![0u8; MIN_PAYLOAD_BUCKET + 1];
    let out = engine.normalize_payload(&over);
    assert_eq!(
        out.len(),
        MIN_PAYLOAD_BUCKET * 2,
        "payload just over bucket must reach two buckets"
    );

    // Original content must be preserved at the front.
    let payload = b"sovereign";
    let out = engine.normalize_payload(payload);
    assert_eq!(
        &out[..payload.len()],
        payload,
        "normalization must preserve original content"
    );
    assert!(
        out[payload.len()..].iter().all(|&b| b == 0),
        "padding must be zero bytes"
    );
}

#[test]
fn perturbation_jitter_within_bounds() {
    use scp_relay_perturbation::{PerturbationEngine, MAX_JITTER_MS};
    use std::time::Duration;

    let max = Duration::from_millis(MAX_JITTER_MS);
    let engine = PerturbationEngine::new(max);

    // Sample many times; every result must be ≤ max_jitter.
    for _ in 0..200 {
        let d = engine.jitter_delay();
        assert!(d <= max, "jitter must never exceed MAX_JITTER_MS");
    }
}

#[test]
fn perturbation_passthrough_is_zero_jitter() {
    use scp_relay_perturbation::PerturbationEngine;
    use std::time::Duration;

    let engine = PerturbationEngine::passthrough();
    for _ in 0..20 {
        assert_eq!(
            engine.jitter_delay(),
            Duration::ZERO,
            "passthrough must always return zero delay"
        );
    }
}

// ── Phase 5: BootstrapConfig relay selection ────────────────────────────────

#[tokio::test]
async fn bootstrap_discover_relays_returns_nonempty() {
    use scp_relay_mesh::discover_relays;

    let relays = discover_relays()
        .await
        .expect("discover_relays must succeed");
    assert!(
        !relays.is_empty(),
        "bootstrap must return at least one relay"
    );
}

#[test]
fn bootstrap_shuffled_relays_preserves_count() {
    use scp_relay_mesh::bootstrap::BootstrapConfig;
    use scp_relay_mesh::RelayNode;

    let nodes: Vec<RelayNode> = (0u8..4)
        .map(|i| RelayNode {
            id: [i; 16],
            endpoint: format!("local://node-{}", i),
        })
        .collect();

    let cfg = BootstrapConfig::with_relays(nodes.clone());
    let shuffled = cfg.shuffled_relays();

    assert_eq!(
        shuffled.len(),
        nodes.len(),
        "shuffle must preserve relay count"
    );

    // All original ids must be present (order may differ).
    let mut orig_ids: Vec<[u8; 16]> = nodes.iter().map(|n| n.id).collect();
    let mut shuf_ids: Vec<[u8; 16]> = shuffled.iter().map(|n| n.id).collect();
    orig_ids.sort();
    shuf_ids.sort();
    assert_eq!(
        orig_ids, shuf_ids,
        "shuffle must not lose or duplicate relays"
    );
}

// ── Phase 6: raw X25519 DH ──────────────────────────────────────────────────

#[test]
fn x25519_raw_dh_is_symmetric() {
    use scp_cryptography::{x25519_dh, x25519_generate_keypair};

    let (alice_secret, alice_pub) = x25519_generate_keypair();
    let (bob_secret, bob_pub) = x25519_generate_keypair();

    let alice_shared = x25519_dh(&alice_secret, &bob_pub);
    let bob_shared = x25519_dh(&bob_secret, &alice_pub);

    assert_eq!(
        alice_shared, bob_shared,
        "raw DH must produce the same shared secret on both sides"
    );
    assert_ne!(alice_shared, [0u8; 32], "shared secret must be non-zero");
}

#[test]
fn x25519_raw_dh_differs_from_blake3_wrapped() {
    use scp_cryptography::keys::SessionKey;
    use scp_cryptography::{x25519_dh, x25519_generate_keypair};

    let (alice_secret, _) = x25519_generate_keypair();
    let (_, bob_pub) = x25519_generate_keypair();

    let raw = x25519_dh(&alice_secret, &bob_pub);
    let wrapped = SessionKey::derive_x25519(&alice_secret, &bob_pub).0;

    assert_ne!(
        raw, wrapped,
        "raw DH and BLAKE3-wrapped DH must produce different outputs"
    );
}

// ── Phase 6: FlashTranscriptV2 ──────────────────────────────────────────────

#[test]
fn transcript_v2_binds_sender_ephemeral_pub() {
    use scp_transport::session::{FreshnessNonce, RouteId};
    use scp_transport::transcript::v2::FlashTranscriptV2;
    use scp_vitality::VitalityState;

    let base = FlashTranscriptV2 {
        route_id: RouteId([0x10; 16]),
        nonce: FreshnessNonce(0xaaaa_bbbb_cccc_dddd),
        recipient_ops_pub: [0x33; 32],
        vitality_snapshot: VitalityState::Active,
        protocol_version: 2,
        sender_ephemeral_pub: [0x44; 32],
    };
    let different_sender = FlashTranscriptV2 {
        sender_ephemeral_pub: [0x55; 32],
        ..FlashTranscriptV2 {
            route_id: RouteId([0x10; 16]),
            nonce: FreshnessNonce(0xaaaa_bbbb_cccc_dddd),
            recipient_ops_pub: [0x33; 32],
            vitality_snapshot: VitalityState::Active,
            protocol_version: 2,
            sender_ephemeral_pub: [0x44; 32],
        }
    };

    assert_ne!(
        base.hash(),
        different_sender.hash(),
        "different sender ephemeral pubs must produce different v2 transcript hashes"
    );
}

#[test]
fn transcript_v1_and_v2_diverge_for_same_base_fields() {
    use scp_transport::session::{FreshnessNonce, RouteId};
    use scp_transport::transcript::v1::FlashTranscript;
    use scp_transport::transcript::v2::FlashTranscriptV2;
    use scp_vitality::VitalityState;

    let t1 = FlashTranscript {
        route_id: RouteId([0xf0; 16]),
        nonce: FreshnessNonce(42),
        recipient_ops_pub: [0x77; 32],
        vitality_snapshot: VitalityState::Warm,
        protocol_version: 1,
    };
    let t2 = FlashTranscriptV2 {
        route_id: RouteId([0xf0; 16]),
        nonce: FreshnessNonce(42),
        recipient_ops_pub: [0x77; 32],
        vitality_snapshot: VitalityState::Warm,
        protocol_version: 1,
        sender_ephemeral_pub: [0u8; 32],
    };

    assert_ne!(
        t1.hash(), t2.hash(),
        "v1 and v2 transcripts with the same base fields must hash differently (format bytes differ)"
    );
}

// ── Phase 6: HandshakeEphemeral in ledger ───────────────────────────────────

fn make_handshake_ephemeral_for_test(
    ops_kp: &scp_cryptography::keys::KeyPair,
    expires_at: u64,
) -> (scp_ledger_substrate::HandshakeEphemeral, [u8; 32]) {
    use scp_cryptography::x25519_generate_keypair;
    use scp_ledger_substrate::handshake_sig_message;

    let (_, eph_pub) = x25519_generate_keypair();
    let msg = handshake_sig_message(&eph_pub, expires_at);
    let sig = ops_kp.sign(&msg);

    let eph = scp_ledger_substrate::HandshakeEphemeral {
        pub_key: eph_pub,
        sig: sig.to_vec(),
        published_at: 1_000_000,
        expires_at,
    };
    (eph, eph_pub)
}

#[test]
fn ledger_publish_and_retrieve_handshake_ephemeral() {
    use scp_cryptography::keys::KeyPair;
    use scp_ledger_substrate::SubstrateLedger;

    let ops_kp = KeyPair::generate();
    let ledger = SubstrateLedger::new();
    let expires = 2_000_000u64;

    let (eph, eph_pub) = make_handshake_ephemeral_for_test(&ops_kp, expires);
    ledger
        .publish_handshake_ephemeral(&ops_kp.public, eph)
        .expect("valid ephemeral must be accepted");

    let retrieved = ledger.get_handshake_ephemeral(&ops_kp.public, 1_500_000);
    assert!(
        retrieved.is_some(),
        "non-expired ephemeral must be retrievable"
    );
    assert_eq!(
        retrieved.unwrap().pub_key,
        eph_pub,
        "retrieved pub_key must match published"
    );
}

#[test]
fn ledger_expired_ephemeral_not_returned() {
    use scp_cryptography::keys::KeyPair;
    use scp_ledger_substrate::SubstrateLedger;

    let ops_kp = KeyPair::generate();
    let ledger = SubstrateLedger::new();
    let expires = 1_000_100u64; // expires just after published_at

    let (eph, _) = make_handshake_ephemeral_for_test(&ops_kp, expires);
    ledger
        .publish_handshake_ephemeral(&ops_kp.public, eph)
        .expect("publish must succeed");

    // now = 2_000_000 >> expires_at = 1_000_100 → expired
    let retrieved = ledger.get_handshake_ephemeral(&ops_kp.public, 2_000_000);
    assert!(
        retrieved.is_none(),
        "expired ephemeral must not be returned"
    );
}

#[test]
fn ledger_rejects_invalid_handshake_sig() {
    use scp_cryptography::keys::KeyPair;
    use scp_cryptography::x25519_generate_keypair;
    use scp_ledger_substrate::{HandshakeEphemeral, SubstrateLedger};

    let ops_kp = KeyPair::generate();
    let ledger = SubstrateLedger::new();
    let (_, eph_pub) = x25519_generate_keypair();

    let bad_eph = HandshakeEphemeral {
        pub_key: eph_pub,
        sig: vec![0u8; 64], // all-zero sig — invalid
        published_at: 1_000_000,
        expires_at: 2_000_000,
    };
    let result = ledger.publish_handshake_ephemeral(&ops_kp.public, bad_eph);
    assert!(
        result.is_err(),
        "invalid signature must be rejected by the ledger"
    );
}

// ── Phase 6: bilateral DH flash session ────────────────────────────────────

#[tokio::test]
async fn flash_session_dh_path_succeeds() {
    use scp_cryptography::keys::KeyPair;
    use scp_cryptography::x25519_generate_keypair;
    use scp_ledger_substrate::handshake_sig_message;
    use scp_relay_cache::WarmCache;
    use scp_relay_perturbation::PerturbationEngine;
    use scp_transport::flash::{FlashSession, PublishedHandshakeKey, RecipientState};
    use scp_vitality::VitalityState;
    use std::time::Duration;

    let ops_kp = KeyPair::generate();
    let (_, eph_pub) = x25519_generate_keypair();
    let expires_at = 9_999_999_999u64;
    let sig_msg = handshake_sig_message(&eph_pub, expires_at);
    let sig = ops_kp.sign(&sig_msg);

    let state = RecipientState {
        ops_pub: ops_kp.public,
        vitality: VitalityState::Active,
        routing_hints: vec![],
        handshake_ephemeral: Some(PublishedHandshakeKey {
            pub_key: eph_pub,
            sig,
            expires_at,
        }),
    };

    let cache = WarmCache::new(Duration::from_secs(600));
    let engine = PerturbationEngine::passthrough();

    let session = FlashSession::open_and_send(state, b"bilateral forward secrecy", &cache, &engine)
        .await
        .expect("DH-path session must succeed");

    let _ = session.dissolve();
}

#[tokio::test]
async fn flash_session_dh_rejects_bad_sig() {
    use scp_cryptography::x25519_generate_keypair;
    use scp_relay_cache::WarmCache;
    use scp_relay_perturbation::PerturbationEngine;
    use scp_transport::flash::{
        FlashSession, PublishedHandshakeKey, RecipientState, TransportError,
    };
    use scp_vitality::VitalityState;
    use std::time::Duration;

    let (_, eph_pub) = x25519_generate_keypair();

    let state = RecipientState {
        ops_pub: [0xffu8; 32], // ops key that did NOT sign the ephemeral
        vitality: VitalityState::Active,
        routing_hints: vec![],
        handshake_ephemeral: Some(PublishedHandshakeKey {
            pub_key: eph_pub,
            sig: [0u8; 64], // all-zero — will not verify
            expires_at: 9_999_999_999,
        }),
    };

    let cache = WarmCache::new(Duration::from_secs(600));
    let engine = PerturbationEngine::passthrough();

    let result = FlashSession::open_and_send(state, b"should fail", &cache, &engine).await;
    assert!(
        matches!(result, Err(TransportError::HandshakeKeyInvalid)),
        "invalid handshake sig must produce HandshakeKeyInvalid error"
    );
}

// ── Phase 6: dummy traffic ──────────────────────────────────────────────────

#[tokio::test]
async fn dummy_burst_closed_vitality_emits_nothing() {
    // For Severed/Burned vitality (not open), maybe_emit_dummy must return
    // without attempting any relay connection. We verify by calling it without
    // a running relay — if it tried to connect, it would error internally
    // (but it discards errors). The key invariant is: no panic, no hang.
    use scp_relay_perturbation::PerturbationEngine;
    use scp_vitality::VitalityState;
    use std::time::Duration;

    let engine = PerturbationEngine::new(Duration::ZERO);
    for vitality in [
        VitalityState::Severed,
        VitalityState::Burned,
        VitalityState::Suspended,
    ] {
        // Called 50 times — with closed vitality, should_emit_dummy is always false.
        for _ in 0..50 {
            engine.maybe_emit_dummy(&vitality).await;
        }
    }
}

#[tokio::test]
async fn dummy_burst_active_vitality_completes_without_panic() {
    use scp_relay_mesh::spawn_relay_listener;
    use scp_relay_perturbation::PerturbationEngine;
    use scp_vitality::VitalityState;
    use std::time::Duration;

    // Spin up a local relay so any emitted dummy burst has somewhere to go.
    let _addr = spawn_relay_listener().await.expect("relay must bind");

    let engine = PerturbationEngine::new(Duration::ZERO);
    // 20 calls — probabilistic but must never panic.
    for _ in 0..20 {
        engine.maybe_emit_dummy(&VitalityState::Active).await;
    }
}

// ── Phase 8: State Layer Integration ─────────────────────────────────────────
//
// These tests exercise the full retrieve_state() → open_and_send() path using
// a real SubstrateLedger. They verify that:
//   - An empty ledger produces the v1 (OsRng seed) path
//   - A published ephemeral produces the v2 (bilateral DH) path
//   - A revoked ops key is rejected before any session is opened
//   - An expired ephemeral is filtered by the ledger, falling back to v1

#[tokio::test]
async fn ledger_state_provider_empty_ledger_gives_v1_path() {
    use scp_ledger_substrate::SubstrateLedger;
    use scp_transport::flash::FlashSession;

    let ledger = SubstrateLedger::new();
    let state = FlashSession::retrieve_state(&ledger, &[0x11u8; 32])
        .await
        .expect("empty ledger must not error");
    assert!(
        state.handshake_ephemeral.is_none(),
        "no ephemeral published → retrieve_state falls back to v1 (OsRng seed) path"
    );
    assert!(state.vitality.is_open(), "default vitality must be open");
}

#[tokio::test]
async fn ledger_state_provider_published_ephemeral_gives_v2_path() {
    use scp_cryptography::keys::KeyPair;
    use scp_cryptography::x25519_generate_keypair;
    use scp_ledger_substrate::{HandshakeEphemeral, SubstrateLedger};
    use scp_relay_cache::WarmCache;
    use scp_relay_perturbation::PerturbationEngine;
    use scp_transport::flash::FlashSession;
    use scp_wire_format::signing::handshake_sig_message;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    let ledger = SubstrateLedger::new();
    let ops_kp = KeyPair::generate();
    let (_, eph_pub) = x25519_generate_keypair();
    let expires_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 3600;

    let sig_msg = handshake_sig_message(&eph_pub, expires_at);
    let sig = ops_kp.sign(&sig_msg);

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
        .expect("publish must succeed for non-revoked key");

    let state = FlashSession::retrieve_state(&ledger, &ops_kp.public)
        .await
        .expect("published ephemeral must be retrievable");
    assert!(
        state.handshake_ephemeral.is_some(),
        "published ephemeral must populate state → open_and_send will use v2 DH path"
    );

    let cache = WarmCache::new(Duration::from_secs(600));
    let engine = PerturbationEngine::passthrough();
    let session = FlashSession::open_and_send(state, b"v2-integration", &cache, &engine)
        .await
        .expect("v2 session must open with published ephemeral");
    let _ = session.dissolve();
}

#[tokio::test]
async fn ledger_state_provider_revoked_ops_key_returns_error() {
    use scp_cryptography::keys::KeyPair;
    use scp_ledger_substrate::{LedgerIdentityRecord, SubstrateLedger};
    use scp_transport::flash::{FlashSession, TransportError};
    use scp_wire_format::signing::registration_message;

    let ledger = SubstrateLedger::new();
    let root_kp = KeyPair::generate();
    let ops_kp = KeyPair::generate();

    let record = LedgerIdentityRecord {
        k_root_pub: root_kp.public,
        k_ops_pub: ops_kp.public,
        recovery_policy_hash: [0u8; 32],
        continuity_commitment: [0u8; 32],
    };
    let reg_msg = registration_message(&root_kp.public, &ops_kp.public, &[0u8; 32]);
    let root_sig = root_kp.sign(&reg_msg);
    ledger
        .register_identity(&record, &root_sig)
        .expect("registration must succeed");

    let revoke_sig = root_kp.sign(&ops_kp.public);
    ledger
        .revoke(&ops_kp.public, &revoke_sig)
        .expect("revocation must succeed");

    let result = FlashSession::retrieve_state(&ledger, &ops_kp.public).await;
    assert!(
        matches!(result, Err(TransportError::RecipientRevoked)),
        "revoked ops key must return RecipientRevoked — state layer must not produce \
         a usable RecipientState for a revoked identity"
    );
}

#[tokio::test]
async fn ledger_state_provider_expired_ephemeral_falls_back_to_v1() {
    use scp_cryptography::keys::KeyPair;
    use scp_cryptography::x25519_generate_keypair;
    use scp_ledger_substrate::{HandshakeEphemeral, SubstrateLedger};
    use scp_transport::flash::FlashSession;
    use scp_wire_format::signing::handshake_sig_message;

    let ledger = SubstrateLedger::new();
    let ops_kp = KeyPair::generate();
    let (_, eph_pub) = x25519_generate_keypair();
    let expires_at = 1u64; // 1970-01-01 — expired on any real system

    let sig_msg = handshake_sig_message(&eph_pub, expires_at);
    let sig = ops_kp.sign(&sig_msg);

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
        .expect("ledger accepts publication even for past expiry");

    let state = FlashSession::retrieve_state(&ledger, &ops_kp.public)
        .await
        .expect("expired ephemeral must not error — ledger filters it silently");
    assert!(
        state.handshake_ephemeral.is_none(),
        "expired ephemeral must be filtered by ledger → retrieve_state falls back to v1"
    );
}
