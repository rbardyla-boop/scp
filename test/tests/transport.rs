// Phase 0 cryptographic core tests.
// Phase 2 transport tests: RouteId, WarmCache, FlashSession lifecycle.

use scp_cryptography::keys::{hash, KeyPair, PublicKey, SessionKey};
use scp_cryptography::algorithms::{negotiate, AlgorithmSuite};
use scp_identity::genesis::IdentityGenesis;
use scp_identity::rotation::RotationEvent;
use x25519_dalek::StaticSecret;
use rand_core::OsRng;

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
    assert!(!pk.verify(&bad_msg, &sig), "tampered message must not verify");
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

    assert_ne!(ct.as_slice(), plaintext.as_slice(), "ciphertext must differ from plaintext");

    let recovered = sk.decrypt(&ct, &nonce).expect("decryption must succeed");
    assert_eq!(recovered, plaintext);
}

#[test]
fn decrypt_with_wrong_key_fails() {
    let sk1 = SessionKey(hash(b"key-one"));
    let sk2 = SessionKey(hash(b"key-two"));
    let (ct, nonce) = sk1.encrypt(b"secret");
    assert!(sk2.decrypt(&ct, &nonce).is_err(), "wrong key must not decrypt");
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
    let bob_secret:   [u8; 32] = StaticSecret::random_from_rng(OsRng).to_bytes();

    let alice_pub: [u8; 32] = x25519_dalek::PublicKey::from(&StaticSecret::from(alice_secret)).to_bytes();
    let bob_pub:   [u8; 32] = x25519_dalek::PublicKey::from(&StaticSecret::from(bob_secret)).to_bytes();

    let alice_key = SessionKey::derive_x25519(&alice_secret, &bob_pub);
    let bob_key   = SessionKey::derive_x25519(&bob_secret,   &alice_pub);

    assert_eq!(alice_key.0, bob_key.0, "ECDH must produce the same shared key on both sides");
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

    assert_ne!(a.k_root_pub,  [0u8; 32], "root public key must be non-zero");
    assert_ne!(a.k_root_priv, [0u8; 32], "root private key must be non-zero");
    assert_ne!(a.k_ops_pub,   [0u8; 32], "ops public key must be non-zero");
    assert_ne!(a.k_ops_priv,  [0u8; 32], "ops private key must be non-zero");
    assert_ne!(a.recovery_policy_hash,  [0u8; 32]);
    assert_ne!(a.continuity_commitment, [0u8; 32]);
    assert_ne!(a.k_root_pub, a.k_ops_pub, "root and ops keys must differ");
}

#[test]
fn genesis_produces_unique_keys_each_time() {
    let a = IdentityGenesis::execute().unwrap();
    let b = IdentityGenesis::execute().unwrap();
    assert_ne!(a.k_root_pub, b.k_root_pub);
    assert_ne!(a.k_ops_pub,  b.k_ops_pub);
}

// --- RotationEvent ---

#[test]
fn rotation_sign_verify_roundtrip() {
    let root_kp = KeyPair::generate();
    let old_ops = KeyPair::generate();
    let new_ops = KeyPair::generate();

    let event = RotationEvent::sign(old_ops.public, new_ops.public, &root_kp)
        .expect("rotation sign must succeed");

    assert!(event.verify(&root_kp.public), "rotation must verify with root pub");
}

#[test]
fn rotation_verify_fails_with_wrong_root_key() {
    let root_kp  = KeyPair::generate();
    let wrong_kp = KeyPair::generate();
    let old_ops  = KeyPair::generate();
    let new_ops  = KeyPair::generate();

    let event = RotationEvent::sign(old_ops.public, new_ops.public, &root_kp).unwrap();
    assert!(!event.verify(&wrong_kp.public));
}

#[test]
fn rotation_verify_fails_on_tampered_nonce() {
    let root_kp = KeyPair::generate();
    let old_ops = KeyPair::generate();
    let new_ops = KeyPair::generate();

    let mut event = RotationEvent::sign(old_ops.public, new_ops.public, &root_kp).unwrap();
    event.nonce ^= 1;   // flip one bit
    assert!(!event.verify(&root_kp.public), "tampered nonce must not verify");
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
    assert_eq!(cache.get(&route_id), Some(key), "warm entry must be retrievable before expiry");
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
    assert_eq!(cache.get(&route_id), None, "zero-TTL entry must be immediately expired");
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
        assert_eq!(cache.get(&[i; 16]), None, "all entries must be gone after purge");
    }
}

// ── Phase 2: FlashSession lifecycle ────────────────────────────────────────

#[tokio::test]
async fn flash_session_full_lifecycle() {
    use scp_relay_cache::WarmCache;
    use scp_transport::flash::{FlashSession, FlashSessionLifecycle};
    use std::time::Duration;

    let cache = WarmCache::new(Duration::from_secs(600));
    let recipient_pub = [7u8; 32];

    // Step 1: retrieve state.
    let state = FlashSession::retrieve_state(&recipient_pub)
        .await
        .expect("retrieve_state must succeed");
    assert!(state.vitality.is_open(), "simulated recipient must be open");

    // Steps 2–4: open session and transmit.
    let session = FlashSession::open_and_send(state, b"sovereign payload", &cache)
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
    assert!(cached.is_some(), "session key must be in warm cache after open_and_send");
    assert_eq!(cached.unwrap(), key_bytes, "cached key must match session key");

    // Step 5: dissolve (consumes session; SessionKey zeroized on drop).
    let proof = session.dissolve();
    assert_eq!(proof.route.0, route_id, "dissolved proof must carry the session's route ID");
}

#[tokio::test]
async fn flash_session_rejects_closed_vitality() {
    use scp_relay_cache::WarmCache;
    use scp_transport::flash::{FlashSession, RecipientState, TransportError};
    use scp_vitality::VitalityState;
    use std::time::Duration;

    let cache = WarmCache::new(Duration::from_secs(600));

    for vitality in [VitalityState::Suspended, VitalityState::Severed, VitalityState::Burned] {
        let state = RecipientState {
            ops_pub: [1u8; 32],
            vitality,
            routing_hints: vec![],
        };
        let result = FlashSession::open_and_send(state, b"blocked payload", &cache).await;
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
        SCP_DOMAIN_RELAY, SCP_DOMAIN_RECOVERY, SCP_DOMAIN_TRANSPORT,
        SCP_DOMAIN_TUNNEL, SCP_DOMAIN_VITALITY,
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
    use scp_relay_mesh::{RelayNode, route_burst};

    let relay = RelayNode { id: [0u8; 16], endpoint: "local://loopback".to_string() };
    let result = route_burst(b"opaque burst - relay must not inspect this".to_vec(), vec![relay]).await;
    assert!(result.is_ok(), "local blind relay must accept any opaque payload");
}

#[tokio::test]
async fn tcp_relay_burst_delivers_and_disconnects() {
    use scp_relay_mesh::{spawn_relay_listener, RelayNode, route_burst};

    let addr = spawn_relay_listener().await.expect("relay listener must bind");
    let relay = RelayNode { id: [1u8; 16], endpoint: addr.to_string() };

    let result = route_burst(b"sovereign burst payload".to_vec(), vec![relay]).await;
    assert!(result.is_ok(), "real TCP relay must accept and ACK the burst");
}

// ── Phase 3: DissolvedProof ─────────────────────────────────────────────────

#[tokio::test]
async fn dissolved_proof_captures_route_id() {
    use scp_relay_cache::WarmCache;
    use scp_transport::flash::FlashSession;
    use std::time::Duration;

    let cache = WarmCache::new(Duration::from_secs(600));
    let state = FlashSession::retrieve_state(&[9u8; 32]).await.unwrap();
    let session = FlashSession::open_and_send(state, b"payload", &cache).await.unwrap();

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
    use scp_transport::flash::FlashSession;
    use std::time::Duration;

    let cache = WarmCache::new(Duration::from_secs(600));

    let s1 = FlashSession::open_and_send(
        FlashSession::retrieve_state(&[1u8; 32]).await.unwrap(),
        b"first",
        &cache,
    ).await.unwrap();
    let s2 = FlashSession::open_and_send(
        FlashSession::retrieve_state(&[2u8; 32]).await.unwrap(),
        b"second",
        &cache,
    ).await.unwrap();

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
    use scp_transport::transcript::FlashTranscript;
    use scp_transport::session::{FreshnessNonce, RouteId};
    use scp_vitality::VitalityState;

    let base = FlashTranscript {
        route_id:          RouteId([0x01; 16]),
        nonce:             FreshnessNonce(0xdeadbeef),
        recipient_ops_pub: [0xaa; 32],
        vitality_snapshot: VitalityState::Active,
        protocol_version:  1,
    };
    let different_route = FlashTranscript {
        route_id: RouteId([0x02; 16]),
        ..FlashTranscript {
            route_id:          RouteId([0x02; 16]),
            nonce:             FreshnessNonce(0xdeadbeef),
            recipient_ops_pub: [0xaa; 32],
            vitality_snapshot: VitalityState::Active,
            protocol_version:  1,
        }
    };
    assert_ne!(
        base.hash(), different_route.hash(),
        "transcript hash must differ when route_id differs"
    );
}

#[test]
fn transcript_hash_is_nonce_bound() {
    use scp_transport::transcript::FlashTranscript;
    use scp_transport::session::{FreshnessNonce, RouteId};
    use scp_vitality::VitalityState;

    let t1 = FlashTranscript {
        route_id:          RouteId([0x01; 16]),
        nonce:             FreshnessNonce(1000),
        recipient_ops_pub: [0xbb; 32],
        vitality_snapshot: VitalityState::Active,
        protocol_version:  1,
    };
    let t2 = FlashTranscript {
        route_id:          RouteId([0x01; 16]),
        nonce:             FreshnessNonce(1001),  // differs by one
        recipient_ops_pub: [0xbb; 32],
        vitality_snapshot: VitalityState::Active,
        protocol_version:  1,
    };
    assert_ne!(t1.hash(), t2.hash(), "transcript hash must differ when nonce differs");
}

#[test]
fn transcript_serialization_is_stable() {
    use scp_transport::transcript::FlashTranscript;
    use scp_transport::session::{FreshnessNonce, RouteId};
    use scp_vitality::VitalityState;

    // Identical construction must always produce identical hashes — field order,
    // byte encoding, and domain must never drift silently.
    let t1 = FlashTranscript {
        route_id:          RouteId([0x42; 16]),
        nonce:             FreshnessNonce(0xdeadbeefcafe1234),
        recipient_ops_pub: [0xab; 32],
        vitality_snapshot: VitalityState::Active,
        protocol_version:  1,
    };
    let t2 = FlashTranscript {
        route_id:          RouteId([0x42; 16]),
        nonce:             FreshnessNonce(0xdeadbeefcafe1234),
        recipient_ops_pub: [0xab; 32],
        vitality_snapshot: VitalityState::Active,
        protocol_version:  1,
    };
    assert_eq!(t1.hash(), t2.hash(), "identical transcripts must always produce identical hashes");
    assert_ne!(t1.hash(), [0u8; 32], "transcript hash must be non-zero");
}

#[test]
fn session_key_is_transcript_bound() {
    use scp_transport::transcript::{FlashTranscript, TransportKeyMaterial};
    use scp_transport::session::{FreshnessNonce, RouteId};
    use scp_cryptography::{DomainLabel, scp_derive_key};
    use scp_vitality::VitalityState;
    use rand_core::{OsRng, RngCore};

    let mut seed = [0u8; 32];
    OsRng.fill_bytes(&mut seed);
    let ops_pub = [0x55u8; 32];

    let make_key = |nonce: u64| {
        let t = FlashTranscript {
            route_id:          RouteId([0xf0; 16]),
            nonce:             FreshnessNonce(nonce),
            recipient_ops_pub: ops_pub,
            vitality_snapshot: VitalityState::Warm,
            protocol_version:  1,
        };
        let km = TransportKeyMaterial {
            ephemeral_seed:    seed,
            transcript_hash:   t.hash(),
            recipient_binding: ops_pub,
        };
        scp_derive_key(DomainLabel::Transport, &km.as_bytes())
    };

    let key_a = make_key(100);
    let key_b = make_key(101);

    assert_ne!(key_a, key_b, "different nonces must produce different session keys");
}

// ── Phase 4: Noise relay ────────────────────────────────────────────────────

#[tokio::test]
async fn noise_relay_burst_delivers_and_disconnects() {
    use scp_relay_mesh::{spawn_noise_relay_listener, RelayNode, route_burst};

    let (addr, _relay_pub) = spawn_noise_relay_listener().await.expect("noise relay must bind");
    let relay = RelayNode { id: [2u8; 16], endpoint: format!("noise://{}", addr) };

    let result = route_burst(b"noise-encrypted sovereign burst".to_vec(), vec![relay]).await;
    assert!(result.is_ok(), "Noise-encrypted relay must accept, decrypt, and ACK the burst");
}

#[tokio::test]
async fn noise_relay_fresh_identity_per_listener() {
    use scp_relay_mesh::spawn_noise_relay_listener;

    let (_addr1, pub1) = spawn_noise_relay_listener().await.expect("first relay must bind");
    let (_addr2, pub2) = spawn_noise_relay_listener().await.expect("second relay must bind");

    assert_ne!(
        pub1, pub2,
        "each relay listener must have a distinct Noise static key — no persistent transport identity"
    );
}
