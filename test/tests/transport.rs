// Phase 0 cryptographic core tests.
// Phase 2+ transport tests will be added when FlashSession is implemented.

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
