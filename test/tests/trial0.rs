// Phase 41 — Trial 0 Step 2: Relay-Mailbox Encrypted Exchange
//
// Proves the full three-actor flow:
//   A packages DevHarnessBurst → relay stores under DevMailboxId → B retrieves and decrypts.
//
// The relay actor is an in-process DevRelayMailbox struct (HashMap keyed by mailbox token
// hex). It sees only the opaque token and serialized CBOR bytes — no identity keys,
// no session keys, no plaintext.
//
// Claims proven by these tests:
//   - End-to-end encrypt/decrypt through relay-mailbox transit (CBOR serialization preserved)
//   - Relay routing key is DevMailboxId, never recipient_ops_pub or sender identity
//   - Wrong mailbox token cannot retrieve the target burst
//   - Wrong recipient secret cannot decrypt
//   - Modified ciphertext and modified nonce fail after mailbox transit
//
// Claims explicitly NOT proven here:
//   - TCP relay daemon
//   - Endpoint CLI
//   - LAN / multi-process delivery
//   - Key persistence on disk

use scp_cryptography::keys::KeyPair;
use scp_cryptography::x25519_generate_keypair;
use scp_ledger_substrate::{HandshakeEphemeral, SubstrateLedger};
use scp_relay_cache::WarmCache;
use scp_relay_perturbation::PerturbationEngine;
use scp_transport::flash::FlashSession;
use scp_transport::harness::{
    deserialize_burst, serialize_burst, receive_harness, DevMailboxId,
};
use scp_wire_format::signing::handshake_sig_message;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

// ── In-process relay mailbox abstraction ────────────────────────────────────
//
// Models the dev relay's opaque store/drain interface.
// The relay sees only DevMailboxId (hex) as a bucket key and opaque CBOR bytes.
// It never receives or stores identity keys, session keys, or plaintext.

struct DevRelayMailbox {
    store: Mutex<HashMap<String, Vec<Vec<u8>>>>,
}

impl DevRelayMailbox {
    fn new() -> Self {
        Self { store: Mutex::new(HashMap::new()) }
    }

    fn put(&self, mailbox_id: &DevMailboxId, burst_cbor: Vec<u8>) {
        self.store
            .lock()
            .unwrap()
            .entry(mailbox_id.to_hex())
            .or_default()
            .push(burst_cbor);
    }

    fn drain(&self, mailbox_id: &DevMailboxId) -> Vec<Vec<u8>> {
        self.store
            .lock()
            .unwrap()
            .remove(&mailbox_id.to_hex())
            .unwrap_or_default()
    }
}

// ── Shared trial setup ────────────────────────────────────────────────────────

struct TrialIdentityB {
    handshake_secret: [u8; 32],
    ops_pub:          [u8; 32],
    ledger:           SubstrateLedger,
}

fn setup_b() -> TrialIdentityB {
    let ops_kp = KeyPair::generate();
    let (handshake_secret, handshake_pub) = x25519_generate_keypair();

    let expires_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 3600;
    let sig_msg = handshake_sig_message(&handshake_pub, expires_at);
    let sig = ops_kp.sign(&sig_msg);

    let ledger = SubstrateLedger::new();
    ledger
        .publish_handshake_ephemeral(
            &ops_kp.public,
            HandshakeEphemeral {
                pub_key:      handshake_pub,
                sig:          sig.to_vec(),
                published_at: 0,
                expires_at,
            },
        )
        .expect("handshake ephemeral publication must succeed");

    TrialIdentityB {
        handshake_secret,
        ops_pub: ops_kp.public,
        ledger,
    }
}

// ── Test 1: full A→relay→B roundtrip recovers plaintext ─────────────────────

#[tokio::test]
async fn trial0_relay_mailbox_ab_full_flow() {
    let b = setup_b();
    let mailbox = DevRelayMailbox::new();
    let mailbox_id = DevMailboxId::generate();

    let cache  = WarmCache::new(Duration::from_secs(600));
    let engine = PerturbationEngine::passthrough();

    // A: retrieve state, package harness burst.
    let state = FlashSession::retrieve_state(&b.ledger, &b.ops_pub)
        .await
        .expect("retrieve_state must succeed");

    let payload = b"trial-0-relay-mailbox-roundtrip";
    let (_session, burst) =
        FlashSession::open_and_package_harness_burst(state, payload, &cache, &engine)
            .await
            .expect("open_and_package_harness_burst must succeed on v2 path");

    // Relay: store opaque CBOR bytes under DevMailboxId.
    let cbor = serialize_burst(&burst).expect("serialize_burst must succeed");
    mailbox.put(&mailbox_id, cbor);

    // B: drain mailbox by token, deserialize, decrypt.
    let bursts = mailbox.drain(&mailbox_id);
    assert_eq!(bursts.len(), 1, "relay mailbox must contain exactly one burst");

    let recovered_burst = deserialize_burst(&bursts[0]).expect("deserialize_burst must succeed");
    let plaintext = receive_harness(&b.handshake_secret, &b.ops_pub, &recovered_burst)
        .expect("receive_harness must succeed");

    assert_eq!(
        plaintext.as_slice(),
        payload.as_slice(),
        "decrypted payload must equal original plaintext"
    );
}

// ── Test 2: relay routing key is DevMailboxId, not recipient_ops_pub ────────

#[tokio::test]
async fn trial0_relay_routing_key_is_mailbox_id_not_ops_pub() {
    let b = setup_b();
    let mailbox = DevRelayMailbox::new();
    let mailbox_id = DevMailboxId::generate();

    let cache  = WarmCache::new(Duration::from_secs(600));
    let engine = PerturbationEngine::passthrough();

    let state = FlashSession::retrieve_state(&b.ledger, &b.ops_pub)
        .await
        .unwrap();

    let (_session, burst) =
        FlashSession::open_and_package_harness_burst(state, b"routing key test", &cache, &engine)
            .await
            .unwrap();

    let cbor = serialize_burst(&burst).unwrap();
    mailbox.put(&mailbox_id, cbor);

    // The relay store key is the DevMailboxId hex, not ops_pub.
    // Asserting: if we try to drain using ops_pub as a hex mailbox token, we get nothing.
    let ops_pub_as_hex: String = b.ops_pub.iter().map(|b| format!("{:02x}", b)).collect();
    let fake_id = DevMailboxId::from_hex(&ops_pub_as_hex)
        .expect("ops_pub is 32 bytes so it parses as a token");
    let drained_by_ops_pub = mailbox.drain(&fake_id);
    assert!(
        drained_by_ops_pub.is_empty(),
        "relay must not route by ops_pub — draining by ops_pub key must return nothing"
    );

    // The real mailbox_id retrieves the burst.
    let drained = mailbox.drain(&mailbox_id);
    assert_eq!(drained.len(), 1, "correct mailbox_id must retrieve the burst");
}

// ── Test 3: wrong mailbox token cannot retrieve burst ────────────────────────

#[tokio::test]
async fn trial0_wrong_mailbox_token_cannot_retrieve() {
    let b = setup_b();
    let mailbox = DevRelayMailbox::new();
    let mailbox_id = DevMailboxId::generate();
    let wrong_id   = DevMailboxId::generate();

    let cache  = WarmCache::new(Duration::from_secs(600));
    let engine = PerturbationEngine::passthrough();

    let state = FlashSession::retrieve_state(&b.ledger, &b.ops_pub)
        .await
        .unwrap();

    let (_session, burst) =
        FlashSession::open_and_package_harness_burst(state, b"mailbox partitioning", &cache, &engine)
            .await
            .unwrap();

    let cbor = serialize_burst(&burst).unwrap();
    mailbox.put(&mailbox_id, cbor);

    let wrong_drain = mailbox.drain(&wrong_id);
    assert!(
        wrong_drain.is_empty(),
        "wrong mailbox token must not retrieve any burst"
    );

    // Correct token still retrieves.
    let correct_drain = mailbox.drain(&mailbox_id);
    assert_eq!(correct_drain.len(), 1, "correct token must still retrieve the burst");
}

// ── Test 4: wrong recipient secret cannot decrypt ────────────────────────────

#[tokio::test]
async fn trial0_wrong_recipient_secret_cannot_decrypt() {
    let b = setup_b();
    let mailbox = DevRelayMailbox::new();
    let mailbox_id = DevMailboxId::generate();

    let cache  = WarmCache::new(Duration::from_secs(600));
    let engine = PerturbationEngine::passthrough();

    let state = FlashSession::retrieve_state(&b.ledger, &b.ops_pub)
        .await
        .unwrap();

    let (_session, burst) =
        FlashSession::open_and_package_harness_burst(state, b"wrong secret test", &cache, &engine)
            .await
            .unwrap();

    let cbor = serialize_burst(&burst).unwrap();
    mailbox.put(&mailbox_id, cbor);

    let (wrong_secret, _) = x25519_generate_keypair();
    let bursts = mailbox.drain(&mailbox_id);
    let recovered = deserialize_burst(&bursts[0]).unwrap();

    let result = receive_harness(&wrong_secret, &b.ops_pub, &recovered);
    assert!(
        result.is_err(),
        "wrong recipient handshake secret must cause decryption failure"
    );
}

// ── Test 5: modified ciphertext fails after mailbox transit ──────────────────

#[tokio::test]
async fn trial0_modified_ciphertext_fails_after_mailbox_transit() {
    let b = setup_b();
    let mailbox = DevRelayMailbox::new();
    let mailbox_id = DevMailboxId::generate();

    let cache  = WarmCache::new(Duration::from_secs(600));
    let engine = PerturbationEngine::passthrough();

    let state = FlashSession::retrieve_state(&b.ledger, &b.ops_pub)
        .await
        .unwrap();

    let (_session, burst) =
        FlashSession::open_and_package_harness_burst(state, b"integrity test", &cache, &engine)
            .await
            .unwrap();

    let cbor = serialize_burst(&burst).unwrap();
    mailbox.put(&mailbox_id, cbor);

    let bursts = mailbox.drain(&mailbox_id);
    let mut recovered = deserialize_burst(&bursts[0]).unwrap();

    // Flip a bit in the ciphertext — authentication tag must reject it.
    recovered.ciphertext[0] ^= 0xff;

    assert!(
        receive_harness(&b.handshake_secret, &b.ops_pub, &recovered).is_err(),
        "modified ciphertext must fail authentication after mailbox transit"
    );
}

// ── Test 6: modified enc_nonce fails after mailbox transit ───────────────────

#[tokio::test]
async fn trial0_modified_enc_nonce_fails_after_mailbox_transit() {
    let b = setup_b();
    let mailbox = DevRelayMailbox::new();
    let mailbox_id = DevMailboxId::generate();

    let cache  = WarmCache::new(Duration::from_secs(600));
    let engine = PerturbationEngine::passthrough();

    let state = FlashSession::retrieve_state(&b.ledger, &b.ops_pub)
        .await
        .unwrap();

    let (_session, burst) =
        FlashSession::open_and_package_harness_burst(state, b"nonce integrity test", &cache, &engine)
            .await
            .unwrap();

    let cbor = serialize_burst(&burst).unwrap();
    mailbox.put(&mailbox_id, cbor);

    let bursts = mailbox.drain(&mailbox_id);
    let mut recovered = deserialize_burst(&bursts[0]).unwrap();

    // Flip a bit in the enc_nonce — decryption must fail.
    recovered.enc_nonce[0] ^= 0x01;

    assert!(
        receive_harness(&b.handshake_secret, &b.ops_pub, &recovered).is_err(),
        "modified enc_nonce must cause decryption failure after mailbox transit"
    );
}

// ── Test 7: CBOR round-trip preserves all burst fields ───────────────────────

#[tokio::test]
async fn trial0_cbor_transit_preserves_burst_fields() {
    let b = setup_b();
    let cache  = WarmCache::new(Duration::from_secs(600));
    let engine = PerturbationEngine::passthrough();

    let state = FlashSession::retrieve_state(&b.ledger, &b.ops_pub)
        .await
        .unwrap();

    let (_session, burst) =
        FlashSession::open_and_package_harness_burst(state, b"cbor field test", &cache, &engine)
            .await
            .unwrap();

    let cbor = serialize_burst(&burst).unwrap();
    let recovered = deserialize_burst(&cbor).unwrap();

    assert_eq!(burst.sender_ephemeral_pub, recovered.sender_ephemeral_pub);
    assert_eq!(burst.route_id,             recovered.route_id);
    assert_eq!(burst.freshness_nonce,      recovered.freshness_nonce);
    assert_eq!(burst.vitality_byte,        recovered.vitality_byte);
    assert_eq!(burst.enc_nonce,            recovered.enc_nonce);
    assert_eq!(burst.ciphertext,           recovered.ciphertext);
}

// ── Test 8: relay burst bytes do not expose plaintext ────────────────────────

#[tokio::test]
async fn trial0_relay_burst_bytes_do_not_expose_plaintext() {
    let b = setup_b();
    let cache  = WarmCache::new(Duration::from_secs(600));
    let engine = PerturbationEngine::passthrough();

    let state = FlashSession::retrieve_state(&b.ledger, &b.ops_pub)
        .await
        .unwrap();

    let payload = b"secret-must-not-appear-in-relay-bytes";
    let (_session, burst) =
        FlashSession::open_and_package_harness_burst(state, payload, &cache, &engine)
            .await
            .unwrap();

    let cbor = serialize_burst(&burst).unwrap();

    // The relay-visible bytes must not contain the plaintext as a substring.
    let cbor_str = scp_transport::harness::hex_encode(&cbor);
    let payload_hex = scp_transport::harness::hex_encode(payload);
    assert!(
        !cbor_str.contains(&payload_hex),
        "relay-visible CBOR bytes must not contain the plaintext payload"
    );
}
