// scp-cli: dev-harness endpoint CLI for Level 1 multi-process exchange.
//
// NOT PRODUCTION. Identity key files store secrets in plaintext. Use only for
// local development and the explicit trial harness described in RUNTIME_BOOTSTRAP_PLAN.md.
//
// Commands:
//   keygen   --out <path>          Generate identity; write key file; print public card.
//   public   --identity <path>     Print public card for an existing identity.
//   mailbox-new                    Print a fresh random DevMailboxId hex.
//   send     --identity <path>     Send an encrypted payload to a relay mailbox.
//            --recipient <card>    Recipient public card JSON path.
//            --relay <addr>        Relay address (host:port).
//            --mailbox <hex>       DevMailboxId hex (64 chars).
//            --message <text>      Plaintext message.
//   receive  --identity <path>     Poll relay mailbox and decrypt all bursts.
//            --relay <addr>
//            --mailbox <hex>
//   agent-send     Send a signed agent envelope inside an encrypted burst.
//   agent-receive  Poll, decrypt, verify pinned sender, TTL-check, and task_id-dedup.
//                  Uses <identity>.agent-seen by default; override with --seen-dir <path>.
//
// Output events (vocabulary-neutral, no vitality label words):
//   identity_created, mailbox_created, burst_stored, payload_decrypted,
//   exchange_complete, agent_message_verified, agent_receive_complete, error

use rand_core::{OsRng, RngCore};
use scp_cryptography::keys::{KeyPair, PublicKey};
use scp_cryptography::x25519_generate_keypair;
use scp_provider_delivery::{DeliveryEndpoint, DeliveryPool, DeliveryRoute, RelayEndpoint};
use scp_provider_pool::SamplingStrategy;
use scp_transport::harness::{
    deserialize_burst, hex_decode, hex_encode, receive_harness, send_harness_direct,
    serialize_burst, DevMailboxId,
};
use scp_wire_format::signing::handshake_sig_message;
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

const AGENT_ENVELOPE_SCHEMA_VERSION: u16 = 1;
const AGENT_ENVELOPE_SIGNING_DOMAIN: &[u8] = b"scp-agent-envelope-v0";
const AGENT_SEEN_TASK_DOMAIN: &[u8] = b"scp-agent-seen-task-v1";
const AGENT_SEEN_SALT_FILE: &str = "seen.salt";
const MAX_AGENT_ENVELOPE_TTL_SECS: u64 = 86_400;
const MAX_AGENT_ENVELOPE_FUTURE_SKEW_SECS: u64 = 300;

// ── Identity file (private, 0600) ─────────────────────────────────────────────

#[derive(Clone, Serialize, Deserialize)]
struct IdentityFile {
    ops_pub: String,        // 64 hex chars (Ed25519 public)
    ops_priv: String,       // 64 hex chars (Ed25519 secret) — KEEP SECRET
    handshake_pub: String,  // 64 hex chars (X25519 public)
    handshake_priv: String, // 64 hex chars (X25519 secret) — KEEP SECRET
    handshake_sig: String,  // 128 hex chars (ops signs handshake_pub + expires_at)
    handshake_expires_at: u64,
}

// ── Public card (shareable) ───────────────────────────────────────────────────

#[derive(Clone, Serialize, Deserialize)]
struct ContactCard {
    ops_pub: String,
    handshake_pub: String,
    handshake_sig: String,
    handshake_expires_at: u64,
}

// ── Agent envelope (encrypted inside a dev-harness burst) ─────────────────────

#[derive(Clone, Serialize, Deserialize)]
struct AgentReplyTo {
    relays: Vec<String>,
    mailbox: String,
}

#[derive(Clone, Serialize, Deserialize)]
struct AgentEnvelopeV0 {
    schema_version: u16,
    task_id: String,
    kind: String,
    from: ContactCard,
    reply_to: AgentReplyTo,
    created_at: u64,
    ttl: u64,
    body: String,
    sig: String,
}

struct AgentEnvelopeDraft {
    task_id: String,
    kind: String,
    from: ContactCard,
    reply_to: AgentReplyTo,
    created_at: u64,
    ttl: u64,
    body: String,
}

struct SeenTaskStore {
    dir: PathBuf,
    salt: [u8; 32],
}

enum AgentEnvelopeTimeStatus {
    Current { expires_at: u64 },
    Expired,
    Invalid(String),
}

// ── Entry point ───────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("{{\"event\":\"error\",\"reason\":\"no command specified\"}}");
        std::process::exit(1);
    }
    let result = match args[1].as_str() {
        "keygen" => cmd_keygen(&args[2..]),
        "public" => cmd_public(&args[2..]),
        "mailbox-new" => cmd_mailbox_new(),
        "send" => cmd_send(&args[2..]).await,
        "receive" => cmd_receive(&args[2..]).await,
        "agent-send" => cmd_agent_send(&args[2..]).await,
        "agent-receive" => cmd_agent_receive(&args[2..]).await,
        other => {
            eprintln!("{{\"event\":\"error\",\"reason\":\"unknown command: {other}\"}}");
            std::process::exit(1);
        }
    };
    if let Err(e) = result {
        eprintln!("{{\"event\":\"error\",\"reason\":\"{e}\"}}");
        std::process::exit(1);
    }
}

// ── keygen ────────────────────────────────────────────────────────────────────

fn cmd_keygen(args: &[String]) -> Result<(), String> {
    let out = require_arg(args, "--out")?;

    let ops_kp = KeyPair::generate();
    let (hs_priv, hs_pub) = x25519_generate_keypair();

    let expires_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 86400; // 24-hour default TTL for dev harness

    let sig_msg = handshake_sig_message(&hs_pub, expires_at);
    let sig = ops_kp.sign(&sig_msg);

    let identity = IdentityFile {
        ops_pub: hex_encode(&ops_kp.public),
        ops_priv: hex_encode(&ops_kp.secret),
        handshake_pub: hex_encode(&hs_pub),
        handshake_priv: hex_encode(&hs_priv),
        handshake_sig: hex_encode(&sig),
        handshake_expires_at: expires_at,
    };

    let json = serde_json::to_string_pretty(&identity)
        .map_err(|e| format!("JSON serialization failed: {e}"))?;

    write_secret_file(&out, json.as_bytes()).map_err(|e| format!("write identity file: {e}"))?;

    // Print the public card to stdout so the user can share it with senders.
    let card = ContactCard {
        ops_pub: hex_encode(&ops_kp.public),
        handshake_pub: hex_encode(&hs_pub),
        handshake_sig: hex_encode(&sig),
        handshake_expires_at: expires_at,
    };
    let card_event = serde_json::json!({
        "event":              "identity_created",
        "ops_pub":            card.ops_pub,
        "handshake_pub":      card.handshake_pub,
        "handshake_sig":      card.handshake_sig,
        "handshake_expires_at": card.handshake_expires_at,
    });
    println!("{}", serde_json::to_string(&card_event).unwrap());
    Ok(())
}

// ── public ────────────────────────────────────────────────────────────────────

fn cmd_public(args: &[String]) -> Result<(), String> {
    let path = require_arg(args, "--identity")?;
    let identity = load_identity(&path)?;
    let card_event = serde_json::json!({
        "event":              "identity_public",
        "ops_pub":            identity.ops_pub,
        "handshake_pub":      identity.handshake_pub,
        "handshake_sig":      identity.handshake_sig,
        "handshake_expires_at": identity.handshake_expires_at,
    });
    println!("{}", serde_json::to_string(&card_event).unwrap());
    Ok(())
}

// ── mailbox-new ───────────────────────────────────────────────────────────────

fn cmd_mailbox_new() -> Result<(), String> {
    let id = DevMailboxId::generate();
    let event = serde_json::json!({
        "event":      "mailbox_created",
        "mailbox_id": id.to_hex(),
    });
    println!("{}", serde_json::to_string(&event).unwrap());
    Ok(())
}

// ── send ──────────────────────────────────────────────────────────────────────

async fn cmd_send(args: &[String]) -> Result<(), String> {
    let identity_path = require_arg(args, "--identity")?;
    let card_path = require_arg(args, "--recipient")?;
    let relay_addrs = collect_relays(args)?;
    let mailbox_hex = require_arg(args, "--mailbox")?;
    let message = require_arg(args, "--message")?;

    let _identity = load_identity(&identity_path)?;
    let card = load_card(&card_path)?;

    let ops_pub = parse_hex32(&card.ops_pub, "ops_pub")?;
    let hs_pub = parse_hex32(&card.handshake_pub, "handshake_pub")?;

    // Verify the recipient's handshake key signature using their ops key.
    let sig_msg = handshake_sig_message(&hs_pub, card.handshake_expires_at);
    let sig_bytes = hex_decode(&card.handshake_sig).map_err(|e| format!("{e}"))?;
    let mut sig_arr = [0u8; 64];
    if sig_bytes.len() != 64 {
        return Err("handshake_sig must be 64 bytes".to_string());
    }
    sig_arr.copy_from_slice(&sig_bytes);
    if !PublicKey(ops_pub).verify(&sig_msg, &sig_arr) {
        return Err("recipient handshake key signature verification failed".to_string());
    }

    let mailbox_id = DevMailboxId::from_hex(&mailbox_hex).map_err(|e| format!("{e}"))?;

    let burst = send_harness_direct(&ops_pub, &hs_pub, message.as_bytes());
    let route_id_hex = hex_encode(&burst.route_id);
    let cbor = serialize_burst(&burst).map_err(|e| format!("{e}"))?;

    // R1 (design §2.2): replicate-store to every currently-live selected relay.
    let mut pool = build_delivery_pool(&relay_addrs);
    let routes = select_relay_routes(&mut pool)?;

    let mut successes = 0usize;
    for route in routes {
        match route.endpoint.attempt_store(&mailbox_id, &cbor).await {
            Ok(()) => {
                let _ = pool.record_delivery_success(&route.receipt);
                successes += 1;
                let event = serde_json::json!({
                    "event":      "burst_stored",
                    "mailbox_id": mailbox_id.to_hex(),
                    "route_id":   route_id_hex,
                });
                println!("{}", serde_json::to_string(&event).unwrap());
            }
            Err(_e) => {
                let _ = pool.record_delivery_failure(&route.receipt);
            }
        }
    }

    if successes == 0 {
        return Err("relay store: all configured relays failed".to_string());
    }

    let summary = serde_json::json!({
        "event": "burst_replicated",
        "count": successes,
    });
    println!("{}", serde_json::to_string(&summary).unwrap());
    Ok(())
}

// ── receive ───────────────────────────────────────────────────────────────────

async fn cmd_receive(args: &[String]) -> Result<(), String> {
    let identity_path = require_arg(args, "--identity")?;
    let relay_addrs = collect_relays(args)?;
    let mailbox_hex = require_arg(args, "--mailbox")?;

    let identity = load_identity(&identity_path)?;
    let ops_pub = parse_hex32(&identity.ops_pub, "ops_pub")?;
    let hs_priv = parse_hex32(&identity.handshake_priv, "handshake_priv")?;

    let mailbox_id = DevMailboxId::from_hex(&mailbox_hex).map_err(|e| format!("{e}"))?;

    // R1 (design §2.2): poll-any across every currently-live selected relay,
    // deduplicating by route_id (the same burst may be visible on more than
    // one relay after replicate-store).
    let mut pool = build_delivery_pool(&relay_addrs);
    let routes = select_relay_routes(&mut pool)?;

    let mut any_reachable = false;
    let mut seen_route_ids = std::collections::HashSet::new();
    let mut events = Vec::new();

    for route in routes {
        match route.endpoint.attempt_poll(&mailbox_id).await {
            Ok(blobs) => {
                any_reachable = true;
                let _ = pool.record_delivery_success(&route.receipt);
                for blob in &blobs {
                    let burst = deserialize_burst(blob).map_err(|e| format!("{e}"))?;
                    let route_id_hex = hex_encode(&burst.route_id);
                    // Security: dedup MUST run only on a burst that has already
                    // passed AEAD verification, never on the raw, unauthenticated
                    // route_id field. Relays are blind and untrusted; a malicious
                    // relay in the configured set could otherwise forge a blob
                    // with a colliding route_id to silently suppress a legitimate
                    // message replicated (R1) via a different, honest relay.
                    match receive_harness(&hs_priv, &ops_pub, &burst) {
                        Ok(plaintext) => {
                            if !seen_route_ids.insert(route_id_hex.clone()) {
                                continue; // genuinely the same verified message, seen via another relay
                            }
                            let text = String::from_utf8(plaintext)
                                .unwrap_or_else(|_| "<non-utf8 payload>".to_string());
                            events.push(serde_json::json!({
                                "event":    "payload_decrypted",
                                "route_id": route_id_hex,
                                "plaintext": text,
                            }));
                        }
                        Err(e) => {
                            // Do NOT dedup failures — a forged/garbage blob from one
                            // relay must never suppress a legitimate message with the
                            // same route_id arriving from a different, honest relay.
                            events.push(serde_json::json!({
                                "event":    "decrypt_failed",
                                "route_id": route_id_hex,
                                "reason":   format!("{e}"),
                            }));
                        }
                    }
                }
            }
            Err(_e) => {
                let _ = pool.record_delivery_failure(&route.receipt);
            }
        }
    }

    if !any_reachable {
        return Err("relay poll: all configured relays failed".to_string());
    }

    for event in &events {
        println!("{}", serde_json::to_string(event).unwrap());
    }

    let event = serde_json::json!({
        "event": "exchange_complete",
        "count": events.len(),
    });
    println!("{}", serde_json::to_string(&event).unwrap());
    Ok(())
}

// ── agent-send / agent-receive ────────────────────────────────────────────────

async fn cmd_agent_send(args: &[String]) -> Result<(), String> {
    let identity_path = require_arg(args, "--identity")?;
    let card_path = require_arg(args, "--recipient")?;
    let relay_addrs = collect_relays(args)?;
    let mailbox_hex = require_arg(args, "--mailbox")?;
    let task_id = require_arg(args, "--task-id")?;
    let kind = require_arg(args, "--kind")?;
    let reply_relays = collect_required_values(args, "--reply-relay")?;
    let reply_mailbox = require_arg(args, "--reply-mailbox")?;
    let ttl = parse_u64_arg(args, "--ttl-secs")?;
    let body = require_arg(args, "--body")?;

    if ttl == 0 {
        return Err("--ttl-secs must be greater than zero".to_string());
    }

    let identity = load_identity(&identity_path)?;
    let sender_card = contact_card_from_identity(&identity);
    let envelope = build_agent_envelope(
        &identity,
        AgentEnvelopeDraft {
            task_id,
            kind,
            from: sender_card,
            reply_to: AgentReplyTo {
                relays: reply_relays,
                mailbox: reply_mailbox,
            },
            created_at: now_secs()?,
            ttl,
            body,
        },
    )?;
    let envelope_bytes =
        serde_json::to_vec(&envelope).map_err(|e| format!("agent envelope encode: {e}"))?;

    let card = load_card(&card_path)?;
    let mailbox_id = DevMailboxId::from_hex(&mailbox_hex).map_err(|e| format!("{e}"))?;
    let (successes, route_id_hex) =
        replicate_encrypted_payload(&card, &relay_addrs, &mailbox_id, &envelope_bytes).await?;

    let stored = serde_json::json!({
        "event":    "agent_burst_stored",
        "task_id":  envelope.task_id,
        "route_id": route_id_hex,
    });
    println!("{}", serde_json::to_string(&stored).unwrap());

    let summary = serde_json::json!({
        "event": "agent_burst_replicated",
        "task_id": envelope.task_id,
        "count": successes,
    });
    println!("{}", serde_json::to_string(&summary).unwrap());
    Ok(())
}

async fn cmd_agent_receive(args: &[String]) -> Result<(), String> {
    let identity_path = require_arg(args, "--identity")?;
    let sender_card_path = require_arg(args, "--sender")?;
    let relay_addrs = collect_relays(args)?;
    let mailbox_hex = require_arg(args, "--mailbox")?;
    let seen_dir = optional_arg(args, "--seen-dir")
        .map(PathBuf::from)
        .unwrap_or_else(|| default_agent_seen_dir(&identity_path));

    let identity = load_identity(&identity_path)?;
    let expected_sender = load_card(&sender_card_path)?;
    verified_card_keys(&expected_sender).map_err(|e| format!("sender card: {e}"))?;
    let expected_sender_ops_pub = expected_sender.ops_pub;
    let ops_pub = parse_hex32(&identity.ops_pub, "ops_pub")?;
    let hs_priv = parse_hex32(&identity.handshake_priv, "handshake_priv")?;
    let mailbox_id = DevMailboxId::from_hex(&mailbox_hex).map_err(|e| format!("{e}"))?;
    let now = now_secs()?;
    let seen_tasks = SeenTaskStore::open(seen_dir, now)?;

    let mut pool = build_delivery_pool(&relay_addrs);
    let routes = select_relay_routes(&mut pool)?;

    let mut any_reachable = false;
    let mut seen_route_ids = std::collections::HashSet::new();
    let mut verified = 0usize;
    let mut rejected = 0usize;
    let mut expired = 0usize;
    let mut duplicates = 0usize;

    for route in routes {
        match route.endpoint.attempt_poll(&mailbox_id).await {
            Ok(blobs) => {
                any_reachable = true;
                let _ = pool.record_delivery_success(&route.receipt);
                for blob in &blobs {
                    let burst = match deserialize_burst(blob) {
                        Ok(burst) => burst,
                        Err(e) => {
                            rejected += 1;
                            let event = serde_json::json!({
                                "event": "agent_message_rejected",
                                "reason": format!("{e}"),
                            });
                            println!("{}", serde_json::to_string(&event).unwrap());
                            continue;
                        }
                    };
                    let route_id_hex = hex_encode(&burst.route_id);
                    let plaintext = match receive_harness(&hs_priv, &ops_pub, &burst) {
                        Ok(plaintext) => plaintext,
                        Err(e) => {
                            rejected += 1;
                            let event = serde_json::json!({
                                "event": "agent_message_rejected",
                                "route_id": route_id_hex,
                                "reason": format!("{e}"),
                            });
                            println!("{}", serde_json::to_string(&event).unwrap());
                            continue;
                        }
                    };

                    if !seen_route_ids.insert(route_id_hex.clone()) {
                        duplicates += 1;
                        continue;
                    }

                    let envelope: AgentEnvelopeV0 = match serde_json::from_slice(&plaintext) {
                        Ok(envelope) => envelope,
                        Err(e) => {
                            rejected += 1;
                            let event = serde_json::json!({
                                "event": "agent_message_rejected",
                                "route_id": route_id_hex,
                                "reason": format!("agent envelope decode: {e}"),
                            });
                            println!("{}", serde_json::to_string(&event).unwrap());
                            continue;
                        }
                    };

                    if let Err(e) = verify_agent_envelope(&envelope) {
                        rejected += 1;
                        let event = serde_json::json!({
                            "event": "agent_message_rejected",
                            "route_id": route_id_hex,
                            "task_id": envelope.task_id,
                            "reason": e,
                        });
                        println!("{}", serde_json::to_string(&event).unwrap());
                        continue;
                    }

                    if envelope.from.ops_pub != expected_sender_ops_pub {
                        rejected += 1;
                        let event = serde_json::json!({
                            "event": "agent_message_rejected",
                            "route_id": route_id_hex,
                            "task_id": envelope.task_id,
                            "reason": "agent envelope sender does not match pinned sender card",
                        });
                        println!("{}", serde_json::to_string(&event).unwrap());
                        continue;
                    }

                    let expires_at = match agent_envelope_time_status(&envelope, now) {
                        AgentEnvelopeTimeStatus::Current { expires_at } => expires_at,
                        AgentEnvelopeTimeStatus::Expired => {
                            expired += 1;
                            let event = serde_json::json!({
                                "event": "agent_message_expired",
                                "route_id": route_id_hex,
                                "task_id": envelope.task_id,
                            });
                            println!("{}", serde_json::to_string(&event).unwrap());
                            continue;
                        }
                        AgentEnvelopeTimeStatus::Invalid(reason) => {
                            rejected += 1;
                            let event = serde_json::json!({
                                "event": "agent_message_rejected",
                                "route_id": route_id_hex,
                                "task_id": envelope.task_id,
                                "reason": reason,
                            });
                            println!("{}", serde_json::to_string(&event).unwrap());
                            continue;
                        }
                    };

                    match seen_tasks.claim(&expected_sender_ops_pub, &envelope.task_id, expires_at)
                    {
                        Ok(true) => {}
                        Ok(false) => {
                            duplicates += 1;
                            let event = serde_json::json!({
                                "event": "agent_message_duplicate",
                                "route_id": route_id_hex,
                                "task_id": envelope.task_id,
                            });
                            println!("{}", serde_json::to_string(&event).unwrap());
                            continue;
                        }
                        Err(e) => return Err(format!("agent seen-task store: {e}")),
                    }

                    verified += 1;
                    let event = serde_json::json!({
                        "event": "agent_message_verified",
                        "route_id": route_id_hex,
                        "task_id": envelope.task_id,
                        "kind": envelope.kind,
                        "from_ops_pub": envelope.from.ops_pub,
                        "reply_relays": envelope.reply_to.relays,
                        "reply_mailbox": envelope.reply_to.mailbox,
                        "body": envelope.body,
                    });
                    println!("{}", serde_json::to_string(&event).unwrap());
                }
            }
            Err(_e) => {
                let _ = pool.record_delivery_failure(&route.receipt);
            }
        }
    }

    if !any_reachable {
        return Err("relay poll: all configured relays failed".to_string());
    }

    let event = serde_json::json!({
        "event": "agent_receive_complete",
        "verified": verified,
        "rejected": rejected,
        "expired": expired,
        "duplicates": duplicates,
    });
    println!("{}", serde_json::to_string(&event).unwrap());
    Ok(())
}

// ── Multi-relay delivery plumbing ─────────────────────────────────────────────

/// Gathers every `--relay <addr>` occurrence (one or more). Repeatable flag,
/// not a config file or discovery — see design §3.3.
fn collect_relays(args: &[String]) -> Result<Vec<String>, String> {
    let mut relays = Vec::new();
    let mut i = 0;
    while i < args.len() {
        if args[i] == "--relay" {
            if i + 1 >= args.len() {
                return Err("missing value for --relay".to_string());
            }
            relays.push(args[i + 1].clone());
            i += 2;
        } else {
            i += 1;
        }
    }
    if relays.is_empty() {
        return Err("missing required argument: --relay".to_string());
    }
    Ok(relays)
}

fn build_delivery_pool(relay_addrs: &[String]) -> DeliveryPool<RelayEndpoint> {
    let k = relay_addrs.len();
    let mut pool = DeliveryPool::new(SamplingStrategy::RandomK(k), k * 4).with_liveness(2, 60);
    for addr in relay_addrs {
        // endpoint_id is a fresh random operator-assigned tag — never derived
        // from addr (design §3.2: keeps pool internals address-free).
        let mut tag = [0u8; 32];
        OsRng.fill_bytes(&mut tag);
        pool.add(RelayEndpoint::new(tag, addr.clone()));
    }
    pool
}

/// The single audited routing seam: `ProviderPool` liveness (via `DeliveryPool`)
/// gates which real relay(s) a real burst is routed through. Authorized by ADR
/// verdict `B — OPTION_2_ROUTING_SEAM_AUTHORIZED`
/// (`docs/architecture/PROVIDERPOOL_MULTIRELAY_ARCHITECTURE_DESIGN.md` §4).
///
/// This does NOT influence: `VitalityEvidenceStore`, send authorization (a
/// burst to any live relay is authorized identically to today — liveness
/// changes WHERE, never WHETHER), corridor suspension, rotation of
/// state-consistency providers, or TOLS. The RNG here is freshly drawn per
/// call and is NOT derived from the mailbox token or recipient identity —
/// selection must never be keyed to either (design §3.2 anti-correlation
/// invariant).
fn select_relay_routes(
    pool: &mut DeliveryPool<RelayEndpoint>,
) -> Result<Vec<DeliveryRoute<RelayEndpoint>>, String> {
    let mut rng = OsRng;
    pool.select_route(&mut rng)
        .map_err(|e| format!("relay selection: {e:?}"))
}

async fn replicate_encrypted_payload(
    recipient: &ContactCard,
    relay_addrs: &[String],
    mailbox_id: &DevMailboxId,
    payload: &[u8],
) -> Result<(usize, String), String> {
    let (ops_pub, hs_pub) = verified_card_keys(recipient)?;
    let burst = send_harness_direct(&ops_pub, &hs_pub, payload);
    let route_id_hex = hex_encode(&burst.route_id);
    let cbor = serialize_burst(&burst).map_err(|e| format!("{e}"))?;

    let mut pool = build_delivery_pool(relay_addrs);
    let routes = select_relay_routes(&mut pool)?;

    let mut successes = 0usize;
    for route in routes {
        match route.endpoint.attempt_store(mailbox_id, &cbor).await {
            Ok(()) => {
                let _ = pool.record_delivery_success(&route.receipt);
                successes += 1;
            }
            Err(_e) => {
                let _ = pool.record_delivery_failure(&route.receipt);
            }
        }
    }

    if successes == 0 {
        return Err("relay store: all configured relays failed".to_string());
    }
    Ok((successes, route_id_hex))
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn require_arg(args: &[String], flag: &str) -> Result<String, String> {
    let mut i = 0;
    while i < args.len() {
        if args[i] == flag && i + 1 < args.len() {
            return Ok(args[i + 1].clone());
        }
        i += 1;
    }
    Err(format!("missing required argument: {flag}"))
}

fn collect_required_values(args: &[String], flag: &str) -> Result<Vec<String>, String> {
    let mut values = Vec::new();
    let mut i = 0;
    while i < args.len() {
        if args[i] == flag {
            if i + 1 >= args.len() {
                return Err(format!("missing value for {flag}"));
            }
            values.push(args[i + 1].clone());
            i += 2;
        } else {
            i += 1;
        }
    }
    if values.is_empty() {
        return Err(format!("missing required argument: {flag}"));
    }
    Ok(values)
}

fn optional_arg(args: &[String], flag: &str) -> Option<String> {
    let mut i = 0;
    while i < args.len() {
        if args[i] == flag && i + 1 < args.len() {
            return Some(args[i + 1].clone());
        }
        i += 1;
    }
    None
}

fn parse_u64_arg(args: &[String], flag: &str) -> Result<u64, String> {
    require_arg(args, flag)?
        .parse::<u64>()
        .map_err(|e| format!("{flag}: expected unsigned integer: {e}"))
}

fn load_identity(path: &str) -> Result<IdentityFile, String> {
    let contents =
        std::fs::read_to_string(path).map_err(|e| format!("read identity file '{path}': {e}"))?;
    serde_json::from_str(&contents).map_err(|e| format!("parse identity file '{path}': {e}"))
}

fn contact_card_from_identity(identity: &IdentityFile) -> ContactCard {
    ContactCard {
        ops_pub: identity.ops_pub.clone(),
        handshake_pub: identity.handshake_pub.clone(),
        handshake_sig: identity.handshake_sig.clone(),
        handshake_expires_at: identity.handshake_expires_at,
    }
}

fn load_card(path: &str) -> Result<ContactCard, String> {
    let contents =
        std::fs::read_to_string(path).map_err(|e| format!("read card file '{path}': {e}"))?;
    // The card may be the raw ContactCard JSON, or the full identity_created event JSON.
    // Try ContactCard first; fall back to extracting from event JSON.
    if let Ok(card) = serde_json::from_str::<ContactCard>(&contents) {
        return Ok(card);
    }
    // Try as event JSON (has an "event" field plus the card fields)
    let v: serde_json::Value =
        serde_json::from_str(&contents).map_err(|e| format!("parse card file '{path}': {e}"))?;
    Ok(ContactCard {
        ops_pub: v["ops_pub"].as_str().ok_or("missing ops_pub")?.to_string(),
        handshake_pub: v["handshake_pub"]
            .as_str()
            .ok_or("missing handshake_pub")?
            .to_string(),
        handshake_sig: v["handshake_sig"]
            .as_str()
            .ok_or("missing handshake_sig")?
            .to_string(),
        handshake_expires_at: v["handshake_expires_at"]
            .as_u64()
            .ok_or("missing handshake_expires_at")?,
    })
}

fn verified_card_keys(card: &ContactCard) -> Result<([u8; 32], [u8; 32]), String> {
    let ops_pub = parse_hex32(&card.ops_pub, "ops_pub")?;
    let hs_pub = parse_hex32(&card.handshake_pub, "handshake_pub")?;

    let sig_msg = handshake_sig_message(&hs_pub, card.handshake_expires_at);
    let sig = parse_hex64(&card.handshake_sig, "handshake_sig")?;
    if !PublicKey(ops_pub).verify(&sig_msg, &sig) {
        return Err("handshake key signature verification failed".to_string());
    }

    Ok((ops_pub, hs_pub))
}

fn build_agent_envelope(
    identity: &IdentityFile,
    draft: AgentEnvelopeDraft,
) -> Result<AgentEnvelopeV0, String> {
    let ops_pub = parse_hex32(&identity.ops_pub, "ops_pub")?;
    let ops_priv = parse_hex32(&identity.ops_priv, "ops_priv")?;
    let keypair = KeyPair {
        public: ops_pub,
        secret: ops_priv,
    };

    let mut envelope = AgentEnvelopeV0 {
        schema_version: AGENT_ENVELOPE_SCHEMA_VERSION,
        task_id: draft.task_id,
        kind: draft.kind,
        from: draft.from,
        reply_to: draft.reply_to,
        created_at: draft.created_at,
        ttl: draft.ttl,
        body: draft.body,
        sig: String::new(),
    };
    envelope.sig = hex_encode(&keypair.sign(&agent_envelope_signing_bytes(&envelope)));
    Ok(envelope)
}

fn verify_agent_envelope(envelope: &AgentEnvelopeV0) -> Result<(), String> {
    if envelope.schema_version != AGENT_ENVELOPE_SCHEMA_VERSION {
        return Err(format!(
            "unsupported agent envelope schema_version {}",
            envelope.schema_version
        ));
    }
    if envelope.ttl == 0 {
        return Err("agent envelope ttl must be greater than zero".to_string());
    }
    if envelope.ttl > MAX_AGENT_ENVELOPE_TTL_SECS {
        return Err(format!(
            "agent envelope ttl exceeds max {} seconds",
            MAX_AGENT_ENVELOPE_TTL_SECS
        ));
    }

    verified_card_keys(&envelope.from).map_err(|e| format!("sender card: {e}"))?;
    let from_ops_pub = parse_hex32(&envelope.from.ops_pub, "from.ops_pub")?;
    let sig = parse_hex64(&envelope.sig, "sig")?;
    if !PublicKey(from_ops_pub).verify(&agent_envelope_signing_bytes(envelope), &sig) {
        return Err("agent envelope signature verification failed".to_string());
    }

    Ok(())
}

fn agent_envelope_time_status(envelope: &AgentEnvelopeV0, now: u64) -> AgentEnvelopeTimeStatus {
    if envelope.created_at > now.saturating_add(MAX_AGENT_ENVELOPE_FUTURE_SKEW_SECS) {
        return AgentEnvelopeTimeStatus::Invalid(format!(
            "agent envelope created_at is more than {} seconds in the future",
            MAX_AGENT_ENVELOPE_FUTURE_SKEW_SECS
        ));
    }

    let Some(expires_at) = envelope.created_at.checked_add(envelope.ttl) else {
        return AgentEnvelopeTimeStatus::Invalid("agent envelope expiry overflow".to_string());
    };

    if now > expires_at {
        AgentEnvelopeTimeStatus::Expired
    } else {
        AgentEnvelopeTimeStatus::Current { expires_at }
    }
}

fn agent_envelope_signing_bytes(envelope: &AgentEnvelopeV0) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(AGENT_ENVELOPE_SIGNING_DOMAIN);
    push_u16(&mut out, envelope.schema_version);
    push_str(&mut out, &envelope.task_id);
    push_str(&mut out, &envelope.kind);
    push_contact_card(&mut out, &envelope.from);
    push_reply_to(&mut out, &envelope.reply_to);
    push_u64(&mut out, envelope.created_at);
    push_u64(&mut out, envelope.ttl);
    push_str(&mut out, &envelope.body);
    out
}

fn push_contact_card(out: &mut Vec<u8>, card: &ContactCard) {
    push_str(out, &card.ops_pub);
    push_str(out, &card.handshake_pub);
    push_str(out, &card.handshake_sig);
    push_u64(out, card.handshake_expires_at);
}

fn push_reply_to(out: &mut Vec<u8>, reply_to: &AgentReplyTo) {
    push_u64(out, reply_to.relays.len() as u64);
    for relay in &reply_to.relays {
        push_str(out, relay);
    }
    push_str(out, &reply_to.mailbox);
}

fn push_str(out: &mut Vec<u8>, value: &str) {
    push_u64(out, value.len() as u64);
    out.extend_from_slice(value.as_bytes());
}

fn push_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn push_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_le_bytes());
}

impl SeenTaskStore {
    fn open(dir: PathBuf, now: u64) -> Result<Self, String> {
        std::fs::create_dir_all(&dir).map_err(|e| format!("create seen-task dir: {e}"))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
                .map_err(|e| format!("restrict seen-task dir permissions: {e}"))?;
        }
        let salt = load_or_create_seen_salt(&dir)?;
        let store = Self { dir, salt };
        store.purge_expired(now)?;
        Ok(store)
    }

    fn claim(&self, sender_ops_pub: &str, task_id: &str, expires_at: u64) -> std::io::Result<bool> {
        let path = self.task_path(sender_ops_pub, task_id);
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
        {
            Ok(mut file) => {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
                }
                file.write_all(&expires_at.to_le_bytes())?;
                file.sync_all()?;
                Ok(true)
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(false),
            Err(e) => Err(e),
        }
    }

    fn purge_expired(&self, now: u64) -> Result<(), String> {
        let entries =
            std::fs::read_dir(&self.dir).map_err(|e| format!("read seen-task dir: {e}"))?;
        for entry in entries {
            let entry = entry.map_err(|e| format!("read seen-task entry: {e}"))?;
            let path = entry.path();
            if path.file_name().and_then(|n| n.to_str()) == Some(AGENT_SEEN_SALT_FILE) {
                continue;
            }
            if path.extension().and_then(|e| e.to_str()) != Some("seen") {
                continue;
            }
            let remove = match std::fs::read(&path) {
                Ok(bytes) if bytes.len() == 8 => {
                    let mut arr = [0u8; 8];
                    arr.copy_from_slice(&bytes);
                    now > u64::from_le_bytes(arr)
                }
                Ok(_) | Err(_) => true,
            };
            if remove {
                std::fs::remove_file(&path)
                    .map_err(|e| format!("remove expired seen-task file: {e}"))?;
            }
        }
        Ok(())
    }

    fn task_path(&self, sender_ops_pub: &str, task_id: &str) -> PathBuf {
        let mut material = Vec::new();
        material.extend_from_slice(AGENT_SEEN_TASK_DOMAIN);
        material.extend_from_slice(&self.salt);
        push_str(&mut material, sender_ops_pub);
        push_str(&mut material, task_id);
        let digest = blake3::hash(&material).to_hex().to_string();
        self.dir.join(format!("{digest}.seen"))
    }
}

fn default_agent_seen_dir(identity_path: &str) -> PathBuf {
    PathBuf::from(format!("{identity_path}.agent-seen"))
}

fn load_or_create_seen_salt(dir: &Path) -> Result<[u8; 32], String> {
    let path = dir.join(AGENT_SEEN_SALT_FILE);
    match read_seen_salt(&path) {
        Ok(salt) => Ok(salt),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => create_seen_salt(&path),
        Err(e) => Err(format!("read seen-task salt: {e}")),
    }
}

fn read_seen_salt(path: &Path) -> std::io::Result<[u8; 32]> {
    let mut file = std::fs::File::open(path)?;
    if file.metadata()?.len() != 32 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "invalid seen-task salt length",
        ));
    }
    let mut salt = [0u8; 32];
    file.read_exact(&mut salt)?;
    Ok(salt)
}

fn create_seen_salt(path: &Path) -> Result<[u8; 32], String> {
    let mut salt = [0u8; 32];
    OsRng.fill_bytes(&mut salt);
    match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
    {
        Ok(mut file) => {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                file.set_permissions(std::fs::Permissions::from_mode(0o600))
                    .map_err(|e| format!("restrict seen-task salt permissions: {e}"))?;
            }
            file.write_all(&salt)
                .map_err(|e| format!("write seen-task salt: {e}"))?;
            file.sync_all()
                .map_err(|e| format!("sync seen-task salt: {e}"))?;
            Ok(salt)
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            read_seen_salt(path).map_err(|e| format!("read seen-task salt: {e}"))
        }
        Err(e) => Err(format!("create seen-task salt: {e}")),
    }
}

fn parse_hex32(hex: &str, field: &str) -> Result<[u8; 32], String> {
    let bytes = hex_decode(hex).map_err(|e| format!("{field}: {e}"))?;
    if bytes.len() != 32 {
        return Err(format!("{field}: expected 32 bytes, got {}", bytes.len()));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

fn parse_hex64(hex: &str, field: &str) -> Result<[u8; 64], String> {
    let bytes = hex_decode(hex).map_err(|e| format!("{field}: {e}"))?;
    if bytes.len() != 64 {
        return Err(format!("{field}: expected 64 bytes, got {}", bytes.len()));
    }
    let mut arr = [0u8; 64];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

fn now_secs() -> Result<u64, String> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| format!("system time before unix epoch: {e}"))
        .map(|d| d.as_secs())
}

fn write_secret_file(path: &str, contents: &[u8]) -> std::io::Result<()> {
    let file = std::fs::File::create(path)?;

    // Restrict permissions to owner-read-write only (Unix 0600).
    // This is a best-effort dev-harness safety measure — not a production keystore.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }

    let mut writer = std::io::BufWriter::new(file);
    writer.write_all(contents)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    fn test_identity() -> IdentityFile {
        let ops_kp = KeyPair::generate();
        let (hs_priv, hs_pub) = x25519_generate_keypair();
        let expires_at = 1_000_000;
        let sig = ops_kp.sign(&handshake_sig_message(&hs_pub, expires_at));
        IdentityFile {
            ops_pub: hex_encode(&ops_kp.public),
            ops_priv: hex_encode(&ops_kp.secret),
            handshake_pub: hex_encode(&hs_pub),
            handshake_priv: hex_encode(&hs_priv),
            handshake_sig: hex_encode(&sig),
            handshake_expires_at: expires_at,
        }
    }

    #[test]
    fn collect_relays_gathers_repeated_flag() {
        let a = args(&["--relay", "127.0.0.1:7700", "--relay", "127.0.0.1:7701"]);
        assert_eq!(
            collect_relays(&a).unwrap(),
            vec!["127.0.0.1:7700", "127.0.0.1:7701"]
        );
    }

    #[test]
    fn collect_relays_single_flag_still_works() {
        let a = args(&[
            "--identity",
            "x.key",
            "--relay",
            "127.0.0.1:7700",
            "--mailbox",
            "abc",
        ]);
        assert_eq!(collect_relays(&a).unwrap(), vec!["127.0.0.1:7700"]);
    }

    #[test]
    fn collect_relays_errors_when_absent() {
        let a = args(&["--identity", "x.key"]);
        assert!(collect_relays(&a).is_err());
    }

    #[test]
    fn collect_relays_errors_on_missing_value() {
        let a = args(&["--relay"]);
        assert!(collect_relays(&a).is_err());
    }

    #[test]
    fn collect_required_values_gathers_repeated_flag() {
        let a = args(&["--reply-relay", "a", "--reply-relay", "b"]);
        assert_eq!(
            collect_required_values(&a, "--reply-relay").unwrap(),
            vec!["a", "b"]
        );
    }

    #[test]
    fn agent_envelope_signature_verifies_and_rejects_tamper() {
        let identity = test_identity();
        let from = contact_card_from_identity(&identity);
        let mut envelope = build_agent_envelope(
            &identity,
            AgentEnvelopeDraft {
                task_id: "task-1".to_string(),
                kind: "echo".to_string(),
                from,
                reply_to: AgentReplyTo {
                    relays: vec!["127.0.0.1:7700".to_string()],
                    mailbox: "a".repeat(64),
                },
                created_at: 1_000,
                ttl: 60,
                body: "hello".to_string(),
            },
        )
        .unwrap();

        verify_agent_envelope(&envelope).unwrap();
        envelope.body = "tampered".to_string();
        assert!(verify_agent_envelope(&envelope).is_err());
    }

    #[test]
    fn agent_envelope_expiry_is_receiver_enforced() {
        let identity = test_identity();
        let mut envelope = build_agent_envelope(
            &identity,
            AgentEnvelopeDraft {
                task_id: "task-2".to_string(),
                kind: "echo".to_string(),
                from: contact_card_from_identity(&identity),
                reply_to: AgentReplyTo {
                    relays: vec!["127.0.0.1:7700".to_string()],
                    mailbox: "b".repeat(64),
                },
                created_at: 1_000,
                ttl: 10,
                body: "hello".to_string(),
            },
        )
        .unwrap();

        assert!(matches!(
            agent_envelope_time_status(&envelope, 1_010),
            AgentEnvelopeTimeStatus::Current { .. }
        ));
        assert!(matches!(
            agent_envelope_time_status(&envelope, 1_011),
            AgentEnvelopeTimeStatus::Expired
        ));

        envelope.created_at = 1_500;
        assert!(matches!(
            agent_envelope_time_status(&envelope, 1_000),
            AgentEnvelopeTimeStatus::Invalid(_)
        ));
    }

    #[test]
    fn agent_envelope_rejects_oversized_ttl() {
        let identity = test_identity();
        let envelope = build_agent_envelope(
            &identity,
            AgentEnvelopeDraft {
                task_id: "task-3".to_string(),
                kind: "echo".to_string(),
                from: contact_card_from_identity(&identity),
                reply_to: AgentReplyTo {
                    relays: vec!["127.0.0.1:7700".to_string()],
                    mailbox: "c".repeat(64),
                },
                created_at: 1_000,
                ttl: MAX_AGENT_ENVELOPE_TTL_SECS + 1,
                body: "hello".to_string(),
            },
        )
        .unwrap();

        assert!(verify_agent_envelope(&envelope).is_err());
    }
}
