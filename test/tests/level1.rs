// Phase 41 — Level 1: Multi-process localhost exchange
//
// Proves that the proven Trial 0 cryptographic exchange works across separate
// OS processes (scp-relay + scp-cli), not only inside a single Rust test process.
//
// Three logical actors:
//   1. scp-relay       — standalone relay daemon process
//   2. scp-cli (A)     — sender endpoint
//   3. scp-cli (B)     — receiver endpoint
//
// Pass condition (LEVEL_1_LOCALHOST_MULTI_PROCESS_EXCHANGE_PROVEN):
//   B's `receive` output contains the exact plaintext sent by A,
//   in a `payload_decrypted` JSON event with no vocabulary labels.
//
// Claims proven:
//   - Binaries compile and start from the workspace target directory
//   - scp-relay wire protocol (store/poll) is correctly exercised across process boundaries
//   - A → relay → B encrypted exchange delivers and decrypts the exact payload
//   - Wrong mailbox token produces no bursts at receive
//   - Relay restart clears in-memory mailbox contents
//   - Opt-in durable relay storage survives restart and drains once
//   - Durable queue filenames do not expose raw mailbox tokens
//   - No vocabulary labels (Active, Warm, Dormant, Suspended, Severed, Burned) in output
//
// Claims NOT proven here:
//   - LAN or multi-machine deployment
//   - TLS or Noise encryption of relay transport (localhost only)
//   - Identity persistence durability
//   - ProviderPool/telemetry integration

use scp_transport::harness::DevMailboxId;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::Command;

// ── Binary paths ─────────────────────────────────────────────────────────────

fn workspace_bin(name: &str) -> PathBuf {
    // Integration test binary: target/debug/deps/<name>-<hash>
    // Workspace binaries:      target/debug/<name>
    let mut p = std::env::current_exe().expect("current_exe must succeed");
    p.pop(); // strip binary filename
    p.pop(); // strip "deps"
    p.push(name);
    p
}

fn relay_bin() -> PathBuf {
    workspace_bin("scp-relay")
}
fn cli_bin() -> PathBuf {
    workspace_bin("scp-cli")
}

fn bins_exist() -> bool {
    relay_bin().exists() && cli_bin().exists()
}

// ── Free port ─────────────────────────────────────────────────────────────────

fn free_port() -> u16 {
    // Bind port 0, let the OS assign, then release; relay will claim it shortly after.
    let l = TcpListener::bind("127.0.0.1:0").expect("bind must succeed");
    l.local_addr().unwrap().port()
}

// ── Temp dir ──────────────────────────────────────────────────────────────────

fn test_tmp_dir(suffix: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("scp-level1-{suffix}"));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

fn cleanup(dir: &PathBuf) {
    let _ = std::fs::remove_dir_all(dir);
}

fn durable_mailbox_files(dir: &Path) -> Vec<String> {
    let mut files: Vec<String> = std::fs::read_dir(dir)
        .expect("read durable relay store dir")
        .filter_map(|entry| {
            let entry = entry.ok()?;
            let name = entry.file_name().into_string().ok()?;
            name.ends_with(".mbox").then_some(name)
        })
        .collect();
    files.sort();
    files
}

fn durable_mailbox_bytes(dir: &Path) -> Vec<u8> {
    let mut bytes = Vec::new();
    for name in durable_mailbox_files(dir) {
        let path = dir.join(name);
        bytes.extend(std::fs::read(path).expect("read durable relay mailbox file"));
    }
    bytes
}

fn bytes_contain(haystack: &[u8], needle: &str) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle.as_bytes())
}

// ── Wait for relay to be ready ────────────────────────────────────────────────

async fn wait_for_relay(port: u16) {
    for _ in 0..50 {
        if tokio::net::TcpStream::connect(format!("127.0.0.1:{port}"))
            .await
            .is_ok()
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("relay on port {port} did not become ready within 2.5 seconds");
}

async fn relay_store_raw(port: u16, mailbox_hex: &str, payload: &[u8]) {
    let mailbox = DevMailboxId::from_hex(mailbox_hex).expect("mailbox hex must parse");
    let mut stream = tokio::net::TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .expect("connect to relay for raw store");
    stream.write_all(&[0x01]).await.expect("write store cmd");
    stream
        .write_all(&mailbox.0)
        .await
        .expect("write mailbox token");
    stream
        .write_all(&(payload.len() as u32).to_le_bytes())
        .await
        .expect("write raw payload len");
    stream.write_all(payload).await.expect("write raw payload");
    let mut ack = [0u8; 1];
    stream.read_exact(&mut ack).await.expect("read store ack");
    assert_eq!(ack, [0x00], "relay raw store must ack");
}

// ── CLI helpers ───────────────────────────────────────────────────────────────

async fn cli_run(args: &[&str]) -> (bool, String) {
    let out = Command::new(cli_bin())
        .args(args)
        .output()
        .await
        .expect("cli invocation must succeed");
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    (out.status.success(), stdout)
}

fn extract_json_field(json_line: &str, field: &str) -> Option<String> {
    let v: serde_json::Value = serde_json::from_str(json_line.trim()).ok()?;
    v[field].as_str().map(|s| s.to_string())
}

fn extract_mailbox_id(output: &str) -> String {
    // Output is one compact JSON line per event.
    for line in output.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Some(id) = extract_json_field(line, "mailbox_id") {
            return id;
        }
    }
    // Fallback: parse entire output as a single JSON object (handles edge cases).
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(output.trim()) {
        if let Some(id) = v["mailbox_id"].as_str() {
            return id.to_string();
        }
    }
    panic!("mailbox_id not found in output:\n{output}");
}

fn contains_vocabulary_label(text: &str) -> bool {
    let labels = [
        "Active",
        "Warm",
        "Dormant",
        "Suspended",
        "Severed",
        "Burned",
    ];
    labels.iter().any(|&l| text.contains(l))
}

// ── Test 1: Full A → relay → B encrypted exchange ────────────────────────────

#[tokio::test]
async fn level1_multiprocess_exchange_full_flow() {
    if !bins_exist() {
        eprintln!("SKIP: run `cargo build` first (scp-relay or scp-cli not found)");
        return;
    }

    let port = free_port();
    let tmp = test_tmp_dir(&format!("{port}a"));

    // Start relay.
    let mut relay = Command::new(relay_bin())
        .arg("--bind")
        .arg(format!("127.0.0.1:{port}"))
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("relay spawn must succeed");

    wait_for_relay(port).await;

    let alice_key = tmp.join("alice.key");
    let bob_key = tmp.join("bob.key");
    let bob_card = tmp.join("bob.card");

    // keygen for Alice and Bob.
    let (ok, _) = cli_run(&["keygen", "--out", alice_key.to_str().unwrap()]).await;
    assert!(ok, "alice keygen must succeed");

    let (ok, bob_card_output) = cli_run(&["keygen", "--out", bob_key.to_str().unwrap()]).await;
    assert!(ok, "bob keygen must succeed");

    // Save Bob's card JSON (the stdout of keygen is the public card event).
    std::fs::write(&bob_card, &bob_card_output).expect("write bob card");

    // Generate a mailbox ID.
    let (ok, mailbox_output) = cli_run(&["mailbox-new"]).await;
    assert!(ok, "mailbox-new must succeed");
    let mailbox_id = extract_mailbox_id(&mailbox_output);

    // A sends to relay under the mailbox token.
    let relay_addr = format!("127.0.0.1:{port}");
    let (ok, send_output) = cli_run(&[
        "send",
        "--identity",
        alice_key.to_str().unwrap(),
        "--recipient",
        bob_card.to_str().unwrap(),
        "--relay",
        &relay_addr,
        "--mailbox",
        &mailbox_id,
        "--message",
        "hello scp level1",
    ])
    .await;
    assert!(ok, "send must succeed\nsend output: {send_output}");
    assert!(
        send_output.contains("burst_stored"),
        "send output must confirm burst_stored"
    );

    // B polls relay and decrypts.
    let (ok, recv_output) = cli_run(&[
        "receive",
        "--identity",
        bob_key.to_str().unwrap(),
        "--relay",
        &relay_addr,
        "--mailbox",
        &mailbox_id,
    ])
    .await;
    assert!(ok, "receive must succeed\nrecv output: {recv_output}");

    // Plaintext equality.
    assert!(
        recv_output.contains("hello scp level1"),
        "decrypted plaintext must match sent message\nrecv: {recv_output}"
    );

    // exchange_complete event must appear.
    assert!(
        recv_output.contains("exchange_complete"),
        "exchange_complete must appear"
    );

    // No vocabulary labels anywhere in any output.
    for output in &[send_output, recv_output, mailbox_output, bob_card_output] {
        assert!(
            !contains_vocabulary_label(output),
            "output must not contain vocabulary labels: {output}"
        );
    }

    relay.kill().await.ok();
    cleanup(&tmp);
}

// ── Test 2: Wrong mailbox token produces empty receive ────────────────────────

#[tokio::test]
async fn level1_wrong_mailbox_token_produces_empty_receive() {
    if !bins_exist() {
        return;
    }

    let port = free_port();
    let tmp = test_tmp_dir(&format!("{port}b"));

    let mut relay = Command::new(relay_bin())
        .arg("--bind")
        .arg(format!("127.0.0.1:{port}"))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("relay spawn");
    wait_for_relay(port).await;

    let alice_key = tmp.join("alice.key");
    let bob_key = tmp.join("bob.key");
    let bob_card = tmp.join("bob.card");

    let (_, _) = cli_run(&["keygen", "--out", alice_key.to_str().unwrap()]).await;
    let (_, bob_out) = cli_run(&["keygen", "--out", bob_key.to_str().unwrap()]).await;
    std::fs::write(&bob_card, &bob_out).unwrap();

    // Send under the correct mailbox token.
    let (_, mailbox_out) = cli_run(&["mailbox-new"]).await;
    let correct_id = extract_mailbox_id(&mailbox_out);

    let relay_addr = format!("127.0.0.1:{port}");
    cli_run(&[
        "send",
        "--identity",
        alice_key.to_str().unwrap(),
        "--recipient",
        bob_card.to_str().unwrap(),
        "--relay",
        &relay_addr,
        "--mailbox",
        &correct_id,
        "--message",
        "wrong token test",
    ])
    .await;

    // B polls with a DIFFERENT mailbox token.
    let (_, wrong_out) = cli_run(&["mailbox-new"]).await;
    let wrong_id = extract_mailbox_id(&wrong_out);

    let (ok, recv_output) = cli_run(&[
        "receive",
        "--identity",
        bob_key.to_str().unwrap(),
        "--relay",
        &relay_addr,
        "--mailbox",
        &wrong_id,
    ])
    .await;
    assert!(ok, "receive with wrong token must exit cleanly");
    // Should see exchange_complete with count 0.
    assert!(
        recv_output.contains("\"count\":0"),
        "wrong token must yield empty receive; got: {recv_output}"
    );
    assert!(
        !recv_output.contains("payload_decrypted"),
        "wrong token must not produce any decrypted payloads"
    );

    relay.kill().await.ok();
    cleanup(&tmp);
}

// ── Test 3: Relay restart clears mailbox contents ─────────────────────────────

#[tokio::test]
async fn level1_relay_restart_clears_mailbox() {
    if !bins_exist() {
        return;
    }

    let port = free_port();
    let tmp = test_tmp_dir(&format!("{port}c"));

    let mut relay = Command::new(relay_bin())
        .arg("--bind")
        .arg(format!("127.0.0.1:{port}"))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("relay spawn");
    wait_for_relay(port).await;

    let alice_key = tmp.join("alice.key");
    let bob_key = tmp.join("bob.key");
    let bob_card = tmp.join("bob.card");

    let (_, _) = cli_run(&["keygen", "--out", alice_key.to_str().unwrap()]).await;
    let (_, bob_out) = cli_run(&["keygen", "--out", bob_key.to_str().unwrap()]).await;
    std::fs::write(&bob_card, &bob_out).unwrap();

    let (_, mailbox_out) = cli_run(&["mailbox-new"]).await;
    let mailbox_id = extract_mailbox_id(&mailbox_out);

    let relay_addr = format!("127.0.0.1:{port}");
    cli_run(&[
        "send",
        "--identity",
        alice_key.to_str().unwrap(),
        "--recipient",
        bob_card.to_str().unwrap(),
        "--relay",
        &relay_addr,
        "--mailbox",
        &mailbox_id,
        "--message",
        "restart test",
    ])
    .await;

    // Kill relay — all in-memory bursts are lost (documented limitation).
    relay.kill().await.ok();
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Restart relay on the same port.
    let mut relay2 = Command::new(relay_bin())
        .arg("--bind")
        .arg(format!("127.0.0.1:{port}"))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("relay2 spawn");
    wait_for_relay(port).await;

    // B polls after restart — mailbox should be empty.
    let (ok, recv_output) = cli_run(&[
        "receive",
        "--identity",
        bob_key.to_str().unwrap(),
        "--relay",
        &relay_addr,
        "--mailbox",
        &mailbox_id,
    ])
    .await;
    assert!(ok, "receive after restart must exit cleanly");
    assert!(
        recv_output.contains("\"count\":0"),
        "relay restart must clear all mailbox contents; got: {recv_output}"
    );

    relay2.kill().await.ok();
    cleanup(&tmp);
}

// ── Test 4: Opt-in durable relay survives restart and drains once ─────────────

#[tokio::test]
async fn level1_durable_relay_survives_restart_when_store_dir_set() {
    if !bins_exist() {
        return;
    }

    let port = free_port();
    let tmp = test_tmp_dir(&format!("{port}durable"));
    let store_dir = tmp.join("relay-store");

    let mut relay = Command::new(relay_bin())
        .arg("--bind")
        .arg(format!("127.0.0.1:{port}"))
        .arg("--store-dir")
        .arg(&store_dir)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("durable relay spawn");
    wait_for_relay(port).await;

    let alice_key = tmp.join("alice.key");
    let bob_key = tmp.join("bob.key");
    let bob_card = tmp.join("bob.card");

    let (_, _) = cli_run(&["keygen", "--out", alice_key.to_str().unwrap()]).await;
    let (_, bob_out) = cli_run(&["keygen", "--out", bob_key.to_str().unwrap()]).await;
    std::fs::write(&bob_card, &bob_out).unwrap();

    let (_, mailbox_out) = cli_run(&["mailbox-new"]).await;
    let mailbox_id = extract_mailbox_id(&mailbox_out);
    let relay_addr = format!("127.0.0.1:{port}");

    let (ok, send_output) = cli_run(&[
        "send",
        "--identity",
        alice_key.to_str().unwrap(),
        "--recipient",
        bob_card.to_str().unwrap(),
        "--relay",
        &relay_addr,
        "--mailbox",
        &mailbox_id,
        "--message",
        "durable restart test",
    ])
    .await;
    assert!(
        ok,
        "send to durable relay must succeed\nsend: {send_output}"
    );

    let durable_files = durable_mailbox_files(&store_dir);
    let legacy_filename = format!("{mailbox_id}.mbox");
    assert_eq!(
        durable_files.len(),
        1,
        "durable relay must write one queue file before restart; files: {durable_files:?}"
    );
    assert!(
        !durable_files.iter().any(|name| name == &legacy_filename),
        "durable queue filename must not expose raw mailbox token; files: {durable_files:?}"
    );

    relay.kill().await.ok();
    tokio::time::sleep(Duration::from_millis(100)).await;

    let mut relay2 = Command::new(relay_bin())
        .arg("--bind")
        .arg(format!("127.0.0.1:{port}"))
        .arg("--store-dir")
        .arg(&store_dir)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("durable relay2 spawn");
    wait_for_relay(port).await;

    let (ok, recv_output) = cli_run(&[
        "receive",
        "--identity",
        bob_key.to_str().unwrap(),
        "--relay",
        &relay_addr,
        "--mailbox",
        &mailbox_id,
    ])
    .await;
    assert!(ok, "receive after durable restart must succeed");
    assert!(
        recv_output.contains("durable restart test"),
        "durable relay must deliver queued payload after restart; got: {recv_output}"
    );
    assert!(
        recv_output.contains("\"count\":1"),
        "durable relay must report one delivered burst; got: {recv_output}"
    );

    let (ok, recv_again) = cli_run(&[
        "receive",
        "--identity",
        bob_key.to_str().unwrap(),
        "--relay",
        &relay_addr,
        "--mailbox",
        &mailbox_id,
    ])
    .await;
    assert!(ok, "second receive after durable drain must succeed");
    assert!(
        recv_again.contains("\"count\":0"),
        "durable mailbox must drain exactly once; got: {recv_again}"
    );
    assert!(
        durable_mailbox_files(&store_dir).is_empty(),
        "durable mailbox file must be removed after drain"
    );

    relay2.kill().await.ok();
    cleanup(&tmp);
}

// ── Test 5: Signed agent envelope survives durable restart ────────────────────

#[tokio::test]
async fn level1_agent_envelope_durable_flow_authenticates_sender() {
    if !bins_exist() {
        return;
    }

    let port = free_port();
    let tmp = test_tmp_dir(&format!("{port}agent"));
    let store_dir = tmp.join("relay-store");

    let mut relay = Command::new(relay_bin())
        .arg("--bind")
        .arg(format!("127.0.0.1:{port}"))
        .arg("--store-dir")
        .arg(&store_dir)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("agent durable relay spawn");
    wait_for_relay(port).await;

    let alice_key = tmp.join("alice.key");
    let alice_card = tmp.join("alice.card");
    let mallory_key = tmp.join("mallory.key");
    let mallory_card = tmp.join("mallory.card");
    let bob_key = tmp.join("bob.key");
    let bob_card = tmp.join("bob.card");

    let (_, alice_out) = cli_run(&["keygen", "--out", alice_key.to_str().unwrap()]).await;
    std::fs::write(&alice_card, &alice_out).unwrap();
    let alice_ops_pub = extract_json_field(&alice_out, "ops_pub").expect("alice ops_pub");
    let (_, mallory_out) = cli_run(&["keygen", "--out", mallory_key.to_str().unwrap()]).await;
    std::fs::write(&mallory_card, &mallory_out).unwrap();
    let (_, bob_out) = cli_run(&["keygen", "--out", bob_key.to_str().unwrap()]).await;
    std::fs::write(&bob_card, &bob_out).unwrap();

    let (_, mailbox_out) = cli_run(&["mailbox-new"]).await;
    let mailbox_id = extract_mailbox_id(&mailbox_out);
    let (_, reply_mailbox_out) = cli_run(&["mailbox-new"]).await;
    let reply_mailbox = extract_mailbox_id(&reply_mailbox_out);
    let relay_addr = format!("127.0.0.1:{port}");
    let task_id = "agent-task-live-2026-07-05";
    let body = "agent-envelope-body-not-relay-visible-2026-07-05";
    let action_dir = tmp.join("agent-actions");

    relay_store_raw(port, &mailbox_id, b"not-cbor-agent-burst").await;

    let (ok, send_output) = cli_run(&[
        "agent-send",
        "--identity",
        alice_key.to_str().unwrap(),
        "--recipient",
        bob_card.to_str().unwrap(),
        "--relay",
        &relay_addr,
        "--mailbox",
        &mailbox_id,
        "--task-id",
        task_id,
        "--kind",
        "echo",
        "--reply-relay",
        &relay_addr,
        "--reply-mailbox",
        &reply_mailbox,
        "--ttl-secs",
        "3600",
        "--body",
        body,
    ])
    .await;
    assert!(ok, "agent-send must succeed\nsend: {send_output}");
    assert!(
        send_output.contains("\"event\":\"agent_burst_replicated\""),
        "agent-send must report replication summary: {send_output}"
    );
    assert!(
        send_output.contains("\"count\":1"),
        "single durable relay should store one agent burst: {send_output}"
    );

    let durable_files = durable_mailbox_files(&store_dir);
    assert_eq!(
        durable_files.len(),
        1,
        "agent envelope must be queued in exactly one durable mailbox file: {durable_files:?}"
    );
    let durable_bytes = durable_mailbox_bytes(&store_dir);
    for forbidden_plaintext in [task_id, body, "echo", &alice_ops_pub, &reply_mailbox] {
        assert!(
            !bytes_contain(&durable_bytes, forbidden_plaintext),
            "durable relay file must not expose agent envelope plaintext: {forbidden_plaintext}"
        );
    }

    relay.kill().await.ok();
    tokio::time::sleep(Duration::from_millis(100)).await;

    let mut relay2 = Command::new(relay_bin())
        .arg("--bind")
        .arg(format!("127.0.0.1:{port}"))
        .arg("--store-dir")
        .arg(&store_dir)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("agent durable relay2 spawn");
    wait_for_relay(port).await;

    let (ok, recv_output) = cli_run(&[
        "agent-receive",
        "--identity",
        bob_key.to_str().unwrap(),
        "--sender",
        alice_card.to_str().unwrap(),
        "--relay",
        &relay_addr,
        "--mailbox",
        &mailbox_id,
    ])
    .await;
    assert!(ok, "agent-receive must succeed\nrecv: {recv_output}");
    assert!(
        recv_output.contains("\"event\":\"agent_message_verified\""),
        "agent-receive must verify a signed envelope: {recv_output}"
    );
    for expected in [task_id, body, &alice_ops_pub, &reply_mailbox] {
        assert!(
            recv_output.contains(expected),
            "verified agent output must contain decrypted field {expected}: {recv_output}"
        );
    }
    assert!(
        recv_output.contains("\"verified\":1"),
        "agent receive summary must count one verified message: {recv_output}"
    );
    assert!(
        recv_output.contains("\"rejected\":1"),
        "agent receive summary must reject only the malformed relay blob: {recv_output}"
    );

    cli_run(&[
        "agent-send",
        "--identity",
        alice_key.to_str().unwrap(),
        "--recipient",
        bob_card.to_str().unwrap(),
        "--relay",
        &relay_addr,
        "--mailbox",
        &mailbox_id,
        "--task-id",
        task_id,
        "--kind",
        "echo",
        "--reply-relay",
        &relay_addr,
        "--reply-mailbox",
        &reply_mailbox,
        "--ttl-secs",
        "3600",
        "--body",
        body,
    ])
    .await;

    let (ok, replay_output) = cli_run(&[
        "agent-receive",
        "--identity",
        bob_key.to_str().unwrap(),
        "--sender",
        alice_card.to_str().unwrap(),
        "--relay",
        &relay_addr,
        "--mailbox",
        &mailbox_id,
    ])
    .await;
    assert!(
        ok,
        "agent-receive of replayed task must exit cleanly\nrecv: {replay_output}"
    );
    assert!(
        replay_output.contains("\"duplicates\":1"),
        "replayed task_id must be rejected by persistent dedup: {replay_output}"
    );
    assert!(
        replay_output.contains("\"verified\":0"),
        "replayed task_id must not verify again: {replay_output}"
    );

    let task_id_recovery = "agent-task-reserve-recover-2026-07-05";
    let recovery_body = "journaled-action-body-2026-07-05";
    cli_run(&[
        "agent-send",
        "--identity",
        alice_key.to_str().unwrap(),
        "--recipient",
        bob_card.to_str().unwrap(),
        "--relay",
        &relay_addr,
        "--mailbox",
        &mailbox_id,
        "--task-id",
        task_id_recovery,
        "--kind",
        "echo",
        "--reply-relay",
        &relay_addr,
        "--reply-mailbox",
        &reply_mailbox,
        "--ttl-secs",
        "3600",
        "--body",
        recovery_body,
    ])
    .await;

    let (ok, reserve_only_output) = cli_run(&[
        "agent-receive",
        "--identity",
        bob_key.to_str().unwrap(),
        "--sender",
        alice_card.to_str().unwrap(),
        "--relay",
        &relay_addr,
        "--mailbox",
        &mailbox_id,
        "--reserve-only",
    ])
    .await;
    assert!(
        ok,
        "reserve-only receive must exit cleanly\nrecv: {reserve_only_output}"
    );
    assert!(
        reserve_only_output.contains("\"event\":\"agent_task_reserved\""),
        "reserve-only receive must journal the task before action: {reserve_only_output}"
    );
    assert!(
        reserve_only_output.contains("\"verified\":0"),
        "reserve-only receive must not execute the task: {reserve_only_output}"
    );
    assert!(
        reserve_only_output.contains("\"acked\":0"),
        "reserve-only receive must leave the task unacked: {reserve_only_output}"
    );

    let (ok, recovered_output) = cli_run(&[
        "agent-receive",
        "--identity",
        bob_key.to_str().unwrap(),
        "--sender",
        alice_card.to_str().unwrap(),
        "--relay",
        &relay_addr,
        "--mailbox",
        &mailbox_id,
        "--execute-echo-dir",
        action_dir.to_str().unwrap(),
    ])
    .await;
    assert!(
        ok,
        "journal recovery receive must exit cleanly\nrecv: {recovered_output}"
    );
    for expected in [
        "\"event\":\"agent_task_recovered\"",
        "\"event\":\"agent_message_verified\"",
        "\"event\":\"agent_task_executed\"",
        "\"event\":\"agent_task_acked\"",
        "\"recovered\":1",
        "\"executed\":1",
        "\"acked\":1",
    ] {
        assert!(
            recovered_output.contains(expected),
            "journal recovery output missing {expected}: {recovered_output}"
        );
    }
    let action_files: Vec<_> = std::fs::read_dir(&action_dir)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect();
    assert_eq!(
        action_files.len(),
        1,
        "journal recovery must write exactly one idempotent action file"
    );
    let action_body = std::fs::read_to_string(&action_files[0]).unwrap();
    assert_eq!(
        action_body, recovery_body,
        "journal recovery action file must contain the task body"
    );

    let task_id_wrong_sender = "agent-task-wrong-sender-2026-07-05";
    cli_run(&[
        "agent-send",
        "--identity",
        alice_key.to_str().unwrap(),
        "--recipient",
        bob_card.to_str().unwrap(),
        "--relay",
        &relay_addr,
        "--mailbox",
        &mailbox_id,
        "--task-id",
        task_id_wrong_sender,
        "--kind",
        "echo",
        "--reply-relay",
        &relay_addr,
        "--reply-mailbox",
        &reply_mailbox,
        "--ttl-secs",
        "3600",
        "--body",
        body,
    ])
    .await;

    let (ok, wrong_sender_output) = cli_run(&[
        "agent-receive",
        "--identity",
        bob_key.to_str().unwrap(),
        "--sender",
        mallory_card.to_str().unwrap(),
        "--relay",
        &relay_addr,
        "--mailbox",
        &mailbox_id,
    ])
    .await;
    assert!(
        ok,
        "agent-receive with wrong pinned sender must exit cleanly\nrecv: {wrong_sender_output}"
    );
    assert!(
        wrong_sender_output.contains("\"rejected\":1"),
        "wrong pinned sender must reject the envelope: {wrong_sender_output}"
    );
    assert!(
        wrong_sender_output.contains("sender does not match pinned sender card"),
        "wrong pinned sender reason must be explicit: {wrong_sender_output}"
    );

    let (ok, recv_again) = cli_run(&[
        "agent-receive",
        "--identity",
        bob_key.to_str().unwrap(),
        "--sender",
        alice_card.to_str().unwrap(),
        "--relay",
        &relay_addr,
        "--mailbox",
        &mailbox_id,
    ])
    .await;
    assert!(ok, "second agent-receive must succeed\nrecv: {recv_again}");
    assert!(
        recv_again.contains("\"verified\":0"),
        "agent durable mailbox must drain exactly once: {recv_again}"
    );

    relay2.kill().await.ok();
    cleanup(&tmp);
}

// ── Test 6: No vocabulary labels in any command output ────────────────────────

#[tokio::test]
async fn level1_no_vocabulary_labels_in_output() {
    if !bins_exist() {
        return;
    }

    let port = free_port();
    let tmp = test_tmp_dir(&format!("{port}d"));

    let mut relay = Command::new(relay_bin())
        .arg("--bind")
        .arg(format!("127.0.0.1:{port}"))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("relay spawn");
    wait_for_relay(port).await;

    let alice_key = tmp.join("alice.key");
    let bob_key = tmp.join("bob.key");
    let bob_card = tmp.join("bob.card");

    let (_, alice_out) = cli_run(&["keygen", "--out", alice_key.to_str().unwrap()]).await;
    let (_, bob_out) = cli_run(&["keygen", "--out", bob_key.to_str().unwrap()]).await;
    std::fs::write(&bob_card, &bob_out).unwrap();

    let (_, mb_out) = cli_run(&["mailbox-new"]).await;
    let mailbox_id = extract_mailbox_id(&mb_out);
    let relay_addr = format!("127.0.0.1:{port}");

    let (_, send_out) = cli_run(&[
        "send",
        "--identity",
        alice_key.to_str().unwrap(),
        "--recipient",
        bob_card.to_str().unwrap(),
        "--relay",
        &relay_addr,
        "--mailbox",
        &mailbox_id,
        "--message",
        "vocab test",
    ])
    .await;

    let (_, recv_out) = cli_run(&[
        "receive",
        "--identity",
        bob_key.to_str().unwrap(),
        "--relay",
        &relay_addr,
        "--mailbox",
        &mailbox_id,
    ])
    .await;

    let all_output = format!("{alice_out}{bob_out}{mb_out}{send_out}{recv_out}");
    assert!(
        !contains_vocabulary_label(&all_output),
        "vocabulary labels must not appear in any CLI output:\n{all_output}"
    );

    relay.kill().await.ok();
    cleanup(&tmp);
}
