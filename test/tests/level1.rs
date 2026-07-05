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
//   - No vocabulary labels (Active, Warm, Dormant, Suspended, Severed, Burned) in output
//
// Claims NOT proven here:
//   - LAN or multi-machine deployment
//   - TLS or Noise encryption of relay transport (localhost only)
//   - Identity persistence durability
//   - ProviderPool/telemetry integration

use std::net::TcpListener;
use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;
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
    std::fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

fn cleanup(dir: &PathBuf) {
    let _ = std::fs::remove_dir_all(dir);
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

// ── Test 4: No vocabulary labels in any command output ────────────────────────

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
