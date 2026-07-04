// Multi-Relay Failover — Phase 4 (Option 2, localhost)
//
// See docs/architecture/PROVIDERPOOL_MULTIRELAY_ARCHITECTURE_DESIGN.md §4/§6
// (ADR verdict B — OPTION_2_ROUTING_SEAM_AUTHORIZED) and
// docs/architecture/PROVIDERPOOL_REAL_NETWORK_LIVENESS_TRIAL_PLAN.md (Option 1,
// the prerequisite real-network observation trial this builds on).
//
// This is a CLI-level integration test: `scp-cli` is a one-shot process that
// does not print internal ProviderPool/DeliveryPool telemetry to stdout (by
// design — vocabulary-neutral, minimal machine-readable event output only).
// Exact-value kappa/liveness_weighted_kappa assertions were already proven at
// the unit level in provider/delivery/src/lib.rs's own test suite, using the
// identical DeliveryPool code path this CLI calls. This file instead proves
// the OBSERVABLE behavioral claim: real multi-relay replicate-store (R1) and
// poll-any-with-dedup actually deliver and actually survive a real relay kill,
// exercised through real OS processes exactly as test/tests/lan_liveness_trial.rs
// and test/tests/level1.rs already do.
//
// Claims proven:
//   - send --relay A --relay B replicates a real burst to both live relays
//   - receive --relay A --relay B drains exactly one logical message
//     (poll-any + dedup-by-route_id), not two, despite two relays holding it
//   - killing one relay for real still allows send/receive to succeed via
//     the surviving relay (partial success = success, matching the ADR's
//     "liveness changes WHERE, never WHETHER" principle)
//   - no vocabulary labels in any multi-relay CLI output
//
// Explicit non-claims:
//   - Exact ProviderPool/DeliveryPool telemetry values (proven at the unit
//     level in provider/delivery/src/lib.rs, not re-asserted here)
//   - Live Tailscale mesh multi-relay failover (Phase 5, #[ignore]'d)
//   - Any change to send/receive cryptographic authorization based on liveness

use std::net::TcpListener;
use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;
use tokio::process::Command;

fn workspace_bin(name: &str) -> PathBuf {
    let mut p = std::env::current_exe().expect("current_exe must succeed");
    p.pop();
    p.pop();
    p.push(name);
    p
}

fn relay_bin() -> PathBuf { workspace_bin("scp-relay") }
fn cli_bin()   -> PathBuf { workspace_bin("scp-cli") }

fn bins_exist() -> bool {
    relay_bin().exists() && cli_bin().exists()
}

fn free_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind must succeed");
    l.local_addr().unwrap().port()
}

fn test_tmp_dir(suffix: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("scp-multirelay-{suffix}"));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

fn cleanup(dir: &PathBuf) {
    let _ = std::fs::remove_dir_all(dir);
}

async fn wait_for_relay(port: u16) {
    for _ in 0..50 {
        if tokio::net::TcpStream::connect(format!("127.0.0.1:{port}")).await.is_ok() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("relay on port {port} did not become ready within 2.5 seconds");
}

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
    for line in output.lines() {
        let line = line.trim();
        if line.is_empty() { continue; }
        if let Some(id) = extract_json_field(line, "mailbox_id") {
            return id;
        }
    }
    panic!("mailbox_id not found in output:\n{output}");
}

fn contains_vocabulary_label(text: &str) -> bool {
    let labels = ["Active", "Warm", "Dormant", "Suspended", "Severed", "Burned"];
    labels.iter().any(|&l| text.contains(l))
}

fn count_occurrences(haystack: &str, needle: &str) -> usize {
    haystack.matches(needle).count()
}

// ── Test 1: replicate-store to both live relays, drain exactly once ─────────

#[tokio::test]
async fn two_live_relays_replicate_store_and_dedup_on_receive() {
    if !bins_exist() {
        eprintln!("SKIP: run `cargo build` first (scp-relay or scp-cli not found)");
        return;
    }

    let tmp = test_tmp_dir("happy");
    let port_a = free_port();
    let port_b = free_port();

    let mut relay_a = Command::new(relay_bin())
        .arg("--bind").arg(format!("127.0.0.1:{port_a}"))
        .stdout(Stdio::null()).stderr(Stdio::null())
        .spawn().expect("relay_a spawn must succeed");
    let mut relay_b = Command::new(relay_bin())
        .arg("--bind").arg(format!("127.0.0.1:{port_b}"))
        .stdout(Stdio::null()).stderr(Stdio::null())
        .spawn().expect("relay_b spawn must succeed");
    wait_for_relay(port_a).await;
    wait_for_relay(port_b).await;
    let addr_a = format!("127.0.0.1:{port_a}");
    let addr_b = format!("127.0.0.1:{port_b}");

    let alice_key = tmp.join("alice.key");
    let bob_key   = tmp.join("bob.key");
    let bob_card  = tmp.join("bob.card");

    let (ok, _) = cli_run(&["keygen", "--out", alice_key.to_str().unwrap()]).await;
    assert!(ok);
    let (ok, bob_out) = cli_run(&["keygen", "--out", bob_key.to_str().unwrap()]).await;
    assert!(ok);
    std::fs::write(&bob_card, &bob_out).unwrap();

    let (ok, mailbox_out) = cli_run(&["mailbox-new"]).await;
    assert!(ok);
    let mailbox_id = extract_mailbox_id(&mailbox_out);

    let (ok, send_out) = cli_run(&[
        "send",
        "--identity", alice_key.to_str().unwrap(),
        "--recipient", bob_card.to_str().unwrap(),
        "--relay", &addr_a,
        "--relay", &addr_b,
        "--mailbox", &mailbox_id,
        "--message", "multirelay happy path",
    ]).await;
    assert!(ok, "send across two live relays must succeed\n{send_out}");
    assert_eq!(
        count_occurrences(&send_out, "\"event\":\"burst_stored\""), 2,
        "R1 replicate-store must store the burst on BOTH live relays: {send_out}"
    );
    assert!(send_out.contains("\"event\":\"burst_replicated\""));
    assert!(send_out.contains("\"count\":2"), "burst_replicated count must be 2: {send_out}");

    let (ok, recv_out) = cli_run(&[
        "receive",
        "--identity", bob_key.to_str().unwrap(),
        "--relay", &addr_a,
        "--relay", &addr_b,
        "--mailbox", &mailbox_id,
    ]).await;
    assert!(ok, "receive across two live relays must succeed\n{recv_out}");
    assert!(recv_out.contains("multirelay happy path"), "plaintext must match: {recv_out}");
    assert_eq!(
        count_occurrences(&recv_out, "\"event\":\"payload_decrypted\""), 1,
        "poll-any + dedup-by-route_id must yield exactly ONE decrypted message, \
         not two, despite the burst being present on both relays: {recv_out}"
    );
    assert!(recv_out.contains("\"count\":1"), "exchange_complete count must be the deduped 1: {recv_out}");

    relay_a.kill().await.ok();
    relay_b.kill().await.ok();
    cleanup(&tmp);
}

// ── Test 2: real relay kill mid-run — survivor still delivers ───────────────

#[tokio::test]
async fn killing_one_of_two_relays_still_delivers_via_the_survivor() {
    if !bins_exist() {
        eprintln!("SKIP: run `cargo build` first (scp-relay or scp-cli not found)");
        return;
    }

    let tmp = test_tmp_dir("failover");
    let port_a = free_port();
    let port_b = free_port();

    let mut relay_a = Command::new(relay_bin())
        .arg("--bind").arg(format!("127.0.0.1:{port_a}"))
        .stdout(Stdio::null()).stderr(Stdio::null())
        .spawn().expect("relay_a spawn must succeed");
    let mut relay_b = Command::new(relay_bin())
        .arg("--bind").arg(format!("127.0.0.1:{port_b}"))
        .stdout(Stdio::null()).stderr(Stdio::null())
        .spawn().expect("relay_b spawn must succeed");
    wait_for_relay(port_a).await;
    wait_for_relay(port_b).await;
    let addr_a = format!("127.0.0.1:{port_a}");
    let addr_b = format!("127.0.0.1:{port_b}");

    let alice_key = tmp.join("alice.key");
    let bob_key   = tmp.join("bob.key");
    let bob_card  = tmp.join("bob.card");
    let (_, _) = cli_run(&["keygen", "--out", alice_key.to_str().unwrap()]).await;
    let (_, bob_out) = cli_run(&["keygen", "--out", bob_key.to_str().unwrap()]).await;
    std::fs::write(&bob_card, &bob_out).unwrap();
    let (_, mailbox_out) = cli_run(&["mailbox-new"]).await;
    let mailbox_id = extract_mailbox_id(&mailbox_out);

    // Kill relay_b for real BEFORE sending — proves failover, not just luck.
    relay_b.kill().await.ok();
    // Give the OS a moment to actually tear down the listening socket.
    for _ in 0..50 {
        if tokio::net::TcpStream::connect(&addr_b).await.is_err() { break; }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    let (ok, send_out) = cli_run(&[
        "send",
        "--identity", alice_key.to_str().unwrap(),
        "--recipient", bob_card.to_str().unwrap(),
        "--relay", &addr_a,
        "--relay", &addr_b,
        "--mailbox", &mailbox_id,
        "--message", "survives one dead relay",
    ]).await;
    assert!(ok, "send must still succeed via the surviving relay (partial success = success)\n{send_out}");
    assert_eq!(
        count_occurrences(&send_out, "\"event\":\"burst_stored\""), 1,
        "only the ONE live relay should confirm storage: {send_out}"
    );
    assert!(send_out.contains("\"count\":1"), "burst_replicated count must reflect only the survivor: {send_out}");

    let (ok, recv_out) = cli_run(&[
        "receive",
        "--identity", bob_key.to_str().unwrap(),
        "--relay", &addr_a,
        "--relay", &addr_b,
        "--mailbox", &mailbox_id,
    ]).await;
    assert!(ok, "receive must still succeed via the surviving relay\n{recv_out}");
    assert!(recv_out.contains("survives one dead relay"), "plaintext must match: {recv_out}");
    assert!(recv_out.contains("\"count\":1"));

    relay_a.kill().await.ok();
    cleanup(&tmp);
}

// ── Test 3: no vocabulary labels anywhere in multi-relay output ─────────────

#[tokio::test]
async fn multirelay_flow_produces_no_vocabulary_labels() {
    if !bins_exist() {
        eprintln!("SKIP: run `cargo build` first (scp-relay or scp-cli not found)");
        return;
    }

    let tmp = test_tmp_dir("novocab");
    let port_a = free_port();
    let port_b = free_port();
    let mut relay_a = Command::new(relay_bin())
        .arg("--bind").arg(format!("127.0.0.1:{port_a}"))
        .stdout(Stdio::null()).stderr(Stdio::null())
        .spawn().expect("relay_a spawn must succeed");
    let mut relay_b = Command::new(relay_bin())
        .arg("--bind").arg(format!("127.0.0.1:{port_b}"))
        .stdout(Stdio::null()).stderr(Stdio::null())
        .spawn().expect("relay_b spawn must succeed");
    wait_for_relay(port_a).await;
    wait_for_relay(port_b).await;
    let addr_a = format!("127.0.0.1:{port_a}");
    let addr_b = format!("127.0.0.1:{port_b}");

    let alice_key = tmp.join("alice.key");
    let bob_key   = tmp.join("bob.key");
    let bob_card  = tmp.join("bob.card");
    let (_, alice_out) = cli_run(&["keygen", "--out", alice_key.to_str().unwrap()]).await;
    let (_, bob_out)   = cli_run(&["keygen", "--out", bob_key.to_str().unwrap()]).await;
    std::fs::write(&bob_card, &bob_out).unwrap();
    let (_, mb_out) = cli_run(&["mailbox-new"]).await;
    let mailbox_id  = extract_mailbox_id(&mb_out);

    let (_, send_out) = cli_run(&[
        "send", "--identity", alice_key.to_str().unwrap(),
        "--recipient", bob_card.to_str().unwrap(),
        "--relay", &addr_a, "--relay", &addr_b,
        "--mailbox", &mailbox_id, "--message", "vocab check",
    ]).await;
    let (_, recv_out) = cli_run(&[
        "receive", "--identity", bob_key.to_str().unwrap(),
        "--relay", &addr_a, "--relay", &addr_b, "--mailbox", &mailbox_id,
    ]).await;

    let all = format!("{alice_out}{bob_out}{mb_out}{send_out}{recv_out}");
    assert!(!contains_vocabulary_label(&all), "no vocabulary labels allowed: {all}");

    relay_a.kill().await.ok();
    relay_b.kill().await.ok();
    cleanup(&tmp);
}

// ── Test 4 (Phase 5, live mesh): real two-relay failover across Tailscale ───
//
// Requires: the 3-machine Tailscale mesh from LAN_DEV_HARNESS_RUNBOOK.md /
// project-scp-level2-tailscale, with scp-relay running on BOTH wowserver
// (100.72.12.57:7700) and ryan-desktop (100.101.76.81:7700), and passwordless
// SSH to both aliases. NOT run by default `cargo test --workspace` — ignored
// because it depends on live external infrastructure.
//
// Run manually with:
//   cargo test --test multirelay_failover -- --ignored --test-threads=1
//
// Mirrors killing_one_of_two_relays_still_delivers_via_the_survivor, but both
// "relays" are real remote processes on the live mesh, and the kill is a real
// SSH command against a real remote host — proving Option 2's real multi-relay
// failover holds over actual mesh-routed TCP, not just localhost sockets.
//
// Leaves both remote relays running on exit (restarts ryan-desktop's if killed
// mid-test), matching how prior live-mesh trials left the mesh.

async fn run_ssh_with_timeout(args: &[&str], timeout_secs: u64) {
    let mut child = tokio::process::Command::new("ssh")
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("ssh spawn must succeed");
    if tokio::time::timeout(Duration::from_secs(timeout_secs), child.wait())
        .await
        .is_err()
    {
        let _ = child.kill().await;
    }
}

async fn ssh_kill_relay_on_ryan_desktop() {
    run_ssh_with_timeout(&["ryan-desktop", "pkill -f './scp-relay'"], 5).await;
}

async fn ssh_restart_relay_on_ryan_desktop() {
    run_ssh_with_timeout(
        &[
            "ryan-desktop",
            "cd ~/scp && nohup setsid ./scp-relay --bind 100.101.76.81:7700 \
             > relay_test_restart.log 2>&1 < /dev/null & disown",
        ],
        5,
    )
    .await;
}

#[tokio::test]
#[ignore = "requires the live 3-machine Tailscale mesh with scp-relay on wowserver AND ryan-desktop"]
async fn live_mesh_two_relay_failover() {
    if !bins_exist() {
        eprintln!("SKIP: run `cargo build` first (scp-relay or scp-cli not found)");
        return;
    }

    const WOWSERVER_ADDR:    &str = "100.72.12.57:7700";
    const RYAN_DESKTOP_ADDR: &str = "100.101.76.81:7700";

    let tmp = test_tmp_dir("live-mesh");
    let alice_key = tmp.join("alice.key");
    let bob_key   = tmp.join("bob.key");
    let bob_card  = tmp.join("bob.card");
    let (ok, _) = cli_run(&["keygen", "--out", alice_key.to_str().unwrap()]).await;
    assert!(ok);
    let (ok, bob_out) = cli_run(&["keygen", "--out", bob_key.to_str().unwrap()]).await;
    assert!(ok);
    std::fs::write(&bob_card, &bob_out).unwrap();
    let (ok, mailbox_out) = cli_run(&["mailbox-new"]).await;
    assert!(ok);
    let mailbox_id = extract_mailbox_id(&mailbox_out);

    // Ensure both real relays are up before starting (either may already be
    // running from a prior manual trial).
    if tokio::net::TcpStream::connect(WOWSERVER_ADDR).await.is_err() {
        panic!("wowserver relay is not reachable — start it before running this test");
    }
    if tokio::net::TcpStream::connect(RYAN_DESKTOP_ADDR).await.is_err() {
        ssh_restart_relay_on_ryan_desktop().await;
        for _ in 0..50 {
            if tokio::net::TcpStream::connect(RYAN_DESKTOP_ADDR).await.is_ok() { break; }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    // Real send across both live mesh relays.
    let (ok, send_out) = cli_run(&[
        "send",
        "--identity", alice_key.to_str().unwrap(),
        "--recipient", bob_card.to_str().unwrap(),
        "--relay", WOWSERVER_ADDR,
        "--relay", RYAN_DESKTOP_ADDR,
        "--mailbox", &mailbox_id,
        "--message", "live mesh multirelay",
    ]).await;
    assert!(ok, "send across both live mesh relays must succeed\n{send_out}");
    assert_eq!(count_occurrences(&send_out, "\"event\":\"burst_stored\""), 2,
        "both live mesh relays must confirm storage: {send_out}");

    // Kill the real ryan-desktop relay over SSH — an actual remote process.
    ssh_kill_relay_on_ryan_desktop().await;
    for _ in 0..50 {
        if tokio::net::TcpStream::connect(RYAN_DESKTOP_ADDR).await.is_err() { break; }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // Real receive: must still succeed via the surviving wowserver relay.
    let (ok, recv_out) = cli_run(&[
        "receive",
        "--identity", bob_key.to_str().unwrap(),
        "--relay", WOWSERVER_ADDR,
        "--relay", RYAN_DESKTOP_ADDR,
        "--mailbox", &mailbox_id,
    ]).await;
    assert!(ok, "receive must still succeed via the surviving live relay\n{recv_out}");
    assert!(recv_out.contains("live mesh multirelay"), "plaintext must match: {recv_out}");
    assert!(recv_out.contains("\"count\":1"));

    // Restore ryan-desktop's relay, leaving the mesh as found.
    ssh_restart_relay_on_ryan_desktop().await;
    for _ in 0..50 {
        if tokio::net::TcpStream::connect(RYAN_DESKTOP_ADDR).await.is_ok() { break; }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    cleanup(&tmp);
}
