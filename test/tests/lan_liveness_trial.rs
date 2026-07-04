// ProviderPool Real-Network Liveness Trial (Option 1)
//
// Extends Trial 2's (TRIAL_2_CLOSURE_RECORD.md) scripted-failure discipline to
// REAL sockets. Two real `scp-relay` OS processes on localhost stand in for two
// providers. Every record_response()/record_failure() call in this file is
// driven by the real outcome of a real `scp-cli receive` process against a
// real relay — success or a real connection failure (the relay process was
// actually killed) — not a bare synthetic function call.
//
// See docs/architecture/PROVIDERPOOL_REAL_NETWORK_LIVENESS_TRIAL_PLAN.md
// (scope gate verdict: A — OPTION_1_REAL_NETWORK_OBSERVATION_AUTHORIZED).
//
// No production code is touched. `ProviderPool` is exercised read-only via its
// existing public API, exactly as test/tests/trial2.rs already does. The two
// subsystems (real LAN transport, ProviderPool telemetry) remain architecturally
// separate; this file only observes both side-by-side in one process.
//
// Claims proven:
//   - A real successful `receive` roundtrip against a live relay feeds
//     record_response() and produces the exact telemetry Trial 2's scripted
//     T1 (healthy baseline) trace produced.
//   - A real killed relay process, producing a real connection failure on
//     `receive`, feeds record_failure() and produces the exact telemetry
//     Trial 2's scripted T2 (explicit failure) trace produced.
//   - Observing this real-network-driven telemetry does not mutate
//     VitalityEvidenceStore or trigger pool rotation (T7-equivalent check).
//
// Explicit non-claims (mirrors TRIAL_2_CLOSURE_RECORD.md §9 and the plan's §7):
//   - Real multi-relay selection or failover (Option 2 in the plan; unscoped)
//   - Any change to production send/receive authorization based on liveness
//   - Any coupling between real relay liveness and VitalityEvidenceStore
//   - Metadata-resistant relay addressing
//   - Production readiness of ProviderPool for real network conditions at scale

use std::net::TcpListener;
use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;
use tokio::process::Command;

use rand::SeedableRng;
use rand::rngs::StdRng;

use scp_ledger_substrate::SubstrateLedger;
use scp_provider_pool::{ProviderPool, SamplingStrategy};
use scp_vitality::{VitalityEvidenceStore, VitalityState};

// ── Binary paths (identical pattern to test/tests/level1.rs) ─────────────────

fn workspace_bin(name: &str) -> PathBuf {
    let mut p = std::env::current_exe().expect("current_exe must succeed");
    p.pop(); // strip binary filename
    p.pop(); // strip "deps"
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
    let dir = std::env::temp_dir().join(format!("scp-lan-liveness-{suffix}"));
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

async fn wait_for_relay_down(port: u16) {
    for _ in 0..50 {
        if tokio::net::TcpStream::connect(format!("127.0.0.1:{port}")).await.is_err() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("relay on port {port} did not go down within 2.5 seconds");
}

// ── Live-mesh helpers (Step 2 stretch goal only) ─────────────────────────────
//
// These shell out over the SSH alias "wowserver" (passwordless, configured
// per project-scp-level2-tailscale) to kill/restart the real relay process on
// the real remote host. Only used by the #[ignore]'d live-mesh test below.

async fn wait_for_addr_up(addr: &str) {
    for _ in 0..100 {
        if tokio::net::TcpStream::connect(addr).await.is_ok() { return; }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("relay at {addr} did not become reachable in time");
}

async fn wait_for_addr_down(addr: &str) {
    for _ in 0..100 {
        if tokio::net::TcpStream::connect(addr).await.is_err() { return; }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("relay at {addr} did not become unreachable in time");
}

/// Runs an ssh command with a hard local timeout, then kills our local ssh
/// client if it hasn't returned. Needed because ssh sometimes does not close
/// its local channel promptly when the remote command backgrounds a
/// long-lived process (a known quirk), even though the remote side has
/// already executed by that point. This bounds that wait instead of hanging
/// the test indefinitely.
async fn run_ssh_with_timeout(args: &[&str], timeout_secs: u64) {
    let mut child = Command::new("ssh")
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

async fn ssh_kill_relay_on_wowserver() {
    // pkill exits nonzero if no process matched (already dead) — that's fine.
    run_ssh_with_timeout(&["wowserver", "pkill -f './scp-relay'"], 5).await;
}

async fn ssh_restart_relay_on_wowserver() {
    run_ssh_with_timeout(
        &[
            "wowserver",
            "cd ~/scp && nohup setsid ./scp-relay --bind 100.72.12.57:7700 \
             > relay_test_restart.log 2>&1 < /dev/null & disown",
        ],
        5,
    )
    .await;
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

fn contains_vocabulary_label(text: &str) -> bool {
    let labels = ["Active", "Warm", "Dormant", "Suspended", "Severed", "Burned"];
    labels.iter().any(|&l| text.contains(l))
}

fn pid(byte: u8) -> [u8; 32] { [byte; 32] }

fn seeded() -> StdRng { StdRng::seed_from_u64(0) }

/// One real attempt: `scp-cli receive` against a real relay address, using a
/// throwaway identity and a throwaway mailbox token. Success/failure of the
/// process reflects real TCP reachability of the relay at `addr` — the relay
/// has either not been started, is alive, or was killed for real.
async fn real_receive_attempt(identity: &PathBuf, relay_addr: &str) -> (bool, String) {
    let mailbox = "aa".repeat(32); // fixed dummy 64-hex mailbox; content is irrelevant here
    cli_run(&[
        "receive",
        "--identity", identity.to_str().unwrap(),
        "--relay", relay_addr,
        "--mailbox", &mailbox,
    ]).await
}

// ── Test 1: real killed relay reproduces Trial 2's T2 explicit-failure shape ─
//
// relay_a stays alive the whole test. relay_b is killed before any use.
// pool.with_liveness(2, u64::MAX): 2 real failed attempts against relay_b mark
// it dead; 4 seeded sample() calls then only ever select pid(1); 4 real
// successful attempts against relay_a feed record_response(pid(1)).
//
// Expected telemetry is IDENTICAL to trial2.rs::t2_explicit_failure_concentrates_selection_surface,
// but every record_failure()/record_response() call here is backed by a real
// process and a real socket outcome.

#[tokio::test]
async fn real_network_explicit_failure_matches_trial2_t2_shape() {
    if !bins_exist() {
        eprintln!("SKIP: run `cargo build` first (scp-relay or scp-cli not found)");
        return;
    }

    let tmp = test_tmp_dir("failure");
    let identity = tmp.join("observer.key");
    let (ok, _) = cli_run(&["keygen", "--out", identity.to_str().unwrap()]).await;
    assert!(ok, "observer keygen must succeed");

    // relay_a: healthy for the whole test.
    let port_a = free_port();
    let mut relay_a = Command::new(relay_bin())
        .arg("--bind").arg(format!("127.0.0.1:{port_a}"))
        .stdout(Stdio::null()).stderr(Stdio::null())
        .spawn().expect("relay_a spawn must succeed");
    wait_for_relay(port_a).await;
    let addr_a = format!("127.0.0.1:{port_a}");

    // relay_b: started, then killed for real before any use.
    let port_b = free_port();
    let mut relay_b = Command::new(relay_bin())
        .arg("--bind").arg(format!("127.0.0.1:{port_b}"))
        .stdout(Stdio::null()).stderr(Stdio::null())
        .spawn().expect("relay_b spawn must succeed");
    wait_for_relay(port_b).await;
    let addr_b = format!("127.0.0.1:{port_b}");
    relay_b.kill().await.ok();
    wait_for_relay_down(port_b).await;

    let mut rng = seeded();
    let mut pool = ProviderPool::new(SamplingStrategy::RandomK(1))
        .with_liveness(2, u64::MAX); // dead when consecutive_failures >= 2
    pool.add(pid(1), SubstrateLedger::new()); // backed by relay_a (healthy)
    pool.add(pid(2), SubstrateLedger::new()); // backed by relay_b (killed)

    // Two real failed attempts against the killed relay_b.
    for _ in 0..2 {
        let (ok, _) = real_receive_attempt(&identity, &addr_b).await;
        assert!(!ok, "receive against a killed relay must fail for real");
        pool.record_failure(pid(2));
    }

    // Fixed selection trace: pid(2) is now dead and filtered from sample().
    for _ in 0..4 { let _ = pool.sample(&mut rng); }

    // Four real successful attempts against the healthy relay_a.
    for _ in 0..4 {
        let (ok, out) = real_receive_attempt(&identity, &addr_a).await;
        assert!(ok, "receive against a live relay must succeed for real\noutput: {out}");
        assert!(out.contains("exchange_complete"), "must see exchange_complete: {out}");
        pool.record_response(pid(1));
    }

    // ── Vitality isolation baseline (T7-equivalent), captured before telemetry read ──
    let consent_hash = [7u8; 32];
    let mut vstore = VitalityEvidenceStore::new();
    vstore.initialize_at(consent_hash, 0);
    let state_before = vstore.compute_state(consent_hash, 1_000, 1.0, 1.0, 0.0);
    assert_eq!(state_before, VitalityState::Active);

    let snap = pool.operational_telemetry();

    // — Exactly Trial 2's T2 numbers, now real-network-driven ───────────────
    assert_eq!(snap.active_n, 2,
        "both providers remain in pool; dead provider is filtered from sample, not removed");
    assert!(snap.survivor_surface_evaluable);
    assert_eq!(snap.kappa, 1.0,
        "dead pid(2) excluded from real sampling → only pid(1) selected → kappa=1.0");
    assert!(snap.liveness_surface_evaluable);
    assert_eq!(snap.liveness_weighted_kappa, 1.0,
        "only pid(1) received real successful responses → liveness_weighted_kappa=1.0");
    assert_eq!(snap.selection_total, 4);
    assert_eq!(snap.response_total, 4);
    assert_eq!(snap.recent_reported_response_ratio(), Some(1.0));

    // — Isolation: observing real-network telemetry must not touch vitality or rotation ──
    let state_after = vstore.compute_state(consent_hash, 1_000, 1.0, 1.0, 0.0);
    assert_eq!(state_after, VitalityState::Active,
        "driving pool telemetry from real network events must not alter VitalityEvidenceStore state");
    assert_eq!(pool.epoch_count(), 0,
        "operational_telemetry() must not trigger rotation even when fed real network data");

    relay_a.kill().await.ok();
    cleanup(&tmp);
}

// ── Test 2: real healthy baseline reproduces Trial 2's uniform-response shape ─
//
// Both relays stay alive the whole test. 8 real successful attempts split
// evenly (4 + 4) across two real relays feed a uniform response distribution,
// matching Trial 2's T1/T5-recovery uniform-2-provider shape:
// liveness_weighted_kappa = 0.0.

#[tokio::test]
async fn real_network_healthy_baseline_matches_trial2_uniform_shape() {
    if !bins_exist() {
        eprintln!("SKIP: run `cargo build` first (scp-relay or scp-cli not found)");
        return;
    }

    let tmp = test_tmp_dir("healthy");
    let identity = tmp.join("observer.key");
    let (ok, _) = cli_run(&["keygen", "--out", identity.to_str().unwrap()]).await;
    assert!(ok, "observer keygen must succeed");

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

    let mut rng = seeded();
    let mut pool = ProviderPool::new(SamplingStrategy::RandomK(1));
    pool.add(pid(1), SubstrateLedger::new());
    pool.add(pid(2), SubstrateLedger::new());

    // 8 samples ≥ 4 * active_n(2) → Steady phase, matching Trial 2's T1 margin.
    for _ in 0..8 { let _ = pool.sample(&mut rng); }

    for _ in 0..4 {
        let (ok, out) = real_receive_attempt(&identity, &addr_a).await;
        assert!(ok, "receive against relay_a must succeed for real\noutput: {out}");
        pool.record_response(pid(1));
    }
    for _ in 0..4 {
        let (ok, out) = real_receive_attempt(&identity, &addr_b).await;
        assert!(ok, "receive against relay_b must succeed for real\noutput: {out}");
        pool.record_response(pid(2));
    }

    let snap = pool.operational_telemetry();

    assert_eq!(snap.active_n, 2);
    assert!(snap.liveness_surface_evaluable);
    assert_eq!(snap.liveness_weighted_kappa, 0.0,
        "uniform real responses across both live relays → response_entropy=1 bit → kappa_L=0.0");
    assert_eq!(snap.selection_total, 8);
    assert_eq!(snap.response_total, 8);
    assert_eq!(snap.recent_reported_response_ratio(), Some(1.0));

    relay_a.kill().await.ok();
    relay_b.kill().await.ok();
    cleanup(&tmp);
}

// ── Test 3: no vocabulary labels in any real CLI output used above ──────────

#[tokio::test]
async fn real_network_liveness_trial_produces_no_vocabulary_labels() {
    if !bins_exist() {
        eprintln!("SKIP: run `cargo build` first (scp-relay or scp-cli not found)");
        return;
    }

    let tmp = test_tmp_dir("novocab");
    let identity = tmp.join("observer.key");
    let (_, keygen_out) = cli_run(&["keygen", "--out", identity.to_str().unwrap()]).await;

    let port = free_port();
    let mut relay = Command::new(relay_bin())
        .arg("--bind").arg(format!("127.0.0.1:{port}"))
        .stdout(Stdio::null()).stderr(Stdio::null())
        .spawn().expect("relay spawn must succeed");
    wait_for_relay(port).await;
    let addr = format!("127.0.0.1:{port}");

    let (_, ok_out) = real_receive_attempt(&identity, &addr).await;

    relay.kill().await.ok();
    wait_for_relay_down(port).await;
    let (_, fail_out) = real_receive_attempt(&identity, &addr).await;

    let all_output = format!("{keygen_out}{ok_out}{fail_out}");
    assert!(
        !contains_vocabulary_label(&all_output),
        "no vocabulary labels may appear in real-network trial output: {all_output}"
    );

    cleanup(&tmp);
}

// ── Test 4 (Step 2 stretch goal): real Tailscale mesh relay kill ────────────
//
// Requires: the 3-machine Tailscale mesh from LAN_DEV_HARNESS_RUNBOOK.md /
// project-scp-level2-tailscale, an SSH alias "wowserver" with passwordless
// access, and scp-relay already copied to ~/scp/ on wowserver. NOT run by
// default `cargo test --workspace` — ignored because it depends on live
// external infrastructure unavailable in CI or on other developers' machines.
//
// Run manually with:
//   cargo test --test lan_liveness_trial -- --ignored --test-threads=1
//
// Repeats the exact T2-shape trial from
// real_network_explicit_failure_matches_trial2_t2_shape, but the "killed
// provider" is the REAL wowserver relay on the live Tailscale mesh, killed via
// a real SSH command against a real remote host — not a local child process.
// Confirms Option 1's real-network telemetry behavior holds over actual
// mesh-routed TCP, not just localhost sockets (plan §3 Step 2).
//
// Leaves the remote relay running on exit, matching how Level 2 left it.

#[tokio::test]
#[ignore = "requires the live 3-machine Tailscale mesh and SSH access to 'wowserver'"]
async fn real_mesh_explicit_failure_matches_trial2_t2_shape() {
    if !bins_exist() {
        eprintln!("SKIP: run `cargo build` first (scp-relay or scp-cli not found)");
        return;
    }

    const WOWSERVER_RELAY_ADDR: &str = "100.72.12.57:7700";

    let tmp = test_tmp_dir("mesh-failure");
    let identity = tmp.join("observer.key");
    let (ok, _) = cli_run(&["keygen", "--out", identity.to_str().unwrap()]).await;
    assert!(ok, "observer keygen must succeed");

    // Local control relay: always healthy, isolates "the mesh relay died" from
    // "something is wrong with the CLI/telemetry plumbing itself".
    let port_a = free_port();
    let mut relay_a = Command::new(relay_bin())
        .arg("--bind").arg(format!("127.0.0.1:{port_a}"))
        .stdout(Stdio::null()).stderr(Stdio::null())
        .spawn().expect("relay_a spawn must succeed");
    wait_for_relay(port_a).await;
    let addr_a = format!("127.0.0.1:{port_a}");

    // Ensure the real remote relay is up before we start — it may already be
    // running from a prior manual trial (Level 2 left it running).
    if tokio::net::TcpStream::connect(WOWSERVER_RELAY_ADDR).await.is_err() {
        ssh_restart_relay_on_wowserver().await;
        wait_for_addr_up(WOWSERVER_RELAY_ADDR).await;
    }

    let mut rng = seeded();
    let mut pool = ProviderPool::new(SamplingStrategy::RandomK(1))
        .with_liveness(2, u64::MAX);
    pool.add(pid(1), SubstrateLedger::new()); // local control
    pool.add(pid(2), SubstrateLedger::new()); // real wowserver mesh relay

    // Prove a real successful roundtrip over the actual mesh first.
    let (ok, out) = real_receive_attempt(&identity, WOWSERVER_RELAY_ADDR).await;
    assert!(ok, "receive against the live wowserver relay must succeed for real\n{out}");
    assert!(out.contains("exchange_complete"), "must see exchange_complete: {out}");

    // Kill it for real, over SSH, on the actual remote host.
    ssh_kill_relay_on_wowserver().await;
    wait_for_addr_down(WOWSERVER_RELAY_ADDR).await;

    // Two real failed attempts against the now-really-dead remote relay.
    for _ in 0..2 {
        let (ok, _) = real_receive_attempt(&identity, WOWSERVER_RELAY_ADDR).await;
        assert!(!ok, "receive against the killed remote relay must fail for real");
        pool.record_failure(pid(2));
    }

    // Fixed selection trace: pid(2) is now dead and filtered from sample().
    for _ in 0..4 { let _ = pool.sample(&mut rng); }

    // Four real successful attempts against the healthy local control relay.
    for _ in 0..4 {
        let (ok, out) = real_receive_attempt(&identity, &addr_a).await;
        assert!(ok, "receive against the local control relay must succeed for real\n{out}");
        pool.record_response(pid(1));
    }

    let snap = pool.operational_telemetry();
    assert_eq!(snap.active_n, 2,
        "both providers remain in pool; the dead remote relay is filtered from sample, not removed");
    assert!(snap.survivor_surface_evaluable);
    assert_eq!(snap.kappa, 1.0,
        "dead remote relay excluded from real sampling → only local pid(1) selected → kappa=1.0");
    assert!(snap.liveness_surface_evaluable);
    assert_eq!(snap.liveness_weighted_kappa, 1.0,
        "only the healthy local relay received real successful responses → liveness_weighted_kappa=1.0");
    assert_eq!(snap.selection_total, 4);
    assert_eq!(snap.response_total, 4);
    assert_eq!(snap.recent_reported_response_ratio(), Some(1.0));

    // Restore the remote relay to running, leaving wowserver as we found it.
    ssh_restart_relay_on_wowserver().await;
    wait_for_addr_up(WOWSERVER_RELAY_ADDR).await;

    relay_a.kill().await.ok();
    cleanup(&tmp);
}
