# LAN Dev-Harness Runbook — Level 2

**Status:** READY FOR DEPLOYMENT  
**Prerequisite verdict:** `A — MULTIPROCESS_LOCALHOST_DEV_HARNESS_PROVEN`  
**Target verdict:** `A — LEVEL_2_LAN_DEV_HARNESS_PROVEN`

This runbook covers the physical three-machine LAN dev-harness exchange.  
Complete every section in order. Do not begin the actual LAN run until §1 and §2 are checked.

---

## §1 — Provenance Capture

All values below were captured immediately before LAN deployment.

| Field | Value |
|---|---|
| Branch | `master` |
| Commit hash | `b2ac7f499cb4564cf746657f3b14d0252b12badf` |
| Commit message | `feat: Add SCP wire format implementation` |
| Rust toolchain | `rustc 1.94.0 (4a4ef493e 2026-03-02)` |
| Cargo | `cargo 1.94.0 (85eff7c80 2026-01-15)` |
| Build profile | `release` |
| OS / architecture | `Linux 6.8.0-63-generic / x86_64` |

### Serial workspace test result

Command:
```
cargo test --workspace -- --test-threads=1
```

Result: **GREEN — 517 passing, 0 failed**

Note: Test count increased from baseline 429 (Phase 41 commit) to 517 (2026-07-04 worktree) due to subsequent crate additions and test suite growth. All tests pass serially.

> Parallel nondeterminism note: `sim_s34_liveness_failures_elevate_kappa` and
> `sim_s41_t1_detection_envelope_across_pool_sizes` exhibit RNG-based flakiness
> when run with `--test-threads` > 1. These are pre-existing simulator tests
> unrelated to Phase 41 changes. Recorded as reliability debt. They do not
> block this LAN deployment.

### Binary paths and SHA-256 hashes

| Binary | Path (on laptop) | SHA-256 (as of 2026-07-04) |
|---|---|---|
| `scp-cli` | `target/release/scp-cli` | `bb9405c78026029582122d1c9989619420319046f2d0a1309c9ef1b961a60b6a` |
| `scp-relay` | `target/release/scp-relay` | `d134908838cbfb22dfd7eb3b174c2b5da7c68f297b573103751b6c71a2f9427b` |

After copying binaries to the clean nodes, verify hashes match before running:

```bash
sha256sum scp-cli scp-relay
```

---

## §2 — Secret-File Safety Check

Before deploying, confirm no generated identity files are tracked by Git.

### Run on laptop

```bash
git ls-files '*.key' '*.card'
git status --ignored | grep -E '\.key|\.card'
```

**Expected result:** no output from either command.

### Documented `.gitignore` entries

`.gitignore` contains:
```
*.key
*.card
```

### Policy

Dev-harness key files (`.key`, `.card`) are **plaintext local secrets**. They are:
- Not production key storage.
- Not tracked by Git.
- Not to be copied into any location with network-accessible paths.
- Never to be committed even if the `.gitignore` is bypassed with `--force`.

---

## §3 — Deployment Choice

### Preferred: copy prebuilt binaries

All three machines are x86_64 Linux. Copy the release binaries built on the laptop.

```bash
# From the laptop, copy to each node (substitute actual IPs)
scp target/release/scp-relay user@DESKTOP2_LAN_IP:~/scp/
scp target/release/scp-cli   user@DESKTOP1_LAN_IP:~/scp/
```

After copying, verify SHA-256 hashes on each node (see §1 table).

### Alternative: build from source on each node

Only if architectures differ. Requires:
1. `git clone` of the repo at exact commit `b2ac7f499cb4564cf746657f3b14d0252b12badf`
2. `cargo build --release` on each node
3. Fresh SHA-256 capture and update of the §1 table

> Building from source on nodes proves developer-build deployment only — it does not
> prove easy consumer installation.

---

## §4 — Node Setup and Commands

### Topology

```
Laptop / Endpoint A (100.127.135.32)   ──────┐
                                              │  Tailscale mesh (WireGuard)
                         wowserver / scp-relay   ← bind to 100.72.12.57:7700
                                              │  Tailscale mesh (WireGuard)
ryan-desktop / Endpoint B (100.101.76.81)  ──┘
```

**Note on this deployment:** This trial runs over an existing Tailscale mesh VPN,
not a raw local LAN segment. Tailscale provides WireGuard encryption between nodes.
This trial thus does **not** prove SCP transport security independent of the
Tailscale tunnel — it proves SCP application-layer logic over mesh-routed transport.
See §8 for full "what this run does NOT prove" disclaimers.

### wowserver — relay node

1. Start the relay bound to the Tailscale IP:

```bash
./scp-relay --bind 100.72.12.57:7700
```

Expected output:
```json
{"event":"relay_listening","addr":"100.72.12.57:7700"}
```

2. Confirm the chosen port is allowed through the firewall (Tailscale segment only):

```bash
sudo ufw allow in on tailscale0 to any port 7700
```

---

### ryan-desktop — Endpoint B

All commands run on ryan-desktop. Use the relay address `100.72.12.57:7700`.

**Step B-1: Generate identity**
```bash
./scp-cli keygen --out alice-b.key
```
Expected event in output: `identity_created`  
This writes `alice-b.key` (secret, do not share) and prints a public card JSON.

**Step B-2: Export public card to a file**
```bash
./scp-cli public --identity alice-b.key > alice-b.card
```

**Step B-3: Generate a temporary mailbox token**
```bash
./scp-cli mailbox-new > b-mailbox.hex
cat b-mailbox.hex
```
Expected event in output: `mailbox_created`  
The hex value is Endpoint B's temporary mailbox token (64 hex chars / 32 bytes).

**Step B-4: Transfer public material to Endpoint A**

Copy `alice-b.card` and `b-mailbox.hex` to the laptop using SSH over the Tailscale mesh:

```bash
scp alice-b.card alice-b.card b-mailbox.hex laptop:~/scp/
```

Only these two files need to move.  
**Do not copy `alice-b.key`.** The secret key never leaves ryan-desktop.

---

### Laptop — Endpoint A

Use the relay address `100.72.12.57:7700`. Use the actual path to `alice-b.card`
and the hex value from `b-mailbox.hex` (received from ryan-desktop).

**Step A-1: Generate Endpoint A identity (if not already done)**
```bash
./scp-cli keygen --out alice-a.key
```

**Step A-2: Send the fixed Level 2 payload**
```bash
./scp-cli send \
  --identity alice-a.key \
  --recipient alice-b.card \
  --relay 100.72.12.57:7700 \
  --mailbox $(cat b-mailbox.hex) \
  --message "trial-level2-message-001"
```
Expected event in output: `burst_stored`

---

### ryan-desktop — Endpoint B receive

**Step B-5: Poll and decrypt**
```bash
./scp-cli receive \
  --identity alice-b.key \
  --relay 100.72.12.57:7700 \
  --mailbox $(cat b-mailbox.hex)
```
Expected events in output: `payload_decrypted`, `exchange_complete`  
Expected recovered plaintext: `trial-level2-message-001`

---

## §5 — Fixed Level 2 Payload

```
trial-level2-message-001
```

This is a non-sensitive fixed string. Use it verbatim in the send command.  
Record the exact decrypted text from the receive output for evidence capture.

---

## §6 — Required Evidence Capture

Record each item in the evidence table below before declaring a verdict.

| # | Evidence item | Required result | Captured |
|---|---|---|---|
| 1 | `relay_listening` output from wowserver | JSON line with `"event":"relay_listening"` and LAN addr | ✅ `{"event":"relay_listening","addr":"100.72.12.57:7700"}` |
| 2 | `mailbox_created` output from ryan-desktop | JSON line with `"event":"mailbox_created"` | ✅ `{"event":"mailbox_created","mailbox_id":"775faf...a1c"}` |
| 3 | `burst_stored` output from laptop | JSON line with `"event":"burst_stored"` | ✅ `{"event":"burst_stored","mailbox_id":"775faf...a1c","route_id":"4ca232f9..."}` |
| 4 | `payload_decrypted` output from ryan-desktop | JSON line with `"event":"payload_decrypted"` | ✅ `{"event":"payload_decrypted","plaintext":"trial-level2-message-001","route_id":"4ca232f9..."}` |
| 5 | Recovered plaintext | Exact string `trial-level2-message-001` | ✅ Exact match |
| 6 | No vocabulary-label output | None of: Active, Warm, Dormant, Suspended, Severed, Burned | ✅ None observed across all captured output |
| 7 | Wrong-mailbox negative test | Poll with incorrect token → no bursts returned | ✅ `{"count":0,"event":"exchange_complete"}` |
| 8 | Relay-restart mailbox-loss test | Stop relay, restart, ryan-desktop polls → no bursts returned | ✅ `{"count":0,"event":"exchange_complete"}` after restart (probe payload `trial-level2-restart-probe` lost as expected) |
| 9 | Secret key not transferred | `alice-b.key` remains only on ryan-desktop | ✅ Confirmed absent on laptop and wowserver; present (0600) only on ryan-desktop |

**Run date:** 2026-07-04. All 9 items captured with real command output (no assumptions).

**Runbook correction discovered during execution:** §4 Step B-3 assumed `mailbox-new`
emits a bare hex string. The actual CLI (`cli/endpoint/src/main.rs`) emits a JSON event
line `{"event":"mailbox_created","mailbox_id":"<hex>"}` for every command, consistent
with its vocabulary-neutral, uniformly-structured output design. The 64-char hex token
must be extracted from the `mailbox_id` field (e.g. via
`grep -oP '(?<="mailbox_id":")[0-9a-f]+'`) before use in `--mailbox`. This is a
documentation gap, not a protocol or transport defect — `--recipient` similarly takes
a **file path** to the card JSON (confirmed at `cli/endpoint/src/main.rs:11`), which
matched the runbook's assumption correctly.

### Wrong-mailbox test procedure

After successful exchange:
```bash
# On ryan-desktop: generate a different mailbox token
./scp-cli mailbox-new > wrong-mailbox.hex

# Poll using the wrong token
./scp-cli receive \
  --identity alice-b.key \
  --relay 100.72.12.57:7700 \
  --mailbox $(cat wrong-mailbox.hex)
```
Expected: zero bursts retrieved.

### Relay-restart mailbox-loss procedure

```bash
# On laptop: send a second payload
./scp-cli send \
  --identity alice-a.key \
  --recipient alice-b.card \
  --relay 100.72.12.57:7700 \
  --mailbox $(cat b-mailbox.hex) \
  --message "trial-level2-restart-probe"

# On wowserver: stop the relay daemon (Ctrl-C or kill)
# Then restart:
./scp-relay --bind 100.72.12.57:7700

# On ryan-desktop: poll immediately after restart
./scp-cli receive \
  --identity alice-b.key \
  --relay 100.72.12.57:7700 \
  --mailbox $(cat b-mailbox.hex)
```
Expected: zero bursts (mailbox state is ephemeral, cleared on restart).

---

## §7 — Verdict Options

Record one of the following after all evidence in §6 is captured.

| Verdict | Condition |
|---|---|
| `A — LEVEL_2_LAN_DEV_HARNESS_PROVEN` | All 9 evidence items pass. Exact plaintext recovered. No vocabulary-label words observed. |
| `B — LAN_DEPLOYMENT_BLOCKED_BY_PACKAGING_OR_ENVIRONMENT` | Binary copy failed, firewall not configurable, or node setup could not be completed. |
| `C — LAN_RUNTIME_REVEALS_PROTOCOL_OR_TRANSPORT_GAP` | Exchange attempted but failed due to protocol, serialization, or transport issue not seen in localhost testing. |
| `D — HARNESS_SECURITY_BOUNDARY_VIOLATED` | Secret key transferred off origin node, vitality vocabulary observed in output, or key/card file committed to Git. |

### Recorded Verdict (2026-07-04)

**`A — LEVEL_2_LAN_DEV_HARNESS_PROVEN`**

All 9 evidence items in §6 passed on the first execution against the Tailscale
mesh (laptop=Endpoint A, wowserver=relay, ryan-desktop=Endpoint B). Exact
plaintext `trial-level2-message-001` recovered. No vitality vocabulary observed.
Both negative tests (wrong-mailbox, relay-restart) behaved as required — zero
bursts returned in each case. Secret key (`alice-b.key`) never left ryan-desktop.

One documentation gap was found and corrected during the run (see §6 note on
`mailbox-new` JSON output vs. the runbook's original bare-hex assumption) — this
was a runbook error, not a protocol or transport defect, and does not affect
the verdict.

---

## §8 — What This Run Does NOT Prove

Record these explicitly to prevent scope creep in reporting.

| Not proven | Reason |
|---|---|
| SCP transport security independent of mesh | Trial runs over Tailscale (WireGuard), not a raw untrusted network |
| Internet routing works | All machines are on one Tailscale mesh segment |
| NAT or firewall traversal works | Mesh traffic is point-to-point WireGuard, avoids NAT entirely |
| Production metadata resistance | `DevMailboxId` is harness-only, temporary, token-routed |
| Mailbox injection or replay resistance | Explicitly out of harness scope |
| Easy consumer installation | Developer binary copy, not packaged installer |
| Human vocabulary or UI works | Separate human lane, separate test packet (frozen v1.2) |
| Deterministic parallel workspace continuity | Previously debt (sim_s34 / sim_s41 flakes); fixed in Trial 1c and re-verified clean under default parallel `cargo test` (558/0 across 6 runs) |

---

## §9 — Post-LAN Sequencing

After verdict A is recorded:

```
Trial 0:  in-process encrypted exchange              PROVEN
Level 1:  multi-process localhost dev-harness        PROVEN
Level 2:  three-machine LAN dev-harness              ← current
Trial 2:  ProviderPool/liveness failure injection into corridor traffic
```

The simulator adversarial scenarios (provider withholding, relay churn, gamed
response telemetry, three observability surfaces) become appropriate only after a
real LAN message path is proven.

Human lane smoke test (three ordinary participants, frozen v1.2 pages) proceeds
independently and does not block the LAN run.
