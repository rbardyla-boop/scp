# Production-Readiness Build Plan

**Status**: Planning artifact only.
**Deployment authorization**: Not granted.
**Current system status**: Development harness, production-adjacent Rust workspace.
Latest live-network harness proof is
`A — LEVEL_2_LAN_DEV_HARNESS_PROVEN` re-confirmed on 2026-07-05, but this is
not production authorization.

This plan defines how SCP can be built and reviewed as a production-readiness exercise
without authorizing production deployment, real-user communication, managed service
operation, or claims of installability beyond the documented dev harness.

## Correctness Gate

This output is correct if:
- It defines a build/review/self-correction sequence that can be run by a strict reviewer.
- It keeps deployment authorization explicitly separate from release-build compilation.
- It covers the declared Rust workspace and the desktop TypeScript shell separately.
- It lists hard blockers that must remain unresolved before any production claim.
- It gives exact commands for the current repository state.

This output is wrong if a reviewer sees:
- Any claim that production deployment is approved.
- Any reliance on the harness-only mailbox, file keys, or unvalidated vitality labels as
  production-ready components.
- Any skipped compiler, lint, format, or test gate.
- Any build command that silently excludes a declared workspace member.

## Build Scope

The production-readiness build gate covers the Cargo workspace declared in the root
`Cargo.toml`:

- `scp-wire-format`
- `core/cryptography`
- `core/identity`
- `core/vitality`
- `core/transport`
- `core/recovery`
- `relay/mesh`
- `relay/cache`
- `relay/perturbation`
- `provider/pool`
- `provider/delivery`
- `ledger/substrate`
- `ledger/cosmos`
- `test`
- `relay/daemon`
- `cli/endpoint`

The Tauri shell at `client/desktop/src-tauri` is intentionally not part of the root
workspace because it requires platform WebKit packages on Linux. Its web shell should be
checked separately through `client/desktop/package.json`.

## Current Dev-Harness Evidence

The latest real-network harness evidence available to this plan is the 2026-07-05
three-node relay run over the Tailscale mesh. This re-executed the Level 2 path
with fresh current-worktree release binaries; it is not a replay of the 2026-07-04
record.

Topology:

```text
laptop 100.127.135.32 (Endpoint A, sender)
        -> wowserver 100.72.12.57 (relay :7700)
        -> ryan-desktop 100.101.76.81 (Endpoint B, receiver)
```

Provenance:

| Field | Value |
|-------|-------|
| Commit | `69a56e9fd2cafc9e831757befa956abade847b3b` |
| Rust toolchain | `rustc 1.94.0 (4a4ef493e 2026-03-02)` |
| Build profile | `release` |
| `scp-relay` SHA-256 | `929fa196b824254ed043b5cc21fb665eb72677cbd1232eb89fa2b1e38e52a00e` |
| `scp-cli` SHA-256 | `2314bbf27ad535d34647a9921d8a6bc543aca84ddda4192df43245c382c67398` |

Evidence captured:

| # | Evidence item | Result |
|---|---------------|--------|
| 1 | Relay listening on wowserver | `{"event":"relay_listening","addr":"100.72.12.57:7700"}` |
| 2 | Receiver mailbox created | 64-hex mailbox id `374e8962...8516` |
| 3 | Sender burst stored | Route `a5762442...`; `burst_replicated` count `1` |
| 4 | Receiver decrypted payload | Matching `route_id` |
| 5 | Recovered plaintext | Exact string `trial-3node-live-2026-07-05` |
| 6 | Vocabulary isolation | No `Active`, `Warm`, `Dormant`, `Suspended`, `Severed`, or `Burned` in output |
| 7 | Wrong-mailbox negative | Poll returned `count:0` |
| 8 | Relay-restart mailbox loss | Poll returned `count:0` after restart; ephemeral relay state was gone |
| 9 | Secret-key locality | `alice-b.key` remained on ryan-desktop only, mode `0600` |

Operational note: the relay was intentionally left running on wowserver with log
`~/scp/relay_live.log` so the proven path remains standing. Stop it with:

```bash
ssh wowserver 'pkill -f "scp-relay --bind"'
```

Scope boundary: this proves dev-harness application behavior over Tailscale/WireGuard
only. It does not prove raw-network transport security, NAT traversal, Internet
routing, production metadata resistance, or production key storage. The next
dev-harness follow-up remains ProviderPool/liveness failure injection on the now
proven path; the production-readiness build gate below remains separate.

## Plan, Review, Self-Correct, Build Loop

1. Plan the gate.
   - Confirm the workspace members with `cargo metadata --no-deps`.
   - Confirm feature maps. If features are later added, keep `--all-features` in every
     relevant Rust command.
   - Confirm no production-deployment language was introduced.

2. Review before building.
   - Run `git diff --check` to catch whitespace and patch hygiene problems.
   - Run `cargo fmt --all --check`.
   - Read any changed production-adjacent code or docs for unauthorized claims.

3. Self-correct before continuing.
   - If formatting fails, run `cargo fmt --all`, inspect the diff, then rerun
     `cargo fmt --all --check`.
   - If clippy fails, fix the code or the test. Do not suppress warnings unless the
     suppression is justified in the code.
   - If tests fail, identify the exact failing test, fix the failing behavior or invalid
     test expectation, and rerun the failed target before rerunning the full suite.
   - If release build fails, fix the compiler error and rerun the full release build.

4. Build.
   - `cargo clippy --workspace --all-targets --all-features -- -D warnings`
   - `cargo test --workspace --all-targets --all-features`
   - `cargo build --release --workspace --all-targets --all-features`
   - `npm ci` in `client/desktop`
   - `npm run build` in `client/desktop`

5. Verify.
   - All commands above must exit with code 0.
   - If any command fails, the gate is failed until the failure is fixed and the command
     passes on rerun.
   - Record any commands intentionally not run, with the concrete blocker.

## Production Blockers

These blockers remain outside this build gate. Passing the build gate does not clear them.

| Area | Blocker |
|------|---------|
| Key storage | Dev-harness file keys are not production key storage. Root keys require a production keystore design and audit. |
| Relay routing | Harness-only `DevMailboxId` is not a production metadata-resistance scheme. |
| Transport | Level 2 LAN/dev transport does not prove Internet-scale QUIC/Noise operation. |
| Identity UX | Human-facing vitality labels remain gated by user validation. |
| Telemetry policy | Entropy and liveness metrics are not authorized as automatic production policy without provenance closure. |
| Cryptography | Independent protocol review, implementation audit, fuzzing, and negative test campaigns are still required. |
| Operations | Incident response, abuse handling, key-loss recovery, relay operator doctrine, and privacy-preserving observability are not production-ready. |

## Strict Reviewer Checklist

- [ ] The worktree has no hidden generated key material or harness identity files.
- [ ] `cargo metadata --no-deps` succeeds and matches the intended workspace members.
- [ ] `cargo fmt --all --check` succeeds.
- [ ] `cargo clippy --workspace --all-targets --all-features -- -D warnings` succeeds.
- [ ] `cargo test --workspace --all-targets --all-features` succeeds (default parallel; re-verified 558/0).
- [ ] `cargo build --release --workspace --all-targets --all-features` succeeds.
- [ ] `npm ci` succeeds in `client/desktop`.
- [ ] `npm run build` succeeds in `client/desktop`.
- [ ] No document or binary output claims production deployment authorization.
- [ ] Any failed command was fixed and rerun before the gate was considered passing.
