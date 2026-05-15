# SCP — Sovereign Communication Protocol

A consent-based cryptographic relationship protocol. Identity is sovereign. Transport forgets. The user owns the relationship, not the infrastructure.

## Architecture

| Layer | Role |
|-------|------|
| State | Trust continuity + consent memory (Substrate / Cosmos) |
| Transport | Ephemeral encrypted burst transmission (libp2p + Noise + QUIC) |
| Edge | Local sovereign UX (Rust core + Kotlin / Swift / Tauri shells) |

## Build Roadmap

| Phase | Focus |
|-------|-------|
| 0 | Cryptographic Core |
| 1 | State Machine Layer |
| 2 | Relay Mesh Alpha |
| 3 | Reference Client |
| 4 | Recovery Layer |
| 5 | Metadata Resistance Hardening |
| 6 | Multi-Client Federation |
| 7 | Formal Verification + Audit |
| 8 | Sovereign Infrastructure Decision |

## Workspace

```
core/        — identity · vitality · transport · recovery · cryptography
relay/       — mesh · cache · perturbation
ledger/      — substrate · cosmos
client/      — mobile (Android/iOS) · desktop (Tauri)
test/        — adversarial · recovery · metadata · transport
docs/        — philosophy · sts · threat-model · cryptography · transport
```

## Quick Start

```bash
cargo check --workspace
cargo test --workspace
```
