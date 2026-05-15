# SCP Cryptography Standards

## Requirements

- Algorithm agility
- Forward secrecy
- Hybrid PQ migration path
- Secure enclave integration

## Algorithm Table

| Purpose | Algorithm | Crate |
|---------|-----------|-------|
| Current ECDH | X25519 | `x25519-dalek` |
| PQ Migration | CRYSTALS-Kyber | `pqcrypto-kyber` |
| Signatures | Ed25519 | `ed25519-dalek` |
| Symmetric Encryption | ChaCha20-Poly1305 | `chacha20poly1305` |
| Hashing | BLAKE3 | `blake3` |
| Key zeroing | — | `zeroize` |

## Key Hierarchy

| Layer | Name | Purpose |
|-------|------|---------|
| L0 | Root Anchor | Sovereign continuity identity |
| L1 | Operational Persona | Active communication identity |
| L2 | Guardian Shards | Recovery continuity |
| L3 | Continuity Proof | Ledger ancestry verification |

## Root Key Rules

Root keys:
- never directly message,
- never negotiate transport,
- never leave hardware enclave,
- only sign lineage continuity.
