# SCP State–Transport–Edge Layer Model

## Layer 1 — State Layer (Distributed Notary)

**Responsibilities:**
- Identity continuity
- Consent registration
- Tunnel authorization state
- Key rotation history
- Revocation events
- Recovery commitments

**Does NOT store:** messages, payloads, voice/video, files, social graphs

**Recommended stack:** Substrate pallet OR Cosmos SDK module (minimal state footprint)

## Layer 2 — Transport Layer (Oblivious Relay Mesh)

**Responsibilities:**
- Burst transmission routing
- NAT traversal
- Relay coordination
- Ephemeral transport sessions
- Temporary encrypted packet retention

**Recommended stack:** libp2p · Noise Protocol Framework · QUIC transport · Relay perturbation engine

**Transport principles:**
- Relays are blind
- Routes are ephemeral
- Sessions dissolve automatically
- Routing state expires aggressively

## Layer 3 — Edge Layer (Sovereign Client)

**Responsibilities:**
- Local encrypted storage
- Hardware-backed identity
- Tunnel vitality management
- Consent visualization
- Recovery coordination

| Component | Technology |
|-----------|------------|
| Core Runtime | Rust |
| Mobile Shell | Swift / Kotlin |
| Desktop | Tauri |
| Local DB | SQLite + SQLCipher |
| Crypto | RustCrypto + libsodium |
