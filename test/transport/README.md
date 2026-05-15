# Transport Tests

Integration tests for Phase 2 flash tunnel transport:

- Flash session 5-step lifecycle (StateRetrieval → Dissolution)
- Warm cache TTL and purge behavior
- Relay routing with blind nodes
- Session key zeroization on dissolution

Tests live in `../tests/transport.rs`.
