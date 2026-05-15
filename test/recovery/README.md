# Recovery Tests

Integration tests for Phase 4 recovery scenarios:

- Device loss → restore continuity without platform intervention
- Guardian blindness: guardians never learn relationship graph
- Identity shedding: operational key rotation post-recovery
- Threshold reconstruction: minimum shard count enforcement

Tests live in `../tests/recovery.rs`.
