/// SCP protocol domain separation constants.
///
/// Every hash, key derivation, and signing operation must include the relevant
/// domain constant as a prefix in its input. This prevents cross-context reuse:
/// a value derived under SCP_DOMAIN_TRANSPORT cannot be confused with a value
/// derived under SCP_DOMAIN_RECOVERY, even if the raw key bytes match.
///
/// Phase 4/5: wire these into HKDF, transcript hashing, and replay windows.
pub const SCP_DOMAIN_TRANSPORT: &[u8] = b"scp:transport:v1:";
pub const SCP_DOMAIN_RELAY:     &[u8] = b"scp:relay:v1:";
pub const SCP_DOMAIN_RECOVERY:  &[u8] = b"scp:recovery:v1:";
pub const SCP_DOMAIN_VITALITY:  &[u8] = b"scp:vitality:v1:";

/// Canonical tunnel consent hash domain (matches the literal in tunnel_consent_hash).
/// Ledger implementations should migrate to reference this constant directly.
pub const SCP_DOMAIN_TUNNEL:    &[u8] = b"scp:tunnel:v1:";
