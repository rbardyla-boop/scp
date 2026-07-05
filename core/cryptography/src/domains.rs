/// SCP protocol domain separation labels.
///
/// Every hash, key derivation, and signing operation must be called through
/// `scp_derive_key` with the relevant DomainLabel. This prevents cross-context
/// reuse: key material derived under Transport cannot be confused with key
/// material derived under Recovery, even if the raw bytes happen to match.
///
/// Phase 5+: `scp_derive_key` can migrate from BLAKE3 to HKDF-SHA256 without
/// any caller changes — the DomainLabel enum is the stable interface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DomainLabel {
    Transport,
    Recovery,
    Relay,
    Vitality,
    /// Used when hashing FlashTranscript objects for key derivation input.
    Transcript,
    /// Tunnel consent hash — ledger implementations should migrate to use this.
    Tunnel,
}

impl DomainLabel {
    /// Returns the canonical context string passed to BLAKE3 `derive_key`.
    ///
    /// These strings are protocol-stable: they must never change after deployment.
    /// Adding a new variant here is safe; changing an existing string is a
    /// breaking protocol change.
    pub fn as_context(&self) -> &'static str {
        match self {
            DomainLabel::Transport => "scp:transport:v1:",
            DomainLabel::Recovery => "scp:recovery:v1:",
            DomainLabel::Relay => "scp:relay:v1:",
            DomainLabel::Vitality => "scp:vitality:v1:",
            DomainLabel::Transcript => "scp:transcript:v1:",
            DomainLabel::Tunnel => "scp:tunnel:v1:",
        }
    }
}

/// Domain-separated key derivation — the canonical entrypoint for all SCP key material.
///
/// All callers must use this function. Do not call `blake3::derive_key` directly.
/// This indirection lets the underlying KDF be swapped or audited centrally.
pub fn scp_derive_key(domain: DomainLabel, key_material: &[u8]) -> [u8; 32] {
    blake3::derive_key(domain.as_context(), key_material)
}

// ── Backwards-compatible byte constants (Phase 3) ──────────────────────────
// Kept for tunnel_consent_hash and existing tests that import them.
// New code must use DomainLabel + scp_derive_key instead.

pub const SCP_DOMAIN_TRANSPORT: &[u8] = b"scp:transport:v1:";
pub const SCP_DOMAIN_RELAY: &[u8] = b"scp:relay:v1:";
pub const SCP_DOMAIN_RECOVERY: &[u8] = b"scp:recovery:v1:";
pub const SCP_DOMAIN_VITALITY: &[u8] = b"scp:vitality:v1:";
pub const SCP_DOMAIN_TUNNEL: &[u8] = b"scp:tunnel:v1:";
