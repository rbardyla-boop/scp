use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};

/// Opaque ephemeral symmetric session key (32 bytes, zeroized on drop).
///
/// Future key hierarchy — Phase 4/5 cryptographic hardening:
///   encryption_key: payload confidentiality (current use)
///   routing_key:    relay path isolation
///   integrity_key:  message authentication
///   ratchet_seed:   forward-secret session continuity
///
/// Derivation should also move toward:
///   HKDF(dh_output, route_id, protocol_version, transcript_hash)
/// to prevent cross-context reuse and relay confusion.
#[derive(Clone)]
pub struct SessionKey(pub [u8; 32]);

impl Drop for SessionKey {
    fn drop(&mut self) {
        self.0.iter_mut().for_each(|b| *b = 0);
    }
}

/// Unique, single-use route identifier for a flash session.
///
/// Future indexing: (route_id, recipient_ops_pub) or (route_id, session_fingerprint)
/// to prevent relay confusion and cache poisoning in multi-party scenarios.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteId(pub [u8; 16]);

/// Replay-prevention nonce bound to a single burst transmission.
///
/// ReplayWindow (Phase 5) enforces duplicate rejection on the receive path.
/// Each nonce is generated from OsRng — not monotonic, so no clock dependency
/// or sequence-number leak into transport metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FreshnessNonce(pub u64);

impl RouteId {
    pub fn generate() -> Self {
        let mut buf = [0u8; 16];
        OsRng.fill_bytes(&mut buf);
        Self(buf)
    }
}

impl FreshnessNonce {
    /// Generate a cryptographically random nonce (not monotonic — avoids clock dependency).
    pub fn generate() -> Self {
        let mut buf = [0u8; 8];
        OsRng.fill_bytes(&mut buf);
        Self(u64::from_le_bytes(buf))
    }
}
