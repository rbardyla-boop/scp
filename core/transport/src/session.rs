use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};

/// Opaque ephemeral symmetric session key (32 bytes, zeroized on drop).
#[derive(Clone)]
pub struct SessionKey(pub [u8; 32]);

impl Drop for SessionKey {
    fn drop(&mut self) {
        self.0.iter_mut().for_each(|b| *b = 0);
    }
}

/// Unique, single-use route identifier for a flash session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteId(pub [u8; 16]);

/// Replay-prevention nonce bound to a single burst transmission.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FreshnessNonce(pub u64);

impl RouteId {
    pub fn generate() -> Self {
        todo!("Phase 2: random route ID generation")
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
