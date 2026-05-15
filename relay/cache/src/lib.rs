use std::time::Duration;

/// Warm session cache — retains ephemeral state for 5–15 minutes after a burst.
/// Purpose: reduce re-handshake overhead, lower latency, preserve calm UX.
/// All entries expire automatically; no persistent storage.
pub struct WarmCache {
    /// Recommended TTL per spec §7.2 Step 4.
    pub default_ttl: Duration,
}

impl WarmCache {
    pub fn new(ttl: Duration) -> Self {
        Self { default_ttl: ttl }
    }

    /// Store a warm entry keyed by route ID.
    pub fn retain(&self, _route_id: &[u8; 16], _session_key: &[u8; 32]) {
        todo!("Phase 2: in-memory TTL cache for warm session keys")
    }

    /// Immediately purge all warm cache entries (called on session dissolution or app background).
    pub fn purge(&mut self) {
        todo!("Phase 2: full cache purge")
    }

    /// Retrieve a cached session key if still warm.
    pub fn get(&self, _route_id: &[u8; 16]) -> Option<[u8; 32]> {
        todo!("Phase 2: warm cache lookup")
    }
}
