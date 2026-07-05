use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

struct WarmEntry {
    key: [u8; 32],
    expires: Instant,
}

/// Warm session cache — retains ephemeral state for 5–15 minutes after a burst.
/// Purpose: reduce re-handshake overhead, lower latency, preserve calm UX.
/// All entries expire automatically; no persistent storage.
///
/// Eviction is lazy: expired entries are removed on `get`, not by a background task.
/// This avoids concurrency complexity and timing artifacts in Phase 2.
///
/// Future: index by (route_id, recipient_ops_pub) to prevent relay confusion
/// and cache poisoning in multi-party scenarios.
#[derive(Clone, Default)]
pub struct WarmCache {
    pub default_ttl: Duration,
    entries: Arc<Mutex<HashMap<[u8; 16], WarmEntry>>>,
}

impl WarmCache {
    pub fn new(ttl: Duration) -> Self {
        Self {
            default_ttl: ttl,
            entries: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Store a warm entry keyed by route ID. Overwrites any existing entry for the same route.
    pub fn retain(&self, route_id: &[u8; 16], session_key: &[u8; 32]) {
        let expires = Instant::now() + self.default_ttl;
        self.entries.lock().unwrap().insert(
            *route_id,
            WarmEntry {
                key: *session_key,
                expires,
            },
        );
    }

    /// Retrieve a cached session key if still warm. Lazy-evicts expired entries on access.
    pub fn get(&self, route_id: &[u8; 16]) -> Option<[u8; 32]> {
        let mut map = self.entries.lock().unwrap();
        match map.get(route_id) {
            Some(entry) if entry.expires > Instant::now() => Some(entry.key),
            Some(_) => {
                map.remove(route_id);
                None
            }
            None => None,
        }
    }

    /// Immediately purge all warm cache entries.
    /// Call before dissolving a session in high-security contexts.
    pub fn purge(&self) {
        self.entries.lock().unwrap().clear();
    }
}
