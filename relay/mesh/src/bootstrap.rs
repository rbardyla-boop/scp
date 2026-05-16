use crate::RelayNode;
use rand::seq::SliceRandom;

/// Static bootstrap relay list with randomized selection.
///
/// Relay selection rotates on every call to `shuffled_relays()` — no affinity
/// accumulates, no preferred-relay memory forms. If the caller routes through
/// `route[0]` of the returned list, the choice is effectively random.
///
/// Phase 6+: replace with DHT/mDNS peer discovery once the overlay is real.
/// The interface is stable regardless of the discovery mechanism.
pub struct BootstrapConfig {
    relays: Vec<RelayNode>,
}

impl BootstrapConfig {
    /// Single local-only relay for simulation and testing.
    pub fn local_only() -> Self {
        Self {
            relays: vec![RelayNode {
                id: [0u8; 16],
                endpoint: "local://loopback".to_string(),
            }],
        }
    }

    pub fn with_relays(relays: Vec<RelayNode>) -> Self {
        Self { relays }
    }

    /// Return all known relays in randomized order.
    ///
    /// Fresh shuffle on every call — no ordering persistence, no routing
    /// reputation, no timing-based fingerprint from relay preference.
    pub fn shuffled_relays(&self) -> Vec<RelayNode> {
        let mut list = self.relays.clone();
        list.shuffle(&mut rand::thread_rng());
        list
    }
}
