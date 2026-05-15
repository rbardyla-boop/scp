use serde::{Deserialize, Serialize};

/// A single node in the oblivious relay mesh.
/// Relays are blind — they see encrypted packets but not their meaning.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayNode {
    pub id: [u8; 16],
    pub endpoint: String,
}

/// Route an encrypted burst payload through the relay mesh.
///
/// Phase 2: local-direct simulation — validates the route is non-empty and
/// returns Ok(()). The caller is responsible for payload encryption before routing.
///
/// Phase 3: replace with real libp2p + QUIC multi-hop routing.
///
/// Relay invariants (enforced by real relays, simulated here):
///   - payloads are not stored beyond the session window
///   - sender/recipient correlation is not possible at any relay node
///   - routing state is not exposed to observers
pub async fn route_burst(
    _payload: Vec<u8>,
    route: Vec<RelayNode>,
) -> Result<(), MeshError> {
    if route.is_empty() {
        return Err(MeshError::NoRoute);
    }
    Ok(())
}

/// Discover available relay nodes from the mesh.
///
/// Phase 2: returns a single synthetic local relay for simulation.
/// Phase 3: replace with real libp2p mDNS / DHT peer discovery.
pub async fn discover_relays() -> Result<Vec<RelayNode>, MeshError> {
    Ok(vec![RelayNode {
        id: [0u8; 16],
        endpoint: "local://loopback".to_string(),
    }])
}

#[derive(Debug, thiserror::Error)]
pub enum MeshError {
    #[error("no relay path available")]
    NoRoute,
    #[error("relay refused connection")]
    RelayRefused,
    #[error("transmission timeout")]
    Timeout,
}
