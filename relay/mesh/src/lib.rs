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
/// Relays must not:
/// - store payloads beyond the session window
/// - correlate sender/recipient
/// - expose routing state to observers
pub async fn route_burst(
    _payload: Vec<u8>,
    _route: Vec<RelayNode>,
) -> Result<(), MeshError> {
    todo!("Phase 2: libp2p + QUIC burst routing through blind relay mesh")
}

/// Discover available relay nodes from the mesh.
pub async fn discover_relays() -> Result<Vec<RelayNode>, MeshError> {
    todo!("Phase 2: relay discovery via libp2p mDNS / DHT")
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
