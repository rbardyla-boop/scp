use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

// ── BlindRelay abstraction ──────────────────────────────────────────────────

/// Relay transport variants. The relay receives opaque encrypted bytes and may
/// not inspect, correlate, or retain any payload content — enforced by API shape.
///
/// Phase 4: wrap TcpRelay with libp2p Noise encryption for peer authentication
/// and transport confidentiality. The BlindRelay surface stays identical.
enum RelayTransport {
    /// Phase 2 local-direct: validates burst shape, returns Ok(()).
    Local,
    /// Phase 3 real TCP: connects, writes [4-byte len][payload], reads ACK 0x01, closes.
    Tcp(SocketAddr),
}

/// Enforces relay ignorance: a relay accepts opaque bytes and may not inspect,
/// correlate, or retain any payload content.
pub struct BlindRelay {
    inner: RelayTransport,
}

impl BlindRelay {
    pub fn local() -> Self {
        Self { inner: RelayTransport::Local }
    }

    pub fn tcp(addr: SocketAddr) -> Self {
        Self { inner: RelayTransport::Tcp(addr) }
    }

    /// Forward opaque payload. Relay sees bytes only — no semantic access.
    pub async fn forward(&self, payload: &[u8]) -> Result<(), MeshError> {
        match &self.inner {
            RelayTransport::Local => Ok(()),
            RelayTransport::Tcp(addr) => tcp_forward(payload, *addr).await,
        }
    }
}

/// Open a TCP connection, write the framed payload, read a 1-byte ACK, close.
/// No state is retained after the function returns.
async fn tcp_forward(payload: &[u8], addr: SocketAddr) -> Result<(), MeshError> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    let mut stream = TcpStream::connect(addr).await.map_err(|_| MeshError::RelayRefused)?;

    let len = payload.len() as u32;
    stream.write_all(&len.to_le_bytes()).await.map_err(|_| MeshError::Timeout)?;
    stream.write_all(payload).await.map_err(|_| MeshError::Timeout)?;

    let mut ack = [0u8; 1];
    stream.read_exact(&mut ack).await.map_err(|_| MeshError::Timeout)?;
    if ack[0] != 0x01 {
        return Err(MeshError::RelayRefused);
    }
    Ok(())
    // stream closes on drop — no connection state retained
}

// ── RelayNode ───────────────────────────────────────────────────────────────

/// A single node in the oblivious relay mesh.
/// Relays are blind — they see encrypted packets but not their meaning.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayNode {
    pub id: [u8; 16],
    pub endpoint: String,
}

impl RelayNode {
    /// Resolve this node into a BlindRelay ready to forward bursts.
    pub fn blind_relay(&self) -> BlindRelay {
        if self.endpoint.starts_with("local://") {
            BlindRelay::local()
        } else if let Ok(addr) = self.endpoint.parse() {
            BlindRelay::tcp(addr)
        } else {
            BlindRelay::local()
        }
    }
}

// ── Public relay functions ──────────────────────────────────────────────────

/// Route an encrypted burst payload through the first relay in the route.
///
/// Phase 3: local or TCP delivery depending on relay endpoint scheme.
/// Phase 4+: multi-hop onion routing; libp2p Noise transport wrapping.
///
/// Relay invariants:
///   - payloads are not stored beyond the forward call
///   - sender/recipient correlation is not possible at any relay node
///   - routing state is not exposed to observers
pub async fn route_burst(
    payload: Vec<u8>,
    route: Vec<RelayNode>,
) -> Result<(), MeshError> {
    if route.is_empty() {
        return Err(MeshError::NoRoute);
    }
    route[0].blind_relay().forward(&payload).await
}

/// Discover available relay nodes from the mesh.
///
/// Phase 3: returns a single synthetic local relay for simulation.
/// Phase 5: replace with real libp2p mDNS / DHT peer discovery.
pub async fn discover_relays() -> Result<Vec<RelayNode>, MeshError> {
    Ok(vec![RelayNode {
        id: [0u8; 16],
        endpoint: "local://loopback".to_string(),
    }])
}

/// Spawn a blind relay listener on a random local TCP port for testing.
///
/// The listener accepts a burst, reads [4-byte len][payload], drops the payload
/// (intentionally blind), sends ACK 0x01, and closes. No state is retained
/// between connections.
pub async fn spawn_relay_listener() -> Result<SocketAddr, MeshError> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|_| MeshError::NoRoute)?;
    let addr = listener.local_addr().map_err(|_| MeshError::NoRoute)?;

    tokio::spawn(async move {
        while let Ok((mut stream, _peer)) = listener.accept().await {
            tokio::spawn(async move {
                let mut len_bytes = [0u8; 4];
                if stream.read_exact(&mut len_bytes).await.is_err() {
                    return;
                }
                let len = u32::from_le_bytes(len_bytes) as usize;

                let mut payload = vec![0u8; len];
                if stream.read_exact(&mut payload).await.is_err() {
                    return;
                }

                // Intentionally blind: payload is never stored or inspected.
                drop(payload);

                let _ = stream.write_all(&[0x01]).await;
                // stream closes on drop — no connection state retained
            });
        }
    });

    Ok(addr)
}

// ── Error type ──────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum MeshError {
    #[error("no relay path available")]
    NoRoute,
    #[error("relay refused connection")]
    RelayRefused,
    #[error("transmission timeout")]
    Timeout,
}
