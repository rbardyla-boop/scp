pub mod bootstrap;

use bootstrap::BootstrapConfig;
use scp_wire_format::constants::{NOISE_PARAMS, RELAY_ACK_BYTE};
use scp_wire_format::framing::{decode_noise_length, decode_tcp_length, encode_noise_frame, encode_tcp_frame};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

// ── BlindRelay abstraction ──────────────────────────────────────────────────

enum RelayTransport {
    /// Phase 2 local-direct: validate route shape, return Ok(()).
    Local,
    /// Phase 3 real TCP: framed plaintext burst delivery.
    Tcp(SocketAddr),
    /// Phase 4 Noise-encrypted TCP: Noise_XX handshake + encrypted burst.
    /// Fresh initiator static key per forward() call — no persistent transport identity.
    Noise(SocketAddr),
}

/// Enforces relay ignorance: a relay accepts opaque bytes and may not inspect,
/// correlate, or retain any payload content.
///
/// Phase 4 upgrade path: `BlindRelay::noise(addr)` adds Noise_XX encryption.
/// The caller API is identical to `BlindRelay::tcp(addr)`.
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

    /// Phase 4 Noise-encrypted relay. Generates a fresh Noise static key per
    /// forward() call, so no two bursts share a transport identity.
    pub fn noise(addr: SocketAddr) -> Self {
        Self { inner: RelayTransport::Noise(addr) }
    }

    /// Forward opaque payload. Relay sees bytes only — no semantic access.
    pub async fn forward(&self, payload: &[u8]) -> Result<(), MeshError> {
        match &self.inner {
            RelayTransport::Local      => Ok(()),
            RelayTransport::Tcp(addr)  => tcp_forward(payload, *addr).await,
            RelayTransport::Noise(addr) => noise_forward(payload, *addr).await,
        }
    }
}

// ── TCP relay (Phase 3) ─────────────────────────────────────────────────────

async fn tcp_forward(payload: &[u8], addr: SocketAddr) -> Result<(), MeshError> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    let mut stream = TcpStream::connect(addr).await.map_err(|_| MeshError::RelayRefused)?;
    stream.write_all(&encode_tcp_frame(payload)).await.map_err(|_| MeshError::Timeout)?;
    let mut ack = [0u8; 1];
    stream.read_exact(&mut ack).await.map_err(|_| MeshError::Timeout)?;
    if ack[0] != RELAY_ACK_BYTE {
        return Err(MeshError::RelayRefused);
    }
    Ok(())
}

// ── Noise relay (Phase 4) ───────────────────────────────────────────────────

/// Write a length-prefixed Noise message over a TCP stream.
async fn write_noise_msg(
    stream: &mut (impl tokio::io::AsyncWrite + Unpin),
    msg: &[u8],
) -> Result<(), MeshError> {
    use tokio::io::AsyncWriteExt;
    stream.write_all(&encode_noise_frame(msg)).await.map_err(|_| MeshError::Timeout)?;
    Ok(())
}

/// Read a length-prefixed Noise message from a TCP stream.
async fn read_noise_msg(
    stream: &mut (impl tokio::io::AsyncRead + Unpin),
    buf: &mut [u8],
) -> Result<usize, MeshError> {
    use tokio::io::AsyncReadExt;
    let mut len_bytes = [0u8; 2];
    stream.read_exact(&mut len_bytes).await.map_err(|_| MeshError::Timeout)?;
    let len = decode_noise_length(&len_bytes);
    stream.read_exact(&mut buf[..len]).await.map_err(|_| MeshError::Timeout)?;
    Ok(len)
}

/// Noise XX initiator (sender side).
/// Generates a fresh static key — no two forward() calls share a transport identity.
async fn noise_forward(payload: &[u8], addr: SocketAddr) -> Result<(), MeshError> {
    use tokio::net::TcpStream;

    let params: snow::params::NoiseParams =
        NOISE_PARAMS.parse().map_err(|_| MeshError::RelayRefused)?;

    // Fresh static key per session — ephemeral transport identity.
    let initiator_static = snow::Builder::new(params.clone())
        .generate_keypair()
        .map_err(|_| MeshError::RelayRefused)?;

    let mut noise = snow::Builder::new(params)
        .local_private_key(&initiator_static.private)
        .build_initiator()
        .map_err(|_| MeshError::RelayRefused)?;

    let mut stream = TcpStream::connect(addr).await.map_err(|_| MeshError::RelayRefused)?;
    let mut tx = vec![0u8; 65535];
    let mut rx = vec![0u8; 65535];

    // Noise XX handshake — 3 messages.
    // -> e
    let len = noise.write_message(&[], &mut tx).map_err(|_| MeshError::Timeout)?;
    write_noise_msg(&mut stream, &tx[..len]).await?;

    // <- e, ee, s, es
    let len = read_noise_msg(&mut stream, &mut rx).await?;
    let mut plain = vec![0u8; 65535];
    noise.read_message(&rx[..len], &mut plain).map_err(|_| MeshError::Timeout)?;

    // -> s, se
    let len = noise.write_message(&[], &mut tx).map_err(|_| MeshError::Timeout)?;
    write_noise_msg(&mut stream, &tx[..len]).await?;

    let mut transport = noise.into_transport_mode().map_err(|_| MeshError::Timeout)?;

    // Send encrypted burst.
    let len = transport.write_message(payload, &mut tx).map_err(|_| MeshError::Timeout)?;
    write_noise_msg(&mut stream, &tx[..len]).await?;

    // Receive encrypted ACK.
    let len = read_noise_msg(&mut stream, &mut rx).await?;
    let plen = transport.read_message(&rx[..len], &mut plain).map_err(|_| MeshError::Timeout)?;
    if plen != 1 || plain[0] != RELAY_ACK_BYTE {
        return Err(MeshError::RelayRefused);
    }

    Ok(())
    // stream and transport close on drop — no connection state retained
}

/// Noise XX responder (relay side).
async fn handle_noise_connection(
    mut stream: tokio::net::TcpStream,
    relay_private_key: Vec<u8>,
) -> Result<(), MeshError> {
    let params: snow::params::NoiseParams =
        NOISE_PARAMS.parse().map_err(|_| MeshError::RelayRefused)?;

    let mut noise = snow::Builder::new(params)
        .local_private_key(&relay_private_key)
        .build_responder()
        .map_err(|_| MeshError::RelayRefused)?;

    let mut tx = vec![0u8; 65535];
    let mut rx = vec![0u8; 65535];
    let mut plain = vec![0u8; 65535];

    // <- e (receive initiator's first message)
    let len = read_noise_msg(&mut stream, &mut rx).await?;
    noise.read_message(&rx[..len], &mut plain).map_err(|_| MeshError::Timeout)?;

    // -> e, ee, s, es
    let len = noise.write_message(&[], &mut tx).map_err(|_| MeshError::Timeout)?;
    write_noise_msg(&mut stream, &tx[..len]).await?;

    // <- s, se
    let len = read_noise_msg(&mut stream, &mut rx).await?;
    noise.read_message(&rx[..len], &mut plain).map_err(|_| MeshError::Timeout)?;

    let mut transport = noise.into_transport_mode().map_err(|_| MeshError::Timeout)?;

    // Receive encrypted burst.
    let len = read_noise_msg(&mut stream, &mut rx).await?;
    let plen = transport.read_message(&rx[..len], &mut plain).map_err(|_| MeshError::Timeout)?;
    // Intentionally blind: payload is decrypted to verify integrity, then dropped.
    let _ = &plain[..plen];

    // Send encrypted ACK.
    let len = transport.write_message(&[RELAY_ACK_BYTE], &mut tx).map_err(|_| MeshError::Timeout)?;
    write_noise_msg(&mut stream, &tx[..len]).await?;

    Ok(())
    // stream and transport close on drop — no state retained
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
    ///
    /// Endpoint schemes:
    ///   "local://..."  — local-direct simulation
    ///   "noise://<ip:port>" — Phase 4 Noise-encrypted TCP
    ///   "<ip:port>"        — Phase 3 plaintext TCP
    pub fn blind_relay(&self) -> BlindRelay {
        if self.endpoint.starts_with("local://") {
            BlindRelay::local()
        } else if let Some(addr_str) = self.endpoint.strip_prefix("noise://") {
            if let Ok(addr) = addr_str.parse() {
                BlindRelay::noise(addr)
            } else {
                BlindRelay::local()
            }
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
/// Phase 4: local, TCP (Phase 3), or Noise-encrypted (Phase 4) depending on endpoint scheme.
/// Phase 5+: multi-hop onion routing through the full relay path.
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
/// Phase 5: returns the local bootstrap list in randomized order — no
/// sticky affinity, no preferred-relay memory. Caller routes through
/// the first entry, achieving effective random relay selection.
/// Phase 6+: replace with DHT/mDNS peer discovery.
pub async fn discover_relays() -> Result<Vec<RelayNode>, MeshError> {
    Ok(BootstrapConfig::local_only().shuffled_relays())
}

/// Spawn a plain TCP blind relay listener for testing (Phase 3).
/// Returns the bound address.
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
                if stream.read_exact(&mut len_bytes).await.is_err() { return; }
                let len = decode_tcp_length(&len_bytes);
                let mut payload = vec![0u8; len];
                if stream.read_exact(&mut payload).await.is_err() { return; }
                drop(payload); // intentionally blind
                let _ = stream.write_all(&[RELAY_ACK_BYTE]).await;
            });
        }
    });

    Ok(addr)
}

/// Spawn a Noise-encrypted relay listener for testing (Phase 4).
/// Returns the bound address and the relay's Noise static public key.
///
/// The static key is ephemeral to this listener's lifetime — it is gone
/// when the listener shuts down. Each call to this function generates a
/// distinct key pair, enforcing fresh transport identity per listener.
pub async fn spawn_noise_relay_listener() -> Result<(SocketAddr, Vec<u8>), MeshError> {
    use tokio::net::TcpListener;

    let params: snow::params::NoiseParams =
        NOISE_PARAMS.parse().map_err(|_| MeshError::NoRoute)?;

    let relay_keypair = snow::Builder::new(params)
        .generate_keypair()
        .map_err(|_| MeshError::NoRoute)?;

    let relay_pub  = relay_keypair.public.clone();
    let relay_priv = relay_keypair.private.clone();

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|_| MeshError::NoRoute)?;
    let addr = listener.local_addr().map_err(|_| MeshError::NoRoute)?;

    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let priv_key = relay_priv.clone();
            tokio::spawn(async move {
                let _ = handle_noise_connection(stream, priv_key).await;
            });
        }
    });

    Ok((addr, relay_pub))
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
