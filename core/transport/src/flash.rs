use crate::session::{FreshnessNonce, RouteId, SessionKey};
use rand_core::{OsRng, RngCore};
use scp_cryptography::keys::{hash, SessionKey as CryptoSessionKey};
use scp_relay_cache::WarmCache;
use scp_relay_mesh::{discover_relays, route_burst};
use scp_vitality::VitalityState;
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// The five-step flash session lifecycle (spec §7.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FlashSessionLifecycle {
    StateRetrieval,
    EphemeralGen,
    TransmissionBurst,
    WarmCache { ttl: u64 },
    Dissolution,
}

/// An in-progress flash transport session.
pub struct FlashSession {
    pub route: RouteId,
    pub session_key: SessionKey,
    pub nonce: FreshnessNonce,
    pub vitality: VitalityState,
    pub lifecycle: FlashSessionLifecycle,
}

impl FlashSession {
    /// Step 1: retrieve recipient state and routing hints.
    ///
    /// Phase 2: returns simulated Active state without a real ledger lookup.
    /// Phase 8: replace with real state layer query for vitality + routing hints.
    pub async fn retrieve_state(recipient_ops_pub: &[u8; 32]) -> Result<RecipientState, TransportError> {
        Ok(RecipientState {
            ops_pub: *recipient_ops_pub,
            vitality: VitalityState::Active,
            routing_hints: vec![],
        })
    }

    /// Steps 2–4: generate ephemeral session, transmit burst, retain in warm cache.
    ///
    /// Phase 2 key derivation: BLAKE3(random ephemeral bytes).
    /// Phase 3+: replace with X25519 ECDH over published ephemeral keys, then
    ///   HKDF(dh_output, route_id, protocol_version, transcript_hash)
    ///   to prevent cross-context reuse and relay confusion.
    pub async fn open_and_send(
        state: RecipientState,
        payload: &[u8],
        cache: &WarmCache,
    ) -> Result<FlashSession, TransportError> {
        if !state.vitality.is_open() {
            return Err(TransportError::VitalityInsufficient(state.vitality));
        }

        // Step 2: generate ephemeral session material.
        let mut eph_bytes = [0u8; 32];
        OsRng.fill_bytes(&mut eph_bytes);
        let session_key = SessionKey(hash(&eph_bytes));
        let route = RouteId::generate();
        let nonce = FreshnessNonce::generate();

        // Step 3: encrypt payload and route through relay mesh.
        // CryptoSessionKey gets a copy of key bytes; zeroized when dropped after encrypt.
        let crypto_sk = CryptoSessionKey(session_key.0);
        let (ciphertext, _enc_nonce) = crypto_sk.encrypt(payload);

        let relays = discover_relays().await.map_err(|_| TransportError::RoutingFailed)?;
        route_burst(ciphertext, relays).await.map_err(|_| TransportError::TransmissionFailed)?;

        // Step 4: retain warm cache entry (10 min default TTL; spec §7.2 range: 5–15 min).
        cache.retain(&route.0, &session_key.0);

        Ok(FlashSession {
            route,
            session_key,
            nonce,
            vitality: state.vitality,
            lifecycle: FlashSessionLifecycle::WarmCache { ttl: 600 },
        })
    }

    /// Step 5: destroy all transport state. Returns a DissolvedProof token.
    ///
    /// Consuming self drops SessionKey, which is zeroized by its Drop impl.
    /// Warm cache entries expire by TTL. For immediate eviction in high-security
    /// contexts, call cache.purge() before calling dissolve().
    ///
    /// The returned DissolvedProof is #[must_use]: discarding it silently is
    /// a compile-time warning, forcing callers to acknowledge dissolution.
    pub fn dissolve(self) -> DissolvedProof {
        let route = self.route.clone();
        drop(self); // SessionKey is zeroized here
        DissolvedProof { route }
    }
}

/// Proof that a flash session was explicitly dissolved.
///
/// Carries the RouteId of the dissolved session for audit or warm-cache
/// eviction purposes. Phase 4+: add a dissolution timestamp.
#[must_use = "dissolution must be acknowledged — use the proof or call cache.purge()"]
pub struct DissolvedProof {
    pub route: RouteId,
}

/// Minimal recipient state retrieved from the state layer.
pub struct RecipientState {
    pub ops_pub: [u8; 32],
    pub vitality: VitalityState,
    pub routing_hints: Vec<String>,
}

/// Warm session cache entry (lives 5–15 minutes post-burst).
pub struct WarmCacheEntry {
    pub route: RouteId,
    pub session_key: SessionKey,
    pub expires_in: Duration,
}

#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    #[error("recipient vitality too low: {0:?}")]
    VitalityInsufficient(VitalityState),
    #[error("route generation failed")]
    RoutingFailed,
    #[error("burst transmission failed")]
    TransmissionFailed,
}
