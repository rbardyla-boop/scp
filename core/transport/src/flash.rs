use crate::session::{FreshnessNonce, RouteId, SessionKey};
use crate::transcript::{FlashTranscript, TransportKeyMaterial};
use rand_core::{OsRng, RngCore};
use scp_cryptography::{scp_derive_key, DomainLabel};
use scp_cryptography::keys::SessionKey as CryptoSessionKey;
use scp_relay_cache::WarmCache;
use scp_relay_mesh::{discover_relays, route_burst};
use scp_relay_perturbation::PerturbationEngine;
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
    /// Phase 2–4: returns simulated Active state without a real ledger lookup.
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
    /// Phase 4 key derivation:
    ///   session_key = scp_derive_key(
    ///     DomainLabel::Transport,
    ///     ephemeral_seed || transcript_hash || recipient_ops_pub
    ///   )
    ///
    /// The ephemeral_seed provides forward secrecy; the transcript_hash binds
    /// the key to its exact (route, nonce, recipient, vitality) context.
    ///
    /// Phase 5: replace ephemeral_seed with X25519 DH output against the
    /// recipient's published ephemeral key for true contributory forward secrecy.
    /// Steps 2–4: generate ephemeral session, perturb, transmit burst, retain in warm cache.
    ///
    /// Perturbation pipeline (Phase 5 invariant — order must not change):
    ///   1. encrypt payload
    ///   2. normalize (pad to bucket boundary)
    ///   3. jitter (bounded random delay)
    ///   4. relay selection
    ///   5. transmit
    ///
    /// Perturbation precedes relay selection so that relay-selection timing is
    /// not observable as metadata.
    pub async fn open_and_send(
        state: RecipientState,
        payload: &[u8],
        cache: &WarmCache,
        engine: &PerturbationEngine,
    ) -> Result<FlashSession, TransportError> {
        if !state.vitality.is_open() {
            return Err(TransportError::VitalityInsufficient(state.vitality));
        }

        // Step 2: generate ephemeral session material.
        let route = RouteId::generate();
        let nonce = FreshnessNonce::generate();

        let mut ephemeral_seed = [0u8; 32];
        OsRng.fill_bytes(&mut ephemeral_seed);

        let transcript = FlashTranscript {
            route_id:          route.clone(),
            nonce:             nonce.clone(),
            recipient_ops_pub: state.ops_pub,
            vitality_snapshot: state.vitality.clone(),
            protocol_version:  1,
        };

        let key_material = TransportKeyMaterial {
            ephemeral_seed,
            transcript_hash:   transcript.hash(),
            recipient_binding: state.ops_pub,
        };

        let session_key = SessionKey(scp_derive_key(DomainLabel::Transport, &key_material.as_bytes()));

        // Step 3: encrypt payload.
        // CryptoSessionKey gets a copy of key bytes; zeroized when it drops after encrypt.
        let crypto_sk = CryptoSessionKey(session_key.0);
        let (ciphertext, _enc_nonce) = crypto_sk.encrypt(payload);

        // Step 3a: normalize payload size (perturbation, Phase 5).
        // Pads to bucket boundary to remove exact-length signals.
        let normalized = engine.normalize_payload(&ciphertext);

        // Step 3b: timing jitter (perturbation, Phase 5).
        // Jitter precedes relay selection — relay-selection timing must not be observable.
        tokio::time::sleep(engine.jitter_delay()).await;

        // Step 3c: relay selection and transmission.
        let relays = discover_relays().await.map_err(|_| TransportError::RoutingFailed)?;
        route_burst(normalized, relays).await.map_err(|_| TransportError::TransmissionFailed)?;

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
