use crate::session::{FreshnessNonce, RouteId, SessionKey};
use crate::transcript::{FlashTranscript, FlashTranscriptV2, TransportKeyMaterial};
use rand_core::{OsRng, RngCore};
use scp_cryptography::{scp_derive_key, DomainLabel};
use scp_cryptography::keys::{x25519_dh, x25519_generate_keypair, PublicKey, SessionKey as CryptoSessionKey};
use scp_relay_cache::WarmCache;
use scp_relay_mesh::{discover_relays, route_burst};
use scp_relay_perturbation::PerturbationEngine;
use scp_vitality::VitalityState;
use crate::state::StateProvider;
use scp_wire_format::signing::handshake_sig_message;
use serde::{Deserialize, Serialize};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

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

/// Recipient's published X25519 handshake ephemeral key for bilateral DH.
///
/// Signed by the recipient's ops key so the sender can verify that this key
/// was legitimately issued without requiring a direct ops-key exchange.
/// `handshake_ephemeral_pub` rotates independently of `ops_pub` — the ops key
/// is the continuity anchor; the handshake key is temporary transport capability.
pub struct PublishedHandshakeKey {
    /// X25519 public key — input to sender-side DH.
    pub pub_key:    [u8; 32],
    /// Ed25519 sig by ops key over `handshake_sig_message(pub_key, expires_at)`.
    pub sig:        [u8; 64],
    /// Unix epoch seconds; key is invalid after this time.
    pub expires_at: u64,
}

impl FlashSession {
    /// Step 1: retrieve recipient state and routing hints.
    ///
    /// Phase 2–6: returns simulated Active state without a real ledger lookup.
    /// `handshake_ephemeral` is None — callers that want the DH path supply
    /// a `RecipientState` with `handshake_ephemeral: Some(...)` directly.
    /// Phase 8: replace with real state layer query.
    pub async fn retrieve_state(recipient_ops_pub: &[u8; 32]) -> Result<RecipientState, TransportError> {
        Ok(RecipientState {
            ops_pub: *recipient_ops_pub,
            vitality: VitalityState::Active,
            routing_hints: vec![],
            handshake_ephemeral: None,
        })
    }

    /// Steps 2–4: generate ephemeral session, perturb, transmit burst, retain in warm cache.
    ///
    /// # Key derivation path
    ///
    /// **v2 (bilateral DH, when `state.handshake_ephemeral` is `Some`):**
    /// 1. Verify ops-key signature over recipient's handshake ephemeral.
    /// 2. Generate fresh sender X25519 keypair (ephemeral per session).
    /// 3. `dh_output = X25519(sender_secret, recipient_handshake_pub)` — raw, no KDF.
    /// 4. `session_key = scp_derive_key(Transport, dh_output || transcript_v2_hash || recipient_binding)`
    ///    where `transcript_v2_hash` binds sender_ephemeral_pub, route, nonce, vitality.
    ///
    /// **v1 fallback (OsRng seed, when `state.handshake_ephemeral` is `None`):**
    /// `session_key = scp_derive_key(Transport, ephemeral_seed || transcript_v1_hash || recipient_binding)`
    ///
    /// # Perturbation pipeline (order must not change)
    /// `encrypt → normalize → jitter → relay select → transmit`
    ///
    /// Perturbation precedes relay selection so relay-selection timing is not
    /// observable as metadata.
    pub async fn open_and_send(
        state: RecipientState,
        payload: &[u8],
        cache: &WarmCache,
        engine: &PerturbationEngine,
    ) -> Result<FlashSession, TransportError> {
        if !state.vitality.is_open() {
            return Err(TransportError::VitalityInsufficient(state.vitality));
        }

        let route = RouteId::generate();
        let nonce = FreshnessNonce::generate();

        // Determine key derivation path and transcript version.
        let (ephemeral_seed, transcript_hash) = match &state.handshake_ephemeral {
            Some(hk) => {
                // v2 path: bilateral DH.
                // Defense-in-depth: transport layer independently rejects expired ephemerals
                // even if the state layer failed to filter them. This guards against a
                // compromised state layer feeding stale-but-validly-signed keys.
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                if hk.expires_at <= now {
                    return Err(TransportError::HandshakeKeyExpired);
                }

                // Verify recipient's handshake ephemeral was signed by their ops key.
                let sig_msg = handshake_sig_message(&hk.pub_key, hk.expires_at);
                if !PublicKey(state.ops_pub).verify(&sig_msg, &hk.sig) {
                    return Err(TransportError::HandshakeKeyInvalid);
                }

                // Generate sender X25519 ephemeral (fresh per session).
                let (sender_secret, sender_pub) = x25519_generate_keypair();

                // Raw DH — no KDF here; derivation happens below via scp_derive_key.
                let dh_output = x25519_dh(&sender_secret, &hk.pub_key);

                let transcript = FlashTranscriptV2 {
                    route_id:             route.clone(),
                    nonce:                nonce.clone(),
                    recipient_ops_pub:    state.ops_pub,
                    vitality_snapshot:    state.vitality.clone(),
                    protocol_version:     2,
                    sender_ephemeral_pub: sender_pub,
                };

                (dh_output, transcript.hash())
            }
            None => {
                // v1 fallback: OsRng seed (no bilateral DH).
                let mut seed = [0u8; 32];
                OsRng.fill_bytes(&mut seed);

                let transcript = FlashTranscript {
                    route_id:          route.clone(),
                    nonce:             nonce.clone(),
                    recipient_ops_pub: state.ops_pub,
                    vitality_snapshot: state.vitality.clone(),
                    protocol_version:  1,
                };

                (seed, transcript.hash())
            }
        };

        let key_material = TransportKeyMaterial {
            ephemeral_seed,
            transcript_hash,
            recipient_binding: state.ops_pub,
        };

        let session_key = SessionKey(scp_derive_key(DomainLabel::Transport, &key_material.as_bytes()));

        // Encrypt payload.
        let crypto_sk = CryptoSessionKey(session_key.0);
        let (ciphertext, _enc_nonce) = crypto_sk.encrypt(payload);

        // Perturbation pipeline: normalize → jitter → relay select → transmit.
        let normalized = engine.normalize_payload(&ciphertext);
        tokio::time::sleep(engine.jitter_delay()).await;

        let relays = discover_relays().await.map_err(|_| TransportError::RoutingFailed)?;
        route_burst(normalized, relays).await.map_err(|_| TransportError::TransmissionFailed)?;

        // Warm cache retention (TTL 10 min).
        cache.retain(&route.0, &session_key.0);

        // Sparse dummy burst — after real transmission to avoid timing correlation.
        // Ignored if budget is exhausted or vitality is non-open.
        engine.maybe_emit_dummy(&state.vitality).await;

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
/// eviction purposes.
#[must_use = "dissolution must be acknowledged — use the proof or call cache.purge()"]
pub struct DissolvedProof {
    pub route: RouteId,
}

/// Minimal recipient state retrieved from the state layer.
pub struct RecipientState {
    pub ops_pub: [u8; 32],
    pub vitality: VitalityState,
    pub routing_hints: Vec<String>,
    /// Phase 6: optional bilateral DH handshake key.
    /// Present when the recipient has published a valid handshake ephemeral
    /// through the state layer. Absence falls back to v1 (OsRng seed).
    pub handshake_ephemeral: Option<PublishedHandshakeKey>,
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
    #[error("handshake ephemeral key failed signature verification")]
    HandshakeKeyInvalid,
    #[error("handshake ephemeral key has expired")]
    HandshakeKeyExpired,
}

