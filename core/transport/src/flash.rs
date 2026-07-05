use crate::harness::{vitality_to_byte, DevHarnessBurst};
use crate::session::{FreshnessNonce, RouteId, SessionKey};
use crate::state::StateProvider;
use crate::transcript::{FlashTranscript, FlashTranscriptV2, TransportKeyMaterial};
use rand_core::{OsRng, RngCore};
use scp_cryptography::keys::{
    x25519_dh, x25519_generate_keypair, PublicKey, SessionKey as CryptoSessionKey,
};
use scp_cryptography::{scp_derive_key, DomainLabel};
use scp_relay_cache::WarmCache;
use scp_relay_mesh::{discover_relays, route_burst};
use scp_relay_perturbation::PerturbationEngine;
use scp_vitality::SimVitalityEvaluationContext;
use scp_vitality::{VitalityEvidenceStore, VitalityState};
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
    pub pub_key: [u8; 32],
    /// Ed25519 sig by ops key over `handshake_sig_message(pub_key, expires_at)`.
    pub sig: [u8; 64],
    /// Unix epoch seconds; key is invalid after this time.
    pub expires_at: u64,
}

impl FlashSession {
    /// Step 1: retrieve recipient state from the sovereign state layer.
    ///
    /// Rejects revoked operational keys immediately. Fetches the most recent
    /// non-expired handshake ephemeral (if any) to enable the v2 bilateral DH path.
    ///
    /// Vitality and routing hints are deferred to Phase 9 (vitality oracle and
    /// routing discovery). Until then both default to Active / empty.
    pub async fn retrieve_state(
        provider: &impl StateProvider,
        recipient_ops_pub: &[u8; 32],
    ) -> Result<RecipientState, TransportError> {
        if provider.is_revoked(recipient_ops_pub) {
            return Err(TransportError::RecipientRevoked);
        }
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        Ok(RecipientState {
            ops_pub: *recipient_ops_pub,
            vitality: VitalityState::Active, // Phase 9: vitality oracle
            routing_hints: vec![],           // Phase 9: routing discovery
            handshake_ephemeral: provider.get_handshake_ephemeral(recipient_ops_pub, now),
        })
    }

    /// Simulator-runtime retrieve_state with explicit vitality oracle.
    ///
    /// SIMULATOR ONLY. Replaces the hardcoded `VitalityState::Active` with a value
    /// computed from `vitality_store` using the bilateral consent hash and simulated
    /// time in `ctx`. Uses `ctx.now()` for handshake ephemeral validation — fully
    /// deterministic, no wall-clock reads.
    ///
    /// Does not modify the production `retrieve_state()` path or its Phase 9 deferral.
    pub async fn retrieve_state_sim(
        provider: &impl StateProvider,
        recipient_ops_pub: &[u8; 32],
        vitality_store: &VitalityEvidenceStore,
        ctx: &SimVitalityEvaluationContext,
    ) -> Result<RecipientState, TransportError> {
        if provider.is_revoked(recipient_ops_pub) {
            return Err(TransportError::RecipientRevoked);
        }
        let handshake_ephemeral = provider.get_handshake_ephemeral(recipient_ops_pub, ctx.now());
        let vitality =
            vitality_store.compute_state(ctx.consent_hash(), ctx.now(), ctx.i(), ctx.r(), ctx.p());
        Ok(RecipientState {
            ops_pub: *recipient_ops_pub,
            vitality,
            routing_hints: vec![],
            handshake_ephemeral,
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
        let (session, _) = Self::open_and_send_core(state, payload, cache, engine).await?;
        Ok(session)
    }

    /// Same as [`open_and_send`] but also returns a [`BurstEnvelope`] containing all
    /// fields the recipient needs to reconstruct the session key and decrypt.
    ///
    /// Requires the v2 bilateral DH path — `state.handshake_ephemeral` must be `Some`.
    /// Returns [`TransportError::V1PathNotReceivable`] if no handshake ephemeral is present.
    ///
    /// This is the entry point for the in-process scenario harness (Trial 0).
    pub async fn open_and_send_with_envelope(
        state: RecipientState,
        payload: &[u8],
        cache: &WarmCache,
        engine: &PerturbationEngine,
    ) -> Result<(FlashSession, crate::corridor::BurstEnvelope), TransportError> {
        let (session, maybe_env) = Self::open_and_send_core(state, payload, cache, engine).await?;
        let env = maybe_env.ok_or(TransportError::V1PathNotReceivable)?;
        Ok((session, env))
    }

    /// Sender packaging path for the dev harness relay-mailbox flow (Trial 0).
    ///
    /// Produces a CBOR-serializable `DevHarnessBurst` containing all fields needed for
    /// recipient key reconstruction and decryption. For relay delivery the caller
    /// serializes this struct with `harness::serialize_burst()` and routes it under a
    /// `DevMailboxId` — the relay sees only the opaque token, not any identity key.
    ///
    /// Requires the v2 bilateral DH path — `state.handshake_ephemeral` must be `Some`.
    /// Returns [`TransportError::V1PathNotReceivable`] if no handshake ephemeral is present.
    ///
    /// This method is explicitly harness-only. It does not replace or modify
    /// [`open_and_send`] or the canonical relay transmission path.
    pub async fn open_and_package_harness_burst(
        state: RecipientState,
        payload: &[u8],
        cache: &WarmCache,
        engine: &PerturbationEngine,
    ) -> Result<(FlashSession, DevHarnessBurst), TransportError> {
        let (session, maybe_env) = Self::open_and_send_core(state, payload, cache, engine).await?;
        let env = maybe_env.ok_or(TransportError::V1PathNotReceivable)?;
        let burst = DevHarnessBurst {
            sender_ephemeral_pub: env.sender_ephemeral_pub,
            route_id: env.route_id.0,
            freshness_nonce: env.nonce.0,
            vitality_byte: vitality_to_byte(&env.vitality_snapshot),
            enc_nonce: env.enc_nonce,
            ciphertext: env.ciphertext,
        };
        Ok((session, burst))
    }

    /// Designated SCP simulator send operation.
    ///
    /// SIMULATOR ONLY. Retrieves recipient state through the bilateral vitality oracle
    /// using the supplied `vitality_store` and `ctx`, then invokes the send core under
    /// a single deterministic evaluation clock (`ctx.now()`). Cannot be called without
    /// a `VitalityEvidenceStore` and `SimVitalityEvaluationContext` — vitality bypass
    /// through this path is structurally prevented.
    ///
    /// Requires the v2 bilateral DH path. Returns `TransportError::V1PathNotReceivable`
    /// if no valid handshake ephemeral is present at `ctx.now()`.
    ///
    /// Does not replace or modify [`open_and_send`], [`open_and_send_with_envelope`],
    /// or any production call site.
    pub async fn open_and_send_sim(
        provider: &impl StateProvider,
        vitality_store: &VitalityEvidenceStore,
        ctx: &SimVitalityEvaluationContext,
        recipient_ops_pub: &[u8; 32],
        payload: &[u8],
        cache: &WarmCache,
        engine: &PerturbationEngine,
    ) -> Result<(FlashSession, crate::corridor::BurstEnvelope), TransportError> {
        let state =
            Self::retrieve_state_sim(provider, recipient_ops_pub, vitality_store, ctx).await?;
        let (session, maybe_env) =
            Self::open_and_send_core_at(state, payload, cache, engine, ctx.now()).await?;
        let env = maybe_env.ok_or(TransportError::V1PathNotReceivable)?;
        Ok((session, env))
    }

    /// Shared implementation for [`open_and_send`] and [`open_and_send_with_envelope`].
    ///
    /// Returns `(FlashSession, Some(BurstEnvelope))` on the v2 path and
    /// `(FlashSession, None)` on the v1 path. Both public entry points call this function
    /// so the sender-side cryptographic construction has a single source of truth.
    async fn open_and_send_core(
        state: RecipientState,
        payload: &[u8],
        cache: &WarmCache,
        engine: &PerturbationEngine,
    ) -> Result<(FlashSession, Option<crate::corridor::BurstEnvelope>), TransportError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        Self::open_and_send_core_at(state, payload, cache, engine, now).await
    }

    /// Time-parameterized send core — single source of truth for all path variants.
    ///
    /// `now` governs every time-sensitive check in this operation: handshake ephemeral
    /// expiry and any future time-dependent policy. Production callers supply
    /// `SystemTime::now()` via [`open_and_send_core`]; simulator callers supply
    /// `ctx.now()` via [`open_and_send_sim`]. A single evaluation clock per call
    /// is enforced by this interface.
    async fn open_and_send_core_at(
        state: RecipientState,
        payload: &[u8],
        cache: &WarmCache,
        engine: &PerturbationEngine,
        now: u64,
    ) -> Result<(FlashSession, Option<crate::corridor::BurstEnvelope>), TransportError> {
        if !state.vitality.is_open() {
            return Err(TransportError::VitalityInsufficient(state.vitality));
        }

        let route = RouteId::generate();
        let nonce = FreshnessNonce::generate();

        // Determine key derivation path and transcript version.
        // v2 path also captures sender_pub for BurstEnvelope construction.
        let (ephemeral_seed, transcript_hash, v2_sender_pub) = match &state.handshake_ephemeral {
            Some(hk) => {
                // v2 path: bilateral DH.
                // Defense-in-depth: transport layer independently rejects expired ephemerals
                // even if the state layer failed to filter them. This guards against a
                // compromised state layer feeding stale-but-validly-signed keys.
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
                    route_id: route.clone(),
                    nonce: nonce.clone(),
                    recipient_ops_pub: state.ops_pub,
                    vitality_snapshot: state.vitality.clone(),
                    protocol_version: 2,
                    sender_ephemeral_pub: sender_pub,
                };

                (dh_output, transcript.hash(), Some(sender_pub))
            }
            None => {
                // v1 fallback: OsRng seed (no bilateral DH).
                let mut seed = [0u8; 32];
                OsRng.fill_bytes(&mut seed);

                let transcript = FlashTranscript {
                    route_id: route.clone(),
                    nonce: nonce.clone(),
                    recipient_ops_pub: state.ops_pub,
                    vitality_snapshot: state.vitality.clone(),
                    protocol_version: 1,
                };

                (seed, transcript.hash(), None)
            }
        };

        let key_material = TransportKeyMaterial {
            ephemeral_seed,
            transcript_hash,
            recipient_binding: state.ops_pub,
        };

        let session_key = SessionKey(scp_derive_key(
            DomainLabel::Transport,
            &key_material.as_bytes(),
        ));

        // Encrypt payload — retain enc_nonce for BurstEnvelope on the v2 path.
        let crypto_sk = CryptoSessionKey(session_key.0);
        let (ciphertext, enc_nonce) = crypto_sk.encrypt(payload);

        // Perturbation pipeline: normalize → jitter → relay select → transmit.
        let normalized = engine.normalize_payload(&ciphertext);
        tokio::time::sleep(engine.jitter_delay()).await;

        let relays = discover_relays()
            .await
            .map_err(|_| TransportError::RoutingFailed)?;
        route_burst(normalized, relays)
            .await
            .map_err(|_| TransportError::TransmissionFailed)?;

        // Warm cache retention (TTL 10 min).
        cache.retain(&route.0, &session_key.0);

        // Sparse dummy burst — after real transmission to avoid timing correlation.
        // Ignored if budget is exhausted or vitality is non-open.
        engine.maybe_emit_dummy(&state.vitality).await;

        // Capture values needed for the envelope before they move into FlashSession.
        let envelope_route_id = route.clone();
        let envelope_nonce = nonce.clone();
        let envelope_vitality = state.vitality.clone();
        let envelope_ops_pub = state.ops_pub;

        let session = FlashSession {
            route,
            session_key,
            nonce,
            vitality: state.vitality,
            lifecycle: FlashSessionLifecycle::WarmCache { ttl: 600 },
        };

        let envelope = v2_sender_pub.map(|sender_pub| crate::corridor::BurstEnvelope {
            sender_ephemeral_pub: sender_pub,
            route_id: envelope_route_id,
            nonce: envelope_nonce,
            vitality_snapshot: envelope_vitality,
            ciphertext,
            enc_nonce,
            recipient_ops_pub: envelope_ops_pub,
            protocol_version: 2,
        });

        Ok((session, envelope))
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

impl RecipientState {
    /// Returns a protocol-stable BLAKE3 commitment over the canonical state fields.
    ///
    /// Field ordering and byte encoding are consensus-relevant — future auditors,
    /// federated providers, and zk-attestation systems depend on this being stable.
    /// Any change to the hash input layout is a breaking change and must be
    /// versioned (e.g., by prepending a domain separator byte in future revisions).
    ///
    /// Current encoding (v0):
    ///   ops_pub(32) ‖ vitality_byte(1) ‖ ephemeral_present(1) ‖
    ///   [if Some: ephemeral.pub_key(32) ‖ ephemeral.expires_at(8, LE)]
    ///
    /// Note: `ephemeral_present` is a binary flag today. If future versions add
    /// algorithm negotiation, Kyber ephemerals, or multi-ephemeral bundles, replace
    /// this with an `ephemeral_mode_byte` encoding capability sets.
    pub fn commitment(&self) -> [u8; 32] {
        use blake3::Hasher;
        use scp_wire_format::constants::{
            VITALITY_ACTIVE, VITALITY_BURNED, VITALITY_DORMANT, VITALITY_SEVERED,
            VITALITY_SUSPENDED, VITALITY_WARM,
        };
        let vitality_byte = match self.vitality {
            VitalityState::Active => VITALITY_ACTIVE,
            VitalityState::Warm => VITALITY_WARM,
            VitalityState::Dormant => VITALITY_DORMANT,
            VitalityState::Suspended => VITALITY_SUSPENDED,
            VitalityState::Severed => VITALITY_SEVERED,
            VitalityState::Burned => VITALITY_BURNED,
        };
        let mut h = Hasher::new();
        h.update(&self.ops_pub);
        h.update(&[vitality_byte]);
        h.update(&[self.handshake_ephemeral.is_some() as u8]);
        if let Some(eph) = &self.handshake_ephemeral {
            h.update(&eph.pub_key);
            h.update(&eph.expires_at.to_le_bytes());
        }
        *h.finalize().as_bytes()
    }
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
    #[error("recipient operational key is revoked")]
    RecipientRevoked,
    #[error("route generation failed")]
    RoutingFailed,
    #[error("burst transmission failed")]
    TransmissionFailed,
    #[error("handshake ephemeral key failed signature verification")]
    HandshakeKeyInvalid,
    #[error("handshake ephemeral key has expired")]
    HandshakeKeyExpired,
    #[error("decryption failed: authentication tag mismatch or wrong session key")]
    DecryptionFailed,
    #[error("v1 path (OsRng seed) cannot be decrypted by recipient — requires v2 bilateral DH")]
    V1PathNotReceivable,
}
