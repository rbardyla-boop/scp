use crate::session::{FreshnessNonce, RouteId, SessionKey};
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
    pub async fn retrieve_state(_recipient_ops_pub: &[u8; 32]) -> Result<RecipientState, TransportError> {
        todo!("Phase 2: state layer lookup for recipient")
    }

    /// Steps 2–3: generate ephemeral session and transmit burst.
    pub async fn open_and_send(
        _state: RecipientState,
        _payload: &[u8],
    ) -> Result<FlashSession, TransportError> {
        todo!("Phase 2: ephemeral session negotiation + burst send")
    }

    /// Step 5: destroy all transport state.
    pub fn dissolve(self) {
        todo!("Phase 2: session dissolution — purge relay memory, expire keys")
    }
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
