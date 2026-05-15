use serde::{Deserialize, Serialize};

/// The vitality state of a cryptographic corridor.
///
/// Vitality is probabilistic and non-binary; these states represent
/// discretized bands of the V(t,i,r,p) function output.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum VitalityState {
    /// High vitality — recent, reciprocal exchange.
    Active,
    /// Stable low-frequency trust — corridor is healthy but quiet.
    Warm,
    /// Cooling — no recent exchange; reaffirmation suggested.
    Dormant,
    /// Reduced visibility — contact suspended by one party.
    Suspended,
    /// Explicit revocation — corridor formally closed.
    Severed,
    /// Security distrust — cryptographic incident detected.
    Burned,
}

impl VitalityState {
    /// Derive the state band from a raw vitality score in [0.0, 1.0].
    pub fn from_score(score: f64) -> Self {
        match score {
            s if s >= 0.80 => Self::Active,
            s if s >= 0.50 => Self::Warm,
            s if s >= 0.20 => Self::Dormant,
            _ => Self::Suspended,
        }
    }

    /// Returns true if any communication is permitted through this corridor.
    pub fn is_open(&self) -> bool {
        matches!(self, Self::Active | Self::Warm | Self::Dormant)
    }
}
