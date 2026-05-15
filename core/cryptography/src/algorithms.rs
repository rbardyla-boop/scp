use serde::{Deserialize, Serialize};

/// The negotiated algorithm suite for a session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AlgorithmSuite {
    /// X25519 ECDH + Ed25519 signatures + ChaCha20-Poly1305 + BLAKE3.
    Current,
    /// Hybrid: X25519 + CRYSTALS-Kyber KEM + same symmetric/signature stack.
    PqMigration,
}

impl Default for AlgorithmSuite {
    fn default() -> Self {
        Self::Current
    }
}

/// Negotiate the best mutually supported suite.
pub fn negotiate(_local: &AlgorithmSuite, _remote: &AlgorithmSuite) -> AlgorithmSuite {
    todo!("Phase 0: algorithm negotiation")
}
