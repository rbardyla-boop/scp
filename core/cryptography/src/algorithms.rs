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
/// Upgrades to PqMigration only when both sides explicitly support it.
pub fn negotiate(local: &AlgorithmSuite, remote: &AlgorithmSuite) -> AlgorithmSuite {
    if *local == AlgorithmSuite::PqMigration && *remote == AlgorithmSuite::PqMigration {
        AlgorithmSuite::PqMigration
    } else {
        AlgorithmSuite::Current
    }
}
