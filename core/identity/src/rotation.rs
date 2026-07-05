use rand_core::{OsRng, RngCore};
use scp_cryptography::keys::{KeyPair, PublicKey};
use serde::{Deserialize, Serialize};

/// Signals that an operational key rotation should occur.
/// The root key signs this event — root keys never sign anything else.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotationEvent {
    /// The public key being retired.
    pub old_ops_pub: [u8; 32],
    /// The new operational public key.
    pub new_ops_pub: [u8; 32],
    /// Root-key signature (Ed25519, 64 bytes) over (old_ops_pub || new_ops_pub || nonce).
    pub root_sig: Vec<u8>,
    /// Random nonce to prevent replay of rotation events.
    pub nonce: u64,
}

impl RotationEvent {
    /// Produce a signed rotation event.
    /// `root_keypair` must be the identity's root keypair held in the hardware enclave.
    pub fn sign(
        old_ops_pub: [u8; 32],
        new_ops_pub: [u8; 32],
        root_keypair: &KeyPair,
    ) -> Result<Self, RotationError> {
        let mut nonce_bytes = [0u8; 8];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = u64::from_le_bytes(nonce_bytes);

        let msg = rotation_message(&old_ops_pub, &new_ops_pub, nonce);
        let root_sig = root_keypair.sign(&msg).to_vec();

        Ok(Self {
            old_ops_pub,
            new_ops_pub,
            root_sig,
            nonce,
        })
    }

    /// Verify this rotation event against the identity's root public key.
    pub fn verify(&self, root_pub: &[u8; 32]) -> bool {
        if self.root_sig.len() != 64 {
            return false;
        }
        let Ok(sig_bytes) = self.root_sig[..64].try_into() else {
            return false;
        };
        let msg = rotation_message(&self.old_ops_pub, &self.new_ops_pub, self.nonce);
        PublicKey(*root_pub).verify(&msg, sig_bytes)
    }
}

fn rotation_message(old_ops_pub: &[u8; 32], new_ops_pub: &[u8; 32], nonce: u64) -> Vec<u8> {
    let mut msg = Vec::with_capacity(72);
    msg.extend_from_slice(old_ops_pub);
    msg.extend_from_slice(new_ops_pub);
    msg.extend_from_slice(&nonce.to_le_bytes());
    msg
}

#[derive(Debug, thiserror::Error)]
pub enum RotationError {
    #[error("enclave signing failed")]
    EnclaveFailed,
}
