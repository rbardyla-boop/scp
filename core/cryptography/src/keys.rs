use zeroize::Zeroize;

/// Root or operational public key (Ed25519).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicKey(pub [u8; 32]);

/// Zeroized keypair for root or operational identities.
#[derive(Zeroize)]
#[zeroize(drop)]
pub struct KeyPair {
    pub public: [u8; 32],
    pub secret: [u8; 32],
}

/// Ephemeral symmetric session key (ChaCha20-Poly1305, 32 bytes).
#[derive(Zeroize)]
#[zeroize(drop)]
pub struct SessionKey(pub [u8; 32]);

impl KeyPair {
    /// Generate a fresh Ed25519 keypair using the OS RNG.
    pub fn generate() -> Self {
        todo!("Phase 0: generate Ed25519 keypair via rand_core OsRng")
    }

    /// Sign `message` with the secret key. Returns a 64-byte signature.
    pub fn sign(&self, _message: &[u8]) -> [u8; 64] {
        todo!("Phase 0: Ed25519 sign")
    }
}

impl PublicKey {
    /// Verify a detached signature over `message`.
    pub fn verify(&self, _message: &[u8], _sig: &[u8; 64]) -> bool {
        todo!("Phase 0: Ed25519 verify")
    }
}

impl SessionKey {
    /// Derive an ephemeral session key via X25519 ECDH.
    pub fn derive_x25519(_local_secret: &[u8; 32], _remote_public: &[u8; 32]) -> Self {
        todo!("Phase 0: X25519 ECDH session key derivation")
    }

    /// Encrypt plaintext with ChaCha20-Poly1305. Returns (ciphertext, nonce).
    pub fn encrypt(&self, _plaintext: &[u8]) -> (Vec<u8>, [u8; 12]) {
        todo!("Phase 0: ChaCha20-Poly1305 encrypt")
    }

    /// Decrypt ciphertext with ChaCha20-Poly1305.
    pub fn decrypt(&self, _ciphertext: &[u8], _nonce: &[u8; 12]) -> Result<Vec<u8>, CryptoError> {
        todo!("Phase 0: ChaCha20-Poly1305 decrypt")
    }
}

/// Hash `data` with BLAKE3. Returns a 32-byte digest.
pub fn hash(data: &[u8]) -> [u8; 32] {
    todo!("Phase 0: BLAKE3 hash")
}

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("decryption failed: authentication tag mismatch")]
    DecryptionFailed,
    #[error("invalid key material")]
    InvalidKey,
}
