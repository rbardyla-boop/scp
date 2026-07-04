use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use rand_core::{OsRng, RngCore};
use x25519_dalek::StaticSecret;
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
        let sk = SigningKey::generate(&mut OsRng);
        Self {
            public: sk.verifying_key().to_bytes(),
            secret: sk.to_bytes(),
        }
    }

    /// Sign `message` with the secret key. Returns a 64-byte Ed25519 signature.
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        SigningKey::from_bytes(&self.secret).sign(message).to_bytes()
    }
}

impl PublicKey {
    /// Verify a detached Ed25519 signature over `message`.
    pub fn verify(&self, message: &[u8], sig: &[u8; 64]) -> bool {
        let Ok(vk) = VerifyingKey::from_bytes(&self.0) else {
            return false;
        };
        // verify_strict rejects non-canonical signatures (cofactor attack resistance).
        vk.verify_strict(message, &(*sig).into()).is_ok()
    }
}

/// Raw X25519 Diffie-Hellman shared secret (no KDF applied).
///
/// Returns the 32-byte output directly. The caller MUST domain-separate and
/// derive keys from this output via `scp_derive_key` before any cryptographic
/// use. Do not use this output directly as a symmetric key.
pub fn x25519_dh(local_secret: &[u8; 32], remote_public: &[u8; 32]) -> [u8; 32] {
    let shared = StaticSecret::from(*local_secret)
        .diffie_hellman(&(*remote_public).into());
    *shared.as_bytes()
}

/// Generate a fresh X25519 keypair for use as a session handshake ephemeral.
///
/// Returns `(secret_bytes, public_bytes)`. The secret is ephemeral — do not
/// store it. Do not use this for long-lived identity keys.
pub fn x25519_generate_keypair() -> ([u8; 32], [u8; 32]) {
    x25519_generate_keypair_with_rng(&mut OsRng)
}

/// RNG-injectable variant of `x25519_generate_keypair` for deterministic testing.
pub fn x25519_generate_keypair_with_rng<R: rand_core::CryptoRng + RngCore>(rng: &mut R) -> ([u8; 32], [u8; 32]) {
    let secret = StaticSecret::random_from_rng(rng);
    let public = x25519_dalek::PublicKey::from(&secret);
    (secret.to_bytes(), *public.as_bytes())
}

impl SessionKey {
    /// Derive an ephemeral session key from a local X25519 secret and remote X25519 public key.
    /// The raw DH shared secret is hashed with BLAKE3 to produce the symmetric key.
    pub fn derive_x25519(local_secret: &[u8; 32], remote_public: &[u8; 32]) -> Self {
        let shared = StaticSecret::from(*local_secret)
            .diffie_hellman(&(*remote_public).into());
        SessionKey(*blake3::hash(shared.as_bytes()).as_bytes())
    }

    /// Encrypt `plaintext` with ChaCha20-Poly1305.
    /// Returns `(ciphertext_with_tag, random_nonce)`.
    pub fn encrypt(&self, plaintext: &[u8]) -> (Vec<u8>, [u8; 12]) {
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&self.0));
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let ct = cipher
            .encrypt(Nonce::from_slice(&nonce_bytes), plaintext)
            .expect("ChaCha20-Poly1305 encryption failed");
        (ct, nonce_bytes)
    }

    /// Decrypt `ciphertext` (with authentication tag) using the provided nonce.
    pub fn decrypt(&self, ciphertext: &[u8], nonce: &[u8; 12]) -> Result<Vec<u8>, CryptoError> {
        ChaCha20Poly1305::new(Key::from_slice(&self.0))
            .decrypt(Nonce::from_slice(nonce), ciphertext)
            .map_err(|_| CryptoError::DecryptionFailed)
    }
}

/// Hash `data` with BLAKE3. Returns a 32-byte digest.
pub fn hash(data: &[u8]) -> [u8; 32] {
    *blake3::hash(data).as_bytes()
}

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("decryption failed: authentication tag mismatch")]
    DecryptionFailed,
    #[error("invalid key material")]
    InvalidKey,
}
