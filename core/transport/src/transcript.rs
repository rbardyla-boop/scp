pub mod v1;
pub mod v2;

pub use v1::FlashTranscript;
pub use v2::FlashTranscriptV2;

/// Structured key material for transport session key derivation.
///
/// Version-agnostic: the same 96-byte layout is fed into `scp_derive_key`
/// regardless of whether the session uses the v1 (OsRng seed) or v2 (DH
/// output) derivation path. What changes between versions is what
/// `ephemeral_seed` contains and which transcript hash is used.
///
/// Field order is protocol-stable:
///   ephemeral_seed | transcript_hash | recipient_binding
pub struct TransportKeyMaterial {
    /// v1: random 32 bytes from OsRng (forward secrecy via entropy).
    /// v2: raw X25519 DH output (forward secrecy via bilateral contribution).
    pub ephemeral_seed:    [u8; 32],
    /// FlashTranscript::hash() or FlashTranscriptV2::hash() —
    /// binds the key to its exact (route, nonce, recipient, vitality, version) context.
    pub transcript_hash:   [u8; 32],
    /// Recipient's operational public key — ensures key is recipient-specific.
    pub recipient_binding: [u8; 32],
}

impl TransportKeyMaterial {
    /// Serialize to 96 bytes in canonical order for `scp_derive_key`.
    pub fn as_bytes(&self) -> [u8; 96] {
        let mut out = [0u8; 96];
        out[0..32].copy_from_slice(&self.ephemeral_seed);
        out[32..64].copy_from_slice(&self.transcript_hash);
        out[64..96].copy_from_slice(&self.recipient_binding);
        out
    }
}
