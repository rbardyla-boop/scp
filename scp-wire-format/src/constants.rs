// ── Transcript format ──────────────────────────────────────────────────────
pub const TRANSCRIPT_MAGIC: &[u8; 4] = b"SCPt";
pub const TRANSCRIPT_V1_FORMAT: u8   = 0x01;
pub const TRANSCRIPT_V2_FORMAT: u8   = 0x02;
pub const TRANSCRIPT_V1_LEN: usize   = 63;
pub const TRANSCRIPT_V2_LEN: usize   = 95;

// ── Vitality wire bytes ────────────────────────────────────────────────────
pub const VITALITY_ACTIVE:    u8 = 0;
pub const VITALITY_WARM:      u8 = 1;
pub const VITALITY_DORMANT:   u8 = 2;
pub const VITALITY_SUSPENDED: u8 = 3;
pub const VITALITY_SEVERED:   u8 = 4;
pub const VITALITY_BURNED:    u8 = 5;

// ── Relay wire protocol ────────────────────────────────────────────────────
/// TCP frame header length: u32 payload length prefix, little-endian.
pub const TCP_FRAME_HEADER_LEN: usize  = 4;
/// Noise frame header length: u16 message length prefix, big-endian (Noise standard).
///
/// Note: TCP uses LE u32; Noise uses BE u16. This inconsistency is preserved to
/// avoid a breaking protocol change. Unification is planned for Phase 9.
pub const NOISE_FRAME_HEADER_LEN: usize = 2;
pub const RELAY_ACK_BYTE: u8           = 0x01;
pub const NOISE_PARAMS: &str           = "Noise_XX_25519_ChaChaPoly_BLAKE2s";

// ── Signing message layout ─────────────────────────────────────────────────
pub const HANDSHAKE_SIG_PREFIX: &[u8; 27] = b"scp:handshake-ephemeral:v1:";
/// Handshake sig message length: 27 + 32 + 8 = 67.
pub const HANDSHAKE_SIG_MSG_LEN: usize = 67;
/// Registration message length: 32 + 32 + 32 = 96.
pub const REGISTRATION_MSG_LEN: usize  = 96;
/// Rotation message length: 32 + 32 + 8 = 72.
pub const ROTATION_MSG_LEN: usize      = 72;

// ── Perturbation protocol ──────────────────────────────────────────────────
pub const PAYLOAD_BUCKET_BYTES: usize = 256;
