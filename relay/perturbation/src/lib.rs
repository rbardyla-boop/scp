use rand::Rng;
use std::time::Duration;

// ── Protocol-level perturbation budget constants ────────────────────────────
//
// These bounds are protocol law: all SCP clients must use the same limits so
// that traffic behavior across implementations remains indistinguishable.
// Tightening or widening these values is a protocol version bump.

/// Maximum random timing jitter added to any outgoing burst (milliseconds).
pub const MAX_JITTER_MS: u64 = 250;

/// Payload normalization bucket size (bytes). Bursts are padded to the next
/// multiple of this value to reduce length-based traffic fingerprinting.
pub const MIN_PAYLOAD_BUCKET: usize = 256;

/// Maximum padding that normalize_payload() will ever append (bytes).
/// Satisfied by construction when MIN_PAYLOAD_BUCKET ≤ MAX_PADDING_BYTES + 1.
pub const MAX_PADDING_BYTES: usize = 512;

// ── PerturbationEngine ──────────────────────────────────────────────────────

/// Injects bounded timing and size noise before relay handoff.
///
/// Goal: statistical softness, not cryptographic invisibility.
/// Dummy traffic injection is Phase 6 — not implemented here.
pub struct PerturbationEngine {
    /// Upper bound on timing jitter. Use Duration::ZERO for testing.
    pub max_jitter: Duration,
}

impl PerturbationEngine {
    pub fn new(max_jitter: Duration) -> Self {
        Self { max_jitter }
    }

    /// Zero-jitter, zero-normalization engine for tests and local-direct mode.
    pub fn passthrough() -> Self {
        Self { max_jitter: Duration::ZERO }
    }

    /// Returns a bounded random jitter delay in [0, max_jitter].
    /// Caller awaits `tokio::time::sleep(engine.jitter_delay())`.
    pub fn jitter_delay(&self) -> Duration {
        if self.max_jitter.is_zero() {
            return Duration::ZERO;
        }
        let max_ms = self.max_jitter.as_millis() as u64;
        let ms = rand::thread_rng().gen_range(0..=max_ms);
        Duration::from_millis(ms)
    }

    /// Pad `payload` to the next MIN_PAYLOAD_BUCKET boundary.
    /// Padding is zero bytes; bucket quantization removes exact-length signals.
    ///
    /// The padded length never exceeds MAX_PADDING_BYTES beyond the input
    /// (satisfied by MIN_PAYLOAD_BUCKET ≤ MAX_PADDING_BYTES + 1).
    pub fn normalize_payload(&self, payload: &[u8]) -> Vec<u8> {
        let padded_len = bucket_ceil(payload.len());
        let mut out = Vec::with_capacity(padded_len);
        out.extend_from_slice(payload);
        out.resize(padded_len, 0u8);
        out
    }
}

fn bucket_ceil(n: usize) -> usize {
    let b = MIN_PAYLOAD_BUCKET;
    if n == 0 { return b; }
    ((n + b - 1) / b) * b
}
