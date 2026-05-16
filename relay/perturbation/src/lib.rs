use rand::Rng;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

// ── Protocol-level perturbation budget constants ────────────────────────────
//
// These bounds are protocol law: all SCP clients must use identical limits so
// that traffic behavior across implementations is indistinguishable.
// Changing any value is a protocol version bump.

/// Maximum random timing jitter added to any outgoing burst (milliseconds).
pub const MAX_JITTER_MS: u64 = 250;

/// Payload normalization bucket size (bytes). Bursts are padded to the next
/// multiple of this value to reduce length-based traffic fingerprinting.
pub const MIN_PAYLOAD_BUCKET: usize = 256;

/// Maximum padding that normalize_payload() will ever append (bytes).
/// Satisfied by construction when MIN_PAYLOAD_BUCKET ≤ MAX_PADDING_BYTES + 1.
pub const MAX_PADDING_BYTES: usize = 512;

/// Probability of emitting a dummy burst per real burst, for Active vitality.
pub const DUMMY_BURST_PROBABILITY: f64 = 0.08;

/// Maximum dummy bursts emitted per 60-second window per engine instance.
pub const MAX_DUMMY_BURSTS_PER_MINUTE: u32 = 3;

// ── DummyBudget ─────────────────────────────────────────────────────────────

struct DummyBudget {
    count: u32,
    window_start: Instant,
}

impl DummyBudget {
    fn new() -> Self {
        Self { count: 0, window_start: Instant::now() }
    }

    fn can_emit(&mut self) -> bool {
        if self.window_start.elapsed().as_secs() >= 60 {
            self.count = 0;
            self.window_start = Instant::now();
        }
        if self.count >= MAX_DUMMY_BURSTS_PER_MINUTE {
            return false;
        }
        self.count += 1;
        true
    }
}

// ── PerturbationEngine ──────────────────────────────────────────────────────

/// Injects bounded timing and size noise before relay handoff, and emits
/// sparse dummy bursts after real transmissions.
///
/// Goal: statistical softness, not cryptographic invisibility.
/// Dummy bursts go through the full perturbation pipeline so they are
/// structurally identical to real bursts from the relay's perspective.
pub struct PerturbationEngine {
    /// Upper bound on timing jitter. Use Duration::ZERO for testing.
    pub max_jitter: Duration,
    budget: Arc<Mutex<DummyBudget>>,
}

impl PerturbationEngine {
    pub fn new(max_jitter: Duration) -> Self {
        Self {
            max_jitter,
            budget: Arc::new(Mutex::new(DummyBudget::new())),
        }
    }

    /// Zero-jitter, zero-normalization engine for tests and local-direct mode.
    /// Dummy budget still tracks but probability is unchanged.
    pub fn passthrough() -> Self {
        Self::new(Duration::ZERO)
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
    pub fn normalize_payload(&self, payload: &[u8]) -> Vec<u8> {
        let padded_len = bucket_ceil(payload.len());
        let mut out = Vec::with_capacity(padded_len);
        out.extend_from_slice(payload);
        out.resize(padded_len, 0u8);
        out
    }

    /// Possibly emit a dummy burst after a real transmission.
    ///
    /// Dummy bursts share the full perturbation pipeline — normalization,
    /// jitter, relay randomization — so they are indistinguishable from real
    /// bursts at the relay layer. Budget is per engine instance per minute.
    ///
    /// Vitality correlation is intentionally noisy to avoid deterministic
    /// relationship-fingerprinting through traffic volume.
    pub async fn maybe_emit_dummy(&self, vitality: &scp_vitality::VitalityState) {
        use scp_relay_mesh::{discover_relays, route_burst};

        if !self.should_emit_dummy(vitality) {
            return;
        }
        if !self.budget.lock().unwrap().can_emit() {
            return;
        }

        // Dummy payload: one normalized bucket of zeros.
        // Structurally identical to a real burst from the relay's perspective.
        let dummy_payload = self.normalize_payload(&[]);

        // Full pipeline: jitter → relay select → transmit.
        tokio::time::sleep(self.jitter_delay()).await;
        if let Ok(relays) = discover_relays().await {
            let _ = route_burst(dummy_payload, relays).await;
        }
    }

    fn should_emit_dummy(&self, vitality: &scp_vitality::VitalityState) -> bool {
        use scp_vitality::VitalityState;
        if !vitality.is_open() {
            return false;
        }
        let base_p = match vitality {
            VitalityState::Active => DUMMY_BURST_PROBABILITY,
            VitalityState::Warm   => DUMMY_BURST_PROBABILITY * 0.5,
            _                     => 0.0,
        };
        // Small noise on the base probability prevents deterministic
        // vitality-volume correlation from becoming a relationship fingerprint.
        let noise: f64 = rand::thread_rng().gen_range(-0.015..=0.015);
        rand::thread_rng().gen::<f64>() < (base_p + noise).clamp(0.0, 1.0)
    }
}

fn bucket_ceil(n: usize) -> usize {
    let b = MIN_PAYLOAD_BUCKET;
    if n == 0 { return b; }
    ((n + b - 1) / b) * b
}
