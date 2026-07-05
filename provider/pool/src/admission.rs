use std::collections::HashMap;
use std::time::{Duration, Instant};

use scp_cryptography::keys::PublicKey;

const ADMISSION_PREFIX: &[u8] = b"scp:admission-challenge:v1:"; // 27 bytes

/// Domain-separated message candidates sign to prove key ownership.
///
/// Format: `"scp:admission-challenge:v1:" || provider_id || challenge` = 91 bytes.
/// The candidate signs this with their Ed25519 private key; the pool verifies with
/// `provider_id` as the public key.
pub fn admission_challenge_message(provider_id: &[u8; 32], challenge: &[u8; 32]) -> [u8; 91] {
    let mut msg = [0u8; 91];
    msg[..27].copy_from_slice(ADMISSION_PREFIX);
    msg[27..59].copy_from_slice(provider_id);
    msg[59..91].copy_from_slice(challenge);
    msg
}

/// Configuration for the provider admission gate.
pub struct AdmissionConfig {
    /// Maximum provider admits allowed per rolling time window.
    pub max_admits_per_window: u32,
    /// Duration of the rolling window for the admit budget.
    pub window_duration: Duration,
    /// How long a pending challenge remains valid before it expires.
    pub challenge_ttl: Duration,
}

/// Errors returned by `request_admission()` and `complete_admission()`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmissionError {
    /// Admission gate not configured; call `.with_admission()` on the pool builder.
    NotConfigured,
    /// Admit budget exhausted for this window; retry after `window_duration` elapses.
    BudgetExhausted,
    /// `provider_id` is already in the active or dormant set.
    AlreadyInPool,
    /// A challenge is already pending for this `provider_id`.
    PendingChallenge,
    /// No pending challenge found; call `request_admission()` first.
    ChallengeNotFound,
    /// Challenge TTL elapsed before `complete_admission()` was called.
    ChallengeExpired,
    /// Ed25519 signature verification failed.
    SignatureInvalid,
    /// Provider is permanently banned by an operator (`EvictionReason::OperatorBan`).
    /// Call `lift_eviction_ban()` to remove the ban before re-admission is possible.
    Banned,
    /// Provider was evicted and the cooldown period has not yet elapsed.
    /// `eligible_at_secs` is the earliest Unix timestamp at which re-admission may proceed.
    EvictionCooldown { eligible_at_secs: u64 },
    /// Provider has been re-admitted the maximum number of times allowed by `EvictionConfig`.
    MaxReAdmissionsExceeded,
}

pub(crate) struct PendingAdmission {
    pub(crate) challenge: [u8; 32],
    pub(crate) issued_at: Instant,
}

pub(crate) struct AdmissionState {
    pub(crate) config: AdmissionConfig,
    pub(crate) pending: HashMap<[u8; 32], PendingAdmission>,
    pub(crate) budget_count: u32,
    pub(crate) budget_window_start: Instant,
}

impl AdmissionState {
    pub(crate) fn new(config: AdmissionConfig) -> Self {
        Self {
            budget_count: 0,
            budget_window_start: Instant::now(),
            pending: HashMap::new(),
            config,
        }
    }

    /// Checks and atomically claims one admit from the rolling budget.
    /// Resets the counter if the window has elapsed. Returns `false` when exhausted.
    pub(crate) fn check_and_claim_budget(&mut self) -> bool {
        if self.budget_window_start.elapsed() >= self.config.window_duration {
            self.budget_count = 0;
            self.budget_window_start = Instant::now();
        }
        if self.budget_count >= self.config.max_admits_per_window {
            return false;
        }
        self.budget_count += 1;
        true
    }

    /// Verifies a challenge response without removing the pending entry.
    /// On failure, the pending entry remains (consumable until TTL expires).
    pub(crate) fn verify(
        &self,
        provider_id: &[u8; 32],
        sig: &[u8; 64],
    ) -> Result<(), AdmissionError> {
        let pending = self
            .pending
            .get(provider_id)
            .ok_or(AdmissionError::ChallengeNotFound)?;
        if pending.issued_at.elapsed() > self.config.challenge_ttl {
            return Err(AdmissionError::ChallengeExpired);
        }
        let msg = admission_challenge_message(provider_id, &pending.challenge);
        if !PublicKey(*provider_id).verify(&msg, sig) {
            return Err(AdmissionError::SignatureInvalid);
        }
        Ok(())
    }
}
