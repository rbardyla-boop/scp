/// Input parameters for the vitality function V(t, i, r, p).
#[derive(Debug, Clone)]
pub struct VitalityParams {
    /// Seconds elapsed since the last successful reaffirmation event.
    /// 0 = just reaffirmed, 2_592_000 = 30 days.
    pub t: f64,
    /// Interaction entropy — diversity and richness of recent exchanges, in [0.0, 1.0].
    /// 0 = no interaction, 1 = maximum variety and frequency.
    pub i: f64,
    /// Reciprocal participation quality — symmetry of engagement, in [0.0, 1.0].
    /// 0 = entirely one-sided, 1 = perfectly mutual.
    pub r: f64,
    /// Protocol perturbation factor injected by the relay layer, in [0.0, 1.0].
    /// 0 = no noise, 1 = maximum uncertainty about the relationship.
    pub p: f64,
}

/// Characteristic time constant: vitality decays to ~37% after 30 days of silence.
const TAU_SECS: f64 = 30.0 * 24.0 * 3600.0; // 2_592_000 s

/// Perturbation weight: max 20% reduction from relay noise.
const PERTURBATION_WEIGHT: f64 = 0.20;

/// Compute a normalized vitality score in [0.0, 1.0].
///
/// Formula: V = exp(-t / TAU) * sqrt(i * r) * (1 - PERTURBATION_WEIGHT * p)
///
/// Properties:
/// - Decays exponentially with time since last reaffirmation
/// - Geometric mean of interaction entropy and reciprocal participation
/// - Perturbation injects controlled statistical uncertainty
/// - Probabilistic and non-binary — caller maps to VitalityState bands
pub fn compute(params: VitalityParams) -> f64 {
    let time_decay = (-params.t / TAU_SECS).exp();
    let engagement  = (params.i.clamp(0.0, 1.0) * params.r.clamp(0.0, 1.0)).sqrt();
    let perturbation_reduction = 1.0 - PERTURBATION_WEIGHT * params.p.clamp(0.0, 1.0);

    (time_decay * engagement * perturbation_reduction).clamp(0.0, 1.0)
}
