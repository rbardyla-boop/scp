/// Errors returned when constructing a [`SimVitalityEvaluationContext`].
#[derive(Debug, Clone, PartialEq)]
pub enum SimVitalityContextError {
    /// `i` (interaction entropy) is outside the valid range.
    InvalidI(f64),
    /// `r` (reciprocal participation) is outside the valid range.
    InvalidR(f64),
    /// `p` (perturbation pressure) is outside the valid range.
    InvalidP(f64),
}

impl std::fmt::Display for SimVitalityContextError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidI(v) => write!(f, "i={v} is not a finite value in [0.0, 1.0]"),
            Self::InvalidR(v) => write!(f, "r={v} is not a finite value in [0.0, 1.0]"),
            Self::InvalidP(v) => write!(f, "p={v} is not a finite value in [0.0, 1.0]"),
        }
    }
}

impl std::error::Error for SimVitalityContextError {}

/// Explicit vitality evaluation context for simulator runtime tests.
///
/// SIMULATOR ONLY. All three formula inputs (`i`, `r`, `p`) are declared scenario
/// controls, not production measurements. Do not substitute real network interaction
/// data through this type.
///
/// Fields are private. Construction goes through [`SimVitalityEvaluationContext::new`],
/// which rejects any control value that is outside `[0.0, 1.0]`, `NaN`, or non-finite.
/// This makes invalid scenario declarations fail loudly rather than being silently
/// clamped, preserving the invariant that the underlying vitality formula is not
/// redesigned by this type.
#[derive(Debug)]
pub struct SimVitalityEvaluationContext {
    /// Pre-computed tunnel consent hash — `tunnel_consent_hash(sender, recipient)`.
    /// Must be derived from a real bilateral tunnel consent; not an arbitrary byte string.
    consent_hash: [u8; 32],
    /// Evaluation timestamp (Unix seconds). Governs both ephemeral expiry and
    /// vitality computation. Deterministic — not `SystemTime::now()`.
    now: u64,
    /// Declared interaction entropy control, validated finite in [0.0, 1.0].
    i: f64,
    /// Declared reciprocal participation control, validated finite in [0.0, 1.0].
    r: f64,
    /// Declared perturbation pressure control, validated finite in [0.0, 1.0].
    p: f64,
}

fn is_valid_control(v: f64) -> bool {
    v.is_finite() && (0.0..=1.0).contains(&v)
}

impl SimVitalityEvaluationContext {
    /// Construct a validated simulator evaluation context.
    ///
    /// Returns `Err` if any of `i`, `r`, or `p` is outside the inclusive range
    /// `[0.0, 1.0]`, is `NaN`, or is infinite. Valid values are finite and satisfy
    /// `0.0 <= v <= 1.0`.
    ///
    /// `consent_hash` must be the canonical `tunnel_consent_hash(sender, recipient)`
    /// derived from an actual bilateral tunnel consent registration. Callers are
    /// responsible for assembling bilateral identity before constructing this context.
    pub fn new(
        consent_hash: [u8; 32],
        now: u64,
        i: f64,
        r: f64,
        p: f64,
    ) -> Result<Self, SimVitalityContextError> {
        if !is_valid_control(i) {
            return Err(SimVitalityContextError::InvalidI(i));
        }
        if !is_valid_control(r) {
            return Err(SimVitalityContextError::InvalidR(r));
        }
        if !is_valid_control(p) {
            return Err(SimVitalityContextError::InvalidP(p));
        }
        Ok(Self {
            consent_hash,
            now,
            i,
            r,
            p,
        })
    }

    /// Returns the pre-computed bilateral tunnel consent hash.
    pub fn consent_hash(&self) -> [u8; 32] {
        self.consent_hash
    }

    /// Returns the simulated evaluation timestamp (Unix seconds).
    pub fn now(&self) -> u64 {
        self.now
    }

    /// Returns the declared interaction entropy control.
    pub fn i(&self) -> f64 {
        self.i
    }

    /// Returns the declared reciprocal participation control.
    pub fn r(&self) -> f64 {
        self.r
    }

    /// Returns the declared perturbation pressure control.
    pub fn p(&self) -> f64 {
        self.p
    }
}
