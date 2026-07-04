/// How `ProviderPool` draws providers when constructing an ephemeral quorum.
pub enum SamplingStrategy {
    /// Draw exactly k providers uniformly at random without replacement.
    RandomK(usize),

    /// Draw k providers with probability proportional to reputation-derived weights.
    ///
    /// Weight = `max(1 / (1 + influence * equivocations), floor)`.
    /// `influence = 0.0` degenerates to uniform. `floor > 0` prevents starvation.
    /// Pre-filters to live providers via `live_indices` before weighting.
    WeightedByReputation {
        k: usize,
        influence: f64,
        floor: f64,
    },

    /// Draw between `min_k` and `max_k` providers from the live active set.
    ///
    /// Actual k = `min(max_k, n_live)` bounded below by `min(min_k, n_live)`.
    /// Equivalent to `RandomK(max_k)` when `n_live >= max_k`.
    Threshold { min_k: usize, max_k: usize },

    /// Combines reputation weighting with a liveness soft-discount across all active providers.
    ///
    /// Unlike `WeightedByReputation`, this variant does NOT pre-filter to live providers.
    /// Dead providers participate with weight `reputation_weight × liveness_discount`.
    /// `liveness_discount = 0.0`: dead providers are effectively excluded (weight = 0).
    /// `liveness_discount = 1.0`: liveness ignored — all providers compete equally by reputation.
    WeightedComposite {
        k: usize,
        influence: f64,
        floor: f64,
        liveness_discount: f64,
    },
}
