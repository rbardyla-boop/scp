pub(crate) struct LivenessState {
    pub(crate) last_seen_secs: u64,
    pub(crate) consecutive_failures: u32,
}

pub(crate) struct LivenessConfig {
    pub(crate) max_consecutive_failures: u32,
    pub(crate) max_silence_secs: u64,
}
