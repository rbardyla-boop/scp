use std::time::Instant;

/// Probability of issuing a dummy query per `maybe_issue_dummy_query` call.
pub const DUMMY_QUERY_PROBABILITY: f64 = 0.05;

/// Maximum dummy queries issued per 60-second window per pool instance.
pub const MAX_DUMMY_QUERIES_PER_MINUTE: u32 = 3;

pub(crate) struct DummyQueryBudget {
    count:        u32,
    window_start: Instant,
}

impl DummyQueryBudget {
    pub(crate) fn new() -> Self {
        Self { count: 0, window_start: Instant::now() }
    }

    pub(crate) fn can_emit(&mut self) -> bool {
        if self.window_start.elapsed().as_secs() >= 60 {
            self.count = 0;
            self.window_start = Instant::now();
        }
        if self.count >= MAX_DUMMY_QUERIES_PER_MINUTE {
            return false;
        }
        self.count += 1;
        true
    }
}
