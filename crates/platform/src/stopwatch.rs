use std::time::{Duration, Instant};

pub struct Stopwatch {
    started: Instant,
}

impl Stopwatch {
    #[must_use]
    pub fn start() -> Self {
        Self {
            started: Instant::now(),
        }
    }

    #[must_use]
    pub fn elapsed(&self) -> Duration {
        self.started.elapsed()
    }
}
