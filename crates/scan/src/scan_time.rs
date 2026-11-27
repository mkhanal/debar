use debar_matching::WorkMeter;

const WORK_PER_MILLISECOND: u64 = 31_590;
pub const DEFAULT_LONGEST_SCAN: ScanTime = ScanTime::from_milliseconds(120_000);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScanTime {
    milliseconds: u64,
}

impl ScanTime {
    #[must_use]
    pub const fn from_milliseconds(milliseconds: u64) -> Self {
        Self { milliseconds }
    }

    const fn work_allowed(self) -> u64 {
        self.milliseconds.saturating_mul(WORK_PER_MILLISECOND)
    }
}

pub(crate) const fn work_meter_for(longest_scan: Option<ScanTime>) -> WorkMeter {
    match longest_scan {
        Some(longest) => WorkMeter::allowing(longest.work_allowed()),
        None => WorkMeter::unlimited(),
    }
}
