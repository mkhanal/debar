use debar_platform::input::InputError;

use crate::object::Object;
use crate::pdf::filters::{StageOutcome, StageReport, pipeline};
use crate::pdf::objects::Filter;
use crate::pdf::pulled::{Pull, PullFactory, PulledWhole, Reading, WindowSource, pull_all};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Content {
    Raw,
    Nothing,
    Decoded { through: usize, length: u64 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChainVerdict {
    pub scanned: Content,
    pub object_stream: Option<Content>,
    pub needed_beyond_the_limit: Option<u64>,
}

pub fn verdict(reports: &[StageReport]) -> ChainVerdict {
    let mut decoded = 0usize;
    let mut emptied = false;
    let mut failed = false;
    let mut needed_beyond_the_limit = None;
    for report in reports {
        match report.outcome {
            StageOutcome::Decoded if report.produced == 0 => {
                emptied = true;
                break;
            }
            StageOutcome::Decoded => decoded = decoded.saturating_add(1),
            StageOutcome::Untouched => break,
            StageOutcome::Failed => {
                failed = true;
                needed_beyond_the_limit = report.needed_beyond_the_limit;
                break;
            }
        }
    }
    let scanned = match decoded.checked_sub(1).and_then(|last| reports.get(last)) {
        None => Content::Raw,
        Some(_) if emptied => Content::Nothing,
        Some(last) => Content::Decoded {
            through: decoded,
            length: last.produced,
        },
    };
    let object_stream = if failed {
        None
    } else if emptied {
        Some(Content::Nothing)
    } else {
        Some(scanned)
    };
    ChainVerdict {
        scanned,
        object_stream,
        needed_beyond_the_limit,
    }
}

#[derive(Clone)]
pub struct StreamWindow<'o> {
    pub document: Object<'o>,
    pub offset: u64,
    pub length: u64,
}

impl<'o> StreamWindow<'o> {
    fn source(&self, reading: Reading) -> Box<dyn Pull + 'o> {
        Box::new(WindowSource::new(
            self.document.clone(),
            self.offset,
            self.length,
            reading,
        ))
    }

    pub fn decoding(&self, filters: &[Filter], reading: Reading) -> Box<dyn Pull + 'o> {
        pipeline(self.source(reading), filters, None).output
    }

    pub fn regenerating(&self, filters: &[Filter]) -> PullFactory<'o> {
        let window = self.clone();
        let filters = filters.to_vec();
        Box::new(move || window.decoding(&filters, Reading::Again))
    }
}

pub struct Measured {
    pub verdict: ChainVerdict,
    pub held: Option<Vec<u8>>,
}

pub fn measure(
    stream: &StreamWindow<'_>,
    filters: &[Filter],
    limit: Option<u64>,
    most_held: u64,
) -> Result<Measured, InputError> {
    if filters.is_empty() {
        return Ok(Measured {
            verdict: verdict(&[]),
            held: None,
        });
    }
    let mut decoding = pipeline(stream.source(Reading::First), filters, limit);
    let whole = pull_all(decoding.output.as_mut(), most_held)?;
    let reports: Vec<StageReport> = decoding.reports.iter().map(|report| report.get()).collect();
    let verdict = verdict(&reports);
    let held = match (whole, verdict.scanned) {
        (PulledWhole::Held(bytes), Content::Decoded { through, .. })
            if through == filters.len() =>
        {
            Some(bytes)
        }
        _ => None,
    };
    Ok(Measured { verdict, held })
}
