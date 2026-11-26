use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt;

use debar_image::{
    AnchoredProgram, Category, GroupMalformed, Image, ImageError, Indicator, LONG_ANCHOR_LENGTH,
    PatternGroup, PatternSignatureId, PatternSignatureRecord, Placement, ProgramId, ProgramView,
    ReportWindows, SHORT_ANCHOR_LENGTH,
};

use crate::verification::{PositionSet, RetainedBytes, match_ends};

const POSITIONS_PER_PASS: u64 = 4096;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PatternSettings {
    pub potentially_unwanted: bool,
    pub every_match: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PatternDetection {
    pub name: String,
    pub indicator: Indicator,
}

#[derive(Debug)]
pub enum PatternScanError {
    Image(ImageError),
    Group(GroupMalformed),
    MoreBytesThanDeclared { declared: u64 },
    FewerBytesThanDeclared { declared: u64, fed: u64 },
    RetainedBytesLost { position: u64 },
}

impl fmt::Display for PatternScanError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Image(error) => write!(formatter, "{error}"),
            Self::Group(error) => {
                write!(formatter, "the pattern signatures are malformed: {error:?}")
            }
            Self::MoreBytesThanDeclared { declared } => {
                write!(
                    formatter,
                    "the object holds more than its declared {declared} bytes"
                )
            }
            Self::FewerBytesThanDeclared { declared, fed } => write!(
                formatter,
                "the object ended after {fed} of its declared {declared} bytes"
            ),
            Self::RetainedBytesLost { position } => write!(
                formatter,
                "the bytes at {position} were released before a candidate there was verified"
            ),
        }
    }
}

impl std::error::Error for PatternScanError {}

impl From<GroupMalformed> for PatternScanError {
    fn from(error: GroupMalformed) -> Self {
        Self::Group(error)
    }
}

impl From<ImageError> for PatternScanError {
    fn from(error: ImageError) -> Self {
        Self::Image(error)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanProgress {
    Continue,
    Stopped,
}

#[derive(Debug, Clone)]
struct Candidate {
    anchor: u64,
    program: ProgramId,
    first_start: u64,
    last_start: u64,
    ready_at: u64,
}

pub struct PatternScan<'i, 'm> {
    image: &'i Image<'m>,
    group: Option<PatternGroup<'m>>,
    settings: PatternSettings,
    object_length: u64,
    retained: Vec<u8>,
    first_retained: u64,
    fed: u64,
    probed_to: u64,
    positional: VecDeque<Candidate>,
    queue: VecDeque<Candidate>,
    chains: BTreeMap<u32, Vec<u64>>,
    detected: BTreeSet<u32>,
    found: Vec<Found>,
    stop_once_past: Option<u64>,
    stopped: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct ReportOrder {
    window: u64,
    rank: u8,
    position: u64,
}

struct Found {
    order: ReportOrder,
    detection: PatternDetection,
}

impl<'i, 'm> PatternScan<'i, 'm> {
    pub fn new(
        image: &'i Image<'m>,
        settings: PatternSettings,
        object_length: u64,
    ) -> Result<Self, PatternScanError> {
        let group = image.pattern_group()?;
        let mut scan = Self {
            image,
            group,
            settings,
            object_length,
            retained: Vec::new(),
            first_retained: 0,
            fed: 0,
            probed_to: 0,
            positional: VecDeque::new(),
            queue: VecDeque::new(),
            chains: BTreeMap::new(),
            detected: BTreeSet::new(),
            found: Vec::new(),
            stop_once_past: None,
            stopped: false,
        };
        scan.place_positional()?;
        Ok(scan)
    }

    pub fn feed(&mut self, chunk: &[u8]) -> Result<ScanProgress, PatternScanError> {
        let length = u64::try_from(chunk.len()).unwrap_or(u64::MAX);
        let fed = self
            .fed
            .checked_add(length)
            .filter(|fed| *fed <= self.object_length)
            .ok_or(PatternScanError::MoreBytesThanDeclared {
                declared: self.object_length,
            })?;
        if self.stopped || self.group.is_none() {
            self.fed = fed;
            return Ok(self.progress());
        }
        self.retained.extend_from_slice(chunk);
        self.fed = fed;
        self.advance()?;
        Ok(self.progress())
    }

    pub fn finish(mut self) -> Result<Vec<PatternDetection>, PatternScanError> {
        if self.fed != self.object_length {
            return Err(PatternScanError::FewerBytesThanDeclared {
                declared: self.object_length,
                fed: self.fed,
            });
        }
        if !self.stopped && self.group.is_some() {
            self.advance()?;
        }
        self.found.sort_by_key(|found| found.order);
        let mut detections = Vec::with_capacity(self.found.len());
        for found in self.found {
            let strong = found.detection.indicator == Indicator::Strong;
            detections.push(found.detection);
            if strong && !self.settings.every_match {
                break;
            }
        }
        Ok(detections)
    }

    fn progress(&self) -> ScanProgress {
        if self.stopped {
            ScanProgress::Stopped
        } else {
            ScanProgress::Continue
        }
    }

    fn place_positional(&mut self) -> Result<(), PatternScanError> {
        let Some(group) = self.group else {
            return Ok(());
        };
        let mut placed = Vec::new();
        for id in group.positional() {
            let record = group.signature(id)?;
            if !self.category_is_live(record.category) {
                continue;
            }
            let Some((first_start, last_start)) = self.placed_starts(record.placement) else {
                continue;
            };
            let program = group.program(record.first_program)?;
            placed.push(Candidate {
                anchor: first_start,
                program: record.first_program,
                first_start,
                last_start,
                ready_at: ready_at(&program, last_start),
            });
        }
        placed.sort_by_key(|candidate| candidate.first_start);
        self.positional = placed.into();
        Ok(())
    }

    fn placed_starts(&self, placement: Placement) -> Option<(u64, u64)> {
        let (first, shift) = match placement {
            Placement::Anywhere => return None,
            Placement::FromStart { distance, shift } => (u64::from(distance), shift),
            Placement::BeforeEnd { distance, shift } => {
                (self.object_length.checked_sub(u64::from(distance))?, shift)
            }
        };
        let last = first
            .saturating_add(u64::from(shift))
            .min(self.object_length.checked_sub(1)?);
        (first <= last).then_some((first, last))
    }

    fn category_is_live(&self, category: Category) -> bool {
        match category {
            Category::Malware => true,
            Category::PotentiallyUnwanted => self.settings.potentially_unwanted,
        }
    }

    fn advance(&mut self) -> Result<(), PatternScanError> {
        let Some(group) = self.group else {
            return Ok(());
        };
        let complete = self.fed == self.object_length;
        let probe_limit = if complete {
            self.fed
        } else {
            self.fed.saturating_sub(3)
        };
        while self.probed_to < probe_limit && !self.stopped {
            let pass_end = self
                .probed_to
                .saturating_add(POSITIONS_PER_PASS)
                .min(probe_limit);
            self.probe(&group, pass_end)?;
            self.verify_ready()?;
        }
        if complete {
            while let Some(candidate) = self.positional.pop_front() {
                self.queue.push_back(candidate);
            }
        }
        self.verify_ready()?;
        self.release_unneeded(&group);
        Ok(())
    }

    fn probe(&mut self, group: &PatternGroup<'m>, pass_end: u64) -> Result<(), PatternScanError> {
        let long_filter = group.long_anchor_filter();
        let short_filter = group.short_anchor_filter();
        let probes_short = group.has_short_anchors();
        let everywhere: Vec<ProgramId> = group.everywhere().collect();
        let mut hits: Vec<(u64, AnchoredProgram)> = Vec::new();
        let mut position = self.probed_to;
        while position < pass_end {
            let window = self.window_at(position, LONG_ANCHOR_LENGTH);
            if let Some(window) =
                window.and_then(|window| <[u8; LONG_ANCHOR_LENGTH]>::try_from(window).ok())
                && long_filter.may_hold(u32::from_le_bytes(window))
            {
                hits.extend(group.long_anchored(window).map(|hit| (position, hit)));
            }
            if probes_short
                && let Some(window) = self
                    .window_at(position, SHORT_ANCHOR_LENGTH)
                    .and_then(|window| <[u8; SHORT_ANCHOR_LENGTH]>::try_from(window).ok())
                && short_filter.may_hold(u16::from_le_bytes(window))
            {
                hits.extend(group.short_anchored(window).map(|hit| (position, hit)));
            }
            for program in &everywhere {
                hits.push((
                    position,
                    AnchoredProgram {
                        program: *program,
                        displacement: debar_image::Displacement {
                            nearest: 0,
                            farthest: 0,
                        },
                    },
                ));
            }
            position = position.saturating_add(1);
        }
        self.probed_to = pass_end;
        for (position, hit) in hits {
            self.admit_positional_up_to(position);
            let program = group.program(hit.program)?;
            let Some(last_start) = position.checked_sub(u64::from(hit.displacement.nearest)) else {
                continue;
            };
            let first_start = position.saturating_sub(u64::from(hit.displacement.farthest));
            self.queue.push_back(Candidate {
                anchor: position,
                program: hit.program,
                first_start,
                last_start,
                ready_at: ready_at(&program, last_start),
            });
        }
        self.admit_positional_up_to(pass_end.saturating_sub(1));
        Ok(())
    }

    fn admit_positional_up_to(&mut self, position: u64) {
        while self
            .positional
            .front()
            .is_some_and(|candidate| candidate.first_start <= position)
        {
            if let Some(candidate) = self.positional.pop_front() {
                self.queue.push_back(candidate);
            }
        }
    }

    fn window_at(&self, position: u64, length: usize) -> Option<&[u8]> {
        let start = usize::try_from(position.checked_sub(self.first_retained)?).ok()?;
        self.retained.get(start..start.checked_add(length)?)
    }

    fn verify_ready(&mut self) -> Result<(), PatternScanError> {
        let available = self.fed;
        let complete = self.fed == self.object_length;
        while let Some(candidate) = self.queue.front() {
            if self.stopped {
                self.queue.clear();
                return Ok(());
            }
            if self
                .stop_once_past
                .is_some_and(|window_end| candidate.anchor >= window_end)
            {
                self.stopped = true;
                continue;
            }
            if !complete && candidate.ready_at > available {
                return Ok(());
            }
            if let Some(candidate) = self.queue.pop_front() {
                self.verify(&candidate)?;
            }
        }
        Ok(())
    }

    fn verify(&mut self, candidate: &Candidate) -> Result<(), PatternScanError> {
        let Some(group) = self.group else {
            return Ok(());
        };
        let program = group.program(candidate.program)?;
        let signature = program.header.signature.get();
        if self.detected.contains(&signature) {
            return Ok(());
        }
        let record = group.signature(PatternSignatureId(signature))?;
        if !self.category_is_live(record.category) {
            return Ok(());
        }
        let segment = program.header.segment.get();
        let mut first_start = candidate.first_start;
        if let Some(previous) = segment.checked_sub(1) {
            let Some(previous_end) = self
                .chains
                .get(&signature)
                .and_then(|ends| ends.get(usize::try_from(previous).ok()?))
            else {
                return Ok(());
            };
            first_start = first_start
                .max(previous_end.saturating_add(u64::from(program.header.gap_before.get())));
        }
        if first_start > candidate.last_start {
            return Ok(());
        }
        if first_start < self.first_retained {
            return Err(PatternScanError::RetainedBytesLost {
                position: first_start,
            });
        }
        let bytes = RetainedBytes {
            bytes: &self.retained,
            first_position: self.first_retained,
            object_length: self.object_length,
        };
        let ends = match_ends(
            &program,
            &bytes,
            &PositionSet::between(first_start, candidate.last_start),
        )
        .map_err(|_| GroupMalformed::Program(candidate.program))?;
        let Some(earliest_end) = ends.first() else {
            return Ok(());
        };
        if segment.saturating_add(1) < record.segment_count {
            let ends = self.chains.entry(signature).or_default();
            let index = usize::try_from(segment).unwrap_or(usize::MAX);
            if let Some(end) = ends.get_mut(index) {
                *end = (*end).min(earliest_end);
            } else if ends.len() == index {
                ends.push(earliest_end);
            }
            return Ok(());
        }
        let order = ReportOrder {
            window: report_window(self.report_windows(), earliest_end),
            rank: record.report_rank,
            position: candidate.anchor,
        };
        self.detect(signature, &record, order)
    }

    fn report_windows(&self) -> Option<ReportWindows> {
        self.group.and_then(|group| group.report_windows())
    }

    fn detect(
        &mut self,
        signature: u32,
        record: &PatternSignatureRecord,
        order: ReportOrder,
    ) -> Result<(), PatternScanError> {
        self.detected.insert(signature);
        self.chains.remove(&signature);
        let name = self.image.signature_name(record.name)?;
        if name.indicator == Indicator::Strong
            && !self.settings.every_match
            && self.stop_once_past.is_none()
        {
            self.stop_once_past = Some(window_end(self.report_windows(), order.window));
        }
        self.found.push(Found {
            order,
            detection: PatternDetection {
                name: name.text,
                indicator: name.indicator,
            },
        });
        Ok(())
    }

    fn release_unneeded(&mut self, group: &PatternGroup<'m>) {
        let oldest_needed = self
            .queue
            .front()
            .map_or(self.probed_to, |candidate| {
                candidate.first_start.min(self.probed_to)
            })
            .saturating_sub(u64::from(group.lookback()));
        let releasable = usize::try_from(oldest_needed.saturating_sub(self.first_retained))
            .unwrap_or(usize::MAX)
            .min(self.retained.len());
        if releasable > 0 && releasable >= self.retained.len() / 2 {
            self.retained.drain(..releasable);
            self.first_retained = self
                .first_retained
                .saturating_add(u64::try_from(releasable).unwrap_or(u64::MAX));
        }
    }
}

fn report_window(windows: Option<ReportWindows>, match_end: u64) -> u64 {
    let Some(windows) = windows else {
        return 0;
    };
    let step = u64::from(windows.length.saturating_sub(windows.overlap)).max(1);
    match_end
        .saturating_sub(u64::from(windows.length))
        .div_ceil(step)
}

fn window_end(windows: Option<ReportWindows>, window: u64) -> u64 {
    let Some(windows) = windows else {
        return u64::MAX;
    };
    let step = u64::from(windows.length.saturating_sub(windows.overlap)).max(1);
    window
        .saturating_mul(step)
        .saturating_add(u64::from(windows.length))
}

fn ready_at(program: &ProgramView<'_>, last_start: u64) -> u64 {
    let after_reach = program.after.map_or(0, |after| {
        after
            .sequences()
            .filter_map(Result::ok)
            .map(|sets| u64::try_from(sets.len() / 32).unwrap_or(u64::MAX))
            .max()
            .unwrap_or(0)
    });
    last_start
        .saturating_add(u64::from(program.header.longest.get()))
        .saturating_add(after_reach)
}
