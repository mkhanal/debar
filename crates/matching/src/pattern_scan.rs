use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt;

use debar_image::{
    AnchoredProgram, Category, GroupMalformed, Image, ImageError, Indicator, KindsMalformed,
    LONG_ANCHOR_LENGTH, ObjectKind, PatternGroup, PatternSignatureId, PatternSignatureRecord,
    ProgramId, ProgramView, RecordedOutcome, ReportWindows, SHORT_ANCHOR_LENGTH, SignatureGroup,
};

use crate::executable_layout::{ExecutableLayout, LayoutState, placed_starts};
use crate::part_ends::RememberedEnds;
use crate::verification::{PositionSet, RetainedBytes, match_ends};

const POSITIONS_PER_PASS: u64 = 4096;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PatternSettings {
    pub potentially_unwanted: bool,
    pub every_match: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroupSelection {
    ForKind(ObjectKind),
    ForKindRecognisingTypes(ObjectKind),
    TypeRecognitionOnly(ObjectKind),
}

impl GroupSelection {
    const fn kind(self) -> ObjectKind {
        match self {
            Self::ForKind(kind)
            | Self::ForKindRecognisingTypes(kind)
            | Self::TypeRecognitionOnly(kind) => kind,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PatternRequest {
    pub selection: GroupSelection,
    pub settings: PatternSettings,
    pub object_length: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PatternDetection {
    pub name: String,
    pub indicator: Indicator,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TypeFound {
    pub kind: ObjectKind,
    pub offset: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PatternOutcomes {
    pub detections: Vec<PatternDetection>,
    pub types_found: Vec<TypeFound>,
}

#[derive(Debug)]
pub enum PatternScanError {
    Image(ImageError),
    Group(GroupMalformed),
    Kinds(KindsMalformed),
    KindNotDescribed(ObjectKind),
    NoTypeRecognition,
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
            Self::Kinds(error) => write!(formatter, "the object kinds are malformed: {error:?}"),
            Self::KindNotDescribed(kind) => write!(
                formatter,
                "the image does not say which signatures apply to {kind:?}"
            ),
            Self::NoTypeRecognition => {
                write!(formatter, "the image holds no type recognition signatures")
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
    group: usize,
    anchor: u64,
    program: ProgramId,
    first_start: u64,
    last_start: u64,
    ready_at: u64,
}

struct SelectedGroup<'m> {
    view: PatternGroup<'m>,
    chains: BTreeMap<u32, Vec<RememberedEnds>>,
    detected: BTreeSet<u32>,
}

pub struct PatternScan<'i, 'm> {
    image: &'i Image<'m>,
    groups: Vec<SelectedGroup<'m>>,
    kind: ObjectKind,
    settings: PatternSettings,
    object_length: u64,
    report_windows: Option<ReportWindows>,
    lookback: u32,
    retained: Vec<u8>,
    first_retained: u64,
    fed: u64,
    probed_to: u64,
    positional: VecDeque<Candidate>,
    queue: VecDeque<Candidate>,
    found: Vec<Found>,
    types_found: Vec<TypeFound>,
    stop_once_past: Option<u64>,
    stopped: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct ReportOrder {
    window: u64,
    group: usize,
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
        request: PatternRequest,
        executable_layout: impl FnOnce() -> Option<ExecutableLayout>,
    ) -> Result<Self, PatternScanError> {
        let selected = selected_groups(image, request.selection)?;
        let groups = selected
            .groups
            .into_iter()
            .map(|view| SelectedGroup {
                view,
                chains: BTreeMap::new(),
                detected: BTreeSet::new(),
            })
            .collect::<Vec<_>>();
        let report_windows = combined_report_windows(&groups);
        let lookback = groups
            .iter()
            .map(|group| group.view.lookback())
            .max()
            .unwrap_or(0);
        let layout = match selected.layout {
            LayoutNeed::NotExecutable => None,
            LayoutNeed::NeverResolved => Some(None),
            LayoutNeed::Executable => Some(executable_layout()),
        };
        let mut scan = Self {
            image,
            groups,
            kind: request.selection.kind(),
            settings: request.settings,
            object_length: request.object_length,
            report_windows,
            lookback,
            retained: Vec::new(),
            first_retained: 0,
            fed: 0,
            probed_to: 0,
            positional: VecDeque::new(),
            queue: VecDeque::new(),
            found: Vec::new(),
            types_found: Vec::new(),
            stop_once_past: None,
            stopped: false,
        };
        let state = match &layout {
            None => LayoutState::NotExecutable,
            Some(None) => LayoutState::Missing,
            Some(Some(layout)) => LayoutState::Known(layout),
        };
        scan.place_positional(state)?;
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
        if self.stopped || self.groups.is_empty() {
            self.fed = fed;
            return Ok(self.progress());
        }
        self.retained.extend_from_slice(chunk);
        self.fed = fed;
        self.advance()?;
        Ok(self.progress())
    }

    pub fn finish(mut self) -> Result<PatternOutcomes, PatternScanError> {
        if self.fed != self.object_length {
            return Err(PatternScanError::FewerBytesThanDeclared {
                declared: self.object_length,
                fed: self.fed,
            });
        }
        if !self.stopped && !self.groups.is_empty() {
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
        self.types_found.sort_by_key(|found| found.offset);
        Ok(PatternOutcomes {
            detections,
            types_found: self.types_found,
        })
    }

    fn progress(&self) -> ScanProgress {
        if self.stopped {
            ScanProgress::Stopped
        } else {
            ScanProgress::Continue
        }
    }

    fn place_positional(&mut self, layout: LayoutState<'_>) -> Result<(), PatternScanError> {
        let mut placed = Vec::new();
        for (group_index, group) in self.groups.iter().enumerate() {
            for id in group.view.positional() {
                let record = group.view.signature(id)?;
                if !self.category_is_live(record.category) {
                    continue;
                }
                let program = group.view.program(record.first_program)?;
                for (first_start, last_start) in
                    placed_starts(record.placement, self.object_length, layout)
                {
                    placed.push(Candidate {
                        group: group_index,
                        anchor: first_start,
                        program: record.first_program,
                        first_start,
                        last_start,
                        ready_at: ready_at(&program, last_start),
                    });
                }
            }
        }
        placed.sort_by_key(|candidate| (candidate.first_start, candidate.group));
        self.positional = placed.into();
        Ok(())
    }

    fn category_is_live(&self, category: Category) -> bool {
        match category {
            Category::Malware => true,
            Category::PotentiallyUnwanted => self.settings.potentially_unwanted,
        }
    }

    fn advance(&mut self) -> Result<(), PatternScanError> {
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
            self.probe(pass_end)?;
            self.verify_ready()?;
        }
        if complete {
            while let Some(candidate) = self.positional.pop_front() {
                self.queue.push_back(candidate);
            }
        }
        self.verify_ready()?;
        self.release_unneeded();
        Ok(())
    }

    fn probe(&mut self, pass_end: u64) -> Result<(), PatternScanError> {
        let mut hits: Vec<(u64, usize, AnchoredProgram)> = Vec::new();
        for (group_index, group) in self.groups.iter().enumerate() {
            self.probe_group(group_index, &group.view, pass_end, &mut hits);
        }
        if self.groups.len() > 1 {
            hits.sort_by_key(|(position, group, _)| (*position, *group));
        }
        self.probed_to = pass_end;
        for (position, group_index, hit) in hits {
            self.admit_positional_up_to(position);
            let group = self
                .groups
                .get(group_index)
                .ok_or(GroupMalformed::UnknownProgram(hit.program))?;
            let program = group.view.program(hit.program)?;
            let Some(last_start) = position.checked_sub(u64::from(hit.displacement.nearest)) else {
                continue;
            };
            let first_start = position.saturating_sub(u64::from(hit.displacement.farthest));
            self.queue.push_back(Candidate {
                group: group_index,
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

    fn probe_group(
        &self,
        group_index: usize,
        group: &PatternGroup<'m>,
        pass_end: u64,
        hits: &mut Vec<(u64, usize, AnchoredProgram)>,
    ) {
        let long_filter = group.long_anchor_filter();
        let short_filter = group.short_anchor_filter();
        let probes_short = group.has_short_anchors();
        let everywhere: Vec<ProgramId> = group.everywhere().collect();
        let mut position = self.probed_to;
        while position < pass_end {
            if let Some(window) = self
                .window_at(position, LONG_ANCHOR_LENGTH)
                .and_then(|window| <[u8; LONG_ANCHOR_LENGTH]>::try_from(window).ok())
                && long_filter.may_hold(u32::from_le_bytes(window))
            {
                hits.extend(
                    group
                        .long_anchored(window)
                        .map(|hit| (position, group_index, hit)),
                );
            }
            if probes_short
                && let Some(window) = self
                    .window_at(position, SHORT_ANCHOR_LENGTH)
                    .and_then(|window| <[u8; SHORT_ANCHOR_LENGTH]>::try_from(window).ok())
                && short_filter.may_hold(u16::from_le_bytes(window))
            {
                hits.extend(
                    group
                        .short_anchored(window)
                        .map(|hit| (position, group_index, hit)),
                );
            }
            for program in &everywhere {
                hits.push((
                    position,
                    group_index,
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
        let Some(group) = self.groups.get(candidate.group) else {
            return Ok(());
        };
        let view = group.view;
        let program = view.program(candidate.program)?;
        let signature = program.header.signature.get();
        if group.detected.contains(&signature) {
            return Ok(());
        }
        let record = view.signature(PatternSignatureId(signature))?;
        if !self.category_is_live(record.category) {
            return Ok(());
        }
        let segment = program.header.segment.get();
        let starts = match segment.checked_sub(1) {
            None => PositionSet::between(candidate.first_start, candidate.last_start),
            Some(previous) => {
                let Some(previous_ends) = group
                    .chains
                    .get(&signature)
                    .and_then(|ends| ends.get(usize::try_from(previous).ok()?))
                else {
                    return Ok(());
                };
                let gap_least = u64::from(program.header.gap_before.get());
                let gap_most = program.gap_most().map(u64::from);
                PositionSet::of_ranges(previous_ends.iter().map(|end| {
                    let first = candidate.first_start.max(end.saturating_add(gap_least));
                    let last = gap_most.map_or(candidate.last_start, |most| {
                        candidate.last_start.min(end.saturating_add(most))
                    });
                    (first, last)
                }))
            }
        };
        let Some(first_start) = starts.first() else {
            return Ok(());
        };
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
        let ends = match_ends(&program, &bytes, &starts)
            .map_err(|_| GroupMalformed::Program(candidate.program))?;
        let Some(earliest_end) = ends.first() else {
            return Ok(());
        };
        if segment.saturating_add(1) < record.segment_count {
            let memory = view.part_memory();
            let Some(group) = self.groups.get_mut(candidate.group) else {
                return Ok(());
            };
            let ends = group.chains.entry(signature).or_default();
            let index = usize::try_from(segment).unwrap_or(usize::MAX);
            if index == ends.len() {
                ends.push(RememberedEnds::new(memory));
            }
            if let Some(remembered) = ends.get_mut(index) {
                remembered.remember(earliest_end);
            }
            return Ok(());
        }
        let order = ReportOrder {
            window: report_window(self.report_windows, earliest_end),
            group: candidate.group,
            rank: record.report_rank,
            position: candidate.anchor,
        };
        self.matched(candidate, signature, &record, order)
    }

    fn matched(
        &mut self,
        candidate: &Candidate,
        signature: u32,
        record: &PatternSignatureRecord,
        order: ReportOrder,
    ) -> Result<(), PatternScanError> {
        if let Some(group) = self.groups.get_mut(candidate.group) {
            group.detected.insert(signature);
            group.chains.remove(&signature);
        }
        match record.outcome {
            RecordedOutcome::Detection(name) => {
                let name = self.image.signature_name(name)?;
                if name.indicator == Indicator::Strong
                    && !self.settings.every_match
                    && self.stop_once_past.is_none()
                {
                    self.stop_once_past = Some(window_end(self.report_windows, order.window));
                }
                self.found.push(Found {
                    order,
                    detection: PatternDetection {
                        name: name.text,
                        indicator: name.indicator,
                    },
                });
            }
            RecordedOutcome::TypeFound(finding) => {
                if finding
                    .required
                    .is_none_or(|required| required == self.kind)
                {
                    self.types_found.push(TypeFound {
                        kind: finding.found,
                        offset: candidate.first_start,
                    });
                }
            }
        }
        Ok(())
    }

    fn release_unneeded(&mut self) {
        let oldest_needed = self
            .queue
            .front()
            .map_or(self.probed_to, |candidate| {
                candidate.first_start.min(self.probed_to)
            })
            .saturating_sub(u64::from(self.lookback));
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

enum LayoutNeed {
    NotExecutable,
    NeverResolved,
    Executable,
}

struct Selected<'m> {
    groups: Vec<PatternGroup<'m>>,
    layout: LayoutNeed,
}

fn selected_groups<'m>(
    image: &Image<'m>,
    selection: GroupSelection,
) -> Result<Selected<'m>, PatternScanError> {
    let kinds = image.object_kinds()?;
    let recognition_group = || -> Result<SignatureGroup, PatternScanError> {
        kinds
            .and_then(|kinds| kinds.typing_rules().recognition_group)
            .ok_or(PatternScanError::NoTypeRecognition)
    };
    let mut wanted: Vec<SignatureGroup> = Vec::new();
    let layout = match selection {
        GroupSelection::TypeRecognitionOnly(_) => {
            wanted.push(recognition_group()?);
            LayoutNeed::NeverResolved
        }
        GroupSelection::ForKind(kind) | GroupSelection::ForKindRecognisingTypes(kind) => {
            let description = kinds
                .map(|kinds| kinds.describe(kind))
                .transpose()
                .map_err(PatternScanError::Kinds)?
                .flatten()
                .ok_or(PatternScanError::KindNotDescribed(kind))?;
            wanted.extend(description.groups());
            if matches!(selection, GroupSelection::ForKindRecognisingTypes(_)) {
                wanted.push(recognition_group()?);
            }
            if description.executable {
                LayoutNeed::Executable
            } else {
                LayoutNeed::NotExecutable
            }
        }
    };
    let mut groups = Vec::with_capacity(wanted.len());
    for group in wanted {
        if let Some(view) = image.pattern_group(group)? {
            groups.push(view);
        }
    }
    Ok(Selected { groups, layout })
}

fn combined_report_windows(groups: &[SelectedGroup<'_>]) -> Option<ReportWindows> {
    groups
        .iter()
        .filter_map(|group| group.view.report_windows())
        .reduce(|combined, windows| ReportWindows {
            length: combined.length.max(windows.length),
            overlap: combined.overlap.max(windows.overlap),
        })
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
