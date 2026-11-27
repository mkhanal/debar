use std::collections::{BTreeMap, VecDeque};
use std::fmt;

use debar_image::{
    AnchorCase, AnchorTables, AnchoredProgram, ArmedAnchor, Category, Displacement, GroupMalformed,
    Image, ImageError, Indicator, KindsMalformed, LONG_ANCHOR_LENGTH, LogicalGroup,
    LogicalSignatureId, LongAnchorFilter, LongAnchorTable, MatchingPass, ObjectKind, PatternGroup,
    PatternSignatureId, PatternSignatureRecord, PlugInSubsignatures, ProgramHeader, ProgramId,
    ProgramMalformed, ProgramView, RecordedOutcome, ReportWindows, SHORT_ANCHOR_LENGTH,
    SelectionFilter, ShortAnchorFilter, SignatureGroup, ascii_lowercase,
};

use crate::executable_layout::{ExecutableLayout, LayoutState, placed_starts};
use crate::logical_state::{
    CountedMatches, LogicalFindings, LogicalState, ObjectContext, UnwantedCategories,
};
use crate::part_ends::RememberedEnds;
use crate::plug_in_matching::{PlugInRequest, match_plug_ins};
use crate::second_pass_search::{ArmedGroup, SecondPassSearch};
use crate::verification::{PositionSet, RetainedBytes, match_ends};

const POSITIONS_PER_PASS: u64 = 4096;
const CHUNK_LENGTH: usize = 128 * 1024;
const ARMED_FILTER_WORDS: usize = 1 << 10;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PatternSettings<'s> {
    pub potentially_unwanted: bool,
    pub unwanted_categories: UnwantedCategories<'s>,
    pub every_match: bool,
    pub largest_object_for_regular_expressions: Option<u64>,
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
pub struct PatternRequest<'r> {
    pub selection: GroupSelection,
    pub settings: PatternSettings<'r>,
    pub object_length: u64,
    pub context: ObjectContext<'r>,
    pub image_fuzzy_hash: Option<u64>,
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
    pub logical: LogicalFindings,
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
    SecondPassNotRun,
    WholeObjectNotGiven,
    ArmedSearchNotBuilt,
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
            Self::ArmedSearchNotBuilt => write!(
                formatter,
                "the search for the armed logical signatures could not be built"
            ),
            Self::WholeObjectNotGiven => write!(
                formatter,
                "the whole object must be given before its regular expressions and byte comparisons are matched"
            ),
            Self::SecondPassNotRun => write!(
                formatter,
                "the object must be matched a second time before its outcomes are known"
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

pub enum ScanEnd<'i, 'm, 'r> {
    Complete(PatternOutcomes),
    SecondPassNeeded(Box<PatternScan<'i, 'm, 'r>>),
    WholeObjectNeeded(Box<PatternScan<'i, 'm, 'r>>),
}

impl ScanEnd<'_, '_, '_> {
    pub fn into_outcomes(self) -> Result<PatternOutcomes, PatternScanError> {
        match self {
            Self::Complete(outcomes) => Ok(outcomes),
            Self::SecondPassNeeded(_) => Err(PatternScanError::SecondPassNotRun),
            Self::WholeObjectNeeded(_) => Err(PatternScanError::WholeObjectNotGiven),
        }
    }
}

pub fn scan_object(
    image: &Image<'_>,
    request: PatternRequest<'_>,
    executable_layout: impl FnOnce() -> Option<ExecutableLayout>,
    object: &[u8],
) -> Result<PatternOutcomes, PatternScanError> {
    let mut scan = PatternScan::new(image, request, executable_layout)?;
    loop {
        for chunk in object.chunks(CHUNK_LENGTH) {
            if scan.feed(chunk)? == ScanProgress::Stopped {
                break;
            }
        }
        if object.len() > scan.fed_length() {
            let rest =
                object
                    .get(scan.fed_length()..)
                    .ok_or(PatternScanError::MoreBytesThanDeclared {
                        declared: request.object_length,
                    })?;
            scan.skip(rest.len())?;
        }
        match scan.finish()? {
            ScanEnd::Complete(outcomes) => return Ok(outcomes),
            ScanEnd::SecondPassNeeded(second) => scan = *second,
            ScanEnd::WholeObjectNeeded(waiting) => {
                return waiting.match_whole_object(object)?.into_outcomes();
            }
        }
    }
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

#[derive(Debug, Clone)]
struct ArmedPart {
    group: usize,
    program: ProgramId,
    anchor: Option<[u8; SHORT_ANCHOR_LENGTH]>,
    case: AnchorCase,
    displacement: Displacement,
    first_start: u64,
    last_start: Option<u64>,
}

impl ArmedPart {
    fn anchored_by(&self, window: [u8; SHORT_ANCHOR_LENGTH]) -> bool {
        self.anchor.is_some_and(|anchor| match self.case {
            AnchorCase::Exact => window == anchor,
            AnchorCase::Folded => ascii_lowercase(window) == anchor,
        })
    }

    fn admits_anchor_at(&self, position: u64) -> bool {
        position
            >= self
                .first_start
                .saturating_add(u64::from(self.displacement.nearest))
            && self.last_start.is_none_or(|last| {
                position <= last.saturating_add(u64::from(self.displacement.farthest))
            })
    }
}

#[derive(Default)]
struct ArmedParts {
    parts: Vec<ArmedPart>,
    by_program: BTreeMap<(usize, u32), usize>,
    by_anchor: BTreeMap<[u8; SHORT_ANCHOR_LENGTH], Vec<usize>>,
    filter: Option<Box<ArmedFilter>>,
}

type ArmedFilter = [u64; ARMED_FILTER_WORDS];

impl ArmedParts {
    fn clear(&mut self) {
        self.parts.clear();
        self.by_program.clear();
        self.by_anchor.clear();
        self.filter = None;
    }

    fn may_hold(&self, window: u16) -> bool {
        self.filter
            .as_deref()
            .is_some_and(|filter| armed_filter_holds(filter, window))
    }

    fn hits(
        &self,
        window: [u8; SHORT_ANCHOR_LENGTH],
        lowered: [u8; SHORT_ANCHOR_LENGTH],
        position: u64,
        hits: &mut Vec<(u64, usize, AnchoredProgram)>,
    ) {
        for index in self.by_anchor.get(&lowered).into_iter().flatten() {
            if let Some(part) = self.parts.get(*index)
                && part.anchored_by(window)
                && part.admits_anchor_at(position)
            {
                hits.push((
                    position,
                    part.group,
                    AnchoredProgram {
                        program: part.program,
                        displacement: part.displacement,
                    },
                ));
            }
        }
    }

    fn arm(&mut self, part: ArmedPart) -> Arming {
        let key = (part.group, part.program.0);
        if let Some(existing) = self
            .by_program
            .get(&key)
            .and_then(|index| self.parts.get_mut(*index))
        {
            let admitted = existing.last_start.map(|last| {
                last.saturating_add(u64::from(existing.displacement.farthest))
                    .saturating_add(1)
            });
            existing.first_start = existing.first_start.min(part.first_start);
            existing.last_start = existing
                .last_start
                .zip(part.last_start)
                .map(|(a, b)| a.max(b));
            return Arming::AlreadyAdmittedBefore(admitted);
        }
        let index = self.parts.len();
        if let Some(anchor) = part.anchor.map(ascii_lowercase) {
            let filter = self
                .filter
                .get_or_insert_with(|| Box::new([0; ARMED_FILTER_WORDS]));
            for variant in case_variants(anchor) {
                let window = u16::from_le_bytes(variant);
                if let Some(word) = filter.get_mut(usize::from(window >> 6)) {
                    *word |= 1u64 << (window & 63);
                }
            }
            self.by_anchor.entry(anchor).or_default().push(index);
        }
        self.by_program.insert(key, index);
        self.parts.push(part);
        Arming::New
    }
}

fn case_variants(
    lowered: [u8; SHORT_ANCHOR_LENGTH],
) -> impl Iterator<Item = [u8; SHORT_ANCHOR_LENGTH]> {
    let [first, second] = lowered.map(|byte| [byte, byte.to_ascii_uppercase()]);
    first
        .into_iter()
        .flat_map(move |first| second.map(|second| [first, second]))
}

enum Arming {
    New,
    AlreadyAdmittedBefore(Option<u64>),
}

struct GroupProbe<'m> {
    group: usize,
    tables: AnchorTables<'m>,
    exact: LongAnchorTable<'m>,
    exact_filter: LongAnchorFilter<'m>,
    folded: Option<(LongAnchorTable<'m>, LongAnchorFilter<'m>)>,
    short: Option<ShortAnchorFilter<'m>>,
}

impl<'m> GroupProbe<'m> {
    fn of(group: usize, tables: AnchorTables<'m>) -> Self {
        let exact = tables.exact_long();
        let folded = tables.folded_long();
        Self {
            group,
            tables,
            exact,
            exact_filter: exact.filter(),
            folded: (!folded.is_empty()).then(|| (folded, folded.filter())),
            short: tables
                .has_short_anchors()
                .then(|| tables.short_anchor_filter()),
        }
    }
}

struct ProbedWindow<'b, 'm> {
    bytes: &'b [u8],
    positions: usize,
    first_position: u64,
    selection_filter: Option<SelectionFilter<'m>>,
}

impl ProbedWindow<'_, '_> {
    fn position(&self, offset: usize) -> u64 {
        self.first_position
            .saturating_add(u64::try_from(offset).unwrap_or(u64::MAX))
    }
}

fn probe_windows(
    window: &ProbedWindow<'_, '_>,
    probes: &[GroupProbe<'_>],
    armed: Option<&ArmedParts>,
    hits: &mut Vec<(u64, usize, AnchoredProgram)>,
) {
    let probe = PositionProbe {
        window,
        probes,
        armed,
        probes_long: !probes.is_empty(),
        probes_short: probes.iter().any(|probe| probe.short.is_some()),
        probes_folded: probes.iter().any(|probe| probe.folded.is_some()),
    };
    let tests = probe.tests();
    let long_positions = window
        .positions
        .min(window.bytes.len().saturating_sub(LONG_ANCHOR_LENGTH - 1));
    let mut offset = 0;
    while let Some(admitted) = tests.next_admitted(window.bytes, offset, long_positions) {
        if let Some(bytes) = window.bytes.get(admitted..) {
            probe.long_position(admitted, bytes, hits);
        }
        offset = admitted.saturating_add(1);
    }
    let short_positions = window
        .positions
        .min(window.bytes.len().saturating_sub(SHORT_ANCHOR_LENGTH - 1));
    for offset in long_positions..short_positions {
        if let Some(bytes) = window.bytes.get(offset..) {
            probe.short_position(offset, bytes, hits);
        }
    }
}

struct PositionProbe<'p, 'w, 'm> {
    window: &'p ProbedWindow<'w, 'm>,
    probes: &'p [GroupProbe<'m>],
    armed: Option<&'p ArmedParts>,
    probes_long: bool,
    probes_short: bool,
    probes_folded: bool,
}

impl<'p, 'm> PositionProbe<'p, '_, 'm> {
    fn tests(&self) -> PositionTests<'p, 'm> {
        let selection = self.window.selection_filter;
        let unfiltered = selection.is_none() && (self.probes_long || self.probes_short);
        PositionTests {
            long: selection.filter(|_| self.probes_long),
            short: selection.filter(|_| self.probes_short),
            armed: self.armed.and_then(|armed| armed.filter.as_deref()),
            every_position: unfiltered,
        }
    }

    fn long_position(
        &self,
        offset: usize,
        bytes: &[u8],
        hits: &mut Vec<(u64, usize, AnchoredProgram)>,
    ) {
        let Some(long) = bytes
            .first_chunk::<LONG_ANCHOR_LENGTH>()
            .copied()
            .map(u32::from_le_bytes)
        else {
            return;
        };
        let selection = self.window.selection_filter;
        if self.probes_long && selection.is_none_or(|filter| filter.may_hold_long(long)) {
            long_hits(
                self.window,
                self.probes,
                self.probes_folded,
                offset,
                long,
                hits,
            );
        }
        self.short_position(offset, bytes, hits);
    }

    fn short_position(
        &self,
        offset: usize,
        bytes: &[u8],
        hits: &mut Vec<(u64, usize, AnchoredProgram)>,
    ) {
        let Some(short) = bytes.first_chunk::<SHORT_ANCHOR_LENGTH>().copied() else {
            return;
        };
        let selection = self.window.selection_filter;
        if self.probes_short
            && selection.is_none_or(|filter| filter.may_hold_short(u16::from_le_bytes(short)))
        {
            short_hits(self.window, self.probes, offset, short, hits);
        }
        if let Some(armed) = self.armed
            && armed.may_hold(u16::from_le_bytes(short))
        {
            armed.hits(
                short,
                ascii_lowercase(short),
                self.window.position(offset),
                hits,
            );
        }
    }
}

#[derive(Clone, Copy)]
struct PositionTests<'f, 'm> {
    long: Option<SelectionFilter<'m>>,
    short: Option<SelectionFilter<'m>>,
    armed: Option<&'f ArmedFilter>,
    every_position: bool,
}

impl PositionTests<'_, '_> {
    fn next_admitted(&self, bytes: &[u8], from: usize, positions: usize) -> Option<usize> {
        if from >= positions {
            return None;
        }
        if self.every_position {
            return Some(from);
        }
        let windows = bytes
            .get(from..positions.saturating_add(LONG_ANCHOR_LENGTH - 1))?
            .windows(LONG_ANCHOR_LENGTH);
        for (index, window) in windows.enumerate() {
            let Some(long) = window
                .first_chunk::<LONG_ANCHOR_LENGTH>()
                .copied()
                .map(u32::from_le_bytes)
            else {
                continue;
            };
            if self.admits(long) {
                return Some(from.saturating_add(index));
            }
        }
        None
    }

    fn admits(&self, long: u32) -> bool {
        let [first, second, _, _] = long.to_le_bytes();
        let short = u16::from_le_bytes([first, second]);
        self.long.is_some_and(|filter| filter.may_hold_long(long))
            || self
                .short
                .is_some_and(|filter| filter.may_hold_short(short))
            || self
                .armed
                .is_some_and(|words| armed_filter_holds(words, short))
    }
}

fn armed_filter_holds(words: &ArmedFilter, window: u16) -> bool {
    words
        .get(usize::from(window >> 6))
        .is_some_and(|word| word & (1u64 << (window & 63)) != 0)
}

#[inline(never)]
fn long_hits(
    window: &ProbedWindow<'_, '_>,
    probes: &[GroupProbe<'_>],
    probes_folded: bool,
    offset: usize,
    long: u32,
    hits: &mut Vec<(u64, usize, AnchoredProgram)>,
) {
    let lowered = if probes_folded {
        ascii_lowercase_word(long)
    } else {
        long
    };
    let position = window.position(offset);
    for probe in probes {
        if probe.exact_filter.may_hold(long) {
            hits.extend(
                probe
                    .exact
                    .anchored(long.to_le_bytes())
                    .map(|hit| (position, probe.group, hit)),
            );
        }
        if let Some((folded, filter)) = &probe.folded
            && filter.may_hold(lowered)
        {
            hits.extend(
                folded
                    .anchored(lowered.to_le_bytes())
                    .map(|hit| (position, probe.group, hit)),
            );
        }
    }
}

#[inline(never)]
fn short_hits(
    window: &ProbedWindow<'_, '_>,
    probes: &[GroupProbe<'_>],
    offset: usize,
    short: [u8; SHORT_ANCHOR_LENGTH],
    hits: &mut Vec<(u64, usize, AnchoredProgram)>,
) {
    let value = u16::from_le_bytes(short);
    for probe in probes {
        if let Some(filter) = &probe.short
            && filter.may_hold(value)
        {
            let position = window.position(offset);
            hits.extend(
                probe
                    .tables
                    .short_anchored(short)
                    .map(|hit| (position, probe.group, hit)),
            );
        }
    }
}

fn probe_everywhere(
    window: &ProbedWindow<'_, '_>,
    probes: &[GroupProbe<'_>],
    hits: &mut Vec<(u64, usize, AnchoredProgram)>,
) {
    for probe in probes {
        let everywhere: Vec<ProgramId> = probe.tables.everywhere().collect();
        if everywhere.is_empty() {
            continue;
        }
        for offset in 0..window.positions {
            let position = window.position(offset);
            hits.extend(everywhere.iter().map(|program| {
                (
                    position,
                    probe.group,
                    AnchoredProgram {
                        program: *program,
                        displacement: Displacement {
                            nearest: 0,
                            farthest: 0,
                        },
                    },
                )
            }));
        }
    }
}

const ASCII_SEVEN_BITS: u32 = 0x7f7f_7f7f;
const PAST_CAPITAL_Z: u32 = 0x2525_2525;
const FROM_CAPITAL_A: u32 = 0x3f3f_3f3f;
const HIGH_BITS: u32 = 0x8080_8080;
const HIGH_BIT_TO_CASE_BIT: u32 = 2;

fn ascii_lowercase_word(word: u32) -> u32 {
    let seven_bits = word & ASCII_SEVEN_BITS;
    let at_least_a = seven_bits.wrapping_add(FROM_CAPITAL_A);
    let past_z = seven_bits.wrapping_add(PAST_CAPITAL_Z);
    let capitals = at_least_a & !past_z & !word & HIGH_BITS;
    word | (capitals >> HIGH_BIT_TO_CASE_BIT)
}

struct SignatureBits {
    words: Vec<u64>,
    signatures: usize,
}

impl SignatureBits {
    fn sized_for(signatures: usize) -> Self {
        Self {
            words: Vec::new(),
            signatures,
        }
    }

    fn contains(&self, signature: u32) -> bool {
        usize::try_from(signature / u64::BITS)
            .ok()
            .and_then(|word| self.words.get(word))
            .is_some_and(|word| word & (1u64 << (signature % u64::BITS)) != 0)
    }

    fn insert(&mut self, signature: u32) {
        if self.words.is_empty() {
            self.words.resize(self.signatures.div_ceil(64), 0);
        }
        if let Some(word) = usize::try_from(signature / u64::BITS)
            .ok()
            .and_then(|word| self.words.get_mut(word))
        {
            *word |= 1u64 << (signature % u64::BITS);
        }
    }

    fn bytes(&self) -> usize {
        self.words
            .capacity()
            .saturating_mul(std::mem::size_of::<u64>())
    }
}

struct SelectedGroup<'m> {
    id: SignatureGroup,
    plug_ins: Option<PlugInSubsignatures<'m>>,
    view: PatternGroup<'m>,
    tables: AnchorTables<'m>,
    logical: Option<LogicalState<'m>>,
    chains: BTreeMap<u32, Vec<RememberedEnds>>,
    detected: SignatureBits,
}

pub struct PatternScan<'i, 'm, 'r> {
    image: &'i Image<'m>,
    groups: Vec<SelectedGroup<'m>>,
    kind: ObjectKind,
    settings: PatternSettings<'r>,
    context: ObjectContext<'r>,
    object_length: u64,
    pass: MatchingPass,
    report_windows: Option<ReportWindows>,
    lookback: u32,
    executable_layout: Option<ExecutableLayout>,
    layout_need: LayoutNeed,
    retained: Vec<u8>,
    first_retained: u64,
    fed: u64,
    probed_to: u64,
    positional: VecDeque<Candidate>,
    queue: VecDeque<Candidate>,
    hits: Vec<(u64, usize, AnchoredProgram)>,
    armed: ArmedParts,
    second_pass_search: Option<SecondPassSearch>,
    selection_filter: Option<SelectionFilter<'m>>,
    found: Vec<Found>,
    types_found: Vec<TypeFound>,
    stop_once_past: Option<u64>,
    stopped: bool,
    image_fuzzy_hash: Option<u64>,
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

impl<'i, 'm, 'r> PatternScan<'i, 'm, 'r> {
    #[inline(never)]
    pub fn new(
        image: &'i Image<'m>,
        request: PatternRequest<'r>,
        executable_layout: impl FnOnce() -> Option<ExecutableLayout>,
    ) -> Result<Self, PatternScanError> {
        let selected = selected_groups(image, request.selection)?;
        let selected_ids: Vec<SignatureGroup> = selected
            .groups
            .iter()
            .map(|(group, _, _, _)| *group)
            .collect();
        let selection_filter = image.selection_filter(&selected_ids)?;
        let groups = selected
            .groups
            .into_iter()
            .map(|(group, view, logical, plug_ins)| SelectedGroup {
                id: group,
                plug_ins,
                view,
                tables: view.anchor_tables(MatchingPass::Main),
                logical: logical.map(|logical| LogicalState::new(logical, group)),
                chains: BTreeMap::new(),
                detected: SignatureBits::sized_for(view.signature_count()),
            })
            .collect::<Vec<_>>();
        let report_windows = combined_report_windows(&groups);
        let lookback = groups
            .iter()
            .map(|group| group.view.lookback())
            .max()
            .unwrap_or(0);
        let executable_layout = match selected.layout {
            LayoutNeed::Executable => executable_layout(),
            LayoutNeed::NotExecutable | LayoutNeed::NeverResolved => None,
        };
        let mut scan = Self {
            image,
            groups,
            kind: request.selection.kind(),
            settings: request.settings,
            context: request.context,
            object_length: request.object_length,
            pass: MatchingPass::Main,
            report_windows,
            lookback,
            executable_layout,
            layout_need: selected.layout,
            retained: Vec::new(),
            first_retained: 0,
            fed: 0,
            probed_to: 0,
            positional: VecDeque::new(),
            queue: VecDeque::new(),
            hits: Vec::new(),
            armed: ArmedParts::default(),
            second_pass_search: None,
            selection_filter,
            found: Vec::new(),
            types_found: Vec::new(),
            stop_once_past: None,
            stopped: false,
            image_fuzzy_hash: request.image_fuzzy_hash,
        };
        scan.place_positional()?;
        Ok(scan)
    }

    #[must_use]
    pub fn fed_length(&self) -> usize {
        usize::try_from(self.fed).unwrap_or(usize::MAX)
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
        if self.is_done() || self.groups.is_empty() {
            self.fed = fed;
            return Ok(self.progress());
        }
        self.retained.extend_from_slice(chunk);
        self.fed = fed;
        self.advance()?;
        Ok(self.progress())
    }

    pub fn skip(&mut self, length: usize) -> Result<(), PatternScanError> {
        if !self.is_done() && !self.groups.is_empty() {
            return Err(PatternScanError::FewerBytesThanDeclared {
                declared: self.object_length,
                fed: self.fed,
            });
        }
        self.fed = self
            .fed
            .checked_add(u64::try_from(length).unwrap_or(u64::MAX))
            .filter(|fed| *fed <= self.object_length)
            .ok_or(PatternScanError::MoreBytesThanDeclared {
                declared: self.object_length,
            })?;
        Ok(())
    }

    #[must_use]
    pub fn logical_state_bytes(&self) -> usize {
        self.groups
            .iter()
            .map(|group| {
                group
                    .logical
                    .as_ref()
                    .map_or(0, LogicalState::state_bytes)
                    .saturating_add(group.detected.bytes())
            })
            .fold(
                self.second_pass_search
                    .as_ref()
                    .map_or(0, SecondPassSearch::state_bytes),
                usize::saturating_add,
            )
    }

    pub fn finish(mut self) -> Result<ScanEnd<'i, 'm, 'r>, PatternScanError> {
        if self.fed != self.object_length {
            return Err(PatternScanError::FewerBytesThanDeclared {
                declared: self.object_length,
                fed: self.fed,
            });
        }
        if !self.is_done() && !self.groups.is_empty() {
            self.advance()?;
        }
        if self.pass == MatchingPass::Main && !self.stopped && self.needs_second_pass() {
            self.start_second_pass()?;
            return Ok(ScanEnd::SecondPassNeeded(Box::new(self)));
        }
        if !self.stopped && self.groups.iter().any(|group| group.plug_ins.is_some()) {
            return Ok(ScanEnd::WholeObjectNeeded(Box::new(self)));
        }
        Ok(ScanEnd::Complete(self.outcomes()?))
    }

    #[inline(never)]
    pub fn match_whole_object(
        mut self,
        object: &[u8],
    ) -> Result<ScanEnd<'i, 'm, 'r>, PatternScanError> {
        let length = u64::try_from(object.len()).unwrap_or(u64::MAX);
        if length != self.object_length {
            return Err(PatternScanError::FewerBytesThanDeclared {
                declared: self.object_length,
                fed: length,
            });
        }
        let request = PlugInRequest {
            object,
            windows: self.report_windows,
            image_fuzzy_hash: self.image_fuzzy_hash,
            largest_object_for_regular_expressions: self
                .settings
                .largest_object_for_regular_expressions,
            layout: match self.layout_need {
                LayoutNeed::Executable => match &self.executable_layout {
                    Some(layout) => LayoutState::Known(layout),
                    None => LayoutState::Missing,
                },
                LayoutNeed::NotExecutable | LayoutNeed::NeverResolved => LayoutState::NotExecutable,
            },
        };
        for group in &mut self.groups {
            if let (Some(plug_ins), Some(state)) = (&group.plug_ins, group.logical.as_mut()) {
                match_plug_ins(group.id, plug_ins, state, &request)?;
            }
        }
        Ok(ScanEnd::Complete(self.outcomes()?))
    }

    fn layout_state(&self) -> LayoutState<'_> {
        match self.layout_need {
            LayoutNeed::Executable => match &self.executable_layout {
                Some(layout) => LayoutState::Known(layout),
                None => LayoutState::Missing,
            },
            LayoutNeed::NotExecutable | LayoutNeed::NeverResolved => LayoutState::NotExecutable,
        }
    }

    fn needs_second_pass(&self) -> bool {
        self.groups.iter().any(|group| {
            group
                .logical
                .as_ref()
                .is_some_and(LogicalState::needs_second_pass)
        })
    }

    fn is_done(&self) -> bool {
        self.stopped
    }

    fn start_second_pass(&mut self) -> Result<(), PatternScanError> {
        self.pass = MatchingPass::Second;
        let armed: Vec<ArmedGroup<'_, '_>> = self
            .groups
            .iter()
            .enumerate()
            .filter_map(|(index, group)| {
                group.logical.as_ref().map(|state| ArmedGroup {
                    index,
                    patterns: &group.view,
                    logical: state.view(),
                    armed: state.armed_signatures(),
                })
            })
            .collect();
        self.second_pass_search = SecondPassSearch::for_armed(&armed)?;
        for group in &mut self.groups {
            group.tables = group.view.anchor_tables(MatchingPass::Second);
            group.chains.clear();
        }
        self.retained.clear();
        self.first_retained = 0;
        self.fed = 0;
        self.probed_to = 0;
        self.positional.clear();
        self.queue.clear();
        self.armed.clear();
        Ok(())
    }

    fn outcomes(mut self) -> Result<PatternOutcomes, PatternScanError> {
        self.found.sort_by_key(|found| found.order);
        let mut detections = Vec::with_capacity(self.found.len());
        let mut strong_found = false;
        for found in std::mem::take(&mut self.found) {
            let strong = found.detection.indicator == Indicator::Strong;
            detections.push(found.detection);
            if strong && !self.settings.every_match {
                strong_found = true;
                break;
            }
        }
        self.types_found.sort_by_key(|found| found.offset);
        let logical = if strong_found || self.stopped {
            LogicalFindings::default()
        } else {
            self.logical_findings()?
        };
        Ok(PatternOutcomes {
            detections,
            types_found: self.types_found,
            logical,
        })
    }

    #[inline(never)]
    fn logical_findings(&self) -> Result<LogicalFindings, PatternScanError> {
        let mut findings = LogicalFindings::default();
        let layout = self.layout_state();
        for group in &self.groups {
            let Some(logical) = &group.logical else {
                continue;
            };
            logical.evaluate(
                self.image,
                &self.settings,
                &self.context,
                self.object_length,
                layout,
                &mut findings,
            )?;
            if findings.ends_the_scan(self.settings.every_match) {
                break;
            }
        }
        Ok(findings)
    }

    fn progress(&self) -> ScanProgress {
        if self.is_done() {
            ScanProgress::Stopped
        } else {
            ScanProgress::Continue
        }
    }

    fn place_positional(&mut self) -> Result<(), PatternScanError> {
        let layout = match self.layout_need {
            LayoutNeed::NotExecutable => LayoutState::NotExecutable,
            LayoutNeed::NeverResolved => LayoutState::Missing,
            LayoutNeed::Executable => match &self.executable_layout {
                Some(layout) => LayoutState::Known(layout),
                None => LayoutState::Missing,
            },
        };
        let mut placed = Vec::new();
        let mut starts = Vec::new();
        for (group_index, group) in self.groups.iter().enumerate() {
            for id in group.view.positional() {
                let record = group.view.signature(id)?;
                if !self.category_is_live(record.category) {
                    continue;
                }
                placed_starts(record.placement, self.object_length, layout, &mut starts);
                if starts.is_empty() {
                    continue;
                }
                let program = group.view.program_header(record.first_program)?;
                for (first_start, last_start) in starts.iter().copied() {
                    placed.push(Candidate {
                        group: group_index,
                        anchor: first_start,
                        program: record.first_program,
                        first_start,
                        last_start,
                        ready_at: ready_at(program, last_start),
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
        while self.probed_to < probe_limit && !self.is_done() {
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
        let mut hits = std::mem::take(&mut self.hits);
        hits.clear();
        self.search_armed_signatures(pass_end, &mut hits);
        self.probe_positions(pass_end, &mut hits);
        hits.sort_by_key(|(position, group, _)| (*position, *group));
        self.probed_to = pass_end;
        for (position, group_index, hit) in hits.drain(..) {
            self.admit_positional_up_to(position);
            let group = self
                .groups
                .get(group_index)
                .ok_or(GroupMalformed::UnknownProgram(hit.program))?;
            let program = group.view.program_header(hit.program)?;
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
                ready_at: ready_at(program, last_start),
            });
        }
        self.hits = hits;
        self.admit_positional_up_to(pass_end.saturating_sub(1));
        self.expire_armed();
        Ok(())
    }

    fn expire_armed(&mut self) {
        let probed_to = self.probed_to;
        let expired = |part: &ArmedPart| {
            part.last_start.is_some_and(|last| {
                last.saturating_add(u64::from(part.displacement.farthest)) < probed_to
            })
        };
        let stale = self.armed.parts.iter().filter(|part| expired(part)).count();
        if stale.saturating_mul(2) <= self.armed.parts.len() {
            return;
        }
        let kept: Vec<ArmedPart> = self
            .armed
            .parts
            .drain(..)
            .filter(|part| !expired(part))
            .collect();
        self.armed.clear();
        for part in kept {
            self.armed.arm(part);
        }
    }

    fn arm_next_part(
        &mut self,
        group: usize,
        part_program: ProgramId,
        part_end: u64,
    ) -> Result<(), PatternScanError> {
        let Some(view) = self.groups.get(group).map(|group| group.view) else {
            return Ok(());
        };
        let next = ProgramId(part_program.0.saturating_add(1));
        let program = view.program(next)?;
        let Some(ArmedAnchor {
            bytes: anchor,
            case,
            displacement,
        }) = program.armed_anchor()
        else {
            return Ok(());
        };
        let first_start = part_end.saturating_add(u64::from(program.header.gap_before.get()));
        let last_start = program
            .gap_most()
            .map(|most| part_end.saturating_add(u64::from(most)))
            .or(match anchor {
                Some(_) => None,
                None => Some(self.object_length.saturating_sub(1)),
            });
        let part = ArmedPart {
            group,
            program: next,
            anchor,
            case,
            displacement,
            first_start,
            last_start,
        };
        let searched_from = if anchor.is_some() {
            match self.armed.arm(part.clone()) {
                Arming::New => 0,
                Arming::AlreadyAdmittedBefore(Some(position)) => position,
                Arming::AlreadyAdmittedBefore(None) => return Ok(()),
            }
        } else {
            0
        };
        if anchor.is_none() {
            let last = last_start.unwrap_or(first_start);
            self.insert_in_order(Candidate {
                group,
                anchor: first_start,
                program: next,
                first_start,
                last_start: last,
                ready_at: ready_at(program.header, last),
            });
        } else {
            {
                let from = first_start
                    .saturating_add(u64::from(displacement.nearest))
                    .max(searched_from)
                    .max(self.first_retained);
                let found = self.anchors_already_probed(&part, from);
                for position in found {
                    let Some(last) = position.checked_sub(u64::from(displacement.nearest)) else {
                        continue;
                    };
                    self.insert_in_order(Candidate {
                        group,
                        anchor: position,
                        program: next,
                        first_start: position.saturating_sub(u64::from(displacement.farthest)),
                        last_start: last,
                        ready_at: ready_at(program.header, last),
                    });
                }
            }
        }
        Ok(())
    }

    fn anchors_already_probed(&self, part: &ArmedPart, from: u64) -> Vec<u64> {
        let mut found = Vec::new();
        let first = usize::try_from(from.saturating_sub(self.first_retained)).unwrap_or(usize::MAX);
        let searched_to = part.last_start.map_or(self.probed_to, |last| {
            self.probed_to.min(
                last.saturating_add(u64::from(part.displacement.farthest))
                    .saturating_add(1),
            )
        });
        let last = usize::try_from(
            searched_to
                .saturating_sub(self.first_retained)
                .saturating_add(1),
        )
        .unwrap_or(usize::MAX)
        .min(self.retained.len());
        if let Some(searched) = self.retained.get(first..last) {
            for (offset, window) in searched.windows(SHORT_ANCHOR_LENGTH).enumerate() {
                let Ok(window) = <[u8; SHORT_ANCHOR_LENGTH]>::try_from(window) else {
                    continue;
                };
                let position = from.saturating_add(u64::try_from(offset).unwrap_or(0));
                if position < self.probed_to
                    && part.anchored_by(window)
                    && part.admits_anchor_at(position)
                {
                    found.push(position);
                }
            }
        }
        found
    }

    fn insert_in_order(&mut self, candidate: Candidate) {
        let at = self
            .queue
            .partition_point(|queued| queued.anchor <= candidate.anchor);
        self.queue.insert(at, candidate);
    }

    #[inline(never)]
    fn probe_positions(&self, pass_end: u64, hits: &mut Vec<(u64, usize, AnchoredProgram)>) {
        let Some(bytes) = self.unprobed_bytes(pass_end) else {
            return;
        };
        let positions = usize::try_from(pass_end.saturating_sub(self.probed_to)).unwrap_or(0);
        let probes: Vec<GroupProbe<'m>> = if self.second_pass_search.is_some() {
            Vec::new()
        } else {
            self.groups
                .iter()
                .enumerate()
                .filter(|(_, group)| !group.tables.is_empty())
                .map(|(index, group)| GroupProbe::of(index, group.tables))
                .collect()
        };
        let window = ProbedWindow {
            bytes,
            positions,
            first_position: self.probed_to,
            selection_filter: self
                .selection_filter
                .filter(|_| self.pass == MatchingPass::Main),
        };
        let armed = (!self.armed.by_anchor.is_empty()).then_some(&self.armed);
        if !probes.is_empty() || armed.is_some() {
            probe_windows(&window, &probes, armed, hits);
        }
        probe_everywhere(&window, &probes, hits);
    }

    fn search_armed_signatures(
        &self,
        pass_end: u64,
        hits: &mut Vec<(u64, usize, AnchoredProgram)>,
    ) {
        if let (Some(search), Some(bytes)) =
            (&self.second_pass_search, self.unprobed_bytes(pass_end))
        {
            let positions = usize::try_from(pass_end.saturating_sub(self.probed_to)).unwrap_or(0);
            search.search(bytes, self.probed_to, positions, hits);
        }
    }

    fn unprobed_bytes(&self, pass_end: u64) -> Option<&[u8]> {
        if pass_end <= self.probed_to {
            return None;
        }
        let start = usize::try_from(self.probed_to.checked_sub(self.first_retained)?).ok()?;
        let positions = usize::try_from(pass_end.saturating_sub(self.probed_to)).unwrap_or(0);
        let end = start
            .saturating_add(positions)
            .saturating_add(LONG_ANCHOR_LENGTH - 1)
            .min(self.retained.len());
        self.retained.get(start..end)
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

    #[inline(never)]
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
        if group.detected.contains(signature) {
            return Ok(());
        }
        let segment = program.header.segment.get();
        if segment > 0 && !group.chains.contains_key(&signature) {
            return Ok(());
        }
        let record = view.signature(PatternSignatureId(signature))?;
        if !self.category_is_live(record.category) {
            return Ok(());
        }
        if let RecordedOutcome::Subsignature { logical, .. } = record.outcome
            && self.pass == MatchingPass::Second
            && !group
                .logical
                .as_ref()
                .is_some_and(|state| state.is_armed(logical))
        {
            return Ok(());
        }
        let Some(starts) = candidate_starts(group, &program, candidate) else {
            return Ok(());
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
            return self.arm_next_part(candidate.group, candidate.program, earliest_end);
        }
        if let RecordedOutcome::Subsignature { logical, index } = record.outcome {
            let counts_each_start = record.segment_count == 1
                && self
                    .groups
                    .get(candidate.group)
                    .and_then(|group| group.logical.as_ref())
                    .map(|state| state.counts_each_match(logical, index))
                    .transpose()?
                    .unwrap_or(false);
            let matches = counted_matches(
                &program,
                &bytes,
                &starts,
                record.segment_count,
                counts_each_start,
            )
            .map_err(|_| GroupMalformed::Program(candidate.program))?;
            return self.count_subsignature(candidate.group, signature, logical, index, &matches);
        }
        let order = ReportOrder {
            window: report_window(self.report_windows, earliest_end),
            group: candidate.group,
            rank: record.report_rank,
            position: first_start,
        };
        self.matched(candidate, signature, &record, order)
    }

    fn count_subsignature(
        &mut self,
        group_index: usize,
        signature: u32,
        logical: LogicalSignatureId,
        index: u16,
        matches: &CountedMatches,
    ) -> Result<(), PatternScanError> {
        let pass = self.pass;
        let Some(group) = self.groups.get_mut(group_index) else {
            return Ok(());
        };
        let Some(state) = group.logical.as_mut() else {
            return Ok(());
        };
        if state.count(logical, index, matches, pass)?.saturated {
            group.detected.insert(signature);
            group.chains.remove(&signature);
        }
        Ok(())
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
                if record.category == Category::PotentiallyUnwanted
                    && !self.settings.unwanted_categories.admit(self.image, name)?
                {
                    return Ok(());
                }
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
            RecordedOutcome::Subsignature { .. } => {}
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LayoutNeed {
    NotExecutable,
    NeverResolved,
    Executable,
}

type SelectedViews<'m> = Vec<(
    SignatureGroup,
    PatternGroup<'m>,
    Option<LogicalGroup<'m>>,
    Option<PlugInSubsignatures<'m>>,
)>;

struct Selected<'m> {
    groups: SelectedViews<'m>,
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
            groups.push((
                group,
                view,
                image.logical_group(group)?,
                image.plug_in_subsignatures(group)?,
            ));
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

fn candidate_starts(
    group: &SelectedGroup<'_>,
    program: &ProgramView<'_>,
    candidate: &Candidate,
) -> Option<PositionSet> {
    let signature = program.header.signature.get();
    let Some(previous) = program.header.segment.get().checked_sub(1) else {
        return Some(PositionSet::between(
            candidate.first_start,
            candidate.last_start,
        ));
    };
    let previous_ends = group
        .chains
        .get(&signature)
        .and_then(|ends| ends.get(usize::try_from(previous).ok()?))?;
    let gap_least = u64::from(program.header.gap_before.get());
    let gap_most = program.gap_most().map(u64::from);
    Some(PositionSet::of_ranges(previous_ends.iter().map(|end| {
        let first = candidate.first_start.max(end.saturating_add(gap_least));
        let last = gap_most.map_or(candidate.last_start, |most| {
            candidate.last_start.min(end.saturating_add(most))
        });
        (first, last)
    })))
}

fn counted_matches(
    program: &ProgramView<'_>,
    bytes: &RetainedBytes<'_>,
    starts: &PositionSet,
    segment_count: u32,
    counts_each_start: bool,
) -> Result<CountedMatches, ProgramMalformed> {
    if segment_count > 1 {
        return Ok(CountedMatches::Completion);
    }
    if !counts_each_start {
        return Ok(CountedMatches::Once);
    }
    let mut matching = Vec::new();
    for start in starts.positions() {
        if !match_ends(program, bytes, &PositionSet::between(start, start))?.is_empty() {
            matching.push(start);
        }
    }
    Ok(CountedMatches::EachStart(matching))
}

fn ready_at(program: &ProgramHeader, last_start: u64) -> u64 {
    last_start
        .saturating_add(u64::from(program.longest.get()))
        .saturating_add(u64::from(program.after_reach.get()))
}
