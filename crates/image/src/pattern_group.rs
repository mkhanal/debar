use zerocopy::little_endian::{U16, U32};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::logical_group::{LogicalSignatureId, MatchingPass};
use crate::model::{Category, ExecutableAnchor, PartMemory, Placement, ReportWindows, TypeFinding};
use crate::names::NameId;
use crate::object_kind::ObjectKind;
use crate::pattern_program::{
    Anchor, AnchorCase, Displacement, LONG_ANCHOR_LENGTH, PatternNotCompiled, ProgramHeader,
    ProgramMalformed, ProgramPlace, ProgramView, SHORT_ANCHOR_LENGTH, Segment, encode,
};
use crate::selection_filters::GroupAnchors;

const FOUR_GRAM_SPREAD: u32 = 0x9e37_79b1;
const FILTER_SLOTS_PER_ANCHOR_LOG: u32 = 5;
const SMALLEST_FILTER_BITS: u32 = 10;
const LARGEST_FILTER_BITS: u32 = 30;
const SMALLEST_BUCKET_BITS: u32 = 4;
const SHORT_FILTER_BYTES: usize = 1 << 13;
const TABLE_PART_COUNT: usize = 9;
const PART_COUNT: usize = 2 * TABLE_PART_COUNT + 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TablePart {
    LongFilter,
    LongBuckets,
    LongAnchors,
    FoldedFilter,
    FoldedBuckets,
    FoldedAnchors,
    ShortFilter,
    ShortAnchors,
    Everywhere,
}

const TABLE_PARTS_IN_ORDER: [TablePart; TABLE_PART_COUNT] = [
    TablePart::LongFilter,
    TablePart::LongBuckets,
    TablePart::LongAnchors,
    TablePart::FoldedFilter,
    TablePart::FoldedBuckets,
    TablePart::FoldedAnchors,
    TablePart::ShortFilter,
    TablePart::ShortAnchors,
    TablePart::Everywhere,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Part {
    Table(MatchingPass, TablePart),
    Positional,
    Signatures,
    ProgramStarts,
    Programs,
}

impl Part {
    fn index(self) -> usize {
        let table_index = |table: TablePart| {
            TABLE_PARTS_IN_ORDER
                .iter()
                .position(|part| *part == table)
                .unwrap_or(0)
        };
        let tables_end = 2 * TABLE_PART_COUNT;
        match self {
            Self::Table(MatchingPass::Main, table) => table_index(table),
            Self::Table(MatchingPass::Second, table) => {
                TABLE_PART_COUNT.saturating_add(table_index(table))
            }
            Self::Positional => tables_end,
            Self::Signatures => tables_end.saturating_add(1),
            Self::ProgramStarts => tables_end.saturating_add(2),
            Self::Programs => tables_end.saturating_add(3),
        }
    }
}

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned, Clone, Copy)]
#[repr(C)]
struct PartExtent {
    offset: U32,
    length: U32,
}

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
struct GroupHeader {
    long_filter_bits: [U32; 4],
    long_bucket_bits: [U32; 4],
    lookback: U32,
    report_window: U32,
    report_overlap: U32,
    executable_placements: U32,
    latest_part_ends: U32,
    parts: [PartExtent; PART_COUNT],
}

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned, Clone, Copy)]
#[repr(C)]
struct LongAnchorEntry {
    anchor: [u8; LONG_ANCHOR_LENGTH],
    program: U32,
    nearest: U32,
    farthest: U32,
}

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned, Clone, Copy)]
#[repr(C)]
struct ShortAnchorEntry {
    anchor: [u8; SHORT_ANCHOR_LENGTH],
    program: U32,
    nearest: U32,
    farthest: U32,
}

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned, Clone, Copy)]
#[repr(C)]
struct SignatureEntry {
    outcome_value: U32,
    required_kind: U16,
    outcome: u8,
    category: u8,
    placement: u8,
    report_rank: u8,
    subsignature: U16,
    distance: U32,
    shift: U32,
    section: U32,
    first_program: U32,
    segment_count: U32,
}

const PLACEMENT_ANYWHERE: u8 = 1;
const PLACEMENT_FROM_START: u8 = 2;
const PLACEMENT_BEFORE_END: u8 = 3;
const PLACEMENT_AFTER_ENTRY_POINT: u8 = 4;
const PLACEMENT_BEFORE_ENTRY_POINT: u8 = 5;
const PLACEMENT_SECTION_START: u8 = 6;
const PLACEMENT_LAST_SECTION_START: u8 = 7;
const PLACEMENT_WHOLE_SECTION: u8 = 8;
const PLACEMENT_BEFORE_EXECUTABLE_END: u8 = 9;
const PLACEMENT_VERSION_INFORMATION: u8 = 10;
const PLACEMENT_WHOLE_SECTION_BUT_ITS_START_IN_LARGE_OBJECTS: u8 = 11;
const CATEGORY_MALWARE: u8 = 1;
const CATEGORY_POTENTIALLY_UNWANTED: u8 = 2;
const OUTCOME_DETECTION: u8 = 1;
const OUTCOME_TYPE_FOUND: u8 = 2;
const OUTCOME_SUBSIGNATURE: u8 = 3;
const ANY_REQUIRED_KIND: u16 = 0;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PatternSignatureId(pub u32);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProgramId(pub u32);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordedOutcome {
    Detection(NameId),
    TypeFound(TypeFinding),
    Subsignature {
        logical: LogicalSignatureId,
        index: u16,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PatternSignatureRecord {
    pub outcome: RecordedOutcome,
    pub category: Category,
    pub placement: Placement,
    pub report_rank: u8,
    pub first_program: ProgramId,
    pub segment_count: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AnchoredProgram {
    pub program: ProgramId,
    pub displacement: Displacement,
}

pub struct PendingPatternSignature {
    pub outcome: RecordedOutcome,
    pub category: Category,
    pub placement: Placement,
    pub report_rank: u8,
    pub pass: MatchingPass,
    pub segments: Vec<Segment>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GroupNotBuilt {
    TooLarge,
    Program(PatternNotCompiled),
}

pub struct BuiltGroup {
    pub bytes: Vec<u8>,
    pub signature_count: usize,
    pub main_anchors: GroupAnchors,
}

#[must_use]
pub fn four_gram_hash(window: u32, bits: u32) -> u32 {
    window
        .wrapping_mul(FOUR_GRAM_SPREAD)
        .checked_shr(u32::BITS.saturating_sub(bits))
        .unwrap_or(0)
}

#[derive(Default)]
struct PendingTables {
    long_anchors: Vec<LongAnchorEntry>,
    folded_anchors: Vec<LongAnchorEntry>,
    short_anchors: Vec<ShortAnchorEntry>,
    everywhere: Vec<U32>,
}

struct BuiltTables {
    filter_bits: [u32; 2],
    bucket_bits: [u32; 2],
    parts: [Vec<u8>; TABLE_PART_COUNT],
}

impl PendingTables {
    fn built(self) -> Result<BuiltTables, GroupNotBuilt> {
        let Self {
            long_anchors,
            folded_anchors,
            mut short_anchors,
            everywhere,
        } = self;
        let (long_filter_bits, long_bucket_bits) = long_geometry(&long_anchors);
        let (long_filter, long_buckets, long_anchors) =
            long_anchor_table(long_anchors, long_filter_bits, long_bucket_bits)?;
        let (folded_filter_bits, folded_bucket_bits) = long_geometry(&folded_anchors);
        let (folded_filter, folded_buckets, folded_anchors) =
            long_anchor_table(folded_anchors, folded_filter_bits, folded_bucket_bits)?;
        short_anchors.sort_by_key(|entry| (entry.anchor, entry.program.get()));
        let short_filter = short_anchor_filter(&short_anchors);
        Ok(BuiltTables {
            filter_bits: [long_filter_bits, folded_filter_bits],
            bucket_bits: [long_bucket_bits, folded_bucket_bits],
            parts: [
                long_filter,
                long_buckets.as_bytes().to_vec(),
                long_anchors.as_bytes().to_vec(),
                folded_filter,
                folded_buckets.as_bytes().to_vec(),
                folded_anchors.as_bytes().to_vec(),
                short_filter,
                short_anchors.as_bytes().to_vec(),
                everywhere.as_bytes().to_vec(),
            ],
        })
    }
}

fn case_variants(bytes: [u8; SHORT_ANCHOR_LENGTH]) -> Vec<[u8; SHORT_ANCHOR_LENGTH]> {
    let mut variants = vec![bytes];
    for index in 0..SHORT_ANCHOR_LENGTH {
        let mut more = Vec::new();
        for variant in &variants {
            if let Some(byte) = variant.get(index)
                && byte.is_ascii_alphabetic()
            {
                let mut flipped = *variant;
                if let Some(slot) = flipped.get_mut(index) {
                    *slot ^= 0x20;
                }
                more.push(flipped);
            }
        }
        variants.extend(more);
    }
    variants
}

#[derive(Default)]
struct PlacedPrograms {
    main: PendingTables,
    second: PendingTables,
    positional: Vec<U32>,
    entries: Vec<SignatureEntry>,
    program_starts: Vec<U32>,
    programs: Vec<u8>,
    lookback: u32,
    executable_placements: bool,
}

pub fn build(
    signatures: &[PendingPatternSignature],
    windows: Option<ReportWindows>,
    part_memory: PartMemory,
) -> Result<BuiltGroup, GroupNotBuilt> {
    let mut placed = PlacedPrograms::default();
    for (signature_index, signature) in signatures.iter().enumerate() {
        placed.add_signature(signature_index, signature)?;
    }
    let PlacedPrograms {
        main,
        second,
        positional,
        entries,
        mut program_starts,
        programs,
        lookback,
        executable_placements,
    } = placed;
    program_starts.push(U32::new(
        u32::try_from(programs.len()).map_err(|_| GroupNotBuilt::TooLarge)?,
    ));
    let main_anchors = GroupAnchors {
        exact: main.long_anchors.iter().map(|entry| entry.anchor).collect(),
        folded: main
            .folded_anchors
            .iter()
            .map(|entry| entry.anchor)
            .collect(),
        short: main
            .short_anchors
            .iter()
            .map(|entry| entry.anchor)
            .collect(),
    };
    let main = main.built()?;
    let second = second.built()?;
    let header = GroupHeader {
        long_filter_bits: [
            U32::new(main.filter_bits[0]),
            U32::new(main.filter_bits[1]),
            U32::new(second.filter_bits[0]),
            U32::new(second.filter_bits[1]),
        ],
        long_bucket_bits: [
            U32::new(main.bucket_bits[0]),
            U32::new(main.bucket_bits[1]),
            U32::new(second.bucket_bits[0]),
            U32::new(second.bucket_bits[1]),
        ],
        lookback: U32::new(lookback),
        report_window: U32::new(windows.map_or(0, |windows| windows.length)),
        report_overlap: U32::new(windows.map_or(0, |windows| windows.overlap)),
        executable_placements: U32::new(u32::from(executable_placements)),
        latest_part_ends: U32::new(match part_memory {
            PartMemory::EarliestEnd => 0,
            PartMemory::FirstAndLatestEnds { latest } => latest,
        }),
        parts: [PartExtent {
            offset: U32::new(0),
            length: U32::new(0),
        }; PART_COUNT],
    };
    let mut parts: Vec<Vec<u8>> = Vec::with_capacity(PART_COUNT);
    parts.extend(main.parts);
    parts.extend(second.parts);
    parts.extend([
        positional.as_bytes().to_vec(),
        entries.as_bytes().to_vec(),
        program_starts.as_bytes().to_vec(),
        programs,
    ]);
    let parts: [Vec<u8>; PART_COUNT] = parts.try_into().map_err(|_| GroupNotBuilt::TooLarge)?;
    Ok(BuiltGroup {
        bytes: assemble(header, parts)?,
        signature_count: signatures
            .iter()
            .filter(|signature| !matches!(signature.outcome, RecordedOutcome::Subsignature { .. }))
            .count(),
        main_anchors,
    })
}

fn assemble(
    mut header: GroupHeader,
    parts: [Vec<u8>; PART_COUNT],
) -> Result<Vec<u8>, GroupNotBuilt> {
    let mut offset = std::mem::size_of::<GroupHeader>();
    for (extent, part) in header.parts.iter_mut().zip(&parts) {
        extent.offset = U32::new(u32::try_from(offset).map_err(|_| GroupNotBuilt::TooLarge)?);
        extent.length = U32::new(u32::try_from(part.len()).map_err(|_| GroupNotBuilt::TooLarge)?);
        offset = offset
            .checked_add(part.len())
            .ok_or(GroupNotBuilt::TooLarge)?;
    }
    let mut bytes = header.as_bytes().to_vec();
    for part in parts {
        bytes.extend(part);
    }
    Ok(bytes)
}

impl PlacedPrograms {
    fn add_signature(
        &mut self,
        signature_index: usize,
        signature: &PendingPatternSignature,
    ) -> Result<(), GroupNotBuilt> {
        let too_large = |_| GroupNotBuilt::TooLarge;
        let signature_id = u32::try_from(signature_index).map_err(too_large)?;
        let first_program = u32::try_from(self.program_starts.len()).map_err(too_large)?;
        let segment_count = u32::try_from(signature.segments.len()).map_err(too_large)?;
        let fields = placement_fields(signature.placement);
        let placement = fields.code;
        if placement != PLACEMENT_ANYWHERE {
            self.positional.push(U32::new(signature_id));
        }
        if fields.in_executable {
            self.executable_placements = true;
        }
        let (outcome, outcome_value, required_kind, subsignature) =
            outcome_fields(signature.outcome);
        self.entries.push(SignatureEntry {
            outcome_value: U32::new(outcome_value),
            required_kind: U16::new(required_kind),
            outcome,
            category: category_code(signature.category),
            placement,
            report_rank: signature.report_rank,
            subsignature: U16::new(subsignature),
            distance: U32::new(fields.distance),
            shift: U32::new(fields.shift),
            section: U32::new(fields.section),
            first_program: U32::new(first_program),
            segment_count: U32::new(segment_count),
        });
        for (segment_index, segment) in signature.segments.iter().enumerate() {
            let place = ProgramPlace {
                signature: signature_id,
                segment: u32::try_from(segment_index).map_err(too_large)?,
                segment_count,
            };
            let placed_by_offset = place.segment == 0 && placement != PLACEMENT_ANYWHERE;
            self.add_program(segment, &place, placed_by_offset, signature.pass)?;
        }
        Ok(())
    }

    fn add_program(
        &mut self,
        segment: &Segment,
        place: &ProgramPlace,
        placed_by_offset: bool,
        pass: MatchingPass,
    ) -> Result<(), GroupNotBuilt> {
        let too_large = |_| GroupNotBuilt::TooLarge;
        let program = U32::new(u32::try_from(self.program_starts.len()).map_err(too_large)?);
        self.program_starts.push(U32::new(
            u32::try_from(self.programs.len()).map_err(too_large)?,
        ));
        self.programs
            .extend(encode(segment, place).map_err(GroupNotBuilt::Program)?);
        self.lookback = self.lookback.max(segment.context_reach_before());
        if segment.is_armed_by_predecessor(place.segment) {
            if let Anchor::Short { displacement, .. } = segment.anchor {
                self.lookback = self.lookback.max(reach_before(segment, displacement));
            }
            return Ok(());
        }
        if placed_by_offset {
            return Ok(());
        }
        let tables = match pass {
            MatchingPass::Main => &mut self.main,
            MatchingPass::Second => &mut self.second,
        };
        match segment.anchor {
            Anchor::Long {
                bytes,
                case,
                displacement,
            } => {
                self.lookback = self.lookback.max(reach_before(segment, displacement));
                let entry = LongAnchorEntry {
                    anchor: bytes,
                    program,
                    nearest: U32::new(displacement.nearest),
                    farthest: U32::new(displacement.farthest),
                };
                match case {
                    AnchorCase::Exact => tables.long_anchors.push(entry),
                    AnchorCase::Folded => tables.folded_anchors.push(entry),
                }
            }
            Anchor::Short {
                bytes,
                case,
                displacement,
            } => {
                self.lookback = self.lookback.max(reach_before(segment, displacement));
                let variants = match case {
                    AnchorCase::Exact => vec![bytes],
                    AnchorCase::Folded => case_variants(bytes),
                };
                for anchor in variants {
                    tables.short_anchors.push(ShortAnchorEntry {
                        anchor,
                        program,
                        nearest: U32::new(displacement.nearest),
                        farthest: U32::new(displacement.farthest),
                    });
                }
            }
            Anchor::Everywhere => tables.everywhere.push(program),
        }
        Ok(())
    }
}

fn reach_before(segment: &Segment, displacement: Displacement) -> u32 {
    displacement
        .farthest
        .saturating_add(segment.context_reach_before())
}

struct PlacementFields {
    code: u8,
    distance: u32,
    shift: u32,
    section: u32,
    in_executable: bool,
}

fn placement_fields(placement: Placement) -> PlacementFields {
    let plain = |code, distance, shift| PlacementFields {
        code,
        distance,
        shift,
        section: 0,
        in_executable: false,
    };
    match placement {
        Placement::Anywhere => plain(PLACEMENT_ANYWHERE, 0, 0),
        Placement::FromStart { distance, shift } => plain(PLACEMENT_FROM_START, distance, shift),
        Placement::BeforeEnd { distance, shift } => plain(PLACEMENT_BEFORE_END, distance, shift),
        Placement::InExecutable { anchor, shift } => {
            let (code, distance, section) = match anchor {
                ExecutableAnchor::AfterEntryPoint { distance } => {
                    (PLACEMENT_AFTER_ENTRY_POINT, distance, 0)
                }
                ExecutableAnchor::BeforeEntryPoint { distance } => {
                    (PLACEMENT_BEFORE_ENTRY_POINT, distance, 0)
                }
                ExecutableAnchor::SectionStart { section, distance } => {
                    (PLACEMENT_SECTION_START, distance, section)
                }
                ExecutableAnchor::LastSectionStart { distance } => {
                    (PLACEMENT_LAST_SECTION_START, distance, 0)
                }
                ExecutableAnchor::WholeSection {
                    section,
                    start_only_from_length: None,
                } => (PLACEMENT_WHOLE_SECTION, 0, section),
                ExecutableAnchor::WholeSection {
                    section,
                    start_only_from_length: Some(length),
                } => (
                    PLACEMENT_WHOLE_SECTION_BUT_ITS_START_IN_LARGE_OBJECTS,
                    length,
                    section,
                ),
                ExecutableAnchor::BeforeEnd { distance } => {
                    (PLACEMENT_BEFORE_EXECUTABLE_END, distance, 0)
                }
                ExecutableAnchor::VersionInformation => (PLACEMENT_VERSION_INFORMATION, 0, 0),
            };
            PlacementFields {
                code,
                distance,
                shift,
                section,
                in_executable: true,
            }
        }
    }
}

fn placement_of(code: u8, distance: u32, shift: u32, section: u32) -> Option<Placement> {
    let in_executable = |anchor| Some(Placement::InExecutable { anchor, shift });
    match code {
        PLACEMENT_ANYWHERE => Some(Placement::Anywhere),
        PLACEMENT_FROM_START => Some(Placement::FromStart { distance, shift }),
        PLACEMENT_BEFORE_END => Some(Placement::BeforeEnd { distance, shift }),
        PLACEMENT_AFTER_ENTRY_POINT => {
            in_executable(ExecutableAnchor::AfterEntryPoint { distance })
        }
        PLACEMENT_BEFORE_ENTRY_POINT => {
            in_executable(ExecutableAnchor::BeforeEntryPoint { distance })
        }
        PLACEMENT_SECTION_START => {
            in_executable(ExecutableAnchor::SectionStart { section, distance })
        }
        PLACEMENT_LAST_SECTION_START => {
            in_executable(ExecutableAnchor::LastSectionStart { distance })
        }
        PLACEMENT_WHOLE_SECTION => in_executable(ExecutableAnchor::WholeSection {
            section,
            start_only_from_length: None,
        }),
        PLACEMENT_WHOLE_SECTION_BUT_ITS_START_IN_LARGE_OBJECTS => {
            in_executable(ExecutableAnchor::WholeSection {
                section,
                start_only_from_length: Some(distance),
            })
        }
        PLACEMENT_BEFORE_EXECUTABLE_END => in_executable(ExecutableAnchor::BeforeEnd { distance }),
        PLACEMENT_VERSION_INFORMATION => in_executable(ExecutableAnchor::VersionInformation),
        _ => None,
    }
}

fn outcome_fields(outcome: RecordedOutcome) -> (u8, u32, u16, u16) {
    match outcome {
        RecordedOutcome::Detection(name) => (OUTCOME_DETECTION, name.0, ANY_REQUIRED_KIND, 0),
        RecordedOutcome::TypeFound(finding) => (
            OUTCOME_TYPE_FOUND,
            u32::from(finding.found.code()),
            finding.required.map_or(ANY_REQUIRED_KIND, ObjectKind::code),
            0,
        ),
        RecordedOutcome::Subsignature { logical, index } => {
            (OUTCOME_SUBSIGNATURE, logical.0, ANY_REQUIRED_KIND, index)
        }
    }
}

fn outcome_of(
    code: u8,
    value: u32,
    required_kind: u16,
    subsignature: u16,
) -> Option<RecordedOutcome> {
    match code {
        OUTCOME_DETECTION => Some(RecordedOutcome::Detection(NameId(value))),
        OUTCOME_SUBSIGNATURE => Some(RecordedOutcome::Subsignature {
            logical: LogicalSignatureId(value),
            index: subsignature,
        }),
        OUTCOME_TYPE_FOUND => {
            let found = ObjectKind::from_code(u16::try_from(value).ok()?)?;
            let required = if required_kind == ANY_REQUIRED_KIND {
                None
            } else {
                Some(ObjectKind::from_code(required_kind)?)
            };
            Some(RecordedOutcome::TypeFound(TypeFinding { found, required }))
        }
        _ => None,
    }
}

const fn category_code(category: Category) -> u8 {
    match category {
        Category::Malware => CATEGORY_MALWARE,
        Category::PotentiallyUnwanted => CATEGORY_POTENTIALLY_UNWANTED,
    }
}

fn ceiling_log2(value: usize) -> u32 {
    usize::BITS.saturating_sub(value.saturating_sub(1).leading_zeros())
}

fn long_geometry(anchors: &[LongAnchorEntry]) -> (u32, u32) {
    let mut distinct: Vec<[u8; LONG_ANCHOR_LENGTH]> =
        anchors.iter().map(|entry| entry.anchor).collect();
    distinct.sort_unstable();
    distinct.dedup();
    let filter_bits = ceiling_log2(distinct.len())
        .saturating_add(FILTER_SLOTS_PER_ANCHOR_LOG)
        .clamp(SMALLEST_FILTER_BITS, LARGEST_FILTER_BITS);
    let bucket_bits = ceiling_log2(distinct.len()).clamp(SMALLEST_BUCKET_BITS, filter_bits);
    (filter_bits, bucket_bits)
}

type LongTable = (Vec<u8>, Vec<U32>, Vec<LongAnchorEntry>);

fn long_anchor_table(
    mut anchors: Vec<LongAnchorEntry>,
    filter_bits: u32,
    bucket_bits: u32,
) -> Result<LongTable, GroupNotBuilt> {
    let filter_length = 1usize
        .checked_shl(filter_bits)
        .map(|bits| bits / 8)
        .ok_or(GroupNotBuilt::TooLarge)?;
    let mut filter = vec![0u8; filter_length];
    let bucket_shift = filter_bits.saturating_sub(bucket_bits);
    let hash_of =
        |entry: &LongAnchorEntry| four_gram_hash(u32::from_le_bytes(entry.anchor), filter_bits);
    anchors.sort_by_key(|entry| {
        (
            hash_of(entry) >> bucket_shift,
            entry.anchor,
            entry.program.get(),
        )
    });
    let bucket_count = 1usize
        .checked_shl(bucket_bits)
        .ok_or(GroupNotBuilt::TooLarge)?;
    let mut ends = vec![0u32; bucket_count.checked_add(1).ok_or(GroupNotBuilt::TooLarge)?];
    for entry in &anchors {
        let hash = hash_of(entry);
        if let Some(slot) = usize::try_from(hash >> 3)
            .ok()
            .and_then(|at| filter.get_mut(at))
        {
            *slot |= 1 << (hash & 7);
        }
        let after_bucket = usize::try_from(hash >> bucket_shift)
            .ok()
            .and_then(|bucket| bucket.checked_add(1))
            .and_then(|after| ends.get_mut(after))
            .ok_or(GroupNotBuilt::TooLarge)?;
        *after_bucket = after_bucket.checked_add(1).ok_or(GroupNotBuilt::TooLarge)?;
    }
    let mut running: u32 = 0;
    let buckets = ends
        .into_iter()
        .map(|count| {
            running = running.saturating_add(count);
            U32::new(running)
        })
        .collect();
    Ok((filter, buckets, anchors))
}

fn short_anchor_filter(anchors: &[ShortAnchorEntry]) -> Vec<u8> {
    let mut filter = vec![0u8; SHORT_FILTER_BYTES];
    for entry in anchors {
        let window = u16::from_le_bytes(entry.anchor);
        if let Some(slot) = filter.get_mut(usize::from(window >> 3)) {
            *slot |= 1 << (window & 7);
        }
    }
    filter
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroupMalformed {
    Layout,
    UnknownSignature(PatternSignatureId),
    UnknownProgram(ProgramId),
    Program(ProgramId),
}

#[derive(Clone, Copy)]
pub struct LongAnchorFilter<'m> {
    bits: &'m [u8],
    filter_bits: u32,
}

impl LongAnchorFilter<'_> {
    #[inline]
    #[must_use]
    pub fn may_hold(&self, window: u32) -> bool {
        let hash = four_gram_hash(window, self.filter_bits);
        usize::try_from(hash >> 3)
            .ok()
            .and_then(|at| self.bits.get(at))
            .is_some_and(|slot| slot & (1 << (hash & 7)) != 0)
    }
}

#[derive(Clone, Copy)]
pub struct ShortAnchorFilter<'m> {
    bits: &'m [u8],
}

impl ShortAnchorFilter<'_> {
    #[inline]
    #[must_use]
    pub fn may_hold(&self, window: u16) -> bool {
        self.bits
            .get(usize::from(window >> 3))
            .is_some_and(|slot| slot & (1 << (window & 7)) != 0)
    }
}

#[derive(Clone, Copy)]
pub struct LongAnchorTable<'m> {
    filter: LongAnchorFilter<'m>,
    bucket_shift: u32,
    buckets: &'m [U32],
    anchors: &'m [LongAnchorEntry],
}

impl<'m> LongAnchorTable<'m> {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.anchors.is_empty()
    }

    #[must_use]
    pub fn filter(&self) -> LongAnchorFilter<'m> {
        self.filter
    }

    pub fn anchored(
        &self,
        window: [u8; LONG_ANCHOR_LENGTH],
    ) -> impl Iterator<Item = AnchoredProgram> + 'm {
        let hash = four_gram_hash(u32::from_le_bytes(window), self.filter.filter_bits);
        let bucket = usize::try_from(hash >> self.bucket_shift).unwrap_or(usize::MAX);
        let start = self.buckets.get(bucket).map_or(0, |start| start.get());
        let end = bucket
            .checked_add(1)
            .and_then(|next| self.buckets.get(next))
            .map_or(0, |end| end.get());
        let range = usize::try_from(start).unwrap_or(0)..usize::try_from(end).unwrap_or(0);
        self.anchors
            .get(range)
            .unwrap_or_default()
            .iter()
            .filter(move |entry| entry.anchor == window)
            .map(|entry| AnchoredProgram {
                program: ProgramId(entry.program.get()),
                displacement: Displacement {
                    nearest: entry.nearest.get(),
                    farthest: entry.farthest.get(),
                },
            })
    }
}

#[derive(Clone, Copy)]
pub struct AnchorTables<'m> {
    exact: LongAnchorTable<'m>,
    folded: LongAnchorTable<'m>,
    short_filter: ShortAnchorFilter<'m>,
    short_anchors: &'m [ShortAnchorEntry],
    everywhere: &'m [U32],
}

impl<'m> AnchorTables<'m> {
    fn read(
        header: &GroupHeader,
        pass: MatchingPass,
        part: &dyn Fn(Part) -> Result<&'m [u8], GroupMalformed>,
    ) -> Result<Self, GroupMalformed> {
        fn layout<E>(_: E) -> GroupMalformed {
            GroupMalformed::Layout
        }
        let table = |table: TablePart| part(Part::Table(pass, table));
        let first_slot = match pass {
            MatchingPass::Main => 0,
            MatchingPass::Second => 2,
        };
        let long_table = |slot: usize,
                          filter: TablePart,
                          buckets: TablePart,
                          anchors: TablePart|
         -> Result<LongAnchorTable<'m>, GroupMalformed> {
            let filter_bits = header
                .long_filter_bits
                .get(slot)
                .ok_or(GroupMalformed::Layout)?
                .get();
            let bucket_bits = header
                .long_bucket_bits
                .get(slot)
                .ok_or(GroupMalformed::Layout)?
                .get();
            if filter_bits > LARGEST_FILTER_BITS || bucket_bits > filter_bits {
                return Err(GroupMalformed::Layout);
            }
            let bits = table(filter)?;
            if Some(bits.len()) != 1usize.checked_shl(filter_bits).map(|bits| bits / 8) {
                return Err(GroupMalformed::Layout);
            }
            Ok(LongAnchorTable {
                filter: LongAnchorFilter { bits, filter_bits },
                bucket_shift: filter_bits.saturating_sub(bucket_bits),
                buckets: <[U32]>::ref_from_bytes(table(buckets)?).map_err(layout)?,
                anchors: <[LongAnchorEntry]>::ref_from_bytes(table(anchors)?).map_err(layout)?,
            })
        };
        let short_filter = table(TablePart::ShortFilter)?;
        if short_filter.len() != SHORT_FILTER_BYTES {
            return Err(GroupMalformed::Layout);
        }
        Ok(Self {
            exact: long_table(
                first_slot,
                TablePart::LongFilter,
                TablePart::LongBuckets,
                TablePart::LongAnchors,
            )?,
            folded: long_table(
                first_slot.saturating_add(1),
                TablePart::FoldedFilter,
                TablePart::FoldedBuckets,
                TablePart::FoldedAnchors,
            )?,
            short_filter: ShortAnchorFilter { bits: short_filter },
            short_anchors: <[ShortAnchorEntry]>::ref_from_bytes(table(TablePart::ShortAnchors)?)
                .map_err(layout)?,
            everywhere: <[U32]>::ref_from_bytes(table(TablePart::Everywhere)?).map_err(layout)?,
        })
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.exact.is_empty()
            && self.folded.is_empty()
            && self.short_anchors.is_empty()
            && self.everywhere.is_empty()
    }

    #[must_use]
    pub fn exact_long(&self) -> LongAnchorTable<'m> {
        self.exact
    }

    #[must_use]
    pub fn folded_long(&self) -> LongAnchorTable<'m> {
        self.folded
    }

    #[must_use]
    pub fn short_anchor_filter(&self) -> ShortAnchorFilter<'m> {
        self.short_filter
    }

    #[must_use]
    pub fn has_short_anchors(&self) -> bool {
        !self.short_anchors.is_empty()
    }

    pub fn short_anchored(
        &self,
        window: [u8; SHORT_ANCHOR_LENGTH],
    ) -> impl Iterator<Item = AnchoredProgram> + 'm {
        let first = self
            .short_anchors
            .partition_point(|entry| entry.anchor < window);
        self.short_anchors
            .get(first..)
            .unwrap_or_default()
            .iter()
            .take_while(move |entry| entry.anchor == window)
            .map(|entry| AnchoredProgram {
                program: ProgramId(entry.program.get()),
                displacement: Displacement {
                    nearest: entry.nearest.get(),
                    farthest: entry.farthest.get(),
                },
            })
    }

    pub fn everywhere(&self) -> impl Iterator<Item = ProgramId> + 'm {
        self.everywhere
            .iter()
            .map(|program| ProgramId(program.get()))
    }
}

#[derive(Clone, Copy)]
pub struct PatternGroup<'m> {
    lookback: u32,
    executable_placements: bool,
    part_memory: PartMemory,
    report_windows: Option<ReportWindows>,
    main: AnchorTables<'m>,
    second: AnchorTables<'m>,
    positional: &'m [U32],
    signatures: &'m [SignatureEntry],
    program_starts: &'m [U32],
    programs: &'m [u8],
}

impl<'m> PatternGroup<'m> {
    pub fn read(bytes: &'m [u8]) -> Result<Self, GroupMalformed> {
        let (header, _) =
            GroupHeader::ref_from_prefix(bytes).map_err(|_| GroupMalformed::Layout)?;
        let part = |part: Part| -> Result<&'m [u8], GroupMalformed> {
            let extent = header
                .parts
                .get(part.index())
                .ok_or(GroupMalformed::Layout)?;
            let start = usize::try_from(extent.offset.get()).map_err(|_| GroupMalformed::Layout)?;
            let length =
                usize::try_from(extent.length.get()).map_err(|_| GroupMalformed::Layout)?;
            bytes
                .get(start..start.checked_add(length).ok_or(GroupMalformed::Layout)?)
                .ok_or(GroupMalformed::Layout)
        };
        let records = |part_bytes: &'m [u8]| -> Result<&'m [U32], GroupMalformed> {
            <[U32]>::ref_from_bytes(part_bytes).map_err(|_| GroupMalformed::Layout)
        };
        let report_windows =
            (header.report_window.get() > header.report_overlap.get()).then(|| ReportWindows {
                length: header.report_window.get(),
                overlap: header.report_overlap.get(),
            });
        Ok(Self {
            lookback: header.lookback.get(),
            executable_placements: header.executable_placements.get() != 0,
            part_memory: match header.latest_part_ends.get() {
                0 => PartMemory::EarliestEnd,
                latest => PartMemory::FirstAndLatestEnds { latest },
            },
            report_windows,
            main: AnchorTables::read(header, MatchingPass::Main, &part)?,
            second: AnchorTables::read(header, MatchingPass::Second, &part)?,
            positional: records(part(Part::Positional)?)?,
            signatures: <[SignatureEntry]>::ref_from_bytes(part(Part::Signatures)?)
                .map_err(|_| GroupMalformed::Layout)?,
            program_starts: records(part(Part::ProgramStarts)?)?,
            programs: part(Part::Programs)?,
        })
    }

    #[must_use]
    pub fn lookback(&self) -> u32 {
        self.lookback
    }

    #[must_use]
    pub fn part_memory(&self) -> PartMemory {
        self.part_memory
    }

    #[must_use]
    pub fn has_executable_placements(&self) -> bool {
        self.executable_placements
    }

    #[must_use]
    pub fn report_windows(&self) -> Option<ReportWindows> {
        self.report_windows
    }

    #[must_use]
    pub fn anchor_tables(&self, pass: MatchingPass) -> AnchorTables<'m> {
        match pass {
            MatchingPass::Main => self.main,
            MatchingPass::Second => self.second,
        }
    }

    pub fn positional(&self) -> impl Iterator<Item = PatternSignatureId> + 'm {
        self.positional
            .iter()
            .map(|signature| PatternSignatureId(signature.get()))
    }

    #[must_use]
    pub fn signature_count(&self) -> usize {
        self.signatures.len()
    }

    pub fn signature(
        &self,
        id: PatternSignatureId,
    ) -> Result<PatternSignatureRecord, GroupMalformed> {
        let entry = usize::try_from(id.0)
            .ok()
            .and_then(|index| self.signatures.get(index))
            .ok_or(GroupMalformed::UnknownSignature(id))?;
        let malformed = GroupMalformed::UnknownSignature(id);
        let category = match entry.category {
            CATEGORY_MALWARE => Category::Malware,
            CATEGORY_POTENTIALLY_UNWANTED => Category::PotentiallyUnwanted,
            _ => return Err(malformed),
        };
        let placement = placement_of(
            entry.placement,
            entry.distance.get(),
            entry.shift.get(),
            entry.section.get(),
        )
        .ok_or(malformed)?;
        let outcome = outcome_of(
            entry.outcome,
            entry.outcome_value.get(),
            entry.required_kind.get(),
            entry.subsignature.get(),
        )
        .ok_or(malformed)?;
        Ok(PatternSignatureRecord {
            outcome,
            category,
            placement,
            report_rank: entry.report_rank,
            first_program: ProgramId(entry.first_program.get()),
            segment_count: entry.segment_count.get(),
        })
    }

    pub fn program_header(&self, id: ProgramId) -> Result<&'m ProgramHeader, GroupMalformed> {
        let index = usize::try_from(id.0).map_err(|_| GroupMalformed::UnknownProgram(id))?;
        let start = self
            .program_starts
            .get(index)
            .ok_or(GroupMalformed::UnknownProgram(id))?
            .get();
        let bytes = usize::try_from(start)
            .ok()
            .and_then(|start| self.programs.get(start..))
            .ok_or(GroupMalformed::Program(id))?;
        ProgramHeader::ref_from_prefix(bytes)
            .map(|(header, _)| header)
            .map_err(|_| GroupMalformed::Program(id))
    }

    pub fn program(&self, id: ProgramId) -> Result<ProgramView<'m>, GroupMalformed> {
        let index = usize::try_from(id.0).map_err(|_| GroupMalformed::UnknownProgram(id))?;
        let start = self
            .program_starts
            .get(index)
            .ok_or(GroupMalformed::UnknownProgram(id))?
            .get();
        let end = index
            .checked_add(1)
            .and_then(|next| self.program_starts.get(next))
            .ok_or(GroupMalformed::UnknownProgram(id))?
            .get();
        let bytes = usize::try_from(start)
            .ok()
            .zip(usize::try_from(end).ok())
            .and_then(|(start, end)| self.programs.get(start..end))
            .ok_or(GroupMalformed::Program(id))?;
        ProgramView::read(bytes).map_err(|ProgramMalformed| GroupMalformed::Program(id))
    }
}
