use zerocopy::little_endian::U32;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::model::{Category, Placement, ReportWindows};
use crate::names::NameId;
use crate::pattern_program::{
    Anchor, Displacement, LONG_ANCHOR_LENGTH, PatternNotCompiled, ProgramMalformed, ProgramPlace,
    ProgramView, SHORT_ANCHOR_LENGTH, Segment, encode,
};

const FOUR_GRAM_SPREAD: u32 = 0x9e37_79b1;
const FILTER_SLOTS_PER_ANCHOR_LOG: u32 = 5;
const SMALLEST_FILTER_BITS: u32 = 10;
const LARGEST_FILTER_BITS: u32 = 30;
const SMALLEST_BUCKET_BITS: u32 = 4;
const SHORT_FILTER_BYTES: usize = 1 << 13;
const PART_COUNT: usize = 10;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Part {
    LongFilter,
    LongBuckets,
    LongAnchors,
    ShortFilter,
    ShortAnchors,
    Everywhere,
    Positional,
    Signatures,
    ProgramStarts,
    Programs,
}

const PARTS_IN_ORDER: [Part; PART_COUNT] = [
    Part::LongFilter,
    Part::LongBuckets,
    Part::LongAnchors,
    Part::ShortFilter,
    Part::ShortAnchors,
    Part::Everywhere,
    Part::Positional,
    Part::Signatures,
    Part::ProgramStarts,
    Part::Programs,
];

impl Part {
    fn index(self) -> usize {
        PARTS_IN_ORDER
            .iter()
            .position(|part| *part == self)
            .unwrap_or(0)
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
    long_filter_bits: U32,
    long_bucket_bits: U32,
    lookback: U32,
    report_window: U32,
    report_overlap: U32,
    reserved: U32,
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
    name: U32,
    category: u8,
    placement: u8,
    report_rank: u8,
    reserved: u8,
    distance: U32,
    shift: U32,
    first_program: U32,
    segment_count: U32,
}

const PLACEMENT_ANYWHERE: u8 = 1;
const PLACEMENT_FROM_START: u8 = 2;
const PLACEMENT_BEFORE_END: u8 = 3;
const CATEGORY_MALWARE: u8 = 1;
const CATEGORY_POTENTIALLY_UNWANTED: u8 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PatternSignatureId(pub u32);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProgramId(pub u32);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PatternSignatureRecord {
    pub name: NameId,
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
    pub name: NameId,
    pub category: Category,
    pub placement: Placement,
    pub report_rank: u8,
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
}

#[must_use]
pub fn four_gram_hash(window: u32, bits: u32) -> u32 {
    window
        .wrapping_mul(FOUR_GRAM_SPREAD)
        .checked_shr(u32::BITS.saturating_sub(bits))
        .unwrap_or(0)
}

#[derive(Default)]
struct PlacedPrograms {
    long_anchors: Vec<LongAnchorEntry>,
    short_anchors: Vec<ShortAnchorEntry>,
    everywhere: Vec<U32>,
    positional: Vec<U32>,
    entries: Vec<SignatureEntry>,
    program_starts: Vec<U32>,
    programs: Vec<u8>,
    lookback: u32,
}

pub fn build(
    signatures: &[PendingPatternSignature],
    windows: Option<ReportWindows>,
) -> Result<BuiltGroup, GroupNotBuilt> {
    let mut placed = PlacedPrograms::default();
    for (signature_index, signature) in signatures.iter().enumerate() {
        placed.add_signature(signature_index, signature)?;
    }
    let PlacedPrograms {
        long_anchors,
        mut short_anchors,
        everywhere,
        positional,
        entries,
        mut program_starts,
        programs,
        lookback,
    } = placed;
    program_starts.push(U32::new(
        u32::try_from(programs.len()).map_err(|_| GroupNotBuilt::TooLarge)?,
    ));
    let (long_filter_bits, long_bucket_bits) = long_geometry(&long_anchors);
    let (long_filter, long_buckets, long_anchors) =
        long_anchor_table(long_anchors, long_filter_bits, long_bucket_bits)?;
    short_anchors.sort_by_key(|entry| (entry.anchor, entry.program.get()));
    let short_filter = short_anchor_filter(&short_anchors);
    let header = GroupHeader {
        long_filter_bits: U32::new(long_filter_bits),
        long_bucket_bits: U32::new(long_bucket_bits),
        lookback: U32::new(lookback),
        report_window: U32::new(windows.map_or(0, |windows| windows.length)),
        report_overlap: U32::new(windows.map_or(0, |windows| windows.overlap)),
        reserved: U32::new(0),
        parts: [PartExtent {
            offset: U32::new(0),
            length: U32::new(0),
        }; PART_COUNT],
    };
    let parts: [Vec<u8>; PART_COUNT] = [
        long_filter,
        long_buckets.as_bytes().to_vec(),
        long_anchors.as_bytes().to_vec(),
        short_filter,
        short_anchors.as_bytes().to_vec(),
        everywhere.as_bytes().to_vec(),
        positional.as_bytes().to_vec(),
        entries.as_bytes().to_vec(),
        program_starts.as_bytes().to_vec(),
        programs,
    ];
    Ok(BuiltGroup {
        bytes: assemble(header, parts)?,
        signature_count: signatures.len(),
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
        let (placement, distance, shift) = placement_fields(signature.placement);
        if placement != PLACEMENT_ANYWHERE {
            self.positional.push(U32::new(signature_id));
        }
        self.entries.push(SignatureEntry {
            name: U32::new(signature.name.0),
            category: category_code(signature.category),
            placement,
            report_rank: signature.report_rank,
            reserved: 0,
            distance: U32::new(distance),
            shift: U32::new(shift),
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
            self.add_program(segment, &place, placed_by_offset)?;
        }
        Ok(())
    }

    fn add_program(
        &mut self,
        segment: &Segment,
        place: &ProgramPlace,
        placed_by_offset: bool,
    ) -> Result<(), GroupNotBuilt> {
        let too_large = |_| GroupNotBuilt::TooLarge;
        let program = U32::new(u32::try_from(self.program_starts.len()).map_err(too_large)?);
        self.program_starts.push(U32::new(
            u32::try_from(self.programs.len()).map_err(too_large)?,
        ));
        self.programs
            .extend(encode(segment, place).map_err(GroupNotBuilt::Program)?);
        self.lookback = self.lookback.max(segment.context_reach_before());
        if placed_by_offset {
            return Ok(());
        }
        match segment.anchor {
            Anchor::Long {
                bytes,
                displacement,
            } => {
                self.lookback = self.lookback.max(reach_before(segment, displacement));
                self.long_anchors.push(LongAnchorEntry {
                    anchor: bytes,
                    program,
                    nearest: U32::new(displacement.nearest),
                    farthest: U32::new(displacement.farthest),
                });
            }
            Anchor::Short {
                bytes,
                displacement,
            } => {
                self.lookback = self.lookback.max(reach_before(segment, displacement));
                self.short_anchors.push(ShortAnchorEntry {
                    anchor: bytes,
                    program,
                    nearest: U32::new(displacement.nearest),
                    farthest: U32::new(displacement.farthest),
                });
            }
            Anchor::Everywhere => self.everywhere.push(program),
        }
        Ok(())
    }
}

fn reach_before(segment: &Segment, displacement: Displacement) -> u32 {
    displacement
        .farthest
        .saturating_add(segment.context_reach_before())
}

fn placement_fields(placement: Placement) -> (u8, u32, u32) {
    match placement {
        Placement::Anywhere => (PLACEMENT_ANYWHERE, 0, 0),
        Placement::FromStart { distance, shift } => (PLACEMENT_FROM_START, distance, shift),
        Placement::BeforeEnd { distance, shift } => (PLACEMENT_BEFORE_END, distance, shift),
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
pub struct PatternGroup<'m> {
    lookback: u32,
    report_windows: Option<ReportWindows>,
    long_filter: LongAnchorFilter<'m>,
    bucket_shift: u32,
    long_buckets: &'m [U32],
    long_anchors: &'m [LongAnchorEntry],
    short_filter: ShortAnchorFilter<'m>,
    short_anchors: &'m [ShortAnchorEntry],
    everywhere: &'m [U32],
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
        let filter_bits = header.long_filter_bits.get();
        let bucket_bits = header.long_bucket_bits.get();
        if filter_bits > LARGEST_FILTER_BITS || bucket_bits > filter_bits {
            return Err(GroupMalformed::Layout);
        }
        let long_filter = part(Part::LongFilter)?;
        if Some(long_filter.len()) != 1usize.checked_shl(filter_bits).map(|bits| bits / 8) {
            return Err(GroupMalformed::Layout);
        }
        let short_filter = part(Part::ShortFilter)?;
        if short_filter.len() != SHORT_FILTER_BYTES {
            return Err(GroupMalformed::Layout);
        }
        let report_windows =
            (header.report_window.get() > header.report_overlap.get()).then(|| ReportWindows {
                length: header.report_window.get(),
                overlap: header.report_overlap.get(),
            });
        Ok(Self {
            lookback: header.lookback.get(),
            report_windows,
            long_filter: LongAnchorFilter {
                bits: long_filter,
                filter_bits,
            },
            bucket_shift: filter_bits.saturating_sub(bucket_bits),
            long_buckets: records(part(Part::LongBuckets)?)?,
            long_anchors: <[LongAnchorEntry]>::ref_from_bytes(part(Part::LongAnchors)?)
                .map_err(|_| GroupMalformed::Layout)?,
            short_filter: ShortAnchorFilter { bits: short_filter },
            short_anchors: <[ShortAnchorEntry]>::ref_from_bytes(part(Part::ShortAnchors)?)
                .map_err(|_| GroupMalformed::Layout)?,
            everywhere: records(part(Part::Everywhere)?)?,
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
    pub fn report_windows(&self) -> Option<ReportWindows> {
        self.report_windows
    }

    #[must_use]
    pub fn long_anchor_filter(&self) -> LongAnchorFilter<'m> {
        self.long_filter
    }

    #[must_use]
    pub fn short_anchor_filter(&self) -> ShortAnchorFilter<'m> {
        self.short_filter
    }

    #[must_use]
    pub fn has_short_anchors(&self) -> bool {
        !self.short_anchors.is_empty()
    }

    pub fn long_anchored(
        &self,
        window: [u8; LONG_ANCHOR_LENGTH],
    ) -> impl Iterator<Item = AnchoredProgram> + 'm {
        let hash = four_gram_hash(u32::from_le_bytes(window), self.long_filter.filter_bits);
        let bucket = usize::try_from(hash >> self.bucket_shift).unwrap_or(usize::MAX);
        let start = self.long_buckets.get(bucket).map_or(0, |start| start.get());
        let end = bucket
            .checked_add(1)
            .and_then(|next| self.long_buckets.get(next))
            .map_or(0, |end| end.get());
        let range = usize::try_from(start).unwrap_or(0)..usize::try_from(end).unwrap_or(0);
        self.long_anchors
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
        let distance = entry.distance.get();
        let shift = entry.shift.get();
        let placement = match entry.placement {
            PLACEMENT_ANYWHERE => Placement::Anywhere,
            PLACEMENT_FROM_START => Placement::FromStart { distance, shift },
            PLACEMENT_BEFORE_END => Placement::BeforeEnd { distance, shift },
            _ => return Err(malformed),
        };
        Ok(PatternSignatureRecord {
            name: NameId(entry.name.get()),
            category,
            placement,
            report_rank: entry.report_rank,
            first_program: ProgramId(entry.first_program.get()),
            segment_count: entry.segment_count.get(),
        })
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
