use debar_image::{
    AnchorBytes, AnchorCase, AnchoredProgram, Displacement, GroupMalformed, LONG_ANCHOR_LENGTH,
    LogicalGroup, LogicalSignatureId, MatchingPass, PatternGroup, PatternSignatureId, ProgramId,
    SHORT_ANCHOR_LENGTH, ascii_lowercase,
};

use crate::pattern_scan::PatternScanError;

const MOST_PROGRAMS: usize = 8_192;
const MOST_BUCKET_BITS: u32 = 13;
const BUCKET_HASH_MULTIPLIER: u32 = 0x9e37_79b1;
const SHORT_ANCHOR_MASK: u32 = 0xffff;
const LONG_ANCHOR_MASK: u32 = 0xffff_ffff;
const PREFIX_FILTER_WORDS: usize = 1 << 10;
const POSITIONS_PER_BLOCK: usize = 8;
const BLOCK_BYTES: usize = POSITIONS_PER_BLOCK + SHORT_ANCHOR_LENGTH - 1;

type PrefixFilter = [u64; PREFIX_FILTER_WORDS];

#[derive(Debug, Clone, Copy)]
struct Entry {
    group: usize,
    program: ProgramId,
    displacement: Displacement,
}

impl Entry {
    fn hit_at(&self, position: u64) -> (u64, usize, AnchoredProgram) {
        (
            position,
            self.group,
            AnchoredProgram {
                program: self.program,
                displacement: self.displacement,
            },
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum AnchorLength {
    Short,
    Long,
}

impl AnchorLength {
    const fn bytes(self) -> usize {
        match self {
            Self::Short => SHORT_ANCHOR_LENGTH,
            Self::Long => LONG_ANCHOR_LENGTH,
        }
    }

    const fn mask(self) -> u32 {
        match self {
            Self::Short => SHORT_ANCHOR_MASK,
            Self::Long => LONG_ANCHOR_MASK,
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct SearchedAnchor {
    lowered_prefix: u16,
    case: AnchorCase,
    length: AnchorLength,
    bytes: u32,
    entry: Entry,
}

impl SearchedAnchor {
    fn new(
        bytes: [u8; LONG_ANCHOR_LENGTH],
        length: AnchorLength,
        case: AnchorCase,
        entry: Entry,
    ) -> Self {
        let [first, second, _, _] = ascii_lowercase(bytes);
        let compared = match case {
            AnchorCase::Exact => bytes,
            AnchorCase::Folded => ascii_lowercase(bytes),
        };
        Self {
            lowered_prefix: u16::from_le_bytes([first, second]),
            case,
            length,
            bytes: u32::from_le_bytes(compared) & length.mask(),
            entry,
        }
    }

    fn search_order(&self, bucket_bits: u32) -> (u32, u16, u8, AnchorLength) {
        let case = match self.case {
            AnchorCase::Exact => 0,
            AnchorCase::Folded => 1,
        };
        (
            bucket_of(self.lowered_prefix, bucket_bits),
            self.lowered_prefix,
            case,
            self.length,
        )
    }

    fn found_in(&self, window: &Window) -> bool {
        let seen = match self.case {
            AnchorCase::Exact => window.exact,
            AnchorCase::Folded => window.lowered,
        };
        window.length >= self.length.bytes() && seen & self.length.mask() == self.bytes
    }

    fn prefix_variants(&self) -> impl Iterator<Item = u16> {
        let case = self.case;
        let variants = move |byte: u8| match case {
            AnchorCase::Exact => [byte, byte],
            AnchorCase::Folded => [byte, byte.to_ascii_uppercase()],
        };
        let [first, second, _, _] = self.bytes.to_le_bytes();
        let [first, second] = [first, second].map(variants);
        first
            .into_iter()
            .flat_map(move |first| second.map(|second| u16::from_le_bytes([first, second])))
    }
}

struct Window {
    exact: u32,
    lowered: u32,
    length: usize,
}

impl Window {
    fn of(bytes: &[u8]) -> Self {
        let mut seen = [0; LONG_ANCHOR_LENGTH];
        for (slot, byte) in seen.iter_mut().zip(bytes) {
            *slot = *byte;
        }
        Self {
            exact: u32::from_le_bytes(seen),
            lowered: u32::from_le_bytes(ascii_lowercase(seen)),
            length: bytes.len().min(LONG_ANCHOR_LENGTH),
        }
    }

    fn lowered_prefix(&self) -> u16 {
        let [first, second, _, _] = self.lowered.to_le_bytes();
        u16::from_le_bytes([first, second])
    }
}

fn bucket_of(lowered_prefix: u16, bucket_bits: u32) -> u32 {
    u32::from(lowered_prefix)
        .wrapping_mul(BUCKET_HASH_MULTIPLIER)
        .checked_shr(u32::BITS.saturating_sub(bucket_bits))
        .unwrap_or(0)
}

fn bucket_bits_for(anchors: usize) -> u32 {
    anchors
        .checked_next_power_of_two()
        .map_or(MOST_BUCKET_BITS, usize::trailing_zeros)
        .clamp(1, MOST_BUCKET_BITS)
}

pub(crate) struct ArmedGroup<'v, 'm> {
    pub index: usize,
    pub patterns: &'v PatternGroup<'m>,
    pub logical: &'v LogicalGroup<'m>,
    pub armed: &'v [u32],
}

#[must_use]
pub fn largest_armed_search_bytes() -> usize {
    let buckets = (1usize << MOST_BUCKET_BITS).saturating_add(1);
    MOST_PROGRAMS
        .saturating_mul(std::mem::size_of::<SearchedAnchor>())
        .saturating_add(buckets.saturating_mul(std::mem::size_of::<u32>()))
        .saturating_add(std::mem::size_of::<PrefixFilter>())
}

pub(crate) struct SecondPassSearch {
    prefixes: Box<PrefixFilter>,
    bucket_bits: u32,
    bucket_starts: Vec<u32>,
    anchors: Vec<SearchedAnchor>,
    everywhere: Vec<Entry>,
}

impl SecondPassSearch {
    #[inline(never)]
    pub(crate) fn for_armed(
        groups: &[ArmedGroup<'_, '_>],
    ) -> Result<Option<Self>, PatternScanError> {
        let mut anchors = Vec::new();
        let mut everywhere = Vec::new();
        let mut programs = 0usize;
        for group in groups {
            for id in group.armed {
                let record = group
                    .logical
                    .signature(LogicalSignatureId(*id))
                    .map_err(|_| GroupMalformed::Layout)?;
                for index in 0..record.subsignature_count {
                    let index = u16::try_from(index).map_err(|_| GroupMalformed::Layout)?;
                    let subsignature = group
                        .logical
                        .subsignature(&record, index)
                        .map_err(|_| GroupMalformed::Layout)?;
                    let Some(first) = subsignature.pattern else {
                        continue;
                    };
                    if subsignature.pass != MatchingPass::Second {
                        continue;
                    }
                    for offset in 0..u32::from(subsignature.pattern_count) {
                        let pattern = group
                            .patterns
                            .signature(PatternSignatureId(first.0.saturating_add(offset)))?;
                        for segment in 0..pattern.segment_count {
                            let program =
                                ProgramId(pattern.first_program.0.saturating_add(segment));
                            let header = group.patterns.program_header(program)?;
                            if segment > 0 && header.is_armed_by_predecessor() {
                                continue;
                            }
                            programs = programs.saturating_add(1);
                            if programs > MOST_PROGRAMS {
                                return Ok(None);
                            }
                            let anchor = header.anchor();
                            let entry = Entry {
                                group: group.index,
                                program,
                                displacement: anchor.displacement,
                            };
                            let (bytes, length) = match anchor.bytes {
                                AnchorBytes::Long(bytes) => (bytes, AnchorLength::Long),
                                AnchorBytes::Short([first, second]) => {
                                    ([first, second, 0, 0], AnchorLength::Short)
                                }
                                AnchorBytes::None => {
                                    everywhere.push(entry);
                                    continue;
                                }
                            };
                            anchors.push(SearchedAnchor::new(bytes, length, anchor.case, entry));
                        }
                    }
                }
            }
        }
        anchors.shrink_to_fit();
        everywhere.shrink_to_fit();
        let bucket_bits = bucket_bits_for(anchors.len());
        anchors.sort_by_key(|anchor| anchor.search_order(bucket_bits));
        let mut prefixes = Box::new([0; PREFIX_FILTER_WORDS]);
        for anchor in &anchors {
            for window in anchor.prefix_variants() {
                if let Some(word) = prefixes.get_mut(usize::from(window >> 6)) {
                    *word |= 1 << (window & 63);
                }
            }
        }
        let mut placed = anchors
            .iter()
            .map(|anchor| bucket_of(anchor.lowered_prefix, bucket_bits))
            .enumerate()
            .peekable();
        let mut bucket_starts = Vec::new();
        for bucket in 0..=1u32 << bucket_bits {
            while placed
                .next_if(|(_, placed_in)| *placed_in < bucket)
                .is_some()
            {}
            let first = placed.peek().map_or(anchors.len(), |(index, _)| *index);
            bucket_starts.push(u32::try_from(first).unwrap_or(u32::MAX));
        }
        Ok(Some(Self {
            prefixes,
            bucket_bits,
            bucket_starts,
            anchors,
            everywhere,
        }))
    }

    #[inline(never)]
    pub(crate) fn search(
        &self,
        bytes: &[u8],
        first_position: u64,
        positions: usize,
        hits: &mut Vec<(u64, usize, AnchoredProgram)>,
    ) {
        if !self.anchors.is_empty() {
            let searched = positions.min(bytes.len().saturating_sub(SHORT_ANCHOR_LENGTH - 1));
            let mut offset = 0;
            while offset < searched {
                let block_end = offset.saturating_add(POSITIONS_PER_BLOCK);
                let block = bytes
                    .get(offset..)
                    .and_then(<[u8]>::first_chunk::<BLOCK_BYTES>);
                if block_end > searched || block.is_none_or(|block| self.block_may_hold(block)) {
                    for at in offset..block_end.min(searched) {
                        self.search_at(bytes, at, first_position, hits);
                    }
                }
                offset = block_end;
            }
        }
        if !self.everywhere.is_empty() {
            for offset in 0..positions {
                let position =
                    first_position.saturating_add(u64::try_from(offset).unwrap_or(u64::MAX));
                hits.extend(self.everywhere.iter().map(|entry| entry.hit_at(position)));
            }
        }
    }

    fn block_may_hold(&self, block: &[u8; BLOCK_BYTES]) -> bool {
        block.windows(SHORT_ANCHOR_LENGTH).fold(0, |held, window| {
            held | window
                .first_chunk::<SHORT_ANCHOR_LENGTH>()
                .map_or(0, |prefix| {
                    self.word_shifted_to(u16::from_le_bytes(*prefix))
                })
        }) & 1
            != 0
    }

    fn word_shifted_to(&self, window: u16) -> u64 {
        self.prefixes
            .get(usize::from(window >> 6))
            .map_or(0, |word| word >> (window & 63))
    }

    fn search_at(
        &self,
        bytes: &[u8],
        offset: usize,
        first_position: u64,
        hits: &mut Vec<(u64, usize, AnchoredProgram)>,
    ) {
        let Some(window) = bytes.get(offset..) else {
            return;
        };
        let held = window
            .first_chunk::<SHORT_ANCHOR_LENGTH>()
            .is_some_and(|prefix| self.word_shifted_to(u16::from_le_bytes(*prefix)) & 1 != 0);
        if held {
            let position = first_position.saturating_add(u64::try_from(offset).unwrap_or(u64::MAX));
            self.anchored_at(window, position, hits);
        }
    }

    #[inline(never)]
    fn anchored_at(
        &self,
        bytes: &[u8],
        position: u64,
        hits: &mut Vec<(u64, usize, AnchoredProgram)>,
    ) {
        let window = Window::of(bytes);
        let prefix = window.lowered_prefix();
        let bucket = usize::try_from(bucket_of(prefix, self.bucket_bits)).unwrap_or(usize::MAX);
        let first = self.bucket_starts.get(bucket);
        let end = bucket
            .checked_add(1)
            .and_then(|next| self.bucket_starts.get(next));
        let (Some(first), Some(end)) = (first, end) else {
            return;
        };
        let in_bucket = usize::try_from(*first).unwrap_or(usize::MAX)
            ..usize::try_from(*end).unwrap_or(usize::MAX);
        hits.extend(
            self.anchors
                .get(in_bucket)
                .unwrap_or_default()
                .iter()
                .filter(|anchor| anchor.lowered_prefix == prefix && anchor.found_in(&window))
                .map(|anchor| anchor.entry.hit_at(position)),
        );
    }

    pub(crate) fn state_bytes(&self) -> usize {
        std::mem::size_of::<PrefixFilter>()
            .saturating_add(
                self.bucket_starts
                    .capacity()
                    .saturating_mul(std::mem::size_of::<u32>()),
            )
            .saturating_add(
                self.anchors
                    .capacity()
                    .saturating_mul(std::mem::size_of::<SearchedAnchor>()),
            )
            .saturating_add(
                self.everywhere
                    .capacity()
                    .saturating_mul(std::mem::size_of::<Entry>()),
            )
    }
}
