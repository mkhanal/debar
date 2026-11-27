use zerocopy::little_endian::U32;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::model::SignatureGroup;
use crate::pattern_group::four_gram_hash;
use crate::pattern_program::{LONG_ANCHOR_LENGTH, SHORT_ANCHOR_LENGTH};

const MOST_GROUPS: usize = 4;
const SLOTS_PER_ANCHOR_LOG: u32 = 5;
const SMALLEST_FILTER_BITS: u32 = 10;
const LARGEST_FILTER_BITS: u32 = 30;
const SHORT_FILTER_BYTES: usize = 1 << 13;
const NO_GROUP: u32 = u32::MAX;
const CASE_BIT: u8 = 0x20;

#[derive(Default)]
pub struct GroupAnchors {
    pub exact: Vec<[u8; LONG_ANCHOR_LENGTH]>,
    pub folded: Vec<[u8; LONG_ANCHOR_LENGTH]>,
    pub short: Vec<[u8; SHORT_ANCHOR_LENGTH]>,
}

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned, Clone, Copy)]
#[repr(C)]
struct FilterEntry {
    groups: [U32; MOST_GROUPS],
    long_bits: U32,
    long_start: U32,
    short_start: U32,
}

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
struct FiltersHeader {
    entry_count: U32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FiltersNotBuilt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FiltersMalformed;

fn case_variants(anchor: [u8; LONG_ANCHOR_LENGTH]) -> Vec<[u8; LONG_ANCHOR_LENGTH]> {
    let mut variants = vec![anchor];
    for index in 0..LONG_ANCHOR_LENGTH {
        if !anchor.get(index).is_some_and(u8::is_ascii_alphabetic) {
            continue;
        }
        let flipped: Vec<[u8; LONG_ANCHOR_LENGTH]> = variants
            .iter()
            .map(|variant| {
                let mut flipped = *variant;
                if let Some(byte) = flipped.get_mut(index) {
                    *byte ^= CASE_BIT;
                }
                flipped
            })
            .collect();
        variants.extend(flipped);
    }
    variants
}

fn ceiling_log2(value: usize) -> u32 {
    usize::BITS.saturating_sub(value.saturating_sub(1).leading_zeros())
}

pub fn build<'a>(
    selections: &[Vec<SignatureGroup>],
    anchors_of: &dyn Fn(SignatureGroup) -> Option<&'a GroupAnchors>,
) -> Result<Vec<u8>, FiltersNotBuilt> {
    let mut entries = Vec::with_capacity(selections.len());
    let mut data = Vec::new();
    for groups in selections {
        if groups.len() > MOST_GROUPS {
            return Err(FiltersNotBuilt);
        }
        let mut long: Vec<u32> = Vec::new();
        let mut short = vec![0u8; SHORT_FILTER_BYTES];
        for group in groups {
            let Some(anchors) = anchors_of(*group) else {
                continue;
            };
            long.extend(
                anchors
                    .exact
                    .iter()
                    .map(|anchor| u32::from_le_bytes(*anchor)),
            );
            for anchor in &anchors.folded {
                long.extend(case_variants(*anchor).into_iter().map(u32::from_le_bytes));
            }
            for anchor in &anchors.short {
                let window = u16::from_le_bytes(*anchor);
                if let Some(slot) = short.get_mut(usize::from(window >> 3)) {
                    *slot |= 1 << (window & 7);
                }
            }
        }
        long.sort_unstable();
        long.dedup();
        let long_bits = ceiling_log2(long.len())
            .saturating_add(SLOTS_PER_ANCHOR_LOG)
            .clamp(SMALLEST_FILTER_BITS, LARGEST_FILTER_BITS);
        let long_length = 1usize
            .checked_shl(long_bits)
            .map(|bits| bits / 8)
            .ok_or(FiltersNotBuilt)?;
        let mut long_filter = vec![0u8; long_length];
        for window in long {
            let hash = four_gram_hash(window, long_bits);
            if let Some(slot) = usize::try_from(hash >> 3)
                .ok()
                .and_then(|at| long_filter.get_mut(at))
            {
                *slot |= 1 << (hash & 7);
            }
        }
        let mut group_ids = [U32::new(NO_GROUP); MOST_GROUPS];
        for (slot, group) in group_ids.iter_mut().zip(groups) {
            *slot = U32::new(group.0);
        }
        let long_start = u32::try_from(data.len()).map_err(|_| FiltersNotBuilt)?;
        data.extend_from_slice(&long_filter);
        let short_start = u32::try_from(data.len()).map_err(|_| FiltersNotBuilt)?;
        data.extend_from_slice(&short);
        entries.push(FilterEntry {
            groups: group_ids,
            long_bits: U32::new(long_bits),
            long_start: U32::new(long_start),
            short_start: U32::new(short_start),
        });
    }
    let header = FiltersHeader {
        entry_count: U32::new(u32::try_from(entries.len()).map_err(|_| FiltersNotBuilt)?),
    };
    let mut bytes = header.as_bytes().to_vec();
    bytes.extend_from_slice(entries.as_bytes());
    bytes.extend_from_slice(&data);
    Ok(bytes)
}

#[derive(Clone, Copy)]
pub struct SelectionFilter<'m> {
    long: &'m [u8],
    long_bits: u32,
    short: &'m [u8; SHORT_FILTER_BYTES],
}

impl SelectionFilter<'_> {
    #[inline]
    #[must_use]
    pub fn may_hold_long(&self, window: u32) -> bool {
        let hash = four_gram_hash(window, self.long_bits);
        usize::try_from(hash >> 3)
            .ok()
            .and_then(|at| self.long.get(at))
            .is_some_and(|slot| slot & (1 << (hash & 7)) != 0)
    }

    #[inline]
    #[must_use]
    pub fn may_hold_short(&self, window: u16) -> bool {
        self.short
            .get(usize::from(window >> 3))
            .is_some_and(|slot| slot & (1 << (window & 7)) != 0)
    }
}

pub fn find<'m>(
    bytes: &'m [u8],
    groups: &[SignatureGroup],
) -> Result<Option<SelectionFilter<'m>>, FiltersMalformed> {
    let (header, rest) = FiltersHeader::ref_from_prefix(bytes).map_err(|_| FiltersMalformed)?;
    let count = usize::try_from(header.entry_count.get()).map_err(|_| FiltersMalformed)?;
    let (entries, data) =
        <[FilterEntry]>::ref_from_prefix_with_elems(rest, count).map_err(|_| FiltersMalformed)?;
    let wanted: Vec<u32> = groups.iter().map(|group| group.0).collect();
    for entry in entries {
        let listed: Vec<u32> = entry
            .groups
            .iter()
            .map(|group| group.get())
            .filter(|group| *group != NO_GROUP)
            .collect();
        if listed != wanted {
            continue;
        }
        let long_bits = entry.long_bits.get();
        if long_bits > LARGEST_FILTER_BITS {
            return Err(FiltersMalformed);
        }
        let long_length = 1usize
            .checked_shl(long_bits)
            .map(|bits| bits / 8)
            .ok_or(FiltersMalformed)?;
        let long_start = usize::try_from(entry.long_start.get()).map_err(|_| FiltersMalformed)?;
        let short_start = usize::try_from(entry.short_start.get()).map_err(|_| FiltersMalformed)?;
        let long = data
            .get(
                long_start
                    ..long_start
                        .checked_add(long_length)
                        .ok_or(FiltersMalformed)?,
            )
            .ok_or(FiltersMalformed)?;
        let short = data
            .get(short_start..)
            .and_then(|rest| rest.first_chunk::<SHORT_FILTER_BYTES>())
            .ok_or(FiltersMalformed)?;
        return Ok(Some(SelectionFilter {
            long,
            long_bits,
            short,
        }));
    }
    Ok(None)
}
