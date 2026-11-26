use zerocopy::little_endian::U32;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::fuse_filter::{self, FilterMalformed, FilterNotBuilt, FilterView};
use crate::model::{Category, DigestAlgorithm, HashPurpose, HashedSize};
use crate::names::NameId;

const SIZES_PER_FENCE: usize = 64;
const SIZE_KEY_SPREAD: u64 = 0x9e37_79b9_7f4a_7c15;
const NAME_ID_LENGTH: usize = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PartitionKey {
    pub purpose: HashPurpose,
    pub category: Category,
    pub algorithm: DigestAlgorithm,
}

impl PartitionKey {
    #[must_use]
    pub fn qualifier(self) -> u32 {
        let purpose: u32 = match self.purpose {
            HashPurpose::WholeObjectDetection => 1,
            HashPurpose::ExecutableSectionDetection => 2,
            HashPurpose::WholeObjectTrust => 3,
        };
        let category: u32 = match self.category {
            Category::Malware => 1,
            Category::PotentiallyUnwanted => 2,
        };
        let algorithm: u32 = match self.algorithm {
            DigestAlgorithm::Md5 => 1,
            DigestAlgorithm::Sha1 => 2,
            DigestAlgorithm::Sha256 => 3,
        };
        (purpose << 16) | (category << 8) | algorithm
    }
}

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
struct SizesHeader {
    size_count: U32,
    exact_entry_count: U32,
    any_size_entry_count: U32,
    digest_length: U32,
}

pub struct PendingEntry {
    pub size: HashedSize,
    pub digest: Vec<u8>,
    pub name: NameId,
}

pub struct BuiltPartition {
    pub sizes: Vec<u8>,
    pub filter: Vec<u8>,
    pub entries: Vec<u8>,
    pub entry_count: usize,
}

#[derive(Debug, PartialEq, Eq)]
pub enum PartitionNotBuilt {
    TooLarge,
    Filter(FilterNotBuilt),
}

pub fn build(
    algorithm: DigestAlgorithm,
    mut entries: Vec<PendingEntry>,
) -> Result<BuiltPartition, PartitionNotBuilt> {
    entries.sort_by(|left, right| (left.size, &left.digest).cmp(&(right.size, &right.digest)));
    let mut sizes: Vec<U32> = Vec::new();
    let mut entry_starts: Vec<U32> = Vec::new();
    let mut exact_entry_count: u32 = 0;
    let mut filter_keys = Vec::new();
    let mut entry_bytes = Vec::new();
    for entry in &entries {
        if let HashedSize::Exactly(size) = entry.size {
            if sizes.last().map(|last| last.get()) != Some(size) {
                sizes.push(U32::new(size));
                entry_starts.push(U32::new(exact_entry_count));
            }
            exact_entry_count = exact_entry_count
                .checked_add(1)
                .ok_or(PartitionNotBuilt::TooLarge)?;
            filter_keys.push(filter_key(size, &entry.digest));
        }
        entry_bytes.extend_from_slice(&entry.digest);
        entry_bytes.extend_from_slice(&entry.name.0.to_le_bytes());
    }
    entry_starts.push(U32::new(exact_entry_count));
    let any_size_entry_count = u32::try_from(entries.len())
        .map_err(|_| PartitionNotBuilt::TooLarge)?
        .checked_sub(exact_entry_count)
        .ok_or(PartitionNotBuilt::TooLarge)?;
    let fences: Vec<U32> = sizes.iter().step_by(SIZES_PER_FENCE).copied().collect();
    let header = SizesHeader {
        size_count: U32::new(u32::try_from(sizes.len()).map_err(|_| PartitionNotBuilt::TooLarge)?),
        exact_entry_count: U32::new(exact_entry_count),
        any_size_entry_count: U32::new(any_size_entry_count),
        digest_length: U32::new(
            u32::try_from(algorithm.digest_length()).map_err(|_| PartitionNotBuilt::TooLarge)?,
        ),
    };
    let mut size_bytes = header.as_bytes().to_vec();
    size_bytes.extend_from_slice(fences.as_bytes());
    size_bytes.extend_from_slice(sizes.as_bytes());
    size_bytes.extend_from_slice(entry_starts.as_bytes());
    Ok(BuiltPartition {
        sizes: size_bytes,
        filter: fuse_filter::build(filter_keys).map_err(PartitionNotBuilt::Filter)?,
        entries: entry_bytes,
        entry_count: entries.len(),
    })
}

#[must_use]
pub fn filter_key(size: u32, digest: &[u8]) -> u64 {
    let mut leading = [0u8; 8];
    for (slot, byte) in leading.iter_mut().zip(digest) {
        *slot = *byte;
    }
    fuse_filter::mix(u64::from_le_bytes(leading) ^ u64::from(size).wrapping_mul(SIZE_KEY_SPREAD))
}

#[derive(Debug, PartialEq, Eq)]
pub enum PartitionMalformed {
    Sizes,
    Filter(FilterMalformed),
    Entries,
}

pub struct HashPartition<'m> {
    digest_length: usize,
    fences: &'m [U32],
    sizes: &'m [U32],
    entry_starts: &'m [U32],
    filter: FilterView<'m>,
    exact_entries: &'m [u8],
    any_size_entries: &'m [u8],
}

impl<'m> HashPartition<'m> {
    pub fn read(
        algorithm: DigestAlgorithm,
        sizes: &'m [u8],
        filter: &'m [u8],
        entries: &'m [u8],
    ) -> Result<Self, PartitionMalformed> {
        let (header, rest) =
            SizesHeader::ref_from_prefix(sizes).map_err(|_| PartitionMalformed::Sizes)?;
        let digest_length = algorithm.digest_length();
        if usize::try_from(header.digest_length.get()).ok() != Some(digest_length) {
            return Err(PartitionMalformed::Sizes);
        }
        let size_count = to_usize(header.size_count.get()).ok_or(PartitionMalformed::Sizes)?;
        let fence_count = size_count.div_ceil(SIZES_PER_FENCE);
        let (fences, rest) = <[U32]>::ref_from_prefix_with_elems(rest, fence_count)
            .map_err(|_| PartitionMalformed::Sizes)?;
        let (sizes, rest) = <[U32]>::ref_from_prefix_with_elems(rest, size_count)
            .map_err(|_| PartitionMalformed::Sizes)?;
        let (entry_starts, _) = <[U32]>::ref_from_prefix_with_elems(
            rest,
            size_count.checked_add(1).ok_or(PartitionMalformed::Sizes)?,
        )
        .map_err(|_| PartitionMalformed::Sizes)?;
        let record_length = digest_length
            .checked_add(NAME_ID_LENGTH)
            .ok_or(PartitionMalformed::Entries)?;
        let exact_length = to_usize(header.exact_entry_count.get())
            .and_then(|count| count.checked_mul(record_length))
            .ok_or(PartitionMalformed::Entries)?;
        let any_size_length = to_usize(header.any_size_entry_count.get())
            .and_then(|count| count.checked_mul(record_length))
            .ok_or(PartitionMalformed::Entries)?;
        let (exact_entries, rest) = entries
            .split_at_checked(exact_length)
            .ok_or(PartitionMalformed::Entries)?;
        let any_size_entries = rest
            .get(..any_size_length)
            .ok_or(PartitionMalformed::Entries)?;
        Ok(Self {
            digest_length,
            fences,
            sizes,
            entry_starts,
            filter: FilterView::read(filter).map_err(PartitionMalformed::Filter)?,
            exact_entries,
            any_size_entries,
        })
    }

    #[must_use]
    pub fn has_size(&self, size: u32) -> bool {
        self.size_index(size).is_some()
    }

    #[must_use]
    pub fn has_any_size_entries(&self) -> bool {
        !self.any_size_entries.is_empty()
    }

    pub fn lookup_exact_size(
        &self,
        size: u32,
        digest: &[u8],
    ) -> Result<Option<NameId>, PartitionMalformed> {
        let Some(index) = self.size_index(size) else {
            return Ok(None);
        };
        if !self.filter.may_contain(filter_key(size, digest)) {
            return Ok(None);
        }
        let start = self.entry_start(index)?;
        let end = self.entry_start(index.checked_add(1).ok_or(PartitionMalformed::Sizes)?)?;
        let records = self
            .exact_entries
            .get(self.byte_range(start, end)?)
            .ok_or(PartitionMalformed::Entries)?;
        self.last_loaded_match(records, digest)
    }

    pub fn lookup_any_size(&self, digest: &[u8]) -> Result<Option<NameId>, PartitionMalformed> {
        self.last_loaded_match(self.any_size_entries, digest)
    }

    fn size_index(&self, size: u32) -> Option<usize> {
        let fence = self
            .fences
            .partition_point(|fence| fence.get() <= size)
            .checked_sub(1)?;
        let block_start = fence.checked_mul(SIZES_PER_FENCE)?;
        let block_end = block_start
            .checked_add(SIZES_PER_FENCE)?
            .min(self.sizes.len());
        let block = self.sizes.get(block_start..block_end)?;
        let within = block
            .binary_search_by_key(&size, |candidate| candidate.get())
            .ok()?;
        block_start.checked_add(within)
    }

    fn entry_start(&self, index: usize) -> Result<usize, PartitionMalformed> {
        self.entry_starts
            .get(index)
            .and_then(|start| to_usize(start.get()))
            .ok_or(PartitionMalformed::Sizes)
    }

    fn byte_range(
        &self,
        start: usize,
        end: usize,
    ) -> Result<std::ops::Range<usize>, PartitionMalformed> {
        let record_length = self.record_length();
        let from = start.checked_mul(record_length);
        let to = end.checked_mul(record_length);
        match (from, to) {
            (Some(from), Some(to)) if from <= to => Ok(from..to),
            _ => Err(PartitionMalformed::Sizes),
        }
    }

    fn record_length(&self) -> usize {
        self.digest_length.saturating_add(NAME_ID_LENGTH)
    }

    fn last_loaded_match(
        &self,
        records: &[u8],
        digest: &[u8],
    ) -> Result<Option<NameId>, PartitionMalformed> {
        let record_length = self.record_length();
        let record_count = records
            .len()
            .checked_div(record_length)
            .ok_or(PartitionMalformed::Entries)?;
        let digest_of = |index: usize| {
            let start = index.checked_mul(record_length)?;
            records.get(start..start.checked_add(self.digest_length)?)
        };
        let mut low = 0usize;
        let mut high = record_count;
        while low < high {
            let middle = low
                .checked_add(high.checked_sub(low).ok_or(PartitionMalformed::Entries)? / 2)
                .ok_or(PartitionMalformed::Entries)?;
            if digest_of(middle).ok_or(PartitionMalformed::Entries)? < digest {
                low = middle.checked_add(1).ok_or(PartitionMalformed::Entries)?;
            } else {
                high = middle;
            }
        }
        let mut last = None;
        let mut index = low;
        while index < record_count && digest_of(index) == Some(digest) {
            last = Some(index);
            index = index.checked_add(1).ok_or(PartitionMalformed::Entries)?;
        }
        let Some(last) = last else {
            return Ok(None);
        };
        let start = last
            .checked_mul(record_length)
            .and_then(|start| start.checked_add(self.digest_length))
            .ok_or(PartitionMalformed::Entries)?;
        let name = records
            .get(start..)
            .and_then(|rest| U32::read_from_prefix(rest).ok())
            .ok_or(PartitionMalformed::Entries)?
            .0;
        Ok(Some(NameId(name.get())))
    }
}

fn to_usize(value: u32) -> Option<usize> {
    usize::try_from(value).ok()
}
