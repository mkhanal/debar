use sha2::{Digest, Sha256};
use zerocopy::little_endian::{U32, U64};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

const SEED_DOMAIN: &[u8] = b"debar-fuse";
const CONSTRUCTION_ATTEMPTS: u32 = 1_000;
const LARGEST_SEGMENT_LENGTH_LOG: u32 = 18;
const SMALLEST_SIZE_FACTOR_PER_MILLE: u64 = 1_125;
const HASHES_PER_KEY: usize = 3;

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned, Clone, Copy)]
#[repr(C)]
pub struct FilterHeader {
    pub seed: U64,
    pub segment_length: U32,
    pub segment_count_length: U32,
    pub fingerprint_count: U32,
    pub key_count: U32,
}

#[derive(Debug, PartialEq, Eq)]
pub struct FilterNotBuilt;

pub fn build(mut keys: Vec<u64>) -> Result<Vec<u8>, FilterNotBuilt> {
    keys.sort_unstable();
    keys.dedup();
    let geometry = Geometry::for_key_count(keys.len()).ok_or(FilterNotBuilt)?;
    for attempt in 0..CONSTRUCTION_ATTEMPTS {
        let seed = seed_for_attempt(attempt);
        if let Some(fingerprints) = construct(&keys, &geometry, seed) {
            return serialise(&geometry, seed, keys.len(), &fingerprints).ok_or(FilterNotBuilt);
        }
    }
    Err(FilterNotBuilt)
}

pub struct FilterView<'m> {
    header: &'m FilterHeader,
    fingerprints: &'m [u8],
}

#[derive(Debug, PartialEq, Eq)]
pub struct FilterMalformed;

impl<'m> FilterView<'m> {
    pub fn read(bytes: &'m [u8]) -> Result<Self, FilterMalformed> {
        let (header, fingerprints) =
            FilterHeader::ref_from_prefix(bytes).map_err(|_| FilterMalformed)?;
        let expected =
            usize::try_from(header.fingerprint_count.get()).map_err(|_| FilterMalformed)?;
        let fingerprints = fingerprints.get(..expected).ok_or(FilterMalformed)?;
        Ok(Self {
            header,
            fingerprints,
        })
    }

    #[must_use]
    pub fn may_contain(&self, key: u64) -> bool {
        if self.header.key_count.get() == 0 {
            return false;
        }
        let geometry = Geometry {
            segment_length: u64::from(self.header.segment_length.get()),
            segment_count_length: u64::from(self.header.segment_count_length.get()),
            fingerprint_count: self.fingerprints.len(),
        };
        let hash = mix(key.wrapping_add(self.header.seed.get()));
        let Some(positions) = geometry.positions(hash) else {
            return false;
        };
        let mut combined = fingerprint(hash);
        for position in positions {
            match self.fingerprints.get(position) {
                Some(stored) => combined ^= stored,
                None => return false,
            }
        }
        combined == 0
    }
}

#[must_use]
pub fn mix(mut value: u64) -> u64 {
    value ^= value >> 33;
    value = value.wrapping_mul(0xff51_afd7_ed55_8ccd);
    value ^= value >> 33;
    value = value.wrapping_mul(0xc4ce_b9fe_1a85_ec53);
    value ^ (value >> 33)
}

struct Geometry {
    segment_length: u64,
    segment_count_length: u64,
    fingerprint_count: usize,
}

impl Geometry {
    fn for_key_count(key_count: usize) -> Option<Self> {
        let keys = u64::try_from(key_count).ok()?.max(1);
        let log2_keys = u64::from(keys.ilog2());
        let segment_length_log = u32::try_from(
            log2_keys
                .checked_mul(5_762)?
                .checked_add(22_500)?
                .checked_div(10_000)?,
        )
        .ok()?
        .min(LARGEST_SEGMENT_LENGTH_LOG);
        let segment_length = 1u64.checked_shl(segment_length_log)?;
        let size_factor_per_mille = 250u64
            .checked_mul(19_932)?
            .checked_div(log2_keys.max(1).checked_mul(1_000)?)?
            .checked_add(875)?
            .max(SMALLEST_SIZE_FACTOR_PER_MILLE);
        let capacity = keys.checked_mul(size_factor_per_mille)?.div_ceil(1_000);
        let segment_count = capacity.div_ceil(segment_length).saturating_sub(2).max(1);
        let segment_count_length = segment_count.checked_mul(segment_length)?;
        let fingerprint_count =
            usize::try_from(segment_count.checked_add(2)?.checked_mul(segment_length)?).ok()?;
        u32::try_from(fingerprint_count).ok()?;
        Some(Self {
            segment_length,
            segment_count_length,
            fingerprint_count,
        })
    }

    fn positions(&self, hash: u64) -> Option<[usize; HASHES_PER_KEY]> {
        let mask = self.segment_length.checked_sub(1)?;
        let first = u64::try_from(
            (u128::from(hash).checked_mul(u128::from(self.segment_count_length))?) >> 64,
        )
        .ok()?;
        let second = first.checked_add(self.segment_length)? ^ ((hash >> 18) & mask);
        let third = first.checked_add(self.segment_length.checked_mul(2)?)? ^ (hash & mask);
        Some([
            usize::try_from(first).ok()?,
            usize::try_from(second).ok()?,
            usize::try_from(third).ok()?,
        ])
    }
}

fn fingerprint(hash: u64) -> u8 {
    (hash ^ (hash >> 32)).to_le_bytes()[0]
}

fn seed_for_attempt(attempt: u32) -> u64 {
    let digest = Sha256::new()
        .chain_update(SEED_DOMAIN)
        .chain_update(attempt.to_le_bytes())
        .finalize();
    let bytes: [u8; 32] = digest.into();
    let [b0, b1, b2, b3, b4, b5, b6, b7, ..] = bytes;
    u64::from_le_bytes([b0, b1, b2, b3, b4, b5, b6, b7])
}

struct Peeled {
    hash: u64,
    slot: usize,
}

fn construct(keys: &[u64], geometry: &Geometry, seed: u64) -> Option<Vec<u8>> {
    let mut counts = vec![0u32; geometry.fingerprint_count];
    let mut hash_sums = vec![0u64; geometry.fingerprint_count];
    for key in keys {
        let hash = mix(key.wrapping_add(seed));
        for position in geometry.positions(hash)? {
            let count = counts.get_mut(position)?;
            *count = count.checked_add(1)?;
            *hash_sums.get_mut(position)? ^= hash;
        }
    }
    let mut ready: Vec<usize> = (0..geometry.fingerprint_count)
        .filter(|position| counts.get(*position) == Some(&1))
        .collect();
    let mut peeled = Vec::with_capacity(keys.len());
    while let Some(position) = ready.pop() {
        if counts.get(position) != Some(&1) {
            continue;
        }
        let hash = *hash_sums.get(position)?;
        let positions = geometry.positions(hash)?;
        let slot = positions
            .iter()
            .position(|candidate| *candidate == position)?;
        peeled.push(Peeled { hash, slot });
        for other in positions {
            let count = counts.get_mut(other)?;
            *count = count.checked_sub(1)?;
            *hash_sums.get_mut(other)? ^= hash;
            if *count == 1 {
                ready.push(other);
            }
        }
    }
    if peeled.len() != keys.len() {
        return None;
    }
    let mut fingerprints = vec![0u8; geometry.fingerprint_count];
    for Peeled { hash, slot } in peeled.iter().rev() {
        let positions = geometry.positions(*hash)?;
        let mut value = fingerprint(*hash);
        for (index, position) in positions.iter().enumerate() {
            if index != *slot {
                value ^= fingerprints.get(*position)?;
            }
        }
        *fingerprints.get_mut(*positions.get(*slot)?)? = value;
    }
    Some(fingerprints)
}

fn serialise(
    geometry: &Geometry,
    seed: u64,
    key_count: usize,
    fingerprints: &[u8],
) -> Option<Vec<u8>> {
    let header = FilterHeader {
        seed: U64::new(seed),
        segment_length: U32::new(u32::try_from(geometry.segment_length).ok()?),
        segment_count_length: U32::new(u32::try_from(geometry.segment_count_length).ok()?),
        fingerprint_count: U32::new(u32::try_from(fingerprints.len()).ok()?),
        key_count: U32::new(u32::try_from(key_count).ok()?),
    };
    let mut bytes = header.as_bytes().to_vec();
    bytes.extend_from_slice(fingerprints);
    Some(bytes)
}
