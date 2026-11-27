use debar_matching::{DigestNeed, DigestsInProgress, ObjectDigests};
use debar_platform::input::{InputError, ScannedFile};

pub(crate) const CHUNK_LENGTH: usize = 128 * 1024;

pub trait ObjectBytes {
    fn length(&self) -> u64;

    fn read_at(&self, offset: u64, into: &mut [u8]) -> Result<(), InputError>;
}

impl ObjectBytes for ScannedFile {
    fn length(&self) -> u64 {
        ScannedFile::length(self)
    }

    fn read_at(&self, offset: u64, into: &mut [u8]) -> Result<(), InputError> {
        ScannedFile::read_at(self, offset, into)
    }
}

impl ObjectBytes for [u8] {
    fn length(&self) -> u64 {
        u64::try_from(self.len()).unwrap_or(u64::MAX)
    }

    fn read_at(&self, offset: u64, into: &mut [u8]) -> Result<(), InputError> {
        let wanted = u64::try_from(into.len()).unwrap_or(u64::MAX);
        let held = usize::try_from(offset)
            .ok()
            .and_then(|start| self.get(start..start.checked_add(into.len())?))
            .ok_or(InputError::BeyondTheEnd {
                offset,
                wanted,
                length: ObjectBytes::length(self),
            })?;
        into.copy_from_slice(held);
        Ok(())
    }
}

pub(crate) enum ChunkUse {
    Continue,
    Stop,
}

pub(crate) enum ReadThrough {
    ToTheEnd,
    StoppedAt(u64),
}

pub(crate) fn read_in_chunks(
    bytes: &dyn ObjectBytes,
    mut use_chunk: impl FnMut(&[u8]) -> ChunkUse,
) -> Result<ReadThrough, InputError> {
    let length = bytes.length();
    let mut chunk = vec![0u8; CHUNK_LENGTH];
    let mut offset = 0u64;
    while offset < length {
        let wanted = length
            .saturating_sub(offset)
            .min(u64::try_from(CHUNK_LENGTH).unwrap_or(u64::MAX));
        let filled = chunk
            .get_mut(..usize::try_from(wanted).unwrap_or(CHUNK_LENGTH))
            .unwrap_or_default();
        bytes.read_at(offset, filled)?;
        offset = offset.saturating_add(wanted);
        if let ChunkUse::Stop = use_chunk(filled) {
            return Ok(ReadThrough::StoppedAt(offset));
        }
    }
    Ok(ReadThrough::ToTheEnd)
}

pub(crate) fn digests_of(
    bytes: &dyn ObjectBytes,
    need: DigestNeed,
) -> Result<ObjectDigests, InputError> {
    let mut digesting = DigestsInProgress::new(need);
    read_in_chunks(bytes, |chunk| {
        digesting.update(chunk);
        ChunkUse::Continue
    })?;
    Ok(digesting.finish())
}

pub(crate) fn whole_object(bytes: &dyn ObjectBytes) -> Result<Vec<u8>, InputError> {
    let mut whole = Vec::new();
    read_in_chunks(bytes, |chunk| {
        whole.extend_from_slice(chunk);
        ChunkUse::Continue
    })?;
    Ok(whole)
}
