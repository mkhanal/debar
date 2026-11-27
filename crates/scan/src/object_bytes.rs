use debar_matching::{DigestNeed, DigestsInProgress, ObjectDigests};
use debar_platform::input::InputError;
pub use debar_platform::input::ObjectBytes;

pub(crate) const CHUNK_LENGTH: usize = 128 * 1024;

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
