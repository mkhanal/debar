use debar_matching::{DigestNeed, DigestsInProgress, ObjectDigests};
use debar_platform::input::InputError;
pub use debar_platform::input::ObjectBytes;

pub(crate) const CHUNK_LENGTH: usize = 128 * 1024;

#[derive(Clone, Copy)]
pub(crate) struct ObjectWindow<'o> {
    whole: &'o dyn ObjectBytes,
    start: u64,
    length: u64,
}

impl<'o> ObjectWindow<'o> {
    pub(crate) fn whole(whole: &'o dyn ObjectBytes) -> Self {
        Self {
            whole,
            start: 0,
            length: whole.length(),
        }
    }

    pub(crate) fn onward_from(self, offset: u64) -> Option<Self> {
        Some(Self {
            whole: self.whole,
            start: self.start.checked_add(offset)?,
            length: self.length.checked_sub(offset)?,
        })
    }
}

impl ObjectBytes for ObjectWindow<'_> {
    fn length(&self) -> u64 {
        self.length
    }

    fn read_at(&self, offset: u64, into: &mut [u8]) -> Result<(), InputError> {
        let wanted = u64::try_from(into.len()).unwrap_or(u64::MAX);
        if offset
            .checked_add(wanted)
            .is_none_or(|end| end > self.length)
        {
            return Err(InputError::BeyondTheEnd {
                offset,
                wanted,
                length: self.length,
            });
        }
        let at = self
            .start
            .checked_add(offset)
            .ok_or(InputError::BeyondTheEnd {
                offset,
                wanted,
                length: self.length,
            })?;
        self.whole.read_at(at, into)
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
