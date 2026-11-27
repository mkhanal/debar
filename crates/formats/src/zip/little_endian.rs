use debar_platform::input::{InputError, ObjectBytes};

pub struct Fields<'b> {
    bytes: &'b [u8],
}

impl<'b> Fields<'b> {
    pub const fn of(bytes: &'b [u8]) -> Self {
        Self { bytes }
    }

    pub fn u16_at(&self, at: usize) -> u16 {
        let mut field = [0u8; 2];
        if let Some(found) = at.checked_add(2).and_then(|end| self.bytes.get(at..end)) {
            field.copy_from_slice(found);
        }
        u16::from_le_bytes(field)
    }

    pub fn u32_at(&self, at: usize) -> u32 {
        let mut field = [0u8; 4];
        if let Some(found) = at.checked_add(4).and_then(|end| self.bytes.get(at..end)) {
            field.copy_from_slice(found);
        }
        u32::from_le_bytes(field)
    }
}

pub fn read_within(
    object: &dyn ObjectBytes,
    offset: u64,
    length: u64,
) -> Result<Option<Vec<u8>>, InputError> {
    let Some(end) = offset.checked_add(length) else {
        return Ok(None);
    };
    if end > object.length() {
        return Ok(None);
    }
    let Ok(length) = usize::try_from(length) else {
        return Ok(None);
    };
    let mut bytes = vec![0u8; length];
    object.read_at(offset, &mut bytes)?;
    Ok(Some(bytes))
}
