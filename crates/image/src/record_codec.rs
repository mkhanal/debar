#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecordMalformed;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecordTooLarge;

#[derive(Default)]
pub struct RecordWriter {
    bytes: Vec<u8>,
    count: u32,
}

impl RecordWriter {
    pub fn record(&mut self, fields: &RecordFields) -> Result<(), RecordTooLarge> {
        let length = u32::try_from(fields.bytes.len()).map_err(|_| RecordTooLarge)?;
        self.bytes.extend_from_slice(&length.to_le_bytes());
        self.bytes.extend_from_slice(&fields.bytes);
        self.count = self.count.checked_add(1).ok_or(RecordTooLarge)?;
        Ok(())
    }

    #[must_use]
    pub fn finish(self) -> Vec<u8> {
        let mut bytes = self.count.to_le_bytes().to_vec();
        bytes.extend(self.bytes);
        bytes
    }
}

#[derive(Default)]
pub struct RecordFields {
    bytes: Vec<u8>,
}

impl RecordFields {
    pub fn byte(&mut self, value: u8) -> &mut Self {
        self.bytes.push(value);
        self
    }

    pub fn flag(&mut self, value: bool) -> &mut Self {
        self.byte(u8::from(value))
    }

    pub fn u16(&mut self, value: u16) -> &mut Self {
        self.bytes.extend_from_slice(&value.to_le_bytes());
        self
    }

    pub fn u32(&mut self, value: u32) -> &mut Self {
        self.bytes.extend_from_slice(&value.to_le_bytes());
        self
    }

    pub fn u64(&mut self, value: u64) -> &mut Self {
        self.bytes.extend_from_slice(&value.to_le_bytes());
        self
    }

    pub fn i64(&mut self, value: i64) -> &mut Self {
        self.bytes.extend_from_slice(&value.to_le_bytes());
        self
    }

    pub fn bytes(&mut self, value: &[u8]) -> Result<&mut Self, RecordTooLarge> {
        let length = u32::try_from(value.len()).map_err(|_| RecordTooLarge)?;
        self.u32(length);
        self.bytes.extend_from_slice(value);
        Ok(self)
    }

    pub fn count_of(&mut self, length: usize) -> Result<&mut Self, RecordTooLarge> {
        let length = u32::try_from(length).map_err(|_| RecordTooLarge)?;
        Ok(self.u32(length))
    }
}

#[derive(Clone, Copy)]
pub struct Records<'m> {
    count: u32,
    rest: &'m [u8],
}

impl<'m> Records<'m> {
    pub fn read(bytes: &'m [u8]) -> Result<Self, RecordMalformed> {
        let (count, rest) = bytes.split_first_chunk::<4>().ok_or(RecordMalformed)?;
        Ok(Self {
            count: u32::from_le_bytes(*count),
            rest,
        })
    }

    #[must_use]
    pub fn record_count(&self) -> u32 {
        self.count
    }
}

impl<'m> Records<'m> {
    pub fn each(self) -> impl Iterator<Item = Result<FieldReader<'m>, RecordMalformed>> {
        let mut records = self;
        std::iter::from_fn(move || records.next_record())
    }

    fn next_record(&mut self) -> Option<Result<FieldReader<'m>, RecordMalformed>> {
        if self.count == 0 {
            return None;
        }
        self.count = self.count.saturating_sub(1);
        let mut reader = FieldReader { rest: self.rest };
        let record = reader.length().and_then(|length| {
            let (record, after) = self
                .rest
                .get(4..)
                .and_then(|rest| rest.split_at_checked(length))
                .ok_or(RecordMalformed)?;
            self.rest = after;
            Ok(FieldReader { rest: record })
        });
        if record.is_err() {
            self.count = 0;
        }
        Some(record)
    }
}

pub struct FieldReader<'m> {
    rest: &'m [u8],
}

impl<'m> FieldReader<'m> {
    fn take<const N: usize>(&mut self) -> Result<[u8; N], RecordMalformed> {
        let (value, rest) = self.rest.split_first_chunk::<N>().ok_or(RecordMalformed)?;
        self.rest = rest;
        Ok(*value)
    }

    pub fn byte(&mut self) -> Result<u8, RecordMalformed> {
        self.take::<1>().map(|[value]| value)
    }

    pub fn flag(&mut self) -> Result<bool, RecordMalformed> {
        match self.byte()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(RecordMalformed),
        }
    }

    pub fn u16(&mut self) -> Result<u16, RecordMalformed> {
        self.take().map(u16::from_le_bytes)
    }

    pub fn u32(&mut self) -> Result<u32, RecordMalformed> {
        self.take().map(u32::from_le_bytes)
    }

    pub fn u64(&mut self) -> Result<u64, RecordMalformed> {
        self.take().map(u64::from_le_bytes)
    }

    pub fn i64(&mut self) -> Result<i64, RecordMalformed> {
        self.take().map(i64::from_le_bytes)
    }

    fn length(&mut self) -> Result<usize, RecordMalformed> {
        let length = self.u32()?;
        usize::try_from(length).map_err(|_| RecordMalformed)
    }

    pub fn bytes(&mut self) -> Result<&'m [u8], RecordMalformed> {
        let length = self.length()?;
        let (value, rest) = self.rest.split_at_checked(length).ok_or(RecordMalformed)?;
        self.rest = rest;
        Ok(value)
    }

    pub fn text(&mut self) -> Result<&'m str, RecordMalformed> {
        std::str::from_utf8(self.bytes()?).map_err(|_| RecordMalformed)
    }

    pub fn count(&mut self, each_at_least: usize) -> Result<usize, RecordMalformed> {
        let count = self.length()?;
        if count.saturating_mul(each_at_least.max(1)) > self.rest.len() {
            return Err(RecordMalformed);
        }
        Ok(count)
    }

    pub fn finish(&self) -> Result<(), RecordMalformed> {
        if self.rest.is_empty() {
            Ok(())
        } else {
            Err(RecordMalformed)
        }
    }
}
