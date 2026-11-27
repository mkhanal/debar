use memchr::{memchr, memmem};

pub trait Searchable {
    fn length(&self) -> u64;

    fn byte(&self, at: u64) -> Option<u8>;

    fn find(&self, needle: &[u8], from: u64, end: u64) -> Option<u64>;

    fn find_byte(&self, byte: u8, from: u64, end: u64) -> Option<u64>;

    fn copy(&self, from: u64, length: u64, into: &mut Vec<u8>);

    fn byte_or_nul(&self, at: u64) -> u8 {
        self.byte(at).unwrap_or(0)
    }
}

impl Searchable for [u8] {
    fn length(&self) -> u64 {
        u64::try_from(self.len()).unwrap_or(u64::MAX)
    }

    fn byte(&self, at: u64) -> Option<u8> {
        self.get(usize::try_from(at).ok()?).copied()
    }

    fn find(&self, needle: &[u8], from: u64, end: u64) -> Option<u64> {
        let range = self.within(from, end)?;
        let found = memmem::find(range, needle)?;
        from.checked_add(u64::try_from(found).ok()?)
    }

    fn find_byte(&self, byte: u8, from: u64, end: u64) -> Option<u64> {
        let range = self.within(from, end)?;
        let found = memchr(byte, range)?;
        from.checked_add(u64::try_from(found).ok()?)
    }

    fn copy(&self, from: u64, length: u64, into: &mut Vec<u8>) {
        if let Some(range) = self.within(from, from.saturating_add(length)) {
            into.extend_from_slice(range);
        }
    }
}

trait Within {
    fn within(&self, from: u64, end: u64) -> Option<&[u8]>;
}

impl Within for [u8] {
    fn within(&self, from: u64, end: u64) -> Option<&[u8]> {
        let end = usize::try_from(end).unwrap_or(usize::MAX).min(self.len());
        self.get(usize::try_from(from).ok()?..end)
    }
}
