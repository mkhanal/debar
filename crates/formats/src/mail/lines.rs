use debar_platform::input::{InputError, ObjectBytes};

use crate::object::Object;

const MOST_BYTES_A_LINE_READ_TAKES: u64 = 999;
const CHUNK_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reading {
    First,
    Again,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawLine {
    pub start: u64,
    pub text: Vec<u8>,
}

pub struct LineReader<'o> {
    object: Object<'o>,
    reading: Reading,
    at: u64,
    end: u64,
    chunk: Vec<u8>,
    chunk_start: u64,
}

impl<'o> LineReader<'o> {
    pub fn new(object: &Object<'o>, from: u64, to: u64, reading: Reading) -> Self {
        Self {
            object: object.clone(),
            reading,
            at: from,
            end: to.min(object.length()),
            chunk: Vec::new(),
            chunk_start: from,
        }
    }

    pub const fn position(&self) -> u64 {
        self.at
    }

    pub fn byte_at_position(&mut self) -> Result<Option<u8>, InputError> {
        self.byte(self.at)
    }

    pub fn next_line(&mut self) -> Result<Option<RawLine>, InputError> {
        let start = self.at;
        let mut position = start;
        let mut taken = 0u64;
        let mut text = Vec::new();
        let mut anything_kept = false;
        while taken < MOST_BYTES_A_LINE_READ_TAKES {
            let Some(byte) = self.byte(position)? else {
                if !anything_kept {
                    return Ok(None);
                }
                break;
            };
            position = position.saturating_add(1);
            match byte {
                0 => {
                    taken = taken.saturating_add(1);
                }
                b'\n' | b'\r' => {
                    let partner = if byte == b'\n' { b'\r' } else { b'\n' };
                    if self.byte(position)? == Some(partner) {
                        position = position.saturating_add(1);
                    }
                    break;
                }
                other => {
                    anything_kept = true;
                    text.push(other);
                    taken = taken.saturating_add(1);
                }
            }
        }
        self.at = position;
        Ok(Some(RawLine { start, text }))
    }

    pub fn next_line_up_to_a_line_feed(&mut self) -> Result<Option<RawLine>, InputError> {
        let start = self.at;
        let mut position = start;
        let mut taken = Vec::new();
        while u64::try_from(taken.len()).unwrap_or(u64::MAX) < MOST_BYTES_A_LINE_READ_TAKES {
            let Some(byte) = self.byte(position)? else {
                break;
            };
            position = position.saturating_add(1);
            taken.push(byte);
            if byte == b'\n' {
                break;
            }
        }
        if taken.is_empty() {
            return Ok(None);
        }
        self.at = position;
        Ok(Some(RawLine { start, text: taken }))
    }

    fn byte(&mut self, offset: u64) -> Result<Option<u8>, InputError> {
        if offset >= self.end {
            return Ok(None);
        }
        let chunk_end = self
            .chunk_start
            .saturating_add(u64::try_from(self.chunk.len()).unwrap_or(u64::MAX));
        if offset < self.chunk_start || offset >= chunk_end {
            self.fill_from(offset)?;
        }
        let index = usize::try_from(offset.saturating_sub(self.chunk_start)).unwrap_or(usize::MAX);
        Ok(self.chunk.get(index).copied())
    }

    fn fill_from(&mut self, offset: u64) -> Result<(), InputError> {
        let wanted = self
            .end
            .saturating_sub(offset)
            .min(u64::try_from(CHUNK_BYTES).unwrap_or(u64::MAX));
        self.chunk
            .resize(usize::try_from(wanted).unwrap_or(CHUNK_BYTES), 0);
        match self.reading {
            Reading::First => self.object.read_at(offset, &mut self.chunk)?,
            Reading::Again => self.object.read_again_at(offset, &mut self.chunk)?,
        }
        self.chunk_start = offset;
        Ok(())
    }
}

pub fn without_line_ends(text: &[u8]) -> &[u8] {
    let kept = text
        .iter()
        .rposition(|byte| *byte != b'\n' && *byte != b'\r')
        .map_or(0, |last| last.saturating_add(1));
    text.get(..kept).unwrap_or_default()
}

pub fn up_to_the_first_nul(text: &[u8]) -> &[u8] {
    let kept = text
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(text.len());
    text.get(..kept).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]

    use super::*;

    fn lines_of(bytes: &[u8]) -> Vec<Vec<u8>> {
        let object = Object::held(bytes.to_vec());
        let mut reader = LineReader::new(&object, 0, object.length(), Reading::First);
        let mut lines = Vec::new();
        while let Some(line) = reader.next_line().unwrap() {
            lines.push(line.text);
        }
        lines
    }

    #[test]
    fn each_of_the_four_line_ends_ends_one_line() {
        assert_eq!(
            lines_of(b"a\nb\r\nc\rd\n\re\r\r\nf"),
            [
                b"a".to_vec(),
                b"b".to_vec(),
                b"c".to_vec(),
                b"d".to_vec(),
                b"e".to_vec(),
                b"".to_vec(),
                b"f".to_vec()
            ]
        );
    }

    #[test]
    fn a_nul_is_dropped_but_counts_toward_the_longest_line() {
        let mut long = vec![0u8; 3];
        long.extend(vec![b'x'; 996]);
        long.extend_from_slice(b"\nz");
        let lines = lines_of(&long);
        assert_eq!(lines[0].len(), 996);
        assert_eq!(lines[1], b"");
        assert_eq!(lines[2], b"z");
    }

    #[test]
    fn a_line_of_only_nuls_at_the_end_is_no_line() {
        assert_eq!(lines_of(b"a\n\0\0"), [b"a".to_vec()]);
    }
}
