use std::cell::RefCell;

use debar_platform::input::{InputError, ObjectBytes};

use crate::object::Object;

const RAW_READ_BYTES: usize = 64 * 1024;
const NORMALISED_WINDOW_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ByteAction {
    Kept,
    Lowercased,
    Whitespace,
    Dropped,
}

const fn action_for(byte: u8) -> ByteAction {
    match byte {
        0x09..=0x0d | b' ' => ByteAction::Whitespace,
        b'A'..=b'Z' => ByteAction::Lowercased,
        0x21..=0x7f => ByteAction::Kept,
        0x00..=0x08 | 0x0e..=0x1f | 0x80..=0xff => ByteAction::Dropped,
    }
}

const LOWERCASE_OFFSET: u8 = b'a' - b'A';

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PieceLength(u64);

impl PieceLength {
    #[must_use]
    pub fn of_raw_bytes(length: u64) -> Option<Self> {
        (length > 0).then_some(Self(length))
    }
}

struct Normaliser {
    actions: [ByteAction; 256],
    piece: PieceLength,
    raw_into_the_piece: u64,
    space_written: bool,
}

impl Normaliser {
    fn new(piece: PieceLength) -> Self {
        Self {
            actions: std::array::from_fn(|byte| {
                u8::try_from(byte).map_or(ByteAction::Dropped, action_for)
            }),
            piece,
            raw_into_the_piece: 0,
            space_written: false,
        }
    }

    fn normalise(&mut self, raw: &[u8], into: &mut Vec<u8>) {
        for &byte in raw {
            if self.raw_into_the_piece == self.piece.0 {
                self.raw_into_the_piece = 0;
                self.space_written = false;
            }
            self.raw_into_the_piece = self.raw_into_the_piece.saturating_add(1);
            match self
                .actions
                .get(usize::from(byte))
                .copied()
                .unwrap_or(ByteAction::Dropped)
            {
                ByteAction::Whitespace => {
                    if !self.space_written {
                        into.push(b' ');
                    }
                    self.space_written = true;
                }
                ByteAction::Lowercased => {
                    self.space_written = false;
                    into.push(byte.saturating_add(LOWERCASE_OFFSET));
                }
                ByteAction::Kept => {
                    self.space_written = false;
                    into.push(byte);
                }
                ByteAction::Dropped => {}
            }
        }
    }
}

pub enum NormalisedText {
    Held(Vec<u8>),
    Measured(u64),
}

pub fn normalise(
    raw: &Object<'_>,
    piece: PieceLength,
    most_held: u64,
) -> Result<NormalisedText, InputError> {
    let mut stream = Stream::new(raw.clone(), piece);
    let mut held = Some(Vec::new());
    let mut measured = 0u64;
    let mut fresh = Vec::with_capacity(RAW_READ_BYTES);
    loop {
        fresh.clear();
        if !stream.next_bytes(&mut fresh, Reread::No)? {
            break;
        }
        measured = measured.saturating_add(fresh.as_slice().length());
        if let Some(bytes) = &mut held {
            if measured > most_held {
                held = None;
            } else {
                bytes.extend_from_slice(&fresh);
            }
        }
    }
    Ok(match held {
        Some(bytes) => NormalisedText::Held(bytes),
        None => NormalisedText::Measured(measured),
    })
}

pub struct Regenerated<'o> {
    raw: Object<'o>,
    piece: PieceLength,
    length: u64,
    reading: RefCell<Reading<'o>>,
}

impl<'o> Regenerated<'o> {
    pub fn new(raw: Object<'o>, piece: PieceLength, length: u64) -> Self {
        let reading = RefCell::new(Reading::from_the_start(&raw, piece));
        Self {
            raw,
            piece,
            length,
            reading,
        }
    }
}

impl ObjectBytes for Regenerated<'_> {
    fn length(&self) -> u64 {
        self.length
    }

    fn read_at(&self, offset: u64, into: &mut [u8]) -> Result<(), InputError> {
        let wanted = into.length();
        let beyond_the_end = |at: u64, wanted: u64| InputError::BeyondTheEnd {
            offset: at,
            wanted,
            length: self.length,
        };
        if offset
            .checked_add(wanted)
            .is_none_or(|end| end > self.length)
        {
            return Err(beyond_the_end(offset, wanted));
        }
        let mut reading = self.reading.borrow_mut();
        if offset < reading.window_start {
            *reading = Reading::from_the_start(&self.raw, self.piece);
        }
        let mut filled = 0usize;
        while let Some(rest) = into.get_mut(filled..).filter(|rest| !rest.is_empty()) {
            let at = offset.saturating_add(filled.length_as_offset());
            let copied = reading.copy_from(at, rest)?;
            if copied == 0 {
                return Err(beyond_the_end(at, rest.length()));
            }
            filled = filled.saturating_add(copied);
        }
        Ok(())
    }
}

trait AsOffset {
    fn length_as_offset(self) -> u64;
}

impl AsOffset for usize {
    fn length_as_offset(self) -> u64 {
        u64::try_from(self).unwrap_or(u64::MAX)
    }
}

struct Reading<'o> {
    stream: Stream<'o>,
    window: Vec<u8>,
    window_start: u64,
}

impl<'o> Reading<'o> {
    fn from_the_start(raw: &Object<'o>, piece: PieceLength) -> Self {
        Self {
            stream: Stream::new(raw.clone(), piece),
            window: Vec::with_capacity(NORMALISED_WINDOW_BYTES),
            window_start: 0,
        }
    }

    fn copy_from(&mut self, at: u64, into: &mut [u8]) -> Result<usize, InputError> {
        loop {
            let window_end = self
                .window_start
                .saturating_add(self.window.len().length_as_offset());
            if at < window_end {
                let skip = usize::try_from(at.saturating_sub(self.window_start)).unwrap_or(0);
                let available = self.window.get(skip..).unwrap_or_default();
                let copied = available.len().min(into.len());
                if let (Some(to), Some(from)) = (into.get_mut(..copied), available.get(..copied)) {
                    to.copy_from_slice(from);
                }
                return Ok(copied);
            }
            self.window.clear();
            self.window_start = window_end;
            if !self.stream.next_bytes(&mut self.window, Reread::Yes)? {
                return Ok(0);
            }
        }
    }
}

#[derive(Clone, Copy)]
enum Reread {
    No,
    Yes,
}

struct Stream<'o> {
    raw: Object<'o>,
    normaliser: Normaliser,
    read: u64,
    buffer: Vec<u8>,
}

impl<'o> Stream<'o> {
    fn new(raw: Object<'o>, piece: PieceLength) -> Self {
        Self {
            raw,
            normaliser: Normaliser::new(piece),
            read: 0,
            buffer: Vec::new(),
        }
    }

    fn next_bytes(&mut self, into: &mut Vec<u8>, reread: Reread) -> Result<bool, InputError> {
        while into.is_empty() {
            let left = self.raw.length().saturating_sub(self.read);
            if left == 0 {
                return Ok(false);
            }
            let take = usize::try_from(left)
                .unwrap_or(usize::MAX)
                .min(RAW_READ_BYTES);
            self.buffer.resize(take, 0);
            match reread {
                Reread::No => self.raw.read_at(self.read, &mut self.buffer)?,
                Reread::Yes => self.raw.read_again_at(self.read, &mut self.buffer)?,
            }
            self.read = self.read.saturating_add(take.length_as_offset());
            self.normaliser.normalise(&self.buffer, into);
        }
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    const PIECE_OF_THE_PINNED_DATABASES: u64 = 132_132;

    fn normalised(raw: &[u8], piece: u64, most_held: u64) -> Vec<u8> {
        let object = Object::held(raw.to_vec());
        let piece = PieceLength::of_raw_bytes(piece).unwrap();
        match normalise(&object, piece, most_held).unwrap() {
            NormalisedText::Held(bytes) => bytes,
            NormalisedText::Measured(length) => {
                let regenerated = Regenerated::new(object, piece, length);
                let mut bytes = vec![0u8; usize::try_from(length).unwrap()];
                regenerated.read_at(0, &mut bytes).unwrap();
                bytes
            }
        }
    }

    #[test]
    fn letters_are_lowercased_whitespace_runs_become_one_space_and_other_bytes_are_dropped() {
        let raw = b"  \x1b\x80 Hello\x08World \x80 \t END\n";
        assert_eq!(
            normalised(raw, PIECE_OF_THE_PINNED_DATABASES, u64::MAX),
            b" helloworld end "
        );
    }

    #[test]
    fn delete_is_kept() {
        assert_eq!(
            normalised(b"ab\x7fcd ef", PIECE_OF_THE_PINNED_DATABASES, u64::MAX),
            b"ab\x7fcd ef"
        );
    }

    #[test]
    fn a_whitespace_run_across_a_piece_boundary_gives_two_spaces() {
        let raw = [vec![b'x'; 132_131], b"  y".to_vec()].concat();
        let text = normalised(&raw, PIECE_OF_THE_PINNED_DATABASES, u64::MAX);
        assert_eq!(text.get(132_130..).unwrap(), b"x  y");
    }

    #[test]
    fn a_whitespace_run_ending_before_a_piece_boundary_gives_one_space() {
        let raw = [vec![b'x'; 132_130], b"  y".to_vec()].concat();
        let text = normalised(&raw, PIECE_OF_THE_PINNED_DATABASES, u64::MAX);
        assert_eq!(text.get(132_129..).unwrap(), b"x y");
    }

    #[test]
    fn regenerated_text_reads_as_the_held_text_does() {
        let raw: Vec<u8> = (0..300_000u32)
            .map(|index| u8::try_from(index.wrapping_mul(2_654_435_761) >> 24).unwrap())
            .collect();
        let held = normalised(&raw, 1_000, u64::MAX);
        let regenerated = normalised(&raw, 1_000, 10);
        assert_eq!(held, regenerated);
    }

    #[test]
    fn regenerated_text_can_be_read_again_from_an_earlier_offset() {
        let raw = b"Some TEXT\twith\t\tTABS ".repeat(20_000);
        let object = Object::held(raw.clone());
        let piece = PieceLength::of_raw_bytes(PIECE_OF_THE_PINNED_DATABASES).unwrap();
        let held = normalised(&raw, PIECE_OF_THE_PINNED_DATABASES, u64::MAX);
        let regenerated = Regenerated::new(object, piece, held.as_slice().length());
        let mut late = [0u8; 16];
        regenerated.read_at(300_000, &mut late).unwrap();
        let mut early = [0u8; 16];
        regenerated.read_at(10, &mut early).unwrap();
        assert_eq!(late, held.get(300_000..300_016).unwrap());
        assert_eq!(early, held.get(10..26).unwrap());
    }
}
