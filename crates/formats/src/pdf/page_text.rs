use debar_platform::input::InputError;

use crate::pdf::pulled::Pull;

pub const READ_IN_BLOCKS_OF: usize = 8192;
const NORMALISED_IN_BUFFERS_OF: usize = 8192;
const LOWER_CASE_DISTANCE: u8 = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Within {
    Lines,
    TextArray,
    TextString,
}

pub struct PageText {
    within: Within,
    buffer: Vec<u8>,
    space_written: bool,
}

impl PageText {
    pub fn new() -> Self {
        Self {
            within: Within::Lines,
            buffer: Vec::with_capacity(NORMALISED_IN_BUFFERS_OF),
            space_written: false,
        }
    }

    pub fn block(&mut self, block: &[u8], written: &mut Vec<u8>) {
        let mut at = 0usize;
        while let Some(byte) = block.get(at).copied() {
            match self.within {
                Within::Lines => {
                    if byte == b'[' {
                        self.within = Within::TextArray;
                    } else {
                        let rest = block.get(at..).unwrap_or_default();
                        let Some(line_end) = memchr::memchr(b'\n', rest) else {
                            return;
                        };
                        at = at.saturating_add(line_end);
                    }
                }
                Within::TextArray => {
                    if byte == b'(' {
                        self.within = Within::TextString;
                    }
                }
                Within::TextString => {
                    if byte == b')' {
                        self.within = Within::TextArray;
                    } else {
                        self.normalise(byte, written);
                    }
                }
            }
            at = at.saturating_add(1);
        }
    }

    pub fn finish(&mut self, written: &mut Vec<u8>) {
        written.append(&mut self.buffer);
    }

    fn normalise(&mut self, byte: u8, written: &mut Vec<u8>) {
        if self.buffer.len() >= NORMALISED_IN_BUFFERS_OF {
            written.append(&mut self.buffer);
            self.space_written = false;
            return;
        }
        match byte {
            b'\t' | b'\n' | 0x0b | 0x0c | b'\r' | b' ' => {
                if !self.space_written {
                    self.buffer.push(b' ');
                }
                self.space_written = true;
            }
            b'A'..=b'Z' => {
                self.space_written = false;
                self.buffer.push(byte.saturating_add(LOWER_CASE_DISTANCE));
            }
            0x21..=0x7f => {
                self.space_written = false;
                self.buffer.push(byte);
            }
            _ => {}
        }
    }
}

pub fn page_text_of(bytes: &[u8]) -> Vec<u8> {
    let mut text = PageText::new();
    let mut written = Vec::new();
    for block in bytes.chunks(READ_IN_BLOCKS_OF) {
        text.block(block, &mut written);
    }
    text.finish(&mut written);
    written
}

pub struct PageTextOf<'a> {
    source: Box<dyn Pull + 'a>,
    text: PageText,
    unread: Vec<u8>,
    source_finished: bool,
    finished: bool,
}

impl<'a> PageTextOf<'a> {
    pub fn new(source: Box<dyn Pull + 'a>) -> Self {
        Self {
            source,
            text: PageText::new(),
            unread: Vec::new(),
            source_finished: false,
            finished: false,
        }
    }
}

impl Pull for PageTextOf<'_> {
    fn pull(&mut self, into: &mut Vec<u8>) -> Result<bool, InputError> {
        let before = into.len();
        while into.len() == before && !self.finished {
            while self.unread.len() < READ_IN_BLOCKS_OF && !self.source_finished {
                if !self.source.pull(&mut self.unread)? {
                    self.source_finished = true;
                }
            }
            if self.unread.is_empty() {
                self.text.finish(into);
                self.finished = true;
                break;
            }
            let taken = self.unread.len().min(READ_IN_BLOCKS_OF);
            let block: Vec<u8> = self.unread.drain(..taken).collect();
            self.text.block(&block, into);
        }
        Ok(into.len() > before)
    }
}
