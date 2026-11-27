use debar_platform::input::InputError;

use crate::mail::header_text::field;
use crate::mail::line_decoding::uudecoded_line;
use crate::mail::lines::{LineReader, RawLine, Reading, up_to_the_first_nul, without_line_ends};
use crate::object::Object;

const SPACE: &[u8] = b" ";
const MOST_BLANK_LED_LINES_IN_A_ROW: u32 = 256 * 1024;
const UUENCODE_END: &[u8] = b"end";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Storing {
    pub lines: LineSource,
    pub after_a_blank_line: bool,
    pub after_only_blanks_and_semicolons: bool,
    pub drops_leading_header_lines: bool,
    pub blank_led_lines_in_a_row: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LineSource {
    MessageFile,
    TextMessageFile,
    Mailbox,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Stored {
    Dropped,
    Line(Option<Vec<u8>>),
    UuencodedBlock,
    Ended,
}

impl Storing {
    pub const fn reading_headers() -> Self {
        Self {
            lines: LineSource::MessageFile,
            after_a_blank_line: false,
            after_only_blanks_and_semicolons: false,
            drops_leading_header_lines: true,
            blank_led_lines_in_a_row: 0,
        }
    }

    pub const fn reading_a_mailbox_message() -> Self {
        Self {
            lines: LineSource::Mailbox,
            after_a_blank_line: false,
            after_only_blanks_and_semicolons: false,
            drops_leading_header_lines: false,
            blank_led_lines_in_a_row: 0,
        }
    }

    pub fn drops_a_repeated_line_of_blanks_and_semicolons(&mut self, line: &[u8]) -> bool {
        if line.is_empty() {
            return false;
        }
        let only_blanks_and_semicolons =
            line.iter().all(|byte| matches!(byte, b' ' | b'\t' | b';'));
        if !only_blanks_and_semicolons {
            self.after_only_blanks_and_semicolons = false;
            return false;
        }
        if self.after_only_blanks_and_semicolons {
            return true;
        }
        self.after_only_blanks_and_semicolons = true;
        false
    }

    pub fn ends_at_too_many_blank_led_lines(&mut self, line: &[u8]) -> bool {
        let Some(&first) = line.first() else {
            return false;
        };
        if is_c_blank(first) {
            self.blank_led_lines_in_a_row = self.blank_led_lines_in_a_row.saturating_add(1);
        } else {
            self.blank_led_lines_in_a_row = 0;
        }
        self.blank_led_lines_in_a_row >= MOST_BLANK_LED_LINES_IN_A_ROW
    }

    fn stored(&mut self, line: &[u8]) -> Stored {
        if self.lines != LineSource::Mailbox {
            if self.drops_a_repeated_line_of_blanks_and_semicolons(line) {
                return Stored::Dropped;
            }
            if self.ends_at_too_many_blank_led_lines(line) {
                return Stored::Ended;
            }
        }
        if is_uuencode_begin(line) {
            self.drops_leading_header_lines = false;
            if field(line, 2, b" ").is_some() {
                return Stored::UuencodedBlock;
            }
            return Stored::Line(Some(line.to_vec()));
        }
        if line.is_empty() {
            if self.after_a_blank_line && self.lines != LineSource::TextMessageFile {
                return Stored::Dropped;
            }
            self.after_a_blank_line = true;
            return Stored::Line(None);
        }
        if self.drops_leading_header_lines {
            if line.starts_with(b"Message-Id: ") || line.starts_with(b"Date: ") {
                return Stored::Dropped;
            }
            self.drops_leading_header_lines = false;
        }
        self.after_a_blank_line = false;
        if line.iter().all(|byte| is_c_space(*byte)) {
            return Stored::Line(Some(SPACE.to_vec()));
        }
        Stored::Line(Some(line.to_vec()))
    }
}

pub fn is_uuencode_begin(line: &[u8]) -> bool {
    line.len() >= 10
        && line.first() == Some(&b'b')
        && line
            .get(..6)
            .is_some_and(|begin| begin.eq_ignore_ascii_case(b"begin "))
        && line
            .get(6..9)
            .is_some_and(|mode| mode.iter().all(u8::is_ascii_digit))
        && line.get(9) == Some(&b' ')
}

pub const fn is_c_space(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r')
}

pub const fn is_c_blank(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t')
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Mark {
    pub position: u64,
    pub storing: Storing,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Span {
    pub from: Mark,
    pub to: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredLine {
    pub mark: Mark,
    pub after: u64,
    pub text: Option<Vec<u8>>,
}

impl StoredLine {
    pub fn text(&self) -> &[u8] {
        self.text.as_deref().unwrap_or_default()
    }
}

pub struct StoredLines<'o> {
    reader: LineReader<'o>,
    storing: Storing,
    ended: bool,
    peeked: Option<StoredLine>,
    uuencoded_blocks: Vec<u64>,
}

impl<'o> StoredLines<'o> {
    pub fn new(object: &Object<'o>, span: Span, reading: Reading) -> Self {
        Self {
            reader: LineReader::new(object, span.from.position, span.to, reading),
            storing: span.from.storing,
            ended: false,
            peeked: None,
            uuencoded_blocks: Vec::new(),
        }
    }

    pub fn next_line(&mut self) -> Result<Option<StoredLine>, InputError> {
        if let Some(peeked) = self.peeked.take() {
            return Ok(Some(peeked));
        }
        self.read_line()
    }

    pub fn peek(&mut self) -> Result<Option<&StoredLine>, InputError> {
        if self.peeked.is_none() {
            self.peeked = self.read_line()?;
        }
        Ok(self.peeked.as_ref())
    }

    pub fn take_uuencoded_blocks(&mut self) -> Vec<u64> {
        std::mem::take(&mut self.uuencoded_blocks)
    }

    fn read_line(&mut self) -> Result<Option<StoredLine>, InputError> {
        while !self.ended {
            let mark = Mark {
                position: self.reader.position(),
                storing: self.storing,
            };
            let read = if self.storing.lines == LineSource::Mailbox {
                self.reader
                    .next_line_up_to_a_line_feed()?
                    .map(|raw| RawLine {
                        text: without_line_ends(up_to_the_first_nul(&raw.text)).to_vec(),
                        ..raw
                    })
            } else {
                self.reader.next_line()?
            };
            let Some(RawLine { text, .. }) = read else {
                return Ok(None);
            };
            match self.storing.stored(&text) {
                Stored::Dropped => {}
                Stored::Ended => self.ended = true,
                Stored::UuencodedBlock => {
                    self.uuencoded_blocks.push(self.reader.position());
                    skip_uuencoded_block(&mut self.reader)?;
                }
                Stored::Line(text) => {
                    return Ok(Some(StoredLine {
                        mark,
                        after: self.reader.position(),
                        text,
                    }));
                }
            }
        }
        Ok(None)
    }
}

pub fn next_uudecoded_line(
    reader: &mut LineReader<'_>,
    out: &mut Vec<u8>,
) -> Result<bool, InputError> {
    let Some(raw) = reader.next_line_up_to_a_line_feed()? else {
        return Ok(false);
    };
    let line = without_line_ends(up_to_the_first_nul(&raw.text));
    if line.eq_ignore_ascii_case(UUENCODE_END) || line.is_empty() || is_uuencode_begin(line) {
        return Ok(false);
    }
    Ok(uudecoded_line(line, out))
}

fn skip_uuencoded_block(reader: &mut LineReader<'_>) -> Result<(), InputError> {
    let mut out = Vec::new();
    while next_uudecoded_line(reader, &mut out)? {
        out.clear();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use debar_platform::input::ObjectBytes;

    use super::*;

    fn stored(bytes: &[u8], keeps_blank_runs: bool) -> Vec<Option<Vec<u8>>> {
        let object = Object::held(bytes.to_vec());
        let span = Span {
            from: Mark {
                position: 0,
                storing: Storing {
                    lines: if keeps_blank_runs {
                        LineSource::TextMessageFile
                    } else {
                        LineSource::MessageFile
                    },
                    ..Storing::reading_headers()
                },
            },
            to: object.length(),
        };
        let mut lines = StoredLines::new(&object, span, Reading::First);
        let mut found = Vec::new();
        while let Some(line) = lines.next_line().unwrap() {
            found.push(line.text);
        }
        found
    }

    #[test]
    fn blank_runs_are_one_line_unless_the_message_is_text() {
        let body = b"a\n\n\n\nb\n";
        assert_eq!(
            stored(body, false),
            [Some(b"a".to_vec()), None, Some(b"b".to_vec())]
        );
        assert_eq!(stored(body, true).len(), 5);
    }

    #[test]
    fn a_line_of_whitespace_is_one_space_and_a_second_in_a_row_is_dropped() {
        assert_eq!(
            stored(b"a\n  \t\n \nb\n", false),
            [
                Some(b"a".to_vec()),
                Some(b" ".to_vec()),
                Some(b"b".to_vec())
            ]
        );
    }

    #[test]
    fn leading_message_id_and_date_lines_are_dropped() {
        assert_eq!(
            stored(b"\nDate: x\nMessage-Id: y\nhello\nDate: z\n", false),
            [None, Some(b"hello".to_vec()), Some(b"Date: z".to_vec())]
        );
    }

    #[test]
    fn a_uuencoded_block_is_left_out_up_to_the_line_that_ends_it() {
        assert_eq!(
            stored(b"before\nbegin 644 f.txt\n#86)C\n`\nend\nafter\n", false),
            [
                Some(b"before".to_vec()),
                Some(b"end".to_vec()),
                Some(b"after".to_vec())
            ]
        );
    }
}
