use std::cell::RefCell;

use debar_platform::input::{InputError, ObjectBytes};

use crate::mail::headers::TransferEncoding;
use crate::mail::line_decoding::{
    Base64Carry, as_written, base64, base64_flush, is_yenc_end, quoted_printable, yenc,
};
use crate::mail::lines::{LineReader, Reading, up_to_the_first_nul};
use crate::mail::stored::{Mark, Span, StoredLines, next_uudecoded_line};
use crate::object::Object;

const BOUNCE_HEADER: &[u8] = b"Received: by clamd (bounce)\n";
const PIECE_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decoding {
    AsWritten,
    QuotedPrintable,
    Base64,
    YEnc,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum YencStart {
    AfterTheLastLine,
    At(Mark),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TextSegment {
    AsWritten {
        lines: Span,
    },
    Decoded {
        lines: Span,
        encodings: Vec<TransferEncoding>,
        yenc_from: Option<YencStart>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Output {
    Lines { lines: Span, decoding: Decoding },
    Bounce { lines: Span },
    TextPart { segments: Vec<TextSegment> },
    Uudecoded { from: u64 },
}

pub enum Produced {
    Held(Vec<u8>),
    Measured(u64),
}

pub fn produce(
    object: &Object<'_>,
    output: &Output,
    most_held: u64,
) -> Result<Produced, InputError> {
    let mut stream = OutputStream::new(object, output.clone(), Reading::Again);
    let mut held = Some(Vec::new());
    let mut length = 0u64;
    let mut piece = Vec::new();
    while stream.next_piece(&mut piece)? {
        length = length.saturating_add(piece.as_slice().length());
        if let Some(bytes) = &mut held {
            if length > most_held {
                held = None;
            } else {
                bytes.extend_from_slice(&piece);
            }
        }
        piece.clear();
    }
    Ok(match held {
        Some(bytes) => Produced::Held(bytes),
        None => Produced::Measured(length),
    })
}

pub struct Regenerated<'o> {
    object: Object<'o>,
    output: Output,
    length: u64,
    reading: RefCell<Window<'o>>,
}

struct Window<'o> {
    stream: OutputStream<'o>,
    bytes: Vec<u8>,
    start: u64,
}

impl<'o> Regenerated<'o> {
    pub fn new(object: Object<'o>, output: Output, length: u64) -> Self {
        let reading = RefCell::new(Window::from_the_start(&object, &output));
        Self {
            object,
            output,
            length,
            reading,
        }
    }
}

impl<'o> Window<'o> {
    fn from_the_start(object: &Object<'o>, output: &Output) -> Self {
        Self {
            stream: OutputStream::new(object, output.clone(), Reading::Again),
            bytes: Vec::new(),
            start: 0,
        }
    }

    fn end(&self) -> u64 {
        self.start.saturating_add(self.bytes.as_slice().length())
    }

    fn copy_from(&mut self, at: u64, into: &mut [u8]) -> Result<usize, InputError> {
        loop {
            if at >= self.start && at < self.end() {
                let skip = usize::try_from(at.saturating_sub(self.start)).unwrap_or(usize::MAX);
                let available = self.bytes.get(skip..).unwrap_or_default();
                let copied = available.len().min(into.len());
                if let (Some(to), Some(from)) = (into.get_mut(..copied), available.get(..copied)) {
                    to.copy_from_slice(from);
                }
                return Ok(copied);
            }
            let next_start = self.end();
            self.bytes.clear();
            while self.bytes.len() < PIECE_BYTES {
                let mut piece = Vec::new();
                if !self.stream.next_piece(&mut piece)? {
                    break;
                }
                self.bytes.extend_from_slice(&piece);
            }
            self.start = next_start;
            if self.bytes.is_empty() {
                return Ok(0);
            }
        }
    }
}

impl ObjectBytes for Regenerated<'_> {
    fn length(&self) -> u64 {
        self.length
    }

    fn read_at(&self, offset: u64, into: &mut [u8]) -> Result<(), InputError> {
        let wanted = into.length();
        let beyond = |offset| InputError::BeyondTheEnd {
            offset,
            wanted,
            length: self.length,
        };
        if offset
            .checked_add(wanted)
            .is_none_or(|end| end > self.length)
        {
            return Err(beyond(offset));
        }
        let mut reading = self.reading.borrow_mut();
        if offset < reading.start {
            *reading = Window::from_the_start(&self.object, &self.output);
        }
        let mut filled = 0usize;
        while let Some(rest) = into.get_mut(filled..).filter(|rest| !rest.is_empty()) {
            let at = offset.saturating_add(u64::try_from(filled).unwrap_or(u64::MAX));
            let copied = reading.copy_from(at, rest)?;
            if copied == 0 {
                return Err(beyond(at));
            }
            filled = filled.saturating_add(copied);
        }
        Ok(())
    }
}

struct OutputStream<'o> {
    object: Object<'o>,
    reading: Reading,
    pending: Vec<Source>,
    current: Option<Running<'o>>,
}

enum Source {
    Fixed(&'static [u8]),
    Lines(Span, LineRule),
    Uudecoded(u64),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LineRule {
    Exported(Decoding),
    AsText(TextRule),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TextRule {
    Copied,
    Decoded(Decoding),
}

enum Running<'o> {
    Lines {
        lines: StoredLines<'o>,
        rule: LineRule,
        carry: Base64Carry,
        finished: bool,
    },
    Uudecoded {
        reader: LineReader<'o>,
        finished: bool,
    },
}

impl<'o> OutputStream<'o> {
    fn new(object: &Object<'o>, output: Output, reading: Reading) -> Self {
        let mut pending = Vec::new();
        match output {
            Output::Lines { lines, decoding } => {
                pending.push(Source::Lines(lines, LineRule::Exported(decoding)));
            }
            Output::Bounce { lines } => {
                pending.push(Source::Fixed(BOUNCE_HEADER));
                pending.push(Source::Lines(
                    lines,
                    LineRule::Exported(Decoding::AsWritten),
                ));
            }
            Output::TextPart { segments } => {
                for segment in segments {
                    push_text_segment(&mut pending, segment);
                }
            }
            Output::Uudecoded { from } => pending.push(Source::Uudecoded(from)),
        }
        pending.reverse();
        Self {
            object: object.clone(),
            reading,
            pending,
            current: None,
        }
    }

    fn next_piece(&mut self, piece: &mut Vec<u8>) -> Result<bool, InputError> {
        loop {
            if let Some(running) = &mut self.current {
                if running.next_piece(piece)? {
                    return Ok(true);
                }
                self.current = None;
            }
            let Some(source) = self.pending.pop() else {
                return Ok(false);
            };
            match source {
                Source::Fixed(bytes) => {
                    piece.extend_from_slice(bytes);
                    return Ok(true);
                }
                Source::Lines(span, rule) => {
                    self.current = Some(Running::Lines {
                        lines: StoredLines::new(&self.object, span, self.reading),
                        rule,
                        carry: Base64Carry::default(),
                        finished: false,
                    });
                }
                Source::Uudecoded(from) => {
                    let reader =
                        LineReader::new(&self.object, from, self.object.length(), self.reading);
                    self.current = Some(Running::Uudecoded {
                        reader,
                        finished: false,
                    });
                }
            }
        }
    }
}

fn push_text_segment(pending: &mut Vec<Source>, segment: TextSegment) {
    match segment {
        TextSegment::AsWritten { lines } => {
            pending.push(Source::Lines(lines, LineRule::AsText(TextRule::Copied)));
        }
        TextSegment::Decoded {
            lines,
            encodings,
            yenc_from,
        } => {
            if encodings.contains(&TransferEncoding::Uuencode) {
                return;
            }
            if encodings.contains(&TransferEncoding::Yencode) && yenc_from.is_none() {
                return;
            }
            for encoding in encodings {
                let rule = match encoding {
                    TransferEncoding::AsWritten
                    | TransferEncoding::Binary
                    | TransferEncoding::EightBit => TextRule::Copied,
                    TransferEncoding::QuotedPrintable => {
                        TextRule::Decoded(Decoding::QuotedPrintable)
                    }
                    TransferEncoding::Base64 => TextRule::Decoded(Decoding::Base64),
                    TransferEncoding::Binhex | TransferEncoding::Uuencode => {
                        TextRule::Decoded(Decoding::AsWritten)
                    }
                    TransferEncoding::Yencode => TextRule::Decoded(Decoding::YEnc),
                };
                let from = match (encoding, yenc_from) {
                    (TransferEncoding::Yencode, Some(YencStart::At(from))) => from,
                    (TransferEncoding::Yencode, _) => continue,
                    _ => lines.from,
                };
                pending.push(Source::Lines(
                    Span { from, to: lines.to },
                    LineRule::AsText(rule),
                ));
            }
        }
    }
}

impl Running<'_> {
    fn next_piece(&mut self, piece: &mut Vec<u8>) -> Result<bool, InputError> {
        match self {
            Running::Lines {
                lines,
                rule,
                carry,
                finished,
            } => loop {
                if *finished {
                    return Ok(false);
                }
                let Some(line) = lines.next_line()? else {
                    *finished = true;
                    finish(*rule, carry, piece);
                    return Ok(!piece.is_empty());
                };
                if line_piece(*rule, line.text.as_deref(), carry, piece) == Flow::Stop {
                    *finished = true;
                    finish(*rule, carry, piece);
                    return Ok(!piece.is_empty());
                }
                if !piece.is_empty() {
                    return Ok(true);
                }
            },
            Running::Uudecoded { reader, finished } => {
                if *finished {
                    return Ok(false);
                }
                if !next_uudecoded_line(reader, piece)? {
                    *finished = true;
                    return Ok(false);
                }
                Ok(true)
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Flow {
    Going,
    Stop,
}

fn line_piece(
    rule: LineRule,
    line: Option<&[u8]>,
    carry: &mut Base64Carry,
    piece: &mut Vec<u8>,
) -> Flow {
    match rule {
        LineRule::Exported(Decoding::AsWritten) | LineRule::AsText(TextRule::Copied) => {
            as_written(line, piece);
        }
        LineRule::Exported(Decoding::QuotedPrintable) => quoted_printable(line, piece),
        LineRule::Exported(Decoding::Base64) => base64(line, carry, piece),
        LineRule::Exported(Decoding::YEnc) => {
            if line.is_none() {
                return Flow::Going;
            }
            if is_yenc_end(line) {
                return Flow::Stop;
            }
            yenc(line, piece);
        }
        LineRule::AsText(TextRule::Decoded(decoding)) => {
            return text_line(decoding, line, carry, piece);
        }
    }
    Flow::Going
}

fn text_line(
    decoding: Decoding,
    line: Option<&[u8]>,
    carry: &mut Base64Carry,
    piece: &mut Vec<u8>,
) -> Flow {
    if decoding == Decoding::Base64 && line.is_none() {
        return Flow::Going;
    }
    let mut decoded = Vec::new();
    match decoding {
        Decoding::AsWritten => as_written(line, &mut decoded),
        Decoding::QuotedPrintable => quoted_printable(line, &mut decoded),
        Decoding::Base64 => base64(line, carry, &mut decoded),
        Decoding::YEnc => {
            if !is_yenc_end(line) {
                yenc(line, &mut decoded);
            }
        }
    }
    let decoded = up_to_the_first_nul(&decoded);
    match (decoded.first(), line) {
        (None | Some(b'\n'), _) => {}
        (_, Some(original)) if decoded.starts_with(original) => piece.extend_from_slice(original),
        _ => piece.extend_from_slice(decoded),
    }
    piece.push(b'\n');
    let ends_the_text =
        decoding == Decoding::Base64 && line.is_some_and(|original| original.contains(&b'='));
    if ends_the_text {
        Flow::Stop
    } else {
        Flow::Going
    }
}

fn finish(rule: LineRule, carry: &mut Base64Carry, piece: &mut Vec<u8>) {
    match rule {
        LineRule::Exported(Decoding::Base64) => base64_flush(carry, piece),
        LineRule::AsText(TextRule::Decoded(Decoding::Base64)) => {
            let mut flushed = Vec::new();
            base64_flush(carry, &mut flushed);
            let flushed = up_to_the_first_nul(&flushed);
            if !flushed.is_empty() {
                piece.extend_from_slice(flushed);
                piece.push(b'\n');
            }
        }
        LineRule::Exported(_) | LineRule::AsText(_) => {}
    }
}
