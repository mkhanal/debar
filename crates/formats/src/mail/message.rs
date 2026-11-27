use debar_platform::input::{InputError, ObjectBytes};

use crate::mail::boundaries::is_boundary_start;
use crate::mail::header_text::{field, without_comments_or_as_is, without_trailing_unprintables};
use crate::mail::headers::{HeaderLine, MediaType, PartHeaders, content_header};
use crate::mail::lines::{LineReader, Reading, up_to_the_first_nul, without_line_ends};
use crate::mail::stored::{
    LineSource, Mark, Span, StoredLine, StoredLines, Storing, is_c_blank, is_c_space,
    is_uuencode_begin, next_uudecoded_line,
};
use crate::object::Object;

const MOST_HEADER_BYTES: usize = 256 * 1024;
const MOST_HEADERS: usize = 1024;
const MBOX_SEPARATOR: &[u8] = b"From ";
const COMMUNIGATE_PREFIX: &[u8] = b"P I ";
const HEADERS_THAT_MAKE_A_MESSAGE: [&[u8]; 3] = [b"From", b"Received", b"De"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Markers {
    FromEveryLine,
    AfterTheFirstLine,
    None,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    pub headers: PartHeaders,
    pub body: Option<Span>,
    pub markers: Markers,
}

pub enum Opened {
    Nothing,
    Mailbox(Vec<Separator>),
    Message(Message),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Separator {
    pub start: u64,
    pub end: u64,
}

pub fn open_message_file(object: &Object<'_>) -> Result<Opened, InputError> {
    let mut reader = LineReader::new(object, 0, object.length(), Reading::First);
    let Some(first) = reader.next_line_up_to_a_line_feed()? else {
        return Ok(Opened::Nothing);
    };
    if first.text.starts_with(MBOX_SEPARATOR) {
        return Ok(Opened::Mailbox(mailbox_separators(object)?));
    }
    let mut first_line = FirstLine::UpToALineFeed(first.text);
    if first_line.raw().starts_with(COMMUNIGATE_PREFIX) {
        while let Some(next) = reader.next_line_up_to_a_line_feed()? {
            first_line = FirstLine::UpToALineFeed(next.text);
            if first_line.is_blank() {
                break;
            }
        }
    }
    while first_line.is_blank() {
        let Some(next) = reader.next_line()? else {
            break;
        };
        first_line = FirstLine::Ended(next.text);
    }
    let mut reading = TopHeaders::new(object.length());
    let mut line = first_line.text();
    loop {
        let start = reader.position();
        if let HeaderStep::Ended(found) = reading.read(&line, start, &mut reader)? {
            return Ok(found.map_or(Opened::Nothing, Opened::Message));
        }
        let Some(next) = reader.next_line()? else {
            return Ok(reading.finished().map_or(Opened::Nothing, Opened::Message));
        };
        line = next.text;
    }
}

fn mailbox_separators(object: &Object<'_>) -> Result<Vec<Separator>, InputError> {
    let mut reader = LineReader::new(object, 0, object.length(), Reading::First);
    let mut separators = Vec::new();
    let mut after_an_empty_line = false;
    while let Some(raw) = reader.next_line_up_to_a_line_feed()? {
        let line = without_line_ends(up_to_the_first_nul(&raw.text));
        if after_an_empty_line && line.starts_with(MBOX_SEPARATOR) {
            separators.push(Separator {
                start: raw.start,
                end: reader.position(),
            });
            continue;
        }
        after_an_empty_line = line.is_empty();
        if is_uuencode_begin(line) && field(line, 2, b" ").is_some() {
            let mut decoded = Vec::new();
            while next_uudecoded_line(&mut reader, &mut decoded)? {
                decoded.clear();
            }
        }
    }
    Ok(separators)
}

enum FirstLine {
    UpToALineFeed(Vec<u8>),
    Ended(Vec<u8>),
}

impl FirstLine {
    fn raw(&self) -> &[u8] {
        match self {
            Self::UpToALineFeed(raw) | Self::Ended(raw) => raw,
        }
    }

    fn is_blank(&self) -> bool {
        match self {
            Self::UpToALineFeed(raw) => matches!(raw.first(), Some(b'\r' | b'\n' | 0) | None),
            Self::Ended(text) => text.is_empty(),
        }
    }

    fn text(&self) -> Vec<u8> {
        match self {
            Self::UpToALineFeed(raw) => without_line_ends(up_to_the_first_nul(raw)).to_vec(),
            Self::Ended(text) => text.clone(),
        }
    }
}

enum HeaderStep {
    Going,
    Ended(Option<Message>),
}

struct TopHeaders {
    end: u64,
    headers: PartHeaders,
    storing: Storing,
    found_a_header: bool,
    boundary: Option<Vec<u8>>,
    after_a_blank_continuation: bool,
    pending: Vec<u8>,
    header_bytes: usize,
    headers_read: usize,
    started_at: Option<u64>,
}

impl TopHeaders {
    fn new(end: u64) -> Self {
        Self {
            end,
            headers: PartHeaders::default(),
            storing: Storing::reading_headers(),
            found_a_header: false,
            boundary: None,
            after_a_blank_continuation: false,
            pending: Vec::new(),
            header_bytes: 0,
            headers_read: 0,
            started_at: None,
        }
    }

    fn finished(self) -> Option<Message> {
        self.found_a_header.then_some(Message {
            headers: self.headers,
            body: None,
            markers: Markers::FromEveryLine,
        })
    }

    fn with_body_from(self, mark: Mark) -> Option<Message> {
        self.found_a_header.then_some(Message {
            body: Some(Span {
                from: mark,
                to: self.end,
            }),
            headers: self.headers,
            markers: Markers::FromEveryLine,
        })
    }

    fn body_storing(&self, storing: Storing) -> Storing {
        Storing {
            lines: if self.headers.media_type == MediaType::Text {
                LineSource::TextMessageFile
            } else {
                LineSource::MessageFile
            },
            after_a_blank_line: false,
            drops_leading_header_lines: true,
            ..storing
        }
    }

    fn read(
        &mut self,
        line: &[u8],
        end_of_line: u64,
        reader: &mut LineReader<'_>,
    ) -> Result<HeaderStep, InputError> {
        let started_at = self.started_at.unwrap_or(0);
        self.started_at = Some(end_of_line);
        let before = self.storing;
        if self
            .storing
            .drops_a_repeated_line_of_blanks_and_semicolons(line)
        {
            return Ok(HeaderStep::Going);
        }
        if self.storing.ends_at_too_many_blank_led_lines(line) {
            return Ok(HeaderStep::Ended(self.take().finished()));
        }
        if self.after_a_blank_continuation {
            self.after_a_blank_continuation = false;
            if is_boundary_start(line, self.boundary.as_deref()) {
                let storing = self.body_storing(before);
                let mark = Mark {
                    position: started_at,
                    storing,
                };
                return Ok(HeaderStep::Ended(self.take().with_body_from(mark)));
            }
        }
        if line.first().is_some_and(|first| is_c_space(*first))
            && without_trailing_unprintables(line).is_empty()
            && let Some(step) = self.blank_continuation()
        {
            return Ok(step);
        }
        if line.is_empty() && self.pending.is_empty() {
            if !self.found_a_header {
                return Ok(HeaderStep::Going);
            }
            let storing = self.body_storing(self.storing);
            let mark = Mark {
                position: end_of_line,
                storing,
            };
            return Ok(HeaderStep::Ended(self.take().with_body_from(mark)));
        }
        if self.pending.is_empty() {
            if line.first().is_some_and(|first| is_c_blank(*first)) {
                return Ok(HeaderStep::Going);
            }
            let Some(name) = field(line, 0, b":").filter(|_| line.contains(&b':')) else {
                if line.starts_with(MBOX_SEPARATOR) {
                    self.found_a_header = true;
                }
                return Ok(HeaderStep::Going);
            };
            if content_header(&without_comments_or_as_is(name)).is_none() {
                if !self.found_a_header {
                    self.found_a_header = makes_a_message(name);
                }
                return Ok(HeaderStep::Going);
            }
            self.found_a_header = true;
            self.pending.extend_from_slice(line);
        } else {
            self.pending.extend_from_slice(line);
        }
        if !line.is_empty() {
            self.header_bytes = self.header_bytes.saturating_add(line.len());
            if self.header_bytes > MOST_HEADER_BYTES {
                return Ok(HeaderStep::Ended(self.take().finished()));
            }
        }
        if reader.byte_at_position()?.is_some_and(is_c_blank) {
            return Ok(HeaderStep::Going);
        }
        let mut unfinished = self.pending.last() == Some(&b';');
        if !unfinished {
            unfinished = !line.is_empty() && has_an_odd_number_of_quotes(&self.pending);
        }
        if !unfinished {
            self.headers_read = self.headers_read.saturating_add(1);
            if self.headers_read > MOST_HEADERS {
                return Ok(HeaderStep::Ended(self.take().finished()));
            }
            let header = self.pending.clone();
            unfinished = self.headers.read_header_line(&header) == HeaderLine::Unread;
        }
        if !unfinished {
            self.pending.clear();
        }
        Ok(HeaderStep::Going)
    }

    fn blank_continuation(&mut self) -> Option<HeaderStep> {
        if !self.pending.is_empty() {
            let header = std::mem::take(&mut self.pending);
            self.headers_read = self.headers_read.saturating_add(1);
            if self.headers_read > MOST_HEADERS {
                return Some(HeaderStep::Ended(self.take().finished()));
            }
            if self.headers.read_header_line(&header) == HeaderLine::Unread {
                return Some(HeaderStep::Going);
            }
        }
        if self.boundary.is_none() {
            self.boundary = self.headers.parameter(b"boundary");
        }
        if self.boundary.is_some() {
            self.after_a_blank_continuation = true;
            return Some(HeaderStep::Going);
        }
        None
    }

    fn take(&mut self) -> Self {
        std::mem::replace(self, Self::new(self.end))
    }
}

fn makes_a_message(name: &[u8]) -> bool {
    HEADERS_THAT_MAKE_A_MESSAGE
        .iter()
        .any(|known| known.eq_ignore_ascii_case(name))
}

pub fn has_an_odd_number_of_quotes(text: &[u8]) -> bool {
    text.iter().fold(false, |odd, byte| odd ^ (*byte == b'"'))
}

pub fn is_folded_into(current: &[u8], next: Option<&StoredLine>) -> bool {
    let Some(next) = next.and_then(|next| next.text.as_deref()) else {
        return false;
    };
    if next.first().is_some_and(|first| is_c_blank(*first)) {
        return true;
    }
    if !next.contains(&b'=') {
        return false;
    }
    for byte in current.iter().skip(1).rev() {
        match byte {
            b';' => return true,
            b'\n' | b' ' | b'\r' | b'\t' => {}
            _ => return false,
        }
    }
    false
}

pub fn is_a_header_line_in_the_body(line: &[u8]) -> bool {
    line.starts_with(b"Message-Id: ") || line.starts_with(b"Date: ")
}

pub fn read_inner_message(
    object: &Object<'_>,
    body: Span,
    outer_has_markers: bool,
) -> Result<Option<Message>, InputError> {
    let mut lines = StoredLines::new(object, body, Reading::Again);
    let mut storing = Storing::reading_headers();
    let mut headers = PartHeaders::default();
    let mut found_a_header = false;
    let mut in_headers = true;
    let mut pending: Option<Vec<u8>> = None;
    let mut pending_length = 0usize;
    let mut headers_read = 0usize;
    let mut inner_body = None;
    while let Some(line) = lines.next_line()? {
        let text = line.text();
        if storing.drops_a_repeated_line_of_blanks_and_semicolons(text) {
            continue;
        }
        if storing.ends_at_too_many_blank_led_lines(text) {
            break;
        }
        if !in_headers {
            if line.text.is_none() || is_a_header_line_in_the_body(text) {
                continue;
            }
            inner_body = Some(Span {
                from: line.mark,
                to: body.to,
            });
            break;
        }
        if line.text.is_none() {
            if !found_a_header {
                break;
            }
            in_headers = false;
            continue;
        }
        let collected = if let Some(collected) = pending.as_mut() {
            collected.extend_from_slice(text);
            pending_length = pending_length.saturating_add(text.len()).saturating_add(1);
            collected.clone()
        } else {
            if text.first().is_some_and(|first| is_c_blank(*first)) {
                continue;
            }
            let Some(name) = field(text, 0, b":").filter(|_| text.contains(&b':')) else {
                if text.starts_with(MBOX_SEPARATOR) {
                    found_a_header = true;
                }
                continue;
            };
            if content_header(&without_comments_or_as_is(name)).is_none() {
                if !found_a_header {
                    found_a_header = makes_a_message(name);
                }
                continue;
            }
            found_a_header = true;
            pending = Some(text.to_vec());
            pending_length = text.len().saturating_add(1);
            text.to_vec()
        };
        if pending_length > MOST_HEADER_BYTES {
            break;
        }
        if is_folded_into(text, lines.peek()?) {
            continue;
        }
        if has_an_odd_number_of_quotes(&collected) {
            continue;
        }
        let header = without_comments_or_as_is(&collected);
        headers_read = headers_read.saturating_add(1);
        if headers_read > MOST_HEADERS {
            break;
        }
        if headers.read_header_line(&header) == HeaderLine::Unread {
            pending = Some(header);
            continue;
        }
        pending = None;
    }
    Ok(found_a_header.then_some(Message {
        headers,
        body: inner_body,
        markers: if outer_has_markers {
            Markers::AfterTheFirstLine
        } else {
            Markers::None
        },
    }))
}
