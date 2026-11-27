use debar_platform::input::{InputError, ObjectBytes};

use crate::limits::Limit;
use crate::mail::boundaries::{is_boundary_end, is_boundary_start};
use crate::mail::header_text::{contains, starts_with_ignoring_case};
use crate::mail::headers::{MediaType, PartHeaders, TransferEncoding};
use crate::mail::lines::{Reading, without_line_ends};
use crate::mail::message::{Markers, Message, Separator, is_folded_into, read_inner_message};
use crate::mail::output::{Decoding, Output, TextSegment, YencStart};
use crate::mail::similarity::similarity;
use crate::mail::stored::{Mark, Span, StoredLine, StoredLines, Storing, is_c_space};
use crate::object::Object;

const MOST_PARTS_KEPT: usize = 1024;
const BINHEX_NOTICE: &[u8] = b"(This file must be converted with BinHex 4.0)";
const BINHEX_SIMILARITY: i32 = 90;
const YENC_BEGIN: &[u8] = b"=ybegin line=";
const ENCODING_HEADER: &[u8] = b"Content-Transfer-Encoding";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Status {
    Done,
    AttachmentsNotSaved,
    Failed,
    TooDeep,
    TooManyFiles,
    Unexpected,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Subtype {
    Plain,
    Enriched,
    Html,
    RichText,
    Mixed,
    Alternative,
    Digest,
    Signed,
    Parallel,
    Related,
    Report,
    AppleDouble,
    Encrypted,
    Knowbot,
    Unknown,
}

fn subtype_of(name: &[u8]) -> Subtype {
    const NAMES: [(&[u8], Subtype); 20] = [
        (b"plain", Subtype::Plain),
        (b"enriched", Subtype::Enriched),
        (b"html", Subtype::Html),
        (b"richtext", Subtype::RichText),
        (b"mixed", Subtype::Mixed),
        (b"alternative", Subtype::Alternative),
        (b"digest", Subtype::Digest),
        (b"signed", Subtype::Signed),
        (b"parallel", Subtype::Parallel),
        (b"related", Subtype::Related),
        (b"report", Subtype::Report),
        (b"appledouble", Subtype::AppleDouble),
        (b"fax-message", Subtype::Mixed),
        (b"encrypted", Subtype::Encrypted),
        (b"x-bfile", Subtype::Related),
        (b"knowbot", Subtype::Knowbot),
        (b"knowbot-metadata", Subtype::Knowbot),
        (b"knowbot-code", Subtype::Knowbot),
        (b"knowbot-state", Subtype::Knowbot),
        (b"", Subtype::Unknown),
    ];
    NAMES
        .iter()
        .take(NAMES.len().saturating_sub(1))
        .find(|(known, _)| known.eq_ignore_ascii_case(name))
        .map_or(Subtype::Unknown, |(_, subtype)| *subtype)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExportRule {
    MatchedAtOnce,
    ByWhatTheExportLeaves,
}

#[derive(Debug, Default, Clone, Copy)]
struct FoundMarkers {
    encoding_line: Option<Mark>,
    binhex_line: Option<u64>,
    yenc_data: Option<YencStart>,
}

impl FoundMarkers {
    const fn any(&self) -> bool {
        self.encoding_line.is_some() || self.binhex_line.is_some() || self.yenc_data.is_some()
    }
}

struct Section<'t> {
    main_alive: bool,
    status: Status,
    kept: Vec<Option<Part>>,
    kept_too_many: bool,
    inherited: Option<&'t mut Vec<TextSegment>>,
    own_text: &'t mut Option<Vec<TextSegment>>,
    level: u32,
}

pub struct Plan {
    pub at_once: Vec<Output>,
    pub folder: Vec<Output>,
    pub folder_scanned: bool,
    pub limit: Option<Limit>,
}

#[derive(Clone)]
struct Part {
    message: Message,
    yenc_used: bool,
}

impl Part {
    const fn new(message: Message) -> Self {
        Self {
            message,
            yenc_used: false,
        }
    }

    fn headers(&mut self) -> &mut PartHeaders {
        &mut self.message.headers
    }
}

pub struct Walker<'r, 'o> {
    object: &'r Object<'o>,
    most_files: Option<u64>,
    deepest_level: u32,
    files: u64,
    at_once: Vec<Output>,
    folder: Vec<Output>,
}

impl<'r, 'o> Walker<'r, 'o> {
    pub const fn new(object: &'r Object<'o>, most_files: Option<u64>, deepest_level: u32) -> Self {
        Self {
            object,
            most_files,
            deepest_level,
            files: 0,
            at_once: Vec::new(),
            folder: Vec::new(),
        }
    }

    pub fn walk(mut self, message: Message, uudecoded: Vec<u64>) -> Result<Plan, InputError> {
        self.folder
            .extend(uudecoded.into_iter().map(|from| Output::Uudecoded { from }));
        let has_body = self.has_lines(message.body)?;
        let status = if has_body {
            self.body(Part::new(message), None, 0)?
        } else {
            Status::Done
        };
        Ok(self.planned(status))
    }

    pub fn walk_mailbox(mut self, separators: &[Separator]) -> Result<Plan, InputError> {
        let end = self.object.length();
        let mut from = 0u64;
        let mut status = Status::Done;
        for index in 0..=separators.len() {
            let to = separators
                .get(index)
                .map_or(end, |separator| separator.start);
            let span = Span {
                from: Mark {
                    position: from,
                    storing: Storing::reading_a_mailbox_message(),
                },
                to,
            };
            let mut lines = StoredLines::new(self.object, span, Reading::First);
            while lines.next_line()?.is_some() {}
            self.folder.extend(
                lines
                    .take_uuencoded_blocks()
                    .into_iter()
                    .map(|from| Output::Uudecoded { from }),
            );
            let outcome = self.mailbox_message(span)?;
            let Some(separator) = separators.get(index) else {
                status = outcome.unwrap_or(Status::Done);
                break;
            };
            from = match outcome {
                None | Some(Status::Failed) => separator.end,
                Some(_) => separator.start,
            };
        }
        Ok(self.planned(status))
    }

    fn mailbox_message(&mut self, span: Span) -> Result<Option<Status>, InputError> {
        let whole = Part::new(Message {
            headers: PartHeaders::default(),
            body: Some(span),
            markers: Markers::FromEveryLine,
        });
        let outer_has_markers = self.markers(&whole)?.any();
        let Some(inner) = read_inner_message(self.object, span, outer_has_markers)? else {
            return Ok(None);
        };
        if !self.has_lines(inner.body)? {
            return Ok(Some(Status::Done));
        }
        self.body(Part::new(inner), None, 0).map(Some)
    }

    fn planned(self, status: Status) -> Plan {
        let (folder_scanned, limit) = match status {
            Status::Done | Status::AttachmentsNotSaved | Status::Unexpected => (true, None),
            Status::Failed => (false, None),
            Status::TooDeep => (false, Some(Limit::DeepestLevel)),
            Status::TooManyFiles => (false, Some(Limit::MostFiles)),
        };
        Plan {
            at_once: self.at_once,
            folder: self.folder,
            folder_scanned,
            limit,
        }
    }

    fn has_lines(&self, body: Option<Span>) -> Result<bool, InputError> {
        let Some(body) = body else {
            return Ok(false);
        };
        Ok(StoredLines::new(self.object, body, Reading::Again)
            .next_line()?
            .is_some())
    }

    fn body(
        &mut self,
        mut main: Part,
        mut inherited: Option<&mut Vec<TextSegment>>,
        level: u32,
    ) -> Result<Status, InputError> {
        if level > self.deepest_level {
            return Ok(Status::TooDeep);
        }
        if self
            .most_files
            .is_some_and(|most| most > 0 && self.files >= most)
        {
            return Ok(Status::TooManyFiles);
        }
        let mut status = Status::Done;
        let mut own_text: Option<Vec<TextSegment>> = None;
        let text_given = inherited.is_some();
        if !self.has_lines(main.message.body)? {
            return self.tail(main, status);
        }
        let subtype = subtype_of(&main.message.headers.subtype);
        let mut media = main.message.headers.media_type;
        let read_as_text = (media == MediaType::Text && subtype == Subtype::Plain)
            || (media == MediaType::Message
                && main
                    .message
                    .headers
                    .subtype
                    .eq_ignore_ascii_case(b"rfc822-headers"));
        if read_as_text {
            media = MediaType::Unstated;
            main.headers().subtype = Vec::new();
        }
        match media {
            MediaType::Unstated => {
                let segment = self.text_of(&main)?;
                active_text(&mut inherited, &mut own_text, segment);
                self.prepare_for_links(&mut main)?;
            }
            MediaType::Text => self.prepare_for_links(&mut main)?,
            MediaType::Multipart => {
                match self.multipart(&mut main, inherited, &mut own_text, text_given, level)? {
                    Some(status) => return Ok(status),
                    None => return self.tail(main, status),
                }
            }
            MediaType::Message => return self.inner_message(&main, level),
            MediaType::Application | MediaType::Extension => {
                if self.export(&mut main, ExportRule::ByWhatTheExportLeaves)? {
                    self.files = self.files.saturating_add(1);
                    main.message.body = None;
                    main.message.headers = PartHeaders::default();
                }
            }
            MediaType::Audio | MediaType::Image | MediaType::Video => {}
        }
        status = self.tail(main, status)?;
        Ok(status)
    }

    fn tail(&mut self, mut main: Part, status: Status) -> Result<Status, InputError> {
        let markers = self.markers(&main)?;
        let save_it = if main.message.headers.media_type == MediaType::Message {
            markers.encoding_line.is_some()
        } else if let (Some(encoding_line), Some(body)) = (markers.encoding_line, main.message.body)
        {
            self.folder.push(Output::Bounce {
                lines: Span {
                    from: encoding_line,
                    to: body.to,
                },
            });
            self.files = self.files.saturating_add(1);
            false
        } else {
            true
        };
        if save_it {
            self.save_text_part(&mut main)?;
        }
        Ok(status)
    }

    fn save_text_part(&mut self, part: &mut Part) -> Result<(), InputError> {
        part.headers().add_parameter(b"filename=textportion");
        if self.export(part, ExportRule::ByWhatTheExportLeaves)? {
            self.files = self.files.saturating_add(1);
        }
        Ok(())
    }

    fn inner_message(&mut self, main: &Part, level: u32) -> Result<Status, InputError> {
        let subtype = &main.message.headers.subtype;
        if subtype.eq_ignore_ascii_case(b"rfc822")
            || subtype.eq_ignore_ascii_case(b"delivery-status")
        {
            let Some(body) = main.message.body else {
                return Ok(Status::Failed);
            };
            let outer_has_markers = self.markers(main)?.any();
            let Some(inner) = read_inner_message(self.object, body, outer_has_markers)? else {
                return Ok(Status::Failed);
            };
            if inner.body.is_none() {
                return Ok(Status::Failed);
            }
            return self.body(Part::new(inner), None, level.saturating_add(1));
        }
        if subtype.eq_ignore_ascii_case(b"disposition-notification") {
            return Ok(Status::Done);
        }
        Ok(Status::Failed)
    }

    fn multipart(
        &mut self,
        main: &mut Part,
        inherited: Option<&mut Vec<TextSegment>>,
        own_text: &mut Option<Vec<TextSegment>>,
        text_given: bool,
        level: u32,
    ) -> Result<Option<Status>, InputError> {
        let Some(boundary) = main.message.headers.parameter(b"boundary") else {
            return Ok(None);
        };
        let boundary = without_line_ends(&boundary).to_vec();
        if main.message.headers.subtype.is_empty() {
            main.headers().subtype = b"alternative".to_vec();
        }
        let Some(body) = main.message.body else {
            return Ok(None);
        };
        let markers = self.markers(main)?;
        let mut lines = StoredLines::new(self.object, body, Reading::Again);
        if !self.found_the_first_part(main, &markers, &boundary, &mut lines)? {
            return Ok(None);
        }
        let subtype = subtype_of(&main.message.headers.subtype);
        let mut section = Section {
            main_alive: true,
            status: Status::Done,
            kept: Vec::new(),
            kept_too_many: false,
            inherited,
            own_text,
            level,
        };
        let mut in_headers = true;
        loop {
            let first = loop {
                match lines.next_line()? {
                    None => break None,
                    Some(line) if line.text().is_empty() => {}
                    Some(line) => break Some(line),
                }
            };
            let Some(first) = first else {
                if !section.main_alive || markers.binhex_line.is_some() {
                    section.kept.push(Some(Part::new(Message {
                        headers: PartHeaders::default(),
                        body: None,
                        markers: Markers::FromEveryLine,
                    })));
                }
                break;
            };
            let part = Self::read_part(&mut lines, first, &boundary, &mut in_headers, body.to)?;
            self.part_as_read(main, &mut section, subtype, part)?;
        }
        if section.kept_too_many || section.kept.len() >= MOST_PARTS_KEPT {
            return Ok(None);
        }
        let has_text = section.inherited.is_some() || section.own_text.is_some();
        if section.kept.is_empty() && !has_text {
            return Ok(Some(match section.status {
                Status::TooDeep => Status::TooDeep,
                _ => Status::AttachmentsNotSaved,
            }));
        }
        self.kept_parts(main, &mut section, subtype)?;
        if !text_given && let Some(segments) = section.own_text.take() {
            self.folder.push(Output::TextPart { segments });
            self.files = self.files.saturating_add(1);
        }
        Ok(Some(section.status))
    }

    fn found_the_first_part(
        &mut self,
        main: &mut Part,
        markers: &FoundMarkers,
        boundary: &[u8],
        lines: &mut StoredLines<'_>,
    ) -> Result<bool, InputError> {
        while let Some(line) = lines.next_line()? {
            if line.text.is_none() {
                continue;
            }
            if is_boundary_start(line.text(), Some(boundary)) {
                return Ok(true);
            }
            if markers.binhex_line == Some(line.mark.position) {
                self.binhex_export(main)?;
            } else if let Some(next) = lines.peek()?
                && markers
                    .encoding_line
                    .is_some_and(|mark| mark.position == next.mark.position)
                && main.message.headers.encoding() == TransferEncoding::AsWritten
            {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn part_as_read(
        &mut self,
        main: &mut Part,
        section: &mut Section<'_>,
        subtype: Subtype,
        part: Message,
    ) -> Result<(), InputError> {
        match subtype {
            Subtype::Mixed
            | Subtype::Alternative
            | Subtype::Report
            | Subtype::Digest
            | Subtype::AppleDouble
            | Subtype::Knowbot
            | Subtype::Unknown => {
                let before = section.status;
                let text = active_list(&mut section.inherited, section.own_text);
                self.one_part(
                    main,
                    &mut section.main_alive,
                    part,
                    &mut section.status,
                    text,
                    section.level,
                )?;
                if section.status == Status::AttachmentsNotSaved && before == Status::Done {
                    section.status = Status::Done;
                }
            }
            Subtype::Related | Subtype::Encrypted | Subtype::Signed | Subtype::Parallel => {
                if section.kept.len() < MOST_PARTS_KEPT {
                    section.kept.push(Some(Part::new(part)));
                } else {
                    section.kept_too_many = true;
                }
            }
            Subtype::Plain | Subtype::Enriched | Subtype::Html | Subtype::RichText => {}
        }
        Ok(())
    }

    fn kept_parts(
        &mut self,
        main: &mut Part,
        section: &mut Section<'_>,
        subtype: Subtype,
    ) -> Result<(), InputError> {
        match subtype {
            Subtype::Related
            | Subtype::Digest
            | Subtype::Alternative
            | Subtype::Report
            | Subtype::Encrypted
            | Subtype::Mixed
            | Subtype::AppleDouble
            | Subtype::Knowbot
            | Subtype::Unknown => {
                if subtype == Subtype::Related {
                    self.related_root(section)?;
                }
                self.remaining_parts(main, section)?;
            }
            Subtype::Signed | Subtype::Parallel => {
                if !section.kept.is_empty() {
                    let index = text_part(&section.kept).unwrap_or(0);
                    if let Some(part) = section.kept.get_mut(index).and_then(Option::take) {
                        let text = active_list(&mut section.inherited, section.own_text);
                        section.status = self.body(part, text, section.level.saturating_add(1))?;
                    }
                }
            }
            Subtype::Plain | Subtype::Enriched | Subtype::Html | Subtype::RichText => {
                section.status = Status::Unexpected;
            }
        }
        Ok(())
    }

    fn related_root(&mut self, section: &mut Section<'_>) -> Result<(), InputError> {
        let text_part_found = text_part(&section.kept);
        if let Some(Some(part)) = text_part_found.and_then(|index| section.kept.get(index))
            && self.has_lines(part.message.body)?
        {
            let segment = self.text_of(part)?;
            active_text(&mut section.inherited, section.own_text, segment);
        }
        let chosen = text_part_found.or_else(|| {
            section.kept.iter().position(|part| {
                part.as_ref()
                    .is_some_and(|part| part.message.headers.media_type == MediaType::Multipart)
            })
        });
        let Some(index) = chosen else {
            return Ok(());
        };
        if let Some(part) = section.kept.get(index).cloned().flatten() {
            let text = active_list(&mut section.inherited, section.own_text);
            section.status = self.body(part, text, section.level.saturating_add(1))?;
            if section.status == Status::Done
                && let Some(slot) = section.kept.get_mut(index)
            {
                *slot = None;
            }
        }
        Ok(())
    }

    fn remaining_parts(
        &mut self,
        main: &mut Part,
        section: &mut Section<'_>,
    ) -> Result<(), InputError> {
        if section.inherited.is_some() || section.own_text.is_some() {
            section.main_alive = false;
        }
        let mut kept = std::mem::take(&mut section.kept);
        for slot in &mut kept {
            if let Some(part) = slot.take() {
                let text = active_list(&mut section.inherited, section.own_text);
                self.one_part(
                    main,
                    &mut section.main_alive,
                    part.message,
                    &mut section.status,
                    text,
                    section.level.saturating_add(1),
                )?;
            }
            if section.status == Status::TooDeep {
                break;
            }
            if section.status == Status::AttachmentsNotSaved {
                section.status = Status::Done;
            }
        }
        Ok(())
    }

    fn read_part(
        lines: &mut StoredLines<'_>,
        first: StoredLine,
        boundary: &[u8],
        in_headers: &mut bool,
        end: u64,
    ) -> Result<Message, InputError> {
        let mut part = PartHeaders::default();
        let mut body_from: Option<Mark> = None;
        let mut body_to = end;
        let mut current = Some(first);
        while let Some(line) = current.take() {
            if *in_headers {
                Self::part_header_line(lines, line, &mut part, in_headers)?;
            } else if is_boundary_end(line.text(), boundary) && line.text.is_some() {
                body_to = line.mark.position;
                break;
            } else if line.text.is_some() && is_boundary_start(line.text(), Some(boundary)) {
                *in_headers = true;
                body_to = line.mark.position;
                break;
            } else if body_from.is_none() {
                body_from = Some(line.mark);
            }
            current = lines.next_line()?;
        }
        Ok(Message {
            headers: part,
            body: body_from.map(|from| Span { from, to: body_to }),
            markers: Markers::FromEveryLine,
        })
    }

    fn part_header_line(
        lines: &mut StoredLines<'_>,
        line: StoredLine,
        part: &mut PartHeaders,
        in_headers: &mut bool,
    ) -> Result<(), InputError> {
        let Some(text) = line.text.as_deref() else {
            if let Some(next) = lines.peek()?.and_then(|next| next.text.as_deref()) {
                if part.encoding() == TransferEncoding::AsWritten
                    && part.media_type == MediaType::Application
                    && contains(next, b"base64")
                {
                    part.add_transfer_encoding(b"base64");
                    return Ok(());
                }
                if next.starts_with(b"Content") || next.starts_with(b"filename=") {
                    return Ok(());
                }
            }
            *in_headers = false;
            return Ok(());
        };
        if text.first().is_some_and(|first| is_c_space(*first)) {
            part.add_parameter(text);
            if part.media_type == MediaType::Unstated {
                part.media_type = MediaType::Application;
            }
            return Ok(());
        }
        let mut full = crate::mail::header_text::without_comments_or_as_is(text);
        let mut current = line;
        while is_folded_into(current.text(), lines.peek()?) {
            let Some(next) = lines.next_line()? else {
                break;
            };
            if next.text().len() == 1 {
                *in_headers = false;
                break;
            }
            full.extend_from_slice(next.text());
            current = next;
        }
        part.read_header_line(&full);
        Ok(())
    }

    fn one_part(
        &mut self,
        main: &mut Part,
        main_alive: &mut bool,
        message: Message,
        status: &mut Status,
        text: Option<&mut Vec<TextSegment>>,
        level: u32,
    ) -> Result<(), InputError> {
        if *status != Status::Done {
            return Ok(());
        }
        let mut part = Part::new(message);
        let mut adds_to_text = false;
        match part.message.headers.media_type {
            MediaType::Application
            | MediaType::Audio
            | MediaType::Image
            | MediaType::Video
            | MediaType::Extension => {}
            MediaType::Unstated => {
                let part_markers = self.markers(&part)?;
                if *main_alive {
                    if part_markers.binhex_line.is_some() {
                        self.binhex_export(main)?;
                    }
                    *main_alive = false;
                } else if part_markers.binhex_line.is_some() {
                    self.binhex_export(&mut part)?;
                    part.message.body = None;
                    part.message.headers = PartHeaders::default();
                }
                adds_to_text = true;
            }
            MediaType::Text => {
                let disposition = part.message.headers.disposition().to_vec();
                if !disposition.eq_ignore_ascii_case(b"attachment") {
                    if !disposition.is_empty() && !disposition.eq_ignore_ascii_case(b"inline") {
                        return Ok(());
                    }
                    *main_alive = false;
                    let plain = subtype_of(&part.message.headers.subtype) == Subtype::Plain;
                    if plain && part.message.headers.encoding() == TransferEncoding::AsWritten {
                        adds_to_text = !part.message.headers.has_filename();
                    } else {
                        self.prepare_for_links(&mut part)?;
                        part.headers().add_parameter(b"filename=mixedtextportion");
                    }
                }
            }
            MediaType::Message => {
                let unencoded = matches!(
                    part.message.headers.encoding(),
                    TransferEncoding::AsWritten
                        | TransferEncoding::EightBit
                        | TransferEncoding::Binary
                );
                if unencoded && self.markers(&part)?.encoding_line.is_none() {
                    return Ok(());
                }
                self.save_text_part(&mut part)?;
                return Ok(());
            }
            MediaType::Multipart => {
                *status = self.body(part, text, level.saturating_add(1))?;
                return Ok(());
            }
        }
        if self.export(&mut part, ExportRule::MatchedAtOnce)? && !adds_to_text {
            self.files = self.files.saturating_add(1);
        }
        Ok(())
    }

    fn binhex_export(&mut self, message: &mut Part) -> Result<(), InputError> {
        if message.message.headers.encoding() == TransferEncoding::AsWritten {
            message.headers().add_transfer_encoding(b"x-binhex");
        }
        if self.export(message, ExportRule::ByWhatTheExportLeaves)? {
            self.files = self.files.saturating_add(1);
        }
        Ok(())
    }

    fn prepare_for_links(&mut self, part: &mut Part) -> Result<(), InputError> {
        if !self.has_lines(part.message.body)? {
            return Ok(());
        }
        let markers = self.markers(part)?;
        let mut yenc = (!part.yenc_used).then_some(markers.yenc_data).flatten();
        export_encodings(&mut part.message.headers, &mut yenc);
        if yenc.is_none() && markers.yenc_data.is_some() {
            part.yenc_used = true;
        }
        Ok(())
    }

    fn export(&mut self, part: &mut Part, rule: ExportRule) -> Result<bool, InputError> {
        let Some(body) = part.message.body else {
            return Ok(false);
        };
        if !self.has_lines(Some(body))? {
            return Ok(false);
        }
        let markers = self.markers(part)?;
        let mut yenc = (!part.yenc_used).then_some(markers.yenc_data).flatten();
        let exports = export_encodings(&mut part.message.headers, &mut yenc);
        if yenc.is_none() && markers.yenc_data.is_some() {
            part.yenc_used = true;
        }
        let count = exports.outputs.len();
        for (index, (encoding, decoding, from)) in exports.outputs.into_iter().enumerate() {
            let output = Output::Lines {
                lines: Span {
                    from: from.unwrap_or(body.from),
                    to: body.to,
                },
                decoding,
            };
            let last = index.saturating_add(1) == count && exports.completed;
            let at_once = last
                && match rule {
                    ExportRule::MatchedAtOnce => true,
                    ExportRule::ByWhatTheExportLeaves => {
                        exports.through_the_loop
                            && count == 1
                            && encoding != TransferEncoding::AsWritten
                    }
                };
            if at_once {
                self.at_once.push(output);
            } else {
                self.folder.push(output);
            }
        }
        Ok(exports.completed)
    }

    fn text_of(&self, part: &Part) -> Result<Option<TextSegment>, InputError> {
        let Some(body) = part.message.body else {
            return Ok(None);
        };
        if part.message.headers.encoding() == TransferEncoding::AsWritten {
            return Ok(Some(TextSegment::AsWritten { lines: body }));
        }
        let markers = self.markers(part)?;
        let yenc = (!part.yenc_used).then_some(markers.yenc_data).flatten();
        Ok(Some(TextSegment::Decoded {
            lines: body,
            encodings: part.message.headers.encodings.clone(),
            yenc_from: yenc,
        }))
    }

    fn markers(&self, part: &Part) -> Result<FoundMarkers, InputError> {
        let mut found = FoundMarkers::default();
        let Some(body) = part.message.body else {
            return Ok(found);
        };
        let skip_first = match part.message.markers {
            Markers::None => return Ok(found),
            Markers::AfterTheFirstLine => true,
            Markers::FromEveryLine => false,
        };
        let mut lines = StoredLines::new(self.object, body, Reading::Again);
        if skip_first {
            lines.next_line()?;
        }
        let mut awaiting_yenc_data = false;
        while let Some(line) = lines.next_line()? {
            if awaiting_yenc_data {
                found.yenc_data = Some(YencStart::At(line.mark));
                awaiting_yenc_data = false;
            }
            let Some(text) = line.text.as_deref() else {
                continue;
            };
            if found.encoding_line.is_none()
                && starts_with_ignoring_case(text, ENCODING_HEADER)
                && !contains(text, b"7bit")
            {
                found.encoding_line = Some(line.mark);
            } else if found.binhex_line.is_none()
                && contains(text, b"BinHex")
                && similarity(text, BINHEX_NOTICE) > BINHEX_SIMILARITY
            {
                found.binhex_line = Some(line.mark.position);
            } else if found.yenc_data.is_none() && text.starts_with(YENC_BEGIN) {
                found.yenc_data = Some(YencStart::AfterTheLastLine);
                awaiting_yenc_data = true;
            }
        }
        Ok(found)
    }
}

struct Exports {
    outputs: Vec<(TransferEncoding, Decoding, Option<Mark>)>,
    through_the_loop: bool,
    completed: bool,
}

fn export_encodings(headers: &mut PartHeaders, yenc: &mut Option<YencStart>) -> Exports {
    if headers.encodings.is_empty() {
        if headers.parameter(b"filename").is_none() {
            if headers.parameter(b"name").is_none() {
                headers.add_parameter(b"name=attachment");
            } else {
                headers.add_transfer_encoding(b"7-bit");
            }
        }
        if headers.encodings.is_empty() {
            return Exports {
                outputs: vec![(TransferEncoding::AsWritten, Decoding::AsWritten, None)],
                through_the_loop: false,
                completed: true,
            };
        }
    }
    let mut outputs = Vec::new();
    let mut index = 0usize;
    while let Some(&listed) = headers.encodings.get(index) {
        if (listed == TransferEncoding::Yencode || index == 0)
            && let Some(from) = yenc.take()
        {
            let YencStart::At(from) = from else {
                return Exports {
                    outputs,
                    through_the_loop: true,
                    completed: false,
                };
            };
            outputs.push((TransferEncoding::Yencode, Decoding::YEnc, Some(from)));
            index = index.saturating_add(1);
            continue;
        }
        let mut encoding = listed;
        if encoding == TransferEncoding::Uuencode {
            encoding = TransferEncoding::AsWritten;
            if let Some(slot) = headers.encodings.get_mut(index) {
                *slot = encoding;
            }
        }
        if headers.filename().is_none() {
            headers.add_parameter(b"name=attachment");
        } else if encoding == TransferEncoding::AsWritten {
            headers.add_transfer_encoding(b"base64");
        }
        outputs.push((encoding, decoding_of(encoding), None));
        index = index.saturating_add(1);
    }
    Exports {
        outputs,
        through_the_loop: true,
        completed: true,
    }
}

const fn decoding_of(encoding: TransferEncoding) -> Decoding {
    match encoding {
        TransferEncoding::AsWritten
        | TransferEncoding::EightBit
        | TransferEncoding::Binary
        | TransferEncoding::Binhex
        | TransferEncoding::Uuencode => Decoding::AsWritten,
        TransferEncoding::QuotedPrintable => Decoding::QuotedPrintable,
        TransferEncoding::Base64 => Decoding::Base64,
        TransferEncoding::Yencode => Decoding::YEnc,
    }
}

fn text_part(parts: &[Option<Part>]) -> Option<usize> {
    let mut found = None;
    for (index, part) in parts.iter().enumerate() {
        let Some(part) = part else {
            continue;
        };
        if part.message.headers.media_type == MediaType::Text {
            if part.message.headers.subtype.eq_ignore_ascii_case(b"html") {
                return Some(index);
            }
            found = Some(index);
        }
    }
    found
}

fn active_list<'t>(
    inherited: &'t mut Option<&mut Vec<TextSegment>>,
    own: &'t mut Option<Vec<TextSegment>>,
) -> Option<&'t mut Vec<TextSegment>> {
    match inherited {
        Some(list) => Some(&mut **list),
        None => own.as_mut(),
    }
}

fn active_text(
    inherited: &mut Option<&mut Vec<TextSegment>>,
    own: &mut Option<Vec<TextSegment>>,
    segment: Option<TextSegment>,
) {
    let Some(segment) = segment else {
        return;
    };
    match inherited {
        Some(list) => list.push(segment),
        None => own.get_or_insert_with(Vec::new).push(segment),
    }
}
