use crate::mail::header_text::{
    field, first_token_and_rest, parameter_value, starts_with_ignoring_case,
    with_encoded_words_decoded, without_comments_or_as_is, without_trailing_unprintables,
};
use crate::mail::similarity::{IDENTICAL, similarity};
use crate::mail::stored::{is_c_blank, is_c_space};

const MOST_PARAMETERS_READ: usize = 255;
const CLOSE_ENOUGH: i32 = 50;
const HEADER_SEPARATORS: [u8; 3] = *b":= ";
const KEPT_PARAMETERS: [&[u8]; 8] = [
    b"name",
    b"filename",
    b"boundary",
    b"protocol",
    b"id",
    b"number",
    b"total",
    b"type",
];
const UNKNOWN_FILENAME: &[u8] = b"filename=unknown";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MediaType {
    #[default]
    Unstated,
    Text,
    Multipart,
    Application,
    Audio,
    Image,
    Message,
    Video,
    Extension,
}

const MEDIA_TYPES: [(&[u8], MediaType); 7] = [
    (b"text", MediaType::Text),
    (b"multipart", MediaType::Multipart),
    (b"application", MediaType::Application),
    (b"audio", MediaType::Audio),
    (b"image", MediaType::Image),
    (b"message", MediaType::Message),
    (b"video", MediaType::Video),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferEncoding {
    AsWritten,
    QuotedPrintable,
    Base64,
    EightBit,
    Binary,
    Uuencode,
    Yencode,
    Binhex,
}

const UUENCODE_NAME: &[u8] = b"uuencode";

const TRANSFER_ENCODINGS: [(&[u8], TransferEncoding); 12] = [
    (b"7bit", TransferEncoding::AsWritten),
    (b"text/plain", TransferEncoding::AsWritten),
    (b"quoted-printable", TransferEncoding::QuotedPrintable),
    (b"base64", TransferEncoding::Base64),
    (b"8bit", TransferEncoding::EightBit),
    (b"binary", TransferEncoding::Binary),
    (b"x-uuencode", TransferEncoding::Uuencode),
    (b"x-yencode", TransferEncoding::Yencode),
    (b"x-binhex", TransferEncoding::Binhex),
    (b"us-ascii", TransferEncoding::AsWritten),
    (b"x-uue", TransferEncoding::Uuencode),
    (UUENCODE_NAME, TransferEncoding::Uuencode),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContentHeader {
    Type,
    TransferEncoding,
    Disposition,
}

pub fn content_header(name: &[u8]) -> Option<ContentHeader> {
    [
        (b"Content-Type".as_slice(), ContentHeader::Type),
        (
            b"Content-Transfer-Encoding",
            ContentHeader::TransferEncoding,
        ),
        (b"Content-Disposition", ContentHeader::Disposition),
    ]
    .into_iter()
    .find(|(known, _)| known.eq_ignore_ascii_case(name))
    .map(|(_, header)| header)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeaderLine {
    Read,
    Unread,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PartHeaders {
    pub media_type: MediaType,
    pub subtype: Vec<u8>,
    pub encodings: Vec<TransferEncoding>,
    disposition: Option<Vec<u8>>,
    parameters: Vec<Option<Vec<u8>>>,
}

impl PartHeaders {
    pub fn encoding(&self) -> TransferEncoding {
        self.encodings
            .first()
            .copied()
            .unwrap_or(TransferEncoding::AsWritten)
    }

    pub fn disposition(&self) -> &[u8] {
        self.disposition.as_deref().unwrap_or_default()
    }

    pub fn read_header_line(&mut self, line: &[u8]) -> HeaderLine {
        let Some(separator) = HEADER_SEPARATORS
            .into_iter()
            .find(|separator| line.contains(separator))
        else {
            return HeaderLine::Unread;
        };
        let decoded = with_encoded_words_decoded(line).unwrap_or_else(|| line.to_vec());
        let Some((name, value)) = first_token_and_rest(&decoded, separator) else {
            return HeaderLine::Unread;
        };
        let name = without_trailing_unprintables(name);
        let (false, Some(value)) = (name.is_empty(), value) else {
            return HeaderLine::Unread;
        };
        self.read_content_header(name, value);
        HeaderLine::Read
    }

    fn read_content_header(&mut self, name: &[u8], value: &[u8]) {
        let Some(header) = content_header(&without_comments_or_as_is(name)) else {
            return;
        };
        let cleaned = without_comments_or_as_is(value);
        match header {
            ContentHeader::Type => self.read_content_type(value, &cleaned),
            ContentHeader::TransferEncoding => self.add_transfer_encoding(&cleaned),
            ContentHeader::Disposition => self.read_disposition(&cleaned),
        }
    }

    fn read_content_type(&mut self, raw: &[u8], cleaned: &[u8]) {
        if !cleaned.contains(&b'/') {
            return;
        }
        let parameters_from: &[u8] = if raw.first() == Some(&b'/') {
            self.media_type = MediaType::Application;
            self.subtype = b"octet-stream".to_vec();
            cleaned
        } else {
            let mut start = cleaned
                .iter()
                .position(|byte| !is_c_space(*byte))
                .unwrap_or(cleaned.len());
            if cleaned.get(start) == Some(&b'"') {
                start = start.saturating_add(1);
            }
            let from = cleaned.get(start..).unwrap_or_default();
            if from.first() != Some(&b'/') {
                self.read_type_and_subtype(from);
            }
            from
        };
        let mut index = 1usize;
        let mut read = 0usize;
        while let Some(parameter) = field(parameters_from, index, b";") {
            read = read.saturating_add(1);
            if read > MOST_PARAMETERS_READ {
                break;
            }
            self.add_parameters(parameter);
            index = index.saturating_add(1);
        }
    }

    fn read_type_and_subtype(&mut self, value: &[u8]) {
        let Some(first) = field(value, 0, b";") else {
            return;
        };
        let mut words = first.to_vec();
        loop {
            let (media, subtype) = match first_token_and_rest(&words, b'/') {
                Some((media, subtype)) => (Some(media.to_vec()), subtype.map(<[u8]>::to_vec)),
                None => (None, None),
            };
            let set = self.set_media_type(media.as_deref());
            let Some(mut subtype) = subtype else {
                break;
            };
            if set {
                subtype = self.read_subtype(&subtype);
            }
            let Some(space) = subtype.iter().position(|byte| is_c_space(*byte)) else {
                break;
            };
            let after = subtype.get(space.saturating_add(1)..).unwrap_or_default();
            if after.is_empty() {
                break;
            }
            words = after.to_vec();
        }
    }

    fn read_subtype(&mut self, subtype: &[u8]) -> Vec<u8> {
        let stripped = without_trailing_unprintables(subtype).to_vec();
        if stripped.is_empty() {
            self.subtype = Vec::new();
            return stripped;
        }
        let (named, kept) = match stripped.split_last() {
            Some((b'"', before)) => {
                let unquoted = without_trailing_unprintables(before).to_vec();
                (!unquoted.is_empty(), unquoted)
            }
            _ => (stripped.len() > 1, stripped),
        };
        if named {
            self.subtype = if kept.contains(&b' ') {
                field(&kept, 0, b" ").map_or_else(Vec::new, <[u8]>::to_vec)
            } else {
                kept.clone()
            };
        }
        kept
    }

    fn set_media_type(&mut self, word: Option<&[u8]>) -> bool {
        let Some(word) = word else {
            return false;
        };
        let Some(letter) = word.iter().position(u8::is_ascii_alphabetic) else {
            return false;
        };
        let word = word.get(letter..).unwrap_or_default();
        if let Some((_, known)) = MEDIA_TYPES
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case(word))
        {
            self.media_type = *known;
            return true;
        }
        if self.media_type != MediaType::Unstated {
            return false;
        }
        self.media_type = if starts_with_ignoring_case(word, b"x-") {
            MediaType::Extension
        } else if word.eq_ignore_ascii_case(b"plain") {
            MediaType::Text
        } else {
            closest_media_type(word)
        };
        true
    }

    pub fn add_transfer_encoding(&mut self, value: &[u8]) {
        let start = value
            .iter()
            .position(|byte| !is_c_blank(*byte))
            .unwrap_or(value.len());
        let mut value = value.get(start..).unwrap_or_default();
        if value.eq_ignore_ascii_case(b"8 bit") {
            value = b"8bit";
        }
        let mut index = 0usize;
        while let Some(token) = field(value, index, b" \t") {
            self.add_one_transfer_encoding(token);
            index = index.saturating_add(1);
        }
    }

    fn add_one_transfer_encoding(&mut self, token: &[u8]) {
        let initial = token.first().copied().unwrap_or(0).to_ascii_lowercase();
        let mut best = 0;
        let mut closest = None;
        for (name, encoding) in TRANSFER_ENCODINGS {
            let name_initial = name.first().copied().unwrap_or(0).to_ascii_lowercase();
            if (initial != name_initial && initial != b'x') || name == UUENCODE_NAME {
                continue;
            }
            let score = similarity(token, name);
            if score == IDENTICAL {
                if !self.encodings.contains(&encoding) {
                    self.encodings.push(encoding);
                }
                return;
            }
            if score > best {
                best = score;
                closest = Some(name);
            }
        }
        if let Some(name) = closest.filter(|_| best >= CLOSE_ENOUGH) {
            self.add_transfer_encoding(name);
        } else {
            self.add_transfer_encoding(b"base64");
            self.add_transfer_encoding(b"quoted-printable");
        }
    }

    fn read_disposition(&mut self, value: &[u8]) {
        if let Some(kind) = field(value, 0, b";").filter(|kind| !kind.is_empty()) {
            let start = kind
                .iter()
                .position(|byte| !is_c_space(*byte))
                .unwrap_or(kind.len());
            let kind = kind.get(start..).unwrap_or_default();
            self.disposition =
                (!kind.is_empty()).then(|| without_trailing_unprintables(kind).to_vec());
            if let Some(first) = field(value, 1, b";") {
                self.add_parameter(first);
            }
        }
        if !self.has_filename() {
            self.add_parameter(UNKNOWN_FILENAME);
        }
    }

    pub fn add_parameters(&mut self, text: &[u8]) {
        let mut at = 0usize;
        while let Some(&byte) = text.get(at) {
            if is_c_space(byte) || byte == b';' {
                at = at.saturating_add(1);
                continue;
            }
            let key = text.get(at..).unwrap_or_default();
            let Some(equals) = key
                .iter()
                .position(|byte| *byte == b'=')
                .or_else(|| key.iter().position(|byte| *byte == b':'))
            else {
                return;
            };
            let mut value_at = equals.saturating_add(1);
            while key.get(value_at).is_some_and(|byte| is_c_space(*byte)) {
                value_at = value_at.saturating_add(1);
            }
            if key.get(value_at) == Some(&b'"') {
                let name = key.get(..equals).unwrap_or_default();
                let quoted = key.get(value_at.saturating_add(1)..).unwrap_or_default();
                let closing = quoted.iter().position(|byte| *byte == b'"');
                at = match closing {
                    None => text.len(),
                    Some(closing) => at
                        .saturating_add(value_at)
                        .saturating_add(closing)
                        .saturating_add(2),
                };
                if !is_kept_parameter(name) {
                    continue;
                }
                let value =
                    closing.map_or(quoted, |closing| quoted.get(..closing).unwrap_or_default());
                let mut parameter = name.to_vec();
                parameter.push(b'=');
                parameter.extend_from_slice(value);
                self.add_parameter(&parameter);
            } else {
                if key.get(value_at).is_none() {
                    return;
                }
                let mut end = value_at.saturating_add(1);
                while key.get(end).is_some_and(|byte| !is_c_space(*byte)) {
                    end = end.saturating_add(1);
                }
                let parameter = key.get(..end).unwrap_or_default().to_vec();
                at = at.saturating_add(end);
                self.add_parameter(&parameter);
            }
        }
    }

    pub fn add_parameter(&mut self, text: &[u8]) {
        let start = text
            .iter()
            .position(|byte| !is_c_space(*byte))
            .unwrap_or(text.len());
        let text = text.get(start..).unwrap_or_default();
        if text.is_empty() || !is_kept_parameter(text) {
            return;
        }
        let mut slot = self.parameters.len();
        for (index, existing) in self.parameters.iter().enumerate() {
            match existing {
                None => {
                    slot = index;
                    break;
                }
                Some(existing) if existing.eq_ignore_ascii_case(text) => return,
                Some(_) => {}
            }
        }
        let mut value = parameter_value(text);
        if !value.contains(&b'=') {
            if value.starts_with(b"filename") {
                if let Some(ninth) = value.get_mut(8) {
                    *ninth = b'=';
                }
            } else {
                self.place_parameter(slot, None);
                return;
            }
        }
        let names_a_file = starts_with_ignoring_case(&value, b"filename=")
            || starts_with_ignoring_case(&value, b"name=");
        self.place_parameter(slot, Some(value));
        if names_a_file && self.media_type == MediaType::Unstated {
            self.media_type = MediaType::Application;
        }
    }

    fn place_parameter(&mut self, slot: usize, value: Option<Vec<u8>>) {
        match self.parameters.get_mut(slot) {
            Some(existing) => *existing = value,
            None => self.parameters.push(value),
        }
    }

    pub fn parameter(&self, name: &[u8]) -> Option<Vec<u8>> {
        let value = self.value_after(name)?;
        let quoted = value.len() > 1
            && value.first() == Some(&b'"')
            && value.get(1..).is_some_and(|rest| rest.contains(&b'"'));
        if !quoted {
            return Some(value.to_vec());
        }
        let mut unquoted = value.get(1..).unwrap_or_default().to_vec();
        if unquoted.contains(&b'"') {
            unquoted.pop();
        }
        Some(unquoted)
    }

    fn value_after(&self, name: &[u8]) -> Option<&[u8]> {
        let existing = self
            .parameters
            .iter()
            .flatten()
            .filter(|existing| !existing.is_empty())
            .find(|existing| starts_with_ignoring_case(existing, name))?;
        let after = existing.get(name.len()..).unwrap_or_default();
        let start = after
            .iter()
            .position(|byte| !is_c_space(*byte))
            .unwrap_or(after.len());
        let after = after.get(start..).unwrap_or_default();
        if after.first() != Some(&b'=') {
            return None;
        }
        after.get(1..)
    }

    pub fn has_parameter(&self, name: &[u8]) -> bool {
        self.value_after(name).is_some()
    }

    pub fn has_filename(&self) -> bool {
        self.has_parameter(b"filename") || self.has_parameter(b"file")
    }

    pub fn filename(&self) -> Option<Vec<u8>> {
        self.parameter(b"filename")
            .or_else(|| self.parameter(b"name"))
    }
}

fn is_kept_parameter(text: &[u8]) -> bool {
    KEPT_PARAMETERS
        .iter()
        .any(|kept| starts_with_ignoring_case(text, kept))
}

fn closest_media_type(word: &[u8]) -> MediaType {
    let mut best = 0;
    let mut closest = MediaType::Application;
    for (name, media_type) in MEDIA_TYPES {
        let score = similarity(name, word);
        if score > best {
            best = score;
            closest = media_type;
        }
    }
    if best >= CLOSE_ENOUGH {
        closest
    } else {
        MediaType::Application
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    fn headers(lines: &[&[u8]]) -> PartHeaders {
        let mut headers = PartHeaders::default();
        for line in lines {
            headers.read_header_line(line);
        }
        headers
    }

    #[test]
    fn a_content_type_gives_the_media_type_subtype_and_kept_parameters() {
        let read = headers(&[b"Content-Type: multipart/mixed; charset=x; boundary=\"b 1\""]);
        assert_eq!(read.media_type, MediaType::Multipart);
        assert_eq!(read.subtype, b"mixed");
        assert_eq!(read.parameter(b"boundary").unwrap(), b"b 1");
        assert_eq!(read.parameter(b"charset"), None);
    }

    #[test]
    fn an_unknown_encoding_adds_base64_and_quoted_printable() {
        let read = headers(&[b"Content-Transfer-Encoding: x-foo"]);
        assert_eq!(
            read.encodings,
            [TransferEncoding::Base64, TransferEncoding::QuotedPrintable]
        );
    }

    #[test]
    fn a_disposition_without_a_filename_is_given_an_unknown_one() {
        let read = headers(&[b"Content-Disposition: inline"]);
        assert_eq!(read.disposition(), b"inline");
        assert_eq!(read.filename().unwrap(), b"unknown");
        assert_eq!(read.media_type, MediaType::Application);
    }

    #[test]
    fn a_name_parameter_is_found_as_the_filename() {
        let read = headers(&[b"Content-Type: application/octet-stream; name=\"a.bin\""]);
        assert_eq!(read.filename().unwrap(), b"a.bin");
        assert!(!read.has_filename());
    }
}
