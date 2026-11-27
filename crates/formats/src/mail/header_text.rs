use crate::mail::line_decoding::{Base64Carry, base64, base64_flush, hex_digit, quoted_printable};
use crate::mail::lines::up_to_the_first_nul;
use crate::mail::stored::is_c_space;

const FAILED_CONTINUATION: &[u8] = b"=rfc2231failure";

pub fn without_trailing_unprintables(text: &[u8]) -> &[u8] {
    let mut kept = text.len();
    while let Some(&last) = kept.checked_sub(1).and_then(|index| text.get(index)) {
        if last.is_ascii_graphic() || last == b'\n' || last == b'\r' {
            break;
        }
        kept = kept.saturating_sub(1);
    }
    text.get(..kept).unwrap_or_default()
}

pub fn field<'t>(text: &'t [u8], wanted: usize, delimiters: &[u8]) -> Option<&'t [u8]> {
    let mut at = 0usize;
    let mut counted = 0usize;
    while counted != wanted {
        let byte = *text.get(at)?;
        if delimiters.contains(&byte) {
            counted = counted.saturating_add(1);
            while text
                .get(at.saturating_add(1))
                .is_some_and(|next| delimiters.contains(next))
            {
                at = at.saturating_add(1);
            }
        }
        at = at.saturating_add(1);
    }
    text.get(at)?;
    let rest = text.get(at..).unwrap_or_default();
    let length = rest
        .iter()
        .position(|byte| delimiters.contains(byte))
        .unwrap_or(rest.len());
    if length == 0 {
        return None;
    }
    rest.get(..length)
}

pub fn first_token_and_rest(text: &[u8], separator: u8) -> Option<(&[u8], Option<&[u8]>)> {
    let start = text.iter().position(|byte| *byte != separator)?;
    let from_token = text.get(start..).unwrap_or_default();
    match from_token.iter().position(|byte| *byte == separator) {
        None => Some((from_token, None)),
        Some(end) => {
            let rest = from_token.get(end.saturating_add(1)..).unwrap_or_default();
            Some((
                from_token.get(..end).unwrap_or_default(),
                (!rest.is_empty()).then_some(rest),
            ))
        }
    }
}

pub fn without_comments(text: &[u8]) -> Option<Vec<u8>> {
    if !text.contains(&b'(') {
        return None;
    }
    let start = text
        .iter()
        .position(|byte| !is_c_space(*byte))
        .unwrap_or(text.len());
    let mut out = Vec::with_capacity(text.len());
    let mut escaped = false;
    let mut quoted = false;
    let mut depth = 0usize;
    for &byte in text.get(start..).unwrap_or_default() {
        if escaped {
            if depth == 0 {
                out.push(byte);
            }
            escaped = false;
            continue;
        }
        match byte {
            b'\\' => escaped = true,
            b'"' => {
                out.push(b'"');
                quoted = !quoted;
            }
            b'(' | b')' if quoted => out.push(byte),
            b'(' => depth = depth.saturating_add(1),
            b')' => depth = depth.saturating_sub(1),
            other => {
                if depth == 0 {
                    out.push(other);
                }
            }
        }
    }
    if escaped {
        out.push(b'\\');
    }
    Some(out)
}

pub fn without_comments_or_as_is(text: &[u8]) -> Vec<u8> {
    without_comments(text).unwrap_or_else(|| text.to_vec())
}

pub fn parameter_value(argument: &[u8]) -> Vec<u8> {
    if contains(argument, b"*0*=") {
        return unfinished_continuation(argument);
    }
    let (marker, in_contents) = match find(argument, b"*0=") {
        Some(at) => (Some(at), true),
        None => (find(argument, b"*="), false),
    };
    let Some(marker) = marker else {
        return argument.iter().map(|byte| byte & 0x7f).collect();
    };
    let mut out = argument.get(..marker).unwrap_or_default().to_vec();
    out.push(b'=');
    let after_equals = argument
        .get(marker..)
        .unwrap_or_default()
        .iter()
        .position(|byte| *byte == b'=')
        .map_or(argument.len(), |equals| {
            marker.saturating_add(equals).saturating_add(1)
        });
    let rest = argument.get(after_equals..).unwrap_or_default();
    let mut part = if in_contents {
        ParameterPart::Contents
    } else {
        ParameterPart::Language
    };
    let mut at = 0usize;
    while let Some(&byte) = rest.get(at) {
        match part {
            ParameterPart::Language if byte == b'\'' => part = ParameterPart::Charset,
            ParameterPart::Charset if byte == b'\'' => part = ParameterPart::Contents,
            ParameterPart::Language | ParameterPart::Charset => {}
            ParameterPart::Contents if byte == b'%' => {
                at = at.saturating_add(1);
                let Some(&high) = rest.get(at) else {
                    break;
                };
                at = at.saturating_add(1);
                let Some(&low) = rest.get(at) else {
                    out.push(hex_digit(high));
                    break;
                };
                out.push(hex_digit(high).wrapping_shl(4).wrapping_add(hex_digit(low)));
            }
            ParameterPart::Contents => out.push(byte),
        }
        at = at.saturating_add(1);
    }
    if part != ParameterPart::Contents {
        return Vec::new();
    }
    out
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ParameterPart {
    Language,
    Charset,
    Contents,
}

fn unfinished_continuation(argument: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(argument.len().saturating_add(16));
    let mut at = 0usize;
    while let Some(&byte) = argument.get(at) {
        match byte {
            b'*' => {
                let closing = argument
                    .get(at.saturating_add(1)..)
                    .unwrap_or_default()
                    .iter()
                    .position(|next| *next == b'*');
                let Some(closing) = closing else {
                    break;
                };
                at = at.saturating_add(closing).saturating_add(2);
            }
            b'=' => {
                out.extend_from_slice(FAILED_CONTINUATION);
                break;
            }
            other => {
                out.push(other);
                at = at.saturating_add(1);
            }
        }
    }
    out
}

pub fn with_encoded_words_decoded(line: &[u8]) -> Option<Vec<u8>> {
    if find(line, b"=?").is_none() || find(line, b"?=").is_none() {
        return Some(line.to_vec());
    }
    let mut out = Vec::with_capacity(line.len());
    let mut at = 0usize;
    while at < line.len() {
        while let Some(&byte) = line.get(at) {
            if byte == b'=' && line.get(at.saturating_add(1)) == Some(&b'?') {
                at = at.saturating_add(2);
                break;
            }
            out.push(byte);
            at = at.saturating_add(1);
        }
        while line.get(at).is_some_and(|byte| *byte != b'?') {
            at = at.saturating_add(1);
        }
        if at >= line.len() {
            break;
        }
        at = at.saturating_add(1);
        let encoding = line.get(at).copied().unwrap_or(0).to_ascii_lowercase();
        if encoding != b'q' && encoding != b'b' {
            return None;
        }
        at = at.saturating_add(1);
        if line.get(at) != Some(&b'?') {
            break;
        }
        at = at.saturating_add(1);
        if at >= line.len() {
            break;
        }
        let encoded_and_after = line.get(at..).unwrap_or_default();
        let Some(end) = find(encoded_and_after, b"?=") else {
            break;
        };
        let encoded = encoded_and_after.get(..end).unwrap_or_default();
        at = at.saturating_add(end).saturating_add(2);
        let mut decoded = decoded_word(encoded, encoding == b'q');
        if decoded.last() == Some(&b'\n') {
            decoded.pop();
        }
        out.extend_from_slice(&decoded);
    }
    Some(up_to_the_first_nul(&out).to_vec())
}

fn decoded_word(encoded: &[u8], quoted_printable_word: bool) -> Vec<u8> {
    let stored: Option<&[u8]> = if encoded.is_empty() {
        None
    } else if encoded.iter().all(|byte| is_c_space(*byte)) {
        Some(b" ")
    } else {
        Some(encoded)
    };
    let mut out = Vec::new();
    if quoted_printable_word {
        quoted_printable(stored, &mut out);
    } else {
        let mut carry = Base64Carry::default();
        base64(stored, &mut carry, &mut out);
        base64_flush(&mut carry, &mut out);
    }
    out
}

pub fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

pub fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    find(haystack, needle).is_some()
}

pub fn starts_with_ignoring_case(text: &[u8], prefix: &[u8]) -> bool {
    text.get(..prefix.len())
        .is_some_and(|start| start.eq_ignore_ascii_case(prefix))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fields_are_split_on_runs_of_delimiters_and_the_first_starts_at_the_first_byte() {
        assert_eq!(field(b"a;;b; c", 1, b";"), Some(b"b".as_slice()));
        assert_eq!(field(b"a;;b; c", 2, b";"), Some(b" c".as_slice()));
        assert_eq!(field(b";a", 0, b";"), None);
        assert_eq!(field(b"a", 1, b";"), None);
    }

    #[test]
    fn comments_outside_quotes_are_removed() {
        assert_eq!(
            without_comments(b"  text/plain (a (b) c) \"(kept)\""),
            Some(b"text/plain  \"(kept)\"".to_vec())
        );
    }

    #[test]
    fn a_parameter_without_an_extended_value_loses_its_high_bits() {
        assert_eq!(parameter_value(b"name=\xe9"), b"name=i".to_vec());
        assert_eq!(
            parameter_value(b"filename*=utf-8''a%41b"),
            b"filename=aAb".to_vec()
        );
        assert_eq!(
            parameter_value(b"filename*0*=utf-8''a"),
            b"filename=rfc2231failure".to_vec()
        );
    }

    #[test]
    fn encoded_words_are_decoded() {
        assert_eq!(
            with_encoded_words_decoded(b"name=\"=?utf-8?B?YS5leGU=?=\""),
            Some(b"name=\"a.exe\"".to_vec())
        );
        assert_eq!(
            with_encoded_words_decoded(b"x =?iso?Q?a=41_b?= y"),
            Some(b"x aA_b y".to_vec())
        );
        assert_eq!(with_encoded_words_decoded(b"=?x?z?abc?="), None);
    }
}
