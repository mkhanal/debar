use crate::mail::header_text::{contains, starts_with_ignoring_case, without_comments_or_as_is};

pub fn is_boundary_start(line: &[u8], boundary: Option<&[u8]>) -> bool {
    let Some(boundary) = boundary else {
        return false;
    };
    let trimmed = without_trailing_spaces(line);
    if !matches!(trimmed.first(), Some(b'-' | b'(')) || !trimmed.contains(&b'-') {
        return false;
    }
    let cleaned = without_comments_or_as_is(trimmed);
    if cleaned.first() != Some(&b'-') || cleaned.len() < 2 {
        return false;
    }
    let after_the_first_dash = cleaned.get(1..).unwrap_or_default();
    let mentioned = contains(after_the_first_dash.get(1..).unwrap_or_default(), boundary)
        || contains(trimmed, boundary);
    if mentioned {
        return ends_in_the_boundary_after_dashes(&cleaned, boundary)
            || ends_in_the_boundary_after_dashes(line, boundary);
    }
    after_the_first_dash.first() == Some(&b'-')
        && after_the_first_dash
            .get(1..)
            .is_some_and(|rest| rest.eq_ignore_ascii_case(boundary))
}

pub fn is_boundary_end(line: &[u8], boundary: &[u8]) -> bool {
    let trimmed = without_trailing_spaces(line);
    let Some(after_dashes) = trimmed.strip_prefix(b"--") else {
        return false;
    };
    if !starts_with_ignoring_case(after_dashes, boundary)
        || after_dashes.len() < boundary.len().saturating_add(2)
    {
        return false;
    }
    after_dashes
        .get(boundary.len()..)
        .is_some_and(|rest| rest.starts_with(b"--"))
}

fn ends_in_the_boundary_after_dashes(text: &[u8], boundary: &[u8]) -> bool {
    let mut at = 2usize;
    loop {
        let Some(rest) = text.get(at..) else {
            return false;
        };
        if rest == boundary {
            return true;
        }
        if text.get(at) != Some(&b'-') {
            return false;
        }
        at = at.saturating_add(1);
    }
}

fn without_trailing_spaces(line: &[u8]) -> &[u8] {
    let kept = line
        .iter()
        .rposition(|byte| *byte != b' ')
        .map_or(0, |last| last.saturating_add(1));
    line.get(..kept).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_boundary_line_starts_a_part_even_with_extra_dashes_or_any_second_byte() {
        assert!(is_boundary_start(b"--abc", Some(b"abc")));
        assert!(is_boundary_start(b"----abc  ", Some(b"abc")));
        assert!(is_boundary_start(b"-Xabc", Some(b"abc")));
        assert!(is_boundary_start(b"--ABC", Some(b"abc")));
        assert!(!is_boundary_start(b"--abcd", Some(b"abc")));
        assert!(!is_boundary_start(b"abc", Some(b"abc")));
    }

    #[test]
    fn a_closing_boundary_is_the_boundary_between_two_pairs_of_dashes() {
        assert!(is_boundary_end(b"--abc--", b"abc"));
        assert!(is_boundary_end(b"--ABC-- trailing", b"abc"));
        assert!(!is_boundary_end(b"--abc", b"abc"));
        assert!(!is_boundary_end(b"--abc-", b"abc"));
    }
}
