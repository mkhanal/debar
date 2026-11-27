use crate::mail::header_text::without_trailing_unprintables;

pub const IDENTICAL: i32 = 100;
const LONGEST_COMPARED: usize = 49;
const TOO_LONG_TO_COMPARE: i32 = -5;

pub fn similarity(first: &[u8], second: &[u8]) -> i32 {
    if first.eq_ignore_ascii_case(second) {
        return IDENTICAL;
    }
    let first = without_trailing_unprintables(first);
    let second = without_trailing_unprintables(second);
    if first.len() > LONGEST_COMPARED || second.len() > LONGEST_COMPARED {
        return TOO_LONG_TO_COMPARE;
    }
    let total = first.len().saturating_add(second.len());
    let mut pending: Vec<(Vec<u8>, Vec<u8>)> = vec![(first.to_vec(), second.to_vec())];
    let mut score = 0usize;
    while let Some((left, right)) = pending.pop() {
        let Some(common) = longest_common_run(&left, &right) else {
            continue;
        };
        score = score.saturating_add(common.length);
        let left_before = left.get(..common.left_start).unwrap_or_default();
        let right_before = right.get(..common.right_start).unwrap_or_default();
        let left_after = left.get(common.left_end..).unwrap_or_default();
        let right_after = right.get(common.right_end..).unwrap_or_default();
        if worth_comparing(left_before, right_before) {
            pending.push((left_before.to_vec(), right_before.to_vec()));
        }
        if worth_comparing(left_after, right_after) {
            pending.push((left_after.to_vec(), right_after.to_vec()));
        }
    }
    if total == 0 {
        return 0;
    }
    i32::try_from(score.saturating_mul(200).checked_div(total).unwrap_or(0)).unwrap_or(0)
}

fn worth_comparing(left: &[u8], right: &[u8]) -> bool {
    (left.len() > 1 && !right.is_empty()) || (right.len() > 1 && !left.is_empty())
}

struct CommonRun {
    length: usize,
    left_start: usize,
    left_end: usize,
    right_start: usize,
    right_end: usize,
}

fn longest_common_run(left: &[u8], right: &[u8]) -> Option<CommonRun> {
    let same = |left_at: usize, right_at: usize| {
        let left_byte = left.get(left_at).copied().unwrap_or(0);
        let right_byte = right.get(right_at).copied().unwrap_or(0);
        left_byte.eq_ignore_ascii_case(&right_byte)
    };
    let mut left_end = left.len();
    let mut right_end = right.len();
    let mut best: Option<CommonRun> = None;
    let mut start = 0usize;
    while start < left_end {
        let mut left_at = start;
        let mut right_at = 0usize;
        while left_at < left_end && right_at < right_end {
            if !same(left_at, right_at) {
                right_at = right_at.saturating_add(1);
                continue;
            }
            let (run_left, run_right) = (left_at, right_at);
            let mut length = 0usize;
            loop {
                if left_at == left_end || right_at == right_end {
                    break;
                }
                left_at = left_at.saturating_add(1);
                right_at = right_at.saturating_add(1);
                length = length.saturating_add(1);
                if left_at >= left.len() || right_at >= right.len() || !same(left_at, right_at) {
                    break;
                }
            }
            let longest = best.as_ref().map_or(0, |run| run.length);
            if length > longest {
                let grown = length.saturating_sub(longest);
                best = Some(CommonRun {
                    length,
                    left_start: run_left,
                    left_end: left_at,
                    right_start: run_right,
                    right_end: right_at,
                });
                left_end = left_end.saturating_sub(grown);
                right_end = right_end.saturating_sub(grown);
            } else {
                left_at = left_at.saturating_sub(length);
            }
        }
        start = start.saturating_add(1);
    }
    best
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identical_names_ignoring_case_score_a_hundred() {
        assert_eq!(similarity(b"Base64", b"base64"), IDENTICAL);
    }

    #[test]
    fn a_close_name_scores_by_the_runs_it_shares() {
        assert_eq!(similarity(b"7-bit", b"7bit"), 66);
        assert_eq!(similarity(b"base64;", b"base64"), 92);
    }

    #[test]
    fn a_name_longer_than_forty_nine_bytes_is_not_compared() {
        assert_eq!(similarity(&[b'a'; 50], b"base64"), TOO_LONG_TO_COMPARE);
    }
}
