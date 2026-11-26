#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    clippy::cast_possible_truncation
)]

use debar_image::{
    Assertion, BacktrackingProgram, ByteSet, ExpressionTree, Greed, LookDirection, TreeRepetition,
    compile_backtracking,
};
use debar_matching::{BacktrackingBounds, BacktrackingSearch, backtracking_search};
use regex_automata::{Input, MatchKind, meta};

fn bytes(text: &[u8]) -> ExpressionTree {
    ExpressionTree::literal(text)
}

fn set(members: &[u8]) -> ExpressionTree {
    ExpressionTree::Byte(ByteSet::of(members.iter().copied()))
}

fn word() -> ExpressionTree {
    ExpressionTree::Byte(ByteSet::of(
        (0..=u8::MAX).filter(|byte| byte.is_ascii_alphanumeric() || *byte == b'_'),
    ))
}

fn any() -> ExpressionTree {
    ExpressionTree::Byte(ByteSet::of(0..=u8::MAX))
}

fn concat(items: Vec<ExpressionTree>) -> ExpressionTree {
    ExpressionTree::Concat(items)
}

fn alternation(branches: Vec<ExpressionTree>) -> ExpressionTree {
    ExpressionTree::Alternation(branches)
}

fn repeat(item: ExpressionTree, min: u32, max: Option<u32>, greed: Greed) -> ExpressionTree {
    ExpressionTree::Repetition(Box::new(TreeRepetition {
        min,
        max,
        greed,
        item,
    }))
}

fn capture(group: u32, item: ExpressionTree) -> ExpressionTree {
    ExpressionTree::Capture {
        group,
        item: Box::new(item),
    }
}

fn reference(group: u32) -> ExpressionTree {
    ExpressionTree::Backreference {
        group,
        caseless: false,
    }
}

fn look(direction: LookDirection, negated: bool, item: ExpressionTree) -> ExpressionTree {
    ExpressionTree::Lookaround {
        direction,
        negated,
        item: Box::new(item),
    }
}

fn search(tree: &ExpressionTree, subject: &[u8]) -> BacktrackingSearch {
    let program = compile_backtracking(tree).unwrap();
    let program = BacktrackingProgram::read(&program).unwrap();
    backtracking_search(
        &program,
        subject,
        0,
        false,
        BacktrackingBounds::FOR_SIGNATURES,
    )
    .unwrap()
}

fn found(tree: &ExpressionTree, subject: &[u8]) -> Option<(usize, usize)> {
    match search(tree, subject) {
        BacktrackingSearch::Found { start, end } => Some((start, end)),
        BacktrackingSearch::NotFound | BacktrackingSearch::GaveUp => None,
    }
}

#[test]
fn a_backreference_matches_only_what_its_group_captured() {
    let tree = concat(vec![
        capture(1, repeat(word(), 1, None, Greed::Greedy)),
        bytes(b"="),
        reference(1),
    ]);
    assert_eq!(found(&tree, b"x abc=abc"), Some((2, 9)));
    assert_eq!(found(&tree, b"abc=abd"), None);
    assert_eq!(found(&tree, b"abc=bc"), Some((1, 6)));
}

#[test]
fn a_caseless_backreference_ignores_ascii_case() {
    let tree = concat(vec![
        capture(1, bytes(b"ab")),
        ExpressionTree::Backreference {
            group: 1,
            caseless: true,
        },
    ]);
    assert_eq!(found(&tree, b"abAB"), Some((0, 4)));
    assert_eq!(found(&tree, b"ab\xc1\xc2"), None);
}

#[test]
fn a_backreference_to_a_group_that_took_no_part_fails() {
    let tree = concat(vec![
        alternation(vec![capture(1, bytes(b"a")), bytes(b"b")]),
        reference(1),
    ]);
    assert_eq!(found(&tree, b"b"), None);
    assert_eq!(found(&tree, b"aa"), Some((0, 2)));
}

#[test]
fn a_backreference_sees_the_last_iteration_of_a_repeated_group() {
    let tree = concat(vec![
        repeat(capture(1, set(b"ab")), 2, Some(2), Greed::Greedy),
        reference(1),
    ]);
    assert_eq!(found(&tree, b"abb"), Some((0, 3)));
    assert_eq!(found(&tree, b"aba"), None);
}

#[test]
fn lookahead_and_lookbehind_test_without_consuming() {
    let ahead = concat(vec![
        bytes(b"a"),
        look(LookDirection::Ahead, false, bytes(b"b")),
    ]);
    assert_eq!(found(&ahead, b"acab"), Some((2, 3)));
    let not_ahead = concat(vec![
        bytes(b"a"),
        look(LookDirection::Ahead, true, bytes(b"b")),
    ]);
    assert_eq!(found(&not_ahead, b"abac"), Some((2, 3)));
    let behind = concat(vec![
        look(LookDirection::Behind, false, bytes(b"x")),
        bytes(b"a"),
    ]);
    assert_eq!(found(&behind, b"ayaxa"), Some((4, 5)));
    let not_behind = concat(vec![
        look(LookDirection::Behind, true, word()),
        bytes(b"inject"),
    ]);
    assert_eq!(found(&not_behind, b"reinject inject"), Some((9, 15)));
}

#[test]
fn a_lookbehind_with_branches_of_different_lengths_tests_each() {
    let tree = concat(vec![
        bytes(b"("),
        look(
            LookDirection::Behind,
            true,
            alternation(vec![bytes(b"Unix("), bytes(b"Inet4("), bytes(b"Any(")]),
        ),
        bytes(b"x"),
    ]);
    assert_eq!(found(&tree, b"Unix(x"), None);
    assert_eq!(found(&tree, b"Inet4(x"), None);
    assert_eq!(found(&tree, b"Other(x"), Some((5, 7)));
}

#[test]
fn an_atomic_group_never_gives_back_what_it_matched() {
    let atomic = concat(vec![
        ExpressionTree::Atomic(Box::new(repeat(any(), 0, None, Greed::Greedy))),
        bytes(b"b"),
    ]);
    assert_eq!(found(&atomic, b"aab"), None);
    let plain = concat(vec![repeat(any(), 0, None, Greed::Greedy), bytes(b"b")]);
    assert_eq!(found(&plain, b"aab"), Some((0, 3)));
}

#[test]
fn a_possessive_quantifier_never_gives_back_what_it_matched() {
    let tree = concat(vec![
        repeat(set(b"a"), 1, None, Greed::Possessive),
        bytes(b"a"),
    ]);
    assert_eq!(found(&tree, b"aaa"), None);
    let group = concat(vec![
        repeat(capture(1, bytes(b"ab")), 1, None, Greed::Possessive),
        bytes(b"ab"),
    ]);
    assert_eq!(found(&group, b"ababab"), None);
}

#[test]
fn a_lazy_repetition_takes_as_little_as_it_can() {
    let tree = concat(vec![
        bytes(b"<"),
        repeat(any(), 0, None, Greed::Lazy),
        bytes(b">"),
    ]);
    assert_eq!(found(&tree, b"<a><b>"), Some((0, 3)));
}

#[test]
fn an_end_assertion_holds_before_a_final_newline_without_consuming_it() {
    let tree = concat(vec![
        bytes(b"a"),
        ExpressionTree::Assertion(Assertion::SubjectEndOrBeforeFinalNewline),
        bytes(b"\n"),
    ]);
    assert_eq!(found(&tree, b"a\n"), Some((0, 2)));
    assert_eq!(found(&tree, b"a\nb"), None);
}

#[test]
fn a_multiline_line_start_does_not_hold_after_a_final_newline() {
    let tree = concat(vec![
        bytes(b"\n"),
        ExpressionTree::Assertion(Assertion::LineStartNotAtSubjectEnd),
    ]);
    assert_eq!(found(&tree, b"a\n"), None);
    assert_eq!(found(&tree, b"a\nb"), Some((1, 2)));
}

#[test]
fn an_expression_that_exhausts_the_step_bound_does_not_match() {
    let nested = concat(vec![
        repeat(
            capture(1, repeat(set(b"a"), 1, None, Greed::Greedy)),
            1,
            None,
            Greed::Greedy,
        ),
        bytes(b"b"),
    ]);
    let mut subject = vec![b'a'; 25];
    subject.extend_from_slice(b"cab");
    assert_eq!(search(&nested, &subject), BacktrackingSearch::GaveUp);
    assert_eq!(found(&nested, b"aaaab"), Some((0, 5)));
}

#[test]
fn an_expression_that_exhausts_the_depth_bound_does_not_match() {
    let tree = concat(vec![
        repeat(
            alternation(vec![bytes(b"a"), bytes(b"ab")]),
            0,
            None,
            Greed::Greedy,
        ),
        bytes(b"c"),
    ]);
    let subject = |count: usize| {
        let mut subject = vec![b'a'; count];
        subject.push(b'c');
        subject
    };
    assert_eq!(found(&tree, &subject(500)), Some((0, 501)));
    assert_eq!(search(&tree, &subject(5_000)), BacktrackingSearch::GaveUp);
}

#[test]
fn a_repeated_group_that_can_match_nothing_stops_repeating() {
    let tree = concat(vec![
        repeat(
            capture(1, repeat(set(b"a"), 0, None, Greed::Greedy)),
            0,
            None,
            Greed::Greedy,
        ),
        bytes(b"b"),
    ]);
    assert_eq!(found(&tree, b"xxb"), Some((2, 3)));
    assert_eq!(found(&tree, b"aab"), Some((0, 3)));
}

#[test]
fn an_anchored_search_tries_only_its_starting_position() {
    let program = compile_backtracking(&bytes(b"b")).unwrap();
    let program = BacktrackingProgram::read(&program).unwrap();
    assert_eq!(
        backtracking_search(&program, b"ab", 0, true, BacktrackingBounds::FOR_SIGNATURES).unwrap(),
        BacktrackingSearch::NotFound
    );
    assert_eq!(
        backtracking_search(&program, b"ab", 1, true, BacktrackingBounds::FOR_SIGNATURES).unwrap(),
        BacktrackingSearch::Found { start: 1, end: 2 }
    );
}

#[test]
fn a_malformed_program_is_refused_or_never_matches_without_panicking() {
    let program =
        compile_backtracking(&concat(vec![capture(1, bytes(b"ab")), reference(1)])).unwrap();
    for cut in 0..program.len() {
        let _ = BacktrackingProgram::read(&program[..cut]);
    }
    for position in 0..program.len() {
        for value in [0u8, 1, 0x7f, 0xff] {
            let mut damaged = program.clone();
            damaged[position] = value;
            if let Ok(view) = BacktrackingProgram::read(&damaged) {
                let _ = backtracking_search(
                    &view,
                    b"ababab",
                    0,
                    false,
                    BacktrackingBounds::FOR_SIGNATURES,
                );
            }
        }
    }
}

struct Random(u64);

impl Random {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, bound: u64) -> u64 {
        self.next() % bound
    }
}

const ALPHABET: [u8; 4] = *b"ab \n";

fn random_tree(random: &mut Random, depth: u32, groups: &mut u32) -> ExpressionTree {
    let choice = if depth == 0 {
        random.below(3)
    } else {
        random.below(9)
    };
    match choice {
        0 => ExpressionTree::literal(&[ALPHABET[random.below(4) as usize]]),
        1 => {
            let members: Vec<u8> = ALPHABET
                .iter()
                .copied()
                .filter(|_| random.below(2) == 0)
                .collect();
            if members.is_empty() {
                ExpressionTree::literal(b"a")
            } else {
                ExpressionTree::Byte(ByteSet::of(members))
            }
        }
        2 => ExpressionTree::Assertion(match random.below(5) {
            0 => Assertion::SubjectStart,
            1 => Assertion::SubjectEnd,
            2 => Assertion::WordBoundary,
            3 => Assertion::NotWordBoundary,
            _ => Assertion::LineEnd,
        }),
        3 | 4 => ExpressionTree::Concat(
            (0..=random.below(3))
                .map(|_| random_tree(random, depth - 1, groups))
                .collect(),
        ),
        5 => ExpressionTree::Alternation(
            (0..=random.below(2) + 1)
                .map(|_| random_tree(random, depth - 1, groups))
                .collect(),
        ),
        6 | 7 => {
            let min = random.below(3) as u32;
            let max = match random.below(3) {
                0 => None,
                _ => Some(min + random.below(3) as u32),
            };
            let greed = if random.below(2) == 0 {
                Greed::Greedy
            } else {
                Greed::Lazy
            };
            let item = random_tree(random, depth - 1, groups);
            if item.shortest_match() == 0 {
                return item;
            }
            repeat(item, min, max, greed)
        }
        _ => {
            *groups += 1;
            capture(*groups, random_tree(random, depth - 1, groups))
        }
    }
}

fn random_subject(random: &mut Random) -> Vec<u8> {
    (0..random.below(12))
        .map(|_| ALPHABET[random.below(4) as usize])
        .collect()
}

#[test]
fn the_backtracking_engine_agrees_with_the_linear_engine_where_both_can_match() {
    let mut random = Random(0x9e37_79b9_7f4a_7c15);
    let mut compared = 0;
    for _ in 0..4_000 {
        let mut groups = 0;
        let tree = random_tree(&mut random, 4, &mut groups);
        let hir = tree.linear_form().unwrap();
        let Ok(linear) = meta::Builder::new()
            .configure(
                meta::Config::new()
                    .match_kind(MatchKind::LeftmostFirst)
                    .utf8_empty(false),
            )
            .build_from_hir(&hir)
        else {
            continue;
        };
        let program = compile_backtracking(&tree).unwrap();
        let program = BacktrackingProgram::read(&program).unwrap();
        for _ in 0..8 {
            let subject = random_subject(&mut random);
            let expected = linear
                .search(&Input::new(&subject))
                .map(|found| (found.start(), found.end()));
            let actual = match backtracking_search(
                &program,
                &subject,
                0,
                false,
                BacktrackingBounds::FOR_SIGNATURES,
            )
            .unwrap()
            {
                BacktrackingSearch::Found { start, end } => Some((start, end)),
                BacktrackingSearch::NotFound => None,
                BacktrackingSearch::GaveUp => continue,
            };
            assert_eq!(
                actual,
                expected,
                "pattern {hir} on {:?}",
                String::from_utf8_lossy(&subject)
            );
            compared += 1;
        }
    }
    assert!(compared > 20_000);
}
