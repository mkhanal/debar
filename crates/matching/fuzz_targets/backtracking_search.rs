#![no_main]

use debar_image::{
    Assertion, BacktrackingProgram, ByteSet, ExpressionTree, Greed, LookDirection, TreeRepetition,
    compile_backtracking,
};
use debar_matching::{BacktrackingBounds, backtracking_search};
use libfuzzer_sys::fuzz_target;

const FUZZ_BOUNDS: BacktrackingBounds = BacktrackingBounds {
    steps_per_start: 2_000,
    live_choices: 200,
};
const DEEPEST: u32 = 6;
const LONGEST_SUBJECT: usize = 256;
const ASSERTIONS: [Assertion; 7] = [
    Assertion::SubjectStart,
    Assertion::SubjectEnd,
    Assertion::SubjectEndOrBeforeFinalNewline,
    Assertion::LineStartNotAtSubjectEnd,
    Assertion::LineEnd,
    Assertion::WordBoundary,
    Assertion::NotWordBoundary,
];

struct Bytes<'d> {
    data: &'d [u8],
    groups: u32,
}

impl Bytes<'_> {
    fn next(&mut self) -> u8 {
        match self.data.split_first() {
            Some((first, rest)) => {
                self.data = rest;
                *first
            }
            None => 0,
        }
    }

    fn tree(&mut self, depth: u32) -> ExpressionTree {
        let choice = if depth >= DEEPEST { self.next() % 3 } else { self.next() % 12 };
        let child = |bytes: &mut Self| Box::new(bytes.tree(depth + 1));
        match choice {
            0 => ExpressionTree::Byte(ByteSet::of([self.next() % 4 + b'a'])),
            1 => {
                let low = self.next();
                let high = low.saturating_add(self.next() % 8);
                ExpressionTree::Byte(ByteSet::of(low..=high))
            }
            2 => ExpressionTree::Assertion(ASSERTIONS[usize::from(self.next()) % ASSERTIONS.len()]),
            3 | 4 => ExpressionTree::Concat((0..self.next() % 4).map(|_| self.tree(depth + 1)).collect()),
            5 => ExpressionTree::Alternation((0..=self.next() % 3).map(|_| self.tree(depth + 1)).collect()),
            6 => {
                let min = u32::from(self.next() % 4);
                let max = match self.next() % 3 {
                    0 => None,
                    _ => Some(min + u32::from(self.next() % 4)),
                };
                let greed = [Greed::Greedy, Greed::Lazy, Greed::Possessive][usize::from(self.next() % 3)];
                ExpressionTree::Repetition(Box::new(TreeRepetition {
                    min,
                    max,
                    greed,
                    item: self.tree(depth + 1),
                }))
            }
            7 => {
                self.groups += 1;
                ExpressionTree::Capture {
                    group: self.groups,
                    item: child(self),
                }
            }
            8 if self.groups > 0 => ExpressionTree::Backreference {
                group: 1 + u32::from(self.next()) % self.groups,
                caseless: self.next() % 2 == 0,
            },
            9 => ExpressionTree::Lookaround {
                direction: if self.next() % 2 == 0 { LookDirection::Ahead } else { LookDirection::Behind },
                negated: self.next() % 2 == 0,
                item: child(self),
            },
            10 => ExpressionTree::Atomic(child(self)),
            _ => ExpressionTree::Empty,
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let Some(split) = data.iter().position(|byte| *byte == 0xff) else {
        return;
    };
    let (shape, rest) = data.split_at(split);
    let subject = rest.get(1..).unwrap_or_default();
    let subject = &subject[..subject.len().min(LONGEST_SUBJECT)];
    if shape.first() == Some(&0) {
        if let Ok(program) = BacktrackingProgram::read(shape) {
            let _ = backtracking_search(&program, subject, 0, false, FUZZ_BOUNDS);
        }
        return;
    }
    let mut bytes = Bytes { data: shape, groups: 0 };
    let tree = bytes.tree(0);
    let Ok(program) = compile_backtracking(&tree) else {
        return;
    };
    let program = BacktrackingProgram::read(&program).expect("a compiled program reads back");
    let _ = backtracking_search(&program, subject, 0, false, FUZZ_BOUNDS);
    let _ = backtracking_search(&program, subject, subject.len() / 2, true, FUZZ_BOUNDS);
});
