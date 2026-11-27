use std::ops::ControlFlow;

use debar_image::{InPlaceAutomaton, LazyExpression};
use debar_platform::input::InputError;
use regex_automata::Anchored;
use regex_automata::dfa::Automaton as _;
use regex_automata::hybrid::LazyStateID;
use regex_automata::hybrid::dfa::{Cache, DFA};
use regex_automata::util::primitives::StateID;
use regex_automata::util::start;

use crate::backtracking_search::SubjectBytes as _;
use crate::whole_object::{ObjectPages, PagedSubject};

#[derive(Debug)]
pub(crate) enum PagedSearchFailure {
    Unsearchable,
    Input(InputError),
}

impl From<InputError> for PagedSearchFailure {
    fn from(error: InputError) -> Self {
        Self::Input(error)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Reached {
    Searching,
    Match,
    Dead,
    Quit,
}

trait Stepping {
    type State: Copy;

    fn start(&mut self, look_behind: Option<u8>, anchored: Anchored) -> Option<Self::State>;

    fn next(&mut self, state: Self::State, byte: u8) -> Option<Self::State>;

    fn end_of_input(&mut self, state: Self::State) -> Option<Self::State>;

    fn is_special(&self, state: Self::State) -> bool;

    fn reached(&self, state: Self::State) -> Reached;

    fn leaving_bytes(&self, state: Self::State) -> &[u8];
}

struct InPlaceStepping<'a, 'm>(&'a InPlaceAutomaton<'m>);

impl Stepping for InPlaceStepping<'_, '_> {
    type State = StateID;

    fn start(&mut self, look_behind: Option<u8>, anchored: Anchored) -> Option<StateID> {
        self.0
            .start_state(
                &start::Config::new()
                    .look_behind(look_behind)
                    .anchored(anchored),
            )
            .ok()
    }

    fn next(&mut self, state: StateID, byte: u8) -> Option<StateID> {
        Some(self.0.next_state(state, byte))
    }

    fn end_of_input(&mut self, state: StateID) -> Option<StateID> {
        Some(self.0.next_eoi_state(state))
    }

    fn is_special(&self, state: StateID) -> bool {
        self.0.is_special_state(state)
    }

    fn reached(&self, state: StateID) -> Reached {
        if self.0.is_match_state(state) {
            Reached::Match
        } else if self.0.is_dead_state(state) {
            Reached::Dead
        } else if self.0.is_quit_state(state) {
            Reached::Quit
        } else {
            Reached::Searching
        }
    }

    fn leaving_bytes(&self, state: StateID) -> &[u8] {
        if self.0.is_accel_state(state) && !self.0.is_match_state(state) {
            self.0.accelerator(state)
        } else {
            &[]
        }
    }
}

struct LazyStepping<'a> {
    automaton: &'a DFA,
    cache: &'a mut Cache,
}

impl Stepping for LazyStepping<'_> {
    type State = LazyStateID;

    fn start(&mut self, look_behind: Option<u8>, anchored: Anchored) -> Option<LazyStateID> {
        self.automaton
            .start_state(
                self.cache,
                &start::Config::new()
                    .look_behind(look_behind)
                    .anchored(anchored),
            )
            .ok()
    }

    fn next(&mut self, state: LazyStateID, byte: u8) -> Option<LazyStateID> {
        self.automaton.next_state(self.cache, state, byte).ok()
    }

    fn end_of_input(&mut self, state: LazyStateID) -> Option<LazyStateID> {
        self.automaton.next_eoi_state(self.cache, state).ok()
    }

    fn is_special(&self, state: LazyStateID) -> bool {
        state.is_tagged()
    }

    fn reached(&self, state: LazyStateID) -> Reached {
        if state.is_match() {
            Reached::Match
        } else if state.is_dead() {
            Reached::Dead
        } else if state.is_quit() || state.is_unknown() {
            Reached::Quit
        } else {
            Reached::Searching
        }
    }

    fn leaving_bytes(&self, _state: LazyStateID) -> &[u8] {
        &[]
    }
}

pub(crate) fn search_in_place(
    forward: &InPlaceAutomaton<'_>,
    reverse: &InPlaceAutomaton<'_>,
    subject: &mut PagedSubject<'_, '_>,
    from: usize,
    anchored: Anchored,
) -> Result<Option<(usize, usize)>, PagedSearchFailure> {
    let anchored_at_from = anchored == Anchored::Yes || forward.is_always_start_anchored();
    search(
        &mut InPlaceStepping(forward),
        &mut InPlaceStepping(reverse),
        anchored_at_from,
        subject,
        from,
        anchored,
    )
}

pub(crate) fn search_lazily(
    expression: &LazyExpression,
    cache: &mut regex_automata::hybrid::regex::Cache,
    subject: &mut PagedSubject<'_, '_>,
    from: usize,
    anchored: Anchored,
) -> Result<Option<(usize, usize)>, PagedSearchFailure> {
    let anchored_at_from =
        anchored == Anchored::Yes || expression.forward().get_nfa().is_always_start_anchored();
    let (forward_cache, reverse_cache) = cache.as_parts_mut();
    search(
        &mut LazyStepping {
            automaton: expression.forward(),
            cache: forward_cache,
        },
        &mut LazyStepping {
            automaton: expression.reverse(),
            cache: reverse_cache,
        },
        anchored_at_from,
        subject,
        from,
        anchored,
    )
}

fn search<F: Stepping, R: Stepping>(
    forward: &mut F,
    reverse: &mut R,
    anchored_at_from: bool,
    subject: &mut PagedSubject<'_, '_>,
    from: usize,
    anchored: Anchored,
) -> Result<Option<(usize, usize)>, PagedSearchFailure> {
    let end = match_end(forward, subject, from, anchored)?;
    match_from_its_end(reverse, anchored_at_from, subject, from, end)
}

pub(crate) fn search_in_place_from_its_end(
    forward: &InPlaceAutomaton<'_>,
    reverse: &InPlaceAutomaton<'_>,
    subject: &mut PagedSubject<'_, '_>,
    from: usize,
    anchored: Anchored,
    end: Option<usize>,
) -> Result<Option<(usize, usize)>, PagedSearchFailure> {
    let anchored_at_from = anchored == Anchored::Yes || forward.is_always_start_anchored();
    match_from_its_end(
        &mut InPlaceStepping(reverse),
        anchored_at_from,
        subject,
        from,
        end,
    )
}

fn match_from_its_end<R: Stepping>(
    reverse: &mut R,
    anchored_at_from: bool,
    subject: &mut PagedSubject<'_, '_>,
    from: usize,
    end: Option<usize>,
) -> Result<Option<(usize, usize)>, PagedSearchFailure> {
    let Some(end) = end else {
        return Ok(None);
    };
    if end == from || anchored_at_from {
        return Ok(Some((from, end)));
    }
    let start =
        match_start(reverse, subject, from, end)?.ok_or(PagedSearchFailure::Unsearchable)?;
    Ok(Some((start, end)))
}

fn match_end<F: Stepping>(
    forward: &mut F,
    subject: &mut PagedSubject<'_, '_>,
    from: usize,
    anchored: Anchored,
) -> Result<Option<usize>, PagedSearchFailure> {
    let look_behind = match from.checked_sub(1) {
        Some(before) => Some(byte_at(subject, before)?),
        None => None,
    };
    let mut scan = ForwardScan::starting(forward, look_behind, from, anchored)?;
    subject.visit_forward(from, |bytes| scan.feed(forward, bytes))?;
    scan.finish(forward, subject.length())
}

struct ForwardScan<State> {
    state: State,
    found: Option<usize>,
    at: usize,
    stopped: Reached,
}

impl<State: Copy> ForwardScan<State> {
    fn starting<F: Stepping<State = State>>(
        forward: &mut F,
        look_behind: Option<u8>,
        from: usize,
        anchored: Anchored,
    ) -> Result<Self, PagedSearchFailure> {
        Ok(Self {
            state: forward
                .start(look_behind, anchored)
                .ok_or(PagedSearchFailure::Unsearchable)?,
            found: None,
            at: from,
            stopped: Reached::Searching,
        })
    }

    fn is_stopped(&self) -> bool {
        matches!(self.stopped, Reached::Dead | Reached::Quit)
    }

    fn feed<F: Stepping<State = State>>(
        &mut self,
        forward: &mut F,
        bytes: &[u8],
    ) -> ControlFlow<()> {
        let mut index = 0usize;
        while let Some(byte) = bytes.get(index) {
            let Some(next) = forward.next(self.state, *byte) else {
                self.stopped = Reached::Quit;
                return ControlFlow::Break(());
            };
            self.state = next;
            if forward.is_special(self.state) {
                match forward.reached(self.state) {
                    Reached::Match => self.found = Some(self.at.saturating_add(index)),
                    Reached::Searching => {
                        index = index.saturating_add(skipped(
                            bytes,
                            index,
                            forward.leaving_bytes(self.state),
                        ));
                    }
                    ended @ (Reached::Dead | Reached::Quit) => {
                        self.stopped = ended;
                        return ControlFlow::Break(());
                    }
                }
            }
            index = index.saturating_add(1);
        }
        self.at = self.at.saturating_add(bytes.len());
        ControlFlow::Continue(())
    }

    fn finish<F: Stepping<State = State>>(
        mut self,
        forward: &mut F,
        subject_length: usize,
    ) -> Result<Option<usize>, PagedSearchFailure> {
        match self.stopped {
            Reached::Dead => return Ok(self.found),
            Reached::Quit => return Err(PagedSearchFailure::Unsearchable),
            Reached::Searching | Reached::Match => {}
        }
        if self.at < subject_length {
            return Err(PagedSearchFailure::Unsearchable);
        }
        self.state = forward
            .end_of_input(self.state)
            .ok_or(PagedSearchFailure::Unsearchable)?;
        if forward.reached(self.state) == Reached::Match {
            self.found = Some(self.at);
        }
        Ok(self.found)
    }
}

pub(crate) struct SharedSearch<'a, 'm> {
    pub forward: &'a InPlaceAutomaton<'m>,
    pub subject_start: usize,
    pub subject_end: usize,
    pub anchored: Anchored,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FirstMatchEnd {
    Unknown,
    Known(Option<usize>),
}

pub(crate) fn first_match_ends_sharing_one_read(
    pages: &mut ObjectPages<'_>,
    searches: &[SharedSearch<'_, '_>],
) -> Result<Vec<FirstMatchEnd>, InputError> {
    let mut object = pages.subject(0, u64::MAX);
    let mut scans: Vec<_> = searches
        .iter()
        .map(|search| {
            ForwardScan::starting(
                &mut InPlaceStepping(search.forward),
                None,
                0,
                search.anchored,
            )
            .ok()
        })
        .collect();
    let from = searches
        .iter()
        .map(|search| search.subject_start)
        .min()
        .unwrap_or(0);
    let mut at = from;
    object.visit_forward(from, |bytes| {
        let bytes_end = at.saturating_add(bytes.len());
        let mut searching = false;
        for (search, scan) in searches.iter().zip(scans.iter_mut()) {
            let Some(scan) = scan.as_mut().filter(|scan| !scan.is_stopped()) else {
                continue;
            };
            let first = search.subject_start.max(at);
            let last = search.subject_end.min(bytes_end);
            let fed = bytes
                .get(first.saturating_sub(at)..last.saturating_sub(at))
                .unwrap_or_default();
            if !fed.is_empty()
                && scan
                    .feed(&mut InPlaceStepping(search.forward), fed)
                    .is_break()
            {
                continue;
            }
            searching |= search.subject_end > bytes_end;
        }
        at = bytes_end;
        if searching {
            ControlFlow::Continue(())
        } else {
            ControlFlow::Break(())
        }
    })?;
    Ok(searches
        .iter()
        .zip(scans)
        .map(|(search, scan)| {
            scan.and_then(|scan| {
                scan.finish(
                    &mut InPlaceStepping(search.forward),
                    search.subject_end.saturating_sub(search.subject_start),
                )
                .ok()
            })
            .map_or(FirstMatchEnd::Unknown, FirstMatchEnd::Known)
        })
        .collect())
}

fn skipped(bytes: &[u8], index: usize, leaving: &[u8]) -> usize {
    if leaving.is_empty() {
        return 0;
    }
    let rest = bytes.get(index.saturating_add(1)..).unwrap_or_default();
    let found = match *leaving {
        [one] => memchr::memchr(one, rest),
        [one, two] => memchr::memchr2(one, two, rest),
        [one, two, three] => memchr::memchr3(one, two, three, rest),
        _ => rest.iter().position(|byte| leaving.contains(byte)),
    };
    found.unwrap_or(rest.len())
}

fn match_start<R: Stepping>(
    reverse: &mut R,
    subject: &mut PagedSubject<'_, '_>,
    from: usize,
    end: usize,
) -> Result<Option<usize>, PagedSearchFailure> {
    let look_behind = if end < subject.length() {
        Some(byte_at(subject, end)?)
    } else {
        None
    };
    let mut state = reverse
        .start(look_behind, Anchored::Yes)
        .ok_or(PagedSearchFailure::Unsearchable)?;
    let mut found = None;
    let mut at = end;
    let mut stopped = Reached::Searching;
    subject.visit_backward(from, end, |bytes| {
        for byte in bytes.iter().rev() {
            let Some(next) = reverse.next(state, *byte) else {
                stopped = Reached::Quit;
                return ControlFlow::Break(());
            };
            state = next;
            at = at.saturating_sub(1);
            if reverse.is_special(state) {
                match reverse.reached(state) {
                    Reached::Searching => {}
                    Reached::Match => found = Some(at.saturating_add(1)),
                    ended @ (Reached::Dead | Reached::Quit) => {
                        stopped = ended;
                        return ControlFlow::Break(());
                    }
                }
            }
        }
        ControlFlow::Continue(())
    })?;
    match stopped {
        Reached::Dead => return Ok(found),
        Reached::Quit => return Err(PagedSearchFailure::Unsearchable),
        Reached::Searching | Reached::Match => {}
    }
    if at > from {
        return Err(PagedSearchFailure::Unsearchable);
    }
    state = match from.checked_sub(1) {
        Some(before) => reverse.next(state, byte_at(subject, before)?),
        None => reverse.end_of_input(state),
    }
    .ok_or(PagedSearchFailure::Unsearchable)?;
    match reverse.reached(state) {
        Reached::Match => Ok(Some(from)),
        Reached::Quit => Err(PagedSearchFailure::Unsearchable),
        Reached::Searching | Reached::Dead => Ok(found),
    }
}

fn byte_at(subject: &mut PagedSubject<'_, '_>, at: usize) -> Result<u8, PagedSearchFailure> {
    if let Some(byte) = subject.byte(at) {
        return Ok(byte);
    }
    subject.take_failure()?;
    Err(PagedSearchFailure::Unsearchable)
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    clippy::cast_possible_truncation
)]
mod tests {
    use debar_image::{
        BacktrackingProgram, ByteSet, ExpressionTree, Greed, LookDirection, TreeRepetition,
        compile_backtracking, compile_text, compile_text_lazily,
    };
    use regex_automata::dfa::regex::Regex;
    use regex_automata::dfa::{StartKind, dense};
    use regex_automata::nfa::thompson;
    use regex_automata::util::syntax;
    use regex_automata::{Anchored, Input, MatchKind};

    use super::{
        FirstMatchEnd, SharedSearch, first_match_ends_sharing_one_read, search_in_place,
        search_in_place_from_its_end, search_lazily,
    };
    use crate::backtracking_search::{BacktrackingBounds, backtracking_search, search_subject};
    use crate::whole_object::ObjectPages;
    use crate::work_meter::WorkMeter;

    const PATTERNS: [&str; 14] = [
        "ab",
        "a+b",
        "^a",
        "b$",
        r"\bab\b",
        "(?m)^b",
        "a*",
        "(a|ab)(c|bcd)?",
        "a[^b]{2}b",
        r"\B.",
        "(?s).{3}$",
        "x?",
        "ba+$|^ab",
        r"(?m)a$\n",
    ];
    const ALPHABET: &[u8] = b"ab\n xcd";
    const PAGE_LENGTHS: [usize; 4] = [1, 2, 3, 7];
    const SUBJECT_STARTS: [usize; 3] = [0, 1, 4];

    struct Haystacks(u64);

    impl Haystacks {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }

        fn haystack(&mut self) -> Vec<u8> {
            let length = (self.next() % 24) as usize;
            (0..length)
                .map(|_| ALPHABET[(self.next() % ALPHABET.len() as u64) as usize])
                .collect()
        }
    }

    fn automata(pattern: &str) -> (dense::DFA<Vec<u32>>, dense::DFA<Vec<u32>>) {
        let build = |reverse: bool| {
            let config = if reverse {
                dense::Config::new()
                    .start_kind(StartKind::Anchored)
                    .match_kind(MatchKind::All)
            } else {
                dense::Config::new()
                    .start_kind(StartKind::Both)
                    .match_kind(MatchKind::LeftmostFirst)
            };
            dense::Builder::new()
                .configure(config)
                .syntax(syntax::Config::new().unicode(false).utf8(false))
                .thompson(thompson::Config::new().utf8(false).reverse(reverse))
                .build(pattern)
                .unwrap()
        };
        (build(false), build(true))
    }

    fn each_case(mut check: impl FnMut(&[u8], usize, usize, usize, Anchored)) {
        let mut haystacks = Haystacks(0x05ee_d0f9_a9e5);
        for _ in 0..60 {
            let object = haystacks.haystack();
            for subject_start in SUBJECT_STARTS {
                if subject_start > object.len() {
                    continue;
                }
                for page_length in PAGE_LENGTHS {
                    for from in 0..=object.len() - subject_start {
                        for anchored in [Anchored::No, Anchored::Yes] {
                            check(&object, subject_start, page_length, from, anchored);
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn searches_sharing_one_read_find_what_each_finds_reading_alone() {
        let built: Vec<_> = PATTERNS.iter().map(|pattern| automata(pattern)).collect();
        let automata: Vec<_> = built
            .iter()
            .map(|(forward, reverse)| (forward.as_ref(), reverse.as_ref()))
            .collect();
        let mut haystacks = Haystacks(0x0bad_cafe_f00d);
        for _ in 0..200 {
            let object = haystacks.haystack();
            for page_length in PAGE_LENGTHS {
                for anchored in [Anchored::No, Anchored::Yes] {
                    let subjects: Vec<(usize, usize)> = automata
                        .iter()
                        .map(|_| {
                            let start = (haystacks.next() as usize) % (object.len() + 1);
                            let end =
                                start + (haystacks.next() as usize) % (object.len() - start + 1);
                            (start, end)
                        })
                        .collect();
                    let searches: Vec<SharedSearch<'_, '_>> = automata
                        .iter()
                        .zip(&subjects)
                        .map(|((forward, _), (start, end))| SharedSearch {
                            forward,
                            subject_start: *start,
                            subject_end: *end,
                            anchored,
                        })
                        .collect();
                    let bytes = &object.as_slice();
                    let mut pages = ObjectPages::new(bytes, page_length, 2);
                    let shared = first_match_ends_sharing_one_read(&mut pages, &searches).unwrap();
                    for (((forward, reverse), (start, end)), first_end) in
                        automata.iter().zip(&subjects).zip(shared)
                    {
                        let mut alone = ObjectPages::new(bytes, page_length, 2);
                        let mut subject = alone.subject(*start as u64, *end as u64);
                        let expected =
                            search_in_place(forward, reverse, &mut subject, 0, anchored).unwrap();
                        let FirstMatchEnd::Known(first_end) = first_end else {
                            panic!("no first end for {object:?} {start}..{end}");
                        };
                        let found = search_in_place_from_its_end(
                            forward,
                            reverse,
                            &mut subject,
                            0,
                            anchored,
                            first_end,
                        )
                        .unwrap();
                        assert_eq!(
                            found, expected,
                            "{object:?} {start}..{end} {anchored:?}, pages of {page_length}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn a_search_through_pages_finds_what_a_search_of_the_held_subject_finds() {
        for pattern in PATTERNS {
            let (forward, reverse) = automata(pattern);
            let held = Regex::builder().build_from_dfas(forward.as_ref(), reverse.as_ref());
            each_case(|object, subject_start, page_length, from, anchored| {
                let haystack = &object[subject_start..];
                let expected = held
                    .try_search(&Input::new(haystack).range(from..).anchored(anchored))
                    .unwrap()
                    .map(|found| (found.start(), found.end()));
                let bytes = &object;
                let mut pages = ObjectPages::new(bytes, page_length, 2);
                let mut subject = pages.subject(subject_start as u64, object.len() as u64);
                let through_pages = search_in_place(
                    &forward.as_ref(),
                    &reverse.as_ref(),
                    &mut subject,
                    from,
                    anchored,
                )
                .unwrap();
                assert_eq!(
                    through_pages, expected,
                    "{pattern:?} in {haystack:?} from {from} {anchored:?}, pages of {page_length}"
                );
            });
        }
    }

    #[test]
    fn a_lazy_search_through_pages_finds_what_the_compiled_text_finds_held() {
        for pattern in PATTERNS {
            let held = compile_text(pattern).unwrap();
            let lazy = compile_text_lazily(pattern).unwrap();
            let mut cache = lazy.create_cache();
            each_case(|object, subject_start, page_length, from, anchored| {
                let haystack = &object[subject_start..];
                let expected = held
                    .search(&Input::new(haystack).range(from..).anchored(anchored))
                    .map(|found| (found.start(), found.end()));
                let bytes = &object;
                let mut pages = ObjectPages::new(bytes, page_length, 2);
                let mut subject = pages.subject(subject_start as u64, object.len() as u64);
                let through_pages =
                    search_lazily(&lazy, &mut cache, &mut subject, from, anchored).unwrap();
                assert_eq!(
                    through_pages, expected,
                    "{pattern:?} in {haystack:?} from {from} {anchored:?}, pages of {page_length}"
                );
            });
        }
    }

    fn word_run() -> ExpressionTree {
        ExpressionTree::Repetition(Box::new(TreeRepetition {
            min: 1,
            max: None,
            greed: Greed::Greedy,
            item: ExpressionTree::Byte(ByteSet::of(b"abcd".iter().copied())),
        }))
    }

    #[test]
    fn a_backtracking_search_through_pages_finds_what_it_finds_held() {
        let trees = [
            ExpressionTree::Concat(vec![
                ExpressionTree::Capture {
                    group: 1,
                    item: Box::new(word_run()),
                },
                ExpressionTree::literal(b" "),
                ExpressionTree::Backreference {
                    group: 1,
                    caseless: false,
                },
            ]),
            ExpressionTree::Concat(vec![
                ExpressionTree::Lookaround {
                    direction: LookDirection::Behind,
                    negated: true,
                    item: Box::new(ExpressionTree::literal(b"a")),
                },
                ExpressionTree::literal(b"b"),
                ExpressionTree::Lookaround {
                    direction: LookDirection::Ahead,
                    negated: false,
                    item: Box::new(ExpressionTree::literal(b"\n")),
                },
            ]),
        ];
        for tree in &trees {
            let program = compile_backtracking(tree).unwrap();
            let program = BacktrackingProgram::read(&program).unwrap();
            each_case(|object, subject_start, page_length, from, anchored| {
                let anchored = anchored == Anchored::Yes;
                let haystack = &object[subject_start..];
                let bounds = BacktrackingBounds::FOR_SIGNATURES;
                let expected =
                    backtracking_search(&program, haystack, from, anchored, bounds).unwrap();
                let bytes = &object;
                let mut pages = ObjectPages::new(bytes, page_length, 2);
                let mut subject = pages.subject(subject_start as u64, object.len() as u64);
                let through_pages = search_subject(
                    &program,
                    &mut subject,
                    from,
                    anchored,
                    bounds,
                    &mut WorkMeter::unlimited(),
                )
                .unwrap();
                assert_eq!(
                    through_pages, expected,
                    "{haystack:?} from {from}, pages of {page_length}"
                );
            });
        }
    }
}
