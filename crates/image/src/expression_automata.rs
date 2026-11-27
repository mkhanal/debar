use std::collections::BTreeMap;
use std::sync::{Mutex, PoisonError};

use regex_automata::dfa::{StartKind, dense};
use regex_automata::nfa::thompson::{self, NFA, WhichCaptures};
use regex_automata::util::syntax;
use regex_automata::{MatchKind, hybrid, meta};
use regex_syntax::hir::Hir;

pub const LARGEST_AUTOMATON_IN_IMAGE: usize = 256 * 1024;
const LARGEST_DETERMINIZATION: usize = 16 * 1024 * 1024;
const LARGEST_COMPILED_EXPRESSION: usize = 16 * 1024 * 1024;
pub const AUTOMATON_ALIGNMENT: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExpressionNotCompiled {
    TooLarge,
}

pub enum CompiledExpression {
    InImage { forward: Vec<u8>, reverse: Vec<u8> },
    FromText,
}

pub struct BuiltExpression {
    pub text: String,
    pub compiled: CompiledExpression,
}

fn nfa_of(hir: &Hir, reverse: bool) -> Result<NFA, ExpressionNotCompiled> {
    thompson::Compiler::new()
        .configure(
            thompson::Config::new()
                .utf8(false)
                .reverse(reverse)
                .which_captures(WhichCaptures::None)
                .nfa_size_limit(Some(LARGEST_COMPILED_EXPRESSION)),
        )
        .build_from_hir(hir)
        .map_err(|_| ExpressionNotCompiled::TooLarge)
}

fn dense_automaton(nfa: &NFA, reverse: bool) -> Option<Vec<u8>> {
    let config = dense::Config::new()
        .minimize(false)
        .byte_classes(true)
        .dfa_size_limit(Some(LARGEST_AUTOMATON_IN_IMAGE))
        .determinize_size_limit(Some(LARGEST_DETERMINIZATION));
    let config = if reverse {
        config
            .prefilter(None)
            .start_kind(StartKind::Anchored)
            .match_kind(MatchKind::All)
    } else {
        config
            .start_kind(StartKind::Both)
            .match_kind(MatchKind::LeftmostFirst)
    };
    let automaton = dense::Builder::new()
        .configure(config)
        .build_from_nfa(nfa)
        .ok()?;
    let mut bytes = vec![0u8; automaton.write_to_len()];
    automaton.write_to_little_endian(&mut bytes).ok()?;
    (bytes.len() <= LARGEST_AUTOMATON_IN_IMAGE).then_some(bytes)
}

pub fn build(hir: &Hir) -> Result<BuiltExpression, ExpressionNotCompiled> {
    let forward_nfa = nfa_of(hir, false)?;
    let reverse_nfa = nfa_of(hir, true)?;
    let compiled = match (
        dense_automaton(&forward_nfa, false),
        dense_automaton(&reverse_nfa, true),
    ) {
        (Some(forward), Some(reverse))
            if forward.len().saturating_add(reverse.len()) <= LARGEST_AUTOMATON_IN_IMAGE =>
        {
            CompiledExpression::InImage { forward, reverse }
        }
        _ => CompiledExpression::FromText,
    };
    Ok(BuiltExpression {
        text: hir.to_string(),
        compiled,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AutomatonMalformed;

pub fn compile_text(text: &str) -> Result<meta::Regex, AutomatonMalformed> {
    meta::Builder::new()
        .configure(
            meta::Config::new()
                .match_kind(MatchKind::LeftmostFirst)
                .utf8_empty(false)
                .nfa_size_limit(Some(LARGEST_COMPILED_EXPRESSION)),
        )
        .syntax(syntax::Config::new().unicode(false).utf8(false))
        .build(text)
        .map_err(|_| AutomatonMalformed)
}

pub type LazyExpression = hybrid::regex::Regex;

pub fn compile_text_lazily(text: &str) -> Result<LazyExpression, AutomatonMalformed> {
    hybrid::regex::Builder::new()
        .syntax(syntax::Config::new().unicode(false).utf8(false))
        .thompson(
            thompson::Config::new()
                .utf8(false)
                .which_captures(WhichCaptures::None)
                .nfa_size_limit(Some(LARGEST_COMPILED_EXPRESSION)),
        )
        .dfa(
            hybrid::dfa::Config::new()
                .match_kind(MatchKind::LeftmostFirst)
                .byte_classes(true)
                .minimum_cache_clear_count(None)
                .skip_cache_capacity_check(true),
        )
        .build(text)
        .map_err(|_| AutomatonMalformed)
}

pub type InPlaceAutomaton<'m> = dense::DFA<&'m [u32]>;

#[derive(Default)]
pub(crate) struct ValidatedAutomata<'m> {
    by_extent: Mutex<BTreeMap<(usize, usize), InPlaceAutomaton<'m>>>,
}

impl<'m> ValidatedAutomata<'m> {
    pub(crate) fn automaton(
        &self,
        bytes: &'m [u8],
    ) -> Result<InPlaceAutomaton<'m>, AutomatonMalformed> {
        let extent = (bytes.as_ptr().addr(), bytes.len());
        let mut validated = self
            .by_extent
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if let Some(automaton) = validated.get(&extent) {
            return Ok(automaton.clone());
        }
        let automaton = automaton_in_place(bytes)?;
        validated.insert(extent, automaton.clone());
        Ok(automaton)
    }
}

pub fn automaton_in_place(bytes: &[u8]) -> Result<InPlaceAutomaton<'_>, AutomatonMalformed> {
    dense::DFA::from_bytes(bytes)
        .map(|(automaton, _)| automaton)
        .map_err(|_| AutomatonMalformed)
}

pub struct BuiltSearch {
    pub text: String,
    pub automaton: Option<Vec<u8>>,
}

pub fn build_search(hir: &Hir) -> Result<BuiltSearch, ExpressionNotCompiled> {
    let nfa = nfa_of(hir, false)?;
    Ok(BuiltSearch {
        text: hir.to_string(),
        automaton: dense_automaton(&nfa, false),
    })
}
