use aho_corasick::{AhoCorasick, AhoCorasickKind, MatchKind};
use debar_image::{
    AnchorBytes, AnchorCase, AnchoredProgram, Displacement, GroupMalformed, LogicalGroup,
    LogicalSignatureId, MatchingPass, PatternGroup, PatternSignatureId, ProgramId,
};

use crate::pattern_scan::PatternScanError;

const MOST_PROGRAMS: usize = 16_384;

#[derive(Debug, Clone, Copy)]
struct Entry {
    group: usize,
    program: ProgramId,
    displacement: Displacement,
}

pub(crate) struct ArmedGroup<'v, 'm> {
    pub index: usize,
    pub patterns: &'v PatternGroup<'m>,
    pub logical: &'v LogicalGroup<'m>,
    pub armed: &'v [u32],
}

struct Searcher {
    automaton: AhoCorasick,
    entries: Vec<Entry>,
}

impl Searcher {
    fn of(
        anchors: Vec<(Vec<u8>, Entry)>,
        case: AnchorCase,
    ) -> Result<Option<Self>, PatternScanError> {
        if anchors.is_empty() {
            return Ok(None);
        }
        let (patterns, entries): (Vec<Vec<u8>>, Vec<Entry>) = anchors.into_iter().unzip();
        let automaton = AhoCorasick::builder()
            .kind(Some(AhoCorasickKind::DFA))
            .match_kind(MatchKind::Standard)
            .ascii_case_insensitive(case == AnchorCase::Folded)
            .build(&patterns)
            .map_err(|_| PatternScanError::ArmedSearchNotBuilt)?;
        Ok(Some(Self { automaton, entries }))
    }

    fn search(
        &self,
        bytes: &[u8],
        first_position: u64,
        positions: usize,
        hits: &mut Vec<(u64, usize, AnchoredProgram)>,
    ) {
        for found in self.automaton.find_overlapping_iter(bytes) {
            if found.start() >= positions {
                continue;
            }
            let Some(entry) = self.entries.get(found.pattern().as_usize()) else {
                continue;
            };
            hits.push((
                first_position.saturating_add(u64::try_from(found.start()).unwrap_or(u64::MAX)),
                entry.group,
                AnchoredProgram {
                    program: entry.program,
                    displacement: entry.displacement,
                },
            ));
        }
    }
}

pub(crate) struct SecondPassSearch {
    exact: Option<Searcher>,
    folded: Option<Searcher>,
    everywhere: Vec<Entry>,
    programs: usize,
}

impl SecondPassSearch {
    pub(crate) fn for_armed(
        groups: &[ArmedGroup<'_, '_>],
    ) -> Result<Option<Self>, PatternScanError> {
        let mut exact = Vec::new();
        let mut folded = Vec::new();
        let mut everywhere = Vec::new();
        let mut programs = 0usize;
        for group in groups {
            for id in group.armed {
                let record = group
                    .logical
                    .signature(LogicalSignatureId(*id))
                    .map_err(|_| GroupMalformed::Layout)?;
                for index in 0..record.subsignature_count {
                    let index = u16::try_from(index).map_err(|_| GroupMalformed::Layout)?;
                    let subsignature = group
                        .logical
                        .subsignature(&record, index)
                        .map_err(|_| GroupMalformed::Layout)?;
                    let Some(first) = subsignature.pattern else {
                        continue;
                    };
                    if subsignature.pass != MatchingPass::Second {
                        continue;
                    }
                    for offset in 0..u32::from(subsignature.pattern_count) {
                        let pattern = group
                            .patterns
                            .signature(PatternSignatureId(first.0.saturating_add(offset)))?;
                        for segment in 0..pattern.segment_count {
                            let program =
                                ProgramId(pattern.first_program.0.saturating_add(segment));
                            let header = group.patterns.program_header(program)?;
                            if segment > 0 && header.is_armed_by_predecessor() {
                                continue;
                            }
                            programs = programs.saturating_add(1);
                            if programs > MOST_PROGRAMS {
                                return Ok(None);
                            }
                            let anchor = header.anchor();
                            let entry = Entry {
                                group: group.index,
                                program,
                                displacement: anchor.displacement,
                            };
                            let bytes = match anchor.bytes {
                                AnchorBytes::Long(bytes) => bytes.to_vec(),
                                AnchorBytes::Short(bytes) => bytes.to_vec(),
                                AnchorBytes::None => {
                                    everywhere.push(entry);
                                    continue;
                                }
                            };
                            match anchor.case {
                                AnchorCase::Exact => exact.push((bytes, entry)),
                                AnchorCase::Folded => folded.push((bytes, entry)),
                            }
                        }
                    }
                }
            }
        }
        Ok(Some(Self {
            exact: Searcher::of(exact, AnchorCase::Exact)?,
            folded: Searcher::of(folded, AnchorCase::Folded)?,
            everywhere,
            programs,
        }))
    }

    pub(crate) fn search(
        &self,
        bytes: &[u8],
        first_position: u64,
        positions: usize,
        hits: &mut Vec<(u64, usize, AnchoredProgram)>,
    ) {
        for searcher in [&self.exact, &self.folded].into_iter().flatten() {
            searcher.search(bytes, first_position, positions, hits);
        }
        for offset in 0..positions {
            let position = first_position.saturating_add(u64::try_from(offset).unwrap_or(u64::MAX));
            hits.extend(self.everywhere.iter().map(|entry| {
                (
                    position,
                    entry.group,
                    AnchoredProgram {
                        program: entry.program,
                        displacement: entry.displacement,
                    },
                )
            }));
        }
    }

    pub(crate) fn state_bytes(&self) -> usize {
        let automata: usize = [&self.exact, &self.folded]
            .into_iter()
            .flatten()
            .map(|searcher| {
                searcher.automaton.memory_usage().saturating_add(
                    searcher
                        .entries
                        .capacity()
                        .saturating_mul(std::mem::size_of::<Entry>()),
                )
            })
            .sum();
        automata.saturating_add(self.programs.saturating_mul(std::mem::size_of::<Entry>()))
    }
}
