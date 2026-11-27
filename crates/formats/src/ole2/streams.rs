use std::collections::VecDeque;
use std::rc::Rc;

use debar_platform::input::{InputError, ObjectBytes};

use crate::context::{ModuleContext, PartOutcome};
use crate::facts::{EncryptedContent, Fact, MacroLanguage};
use crate::limits::Limit;
use crate::module::{ModuleError, ModuleOutput, Part, PartBytes, PartRole, PartSource};
use crate::object::Object;
use crate::ole2::directory::DirectoryEntry;
use crate::ole2::findings::Findings;
use crate::ole2::folders::{FolderScan, Folders};
use crate::ole2::header::{Header, header_of};
use crate::ole2::sectors::Sectors;
use crate::ole2::stream_bytes::{ChainedStream, StreamChain};
use crate::ole2::walk::{Visit, Walk, WalkEnd};
use crate::ole2::zlib_stream::{Inflated, Inflation, inflate};

const COMPRESSED_STREAM_MARK_AT: u64 = 4;
const COMPRESSED_STREAM_MARK: [u8; 2] = [0x78, 0x9c];

pub struct DocumentStreams<'o> {
    document: Object<'o>,
    initial_scan_budget: u64,
    phase: Phase<'o>,
    pending: VecDeque<ModuleOutput<'o>>,
}

enum Phase<'o> {
    Opening,
    StreamsAsRead(Pass<'o>),
    Folders(FolderPass<'o>),
    Finished,
}

struct Pass<'o> {
    sectors: Rc<Sectors<'o>>,
    findings: Findings,
    walk: Walk,
    counted: u64,
    scan_budget: u64,
}

struct FolderPass<'o> {
    sectors: Rc<Sectors<'o>>,
    findings: Findings,
    scan: FolderScan,
}

enum Admission {
    Counted,
    Skipped,
    Stopped,
}

impl<'o> DocumentStreams<'o> {
    pub fn new(document: Object<'o>, context: &ModuleContext) -> Self {
        Self {
            document,
            initial_scan_budget: context.scan_bytes_left().unwrap_or(u64::MAX),
            phase: Phase::Opening,
            pending: VecDeque::new(),
        }
    }
}

impl<'o> PartSource<'o> for DocumentStreams<'o> {
    fn next(
        &mut self,
        context: &mut ModuleContext,
    ) -> Result<Option<ModuleOutput<'o>>, ModuleError> {
        loop {
            if let Some(output) = self.pending.pop_front() {
                return Ok(Some(output));
            }
            match std::mem::replace(&mut self.phase, Phase::Finished) {
                Phase::Opening => self.phase = self.open(context)?,
                Phase::StreamsAsRead(mut pass) => {
                    if pass.next_stream_as_read(context, &mut self.pending)? {
                        self.phase = Phase::StreamsAsRead(pass);
                    } else {
                        self.finish(pass.findings, context);
                    }
                }
                Phase::Folders(mut pass) => {
                    if pass.next_stream_in_a_folder(context, &mut self.pending)? {
                        self.phase = Phase::Folders(pass);
                    } else {
                        self.finish(pass.findings, context);
                    }
                }
                Phase::Finished => return Ok(None),
            }
        }
    }
}

impl<'o> DocumentStreams<'o> {
    fn open(&mut self, context: &mut ModuleContext) -> Result<Phase<'o>, ModuleError> {
        let geometry = match header_of(&self.document)? {
            Header::Holds(geometry) => geometry,
            Header::TooShort => return Ok(Phase::Finished),
            Header::Rejected { at } => return Err(ModuleError::Damaged { at }),
        };
        if context.scan_bytes_left() == Some(0) {
            return Ok(Phase::Finished);
        }
        let sectors = Rc::new(Sectors::new(self.document.clone(), geometry));
        let mut first = Pass::new(
            Rc::clone(&sectors),
            Findings::default(),
            self.initial_scan_budget,
        );
        first.look(context, &mut self.pending)?;
        if first.counted == 0 {
            return Ok(Phase::Finished);
        }
        let findings = first.findings;
        if context.facts_wanted() {
            if findings.project.holds_a_vba_project {
                self.pending
                    .push_back(ModuleOutput::Fact(Fact::Macros(MacroLanguage::VisualBasic)));
            }
            if findings.workbook.has_macro_sheets {
                self.pending.push_back(ModuleOutput::Fact(Fact::Macros(
                    MacroLanguage::SpreadsheetFormulas,
                )));
            }
        }
        let second = Pass::new(sectors, findings, self.initial_scan_budget);
        if findings.streams_go_to_a_folder() {
            return second.into_folders(context, &mut self.pending);
        }
        Ok(Phase::StreamsAsRead(second))
    }

    fn finish(&mut self, findings: Findings, context: &ModuleContext) {
        self.phase = Phase::Finished;
        if findings.encrypted && context.facts_wanted() {
            self.pending.push_back(ModuleOutput::Fact(Fact::Encrypted {
                content: EncryptedContent::Document,
                decryptable: false,
            }));
        }
    }
}

impl<'o> Pass<'o> {
    fn new(sectors: Rc<Sectors<'o>>, findings: Findings, scan_budget: u64) -> Self {
        let walk = Walk::new(&sectors);
        Self {
            sectors,
            findings,
            walk,
            counted: 0,
            scan_budget,
        }
    }

    fn look(
        &mut self,
        context: &mut ModuleContext,
        pending: &mut VecDeque<ModuleOutput<'o>>,
    ) -> Result<(), InputError> {
        while let Some(visit) = self.next_visit(context)? {
            let entry = match visit {
                Visit::Stream { entry, .. } => entry,
                Visit::Ended(end) => {
                    ended(end, context, pending);
                    break;
                }
                Visit::Root { .. } | Visit::Dropped { .. } | Visit::Storage { .. } => continue,
            };
            match self.admission(&entry, context) {
                Admission::Counted => self.findings.note_counted_stream(&self.sectors, &entry)?,
                Admission::Skipped => {}
                Admission::Stopped => break,
            }
        }
        Ok(())
    }

    fn into_folders(
        mut self,
        context: &mut ModuleContext,
        pending: &mut VecDeque<ModuleOutput<'o>>,
    ) -> Result<Phase<'o>, ModuleError> {
        let mut folders = Folders::new();
        while let Some(visit) = self.next_visit(context)? {
            match visit {
                Visit::Stream { entry, folder } => match self.admission(&entry, context) {
                    Admission::Counted => folders.add_stream(folder, entry.chain),
                    Admission::Skipped => {}
                    Admission::Stopped => break,
                },
                Visit::Storage { folder, inner, .. } => folders.add_folder(folder, inner),
                Visit::Ended(end) => {
                    ended(end, context, pending);
                    break;
                }
                Visit::Root { .. } | Visit::Dropped { .. } => {}
            }
        }
        Ok(Phase::Folders(FolderPass {
            sectors: self.sectors,
            findings: self.findings,
            scan: folders.scan_order(self.findings.folder_is_scanned()),
        }))
    }

    fn next_stream_as_read(
        &mut self,
        context: &mut ModuleContext,
        pending: &mut VecDeque<ModuleOutput<'o>>,
    ) -> Result<bool, InputError> {
        while let Some(visit) = self.next_visit(context)? {
            let entry = match visit {
                Visit::Stream { entry, .. } => entry,
                Visit::Ended(end) => {
                    ended(end, context, pending);
                    return Ok(false);
                }
                Visit::Root { .. } | Visit::Dropped { .. } | Visit::Storage { .. } => continue,
            };
            match self.admission(&entry, context) {
                Admission::Counted => {
                    self.stream_as_read(entry.chain, context, pending)?;
                    if !pending.is_empty() {
                        return Ok(true);
                    }
                }
                Admission::Skipped => {}
                Admission::Stopped => return Ok(false),
            }
        }
        Ok(false)
    }

    fn stream_as_read(
        &self,
        chain: StreamChain,
        context: &ModuleContext,
        pending: &mut VecDeque<ModuleOutput<'o>>,
    ) -> Result<(), InputError> {
        let stream = ChainedStream::measured(Rc::clone(&self.sectors), chain)?;
        if !self.findings.is_hangul && carries_the_compressed_stream_mark(&stream)? {
            let compressed = Object::regenerable(Box::new(stream));
            if let Some(inflated) = compressed.onward_from(COMPRESSED_STREAM_MARK_AT) {
                inflated_stream(inflated, context, pending)?;
            }
            return Ok(());
        }
        pending.push_back(child(PartBytes::Regenerable(Box::new(stream))));
        Ok(())
    }

    fn next_visit(&mut self, context: &ModuleContext) -> Result<Option<Visit>, InputError> {
        let visit = self
            .walk
            .next(&self.sectors, self.counted, most_storage_levels(context))?;
        match &visit {
            Some(
                Visit::Stream { entry, .. }
                | Visit::Storage { entry, .. }
                | Visit::Root { entry }
                | Visit::Dropped { entry },
            ) => self.findings.note_encryption(&self.sectors, entry)?,
            Some(Visit::Ended(_)) | None => {}
        }
        Ok(visit)
    }

    fn admission(&mut self, entry: &DirectoryEntry, context: &mut ModuleContext) -> Admission {
        if let Some(most) = context.most_files() {
            let scanned = most.saturating_sub(context.files_left().unwrap_or(most));
            if self.counted > most || scanned > most.saturating_sub(self.counted) {
                context.reached(Limit::MostFiles);
                return Admission::Stopped;
            }
        }
        let declared = u64::from(entry.chain.declared_size);
        let fits = context
            .largest_file()
            .is_none_or(|largest| declared <= largest)
            || declared <= self.scan_budget;
        if !fits {
            return Admission::Skipped;
        }
        self.counted = self.counted.saturating_add(1);
        self.scan_budget = self.scan_budget.wrapping_sub(declared);
        Admission::Counted
    }
}

impl<'o> FolderPass<'o> {
    fn next_stream_in_a_folder(
        &mut self,
        context: &ModuleContext,
        pending: &mut VecDeque<ModuleOutput<'o>>,
    ) -> Result<bool, InputError> {
        if context.last_part() == Some(PartOutcome::Refused(Limit::MostFiles)) {
            return Ok(false);
        }
        let Some(chain) = self.scan.next() else {
            return Ok(false);
        };
        let stream = ChainedStream::measured(Rc::clone(&self.sectors), chain)?;
        pending.push_back(child(PartBytes::Regenerable(Box::new(stream))));
        Ok(true)
    }
}

fn most_storage_levels(context: &ModuleContext) -> u32 {
    context.deepest_level().saturating_add(1)
}

fn ended(end: WalkEnd, context: &mut ModuleContext, pending: &mut VecDeque<ModuleOutput<'_>>) {
    match end {
        WalkEnd::TooDeep => context.reached(Limit::DeepestLevel),
        WalkEnd::Loop { at } => {
            if context.facts_wanted() {
                pending.push_back(ModuleOutput::Fact(Fact::BrokenStructure {
                    at: u64::try_from(at.0).unwrap_or(0),
                }));
            }
        }
    }
}

fn carries_the_compressed_stream_mark(stream: &ChainedStream<'_>) -> Result<bool, InputError> {
    let mark_end = COMPRESSED_STREAM_MARK_AT.saturating_add(COMPRESSED_STREAM_MARK.length());
    if stream.length() < mark_end {
        return Ok(false);
    }
    let mut mark = [0u8; 2];
    stream.read_at(COMPRESSED_STREAM_MARK_AT, &mut mark)?;
    Ok(mark == COMPRESSED_STREAM_MARK)
}

fn inflated_stream<'o>(
    compressed: Object<'o>,
    context: &ModuleContext,
    pending: &mut VecDeque<ModuleOutput<'o>>,
) -> Result<(), InputError> {
    let cut = match (context.largest_file(), context.scan_bytes_left()) {
        (Some(largest), Some(left)) => Some(largest.min(left)),
        (largest, left) => largest.or(left),
    };
    let bytes = match inflate(&compressed, cut, context.room_to_produce())? {
        Inflation::Failed => return Ok(()),
        Inflation::Held(bytes) => PartBytes::Produced(bytes),
        Inflation::Measured(length) => {
            PartBytes::Regenerable(Box::new(Inflated::new(compressed, length)))
        }
    };
    pending.push_back(child(bytes));
    Ok(())
}

const fn child(bytes: PartBytes<'_>) -> ModuleOutput<'_> {
    ModuleOutput::Part(Part {
        bytes,
        role: PartRole::Child { kind: None },
    })
}
