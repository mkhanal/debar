use debar_platform::input::ObjectBytes;

use crate::context::{ModuleContext, PartOutcome};
use crate::facts::{DocumentAction, Fact, ScriptLanguage};
use crate::module::{ModuleError, ModuleOutput, Part, PartBytes, PartRole, PartSource};
use crate::object::Object;
use crate::pdf::document::DocumentBytes;
use crate::pdf::extraction::{Extracted, Extraction, PageText, page_text_bytes};
use crate::pdf::names::DocumentSigns;
use crate::pdf::object_dictionary::read_object;
use crate::pdf::object_streams::ObjectStreams;
use crate::pdf::objects::{Mark, ObjectTable, find_objects};
use crate::pdf::searchable::Searchable;

const HEADER: &[u8] = b"%PDF-";
const HEADER_SEARCHED_WITHIN: u64 = 1032;
const SHORTEST_VERSION_MARK: u64 = 8;

pub enum DocumentParts<'o> {
    Unopened(Object<'o>),
    Open(Box<OpenDocument<'o>>),
    Finished(Vec<Fact>),
}

pub struct OpenDocument<'o> {
    document: DocumentBytes<'o>,
    header: u64,
    table: ObjectTable,
    streams: ObjectStreams,
    signs: DocumentSigns,
    next: usize,
    waiting: Waiting<'o>,
}

enum Waiting<'o> {
    Nothing,
    ForTheObject(PageText<'o>),
    ForThePageText,
}

impl<'o> PartSource<'o> for DocumentParts<'o> {
    fn next(
        &mut self,
        context: &mut ModuleContext,
    ) -> Result<Option<ModuleOutput<'o>>, ModuleError> {
        loop {
            match std::mem::replace(self, Self::Finished(Vec::new())) {
                Self::Unopened(object) => {
                    if let Some(open) = open(&object)? {
                        *self = Self::Open(Box::new(open));
                    }
                }
                Self::Open(mut open) => {
                    let output = open.next_output(context)?;
                    match output {
                        Next::Output(output) => {
                            *self = Self::Open(open);
                            return Ok(Some(output));
                        }
                        Next::Stopped => return Ok(None),
                        Next::Ended => *self = Self::Finished(open.ending(context)),
                    }
                }
                Self::Finished(mut facts) => {
                    let fact = facts.pop();
                    *self = Self::Finished(facts);
                    return Ok(fact.map(ModuleOutput::Fact));
                }
            }
        }
    }
}

enum Next<'o> {
    Output(ModuleOutput<'o>),
    Stopped,
    Ended,
}

fn open<'o>(object: &Object<'o>) -> Result<Option<OpenDocument<'o>>, ModuleError> {
    let searched = object.length().min(HEADER_SEARCHED_WITHIN);
    let mut first = vec![0u8; usize::try_from(searched).unwrap_or(0)];
    object.read_at(0, &mut first)?;
    let Some(header) = first.as_slice().find(HEADER, 0, searched) else {
        return Ok(None);
    };
    if searched.saturating_sub(header) < SHORTEST_VERSION_MARK {
        return Ok(None);
    }
    let Some(from_the_header) = object.onward_from(header) else {
        return Ok(None);
    };
    let document = DocumentBytes::new(from_the_header);
    let mut table = ObjectTable::default();
    let mut signs = DocumentSigns::default();
    find_objects(&document, &mut table);
    for index in 0..table.len() {
        read_object(&document, &mut table, index, &mut signs);
    }
    document.take_failure()?;
    Ok(Some(OpenDocument {
        document,
        header,
        table,
        streams: ObjectStreams::default(),
        signs,
        next: 0,
        waiting: Waiting::Nothing,
    }))
}

impl<'o> OpenDocument<'o> {
    fn next_output(&mut self, context: &mut ModuleContext) -> Result<Next<'o>, ModuleError> {
        match std::mem::replace(&mut self.waiting, Waiting::Nothing) {
            Waiting::Nothing => {}
            Waiting::ForTheObject(page_text) => {
                if refused(context) {
                    return Ok(Next::Stopped);
                }
                if let Some(bytes) = page_text_bytes(page_text, context.room_to_produce())? {
                    self.waiting = Waiting::ForThePageText;
                    return Ok(Next::Output(child(bytes)));
                }
            }
            Waiting::ForThePageText => {
                if refused(context) {
                    return Ok(Next::Stopped);
                }
            }
        }
        while self.next < self.table.len() {
            let index = self.next;
            self.next = self.next.saturating_add(1);
            let extracted = Extraction {
                document: &self.document,
                header: self.header,
                table: &mut self.table,
                streams: &mut self.streams,
                signs: &mut self.signs,
            }
            .extract(index, context);
            self.document.take_failure()?;
            if let Extracted::Part { bytes, page_text } = extracted? {
                self.waiting = Waiting::ForTheObject(page_text);
                return Ok(Next::Output(child(bytes)));
            }
        }
        Ok(Next::Ended)
    }

    fn ending(&self, context: &ModuleContext) -> Vec<Fact> {
        let mut facts = Vec::new();
        if context.facts_wanted() {
            let marked = |mark: Mark| {
                self.table
                    .objects()
                    .iter()
                    .any(|object| object.marks.has(mark))
            };
            if marked(Mark::EmbeddedFile) {
                facts.push(Fact::DocumentAction(DocumentAction::AttachesFile));
            }
            if self.signs.launches_a_program {
                facts.push(Fact::DocumentAction(DocumentAction::LaunchesProgram));
            }
            if self.signs.opens_with_an_action {
                facts.push(Fact::DocumentAction(DocumentAction::ActsOnOpening));
            }
            if marked(Mark::JavaScript) {
                facts.push(Fact::Script(ScriptLanguage::JavaScript));
            }
        }
        if self.signs.common_name_escaped {
            facts.push(Fact::ObfuscatedNames);
        }
        facts
    }
}

fn refused(context: &ModuleContext) -> bool {
    matches!(context.last_part(), Some(PartOutcome::Refused(_)))
}

fn child(bytes: PartBytes<'_>) -> ModuleOutput<'_> {
    ModuleOutput::Part(Part {
        bytes,
        role: PartRole::Child { kind: None },
    })
}
