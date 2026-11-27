use std::collections::VecDeque;

use debar_platform::input::ObjectBytes;

use crate::context::ModuleContext;
use crate::facts::{EncryptedContent, Fact, Unsupported};
use crate::limits::Limit;
use crate::module::{ModuleError, ModuleOutput, Part, PartBytes, PartRole, PartSource};
use crate::object::Object;
use crate::zip::catalogue::{Catalogue, Indexed};
use crate::zip::headers::{LocalParse, Record, local_record_at};
use crate::zip::inflated::{Inflated, Inflation, inflate};

const STORED: u16 = 0;
const IMPLODED: u16 = 6;
const DEFLATED: u16 = 8;
const DEFLATED_64: u16 = 9;
const BZIP2: u16 = 12;
const POSITION_INSIDE_ANOTHER: u64 = 0;

pub struct Members<'o> {
    object: Object<'o>,
    phase: Phase,
    pending: VecDeque<ModuleOutput<'o>>,
}

enum Phase {
    Indexing(Catalogue),
    TheOneRecordAtTheStart,
    Extracting(Extraction),
    Finished,
}

struct Extraction {
    records: std::vec::IntoIter<Record>,
    previous: Option<Record>,
    unzipped: u64,
}

impl<'o> Members<'o> {
    pub fn new(object: Object<'o>, context: &ModuleContext) -> Self {
        let phase = if context.found_inside_another() {
            Phase::TheOneRecordAtTheStart
        } else {
            Phase::Indexing(Catalogue::new())
        };
        Self {
            object,
            phase,
            pending: VecDeque::new(),
        }
    }
}

impl<'o> PartSource<'o> for Members<'o> {
    fn next(
        &mut self,
        context: &mut ModuleContext,
    ) -> Result<Option<ModuleOutput<'o>>, ModuleError> {
        loop {
            if let Some(output) = self.pending.pop_front() {
                return Ok(Some(output));
            }
            match &mut self.phase {
                Phase::Indexing(catalogue) => match catalogue.next(&self.object, context)? {
                    Indexed::Entry(entry) => return Ok(Some(ModuleOutput::Entry(entry))),
                    Indexed::Fact(fact) => return Ok(Some(ModuleOutput::Fact(fact))),
                    Indexed::Records(records) => {
                        self.phase = Phase::Extracting(Extraction {
                            records: records.into_iter(),
                            previous: None,
                            unzipped: 0,
                        });
                    }
                },
                Phase::TheOneRecordAtTheStart => {
                    self.phase = Phase::Finished;
                    match local_record_at(&self.object, 0, None, POSITION_INSIDE_ANOTHER)? {
                        LocalParse::Unreadable => {}
                        LocalParse::Rejected { entry } => {
                            self.pending.push_back(ModuleOutput::Entry(entry));
                        }
                        LocalParse::Accepted { entry, record } => {
                            self.pending.push_back(ModuleOutput::Entry(entry));
                            self.extract(record, context)?;
                        }
                    }
                }
                Phase::Extracting(extraction) => {
                    let Some(record) = extraction.records.next() else {
                        self.phase = Phase::Finished;
                        continue;
                    };
                    if extraction
                        .previous
                        .is_some_and(|previous| previous.same_member_as(&record))
                    {
                        continue;
                    }
                    extraction.previous = Some(record);
                    let mut unzipped = extraction.unzipped;
                    unzipped = unzipped.saturating_add(self.extract(record, context)?);
                    if let Phase::Extracting(extraction) = &mut self.phase {
                        extraction.unzipped = unzipped;
                    }
                    if context.most_files().is_some_and(|most| unzipped >= most) {
                        context.reached(Limit::MostFiles);
                        self.phase = Phase::Finished;
                    }
                }
                Phase::Finished => return Ok(None),
            }
        }
    }
}

impl<'o> Members<'o> {
    fn extract(&mut self, record: Record, context: &ModuleContext) -> Result<u64, ModuleError> {
        if record.compressed_size == 0 || record.end() > self.object.length() {
            return Ok(0);
        }
        if record.encrypted && context.facts_wanted() {
            self.pending.push_back(ModuleOutput::Fact(Fact::Encrypted {
                content: EncryptedContent::Archive,
                decryptable: false,
            }));
        }
        let Some(data) = self
            .object
            .window(record.data_offset(), record.compressed_size)
        else {
            return Ok(0);
        };
        match record.method {
            STORED if record.compressed_size >= record.real_size => {
                self.stored(&record, context);
                Ok(1)
            }
            STORED => {
                if self.inflated(data, context)? {
                    self.stored(&record, context);
                }
                Ok(2)
            }
            DEFLATED => Ok(u64::from(self.inflated(data, context)?)),
            IMPLODED | DEFLATED_64 | BZIP2 => {
                if context.facts_wanted() {
                    self.pending.push_back(ModuleOutput::Fact(Fact::Unsupported(
                        Unsupported::Compression,
                    )));
                }
                Ok(0)
            }
            _ => Ok(0),
        }
    }

    fn stored(&mut self, record: &Record, context: &ModuleContext) {
        let length = context
            .largest_file()
            .map_or(record.compressed_size, |largest| {
                record.compressed_size.min(largest)
            });
        self.member(PartBytes::Window {
            offset: record.data_offset(),
            length,
        });
    }

    fn inflated(&mut self, data: Object<'o>, context: &ModuleContext) -> Result<bool, ModuleError> {
        let bytes = match inflate(&data, context.largest_file(), context.room_to_produce())? {
            Inflation::Failed => return Ok(false),
            Inflation::Held(bytes) => PartBytes::Produced(bytes),
            Inflation::Measured(length) => {
                PartBytes::Regenerable(Box::new(Inflated::new(data, length)))
            }
        };
        self.member(bytes);
        Ok(true)
    }

    fn member(&mut self, bytes: PartBytes<'o>) {
        self.pending.push_back(ModuleOutput::Part(Part {
            bytes,
            role: PartRole::Child { kind: None },
        }));
    }
}
