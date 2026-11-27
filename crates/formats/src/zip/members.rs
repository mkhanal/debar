use std::collections::VecDeque;

use debar_platform::input::ObjectBytes;

use crate::context::ModuleContext;
use crate::facts::{EncryptedContent, Fact};
use crate::limits::Limit;
use crate::module::{ModuleError, ModuleOutput, Part, PartBytes, PartRole, PartSource};
use crate::object::Object;
use crate::zip::catalogue::{Catalogue, Indexed};
use crate::zip::decoded::{Decoded, Method, Regenerated, decode};
use crate::zip::headers::{LocalParse, Record, local_record_at};
use crate::zip::imploded::ImplodedShape;

const STORED: u16 = 0;
const IMPLODED: u16 = 6;
const DEFLATED: u16 = 8;
const DEFLATED_64: u16 = 9;
const BZIP2: u16 = 12;
const LARGE_IMPLODE_WINDOW: u16 = 0x0002;
const IMPLODED_LITERAL_CODE: u16 = 0x0004;
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
        let method = match record.method {
            STORED if record.compressed_size >= record.real_size => {
                self.stored(&record, context);
                return Ok(1);
            }
            STORED => {
                if self.decoded(Method::Deflate, data, context)? {
                    self.stored(&record, context);
                }
                return Ok(2);
            }
            DEFLATED => Method::Deflate,
            DEFLATED_64 => Method::Deflate64,
            BZIP2 => Method::Bzip2,
            IMPLODED => Method::Implode(ImplodedShape {
                large_window: record.flags & LARGE_IMPLODE_WINDOW != 0,
                literal_code: record.flags & IMPLODED_LITERAL_CODE != 0,
            }),
            _ => return Ok(0),
        };
        Ok(u64::from(self.decoded(method, data, context)?))
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

    fn decoded(
        &mut self,
        method: Method,
        data: Object<'o>,
        context: &ModuleContext,
    ) -> Result<bool, ModuleError> {
        let bytes = match decode(
            method,
            &data,
            context.largest_file(),
            context.room_to_produce(),
        )? {
            Decoded::Failed => return Ok(false),
            Decoded::Held(bytes) => PartBytes::Produced(bytes),
            Decoded::Measured(length) => {
                PartBytes::Regenerable(Box::new(Regenerated::new(method, data, length)))
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
