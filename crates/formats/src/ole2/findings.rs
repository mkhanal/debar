use std::rc::Rc;

use debar_platform::input::{InputError, ObjectBytes};

use crate::little_endian::Fields;
use crate::ole2::directory::{DirectoryEntry, EntryType};
use crate::ole2::sectors::Sectors;
use crate::ole2::stream_bytes::ChainedStream;

const MACRO_STREAM_NAMES: [&str; 4] = [
    "_vba_project",
    "powerpoint document",
    "worddocument",
    "_1_ole10native",
];
const VBA_PROJECT_NAME: &str = "_vba_project";
const WORKBOOK_NAMES: [&str; 2] = ["workbook", "book"];
const HANGUL_HEADER_NAME: &str = "fileheader";
const HANGUL_SIGNATURE: &[u8] = b"HWP Document File";
const BOUNDSHEET: u16 = 0x85;
const BOUNDSHEET_SHEET_TYPE_AT: u16 = 5;
const MACRO_SHEET: u8 = 1;
const DRAWING_GROUP: u16 = 0xeb;
const BIFF_HEADER_BYTES: usize = 4;
const BIFF_READ_BYTES: usize = 4096;
const ENCRYPTION_STREAM_NAMES: [&str; 2] = ["encryptioninfo", "encryptedpackage"];
const WORD_LIKE_NAMES: [&str; 2] = ["worddocument", "powerpoint document"];
const WORD_IDENTIFIER: u16 = 0xa5ec;
const WORD_FLAGS_AT: usize = 10;
const WORD_ENCRYPTED_FLAG: u16 = 0x0100;
const WORD_HEADER_BYTES: u64 = 12;
const WORKBOOK_BEGINNING: u16 = 0x0809;
const FILE_PASSWORD_RECORD: u16 = 0x2f;
const WORKBOOK_SEARCHED_BYTES: u64 = 512;

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Findings {
    pub project: ProjectSigns,
    pub workbook: WorkbookSigns,
    pub is_hangul: bool,
    pub encrypted: bool,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ProjectSigns {
    pub names_a_macro_stream: bool,
    pub holds_a_vba_project: bool,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct WorkbookSigns {
    pub has_macro_sheets: bool,
    pub has_drawing_group: bool,
}

impl Findings {
    pub const fn streams_go_to_a_folder(self) -> bool {
        self.project.names_a_macro_stream
            || self.workbook.has_macro_sheets
            || self.workbook.has_drawing_group
    }

    pub const fn folder_is_scanned(self) -> bool {
        self.project.names_a_macro_stream || self.workbook.has_macro_sheets
    }

    pub fn note_counted_stream(
        &mut self,
        sectors: &Rc<Sectors<'_>>,
        entry: &DirectoryEntry,
    ) -> Result<(), InputError> {
        let Some(name) = entry.name.as_deref() else {
            return Ok(());
        };
        if MACRO_STREAM_NAMES.contains(&name) {
            self.project.names_a_macro_stream = true;
        }
        if name == VBA_PROJECT_NAME {
            self.project.holds_a_vba_project = true;
        }
        if !self.is_hangul && name == HANGUL_HEADER_NAME && entry.chain.declared_size > 0 {
            let stream = ChainedStream::measured(Rc::clone(sectors), entry.chain)?;
            self.is_hangul = starts_with(&stream, HANGUL_SIGNATURE)?;
        }
        if WORKBOOK_NAMES.contains(&name)
            && !(self.workbook.has_macro_sheets && self.workbook.has_drawing_group)
        {
            let stream = ChainedStream::measured(Rc::clone(sectors), entry.chain)?;
            self.note_workbook_records(&stream)?;
        }
        Ok(())
    }

    pub fn note_encryption(
        &mut self,
        sectors: &Rc<Sectors<'_>>,
        entry: &DirectoryEntry,
    ) -> Result<(), InputError> {
        let Some(name) = entry.name.as_deref() else {
            return Ok(());
        };
        if ENCRYPTION_STREAM_NAMES.contains(&name) {
            self.encrypted = true;
            return Ok(());
        }
        if entry.entry_type != EntryType::Stream {
            return Ok(());
        }
        if WORD_LIKE_NAMES.contains(&name) {
            let stream = ChainedStream::measured(Rc::clone(sectors), entry.chain)?;
            if let Some(header) = first_bytes(&stream, WORD_HEADER_BYTES)? {
                let fields = Fields::of(&header);
                if fields.u16_at(0) == WORD_IDENTIFIER {
                    self.encrypted = fields.u16_at(WORD_FLAGS_AT) & WORD_ENCRYPTED_FLAG != 0;
                }
            }
        } else if WORKBOOK_NAMES.contains(&name) {
            let stream = ChainedStream::measured(Rc::clone(sectors), entry.chain)?;
            if workbook_has_a_password(&stream)? {
                self.encrypted = true;
            }
        }
        Ok(())
    }

    fn note_workbook_records(&mut self, stream: &ChainedStream<'_>) -> Result<(), InputError> {
        let mut records = RecordReader::default();
        let mut chunk = vec![0u8; BIFF_READ_BYTES];
        let mut offset = 0u64;
        while offset < stream.length() {
            let length = stream.length().saturating_sub(offset).min(chunk.length());
            let Some(part) = chunk.get_mut(..usize::try_from(length).unwrap_or(0)) else {
                break;
            };
            stream.read_at(offset, part)?;
            for byte in part.iter() {
                if let Some((opcode, at, value)) = records.feed(*byte) {
                    if opcode == BOUNDSHEET
                        && at == BOUNDSHEET_SHEET_TYPE_AT
                        && value == MACRO_SHEET
                    {
                        self.workbook.has_macro_sheets = true;
                    }
                    if opcode == DRAWING_GROUP {
                        self.workbook.has_drawing_group = true;
                    }
                }
            }
            offset = offset.saturating_add(length);
        }
        Ok(())
    }
}

#[derive(Default)]
struct RecordReader {
    header: [u8; BIFF_HEADER_BYTES],
    header_filled: usize,
    opcode: u16,
    data_left: u16,
    data_at: u16,
}

impl RecordReader {
    fn feed(&mut self, byte: u8) -> Option<(u16, u16, u8)> {
        if self.data_left > 0 {
            let at = self.data_at;
            self.data_at = self.data_at.saturating_add(1);
            self.data_left = self.data_left.saturating_sub(1);
            return Some((self.opcode, at, byte));
        }
        if let Some(slot) = self.header.get_mut(self.header_filled) {
            *slot = byte;
        }
        self.header_filled = self.header_filled.saturating_add(1);
        if self.header_filled == BIFF_HEADER_BYTES {
            let fields = Fields::of(&self.header);
            self.opcode = fields.u16_at(0);
            self.data_left = fields.u16_at(2);
            self.data_at = 0;
            self.header_filled = 0;
        }
        None
    }
}

fn starts_with(stream: &ChainedStream<'_>, expected: &[u8]) -> Result<bool, InputError> {
    let wanted = expected.length();
    Ok(first_bytes(stream, wanted)?.is_some_and(|found| found == expected))
}

fn first_bytes(stream: &ChainedStream<'_>, wanted: u64) -> Result<Option<Vec<u8>>, InputError> {
    if stream.length() < wanted {
        return Ok(None);
    }
    let mut bytes = vec![0u8; usize::try_from(wanted).unwrap_or(0)];
    stream.read_at(0, &mut bytes)?;
    Ok(Some(bytes))
}

fn workbook_has_a_password(stream: &ChainedStream<'_>) -> Result<bool, InputError> {
    let searched = stream.length().min(WORKBOOK_SEARCHED_BYTES);
    let Some(bytes) = first_bytes(stream, searched)? else {
        return Ok(false);
    };
    let fields = Fields::of(&bytes);
    if fields.u16_at(0) != WORKBOOK_BEGINNING {
        return Ok(false);
    }
    let mut at = 0usize;
    while at.saturating_add(BIFF_HEADER_BYTES) <= bytes.len() {
        let opcode = fields.u16_at(at);
        if opcode == FILE_PASSWORD_RECORD {
            return Ok(true);
        }
        let length = usize::from(fields.u16_at(at.saturating_add(2)));
        at = at.saturating_add(BIFF_HEADER_BYTES).saturating_add(length);
    }
    Ok(false)
}
