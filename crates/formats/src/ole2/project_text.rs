use debar_platform::input::InputError;

use crate::ole2::codepages::{Codepage, LATIN_1, UTF_16_LITTLE_ENDIAN, to_utf8};
use crate::ole2::directory::decoded_name;
use crate::ole2::normalised_source::normalised;

const BANNER: &[u8] = b"REM VBA project extracted from Microsoft Office document\n\n";
const UNDECODABLE_STRING: &[u8] = b"<error decoding string>";
const UNDECODABLE_SOURCE: &[u8] = b"\n<Error decoding module data>\n";
const MODULE_SOURCE_RULE: &[u8] = b"\nREM ##################################################\n";
const RECORD_HEADER_BYTES: usize = 6;
const ID_BYTES: usize = 2;
const LONGEST_PROJECT_NAME: usize = 128;
const LONGEST_DOCSTRING: usize = 2000;
const LONGEST_HELP_FILE_PATH: usize = 260;
const NAME_TERMINATOR_BYTES: usize = 2;

const SYSKIND: u16 = 0x0001;
const LCID: u16 = 0x0002;
const CODEPAGE: u16 = 0x0003;
const NAME: u16 = 0x0004;
const DOCSTRING: u16 = 0x0005;
const HELP_FILE_PATH: u16 = 0x0006;
const HELP_CONTEXT: u16 = 0x0007;
const LIBFLAGS: u16 = 0x0008;
const VERSION: u16 = 0x0009;
const MODULES: u16 = 0x000f;
const TERMINATOR: u16 = 0x0010;
const COOKIE: u16 = 0x0013;
const LCID_INVOKE: u16 = 0x0014;
const MODULE_NAME: u16 = 0x0019;
const MODULE_STREAM_NAME: u16 = 0x001a;
const MODULE_DOCSTRING: u16 = 0x001c;
const MODULE_HELP_CONTEXT: u16 = 0x001e;
const MODULE_PROCEDURAL: u16 = 0x0021;
const MODULE_CLASS: u16 = 0x0022;
const MODULE_READ_ONLY: u16 = 0x0025;
const MODULE_PRIVATE: u16 = 0x0028;
const MODULE_TERMINATOR: u16 = 0x002b;
const MODULE_COOKIE: u16 = 0x002c;
const MODULE_OFFSET: u16 = 0x0031;
const MODULE_STREAM_NAME_UNICODE: u16 = 0x0032;
const HELP_FILE_PATH_2: u16 = 0x003d;
const DOCSTRING_UNICODE: u16 = 0x0040;
const MODULE_NAME_UNICODE: u16 = 0x0047;
const MODULE_DOCSTRING_UNICODE: u16 = 0x0048;

const SYSKIND_NAMES: [&str; 4] = [
    "Windows 16 bit",
    "Windows 32 bit",
    "Macintosh",
    "Windows 64 bit",
];

pub trait ModuleSources {
    fn source(&mut self, stream_name: &str, offset: u32) -> Result<Option<Vec<u8>>, InputError>;
}

pub fn project_text(
    dir: &[u8],
    sources: &mut dyn ModuleSources,
) -> Result<Option<Vec<u8>>, InputError> {
    let mut writer = Writer {
        records: Records { bytes: dir, at: 0 },
        text: BANNER.to_vec(),
        codepage: LATIN_1,
    };
    Ok(writer.project(sources)?.then_some(writer.text))
}

struct Records<'d> {
    bytes: &'d [u8],
    at: usize,
}

struct Record<'d> {
    id: u16,
    data: &'d [u8],
}

impl<'d> Records<'d> {
    fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.at)
    }

    fn u16_at(&self, at: usize) -> Option<u16> {
        let bytes = self.bytes.get(at..at.checked_add(2)?)?;
        Some(u16::from_le_bytes([*bytes.first()?, *bytes.get(1)?]))
    }

    fn u32_at(&self, at: usize) -> Option<u32> {
        let bytes = self.bytes.get(at..at.checked_add(4)?)?;
        Some(u32::from_le_bytes(bytes.try_into().ok()?))
    }

    fn peek_id(&self) -> Option<u16> {
        self.u16_at(self.at)
    }

    fn next(&mut self) -> Option<Record<'d>> {
        if self.remaining() < RECORD_HEADER_BYTES {
            return None;
        }
        let id = self.u16_at(self.at)?;
        let size = usize::try_from(self.u32_at(self.at.checked_add(ID_BYTES)?)?).ok()?;
        let start = self.at.checked_add(RECORD_HEADER_BYTES)?;
        let data = self.bytes.get(start..start.checked_add(size)?)?;
        self.at = start.saturating_add(size);
        Some(Record { id, data })
    }

    fn take(&mut self, length: usize) -> Option<&'d [u8]> {
        let taken = self.bytes.get(self.at..self.at.checked_add(length)?)?;
        self.at = self.at.saturating_add(length);
        Some(taken)
    }

    fn following(&self, length: usize) -> Option<&'d [u8]> {
        let start = self.at.checked_sub(length)?;
        self.bytes
            .get(start..self.at.checked_add(NAME_TERMINATOR_BYTES)?)
    }
}

struct Writer<'d> {
    records: Records<'d>,
    text: Vec<u8>,
    codepage: Codepage,
}

impl<'d> Writer<'d> {
    fn project(&mut self, sources: &mut dyn ModuleSources) -> Result<bool, InputError> {
        while self.records.remaining() > 0 {
            let Some(record) = self.records.next() else {
                return Ok(false);
            };
            let written = match record.id {
                SYSKIND => self.syskind(record.data),
                LCID => self.hex_line(b"REM PROJECTLCID: ", record.data, 4, 8),
                LCID_INVOKE => self.hex_line(b"REM PROJECTLCIDINVOKE: ", record.data, 4, 8),
                CODEPAGE => self.codepage(record.data),
                NAME => {
                    self.string_line(b"REM PROJECTNAME: ", record.data, 1, LONGEST_PROJECT_NAME)
                }
                DOCSTRING => {
                    self.string_line(b"REM PROJECTDOCSTRING: ", record.data, 0, LONGEST_DOCSTRING)
                }
                DOCSTRING_UNICODE => self.unicode_line(record.data),
                HELP_FILE_PATH => self.help_file_paths(record.data),
                HELP_CONTEXT => self.hex_line(b"REM PROJECTHELPCONTEXT: ", record.data, 4, 4),
                LIBFLAGS => self.hex_line(b"REM PROJECTLIBFLAGS: ", record.data, 4, 4),
                VERSION => self.version(record.data),
                MODULES => self.decimal_line(b"REM PROJECTMODULES: ", record.data),
                COOKIE => self.hex_line(b"REM PROJECTCOOKIE: ", record.data, 2, 4),
                MODULE_NAME => self.module(record.data, sources)?,
                TERMINATOR => return Ok(true),
                _ => true,
            };
            if !written {
                return Ok(false);
            }
        }
        Ok(true)
    }

    fn syskind(&mut self, data: &[u8]) -> bool {
        let Some(kind) = exact_u32(data) else {
            return false;
        };
        self.text.extend_from_slice(b"REM PROJECTSYSKIND: ");
        match SYSKIND_NAMES.get(usize::try_from(kind).unwrap_or(usize::MAX)) {
            Some(name) => self.text.extend_from_slice(name.as_bytes()),
            None => self
                .text
                .extend_from_slice(format!("Unknown (0x{kind:x})").as_bytes()),
        }
        self.text.push(b'\n');
        true
    }

    fn hex_line(&mut self, prefix: &[u8], data: &[u8], size: usize, digits: usize) -> bool {
        let Some(value) = exact_number(data, size) else {
            return false;
        };
        self.text.extend_from_slice(prefix);
        self.text
            .extend_from_slice(format!("0x{value:0digits$x}\n").as_bytes());
        true
    }

    fn decimal_line(&mut self, prefix: &[u8], data: &[u8]) -> bool {
        let Some(value) = exact_number(data, 2) else {
            return false;
        };
        self.text.extend_from_slice(prefix);
        self.text.extend_from_slice(format!("{value}\n").as_bytes());
        true
    }

    fn codepage(&mut self, data: &[u8]) -> bool {
        let Some(value) = exact_number(data, 2) else {
            return false;
        };
        self.codepage = Codepage(u16::try_from(value).unwrap_or(0));
        self.text
            .extend_from_slice(format!("REM PROJECTCODEPAGE: 0x{value:04x}\n").as_bytes());
        true
    }

    fn string_line(&mut self, prefix: &[u8], data: &[u8], shortest: usize, longest: usize) -> bool {
        if data.len() < shortest || data.len() > longest {
            return false;
        }
        self.text.extend_from_slice(prefix);
        self.converted(data, self.codepage);
        self.text.push(b'\n');
        true
    }

    fn unicode_line(&mut self, data: &[u8]) -> bool {
        if data.len() % 2 == 1 {
            return false;
        }
        self.text
            .extend_from_slice(b"REM PROJECTDOCSTRINGUNICODE: ");
        self.converted(data, UTF_16_LITTLE_ENDIAN);
        self.text.push(b'\n');
        true
    }

    fn help_file_paths(&mut self, first: &[u8]) -> bool {
        if first.len() > LONGEST_HELP_FILE_PATH {
            return false;
        }
        self.text.extend_from_slice(b"REM PROJECTHELPFILEPATH: ");
        self.converted(first, self.codepage);
        self.text.push(b'\n');
        let Some(next_id) = self.records.peek_id() else {
            return false;
        };
        if next_id != HELP_FILE_PATH_2 {
            self.text.extend_from_slice(
                b"REM WARNING: PROJECTHELPFILEPATH is not followed by PROJECTHELPFILEPATH2\n",
            );
            return true;
        }
        let Some(second) = self.records.next() else {
            return false;
        };
        if second.data.len() > LONGEST_HELP_FILE_PATH {
            return false;
        }
        if second.data.len() != first.len() {
            self.text.extend_from_slice(
                b"REM WARNING: PROJECTHELPFILEPATH and PROJECTHELPFILEPATH2 record sizes differ\n",
            );
        } else if second.data != first {
            self.text.extend_from_slice(
                b"REM WARNING: PROJECTHELPFILEPATH and PROJECTHELPFILEPATH2 contents differ\n",
            );
        }
        self.text.extend_from_slice(b"REM PROJECTHELPFILEPATH2: ");
        self.converted(second.data, UTF_16_LITTLE_ENDIAN);
        self.text.push(b'\n');
        true
    }

    fn version(&mut self, data: &[u8]) -> bool {
        if data.len() != 4 {
            return false;
        }
        let Some(major) = exact_u32(data) else {
            return false;
        };
        let Some(minor) = self.records.take(2) else {
            return false;
        };
        let minor = u16::from_le_bytes([
            minor.first().copied().unwrap_or(0),
            minor.get(1).copied().unwrap_or(0),
        ]);
        self.text
            .extend_from_slice(format!("REM PROJECTVERSION: {major}.{minor}\n").as_bytes());
        true
    }

    fn module(
        &mut self,
        name: &'d [u8],
        sources: &mut dyn ModuleSources,
    ) -> Result<bool, InputError> {
        self.text.extend_from_slice(b"\n\nREM MODULENAME: ");
        let name_text = self.converted(name, self.codepage);
        let Some(unicode) = self.sub_record(MODULE_NAME_UNICODE) else {
            return Ok(false);
        };
        self.paired_unicode(
            b"\nREM MODULENAMEUNICODE: ",
            unicode,
            name_text.as_deref(),
            b"\nREM WARNING: MODULENAME and MODULENAMEUNICODE differ",
        );
        let Some(stream_name) = self.sub_record(MODULE_STREAM_NAME) else {
            return Ok(false);
        };
        self.text.extend_from_slice(b"\nREM MODULESTREAMNAME: ");
        let stream_name_text = self.converted(stream_name, self.codepage);
        let Some(stream_unicode) = self.sub_record(MODULE_STREAM_NAME_UNICODE) else {
            return Ok(false);
        };
        let Some(lookup) = self
            .records
            .following(stream_unicode.len())
            .and_then(|bytes| {
                let size =
                    u16::try_from(stream_unicode.len().checked_add(NAME_TERMINATOR_BYTES)?).ok()?;
                decoded_name(bytes, size)
            })
        else {
            return Ok(false);
        };
        self.paired_unicode(
            b"\nREM MODULESTREAMNAMEUNICODE: ",
            stream_unicode,
            stream_name_text.as_deref(),
            b"\nREM WARNING: MODULESTREAMNAME and MODULESTREAMNAMEUNICODE differ",
        );
        let Some(docstring) = self.sub_record(MODULE_DOCSTRING) else {
            return Ok(false);
        };
        self.text.extend_from_slice(b"\nREM MODULEDOCSTRING: ");
        let docstring_text = self.converted(docstring, self.codepage);
        let Some(docstring_unicode) = self.sub_record(MODULE_DOCSTRING_UNICODE) else {
            return Ok(false);
        };
        self.paired_unicode(
            b"\nREM MODULEDOCSTRINGUNICODE: ",
            docstring_unicode,
            docstring_text.as_deref(),
            b"\nREM WARNING: MODULEDOCSTRING and MODULEDOCSTRINGUNICODE differ",
        );
        let Some(offset) = self.sub_record(MODULE_OFFSET).and_then(exact_u32) else {
            return Ok(false);
        };
        self.text
            .extend_from_slice(format!("\nREM MODULEOFFSET: 0x{offset:08x}").as_bytes());
        let Some(help) = self.sub_record(MODULE_HELP_CONTEXT).and_then(exact_u32) else {
            return Ok(false);
        };
        self.text
            .extend_from_slice(format!("\nREM MODULEHELPCONTEXT: 0x{help:08x}").as_bytes());
        let Some(cookie) = self
            .sub_record(MODULE_COOKIE)
            .and_then(|data| exact_number(data, 2))
        else {
            return Ok(false);
        };
        self.text
            .extend_from_slice(format!("\nREM MODULECOOKIE: 0x{cookie:04x}").as_bytes());
        if !self.module_type() || !self.module_flags_and_end() {
            return Ok(false);
        }
        if let Some(source) = sources.source(&lookup, offset)? {
            match to_utf8(&source, self.codepage) {
                Some(converted) => self.text.extend_from_slice(&normalised(&converted)),
                None => self.text.extend_from_slice(UNDECODABLE_SOURCE),
            }
        }
        Ok(true)
    }

    fn module_type(&mut self) -> bool {
        let Some(id) = self.records.peek_id() else {
            return false;
        };
        let written: &[u8] = match id {
            MODULE_PROCEDURAL => b"\nREM MODULETYPE: Procedural",
            MODULE_CLASS => b"\nREM MODULETYPE: Class",
            _ => return false,
        };
        if !self.sub_record(id).is_some_and(<[u8]>::is_empty) {
            return false;
        }
        self.text.extend_from_slice(written);
        true
    }

    fn module_flags_and_end(&mut self) -> bool {
        for (id, written) in [
            (MODULE_READ_ONLY, b"\nREM MODULEREADONLY".as_slice()),
            (MODULE_PRIVATE, b"\nREM MODULEPRIVATE".as_slice()),
        ] {
            if self.records.peek_id() == Some(id) {
                if !self.sub_record(id).is_some_and(<[u8]>::is_empty) {
                    return false;
                }
                self.text.extend_from_slice(written);
            }
        }
        if !self
            .sub_record(MODULE_TERMINATOR)
            .is_some_and(<[u8]>::is_empty)
        {
            return false;
        }
        self.text.extend_from_slice(MODULE_SOURCE_RULE);
        true
    }

    fn sub_record(&mut self, id: u16) -> Option<&'d [u8]> {
        if self.records.peek_id() != Some(id) {
            return None;
        }
        self.records.next().map(|record| record.data)
    }

    fn paired_unicode(
        &mut self,
        prefix: &[u8],
        unicode: &[u8],
        single_byte: Option<&[u8]>,
        warning: &[u8],
    ) {
        self.text.extend_from_slice(prefix);
        let converted = self.converted(unicode, UTF_16_LITTLE_ENDIAN);
        if let (Some(single_byte), Some(converted)) = (single_byte, converted)
            && single_byte != converted.as_slice()
        {
            self.text.extend_from_slice(warning);
        }
    }

    fn converted(&mut self, data: &[u8], codepage: Codepage) -> Option<Vec<u8>> {
        if data.is_empty() {
            return None;
        }
        let converted = to_utf8(data, codepage);
        match &converted {
            Some(text) => self.text.extend_from_slice(text),
            None => self.text.extend_from_slice(UNDECODABLE_STRING),
        }
        converted
    }
}

fn exact_u32(data: &[u8]) -> Option<u32> {
    Some(u32::from_le_bytes(data.try_into().ok()?))
}

fn exact_number(data: &[u8], size: usize) -> Option<u64> {
    if data.len() != size {
        return None;
    }
    match size {
        2 => Some(u64::from(u16::from_le_bytes(data.try_into().ok()?))),
        4 => Some(u64::from(u32::from_le_bytes(data.try_into().ok()?))),
        _ => None,
    }
}
