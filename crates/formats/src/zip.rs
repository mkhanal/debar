mod bzip2;
mod catalogue;
mod compressed_bits;
mod decoded;
mod deflate64;
mod headers;
mod imploded;
mod little_endian;
mod members;
mod office_open;
mod prefix_codes;
mod shannon_fano;

use debar_image::ObjectKind;

use crate::context::ModuleContext;
use crate::module::{
    AfterTheEntry, ContainerEntry, FormatModule, HeaderCheck, ModuleError, PartSource, Stage,
};
use crate::object::Object;
use crate::zip::headers::{LocalParse, local_record_at};
use crate::zip::members::Members;

const POSITION_OF_A_CHECKED_HEADER: u64 = 0;

pub struct ZipArchives;

pub static ZIP_ARCHIVES: ZipArchives = ZipArchives;

const CLAIMED_KINDS: [ObjectKind; 5] = [
    ObjectKind::Zip,
    ObjectKind::OfficeOpenWord,
    ObjectKind::OfficeOpenPresentation,
    ObjectKind::OfficeOpenSpreadsheet,
    ObjectKind::HangulOpen,
];

impl FormatModule for ZipArchives {
    fn kinds(&self) -> &[ObjectKind] {
        &CLAIMED_KINDS
    }

    fn stage(&self) -> Stage {
        Stage::BeforeOwnBytes
    }

    fn open<'o>(
        &self,
        object: Object<'o>,
        context: &mut ModuleContext,
    ) -> Result<Box<dyn PartSource<'o> + 'o>, ModuleError> {
        Ok(Box::new(Members::new(object, context)))
    }

    fn header_check(
        &self,
        from: &Object<'_>,
        entries: &mut dyn FnMut(ContainerEntry) -> AfterTheEntry,
    ) -> Result<HeaderCheck, ModuleError> {
        let record = match local_record_at(from, 0, None, POSITION_OF_A_CHECKED_HEADER)? {
            LocalParse::Unreadable => return Ok(HeaderCheck::Fails),
            LocalParse::Rejected { entry } => {
                entries(entry);
                return Ok(HeaderCheck::Fails);
            }
            LocalParse::Accepted { entry, record } => {
                if entries(entry) == AfterTheEntry::Stop {
                    return Ok(HeaderCheck::Fails);
                }
                record
            }
        };
        if record.compressed_size == 0 || record.real_size == 0 {
            return Ok(HeaderCheck::Fails);
        }
        Ok(HeaderCheck::Holds {
            length: record.end(),
        })
    }

    fn refined_kind(
        &self,
        object: &Object<'_>,
        typed_as: ObjectKind,
        entries: &mut dyn FnMut(ContainerEntry) -> AfterTheEntry,
    ) -> Result<Option<ObjectKind>, ModuleError> {
        if typed_as != ObjectKind::Zip {
            return Ok(None);
        }
        Ok(office_open::office_kind(object, entries)?)
    }
}
