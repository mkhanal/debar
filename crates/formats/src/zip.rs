mod catalogue;
mod headers;
mod inflated;
mod little_endian;
mod members;
mod office_open;

use debar_image::ObjectKind;

use crate::context::ModuleContext;
use crate::module::{FormatModule, HeaderCheck, ModuleError, PartSource, Stage};
use crate::object::Object;
use crate::zip::headers::{LocalParse, local_record_at};
use crate::zip::members::Members;

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

    fn header_check(&self, from: &Object<'_>) -> Result<HeaderCheck, ModuleError> {
        let LocalParse::Accepted { record, .. } = local_record_at(from, 0, None, 0)? else {
            return Ok(HeaderCheck::Fails);
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
    ) -> Result<Option<ObjectKind>, ModuleError> {
        if typed_as != ObjectKind::Zip {
            return Ok(None);
        }
        Ok(office_open::office_kind(object)?)
    }
}
