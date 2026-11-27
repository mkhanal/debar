mod document;
mod document_parts;
mod extraction;
mod filter_chain;
mod filters;
mod javascript;
mod names;
mod object_dictionary;
mod object_streams;
mod objects;
mod page_text;
mod pulled;
mod searchable;
mod stream_length;
mod tokens;

use debar_image::ObjectKind;

use crate::context::ModuleContext;
use crate::module::{FormatModule, ModuleError, PartSource, Stage};
use crate::object::Object;
use crate::pdf::document_parts::DocumentParts;

pub struct PdfDocuments;

pub static PDF_DOCUMENTS: PdfDocuments = PdfDocuments;

const CLAIMED_KINDS: [ObjectKind; 1] = [ObjectKind::Pdf];

impl FormatModule for PdfDocuments {
    fn kinds(&self) -> &[ObjectKind] {
        &CLAIMED_KINDS
    }

    fn stage(&self) -> Stage {
        Stage::AfterOwnBytes
    }

    fn open<'o>(
        &self,
        object: Object<'o>,
        _context: &mut ModuleContext,
    ) -> Result<Box<dyn PartSource<'o> + 'o>, ModuleError> {
        Ok(Box::new(DocumentParts::Unopened(object)))
    }
}
