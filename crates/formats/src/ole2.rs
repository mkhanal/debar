mod codepages;
mod compressed_container;
mod directory;
mod findings;
mod folders;
mod header;
mod normalised_source;
mod project_text;
mod sectors;
mod stream_bytes;
mod streams;
mod visited;
mod walk;
mod zlib_stream;

use debar_image::ObjectKind;

use crate::context::ModuleContext;
use crate::module::{FormatModule, ModuleError, PartSource, Stage};
use crate::object::Object;
use crate::ole2::streams::DocumentStreams;

pub struct Ole2Documents;

pub static OLE2_DOCUMENTS: Ole2Documents = Ole2Documents;

const CLAIMED_KINDS: [ObjectKind; 1] = [ObjectKind::Ole2];

impl FormatModule for Ole2Documents {
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
        Ok(Box::new(DocumentStreams::new(object, context)))
    }
}
