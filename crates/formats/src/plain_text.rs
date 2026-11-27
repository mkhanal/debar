mod normalised_text;

use debar_image::ObjectKind;
use debar_platform::input::ObjectBytes;

use crate::context::ModuleContext;
use crate::module::{
    FormatModule, ModuleError, ModuleOutput, Part, PartBytes, PartRole, PartSource, Stage,
};
use crate::object::Object;
use crate::plain_text::normalised_text::{NormalisedText, PieceLength, Regenerated, normalise};

pub const LARGEST_TEXT_NORMALISED: u64 = 20 * 1024 * 1024;

pub struct PlainText;

pub static PLAIN_TEXT: PlainText = PlainText;

pub struct ScriptText;

pub static SCRIPT_TEXT: ScriptText = ScriptText;

const TEXT_KINDS: [ObjectKind; 4] = [
    ObjectKind::Text,
    ObjectKind::TextUtf8,
    ObjectKind::TextUtf16LittleEndian,
    ObjectKind::TextUtf16BigEndian,
];

const SCRIPT_KINDS: [ObjectKind; 1] = [ObjectKind::Script];

impl FormatModule for PlainText {
    fn kinds(&self) -> &[ObjectKind] {
        &TEXT_KINDS
    }

    fn stage(&self) -> Stage {
        Stage::AfterOwnBytes
    }

    fn open<'o>(
        &self,
        object: Object<'o>,
        context: &mut ModuleContext,
    ) -> Result<Box<dyn PartSource<'o> + 'o>, ModuleError> {
        if context.current_kind() == ObjectKind::Html {
            return Ok(Box::new(TextView::Finished));
        }
        Ok(Box::new(TextView::Pending(object)))
    }
}

impl FormatModule for ScriptText {
    fn kinds(&self) -> &[ObjectKind] {
        &SCRIPT_KINDS
    }

    fn stage(&self) -> Stage {
        Stage::BeforeOwnBytes
    }

    fn open<'o>(
        &self,
        object: Object<'o>,
        _context: &mut ModuleContext,
    ) -> Result<Box<dyn PartSource<'o> + 'o>, ModuleError> {
        Ok(Box::new(TextView::Pending(object)))
    }
}

enum TextView<'o> {
    Pending(Object<'o>),
    Finished,
}

impl<'o> PartSource<'o> for TextView<'o> {
    fn next(
        &mut self,
        context: &mut ModuleContext,
    ) -> Result<Option<ModuleOutput<'o>>, ModuleError> {
        let TextView::Pending(object) = std::mem::replace(self, TextView::Finished) else {
            return Ok(None);
        };
        if object.length() > LARGEST_TEXT_NORMALISED {
            return Ok(None);
        }
        let Some(piece) = context
            .text_normalised_in_pieces_of()
            .and_then(PieceLength::of_raw_bytes)
        else {
            return Ok(None);
        };
        let bytes = match normalise(&object, piece, context.room_to_produce())? {
            NormalisedText::Held(bytes) => PartBytes::Produced(bytes),
            NormalisedText::Measured(length) => {
                PartBytes::Regenerable(Box::new(Regenerated::new(object, piece, length)))
            }
        };
        Ok(Some(ModuleOutput::Part(Part {
            bytes,
            role: PartRole::View {
                matched_as: ObjectKind::Text,
            },
        })))
    }
}
