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
        match context.current_kind() {
            ObjectKind::Html => Ok(Box::new(TextView::Finished)),
            ObjectKind::Mail => Ok(Box::new(TextView::PendingThenMatchedAsMail(object))),
            _ => Ok(Box::new(TextView::Pending(object))),
        }
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
    PendingThenMatchedAsMail(Object<'o>),
    Pending(Object<'o>),
    MatchedAsMail { length: u64 },
    Finished,
}

impl<'o> PartSource<'o> for TextView<'o> {
    fn next(
        &mut self,
        context: &mut ModuleContext,
    ) -> Result<Option<ModuleOutput<'o>>, ModuleError> {
        let object = match std::mem::replace(self, TextView::Finished) {
            TextView::Pending(object) => object,
            TextView::PendingThenMatchedAsMail(object) => {
                *self = TextView::MatchedAsMail {
                    length: object.length(),
                };
                object
            }
            TextView::MatchedAsMail { length } => {
                return Ok(Some(ModuleOutput::Part(Part {
                    bytes: PartBytes::Window { offset: 0, length },
                    role: PartRole::View {
                        matched_as: ObjectKind::Mail,
                    },
                })));
            }
            TextView::Finished => return Ok(None),
        };
        if object.length() > LARGEST_TEXT_NORMALISED {
            return self.next(context);
        }
        let Some(piece) = context
            .text_normalised_in_pieces_of()
            .and_then(PieceLength::of_raw_bytes)
        else {
            return self.next(context);
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
