mod boundaries;
mod header_text;
mod headers;
mod line_decoding;
mod lines;
mod message;
mod output;
mod similarity;
mod stored;
mod walk;

use std::collections::VecDeque;

use debar_image::ObjectKind;

use crate::context::ModuleContext;
use crate::limits::Limit;
use crate::mail::lines::Reading;
use crate::mail::message::{Opened, open_message_file};
use crate::mail::output::{Output, Produced, Regenerated, produce};
use crate::mail::stored::StoredLines;
use crate::mail::walk::{Plan, Walker};
use crate::module::{
    FormatModule, ModuleError, ModuleOutput, Part, PartBytes, PartRole, PartSource, Stage,
};
use crate::object::Object;

pub const DEEPEST_MIME_NESTING: u32 = 64;

pub struct MailMessages;

pub static MAIL_MESSAGES: MailMessages = MailMessages;

const CLAIMED_KINDS: [ObjectKind; 2] = [ObjectKind::Mail, ObjectKind::Mhtml];

impl FormatModule for MailMessages {
    fn kinds(&self) -> &[ObjectKind] {
        &CLAIMED_KINDS
    }

    fn stage(&self) -> Stage {
        Stage::BeforeOwnBytes
    }

    fn open<'o>(
        &self,
        object: Object<'o>,
        _context: &mut ModuleContext,
    ) -> Result<Box<dyn PartSource<'o> + 'o>, ModuleError> {
        Ok(Box::new(MessageParts {
            object,
            state: State::Unread,
        }))
    }
}

struct MessageParts<'o> {
    object: Object<'o>,
    state: State,
}

enum State {
    Unread,
    Yielding {
        outputs: VecDeque<Output>,
        limit: Option<Limit>,
    },
    Finished,
}

impl<'o> PartSource<'o> for MessageParts<'o> {
    fn next(
        &mut self,
        context: &mut ModuleContext,
    ) -> Result<Option<ModuleOutput<'o>>, ModuleError> {
        loop {
            match &mut self.state {
                State::Unread => self.state = self.planned(context)?,
                State::Yielding { outputs, limit } => {
                    let Some(output) = outputs.pop_front() else {
                        if let Some(limit) = limit.take() {
                            context.reached(limit);
                        }
                        self.state = State::Finished;
                        continue;
                    };
                    if let Some(bytes) = self.bytes_of(output, context)? {
                        return Ok(Some(ModuleOutput::Part(Part {
                            bytes,
                            role: PartRole::Child { kind: None },
                        })));
                    }
                }
                State::Finished => return Ok(None),
            }
        }
    }
}

fn plan_outputs(plan: Plan) -> State {
    let mut outputs: VecDeque<Output> = plan.at_once.into();
    if plan.folder_scanned {
        outputs.extend(plan.folder);
    }
    State::Yielding {
        outputs,
        limit: plan.limit,
    }
}

impl<'o> MessageParts<'o> {
    fn planned(&self, context: &ModuleContext) -> Result<State, ModuleError> {
        let message = match open_message_file(&self.object)? {
            Opened::Nothing => return Ok(State::Finished),
            Opened::Mailbox(separators) => {
                let plan = self.walker(context).walk_mailbox(&separators)?;
                return Ok(plan_outputs(plan));
            }
            Opened::Message(message) => message,
        };
        let mut uuencoded = Vec::new();
        if let Some(body) = message.body {
            let mut lines = StoredLines::new(&self.object, body, Reading::First);
            while lines.next_line()?.is_some() {}
            uuencoded = lines.take_uuencoded_blocks();
        }
        let plan = self.walker(context).walk(message, uuencoded)?;
        Ok(plan_outputs(plan))
    }

    fn walker<'w>(&'w self, context: &ModuleContext) -> Walker<'w, 'o> {
        let deepest = match context.deepest_level() {
            0 => DEEPEST_MIME_NESTING,
            deepest => deepest.min(DEEPEST_MIME_NESTING),
        };
        Walker::new(&self.object, context.most_files(), deepest)
    }

    fn bytes_of(
        &self,
        output: Output,
        context: &ModuleContext,
    ) -> Result<Option<PartBytes<'o>>, ModuleError> {
        Ok(
            match produce(&self.object, &output, context.room_to_produce())? {
                Produced::Held(bytes) if bytes.is_empty() => None,
                Produced::Held(bytes) => Some(PartBytes::Produced(bytes)),
                Produced::Measured(0) => None,
                Produced::Measured(length) => Some(PartBytes::Regenerable(Box::new(
                    Regenerated::new(self.object.clone(), output, length),
                ))),
            },
        )
    }
}
