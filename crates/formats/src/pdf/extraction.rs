use debar_platform::input::InputError;

use crate::context::ModuleContext;
use crate::module::PartBytes;
use crate::pdf::document::DocumentBytes;
use crate::pdf::filter_chain::{Content, StreamWindow, measure};
use crate::pdf::names::DocumentSigns;
use crate::pdf::object_streams::{ObjectStreams, object_stream_layout};
use crate::pdf::objects::{Home, Mark, ObjectTable, PdfObject, StreamBounds};
use crate::pdf::page_text::{PageTextOf, page_text_of};
use crate::pdf::pulled::{PullFactory, PulledWhole, Reading, Regenerated, WindowSource, pull_all};
use crate::pdf::searchable::Searchable;
use crate::pdf::stream_length::{ObjectStreamText, declared_length};

const DUMPED_FOR: [Mark; 9] = [
    Mark::Contents,
    Mark::Flate,
    Mark::Dct,
    Mark::AsciiHex,
    Mark::Ascii85,
    Mark::EmbeddedFile,
    Mark::JavaScript,
    Mark::OpenAction,
    Mark::LaunchAction,
];

pub enum PageText<'o> {
    NotWanted,
    Held(Vec<u8>),
    Regenerated(PullFactory<'o>),
}

pub enum Extracted<'o> {
    Nothing,
    Part {
        bytes: PartBytes<'o>,
        page_text: PageText<'o>,
    },
}

pub struct Extraction<'d, 'o> {
    pub document: &'d DocumentBytes<'o>,
    pub header: u64,
    pub table: &'d mut ObjectTable,
    pub streams: &'d mut ObjectStreams,
    pub signs: &'d mut DocumentSigns,
}

impl<'o> Extraction<'_, 'o> {
    pub fn extract(
        &mut self,
        index: usize,
        context: &mut ModuleContext,
    ) -> Result<Extracted<'o>, InputError> {
        let Some(object) = self.table.get(index).cloned() else {
            return Ok(Extracted::Nothing);
        };
        if !dumped(&object) {
            return Ok(Extracted::Nothing);
        }
        match (object.home, object.stream) {
            (Home::Document, Some(stream)) if object.marks.has(Mark::Stream) => {
                self.stream(index, &object, stream, context)
            }
            _ if object.marks.has(Mark::JavaScript) => Ok(self.scripts(&object, context)),
            _ => Ok(self.whole_object(&object, context)),
        }
    }

    fn stream(
        &mut self,
        index: usize,
        object: &PdfObject,
        stream: StreamBounds,
        context: &mut ModuleContext,
    ) -> Result<Extracted<'o>, InputError> {
        let dictionary_length = stream.start.saturating_sub(object.start);
        let length = self.stream_length(index, object, stream, dictionary_length);
        if length == 0 {
            return Ok(Extracted::Nothing);
        }
        let layout = object_stream_layout(self.document, object.start, dictionary_length);
        let window = StreamWindow {
            document: self.document.object().clone(),
            offset: stream.start,
            length,
        };
        let filters = object.filters.as_slice();
        let measured = measure(
            &window,
            filters,
            decoding_limit(context),
            context.room_to_produce(),
        )?;
        if let Some(needed) = measured.verdict.needed_beyond_the_limit {
            let _ = context.admit(needed);
        }
        if let (Some(layout), Some(content)) = (layout, measured.verdict.object_stream) {
            let held = match content {
                Content::Nothing => None,
                Content::Raw => self.held_window(&window),
                Content::Decoded { through, length } => match &measured.held {
                    Some(bytes) => Some(bytes.clone()),
                    None if length <= self.streams.room_left() => {
                        held_decoding(&window, filters.get(..through).unwrap_or_default())?
                    }
                    None => None,
                },
            };
            if let Some(held) = held {
                self.streams.add(held, layout, self.table, self.signs);
            }
        }
        let wants_page_text = object.marks.has(Mark::Contents);
        Ok(match measured.verdict.scanned {
            Content::Nothing => {
                let _ = context.admit(0);
                Extracted::Nothing
            }
            Content::Raw => {
                if context.admit(length).is_err() {
                    return Ok(Extracted::Nothing);
                }
                let page_text = if wants_page_text {
                    let reread = window.clone();
                    PageText::Regenerated(Box::new(move || {
                        Box::new(PageTextOf::new(Box::new(WindowSource::new(
                            reread.document.clone(),
                            reread.offset,
                            reread.length,
                            Reading::Again,
                        ))))
                    }))
                } else {
                    PageText::NotWanted
                };
                Extracted::Part {
                    bytes: PartBytes::Window {
                        offset: self.header.saturating_add(stream.start),
                        length,
                    },
                    page_text,
                }
            }
            Content::Decoded { through, length } => {
                if context.admit(length).is_err() {
                    return Ok(Extracted::Nothing);
                }
                let through_filters = filters.get(..through).unwrap_or_default();
                let held = match measured.held {
                    Some(bytes) => Some(bytes),
                    None if length <= context.room_to_produce() => {
                        held_decoding(&window, through_filters)?
                    }
                    None => None,
                };
                decoded_part(
                    &window,
                    through_filters,
                    length,
                    held,
                    wants_page_text,
                    context,
                )
            }
        })
    }

    fn stream_length(
        &self,
        index: usize,
        object: &PdfObject,
        stream: StreamBounds,
        dictionary_length: u64,
    ) -> u64 {
        let declared = declared_length(
            self.document,
            &*self.streams,
            self.table,
            index,
            object.start,
            dictionary_length,
        );
        let mut length = declared.min(stream.size);
        if !object.marks.has(Mark::Flate) && length == 0 {
            length = stream.size;
            let mut last = object.start.saturating_add(stream.size).checked_sub(1);
            if length > 0 {
                match last.and_then(|at| self.document.byte(at)) {
                    Some(b'\n') => {
                        last = last.and_then(|at| at.checked_sub(1));
                        length = length.saturating_sub(1);
                        if length > 0 && last.and_then(|at| self.document.byte(at)) == Some(b'\r') {
                            length = length.saturating_sub(1);
                        }
                    }
                    Some(b'\r') => length = length.saturating_sub(1),
                    _ => {}
                }
            }
        } else if stream.size > length.saturating_add(2) {
            length = stream.size;
        }
        if length == 0 {
            length = stream.size;
        }
        length
    }

    fn held_window(&self, window: &StreamWindow<'o>) -> Option<Vec<u8>> {
        if window.length > self.streams.room_left() {
            return None;
        }
        let mut bytes = Vec::new();
        self.document.copy(window.offset, window.length, &mut bytes);
        Some(bytes)
    }

    fn scripts(&mut self, object: &PdfObject, context: &mut ModuleContext) -> Extracted<'o> {
        let mut admitted = |so_far: u64| context.admit(so_far).is_ok();
        let scripts = match object.home {
            Home::Document => crate::pdf::javascript::scripts_of(
                self.document,
                object.start,
                object.size,
                &mut admitted,
            ),
            Home::ObjectStream(stream) => {
                let Some(text) = self.streams.object_stream(stream) else {
                    return Extracted::Nothing;
                };
                crate::pdf::javascript::scripts_of(text, object.start, object.size, &mut admitted)
            }
        };
        held_part(scripts, object, context)
    }

    fn whole_object(&mut self, object: &PdfObject, context: &mut ModuleContext) -> Extracted<'o> {
        if context.admit(0).is_err() {
            return Extracted::Nothing;
        }
        match object.home {
            Home::Document => {
                let page_text = if object.marks.has(Mark::Contents) {
                    let document = self.document.object().clone();
                    let (start, size) = (object.start, object.size);
                    PageText::Regenerated(Box::new(move || {
                        Box::new(PageTextOf::new(Box::new(WindowSource::new(
                            document.clone(),
                            start,
                            size,
                            Reading::Again,
                        ))))
                    }))
                } else {
                    PageText::NotWanted
                };
                Extracted::Part {
                    bytes: PartBytes::Window {
                        offset: self.header.saturating_add(object.start),
                        length: object.size,
                    },
                    page_text,
                }
            }
            Home::ObjectStream(stream) => {
                let mut bytes = Vec::new();
                if let Some(text) = self.streams.object_stream(stream) {
                    text.copy(object.start, object.size, &mut bytes);
                }
                held_part(bytes, object, context)
            }
        }
    }
}

fn dumped(object: &PdfObject) -> bool {
    let marks = object.marks;
    if marks.has(Mark::Uri) {
        return false;
    }
    let raw_stream = marks.has(Mark::Stream) && !marks.has(Mark::HasFilters);
    if !raw_stream && !marks.any_of(&DUMPED_FOR) {
        return false;
    }
    !marks.has(Mark::Image) || marks.has(Mark::Dct)
}

fn decoding_limit(context: &ModuleContext) -> Option<u64> {
    match (context.scan_bytes_left(), context.largest_file()) {
        (Some(left), Some(largest)) => Some(left.min(largest)),
        (left, largest) => left.or(largest),
    }
}

fn held_decoding(
    window: &StreamWindow<'_>,
    filters: &[crate::pdf::objects::Filter],
) -> Result<Option<Vec<u8>>, InputError> {
    let mut decoding = window.decoding(filters, Reading::Again);
    Ok(match pull_all(decoding.as_mut(), u64::MAX)? {
        PulledWhole::Held(bytes) => Some(bytes),
        PulledWhole::Measured(_) => None,
    })
}

fn decoded_part<'o>(
    window: &StreamWindow<'o>,
    filters: &[crate::pdf::objects::Filter],
    length: u64,
    held: Option<Vec<u8>>,
    wants_page_text: bool,
    context: &ModuleContext,
) -> Extracted<'o> {
    if let Some(bytes) = held {
        let doubled = u64::try_from(bytes.len())
            .unwrap_or(u64::MAX)
            .saturating_mul(2);
        let page_text = if !wants_page_text {
            PageText::NotWanted
        } else if doubled <= context.room_to_produce() {
            PageText::Held(page_text_of(&bytes))
        } else {
            regenerated_page_text(window, filters)
        };
        return Extracted::Part {
            bytes: PartBytes::Produced(bytes),
            page_text,
        };
    }
    let page_text = if wants_page_text {
        regenerated_page_text(window, filters)
    } else {
        PageText::NotWanted
    };
    Extracted::Part {
        bytes: PartBytes::Regenerable(Box::new(Regenerated::new(
            window.regenerating(filters),
            length,
        ))),
        page_text,
    }
}

fn regenerated_page_text<'o>(
    window: &StreamWindow<'o>,
    filters: &[crate::pdf::objects::Filter],
) -> PageText<'o> {
    let decoding = window.regenerating(filters);
    PageText::Regenerated(Box::new(move || Box::new(PageTextOf::new(decoding()))))
}

fn held_part<'o>(bytes: Vec<u8>, object: &PdfObject, context: &ModuleContext) -> Extracted<'o> {
    if bytes.is_empty()
        || u64::try_from(bytes.len()).unwrap_or(u64::MAX) > context.room_to_produce()
    {
        return Extracted::Nothing;
    }
    let page_text = if object.marks.has(Mark::Contents) {
        PageText::Held(page_text_of(&bytes))
    } else {
        PageText::NotWanted
    };
    Extracted::Part {
        bytes: PartBytes::Produced(bytes),
        page_text,
    }
}

pub fn page_text_bytes(
    page_text: PageText<'_>,
    most_held: u64,
) -> Result<Option<PartBytes<'_>>, InputError> {
    Ok(match page_text {
        PageText::NotWanted => None,
        PageText::Held(bytes) => Some(PartBytes::Produced(bytes)),
        PageText::Regenerated(factory) => {
            let mut text = factory();
            match pull_all(text.as_mut(), most_held)? {
                PulledWhole::Held(bytes) => Some(PartBytes::Produced(bytes)),
                PulledWhole::Measured(length) => Some(PartBytes::Regenerable(Box::new(
                    Regenerated::new(factory, length),
                ))),
            }
        }
    })
}
