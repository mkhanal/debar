mod entities;
mod output;
mod page_chunks;
mod page_normaliser;

use std::cell::RefCell;

use debar_image::ObjectKind;
use debar_platform::input::{InputError, ObjectBytes};

use crate::context::{ModuleContext, PartOutcome};
use crate::html::output::Output;
use crate::html::page_chunks::{PageInChunks, Reread};
use crate::html::page_normaliser::View;
use crate::module::{
    FormatModule, ModuleError, ModuleOutput, Part, PartBytes, PartRole, PartSource, Stage,
};
use crate::object::Object;

pub const LARGEST_PAGE_NORMALISED: u64 = 40 * 1024 * 1024;
pub const LARGEST_PAGE_WITHOUT_TAGS: u64 = 8 * 1024 * 1024;

pub struct HtmlPages;

pub static HTML_PAGES: HtmlPages = HtmlPages;

const PAGE_KINDS: [ObjectKind; 1] = [ObjectKind::Html];

impl FormatModule for HtmlPages {
    fn kinds(&self) -> &[ObjectKind] {
        &PAGE_KINDS
    }

    fn stage(&self) -> Stage {
        Stage::BeforeOwnBytes
    }

    fn open<'o>(
        &self,
        object: Object<'o>,
        _context: &mut ModuleContext,
    ) -> Result<Box<dyn PartSource<'o> + 'o>, ModuleError> {
        if object.length() > LARGEST_PAGE_NORMALISED {
            return Ok(Box::new(PageViews::Finished));
        }
        Ok(Box::new(PageViews::Pending(object)))
    }
}

enum PageViews<'o> {
    Pending(Object<'o>),
    WithoutTagsNext(Object<'o>, NormalisedView),
    Finished,
}

enum NormalisedView {
    Held(Vec<u8>),
    Measured(u64),
}

impl<'o> PartSource<'o> for PageViews<'o> {
    fn next(
        &mut self,
        context: &mut ModuleContext,
    ) -> Result<Option<ModuleOutput<'o>>, ModuleError> {
        match std::mem::replace(self, PageViews::Finished) {
            PageViews::Pending(page) => {
                let (without_comments, without_tags) = normalise(&page, context.room_to_produce())?;
                let part = view_part(&page, View::WithoutComments, without_comments);
                *self = PageViews::WithoutTagsNext(page, without_tags);
                Ok(Some(part))
            }
            PageViews::WithoutTagsNext(page, without_tags) => {
                if context.last_part() != Some(PartOutcome::Scanned)
                    || page.length() > LARGEST_PAGE_WITHOUT_TAGS
                {
                    return Ok(None);
                }
                Ok(Some(view_part(&page, View::WithoutTags, without_tags)))
            }
            PageViews::Finished => Ok(None),
        }
    }
}

fn view_part<'o>(page: &Object<'o>, view: View, normalised: NormalisedView) -> ModuleOutput<'o> {
    let bytes = match normalised {
        NormalisedView::Held(bytes) => PartBytes::Produced(bytes),
        NormalisedView::Measured(length) => {
            PartBytes::Regenerable(Box::new(Regenerated::new(page.clone(), view, length)))
        }
    };
    ModuleOutput::Part(Part {
        bytes,
        role: PartRole::View {
            matched_as: ObjectKind::Html,
        },
    })
}

fn normalise(
    page: &Object<'_>,
    most_held: u64,
) -> Result<(NormalisedView, NormalisedView), InputError> {
    let mut chunks = PageInChunks::new(page.clone(), Output::kept(), Output::kept());
    let most_held = usize::try_from(most_held).unwrap_or(usize::MAX);
    while chunks.normalise_a_chunk(Reread::No)? {
        let held_without_comments = chunks.output(View::WithoutComments).held_length();
        let held_without_tags = chunks.output(View::WithoutTags).held_length();
        if held_without_comments.saturating_add(held_without_tags) > most_held {
            chunks.output(View::WithoutTags).stop_keeping();
        }
        if held_without_comments > most_held {
            chunks.output(View::WithoutComments).stop_keeping();
        }
        chunks
            .output(View::WithoutComments)
            .let_go_of_settled_bytes();
        chunks.output(View::WithoutTags).let_go_of_settled_bytes();
    }
    Ok((
        finished_view(chunks.output(View::WithoutComments)),
        finished_view(chunks.output(View::WithoutTags)),
    ))
}

fn finished_view(output: &mut Output) -> NormalisedView {
    if output.is_kept() {
        NormalisedView::Held(output.take_all())
    } else {
        NormalisedView::Measured(output.length())
    }
}

struct Regenerated<'o> {
    page: Object<'o>,
    view: View,
    length: u64,
    reading: RefCell<Reading<'o>>,
}

impl<'o> Regenerated<'o> {
    fn new(page: Object<'o>, view: View, length: u64) -> Self {
        let reading = RefCell::new(Reading::from_the_start(&page));
        Self {
            page,
            view,
            length,
            reading,
        }
    }
}

impl ObjectBytes for Regenerated<'_> {
    fn length(&self) -> u64 {
        self.length
    }

    fn read_at(&self, offset: u64, into: &mut [u8]) -> Result<(), InputError> {
        let wanted = into.length();
        let beyond_the_end = |at: u64, wanted: u64| InputError::BeyondTheEnd {
            offset: at,
            wanted,
            length: self.length,
        };
        if offset
            .checked_add(wanted)
            .is_none_or(|end| end > self.length)
        {
            return Err(beyond_the_end(offset, wanted));
        }
        let mut reading = self.reading.borrow_mut();
        if offset < reading.window_start {
            *reading = Reading::from_the_start(&self.page);
        }
        let mut filled = 0usize;
        while let Some(rest) = into.get_mut(filled..).filter(|rest| !rest.is_empty()) {
            let at = offset.saturating_add(rest_offset(filled));
            let copied = reading.copy_from(self.view, at, rest)?;
            if copied == 0 {
                return Err(beyond_the_end(at, rest.length()));
            }
            filled = filled.saturating_add(copied);
        }
        Ok(())
    }
}

fn rest_offset(filled: usize) -> u64 {
    u64::try_from(filled).unwrap_or(u64::MAX)
}

struct Reading<'o> {
    chunks: PageInChunks<'o>,
    window: Vec<u8>,
    window_start: u64,
}

impl<'o> Reading<'o> {
    fn from_the_start(page: &Object<'o>) -> Self {
        Self {
            chunks: PageInChunks::new(page.clone(), Output::kept(), Output::kept()),
            window: Vec::new(),
            window_start: 0,
        }
    }

    fn copy_from(&mut self, view: View, at: u64, into: &mut [u8]) -> Result<usize, InputError> {
        loop {
            let window_end = self
                .window_start
                .saturating_add(rest_offset(self.window.len()));
            if at < window_end {
                let skip = usize::try_from(at.saturating_sub(self.window_start)).unwrap_or(0);
                let available = self.window.get(skip..).unwrap_or_default();
                let copied = available.len().min(into.len());
                if let (Some(to), Some(from)) = (into.get_mut(..copied), available.get(..copied)) {
                    to.copy_from_slice(from);
                }
                return Ok(copied);
            }
            self.window_start = window_end;
            self.window.clear();
            loop {
                let more = self.chunks.normalise_a_chunk(Reread::Yes)?;
                let other = match view {
                    View::WithoutComments => View::WithoutTags,
                    View::WithoutTags => View::WithoutComments,
                };
                self.chunks.output(other).take_all();
                self.window = if self.chunks.is_finished() {
                    self.chunks.output(view).take_all()
                } else {
                    self.chunks.output(view).take_settled()
                };
                if !self.window.is_empty() {
                    break;
                }
                if !more {
                    return Ok(0);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    fn page() -> Vec<u8> {
        let mut page = b"<html>".to_vec();
        for index in 0..20_000u32 {
            page.extend_from_slice(
                format!("<P class='C{index}'>Word {index} &amp; caf\u{e9} <!-- x --> </p>\n")
                    .as_bytes(),
            );
        }
        page
    }

    fn read_whole(view: &dyn ObjectBytes) -> Vec<u8> {
        let mut bytes = vec![0u8; usize::try_from(view.length()).unwrap()];
        view.read_at(0, &mut bytes).unwrap();
        bytes
    }

    fn held(normalised: NormalisedView) -> Vec<u8> {
        match normalised {
            NormalisedView::Held(bytes) => bytes,
            NormalisedView::Measured(_) => Vec::new(),
        }
    }

    #[test]
    fn regenerated_views_read_as_the_held_views_do() {
        let page = Object::held(page());
        let (without_comments, without_tags) = normalise(&page, u64::MAX).unwrap();
        let (measured_without_comments, measured_without_tags) = normalise(&page, 10).unwrap();
        for (view, held_view, measured) in [
            (
                View::WithoutComments,
                held(without_comments),
                measured_without_comments,
            ),
            (View::WithoutTags, held(without_tags), measured_without_tags),
        ] {
            let NormalisedView::Measured(length) = measured else {
                panic!("a view beyond the room is measured");
            };
            let regenerated = Regenerated::new(page.clone(), view, length);
            assert_eq!(read_whole(&regenerated), held_view);
            let mut early = [0u8; 16];
            regenerated.read_at(5, &mut early).unwrap();
            assert_eq!(Some(early.as_slice()), held_view.get(5..21));
        }
    }

    #[test]
    fn the_page_without_tags_is_held_only_when_both_views_fit_the_room() {
        let page = Object::held(b"<html><b>some words</b> and more words".to_vec());
        let (without_comments, without_tags) = normalise(&page, 40).unwrap();
        assert!(matches!(without_comments, NormalisedView::Held(_)));
        assert!(matches!(without_tags, NormalisedView::Measured(_)));
    }
}
