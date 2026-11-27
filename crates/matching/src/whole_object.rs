use std::borrow::Cow;
use std::ops::ControlFlow;

use debar_platform::input::{InputError, ObjectBytes};

use crate::backtracking_search::SubjectBytes;

const PAGE_LENGTH: usize = 128 * 1024;
const PAGES_HELD: usize = 32;
pub const LARGEST_OBJECT_HELD_WHOLE: u64 = 4 * 1024 * 1024;

pub(crate) enum WholeObject<'o> {
    Held(Vec<u8>),
    Paged(ObjectPages<'o>),
}

impl<'o> WholeObject<'o> {
    pub(crate) fn of(object: &'o dyn ObjectBytes) -> Result<Self, InputError> {
        let length = object.length();
        if length <= LARGEST_OBJECT_HELD_WHOLE
            && let Ok(held_length) = usize::try_from(length)
        {
            let mut held = vec![0u8; held_length];
            object.read_at(0, &mut held)?;
            return Ok(Self::Held(held));
        }
        Ok(Self::Paged(ObjectPages::new(
            object,
            PAGE_LENGTH,
            PAGES_HELD,
        )))
    }

    pub(crate) fn length(&self) -> u64 {
        match self {
            Self::Held(held) => u64::try_from(held.len()).unwrap_or(u64::MAX),
            Self::Paged(pages) => pages.length,
        }
    }

    pub(crate) fn bytes_at(
        &mut self,
        offset: usize,
        length: usize,
    ) -> Result<Option<Cow<'_, [u8]>>, InputError> {
        match self {
            Self::Held(held) => Ok(held
                .get(offset..offset.saturating_add(length))
                .map(Cow::Borrowed)),
            Self::Paged(pages) => {
                let start = u64::try_from(offset).unwrap_or(u64::MAX);
                let wanted = u64::try_from(length).unwrap_or(u64::MAX);
                if start
                    .checked_add(wanted)
                    .is_none_or(|end| end > pages.length)
                {
                    return Ok(None);
                }
                let mut read = vec![0u8; length];
                pages.object.read_at(start, &mut read)?;
                Ok(Some(Cow::Owned(read)))
            }
        }
    }
}

pub(crate) struct ObjectPages<'o> {
    object: &'o dyn ObjectBytes,
    length: u64,
    page_length: usize,
    most_pages: usize,
    pages: Vec<HeldPage>,
    failure: Option<InputError>,
}

struct HeldPage {
    index: u64,
    bytes: Vec<u8>,
}

impl<'o> ObjectPages<'o> {
    pub(crate) fn new(object: &'o dyn ObjectBytes, page_length: usize, most_pages: usize) -> Self {
        Self {
            object,
            length: object.length(),
            page_length: page_length.max(1),
            most_pages: most_pages.max(1),
            pages: Vec::new(),
            failure: None,
        }
    }

    pub(crate) fn subject(&mut self, start: u64, end: u64) -> PagedSubject<'_, 'o> {
        let end = end.min(self.length);
        PagedSubject {
            pages: self,
            start,
            length: usize::try_from(end.saturating_sub(start)).unwrap_or(usize::MAX),
        }
    }

    pub(crate) fn take_failure(&mut self) -> Result<(), InputError> {
        self.failure.take().map_or(Ok(()), Err)
    }

    fn page_length_u64(&self) -> u64 {
        u64::try_from(self.page_length).unwrap_or(u64::MAX)
    }

    fn byte(&mut self, at: u64) -> Option<u8> {
        let page_length = self.page_length_u64();
        let index = at.checked_div(page_length)?;
        let within = usize::try_from(at.checked_rem(page_length)?).ok()?;
        self.page(index)?.get(within).copied()
    }

    fn page(&mut self, index: u64) -> Option<&[u8]> {
        if self.failure.is_some() {
            return None;
        }
        match self.held_or_read(index) {
            Ok(()) => self.pages.first().map(|page| page.bytes.as_slice()),
            Err(failure) => {
                self.failure = Some(failure);
                None
            }
        }
    }

    fn held_or_read(&mut self, index: u64) -> Result<(), InputError> {
        if self.pages.first().is_some_and(|page| page.index == index) {
            return Ok(());
        }
        if let Some(found) = self.pages.iter().position(|page| page.index == index) {
            if let Some(most_recent_first) = self.pages.get_mut(..=found) {
                most_recent_first.rotate_right(1);
            }
            return Ok(());
        }
        let start = index.saturating_mul(self.page_length_u64());
        let end = start
            .saturating_add(self.page_length_u64())
            .min(self.length);
        let length = usize::try_from(end.saturating_sub(start)).unwrap_or(0);
        let mut reused = if self.pages.len() >= self.most_pages {
            self.pages.pop()
        } else {
            None
        }
        .map_or_else(Vec::new, |page| page.bytes);
        reused.resize(length, 0);
        self.object.read_at(start, &mut reused)?;
        self.pages.insert(
            0,
            HeldPage {
                index,
                bytes: reused,
            },
        );
        Ok(())
    }

    fn visit_forward(
        &mut self,
        from: u64,
        to: u64,
        mut visit: impl FnMut(&[u8]) -> ControlFlow<()>,
    ) -> Result<(), InputError> {
        let page_length = self.page_length_u64();
        let mut at = from;
        while at < to {
            let Some(index) = at.checked_div(page_length) else {
                return Ok(());
            };
            let page_start = index.saturating_mul(page_length);
            let within = usize::try_from(at.saturating_sub(page_start)).unwrap_or(usize::MAX);
            let until = usize::try_from(to.saturating_sub(page_start)).unwrap_or(usize::MAX);
            let Some(page) = self.page(index) else {
                return self.take_failure();
            };
            let visited = page.get(within..until.min(page.len())).unwrap_or_default();
            if visited.is_empty() {
                return Ok(());
            }
            at = at.saturating_add(u64::try_from(visited.len()).unwrap_or(u64::MAX));
            if visit(visited).is_break() {
                return Ok(());
            }
        }
        Ok(())
    }

    fn visit_backward(
        &mut self,
        from: u64,
        to: u64,
        mut visit: impl FnMut(&[u8]) -> ControlFlow<()>,
    ) -> Result<(), InputError> {
        let page_length = self.page_length_u64();
        let mut at = to;
        while at > from {
            let last = at.saturating_sub(1);
            let Some(index) = last.checked_div(page_length) else {
                return Ok(());
            };
            let page_start = index.saturating_mul(page_length);
            let within = usize::try_from(from.max(page_start).saturating_sub(page_start))
                .unwrap_or(usize::MAX);
            let until = usize::try_from(at.saturating_sub(page_start)).unwrap_or(usize::MAX);
            let Some(page) = self.page(index) else {
                return self.take_failure();
            };
            let visited = page.get(within..until).unwrap_or_default();
            if visited.is_empty() {
                return Ok(());
            }
            at = at.saturating_sub(u64::try_from(visited.len()).unwrap_or(u64::MAX));
            if visit(visited).is_break() {
                return Ok(());
            }
        }
        Ok(())
    }
}

pub(crate) struct PagedSubject<'p, 'o> {
    pages: &'p mut ObjectPages<'o>,
    start: u64,
    length: usize,
}

impl PagedSubject<'_, '_> {
    fn absolute(&self, at: usize) -> u64 {
        self.start
            .saturating_add(u64::try_from(at).unwrap_or(u64::MAX))
    }

    pub(crate) fn take_failure(&mut self) -> Result<(), InputError> {
        self.pages.take_failure()
    }

    pub(crate) fn visit_forward(
        &mut self,
        from: usize,
        visit: impl FnMut(&[u8]) -> ControlFlow<()>,
    ) -> Result<(), InputError> {
        let (from, to) = (self.absolute(from), self.absolute(self.length));
        self.pages.visit_forward(from, to, visit)
    }

    pub(crate) fn visit_backward(
        &mut self,
        from: usize,
        to: usize,
        visit: impl FnMut(&[u8]) -> ControlFlow<()>,
    ) -> Result<(), InputError> {
        let (from, to) = (self.absolute(from), self.absolute(to.min(self.length)));
        self.pages.visit_backward(from, to, visit)
    }
}

impl SubjectBytes for PagedSubject<'_, '_> {
    fn length(&self) -> usize {
        self.length
    }

    fn byte(&mut self, at: usize) -> Option<u8> {
        if at >= self.length {
            return None;
        }
        let absolute = self.absolute(at);
        self.pages.byte(absolute)
    }

    fn first_from(&mut self, from: usize, wanted: impl Fn(u8) -> bool) -> Option<usize> {
        let mut found = None;
        let mut at = from;
        let visited = self.visit_forward(from, |bytes| {
            if let Some(position) = bytes.iter().position(|byte| wanted(*byte)) {
                found = Some(at.saturating_add(position));
                return ControlFlow::Break(());
            }
            at = at.saturating_add(bytes.len());
            ControlFlow::Continue(())
        });
        if let Err(failure) = visited {
            self.pages.failure = Some(failure);
            return None;
        }
        found
    }
}
