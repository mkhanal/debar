use std::cell::{Cell, RefCell};
use std::rc::Rc;

use debar_platform::input::{InputError, ObjectBytes};
use memchr::{memchr, memmem};

use crate::object::Object;
use crate::pdf::searchable::Searchable;

const PAGE_BYTES: u64 = 16 * 1024;
const PAGES_KEPT: usize = 16;

pub struct DocumentBytes<'o> {
    document: Object<'o>,
    pages: RefCell<Vec<Page>>,
    first_unread_page: Cell<u64>,
    failure: RefCell<Option<InputError>>,
}

struct Page {
    number: u64,
    bytes: Rc<[u8]>,
}

impl<'o> DocumentBytes<'o> {
    pub fn new(document: Object<'o>) -> Self {
        Self {
            document,
            pages: RefCell::new(Vec::with_capacity(PAGES_KEPT)),
            first_unread_page: Cell::new(0),
            failure: RefCell::new(None),
        }
    }

    pub fn object(&self) -> &Object<'o> {
        &self.document
    }

    pub fn take_failure(&self) -> Result<(), InputError> {
        match self.failure.borrow_mut().take() {
            Some(failure) => Err(failure),
            None => Ok(()),
        }
    }

    fn page(&self, number: u64) -> Option<Rc<[u8]>> {
        if self.failure.borrow().is_some() {
            return None;
        }
        let mut pages = self.pages.borrow_mut();
        if let Some(index) = pages.iter().position(|page| page.number == number) {
            let page = pages.remove(index);
            let bytes = Rc::clone(&page.bytes);
            pages.push(page);
            return Some(bytes);
        }
        let start = number.checked_mul(PAGE_BYTES)?;
        let length = self.document.length().checked_sub(start)?.min(PAGE_BYTES);
        if length == 0 {
            return None;
        }
        let mut bytes = vec![0u8; usize::try_from(length).ok()?];
        let read = if number >= self.first_unread_page.get() {
            self.first_unread_page.set(number.saturating_add(1));
            self.document.read_at(start, &mut bytes)
        } else {
            self.document.read_again_at(start, &mut bytes)
        };
        if let Err(failure) = read {
            *self.failure.borrow_mut() = Some(failure);
            return None;
        }
        if pages.len() >= PAGES_KEPT {
            pages.remove(0);
        }
        let bytes: Rc<[u8]> = Rc::from(bytes);
        pages.push(Page {
            number,
            bytes: Rc::clone(&bytes),
        });
        Some(bytes)
    }

    fn page_of(at: u64) -> (u64, usize) {
        let number = at.checked_div(PAGE_BYTES).unwrap_or(0);
        let within = at.checked_rem(PAGE_BYTES).unwrap_or(0);
        (number, usize::try_from(within).unwrap_or(0))
    }
}

impl Searchable for DocumentBytes<'_> {
    fn length(&self) -> u64 {
        self.document.length()
    }

    fn byte(&self, at: u64) -> Option<u8> {
        let (number, within) = Self::page_of(at);
        if let Some(latest) = self.pages.borrow().last()
            && latest.number == number
        {
            return latest.bytes.get(within).copied();
        }
        self.page(number)?.get(within).copied()
    }

    fn find(&self, needle: &[u8], from: u64, end: u64) -> Option<u64> {
        let needle_length = Searchable::length(needle);
        let end = end.min(self.document.length());
        let mut at = from;
        let finder = memmem::Finder::new(needle);
        while at.checked_add(needle_length)? <= end {
            let (number, within) = Self::page_of(at);
            let page = self.page(number)?;
            let page_start = number.checked_mul(PAGE_BYTES)?;
            let page_end = page_start.checked_add(Searchable::length(page.as_ref()))?;
            let stop = usize::try_from(end.min(page_end).checked_sub(page_start)?).ok()?;
            if let Some(found) = page.get(within..stop).and_then(|bytes| finder.find(bytes)) {
                return at.checked_add(u64::try_from(found).ok()?);
            }
            let first_spanning = page_end
                .saturating_sub(needle_length.saturating_sub(1))
                .max(at);
            let mut candidate = first_spanning;
            while candidate < page_end && candidate.checked_add(needle_length)? <= end {
                if self.matches_at(needle, candidate) {
                    return Some(candidate);
                }
                candidate = candidate.checked_add(1)?;
            }
            at = page_end;
        }
        None
    }

    fn find_byte(&self, byte: u8, from: u64, end: u64) -> Option<u64> {
        let end = end.min(self.document.length());
        let mut at = from;
        while at < end {
            let (number, within) = Self::page_of(at);
            let page = self.page(number)?;
            let page_start = number.checked_mul(PAGE_BYTES)?;
            let page_end = page_start.checked_add(Searchable::length(page.as_ref()))?;
            let stop = usize::try_from(end.min(page_end).checked_sub(page_start)?).ok()?;
            if let Some(found) = page.get(within..stop).and_then(|bytes| memchr(byte, bytes)) {
                return at.checked_add(u64::try_from(found).ok()?);
            }
            at = page_end;
        }
        None
    }

    fn copy(&self, from: u64, length: u64, into: &mut Vec<u8>) {
        let end = from.saturating_add(length).min(self.document.length());
        let mut at = from;
        while at < end {
            let (number, within) = Self::page_of(at);
            let Some(page) = self.page(number) else {
                return;
            };
            let page_start = number.saturating_mul(PAGE_BYTES);
            let page_end = page_start.saturating_add(Searchable::length(page.as_ref()));
            let stop = usize::try_from(end.min(page_end).saturating_sub(page_start)).unwrap_or(0);
            if let Some(bytes) = page.get(within..stop) {
                into.extend_from_slice(bytes);
            }
            at = page_end;
        }
    }
}

impl DocumentBytes<'_> {
    fn matches_at(&self, needle: &[u8], at: u64) -> bool {
        needle.iter().zip(0u64..).all(|(wanted, offset)| {
            at.checked_add(offset)
                .and_then(|position| self.byte(position))
                == Some(*wanted)
        })
    }
}
