use std::cell::RefCell;
use std::rc::Rc;

use debar_platform::input::{InputError, ObjectBytes};

use crate::ole2::sectors::{MiniSector, Sector, Sectors, Span};
use crate::ole2::visited::Visited;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamChain {
    pub start: i32,
    pub declared_size: u32,
}

pub struct ChainedStream<'o> {
    sectors: Rc<Sectors<'o>>,
    chain: StreamChain,
    length: u64,
    cursor: RefCell<Cursor>,
}

impl<'o> ChainedStream<'o> {
    pub fn measured(sectors: Rc<Sectors<'o>>, chain: StreamChain) -> Result<Self, InputError> {
        let mut measuring = Cursor::at_the_start(&sectors, chain);
        let mut length = 0u64;
        while let Some(unit) = measuring.next_unit(&sectors)? {
            length = length.saturating_add(unit.taken);
        }
        let cursor = RefCell::new(Cursor::at_the_start(&sectors, chain));
        Ok(Self {
            sectors,
            chain,
            length,
            cursor,
        })
    }
}

impl ObjectBytes for ChainedStream<'_> {
    fn length(&self) -> u64 {
        self.length
    }

    fn read_at(&self, offset: u64, into: &mut [u8]) -> Result<(), InputError> {
        let wanted = into.length();
        let beyond_the_end = InputError::BeyondTheEnd {
            offset,
            wanted,
            length: self.length,
        };
        if offset
            .checked_add(wanted)
            .is_none_or(|end| end > self.length)
        {
            return Err(beyond_the_end);
        }
        let mut cursor = self.cursor.borrow_mut();
        if cursor
            .current_unit
            .is_none_or(|unit| offset < unit.stream_offset)
        {
            *cursor = Cursor::at_the_start(&self.sectors, self.chain);
        }
        let mut filled = 0usize;
        while filled < into.len() {
            let at = offset.saturating_add(u64::try_from(filled).unwrap_or(u64::MAX));
            let unit = match cursor.current_unit {
                Some(unit) if at < unit.stream_offset.saturating_add(unit.taken) => unit,
                _ => match cursor.next_unit(&self.sectors)? {
                    Some(unit) => unit,
                    None => return Err(beyond_the_end),
                },
            };
            if at < unit.stream_offset {
                return Err(beyond_the_end);
            }
            let Some(rest) = into.get_mut(filled..) else {
                break;
            };
            filled = filled.saturating_add(self.copy_from_unit(unit, at, rest)?);
        }
        Ok(())
    }
}

impl ChainedStream<'_> {
    fn copy_from_unit(&self, unit: Unit, at: u64, into: &mut [u8]) -> Result<usize, InputError> {
        let within = at.saturating_sub(unit.stream_offset);
        let available = unit.taken.saturating_sub(within);
        let copied = usize::try_from(available)
            .unwrap_or(usize::MAX)
            .min(into.len());
        let Some(into) = into.get_mut(..copied) else {
            return Ok(0);
        };
        let present = unit.span.present.min(unit.taken);
        let from_the_document = usize::try_from(present.saturating_sub(within))
            .unwrap_or(usize::MAX)
            .min(copied);
        let (stored, zeros) = into.split_at_mut(from_the_document);
        if !stored.is_empty() {
            self.sectors
                .document()
                .read_at(unit.span.offset.saturating_add(within), stored)?;
        }
        zeros.fill(0);
        Ok(copied)
    }
}

#[derive(Debug, Clone, Copy)]
struct Unit {
    span: Span,
    taken: u64,
    stream_offset: u64,
}

struct Cursor {
    in_the_mini_stream: bool,
    current: i32,
    left: u64,
    next_stream_offset: u64,
    visited: Visited,
    current_unit: Option<Unit>,
}

impl Cursor {
    fn at_the_start(sectors: &Sectors<'_>, chain: StreamChain) -> Self {
        Self {
            in_the_mini_stream: chain.declared_size < sectors.geometry().mini_stream_cutoff,
            current: chain.start,
            left: u64::from(chain.declared_size),
            next_stream_offset: 0,
            visited: Visited::new(sectors.geometry().highest_unit_number),
            current_unit: None,
        }
    }

    fn next_unit(&mut self, sectors: &Sectors<'_>) -> Result<Option<Unit>, InputError> {
        if self.current < 0 || self.left == 0 || sectors.is_beyond_the_highest_unit(self.current) {
            return Ok(self.ended());
        }
        if !self.visited.first_visit(self.current) {
            return Ok(self.ended());
        }
        let (span, unit_bytes, next) = if self.in_the_mini_stream {
            let Some(span) = sectors.mini_span(MiniSector(self.current))? else {
                return Ok(self.ended());
            };
            let next = sectors.next_mini_sector(MiniSector(self.current))?.0;
            (span, sectors.geometry().mini_sector_bytes(), next)
        } else {
            let sector_bytes = sectors.geometry().sector_bytes();
            let Some(span) = sectors.span(Sector(self.current), sector_bytes) else {
                return Ok(self.ended());
            };
            let next = sectors.next_sector(Sector(self.current))?.0;
            (span, sector_bytes, next)
        };
        let taken = self.left.min(unit_bytes);
        let unit = Unit {
            span,
            taken,
            stream_offset: self.next_stream_offset,
        };
        self.left = self.left.saturating_sub(taken);
        self.next_stream_offset = self.next_stream_offset.saturating_add(taken);
        self.current = next;
        self.current_unit = Some(unit);
        Ok(Some(unit))
    }

    const fn ended(&mut self) -> Option<Unit> {
        self.current = -1;
        None
    }
}
