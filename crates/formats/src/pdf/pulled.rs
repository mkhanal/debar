use std::cell::RefCell;

use debar_platform::input::{InputError, ObjectBytes};

use crate::object::Object;

const SOURCE_READ_BYTES: u64 = 64 * 1024;
const HISTORY_KEPT_BYTES: u64 = 64 * 1024;

pub trait Pull {
    fn pull(&mut self, into: &mut Vec<u8>) -> Result<bool, InputError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reading {
    First,
    Again,
}

pub struct WindowSource<'o> {
    object: Object<'o>,
    at: u64,
    end: u64,
    reading: Reading,
}

impl<'o> WindowSource<'o> {
    pub fn new(object: Object<'o>, offset: u64, length: u64, reading: Reading) -> Self {
        Self {
            object,
            at: offset,
            end: offset.saturating_add(length),
            reading,
        }
    }
}

impl Pull for WindowSource<'_> {
    fn pull(&mut self, into: &mut Vec<u8>) -> Result<bool, InputError> {
        let wanted = self.end.saturating_sub(self.at).min(SOURCE_READ_BYTES);
        if wanted == 0 {
            return Ok(false);
        }
        let held = into.len();
        into.resize(held.saturating_add(usize::try_from(wanted).unwrap_or(0)), 0);
        let fresh = into.get_mut(held..).unwrap_or_default();
        match self.reading {
            Reading::First => self.object.read_at(self.at, fresh)?,
            Reading::Again => self.object.read_again_at(self.at, fresh)?,
        }
        self.at = self.at.saturating_add(wanted);
        Ok(true)
    }
}

pub fn pull_all(source: &mut dyn Pull, most_held: u64) -> Result<PulledWhole, InputError> {
    let mut held = Some(Vec::new());
    let mut length = 0u64;
    let mut fresh = Vec::new();
    while source.pull(&mut fresh)? {
        length = length.saturating_add(u64::try_from(fresh.len()).unwrap_or(u64::MAX));
        if let Some(bytes) = &mut held {
            if length > most_held {
                held = None;
            } else {
                bytes.append(&mut fresh);
            }
        }
        fresh.clear();
    }
    Ok(match held {
        Some(bytes) => PulledWhole::Held(bytes),
        None => PulledWhole::Measured(length),
    })
}

pub enum PulledWhole {
    Held(Vec<u8>),
    Measured(u64),
}

pub type PullFactory<'o> = Box<dyn Fn() -> Box<dyn Pull + 'o> + 'o>;

pub struct Regenerated<'o> {
    factory: PullFactory<'o>,
    length: u64,
    reading: RefCell<Window<'o>>,
}

struct Window<'o> {
    source: Box<dyn Pull + 'o>,
    start: u64,
    bytes: Vec<u8>,
    finished: bool,
}

impl<'o> Regenerated<'o> {
    pub fn new(factory: PullFactory<'o>, length: u64) -> Self {
        let reading = RefCell::new(Window::from_the_start(&factory));
        Self {
            factory,
            length,
            reading,
        }
    }
}

impl<'o> Window<'o> {
    fn from_the_start(factory: &PullFactory<'o>) -> Self {
        Self {
            source: factory(),
            start: 0,
            bytes: Vec::new(),
            finished: false,
        }
    }

    fn end(&self) -> u64 {
        self.start
            .saturating_add(u64::try_from(self.bytes.len()).unwrap_or(u64::MAX))
    }

    fn forget_before(&mut self, offset: u64) {
        let keep_from = offset.saturating_sub(HISTORY_KEPT_BYTES);
        if keep_from <= self.start {
            return;
        }
        let dropped = usize::try_from(keep_from.saturating_sub(self.start))
            .unwrap_or(usize::MAX)
            .min(self.bytes.len());
        self.bytes.drain(..dropped);
        self.start = self
            .start
            .saturating_add(u64::try_from(dropped).unwrap_or(u64::MAX));
    }

    fn reach(&mut self, end: u64) -> Result<(), InputError> {
        while self.end() < end && !self.finished {
            if !self.source.pull(&mut self.bytes)? {
                self.finished = true;
            }
        }
        Ok(())
    }
}

impl ObjectBytes for Regenerated<'_> {
    fn length(&self) -> u64 {
        self.length
    }

    fn read_at(&self, offset: u64, into: &mut [u8]) -> Result<(), InputError> {
        let wanted = u64::try_from(into.len()).unwrap_or(u64::MAX);
        let beyond = InputError::BeyondTheEnd {
            offset,
            wanted,
            length: self.length,
        };
        let end = offset.checked_add(wanted).filter(|end| *end <= self.length);
        let Some(end) = end else {
            return Err(beyond);
        };
        let mut window = self.reading.borrow_mut();
        if offset < window.start {
            *window = Window::from_the_start(&self.factory);
        }
        window.forget_before(offset);
        window.reach(end)?;
        let from = usize::try_from(offset.saturating_sub(window.start)).unwrap_or(usize::MAX);
        let to = from.saturating_add(into.len());
        let Some(held) = window.bytes.get(from..to) else {
            return Err(beyond);
        };
        into.copy_from_slice(held);
        Ok(())
    }
}
