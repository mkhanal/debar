use std::rc::Rc;

use debar_platform::input::{InputError, ObjectBytes};

#[derive(Clone)]
pub struct Object<'o> {
    whole: Rc<dyn ObjectBytes + 'o>,
    start: u64,
    length: u64,
}

impl<'o> Object<'o> {
    pub fn borrowed(bytes: &'o dyn ObjectBytes) -> Self {
        Self::whole(Rc::new(bytes))
    }

    #[must_use]
    pub fn held(bytes: Vec<u8>) -> Self {
        Self::whole(Rc::new(Held(bytes)))
    }

    #[must_use]
    pub fn regenerable(producer: Box<dyn ObjectBytes + 'o>) -> Self {
        Self::whole(Rc::from(producer))
    }

    fn whole(whole: Rc<dyn ObjectBytes + 'o>) -> Self {
        let length = whole.length();
        Self {
            whole,
            start: 0,
            length,
        }
    }

    #[must_use]
    pub fn window(&self, offset: u64, length: u64) -> Option<Self> {
        if offset.checked_add(length)? > self.length {
            return None;
        }
        Some(Self {
            whole: Rc::clone(&self.whole),
            start: self.start.checked_add(offset)?,
            length,
        })
    }

    #[must_use]
    pub fn onward_from(&self, offset: u64) -> Option<Self> {
        self.window(offset, self.length.checked_sub(offset)?)
    }
}

impl ObjectBytes for Object<'_> {
    fn length(&self) -> u64 {
        self.length
    }

    fn read_at(&self, offset: u64, into: &mut [u8]) -> Result<(), InputError> {
        let at = self.within_the_whole(offset, into.len())?;
        self.whole.read_at(at, into)
    }

    fn read_again_at(&self, offset: u64, into: &mut [u8]) -> Result<(), InputError> {
        let at = self.within_the_whole(offset, into.len())?;
        self.whole.read_again_at(at, into)
    }
}

impl Object<'_> {
    fn within_the_whole(&self, offset: u64, wanted: usize) -> Result<u64, InputError> {
        let wanted = u64::try_from(wanted).unwrap_or(u64::MAX);
        let beyond_the_end = || InputError::BeyondTheEnd {
            offset,
            wanted,
            length: self.length,
        };
        if offset
            .checked_add(wanted)
            .is_none_or(|end| end > self.length)
        {
            return Err(beyond_the_end());
        }
        self.start.checked_add(offset).ok_or_else(beyond_the_end)
    }
}

struct Held(Vec<u8>);

impl ObjectBytes for Held {
    fn length(&self) -> u64 {
        self.0.as_slice().length()
    }

    fn read_at(&self, offset: u64, into: &mut [u8]) -> Result<(), InputError> {
        self.0.as_slice().read_at(offset, into)
    }
}
