use std::fmt;

use debar_image::ObjectKind;
use debar_platform::input::{InputError, ObjectBytes};

use crate::context::ModuleContext;
use crate::facts::Fact;
use crate::object::Object;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage {
    BeforeOwnBytes,
    AfterOwnBytes,
}

pub trait FormatModule: Sync {
    fn kinds(&self) -> &[ObjectKind];

    fn stage(&self) -> Stage;

    fn open<'o>(
        &self,
        object: Object<'o>,
        context: &mut ModuleContext,
    ) -> Result<Box<dyn PartSource<'o> + 'o>, ModuleError>;

    fn header_check(
        &self,
        from: &Object<'_>,
        entries: &mut dyn FnMut(ContainerEntry) -> AfterTheEntry,
    ) -> Result<HeaderCheck, ModuleError> {
        let _ = (from, entries);
        Ok(HeaderCheck::NotNeeded)
    }

    fn refined_kind(
        &self,
        object: &Object<'_>,
        typed_as: ObjectKind,
        entries: &mut dyn FnMut(ContainerEntry) -> AfterTheEntry,
    ) -> Result<Option<ObjectKind>, ModuleError> {
        let _ = (object, typed_as, entries);
        Ok(None)
    }
}

pub trait PartSource<'o> {
    fn next(
        &mut self,
        context: &mut ModuleContext,
    ) -> Result<Option<ModuleOutput<'o>>, ModuleError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AfterTheEntry {
    GoOn,
    Stop,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeaderCheck {
    NotNeeded,
    Holds { length: u64 },
    Fails,
}

pub enum ModuleOutput<'o> {
    Part(Part<'o>),
    Entry(ContainerEntry),
    Fact(Fact),
}

pub struct Part<'o> {
    pub bytes: PartBytes<'o>,
    pub role: PartRole,
}

pub enum PartBytes<'o> {
    Window { offset: u64, length: u64 },
    Produced(Vec<u8>),
    Regenerable(Box<dyn ObjectBytes + 'o>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PartRole {
    Child { kind: Option<ObjectKind> },
    View { matched_as: ObjectKind },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerEntry {
    pub name: Option<Vec<u8>>,
    pub compressed_size: u64,
    pub real_size: u64,
    pub encrypted: bool,
    pub position: u64,
}

#[derive(Debug)]
pub enum ModuleError {
    Input(InputError),
    Damaged { at: u64 },
}

impl fmt::Display for ModuleError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Input(error) => write!(formatter, "{error}"),
            Self::Damaged { at } => write!(formatter, "the object is damaged at {at}"),
        }
    }
}

impl std::error::Error for ModuleError {}

impl From<InputError> for ModuleError {
    fn from(error: InputError) -> Self {
        Self::Input(error)
    }
}
