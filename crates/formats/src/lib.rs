#![forbid(unsafe_code)]

mod context;
mod facts;
mod limits;
mod module;
mod object;
mod zip;

pub use context::{ContextOfTheObject, ModuleContext, PartOutcome};
pub use facts::{
    DocumentAction, EncryptedContent, Fact, MacroLanguage, ScriptLanguage, Unsupported,
};
pub use limits::{Limit, Room};
pub use module::{
    AfterTheEntry, ContainerEntry, FormatModule, HeaderCheck, ModuleError, ModuleOutput, Part,
    PartBytes, PartRole, PartSource, Stage,
};
pub use object::Object;

pub use zip::{ZIP_ARCHIVES, ZipArchives};

pub const BUILT_IN_MODULES: &[&dyn FormatModule] = &[&ZIP_ARCHIVES];
