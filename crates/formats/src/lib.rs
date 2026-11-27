#![forbid(unsafe_code)]

mod context;
mod facts;
mod limits;
mod module;
mod object;

pub use context::{ModuleContext, PartOutcome};
pub use facts::{
    DocumentAction, EncryptedContent, Fact, MacroLanguage, ScriptLanguage, Unsupported,
};
pub use limits::{Limit, Room};
pub use module::{
    ContainerEntry, FormatModule, HeaderCheck, ModuleError, ModuleOutput, Part, PartBytes,
    PartRole, PartSource, Stage,
};
pub use object::Object;

pub const BUILT_IN_MODULES: &[&dyn FormatModule] = &[];
