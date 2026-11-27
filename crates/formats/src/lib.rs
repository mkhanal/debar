#![forbid(unsafe_code)]

mod context;
mod facts;
mod html;
mod limits;
mod little_endian;
mod mail;
mod module;
mod object;
mod ole2;
mod plain_text;
mod zip;

pub use context::{ContextOfTheObject, ModuleContext, PartOutcome};
pub use facts::{
    DocumentAction, EncryptedContent, Fact, MacroLanguage, ScriptLanguage, Unsupported,
};
pub use limits::{Limit, Room};
pub use mail::{DEEPEST_MIME_NESTING, MAIL_MESSAGES, MailMessages};
pub use module::{
    AfterTheEntry, ContainerEntry, FormatModule, HeaderCheck, ModuleError, ModuleOutput, Part,
    PartBytes, PartRole, PartSource, Stage,
};
pub use object::Object;

pub use html::{HTML_PAGES, HtmlPages, LARGEST_PAGE_NORMALISED, LARGEST_PAGE_WITHOUT_TAGS};
pub use ole2::{OLE2_DOCUMENTS, Ole2Documents};
pub use plain_text::{LARGEST_TEXT_NORMALISED, PLAIN_TEXT, PlainText, SCRIPT_TEXT, ScriptText};
pub use zip::{ZIP_ARCHIVES, ZipArchives};

pub const BUILT_IN_MODULES: &[&dyn FormatModule] = &[
    &ZIP_ARCHIVES,
    &OLE2_DOCUMENTS,
    &HTML_PAGES,
    &MAIL_MESSAGES,
    &PLAIN_TEXT,
    &SCRIPT_TEXT,
];
