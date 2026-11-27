#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fact {
    Macros(MacroLanguage),
    Script(ScriptLanguage),
    ExecutableContent,
    Encrypted {
        content: EncryptedContent,
        decryptable: bool,
    },
    DocumentAction(DocumentAction),
    ExternalLink,
    KindDisagreesWithName,
    Expansion {
        consumed: u64,
        produced: u64,
    },
    OverlappingParts,
    ObfuscatedNames,
    BrokenStructure {
        at: u64,
    },
    Unsupported(Unsupported),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MacroLanguage {
    VisualBasic,
    SpreadsheetFormulas,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScriptLanguage {
    JavaScript,
    VisualBasic,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncryptedContent {
    Archive,
    Document,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DocumentAction {
    RunsScript,
    LaunchesProgram,
    ActsOnOpening,
    AttachesFile,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unsupported {
    Variant,
    Compression,
}
