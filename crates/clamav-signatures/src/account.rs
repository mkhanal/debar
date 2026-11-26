#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum LineOutcome {
    Compiled,
    OutsideFunctionalityLevel,
    Ignored,
    Comment,
    NotASignature,
    TargetNotLoaded,
    NeverReports,
    NeedsExecutableFacts,
    NotYetCompiled,
}

impl LineOutcome {
    pub const ALL: [Self; 9] = [
        Self::Compiled,
        Self::OutsideFunctionalityLevel,
        Self::Ignored,
        Self::Comment,
        Self::NotASignature,
        Self::TargetNotLoaded,
        Self::NeverReports,
        Self::NeedsExecutableFacts,
        Self::NotYetCompiled,
    ];
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileAccount {
    pub file: String,
    pub member: Option<String>,
    pub kind: &'static str,
    pub lines: Vec<LineOutcome>,
}

impl FileAccount {
    #[must_use]
    pub fn count(&self, outcome: LineOutcome) -> usize {
        self.lines.iter().filter(|line| **line == outcome).count()
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Account {
    pub files: Vec<FileAccount>,
    pub not_databases: Vec<String>,
}
