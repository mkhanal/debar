use std::fmt;

use debar_image::{
    BuildError, Category, DatabaseRecord, HashPurpose, HashSignature, ImageBuilder,
    PatternSignature, Provenance, ReportWindows,
};

use crate::account::{Account, FileAccount, LineOutcome};
use crate::container::{self, ContainerError, Member};
use crate::extended_lines::{self, MalformedExtendedLine, ReadExtendedLine};
use crate::hash_lines::{FieldOrder, HashFile, MalformedLine, ReadLine, read_line};
use crate::ignore_list::IgnoreList;
use crate::line_text::{lines, without_line_ending};

const UNOFFICIAL_SUFFIX: &str = ".UNOFFICIAL";
const LICENCE_MEMBER: &str = "COPYING";
const SCAN_WINDOW_LENGTH: u32 = 131_072;
const RANK_OF_PLAIN_BYTES: u8 = 0;
const RANK_OF_OTHER_BODIES: u8 = 1;

pub struct DatabaseFile<'a> {
    pub name: &'a str,
    pub contents: &'a [u8],
}

#[derive(Debug)]
pub enum DatabaseError {
    Container {
        file: String,
        reason: ContainerError,
    },
    MalformedLine {
        file: String,
        member: Option<String>,
        line: usize,
        reason: MalformedLine,
    },
    MalformedExtendedLine {
        file: String,
        member: Option<String>,
        line: usize,
        reason: MalformedExtendedLine,
    },
    EmptyHashFile {
        file: String,
        member: Option<String>,
    },
    EmptyDatabaseFile {
        file: String,
        member: Option<String>,
    },
    Image(BuildError),
}

impl fmt::Display for DatabaseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let place = |file: &str, member: &Option<String>| match member {
            Some(member) => format!("{file}, member {member}"),
            None => file.to_owned(),
        };
        match self {
            Self::Container { file, reason } => write!(formatter, "{file}: {reason}"),
            Self::MalformedLine {
                file,
                member,
                line,
                reason,
            } => write!(formatter, "{} line {line}: {reason}", place(file, member)),
            Self::MalformedExtendedLine {
                file,
                member,
                line,
                reason,
            } => write!(formatter, "{} line {line}: {reason}", place(file, member)),
            Self::EmptyHashFile { file, member } | Self::EmptyDatabaseFile { file, member } => {
                write!(formatter, "{} is empty", place(file, member))
            }
            Self::Image(reason) => write!(formatter, "{reason}"),
        }
    }
}

impl std::error::Error for DatabaseError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FileKind {
    Container,
    IgnoreList,
    Hashes(HashFile),
    Extended(Category),
    NotYetCompiled,
}

const fn hashes(purpose: HashPurpose, category: Category, field_order: FieldOrder) -> FileKind {
    FileKind::Hashes(HashFile {
        purpose,
        category,
        field_order,
    })
}

const WHOLE_OBJECT: FileKind = hashes(
    HashPurpose::WholeObjectDetection,
    Category::Malware,
    FieldOrder::HashSizeName,
);
const WHOLE_OBJECT_UNWANTED: FileKind = hashes(
    HashPurpose::WholeObjectDetection,
    Category::PotentiallyUnwanted,
    FieldOrder::HashSizeName,
);
const SECTION: FileKind = hashes(
    HashPurpose::ExecutableSectionDetection,
    Category::Malware,
    FieldOrder::SizeHashName,
);
const SECTION_UNWANTED: FileKind = hashes(
    HashPurpose::ExecutableSectionDetection,
    Category::PotentiallyUnwanted,
    FieldOrder::SizeHashName,
);
const TRUST: FileKind = hashes(
    HashPurpose::WholeObjectTrust,
    Category::Malware,
    FieldOrder::HashSizeName,
);

const FILE_KINDS: [(&str, FileKind); 37] = [
    ("cvd", FileKind::Container),
    ("cld", FileKind::Container),
    ("ign", FileKind::IgnoreList),
    ("ign2", FileKind::IgnoreList),
    ("hdb", WHOLE_OBJECT),
    ("hsb", WHOLE_OBJECT),
    ("hdu", WHOLE_OBJECT_UNWANTED),
    ("hsu", WHOLE_OBJECT_UNWANTED),
    ("mdb", SECTION),
    ("msb", SECTION),
    ("mdu", SECTION_UNWANTED),
    ("msu", SECTION_UNWANTED),
    ("fp", TRUST),
    ("sfp", TRUST),
    ("cat", FileKind::NotYetCompiled),
    ("cbc", FileKind::NotYetCompiled),
    ("cdb", FileKind::NotYetCompiled),
    ("cfg", FileKind::NotYetCompiled),
    ("crb", FileKind::NotYetCompiled),
    ("cud", FileKind::NotYetCompiled),
    ("db", FileKind::NotYetCompiled),
    ("ftm", FileKind::NotYetCompiled),
    ("gdb", FileKind::NotYetCompiled),
    ("idb", FileKind::NotYetCompiled),
    ("imp", FileKind::NotYetCompiled),
    ("ioc", FileKind::NotYetCompiled),
    ("ldb", FileKind::NotYetCompiled),
    ("ldu", FileKind::NotYetCompiled),
    ("ndb", FileKind::Extended(Category::Malware)),
    ("ndu", FileKind::Extended(Category::PotentiallyUnwanted)),
    ("pdb", FileKind::NotYetCompiled),
    ("pwdb", FileKind::NotYetCompiled),
    ("rmd", FileKind::NotYetCompiled),
    ("sdb", FileKind::NotYetCompiled),
    ("wdb", FileKind::NotYetCompiled),
    ("yar", FileKind::NotYetCompiled),
    ("yara", FileKind::NotYetCompiled),
];

const LOADED_EARLY: [&str; 4] = ["daily.cld", "daily.cvd", "local.gdb", "daily.cfg"];

fn kind_of(name: &str) -> Option<FileKind> {
    let (_, extension) = name.rsplit_once('.')?;
    FILE_KINDS
        .iter()
        .find(|(known, _)| known.eq_ignore_ascii_case(extension))
        .map(|(_, kind)| *kind)
        .or_else(|| {
            extension
                .eq_ignore_ascii_case("zmd")
                .then_some(FileKind::NotYetCompiled)
        })
}

fn kind_description(kind: FileKind) -> &'static str {
    match kind {
        FileKind::Container => "signed container",
        FileKind::IgnoreList => "ignore list",
        FileKind::Hashes(file) => match (file.purpose, file.category) {
            (HashPurpose::WholeObjectDetection, Category::Malware) => "whole-file hashes",
            (HashPurpose::WholeObjectDetection, Category::PotentiallyUnwanted) => {
                "whole-file hashes, potentially unwanted"
            }
            (HashPurpose::ExecutableSectionDetection, Category::Malware) => {
                "executable section hashes"
            }
            (HashPurpose::ExecutableSectionDetection, Category::PotentiallyUnwanted) => {
                "executable section hashes, potentially unwanted"
            }
            (HashPurpose::WholeObjectTrust, _) => "false-positive hashes",
        },
        FileKind::Extended(Category::Malware) => "extended signatures",
        FileKind::Extended(Category::PotentiallyUnwanted) => {
            "extended signatures, potentially unwanted"
        }
        FileKind::NotYetCompiled => "not yet compiled",
    }
}

fn load_priority(name: &str, kind: FileKind) -> usize {
    if kind == FileKind::IgnoreList {
        return 0;
    }
    if let Some(position) = LOADED_EARLY
        .iter()
        .position(|early| early.eq_ignore_ascii_case(name))
    {
        return position.saturating_add(1);
    }
    if name
        .rsplit_once('.')
        .is_some_and(|(_, extension)| extension.eq_ignore_ascii_case("crb"))
    {
        return LOADED_EARLY.len().saturating_add(1);
    }
    LOADED_EARLY.len().saturating_add(2)
}

pub fn compile(
    files: &[DatabaseFile<'_>],
    image: &mut ImageBuilder,
) -> Result<Account, DatabaseError> {
    let mut account = Account::default();
    let mut databases: Vec<(&DatabaseFile<'_>, FileKind)> = Vec::new();
    for file in files {
        match kind_of(file.name) {
            Some(kind) => databases.push((file, kind)),
            None => account.not_databases.push(file.name.to_owned()),
        }
    }
    databases.sort_by(|(left, left_kind), (right, right_kind)| {
        (load_priority(left.name, *left_kind), left.name)
            .cmp(&(load_priority(right.name, *right_kind), right.name))
    });
    let mut loader = Loader {
        image,
        ignored: IgnoreList::default(),
        account,
        longest_part: 0,
    };
    for (file, kind) in databases {
        match kind {
            FileKind::Container => loader.load_container(file)?,
            _ => loader.load(&Source::loose(file.name), kind, file.contents)?,
        }
    }
    loader.image.set_report_windows(ReportWindows {
        length: SCAN_WINDOW_LENGTH,
        overlap: loader.longest_part,
    });
    Ok(loader.account)
}

struct Source<'a> {
    file: &'a str,
    member: Option<&'a str>,
    official: bool,
}

impl<'a> Source<'a> {
    fn loose(file: &'a str) -> Self {
        Self {
            file,
            member: None,
            official: false,
        }
    }
}

struct Loader<'i> {
    image: &'i mut ImageBuilder,
    ignored: IgnoreList,
    account: Account,
    longest_part: u32,
}

impl Loader<'_> {
    fn load_container(&mut self, file: &DatabaseFile<'_>) -> Result<(), DatabaseError> {
        let failed = |reason| DatabaseError::Container {
            file: file.name.to_owned(),
            reason,
        };
        let container = container::open(file.contents).map_err(failed)?;
        self.image
            .add_database(DatabaseRecord {
                name: file
                    .name
                    .split_once('.')
                    .map_or(file.name, |(stem, _)| stem)
                    .to_owned(),
                version: container.header.version,
                declared_signature_count: container.header.signature_count,
                functionality_level: container.header.functionality_level,
                provenance: Provenance::SignedContainerNotYetVerified,
            })
            .map_err(DatabaseError::Image)?;
        for member in &container.members {
            let source = Source {
                file: file.name,
                member: Some(&member.name),
                official: true,
            };
            match member_kind(member) {
                Some(kind) => {
                    container.index.check(member).map_err(failed)?;
                    self.load(&source, kind, &member.contents)?;
                }
                None => self.account_every_line(
                    &source,
                    "not signatures",
                    &member.contents,
                    LineOutcome::NotASignature,
                ),
            }
        }
        Ok(())
    }

    fn load(
        &mut self,
        source: &Source<'_>,
        kind: FileKind,
        contents: &[u8],
    ) -> Result<(), DatabaseError> {
        match kind {
            FileKind::Hashes(hash_file) => self.load_hashes(source, hash_file, kind, contents),
            FileKind::Extended(category) => self.load_extended(source, category, kind, contents),
            FileKind::IgnoreList => {
                self.ignored.add_entries_from(contents);
                self.account_every_line(
                    source,
                    kind_description(kind),
                    contents,
                    LineOutcome::NotASignature,
                );
                Ok(())
            }
            FileKind::Container | FileKind::NotYetCompiled => {
                self.account_every_line(
                    source,
                    kind_description(kind),
                    contents,
                    LineOutcome::NotYetCompiled,
                );
                Ok(())
            }
        }
    }

    fn load_hashes(
        &mut self,
        source: &Source<'_>,
        hash_file: HashFile,
        kind: FileKind,
        contents: &[u8],
    ) -> Result<(), DatabaseError> {
        if contents.is_empty() {
            return Err(DatabaseError::EmptyHashFile {
                file: source.file.to_owned(),
                member: source.member.map(str::to_owned),
            });
        }
        let mut outcomes = Vec::new();
        let mut unofficial_name = String::new();
        for (index, line) in lines(contents).enumerate() {
            let read = read_line(hash_file, without_line_ending(line), &self.ignored).map_err(
                |reason| DatabaseError::MalformedLine {
                    file: source.file.to_owned(),
                    member: source.member.map(str::to_owned),
                    line: index.saturating_add(1),
                    reason,
                },
            )?;
            outcomes.push(match read {
                ReadLine::Comment => LineOutcome::Comment,
                ReadLine::OutsideFunctionalityLevel => LineOutcome::OutsideFunctionalityLevel,
                ReadLine::Ignored => LineOutcome::Ignored,
                ReadLine::Signature(signature) => {
                    let name = if source.official {
                        signature.name
                    } else {
                        unofficial_name.clear();
                        unofficial_name.push_str(signature.name);
                        unofficial_name.push_str(UNOFFICIAL_SUFFIX);
                        &unofficial_name
                    };
                    self.image
                        .add_hash_signature(&HashSignature {
                            purpose: signature.purpose,
                            category: signature.category,
                            size: signature.size,
                            digest: signature.digest,
                            name,
                            indicator: signature.indicator,
                        })
                        .map_err(DatabaseError::Image)?;
                    LineOutcome::Compiled
                }
            });
        }
        self.record(source, kind_description(kind), outcomes);
        Ok(())
    }

    fn load_extended(
        &mut self,
        source: &Source<'_>,
        category: Category,
        kind: FileKind,
        contents: &[u8],
    ) -> Result<(), DatabaseError> {
        if contents.is_empty() {
            return Err(DatabaseError::EmptyDatabaseFile {
                file: source.file.to_owned(),
                member: source.member.map(str::to_owned),
            });
        }
        let mut outcomes = Vec::new();
        let mut unofficial_name = String::new();
        for (index, line) in lines(contents).enumerate() {
            let read =
                extended_lines::read_line(category, without_line_ending(line), &self.ignored)
                    .map_err(|reason| DatabaseError::MalformedExtendedLine {
                        file: source.file.to_owned(),
                        member: source.member.map(str::to_owned),
                        line: index.saturating_add(1),
                        reason,
                    })?;
            outcomes.push(match read {
                ReadExtendedLine::Comment => LineOutcome::Comment,
                ReadExtendedLine::Ignored => LineOutcome::Ignored,
                ReadExtendedLine::OutsideFunctionalityLevel => {
                    LineOutcome::OutsideFunctionalityLevel
                }
                ReadExtendedLine::TargetNotLoaded => LineOutcome::TargetNotLoaded,
                ReadExtendedLine::NeverReports => LineOutcome::NeverReports,
                ReadExtendedLine::NeedsExecutableFacts => LineOutcome::NeedsExecutableFacts,
                ReadExtendedLine::TargetNotYetCompiled
                | ReadExtendedLine::BodyNotYetCompiled(_) => LineOutcome::NotYetCompiled,
                ReadExtendedLine::Signature(signature) => {
                    let name = if source.official {
                        signature.name
                    } else {
                        unofficial_name.clear();
                        unofficial_name.push_str(signature.name);
                        unofficial_name.push_str(UNOFFICIAL_SUFFIX);
                        &unofficial_name
                    };
                    self.longest_part = self
                        .longest_part
                        .max(longest_part_of(&signature.pattern.elements));
                    self.image
                        .add_pattern_signature(&PatternSignature {
                            category: signature.category,
                            placement: signature.placement,
                            report_rank: if signature.plain_bytes {
                                RANK_OF_PLAIN_BYTES
                            } else {
                                RANK_OF_OTHER_BODIES
                            },
                            pattern: &signature.pattern,
                            name,
                            indicator: signature.indicator,
                        })
                        .map_err(DatabaseError::Image)?;
                    LineOutcome::Compiled
                }
            });
        }
        self.record(source, kind_description(kind), outcomes);
        Ok(())
    }

    fn account_every_line(
        &mut self,
        source: &Source<'_>,
        kind: &'static str,
        contents: &[u8],
        outcome: LineOutcome,
    ) {
        let outcomes = vec![outcome; lines(contents).count()];
        self.record(source, kind, outcomes);
    }

    fn record(&mut self, source: &Source<'_>, kind: &'static str, lines: Vec<LineOutcome>) {
        self.account.files.push(FileAccount {
            file: source.file.to_owned(),
            member: source.member.map(str::to_owned),
            kind,
            lines,
        });
    }
}

fn member_kind(member: &Member) -> Option<FileKind> {
    let is_index = member
        .name
        .rsplit_once('.')
        .is_some_and(|(_, extension)| extension.eq_ignore_ascii_case("info"));
    if member.name == LICENCE_MEMBER || is_index {
        return None;
    }
    kind_of(&member.name)
}

fn longest_part_of(elements: &[debar_image::PatternElement]) -> u32 {
    use debar_image::PatternElement;
    let mut longest: u32 = 0;
    let mut current: u32 = 0;
    for element in elements {
        let width = match element {
            PatternElement::Gap { .. } => {
                current = 0;
                continue;
            }
            PatternElement::Byte(_) | PatternElement::OneOf(_) => 1,
            PatternElement::Choice(alternatives) => alternatives
                .iter()
                .map(|alternative| u32::try_from(alternative.len()).unwrap_or(u32::MAX))
                .max()
                .unwrap_or(0),
            PatternElement::NoneOf { width, .. } => *width,
        };
        current = current.saturating_add(width);
        longest = longest.max(current);
    }
    longest
}
