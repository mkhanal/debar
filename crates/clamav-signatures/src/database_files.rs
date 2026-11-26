use std::fmt;

use std::collections::BTreeMap;

use debar_image::{
    BuildError, Category, DatabaseRecord, HashEntryId, HashPurpose, HashSignature, ImageBuilder,
    LogicalSignature, MagicTable, PartMemory, Pattern, PatternOutcome, PatternSignature, Placement,
    Provenance, ReportWindows, SignatureGroup, TypeFinding, UnwantedCategory,
};

use crate::account::{Account, FileAccount, LineOutcome};
use crate::container::{self, ContainerError, Member};
use crate::extended_lines::{self, MalformedExtendedLine, ReadExtendedLine};
use crate::file_type_lines::{self, MagicTarget, MalformedFileTypeLine, ReadFileTypeLine};
use crate::hash_duplicates::entries_not_reported;
use crate::hash_lines::{FieldOrder, HashFile, MalformedLine, ReadLine, read_line};
use crate::ignore_list::IgnoreList;
use crate::line_text::{lines, without_line_ending};
use crate::logical_lines::{self, MalformedLogicalLine, ReadLogicalLine};
use crate::type_names::{GENERIC_GROUP, TYPE_RECOGNITION_GROUP, describe_object_kinds};

const UNOFFICIAL_SUFFIX: &str = ".UNOFFICIAL";
const LICENCE_MEMBER: &str = "COPYING";
const SCAN_WINDOW_LENGTH: u32 = 131_072;
const LATEST_PART_ENDS_REMEMBERED: u32 = 8;
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
    MalformedFileTypeLine {
        file: String,
        member: Option<String>,
        line: usize,
        reason: MalformedFileTypeLine,
    },
    MalformedLogicalLine {
        file: String,
        member: Option<String>,
        line: usize,
        reason: MalformedLogicalLine,
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
            Self::MalformedFileTypeLine {
                file,
                member,
                line,
                reason,
            } => write!(formatter, "{} line {line}: {reason}", place(file, member)),
            Self::MalformedLogicalLine {
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
    FileTypes,
    Logical(Category),
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
    ("ftm", FileKind::FileTypes),
    ("gdb", FileKind::NotYetCompiled),
    ("idb", FileKind::NotYetCompiled),
    ("imp", FileKind::NotYetCompiled),
    ("ioc", FileKind::NotYetCompiled),
    ("ldb", FileKind::Logical(Category::Malware)),
    ("ldu", FileKind::Logical(Category::PotentiallyUnwanted)),
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
        FileKind::FileTypes => "file types",
        FileKind::Logical(Category::Malware) => "logical signatures",
        FileKind::Logical(Category::PotentiallyUnwanted) => {
            "logical signatures, potentially unwanted"
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
        longest_parts: BTreeMap::new(),
        hash_lines: Vec::new(),
        magic: Vec::new(),
    };
    for (file, kind) in databases {
        match kind {
            FileKind::Container => loader.load_container(file)?,
            _ => loader.load(&Source::loose(file.name), kind, file.contents)?,
        }
    }
    loader.finish()
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
    longest_parts: BTreeMap<SignatureGroup, u32>,
    hash_lines: Vec<LinePlace>,
    magic: Vec<file_type_lines::MagicLine>,
}

#[derive(Clone, Copy)]
struct LinePlace {
    file: usize,
    line: usize,
}

impl Loader<'_> {
    fn finish(mut self) -> Result<Account, DatabaseError> {
        self.withdraw_unreported_duplicates()?;
        for magic in self.magic.iter().rev() {
            let table = match magic.target {
                MagicTarget::File => MagicTable::Files,
                MagicTarget::Partition => MagicTable::Partitions,
            };
            self.image
                .add_type_magic(table, magic.offset, &magic.magic, magic.found);
        }
        let generic_overlap = self
            .longest_parts
            .get(&GENERIC_GROUP)
            .copied()
            .unwrap_or(0)
            .max(
                self.longest_parts
                    .get(&TYPE_RECOGNITION_GROUP)
                    .copied()
                    .unwrap_or(0),
            );
        let groups: Vec<SignatureGroup> = self.longest_parts.keys().copied().collect();
        for group in groups {
            let own = self.longest_parts.get(&group).copied().unwrap_or(0);
            let overlap = if group == TYPE_RECOGNITION_GROUP || group == GENERIC_GROUP {
                generic_overlap
            } else {
                own
            };
            self.image.set_report_windows(
                group,
                ReportWindows {
                    length: SCAN_WINDOW_LENGTH,
                    overlap,
                },
            );
            self.image.set_part_memory(
                group,
                PartMemory::FirstAndLatestEnds {
                    latest: LATEST_PART_ENDS_REMEMBERED,
                },
            );
        }
        describe_object_kinds(self.image);
        Ok(self.account)
    }

    fn withdraw_unreported_duplicates(&mut self) -> Result<(), DatabaseError> {
        let mut withdrawn: Vec<HashEntryId> = Vec::new();
        for bucket in self.image.hash_buckets_with_repeated_keys() {
            withdrawn.extend(entries_not_reported(&bucket));
        }
        for (bucket, unwanted) in self.image.hash_buckets_shared_with_unwanted() {
            withdrawn.extend(
                entries_not_reported(&bucket)
                    .into_iter()
                    .filter(|id| unwanted.contains(id)),
            );
        }
        withdrawn.sort();
        withdrawn.dedup();
        for id in &withdrawn {
            let place = usize::try_from(id.0)
                .ok()
                .and_then(|index| self.hash_lines.get(index))
                .copied()
                .ok_or(DatabaseError::Image(BuildError::TooManySignatures))?;
            if let Some(outcome) = self
                .account
                .files
                .get_mut(place.file)
                .and_then(|file| file.lines.get_mut(place.line))
            {
                *outcome = LineOutcome::ShadowedByDuplicate;
            }
        }
        self.image.withdraw_hash_signatures(withdrawn);
        Ok(())
    }

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
            FileKind::FileTypes => self.load_file_types(source, kind, contents),
            FileKind::Logical(category) => self.load_logical(source, category, kind, contents),
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
        let file = self.account.files.len();
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
                    if signature.category == Category::PotentiallyUnwanted {
                        self.image
                            .set_unwanted_category(name, unwanted_category_of(signature.name));
                    }
                    let id = self
                        .image
                        .add_hash_signature(&HashSignature {
                            purpose: signature.purpose,
                            category: signature.category,
                            size: signature.size,
                            digest: signature.digest,
                            name,
                            indicator: signature.indicator,
                        })
                        .map_err(DatabaseError::Image)?;
                    if usize::try_from(id.0).ok() != Some(self.hash_lines.len()) {
                        return Err(DatabaseError::Image(BuildError::TooManySignatures));
                    }
                    self.hash_lines.push(LinePlace { file, line: index });
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
                ReadExtendedLine::NeverReports(loaded) => {
                    self.lengthen(SignatureGroup(loaded.target), loaded.longest_part);
                    LineOutcome::NeverReports
                }
                ReadExtendedLine::BodyNotYetCompiled { loaded, .. } => {
                    self.lengthen(SignatureGroup(loaded.target), loaded.longest_part);
                    LineOutcome::NotYetCompiled
                }
                ReadExtendedLine::Signature(signature) => {
                    let name = if source.official {
                        signature.name
                    } else {
                        unofficial_name.clear();
                        unofficial_name.push_str(signature.name);
                        unofficial_name.push_str(UNOFFICIAL_SUFFIX);
                        &unofficial_name
                    };
                    self.lengthen(SignatureGroup(signature.target), signature.longest_part);
                    if signature.category == Category::PotentiallyUnwanted {
                        self.image
                            .set_unwanted_category(name, unwanted_category_of(signature.name));
                    }
                    self.add_pattern(
                        SignatureGroup(signature.target),
                        signature.category,
                        signature.placement,
                        &signature.pattern,
                        signature.plain_bytes,
                        PatternOutcome::Detection {
                            name,
                            indicator: signature.indicator,
                        },
                    )?;
                    LineOutcome::Compiled
                }
            });
        }
        self.record(source, kind_description(kind), outcomes);
        Ok(())
    }

    fn load_logical(
        &mut self,
        source: &Source<'_>,
        category: Category,
        kind: FileKind,
        contents: &[u8],
    ) -> Result<(), DatabaseError> {
        let mut outcomes = Vec::new();
        let mut unofficial_name = String::new();
        for (index, line) in lines(contents).enumerate() {
            let read = logical_lines::read_line(without_line_ending(line), &self.ignored).map_err(
                |reason| DatabaseError::MalformedLogicalLine {
                    file: source.file.to_owned(),
                    member: source.member.map(str::to_owned),
                    line: index.saturating_add(1),
                    reason,
                },
            )?;
            outcomes.push(match read {
                ReadLogicalLine::Comment => LineOutcome::Comment,
                ReadLogicalLine::Ignored => LineOutcome::Ignored,
                ReadLogicalLine::OutsideFunctionalityLevel => {
                    LineOutcome::OutsideFunctionalityLevel
                }
                ReadLogicalLine::TargetNotLoaded => LineOutcome::TargetNotLoaded,
                ReadLogicalLine::NotLoaded => LineOutcome::NotLoaded,
                ReadLogicalLine::NotYetCompiled { loaded, .. } => {
                    self.lengthen(SignatureGroup(loaded.target), loaded.longest_part);
                    LineOutcome::NotYetCompiled
                }
                ReadLogicalLine::Signature(signature) => {
                    let name = if source.official {
                        signature.name
                    } else {
                        unofficial_name.clear();
                        unofficial_name.push_str(signature.name);
                        unofficial_name.push_str(UNOFFICIAL_SUFFIX);
                        &unofficial_name
                    };
                    self.lengthen(SignatureGroup(signature.target), signature.longest_part);
                    if category == Category::PotentiallyUnwanted {
                        self.image
                            .set_unwanted_category(name, unwanted_category_of(signature.name));
                    }
                    self.image
                        .add_logical_signature(&LogicalSignature {
                            group: SignatureGroup(signature.target),
                            category,
                            name,
                            indicator: signature.indicator,
                            expression: &signature.expression,
                            subsignatures: &signature.subsignatures,
                            conditions: &signature.conditions,
                        })
                        .map_err(DatabaseError::Image)?;
                    LineOutcome::Compiled
                }
            });
        }
        self.record(source, kind_description(kind), outcomes);
        Ok(())
    }

    fn load_file_types(
        &mut self,
        source: &Source<'_>,
        kind: FileKind,
        contents: &[u8],
    ) -> Result<(), DatabaseError> {
        let mut outcomes = Vec::new();
        for (index, line) in lines(contents).enumerate() {
            let read = file_type_lines::read_line(without_line_ending(line)).map_err(|reason| {
                DatabaseError::MalformedFileTypeLine {
                    file: source.file.to_owned(),
                    member: source.member.map(str::to_owned),
                    line: index.saturating_add(1),
                    reason,
                }
            })?;
            outcomes.push(match read {
                ReadFileTypeLine::Comment => LineOutcome::Comment,
                ReadFileTypeLine::OutsideFunctionalityLevel => {
                    LineOutcome::OutsideFunctionalityLevel
                }
                ReadFileTypeLine::OtherMode => LineOutcome::NotASignature,
                ReadFileTypeLine::NeverReports { longest_part } => {
                    self.lengthen(TYPE_RECOGNITION_GROUP, longest_part);
                    LineOutcome::NeverReports
                }
                ReadFileTypeLine::BodyNotYetCompiled { longest_part, .. } => {
                    self.lengthen(TYPE_RECOGNITION_GROUP, longest_part);
                    LineOutcome::NotYetCompiled
                }
                ReadFileTypeLine::Magic(magic) => {
                    self.magic.push(magic);
                    LineOutcome::Compiled
                }
                ReadFileTypeLine::Recognition(recognition) => {
                    self.lengthen(TYPE_RECOGNITION_GROUP, recognition.longest_part);
                    self.add_pattern(
                        TYPE_RECOGNITION_GROUP,
                        Category::Malware,
                        recognition.placement,
                        &recognition.pattern,
                        recognition.plain_bytes,
                        PatternOutcome::TypeFound(TypeFinding {
                            found: recognition.found,
                            required: recognition.required,
                        }),
                    )?;
                    LineOutcome::Compiled
                }
            });
        }
        self.record(source, kind_description(kind), outcomes);
        Ok(())
    }

    fn add_pattern(
        &mut self,
        group: SignatureGroup,
        category: Category,
        placement: Placement,
        pattern: &Pattern,
        plain_bytes: bool,
        outcome: PatternOutcome<'_>,
    ) -> Result<(), DatabaseError> {
        self.image
            .add_pattern_signature(&PatternSignature {
                group,
                category,
                placement,
                report_rank: if plain_bytes {
                    RANK_OF_PLAIN_BYTES
                } else {
                    RANK_OF_OTHER_BODIES
                },
                pattern,
                outcome,
            })
            .map_err(DatabaseError::Image)
    }

    fn lengthen(&mut self, group: SignatureGroup, longest_part: u32) {
        let longest = self.longest_parts.entry(group).or_insert(0);
        *longest = (*longest).max(longest_part);
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

const UNWANTED_PREFIX: &str = "PUA";
const LONGEST_UNWANTED_CATEGORY: usize = 31;

fn unwanted_category_of(name: &str) -> UnwantedCategory<'_> {
    let Some(rest) = name.strip_prefix(UNWANTED_PREFIX) else {
        return UnwantedCategory::Unnamed;
    };
    if !rest.starts_with('.') {
        return UnwantedCategory::Unnamed;
    }
    match rest.rfind('.') {
        Some(last) if last > 0 => rest
            .get(..=last)
            .filter(|category| category.len() <= LONGEST_UNWANTED_CATEGORY)
            .map_or(UnwantedCategory::Unnamed, UnwantedCategory::Named),
        _ => UnwantedCategory::Unnamed,
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
