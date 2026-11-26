use std::fmt;

use std::collections::BTreeMap;

use debar_image::{
    BuildError, Category, CertificateRule, ContainerSignature, DatabaseRecord, HashEntryId,
    HashPurpose, HashSignature, IconGroups, ImageBuilder, LogicalOutcome, LogicalSignature,
    MagicTable, PartMemory, Pattern, PatternOutcome, PatternSignature, Placement, ProgramKind,
    ReportWindows, SignatureGroup, SignatureProgram, TypeFinding, UnwantedCategory, UrlRule,
};

use crate::account::{Account, FileAccount, LineOutcome};
use crate::certificate_lines::{
    CertificateFile, MalformedCertificateLine, ReadCertificateLine, repeats_a_stored_rule,
};
use crate::container::{self, ContainerError, ContainerKind, Member};
use crate::container_lines::{self, MalformedContainerLine, ReadContainerLine};
use crate::engine_switches::{
    CERTIFICATES, EngineSwitches, MalformedSwitchLine, PHISHING_ENGINE, ReadSwitchLine,
};
use crate::extended_lines::{self, MalformedExtendedLine, ReadExtendedLine};
use crate::file_type_lines::{self, MagicTarget, MalformedFileTypeLine, ReadFileTypeLine};
use crate::hash_duplicates::entries_not_reported;
use crate::hash_lines::{FieldOrder, HashFile, MalformedLine, ReadLine, read_line};
use crate::icon_lines::{self, MalformedIconLine, ReadIconLine};
use crate::ignore_list::IgnoreList;
use crate::line_text::{lines, without_line_ending};
use crate::logical_lines::{self, MalformedLogicalLine, ReadLogicalLine};
use crate::program_text::{
    MalformedProgram, ParsedProgram, ProgramSkip, ReadProgram, read_program,
};
use crate::type_names::{GENERIC_GROUP, TYPE_RECOGNITION_GROUP, describe_object_kinds};
use crate::url_lines::{
    self, MalformedUrlLine, ReadUrlLine, UrlFile, shadowed_by_an_allowed_digest,
};

const UNOFFICIAL_SUFFIX: &str = ".UNOFFICIAL";
const LICENCE_MEMBER: &str = "COPYING";
const SCAN_WINDOW_LENGTH: u32 = 131_072;
const LATEST_PART_ENDS_REMEMBERED: u32 = 8;
const RANK_OF_PLAIN_BYTES: u8 = 0;
const RANK_OF_OTHER_BODIES: u8 = 1;
const DETACHED_SIGNATURE_SUFFIX: &str = ".cvd.sign";

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
    MalformedContainerLine {
        file: String,
        member: Option<String>,
        line: usize,
        reason: MalformedContainerLine,
    },
    EmptyHashFile {
        file: String,
        member: Option<String>,
    },
    EmptyDatabaseFile {
        file: String,
        member: Option<String>,
    },
    MalformedSwitchLine {
        file: String,
        member: Option<String>,
        line: usize,
        reason: MalformedSwitchLine,
    },
    MalformedCertificateLine {
        file: String,
        member: Option<String>,
        line: usize,
        reason: MalformedCertificateLine,
    },
    MalformedIconLine {
        file: String,
        member: Option<String>,
        line: usize,
        reason: MalformedIconLine,
    },
    MalformedUrlLine {
        file: String,
        member: Option<String>,
        line: usize,
        reason: MalformedUrlLine,
    },
    MalformedProgram {
        file: String,
        member: Option<String>,
        reason: MalformedProgram,
    },
    MalformedProgramTrigger {
        file: String,
        member: Option<String>,
        reason: MalformedLogicalLine,
    },
    ProgramTriggerNotLoaded {
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
            Self::MalformedContainerLine {
                file,
                member,
                line,
                reason,
            } => write!(formatter, "{} line {line}: {reason}", place(file, member)),
            Self::EmptyHashFile { file, member } | Self::EmptyDatabaseFile { file, member } => {
                write!(formatter, "{} is empty", place(file, member))
            }
            Self::MalformedSwitchLine {
                file,
                member,
                line,
                reason,
            } => write!(formatter, "{} line {line}: {reason}", place(file, member)),
            Self::MalformedCertificateLine {
                file,
                member,
                line,
                reason,
            } => write!(formatter, "{} line {line}: {reason}", place(file, member)),
            Self::MalformedIconLine {
                file,
                member,
                line,
                reason,
            } => write!(formatter, "{} line {line}: {reason}", place(file, member)),
            Self::MalformedUrlLine {
                file,
                member,
                line,
                reason,
            } => write!(formatter, "{} line {line}: {reason}", place(file, member)),
            Self::MalformedProgram {
                file,
                member,
                reason,
            } => write!(
                formatter,
                "{}: the signature program: {reason}",
                place(file, member)
            ),
            Self::MalformedProgramTrigger {
                file,
                member,
                reason,
            } => write!(
                formatter,
                "{}: the signature program's trigger: {reason}",
                place(file, member)
            ),
            Self::ProgramTriggerNotLoaded { file, member } => write!(
                formatter,
                "{}: the signature program's trigger is outside the functionality level, but the program is not",
                place(file, member)
            ),
            Self::Image(reason) => write!(formatter, "{reason}"),
        }
    }
}

impl std::error::Error for DatabaseError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FileKind {
    Container(ContainerKind),
    IgnoreList,
    Switches,
    CertificateRules,
    Icons,
    UrlRules(UrlFile),
    Programs,
    Hashes(HashFile),
    Extended(Category),
    FileTypes,
    Logical(Category),
    ContainerSignatures,
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
    ("cvd", FileKind::Container(ContainerKind::HeaderSigned)),
    ("cld", FileKind::Container(ContainerKind::IndexSigned)),
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
    ("cbc", FileKind::Programs),
    ("cdb", FileKind::ContainerSignatures),
    ("cfg", FileKind::Switches),
    ("crb", FileKind::CertificateRules),
    ("cud", FileKind::Container(ContainerKind::Unsigned)),
    ("db", FileKind::NotYetCompiled),
    ("ftm", FileKind::FileTypes),
    ("gdb", FileKind::UrlRules(UrlFile::Monitored)),
    ("idb", FileKind::Icons),
    ("imp", FileKind::NotYetCompiled),
    ("ioc", FileKind::NotYetCompiled),
    ("ldb", FileKind::Logical(Category::Malware)),
    ("ldu", FileKind::Logical(Category::PotentiallyUnwanted)),
    ("ndb", FileKind::Extended(Category::Malware)),
    ("ndu", FileKind::Extended(Category::PotentiallyUnwanted)),
    ("pdb", FileKind::UrlRules(UrlFile::Monitored)),
    ("pwdb", FileKind::NotYetCompiled),
    ("rmd", FileKind::NotYetCompiled),
    ("sdb", FileKind::NotYetCompiled),
    ("wdb", FileKind::UrlRules(UrlFile::Allowed)),
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
        FileKind::Container(ContainerKind::HeaderSigned | ContainerKind::IndexSigned) => {
            "signed container"
        }
        FileKind::Container(ContainerKind::Unsigned) => "unsigned container",
        FileKind::IgnoreList => "ignore list",
        FileKind::Switches => "engine switches",
        FileKind::CertificateRules => "certificate rules",
        FileKind::Icons => "icon signatures",
        FileKind::UrlRules(UrlFile::Monitored) => "monitored URL rules",
        FileKind::UrlRules(UrlFile::Allowed) => "allowed URL rules",
        FileKind::Programs => "signature programs",
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
        FileKind::ContainerSignatures => "container signatures",
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
    let mut detached_signatures: BTreeMap<&str, &[u8]> = BTreeMap::new();
    for file in files {
        if let Some(kind) = kind_of(file.name) {
            databases.push((file, kind));
        } else {
            if file.name.ends_with(DETACHED_SIGNATURE_SUFFIX) {
                detached_signatures.insert(file.name, file.contents);
            }
            account.not_databases.push(file.name.to_owned());
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
        switches: EngineSwitches::default(),
        certificate_rules: Vec::new(),
        icon_groups: None,
        url_rules: Vec::new(),
        startup_program_loaded: false,
    };
    for (file, kind) in databases {
        match kind {
            FileKind::Container(container_kind) => {
                loader.load_container(file, container_kind, &detached_signatures)?;
            }
            _ => loader.load(&Source::loose(file.name), kind, file.contents)?,
        }
    }
    loader.finish()
}

struct Source<'a> {
    file: &'a str,
    member: Option<&'a str>,
    official: bool,
    signed: bool,
}

impl<'a> Source<'a> {
    fn loose(file: &'a str) -> Self {
        Self {
            file,
            member: None,
            official: false,
            signed: false,
        }
    }

    fn file_name(&self) -> String {
        self.file.to_owned()
    }

    fn member_name(&self) -> Option<String> {
        self.member.map(str::to_owned)
    }
}

struct Loader<'i> {
    image: &'i mut ImageBuilder,
    ignored: IgnoreList,
    account: Account,
    longest_parts: BTreeMap<SignatureGroup, u32>,
    hash_lines: Vec<LinePlace>,
    magic: Vec<file_type_lines::MagicLine>,
    switches: EngineSwitches,
    certificate_rules: Vec<CertificateRule>,
    icon_groups: Option<IconGroups>,
    url_rules: Vec<UrlRule>,
    startup_program_loaded: bool,
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
        self.image
            .set_engine_features(&self.switches.enabled_features());
        for rule in self.certificate_rules.drain(..).rev() {
            self.image.add_certificate_rule(rule);
        }
        if let Some(groups) = self.icon_groups.take() {
            self.image.set_icon_groups(groups);
        }
        for rule in self.url_rules.drain(..) {
            self.image.add_url_rule(rule);
        }
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

    fn load_container(
        &mut self,
        file: &DatabaseFile<'_>,
        kind: ContainerKind,
        detached_signatures: &BTreeMap<&str, &[u8]>,
    ) -> Result<(), DatabaseError> {
        let failed = |reason| DatabaseError::Container {
            file: file.name.to_owned(),
            reason,
        };
        let stem_length = file.name.find(['-', '.']).unwrap_or(file.name.len());
        let stem = file.name.get(..stem_length).unwrap_or(file.name);
        let version = container::header_version(file.contents).map_err(failed)?;
        let detached = detached_signatures
            .get(format!("{stem}-{version}{DETACHED_SIGNATURE_SUFFIX}").as_str())
            .copied();
        let container = container::open(file.contents, kind, detached).map_err(failed)?;
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
                provenance: container.provenance,
            })
            .map_err(DatabaseError::Image)?;
        for member in &container.members {
            let source = Source {
                file: file.name,
                member: Some(&member.name),
                official: container.provenance.is_signed(),
                signed: container.provenance.is_signed(),
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
            FileKind::ContainerSignatures => self.load_container_signatures(source, kind, contents),
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
            FileKind::Switches => self.load_switches(source, kind, contents),
            FileKind::CertificateRules => self.load_certificate_rules(source, kind, contents),
            FileKind::Icons => self.load_icons(source, kind, contents),
            FileKind::UrlRules(url_file) => self.load_url_rules(source, url_file, kind, contents),
            FileKind::Programs => self.load_program(source, kind, contents),
            FileKind::Container(_) | FileKind::NotYetCompiled => {
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
                            outcome: LogicalOutcome::Detection,
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

    fn load_container_signatures(
        &mut self,
        source: &Source<'_>,
        kind: FileKind,
        contents: &[u8],
    ) -> Result<(), DatabaseError> {
        let mut outcomes = Vec::new();
        let mut unofficial_name = String::new();
        for (index, line) in lines(contents).enumerate() {
            let read = container_lines::read_line(without_line_ending(line), &self.ignored)
                .map_err(|reason| DatabaseError::MalformedContainerLine {
                    file: source.file.to_owned(),
                    member: source.member.map(str::to_owned),
                    line: index.saturating_add(1),
                    reason,
                })?;
            outcomes.push(match read {
                ReadContainerLine::Comment => LineOutcome::Comment,
                ReadContainerLine::OutsideFunctionalityLevel => {
                    LineOutcome::OutsideFunctionalityLevel
                }
                ReadContainerLine::Ignored => LineOutcome::Ignored,
                ReadContainerLine::Signature(signature) => {
                    let name = if source.official {
                        signature.name
                    } else {
                        unofficial_name.clear();
                        unofficial_name.push_str(signature.name);
                        unofficial_name.push_str(UNOFFICIAL_SUFFIX);
                        &unofficial_name
                    };
                    self.image
                        .add_container_signature(&ContainerSignature {
                            name,
                            indicator: signature.indicator,
                            container: signature.container,
                            container_size: signature.container_size,
                            entry_name: signature.entry_name,
                            compressed_size: signature.compressed_size,
                            real_size: signature.real_size,
                            encrypted: signature.encrypted,
                            position: signature.position,
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

    fn record_every_line(
        &mut self,
        source: &Source<'_>,
        kind: FileKind,
        contents: &[u8],
        outcome: LineOutcome,
    ) {
        self.account_every_line(source, kind_description(kind), contents, outcome);
    }

    fn load_switches(
        &mut self,
        source: &Source<'_>,
        kind: FileKind,
        contents: &[u8],
    ) -> Result<(), DatabaseError> {
        let mut outcomes = Vec::new();
        for (index, line) in lines(contents).enumerate() {
            let line = without_line_ending(line);
            let read = self.switches.read_line(line).map_err(|reason| {
                DatabaseError::MalformedSwitchLine {
                    file: source.file_name(),
                    member: source.member_name(),
                    line: index.saturating_add(1),
                    reason,
                }
            })?;
            outcomes.push(match read {
                ReadSwitchLine::NotASwitch if line.first() == Some(&b'#') => LineOutcome::Comment,
                ReadSwitchLine::NotASwitch => LineOutcome::NotASignature,
                ReadSwitchLine::OutsideFunctionalityLevel => LineOutcome::OutsideFunctionalityLevel,
                ReadSwitchLine::Applied => LineOutcome::Compiled,
            });
        }
        self.record(source, kind_description(kind), outcomes);
        Ok(())
    }

    fn load_certificate_rules(
        &mut self,
        source: &Source<'_>,
        kind: FileKind,
        contents: &[u8],
    ) -> Result<(), DatabaseError> {
        if !self.switches.is_on(CERTIFICATES) {
            self.record_every_line(source, kind, contents, LineOutcome::NotLoaded);
            return Ok(());
        }
        let mut file = CertificateFile::default();
        let mut outcomes = Vec::new();
        for (index, line) in lines(contents).enumerate() {
            let read = file
                .read_line(without_line_ending(line))
                .map_err(|reason| DatabaseError::MalformedCertificateLine {
                    file: source.file_name(),
                    member: source.member_name(),
                    line: index.saturating_add(1),
                    reason,
                })?;
            outcomes.push(match read {
                ReadCertificateLine::Comment => LineOutcome::Comment,
                ReadCertificateLine::OutsideFunctionalityLevel => {
                    LineOutcome::OutsideFunctionalityLevel
                }
                ReadCertificateLine::Rule(rule) => {
                    if repeats_a_stored_rule(&self.certificate_rules, &rule) {
                        LineOutcome::ShadowedByDuplicate
                    } else {
                        self.certificate_rules.push(rule);
                        LineOutcome::Compiled
                    }
                }
            });
        }
        self.record(source, kind_description(kind), outcomes);
        Ok(())
    }

    fn load_icons(
        &mut self,
        source: &Source<'_>,
        kind: FileKind,
        contents: &[u8],
    ) -> Result<(), DatabaseError> {
        let mut outcomes = Vec::new();
        for (index, line) in lines(contents).enumerate() {
            let groups = self.icon_groups.get_or_insert_with(IconGroups::default);
            let read = icon_lines::read_line(without_line_ending(line), &self.ignored, groups)
                .map_err(|reason| DatabaseError::MalformedIconLine {
                    file: source.file_name(),
                    member: source.member_name(),
                    line: index.saturating_add(1),
                    reason,
                })?;
            outcomes.push(match read {
                ReadIconLine::Comment => LineOutcome::Comment,
                ReadIconLine::Ignored => LineOutcome::Ignored,
                ReadIconLine::Signature => LineOutcome::Compiled,
            });
        }
        self.record(source, kind_description(kind), outcomes);
        Ok(())
    }

    fn load_url_rules(
        &mut self,
        source: &Source<'_>,
        url_file: UrlFile,
        kind: FileKind,
        contents: &[u8],
    ) -> Result<(), DatabaseError> {
        if !self.switches.is_on(PHISHING_ENGINE) {
            self.record_every_line(source, kind, contents, LineOutcome::NotLoaded);
            return Ok(());
        }
        let mut outcomes = Vec::new();
        for (index, line) in lines(contents).enumerate() {
            let read =
                url_lines::read_line(url_file, without_line_ending(line)).map_err(|reason| {
                    DatabaseError::MalformedUrlLine {
                        file: source.file_name(),
                        member: source.member_name(),
                        line: index.saturating_add(1),
                        reason,
                    }
                })?;
            outcomes.push(match read {
                ReadUrlLine::Comment => LineOutcome::Comment,
                ReadUrlLine::OutsideFunctionalityLevel => LineOutcome::OutsideFunctionalityLevel,
                ReadUrlLine::Rule(rule) => {
                    if shadowed_by_an_allowed_digest(&self.url_rules, &rule) {
                        LineOutcome::ShadowedByDuplicate
                    } else {
                        self.url_rules.push(rule);
                        LineOutcome::Compiled
                    }
                }
            });
        }
        self.record(source, kind_description(kind), outcomes);
        Ok(())
    }

    fn load_program(
        &mut self,
        source: &Source<'_>,
        kind: FileKind,
        contents: &[u8],
    ) -> Result<(), DatabaseError> {
        if !self.switches.runs_programs() {
            self.record_every_line(source, kind, contents, LineOutcome::NotLoaded);
            return Ok(());
        }
        let malformed = |reason| DatabaseError::MalformedProgram {
            file: source.file_name(),
            member: source.member_name(),
            reason,
        };
        let parsed = match read_program(contents, source.member.is_some()).map_err(malformed)? {
            ReadProgram::Skipped(skip) => {
                let outcome = match skip {
                    ProgramSkip::FormatLevel | ProgramSkip::FunctionalityLevel => {
                        LineOutcome::OutsideFunctionalityLevel
                    }
                    ProgramSkip::InterfaceBeyondEngine | ProgramSkip::GlobalsBeyondEngine => {
                        LineOutcome::NotLoaded
                    }
                };
                self.record_every_line(source, kind, contents, outcome);
                return Ok(());
            }
            ReadProgram::Program(parsed) => parsed,
        };
        if parsed.kind == ProgramKind::Startup {
            if self.startup_program_loaded {
                return Err(malformed(MalformedProgram::SecondStartupProgram));
            }
            self.startup_program_loaded = true;
        }
        let outcome = match parsed.trigger {
            None => {
                self.add_program(source, &parsed, false)?;
                LineOutcome::Compiled
            }
            Some(trigger) => self.load_program_trigger(source, &parsed, trigger)?,
        };
        self.record_every_line(source, kind, contents, outcome);
        Ok(())
    }

    fn add_program(
        &mut self,
        source: &Source<'_>,
        parsed: &ParsedProgram<'_>,
        triggered: bool,
    ) -> Result<debar_image::SignatureProgramId, DatabaseError> {
        self.image
            .add_signature_program(SignatureProgram {
                name: source.member.unwrap_or(source.file).to_owned(),
                kind: parsed.kind,
                from_signed_container: source.signed,
                triggered,
                apis: parsed.apis.clone(),
                types: parsed.types.clone(),
                globals: parsed.globals.clone(),
                functions: parsed.functions.clone(),
            })
            .map_err(DatabaseError::Image)
    }

    fn load_program_trigger(
        &mut self,
        source: &Source<'_>,
        parsed: &ParsedProgram<'_>,
        trigger: &[u8],
    ) -> Result<LineOutcome, DatabaseError> {
        let read =
            logical_lines::read_program_trigger(trigger, &self.ignored).map_err(|reason| {
                DatabaseError::MalformedProgramTrigger {
                    file: source.file_name(),
                    member: source.member_name(),
                    reason,
                }
            })?;
        let signature = match read {
            ReadLogicalLine::Ignored => return Ok(LineOutcome::Ignored),
            ReadLogicalLine::NotYetCompiled { .. } => return Ok(LineOutcome::NotYetCompiled),
            ReadLogicalLine::Comment
            | ReadLogicalLine::OutsideFunctionalityLevel
            | ReadLogicalLine::TargetNotLoaded
            | ReadLogicalLine::NotLoaded => {
                return Err(DatabaseError::ProgramTriggerNotLoaded {
                    file: source.file_name(),
                    member: source.member_name(),
                });
            }
            ReadLogicalLine::Signature(signature) => signature,
        };
        let program = self.add_program(source, parsed, true)?;
        let outcome = if parsed.kind == ProgramKind::Logical {
            LogicalOutcome::RunProgram(program)
        } else {
            LogicalOutcome::HookTriggered(program)
        };
        let name = if source.official {
            signature.name.to_owned()
        } else {
            format!("{}{UNOFFICIAL_SUFFIX}", signature.name)
        };
        self.lengthen(SignatureGroup(signature.target), signature.longest_part);
        self.image
            .add_logical_signature(&LogicalSignature {
                group: SignatureGroup(signature.target),
                category: Category::Malware,
                name: &name,
                indicator: signature.indicator,
                outcome,
                expression: &signature.expression,
                subsignatures: &signature.subsignatures,
                conditions: &signature.conditions,
            })
            .map_err(DatabaseError::Image)?;
        Ok(LineOutcome::Compiled)
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
