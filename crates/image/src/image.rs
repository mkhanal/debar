use std::fmt;
use std::ops::Range;

use sha2::{Digest as _, Sha256};
use zerocopy::FromBytes;

use crate::builder::provenance_code;
use crate::hash_partition::{HashPartition, PartitionKey, PartitionMalformed};
use crate::layout::{
    BYTE_ORDER_MARK, CHECKSUM_LENGTH, DatabaseEntry, DirectoryEntry, Header, LAYOUT_VERSION, MAGIC,
    SECTION_ALIGNMENT, SectionKind,
};
use crate::model::{DatabaseRecord, Provenance, SignatureGroup, SignatureName};
use crate::names::{NameId, NamesMalformed, NamesView};
use crate::object_kinds::{KindsMalformed, ObjectKinds};
use crate::pattern_group::{GroupMalformed, PatternGroup};
use crate::type_magic::{MagicMalformed, TypeMagic};

#[derive(Debug, PartialEq, Eq)]
pub enum ImageError {
    TooShort,
    NotAnImage,
    UnsupportedLayout {
        found: u32,
    },
    ForeignByteOrder,
    LengthDisagrees {
        recorded: u64,
        actual: usize,
    },
    HeaderChecksumMismatch,
    SectionOutsideTheImage {
        index: usize,
    },
    SectionMisplaced {
        index: usize,
    },
    UnknownSection {
        index: usize,
        kind: u32,
    },
    SectionMissing {
        kind: SectionKind,
        qualifier: u32,
    },
    SectionChecksumMismatch {
        kind: SectionKind,
        qualifier: u32,
    },
    DatabasesMalformed,
    HashPartitionMalformed {
        key: PartitionKey,
        reason: PartitionMalformed,
    },
    NamesMalformed(NamesMalformed),
    PatternGroupMalformed {
        group: SignatureGroup,
        reason: GroupMalformed,
    },
    ObjectKindsMalformed(KindsMalformed),
    TypeMagicMalformed(MagicMalformed),
}

impl fmt::Display for ImageError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooShort => write!(formatter, "the file is shorter than an image header"),
            Self::NotAnImage => write!(formatter, "the file is not a Debar image"),
            Self::UnsupportedLayout { found } => write!(
                formatter,
                "the image has layout version {found}; this build reads version {LAYOUT_VERSION}; compile the databases again"
            ),
            Self::ForeignByteOrder => write!(formatter, "the image's byte-order mark is wrong"),
            Self::LengthDisagrees { recorded, actual } => write!(
                formatter,
                "the image records a length of {recorded} bytes but is {actual} bytes long"
            ),
            Self::HeaderChecksumMismatch => write!(
                formatter,
                "the image's header and section directory do not match their checksum"
            ),
            Self::SectionOutsideTheImage { index } => {
                write!(formatter, "section {index} lies outside the image")
            }
            Self::SectionMisplaced { index } => write!(
                formatter,
                "section {index} does not start on a page boundary after the previous one"
            ),
            Self::UnknownSection { index, kind } => {
                write!(formatter, "section {index} has unknown kind {kind}")
            }
            Self::SectionMissing { kind, qualifier } => {
                write!(
                    formatter,
                    "the image has no {kind:?} section {qualifier:#x}"
                )
            }
            Self::SectionChecksumMismatch { kind, qualifier } => write!(
                formatter,
                "the {kind:?} section {qualifier:#x} does not match its checksum"
            ),
            Self::DatabasesMalformed => write!(formatter, "the databases section is malformed"),
            Self::HashPartitionMalformed { key, reason } => {
                write!(formatter, "the hash table {key:?} is malformed: {reason:?}")
            }
            Self::NamesMalformed(reason) => {
                write!(formatter, "the names section is malformed: {reason:?}")
            }
            Self::PatternGroupMalformed { group, reason } => write!(
                formatter,
                "the pattern signatures of group {} are malformed: {reason:?}",
                group.0
            ),
            Self::ObjectKindsMalformed(reason) => {
                write!(formatter, "the object kinds are malformed: {reason:?}")
            }
            Self::TypeMagicMalformed(reason) => {
                write!(formatter, "the type magic is malformed: {reason:?}")
            }
        }
    }
}

impl std::error::Error for ImageError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SectionExtent {
    pub kind: SectionKind,
    pub qualifier: u32,
    pub range: Range<usize>,
    pub item_count: u64,
}

pub struct Image<'m> {
    bytes: &'m [u8],
    sections: Vec<SectionExtent>,
}

impl<'m> Image<'m> {
    pub fn open(bytes: &'m [u8]) -> Result<Self, ImageError> {
        let (header, rest) = Header::ref_from_prefix(bytes).map_err(|_| ImageError::TooShort)?;
        if header.magic != MAGIC {
            return Err(ImageError::NotAnImage);
        }
        if header.layout_version.get() != LAYOUT_VERSION {
            return Err(ImageError::UnsupportedLayout {
                found: header.layout_version.get(),
            });
        }
        if header.byte_order.get() != BYTE_ORDER_MARK {
            return Err(ImageError::ForeignByteOrder);
        }
        if usize::try_from(header.file_length.get()).ok() != Some(bytes.len()) {
            return Err(ImageError::LengthDisagrees {
                recorded: header.file_length.get(),
                actual: bytes.len(),
            });
        }
        let section_count =
            usize::try_from(header.section_count.get()).map_err(|_| ImageError::TooShort)?;
        let (directory, rest) = <[DirectoryEntry]>::ref_from_prefix_with_elems(rest, section_count)
            .map_err(|_| ImageError::TooShort)?;
        let checksum = rest.get(..CHECKSUM_LENGTH).ok_or(ImageError::TooShort)?;
        let checked_length = bytes
            .len()
            .checked_sub(rest.len())
            .ok_or(ImageError::TooShort)?;
        let checked = bytes.get(..checked_length).ok_or(ImageError::TooShort)?;
        if Sha256::digest(checked).as_slice() != checksum {
            return Err(ImageError::HeaderChecksumMismatch);
        }
        let sections = section_extents(directory, bytes.len())?;
        Ok(Self { bytes, sections })
    }

    #[must_use]
    pub fn sections(&self) -> &[SectionExtent] {
        &self.sections
    }

    pub fn databases(&self) -> Result<Vec<DatabaseRecord>, ImageError> {
        let bytes = self.section_bytes(SectionKind::Databases, 0)?;
        let entries =
            <[DatabaseEntry]>::ref_from_bytes(bytes).map_err(|_| ImageError::DatabasesMalformed)?;
        entries
            .iter()
            .map(|entry| {
                let name_length = entry
                    .name
                    .iter()
                    .position(|byte| *byte == 0)
                    .unwrap_or(entry.name.len());
                let name = entry
                    .name
                    .get(..name_length)
                    .and_then(|name| std::str::from_utf8(name).ok())
                    .ok_or(ImageError::DatabasesMalformed)?;
                let provenance = [
                    Provenance::SignedContainerNotYetVerified,
                    Provenance::UnsignedFile,
                ]
                .into_iter()
                .find(|known| provenance_code(*known) == entry.provenance.get())
                .ok_or(ImageError::DatabasesMalformed)?;
                Ok(DatabaseRecord {
                    name: name.to_owned(),
                    version: entry.version.get(),
                    declared_signature_count: entry.declared_signature_count.get(),
                    functionality_level: entry.functionality_level.get(),
                    provenance,
                })
            })
            .collect()
    }

    pub fn hash_partition(
        &self,
        key: PartitionKey,
    ) -> Result<Option<HashPartition<'m>>, ImageError> {
        let qualifier = key.qualifier();
        let Some(sizes) = self.optional_section_bytes(SectionKind::HashSizes, qualifier) else {
            return Ok(None);
        };
        let filter = self.section_bytes(SectionKind::HashFilter, qualifier)?;
        let entries = self.section_bytes(SectionKind::HashEntries, qualifier)?;
        HashPartition::read(key.algorithm, sizes, filter, entries)
            .map(Some)
            .map_err(|reason| ImageError::HashPartitionMalformed { key, reason })
    }

    pub fn pattern_group(
        &self,
        group: SignatureGroup,
    ) -> Result<Option<PatternGroup<'m>>, ImageError> {
        self.optional_section_bytes(SectionKind::PatternGroup, group.0)
            .map(PatternGroup::read)
            .transpose()
            .map_err(|reason| ImageError::PatternGroupMalformed { group, reason })
    }

    pub fn object_kinds(&self) -> Result<Option<ObjectKinds<'m>>, ImageError> {
        self.optional_section_bytes(SectionKind::ObjectKinds, 0)
            .map(ObjectKinds::read)
            .transpose()
            .map_err(ImageError::ObjectKindsMalformed)
    }

    pub fn type_magic(&self) -> Result<Option<TypeMagic<'m>>, ImageError> {
        self.optional_section_bytes(SectionKind::TypeMagic, 0)
            .map(TypeMagic::read)
            .transpose()
            .map_err(ImageError::TypeMagicMalformed)
    }

    pub fn signature_name(&self, id: NameId) -> Result<SignatureName, ImageError> {
        let names = NamesView::read(self.section_bytes(SectionKind::Names, 0)?)
            .map_err(ImageError::NamesMalformed)?;
        names.signature_name(id).map_err(ImageError::NamesMalformed)
    }

    pub fn verify_sections(&self) -> Result<(), ImageError> {
        let (_, rest) = Header::ref_from_prefix(self.bytes).map_err(|_| ImageError::TooShort)?;
        let (directory, _) =
            <[DirectoryEntry]>::ref_from_prefix_with_elems(rest, self.sections.len())
                .map_err(|_| ImageError::TooShort)?;
        for (extent, entry) in self.sections.iter().zip(directory) {
            let bytes = self
                .bytes
                .get(extent.range.clone())
                .ok_or(ImageError::TooShort)?;
            if Sha256::digest(bytes).as_slice() != entry.checksum {
                return Err(ImageError::SectionChecksumMismatch {
                    kind: extent.kind,
                    qualifier: extent.qualifier,
                });
            }
        }
        Ok(())
    }

    fn optional_section_bytes(&self, kind: SectionKind, qualifier: u32) -> Option<&'m [u8]> {
        let extent = self
            .sections
            .iter()
            .find(|extent| extent.kind == kind && extent.qualifier == qualifier)?;
        self.bytes.get(extent.range.clone())
    }

    fn section_bytes(&self, kind: SectionKind, qualifier: u32) -> Result<&'m [u8], ImageError> {
        self.optional_section_bytes(kind, qualifier)
            .ok_or(ImageError::SectionMissing { kind, qualifier })
    }
}

fn section_extents(
    directory: &[DirectoryEntry],
    image_length: usize,
) -> Result<Vec<SectionExtent>, ImageError> {
    let mut earliest_start = SECTION_ALIGNMENT;
    let mut extents = Vec::with_capacity(directory.len());
    for (index, entry) in directory.iter().enumerate() {
        let kind = SectionKind::from_code(entry.kind.get()).ok_or(ImageError::UnknownSection {
            index,
            kind: entry.kind.get(),
        })?;
        let start = usize::try_from(entry.offset.get())
            .map_err(|_| ImageError::SectionOutsideTheImage { index })?;
        let length = usize::try_from(entry.length.get())
            .map_err(|_| ImageError::SectionOutsideTheImage { index })?;
        let end = start
            .checked_add(length)
            .filter(|end| *end <= image_length)
            .ok_or(ImageError::SectionOutsideTheImage { index })?;
        if start < earliest_start || start % SECTION_ALIGNMENT != 0 {
            return Err(ImageError::SectionMisplaced { index });
        }
        earliest_start = end;
        extents.push(SectionExtent {
            kind,
            qualifier: entry.qualifier.get(),
            range: start..end,
            item_count: entry.item_count.get(),
        });
    }
    Ok(extents)
}
