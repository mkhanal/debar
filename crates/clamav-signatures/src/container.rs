use std::fmt;
use std::io::Read;

use debar_image::Provenance;
use flate2::read::GzDecoder;
use md5::Md5;
use sha2::{Digest as _, Sha256};

use crate::FUNCTIONALITY_LEVEL;
use crate::container_verification::{
    DetachedSignatureInvalid, DetachedVerification, detached_signature_holds,
    header_signature_holds, index_signature_holds,
};
use crate::ignore_list::hex_value;
use crate::line_text::{lines, without_line_ending};
use crate::numbers::leading_integer;

const HEADER_LENGTH: usize = 512;
const HEADER_MAGIC: &[u8] = b"ClamAV-VDB";
const HEADER_FIELD_COUNT: usize = 9;
const PLAIN_TAR_START: &[u8] = b"COPYING";
const TAR_BLOCK: usize = 512;
const TAR_NAME_FIELD: std::ops::Range<usize> = 0..100;
const TAR_SIZE_FIELD: std::ops::Range<usize> = 124..136;
const TAR_TYPE_FLAG: usize = 156;
const LARGEST_PAYLOAD: u64 = 4 * 1024 * 1024 * 1024;
const INDEX_SUFFIX: &str = ".info";
const INDEX_SIGNATURE_PREFIX: &[u8] = b"DSIG:";
const SHA256_HEX_LENGTH: usize = 64;
const MD5_HEX_LENGTH: usize = 32;
const SHORTEST_HEADER_SIGNATURE: usize = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContainerKind {
    HeaderSigned,
    IndexSigned,
    Unsigned,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContainerError {
    HeaderTooShort,
    NotAContainer,
    HeaderField { field: &'static str },
    PayloadDigestMismatch,
    HeaderSignatureMissing,
    HeaderSignatureDoesNotVerify,
    DetachedSignatureInvalid(DetachedSignatureInvalid),
    IndexSignatureDoesNotVerify,
    PayloadNotGzip(String),
    PayloadTooLarge,
    TarHeaderTruncated,
    TarSizeNotOctal { member: String },
    TarMemberTruncated { member: String },
    TarMemberNotAFile { member: String },
    TarMemberInADirectory { member: String },
    IndexMissing,
    IndexHeaderDisagrees,
    IndexLineMalformed { line: usize },
    IndexUnsigned,
    MemberNotInIndex { member: String },
    MemberDisagreesWithIndex { member: String },
}

impl fmt::Display for ContainerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HeaderTooShort => write!(formatter, "shorter than a container header"),
            Self::NotAContainer => write!(
                formatter,
                "the header does not start with {:?}",
                "ClamAV-VDB"
            ),
            Self::HeaderField { field } => {
                write!(formatter, "the header's {field} is not a number")
            }
            Self::PayloadDigestMismatch => {
                write!(
                    formatter,
                    "the payload does not match the MD5 in the header"
                )
            }
            Self::PayloadNotGzip(reason) => write!(formatter, "the payload is not gzip: {reason}"),
            Self::HeaderSignatureMissing => {
                write!(formatter, "the header carries no digital signature")
            }
            Self::HeaderSignatureDoesNotVerify => write!(
                formatter,
                "the header's digital signature does not verify against the payload"
            ),
            Self::DetachedSignatureInvalid(reason) => {
                write!(formatter, "the detached signature is invalid: {reason:?}")
            }
            Self::IndexSignatureDoesNotVerify => {
                write!(
                    formatter,
                    "the .info member's digital signature does not verify"
                )
            }
            Self::PayloadTooLarge => write!(formatter, "the payload unpacks to more than 4 GiB"),
            Self::TarHeaderTruncated => write!(formatter, "a tar header is cut short"),
            Self::TarSizeNotOctal { member } => {
                write!(formatter, "the tar size of {member} is not octal")
            }
            Self::TarMemberTruncated { member } => write!(formatter, "{member} is cut short"),
            Self::TarMemberNotAFile { member } => {
                write!(formatter, "{member} is not a regular file")
            }
            Self::TarMemberInADirectory { member } => {
                write!(formatter, "{member} names a directory")
            }
            Self::IndexMissing => write!(formatter, "no .info member"),
            Self::IndexHeaderDisagrees => {
                write!(
                    formatter,
                    "the .info header disagrees with the container header"
                )
            }
            Self::IndexLineMalformed { line } => {
                write!(formatter, ".info line {line} is malformed")
            }
            Self::IndexUnsigned => write!(formatter, "the .info member has no DSIG line"),
            Self::MemberNotInIndex { member } => {
                write!(formatter, "{member} is not listed in .info")
            }
            Self::MemberDisagreesWithIndex { member } => write!(
                formatter,
                "{member} does not match the size and SHA-256 listed in .info"
            ),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerHeader {
    pub version: u32,
    pub signature_count: u32,
    pub functionality_level: u32,
    pub build_seconds: u64,
}

pub struct Member {
    pub name: String,
    pub contents: Vec<u8>,
}

pub struct Container {
    pub header: ContainerHeader,
    pub provenance: Provenance,
    pub members: Vec<Member>,
    pub index: Index,
}

pub struct Index {
    listed: Vec<(String, u64, [u8; 32])>,
}

impl Index {
    pub fn check(&self, member: &Member) -> Result<(), ContainerError> {
        let (_, size, digest) = self
            .listed
            .iter()
            .find(|(name, _, _)| *name == member.name)
            .ok_or_else(|| ContainerError::MemberNotInIndex {
                member: member.name.clone(),
            })?;
        let actual_size = u64::try_from(member.contents.len()).ok();
        let actual_digest: [u8; 32] = Sha256::digest(&member.contents).into();
        if actual_size == Some(*size) && actual_digest == *digest {
            Ok(())
        } else {
            Err(ContainerError::MemberDisagreesWithIndex {
                member: member.name.clone(),
            })
        }
    }
}

pub fn header_version(contents: &[u8]) -> Result<u32, ContainerError> {
    let header_bytes = contents
        .get(..HEADER_LENGTH)
        .ok_or(ContainerError::HeaderTooShort)?;
    read_header(header_bytes).map(|(header, _)| header.version)
}

pub fn open(
    contents: &[u8],
    kind: ContainerKind,
    detached_signature: Option<&[u8]>,
) -> Result<Container, ContainerError> {
    let (header_bytes, payload) = contents
        .split_at_checked(HEADER_LENGTH)
        .ok_or(ContainerError::HeaderTooShort)?;
    let (header, signature_fields) = read_header(header_bytes)?;
    let provenance = match kind {
        ContainerKind::HeaderSigned => {
            verify_header(contents, payload, &signature_fields, detached_signature)?
        }
        ContainerKind::IndexSigned => Provenance::IndexSignatureVerified,
        ContainerKind::Unsigned => Provenance::UnsignedContainer,
    };
    let tar = if payload.starts_with(PLAIN_TAR_START) {
        payload.to_vec()
    } else {
        gunzip(payload)?
    };
    let members = tar_members(&tar)?;
    let index_member = members
        .iter()
        .find(|member| member.name.ends_with(INDEX_SUFFIX))
        .ok_or(ContainerError::IndexMissing)?;
    let index = read_index(
        &index_member.contents,
        &header,
        kind != ContainerKind::Unsigned,
    )?;
    Ok(Container {
        header,
        provenance,
        members,
        index,
    })
}

fn verify_header(
    contents: &[u8],
    payload: &[u8],
    fields: &SignatureFields,
    detached_signature: Option<&[u8]>,
) -> Result<Provenance, ContainerError> {
    let level = u32::try_from(FUNCTIONALITY_LEVEL).unwrap_or(u32::MAX);
    if let Some(detached) = detached_signature {
        match detached_signature_holds(contents, detached, level) {
            DetachedVerification::Verified => return Ok(Provenance::DetachedSignatureVerified),
            DetachedVerification::Invalid(reason) => {
                return Err(ContainerError::DetachedSignatureInvalid(reason));
            }
            DetachedVerification::CannotVerify => {}
        }
    }
    let actual_md5: [u8; 16] = Md5::digest(payload).into();
    if fields.md5.len() == MD5_HEX_LENGTH && fields.md5 != lowercase_hex(&actual_md5).as_bytes() {
        return Err(ContainerError::PayloadDigestMismatch);
    }
    if fields.signature.len() < SHORTEST_HEADER_SIGNATURE {
        return Err(ContainerError::HeaderSignatureMissing);
    }
    if !header_signature_holds(&fields.signature, &actual_md5) {
        return Err(ContainerError::HeaderSignatureDoesNotVerify);
    }
    Ok(Provenance::HeaderSignatureVerified)
}

fn lowercase_hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut text, byte| {
        use std::fmt::Write as _;
        let _ = write!(text, "{byte:02x}");
        text
    })
}

struct SignatureFields {
    md5: Vec<u8>,
    signature: Vec<u8>,
}

fn read_header(bytes: &[u8]) -> Result<(ContainerHeader, SignatureFields), ContainerError> {
    let text_end = bytes
        .iter()
        .rposition(|byte| !matches!(byte, b' ' | b'\0'))
        .map_or(0, |last| last.saturating_add(1));
    let text = bytes
        .get(..text_end)
        .ok_or(ContainerError::HeaderTooShort)?;
    let fields: Vec<&[u8]> = text.split(|byte| *byte == b':').collect();
    if fields.first() != Some(&HEADER_MAGIC) {
        return Err(ContainerError::NotAContainer);
    }
    if fields.len() < HEADER_FIELD_COUNT {
        return Err(ContainerError::HeaderField {
            field: "field count",
        });
    }
    let number = |index: usize, field: &'static str| {
        fields
            .get(index)
            .and_then(|text| std::str::from_utf8(text).ok())
            .and_then(|text| text.trim_end().parse::<u64>().ok())
            .ok_or(ContainerError::HeaderField { field })
    };
    let small = |index: usize, field: &'static str| {
        u32::try_from(number(index, field)?).map_err(|_| ContainerError::HeaderField { field })
    };
    let header = ContainerHeader {
        version: small(2, "version")?,
        signature_count: small(3, "signature count")?,
        functionality_level: small(4, "functionality level")?,
        build_seconds: number(8, "build time")?,
    };
    let field = |index: usize| {
        fields
            .get(index)
            .map_or_else(Vec::new, |text| text.to_vec())
    };
    Ok((
        header,
        SignatureFields {
            md5: field(5),
            signature: field(6),
        },
    ))
}

fn gunzip(payload: &[u8]) -> Result<Vec<u8>, ContainerError> {
    let mut tar = Vec::new();
    GzDecoder::new(payload)
        .take(LARGEST_PAYLOAD.saturating_add(1))
        .read_to_end(&mut tar)
        .map_err(|error| ContainerError::PayloadNotGzip(error.to_string()))?;
    if u64::try_from(tar.len()).map_or(true, |length| length > LARGEST_PAYLOAD) {
        return Err(ContainerError::PayloadTooLarge);
    }
    Ok(tar)
}

fn tar_members(tar: &[u8]) -> Result<Vec<Member>, ContainerError> {
    let mut members = Vec::new();
    let mut rest = tar;
    while !rest.is_empty() {
        let (block, after) = rest
            .split_at_checked(TAR_BLOCK)
            .ok_or(ContainerError::TarHeaderTruncated)?;
        if block.iter().all(|byte| *byte == 0) {
            break;
        }
        let name_field = block
            .get(TAR_NAME_FIELD)
            .ok_or(ContainerError::TarHeaderTruncated)?;
        let name_length = name_field
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(name_field.len());
        let name =
            String::from_utf8_lossy(name_field.get(..name_length).unwrap_or_default()).into_owned();
        if name.contains('/') {
            return Err(ContainerError::TarMemberInADirectory { member: name });
        }
        if !matches!(block.get(TAR_TYPE_FLAG), Some(b'\0' | b'0')) {
            return Err(ContainerError::TarMemberNotAFile { member: name });
        }
        let size = block.get(TAR_SIZE_FIELD).and_then(octal).ok_or_else(|| {
            ContainerError::TarSizeNotOctal {
                member: name.clone(),
            }
        })?;
        let padded = size.checked_next_multiple_of(TAR_BLOCK).ok_or_else(|| {
            ContainerError::TarMemberTruncated {
                member: name.clone(),
            }
        })?;
        let contents = after
            .get(..size)
            .ok_or_else(|| ContainerError::TarMemberTruncated {
                member: name.clone(),
            })?
            .to_vec();
        rest = after.get(padded..).unwrap_or_default();
        members.push(Member { name, contents });
    }
    Ok(members)
}

fn octal(field: &[u8]) -> Option<usize> {
    let digits: Vec<u8> = field
        .iter()
        .copied()
        .skip_while(|byte| *byte == b' ')
        .take_while(|byte| (b'0'..=b'7').contains(byte))
        .collect();
    if digits.is_empty() {
        return None;
    }
    digits.iter().try_fold(0usize, |value, digit| {
        value
            .checked_mul(8)?
            .checked_add(usize::from(digit.checked_sub(b'0')?))
    })
}

fn read_index(
    contents: &[u8],
    header: &ContainerHeader,
    signed: bool,
) -> Result<Index, ContainerError> {
    let raw_lines: Vec<&[u8]> = contents.split(|byte| *byte == b'\n').collect();
    let mut lines = lines(contents).map(without_line_ending).enumerate();
    let (_, header_line) = lines.next().ok_or(ContainerError::IndexMissing)?;
    let fields: Vec<&[u8]> = header_line.split(|byte| *byte == b':').collect();
    let field = |index: usize| fields.get(index).map(|text| leading_integer(text));
    let agrees = field(2) == Some(i64::from(header.version))
        && field(3) == Some(i64::from(header.signature_count))
        && field(4) == Some(i64::from(header.functionality_level))
        && field(8).is_none_or(|seconds| i64::try_from(header.build_seconds).ok() == Some(seconds));
    if !agrees {
        return Err(ContainerError::IndexHeaderDisagrees);
    }
    let mut listed = Vec::new();
    for (index, line) in lines {
        let line_number = index.saturating_add(1);
        if signed && line.starts_with(INDEX_SIGNATURE_PREFIX) {
            let signed_lines = raw_lines.get(..index).unwrap_or_default();
            let signature = line.get(INDEX_SIGNATURE_PREFIX.len()..).unwrap_or_default();
            if !index_signature_holds(signed_lines, signature) {
                return Err(ContainerError::IndexSignatureDoesNotVerify);
            }
            return Ok(Index { listed });
        }
        let malformed = ContainerError::IndexLineMalformed { line: line_number };
        let parts: Vec<&[u8]> = line.split(|byte| *byte == b':').collect();
        let [name, size, digest] = parts.as_slice() else {
            return Err(malformed);
        };
        if digest.len() != SHA256_HEX_LENGTH
            || size.is_empty()
            || !size.iter().all(u8::is_ascii_digit)
        {
            return Err(malformed);
        }
        let size: u64 = std::str::from_utf8(size)
            .ok()
            .and_then(|size| size.parse().ok())
            .ok_or(malformed.clone())?;
        let digest: [u8; 32] = digest
            .chunks(2)
            .map(|pair| match pair {
                [high, low] => hex_value(*high)?
                    .checked_mul(16)?
                    .checked_add(hex_value(*low)?),
                _ => None,
            })
            .collect::<Option<Vec<u8>>>()
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or(malformed)?;
        listed.push((String::from_utf8_lossy(name).into_owned(), size, digest));
    }
    if signed {
        Err(ContainerError::IndexUnsigned)
    } else {
        Ok(Index { listed })
    }
}
