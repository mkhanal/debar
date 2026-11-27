use std::collections::BTreeMap;

use zerocopy::little_endian::{U16, U32};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::model::{ByteSet, SignatureGroup};
use crate::object_kind::ObjectKind;

const ALWAYS_REPLACES: u8 = 1;
const LEFT_FOR_THE_FULL_SCAN: u8 = 2;
const ENDS_RECOGNITION: u8 = 4;
const EXECUTABLE: u8 = 8;
const OWN_BYTES_MATCHED: u8 = 16;
const RECOGNISES_TYPES_IN_FULL_SCAN: u8 = 32;
const NO_KIND: u16 = 0;
const NOT_NORMALISED: u32 = 0;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KindDescription {
    pub format_name: String,
    pub groups: Vec<SignatureGroup>,
    pub recognition: RecognitionRank,
    pub own_bytes: OwnBytes,
    pub matched_again_as: Option<ObjectKind>,
    pub found_in_full_scan_retypes: Vec<ObjectKind>,
    pub found_at_an_offset: Option<FoundAtAnOffset>,
    pub executable: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FoundAtAnOffset {
    Recorded,
    RetypesTheObject {
        hosts: Hosts,
    },
    Embedded {
        object: EmbeddedObject,
        hosts: Hosts,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Hosts {
    Any,
    OnlyIn(Vec<ObjectKind>),
    NotIn(Vec<ObjectKind>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EmbeddedObject {
    pub scanned_as: ObjectKind,
    pub starts_before_the_match: u16,
    pub recorded_up_to_the_file_count: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OffsetAction {
    Recorded,
    RetypesTheObject,
    Embedded(EmbeddedObject),
}

const NOT_RECORDED: u8 = 0;
const RECORDED: u8 = 1;
const RETYPES_THE_OBJECT: u8 = 2;
const EMBEDDED: u8 = 3;
const CAPPED_BY_THE_TYPING_RULES: u16 = 0;
const CAPPED_BY_THE_FILE_COUNT: u16 = 1;
const ANY_HOST: u8 = 0;
const ONLY_IN_HOSTS: u8 = 1;
const NOT_IN_HOSTS: u8 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RecognitionRank {
    pub priority: u32,
    pub always_replaces: bool,
    pub left_for_the_full_scan: bool,
    pub ends_recognition: bool,
}

impl RecognitionRank {
    #[must_use]
    pub fn replaces(self, winning_priority: Option<u32>) -> bool {
        self.ends_recognition
            || self.always_replaces
            || winning_priority.is_none_or(|priority| self.priority > priority)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OwnBytes {
    NotMatched,
    Matched {
        as_kind: Option<ObjectKind>,
        recognising_types: bool,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WideTextRetry {
    pub found: ObjectKind,
    pub becomes: ObjectKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TypingRules {
    pub prefix_length: u32,
    pub recognition_group: Option<SignatureGroup>,
    pub text_bytes: ByteSet,
    pub wide_text_retry: Option<WideTextRetry>,
    pub most_found_at_offsets: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TextNormalisation {
    pub normalised_in_pieces_of: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KindsNotBuilt {
    TooLarge,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KindsMalformed {
    Layout,
    UnknownKind,
}

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
struct KindsHeader {
    prefix_length: U32,
    has_recognition_group: U32,
    recognition_group: U32,
    text_bytes: [u8; 32],
    wide_text_found: U16,
    wide_text_becomes: U16,
    most_found_at_offsets: U32,
    text_normalised_in_pieces_of: U32,
    kind_count: U32,
    group_count: U32,
    retype_count: U32,
    host_count: U32,
    name_bytes: U32,
}

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned, Clone, Copy)]
#[repr(C)]
struct KindEntry {
    kind: U16,
    matched_as: U16,
    matched_again_as: U16,
    flags: u8,
    reserved: u8,
    priority: U32,
    name_start: U32,
    name_length: U32,
    first_group: U32,
    group_count: U32,
    first_retype: U32,
    retype_count: U32,
    offset_action: u8,
    offset_hosts: u8,
    embedded_as: U16,
    starts_before_the_match: U16,
    offset_cap: U16,
    first_host: U32,
    host_count: U32,
}

fn code_or_none(kind: Option<ObjectKind>) -> u16 {
    kind.map_or(NO_KIND, ObjectKind::code)
}

fn kind_or_none(code: u16) -> Result<Option<ObjectKind>, KindsMalformed> {
    if code == NO_KIND {
        return Ok(None);
    }
    ObjectKind::from_code(code)
        .map(Some)
        .ok_or(KindsMalformed::UnknownKind)
}

fn flags_of(description: &KindDescription) -> u8 {
    let rank = description.recognition;
    let mut flags = 0;
    for (set, flag) in [
        (rank.always_replaces, ALWAYS_REPLACES),
        (rank.left_for_the_full_scan, LEFT_FOR_THE_FULL_SCAN),
        (rank.ends_recognition, ENDS_RECOGNITION),
        (description.executable, EXECUTABLE),
    ] {
        if set {
            flags |= flag;
        }
    }
    if let OwnBytes::Matched {
        recognising_types, ..
    } = description.own_bytes
    {
        flags |= OWN_BYTES_MATCHED;
        if recognising_types {
            flags |= RECOGNISES_TYPES_IN_FULL_SCAN;
        }
    }
    flags
}

struct EncodedOffsetFinding<'d> {
    action: u8,
    hosts: u8,
    embedded: Option<EmbeddedObject>,
    host_kinds: &'d [ObjectKind],
}

impl<'d> EncodedOffsetFinding<'d> {
    fn of(finding: Option<&'d FoundAtAnOffset>) -> Self {
        let (action, embedded, hosts) = match finding {
            None => (NOT_RECORDED, None, None),
            Some(FoundAtAnOffset::Recorded) => (RECORDED, None, None),
            Some(FoundAtAnOffset::RetypesTheObject { hosts }) => {
                (RETYPES_THE_OBJECT, None, Some(hosts))
            }
            Some(FoundAtAnOffset::Embedded { object, hosts }) => {
                (EMBEDDED, Some(*object), Some(hosts))
            }
        };
        let (hosts, host_kinds): (u8, &[ObjectKind]) = match hosts {
            None | Some(Hosts::Any) => (ANY_HOST, &[]),
            Some(Hosts::OnlyIn(kinds)) => (ONLY_IN_HOSTS, kinds),
            Some(Hosts::NotIn(kinds)) => (NOT_IN_HOSTS, kinds),
        };
        Self {
            action,
            hosts,
            embedded,
            host_kinds,
        }
    }
}

pub fn build(
    kinds: &BTreeMap<ObjectKind, KindDescription>,
    typing: Option<TypingRules>,
    text: Option<TextNormalisation>,
) -> Result<Vec<u8>, KindsNotBuilt> {
    let count = |value: usize| u32::try_from(value).map_err(|_| KindsNotBuilt::TooLarge);
    let mut entries = Vec::with_capacity(kinds.len());
    let mut groups: Vec<U32> = Vec::new();
    let mut retypes: Vec<U16> = Vec::new();
    let mut hosts: Vec<U16> = Vec::new();
    let mut names = Vec::new();
    for (kind, description) in kinds {
        let offset = EncodedOffsetFinding::of(description.found_at_an_offset.as_ref());
        let matched_as = match description.own_bytes {
            OwnBytes::Matched { as_kind, .. } => code_or_none(as_kind),
            OwnBytes::NotMatched => NO_KIND,
        };
        entries.push(KindEntry {
            kind: U16::new(kind.code()),
            matched_as: U16::new(matched_as),
            matched_again_as: U16::new(code_or_none(description.matched_again_as)),
            flags: flags_of(description),
            reserved: 0,
            priority: U32::new(description.recognition.priority),
            name_start: U32::new(count(names.len())?),
            name_length: U32::new(count(description.format_name.len())?),
            first_group: U32::new(count(groups.len())?),
            group_count: U32::new(count(description.groups.len())?),
            first_retype: U32::new(count(retypes.len())?),
            retype_count: U32::new(count(description.found_in_full_scan_retypes.len())?),
            offset_action: offset.action,
            offset_hosts: offset.hosts,
            embedded_as: U16::new(code_or_none(
                offset.embedded.map(|object| object.scanned_as),
            )),
            starts_before_the_match: U16::new(
                offset
                    .embedded
                    .map_or(0, |object| object.starts_before_the_match),
            ),
            offset_cap: U16::new(
                if offset
                    .embedded
                    .is_some_and(|object| object.recorded_up_to_the_file_count)
                {
                    CAPPED_BY_THE_FILE_COUNT
                } else {
                    CAPPED_BY_THE_TYPING_RULES
                },
            ),
            first_host: U32::new(count(hosts.len())?),
            host_count: U32::new(count(offset.host_kinds.len())?),
        });
        names.extend_from_slice(description.format_name.as_bytes());
        groups.extend(description.groups.iter().map(|group| U32::new(group.0)));
        retypes.extend(
            description
                .found_in_full_scan_retypes
                .iter()
                .map(|kind| U16::new(kind.code())),
        );
        hosts.extend(offset.host_kinds.iter().map(|kind| U16::new(kind.code())));
    }
    let retry = typing.and_then(|rules| rules.wide_text_retry);
    let header = KindsHeader {
        prefix_length: U32::new(typing.map_or(0, |rules| rules.prefix_length)),
        has_recognition_group: U32::new(u32::from(
            typing.is_some_and(|rules| rules.recognition_group.is_some()),
        )),
        recognition_group: U32::new(
            typing
                .and_then(|rules| rules.recognition_group)
                .map_or(0, |group| group.0),
        ),
        text_bytes: typing.map_or([0; 32], |rules| rules.text_bytes.0),
        wide_text_found: U16::new(code_or_none(retry.map(|retry| retry.found))),
        wide_text_becomes: U16::new(code_or_none(retry.map(|retry| retry.becomes))),
        most_found_at_offsets: U32::new(typing.map_or(0, |rules| rules.most_found_at_offsets)),
        text_normalised_in_pieces_of: U32::new(
            text.map_or(NOT_NORMALISED, |text| text.normalised_in_pieces_of),
        ),
        kind_count: U32::new(count(entries.len())?),
        group_count: U32::new(count(groups.len())?),
        retype_count: U32::new(count(retypes.len())?),
        host_count: U32::new(count(hosts.len())?),
        name_bytes: U32::new(count(names.len())?),
    };
    let mut bytes = header.as_bytes().to_vec();
    bytes.extend_from_slice(entries.as_bytes());
    bytes.extend_from_slice(groups.as_bytes());
    bytes.extend_from_slice(retypes.as_bytes());
    bytes.extend_from_slice(hosts.as_bytes());
    bytes.extend_from_slice(&names);
    Ok(bytes)
}

#[derive(Clone, Copy)]
pub struct ObjectKinds<'m> {
    typing: TypingRules,
    text: Option<TextNormalisation>,
    entries: &'m [KindEntry],
    groups: &'m [U32],
    retypes: &'m [U16],
    hosts: &'m [U16],
    names: &'m [u8],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KindView<'m> {
    pub format_name: &'m str,
    pub recognition: RecognitionRank,
    pub own_bytes: OwnBytes,
    pub matched_again_as: Option<ObjectKind>,
    pub offset_action: Option<OffsetAction>,
    pub executable: bool,
    groups: &'m [U32],
    retypes: &'m [U16],
    offset_hosts: HostsView<'m>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HostsView<'m> {
    Any,
    OnlyIn(&'m [U16]),
    NotIn(&'m [U16]),
}

impl KindView<'_> {
    pub fn groups(&self) -> impl Iterator<Item = SignatureGroup> + '_ {
        self.groups.iter().map(|group| SignatureGroup(group.get()))
    }

    #[must_use]
    pub fn retypes_when_found_in(&self, kind: ObjectKind) -> bool {
        self.retypes.iter().any(|code| code.get() == kind.code())
    }

    #[must_use]
    pub fn acts_in(&self, host: ObjectKind) -> bool {
        let listed = |kinds: &[U16]| kinds.iter().any(|code| code.get() == host.code());
        match self.offset_hosts {
            HostsView::Any => true,
            HostsView::OnlyIn(kinds) => listed(kinds),
            HostsView::NotIn(kinds) => !listed(kinds),
        }
    }
}

fn span(start: U32, length: U32) -> Result<std::ops::Range<usize>, KindsMalformed> {
    let start = usize::try_from(start.get()).map_err(|_| KindsMalformed::Layout)?;
    let length = usize::try_from(length.get()).map_err(|_| KindsMalformed::Layout)?;
    Ok(start..start.checked_add(length).ok_or(KindsMalformed::Layout)?)
}

impl<'m> ObjectKinds<'m> {
    pub fn read(bytes: &'m [u8]) -> Result<Self, KindsMalformed> {
        let (header, rest) =
            KindsHeader::ref_from_prefix(bytes).map_err(|_| KindsMalformed::Layout)?;
        let length = |value: &U32| usize::try_from(value.get()).map_err(|_| KindsMalformed::Layout);
        let (entries, rest) =
            <[KindEntry]>::ref_from_prefix_with_elems(rest, length(&header.kind_count)?)
                .map_err(|_| KindsMalformed::Layout)?;
        let (groups, rest) =
            <[U32]>::ref_from_prefix_with_elems(rest, length(&header.group_count)?)
                .map_err(|_| KindsMalformed::Layout)?;
        let (retypes, rest) =
            <[U16]>::ref_from_prefix_with_elems(rest, length(&header.retype_count)?)
                .map_err(|_| KindsMalformed::Layout)?;
        let (hosts, names) = <[U16]>::ref_from_prefix_with_elems(rest, length(&header.host_count)?)
            .map_err(|_| KindsMalformed::Layout)?;
        if names.len() != length(&header.name_bytes)? {
            return Err(KindsMalformed::Layout);
        }
        let recognition_group = (header.has_recognition_group.get() != 0)
            .then(|| SignatureGroup(header.recognition_group.get()));
        let wide_text_retry = match (
            kind_or_none(header.wide_text_found.get())?,
            kind_or_none(header.wide_text_becomes.get())?,
        ) {
            (Some(found), Some(becomes)) => Some(WideTextRetry { found, becomes }),
            _ => None,
        };
        Ok(Self {
            typing: TypingRules {
                prefix_length: header.prefix_length.get(),
                recognition_group,
                text_bytes: ByteSet(header.text_bytes),
                wide_text_retry,
                most_found_at_offsets: header.most_found_at_offsets.get(),
            },
            text: match header.text_normalised_in_pieces_of.get() {
                NOT_NORMALISED => None,
                normalised_in_pieces_of => Some(TextNormalisation {
                    normalised_in_pieces_of,
                }),
            },
            entries,
            groups,
            retypes,
            hosts,
            names,
        })
    }

    #[must_use]
    pub fn typing_rules(&self) -> TypingRules {
        self.typing
    }

    #[must_use]
    pub const fn text_normalisation(&self) -> Option<TextNormalisation> {
        self.text
    }

    pub fn describe(&self, kind: ObjectKind) -> Result<Option<KindView<'m>>, KindsMalformed> {
        let Ok(index) = self
            .entries
            .binary_search_by_key(&kind.code(), |entry| entry.kind.get())
        else {
            return Ok(None);
        };
        let entry = self.entries.get(index).ok_or(KindsMalformed::Layout)?;
        let format_name = self
            .names
            .get(span(entry.name_start, entry.name_length)?)
            .and_then(|name| std::str::from_utf8(name).ok())
            .ok_or(KindsMalformed::Layout)?;
        let groups = self
            .groups
            .get(span(entry.first_group, entry.group_count)?)
            .ok_or(KindsMalformed::Layout)?;
        let retypes = self
            .retypes
            .get(span(entry.first_retype, entry.retype_count)?)
            .ok_or(KindsMalformed::Layout)?;
        let host_kinds = self
            .hosts
            .get(span(entry.first_host, entry.host_count)?)
            .ok_or(KindsMalformed::Layout)?;
        let offset_hosts = match entry.offset_hosts {
            ANY_HOST => HostsView::Any,
            ONLY_IN_HOSTS => HostsView::OnlyIn(host_kinds),
            NOT_IN_HOSTS => HostsView::NotIn(host_kinds),
            _ => return Err(KindsMalformed::Layout),
        };
        let offset_action = match entry.offset_action {
            NOT_RECORDED => None,
            RECORDED => Some(OffsetAction::Recorded),
            RETYPES_THE_OBJECT => Some(OffsetAction::RetypesTheObject),
            EMBEDDED => Some(OffsetAction::Embedded(EmbeddedObject {
                scanned_as: kind_or_none(entry.embedded_as.get())?.ok_or(KindsMalformed::Layout)?,
                starts_before_the_match: entry.starts_before_the_match.get(),
                recorded_up_to_the_file_count: match entry.offset_cap.get() {
                    CAPPED_BY_THE_TYPING_RULES => false,
                    CAPPED_BY_THE_FILE_COUNT => true,
                    _ => return Err(KindsMalformed::Layout),
                },
            })),
            _ => return Err(KindsMalformed::Layout),
        };
        let flag = |flag: u8| entry.flags & flag != 0;
        let own_bytes = if flag(OWN_BYTES_MATCHED) {
            OwnBytes::Matched {
                as_kind: kind_or_none(entry.matched_as.get())?,
                recognising_types: flag(RECOGNISES_TYPES_IN_FULL_SCAN),
            }
        } else {
            OwnBytes::NotMatched
        };
        Ok(Some(KindView {
            format_name,
            recognition: RecognitionRank {
                priority: entry.priority.get(),
                always_replaces: flag(ALWAYS_REPLACES),
                left_for_the_full_scan: flag(LEFT_FOR_THE_FULL_SCAN),
                ends_recognition: flag(ENDS_RECOGNITION),
            },
            own_bytes,
            matched_again_as: kind_or_none(entry.matched_again_as.get())?,
            offset_action,
            executable: flag(EXECUTABLE),
            groups,
            retypes,
            offset_hosts,
        }))
    }

    pub fn described(&self) -> impl Iterator<Item = Result<ObjectKind, KindsMalformed>> + 'm {
        self.entries
            .iter()
            .map(|entry| ObjectKind::from_code(entry.kind.get()).ok_or(KindsMalformed::UnknownKind))
    }
}
