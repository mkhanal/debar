use debar_image::{
    ByteSet, EmbeddedObject, EngineFeature, FoundAtAnOffset, Hosts, ImageBuilder, KindDescription,
    ObjectKind, OwnBytes, RecognitionRank, SignatureGroup, TypingRules, WideTextRetry,
};

pub const GENERIC_GROUP: SignatureGroup = SignatureGroup(0);
pub const TYPE_RECOGNITION_GROUP: SignatureGroup = SignatureGroup(15);
pub const TEXT_TARGET_GROUP: SignatureGroup = SignatureGroup(7);
const WEB_PAGE_GROUP: SignatureGroup = SignatureGroup(3);
pub const GROUPS_MATCHED_AGAINST_NORMALISED_TEXT: [SignatureGroup; 2] =
    [WEB_PAGE_GROUP, TEXT_TARGET_GROUP];
const TYPING_PREFIX_LENGTH: u32 = 1024;
const MOST_FOUND_AT_OFFSETS: u32 = 10;
const FIRST_ALWAYS_REPLACING_NUMBER: u32 = 563;
const BYTES_NEVER_IN_TEXT: [(u8, u8); 5] = [
    (0x00, 0x06),
    (0x0b, 0x0b),
    (0x0e, 0x1a),
    (0x1c, 0x1f),
    (0x7f, 0x7f),
];

const TYPE_NUMBERS: [(&str, ObjectKind, u32); 89] = [
    ("CL_TYPE_ANY", ObjectKind::Untyped, 0),
    ("CL_TYPE_TEXT_ASCII", ObjectKind::Text, 500),
    ("CL_TYPE_TEXT_UTF8", ObjectKind::TextUtf8, 501),
    (
        "CL_TYPE_TEXT_UTF16LE",
        ObjectKind::TextUtf16LittleEndian,
        502,
    ),
    ("CL_TYPE_TEXT_UTF16BE", ObjectKind::TextUtf16BigEndian, 503),
    ("CL_TYPE_BINARY_DATA", ObjectKind::BinaryData, 504),
    ("CL_TYPE_ERROR", ObjectKind::Unreadable, 505),
    ("CL_TYPE_MSEXE", ObjectKind::WindowsExecutable, 506),
    ("CL_TYPE_ELF", ObjectKind::Elf, 507),
    ("CL_TYPE_MACHO", ObjectKind::MachO, 508),
    ("CL_TYPE_MACHO_UNIBIN", ObjectKind::MachOUniversal, 509),
    ("CL_TYPE_POSIX_TAR", ObjectKind::PosixTar, 510),
    ("CL_TYPE_OLD_TAR", ObjectKind::OldTar, 511),
    ("CL_TYPE_CPIO_OLD", ObjectKind::CpioOld, 512),
    ("CL_TYPE_CPIO_ODC", ObjectKind::CpioOdc, 513),
    ("CL_TYPE_CPIO_NEWC", ObjectKind::CpioNewc, 514),
    ("CL_TYPE_CPIO_CRC", ObjectKind::CpioCrc, 515),
    ("CL_TYPE_GZ", ObjectKind::Gzip, 516),
    ("CL_TYPE_ZIP", ObjectKind::Zip, 517),
    ("CL_TYPE_BZ", ObjectKind::Bzip2, 518),
    ("CL_TYPE_RAR", ObjectKind::Rar, 519),
    ("CL_TYPE_ARJ", ObjectKind::Arj, 520),
    ("CL_TYPE_MSSZDD", ObjectKind::MicrosoftSzdd, 521),
    ("CL_TYPE_MSOLE2", ObjectKind::Ole2, 522),
    ("CL_TYPE_MSCAB", ObjectKind::MicrosoftCabinet, 523),
    ("CL_TYPE_MSCHM", ObjectKind::MicrosoftHelp, 524),
    ("CL_TYPE_SIS", ObjectKind::SymbianInstaller, 525),
    ("CL_TYPE_SCRENC", ObjectKind::ScriptEncoded, 526),
    ("CL_TYPE_GRAPHICS", ObjectKind::Graphics, 527),
    ("CL_TYPE_GIF", ObjectKind::Gif, 528),
    ("CL_TYPE_PNG", ObjectKind::Png, 529),
    ("CL_TYPE_JPEG", ObjectKind::Jpeg, 530),
    ("CL_TYPE_TIFF", ObjectKind::Tiff, 531),
    ("CL_TYPE_RIFF", ObjectKind::Riff, 532),
    ("CL_TYPE_BINHEX", ObjectKind::BinHex, 533),
    ("CL_TYPE_TNEF", ObjectKind::Tnef, 534),
    ("CL_TYPE_CRYPTFF", ObjectKind::CryptFf, 535),
    ("CL_TYPE_PDF", ObjectKind::Pdf, 536),
    ("CL_TYPE_UUENCODED", ObjectKind::Uuencoded, 537),
    ("CL_TYPE_SCRIPT", ObjectKind::Script, 538),
    ("CL_TYPE_HTML_UTF16", ObjectKind::HtmlUtf16, 539),
    ("CL_TYPE_RTF", ObjectKind::RichText, 540),
    ("CL_TYPE_7Z", ObjectKind::SevenZip, 541),
    ("CL_TYPE_SWF", ObjectKind::Flash, 542),
    ("CL_TYPE_JAVA", ObjectKind::JavaClass, 543),
    ("CL_TYPE_XAR", ObjectKind::Xar, 544),
    ("CL_TYPE_XZ", ObjectKind::Xz, 545),
    ("CL_TYPE_OOXML_WORD", ObjectKind::OfficeOpenWord, 546),
    ("CL_TYPE_OOXML_PPT", ObjectKind::OfficeOpenPresentation, 547),
    ("CL_TYPE_OOXML_XL", ObjectKind::OfficeOpenSpreadsheet, 548),
    ("CL_TYPE_INTERNAL", ObjectKind::ScannerMetadata, 549),
    ("CL_TYPE_HWP3", ObjectKind::Hangul3, 550),
    ("CL_TYPE_OOXML_HWP", ObjectKind::HangulOpen, 551),
    ("CL_TYPE_PS", ObjectKind::PostScript, 552),
    ("CL_TYPE_EGG", ObjectKind::Egg, 553),
    ("CL_TYPE_ONENOTE", ObjectKind::OneNote, 554),
    ("CL_TYPE_PYTHON_COMPILED", ObjectKind::PythonCompiled, 555),
    ("CL_TYPE_LHA_LZH", ObjectKind::Lha, 556),
    ("CL_TYPE_AI_MODEL", ObjectKind::AiModel, 557),
    ("CL_TYPE_PART_ANY", ObjectKind::AnyPartition, 558),
    ("CL_TYPE_PART_HFSPLUS", ObjectKind::HfsPlusPartition, 559),
    ("CL_TYPE_MBR", ObjectKind::MasterBootRecord, 560),
    ("CL_TYPE_HTML", ObjectKind::Html, 561),
    ("CL_TYPE_MAIL", ObjectKind::Mail, 562),
    ("CL_TYPE_SFX", ObjectKind::SelfExtracting, 563),
    ("CL_TYPE_ZIPSFX", ObjectKind::ZipSelfExtracting, 564),
    ("CL_TYPE_RARSFX", ObjectKind::RarSelfExtracting, 565),
    ("CL_TYPE_7ZSFX", ObjectKind::SevenZipSelfExtracting, 566),
    ("CL_TYPE_CABSFX", ObjectKind::CabinetSelfExtracting, 567),
    ("CL_TYPE_ARJSFX", ObjectKind::ArjSelfExtracting, 568),
    ("CL_TYPE_EGGSFX", ObjectKind::EggSelfExtracting, 569),
    ("CL_TYPE_NULSFT", ObjectKind::NullsoftInstaller, 570),
    ("CL_TYPE_AUTOIT", ObjectKind::AutoIt, 571),
    ("CL_TYPE_ISHIELD_MSI", ObjectKind::InstallShieldMsi, 572),
    ("CL_TYPE_ISO9660", ObjectKind::Iso9660, 573),
    ("CL_TYPE_DMG", ObjectKind::AppleDiskImage, 574),
    ("CL_TYPE_GPT", ObjectKind::GuidPartitionTable, 575),
    ("CL_TYPE_APM", ObjectKind::ApplePartitionMap, 576),
    ("CL_TYPE_XDP", ObjectKind::XmlDataPackage, 577),
    ("CL_TYPE_XML_WORD", ObjectKind::XmlWord, 578),
    ("CL_TYPE_XML_XL", ObjectKind::XmlSpreadsheet, 579),
    ("CL_TYPE_XML_HWP", ObjectKind::XmlHangul, 580),
    ("CL_TYPE_HWPOLE2", ObjectKind::HangulOle2, 581),
    ("CL_TYPE_MHTML", ObjectKind::Mhtml, 582),
    ("CL_TYPE_LNK", ObjectKind::WindowsShortcut, 583),
    ("CL_TYPE_UDF", ObjectKind::Udf, 584),
    ("CL_TYPE_ALZ", ObjectKind::Alz, 585),
    ("CL_TYPE_OTHER", ObjectKind::Other, 586),
    ("CL_TYPE_IGNORED", ObjectKind::Ignored, 587),
];

const TARGET_GROUPS: [(ObjectKind, SignatureGroup); 19] = [
    (ObjectKind::WindowsExecutable, SignatureGroup(1)),
    (ObjectKind::Ole2, SignatureGroup(2)),
    (ObjectKind::Html, WEB_PAGE_GROUP),
    (ObjectKind::Mail, SignatureGroup(4)),
    (ObjectKind::Graphics, SignatureGroup(5)),
    (ObjectKind::Gif, SignatureGroup(5)),
    (ObjectKind::Png, SignatureGroup(5)),
    (ObjectKind::Jpeg, SignatureGroup(5)),
    (ObjectKind::Tiff, SignatureGroup(5)),
    (ObjectKind::Elf, SignatureGroup(6)),
    (ObjectKind::Text, TEXT_TARGET_GROUP),
    (ObjectKind::Unreadable, SignatureGroup(8)),
    (ObjectKind::MachO, SignatureGroup(9)),
    (ObjectKind::MachOUniversal, SignatureGroup(9)),
    (ObjectKind::Pdf, SignatureGroup(10)),
    (ObjectKind::Flash, SignatureGroup(11)),
    (ObjectKind::JavaClass, SignatureGroup(12)),
    (ObjectKind::ScannerMetadata, SignatureGroup(13)),
    (ObjectKind::Other, SignatureGroup(14)),
];

const ALSO_ALWAYS_REPLACING: [ObjectKind; 1] = [ObjectKind::WindowsExecutable];

const LEFT_FOR_THE_FULL_SCAN: [ObjectKind; 6] = [
    ObjectKind::ZipSelfExtracting,
    ObjectKind::ArjSelfExtracting,
    ObjectKind::RarSelfExtracting,
    ObjectKind::EggSelfExtracting,
    ObjectKind::CabinetSelfExtracting,
    ObjectKind::SevenZipSelfExtracting,
];

const ENDING_RECOGNITION: [ObjectKind; 1] = [ObjectKind::Ignored];

const EXECUTABLES: [ObjectKind; 4] = [
    ObjectKind::WindowsExecutable,
    ObjectKind::Elf,
    ObjectKind::MachO,
    ObjectKind::MachOUniversal,
];

const OWN_BYTES_NOT_MATCHED: [ObjectKind; 2] = [ObjectKind::Html, ObjectKind::Ignored];

const NOT_RECOGNISING_TYPES_IN_FULL_SCAN: [ObjectKind; 11] = [
    ObjectKind::Gzip,
    ObjectKind::CpioOld,
    ObjectKind::Zip,
    ObjectKind::OfficeOpenWord,
    ObjectKind::OfficeOpenPresentation,
    ObjectKind::OfficeOpenSpreadsheet,
    ObjectKind::HangulOpen,
    ObjectKind::PosixTar,
    ObjectKind::OldTar,
    ObjectKind::Tnef,
    ObjectKind::AnyPartition,
];

const MATCHED_AS: [(ObjectKind, ObjectKind); 1] = [(ObjectKind::Text, ObjectKind::Untyped)];

const MATCHED_AGAIN_AS: [(ObjectKind, ObjectKind); 3] = [
    (ObjectKind::BinaryData, ObjectKind::Other),
    (ObjectKind::PythonCompiled, ObjectKind::Other),
    (ObjectKind::AiModel, ObjectKind::Other),
];

const RETYPED_WHEN_FOUND: [(ObjectKind, &[ObjectKind]); 2] = [
    (ObjectKind::Html, &[ObjectKind::Text, ObjectKind::Gif]),
    (ObjectKind::Mail, &[ObjectKind::Text]),
];

const MASTER_BOOT_RECORD_NUMBER: u32 = 560;
const LAST_NUMBER_RECORDED_AT_AN_OFFSET: u32 = 585;
const NULLSOFT_MARK_FOLLOWS_ITS_START_BY: u16 = 4;

const TEXT_OR_BINARY_DATA: [ObjectKind; 5] = [
    ObjectKind::Text,
    ObjectKind::TextUtf8,
    ObjectKind::TextUtf16LittleEndian,
    ObjectKind::TextUtf16BigEndian,
    ObjectKind::BinaryData,
];

#[derive(Clone, Copy)]
enum ActionAtAnOffset {
    RetypesAnyObject,
    RetypesTextOrBinaryData,
    EmbeddedOutsideItsOwnKind(ObjectKind),
    EachRecordEmbeddedOutsideItsOwnKind(ObjectKind),
    EmbeddedInAnExecutable { starts_before_the_match: u16 },
}

const ACTIONS_AT_AN_OFFSET: [(ObjectKind, EngineFeature, ActionAtAnOffset); 15] = [
    (
        ObjectKind::Mhtml,
        EngineFeature::MailMbox,
        ActionAtAnOffset::RetypesTextOrBinaryData,
    ),
    (
        ObjectKind::XmlDataPackage,
        EngineFeature::DocumentPdf,
        ActionAtAnOffset::RetypesTextOrBinaryData,
    ),
    (
        ObjectKind::XmlWord,
        EngineFeature::DocumentMsXml,
        ActionAtAnOffset::RetypesTextOrBinaryData,
    ),
    (
        ObjectKind::XmlSpreadsheet,
        EngineFeature::DocumentMsXml,
        ActionAtAnOffset::RetypesTextOrBinaryData,
    ),
    (
        ObjectKind::XmlHangul,
        EngineFeature::DocumentHwp,
        ActionAtAnOffset::RetypesTextOrBinaryData,
    ),
    (
        ObjectKind::AppleDiskImage,
        EngineFeature::ArchiveDmg,
        ActionAtAnOffset::RetypesAnyObject,
    ),
    (
        ObjectKind::Iso9660,
        EngineFeature::ArchiveIso9660,
        ActionAtAnOffset::RetypesAnyObject,
    ),
    (
        ObjectKind::Udf,
        EngineFeature::ArchiveUdf,
        ActionAtAnOffset::RetypesAnyObject,
    ),
    (
        ObjectKind::ZipSelfExtracting,
        EngineFeature::ArchiveZip,
        ActionAtAnOffset::EachRecordEmbeddedOutsideItsOwnKind(ObjectKind::Zip),
    ),
    (
        ObjectKind::RarSelfExtracting,
        EngineFeature::ArchiveRar,
        ActionAtAnOffset::EmbeddedOutsideItsOwnKind(ObjectKind::Rar),
    ),
    (
        ObjectKind::EggSelfExtracting,
        EngineFeature::ArchiveEgg,
        ActionAtAnOffset::EmbeddedOutsideItsOwnKind(ObjectKind::Egg),
    ),
    (
        ObjectKind::SevenZipSelfExtracting,
        EngineFeature::ArchiveSevenZip,
        ActionAtAnOffset::EmbeddedOutsideItsOwnKind(ObjectKind::SevenZip),
    ),
    (
        ObjectKind::NullsoftInstaller,
        EngineFeature::ArchiveNsis,
        ActionAtAnOffset::EmbeddedInAnExecutable {
            starts_before_the_match: NULLSOFT_MARK_FOLLOWS_ITS_START_BY,
        },
    ),
    (
        ObjectKind::AutoIt,
        EngineFeature::ArchiveAutoIt,
        ActionAtAnOffset::EmbeddedInAnExecutable {
            starts_before_the_match: 0,
        },
    ),
    (
        ObjectKind::InstallShieldMsi,
        EngineFeature::ArchiveInstallShield,
        ActionAtAnOffset::EmbeddedInAnExecutable {
            starts_before_the_match: 0,
        },
    ),
];

fn action_at_an_offset(kind: ObjectKind, enabled: &[EngineFeature]) -> Option<ActionAtAnOffset> {
    ACTIONS_AT_AN_OFFSET
        .into_iter()
        .find(|(found, _, _)| *found == kind)
        .filter(|(_, gate, _)| enabled.contains(gate))
        .map(|(_, _, action)| action)
}

fn found_at_an_offset(
    kind: ObjectKind,
    number: u32,
    enabled: &[EngineFeature],
) -> Option<FoundAtAnOffset> {
    let recorded = number == MASTER_BOOT_RECORD_NUMBER
        || (FIRST_ALWAYS_REPLACING_NUMBER..=LAST_NUMBER_RECORDED_AT_AN_OFFSET).contains(&number);
    if !recorded {
        return None;
    }
    Some(match action_at_an_offset(kind, enabled) {
        None => FoundAtAnOffset::Recorded,
        Some(ActionAtAnOffset::RetypesAnyObject) => {
            FoundAtAnOffset::RetypesTheObject { hosts: Hosts::Any }
        }
        Some(ActionAtAnOffset::RetypesTextOrBinaryData) => FoundAtAnOffset::RetypesTheObject {
            hosts: Hosts::OnlyIn(TEXT_OR_BINARY_DATA.to_vec()),
        },
        Some(ActionAtAnOffset::EmbeddedOutsideItsOwnKind(scanned_as)) => {
            FoundAtAnOffset::Embedded {
                object: EmbeddedObject {
                    scanned_as,
                    starts_before_the_match: 0,
                    recorded_up_to_the_file_count: false,
                },
                hosts: Hosts::NotIn(vec![scanned_as]),
            }
        }
        Some(ActionAtAnOffset::EachRecordEmbeddedOutsideItsOwnKind(scanned_as)) => {
            FoundAtAnOffset::Embedded {
                object: EmbeddedObject {
                    scanned_as,
                    starts_before_the_match: 0,
                    recorded_up_to_the_file_count: true,
                },
                hosts: Hosts::NotIn(vec![scanned_as]),
            }
        }
        Some(ActionAtAnOffset::EmbeddedInAnExecutable {
            starts_before_the_match,
        }) => FoundAtAnOffset::Embedded {
            object: EmbeddedObject {
                scanned_as: kind,
                starts_before_the_match,
                recorded_up_to_the_file_count: false,
            },
            hosts: Hosts::OnlyIn(vec![ObjectKind::WindowsExecutable]),
        },
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NamedType {
    AnyType,
    Kind(ObjectKind),
}

pub fn type_named(name: &str) -> Option<NamedType> {
    TYPE_NUMBERS
        .iter()
        .find(|(known, _, _)| *known == name)
        .map(|(_, kind, _)| {
            if *kind == ObjectKind::Untyped {
                NamedType::AnyType
            } else {
                NamedType::Kind(*kind)
            }
        })
}

pub fn describe_object_kinds(image: &mut ImageBuilder, enabled: &[EngineFeature]) {
    for (name, kind, number) in TYPE_NUMBERS {
        image.describe_object_kind(kind, description(name, kind, number, enabled));
    }
    image.set_typing(TypingRules {
        prefix_length: TYPING_PREFIX_LENGTH,
        recognition_group: Some(TYPE_RECOGNITION_GROUP),
        text_bytes: ByteSet::of((0..=u8::MAX).filter(|byte| {
            !BYTES_NEVER_IN_TEXT
                .iter()
                .any(|(first, last)| (*first..=*last).contains(byte))
        })),
        wide_text_retry: Some(WideTextRetry {
            found: ObjectKind::Html,
            becomes: ObjectKind::HtmlUtf16,
        }),
        most_found_at_offsets: MOST_FOUND_AT_OFFSETS,
    });
}

fn description(
    name: &str,
    kind: ObjectKind,
    number: u32,
    enabled: &[EngineFeature],
) -> KindDescription {
    let target = TARGET_GROUPS
        .iter()
        .find(|(targeted, _)| *targeted == kind)
        .map(|(_, group)| *group);
    let own_bytes = if OWN_BYTES_NOT_MATCHED.contains(&kind) {
        OwnBytes::NotMatched
    } else {
        OwnBytes::Matched {
            as_kind: MATCHED_AS
                .iter()
                .find(|(matched, _)| *matched == kind)
                .map(|(_, as_kind)| *as_kind),
            recognising_types: !NOT_RECOGNISING_TYPES_IN_FULL_SCAN.contains(&kind),
        }
    };
    KindDescription {
        format_name: name.to_owned(),
        groups: target.into_iter().chain([GENERIC_GROUP]).collect(),
        recognition: RecognitionRank {
            priority: number,
            always_replaces: number >= FIRST_ALWAYS_REPLACING_NUMBER
                || ALSO_ALWAYS_REPLACING.contains(&kind),
            left_for_the_full_scan: LEFT_FOR_THE_FULL_SCAN.contains(&kind),
            ends_recognition: ENDING_RECOGNITION.contains(&kind),
        },
        own_bytes,
        matched_again_as: MATCHED_AGAIN_AS
            .iter()
            .find(|(matched, _)| *matched == kind)
            .map(|(_, again_as)| *again_as),
        found_in_full_scan_retypes: RETYPED_WHEN_FOUND
            .iter()
            .find(|(found, _)| *found == kind)
            .map_or_else(Vec::new, |(_, retyped)| retyped.to_vec()),
        found_at_an_offset: found_at_an_offset(kind, number, enabled),
        executable: EXECUTABLES.contains(&kind),
    }
}
