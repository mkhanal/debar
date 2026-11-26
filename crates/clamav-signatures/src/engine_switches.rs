use std::fmt;

use debar_image::EngineFeature;

use crate::FUNCTIONALITY_LEVEL;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SwitchModule {
    Executable,
    Elf,
    MachO,
    Archive,
    Document,
    Mail,
    Other,
    Phishing,
    Programs,
    Statistics,
    RegularExpressions,
}

const MODULES: [(&[u8], SwitchModule, u32); 11] = [
    (b"PE:", SwitchModule::Executable, 0x000F_FF7F),
    (b"ELF:", SwitchModule::Elf, 0x1),
    (b"MACHO:", SwitchModule::MachO, 0x1),
    (b"ARCHIVE:", SwitchModule::Archive, 0x3FFF_FFFF),
    (b"DOCUMENT:", SwitchModule::Document, 0x7FF),
    (b"MAIL:", SwitchModule::Mail, 0x3),
    (b"OTHER:", SwitchModule::Other, 0x7FBF),
    (b"PHISHING:", SwitchModule::Phishing, 0x3),
    (b"BYTECODE:", SwitchModule::Programs, 0x7),
    (b"STATS:", SwitchModule::Statistics, 0x0),
    (b"PCRE:", SwitchModule::RegularExpressions, 0x7),
];

pub const CERTIFICATES: (SwitchModule, u32) = (SwitchModule::Executable, 0x2_0000);
pub const PHISHING_ENGINE: (SwitchModule, u32) = (SwitchModule::Phishing, 0x1);
const PROGRAM_ENGINES: u32 = 0xF;

const FEATURES: [(SwitchModule, u32, EngineFeature); 91] = [
    (
        SwitchModule::Executable,
        0x1,
        EngineFeature::ExecutablePariteCheck,
    ),
    (
        SwitchModule::Executable,
        0x2,
        EngineFeature::ExecutableKrizCheck,
    ),
    (
        SwitchModule::Executable,
        0x4,
        EngineFeature::ExecutableMagistrCheck,
    ),
    (
        SwitchModule::Executable,
        0x8,
        EngineFeature::ExecutablePoliposCheck,
    ),
    (
        SwitchModule::Executable,
        0x10,
        EngineFeature::ExecutableSectionHashes,
    ),
    (SwitchModule::Executable, 0x20, EngineFeature::UnpackUpx),
    (SwitchModule::Executable, 0x40, EngineFeature::UnpackFsg),
    (
        SwitchModule::Executable,
        0x80,
        EngineFeature::ExecutableSwizzorCheck,
    ),
    (SwitchModule::Executable, 0x100, EngineFeature::UnpackPetite),
    (SwitchModule::Executable, 0x200, EngineFeature::UnpackPespin),
    (SwitchModule::Executable, 0x400, EngineFeature::UnpackYc),
    (SwitchModule::Executable, 0x800, EngineFeature::UnpackWwpack),
    (
        SwitchModule::Executable,
        0x1000,
        EngineFeature::UnpackNspack,
    ),
    (SwitchModule::Executable, 0x2000, EngineFeature::UnpackMew),
    (SwitchModule::Executable, 0x4000, EngineFeature::UnpackUpack),
    (
        SwitchModule::Executable,
        0x8000,
        EngineFeature::UnpackAspack,
    ),
    (
        SwitchModule::Executable,
        0x1_0000,
        EngineFeature::ExecutableCatalogs,
    ),
    (
        SwitchModule::Executable,
        0x2_0000,
        EngineFeature::ExecutableCertificates,
    ),
    (
        SwitchModule::Executable,
        0x4_0000,
        EngineFeature::ExecutableIcons,
    ),
    (
        SwitchModule::Executable,
        0x8_0000,
        EngineFeature::ExecutableImportHashes,
    ),
    (SwitchModule::Elf, 0x1, EngineFeature::ElfParsing),
    (SwitchModule::MachO, 0x1, EngineFeature::MachOParsing),
    (SwitchModule::Archive, 0x1, EngineFeature::ArchiveRar),
    (SwitchModule::Archive, 0x2, EngineFeature::ArchiveZip),
    (SwitchModule::Archive, 0x4, EngineFeature::ArchiveGzip),
    (SwitchModule::Archive, 0x8, EngineFeature::ArchiveBzip2),
    (SwitchModule::Archive, 0x10, EngineFeature::ArchiveSzdd),
    (SwitchModule::Archive, 0x20, EngineFeature::ArchiveCab),
    (SwitchModule::Archive, 0x40, EngineFeature::ArchiveChm),
    (SwitchModule::Archive, 0x80, EngineFeature::ArchiveOle2),
    (SwitchModule::Archive, 0x100, EngineFeature::ArchiveTar),
    (SwitchModule::Archive, 0x200, EngineFeature::ArchiveBinhex),
    (SwitchModule::Archive, 0x400, EngineFeature::ArchiveSis),
    (SwitchModule::Archive, 0x800, EngineFeature::ArchiveNsis),
    (SwitchModule::Archive, 0x1000, EngineFeature::ArchiveArj),
    (SwitchModule::Archive, 0x2000, EngineFeature::ArchiveAutoIt),
    (SwitchModule::Archive, 0x4000, EngineFeature::ArchiveCpio),
    (
        SwitchModule::Archive,
        0x8000,
        EngineFeature::ArchiveInstallShield,
    ),
    (
        SwitchModule::Archive,
        0x1_0000,
        EngineFeature::ArchiveSevenZip,
    ),
    (
        SwitchModule::Archive,
        0x2_0000,
        EngineFeature::ArchiveIso9660,
    ),
    (SwitchModule::Archive, 0x4_0000, EngineFeature::ArchiveDmg),
    (SwitchModule::Archive, 0x8_0000, EngineFeature::ArchiveXar),
    (
        SwitchModule::Archive,
        0x10_0000,
        EngineFeature::ArchiveHfsPlus,
    ),
    (SwitchModule::Archive, 0x20_0000, EngineFeature::ArchiveXz),
    (
        SwitchModule::Archive,
        0x40_0000,
        EngineFeature::ArchiveEncrypted,
    ),
    (SwitchModule::Archive, 0x80_0000, EngineFeature::ArchiveMbr),
    (SwitchModule::Archive, 0x100_0000, EngineFeature::ArchiveGpt),
    (SwitchModule::Archive, 0x200_0000, EngineFeature::ArchiveApm),
    (SwitchModule::Archive, 0x400_0000, EngineFeature::ArchiveEgg),
    (SwitchModule::Archive, 0x800_0000, EngineFeature::ArchiveUdf),
    (
        SwitchModule::Archive,
        0x1000_0000,
        EngineFeature::ArchiveLha,
    ),
    (
        SwitchModule::Archive,
        0x2000_0000,
        EngineFeature::ArchiveAlz,
    ),
    (SwitchModule::Document, 0x1, EngineFeature::DocumentHtml),
    (SwitchModule::Document, 0x2, EngineFeature::DocumentRtf),
    (SwitchModule::Document, 0x4, EngineFeature::DocumentPdf),
    (SwitchModule::Document, 0x8, EngineFeature::DocumentScript),
    (
        SwitchModule::Document,
        0x10,
        EngineFeature::DocumentHtmlSkipRaw,
    ),
    (
        SwitchModule::Document,
        0x20,
        EngineFeature::DocumentJavaScriptNormalisation,
    ),
    (SwitchModule::Document, 0x40, EngineFeature::DocumentSwf),
    (SwitchModule::Document, 0x80, EngineFeature::DocumentMsXml),
    (SwitchModule::Document, 0x100, EngineFeature::DocumentOoxml),
    (SwitchModule::Document, 0x200, EngineFeature::DocumentHwp),
    (
        SwitchModule::Document,
        0x400,
        EngineFeature::DocumentOneNote,
    ),
    (SwitchModule::Mail, 0x1, EngineFeature::MailMbox),
    (SwitchModule::Mail, 0x2, EngineFeature::MailTnef),
    (SwitchModule::Other, 0x1, EngineFeature::OtherUuencoded),
    (SwitchModule::Other, 0x2, EngineFeature::OtherScriptEncoder),
    (SwitchModule::Other, 0x4, EngineFeature::OtherRiff),
    (SwitchModule::Other, 0x8, EngineFeature::OtherJpeg),
    (SwitchModule::Other, 0x10, EngineFeature::OtherCryptFf),
    (
        SwitchModule::Other,
        0x20,
        EngineFeature::OtherDataLossPrevention,
    ),
    (SwitchModule::Other, 0x40, EngineFeature::OtherMydoomLog),
    (SwitchModule::Other, 0x80, EngineFeature::OtherPrefiltering),
    (
        SwitchModule::Other,
        0x100,
        EngineFeature::OtherPdfNameObjects,
    ),
    (
        SwitchModule::Other,
        0x200,
        EngineFeature::OtherPartitionIntersection,
    ),
    (SwitchModule::Other, 0x400, EngineFeature::OtherLzw),
    (SwitchModule::Other, 0x800, EngineFeature::OtherPng),
    (SwitchModule::Other, 0x1000, EngineFeature::OtherGif),
    (SwitchModule::Other, 0x2000, EngineFeature::OtherTiff),
    (
        SwitchModule::Other,
        0x4000,
        EngineFeature::OtherImageFuzzyHash,
    ),
    (SwitchModule::Phishing, 0x1, EngineFeature::PhishingEngine),
    (
        SwitchModule::Phishing,
        0x2,
        EngineFeature::PhishingEntityConversion,
    ),
    (
        SwitchModule::Programs,
        0x1,
        EngineFeature::ProgramInterpreter,
    ),
    (
        SwitchModule::Programs,
        0x2,
        EngineFeature::ProgramCompilerX86,
    ),
    (
        SwitchModule::Programs,
        0x4,
        EngineFeature::ProgramCompilerPpc,
    ),
    (
        SwitchModule::Programs,
        0x8,
        EngineFeature::ProgramCompilerArm,
    ),
    (SwitchModule::Statistics, 0x1, EngineFeature::StatisticsOff),
    (
        SwitchModule::Statistics,
        0x2,
        EngineFeature::SectionStatisticsOff,
    ),
    (
        SwitchModule::RegularExpressions,
        0x1,
        EngineFeature::RegularExpressionSupport,
    ),
    (
        SwitchModule::RegularExpressions,
        0x2,
        EngineFeature::RegularExpressionOptions,
    ),
    (
        SwitchModule::RegularExpressions,
        0x4,
        EngineFeature::RegularExpressionGlobal,
    ),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MalformedSwitchLine;

impl fmt::Display for MalformedSwitchLine {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("the switch bits are not written 0x followed by hexadecimal digits")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadSwitchLine {
    NotASwitch,
    OutsideFunctionalityLevel,
    Applied,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EngineSwitches {
    words: [u32; 11],
}

impl Default for EngineSwitches {
    fn default() -> Self {
        Self {
            words: MODULES.map(|(_, _, default)| default),
        }
    }
}

impl EngineSwitches {
    fn slot(module: SwitchModule) -> Option<usize> {
        MODULES.iter().position(|(_, known, _)| *known == module)
    }

    #[must_use]
    pub fn is_on(&self, (module, bit): (SwitchModule, u32)) -> bool {
        Self::slot(module)
            .and_then(|slot| self.words.get(slot))
            .is_some_and(|word| word & bit != 0)
    }

    #[must_use]
    pub fn runs_programs(&self) -> bool {
        Self::slot(SwitchModule::Programs)
            .and_then(|slot| self.words.get(slot))
            .is_some_and(|word| word & PROGRAM_ENGINES != 0)
    }

    #[must_use]
    pub fn enabled_features(&self) -> Vec<EngineFeature> {
        FEATURES
            .iter()
            .filter(|(module, bit, _)| self.is_on((*module, *bit)))
            .map(|(_, _, feature)| *feature)
            .collect()
    }

    pub fn read_line(&mut self, line: &[u8]) -> Result<ReadSwitchLine, MalformedSwitchLine> {
        let Some((prefix, module)) = MODULES
            .iter()
            .find(|(prefix, _, _)| line.starts_with(prefix))
            .map(|(prefix, module, _)| (*prefix, *module))
        else {
            return Ok(ReadSwitchLine::NotASwitch);
        };
        if !level_applies(line) {
            return Ok(ReadSwitchLine::OutsideFunctionalityLevel);
        }
        let bits = line.get(prefix.len()..).unwrap_or_default();
        let value = hexadecimal_bits(bits).ok_or(MalformedSwitchLine)?;
        if let Some(word) = Self::slot(module).and_then(|slot| self.words.get_mut(slot)) {
            *word = value;
        }
        Ok(ReadSwitchLine::Applied)
    }
}

fn level_applies(line: &[u8]) -> bool {
    let fields: Vec<&[u8]> = line
        .split(|byte| *byte == b':')
        .filter(|field| !field.is_empty())
        .collect();
    let level = i64::from(u32::try_from(FUNCTIONALITY_LEVEL).unwrap_or(u32::MAX));
    let bound = |field: &[u8]| -> Option<i64> {
        field.first().filter(|byte| byte.is_ascii_digit())?;
        Some(leading_decimal(field))
    };
    match fields.get(2) {
        None => true,
        Some(lowest) => match bound(lowest) {
            None => false,
            Some(lowest) if lowest > level => false,
            Some(_) => match fields.get(3) {
                None => true,
                Some(highest) => bound(highest).is_some_and(|highest| highest >= level),
            },
        },
    }
}

fn leading_decimal(field: &[u8]) -> i64 {
    field
        .iter()
        .take_while(|byte| byte.is_ascii_digit())
        .fold(0i64, |value, digit| {
            value
                .saturating_mul(10)
                .saturating_add(i64::from(digit.saturating_sub(b'0')))
        })
}

fn hexadecimal_bits(text: &[u8]) -> Option<u32> {
    let digits = text.strip_prefix(b"0x")?;
    let digits = digits
        .strip_prefix(b"0x")
        .or_else(|| digits.strip_prefix(b"0X"))
        .unwrap_or(digits);
    let length = digits
        .iter()
        .take_while(|byte| byte.is_ascii_hexdigit())
        .count();
    if length == 0 {
        return None;
    }
    digits.get(..length)?.iter().try_fold(0u32, |value, digit| {
        let nibble = char::from(*digit).to_digit(16)?;
        Some(value.wrapping_shl(4) | nibble)
    })
}
