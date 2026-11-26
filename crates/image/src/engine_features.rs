#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EngineFeature {
    ExecutablePariteCheck,
    ExecutableKrizCheck,
    ExecutableMagistrCheck,
    ExecutablePoliposCheck,
    ExecutableSectionHashes,
    UnpackUpx,
    UnpackFsg,
    ExecutableSwizzorCheck,
    UnpackPetite,
    UnpackPespin,
    UnpackYc,
    UnpackWwpack,
    UnpackNspack,
    UnpackMew,
    UnpackUpack,
    UnpackAspack,
    ExecutableCatalogs,
    ExecutableCertificates,
    ExecutableIcons,
    ExecutableImportHashes,
    ElfParsing,
    MachOParsing,
    ArchiveRar,
    ArchiveZip,
    ArchiveGzip,
    ArchiveBzip2,
    ArchiveSzdd,
    ArchiveCab,
    ArchiveChm,
    ArchiveOle2,
    ArchiveTar,
    ArchiveBinhex,
    ArchiveSis,
    ArchiveNsis,
    ArchiveArj,
    ArchiveAutoIt,
    ArchiveCpio,
    ArchiveInstallShield,
    ArchiveSevenZip,
    ArchiveIso9660,
    ArchiveDmg,
    ArchiveXar,
    ArchiveHfsPlus,
    ArchiveXz,
    ArchiveEncrypted,
    ArchiveMbr,
    ArchiveGpt,
    ArchiveApm,
    ArchiveEgg,
    ArchiveUdf,
    ArchiveLha,
    ArchiveAlz,
    DocumentHtml,
    DocumentRtf,
    DocumentPdf,
    DocumentScript,
    DocumentHtmlSkipRaw,
    DocumentJavaScriptNormalisation,
    DocumentSwf,
    DocumentMsXml,
    DocumentOoxml,
    DocumentHwp,
    DocumentOneNote,
    MailMbox,
    MailTnef,
    OtherUuencoded,
    OtherScriptEncoder,
    OtherRiff,
    OtherJpeg,
    OtherCryptFf,
    OtherDataLossPrevention,
    OtherMydoomLog,
    OtherPrefiltering,
    OtherPdfNameObjects,
    OtherPartitionIntersection,
    OtherLzw,
    OtherPng,
    OtherGif,
    OtherTiff,
    OtherImageFuzzyHash,
    PhishingEngine,
    PhishingEntityConversion,
    ProgramInterpreter,
    ProgramCompilerX86,
    ProgramCompilerPpc,
    ProgramCompilerArm,
    StatisticsOff,
    SectionStatisticsOff,
    RegularExpressionSupport,
    RegularExpressionOptions,
    RegularExpressionGlobal,
}

impl EngineFeature {
    pub const ALL: [Self; 91] = [
        Self::ExecutablePariteCheck,
        Self::ExecutableKrizCheck,
        Self::ExecutableMagistrCheck,
        Self::ExecutablePoliposCheck,
        Self::ExecutableSectionHashes,
        Self::UnpackUpx,
        Self::UnpackFsg,
        Self::ExecutableSwizzorCheck,
        Self::UnpackPetite,
        Self::UnpackPespin,
        Self::UnpackYc,
        Self::UnpackWwpack,
        Self::UnpackNspack,
        Self::UnpackMew,
        Self::UnpackUpack,
        Self::UnpackAspack,
        Self::ExecutableCatalogs,
        Self::ExecutableCertificates,
        Self::ExecutableIcons,
        Self::ExecutableImportHashes,
        Self::ElfParsing,
        Self::MachOParsing,
        Self::ArchiveRar,
        Self::ArchiveZip,
        Self::ArchiveGzip,
        Self::ArchiveBzip2,
        Self::ArchiveSzdd,
        Self::ArchiveCab,
        Self::ArchiveChm,
        Self::ArchiveOle2,
        Self::ArchiveTar,
        Self::ArchiveBinhex,
        Self::ArchiveSis,
        Self::ArchiveNsis,
        Self::ArchiveArj,
        Self::ArchiveAutoIt,
        Self::ArchiveCpio,
        Self::ArchiveInstallShield,
        Self::ArchiveSevenZip,
        Self::ArchiveIso9660,
        Self::ArchiveDmg,
        Self::ArchiveXar,
        Self::ArchiveHfsPlus,
        Self::ArchiveXz,
        Self::ArchiveEncrypted,
        Self::ArchiveMbr,
        Self::ArchiveGpt,
        Self::ArchiveApm,
        Self::ArchiveEgg,
        Self::ArchiveUdf,
        Self::ArchiveLha,
        Self::ArchiveAlz,
        Self::DocumentHtml,
        Self::DocumentRtf,
        Self::DocumentPdf,
        Self::DocumentScript,
        Self::DocumentHtmlSkipRaw,
        Self::DocumentJavaScriptNormalisation,
        Self::DocumentSwf,
        Self::DocumentMsXml,
        Self::DocumentOoxml,
        Self::DocumentHwp,
        Self::DocumentOneNote,
        Self::MailMbox,
        Self::MailTnef,
        Self::OtherUuencoded,
        Self::OtherScriptEncoder,
        Self::OtherRiff,
        Self::OtherJpeg,
        Self::OtherCryptFf,
        Self::OtherDataLossPrevention,
        Self::OtherMydoomLog,
        Self::OtherPrefiltering,
        Self::OtherPdfNameObjects,
        Self::OtherPartitionIntersection,
        Self::OtherLzw,
        Self::OtherPng,
        Self::OtherGif,
        Self::OtherTiff,
        Self::OtherImageFuzzyHash,
        Self::PhishingEngine,
        Self::PhishingEntityConversion,
        Self::ProgramInterpreter,
        Self::ProgramCompilerX86,
        Self::ProgramCompilerPpc,
        Self::ProgramCompilerArm,
        Self::StatisticsOff,
        Self::SectionStatisticsOff,
        Self::RegularExpressionSupport,
        Self::RegularExpressionOptions,
        Self::RegularExpressionGlobal,
    ];

    #[must_use]
    pub fn code(self) -> u16 {
        Self::ALL
            .iter()
            .position(|feature| *feature == self)
            .and_then(|position| u16::try_from(position).ok())
            .unwrap_or(u16::MAX)
    }

    #[must_use]
    pub fn of_code(code: u16) -> Option<Self> {
        Self::ALL.get(usize::from(code)).copied()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EngineFeaturesMalformed;

pub fn build(enabled: &[EngineFeature]) -> Vec<u8> {
    let mut codes: Vec<u16> = enabled.iter().map(|feature| feature.code()).collect();
    codes.sort_unstable();
    codes.dedup();
    codes.iter().flat_map(|code| code.to_le_bytes()).collect()
}

#[derive(Clone, Copy)]
pub struct EngineFeatures<'m> {
    codes: &'m [u8],
}

impl<'m> EngineFeatures<'m> {
    pub fn read(bytes: &'m [u8]) -> Result<Self, EngineFeaturesMalformed> {
        if !bytes.len().is_multiple_of(2) {
            return Err(EngineFeaturesMalformed);
        }
        Ok(Self { codes: bytes })
    }

    pub fn enabled(
        &self,
    ) -> impl Iterator<Item = Result<EngineFeature, EngineFeaturesMalformed>> + 'm {
        let (pairs, _) = self.codes.as_chunks::<2>();
        pairs.iter().map(|pair| {
            EngineFeature::of_code(u16::from_le_bytes(*pair)).ok_or(EngineFeaturesMalformed)
        })
    }

    #[must_use]
    pub fn contains(&self, feature: EngineFeature) -> bool {
        let wanted = feature.code().to_le_bytes();
        let (pairs, _) = self.codes.as_chunks::<2>();
        pairs.contains(&wanted)
    }
}
