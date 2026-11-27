#![allow(dead_code)]

use debar_formats::{
    ContainerEntry, EncryptedContent, Fact, FormatModule, HeaderCheck, Limit, MacroLanguage,
    ModuleContext, ModuleError, ModuleOutput, Object, Part, PartBytes, PartOutcome, PartRole,
    PartSource, Stage,
};
use debar_image::{
    BuildError, ByteSet, Category, EmbeddedObject, EngineAlert, FoundAtAnOffset, Hosts,
    ImageBuilder, Indicator, KindDescription, MagicTable, MaskedByte, ObjectKind, OwnBytes,
    Pattern, PatternElement, PatternOutcome, PatternSignature, Placement, RecognitionRank,
    SignatureGroup, TypeFinding, TypingRules,
};
use debar_platform::input::{InputError, ObjectBytes};

pub const TEST_CONTAINER: ObjectKind = ObjectKind::Xar;
pub const FOUND_TEST_CONTAINER: ObjectKind = ObjectKind::SelfExtracting;
pub const MAGIC: &[u8] = b"TOYC";
pub const HEADER_LENGTH: u64 = 8;
pub const VIEWED_AS: ObjectKind = ObjectKind::Text;
pub const GENERIC: SignatureGroup = SignatureGroup(0);
const RECOGNITION: SignatureGroup = SignatureGroup(15);
const MOST_FOUND_AT_OFFSETS: u32 = 10;

pub const WINDOW: u8 = b'W';
pub const PRODUCED: u8 = b'P';
pub const INVERTED: u8 = b'N';
const INVERTED_CHILD: u8 = 0;
const INVERTED_VIEW: u8 = 1;
pub const REPEATED: u8 = b'R';
pub const VIEW: u8 = b'V';
pub const ENTRY: u8 = b'E';
pub const FACT: u8 = b'F';
pub const ADMIT: u8 = b'A';
pub const END: u8 = b'.';

pub struct TestContainer;

pub static TEST_CONTAINER_MODULE: TestContainer = TestContainer;

impl FormatModule for TestContainer {
    fn kinds(&self) -> &[ObjectKind] {
        &[TEST_CONTAINER]
    }

    fn stage(&self) -> Stage {
        Stage::BeforeOwnBytes
    }

    fn open<'o>(
        &self,
        object: Object<'o>,
        _context: &mut ModuleContext,
    ) -> Result<Box<dyn PartSource<'o> + 'o>, ModuleError> {
        Ok(Box::new(Records {
            object,
            at: HEADER_LENGTH,
            entries: 0,
        }))
    }

    fn header_check(&self, from: &Object<'_>) -> Result<HeaderCheck, ModuleError> {
        let mut header = [0u8; 8];
        if from.length() < HEADER_LENGTH {
            return Ok(HeaderCheck::Fails);
        }
        from.read_at(0, &mut header)?;
        let (magic, declared) = header.split_at(MAGIC.len());
        let length = u64::from(u32::from_le_bytes(declared.try_into().unwrap_or([0; 4])));
        if magic != MAGIC || length < HEADER_LENGTH {
            return Ok(HeaderCheck::Fails);
        }
        Ok(HeaderCheck::Holds { length })
    }
}

struct Records<'o> {
    object: Object<'o>,
    at: u64,
    entries: u64,
}

impl<'o> PartSource<'o> for Records<'o> {
    fn next(
        &mut self,
        context: &mut ModuleContext,
    ) -> Result<Option<ModuleOutput<'o>>, ModuleError> {
        if context.last_part() == Some(PartOutcome::Refused(Limit::MostFiles)) {
            return Ok(None);
        }
        loop {
            if self.at >= self.object.length() {
                return Ok(None);
            }
            let record_at = self.at;
            let tag = self.byte()?;
            let output = match tag {
                WINDOW => {
                    let offset = self.number()?;
                    let length = self.number()?;
                    self.part(PartBytes::Window { offset, length }, None)
                }
                PRODUCED => {
                    let length = self.short()?;
                    PartBytes::Produced(self.bytes(length)?).into_part(None)
                }
                INVERTED => {
                    let role = self.byte()?;
                    let length = self.short()?;
                    let inverted = self.bytes(length)?.iter().map(|byte| !byte).collect();
                    let viewed_as = (role == INVERTED_VIEW).then_some(VIEWED_AS);
                    PartBytes::Produced(inverted).into_part(viewed_as)
                }
                REPEATED => {
                    let unit_length = self.short()?;
                    let unit = self.bytes(unit_length)?;
                    let times = self.number()?;
                    let length = unit_length
                        .checked_mul(times)
                        .ok_or(ModuleError::Damaged { at: record_at })?;
                    let bytes = if length <= context.room_to_produce() {
                        PartBytes::Produced(Repeated { unit, length }.all()?)
                    } else {
                        PartBytes::Regenerable(Box::new(Repeated { unit, length }))
                    };
                    bytes.into_part(None)
                }
                VIEW => {
                    let offset = self.number()?;
                    let length = self.number()?;
                    self.part(PartBytes::Window { offset, length }, Some(VIEWED_AS))
                }
                ENTRY => {
                    let name_length = u64::from(self.byte()?);
                    let name = self.bytes(name_length)?;
                    let size = self.number()?;
                    let position = self.entries;
                    self.entries = self.entries.saturating_add(1);
                    ModuleOutput::Entry(ContainerEntry {
                        name: Some(name),
                        compressed_size: size,
                        real_size: size,
                        encrypted: false,
                        position,
                    })
                }
                FACT => {
                    let code = self.byte()?;
                    if !context.facts_wanted() {
                        continue;
                    }
                    ModuleOutput::Fact(fact_of(code))
                }
                ADMIT => {
                    let needed = self.number()?;
                    if context.admit(needed).is_err() {
                        return Ok(None);
                    }
                    continue;
                }
                END => return Ok(None),
                _ => return Err(ModuleError::Damaged { at: record_at }),
            };
            return Ok(Some(output));
        }
    }
}

trait IntoPart<'o> {
    fn into_part(self, viewed_as: Option<ObjectKind>) -> ModuleOutput<'o>;
}

impl<'o> IntoPart<'o> for PartBytes<'o> {
    fn into_part(self, viewed_as: Option<ObjectKind>) -> ModuleOutput<'o> {
        let role = match viewed_as {
            Some(matched_as) => PartRole::View { matched_as },
            None => PartRole::Child { kind: None },
        };
        ModuleOutput::Part(Part { bytes: self, role })
    }
}

impl<'o> Records<'o> {
    fn part(&self, bytes: PartBytes<'o>, viewed_as: Option<ObjectKind>) -> ModuleOutput<'o> {
        if let PartBytes::Window { offset, length } = bytes
            && self.object.window(offset, length).is_none()
        {
            return ModuleOutput::Fact(Fact::BrokenStructure { at: offset });
        }
        bytes.into_part(viewed_as)
    }

    fn bytes(&mut self, length: u64) -> Result<Vec<u8>, ModuleError> {
        let at = self.at;
        let end = at
            .checked_add(length)
            .filter(|end| *end <= self.object.length())
            .ok_or(ModuleError::Damaged { at })?;
        let mut bytes =
            vec![0u8; usize::try_from(length).map_err(|_| ModuleError::Damaged { at })?];
        self.object.read_at(at, &mut bytes)?;
        self.at = end;
        Ok(bytes)
    }

    fn byte(&mut self) -> Result<u8, ModuleError> {
        Ok(self.bytes(1)?.first().copied().unwrap_or(0))
    }

    fn short(&mut self) -> Result<u64, ModuleError> {
        let bytes = self.bytes(2)?;
        Ok(u64::from(u16::from_le_bytes(
            bytes.try_into().unwrap_or([0; 2]),
        )))
    }

    fn number(&mut self) -> Result<u64, ModuleError> {
        let bytes = self.bytes(4)?;
        Ok(u64::from(u32::from_le_bytes(
            bytes.try_into().unwrap_or([0; 4]),
        )))
    }
}

const fn fact_of(code: u8) -> Fact {
    match code {
        0 => Fact::Macros(MacroLanguage::VisualBasic),
        1 => Fact::Encrypted {
            content: EncryptedContent::Archive,
            decryptable: false,
        },
        _ => Fact::ExecutableContent,
    }
}

struct Repeated {
    unit: Vec<u8>,
    length: u64,
}

impl Repeated {
    fn all(&self) -> Result<Vec<u8>, ModuleError> {
        let mut bytes =
            vec![0u8; usize::try_from(self.length).map_err(|_| ModuleError::Damaged { at: 0 })?];
        self.read_at(0, &mut bytes)?;
        Ok(bytes)
    }
}

impl ObjectBytes for Repeated {
    fn length(&self) -> u64 {
        self.length
    }

    fn read_at(&self, offset: u64, into: &mut [u8]) -> Result<(), InputError> {
        let wanted = u64::try_from(into.len()).unwrap_or(u64::MAX);
        let unit_length = self.unit.as_slice().length();
        if offset
            .checked_add(wanted)
            .is_none_or(|end| end > self.length)
            || unit_length == 0
        {
            return Err(InputError::BeyondTheEnd {
                offset,
                wanted,
                length: self.length,
            });
        }
        let start = usize::try_from(offset.checked_rem(unit_length).unwrap_or(0)).unwrap_or(0);
        let mut unit_from = self.unit.get(start..).unwrap_or_default();
        let mut rest = into;
        while !rest.is_empty() {
            if unit_from.is_empty() {
                unit_from = &self.unit;
            }
            let run = unit_from.len().min(rest.len());
            let (filled, after) = rest.split_at_mut(run);
            let (copied, unit_after) = unit_from.split_at(run);
            filled.copy_from_slice(copied);
            rest = after;
            unit_from = unit_after;
        }
        Ok(())
    }
}

pub fn exact(text: &[u8]) -> Pattern {
    Pattern {
        before: None,
        elements: text
            .iter()
            .map(|byte| PatternElement::Byte(MaskedByte::exactly(*byte)))
            .collect(),
        after: None,
    }
}

pub fn add_body(builder: &mut ImageBuilder, name: &str, body: &[u8]) -> Result<(), BuildError> {
    builder.add_pattern_signature(&PatternSignature {
        group: GENERIC,
        category: Category::Malware,
        placement: Placement::Anywhere,
        report_rank: 0,
        pattern: &exact(body),
        outcome: PatternOutcome::Detection {
            name,
            indicator: Indicator::Strong,
        },
    })
}

fn describe(builder: &mut ImageBuilder, kind: ObjectKind, found: Option<FoundAtAnOffset>) {
    builder.describe_object_kind(
        kind,
        KindDescription {
            format_name: format!("{kind:?}"),
            groups: vec![GENERIC],
            recognition: RecognitionRank {
                priority: u32::from(kind.code()),
                always_replaces: found.is_some(),
                ..RecognitionRank::default()
            },
            own_bytes: OwnBytes::Matched {
                as_kind: None,
                recognising_types: true,
            },
            matched_again_as: None,
            found_in_full_scan_retypes: Vec::new(),
            found_at_an_offset: found,
            executable: false,
        },
    );
}

pub fn test_container_image_builder() -> Result<ImageBuilder, BuildError> {
    let mut builder = ImageBuilder::new();
    builder.set_typing(TypingRules {
        prefix_length: 16,
        recognition_group: Some(RECOGNITION),
        text_bytes: ByteSet::of(0x20..=0x7e),
        wide_text_retry: None,
        most_found_at_offsets: MOST_FOUND_AT_OFFSETS,
    });
    builder.add_type_magic(MagicTable::Files, 0, MAGIC, TEST_CONTAINER);
    for kind in [ObjectKind::Text, ObjectKind::BinaryData, TEST_CONTAINER] {
        describe(&mut builder, kind, None);
    }
    describe(
        &mut builder,
        FOUND_TEST_CONTAINER,
        Some(FoundAtAnOffset::Embedded {
            object: EmbeddedObject {
                scanned_as: TEST_CONTAINER,
                starts_before_the_match: 0,
            },
            hosts: Hosts::NotIn(vec![TEST_CONTAINER]),
        }),
    );
    builder.add_pattern_signature(&PatternSignature {
        group: RECOGNITION,
        category: Category::Malware,
        placement: Placement::Anywhere,
        report_rank: 0,
        pattern: &exact(MAGIC),
        outcome: PatternOutcome::TypeFound(TypeFinding {
            found: FOUND_TEST_CONTAINER,
            required: None,
        }),
    })?;
    for (alert, name) in [
        (EngineAlert::RecursionLimitExceeded, "Test.Limits.Recursion"),
        (EngineAlert::FileCountLimitExceeded, "Test.Limits.Files"),
        (EngineAlert::ScanSizeLimitExceeded, "Test.Limits.ScanSize"),
        (EngineAlert::FileSizeLimitExceeded, "Test.Limits.FileSize"),
    ] {
        builder.name_engine_alert(alert, name, Indicator::PotentiallyUnwanted)?;
    }
    Ok(builder)
}

pub struct ContainerWriter {
    bytes: Vec<u8>,
}

impl ContainerWriter {
    pub fn new() -> Self {
        let mut bytes = MAGIC.to_vec();
        bytes.extend_from_slice(&[0; 4]);
        Self { bytes }
    }

    pub fn length(&self) -> u64 {
        self.bytes.as_slice().length()
    }

    pub fn window(mut self, offset: u64, length: u64) -> Self {
        self.bytes.push(WINDOW);
        self.number(offset).number(length)
    }

    pub fn view(mut self, offset: u64, length: u64) -> Self {
        self.bytes.push(VIEW);
        self.number(offset).number(length)
    }

    pub fn produced(mut self, bytes: &[u8]) -> Self {
        self.bytes.push(PRODUCED);
        self.short(bytes.len()).raw(bytes)
    }

    pub fn inverted(mut self, bytes: &[u8]) -> Self {
        self.bytes.extend_from_slice(&[INVERTED, INVERTED_CHILD]);
        let inverted: Vec<u8> = bytes.iter().map(|byte| !byte).collect();
        self.short(bytes.len()).raw(&inverted)
    }

    pub fn inverted_view(mut self, bytes: &[u8]) -> Self {
        self.bytes.extend_from_slice(&[INVERTED, INVERTED_VIEW]);
        let inverted: Vec<u8> = bytes.iter().map(|byte| !byte).collect();
        self.short(bytes.len()).raw(&inverted)
    }

    pub fn repeated(mut self, unit: &[u8], times: u32) -> Self {
        self.bytes.push(REPEATED);
        self.short(unit.len()).raw(unit).number(u64::from(times))
    }

    pub fn entry(mut self, name: &[u8], size: u32) -> Self {
        self.bytes.push(ENTRY);
        self.bytes.push(u8::try_from(name.len()).unwrap_or(u8::MAX));
        self.raw(name).number(u64::from(size))
    }

    pub fn fact(mut self, code: u8) -> Self {
        self.bytes.extend_from_slice(&[FACT, code]);
        self
    }

    pub fn end(mut self) -> Self {
        self.bytes.push(END);
        self
    }

    pub fn raw(mut self, bytes: &[u8]) -> Self {
        self.bytes.extend_from_slice(bytes);
        self
    }

    pub fn finish(mut self) -> Vec<u8> {
        let length = u32::try_from(self.bytes.len()).unwrap_or(u32::MAX);
        if let Some(declared) = self.bytes.get_mut(4..8) {
            declared.copy_from_slice(&length.to_le_bytes());
        }
        self.bytes
    }

    fn number(mut self, value: u64) -> Self {
        let value = u32::try_from(value).unwrap_or(u32::MAX);
        self.bytes.extend_from_slice(&value.to_le_bytes());
        self
    }

    fn short(mut self, value: usize) -> Self {
        let value = u16::try_from(value).unwrap_or(u16::MAX);
        self.bytes.extend_from_slice(&value.to_le_bytes());
        self
    }
}
