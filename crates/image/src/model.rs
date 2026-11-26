use regex_syntax::hir::Hir;

use crate::expression_tree::ExpressionTree;
use crate::object_kind::ObjectKind;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DigestAlgorithm {
    Md5,
    Sha1,
    Sha256,
}

impl DigestAlgorithm {
    pub const ALL: [Self; 3] = [Self::Md5, Self::Sha1, Self::Sha256];

    #[must_use]
    pub const fn digest_length(self) -> usize {
        match self {
            Self::Md5 => 16,
            Self::Sha1 => 20,
            Self::Sha256 => 32,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Digest {
    Md5([u8; 16]),
    Sha1([u8; 20]),
    Sha256([u8; 32]),
}

impl Digest {
    #[must_use]
    pub const fn algorithm(&self) -> DigestAlgorithm {
        match self {
            Self::Md5(_) => DigestAlgorithm::Md5,
            Self::Sha1(_) => DigestAlgorithm::Sha1,
            Self::Sha256(_) => DigestAlgorithm::Sha256,
        }
    }

    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        match self {
            Self::Md5(bytes) => bytes,
            Self::Sha1(bytes) => bytes,
            Self::Sha256(bytes) => bytes,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum HashPurpose {
    WholeObjectDetection,
    ExecutableSectionDetection,
    WholeObjectTrust,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Category {
    Malware,
    PotentiallyUnwanted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum HashedSize {
    Exactly(u32),
    Any,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Indicator {
    Strong,
    PotentiallyUnwanted,
    Weak,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HashSignature<'a> {
    pub purpose: HashPurpose,
    pub category: Category,
    pub size: HashedSize,
    pub digest: Digest,
    pub name: &'a str,
    pub indicator: Indicator,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureName {
    pub text: String,
    pub indicator: Indicator,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Provenance {
    DetachedSignatureVerified,
    HeaderSignatureVerified,
    IndexSignatureVerified,
    UnsignedContainer,
}

impl Provenance {
    pub const ALL: [Self; 4] = [
        Self::DetachedSignatureVerified,
        Self::HeaderSignatureVerified,
        Self::IndexSignatureVerified,
        Self::UnsignedContainer,
    ];

    #[must_use]
    pub const fn is_signed(self) -> bool {
        !matches!(self, Self::UnsignedContainer)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DatabaseRecord {
    pub name: String,
    pub version: u32,
    pub declared_signature_count: u32,
    pub functionality_level: u32,
    pub provenance: Provenance,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MaskedByte {
    pub value: u8,
    pub mask: u8,
}

impl MaskedByte {
    pub const ANY: Self = Self { value: 0, mask: 0 };

    #[must_use]
    pub const fn exactly(value: u8) -> Self {
        Self { value, mask: 0xff }
    }

    #[must_use]
    pub const fn accepts(self, byte: u8) -> bool {
        byte & self.mask == self.value & self.mask
    }

    #[must_use]
    pub const fn is_exact(self) -> bool {
        self.mask == 0xff
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ByteSet(pub [u8; 32]);

impl ByteSet {
    #[must_use]
    pub fn of(bytes: impl IntoIterator<Item = u8>) -> Self {
        let mut set = [0u8; 32];
        for byte in bytes {
            if let Some(slot) = set.get_mut(usize::from(byte >> 3)) {
                *slot |= 1 << (byte & 7);
            }
        }
        Self(set)
    }

    #[must_use]
    pub fn contains(&self, byte: u8) -> bool {
        self.0
            .get(usize::from(byte >> 3))
            .is_some_and(|slot| slot & (1 << (byte & 7)) != 0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContextTest {
    pub sequences: Vec<Vec<ByteSet>>,
    pub negated: bool,
    pub satisfied_at_object_edge: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PatternElement {
    Byte(MaskedByte),
    OneOf(ByteSet),
    Gap {
        minimum: u32,
        maximum: Option<u32>,
    },
    PartBreak {
        minimum: u32,
        maximum: Option<u32>,
    },
    Choice(Vec<Vec<MaskedByte>>),
    NoneOf {
        width: u32,
        excluded: Vec<Vec<MaskedByte>>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Placement {
    Anywhere,
    FromStart {
        distance: u32,
        shift: u32,
    },
    BeforeEnd {
        distance: u32,
        shift: u32,
    },
    InExecutable {
        anchor: ExecutableAnchor,
        shift: u32,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ExecutableAnchor {
    AfterEntryPoint {
        distance: u32,
    },
    BeforeEntryPoint {
        distance: u32,
    },
    SectionStart {
        section: u32,
        distance: u32,
    },
    LastSectionStart {
        distance: u32,
    },
    WholeSection {
        section: u32,
        start_only_from_length: Option<u32>,
    },
    BeforeEnd {
        distance: u32,
    },
    VersionInformation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SignatureGroup(pub u32);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pattern {
    pub before: Option<ContextTest>,
    pub elements: Vec<PatternElement>,
    pub after: Option<ContextTest>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PatternSignature<'a> {
    pub group: SignatureGroup,
    pub category: Category,
    pub placement: Placement,
    pub report_rank: u8,
    pub pattern: &'a Pattern,
    pub outcome: PatternOutcome<'a>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PatternOutcome<'a> {
    Detection { name: &'a str, indicator: Indicator },
    TypeFound(TypeFinding),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TypeFinding {
    pub found: ObjectKind,
    pub required: Option<ObjectKind>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PartMemory {
    EarliestEnd,
    FirstAndLatestEnds { latest: u32 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReportWindows {
    pub length: u32,
    pub overlap: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CountComparison {
    Exactly(u32),
    MoreThan(u32),
    FewerThan(u32),
}

impl CountComparison {
    #[must_use]
    pub fn holds_for(self, matches: u64) -> bool {
        match self {
            Self::Exactly(expected) => matches == u64::from(expected),
            Self::MoreThan(bound) => matches > u64::from(bound),
            Self::FewerThan(bound) => matches < u64::from(bound),
        }
    }

    #[must_use]
    pub const fn threshold(self) -> u32 {
        match self {
            Self::Exactly(threshold) | Self::MoreThan(threshold) | Self::FewerThan(threshold) => {
                threshold
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CountTest {
    pub comparison: CountComparison,
    pub distinct_at_least: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Expression {
    Subsignature {
        index: u16,
        count: Option<CountTest>,
    },
    All(Box<Expression>, Box<Expression>),
    Any(Box<Expression>, Box<Expression>),
    Block {
        inner: Box<Expression>,
        count: CountTest,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum KindCondition {
    AnyKind,
    Kind(ObjectKind),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct InclusiveRange {
    pub lowest: u32,
    pub highest: u32,
}

impl InclusiveRange {
    #[must_use]
    pub fn holds(self, value: u64) -> bool {
        value >= u64::from(self.lowest) && value <= u64::from(self.highest)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LogicalConditions {
    pub container: Option<KindCondition>,
    pub intermediates: Vec<KindCondition>,
    pub file_size: Option<InclusiveRange>,
    pub entry_point: Option<InclusiveRange>,
    pub number_of_sections: Option<InclusiveRange>,
    pub handler_type: Option<ObjectKind>,
    pub icon_groups: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContentSubsignature {
    pub placement: Placement,
    pub patterns: Vec<Pattern>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ExpressionAnchoring {
    AtAnUnshiftedPlacement,
    NeverAtThePlacement,
    AtTheSubjectStart,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ExpressionMatches {
    First,
    EveryOneNotOverlapping,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExpressionForm {
    Linear(Hir),
    Backtracking(ExpressionTree),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegularExpressionSubsignature {
    pub trigger: Option<Expression>,
    pub placement: Placement,
    pub expression: ExpressionForm,
    pub anchoring: ExpressionAnchoring,
    pub matches: ExpressionMatches,
    pub bounded_by_shift: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ByteOrder {
    Little,
    Big,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ByteEncoding {
    Binary(ByteOrder),
    HexadecimalText(ByteOrder),
    DecimalText,
    HexadecimalOrDecimalText(ByteOrder),
    NeverMatches,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ValueComparison {
    Equal(i64),
    Greater(i64),
    Less(i64),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ByteComparison {
    pub subsignature: u16,
    pub displacement: i64,
    pub encoding: ByteEncoding,
    pub length: u32,
    pub exact: bool,
    pub comparisons: Vec<ValueComparison>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Subsignature {
    Content(ContentSubsignature),
    RegularExpression(RegularExpressionSubsignature),
    ByteComparison(ByteComparison),
    ImageFuzzyHash(u64),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogicalSignature<'a> {
    pub group: SignatureGroup,
    pub category: Category,
    pub name: &'a str,
    pub indicator: Indicator,
    pub outcome: LogicalOutcome,
    pub expression: &'a Expression,
    pub subsignatures: &'a [Subsignature],
    pub conditions: &'a LogicalConditions,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SignatureProgramId(pub u32);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum LogicalOutcome {
    Detection,
    RunProgram(SignatureProgramId),
    HookTriggered(SignatureProgramId),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SizeCondition {
    Any,
    Exactly(u32),
    Between {
        lowest: Option<u32>,
        highest: Option<u32>,
    },
}

impl SizeCondition {
    #[must_use]
    pub fn holds(self, value: u64) -> bool {
        match self {
            Self::Any => true,
            Self::Exactly(expected) => value == u64::from(expected),
            Self::Between { lowest, highest } => {
                lowest.is_none_or(|lowest| value >= u64::from(lowest))
                    && highest.is_none_or(|highest| value <= u64::from(highest))
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerSignature<'a> {
    pub name: &'a str,
    pub indicator: Indicator,
    pub container: KindCondition,
    pub container_size: SizeCondition,
    pub entry_name: Option<Hir>,
    pub compressed_size: SizeCondition,
    pub real_size: SizeCondition,
    pub encrypted: Option<bool>,
    pub position: SizeCondition,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum UnwantedCategory<'a> {
    Named(&'a str),
    Unnamed,
}
