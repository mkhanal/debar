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
    SignedContainerNotYetVerified,
    UnsignedFile,
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
    Choice(Vec<Vec<MaskedByte>>),
    NoneOf {
        width: u32,
        excluded: Vec<Vec<MaskedByte>>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Placement {
    Anywhere,
    FromStart { distance: u32, shift: u32 },
    BeforeEnd { distance: u32, shift: u32 },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pattern {
    pub before: Option<ContextTest>,
    pub elements: Vec<PatternElement>,
    pub after: Option<ContextTest>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PatternSignature<'a> {
    pub category: Category,
    pub placement: Placement,
    pub report_rank: u8,
    pub pattern: &'a Pattern,
    pub name: &'a str,
    pub indicator: Indicator,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReportWindows {
    pub length: u32,
    pub overlap: u32,
}
