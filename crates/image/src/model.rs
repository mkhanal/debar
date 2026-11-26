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
