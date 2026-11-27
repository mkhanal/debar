use md5::Md5;
use sha1::Sha1;
use sha2::{Digest as _, Sha256};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DigestNeed {
    pub md5: bool,
    pub sha1: bool,
    pub sha256: bool,
}

impl DigestNeed {
    #[must_use]
    pub fn is_empty(self) -> bool {
        !(self.md5 || self.sha1 || self.sha256)
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ObjectDigests {
    pub md5: Option<[u8; 16]>,
    pub sha1: Option<[u8; 20]>,
    pub sha256: Option<[u8; 32]>,
}

impl ObjectDigests {
    #[inline(never)]
    #[must_use]
    pub fn of(bytes: &[u8], need: DigestNeed) -> Self {
        Self {
            md5: need.md5.then(|| Md5::digest(bytes).into()),
            sha1: need.sha1.then(|| Sha1::digest(bytes).into()),
            sha256: need.sha256.then(|| Sha256::digest(bytes).into()),
        }
    }
}
