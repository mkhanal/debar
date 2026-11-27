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
        let mut digesting = DigestsInProgress::new(need);
        digesting.update(bytes);
        digesting.finish()
    }

    #[must_use]
    pub fn missing_from(&self, need: DigestNeed) -> DigestNeed {
        DigestNeed {
            md5: need.md5 && self.md5.is_none(),
            sha1: need.sha1 && self.sha1.is_none(),
            sha256: need.sha256 && self.sha256.is_none(),
        }
    }

    #[must_use]
    pub fn joined_with(self, other: Self) -> Self {
        Self {
            md5: self.md5.or(other.md5),
            sha1: self.sha1.or(other.sha1),
            sha256: self.sha256.or(other.sha256),
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct DigestsInProgress {
    md5: Option<Md5>,
    sha1: Option<Sha1>,
    sha256: Option<Sha256>,
}

impl DigestsInProgress {
    #[must_use]
    pub fn new(need: DigestNeed) -> Self {
        Self {
            md5: need.md5.then(Md5::new),
            sha1: need.sha1.then(Sha1::new),
            sha256: need.sha256.then(Sha256::new),
        }
    }

    pub fn update(&mut self, bytes: &[u8]) {
        if let Some(md5) = &mut self.md5 {
            md5.update(bytes);
        }
        if let Some(sha1) = &mut self.sha1 {
            sha1.update(bytes);
        }
        if let Some(sha256) = &mut self.sha256 {
            sha256.update(bytes);
        }
    }

    #[must_use]
    pub fn finish(self) -> ObjectDigests {
        ObjectDigests {
            md5: self.md5.map(|md5| md5.finalize().into()),
            sha1: self.sha1.map(|sha1| sha1.finalize().into()),
            sha256: self.sha256.map(|sha256| sha256.finalize().into()),
        }
    }
}
