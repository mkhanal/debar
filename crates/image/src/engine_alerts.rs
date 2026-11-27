use zerocopy::little_endian::{U16, U32};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::names::NameId;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EngineAlert {
    ScanSizeLimitExceeded,
    FileSizeLimitExceeded,
    FileCountLimitExceeded,
    RecursionLimitExceeded,
    ScanTimeLimitExceeded,
    OverlappingParts,
    ObfuscatedNames,
}

impl EngineAlert {
    const fn code(self) -> u16 {
        match self {
            Self::ScanSizeLimitExceeded => 1,
            Self::FileSizeLimitExceeded => 2,
            Self::FileCountLimitExceeded => 3,
            Self::RecursionLimitExceeded => 4,
            Self::ScanTimeLimitExceeded => 5,
            Self::OverlappingParts => 6,
            Self::ObfuscatedNames => 7,
        }
    }
}

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned, Clone, Copy)]
#[repr(C)]
struct AlertEntry {
    alert: U16,
    reserved: U16,
    name: U32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EngineAlertsMalformed;

pub(crate) fn build(named: &[(EngineAlert, NameId)]) -> Vec<u8> {
    let mut sorted = named.to_vec();
    sorted.sort_by_key(|(alert, _)| *alert);
    sorted.dedup_by_key(|(alert, _)| *alert);
    let entries: Vec<AlertEntry> = sorted
        .iter()
        .map(|(alert, name)| AlertEntry {
            alert: U16::new(alert.code()),
            reserved: U16::new(0),
            name: U32::new(name.0),
        })
        .collect();
    entries.as_bytes().to_vec()
}

#[derive(Clone, Copy)]
pub struct EngineAlerts<'m> {
    entries: &'m [AlertEntry],
}

impl<'m> EngineAlerts<'m> {
    pub fn read(bytes: &'m [u8]) -> Result<Self, EngineAlertsMalformed> {
        let entries = <[AlertEntry]>::ref_from_bytes(bytes).map_err(|_| EngineAlertsMalformed)?;
        Ok(Self { entries })
    }

    #[must_use]
    pub fn name_of(&self, alert: EngineAlert) -> Option<NameId> {
        self.entries
            .iter()
            .find(|entry| entry.alert.get() == alert.code())
            .map(|entry| NameId(entry.name.get()))
    }
}
