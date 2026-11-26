use zerocopy::little_endian::{U32, U64};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

pub const MAGIC: [u8; 8] = *b"DEBARIMG";
pub const LAYOUT_VERSION: u32 = 4;
pub const BYTE_ORDER_MARK: u32 = 0x0403_0201;
pub const SECTION_ALIGNMENT: usize = 4096;
pub const CHECKSUM_LENGTH: usize = 32;
pub const DATABASE_NAME_LENGTH: usize = 32;

#[cfg(target_endian = "big")]
compile_error!("the image is read in place as little-endian records");

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
pub struct Header {
    pub magic: [u8; 8],
    pub layout_version: U32,
    pub byte_order: U32,
    pub file_length: U64,
    pub section_count: U32,
    pub reserved: U32,
}

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned, Clone, Copy)]
#[repr(C)]
pub struct DirectoryEntry {
    pub kind: U32,
    pub qualifier: U32,
    pub offset: U64,
    pub length: U64,
    pub item_count: U64,
    pub checksum: [u8; CHECKSUM_LENGTH],
}

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
pub struct DatabaseEntry {
    pub name: [u8; DATABASE_NAME_LENGTH],
    pub version: U32,
    pub declared_signature_count: U32,
    pub functionality_level: U32,
    pub provenance: U32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SectionKind {
    Databases,
    HashSizes,
    HashFilter,
    HashEntries,
    PatternGroup,
    Names,
    ObjectKinds,
    TypeMagic,
    LogicalGroup,
    UnwantedCategories,
    SelectionFilters,
}

impl SectionKind {
    #[must_use]
    pub const fn code(self) -> u32 {
        match self {
            Self::Databases => 1,
            Self::HashSizes => 2,
            Self::HashFilter => 3,
            Self::HashEntries => 4,
            Self::Names => 5,
            Self::PatternGroup => 6,
            Self::ObjectKinds => 7,
            Self::TypeMagic => 8,
            Self::LogicalGroup => 9,
            Self::UnwantedCategories => 10,
            Self::SelectionFilters => 11,
        }
    }

    #[must_use]
    pub const fn from_code(code: u32) -> Option<Self> {
        match code {
            1 => Some(Self::Databases),
            2 => Some(Self::HashSizes),
            3 => Some(Self::HashFilter),
            4 => Some(Self::HashEntries),
            5 => Some(Self::Names),
            6 => Some(Self::PatternGroup),
            7 => Some(Self::ObjectKinds),
            8 => Some(Self::TypeMagic),
            9 => Some(Self::LogicalGroup),
            10 => Some(Self::UnwantedCategories),
            11 => Some(Self::SelectionFilters),
            _ => None,
        }
    }
}
