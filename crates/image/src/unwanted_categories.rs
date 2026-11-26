use zerocopy::little_endian::U32;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::model::UnwantedCategory;
use crate::names::NameId;

const UNNAMED: u32 = u32::MAX;

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned, Clone, Copy)]
#[repr(C)]
struct CategoryEntry {
    name: U32,
    text_start: U32,
    text_length: U32,
}

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
struct CategoriesHeader {
    entry_count: U32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CategoriesNotBuilt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CategoriesMalformed;

pub fn build(sorted: &[(NameId, Option<&str>)]) -> Result<Vec<u8>, CategoriesNotBuilt> {
    let mut entries = Vec::with_capacity(sorted.len());
    let mut text = Vec::new();
    for (name, category) in sorted {
        let (text_start, text_length) = match category {
            Some(category) => {
                let start = u32::try_from(text.len()).map_err(|_| CategoriesNotBuilt)?;
                text.extend_from_slice(category.as_bytes());
                (
                    start,
                    u32::try_from(category.len()).map_err(|_| CategoriesNotBuilt)?,
                )
            }
            None => (UNNAMED, 0),
        };
        entries.push(CategoryEntry {
            name: U32::new(name.0),
            text_start: U32::new(text_start),
            text_length: U32::new(text_length),
        });
    }
    let header = CategoriesHeader {
        entry_count: U32::new(u32::try_from(entries.len()).map_err(|_| CategoriesNotBuilt)?),
    };
    let mut bytes = header.as_bytes().to_vec();
    bytes.extend_from_slice(entries.as_bytes());
    bytes.extend_from_slice(&text);
    Ok(bytes)
}

pub struct UnwantedCategories<'m> {
    entries: &'m [CategoryEntry],
    text: &'m [u8],
}

impl<'m> UnwantedCategories<'m> {
    pub fn read(bytes: &'m [u8]) -> Result<Self, CategoriesMalformed> {
        let (header, rest) =
            CategoriesHeader::ref_from_prefix(bytes).map_err(|_| CategoriesMalformed)?;
        let count = usize::try_from(header.entry_count.get()).map_err(|_| CategoriesMalformed)?;
        let (entries, text) = <[CategoryEntry]>::ref_from_prefix_with_elems(rest, count)
            .map_err(|_| CategoriesMalformed)?;
        Ok(Self { entries, text })
    }

    pub fn of(&self, name: NameId) -> Result<Option<UnwantedCategory<'m>>, CategoriesMalformed> {
        let Ok(found) = self
            .entries
            .binary_search_by_key(&name.0, |entry| entry.name.get())
        else {
            return Ok(None);
        };
        let entry = self.entries.get(found).ok_or(CategoriesMalformed)?;
        if entry.text_start.get() == UNNAMED {
            return Ok(Some(UnwantedCategory::Unnamed));
        }
        let start = usize::try_from(entry.text_start.get()).map_err(|_| CategoriesMalformed)?;
        let length = usize::try_from(entry.text_length.get()).map_err(|_| CategoriesMalformed)?;
        let text = self
            .text
            .get(start..start.checked_add(length).ok_or(CategoriesMalformed)?)
            .ok_or(CategoriesMalformed)?;
        std::str::from_utf8(text)
            .map(|text| Some(UnwantedCategory::Named(text)))
            .map_err(|_| CategoriesMalformed)
    }
}
