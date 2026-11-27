use debar_image::ObjectKind;
use debar_platform::input::{InputError, ObjectBytes};

use crate::zip::headers::{
    CentralParse, LOCAL_HEADER_LENGTH, LOCAL_HEADER_MAGIC, central_record_at,
};
use crate::zip::little_endian::read_within;

const FIRST_WINDOW_BYTES: u64 = 1024;
const LATER_WINDOW_BYTES: u64 = 1028;
const SHORTEST_TYPED: u64 = 70;
const NAME_ROOM_NEEDED: u64 = 22;
const WINDOW_OVERLAP: u64 = 53;
const ROOM_FOR_ANOTHER_WINDOW: u64 = 30;
const MOST_STEPS: u32 = 32;
const NAMES_LOOKED_AT: u32 = 3;
const POSITION_WHILE_TYPING: u64 = 1;

const DECIDING_NAMES: [(&[u8], ObjectKind); 4] = [
    (b"xl/", ObjectKind::OfficeOpenSpreadsheet),
    (b"ppt/", ObjectKind::OfficeOpenPresentation),
    (b"word/", ObjectKind::OfficeOpenWord),
    (b"Contents/content.hpf", ObjectKind::HangulOpen),
];

const SUGGESTING_NAMES: [&[u8]; 12] = [
    b"BinData",
    b"mimetype",
    b"Contents",
    b"docProps/",
    b"customXml/",
    b"version.xml",
    b"settings.xml",
    b"_.rels/.rels",
    b"[ContentTypes].xml",
    b"[Content_Types].xml",
    b"Preview/PrvText.txt",
    b"META-INF/container.xml",
];

const DIRECTORY_NAMES: [(&[u8], bool, ObjectKind); 4] = [
    (b"xl/", false, ObjectKind::OfficeOpenSpreadsheet),
    (b"ppt/", false, ObjectKind::OfficeOpenPresentation),
    (b"word/", false, ObjectKind::OfficeOpenWord),
    (b"Contents/content.hpf", true, ObjectKind::HangulOpen),
];

pub fn office_kind(object: &dyn ObjectBytes) -> Result<Option<ObjectKind>, InputError> {
    let length = object.length();
    let first_length = length.min(FIRST_WINDOW_BYTES);
    if first_length <= SHORTEST_TYPED {
        return Ok(None);
    }
    let mut window_start = 0u64;
    let mut window = read_within(object, 0, first_length)?.unwrap_or_default();
    let mut cursor = 0usize;
    let mut names_looked_at = 0u32;
    let mut suggested = false;
    for _ in 0..MOST_STEPS {
        let window_end = window_start.saturating_add(window.as_slice().length());
        if let Some(found) = find_magic(&window, cursor) {
            let name_index = found.saturating_add(as_index(LOCAL_HEADER_LENGTH));
            let name = window.get(name_index..).unwrap_or_default();
            if name.length() > NAME_ROOM_NEEDED {
                if let Some(kind) = DECIDING_NAMES
                    .iter()
                    .find(|(prefix, _)| name.starts_with(prefix))
                    .map(|(_, kind)| *kind)
                {
                    return Ok(Some(kind));
                }
                suggested |= SUGGESTING_NAMES
                    .iter()
                    .any(|prefix| name.starts_with(prefix));
                names_looked_at = names_looked_at.saturating_add(1);
                if names_looked_at >= NAMES_LOOKED_AT {
                    if suggested {
                        return named_in_the_central_directory(object);
                    }
                    return Ok(None);
                }
                cursor = name_index;
                continue;
            }
        }
        if length.saturating_sub(window_end) <= ROOM_FOR_ANOTHER_WINDOW {
            return Ok(None);
        }
        window_start = window_end.saturating_sub(WINDOW_OVERLAP);
        let next_length = length.saturating_sub(window_start).min(LATER_WINDOW_BYTES);
        window = read_within(object, window_start, next_length)?.unwrap_or_default();
        cursor = 0;
    }
    Ok(None)
}

fn named_in_the_central_directory(
    object: &dyn ObjectBytes,
) -> Result<Option<ObjectKind>, InputError> {
    let Some(mut at) = crate::zip::catalogue::central_directory_offset(object)? else {
        return Ok(None);
    };
    loop {
        let (entry, length) = match central_record_at(object, at, POSITION_WHILE_TYPING)? {
            CentralParse::EndOfDirectory | CentralParse::EndAfter(_) => return Ok(None),
            CentralParse::Record { entry, length, .. } => (entry, length),
        };
        let name = entry.name.unwrap_or_default();
        if let Some(kind) = DIRECTORY_NAMES
            .iter()
            .find(|(wanted, whole_name, _)| {
                if *whole_name {
                    name.as_slice() == *wanted
                } else {
                    name.starts_with(wanted)
                }
            })
            .map(|(_, _, kind)| *kind)
        {
            return Ok(Some(kind));
        }
        at = at.saturating_add(length);
    }
}

fn find_magic(window: &[u8], from: usize) -> Option<usize> {
    window
        .get(from..)?
        .windows(LOCAL_HEADER_MAGIC.len())
        .position(|bytes| bytes == LOCAL_HEADER_MAGIC)
        .map(|index| index.saturating_add(from))
}

fn as_index(value: u64) -> usize {
    usize::try_from(value).unwrap_or(usize::MAX)
}
