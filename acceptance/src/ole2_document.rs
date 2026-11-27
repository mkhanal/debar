const SIGNATURE: [u8; 8] = [0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1];
const SECTOR_BYTES: usize = 512;
const MINI_SECTOR_BYTES: usize = 64;
const MINI_STREAM_CUTOFF: usize = 4096;
const DIRECTORY_ENTRY_BYTES: usize = 128;
const FAT_ENTRIES_PER_SECTOR: usize = SECTOR_BYTES / 4;
const HEADER_FAT_SECTORS: usize = 109;
const HEADER_FAT_LIST: usize = 76;
const FREE: u32 = 0xffff_ffff;
const END_OF_CHAIN: u32 = 0xffff_fffe;
const FAT_SECTOR: u32 = 0xffff_fffd;
const NO_ENTRY: u32 = 0xffff_ffff;
const STORAGE: u8 = 1;
const STREAM: u8 = 2;
const ROOT: u8 = 5;
const BLACK: u8 = 1;
const ROOT_NAME: &str = "Root Entry";

#[derive(Debug, Clone)]
pub enum Node {
    Stream { name: String, contents: Vec<u8> },
    Storage { name: String, children: Vec<Node> },
}

impl Node {
    #[must_use]
    pub fn stream(name: &str, contents: &[u8]) -> Self {
        Self::Stream {
            name: name.to_owned(),
            contents: contents.to_vec(),
        }
    }

    #[must_use]
    pub fn storage(name: &str, children: Vec<Self>) -> Self {
        Self::Storage {
            name: name.to_owned(),
            children,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Layout {
    pub first_directory_sector: u32,
    pub first_fat_sector: u32,
}

#[must_use]
pub fn ole2_document(children: &[Node]) -> Vec<u8> {
    ole2_document_with_layout(children).0
}

#[must_use]
pub fn ole2_document_with_layout(children: &[Node]) -> (Vec<u8>, Layout) {
    let mut entries = vec![Entry::new(ROOT_NAME, ROOT, Vec::new())];
    let first_child = flatten(children, &mut entries);
    if let Some(root) = entries.first_mut() {
        root.child = first_child;
    }
    let mut sectors = Sectors::default();
    let mut mini_stream = Vec::new();
    let mut mini_fat = Vec::new();
    for entry in entries.iter_mut().skip(1) {
        if entry.kind != STREAM || entry.contents.is_empty() {
            entry.start = END_OF_CHAIN;
            continue;
        }
        if entry.contents.len() < MINI_STREAM_CUTOFF {
            entry.start = place_in_mini_stream(&entry.contents, &mut mini_stream, &mut mini_fat);
        }
    }
    let directory_bytes = directory_size(entries.len());
    let mini_fat_bytes = padded(mini_fat.len().saturating_mul(4), SECTOR_BYTES);
    let mini_stream_bytes = padded(mini_stream.len(), SECTOR_BYTES);
    let large_streams: usize = entries
        .iter()
        .filter(|entry| entry.kind == STREAM && entry.contents.len() >= MINI_STREAM_CUTOFF)
        .map(|entry| entry.contents.len().div_ceil(SECTOR_BYTES))
        .fold(0, usize::saturating_add);
    let data_sectors = directory_bytes
        .saturating_add(mini_fat_bytes)
        .saturating_add(mini_stream_bytes)
        .div_ceil(SECTOR_BYTES)
        .saturating_add(large_streams);
    let mut fat_sectors: usize = 1;
    while fat_sectors.saturating_mul(FAT_ENTRIES_PER_SECTOR)
        < fat_sectors.saturating_add(data_sectors)
    {
        fat_sectors = fat_sectors.saturating_add(1);
    }
    assert!(
        fat_sectors <= HEADER_FAT_SECTORS,
        "the test document is too large for a header-only FAT"
    );
    for _ in 0..fat_sectors {
        sectors.push_marked(FAT_SECTOR);
    }
    let first_directory_sector = sectors.push_chain(&directory(&entries));
    let first_mini_fat = if mini_fat.is_empty() {
        END_OF_CHAIN
    } else {
        sectors.push_chain(&mini_fat_bytes_of(&mini_fat))
    };
    let mini_stream_start = if mini_stream.is_empty() {
        END_OF_CHAIN
    } else {
        sectors.push_chain(&mini_stream)
    };
    if let Some(root) = entries.first_mut() {
        root.start = mini_stream_start;
        root.size = mini_stream.len();
    }
    for index in 1..entries.len() {
        let Some(entry) = entries.get(index) else {
            continue;
        };
        if entry.kind == STREAM && entry.contents.len() >= MINI_STREAM_CUTOFF {
            let contents = entry.contents.clone();
            let start = sectors.push_chain(&contents);
            if let Some(entry) = entries.get_mut(index) {
                entry.start = start;
            }
        }
    }
    sectors.overwrite_chain(first_directory_sector, &directory(&entries));
    let mut document = header(
        fat_sectors,
        first_directory_sector,
        first_mini_fat,
        mini_fat_bytes.div_ceil(SECTOR_BYTES),
    );
    document.extend_from_slice(&sectors.fat_bytes(fat_sectors));
    document.extend_from_slice(&sectors.bytes);
    let layout = Layout {
        first_directory_sector,
        first_fat_sector: 0,
    };
    (document, layout)
}

#[must_use]
pub fn sector_offset(sector: u32) -> usize {
    usize::try_from(sector)
        .unwrap_or(usize::MAX)
        .saturating_add(1)
        .saturating_mul(SECTOR_BYTES)
}

#[must_use]
pub fn directory_entry_offset(layout: Layout, index: usize) -> usize {
    sector_offset(layout.first_directory_sector)
        .saturating_add(index.saturating_mul(DIRECTORY_ENTRY_BYTES))
}

struct Entry {
    name: String,
    kind: u8,
    contents: Vec<u8>,
    left: u32,
    right: u32,
    child: u32,
    start: u32,
    size: usize,
}

impl Entry {
    fn new(name: &str, kind: u8, contents: Vec<u8>) -> Self {
        let size = contents.len();
        Self {
            name: name.to_owned(),
            kind,
            contents,
            left: NO_ENTRY,
            right: NO_ENTRY,
            child: NO_ENTRY,
            start: END_OF_CHAIN,
            size,
        }
    }
}

fn flatten(children: &[Node], entries: &mut Vec<Entry>) -> u32 {
    let mut first = NO_ENTRY;
    let mut previous: Option<usize> = None;
    for node in children {
        let index = entries.len();
        match node {
            Node::Stream { name, contents } => {
                entries.push(Entry::new(name, STREAM, contents.clone()));
            }
            Node::Storage { name, children } => {
                entries.push(Entry::new(name, STORAGE, Vec::new()));
                let child = flatten(children, entries);
                if let Some(storage) = entries.get_mut(index) {
                    storage.child = child;
                }
            }
        }
        let number = u32::try_from(index).unwrap_or(NO_ENTRY);
        match previous {
            None => first = number,
            Some(previous) => {
                if let Some(entry) = entries.get_mut(previous) {
                    entry.right = number;
                }
            }
        }
        previous = Some(index);
    }
    first
}

fn place_in_mini_stream(
    contents: &[u8],
    mini_stream: &mut Vec<u8>,
    mini_fat: &mut Vec<u32>,
) -> u32 {
    let first = u32::try_from(mini_fat.len()).unwrap_or(FREE);
    let count = contents.len().div_ceil(MINI_SECTOR_BYTES);
    for step in 1..=count {
        let next = if step == count {
            END_OF_CHAIN
        } else {
            u32::try_from(mini_fat.len().saturating_add(1)).unwrap_or(FREE)
        };
        mini_fat.push(next);
    }
    mini_stream.extend_from_slice(contents);
    mini_stream.resize(padded(mini_stream.len(), MINI_SECTOR_BYTES), 0);
    first
}

fn directory_size(entries: usize) -> usize {
    padded(entries.saturating_mul(DIRECTORY_ENTRY_BYTES), SECTOR_BYTES)
}

fn directory(entries: &[Entry]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for entry in entries {
        bytes.extend_from_slice(&directory_entry(entry));
    }
    while !bytes.len().is_multiple_of(SECTOR_BYTES) {
        bytes.extend_from_slice(&unused_directory_entry());
    }
    bytes
}

fn directory_entry(entry: &Entry) -> [u8; DIRECTORY_ENTRY_BYTES] {
    let mut bytes = [0u8; DIRECTORY_ENTRY_BYTES];
    let name: Vec<u8> = entry
        .name
        .encode_utf16()
        .chain(std::iter::once(0))
        .flat_map(u16::to_le_bytes)
        .take(64)
        .collect();
    put(&mut bytes, 0, &name);
    put(
        &mut bytes,
        64,
        &u16::try_from(name.len()).unwrap_or(64).to_le_bytes(),
    );
    put(&mut bytes, 66, &[entry.kind, BLACK]);
    put(&mut bytes, 68, &entry.left.to_le_bytes());
    put(&mut bytes, 72, &entry.right.to_le_bytes());
    put(&mut bytes, 76, &entry.child.to_le_bytes());
    put(&mut bytes, 116, &entry.start.to_le_bytes());
    put(
        &mut bytes,
        120,
        &u64::try_from(entry.size).unwrap_or(0).to_le_bytes(),
    );
    bytes
}

fn unused_directory_entry() -> [u8; DIRECTORY_ENTRY_BYTES] {
    let mut bytes = [0u8; DIRECTORY_ENTRY_BYTES];
    for offset in [68, 72, 76] {
        put(&mut bytes, offset, &NO_ENTRY.to_le_bytes());
    }
    bytes
}

fn mini_fat_bytes_of(mini_fat: &[u32]) -> Vec<u8> {
    let mut bytes: Vec<u8> = mini_fat
        .iter()
        .flat_map(|entry| entry.to_le_bytes())
        .collect();
    while !bytes.len().is_multiple_of(SECTOR_BYTES) {
        bytes.extend_from_slice(&FREE.to_le_bytes());
    }
    bytes
}

fn header(
    fat_sectors: usize,
    first_directory_sector: u32,
    first_mini_fat: u32,
    mini_fat_sectors: usize,
) -> Vec<u8> {
    let mut bytes = vec![0u8; SECTOR_BYTES];
    put(&mut bytes, 0, &SIGNATURE);
    put(&mut bytes, 24, &0x003e_u16.to_le_bytes());
    put(&mut bytes, 26, &3_u16.to_le_bytes());
    put(&mut bytes, 28, &0xfffe_u16.to_le_bytes());
    put(&mut bytes, 30, &9_u16.to_le_bytes());
    put(&mut bytes, 32, &6_u16.to_le_bytes());
    put(
        &mut bytes,
        44,
        &u32::try_from(fat_sectors).unwrap_or(0).to_le_bytes(),
    );
    put(&mut bytes, 48, &first_directory_sector.to_le_bytes());
    put(
        &mut bytes,
        56,
        &u32::try_from(MINI_STREAM_CUTOFF).unwrap_or(0).to_le_bytes(),
    );
    put(&mut bytes, 60, &first_mini_fat.to_le_bytes());
    put(
        &mut bytes,
        64,
        &u32::try_from(mini_fat_sectors).unwrap_or(0).to_le_bytes(),
    );
    put(&mut bytes, 68, &END_OF_CHAIN.to_le_bytes());
    for slot in 0..HEADER_FAT_SECTORS {
        let sector = if slot < fat_sectors {
            u32::try_from(slot).unwrap_or(FREE)
        } else {
            FREE
        };
        put(
            &mut bytes,
            HEADER_FAT_LIST.saturating_add(slot.saturating_mul(4)),
            &sector.to_le_bytes(),
        );
    }
    bytes
}

#[derive(Default)]
struct Sectors {
    fat: Vec<u32>,
    bytes: Vec<u8>,
    marked: usize,
}

impl Sectors {
    fn push_marked(&mut self, mark: u32) {
        self.fat.push(mark);
        self.marked = self.marked.saturating_add(1);
    }

    fn push_chain(&mut self, contents: &[u8]) -> u32 {
        let first = u32::try_from(self.fat.len()).unwrap_or(FREE);
        let count = contents.len().div_ceil(SECTOR_BYTES);
        for step in 1..=count {
            let next = if step == count {
                END_OF_CHAIN
            } else {
                u32::try_from(self.fat.len().saturating_add(1)).unwrap_or(FREE)
            };
            self.fat.push(next);
        }
        self.bytes.extend_from_slice(contents);
        self.bytes.resize(padded(self.bytes.len(), SECTOR_BYTES), 0);
        first
    }

    fn overwrite_chain(&mut self, first: u32, contents: &[u8]) {
        let start = usize::try_from(first)
            .unwrap_or(usize::MAX)
            .saturating_sub(self.marked)
            .saturating_mul(SECTOR_BYTES);
        put(&mut self.bytes, start, contents);
    }

    fn fat_bytes(&self, fat_sectors: usize) -> Vec<u8> {
        let mut bytes: Vec<u8> = self
            .fat
            .iter()
            .flat_map(|entry| entry.to_le_bytes())
            .collect();
        bytes.resize(fat_sectors.saturating_mul(SECTOR_BYTES), 0xff);
        bytes
    }
}

fn padded(length: usize, unit: usize) -> usize {
    length.div_ceil(unit).saturating_mul(unit)
}

fn put(bytes: &mut [u8], at: usize, value: &[u8]) {
    if let Some(slot) = bytes.get_mut(at..at.saturating_add(value.len())) {
        slot.copy_from_slice(value);
    }
}
