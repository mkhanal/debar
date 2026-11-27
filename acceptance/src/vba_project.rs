const CHUNK_BYTES: usize = 4096;
const CONTAINER_SIGNATURE: u8 = 0x01;
const CHUNK_SIGNATURE_AND_FLAG: u16 = 0b1011 << 12;
const SHORTEST_COPY: usize = 3;
const TOKENS_PER_FLAG_BYTE: usize = 8;
const WINDOWS_1252: u16 = 1252;
const MINIMAL_PERFORMANCE_CACHE: [u8; 7] = [0xcc, 0x61, 0xff, 0xff, 0x00, 0x00, 0x00];

#[must_use]
pub const fn minimal_vba_project_stream() -> [u8; 7] {
    MINIMAL_PERFORMANCE_CACHE
}

#[must_use]
pub fn compressed(source: &[u8]) -> Vec<u8> {
    let mut container = vec![CONTAINER_SIGNATURE];
    for chunk in source.chunks(CHUNK_BYTES) {
        let body = compressed_chunk(chunk);
        let size = u16::try_from(body.len().saturating_add(2).saturating_sub(3)).unwrap_or(0);
        container.extend_from_slice(&(CHUNK_SIGNATURE_AND_FLAG | size).to_le_bytes());
        container.extend_from_slice(&body);
    }
    container
}

fn compressed_chunk(chunk: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    let mut position = 0usize;
    while position < chunk.len() {
        let flag_at = body.len();
        body.push(0u8);
        for token in 0..TOKENS_PER_FLAG_BYTE {
            if position >= chunk.len() {
                break;
            }
            let offset_bits = offset_bits(position);
            let length_bits = 16u32.saturating_sub(offset_bits);
            let longest = usize::from(u16::MAX >> offset_bits).saturating_add(SHORTEST_COPY);
            let farthest = 1usize << offset_bits;
            let (distance, length) = longest_match(chunk, position, farthest, longest);
            if length >= SHORTEST_COPY {
                let encoded = (u16::try_from(distance.saturating_sub(1)).unwrap_or(0)
                    << length_bits)
                    | u16::try_from(length.saturating_sub(SHORTEST_COPY)).unwrap_or(0);
                body.extend_from_slice(&encoded.to_le_bytes());
                if let Some(flags) = body.get_mut(flag_at) {
                    *flags |= 1 << token;
                }
                position = position.saturating_add(length);
            } else {
                body.push(chunk.get(position).copied().unwrap_or(0));
                position = position.saturating_add(1);
            }
        }
    }
    body
}

fn offset_bits(position: usize) -> u32 {
    let mut bits: u32 = 4;
    while (1usize << bits) < position {
        bits = bits.saturating_add(1);
    }
    bits
}

fn longest_match(chunk: &[u8], position: usize, farthest: usize, longest: usize) -> (usize, usize) {
    let mut best = (0, 0);
    for distance in 1..=farthest.min(position) {
        let start = position.saturating_sub(distance);
        let mut length = 0;
        while length < longest
            && position.saturating_add(length) < chunk.len()
            && chunk.get(start.saturating_add(length)) == chunk.get(position.saturating_add(length))
        {
            length = length.saturating_add(1);
        }
        if length > best.1 {
            best = (distance, length);
        }
    }
    best
}

#[derive(Debug, Clone)]
pub struct Module {
    pub name: String,
    pub source: Vec<u8>,
}

#[must_use]
pub fn dir_stream(project_name: &str, modules: &[Module]) -> Vec<u8> {
    let mut records = Vec::new();
    record(&mut records, 0x0001, &1u32.to_le_bytes());
    record(&mut records, 0x0002, &0x409u32.to_le_bytes());
    record(&mut records, 0x0014, &0x409u32.to_le_bytes());
    record(&mut records, 0x0003, &WINDOWS_1252.to_le_bytes());
    record(&mut records, 0x0004, project_name.as_bytes());
    record(&mut records, 0x0005, b"");
    record(&mut records, 0x0040, b"");
    record(&mut records, 0x0006, b"");
    record(&mut records, 0x003d, b"");
    record(&mut records, 0x0007, &0u32.to_le_bytes());
    record(&mut records, 0x0008, &0u32.to_le_bytes());
    record(&mut records, 0x0009, &0x5c1a_3d2bu32.to_le_bytes());
    records.extend_from_slice(&0x0012u16.to_le_bytes());
    record(
        &mut records,
        0x000f,
        &u16::try_from(modules.len()).unwrap_or(0).to_le_bytes(),
    );
    record(&mut records, 0x0013, &0xffffu16.to_le_bytes());
    for module in modules {
        let unicode: Vec<u8> = module
            .name
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        record(&mut records, 0x0019, module.name.as_bytes());
        record(&mut records, 0x0047, &unicode);
        record(&mut records, 0x001a, module.name.as_bytes());
        record(&mut records, 0x0032, &unicode);
        record(&mut records, 0x001c, b"");
        record(&mut records, 0x0048, b"");
        record(&mut records, 0x0031, &0u32.to_le_bytes());
        record(&mut records, 0x001e, &0u32.to_le_bytes());
        record(&mut records, 0x002c, &0xffffu16.to_le_bytes());
        record(&mut records, 0x0021, b"");
        record(&mut records, 0x002b, b"");
    }
    record(&mut records, 0x0010, b"");
    records
}

fn record(into: &mut Vec<u8>, id: u16, data: &[u8]) {
    into.extend_from_slice(&id.to_le_bytes());
    into.extend_from_slice(&u32::try_from(data.len()).unwrap_or(0).to_le_bytes());
    into.extend_from_slice(data);
}
