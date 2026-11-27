const DEFLATE64_WINDOW: usize = 64 * 1024;
const DEFLATE64_LONGEST_MATCH: usize = 65_538;
const DEFLATE64_LONGEST_SHORT_MATCH: usize = 258;
const DEFLATE64_LONG_MATCH_INDEX: usize = 28;
const SHORTEST_DEFLATE_MATCH: usize = 3;
const FIRST_LENGTH_SYMBOL: usize = 257;
const END_OF_BLOCK: usize = 256;
const DISTANCE_CODE_BITS: u32 = 5;
const LENGTH_BASES: [usize; 29] = [
    3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131,
    163, 195, 227, 3,
];
const LENGTH_EXTRA_BITS: [u32; 29] = [
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 16,
];
const DISTANCE_BASES: [usize; 32] = [
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537,
    2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577, 32769, 49153,
];
const DISTANCE_EXTRA_BITS: [u32; 32] = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13,
    13, 14, 14,
];
const IMPLODE_LITERAL_BITS: u32 = 8;
const IMPLODE_TREE_BITS: u32 = 6;
const IMPLODE_LITERAL_SYMBOLS: usize = 256;
const IMPLODE_TREE_SYMBOLS: usize = 64;
const IMPLODE_LONGEST_LENGTH_SYMBOL: usize = 63;
const IMPLODE_LENGTH_EXTENSION: usize = 255;
const CODES_PER_DESCRIPTION: usize = 16;
const LARGE_WINDOW_FLAG: u16 = 2;
const LITERAL_CODE_FLAG: u16 = 4;

#[derive(Default)]
struct LowBitsFirst {
    bytes: Vec<u8>,
    held: u64,
    held_count: u32,
}

impl LowBitsFirst {
    fn bits(&mut self, value: usize, count: u32) {
        let mask = 1u64.wrapping_shl(count).wrapping_sub(1);
        let value = u64::try_from(value).unwrap_or(0) & mask;
        self.held |= value.wrapping_shl(self.held_count);
        self.held_count = self.held_count.wrapping_add(count);
        while self.held_count >= 8 {
            self.bytes.push(self.held.to_le_bytes()[0]);
            self.held = self.held.wrapping_shr(8);
            self.held_count = self.held_count.wrapping_sub(8);
        }
    }

    fn code(&mut self, code: usize, length: u32) {
        for bit in (0..length).rev() {
            self.bits(code.wrapping_shr(bit) & 1, 1);
        }
    }

    fn finish(mut self) -> Vec<u8> {
        if self.held_count > 0 {
            self.bytes.push(self.held.to_le_bytes()[0]);
        }
        self.bytes
    }
}

fn fixed_literal_length_code(symbol: usize) -> (usize, u32) {
    match symbol {
        0..=143 => (symbol.wrapping_add(0x30), 8),
        144..=255 => (symbol.wrapping_sub(144).wrapping_add(0x190), 9),
        256..=279 => (symbol.wrapping_sub(256), 7),
        _ => (symbol.wrapping_sub(280).wrapping_add(0xc0), 8),
    }
}

fn longest_match(contents: &[u8], at: usize, window: usize, longest: usize) -> (usize, usize) {
    let mut best = (0, 0);
    for start in at.saturating_sub(window)..at {
        let length = contents
            .get(start..)
            .unwrap_or_default()
            .iter()
            .zip(contents.get(at..).unwrap_or_default())
            .take(longest)
            .take_while(|(earlier, later)| earlier == later)
            .count();
        if length > best.0 {
            best = (length, at.wrapping_sub(start));
        }
    }
    best
}

fn index_of_base(bases: &[usize], value: usize) -> usize {
    bases.iter().rposition(|base| *base <= value).unwrap_or(0)
}

#[must_use]
pub fn deflate64_fixed(contents: &[u8]) -> Vec<u8> {
    let mut out = LowBitsFirst::default();
    out.bits(1, 1);
    out.bits(1, 2);
    let mut at = 0;
    while let Some(byte) = contents.get(at) {
        let (length, distance) =
            longest_match(contents, at, DEFLATE64_WINDOW, DEFLATE64_LONGEST_MATCH);
        if length < SHORTEST_DEFLATE_MATCH {
            let (code, bits) = fixed_literal_length_code(usize::from(*byte));
            out.code(code, bits);
            at = at.wrapping_add(1);
            continue;
        }
        let length_index = if length > DEFLATE64_LONGEST_SHORT_MATCH {
            DEFLATE64_LONG_MATCH_INDEX
        } else {
            index_of_base(
                LENGTH_BASES
                    .get(..DEFLATE64_LONG_MATCH_INDEX)
                    .unwrap_or_default(),
                length,
            )
        };
        let (code, bits) =
            fixed_literal_length_code(FIRST_LENGTH_SYMBOL.wrapping_add(length_index));
        out.code(code, bits);
        out.bits(
            length.wrapping_sub(LENGTH_BASES.get(length_index).copied().unwrap_or(0)),
            LENGTH_EXTRA_BITS.get(length_index).copied().unwrap_or(0),
        );
        let distance_index = index_of_base(&DISTANCE_BASES, distance);
        out.code(distance_index, DISTANCE_CODE_BITS);
        out.bits(
            distance.wrapping_sub(DISTANCE_BASES.get(distance_index).copied().unwrap_or(0)),
            DISTANCE_EXTRA_BITS
                .get(distance_index)
                .copied()
                .unwrap_or(0),
        );
        at = at.wrapping_add(length);
    }
    let (code, bits) = fixed_literal_length_code(END_OF_BLOCK);
    out.code(code, bits);
    out.finish()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ImplodeShape {
    pub large_window: bool,
    pub literal_code: bool,
}

impl ImplodeShape {
    #[must_use]
    pub const fn flags(self) -> u16 {
        let window = if self.large_window {
            LARGE_WINDOW_FLAG
        } else {
            0
        };
        let literal = if self.literal_code {
            LITERAL_CODE_FLAG
        } else {
            0
        };
        window | literal
    }
}

fn even_tree(symbols: usize, bits: u32) -> Vec<u8> {
    let descriptions = symbols.wrapping_div(CODES_PER_DESCRIPTION);
    let description = 0xf0 | u8::try_from(bits.wrapping_sub(1)).unwrap_or(0);
    let mut tree = vec![u8::try_from(descriptions.wrapping_sub(1)).unwrap_or(0)];
    tree.extend(std::iter::repeat_n(description, descriptions));
    tree
}

fn shannon_fano(out: &mut LowBitsFirst, symbol: usize, bits: u32) {
    let all_ones = 1usize.wrapping_shl(bits).wrapping_sub(1);
    out.code(all_ones ^ symbol, bits);
}

#[must_use]
pub fn imploded(contents: &[u8], shape: ImplodeShape) -> Vec<u8> {
    let mut stream = Vec::new();
    if shape.literal_code {
        stream.extend(even_tree(IMPLODE_LITERAL_SYMBOLS, IMPLODE_LITERAL_BITS));
    }
    stream.extend(even_tree(IMPLODE_TREE_SYMBOLS, IMPLODE_TREE_BITS));
    stream.extend(even_tree(IMPLODE_TREE_SYMBOLS, IMPLODE_TREE_BITS));
    let low_bits: u32 = if shape.large_window { 7 } else { 6 };
    let window: usize = if shape.large_window { 8192 } else { 4096 };
    let shortest: usize = if shape.literal_code { 3 } else { 2 };
    let longest = shortest
        .wrapping_add(IMPLODE_LONGEST_LENGTH_SYMBOL)
        .wrapping_add(IMPLODE_LENGTH_EXTENSION);
    let low_mask = 1usize.wrapping_shl(low_bits).wrapping_sub(1);
    let mut out = LowBitsFirst::default();
    let mut at = 0;
    while let Some(byte) = contents.get(at) {
        let (length, distance) = longest_match(contents, at, window, longest);
        if length < shortest {
            out.bits(1, 1);
            if shape.literal_code {
                shannon_fano(&mut out, usize::from(*byte), IMPLODE_LITERAL_BITS);
            } else {
                out.bits(usize::from(*byte), 8);
            }
            at = at.wrapping_add(1);
            continue;
        }
        out.bits(0, 1);
        let encoded_distance = distance.wrapping_sub(1);
        out.bits(encoded_distance & low_mask, low_bits);
        shannon_fano(
            &mut out,
            encoded_distance.wrapping_shr(low_bits),
            IMPLODE_TREE_BITS,
        );
        let encoded_length = length.wrapping_sub(shortest);
        if encoded_length >= IMPLODE_LONGEST_LENGTH_SYMBOL {
            shannon_fano(&mut out, IMPLODE_LONGEST_LENGTH_SYMBOL, IMPLODE_TREE_BITS);
            out.bits(
                encoded_length.wrapping_sub(IMPLODE_LONGEST_LENGTH_SYMBOL),
                8,
            );
        } else {
            shannon_fano(&mut out, encoded_length, IMPLODE_TREE_BITS);
        }
        at = at.wrapping_add(length);
    }
    stream.extend(out.finish());
    stream
}
