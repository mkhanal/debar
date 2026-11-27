const RING_BYTES: usize = 4096;
const RING_MASK: u64 = 4095;
const SKIPPED_BEFORE_THE_FIRST_FLAG: usize = 3;
const CHUNK_HEADER_BYTES: usize = 2;
const COPY_TOKEN_BYTES: usize = 2;
const SHORTEST_COPY: u64 = 3;
const MOST_LENGTH_BITS: u32 = 12;
const LENGTH_BIT_THRESHOLDS: [u64; 8] = [16, 32, 64, 128, 256, 512, 1024, 2048];

pub fn decompressed(container: &[u8], from: usize, most_produced: usize) -> Option<Vec<u8>> {
    let mut ring = [0u8; RING_BYTES];
    let mut produced: u64 = 0;
    let mut after_a_token = true;
    let mut output = Vec::new();
    let mut at = from.checked_add(SKIPPED_BEFORE_THE_FIRST_FLAG)?;
    while let Some(flags) = container.get(at).copied() {
        at = at.saturating_add(1);
        for bit in 0..8 {
            let in_ring = produced & RING_MASK;
            if (flags >> bit) & 1 == 1 {
                let token = container.get(at..at.saturating_add(COPY_TOKEN_BYTES))?;
                at = at.saturating_add(COPY_TOKEN_BYTES);
                let token = u16::from_le_bytes([*token.first()?, *token.get(1)?]);
                let length_bits = MOST_LENGTH_BITS.saturating_sub(
                    u32::try_from(
                        LENGTH_BIT_THRESHOLDS
                            .iter()
                            .filter(|threshold| in_ring > **threshold)
                            .count(),
                    )
                    .unwrap_or(0),
                );
                let length_mask = (1u16 << length_bits).wrapping_sub(1);
                let length = u64::from(token & length_mask).saturating_add(SHORTEST_COPY);
                let distance =
                    u64::from(token.checked_shr(length_bits).unwrap_or(0)).saturating_add(1);
                for _ in 0..length {
                    let from_slot = ring_slot(produced.wrapping_sub(distance));
                    let byte = ring.get(from_slot).copied().unwrap_or(0);
                    if let Some(slot) = ring.get_mut(ring_slot(produced)) {
                        *slot = byte;
                    }
                    produced = produced.saturating_add(1);
                }
                if produced > u64::try_from(most_produced).unwrap_or(u64::MAX) {
                    return None;
                }
            } else {
                if produced != 0 && in_ring == 0 && after_a_token {
                    container.get(at..at.saturating_add(CHUNK_HEADER_BYTES))?;
                    at = at.saturating_add(CHUNK_HEADER_BYTES);
                    output.extend_from_slice(&ring);
                    if output.len() > most_produced {
                        return None;
                    }
                    after_a_token = false;
                    break;
                }
                if let Some(byte) = container.get(at).copied() {
                    at = at.saturating_add(1);
                    if let Some(slot) = ring.get_mut(ring_slot(produced)) {
                        *slot = byte;
                    }
                    produced = produced.saturating_add(1);
                }
            }
            after_a_token = true;
        }
    }
    let tail = ring_slot(produced);
    output.extend_from_slice(ring.get(..tail).unwrap_or_default());
    (!output.is_empty() && output.len() <= most_produced).then_some(output)
}

fn ring_slot(position: u64) -> usize {
    usize::try_from(position & RING_MASK).unwrap_or(0)
}
