use std::cmp::Ordering;

use debar_image::{Digest, HashBucket, HashEntryId};

pub fn entries_not_reported(bucket: &HashBucket) -> Vec<HashEntryId> {
    let mut lookup_order = bucket.entries_in_load_order.clone();
    arrange_for_lookup(&mut lookup_order);
    let mut repeated: Vec<&Digest> = Vec::new();
    let mut seen: Vec<&Digest> = bucket
        .entries_in_load_order
        .iter()
        .map(|(_, digest)| digest)
        .collect();
    seen.sort();
    for pair in seen.windows(2) {
        if let [earlier, later] = pair
            && earlier == later
            && repeated.last() != Some(earlier)
        {
            repeated.push(earlier);
        }
    }
    let mut withdrawn = Vec::new();
    for digest in repeated {
        let Some(reported) = first_found(&lookup_order, digest) else {
            continue;
        };
        withdrawn.extend(
            bucket
                .entries_in_load_order
                .iter()
                .filter(|(id, candidate)| candidate == digest && *id != reported)
                .map(|(id, _)| *id),
        );
    }
    withdrawn
}

fn lookup_ordering(left: &Digest, right: &Digest) -> Ordering {
    let leading_word = |digest: &Digest| {
        let bytes = digest.bytes();
        let mut word = [0u8; 4];
        for (slot, byte) in word.iter_mut().zip(bytes) {
            *slot = *byte;
        }
        u32::from_le_bytes(word)
    };
    let rest = |digest: &Digest| digest.bytes().get(4..).unwrap_or_default().to_vec();
    leading_word(right)
        .cmp(&leading_word(left))
        .then_with(|| rest(left).cmp(&rest(right)))
}

fn arrange_for_lookup(entries: &mut [(HashEntryId, Digest)]) {
    let mut ranges = vec![(0usize, entries.len())];
    while let Some((start, end)) = ranges.pop() {
        if end.saturating_sub(start) < 2 {
            continue;
        }
        let Some(pivot) = entries.get(start).map(|(_, digest)| *digest) else {
            continue;
        };
        let mut scanning = start.saturating_add(1);
        let mut limit = end;
        while scanning < limit {
            let orders_after = entries
                .get(scanning)
                .is_some_and(|(_, digest)| lookup_ordering(digest, &pivot) == Ordering::Greater);
            if orders_after {
                limit = limit.saturating_sub(1);
                if limit != scanning {
                    entries.swap(scanning, limit);
                }
            } else {
                scanning = scanning.saturating_add(1);
            }
        }
        let pivot_place = scanning.saturating_sub(1);
        if pivot_place != start {
            entries.swap(start, pivot_place);
        }
        ranges.push((limit, end));
        ranges.push((start, pivot_place));
    }
}

fn first_found(entries: &[(HashEntryId, Digest)], wanted: &Digest) -> Option<HashEntryId> {
    let mut low = 0usize;
    let mut high = entries.len().checked_sub(1)?;
    while low <= high {
        let middle = low.checked_add(high)? / 2;
        let (id, here) = entries.get(middle)?;
        match lookup_ordering(wanted, here) {
            Ordering::Less => {
                high = middle.checked_sub(1)?;
            }
            Ordering::Greater => low = middle.checked_add(1)?,
            Ordering::Equal => return Some(*id),
        }
    }
    None
}
