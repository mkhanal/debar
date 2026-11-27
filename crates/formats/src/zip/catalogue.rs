use std::collections::VecDeque;

use debar_platform::input::{InputError, ObjectBytes};

use crate::context::ModuleContext;
use crate::facts::Fact;
use crate::limits::Limit;
use crate::little_endian::{Fields, read_within};
use crate::module::ContainerEntry;
use crate::zip::headers::{
    CentralParse, LOCAL_HEADER_LENGTH, LOCAL_HEADER_MAGIC, LocalParse, Record, central_record_at,
    local_record_at,
};

const END_RECORD_MAGIC: [u8; 4] = *b"PK\x05\x06";
const END_RECORD_LENGTH: u64 = 22;
const END_RECORD_READ: u64 = 20;
const CENTRAL_DIRECTORY_OFFSET_AT: usize = 16;
const SHORTEST_CENTRAL_RECORD: u64 = 46;
const OVERLAP_ALLOWANCE: u64 = 2;
const MOST_OVERLAPS_TOLERATED: u64 = 5;
const SEARCH_CHUNK: u64 = 64 * 1024;
const LARGEST_RECORD_END: u64 = 1 << 32;

pub enum Indexed {
    Entry(ContainerEntry),
    Fact(Fact),
    Records(Vec<Record>),
}

pub struct Catalogue {
    phase: Phase,
    pending: VecDeque<Indexed>,
    counted: u64,
    records: Vec<Record>,
    found: Vec<Record>,
}

enum Phase {
    FindingTheEndRecord,
    WalkingTheCentralDirectory { at: u64 },
    OrderingTheCentralRecords,
    SearchingGaps(Gaps),
    MergingFoundRecords,
    Finished,
}

struct Gaps {
    bounds: Vec<(u64, u64)>,
    current: usize,
    at: Option<u64>,
}

enum Ordered {
    Kept,
    TooManyOverlaps,
    Unordered,
}

impl Catalogue {
    pub const fn new() -> Self {
        Self {
            phase: Phase::FindingTheEndRecord,
            pending: VecDeque::new(),
            counted: 0,
            records: Vec::new(),
            found: Vec::new(),
        }
    }

    pub fn next(
        &mut self,
        object: &dyn ObjectBytes,
        context: &mut ModuleContext,
    ) -> Result<Indexed, InputError> {
        loop {
            if let Some(indexed) = self.pending.pop_front() {
                return Ok(indexed);
            }
            match &mut self.phase {
                Phase::FindingTheEndRecord => {
                    self.phase = match central_directory_offset(object)? {
                        Some(at) => Phase::WalkingTheCentralDirectory { at },
                        None => Phase::SearchingGaps(Gaps::whole(object.length())),
                    };
                }
                Phase::WalkingTheCentralDirectory { at } => {
                    let at = *at;
                    self.walk_one_central_record(object, at, context)?;
                }
                Phase::OrderingTheCentralRecords => self.order_the_central_records(object),
                Phase::SearchingGaps(_) => self.search_gaps(object, context)?,
                Phase::MergingFoundRecords => self.merge_found_records(),
                Phase::Finished => {
                    return Ok(Indexed::Records(std::mem::take(&mut self.records)));
                }
            }
        }
    }

    fn walk_one_central_record(
        &mut self,
        object: &dyn ObjectBytes,
        at: u64,
        context: &mut ModuleContext,
    ) -> Result<(), InputError> {
        let position = self.counted.saturating_add(1);
        let (entry, local_header_offset, sizes, length) =
            match central_record_at(object, at, position)? {
                CentralParse::EndOfDirectory => {
                    self.phase = Phase::OrderingTheCentralRecords;
                    return Ok(());
                }
                CentralParse::EndAfter(entry) => {
                    self.pending.push_back(Indexed::Entry(entry));
                    self.phase = Phase::OrderingTheCentralRecords;
                    return Ok(());
                }
                CentralParse::Record {
                    entry,
                    local_header_offset,
                    sizes,
                    length,
                } => (entry, local_header_offset, sizes, length),
            };
        self.pending.push_back(Indexed::Entry(entry));
        let record = match local_record_at(object, local_header_offset, Some(sizes), position)? {
            LocalParse::Unreadable => Record::UNREAD,
            LocalParse::Rejected { entry } => {
                self.pending.push_back(Indexed::Entry(entry));
                Record::UNREAD
            }
            LocalParse::Accepted { entry, record } => {
                self.pending.push_back(Indexed::Entry(entry));
                record
            }
        };
        self.records.push(record);
        self.counted = position;
        self.phase = if self.reached_most_files(context) {
            Phase::OrderingTheCentralRecords
        } else {
            Phase::WalkingTheCentralDirectory {
                at: at.saturating_add(length),
            }
        };
        Ok(())
    }

    fn reached_most_files(&self, context: &mut ModuleContext) -> bool {
        let reached = context
            .most_files()
            .is_some_and(|most| self.counted >= most);
        if reached {
            context.reached(Limit::MostFiles);
        }
        reached
    }

    fn order_the_central_records(&mut self, object: &dyn ObjectBytes) {
        if self.records.len() > 1 {
            self.records.sort_by_key(|record| record.offset);
        }
        match ordering_of(&self.records) {
            Ordered::Kept => {
                self.phase = Phase::SearchingGaps(Gaps::around(&self.records, object.length()));
                return;
            }
            Ordered::TooManyOverlaps => {
                self.pending
                    .push_back(Indexed::Fact(Fact::OverlappingParts));
            }
            Ordered::Unordered => {}
        }
        self.records.clear();
        self.counted = 0;
        self.phase = Phase::SearchingGaps(Gaps::whole(object.length()));
    }

    fn search_gaps(
        &mut self,
        object: &dyn ObjectBytes,
        context: &mut ModuleContext,
    ) -> Result<(), InputError> {
        let Phase::SearchingGaps(gaps) = &mut self.phase else {
            return Ok(());
        };
        let Some(&(start, end)) = gaps.bounds.get(gaps.current) else {
            self.phase = Phase::MergingFoundRecords;
            return Ok(());
        };
        let first_gap = gaps.current == 0;
        let at = if let Some(at) = gaps.at {
            at
        } else {
            if !first_gap
                && context
                    .most_files()
                    .is_some_and(|most| self.counted >= most)
            {
                context.reached(Limit::MostFiles);
                self.phase = Phase::MergingFoundRecords;
                return Ok(());
            }
            if start > end {
                self.records.clear();
                self.found.clear();
                self.phase = Phase::Finished;
                return Ok(());
            }
            start
        };
        let Some(candidate) = next_local_magic(object, at, end)? else {
            gaps.current = gaps.current.saturating_add(1);
            gaps.at = None;
            return Ok(());
        };
        let position = self.counted.saturating_add(1);
        let resume_at = match local_record_at(object, candidate, None, position)? {
            LocalParse::Unreadable => candidate.saturating_add(1),
            LocalParse::Rejected { entry } => {
                self.pending.push_back(Indexed::Entry(entry));
                candidate.saturating_add(1)
            }
            LocalParse::Accepted { entry, record } => {
                self.pending.push_back(Indexed::Entry(entry));
                self.found.push(record);
                self.counted = position;
                record.end().max(candidate.saturating_add(1))
            }
        };
        gaps.at = Some(resume_at);
        if context
            .most_files()
            .is_some_and(|most| self.counted >= most)
        {
            context.reached(Limit::MostFiles);
            self.phase = Phase::MergingFoundRecords;
        }
        Ok(())
    }

    fn merge_found_records(&mut self) {
        let central = std::mem::take(&mut self.records);
        let found = std::mem::take(&mut self.found);
        let mut merged = Vec::with_capacity(central.len().saturating_add(found.len()));
        let mut central = central.into_iter().peekable();
        let mut found = found.into_iter().peekable();
        loop {
            let take_found = match (central.peek(), found.peek()) {
                (None, None) => break,
                (Some(_), None) => false,
                (None, Some(_)) => true,
                (Some(listed), Some(searched)) => searched.offset < listed.offset,
            };
            let next = if take_found {
                found.next()
            } else {
                central.next()
            };
            merged.extend(next);
        }
        if matches!(ordering_of(&merged), Ordered::TooManyOverlaps) {
            self.pending
                .push_back(Indexed::Fact(Fact::OverlappingParts));
            merged.clear();
        }
        self.records = merged;
        self.phase = Phase::Finished;
    }
}

impl Gaps {
    fn whole(length: u64) -> Self {
        Self {
            bounds: vec![(0, length)],
            current: 0,
            at: None,
        }
    }

    fn around(records: &[Record], length: u64) -> Self {
        let Some(first) = records.first() else {
            return Self::whole(length);
        };
        let mut bounds = vec![(0, first.offset)];
        for pair in records.windows(2) {
            if let [before, after] = pair {
                bounds.push((before.end(), after.offset));
            }
        }
        if let Some(last) = records.last() {
            bounds.push((last.end(), length));
        }
        Self {
            bounds,
            current: 0,
            at: None,
        }
    }
}

fn ordering_of(records: &[Record]) -> Ordered {
    let mut overlaps = 0u64;
    for pair in records.windows(2) {
        let [before, after] = pair else {
            continue;
        };
        if before.end() >= LARGEST_RECORD_END || after.end() >= LARGEST_RECORD_END {
            return Ordered::Unordered;
        }
        if after.offset.saturating_add(OVERLAP_ALLOWANCE) < before.end() {
            overlaps = overlaps.saturating_add(1);
            if !after.same_member_as(before) && overlaps > MOST_OVERLAPS_TOLERATED {
                return Ordered::TooManyOverlaps;
            }
        }
    }
    Ordered::Kept
}

pub fn central_directory_offset(object: &dyn ObjectBytes) -> Result<Option<u64>, InputError> {
    let length = object.length();
    let Some(last_start) = length.checked_sub(END_RECORD_LENGTH) else {
        return Ok(None);
    };
    let mut chunk_end = last_start.saturating_add(END_RECORD_READ);
    while chunk_end > 1 {
        let chunk_start = chunk_end.saturating_sub(SEARCH_CHUNK).max(1);
        let Some(chunk) = read_within(object, chunk_start, chunk_end.saturating_sub(chunk_start))?
        else {
            return Ok(None);
        };
        let mut candidates = chunk
            .windows(END_RECORD_MAGIC.len())
            .enumerate()
            .filter(|(_, window)| *window == END_RECORD_MAGIC)
            .map(|(index, _)| chunk_start.saturating_add(u64::try_from(index).unwrap_or(0)))
            .filter(|start| *start <= last_start)
            .collect::<Vec<u64>>();
        candidates.reverse();
        for start in candidates {
            let Some(fixed) = read_within(object, start, END_RECORD_READ)? else {
                continue;
            };
            let offset = u64::from(Fields::of(&fixed).u32_at(CENTRAL_DIRECTORY_OFFSET_AT));
            if offset.saturating_add(SHORTEST_CENTRAL_RECORD) <= length {
                return Ok(Some(offset));
            }
        }
        let overlap = u64::try_from(END_RECORD_MAGIC.len())
            .unwrap_or(0)
            .saturating_sub(1);
        chunk_end = chunk_start.saturating_add(overlap);
        if chunk_start <= 1 {
            break;
        }
    }
    Ok(None)
}

fn next_local_magic(
    object: &dyn ObjectBytes,
    from: u64,
    gap_end: u64,
) -> Result<Option<u64>, InputError> {
    let Some(last_start) = object.length().checked_sub(LOCAL_HEADER_LENGTH) else {
        return Ok(None);
    };
    let search_end = gap_end.min(last_start.saturating_add(1));
    let magic_length = u64::try_from(LOCAL_HEADER_MAGIC.len()).unwrap_or(0);
    let mut at = from;
    while at < search_end {
        let chunk_end = at
            .saturating_add(SEARCH_CHUNK)
            .min(search_end)
            .saturating_add(magic_length.saturating_sub(1));
        let Some(chunk) = read_within(object, at, chunk_end.saturating_sub(at))? else {
            return Ok(None);
        };
        if let Some(index) = chunk
            .windows(LOCAL_HEADER_MAGIC.len())
            .position(|window| window == LOCAL_HEADER_MAGIC)
        {
            let found = at.saturating_add(u64::try_from(index).unwrap_or(u64::MAX));
            return Ok((found < search_end).then_some(found));
        }
        at = chunk_end.saturating_sub(magic_length.saturating_sub(1));
    }
    Ok(None)
}
