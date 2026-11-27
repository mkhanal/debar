use crate::limits::{Limit, Room};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModuleContext {
    room: Room,
    room_to_produce: u64,
    most_files: Option<u64>,
    deepest_level: u32,
    found_inside_another: bool,
    facts_wanted: bool,
    last_part: Option<PartOutcome>,
    refusals: Vec<Limit>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContextOfTheObject {
    pub room: Room,
    pub room_to_produce: u64,
    pub most_files: Option<u64>,
    pub deepest_level: u32,
    pub found_inside_another: bool,
    pub facts_wanted: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PartOutcome {
    Scanned,
    Trusted,
    Refused(Limit),
}

impl ModuleContext {
    #[must_use]
    pub const fn new(object: ContextOfTheObject, last_part: Option<PartOutcome>) -> Self {
        Self {
            room: object.room,
            room_to_produce: object.room_to_produce,
            most_files: object.most_files,
            deepest_level: object.deepest_level,
            found_inside_another: object.found_inside_another,
            facts_wanted: object.facts_wanted,
            last_part,
            refusals: Vec::new(),
        }
    }

    pub fn reached(&mut self, limit: Limit) {
        self.refusals.push(limit);
    }

    #[must_use]
    pub const fn largest_file(&self) -> Option<u64> {
        self.room.largest_file
    }

    #[must_use]
    pub const fn most_files(&self) -> Option<u64> {
        self.most_files
    }

    #[must_use]
    pub const fn deepest_level(&self) -> u32 {
        self.deepest_level
    }

    #[must_use]
    pub const fn scan_bytes_left(&self) -> Option<u64> {
        self.room.scan_bytes_left
    }

    #[must_use]
    pub const fn files_left(&self) -> Option<u64> {
        self.room.files_left
    }

    #[must_use]
    pub const fn found_inside_another(&self) -> bool {
        self.found_inside_another
    }

    pub fn admit(&mut self, needed: u64) -> Result<(), Limit> {
        let admitted = self.room.admit(needed);
        if let Err(limit) = admitted {
            self.refusals.push(limit);
        }
        admitted
    }

    #[must_use]
    pub const fn room_to_produce(&self) -> u64 {
        self.room_to_produce
    }

    #[must_use]
    pub const fn facts_wanted(&self) -> bool {
        self.facts_wanted
    }

    #[must_use]
    pub const fn last_part(&self) -> Option<PartOutcome> {
        self.last_part
    }

    #[must_use]
    pub fn into_refusals(self) -> Vec<Limit> {
        self.refusals
    }
}
