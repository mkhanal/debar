use crate::limits::{Limit, Room};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModuleContext {
    room: Room,
    room_to_produce: u64,
    facts_wanted: bool,
    last_part: Option<PartOutcome>,
    refusals: Vec<Limit>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PartOutcome {
    Scanned,
    Trusted,
    Refused(Limit),
}

impl ModuleContext {
    #[must_use]
    pub const fn new(
        room: Room,
        room_to_produce: u64,
        facts_wanted: bool,
        last_part: Option<PartOutcome>,
    ) -> Self {
        Self {
            room,
            room_to_produce,
            facts_wanted,
            last_part,
            refusals: Vec::new(),
        }
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
