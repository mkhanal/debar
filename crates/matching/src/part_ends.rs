use debar_image::PartMemory;

pub struct RememberedEnds {
    memory: PartMemory,
    first: Option<u64>,
    latest: Vec<u64>,
    next_overwritten: usize,
}

impl RememberedEnds {
    pub fn new(memory: PartMemory) -> Self {
        Self {
            memory,
            first: None,
            latest: Vec::new(),
            next_overwritten: 0,
        }
    }

    pub fn remember(&mut self, end: u64) {
        let latest_kept = match self.memory {
            PartMemory::EarliestEnd => {
                self.first = Some(self.first.map_or(end, |first| first.min(end)));
                return;
            }
            PartMemory::FirstAndLatestEnds { latest } => usize::try_from(latest).unwrap_or(0),
        };
        if self.first.is_none() {
            self.first = Some(end);
            return;
        }
        if latest_kept == 0 {
            return;
        }
        if self.latest.len() < latest_kept {
            self.latest.push(end);
            return;
        }
        if let Some(slot) = self.latest.get_mut(self.next_overwritten) {
            *slot = end;
        }
        self.next_overwritten = self
            .next_overwritten
            .saturating_add(1)
            .checked_rem(latest_kept)
            .unwrap_or(0);
    }

    pub fn iter(&self) -> impl Iterator<Item = u64> + '_ {
        self.first.into_iter().chain(self.latest.iter().copied())
    }
}
