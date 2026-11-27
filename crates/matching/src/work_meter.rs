#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WorkMeter {
    spent: u64,
    allowed: Option<u64>,
}

impl WorkMeter {
    #[must_use]
    pub const fn unlimited() -> Self {
        Self {
            spent: 0,
            allowed: None,
        }
    }

    #[must_use]
    pub const fn allowing(units: u64) -> Self {
        Self {
            spent: 0,
            allowed: Some(units),
        }
    }

    pub const fn charge(&mut self, units: u64) {
        self.spent = self.spent.saturating_add(units);
    }

    #[must_use]
    pub const fn spent(&self) -> u64 {
        self.spent
    }

    #[must_use]
    pub const fn left(&self) -> Option<u64> {
        match self.allowed {
            Some(allowed) => Some(allowed.saturating_sub(self.spent)),
            None => None,
        }
    }

    #[must_use]
    pub const fn ran_out(&self) -> bool {
        match self.allowed {
            Some(allowed) => self.spent > allowed,
            None => false,
        }
    }
}
