pub struct Visited {
    highest: i64,
    words: Vec<u64>,
}

impl Visited {
    pub const fn new(highest: i64) -> Self {
        Self {
            highest,
            words: Vec::new(),
        }
    }

    pub fn first_visit(&mut self, unit: i32) -> bool {
        let Ok(number) = usize::try_from(unit) else {
            return false;
        };
        if self.words.is_empty() {
            let units = usize::try_from(self.highest.saturating_add(1)).unwrap_or(0);
            self.words = vec![0; units.div_ceil(64).max(1)];
        }
        let bit = 1u64 << (number % 64);
        let Some(word) = self.words.get_mut(number / 64) else {
            return false;
        };
        if *word & bit != 0 {
            return false;
        }
        *word |= bit;
        true
    }
}
