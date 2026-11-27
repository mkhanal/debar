pub struct Output {
    bytes: Vec<u8>,
    keeping: bool,
    let_go: u64,
}

impl Output {
    pub const fn kept() -> Self {
        Self {
            bytes: Vec::new(),
            keeping: true,
            let_go: 0,
        }
    }

    #[inline]
    pub fn write(&mut self, byte: u8) {
        self.bytes.push(byte);
    }

    #[inline]
    pub fn write_all(&mut self, bytes: &[u8]) {
        self.bytes.extend_from_slice(bytes);
    }

    pub fn take_back_last_byte(&mut self) {
        self.bytes.pop();
    }

    pub fn length(&self) -> u64 {
        self.let_go
            .saturating_add(u64::try_from(self.bytes.len()).unwrap_or(u64::MAX))
    }

    pub const fn is_kept(&self) -> bool {
        self.keeping
    }

    pub fn held_length(&self) -> usize {
        self.bytes.len()
    }

    pub fn stop_keeping(&mut self) {
        self.keeping = false;
        self.let_go_of_settled_bytes();
    }

    pub fn let_go_of_settled_bytes(&mut self) {
        if !self.keeping {
            let settled = self.take_settled();
            self.let_go = self
                .let_go
                .saturating_add(u64::try_from(settled.len()).unwrap_or(u64::MAX));
        }
    }

    pub fn take_settled(&mut self) -> Vec<u8> {
        let Some(last) = self.bytes.pop() else {
            return Vec::new();
        };
        std::mem::replace(&mut self.bytes, vec![last])
    }

    pub fn take_all(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.bytes)
    }
}
