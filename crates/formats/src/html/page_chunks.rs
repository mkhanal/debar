use debar_platform::input::{InputError, ObjectBytes};

use crate::html::output::Output;
use crate::html::page_normaliser::{PageNormaliser, View, is_whitespace};
use crate::object::Object;

const LONGEST_CHUNK: usize = 8191;

#[derive(Clone, Copy)]
pub enum Reread {
    No,
    Yes,
}

pub struct PageInChunks<'o> {
    page: Object<'o>,
    next_chunk_at: u64,
    raw: Vec<u8>,
    chunk: Vec<u8>,
    normaliser: PageNormaliser,
    finished: bool,
}

impl<'o> PageInChunks<'o> {
    pub fn new(page: Object<'o>, without_comments: Output, without_tags: Output) -> Self {
        Self {
            page,
            next_chunk_at: 0,
            raw: Vec::new(),
            chunk: Vec::new(),
            normaliser: PageNormaliser::new(without_comments, without_tags),
            finished: false,
        }
    }

    pub fn output(&mut self, view: View) -> &mut Output {
        self.normaliser.output(view)
    }

    pub const fn is_finished(&self) -> bool {
        self.finished
    }

    pub fn normalise_a_chunk(&mut self, reread: Reread) -> Result<bool, InputError> {
        if self.finished {
            return Ok(false);
        }
        if !self.read_a_chunk(reread)? {
            self.normaliser.finish();
            self.finished = true;
            return Ok(true);
        }
        let leading_whitespace = self
            .chunk
            .iter()
            .take_while(|&&byte| is_whitespace(byte))
            .count();
        let mut rest = self.chunk.get(leading_whitespace..).unwrap_or_default();
        while let Some((&byte, after)) = rest.split_first() {
            let plain_text = self.normaliser.normalise_plain_text(rest);
            if plain_text > 0 {
                rest = rest.get(plain_text..).unwrap_or_default();
                continue;
            }
            rest = after;
            if self.normaliser.reads_data_uri_bytes_as_they_are() {
                self.normaliser.normalise_byte(byte);
                continue;
            }
            match byte {
                b'\r' => {}
                b'\n' => self.normaliser.normalise_byte(b' '),
                _ => self.normaliser.normalise_byte(byte),
            }
        }
        Ok(true)
    }

    fn read_a_chunk(&mut self, reread: Reread) -> Result<bool, InputError> {
        let at = self.next_chunk_at;
        let left = self.page.length().saturating_sub(at);
        if left == 0 {
            return Ok(false);
        }
        self.chunk.clear();
        let mut read_to = at;
        while self.chunk.len() < LONGEST_CHUNK && read_to < self.page.length() {
            let wanted = LONGEST_CHUNK.saturating_sub(self.chunk.len());
            let take = usize::try_from(self.page.length().saturating_sub(read_to))
                .unwrap_or(usize::MAX)
                .min(wanted);
            self.raw.resize(take, 0);
            match reread {
                Reread::No => self.page.read_at(read_to, &mut self.raw)?,
                Reread::Yes => self.page.read_again_at(read_to, &mut self.raw)?,
            }
            read_to = read_to.saturating_add(as_offset(take));
            self.chunk
                .extend(self.raw.iter().copied().filter(|&byte| byte != 0));
        }
        let cut_off = if read_to < self.page.length() {
            let mut next = [0u8; 1];
            self.page.read_again_at(read_to, &mut next)?;
            if next.iter().any(|&byte| is_whitespace(byte)) {
                0
            } else {
                self.cut_back_to_the_last_whitespace()
            }
        } else {
            0
        };
        self.next_chunk_at = read_to.saturating_sub(as_offset(cut_off));
        Ok(true)
    }

    fn cut_back_to_the_last_whitespace(&mut self) -> usize {
        let last_whitespace = self
            .chunk
            .iter()
            .enumerate()
            .skip(1)
            .rev()
            .find(|(_, byte)| is_whitespace(**byte))
            .map(|(index, _)| index);
        let Some(kept) = last_whitespace.map(|index| index.saturating_add(1)) else {
            return 0;
        };
        let cut_off = self.chunk.len().saturating_sub(kept);
        self.chunk.truncate(kept);
        cut_off
    }
}

fn as_offset(length: usize) -> u64 {
    u64::try_from(length).unwrap_or(u64::MAX)
}
