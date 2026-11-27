use std::cell::RefCell;

use debar_platform::input::{InputError, ObjectBytes};
use flate2::{Decompress, FlushDecompress};

use crate::object::Object;

const COMPRESSED_READ_BYTES: usize = 16 * 1024;
const DECODED_WINDOW_BYTES: usize = 64 * 1024;

const OUTPUT_BUFFER_BYTES: u64 = 8192;

pub enum Inflation {
    Failed,
    Held(Vec<u8>),
    Measured(u64),
}

pub fn inflate(
    compressed: &Object<'_>,
    largest_file: Option<u64>,
    most_held: u64,
) -> Result<Inflation, InputError> {
    let whole_buffers_allowed = largest_file.map(|largest| {
        largest
            .checked_div(OUTPUT_BUFFER_BYTES)
            .unwrap_or(0)
            .saturating_mul(OUTPUT_BUFFER_BYTES)
    });
    let decoded_at_most = whole_buffers_allowed.map_or(u64::MAX, |allowed| {
        allowed.saturating_add(OUTPUT_BUFFER_BYTES)
    });
    let mut stream = Stream::new(compressed.clone(), decoded_at_most);
    let mut held = Some(Vec::new());
    let mut window = vec![0u8; DECODED_WINDOW_BYTES];
    loop {
        let produced = stream.next_bytes(&mut window)?;
        let Some(fresh) = window.get(..produced).filter(|fresh| !fresh.is_empty()) else {
            break;
        };
        if let Some(bytes) = &mut held {
            if fresh.length().saturating_add(bytes.as_slice().length()) > most_held {
                held = None;
            } else {
                bytes.extend_from_slice(fresh);
            }
        }
    }
    if stream.failed {
        return Ok(Inflation::Failed);
    }
    let length = match (largest_file, whole_buffers_allowed) {
        (Some(largest), Some(allowed)) if stream.produced > largest => allowed,
        _ => stream.produced,
    };
    Ok(match held {
        Some(mut bytes) => {
            bytes.truncate(usize::try_from(length).unwrap_or(usize::MAX));
            Inflation::Held(bytes)
        }
        None => Inflation::Measured(length),
    })
}

pub struct Inflated<'o> {
    compressed: Object<'o>,
    length: u64,
    reading: RefCell<Reading<'o>>,
}

impl<'o> Inflated<'o> {
    pub fn new(compressed: Object<'o>, length: u64) -> Self {
        let reading = RefCell::new(Reading::from_the_start(&compressed, length));
        Self {
            compressed,
            length,
            reading,
        }
    }
}

impl ObjectBytes for Inflated<'_> {
    fn length(&self) -> u64 {
        self.length
    }

    fn read_at(&self, offset: u64, into: &mut [u8]) -> Result<(), InputError> {
        let wanted = into.length();
        if offset
            .checked_add(wanted)
            .is_none_or(|end| end > self.length)
        {
            return Err(InputError::BeyondTheEnd {
                offset,
                wanted,
                length: self.length,
            });
        }
        let mut reading = self.reading.borrow_mut();
        if offset < reading.window_start {
            *reading = Reading::from_the_start(&self.compressed, self.length);
        }
        let mut filled = 0usize;
        while let Some(rest) = into.get_mut(filled..).filter(|rest| !rest.is_empty()) {
            let at = offset.saturating_add(u64::try_from(filled).unwrap_or(u64::MAX));
            let copied = reading.copy_from(at, rest)?;
            if copied == 0 {
                return Err(InputError::BeyondTheEnd {
                    offset: at,
                    wanted: rest.length(),
                    length: self.length,
                });
            }
            filled = filled.saturating_add(copied);
        }
        Ok(())
    }
}

struct Reading<'o> {
    stream: Stream<'o>,
    window: Vec<u8>,
    window_start: u64,
    window_length: usize,
}

impl<'o> Reading<'o> {
    fn from_the_start(compressed: &Object<'o>, length: u64) -> Self {
        Self {
            stream: Stream::new(compressed.clone(), length),
            window: vec![0u8; DECODED_WINDOW_BYTES],
            window_start: 0,
            window_length: 0,
        }
    }

    fn copy_from(&mut self, at: u64, into: &mut [u8]) -> Result<usize, InputError> {
        loop {
            let window_end = self
                .window_start
                .saturating_add(u64::try_from(self.window_length).unwrap_or(u64::MAX));
            if at < window_end {
                let skip = usize::try_from(at.saturating_sub(self.window_start)).unwrap_or(0);
                let available = self
                    .window
                    .get(skip..self.window_length)
                    .unwrap_or_default();
                let copied = available.len().min(into.len());
                if let (Some(to), Some(from)) = (into.get_mut(..copied), available.get(..copied)) {
                    to.copy_from_slice(from);
                }
                return Ok(copied);
            }
            let produced = self.stream.next_bytes(&mut self.window)?;
            if produced == 0 {
                return Ok(0);
            }
            self.window_start = window_end;
            self.window_length = produced;
        }
    }
}

struct Stream<'o> {
    compressed: Object<'o>,
    decoder: Decompress,
    input: Vec<u8>,
    input_used: usize,
    input_read: u64,
    produced: u64,
    most_produced: u64,
    ended: bool,
    failed: bool,
}

impl<'o> Stream<'o> {
    fn new(compressed: Object<'o>, most_produced: u64) -> Self {
        Self {
            compressed,
            decoder: Decompress::new(false),
            input: Vec::new(),
            input_used: 0,
            input_read: 0,
            produced: 0,
            most_produced,
            ended: false,
            failed: false,
        }
    }

    fn next_bytes(&mut self, into: &mut [u8]) -> Result<usize, InputError> {
        let room = usize::try_from(self.most_produced.saturating_sub(self.produced))
            .unwrap_or(usize::MAX)
            .min(into.len());
        let Some(into) = into.get_mut(..room) else {
            return Ok(0);
        };
        let mut written = 0usize;
        while !self.ended && written < into.len() {
            if self.input_used >= self.input.len() && !self.refill()? {
                self.ended = true;
                break;
            }
            let (Some(input), Some(output)) =
                (self.input.get(self.input_used..), into.get_mut(written..))
            else {
                self.ended = true;
                break;
            };
            let in_before = self.decoder.total_in();
            let out_before = self.decoder.total_out();
            let outcome = self
                .decoder
                .decompress(input, output, FlushDecompress::None);
            let consumed = self.decoder.total_in().saturating_sub(in_before);
            let made = self.decoder.total_out().saturating_sub(out_before);
            self.input_used = self
                .input_used
                .saturating_add(usize::try_from(consumed).unwrap_or(usize::MAX));
            written = written.saturating_add(usize::try_from(made).unwrap_or(usize::MAX));
            match outcome {
                Ok(flate2::Status::Ok) => {}
                Ok(flate2::Status::BufError) if consumed > 0 || made > 0 => {}
                Ok(flate2::Status::StreamEnd | flate2::Status::BufError) => self.ended = true,
                Err(_) => {
                    self.ended = true;
                    self.failed = true;
                }
            }
        }
        self.produced = self
            .produced
            .saturating_add(u64::try_from(written).unwrap_or(u64::MAX));
        Ok(written)
    }

    fn refill(&mut self) -> Result<bool, InputError> {
        let left = self.compressed.length().saturating_sub(self.input_read);
        if left == 0 {
            return Ok(false);
        }
        let take = usize::try_from(left)
            .unwrap_or(usize::MAX)
            .min(COMPRESSED_READ_BYTES);
        self.input.resize(take, 0);
        self.compressed.read_at(self.input_read, &mut self.input)?;
        self.input_read = self
            .input_read
            .saturating_add(u64::try_from(take).unwrap_or(u64::MAX));
        self.input_used = 0;
        Ok(true)
    }
}
