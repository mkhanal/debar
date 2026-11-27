use flate2::{Decompress, FlushDecompress, Status};

use crate::pdf::filters::first_attempt::{FirstAttempt, Inflater, Inflation, LoneReturn};

const OUTPUT_STEP_BYTES: usize = 32 * 1024;
const ZLIB_HEADER: bool = true;

pub type Flate = FirstAttempt<ZlibInflater>;

pub fn flate(limit: Option<u64>) -> Flate {
    FirstAttempt::new(ZlibInflater::new(), LoneReturn::KeptAsDecoded, limit)
}

pub struct ZlibInflater {
    decompress: Decompress,
    step: Vec<u8>,
}

impl ZlibInflater {
    fn new() -> Self {
        Self {
            decompress: Decompress::new(ZLIB_HEADER),
            step: vec![0; OUTPUT_STEP_BYTES],
        }
    }
}

impl Inflater for ZlibInflater {
    fn restart(&mut self) {
        self.decompress.reset(ZLIB_HEADER);
    }

    fn inflate(&mut self, input: &[u8], output: &mut Vec<u8>) -> (usize, Inflation) {
        let read_before = self.decompress.total_in();
        let written_before = self.decompress.total_out();
        let result = self
            .decompress
            .decompress(input, &mut self.step, FlushDecompress::None);
        let consumed = usize::try_from(self.decompress.total_in().saturating_sub(read_before))
            .unwrap_or(usize::MAX)
            .min(input.len());
        let produced = usize::try_from(self.decompress.total_out().saturating_sub(written_before))
            .unwrap_or(usize::MAX);
        output.extend_from_slice(self.step.get(..produced).unwrap_or_default());
        let inflation = match result {
            Ok(Status::StreamEnd) => Inflation::Ended,
            Err(_) => Inflation::Broken,
            Ok(Status::Ok | Status::BufError) if consumed == 0 && produced == 0 => {
                Inflation::WantsInput
            }
            Ok(Status::Ok | Status::BufError) => Inflation::Producing,
        };
        (consumed, inflation)
    }
}
