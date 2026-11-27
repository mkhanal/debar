use debar_image::Image;
use debar_matching::{
    DigestNeed, DigestsInProgress, MatchedGroups, ObjectDigests, PatternOutcomes, PatternRequest,
    PatternScan, PatternScanError, ScanEnd, ScanProgress,
};

use crate::object_bytes::{ChunkUse, ObjectBytes, ReadThrough, read_in_chunks};
use crate::report::ScanFailure;

pub(crate) struct OwnBytesMatched {
    pub(crate) outcomes: PatternOutcomes,
    pub(crate) digests_while_read: Option<ObjectDigests>,
}

pub(crate) fn match_own_bytes(
    image: &Image<'_>,
    bytes: &dyn ObjectBytes,
    request: PatternRequest<'_>,
    digest_need: DigestNeed,
    matched_before: &MatchedGroups,
) -> Result<OwnBytesMatched, ScanFailure> {
    let mut scan = PatternScan::reusing(image, request, || None, matched_before)?;
    let mut digesting = (!digest_need.is_empty()).then(|| DigestsInProgress::new(digest_need));
    let mut digests_while_read = None;
    loop {
        if scan.needs_the_bytes() || digesting.is_some() {
            let read_through = feed_the_object(&mut scan, bytes, digesting.as_mut())?;
            if let (Some(digesting), ReadThrough::ToTheEnd) = (digesting.take(), read_through) {
                digests_while_read = Some(digesting.finish());
            }
        } else {
            scan.skip(usize::try_from(bytes.length()).unwrap_or(usize::MAX))?;
        }
        match scan.finish()? {
            ScanEnd::Complete(outcomes) => {
                return Ok(OwnBytesMatched {
                    outcomes,
                    digests_while_read,
                });
            }
            ScanEnd::SecondPassNeeded(second) => scan = *second,
            ScanEnd::WholeObjectNeeded(waiting) => {
                return Ok(OwnBytesMatched {
                    outcomes: waiting.match_whole_object(bytes)?.into_outcomes()?,
                    digests_while_read,
                });
            }
        }
    }
}

fn feed_the_object(
    scan: &mut PatternScan<'_, '_, '_>,
    bytes: &dyn ObjectBytes,
    mut digesting: Option<&mut DigestsInProgress>,
) -> Result<ReadThrough, ScanFailure> {
    let mut refused: Option<PatternScanError> = None;
    let read_through = read_in_chunks(bytes, |chunk| {
        if let Some(digesting) = digesting.as_deref_mut() {
            digesting.update(chunk);
        }
        match scan.feed(chunk) {
            Ok(ScanProgress::Continue) => ChunkUse::Continue,
            Ok(ScanProgress::Stopped) => ChunkUse::Stop,
            Err(error) => {
                refused = Some(error);
                ChunkUse::Stop
            }
        }
    })?;
    if let Some(error) = refused {
        return Err(error.into());
    }
    if let ReadThrough::StoppedAt(offset) = read_through {
        let rest = bytes.length().saturating_sub(offset);
        scan.skip(usize::try_from(rest).unwrap_or(usize::MAX))?;
    }
    Ok(read_through)
}
