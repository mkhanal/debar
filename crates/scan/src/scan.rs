use debar_image::{Image, Indicator, ObjectKind, OwnBytes};
use debar_matching::{
    GroupSelection, ObjectContext, PatternRequest, PatternSettings, Trust, whole_object_detections,
    whole_object_digest_need, whole_object_trust, whole_object_trust_digest_need,
};

use crate::evidence::{Alert, Alerting};
use crate::layers::{Layer, Layers};
use crate::ledger::Ledger;
use crate::object_bytes::ObjectBytes;
use crate::own_bytes::match_own_bytes;
use crate::report::{
    Completion, LayerId, Limit, LimitEvent, Reported, ScanFailure, ScanReport, Verdict,
};
use crate::settings::{Matching, ScanSettings};
use crate::typing::{TypingError, kind_after_full_scan, kind_from_first_bytes};

pub const LARGEST_OBJECT_LEFT_UNSCANNED: u64 = 5;

pub struct FinishedObject<'o> {
    pub layer: LayerId,
    pub parent: Option<LayerId>,
    pub depth: u32,
    pub kind: Option<ObjectKind>,
    pub bytes: &'o dyn ObjectBytes,
}

pub trait ObjectObserver {
    fn object_finished(&mut self, object: &FinishedObject<'_>);
}

pub struct Unobserved;

impl ObjectObserver for Unobserved {
    fn object_finished(&mut self, _object: &FinishedObject<'_>) {}
}

pub fn scan(
    image: &Image<'_>,
    object: &dyn ObjectBytes,
    settings: &ScanSettings<'_>,
    observer: &mut dyn ObjectObserver,
) -> ScanReport {
    let mut scan = Scan {
        image,
        settings,
        ledger: Ledger::new(settings.limits),
        layers: Layers::with_top_level(object),
        reported: Vec::new(),
        limits: Vec::new(),
        observer,
    };
    let completion = match scan.scan_top_level() {
        Ok(Flow::Continue | Flow::Abort) => Completion::Complete,
        Err(failure) => Completion::Incomplete(failure),
    };
    scan.report(completion)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Flow {
    Continue,
    Abort,
}

struct Scan<'i, 'm, 's, 'o, 'b> {
    image: &'i Image<'m>,
    settings: &'s ScanSettings<'s>,
    ledger: Ledger,
    layers: Layers<'o>,
    reported: Vec<Reported>,
    limits: Vec<LimitEvent>,
    observer: &'b mut dyn ObjectObserver,
}

impl<'s, 'o> Scan<'_, '_, 's, 'o, '_> {
    fn scan_top_level(&mut self) -> Result<Flow, ScanFailure> {
        let flow = self.top_level_steps();
        self.finish_layer();
        flow
    }

    fn top_level_steps(&mut self) -> Result<Flow, ScanFailure> {
        let length = self.current().bytes.length();
        if length <= LARGEST_OBJECT_LEFT_UNSCANNED {
            return Ok(Flow::Continue);
        }
        if self
            .settings
            .limits
            .largest_file
            .is_some_and(|largest| length > largest)
        {
            self.record_limit(Limit::LargestFile);
            return Ok(Flow::Continue);
        }
        self.object_steps()
    }

    fn object_steps(&mut self) -> Result<Flow, ScanFailure> {
        let length = self.current().bytes.length();
        if length <= LARGEST_OBJECT_LEFT_UNSCANNED {
            return Ok(Flow::Continue);
        }
        if let Err(limit) = self.ledger.count(length) {
            self.record_limit(limit);
            return Ok(Flow::Continue);
        }
        let kind = self.kind_from_first_bytes()?;
        self.current_mut().kind = Some(kind);
        match self.own_bytes_rule(kind)? {
            OwnBytes::NotMatched => Ok(Flow::Continue),
            OwnBytes::Matched {
                as_kind,
                recognising_types,
            } => {
                let matched_as = as_kind.unwrap_or(kind);
                let selection = if recognising_types {
                    GroupSelection::ForKindRecognisingTypes(matched_as)
                } else {
                    GroupSelection::ForKind(matched_as)
                };
                self.own_bytes(kind, selection)
            }
        }
    }

    fn own_bytes(
        &mut self,
        kind: ObjectKind,
        selection: GroupSelection,
    ) -> Result<Flow, ScanFailure> {
        let length = self.current().bytes.length();
        let hashes = self.settings.hashes();
        let digest_need = whole_object_digest_need(self.image, length, hashes)?;
        let matched = match_own_bytes(
            self.image,
            self.current().bytes,
            self.pattern_request(selection, length),
            digest_need,
        )?;
        if let Some(digests) = matched.digests_while_read {
            self.current_mut().digests = digests;
        }
        let outcomes = matched.outcomes;
        for detection in outcomes.detections {
            if self.alert(detection.name, detection.indicator)? == Flow::Abort {
                return Ok(Flow::Abort);
            }
        }
        let digests = self.current_mut().digests(digest_need)?;
        for detection in whole_object_detections(self.image, length, &digests, hashes)? {
            if self.alert(detection.name, detection.indicator)? == Flow::Abort {
                return Ok(Flow::Abort);
            }
        }
        for detection in outcomes.logical.detections {
            if self.alert(detection.name, detection.indicator)? == Flow::Abort {
                return Ok(Flow::Abort);
            }
        }
        let kind = kind_after_full_scan(self.image, kind, &outcomes.types_found)?;
        self.current_mut().kind = Some(kind);
        Ok(Flow::Continue)
    }

    fn pattern_request(&self, selection: GroupSelection, length: u64) -> PatternRequest<'s> {
        PatternRequest {
            selection,
            settings: PatternSettings {
                potentially_unwanted: self.settings.potentially_unwanted,
                unwanted_categories: self.settings.unwanted_categories,
                every_match: self.settings.matching == Matching::EveryMatch,
                largest_object_for_regular_expressions: self
                    .settings
                    .largest_object_for_regular_expressions,
            },
            object_length: length,
            context: ObjectContext::TOP_LEVEL,
            image_fuzzy_hash: None,
        }
    }

    fn alert(&mut self, name: String, indicator: Indicator) -> Result<Flow, ScanFailure> {
        let alerting = match indicator {
            Indicator::Weak => return Ok(Flow::Continue),
            Indicator::Strong => Alerting::Strong,
            Indicator::PotentiallyUnwanted if self.settings.heuristic_precedence => {
                Alerting::Strong
            }
            Indicator::PotentiallyUnwanted => Alerting::PotentiallyUnwanted,
        };
        if self.trusted_by_a_layer_each_from_the_current_up()? {
            return Ok(Flow::Continue);
        }
        let layer = self.current().id;
        if alerting == Alerting::Strong {
            self.reported.push(Reported {
                name: name.clone(),
                layer,
            });
        }
        self.current_mut().evidence.record(Alert {
            name,
            alerting,
            layer,
        });
        let ends_the_scan =
            alerting == Alerting::Strong && self.settings.matching == Matching::FirstMatch;
        Ok(if ends_the_scan {
            Flow::Abort
        } else {
            Flow::Continue
        })
    }

    fn trusted_by_a_layer_each_from_the_current_up(&mut self) -> Result<bool, ScanFailure> {
        let image = self.image;
        let mut trusted_from = None;
        for layer in self.layers.each_from_the_current_up() {
            let length = layer.bytes.length();
            let need = whole_object_trust_digest_need(image, length)?;
            if need.is_empty() {
                continue;
            }
            let digests = layer.digests(need)?;
            if whole_object_trust(image, length, &digests)? == Trust::Trusted {
                trusted_from = Some(layer.id);
                break;
            }
        }
        if let Some(highest) = trusted_from {
            self.layers.trust_each_from_the_current_up_to(highest);
        }
        Ok(trusted_from.is_some())
    }

    fn kind_from_first_bytes(&self) -> Result<ObjectKind, ScanFailure> {
        let kinds = self.image.object_kinds()?.ok_or(TypingError::NoKinds)?;
        let bytes = self.current().bytes;
        let prefix_length = u64::from(kinds.typing_rules().prefix_length).min(bytes.length());
        let mut first_bytes = vec![0u8; usize::try_from(prefix_length).unwrap_or(0)];
        bytes.read_at(0, &mut first_bytes)?;
        Ok(kind_from_first_bytes(self.image, &first_bytes)?)
    }

    fn own_bytes_rule(&self, kind: ObjectKind) -> Result<OwnBytes, ScanFailure> {
        let kinds = self.image.object_kinds()?.ok_or(TypingError::NoKinds)?;
        Ok(kinds
            .describe(kind)
            .map_err(TypingError::Kinds)?
            .ok_or(ScanFailure::KindNotDescribed(kind))?
            .own_bytes)
    }

    fn record_limit(&mut self, limit: Limit) {
        let layer = self.current().id;
        self.limits.push(LimitEvent { limit, layer });
    }

    fn finish_layer(&mut self) {
        let layer = self.layers.current();
        self.observer.object_finished(&FinishedObject {
            layer: layer.id,
            parent: layer.parent,
            depth: layer.depth,
            kind: layer.kind,
            bytes: layer.bytes,
        });
    }

    fn report(self, completion: Completion) -> ScanReport {
        let top_level = self.layers.top_level();
        let verdict = top_level.verdict();
        let mut reported = self.reported;
        let deferred = top_level
            .evidence
            .potentially_unwanted()
            .map(|alert| Reported {
                name: alert.name.clone(),
                layer: alert.layer,
            });
        match self.settings.matching {
            Matching::EveryMatch => reported.extend(deferred),
            Matching::FirstMatch => {
                if verdict == Verdict::PotentiallyUnwanted {
                    reported.extend(deferred.last());
                }
            }
        }
        ScanReport {
            verdict,
            reported,
            completion,
            limits: self.limits,
        }
    }

    fn current(&self) -> &Layer<'o> {
        self.layers.current()
    }

    fn current_mut(&mut self) -> &mut Layer<'o> {
        self.layers.current_mut()
    }
}
