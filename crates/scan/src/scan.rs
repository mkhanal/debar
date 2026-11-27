use debar_image::{
    EngineAlert, Image, Indicator, KindView, ObjectKind, OffsetAction, OwnBytes, TypingRules,
};
use debar_matching::{
    GroupSelection, LogicalEvent, ObjectContext, PatternRequest, PatternSettings, Trust, TypeFound,
    whole_object_detections, whole_object_digest_need, whole_object_trust,
    whole_object_trust_digest_need,
};

use crate::evidence::{Alert, Alerting};
use crate::layers::{Arrival, Layer, Layers};
use crate::ledger::Ledger;
use crate::object_bytes::{ObjectBytes, ObjectWindow};
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
    pub cacheable: bool,
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
        limit_alerted: false,
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

enum PassEnd {
    Finished { types_found: Vec<TypeFound> },
    Aborted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Child {
    Scanned,
    Refused,
    Aborted,
}

struct Scan<'i, 'm, 's, 'o, 'b> {
    image: &'i Image<'m>,
    settings: &'s ScanSettings<'s>,
    ledger: Ledger,
    layers: Layers<'o>,
    reported: Vec<Reported>,
    limits: Vec<LimitEvent>,
    limit_alerted: bool,
    observer: &'b mut dyn ObjectObserver,
}

impl<'m, 's, 'o> Scan<'_, 'm, 's, 'o, '_> {
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
            return self.limit_reached(Limit::LargestFile);
        }
        self.object_steps(None)
    }

    fn scan_child(
        &mut self,
        arrival: Arrival,
        given_kind: ObjectKind,
        bytes: ObjectWindow<'o>,
    ) -> Result<Child, ScanFailure> {
        if bytes.length() <= LARGEST_OBJECT_LEFT_UNSCANNED {
            return Ok(Child::Scanned);
        }
        let admitted = self
            .ledger
            .admit(bytes.length())
            .and_then(|()| self.ledger.admits_a_level_below(self.current().depth));
        if let Err(limit) = admitted {
            return Ok(match self.limit_reached(limit)? {
                Flow::Continue => Child::Refused,
                Flow::Abort => Child::Aborted,
            });
        }
        self.layers.push(arrival, bytes);
        let flow = self.object_steps(Some(given_kind));
        self.finish_layer();
        self.layers.pop();
        Ok(match flow? {
            Flow::Continue => Child::Scanned,
            Flow::Abort => Child::Aborted,
        })
    }

    fn object_steps(&mut self, given_kind: Option<ObjectKind>) -> Result<Flow, ScanFailure> {
        let length = self.current().bytes.length();
        if length <= LARGEST_OBJECT_LEFT_UNSCANNED {
            return Ok(Flow::Continue);
        }
        if let Err(limit) = self.ledger.count(length) {
            return self.limit_reached(limit);
        }
        let kind = match given_kind {
            Some(kind) => kind,
            None => self.kind_from_first_bytes()?,
        };
        self.current_mut().kind = Some(kind);
        if self.own_bytes(kind)? == Flow::Abort {
            return Ok(Flow::Abort);
        }
        self.extra_pass(kind)
    }

    fn own_bytes(&mut self, kind: ObjectKind) -> Result<Flow, ScanFailure> {
        let OwnBytes::Matched {
            as_kind,
            recognising_types,
        } = self.description(kind)?.own_bytes
        else {
            return Ok(Flow::Continue);
        };
        let matched_as = as_kind.unwrap_or(kind);
        let selection = if recognising_types && self.current().arrival != Arrival::Embedded {
            GroupSelection::ForKindRecognisingTypes(matched_as)
        } else {
            GroupSelection::ForKind(matched_as)
        };
        let PassEnd::Finished { types_found } = self.pass(selection)? else {
            return Ok(Flow::Abort);
        };
        if self.found_at_offsets(kind, &types_found)? == Flow::Abort {
            return Ok(Flow::Abort);
        }
        let found_kind = kind_after_full_scan(self.image, kind, &types_found)?;
        if found_kind != kind {
            self.current_mut().kind = Some(found_kind);
        }
        Ok(Flow::Continue)
    }

    fn found_at_offsets(
        &mut self,
        passed_as: ObjectKind,
        types_found: &[TypeFound],
    ) -> Result<Flow, ScanFailure> {
        let most_recorded = self.typing_rules()?.most_found_at_offsets;
        let mut recorded = 0u32;
        let mut last_taken = 0u64;
        for found in types_found {
            let description = self.description(found.kind)?;
            let Some(action) = description.offset_action else {
                continue;
            };
            if recorded >= most_recorded {
                break;
            }
            recorded = recorded.saturating_add(1);
            if found.offset <= last_taken {
                continue;
            }
            last_taken = found.offset;
            let current_kind = self.current().kind.unwrap_or(passed_as);
            match action {
                OffsetAction::Recorded => {}
                OffsetAction::RetypesTheObject => {
                    if description.acts_in(current_kind) {
                        self.current_mut().kind = Some(found.kind);
                    }
                }
                OffsetAction::Embedded(embedded) => {
                    let before = u64::from(embedded.starts_before_the_match);
                    if !description.acts_in(passed_as) || found.offset <= before {
                        continue;
                    }
                    let Some(bytes) = self
                        .current()
                        .bytes
                        .onward_from(found.offset.saturating_sub(before))
                    else {
                        continue;
                    };
                    if self.scan_child(Arrival::Embedded, embedded.scanned_as, bytes)?
                        == Child::Aborted
                    {
                        return Ok(Flow::Abort);
                    }
                }
            }
        }
        Ok(Flow::Continue)
    }

    fn extra_pass(&mut self, typed_from_first_bytes: ObjectKind) -> Result<Flow, ScanFailure> {
        let Some(again_as) = self.description(typed_from_first_bytes)?.matched_again_as else {
            return Ok(Flow::Continue);
        };
        Ok(match self.pass(GroupSelection::ForKind(again_as))? {
            PassEnd::Finished { .. } => Flow::Continue,
            PassEnd::Aborted => Flow::Abort,
        })
    }

    fn pass(&mut self, selection: GroupSelection) -> Result<PassEnd, ScanFailure> {
        let bytes = self.current().bytes;
        let length = bytes.length();
        let hashes = self.settings.hashes();
        let digest_need = whole_object_digest_need(self.image, length, hashes)?;
        let ancestors = self.layers.ancestor_kinds();
        let context = ObjectContext {
            ancestors: &ancestors,
            retyped: self.current().arrival == Arrival::Retyped,
        };
        let matched = match_own_bytes(
            self.image,
            &bytes,
            self.pattern_request(selection, length, context),
            self.current().digests.missing_from(digest_need),
        )?;
        if let Some(digests) = matched.digests_while_read {
            let layer = self.current_mut();
            layer.digests = layer.digests.joined_with(digests);
        }
        let outcomes = matched.outcomes;
        if outcomes.logical.do_not_cache {
            self.current_mut().do_not_cache = true;
        }
        for detection in outcomes.detections {
            if self.alert(detection.name, detection.indicator)? == Flow::Abort {
                return Ok(PassEnd::Aborted);
            }
        }
        let digests = self.current_mut().digests(digest_need)?;
        for detection in whole_object_detections(self.image, length, &digests, hashes)? {
            if self.alert(detection.name, detection.indicator)? == Flow::Abort {
                return Ok(PassEnd::Aborted);
            }
        }
        for event in outcomes.logical.events {
            let child = match event {
                LogicalEvent::Detection(detection) => {
                    match self.alert(detection.name, detection.indicator)? {
                        Flow::Continue => Child::Scanned,
                        Flow::Abort => Child::Aborted,
                    }
                }
                LogicalEvent::Rescan(kind) => self.scan_child(Arrival::Retyped, kind, bytes)?,
                LogicalEvent::ProgramTrigger(_) => Child::Scanned,
            };
            match child {
                Child::Scanned => {}
                Child::Aborted => return Ok(PassEnd::Aborted),
                Child::Refused => {
                    return Ok(PassEnd::Finished {
                        types_found: Vec::new(),
                    });
                }
            }
        }
        Ok(PassEnd::Finished {
            types_found: outcomes.types_found,
        })
    }

    fn pattern_request<'r>(
        &self,
        selection: GroupSelection,
        length: u64,
        context: ObjectContext<'r>,
    ) -> PatternRequest<'r>
    where
        's: 'r,
    {
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
            context,
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

    fn limit_reached(&mut self, limit: Limit) -> Result<Flow, ScanFailure> {
        let layer = self.current().id;
        self.limits.push(LimitEvent { limit, layer });
        self.layers.mark_each_from_the_current_up_not_to_be_cached();
        if !self.settings.alert_on_limits || self.limit_alerted {
            return Ok(Flow::Continue);
        }
        self.limit_alerted = true;
        let Some(name) = self.image.engine_alert_name(exceeded(limit))? else {
            return Ok(Flow::Continue);
        };
        self.alert(name.text, name.indicator)
    }

    fn typing_rules(&self) -> Result<TypingRules, ScanFailure> {
        let kinds = self.image.object_kinds()?.ok_or(TypingError::NoKinds)?;
        Ok(kinds.typing_rules())
    }

    fn kind_from_first_bytes(&self) -> Result<ObjectKind, ScanFailure> {
        let bytes = self.current().bytes;
        let prefix_length = u64::from(self.typing_rules()?.prefix_length).min(bytes.length());
        let mut first_bytes = vec![0u8; usize::try_from(prefix_length).unwrap_or(0)];
        bytes.read_at(0, &mut first_bytes)?;
        Ok(kind_from_first_bytes(self.image, &first_bytes)?)
    }

    fn description(&self, kind: ObjectKind) -> Result<KindView<'m>, ScanFailure> {
        let kinds = self.image.object_kinds()?.ok_or(TypingError::NoKinds)?;
        kinds
            .describe(kind)
            .map_err(TypingError::Kinds)?
            .ok_or(ScanFailure::KindNotDescribed(kind))
    }

    fn finish_layer(&mut self) {
        let layer = self.layers.current();
        self.observer.object_finished(&FinishedObject {
            layer: layer.id,
            parent: layer.parent,
            depth: layer.depth,
            kind: layer.kind,
            cacheable: !layer.do_not_cache,
            bytes: &layer.bytes,
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

const fn exceeded(limit: Limit) -> EngineAlert {
    match limit {
        Limit::LargestScan => EngineAlert::ScanSizeLimitExceeded,
        Limit::LargestFile => EngineAlert::FileSizeLimitExceeded,
        Limit::MostFiles => EngineAlert::FileCountLimitExceeded,
        Limit::DeepestLevel => EngineAlert::RecursionLimitExceeded,
    }
}
