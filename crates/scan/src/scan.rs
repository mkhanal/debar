use debar_formats::{
    AfterTheEntry, ContainerEntry, ContextOfTheObject, Fact, FormatModule, HeaderCheck, Limit,
    ModuleContext, ModuleError, ModuleOutput, Object, Part, PartBytes, PartOutcome, PartRole,
    Stage,
};
use debar_image::{
    EngineAlert, Image, Indicator, KindView, ObjectKind, OffsetAction, OwnBytes, TypingRules,
};
use debar_matching::{
    GroupSelection, LogicalEvent, MatchedGroups, ObjectContext, PatternDetection, PatternRequest,
    PatternSettings, Trust, TypeFound, container_entry_detections, whole_object_detections,
    whole_object_digest_need, whole_object_trust, whole_object_trust_digest_need,
};

use crate::evidence::{Alert, Alerting};
use crate::format_modules::FormatModules;
use crate::layers::{Arrival, Layer, Layers};
use crate::ledger::Ledger;
use crate::object_bytes::ObjectBytes;
use crate::own_bytes::match_own_bytes;
use crate::report::{
    Completion, LayerId, LimitEvent, ObjectFact, Reported, ScanFailure, ScanReport, Verdict,
};
use crate::settings::{Facts, Matching, ObjectSteps, ScanSettings};
use crate::typing::{TypingError, kind_after_full_scan, kind_from_first_bytes};

pub const LARGEST_OBJECT_LEFT_UNSCANNED: u64 = 5;
pub const MOST_PRODUCED_BYTES_HELD: u64 = 16 * 1024 * 1024;
pub const MOST_UNCOUNTED_MODULE_OUTPUTS: u64 = 100_000;

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
    scan_with_modules(image, object, settings, FormatModules::built_in(), observer)
}

pub fn scan_with_modules(
    image: &Image<'_>,
    object: &dyn ObjectBytes,
    settings: &ScanSettings<'_>,
    modules: FormatModules<'_>,
    observer: &mut dyn ObjectObserver,
) -> ScanReport {
    let mut scan = Scan {
        image,
        settings,
        modules,
        ledger: Ledger::new(settings.limits),
        layers: Layers::with_top_level(object),
        reported: Vec::new(),
        limits: Vec::new(),
        limit_alerted: false,
        facts: Vec::new(),
        produced_held: 0,
        uncounted_outputs: 0,
        uncounted_outputs_allowed: MOST_UNCOUNTED_MODULE_OUTPUTS,
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
    Finished {
        types_found: Vec<TypeFound>,
        matched_groups: MatchedGroups,
    },
    Aborted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Child {
    Scanned,
    Trusted,
    Refused(Limit),
    Aborted,
}

impl Child {
    const fn of_part(self) -> Option<PartOutcome> {
        match self {
            Self::Scanned => Some(PartOutcome::Scanned),
            Self::Trusted => Some(PartOutcome::Trusted),
            Self::Refused(limit) => Some(PartOutcome::Refused(limit)),
            Self::Aborted => None,
        }
    }
}

struct Scan<'i, 'm, 's, 'r, 'o, 'b> {
    image: &'i Image<'m>,
    settings: &'s ScanSettings<'s>,
    modules: FormatModules<'r>,
    ledger: Ledger,
    layers: Layers<'o>,
    reported: Vec<Reported>,
    limits: Vec<LimitEvent>,
    limit_alerted: bool,
    facts: Vec<ObjectFact>,
    produced_held: u64,
    uncounted_outputs: u64,
    uncounted_outputs_allowed: u64,
    observer: &'b mut dyn ObjectObserver,
}

impl<'m, 's, 'r, 'o> Scan<'_, 'm, 's, 'r, 'o, '_> {
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
        given_kind: Option<ObjectKind>,
        bytes: Object<'o>,
    ) -> Result<Child, ScanFailure> {
        if bytes.length() <= LARGEST_OBJECT_LEFT_UNSCANNED {
            return Ok(Child::Scanned);
        }
        if let Some(refused) = self.refused_at_the_push(bytes.length())? {
            return Ok(refused);
        }
        self.layers.push(arrival, bytes);
        let flow = self.object_steps(given_kind);
        self.finish_layer();
        Ok(self.popped_after(flow?))
    }

    fn scan_view(
        &mut self,
        matched_as: ObjectKind,
        bytes: Object<'o>,
    ) -> Result<Child, ScanFailure> {
        if bytes.length() == 0 {
            return Ok(Child::Scanned);
        }
        if let Some(refused) = self.refused_at_the_push(bytes.length())? {
            return Ok(refused);
        }
        self.layers.push(Arrival::View, bytes);
        self.current_mut().kind = Some(matched_as);
        let flow = match self.pass(
            GroupSelection::ForKind(matched_as),
            &MatchedGroups::default(),
        ) {
            Ok(PassEnd::Finished { .. }) => Ok(Flow::Continue),
            Ok(PassEnd::Aborted) => Ok(Flow::Abort),
            Err(failure) => Err(failure),
        };
        Ok(self.popped_after(flow?))
    }

    fn refused_at_the_push(&mut self, length: u64) -> Result<Option<Child>, ScanFailure> {
        let admitted = self
            .ledger
            .admit(length)
            .and_then(|()| self.ledger.admits_a_level_below(self.current().depth));
        let Err(limit) = admitted else {
            return Ok(None);
        };
        Ok(Some(match self.limit_reached(limit)? {
            Flow::Continue => Child::Refused(limit),
            Flow::Abort => Child::Aborted,
        }))
    }

    fn popped_after(&mut self, flow: Flow) -> Child {
        let trusted = self.layers.pop().is_some_and(|popped| popped.trusted);
        match flow {
            Flow::Abort => Child::Aborted,
            Flow::Continue if trusted => Child::Trusted,
            Flow::Continue => Child::Scanned,
        }
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
            None => self.kind_of_the_object()?,
        };
        self.current_mut().kind = Some(kind);
        if self.settings.object_steps == ObjectSteps::RawOnly {
            return self.raw_only_pass();
        }
        if self.run_modules(kind, Stage::BeforeOwnBytes)? == Flow::Abort {
            return Ok(Flow::Abort);
        }
        let PassEnd::Finished { matched_groups, .. } = self.own_bytes(kind)? else {
            return Ok(Flow::Abort);
        };
        if self.extra_pass(kind, &matched_groups)? == Flow::Abort {
            return Ok(Flow::Abort);
        }
        self.run_modules(kind, Stage::AfterOwnBytes)
    }

    fn raw_only_pass(&mut self) -> Result<Flow, ScanFailure> {
        Ok(
            match self.pass(
                GroupSelection::ForKind(ObjectKind::Untyped),
                &MatchedGroups::default(),
            )? {
                PassEnd::Finished { .. } => Flow::Continue,
                PassEnd::Aborted => Flow::Abort,
            },
        )
    }

    fn run_modules(&mut self, kind: ObjectKind, stage: Stage) -> Result<Flow, ScanFailure> {
        for module in self.modules.for_kind(kind, stage) {
            if self.run_module(module)? == Flow::Abort {
                return Ok(Flow::Abort);
            }
        }
        Ok(Flow::Continue)
    }

    fn run_module(&mut self, module: &'r dyn FormatModule) -> Result<Flow, ScanFailure> {
        let object = self.current().bytes.clone();
        self.uncounted_outputs_allowed = self
            .uncounted_outputs_allowed
            .saturating_add(object.length());
        let mut context = self.module_context(None);
        let opened = module.open(object, &mut context);
        if self.limits_the_module_reached(context)? == Flow::Abort {
            return Ok(Flow::Abort);
        }
        let mut parts = match opened {
            Ok(parts) => parts,
            Err(error) => return self.module_stopped(error),
        };
        let mut last_part = None;
        loop {
            let mut context = self.module_context(last_part);
            let output = parts.next(&mut context);
            if self.limits_the_module_reached(context)? == Flow::Abort {
                return Ok(Flow::Abort);
            }
            if let Ok(Some(output)) = &output {
                self.count_uncounted(output)?;
            }
            let flow = match output {
                Ok(None) => return Ok(Flow::Continue),
                Err(error) => return self.module_stopped(error),
                Ok(Some(ModuleOutput::Part(part))) => {
                    let child = self.scan_part(part)?;
                    last_part = child.of_part();
                    if child == Child::Aborted {
                        Flow::Abort
                    } else {
                        Flow::Continue
                    }
                }
                Ok(Some(ModuleOutput::Entry(entry))) => {
                    self.container_entry(self.current_kind(), &entry)?
                }
                Ok(Some(ModuleOutput::Fact(fact))) => self.module_fact(fact)?,
            };
            if flow == Flow::Abort {
                return Ok(Flow::Abort);
            }
        }
    }

    fn count_uncounted(&mut self, output: &ModuleOutput<'_>) -> Result<(), ScanFailure> {
        if let ModuleOutput::Part(Part {
            role: PartRole::Child { .. },
            ..
        }) = output
        {
            return Ok(());
        }
        self.uncounted_outputs = self.uncounted_outputs.saturating_add(1);
        if self.uncounted_outputs > self.uncounted_outputs_allowed {
            return Err(ScanFailure::ModuleOutputsBeyondBound {
                most: self.uncounted_outputs_allowed,
            });
        }
        Ok(())
    }

    fn module_context(&self, last_part: Option<PartOutcome>) -> ModuleContext {
        ModuleContext::new(
            ContextOfTheObject {
                room: self.ledger.room(),
                room_to_produce: MOST_PRODUCED_BYTES_HELD.saturating_sub(self.produced_held),
                most_files: self.settings.limits.most_files,
                deepest_level: self.settings.limits.deepest_level,
                found_inside_another: self.current().arrival == Arrival::Embedded,
                facts_wanted: self.settings.facts == Facts::Gathered,
            },
            last_part,
        )
    }

    fn limits_the_module_reached(&mut self, context: ModuleContext) -> Result<Flow, ScanFailure> {
        for limit in context.into_refusals() {
            if self.limit_reached(limit)? == Flow::Abort {
                return Ok(Flow::Abort);
            }
        }
        Ok(Flow::Continue)
    }

    fn module_stopped(&mut self, error: ModuleError) -> Result<Flow, ScanFailure> {
        match error {
            ModuleError::Input(error) => Err(ScanFailure::Input(error)),
            ModuleError::Damaged { at } => {
                self.record_fact(Fact::BrokenStructure { at });
                Ok(Flow::Continue)
            }
        }
    }

    fn scan_part(&mut self, part: Part<'o>) -> Result<Child, ScanFailure> {
        let (bytes, produced) = self.part_bytes(part.bytes)?;
        self.produced_held = self.produced_held.saturating_add(produced);
        let child = match part.role {
            PartRole::Child { kind } => self.scan_child(Arrival::Part, kind, bytes),
            PartRole::View { matched_as } => self.scan_view(matched_as, bytes),
        };
        self.produced_held = self.produced_held.saturating_sub(produced);
        child
    }

    fn part_bytes(&self, bytes: PartBytes<'o>) -> Result<(Object<'o>, u64), ScanFailure> {
        match bytes {
            PartBytes::Window { offset, length } => {
                let object = &self.current().bytes;
                let window =
                    object
                        .window(offset, length)
                        .ok_or(ScanFailure::PartOutsideItsObject {
                            offset,
                            length,
                            object_length: object.length(),
                        })?;
                Ok((window, 0))
            }
            PartBytes::Produced(produced) => {
                let length = ObjectBytes::length(produced.as_slice());
                let room = MOST_PRODUCED_BYTES_HELD.saturating_sub(self.produced_held);
                if length > room {
                    return Err(ScanFailure::ProducedBeyondRoom { length, room });
                }
                Ok((Object::held(produced), length))
            }
            PartBytes::Regenerable(producer) => Ok((Object::regenerable(producer), 0)),
        }
    }

    fn current_kind(&self) -> ObjectKind {
        self.current().kind.unwrap_or(ObjectKind::Untyped)
    }

    fn container_entry(
        &mut self,
        container: ObjectKind,
        entry: &ContainerEntry,
    ) -> Result<Flow, ScanFailure> {
        let tested = debar_matching::ContainerEntry {
            container,
            container_size: self.current().bytes.length(),
            name: entry.name.as_deref(),
            compressed_size: entry.compressed_size,
            real_size: entry.real_size,
            encrypted: entry.encrypted,
            position: entry.position,
        };
        let every_match = self.settings.matching == Matching::EveryMatch;
        for detection in container_entry_detections(self.image, &tested, every_match)? {
            if self.alert(detection.name, detection.indicator)? == Flow::Abort {
                return Ok(Flow::Abort);
            }
        }
        Ok(Flow::Continue)
    }

    fn module_fact(&mut self, fact: Fact) -> Result<Flow, ScanFailure> {
        self.record_fact(fact);
        let Some(alert) = alerted_for(fact) else {
            return Ok(Flow::Continue);
        };
        let Some(name) = self.image.engine_alert_name(alert)? else {
            return Ok(Flow::Continue);
        };
        self.alert(name.text, name.indicator)
    }

    fn record_fact(&mut self, fact: Fact) {
        let found = ObjectFact {
            layer: self.current().id,
            fact,
        };
        if self.settings.facts == Facts::Gathered && !self.facts.contains(&found) {
            self.facts.push(found);
        }
    }

    fn own_bytes(&mut self, kind: ObjectKind) -> Result<PassEnd, ScanFailure> {
        let OwnBytes::Matched {
            as_kind,
            recognising_types,
        } = self.description(kind)?.own_bytes
        else {
            return Ok(PassEnd::Finished {
                types_found: Vec::new(),
                matched_groups: MatchedGroups::default(),
            });
        };
        let matched_as = as_kind.unwrap_or(kind);
        let selection = if recognising_types && self.current().arrival != Arrival::Embedded {
            GroupSelection::ForKindRecognisingTypes(matched_as)
        } else {
            GroupSelection::ForKind(matched_as)
        };
        let PassEnd::Finished {
            types_found,
            matched_groups,
        } = self.pass(selection, &MatchedGroups::default())?
        else {
            return Ok(PassEnd::Aborted);
        };
        if self.found_at_offsets(kind, &types_found)? == Flow::Abort {
            return Ok(PassEnd::Aborted);
        }
        let found_kind = kind_after_full_scan(self.image, kind, &types_found)?;
        if found_kind != kind && self.retype(found_kind)? == Flow::Abort {
            return Ok(PassEnd::Aborted);
        }
        Ok(PassEnd::Finished {
            types_found,
            matched_groups,
        })
    }

    fn found_at_offsets(
        &mut self,
        passed_as: ObjectKind,
        types_found: &[TypeFound],
    ) -> Result<Flow, ScanFailure> {
        let most_recorded = u64::from(self.typing_rules()?.most_found_at_offsets);
        let mut recorded = 0u64;
        let mut last_taken = 0u64;
        for found in types_found {
            let description = self.description(found.kind)?;
            let Some(action) = description.offset_action else {
                continue;
            };
            let cap = match action {
                OffsetAction::Embedded(embedded) if embedded.recorded_up_to_the_file_count => {
                    self.settings.limits.most_files
                }
                OffsetAction::Recorded
                | OffsetAction::RetypesTheObject
                | OffsetAction::Embedded(_) => Some(most_recorded),
            };
            if cap.is_some_and(|cap| recorded >= cap) {
                continue;
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
                    if description.acts_in(current_kind) && self.retype(found.kind)? == Flow::Abort
                    {
                        return Ok(Flow::Abort);
                    }
                }
                OffsetAction::Embedded(embedded) => {
                    let before = u64::from(embedded.starts_before_the_match);
                    if !description.acts_in(passed_as) || found.offset <= before {
                        continue;
                    }
                    let Some(from) = self
                        .current()
                        .bytes
                        .onward_from(found.offset.saturating_sub(before))
                    else {
                        continue;
                    };
                    let host_kind = self.current_kind();
                    let modules = self.modules;
                    let mut tested = Ok(Flow::Continue);
                    let check = modules.header_check(embedded.scanned_as, &from, &mut |entry| {
                        self.entry_tested_while(host_kind, &entry, &mut tested)
                    });
                    if tested? == Flow::Abort {
                        return Ok(Flow::Abort);
                    }
                    let bytes = match check {
                        Ok(HeaderCheck::NotNeeded) => from,
                        Ok(HeaderCheck::Fails) | Err(ModuleError::Damaged { .. }) => continue,
                        Err(ModuleError::Input(error)) => return Err(error.into()),
                        Ok(HeaderCheck::Holds { length }) => {
                            last_taken = end_of_checked_header(found.offset, length);
                            checked_extent(from, length)
                        }
                    };
                    if self.scan_child(Arrival::Embedded, Some(embedded.scanned_as), bytes)?
                        == Child::Aborted
                    {
                        return Ok(Flow::Abort);
                    }
                }
            }
        }
        Ok(Flow::Continue)
    }

    fn retype(&mut self, kind: ObjectKind) -> Result<Flow, ScanFailure> {
        self.current_mut().kind = Some(kind);
        self.run_modules(kind, Stage::BeforeOwnBytes)
    }

    fn extra_pass(
        &mut self,
        typed_from_first_bytes: ObjectKind,
        matched_before: &MatchedGroups,
    ) -> Result<Flow, ScanFailure> {
        let Some(again_as) = self.description(typed_from_first_bytes)?.matched_again_as else {
            return Ok(Flow::Continue);
        };
        Ok(
            match self.pass(GroupSelection::ForKind(again_as), matched_before)? {
                PassEnd::Finished { .. } => Flow::Continue,
                PassEnd::Aborted => Flow::Abort,
            },
        )
    }

    fn pass(
        &mut self,
        selection: GroupSelection,
        matched_before: &MatchedGroups,
    ) -> Result<PassEnd, ScanFailure> {
        let bytes = self.current().bytes.clone();
        let length = bytes.length();
        let hashes = self.settings.hashes();
        let digest_need = whole_object_digest_need(self.image, length, hashes)?;
        let ancestors = self.layers.ancestor_kinds();
        let context = ObjectContext {
            ancestors: &ancestors,
            retyped: self.current().arrival == Arrival::Retyped,
        };
        let missing_digests = self.current().digests.missing_from(digest_need);
        let matched = match_own_bytes(
            self.image,
            &bytes,
            self.pattern_request(selection, length, context),
            missing_digests,
            matched_before,
            self.ledger.work(),
        )?;
        if self.ledger.scan_time_spent() {
            return self.stopped_by_the_scan_time_limit(matched.outcomes.detections);
        }
        if let Some(digests) = matched.digests_while_read {
            let layer = self.current_mut();
            layer.digests = layer.digests.joined_with(digests);
        }
        let mut outcomes = matched.outcomes;
        let matched_groups = std::mem::take(&mut outcomes.matched_groups);
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
                LogicalEvent::Rescan(kind) => {
                    self.scan_child(Arrival::Retyped, Some(kind), bytes.clone())?
                }
                LogicalEvent::ProgramTrigger(_) => Child::Scanned,
            };
            match child {
                Child::Scanned | Child::Trusted => {}
                Child::Aborted => return Ok(PassEnd::Aborted),
                Child::Refused(_) => {
                    return Ok(PassEnd::Finished {
                        types_found: Vec::new(),
                        matched_groups,
                    });
                }
            }
        }
        Ok(PassEnd::Finished {
            types_found: outcomes.types_found,
            matched_groups,
        })
    }

    fn stopped_by_the_scan_time_limit(
        &mut self,
        found_before: Vec<PatternDetection>,
    ) -> Result<PassEnd, ScanFailure> {
        for detection in found_before {
            if self.alert(detection.name, detection.indicator)? == Flow::Abort {
                return Ok(PassEnd::Aborted);
            }
        }
        self.limit_reached(Limit::ScanTime)?;
        Ok(PassEnd::Aborted)
    }

    fn pattern_request<'q>(
        &self,
        selection: GroupSelection,
        length: u64,
        context: ObjectContext<'q>,
    ) -> PatternRequest<'q>
    where
        's: 'q,
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
        let object = self.layers.nearest_object();
        if alerting == Alerting::Strong {
            self.reported.push(Reported {
                name: name.clone(),
                layer,
                object,
            });
        }
        self.current_mut().evidence.record(Alert {
            name,
            alerting,
            layer,
            object,
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
        let reached = LimitEvent {
            limit,
            layer: self.current().id,
        };
        if !self.limits.contains(&reached) {
            self.limits.push(reached);
        }
        self.layers.mark_each_from_the_current_up_not_to_be_cached();
        let flow = self.alert_the_limit(limit)?;
        Ok(match limit {
            Limit::ScanTime => Flow::Abort,
            Limit::LargestFile | Limit::LargestScan | Limit::MostFiles | Limit::DeepestLevel => {
                flow
            }
        })
    }

    fn alert_the_limit(&mut self, limit: Limit) -> Result<Flow, ScanFailure> {
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

    fn kind_of_the_object(&mut self) -> Result<ObjectKind, ScanFailure> {
        let typed = self.kind_from_first_bytes()?;
        let bytes = self.current().bytes.clone();
        let modules = self.modules;
        let mut tested = Ok(Flow::Continue);
        let refined = modules.refined_kind(typed, &bytes, &mut |entry| {
            self.entry_tested_while(ObjectKind::Untyped, &entry, &mut tested)
        });
        tested?;
        match refined {
            Ok(refined) => Ok(refined.unwrap_or(typed)),
            Err(ModuleError::Damaged { .. }) => Ok(typed),
            Err(ModuleError::Input(error)) => Err(error.into()),
        }
    }

    fn entry_tested_while(
        &mut self,
        container: ObjectKind,
        entry: &ContainerEntry,
        tested: &mut Result<Flow, ScanFailure>,
    ) -> AfterTheEntry {
        if matches!(tested, Ok(Flow::Continue)) {
            *tested = self.container_entry(container, entry);
        }
        match tested {
            Ok(Flow::Continue) => AfterTheEntry::GoOn,
            Ok(Flow::Abort) | Err(_) => AfterTheEntry::Stop,
        }
    }

    fn kind_from_first_bytes(&self) -> Result<ObjectKind, ScanFailure> {
        let bytes = &self.current().bytes;
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
                object: alert.object,
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
            facts: self.facts,
            work_spent: self.ledger.work_spent(),
        }
    }

    fn current(&self) -> &Layer<'o> {
        self.layers.current()
    }

    fn current_mut(&mut self) -> &mut Layer<'o> {
        self.layers.current_mut()
    }
}

fn end_of_checked_header(offset: u64, length: u64) -> u64 {
    match length.checked_sub(1) {
        Some(after_the_first_byte) => offset.saturating_add(after_the_first_byte),
        None => offset.saturating_sub(1),
    }
}

fn checked_extent(from: Object<'_>, length: u64) -> Object<'_> {
    if length == 0 {
        return from;
    }
    let within = length.min(from.length());
    from.window(0, within).unwrap_or(from)
}

const fn alerted_for(fact: Fact) -> Option<EngineAlert> {
    match fact {
        Fact::OverlappingParts => Some(EngineAlert::OverlappingParts),
        Fact::Macros(_)
        | Fact::Script(_)
        | Fact::ExecutableContent
        | Fact::Encrypted { .. }
        | Fact::DocumentAction(_)
        | Fact::ExternalLink
        | Fact::KindDisagreesWithName
        | Fact::Expansion { .. }
        | Fact::BrokenStructure { .. }
        | Fact::Unsupported(_) => None,
    }
}

const fn exceeded(limit: Limit) -> EngineAlert {
    match limit {
        Limit::ScanTime => EngineAlert::ScanTimeLimitExceeded,
        Limit::LargestScan => EngineAlert::ScanSizeLimitExceeded,
        Limit::LargestFile => EngineAlert::FileSizeLimitExceeded,
        Limit::MostFiles => EngineAlert::FileCountLimitExceeded,
        Limit::DeepestLevel => EngineAlert::RecursionLimitExceeded,
    }
}
