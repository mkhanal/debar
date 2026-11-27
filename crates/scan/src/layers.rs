use debar_image::ObjectKind;
use debar_matching::{DigestNeed, ObjectDigests};
use debar_platform::input::InputError;

use crate::evidence::Evidence;
use crate::object_bytes::{ObjectBytes, ObjectWindow, digests_of};
use crate::report::{LayerId, Verdict};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Arrival {
    TopLevel,
    Embedded,
    Retyped,
}

pub(crate) struct Layer<'o> {
    pub(crate) id: LayerId,
    pub(crate) parent: Option<LayerId>,
    pub(crate) depth: u32,
    pub(crate) arrival: Arrival,
    pub(crate) kind: Option<ObjectKind>,
    pub(crate) bytes: ObjectWindow<'o>,
    pub(crate) evidence: Evidence,
    pub(crate) trusted: bool,
    pub(crate) do_not_cache: bool,
    pub(crate) digests: ObjectDigests,
}

impl<'o> Layer<'o> {
    fn new(id: LayerId, parent: Option<&Self>, arrival: Arrival, bytes: ObjectWindow<'o>) -> Self {
        Self {
            id,
            parent: parent.map(|parent| parent.id),
            depth: parent.map_or(0, |parent| parent.depth.saturating_add(1)),
            arrival,
            kind: None,
            bytes,
            evidence: Evidence::default(),
            trusted: false,
            do_not_cache: false,
            digests: ObjectDigests::default(),
        }
    }

    pub(crate) fn verdict(&self) -> Verdict {
        if self.trusted {
            Verdict::Trusted
        } else {
            self.evidence.verdict()
        }
    }

    pub(crate) fn digests(&mut self, need: DigestNeed) -> Result<ObjectDigests, InputError> {
        let missing = self.digests.missing_from(need);
        if !missing.is_empty() {
            self.digests = self.digests.joined_with(digests_of(&self.bytes, missing)?);
        }
        Ok(self.digests)
    }

    fn trust(&mut self) {
        self.trusted = true;
        self.evidence.clear();
    }
}

pub(crate) struct Layers<'o> {
    top_level: Layer<'o>,
    nested: Vec<Layer<'o>>,
    pushed: u64,
}

impl<'o> Layers<'o> {
    pub(crate) fn with_top_level(bytes: &'o dyn ObjectBytes) -> Self {
        Self {
            top_level: Layer::new(
                LayerId(0),
                None,
                Arrival::TopLevel,
                ObjectWindow::whole(bytes),
            ),
            nested: Vec::new(),
            pushed: 0,
        }
    }

    pub(crate) fn top_level(&self) -> &Layer<'o> {
        &self.top_level
    }

    pub(crate) fn current(&self) -> &Layer<'o> {
        self.nested.last().unwrap_or(&self.top_level)
    }

    pub(crate) fn current_mut(&mut self) -> &mut Layer<'o> {
        self.nested.last_mut().unwrap_or(&mut self.top_level)
    }

    pub(crate) fn push(&mut self, arrival: Arrival, bytes: ObjectWindow<'o>) {
        self.pushed = self.pushed.saturating_add(1);
        let child = Layer::new(LayerId(self.pushed), Some(self.current()), arrival, bytes);
        self.nested.push(child);
    }

    pub(crate) fn pop(&mut self) -> Option<Layer<'o>> {
        let mut popped = self.nested.pop()?;
        if !popped.trusted {
            let evidence = std::mem::take(&mut popped.evidence);
            self.current_mut().evidence.merge(evidence);
        }
        Some(popped)
    }

    pub(crate) fn ancestor_kinds(&self) -> Vec<ObjectKind> {
        let below_current = self.nested.len().saturating_sub(1);
        self.nested
            .iter()
            .take(below_current)
            .rev()
            .chain((!self.nested.is_empty()).then_some(&self.top_level))
            .map(|layer| layer.kind.unwrap_or(ObjectKind::Untyped))
            .collect()
    }

    pub(crate) fn each_from_the_current_up(&mut self) -> impl Iterator<Item = &mut Layer<'o>> {
        self.nested
            .iter_mut()
            .rev()
            .chain(std::iter::once(&mut self.top_level))
    }

    pub(crate) fn trust_each_from_the_current_up_to(&mut self, highest: LayerId) {
        for layer in self.each_from_the_current_up() {
            layer.trust();
            if layer.id == highest {
                break;
            }
        }
    }

    pub(crate) fn mark_each_from_the_current_up_not_to_be_cached(&mut self) {
        for layer in self.each_from_the_current_up() {
            layer.do_not_cache = true;
        }
    }
}
