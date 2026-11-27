use debar_image::ObjectKind;
use debar_matching::{DigestNeed, ObjectDigests};
use debar_platform::input::InputError;

use crate::evidence::Evidence;
use crate::object_bytes::{ObjectBytes, digests_of};
use crate::report::{LayerId, Verdict};

pub(crate) struct Layer<'o> {
    pub(crate) id: LayerId,
    pub(crate) parent: Option<LayerId>,
    pub(crate) depth: u32,
    pub(crate) kind: Option<ObjectKind>,
    pub(crate) bytes: &'o dyn ObjectBytes,
    pub(crate) evidence: Evidence,
    pub(crate) trusted: bool,
    pub(crate) digests: ObjectDigests,
}

impl<'o> Layer<'o> {
    fn new(id: LayerId, parent: Option<LayerId>, depth: u32, bytes: &'o dyn ObjectBytes) -> Self {
        Self {
            id,
            parent,
            depth,
            kind: None,
            bytes,
            evidence: Evidence::default(),
            trusted: false,
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
            self.digests = self.digests.joined_with(digests_of(self.bytes, missing)?);
        }
        Ok(self.digests)
    }

    pub(crate) fn trust(&mut self) {
        self.trusted = true;
        self.evidence.clear();
    }
}

pub(crate) struct Layers<'o> {
    top_level: Layer<'o>,
    nested: Vec<Layer<'o>>,
}

impl<'o> Layers<'o> {
    pub(crate) fn with_top_level(bytes: &'o dyn ObjectBytes) -> Self {
        Self {
            top_level: Layer::new(LayerId(0), None, 0, bytes),
            nested: Vec::new(),
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
}
