use debar_formats::{
    AfterTheEntry, BUILT_IN_MODULES, ContainerEntry, FormatModule, HeaderCheck, ModuleError,
    Object, Stage,
};
use debar_image::ObjectKind;

#[derive(Clone, Copy)]
pub struct FormatModules<'r> {
    modules: &'r [&'r dyn FormatModule],
}

impl FormatModules<'static> {
    #[must_use]
    pub const fn built_in() -> Self {
        Self {
            modules: BUILT_IN_MODULES,
        }
    }
}

impl<'r> FormatModules<'r> {
    #[must_use]
    pub const fn new(modules: &'r [&'r dyn FormatModule]) -> Self {
        Self { modules }
    }

    pub(crate) fn for_kind(
        self,
        kind: ObjectKind,
        stage: Stage,
    ) -> impl Iterator<Item = &'r dyn FormatModule> {
        self.claiming(kind)
            .filter(move |module| module.stage() == stage)
    }

    pub(crate) fn header_check(
        self,
        kind: ObjectKind,
        from: &Object<'_>,
        entries: &mut dyn FnMut(ContainerEntry) -> AfterTheEntry,
    ) -> Result<HeaderCheck, ModuleError> {
        for module in self.claiming(kind) {
            let check = module.header_check(from, entries)?;
            if check != HeaderCheck::NotNeeded {
                return Ok(check);
            }
        }
        Ok(HeaderCheck::NotNeeded)
    }

    pub(crate) fn refined_kind(
        self,
        typed_as: ObjectKind,
        object: &Object<'_>,
        entries: &mut dyn FnMut(ContainerEntry) -> AfterTheEntry,
    ) -> Result<Option<ObjectKind>, ModuleError> {
        for module in self.claiming(typed_as) {
            if let Some(refined) = module.refined_kind(object, typed_as, entries)? {
                return Ok(Some(refined));
            }
        }
        Ok(None)
    }

    fn claiming(self, kind: ObjectKind) -> impl Iterator<Item = &'r dyn FormatModule> {
        self.modules
            .iter()
            .copied()
            .filter(move |module| module.kinds().contains(&kind))
    }
}
