use debar_image::{ExecutableAnchor, Placement};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExecutableLayout {
    pub entry_point: u32,
    pub sections: Vec<ExecutableSection>,
    pub version_information: Vec<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExecutableSection {
    pub start: u32,
    pub length: u32,
}

pub(crate) fn placed_starts(
    placement: Placement,
    object_length: u64,
    layout: LayoutState<'_>,
    starts: &mut Vec<(u64, u64)>,
) {
    starts.clear();
    let Some(last_position) = object_length.checked_sub(1) else {
        return;
    };
    let length = u32::try_from(object_length).unwrap_or(u32::MAX);
    match (placement, layout) {
        (Placement::Anywhere, _)
        | (Placement::BeforeEnd { .. }, LayoutState::Missing)
        | (Placement::InExecutable { .. }, LayoutState::Missing | LayoutState::NotExecutable) => {}
        (Placement::FromStart { distance, shift }, _) => starts.extend(shifted(distance, shift)),
        (Placement::BeforeEnd { distance, shift }, _) => {
            starts.extend(shifted(length.wrapping_sub(distance), shift));
        }
        (Placement::InExecutable { anchor, shift }, LayoutState::Known(layout)) => {
            executable_ranges(anchor, shift, length, layout, starts);
        }
    }
    starts.retain(|(first, _)| *first <= last_position);
    for (_, last) in starts.iter_mut() {
        *last = (*last).min(last_position);
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum LayoutState<'l> {
    NotExecutable,
    Missing,
    Known(&'l ExecutableLayout),
}

fn shifted(start: u32, shift: u32) -> Option<(u64, u64)> {
    let last = start.wrapping_add(shift);
    (last >= start).then_some((u64::from(start), u64::from(last)))
}

fn executable_ranges(
    anchor: ExecutableAnchor,
    shift: u32,
    object_length: u32,
    layout: &ExecutableLayout,
    starts: &mut Vec<(u64, u64)>,
) {
    let section = |index: u32| {
        usize::try_from(index)
            .ok()
            .and_then(|index| layout.sections.get(index))
    };
    let ranges: Vec<(u64, u64)> = match anchor {
        ExecutableAnchor::AfterEntryPoint { distance } => {
            shifted(layout.entry_point.wrapping_add(distance), shift)
                .into_iter()
                .collect()
        }
        ExecutableAnchor::BeforeEntryPoint { distance } => {
            shifted(layout.entry_point.wrapping_sub(distance), shift)
                .into_iter()
                .collect()
        }
        ExecutableAnchor::SectionStart {
            section: index,
            distance,
        } => section(index)
            .and_then(|section| shifted(section.start.wrapping_add(distance), shift))
            .into_iter()
            .collect(),
        ExecutableAnchor::LastSectionStart { distance } => layout
            .sections
            .last()
            .and_then(|section| shifted(section.start.wrapping_add(distance), shift))
            .into_iter()
            .collect(),
        ExecutableAnchor::WholeSection {
            section: index,
            start_only_from_length,
        } => section(index)
            .and_then(|section| {
                if start_only_from_length.is_some_and(|from| object_length >= from) {
                    return Some((u64::from(section.start), u64::from(section.start)));
                }
                let last = section
                    .start
                    .wrapping_add(section.length)
                    .wrapping_add(shift);
                (last >= section.start).then_some((u64::from(section.start), u64::from(last)))
            })
            .into_iter()
            .collect(),
        ExecutableAnchor::BeforeEnd { distance } => {
            shifted(object_length.wrapping_sub(distance), shift)
                .into_iter()
                .collect()
        }
        ExecutableAnchor::VersionInformation => layout
            .version_information
            .iter()
            .map(|offset| (u64::from(*offset), u64::from(*offset)))
            .collect(),
    };
    starts.extend(ranges);
}
