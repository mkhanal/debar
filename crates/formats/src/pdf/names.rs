use crate::pdf::objects::{Filter, MOST_FILTERS, Mark, PdfObject};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NameState {
    None,
    S,
    Filter,
    JavaScript,
    OpenAction,
    Linearized,
    LaunchAction,
    Contents,
    Uri,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum After {
    State(NameState),
    Any,
}

struct NameAction {
    name: &'static [u8],
    marks: Option<Mark>,
    after: After,
    leads_to: NameState,
    common: bool,
}

const fn action(
    name: &'static [u8],
    marks: Option<Mark>,
    after: After,
    leads_to: NameState,
    common: bool,
) -> NameAction {
    NameAction {
        name,
        marks,
        after,
        leads_to,
        common,
    }
}

const IN_FILTER: After = After::State(NameState::Filter);
const IN_NONE: After = After::State(NameState::None);
const FILTER: NameState = NameState::Filter;
const NONE: NameState = NameState::None;

const NAME_ACTIONS: [NameAction; 47] = [
    action(
        b"ASCIIHexDecode",
        Some(Mark::AsciiHex),
        IN_FILTER,
        FILTER,
        true,
    ),
    action(
        b"ASCII85Decode",
        Some(Mark::Ascii85),
        IN_FILTER,
        FILTER,
        true,
    ),
    action(b"A85", Some(Mark::Ascii85), IN_FILTER, FILTER, true),
    action(b"AHx", Some(Mark::AsciiHex), IN_FILTER, FILTER, true),
    action(
        b"EmbeddedFile",
        Some(Mark::EmbeddedFile),
        IN_NONE,
        NONE,
        true,
    ),
    action(b"FlateDecode", Some(Mark::Flate), IN_FILTER, FILTER, true),
    action(b"Fl", Some(Mark::Flate), IN_FILTER, FILTER, true),
    action(b"Image", Some(Mark::Image), IN_NONE, NONE, true),
    action(b"LZWDecode", Some(Mark::Lzw), IN_FILTER, FILTER, true),
    action(b"LZW", Some(Mark::Lzw), IN_FILTER, FILTER, true),
    action(
        b"RunLengthDecode",
        Some(Mark::RunLength),
        IN_FILTER,
        FILTER,
        true,
    ),
    action(b"RL", Some(Mark::RunLength), IN_FILTER, FILTER, true),
    action(b"CCITTFaxDecode", Some(Mark::Fax), IN_FILTER, FILTER, true),
    action(b"CCF", Some(Mark::Fax), IN_FILTER, FILTER, true),
    action(b"JBIG2Decode", Some(Mark::Dct), IN_FILTER, FILTER, true),
    action(b"DCTDecode", Some(Mark::Dct), IN_FILTER, FILTER, true),
    action(b"DCT", Some(Mark::Dct), IN_FILTER, FILTER, true),
    action(b"JPXDecode", Some(Mark::Jpx), IN_FILTER, FILTER, true),
    action(b"Crypt", Some(Mark::Crypt), IN_FILTER, NONE, true),
    action(b"Standard", Some(Mark::Standard), IN_FILTER, FILTER, true),
    action(b"Sig", Some(Mark::Signed), After::Any, NONE, true),
    action(b"V", Some(Mark::Signed), After::Any, NONE, true),
    action(b"R", Some(Mark::Signed), After::Any, NONE, true),
    action(b"Linearized", None, IN_NONE, NameState::Linearized, true),
    action(b"Filter", Some(Mark::HasFilters), After::Any, FILTER, true),
    action(
        b"JavaScript",
        Some(Mark::JavaScript),
        After::Any,
        NameState::JavaScript,
        true,
    ),
    action(b"Length", None, IN_FILTER, NONE, true),
    action(b"S", None, IN_NONE, NameState::S, true),
    action(b"Type", None, IN_NONE, NONE, true),
    action(
        b"OpenAction",
        Some(Mark::OpenAction),
        After::Any,
        NameState::OpenAction,
        true,
    ),
    action(
        b"Launch",
        Some(Mark::LaunchAction),
        After::Any,
        NameState::LaunchAction,
        true,
    ),
    action(b"Page", Some(Mark::Page), IN_NONE, NONE, true),
    action(
        b"Contents",
        Some(Mark::Contents),
        IN_NONE,
        NameState::Contents,
        true,
    ),
    action(b"Author", None, IN_NONE, NONE, false),
    action(b"Producer", None, IN_NONE, NONE, false),
    action(b"CreationDate", None, IN_NONE, NONE, false),
    action(b"ModDate", None, IN_NONE, NONE, false),
    action(b"Creator", None, IN_NONE, NONE, false),
    action(b"Title", None, IN_NONE, NONE, false),
    action(b"Keywords", None, IN_NONE, NONE, false),
    action(b"Subject", None, IN_NONE, NONE, false),
    action(b"Pages", None, IN_NONE, NONE, false),
    action(b"Colors", None, IN_NONE, NONE, false),
    action(b"RichMedia", None, IN_NONE, NONE, false),
    action(b"AcroForm", None, IN_NONE, NONE, false),
    action(b"XFA", None, IN_NONE, NONE, false),
    action(b"URI", None, IN_NONE, NameState::Uri, false),
];

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DocumentSigns {
    pub common_name_escaped: bool,
    pub opens_with_an_action: bool,
    pub launches_a_program: bool,
}

pub fn name_read(
    name: &[u8],
    escaped: bool,
    state: &mut NameState,
    object: &mut PdfObject,
    signs: &mut DocumentSigns,
) {
    let name = name.split(|byte| *byte == 0).next().unwrap_or_default();
    if name == b"URI" && *state == NameState::S {
        *state = NameState::None;
        return;
    }
    let looked_up: &[u8] = if object.marks.has(Mark::Uri) {
        b"URI"
    } else {
        name
    };
    let Some(action) = NAME_ACTIONS.iter().find(|action| action.name == looked_up) else {
        return;
    };
    if *state == NameState::Filter
        && object.filters.len() < MOST_FILTERS
        && let Some(filter) = action.marks.and_then(Filter::recorded_for)
    {
        object.filters.push(filter);
    }
    if action.common && escaped {
        signs.common_name_escaped = true;
    }
    if action.after == After::Any || action.after == After::State(*state) {
        *state = action.leads_to;
        if let Some(mark) = action.marks {
            object.marks.set(mark);
        }
    } else if *state == NameState::S {
        *state = NameState::None;
    }
}

pub const fn mark_for_reference(state: NameState) -> Option<Mark> {
    match state {
        NameState::JavaScript => Some(Mark::JavaScript),
        NameState::OpenAction => Some(Mark::OpenAction),
        NameState::Contents => Some(Mark::Contents),
        NameState::Uri => Some(Mark::Uri),
        NameState::None
        | NameState::S
        | NameState::Filter
        | NameState::Linearized
        | NameState::LaunchAction => None,
    }
}
