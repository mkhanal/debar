use crate::html::entities::named_entity_value;
use crate::html::output::Output;

const MOST_NAME_BYTES: usize = 1024;
const MOST_VALUE_BYTES: usize = 1024;
const MOST_ENTITY_NAME_BYTES: usize = 1024;
const MOST_GROUPED_HIGH_BYTES: usize = 3;
const FIRST_HIGH_BYTE: u8 = 0x80;
const FULL_STOPS: [[u8; 3]; 3] = [[0xe3, 0x80, 0x82], [0xef, 0xbc, 0x8e], [0xef, 0xb9, 0x92]];
const FULL_STOP_VALUES: [u64; 3] = [0x3002, 0xff0e, 0xfe52];
const FULL_STOP_LEAD: u8 = 0xa1;
const BYTES_MAKING_A_FULL_STOP_AFTER_ITS_LEAD: [u8; 3] = *b"CDO";
const LARGEST_SINGLE_BYTE_ENTITY: u64 = 0xfe;
const ENTITY_VALUE_MASK: u64 = 0xffff;
const DATA_URI_START: &[u8] = b"data:";
const QUOTED_DATA_URI_START: &[u8] = b"\"data:";
const ENCODED_SCRIPT_LANGUAGES: [(&[u8], &[u8]); 2] = [
    (b"jscript.encode", b"javascript"),
    (b"vbscript.encode", b"vbscript"),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum View {
    WithoutComments,
    WithoutTags,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Element {
    None,
    Script,
    Style,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EntityEnteredFrom {
    Text,
    Value,
    DataUriData,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Text,
    WhitespaceRun,
    HighBytes,
    TagOpening,
    TagName,
    Comment,
    WhitespaceBeforeText,
    Arguments,
    ArgumentName,
    ValueOpening,
    Value,
    TagEnded,
    EntityOpening(EntityEnteredFrom),
    NamedEntity(EntityEnteredFrom),
    NumericEntityOpening(EntityEnteredFrom),
    NumericEntity(EntityEnteredFrom, Radix),
    DataUriMediaType,
    DataUriData,
    DataUriEscape(Option<u8>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Radix {
    Decimal,
    Hexadecimal,
}

impl Radix {
    const fn base(self) -> i64 {
        match self {
            Self::Decimal => 10,
            Self::Hexadecimal => 16,
        }
    }

    fn digit(self, byte: u8) -> Option<u8> {
        let radix = match self {
            Self::Decimal => 10,
            Self::Hexadecimal => 16,
        };
        char::from(byte)
            .to_digit(radix)
            .and_then(|digit| u8::try_from(digit).ok())
    }
}

enum Step {
    Consumed,
    Again,
}

#[derive(Default)]
struct HighByteGroup(Vec<u8>);

impl HighByteGroup {
    fn is_full(&self) -> bool {
        self.0.len() >= MOST_GROUPED_HIGH_BYTES
    }

    fn is_full_stop(&self) -> bool {
        FULL_STOPS.iter().any(|stop| stop.as_slice() == self.0)
    }
}

struct Argument {
    name: Vec<u8>,
    value: Vec<u8>,
}

#[derive(Default)]
struct Tag {
    name: Vec<u8>,
    arguments: Vec<Argument>,
    argument_name: Vec<u8>,
    argument_name_ended: bool,
    value: Vec<u8>,
    quote: Option<u8>,
    quoting_ended: bool,
    skipping_whitespace_in_value: bool,
}

impl Tag {
    fn store_argument_without_value(&mut self) {
        if !self.argument_name.is_empty() {
            self.arguments.push(Argument {
                name: std::mem::take(&mut self.argument_name),
                value: Vec::new(),
            });
        }
        self.argument_name_ended = false;
    }

    fn store_argument_with_its_value(&mut self) {
        let mut value = std::mem::take(&mut self.value);
        if value.first() == Some(&b'"') {
            value.remove(0);
            value.pop();
        }
        self.arguments.push(Argument {
            name: std::mem::take(&mut self.argument_name),
            value,
        });
        self.argument_name_ended = false;
        self.quote = None;
        self.quoting_ended = false;
        self.skipping_whitespace_in_value = false;
    }

    fn argument(&self, name: &[u8]) -> Option<&Argument> {
        self.arguments.iter().find(|argument| argument.name == name)
    }

    fn push_value_byte(&mut self, byte: u8) {
        if self.value.len() < MOST_VALUE_BYTES {
            self.value.push(byte);
        }
    }
}

pub struct PageNormaliser {
    state: State,
    element: Element,
    space_written: bool,
    text_group: HighByteGroup,
    value_group: HighByteGroup,
    tag: Tag,
    entity_name: Vec<u8>,
    entity_value: i64,
    without_comments: Output,
    without_tags: Output,
}

impl PageNormaliser {
    pub fn new(without_comments: Output, without_tags: Output) -> Self {
        Self {
            state: State::Text,
            element: Element::None,
            space_written: false,
            text_group: HighByteGroup::default(),
            value_group: HighByteGroup::default(),
            tag: Tag::default(),
            entity_name: Vec::new(),
            entity_value: 0,
            without_comments,
            without_tags,
        }
    }

    pub fn output(&mut self, view: View) -> &mut Output {
        match view {
            View::WithoutComments => &mut self.without_comments,
            View::WithoutTags => &mut self.without_tags,
        }
    }

    pub const fn reads_data_uri_bytes_as_they_are(&self) -> bool {
        matches!(
            self.state,
            State::DataUriData
                | State::DataUriEscape(_)
                | State::EntityOpening(EntityEnteredFrom::DataUriData)
        )
    }

    pub fn normalise_plain_text(&mut self, bytes: &[u8]) -> usize {
        if self.state != State::Text {
            return 0;
        }
        let plain = bytes
            .iter()
            .position(|&byte| !is_plain_text(byte))
            .unwrap_or(bytes.len());
        let Some(run) = bytes.get(..plain).filter(|run| !run.is_empty()) else {
            return 0;
        };
        if self.outside_elements() {
            for &byte in run {
                let lowercased = byte.to_ascii_lowercase();
                self.without_comments.write(lowercased);
                self.without_tags.write(lowercased);
            }
            self.space_written = false;
        } else {
            for &byte in run {
                let lowercased = self.lowercased_in_element(byte);
                self.without_comments.write(lowercased);
            }
        }
        plain
    }

    pub fn normalise_byte(&mut self, byte: u8) {
        while let Step::Again = self.step(byte) {}
    }

    pub fn finish(&mut self) {
        let entered_from = match self.state {
            State::NamedEntity(from) => Some(from),
            _ => None,
        };
        if let Some(from) = entered_from {
            match named_entity_value(&self.entity_name) {
                Some(value) => self.write_entity_value(from, value),
                None => self.write_undecoded_entity(from),
            }
        }
    }

    fn step(&mut self, byte: u8) -> Step {
        match self.state {
            State::Text => self.text(byte),
            State::WhitespaceRun => self.whitespace_run(byte),
            State::HighBytes => self.high_bytes(byte),
            State::TagOpening => self.tag_opening(byte),
            State::TagName => self.tag_name(byte),
            State::Comment => self.comment(byte),
            State::WhitespaceBeforeText => self.whitespace_before_text(byte),
            State::Arguments => self.arguments(byte),
            State::ArgumentName => self.argument_name(byte),
            State::ValueOpening => self.value_opening(byte),
            State::Value => self.value(byte),
            State::TagEnded => self.tag_ended(byte),
            State::EntityOpening(from) => self.entity_opening(from, byte),
            State::NamedEntity(from) => self.named_entity(from, byte),
            State::NumericEntityOpening(from) => self.numeric_entity_opening(from, byte),
            State::NumericEntity(from, radix) => self.numeric_entity(from, radix, byte),
            State::DataUriMediaType => self.data_uri_media_type(byte),
            State::DataUriData => self.data_uri_data(byte),
            State::DataUriEscape(first_digit) => self.data_uri_escape(first_digit, byte),
        }
    }

    fn outside_elements(&self) -> bool {
        self.element == Element::None
    }

    fn separate_in_text_without_tags(&mut self) {
        if self.outside_elements() && !self.space_written {
            self.without_tags.write(b' ');
            self.space_written = true;
        }
    }

    fn lowercased_in_element(&self, byte: u8) -> u8 {
        if byte == b'\'' && !self.outside_elements() {
            b'"'
        } else {
            byte.to_ascii_lowercase()
        }
    }

    fn text(&mut self, byte: u8) -> Step {
        match byte {
            b'<' => {
                self.without_comments.write(b'<');
                self.separate_in_text_without_tags();
                self.tag = Tag::default();
                self.state = State::TagOpening;
            }
            b'&' => {
                self.separate_in_text_without_tags();
                self.state = State::EntityOpening(EntityEnteredFrom::Text);
            }
            _ if is_whitespace(byte) => {
                self.separate_in_text_without_tags();
                self.state = State::WhitespaceRun;
            }
            _ if byte >= FIRST_HIGH_BYTE => {
                self.text_group.0.clear();
                self.text_group.0.push(byte);
                self.state = State::HighBytes;
            }
            _ if byte < b' ' => {
                self.without_comments.write(byte);
                self.separate_in_text_without_tags();
            }
            _ => {
                let lowercased = self.lowercased_in_element(byte);
                self.without_comments.write(lowercased);
                if self.outside_elements() {
                    self.without_tags.write(byte.to_ascii_lowercase());
                    self.space_written = false;
                }
            }
        }
        Step::Consumed
    }

    fn whitespace_run(&mut self, byte: u8) -> Step {
        if is_whitespace(byte) {
            return Step::Consumed;
        }
        if self.outside_elements() {
            self.without_comments.write(b' ');
        }
        self.state = State::Text;
        Step::Again
    }

    fn high_bytes(&mut self, byte: u8) -> Step {
        if self.text_group.0 == [FULL_STOP_LEAD]
            && BYTES_MAKING_A_FULL_STOP_AFTER_ITS_LEAD.contains(&byte)
        {
            self.without_comments.write(b'.');
            self.without_tags.write(b'.');
            self.text_group.0.clear();
            return Step::Consumed;
        }
        if byte >= FIRST_HIGH_BYTE && !self.text_group.is_full() {
            self.text_group.0.push(byte);
            return Step::Consumed;
        }
        self.emit_text_group();
        self.state = State::Text;
        Step::Again
    }

    fn emit_text_group(&mut self) {
        let group = std::mem::take(&mut self.text_group);
        if group.is_full_stop() {
            self.without_comments.write(b'.');
            self.without_tags.write(b'.');
            return;
        }
        if group.0.is_empty() {
            self.without_comments.write(0);
        }
        self.without_comments.write_all(&group.0);
        let missing = MOST_GROUPED_HIGH_BYTES.saturating_sub(group.0.len());
        let at = |index: usize| {
            index
                .checked_sub(missing)
                .and_then(|index| group.0.get(index))
                .copied()
                .unwrap_or(0)
        };
        let (first, second) = (at(0), at(1));
        if first != 0 {
            self.without_tags.write(first);
        }
        if first != 0 || second != 0 {
            self.without_tags.write(second);
        }
        self.without_tags.write(second);
    }

    fn tag_opening(&mut self, byte: u8) -> Step {
        if is_whitespace(byte) {
            return Step::Consumed;
        }
        if byte == b'!' {
            if self.outside_elements() {
                self.without_comments.take_back_last_byte();
            } else {
                self.without_comments.write(b'!');
            }
            self.state = State::Comment;
            return Step::Consumed;
        }
        self.state = if !self.outside_elements() && byte != b'/' {
            State::Text
        } else {
            State::TagName
        };
        Step::Again
    }

    fn tag_name(&mut self, byte: u8) -> Step {
        if byte == b'>' {
            self.without_comments.write(b'>');
            self.state = State::TagEnded;
        } else if is_whitespace(byte) {
            self.state = if self.outside_elements() {
                State::Arguments
            } else {
                State::TagEnded
            };
        } else {
            let lowercased = byte.to_ascii_lowercase();
            self.without_comments.write(lowercased);
            if self.tag.name.len() < MOST_NAME_BYTES {
                self.tag.name.push(lowercased);
            }
        }
        Step::Consumed
    }

    fn comment(&mut self, byte: u8) -> Step {
        if !self.outside_elements() && !is_whitespace(byte) {
            let lowercased = self.lowercased_in_element(byte);
            self.without_comments.write(lowercased);
        }
        if byte == b'>' {
            self.state = State::WhitespaceBeforeText;
        }
        Step::Consumed
    }

    fn whitespace_before_text(&mut self, byte: u8) -> Step {
        if is_whitespace(byte) {
            return Step::Consumed;
        }
        self.state = State::Text;
        Step::Again
    }

    fn arguments(&mut self, byte: u8) -> Step {
        match byte {
            _ if is_whitespace(byte) => {}
            b'>' => {
                self.tag.store_argument_without_value();
                self.without_comments.write(b'>');
                self.state = State::TagEnded;
            }
            b'=' => {
                self.without_comments.write(b'=');
                self.state = State::ValueOpening;
            }
            _ => {
                if self.tag.argument_name_ended {
                    self.tag.store_argument_without_value();
                }
                if self.tag.argument_name.is_empty() {
                    self.without_comments.write(b' ');
                }
                self.state = State::ArgumentName;
                return Step::Again;
            }
        }
        Step::Consumed
    }

    fn argument_name(&mut self, byte: u8) -> Step {
        if is_whitespace(byte) {
            self.tag.argument_name_ended = true;
            self.state = State::Arguments;
            return Step::Consumed;
        }
        if byte == b'>' {
            self.tag.store_argument_without_value();
            self.without_comments.write(b'>');
            self.act_on_the_tag();
            self.state = State::WhitespaceBeforeText;
            return Step::Consumed;
        }
        if byte == b'=' {
            self.state = State::Arguments;
            return Step::Again;
        }
        let lowercased = byte.to_ascii_lowercase();
        self.without_comments.write(lowercased);
        if self.tag.argument_name.len() < MOST_NAME_BYTES {
            self.tag.argument_name.push(lowercased);
        }
        Step::Consumed
    }

    fn value_opening(&mut self, byte: u8) -> Step {
        if is_whitespace(byte) {
            return Step::Consumed;
        }
        self.tag.value.clear();
        self.tag.quoting_ended = false;
        self.tag.skipping_whitespace_in_value = false;
        self.state = State::Value;
        if is_quote(byte) {
            self.tag.quote = Some(byte);
            self.without_comments.write(b'"');
            self.tag.push_value_byte(b'"');
            return Step::Consumed;
        }
        self.tag.quote = None;
        Step::Again
    }

    fn value(&mut self, byte: u8) -> Step {
        if self.tag.skipping_whitespace_in_value {
            if is_whitespace(byte) {
                return Step::Consumed;
            }
            self.tag.skipping_whitespace_in_value = false;
        }
        if self.tag.quote == Some(byte) {
            self.without_comments.write(b'"');
            self.tag.push_value_byte(b'"');
            self.tag.store_argument_with_its_value();
            self.state = State::Arguments;
            return Step::Consumed;
        }
        if is_quote(byte) {
            self.without_comments.write(b'"');
            self.tag.push_value_byte(byte);
            return Step::Consumed;
        }
        if is_whitespace(byte) || byte == b'>' {
            if self.tag.quote.is_some() && !self.tag.quoting_ended {
                self.without_comments.write(byte);
                self.tag
                    .push_value_byte(if byte == b'>' { b'>' } else { b' ' });
                self.tag.quoting_ended = true;
                self.tag.skipping_whitespace_in_value = true;
                return Step::Consumed;
            }
            self.tag.store_argument_with_its_value();
            self.state = State::Arguments;
            return Step::Again;
        }
        if byte == b'&' {
            self.state = State::EntityOpening(EntityEnteredFrom::Value);
            return Step::Consumed;
        }
        if byte >= FIRST_HIGH_BYTE {
            if self.value_group.is_full() {
                self.emit_value_group();
            }
            self.value_group.0.push(byte);
            return Step::Consumed;
        }
        if !self.value_group.0.is_empty() {
            self.emit_value_group();
        }
        self.without_comments.write(byte.to_ascii_lowercase());
        self.tag.push_value_byte(byte);
        if self.tag.value == DATA_URI_START || self.tag.value == QUOTED_DATA_URI_START {
            self.without_comments.take_back_last_byte();
            if self.tag.quote.is_some() {
                self.without_comments.write(b'"');
            }
            self.state = State::DataUriMediaType;
        }
        Step::Consumed
    }

    fn emit_value_group(&mut self) {
        let group = std::mem::take(&mut self.value_group);
        if group.is_full_stop() {
            self.without_comments.write(b'.');
            self.tag.push_value_byte(b'.');
            return;
        }
        self.without_comments.write_all(&group.0);
        for &byte in &group.0 {
            self.tag.push_value_byte(byte);
        }
    }

    fn tag_ended(&mut self, byte: u8) -> Step {
        if is_whitespace(byte) {
            return Step::Consumed;
        }
        self.act_on_the_tag();
        self.state = State::Text;
        Step::Again
    }

    fn act_on_the_tag(&mut self) {
        match self.tag.name.as_slice() {
            b"/script" => self.element = Element::None,
            b"/style" if self.element == Element::Style => self.element = Element::None,
            b"script" => {
                self.element = Element::Script;
                self.rewrite_an_encoded_script_tag();
            }
            b"style" => self.element = Element::Style,
            b"a" => self.write_link_without_tags(b"href"),
            b"img" => self.write_link_without_tags(b"src"),
            _ => {}
        }
    }

    fn write_link_without_tags(&mut self, argument: &[u8]) {
        let Some(link) = self
            .tag
            .argument(argument)
            .map(|argument| argument.value.clone())
            .filter(|value| !value.is_empty())
        else {
            return;
        };
        self.without_tags.write_all(&link);
        self.without_tags.write(b' ');
        self.space_written = true;
    }

    fn rewrite_an_encoded_script_tag(&mut self) {
        let Some(language) = self
            .tag
            .arguments
            .iter_mut()
            .find(|argument| argument.name == b"language")
        else {
            return;
        };
        let Some((_, decoded)) = ENCODED_SCRIPT_LANGUAGES
            .iter()
            .find(|(encoded, _)| language.value.eq_ignore_ascii_case(encoded))
        else {
            return;
        };
        language.value = decoded.to_vec();
        self.without_comments.write(b'<');
        let name = self.tag.name.clone();
        self.without_comments.write_all(&name);
        for argument in &self.tag.arguments {
            self.without_comments.write(b' ');
            self.without_comments.write_all(&argument.name);
            if !argument.value.is_empty() {
                self.without_comments.write_all(b"=\"");
                for &byte in &argument.value {
                    self.without_comments.write(byte.to_ascii_lowercase());
                }
                self.without_comments.write(b'"');
            }
        }
        self.without_comments.write(b'>');
    }

    fn entity_opening(&mut self, from: EntityEnteredFrom, byte: u8) -> Step {
        self.entity_name.clear();
        self.entity_value = 0;
        if byte == b'#' {
            self.state = State::NumericEntityOpening(from);
            return Step::Consumed;
        }
        self.state = State::NamedEntity(from);
        Step::Again
    }

    fn named_entity(&mut self, from: EntityEnteredFrom, byte: u8) -> Step {
        if is_entity_name_byte(byte) && self.entity_name.len() < MOST_ENTITY_NAME_BYTES {
            self.entity_name.push(byte);
            return Step::Consumed;
        }
        if byte == b';' {
            if let Some(value) = named_entity_value(&self.entity_name) {
                self.write_entity_value(from, value);
            } else {
                self.write_undecoded_entity(from);
                self.write_entity_bytes(from, b";");
            }
            self.state = return_state(from);
            return Step::Consumed;
        }
        self.write_undecoded_entity(from);
        self.state = return_state(from);
        Step::Again
    }

    fn write_undecoded_entity(&mut self, from: EntityEnteredFrom) {
        self.without_comments.write(b'&');
        let name = std::mem::take(&mut self.entity_name);
        for &byte in &name {
            self.without_comments.write(byte.to_ascii_lowercase());
        }
        if from == EntityEnteredFrom::Value {
            self.tag.push_value_byte(b'&');
            for &byte in &name {
                self.tag.push_value_byte(byte);
            }
        }
    }

    fn write_entity_value(&mut self, from: EntityEnteredFrom, value: u64) {
        self.write_entity_bytes(from, &entity_bytes(value));
    }

    fn write_entity_bytes(&mut self, from: EntityEnteredFrom, bytes: &[u8]) {
        self.without_comments.write_all(bytes);
        if from == EntityEnteredFrom::Value {
            for &byte in bytes {
                self.tag.push_value_byte(byte);
            }
        }
    }

    fn numeric_entity_opening(&mut self, from: EntityEnteredFrom, byte: u8) -> Step {
        if byte == b'x' || byte == b'X' {
            self.state = State::NumericEntity(from, Radix::Hexadecimal);
            return Step::Consumed;
        }
        self.state = State::NumericEntity(from, Radix::Decimal);
        Step::Again
    }

    fn numeric_entity(&mut self, from: EntityEnteredFrom, radix: Radix, byte: u8) -> Step {
        if let Some(digit) = radix.digit(byte) {
            let grown = self
                .entity_value
                .checked_mul(radix.base())
                .and_then(|value| value.checked_add(i64::from(digit)));
            if let Some(value) = grown {
                self.entity_value = value;
            } else {
                self.write_numeric_low_byte(from);
                self.state = return_state(from);
            }
            return Step::Consumed;
        }
        if byte == b';' {
            let value = self.entity_value.unsigned_abs();
            if value < u64::from(FIRST_HIGH_BYTE) {
                let lowercased = low_byte(value).to_ascii_lowercase();
                self.write_numeric_byte(from, lowercased);
            } else {
                self.without_comments
                    .write_all(&entity_bytes(value & ENTITY_VALUE_MASK));
                if from == EntityEnteredFrom::Value {
                    self.tag.push_value_byte(low_byte(value));
                }
            }
            self.state = return_state(from);
            return Step::Consumed;
        }
        self.write_numeric_low_byte(from);
        self.state = return_state(from);
        Step::Again
    }

    fn write_numeric_low_byte(&mut self, from: EntityEnteredFrom) {
        let byte = low_byte(self.entity_value.unsigned_abs());
        self.write_numeric_byte(from, byte);
    }

    fn write_numeric_byte(&mut self, from: EntityEnteredFrom, byte: u8) {
        self.without_comments.write(byte);
        if from == EntityEnteredFrom::Value {
            self.tag.push_value_byte(byte);
        }
    }

    fn data_uri_media_type(&mut self, byte: u8) -> Step {
        if self.tag.quote == Some(byte) {
            self.abandon_data_uri();
            return Step::Consumed;
        }
        if self.tag.quote.is_none() && (is_whitespace(byte) || byte == b'>') {
            self.abandon_data_uri();
            return Step::Again;
        }
        if byte == b',' {
            self.state = State::DataUriData;
        }
        Step::Consumed
    }

    fn abandon_data_uri(&mut self) {
        self.tag.value.clear();
        self.tag.quote = None;
        self.state = State::Arguments;
    }

    fn data_uri_data(&mut self, byte: u8) -> Step {
        let ends = match self.tag.quote {
            Some(quote) => byte == quote,
            None => is_whitespace(byte) || byte == b'>',
        };
        if ends {
            self.abandon_data_uri();
            return Step::Consumed;
        }
        match byte {
            b'%' => self.state = State::DataUriEscape(None),
            b'&' => self.state = State::EntityOpening(EntityEnteredFrom::DataUriData),
            _ => {}
        }
        Step::Consumed
    }

    fn data_uri_escape(&mut self, first_digit: Option<u8>, byte: u8) -> Step {
        let is_digit = Radix::Hexadecimal.digit(byte).is_some();
        self.state = match (first_digit, is_digit) {
            (None, true) => State::DataUriEscape(Some(byte)),
            _ => State::DataUriData,
        };
        Step::Consumed
    }
}

const fn return_state(from: EntityEnteredFrom) -> State {
    match from {
        EntityEnteredFrom::Text => State::Text,
        EntityEnteredFrom::Value => State::Value,
        EntityEnteredFrom::DataUriData => State::DataUriData,
    }
}

const fn low_byte(value: u64) -> u8 {
    value.to_le_bytes()[0]
}

fn entity_bytes(value: u64) -> Vec<u8> {
    if value == 0 {
        return Vec::new();
    }
    if value <= LARGEST_SINGLE_BYTE_ENTITY {
        return vec![low_byte(value)];
    }
    if FULL_STOP_VALUES.contains(&value) {
        return vec![b'.'];
    }
    format!("&#x{value:04x};").into_bytes()
}

pub const fn is_whitespace(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r')
}

const fn is_plain_text(byte: u8) -> bool {
    matches!(byte, 0x21..=0x7f) && byte != b'<' && byte != b'&'
}

const fn is_quote(byte: u8) -> bool {
    byte == b'"' || byte == b'\''
}

const fn is_entity_name_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b':' | b'-')
}
