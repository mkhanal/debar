use std::fmt;

use serde_json::Value;

use crate::requirements::TextFile;
use crate::workspace::MetadataError;

pub const FORBID_UNSAFE_CODE: &str = "#![forbid(unsafe_code)]";
pub const PLATFORM_PACKAGE: &str = "debar-platform";

pub struct UnsafeModule {
    pub path: &'static str,
    pub blocks: usize,
}

pub const UNSAFE_BLOCKS: [UnsafeModule; 2] = [
    UnsafeModule {
        path: "crates/platform/src/mapped_file.rs",
        blocks: 1,
    },
    UnsafeModule {
        path: "crates/platform/src/effective_user.rs",
        blocks: 1,
    },
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrateRoot {
    pub package: String,
    pub is_library: bool,
    pub path: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnsafeUse {
    Block { line: usize },
    Item { line: usize },
}

#[derive(Debug, PartialEq, Eq)]
pub enum UnsafeCodeFinding {
    RootDoesNotForbidUnsafeCode {
        root: String,
    },
    UnsafeBlocksNotInTheInventory {
        path: String,
        found: usize,
    },
    UnsafeBlockCountDiffers {
        path: String,
        listed: usize,
        found: usize,
    },
    UnsafeItem {
        path: String,
        line: usize,
    },
}

impl fmt::Display for UnsafeCodeFinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RootDoesNotForbidUnsafeCode { root } => write!(
                formatter,
                "{root} must begin with `{FORBID_UNSAFE_CODE}`: every crate outside the platform layer makes the promise in its own root (Constitution §18)"
            ),
            Self::UnsafeBlocksNotInTheInventory { path, found } => write!(
                formatter,
                "{path} has {found} unsafe block(s) and is not in UNSAFE_BLOCKS in xtask/src/unsafe_code.rs; unsafe code lives only in the platform crate's small types (Constitution §18)"
            ),
            Self::UnsafeBlockCountDiffers {
                path,
                listed,
                found,
            } => write!(
                formatter,
                "{path} has {found} unsafe block(s) but UNSAFE_BLOCKS in xtask/src/unsafe_code.rs lists {listed}; change the inventory in the same review as the code (Constitution §18)"
            ),
            Self::UnsafeItem { path, line } => write!(
                formatter,
                "{path}:{line}: an unsafe function, implementation, trait, extern block or attribute; the platform layer's public interface is safe and every unsafe operation is a block with a `// SAFETY:` line (Constitution §18)"
            ),
        }
    }
}

pub fn crate_roots(metadata: &str, root: &str) -> Result<Vec<CrateRoot>, MetadataError> {
    let metadata: Value = serde_json::from_str(metadata)
        .map_err(|error| MetadataError::NotJson(error.to_string()))?;
    let mut roots = Vec::new();
    for package in array_field(&metadata, "packages")? {
        let name = string_field(package, "name")?;
        for target in array_field(package, "targets")? {
            let source = string_field(target, "src_path")?;
            roots.push(CrateRoot {
                package: name.clone(),
                is_library: array_field(target, "kind")?
                    .iter()
                    .any(|kind| kind.as_str() == Some("lib")),
                path: without_parent_steps(source.strip_prefix(root).unwrap_or(&source)),
            });
        }
    }
    Ok(roots)
}

fn without_parent_steps(path: &str) -> String {
    let mut kept: Vec<&str> = Vec::new();
    for component in path.split('/') {
        if component == ".." && kept.last().is_some_and(|last| *last != "..") {
            kept.pop();
        } else {
            kept.push(component);
        }
    }
    kept.join("/")
}

#[must_use]
pub fn roots_without_the_promise(roots: &[(CrateRoot, TextFile)]) -> Vec<UnsafeCodeFinding> {
    roots
        .iter()
        .filter(|(root, _)| !(root.package == PLATFORM_PACKAGE && root.is_library))
        .filter(|(_, source)| {
            !leading_inner_attributes(&source.text).contains(&FORBID_UNSAFE_CODE.to_owned())
        })
        .map(|(root, _)| UnsafeCodeFinding::RootDoesNotForbidUnsafeCode {
            root: root.path.clone(),
        })
        .collect()
}

#[must_use]
pub fn unsafe_inventory_findings(
    sources: &[TextFile],
    inventory: &[UnsafeModule],
) -> Vec<UnsafeCodeFinding> {
    let mut findings = Vec::new();
    for source in sources {
        let uses = unsafe_uses(&source.text);
        let blocks = uses
            .iter()
            .filter(|found| matches!(found, UnsafeUse::Block { .. }))
            .count();
        findings.extend(uses.iter().filter_map(|found| match found {
            UnsafeUse::Item { line } => Some(UnsafeCodeFinding::UnsafeItem {
                path: source.path.clone(),
                line: *line,
            }),
            UnsafeUse::Block { .. } => None,
        }));
        let listed = inventory.iter().find(|module| module.path == source.path);
        match listed {
            None if blocks > 0 => findings.push(UnsafeCodeFinding::UnsafeBlocksNotInTheInventory {
                path: source.path.clone(),
                found: blocks,
            }),
            Some(module) if module.blocks != blocks => {
                findings.push(UnsafeCodeFinding::UnsafeBlockCountDiffers {
                    path: source.path.clone(),
                    listed: module.blocks,
                    found: blocks,
                });
            }
            _ => {}
        }
    }
    findings.extend(
        inventory
            .iter()
            .filter(|module| !sources.iter().any(|source| source.path == module.path))
            .map(|module| UnsafeCodeFinding::UnsafeBlockCountDiffers {
                path: module.path.to_owned(),
                listed: module.blocks,
                found: 0,
            }),
    );
    findings
}

#[must_use]
pub fn unsafe_uses(source: &str) -> Vec<UnsafeUse> {
    let tokens = code_tokens(source);
    tokens
        .iter()
        .enumerate()
        .filter(|(_, token)| token.text == "unsafe")
        .map(|(index, token)| {
            let next = index.checked_add(1).and_then(|next| tokens.get(next));
            if next.is_some_and(|next| next.text == "{") {
                UnsafeUse::Block { line: token.line }
            } else {
                UnsafeUse::Item { line: token.line }
            }
        })
        .collect()
}

struct Token {
    text: String,
    line: usize,
}

fn code_tokens(source: &str) -> Vec<Token> {
    let characters: Vec<char> = source.chars().collect();
    let mut lexer = Lexer {
        characters: &characters,
        position: 0,
        line: 1,
    };
    let mut tokens = Vec::new();
    while let Some(current) = lexer.peek(0) {
        if current == '\n' || current.is_whitespace() {
            lexer.advance();
        } else if current == '/' && lexer.peek(1) == Some('/') {
            lexer.skip_line_comment();
        } else if current == '/' && lexer.peek(1) == Some('*') {
            lexer.skip_block_comment();
        } else if current == '"' {
            lexer.skip_string();
        } else if current == '\'' {
            lexer.skip_character_or_lifetime();
        } else if current == '_' || current.is_alphabetic() {
            let line = lexer.line;
            let word = lexer.take_word();
            if is_string_prefix(&word) && lexer.skip_prefixed_string() {
                continue;
            }
            tokens.push(Token { text: word, line });
        } else {
            tokens.push(Token {
                text: current.to_string(),
                line: lexer.line,
            });
            lexer.advance();
        }
    }
    tokens
}

fn is_string_prefix(word: &str) -> bool {
    matches!(word, "r" | "b" | "br" | "c" | "cr")
}

struct Lexer<'a> {
    characters: &'a [char],
    position: usize,
    line: usize,
}

impl Lexer<'_> {
    fn peek(&self, ahead: usize) -> Option<char> {
        self.characters
            .get(self.position.checked_add(ahead)?)
            .copied()
    }

    fn advance(&mut self) {
        if self.peek(0) == Some('\n') {
            self.line = self.line.saturating_add(1);
        }
        self.position = self.position.saturating_add(1);
    }

    fn advance_by(&mut self, count: usize) {
        for _ in 0..count {
            self.advance();
        }
    }

    fn skip_line_comment(&mut self) {
        while self.peek(0).is_some_and(|current| current != '\n') {
            self.advance();
        }
    }

    fn skip_block_comment(&mut self) {
        let mut depth = 0usize;
        while let Some(current) = self.peek(0) {
            if current == '/' && self.peek(1) == Some('*') {
                depth = depth.saturating_add(1);
                self.advance_by(2);
            } else if current == '*' && self.peek(1) == Some('/') {
                depth = depth.saturating_sub(1);
                self.advance_by(2);
                if depth == 0 {
                    return;
                }
            } else {
                self.advance();
            }
        }
    }

    fn skip_string(&mut self) {
        self.advance();
        while let Some(current) = self.peek(0) {
            self.advance();
            match current {
                '\\' => self.advance(),
                '"' => return,
                _ => {}
            }
        }
    }

    fn skip_prefixed_string(&mut self) -> bool {
        let mut hashes = 0usize;
        while self.peek(hashes) == Some('#') {
            hashes = hashes.saturating_add(1);
        }
        if self.peek(hashes) != Some('"') {
            return false;
        }
        if hashes == 0 && self.characters.get(self.position.wrapping_sub(1)) != Some(&'r') {
            self.skip_string();
            return true;
        }
        self.advance_by(hashes.saturating_add(1));
        while self.peek(0).is_some() {
            if self.peek(0) == Some('"')
                && (1..=hashes).all(|offset| self.peek(offset) == Some('#'))
            {
                self.advance_by(hashes.saturating_add(1));
                return true;
            }
            self.advance();
        }
        true
    }

    fn skip_character_or_lifetime(&mut self) {
        if self.peek(1) == Some('\\') {
            self.advance_by(2);
            while self.peek(0).is_some_and(|current| current != '\'') {
                self.advance();
            }
            self.advance();
        } else if self.peek(2) == Some('\'') {
            self.advance_by(3);
        } else {
            self.advance();
        }
    }

    fn take_word(&mut self) -> String {
        let mut word = String::new();
        while let Some(current) = self
            .peek(0)
            .filter(|current| *current == '_' || current.is_alphanumeric())
        {
            word.push(current);
            self.advance();
        }
        word
    }
}

fn leading_inner_attributes(source: &str) -> Vec<String> {
    let tokens = code_tokens(source);
    let mut attributes = Vec::new();
    let mut index = 0usize;
    while tokens.get(index).is_some_and(|token| token.text == "#")
        && tokens
            .get(index.saturating_add(1))
            .is_some_and(|token| token.text == "!")
    {
        let mut depth = 0usize;
        let mut attribute = String::from("#!");
        index = index.saturating_add(2);
        while let Some(token) = tokens.get(index) {
            attribute.push_str(&token.text);
            index = index.saturating_add(1);
            match token.text.as_str() {
                "[" | "(" => depth = depth.saturating_add(1),
                "]" | ")" => {
                    depth = depth.saturating_sub(1);
                    if depth == 0 {
                        break;
                    }
                }
                _ => {}
            }
        }
        attributes.push(attribute);
    }
    attributes
}

fn string_field(object: &Value, field: &'static str) -> Result<String, MetadataError> {
    object
        .get(field)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or(MetadataError::MissingField(field))
}

fn array_field<'a>(
    object: &'a Value,
    field: &'static str,
) -> Result<&'a Vec<Value>, MetadataError> {
    object
        .get(field)
        .and_then(Value::as_array)
        .ok_or(MetadataError::MissingField(field))
}
