use std::fmt;

pub const REFERENCE_SCANNER_NAMES: [&str; 9] = [
    "clamav",
    "clamd",
    "clamscan",
    "clamdscan",
    "freshclam",
    "libclamav",
    "sigtool",
    "cvdupdate",
    "clam av",
];

pub enum AllowedPath {
    File(&'static str),
    Under(&'static str),
}

pub const MAY_NAME_THE_REFERENCE_SCANNER: [AllowedPath; 5] = [
    AllowedPath::File("PRODUCT.md"),
    AllowedPath::File("README.md"),
    AllowedPath::Under("specs/"),
    AllowedPath::Under("crates/compat-clamav/"),
    AllowedPath::File("xtask/src/reference_mentions.rs"),
];

#[derive(Debug, PartialEq, Eq)]
pub struct Mention {
    pub path: String,
    pub line: Option<usize>,
    pub name: &'static str,
}

impl fmt::Display for Mention {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let place = match self.line {
            Some(line) => format!("{}:{line}", self.path),
            None => format!("the path {}", self.path),
        };
        write!(
            formatter,
            "{place} names the reference scanner (\"{}\"); a committed file names it only to state the supported format and the compatibility surface (Constitution §4), and the rest belongs in study/",
            self.name
        )
    }
}

#[must_use]
pub fn mentions(path: &str, content: &[u8]) -> Vec<Mention> {
    if MAY_NAME_THE_REFERENCE_SCANNER
        .iter()
        .any(|allowed| allowed.covers(path))
    {
        return Vec::new();
    }
    let in_path = first_name_in(path.as_bytes()).map(|name| Mention {
        path: path.to_owned(),
        line: None,
        name,
    });
    let in_content = (1..)
        .zip(content.split(|byte| *byte == b'\n'))
        .filter_map(|(line, text)| {
            first_name_in(text).map(|name| Mention {
                path: path.to_owned(),
                line: Some(line),
                name,
            })
        });
    in_path.into_iter().chain(in_content).collect()
}

impl AllowedPath {
    fn covers(&self, path: &str) -> bool {
        match self {
            Self::File(allowed) => path == *allowed,
            Self::Under(directory) => path.starts_with(directory),
        }
    }
}

fn first_name_in(text: &[u8]) -> Option<&'static str> {
    let lowered = text.to_ascii_lowercase();
    REFERENCE_SCANNER_NAMES.into_iter().find(|name| {
        lowered
            .windows(name.len())
            .any(|window| window == name.as_bytes())
    })
}
