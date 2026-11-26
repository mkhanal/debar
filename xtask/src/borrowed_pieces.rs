use std::fmt;

const BORROWED_PIECES_HEADING: &str = "## Borrowed pieces";
const NEXT_SECTION: &str = "## ";
const LIST_ITEM: &str = "- ";
const NOTHING_BORROWED: &str = "None.";

#[derive(Debug, PartialEq, Eq)]
pub enum ReleaseBlocker {
    ListMissing,
    PiecesBorrowed { listed: Vec<String> },
}

impl fmt::Display for ReleaseBlocker {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ListMissing => write!(
                formatter,
                "architecture-overview/ROADMAP.md has no \"{BORROWED_PIECES_HEADING}\" section, so it cannot show that a release borrows nothing (Constitution §13)"
            ),
            Self::PiecesBorrowed { listed } => write!(
                formatter,
                "\"Borrowed pieces\" in architecture-overview/ROADMAP.md must list exactly \"{NOTHING_BORROWED}\" before a release (Constitution §13); it lists: {}",
                if listed.is_empty() {
                    "nothing".to_owned()
                } else {
                    listed.join("; ")
                }
            ),
        }
    }
}

pub fn release_blockers(roadmap: &str) -> Result<(), ReleaseBlocker> {
    let mut lines = roadmap.lines();
    if !lines.any(|line| line.trim_end() == BORROWED_PIECES_HEADING) {
        return Err(ReleaseBlocker::ListMissing);
    }
    let listed: Vec<String> = lines
        .take_while(|line| !line.starts_with(NEXT_SECTION))
        .filter_map(|line| line.strip_prefix(LIST_ITEM))
        .map(|item| item.trim().to_owned())
        .collect();
    if listed == [NOTHING_BORROWED] {
        Ok(())
    } else {
        Err(ReleaseBlocker::PiecesBorrowed { listed })
    }
}
