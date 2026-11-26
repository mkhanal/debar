use xtask::borrowed_pieces::{ReleaseBlocker, release_blockers};

const ROADMAP_WITHOUT_BORROWING: &str = "\
# Roadmap

## Borrowed pieces

A build that is not a release may link a reference scanner's code.

- None.

## Evidence for the same detections

- Each pattern signature is checked.
";

#[test]
fn a_release_may_be_cut_when_nothing_is_borrowed() {
    assert_eq!(release_blockers(ROADMAP_WITHOUT_BORROWING), Ok(()));
}

#[test]
fn a_borrowed_piece_blocks_a_release() {
    let roadmap = ROADMAP_WITHOUT_BORROWING
        .replace("- None.", "- The archive unpacker, replaced by piece 6.");

    assert_eq!(
        release_blockers(&roadmap),
        Err(ReleaseBlocker::PiecesBorrowed {
            listed: vec!["The archive unpacker, replaced by piece 6.".to_owned()],
        })
    );
}

#[test]
fn a_borrowed_piece_listed_beside_none_blocks_a_release() {
    let roadmap = ROADMAP_WITHOUT_BORROWING.replace(
        "- None.",
        "- None.\n- The archive unpacker, replaced by piece 6.",
    );

    assert!(release_blockers(&roadmap).is_err());
}

#[test]
fn an_empty_list_of_borrowed_pieces_blocks_a_release() {
    let roadmap = ROADMAP_WITHOUT_BORROWING.replace("- None.\n", "");

    assert_eq!(
        release_blockers(&roadmap),
        Err(ReleaseBlocker::PiecesBorrowed { listed: vec![] })
    );
}

#[test]
fn a_roadmap_without_the_list_blocks_a_release() {
    let roadmap = ROADMAP_WITHOUT_BORROWING.replace("## Borrowed pieces", "## Borrowing");

    assert_eq!(release_blockers(&roadmap), Err(ReleaseBlocker::ListMissing));
}

#[test]
fn the_committed_roadmap_borrows_nothing() {
    assert_eq!(
        release_blockers(include_str!("../../architecture-overview/ROADMAP.md")),
        Ok(())
    );
}
