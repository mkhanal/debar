#![allow(clippy::unwrap_used)]

use serde_json::json;
use xtask::github_responses::{
    RepositoryPath, ResponseError, pages, remote_branches, repository_path_of_remote,
};

#[test]
fn a_repository_is_read_from_an_https_remote() {
    assert_eq!(
        repository_path_of_remote("https://github.com/mkhanal/debar.git\n").unwrap(),
        RepositoryPath {
            owner: "mkhanal".to_owned(),
            name: "debar".to_owned(),
        }
    );
}

#[test]
fn a_repository_is_read_from_an_ssh_remote() {
    assert_eq!(
        repository_path_of_remote("git@github.com:acme/scanner-harness").unwrap(),
        RepositoryPath {
            owner: "acme".to_owned(),
            name: "scanner-harness".to_owned(),
        }
    );
}

#[test]
fn a_remote_that_names_no_repository_is_refused() {
    assert_eq!(
        repository_path_of_remote("mirror").unwrap_err(),
        ResponseError::NotARepositoryRemote("mirror".to_owned())
    );
}

#[test]
fn paginated_arrays_are_joined_into_one_list() {
    assert_eq!(
        pages("[{\"id\":1},{\"id\":2}][{\"id\":3}]\n").unwrap(),
        [json!({"id": 1}), json!({"id": 2}), json!({"id": 3})]
    );
}

#[test]
fn a_page_that_is_not_an_array_is_refused() {
    assert!(pages("{\"message\":\"Not Found\"}").is_err());
}

#[test]
fn remote_branches_are_read_from_a_listing_of_heads() {
    let listing = "aaa111\trefs/heads/main\nbbb222\trefs/heads/autofix/7-draft\n";

    assert_eq!(
        remote_branches(listing)
            .unwrap()
            .into_iter()
            .collect::<Vec<_>>(),
        [
            ("autofix/7-draft".to_owned(), "bbb222".to_owned()),
            ("main".to_owned(), "aaa111".to_owned()),
        ]
    );
}

#[test]
fn a_listing_line_that_is_not_a_head_is_refused() {
    assert!(remote_branches("aaa111\trefs/tags/v1\n").is_err());
}
