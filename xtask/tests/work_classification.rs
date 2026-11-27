#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used)]

use xtask::board_items::{
    BoardError, BoardField, FieldType, FieldUpdate, FieldValue, SelectOption,
};
use xtask::work_classification::{
    Classification, NEW_AREA_COLOR, area_options_adding, classification_options,
    classification_updates,
};

fn option(field: &str, name: &str, description: &str) -> SelectOption {
    SelectOption {
        id: Some(format!("{field}:{name}")),
        name: name.to_owned(),
        color: "GRAY".to_owned(),
        description: description.to_owned(),
    }
}

fn single_select(id: u64, name: &str, options: &[(&str, &str)]) -> BoardField {
    BoardField {
        id,
        node_id: format!("PVTSSF_{name}"),
        name: name.to_owned(),
        data_type: FieldType::SingleSelect,
        options: options
            .iter()
            .map(|(option_name, description)| option(name, option_name, description))
            .collect(),
    }
}

fn fields() -> Vec<BoardField> {
    vec![
        single_select(
            1,
            "Theme",
            &[("Robustness", "Hostile input never crashes Debar.")],
        ),
        single_select(2, "Kind", &[("Fix", "It did not work.")]),
        single_select(
            3,
            "Area",
            &[
                ("Matching", "Matching signatures."),
                ("Scan core", "Objects, layers and limits."),
            ],
        ),
        single_select(
            4,
            "Impact",
            &[
                ("High", "A user would notice."),
                ("Normal", "Everything else."),
            ],
        ),
        BoardField {
            id: 5,
            node_id: "PVTF_why".to_owned(),
            name: "Why it matters".to_owned(),
            data_type: FieldType::Text,
            options: Vec::new(),
        },
    ]
}

fn area() -> BoardField {
    fields().into_iter().nth(2).unwrap()
}

#[test]
fn classifying_writes_only_the_fields_it_is_given() {
    let classification = Classification {
        theme: Some("Robustness".to_owned()),
        kind: Some("Fix".to_owned()),
        ..Classification::default()
    };

    assert_eq!(
        classification_updates(&fields(), &classification).unwrap(),
        [
            FieldUpdate {
                field_id: 1,
                value: FieldValue::SingleSelectOption("Theme:Robustness".to_owned()),
            },
            FieldUpdate {
                field_id: 2,
                value: FieldValue::SingleSelectOption("Kind:Fix".to_owned()),
            },
        ]
    );
}

#[test]
fn classifying_writes_the_reason_it_matters_as_text() {
    let classification = Classification {
        impact: Some("High".to_owned()),
        why: Some("Every archive is scanned to the depth the settings allow.".to_owned()),
        ..Classification::default()
    };

    assert_eq!(
        classification_updates(&fields(), &classification).unwrap(),
        [
            FieldUpdate {
                field_id: 4,
                value: FieldValue::SingleSelectOption("Impact:High".to_owned()),
            },
            FieldUpdate {
                field_id: 5,
                value: FieldValue::Text(
                    "Every archive is scanned to the depth the settings allow.".to_owned()
                ),
            },
        ]
    );
}

#[test]
fn classifying_refuses_a_value_that_is_not_one_of_the_board_options_listing_them() {
    let classification = Classification {
        area: Some("Archives".to_owned()),
        ..Classification::default()
    };

    assert_eq!(
        classification_updates(&fields(), &classification)
            .unwrap_err()
            .to_string(),
        "\"Archives\" is not one of the Area options on \"Debar\": Matching, Scan core"
    );
}

#[test]
fn classifying_fails_naming_the_field_when_the_board_lacks_it() {
    let without_kind: Vec<BoardField> = fields()
        .into_iter()
        .filter(|field| field.name != "Kind")
        .collect();
    let classification = Classification {
        kind: Some("Fix".to_owned()),
        ..Classification::default()
    };

    assert_eq!(
        classification_updates(&without_kind, &classification)
            .unwrap_err()
            .to_string(),
        "project \"Debar\" has no single-select \"Kind\" field"
    );
}

#[test]
fn classifying_fails_when_the_field_exists_with_another_type() {
    let mut fields = fields();
    if let Some(why) = fields
        .iter_mut()
        .find(|field| field.name == "Why it matters")
    {
        why.data_type = FieldType::Number;
    }
    let classification = Classification {
        why: Some("Because.".to_owned()),
        ..Classification::default()
    };

    assert!(matches!(
        classification_updates(&fields, &classification),
        Err(BoardError::MissingField { .. })
    ));
}

#[test]
fn the_options_list_every_option_of_theme_kind_area_and_impact_in_that_order() {
    assert_eq!(
        classification_options(&fields()).unwrap(),
        [
            "## Theme",
            "- Robustness: Hostile input never crashes Debar.",
            "",
            "## Kind",
            "- Fix: It did not work.",
            "",
            "## Area",
            "- Matching: Matching signatures.",
            "- Scan core: Objects, layers and limits.",
            "",
            "## Impact",
            "- High: A user would notice.",
            "- Normal: Everything else.",
            "",
        ]
        .join("\n")
    );
}

#[test]
fn the_options_fail_naming_the_field_when_the_board_lacks_one() {
    let without_kind: Vec<BoardField> = fields()
        .into_iter()
        .filter(|field| field.name != "Kind")
        .collect();

    assert_eq!(
        classification_options(&without_kind)
            .unwrap_err()
            .to_string(),
        "project \"Debar\" has no single-select \"Kind\" field"
    );
}

#[test]
fn adding_an_area_sends_every_existing_option_back_so_items_keep_their_values() {
    let options = area_options_adding(&area(), "Format modules", "Unpacking.").unwrap();

    assert_eq!(options.get(..2).unwrap(), area().options.as_slice());
}

#[test]
fn adding_an_area_appends_it_last_without_an_id_in_the_new_area_colour() {
    let options = area_options_adding(&area(), "Format modules", "Unpacking.").unwrap();

    assert_eq!(
        options.last(),
        Some(&SelectOption {
            id: None,
            name: "Format modules".to_owned(),
            color: NEW_AREA_COLOR.to_owned(),
            description: "Unpacking.".to_owned(),
        })
    );
}

#[test]
fn adding_an_area_refuses_a_name_that_already_exists_whatever_its_case() {
    assert_eq!(
        area_options_adding(&area(), "scan CORE", "Again.")
            .unwrap_err()
            .to_string(),
        "Area \"Scan core\" already exists on \"Debar\""
    );
}
