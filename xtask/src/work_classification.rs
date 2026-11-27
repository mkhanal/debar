use crate::board_items::{
    BoardError, BoardField, FieldType, FieldUpdate, FieldValue, SelectOption, require_field,
};

pub const THEME_FIELD: &str = "Theme";
pub const KIND_FIELD: &str = "Kind";
pub const AREA_FIELD: &str = "Area";
pub const IMPACT_FIELD: &str = "Impact";
pub const WHY_FIELD: &str = "Why it matters";
pub const NEW_AREA_COLOR: &str = "PURPLE";

const CHOICE_FIELDS: [&str; 4] = [THEME_FIELD, KIND_FIELD, AREA_FIELD, IMPACT_FIELD];

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Classification {
    pub theme: Option<String>,
    pub kind: Option<String>,
    pub area: Option<String>,
    pub impact: Option<String>,
    pub why: Option<String>,
}

impl Classification {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self == &Self::default()
    }

    fn choices(&self) -> [(&'static str, Option<&String>); 4] {
        [
            (THEME_FIELD, self.theme.as_ref()),
            (KIND_FIELD, self.kind.as_ref()),
            (AREA_FIELD, self.area.as_ref()),
            (IMPACT_FIELD, self.impact.as_ref()),
        ]
    }
}

pub fn classification_updates(
    fields: &[BoardField],
    classification: &Classification,
) -> Result<Vec<FieldUpdate>, BoardError> {
    let mut updates = Vec::new();
    for (name, value) in classification.choices() {
        if let Some(value) = value {
            let field = require_field(fields, name, &FieldType::SingleSelect)?;
            updates.push(FieldUpdate {
                field_id: field.id,
                value: FieldValue::SingleSelectOption(field.option_id(value)?),
            });
        }
    }
    if let Some(why) = &classification.why {
        updates.push(FieldUpdate {
            field_id: require_field(fields, WHY_FIELD, &FieldType::Text)?.id,
            value: FieldValue::Text(why.clone()),
        });
    }
    Ok(updates)
}

pub fn classification_options(fields: &[BoardField]) -> Result<String, BoardError> {
    let mut sections = Vec::new();
    for name in CHOICE_FIELDS {
        let field = require_field(fields, name, &FieldType::SingleSelect)?;
        let mut lines = vec![format!("## {}", field.name)];
        lines.extend(
            field
                .options
                .iter()
                .map(|option| format!("- {}: {}", option.name, option.description)),
        );
        lines.push(String::new());
        sections.push(lines.join("\n"));
    }
    Ok(sections.join("\n"))
}

pub fn area_options_adding(
    area: &BoardField,
    name: &str,
    description: &str,
) -> Result<Vec<SelectOption>, BoardError> {
    if let Some(existing) = area
        .options
        .iter()
        .find(|option| option.name.to_lowercase() == name.to_lowercase())
    {
        return Err(BoardError::AreaExists {
            name: existing.name.clone(),
        });
    }
    let mut options = area.options.clone();
    options.push(SelectOption {
        id: None,
        name: name.to_owned(),
        color: NEW_AREA_COLOR.to_owned(),
        description: description.to_owned(),
    });
    Ok(options)
}
