use std::collections::{BTreeMap, BTreeSet};

use crate::task_outcome::TaskError;

#[derive(Debug, Default, PartialEq, Eq)]
pub struct TaskArguments {
    pub positionals: Vec<String>,
    pub values: BTreeMap<String, String>,
    pub flags: BTreeSet<String>,
}

impl TaskArguments {
    pub fn parse(
        arguments: &[String],
        value_options: &[&str],
        flag_options: &[&str],
    ) -> Result<Self, TaskError> {
        let mut parsed = Self::default();
        let mut rest = arguments.iter();
        while let Some(argument) = rest.next() {
            let Some(name) = argument.strip_prefix("--") else {
                parsed.positionals.push(argument.clone());
                continue;
            };
            if flag_options.contains(&name) {
                parsed.flags.insert(name.to_owned());
            } else if value_options.contains(&name) {
                let value = rest
                    .next()
                    .ok_or_else(|| TaskError::Usage(format!("--{name} needs a value")))?;
                parsed.values.insert(name.to_owned(), value.clone());
            } else {
                return Err(TaskError::Usage(format!("unknown option --{name}")));
            }
        }
        Ok(parsed)
    }

    #[must_use]
    pub fn value(&self, name: &str) -> Option<&str> {
        self.values.get(name).map(String::as_str)
    }

    #[must_use]
    pub fn flag(&self, name: &str) -> bool {
        self.flags.contains(name)
    }
}
