use regex_syntax::hir::Hir;

use crate::expression_automata::{ExpressionNotCompiled, build_search};
use crate::record_codec::{FieldReader, RecordFields, RecordMalformed, RecordWriter, Records};

const LIST_MONITORED: u8 = 1;
const LIST_ALLOWED: u8 = 2;
const PATTERN_HOST: u8 = 1;
const PATTERN_EXPRESSION: u8 = 2;
const PATTERN_DIGEST: u8 = 3;
const PATTERN_DIGEST_PREFIX: u8 = 4;
const VERDICT_ALLOWED: u8 = 1;
const VERDICT_BLOCKED: u8 = 2;
const VERDICT_SUSPECTED_PHISHING: u8 = 3;
const VERDICT_SUSPECTED_MALWARE: u8 = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum UrlList {
    Monitored,
    Allowed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum UrlVerdict {
    Allowed,
    Blocked,
    SuspectedPhishing,
    SuspectedMalware,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UrlPattern {
    Host(Vec<u8>),
    Expression {
        text: Vec<u8>,
        expression: Hir,
    },
    Digest {
        digest: Vec<u8>,
        verdict: UrlVerdict,
    },
    DigestPrefix {
        prefix: Vec<u8>,
        verdict: UrlVerdict,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UrlRule {
    pub list: UrlList,
    pub pattern: UrlPattern,
    pub never_matches: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UrlRulesNotBuilt {
    TooLarge,
    Expression(ExpressionNotCompiled),
}

const fn verdict_code(verdict: UrlVerdict) -> u8 {
    match verdict {
        UrlVerdict::Allowed => VERDICT_ALLOWED,
        UrlVerdict::Blocked => VERDICT_BLOCKED,
        UrlVerdict::SuspectedPhishing => VERDICT_SUSPECTED_PHISHING,
        UrlVerdict::SuspectedMalware => VERDICT_SUSPECTED_MALWARE,
    }
}

const fn verdict_of(code: u8) -> Option<UrlVerdict> {
    match code {
        VERDICT_ALLOWED => Some(UrlVerdict::Allowed),
        VERDICT_BLOCKED => Some(UrlVerdict::Blocked),
        VERDICT_SUSPECTED_PHISHING => Some(UrlVerdict::SuspectedPhishing),
        VERDICT_SUSPECTED_MALWARE => Some(UrlVerdict::SuspectedMalware),
        _ => None,
    }
}

pub fn build(rules: &[UrlRule]) -> Result<Vec<u8>, UrlRulesNotBuilt> {
    let too_large = |_| UrlRulesNotBuilt::TooLarge;
    let mut writer = RecordWriter::default();
    for rule in rules {
        let mut fields = RecordFields::default();
        fields
            .byte(match rule.list {
                UrlList::Monitored => LIST_MONITORED,
                UrlList::Allowed => LIST_ALLOWED,
            })
            .flag(rule.never_matches);
        match &rule.pattern {
            UrlPattern::Host(host) => {
                fields.byte(PATTERN_HOST).bytes(host).map_err(too_large)?;
            }
            UrlPattern::Expression { text, expression } => {
                let built = build_search(expression).map_err(UrlRulesNotBuilt::Expression)?;
                fields
                    .byte(PATTERN_EXPRESSION)
                    .bytes(text)
                    .and_then(|fields| fields.bytes(built.text.as_bytes()))
                    .and_then(|fields| fields.bytes(built.automaton.as_deref().unwrap_or_default()))
                    .map_err(too_large)?;
            }
            UrlPattern::Digest { digest, verdict } => {
                fields
                    .byte(PATTERN_DIGEST)
                    .byte(verdict_code(*verdict))
                    .bytes(digest)
                    .map_err(too_large)?;
            }
            UrlPattern::DigestPrefix { prefix, verdict } => {
                fields
                    .byte(PATTERN_DIGEST_PREFIX)
                    .byte(verdict_code(*verdict))
                    .bytes(prefix)
                    .map_err(too_large)?;
            }
        }
        writer.record(&fields).map_err(too_large)?;
    }
    Ok(writer.finish())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordedUrlPattern<'m> {
    Host(&'m [u8]),
    Expression {
        text: &'m [u8],
        engine_text: &'m str,
        automaton: Option<&'m [u8]>,
    },
    Digest {
        digest: &'m [u8],
        verdict: UrlVerdict,
    },
    DigestPrefix {
        prefix: &'m [u8],
        verdict: UrlVerdict,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UrlRuleRecord<'m> {
    pub list: UrlList,
    pub pattern: RecordedUrlPattern<'m>,
    pub never_matches: bool,
}

#[derive(Clone, Copy)]
pub struct UrlRules<'m> {
    records: Records<'m>,
}

impl<'m> UrlRules<'m> {
    pub fn read(bytes: &'m [u8]) -> Result<Self, RecordMalformed> {
        Records::read(bytes).map(|records| Self { records })
    }

    #[must_use]
    pub fn count(&self) -> u32 {
        self.records.record_count()
    }

    pub fn rules(&self) -> impl Iterator<Item = Result<UrlRuleRecord<'m>, RecordMalformed>> + 'm {
        self.records
            .each()
            .map(|record| record.and_then(|mut fields| rule_of(&mut fields)))
    }
}

fn rule_of<'m>(fields: &mut FieldReader<'m>) -> Result<UrlRuleRecord<'m>, RecordMalformed> {
    let list = match fields.byte()? {
        LIST_MONITORED => UrlList::Monitored,
        LIST_ALLOWED => UrlList::Allowed,
        _ => return Err(RecordMalformed),
    };
    let never_matches = fields.flag()?;
    let pattern = match fields.byte()? {
        PATTERN_HOST => RecordedUrlPattern::Host(fields.bytes()?),
        PATTERN_EXPRESSION => {
            let text = fields.bytes()?;
            let engine_text = fields.text()?;
            let automaton = fields.bytes()?;
            RecordedUrlPattern::Expression {
                text,
                engine_text,
                automaton: (!automaton.is_empty()).then_some(automaton),
            }
        }
        PATTERN_DIGEST => {
            let verdict = verdict_of(fields.byte()?).ok_or(RecordMalformed)?;
            RecordedUrlPattern::Digest {
                verdict,
                digest: fields.bytes()?,
            }
        }
        PATTERN_DIGEST_PREFIX => {
            let verdict = verdict_of(fields.byte()?).ok_or(RecordMalformed)?;
            RecordedUrlPattern::DigestPrefix {
                verdict,
                prefix: fields.bytes()?,
            }
        }
        _ => return Err(RecordMalformed),
    };
    fields.finish()?;
    Ok(UrlRuleRecord {
        list,
        pattern,
        never_matches,
    })
}
