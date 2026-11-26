use crate::record_codec::{
    FieldReader, RecordFields, RecordMalformed, RecordTooLarge, RecordWriter, Records,
};

pub const CERTIFICATE_KEY_IDENTIFIER_LENGTH: usize = 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CertificateTrust {
    Trusted,
    Blocked,
}

#[expect(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateRule {
    pub name: Option<String>,
    pub trust: CertificateTrust,
    pub subject: [u8; CERTIFICATE_KEY_IDENTIFIER_LENGTH],
    pub serial: [u8; CERTIFICATE_KEY_IDENTIFIER_LENGTH],
    pub compares_serial: bool,
    pub modulus: Vec<u8>,
    pub exponent: u32,
    pub code_signing: bool,
    pub time_stamping: bool,
    pub certificate_signing: bool,
    pub not_before: i64,
}

pub fn build(rules: &[CertificateRule]) -> Result<Vec<u8>, RecordTooLarge> {
    let mut writer = RecordWriter::default();
    for rule in rules {
        let mut fields = RecordFields::default();
        fields
            .flag(rule.name.is_some())
            .bytes(rule.name.as_deref().unwrap_or_default().as_bytes())?
            .flag(rule.trust == CertificateTrust::Trusted)
            .bytes(&rule.subject)?
            .bytes(&rule.serial)?
            .flag(rule.compares_serial)
            .bytes(&rule.modulus)?
            .u32(rule.exponent)
            .flag(rule.code_signing)
            .flag(rule.time_stamping)
            .flag(rule.certificate_signing)
            .i64(rule.not_before);
        writer.record(&fields)?;
    }
    Ok(writer.finish())
}

#[derive(Clone, Copy)]
pub struct CertificateRules<'m> {
    records: Records<'m>,
}

impl<'m> CertificateRules<'m> {
    pub fn read(bytes: &'m [u8]) -> Result<Self, RecordMalformed> {
        Records::read(bytes).map(|records| Self { records })
    }

    #[must_use]
    pub fn count(&self) -> u32 {
        self.records.record_count()
    }

    pub fn rules(&self) -> impl Iterator<Item = Result<CertificateRule, RecordMalformed>> + 'm {
        self.records
            .each()
            .map(|record| record.and_then(|mut fields| rule_of(&mut fields)))
    }
}

fn identifier(
    fields: &mut FieldReader<'_>,
) -> Result<[u8; CERTIFICATE_KEY_IDENTIFIER_LENGTH], RecordMalformed> {
    fields.bytes()?.try_into().map_err(|_| RecordMalformed)
}

fn rule_of(fields: &mut FieldReader<'_>) -> Result<CertificateRule, RecordMalformed> {
    let named = fields.flag()?;
    let name = fields.text()?;
    let rule = CertificateRule {
        name: named.then(|| name.to_owned()),
        trust: if fields.flag()? {
            CertificateTrust::Trusted
        } else {
            CertificateTrust::Blocked
        },
        subject: identifier(fields)?,
        serial: identifier(fields)?,
        compares_serial: fields.flag()?,
        modulus: fields.bytes()?.to_vec(),
        exponent: fields.u32()?,
        code_signing: fields.flag()?,
        time_stamping: fields.flag()?,
        certificate_signing: fields.flag()?,
        not_before: fields.i64()?,
    };
    fields.finish()?;
    Ok(rule)
}
