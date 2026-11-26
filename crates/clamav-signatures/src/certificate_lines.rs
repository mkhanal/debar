use std::fmt;

use debar_image::{CERTIFICATE_KEY_IDENTIFIER_LENGTH, CertificateRule, CertificateTrust};

use crate::FUNCTIONALITY_LEVEL;
use crate::ignore_list::hex_value;

const COMMENT_MARK: u8 = b'#';
const SEPARATOR: u8 = b';';
const FEWEST_FIELDS: usize = 11;
const MOST_FIELDS: usize = 13;
const IDENTIFIER_HEX_LENGTH: usize = 40;
const UNCOMPARED_SERIAL_BYTE: u8 = 0xCA;
const RULE_EXPONENT: u32 = 65_537;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MalformedCertificateLine {
    FieldCount(usize),
    LowestLevelNotANumber,
    HighestLevelNotANumber,
    TrustNotOneOrZero,
    SerialLength,
    SerialNotHexadecimal,
    SubjectLength,
    SubjectNotHexadecimal,
    PublicKeyNotHexadecimal,
    CodeSigningNotOneOrZero,
    TimeStampingNotOneOrZero,
    CertificateSigningNotOneOrZero,
}

impl fmt::Display for MalformedCertificateLine {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FieldCount(count) => write!(formatter, "{count} fields, not 11 to 13"),
            Self::LowestLevelNotANumber => formatter.write_str("the lowest level is not a number"),
            Self::HighestLevelNotANumber => {
                formatter.write_str("the highest level is not a number")
            }
            Self::TrustNotOneOrZero => formatter.write_str("the trust field is neither 1 nor 0"),
            Self::SerialLength => formatter.write_str("the serial is not 40 hexadecimal digits"),
            Self::SerialNotHexadecimal => formatter.write_str("the serial is not hexadecimal"),
            Self::SubjectLength => formatter.write_str("the subject is not 40 hexadecimal digits"),
            Self::SubjectNotHexadecimal => formatter.write_str("the subject is not hexadecimal"),
            Self::PublicKeyNotHexadecimal => {
                formatter.write_str("the public key does not start with a hexadecimal digit")
            }
            Self::CodeSigningNotOneOrZero => {
                formatter.write_str("the code-signing field is neither 1 nor 0")
            }
            Self::TimeStampingNotOneOrZero => {
                formatter.write_str("the time-stamping field is neither 1 nor 0")
            }
            Self::CertificateSigningNotOneOrZero => {
                formatter.write_str("the certificate-signing field is neither 1 nor 0")
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReadCertificateLine {
    Comment,
    OutsideFunctionalityLevel,
    Rule(CertificateRule),
}

#[derive(Default)]
pub struct CertificateFile {
    serial_ignored_from_here: bool,
    not_before: i64,
}

impl CertificateFile {
    pub fn read_line(
        &mut self,
        line_without_ending: &[u8],
    ) -> Result<ReadCertificateLine, MalformedCertificateLine> {
        if line_without_ending.first() == Some(&COMMENT_MARK) || line_without_ending.is_empty() {
            return Ok(ReadCertificateLine::Comment);
        }
        let fields: Vec<&[u8]> = line_without_ending
            .split(|byte| *byte == SEPARATOR)
            .collect();
        if !(FEWEST_FIELDS..=MOST_FIELDS).contains(&fields.len()) {
            return Err(MalformedCertificateLine::FieldCount(fields.len()));
        }
        let field = |index: usize| fields.get(index).copied().unwrap_or_default();
        let level = i64::from(u32::try_from(FUNCTIONALITY_LEVEL).unwrap_or(u32::MAX));
        if fields.len() > FEWEST_FIELDS {
            let lowest = field(11);
            if !lowest.iter().all(u8::is_ascii_digit) {
                return Err(MalformedCertificateLine::LowestLevelNotANumber);
            }
            if decimal(lowest) > level {
                return Ok(ReadCertificateLine::OutsideFunctionalityLevel);
            }
        }
        if fields.len() == MOST_FIELDS {
            let highest = field(12);
            if !highest.iter().all(u8::is_ascii_digit) {
                return Err(MalformedCertificateLine::HighestLevelNotANumber);
            }
            if decimal(highest) < level {
                return Ok(ReadCertificateLine::OutsideFunctionalityLevel);
            }
        }
        let trust = match field(1).first() {
            Some(b'1') => CertificateTrust::Trusted,
            Some(b'0') => CertificateTrust::Blocked,
            _ => return Err(MalformedCertificateLine::TrustNotOneOrZero),
        };
        let serial = if field(3).is_empty() {
            self.serial_ignored_from_here = true;
            [UNCOMPARED_SERIAL_BYTE; CERTIFICATE_KEY_IDENTIFIER_LENGTH]
        } else {
            identifier(
                field(3),
                MalformedCertificateLine::SerialLength,
                MalformedCertificateLine::SerialNotHexadecimal,
            )?
        };
        let subject = identifier(
            field(2),
            MalformedCertificateLine::SubjectLength,
            MalformedCertificateLine::SubjectNotHexadecimal,
        )?;
        let modulus = leading_hexadecimal_number(field(4))
            .ok_or(MalformedCertificateLine::PublicKeyNotHexadecimal)?;
        let sign_flag = |index: usize, malformed| match field(index).first() {
            Some(b'1') => Ok(true),
            Some(b'0') => Ok(false),
            _ => Err(malformed),
        };
        let code_signing = sign_flag(6, MalformedCertificateLine::CodeSigningNotOneOrZero)?;
        let time_stamping = sign_flag(7, MalformedCertificateLine::TimeStampingNotOneOrZero)?;
        let certificate_signing =
            sign_flag(8, MalformedCertificateLine::CertificateSigningNotOneOrZero)?;
        let name = field(0);
        if !field(9).is_empty() {
            self.not_before = leading_signed_decimal(field(9));
        }
        Ok(ReadCertificateLine::Rule(CertificateRule {
            name: (!name.is_empty()).then(|| String::from_utf8_lossy(name).into_owned()),
            trust,
            subject,
            serial,
            compares_serial: !self.serial_ignored_from_here,
            modulus,
            exponent: RULE_EXPONENT,
            code_signing,
            time_stamping,
            certificate_signing,
            not_before: self.not_before,
        }))
    }
}

#[must_use]
pub fn repeats_a_stored_rule(stored: &[CertificateRule], rule: &CertificateRule) -> bool {
    stored.iter().any(|existing| {
        if existing.trust != rule.trust
            || existing.subject != rule.subject
            || existing.modulus != rule.modulus
            || (existing.compares_serial && existing.serial != rule.serial)
        {
            return false;
        }
        match rule.trust {
            CertificateTrust::Blocked => true,
            CertificateTrust::Trusted => {
                existing.compares_serial == rule.compares_serial
                    && existing.exponent == rule.exponent
                    && rule.not_before >= existing.not_before
                    && (!rule.code_signing || existing.code_signing)
                    && (!rule.time_stamping || existing.time_stamping)
                    && (!rule.certificate_signing || existing.certificate_signing)
            }
        }
    })
}

fn identifier(
    text: &[u8],
    wrong_length: MalformedCertificateLine,
    not_hexadecimal: MalformedCertificateLine,
) -> Result<[u8; CERTIFICATE_KEY_IDENTIFIER_LENGTH], MalformedCertificateLine> {
    if text.len() != IDENTIFIER_HEX_LENGTH {
        return Err(wrong_length);
    }
    let mut bytes = [0u8; CERTIFICATE_KEY_IDENTIFIER_LENGTH];
    let (pairs, _) = text.as_chunks::<2>();
    for (slot, [high, low]) in bytes.iter_mut().zip(pairs) {
        *slot = hex_value(*high)
            .zip(hex_value(*low))
            .map(|(high, low)| high.wrapping_shl(4) | low)
            .ok_or(not_hexadecimal)?;
    }
    Ok(bytes)
}

fn leading_hexadecimal_number(text: &[u8]) -> Option<Vec<u8>> {
    let digits: Vec<u8> = text
        .iter()
        .map_while(|byte| hex_value(*byte))
        .skip_while(|digit| *digit == 0)
        .collect();
    if !text.first().is_some_and(u8::is_ascii_hexdigit) {
        return None;
    }
    let mut bytes = Vec::with_capacity(digits.len().div_ceil(2));
    let mut digits = digits.as_slice();
    if digits.len() % 2 == 1 {
        let (first, rest) = digits.split_first()?;
        bytes.push(*first);
        digits = rest;
    }
    let (pairs, _) = digits.as_chunks::<2>();
    for [high, low] in pairs {
        bytes.push(high.wrapping_shl(4) | low);
    }
    Some(bytes)
}

fn decimal(text: &[u8]) -> i64 {
    text.iter().fold(0i64, |value, digit| {
        value
            .saturating_mul(10)
            .saturating_add(i64::from(digit.saturating_sub(b'0')))
    })
}

fn leading_signed_decimal(text: &[u8]) -> i64 {
    let text = text
        .iter()
        .position(|byte| !byte.is_ascii_whitespace())
        .and_then(|start| text.get(start..))
        .unwrap_or_default();
    let (negative, digits) = match text.split_first() {
        Some((b'-', rest)) => (true, rest),
        Some((b'+', rest)) => (false, rest),
        _ => (false, text),
    };
    let length = digits
        .iter()
        .take_while(|byte| byte.is_ascii_digit())
        .count();
    let magnitude = decimal(digits.get(..length).unwrap_or_default());
    if negative {
        magnitude.saturating_neg()
    } else {
        magnitude
    }
}
