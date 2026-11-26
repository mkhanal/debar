use base64ct::{Base64, Encoding as _};
use cms::cert::CertificateChoices;
use cms::content_info::ContentInfo;
use cms::signed_data::{SignedData, SignerIdentifier};
use const_oid::ObjectIdentifier;
use der::{Decode as _, Encode as _};
use num_bigint::BigUint;
use sha2::{Digest as _, Sha256, Sha512};
use x509_cert::Certificate;

const SIX_BIT_DIGITS: &[u8; 64] =
    b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/";

const HEADER_KEY_MODULUS: &str = "a8f34c7b2bae902e1e608cfcec44c024375370c09cd460e1917a98546ddfc53a90c608bb48ba8cb7eed1ff342085ecdd1491428ca8a895972403a3db2a452dd80173bb07e1e23acbc84fab2e2586930f62909d56d2e25256c989d399fa722ab25ab628df79bcfce43b86a0e049263171352b75048f2d4778b69a5e574a6130ad";
const HEADER_KEY_EXPONENT: u32 = 100_001_027;
const MD5_LENGTH: usize = 16;

const INDEX_KEY_MODULUS: &str = "57d749b7e7d61160421a14aeadb263bbaec4422cabda76e94db3fa98cd63bfe32a54c72b3026f2356dfa9543f9020219cbdcbdae9e642c4441c23a2523cf4fa6d444722ec227b89e04dad097c38eeef93b588baabecc6fc20199fea6ea47a66c736d4fec15b5a8d4411e1ae838e2a0a55b7398f4d48b346a7d747134c62bfdf95a4bce381fa151a2118b6788ccb3289512a6c8b3a84d640e0fca01d0f4611d7dd1a47452027ddecfc1572d08370e63c51d9bd4773153ce7ad95c4ffb2f4a1147e35304f827f34a4d5ef388bab077f7cae0b2fbbbfea09936b656b4c0c7c4e9907c6c6d392e01b047746d2b8694bede7a5e0861f8d95ef844a29b71e7f8b8f0c9";
const INDEX_KEY_EXPONENT: u32 = 100_002_049;
const INDEX_ENCODED_LENGTH: usize = 256;
const INDEX_MASKED_LENGTH: usize = 223;
const INDEX_TRAILER: u8 = 0xbc;
const INDEX_SALT_LENGTH: usize = 32;
const INDEX_SALT_PREFIX: [u8; 8] = [0; 8];

const DETACHED_SIGNATURE_LEVEL: u32 = 230;
const DETACHED_FORMAT_LINE: &str = "#clamsign";
const DETACHED_FORMAT_VERSION: &str = "1.0";
const DETACHED_SIGNATURE_FORMAT: &str = "pkcs7-pem";
const DEEPEST_CHAIN: usize = 8;
const TRUSTED_ROOT_FINGERPRINT: [u8; 32] = [
    0x6b, 0x3d, 0x4e, 0x1b, 0x5e, 0x26, 0x31, 0x8c, 0x0b, 0xb6, 0xa2, 0x2f, 0xb1, 0x20, 0x6d, 0x28,
    0x7f, 0xa3, 0xfb, 0x0c, 0x5f, 0xe3, 0x4e, 0xeb, 0xbf, 0x86, 0x13, 0x95, 0x4f, 0x8a, 0x64, 0xa7,
];

const MESSAGE_DIGEST: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.4");
const CONTENT_TYPE: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.3");
const DATA_CONTENT: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.1");
const SIGNED_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.2");
const SHA256_ALGORITHM: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");
const RSA_ENCRYPTION: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");
const SHA256_WITH_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");
const SHA512_WITH_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.13");
const BASIC_CONSTRAINTS: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.19");
const SHA256_DIGEST_INFO: [u8; 19] = [
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x20,
];
const SHA512_DIGEST_INFO: [u8; 19] = [
    0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05,
    0x00, 0x04, 0x40,
];
const SHORTEST_PADDING: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DetachedVerification {
    Verified,
    Invalid(DetachedSignatureInvalid),
    CannotVerify,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DetachedSignatureInvalid {
    DigestDiffers,
    SignatureDoesNotVerify,
    ChainDoesNotReachTheTrustedRoot,
}

#[must_use]
pub fn six_bit_number(text: &[u8]) -> Option<BigUint> {
    let mut bytes = vec![0u8; text.len().checked_mul(6)?.div_ceil(8)];
    for (position, character) in text.iter().enumerate() {
        let digit = SIX_BIT_DIGITS.iter().position(|known| known == character)?;
        for bit in 0..6usize {
            if digit & (1 << bit) != 0 {
                let index = position.checked_mul(6)?.checked_add(bit)?;
                *bytes.get_mut(index / 8)? |= 1 << (index % 8);
            }
        }
    }
    Some(BigUint::from_bytes_le(&bytes))
}

fn modulus(hex: &str) -> BigUint {
    BigUint::parse_bytes(hex.as_bytes(), 16).unwrap_or_default()
}

#[must_use]
pub fn header_signature_holds(signature: &[u8], payload_md5: &[u8; MD5_LENGTH]) -> bool {
    let Some(value) = six_bit_number(signature) else {
        return false;
    };
    let opened = value.modpow(
        &BigUint::from(HEADER_KEY_EXPONENT),
        &modulus(HEADER_KEY_MODULUS),
    );
    let bytes = opened.to_bytes_be();
    if bytes.len() > MD5_LENGTH {
        return false;
    }
    let mut padded = [0u8; MD5_LENGTH];
    if let Some(tail) = padded.get_mut(MD5_LENGTH.saturating_sub(bytes.len())..) {
        tail.copy_from_slice(&bytes);
    }
    padded == *payload_md5
}

#[must_use]
pub fn index_signature_holds(signed_lines: &[&[u8]], signature: &[u8]) -> bool {
    let mut message = Sha256::new();
    for line in signed_lines {
        message.update(line);
        message.update(b"\n");
    }
    let message_hash: [u8; 32] = message.finalize().into();
    let Some(value) = six_bit_number(signature) else {
        return false;
    };
    let opened = value
        .modpow(
            &BigUint::from(INDEX_KEY_EXPONENT),
            &modulus(INDEX_KEY_MODULUS),
        )
        .to_bytes_be();
    if opened.len() > INDEX_ENCODED_LENGTH {
        return false;
    }
    let mut encoded = vec![0u8; INDEX_ENCODED_LENGTH.saturating_sub(opened.len())];
    encoded.extend_from_slice(&opened);
    if encoded.last() != Some(&INDEX_TRAILER) {
        return false;
    }
    let (Some(masked), Some(hash)) = (
        encoded.get(..INDEX_MASKED_LENGTH),
        encoded.get(INDEX_MASKED_LENGTH..INDEX_ENCODED_LENGTH.saturating_sub(1)),
    ) else {
        return false;
    };
    let mut mask = Vec::with_capacity(INDEX_MASKED_LENGTH.saturating_add(32));
    let mut counter = 0u32;
    while mask.len() < INDEX_MASKED_LENGTH {
        let mut block = Sha256::new();
        block.update(hash);
        block.update(counter.to_be_bytes());
        mask.extend_from_slice(&block.finalize());
        counter = counter.saturating_add(1);
    }
    let mut unmasked: Vec<u8> = masked
        .iter()
        .zip(&mask)
        .map(|(byte, key)| byte ^ key)
        .collect();
    if let Some(first) = unmasked.first_mut() {
        *first &= 0x7f;
    }
    let Some(separator) = unmasked.iter().position(|byte| *byte == 0x01) else {
        return false;
    };
    let salt = unmasked
        .get(separator.saturating_add(1)..)
        .unwrap_or_default();
    if salt.len() != INDEX_SALT_LENGTH {
        return false;
    }
    let mut expected = Sha256::new();
    expected.update(INDEX_SALT_PREFIX);
    expected.update(message_hash);
    expected.update(salt);
    expected.finalize().as_slice() == hash
}

#[must_use]
pub fn detached_signature_holds(
    container: &[u8],
    sign_file: &[u8],
    level: u32,
) -> DetachedVerification {
    let Ok(text) = std::str::from_utf8(sign_file) else {
        return DetachedVerification::CannotVerify;
    };
    let mut lines = text.lines();
    let Some(first) = lines.next() else {
        return DetachedVerification::CannotVerify;
    };
    let version = first
        .strip_prefix(DETACHED_FORMAT_LINE)
        .and_then(|rest| rest.split_once('-'))
        .map(|(_, version)| version);
    if version != Some(DETACHED_FORMAT_VERSION) {
        return DetachedVerification::CannotVerify;
    }
    for line in lines.map(str::trim) {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut fields = line.splitn(4, ':');
        let (Some(lowest), Some(highest), Some(format), Some(data)) =
            (fields.next(), fields.next(), fields.next(), fields.next())
        else {
            return DetachedVerification::CannotVerify;
        };
        let Ok(lowest) = lowest.parse::<u32>() else {
            return DetachedVerification::CannotVerify;
        };
        let highest = if highest.is_empty() {
            None
        } else {
            match highest.parse::<u32>() {
                Ok(highest) => Some(highest),
                Err(_) => return DetachedVerification::CannotVerify,
            }
        };
        if lowest < DETACHED_SIGNATURE_LEVEL || format != DETACHED_SIGNATURE_FORMAT {
            return DetachedVerification::CannotVerify;
        }
        let Ok(signature) = Base64::decode_vec(data) else {
            return DetachedVerification::CannotVerify;
        };
        let Ok(signed) = signed_data(&signature) else {
            return DetachedVerification::CannotVerify;
        };
        if level < lowest || highest.is_some_and(|highest| level > highest) {
            continue;
        }
        match verify_signed_data(&signed, container) {
            Ok(()) => return DetachedVerification::Verified,
            Err(invalid) => return DetachedVerification::Invalid(invalid),
        }
    }
    DetachedVerification::CannotVerify
}

struct Unreadable;

fn signed_data(der_bytes: &[u8]) -> Result<SignedData, Unreadable> {
    let info = ContentInfo::from_der(der_bytes).map_err(|_| Unreadable)?;
    if info.content_type != SIGNED_DATA {
        return Err(Unreadable);
    }
    info.content
        .decode_as::<SignedData>()
        .map_err(|_| Unreadable)
}

fn verify_signed_data(
    signed: &SignedData,
    container: &[u8],
) -> Result<(), DetachedSignatureInvalid> {
    let certificates: Vec<&Certificate> = signed
        .certificates
        .iter()
        .flat_map(|set| set.0.iter())
        .filter_map(|choice| match choice {
            CertificateChoices::Certificate(certificate) => Some(certificate),
            CertificateChoices::Other(_) => None,
        })
        .collect();
    let signer_information = signed
        .signer_infos
        .0
        .iter()
        .next()
        .ok_or(DetachedSignatureInvalid::SignatureDoesNotVerify)?;
    if signer_information.digest_alg.oid != SHA256_ALGORITHM {
        return Err(DetachedSignatureInvalid::SignatureDoesNotVerify);
    }
    let SignerIdentifier::IssuerAndSerialNumber(identifier) = &signer_information.sid else {
        return Err(DetachedSignatureInvalid::ChainDoesNotReachTheTrustedRoot);
    };
    let signer_certificate = certificates
        .iter()
        .copied()
        .find(|certificate| {
            certificate.tbs_certificate.issuer == identifier.issuer
                && certificate.tbs_certificate.serial_number == identifier.serial_number
        })
        .ok_or(DetachedSignatureInvalid::ChainDoesNotReachTheTrustedRoot)?;
    let attributes = signer_information
        .signed_attrs
        .as_ref()
        .ok_or(DetachedSignatureInvalid::SignatureDoesNotVerify)?;
    let attribute = |oid: ObjectIdentifier| {
        attributes
            .iter()
            .find(|attribute| attribute.oid == oid)
            .and_then(|attribute| attribute.values.iter().next())
    };
    let digest = attribute(MESSAGE_DIGEST)
        .and_then(|value| value.decode_as::<der::asn1::OctetString>().ok())
        .ok_or(DetachedSignatureInvalid::DigestDiffers)?;
    if digest.as_bytes() != Sha256::digest(container).as_slice() {
        return Err(DetachedSignatureInvalid::DigestDiffers);
    }
    let content_type = attribute(CONTENT_TYPE)
        .and_then(|value| value.decode_as::<ObjectIdentifier>().ok())
        .ok_or(DetachedSignatureInvalid::SignatureDoesNotVerify)?;
    if content_type != DATA_CONTENT {
        return Err(DetachedSignatureInvalid::SignatureDoesNotVerify);
    }
    let signed_attributes = attributes
        .to_der()
        .map_err(|_| DetachedSignatureInvalid::SignatureDoesNotVerify)?;
    if signer_information.signature_algorithm.oid != RSA_ENCRYPTION
        && signer_information.signature_algorithm.oid != SHA256_WITH_RSA
    {
        return Err(DetachedSignatureInvalid::SignatureDoesNotVerify);
    }
    let key =
        rsa_key(signer_certificate).ok_or(DetachedSignatureInvalid::SignatureDoesNotVerify)?;
    if !key.holds(
        signer_information.signature.as_bytes(),
        &SHA256_DIGEST_INFO,
        &Sha256::digest(&signed_attributes),
    ) {
        return Err(DetachedSignatureInvalid::SignatureDoesNotVerify);
    }
    chain_reaches_the_trusted_root(signer_certificate, &certificates)
}

fn chain_reaches_the_trusted_root(
    signer: &Certificate,
    certificates: &[&Certificate],
) -> Result<(), DetachedSignatureInvalid> {
    let mut current = signer;
    for _ in 0..DEEPEST_CHAIN {
        let encoded = current
            .to_der()
            .map_err(|_| DetachedSignatureInvalid::ChainDoesNotReachTheTrustedRoot)?;
        if Sha256::digest(&encoded).as_slice() == TRUSTED_ROOT_FINGERPRINT {
            return Ok(());
        }
        let issuer = certificates
            .iter()
            .copied()
            .find(|candidate| {
                candidate.tbs_certificate.subject == current.tbs_certificate.issuer
                    && is_authority(candidate)
                    && certificate_signed_by(current, candidate)
            })
            .ok_or(DetachedSignatureInvalid::ChainDoesNotReachTheTrustedRoot)?;
        if std::ptr::eq(issuer, current) {
            return Err(DetachedSignatureInvalid::ChainDoesNotReachTheTrustedRoot);
        }
        current = issuer;
    }
    Err(DetachedSignatureInvalid::ChainDoesNotReachTheTrustedRoot)
}

fn is_authority(certificate: &Certificate) -> bool {
    certificate
        .tbs_certificate
        .extensions
        .iter()
        .flatten()
        .find(|extension| extension.extn_id == BASIC_CONSTRAINTS)
        .is_some_and(|extension| {
            let value = extension.extn_value.as_bytes();
            matches!(value, [0x30, _, 0x01, 0x01, flag, ..] if *flag != 0)
        })
}

fn certificate_signed_by(certificate: &Certificate, issuer: &Certificate) -> bool {
    let Ok(signed) = certificate.tbs_certificate.to_der() else {
        return false;
    };
    let Some(key) = rsa_key(issuer) else {
        return false;
    };
    let Some(signature) = certificate.signature.as_bytes() else {
        return false;
    };
    let algorithm = certificate.signature_algorithm.oid;
    if algorithm == SHA512_WITH_RSA {
        key.holds(signature, &SHA512_DIGEST_INFO, &Sha512::digest(&signed))
    } else if algorithm == SHA256_WITH_RSA {
        key.holds(signature, &SHA256_DIGEST_INFO, &Sha256::digest(&signed))
    } else {
        false
    }
}

struct RsaKey {
    modulus: BigUint,
    exponent: BigUint,
    length: usize,
}

impl RsaKey {
    fn holds(&self, signature: &[u8], digest_info: &[u8], digest: &[u8]) -> bool {
        if signature.len() != self.length {
            return false;
        }
        let value = BigUint::from_bytes_be(signature);
        if value >= self.modulus {
            return false;
        }
        let opened = value.modpow(&self.exponent, &self.modulus).to_bytes_be();
        let mut encoded = vec![0u8; self.length.saturating_sub(opened.len())];
        encoded.extend_from_slice(&opened);
        let suffix_length = digest_info.len().saturating_add(digest.len());
        let padding_length = self.length.saturating_sub(suffix_length).saturating_sub(3);
        if padding_length < SHORTEST_PADDING || encoded.len() != self.length {
            return false;
        }
        let mut expected = vec![0x00, 0x01];
        expected.extend(std::iter::repeat_n(0xff, padding_length));
        expected.push(0x00);
        expected.extend_from_slice(digest_info);
        expected.extend_from_slice(digest);
        expected == encoded
    }
}

fn rsa_key(certificate: &Certificate) -> Option<RsaKey> {
    let public_key = &certificate.tbs_certificate.subject_public_key_info;
    if public_key.algorithm.oid != RSA_ENCRYPTION {
        return None;
    }
    let (modulus, exponent) = rsa_public_key(public_key.subject_public_key.as_bytes()?)?;
    let modulus = BigUint::from_bytes_be(modulus);
    let length = usize::try_from(modulus.bits().div_ceil(8)).ok()?;
    Some(RsaKey {
        exponent: BigUint::from_bytes_be(exponent),
        modulus,
        length,
    })
}

fn der_element(bytes: &[u8], tag: u8) -> Option<(&[u8], &[u8])> {
    let (found, rest) = bytes.split_first()?;
    if *found != tag {
        return None;
    }
    let (first, rest) = rest.split_first()?;
    let (length, rest) = if *first < 0x80 {
        (usize::from(*first), rest)
    } else {
        let count = usize::from(first & 0x7f);
        if count == 0 || count > 4 {
            return None;
        }
        let (digits, rest) = rest.split_at_checked(count)?;
        let length = digits.iter().try_fold(0usize, |length, digit| {
            length.checked_mul(256)?.checked_add(usize::from(*digit))
        })?;
        (length, rest)
    };
    rest.split_at_checked(length)
}

fn rsa_public_key(bytes: &[u8]) -> Option<(&[u8], &[u8])> {
    let (sequence, _) = der_element(bytes, 0x30)?;
    let (modulus, rest) = der_element(sequence, 0x02)?;
    let (exponent, _) = der_element(rest, 0x02)?;
    Some((modulus, exponent))
}
