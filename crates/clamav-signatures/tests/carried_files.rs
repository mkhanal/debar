#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    clippy::cast_possible_truncation
)]

use debar_clamav_signatures::{
    Account, DatabaseError, DatabaseFile, LineOutcome, MalformedCertificateLine, MalformedIconLine,
    MalformedProgram, MalformedSwitchLine, MalformedUrlLine, compile,
};
use debar_image::{
    CertificateTrust, EngineFeature, Image, ImageBuilder, ProgramKind, RecordedUrlPattern, UrlList,
    UrlVerdict,
};

struct Compiled {
    image: Vec<u8>,
    account: Account,
}

fn compile_files(files: &[(&str, &[u8])]) -> Result<Compiled, DatabaseError> {
    let files: Vec<DatabaseFile<'_>> = files
        .iter()
        .map(|(name, contents)| DatabaseFile { name, contents })
        .collect();
    let mut builder = ImageBuilder::new();
    let account = compile(&files, &mut builder)?;
    Ok(Compiled {
        image: builder.finish().unwrap(),
        account,
    })
}

fn outcomes(compiled: &Compiled, file: &str) -> Vec<LineOutcome> {
    compiled
        .account
        .files
        .iter()
        .find(|account| account.file == file)
        .unwrap()
        .lines
        .clone()
}

#[test]
fn switches_that_apply_at_the_functionality_level_replace_the_word_of_their_module() {
    let compiled = compile_files(&[(
        "daily.cfg",
        b"# comment\nPE:0x0:51:51\nPHISHING:0x2\nOTHER:0x0:235\nDOCUMENT:0x1:0:234\nFOO:0x1\n",
    )])
    .unwrap();
    assert_eq!(
        outcomes(&compiled, "daily.cfg"),
        [
            LineOutcome::Comment,
            LineOutcome::OutsideFunctionalityLevel,
            LineOutcome::Compiled,
            LineOutcome::OutsideFunctionalityLevel,
            LineOutcome::Compiled,
            LineOutcome::NotASignature,
        ]
    );
    let image = Image::open(&compiled.image).unwrap();
    let features = image.engine_features().unwrap().unwrap();
    assert!(features.contains(EngineFeature::UnpackUpx));
    assert!(!features.contains(EngineFeature::PhishingEngine));
    assert!(features.contains(EngineFeature::PhishingEntityConversion));
    assert!(features.contains(EngineFeature::OtherJpeg));
    assert!(features.contains(EngineFeature::DocumentHtml));
    assert!(!features.contains(EngineFeature::DocumentPdf));
    assert!(!features.contains(EngineFeature::ExecutableSwizzorCheck));
}

#[test]
fn without_switch_files_every_feature_keeps_its_default() {
    let compiled =
        compile_files(&[("x.hdb", b"44d88612fea8a8f36de82e1278abb02f:68:Eicar\n")]).unwrap();
    let image = Image::open(&compiled.image).unwrap();
    let enabled: Vec<EngineFeature> = image
        .engine_features()
        .unwrap()
        .unwrap()
        .enabled()
        .map(Result::unwrap)
        .collect();
    assert_eq!(enabled.len(), EngineFeature::ALL.len() - 5);
    for off in [
        EngineFeature::ExecutableSwizzorCheck,
        EngineFeature::OtherMydoomLog,
        EngineFeature::ProgramCompilerArm,
        EngineFeature::StatisticsOff,
        EngineFeature::SectionStatisticsOff,
    ] {
        assert!(!enabled.contains(&off), "{off:?}");
    }
}

#[test]
fn a_switch_line_whose_bits_are_not_hexadecimal_fails_the_compile_only_when_it_applies() {
    assert!(compile_files(&[("daily.cfg", b"PE:zz:999\n")]).is_ok());
    for line in [&b"PE:zz\n"[..], b"PE:0X0\n", b"PE: 0x0\n"] {
        assert!(matches!(
            compile_files(&[("daily.cfg", line)]),
            Err(DatabaseError::MalformedSwitchLine {
                reason: MalformedSwitchLine,
                ..
            })
        ));
    }
}

const SUBJECT: &str = "1111111111111111111111111111111111111111";
const SERIAL_A: &str = "2222222222222222222222222222222222222222";
const SERIAL_B: &str = "3333333333333333333333333333333333333333";

fn certificate_line(
    name: &str,
    trusted: &str,
    serial: &str,
    modulus: &str,
    levels: &str,
) -> String {
    format!("{name};{trusted};{SUBJECT};{serial};{modulus};010001;1;0;0;;comment{levels}\n")
}

#[test]
fn certificate_rules_load_with_their_fields_and_a_blank_serial_stops_later_serial_comparison() {
    let text = [
        "# There must always be one line in the file\n".to_owned(),
        certificate_line("Blocked.One", "0", SERIAL_A, "00C0FFEE", ""),
        certificate_line("Blocked.Two", "0", "", "BEEF", ""),
        certificate_line("Blocked.Three", "0", SERIAL_A, "C0FFEE", ""),
        certificate_line("Blocked.Four", "0", SERIAL_B, "C0FFEE", ""),
        certificate_line("Trusted.Later", "1", SERIAL_B, "ABCD", ";235"),
        certificate_line("Trusted.Bounded", "1x", SERIAL_B, "ABCD", ";0;234"),
    ]
    .concat();
    let compiled = compile_files(&[("local.crb", text.as_bytes())]).unwrap();
    assert_eq!(
        outcomes(&compiled, "local.crb"),
        [
            LineOutcome::Comment,
            LineOutcome::Compiled,
            LineOutcome::Compiled,
            LineOutcome::ShadowedByDuplicate,
            LineOutcome::Compiled,
            LineOutcome::OutsideFunctionalityLevel,
            LineOutcome::Compiled,
        ]
    );
    let image = Image::open(&compiled.image).unwrap();
    let rules: Vec<_> = image
        .certificate_rules()
        .unwrap()
        .unwrap()
        .rules()
        .map(Result::unwrap)
        .collect();
    let names: Vec<_> = rules
        .iter()
        .map(|rule| rule.name.clone().unwrap())
        .collect();
    assert_eq!(
        names,
        [
            "Trusted.Bounded",
            "Blocked.Four",
            "Blocked.Two",
            "Blocked.One"
        ]
    );
    assert_eq!(rules[0].trust, CertificateTrust::Trusted);
    assert!(!rules[1].compares_serial);
    assert!(rules[3].compares_serial);
    assert_eq!(rules[3].modulus, [0xc0, 0xff, 0xee]);
    assert_eq!(rules[3].exponent, 65_537);
    assert!(rules[3].code_signing && !rules[3].time_stamping);
}

#[test]
fn a_malformed_certificate_rule_fails_the_compile() {
    let cases: [(String, MalformedCertificateLine); 5] = [
        (
            "a;0;b;c\n".to_owned(),
            MalformedCertificateLine::FieldCount(4),
        ),
        (
            certificate_line("X", "2", SERIAL_A, "AB", ""),
            MalformedCertificateLine::TrustNotOneOrZero,
        ),
        (
            certificate_line("X", "0", "12", "AB", ""),
            MalformedCertificateLine::SerialLength,
        ),
        (
            certificate_line("X", "0", SERIAL_A, "zz", ""),
            MalformedCertificateLine::PublicKeyNotHexadecimal,
        ),
        (
            certificate_line("X", "0", SERIAL_A, "AB", ";a"),
            MalformedCertificateLine::LowestLevelNotANumber,
        ),
    ];
    for (line, expected) in cases {
        match compile_files(&[("local.crb", line.as_bytes())]) {
            Err(DatabaseError::MalformedCertificateLine {
                reason, line: 1, ..
            }) => {
                assert_eq!(reason, expected, "{line}");
            }
            other => panic!("{line}: {:?}", other.map(|_| ())),
        }
    }
}

#[test]
fn certificate_rules_are_not_loaded_when_a_switch_turns_certificates_off() {
    let compiled =
        compile_files(&[("daily.cfg", b"PE:0x0\n"), ("local.crb", b"garbage\n")]).unwrap();
    assert_eq!(outcomes(&compiled, "local.crb"), [LineOutcome::NotLoaded]);
}

fn icon_hash(edge_length: u8, colour_x: u8, spread: &str) -> String {
    let point3 = format!("{:03x}{colour_x:02x}01", 0x100);
    let point2 = "100101";
    format!(
        "{edge_length:02x}{}{}{}{}{}{}{spread}",
        point3.repeat(3),
        point3.repeat(3),
        point2.repeat(3),
        point2.repeat(3),
        point2.repeat(3),
        point2.repeat(3)
    )
}

#[test]
fn icon_signatures_load_into_two_group_namespaces() {
    let good = icon_hash(24, 21, "01020364");
    assert_eq!(good.len(), 124);
    let text = format!(
        "# There must always be one line in the file\nIcon.One:MS:IE:{good}\nIcon.Two:DOCUMENT:IE:{good}\nIcon.Three:MS:MS:{good}\nIcon.Ignored:MS:IE:{good}\n"
    );
    let compiled = compile_files(&[
        ("local.ign2", b"Icon.Ignored\n"),
        ("local.idb", text.as_bytes()),
    ])
    .unwrap();
    assert_eq!(
        outcomes(&compiled, "local.idb"),
        [
            LineOutcome::Comment,
            LineOutcome::Compiled,
            LineOutcome::Compiled,
            LineOutcome::Compiled,
            LineOutcome::Ignored,
        ]
    );
    let groups = Image::open(&compiled.image)
        .unwrap()
        .icon_groups()
        .unwrap()
        .unwrap();
    assert_eq!(groups.first, ["MS", "DOCUMENT"]);
    assert_eq!(groups.second, ["IE", "MS"]);
    let placed: Vec<(u16, u16)> = groups
        .signatures
        .iter()
        .map(|signature| (signature.first_group, signature.second_group))
        .collect();
    assert_eq!(placed, [(0, 0), (1, 0), (0, 1)]);
    assert_eq!(groups.signatures[0].metrics.edge_length, 24);
    assert_eq!(groups.signatures[0].metrics.colour[0].average, 0x100);
    assert_eq!(groups.signatures[0].metrics.colour_count, 100);
}

#[test]
fn a_malformed_icon_signature_fails_the_compile() {
    let cases = [
        ("\n".to_owned(), MalformedIconLine::WrongFieldCount),
        (
            format!("a:b:c:{}\n", "0".repeat(123)),
            MalformedIconLine::WrongLength,
        ),
        (
            format!("a:b:c:{}\n", icon_hash(48, 1, "01020364")),
            MalformedIconLine::EdgeLength,
        ),
        (
            format!("a:b:c:{}\n", icon_hash(24, 22, "01020364")),
            MalformedIconLine::Colour,
        ),
        (
            format!("a:b:c:{}\n", icon_hash(24, 21, "68000000")),
            MalformedIconLine::Spread,
        ),
    ];
    for (line, expected) in cases {
        match compile_files(&[("local.idb", line.as_bytes())]) {
            Err(DatabaseError::MalformedIconLine { reason, .. }) => assert_eq!(reason, expected),
            other => panic!("{line}: {:?}", other.map(|_| ())),
        }
    }
}

#[test]
fn url_rules_load_by_kind_into_the_monitored_and_allowed_lists() {
    let monitored = b"# c\n\nH:paypal.com\nR:evil\\.example\\.com\nS1:F:abcd\nS:P:00112233\nH:a.com:300-\nH:b.com:-\n";
    let allowed = b"M:evil.example.com:www.paypal.com\nX:.+\\.example\\.com([/?].*)?:www\\.paypal\\.com([/?].*)?\nX:.+\\.example\\.com:www\\.paypal\\.co[m]{1}([/?].*)?\nS:W:abcd\n";
    let compiled = compile_files(&[("local.pdb", monitored), ("local.wdb", allowed)]).unwrap();
    assert_eq!(
        outcomes(&compiled, "local.pdb"),
        [
            LineOutcome::Comment,
            LineOutcome::Comment,
            LineOutcome::Compiled,
            LineOutcome::Compiled,
            LineOutcome::Compiled,
            LineOutcome::Compiled,
            LineOutcome::OutsideFunctionalityLevel,
            LineOutcome::Compiled,
        ]
    );
    let image = Image::open(&compiled.image).unwrap();
    let rules: Vec<_> = image
        .url_rules()
        .unwrap()
        .unwrap()
        .rules()
        .map(Result::unwrap)
        .collect();
    assert_eq!(rules.len(), 9);
    assert_eq!(rules[0].list, UrlList::Monitored);
    assert_eq!(rules[0].pattern, RecordedUrlPattern::Host(b"paypal.com/"));
    assert!(matches!(
        rules[1].pattern,
        RecordedUrlPattern::Expression {
            text: b"evil\\.example\\.com/",
            ..
        }
    ));
    assert_eq!(
        rules[2].pattern,
        RecordedUrlPattern::Digest {
            digest: &[0xab, 0xcd],
            verdict: UrlVerdict::Blocked
        }
    );
    assert!(rules[3].never_matches);
    assert_eq!(rules[4].pattern, RecordedUrlPattern::Host(b"b.com/"));
    assert_eq!(rules[5].list, UrlList::Allowed);
    let RecordedUrlPattern::Expression { text, .. } = rules[6].pattern else {
        panic!("an expression");
    };
    assert_eq!(text, b".+\\.example\\.com([/?].*)?:www\\.paypal\\.com/");
    assert!(!rules[6].never_matches);
    assert!(rules[7].never_matches);
}

#[test]
fn an_allowed_digest_loaded_first_shadows_the_same_digest_listed_later() {
    let compiled = compile_files(&[("local.gdb", b"S:W:abcd\nS:F:abcd\n")]).unwrap();
    assert_eq!(
        outcomes(&compiled, "local.gdb"),
        [LineOutcome::Compiled, LineOutcome::ShadowedByDuplicate]
    );
}

#[test]
fn a_malformed_url_rule_fails_the_compile() {
    let cases: [(&str, &[u8], MalformedUrlLine); 6] = [
        ("local.pdb", b"Hpaypal.com\n", MalformedUrlLine::NoSeparator),
        (
            "local.pdb",
            b"X:a\\.com\n",
            MalformedUrlLine::KindNotAccepted(b'X'),
        ),
        (
            "local.wdb",
            b"H:a.com\n",
            MalformedUrlLine::KindNotAccepted(b'H'),
        ),
        ("local.pdb", b"R:.*\n", MalformedUrlLine::PatternTooShort),
        ("local.pdb", b"H:\n", MalformedUrlLine::PatternTooShort),
        (
            "local.pdb",
            b"S:Q:abcd\n",
            MalformedUrlLine::DigestType(b'Q'),
        ),
    ];
    for (name, line, expected) in cases {
        match compile_files(&[(name, line)]) {
            Err(DatabaseError::MalformedUrlLine { reason, .. }) => assert_eq!(reason, expected),
            other => panic!(
                "{:?}: {:?}",
                String::from_utf8_lossy(line),
                other.map(|_| ())
            ),
        }
    }
    assert!(matches!(
        compile_files(&[("local.pdb", b"R:a(b\n")]),
        Err(DatabaseError::MalformedUrlLine {
            reason: MalformedUrlLine::Expression(_),
            ..
        })
    ));
}

#[test]
fn url_rules_are_not_loaded_when_a_switch_turns_the_phishing_engine_off() {
    let compiled = compile_files(&[
        ("daily.cfg", b"PHISHING:0x2:0:255\n"),
        ("local.pdb", b"Q:bad\n"),
    ])
    .unwrap();
    assert_eq!(outcomes(&compiled, "local.pdb"), [LineOutcome::NotLoaded]);
}

fn number(value: u64) -> String {
    if value == 0 {
        return "`".to_owned();
    }
    let mut nibbles = String::new();
    let mut rest = value;
    while rest > 0 {
        nibbles.push(char::from(0x60 + (rest & 0xf) as u8));
        rest >>= 4;
    }
    format!("{}{nibbles}", char::from(0x60 + nibbles.len() as u8))
}

fn fixed(value: u64, width: u32) -> String {
    (0..width)
        .map(|index| char::from(0x60 + ((value >> (4 * index)) & 0xf) as u8))
        .collect()
}

fn empty_string() -> String {
    format!("|{}", number(0))
}

fn program(kind: u64, levels: (u64, u64), trigger: &str, opcode: u64) -> String {
    let header = [
        "ClamBC".to_owned(),
        number(7),
        number(0),
        empty_string(),
        number(0),
        number(kind),
        number(levels.0),
        number(levels.1),
        number(0),
        empty_string(),
        number(5),
        number(1),
        number(0x53e5_493e_9f3d_1c30),
        fixed(42, 2),
        ":4096".to_owned(),
    ]
    .concat();
    let function = format!(
        "A{}{}L{}F{}{}",
        fixed(0, 1),
        number(32),
        number(0),
        number(1),
        number(1)
    );
    let block = format!("BT{}{}@dE", fixed(opcode, 2), number(32));
    format!(
        "{header}\n{trigger}\nT{}\nE{}{}\nG{}{}\n{function}\n{block}\nS source\n",
        fixed(69, 2),
        number(0),
        number(0),
        number(0),
        number(0)
    )
}

const TRIGGER: &str = "Test.Program;Engine:51-255,Target:0;0;41424344";

#[test]
fn a_signature_program_compiles_with_its_trigger_as_a_logical_signature() {
    let text = program(256, (51, 0), TRIGGER, 19);
    let compiled = compile_files(&[("test.cbc", text.as_bytes())]).unwrap();
    assert!(
        outcomes(&compiled, "test.cbc")
            .iter()
            .all(|outcome| *outcome == LineOutcome::Compiled)
    );
    let image = Image::open(&compiled.image).unwrap();
    let programs: Vec<_> = image
        .signature_programs()
        .unwrap()
        .unwrap()
        .programs()
        .map(Result::unwrap)
        .collect();
    assert_eq!(programs.len(), 1);
    assert_eq!(programs[0].kind, ProgramKind::Logical);
    assert!(programs[0].triggered);
    assert!(!programs[0].from_signed_container);
    assert_eq!(programs[0].functions.len(), 1);
    assert_eq!(programs[0].functions[0].blocks[0].len(), 1);
    let logical = image
        .logical_group(debar_image::SignatureGroup(0))
        .unwrap()
        .unwrap();
    assert_eq!(logical.signature_count(), 1);
}

#[test]
fn a_hook_program_without_a_trigger_compiles_and_a_program_outside_the_level_is_left_out() {
    let hook = program(258, (0, 0), "PDF.Hook", 19);
    let late = program(256, (235, 0), TRIGGER, 19);
    let compiled =
        compile_files(&[("hook.cbc", hook.as_bytes()), ("late.cbc", late.as_bytes())]).unwrap();
    assert!(
        outcomes(&compiled, "hook.cbc")
            .iter()
            .all(|outcome| *outcome == LineOutcome::Compiled)
    );
    assert!(
        outcomes(&compiled, "late.cbc")
            .iter()
            .all(|outcome| *outcome == LineOutcome::OutsideFunctionalityLevel)
    );
    let image = Image::open(&compiled.image).unwrap();
    let programs: Vec<_> = image
        .signature_programs()
        .unwrap()
        .unwrap()
        .programs()
        .map(Result::unwrap)
        .collect();
    assert_eq!(programs.len(), 1);
    assert_eq!(programs[0].kind, ProgramKind::Pdf);
    assert!(!programs[0].triggered);
}

#[test]
fn a_malformed_signature_program_fails_the_compile() {
    let cases = [
        (
            program(256, (51, 0), TRIGGER, 19).replace("ClamBC", "ClamBX"),
            MalformedProgram::MissingFileMagic,
        ),
        (
            program(256, (51, 0), "Test.Program", 19),
            MalformedProgram::MissingTrigger,
        ),
        (
            program(0, (51, 0), TRIGGER, 19),
            MalformedProgram::UnhandledKind(0),
        ),
        (
            program(256, (51, 0), TRIGGER, 51),
            MalformedProgram::InvalidOpcode(51),
        ),
        (
            program(256, (51, 0), TRIGGER, 0),
            MalformedProgram::NotPrepared("unhandled opcode"),
        ),
    ];
    for (text, expected) in cases {
        match compile_files(&[("test.cbc", text.as_bytes())]) {
            Err(DatabaseError::MalformedProgram { reason, .. }) => assert_eq!(reason, expected),
            other => panic!("{expected:?}: {:?}", other.map(|_| ())),
        }
    }
    assert!(matches!(
        compile_files(&[(
            "test.cbc",
            program(256, (51, 0), &TRIGGER.replace("51-255", "51-60"), 19).as_bytes()
        )]),
        Err(DatabaseError::ProgramTriggerNotLoaded { .. })
    ));
}
