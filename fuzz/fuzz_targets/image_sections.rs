#![forbid(unsafe_code)]
#![no_main]

use debar_image::{
    CertificateRule, CertificateTrust, EngineFeature, IconGroups, IconMetrics, IconSignature,
    ProgramConstant, ProgramFunction, ProgramGlobal, ProgramInstruction, ProgramKind,
    ProgramOperand, ProgramOperation, ProgramType, SignatureProgram, UrlList, UrlPattern, UrlRule,
    UrlVerdict,
    ByteSet, Category, Digest, DigestAlgorithm, ExecutableAnchor, HashPurpose, HashSignature,
    HashedSize, Image, ImageBuilder, Indicator, KindDescription, MagicTable, MaskedByte,
    ObjectKind, OwnBytes, PartMemory, PartitionKey, Pattern, PatternElement, PatternOutcome,
    PatternSignature, Placement, RecognitionRank, SignatureGroup, TypeFinding, TypingRules,
    WideTextRetry,
};
use debar_matching::{ObjectContext, UnwantedCategories, 
    ExecutableLayout, ExecutableSection, GroupSelection, PatternRequest, PatternScan,
    PatternSettings,
};

const GENERIC: SignatureGroup = SignatureGroup(0);
const EXECUTABLES: SignatureGroup = SignatureGroup(1);
const RECOGNITION: SignatureGroup = SignatureGroup(2);
use libfuzzer_sys::fuzz_target;

const SIGNATURE_COUNT: u8 = 24;

fn digest(seed: u8) -> [u8; 16] {
    let mut bytes = [seed; 16];
    bytes[0] = seed.wrapping_mul(37);
    bytes
}

fn add_carried_sections(builder: &mut ImageBuilder) {
    builder.set_engine_features(&[EngineFeature::ArchiveZip, EngineFeature::PhishingEngine]);
    builder.add_certificate_rule(CertificateRule {
        name: Some("Fuzz.Certificate".to_owned()),
        trust: CertificateTrust::Blocked,
        subject: [1; 20],
        serial: [2; 20],
        compares_serial: true,
        modulus: vec![0xc0, 0xff, 0xee],
        exponent: 65_537,
        code_signing: true,
        time_stamping: false,
        certificate_signing: false,
        not_before: 0,
    });
    builder.set_icon_groups(IconGroups {
        first: vec!["MS".to_owned()],
        second: vec!["IE".to_owned()],
        signatures: vec![IconSignature {
            name: "Fuzz.Icon".to_owned(),
            first_group: 0,
            second_group: 0,
            metrics: IconMetrics::default(),
        }],
    });
    builder.add_url_rule(UrlRule {
        list: UrlList::Monitored,
        pattern: UrlPattern::Host(b"example.com/".to_vec()),
        never_matches: false,
    });
    builder.add_url_rule(UrlRule {
        list: UrlList::Allowed,
        pattern: UrlPattern::Digest {
            digest: vec![0xab; 32],
            verdict: UrlVerdict::Allowed,
        },
        never_matches: false,
    });
    let _ = builder.add_signature_program(SignatureProgram {
        name: "fuzz.cbc".to_owned(),
        kind: ProgramKind::Logical,
        from_signed_container: false,
        triggered: true,
        apis: vec![5],
        types: vec![ProgramType::Pointer(8)],
        globals: vec![ProgramGlobal {
            type_id: 32,
            initial: vec![7],
        }],
        functions: vec![ProgramFunction {
            argument_count: 0,
            return_type: 32,
            values: Vec::new(),
            constants: vec![ProgramConstant { value: 0, bits: 32 }],
            blocks: vec![vec![ProgramInstruction {
                operation: ProgramOperation::Return,
                result_type: 32,
                destination: 0,
                operands: vec![ProgramOperand::Constant(0)],
                blocks: Vec::new(),
                callee: None,
                type_operand: None,
            }]],
        }],
    });
}

fn valid_image() -> Vec<u8> {
    let names: Vec<String> = (0..SIGNATURE_COUNT)
        .map(|index| format!("Fuzz.Name-{index}"))
        .collect();
    let mut builder = ImageBuilder::new();
    for (index, name) in (0..SIGNATURE_COUNT).zip(&names) {
        let size = if index % 5 == 0 {
            HashedSize::Any
        } else {
            HashedSize::Exactly(u32::from(index % 4) + 1)
        };
        let _ = builder.add_hash_signature(&HashSignature {
            purpose: HashPurpose::WholeObjectDetection,
            category: Category::Malware,
            size,
            digest: Digest::Md5(digest(index)),
            name,
            indicator: Indicator::Strong,
        });
    }
    let exact = |text: &[u8]| -> Vec<PatternElement> {
        text.iter()
            .map(|byte| PatternElement::Byte(MaskedByte::exactly(*byte)))
            .collect()
    };
    let mut chained = exact(b"fuzz");
    chained.push(PatternElement::Gap {
        minimum: 0,
        maximum: None,
    });
    chained.extend(exact(b"zzuf"));
    chained.push(PatternElement::PartBreak {
        minimum: 1,
        maximum: Some(9),
    });
    chained.extend(exact(b"ab"));
    let patterns = [
        (
            Pattern {
                before: None,
                elements: chained,
                after: None,
            },
            Placement::Anywhere,
        ),
        (
            Pattern {
                before: None,
                elements: exact(b"head"),
                after: None,
            },
            Placement::FromStart {
                distance: 0,
                shift: 4,
            },
        ),
        (
            Pattern {
                before: None,
                elements: exact(b"xy"),
                after: None,
            },
            Placement::BeforeEnd {
                distance: 2,
                shift: 0,
            },
        ),
    ];
    for ((pattern, placement), name) in patterns.iter().zip(["Fuzz.A", "Fuzz.B", "Fuzz.C"]) {
        let _ = builder.add_pattern_signature(&PatternSignature {
            group: GENERIC,
            category: Category::Malware,
            placement: *placement,
            report_rank: 0,
            pattern,
            outcome: PatternOutcome::Detection {
                name,
                indicator: Indicator::Strong,
            },
        });
    }
    let _ = builder.add_pattern_signature(&PatternSignature {
        group: EXECUTABLES,
        category: Category::Malware,
        placement: Placement::InExecutable {
            anchor: ExecutableAnchor::SectionStart {
                section: 0,
                distance: 1,
            },
            shift: 3,
        },
        report_rank: 0,
        pattern: &Pattern {
            before: None,
            elements: exact(b"of a"),
            after: None,
        },
        outcome: PatternOutcome::Detection {
            name: "Fuzz.D",
            indicator: Indicator::Strong,
        },
    });
    let _ = builder.add_pattern_signature(&PatternSignature {
        group: RECOGNITION,
        category: Category::Malware,
        placement: Placement::Anywhere,
        report_rank: 0,
        pattern: &Pattern {
            before: None,
            elements: exact(b"zzuf"),
            after: None,
        },
        outcome: PatternOutcome::TypeFound(TypeFinding {
            found: ObjectKind::Html,
            required: None,
        }),
    });
    builder.set_part_memory(GENERIC, PartMemory::FirstAndLatestEnds { latest: 8 });
    builder.describe_object_kind(
        ObjectKind::WindowsExecutable,
        KindDescription {
            format_name: "executable".to_owned(),
            groups: vec![EXECUTABLES, GENERIC],
            recognition: RecognitionRank {
                priority: 7,
                always_replaces: true,
                left_for_the_full_scan: false,
                ends_recognition: false,
            },
            own_bytes: OwnBytes::Matched {
                as_kind: None,
                recognising_types: true,
            },
            found_in_full_scan_retypes: vec![ObjectKind::Text],
            executable: true,
        },
    );
    builder.set_typing(TypingRules {
        prefix_length: 1024,
        recognition_group: Some(RECOGNITION),
        text_bytes: ByteSet::of(0x20..=0x7e),
        wide_text_retry: Some(WideTextRetry {
            found: ObjectKind::Html,
            becomes: ObjectKind::HtmlUtf16,
        }),
    });
    builder.add_type_magic(MagicTable::Files, 0, b"head", ObjectKind::WindowsExecutable);
    add_carried_sections(&mut builder);
    builder.finish().unwrap_or_default()
}

const OBJECT: &[u8] = b"head of a fuzz object, zzuf, a-ab and more; it ends xy";

fuzz_target!(|data: &[u8]| {
    let mut bytes = valid_image();
    let Ok(sections) = Image::open(&bytes).map(|image| image.sections().to_vec()) else {
        return;
    };
    let section_bytes: Vec<usize> = sections
        .iter()
        .flat_map(|section| section.range.clone())
        .collect();
    for pair in data.chunks_exact(3) {
        let at = usize::from(u16::from_le_bytes([pair[0], pair[1]]));
        if let Some(offset) = section_bytes.get(at % section_bytes.len().max(1)) {
            bytes[*offset] ^= pair[2];
        }
    }
    let Ok(image) = Image::open(&bytes) else {
        return;
    };
    let key = PartitionKey {
        purpose: HashPurpose::WholeObjectDetection,
        category: Category::Malware,
        algorithm: DigestAlgorithm::Md5,
    };
    let _ = image.databases();
    if let Ok(Some(features)) = image.engine_features() {
        let _ = features.enabled().count();
    }
    if let Ok(Some(rules)) = image.certificate_rules() {
        let _ = rules.rules().count();
    }
    let _ = image.icon_groups();
    if let Ok(Some(rules)) = image.url_rules() {
        let _ = rules.rules().count();
    }
    if let Ok(Some(programs)) = image.signature_programs() {
        let _ = programs.programs().count();
    }
    if let Ok(Some(kinds)) = image.object_kinds() {
        let _ = kinds.describe(ObjectKind::WindowsExecutable);
        let _ = kinds.described().count();
    }
    if let Ok(Some(magic)) = image.type_magic() {
        let _ = magic.first_match(MagicTable::Files, OBJECT);
    }
    let settings = PatternSettings {
        potentially_unwanted: true,
        unwanted_categories: UnwantedCategories::Every,
        every_match: true,
        largest_object_for_regular_expressions: None,
    };
    let request = PatternRequest {
        selection: GroupSelection::ForKindRecognisingTypes(ObjectKind::WindowsExecutable),
        settings,
        object_length: OBJECT.len() as u64,
        context: ObjectContext::TOP_LEVEL,
        image_fuzzy_hash: None,
    };
    let layout = || {
        Some(ExecutableLayout {
            entry_point: 3,
            sections: vec![ExecutableSection {
                start: 4,
                length: 9,
            }],
            version_information: Vec::new(),
        })
    };
    if let Ok(mut scan) = PatternScan::new(&image, request, layout) {
        for chunk in OBJECT.chunks(5) {
            if scan.feed(chunk).is_err() {
                break;
            }
        }
        let _ = scan.finish();
    }
    if let Ok(Some(partition)) = image.hash_partition(key) {
        for index in 0..SIGNATURE_COUNT {
            if let Ok(Some(name)) =
                partition.lookup_exact_size(u32::from(index % 4) + 1, &digest(index))
            {
                let _ = image.signature_name(name);
            }
            if let Ok(Some(name)) = partition.lookup_any_size(&digest(index)) {
                let _ = image.signature_name(name);
            }
        }
    }
});
