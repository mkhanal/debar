#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use std::path::{Path, PathBuf};

use acceptance::{
    CompiledImage, comparison_report, comparison_report_with, compile, detections,
    scratch_directory, write_file,
};

fn loose_databases(test: &str, files: &[(&str, &str)]) -> (PathBuf, CompiledImage) {
    let directory = scratch_directory(test).unwrap();
    let databases = directory.join("databases");
    std::fs::create_dir(&databases).unwrap();
    for (name, text) in files {
        write_file(&databases.join(name), text.as_bytes()).unwrap();
    }
    let compiled = compile(&databases, &directory, "loose").unwrap();
    (directory, compiled)
}

fn file_with(pieces: &[&[u8]]) -> Vec<u8> {
    let mut contents = b"..........".to_vec();
    for piece in pieces {
        contents.extend_from_slice(piece);
        contents.extend_from_slice(b"..........");
    }
    contents
}

fn detected(directory: &Path, image: &Path, pieces: &[&[u8]]) -> Vec<String> {
    let input = directory.join("input");
    write_file(&input, &file_with(pieces)).unwrap();
    detections(&comparison_report(image, &input, directory).unwrap())
}

fn wide(text: &[u8]) -> Vec<u8> {
    text.iter().flat_map(|byte| [*byte, 0]).collect()
}

const EXPRESSIONS: &str = "\
Test.Both;Target:0;0&1;414243444546;4748494a
Test.Either;Target:0;0|1;4b4c4d4e;4f505152
Test.MoreThanTwo;Target:0;0>2;53545556
Test.ExactlyTwo;Target:0;0=2;5758595a
Test.FewerThanTwo;Target:0;0&1<2;31323334;35363738
Test.Block;Target:0;(0|1)>2,2;696a6b6c;6d6e6f70
";

#[test]
fn a_file_is_detected_under_a_logical_signatures_name_exactly_when_its_expression_holds() {
    const REQUIREMENT: &str =
        "A File Is Detected Under A Logical Signature's Name Exactly When Its Expression Holds";
    let (directory, compiled) =
        loose_databases("logical-expressions", &[("local.ldb", EXPRESSIONS)]);
    let scan = |pieces: &[&[u8]]| detected(&directory, &compiled.image, pieces);

    assert_eq!(
        scan(&[b"ABCDEF", b"GHIJ"]),
        ["Test.Both.UNOFFICIAL"],
        "{REQUIREMENT}"
    );
    assert_eq!(scan(&[b"ABCDEF"]), Vec::<String>::new(), "{REQUIREMENT}");
    assert_eq!(
        scan(&[b"OPQR"]),
        ["Test.Either.UNOFFICIAL"],
        "{REQUIREMENT}"
    );
    assert_eq!(
        scan(&[b"STUV", b"STUV"]),
        Vec::<String>::new(),
        "{REQUIREMENT}"
    );
    assert_eq!(
        scan(&[b"STUV", b"STUV", b"STUV"]),
        ["Test.MoreThanTwo.UNOFFICIAL"],
        "{REQUIREMENT}"
    );
    assert_eq!(
        scan(&[b"WXYZ", b"WXYZ"]),
        ["Test.ExactlyTwo.UNOFFICIAL"],
        "{REQUIREMENT}"
    );
    assert_eq!(
        scan(&[b"WXYZ", b"WXYZ", b"WXYZ"]),
        Vec::<String>::new(),
        "{REQUIREMENT}"
    );
    assert_eq!(
        scan(&[b"1234", b"5678"]),
        ["Test.FewerThanTwo.UNOFFICIAL"],
        "{REQUIREMENT}"
    );
    assert_eq!(
        scan(&[b"1234", b"5678", b"5678"]),
        Vec::<String>::new(),
        "{REQUIREMENT}"
    );
    assert_eq!(
        scan(&[b"ijkl", b"ijkl", b"mnop"]),
        ["Test.Block.UNOFFICIAL"],
        "{REQUIREMENT}"
    );
    assert_eq!(
        scan(&[b"ijkl", b"ijkl", b"ijkl"]),
        Vec::<String>::new(),
        "{REQUIREMENT}: two distinct subsignatures are asked for"
    );
    let input = directory.join("input");
    write_file(&input, &file_with(&[b"ABCDEF", b"GHIJ"])).unwrap();
    assert_eq!(
        comparison_report(&compiled.image, &input, &directory).unwrap()["verdict"],
        "strong_indicator",
        "{REQUIREMENT}"
    );
}

#[test]
fn a_logical_expression_is_read_without_operator_precedence() {
    const REQUIREMENT: &str = "A Logical Expression Is Read Without Operator Precedence";
    let (directory, compiled) = loose_databases(
        "logical-precedence",
        &[(
            "local.ldb",
            "Test.First;Target:0;0|1&2;71727374;75767778;797a3031\n\
             Test.Last;Target:0;(0&1|2);41424344;45464748;494a4b4c\n",
        )],
    );
    let scan = |pieces: &[&[u8]]| detected(&directory, &compiled.image, pieces);

    assert_eq!(scan(&[b"qrst"]), ["Test.First.UNOFFICIAL"], "{REQUIREMENT}");
    assert_eq!(scan(&[b"uvwx"]), Vec::<String>::new(), "{REQUIREMENT}");
    assert_eq!(scan(&[b"IJKL"]), ["Test.Last.UNOFFICIAL"], "{REQUIREMENT}");
    assert_eq!(scan(&[b"ABCD"]), Vec::<String>::new(), "{REQUIREMENT}");
}

#[test]
fn a_subsignatures_modifiers_match_as_the_signature_format_defines_them() {
    const REQUIREMENT: &str =
        "A Subsignature's Modifiers Match As The Signature Format Defines Them";
    let (directory, compiled) = loose_databases(
        "logical-modifiers",
        &[(
            "local.ldb",
            "Test.Nocase;Target:0;0;4e4f43415345::i\n\
             Test.Wide;Target:0;0;57494445::w\n\
             Test.WideGap;Target:0;0;4741{2}5021::w\n\
             Test.Both;Target:0;0;424f5448::wa\n\
             Test.Word;Target:0;0;574f5244::f\n",
        )],
    );
    let scan = |pieces: &[&[u8]]| detected(&directory, &compiled.image, pieces);

    assert_eq!(
        scan(&[b"nOcAsE"]),
        ["Test.Nocase.UNOFFICIAL"],
        "{REQUIREMENT}"
    );
    assert_eq!(
        scan(&[&wide(b"WIDE")]),
        ["Test.Wide.UNOFFICIAL"],
        "{REQUIREMENT}"
    );
    assert_eq!(scan(&[b"WIDE"]), Vec::<String>::new(), "{REQUIREMENT}");
    assert_eq!(
        scan(&[b"G\0A\0zzP\0!\0"]),
        ["Test.WideGap.UNOFFICIAL"],
        "{REQUIREMENT}"
    );
    assert_eq!(
        scan(&[b"G\0A\0z\0z\0P\0!\0"]),
        Vec::<String>::new(),
        "{REQUIREMENT}"
    );
    assert_eq!(scan(&[b"BOTH"]), ["Test.Both.UNOFFICIAL"], "{REQUIREMENT}");
    assert_eq!(
        scan(&[&wide(b"BOTH")]),
        ["Test.Both.UNOFFICIAL"],
        "{REQUIREMENT}"
    );
    assert_eq!(
        scan(&[b" WORD "]),
        ["Test.Word.UNOFFICIAL"],
        "{REQUIREMENT}"
    );
    assert_eq!(scan(&[b"SWORDS"]), Vec::<String>::new(), "{REQUIREMENT}");
}

#[test]
fn a_potentially_unwanted_signature_is_reported_only_when_potentially_unwanted_detection_is_on() {
    const REQUIREMENT: &str = "A Potentially Unwanted Signature Is Reported Only When Potentially Unwanted Detection Is On";
    let (directory, compiled) = loose_databases(
        "logical-unwanted",
        &[("local.ldu", "PUA.Win.Packer.Thing-1;Target:0;0;50554131\n")],
    );
    let input = directory.join("input");
    write_file(&input, &file_with(&[b"PUA1"])).unwrap();
    let report = |options: &[&str]| {
        comparison_report_with(&compiled.image, options, &input, &directory).unwrap()
    };

    let off = report(&[]);
    assert_eq!(detections(&off), Vec::<String>::new(), "{REQUIREMENT}");
    assert_eq!(off["verdict"], "nothing_found", "{REQUIREMENT}");
    let on = report(&["--potentially-unwanted"]);
    assert_eq!(
        detections(&on),
        ["PUA.Win.Packer.Thing-1.UNOFFICIAL"],
        "{REQUIREMENT}"
    );
    assert_eq!(on["verdict"], "potentially_unwanted", "{REQUIREMENT}");
    assert_eq!(
        detections(&report(&[
            "--potentially-unwanted",
            "--unwanted-category-containing",
            ".Packer."
        ])),
        ["PUA.Win.Packer.Thing-1.UNOFFICIAL"],
        "{REQUIREMENT}"
    );
    assert_eq!(
        detections(&report(&[
            "--potentially-unwanted",
            "--unwanted-category-containing",
            ".Tool."
        ])),
        Vec::<String>::new(),
        "{REQUIREMENT}"
    );
}

fn scanned(directory: &Path, image: &Path, options: &[&str], contents: &[u8]) -> Vec<String> {
    let input = directory.join("input");
    write_file(&input, contents).unwrap();
    let every_match: Vec<&str> = std::iter::once("--every-match")
        .chain(options.iter().copied())
        .collect();
    detections(&comparison_report_with(image, &every_match, &input, directory).unwrap())
}

const REGULAR_EXPRESSIONS: &str = "\
Test.Trigger;Target:0;1;4d41524b;0/x[0-9]+y/
Test.Anchored;Target:0;1;4d41524b;16:0/abc/
Test.Shifted;Target:0;1;4d41524b;16,2:0/def/
Test.Encompassed;Target:0;1;4d41524b;16,4:0/gh.*k/e
Test.Global;Target:0;1=3;4d41524b;0/qq/g
Test.Single;Target:0;1>1;4d41524b;0/qq/
Test.Dollar;Target:0;1;4d41524b;0/zz$/
Test.Space;Target:0;1;4d41524b;0/v\\sv/
Test.Dot;Target:0;1;4d41524b;0/n.n/
Test.Fold;Target:0;1;4d41524b;0/case\\xe9/i
";

#[test]
fn a_logical_signature_with_a_regular_expression_is_detected_when_its_trigger_holds_and_the_expression_matches()
 {
    const REQUIREMENT: &str = "A Logical Signature With A Regular Expression Is Detected When Its Trigger Holds And The Expression Matches";
    let (directory, compiled) =
        loose_databases("regular-expressions", &[("local.ldb", REGULAR_EXPRESSIONS)]);
    let scan = |contents: &[u8]| scanned(&directory, &compiled.image, &[], contents);
    let found =
        |contents: &[u8], name: &str| scan(contents).contains(&format!("{name}.UNOFFICIAL"));

    assert!(found(b"MARK....x123y", "Test.Trigger"), "{REQUIREMENT}");
    assert!(!found(b"........x123y", "Test.Trigger"), "{REQUIREMENT}");
    assert!(
        found(b"MARK............abc", "Test.Anchored"),
        "{REQUIREMENT}"
    );
    assert!(
        !found(b"MARK.............abc", "Test.Anchored"),
        "{REQUIREMENT}"
    );
    assert!(
        found(b"MARK..............def", "Test.Shifted"),
        "{REQUIREMENT}"
    );
    assert!(
        !found(b"MARK...............def", "Test.Shifted"),
        "{REQUIREMENT}"
    );
    assert!(
        found(b"MARK............ghxk....", "Test.Encompassed"),
        "{REQUIREMENT}"
    );
    assert!(
        !found(b"MARK............ghxxxk..", "Test.Encompassed"),
        "{REQUIREMENT}"
    );
    assert!(found(b"MARK qq qq qq", "Test.Global"), "{REQUIREMENT}");
    assert!(!found(b"MARK qq qq qq", "Test.Single"), "{REQUIREMENT}");
    assert!(found(b"MARK.....zz\n", "Test.Dollar"), "{REQUIREMENT}");
    assert!(!found(b"MARK.....zz\n\n", "Test.Dollar"), "{REQUIREMENT}");
    assert!(found(b"MARK v\x0bv", "Test.Space"), "{REQUIREMENT}");
    assert!(found(b"MARK n\rn", "Test.Dot"), "{REQUIREMENT}");
    assert!(!found(b"MARK n\nn", "Test.Dot"), "{REQUIREMENT}");
    assert!(found(b"MARK CASE\xe9", "Test.Fold"), "{REQUIREMENT}");
    assert!(!found(b"MARK case\xc9", "Test.Fold"), "{REQUIREMENT}");
}

#[test]
fn regular_expressions_are_not_matched_in_a_file_larger_than_the_regular_expression_limit() {
    const REQUIREMENT: &str =
        "Regular Expressions Are Not Matched In A File Larger Than The Regular-Expression Limit";
    let (directory, compiled) = loose_databases(
        "regular-expression-limit",
        &[(
            "local.ldb",
            "Test.Limited;Target:0;1;4d41524b;0/abc/\nTest.Content;Target:0;0;4d41524b\n",
        )],
    );
    let contents = b"MARK.......abc";
    let size = contents.len().to_string();
    let smaller = (contents.len() - 1).to_string();
    let scan = |options: &[&str]| scanned(&directory, &compiled.image, options, contents);
    let both = ["Test.Limited.UNOFFICIAL", "Test.Content.UNOFFICIAL"];
    assert_eq!(scan(&[]), both, "{REQUIREMENT}");
    assert_eq!(
        scan(&["--largest-regular-expression-object", &size]),
        both,
        "{REQUIREMENT}"
    );
    assert_eq!(
        scan(&["--largest-regular-expression-object", &smaller]),
        ["Test.Content.UNOFFICIAL"],
        "{REQUIREMENT}"
    );
    assert_eq!(
        scan(&["--largest-regular-expression-object", "0"]),
        both,
        "{REQUIREMENT}"
    );
}

const BYTE_COMPARISONS: &str = "\
Test.Binary;Target:0;1;4d41524b;0(>>4#ib2#>512)
Test.Little;Target:0;1;4d41524b;0(>>4#il2#=258)
Test.Hex;Target:0;1;4d41524b;0(>>4#hb2#=0x1F)
Test.Decimal;Target:0;1;4d41524b;0(>>4#d3#>99,<200)
Test.Back;Target:0;1;4d41524b;0(<<1#ib1#=65)
";

#[test]
fn a_byte_comparison_holds_when_the_bytes_after_its_subsignatures_last_match_compare_as_it_states()
{
    const REQUIREMENT: &str = "A Byte Comparison Holds When The Bytes After Its Subsignature's Last Match Compare As It States";
    let (directory, compiled) =
        loose_databases("byte-comparisons", &[("local.ldb", BYTE_COMPARISONS)]);
    let scan = |contents: &[u8]| scanned(&directory, &compiled.image, &[], contents);
    let found =
        |contents: &[u8], name: &str| scan(contents).contains(&format!("{name}.UNOFFICIAL"));

    assert!(found(b"..MARK\x02\x01..", "Test.Binary"), "{REQUIREMENT}");
    assert!(!found(b"..MARK\x02\x00..", "Test.Binary"), "{REQUIREMENT}");
    assert!(
        !found(b"..MARK\x02\x01MARK\x00\x00", "Test.Binary"),
        "{REQUIREMENT}"
    );
    assert!(found(b"..MARK\x02\x01..", "Test.Little"), "{REQUIREMENT}");
    assert!(found(b"..MARK1F..", "Test.Hex"), "{REQUIREMENT}");
    assert!(found(b"..MARK150..", "Test.Decimal"), "{REQUIREMENT}");
    assert!(!found(b"..MARK250..", "Test.Decimal"), "{REQUIREMENT}");
    assert!(found(b".AMARK.....", "Test.Back"), "{REQUIREMENT}");
    assert!(!found(b"AMARK.....", "Test.Back"), "{REQUIREMENT}");
    assert!(!found(b"......MARK\x02", "Test.Binary"), "{REQUIREMENT}");
}

const BACKTRACKING_EXPRESSIONS: &str = "\
Test.Numbered;Target:0;0&1;4d41524b;0/var (\\w+)=\\1;/
Test.Named;Target:0;0&1;4d41524b;0/(?P<f>\\w+)\\(\\).{0,20}?(?P=f)\\(\\)/
Test.Ahead;Target:0;0&1;4d41524b;0/load(?!ed)/
Test.Behind;Target:0;0&1;4d41524b;0/(?<!\\w)inject\\w+\\.java/
Test.Atomic;Target:0;0&1;4d41524b;0/\\[(?>a+)ab\\]/
Test.Exhausting;Target:0;0&1;4d41524b;0/(a+)+\\1b/
";

#[test]
fn a_logical_signature_whose_regular_expression_holds_a_backreference_or_lookaround_is_detected_when_it_matches()
 {
    const REQUIREMENT: &str = "A Logical Signature Whose Regular Expression Holds A Backreference Or Lookaround Is Detected When It Matches";
    let (directory, compiled) =
        loose_databases("backtracking", &[("local.ldb", BACKTRACKING_EXPRESSIONS)]);
    let scan = |contents: &[u8]| scanned(&directory, &compiled.image, &[], contents);
    let found =
        |contents: &[u8], name: &str| scan(contents).contains(&format!("{name}.UNOFFICIAL"));

    assert!(
        found(b"MARK var abc=abc;", "Test.Numbered"),
        "{REQUIREMENT}"
    );
    assert!(
        !found(b"MARK var abc=abd;", "Test.Numbered"),
        "{REQUIREMENT}"
    );
    assert!(
        found(b"MARK run() then run()", "Test.Named"),
        "{REQUIREMENT}"
    );
    assert!(
        !found(b"MARK run() then walk()", "Test.Named"),
        "{REQUIREMENT}"
    );
    assert!(found(b"MARK loader", "Test.Ahead"), "{REQUIREMENT}");
    assert!(!found(b"MARK loaded", "Test.Ahead"), "{REQUIREMENT}");
    assert!(
        found(b"MARK injectAll.java", "Test.Behind"),
        "{REQUIREMENT}"
    );
    assert!(
        !found(b"MARK reinjectAll.java", "Test.Behind"),
        "{REQUIREMENT}"
    );
    assert!(!found(b"MARK [aaab]", "Test.Atomic"), "{REQUIREMENT}");
    let mut exhausting = b"MARK ".to_vec();
    exhausting.extend([b'a'; 25]);
    exhausting.extend_from_slice(b"c ab");
    assert!(found(b"MARK aaab", "Test.Exhausting"), "{REQUIREMENT}");
    assert!(!found(&exhausting, "Test.Exhausting"), "{REQUIREMENT}");
}
