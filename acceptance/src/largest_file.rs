use std::path::{Path, PathBuf};

use crate::{CompiledImage, Outcome, compile, write_file};

pub const LARGEST_FILE: usize = 100 * 1024 * 1024;
const READ_WINDOW: usize = 128 * 1024;

pub const EXPRESSIONS_TO_THE_END: &str = r"Test.Tail;Target:0;0&1;4d41524b;0/TAIL[0-9]{4}END/
Test.Span;Target:0;0&1;4d41524b;0/SPAN[0-9]{8}SPAN/
Test.End;Target:0;0&1;4d41524b;EOF-12:0/LAST[0-9]{4}BYTE/
Test.Backreference;Target:0;0&1;4d41524b;0/var (\w+)=\1;/
Test.Large;Target:0;0&1;4d41524b;0/TEXT[ab]*a[ab]{15}Z/
Test.Comparison;Target:0;0&1;4e554d3d;0(>>4#d3#=123)
Test.Absent;Target:0;0&1;4d41524b;0/NOWHERE[0-9]+/
";

pub fn expressions_to_the_end(directory: &Path) -> Outcome<CompiledImage> {
    let databases = directory.join("databases");
    std::fs::create_dir_all(&databases)?;
    write_file(
        &databases.join("local.ldb"),
        EXPRESSIONS_TO_THE_END.as_bytes(),
    )?;
    compile(&databases, directory, "expressions-to-the-end")
}

pub fn matched_only_to_the_end(directory: &Path, length: usize) -> Outcome<PathBuf> {
    let mut contents = vec![b'.'; length];
    let mut put = |offset: usize, piece: &[u8]| {
        if let Some(target) = contents.get_mut(offset..offset.saturating_add(piece.len())) {
            target.copy_from_slice(piece);
        }
    };
    put(0, b"MARK");
    put(LARGEST_FILE - READ_WINDOW - 6, b"SPAN12345678SPAN");
    put(
        LARGEST_FILE - 4096,
        b" TAIL1234END var abc=abc; TEXTabbbbbbbbbbbbbbbZ NUM=123 ",
    );
    put(length.saturating_sub(12), b"LAST1234BYTE");
    let input = directory.join(format!("matched-only-to-the-end-{length}"));
    write_file(&input, &contents)?;
    Ok(input)
}
