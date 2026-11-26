pub fn lines(contents: &[u8]) -> impl Iterator<Item = &[u8]> {
    let without_final_newline = contents.strip_suffix(b"\n").unwrap_or(contents);
    let empty = contents.is_empty();
    without_final_newline
        .split(|byte| *byte == b'\n')
        .filter(move |_| !empty)
}

#[must_use]
pub fn without_line_ending(line: &[u8]) -> &[u8] {
    let mut line = line;
    while let Some(shorter) = line
        .strip_suffix(b"\n")
        .or_else(|| line.strip_suffix(b"\r"))
    {
        line = shorter;
    }
    line
}
