#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Normal,
    InString,
    UnderscoreAfterSpace,
    UnderscoreThenReturn,
    AfterSpace,
}

pub fn normalised(source: &[u8]) -> Vec<u8> {
    let mut output = Vec::with_capacity(source.len());
    let mut state = State::Normal;
    for byte in source {
        state = match *byte {
            b'"' => {
                output.push(b'"');
                match state {
                    State::InString => State::Normal,
                    State::Normal | State::UnderscoreAfterSpace | State::AfterSpace => {
                        State::InString
                    }
                    State::UnderscoreThenReturn => state,
                }
            }
            b'_' => {
                output.push(b'_');
                match state {
                    State::AfterSpace => State::UnderscoreAfterSpace,
                    State::Normal
                    | State::InString
                    | State::UnderscoreAfterSpace
                    | State::UnderscoreThenReturn => state,
                }
            }
            b'\r' => {
                output.push(b'\r');
                match state {
                    State::UnderscoreAfterSpace => State::UnderscoreThenReturn,
                    State::Normal
                    | State::InString
                    | State::UnderscoreThenReturn
                    | State::AfterSpace => state,
                }
            }
            b'\n' => match state {
                State::UnderscoreAfterSpace => {
                    output.pop();
                    State::AfterSpace
                }
                State::UnderscoreThenReturn => {
                    output.pop();
                    output.pop();
                    State::AfterSpace
                }
                State::Normal | State::InString | State::AfterSpace => {
                    output.push(b'\n');
                    state
                }
            },
            b' ' | b'\t' => {
                if state != State::AfterSpace {
                    output.push(b' ');
                }
                match state {
                    State::Normal | State::UnderscoreAfterSpace => State::AfterSpace,
                    State::InString | State::UnderscoreThenReturn | State::AfterSpace => state,
                }
            }
            other => match state {
                State::Normal | State::UnderscoreAfterSpace | State::AfterSpace => {
                    output.push(other.to_ascii_lowercase());
                    State::Normal
                }
                State::InString | State::UnderscoreThenReturn => {
                    output.push(other);
                    state
                }
            },
        };
    }
    output
}
