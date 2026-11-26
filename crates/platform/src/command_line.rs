use std::ffi::OsString;

#[must_use]
pub fn arguments() -> Vec<OsString> {
    std::env::args_os().skip(1).collect()
}
