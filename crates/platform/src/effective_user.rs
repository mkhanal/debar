#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct EffectiveUser(u32);

const ADMINISTRATOR: u32 = 0;

impl EffectiveUser {
    pub(crate) fn of_this_process() -> Self {
        // SAFETY: geteuid takes no arguments, touches no memory and cannot fail.
        Self(unsafe { libc::geteuid() })
    }

    pub(crate) fn trusts_files_owned_by(self, owner: u32) -> bool {
        owner == self.0 || owner == ADMINISTRATOR
    }
}
