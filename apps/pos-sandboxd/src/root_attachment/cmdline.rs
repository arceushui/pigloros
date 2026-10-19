//! Owner decision Q7.8 (B3): the kernel command line must disable systemd's
//! userspace Verity fallback before the provider calls mountfsd.
//!
//! systemd v260.2 activates a signed root by root hash alone after a kernel
//! signature rejection when userspace PKCS#7 validation is allowed; the kernel
//! command line `systemd.allow_userspace_verity=` is one independent veto, and
//! it defaults to allowed when missing. The rule here is deliberately closed:
//! the command line must contain the setting exactly once, as the one plain
//! token below. Any other spelling, quoting, value, `rd.` variant or repeat
//! rejects, because systemd's own parser may read it differently.

/// The only accepted spelling of the veto.
const VETO: &[u8] = b"systemd.allow_userspace_verity=0";
/// The setting's key, without its `systemd.` or `rd.systemd.` prefix.
const KEY: &[u8] = b"allow_userspace_verity";

/// Whether `cmdline` vetoes systemd's userspace Verity fallback.
pub(super) fn vetoes_userspace_verity(cmdline: &[u8]) -> bool {
    let mentions = cmdline
        .windows(KEY.len())
        .filter(|window| *window == KEY)
        .count();
    mentions == 1
        && cmdline
            .split(u8::is_ascii_whitespace)
            .any(|token| token == VETO)
}
