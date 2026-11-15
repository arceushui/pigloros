#![cfg(windows)]

#[cfg(target_arch = "x86_64")]
use windows::core::w;
use windows::core::PCWSTR;
use windows::Win32::Foundation::WIN32_ERROR;
#[cfg(target_arch = "x86_64")]
use windows::Win32::System::Registry::RRF_RT_REG_SZ;
use windows::Win32::System::Registry::{
    RegGetValueW, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, RRF_NOEXPAND, RRF_RT_ANY,
    RRF_SUBKEY_WOW6432KEY, RRF_SUBKEY_WOW6464KEY,
};

pub(super) fn query_policy(
    machine: bool,
    view64: bool,
    subkey: &[u16],
    name: &[u16],
) -> WIN32_ERROR {
    let root = if machine {
        HKEY_LOCAL_MACHINE
    } else {
        HKEY_CURRENT_USER
    };
    let view = if view64 {
        RRF_SUBKEY_WOW6464KEY
    } else {
        RRF_SUBKEY_WOW6432KEY
    };
    // SAFETY: both strings are owned, NUL-terminated UTF-16 supplied by the
    // private adapter. The predefined hive is borrowed; no output buffer or
    // handle is acquired, and the synchronous call retains no pointer.
    unsafe {
        RegGetValueW(
            root,
            PCWSTR(subkey.as_ptr()),
            PCWSTR(name.as_ptr()),
            RRF_RT_ANY | RRF_NOEXPAND | view,
            None,
            None,
            None,
        )
    }
}

#[cfg(target_arch = "x86_64")]
fn local_machine_text(subkey: PCWSTR, name: PCWSTR) -> Result<String, ()> {
    let mut buffer = [0_u16; 256];
    let mut bytes = 512_u32;
    // SAFETY: both PCWSTR inputs are static UTF-16 literals below. Fixed HKLM
    // 64-bit read, owned initialized 512-byte output and independent byte bound;
    // no pointer is retained and only REG_SZ is admitted without expansion.
    unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            subkey,
            name,
            RRF_RT_REG_SZ | RRF_NOEXPAND | RRF_SUBKEY_WOW6464KEY,
            None,
            Some(buffer.as_mut_ptr().cast()),
            Some(&raw mut bytes),
        )
    }
    .ok()
    .map_err(|_| ())?;
    decode_registry_text(&buffer, bytes)
}

#[cfg(target_arch = "x86_64")]
fn decode_registry_text(buffer: &[u16], bytes: u32) -> Result<String, ()> {
    if !bytes.is_multiple_of(2) {
        return Err(());
    }
    let units = buffer.get(..(bytes / 2) as usize).ok_or(())?;
    let text = units.strip_suffix(&[0]).ok_or(())?;
    if text.contains(&0) {
        return Err(());
    }
    String::from_utf16(text).map_err(|_| ())
}

#[cfg(all(test, target_arch = "x86_64"))]
mod tests {
    #![forbid(unsafe_code)]

    use super::decode_registry_text;

    #[test]
    fn modeled_registry_text_requires_bounded_single_terminated_utf16() {
        assert_eq!(
            decode_registry_text(&[49, 50, 51, 0], 8),
            Ok("123".to_owned())
        );
        for (buffer, bytes) in [
            (&[0_u16][..], 0),
            (&[49, 0][..], 3),
            (&[49, 0][..], 6),
            (&[49, 50][..], 4),
            (&[49, 0, 50, 0][..], 8),
            (&[0xd800, 0][..], 4),
        ] {
            assert_eq!(decode_registry_text(buffer, bytes), Err(()));
        }
    }
}

impl crate::Native {
    #[cfg(target_arch = "x86_64")]
    pub(crate) fn os_profile() -> Result<(String, String), ()> {
        let build = local_machine_text(
            w!("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"),
            w!("CurrentBuildNumber"),
        )?;
        let product = local_machine_text(
            w!("SYSTEM\\CurrentControlSet\\Control\\ProductOptions"),
            w!("ProductType"),
        )?;
        Ok((build, product))
    }
}
