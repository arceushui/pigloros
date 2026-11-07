#![cfg(windows)]
#![forbid(unsafe_code)]

use std::ffi::{OsStr, OsString};
use std::os::windows::ffi::OsStrExt;
use std::path::PathBuf;

use pos_owner_bridge::{BridgeError, UnavailableCode};
use windows::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_SUCCESS, WIN32_ERROR};

const POLICIES: [&str; 5] = [
    "BrowserExecutableFolder",
    "UserDataFolder",
    "AdditionalBrowserArguments",
    "ReleaseChannels",
    "ChannelSearchKind",
];

type PolicyQuery<'a> = dyn FnMut(bool, bool, &[u16], &[u16]) -> WIN32_ERROR + 'a;

/// Refuse environment or policy-registry overrides before creating `WebView2`.
///
/// Both registry views and both OS-user/machine policy hives are checked for
/// this executable and the wildcard. Values are refused regardless of type or
/// content. Failed inspection also refuses activation.
///
/// # Errors
///
/// Returns `Unavailable(OverridePresent)` when an override exists, or
/// `Unavailable(InterfaceUnavailable)` when inspection cannot establish absence.
pub fn refuse_overrides() -> Result<(), BridgeError> {
    inspect_overrides(
        &mut std::env::vars_os().map(|(name, _)| name),
        std::env::current_exe(),
        &mut crate::Native::query_policy,
    )
}

fn inspect_overrides(
    environment: &mut dyn Iterator<Item = OsString>,
    executable: std::io::Result<PathBuf>,
    query: &mut PolicyQuery<'_>,
) -> Result<(), BridgeError> {
    for name in environment {
        if is_override(&name) {
            return Err(BridgeError::Unavailable(UnavailableCode::OverridePresent));
        }
    }
    let executable = executable
        .map_err(|_| unavailable())?
        .file_name()
        .map(wide)
        .ok_or_else(unavailable)?;
    for policy in POLICIES {
        let subkey = wide(OsStr::new(&format!(
            "Software\\Policies\\Microsoft\\Edge\\WebView2\\{policy}"
        )));
        for machine in [false, true] {
            for view64 in [false, true] {
                for name in [&executable, &wide(OsStr::new("*"))] {
                    classify(query(machine, view64, &subkey, name))?;
                }
            }
        }
    }
    Ok(())
}

fn wide(value: &OsStr) -> Vec<u16> {
    value.encode_wide().chain([0]).collect()
}

fn is_override(name: &OsStr) -> bool {
    name.encode_wide()
        .take(9)
        .map(|unit| {
            if (97..=122).contains(&unit) {
                unit - 32
            } else {
                unit
            }
        })
        .eq("WEBVIEW2_".encode_utf16())
}

const fn unavailable() -> BridgeError {
    BridgeError::Unavailable(UnavailableCode::InterfaceUnavailable)
}

const fn classify(status: WIN32_ERROR) -> Result<(), BridgeError> {
    match status {
        ERROR_FILE_NOT_FOUND => Ok(()),
        ERROR_SUCCESS => Err(BridgeError::Unavailable(UnavailableCode::OverridePresent)),
        _ => Err(unavailable()),
    }
}

#[cfg(test)]
mod tests {
    use std::os::windows::ffi::OsStringExt;

    use super::*;

    #[test]
    fn environment_names_are_case_insensitive_and_do_not_need_unicode() {
        for name in [
            "WEBVIEW2_",
            "webview2_BROWSER_EXECUTABLE_FOLDER",
            "WeBvIeW2_x",
        ] {
            assert!(is_override(OsStr::new(name)));
        }
        let malformed =
            std::ffi::OsString::from_wide(&[87, 69, 66, 86, 73, 69, 87, 50, 95, 0xD800]);
        assert!(is_override(&malformed));
        for name in ["", "WEBVIEW2", "WEBVIEW3_", "XWEBVIEW2_", "WEBVIEW2x"] {
            assert!(!is_override(OsStr::new(name)));
        }
    }

    #[test]
    fn incomplete_executable_observation_refuses_registry_admission() {
        let mut absent = |_, _, _: &[u16], _: &[u16]| ERROR_FILE_NOT_FOUND;
        assert_eq!(
            inspect_overrides(
                &mut std::iter::empty(),
                Err(std::io::ErrorKind::PermissionDenied.into()),
                &mut absent
            ),
            Err(unavailable())
        );
        assert_eq!(
            inspect_overrides(
                &mut std::iter::empty(),
                Ok(PathBuf::from(r"C:\")),
                &mut absent
            ),
            Err(unavailable())
        );
    }

    #[test]
    fn only_proven_registry_absence_allows_activation() {
        assert_eq!(classify(ERROR_FILE_NOT_FOUND), Ok(()));
        assert_eq!(
            classify(ERROR_SUCCESS),
            Err(BridgeError::Unavailable(UnavailableCode::OverridePresent))
        );
        for status in [
            WIN32_ERROR(5),
            WIN32_ERROR(234),
            WIN32_ERROR(3),
            WIN32_ERROR(u32::MAX),
        ] {
            assert_eq!(classify(status), Err(unavailable()));
        }
    }
}
