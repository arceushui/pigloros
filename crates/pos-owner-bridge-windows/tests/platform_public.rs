#![cfg(windows)]
#![forbid(unsafe_code)]

use std::process::Command;

use pos_owner_bridge::{BridgeError, UnavailableCode};
use pos_owner_bridge_windows::{cpu_requirements, require_windows_profile, CpuFeatures};

#[test]
fn windows_profile_matches_independent_os_and_cpu_observations(
) -> Result<(), Box<dyn std::error::Error>> {
    for (aes_ni, pclmulqdq) in [(true, true), (true, false), (false, true), (false, false)] {
        let expected = if aes_ni && pclmulqdq {
            Ok(())
        } else {
            Err(UnavailableCode::CpuFeatures)
        };
        assert_eq!(
            cpu_requirements(CpuFeatures { aes_ni, pclmulqdq }),
            expected
        );
    }
    let observed = CpuFeatures::current();
    let output = Command::new("powershell.exe")
        .env_remove("PSModulePath")
        .args(["-NoProfile", "-NonInteractive", "-Command", r"
            [Environment]::OSVersion.Version.Build.ToString()
            [Microsoft.Win32.Registry]::GetValue('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\ProductOptions', 'ProductType', '')
        "])
        .output()?;
    assert!(output.status.success());
    let output = String::from_utf8(output.stdout)?;
    let mut lines = output.lines();
    let build: u32 = lines.next().ok_or("no build readback")?.trim().parse()?;
    let product = lines.next().ok_or("no product readback")?.trim();
    let expected = if !cfg!(target_arch = "x86_64")
        || build < 26_100
        || !product.eq_ignore_ascii_case("WinNT")
    {
        Err(BridgeError::Unavailable(
            UnavailableCode::PlatformUnsupported,
        ))
    } else {
        cpu_requirements(observed).map_err(BridgeError::Unavailable)
    };
    assert_eq!(require_windows_profile(), expected);
    Ok(())
}
