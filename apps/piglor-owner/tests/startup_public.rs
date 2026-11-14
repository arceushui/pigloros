//! The minimal executable applies the owner platform gate before any ceremony.

#[cfg(not(windows))]
use pos_owner_bridge::{BridgeError, UnavailableCode};
use std::process::Command;

#[cfg(windows)]
#[test]
fn startup_admits_the_windows_nonce_ledger_profile() {
    assert_eq!(piglor_owner::run(), Ok(()));
}

#[cfg(windows)]
#[test]
fn executable_passes_the_gate_without_starting_a_ceremony() -> Result<(), Box<dyn std::error::Error>>
{
    let output = Command::new(env!("CARGO_BIN_EXE_piglor-owner")).output()?;
    assert_eq!(output.status.code(), Some(0));
    assert!(output.stdout.is_empty());
    assert!(output.stderr.is_empty());
    Ok(())
}

#[cfg(not(windows))]
#[test]
fn startup_refuses_targets_without_the_native_owner_surface() {
    assert_eq!(
        piglor_owner::run(),
        Err(BridgeError::Unavailable(
            UnavailableCode::PlatformUnsupported
        ))
    );
}

#[cfg(not(windows))]
#[test]
fn executable_reports_the_closed_failure_without_starting_a_ceremony(
) -> Result<(), Box<dyn std::error::Error>> {
    let output = Command::new(env!("CARGO_BIN_EXE_piglor-owner")).output()?;
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert_eq!(
        String::from_utf8(output.stderr)?.trim(),
        "Error: Unavailable(PlatformUnsupported)"
    );
    Ok(())
}
