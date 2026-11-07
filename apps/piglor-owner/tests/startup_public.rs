//! The minimal executable refuses unavailable owner profiles before a ceremony.

use pos_owner_bridge::{BridgeError, UnavailableCode};
use std::process::Command;

#[test]
fn startup_preserves_the_existing_owner_platform_gate() {
    assert_eq!(
        piglor_owner::run(),
        Err(BridgeError::Unavailable(
            UnavailableCode::PlatformUnsupported
        ))
    );
}

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
