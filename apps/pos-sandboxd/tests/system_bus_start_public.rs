use std::{error::Error, process::Command};

use pos_sandboxd::{
    SystemdTransientUnitTransport, SystemdTransientUnitTransportError, TransientServiceUnitName,
    TransientServiceUnitNameError,
};

const CONNECT_FAILURE_CHILD: &str = "PIGLOROS_CONNECT_FAILURE_CHILD";

#[test]
fn zero_attempt_identity_cannot_name_a_transient_unit() {
    assert_eq!(
        TransientServiceUnitName::from_attempt_id([0; 16]),
        Err(TransientServiceUnitNameError::ZeroAttemptId)
    );
}

#[tokio::test]
async fn system_bus_connection_failure_is_classified() -> Result<(), Box<dyn Error>> {
    if std::env::var_os(CONNECT_FAILURE_CHILD).is_some() {
        let result = SystemdTransientUnitTransport::connect_system().await;
        let error = result.err().ok_or("unusable system bus was accepted")?;
        assert!(error.to_string().contains("failed to connect"));
        let SystemdTransientUnitTransportError::Connect(_) = error else {
            return Err("connection failure had the wrong error class".into());
        };
        return Ok(());
    }

    // An unusable Unix socket, then transports that would start a local
    // process: none may connect, and no command may run.
    for address in [
        "unix:path=/dev/null",
        "unixexec:path=/bin/true",
        "tcp:host=127.0.0.1,port=1",
    ] {
        let status = Command::new(std::env::current_exe()?)
            .args(["--exact", "system_bus_connection_failure_is_classified"])
            .env(CONNECT_FAILURE_CHILD, "1")
            .env("DBUS_SYSTEM_BUS_ADDRESS", address)
            .status()?;
        if !status.success() {
            return Err(format!("connection-failure child test failed for {address}").into());
        }
    }
    Ok(())
}
