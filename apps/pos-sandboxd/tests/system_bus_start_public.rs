use std::{error::Error, process::Command};

use pos_sandboxd::{
    SystemdTransientUnitTransport, SystemdTransientUnitTransportError, TransientServiceUnitName,
    TransientServiceUnitNameError,
};

const CONNECT_FAILURE_CHILD: &str = "PIGLOROS_CONNECT_FAILURE_CHILD";
const CONNECT_FAILURE_GUARDED: &str = "PIGLOROS_CONNECT_FAILURE_GUARDED";
const NOT_A_UNIX_SOCKET: &str = "the system bus address must be a Unix socket";

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
        let SystemdTransientUnitTransportError::Connect(cause) = error else {
            return Err("connection failure had the wrong error class".into());
        };
        // Only the transport guard produces this cause: without it zbus would
        // spawn the unixexec command or dial TCP and fail differently.
        let guarded = std::env::var_os(CONNECT_FAILURE_GUARDED).is_some();
        assert_eq!(
            cause.to_string().contains(NOT_A_UNIX_SOCKET),
            guarded,
            "{cause}"
        );
        return Ok(());
    }

    // An unusable Unix socket fails to connect; transports that would start a
    // local process or leave the host are refused before any connection.
    for (address, guarded) in [
        ("unix:path=/dev/null", false),
        ("unixexec:path=/bin/true", true),
        ("tcp:host=127.0.0.1,port=1", true),
    ] {
        let mut child = Command::new(std::env::current_exe()?);
        child
            .args(["--exact", "system_bus_connection_failure_is_classified"])
            .env(CONNECT_FAILURE_CHILD, "1")
            .env("DBUS_SYSTEM_BUS_ADDRESS", address);
        if guarded {
            child.env(CONNECT_FAILURE_GUARDED, "1");
        }
        let status = child.status()?;
        if !status.success() {
            return Err(format!("connection-failure child test failed for {address}").into());
        }
    }
    Ok(())
}
