#![cfg(windows)]
#![cfg(test)]
#![forbid(unsafe_code)]

use std::process::{Child, Command};

use super::{pump::Pump, window::Window};
use crate::{NativePulse, NativeResult};

/// Owns the parent window and its STA until the exact child has exited.
struct OwnedParent {
    window: Window,
    pump: Pump,
}

impl OwnedParent {
    fn new() -> NativeResult<Self> {
        let pump = Pump::new()?;
        let window = Window::create(None, 320, 240)?;
        window.show();
        Ok(Self { window, pump })
    }

    fn spawn_child(&self) -> Result<Child, Box<dyn std::error::Error>> {
        self.pump.token.check()?;
        let owner = require_parent_owner(u64::try_from(self.window.handle().0 as usize)?)?;
        Ok(Command::new(std::env::current_exe()?)
            .args(["--exact", "tests::native_host_fixture_child", "--nocapture"])
            .env("PIGLOR_HOST_LIFECYCLE_CHILD", "1")
            .env("PIGLOR_HOST_FIXTURE_PARENT", owner.to_string())
            .spawn()?)
    }

    fn pump(&self) -> NativeResult<NativePulse> {
        self.pump.next()
    }

    fn foreground(&self) -> NativeResult<bool> {
        self.pump.token.check()?;
        Ok(self.window.foreground())
    }

    fn finish(mut self) -> NativeResult<()> {
        self.pump.token.check()?;
        self.window.destroy()?;
        self.pump.stop_timer()
    }
}

fn child_owner() -> Result<u64, Box<dyn std::error::Error>> {
    parse_parent_owner(&std::env::var("PIGLOR_HOST_FIXTURE_PARENT")?)
}

fn parse_parent_owner(value: &str) -> Result<u64, Box<dyn std::error::Error>> {
    require_parent_owner(value.parse::<u64>()?)
}

fn require_parent_owner(owner: u64) -> Result<u64, Box<dyn std::error::Error>> {
    if owner == 0 {
        return Err("parent fixture window is unavailable".into());
    }
    Ok(owner)
}

impl crate::Native {
    pub(crate) fn native_host_fixture_child() -> Result<(), Box<dyn std::error::Error>> {
        if std::env::var_os("PIGLOR_HOST_LIFECYCLE_CHILD").is_some() {
            let owner = child_owner()?;
            Self::native_host_lifecycle(owner)?;
        }
        Ok(())
    }

    pub(crate) fn native_host_parent_fixture() -> Result<(), Box<dyn std::error::Error>> {
        use std::io::Write as _;
        let _port = Self::fixed_port_fixture();
        let parent = OwnedParent::new()?;
        writeln!(
            std::io::stderr(),
            "NATIVE_PARENT stage=before-child foreground={}",
            parent.foreground()?
        )?;
        let mut child = parent.spawn_child()?;
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
        let mut observation_failed = false;
        loop {
            let status = child.try_wait().unwrap_or_else(|_| {
                observation_failed = true;
                None
            });
            if let Some(status) = status {
                // Retain the child through its ordinary native retirement.
                // A late exit still fails this deadline; killing the host
                // would destroy its STA owners while a browser may live.
                let late = std::time::Instant::now() >= deadline;
                writeln!(
                    std::io::stderr(),
                    "NATIVE_PARENT stage=after-child foreground={}",
                    parent.foreground()?
                )?;
                parent.finish()?;
                validate_parent_result(observation_failed, late)?;
                assert!(status.success());
                return Ok(());
            }
            if !matches!(
                parent.pump(),
                Ok(crate::NativePulse::Timer | crate::NativePulse::Dispatched)
            ) {
                observation_failed = true;
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
        }
    }
}

fn validate_parent_result(
    observation_failed: bool,
    late: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    if observation_failed {
        return Err("native host fixture parent observation failed".into());
    }
    if late {
        return Err("native host fixture exceeded its independent wall deadline".into());
    }
    Ok(())
}

#[test]
fn modeled_parent_input_and_retirement_verdict_preserve_refusals() {
    assert_eq!(parse_parent_owner("42").ok(), Some(42));
    for value in ["0", "-1", "bad", "18446744073709551616"] {
        assert!(parse_parent_owner(value).is_err());
    }
    assert!(validate_parent_result(false, false).is_ok());
    assert_eq!(
        validate_parent_result(true, false)
            .err()
            .map(|e| e.to_string())
            .as_deref(),
        Some("native host fixture parent observation failed")
    );
    assert_eq!(
        validate_parent_result(true, true)
            .err()
            .map(|e| e.to_string())
            .as_deref(),
        Some("native host fixture parent observation failed")
    );
    assert_eq!(
        validate_parent_result(false, true)
            .err()
            .map(|e| e.to_string())
            .as_deref(),
        Some("native host fixture exceeded its independent wall deadline")
    );
}
