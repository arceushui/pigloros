#![cfg(windows)]
#![cfg(test)]
#![forbid(unsafe_code)]

use std::process::{Child, Command};

use super::{pump::Pump, window::Window};
use crate::{NativePulse, NativeResult};

/// Owns the parent window and its STA until the exact child has exited.
pub(crate) struct OwnedParent {
    window: Window,
    pump: Pump,
}

impl OwnedParent {
    pub(crate) fn new() -> NativeResult<Self> {
        let pump = Pump::new()?;
        let window = Window::create(None, 320, 240)?;
        window.show();
        Ok(Self { window, pump })
    }

    pub(crate) fn spawn_child(&self) -> Result<Child, Box<dyn std::error::Error>> {
        self.pump.token.check()?;
        let owner = u64::try_from(self.window.handle().0 as usize)?;
        if owner == 0 {
            return Err("parent fixture window is unavailable".into());
        }
        Ok(Command::new(std::env::current_exe()?)
            .args(["--exact", "tests::native_host_fixture_child", "--nocapture"])
            .env("PIGLOR_HOST_LIFECYCLE_CHILD", "1")
            .env("PIGLOR_HOST_FIXTURE_PARENT", owner.to_string())
            .spawn()?)
    }

    pub(crate) fn pump(&self) -> NativeResult<NativePulse> {
        self.pump.next()
    }

    pub(crate) fn foreground(&self) -> NativeResult<bool> {
        self.pump.token.check()?;
        Ok(self.window.foreground())
    }

    pub(crate) fn finish(mut self) -> NativeResult<()> {
        self.pump.token.check()?;
        self.window.destroy()?;
        self.pump.stop_timer()
    }
}

pub(crate) fn child_owner() -> Result<u64, Box<dyn std::error::Error>> {
    let owner = std::env::var("PIGLOR_HOST_FIXTURE_PARENT")?.parse::<u64>()?;
    if owner == 0 {
        return Err("parent fixture window is unavailable".into());
    }
    Ok(owner)
}
