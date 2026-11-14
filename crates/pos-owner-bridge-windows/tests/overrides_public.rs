#![cfg(windows)]
#![forbid(unsafe_code)]

use std::process::{Command, Output};

use pos_owner_bridge::{BridgeError, UnavailableCode};
use pos_owner_bridge_windows::refuse_overrides;

type TestResult = Result<(), Box<dyn std::error::Error>>;
const CHILD: &str = "PIGLOR_OVERRIDE_FIXTURE_CHILD";

fn child() -> Result<Output, std::io::Error> {
    Command::new(std::env::current_exe()?)
        .args(["--exact", "override_child", "--nocapture"])
        .env(CHILD, "present")
        .output()
}

#[test]
fn override_child() {
    if std::env::var_os(CHILD).is_some() {
        assert_eq!(
            refuse_overrides(),
            Err(BridgeError::Unavailable(UnavailableCode::OverridePresent))
        );
    }
}

struct PolicyValue {
    key: String,
    name: String,
    view: &'static str,
    installed: bool,
}

impl PolicyValue {
    fn command(&self, action: &str) -> Command {
        let mut command = Command::new("reg.exe");
        command.args([action, &self.key, "/v", &self.name, self.view]);
        command
    }

    fn install(&mut self) -> TestResult {
        // Refuse to overwrite runner policy. Only this test's new value is
        // removed by Drop, including when a subsequent assertion fails.
        assert!(!self.command("query").output()?.status.success());
        let added = self
            .command("add")
            .args(["/t", "REG_SZ", "/d", "", "/f"])
            .output()?;
        assert!(added.status.success());
        self.installed = true;
        Ok(())
    }

    fn remove(&mut self) -> TestResult {
        assert!(self.command("delete").arg("/f").output()?.status.success());
        self.installed = false;
        Ok(())
    }
}

impl Drop for PolicyValue {
    fn drop(&mut self) {
        if self.installed {
            let _result = self.command("delete").arg("/f").output();
        }
    }
}

#[test]
fn override_refusal_checks_environment_and_both_registry_views() -> TestResult {
    assert_eq!(refuse_overrides(), Ok(()));
    let output = Command::new(std::env::current_exe()?)
        .args(["--exact", "override_child", "--nocapture"])
        .env(CHILD, "present")
        .env("webview2_UNKNOWN_FUTURE_OPTION", "")
        .output()?;
    assert!(output.status.success());
    let executable = std::env::current_exe()?;
    let name = executable
        .file_name()
        .ok_or("fixture has no executable name")?
        .to_str()
        .ok_or("non-Unicode fixture name")?;
    for policy in [
        "BrowserExecutableFolder",
        "UserDataFolder",
        "AdditionalBrowserArguments",
        "ReleaseChannels",
        "ChannelSearchKind",
    ] {
        for view in ["/reg:32", "/reg:64"] {
            for name in [name, "*"] {
                let mut value = PolicyValue {
                    key: format!("HKCU\\Software\\Policies\\Microsoft\\Edge\\WebView2\\{policy}"),
                    name: name.to_owned(),
                    view,
                    installed: false,
                };
                value.install()?;
                assert!(child()?.status.success());
                value.remove()?;
                assert_eq!(refuse_overrides(), Ok(()));
            }
        }
    }
    Ok(())
}
