//! Final root-owned sandbox selector process from ADR-069.
//!
//! The selector owns the provider runtime's lifecycle (ADR-069 R11 §5.0):
//! this entrypoint composes the one production lifecycle port, the systemd
//! adapter of `pos-sandboxd`, and is the only production caller of
//! `RootSelectorRuntime::activate`.

#[cfg(target_os = "linux")]
use pos_reference::root_selector::RootSelectorRuntime;
#[cfg(target_os = "linux")]
use pos_sandboxd::SystemdProviderLifecycle;

#[cfg(target_os = "linux")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    SystemdProviderLifecycle::connect()
        .map_err(Into::into)
        .and_then(|port| {
            RootSelectorRuntime::activate(&port)
                .and_then(RootSelectorRuntime::serve)
                .map_err(Into::into)
        })
}

// Off Linux the package still builds, so the workspace does; the binary only
// reports that it cannot run. A macro keeps this stub out of the mutation
// scope: it is never compiled, and so never tested, on Linux.
#[cfg(not(target_os = "linux"))]
macro_rules! unsupported_platform_main {
    () => {
        fn main() -> std::process::ExitCode {
            use std::io::Write;
            writeln!(
                std::io::stderr(),
                "pos-root-selector runs only on the Linux systemd provider host"
            )
            .ok();
            std::process::ExitCode::FAILURE
        }
    };
}

#[cfg(not(target_os = "linux"))]
unsupported_platform_main!();

#[cfg(test)]
mod tests {
    #[cfg(target_os = "linux")]
    #[test]
    fn entrypoint_fails_closed_without_the_fixed_root_installation() {
        assert!(super::main().is_err());
    }
}
