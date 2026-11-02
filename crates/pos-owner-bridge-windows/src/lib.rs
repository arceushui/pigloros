#![cfg(windows)]

//! Windows-specific owner-bridge adapter boundary.
//!
//! Native Win32 operations are confined to inventoried `ffi` modules. The
//! process probe preserves inspection failure as an indeterminate observation.
//!
//! This crate root deliberately carries no crate-wide `#![forbid(unsafe_code)]`:
//! an inner forbid at the root cannot be relaxed in `ffi`. Every non-ffi `mod`
//! declared here carries `#[forbid(unsafe_code)]` instead, and the policy
//! checker enforces it.

mod ffi;
// Safe entry points implemented by the private native boundary. The type and
// its associated operations are accessible only inside this crate.
struct Native;
#[forbid(unsafe_code)]
mod adapter {
    // The inline boundary and each child file are separate lint scopes. This
    // retains both ADR-110 checks without duplicate attributes on one module.
    mod directory;
    mod overrides;
    mod platform;
    mod process;
    mod runtime;
    mod socket;

    pub use directory::{create_private_directory, verify_private_directory};
    pub use overrides::refuse_overrides;
    pub use platform::{cpu_requirements, require_windows_profile, CpuFeatures};
    pub use process::{process_identity, WindowsProcessProbe};
    pub use runtime::{verify_fixed_runtime, VerifiedRuntime};
    pub use socket::WindowsLoopbackBinder;
}

pub use adapter::{
    cpu_requirements, create_private_directory, process_identity, refuse_overrides,
    require_windows_profile, verify_fixed_runtime, verify_private_directory, CpuFeatures,
    VerifiedRuntime, WindowsLoopbackBinder, WindowsProcessProbe,
};

#[cfg(test)]
#[forbid(unsafe_code)]
mod tests {
    use std::io;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, TcpListener, TcpStream};

    use pos_owner_bridge::listener::bind::LoopbackBinder;

    use crate::WindowsLoopbackBinder;

    #[test]
    fn runtime_checks_all_members_metadata_cache_and_per_start_binaries(
    ) -> Result<(), Box<dyn std::error::Error>> {
        crate::Native::verify_runtime_cache_fixture()
    }

    #[test]
    fn exclusive_loopback_sockets_block_a_reusing_competitor(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut fixed = WindowsLoopbackBinder::default();
        // No connections/TIME_WAIT on the port used by later lifecycle fixtures.
        let fixed_v4 = fixed.bind_v4()?;
        let fixed_v6 = fixed.bind_v6()?;
        assert_eq!(fixed_v4.local_addr()?.port(), 49_291);
        assert_eq!(fixed_v6.local_addr()?.port(), 49_291);
        assert!(fixed.bind_v4().is_err());
        assert!(fixed.bind_v6().is_err());
        drop((fixed_v4, fixed_v6));

        let mut binder = WindowsLoopbackBinder::ephemeral();
        let v4 = binder.bind_v4()?;
        assert_eq!(v4.local_addr()?.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
        let client = TcpStream::connect(v4.local_addr()?)?;
        let (_, peer) = v4.accept()?;
        assert_eq!(peer.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
        drop(client);
        assert!(TcpListener::bind(v4.local_addr()?).is_err());
        let competing = crate::Native::competing_reuse(v4.local_addr()?.port());
        let error = competing
            .err()
            .ok_or("a reusing competitor took the exclusive port")?;
        assert!([io::ErrorKind::AddrInUse, io::ErrorKind::PermissionDenied].contains(&error.kind()));
        let v6 = binder.bind_v6()?;
        assert_eq!(v6.local_addr()?.ip(), IpAddr::V6(Ipv6Addr::LOCALHOST));
        let client = TcpStream::connect(v6.local_addr()?)?;
        assert!(v6.accept().is_ok());
        drop(client);
        assert!(TcpListener::bind(v6.local_addr()?).is_err());
        assert_eq!(binder.probe_v6(), Ok(()));
        drop((v4, v6));
        Ok(())
    }
}
