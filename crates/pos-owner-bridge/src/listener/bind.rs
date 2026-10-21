//! Loopback binding with the IPv4-only fallback and its explicit IPv6-absence probe (ADR-110 §4).

use std::io;
use std::net::TcpListener;

use thiserror::Error;

use crate::{BridgeError, UnavailableCode};

#[cfg(feature = "test-support")]
use std::net::{Ipv4Addr, Ipv6Addr};

/// Platform error values meaning "no IPv6 loopback here": `EAFNOSUPPORT` and `EADDRNOTAVAIL`.
///
/// ADR-110 §4 names the Windows values (`WSAEAFNOSUPPORT` 10047 and `WSAEADDRNOTAVAIL` 10049);
/// the Linux values let the portable core and its tests run on the CI platform, and macOS is
/// listed for development. Any other platform has no values, so every IPv6 failure there is
/// `Other` and the listener fails closed with `PortUnavailable` rather than guessing.
#[cfg(target_os = "linux")]
const IPV6_UNAVAILABLE_CODES: [i32; 2] = [97, 99];
#[cfg(target_os = "macos")]
const IPV6_UNAVAILABLE_CODES: [i32; 2] = [47, 49];
#[cfg(windows)]
const IPV6_UNAVAILABLE_CODES: [i32; 2] = [10047, 10049];
#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
const IPV6_UNAVAILABLE_CODES: [i32; 0] = [];

/// The closed result of one failed bind.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum BindError {
    /// The address is already in use.
    #[error("the loopback address is already in use")]
    InUse,
    /// The IPv6 loopback is absent, with the platform error value that said so.
    #[error("the loopback address family is unavailable (error {0})")]
    Unavailable(i32),
    /// Any other failure.
    #[error("the loopback address could not be bound")]
    Other,
}

/// Classify an I/O error from binding a loopback address.
#[must_use]
pub fn classify_bind_error(error: &io::Error) -> BindError {
    match (error.kind(), error.raw_os_error()) {
        (io::ErrorKind::AddrInUse, _) => BindError::InUse,
        (_, Some(code)) if IPV6_UNAVAILABLE_CODES.contains(&code) => BindError::Unavailable(code),
        _ => BindError::Other,
    }
}

/// Supplies exclusive loopback sockets.
///
/// The Windows shim implements this with `SO_EXCLUSIVEADDRUSE` and `listen(4)` (ADR-110 §4);
/// behind the `test-support` feature, `StdBinder` is a plain `std::net` implementation for tests.
pub trait LoopbackBinder: Send {
    /// Bind `127.0.0.1` on the owner port.
    ///
    /// # Errors
    ///
    /// Returns the classified bind failure.
    fn bind_v4(&mut self) -> Result<TcpListener, BindError>;

    /// Bind `[::1]` on the owner port.
    ///
    /// # Errors
    ///
    /// Returns the classified bind failure.
    fn bind_v6(&mut self) -> Result<TcpListener, BindError>;

    /// Probe `bind([::1]:0)`. `Ok(())` means the probe succeeded and its socket was dropped.
    ///
    /// # Errors
    ///
    /// Returns the classified bind failure.
    fn probe_v6(&mut self) -> Result<(), BindError>;
}

/// Whether the IPv6 loopback socket is held or provably absent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Ipv6Mode {
    /// Both loopback sockets are held.
    Dual,
    /// The IPv6 loopback is absent; startup failed with this platform error value.
    Absent {
        /// The platform error value every later probe must reproduce.
        startup_error: i32,
    },
}

/// The sockets bound at startup.
#[derive(Debug)]
pub(super) struct LoopbackSockets {
    /// The IPv4 loopback socket.
    pub(super) v4: TcpListener,
    /// The IPv6 loopback socket, when the IPv6 loopback exists.
    pub(super) v6: Option<TcpListener>,
    /// Whether IPv6 is held or absent.
    pub(super) mode: Ipv6Mode,
}

/// Check that the IPv6 loopback is still absent with the same platform error value.
///
/// # Errors
///
/// Returns `Unavailable(LoopbackChanged)` when the probe succeeds or fails differently.
pub(super) fn check_ipv6_absent(
    binder: &mut dyn LoopbackBinder,
    startup_error: i32,
) -> Result<(), BridgeError> {
    match binder.probe_v6() {
        Err(BindError::Unavailable(code)) if code == startup_error => Ok(()),
        _ => Err(BridgeError::Unavailable(UnavailableCode::LoopbackChanged)),
    }
}

/// Bind both loopback sockets, falling back to IPv4-only only after the explicit probe.
///
/// # Errors
///
/// Returns `Unavailable(PortUnavailable)` when IPv4 cannot be bound or IPv6 fails for any
/// reason other than absence, and `Unavailable(LoopbackChanged)` when the startup probe
/// disagrees with the startup failure.
pub(super) fn bind_loopback(
    binder: &mut dyn LoopbackBinder,
) -> Result<LoopbackSockets, BridgeError> {
    let port_unavailable = BridgeError::Unavailable(UnavailableCode::PortUnavailable);
    let v4 = binder.bind_v4().or(Err(port_unavailable))?;
    let v6_result = binder.bind_v6();
    match v6_result {
        Ok(v6) => Ok(LoopbackSockets {
            v4,
            v6: Some(v6),
            mode: Ipv6Mode::Dual,
        }),
        Err(BindError::Unavailable(startup_error)) => {
            check_ipv6_absent(binder, startup_error)?;
            Ok(LoopbackSockets {
                v4,
                v6: None,
                mode: Ipv6Mode::Absent { startup_error },
            })
        }
        Err(_) => Err(port_unavailable),
    }
}

/// Binds with `std::net`; `port` is the owner port, or `0` for an ephemeral test port.
///
/// This binder is NOT exclusive: it sets neither `SO_EXCLUSIVEADDRUSE` nor the ADR-110 §4
/// backlog of four, so another local process can share the port on some platforms. It exists for
/// tests only and is therefore compiled only with the `test-support` feature. Production code
/// obtains its binder from the platform shim (Redmine #535).
#[cfg(feature = "test-support")]
#[derive(Clone, Copy, Debug)]
pub struct StdBinder {
    port: u16,
}

#[cfg(feature = "test-support")]
impl StdBinder {
    /// Bind on `port`.
    #[must_use]
    pub const fn new(port: u16) -> Self {
        Self { port }
    }
}

#[cfg(feature = "test-support")]
fn classified(result: io::Result<TcpListener>) -> Result<TcpListener, BindError> {
    match result {
        Ok(listener) => Ok(listener),
        Err(error) => Err(classify_bind_error(&error)),
    }
}

#[cfg(feature = "test-support")]
impl LoopbackBinder for StdBinder {
    fn bind_v4(&mut self) -> Result<TcpListener, BindError> {
        classified(TcpListener::bind((Ipv4Addr::LOCALHOST, self.port)))
    }

    fn bind_v6(&mut self) -> Result<TcpListener, BindError> {
        classified(TcpListener::bind((Ipv6Addr::LOCALHOST, self.port)))
    }

    fn probe_v6(&mut self) -> Result<(), BindError> {
        classified(TcpListener::bind((Ipv6Addr::LOCALHOST, 0))).map(drop)
    }
}
