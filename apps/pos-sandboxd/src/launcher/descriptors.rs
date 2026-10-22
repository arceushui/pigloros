//! Adoption and validation of the descriptors systemd hands the launcher
//! through `ExtraFileDescriptors=` (ADR-069 "Exact descriptor contract").

use std::{io, os::fd::AsRawFd, os::fd::OwnedFd};

use pos_reference::sandbox_provider_protocol::{FdLayoutEntry, FdRole};
use rustix::{
    fs::{open, Dir, Mode, OFlags},
    io::{fcntl_setfd, FdFlags},
    net::{
        sockopt::{socket_domain, socket_type},
        AddressFamily, SocketType,
    },
};

use super::{environment::LaunchEnvironment, error::LauncherError};

/// Name of the Local proxy descriptor (FD 3 in Local mode).
pub(crate) const HOST_SERVICE_NAME: &str = "piglor-host-service-v1";
/// Name of the release descriptor.
pub(crate) const RELEASE_NAME: &str = "piglor-release-v1";
/// Descriptors below this number are stdio.
const FIRST_INHERITED: u32 = 3;

/// Descriptors as adopted: optional systemd name and ownership.
pub(crate) type Inherited = Vec<(Option<String>, OwnedFd)>;

/// The validated inherited descriptors.
#[derive(Debug)]
pub(crate) struct InheritedLayout {
    /// The `SOCK_SEQPACKET` release channel.
    pub(crate) release: OwnedFd,
    /// The Local proxy channel, closed before adapter execution in every
    /// other mode by being absent.
    pub(crate) host_service: Option<OwnedFd>,
    /// The observed FDL1 entries in descriptor order.
    pub(crate) entries: Vec<FdLayoutEntry>,
}

/// Take ownership of descriptors 3 onward named by systemd.
///
/// The environment is validated first, so the count is already bounded. This
/// must be called at most once: every call re-adopts the same numbers.
pub(crate) fn adopt(environment: &LaunchEnvironment) -> Result<Inherited, LauncherError> {
    let adopted = sd_listen_fds::get()
        .ok()
        .ok_or(LauncherError::Environment)?;
    if u32::try_from(adopted.len()) == Ok(environment.descriptor_count) {
        Ok(adopted
            .into_iter()
            .map(|(name, descriptor)| (name, descriptor.into_std()))
            .collect())
    } else {
        Err(LauncherError::Environment)
    }
}

/// Require exactly the expected names, order, socket families and types, and
/// no open descriptor above stdio other than the adopted ones; then seal them
/// all. Adoption numbers them from 3 upward by construction.
///
/// `open` is the complete open set above stdio, excluding the descriptor used
/// to list it.
pub(crate) fn validate(
    inherited: Inherited,
    open: &[u32],
) -> Result<InheritedLayout, LauncherError> {
    let roles = roles(&inherited)?;
    let mut actual_numbers: Vec<u32> = inherited
        .iter()
        .filter_map(|(_, descriptor)| u32::try_from(descriptor.as_raw_fd()).ok())
        .collect();
    actual_numbers.sort_unstable();
    let numbers_match = actual_numbers.len() == roles.len() && open == actual_numbers;
    let types_match = inherited.iter().zip(&roles).all(|((_, descriptor), role)| {
        socket_domain(descriptor).is_ok_and(|domain| domain == AddressFamily::UNIX)
            && socket_type(descriptor).is_ok_and(|kind| kind == expected_type(*role))
    });
    if !numbers_match || !types_match {
        return Err(LauncherError::Layout);
    }
    inherited
        .iter()
        .all(|(_, descriptor)| fcntl_setfd(descriptor, FdFlags::CLOEXEC).is_ok())
        .then_some(())
        .ok_or(LauncherError::Layout)?;
    let entries = (u64::from(FIRST_INHERITED)..)
        .zip(&roles)
        .map(|(fd_number, role)| FdLayoutEntry {
            fd_number,
            role: *role,
        })
        .collect();
    let mut channels = inherited.into_iter().map(|(_, descriptor)| descriptor);
    let (host_service, release) = if roles.len() == 2 {
        (channels.next(), channels.next())
    } else {
        (None, channels.next())
    };
    release
        .map(|release| InheritedLayout {
            release,
            host_service,
            entries,
        })
        .ok_or(LauncherError::Layout)
}

/// The role of each descriptor, from the systemd names alone.
fn roles(inherited: &Inherited) -> Result<Vec<FdRole>, LauncherError> {
    let names: Vec<Option<&str>> = inherited.iter().map(|(name, _)| name.as_deref()).collect();
    match names.as_slice() {
        [Some(RELEASE_NAME)] => Ok(vec![FdRole::Release]),
        [Some(HOST_SERVICE_NAME), Some(RELEASE_NAME)] => {
            Ok(vec![FdRole::HostService, FdRole::Release])
        }
        _ => Err(LauncherError::Layout),
    }
}

const fn expected_type(role: FdRole) -> SocketType {
    match role {
        FdRole::HostService => SocketType::STREAM,
        FdRole::Release => SocketType::SEQPACKET,
    }
}

/// The open descriptors at or above 3, read from `/proc/self/fd`, without the
/// descriptor used for the listing.
pub(crate) fn scan_proc_self_fd() -> io::Result<Vec<u32>> {
    let directory = open(
        "/proc/self/fd",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    let own = directory.as_raw_fd();
    let mut numbers = Vec::new();
    for entry in Dir::new(directory)? {
        let entry = entry?;
        let name = entry.file_name().to_bytes();
        if name == b"." || name == b".." {
            continue;
        }
        let number = std::str::from_utf8(name)
            .ok()
            .and_then(|text| text.parse::<u32>().ok())
            // No real entry is unparsable; a sentinel can never match the
            // adopted set, so it still fails closed.
            .unwrap_or(u32::MAX);
        if number >= FIRST_INHERITED && i32::try_from(number) != Ok(own) {
            numbers.push(number);
        }
    }
    numbers.sort_unstable();
    Ok(numbers)
}
