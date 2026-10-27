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
pub(super) const HOST_SERVICE_NAME: &str = "piglor-host-service-v1";
/// Name of the release descriptor.
pub(super) const RELEASE_NAME: &str = "piglor-release-v1";
const LISTING_FLAGS: OFlags = OFlags::RDONLY
    .union(OFlags::DIRECTORY)
    .union(OFlags::CLOEXEC);
/// Descriptors below this number are stdio.
const FIRST_INHERITED: u32 = 3;

/// Descriptors as adopted: optional systemd name and ownership.
pub(super) type Inherited = Vec<(Option<String>, OwnedFd)>;

/// The validated inherited descriptors.
#[derive(Debug)]
pub(super) struct InheritedLayout {
    /// The `SOCK_SEQPACKET` release channel.
    pub(super) release: OwnedFd,
    /// The Local proxy channel, closed before adapter execution in every
    /// other mode by being absent.
    pub(super) host_service: Option<OwnedFd>,
    /// The observed FDL1 entries in descriptor order.
    pub(super) entries: Vec<FdLayoutEntry>,
}

/// Take ownership of descriptors 3 onward named by systemd.
///
/// The environment is validated first, so the count is already bounded. This
/// must be called at most once: every call re-adopts the same numbers.
pub(super) fn adopt(environment: &LaunchEnvironment) -> Result<Inherited, LauncherError> {
    sd_listen_fds::get()
        .ok()
        .filter(|adopted| u32::try_from(adopted.len()) == Ok(environment.descriptor_count))
        .map(|adopted| {
            adopted
                .into_iter()
                .map(|(name, descriptor)| (name, descriptor.into_std()))
                .collect()
        })
        .ok_or(LauncherError::Environment)
}

/// Require exactly the expected names, order, socket families and types, and
/// no open descriptor above stdio other than the adopted ones; then seal them
/// all. Adoption numbers them from 3 upward by construction.
///
/// `open` is the complete open set above stdio, excluding the descriptor used
/// to list it.
pub(super) fn validate(
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
    // Sealing runs only for a layout that already matched.
    let sealed = || {
        inherited
            .iter()
            .all(|(_, descriptor)| fcntl_setfd(descriptor, FdFlags::CLOEXEC).is_ok())
    };
    if !(numbers_match && types_match && sealed()) {
        return Err(LauncherError::Layout);
    }
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
pub(super) fn scan_proc_self_fd() -> io::Result<Vec<u32>> {
    open("/proc/self/fd", LISTING_FLAGS, Mode::empty())
        .and_then(|directory| {
            let own = directory.as_raw_fd();
            Dir::new(directory)
                .and_then(|entries| {
                    entries
                        .map(|entry| entry.map(|entry| entry_number(entry.file_name().to_bytes())))
                        .collect::<Result<Vec<_>, _>>()
                })
                .map(|numbers| (own, numbers))
        })
        .map(|(own, numbers)| {
            let mut listed: Vec<u32> = numbers
                .into_iter()
                .flatten()
                .filter(|number| *number >= FIRST_INHERITED && i32::try_from(*number) != Ok(own))
                .collect();
            listed.sort_unstable();
            listed
        })
        .map_err(io::Error::from)
}

/// The descriptor number named by one `/proc/self/fd` entry, or nothing for
/// `.` and `..`. No real entry is unparsable; a sentinel can never match the
/// adopted set, so it still fails closed.
pub(super) fn entry_number(name: &[u8]) -> Option<u32> {
    (name != b"." && name != b"..").then(|| {
        std::str::from_utf8(name)
            .ok()
            .and_then(|text| text.parse::<u32>().ok())
            .unwrap_or(u32::MAX)
    })
}
