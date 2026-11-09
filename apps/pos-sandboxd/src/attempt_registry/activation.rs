//! The durable marker of the last `MountImage` request (owner decision D2).
//!
//! A previous runtime's request may still be served by systemd-mountfsd after
//! a restart's inventory, so a loop device could appear after it. Before every
//! request, the registry therefore replaces its one `activation` marker
//! durably, with the current boot ID and the `CLOCK_MONOTONIC` time. Restart
//! reconciliation waits until a marker of the current boot is older than the
//! activator deadline plus [`SERVER_MARGIN`] before it sweeps the provider
//! loops.
//!
//! The time is `CLOCK_MONOTONIC`, not `CLOCK_BOOTTIME`: the monotonic clock
//! stops during suspend, so the age it measures is never larger than the real
//! age of the request, and the wait can only err long.
//!
//! The private PAA1 format is exactly the tag, the 16-byte boot ID, and the
//! time as little-endian u64 seconds and nanoseconds. An all-zero boot ID and
//! time is the explicit "no request yet" record: a new registry owner writes
//! it before it can commit any intent, when no marker exists, so a crash
//! before the first request still leaves a marker. A host boot ID is a random
//! UUID and never all zero, and any other record with a zero boot ID is
//! malformed. Like an intent, the marker is written and fsynced as a unique
//! `.activation-<pid>-<sequence>` temporary file, renamed to `activation`, and
//! the registry is fsynced. It is not an attempt key: reconciliation keeps it.
//!
//! The registry lives on the tmpfs `/run`, so these fsyncs order the marker
//! before the request across a daemon crash; a reboot empties the registry,
//! and a marker could not outlive its boot anyway because the boot ID changes.

use std::io;
use std::time::Duration;

use rustix::fs::RenameFlags;
use rustix::time::{clock_gettime, ClockId};

use super::{
    publish_named, read_named_bytes, registry_io, RegistryDirectory, SystemdAttemptRegistryError,
};
use crate::{BootInstant, MountfsdImageActivator};

/// The committed marker's registry component.
pub(super) const MARKER_NAME: &str = "activation";
/// The prefix of a marker's temporary write.
pub(super) const TEMPORARY_PREFIX: &str = ".activation-";
const MARKER_SIZE: usize = 36;
const TAG: &[u8; 4] = b"PAA1";
const BOOT_ID: &str = "/proc/sys/kernel/random/boot_id";
/// The boot ID of the "no request yet" record; no host boot has it.
const NO_BOOT: [u8; 16] = [0; 16];

/// How long systemd-mountfsd may still complete a request after the client
/// connection was lost at its deadline: the server-side work is not cancelled
/// with the client, so restart waits this long beyond the activator deadline.
const SERVER_MARGIN: Duration = Duration::from_secs(10);
/// How long after it was sent a request can still attach a loop device.
const REQUEST_BOUND: Duration = MountfsdImageActivator::DEADLINE.saturating_add(SERVER_MARGIN);

/// The boot and time at which the last `MountImage` request was about to be
/// sent, or [`ActivationMarker::UNREQUESTED`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct ActivationMarker {
    boot: [u8; 16],
    sent: Duration,
}

impl ActivationMarker {
    /// No `MountImage` request was sent since the registry was created.
    const UNREQUESTED: Self = Self {
        boot: NO_BOOT,
        sent: Duration::ZERO,
    };

    fn encode(self) -> [u8; MARKER_SIZE] {
        let mut bytes = [0; MARKER_SIZE];
        bytes[..4].copy_from_slice(TAG);
        bytes[4..20].copy_from_slice(&self.boot);
        bytes[20..28].copy_from_slice(&self.sent.as_secs().to_le_bytes());
        bytes[28..].copy_from_slice(&u64::from(self.sent.subsec_nanos()).to_le_bytes());
        bytes
    }

    /// The caller has checked the tag and the exact length.
    fn decode(bytes: &[u8]) -> Result<Self, SystemdAttemptRegistryError> {
        let mut boot = [0; 16];
        boot.copy_from_slice(&bytes[4..20]);
        let [seconds, nanoseconds] = [&bytes[20..28], &bytes[28..]].map(|chunk| {
            let mut word = [0; 8];
            word.copy_from_slice(chunk);
            u64::from_le_bytes(word)
        });
        u32::try_from(nanoseconds)
            .ok()
            .filter(|nanoseconds| *nanoseconds < 1_000_000_000)
            .map(|nanoseconds| Self {
                boot,
                sent: Duration::new(seconds, nanoseconds),
            })
            .filter(|marker| marker.boot != NO_BOOT || *marker == Self::UNREQUESTED)
            .ok_or(SystemdAttemptRegistryError::InvalidIntent)
    }

    /// How long restart must still wait for the recorded request's deadline.
    ///
    /// `None` for [`Self::UNREQUESTED`], whose boot is no host's, and when
    /// the request was sent on another boot or at least the activator deadline
    /// plus [`SERVER_MARGIN`] ago. A time in this boot's future is a
    /// contradiction.
    pub(super) fn remaining(
        self,
        (boot, now): BootInstant,
    ) -> Result<Option<Duration>, SystemdAttemptRegistryError> {
        if boot != self.boot {
            return Ok(None);
        }
        now.checked_sub(self.sent)
            .map(|elapsed| {
                REQUEST_BOUND
                    .checked_sub(elapsed)
                    .filter(|remaining| !remaining.is_zero())
            })
            .ok_or(SystemdAttemptRegistryError::ActivationMarker)
    }
}

/// Validate a marker file's content; a temporary write may be any prefix.
///
/// Returns the decoded marker of a complete record.
pub(super) fn parse_content(
    bytes: &[u8],
    temporary: bool,
) -> Result<Option<ActivationMarker>, SystemdAttemptRegistryError> {
    let header = &bytes[..bytes.len().min(4)];
    if !TAG.starts_with(header)
        || bytes.len() > MARKER_SIZE
        || !temporary && bytes.len() != MARKER_SIZE
    {
        return Err(SystemdAttemptRegistryError::InvalidIntent);
    }
    if bytes.len() == MARKER_SIZE {
        ActivationMarker::decode(bytes).map(Some)
    } else {
        Ok(None)
    }
}

/// The current boot ID and `CLOCK_MONOTONIC` time.
///
/// # Errors
/// Returns the read failure, or `InvalidData` for a boot ID that is not one
/// canonical, nonzero UUID line.
pub(super) fn boot_instant() -> io::Result<BootInstant> {
    registry_io(|| std::fs::read(BOOT_ID)).and_then(|text| instant_on(&text))
}

/// The boot named by the boot ID file's `text`, at the current
/// `CLOCK_MONOTONIC` time.
fn instant_on(text: &[u8]) -> io::Result<BootInstant> {
    let boot = parse_boot_id(text).ok_or_else(|| io::Error::from(io::ErrorKind::InvalidData))?;
    let now = clock_gettime(ClockId::Monotonic);
    Ok((
        boot,
        Duration::from_secs(now.tv_sec.unsigned_abs())
            .saturating_add(Duration::from_nanos(now.tv_nsec.unsigned_abs())),
    ))
}

/// The 16 bytes of one `8-4-4-4-12` hexadecimal UUID line, never all zero.
fn parse_boot_id(text: &[u8]) -> Option<[u8; 16]> {
    let line = text.strip_suffix(b"\n")?;
    if line
        .split(|byte| *byte == b'-')
        .map(<[u8]>::len)
        .ne([8, 4, 4, 4, 12])
    {
        return None;
    }
    let nibbles = line
        .iter()
        .filter(|byte| **byte != b'-')
        .map(|byte| {
            char::from(*byte)
                .to_digit(16)
                .and_then(|digit| u8::try_from(digit).ok())
        })
        .collect::<Option<Vec<_>>>()?;
    let mut boot = [0; 16];
    for (slot, pair) in boot.iter_mut().zip(nibbles.chunks_exact(2)) {
        *slot = pair[0] * 16 + pair[1];
    }
    Some(boot).filter(|boot| *boot != NO_BOOT)
}

/// Durably replace the marker with the current boot and time, then read it
/// back. The caller holds the registry owner's state lock, so markers are
/// written one at a time and their times never go backwards.
pub(super) fn publish(
    directory: &RegistryDirectory,
    sequence: u64,
) -> Result<(), SystemdAttemptRegistryError> {
    let (boot, sent) = boot_instant()?;
    write(
        directory,
        sequence,
        ActivationMarker { boot, sent },
        RenameFlags::empty(),
    )
}

/// Durably create the "no request yet" marker of a registry that has none,
/// then read it back. The caller is the new owner, before any commit.
pub(super) fn initialize(
    directory: &RegistryDirectory,
    sequence: u64,
) -> Result<(), SystemdAttemptRegistryError> {
    write(
        directory,
        sequence,
        ActivationMarker::UNREQUESTED,
        RenameFlags::NOREPLACE,
    )
}

fn write(
    directory: &RegistryDirectory,
    sequence: u64,
    marker: ActivationMarker,
    rename: RenameFlags,
) -> Result<(), SystemdAttemptRegistryError> {
    let bytes = marker.encode();
    let temporary = format!("{TEMPORARY_PREFIX}{}-{sequence}", std::process::id());
    publish_named(directory, &temporary, MARKER_NAME, &bytes, rename, || {})?;
    read_named_bytes::<MARKER_SIZE>(directory, MARKER_NAME).and_then(|observed| {
        (observed == bytes)
            .then_some(())
            .ok_or(SystemdAttemptRegistryError::InvalidIntent)
    })
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests;
