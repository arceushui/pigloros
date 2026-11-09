//! The durable marker of the last `MountImage` request (owner decision D2).
//!
//! A previous runtime's request may still be served by systemd-mountfsd after
//! a restart's provider loop sweep, so a loop device could appear after that
//! sweep passed. Before every request, the registry therefore replaces its one
//! `activation` marker durably, with the current boot ID and the
//! `CLOCK_MONOTONIC` time. Restart reconciliation waits until a marker of the
//! current boot is older than the activator deadline before it sweeps again.
//!
//! The private PAA1 format is exactly the tag, the 16-byte boot ID, and the
//! time as little-endian u64 seconds and nanoseconds. Like an intent, the
//! marker is written and fsynced as a unique `.activation-<pid>-<sequence>`
//! temporary file, renamed over `activation`, and the registry is fsynced. It is
//! not an attempt key: reconciliation keeps it, so within one boot it exists
//! once any request was sent.

use std::io;
use std::time::Duration;

use rustix::fs::RenameFlags;
use rustix::time::{clock_gettime, ClockId};

use super::{
    publish_named, read_named_bytes, registry_io, RegistryDirectory, SystemdAttemptRegistryError,
};
use crate::MountfsdImageActivator;

/// The committed marker's registry component.
pub(super) const MARKER_NAME: &str = "activation";
/// The prefix of a marker's temporary write.
pub(super) const TEMPORARY_PREFIX: &str = ".activation-";
const MARKER_SIZE: usize = 36;
const TAG: &[u8; 4] = b"PAA1";
const BOOT_ID: &str = "/proc/sys/kernel/random/boot_id";

/// A boot ID and a `CLOCK_MONOTONIC` time on that boot.
pub(super) type BootInstant = ([u8; 16], Duration);

/// The boot and time at which the last `MountImage` request was about to be
/// sent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct ActivationMarker {
    boot: [u8; 16],
    sent: Duration,
}

impl ActivationMarker {
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
            .ok_or(SystemdAttemptRegistryError::InvalidIntent)
    }

    /// How long restart must still wait for the recorded request's deadline.
    ///
    /// `None` when the request was sent on another boot or at least the
    /// activator deadline ago. A time in this boot's future is a
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
                MountfsdImageActivator::DEADLINE
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
/// canonical UUID line.
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

/// The 16 bytes of one `8-4-4-4-12` hexadecimal UUID line.
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
    Some(boot)
}

/// Durably replace the marker with the current boot and time, then read it
/// back. The caller holds the registry owner's state lock, so markers are
/// written one at a time and their times never go backwards.
pub(super) fn publish(
    directory: &RegistryDirectory,
    sequence: u64,
) -> Result<(), SystemdAttemptRegistryError> {
    let (boot, sent) = boot_instant()?;
    let bytes = ActivationMarker { boot, sent }.encode();
    let temporary = format!("{TEMPORARY_PREFIX}{}-{sequence}", std::process::id());
    publish_named(
        directory,
        &temporary,
        MARKER_NAME,
        &bytes,
        RenameFlags::empty(),
        || {},
    )?;
    read_named_bytes::<MARKER_SIZE>(directory, MARKER_NAME).and_then(|observed| {
        (observed == bytes)
            .then_some(())
            .ok_or(SystemdAttemptRegistryError::InvalidIntent)
    })
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests;
