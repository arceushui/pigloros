//! Durable, content-addressed NXT1 capture retention and offline Replay lookup.
//!
//! The store keeps two private directories below one provider-owned root:
//! `responses/<hex response artifact digest>` holds the exact response bytes,
//! and `transcripts/<hex transcript digest>` holds the canonical NXT1 record.
//! NRP1 version 1 retains every accepted artifact indefinitely, so this store
//! has no deletion, expiry or replacement operation.

use std::fs::File;
use std::io::{self, Read, Write};
use std::os::unix::fs::MetadataExt;

use rustix::fs::{
    mkdirat, openat2, renameat_with, unlinkat, AtFlags, Mode, OFlags, RenameFlags, ResolveFlags,
};
use rustix::io::Errno;
use rustix::process::geteuid;
use rustix::rand::{getrandom, GetRandomFlags};

use super::{
    content_digest, NetworkExchangePlan, NetworkExchangeReply, NetworkExchangeTranscript,
    RESPONSE_DOMAIN,
};

const RESPONSES: &str = "responses";
const TRANSCRIPTS: &str = "transcripts";
// A canonical NXT1 is well below this bound; it only limits retained-record reads.
const TRANSCRIPT_READ_LIMIT: u64 = 1024;
const RESOLVE: ResolveFlags = ResolveFlags::BENEATH
    .union(ResolveFlags::NO_SYMLINKS)
    .union(ResolveFlags::NO_XDEV);
const HEX: &[u8; 16] = b"0123456789abcdef";

/// Closed failures at the durable network capture boundary.
#[derive(Debug, thiserror::Error)]
pub enum NetworkCaptureStoreError {
    /// The root or a retention directory is not a private directory of this user.
    #[error("unsafe network capture store")]
    UnsafeStore,
    /// Only a validated Captured NXY1 reply can become retained evidence.
    #[error("network reply has no captured response")]
    NotCaptured,
    /// A retained record under the same digest does not hold the same bytes.
    #[error("retained network capture differs from the new capture")]
    RetainedMismatch,
    /// The exact capture is missing, unreadable or does not match its authority.
    #[error("captured network exchange is unavailable for Replay")]
    ReplayUnavailable,
    /// An operating-system operation failed; no durable capture is claimed.
    #[error("network capture store I/O failed")]
    Io(#[source] io::Error),
}

/// Content-addressed NXT1 evidence retained under one provider-owned directory.
///
/// Holding the directory descriptors keeps later lookups bound to the opened
/// directories, not to a pathname. The store grants no network authority.
#[derive(Debug)]
pub struct NetworkCaptureStore {
    responses: File,
    transcripts: File,
}

impl NetworkCaptureStore {
    /// Open the retention directories below a provider-owned root directory.
    ///
    /// The root must be a directory owned by the effective user and must not be
    /// writable by its group or others. Missing `responses` and `transcripts`
    /// directories are created with mode `0700`; existing ones must have exactly
    /// that mode and owner. Symbolic links and mount crossings are rejected.
    /// The root is synchronized so newly created directories are durable.
    ///
    /// # Errors
    /// Returns [`NetworkCaptureStoreError::UnsafeStore`] for an unsafe root or
    /// retention directory and [`NetworkCaptureStoreError::Io`] when a directory
    /// cannot be created or opened.
    pub fn open(root: &File) -> Result<Self, NetworkCaptureStoreError> {
        checked_directory(root, false)
            .and_then(|()| {
                retention_directory(root, RESPONSES).and_then(|responses| {
                    retention_directory(root, TRANSCRIPTS).map(|transcripts| Self {
                        responses,
                        transcripts,
                    })
                })
            })
            // Make newly created retention directories durable before any capture.
            .and_then(|store| {
                root.sync_all()
                    .map(|()| store)
                    .map_err(NetworkCaptureStoreError::Io)
            })
    }

    /// Durably retain a Captured reply's response bytes and NXT1 record.
    ///
    /// Call this before writing the Captured reply to the adapter. Each record
    /// is written to a unique temporary file, synchronized, published without
    /// replacement and read back after its directory is synchronized. A record
    /// already retained under the same digest is accepted only when it holds
    /// exactly the same bytes, so repeated identical responses share one artifact.
    ///
    /// # Errors
    /// Rejects a failure reply and a conflicting retained record. An I/O error
    /// means the capture must not be released; a record may still have been
    /// published, so a later persist of the same capture verifies it.
    pub fn persist(&self, reply: &NetworkExchangeReply) -> Result<(), NetworkCaptureStoreError> {
        reply
            .response_bytes()
            .zip(reply.transcript())
            .ok_or(NetworkCaptureStoreError::NotCaptured)
            .and_then(|(response, transcript)| {
                retain(
                    &self.responses,
                    &content_digest(RESPONSE_DOMAIN, response),
                    response,
                )
                .and_then(|()| {
                    transcript
                        .to_canonical_cbor()
                        .map_err(io::Error::other)
                        .map_err(NetworkCaptureStoreError::Io)
                })
                .and_then(|record| retain(&self.transcripts, &transcript.digest(), &record))
            })
    }

    /// Resolve one retained exchange for offline Replay, without network I/O.
    ///
    /// The authorized report supplies the attempt, its exact NXP1 occurrence and
    /// the NXT1 digest it recorded; retained bytes cannot choose their own
    /// lookup authority. The response is found by the plan's expected response
    /// digest and the transcript by the reported digest. Both must match the
    /// exact plan, attempt and digest.
    ///
    /// # Errors
    /// Returns [`NetworkCaptureStoreError::ReplayUnavailable`] when either record
    /// is missing or unreadable, or the retained capture does not match.
    pub fn replay(
        &self,
        attempt_id: [u8; 16],
        plan: &NetworkExchangePlan,
        transcript_digest: [u8; 32],
    ) -> Result<ReplayedNetworkExchange, NetworkCaptureStoreError> {
        read_bounded(
            &self.responses,
            &hexadecimal(&plan.expected_response_digest),
            plan.response_maximum,
        )
        .and_then(|response| {
            read_bounded(
                &self.transcripts,
                &hexadecimal(&transcript_digest),
                TRANSCRIPT_READ_LIMIT,
            )
            .map(|record| (response, record))
        })
        .ok()
        .and_then(|(response, record)| {
            NetworkExchangeTranscript::verify_replay(&record, attempt_id, plan, &response)
                .ok()
                .filter(|transcript| transcript.digest() == transcript_digest)
                .map(|transcript| ReplayedNetworkExchange {
                    transcript,
                    response,
                })
        })
        .ok_or(NetworkCaptureStoreError::ReplayUnavailable)
    }
}

/// One retained exchange verified for Replay against its authorized identity.
///
/// Private fields keep the verified transcript and response bytes together.
#[derive(Clone, Debug, PartialEq)]
pub struct ReplayedNetworkExchange {
    transcript: NetworkExchangeTranscript,
    response: Vec<u8>,
}

impl ReplayedNetworkExchange {
    /// The retained NXT1 transcript, equal to the authorized report's digest.
    #[must_use]
    pub const fn transcript(&self) -> &NetworkExchangeTranscript {
        &self.transcript
    }

    /// The captured response bytes, verified against the transcript and plan.
    #[must_use]
    pub fn response_bytes(&self) -> &[u8] {
        &self.response
    }
}

fn checked_directory(directory: &File, private: bool) -> Result<(), NetworkCaptureStoreError> {
    directory
        .metadata()
        .map_err(NetworkCaptureStoreError::Io)
        .and_then(|metadata| {
            let mode = metadata.mode() & 0o7777;
            let permitted = if private {
                mode == 0o700
            } else {
                mode & 0o022 == 0
            };
            if metadata.is_dir() && metadata.uid() == geteuid().as_raw() && permitted {
                Ok(())
            } else {
                Err(NetworkCaptureStoreError::UnsafeStore)
            }
        })
}

fn retention_directory(root: &File, name: &str) -> Result<File, NetworkCaptureStoreError> {
    // An existing entry is accepted only after the checks below; any other
    // creation failure surfaces when the directory cannot be opened.
    mkdirat(root, name, Mode::RWXU).ok();
    openat2(
        root,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
        RESOLVE,
    )
    .map(File::from)
    .map_err(io::Error::from)
    .map_err(NetworkCaptureStoreError::Io)
    .and_then(|directory| checked_directory(&directory, true).map(|()| directory))
}

fn retain(
    directory: &File,
    digest: &[u8; 32],
    bytes: &[u8],
) -> Result<(), NetworkCaptureStoreError> {
    let name = hexadecimal(digest);
    let mut nonce = [0_u8; 16];
    getrandom(&mut nonce, GetRandomFlags::empty())
        .map_err(io::Error::from)
        .and_then(|_| {
            let temporary = format!(".partial-{name}-{}", hexadecimal(&nonce));
            let published = write_new(directory, &temporary, bytes).and_then(|()| {
                renameat_with(
                    directory,
                    temporary.as_str(),
                    directory,
                    name.as_str(),
                    RenameFlags::NOREPLACE,
                )
                .or_else(|errno| (errno == Errno::EXIST).then_some(()).ok_or(errno))
                .map_err(io::Error::from)
            });
            // After a successful rename this name no longer exists.
            unlinkat(directory, temporary.as_str(), AtFlags::empty()).ok();
            published.and_then(|()| directory.sync_all())
        })
        .and_then(|()| read_bounded(directory, &name, bytes.len() as u64))
        .map_err(NetworkCaptureStoreError::Io)
        .and_then(|retained| {
            if retained == bytes {
                Ok(())
            } else {
                Err(NetworkCaptureStoreError::RetainedMismatch)
            }
        })
}

fn write_new(directory: &File, name: &str, bytes: &[u8]) -> io::Result<()> {
    openat2(
        directory,
        name,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::RUSR,
        RESOLVE,
    )
    .map(File::from)
    .map_err(io::Error::from)
    .and_then(|mut file| file.write_all(bytes).and_then(|()| file.sync_all()))
}

/// Read at most one byte more than `maximum`, so an overlong record is visible.
fn read_bounded(directory: &File, name: &str, maximum: u64) -> io::Result<Vec<u8>> {
    openat2(
        directory,
        name,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
        RESOLVE,
    )
    .map(File::from)
    .map_err(io::Error::from)
    .and_then(|file| {
        let mut bytes = Vec::new();
        file.take(maximum.saturating_add(1))
            .read_to_end(&mut bytes)
            .map(|_| bytes)
    })
}

fn hexadecimal(bytes: &[u8]) -> String {
    let mut value = String::new();
    for byte in bytes {
        value.push(char::from(HEX[usize::from(byte >> 4)]));
        value.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    value
}
