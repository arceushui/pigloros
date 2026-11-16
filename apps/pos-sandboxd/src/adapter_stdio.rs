//! The adapter's standard channels, its stdin feed and its stdout capture
//! (ADR-069 R10 §4.1, §4.5 and §4.6).
//!
//! Immediately before `StartTransientUnit` the provider creates the three
//! unit descriptors ([`open_channels`]): a stdin pipe and a stdout pipe, whose
//! unit ends block and whose provider ends do not, and a write-only
//! `/dev/null` checked as the character device 1:3. No call creates a
//! process. The unit ends go to systemd as `Standard*FileDescriptor`; the
//! provider keeps one end of each pipe and only writes stdin and only reads
//! stdout.
//!
//! Once `ReleaseV1` was sent, [`AdapterChannels::run`] feeds the verified
//! input under ELM1 ID 16 and captures at most ELM1[8] output bytes, until the
//! execute path's ending stops both. The capture is fenced: its bytes leave
//! the [`FencedOutput`] only against the attempt's terminal evidence.

use std::future::Future;
use std::io;
use std::os::fd::OwnedFd as StdOwnedFd;
use std::sync::Arc;
use std::time::Duration;

use futures_util::future::{join, select, Either};
use pos_reference::{
    provider_admission::execution::AdmittedProviderExecution,
    sandbox_provider_protocol::{OutputCaptureRecord, PayloadDescriptor, TransferRecord},
};
use rustix::fs::{fcntl_getfl, fcntl_setfl, fstat, makedev, open, FileType, Mode, OFlags};
use rustix::io::Errno;
use rustix::pipe::{pipe_with, PipeFlags};
use rustix::time::{clock_gettime, ClockId};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::unix::pipe::{Receiver, Sender};
use tokio::sync::watch;

use crate::{OutputReservationRefused, StagingCharge, TerminalResources, UnitStdio};

/// The provider's write-only stderr target for the unit (R10 §4.1, O3).
const NULL_DEVICE: &str = "/dev/null";

/// The most input bytes read from the staged input per feed step.
const FEED_CHUNK: usize = 64 * 1024;

/// The most output bytes read from the stdout channel per capture step.
const CAPTURE_CHUNK: usize = 64 * 1024;

/// The largest EAO1 frame body (`adapter_transport`).
const MAX_FRAME_BODY: usize = 128 * 1024;

/// The exact body of the first frame: the EAO1 stream header.
const EAO1_BODY: [u8; 7] = [0x82, 0x64, 0x45, 0x41, 0x4f, 0x31, 0x01];

/// The prefix of the final frame's body: an EOE1 record.
const EOE1_PREFIX: [u8; 6] = [0x89, 0x64, 0x45, 0x4f, 0x45, 0x31];

/// The SPY1 output descriptor's digest domain.
const OUTPUT_DOMAIN: &[u8] = b"PiglorOS.SandboxOutputBytes.v1\0";

const NANOSECONDS_PER_MILLISECOND: u64 = 1_000_000;

/// The admitted payload of one attempt, behind one port: its verified input
/// and its one output reservation.
///
/// The production implementation is the admitted execution the attempt's
/// entry retains.
pub(crate) trait AttemptPayload: std::fmt::Debug + Send + Sync {
    /// The verified input length, nonzero and at most ELM1[7].
    fn input_len(&self) -> u64;

    /// Read exactly from the verified input.
    ///
    /// # Errors
    /// Fails for a range beyond the input, or when the read fails.
    fn read_input_at(&self, buffer: &mut [u8], offset: u64) -> io::Result<()>;

    /// Reserve the attempt's one output of exactly ELM1[8] bytes; `None`
    /// once it was reserved.
    fn reserve_output(&self) -> Option<Result<StagingCharge, OutputReservationRefused>>;
}

impl AttemptPayload for AdmittedProviderExecution {
    fn input_len(&self) -> u64 {
        self.policy().input_descriptor().byte_length
    }

    fn read_input_at(&self, buffer: &mut [u8], offset: u64) -> io::Result<()> {
        self.read_exact_at(buffer, offset)
    }

    fn reserve_output(&self) -> Option<Result<StagingCharge, OutputReservationRefused>> {
        Self::reserve_output(self)
    }
}

/// Why the adapter's standard channels could not be created (TME1
/// `launch-failure` 4).
#[derive(Debug, thiserror::Error)]
pub enum StdioChannelError {
    /// A `pipe2`, `fcntl`, `open` or `fstat` call failed.
    #[error("a standard channel could not be created")]
    Io(#[source] io::Error),
    /// The descriptor for fd 2 is not the character device 1:3.
    #[error("the stderr descriptor is not /dev/null")]
    NotNullDevice,
}

/// The provider's ends of the two pipes: it only writes stdin and only
/// reads stdout. Both are non-blocking.
#[derive(Debug)]
pub(crate) struct ProviderStdio {
    input: StdOwnedFd,
    output: StdOwnedFd,
}

/// Create the unit's three standard descriptors and keep the provider's two
/// pipe ends (R10 §4.1).
///
/// # Errors
/// [`StdioChannelError`]: a failed call, or a stderr target that is not
/// `/dev/null`.
pub(crate) fn open_channels() -> Result<(UnitStdio, ProviderStdio), StdioChannelError> {
    open_channels_with(NULL_DEVICE)
}

/// [`open_channels`] with `null` as the stderr target, which must still be
/// the character device 1:3.
fn open_channels_with(null: &str) -> Result<(UnitStdio, ProviderStdio), StdioChannelError> {
    pipe_with(PipeFlags::CLOEXEC)
        .and_then(|input| pipe_with(PipeFlags::CLOEXEC).map(|output| (input, output)))
        .and_then(|(input, output)| {
            // O_NONBLOCK on the provider's ends only: the unit's stay blocking.
            nonblocking(&input.1)
                .and_then(|()| nonblocking(&output.0))
                .map(|()| (input, output))
        })
        .and_then(|pipes| {
            open(null, OFlags::WRONLY | OFlags::CLOEXEC, Mode::empty())
                .and_then(|error| fstat(&error).map(|stat| (pipes, error, stat)))
        })
        .map_err(|errno| StdioChannelError::Io(errno.into()))
        .and_then(
            |(((input_read, input_write), (output_read, output_write)), error, stat)| {
                if FileType::from_raw_mode(stat.st_mode) == FileType::CharacterDevice
                    && stat.st_rdev == makedev(1, 3)
                {
                    Ok((
                        UnitStdio::new(input_read.into(), output_write.into(), error.into()),
                        ProviderStdio {
                            input: input_write,
                            output: output_read,
                        },
                    ))
                } else {
                    Err(StdioChannelError::NotNullDevice)
                }
            },
        )
}

fn nonblocking(descriptor: &StdOwnedFd) -> Result<(), Errno> {
    fcntl_getfl(descriptor).and_then(|flags| fcntl_setfl(descriptor, flags | OFlags::NONBLOCK))
}

/// `CLOCK_MONOTONIC` now, in nanoseconds.
pub(crate) fn monotonic_now_ns() -> u64 {
    let now = clock_gettime(ClockId::Monotonic);
    u64::try_from(now.tv_sec)
        .unwrap_or_default()
        .saturating_mul(1_000_000_000)
        .saturating_add(u64::try_from(now.tv_nsec).unwrap_or_default())
}

/// Everything the feed and the capture of one attempt need once the
/// adapter is released.
#[derive(Debug)]
pub(crate) struct AdapterChannels {
    provider: ProviderStdio,
    payload: Arc<dyn AttemptPayload>,
    /// ELM1[8]: the most output bytes accepted.
    output_limit: u64,
    /// ELM1[16] in milliseconds: the feed's window.
    input_window_ms: u64,
    charge: StagingCharge,
}

impl AdapterChannels {
    pub(crate) const fn new(
        provider: ProviderStdio,
        payload: Arc<dyn AttemptPayload>,
        output_limit: u64,
        input_window_ms: u64,
        charge: StagingCharge,
    ) -> Self {
        Self {
            provider,
            payload,
            output_limit,
            input_window_ms,
            charge,
        }
    }

    /// Feed the input and capture the output from now, which is immediately
    /// after `ReleaseV1` was sent, until each stops on its own or `ended`
    /// reports the execute path's ending: `Some(true)` when it observed the
    /// cgroup empty, which drains the stdout channel, and `Some(false)`
    /// otherwise, which aborts the capture.
    pub(crate) async fn run(self, ended: watch::Receiver<Option<bool>>) -> AdapterIo {
        let Self {
            provider,
            payload,
            output_limit,
            input_window_ms,
            charge,
        } = self;
        let start = monotonic_now_ns();
        let window = Duration::from_millis(input_window_ms);
        let deadline = tokio::time::Instant::now().checked_add(window);
        let fed = feed(
            provider.input,
            &*payload,
            deadline,
            ended_signal(ended.clone()),
        );
        let captured = capture(provider.output, output_limit, ended_signal(ended));
        let ((accepted, finish), captured) = join(fed, captured).await;
        let expected = payload.input_len();
        let deadline =
            start.saturating_add(input_window_ms.saturating_mul(NANOSECONDS_PER_MILLISECOND));
        AdapterIo {
            input: TransferRecord {
                start,
                deadline,
                finish,
                expected_bytes: expected,
                accepted_bytes: accepted,
                complete: accepted == expected && finish <= deadline,
            },
            output: captured.fenced(charge),
        }
    }
}

/// Whether the execute path ended with its cgroup observed empty, once it
/// ended. A dropped sender is an ending without that observation.
async fn ended_signal(mut ended: watch::Receiver<Option<bool>>) -> bool {
    ended
        .wait_for(Option::is_some)
        .await
        .is_ok_and(|ended| *ended == Some(true))
}

/// Write the verified input to the stdin channel until every byte was
/// accepted, a write failed, the window closed or the execute path ended;
/// then close the channel. The accepted bytes and when the feed stopped.
async fn feed(
    channel: StdOwnedFd,
    payload: &dyn AttemptPayload,
    deadline: Option<tokio::time::Instant>,
    ended: impl Future<Output = bool> + Send,
) -> (u64, u64) {
    let mut accepted = 0;
    // The descriptor is the non-blocking write end of a pipe.
    if let Ok(mut channel) = Sender::from_owned_fd_unchecked(channel) {
        let closed = async move {
            match deadline {
                Some(deadline) => tokio::time::sleep_until(deadline).await,
                None => std::future::pending().await,
            }
        };
        select(
            std::pin::pin!(write_input(&mut channel, payload, &mut accepted)),
            select(std::pin::pin!(closed), std::pin::pin!(ended)),
        )
        .await;
    }
    (accepted, monotonic_now_ns())
}

/// Write every input byte, counting what the kernel pipe accepted. A
/// non-blocking pipe write never fails with `EINTR`; any failure, `EPIPE`
/// among them, stops the feed.
async fn write_input(channel: &mut Sender, payload: &dyn AttemptPayload, accepted: &mut u64) {
    let expected = payload.input_len();
    let mut chunk = vec![0; FEED_CHUNK];
    while *accepted < expected {
        let length =
            usize::try_from(expected - *accepted).map_or(FEED_CHUNK, |left| left.min(FEED_CHUNK));
        if payload
            .read_input_at(&mut chunk[..length], *accepted)
            .is_err()
        {
            return;
        }
        let mut written = 0;
        while written < length {
            let wrote = std::future::poll_fn(|context| {
                std::pin::Pin::new(&mut *channel).poll_write(context, &chunk[written..length])
            })
            .await;
            let Ok(wrote) = wrote else {
                return;
            };
            written += wrote;
            *accepted += wrote as u64;
        }
    }
}

/// How the capture stopped (R10 §4.6).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CaptureStop {
    /// (E): end of file, or the drain after an empty cgroup reached `EAGAIN`.
    EndOfStream,
    /// (C): ELM1[8] bytes were accepted and one more byte was read.
    Ceiling,
    /// (X): a read failed, or the execute path ended without an empty cgroup.
    Aborted,
}

/// The accepted bytes and how the capture stopped.
#[derive(Debug)]
struct Captured {
    bytes: Vec<u8>,
    stop: CaptureStop,
}

impl Captured {
    fn fenced(self, charge: StagingCharge) -> FencedOutput {
        let ceiling_reached = self.stop == CaptureStop::Ceiling;
        FencedOutput {
            capture: OutputCaptureRecord {
                accepted_bytes: self.bytes.len() as u64,
                ceiling_reached,
                complete_frame: self.stop == CaptureStop::EndOfStream && framed(&self.bytes),
            },
            bytes: self.bytes,
            charge,
        }
    }
}

/// Read the stdout channel until end of file, the ceiling, a read failure or
/// the execute path's ending; then close it. An ending with the cgroup
/// observed empty drains the channel without waiting.
async fn capture(
    channel: StdOwnedFd,
    limit: u64,
    ended: impl Future<Output = bool> + Send,
) -> Captured {
    let mut bytes = Vec::new();
    // The descriptor is the non-blocking read end of a pipe.
    let stop = match Receiver::from_owned_fd_unchecked(channel) {
        Ok(mut channel) => {
            // The read borrows the bytes; it ends with this statement.
            let ended = match select(
                std::pin::pin!(read_output(&mut channel, limit, &mut bytes)),
                std::pin::pin!(ended),
            )
            .await
            {
                Either::Left((stop, _)) => Ok(stop),
                Either::Right((empty, _)) => Err(empty),
            };
            match ended {
                Ok(stop) => stop,
                Err(true) => drain(&channel, limit, &mut bytes),
                Err(false) => CaptureStop::Aborted,
            }
        }
        Err(_) => CaptureStop::Aborted,
    };
    Captured { bytes, stop }
}

/// Read until end of file, the ceiling or a read failure. A non-blocking
/// pipe read never fails with `EINTR`.
async fn read_output(channel: &mut Receiver, limit: u64, bytes: &mut Vec<u8>) -> CaptureStop {
    let mut buffer = vec![0; CAPTURE_CHUNK];
    loop {
        let room = room(limit, bytes.len());
        let mut read = ReadBuf::new(&mut buffer[..room]);
        let polled = std::future::poll_fn(|context| {
            std::pin::Pin::new(&mut *channel).poll_read(context, &mut read)
        })
        .await;
        match polled.map(|()| read.filled()) {
            Ok([]) => return CaptureStop::EndOfStream,
            Ok(read) => {
                if let Some(stop) = accept(bytes, read, limit) {
                    return stop;
                }
            }
            Err(_) => return CaptureStop::Aborted,
        }
    }
}

/// After the cgroup was observed empty no unit task can write any more:
/// read what is queued until `EAGAIN` or end of file. The reads go to the
/// descriptor itself, not through the reactor's cached readiness.
fn drain(channel: &Receiver, limit: u64, bytes: &mut Vec<u8>) -> CaptureStop {
    use std::os::fd::AsFd as _;
    let mut buffer = vec![0; CAPTURE_CHUNK];
    loop {
        let room = room(limit, bytes.len());
        match rustix::io::read(channel.as_fd(), &mut buffer[..room]) {
            Ok(0) | Err(Errno::AGAIN) => return CaptureStop::EndOfStream,
            Ok(read) => {
                if let Some(stop) = accept(bytes, &buffer[..read], limit) {
                    return stop;
                }
            }
            Err(_) => return CaptureStop::Aborted,
        }
    }
}

/// How much to read next: up to one byte more than ELM1[8] still allows,
/// so the byte past the ceiling is seen but never accepted.
fn room(limit: u64, accepted: usize) -> usize {
    usize::try_from(limit - accepted as u64).map_or(CAPTURE_CHUNK, |left| {
        left.saturating_add(1).min(CAPTURE_CHUNK)
    })
}

/// Accept `read` up to ELM1[8]; the ceiling once a byte past it was read.
fn accept(bytes: &mut Vec<u8>, read: &[u8], limit: u64) -> Option<CaptureStop> {
    let left = usize::try_from(limit - bytes.len() as u64).unwrap_or(usize::MAX);
    if read.len() > left {
        bytes.extend_from_slice(&read[..left]);
        Some(CaptureStop::Ceiling)
    } else {
        bytes.extend_from_slice(read);
        None
    }
}

/// Whether `bytes` is a framed EAO1 stream (R10 §4.6, C1): at least two
/// length-prefixed frames, the first exactly the EAO1 header, the last the
/// first EOE1 record, and nothing after it. No CBOR is decoded.
fn framed(bytes: &[u8]) -> bool {
    let mut rest = bytes;
    let mut first = true;
    while let Some((prefix, after)) = rest.split_first_chunk::<4>() {
        let length = u32::from_be_bytes(*prefix) as usize;
        let Some(body) = after
            .get(..length)
            .filter(|_| (1..=MAX_FRAME_BODY).contains(&length))
        else {
            return false;
        };
        rest = &after[length..];
        if first {
            if body != EAO1_BODY {
                return false;
            }
            first = false;
        } else if body.starts_with(&EOE1_PREFIX) {
            return rest.is_empty();
        }
    }
    false
}

/// The adapter's stdin feed and stdout capture of one released attempt:
/// TME1 `adapter-input` and `output-capture`.
#[derive(Debug)]
pub struct AdapterIo {
    input: TransferRecord,
    output: FencedOutput,
}

impl AdapterIo {
    /// TME1 `adapter-input`: the stdin feed under ELM1 ID 16.
    #[must_use]
    pub const fn input(&self) -> TransferRecord {
        self.input
    }

    /// The fenced stdout capture.
    #[must_use]
    pub const fn output(&self) -> &FencedOutput {
        &self.output
    }

    /// The fenced stdout capture, by value.
    #[must_use]
    pub fn into_output(self) -> FencedOutput {
        self.output
    }

    /// A feed of one byte and an empty capture, for lifecycle tests.
    #[cfg(test)]
    pub(crate) fn for_test(charge: StagingCharge) -> Self {
        Self {
            input: TransferRecord {
                start: 1,
                deadline: 2,
                finish: 2,
                expected_bytes: 1,
                accepted_bytes: 1,
                complete: true,
            },
            output: Captured {
                bytes: Vec::new(),
                stop: CaptureStop::EndOfStream,
            }
            .fenced(charge),
        }
    }
}

/// The captured stdout bytes, held under the attempt's output reservation.
///
/// They stay fenced until the attempt's terminal evidence was read: only
/// [`Self::release`] hands them out, and it requires that evidence. Its
/// record and descriptor are available before.
#[derive(Debug)]
pub struct FencedOutput {
    capture: OutputCaptureRecord,
    bytes: Vec<u8>,
    charge: StagingCharge,
}

impl FencedOutput {
    /// TME1 `output-capture`.
    #[must_use]
    pub const fn capture(&self) -> OutputCaptureRecord {
        self.capture
    }

    /// The SPY1 output descriptor of the captured bytes: their length and
    /// `BLAKE3-256("PiglorOS.SandboxOutputBytes.v1\0" || B)` (R10 §4.6, I6).
    #[must_use]
    pub fn descriptor(&self) -> PayloadDescriptor {
        let mut hasher = blake3::Hasher::new();
        hasher.update(OUTPUT_DOMAIN);
        hasher.update(&self.bytes);
        PayloadDescriptor {
            byte_length: self.capture.accepted_bytes,
            digest: *hasher.finalize().as_bytes(),
        }
    }

    /// The captured bytes and their reservation, once the terminal evidence
    /// was read after the unit's exit and before its teardown.
    #[must_use]
    pub fn release(self, _terminal: &TerminalResources) -> ReleasedOutput {
        ReleasedOutput {
            bytes: self.bytes,
            _charge: self.charge,
        }
    }
}

/// Captured stdout bytes released after the terminal evidence; dropping them
/// releases their output reservation.
#[derive(Debug)]
pub struct ReleasedOutput {
    bytes: Vec<u8>,
    _charge: StagingCharge,
}

impl ReleasedOutput {
    /// The exact captured EAO1 stream.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests;
