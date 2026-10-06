//! The worker side of the Local relaxation (ADR-061 revision 4, decision 1).
//!
//! A worker program calls [`prepare_worker_process`] before it reads anything.
//! It refuses to run, and exits without a response, unless:
//! 1. its only argument is a process ID, and binding the parent-death signal
//!    leaves that process as its parent. `PR_SET_PDEATHSIG` with `SIGKILL`
//!    kills the worker when the supervisor exits; the parent check closes the
//!    race in which the supervisor exited before the signal was bound;
//! 2. its environment holds only [`FORWARDED_ENVIRONMENT`] names;
//! 3. its open descriptors are exactly standard input, output and error.
//!
//! These calls are safe `rustix` wrappers; the worker needs no `unsafe` code.
//! The worker then reads exactly one request frame and writes exactly one
//! response frame.

use std::ffi::OsString;
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, OwnedFd};

use rustix::fs::Dir;
use rustix::process::{getppid, set_parent_process_death_signal, Pid, Signal};

use crate::frame::{read_frame, write_frame, WorkerFrameLimitsV1};
use crate::ipc::{
    decode_worker_request_v1, encode_worker_response_v1, WorkerOutcomeV1, WorkerRequestV1,
};
use crate::launch::FORWARDED_ENVIRONMENT;

/// Why a worker process refused to serve its invocation.
///
/// Public so the worker programs can return it; they only turn it into an
/// unsuccessful exit, which the supervisor reports as `WorkerCrashed`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorkerProcessErrorV1 {
    /// The arguments are not exactly one supervisor process ID.
    Arguments,
    /// The parent-death signal could not be bound to the supervisor.
    Parent,
    /// The environment holds a name the supervisor does not forward.
    Environment,
    /// A descriptor other than standard input, output and error is open.
    Descriptors,
    /// The request frame or envelope is malformed.
    Request,
    /// The response frame could not be written.
    Response,
}

/// Check the worker process before it reads its request.
///
/// `arguments` are the process arguments, program name first.
///
/// # Errors
/// Returns the first failed check, in the order the module lists them.
pub fn prepare_worker_process(
    arguments: impl IntoIterator<Item = OsString>,
) -> Result<(), WorkerProcessErrorV1> {
    let parent = supervisor_argument(arguments)?;
    bind_to_parent(parent)?;
    verify_environment(std::env::vars_os().map(|(name, _)| name))?;
    open_descriptors()
        .filter(|open| open.as_slice() == [0, 1, 2])
        .map(|_| ())
        .ok_or(WorkerProcessErrorV1::Descriptors)
}

/// The supervisor process ID: the single argument after the program name.
fn supervisor_argument(
    arguments: impl IntoIterator<Item = OsString>,
) -> Result<Pid, WorkerProcessErrorV1> {
    let mut arguments = arguments.into_iter().skip(1);
    let parent = arguments.next().filter(|_| arguments.next().is_none());
    parent
        .and_then(|parent| parent.into_string().ok())
        .and_then(|parent| parent.parse::<u32>().ok())
        .and_then(|parent| i32::try_from(parent).ok())
        .and_then(Pid::from_raw)
        .ok_or(WorkerProcessErrorV1::Arguments)
}

/// Die with `SIGKILL` when the supervisor exits, which must not have happened.
fn bind_to_parent(parent: Pid) -> Result<(), WorkerProcessErrorV1> {
    set_parent_process_death_signal(Some(Signal::KILL))
        .ok()
        .filter(|()| getppid() == Some(parent))
        .ok_or(WorkerProcessErrorV1::Parent)
}

/// Every environment name must be one the supervisor forwards.
fn verify_environment(
    mut names: impl Iterator<Item = OsString>,
) -> Result<(), WorkerProcessErrorV1> {
    names
        .all(|name| FORWARDED_ENVIRONMENT.iter().any(|allowed| name == *allowed))
        .then_some(())
        .ok_or(WorkerProcessErrorV1::Environment)
}

/// The descriptors open in this process, ascending, except the listing's own.
#[must_use]
pub fn open_descriptors() -> Option<Vec<i32>> {
    let directory = OwnedFd::from(File::open("/proc/self/fd").ok()?);
    let own = directory.as_raw_fd();
    let mut entries = Dir::new(directory).ok()?;
    let mut open = Vec::new();
    while let Some(entry) = entries.read() {
        let name = entry.ok()?.file_name().to_str().ok()?.parse::<i32>();
        open.extend(name.ok().filter(|descriptor| *descriptor != own));
    }
    open.sort_unstable();
    Some(open)
}

/// Read and decode the single request frame.
///
/// # Errors
/// Returns `Request` for a truncated, over-limit or malformed frame or
/// envelope.
pub fn read_request(reader: &mut impl Read) -> Result<WorkerRequestV1, WorkerProcessErrorV1> {
    read_frame(reader, WorkerFrameLimitsV1::REQUEST_BYTES)
        .ok()
        .and_then(|bytes| decode_worker_request_v1(&bytes).ok())
        .ok_or(WorkerProcessErrorV1::Request)
}

/// Encode and write the single response frame.
///
/// # Errors
/// Returns `Response` when the outcome cannot be encoded or the frame cannot
/// be written.
pub fn write_response(
    writer: &mut impl Write,
    outcome: &WorkerOutcomeV1,
) -> Result<(), WorkerProcessErrorV1> {
    encode_worker_response_v1(outcome)
        .ok()
        .and_then(|bytes| write_frame(writer, &bytes, bytes.len()).ok())
        .ok_or(WorkerProcessErrorV1::Response)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use pos_runtime::community_plugin_host::{CommunityPluginHostErrorV1, HostInputs};

    use super::*;
    use crate::test_support::negotiated;
    use crate::ipc::{encode_worker_request_v1, WorkerCallV1};

    fn arguments(values: &[&str]) -> Vec<OsString> {
        values.iter().map(OsString::from).collect()
    }

    #[test]
    fn the_only_argument_is_a_positive_process_id() {
        let parent = supervisor_argument(arguments(&["worker", "42"]));
        assert_eq!(parent.map(Pid::as_raw_nonzero).map(i32::from), Ok(42));
        for invalid in [
            &["worker"][..],
            &["worker", "42", "43"],
            &["worker", "0"],
            &["worker", "-1"],
            &["worker", "2147483648"],
            &["worker", "4x"],
        ] {
            assert_eq!(
                supervisor_argument(arguments(invalid)),
                Err(WorkerProcessErrorV1::Arguments),
                "{invalid:?}"
            );
        }
        let not_utf8 = vec![
            OsString::from("worker"),
            std::os::unix::ffi::OsStringExt::from_vec(vec![0xff]),
        ];
        assert_eq!(
            supervisor_argument(not_utf8),
            Err(WorkerProcessErrorV1::Arguments)
        );
    }

    #[test]
    fn preparation_rejects_bad_arguments_before_any_process_change() {
        assert_eq!(
            prepare_worker_process(arguments(&["worker"])),
            Err(WorkerProcessErrorV1::Arguments)
        );
    }

    #[test]
    fn only_forwarded_names_may_be_in_the_environment() {
        let forwarded = FORWARDED_ENVIRONMENT.iter().map(OsString::from);
        assert_eq!(verify_environment(forwarded), Ok(()));
        assert_eq!(verify_environment(std::iter::empty()), Ok(()));
        let extra = std::iter::once(OsString::from("PATH"));
        assert_eq!(
            verify_environment(extra),
            Err(WorkerProcessErrorV1::Environment)
        );
    }

    #[test]
    fn descriptor_listing_sees_standard_streams_and_new_files() {
        let before = open_descriptors().unwrap_or_default();
        assert!(before.starts_with(&[0, 1, 2]), "{before:?}");
        let file = File::open("/proc/self/stat");
        let raw = file.as_ref().map(AsRawFd::as_raw_fd).ok();
        let during = open_descriptors().unwrap_or_default();
        assert!(raw.is_some_and(|raw| during.contains(&raw)), "{during:?}");
        assert!(during.windows(2).all(|pair| pair[0] < pair[1]));
        drop(file);
    }

    fn request() -> WorkerRequestV1 {
        WorkerRequestV1 {
            component: b"component".to_vec(),
            negotiation: negotiated().to_transport(),
            watchdog_millis: 1_000,
            host_inputs: HostInputs { simulation_time: 9 },
            call: WorkerCallV1::Describe,
        }
    }

    #[test]
    fn requests_and_responses_cross_one_frame_each() {
        let bytes = encode_worker_request_v1(&request()).unwrap_or_default();
        let mut framed = Vec::new();
        assert!(write_frame(&mut framed, &bytes, bytes.len()).is_ok());
        assert_eq!(read_request(&mut framed.as_slice()), Ok(request()));
        let malformed: &[u8] = &[0, 0, 0, 1, 0];
        assert_eq!(
            read_request(&mut &malformed[..]),
            Err(WorkerProcessErrorV1::Request)
        );
        let empty: &[u8] = &[];
        assert_eq!(
            read_request(&mut &empty[..]),
            Err(WorkerProcessErrorV1::Request)
        );
        let outcome: WorkerOutcomeV1 = Err(CommunityPluginHostErrorV1::FuelExhausted);
        let mut out = Vec::new();
        assert_eq!(write_response(&mut out, &outcome), Ok(()));
        let encoded = encode_worker_response_v1(&outcome).unwrap_or_default();
        assert_eq!(out[4..], encoded);
        assert_eq!(
            out[..4],
            u32::try_from(encoded.len()).unwrap_or(0).to_be_bytes()
        );
        let mut full = [0_u8; 3];
        assert_eq!(
            write_response(&mut full.as_mut_slice(), &outcome),
            Err(WorkerProcessErrorV1::Response)
        );
        let unencodable: WorkerOutcomeV1 = Err(CommunityPluginHostErrorV1::WorkerCrashed);
        let mut nothing = Vec::new();
        assert_eq!(
            write_response(&mut nothing, &unencodable),
            Err(WorkerProcessErrorV1::Response)
        );
        assert!(nothing.is_empty());
    }
}
