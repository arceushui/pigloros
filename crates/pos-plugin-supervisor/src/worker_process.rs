//! The worker side of the Local relaxation (ADR-061 revision 4, decision 1).
//!
//! A worker program calls [`prepare_worker_process`] before it reads anything.
//! It refuses to run, and exits without a response, unless:
//! 1. its only arguments are a process ID and a mode token, exactly `local` or
//!    `air-gapped` (lowercase ASCII), and binding the parent-death signal
//!    leaves that process as its parent. `PR_SET_PDEATHSIG` with `SIGKILL`
//!    kills the worker when the supervisor exits; the parent check closes the
//!    race in which the supervisor exited before the signal was bound;
//! 2. its environment holds only [`FORWARDED_ENVIRONMENT`] names and the
//!    [`RUNTIME_ENVIRONMENT`] names its own coverage runtime sets;
//! 3. its open descriptors are exactly standard input, output and error.
//!
//! These calls are safe `rustix` wrappers; the worker needs no `unsafe` code.
//! The worker then reads exactly one request frame and writes exactly one
//! response frame.

use std::ffi::OsString;
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, OwnedFd};

use pos_runtime::community_plugin_host::CommunityPluginModeV1;
use rustix::fs::Dir;
use rustix::process::{getppid, set_parent_process_death_signal, Pid, Signal};

use crate::frame::{read_frame, require_end, write_frame, WorkerFrameLimitsV1};
use crate::ipc::{
    decode_worker_request_v1, encode_worker_response_v1, WorkerOutcomeV1, WorkerRequestV1,
};
use crate::launch::{mode_from_token, FORWARDED_ENVIRONMENT, RUNTIME_ENVIRONMENT};

/// Why a worker process refused to serve its invocation.
///
/// Public so the worker programs can return it; they only turn it into an
/// unsuccessful exit, which the supervisor reports as `WorkerCrashed`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorkerProcessErrorV1 {
    /// The arguments are not exactly a supervisor process ID and a mode token.
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
/// `arguments` are the process arguments, program name first. On success the
/// result is the mode the supervisor's token names: the only mode this worker
/// serves.
///
/// # Errors
/// Returns the first failed check, in the order the module lists them.
pub fn prepare_worker_process(
    arguments: impl IntoIterator<Item = OsString>,
) -> Result<CommunityPluginModeV1, WorkerProcessErrorV1> {
    let (parent, mode) = worker_arguments(arguments)?;
    bind_to_parent(parent)?;
    verify_environment(std::env::vars_os().map(|(name, _)| name))?;
    open_descriptors()
        .filter(|open| open.as_slice() == [0, 1, 2])
        .map(|_| mode)
        .ok_or(WorkerProcessErrorV1::Descriptors)
}

/// The supervisor process ID and the mode: the two arguments after the
/// program name, and nothing else.
fn worker_arguments(
    arguments: impl IntoIterator<Item = OsString>,
) -> Result<(Pid, CommunityPluginModeV1), WorkerProcessErrorV1> {
    let mut arguments = arguments.into_iter().skip(1);
    let (parent, token) = (arguments.next(), arguments.next());
    let exact = parent.zip(token).filter(|_| arguments.next().is_none());
    exact
        .and_then(|(parent, token)| parent_pid(parent).zip(mode_argument(token)))
        .ok_or(WorkerProcessErrorV1::Arguments)
}

/// A positive process ID in decimal.
fn parent_pid(argument: OsString) -> Option<Pid> {
    argument
        .into_string()
        .ok()
        .and_then(|parent| parent.parse::<u32>().ok())
        .and_then(|parent| i32::try_from(parent).ok())
        .and_then(Pid::from_raw)
}

/// The mode of a UTF-8 token that is exactly `local` or `air-gapped`.
fn mode_argument(argument: OsString) -> Option<CommunityPluginModeV1> {
    argument
        .into_string()
        .ok()
        .and_then(|token| mode_from_token(&token))
}

/// Die with `SIGKILL` when the supervisor exits, which must not have happened.
fn bind_to_parent(parent: Pid) -> Result<(), WorkerProcessErrorV1> {
    set_parent_process_death_signal(Some(Signal::KILL))
        .ok()
        .filter(|()| getppid() == Some(parent))
        .ok_or(WorkerProcessErrorV1::Parent)
}

/// Every environment name must be forwarded or set by the worker's runtime.
fn verify_environment(
    mut names: impl Iterator<Item = OsString>,
) -> Result<(), WorkerProcessErrorV1> {
    names
        .all(|name| {
            [FORWARDED_ENVIRONMENT, RUNTIME_ENVIRONMENT]
                .into_iter()
                .flatten()
                .any(|allowed| name == *allowed)
        })
        .then_some(())
        .ok_or(WorkerProcessErrorV1::Environment)
}

/// The descriptors open in this process, ascending, except the listing's own.
///
/// `None` when the listing cannot be opened or read.
#[must_use]
pub fn open_descriptors() -> Option<Vec<i32>> {
    File::open("/proc/self/fd")
        .ok()
        .map(OwnedFd::from)
        .and_then(|directory| {
            let own = directory.as_raw_fd();
            Dir::new(directory)
                .ok()
                .and_then(|entries| descriptor_numbers(entries, own))
        })
}

/// The numeric entry names of `entries`, ascending, without `own`.
///
/// A non-numeric name (`.` and `..`) is skipped; an unreadable entry fails the
/// whole listing.
fn descriptor_numbers(entries: Dir, own: i32) -> Option<Vec<i32>> {
    let names: Result<Vec<Option<i32>>, _> = entries
        .map(|entry| {
            entry.map(|entry| {
                entry
                    .file_name()
                    .to_str()
                    .ok()
                    .and_then(|name| name.parse::<i32>().ok())
            })
        })
        .collect();
    names.ok().map(|names| {
        let mut open: Vec<i32> = names
            .into_iter()
            .flatten()
            .filter(|descriptor| *descriptor != own)
            .collect();
        open.sort_unstable();
        open
    })
}

/// Read and decode the single request frame.
///
/// # Errors
/// Returns `Request` for a truncated, over-limit or malformed frame or
/// envelope, or for any byte after the frame.
pub fn read_request(reader: &mut impl Read) -> Result<WorkerRequestV1, WorkerProcessErrorV1> {
    read_frame(reader, WorkerFrameLimitsV1::REQUEST_BYTES)
        .ok()
        .and_then(|bytes| require_end(reader).ok().map(|()| bytes))
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
    use crate::ipc::{encode_worker_request_v1, WorkerCallV1};
    use crate::test_support::negotiated;

    fn arguments(values: &[&str]) -> Vec<OsString> {
        values.iter().map(OsString::from).collect()
    }

    fn parsed(values: &[&str]) -> Result<(i32, CommunityPluginModeV1), WorkerProcessErrorV1> {
        let (parent, mode) = worker_arguments(arguments(values))?;
        Ok((i32::from(parent.as_raw_nonzero()), mode))
    }

    fn not_utf8() -> OsString {
        std::os::unix::ffi::OsStringExt::from_vec(vec![0xff])
    }

    /// R7-P2: exactly `<pid> local` or `<pid> air-gapped` is accepted.
    #[test]
    fn the_arguments_are_a_positive_process_id_and_a_mode_token() {
        assert_eq!(
            parsed(&["worker", "42", "local"]),
            Ok((42, CommunityPluginModeV1::Local))
        );
        assert_eq!(
            parsed(&["worker", "42", "air-gapped"]),
            Ok((42, CommunityPluginModeV1::AirGapped))
        );
        for invalid in [
            &["worker"][..],
            &["worker", "42"],
            &["worker", "local"],
            &["worker", "local", "42"],
            &["worker", "42", "Local"],
            &["worker", "42", "LOCAL"],
            &["worker", "42", "airgapped"],
            &["worker", "42", "air_gapped"],
            &["worker", "42", "Air-Gapped"],
            &["worker", "42", ""],
            &["worker", "42", "local", "extra"],
            &["worker", "42", "air-gapped", "43"],
            &["worker", "0", "local"],
            &["worker", "-1", "local"],
            &["worker", "2147483648", "local"],
            &["worker", "4x", "local"],
        ] {
            assert_eq!(
                parsed(invalid),
                Err(WorkerProcessErrorV1::Arguments),
                "{invalid:?}"
            );
        }
    }

    #[test]
    fn a_non_utf8_argument_is_refused() {
        let token = vec![OsString::from("worker"), OsString::from("42"), not_utf8()];
        assert_eq!(
            worker_arguments(token).err(),
            Some(WorkerProcessErrorV1::Arguments)
        );
        let parent = vec![
            OsString::from("worker"),
            not_utf8(),
            OsString::from("local"),
        ];
        assert_eq!(
            worker_arguments(parent).err(),
            Some(WorkerProcessErrorV1::Arguments)
        );
    }

    #[test]
    fn preparation_rejects_bad_arguments_before_any_process_change() {
        for invalid in [&["worker"][..], &["worker", "1"], &["worker", "1", "Local"]] {
            assert_eq!(
                prepare_worker_process(arguments(invalid)),
                Err(WorkerProcessErrorV1::Arguments)
            );
        }
    }

    #[test]
    fn preparation_checks_the_parent_and_then_the_environment() {
        // Binding the parent-death signal to a process that is not our parent
        // is refused. The signal stays bound to our real parent, which is the
        // test runner that outlives this test.
        let other = std::process::id().to_string();
        assert_eq!(
            prepare_worker_process(arguments(&["worker", &other, "local"])),
            Err(WorkerProcessErrorV1::Parent)
        );
        // With the real parent the test process still fails: its environment
        // is not a worker's scrubbed one.
        let parent = getppid().map(|parent| parent.as_raw_nonzero().to_string());
        let parent = parent.unwrap_or_default();
        assert_eq!(
            prepare_worker_process(arguments(&["worker", &parent, "air-gapped"])),
            Err(WorkerProcessErrorV1::Environment)
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

    /// The profile runtime's own marker is accepted only in a coverage build.
    #[cfg(coverage)]
    #[test]
    fn a_coverage_build_accepts_the_profile_runtime_marker() {
        let marker = std::iter::once(OsString::from("__LLVM_PROFILE_RT_INIT_ONCE"));
        assert_eq!(verify_environment(marker), Ok(()));
        assert!(RUNTIME_ENVIRONMENT.contains(&"__LLVM_PROFILE_RT_INIT_ONCE"));
    }

    #[cfg(not(coverage))]
    #[test]
    fn a_production_build_refuses_the_profile_runtime_marker() {
        let marker = std::iter::once(OsString::from("__LLVM_PROFILE_RT_INIT_ONCE"));
        assert_eq!(
            verify_environment(marker),
            Err(WorkerProcessErrorV1::Environment)
        );
        assert!(RUNTIME_ENVIRONMENT.is_empty());
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
        let mut trailing = framed.clone();
        trailing.push(0);
        assert_eq!(
            read_request(&mut trailing.as_slice()),
            Err(WorkerProcessErrorV1::Request)
        );
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
