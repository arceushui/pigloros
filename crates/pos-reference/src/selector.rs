//! Root-owned immutable artifact and selector-socket boundary.

use std::io::{Read, Write};
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use rustix::fd::AsFd;
use rustix::net::sockopt::socket_peercred;
use rustix::net::{connect, socket_with, AddressFamily, SocketAddrUnix, SocketFlags, SocketType};

use crate::evaluator::{AdapterError, CaseAttempt, SubjectAdapter, SubjectObservation};
use crate::evaluator_protocol::{EvaluationRequest, SubjectAdapterKind};
use crate::selector_protocol::{
    decode_reply, encode_request, reply_carries_admission_evidence, EncodedSelectorRequest,
};

/// Fixed root-owned selector endpoint. It is not configurable by an evaluator.
pub const SANDBOX_SELECTOR_SOCKET: &str = "/run/pigloros/sandbox-provider.sock";

const SELECTOR_SOCKET_MODE: u32 = 0o600;
const MAX_SELECTOR_TRAILING_BYTES: u64 = 129 * 1024 * 1024;

struct AttemptDeadline {
    expires_at: Instant,
}

impl AttemptDeadline {
    fn new(watchdog_ms: u64) -> Result<Self, AdapterError> {
        Instant::now()
            .checked_add(Duration::from_millis(watchdog_ms))
            .map(|expires_at| Self { expires_at })
            .ok_or(AdapterError::ProtocolFailure)
    }

    fn remaining(&self) -> std::io::Result<Duration> {
        self.expires_at
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::TimedOut))
    }

    fn connect(&self, path: &Path) -> std::io::Result<UnixStream> {
        let address = SocketAddrUnix::new(path)?;
        let socket = socket_with(
            AddressFamily::UNIX,
            SocketType::STREAM,
            SocketFlags::CLOEXEC,
            None,
        )?;
        let stream = UnixStream::from(socket);
        // SO_SNDTIMEO also bounds a blocking Unix-domain connect on Linux,
        // including a selected listener whose accept queue is full.
        stream.set_write_timeout(Some(self.remaining()?))?;
        connect(&stream, &address)?;
        self.remaining().map(|_| stream)
    }
}

struct DeadlineStream {
    stream: UnixStream,
    deadline: AttemptDeadline,
}

impl Read for DeadlineStream {
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        self.stream
            .set_read_timeout(Some(self.deadline.remaining()?))?;
        let read = self.stream.read(bytes)?;
        self.deadline.remaining().map(|_| read)
    }
}

impl Write for DeadlineStream {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.stream
            .set_write_timeout(Some(self.deadline.remaining()?))?;
        let written = self.stream.write(bytes)?;
        self.deadline.remaining().map(|_| written)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.deadline.remaining().and_then(|_| self.stream.flush())
    }
}

fn transport_error(error: &std::io::Error) -> AdapterError {
    match error.kind() {
        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock => {
            AdapterError::WatchdogExpired
        }
        _ => AdapterError::ProtocolFailure,
    }
}

/// Root-authenticated transport to the single selected provider.
#[derive(Debug)]
pub struct SelectorAdapter {
    kind: SubjectAdapterKind,
    subject_artifact_digest: [u8; 32],
    request: EvaluationRequest,
    request_bytes: Vec<u8>,
    next_case_ordinal: Option<u16>,
    provenance: Option<[u8; 32]>,
}

impl SelectorAdapter {
    /// Bind one canonical EVR1 request to the fixed root-owned selector endpoint.
    ///
    /// # Errors
    /// Returns a closed failure when the supplied request cannot produce a
    /// self-consistent canonical EVR1 representation.
    pub fn new(request: EvaluationRequest) -> Result<Self, AdapterError> {
        let request_bytes = request
            .to_canonical_cbor()
            .map_err(|_| AdapterError::ProtocolFailure)?;
        Ok(Self {
            kind: request.subject_adapter,
            subject_artifact_digest: request.subject_artifact_digest,
            request,
            request_bytes,
            next_case_ordinal: None,
            provenance: None,
        })
    }

    fn invoke(&mut self, attempt: &CaseAttempt) -> Result<SubjectObservation, AdapterError> {
        self.invoke_with_selector(attempt, Path::new(SANDBOX_SELECTOR_SOCKET), 0)
    }

    fn invoke_with_selector(
        &mut self,
        attempt: &CaseAttempt,
        socket_path: &Path,
        expected_uid: u32,
    ) -> Result<SubjectObservation, AdapterError> {
        let ordinal = self
            .next_case_ordinal
            .take()
            .ok_or(AdapterError::ProtocolFailure)?;
        let request = encode_request(&self.request, &self.request_bytes, attempt, ordinal)?;
        let reply = Self::invoke_at(
            socket_path,
            expected_uid,
            attempt,
            &request,
            self.request.request_digest,
        )?;
        self.provenance = reply.provenance;
        reply.observation
    }

    fn invoke_at(
        socket_path: &Path,
        expected_uid: u32,
        attempt: &CaseAttempt,
        request: &EncodedSelectorRequest,
        evr1_digest: [u8; 32],
    ) -> Result<crate::selector_protocol::DecodedSelectorReply, AdapterError> {
        let deadline = AttemptDeadline::new(attempt.watchdog_ms)?;
        let socket = connect_at(socket_path, expected_uid, &deadline).map_err(|_| {
            deadline
                .remaining()
                .map_or(AdapterError::WatchdogExpired, |_| AdapterError::Unavailable)
        })?;
        let mut stream = DeadlineStream {
            stream: socket,
            deadline,
        };
        let control_length =
            u32::try_from(request.control.len()).map_err(|_| AdapterError::ProtocolFailure)?;
        stream
            .write_all(&control_length.to_be_bytes())
            .and_then(|()| stream.write_all(&request.control))
            .and_then(|()| stream.write_all(&request.attempt_stream))
            .and_then(|()| stream.flush())
            .map_err(|error| transport_error(&error))?;
        stream
            .stream
            .shutdown(std::net::Shutdown::Write)
            .map_err(|_| AdapterError::ProtocolFailure)?;
        let mut prefix = [0; 4];
        stream
            .read_exact(&mut prefix)
            .map_err(|error| transport_error(&error))?;
        let length = usize::try_from(u32::from_be_bytes(prefix))
            .map_err(|_| AdapterError::ProtocolFailure)?;
        if length == 0 || length > 16 * 1024 * 1024 {
            return Err(AdapterError::ProtocolFailure);
        }
        let mut control = vec![0; length];
        stream
            .read_exact(&mut control)
            .map_err(|error| transport_error(&error))?;
        let has_admission_evidence = reply_carries_admission_evidence(&control);
        let mut trailing = Vec::new();
        stream
            .take(MAX_SELECTOR_TRAILING_BYTES + 1)
            .read_to_end(&mut trailing)
            .map_err(|error| {
                if has_admission_evidence {
                    AdapterError::AuthenticatedEvidenceFailure
                } else {
                    transport_error(&error)
                }
            })?;
        let trailing_length = u64::try_from(trailing.len()).map_err(|_| {
            if has_admission_evidence {
                AdapterError::AuthenticatedEvidenceFailure
            } else {
                AdapterError::ProtocolFailure
            }
        })?;
        if trailing_length > MAX_SELECTOR_TRAILING_BYTES {
            return Err(if has_admission_evidence {
                AdapterError::AuthenticatedEvidenceFailure
            } else {
                AdapterError::ProtocolFailure
            });
        }
        decode_reply(
            &control,
            &trailing,
            request,
            evr1_digest,
            attempt.budget.output_bytes,
        )
    }
}

impl SubjectAdapter for SelectorAdapter {
    fn kind(&self) -> SubjectAdapterKind {
        self.kind
    }

    fn subject_artifact_digest(&self) -> [u8; 32] {
        self.subject_artifact_digest
    }

    fn set_case_ordinal(&mut self, ordinal: u16) {
        self.next_case_ordinal = Some(ordinal);
    }

    fn execute(&mut self, attempt: &CaseAttempt) -> Result<SubjectObservation, AdapterError> {
        self.invoke(attempt)
    }

    fn take_execution_provenance_digest(&mut self) -> Option<[u8; 32]> {
        self.provenance.take()
    }
}

/// Closed local selector/installation failures. No untrusted detail is retained.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum SelectorBoundaryError {
    /// Path ownership, mode, type, identity, or digest is invalid.
    #[error("sandbox selector identity or artifact is invalid")]
    ArtifactInvalid,
    /// Fixed selector socket is unavailable.
    #[error("sandbox selector is unavailable")]
    SelectorUnavailable,
    /// Bounded local I/O failed.
    #[error("sandbox selector I/O failed")]
    Io,
}

fn connect_at(
    path: &Path,
    expected_uid: u32,
    deadline: &AttemptDeadline,
) -> Result<UnixStream, SelectorBoundaryError> {
    connect_at_with(path, expected_uid, |socket_path| {
        deadline.connect(socket_path)
    })
}

fn connect_at_with(
    path: &Path,
    expected_uid: u32,
    connect: impl FnOnce(&Path) -> std::io::Result<UnixStream>,
) -> Result<UnixStream, SelectorBoundaryError> {
    let path = PathBuf::from(path);
    let before =
        std::fs::symlink_metadata(&path).map_err(|_| SelectorBoundaryError::SelectorUnavailable)?;
    if !before.file_type().is_socket()
        || before.uid() != expected_uid
        || before.mode() & 0o777 != SELECTOR_SOCKET_MODE
    {
        return Err(SelectorBoundaryError::ArtifactInvalid);
    }
    let stream = connect(&path).map_err(|_| SelectorBoundaryError::SelectorUnavailable)?;
    let credentials =
        socket_peercred(stream.as_fd()).map_err(|_| SelectorBoundaryError::ArtifactInvalid)?;
    let after =
        std::fs::symlink_metadata(path).map_err(|_| SelectorBoundaryError::SelectorUnavailable)?;
    if credentials.uid.as_raw() != expected_uid
        || before.dev() != after.dev()
        || before.ino() != after.ino()
    {
        return Err(SelectorBoundaryError::ArtifactInvalid);
    }
    Ok(stream)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::os::unix::net::UnixListener;
    use std::thread;

    use super::*;

    fn selector_request() -> Result<EvaluationRequest, AdapterError> {
        use crate::evaluator_protocol::{
            ImplementationIdentity, OutputCapability, SubjectAdapterKind,
        };

        let mut request = EvaluationRequest {
            request_id: [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0],
            profile_digest: [2; 32],
            fixture_bundle_digest: [3; 32],
            subject_adapter: SubjectAdapterKind::PublicPluginProtocol,
            subject_artifact_digest: [4; 32],
            implementation: ImplementationIdentity {
                implementation_id: "subject".to_owned(),
                source_digest: [5; 32],
                build_digest: [6; 32],
                binary_digest: [7; 32],
                public_contract_digest: [8; 32],
                organization_id: None,
            },
            execution_profile_digest: [9; 32],
            trust_policy_snapshot_digest: [10; 32],
            output_capability: OutputCapability {
                capability_digest: [11; 32],
                report_bytes_limit: 1,
                diagnostic_bytes_limit: 0,
            },
            evaluator_protocol_digest: [12; 32],
            evaluator_hard_caps_digest: [13; 32],
            sandbox_requirement: None,
            request_digest: [14; 32],
        };
        request.output_capability.capability_digest = request
            .expected_output_capability_digest()
            .map_err(|_| AdapterError::ProtocolFailure)?;
        request.request_digest = request
            .digest()
            .map_err(|_| AdapterError::ProtocolFailure)?;
        Ok(request)
    }

    fn selector_attempt() -> CaseAttempt {
        use crate::evaluator::{AttemptArtifact, AttemptTransportCaps};
        use crate::profile::DeterministicBudget;

        let artifact = |bytes: Vec<u8>| AttemptArtifact {
            digest: *blake3::hash(&bytes).as_bytes(),
            bytes,
        };
        CaseAttempt {
            case_id: "case".to_owned(),
            claim_layer: 1,
            family: 1,
            mode: 1,
            fixture_digest: [15; 32],
            schema: artifact(vec![1]),
            payload: artifact(vec![2]),
            auxiliary: Vec::new(),
            budget: DeterministicBudget {
                memory_bytes: 1,
                cpu_fuel: 1,
                host_calls: 1,
                event_count: 1,
                output_bytes: 1024,
                storage_bytes: 1,
                execution_steps: 1,
                simulation_time_ns: 1,
            },
            watchdog_ms: 1_000,
            network_allowed: false,
            capability_ids: vec!["execute".to_owned()],
            transport_caps: AttemptTransportCaps {
                max_member_bytes: 1024,
                max_attempt_bytes: 4096,
            },
        }
    }

    fn local_unavailable() -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let value = ciborium::value::Value::Array(vec![
            ciborium::value::Value::Text("SLE1".to_owned()),
            ciborium::value::Value::Integer(1_u64.into()),
            ciborium::value::Value::Integer(0_u64.into()),
            ciborium::value::Value::Null,
            ciborium::value::Value::Null,
            ciborium::value::Value::Null,
            ciborium::value::Value::Null,
            ciborium::value::Value::Integer(2_u64.into()),
            ciborium::value::Value::Null,
        ]);
        let mut bytes = Vec::new();
        ciborium::into_writer(&value, &mut bytes)?;
        Ok(bytes)
    }

    fn evidence_bearing_reply_marker() -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let fields = vec![
            ciborium::value::Value::Text("SLY1".to_owned()),
            ciborium::value::Value::Integer(1_u64.into()),
            ciborium::value::Value::Null,
            ciborium::value::Value::Null,
            ciborium::value::Value::Null,
            ciborium::value::Value::Null,
            ciborium::value::Value::Null,
            ciborium::value::Value::Null,
            ciborium::value::Value::Bytes(vec![1]),
            ciborium::value::Value::Null,
            ciborium::value::Value::Array(Vec::new()),
            ciborium::value::Value::Null,
        ];
        let value = ciborium::value::Value::Array(vec![
            ciborium::value::Value::Array(fields),
            ciborium::value::Value::Null,
        ]);
        let mut bytes = Vec::new();
        ciborium::into_writer(&value, &mut bytes)?;
        Ok(bytes)
    }

    fn invoke_with_framed_reply(
        declared_length: u32,
        control: Vec<u8>,
        trailing: Vec<u8>,
    ) -> Result<crate::selector_protocol::DecodedSelectorReply, AdapterError> {
        let temporary = tempfile::tempdir().map_err(|_| AdapterError::ProtocolFailure)?;
        let socket = temporary.path().join("selector.sock");
        let listener = UnixListener::bind(&socket).map_err(|_| AdapterError::ProtocolFailure)?;
        std::fs::set_permissions(
            &socket,
            std::fs::Permissions::from_mode(SELECTOR_SOCKET_MODE),
        )
        .map_err(|_| AdapterError::ProtocolFailure)?;
        let uid = std::fs::metadata(&socket)
            .map_err(|_| AdapterError::ProtocolFailure)?
            .uid();
        let server = thread::spawn(move || -> std::io::Result<()> {
            let (mut stream, _) = listener.accept()?;
            let mut request = Vec::new();
            stream.read_to_end(&mut request)?;
            stream.write_all(&declared_length.to_be_bytes())?;
            stream.write_all(&control)?;
            stream.write_all(&trailing)
        });
        let request = selector_request()?;
        let attempt = selector_attempt();
        let encoded = encode_request(&request, b"evr1", &attempt, 0)?;
        let result = SelectorAdapter::invoke_at(&socket, uid, &attempt, &encoded, [14; 32]);
        server
            .join()
            .map_err(|_| AdapterError::ProtocolFailure)?
            .map_err(|_| AdapterError::ProtocolFailure)?;
        result
    }

    fn invoke_with_reply(
        control: Vec<u8>,
        trailing: Vec<u8>,
    ) -> Result<crate::selector_protocol::DecodedSelectorReply, AdapterError> {
        let declared_length =
            u32::try_from(control.len()).map_err(|_| AdapterError::ProtocolFailure)?;
        invoke_with_framed_reply(declared_length, control, trailing)
    }

    #[test]
    fn selector_transport_rejects_missing_wrong_type_mode_and_owner(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let deadline = AttemptDeadline::new(1_000)?;
        let temporary = tempfile::tempdir()?;
        let missing = temporary.path().join("missing.sock");
        assert_eq!(
            connect_at(&missing, 0, &deadline).map(|_| ()),
            Err(SelectorBoundaryError::SelectorUnavailable)
        );

        let regular = temporary.path().join("regular");
        std::fs::write(&regular, b"not a socket")?;
        assert_eq!(
            connect_at(&regular, 0, &deadline).map(|_| ()),
            Err(SelectorBoundaryError::ArtifactInvalid)
        );

        let socket = temporary.path().join("selector.sock");
        let listener = UnixListener::bind(&socket)?;
        let uid = std::fs::metadata(&socket)?.uid();
        assert_eq!(
            connect_at(&socket, uid, &deadline).map(|_| ()),
            Err(SelectorBoundaryError::ArtifactInvalid)
        );
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600))?;
        assert_eq!(
            connect_at(&socket, uid.wrapping_add(1), &deadline).map(|_| ()),
            Err(SelectorBoundaryError::ArtifactInvalid)
        );
        drop(listener);
        assert_eq!(
            connect_at(&socket, uid, &deadline).map(|_| ()),
            Err(SelectorBoundaryError::SelectorUnavailable)
        );
        Ok(())
    }

    #[test]
    fn selector_transport_rejects_endpoint_removal_and_replacement(
    ) -> Result<(), Box<dyn std::error::Error>> {
        for replace in [false, true] {
            let temporary = tempfile::tempdir()?;
            let socket = temporary.path().join("selector.sock");
            let listener = UnixListener::bind(&socket)?;
            std::fs::set_permissions(
                &socket,
                std::fs::Permissions::from_mode(SELECTOR_SOCKET_MODE),
            )?;
            let uid = std::fs::metadata(&socket)?.uid();
            let result = connect_at_with(&socket, uid, |path| {
                let stream = UnixStream::connect(path)?;
                std::fs::remove_file(path)?;
                if replace {
                    let replacement = UnixListener::bind(path)?;
                    drop(replacement);
                }
                Ok(stream)
            });
            let expected = if replace {
                SelectorBoundaryError::ArtifactInvalid
            } else {
                SelectorBoundaryError::SelectorUnavailable
            };
            assert_eq!(result.map(|_| ()), Err(expected));
            drop(listener);
        }
        Ok(())
    }

    #[test]
    fn selector_request_rejects_a_zero_watchdog() -> Result<(), AdapterError> {
        let request = selector_request()?;
        let mut attempt = selector_attempt();
        attempt.watchdog_ms = 0;
        assert_eq!(
            encode_request(&request, b"evr1", &attempt, 0).map(|_| ()),
            Err(AdapterError::ProtocolFailure)
        );
        Ok(())
    }

    #[test]
    fn selector_transport_rejects_a_zero_deadline_before_connect(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let temporary = tempfile::tempdir()?;
        let socket = temporary.path().join("selector.sock");
        let listener = UnixListener::bind(&socket)?;
        std::fs::set_permissions(
            &socket,
            std::fs::Permissions::from_mode(SELECTOR_SOCKET_MODE),
        )?;
        let uid = std::fs::metadata(&socket)?.uid();
        let request = selector_request()?;
        let mut attempt = selector_attempt();
        let encoded = encode_request(&request, b"evr1", &attempt, 0)?;
        attempt.watchdog_ms = 0;
        assert_eq!(
            SelectorAdapter::invoke_at(&socket, uid, &attempt, &encoded, [14; 32]),
            Err(AdapterError::WatchdogExpired)
        );
        drop(listener);
        Ok(())
    }

    #[test]
    fn selector_transport_rejects_a_peer_that_closes_without_a_reply(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let temporary = tempfile::tempdir()?;
        let socket = temporary.path().join("selector.sock");
        let listener = UnixListener::bind(&socket)?;
        std::fs::set_permissions(
            &socket,
            std::fs::Permissions::from_mode(SELECTOR_SOCKET_MODE),
        )?;
        let uid = std::fs::metadata(&socket)?.uid();
        let server = thread::spawn(move || -> std::io::Result<()> {
            let (stream, _) = listener.accept()?;
            drop(stream);
            Ok(())
        });
        let request = selector_request()?;
        let attempt = selector_attempt();
        let encoded = encode_request(&request, b"evr1", &attempt, 0)?;
        assert_eq!(
            SelectorAdapter::invoke_at(&socket, uid, &attempt, &encoded, [14; 32]),
            Err(AdapterError::ProtocolFailure)
        );
        server.join().map_err(|_| AdapterError::ProtocolFailure)??;
        Ok(())
    }

    #[test]
    fn selector_transport_rejects_a_peer_that_never_finishes_its_reply(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let temporary = tempfile::tempdir()?;
        let socket = temporary.path().join("selector.sock");
        let listener = UnixListener::bind(&socket)?;
        std::fs::set_permissions(
            &socket,
            std::fs::Permissions::from_mode(SELECTOR_SOCKET_MODE),
        )?;
        let uid = std::fs::metadata(&socket)?.uid();
        let control = local_unavailable()?;
        let control_length = u32::try_from(control.len())?;
        let server = thread::spawn(move || -> std::io::Result<()> {
            let (mut stream, _) = listener.accept()?;
            let mut request = Vec::new();
            stream.read_to_end(&mut request)?;
            stream.write_all(&control_length.to_be_bytes())?;
            stream.write_all(&control)?;
            thread::sleep(Duration::from_millis(250));
            Ok(())
        });
        let request = selector_request()?;
        let mut attempt = selector_attempt();
        attempt.watchdog_ms = 50;
        let encoded = encode_request(&request, b"evr1", &attempt, 0)?;
        assert_eq!(
            SelectorAdapter::invoke_at(&socket, uid, &attempt, &encoded, [14; 32]),
            Err(AdapterError::WatchdogExpired)
        );
        server.join().map_err(|_| AdapterError::ProtocolFailure)??;
        Ok(())
    }

    #[test]
    fn selector_transport_aborts_after_an_evidence_bearing_reply_stalls(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let temporary = tempfile::tempdir()?;
        let socket = temporary.path().join("selector.sock");
        let listener = UnixListener::bind(&socket)?;
        std::fs::set_permissions(
            &socket,
            std::fs::Permissions::from_mode(SELECTOR_SOCKET_MODE),
        )?;
        let uid = std::fs::metadata(&socket)?.uid();
        let control = evidence_bearing_reply_marker()?;
        let control_length = u32::try_from(control.len())?;
        let server = thread::spawn(move || -> std::io::Result<()> {
            let (mut stream, _) = listener.accept()?;
            let mut request = Vec::new();
            stream.read_to_end(&mut request)?;
            stream.write_all(&control_length.to_be_bytes())?;
            stream.write_all(&control)?;
            thread::sleep(Duration::from_millis(250));
            Ok(())
        });
        let request = selector_request()?;
        let mut attempt = selector_attempt();
        attempt.watchdog_ms = 50;
        let encoded = encode_request(&request, b"evr1", &attempt, 0)?;
        assert_eq!(
            SelectorAdapter::invoke_at(&socket, uid, &attempt, &encoded, [14; 32]),
            Err(AdapterError::AuthenticatedEvidenceFailure)
        );
        server.join().map_err(|_| AdapterError::ProtocolFailure)??;
        Ok(())
    }

    #[test]
    fn selector_watchdog_bounds_a_reply_that_keeps_making_progress(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let temporary = tempfile::tempdir()?;
        let socket = temporary.path().join("selector.sock");
        let listener = UnixListener::bind(&socket)?;
        std::fs::set_permissions(
            &socket,
            std::fs::Permissions::from_mode(SELECTOR_SOCKET_MODE),
        )?;
        let uid = std::fs::metadata(&socket)?.uid();
        let server = thread::spawn(move || -> std::io::Result<()> {
            let (mut stream, _) = listener.accept()?;
            let mut request = Vec::new();
            stream.read_to_end(&mut request)?;
            for byte in 1_u32.to_be_bytes() {
                if stream.write_all(&[byte]).is_err() {
                    break;
                }
                thread::sleep(Duration::from_millis(40));
            }
            Ok(())
        });
        let request = selector_request()?;
        let mut attempt = selector_attempt();
        attempt.watchdog_ms = 100;
        let encoded = encode_request(&request, b"evr1", &attempt, 0)?;
        assert_eq!(
            SelectorAdapter::invoke_at(&socket, uid, &attempt, &encoded, [14; 32]),
            Err(AdapterError::WatchdogExpired)
        );
        server.join().map_err(|_| AdapterError::ProtocolFailure)??;
        Ok(())
    }

    #[test]
    fn selector_watchdog_bounds_a_peer_that_does_not_consume_the_request(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let temporary = tempfile::tempdir()?;
        let socket = temporary.path().join("selector.sock");
        let listener = UnixListener::bind(&socket)?;
        std::fs::set_permissions(
            &socket,
            std::fs::Permissions::from_mode(SELECTOR_SOCKET_MODE),
        )?;
        let uid = std::fs::metadata(&socket)?.uid();
        let server = thread::spawn(move || -> std::io::Result<()> {
            let (stream, _) = listener.accept()?;
            thread::sleep(Duration::from_millis(250));
            drop(stream);
            Ok(())
        });
        let request = selector_request()?;
        let mut attempt = selector_attempt();
        attempt.watchdog_ms = 50;
        attempt.payload.bytes = vec![0; 512 * 1024];
        attempt.payload.digest = *blake3::hash(&attempt.payload.bytes).as_bytes();
        attempt.transport_caps.max_member_bytes = 1024 * 1024;
        attempt.transport_caps.max_attempt_bytes = 2 * 1024 * 1024;
        let encoded = encode_request(&request, b"evr1", &attempt, 0)?;
        assert_eq!(
            SelectorAdapter::invoke_at(&socket, uid, &attempt, &encoded, [14; 32]),
            Err(AdapterError::WatchdogExpired)
        );
        server.join().map_err(|_| AdapterError::ProtocolFailure)??;
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn selector_watchdog_bounds_a_full_listener_accept_queue(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let temporary = tempfile::tempdir()?;
        let socket = temporary.path().join("selector.sock");
        let listener = socket_with(
            AddressFamily::UNIX,
            SocketType::STREAM,
            SocketFlags::CLOEXEC,
            None,
        )?;
        rustix::net::bind(&listener, &SocketAddrUnix::new(&socket)?)?;
        rustix::net::listen(&listener, 0)?;
        std::fs::set_permissions(
            &socket,
            std::fs::Permissions::from_mode(SELECTOR_SOCKET_MODE),
        )?;
        let uid = std::fs::metadata(&socket)?.uid();
        let queued = UnixStream::connect(&socket)?;
        let request = selector_request()?;
        let mut attempt = selector_attempt();
        attempt.watchdog_ms = 25;
        let encoded = encode_request(&request, b"evr1", &attempt, 0)?;
        let started = Instant::now();
        assert_eq!(
            SelectorAdapter::invoke_at(&socket, uid, &attempt, &encoded, [14; 32]),
            Err(AdapterError::WatchdogExpired)
        );
        assert!(started.elapsed() < Duration::from_secs(2));
        drop(queued);
        Ok(())
    }

    #[test]
    fn selector_deadline_bounds_reads_writes_and_flush_after_expiry(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (socket, _peer) = UnixStream::pair()?;
        let mut stream = DeadlineStream {
            stream: socket,
            deadline: AttemptDeadline {
                expires_at: Instant::now(),
            },
        };
        assert_eq!(
            stream
                .read(&mut [0])
                .map_err(|error| transport_error(&error)),
            Err(AdapterError::WatchdogExpired)
        );
        assert_eq!(
            stream
                .write(b"request")
                .map_err(|error| transport_error(&error)),
            Err(AdapterError::WatchdogExpired)
        );
        assert_eq!(
            stream.flush().map_err(|error| transport_error(&error)),
            Err(AdapterError::WatchdogExpired)
        );
        Ok(())
    }

    #[test]
    fn selector_adapter_requires_an_explicit_case_ordinal() -> Result<(), AdapterError> {
        let request = selector_request()?;
        let mut adapter = SelectorAdapter::new(request.clone())?;
        assert_eq!(adapter.kind(), request.subject_adapter);
        assert_eq!(
            adapter.subject_artifact_digest(),
            request.subject_artifact_digest
        );
        assert_eq!(
            adapter.execute(&selector_attempt()),
            Err(AdapterError::ProtocolFailure)
        );
        let mut invalid = selector_attempt();
        invalid.case_id.clear();
        adapter.set_case_ordinal(0);
        assert_eq!(
            adapter.invoke_with_selector(&invalid, Path::new("/missing"), 0),
            Err(AdapterError::ProtocolFailure)
        );
        assert_eq!(adapter.take_execution_provenance_digest(), None);
        let mut invalid_request = request;
        invalid_request.request_id = [0; 16];
        assert_eq!(
            SelectorAdapter::new(invalid_request).map(|_| ()),
            Err(AdapterError::ProtocolFailure)
        );
        Ok(())
    }

    #[test]
    fn selector_transport_exchanges_a_bounded_local_failure(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let reply = invoke_with_reply(local_unavailable()?, Vec::new())?;
        assert_eq!(reply.observation, Err(AdapterError::Unavailable));
        assert_eq!(reply.provenance, None);
        Ok(())
    }

    #[test]
    fn selector_adapter_retains_reply_state_through_the_endpoint_seam(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let temporary = tempfile::tempdir()?;
        let socket = temporary.path().join("selector.sock");
        let listener = UnixListener::bind(&socket)?;
        std::fs::set_permissions(
            &socket,
            std::fs::Permissions::from_mode(SELECTOR_SOCKET_MODE),
        )?;
        let uid = std::fs::metadata(&socket)?.uid();
        let control = local_unavailable()?;
        let control_length = u32::try_from(control.len())?;
        let server = thread::spawn(move || -> std::io::Result<()> {
            let (mut stream, _) = listener.accept()?;
            let mut request = Vec::new();
            stream.read_to_end(&mut request)?;
            stream.write_all(&control_length.to_be_bytes())?;
            stream.write_all(&control)
        });
        let request = selector_request()?;
        let attempt = selector_attempt();
        let mut adapter = SelectorAdapter::new(request)?;
        adapter.set_case_ordinal(7);
        assert_eq!(
            adapter.invoke_with_selector(&attempt, &socket, uid),
            Err(AdapterError::Unavailable)
        );
        assert_eq!(adapter.take_execution_provenance_digest(), None);
        server.join().map_err(|_| AdapterError::ProtocolFailure)??;
        Ok(())
    }

    #[test]
    fn selector_transport_rejects_empty_and_truncated_control(
    ) -> Result<(), Box<dyn std::error::Error>> {
        assert_eq!(
            invoke_with_reply(Vec::new(), Vec::new()),
            Err(AdapterError::ProtocolFailure)
        );
        assert_eq!(
            invoke_with_reply(vec![0xff], Vec::new()),
            Err(AdapterError::ProtocolFailure)
        );
        assert_eq!(
            invoke_with_reply(local_unavailable()?, vec![1]),
            Err(AdapterError::ProtocolFailure)
        );
        assert_eq!(
            invoke_with_reply(
                local_unavailable()?,
                vec![0; usize::try_from(MAX_SELECTOR_TRAILING_BYTES + 1)?],
            ),
            Err(AdapterError::ProtocolFailure)
        );
        assert_eq!(
            invoke_with_framed_reply(1, Vec::new(), Vec::new()),
            Err(AdapterError::ProtocolFailure)
        );
        assert_eq!(
            invoke_with_framed_reply(16 * 1024 * 1024 + 1, Vec::new(), Vec::new()),
            Err(AdapterError::ProtocolFailure)
        );
        Ok(())
    }
}
