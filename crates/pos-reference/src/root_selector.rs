//! Fixed normal-path composition for ADR-069's root-owned selector.
//!
//! This module owns no caller-configurable authority. It opens exactly one
//! SIC1 state, fails closed while SIR1 recovery is pending, and exposes the
//! evaluator listener only after bootstrap authentication, provider admission,
//! and fixed administrative-listener binding complete.

use std::fs::{self, File, Metadata};
use std::io::{ErrorKind, Read, Write};
use std::os::fd::AsFd;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::time::Duration;

use rustix::net::sockopt::socket_peercred;
use rustix::rand::{getrandom, GetRandomFlags};

use crate::provider_transport::{
    AuthenticatedProviderExecution, AuthenticatedProviderTerminal, PostAdmissionProviderFailure,
    ProviderTransport, ProviderTransportError,
};
use crate::sandbox_provider_protocol::{
    AdmittedSandboxImage, ExecuteAuthority, LaunchPolicy, RequestAuthority, SandboxExecuteRequest,
    SandboxLocalError, SandboxLocalErrorCode, SandboxLocalErrorPhase, SandboxProviderOperation,
    SignedImageManifest,
};
use crate::selector::installation::authority::{
    AdmittedSelectorProvider, AuthenticatedSelectorBootstrap,
};
use crate::selector::installation::{
    open_directory_chain, InstallationObjectKind, InstalledSelectorState,
};
use crate::selector::{SelectorBoundaryError, SANDBOX_SELECTOR_SOCKET};
use crate::selector_protocol::{
    decode_request, encode_authenticated_reply, encode_local_error_reply,
    AuthenticatedSelectorReply, DecodedSelectorRequest, EncodedSelectorReply,
    SelectorProviderTerminal,
};

const CONTROL_LIMIT: usize = 16 * 1024 * 1024;
const SELECTOR_INPUT_LIMIT: u64 = 128 * 1024 * 1024;
const CONTROL_ARTIFACT_LIMIT: u64 = 16 * 1024 * 1024;
const IMAGE_ARTIFACT_LIMIT: u64 = 1024 * 1024 * 1024;
const ROOT_UID: u32 = 0;
const SOCKET_MODE: u32 = 0o600;
const INITIAL_IO_TIMEOUT: Duration = Duration::from_secs(30);

fn artifact_invalid<T>(_: T) -> SelectorBoundaryError {
    SelectorBoundaryError::ArtifactInvalid
}

fn selector_unavailable<T>(_: T) -> SelectorBoundaryError {
    SelectorBoundaryError::SelectorUnavailable
}

fn io_error<T>(_: T) -> SelectorBoundaryError {
    SelectorBoundaryError::Io
}

fn unit_error<T>(_: T) {}

/// Run the normal (no pending SIR1) selector composition.
///
/// Pending SIR1 deliberately remains unavailable: `InstalledSelectorState::open`
/// rejects it before any listener can be exposed, until #214 supplies the
/// required lifecycle-backed recovery composition.
pub(crate) fn run_fixed() -> Result<(), SelectorBoundaryError> {
    InstalledSelectorState::open()
        .and_then(InstalledSelectorState::authenticate_bootstrap)
        .and_then(AuthenticatedSelectorBootstrap::admit_provider)
        .and_then(|admitted| {
            ProviderTransport::from_admitted(&admitted).map(|transport| (admitted, transport))
        })
        .and_then(|(admitted, transport)| {
            FixedListener::bind(SANDBOX_SELECTOR_SOCKET)
                .map(|evaluator_listener| fixed_service(admitted, transport, evaluator_listener))
        })
        .and_then(|service| service.serve())
}

const fn fixed_service(
    admitted: AdmittedSelectorProvider,
    transport: ProviderTransport,
    evaluator_listener: FixedListener,
) -> RootSelectorService {
    RootSelectorService {
        admitted,
        transport,
        evaluator_listener,
        peer_uid: ROOT_UID,
    }
}

trait ProviderExecutor {
    fn execute(
        &self,
        admitted: &crate::sandbox_provider_protocol::AdmittedSandboxProvider,
        commitment: &crate::sandbox_provider_protocol::SelectorGrantCommitment,
        spx1: &[u8],
        input: &[u8],
        watchdog: Duration,
    ) -> Result<AuthenticatedProviderTerminal, ProviderTransportError>;
}

impl ProviderExecutor for ProviderTransport {
    fn execute(
        &self,
        admitted: &crate::sandbox_provider_protocol::AdmittedSandboxProvider,
        commitment: &crate::sandbox_provider_protocol::SelectorGrantCommitment,
        spx1: &[u8],
        input: &[u8],
        watchdog: Duration,
    ) -> Result<AuthenticatedProviderTerminal, ProviderTransportError> {
        Self::execute(self, admitted, commitment, spx1, input, watchdog)
    }
}

struct RootSelectorService<T = ProviderTransport> {
    admitted: AdmittedSelectorProvider,
    transport: T,
    evaluator_listener: FixedListener,
    peer_uid: u32,
}

impl<T: ProviderExecutor> RootSelectorService<T> {
    fn serve(&self) -> Result<(), SelectorBoundaryError> {
        loop {
            self.evaluator_listener.verify_continuity()?;
            let Some((stream, _)) = accepted_connection(self.evaluator_listener.listener.accept())?
            else {
                continue;
            };
            match self.handle_connection(stream) {
                Ok(())
                | Err(
                    SelectorBoundaryError::ArtifactInvalid
                    | SelectorBoundaryError::SelectorUnavailable
                    | SelectorBoundaryError::Io,
                ) => {}
            }
        }
    }

    fn handle_connection(&self, mut stream: UnixStream) -> Result<(), SelectorBoundaryError> {
        if !root_peer(&stream, self.peer_uid) {
            return Ok(());
        }
        stream
            .set_read_timeout(Some(INITIAL_IO_TIMEOUT))
            .and_then(|()| stream.set_write_timeout(Some(INITIAL_IO_TIMEOUT)))
            .map_err(io_error)?;
        let Ok((decoded, input)) = read_selector_request(&mut stream) else {
            return write_unidentified_request_error(&mut stream);
        };
        self.handle_decoded_request(&mut stream, &decoded, &input)
    }

    fn handle_decoded_request(
        &self,
        stream: &mut UnixStream,
        decoded: &DecodedSelectorRequest,
        input: &[u8],
    ) -> Result<(), SelectorBoundaryError> {
        let Some(requirement) = decoded.request.sandbox_requirement.as_ref() else {
            return write_policy_error(stream, decoded);
        };
        let ordinal = u16::from_be_bytes([
            decoded.provider_request_id[14],
            decoded.provider_request_id[15],
        ]);
        let resolved = match self
            .admitted
            .bootstrap()
            .resolve_installed_case(&decoded.request, ordinal)
        {
            Ok(resolved) if resolved.attempt() == &decoded.attempt => resolved,
            Ok(_) | Err(_) => return write_authority_mismatch(stream, decoded),
        };
        stream
            .set_read_timeout(Some(Duration::from_millis(resolved.attempt().watchdog_ms)))
            .and_then(|()| {
                stream
                    .set_write_timeout(Some(Duration::from_millis(resolved.attempt().watchdog_ms)))
            })
            .map_err(io_error)?;
        let Ok((image, launch)) = selected_image_and_launch(&self.admitted, requirement) else {
            return write_policy_error(stream, decoded);
        };
        let Ok(commitment) = self.admitted.provider().derive_selector_grant_commitment(
            &image,
            &launch,
            &decoded.request,
            resolved.attempt(),
            &[],
        ) else {
            return write_authority_mismatch(stream, decoded);
        };
        let Ok(spx1) = selector_execute_bytes(&self.admitted, decoded, &resolved, requirement)
        else {
            return write_authority_mismatch(stream, decoded);
        };
        let terminal = match self.transport.execute(
            self.admitted.provider(),
            &commitment,
            &spx1,
            input,
            Duration::from_millis(resolved.attempt().watchdog_ms),
        ) {
            Ok(terminal) => terminal,
            Err(ProviderTransportError::BeforeAdmission) => {
                return write_provider_unavailable(stream, decoded);
            }
            Err(ProviderTransportError::AfterAdmission {
                agr1_digest,
                failure,
            }) => {
                return write_post_admission_provider_failure(
                    stream,
                    decoded,
                    agr1_digest,
                    failure,
                );
            }
        };
        write_provider_terminal(stream, decoded, &spx1, terminal)
    }
}

fn write_provider_terminal(
    stream: &mut UnixStream,
    decoded: &DecodedSelectorRequest,
    spx1: &[u8],
    terminal: AuthenticatedProviderTerminal,
) -> Result<(), SelectorBoundaryError> {
    match terminal {
        AuthenticatedProviderTerminal::Execution(mut execution) => {
            match prepare_authenticated_execution(decoded, spx1, &mut execution) {
                Ok(reply) => write_reply(stream, &reply),
                Err(()) => write_post_admission_provider_failure(
                    stream,
                    decoded,
                    execution.agr1_digest(),
                    PostAdmissionProviderFailure::EvidenceInvalid,
                ),
            }
        }
        AuthenticatedProviderTerminal::Error(error) => {
            write_authenticated_error(stream, decoded, spx1, &error)
        }
    }
}

fn selected_image_and_launch(
    admitted: &AdmittedSelectorProvider,
    requirement: &crate::evaluator_protocol::SandboxRequirement,
) -> Result<(AdmittedSandboxImage, LaunchPolicy), SelectorBoundaryError> {
    let installed = admitted.bootstrap().installed();
    read_installed(
        installed,
        9,
        requirement.sim1_digest,
        CONTROL_ARTIFACT_LIMIT,
    )
    .and_then(|sim1| {
        SignedImageManifest::from_canonical_cbor(&sim1)
            .map_err(artifact_invalid)
            .map(|manifest| (sim1, manifest))
    })
    .and_then(|(sim1, manifest)| {
        read_installed(
            installed,
            12,
            manifest.root_image_blake3_digest,
            IMAGE_ARTIFACT_LIMIT,
        )
        .map(|root_image| (sim1, manifest, root_image))
    })
    .and_then(|(sim1, manifest, root_image)| {
        read_installed(
            installed,
            13,
            manifest.executable_blake3_digest,
            IMAGE_ARTIFACT_LIMIT,
        )
        .map(|executable| (sim1, root_image, executable))
    })
    .and_then(|(sim1, root_image, executable)| {
        admitted
            .provider()
            .admit_image(&sim1, &root_image, &executable)
            .map_err(artifact_invalid)
    })
    .and_then(|image| {
        read_installed(
            installed,
            8,
            requirement.lps1_digest,
            CONTROL_ARTIFACT_LIMIT,
        )
        .map(|lps1| (image, lps1))
    })
    .and_then(|(image, lps1)| {
        admitted
            .provider()
            .admit_launch_policy(&lps1, &image)
            .map(|launch| (image, launch))
            .map_err(artifact_invalid)
    })
}

fn read_installed(
    installed: &InstalledSelectorState,
    kind: u8,
    identity: [u8; 32],
    limit: u64,
) -> Result<Vec<u8>, SelectorBoundaryError> {
    let kind = InstallationObjectKind::from_code(kind).map_err(artifact_invalid)?;
    installed.artifact(kind, identity)?.read_control(limit)
}

fn selector_execute_bytes(
    admitted: &AdmittedSelectorProvider,
    decoded: &DecodedSelectorRequest,
    resolved: &crate::selector::installation::ResolvedInstalledCase,
    requirement: &crate::evaluator_protocol::SandboxRequirement,
) -> Result<Vec<u8>, SelectorBoundaryError> {
    let bootstrap = admitted.bootstrap();
    let provider = admitted.provider();
    let authority = ExecuteAuthority {
        evr1_digest: decoded.request.request_digest,
        cpf1_digest: resolved.profile_digest(),
        cfb1_digest: resolved.bundle_digest(),
        fixture_contract_digest: resolved.fixture_contract_digest(),
        fixture_digest: resolved.attempt().fixture_digest,
        execution_profile_digest: decoded.request.execution_profile_digest,
        lps1_digest: requirement.lps1_digest,
        sim1_digest: requirement.sim1_digest,
        apt1_digest: requirement.apt1_digest,
        trs1_digest: bootstrap.trust().snapshot_digest(),
        rvs1_digest: bootstrap.revocation().snapshot_digest(),
        spm1_digest: provider.manifest().manifest_digest,
        pcf1_digest: provider.manifest().pcf1_digest,
        pcr1_digest: provider.conformance_report().report_digest,
        hcp1_digest: provider.host_profile().profile_digest,
    };
    SandboxExecuteRequest::for_selector(
        RequestAuthority {
            request_id: decoded.provider_request_id,
            apt1_digest: requirement.apt1_digest,
            policy_epoch: requirement.policy_epoch,
            nonce: fresh_nonce()?,
        },
        decoded.attempt_id,
        authority,
        resolved.attempt().capability_ids.clone(),
        decoded.input_descriptor(),
        Vec::new(),
    )
    .and_then(|request| request.to_canonical_cbor())
    .map_err(artifact_invalid)
}

fn fresh_nonce() -> Result<[u8; 16], SelectorBoundaryError> {
    let mut nonce = <[u8; 16]>::default();
    let mut remaining = nonce.as_mut_slice();
    while !remaining.is_empty() {
        let received = getrandom(&mut *remaining, GetRandomFlags::empty())
            .map_err(selector_unavailable)
            .and_then(nonzero_random_count)?;
        remaining = &mut remaining[received..];
    }
    validate_nonce(nonce)
}

fn nonzero_random_count(received: usize) -> Result<usize, SelectorBoundaryError> {
    (received != 0)
        .then_some(received)
        .ok_or(SelectorBoundaryError::SelectorUnavailable)
}

fn validate_nonce(nonce: [u8; 16]) -> Result<[u8; 16], SelectorBoundaryError> {
    (nonce != [0; 16])
        .then_some(nonce)
        .ok_or(SelectorBoundaryError::SelectorUnavailable)
}

fn prepare_authenticated_execution(
    decoded: &DecodedSelectorRequest,
    spx1: &[u8],
    execution: &mut AuthenticatedProviderExecution,
) -> Result<EncodedSelectorReply, ()> {
    let output = execution
        .with_verified_output(|descriptor, reader| {
            usize::try_from(descriptor.byte_length)
                .map_err(artifact_invalid)
                .and_then(|capacity| {
                    let mut bytes = Vec::with_capacity(capacity);
                    reader
                        .take(descriptor.byte_length.saturating_add(1))
                        .read_to_end(&mut bytes)
                        .map_err(io_error)
                        .and({
                            if bytes.len() == capacity {
                                Ok(bytes)
                            } else {
                                Err(SelectorBoundaryError::ArtifactInvalid)
                            }
                        })
                })
        })
        .map_err(unit_error);
    output.and_then(|output| {
        encode_authenticated_reply(
            decoded,
            AuthenticatedSelectorReply {
                execute_request: spx1,
                terminal: SelectorProviderTerminal::Result {
                    result: execution.spy1_bytes(),
                    grant: Some(execution.agr1_bytes()),
                    receipt: Some(execution.spr1_bytes()),
                    audit_records: execution.sau1_frames(),
                    output: output.as_deref(),
                },
            },
        )
        .map_err(unit_error)
    })
}

fn write_authenticated_error(
    stream: &mut UnixStream,
    decoded: &DecodedSelectorRequest,
    spx1: &[u8],
    error: &[u8],
) -> Result<(), SelectorBoundaryError> {
    encode_authenticated_reply(
        decoded,
        AuthenticatedSelectorReply {
            execute_request: spx1,
            terminal: SelectorProviderTerminal::Error { error },
        },
    )
    .map_err(artifact_invalid)
    .and_then(|reply| write_reply(stream, &reply))
}

fn write_unidentified_request_error(stream: &mut UnixStream) -> Result<(), SelectorBoundaryError> {
    write_local_error(
        stream,
        &SandboxLocalError {
            phase: SandboxLocalErrorPhase::BeforeSpx1,
            operation: None,
            request_id: None,
            attempt_id: None,
            agr1_digest: None,
            code: SandboxLocalErrorCode::InvalidSelectorRequest,
            safe_detail: None,
        },
    )
}

fn write_policy_error(
    stream: &mut UnixStream,
    decoded: &DecodedSelectorRequest,
) -> Result<(), SelectorBoundaryError> {
    write_local_error(
        stream,
        &SandboxLocalError {
            phase: SandboxLocalErrorPhase::BeforeSpx1,
            operation: Some(SandboxProviderOperation::Execute),
            request_id: Some(decoded.provider_request_id),
            attempt_id: None,
            agr1_digest: None,
            code: SandboxLocalErrorCode::PolicyUnavailable,
            safe_detail: None,
        },
    )
}

fn write_authority_mismatch(
    stream: &mut UnixStream,
    decoded: &DecodedSelectorRequest,
) -> Result<(), SelectorBoundaryError> {
    write_local_error(
        stream,
        &SandboxLocalError {
            phase: SandboxLocalErrorPhase::BeforeSpx1,
            operation: Some(SandboxProviderOperation::Execute),
            request_id: Some(decoded.provider_request_id),
            attempt_id: Some(decoded.attempt_id),
            agr1_digest: None,
            code: SandboxLocalErrorCode::RequestAuthorityMismatch,
            safe_detail: None,
        },
    )
}

fn write_provider_unavailable(
    stream: &mut UnixStream,
    decoded: &DecodedSelectorRequest,
) -> Result<(), SelectorBoundaryError> {
    write_local_error(
        stream,
        &SandboxLocalError {
            phase: SandboxLocalErrorPhase::AfterSpx1BeforeAdmission,
            operation: Some(SandboxProviderOperation::Execute),
            request_id: Some(decoded.provider_request_id),
            attempt_id: Some(decoded.attempt_id),
            agr1_digest: None,
            code: SandboxLocalErrorCode::ProviderUnavailable,
            safe_detail: None,
        },
    )
}

fn write_post_admission_provider_failure(
    stream: &mut UnixStream,
    decoded: &DecodedSelectorRequest,
    agr1_digest: [u8; 32],
    failure: PostAdmissionProviderFailure,
) -> Result<(), SelectorBoundaryError> {
    let code = match failure {
        PostAdmissionProviderFailure::TerminalUnavailable => {
            SandboxLocalErrorCode::ProviderTerminalUnavailable
        }
        PostAdmissionProviderFailure::EvidenceInvalid => {
            SandboxLocalErrorCode::ProviderEvidenceInvalid
        }
    };
    let error = post_admission_provider_error(
        decoded.provider_request_id,
        decoded.attempt_id,
        agr1_digest,
        code,
    );
    write_local_error(stream, &error)
}

const fn post_admission_provider_error(
    request_id: [u8; 16],
    attempt_id: [u8; 16],
    agr1_digest: [u8; 32],
    code: SandboxLocalErrorCode,
) -> SandboxLocalError {
    SandboxLocalError {
        phase: SandboxLocalErrorPhase::AfterAdmission,
        operation: Some(SandboxProviderOperation::Execute),
        request_id: Some(request_id),
        attempt_id: Some(attempt_id),
        agr1_digest: Some(agr1_digest),
        code,
        safe_detail: None,
    }
}

fn write_local_error(
    stream: &mut UnixStream,
    error: &SandboxLocalError,
) -> Result<(), SelectorBoundaryError> {
    encode_local_error_reply(error)
        .map_err(artifact_invalid)
        .and_then(|reply| write_reply(stream, &reply))
}

fn write_reply(
    stream: &mut UnixStream,
    reply: &EncodedSelectorReply,
) -> Result<(), SelectorBoundaryError> {
    u32::try_from(reply.control.len())
        .map_err(io_error)
        .and_then(|length| {
            stream
                .write_all(&length.to_be_bytes())
                .and_then(|()| stream.write_all(&reply.control))
                .and_then(|()| stream.write_all(&reply.trailing))
                .map_err(io_error)
        })
}

fn read_selector_request(stream: &mut UnixStream) -> Result<(DecodedSelectorRequest, Vec<u8>), ()> {
    let mut prefix = [0_u8; 4];
    stream.read_exact(&mut prefix).map_err(unit_error)?;
    let length = usize::try_from(u32::from_be_bytes(prefix)).map_err(unit_error)?;
    if length == 0 || length > CONTROL_LIMIT {
        return Err(());
    }
    let mut control = vec![0_u8; length];
    stream.read_exact(&mut control).map_err(unit_error)?;
    let mut input = Vec::new();
    (&mut *stream)
        .take(SELECTOR_INPUT_LIMIT.saturating_add(1))
        .read_to_end(&mut input)
        .map_err(unit_error)?;
    validate_selector_input_length(input.len())?;
    decode_request(&control, &input)
        .map(|decoded| (decoded, input))
        .map_err(unit_error)
}

fn validate_selector_input_length(length: usize) -> Result<(), ()> {
    u64::try_from(length)
        .map_err(unit_error)
        .and_then(|length| (length <= SELECTOR_INPUT_LIMIT).then_some(()).ok_or(()))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ListenerAcceptAction {
    Retry,
    Backoff,
    Fail,
}

fn listener_accept_action(error: &std::io::Error) -> ListenerAcceptAction {
    if matches!(
        error.kind(),
        ErrorKind::Interrupted | ErrorKind::ConnectionAborted
    ) {
        ListenerAcceptAction::Retry
    } else if [Some(libc::EMFILE), Some(libc::ENFILE)].contains(&error.raw_os_error()) {
        ListenerAcceptAction::Backoff
    } else {
        ListenerAcceptAction::Fail
    }
}

fn accepted_connection<T>(result: std::io::Result<T>) -> Result<Option<T>, SelectorBoundaryError> {
    match result {
        Ok(connection) => Ok(Some(connection)),
        Err(error) => match listener_accept_action(&error) {
            ListenerAcceptAction::Retry => Ok(None),
            ListenerAcceptAction::Backoff => {
                std::thread::sleep(Duration::from_millis(100));
                Ok(None)
            }
            ListenerAcceptAction::Fail => Err(SelectorBoundaryError::Io),
        },
    }
}

fn root_peer(stream: &UnixStream, expected_uid: u32) -> bool {
    socket_peercred(stream.as_fd())
        .is_ok_and(|credentials| credentials.uid.as_raw() == expected_uid)
}

struct FixedListener {
    listener: UnixListener,
    parent: File,
    parent_device: u64,
    parent_inode: u64,
    socket_device: u64,
    socket_inode: u64,
    path: PathBuf,
    owner: u32,
}

impl FixedListener {
    fn bind(path: impl AsRef<Path>) -> Result<Self, SelectorBoundaryError> {
        Self::bind_owned(path, ROOT_UID)
    }

    fn bind_owned(path: impl AsRef<Path>, owner: u32) -> Result<Self, SelectorBoundaryError> {
        let path = path.as_ref();
        let parent_path = path
            .parent()
            .ok_or(SelectorBoundaryError::ArtifactInvalid)?;
        let relative = parent_path.strip_prefix("/").map_err(artifact_invalid)?;
        let root = File::open("/").map_err(io_error)?;
        Self::bind_beneath(path, root, relative, owner)
    }

    fn bind_beneath(
        path: &Path,
        root: File,
        relative_parent: &Path,
        owner: u32,
    ) -> Result<Self, SelectorBoundaryError> {
        let parent = open_directory_chain(root, relative_parent, owner)?;
        let parent_metadata = parent.metadata().map_err(io_error)?;
        let listener = UnixListener::bind(path).map_err(selector_unavailable)?;
        fs::set_permissions(path, fs::Permissions::from_mode(SOCKET_MODE)).map_err(io_error)?;
        let socket_metadata = fs::symlink_metadata(path).map_err(io_error)?;
        validate_listener_leaf(&socket_metadata, owner)?;
        Ok(Self {
            listener,
            parent,
            parent_device: parent_metadata.dev(),
            parent_inode: parent_metadata.ino(),
            socket_device: socket_metadata.dev(),
            socket_inode: socket_metadata.ino(),
            path: path.to_owned(),
            owner,
        })
    }

    fn verify_continuity(&self) -> Result<(), SelectorBoundaryError> {
        let parent = self.parent.metadata().map_err(io_error)?;
        if parent.dev() != self.parent_device
            || parent.ino() != self.parent_inode
            || !parent.is_dir()
            || parent.uid() != self.owner
            || parent.mode() & 0o022 != 0
        {
            return Err(SelectorBoundaryError::ArtifactInvalid);
        }
        let leaf = fs::symlink_metadata(&self.path).map_err(io_error)?;
        validate_listener_leaf(&leaf, self.owner)?;
        if leaf.dev() != self.socket_device || leaf.ino() != self.socket_inode {
            return Err(SelectorBoundaryError::ArtifactInvalid);
        }
        Ok(())
    }
}

fn validate_listener_leaf(metadata: &Metadata, owner: u32) -> Result<(), SelectorBoundaryError> {
    if !metadata.file_type().is_socket()
        || metadata.uid() != owner
        || metadata.mode() & 0o777 != SOCKET_MODE
    {
        Err(SelectorBoundaryError::ArtifactInvalid)
    } else {
        Ok(())
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use std::cell::RefCell;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::os::unix::net::UnixListener;

    use super::*;

    type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

    #[test]
    fn closed_helpers_cover_error_mapping_randomness_and_input_bounds() -> TestResult {
        assert_eq!(artifact_invalid(()), SelectorBoundaryError::ArtifactInvalid);
        assert_eq!(
            selector_unavailable(()),
            SelectorBoundaryError::SelectorUnavailable
        );
        assert_eq!(io_error(()), SelectorBoundaryError::Io);
        unit_error(());
        assert_eq!(
            nonzero_random_count(0),
            Err(SelectorBoundaryError::SelectorUnavailable)
        );
        assert_eq!(nonzero_random_count(1), Ok(1));
        assert_eq!(
            validate_nonce(<[u8; 16]>::default()),
            Err(SelectorBoundaryError::SelectorUnavailable)
        );
        let nonzero = std::array::from_fn(|_| 1);
        assert_eq!(validate_nonce(nonzero), Ok(nonzero));
        assert_eq!(validate_selector_input_length(0), Ok(()));
        assert_eq!(
            validate_selector_input_length(usize::try_from(SELECTOR_INPUT_LIMIT)? + 1),
            Err(())
        );
        assert_eq!(
            FixedListener::bind("relative.sock").err(),
            Some(SelectorBoundaryError::ArtifactInvalid)
        );
        Ok(())
    }

    struct FixedProviderExecutor(
        RefCell<Option<Result<AuthenticatedProviderTerminal, ProviderTransportError>>>,
    );

    impl ProviderExecutor for FixedProviderExecutor {
        fn execute(
            &self,
            _admitted: &crate::sandbox_provider_protocol::AdmittedSandboxProvider,
            _commitment: &crate::sandbox_provider_protocol::SelectorGrantCommitment,
            _spx1: &[u8],
            _input: &[u8],
            _watchdog: Duration,
        ) -> Result<AuthenticatedProviderTerminal, ProviderTransportError> {
            self.0
                .borrow_mut()
                .take()
                .ok_or(ProviderTransportError::BeforeAdmission)?
        }
    }

    #[test]
    fn listener_accept_retries_only_transient_connection_errors() {
        for kind in [ErrorKind::Interrupted, ErrorKind::ConnectionAborted] {
            let error = std::io::Error::from(kind);
            assert_eq!(listener_accept_action(&error), ListenerAcceptAction::Retry);
            assert_eq!(accepted_connection::<()>(Err(error)), Ok(None));
        }
        for error in [
            std::io::Error::from_raw_os_error(rustix::io::Errno::MFILE.raw_os_error()),
            std::io::Error::from_raw_os_error(rustix::io::Errno::NFILE.raw_os_error()),
        ] {
            assert_eq!(
                listener_accept_action(&error),
                ListenerAcceptAction::Backoff
            );
            assert_eq!(accepted_connection::<()>(Err(error)), Ok(None));
        }
        let fatal = std::io::Error::from(ErrorKind::ConnectionReset);
        assert_eq!(listener_accept_action(&fatal), ListenerAcceptAction::Fail);
        assert_eq!(
            accepted_connection::<()>(Err(fatal)),
            Err(SelectorBoundaryError::Io)
        );
        assert_eq!(accepted_connection(Ok(7)), Ok(Some(7)));
    }

    #[test]
    fn fixed_process_composition_and_listener_loop_fail_closed_without_host_state() -> TestResult {
        assert!(run_fixed().is_err());
        assert!(crate::run_fixed_root_selector().is_err());

        let (_, admitted, _) = crate::selector::installation::tests::root_selector_fixture()?;
        assert!(ProviderTransport::from_admitted(&admitted).is_err());
        let provider_directory = tempfile::tempdir()?;
        let provider_path = provider_directory.path().join("provider.sock");
        let _provider_listener = UnixListener::bind(&provider_path)?;
        let evaluator_directory = tempfile::tempdir()?;
        let mut service = fixed_service(
            admitted,
            ProviderTransport::from_path_for_test(&provider_path)?,
            fixed_listener(&evaluator_directory, "evaluator.sock")?,
        );
        service.peer_uid = fs::metadata(".")?.uid();
        let mut client = UnixStream::connect(&service.evaluator_listener.path)?;
        client.shutdown(std::net::Shutdown::Write)?;
        service.evaluator_listener.listener.set_nonblocking(true)?;
        assert_eq!(service.serve(), Err(SelectorBoundaryError::Io));
        assert_eq!(
            read_local_error(&mut client)?.code,
            SandboxLocalErrorCode::InvalidSelectorRequest
        );
        Ok(())
    }

    #[test]
    fn listener_leaf_requires_an_exact_owner_only_socket_mode(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("selector.sock");
        let listener = UnixListener::bind(&path)?;
        let owner = fs::symlink_metadata(&path)?.uid();
        fs::set_permissions(&path, fs::Permissions::from_mode(SOCKET_MODE))?;
        assert!(validate_listener_leaf(&fs::symlink_metadata(&path)?, owner).is_ok());
        assert!(validate_listener_leaf(&fs::metadata(directory.path())?, owner).is_err());
        assert!(validate_listener_leaf(&fs::symlink_metadata(&path)?, owner ^ 1).is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o620))?;
        assert!(validate_listener_leaf(&fs::symlink_metadata(&path)?, owner).is_err());
        drop(listener);
        Ok(())
    }

    #[test]
    fn listener_binding_and_request_reader_cover_the_normal_socket_boundary() -> TestResult {
        let directory = tempfile::tempdir()?;
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
        let owner = fs::metadata(directory.path())?.uid();
        let path = directory.path().join("selector.sock");
        let listener = FixedListener::bind_beneath(
            &path,
            File::open(directory.path())?,
            Path::new(""),
            owner,
        )?;
        assert!(listener.verify_continuity().is_ok());
        assert_eq!(
            fs::symlink_metadata(&listener.path)?.mode() & 0o777,
            SOCKET_MODE
        );
        assert_eq!(
            FixedListener::bind_owned("relative.sock", owner).err(),
            Some(SelectorBoundaryError::ArtifactInvalid)
        );

        let (request, _, resolved) = crate::selector::installation::tests::root_selector_fixture()?;
        let encoded = encoded_request(&request, resolved.attempt())?;
        let (mut client, mut server) = UnixStream::pair()?;
        client.write_all(&u32::try_from(encoded.control.len())?.to_be_bytes())?;
        client.write_all(&encoded.control)?;
        client.write_all(&encoded.attempt_stream)?;
        client.shutdown(std::net::Shutdown::Write)?;
        let (decoded, input) = read_selector_request(&mut server).map_err(|()| "read failed")?;
        assert_eq!(decoded.request.request_digest, request.request_digest);
        assert_eq!(input, encoded.attempt_stream);
        Ok(())
    }

    #[test]
    fn post_admission_provider_failures_retain_the_authenticated_grant(
    ) -> Result<(), crate::evaluator::AdapterError> {
        for code in [
            SandboxLocalErrorCode::ProviderTerminalUnavailable,
            SandboxLocalErrorCode::ProviderEvidenceInvalid,
        ] {
            let error = post_admission_provider_error([1; 16], [2; 16], [3; 32], code);
            assert_eq!(error.phase, SandboxLocalErrorPhase::AfterAdmission);
            assert_eq!(error.operation, Some(SandboxProviderOperation::Execute));
            assert_eq!(error.request_id, Some([1; 16]));
            assert_eq!(error.attempt_id, Some([2; 16]));
            assert_eq!(error.agr1_digest, Some([3; 32]));
            assert_eq!(error.code, code);
            let encoded = encode_local_error_reply(&error)?;
            assert!(encoded.trailing.is_empty());
            assert_eq!(
                SandboxLocalError::from_canonical_cbor(&encoded.control)
                    .map_err(|_| crate::evaluator::AdapterError::ProtocolFailure)?,
                error
            );
        }
        Ok(())
    }

    #[test]
    fn selector_execute_request_binds_every_root_owned_authority() -> TestResult {
        let (request, admitted, resolved) =
            crate::selector::installation::tests::root_selector_fixture()?;
        let requirement = request
            .sandbox_requirement
            .as_ref()
            .ok_or("sandbox requirement missing")?;
        let encoded = encoded_request(&request, resolved.attempt())?;
        let decoded = decode_request(&encoded.control, &encoded.attempt_stream)
            .map_err(|error| format!("selector request decode failed: {error:?}"))?;
        let bytes = selector_execute_bytes(&admitted, &decoded, &resolved, requirement)?;
        let execute = SandboxExecuteRequest::from_canonical_cbor(&bytes)?;

        assert_eq!(execute.request.request_id, decoded.provider_request_id);
        assert_eq!(execute.request.apt1_digest, requirement.apt1_digest);
        assert_eq!(execute.request.policy_epoch, requirement.policy_epoch);
        assert_ne!(execute.request.nonce, [0; 16]);
        assert_eq!(execute.attempt_id, decoded.attempt_id);
        assert_eq!(execute.authority.evr1_digest, request.request_digest);
        assert_eq!(execute.authority.cpf1_digest, resolved.profile_digest());
        assert_eq!(execute.authority.cfb1_digest, resolved.bundle_digest());
        assert_eq!(
            execute.authority.fixture_contract_digest,
            resolved.fixture_contract_digest()
        );
        assert_eq!(
            execute.authority.fixture_digest,
            resolved.attempt().fixture_digest
        );
        assert_eq!(
            execute.authority.execution_profile_digest,
            request.execution_profile_digest
        );
        assert_eq!(execute.capability_ids, resolved.attempt().capability_ids);
        assert_eq!(execute.adapter_input, decoded.input_descriptor());
        let selected = selected_image_and_launch(&admitted, requirement)?;
        assert_eq!(
            selected.0.manifest().manifest_digest,
            requirement.sim1_digest
        );
        assert!(read_installed(admitted.bootstrap().installed(), u8::MAX, [0; 32], 1).is_err());
        assert_ne!(fresh_nonce()?, [0; 16]);

        let mut missing_image = requirement.clone();
        missing_image.sim1_digest = [0; 32];
        assert!(selected_image_and_launch(&admitted, &missing_image).is_err());
        let mut missing_policy = requirement.clone();
        missing_policy.lps1_digest = [0; 32];
        assert!(selected_image_and_launch(&admitted, &missing_policy).is_err());
        Ok(())
    }

    #[test]
    fn selector_service_returns_closed_errors_before_provider_execution() -> TestResult {
        let (request, admitted, resolved) =
            crate::selector::installation::tests::root_selector_fixture()?;
        let provider_directory = tempfile::tempdir()?;
        let provider_path = provider_directory.path().join("provider.sock");
        let provider_listener = UnixListener::bind(&provider_path)?;
        let transport = ProviderTransport::from_path_for_test(&provider_path)?;
        let evaluator_directory = tempfile::tempdir()?;
        let service = RootSelectorService {
            admitted,
            transport,
            evaluator_listener: fixed_listener(&evaluator_directory, "evaluator.sock")?,
            peer_uid: fs::metadata(".")?.uid(),
        };

        let mut without_requirement = request.clone();
        without_requirement.sandbox_requirement = None;
        refresh_request_digest(&mut without_requirement)?;
        assert_service_error(
            &service,
            &without_requirement,
            resolved.attempt(),
            SandboxLocalErrorCode::PolicyUnavailable,
        )?;

        let mut foreign_attempt = resolved.attempt().clone();
        foreign_attempt.case_id = "foreign-case".to_owned();
        assert_service_error(
            &service,
            &request,
            &foreign_attempt,
            SandboxLocalErrorCode::RequestAuthorityMismatch,
        )?;

        let mut missing_image = request.clone();
        missing_image
            .sandbox_requirement
            .as_mut()
            .ok_or("sandbox requirement missing")?
            .sim1_digest = [99; 32];
        refresh_request_digest(&mut missing_image)?;
        assert_service_error(
            &service,
            &missing_image,
            resolved.attempt(),
            SandboxLocalErrorCode::PolicyUnavailable,
        )?;

        let mut foreign_capability = request.clone();
        foreign_capability
            .sandbox_requirement
            .as_mut()
            .ok_or("sandbox requirement missing")?
            .required_provider_capability
            .capability_id = "foreign-capability".to_owned();
        refresh_request_digest(&mut foreign_capability)?;
        assert_service_error(
            &service,
            &foreign_capability,
            resolved.attempt(),
            SandboxLocalErrorCode::RequestAuthorityMismatch,
        )?;

        drop(provider_listener);
        assert_service_error(
            &service,
            &request,
            resolved.attempt(),
            SandboxLocalErrorCode::ProviderUnavailable,
        )?;
        Ok(())
    }

    #[test]
    fn selector_service_maps_each_provider_transport_failure_class() -> TestResult {
        let cases: [(
            Result<AuthenticatedProviderTerminal, ProviderTransportError>,
            SandboxLocalErrorCode,
        ); 3] = [
            (
                Err(ProviderTransportError::BeforeAdmission),
                SandboxLocalErrorCode::ProviderUnavailable,
            ),
            (
                Err(ProviderTransportError::AfterAdmission {
                    agr1_digest: [91; 32],
                    failure: PostAdmissionProviderFailure::TerminalUnavailable,
                }),
                SandboxLocalErrorCode::ProviderTerminalUnavailable,
            ),
            (
                Err(ProviderTransportError::AfterAdmission {
                    agr1_digest: [92; 32],
                    failure: PostAdmissionProviderFailure::EvidenceInvalid,
                }),
                SandboxLocalErrorCode::ProviderEvidenceInvalid,
            ),
        ];
        for (result, expected) in cases {
            let (request, admitted, resolved) =
                crate::selector::installation::tests::root_selector_fixture()?;
            let evaluator_directory = tempfile::tempdir()?;
            let service = RootSelectorService {
                admitted,
                transport: FixedProviderExecutor(RefCell::new(Some(result))),
                evaluator_listener: fixed_listener(&evaluator_directory, "evaluator.sock")?,
                peer_uid: fs::metadata(".")?.uid(),
            };
            assert_service_error(&service, &request, resolved.attempt(), expected)?;
        }
        Ok(())
    }

    #[test]
    fn selector_service_closes_an_invalid_authenticated_execution() -> TestResult {
        let (request, admitted, resolved) =
            crate::selector::installation::tests::root_selector_fixture()?;
        let fixture = crate::selector_transport_test_fixture::authenticated_transport_fixture()?;
        let execution = AuthenticatedProviderExecution::from_test_frames(
            fixture.agr1,
            fixture.spr1,
            fixture.spy1,
            fixture.sau1,
            None,
        );
        let evaluator_directory = tempfile::tempdir()?;
        let service = RootSelectorService {
            admitted,
            transport: FixedProviderExecutor(RefCell::new(Some(Ok(
                AuthenticatedProviderTerminal::Execution(execution),
            )))),
            evaluator_listener: fixed_listener(&evaluator_directory, "evaluator.sock")?,
            peer_uid: fs::metadata(".")?.uid(),
        };
        assert_service_error(
            &service,
            &request,
            resolved.attempt(),
            SandboxLocalErrorCode::ProviderEvidenceInvalid,
        )?;
        Ok(())
    }

    #[test]
    fn selector_service_writes_an_authenticated_provider_error() -> TestResult {
        let (request, admitted, resolved) =
            crate::selector::installation::tests::root_selector_fixture()?;
        let fixture = crate::selector_transport_test_fixture::authenticated_transport_fixture()?;
        let evaluator_directory = tempfile::tempdir()?;
        let service = RootSelectorService {
            admitted,
            transport: FixedProviderExecutor(RefCell::new(Some(Ok(
                AuthenticatedProviderTerminal::Error(fixture.spe1),
            )))),
            evaluator_listener: fixed_listener(&evaluator_directory, "evaluator.sock")?,
            peer_uid: fs::metadata(".")?.uid(),
        };
        let encoded = encoded_request(&request, resolved.attempt())?;
        let (mut client, server) = UnixStream::pair()?;
        client.write_all(&u32::try_from(encoded.control.len())?.to_be_bytes())?;
        client.write_all(&encoded.control)?;
        client.write_all(&encoded.attempt_stream)?;
        client.shutdown(std::net::Shutdown::Write)?;
        service.handle_connection(server)?;
        let mut prefix = [0; 4];
        client.read_exact(&mut prefix)?;
        let mut control = vec![0; usize::try_from(u32::from_be_bytes(prefix))?];
        client.read_exact(&mut control)?;
        assert!(!control.is_empty());
        Ok(())
    }

    #[test]
    fn selector_service_closes_unidentified_and_foreign_peer_connections() -> TestResult {
        let (_, admitted, _) = crate::selector::installation::tests::root_selector_fixture()?;
        let provider_directory = tempfile::tempdir()?;
        let provider_path = provider_directory.path().join("provider.sock");
        let _provider_listener = UnixListener::bind(&provider_path)?;
        let evaluator_directory = tempfile::tempdir()?;
        let owner = fs::metadata(".")?.uid();
        let mut service = RootSelectorService {
            admitted,
            transport: ProviderTransport::from_path_for_test(&provider_path)?,
            evaluator_listener: fixed_listener(&evaluator_directory, "evaluator.sock")?,
            peer_uid: owner ^ 1,
        };

        let (client, server) = UnixStream::pair()?;
        service.handle_connection(server)?;
        drop(client);

        service.peer_uid = owner;
        let (mut client, server) = UnixStream::pair()?;
        client.shutdown(std::net::Shutdown::Write)?;
        service.handle_connection(server)?;
        assert_eq!(
            read_local_error(&mut client)?.code,
            SandboxLocalErrorCode::InvalidSelectorRequest
        );
        Ok(())
    }

    #[test]
    fn authenticated_terminal_writers_preserve_result_error_and_output() -> TestResult {
        let fixture = crate::selector_transport_test_fixture::authenticated_transport_fixture()?;
        let (request, _, resolved) = crate::selector::installation::tests::root_selector_fixture()?;
        let transport_request = SandboxExecuteRequest::from_canonical_cbor(&fixture.spx1)?;
        let decoded = crate::selector_protocol::decoded_request_for_execute_test(
            request,
            resolved.attempt().clone(),
            &transport_request,
        );
        let mut file = tempfile::NamedTempFile::new()?;
        file.write_all(b"output")?;
        let descriptor = crate::sandbox_provider_protocol::PayloadDescriptor {
            byte_length: 6,
            digest: [0; 32],
        };
        let mut execution = AuthenticatedProviderExecution::from_test_frames(
            fixture.agr1.clone(),
            fixture.spr1.clone(),
            fixture.spy1.clone(),
            fixture.sau1.clone(),
            Some((file, descriptor)),
        );
        let reply = prepare_authenticated_execution(&decoded, &fixture.spx1, &mut execution)
            .map_err(|()| "authenticated result composition failed")?;
        assert!(!reply.control.is_empty());
        assert_eq!(reply.trailing, b"output");

        let mut staged = tempfile::NamedTempFile::new()?;
        staged.write_all(b"output")?;
        let complete = AuthenticatedProviderExecution::from_test_frames(
            fixture.agr1.clone(),
            fixture.spr1.clone(),
            fixture.spy1.clone(),
            fixture.sau1.clone(),
            Some((
                staged,
                crate::sandbox_provider_protocol::PayloadDescriptor {
                    byte_length: 6,
                    digest: [0; 32],
                },
            )),
        );
        let (mut reply_reader, mut reply_writer) = UnixStream::pair()?;
        write_provider_terminal(
            &mut reply_writer,
            &decoded,
            &fixture.spx1,
            AuthenticatedProviderTerminal::Execution(complete),
        )?;
        let mut length = [0; 4];
        reply_reader.read_exact(&mut length)?;
        assert_ne!(u32::from_be_bytes(length), 0);

        let (mut reply_reader, mut reply_writer) = UnixStream::pair()?;
        write_provider_terminal(
            &mut reply_writer,
            &decoded,
            &fixture.spx1,
            AuthenticatedProviderTerminal::Error(fixture.spe1.clone()),
        )?;
        reply_reader.read_exact(&mut length)?;
        assert_ne!(u32::from_be_bytes(length), 0);

        let mut short_execution = AuthenticatedProviderExecution::from_test_frames(
            fixture.agr1.clone(),
            fixture.spr1.clone(),
            fixture.spy1.clone(),
            fixture.sau1.clone(),
            Some((
                tempfile::NamedTempFile::new()?,
                crate::sandbox_provider_protocol::PayloadDescriptor {
                    byte_length: 1,
                    digest: [0; 32],
                },
            )),
        );
        assert!(
            prepare_authenticated_execution(&decoded, &fixture.spx1, &mut short_execution).is_err()
        );

        let mut no_output = AuthenticatedProviderExecution::from_test_frames(
            fixture.agr1,
            fixture.spr1,
            fixture.spy1,
            fixture.sau1,
            None,
        );
        assert!(prepare_authenticated_execution(&decoded, &fixture.spx1, &mut no_output).is_err());

        let (mut root, _) = UnixStream::pair()?;
        assert!(
            write_authenticated_error(&mut root, &decoded, &fixture.spx1, b"unsigned error")
                .is_err()
        );
        let (mut root, mut client) = UnixStream::pair()?;
        write_authenticated_error(&mut root, &decoded, &fixture.spx1, &fixture.spe1)?;
        let mut prefix = [0; 4];
        client.read_exact(&mut prefix)?;
        let mut control = vec![0; usize::try_from(u32::from_be_bytes(prefix))?];
        client.read_exact(&mut control)?;
        assert!(!control.is_empty());
        Ok(())
    }

    #[test]
    fn local_error_writers_preserve_each_failure_phase() -> TestResult {
        let (request, _, resolved) = crate::selector::installation::tests::root_selector_fixture()?;
        let encoded = encoded_request(&request, resolved.attempt())?;
        let decoded = decode_request(&encoded.control, &encoded.attempt_stream)
            .map_err(|error| format!("selector request decode failed: {error:?}"))?;

        assert_written_error(
            write_unidentified_request_error,
            SandboxLocalErrorCode::InvalidSelectorRequest,
        )?;
        assert_written_error(
            |stream| write_policy_error(stream, &decoded),
            SandboxLocalErrorCode::PolicyUnavailable,
        )?;
        assert_written_error(
            |stream| write_authority_mismatch(stream, &decoded),
            SandboxLocalErrorCode::RequestAuthorityMismatch,
        )?;
        assert_written_error(
            |stream| write_provider_unavailable(stream, &decoded),
            SandboxLocalErrorCode::ProviderUnavailable,
        )?;
        for (failure, code) in [
            (
                PostAdmissionProviderFailure::TerminalUnavailable,
                SandboxLocalErrorCode::ProviderTerminalUnavailable,
            ),
            (
                PostAdmissionProviderFailure::EvidenceInvalid,
                SandboxLocalErrorCode::ProviderEvidenceInvalid,
            ),
        ] {
            assert_written_error(
                |stream| write_post_admission_provider_failure(stream, &decoded, [91; 32], failure),
                code,
            )?;
        }
        Ok(())
    }

    #[test]
    fn selector_request_reader_rejects_invalid_frame_boundaries() -> TestResult {
        for prefix in [0_u32, u32::try_from(CONTROL_LIMIT)? + 1] {
            let (mut client, mut server) = UnixStream::pair()?;
            client.write_all(&prefix.to_be_bytes())?;
            client.shutdown(std::net::Shutdown::Write)?;
            assert!(read_selector_request(&mut server).is_err());
        }
        let (mut client, mut server) = UnixStream::pair()?;
        client.write_all(&4_u32.to_be_bytes())?;
        client.write_all(&[1, 2])?;
        client.shutdown(std::net::Shutdown::Write)?;
        assert!(read_selector_request(&mut server).is_err());

        let (mut client, mut server) = UnixStream::pair()?;
        client.write_all(&1_u32.to_be_bytes())?;
        client.write_all(&[0xff])?;
        client.shutdown(std::net::Shutdown::Write)?;
        assert!(read_selector_request(&mut server).is_err());
        Ok(())
    }

    #[test]
    fn peer_identity_uses_the_explicit_service_owner() -> TestResult {
        let (peer, _) = UnixStream::pair()?;
        let owner = fs::metadata(".")?.uid();
        assert!(root_peer(&peer, owner));
        assert!(!root_peer(&peer, owner ^ 1));
        Ok(())
    }

    #[test]
    fn listener_continuity_rejects_parent_and_socket_replacement() -> TestResult {
        let directory = tempfile::tempdir()?;
        let listener = fixed_listener(&directory, "selector.sock")?;
        assert!(listener.verify_continuity().is_ok());

        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o722))?;
        assert_eq!(
            listener.verify_continuity(),
            Err(SelectorBoundaryError::ArtifactInvalid)
        );
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;

        fs::set_permissions(&listener.path, fs::Permissions::from_mode(0o620))?;
        assert_eq!(
            listener.verify_continuity(),
            Err(SelectorBoundaryError::ArtifactInvalid)
        );
        fs::remove_file(&listener.path)?;
        let _replacement = UnixListener::bind(&listener.path)?;
        fs::set_permissions(&listener.path, fs::Permissions::from_mode(SOCKET_MODE))?;
        assert_eq!(
            listener.verify_continuity(),
            Err(SelectorBoundaryError::ArtifactInvalid)
        );
        Ok(())
    }

    fn encoded_request(
        request: &crate::evaluator_protocol::EvaluationRequest,
        attempt: &crate::evaluator::CaseAttempt,
    ) -> TestResult<crate::selector_protocol::EncodedSelectorRequest> {
        let request_bytes = request.to_canonical_cbor()?;
        crate::selector_protocol::encode_request(request, &request_bytes, attempt, 0)
            .map_err(|error| format!("selector request encode failed: {error:?}").into())
    }

    fn refresh_request_digest(
        request: &mut crate::evaluator_protocol::EvaluationRequest,
    ) -> TestResult {
        request.output_capability.capability_digest =
            request.expected_output_capability_digest()?;
        request.request_digest = request.digest()?;
        Ok(())
    }

    fn fixed_listener(directory: &tempfile::TempDir, name: &str) -> TestResult<FixedListener> {
        let path = directory.path().join(name);
        let listener = UnixListener::bind(&path)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(SOCKET_MODE))?;
        let parent = File::open(directory.path())?;
        let parent_metadata = parent.metadata()?;
        let socket_metadata = fs::symlink_metadata(&path)?;
        Ok(FixedListener {
            listener,
            parent,
            parent_device: parent_metadata.dev(),
            parent_inode: parent_metadata.ino(),
            socket_device: socket_metadata.dev(),
            socket_inode: socket_metadata.ino(),
            path,
            owner: socket_metadata.uid(),
        })
    }

    fn assert_service_error<T: ProviderExecutor>(
        service: &RootSelectorService<T>,
        request: &crate::evaluator_protocol::EvaluationRequest,
        attempt: &crate::evaluator::CaseAttempt,
        expected: SandboxLocalErrorCode,
    ) -> TestResult {
        let encoded = encoded_request(request, attempt)?;
        let (mut client, server) = UnixStream::pair()?;
        let control_length = u32::try_from(encoded.control.len())?;
        client.write_all(&control_length.to_be_bytes())?;
        client.write_all(&encoded.control)?;
        client.write_all(&encoded.attempt_stream)?;
        client.shutdown(std::net::Shutdown::Write)?;
        service.handle_connection(server)?;
        assert_eq!(read_local_error(&mut client)?.code, expected);
        Ok(())
    }

    fn assert_written_error(
        write: impl FnOnce(&mut UnixStream) -> Result<(), SelectorBoundaryError>,
        expected: SandboxLocalErrorCode,
    ) -> TestResult {
        let (mut root, mut client) = UnixStream::pair()?;
        write(&mut root)?;
        assert_eq!(read_local_error(&mut client)?.code, expected);
        Ok(())
    }

    fn read_local_error(stream: &mut UnixStream) -> TestResult<SandboxLocalError> {
        let mut prefix = [0_u8; 4];
        stream.read_exact(&mut prefix)?;
        let length = usize::try_from(u32::from_be_bytes(prefix))?;
        let mut control = vec![0_u8; length];
        stream.read_exact(&mut control)?;
        SandboxLocalError::from_canonical_cbor(&control).map_err(Into::into)
    }
}
