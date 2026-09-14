//! Non-activating normal-path composition for ADR-069's root-owned selector.
//!
//! This module owns no caller-configurable authority. It opens exactly one
//! SIC1 state and fails closed while SIR1 recovery is pending. ADR-069 assigns
//! both fixed listeners and final production activation to #359, so this module
//! deliberately exposes no runtime socket by itself.

use std::io::{Read, Write};
use std::os::fd::AsFd;
use std::os::unix::net::UnixStream;
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
use crate::selector::installation::{InstallationObjectKind, InstalledSelectorState};
use crate::selector::SelectorBoundaryError;
use crate::selector_protocol::{
    decode_request, encode_authenticated_reply, encode_local_error_reply,
    AuthenticatedSelectorReply, DecodedSelectorRequest, EncodedSelectorReply,
    SelectorProviderTerminal,
};

const CONTROL_LIMIT: u32 = 16 * 1024 * 1024;
const SELECTOR_INPUT_LIMIT: u64 = 128 * 1024 * 1024;
const CONTROL_ARTIFACT_LIMIT: u64 = 16 * 1024 * 1024;
const IMAGE_ARTIFACT_LIMIT: u64 = 1024 * 1024 * 1024;
const ROOT_UID: u32 = 0;
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

fn map_to_unit_error<T>(_: T) {}

/// Authenticated normal-path composition without fixed runtime activation.
///
/// Pending SIR1 deliberately remains unavailable: `InstalledSelectorState::open`
/// rejects it before any capability can be returned. #359 consumes this seam
/// only after composing the mandatory administrative and evaluator listeners.
pub struct RootSelectorComposition {
    service: RootSelectorService<ProviderTransport>,
}

impl RootSelectorComposition {
    /// Opens and authenticates the exact fixed installation and selected provider.
    ///
    /// # Errors
    ///
    /// Returns a closed boundary error for missing, invalid, pending-recovery,
    /// or unavailable installation/provider state.
    pub fn open() -> Result<Self, SelectorBoundaryError> {
        InstalledSelectorState::open()
            .and_then(InstalledSelectorState::authenticate_bootstrap)
            .and_then(AuthenticatedSelectorBootstrap::admit_provider)
            .and_then(|admitted| {
                connect_fixed_provider(&admitted).map(|transport| Self {
                    service: RootSelectorService {
                        admitted,
                        transport,
                        peer_uid: ROOT_UID,
                    },
                })
            })
    }

    /// Evaluates one already-accepted root peer without binding any socket.
    ///
    /// # Errors
    ///
    /// Returns a closed boundary error when the stream cannot be authenticated,
    /// decoded, executed, or answered. Protocol-level failures are encoded in
    /// the selector reply where the request identity permits one.
    pub fn evaluate_root_connection(
        &self,
        stream: UnixStream,
    ) -> Result<(), SelectorBoundaryError> {
        self.service.handle_connection(stream)
    }
}

fn connect_fixed_provider(
    admitted: &AdmittedSelectorProvider,
) -> Result<ProviderTransport, SelectorBoundaryError> {
    connect_and_synchronize(
        admitted,
        ProviderTransport::from_admitted,
        fresh_nonce,
        synchronize_fixed_provider,
    )
}

fn synchronize_fixed_provider(
    transport: &ProviderTransport,
    admitted: &AdmittedSelectorProvider,
    request_id: [u8; 16],
    nonce: [u8; 16],
) -> Result<(), SelectorBoundaryError> {
    transport.synchronize_revocation(admitted.provider(), request_id, nonce, INITIAL_IO_TIMEOUT)
}

fn connect_and_synchronize<Admitted, Transport, Error>(
    admitted: &Admitted,
    connect: impl FnOnce(&Admitted) -> Result<Transport, Error>,
    mut nonce: impl FnMut() -> Result<[u8; 16], Error>,
    synchronize: impl FnOnce(&Transport, &Admitted, [u8; 16], [u8; 16]) -> Result<(), Error>,
) -> Result<Transport, Error> {
    let transport = connect(admitted)?;
    let request_id = nonce()?;
    let challenge = nonce()?;
    synchronize(&transport, admitted, request_id, challenge)?;
    Ok(transport)
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
    peer_uid: u32,
}

impl<T: ProviderExecutor> RootSelectorService<T> {
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
        InstallationObjectKind::IMAGE_MANIFEST,
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
            InstallationObjectKind::ROOT_IMAGE,
            manifest.root_image_blake3_digest,
            IMAGE_ARTIFACT_LIMIT,
        )
        .map(|root_image| (sim1, manifest, root_image))
    })
    .and_then(|(sim1, manifest, root_image)| {
        read_installed(
            installed,
            InstallationObjectKind::SUBJECT_EXECUTABLE,
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
            InstallationObjectKind::LAUNCH_POLICY,
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
    kind: InstallationObjectKind,
    identity: [u8; 32],
    limit: u64,
) -> Result<Vec<u8>, SelectorBoundaryError> {
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
        .map_err(map_to_unit_error);
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
        .map_err(map_to_unit_error)
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

fn read_selector_request<R: Read>(stream: &mut R) -> Result<(DecodedSelectorRequest, Vec<u8>), ()> {
    let mut prefix = [0_u8; 4];
    stream.read_exact(&mut prefix).map_err(map_to_unit_error)?;
    let length = u32::from_be_bytes(prefix);
    if length == 0 || length > CONTROL_LIMIT {
        return Err(());
    }
    let length = usize::try_from(length).unwrap_or_default();
    let mut control = vec![0_u8; length];
    stream.read_exact(&mut control).map_err(map_to_unit_error)?;
    let mut input = Vec::new();
    (&mut *stream)
        .take(SELECTOR_INPUT_LIMIT.saturating_add(1))
        .read_to_end(&mut input)
        .map_err(map_to_unit_error)?;
    validate_selector_input_length(input.len())?;
    decode_request(&control, &input)
        .map(|decoded| (decoded, input))
        .map_err(map_to_unit_error)
}

fn validate_selector_input_length(length: usize) -> Result<(), ()> {
    u64::try_from(length)
        .map_err(map_to_unit_error)
        .and_then(|length| (length <= SELECTOR_INPUT_LIMIT).then_some(()).ok_or(()))
}

fn root_peer(stream: &UnixStream, expected_uid: u32) -> bool {
    socket_peercred(stream.as_fd())
        .is_ok_and(|credentials| credentials.uid.as_raw() == expected_uid)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use std::cell::RefCell;
    use std::fs;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::os::unix::net::UnixListener;
    use std::path::Path;
    use std::process::Command;

    use super::*;

    type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
    const PRIVILEGED_COMPOSITION_TEST: &str = "PIGLOROS_PRIVILEGED_COMPOSITION_TEST";
    const INSTALLATION_PARENT: &str = "/var/lib/pigloros";
    const RUNTIME_DIRECTORY: &str = "/run/pigloros";
    const SOCKET_MODE: u32 = 0o600;

    struct FixedCompositionFixture;

    impl FixedCompositionFixture {
        fn create() -> TestResult<Self> {
            if Path::new(INSTALLATION_PARENT).exists() || Path::new(RUNTIME_DIRECTORY).exists() {
                return Err("fixed selector test paths already exist".into());
            }
            fs::create_dir(INSTALLATION_PARENT)?;
            let fixture = Self;
            fs::set_permissions(INSTALLATION_PARENT, fs::Permissions::from_mode(0o700))?;
            fs::create_dir(crate::selector::installation::SANDBOX_ARTIFACT_ROOT)?;
            fs::set_permissions(
                crate::selector::installation::SANDBOX_ARTIFACT_ROOT,
                fs::Permissions::from_mode(0o700),
            )?;
            fs::create_dir(RUNTIME_DIRECTORY)?;
            fs::set_permissions(RUNTIME_DIRECTORY, fs::Permissions::from_mode(0o700))?;
            Ok(fixture)
        }
    }

    impl Drop for FixedCompositionFixture {
        fn drop(&mut self) {
            for socket in [
                "/run/pigloros/provider-execute.sock",
                "/run/pigloros/provider-control.sock",
            ] {
                drop(fs::remove_file(socket));
            }
            drop(fs::remove_dir_all(INSTALLATION_PARENT));
            drop(fs::remove_dir_all(RUNTIME_DIRECTORY));
        }
    }

    fn privileged_composition_child() -> TestResult<bool> {
        if rustix::process::geteuid().as_raw() == ROOT_UID {
            return Ok(false);
        }
        let mut command = Command::new("sudo");
        command.args(["-n", "env"]);
        command.arg(format!("{PRIVILEGED_COMPOSITION_TEST}=1"));
        if let Some(profile) = std::env::var_os("LLVM_PROFILE_FILE") {
            command.arg(format!("LLVM_PROFILE_FILE={}", profile.to_string_lossy()));
        }
        let output = command
            .arg(std::env::current_exe()?)
            .args([
                "--exact",
                "root_selector::tests::nonactivating_public_composition_authenticates_sly1",
                "--nocapture",
            ])
            .output()?;
        if !output.status.success() {
            return Err(format!(
                "privileged selector composition failed:\nstdout:\n{}\nstderr:\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            )
            .into());
        }
        Ok(true)
    }

    fn serve_describe_response(
        listener: &UnixListener,
        fixture: &crate::selector_transport_test_fixture::TransportAdmissionFixture,
        provider: &crate::sandbox_provider_protocol::AdmittedSandboxProvider,
    ) -> TestResult {
        let (mut stream, _) = listener.accept()?;
        stream.set_read_timeout(Some(Duration::from_secs(5)))?;
        stream.set_write_timeout(Some(Duration::from_secs(5)))?;
        let mut prefix = [0; 4];
        stream.read_exact(&mut prefix)?;
        let length = usize::try_from(u32::from_be_bytes(prefix))?;
        let mut request = vec![0; length];
        stream.read_exact(&mut request)?;
        let mut trailing = Vec::new();
        stream.read_to_end(&mut trailing)?;
        if !trailing.is_empty() {
            return Err("describe request contained trailing bytes".into());
        }
        let response = fixture.describe_response_for_provider(&request, provider)?;
        stream.write_all(&u32::try_from(response.len())?.to_be_bytes())?;
        stream.write_all(&response)?;
        stream.shutdown(std::net::Shutdown::Write)?;
        Ok(())
    }

    fn read_frame(stream: &mut UnixStream) -> TestResult<Vec<u8>> {
        let mut prefix = [0; 4];
        stream.read_exact(&mut prefix)?;
        let mut frame = vec![0; usize::try_from(u32::from_be_bytes(prefix))?];
        stream.read_exact(&mut frame)?;
        Ok(frame)
    }

    fn write_frame(stream: &mut UnixStream, frame: &[u8]) -> TestResult {
        stream.write_all(&u32::try_from(frame.len())?.to_be_bytes())?;
        stream.write_all(frame)?;
        Ok(())
    }

    fn serve_execution_response(
        listener: &UnixListener,
        fixture: &crate::selector_transport_test_fixture::TransportAdmissionFixture,
        provider: &crate::sandbox_provider_protocol::AdmittedSandboxProvider,
        commitment: &crate::sandbox_provider_protocol::SelectorGrantCommitment,
        epochs: [u64; 3],
    ) -> TestResult {
        let (mut stream, _) = listener.accept()?;
        stream.set_read_timeout(Some(Duration::from_secs(5)))?;
        stream.set_write_timeout(Some(Duration::from_secs(5)))?;
        let spx1 = read_frame(&mut stream)?;
        let mut input_frames = Vec::new();
        stream.read_to_end(&mut input_frames)?;
        if input_frames.is_empty() {
            return Err("provider input frames missing".into());
        }
        for response in fixture.execution_response_for(provider, &spx1, commitment, epochs)? {
            write_frame(&mut stream, &response)?;
        }
        stream.shutdown(std::net::Shutdown::Write)?;
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn nonactivating_public_composition_authenticates_sly1() -> TestResult {
        if privileged_composition_child()? {
            return Ok(());
        }
        if std::env::var_os(PRIVILEGED_COMPOSITION_TEST).is_none()
            && rustix::process::geteuid().as_raw() != ROOT_UID
        {
            return Err("privileged selector composition did not start".into());
        }

        let _paths = FixedCompositionFixture::create()?;
        assert!(RootSelectorComposition::open().is_err());
        let (request, _, resolved) = crate::selector::installation::tests::root_selector_fixture()?;
        let encoded = encoded_request(&request, resolved.attempt())?;
        let admitted = crate::selector::installation::tests::materialize_admitted_state(
            Path::new(crate::selector::installation::SANDBOX_ARTIFACT_ROOT),
        )?;
        let control_fixture =
            crate::selector_transport_test_fixture::authenticated_transport_fixture()?;
        let execute_fixture =
            crate::selector_transport_test_fixture::authenticated_transport_fixture()?;
        let requirement = request
            .sandbox_requirement
            .as_ref()
            .ok_or("sandbox requirement missing")?;
        let (image, launch) = selected_image_and_launch(&admitted, requirement)?;
        let commitment = admitted.provider().derive_selector_grant_commitment(
            &image,
            &launch,
            &request,
            resolved.attempt(),
            &[],
        )?;
        let epochs = [
            admitted.bootstrap().trust().trust_epoch(),
            admitted.bootstrap().revocation().revocation_epoch(),
            admitted.bootstrap().policy().policy_epoch(),
        ];
        let execute_provider_identity = admitted.provider().clone();

        let execute_listener = UnixListener::bind("/run/pigloros/provider-execute.sock")?;
        fs::set_permissions(
            "/run/pigloros/provider-execute.sock",
            fs::Permissions::from_mode(SOCKET_MODE),
        )?;
        let control_listener = UnixListener::bind("/run/pigloros/provider-control.sock")?;
        fs::set_permissions(
            "/run/pigloros/provider-control.sock",
            fs::Permissions::from_mode(SOCKET_MODE),
        )?;
        let control_provider = std::thread::spawn(move || {
            serve_describe_response(&control_listener, &control_fixture, admitted.provider())
                .map_err(|error| error.to_string())
        });
        let execute_provider = std::thread::spawn(move || {
            serve_execution_response(
                &execute_listener,
                &execute_fixture,
                &execute_provider_identity,
                &commitment,
                epochs,
            )
            .map_err(|error| error.to_string())
        });
        let composition = RootSelectorComposition::open()?;
        assert!(!Path::new(crate::selector::SANDBOX_SELECTOR_SOCKET).exists());
        assert!(!Path::new(crate::selector::installation::SANDBOX_ADMIN_SOCKET).exists());

        let (mut client, server) = UnixStream::pair()?;
        write_frame(&mut client, &encoded.control)?;
        client.write_all(&encoded.attempt_stream)?;
        client.shutdown(std::net::Shutdown::Write)?;
        composition.evaluate_root_connection(server)?;
        let control = read_frame(&mut client)?;
        let mut trailing = Vec::new();
        client.read_to_end(&mut trailing)?;
        if let Ok(local) = SandboxLocalError::from_canonical_cbor(&control) {
            return Err(format!("composition returned local selector failure: {local:?}").into());
        }
        let reply = crate::selector_protocol::decode_reply(
            &control,
            &trailing,
            &encoded,
            request.request_digest,
            SELECTOR_INPUT_LIMIT,
        )?;
        assert_eq!(
            reply.observation,
            Ok(crate::evaluator::SubjectObservation {
                result: crate::evaluator::SubjectResult::Unavailable,
                usage: crate::evaluator::ResourceUsage::default(),
            })
        );
        assert!(reply.provenance.is_some());
        control_provider
            .join()
            .map_err(|_| "provider control thread panicked")??;
        execute_provider
            .join()
            .map_err(|_| "provider execute thread panicked")??;
        Ok(())
    }

    #[test]
    fn provider_connection_requires_two_nonces_and_completed_synchronization() {
        let mut nonces = [[3; 16], [4; 16]].into_iter();
        assert_eq!(
            connect_and_synchronize(
                &1,
                |_| Ok::<_, ()>(2),
                || nonces.next().ok_or(()),
                |transport, admitted, request_id, challenge| {
                    assert_eq!((*transport, *admitted), (2, 1));
                    assert_eq!((request_id, challenge), ([3; 16], [4; 16]));
                    Ok(())
                },
            ),
            Ok(2)
        );
        assert_eq!(
            connect_and_synchronize(
                &1,
                |_| Err::<u8, _>(()),
                || Ok([1; 16]),
                |_, _, _, _| { Ok(()) }
            ),
            Err(())
        );

        let mut missing_first = std::iter::empty();
        assert_eq!(
            connect_and_synchronize(
                &1,
                |_| Ok::<_, ()>(2),
                || missing_first.next().ok_or(()),
                |_, _, _, _| Ok(()),
            ),
            Err(())
        );
        let mut missing_second = std::iter::once([1; 16]);
        assert_eq!(
            connect_and_synchronize(
                &1,
                |_| Ok::<_, ()>(2),
                || missing_second.next().ok_or(()),
                |_, _, _, _| Ok(()),
            ),
            Err(())
        );
        assert_eq!(
            connect_and_synchronize(&1, |_| Ok::<_, ()>(2), || Ok([1; 16]), |_, _, _, _| Err(()),),
            Err(())
        );
    }

    #[test]
    fn closed_helpers_cover_error_mapping_randomness_and_input_bounds() -> TestResult {
        assert_eq!(artifact_invalid(()), SelectorBoundaryError::ArtifactInvalid);
        assert_eq!(
            selector_unavailable(()),
            SelectorBoundaryError::SelectorUnavailable
        );
        assert_eq!(io_error(()), SelectorBoundaryError::Io);
        map_to_unit_error(());
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
    fn provider_synchronization_fails_closed_when_host_state_is_lost() -> TestResult {
        let (_, admitted, _) = crate::selector::installation::tests::root_selector_fixture()?;
        assert!(connect_fixed_provider(&admitted).is_err());
        let sync_directory = tempfile::tempdir()?;
        let sync_path = sync_directory.path().join("provider-control.sock");
        let sync_listener = UnixListener::bind(&sync_path)?;
        fs::set_permissions(&sync_path, fs::Permissions::from_mode(SOCKET_MODE))?;
        let sync_provider = std::thread::spawn(move || -> std::io::Result<()> {
            let (stream, _) = sync_listener.accept()?;
            drop(stream);
            Ok(())
        });
        let sync_transport = ProviderTransport::from_path_for_test(&sync_path)?;
        assert!(synchronize_fixed_provider(
            &sync_transport,
            &admitted,
            rand::random(),
            rand::random(),
        )
        .is_err());
        sync_provider
            .join()
            .map_err(|_| "provider synchronization thread panicked")??;
        Ok(())
    }

    #[test]
    fn request_reader_covers_the_normal_framed_boundary() -> TestResult {
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
        let service = RootSelectorService {
            admitted,
            transport,
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
            let service = RootSelectorService {
                admitted,
                transport: FixedProviderExecutor(RefCell::new(Some(result))),
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
        let service = RootSelectorService {
            admitted,
            transport: FixedProviderExecutor(RefCell::new(Some(Ok(
                AuthenticatedProviderTerminal::Execution(execution),
            )))),
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
        let service = RootSelectorService {
            admitted,
            transport: FixedProviderExecutor(RefCell::new(Some(Ok(
                AuthenticatedProviderTerminal::Error(fixture.spe1),
            )))),
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
        let owner = fs::metadata(".")?.uid();
        let mut service = RootSelectorService {
            admitted,
            transport: ProviderTransport::from_path_for_test(&provider_path)?,
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
        for prefix in [0_u32, CONTROL_LIMIT + 1] {
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

        let (request, _, resolved) = crate::selector::installation::tests::root_selector_fixture()?;
        let encoded = encoded_request(&request, resolved.attempt())?;
        let mut framed = u32::try_from(encoded.control.len())?.to_be_bytes().to_vec();
        framed.extend_from_slice(&encoded.control);
        let mut failing_input = std::io::Cursor::new(framed).chain(FailingReader);
        assert!(read_selector_request(&mut failing_input).is_err());
        Ok(())
    }

    struct FailingReader;

    impl Read for FailingReader {
        fn read(&mut self, _buffer: &mut [u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("injected input read failure"))
        }
    }

    #[test]
    fn peer_identity_uses_the_explicit_service_owner() -> TestResult {
        let (peer, _) = UnixStream::pair()?;
        let owner = fs::metadata(".")?.uid();
        assert!(root_peer(&peer, owner));
        assert!(!root_peer(&peer, owner ^ 1));
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
