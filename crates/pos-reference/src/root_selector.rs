//! Fixed normal-path composition for ADR-069's root-owned selector.
//!
//! This module owns no caller-configurable authority. It opens exactly one
//! SIC1 state, fails closed while SIR1 recovery is pending, and exposes the
//! evaluator listener only after bootstrap authentication, provider admission,
//! and fixed administrative-listener binding complete.

use std::fs::{self, File, Metadata};
use std::io::{Read, Write};
use std::os::fd::AsFd;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::time::Duration;

use rustix::net::sockopt::socket_peercred;
use rustix::rand::{getrandom, GetRandomFlags};

use crate::provider_transport::{AuthenticatedProviderExecution, ProviderTransport};
use crate::sandbox_provider_protocol::{
    AdmittedSandboxImage, ExecuteAuthority, LaunchPolicy, RequestAuthority, SandboxExecuteRequest,
    SandboxLocalError, SandboxLocalErrorCode, SandboxLocalErrorPhase, SandboxProviderOperation,
    SignedImageManifest,
};
use crate::selector::installation::authority::AdmittedSelectorProvider;
use crate::selector::installation::{
    open_directory_chain, InstallationObjectKind, InstalledSelectorState, SANDBOX_ADMIN_SOCKET,
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

/// Run the normal (no pending SIR1) selector composition.
///
/// Pending SIR1 deliberately remains unavailable: `InstalledSelectorState::open`
/// rejects it before any listener can be exposed, until #214 supplies the
/// required lifecycle-backed recovery composition.
pub(crate) fn run_fixed() -> Result<(), SelectorBoundaryError> {
    let admitted = InstalledSelectorState::open()?
        .authenticate_bootstrap()?
        .admit_provider()?;
    let admin_listener = FixedListener::bind(SANDBOX_ADMIN_SOCKET)?;
    let transport = ProviderTransport::from_admitted(&admitted)?;
    let evaluator_listener = FixedListener::bind(SANDBOX_SELECTOR_SOCKET)?;
    RootSelectorService {
        admitted,
        transport,
        admin_listener,
        evaluator_listener,
    }
    .serve()
}

struct RootSelectorService {
    admitted: AdmittedSelectorProvider,
    transport: ProviderTransport,
    admin_listener: FixedListener,
    evaluator_listener: FixedListener,
}

impl RootSelectorService {
    fn serve(&self) -> Result<(), SelectorBoundaryError> {
        self.admin_listener.verify_continuity()?;
        loop {
            self.admin_listener.verify_continuity()?;
            self.evaluator_listener.verify_continuity()?;
            let (stream, _) = self
                .evaluator_listener
                .listener
                .accept()
                .map_err(|_| SelectorBoundaryError::Io)?;
            match self.handle_connection(stream) {
                Ok(())
                | Err(SelectorBoundaryError::ArtifactInvalid)
                | Err(SelectorBoundaryError::SelectorUnavailable)
                | Err(SelectorBoundaryError::Io) => {}
            }
        }
    }

    fn handle_connection(&self, mut stream: UnixStream) -> Result<(), SelectorBoundaryError> {
        if !root_peer(&stream) {
            return Ok(());
        }
        stream
            .set_read_timeout(Some(INITIAL_IO_TIMEOUT))
            .and_then(|()| stream.set_write_timeout(Some(INITIAL_IO_TIMEOUT)))
            .map_err(|_| SelectorBoundaryError::Io)?;
        let (decoded, input) = match read_selector_request(&mut stream) {
            Ok(decoded) => decoded,
            Err(()) => return write_unidentified_request_error(&mut stream),
        };
        stream
            .set_read_timeout(Some(Duration::from_millis(decoded.attempt.watchdog_ms)))
            .and_then(|()| {
                stream.set_write_timeout(Some(Duration::from_millis(decoded.attempt.watchdog_ms)))
            })
            .map_err(|_| SelectorBoundaryError::Io)?;
        self.handle_decoded_request(&mut stream, decoded, &input)
    }

    fn handle_decoded_request(
        &self,
        stream: &mut UnixStream,
        decoded: DecodedSelectorRequest,
        input: &[u8],
    ) -> Result<(), SelectorBoundaryError> {
        let requirement = match decoded.request.sandbox_requirement.as_ref() {
            Some(requirement) => requirement,
            None => return write_policy_error(stream, &decoded),
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
            Ok(_) | Err(_) => return write_authority_mismatch(stream, &decoded),
        };
        let (image, launch) = match selected_image_and_launch(&self.admitted, requirement) {
            Ok(selection) => selection,
            Err(_) => return write_policy_error(stream, &decoded),
        };
        let commitment = match self.admitted.provider().derive_selector_grant_commitment(
            &image,
            &launch,
            &decoded.request,
            resolved.attempt(),
            &[],
        ) {
            Ok(commitment) => commitment,
            Err(_) => return write_authority_mismatch(stream, &decoded),
        };
        let spx1 = match selector_execute_bytes(&self.admitted, &decoded, &resolved, requirement) {
            Ok(bytes) => bytes,
            Err(_) => return write_authority_mismatch(stream, &decoded),
        };
        let execution = match self.transport.execute(
            &self.admitted,
            &commitment,
            &spx1,
            input,
            Duration::from_millis(decoded.attempt.watchdog_ms),
        ) {
            Ok(execution) => execution,
            Err(_) => return write_provider_unavailable(stream, &decoded),
        };
        write_authenticated_execution(stream, &decoded, &spx1, execution)
    }
}

fn selected_image_and_launch(
    admitted: &AdmittedSelectorProvider,
    requirement: &crate::evaluator_protocol::SandboxRequirement,
) -> Result<(AdmittedSandboxImage, LaunchPolicy), SelectorBoundaryError> {
    let installed = admitted.bootstrap().installed();
    let sim1 = read_installed(
        installed,
        9,
        requirement.sim1_digest,
        CONTROL_ARTIFACT_LIMIT,
    )?;
    let image_manifest = SignedImageManifest::from_canonical_cbor(&sim1)
        .map_err(|_| SelectorBoundaryError::ArtifactInvalid)?;
    let root_image = read_installed(
        installed,
        12,
        image_manifest.root_image_blake3_digest,
        IMAGE_ARTIFACT_LIMIT,
    )?;
    let executable = read_installed(
        installed,
        13,
        image_manifest.executable_blake3_digest,
        IMAGE_ARTIFACT_LIMIT,
    )?;
    let image = admitted
        .provider()
        .admit_image(&sim1, &root_image, &executable)
        .map_err(|_| SelectorBoundaryError::ArtifactInvalid)?;
    let lps1 = read_installed(
        installed,
        8,
        requirement.lps1_digest,
        CONTROL_ARTIFACT_LIMIT,
    )?;
    admitted
        .provider()
        .admit_launch_policy(&lps1, &image)
        .map(|launch| (image, launch))
        .map_err(|_| SelectorBoundaryError::ArtifactInvalid)
}

fn read_installed(
    installed: &InstalledSelectorState,
    kind: u8,
    identity: [u8; 32],
    limit: u64,
) -> Result<Vec<u8>, SelectorBoundaryError> {
    let kind = InstallationObjectKind::from_code(kind)
        .map_err(|_| SelectorBoundaryError::ArtifactInvalid)?;
    installed.artifact(kind, identity)?.read_control(limit)
}

fn selector_execute_bytes(
    admitted: &AdmittedSelectorProvider,
    decoded: &DecodedSelectorRequest,
    resolved: &crate::selector::installation::cases::ResolvedInstalledCase,
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
    .map_err(|_| SelectorBoundaryError::ArtifactInvalid)
}

fn fresh_nonce() -> Result<[u8; 16], SelectorBoundaryError> {
    let mut nonce = [0_u8; 16];
    let mut remaining = nonce.as_mut_slice();
    while !remaining.is_empty() {
        let received = getrandom(remaining, GetRandomFlags::empty())
            .map_err(|_| SelectorBoundaryError::SelectorUnavailable)?;
        if received == 0 {
            return Err(SelectorBoundaryError::SelectorUnavailable);
        }
        remaining = &mut remaining[received..];
    }
    if nonce == [0; 16] {
        Err(SelectorBoundaryError::SelectorUnavailable)
    } else {
        Ok(nonce)
    }
}

fn write_authenticated_execution(
    stream: &mut UnixStream,
    decoded: &DecodedSelectorRequest,
    spx1: &[u8],
    mut execution: AuthenticatedProviderExecution,
) -> Result<(), SelectorBoundaryError> {
    let output = execution.with_verified_output(|descriptor, reader| {
        let capacity = usize::try_from(descriptor.byte_length)
            .map_err(|_| SelectorBoundaryError::ArtifactInvalid)?;
        let mut bytes = Vec::with_capacity(capacity);
        reader
            .take(descriptor.byte_length.saturating_add(1))
            .read_to_end(&mut bytes)
            .map_err(|_| SelectorBoundaryError::Io)?;
        if bytes.len() != capacity {
            return Err(SelectorBoundaryError::ArtifactInvalid);
        }
        Ok(bytes)
    })?;
    let reply = encode_authenticated_reply(
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
    .map_err(|_| SelectorBoundaryError::ArtifactInvalid)?;
    write_reply(stream, reply)
}

fn write_unidentified_request_error(stream: &mut UnixStream) -> Result<(), SelectorBoundaryError> {
    write_local_error(
        stream,
        SandboxLocalError {
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
        SandboxLocalError {
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
        SandboxLocalError {
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
        SandboxLocalError {
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

fn write_local_error(
    stream: &mut UnixStream,
    error: SandboxLocalError,
) -> Result<(), SelectorBoundaryError> {
    encode_local_error_reply(&error)
        .map_err(|_| SelectorBoundaryError::ArtifactInvalid)
        .and_then(|reply| write_reply(stream, reply))
}

fn write_reply(
    stream: &mut UnixStream,
    reply: EncodedSelectorReply,
) -> Result<(), SelectorBoundaryError> {
    let length = u32::try_from(reply.control.len()).map_err(|_| SelectorBoundaryError::Io)?;
    stream
        .write_all(&length.to_be_bytes())
        .and_then(|()| stream.write_all(&reply.control))
        .and_then(|()| stream.write_all(&reply.trailing))
        .map_err(|_| SelectorBoundaryError::Io)
}

fn read_selector_request(stream: &mut UnixStream) -> Result<(DecodedSelectorRequest, Vec<u8>), ()> {
    let mut prefix = [0_u8; 4];
    stream.read_exact(&mut prefix).map_err(|_| ())?;
    let length = usize::try_from(u32::from_be_bytes(prefix)).map_err(|_| ())?;
    if length == 0 || length > CONTROL_LIMIT {
        return Err(());
    }
    let mut control = vec![0_u8; length];
    stream.read_exact(&mut control).map_err(|_| ())?;
    let mut input = Vec::new();
    (&mut *stream)
        .take(SELECTOR_INPUT_LIMIT.saturating_add(1))
        .read_to_end(&mut input)
        .map_err(|_| ())?;
    if u64::try_from(input.len()).map_err(|_| ())? > SELECTOR_INPUT_LIMIT {
        return Err(());
    }
    decode_request(&control, &input)
        .map(|decoded| (decoded, input))
        .map_err(|_| ())
}

fn root_peer(stream: &UnixStream) -> bool {
    socket_peercred(stream.as_fd())
        .map(|credentials| credentials.uid.as_raw() == ROOT_UID)
        .unwrap_or(false)
}

struct FixedListener {
    listener: UnixListener,
    parent: File,
    parent_device: u64,
    parent_inode: u64,
    socket_device: u64,
    socket_inode: u64,
    path: &'static str,
}

impl FixedListener {
    fn bind(path: &'static str) -> Result<Self, SelectorBoundaryError> {
        let path_text = path;
        let path = Path::new(path_text);
        let parent_path = path
            .parent()
            .ok_or(SelectorBoundaryError::ArtifactInvalid)?;
        let relative = parent_path
            .strip_prefix("/")
            .map_err(|_| SelectorBoundaryError::ArtifactInvalid)?;
        let parent = File::open("/")
            .map_err(|_| SelectorBoundaryError::Io)
            .and_then(|root| open_directory_chain(root, relative, ROOT_UID))?;
        let parent_metadata = parent.metadata().map_err(|_| SelectorBoundaryError::Io)?;
        let listener =
            UnixListener::bind(path).map_err(|_| SelectorBoundaryError::SelectorUnavailable)?;
        fs::set_permissions(path, fs::Permissions::from_mode(SOCKET_MODE))
            .map_err(|_| SelectorBoundaryError::Io)?;
        let socket_metadata = fs::symlink_metadata(path).map_err(|_| SelectorBoundaryError::Io)?;
        validate_listener_leaf(&socket_metadata, ROOT_UID)?;
        Ok(Self {
            listener,
            parent,
            parent_device: parent_metadata.dev(),
            parent_inode: parent_metadata.ino(),
            socket_device: socket_metadata.dev(),
            socket_inode: socket_metadata.ino(),
            path: path_text,
        })
    }

    fn verify_continuity(&self) -> Result<(), SelectorBoundaryError> {
        let parent = self
            .parent
            .metadata()
            .map_err(|_| SelectorBoundaryError::Io)?;
        if parent.dev() != self.parent_device
            || parent.ino() != self.parent_inode
            || !parent.is_dir()
            || parent.uid() != ROOT_UID
            || parent.mode() & 0o022 != 0
        {
            return Err(SelectorBoundaryError::ArtifactInvalid);
        }
        let leaf = fs::symlink_metadata(self.path).map_err(|_| SelectorBoundaryError::Io)?;
        validate_listener_leaf(&leaf, ROOT_UID)?;
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
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::os::unix::net::UnixListener;

    use super::*;

    #[test]
    fn listener_leaf_requires_an_exact_owner_only_socket_mode(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("selector.sock");
        let listener = UnixListener::bind(&path)?;
        let owner = fs::symlink_metadata(&path)?.uid();
        fs::set_permissions(&path, fs::Permissions::from_mode(SOCKET_MODE))?;
        assert!(validate_listener_leaf(&fs::symlink_metadata(&path)?, owner).is_ok());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o620))?;
        assert!(validate_listener_leaf(&fs::symlink_metadata(&path)?, owner).is_err());
        drop(listener);
        Ok(())
    }
}
