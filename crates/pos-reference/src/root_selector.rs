//! Root-owned selector service between the evaluator and one admitted provider.

use std::io::{Read, Write};
use std::os::fd::AsFd;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::time::Duration;

use rustix::net::sockopt::socket_peercred;

use crate::evaluator::CaseAttempt;
use crate::evaluator_protocol::{EvaluationRequest, SandboxRequirement};
use crate::sandbox_provider_protocol::{
    ExecuteAuthority, NetworkExchangePlan, PayloadDescriptor, RequestAuthority,
    RootSelectorAdmission, RootSelectorAdmissionInputs, SandboxAdministratorPolicy,
    SandboxGrantExpectations, SandboxLocalError, SandboxLocalErrorCode, SandboxLocalErrorPhase,
    SandboxProviderAdmissionInputs, SandboxProviderOperation, SandboxRevocationSnapshot,
    SandboxTerminalOutcome, SandboxTrustSnapshot,
};
use crate::selector_protocol::{
    decode_request, derived_id, encode_authenticated_reply, AuthenticatedSelectorReply,
    AuthenticatedSelectorTerminal, DecodedSelectorRequest,
};

const CONTROL_LIMIT: usize = 16 * 1024 * 1024;
const SANDBOX_PAYLOAD_LIMIT: u64 = 128 * 1024 * 1024;
const SOCKET_MODE: u32 = 0o600;

/// Root-owned immutable authority needed for one independently selected case.
#[derive(Clone, Debug)]
pub struct RootSelectorAdmissionArtifacts {
    /// Authenticated active APT1.
    pub policy: SandboxAdministratorPolicy,
    /// Offline-root-authenticated TRS1 selected by APT1.
    pub trust: SandboxTrustSnapshot,
    /// Current authenticated RVS1 selected by APT1.
    pub revocation: SandboxRevocationSnapshot,
    /// Exact selected SPM1 bytes.
    pub provider_manifest: Vec<u8>,
    /// Exact immutable selected provider executable bytes.
    pub provider_binary: Vec<u8>,
    /// Exact independently installed broker hard-cap bytes.
    pub broker_hard_caps: Vec<u8>,
    /// Exact independent PCR1 bytes.
    pub conformance_report: Vec<u8>,
    /// Exact current HCP1 bytes.
    pub host_profile: Vec<u8>,
    /// Exact architecture-qualified SCS1 bytes.
    pub syscall_set: Vec<u8>,
    /// Canonically ordered host-feature identifiers selected for admission.
    pub required_features: Vec<String>,
    /// Exact selected SIM1 bytes.
    pub image_manifest: Vec<u8>,
    /// Exact immutable root-image bytes bound by SIM1.
    pub root_image: Vec<u8>,
    /// Exact executable bytes bound by SIM1 and EVR1.
    pub executable: Vec<u8>,
    /// Exact selected LPS1 bytes.
    pub launch_policy: Vec<u8>,
    /// Selector-derived ELM1, readback, and provider-capability expectations.
    pub grant_expectations: SandboxGrantExpectations,
}

impl RootSelectorAdmissionArtifacts {
    fn admit(
        &self,
        request: &EvaluationRequest,
        requirement: &SandboxRequirement,
    ) -> Result<RootSelectorAdmission, RootSelectorServiceError> {
        if self.grant_expectations.required_provider_capability
            != requirement.required_provider_capability
        {
            return Err(RootSelectorServiceError::AuthorityMismatch);
        }
        RootSelectorAdmission::establish(
            &self.policy,
            &self.trust,
            &self.revocation,
            RootSelectorAdmissionInputs {
                provider: SandboxProviderAdmissionInputs {
                    provider_manifest: &self.provider_manifest,
                    provider_binary: &self.provider_binary,
                    broker_hard_caps: &self.broker_hard_caps,
                    conformance_report: &self.conformance_report,
                    host_profile: &self.host_profile,
                    syscall_set: &self.syscall_set,
                    required_features: &self.required_features,
                },
                image_manifest: &self.image_manifest,
                root_image: &self.root_image,
                executable: &self.executable,
                subject_artifact_digest: request.subject_artifact_digest,
                launch_policy: &self.launch_policy,
                grant_expectations: self.grant_expectations.clone(),
            },
        )
        .map_err(|_| RootSelectorServiceError::Admission)
    }
}

/// Independently reconstructed authority for one canonical selected case.
#[derive(Clone, Debug)]
pub struct RootSelectorCasePlan {
    /// `CaseAttempt` independently reconstructed from installed CFB1/CPF1 state.
    pub expected_attempt: CaseAttempt,
    /// Exact fifteen-digest SPX1 authority block.
    pub execute_authority: ExecuteAuthority,
    /// Canonical provider-neutral network plan, empty for Air-Gapped execution.
    pub network_plans: Vec<NetworkExchangePlan>,
    /// Fresh selector-generated request nonce.
    pub request_nonce: [u8; 16],
    /// Exact immutable admission artifacts selected for this request.
    pub admission: RootSelectorAdmissionArtifacts,
}

/// Root-owned resolution of immutable policy, bundle, fixture, and image state.
///
/// Implementations are part of the selector TCB. They must use digest-addressed
/// immutable artifacts and independently reconstruct the selected case from
/// EVR1; evaluator-supplied EAI1 fields are never an authority source.
pub trait RootSelectorAuthoritySource {
    /// Resolve one request without treating any evaluator-supplied attempt field as authority.
    ///
    /// # Errors
    /// Returns a closed failure when installed state is unavailable or disagrees with EVR1.
    fn resolve_case(
        &mut self,
        request: &EvaluationRequest,
        ordinal: u16,
    ) -> Result<RootSelectorCasePlan, RootSelectorServiceError>;
}

/// Exact provider evidence returned to the root selector.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RootSelectorProviderReply {
    /// AGR1 admission followed by complete authenticated lifecycle evidence.
    Admitted {
        /// Exact signed AGR1 bytes.
        grant: Vec<u8>,
        /// Exact signed SPR1 bytes.
        receipt: Vec<u8>,
        /// Exact signed SPY1 bytes.
        result: Vec<u8>,
        /// Exact ordered signed SAU1 records.
        audit: Vec<Vec<u8>>,
        /// Exact framed EAO1 stream, present only for Completed.
        output_stream: Option<Vec<u8>>,
    },
    /// Authenticated Rejected or `UnavailableBeforeAdmission` SPY1.
    BeforeAdmission {
        /// Exact signed SPY1 bytes.
        result: Vec<u8>,
    },
    /// Authenticated provider SPE1 before admission.
    Error {
        /// Exact signed SPE1 bytes.
        error: Vec<u8>,
    },
}

/// Provider execute port selected from root-owned installation state.
pub trait RootSelectorProvider {
    /// Execute one selector-constructed SPX1 and exact framed input stream.
    ///
    /// # Errors
    /// Returns a closed failure when the selected provider transport is unavailable.
    fn execute(
        &mut self,
        request: &crate::sandbox_provider_protocol::SandboxExecuteRequest,
        input_stream: &[u8],
        watchdog: Duration,
    ) -> Result<RootSelectorProviderReply, RootSelectorServiceError>;
}

/// Closed root-selector service failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum RootSelectorServiceError {
    #[error("selector request is invalid")]
    InvalidRequest,
    #[error("selector authority is unavailable")]
    AuthorityUnavailable,
    #[error("selector authority does not match the request")]
    AuthorityMismatch,
    #[error("selector admission failed")]
    Admission,
    #[error("selected provider is unavailable")]
    ProviderUnavailable,
    #[error("selected provider evidence is invalid")]
    ProviderEvidence,
    #[error("selector I/O failed")]
    Io,
}

/// Production root-selector listener and request handler.
pub struct RootSelectorServer<A, P> {
    authority: A,
    provider: P,
    evaluator_uid: u32,
    initial_io_timeout: Duration,
}

#[derive(Clone, Copy)]
struct ProviderResponseContext<'a> {
    decoded: &'a DecodedSelectorRequest,
    admission: &'a RootSelectorAdmission,
    request: &'a crate::sandbox_provider_protocol::SandboxExecuteRequest,
    request_bytes: &'a [u8],
}

struct AdmittedProviderReply {
    grant: Vec<u8>,
    receipt: Vec<u8>,
    result: Vec<u8>,
    audit: Vec<Vec<u8>>,
    output_stream: Option<Vec<u8>>,
}

impl<A: RootSelectorAuthoritySource, P: RootSelectorProvider> RootSelectorServer<A, P> {
    #[must_use]
    pub const fn new(
        authority: A,
        provider: P,
        evaluator_uid: u32,
        initial_io_timeout: Duration,
    ) -> Self {
        Self {
            authority,
            provider,
            evaluator_uid,
            initial_io_timeout,
        }
    }

    /// Bind the fixed root-owned selector endpoint.
    ///
    /// # Errors
    /// Refuses an existing endpoint, non-root parent, insecure parent mode, or bind failure.
    pub fn bind_fixed() -> Result<UnixListener, RootSelectorServiceError> {
        let path = Path::new(crate::selector::SANDBOX_SELECTOR_SOCKET);
        let parent = path.parent().ok_or(RootSelectorServiceError::Io)?;
        let metadata = std::fs::metadata(parent).map_err(|_| RootSelectorServiceError::Io)?;
        if metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
            return Err(RootSelectorServiceError::Io);
        }
        let listener = UnixListener::bind(path).map_err(|_| RootSelectorServiceError::Io)?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(SOCKET_MODE))
            .map_err(|_| RootSelectorServiceError::Io)?;
        Ok(listener)
    }

    /// Accept and process one evaluator connection.
    ///
    /// # Errors
    /// Rejects a foreign peer or any malformed, unauthorized, or unauthenticated transition.
    pub fn serve_once(&mut self, listener: &UnixListener) -> Result<(), RootSelectorServiceError> {
        let (mut stream, _) = listener
            .accept()
            .map_err(|_| RootSelectorServiceError::Io)?;
        let peer = socket_peercred(stream.as_fd()).map_err(|_| RootSelectorServiceError::Io)?;
        if peer.uid.as_raw() != self.evaluator_uid {
            return Err(RootSelectorServiceError::InvalidRequest);
        }
        stream
            .set_read_timeout(Some(self.initial_io_timeout))
            .map_err(|_| RootSelectorServiceError::Io)?;
        stream
            .set_write_timeout(Some(self.initial_io_timeout))
            .map_err(|_| RootSelectorServiceError::Io)?;
        self.handle_connection(&mut stream)
    }

    fn handle_connection(
        &mut self,
        stream: &mut UnixStream,
    ) -> Result<(), RootSelectorServiceError> {
        let decoded = match read_selector_request(stream) {
            Ok(decoded) => decoded,
            Err(error) => {
                let control = error
                    .to_canonical_cbor()
                    .map_err(|_| RootSelectorServiceError::Io)?;
                return write_selector_response(stream, &control, &[]);
            }
        };
        let Some(requirement) = decoded.evaluation.sandbox_requirement.as_ref() else {
            return Self::write_local_error(
                stream,
                &decoded,
                SandboxLocalErrorPhase::BeforeSpx1,
                SandboxLocalErrorCode::RequestAuthorityMismatch,
                None,
            );
        };
        let Some((plan, admission)) = self.resolve_admission(stream, &decoded, requirement)? else {
            return Ok(());
        };
        let execute_request = crate::sandbox_provider_protocol::SandboxExecuteRequest::for_selector(
            RequestAuthority {
                request_id: decoded.encoded.provider_request_id,
                apt1_digest: requirement.apt1_digest,
                policy_epoch: requirement.policy_epoch,
                nonce: plan.request_nonce,
            },
            decoded.encoded.attempt_id,
            plan.execute_authority,
            decoded.attempt.capability_ids.clone(),
            PayloadDescriptor {
                byte_length: decoded.encoded.attempt_stream.len() as u64,
                digest: sandbox_input_digest(&decoded.encoded.attempt_stream),
            },
            plan.network_plans,
        );
        let Ok(execute_request) = execute_request else {
            return Self::write_local_error(
                stream,
                &decoded,
                SandboxLocalErrorPhase::BeforeSpx1,
                SandboxLocalErrorCode::RequestAuthorityMismatch,
                None,
            );
        };
        let execute_bytes = execute_request
            .to_canonical_cbor()
            .map_err(|_| RootSelectorServiceError::AuthorityMismatch)?;
        let provider_reply = self.provider.execute(
            &execute_request,
            &decoded.encoded.attempt_stream,
            Duration::from_millis(decoded.attempt.watchdog_ms),
        );
        Self::write_provider_reply(
            stream,
            ProviderResponseContext {
                decoded: &decoded,
                admission: &admission,
                request: &execute_request,
                request_bytes: &execute_bytes,
            },
            provider_reply,
        )
    }

    fn resolve_admission(
        &mut self,
        stream: &mut UnixStream,
        decoded: &DecodedSelectorRequest,
        requirement: &SandboxRequirement,
    ) -> Result<Option<(RootSelectorCasePlan, RootSelectorAdmission)>, RootSelectorServiceError>
    {
        let expected_request = derived_id(decoded.evaluation.request_id, decoded.ordinal);
        let expected_attempt = derived_id(decoded.evaluation.request_id, decoded.ordinal ^ 0x8000);
        if decoded.encoded.provider_request_id != expected_request
            || decoded.encoded.attempt_id != expected_attempt
        {
            Self::write_local_error(
                stream,
                decoded,
                SandboxLocalErrorPhase::BeforeSpx1,
                SandboxLocalErrorCode::RequestAuthorityMismatch,
                None,
            )?;
            return Ok(None);
        }
        let plan = match self
            .authority
            .resolve_case(&decoded.evaluation, decoded.ordinal)
        {
            Ok(plan) => plan,
            Err(
                RootSelectorServiceError::AuthorityUnavailable
                | RootSelectorServiceError::Admission,
            ) => {
                Self::write_local_error(
                    stream,
                    decoded,
                    SandboxLocalErrorPhase::BeforeSpx1,
                    SandboxLocalErrorCode::PolicyUnavailable,
                    None,
                )?;
                return Ok(None);
            }
            Err(RootSelectorServiceError::AuthorityMismatch) => {
                Self::write_local_error(
                    stream,
                    decoded,
                    SandboxLocalErrorPhase::BeforeSpx1,
                    SandboxLocalErrorCode::RequestAuthorityMismatch,
                    None,
                )?;
                return Ok(None);
            }
            Err(error) => return Err(error),
        };
        if plan.expected_attempt != decoded.attempt {
            Self::write_local_error(
                stream,
                decoded,
                SandboxLocalErrorPhase::BeforeSpx1,
                SandboxLocalErrorCode::RequestAuthorityMismatch,
                None,
            )?;
            return Ok(None);
        }
        if validate_execute_authority(decoded, &plan, requirement).is_err() {
            Self::write_local_error(
                stream,
                decoded,
                SandboxLocalErrorPhase::BeforeSpx1,
                SandboxLocalErrorCode::RequestAuthorityMismatch,
                None,
            )?;
            return Ok(None);
        }
        let admission = match plan.admission.admit(&decoded.evaluation, requirement) {
            Ok(admission) => admission,
            Err(error) => {
                Self::write_local_error(
                    stream,
                    decoded,
                    SandboxLocalErrorPhase::BeforeSpx1,
                    if error == RootSelectorServiceError::AuthorityMismatch {
                        SandboxLocalErrorCode::RequestAuthorityMismatch
                    } else {
                        SandboxLocalErrorCode::PolicyUnavailable
                    },
                    None,
                )?;
                return Ok(None);
            }
        };
        Ok(Some((plan, admission)))
    }

    fn write_provider_reply(
        stream: &mut UnixStream,
        context: ProviderResponseContext<'_>,
        reply: Result<RootSelectorProviderReply, RootSelectorServiceError>,
    ) -> Result<(), RootSelectorServiceError> {
        let reply = match reply {
            Ok(reply) => reply,
            Err(error) => {
                return Self::write_local_error(
                    stream,
                    context.decoded,
                    SandboxLocalErrorPhase::AfterSpx1BeforeAdmission,
                    if error == RootSelectorServiceError::ProviderEvidence {
                        SandboxLocalErrorCode::ProviderEvidenceInvalid
                    } else {
                        SandboxLocalErrorCode::ProviderUnavailable
                    },
                    None,
                );
            }
        };
        match reply {
            RootSelectorProviderReply::Admitted {
                grant,
                receipt,
                result,
                audit,
                output_stream,
            } => Self::write_admitted_reply(
                stream,
                &context,
                &AdmittedProviderReply {
                    grant,
                    receipt,
                    result,
                    audit,
                    output_stream,
                },
            ),
            RootSelectorProviderReply::BeforeAdmission { result } => {
                if context
                    .admission
                    .authenticate_pre_admission_result(context.request, &result)
                    .is_err()
                {
                    return Self::write_local_error(
                        stream,
                        context.decoded,
                        SandboxLocalErrorPhase::AfterSpx1BeforeAdmission,
                        SandboxLocalErrorCode::ProviderEvidenceInvalid,
                        None,
                    );
                }
                Self::write_authenticated_reply(
                    stream,
                    context.decoded,
                    &AuthenticatedSelectorReply {
                        execute_request: context.request_bytes,
                        terminal: AuthenticatedSelectorTerminal::ProviderResult {
                            result: &result,
                            grant: None,
                            receipt: None,
                            audit: &[],
                        },
                        output_stream: None,
                    },
                )
            }
            RootSelectorProviderReply::Error { error } => {
                if context
                    .admission
                    .authenticate_provider_error(context.request, &error)
                    .is_err()
                {
                    return Self::write_local_error(
                        stream,
                        context.decoded,
                        SandboxLocalErrorPhase::AfterSpx1BeforeAdmission,
                        SandboxLocalErrorCode::ProviderEvidenceInvalid,
                        None,
                    );
                }
                Self::write_authenticated_reply(
                    stream,
                    context.decoded,
                    &AuthenticatedSelectorReply {
                        execute_request: context.request_bytes,
                        terminal: AuthenticatedSelectorTerminal::ProviderError(&error),
                        output_stream: None,
                    },
                )
            }
        }
    }

    fn write_admitted_reply(
        stream: &mut UnixStream,
        context: &ProviderResponseContext<'_>,
        reply: &AdmittedProviderReply,
    ) -> Result<(), RootSelectorServiceError> {
        let Ok(grant_record) = context
            .admission
            .authenticate_grant(context.request, &reply.grant)
        else {
            return Self::write_local_error(
                stream,
                context.decoded,
                SandboxLocalErrorPhase::AfterSpx1BeforeAdmission,
                SandboxLocalErrorCode::ProviderEvidenceInvalid,
                None,
            );
        };
        let grant_digest = grant_record.grant_digest;
        let authenticated = context.admission.authenticate_after_grant(
            context.request,
            grant_record,
            &reply.receipt,
            &reply.result,
            &reply.audit,
        );
        let Ok(authenticated) = authenticated else {
            return Self::write_local_error(
                stream,
                context.decoded,
                SandboxLocalErrorPhase::AfterAdmission,
                SandboxLocalErrorCode::ProviderEvidenceInvalid,
                Some(grant_digest),
            );
        };
        if !output_matches(authenticated.result(), reply.output_stream.as_deref()) {
            return Self::write_local_error(
                stream,
                context.decoded,
                SandboxLocalErrorPhase::AfterAdmission,
                SandboxLocalErrorCode::ProviderEvidenceInvalid,
                Some(grant_digest),
            );
        }
        Self::write_authenticated_reply(
            stream,
            context.decoded,
            &AuthenticatedSelectorReply {
                execute_request: context.request_bytes,
                terminal: AuthenticatedSelectorTerminal::ProviderResult {
                    result: &reply.result,
                    grant: Some(&reply.grant),
                    receipt: Some(&reply.receipt),
                    audit: &reply.audit,
                },
                output_stream: reply.output_stream.as_deref(),
            },
        )
    }

    fn write_authenticated_reply(
        stream: &mut UnixStream,
        decoded: &DecodedSelectorRequest,
        reply: &AuthenticatedSelectorReply<'_>,
    ) -> Result<(), RootSelectorServiceError> {
        let (control, trailing) = encode_authenticated_reply(&decoded.encoded, reply)
            .map_err(|_| RootSelectorServiceError::ProviderEvidence)?;
        write_selector_response(stream, &control, &trailing)
    }

    fn write_local_error(
        stream: &mut UnixStream,
        decoded: &DecodedSelectorRequest,
        phase: SandboxLocalErrorPhase,
        code: SandboxLocalErrorCode,
        grant: Option<[u8; 32]>,
    ) -> Result<(), RootSelectorServiceError> {
        let error = SandboxLocalError {
            phase,
            operation: Some(SandboxProviderOperation::Execute),
            request_id: Some(decoded.encoded.provider_request_id),
            attempt_id: Some(decoded.encoded.attempt_id),
            agr1_digest: grant,
            code,
            safe_detail: None,
        };
        let control = error
            .to_canonical_cbor()
            .map_err(|_| RootSelectorServiceError::Io)?;
        write_selector_response(stream, &control, &[])
    }
}

fn read_selector_request(
    stream: &mut UnixStream,
) -> Result<DecodedSelectorRequest, SandboxLocalError> {
    let mut failure = SandboxLocalError {
        phase: SandboxLocalErrorPhase::BeforeSpx1,
        operation: None,
        request_id: None,
        attempt_id: None,
        agr1_digest: None,
        code: SandboxLocalErrorCode::InvalidSelectorRequest,
        safe_detail: None,
    };
    let mut prefix = [0_u8; 4];
    stream
        .read_exact(&mut prefix)
        .map_err(|_| failure.clone())?;
    let length = usize::try_from(u32::from_be_bytes(prefix)).map_err(|_| failure.clone())?;
    if length > CONTROL_LIMIT {
        failure.code = SandboxLocalErrorCode::PayloadLimitExceeded;
        return Err(failure);
    }
    if length == 0 {
        return Err(failure);
    }
    let mut control = Vec::new();
    let received = (&mut *stream).take(length as u64).read_to_end(&mut control);
    crate::selector_protocol::request_identities(&control, &mut failure);
    if received.is_err() || control.len() != length {
        return Err(failure);
    }
    let control = crate::selector_protocol::decode_request_control(control).map_err(|code| {
        failure.code = code;
        failure.clone()
    })?;
    let mut attempt_stream = Vec::new();
    stream
        .take(SANDBOX_PAYLOAD_LIMIT + 1)
        .read_to_end(&mut attempt_stream)
        .map_err(|_| failure.clone())?;
    if attempt_stream.len() as u64 > SANDBOX_PAYLOAD_LIMIT {
        failure.code = SandboxLocalErrorCode::PayloadLimitExceeded;
        return Err(failure);
    }
    decode_request(control, attempt_stream).map_err(|_| failure)
}

fn validate_execute_authority(
    decoded: &DecodedSelectorRequest,
    plan: &RootSelectorCasePlan,
    requirement: &SandboxRequirement,
) -> Result<(), RootSelectorServiceError> {
    let request = &decoded.evaluation;
    let authority = &plan.execute_authority;
    if plan.request_nonce == [0; 16]
        || authority.evr1_digest != request.request_digest
        || authority.cpf1_digest != request.profile_digest
        || authority.cfb1_digest != request.fixture_bundle_digest
        || authority.fixture_digest != decoded.attempt.fixture_digest
        || authority.execution_profile_digest != request.execution_profile_digest
        || authority.lps1_digest != requirement.lps1_digest
        || authority.sim1_digest != requirement.sim1_digest
        || authority.apt1_digest != requirement.apt1_digest
        || plan.admission.policy.policy_digest() != requirement.apt1_digest
        || plan.admission.policy.policy_epoch() != requirement.policy_epoch
    {
        return Err(RootSelectorServiceError::AuthorityMismatch);
    }
    Ok(())
}

fn output_matches(
    result: &crate::sandbox_provider_protocol::SandboxProviderResult,
    output: Option<&[u8]>,
) -> bool {
    match (result.outcome, result.output.as_ref(), output) {
        (SandboxTerminalOutcome::Completed, Some(descriptor), Some(bytes)) => {
            descriptor.byte_length == bytes.len() as u64
                && descriptor.digest == sandbox_output_digest(bytes)
        }
        (
            SandboxTerminalOutcome::Cancelled | SandboxTerminalOutcome::UnavailableAfterAdmission,
            None,
            None,
        ) => true,
        _ => false,
    }
}

fn write_selector_response(
    stream: &mut UnixStream,
    control: &[u8],
    trailing: &[u8],
) -> Result<(), RootSelectorServiceError> {
    let length = u32::try_from(control.len()).map_err(|_| RootSelectorServiceError::Io)?;
    stream
        .write_all(&length.to_be_bytes())
        .and_then(|()| stream.write_all(control))
        .and_then(|()| stream.write_all(trailing))
        .map_err(|_| RootSelectorServiceError::Io)
}

fn sandbox_input_digest(bytes: &[u8]) -> [u8; 32] {
    domain_digest(b"PiglorOS.SandboxInputBytes.v1\0", bytes)
}

fn sandbox_output_digest(bytes: &[u8]) -> [u8; 32] {
    domain_digest(b"PiglorOS.SandboxOutputBytes.v1\0", bytes)
}

fn domain_digest(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(bytes);
    *hasher.finalize().as_bytes()
}
