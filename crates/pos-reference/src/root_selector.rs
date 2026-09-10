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
use crate::provider_transport::StagedOutput;
use crate::sandbox_provider_protocol::{
    ExecuteAuthority, NetworkExchangePlan, PayloadDescriptor, RequestAuthority,
    RootSelectorAdmission, RootSelectorAdmissionInputs, SandboxAdministratorPolicy,
    SandboxLocalError, SandboxLocalErrorCode, SandboxLocalErrorPhase,
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
    /// Exact selected SIM1 bytes.
    pub image_manifest: Vec<u8>,
    /// Exact immutable root-image bytes bound by SIM1.
    pub root_image: Vec<u8>,
    /// Exact executable bytes bound by SIM1 and EVR1.
    pub executable: Vec<u8>,
    /// Exact selected LPS1 bytes.
    pub launch_policy: Vec<u8>,
}

impl RootSelectorAdmissionArtifacts {
    fn admit(
        &self,
        request: &EvaluationRequest,
        attempt: &CaseAttempt,
        network_plans: &[NetworkExchangePlan],
    ) -> Result<RootSelectorAdmission, RootSelectorServiceError> {
        RootSelectorAdmission::establish(
            &self.policy,
            &self.trust,
            &self.revocation,
            &RootSelectorAdmissionInputs {
                provider: SandboxProviderAdmissionInputs {
                    provider_manifest: &self.provider_manifest,
                    provider_binary: &self.provider_binary,
                    broker_hard_caps: &self.broker_hard_caps,
                    conformance_report: &self.conformance_report,
                    host_profile: &self.host_profile,
                    syscall_set: &self.syscall_set,
                },
                image_manifest: &self.image_manifest,
                root_image: &self.root_image,
                executable: &self.executable,
                launch_policy: &self.launch_policy,
                evaluation: request,
                attempt,
                network_plans,
            },
        )
        .or(Err(RootSelectorServiceError::Admission))
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
#[derive(Debug)]
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
        /// Incrementally staged exact framed EAO1 stream, present only for Completed.
        output: Option<StagedOutput>,
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
    /// Both the original and sole exact recovery stream ended before a terminal.
    Incomplete {
        /// Authenticated AGR1 digest retained across the replay, when admission occurred.
        agr1_digest: Option<[u8; 32]>,
    },
    /// Provider framing or evidence was invalid; a retained AGR1 fixes its phase.
    EvidenceInvalid {
        /// Authenticated AGR1 digest retained across the failed stream, when present.
        agr1_digest: Option<[u8; 32]>,
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
        admission: &RootSelectorAdmission,
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
    output: Option<StagedOutput>,
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
        bind_selector_listener(Path::new(crate::selector::SANDBOX_SELECTOR_SOCKET), 0)
    }

    /// Accept and process one evaluator connection.
    ///
    /// # Errors
    /// Rejects a foreign peer or any malformed, unauthorized, or unauthenticated transition.
    pub fn serve_once(&mut self, listener: &UnixListener) -> Result<(), RootSelectorServiceError> {
        let (mut stream, _) = listener.accept().or(Err(RootSelectorServiceError::Io))?;
        let peer = socket_peercred(stream.as_fd()).or(Err(RootSelectorServiceError::Io))?;
        if peer.uid.as_raw() != self.evaluator_uid {
            return Err(RootSelectorServiceError::InvalidRequest);
        }
        stream
            .set_read_timeout(Some(self.initial_io_timeout))
            .or(Err(RootSelectorServiceError::Io))?;
        stream
            .set_write_timeout(Some(self.initial_io_timeout))
            .or(Err(RootSelectorServiceError::Io))?;
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
                    .or(Err(RootSelectorServiceError::Io))?;
                return write_selector_response(stream, &control, None);
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
            .or(Err(RootSelectorServiceError::AuthorityMismatch))?;
        let provider_reply = self.provider.execute(
            &execute_request,
            &decoded.encoded.attempt_stream,
            Duration::from_millis(decoded.attempt.watchdog_ms),
            &admission,
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
        let Ok(admission) = plan.admission.admit(
            &decoded.evaluation,
            &plan.expected_attempt,
            &plan.network_plans,
        ) else {
            Self::write_local_error(
                stream,
                decoded,
                SandboxLocalErrorPhase::BeforeSpx1,
                SandboxLocalErrorCode::PolicyUnavailable,
                None,
            )?;
            return Ok(None);
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
                output,
            } => Self::write_admitted_reply(
                stream,
                &context,
                AdmittedProviderReply {
                    grant,
                    receipt,
                    result,
                    audit,
                    output,
                },
            ),
            RootSelectorProviderReply::BeforeAdmission { result } => {
                Self::write_pre_admission_result(stream, &context, &result)
            }
            RootSelectorProviderReply::Error { error } => {
                Self::write_pre_admission_error(stream, &context, &error)
            }
            RootSelectorProviderReply::Incomplete { agr1_digest } => Self::write_local_error(
                stream,
                context.decoded,
                agr1_digest.map_or(SandboxLocalErrorPhase::AfterSpx1BeforeAdmission, |_| {
                    SandboxLocalErrorPhase::AfterAdmission
                }),
                if agr1_digest.is_some() {
                    SandboxLocalErrorCode::ProviderTerminalUnavailable
                } else {
                    SandboxLocalErrorCode::ProviderUnavailable
                },
                agr1_digest,
            ),
            RootSelectorProviderReply::EvidenceInvalid { agr1_digest } => Self::write_local_error(
                stream,
                context.decoded,
                agr1_digest.map_or(SandboxLocalErrorPhase::AfterSpx1BeforeAdmission, |_| {
                    SandboxLocalErrorPhase::AfterAdmission
                }),
                SandboxLocalErrorCode::ProviderEvidenceInvalid,
                agr1_digest,
            ),
        }
    }

    fn write_pre_admission_result(
        stream: &mut UnixStream,
        context: &ProviderResponseContext<'_>,
        result: &[u8],
    ) -> Result<(), RootSelectorServiceError> {
        if context
            .admission
            .authenticate_pre_admission_result(context.request, result)
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
                    result,
                    grant: None,
                    receipt: None,
                    audit: &[],
                },
                output: None,
            },
            None,
        )
    }

    fn write_pre_admission_error(
        stream: &mut UnixStream,
        context: &ProviderResponseContext<'_>,
        error: &[u8],
    ) -> Result<(), RootSelectorServiceError> {
        if context
            .admission
            .authenticate_provider_error(context.request, error)
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
                terminal: AuthenticatedSelectorTerminal::ProviderError(error),
                output: None,
            },
            None,
        )
    }

    fn write_admitted_reply(
        stream: &mut UnixStream,
        context: &ProviderResponseContext<'_>,
        mut reply: AdmittedProviderReply,
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
        if !output_matches(authenticated.result(), reply.output.as_ref()) {
            return Self::write_local_error(
                stream,
                context.decoded,
                SandboxLocalErrorPhase::AfterAdmission,
                SandboxLocalErrorCode::ProviderEvidenceInvalid,
                Some(grant_digest),
            );
        }
        let output_descriptor = reply
            .output
            .as_ref()
            .map(|output| output.descriptor().clone());
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
                output: output_descriptor.as_ref(),
            },
            reply.output.as_mut(),
        )
    }

    fn write_authenticated_reply(
        stream: &mut UnixStream,
        decoded: &DecodedSelectorRequest,
        reply: &AuthenticatedSelectorReply<'_>,
        output: Option<&mut StagedOutput>,
    ) -> Result<(), RootSelectorServiceError> {
        let control = encode_authenticated_reply(&decoded.encoded, reply)
            .or(Err(RootSelectorServiceError::ProviderEvidence))?;
        write_selector_response(stream, &control, output)
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
            .or(Err(RootSelectorServiceError::Io))?;
        write_selector_response(stream, &control, None)
    }
}

fn bind_selector_listener(
    path: &Path,
    owner_uid: u32,
) -> Result<UnixListener, RootSelectorServiceError> {
    let parent = path.parent().ok_or(RootSelectorServiceError::Io)?;
    let metadata = std::fs::metadata(parent).or(Err(RootSelectorServiceError::Io))?;
    if metadata.uid() != owner_uid || metadata.mode() & 0o022 != 0 {
        return Err(RootSelectorServiceError::Io);
    }
    let listener = UnixListener::bind(path).or(Err(RootSelectorServiceError::Io))?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(SOCKET_MODE))
        .or(Err(RootSelectorServiceError::Io))?;
    Ok(listener)
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
    let prefix_failure = failure.clone();
    stream.read_exact(&mut prefix).or(Err(prefix_failure))?;
    let length_failure = failure.clone();
    let length = usize::try_from(u32::from_be_bytes(prefix)).or(Err(length_failure))?;
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
    let stream_failure = failure.clone();
    stream
        .take(SANDBOX_PAYLOAD_LIMIT + 1)
        .read_to_end(&mut attempt_stream)
        .or(Err(stream_failure))?;
    if attempt_stream.len() as u64 > SANDBOX_PAYLOAD_LIMIT {
        failure.code = SandboxLocalErrorCode::PayloadLimitExceeded;
        return Err(failure);
    }
    decode_request(control, attempt_stream).or(Err(failure))
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
    output: Option<&StagedOutput>,
) -> bool {
    match (result.outcome, result.output.as_ref(), output) {
        (SandboxTerminalOutcome::Completed, Some(descriptor), Some(output)) => {
            descriptor == output.descriptor()
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
    output: Option<&mut StagedOutput>,
) -> Result<(), RootSelectorServiceError> {
    let length = u32::try_from(control.len()).or(Err(RootSelectorServiceError::Io))?;
    stream
        .write_all(&length.to_be_bytes())
        .and_then(|()| stream.write_all(control))
        .or(Err(RootSelectorServiceError::Io))
        .and_then(|()| output.map_or(Ok(()), |output| output.copy_to(stream)))
}

fn sandbox_input_digest(bytes: &[u8]) -> [u8; 32] {
    domain_digest(b"PiglorOS.SandboxInputBytes.v1\0", bytes)
}

fn domain_digest(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(bytes);
    *hasher.finalize().as_bytes()
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use std::io::{Read, Write};
    use std::net::Shutdown;

    use crate::evaluator::{AttemptArtifact, AttemptTransportCaps};
    use crate::evaluator_protocol::{ImplementationIdentity, OutputCapability, SubjectAdapterKind};
    use crate::profile::DeterministicBudget;

    use super::*;

    pub(super) type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

    struct UnusedAuthority;

    impl RootSelectorAuthoritySource for UnusedAuthority {
        fn resolve_case(
            &mut self,
            _: &EvaluationRequest,
            _: u16,
        ) -> Result<RootSelectorCasePlan, RootSelectorServiceError> {
            Err(RootSelectorServiceError::AuthorityUnavailable)
        }
    }

    struct UnusedProvider;

    impl RootSelectorProvider for UnusedProvider {
        fn execute(
            &mut self,
            _: &crate::sandbox_provider_protocol::SandboxExecuteRequest,
            _: &[u8],
            _: Duration,
            _: &RootSelectorAdmission,
        ) -> Result<RootSelectorProviderReply, RootSelectorServiceError> {
            Err(RootSelectorServiceError::ProviderUnavailable)
        }
    }

    pub(super) fn selector_request_without_sandbox_requirement() -> TestResult<(Vec<u8>, Vec<u8>)> {
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
                capability_digest: [0; 32],
                report_bytes_limit: 1,
                diagnostic_bytes_limit: 0,
            },
            evaluator_protocol_digest: [12; 32],
            evaluator_hard_caps_digest: [13; 32],
            sandbox_requirement: None,
            request_digest: [0; 32],
        };
        request.output_capability.capability_digest =
            request.expected_output_capability_digest()?;
        request.request_digest = request.digest()?;
        let artifact = |bytes: Vec<u8>| AttemptArtifact {
            digest: *blake3::hash(&bytes).as_bytes(),
            bytes,
        };
        let attempt = CaseAttempt {
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
                output_bytes: 1,
                storage_bytes: 1,
                execution_steps: 1,
                simulation_time_ns: 1,
            },
            watchdog_ms: 100,
            network_allowed: false,
            capability_ids: vec!["execute".to_owned()],
            transport_caps: AttemptTransportCaps {
                max_member_bytes: 1024,
                max_attempt_bytes: 4096,
            },
        };
        let request_bytes = request.to_canonical_cbor()?;
        let encoded =
            crate::selector_protocol::encode_request(&request, &request_bytes, &attempt, 0)
                .map_err(|_| "selector test request encoding failed")?;
        Ok((encoded.control, encoded.attempt_stream))
    }

    fn write_selector_request(
        stream: &mut UnixStream,
        control: &[u8],
        attempt_stream: &[u8],
    ) -> TestResult {
        stream.write_all(&u32::try_from(control.len())?.to_be_bytes())?;
        stream.write_all(control)?;
        stream.write_all(attempt_stream)?;
        stream.shutdown(Shutdown::Write)?;
        Ok(())
    }

    #[test]
    fn selector_listener_requires_private_owned_parent_and_exact_socket_mode() -> TestResult {
        let temporary = tempfile::tempdir()?;
        let path = temporary.path().join("selector.sock");
        let owner_uid = std::fs::metadata(temporary.path())?.uid();
        assert!(bind_selector_listener(Path::new(""), owner_uid).is_err());
        assert!(bind_selector_listener(
            &temporary.path().join("missing").join("selector.sock"),
            owner_uid,
        )
        .is_err());
        assert!(bind_selector_listener(&path, owner_uid ^ 1).is_err());
        let listener = bind_selector_listener(&path, owner_uid)?;
        assert_eq!(std::fs::metadata(&path)?.mode() & 0o7777, SOCKET_MODE);
        assert!(bind_selector_listener(&path, owner_uid).is_err());
        drop(listener);
        std::fs::remove_file(&path)?;

        std::fs::set_permissions(temporary.path(), std::fs::Permissions::from_mode(0o777))?;
        assert!(bind_selector_listener(&path, owner_uid).is_err());
        Ok(())
    }

    #[test]
    fn selector_listener_authenticates_peer_before_rejecting_malformed_framing() -> TestResult {
        let temporary = tempfile::tempdir()?;
        let path = temporary.path().join("selector.sock");
        let owner_uid = std::fs::metadata(temporary.path())?.uid();
        let listener = bind_selector_listener(&path, owner_uid)?;
        let client_path = path.clone();
        let client = std::thread::spawn(move || -> std::io::Result<Vec<u8>> {
            let mut stream = UnixStream::connect(client_path)?;
            stream.write_all(&0_u32.to_be_bytes())?;
            stream.shutdown(std::net::Shutdown::Write)?;
            let mut response = Vec::new();
            stream.read_to_end(&mut response)?;
            Ok(response)
        });
        let mut server = RootSelectorServer::new(
            UnusedAuthority,
            UnusedProvider,
            owner_uid,
            Duration::from_secs(1),
        );
        server.serve_once(&listener)?;
        let response = client.join().map_err(|_| "selector client panicked")??;
        assert!(!response.is_empty());

        let foreign_path = path;
        let foreign = std::thread::spawn(move || UnixStream::connect(foreign_path).map(drop));
        let mut server = RootSelectorServer::new(
            UnusedAuthority,
            UnusedProvider,
            owner_uid ^ 1,
            Duration::from_secs(1),
        );
        assert_eq!(
            server.serve_once(&listener),
            Err(RootSelectorServiceError::InvalidRequest)
        );
        foreign.join().map_err(|_| "foreign client panicked")??;
        Ok(())
    }

    #[test]
    fn selector_reader_classifies_each_bounded_framing_failure() -> TestResult {
        let (mut reader, writer) = UnixStream::pair()?;
        drop(writer);
        let Err(error) = read_selector_request(&mut reader) else {
            return Err("closed selector stream unexpectedly decoded".into());
        };
        assert_eq!(error.code, SandboxLocalErrorCode::InvalidSelectorRequest);

        let (mut reader, mut writer) = UnixStream::pair()?;
        writer.write_all(&(u32::try_from(CONTROL_LIMIT)? + 1).to_be_bytes())?;
        writer.shutdown(Shutdown::Write)?;
        let Err(error) = read_selector_request(&mut reader) else {
            return Err("oversized selector control unexpectedly decoded".into());
        };
        assert_eq!(error.code, SandboxLocalErrorCode::PayloadLimitExceeded);

        let (mut reader, mut writer) = UnixStream::pair()?;
        writer.write_all(&0_u32.to_be_bytes())?;
        writer.shutdown(Shutdown::Write)?;
        let Err(error) = read_selector_request(&mut reader) else {
            return Err("empty selector control unexpectedly decoded".into());
        };
        assert_eq!(error.code, SandboxLocalErrorCode::InvalidSelectorRequest);

        let (mut reader, mut writer) = UnixStream::pair()?;
        writer.write_all(&2_u32.to_be_bytes())?;
        writer.write_all(&[0xf6])?;
        writer.shutdown(Shutdown::Write)?;
        let Err(error) = read_selector_request(&mut reader) else {
            return Err("truncated selector control unexpectedly decoded".into());
        };
        assert_eq!(error.code, SandboxLocalErrorCode::InvalidSelectorRequest);

        let (mut reader, mut writer) = UnixStream::pair()?;
        writer.write_all(&1_u32.to_be_bytes())?;
        writer.write_all(&[0xf6])?;
        writer.shutdown(Shutdown::Write)?;
        let Err(error) = read_selector_request(&mut reader) else {
            return Err("malformed selector control unexpectedly decoded".into());
        };
        assert_eq!(error.code, SandboxLocalErrorCode::InvalidSelectorRequest);
        Ok(())
    }

    #[test]
    fn selector_missing_requirement_returns_a_bounded_local_error() -> TestResult {
        let (control, attempt_stream) = selector_request_without_sandbox_requirement()?;
        let (mut server_stream, mut client_stream) = UnixStream::pair()?;
        write_selector_request(&mut client_stream, &control, &attempt_stream)?;
        let mut server =
            RootSelectorServer::new(UnusedAuthority, UnusedProvider, 0, Duration::from_secs(1));
        server.handle_connection(&mut server_stream)?;
        server_stream.shutdown(Shutdown::Write)?;

        let mut response = Vec::new();
        client_stream.read_to_end(&mut response)?;
        let prefix: [u8; 4] = response
            .get(..4)
            .ok_or("selector local error response lacks prefix")?
            .try_into()?;
        let control_length = usize::try_from(u32::from_be_bytes(prefix))?;
        assert_eq!(response.len(), 4 + control_length);
        let error = SandboxLocalError::from_canonical_cbor(&response[4..])?;
        assert_eq!(error.phase, SandboxLocalErrorPhase::BeforeSpx1);
        assert_eq!(error.code, SandboxLocalErrorCode::RequestAuthorityMismatch);
        Ok(())
    }

    #[test]
    fn selector_response_writes_control_and_staged_output_or_reports_io() -> TestResult {
        let payload = b"selector output";
        let descriptor = PayloadDescriptor {
            byte_length: u64::try_from(payload.len())?,
            digest: domain_digest(b"PiglorOS.SandboxOutputBytes.v1\0", payload),
        };
        let mut source = payload.as_slice();
        let mut staged = StagedOutput::stage_verified(&mut source, descriptor)?;
        let (mut writer, mut reader) = UnixStream::pair()?;
        write_selector_response(&mut writer, b"control", Some(&mut staged))?;
        writer.shutdown(Shutdown::Write)?;
        let mut response = Vec::new();
        reader.read_to_end(&mut response)?;
        assert_eq!(
            response,
            [7_u32.to_be_bytes().as_slice(), b"control", payload].concat()
        );

        let (mut writer, reader) = UnixStream::pair()?;
        drop(reader);
        assert_eq!(
            write_selector_response(&mut writer, b"control", None),
            Err(RootSelectorServiceError::Io)
        );
        Ok(())
    }

    #[test]
    fn selector_output_shape_requires_the_authenticated_terminal_shape() -> TestResult {
        let descriptor = PayloadDescriptor {
            byte_length: 0,
            digest: domain_digest(b"PiglorOS.SandboxOutputBytes.v1\0", b""),
        };
        let mut source = b"".as_slice();
        let staged = StagedOutput::stage_verified(&mut source, descriptor.clone())?;
        let result = |outcome, output| crate::sandbox_provider_protocol::SandboxProviderResult {
            request_id: [1; 16],
            attempt_id: [2; 16],
            outcome,
            output,
            agr1_digest: None,
            spr1_digest: None,
            operational_events: Vec::new(),
            runtime_attestation_key_id: "runtime".to_owned(),
            result_digest: [3; 32],
            signature: [4; 64],
        };

        assert!(output_matches(
            &result(SandboxTerminalOutcome::Completed, Some(descriptor.clone())),
            Some(&staged)
        ));
        assert!(!output_matches(
            &result(
                SandboxTerminalOutcome::Completed,
                Some(PayloadDescriptor {
                    byte_length: 1,
                    ..descriptor
                })
            ),
            Some(&staged)
        ));
        assert!(output_matches(
            &result(SandboxTerminalOutcome::Cancelled, None),
            None
        ));
        assert!(output_matches(
            &result(SandboxTerminalOutcome::UnavailableAfterAdmission, None),
            None
        ));
        assert!(!output_matches(
            &result(SandboxTerminalOutcome::Rejected, None),
            None
        ));
        Ok(())
    }
}

#[cfg(test)]
mod coverage_tests {
    use std::io::{Read, Write};
    use std::net::Shutdown;

    use super::*;

    #[test]
    fn selector_framing_reads_a_complete_request_and_writes_a_bounded_response() {
        let (control, attempt_stream) =
            tests::selector_request_without_sandbox_requirement().expect("selector fixture");
        let (mut server, mut client) = UnixStream::pair().expect("socket pair");
        client
            .write_all(
                &u32::try_from(control.len())
                    .expect("control length")
                    .to_be_bytes(),
            )
            .expect("control prefix");
        client.write_all(&control).expect("control");
        client.write_all(&attempt_stream).expect("attempt stream");
        client.shutdown(Shutdown::Write).expect("close request");
        assert!(read_selector_request(&mut server).is_ok());

        let (mut writer, mut reader) = UnixStream::pair().expect("response pair");
        write_selector_response(&mut writer, b"control", None).expect("response write");
        writer.shutdown(Shutdown::Write).expect("close response");
        let mut response = Vec::new();
        reader.read_to_end(&mut response).expect("response read");
        assert_eq!(
            response,
            [7_u32.to_be_bytes().as_slice(), b"control"].concat()
        );
    }
}
