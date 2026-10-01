//! Private ADR-109 coordinator between the Unix listener and the Gateway's
//! one erasure host (ADR-109 revision 9, Decision 1).
//!
//! The coordinator holds no store adapter. It keeps the ADR-107 credentials,
//! the FAH1 record and the session identity digest on the listener thread,
//! builds and signs every FAC1 and FRP1 there, and submits the five private
//! journal commands (ADR-109 revision 9) and the sixth, classifier
//! registration command (ADR-109 revision 12) to the `StoreExecutor` that
//! owns the host. A committed or recovered Fork is released only after that
//! sixth command registers its profile-selected classifier in the executor.

use std::{
    io,
    os::unix::net::{UnixListener, UnixStream},
};

use ciborium::value::Value;
use pos_core::{
    ForkAdmissionCommandCodecErrorV1, ForkAdmissionErrorV1, ForkAdmissionHostCommandV1,
    ForkAdmissionHostRecordV1, ForkAdmissionOperationKindV1, ForkAdmissionOperationResultV1,
    ForkAdmissionRecoveryCommandV1, ForkAdmissionRecoveryProofV1, ForkCreateCommandV1, Hash,
    PrincipalOwnerCommandV1, TimelineId,
};
use pos_runtime::ErasureExecutionHostV1;
use pos_store::{
    ForkAdmissionAuthoritySessionV1, ForkDeliveryClaimOutcomeV1, ForkDeliveryClaimV1,
    ForkDeliveryExecutionV1, ForkDeliveryJournalErrorV1, ForkDeliveryStartupOutcomeV1,
    ForkDeliveryStateV1, ForkDeliveryTupleV1,
};

use crate::{
    executor::{
        ForkAdmissionSubmissionErrorV1, ForkAdmissionSubmissionV1, ForkAdmissionSubmitterV1,
        ForkClassifierRegistrationV1, ForkDeliveryMarkV1,
    },
    local_fork_authentication::{
        LocalForkAuthenticationCredentialsV1, LocalForkAuthenticationErrorV1,
        ResolvedLocalAuthenticationV1,
    },
    local_fork_listener::{
        read_completed_request, write_response, CompletedLocalForkAdmissionV1,
        LocalForkAdmissionCodeV1, LocalForkAdmissionRequestV1, LocalForkAdmissionResponseV1,
        LocalForkFrameErrorV1,
    },
};

/// The private commands the listener thread submits to the executor that
/// owns the host: the five journal commands of ADR-109 revision 9, Decision 1
/// item 4, and the classifier registration of revision 12.
pub(super) trait LocalForkDeliveryJournalV1: Send {
    fn claim(
        &mut self,
        tuple: ForkDeliveryTupleV1,
    ) -> ForkAdmissionSubmissionV1<ForkDeliveryClaimOutcomeV1>;

    fn cancel(&mut self, claim: ForkDeliveryClaimV1) -> ForkAdmissionSubmissionV1<()>;

    fn execute(
        &mut self,
        claim: ForkDeliveryClaimV1,
        command: &ForkAdmissionHostCommandV1,
    ) -> ForkAdmissionSubmissionV1<ForkDeliveryExecutionV1>;

    fn recover(
        &mut self,
        tuple: ForkDeliveryTupleV1,
        proof: &ForkAdmissionRecoveryProofV1,
        principal: Hash,
    ) -> ForkAdmissionSubmissionV1<ForkAdmissionOperationResultV1>;

    fn mark(
        &mut self,
        claim: ForkDeliveryClaimV1,
        mark: ForkDeliveryMarkV1,
    ) -> ForkAdmissionSubmissionV1<()>;

    fn register(
        &mut self,
        child: TimelineId,
        admission_digest: Hash,
    ) -> ForkAdmissionSubmissionV1<ForkClassifierRegistrationV1>;
}

impl LocalForkDeliveryJournalV1 for ForkAdmissionSubmitterV1 {
    fn claim(
        &mut self,
        tuple: ForkDeliveryTupleV1,
    ) -> ForkAdmissionSubmissionV1<ForkDeliveryClaimOutcomeV1> {
        self.claim_fork_delivery(tuple)
    }

    fn cancel(&mut self, claim: ForkDeliveryClaimV1) -> ForkAdmissionSubmissionV1<()> {
        self.cancel_pending_fork_delivery(claim)
    }

    fn execute(
        &mut self,
        claim: ForkDeliveryClaimV1,
        command: &ForkAdmissionHostCommandV1,
    ) -> ForkAdmissionSubmissionV1<ForkDeliveryExecutionV1> {
        self.execute_claimed_fork_delivery(claim, command)
    }

    fn recover(
        &mut self,
        tuple: ForkDeliveryTupleV1,
        proof: &ForkAdmissionRecoveryProofV1,
        principal: Hash,
    ) -> ForkAdmissionSubmissionV1<ForkAdmissionOperationResultV1> {
        self.recover_fork_delivery(tuple, proof, principal)
    }

    fn mark(
        &mut self,
        claim: ForkDeliveryClaimV1,
        mark: ForkDeliveryMarkV1,
    ) -> ForkAdmissionSubmissionV1<()> {
        self.mark_fork_delivery(claim, mark)
    }

    fn register(
        &mut self,
        child: TimelineId,
        admission_digest: Hash,
    ) -> ForkAdmissionSubmissionV1<ForkClassifierRegistrationV1> {
        self.register_fork_classifier(child, admission_digest)
    }
}

/// ADR-109 revision 9 startup step 3: consume one FAO1 challenge on the
/// host's own adapter and read the FAH1 record the session binds. A missing
/// or unequal authority fails before any listener can bind.
pub(super) fn open_fork_admission_session(
    host: &mut ErasureExecutionHostV1,
    credentials: &LocalForkAuthenticationCredentialsV1,
) -> Result<
    (ForkAdmissionAuthoritySessionV1, ForkAdmissionHostRecordV1),
    LocalForkAuthenticationErrorV1,
> {
    let bootstrap = host.fork_admission_bootstrap();
    let session = credentials.open_authority(bootstrap).ok();
    session
        .zip(bootstrap.fork_admission_host_record().ok())
        .ok_or(LocalForkAuthenticationErrorV1::CredentialUnavailable)
}

/// ADR-109 revision 9 startup step 4: reconcile every retained tuple with an
/// FRP1 signed on the startup thread. FRP1 is fence-free, and this never
/// releases a result or Principal: a retained exact operation stays
/// Uncertain for a same-Principal response retry.
pub(super) fn reconcile_startup<E>(
    credentials: &LocalForkAuthenticationCredentialsV1,
    (host, session_identity): (ForkAdmissionHostRecordV1, Hash),
    tuples: Result<Vec<ForkDeliveryTupleV1>, E>,
    mut reconcile: impl FnMut(
        ForkDeliveryTupleV1,
        &ForkAdmissionRecoveryProofV1,
    ) -> Result<ForkDeliveryStartupOutcomeV1, E>,
) -> Result<(), LocalForkAuthenticationErrorV1> {
    let tuples = tuples.map_err(|_| LocalForkAuthenticationErrorV1::CredentialUnavailable)?;
    for tuple in tuples {
        let proof = recovery_proof(credentials, host, session_identity, tuple)?;
        reconcile(tuple, &proof)
            .map_err(|_| LocalForkAuthenticationErrorV1::CredentialUnavailable)?;
    }
    Ok(())
}

/// Listener-thread coordinator: credentials, the FAH1 record, the session
/// identity digest, and the private journal submissions.
pub(super) struct LocalForkAdmissionCoordinatorV1 {
    credentials: LocalForkAuthenticationCredentialsV1,
    host: ForkAdmissionHostRecordV1,
    session_identity: Hash,
    journal: Box<dyn LocalForkDeliveryJournalV1>,
}

impl LocalForkAdmissionCoordinatorV1 {
    /// Bind the listener-thread authority to its journal submissions.
    pub(super) const fn new(
        credentials: LocalForkAuthenticationCredentialsV1,
        host: ForkAdmissionHostRecordV1,
        session_identity: Hash,
        journal: Box<dyn LocalForkDeliveryJournalV1>,
    ) -> Self {
        Self {
            credentials,
            host,
            session_identity,
            journal,
        }
    }

    /// Accept and process one connection with this process-owned authority.
    /// Incomplete, malformed, and unauthenticated requests close silently.
    pub(super) fn serve_one(&mut self, listener: &UnixListener) -> io::Result<()> {
        let (mut stream, _) = listener.accept()?;
        let completed = match read_completed_request(&mut stream, &self.credentials) {
            Ok(completed) => completed,
            Err(LocalForkFrameErrorV1::Invalid) => {
                return write_response(
                    &mut stream,
                    &reject(LocalForkAdmissionCodeV1::InvalidRequest),
                );
            }
            Err(
                LocalForkFrameErrorV1::Malformed
                | LocalForkFrameErrorV1::Peer
                | LocalForkFrameErrorV1::Transport,
            ) => return Ok(()),
        };
        let prepared = self.handle(completed);
        self.write_prepared(&mut stream, &prepared)
    }

    /// Process one complete peer-bound request. No public field becomes an
    /// authority input: all FAC1/FRP1 bytes are built here from the session
    /// identity and protected credentials.
    fn handle(&mut self, completed: CompletedLocalForkAdmissionV1) -> PreparedDeliveryV1 {
        let Ok(delivery_tuple) = delivery_tuple(&completed) else {
            return PreparedDeliveryV1::plain(reject(LocalForkAdmissionCodeV1::InvalidRequest));
        };
        match self.journal.claim(delivery_tuple) {
            Ok(Ok(ForkDeliveryClaimOutcomeV1::Owner(claim))) => {
                self.execute_owned(completed, claim)
            }
            Ok(Ok(ForkDeliveryClaimOutcomeV1::Reconcile(claim, state))) => {
                self.recover(completed, claim, state)
            }
            Ok(Ok(ForkDeliveryClaimOutcomeV1::Busy) | Err(_)) => {
                PreparedDeliveryV1::plain(reject(LocalForkAdmissionCodeV1::Indeterminate))
            }
            Err(error) => PreparedDeliveryV1::plain(reject(submission_code(error))),
        }
    }

    fn write_prepared(
        &mut self,
        stream: &mut UnixStream,
        prepared: &PreparedDeliveryV1,
    ) -> io::Result<()> {
        let write_result = write_response(stream, &prepared.response);
        if let Some(claim) = prepared.claim.filter(|_| prepared.mark_after_write) {
            let mark = if write_result.is_ok() {
                ForkDeliveryMarkV1::Delivered
            } else {
                ForkDeliveryMarkV1::Uncertain
            };
            let marked = matches!(self.journal.mark(claim, mark), Ok(Ok(())));
            if !marked && write_result.is_ok() {
                return Err(io::Error::other("Fork delivery journal transition failed"));
            }
        }
        write_result
    }

    fn execute_owned(
        &mut self,
        completed: CompletedLocalForkAdmissionV1,
        claim: ForkDeliveryClaimV1,
    ) -> PreparedDeliveryV1 {
        let request = completed.request;
        let authentication = match self
            .credentials
            .produce(completed.peer)
            .and_then(|evidence| self.credentials.resolve(evidence))
        {
            Ok(authentication) => authentication,
            Err(error) => return self.cancel_pending(claim, authentication_code(error)),
        };
        let command = match self.command(&request, &authentication) {
            Ok(command) => command,
            Err(error) => return self.cancel_pending(claim, authentication_code(error)),
        };
        match execute_disposition(self.journal.execute(claim, &command)) {
            ExecuteDisposition::Release(result) => self.release_registered(claim, &result, true),
            ExecuteDisposition::Answer(code) => PreparedDeliveryV1::plain(reject(code)),
            ExecuteDisposition::CancelThenAnswer(code) => self.cancel_pending(claim, code),
        }
    }

    /// Definite failures before FAC1 cannot retain a live Pending claim.
    /// A cancellation that cannot complete leaves the caller with only code
    /// 6, and the fenced Pending row waits for startup reconciliation.
    fn cancel_pending(
        &mut self,
        claim: ForkDeliveryClaimV1,
        code: LocalForkAdmissionCodeV1,
    ) -> PreparedDeliveryV1 {
        match self.journal.cancel(claim) {
            Ok(Ok(())) => PreparedDeliveryV1::plain(reject(code)),
            Ok(Err(_)) | Err(_) => {
                PreparedDeliveryV1::plain(reject(LocalForkAdmissionCodeV1::Indeterminate))
            }
        }
    }

    fn recover(
        &mut self,
        completed: CompletedLocalForkAdmissionV1,
        claim: ForkDeliveryClaimV1,
        state: ForkDeliveryStateV1,
    ) -> PreparedDeliveryV1 {
        let tuple = claim.tuple;
        let Ok(authentication) = self
            .credentials
            .produce(completed.peer)
            .and_then(|evidence| self.credentials.resolve(evidence))
        else {
            return PreparedDeliveryV1::plain(reject(LocalForkAdmissionCodeV1::Indeterminate));
        };
        let Ok(proof) = recovery_proof(&self.credentials, self.host, self.session_identity, tuple)
        else {
            return PreparedDeliveryV1::plain(reject(
                LocalForkAdmissionCodeV1::AuthorityUnavailable,
            ));
        };
        self.journal
            .recover(tuple, &proof, authentication.principal_digest())
            .ok()
            .and_then(Result::ok)
            .map_or_else(
                || PreparedDeliveryV1::plain(reject(LocalForkAdmissionCodeV1::Indeterminate)),
                |result| {
                    self.release_registered(claim, &result, state != ForkDeliveryStateV1::Delivered)
                },
            )
    }

    /// Release a committed or recovered result only after a Fork has its
    /// profile-selected classifier registered in the executor (ADR-099
    /// revision 11 section 3; ADR-109 revision 12).
    ///
    /// Any registration failure, including a descriptor with no profile row
    /// or a command that did not run, answers code 6 and leaves the claim
    /// unmarked: the committed FAR1 stays retained, and a same-operation
    /// retry recovers it through FRP1 and retries the same registration. It
    /// is never a rejection.
    fn release_registered(
        &mut self,
        claim: ForkDeliveryClaimV1,
        result: &ForkAdmissionOperationResultV1,
        mark_after_write: bool,
    ) -> PreparedDeliveryV1 {
        let registered = match result {
            ForkAdmissionOperationResultV1::Fork(receipt) => matches!(
                self.journal
                    .register(receipt.child_id, receipt.admission_digest),
                Ok(Ok(Ok(())))
            ),
            ForkAdmissionOperationResultV1::PrincipalOwner(_) => true,
        };
        if registered {
            PreparedDeliveryV1::release(claim, result, mark_after_write)
        } else {
            PreparedDeliveryV1::plain(reject(LocalForkAdmissionCodeV1::Indeterminate))
        }
    }

    fn command(
        &self,
        request: &LocalForkAdmissionRequestV1,
        authentication: &ResolvedLocalAuthenticationV1,
    ) -> Result<ForkAdmissionHostCommandV1, LocalForkAuthenticationErrorV1> {
        let evidence = authentication.evidence_digest();
        let principal = authentication.principal_digest();
        let common = [
            Value::Bytes(self.host.store_id().as_bytes().to_vec()),
            Value::Bytes(self.session_identity.as_bytes().to_vec()),
            Value::Bytes(request.operation_id().as_bytes().to_vec()),
            Value::Bytes(evidence.as_bytes().to_vec()),
            Value::Bytes(principal.as_bytes().to_vec()),
        ];
        match request {
            LocalForkAdmissionRequestV1::Bind { .. } => {
                let mut fields = vec![Value::Text("POC1".to_owned()), Value::Integer(1.into())];
                fields.extend(common);
                fields.push(Value::Text(authentication.owner().as_str().to_owned()));
                encode(fields, PrincipalOwnerCommandV1::from_canonical_cbor).and_then(|command| {
                    self.credentials
                        .sign_principal_owner_command(&command, authentication)
                })
            }
            LocalForkAdmissionRequestV1::Fork {
                parent_id,
                cut,
                descriptor_hash,
                composition_hash,
                attribution_required,
                child_name,
                ..
            } => {
                let mut fields = vec![Value::Text("FCC1".to_owned()), Value::Integer(1.into())];
                fields.extend(common);
                fields.extend([
                    Value::Bytes(parent_id.inner().to_bytes().to_vec()),
                    Value::Integer((*cut).into()),
                    Value::Integer((*cut).into()),
                    Value::Bytes(descriptor_hash.as_bytes().to_vec()),
                    Value::Bytes(composition_hash.as_bytes().to_vec()),
                    Value::Integer(u8::from(*attribution_required).into()),
                    Value::Text(child_name.clone()),
                ]);
                encode(fields, ForkCreateCommandV1::from_canonical_cbor).and_then(|command| {
                    self.credentials.sign_fork_command(&command, authentication)
                })
            }
        }
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
impl LocalForkAdmissionCoordinatorV1 {
    /// Wrap the journal submissions for a service-level fault test.
    pub(super) fn map_journal_for_test(
        self,
        wrap: impl FnOnce(Box<dyn LocalForkDeliveryJournalV1>) -> Box<dyn LocalForkDeliveryJournalV1>,
    ) -> Self {
        Self {
            journal: wrap(self.journal),
            ..self
        }
    }
}

/// Sign one private FRP1 for `tuple` with the session identity digest.
fn recovery_proof(
    credentials: &LocalForkAuthenticationCredentialsV1,
    host: ForkAdmissionHostRecordV1,
    session_identity: Hash,
    tuple: ForkDeliveryTupleV1,
) -> Result<ForkAdmissionRecoveryProofV1, LocalForkAuthenticationErrorV1> {
    let fields = vec![
        Value::Text("FRC1".to_owned()),
        Value::Integer(1.into()),
        Value::Bytes(host.store_id().as_bytes().to_vec()),
        Value::Bytes(session_identity.as_bytes().to_vec()),
        Value::Integer(tuple.kind.wire().into()),
        Value::Bytes(tuple.operation_id.as_bytes().to_vec()),
    ];
    encode(fields, ForkAdmissionRecoveryCommandV1::from_canonical_cbor)
        .and_then(|command| credentials.sign_recovery(&command))
}

/// What the coordinator does with one execute submission outcome.
enum ExecuteDisposition {
    /// FAC1 committed; release the result for delivery.
    Release(Box<ForkAdmissionOperationResultV1>),
    /// Answer with this code; the journal row needs no cancellation.
    Answer(LocalForkAdmissionCodeV1),
    /// Pending is still live: cancel it, then answer with this code.
    CancelThenAnswer(LocalForkAdmissionCodeV1),
}

/// Classify an execute submission (ADR-109 r9 Decision 1 item 6).
fn execute_disposition(
    outcome: ForkAdmissionSubmissionV1<ForkDeliveryExecutionV1>,
) -> ExecuteDisposition {
    match outcome {
        Ok(Ok(ForkDeliveryExecutionV1::Committed(result))) => ExecuteDisposition::Release(result),
        Ok(Ok(ForkDeliveryExecutionV1::Rejected(error))) => {
            ExecuteDisposition::Answer(authority_code(error))
        }
        Ok(
            Ok(ForkDeliveryExecutionV1::Uncertain)
            | Err(ForkDeliveryJournalErrorV1::StorageIndeterminate),
        )
        | Err(ForkAdmissionSubmissionErrorV1::Lost) => {
            ExecuteDisposition::Answer(LocalForkAdmissionCodeV1::Indeterminate)
        }
        // The journal refused the claim before FAC1 submission, so the
        // Pending row is still live and must be deleted (ADR-109).
        Ok(Err(
            ForkDeliveryJournalErrorV1::InvalidTuple
            | ForkDeliveryJournalErrorV1::Conflict
            | ForkDeliveryJournalErrorV1::Fenced
            | ForkDeliveryJournalErrorV1::Corrupt,
        )) => ExecuteDisposition::CancelThenAnswer(LocalForkAdmissionCodeV1::AuthorityUnavailable),
        // The execute command definitely did not run (ADR-109 r9 Decision 1
        // item 6): cancel Pending, then answer 6 or 5.
        Err(
            error @ (ForkAdmissionSubmissionErrorV1::Busy
            | ForkAdmissionSubmissionErrorV1::Unavailable),
        ) => ExecuteDisposition::CancelThenAnswer(submission_code(error)),
    }
}

/// FARL1 code of a Fork-admission command that produced no store result
/// (ADR-109 revision 9, Decision 1 item 6).
const fn submission_code(error: ForkAdmissionSubmissionErrorV1) -> LocalForkAdmissionCodeV1 {
    match error {
        ForkAdmissionSubmissionErrorV1::Busy | ForkAdmissionSubmissionErrorV1::Lost => {
            LocalForkAdmissionCodeV1::Indeterminate
        }
        ForkAdmissionSubmissionErrorV1::Unavailable => {
            LocalForkAdmissionCodeV1::AuthorityUnavailable
        }
    }
}

struct PreparedDeliveryV1 {
    response: LocalForkAdmissionResponseV1,
    claim: Option<ForkDeliveryClaimV1>,
    mark_after_write: bool,
}

impl PreparedDeliveryV1 {
    const fn plain(response: LocalForkAdmissionResponseV1) -> Self {
        Self {
            response,
            claim: None,
            mark_after_write: false,
        }
    }

    /// Release a committed result only when its kind matches the claimed
    /// request kind. A mismatch is an internal authority failure (code 5); the
    /// claim is left untouched for operator reconciliation.
    fn release(
        claim: ForkDeliveryClaimV1,
        result: &ForkAdmissionOperationResultV1,
        mark_after_write: bool,
    ) -> Self {
        response(claim.tuple.kind, result).map_or_else(
            || Self::plain(reject(LocalForkAdmissionCodeV1::AuthorityUnavailable)),
            |response| Self {
                response,
                claim: Some(claim),
                mark_after_write,
            },
        )
    }
}

fn delivery_tuple(completed: &CompletedLocalForkAdmissionV1) -> Result<ForkDeliveryTupleV1, ()> {
    let kind = match completed.request {
        LocalForkAdmissionRequestV1::Bind { .. } => ForkAdmissionOperationKindV1::PrincipalOwner,
        LocalForkAdmissionRequestV1::Fork { .. } => ForkAdmissionOperationKindV1::Fork,
    };
    ForkDeliveryTupleV1::new(
        completed.host_request_id,
        kind,
        completed.request.operation_id(),
    )
    .map_err(|_| ())
}

fn encode<T>(
    fields: Vec<Value>,
    decode: impl FnOnce(&[u8]) -> Result<T, ForkAdmissionCommandCodecErrorV1>,
) -> Result<T, LocalForkAuthenticationErrorV1> {
    // Encoding into a Vec cannot fail; one arm covers both steps.
    let mut bytes = Vec::new();
    ciborium::into_writer(&Value::Array(fields), &mut bytes)
        .ok()
        .and_then(|()| decode(&bytes).ok())
        .ok_or(LocalForkAuthenticationErrorV1::CredentialInvalid)
}

/// FARL1 success for a result of the claimed kind, or `None` on mismatch.
const fn response(
    kind: ForkAdmissionOperationKindV1,
    result: &ForkAdmissionOperationResultV1,
) -> Option<LocalForkAdmissionResponseV1> {
    match (kind, result) {
        (
            ForkAdmissionOperationKindV1::PrincipalOwner,
            ForkAdmissionOperationResultV1::PrincipalOwner(binding),
        ) => Some(LocalForkAdmissionResponseV1::bind_ok(
            binding.input().principal_digest,
        )),
        (ForkAdmissionOperationKindV1::Fork, ForkAdmissionOperationResultV1::Fork(receipt)) => {
            Some(LocalForkAdmissionResponseV1::fork_ok(
                receipt.child_id,
                receipt.admission_digest,
            ))
        }
        _ => None,
    }
}

const fn reject(code: LocalForkAdmissionCodeV1) -> LocalForkAdmissionResponseV1 {
    LocalForkAdmissionResponseV1::rejected(code)
}

const fn authentication_code(error: LocalForkAuthenticationErrorV1) -> LocalForkAdmissionCodeV1 {
    match error {
        LocalForkAuthenticationErrorV1::PeerUnauthenticated => {
            LocalForkAdmissionCodeV1::Unauthenticated
        }
        LocalForkAuthenticationErrorV1::CredentialUnavailable
        | LocalForkAuthenticationErrorV1::CredentialInvalid => {
            LocalForkAdmissionCodeV1::AuthorityUnavailable
        }
    }
}

const fn authority_code(error: ForkAdmissionErrorV1) -> LocalForkAdmissionCodeV1 {
    match error {
        ForkAdmissionErrorV1::Unauthenticated => LocalForkAdmissionCodeV1::Unauthenticated,
        ForkAdmissionErrorV1::PrincipalOwnerConflict | ForkAdmissionErrorV1::Conflict => {
            LocalForkAdmissionCodeV1::Conflict
        }
        ForkAdmissionErrorV1::StaleFoldBoundary => LocalForkAdmissionCodeV1::StaleFoldBoundary,
        ForkAdmissionErrorV1::ParentChanged => LocalForkAdmissionCodeV1::ParentChanged,
        ForkAdmissionErrorV1::InvalidRequest => LocalForkAdmissionCodeV1::InvalidRequest,
        ForkAdmissionErrorV1::CorruptAuthority
        | ForkAdmissionErrorV1::HostAuthorityMismatch
        | ForkAdmissionErrorV1::AuthorityClockUnavailable
        | ForkAdmissionErrorV1::ClockRollback
        | ForkAdmissionErrorV1::AuthorityUninitialized
        | ForkAdmissionErrorV1::AuthorityAlreadyInitialized
        | ForkAdmissionErrorV1::EntropyUnavailable
        | ForkAdmissionErrorV1::ParentErasureContained
        | ForkAdmissionErrorV1::ErasureContainmentUnavailable => {
            LocalForkAdmissionCodeV1::AuthorityUnavailable
        }
        ForkAdmissionErrorV1::StorageIndeterminate | ForkAdmissionErrorV1::OperationMissing => {
            LocalForkAdmissionCodeV1::Indeterminate
        }
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use std::{
        io::{Read as _, Write as _},
        net::Shutdown,
        os::unix::{fs::PermissionsExt as _, net::UnixStream},
        sync::{Arc, Mutex, MutexGuard, PoisonError},
    };

    use super::*;
    use crate::local_fork_classifier_profile::test_profile_source;
    use pos_core::{
        EventStore as _, ForkAuthenticationPolicyV1, ForkClassifierSourceV1, Hash, TimelineId,
    };
    use pos_store::{
        memory::MemoryStore, ForkAdmissionAuthorityBootstrapPortV1,
        ForkAdmissionDeliveryJournalPortV1, ForkEventAuthorityErrorV1, ForkEventPermitIssuerPortV1,
        ForkEventPermitIssuerV1, ForkEventProvenanceAuthorityPortV1,
    };

    type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

    /// Every port the executor's Fork-admission commands and the classified
    /// fixtures use, for the Memory and `SQLite` adapters alike.
    trait AcceptanceStore:
        pos_core::EventStore
        + ForkAdmissionAuthorityBootstrapPortV1
        + ForkAdmissionDeliveryJournalPortV1
        + ForkEventPermitIssuerPortV1
        + ForkEventProvenanceAuthorityPortV1
        + Send
        + 'static
    {
    }

    impl<T> AcceptanceStore for T where
        T: pos_core::EventStore
            + ForkAdmissionAuthorityBootstrapPortV1
            + ForkAdmissionDeliveryJournalPortV1
            + ForkEventPermitIssuerPortV1
            + ForkEventProvenanceAuthorityPortV1
            + Send
            + 'static
    {
    }

    /// The executor slot's ADR-109 r12 classifier authority: the session's
    /// take-once issuer and the activation FCP1 rows.
    struct ClassifierAuthority {
        issuer: ForkEventPermitIssuerV1,
        profile: Vec<ForkClassifierSourceV1>,
    }

    impl ClassifierAuthority {
        /// The executor slot's own row selection.
        fn source_for(&self, descriptor: Hash) -> Option<ForkClassifierSourceV1> {
            crate::executor::select_profile_source(&self.profile, descriptor)
        }
    }

    /// FCP1 rows, one per descriptor byte, each admitting `routes`.
    fn profile_rows(
        descriptors: &[u8],
        routes: &[pos_core::ForkExternalInputRouteV1],
    ) -> TestResult<Vec<ForkClassifierSourceV1>> {
        Ok(descriptors
            .iter()
            .map(|descriptor| test_profile_source(*descriptor, routes.to_vec()))
            .collect::<Result<Vec<_>, _>>()?)
    }

    /// FCP1 rows for every descriptor the journal fixtures commit.
    fn default_profile() -> TestResult<Vec<ForkClassifierSourceV1>> {
        profile_rows(&[18, 22], &[])
    }

    /// Journal outcomes the coordinator must map without a live executor.
    #[derive(Clone, Copy, Eq, PartialEq)]
    enum JournalFault {
        Passthrough,
        ClaimJournal,
        ClaimNotRun(ForkAdmissionSubmissionErrorV1),
        ClaimZeroOperation,
        Cancel,
        ExecuteJournal(ForkDeliveryJournalErrorV1),
        ExecuteRejected,
        ExecuteUncertain,
        ExecuteNotRun(ForkAdmissionSubmissionErrorV1),
        Recover,
        MarkDelivered,
        MarkUncertain,
        RegisterNotRun(ForkAdmissionSubmissionErrorV1),
    }

    /// A journal row whose zero operation identity no FRC1 can carry.
    const fn zero_operation_tuple() -> ForkDeliveryTupleV1 {
        ForkDeliveryTupleV1 {
            host_request_id: Hash::from_bytes([1; 32]),
            kind: ForkAdmissionOperationKindV1::PrincipalOwner,
            operation_id: Hash::zero(),
        }
    }

    fn lock<T>(value: &Mutex<T>) -> MutexGuard<'_, T> {
        value.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The executor's commands run directly on one shared store.
    struct StoreJournal<S> {
        store: Arc<Mutex<S>>,
        session: Arc<ForkAdmissionAuthoritySessionV1>,
        policy: ForkAuthenticationPolicyV1,
        classifier: Arc<Mutex<ClassifierAuthority>>,
        fault: Arc<Mutex<JournalFault>>,
    }

    impl<S> StoreJournal<S> {
        /// The journal outcome currently injected by the test.
        fn fault(&self) -> JournalFault {
            *lock(&self.fault)
        }
    }

    impl<S: AcceptanceStore> LocalForkDeliveryJournalV1 for StoreJournal<S> {
        fn claim(
            &mut self,
            tuple: ForkDeliveryTupleV1,
        ) -> ForkAdmissionSubmissionV1<ForkDeliveryClaimOutcomeV1> {
            match self.fault() {
                JournalFault::ClaimJournal => {
                    Ok(Err(ForkDeliveryJournalErrorV1::StorageIndeterminate))
                }
                JournalFault::ClaimNotRun(error) => Err(error),
                JournalFault::ClaimZeroOperation => Ok(Ok(ForkDeliveryClaimOutcomeV1::Reconcile(
                    ForkDeliveryClaimV1 {
                        tuple: zero_operation_tuple(),
                        owner_fence: 1,
                    },
                    ForkDeliveryStateV1::Uncertain,
                ))),
                _ => Ok(lock(&self.store).claim_fork_delivery(&self.session, tuple)),
            }
        }

        fn cancel(&mut self, claim: ForkDeliveryClaimV1) -> ForkAdmissionSubmissionV1<()> {
            if self.fault() == JournalFault::Cancel {
                return Ok(Err(ForkDeliveryJournalErrorV1::StorageIndeterminate));
            }
            Ok(lock(&self.store).cancel_pending_fork_delivery(&self.session, claim))
        }

        fn execute(
            &mut self,
            claim: ForkDeliveryClaimV1,
            command: &ForkAdmissionHostCommandV1,
        ) -> ForkAdmissionSubmissionV1<ForkDeliveryExecutionV1> {
            match self.fault() {
                JournalFault::ExecuteJournal(error) => Ok(Err(error)),
                JournalFault::ExecuteRejected => Ok(Ok(ForkDeliveryExecutionV1::Rejected(
                    ForkAdmissionErrorV1::InvalidRequest,
                ))),
                JournalFault::ExecuteUncertain => Ok(Ok(ForkDeliveryExecutionV1::Uncertain)),
                JournalFault::ExecuteNotRun(error) => Err(error),
                _ => Ok(lock(&self.store).execute_claimed_fork_delivery(
                    &self.session,
                    &self.policy,
                    claim,
                    command,
                )),
            }
        }

        fn recover(
            &mut self,
            tuple: ForkDeliveryTupleV1,
            proof: &ForkAdmissionRecoveryProofV1,
            principal: Hash,
        ) -> ForkAdmissionSubmissionV1<ForkAdmissionOperationResultV1> {
            if self.fault() == JournalFault::Recover {
                return Ok(Err(ForkDeliveryJournalErrorV1::StorageIndeterminate));
            }
            Ok(lock(&self.store).recover_fork_delivery(&self.session, tuple, proof, principal))
        }

        fn mark(
            &mut self,
            claim: ForkDeliveryClaimV1,
            mark: ForkDeliveryMarkV1,
        ) -> ForkAdmissionSubmissionV1<()> {
            match (self.fault(), mark) {
                (JournalFault::MarkDelivered, ForkDeliveryMarkV1::Delivered)
                | (JournalFault::MarkUncertain, ForkDeliveryMarkV1::Uncertain) => {
                    Ok(Err(ForkDeliveryJournalErrorV1::StorageIndeterminate))
                }
                (_, ForkDeliveryMarkV1::Delivered) => {
                    Ok(lock(&self.store).mark_fork_delivery_delivered(&self.session, claim))
                }
                (_, ForkDeliveryMarkV1::Uncertain) => {
                    Ok(lock(&self.store).mark_fork_delivery_uncertain(&self.session, claim))
                }
            }
        }

        /// The executor slot's registration (ADR-109 r12) over the shared
        /// store: select by durable FAR1, issue, and register.
        fn register(
            &mut self,
            child: TimelineId,
            admission_digest: Hash,
        ) -> ForkAdmissionSubmissionV1<ForkClassifierRegistrationV1> {
            if let JournalFault::RegisterNotRun(error) = self.fault() {
                return Err(error);
            }
            let classifier = lock(&self.classifier);
            let mut store = lock(&self.store);
            Ok(Ok(store
                .read_validated_local_fork_admission(child)
                .and_then(|admission| {
                    classifier
                        .source_for(admission.input().room_revision_descriptor_hash)
                        .ok_or(ForkEventAuthorityErrorV1::Unauthenticated)
                })
                .and_then(|source| {
                    store.issue_classifier_registrar_permit(
                        &classifier.issuer,
                        &self.session,
                        child,
                        source,
                    )
                })
                .and_then(|permit| {
                    store.register_classifier(
                        &self.session,
                        &permit,
                        crate::executor::classifier_registration_operation_id(
                            child,
                            admission_digest,
                        ),
                        child,
                    )
                })
                .map(|_| ())))
        }
    }

    struct Fixture<S = MemoryStore> {
        coordinator: LocalForkAdmissionCoordinatorV1,
        store: Arc<Mutex<S>>,
        session: Arc<ForkAdmissionAuthoritySessionV1>,
        classifier: Arc<Mutex<ClassifierAuthority>>,
        fault: Arc<Mutex<JournalFault>>,
    }

    fn fixture_over(store: MemoryStore, fault: JournalFault) -> TestResult<Fixture> {
        fixture_profiled(store, fault, default_profile()?)
    }

    /// Provision `store`, open its session, and install `profile` with the
    /// session's issuer, as startup steps 3 and 5 do.
    fn fixture_profiled<S: AcceptanceStore>(
        mut store: S,
        fault: JournalFault,
        profile: Vec<ForkClassifierSourceV1>,
    ) -> TestResult<Fixture<S>> {
        let credentials = crate::local_fork_authentication::test_credentials_for_current_peer()?;
        credentials.provision_authority(&mut store)?;
        let session = credentials.open_authority(&mut store)?;
        let host = store.fork_admission_host_record()?;
        fixture_with(credentials, host, (store, session), fault, profile)
    }

    fn fixture_with<S: AcceptanceStore>(
        credentials: LocalForkAuthenticationCredentialsV1,
        host: ForkAdmissionHostRecordV1,
        (store, mut session): (S, ForkAdmissionAuthoritySessionV1),
        fault: JournalFault,
        profile: Vec<ForkClassifierSourceV1>,
    ) -> TestResult<Fixture<S>> {
        let issuer = session
            .take_event_permit_issuer()
            .ok_or("a newly opened session must yield its issuer")?;
        let store = Arc::new(Mutex::new(store));
        let session = Arc::new(session);
        let classifier = Arc::new(Mutex::new(ClassifierAuthority { issuer, profile }));
        let fault = Arc::new(Mutex::new(fault));
        let journal = StoreJournal {
            store: Arc::clone(&store),
            session: Arc::clone(&session),
            policy: credentials.policy().clone(),
            classifier: Arc::clone(&classifier),
            fault: Arc::clone(&fault),
        };
        Ok(Fixture {
            coordinator: LocalForkAdmissionCoordinatorV1::new(
                credentials,
                host,
                session.identity(),
                Box::new(journal),
            ),
            store,
            session,
            classifier,
            fault,
        })
    }

    /// ADR-106 r3: admitted Forks need an available bound erasure gate, so
    /// the default fixture binds the open test gate.
    fn fixture(fault: JournalFault) -> TestResult<Fixture> {
        let mut store = MemoryStore::new();
        store.bind_erasure_gate(Arc::new(pos_core::ErasureContainmentGateV1::new_test_open()))?;
        fixture_over(store, fault)
    }

    fn bind_payload() -> Vec<u8> {
        [0x83, 0x64, b'F', b'A', b'L', b'1', 1, 0x82, 1, 0x58, 0x20]
            .into_iter()
            .chain([1; 32])
            .collect()
    }

    fn closed_request(listener_path: std::path::PathBuf, frame: Vec<u8>) -> io::Result<bool> {
        let worker = std::thread::spawn(move || {
            let mut stream = UnixStream::connect(listener_path)?;
            stream.write_all(&frame)?;
            stream.shutdown(Shutdown::Write)?;
            let mut byte = [0; 1];
            Ok(stream.read(&mut byte)? == 0)
        });
        worker
            .join()
            .map_err(|_| io::Error::other("pathname client panicked"))?
    }

    fn request(listener_path: std::path::PathBuf, payload: Vec<u8>) -> io::Result<Vec<u8>> {
        let worker = std::thread::spawn(move || {
            let mut stream = UnixStream::connect(listener_path)?;
            let length = u32::try_from(payload.len()).map_err(io::Error::other)?;
            stream.write_all(&length.to_be_bytes())?;
            stream.write_all(&payload)?;
            stream.shutdown(Shutdown::Write)?;
            let mut prefix = [0; 4];
            stream.read_exact(&mut prefix)?;
            let length = usize::try_from(u32::from_be_bytes(prefix)).map_err(io::Error::other)?;
            let mut response = vec![0; length];
            stream.read_exact(&mut response)?;
            Ok(response)
        });
        worker
            .join()
            .map_err(|_| io::Error::other("pathname client panicked"))?
    }

    fn current_peer(
        credentials: &LocalForkAuthenticationCredentialsV1,
    ) -> Result<
        crate::local_fork_authentication::AuthenticatedUnixPeerV1,
        LocalForkAuthenticationErrorV1,
    > {
        let (_client, server) = UnixStream::pair()
            .map_err(|_| LocalForkAuthenticationErrorV1::CredentialUnavailable)?;
        credentials.authenticate_peer(&server)
    }

    fn bind_request(operation: u8) -> LocalForkAdmissionRequestV1 {
        LocalForkAdmissionRequestV1::Bind {
            operation_id: Hash::from_bytes([operation; 32]),
        }
    }

    fn fork_request(
        operation: u8,
        parent_id: TimelineId,
        descriptor: u8,
        composition: u8,
        child_name: &str,
    ) -> LocalForkAdmissionRequestV1 {
        LocalForkAdmissionRequestV1::Fork {
            operation_id: Hash::from_bytes([operation; 32]),
            parent_id,
            cut: 0,
            descriptor_hash: Hash::from_bytes([descriptor; 32]),
            composition_hash: Hash::from_bytes([composition; 32]),
            attribution_required: false,
            child_name: child_name.to_owned(),
        }
    }

    fn completed(
        coordinator: &LocalForkAdmissionCoordinatorV1,
        request: LocalForkAdmissionRequestV1,
        host_request: u8,
    ) -> TestResult<CompletedLocalForkAdmissionV1> {
        Ok(CompletedLocalForkAdmissionV1 {
            peer: current_peer(&coordinator.credentials)?,
            request,
            host_request_id: Hash::from_bytes([host_request; 32]),
        })
    }

    fn response_code(prepared: &PreparedDeliveryV1) -> u8 {
        prepared.response.to_canonical_cbor()[8]
    }

    const BIND_OK: [u8; 10] = [0x84, 0x65, b'F', b'A', b'R', b'L', b'1', 1, 0, 0x82];

    #[test]
    fn startup_session_requires_an_initialized_host_authority() -> TestResult {
        let mut host = ErasureExecutionHostV1::open_verified_empty(
            pos_store::StoreConfig::Memory,
            pos_core::ErasureRecoveryLimitsV1::compiled_maximum(),
        )?;
        let credentials = crate::local_fork_authentication::test_credentials_for_current_peer()?;
        assert_eq!(
            open_fork_admission_session(&mut host, &credentials).err(),
            Some(LocalForkAuthenticationErrorV1::CredentialUnavailable)
        );
        let provisioned = credentials.provision_authority(host.fork_admission_bootstrap())?;
        let (session, record) = open_fork_admission_session(&mut host, &credentials)?;
        assert_eq!(record, provisioned);
        assert_ne!(session.identity(), Hash::zero());
        Ok(())
    }

    #[test]
    fn startup_reconciliation_fails_closed_on_list_tuple_and_signing_faults() -> TestResult {
        let Fixture {
            coordinator,
            session,
            ..
        } = fixture(JournalFault::Passthrough)?;
        let ids = (coordinator.host, session.identity());
        let credentials = &coordinator.credentials;
        let tuple = ForkDeliveryTupleV1::new(
            Hash::from_bytes([2; 32]),
            ForkAdmissionOperationKindV1::PrincipalOwner,
            Hash::from_bytes([3; 32]),
        )?;
        let released = |_: ForkDeliveryTupleV1, _: &ForkAdmissionRecoveryProofV1| {
            Ok::<_, ()>(ForkDeliveryStartupOutcomeV1::ReleasedPending)
        };
        assert_eq!(
            reconcile_startup(credentials, ids, Err(()), released),
            Err(LocalForkAuthenticationErrorV1::CredentialUnavailable)
        );
        assert_eq!(
            reconcile_startup(credentials, ids, Ok(vec![tuple]), |_, _| Err(())),
            Err(LocalForkAuthenticationErrorV1::CredentialUnavailable)
        );
        assert_eq!(
            reconcile_startup(credentials, ids, Ok(vec![zero_operation_tuple()]), released),
            Err(LocalForkAuthenticationErrorV1::CredentialInvalid)
        );
        assert_eq!(
            reconcile_startup(credentials, ids, Ok(vec![tuple]), released),
            Ok(())
        );
        Ok(())
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn coordinator_maps_claim_execution_and_cancel_outcomes() -> TestResult {
        for (fault, expected_code) in [
            (JournalFault::ClaimJournal, 6),
            (
                JournalFault::ClaimNotRun(ForkAdmissionSubmissionErrorV1::Busy),
                6,
            ),
            (
                JournalFault::ClaimNotRun(ForkAdmissionSubmissionErrorV1::Lost),
                6,
            ),
            (
                JournalFault::ClaimNotRun(ForkAdmissionSubmissionErrorV1::Unavailable),
                5,
            ),
            (
                JournalFault::ExecuteJournal(ForkDeliveryJournalErrorV1::StorageIndeterminate),
                6,
            ),
            (JournalFault::ExecuteRejected, 7),
            (JournalFault::ExecuteUncertain, 6),
            (
                JournalFault::ExecuteNotRun(ForkAdmissionSubmissionErrorV1::Lost),
                6,
            ),
        ] {
            let mut fixture = fixture(fault)?;
            let request = completed(&fixture.coordinator, bind_request(43), 44)?;
            assert_eq!(
                response_code(&fixture.coordinator.handle(request)),
                expected_code
            );
        }

        // A journal refusal before FAC1 submission, or an execute command
        // that definitely did not run, deletes Pending, so the same tuple can
        // be claimed again (ADR-109 r9 Decision 1 item 6).
        for (fault, expected_code) in [
            (
                JournalFault::ExecuteJournal(ForkDeliveryJournalErrorV1::Corrupt),
                5,
            ),
            (
                JournalFault::ExecuteNotRun(ForkAdmissionSubmissionErrorV1::Busy),
                6,
            ),
            (
                JournalFault::ExecuteNotRun(ForkAdmissionSubmissionErrorV1::Unavailable),
                5,
            ),
        ] {
            let mut fixture = fixture(fault)?;
            let request = completed(&fixture.coordinator, bind_request(64), 65)?;
            let tuple = delivery_tuple(&request)
                .map_err(|()| io::Error::other("valid bind must produce a tuple"))?;
            assert_eq!(
                response_code(&fixture.coordinator.handle(request)),
                expected_code
            );
            assert!(matches!(
                lock(&fixture.store).claim_fork_delivery(&fixture.session, tuple)?,
                ForkDeliveryClaimOutcomeV1::Owner(_)
            ));
        }

        let mut cancel_fault = fixture(JournalFault::Cancel)?;
        let unregistered = CompletedLocalForkAdmissionV1 {
            peer: crate::local_fork_authentication::test_unregistered_peer()?,
            request: bind_request(45),
            host_request_id: Hash::from_bytes([46; 32]),
        };
        assert_eq!(
            response_code(&cancel_fault.coordinator.handle(unregistered)),
            6
        );
        Ok(())
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn coordinator_closes_on_recovery_and_response_transition_faults() -> TestResult {
        let mut recover_fault = fixture(JournalFault::Recover)?;
        let first = completed(&recover_fault.coordinator, bind_request(47), 48)?;
        assert_eq!(response_code(&recover_fault.coordinator.handle(first)), 0);
        let retry = completed(&recover_fault.coordinator, bind_request(47), 48)?;
        assert_eq!(response_code(&recover_fault.coordinator.handle(retry)), 6);

        let mut delivered_fault = fixture(JournalFault::MarkDelivered)?;
        let request = completed(&delivered_fault.coordinator, bind_request(49), 50)?;
        let prepared = delivered_fault.coordinator.handle(request);
        assert_eq!(response_code(&prepared), 0);
        let (mut writer, _reader) = UnixStream::pair()?;
        assert!(delivered_fault
            .coordinator
            .write_prepared(&mut writer, &prepared)
            .is_err());

        let mut uncertain_fault = fixture(JournalFault::MarkUncertain)?;
        let request = completed(&uncertain_fault.coordinator, bind_request(51), 52)?;
        let prepared = uncertain_fault.coordinator.handle(request);
        assert_eq!(response_code(&prepared), 0);
        let (mut writer, reader) = UnixStream::pair()?;
        drop(reader);
        assert!(uncertain_fault
            .coordinator
            .write_prepared(&mut writer, &prepared)
            .is_err());
        Ok(())
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn coordinator_cancels_a_pending_claim_when_fork_command_is_invalid() -> TestResult {
        let mut fixture = fixture(JournalFault::Passthrough)?;
        let request = fork_request(
            53,
            TimelineId::from_ulid(ulid::Ulid::from_bytes([54; 16])),
            55,
            56,
            "",
        );
        let request = completed(&fixture.coordinator, request, 57)?;
        let tuple = delivery_tuple(&request)
            .map_err(|()| io::Error::other("fork request must produce a tuple"))?;
        assert_eq!(response_code(&fixture.coordinator.handle(request)), 5);
        assert!(matches!(
            lock(&fixture.store).claim_fork_delivery(&fixture.session, tuple)?,
            ForkDeliveryClaimOutcomeV1::Owner(_)
        ));
        Ok(())
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn coordinator_keeps_retained_delivery_after_unauthenticated_retry() -> TestResult {
        let mut fixture = fixture(JournalFault::Passthrough)?;
        let first = completed(&fixture.coordinator, bind_request(58), 59)?;
        assert_eq!(response_code(&fixture.coordinator.handle(first)), 0);
        let unauthenticated_retry = CompletedLocalForkAdmissionV1 {
            peer: crate::local_fork_authentication::test_unregistered_peer()?,
            request: bind_request(58),
            host_request_id: Hash::from_bytes([59; 32]),
        };
        assert_eq!(
            response_code(&fixture.coordinator.handle(unauthenticated_retry)),
            6
        );
        let authenticated_retry = completed(&fixture.coordinator, bind_request(58), 59)?;
        assert_eq!(
            response_code(&fixture.coordinator.handle(authenticated_retry)),
            0
        );
        Ok(())
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn real_pathname_peer_receives_and_retries_a_signed_bind_admission() -> TestResult {
        let mut fixture = fixture_over(MemoryStore::new(), JournalFault::Passthrough)?;
        let directory = tempfile::tempdir()?;
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o750))?;
        let path = directory.path().join("fork-admission.sock");
        let listener = crate::local_fork_listener::bind_pathname_listener(&path)?;
        let payload = bind_payload();
        let malformed_frames = [
            vec![0, 0, 0, 0],
            u32::try_from(crate::local_fork_listener::MAX_FAL1_PAYLOAD_BYTES_V1 + 1)
                .map_err(io::Error::other)?
                .to_be_bytes()
                .to_vec(),
            [
                vec![0, 0, 0, 44],
                vec![
                    0x83, 0x64, b'F', b'A', b'L', b'1', 0x18, 1, 0x82, 1, 0x58, 0x20,
                ],
                vec![1; 32],
            ]
            .concat(),
        ];
        for frame in malformed_frames {
            let client_path = path.clone();
            let client = std::thread::spawn(move || closed_request(client_path, frame));
            fixture.coordinator.serve_one(&listener)?;
            assert!(client
                .join()
                .map_err(|_| io::Error::other("close request panicked"))??);
        }
        let mut semantic_payload = payload.clone();
        semantic_payload[11..].fill(0);
        let semantic_path = path.clone();
        let semantic = std::thread::spawn(move || request(semantic_path, semantic_payload));
        fixture.coordinator.serve_one(&listener)?;
        assert_eq!(
            semantic
                .join()
                .map_err(|_| io::Error::other("semantic request panicked"))??,
            vec![0x84, 0x65, b'F', b'A', b'R', b'L', b'1', 1, 7, 0xf6]
        );
        let first_path = path.clone();
        let first_payload = payload.clone();
        let first = std::thread::spawn(move || request(first_path, first_payload));
        fixture.coordinator.serve_one(&listener)?;
        let first = first
            .join()
            .map_err(|_| io::Error::other("first request panicked"))??;
        let second = std::thread::spawn(move || request(path, payload));
        fixture.coordinator.serve_one(&listener)?;
        let second = second
            .join()
            .map_err(|_| io::Error::other("retry request panicked"))??;
        assert_eq!(first, second);
        assert_eq!(&first[..10], &BIND_OK);
        Ok(())
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn coordinator_encodes_commands_and_retries_a_delivered_bind() -> TestResult {
        let mut fixture = fixture(JournalFault::Passthrough)?;
        let coordinator = &mut fixture.coordinator;
        let bind = bind_request(11);
        let authentication = coordinator
            .credentials
            .produce(current_peer(&coordinator.credentials)?)
            .and_then(|evidence| coordinator.credentials.resolve(evidence))?;
        assert!(coordinator.command(&bind, &authentication).is_ok());
        assert!(coordinator
            .command(
                &fork_request(
                    12,
                    TimelineId::from_ulid(ulid::Ulid::from_bytes([13; 16])),
                    14,
                    15,
                    "child",
                ),
                &authentication,
            )
            .is_ok());

        let prepared = coordinator.handle(completed(coordinator, bind.clone(), 16)?);
        let (mut writer, _reader) = UnixStream::pair()?;
        coordinator.write_prepared(&mut writer, &prepared)?;
        assert_eq!(prepared.response.to_canonical_cbor()[..10], BIND_OK);

        let retry = coordinator.handle(completed(coordinator, bind, 16)?);
        assert_eq!(retry.response.to_canonical_cbor()[..10], BIND_OK);

        // ADR-099: a new Bind for the already-bound Principal resolves to the
        // one immutable committed binding rather than a conflict.
        let rebind = coordinator.handle(completed(coordinator, bind_request(21), 22)?);
        assert_eq!(rebind.response.to_canonical_cbor()[..10], BIND_OK);
        Ok(())
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn coordinator_recovers_interrupted_and_retained_fork_deliveries() -> TestResult {
        let mut fixture = fixture(JournalFault::Passthrough)?;
        let binding =
            fixture
                .coordinator
                .handle(completed(&fixture.coordinator, bind_request(16), 16)?);
        let (mut writer, _reader) = UnixStream::pair()?;
        fixture.coordinator.write_prepared(&mut writer, &binding)?;
        assert_eq!(binding.response.to_canonical_cbor()[..10], BIND_OK);

        let parent = lock(&fixture.store).create_timeline("pending Fork parent")?;
        let pending_request = fork_request(17, parent.id(), 18, 19, "pending-child");
        let pending = fixture.coordinator.handle(completed(
            &fixture.coordinator,
            pending_request.clone(),
            20,
        )?);
        let (mut writer, reader) = UnixStream::pair()?;
        drop(reader);
        assert!(fixture
            .coordinator
            .write_prepared(&mut writer, &pending)
            .is_err());
        let recovered =
            fixture
                .coordinator
                .handle(completed(&fixture.coordinator, pending_request, 20)?);
        assert_eq!(
            recovered.response.to_canonical_cbor()[..10],
            [0x84, 0x65, b'F', b'A', b'R', b'L', b'1', 1, 0, 0x83]
        );

        let busy_parent = lock(&fixture.store).create_timeline("busy Fork parent")?;
        let busy_request = fork_request(21, busy_parent.id(), 22, 23, "busy-child");
        let pending_owner =
            fixture
                .coordinator
                .handle(completed(&fixture.coordinator, busy_request.clone(), 24)?);
        let recovered_before_delivery =
            fixture
                .coordinator
                .handle(completed(&fixture.coordinator, busy_request.clone(), 24)?);
        assert_eq!(
            recovered_before_delivery.response.to_canonical_cbor(),
            pending_owner.response.to_canonical_cbor()
        );
        let (mut writer, _reader) = UnixStream::pair()?;
        fixture
            .coordinator
            .write_prepared(&mut writer, &pending_owner)?;
        let (mut duplicate_writer, _duplicate_reader) = UnixStream::pair()?;
        assert!(fixture
            .coordinator
            .write_prepared(&mut duplicate_writer, &recovered_before_delivery)
            .is_err());
        let conflicting_digest =
            fixture
                .coordinator
                .handle(completed(&fixture.coordinator, busy_request, 25)?);
        assert_eq!(
            conflicting_digest.response.to_canonical_cbor(),
            vec![0x84, 0x65, b'F', b'A', b'R', b'L', b'1', 1, 6, 0xf6]
        );
        Ok(())
    }

    /// ADR-106 r3 T13: `ForkAdmissionErrorV1::ParentErasureContained` (frozen
    /// parent) and `ForkAdmissionErrorV1::ErasureContainmentUnavailable`
    /// (store without an available bound gate) are both wire code 5 and, as
    /// definite pre-commit rejections, delete their Pending tuple.
    #[test]
    #[cfg(target_os = "linux")]
    fn coordinator_maps_parent_erasure_contained_and_erasure_containment_unavailable_to_code_five(
    ) -> TestResult {
        let gate = Arc::new(pos_core::ErasureContainmentGateV1::new_test_open());
        let mut gated = MemoryStore::new();
        gated.bind_erasure_gate(Arc::clone(&gate))?;
        for (mut fixture, frozen) in [
            // ForkAdmissionErrorV1::ParentErasureContained
            (fixture_over(gated, JournalFault::Passthrough)?, true),
            // ForkAdmissionErrorV1::ErasureContainmentUnavailable
            (
                fixture_over(MemoryStore::new(), JournalFault::Passthrough)?,
                false,
            ),
        ] {
            let bind =
                fixture
                    .coordinator
                    .handle(completed(&fixture.coordinator, bind_request(26), 26)?);
            assert_eq!(response_code(&bind), 0);
            let parent = lock(&fixture.store).create_timeline("contained Fork parent")?;
            if frozen {
                gate.freeze_timeline_for_test(parent.id());
            }
            let request = fork_request(27, parent.id(), 28, 29, "contained-child");
            for _ in 0..2 {
                let rejected = fixture.coordinator.handle(completed(
                    &fixture.coordinator,
                    request.clone(),
                    30,
                )?);
                assert_eq!(
                    rejected.response.to_canonical_cbor(),
                    vec![0x84, 0x65, b'F', b'A', b'R', b'L', b'1', 1, 5, 0xf6]
                );
            }
        }
        Ok(())
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn coordinator_reconciles_a_retained_delivery_before_serving_a_retry() -> TestResult {
        let Fixture {
            mut coordinator,
            store,
            ..
        } = fixture(JournalFault::Passthrough)?;
        let request = bind_request(26);
        let pending = coordinator.handle(completed(&coordinator, request.clone(), 27)?);
        assert_eq!(pending.response.to_canonical_cbor()[..10], BIND_OK);

        let LocalForkAdmissionCoordinatorV1 {
            credentials,
            host,
            journal,
            ..
        } = coordinator;
        drop(journal);
        let session = credentials.open_authority(&mut *lock(&store))?;
        let tuples = lock(&store).reconcile_fork_delivery_journal(&session);
        reconcile_startup(
            &credentials,
            (host, session.identity()),
            tuples,
            |tuple, proof| lock(&store).reconcile_fork_delivery_startup(&session, tuple, proof),
        )?;
        let store = Arc::try_unwrap(store)
            .map_err(|_| "the restarted journal still shares its store")?
            .into_inner()
            .unwrap_or_else(PoisonError::into_inner);
        let mut restarted = fixture_with(
            credentials,
            host,
            (store, session),
            JournalFault::Passthrough,
            default_profile()?,
        )?;
        let retry = restarted
            .coordinator
            .handle(completed(&restarted.coordinator, request, 27)?);
        assert_eq!(
            retry.response.to_canonical_cbor(),
            pending.response.to_canonical_cbor()
        );
        let (mut writer, _reader) = UnixStream::pair()?;
        restarted.coordinator.write_prepared(&mut writer, &retry)?;
        Ok(())
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn coordinator_withholds_results_when_no_frp1_can_be_signed() -> TestResult {
        let mut fixture = fixture(JournalFault::ClaimZeroOperation)?;
        let request = completed(&fixture.coordinator, bind_request(53), 54)?;
        let prepared = fixture.coordinator.handle(request);
        assert_eq!(response_code(&prepared), 5);
        assert!(prepared.claim.is_none());
        Ok(())
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn coordinator_rejects_a_zero_delivery_identity_before_claiming_authority() -> TestResult {
        let mut fixture = fixture(JournalFault::Passthrough)?;
        let rejected = fixture.coordinator.handle(CompletedLocalForkAdmissionV1 {
            peer: current_peer(&fixture.coordinator.credentials)?,
            request: bind_request(28),
            host_request_id: Hash::zero(),
        });
        assert_eq!(
            rejected.response.to_canonical_cbor(),
            vec![0x84, 0x65, b'F', b'A', b'R', b'L', b'1', 1, 7, 0xf6]
        );
        Ok(())
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn coordinator_cancels_a_pending_claim_after_peer_resolution_fails() -> TestResult {
        let mut fixture = fixture(JournalFault::Passthrough)?;
        let host_request_id = Hash::from_bytes([31; 32]);
        let request = bind_request(32);
        let rejected = fixture.coordinator.handle(CompletedLocalForkAdmissionV1 {
            peer: crate::local_fork_authentication::test_unregistered_peer()?,
            request: request.clone(),
            host_request_id,
        });
        assert_eq!(
            rejected.response.to_canonical_cbor(),
            LocalForkAdmissionResponseV1::rejected(LocalForkAdmissionCodeV1::Unauthenticated)
                .to_canonical_cbor()
        );

        let admitted = fixture
            .coordinator
            .handle(completed(&fixture.coordinator, request, 31)?);
        assert_eq!(&admitted.response.to_canonical_cbor()[..10], &BIND_OK);
        Ok(())
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn coordinator_fails_closed_for_a_superseded_session() -> TestResult {
        let mut fixture = fixture(JournalFault::Passthrough)?;
        let _new_session = fixture
            .coordinator
            .credentials
            .open_authority(&mut *lock(&fixture.store))?;
        let rejected =
            fixture
                .coordinator
                .handle(completed(&fixture.coordinator, bind_request(33), 34)?);
        assert_eq!(
            rejected.response.to_canonical_cbor(),
            LocalForkAdmissionResponseV1::rejected(LocalForkAdmissionCodeV1::Indeterminate)
                .to_canonical_cbor()
        );
        Ok(())
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn coordinator_fails_closed_while_another_owner_holds_a_delivery_claim() -> TestResult {
        let mut fixture = fixture(JournalFault::Passthrough)?;
        let request = completed(&fixture.coordinator, bind_request(29), 30)?;
        let tuple = delivery_tuple(&request)
            .map_err(|()| io::Error::other("valid bind request must produce a delivery tuple"))?;
        assert!(matches!(
            lock(&fixture.store).claim_fork_delivery(&fixture.session, tuple)?,
            ForkDeliveryClaimOutcomeV1::Owner(_)
        ));

        let busy = fixture.coordinator.handle(request);
        assert_eq!(
            busy.response.to_canonical_cbor(),
            vec![0x84, 0x65, b'F', b'A', b'R', b'L', b'1', 1, 6, 0xf6]
        );
        Ok(())
    }

    #[test]
    fn a_result_of_the_wrong_kind_is_an_internal_authority_failure() -> TestResult {
        let tuple = ForkDeliveryTupleV1::new(
            Hash::from_bytes([60; 32]),
            ForkAdmissionOperationKindV1::PrincipalOwner,
            Hash::from_bytes([61; 32]),
        )?;
        let receipt = ForkAdmissionOperationResultV1::Fork(pos_core::ForkAdmissionReceiptV1 {
            child_id: TimelineId::from_ulid(ulid::Ulid::from_bytes([62; 16])),
            admission_digest: Hash::from_bytes([63; 32]),
        });
        let prepared = PreparedDeliveryV1::release(
            ForkDeliveryClaimV1 {
                tuple,
                owner_fence: 1,
            },
            &receipt,
            true,
        );
        assert_eq!(response_code(&prepared), 5);
        assert!(prepared.claim.is_none());
        assert!(!prepared.mark_after_write);
        assert_eq!(
            response(ForkAdmissionOperationKindV1::Fork, &receipt)
                .map(|released| released.to_canonical_cbor()[8]),
            Some(0)
        );
        Ok(())
    }

    #[test]
    fn closed_error_mappings_have_exact_wire_codes() {
        for (error, expected) in [
            (
                ForkAdmissionErrorV1::Unauthenticated,
                LocalForkAdmissionCodeV1::Unauthenticated,
            ),
            (
                ForkAdmissionErrorV1::PrincipalOwnerConflict,
                LocalForkAdmissionCodeV1::Conflict,
            ),
            (
                ForkAdmissionErrorV1::Conflict,
                LocalForkAdmissionCodeV1::Conflict,
            ),
            (
                ForkAdmissionErrorV1::StaleFoldBoundary,
                LocalForkAdmissionCodeV1::StaleFoldBoundary,
            ),
            (
                ForkAdmissionErrorV1::ParentChanged,
                LocalForkAdmissionCodeV1::ParentChanged,
            ),
            (
                ForkAdmissionErrorV1::InvalidRequest,
                LocalForkAdmissionCodeV1::InvalidRequest,
            ),
            (
                ForkAdmissionErrorV1::CorruptAuthority,
                LocalForkAdmissionCodeV1::AuthorityUnavailable,
            ),
            (
                ForkAdmissionErrorV1::HostAuthorityMismatch,
                LocalForkAdmissionCodeV1::AuthorityUnavailable,
            ),
            (
                ForkAdmissionErrorV1::AuthorityClockUnavailable,
                LocalForkAdmissionCodeV1::AuthorityUnavailable,
            ),
            (
                ForkAdmissionErrorV1::ClockRollback,
                LocalForkAdmissionCodeV1::AuthorityUnavailable,
            ),
            (
                ForkAdmissionErrorV1::AuthorityUninitialized,
                LocalForkAdmissionCodeV1::AuthorityUnavailable,
            ),
            (
                ForkAdmissionErrorV1::AuthorityAlreadyInitialized,
                LocalForkAdmissionCodeV1::AuthorityUnavailable,
            ),
            (
                ForkAdmissionErrorV1::EntropyUnavailable,
                LocalForkAdmissionCodeV1::AuthorityUnavailable,
            ),
            (
                ForkAdmissionErrorV1::ParentErasureContained,
                LocalForkAdmissionCodeV1::AuthorityUnavailable,
            ),
            (
                ForkAdmissionErrorV1::ErasureContainmentUnavailable,
                LocalForkAdmissionCodeV1::AuthorityUnavailable,
            ),
            (
                ForkAdmissionErrorV1::StorageIndeterminate,
                LocalForkAdmissionCodeV1::Indeterminate,
            ),
            (
                ForkAdmissionErrorV1::OperationMissing,
                LocalForkAdmissionCodeV1::Indeterminate,
            ),
        ] {
            assert_eq!(authority_code(error), expected);
        }
        assert_eq!(
            authentication_code(LocalForkAuthenticationErrorV1::PeerUnauthenticated),
            LocalForkAdmissionCodeV1::Unauthenticated
        );
        for error in [
            LocalForkAuthenticationErrorV1::CredentialUnavailable,
            LocalForkAuthenticationErrorV1::CredentialInvalid,
        ] {
            assert_eq!(
                authentication_code(error),
                LocalForkAdmissionCodeV1::AuthorityUnavailable
            );
        }
    }

    #[test]
    fn submission_outcomes_have_exact_wire_codes() {
        for (error, expected) in [
            (
                ForkAdmissionSubmissionErrorV1::Busy,
                LocalForkAdmissionCodeV1::Indeterminate,
            ),
            (
                ForkAdmissionSubmissionErrorV1::Lost,
                LocalForkAdmissionCodeV1::Indeterminate,
            ),
            (
                ForkAdmissionSubmissionErrorV1::Unavailable,
                LocalForkAdmissionCodeV1::AuthorityUnavailable,
            ),
        ] {
            assert_eq!(submission_code(error), expected);
        }
    }

    /// ADR-109 r12: a committed Fork whose classifier cannot be registered,
    /// because its descriptor has no profile row or the registration command
    /// did not run, answers code 6 on delivery and on same-operation
    /// recovery; it is never a rejection and never falls back to a row.
    #[test]
    #[cfg(target_os = "linux")]
    fn coordinator_holds_a_committed_fork_until_its_classifier_registers() -> TestResult {
        for (fault, descriptor) in [
            (JournalFault::Passthrough, 40),
            (
                JournalFault::RegisterNotRun(ForkAdmissionSubmissionErrorV1::Lost),
                18,
            ),
        ] {
            let mut fixture = fixture(fault)?;
            assert_eq!(response_code(&fixture.submit(bind_request(41), 41)?), 0);
            let parent = lock(&fixture.store).create_timeline("held Fork parent")?;
            let request = fork_request(42, parent.id(), descriptor, 43, "held-child");
            for _ in 0..2 {
                assert_eq!(response_code(&fixture.submit(request.clone(), 44)?), 6);
            }
        }
        Ok(())
    }

    /// ADR-109 r12: a registration command that definitely did not run,
    /// because the executor was busy or unavailable, answers code 6 and leaves
    /// the claim unmarked; a same-operation retry registers and releases the
    /// Fork once the command runs.
    #[test]
    #[cfg(target_os = "linux")]
    fn coordinator_retries_a_classifier_registration_that_did_not_run() -> TestResult {
        for error in [
            ForkAdmissionSubmissionErrorV1::Busy,
            ForkAdmissionSubmissionErrorV1::Unavailable,
        ] {
            let mut fixture = fixture(JournalFault::RegisterNotRun(error))?;
            assert_eq!(response_code(&fixture.submit(bind_request(41), 41)?), 0);
            let parent = lock(&fixture.store).create_timeline("unregistered Fork parent")?;
            let request = fork_request(42, parent.id(), 18, 43, "unregistered-child");
            let tuple = delivery_tuple(&completed(&fixture.coordinator, request.clone(), 44)?)
                .map_err(|()| io::Error::other("fork request must produce a tuple"))?;

            let held = fixture.submit(request.clone(), 44)?;
            assert_eq!(response_code(&held), 6);
            assert!(held.claim.is_none());
            assert!(matches!(
                lock(&fixture.store).claim_fork_delivery(&fixture.session, tuple)?,
                ForkDeliveryClaimOutcomeV1::Reconcile(_, state)
                    if state != ForkDeliveryStateV1::Delivered
            ));

            *lock(&fixture.fault) = JournalFault::Passthrough;
            assert_eq!(response_code(&fixture.submit(request, 44)?), 0);
            assert!(matches!(
                lock(&fixture.store).claim_fork_delivery(&fixture.session, tuple)?,
                ForkDeliveryClaimOutcomeV1::Reconcile(_, ForkDeliveryStateV1::Delivered)
            ));
        }
        Ok(())
    }

    /// The descriptor every acceptance profile selects.
    const ACCEPTED_DESCRIPTOR: u8 = 70;
    /// A descriptor that only the restarted acceptance profile adds.
    const LATE_DESCRIPTOR: u8 = 71;

    fn adapter_route() -> TestResult<pos_core::ForkEventSourceDescriptorV1> {
        Ok(pos_core::ForkEventSourceDescriptorV1::new(
            "gateway.action.v1",
            Hash::from_bytes([72; 32]),
        )?)
    }

    fn adapter_routes() -> TestResult<Vec<pos_core::ForkExternalInputRouteV1>> {
        Ok(vec![pos_core::ForkExternalInputRouteV1::new(
            adapter_route()?,
            true,
        )])
    }

    fn adapter_source(adapter: &str) -> TestResult<pos_core::ForkAppendSourceIdentityV1> {
        Ok(pos_core::ForkAppendSourceIdentityV1::ExternalInput {
            adapter_identifier: adapter.to_owned(),
            source: adapter_route()?,
        })
    }

    fn classified_draft(payload: &[u8]) -> pos_core::EventDraft {
        pos_core::EventDraft::new(
            pos_core::EntityId::new(),
            pos_core::Kind::new("fork.event.gateway"),
            pos_core::CanonicalBytes::from_vec(payload.to_vec()),
        )
        .with_wall_time(pos_core::WallTime::from_micros(10))
    }

    /// The child of a released FARL1 Fork result.
    fn fork_child(prepared: &PreparedDeliveryV1) -> TestResult<TimelineId> {
        let bytes = prepared.response.to_canonical_cbor();
        if bytes.get(..10) != Some(&[0x84, 0x65, b'F', b'A', b'R', b'L', b'1', 1, 0, 0x83][..]) {
            return Err("the coordinator did not release a committed Fork".into());
        }
        let child: [u8; 16] = bytes.get(12..28).ok_or("short Fork result")?.try_into()?;
        Ok(TimelineId::from_ulid(ulid::Ulid::from_bytes(child)))
    }

    /// The deferred (Wave 9 #479) classified-append host seam, as a fixture
    /// over the shared store: every permit is issued by the store bridge from
    /// the slot's issuer and the profile row selected by durable FAR1.
    impl<S: AcceptanceStore> Fixture<S> {
        /// Submit one completed request and deliver its response.
        fn submit(
            &mut self,
            request: LocalForkAdmissionRequestV1,
            host_request: u8,
        ) -> TestResult<PreparedDeliveryV1> {
            let prepared =
                self.coordinator
                    .handle(completed(&self.coordinator, request, host_request)?);
            let (mut writer, _reader) = UnixStream::pair()?;
            self.coordinator.write_prepared(&mut writer, &prepared)?;
            Ok(prepared)
        }

        /// Activate a host-assigned adapter only for a route an FCP1 row
        /// admits.
        fn activate_external_adapter(
            &self,
            adapter_identifier: &str,
            source: pos_core::ForkEventSourceDescriptorV1,
        ) -> bool {
            let mut classifier = lock(&self.classifier);
            let admitted = classifier
                .profile
                .iter()
                .flat_map(|row| row.input().routes.iter())
                .any(|route| route.source() == &source);
            if admitted {
                classifier.issuer.trust_external_source(
                    pos_core::ForkAppendSourceIdentityV1::ExternalInput {
                        adapter_identifier: adapter_identifier.to_owned(),
                        source,
                    },
                );
            }
            drop(classifier);
            admitted
        }

        /// Deregister an adapter; every permit issued for it stops
        /// authorizing.
        fn deregister_external_adapter(&self, adapter_identifier: &str) {
            lock(&self.classifier)
                .issuer
                .revoke_external_adapter(adapter_identifier);
        }

        /// Issue a fresh permit after selecting the profile row by FAR1.
        fn append_permit(
            &self,
            child: TimelineId,
            source: pos_core::ForkAppendSourceIdentityV1,
        ) -> Result<pos_store::ForkAppendSourcePermitV1, ForkEventAuthorityErrorV1> {
            let classifier = lock(&self.classifier);
            let store = lock(&self.store);
            store
                .read_validated_local_fork_admission(child)
                .and_then(|admission| {
                    classifier
                        .source_for(admission.input().room_revision_descriptor_hash)
                        .ok_or(ForkEventAuthorityErrorV1::Unauthenticated)
                })
                .and_then(|selected| {
                    store.issue_append_source_permit(
                        &classifier.issuer,
                        &self.session,
                        child,
                        &selected,
                        source,
                    )
                })
        }

        /// Append one classified Event with a permit issued for it.
        fn append_classified_event(
            &self,
            child: TimelineId,
            source: pos_core::ForkAppendSourceIdentityV1,
            operation_id: Hash,
            draft: pos_core::EventDraft,
        ) -> Result<pos_store::ForkClassifiedAppendReceiptV1, ForkEventAuthorityErrorV1> {
            let permit = self.append_permit(child, source)?;
            let mut store = lock(&self.store);
            store.append_classified(&self.session, &permit, operation_id, draft)
        }

        /// Recover one stable append operation with a reissued permit.
        fn recover_classified_event(
            &self,
            child: TimelineId,
            source: pos_core::ForkAppendSourceIdentityV1,
            operation_id: Hash,
            draft: &pos_core::EventDraft,
        ) -> Result<Option<pos_store::ForkClassifiedAppendReceiptV1>, ForkEventAuthorityErrorV1>
        {
            let permit = self.append_permit(child, source)?;
            let store = lock(&self.store);
            store.recover_classified_append(&self.session, &permit, operation_id, draft)
        }

        /// Stop this process: drop the coordinator, session, issuer, profile,
        /// adapter registry, and every permit, keeping only the store.
        fn into_store(
            self,
        ) -> TestResult<(
            LocalForkAuthenticationCredentialsV1,
            ForkAdmissionHostRecordV1,
            S,
        )> {
            let Self {
                coordinator, store, ..
            } = self;
            let LocalForkAdmissionCoordinatorV1 {
                credentials,
                host,
                journal,
                ..
            } = coordinator;
            drop(journal);
            let store = Arc::try_unwrap(store)
                .map_err(|_| "the stopped journal still shares its store")?
                .into_inner()
                .unwrap_or_else(PoisonError::into_inner);
            Ok((credentials, host, store))
        }

        /// Restart on the same database with a newly read `profile`, in the
        /// ADR-109 r12 startup order: preflight, FAO1, reconciliation, slot.
        fn restart(
            self,
            reopen: impl FnOnce(S) -> TestResult<S>,
            profile: Vec<ForkClassifierSourceV1>,
        ) -> TestResult<Self> {
            let (credentials, host, store) = self.into_store()?;
            let mut store = reopen(store)?;
            store.preflight_fork_classifier_profile(&profile)?;
            let session = credentials.open_authority(&mut store)?;
            let tuples = store.reconcile_fork_delivery_journal(&session);
            reconcile_startup(
                &credentials,
                (host, session.identity()),
                tuples,
                |tuple, proof| store.reconcile_fork_delivery_startup(&session, tuple, proof),
            )?;
            fixture_with(
                credentials,
                host,
                (store, session),
                JournalFault::Passthrough,
                profile,
            )
        }
    }

    /// Bind the Principal and commit one profile-registered Fork.
    fn registered_fixture<S: AcceptanceStore>(
        store: S,
    ) -> TestResult<(Fixture<S>, TimelineId, TimelineId)> {
        let mut fixture = fixture_profiled(
            store,
            JournalFault::Passthrough,
            profile_rows(&[ACCEPTED_DESCRIPTOR], &adapter_routes()?)?,
        )?;
        assert_eq!(response_code(&fixture.submit(bind_request(60), 60)?), 0);
        let parent = lock(&fixture.store)
            .create_timeline("classified parent")?
            .id();
        let request = fork_request(61, parent, ACCEPTED_DESCRIPTOR, 62, "classified-child");
        let child = fork_child(&fixture.submit(request, 61)?)?;
        Ok((fixture, parent, child))
    }

    /// Committed classified appends, plus a permit held into the restart.
    struct LiveScopeEvidence {
        committed: pos_store::ForkClassifiedAppendReceiptV1,
        host: pos_store::ForkClassifiedAppendReceiptV1,
        stale: pos_store::ForkAppendSourcePermitV1,
    }

    /// Exact configured adapter scopes admit appends; foreign, deregistered,
    /// and generic appends fail before Event insertion.
    fn assert_live_adapter_scopes<S: AcceptanceStore>(
        fixture: &Fixture<S>,
        child: TimelineId,
    ) -> TestResult<LiveScopeEvidence> {
        let foreign_route = pos_core::ForkEventSourceDescriptorV1::new(
            "gateway.other.v1",
            Hash::from_bytes([73; 32]),
        )?;
        assert!(!fixture.activate_external_adapter("gateway.adapter", foreign_route));
        assert!(fixture.activate_external_adapter("gateway.adapter", adapter_route()?));
        let external = adapter_source("gateway.adapter")?;
        let committed = fixture.append_classified_event(
            child,
            external.clone(),
            Hash::from_bytes([65; 32]),
            classified_draft(b"external"),
        )?;
        let host = fixture.append_classified_event(
            child,
            pos_core::ForkAppendSourceIdentityV1::HostInternal,
            Hash::from_bytes([66; 32]),
            classified_draft(b"host"),
        )?;
        assert_eq!(
            fixture
                .append_classified_event(
                    child,
                    adapter_source("foreign.adapter")?,
                    Hash::from_bytes([67; 32]),
                    classified_draft(b"foreign"),
                )
                .err(),
            Some(ForkEventAuthorityErrorV1::Unauthenticated)
        );
        assert!(lock(&fixture.store)
            .append(child, &[classified_draft(b"generic")])
            .is_err());

        // Deregistration revokes a permit that was issued before it.
        let held = fixture.append_permit(child, external.clone())?;
        fixture.deregister_external_adapter("gateway.adapter");
        assert_eq!(
            lock(&fixture.store)
                .append_classified(
                    &fixture.session,
                    &held,
                    Hash::from_bytes([68; 32]),
                    classified_draft(b"revoked"),
                )
                .err(),
            Some(ForkEventAuthorityErrorV1::Unauthenticated)
        );
        assert_eq!(
            fixture
                .append_classified_event(
                    child,
                    external.clone(),
                    Hash::from_bytes([69; 32]),
                    classified_draft(b"deregistered"),
                )
                .err(),
            Some(ForkEventAuthorityErrorV1::Unauthenticated)
        );
        assert_eq!(
            lock(&fixture.store).read_fork_event_suffix(child, 1)?.len(),
            2
        );
        assert!(fixture.activate_external_adapter("gateway.adapter", adapter_route()?));
        let stale = fixture.append_permit(child, external)?;
        Ok(LiveScopeEvidence {
            committed,
            host,
            stale,
        })
    }

    /// After a restart, old permits and adapter scopes are gone; a renewed
    /// scope reissues a permit that recovers the exact FOP1 operation.
    fn assert_restart_reissues_for_recovery<S: AcceptanceStore>(
        fixture: &Fixture<S>,
        child: TimelineId,
        evidence: &LiveScopeEvidence,
    ) -> TestResult {
        assert_eq!(
            lock(&fixture.store)
                .append_classified(
                    &fixture.session,
                    &evidence.stale,
                    Hash::from_bytes([70; 32]),
                    classified_draft(b"stale"),
                )
                .err(),
            Some(ForkEventAuthorityErrorV1::Unauthenticated)
        );
        let external = adapter_source("gateway.adapter")?;
        let operation = Hash::from_bytes([65; 32]);
        // Same-operation recovery requires the exact committed request,
        // including its Entity.
        let committed_draft = pos_core::EventDraft {
            entity: evidence.committed.event.entity,
            ..classified_draft(b"external")
        };
        assert_eq!(
            fixture
                .recover_classified_event(child, external.clone(), operation, &committed_draft)
                .err(),
            Some(ForkEventAuthorityErrorV1::Unauthenticated)
        );
        assert!(fixture.activate_external_adapter("gateway.adapter", adapter_route()?));
        assert_eq!(
            fixture.recover_classified_event(
                child,
                external.clone(),
                operation,
                &committed_draft
            )?,
            Some(evidence.committed.clone())
        );
        assert_eq!(
            fixture.append_classified_event(child, external, operation, committed_draft)?,
            evidence.committed
        );
        Ok(())
    }

    /// ADR-099 r11 section 4 over the Gateway's executor commands: only the
    /// profile-selected FCS1 registers, an unprofiled Fork is held at code 6
    /// until a restarted profile adds its row, live adapter scopes gate every
    /// append, a restart discards permits and the adapter registry, a
    /// reissued permit recovers the same FOP1 operation, and Replay needs no
    /// FCP1.
    fn assert_classified_host_composition<S: AcceptanceStore>(
        store: S,
        reopen: impl Fn(S) -> TestResult<S>,
    ) -> TestResult {
        let (mut fixture, parent, child) = registered_fixture(store)?;
        let late = fork_request(63, parent, LATE_DESCRIPTOR, 64, "late-child");
        for _ in 0..2 {
            assert_eq!(response_code(&fixture.submit(late.clone(), 63)?), 6);
        }
        let evidence = assert_live_adapter_scopes(&fixture, child)?;

        // Restart: a new activation rereads FCP1, which may add a row.
        let mut fixture = fixture.restart(
            &reopen,
            profile_rows(&[ACCEPTED_DESCRIPTOR, LATE_DESCRIPTOR], &adapter_routes()?)?,
        )?;
        assert_restart_reissues_for_recovery(&fixture, child, &evidence)?;
        let late_child = fork_child(&fixture.submit(late, 63)?)?;
        fixture.append_classified_event(
            late_child,
            pos_core::ForkAppendSourceIdentityV1::HostInternal,
            Hash::from_bytes([71; 32]),
            classified_draft(b"late-host"),
        )?;

        // Replay verifies durable authority with no FCP1, session, or adapter.
        let (_, _, store) = fixture.into_store()?;
        let store = reopen(store)?;
        let suffix = store.read_fork_event_suffix(child, 1)?;
        assert_eq!(
            suffix
                .iter()
                .map(|(_, _, operation)| operation.clone())
                .collect::<Vec<_>>(),
            vec![evidence.committed.operation, evidence.host.operation]
        );
        assert_eq!(store.read_fork_event_suffix(late_child, 1)?.len(), 1);
        Ok(())
    }

    /// A restart whose FCP1 changes or drops a durable FCS1 row fails the
    /// read-only preflight that precedes the FAO1 open proof.
    fn assert_changed_profile_fails_preflight<S: AcceptanceStore>(
        new_store: impl Fn() -> TestResult<S>,
    ) -> TestResult {
        for changed in [
            profile_rows(&[ACCEPTED_DESCRIPTOR], &[])?,
            profile_rows(&[LATE_DESCRIPTOR], &adapter_routes()?)?,
        ] {
            let (fixture, _, _) = registered_fixture(new_store()?)?;
            let (_, _, store) = fixture.into_store()?;
            assert_eq!(
                store.preflight_fork_classifier_profile(&changed).err(),
                Some(ForkEventAuthorityErrorV1::Conflict)
            );
        }
        Ok(())
    }

    fn gated_memory_store() -> TestResult<MemoryStore> {
        let mut store = MemoryStore::new();
        store.bind_erasure_gate(Arc::new(pos_core::ErasureContainmentGateV1::new_test_open()))?;
        Ok(store)
    }

    fn gated_sqlite_store(path: &std::path::Path) -> TestResult<pos_store::sqlite::SqliteStore> {
        let mut store =
            pos_store::sqlite::SqliteStore::open(path.to_str().ok_or("non-UTF-8 path")?)?;
        store.bind_erasure_gate(Arc::new(pos_core::ErasureContainmentGateV1::new_test_open()))?;
        Ok(store)
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn memory_gateway_composition_registers_appends_and_recovers_classified_events() -> TestResult {
        assert_classified_host_composition(gated_memory_store()?, Ok)
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn sqlite_gateway_composition_registers_appends_and_recovers_classified_events() -> TestResult {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("classified-gateway.sqlite");
        assert_classified_host_composition(gated_sqlite_store(&path)?, |store| {
            drop(store);
            gated_sqlite_store(&path)
        })
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn memory_gateway_restart_rejects_a_changed_or_missing_profile_row() -> TestResult {
        assert_changed_profile_fails_preflight(gated_memory_store)
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn sqlite_gateway_restart_rejects_a_changed_or_missing_profile_row() -> TestResult {
        let directory = tempfile::tempdir()?;
        let counter = std::cell::Cell::new(0_u8);
        assert_changed_profile_fails_preflight(|| {
            counter.set(counter.get() + 1);
            gated_sqlite_store(
                &directory
                    .path()
                    .join(format!("changed-profile-{}.sqlite", counter.get())),
            )
        })
    }
}
