//! Private ADR-109 coordinator between the Unix listener and the Gateway's
//! one erasure host (ADR-109 revision 9, Decision 1).
//!
//! The coordinator holds no store adapter. It keeps the ADR-107 credentials,
//! the FAH1 record and the session identity digest on the listener thread,
//! builds and signs every FAC1 and FRP1 there, and submits the five private
//! journal commands to the `StoreExecutor` that owns the host.

use std::{
    io,
    os::unix::net::{UnixListener, UnixStream},
};

use ciborium::value::Value;
use pos_core::{
    ForkAdmissionCommandCodecErrorV1, ForkAdmissionErrorV1, ForkAdmissionHostCommandV1,
    ForkAdmissionHostRecordV1, ForkAdmissionOperationKindV1, ForkAdmissionOperationResultV1,
    ForkAdmissionRecoveryCommandV1, ForkAdmissionRecoveryProofV1, ForkCreateCommandV1, Hash,
    PrincipalOwnerCommandV1,
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
        ForkDeliveryMarkV1,
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

/// The five private journal commands the listener thread submits to the
/// executor that owns the host (ADR-109 revision 9, Decision 1 item 4).
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
        match self.journal.execute(claim, &command) {
            Ok(Ok(ForkDeliveryExecutionV1::Committed(result))) => {
                PreparedDeliveryV1::release(claim, &result, true)
            }
            Ok(Ok(ForkDeliveryExecutionV1::Rejected(error))) => {
                PreparedDeliveryV1::plain(reject(authority_code(error)))
            }
            Ok(
                Ok(ForkDeliveryExecutionV1::Uncertain)
                | Err(ForkDeliveryJournalErrorV1::StorageIndeterminate),
            )
            | Err(ForkAdmissionSubmissionErrorV1::Lost) => {
                PreparedDeliveryV1::plain(reject(LocalForkAdmissionCodeV1::Indeterminate))
            }
            // The journal refused the claim before FAC1 submission, so the
            // Pending row is still live and must be deleted (ADR-109).
            Ok(Err(
                ForkDeliveryJournalErrorV1::InvalidTuple
                | ForkDeliveryJournalErrorV1::Conflict
                | ForkDeliveryJournalErrorV1::Fenced
                | ForkDeliveryJournalErrorV1::Corrupt,
            )) => self.cancel_pending(claim, LocalForkAdmissionCodeV1::AuthorityUnavailable),
            // The execute command definitely did not run (ADR-109 r9
            // Decision 1 item 6): cancel Pending, then answer 6 or 5.
            Err(
                error @ (ForkAdmissionSubmissionErrorV1::Busy
                | ForkAdmissionSubmissionErrorV1::Unavailable),
            ) => self.cancel_pending(claim, submission_code(error)),
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
        match self
            .journal
            .recover(tuple, &proof, authentication.principal_digest())
        {
            Ok(Ok(result)) => {
                PreparedDeliveryV1::release(claim, &result, state != ForkDeliveryStateV1::Delivered)
            }
            Ok(Err(_)) | Err(_) => {
                PreparedDeliveryV1::plain(reject(LocalForkAdmissionCodeV1::Indeterminate))
            }
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
    use pos_core::{EventStore as _, ForkAuthenticationPolicyV1, Hash, TimelineId};
    use pos_store::{
        memory::MemoryStore, ForkAdmissionAuthorityBootstrapPortV1 as _,
        ForkAdmissionDeliveryJournalPortV1 as _,
    };

    type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

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
    }

    /// A journal row whose zero operation identity no FRC1 can carry.
    const fn zero_operation_tuple() -> ForkDeliveryTupleV1 {
        ForkDeliveryTupleV1 {
            host_request_id: Hash::from_bytes([1; 32]),
            kind: ForkAdmissionOperationKindV1::PrincipalOwner,
            operation_id: Hash::zero(),
        }
    }

    fn lock(store: &Mutex<MemoryStore>) -> MutexGuard<'_, MemoryStore> {
        store.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The executor's journal commands run directly on one shared store.
    struct StoreJournal {
        store: Arc<Mutex<MemoryStore>>,
        session: Arc<ForkAdmissionAuthoritySessionV1>,
        policy: ForkAuthenticationPolicyV1,
        fault: JournalFault,
    }

    impl LocalForkDeliveryJournalV1 for StoreJournal {
        fn claim(
            &mut self,
            tuple: ForkDeliveryTupleV1,
        ) -> ForkAdmissionSubmissionV1<ForkDeliveryClaimOutcomeV1> {
            match self.fault {
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
            if self.fault == JournalFault::Cancel {
                return Ok(Err(ForkDeliveryJournalErrorV1::StorageIndeterminate));
            }
            Ok(lock(&self.store).cancel_pending_fork_delivery(&self.session, claim))
        }

        fn execute(
            &mut self,
            claim: ForkDeliveryClaimV1,
            command: &ForkAdmissionHostCommandV1,
        ) -> ForkAdmissionSubmissionV1<ForkDeliveryExecutionV1> {
            match self.fault {
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
            if self.fault == JournalFault::Recover {
                return Ok(Err(ForkDeliveryJournalErrorV1::StorageIndeterminate));
            }
            Ok(lock(&self.store).recover_fork_delivery(&self.session, tuple, proof, principal))
        }

        fn mark(
            &mut self,
            claim: ForkDeliveryClaimV1,
            mark: ForkDeliveryMarkV1,
        ) -> ForkAdmissionSubmissionV1<()> {
            match (self.fault, mark) {
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
    }

    struct Fixture {
        coordinator: LocalForkAdmissionCoordinatorV1,
        store: Arc<Mutex<MemoryStore>>,
        session: Arc<ForkAdmissionAuthoritySessionV1>,
    }

    fn fixture_over(mut store: MemoryStore, fault: JournalFault) -> TestResult<Fixture> {
        let credentials = crate::local_fork_authentication::test_credentials_for_current_peer()?;
        credentials.provision_authority(&mut store)?;
        let session = credentials.open_authority(&mut store)?;
        let host = store.fork_admission_host_record()?;
        Ok(fixture_with(credentials, host, (store, session), fault))
    }

    fn fixture_with(
        credentials: LocalForkAuthenticationCredentialsV1,
        host: ForkAdmissionHostRecordV1,
        (store, session): (MemoryStore, ForkAdmissionAuthoritySessionV1),
        fault: JournalFault,
    ) -> Fixture {
        let store = Arc::new(Mutex::new(store));
        let session = Arc::new(session);
        let journal = StoreJournal {
            store: Arc::clone(&store),
            session: Arc::clone(&session),
            policy: credentials.policy().clone(),
            fault,
        };
        Fixture {
            coordinator: LocalForkAdmissionCoordinatorV1::new(
                credentials,
                host,
                session.identity(),
                Box::new(journal),
            ),
            store,
            session,
        }
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
        );
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
}
