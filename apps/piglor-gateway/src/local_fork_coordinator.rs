//! Private ADR-109 coordinator between the Unix listener and durable journal.

use std::{
    io,
    os::unix::net::{UnixListener, UnixStream},
};

use ciborium::value::Value;
use pos_core::{
    ForkAdmissionCommandCodecErrorV1, ForkAdmissionErrorV1, ForkAdmissionHostCommandV1,
    ForkAdmissionHostRecordV1, ForkAdmissionOperationKindV1, ForkAdmissionOperationResultV1,
    ForkAdmissionRecoveryCommandV1, ForkAdmissionRecoveryProofV1, ForkCreateCommandV1,
    PrincipalOwnerCommandV1,
};
use pos_store::{
    ForkAdmissionAuthorityBootstrapPortV1, ForkAdmissionAuthoritySessionV1,
    ForkAdmissionDeliveryJournalPortV1, ForkDeliveryClaimOutcomeV1, ForkDeliveryClaimV1,
    ForkDeliveryExecutionV1, ForkDeliveryJournalErrorV1, ForkDeliveryStateV1, ForkDeliveryTupleV1,
};

use crate::{
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

/// Gateway-owned authority session and its one durable journal adapter.
pub(super) struct LocalForkAdmissionCoordinatorV1<S> {
    credentials: LocalForkAuthenticationCredentialsV1,
    host: ForkAdmissionHostRecordV1,
    session: ForkAdmissionAuthoritySessionV1,
    store: S,
}

impl<S> LocalForkAdmissionCoordinatorV1<S>
where
    S: ForkAdmissionAuthorityBootstrapPortV1 + ForkAdmissionDeliveryJournalPortV1,
{
    /// Open an already-provisioned FAH1 authority. Missing or unequal authority
    /// fails before the caller can bind a Unix listener.
    pub(super) fn open(
        mut store: S,
        credentials: LocalForkAuthenticationCredentialsV1,
    ) -> Result<Self, LocalForkAuthenticationErrorV1> {
        let session = credentials
            .open_authority(&mut store)
            .map_err(|_| LocalForkAuthenticationErrorV1::CredentialUnavailable)?;
        let host = store
            .fork_admission_host_record()
            .map_err(|_| LocalForkAuthenticationErrorV1::CredentialUnavailable)?;
        Ok(Self {
            credentials,
            host,
            session,
            store,
        })
    }

    /// Reconcile every retained tuple with a private FRP1 before binding the
    /// listener. This never releases a result or Principal: a retained exact
    /// operation stays Uncertain for a same-Principal response retry.
    pub(super) fn reconcile_startup(&mut self) -> Result<(), LocalForkAuthenticationErrorV1> {
        let tuples = self
            .store
            .reconcile_fork_delivery_journal(&self.session)
            .map_err(|_| LocalForkAuthenticationErrorV1::CredentialUnavailable)?;
        for tuple in tuples {
            let proof = self.recovery_proof(tuple)?;
            self.store
                .reconcile_fork_delivery_startup(&self.session, tuple, &proof)
                .map_err(|_| LocalForkAuthenticationErrorV1::CredentialUnavailable)?;
        }
        Ok(())
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
    /// authority input: all FAC1/FRP1 bytes are built here from the opened
    /// session and protected credentials.
    fn handle(&mut self, completed: CompletedLocalForkAdmissionV1) -> PreparedDeliveryV1 {
        let Ok(delivery_tuple) = delivery_tuple(&completed) else {
            return PreparedDeliveryV1::plain(reject(LocalForkAdmissionCodeV1::InvalidRequest));
        };
        match self
            .store
            .claim_fork_delivery(&self.session, delivery_tuple)
        {
            Ok(ForkDeliveryClaimOutcomeV1::Owner(claim)) => self.execute_owned(completed, claim),
            Ok(ForkDeliveryClaimOutcomeV1::Busy) => {
                PreparedDeliveryV1::plain(reject(LocalForkAdmissionCodeV1::Indeterminate))
            }
            Ok(ForkDeliveryClaimOutcomeV1::Reconcile(claim, state)) => {
                self.recover(completed, claim, state)
            }
            Err(_) => PreparedDeliveryV1::plain(reject(LocalForkAdmissionCodeV1::Indeterminate)),
        }
    }

    fn write_prepared(
        &mut self,
        stream: &mut UnixStream,
        prepared: &PreparedDeliveryV1,
    ) -> io::Result<()> {
        let write_result = write_response(stream, &prepared.response);
        if let Some(claim) = prepared.claim.filter(|_| prepared.mark_after_write) {
            let transition = if write_result.is_ok() {
                self.store
                    .mark_fork_delivery_delivered(&self.session, claim)
            } else {
                self.store
                    .mark_fork_delivery_uncertain(&self.session, claim)
            };
            if transition.is_err() && write_result.is_ok() {
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
        match self.store.execute_claimed_fork_delivery(
            &self.session,
            self.credentials.policy(),
            claim,
            &command,
        ) {
            Ok(ForkDeliveryExecutionV1::Committed(result)) => {
                PreparedDeliveryV1::release(claim, &result, true)
            }
            Ok(ForkDeliveryExecutionV1::Rejected(error)) => {
                PreparedDeliveryV1::plain(reject(authority_code(error)))
            }
            Ok(ForkDeliveryExecutionV1::Uncertain)
            | Err(ForkDeliveryJournalErrorV1::StorageIndeterminate) => {
                PreparedDeliveryV1::plain(reject(LocalForkAdmissionCodeV1::Indeterminate))
            }
            // The journal refused the claim before FAC1 submission, so the
            // Pending row is still live and must be deleted (ADR-109).
            Err(
                ForkDeliveryJournalErrorV1::InvalidTuple
                | ForkDeliveryJournalErrorV1::Conflict
                | ForkDeliveryJournalErrorV1::Fenced
                | ForkDeliveryJournalErrorV1::Corrupt,
            ) => self.cancel_pending(claim, LocalForkAdmissionCodeV1::AuthorityUnavailable),
        }
    }

    /// Definite failures before FAC1 cannot retain a live Pending claim.
    /// A failed fenced cancellation leaves the caller with only code 6.
    fn cancel_pending(
        &mut self,
        claim: ForkDeliveryClaimV1,
        code: LocalForkAdmissionCodeV1,
    ) -> PreparedDeliveryV1 {
        match self
            .store
            .cancel_pending_fork_delivery(&self.session, claim)
        {
            Ok(()) => PreparedDeliveryV1::plain(reject(code)),
            Err(_) => PreparedDeliveryV1::plain(reject(LocalForkAdmissionCodeV1::Indeterminate)),
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
        let Ok(proof) = self.recovery_proof(tuple) else {
            return PreparedDeliveryV1::plain(reject(
                LocalForkAdmissionCodeV1::AuthorityUnavailable,
            ));
        };
        self.store
            .recover_fork_delivery(
                &self.session,
                tuple,
                &proof,
                authentication.principal_digest(),
            )
            .map_or_else(
                |_| PreparedDeliveryV1::plain(reject(LocalForkAdmissionCodeV1::Indeterminate)),
                |result| {
                    PreparedDeliveryV1::release(
                        claim,
                        &result,
                        state != ForkDeliveryStateV1::Delivered,
                    )
                },
            )
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
            Value::Bytes(self.session.identity().as_bytes().to_vec()),
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

    fn recovery_proof(
        &self,
        tuple: ForkDeliveryTupleV1,
    ) -> Result<ForkAdmissionRecoveryProofV1, LocalForkAuthenticationErrorV1> {
        let fields = vec![
            Value::Text("FRC1".to_owned()),
            Value::Integer(1.into()),
            Value::Bytes(self.host.store_id().as_bytes().to_vec()),
            Value::Bytes(self.session.identity().as_bytes().to_vec()),
            Value::Integer(tuple.kind.wire().into()),
            Value::Bytes(tuple.operation_id.as_bytes().to_vec()),
        ];
        encode(fields, ForkAdmissionRecoveryCommandV1::from_canonical_cbor)
            .and_then(|command| self.credentials.sign_recovery(&command))
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
        | ForkAdmissionErrorV1::EntropyUnavailable => {
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
    };

    use super::*;
    use pos_core::{EventStore as _, Hash, TimelineId};
    use pos_store::memory::MemoryStore;

    #[derive(Clone, Copy, Eq, PartialEq)]
    enum StoreFault {
        HostRecord,
        Claim,
        Cancel,
        ExecuteError,
        ExecuteCorrupt,
        ExecuteRejected,
        ExecuteUncertain,
        Recover,
        MarkDelivered,
        MarkUncertain,
        ReconcileList,
        ReconcileTuple,
    }

    struct FaultingStore {
        inner: MemoryStore,
        fault: StoreFault,
    }

    impl ForkAdmissionAuthorityBootstrapPortV1 for FaultingStore {
        fn begin_fork_admission_initialize(
            &mut self,
            host_key: pos_core::PublicKey,
            policy_digest: Hash,
        ) -> Result<
            pos_core::ForkAdmissionInitializeChallengeV1,
            pos_store::ForkAdmissionAuthorityErrorV1,
        > {
            self.inner
                .begin_fork_admission_initialize(host_key, policy_digest)
        }

        fn finalize_fork_admission_initialize(
            &mut self,
            challenge: &pos_core::ForkAdmissionInitializeChallengeV1,
            signature: &pos_core::Signature,
        ) -> Result<pos_core::ForkAdmissionHostRecordV1, pos_store::ForkAdmissionAuthorityErrorV1>
        {
            self.inner
                .finalize_fork_admission_initialize(challenge, signature)
        }

        fn fork_admission_host_record(
            &self,
        ) -> Result<pos_core::ForkAdmissionHostRecordV1, pos_store::ForkAdmissionAuthorityErrorV1>
        {
            if self.fault == StoreFault::HostRecord {
                return Err(pos_store::ForkAdmissionAuthorityErrorV1::StorageIndeterminate);
            }
            self.inner.fork_admission_host_record()
        }

        fn begin_fork_admission_open(
            &mut self,
            host_key: pos_core::PublicKey,
            policy_digest: Hash,
        ) -> Result<pos_core::ForkAdmissionOpenChallengeV1, pos_store::ForkAdmissionAuthorityErrorV1>
        {
            self.inner
                .begin_fork_admission_open(host_key, policy_digest)
        }

        fn finalize_fork_admission_open(
            &mut self,
            challenge: &pos_core::ForkAdmissionOpenChallengeV1,
            signature: &pos_core::Signature,
        ) -> Result<ForkAdmissionAuthoritySessionV1, pos_store::ForkAdmissionAuthorityErrorV1>
        {
            self.inner
                .finalize_fork_admission_open(challenge, signature)
        }

        fn advance_fork_admission_wall_fence(
            &mut self,
            session: &ForkAdmissionAuthoritySessionV1,
        ) -> Result<(), pos_store::ForkAdmissionAuthorityErrorV1> {
            self.inner.advance_fork_admission_wall_fence(session)
        }
    }

    impl ForkAdmissionDeliveryJournalPortV1 for FaultingStore {
        fn claim_fork_delivery(
            &mut self,
            session: &ForkAdmissionAuthoritySessionV1,
            tuple: ForkDeliveryTupleV1,
        ) -> Result<ForkDeliveryClaimOutcomeV1, pos_store::ForkDeliveryJournalErrorV1> {
            if self.fault == StoreFault::Claim {
                return Err(pos_store::ForkDeliveryJournalErrorV1::StorageIndeterminate);
            }
            self.inner.claim_fork_delivery(session, tuple)
        }

        fn cancel_pending_fork_delivery(
            &mut self,
            session: &ForkAdmissionAuthoritySessionV1,
            claim: pos_store::ForkDeliveryClaimV1,
        ) -> Result<(), pos_store::ForkDeliveryJournalErrorV1> {
            if self.fault == StoreFault::Cancel {
                return Err(pos_store::ForkDeliveryJournalErrorV1::StorageIndeterminate);
            }
            self.inner.cancel_pending_fork_delivery(session, claim)
        }

        fn execute_claimed_fork_delivery(
            &mut self,
            session: &ForkAdmissionAuthoritySessionV1,
            policy: &pos_core::ForkAuthenticationPolicyV1,
            claim: pos_store::ForkDeliveryClaimV1,
            command: &pos_core::ForkAdmissionHostCommandV1,
        ) -> Result<ForkDeliveryExecutionV1, pos_store::ForkDeliveryJournalErrorV1> {
            match self.fault {
                StoreFault::ExecuteError => {
                    Err(pos_store::ForkDeliveryJournalErrorV1::StorageIndeterminate)
                }
                StoreFault::ExecuteCorrupt => Err(pos_store::ForkDeliveryJournalErrorV1::Corrupt),
                StoreFault::ExecuteRejected => Ok(ForkDeliveryExecutionV1::Rejected(
                    ForkAdmissionErrorV1::InvalidRequest,
                )),
                StoreFault::ExecuteUncertain => Ok(ForkDeliveryExecutionV1::Uncertain),
                _ => self
                    .inner
                    .execute_claimed_fork_delivery(session, policy, claim, command),
            }
        }

        fn recover_fork_delivery(
            &mut self,
            session: &ForkAdmissionAuthoritySessionV1,
            tuple: ForkDeliveryTupleV1,
            proof: &pos_core::ForkAdmissionRecoveryProofV1,
            current_principal_digest: Hash,
        ) -> Result<ForkAdmissionOperationResultV1, pos_store::ForkDeliveryJournalErrorV1> {
            if self.fault == StoreFault::Recover {
                return Err(pos_store::ForkDeliveryJournalErrorV1::StorageIndeterminate);
            }
            self.inner
                .recover_fork_delivery(session, tuple, proof, current_principal_digest)
        }

        fn mark_fork_delivery_uncertain(
            &mut self,
            session: &ForkAdmissionAuthoritySessionV1,
            claim: pos_store::ForkDeliveryClaimV1,
        ) -> Result<(), pos_store::ForkDeliveryJournalErrorV1> {
            if self.fault == StoreFault::MarkUncertain {
                return Err(pos_store::ForkDeliveryJournalErrorV1::StorageIndeterminate);
            }
            self.inner.mark_fork_delivery_uncertain(session, claim)
        }

        fn mark_fork_delivery_delivered(
            &mut self,
            session: &ForkAdmissionAuthoritySessionV1,
            claim: pos_store::ForkDeliveryClaimV1,
        ) -> Result<(), pos_store::ForkDeliveryJournalErrorV1> {
            if self.fault == StoreFault::MarkDelivered {
                return Err(pos_store::ForkDeliveryJournalErrorV1::StorageIndeterminate);
            }
            self.inner.mark_fork_delivery_delivered(session, claim)
        }

        fn reconcile_fork_delivery_journal(
            &mut self,
            session: &ForkAdmissionAuthoritySessionV1,
        ) -> Result<Vec<ForkDeliveryTupleV1>, pos_store::ForkDeliveryJournalErrorV1> {
            if self.fault == StoreFault::ReconcileList {
                return Err(pos_store::ForkDeliveryJournalErrorV1::StorageIndeterminate);
            }
            self.inner.reconcile_fork_delivery_journal(session)
        }

        fn reconcile_fork_delivery_startup(
            &mut self,
            session: &ForkAdmissionAuthoritySessionV1,
            tuple: ForkDeliveryTupleV1,
            proof: &pos_core::ForkAdmissionRecoveryProofV1,
        ) -> Result<pos_store::ForkDeliveryStartupOutcomeV1, pos_store::ForkDeliveryJournalErrorV1>
        {
            if self.fault == StoreFault::ReconcileTuple {
                return Err(pos_store::ForkDeliveryJournalErrorV1::StorageIndeterminate);
            }
            self.inner
                .reconcile_fork_delivery_startup(session, tuple, proof)
        }

        fn purge_expired_fork_delivery(
            &mut self,
            session: &ForkAdmissionAuthoritySessionV1,
            tuple: ForkDeliveryTupleV1,
        ) -> Result<(), pos_store::ForkDeliveryJournalErrorV1> {
            self.inner.purge_expired_fork_delivery(session, tuple)
        }
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

    fn coordinator(
    ) -> Result<LocalForkAdmissionCoordinatorV1<MemoryStore>, Box<dyn std::error::Error>> {
        let credentials = crate::local_fork_authentication::test_credentials_for_current_peer()?;
        let mut store = MemoryStore::new();
        credentials.provision_authority(&mut store)?;
        let mut coordinator = LocalForkAdmissionCoordinatorV1::open(store, credentials)?;
        coordinator.reconcile_startup()?;
        Ok(coordinator)
    }

    fn fault_coordinator(
        fault: StoreFault,
    ) -> Result<LocalForkAdmissionCoordinatorV1<FaultingStore>, Box<dyn std::error::Error>> {
        let LocalForkAdmissionCoordinatorV1 {
            credentials,
            host,
            session,
            store,
        } = coordinator()?;
        Ok(LocalForkAdmissionCoordinatorV1 {
            credentials,
            host,
            session,
            store: FaultingStore {
                inner: store,
                fault,
            },
        })
    }

    fn completed_bind(
        credentials: &LocalForkAuthenticationCredentialsV1,
        operation: u8,
        host_request: u8,
    ) -> Result<CompletedLocalForkAdmissionV1, Box<dyn std::error::Error>> {
        Ok(CompletedLocalForkAdmissionV1 {
            peer: current_peer(credentials)?,
            request: bind_request(operation),
            host_request_id: Hash::from_bytes([host_request; 32]),
        })
    }

    fn response_code(prepared: &PreparedDeliveryV1) -> u8 {
        prepared.response.to_canonical_cbor()[8]
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn coordinator_closes_on_host_and_startup_store_faults(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let credentials = crate::local_fork_authentication::test_credentials_for_current_peer()?;
        let mut store = MemoryStore::new();
        credentials.provision_authority(&mut store)?;
        assert_eq!(
            LocalForkAdmissionCoordinatorV1::open(
                FaultingStore {
                    inner: store,
                    fault: StoreFault::HostRecord,
                },
                credentials,
            )
            .err(),
            Some(LocalForkAuthenticationErrorV1::CredentialUnavailable)
        );

        let mut list_fault = fault_coordinator(StoreFault::ReconcileList)?;
        assert_eq!(
            list_fault.reconcile_startup().err(),
            Some(LocalForkAuthenticationErrorV1::CredentialUnavailable)
        );

        let mut tuple_fault = fault_coordinator(StoreFault::ReconcileTuple)?;
        let completed = completed_bind(&tuple_fault.credentials, 41, 42)?;
        let tuple = delivery_tuple(&completed)
            .map_err(|()| io::Error::other("valid bind must produce a tuple"))?;
        assert!(matches!(
            tuple_fault
                .store
                .claim_fork_delivery(&tuple_fault.session, tuple)?,
            ForkDeliveryClaimOutcomeV1::Owner(_)
        ));
        assert_eq!(
            tuple_fault.reconcile_startup().err(),
            Some(LocalForkAuthenticationErrorV1::CredentialUnavailable)
        );
        Ok(())
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn coordinator_closes_on_claim_execution_and_cancel_faults(
    ) -> Result<(), Box<dyn std::error::Error>> {
        for (fault, expected_code) in [
            (StoreFault::Claim, 6),
            (StoreFault::ExecuteError, 6),
            (StoreFault::ExecuteRejected, 7),
            (StoreFault::ExecuteUncertain, 6),
        ] {
            let mut coordinator = fault_coordinator(fault)?;
            let completed = completed_bind(&coordinator.credentials, 43, 44)?;
            assert_eq!(response_code(&coordinator.handle(completed)), expected_code);
        }

        // A journal refusal before FAC1 submission deletes Pending, so the
        // same tuple can be claimed again by a corrected request.
        let mut corrupt = fault_coordinator(StoreFault::ExecuteCorrupt)?;
        let completed = completed_bind(&corrupt.credentials, 64, 65)?;
        let tuple = delivery_tuple(&completed)
            .map_err(|()| io::Error::other("valid bind must produce a tuple"))?;
        assert_eq!(response_code(&corrupt.handle(completed)), 5);
        assert!(matches!(
            corrupt.store.claim_fork_delivery(&corrupt.session, tuple)?,
            ForkDeliveryClaimOutcomeV1::Owner(_)
        ));

        let mut cancel_fault = fault_coordinator(StoreFault::Cancel)?;
        let completed = CompletedLocalForkAdmissionV1 {
            peer: crate::local_fork_authentication::test_unregistered_peer()?,
            request: bind_request(45),
            host_request_id: Hash::from_bytes([46; 32]),
        };
        assert_eq!(response_code(&cancel_fault.handle(completed)), 6);
        Ok(())
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn coordinator_closes_on_recovery_and_response_transition_faults(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut recover_fault = fault_coordinator(StoreFault::Recover)?;
        let first = completed_bind(&recover_fault.credentials, 47, 48)?;
        assert_eq!(response_code(&recover_fault.handle(first)), 0);
        let retry = completed_bind(&recover_fault.credentials, 47, 48)?;
        assert_eq!(response_code(&recover_fault.handle(retry)), 6);

        let mut delivered_fault = fault_coordinator(StoreFault::MarkDelivered)?;
        let completed = completed_bind(&delivered_fault.credentials, 49, 50)?;
        let prepared = delivered_fault.handle(completed);
        assert_eq!(response_code(&prepared), 0);
        let (mut writer, _reader) = UnixStream::pair()?;
        assert!(delivered_fault
            .write_prepared(&mut writer, &prepared)
            .is_err());

        let mut uncertain_fault = fault_coordinator(StoreFault::MarkUncertain)?;
        let completed = completed_bind(&uncertain_fault.credentials, 51, 52)?;
        let prepared = uncertain_fault.handle(completed);
        assert_eq!(response_code(&prepared), 0);
        let (mut writer, reader) = UnixStream::pair()?;
        drop(reader);
        assert!(uncertain_fault
            .write_prepared(&mut writer, &prepared)
            .is_err());
        Ok(())
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn coordinator_cancels_a_pending_claim_when_fork_command_is_invalid(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut coordinator = coordinator()?;
        let request = fork_request(
            53,
            TimelineId::from_ulid(ulid::Ulid::from_bytes([54; 16])),
            55,
            56,
            "",
        );
        let completed = CompletedLocalForkAdmissionV1 {
            peer: current_peer(&coordinator.credentials)?,
            request,
            host_request_id: Hash::from_bytes([57; 32]),
        };
        let tuple = delivery_tuple(&completed)
            .map_err(|()| io::Error::other("fork request must produce a tuple"))?;
        assert_eq!(response_code(&coordinator.handle(completed)), 5);
        let reclaimed = coordinator
            .store
            .claim_fork_delivery(&coordinator.session, tuple)?;
        assert!(matches!(reclaimed, ForkDeliveryClaimOutcomeV1::Owner(_)));
        Ok(())
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn coordinator_keeps_retained_delivery_after_unauthenticated_retry(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut coordinator = coordinator()?;
        let first = completed_bind(&coordinator.credentials, 58, 59)?;
        assert_eq!(response_code(&coordinator.handle(first)), 0);
        let unauthenticated_retry = CompletedLocalForkAdmissionV1 {
            peer: crate::local_fork_authentication::test_unregistered_peer()?,
            request: bind_request(58),
            host_request_id: Hash::from_bytes([59; 32]),
        };
        assert_eq!(response_code(&coordinator.handle(unauthenticated_retry)), 6);
        let authenticated_retry = completed_bind(&coordinator.credentials, 58, 59)?;
        assert_eq!(response_code(&coordinator.handle(authenticated_retry)), 0);
        Ok(())
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

    #[test]
    #[cfg(target_os = "linux")]
    fn real_pathname_peer_receives_and_retries_a_signed_bind_admission(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let credentials = crate::local_fork_authentication::test_credentials_for_current_peer()?;
        let mut store = MemoryStore::new();
        credentials.provision_authority(&mut store)?;
        let mut coordinator = LocalForkAdmissionCoordinatorV1::open(store, credentials)?;
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
            coordinator.serve_one(&listener)?;
            assert!(client
                .join()
                .map_err(|_| io::Error::other("close request panicked"))??);
        }
        let mut semantic_payload = payload.clone();
        semantic_payload[11..].fill(0);
        let semantic_path = path.clone();
        let semantic = std::thread::spawn(move || request(semantic_path, semantic_payload));
        coordinator.serve_one(&listener)?;
        assert_eq!(
            semantic
                .join()
                .map_err(|_| io::Error::other("semantic request panicked"))??,
            vec![0x84, 0x65, b'F', b'A', b'R', b'L', b'1', 1, 7, 0xf6]
        );
        let first_path = path.clone();
        let first_payload = payload.clone();
        let first = std::thread::spawn(move || request(first_path, first_payload));
        coordinator.serve_one(&listener)?;
        let first = first
            .join()
            .map_err(|_| io::Error::other("first request panicked"))??;
        let second = std::thread::spawn(move || request(path, payload));
        coordinator.serve_one(&listener)?;
        let second = second
            .join()
            .map_err(|_| io::Error::other("retry request panicked"))??;
        assert_eq!(first, second);
        assert_eq!(
            &first[..10],
            &[0x84, 0x65, b'F', b'A', b'R', b'L', b'1', 1, 0, 0x82]
        );
        Ok(())
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn coordinator_encodes_commands_and_retries_a_delivered_bind(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut coordinator = coordinator()?;
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

        let completed = CompletedLocalForkAdmissionV1 {
            peer: current_peer(&coordinator.credentials)?,
            request: bind.clone(),
            host_request_id: Hash::from_bytes([16; 32]),
        };
        let prepared = coordinator.handle(completed);
        let (mut writer, _reader) = UnixStream::pair()?;
        coordinator.write_prepared(&mut writer, &prepared)?;
        assert_eq!(
            prepared.response.to_canonical_cbor()[..10],
            [0x84, 0x65, b'F', b'A', b'R', b'L', b'1', 1, 0, 0x82]
        );

        let retry = coordinator.handle(CompletedLocalForkAdmissionV1 {
            peer: current_peer(&coordinator.credentials)?,
            request: bind,
            host_request_id: Hash::from_bytes([16; 32]),
        });
        assert_eq!(
            retry.response.to_canonical_cbor()[..10],
            [0x84, 0x65, b'F', b'A', b'R', b'L', b'1', 1, 0, 0x82]
        );

        // ADR-099: a new Bind for the already-bound Principal resolves to the
        // one immutable committed binding rather than a conflict.
        let rebind = coordinator.handle(CompletedLocalForkAdmissionV1 {
            peer: current_peer(&coordinator.credentials)?,
            request: bind_request(21),
            host_request_id: Hash::from_bytes([22; 32]),
        });
        assert_eq!(
            rebind.response.to_canonical_cbor()[..10],
            [0x84, 0x65, b'F', b'A', b'R', b'L', b'1', 1, 0, 0x82]
        );
        Ok(())
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn coordinator_recovers_interrupted_and_retained_fork_deliveries(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut coordinator = coordinator()?;
        let binding = coordinator.handle(CompletedLocalForkAdmissionV1 {
            peer: current_peer(&coordinator.credentials)?,
            request: bind_request(16),
            host_request_id: Hash::from_bytes([16; 32]),
        });
        let (mut writer, _reader) = UnixStream::pair()?;
        coordinator.write_prepared(&mut writer, &binding)?;
        assert_eq!(
            binding.response.to_canonical_cbor()[..10],
            [0x84, 0x65, b'F', b'A', b'R', b'L', b'1', 1, 0, 0x82]
        );

        let parent = coordinator.store.create_timeline("pending Fork parent")?;
        let pending_request = fork_request(17, parent.id(), 18, 19, "pending-child");
        let pending = coordinator.handle(CompletedLocalForkAdmissionV1 {
            peer: current_peer(&coordinator.credentials)?,
            request: pending_request.clone(),
            host_request_id: Hash::from_bytes([20; 32]),
        });
        let (mut writer, reader) = UnixStream::pair()?;
        drop(reader);
        assert!(coordinator.write_prepared(&mut writer, &pending).is_err());
        let recovered = coordinator.handle(CompletedLocalForkAdmissionV1 {
            peer: current_peer(&coordinator.credentials)?,
            request: pending_request,
            host_request_id: Hash::from_bytes([20; 32]),
        });
        assert_eq!(
            recovered.response.to_canonical_cbor()[..10],
            [0x84, 0x65, b'F', b'A', b'R', b'L', b'1', 1, 0, 0x83]
        );

        let busy_parent = coordinator.store.create_timeline("busy Fork parent")?;
        let busy_request = fork_request(21, busy_parent.id(), 22, 23, "busy-child");
        let busy_host_request_id = Hash::from_bytes([24; 32]);
        let pending_owner = coordinator.handle(CompletedLocalForkAdmissionV1 {
            peer: current_peer(&coordinator.credentials)?,
            request: busy_request.clone(),
            host_request_id: busy_host_request_id,
        });
        let recovered_before_delivery = coordinator.handle(CompletedLocalForkAdmissionV1 {
            peer: current_peer(&coordinator.credentials)?,
            request: busy_request.clone(),
            host_request_id: busy_host_request_id,
        });
        assert_eq!(
            recovered_before_delivery.response.to_canonical_cbor(),
            pending_owner.response.to_canonical_cbor()
        );
        let (mut writer, _reader) = UnixStream::pair()?;
        coordinator.write_prepared(&mut writer, &pending_owner)?;
        let (mut duplicate_writer, _duplicate_reader) = UnixStream::pair()?;
        assert!(coordinator
            .write_prepared(&mut duplicate_writer, &recovered_before_delivery)
            .is_err());
        let conflicting_digest = coordinator.handle(CompletedLocalForkAdmissionV1 {
            peer: current_peer(&coordinator.credentials)?,
            request: busy_request,
            host_request_id: Hash::from_bytes([25; 32]),
        });
        assert_eq!(
            conflicting_digest.response.to_canonical_cbor(),
            vec![0x84, 0x65, b'F', b'A', b'R', b'L', b'1', 1, 6, 0xf6]
        );
        Ok(())
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn coordinator_reconciles_a_retained_delivery_before_serving_a_retry(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut coordinator = coordinator()?;
        let request = bind_request(26);
        let host_request_id = Hash::from_bytes([27; 32]);
        let pending = coordinator.handle(CompletedLocalForkAdmissionV1 {
            peer: current_peer(&coordinator.credentials)?,
            request: request.clone(),
            host_request_id,
        });
        assert_eq!(
            pending.response.to_canonical_cbor()[..10],
            [0x84, 0x65, b'F', b'A', b'R', b'L', b'1', 1, 0, 0x82]
        );

        let LocalForkAdmissionCoordinatorV1 {
            credentials, store, ..
        } = coordinator;
        let mut restarted = LocalForkAdmissionCoordinatorV1::open(store, credentials)?;
        restarted.reconcile_startup()?;

        let retry = restarted.handle(CompletedLocalForkAdmissionV1 {
            peer: current_peer(&restarted.credentials)?,
            request,
            host_request_id,
        });
        assert_eq!(
            retry.response.to_canonical_cbor(),
            pending.response.to_canonical_cbor()
        );
        let (mut writer, _reader) = UnixStream::pair()?;
        restarted.write_prepared(&mut writer, &retry)?;
        Ok(())
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn coordinator_rejects_a_zero_delivery_identity_before_claiming_authority(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut coordinator = coordinator()?;
        let rejected = coordinator.handle(CompletedLocalForkAdmissionV1 {
            peer: current_peer(&coordinator.credentials)?,
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
    fn coordinator_cancels_a_pending_claim_after_peer_resolution_fails(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut coordinator = coordinator()?;
        let host_request_id = Hash::from_bytes([31; 32]);
        let request = bind_request(32);
        let rejected = coordinator.handle(CompletedLocalForkAdmissionV1 {
            peer: crate::local_fork_authentication::test_unregistered_peer()?,
            request: request.clone(),
            host_request_id,
        });
        assert_eq!(
            rejected.response.to_canonical_cbor(),
            LocalForkAdmissionResponseV1::rejected(LocalForkAdmissionCodeV1::Unauthenticated)
                .to_canonical_cbor()
        );

        let admitted = coordinator.handle(CompletedLocalForkAdmissionV1 {
            peer: current_peer(&coordinator.credentials)?,
            request,
            host_request_id,
        });
        assert_eq!(
            &admitted.response.to_canonical_cbor()[..10],
            &[0x84, 0x65, b'F', b'A', b'R', b'L', b'1', 1, 0, 0x82]
        );
        Ok(())
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn coordinator_requires_an_initialized_and_current_host_session(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let credentials = crate::local_fork_authentication::test_credentials_for_current_peer()?;
        assert_eq!(
            LocalForkAdmissionCoordinatorV1::open(MemoryStore::new(), credentials).err(),
            Some(LocalForkAuthenticationErrorV1::CredentialUnavailable)
        );

        let mut coordinator = coordinator()?;
        let _new_session = coordinator
            .credentials
            .open_authority(&mut coordinator.store)?;
        assert_eq!(
            coordinator.reconcile_startup().err(),
            Some(LocalForkAuthenticationErrorV1::CredentialUnavailable)
        );
        let rejected = coordinator.handle(CompletedLocalForkAdmissionV1 {
            peer: current_peer(&coordinator.credentials)?,
            request: bind_request(33),
            host_request_id: Hash::from_bytes([34; 32]),
        });
        assert_eq!(
            rejected.response.to_canonical_cbor(),
            LocalForkAdmissionResponseV1::rejected(LocalForkAdmissionCodeV1::Indeterminate)
                .to_canonical_cbor()
        );
        Ok(())
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn coordinator_fails_closed_while_another_owner_holds_a_delivery_claim(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut coordinator = coordinator()?;
        let request = bind_request(29);
        let completed = CompletedLocalForkAdmissionV1 {
            peer: current_peer(&coordinator.credentials)?,
            request,
            host_request_id: Hash::from_bytes([30; 32]),
        };
        let tuple = delivery_tuple(&completed)
            .map_err(|()| io::Error::other("valid bind request must produce a delivery tuple"))?;
        assert!(matches!(
            coordinator
                .store
                .claim_fork_delivery(&coordinator.session, tuple)?,
            ForkDeliveryClaimOutcomeV1::Owner(_)
        ));

        let busy = coordinator.handle(completed);
        assert_eq!(
            busy.response.to_canonical_cbor(),
            vec![0x84, 0x65, b'F', b'A', b'R', b'L', b'1', 1, 6, 0xf6]
        );
        Ok(())
    }

    #[test]
    fn a_result_of_the_wrong_kind_is_an_internal_authority_failure(
    ) -> Result<(), Box<dyn std::error::Error>> {
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
}
