//! The Local erasure store commands of `requestErasure` and `getErasure`
//! (ADR-136 §6 and §7; #1449).
//!
//! Each runs as one command on the store worker, over the one erasure
//! host, so a submission's admission checks and its ERQ1 commit are one
//! serialized step. A submission records the store's current execution-mode
//! binding in its ELADM1 (owner decision D5 of 2026-11-18 on #1413).

use std::{sync::Arc, time::Instant};

use pos_core::{EntityId, ErasureHostErrorV1, ErasureReferenceV1, ErasureScopeV1, PrincipalRefV1};
use pos_runtime::{
    ErasureExecutionHostV1, LocalErasureAdmittedV1, LocalErasureProjectionV1,
    LocalErasureSubmissionV1, LocalErasureSubmitErrorV1,
};
use tokio::sync::oneshot;

use super::{
    await_command_result, CommandLifecycle, ExecutorState, ExecutorStore, StoreExecutor,
    StoreExecutorError, WorkerCommandV1,
};

/// One erasure request the Gateway admitted: the decided Principal and
/// actor, the scope and the Idempotency-Key digest.
pub(crate) struct LocalErasureRequestV1 {
    pub(crate) principal: PrincipalRefV1,
    pub(crate) actor: EntityId,
    pub(crate) scope: ErasureScopeV1,
    pub(crate) idempotency_key_digest: ErasureReferenceV1,
}

/// One operation on the erasure host, `None` on a test store without one.
type HostOperationV1<T> = Box<dyn FnOnce(Option<&mut ErasureExecutionHostV1>) -> T + Send>;

/// Box `operation`; the bound gives its closure the higher-ranked host
/// argument.
fn host_operation<T, F>(operation: F) -> HostOperationV1<T>
where
    F: FnOnce(Option<&mut ErasureExecutionHostV1>) -> T + Send + 'static,
{
    Box::new(operation)
}

/// One erasure host command and its reply.
struct LocalErasureCommandV1<T> {
    operation: HostOperationV1<T>,
    reply: oneshot::Sender<Result<T, StoreExecutorError>>,
}

impl<T: Send + 'static> WorkerCommandV1 for LocalErasureCommandV1<T> {
    fn run_on_worker(self: Box<Self>, state: &mut ExecutorState) {
        let Self { operation, reply } = *self;
        let host = match &mut state.store {
            ExecutorStore::Host(host, _) => Some(host.as_mut()),
            #[cfg(test)]
            ExecutorStore::Generic(_) | ExecutorStore::Gateway(_) => None,
        };
        drop(reply.send(Ok(operation(host))));
    }

    fn expire_unrun(self: Box<Self>) {
        drop(self.reply.send(Err(StoreExecutorError::DeadlineExceeded)));
    }
}

/// Submit `request` on `host` under the store's current execution-mode
/// binding.
///
/// A host without that binding (an unbound or uncompiled one) serves no
/// erasure: a Local composition only ever attaches to a bound store, so
/// such a host is answered [`LocalErasureSubmitErrorV1::Unserved`] like a
/// host without a Local composition, and no submission without a binding
/// is ever built.
fn submit_on_host(
    host: Option<&mut ErasureExecutionHostV1>,
    request: &LocalErasureRequestV1,
) -> Result<LocalErasureAdmittedV1, LocalErasureSubmitErrorV1> {
    host.and_then(|host| {
        crate::mode_profile::current_binding_v1(host.gateway_mode_binding())
            .map(|binding| (host, binding))
    })
    .ok_or(LocalErasureSubmitErrorV1::Unserved)
    .and_then(|(host, (mode_profile, binding_epoch))| {
        host.command_sender()
            .map_err(LocalErasureSubmitErrorV1::Host)
            .and_then(|mut sender| {
                sender.submit_local_erasure(&LocalErasureSubmissionV1 {
                    principal: request.principal.clone(),
                    actor: request.actor,
                    scope: request.scope,
                    idempotency_key_digest: request.idempotency_key_digest,
                    mode_profile: ErasureReferenceV1::from_digest(mode_profile),
                    binding_epoch: binding_epoch.get(),
                })
            })
    })
}

/// The projection of `erasure_id` for the subject of `principal` acting
/// as `actor`; `None` on a test store without an erasure host.
fn project_on_host(
    host: Option<&mut ErasureExecutionHostV1>,
    principal: &PrincipalRefV1,
    actor: EntityId,
    erasure_id: ulid::Ulid,
) -> Result<Option<LocalErasureProjectionV1>, ErasureHostErrorV1> {
    host.map_or(Ok(None), |host| {
        host.command_sender()
            .and_then(|mut sender| sender.local_erasure_projection(principal, actor, erasure_id))
    })
}

impl StoreExecutor {
    /// Submit one Local erasure request on the store worker.
    ///
    /// # Errors
    /// The executor error of a command that did not run; the inner result
    /// is the host's.
    pub(crate) async fn submit_local_erasure(
        &self,
        request: LocalErasureRequestV1,
    ) -> Result<Result<LocalErasureAdmittedV1, LocalErasureSubmitErrorV1>, StoreExecutorError> {
        let operation = host_operation(move |host| submit_on_host(host, &request));
        submit!(self, |reply| super::Command::Action(Box::new(
            LocalErasureCommandV1 { operation, reply }
        )))
    }

    /// Read the `getErasure` projection of one request on the store worker.
    ///
    /// # Errors
    /// The executor error of a command that did not run; the inner result
    /// is the host's.
    pub(crate) async fn local_erasure_projection(
        &self,
        principal: PrincipalRefV1,
        actor: EntityId,
        erasure_id: ulid::Ulid,
    ) -> Result<Result<Option<LocalErasureProjectionV1>, ErasureHostErrorV1>, StoreExecutorError>
    {
        let operation =
            host_operation(move |host| project_on_host(host, &principal, actor, erasure_id));
        submit!(self, |reply| super::Command::Action(Box::new(
            LocalErasureCommandV1 { operation, reply }
        )))
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::{
        host_operation, LocalErasureCommandV1, LocalErasureRequestV1, StoreExecutor,
        StoreExecutorError, WorkerCommandV1,
    };
    use pos_core::{EntityId, ErasureReferenceV1, ErasureScopeV1, PrincipalRefV1};
    use pos_runtime::LocalErasureSubmitErrorV1;
    use pos_store::memory::MemoryStore;

    type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

    fn principal() -> TestResult<PrincipalRefV1> {
        Ok(PrincipalRefV1::try_new([0x21; 16], "local")?)
    }

    /// A store without an erasure host serves no Local erasure: a
    /// submission is unserved and every projection is absent.
    #[tokio::test]
    async fn a_store_without_an_erasure_host_serves_no_erasure() -> TestResult {
        let executor = StoreExecutor::new(Box::new(MemoryStore::new()));
        let submitted = executor
            .submit_local_erasure(LocalErasureRequestV1 {
                principal: principal()?,
                actor: EntityId::new(),
                scope: ErasureScopeV1::PrivateSubjectData,
                idempotency_key_digest: ErasureReferenceV1::from_digest([0x22; 32]),
            })
            .await
            .map_err(|error| format!("{error:?}"))?;
        assert_eq!(submitted.err(), Some(LocalErasureSubmitErrorV1::Unserved));
        let projected = executor
            .local_erasure_projection(principal()?, EntityId::new(), ulid::Ulid::nil())
            .await
            .map_err(|error| format!("{error:?}"))?;
        assert_eq!(projected, Ok(None));
        assert!(executor.shutdown().await.is_ok());
        drop(executor);
        Ok(())
    }

    /// An erasure host whose store records no execution-mode binding
    /// serves no erasure: the submission is unserved before it is built.
    #[tokio::test]
    async fn an_unbound_erasure_host_serves_no_erasure() -> TestResult {
        let host = pos_runtime::ErasureExecutionHostV1::open_verified_empty(
            pos_store::StoreConfig::Memory,
            pos_core::ErasureRecoveryLimitsV1::compiled_maximum(),
        )?;
        let gateway = crate::Gateway::unprotected_for_harness(host)?;
        let submitted = gateway
            .store
            .submit_local_erasure(LocalErasureRequestV1 {
                principal: principal()?,
                actor: EntityId::new(),
                scope: ErasureScopeV1::PrivateSubjectData,
                idempotency_key_digest: ErasureReferenceV1::from_digest([0x23; 32]),
            })
            .await
            .map_err(|error| format!("{error:?}"))?;
        assert_eq!(submitted.err(), Some(LocalErasureSubmitErrorV1::Unserved));
        gateway.shutdown().await?;
        drop(gateway);
        Ok(())
    }

    /// A command that expires before it runs answers the deadline.
    #[test]
    fn an_expired_erasure_command_answers_the_deadline() {
        let (reply, result) = tokio::sync::oneshot::channel::<Result<(), StoreExecutorError>>();
        Box::new(LocalErasureCommandV1 {
            operation: host_operation(|_| ()),
            reply,
        })
        .expire_unrun();
        assert!(matches!(
            result.blocking_recv(),
            Ok(Err(StoreExecutorError::DeadlineExceeded))
        ));
    }
}
