//! `MemoryStore` side of the ADR-099 revision 12 classified counterfactual
//! commit and append.
//!
//! Both methods compose the recording write path of the `dependency` module
//! with one classified staging step, in the check order of the port and of the
//! `SQLite` adapter. Under the erasure write fence they require the live
//! session and then resolve the Fork: a visible, published counterfactual Fork
//! with a local `FAR1`. The draft guard, the `WallTime` rule, the one
//! authority reread, and the orphan-operation guard are shared reads over the
//! whole store; they run before the recording body takes its write borrow, and
//! their result is reported by the staging step, so it surfaces only after the
//! record and basis checks, exactly where `SQLite` reports it.
//!
//! The staging step stages the Events on the scratch Fork head and derives one
//! host-internal `EOR1` and `FOP1` per Event from the staged Events. The
//! infallible install adds the Events, the provenance, the generation, and the
//! dependency rows only after every fallible step succeeded, so atomicity is
//! structural: a rejection leaves no Event, provenance, generation, or
//! dependency row.

use pos_core::{
    CounterfactualBasisV1, CounterfactualInvalidationCommandV1, CounterfactualInvalidationOutcomeV1,
    CounterfactualTickOutcomeV1, ErasureProtectedOperationV1, ForkAppendSourceIdentityV1,
    ForkClassifiedEventV1, ForkClassifiedProvenanceV1, ForkClassifierTableV1,
    ForkEventAppendRequestV1, ForkEventClassifierV1, Hash, PipelineDraftBatchV1,
    TickDependencyRecordV1, TimelineId,
};

use super::{fenced_result, ForkEntriesV1, StagedProvenanceV1, StagedTickV1};
use crate::fork_admission_authority::validate_live_session;
use crate::fork_event_authority::{
    derive_operation_ids, fork_append_request, without_wall_time_override,
};
use crate::memory::MemoryStore;
use crate::{
    counterfactual_port_error, ClassifiedCounterfactualErrorV1, ClassifiedCounterfactualStorePortV1,
    ClassifiedProvenanceErrorV1, ClassifiedTickAuthorityV1, ForkAdmissionAuthoritySessionV1,
    ForkAppendSourcePermitV1, ForkEventAuthorityErrorV1,
};

type ClassifiedError = ClassifiedCounterfactualErrorV1;
/// The result of the shared-read checks of one classified batch.
type CheckedBatch = Result<ClassifiedBatchV1, ClassifiedError>;
/// The result of staging one classified batch.
type Staged = Result<StagedTickV1, ClassifiedError>;

const APPEND: ErasureProtectedOperationV1 = ErasureProtectedOperationV1::Append;
const INVALID_REQUEST: ClassifiedError =
    ClassifiedError::Provenance(ClassifiedProvenanceErrorV1::InvalidRequest);
const UNAUTHENTICATED: ClassifiedError =
    ClassifiedError::Provenance(ClassifiedProvenanceErrorV1::Unauthenticated);
const CORRUPT_AUTHORITY: ClassifiedError =
    ClassifiedError::Provenance(ClassifiedProvenanceErrorV1::CorruptAuthority);

/// The checked authority of one classified batch: the Fork's validated
/// classifier table and the derived operation ID of each draft.
struct ClassifiedBatchV1 {
    table: ForkClassifierTableV1,
    operations: Vec<Hash>,
}

impl MemoryStore {
    /// The live session, then the Fork resolution.
    ///
    /// The session is checked first, so a caller without one learns nothing
    /// about the Fork. A visible, published counterfactual Fork without a
    /// local `FAR1` is an unclassified or imported Fork, which this path does
    /// not serve.
    fn memory_classified_fork(
        &self,
        fork: TimelineId,
        session: &ForkAdmissionAuthoritySessionV1,
    ) -> Result<(), ClassifiedError> {
        if !validate_live_session(&self.fork_admission_authority, session) {
            return Err(UNAUTHENTICATED);
        }
        let local = self
            .counterfactual_fork(fork)
            .map(|_| self.fork_admissions.contains_key(&fork));
        local
            .map_err(ClassifiedError::from)
            .and_then(|is_local| is_local.then_some(()).ok_or(INVALID_REQUEST))
    }

    /// The shared-read checks of one classified batch, in order: the draft
    /// guard (concealed as an absent Fork), the `WallTime` rule, one authority
    /// reread, and the orphan-operation guard.
    fn memory_check_classified_batch(
        &self,
        fork: TimelineId,
        drafts: &PipelineDraftBatchV1,
        authority: &ClassifiedTickAuthorityV1<'_>,
        operation_base: Hash,
    ) -> CheckedBatch {
        crate::ensure_non_geographic_drafts(drafts.drafts(), fork)
            .map_err(|error| ClassifiedError::Store(counterfactual_port_error(&error)))
            .and_then(|()| without_wall_time_override(drafts))
            .and_then(|()| self.memory_validate_classified_authority_once(authority, fork))
            .and_then(|table| {
                let operations = derive_operation_ids(operation_base, drafts.drafts().len());
                self.memory_reject_orphan_operations(&operations)
                    .map(|()| ClassifiedBatchV1 { table, operations })
            })
    }

    /// Reread the Fork's authority once for the whole batch.
    ///
    /// The permit must name this Fork and be live for the lent session, its
    /// source must be host-internal, and it must name the Fork's validated
    /// `FAR1`/`FCT1`/`FCR1` graph.
    fn memory_validate_classified_authority_once(
        &self,
        authority: &ClassifiedTickAuthorityV1<'_>,
        fork: TimelineId,
    ) -> Result<ForkClassifierTableV1, ClassifiedError> {
        let permit = authority.permit();
        if permit.child_timeline_id() != fork || !permit.is_live_for(authority.session()) {
            return Err(UNAUTHENTICATED);
        }
        if matches!(
            permit.source(),
            ForkAppendSourceIdentityV1::ExternalInput { .. }
        ) {
            return Err(INVALID_REQUEST);
        }
        self.validate_classified_permit(permit)
            .map_err(ClassifiedError::from)
    }

    /// Refuse the batch when any derived operation ID already has a `FOP1`.
    ///
    /// The basis matched, so the generation or Tick is uncommitted and such a
    /// row is an orphan of host misuse or corruption; without this guard the
    /// install would overwrite it.
    fn memory_reject_orphan_operations(&self, operations: &[Hash]) -> Result<(), ClassifiedError> {
        let orphan = operations
            .iter()
            .any(|operation| self.fork_append_operations.contains_key(operation));
        if orphan {
            Err(CORRUPT_AUTHORITY)
        } else {
            Ok(())
        }
    }
}

/// The staging step of a classified Tick: it reports the shared-read checks
/// of the batch, then stages the batch.
fn classified_step<'c>(
    checked: &'c CheckedBatch,
    permit: &'c ForkAppendSourcePermitV1,
) -> impl Fn(&ForkEntriesV1<'_>, &PipelineDraftBatchV1) -> Staged + 'c {
    move |entries, drafts| {
        checked
            .as_ref()
            .map_err(|error| *error)
            .and_then(|batch| memory_stage_classified_batch(entries, batch, permit, drafts))
    }
}

/// Stage one classified batch: its Events on the scratch Fork head, then one
/// host-internal `EOR1` and `FOP1` per staged Event under its derived
/// operation ID. Nothing is installed.
fn memory_stage_classified_batch(
    entries: &ForkEntriesV1<'_>,
    checked: &ClassifiedBatchV1,
    permit: &ForkAppendSourcePermitV1,
    drafts: &PipelineDraftBatchV1,
) -> Staged {
    let staged = entries.stage_events(drafts).map_err(ClassifiedError::from);
    staged.and_then(|tick| {
        let provenance: Result<Vec<_>, ForkEventAuthorityErrorV1> = tick
            .logical_events()
            .zip(checked.operations.iter().zip(drafts.drafts()))
            .map(|(event, (operation, draft))| {
                fork_append_request(*operation, entries.fork, permit.source(), draft)
                    .and_then(|request| staged_provenance(&checked.table, &request, event))
            })
            .collect();
        provenance
            .map(|rows| StagedTickV1 {
                provenance: rows,
                ..tick
            })
            .map_err(ClassifiedError::from)
    })
}

/// Classify the request's source and derive the `EOR1` and `FOP1` of one
/// staged Event.
///
/// A host-internal source classifies as `(0,0)`, which carries no `FIA1`.
fn staged_provenance(
    table: &ForkClassifierTableV1,
    request: &ForkEventAppendRequestV1,
    event: ForkClassifiedEventV1,
) -> Result<StagedProvenanceV1, ForkEventAuthorityErrorV1> {
    let classified = ForkEventClassifierV1::from_table(table)
        .classify_identity(&request.source)
        .or(Err(ForkEventAuthorityErrorV1::ClassifierRejected));
    classified
        .and_then(|classification| {
            ForkClassifiedProvenanceV1::derive(request, table, classification, event)
                .or(Err(ForkEventAuthorityErrorV1::InvalidRequest))
        })
        .map(|provenance| StagedProvenanceV1 {
            event_id: event.event_id,
            origin: provenance.origin,
            operation: provenance.operation,
        })
}

impl ClassifiedCounterfactualStorePortV1 for MemoryStore {
    fn commit_classified_counterfactual_invalidation(
        &mut self,
        command: &CounterfactualInvalidationCommandV1,
        record: &TickDependencyRecordV1,
        authority: &ClassifiedTickAuthorityV1<'_>,
        operation_base: Hash,
    ) -> Result<CounterfactualInvalidationOutcomeV1, ClassifiedError> {
        let fork = command.fork();
        let drafts = command.first_tick_drafts();
        let write = self.with_erasure_fence(fork, APPEND, |store| {
            let resolved = store.memory_classified_fork(fork, authority.session());
            Ok(resolved.and_then(|()| {
                let checked =
                    store.memory_check_classified_batch(fork, drafts, authority, operation_base);
                let step = classified_step(&checked, authority.permit());
                store.commit_recorded(command, record, step)
            }))
        });
        fenced_result(write)
    }

    fn append_classified_counterfactual_tick(
        &mut self,
        fork: TimelineId,
        expected: &CounterfactualBasisV1,
        drafts: &PipelineDraftBatchV1,
        record: &TickDependencyRecordV1,
        authority: &ClassifiedTickAuthorityV1<'_>,
        operation_base: Hash,
    ) -> Result<CounterfactualTickOutcomeV1, ClassifiedError> {
        let write = self.with_erasure_fence(fork, APPEND, |store| {
            let resolved = store.memory_classified_fork(fork, authority.session());
            Ok(resolved.and_then(|()| {
                let checked =
                    store.memory_check_classified_batch(fork, drafts, authority, operation_base);
                let step = classified_step(&checked, authority.permit());
                store.append_recorded(fork, expected, drafts, record, step)
            }))
        });
        fenced_result(write)
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    //! In-crate evidence the public port cannot reach with a live session: an
    //! injected staging failure, a permit naming other durable authority, and
    //! a corrupt authority graph.

    use std::sync::Arc;

    use pos_core::{
        CounterfactualInvalidationOutcomeV1, CounterfactualStoreErrorV1, ErasureContainmentGateV1,
        EventStore, TimelineId,
    };

    use super::super::tests::{inject, snapshot, ForkSnapshot};
    use super::super::InjectedFaultV1;
    use super::{ClassifiedError, CORRUPT_AUTHORITY, UNAUTHENTICATED};
    use crate::classified_fork_fixture::{hash, node_record, Authority, Fallible, Spec, FIRST_TICK};
    use crate::memory::MemoryStore;
    use crate::{ClassifiedCounterfactualStorePortV1, ForkAppendSourcePermitV1};

    type Outcome = CounterfactualInvalidationOutcomeV1;

    fn classified() -> Fallible<(MemoryStore, Authority, TimelineId)> {
        let mut store = MemoryStore::new();
        store.bind_erasure_gate(Arc::new(ErasureContainmentGateV1::new_test_open()))?;
        let authority = Authority::open(&mut store)?;
        let fork = authority.admit(&mut store, 0xb1)?;
        Ok((store, authority, fork))
    }

    /// The default invalidation of `fork` under `permit`.
    fn commit(
        store: &mut MemoryStore,
        authority: &Authority,
        permit: &ForkAppendSourcePermitV1,
        fork: TimelineId,
    ) -> Fallible<Result<Outcome, ClassifiedError>> {
        let command = Spec::new(fork).command()?;
        let record = node_record(FIRST_TICK, "a", 1)?;
        let lent = authority.lend(permit);
        let base = hash(0x61);
        let committed =
            store.commit_classified_counterfactual_invalidation(&command, &record, &lent, base);
        Ok(committed)
    }

    /// The Fork's state with the store-wide `EOR1` and `FOP1` row counts.
    fn written(store: &MemoryStore, fork: TimelineId) -> (ForkSnapshot, usize, usize) {
        (
            snapshot(store, fork),
            store.fork_event_origins.len(),
            store.fork_append_operations.len(),
        )
    }

    #[test]
    fn an_injected_staging_failure_installs_no_event_or_provenance() -> Fallible<()> {
        let (mut store, authority, fork) = classified()?;
        let permit = authority.host_permit(&store, fork)?;
        let before = written(&store, fork);
        inject(InjectedFaultV1::Storage);
        let failed = commit(&mut store, &authority, &permit, fork)?;
        let storage = ClassifiedError::Store(CounterfactualStoreErrorV1::StorageFailure);
        assert_eq!(failed, Err(storage), "the staged head failed");
        assert_eq!(written(&store, fork), before, "nothing was installed");
        // The retry installs both Events, each with one EOR1 and one FOP1.
        let retried = commit(&mut store, &authority, &permit, fork)??;
        assert!(
            matches!(retried, Outcome::Committed(_)),
            "the retry commits: {retried:?}"
        );
        let (_, origins, operations) = written(&store, fork);
        assert_eq!((origins, operations), (before.1 + 2, before.2 + 2));
        Ok(())
    }

    #[test]
    fn a_permit_naming_other_durable_authority_is_unauthenticated() -> Fallible<()> {
        let (mut store, authority, fork) = classified()?;
        let permit = ForkAppendSourcePermitV1 {
            registration_digest: hash(0x55),
            ..authority.host_permit(&store, fork)?
        };
        let before = written(&store, fork);
        let refused = commit(&mut store, &authority, &permit, fork)?;
        assert_eq!(refused, Err(UNAUTHENTICATED), "another FCR1");
        assert_eq!(written(&store, fork), before, "nothing was installed");
        Ok(())
    }

    #[test]
    fn a_corrupt_authority_graph_is_corrupt_authority() -> Fallible<()> {
        let corruptions: [fn(&mut MemoryStore, TimelineId); 2] = [
            |store, fork| {
                store.fork_classifier_tables.remove(&fork);
            },
            |store, _| store.fork_classifier_sources.clear(),
        ];
        for (index, corrupt) in corruptions.into_iter().enumerate() {
            let (mut store, authority, fork) = classified()?;
            let permit = authority.host_permit(&store, fork)?;
            corrupt(&mut store, fork);
            let before = written(&store, fork);
            let refused = commit(&mut store, &authority, &permit, fork)?;
            assert_eq!(refused, Err(CORRUPT_AUTHORITY), "corruption {index}");
            assert_eq!(written(&store, fork), before, "corruption {index}");
        }
        Ok(())
    }
}
