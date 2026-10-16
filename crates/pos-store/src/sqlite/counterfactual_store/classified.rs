//! `SQLite` side of the ADR-099 revision 12 classified counterfactual commit
//! and append.
//!
//! Both methods run the recording write path with two injected steps, in the
//! check order of the port. The basis read requires the live session and then
//! resolves the Fork: a visible counterfactual Fork whose `FAR1` is present
//! and not imported. The Event step guards the drafts, rereads the authority
//! once for the whole batch, rejects any `FOP1` already under a derived
//! operation ID, and inserts one fresh host-internal classified Event, `EOR1`,
//! and `FOP1` per draft. Every rejection rolls the transaction back, so it
//! leaves no Event, provenance, generation, or dependency row.

use pos_core::{
    CoreError, CounterfactualBasisV1, CounterfactualInvalidationCommandV1,
    CounterfactualInvalidationOutcomeV1, CounterfactualTickOutcomeV1, ForkAppendSourceIdentityV1,
    ForkClassifierTableV1, Hash, ImportedForkAdmissionRecordV1, PipelineDraftBatchV1, Seq,
    TickDependencyRecordV1, TimelineId,
};
use rusqlite::{params, OptionalExtension};

use super::{lift, then_staged, Staged};
use crate::fork_event_authority::{derive_operation_ids, fork_append_request};
use crate::sqlite::{sqlite_validate_classified_permit, SqliteStore, FORK_ADMISSION_FAR1_SQL};
use crate::{
    ClassifiedCounterfactualErrorV1, ClassifiedCounterfactualStorePortV1,
    ClassifiedProvenanceErrorV1, ClassifiedTickAuthorityV1, ForkAdmissionAuthoritySessionV1,
};

type ClassifiedError = ClassifiedCounterfactualErrorV1;

const INVALID_REQUEST: ClassifiedError =
    ClassifiedError::Provenance(ClassifiedProvenanceErrorV1::InvalidRequest);
const UNAUTHENTICATED: ClassifiedError =
    ClassifiedError::Provenance(ClassifiedProvenanceErrorV1::Unauthenticated);
const CORRUPT_AUTHORITY: ClassifiedError =
    ClassifiedError::Provenance(ClassifiedProvenanceErrorV1::CorruptAuthority);

/// Whether a `FOP1` row already holds one operation ID.
const OPERATION_EXISTS_SQL: &str =
    "SELECT EXISTS(SELECT 1 FROM fork_append_operations WHERE operation_id = ?1)";

impl SqliteStore {
    /// The live session, then the Fork resolution, then the persisted basis.
    ///
    /// The session is checked first, so a caller without one learns nothing
    /// about the Fork. A visible counterfactual Fork without a local `FAR1` is
    /// an unclassified or imported Fork, which this path does not serve.
    fn classified_counterfactual_basis(
        &self,
        fork: TimelineId,
        session: &ForkAdmissionAuthoritySessionV1,
    ) -> Staged<CounterfactualBasisV1, ClassifiedError> {
        let live = self
            .require_live_fork_event_session(session)
            .map_err(ClassifiedError::from);
        then_staged(Ok(live), |()| {
            let basis = lift(self.persisted_counterfactual_basis(fork));
            then_staged(basis, |persisted| {
                self.local_classified_fork(fork)
                    .map(|local| local.then_some(persisted).ok_or(INVALID_REQUEST))
            })
        })
    }

    /// Whether the Fork holds a `FAR1` that is not imported (origin code 2).
    ///
    /// A malformed `FAR1` passes here and is refused as corrupt by the
    /// authority reread.
    fn local_classified_fork(&self, fork: TimelineId) -> Result<bool, CoreError> {
        let child = fork.to_string();
        self.conn
            .query_row(FORK_ADMISSION_FAR1_SQL, params![child], |row| {
                row.get::<_, Vec<u8>>(0)
            })
            .optional()
            .map(|admission| {
                admission.is_some_and(|bytes| {
                    ImportedForkAdmissionRecordV1::from_canonical_cbor(&bytes).is_err()
                })
            })
            .map_err(Self::into_storage_error)
    }

    /// The Event step of a classified Fork: the draft guards, one authority
    /// reread, the orphan-operation guard, then one fresh classified append per
    /// draft. It returns the Fork Logical Head after the batch.
    fn append_classified_tick_in_transaction(
        &self,
        fork: TimelineId,
        drafts: &PipelineDraftBatchV1,
        lent: &ClassifiedTickAuthorityV1<'_>,
        operation_base: Hash,
    ) -> Staged<Seq, ClassifiedError> {
        crate::ensure_non_geographic_drafts(drafts.drafts(), fork).and_then(|()| {
            let validated = without_wall_time_override(drafts)
                .and_then(|()| self.validate_classified_authority_once(lent, fork));
            then_staged(Ok(validated), |table| {
                let operations = derive_operation_ids(operation_base, drafts.drafts().len());
                then_staged(self.reject_orphan_operations(&operations), |()| {
                    self.insert_fresh_classified_batch(&table, lent, &operations, drafts)
                })
            })
        })
    }

    /// Reread the Fork's authority once for the whole batch.
    ///
    /// The permit must name this Fork and be live for the lent session, its
    /// source must be host-internal, and it must name the Fork's validated
    /// `FAR1`/`FCT1`/`FCR1` graph.
    fn validate_classified_authority_once(
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
        sqlite_validate_classified_permit(&self.conn, self.hasher.as_ref(), permit)
            .map_err(ClassifiedError::from)
    }

    /// Refuse the batch when any derived operation ID already has a `FOP1`.
    ///
    /// The basis matched, so the generation or Tick is uncommitted and such a
    /// row is an orphan of host misuse or corruption.
    fn reject_orphan_operations(&self, operations: &[Hash]) -> Staged<(), ClassifiedError> {
        operations
            .iter()
            .try_fold(false, |found, operation| {
                self.conn
                    .query_row(
                        OPERATION_EXISTS_SQL,
                        params![operation.as_bytes().as_slice()],
                        |row| row.get::<_, bool>(0),
                    )
                    .map(|exists| found || exists)
            })
            .map(|found| (!found).then_some(()).ok_or(CORRUPT_AUTHORITY))
            .map_err(Self::into_storage_error)
    }

    /// Insert one fresh host-internal classified Event, `EOR1`, and `FOP1` for
    /// each draft under its derived operation ID, then read the Fork Logical
    /// Head after the batch.
    fn insert_fresh_classified_batch(
        &self,
        table: &ForkClassifierTableV1,
        authority: &ClassifiedTickAuthorityV1<'_>,
        operations: &[Hash],
        drafts: &PipelineDraftBatchV1,
    ) -> Staged<Seq, ClassifiedError> {
        let permit = authority.permit();
        let child = permit.child_timeline_id();
        let inserted = operations
            .iter()
            .zip(drafts.drafts())
            .try_for_each(|(operation, draft)| {
                fork_append_request(*operation, child, permit.source(), draft)
                    .and_then(|request| {
                        self.insert_fresh_classified_append(table, &request, draft.clone())
                    })
                    .map(drop)
            })
            .map_err(ClassifiedError::from);
        then_staged(Ok(inserted), |()| {
            Self::logical_head_unchecked_on(&self.conn, child).map(Ok)
        })
    }
}

/// A classified Event is stamped by the store clock, so no draft may carry a
/// `WallTime` override.
fn without_wall_time_override(drafts: &PipelineDraftBatchV1) -> Result<(), ClassifiedError> {
    if drafts.drafts().iter().any(|draft| draft.wall_time.is_some()) {
        Err(INVALID_REQUEST)
    } else {
        Ok(())
    }
}

impl ClassifiedCounterfactualStorePortV1 for SqliteStore {
    fn commit_classified_counterfactual_invalidation(
        &mut self,
        command: &CounterfactualInvalidationCommandV1,
        record: &TickDependencyRecordV1,
        authority: &ClassifiedTickAuthorityV1<'_>,
        operation_base: Hash,
    ) -> Result<CounterfactualInvalidationOutcomeV1, ClassifiedError> {
        self.commit_invalidation_recording(
            command,
            Some(record),
            |store, child| store.classified_counterfactual_basis(child, authority.session()),
            |store, child, batch| {
                store.append_classified_tick_in_transaction(child, batch, authority, operation_base)
            },
        )
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
        self.append_tick_recording(
            fork,
            expected,
            drafts,
            Some(record),
            |store, child| store.classified_counterfactual_basis(child, authority.session()),
            |store, child, batch| {
                store.append_classified_tick_in_transaction(child, batch, authority, operation_base)
            },
        )
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    //! In-crate evidence for the authority reread that the public port cannot
    //! reach with a live session: a permit naming other durable authority,
    //! and a corrupt authority graph. A forged permit and an in-connection
    //! edit keep the session live, which a write by another connection would
    //! end.

    use std::sync::Arc;

    use pos_core::{ErasureContainmentGateV1, EventStore, RecordedNodeOriginV1, TimelineId};
    use rusqlite::params;

    use super::{CORRUPT_AUTHORITY, UNAUTHENTICATED};
    use crate::classified_fork_fixture::{empty_record, hash, Authority, Fallible, Spec};
    use crate::sqlite::SqliteStore;
    use crate::{
        ClassifiedCounterfactualErrorV1, ClassifiedCounterfactualStorePortV1,
        ForkAppendSourcePermitV1,
    };

    fn classified() -> Fallible<(SqliteStore, Authority, TimelineId)> {
        let mut store = SqliteStore::open_in_memory()?;
        store.bind_erasure_gate(Arc::new(ErasureContainmentGateV1::new_test_open()))?;
        let authority = Authority::open(&mut store)?;
        let fork = authority.admit(&mut store, 0xb1)?;
        Ok((store, authority, fork))
    }

    /// The error of the default invalidation under `permit`, and the Fork's
    /// own Events after it.
    fn refused(
        store: &mut SqliteStore,
        authority: &Authority,
        permit: &ForkAppendSourcePermitV1,
        fork: TimelineId,
    ) -> Fallible<(Option<ClassifiedCounterfactualErrorV1>, i64)> {
        let command = Spec::new(fork).command()?;
        let record = empty_record(17, RecordedNodeOriginV1::Provisional)?;
        let lent = authority.lend(permit);
        let error = store
            .commit_classified_counterfactual_invalidation(&command, &record, &lent, hash(0x61))
            .err();
        let events = store.conn.query_row(
            "SELECT count(*) FROM events WHERE timeline_id = ?1",
            params![fork.to_string()],
            |row| row.get(0),
        )?;
        Ok((error, events))
    }

    #[test]
    fn a_permit_naming_other_durable_authority_is_unauthenticated() -> Fallible<()> {
        let (mut store, authority, fork) = classified()?;
        let permit = ForkAppendSourcePermitV1 {
            registration_digest: hash(0x55),
            ..authority.host_permit(&store, fork)?
        };
        let refusal = refused(&mut store, &authority, &permit, fork)?;
        assert_eq!(refusal, (Some(UNAUTHENTICATED), 0));
        Ok(())
    }

    #[test]
    fn a_corrupt_authority_graph_is_corrupt_authority() -> Fallible<()> {
        // A malformed FCR1, and a malformed FAR1, which passes the Fork
        // resolution and is refused by the authority reread.
        for (table, column) in [
            ("fork_classifier_registrations", "fcr1_cbor"),
            ("fork_admissions", "far1_cbor"),
        ] {
            let (mut store, authority, fork) = classified()?;
            let permit = authority.host_permit(&store, fork)?;
            store.conn.execute(
                &format!("UPDATE {table} SET {column} = x'00' WHERE child_id = ?1"),
                params![fork.to_string()],
            )?;
            let refusal = refused(&mut store, &authority, &permit, fork)?;
            assert_eq!(refusal, (Some(CORRUPT_AUTHORITY), 0), "{table}");
        }
        Ok(())
    }
}
