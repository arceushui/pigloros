//! Actual publication-row reads on the caller's held snapshot.
//!
//! A keyed type/length query gates the raw `Vec` before retrieval; native
//! decoder allocations and repeated result copies use the same borrowed ledger.

use std::borrow::Cow;

use pos_core::{Hash, TimelineId};
use rusqlite::{params, ToSql};

use super::{
    sqlite_publication_head, SqliteStore, FORK_PUBLICATION_ARTIFACT_SQL,
    FORK_PUBLICATION_BINDING_SQL, FORK_PUBLICATION_OPERATION_SQL,
};
use crate::{
    fork_event_authority::AuthorityValidatorV1,
    fork_manifest_publication::CommittedPublicationRowsV1,
    fork_replay::NativeReadContextV1, ForkManifestPublicationErrorV1 as Error,
};

type Result<T> = std::result::Result<T, Error>;

#[derive(Clone, Copy)]
enum PublicationRowV1 {
    Binding,
    Operation,
    Artifact,
}

impl PublicationRowV1 {
    const fn queries(&self) -> (&'static str, &'static str, usize) {
        match self {
            Self::Binding => (
                "SELECT typeof(fpb1_cbor) = 'blob', length(fpb1_cbor) FROM fork_publication_bindings WHERE child_id = ?1 AND final_logical_head = ?2",
                FORK_PUBLICATION_BINDING_SQL, pos_core::MAX_FORK_PUBLICATION_BINDING_BYTES_V1,
            ),
            Self::Operation => (
                "SELECT typeof(fpo1_cbor) = 'blob', length(fpo1_cbor) FROM fork_publication_operations WHERE operation_id = ?1",
                FORK_PUBLICATION_OPERATION_SQL, pos_core::MAX_FORK_PUBLICATION_OPERATION_BYTES_V1,
            ),
            Self::Artifact => (
                "SELECT typeof(fpa1_cbor) = 'blob', length(fpa1_cbor) FROM fork_publication_artifacts WHERE record_id = ?1",
                FORK_PUBLICATION_ARTIFACT_SQL, pos_core::MAX_FORK_PUBLICATION_ARTIFACT_BYTES_V1,
            ),
        }
    }
}

impl SqliteStore {
    fn publication_blob_with_context(
        &self,
        kind: PublicationRowV1,
        arguments: &[&dyn ToSql],
        context: &mut NativeReadContextV1<'_, '_>,
    ) -> Result<Option<Vec<u8>>> {
        let (probe, fetch, maximum) = kind.queries();
        context.check()?;
        let mut statement = self.conn.prepare(probe).map_err(Error::from)?;
        context.check()?;
        let mut rows = statement.query(arguments).map_err(Error::from)?;
        context.check()?;
        context.row_available()?;
        let Some(row) = rows.next().map_err(Error::from)? else {
            return context.check().map(|()| None);
        };
        context.suffix_row()?;
        let blob: bool = row.get(0).map_err(Error::from)?;
        if !blob {
            // Preserve the old Vec getter's storage-type failure, not validity.
            return Err(Error::StorageIndeterminate);
        }
        let length: usize = row.get(1).map_err(Error::from)?;
        if length > maximum {
            return Err(Error::PublicationConflict);
        }
        context.check()?;
        context.suffix_row()?;
        context.bytes(length)?;
        let bytes = self.conn.query_row(fetch, arguments, |row| row.get::<_, Vec<u8>>(0))
            .map_err(Error::from)?;
        context.check().map(|()| Some(bytes))
    }

    fn publication_operation_with_context(
        &self,
        operation: Hash,
        validator: AuthorityValidatorV1,
        context: &mut NativeReadContextV1<'_, '_>,
    ) -> Result<Option<(pos_core::ForkPublicationOperationV1, crate::fork_event_authority::ValidatedOriginV1)>> {
        self.publication_blob_with_context(PublicationRowV1::Operation,
            params![operation.as_bytes().as_slice()], context)
            .and_then(|bytes| bytes.map(|bytes| context.publication_operation(&bytes, validator)).transpose())
    }

    pub(super) fn committed_publication_rows_with_context(
        &self,
        child: TimelineId,
        head: u64,
        validator: AuthorityValidatorV1,
        context: &mut NativeReadContextV1<'_, '_>,
    ) -> Result<CommittedPublicationRowsV1<'static>> {
        context.bytes(ulid::ULID_LEN)?;
        let key = child.to_string();
        let binding = self.publication_blob_with_context(PublicationRowV1::Binding,
            params![key, sqlite_publication_head(head)], context)?
            .ok_or(Error::PublicationMissing)?;
        let binding = context.publication_binding(&binding)?;
        let fields = binding.input();
        let operation = self.publication_operation_with_context(fields.operation_id, validator, context)?;
        let artifact = self.publication_blob_with_context(PublicationRowV1::Artifact,
            params![fields.signed_manifest_record_id.as_bytes().as_slice()], context)?
            .map(|bytes| context.publication_artifact(&bytes)).transpose()?;
        let ((operation, origin), artifact) = operation.zip(artifact).ok_or(Error::PublicationConflict)?;
        context.canonical(binding.canonical_cbor_len())?;
        let rows = CommittedPublicationRowsV1 {
            child_timeline_id: child, final_logical_head: head, binding, operation, origin,
            artifact: Cow::Owned(artifact),
        };
        context.check().map(|()| rows)
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::{
        fae1_fixture::{pin_policy, request_for, Fallible, Shape, Spec, World},
        ForkAttributionAuthorityImportPortV1, ForkReplayReadBudgetV1, ForkReplayReadLimitsV1,
    };
    use pos_core::trusted_clock::{GuardMonotonicSourceV1, ScriptedGuardMonotonicSourceV1};
    use std::time::Duration;

    fn assert_raw_gate_refusal(
        store: &SqliteStore,
        kind: PublicationRowV1,
        arguments: &[&dyn ToSql],
        expected: Error,
    ) -> Fallible<()> {
        let mut clock = ScriptedGuardMonotonicSourceV1::new([Duration::ZERO]);
        let start = clock.mark();
        let limits = ForkReplayReadLimitsV1::new(1, 1, 2, 64, 1_000_000)?;
        let mut budget = ForkReplayReadBudgetV1::new(limits, start, &mut clock)?;
        assert_eq!(store.publication_blob_with_context(kind, arguments,
            &mut NativeReadContextV1::protected(&mut budget)), Err(expected));
        assert_eq!(budget.remaining_native_bytes(), 64);
        assert!(budget.check_time().is_ok());
        Ok(())
    }

    #[test]
    fn selected_raw_blob_gates_reject_type_and_size_before_retrieval() -> Fallible<()> {
        for (kind, sql, maximum) in [
            (PublicationRowV1::Binding, "UPDATE fork_publication_bindings SET fpb1_cbor = ?1", pos_core::MAX_FORK_PUBLICATION_BINDING_BYTES_V1),
            (PublicationRowV1::Operation, "UPDATE fork_publication_operations SET fpo1_cbor = ?1", pos_core::MAX_FORK_PUBLICATION_OPERATION_BYTES_V1),
            (PublicationRowV1::Artifact, "UPDATE fork_publication_artifacts SET fpa1_cbor = ?1", pos_core::MAX_FORK_PUBLICATION_ARTIFACT_BYTES_V1),
        ] {
            let world = World::new(Shape::Mixed, false)?;
            let built = world.build(&Spec::default())?;
            let mut store = SqliteStore::open(":memory:")?;
            world.seed_destination(&mut store)?;
            pin_policy(&mut store, &built.policy)?;
            store.import_verified(&request_for(&world, &built))?;
            let child = world.child_at(0)?.id.to_string();
            let binding = store.conn.query_row(super::super::FORK_PUBLICATION_BINDING_SQL,
                params![child, super::super::sqlite_publication_head(crate::fae1_fixture::PARENT_CUT + Shape::Mixed.events())],
                |row| row.get::<_, Vec<u8>>(0))?;
            let binding = pos_core::ForkPublicationBindingV1::from_canonical_cbor(&binding)?;
            let fields = binding.input();
            let head = super::super::sqlite_publication_head(crate::fae1_fixture::PARENT_CUT + Shape::Mixed.events());
            let operation = fields.operation_id.as_bytes().as_slice();
            let record = fields.signed_manifest_record_id.as_bytes().as_slice();
            let binding_arguments: [&dyn ToSql; 2] = [&child, &head];
            let operation_arguments: [&dyn ToSql; 1] = [&operation];
            let artifact_arguments: [&dyn ToSql; 1] = [&record];
            let arguments: &[&dyn ToSql] = match kind {
                PublicationRowV1::Binding => &binding_arguments,
                PublicationRowV1::Operation => &operation_arguments,
                PublicationRowV1::Artifact => &artifact_arguments,
            };
            // Stored-state injection isolates raw type/length handling, not authority.
            let oversized = vec![0; maximum + 1];
            store.conn.execute(sql, params![oversized])?;
            assert_raw_gate_refusal(&store, kind, arguments, Error::PublicationConflict)?;
            store.conn.execute(sql, params!["not-a-blob"])?;
            assert_raw_gate_refusal(&store, kind, arguments, Error::StorageIndeterminate)?;
        }
        Ok(())
    }

    #[test]
    fn absent_key_probe_consumes_no_stored_row_or_blob_bytes() -> Fallible<()> {
        let store = SqliteStore::open(":memory:")?;
        let mut clock = ScriptedGuardMonotonicSourceV1::new([Duration::ZERO]);
        let start = clock.mark();
        let limits = ForkReplayReadLimitsV1::new(1, 1, 1, 64, 1_000_000)?;
        let mut budget = ForkReplayReadBudgetV1::new(limits, start, &mut clock)?;
        assert_eq!(store.publication_blob_with_context(PublicationRowV1::Operation,
            params![pos_core::Hash::zero().as_bytes().as_slice()],
            &mut NativeReadContextV1::protected(&mut budget))?, None);
        assert_eq!(budget.remaining_native_bytes(), 64);
        budget.charge_rows(1)?;
        Ok(())
    }
}
