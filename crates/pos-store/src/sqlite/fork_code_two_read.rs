//! `SQLite` side of the ADR-105 r6 R6.9 trusted reads.
//!
//! Validator (a) is the existing local-only admission and classified graph,
//! which every write path keeps. Validator (b) is this module: for a local
//! `FAR1` it is exactly validator (a), and for a code-2 `FAR1` it replaces
//! only the `FCC1` admission row, with the import admission row, and the local
//! `FCS1` custody table, with the imported `FCS1` table keyed by `FCT1` field
//! 6. An imported `FAR1` sits in `fork_admissions` next to the local rows, where
//! the strict local decoder rejects it, so only this module decodes code 2.

mod retained_key;

use pos_core::{
    Hasher, ImportedForkAdmissionRecordV1, ImportedForkAttributionAdmissionV1,
    ImportedForkClassifierGraphV1, TimelineId,
};
use retained_key::retained_key_bytes_with_context;
#[cfg(test)]
use rusqlite::params;
use rusqlite::Connection;

use super::{
    fork_replay_admission::{admission_blob_with_context, AdmissionRowV1},
    fork_replay_classifier::{
        classifier_registration_with_context, classifier_source_with_context,
        classifier_table_with_context, ClassifierKeyV1,
    },
    sqlite_classified_authority_graph_with_context, sqlite_local_fork_admission_with_context,
};
#[cfg(test)]
use crate::fork_event_authority::ValidatedImportV1;
use crate::{
    fork_event_authority::{
        imported_admission_matches, imported_graph_matches, AuthorityValidatorV1,
        ValidatedAdmissionV1, ValidatedGraphV1,
    },
    fork_manifest_publication::{
        PublicationSourceErrorV1, PublicationSourceResultV1, RetainedImportedKeyV1,
        RetainedKeyEvidenceV1,
    },
    fork_replay::NativeReadContextV1,
    ForkEventAuthorityErrorV1 as AuthorityError,
};

/// Read one child's `FAR1` under an explicit R6.9 validator.
pub(super) fn sqlite_validated_admission(
    conn: &Connection,
    hasher: &dyn Hasher,
    child_timeline_id: TimelineId,
    validator: AuthorityValidatorV1,
    context: &mut NativeReadContextV1<'_, '_>,
) -> Result<ValidatedAdmissionV1, AuthorityError> {
    let local = sqlite_local_fork_admission_with_context(conn, hasher, child_timeline_id, context)
        .and_then(|admission| local_admission_result(&admission, context));
    context
        .check()
        .map_err(|_| AuthorityError::CorruptAuthority)
        .and_then(|()| match validator {
            AuthorityValidatorV1::LocalOnly => local,
            AuthorityValidatorV1::CodeTwoAware => {
                local.or_else(|_| sqlite_imported_admission(conn, child_timeline_id, context))
            }
        })
}

/// Read one child's classified authority graph under an explicit R6.9
/// validator.
pub(super) fn sqlite_validated_graph(
    conn: &Connection,
    hasher: &dyn Hasher,
    child_timeline_id: TimelineId,
    validator: AuthorityValidatorV1,
    context: &mut NativeReadContextV1<'_, '_>,
) -> Result<ValidatedGraphV1, AuthorityError> {
    let local =
        sqlite_classified_authority_graph_with_context(conn, hasher, child_timeline_id, context)
            .and_then(|(admission, table, _)| {
                local_admission_result(&admission, context)
                    .map(|admission| ValidatedGraphV1 { admission, table })
            });
    context
        .check()
        .map_err(|_| AuthorityError::CorruptAuthority)
        .and_then(|()| match validator {
            AuthorityValidatorV1::LocalOnly => local,
            AuthorityValidatorV1::CodeTwoAware => {
                local.or_else(|_| sqlite_imported_graph(conn, child_timeline_id, context))
            }
        })
}

fn local_admission_result(
    record: &pos_core::ForkAdmissionRecordV1,
    context: &mut NativeReadContextV1<'_, '_>,
) -> Result<ValidatedAdmissionV1, AuthorityError> {
    context
        .canonical(record.canonical_cbor_len())
        .map_err(|_| AuthorityError::CorruptAuthority)?;
    context
        .canonical(record.canonical_cbor_len())
        .map_err(|_| AuthorityError::CorruptAuthority)?;
    let accepted = ValidatedAdmissionV1::local(record);
    context
        .check()
        .map(|()| accepted)
        .map_err(|_| AuthorityError::CorruptAuthority)
}

/// The `IKR1` and `IKT1` that retain the signing key of an imported publication
/// (ADR-105 erratum E12). A missing, undecodable, or unselected row is
/// invalid and a storage failure is a storage failure; a live-registry sidecar
/// never reads them.
pub(super) fn sqlite_retained_key_evidence(
    conn: &Connection,
    admission: &PublicationSourceResultV1<ValidatedAdmissionV1>,
    context: &mut NativeReadContextV1<'_, '_>,
) -> PublicationSourceResultV1<RetainedKeyEvidenceV1> {
    use PublicationSourceErrorV1::Invalid;
    context.check().map_err(|_| Invalid).and_then(|()| {
        admission
            .as_ref()
            .ok()
            .and_then(ValidatedAdmissionV1::import)
            .map_or(Ok(RetainedKeyEvidenceV1::LiveRegistry), |import| {
                retained_key_bytes_with_context(conn, import, context).and_then(|stored| {
                    context
                        .imported_key_record(&stored.record)
                        .map_err(|_| Invalid)
                        .and_then(|record| {
                            stored
                                .tombstone
                                .as_ref()
                                .map(|bytes| context.imported_key_tombstone(bytes))
                                .transpose()
                                .map_err(|_| Invalid)
                                .and_then(|tombstone| {
                                    context
                                        .canonical(record.canonical_cbor_len())
                                        .and_then(|()| {
                                            tombstone.as_ref().map_or(Ok(()), |tombstone| {
                                                context.canonical(tombstone.canonical_cbor_len())
                                            })
                                        })
                                        .map(|()| {
                                            RetainedKeyEvidenceV1::Imported(Box::new(
                                                RetainedImportedKeyV1 { record, tombstone },
                                            ))
                                        })
                                        .and_then(|retained| context.check().map(|()| retained))
                                        .map_err(|_| Invalid)
                                })
                        })
                })
            })
    })
}

/// R6.9 (b), `FAR1` admission: the code-2 `FAR1` of the child has its one
/// import admission row (the table is `UNIQUE` on the child), which names this
/// child, this origin, and this `FAR1` digest.
fn sqlite_imported_admission(
    conn: &Connection,
    child_timeline_id: TimelineId,
    context: &mut NativeReadContextV1<'_, '_>,
) -> Result<ValidatedAdmissionV1, AuthorityError> {
    use AuthorityError::CorruptAuthority;
    read_imported_admission_pair(conn, child_timeline_id, context).and_then(
        |(admission, record)| {
            context
                .canonical(admission.canonical_cbor_len())
                .map_err(|_| CorruptAuthority)
                .and_then(|()| {
                    let matches =
                        imported_admission_matches(&admission, &record, child_timeline_id);
                    context
                        .check()
                        .map_err(|_| CorruptAuthority)
                        .and_then(|()| matches.then_some(()).ok_or(CorruptAuthority))
                })
                // Acceptance emits the FAR1 digest again and copies its fields.
                .and_then(|()| {
                    context
                        .canonical(admission.canonical_cbor_len())
                        .map_err(|_| CorruptAuthority)
                })
                .and_then(|()| {
                    context
                        .canonical(admission.canonical_cbor_len())
                        .map_err(|_| CorruptAuthority)
                })
                .map(|()| ValidatedAdmissionV1::imported(&admission, &record))
                .and_then(|accepted| {
                    context
                        .check()
                        .map(|()| accepted)
                        .map_err(|_| CorruptAuthority)
                })
        },
    )
}

/// Select and decode the code-2 FAR1 and its unique committed IFA1 in order.
fn read_imported_admission_pair(
    conn: &Connection,
    child_timeline_id: TimelineId,
    context: &mut NativeReadContextV1<'_, '_>,
) -> Result<
    (
        ImportedForkAdmissionRecordV1,
        ImportedForkAttributionAdmissionV1,
    ),
    AuthorityError,
> {
    use AuthorityError::CorruptAuthority;
    context
        .bytes(ulid::ULID_LEN)
        .map_err(|_| CorruptAuthority)?;
    let key = child_timeline_id.to_string();
    let bytes = admission_blob_with_context(conn, AdmissionRowV1::Fork, &key, context)?
        .ok_or(CorruptAuthority)?;
    let admission = context
        .imported_admission_record(&bytes)
        .map_err(|_| CorruptAuthority)?;
    let bytes = admission_blob_with_context(conn, AdmissionRowV1::Import, &key, context)?
        .ok_or(CorruptAuthority)?;
    let record = context
        .imported_admission(&bytes)
        .map_err(|_| CorruptAuthority)?;
    Ok((admission, record))
}

/// R6.9 (b), `FCS1` resolution: the imported `FCS1` is looked up by `FCT1`
/// field 6, and the triple must satisfy G1-G8 against the code-2 `FAR1`.
fn sqlite_imported_graph(
    conn: &Connection,
    child_timeline_id: TimelineId,
    context: &mut NativeReadContextV1<'_, '_>,
) -> Result<ValidatedGraphV1, AuthorityError> {
    sqlite_imported_admission(conn, child_timeline_id, context).and_then(|admission| {
        read_imported_classifier_graph(conn, child_timeline_id, context).and_then(|graph| {
            // Gate source/table digest buffers separately from selected copies.
            context
                .canonical(graph.source.canonical_cbor_len())
                .map_err(|_| AuthorityError::CorruptAuthority)
                .and_then(|()| {
                    context
                        .canonical(graph.table.canonical_cbor_len())
                        .map_err(|_| AuthorityError::CorruptAuthority)
                })
                .and_then(|()| {
                    let matches = imported_graph_matches(&graph, &admission);
                    context
                        .check()
                        .map_err(|_| AuthorityError::CorruptAuthority)
                        .and_then(|()| {
                            matches
                                .then_some(ValidatedGraphV1 {
                                    admission,
                                    table: graph.table,
                                })
                                .ok_or(AuthorityError::CorruptAuthority)
                        })
                })
        })
    })
}

/// Read the classifier triple with the existing selected-row lifetime owners.
fn read_imported_classifier_graph(
    conn: &Connection,
    child_timeline_id: TimelineId,
    context: &mut NativeReadContextV1<'_, '_>,
) -> Result<ImportedForkClassifierGraphV1, AuthorityError> {
    context
        .check()
        .map_err(|_| AuthorityError::CorruptAuthority)?;
    let table = classifier_table_with_context(conn, child_timeline_id, context)?;
    let registration = classifier_registration_with_context(conn, child_timeline_id, context)?;
    let source = classifier_source_with_context(
        conn,
        ClassifierKeyV1::ImportedSource(table.input().source_configuration_revision_digest),
        context,
    )?;
    Ok(ImportedForkClassifierGraphV1 {
        source,
        table,
        registration,
    })
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
    use pos_core::{ErasureInventoryPersistencePortV1, ErasureProtectedEffectDispositionV1};
    use std::time::Duration;

    fn admission_deadline_sweep(
        store: &super::super::SqliteStore,
        child: TimelineId,
        expected: &ValidatedAdmissionV1,
        bytes: usize,
    ) -> Fallible<()> {
        for final_offset in [Duration::ZERO, Duration::from_secs(2)] {
            let mut completed = false;
            for marks in 2..256 {
                let mut clock = ScriptedGuardMonotonicSourceV1::new(
                    std::iter::repeat_n(Duration::from_millis(1), marks).chain([final_offset]),
                );
                let start = clock.mark();
                let limits = ForkReplayReadLimitsV1::new(1, 1, 6, bytes, 1_000_000)?;
                let mut budget = ForkReplayReadBudgetV1::new(limits, start, &mut clock)?;
                let result = sqlite_validated_admission(
                    &store.conn,
                    store.hasher.as_ref(),
                    child,
                    AuthorityValidatorV1::CodeTwoAware,
                    &mut NativeReadContextV1::protected(&mut budget),
                );
                if let Ok(admission) = result {
                    assert_eq!(&admission, expected);
                    assert_eq!(budget.remaining_native_bytes(), 0);
                    completed = true;
                    break;
                }
                assert!(budget.check_time().is_err());
            }
            assert!(
                completed,
                "all observable admission expiry and regression checkpoints tested"
            );
        }
        Ok(())
    }

    fn admission_byte_boundary(
        store: &super::super::SqliteStore,
        child: TimelineId,
        expected: &ValidatedAdmissionV1,
        maximum: usize,
        limit: usize,
    ) -> Fallible<()> {
        let mut clock = ScriptedGuardMonotonicSourceV1::new([Duration::ZERO]);
        let start = clock.mark();
        let limits = ForkReplayReadLimitsV1::new(1, 1, 6, limit, 1_000_000)?;
        let mut budget = ForkReplayReadBudgetV1::new(limits, start, &mut clock)?;
        let result = sqlite_validated_admission(
            &store.conn,
            store.hasher.as_ref(),
            child,
            AuthorityValidatorV1::CodeTwoAware,
            &mut NativeReadContextV1::protected(&mut budget),
        );
        if limit == maximum {
            assert_eq!(&result?, expected);
            assert_eq!(budget.remaining_native_bytes(), 0);
        } else {
            assert_eq!(result, Err(AuthorityError::CorruptAuthority));
            assert!(budget.check_time().is_err());
        }
        Ok(())
    }

    #[test]
    fn file_backed_admission_reads_charge_actual_local_first_and_imported_work() -> Fallible<()> {
        for shape in [
            Shape::Mixed,
            Shape::EmptyClassified,
            Shape::EmptyUnclassified,
        ] {
            let directory = tempfile::tempdir()?;
            let path = directory.path().join("admission-context.sqlite");
            let mut store = super::super::SqliteStore::open(path.to_str().ok_or("UTF-8 path")?)?;
            let world = World::new(shape, false)?;
            let built = world.build(&Spec::default())?;
            world.seed_destination(&mut store)?;
            pin_policy(&mut store, &built.policy)?;
            store.import_verified(&request_for(&world, &built))?;
            let child = world.child_at(0)?.id;
            let expected = store
                .fork_publication_admission(child, AuthorityValidatorV1::CodeTwoAware)
                .map_err(|_| "ordinary admission failed")?;
            let key = child.to_string();
            let import_bytes: Vec<u8> = store.conn.query_row(
                "SELECT ifa1_cbor FROM imported_fork_attribution_admissions WHERE child_id = ?1",
                params![key],
                |row| row.get(0),
            )?;
            let bytes = super::super::fork_replay_admission::imported_admission_phase_cost(
                &built.envelope.unsigned().input().records.fork_admission,
                &import_bytes,
            )?;
            let interval = store.begin_protected_effect_interval()?;
            for limit in 1..=bytes {
                admission_byte_boundary(&store, child, &expected, bytes, limit)?;
            }
            for rows in 1..6 {
                let mut clock = ScriptedGuardMonotonicSourceV1::new([Duration::ZERO]);
                let start = clock.mark();
                let limits = ForkReplayReadLimitsV1::new(1, 1, rows, bytes, 1_000_000)?;
                let mut budget = ForkReplayReadBudgetV1::new(limits, start, &mut clock)?;
                assert_eq!(
                    sqlite_validated_admission(
                        &store.conn,
                        store.hasher.as_ref(),
                        child,
                        AuthorityValidatorV1::CodeTwoAware,
                        &mut NativeReadContextV1::protected(&mut budget)
                    ),
                    Err(AuthorityError::CorruptAuthority)
                );
                assert!(budget.check_time().is_err());
            }
            admission_deadline_sweep(&store, child, &expected, bytes)?;
            store.finish_protected_effect_interval(
                interval,
                ErasureProtectedEffectDispositionV1::Rollback,
            )?;
        }
        Ok(())
    }

    fn graph_boundary(
        store: &super::super::SqliteStore,
        child: TimelineId,
        expected: &ValidatedGraphV1,
        maximum: usize,
        limit: usize,
        rows: usize,
    ) -> Fallible<()> {
        let mut clock = ScriptedGuardMonotonicSourceV1::new([Duration::ZERO]);
        let start = clock.mark();
        let limits = ForkReplayReadLimitsV1::new(1, 1, rows, limit, 1_000_000)?;
        let mut budget = ForkReplayReadBudgetV1::new(limits, start, &mut clock)?;
        let result = sqlite_validated_graph(
            &store.conn,
            store.hasher.as_ref(),
            child,
            AuthorityValidatorV1::CodeTwoAware,
            &mut NativeReadContextV1::protected(&mut budget),
        );
        if limit == maximum && rows == 12 {
            let actual = result?;
            assert_eq!(actual.admission, expected.admission);
            assert_eq!(actual.table, expected.table);
            assert_eq!(budget.remaining_native_bytes(), 0);
        } else {
            assert!(matches!(result, Err(AuthorityError::CorruptAuthority)));
            assert!(budget.check_time().is_err());
        }
        Ok(())
    }

    fn graph_deadline_sweep(
        store: &super::super::SqliteStore,
        child: TimelineId,
        expected: &ValidatedGraphV1,
        bytes: usize,
    ) -> Fallible<()> {
        for final_offset in [Duration::ZERO, Duration::from_secs(2)] {
            let mut completed = false;
            for marks in 2..512 {
                let mut clock = ScriptedGuardMonotonicSourceV1::new(
                    std::iter::repeat_n(Duration::from_millis(1), marks).chain([final_offset]),
                );
                let start = clock.mark();
                let limits = ForkReplayReadLimitsV1::new(1, 1, 12, bytes, 1_000_000)?;
                let mut budget = ForkReplayReadBudgetV1::new(limits, start, &mut clock)?;
                let result = sqlite_validated_graph(
                    &store.conn,
                    store.hasher.as_ref(),
                    child,
                    AuthorityValidatorV1::CodeTwoAware,
                    &mut NativeReadContextV1::protected(&mut budget),
                );
                if let Ok(actual) = result {
                    assert_eq!(actual.admission, expected.admission);
                    assert_eq!(actual.table, expected.table);
                    assert_eq!(budget.remaining_native_bytes(), 0);
                    completed = true;
                    break;
                }
                assert!(budget.check_time().is_err());
            }
            assert!(
                completed,
                "all observable graph expiry and regression checkpoints tested"
            );
        }
        Ok(())
    }

    #[test]
    fn file_backed_classifier_graph_charges_selected_rows_fields_and_digest_buffers() -> Fallible<()>
    {
        for shape in [Shape::Mixed, Shape::EmptyClassified] {
            let directory = tempfile::tempdir()?;
            let path = directory.path().join("classifier-context.sqlite");
            let mut store = super::super::SqliteStore::open(path.to_str().ok_or("UTF-8 path")?)?;
            let world = World::new(shape, false)?;
            let built = world.build(&Spec::default())?;
            world.seed_destination(&mut store)?;
            pin_policy(&mut store, &built.policy)?;
            store.import_verified(&request_for(&world, &built))?;
            let child = world.child_at(0)?.id;
            let expected = sqlite_validated_graph(
                &store.conn,
                store.hasher.as_ref(),
                child,
                AuthorityValidatorV1::CodeTwoAware,
                &mut NativeReadContextV1::ordinary(),
            )?;
            let import_bytes: Vec<u8> = store.conn.query_row(
                "SELECT ifa1_cbor FROM imported_fork_attribution_admissions WHERE child_id = ?1",
                params![child.to_string()],
                |row| row.get(0),
            )?;
            let bytes = super::super::fork_replay_admission::imported_admission_phase_cost(
                &built.envelope.unsigned().input().records.fork_admission,
                &import_bytes,
            )? + super::super::fork_replay_classifier::imported_classifier_phase_cost(
                built.envelope.unsigned().input().classifier.as_ref(),
            )?;
            let interval = store.begin_protected_effect_interval()?;
            for limit in 1..=bytes {
                graph_boundary(&store, child, &expected, bytes, limit, 12)?;
            }
            for rows in 1..12 {
                graph_boundary(&store, child, &expected, bytes, bytes, rows)?;
            }
            graph_deadline_sweep(&store, child, &expected, bytes)?;
            store.finish_protected_effect_interval(
                interval,
                ErasureProtectedEffectDispositionV1::Rollback,
            )?;
        }
        Ok(())
    }

    struct Fixture {
        store: super::super::SqliteStore,
        admission: PublicationSourceResultV1<ValidatedAdmissionV1>,
        expected: RetainedKeyEvidenceV1,
        bytes: usize,
    }

    fn fixture(destroyed: bool) -> Fallible<Fixture> {
        let world = World::new(Shape::Mixed, false)?;
        let built = world.build(&Spec {
            destroyed_key: destroyed,
            ..Spec::default()
        })?;
        let mut store = super::super::SqliteStore::open(":memory:")?;
        world.seed_destination(&mut store)?;
        pin_policy(&mut store, &built.policy)?;
        store.import_verified(&request_for(&world, &built))?;
        let admission = store
            .fork_publication_admission(world.child_at(0)?.id, AuthorityValidatorV1::CodeTwoAware);
        let input = built.envelope.unsigned().input();
        let record = input.key_record;
        let tombstone = input.key_tombstone;
        // Raw retrieval + decoder equality + logical result copy, and owner
        // String: this oracle uses byte encoders, not production length gates.
        let bytes = record.to_canonical_cbor().len() * 3
            + record.identity().owner_id.as_str().len()
            + tombstone.as_ref().map_or(0, |value| {
                value.to_canonical_cbor().len() * 3 + value.identity().owner_id.as_str().len()
            });
        let expected =
            RetainedKeyEvidenceV1::Imported(Box::new(RetainedImportedKeyV1 { record, tombstone }));
        Ok(Fixture {
            store,
            admission,
            expected,
            bytes,
        })
    }

    fn assert_byte_boundary(fixture: &Fixture, bytes: usize) -> Fallible<()> {
        let mut clock = ScriptedGuardMonotonicSourceV1::new([Duration::ZERO]);
        let start = clock.mark();
        let limits = ForkReplayReadLimitsV1::new(1, 1, 2, bytes, 1_000_000)?;
        let mut budget = ForkReplayReadBudgetV1::new(limits, start, &mut clock)?;
        let result = sqlite_retained_key_evidence(
            &fixture.store.conn,
            &fixture.admission,
            &mut NativeReadContextV1::protected(&mut budget),
        );
        if bytes == fixture.bytes {
            assert_eq!(result, Ok(fixture.expected.clone()));
            assert_eq!(budget.remaining_native_bytes(), 0);
        } else {
            assert_eq!(result, Err(PublicationSourceErrorV1::Invalid));
            assert!(budget.check_time().is_err());
        }
        Ok(())
    }

    fn assert_deadline_boundaries(fixture: &Fixture) -> Fallible<()> {
        for final_offset in [Duration::ZERO, Duration::from_secs(2)] {
            let mut completed = false;
            for marks in 2..128 {
                let mut clock = ScriptedGuardMonotonicSourceV1::new(
                    std::iter::repeat_n(Duration::from_millis(1), marks).chain([final_offset]),
                );
                let start = clock.mark();
                let limits = ForkReplayReadLimitsV1::new(1, 1, 2, fixture.bytes, 1_000_000)?;
                let mut budget = ForkReplayReadBudgetV1::new(limits, start, &mut clock)?;
                let result = sqlite_retained_key_evidence(
                    &fixture.store.conn,
                    &fixture.admission,
                    &mut NativeReadContextV1::protected(&mut budget),
                );
                if let Ok(retained) = result {
                    assert_eq!(retained, fixture.expected);
                    assert_eq!(budget.remaining_native_bytes(), 0);
                    completed = true;
                    break;
                }
                assert!(budget.check_time().is_err());
            }
            assert!(
                completed,
                "every observable expiry and regression checkpoint was tested"
            );
        }
        Ok(())
    }

    #[test]
    fn retained_key_phase_accounts_live_and_destroyed_blobs_copies_and_deadlines() -> Fallible<()> {
        for destroyed in [false, true] {
            let fixture = fixture(destroyed)?;
            for bytes in 1..=fixture.bytes {
                assert_byte_boundary(&fixture, bytes)?;
            }
            assert_deadline_boundaries(&fixture)?;
            let mut clock = ScriptedGuardMonotonicSourceV1::new([Duration::ZERO]);
            let start = clock.mark();
            let limits = ForkReplayReadLimitsV1::new(1, 1, 1, fixture.bytes, 1_000_000)?;
            let mut budget = ForkReplayReadBudgetV1::new(limits, start, &mut clock)?;
            assert_eq!(
                sqlite_retained_key_evidence(
                    &fixture.store.conn,
                    &fixture.admission,
                    &mut NativeReadContextV1::protected(&mut budget)
                ),
                Err(PublicationSourceErrorV1::Invalid)
            );
            assert_eq!(budget.remaining_native_bytes(), fixture.bytes);
            assert!(budget.check_time().is_err());
        }
        Ok(())
    }

    #[test]
    fn retained_key_raw_caps_are_inclusive_before_strict_record_decoding() -> Fallible<()> {
        let fixture = fixture(true)?;
        let import = fixture
            .admission
            .as_ref()
            .map_err(|_| "fixture admission")?
            .import()
            .ok_or("fixture imported identity")?;
        let (original_record, original_tombstone): (Vec<u8>, Option<Vec<u8>>) =
            fixture.store.conn.query_row(
                "SELECT ikr1_cbor, ikt1_cbor FROM imported_fork_key_evidence",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )?;
        for (record_column, sql, maximum) in [
            (
                true,
                "UPDATE imported_fork_key_evidence SET ikr1_cbor = ?1",
                pos_core::MAX_IMPORTED_KEY_RECORD_BYTES_V1,
            ),
            (
                false,
                "UPDATE imported_fork_key_evidence SET ikt1_cbor = ?1",
                pos_core::MAX_IMPORTED_KEY_TOMBSTONE_BYTES_V1,
            ),
        ] {
            for length in [maximum - 1, maximum, maximum + 1] {
                fixture.store.conn.execute_batch("SAVEPOINT raw_key_cap")?;
                let changed = vec![0; length];
                assert_eq!(fixture.store.conn.execute(sql, [&changed])?, 1);
                let record = if record_column {
                    &changed
                } else {
                    &original_record
                };
                let tombstone = if record_column {
                    original_tombstone.as_deref()
                } else {
                    Some(changed.as_slice())
                };
                let bytes = record.len() + tombstone.map_or(0, <[u8]>::len);
                let mut clock = ScriptedGuardMonotonicSourceV1::new([Duration::ZERO]);
                let start = clock.mark();
                let limits = ForkReplayReadLimitsV1::new(1, 1, 2, bytes, 1_000_000)?;
                let mut budget = ForkReplayReadBudgetV1::new(limits, start, &mut clock)?;
                // Impossible durable bytes isolate the raw probe/fetch owner;
                // passing its inclusive cap does not authenticate an IKR1/IKT1.
                let actual = retained_key_bytes_with_context(
                    &fixture.store.conn,
                    import,
                    &mut NativeReadContextV1::protected(&mut budget),
                );
                if length <= maximum {
                    let actual = actual
                        .map_err(|error| format!("raw retained-key fetch failed: {error:?}"))?;
                    assert_eq!(&actual.record, record);
                    assert_eq!(actual.tombstone.as_deref(), tombstone);
                    assert_eq!(budget.remaining_native_bytes(), 0);
                } else {
                    assert!(matches!(actual, Err(PublicationSourceErrorV1::Invalid)));
                    assert_eq!(budget.remaining_native_bytes(), bytes);
                }
                budget.check_time()?;
                fixture
                    .store
                    .conn
                    .execute_batch("ROLLBACK TO raw_key_cap; RELEASE raw_key_cap")?;
            }
        }
        assert_eq!(
            sqlite_retained_key_evidence(
                &fixture.store.conn,
                &fixture.admission,
                &mut NativeReadContextV1::ordinary(),
            ),
            Ok(fixture.expected),
        );
        Ok(())
    }

    #[test]
    fn retained_key_type_and_cap_failures_precede_raw_copies() -> Fallible<()> {
        for (sql, maximum) in [
            (
                "UPDATE imported_fork_key_evidence SET ikr1_cbor = ?1",
                pos_core::MAX_IMPORTED_KEY_RECORD_BYTES_V1,
            ),
            (
                "UPDATE imported_fork_key_evidence SET ikt1_cbor = ?1",
                pos_core::MAX_IMPORTED_KEY_TOMBSTONE_BYTES_V1,
            ),
        ] {
            let fixture = fixture(true)?;
            for (value, expected) in [
                (
                    rusqlite::types::Value::Blob(vec![0; maximum + 1]),
                    PublicationSourceErrorV1::Invalid,
                ),
                (
                    rusqlite::types::Value::Text("not-a-blob".into()),
                    PublicationSourceErrorV1::Storage,
                ),
            ] {
                // Impossible stored-state injection exercises only the raw gate.
                fixture.store.conn.execute(sql, [value])?;
                let mut clock = ScriptedGuardMonotonicSourceV1::new([Duration::ZERO]);
                let start = clock.mark();
                let limits = ForkReplayReadLimitsV1::new(1, 1, 2, 64, 1_000_000)?;
                let mut budget = ForkReplayReadBudgetV1::new(limits, start, &mut clock)?;
                assert_eq!(
                    sqlite_retained_key_evidence(
                        &fixture.store.conn,
                        &fixture.admission,
                        &mut NativeReadContextV1::protected(&mut budget)
                    ),
                    Err(expected)
                );
                assert_eq!(budget.remaining_native_bytes(), 64);
                assert!(budget.check_time().is_ok());
            }
        }
        Ok(())
    }

    #[test]
    fn absent_or_unselected_key_evidence_has_no_stored_row_or_blob_unit() -> Fallible<()> {
        let fixture = fixture(false)?;
        // The selected import identity is a structural test value; neither an
        // absent join nor a failed admission may consult other key evidence.
        let import = ValidatedImportV1 {
            import_operation_id: pos_core::Hash::from_bytes([253; 32]),
            full_envelope_digest: pos_core::Hash::from_bytes([254; 32]),
        };
        let mut clock = ScriptedGuardMonotonicSourceV1::new([Duration::ZERO]);
        let start = clock.mark();
        let limits = ForkReplayReadLimitsV1::new(1, 1, 1, 64, 1_000_000)?;
        let mut budget = ForkReplayReadBudgetV1::new(limits, start, &mut clock)?;
        assert!(matches!(
            retained_key_bytes_with_context(
                &fixture.store.conn,
                import,
                &mut NativeReadContextV1::protected(&mut budget)
            ),
            Err(PublicationSourceErrorV1::Invalid)
        ));
        assert_eq!(budget.remaining_native_bytes(), 64);
        budget.charge_rows(1)?;
        assert_eq!(
            sqlite_retained_key_evidence(
                &fixture.store.conn,
                &Err(PublicationSourceErrorV1::Invalid),
                &mut NativeReadContextV1::ordinary()
            ),
            Ok(RetainedKeyEvidenceV1::LiveRegistry)
        );
        // Keep the authentic admitted identity observable, not a fabricated
        // privileged admission used to exercise a private lookup.
        assert!(fixture
            .admission
            .as_ref()
            .is_ok_and(|admission| admission.import().is_some()));
        Ok(())
    }
}
