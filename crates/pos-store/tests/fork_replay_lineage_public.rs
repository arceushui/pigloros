#![cfg_attr(coverage_nightly, feature(coverage_attribute))]
#![cfg(feature = "sqlite")]

//! Independent ADR-117 native-work oracles through the actual public bridge.

use pos_core::{
    trusted_clock::{GuardMonotonicSourceV1, ScriptedGuardMonotonicSourceV1},
    CanonicalBytes, EntityId, ErasureContainmentGateV1, ErasureInventoryPersistencePortV1,
    ErasureProtectedEffectDispositionV1, EventDraft, EventStore, Kind, Seq, TimelineId,
};
use pos_store::{
    memory::MemoryStore, sqlite::SqliteStore, ForkReplayAuthorityReadErrorV1 as ReadError,
    ForkReplayAuthorityReadPortV1, ForkReplayLineageReadErrorV1 as Error, ForkReplayReadBudgetV1,
    ForkReplayReadLimitsV1,
};
use std::{sync::Arc, time::Duration};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn bind(store: &mut impl EventStore) -> TestResult {
    store.bind_erasure_gate(Arc::new(ErasureContainmentGateV1::new_test_open()))?;
    Ok(())
}

/// The oracle comes from literal native fields, not a measured remaining ledger:
/// root ID16 + option1 + local head8 + cycle insertion16; `SQLite` additionally
/// copies key26 and raw ID26. A Fork adds parent16/cut8 to the native carrier,
/// another raw parent26 in `SQLite`, and one internal continuation16.
fn empty_chain<
    S: EventStore + ForkReplayAuthorityReadPortV1 + ErasureInventoryPersistencePortV1,
>(
    store: &S,
    root: TimelineId,
    child: TimelineId,
    sqlite: bool,
) -> TestResult {
    let root_bytes = if sqlite { 26 + 26 + 25 + 16 } else { 25 + 16 };
    let fork_bytes = if sqlite {
        26 + 26 + 26 + 49 + 16
    } else {
        49 + 16
    };
    let chain_bytes = fork_bytes + 16 + root_bytes;
    let chain_rows = if sqlite { 2 * (2 + 2) } else { 2 };
    let interval = store.begin_protected_effect_interval()?;
    for repeats in [1, 2] {
        let exact_bytes = chain_bytes * repeats;
        let exact_rows = chain_rows * repeats;
        let exact_visits = 2 * repeats;
        for (bytes, rows, visits, succeeds) in [
            (exact_bytes, exact_rows, exact_visits, true),
            (exact_bytes + 1, exact_rows + 1, exact_visits + 1, true),
            (exact_bytes - 1, exact_rows, exact_visits, false),
            (exact_bytes, exact_rows - 1, exact_visits, false),
            (exact_bytes, exact_rows, exact_visits - 1, false),
        ] {
            let limits = ForkReplayReadLimitsV1::new(8, visits, rows, bytes, 1_000_000)?;
            let mut clock = ScriptedGuardMonotonicSourceV1::new([Duration::ZERO]);
            let start = clock.mark();
            let mut budget = ForkReplayReadBudgetV1::new(limits, start, &mut clock)?;
            let mut result = Ok(None);
            for _ in 0..repeats {
                result = store.read_fork_replay_lineage_node(child, 0, 1, &mut budget);
                if result.is_err() {
                    break;
                }
                let node = result
                    .as_ref()
                    .map_err(|error| *error)?
                    .as_ref()
                    .ok_or("missing visible child")?;
                assert_eq!(node.timeline_id(), &child);
                assert_eq!(node.fork_point(), Some(&(root, Seq::ZERO)));
            }
            if succeeds {
                assert!(result?.is_some());
                assert_eq!(budget.remaining_native_bytes(), bytes - exact_bytes);
                budget.check_time()?;
            } else {
                assert_eq!(result, Err(Error::Read(ReadError::BoundsExceeded)));
                assert_eq!(budget.check_time(), Err(ReadError::BoundsExceeded));
                assert_eq!(
                    store.read_fork_replay_lineage_node(root, 0, 1, &mut budget),
                    Err(Error::Read(ReadError::BoundsExceeded))
                );
            }
        }
    }
    for (timeline, depth, cap, succeeds) in [
        (root, 0, 0, true),
        (root, 1, 1, true),
        (child, 0, 0, false),
        (child, 8, 8, false),
        (root, 0, 9, false),
        (root, usize::MAX, 8, false),
    ] {
        let limits = ForkReplayReadLimitsV1::new(8, 8, 32, 1_024, 1_000_000)?;
        let mut clock = ScriptedGuardMonotonicSourceV1::new([Duration::ZERO]);
        let start = clock.mark();
        let mut budget = ForkReplayReadBudgetV1::new(limits, start, &mut clock)?;
        let result = store.read_fork_replay_lineage_node(timeline, depth, cap, &mut budget);
        if succeeds {
            let node = result?.ok_or("missing visible root")?;
            assert_eq!(node.timeline_id(), &root);
            assert_eq!(node.fork_point(), None);
            assert_eq!(budget.remaining_native_bytes(), 1_024 - root_bytes);
        } else {
            assert_eq!(result, Err(Error::Read(ReadError::BoundsExceeded)));
        }
    }
    store.finish_protected_effect_interval(
        interval,
        ErasureProtectedEffectDispositionV1::Rollback,
    )?;
    Ok(())
}

fn seed_empty(
    store: &mut impl EventStore,
) -> Result<(TimelineId, TimelineId), Box<dyn std::error::Error>> {
    bind(store)?;
    let root = store
        .create_timeline(&"private unselected name ".repeat(4_096))?
        .id();
    let child = store.fork(root, Seq::ZERO, "empty child")?.id();
    Ok((root, child))
}

#[test]
fn literal_empty_lineage_limits_repeat_on_memory_sqlite_and_readonly() -> TestResult {
    let mut memory = MemoryStore::new();
    let (root, child) = seed_empty(&mut memory)?;
    empty_chain(&memory, root, child, false)?;
    let mut in_memory = SqliteStore::open(":memory:")?;
    let (root, child) = seed_empty(&mut in_memory)?;
    empty_chain(&in_memory, root, child, true)?;
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("lineage.sqlite");
    let path = path.to_str().ok_or("utf-8 path")?;
    let mut writer = SqliteStore::open(path)?;
    let (root, child) = seed_empty(&mut writer)?;
    empty_chain(&writer, root, child, true)?;
    drop(writer);
    let mut readonly = SqliteStore::open_read_only(path)?;
    bind(&mut readonly)?;
    empty_chain(&readonly, root, child, true)?;
    Ok(())
}

fn candidate_events<
    S: EventStore + ForkReplayAuthorityReadPortV1 + ErasureInventoryPersistencePortV1,
>(
    store: &mut S,
    sqlite: bool,
) -> TestResult {
    bind(store)?;
    let root = store.create_timeline("candidate events")?.id();
    for kind in ["x", "ordinary", "nongeo.kind!"] {
        drop(store.append(
            root,
            &[EventDraft::new(
                EntityId::new(),
                Kind::new(kind),
                CanonicalBytes::from_static(b"payload is not inspected"),
            )],
        )?);
    }
    // All three E0 candidates retain a Seq8. Only lengths8/12 need SQLite's
    // additional E1 row and copied String; Memory compares borrowed kinds.
    let bytes = if sqlite {
        93 + 3 * 8 + 8 + 12
    } else {
        41 + 3 * 8
    };
    let rows = if sqlite { 4 + 3 + 2 } else { 1 + 3 };
    let interval = store.begin_protected_effect_interval()?;
    for (bytes, rows, succeeds) in [
        (bytes, rows, true),
        (bytes - 1, rows, false),
        (bytes, rows - 1, false),
    ] {
        let limits = ForkReplayReadLimitsV1::new(8, 1, rows, bytes, 1_000_000)?;
        let mut clock = ScriptedGuardMonotonicSourceV1::new([Duration::ZERO]);
        let start = clock.mark();
        let mut budget = ForkReplayReadBudgetV1::new(limits, start, &mut clock)?;
        let result = store.read_fork_replay_lineage_node(root, 0, 0, &mut budget);
        if succeeds {
            let node = result?.ok_or("missing ordinary root")?;
            assert_eq!(node.fork_point(), None);
            assert_eq!(budget.remaining_native_bytes(), 0);
        } else {
            assert_eq!(result, Err(Error::Read(ReadError::BoundsExceeded)));
        }
    }
    store.finish_protected_effect_interval(
        interval,
        ErasureProtectedEffectDispositionV1::Rollback,
    )?;
    assert_eq!(
        store.get_timeline(root)?.ok_or("missing root")?.head,
        Seq::from_u64(3)
    );
    Ok(())
}

#[test]
fn nonmatching_candidates_are_actual_work_without_payload_or_name_copies() -> TestResult {
    candidate_events(&mut MemoryStore::new(), false)?;
    candidate_events(&mut SqliteStore::open(":memory:")?, true)?;
    Ok(())
}

#[test]
fn missing_targets_and_unheld_sqlite_reads_fail_at_their_actual_seams() -> TestResult {
    let missing = TimelineId::new();
    let mut store = SqliteStore::open(":memory:")?;
    bind(&mut store)?;
    let limits = ForkReplayReadLimitsV1::new(8, 1, 2, 42, 1_000_000)?;
    let mut clock = ScriptedGuardMonotonicSourceV1::new([Duration::ZERO]);
    let start = clock.mark();
    let mut budget = ForkReplayReadBudgetV1::new(limits, start, &mut clock)?;
    assert_eq!(
        store.read_fork_replay_lineage_node(missing, 0, 0, &mut budget),
        Err(Error::Read(ReadError::StorageUnavailable))
    );
    assert_eq!(budget.remaining_native_bytes(), 42);
    let interval = store.begin_protected_effect_interval()?;
    assert_eq!(
        store.read_fork_replay_lineage_node(missing, 0, 0, &mut budget)?,
        None
    );
    assert_eq!(budget.remaining_native_bytes(), 0);
    store.finish_protected_effect_interval(
        interval,
        ErasureProtectedEffectDispositionV1::Rollback,
    )?;
    let mut memory = MemoryStore::new();
    bind(&mut memory)?;
    let limits = ForkReplayReadLimitsV1::new(8, 1, 1, 16, 1_000_000)?;
    let mut clock = ScriptedGuardMonotonicSourceV1::new([Duration::ZERO]);
    let start = clock.mark();
    let mut budget = ForkReplayReadBudgetV1::new(limits, start, &mut clock)?;
    assert_eq!(
        memory.read_fork_replay_lineage_node(missing, 0, 0, &mut budget)?,
        None
    );
    assert_eq!(budget.remaining_native_bytes(), 0);
    Ok(())
}

fn native_gate_denials<
    S: EventStore + ForkReplayAuthorityReadPortV1 + ErasureInventoryPersistencePortV1,
>(
    new_store: impl Fn() -> Result<S, Box<dyn std::error::Error>>,
    expected_ancestor_bytes: usize,
) -> TestResult {
    for ancestor in [false, true] {
        for frozen in [false, true] {
            let mut store = new_store()?;
            let gate = Arc::new(ErasureContainmentGateV1::new_test_open());
            store.bind_erasure_gate(Arc::clone(&gate))?;
            let root = store.create_timeline("native gate root")?.id();
            let child = store.fork(root, Seq::ZERO, "native gate child")?.id();
            let denied = if ancestor { root } else { child };
            let expected = if frozen {
                gate.freeze_timeline_for_test(denied);
                Error::AccessFrozen
            } else {
                gate.block_timeline(denied);
                Error::ContainmentUnavailable
            };
            let interval = store.begin_protected_effect_interval()?;
            let limits = ForkReplayReadLimitsV1::new(2, 8, 32, 1_024, 1_000_000)?;
            let mut clock = ScriptedGuardMonotonicSourceV1::new([Duration::ZERO]);
            let start = clock.mark();
            let mut budget = ForkReplayReadBudgetV1::new(limits, start, &mut clock)?;
            assert_eq!(
                store.read_fork_replay_lineage_node(child, 0, 2, &mut budget),
                Err(expected)
            );
            // A denied target copies no native carrier. A denied ancestor
            // follows one actual Fork carrier plus its internal parent ID:
            // Memory metadata49 + visitedID16 + parentID16; SQLite also
            // copies key26, rawID26 and rawParent26. Freshness rows are scratch.
            let prefix = if ancestor { expected_ancestor_bytes } else { 0 };
            assert_eq!(budget.remaining_native_bytes(), 1_024 - prefix);
            // A native gate denial is not a failed ledger debit. Keep the
            // closed error distinct from resource/time exhaustion.
            budget.check_time()?;
            store.finish_protected_effect_interval(
                interval,
                ErasureProtectedEffectDispositionV1::Rollback,
            )?;
        }
    }
    Ok(())
}

#[test]
fn real_native_gate_denials_keep_both_closed_mappings_on_both_adapters() -> TestResult {
    native_gate_denials(|| Ok(MemoryStore::new()), 49 + 16 + 16)?;
    native_gate_denials(|| Ok(SqliteStore::open(":memory:")?), 3 * 26 + 49 + 16 + 16)
}
