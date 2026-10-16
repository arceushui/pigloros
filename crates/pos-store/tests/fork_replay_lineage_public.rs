#![cfg_attr(coverage_nightly, feature(coverage_attribute))]
#![cfg(feature = "sqlite")]

//! Independent ADR-117 native-work oracles through the actual public bridge.

use pos_core::{
    trusted_clock::{GuardMonotonicSourceV1, ScriptedGuardMonotonicSourceV1},
    CanonicalBytes, EntityId, ErasureContainmentGateV1, ErasureInventoryPersistencePortV1,
    ErasureProtectedEffectDispositionV1, EventDraft, EventReadBounds, EventStore, Kind, Seq,
    SeqRange, TimelineId,
};
use pos_store::{
    memory::MemoryStore, sqlite::SqliteStore, ForkReplayAuthorityReadErrorV1 as ReadError,
    ForkReplayAuthorityReadPortV1, ForkReplayLineageReadErrorV1 as Error, ForkReplayReadBudgetV1,
    ForkReplayReadLimitsV1,
};
use std::{sync::Arc, time::Duration};

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[path = "fork_replay_lineage_public/refusals.rs"]
mod refusals;

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

/// Independent ADR-118 H/M head oracles. The returned Seq costs8 in addition
/// to the existing root25/Fork49 carriers, actual raw SQL buffers and history.
fn head_limits<
    S: EventStore + ForkReplayAuthorityReadPortV1 + ErasureInventoryPersistencePortV1,
>(
    store: &S,
    root: TimelineId,
    child: TimelineId,
    sqlite: bool,
) -> TestResult {
    let root_native = if sqlite { 26 + 26 + 25 + 16 } else { 25 + 16 };
    let fork_native = if sqlite {
        26 + 26 + 26 + 49 + 16
    } else {
        49 + 16
    };
    let interval = store.begin_protected_effect_interval()?;
    for (timeline, bytes, rows, visits) in [
        (root, root_native + 8, if sqlite { 4 } else { 1 }, 1),
        (
            child,
            root_native + fork_native + 16 + 8,
            if sqlite { 8 } else { 2 },
            2,
        ),
    ] {
        for repeats in [1, 2] {
            let (bytes, rows, visits) = (bytes * repeats, rows * repeats, visits * repeats);
            for (bytes_limit, rows_limit, visits_limit, succeeds) in [
                (bytes, rows, visits, true),
                (bytes + 1, rows + 1, visits + 1, true),
                (bytes - 1, rows, visits, false),
                (bytes, rows - 1, visits, false),
                (bytes, rows, visits - 1, false),
            ] {
                let limits = ForkReplayReadLimitsV1::new(
                    8,
                    visits_limit,
                    rows_limit,
                    bytes_limit,
                    1_000_000,
                );
                if rows_limit == 0 || visits_limit == 0 {
                    assert_eq!(limits, Err(ReadError::BoundsExceeded));
                    continue;
                }
                let mut clock = ScriptedGuardMonotonicSourceV1::new([Duration::ZERO]);
                let start = clock.mark();
                let mut budget = ForkReplayReadBudgetV1::new(limits?, start, &mut clock)?;
                let mut result = Ok(Seq::ZERO);
                for _ in 0..repeats {
                    result = store.fork_replay_logical_head(timeline, 1, &mut budget);
                    if result.is_err() {
                        break;
                    }
                }
                if succeeds {
                    assert_eq!(result?, Seq::ZERO);
                    assert_eq!(budget.remaining_native_bytes(), bytes_limit - bytes);
                } else {
                    assert_eq!(result, Err(Error::Read(ReadError::BoundsExceeded)));
                    assert_eq!(
                        store.fork_replay_logical_head(root, 1, &mut budget),
                        Err(Error::Read(ReadError::BoundsExceeded))
                    );
                }
            }
        }
    }
    store.finish_protected_effect_interval(
        interval,
        ErasureProtectedEffectDispositionV1::Rollback,
    )?;
    Ok(())
}

#[test]
fn guarded_logical_heads_charge_literal_native_work_and_each_repetition() -> TestResult {
    let mut memory = MemoryStore::new();
    let (root, child) = seed_empty(&mut memory)?;
    head_limits(&memory, root, child, false)?;
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("head-ledger.sqlite");
    let path = path.to_str().ok_or("utf-8 path")?;
    let mut writer = SqliteStore::open(path)?;
    let (root, child) = seed_empty(&mut writer)?;
    head_limits(&writer, root, child, true)?;
    drop(writer);
    let mut readonly = SqliteStore::open_read_only(path)?;
    bind(&mut readonly)?;
    head_limits(&readonly, root, child, true)?;
    Ok(())
}

fn interval_units<S: ForkReplayAuthorityReadPortV1 + ErasureInventoryPersistencePortV1>(
    store: &S,
    sqlite: bool,
) -> TestResult {
    let limits = ForkReplayReadLimitsV1::new(8, 1, 1, 1, 1_000_000)?;
    let mut clock = ScriptedGuardMonotonicSourceV1::new([Duration::ZERO]);
    let start = clock.mark();
    let mut budget = ForkReplayReadBudgetV1::new(limits, start, &mut clock)?;
    let owned = store.begin_fork_replay_read_interval(&mut budget)?;
    let joined = store.begin_fork_replay_read_interval(&mut budget)?;
    assert_eq!(joined, pos_core::ErasureProtectedEffectIntervalV1::Unowned);
    assert_eq!(budget.remaining_native_bytes(), 1);
    assert_eq!(budget.charge_rows(1).is_err(), sqlite);
    // The refused ledger cannot prevent inert owned reader/writer cleanup.
    store
        .finish_protected_effect_interval(joined, ErasureProtectedEffectDispositionV1::Rollback)?;
    store.finish_protected_effect_interval(owned, ErasureProtectedEffectDispositionV1::Rollback)?;
    let next = store.begin_protected_effect_interval()?;
    assert_eq!(
        next == pos_core::ErasureProtectedEffectIntervalV1::Owned,
        sqlite
    );
    store.finish_protected_effect_interval(next, ErasureProtectedEffectDispositionV1::Rollback)?;
    Ok(())
}

#[test]
fn contextual_interval_setup_charges_only_its_actual_scalar_row() -> TestResult {
    let mut memory = MemoryStore::new();
    bind(&mut memory)?;
    interval_units(&memory, false)?;
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("interval-ledger.sqlite");
    let path = path.to_str().ok_or("utf-8 path")?;
    let mut writer = SqliteStore::open(path)?;
    bind(&mut writer)?;
    interval_units(&writer, true)?;
    drop(writer);
    let mut readonly = SqliteStore::open_read_only(path)?;
    bind(&mut readonly)?;
    interval_units(&readonly, true)?;
    Ok(())
}

const EVENT_BOUNDS: EventReadBounds =
    EventReadBounds::new_with_total_bytes_and_elapsed(3, 1, 1, 2, 8, 1_000_000);

/// Three-byte payloads and a one-byte kind make the independent ER oracle
/// explicit: Memory `8+P+T=12` per selected Event; `SQLite` 26 per selected segment
/// plus8+110+P+T=122 per Event. All visibility candidates still cost8 each.
fn seed_read_history(
    store: &mut impl EventStore,
) -> Result<[TimelineId; 3], Box<dyn std::error::Error>> {
    bind(store)?;
    let root = store.create_timeline("Event read root")?.id();
    let draft = |payload| EventDraft::new(EntityId::new(), Kind::new("x"), payload);
    drop(store.append(root, &[draft(CanonicalBytes::from_static(b"one"))])?);
    let child = store.fork(root, Seq::from_u64(1), "Event read child")?.id();
    drop(store.append(root, &[draft(CanonicalBytes::from_static(b"two"))])?);
    drop(store.append(child, &[draft(CanonicalBytes::from_static(b"kid"))])?);
    let empty = store.create_timeline("Event read empty")?.id();
    Ok([root, child, empty])
}

fn event_read_case<S: ForkReplayAuthorityReadPortV1>(
    store: &S,
    timeline: TimelineId,
    range: SeqRange,
    units: (usize, usize, usize),
    expected: &[(TimelineId, u64, &[u8])],
) -> TestResult {
    for repeats in [1, 2] {
        let (bytes, rows, visits) = (units.0 * repeats, units.1 * repeats, units.2 * repeats);
        for (byte_limit, row_limit, visit_limit, succeeds) in [
            (bytes, rows, visits, true),
            (bytes + 1, rows + 1, visits + 1, true),
            (bytes - 1, rows, visits, false),
            (bytes, rows - 1, visits, false),
            (bytes, rows, visits - 1, false),
        ] {
            let limits =
                ForkReplayReadLimitsV1::new(1, visit_limit, row_limit, byte_limit, 1_000_000);
            if visit_limit == 0 || row_limit == 0 {
                assert_eq!(limits, Err(ReadError::BoundsExceeded));
                continue;
            }
            let mut clock = ScriptedGuardMonotonicSourceV1::new([Duration::ZERO]);
            let start = clock.mark();
            let mut budget = ForkReplayReadBudgetV1::new(limits?, start, &mut clock)?;
            let mut failed = false;
            for _ in 0..repeats {
                let mut result =
                    store.read_fork_replay_events(timeline, range, EVENT_BOUNDS, &mut budget);
                if let Ok(events) = result.as_mut() {
                    let first = range.from.as_u64().max(1);
                    assert_eq!(events.len(), expected.len());
                    for (index, (event, (origin, origin_seq, payload))) in
                        events.iter().zip(expected).enumerate()
                    {
                        assert_eq!(event.seq.as_u64(), first + u64::try_from(index)?);
                        assert_eq!(event.event_type.as_str(), "x");
                        assert_eq!(event.payload.as_slice(), *payload);
                        let actual = event.origin.ok_or("missing committed Event origin")?;
                        assert_eq!(actual.origin_timeline_id, *origin);
                        assert_eq!(actual.origin_logical_seq.as_u64(), *origin_seq);
                    }
                    // Public scrub success proves the returned payloads are
                    // owned, not shared handles into persistent Store state.
                    assert!(pos_core::store::zeroize_event_plaintext_staging(events));
                }
                if result.is_err() {
                    failed = true;
                    assert!(!succeeds);
                    assert_eq!(result, Err(Error::Read(ReadError::BoundsExceeded)));
                    assert_eq!(budget.check_time(), Err(ReadError::BoundsExceeded));
                    assert_eq!(
                        store.read_fork_replay_events(timeline, range, EVENT_BOUNDS, &mut budget),
                        Err(Error::Read(ReadError::BoundsExceeded))
                    );
                    break;
                }
            }
            assert_eq!(failed, !succeeds);
            if succeeds {
                assert_eq!(budget.remaining_native_bytes(), byte_limit - bytes);
                budget.check_time()?;
            }
        }
    }
    Ok(())
}

fn root_event_read_oracles<S: ForkReplayAuthorityReadPortV1>(
    store: &S,
    root: TimelineId,
    empty: TimelineId,
    sqlite: bool,
) -> TestResult {
    // H/M: root93/41 + two visibility cursors; child143/65 + one
    // visibility cursor + continuation16 + that root. No head-return Seq8
    // belongs to this Event method. Bound SQLite has F entry/completion
    // per member and selected segment; ER contributes two real rows/Event.
    let root_native = if sqlite { 93 + 2 * 8 } else { 41 + 2 * 8 };
    let one = [(root, 1, b"one".as_slice())];
    let two = [(root, 1, b"one".as_slice()), (root, 2, b"two".as_slice())];
    let cases = [
        (
            empty,
            SeqRange::all(),
            if sqlite { (93, 4, 1) } else { (41, 1, 1) },
            &[][..],
        ),
        (
            root,
            SeqRange::bounded(Seq::ZERO, Seq::ZERO),
            (root_native, if sqlite { 6 } else { 3 }, 1),
            &[][..],
        ),
        (
            root,
            SeqRange::bounded(Seq::ZERO, Seq::from_u64(1)),
            (
                root_native + if sqlite { 148 } else { 12 },
                if sqlite { 10 } else { 4 },
                1,
            ),
            &one[..],
        ),
        (
            root,
            SeqRange::all(),
            (
                root_native + if sqlite { 26 + 2 * 122 } else { 2 * 12 },
                if sqlite { 12 } else { 5 },
                1,
            ),
            &two[..],
        ),
    ];
    for (timeline, range, units, expected) in cases {
        event_read_case(store, timeline, range, units, expected)?;
    }
    Ok(())
}

fn fork_event_read_oracles<S: ForkReplayAuthorityReadPortV1>(
    store: &S,
    root: TimelineId,
    child: TimelineId,
    sqlite: bool,
) -> TestResult {
    let chain_native = if sqlite {
        93 + 143 + 16 + 3 * 8
    } else {
        41 + 65 + 16 + 3 * 8
    };
    let one = [(root, 1, b"one".as_slice())];
    let fork = [(root, 1, b"one".as_slice()), (child, 2, b"kid".as_slice())];
    let cases = [
        (
            child,
            SeqRange::all(),
            (
                chain_native + if sqlite { 2 * 148 } else { 2 * 12 },
                if sqlite { 19 } else { 7 },
                2,
            ),
            &fork[..],
        ),
        (
            child,
            SeqRange::bounded(Seq::ZERO, Seq::from_u64(1)),
            (
                chain_native + if sqlite { 148 } else { 12 },
                if sqlite { 15 } else { 6 },
                2,
            ),
            &one[..],
        ),
        (
            child,
            SeqRange::from_seq(Seq::from_u64(2)),
            (
                chain_native + if sqlite { 148 } else { 12 },
                if sqlite { 15 } else { 6 },
                2,
            ),
            &fork[1..],
        ),
    ];
    for (timeline, range, units, expected) in cases {
        event_read_case(store, timeline, range, units, expected)?;
    }
    Ok(())
}

fn event_read_oracles<S: ForkReplayAuthorityReadPortV1 + ErasureInventoryPersistencePortV1>(
    store: &S,
    [root, child, empty]: [TimelineId; 3],
    sqlite: bool,
) -> TestResult {
    let interval = store.begin_protected_effect_interval()?;
    root_event_read_oracles(store, root, empty, sqlite)?;
    fork_event_read_oracles(store, root, child, sqlite)?;
    store.finish_protected_effect_interval(
        interval,
        ErasureProtectedEffectDispositionV1::Rollback,
    )?;
    Ok(())
}

#[test]
fn complete_event_reads_charge_literal_full_visibility_and_only_selected_segments() -> TestResult {
    let mut memory = MemoryStore::new();
    let ids = seed_read_history(&mut memory)?;
    event_read_oracles(&memory, ids, false)?;
    let mut named = SqliteStore::open(":memory:")?;
    let ids = seed_read_history(&mut named)?;
    event_read_oracles(&named, ids, true)?;
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("complete-event-ledger.sqlite");
    let path = path.to_str().ok_or("utf-8 path")?;
    let mut writer = SqliteStore::open(path)?;
    let ids = seed_read_history(&mut writer)?;
    event_read_oracles(&writer, ids, true)?;
    drop(writer);
    let mut readonly = SqliteStore::open_read_only(path)?;
    bind(&mut readonly)?;
    event_read_oracles(&readonly, ids, true)
}

fn per_read_event_bounds<S: ForkReplayAuthorityReadPortV1 + ErasureInventoryPersistencePortV1>(
    store: &S,
    child: TimelineId,
) -> TestResult {
    let interval = store.begin_protected_effect_interval()?;
    for bounds in [
        EventReadBounds::new_with_total_bytes_and_elapsed(2, 1, 1, 2, 8, 1_000_000),
        EventReadBounds::new_with_total_bytes_and_elapsed(3, 0, 1, 2, 8, 1_000_000),
        EventReadBounds::new_with_total_bytes_and_elapsed(3, 1, 0, 2, 8, 1_000_000),
        EventReadBounds::new_with_total_bytes_and_elapsed(3, 1, 1, 1, 8, 1_000_000),
        EventReadBounds::new_with_total_bytes_and_elapsed(3, 1, 1, 2, 7, 1_000_000),
        EventReadBounds::new_with_total_bytes_and_elapsed(3, 1, 1, 2, 8, 0),
    ] {
        let limits = ForkReplayReadLimitsV1::new(8, 32, 256, 16_384, 1_000_000)?;
        let mut clock = ScriptedGuardMonotonicSourceV1::new([Duration::ZERO]);
        let start = clock.mark();
        let mut budget = ForkReplayReadBudgetV1::new(limits, start, &mut clock)?;
        assert_eq!(
            store.read_fork_replay_events(child, SeqRange::all(), bounds, &mut budget),
            Err(Error::Read(ReadError::BoundsExceeded))
        );
        assert_eq!(
            store.read_fork_replay_events(child, SeqRange::all(), EVENT_BOUNDS, &mut budget),
            Err(Error::Read(ReadError::BoundsExceeded))
        );
    }
    store.finish_protected_effect_interval(
        interval,
        ErasureProtectedEffectDispositionV1::Rollback,
    )?;
    Ok(())
}

#[test]
fn event_read_envelopes_are_additional_to_the_shared_operation_budget() -> TestResult {
    let mut memory = MemoryStore::new();
    let [_, child, _] = seed_read_history(&mut memory)?;
    per_read_event_bounds(&memory, child)?;
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("event-read-envelope.sqlite");
    let path = path.to_str().ok_or("utf-8 path")?;
    let mut writer = SqliteStore::open(path)?;
    let [_, child, _] = seed_read_history(&mut writer)?;
    per_read_event_bounds(&writer, child)?;
    drop(writer);
    let mut readonly = SqliteStore::open_read_only(path)?;
    bind(&mut readonly)?;
    per_read_event_bounds(&readonly, child)
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
    assert_eq!(
        store.fork_replay_logical_head(missing, 0, &mut budget),
        Err(Error::Read(ReadError::StorageUnavailable))
    );
    assert_eq!(budget.remaining_native_bytes(), 42);
    budget.check_time()?;
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
