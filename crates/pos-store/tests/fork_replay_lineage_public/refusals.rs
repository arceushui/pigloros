//! Complete Event reads refuse every expired native prefix, never a partial batch.

use super::*;

fn event_prefixes<S: ForkReplayAuthorityReadPortV1 + ErasureInventoryPersistencePortV1>(
    store: &S,
    [root, child, _]: [TimelineId; 3],
    sqlite: bool,
) -> TestResult {
    let interval = store.begin_protected_effect_interval()?;
    // Independent literal H/M + ER accounting for this two-segment fixture.
    let bytes = if sqlite {
        93 + 143 + 16 + 3 * 8 + 2 * 148
    } else {
        41 + 65 + 16 + 3 * 8 + 2 * 12
    };
    let rows = if sqlite { 19 } else { 7 };
    let limits = ForkReplayReadLimitsV1::new(1, 2, rows, bytes, 1_000_000)?;
    let mut clock = ScriptedGuardMonotonicSourceV1::new([Duration::ZERO]);
    {
        let start = clock.mark();
        let mut budget = ForkReplayReadBudgetV1::new(limits, start, &mut clock)?;
        let events =
            store.read_fork_replay_events(child, SeqRange::all(), EVENT_BOUNDS, &mut budget)?;
        assert_eq!(events.len(), 2);
        for (event, origin, seq, payload) in [
            (&events[0], root, 1, b"one"),
            (&events[1], child, 2, b"kid"),
        ] {
            assert_eq!(event.seq.as_u64(), seq);
            assert_eq!(event.payload.as_slice(), payload);
            let actual = event.origin.ok_or("committed origin")?;
            assert_eq!(actual.origin_timeline_id, origin);
            assert_eq!(actual.origin_logical_seq.as_u64(), seq);
        }
        assert_eq!(budget.remaining_native_bytes(), 0);
    }
    let samples = clock.samples_taken();
    assert!(samples > 2);
    for prefix in 2..samples {
        let mut clock = ScriptedGuardMonotonicSourceV1::new(
            std::iter::repeat_n(Duration::ZERO, prefix).chain([Duration::from_secs(2)]),
        );
        let start = clock.mark();
        let mut budget = ForkReplayReadBudgetV1::new(limits, start, &mut clock)?;
        assert_eq!(
            store.read_fork_replay_events(child, SeqRange::all(), EVENT_BOUNDS, &mut budget),
            Err(Error::Read(ReadError::BoundsExceeded)),
            "accepted expired Event checkpoint {prefix}/{samples}",
        );
        assert_eq!(budget.check_time(), Err(ReadError::BoundsExceeded));
    }
    for byte_limit in 1..bytes {
        let limits = ForkReplayReadLimitsV1::new(1, 2, rows, byte_limit, 1_000_000)?;
        let mut clock = ScriptedGuardMonotonicSourceV1::new([Duration::ZERO]);
        let start = clock.mark();
        let mut budget = ForkReplayReadBudgetV1::new(limits, start, &mut clock)?;
        assert_eq!(
            store.read_fork_replay_events(child, SeqRange::all(), EVENT_BOUNDS, &mut budget),
            Err(Error::Read(ReadError::BoundsExceeded)),
            "accepted insufficient native bytes {byte_limit}/{bytes}",
        );
        assert_eq!(budget.check_time(), Err(ReadError::BoundsExceeded));
    }
    // Budget refusals neither damage native history nor return partial output.
    fork_event_read_oracles(store, root, child, sqlite)?;
    store.finish_protected_effect_interval(
        interval,
        ErasureProtectedEffectDispositionV1::Rollback,
    )?;
    Ok(())
}

#[test]
fn every_native_event_clock_and_byte_prefix_refuses_on_both_adapters() -> TestResult {
    let mut memory = MemoryStore::new();
    let ids = seed_read_history(&mut memory)?;
    event_prefixes(&memory, ids, false)?;
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("event-prefixes.sqlite");
    let path = path.to_str().ok_or("UTF-8 path")?;
    let mut writer = SqliteStore::open(path)?;
    let ids = seed_read_history(&mut writer)?;
    event_prefixes(&writer, ids, true)?;
    drop(writer);
    let mut reader = SqliteStore::open_read_only(path)?;
    bind(&mut reader)?;
    event_prefixes(&reader, ids, true)
}

fn unavailable_range<S: ForkReplayAuthorityReadPortV1 + ErasureInventoryPersistencePortV1>(
    store: &S,
    root: TimelineId,
) -> TestResult {
    let interval = store.begin_protected_effect_interval()?;
    for (timeline, range) in [
        (root, SeqRange::bounded(Seq::ZERO, Seq::from_u64(3))),
        (TimelineId::new(), SeqRange::all()),
    ] {
        let limits = ForkReplayReadLimitsV1::new(1, 8, 64, 4_096, 1_000_000)?;
        let mut clock = ScriptedGuardMonotonicSourceV1::new([Duration::ZERO]);
        let start = clock.mark();
        let mut budget = ForkReplayReadBudgetV1::new(limits, start, &mut clock)?;
        assert_eq!(
            store.read_fork_replay_events(timeline, range, EVENT_BOUNDS, &mut budget),
            Err(Error::Read(ReadError::Unavailable)),
        );
        budget.check_time()?;
    }
    store.finish_protected_effect_interval(
        interval,
        ErasureProtectedEffectDispositionV1::Rollback,
    )?;
    Ok(())
}

#[test]
fn unavailable_event_ranges_are_not_partial_success_or_budget_refusal() -> TestResult {
    let mut memory = MemoryStore::new();
    let [root, _, _] = seed_read_history(&mut memory)?;
    unavailable_range(&memory, root)?;
    let mut sqlite = SqliteStore::open(":memory:")?;
    let [root, _, _] = seed_read_history(&mut sqlite)?;
    unavailable_range(&sqlite, root)
}

fn inclusive_event_caps<S: ForkReplayAuthorityReadPortV1 + ErasureInventoryPersistencePortV1>(
    store: &S,
    root: TimelineId,
) -> TestResult {
    let interval = store.begin_protected_effect_interval()?;
    for (from, to, maximum, expected) in [
        (1, 1, 0, Err(Error::Read(ReadError::BoundsExceeded))),
        (2, 2, 0, Err(Error::Read(ReadError::BoundsExceeded))),
        (1, 1, 1, Ok(1)),
        (2, 2, 1, Ok(1)),
        (1, 2, 1, Err(Error::Read(ReadError::BoundsExceeded))),
        (3, 1, 0, Ok(0)),
        (4, 1, 0, Ok(0)),
    ] {
        let bounds =
            EventReadBounds::new_with_total_bytes_and_elapsed(3, 1, 1, maximum, 8, 1_000_000);
        let limits = ForkReplayReadLimitsV1::new(1, 8, 64, 4_096, 1_000_000)?;
        let mut clock = ScriptedGuardMonotonicSourceV1::new([Duration::ZERO]);
        let start = clock.mark();
        let mut budget = ForkReplayReadBudgetV1::new(limits, start, &mut clock)?;
        let result = store
            .read_fork_replay_events(
                root,
                SeqRange::bounded(Seq::from_u64(from), Seq::from_u64(to)),
                bounds,
                &mut budget,
            )
            .map(|events| events.len());
        assert_eq!(result, expected, "range={from}..={to}, cap={maximum}");
        assert_eq!(budget.check_time().is_ok(), expected.is_ok());
    }
    store.finish_protected_effect_interval(
        interval,
        ErasureProtectedEffectDispositionV1::Rollback,
    )?;
    Ok(())
}

#[test]
fn event_caps_include_single_event_ranges_and_accept_disjoint_empty_ranges() -> TestResult {
    let mut memory = MemoryStore::new();
    let [root, _, _] = seed_read_history(&mut memory)?;
    inclusive_event_caps(&memory, root)?;
    let mut sqlite = SqliteStore::open(":memory:")?;
    let [root, _, _] = seed_read_history(&mut sqlite)?;
    inclusive_event_caps(&sqlite, root)
}
