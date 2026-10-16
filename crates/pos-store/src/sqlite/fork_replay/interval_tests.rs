//! Partial acquisition must leave no reservation owned by a refused read.

use super::*;
use pos_core::{
    trusted_clock::{GuardMonotonicSourceV1, ScriptedGuardMonotonicSourceV1},
    ErasureContainmentGateV1, ErasureInventoryPersistencePortV1,
    ErasureProtectedEffectDispositionV1, EventStore,
};
use std::{sync::Arc, time::Duration};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn assert_released(store: &SqliteStore) -> TestResult {
    assert!(store.conn.is_autocommit());
    if let Some(writer) = &store.writer_reservation_connection {
        assert!(writer.is_autocommit());
    }
    // The same native connections remain usable, not merely closed by Drop.
    let interval = store.begin_protected_effect_interval()?;
    assert_eq!(interval, ErasureProtectedEffectIntervalV1::Owned);
    store.finish_protected_effect_interval(
        interval,
        ErasureProtectedEffectDispositionV1::Rollback,
    )?;
    Ok(())
}

fn expiry_at_each_acquisition_checkpoint(store: &SqliteStore) -> TestResult {
    let limits = crate::ForkReplayReadLimitsV1::new(1, 1, 1, 1, 1_000_000)?;
    let mut clock = ScriptedGuardMonotonicSourceV1::new([Duration::ZERO]);
    {
        let start = clock.mark();
        let mut budget = ForkReplayReadBudgetV1::new(limits, start, &mut clock)?;
        let interval = store.begin_fork_replay_read_interval(&mut budget)?;
        assert_eq!(interval, ErasureProtectedEffectIntervalV1::Owned);
        assert_eq!(budget.remaining_native_bytes(), 1);
        store.finish_protected_effect_interval(
            interval,
            ErasureProtectedEffectDispositionV1::Rollback,
        )?;
    }
    let samples = clock.samples_taken();
    assert!(samples > 2);
    // The positive control enumerates checkpoints, not the success oracle.
    // Every proper prefix must refuse; no larger elapsed allowance is used.
    for prefix in 2..samples {
        let mut clock = ScriptedGuardMonotonicSourceV1::new(
            std::iter::repeat_n(Duration::ZERO, prefix).chain([Duration::from_secs(2)]),
        );
        let start = clock.mark();
        let mut budget = ForkReplayReadBudgetV1::new(limits, start, &mut clock)?;
        assert_eq!(
            store.begin_fork_replay_read_interval(&mut budget),
            Err(crate::ForkReplayLineageReadErrorV1::Read(
                Error::BoundsExceeded
            )),
            "accepted expired acquisition checkpoint {prefix}/{samples}",
        );
        assert_eq!(budget.check_time(), Err(Error::BoundsExceeded));
        assert_released(store)?;
    }
    Ok(())
}

#[test]
fn acquisition_expiry_releases_only_owned_resources_on_both_sqlite_modes() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("acquisition-expiry.sqlite");
    let path = path.to_str().ok_or("UTF-8 path")?;
    let mut writer = SqliteStore::open(path)?;
    writer.bind_erasure_gate(Arc::new(ErasureContainmentGateV1::new_test_open()))?;
    expiry_at_each_acquisition_checkpoint(&writer)?;
    drop(writer);
    let mut reader = SqliteStore::open_read_only(path)?;
    reader.bind_erasure_gate(Arc::new(ErasureContainmentGateV1::new_test_open()))?;
    expiry_at_each_acquisition_checkpoint(&reader)
}

#[test]
fn acquisition_does_not_rollback_a_preexisting_reader_transaction() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("preexisting-reader.sqlite");
    let path = path.to_str().ok_or("UTF-8 path")?;
    drop(SqliteStore::open(path)?);
    let reader = SqliteStore::open_read_only(path)?;
    reader.conn.execute_batch("BEGIN DEFERRED")?;
    let mut clock = ScriptedGuardMonotonicSourceV1::new([Duration::ZERO]);
    let start = clock.mark();
    let limits = crate::ForkReplayReadLimitsV1::new(1, 1, 1, 1, 1_000_000)?;
    let mut budget = ForkReplayReadBudgetV1::new(limits, start, &mut clock)?;
    assert_eq!(
        reader.begin_fork_replay_read_interval(&mut budget),
        Err(INTERVAL_STORAGE_ERROR),
    );
    assert!(!reader.conn.is_autocommit());
    assert!(reader
        .writer_reservation_connection
        .as_ref()
        .ok_or("writer reservation")?
        .is_autocommit());
    reader.conn.execute_batch("ROLLBACK")?;
    assert_released(&reader)
}
