//! Native setup refusal through each public consumer, before any State install.

use super::*;

fn refused_begin(call: ConsumerCall, read_only: bool, denied: Connection) -> Fallible<()> {
    let fixture = ProtectedFixture::new("count", count);
    let mut world = World::new(Shape::Mixed, false)?;
    world.add_child(Shape::EmptyUnclassified)?;
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("refused-begin.sqlite");
    let path = path.to_str().ok_or("fixture path")?;
    let mut seed = SqliteStore::open(path)?;
    let requirements = populate_pair(&mut seed, &world)?;
    let timelines = requirements.map(ForkReplayRequirementV1::child_timeline_id);
    let writer = SqliteStore::open(path)?;
    drop(seed);
    let (verifier, before_keys) = reservation_verifier(writer, &world, requirements, call)?;
    let store = if read_only {
        SqliteStore::open_read_only(path)?
    } else {
        SqliteStore::open(path)?
    };
    let record = Arc::new(Mutex::new(Transcript::default()));
    let armed = Arc::new(AtomicBool::new(false));
    let native_record = Arc::clone(&record);
    let native_armed = Arc::clone(&armed);
    store.observe_interval_transactions_for_test(Arc::new(move |connection, operation| {
        if !native_armed.load(Ordering::SeqCst) {
            return true;
        }
        test_ok(native_record.lock())
            .native
            .push((connection, operation));
        !(connection == denied && operation == TransactionOperation::Begin)
    }))?;
    let composition =
        ErasureCoordinatorCompositionV1::closed().with_world_replay_verifier(verifier.clone());
    let mut host = ErasureExecutionHostV1::recover_sqlite_fixture_with_authority(
        store,
        &composition,
        ErasureRecoveryLimitsV1::compiled_maximum(),
    )?;
    let gate = host.containment_gate();
    let mut a = fixture.registry(gate.clone());
    let mut b = fixture.registry(gate);
    let before = [a.retained_state_for_test(), b.retained_state_for_test()];
    let invocation = Invocation {
        case: Case {
            call,
            boundary: Boundary::Normal,
            cleanup: Cleanup::Clean,
        },
        timelines,
        closures: closures_for(&host, timelines),
        fixture: &fixture,
        record: Arc::clone(&record),
        writer: None,
    };
    armed.store(true, Ordering::SeqCst);
    let result = test_ok(invocation.run(&mut host, [&mut a, &mut b], false));
    assert_eq!(
        result.map(|_| ()).map_err(|error| error.to_string()),
        Err(CoreError::ArtifactUnavailable.to_string()),
    );
    assert_eq!(
        [a.retained_state_for_test(), b.retained_state_for_test()],
        before
    );
    assert_eq!(host.status(), ErasureHostStatusV1::Poisoned);
    assert!(host.read_sender().is_err());
    assert!(host.command_sender().is_err());
    {
        let record = test_ok(record.lock());
        let expected = if denied == Connection::Writer {
            vec![(Connection::Writer, TransactionOperation::Begin)]
        } else {
            vec![
                (Connection::Writer, TransactionOperation::Begin),
                (Connection::Reader, TransactionOperation::Begin),
                (Connection::Writer, TransactionOperation::Rollback),
            ]
        };
        assert_eq!(record.native, expected);
        assert!(!record.phases.contains(&Phase::Installed));
        assert!(!record.phases.contains(&Phase::Staged));
        assert!(record.phases.contains(&Phase::FailureP2));
        drop(record);
    }
    // Check before dropping the failed host: cleanup, not connection teardown,
    // must release the successfully acquired writer when reader BEGIN fails.
    let mut writer = verifier
        .writer
        .lock()
        .map_err(|_| "writer fixture poisoned")?;
    assert_eq!(writer.load_key_registry()?, Some(before_keys));
    writer.save_key_registry(&verifier.next)?;
    assert_eq!(writer.load_key_registry()?, Some(verifier.next.clone()));
    drop(writer);
    Ok(())
}

#[test]
fn begin_refusal_poison_closes_all_consumers_and_releases_partial_acquisition() -> Fallible<()> {
    for call in [
        ConsumerCall::Replay,
        ConsumerCall::ReplayAt,
        ConsumerCall::Compare,
    ] {
        for (read_only, denied) in [
            (false, Connection::Writer),
            (true, Connection::Writer),
            (true, Connection::Reader),
        ] {
            refused_begin(call, read_only, denied)?;
        }
    }
    Ok(())
}
