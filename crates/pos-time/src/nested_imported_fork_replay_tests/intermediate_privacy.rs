//! Late geographic hiding beyond a signed ordinary intermediate's inherited cut.
//!
//! Only leaves import code-2 authority. Ordinary intermediates retain verified
//! signed own segments; a later normal admission never changes an imported leaf.
//! The parent module calls this from its one serial matrix test so the shared
//! fold counter remains isolated.

use super::*;

fn intermediate_privacy_world() -> Fallible<World> {
    let mut world = World::new(Shape::Mixed, false)?;
    world.add_child(Shape::Mixed)?;
    for arm in 0..2 {
        let parent = world.child_at(arm)?.id;
        world.add_child_at(parent, Seq::from_u64(8), Shape::Mixed)?;
    }
    Ok(world)
}

fn populate_intermediate_privacy<S>(
    store: &mut S,
    world: &World,
    destroyed: bool,
    hidden_arm: usize,
) -> Fallible<Vec<ForkReplayRequirementV1>>
where
    S: Port + OwnTracksEnrollmentStore + GeoLocationAdmissionStore,
{
    world.seed_destination(store)?;
    // These are ordinary, signature-verified own segments, not code-2 imports.
    // Their four signed Events extend the signed root prefix from four to eight.
    for arm in 0..2 {
        let parent = world.child_at(arm)?;
        pos_store::import_timeline_verified_v1(store, parent.export.clone(), &world.anchors)?;
        assert_eq!(store.protected_logical_head(parent.id)?, Seq::from_u64(8));
    }
    let mut required = Vec::new();
    for index in 2..4 {
        let child = world.child_at(index)?;
        assert_eq!(child.parent_cut, 8);
        let built = world.build(&import_spec(index, destroyed)?)?;
        pin_policy(store, &built.policy)?;
        store.import_verified(&ForkAttributionAuthorityImportRequestV1 {
            envelope_bytes: &built.bytes,
            expected_issuer_policy_digest: built.policy.digest(),
            parent_timeline_id: child.parent,
            trust_anchors: &world.anchors,
        })?;
        let committed = store.read_committed(child.id, 12)?;
        required.push(ForkReplayRequirementV1::new(
            child.id,
            Seq::from_u64(12),
            committed.record_id,
            committed.authority_origin_digest,
        )?);
    }
    // Only the selected ordinary intermediate changes after both publications.
    // Neither imported leaf receives signing, append or repair authority.
    hide_geographic_member(store, world.child_at(hidden_arm)?.id, 8)?;
    Ok(required)
}

fn intermediate_privacy_verifier(
    world: &World,
    required: &[ForkReplayRequirementV1],
) -> Fallible<Arc<NestedVerifier>> {
    let sources_for = |arm: usize| -> Fallible<Vec<WorldReplayForkSourceV1>> {
        Ok(vec![
            WorldReplayForkSourceV1::new(
                world.child_at(arm + 2)?.id,
                Some(*required.get(arm).ok_or("leaf requirement")?),
            )?,
            WorldReplayForkSourceV1::new(world.child_at(arm)?.id, None)?,
            WorldReplayForkSourceV1::new(world.root, None)?,
        ])
    };
    Ok(Arc::new(NestedVerifier {
        sources: [sources_for(0)?, sources_for(1)?],
        scenario: Mutex::new(None),
        admissions: AtomicUsize::new(0),
    }))
}

fn run_intermediate_privacy_on_host(
    mut host: ErasureExecutionHostV1,
    world: &World,
    verifier: &NestedVerifier,
    hidden_arm: usize,
) -> Fallible<()> {
    let fixture = ProtectedFixture::new("count", count);
    let seed = world
        .source
        .read(world.root, SeqRange::all())?
        .into_iter()
        .next()
        .ok_or("root seed")?;
    for (consumer, visible_control) in [
        (Consumer::Replay, true),
        (Consumer::Replay, false),
        (Consumer::ReplayAtInherited, false),
        (Consumer::ReplayAtOwn, false),
        (Consumer::Compare, false),
    ] {
        let selected = if visible_control {
            1 - hidden_arm
        } else {
            hidden_arm
        };
        *verifier.scenario.lock().map_err(|_| "scenario poisoned")? = Some(Scenario {
            consumer,
            fault: Fault::None,
            target: selected,
        });
        verifier.admissions.store(0, Ordering::SeqCst);
        let mut timelines = verifier
            .sources
            .each_ref()
            .map(|sources| sources[0].timeline_id());
        if !matches!(consumer, Consumer::Compare) && selected == 1 {
            timelines.swap(0, 1);
        }
        let gate = host.containment_gate();
        let generation = Hash::from_bytes(gate.inventory_generation()?.digest());
        let closures = timelines
            .map(|timeline| {
                WorldReplayClosureV1::test_fixture_for_timeline_with_inventory_generation(
                    timeline, generation,
                )
            })
            .into_iter()
            .collect::<Result<Vec<_>, _>>()?;
        let mut a = seeded_registry(&fixture, Arc::clone(&gate), world, timelines[0], &seed)?;
        let mut b = seeded_registry(&fixture, gate, world, timelines[1], &seed)?;
        let before_a = a.state_snapshot(timelines[0])?;
        let before_b = b.state_snapshot(timelines[1])?;
        FOLDED.store(0, Ordering::SeqCst);
        let result = invoke(
            &mut host,
            [&mut a, &mut b],
            [&closures[0], &closures[1]],
            &fixture,
            consumer,
            timelines,
            Seq::from_u64(9),
        );
        if visible_control {
            assert!(result?.is_none());
            assert_eq!(FOLDED.load(Ordering::SeqCst), 12);
            assert_eq!(verifier.admissions.load(Ordering::SeqCst), 2);
            let installed = a.state_snapshot(timelines[0])?;
            assert_eq!(installed["count"].len(), 12);
            assert!(installed["count"]
                .entries()
                .all(|(_, state)| state.get("n") == Some(&serde_json::json!(1))));
        } else {
            assert_eq!(
                result.map(|_| ()).map_err(|error| error.to_string()),
                Err(CoreError::ArtifactUnavailable.to_string()),
            );
            assert_eq!(FOLDED.load(Ordering::SeqCst), 0);
            assert_eq!(verifier.admissions.load(Ordering::SeqCst), 0);
            assert_eq!(a.state_snapshot(timelines[0])?, before_a);
        }
        assert_eq!(b.state_snapshot(timelines[1])?, before_b);
    }
    Ok(())
}

fn intermediate_privacy_sqlite(
    path: &str,
    world: &World,
    verifier: &Arc<NestedVerifier>,
    destroyed: bool,
    hidden_arm: usize,
    also_run_read_only: bool,
) -> Fallible<()> {
    let mut store = SqliteStore::open(path)?;
    let actual = populate_intermediate_privacy(&mut store, world, destroyed, hidden_arm)?;
    let expected: Vec<_> = verifier
        .sources
        .iter()
        .filter_map(|sources| sources[0].required_attribution())
        .collect();
    assert_eq!(actual, expected);
    drop(store);
    let composition =
        ErasureCoordinatorCompositionV1::closed().with_world_replay_verifier(verifier.clone());
    let host = ErasureExecutionHostV1::open_with_authority(
        StoreConfig::Sqlite {
            path: path.to_owned(),
        },
        &composition,
        ErasureRecoveryLimitsV1::compiled_maximum(),
    )?;
    run_intermediate_privacy_on_host(host, world, verifier, hidden_arm)?;
    if also_run_read_only {
        let host = ErasureExecutionHostV1::open_read_only_with_authority(
            path,
            &composition,
            ErasureRecoveryLimitsV1::compiled_maximum(),
        )?;
        run_intermediate_privacy_on_host(host, world, verifier, hidden_arm)?;
    }
    Ok(())
}

pub(super) fn run_cases() -> Fallible<()> {
    let world = intermediate_privacy_world()?;
    for destroyed in [false, true] {
        for hidden_arm in 0..2 {
            let mut memory = MemoryStore::new();
            let required =
                populate_intermediate_privacy(&mut memory, &world, destroyed, hidden_arm)?;
            let verifier = intermediate_privacy_verifier(&world, &required)?;
            let composition = ErasureCoordinatorCompositionV1::closed()
                .with_world_replay_verifier(verifier.clone());
            let host = ErasureExecutionHostV1::recover_memory_fixture_with_authority(
                memory,
                &composition,
                ErasureRecoveryLimitsV1::compiled_maximum(),
            )?;
            run_intermediate_privacy_on_host(host, &world, &verifier, hidden_arm)?;
            let uri = format!(
                "file:pigloros-561-intermediate-{}?mode=memory&cache=shared",
                TimelineId::new(),
            );
            let keeper = SqliteStore::open(&uri)?;
            intermediate_privacy_sqlite(
                &uri,
                &world,
                &verifier,
                destroyed,
                hidden_arm,
                false,
            )?;
            drop(keeper);
            let directory = tempfile::tempdir()?;
            let path = directory.path().join("intermediate-privacy.sqlite");
            intermediate_privacy_sqlite(
                path.to_str().ok_or("utf-8 path")?,
                &world,
                &verifier,
                destroyed,
                hidden_arm,
                true,
            )?;
        }
    }
    Ok(())
}
