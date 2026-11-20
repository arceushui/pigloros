//! ADR-136 acceptance matrix, slice C6a (#1469): the runtime gaps of
//! acceptance tests 2 to 6 at the public host seam.
//!
//! Every test runs over both `MemoryStore` and `SQLite` unless its doc names
//! why it cannot: a `SQLite` close and reopen, the recipient-export catalog
//! that Memory does not have, or the held `SQLite` reader that is the one
//! transient negative. `docs/erasure/adr-136-acceptance-matrix.md` maps
//! every ADR-136 bullet to its test.

use super::*;

use pos_core::store::{import_timeline_with_id, TimelineExport};
use pos_runtime::LOCAL_ERASURE_AUTO_RETRY_MAX_V1;

/// The committed head of `request`.
fn head_state(
    host: &mut ErasureExecutionHostV1,
    request: ErasureReferenceV1,
) -> TestResult<pos_core::ErasureStateV1> {
    Ok(host
        .read_sender()?
        .erasure_state(request)?
        .ok_or("request missing")?
        .state()
        .clone())
}

/// Submit request 1 for `scope` and drive it until its freeze commits.
fn frozen_request(host: &mut ErasureExecutionHostV1, scope: ErasureScopeV1) -> TestResult {
    submitted(host, 1, scope)?;
    let steps = driven_steps(host, |step| *step == LocalErasureStepV1::Frozen)?;
    assert_eq!(steps.last(), Some(&LocalErasureStepV1::Frozen));
    Ok(())
}

// ---------------------------------------------------------------------------
// Acceptance test 2: the C1′ partition.
// ---------------------------------------------------------------------------

/// The Timelines a partition seed adds beside the driver fixture's.
struct Seeded {
    /// The other actor's root, holding one Event of the actor.
    other: TimelineId,
    /// An unowned root.
    unowned: TimelineId,
    /// Imports of a Timeline the actor owns, of one the other actor owns
    /// and of an unowned one, each from another store, keeping its
    /// identity and owner.
    imported: Imported,
}

/// The identity-preserving imports of a partition seed.
struct Imported {
    own: TimelineId,
    other: TimelineId,
    unowned: TimelineId,
}

/// The host-made Timelines of the partition.
struct Forks {
    /// A Fork of the actor's owned root: whoever forks it, it inherits the
    /// actor as owner.
    of_owned: TimelineId,
    /// The actor's Fork of the other actor's root, which inherits that
    /// actor as owner.
    of_other: TimelineId,
    /// A host-owned root opened as the Gateway opens its Consent Timeline.
    consent: TimelineId,
}

/// An Event of the actor.
fn actor_event() -> pos_core::EventDraft {
    pos_core::EventDraft::new(
        actor(),
        pos_core::Kind::new("acceptance.actor.event"),
        CanonicalBytes::from_static(b"actor-in-another-timeline"),
    )
}

/// The identity-preserving export of a root Timeline that `owner` owns on
/// another store, holding one Event of the actor.
fn export_of(owner: Option<EntityId>) -> TestResult<TimelineExport> {
    let mut source = MemoryStore::new();
    source.bind_erasure_gate(Arc::new(ErasureContainmentGateV1::new_test_open()))?;
    let meta = TimelineMeta {
        owner,
        ..TimelineMeta::root("exported")
    };
    let timeline = source.create_timeline_with_meta(meta)?.id();
    source.append(timeline, &[actor_event()])?;
    Ok(TimelineExport {
        timeline: source
            .get_timeline(timeline)?
            .ok_or("no exported Timeline")?,
        events: source.read(timeline, pos_core::SeqRange::all())?,
        parent_fork_hash: None,
    })
}

/// Import the export of a Timeline `owner` owns, keeping its identity and
/// owner (owner decision of 2026-11-20: ownership follows the data).
fn import_owned_by(store: &mut dyn SeedStore, owner: Option<EntityId>) -> TestResult<TimelineId> {
    let timeline = import_timeline_with_id(&mut *store, export_of(owner)?)?;
    assert_eq!(timeline.meta.owner, owner);
    Ok(timeline.id())
}

/// Seed the partition beside the driver fixture's content.
///
/// It adds the other actor's root with an Event of the actor, an unowned
/// root, the three imports, the other actor's role-0 key and a role-7 key
/// under the actor's own subject owner.
fn seed_partition(store: &mut dyn SeedStore) -> TestResult<Seeded> {
    let other = owned_roots_on(store, other_actor(), 1)?[0];
    store.append(other, &[actor_event()])?;
    let unowned = store
        .create_timeline_with_meta(TimelineMeta::root("unowned"))?
        .id();
    let imported = Imported {
        own: import_owned_by(store, Some(actor()))?,
        other: import_owned_by(store, Some(other_actor()))?,
        unowned: import_owned_by(store, None)?,
    };
    let mut registry = store.load_key_registry()?.ok_or("no key registry")?;
    let own_role_7 = KeyIdentityV1::from_parts(
        subject_key(1)?.owner_id,
        KeyRoleV1::CommunityArtifactEncryption,
        1,
    );
    for (identity, material) in [
        (subject_key_of(other_actor(), 1)?, 0x82),
        (own_role_7, 0x83),
    ] {
        registry
            .register_key(KeyRegistrationV1::new(
                identity,
                Hash::from_bytes([material; 32]),
                None,
            ))
            .map_err(fail)?;
    }
    store.save_key_registry(&registry)?;
    Ok(Seeded {
        other,
        unowned,
        imported,
    })
}

/// Fork the actor's root and the other actor's root on the host, and open
/// a host-owned root, before any request exists.
fn forked(host: &mut ErasureExecutionHostV1, seeded: &Seeded) -> TestResult<Forks> {
    let mut sender = host.command_sender()?;
    let of_owned = sender.fork_timeline(memory_owned_timeline(), Seq::ZERO, "another-actor")?;
    let of_other = sender.fork_timeline(seeded.other, Seq::ZERO, "the-actor")?;
    let consent = sender.open_root_timeline(
        TimelineId::from_ulid(Ulid::from_bytes([0x8c; 16])),
        "pigloros.local-principal.consents",
    )?;
    assert_eq!(of_owned.meta.owner, Some(actor()));
    assert_eq!(of_other.meta.owner, Some(other_actor()));
    assert_eq!(consent.meta.owner, None);
    Ok(Forks {
        of_owned: of_owned.id(),
        of_other: of_other.id(),
        consent: consent.id(),
    })
}

/// Request 1 is frozen over exactly the actor's lineage.
///
/// That is the actor's root, its Fork and the import the actor owns. The
/// closure is the store target, their payloads and the actor's own role-0
/// key: neither the other subject's key nor the role-7 key. Every other
/// Timeline stays readable.
fn assert_partition(
    host: &mut ErasureExecutionHostV1,
    seeded: &Seeded,
    forks: &Forks,
) -> TestResult {
    let verified = host
        .read_sender()?
        .erasure_state(request_of(1)?)?
        .ok_or("request missing")?;
    assert_eq!(verified.lifecycle(), ErasureLifecycleV1::AccessFrozen);
    let scope = verified.scope().ok_or("no committed scope")?;
    let mut affected = vec![memory_owned_timeline(), forks.of_owned, seeded.imported.own];
    affected.sort_unstable();
    assert_eq!(scope.scope_timeline_ids(), affected.as_slice());
    let mut targets = vec![store_target()?, subject_key_cells()?[0].0];
    for timeline in &affected {
        targets.push(payload_cell(*timeline)?.0);
    }
    targets.sort_unstable();
    assert_eq!(scope.target_closure(), target_closure_digest(&targets));
    let open = [
        seeded.other,
        seeded.unowned,
        seeded.imported.other,
        seeded.imported.unowned,
        forks.of_other,
        forks.consent,
        erasure_host_timeline()?,
    ];
    let mut reads = host.read_sender()?;
    for timeline in affected {
        assert_eq!(
            reads.timeline(timeline).map(drop),
            Err(ErasureHostErrorV1::AccessFrozen)
        );
    }
    for timeline in open {
        assert!(reads.timeline(timeline)?.is_some(), "{timeline:?}");
    }
    Ok(())
}

/// Create a root the actor owns after the freeze, and a Fork of it.
fn late_lineage(host: &mut ErasureExecutionHostV1) -> TestResult<[TimelineId; 2]> {
    let mut sender = host.command_sender()?;
    let root = sender.create_owned_timeline("late-root", actor())?;
    let fork = sender.fork_timeline(root.id(), Seq::ZERO, "late-fork")?;
    assert_eq!(fork.meta.owner, Some(actor()));
    Ok([root.id(), fork.id()])
}

/// The actor's Event in `other` is still there, unchanged.
fn assert_actor_event_kept(host: &mut ErasureExecutionHostV1, other: TimelineId) -> TestResult {
    let events = host.read_sender()?.read_bounded(
        other,
        pos_core::SeqRange::all(),
        pos_core::EventReadBounds::new(64, 64, 4, 4),
    )?;
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].entity, actor());
    assert_eq!(events[0].payload.as_slice(), b"actor-in-another-timeline");
    Ok(())
}

/// Acceptance test 2 (C1′), on both adapters: the freeze selects exactly
/// the actor's lineage.
///
/// Affected: the actor's root, a Fork of it made on the host for another
/// actor, and an imported Timeline the actor owns (owner decision of
/// 2026-11-20: ownership follows the data). Unaffected: another actor's
/// root and the actor's Fork of it, an unowned root, imports of another
/// owner's and of an unowned Timeline, and a host-owned root. The positive
/// proof holds after a restart (`SQLite`; a Memory store has no close and
/// reopen). A root the actor creates after the freeze, and its Fork, stay
/// unaffected for the request. The actor's Event in the other actor's
/// Timeline stays out of scope, and the receipt discloses the retained
/// Timeline payloads (ELD1 of `timeline-payload`).
#[test]
fn the_c1_partition_freezes_exactly_the_actors_lineage() -> TestResult {
    for adapter in ADAPTERS {
        let (mut fixture, seeded) = Fixture::new(adapter, seed_partition)?;
        let forks = forked(&mut fixture.host, &seeded)?;
        frozen_request(&mut fixture.host, ErasureScopeV1::PrivateSubjectData)?;
        assert_partition(&mut fixture.host, &seeded, &forks)?;
        fixture = fixture.restarted()?;
        assert_partition(&mut fixture.host, &seeded, &forks)?;
        let late = late_lineage(&mut fixture.host)?;
        assert_partition(&mut fixture.host, &seeded, &forks)?;
        let receipt = finalized(driver().drive(&mut fixture.host, request_of(1)?)?)?;
        assert_eq!(receipt.lifecycle(), ErasureLifecycleV1::PartialFailure);
        assert_evaluated_rows(&receipt)?;
        assert_eq!(
            receipt
                .inventories()
                .artifacts
                .iter()
                .filter(|row| class_of(row.transition.owner).ok() == Some("timeline-payload"))
                .count(),
            3
        );
        assert_actor_event_kept(&mut fixture.host, seeded.other)?;
        let mut reads = fixture.host.read_sender()?;
        for timeline in late {
            assert!(reads.timeline(timeline)?.is_some(), "{adapter:?}");
        }
    }
    Ok(())
}

/// Acceptance test 2, on both adapters: a Fork admitted after the freeze
/// is the first ERSE1 of the frozen scope.
///
/// The runtime host admits it while the scope has no extension yet; the
/// extension still verifies after a restart (`SQLite`). The Gateway's Fork
/// admission service is C6b.
#[test]
fn a_fork_admitted_after_freeze_is_the_first_extension_of_the_frozen_scope() -> TestResult {
    for adapter in ADAPTERS {
        let mut fixture = Fixture::plain(adapter)?;
        let request = request_of(1)?;
        frozen_request(&mut fixture.host, ErasureScopeV1::PrivateSubjectData)?;
        let extensions = |host: &mut ErasureExecutionHostV1| -> TestResult<Vec<TimelineId>> {
            Ok(host
                .read_sender()?
                .erasure_state(request)?
                .ok_or("request missing")?
                .scope_extensions()
                .iter()
                .map(ErasureScopeExtensionV1::child_timeline)
                .collect())
        };
        assert!(extensions(&mut fixture.host)?.is_empty());
        let child = fixture
            .host
            .command_sender()?
            .fork_timeline_identified(
                reference(0x46),
                memory_owned_timeline(),
                Seq::ZERO,
                "first-extension",
            )?
            .id();
        assert_eq!(extensions(&mut fixture.host)?, [child]);
        fixture = fixture.restarted()?;
        assert_eq!(extensions(&mut fixture.host)?, [child]);
        assert_frozen(
            &mut fixture.host,
            &[memory_owned_timeline(), child],
            erasure_host_timeline()?,
        )?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Acceptance test 3: key binding and recipient exports (`SQLite` only:
// Memory has no recipient-export catalog).
// ---------------------------------------------------------------------------

/// Acceptance test 3 (`SQLite` only: the recipient-export catalog): the
/// actor's erasure destroys its own role-0 subject key and no other.
///
/// Another subject's role-0 key and the actor's own role-4 recipient key
/// survive, and the actor still decrypts an export another subject granted
/// it.
#[test]
fn the_actors_recipient_key_survives_its_erasure_and_still_decrypts_a_grant() -> TestResult {
    let store = driver_store()?;
    let other = store.owned_roots(other_actor(), 1)?[0];
    store.register(KeyRegistrationV1::new(
        subject_key_of(other_actor(), 1)?,
        Hash::from_bytes([0x82; 32]),
        None,
    ))?;
    let (_custody, private) = custody_directory()?;
    let owner = pos_store::sqlite::RecipientKeyOwnerV1::open(&private, actor())?;
    let (export_id, recipient) = publish_export_as(&store, other, other_actor(), actor(), &owner)?;
    let receipt = {
        let mut host = store.host(&driver_case()?, 4_096)?;
        submitted(&mut host, 1, ErasureScopeV1::PrivateSubjectData)?;
        finalized(driver().drive(&mut host, request_of(1)?)?)?
    };
    let subject = pos_core::local_erasure_key_digest_v1(&subject_key(1)?)?;
    assert!(!receipt.inventories().keys.is_empty());
    assert!(receipt
        .inventories()
        .keys
        .iter()
        .all(|row| row.target.key_digest == subject));
    let sqlite = store.sqlite()?;
    let registry = sqlite.load_key_registry()?.ok_or("no key registry")?;
    assert!(registry.tombstone(subject_key(1)?).is_some());
    assert!(registry
        .tombstone(subject_key_of(other_actor(), 1)?)
        .is_none());
    let encoded = sqlite
        .read_recipient_export(&owner, export_id)
        .map_err(fail)?;
    sqlite
        .decrypt_recipient_export(&owner, &encoded, export_id, recipient)
        .map(drop)
        .map_err(fail)?;
    Ok(())
}

/// Acceptance test 3: one negative `export-recipient` obligation per
/// grantee of an affected Timeline's exports.
///
/// `SQLite` only: Memory has no recipient-export catalog.
#[test]
fn each_export_grantee_is_one_negative_export_recipient_obligation() -> TestResult {
    let store = driver_store()?;
    let grantees = [
        other_actor(),
        EntityId::from_ulid(Ulid::from_bytes([0x7c; 16])),
    ];
    let mut expected = Vec::new();
    for grantee in grantees {
        let export_id = publish_export(&store, memory_owned_timeline(), grantee)?;
        let owner = pos_core::recipient_owner_id_from_grantee(grantee).map_err(fail)?;
        expected.push(pos_core::local_erasure_export_recipient_v1(
            export_id, &owner,
        )?);
    }
    expected.sort_unstable();
    let mut host = store.host(&driver_case()?, 4_096)?;
    submitted(&mut host, 1, ErasureScopeV1::ConsentedSharedData)?;
    let receipt = finalized(driver().drive(&mut host, request_of(1)?)?)?;
    assert_eq!(receipt.lifecycle(), ErasureLifecycleV1::PartialFailure);
    let export_owner = pos_core::local_erasure_owner_ref_v1(
        ErasureReferenceV1::from_digest(STORE_IDENTITY),
        0,
        "export-recipient",
    )?;
    let exports = receipt
        .acknowledgements()
        .iter()
        .filter(|acknowledgement| acknowledgement.owner == export_owner)
        .collect::<Vec<_>>();
    assert!(exports.iter().all(
        |acknowledgement| acknowledgement.outcome == ErasureAcknowledgementOutcomeV1::Negative
    ));
    let mut targets = exports
        .iter()
        .map(|acknowledgement| acknowledgement.target.artifact_digest)
        .collect::<Vec<_>>();
    targets.sort_unstable();
    assert_eq!(targets, expected);
    Ok(())
}

// ---------------------------------------------------------------------------
// Acceptance test 3b: the closure bound at freeze, and test 5: its
// rejection and the exact retry.
// ---------------------------------------------------------------------------

/// Acceptance tests 3b and 5, on both adapters: a closure that outgrows
/// its bound after submission commits `Rejected(ScopeInvalid)` at freeze.
///
/// At exactly 4,096 targets the freeze needs a signature. Past the bound
/// the ERS1 provenance is the freeze failure `ScopeInvalid` under the
/// request's ERAZ1. An exact retry of the freeze reproduces it, and it
/// survives a restart (`SQLite`).
#[test]
fn a_closure_that_outgrows_its_bound_commits_scope_invalid_at_freeze() -> TestResult {
    for adapter in ADAPTERS {
        // The fixture's closure is the store target, the owned root's
        // payload and the role-0 key: 4,093 more owned roots fill the
        // 4,096-target bound exactly.
        let (mut fixture, roots) =
            Fixture::new(adapter, |store| owned_roots_on(store, actor(), 4_093))?;
        let request = request_of(1)?;
        submitted(&mut fixture.host, 1, ErasureScopeV1::PrivateSubjectData)?;
        assert_eq!(
            driver().step(&mut fixture.host, request)?,
            LocalErasureStepV1::Authorized
        );
        assert!(matches!(
            fixture
                .host
                .command_sender()?
                .prepare_local_freeze(request)?,
            LocalFreezePreparationV1::Sign(_)
        ));
        fixture
            .host
            .command_sender()?
            .fork_timeline(roots[0], Seq::ZERO, "growth")?;
        assert_eq!(
            driver().drive(&mut fixture.host, request)?,
            LocalErasureStepV1::FreezeRejected
        );
        let eraz1 = authorization(1, fixture.head)?.reference()?;
        let failure =
            pos_core::ErasureFreezeFailureV1::new(pos_core::ErasureFreezeFailureInputV1 {
                request,
                error: ErasureErrorV1::ScopeInvalid,
                authorization_provenance: eraz1,
                evidence: eraz1,
            })?;
        let committed = head_state(&mut fixture.host, request)?;
        assert_eq!(committed.lifecycle(), ErasureLifecycleV1::Rejected);
        assert_eq!(committed.provenance(), failure.reference());
        assert_eq!(
            fixture
                .host
                .command_sender()?
                .freeze_access(request, &freeze(eraz1))?,
            committed
        );
        assert_eq!(
            driver().step(&mut fixture.host, request)?,
            LocalErasureStepV1::Idle
        );
        fixture = fixture.restarted()?;
        assert_eq!(head_state(&mut fixture.host, request)?, committed);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Acceptance test 4: the retry cap and reordered acknowledgements.
// ---------------------------------------------------------------------------

/// Acceptance test 4: the retry cap ends a transient failure in
/// `partial-failure`.
///
/// `SQLite` only: the held reader is the one transient negative, and a
/// Memory replica is the permanent one. When attempt 0 and all
/// `auto_retry_max` retries time out, no further attempt is due, even once
/// the store is free again and after a restart.
#[test]
fn the_retry_cap_ends_a_transient_failure_in_partial_failure() -> TestResult {
    let store = driver_store()?;
    let request = request_of(1)?;
    let mut host = store.host(&driver_case()?, 4_096)?;
    submitted(&mut host, 1, ErasureScopeV1::ConsentedSharedData)?;
    let receipts = held_attempts(&store, &mut host, LOCAL_ERASURE_AUTO_RETRY_MAX_V1 + 1)?;
    assert_eq!(
        u64::try_from(receipts.len())?,
        LOCAL_ERASURE_AUTO_RETRY_MAX_V1 + 1
    );
    assert_eq!(driver().step(&mut host, request)?, LocalErasureStepV1::Idle);
    assert_eq!(driver().run(&mut host)?, 0);
    assert_eq!(
        lifecycle(&mut host, request)?,
        ErasureLifecycleV1::PartialFailure
    );
    drop(host);
    let mut host = store.host(&driver_case()?, 4_096)?;
    assert_eq!(driver().step(&mut host, request)?, LocalErasureStepV1::Idle);
    assert_eq!(
        lifecycle(&mut host, request)?,
        ErasureLifecycleV1::PartialFailure
    );
    Ok(())
}

/// The receipt of request 1 with its Artifact acknowledgements reordered.
///
/// Drive it through its dispatch and the key's acknowledgement, then run
/// and acknowledge its two Artifact commands in the reverse of the
/// driver's outbox order, through the Local executor, signer and authority,
/// each twice when `duplicated`; then drive it to its receipt.
fn reordered_receipt(
    host: &mut ErasureExecutionHostV1,
    duplicated: bool,
) -> TestResult<ErasureReceiptV1> {
    let request = request_of(1)?;
    let steps = driven_steps(host, |step| {
        matches!(step, LocalErasureStepV1::Acknowledged(_))
    })?;
    assert!(matches!(
        steps.last(),
        Some(LocalErasureStepV1::Acknowledged(_))
    ));
    let mut artifacts = host
        .command_sender()?
        .dispatched_owner_commands(request)?
        .into_iter()
        .filter(|command| command.destruction.category == ErasureInventoryCategoryV1::Artifact)
        .collect::<Vec<_>>();
    assert_eq!(artifacts.len(), 2);
    assert_ne!(
        artifacts[0].destruction.obligation,
        artifacts[1].destruction.obligation
    );
    // The driver runs the first command of this outbox order
    // (`LocalErasureDriverV1::attempt`), so the reverse is another order.
    artifacts.reverse();
    let signer = signer_of(erasure_signer(), 1);
    let mut acknowledgements = Vec::new();
    for command in &artifacts {
        let result = executor().execute(command, host).map_err(fail)?;
        let evidence = signer.sign(
            host,
            LocalErasureSigningRequestV1::OwnerResult {
                owner_result: result.owner_result(),
            },
        )?;
        let outcome = if result.error().is_some() {
            ErasureAcknowledgementOutcomeV1::Negative
        } else {
            ErasureAcknowledgementOutcomeV1::Acknowledged
        };
        let destruction = command.destruction;
        let acknowledgement = ErasureAcknowledgementV1 {
            obligation: destruction.obligation,
            target: destruction.target,
            owner: destruction.owner,
            evidence,
            outcome,
        };
        host.command_sender()?
            .acknowledge_erasure(request, acknowledgement)?;
        acknowledgements.push(acknowledgement);
    }
    if duplicated {
        for acknowledgement in acknowledgements {
            host.command_sender()?
                .acknowledge_erasure(request, acknowledgement)?;
        }
    }
    finalized(driver().drive(host, request)?)
}

/// Acceptance test 4, on both adapters: reordered or duplicated
/// acknowledgements give the receipt bytes of the driver's own run.
#[test]
fn reordered_or_duplicated_acknowledgements_give_identical_receipt_bytes() -> TestResult {
    for adapter in ADAPTERS {
        let (straight, _) = straight_fixture_run(adapter)?;
        // Reordered only, then reordered and duplicated.
        for duplicated in [false, true] {
            let mut fixture = Fixture::plain(adapter)?;
            submitted(&mut fixture.host, 1, ErasureScopeV1::PrivateSubjectData)?;
            let reordered = reordered_receipt(&mut fixture.host, duplicated)?;
            assert_eq!(
                reordered.to_canonical_cbor()?,
                straight.to_canonical_cbor()?,
                "{adapter:?} duplicated={duplicated}"
            );
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Acceptance test 6: an expired TPS1, and the TPS1 key-id codec.
// ---------------------------------------------------------------------------

/// Acceptance test 6: an expired TPS1 refuses a freeze, while a request
/// frozen before the expiry still verifies, is projected and completes.
///
/// `SQLite` only: a new clock needs a close and reopen.
#[test]
fn an_expired_tps1_refuses_a_freeze_but_a_frozen_request_still_completes() -> TestResult {
    let mut expired = driver_case()?;
    expired.clock = after_trust_expiry;
    let request = request_of(1)?;
    let (authorized, _) = driven_until(|step| *step == LocalErasureStepV1::Authorized)?;
    let mut host = authorized.host(&expired, 4_096)?;
    // The freeze step prepares before it signs: `prepare_freeze` refuses
    // first in `admits_new_work` (`TrustSnapshotInvalid`), which the host
    // maps to `RecoveryUnavailable`, so the signer is never reached.
    assert_eq!(
        driver().step(&mut host, request),
        Err(ErasureHostErrorV1::RecoveryUnavailable)
    );
    let projected = projection(&mut host, actor(), 1)?.ok_or("no projection")?;
    assert_eq!(projected.state.lifecycle(), ErasureLifecycleV1::Authorized);
    drop(host);
    let (frozen, _) = driven_until(|step| *step == LocalErasureStepV1::Frozen)?;
    let mut host = frozen.host(&expired, 4_096)?;
    let projected = projection(&mut host, actor(), 1)?.ok_or("no projection")?;
    assert_eq!(
        projected.state.lifecycle(),
        ErasureLifecycleV1::AccessFrozen
    );
    let receipt = finalized(driver().drive(&mut host, request)?)?;
    assert_eq!(receipt.lifecycle(), ErasureLifecycleV1::PartialFailure);
    assert_eq!(receipt.issue_position(), LOCAL_ERASURE_ATTEMPT_WINDOW_V1);
    Ok(())
}

/// `bytes` with the one occurrence of `from` respelled as `to`, a text of
/// the same length.
fn respelled(bytes: &[u8], from: &str, to: &str) -> TestResult<Vec<u8>> {
    assert_eq!(from.len(), to.len());
    let at = bytes
        .windows(from.len())
        .position(|window| window == from.as_bytes())
        .ok_or("no occurrence")?;
    let mut respelled = bytes.to_vec();
    respelled[at..at + to.len()].copy_from_slice(to.as_bytes());
    Ok(respelled)
}

/// Acceptance test 6: the erasure key ids round-trip through the TPS1
/// codec.
///
/// They are an `erasure-bundle/` root and an `erasure-signer/<64 hex>`
/// revocation. Their colon forms are refused on encode and on decode.
#[test]
fn erasure_key_ids_round_trip_through_the_tps1_codec() -> TestResult {
    use pos_conformance::TrustPolicySnapshotContractErrorV1::FieldOutOfBounds;

    let signer = bundle().signer_key_id;
    assert_eq!(signer.len(), "erasure-signer/".len() + 64);
    assert!(signer.starts_with(pos_core::ERASURE_SIGNER_KEY_PREFIX_V1));
    let snapshot = signed_snapshot(&operator(), &[signer.as_str()])?;
    let bytes = snapshot.to_canonical_cbor()?;
    let decoded = TrustPolicySnapshotV1::from_canonical_cbor(&bytes)?;
    assert_eq!(decoded, snapshot);
    assert_eq!(decoded.trust_roots[0].key_id, BUNDLE_ROOT);
    assert_eq!(decoded.revoked_key_ids, [signer.as_str()]);
    let colon_root = BUNDLE_ROOT.replacen('/', ":", 1);
    let colon_signer = signer.replacen('/', ":", 1);
    let mut encoded_root = snapshot.clone();
    colon_root.clone_into(&mut encoded_root.trust_roots[0].key_id);
    assert_eq!(
        encoded_root.to_canonical_cbor().map(drop),
        Err(FieldOutOfBounds)
    );
    let mut encoded_signer = snapshot;
    encoded_signer.revoked_key_ids = vec![colon_signer.clone()];
    assert_eq!(
        encoded_signer.to_canonical_cbor().map(drop),
        Err(FieldOutOfBounds)
    );
    for (from, to) in [
        (BUNDLE_ROOT, colon_root.as_str()),
        (signer.as_str(), colon_signer.as_str()),
    ] {
        assert_eq!(
            TrustPolicySnapshotV1::from_canonical_cbor(&respelled(&bytes, from, to)?).map(drop),
            Err(FieldOutOfBounds)
        );
    }
    Ok(())
}
