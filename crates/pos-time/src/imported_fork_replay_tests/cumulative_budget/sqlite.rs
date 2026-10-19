//! Independent complete `SQLite` Replay/Replay-at/Compare totals.
//!
//! Neither a native cost helper nor a measured ledger supplies these units.

mod compare;

use super::super::{
    fixture::{pin_policy, request_for, Built, Fallible, Shape, Spec, World},
    Fault, ImportedVerifier,
};
use super::exercise;
use pos_core::{
    store::{EventStore, SeqRange},
    ErasureRecoveryLimitsV1, ForkAdmissionRecordV1, ForkAttributionImportClosureV1,
    ImportedForkAttributionAdmissionV1, KeyRegistrationV1, KeyRegistryStateV1, KeyRoleV1, Seq,
};
use pos_runtime::{ErasureCoordinatorCompositionV1, ErasureExecutionHostV1};
use pos_store::{
    sqlite::SqliteStore, ForkAttributionAuthorityImportPortV1, ForkManifestPublicationPortV1,
    ForkReplayReadLimitsV1, ForkReplayRequirementV1, StoreConfig,
};
use std::sync::{atomic::AtomicUsize, Arc};

fn registry_bytes(world: &World) -> Fallible<usize> {
    assert_eq!(world.anchors.len(), 1);
    let (identity, public_key) = world.anchors[0];
    assert_eq!(identity.owner_id.as_str(), "import-owner");
    assert_eq!(identity.role, KeyRoleV1::TimelineIntegritySigning);
    assert_eq!(identity.epoch, 1);
    let record = world
        .registry
        .key_record(identity)
        .ok_or("live registry key")?;
    assert_eq!(record.public_verification_key, Some(public_key));
    let material = record
        .private_material_digest
        .ok_or("live private digest")?;
    let mut expected = KeyRegistryStateV1::new();
    expected.register_key(KeyRegistrationV1::new(identity, material, Some(public_key)))?;
    // Whole-value equality also guards every otherwise-private map, including
    // empty tombstones/pending requests and exactly one active/high-water key.
    assert_eq!(world.registry, expected);
    assert!(world
        .registry
        .committed_destruction_facts()
        .next()
        .is_none());
    assert!(world
        .registry
        .pending_destruction_requests()
        .next()
        .is_none());
    // Pinned ordinary Ciborium representation of ONLY this asserted value:
    // identity=61, active-scope tuple=40, record=187; top map header plus
    // records/active/tombstones/highest_epoch/pending_destructions/version:
    // 1 + 257 + 109 + 12 + 56 + 22 + 9 = 466. No generic encoder is added.
    // ADR-116 native copies: I=2n+1+8, S=2n+1, D=64; 3I+2S+2D+8+1+4n+44.
    let owner = identity.owner_id.as_str().len();
    let identity = 2 * owner + 1 + 8;
    let scope = 2 * owner + 1;
    Ok(466 + 3 * identity + 2 * scope + 2 * 64 + 8 + 1 + 4 * owner + 44)
}

fn final_chain_bytes(world: &World, child_index: usize) -> Fallible<usize> {
    let child = world.child_at(child_index)?;
    assert_eq!(child.parent, world.root);
    assert_eq!(child.parent_cut, 4);
    assert!(world.source.read_own(child.id, SeqRange::all())?.is_empty());
    let events = world.source.read(world.root, SeqRange::all())?;
    assert_eq!(events.len(), 4);
    let mut bytes = 0;
    for event in &events {
        assert_eq!(event.payload.len(), 6);
        assert_eq!(event.event_type.as_str(), "fae1.import.test");
        assert!(event.causation_id.is_none());
        assert!(event.correlation_id.is_none());
        assert!(event.signature.is_some());
        assert_eq!(event.signature_identity, Some(world.anchors[0].0));
        let origin = event.origin.ok_or("root Event origin")?;
        assert_eq!(origin.origin_timeline_id, world.root);
        // Successful SQLite getters: id/entity/kind/payload/hash/signature/
        // signing owner/origin Timeline. Final hash input copies id/payload.
        bytes += event.id.to_string().len()
            + event.entity.to_string().len()
            + event.event_type.as_str().len()
            + event.payload.len()
            + event.payload_hash.as_bytes().len()
            + 64
            + world.anchors[0].0.owner_id.as_str().len()
            + origin.origin_timeline_id.to_string().len()
            + event.id.to_string().len()
            + event.payload.len();
    }
    // Root/child metadata: query keys, visited IDs, retained ID/head/cut and
    // the child's parent String; then one Event-cursor key per segment.
    Ok(bytes + (26 + 2 * 16 + 8) + (26 + 2 * 16 + 2 * 8 + 26) + 2 * 26)
}

fn authority_bytes(
    world: &World,
    built: &Built,
    admission: &ImportedForkAttributionAdmissionV1,
    child_index: usize,
) -> Fallible<usize> {
    let closure = ForkAttributionImportClosureV1::validate(&built.envelope)?;
    assert!(closure.classifier().is_none());
    assert!(closure.append_operations().is_empty());
    assert!(built.envelope.unsigned().input().key_tombstone.is_none());
    let operation = closure.publication_operation();
    let projection = operation.projection();
    assert_eq!(
        projection.input().child_timeline_id,
        world.child_at(child_index)?.id
    );
    assert!(world
        .registry
        .key_record(projection.input().signing_identity)
        .is_none());
    let owner = projection.input().signing_identity.owner_id.as_str().len();
    let projection_fields = 32 + 16 + 8 + 32 + 32 + owner + 1 + 8 + 32 + 32 + 32 + 1;
    let binding = closure.publication_binding().to_canonical_cbor().len();
    let imported_operation = operation.to_canonical_cbor().len();
    let local_operation = projection.to_canonical_cbor().len();
    let signed = closure.signed_manifest();
    assert!(signed.manifest().input().intervention_sequences.is_empty());
    let outer = signed.to_canonical_cbor().len();
    let manifest = signed.manifest_bytes().len();
    let artifact = closure.publication_artifact().to_canonical_cbor().len();
    // Publication probe/fetch/decode: binding raw/equality/native encoding,
    // imported/local FPO buffers and copies, signed artifact nested buffers.
    let publication = 26
        + 3 * binding
        + imported_operation
        + 2 * owner
        + 2 * local_operation
        + projection_fields
        + 1
        + 32
        + 2 * artifact
        + 3 * outer
        + 3 * manifest
        + signed.identity().owner_id.as_str().len();
    let fork = closure.fork_admission();
    let local_fork = ForkAdmissionRecordV1::new(fork.fields().clone())?;
    let issuer = &admission.input().issuer;
    // One admission selection: local/imported query keys; FAR raw/equality/
    // accepted/native buffers and local projections; IFA/FAI nested buffers.
    let admitted = 2 * 26
        + 5 * fork.to_canonical_cbor().len()
        + 2 * local_fork.to_canonical_cbor().len()
        + 2 * fork.fields().creator.as_str().len()
        + 2 * admission.to_canonical_cbor().len()
        + 2 * issuer.to_canonical_cbor().len()
        + issuer.issuer_id().len();
    let key = &built.envelope.unsigned().input().key_record;
    let retained_key = 3 * key.to_canonical_cbor().len() + key.identity().owner_id.as_str().len();
    // Two full admission selections; absent classifier key; five actual empty
    // suffix keys; signed/repro/binding copies; receipt/projection/origin;
    // absent local key fields; registry; final chain; evidence projection,
    // separately retained origin, imported FPO and two digest copies.
    Ok(publication
        + 2 * admitted
        + retained_key
        + 6 * 26
        + 2 * outer
        + 2 * manifest
        + binding
        + (32 + 16 + 8 + 32)
        + projection_fields
        + (1 + 32)
        + (owner + 1 + 8 + 1 + 32 + 1 + 32)
        + registry_bytes(world)?
        + final_chain_bytes(world, child_index)?
        + projection_fields
        + 32
        + imported_operation
        + 2 * 32)
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum SqliteReplayAccess {
    ReadWrite,
    ReadOnly,
    HeldMemory,
}

struct SqliteReplayFixture<'a> {
    world: &'a World,
    built: &'a Built,
    admission: &'a ImportedForkAttributionAdmissionV1,
    unrelated: Option<&'a Built>,
}

fn whole_sqlite_budget(
    fixture: &SqliteReplayFixture<'_>,
    child_index: usize,
    folded_events: usize,
) -> Fallible<(usize, usize, usize)> {
    // Selected child/root walk 284, explicit root walk 125, Runtime link 24.
    let lineage_bytes = 284 + 125 + 24;
    let bytes = 2
        * (authority_bytes(fixture.world, fixture.built, fixture.admission, child_index)?
            + lineage_bytes)
        // Owning fence: native child/root284 + root125, gate IDs32 and
        // parent16. Two head calls each return an additional Seq8. Event
        // H/M repeats284; the one selected root segment reuses one key26.
        + (284 + 125 + 32 + 16) + 2 * (284 + 8) + 284 + 26
        // Raw signed row208 = IDs52 + P6+T16 + hash32 + sig64 + owner12
        // + origin26; ER also retains a cursor8 per selected Event.
        + folded_events * (208 + 8);
    // Per validation: lineage 12 freshness/metadata + 8 Event rows; authority
    // publication6 + FAR/IFA6 + key2 + suffix11 + final chain14 + registry2
    // + absent local-key lookup1. Visits: lineage3 + suffix1 + chain2.
    // Interval setup's actual PRAGMA row is added ONCE by the operation,
    // not per arm: Compare adds two arm values then that one setup row.
    let rows =
        2 * (12 + 8 + 6 + 6 + 2 + 11 + 14 + 2 + 1) + 20 + 2 * 12 + 12 + 2 + 2 * folded_events;
    let visits = 2 * (3 + 1 + 2) + 3 + 3 * 2;
    Ok((bytes, rows, visits))
}

fn sqlite_replay_case(
    access: SqliteReplayAccess,
    fixture: &SqliteReplayFixture<'_>,
    cut: Option<Seq>,
    limits: ForkReplayReadLimitsV1,
    succeeds: bool,
) -> Fallible<()> {
    let world = fixture.world;
    let built = fixture.built;
    let admission = fixture.admission;
    let directory = (access != SqliteReplayAccess::HeldMemory)
        .then(tempfile::tempdir)
        .transpose()?;
    let path = match &directory {
        Some(directory) => directory
            .path()
            .join("imported-budget.sqlite")
            .to_str()
            .ok_or("UTF-8 path")?
            .to_owned(),
        None => format!(
            "file:pigloros-561-cumulative-{}?mode=memory&cache=shared",
            pos_core::TimelineId::new(),
        ),
    };
    // Keep the named database alive across setup-store drop and host recovery.
    // This gate-unbound connection issues no command or transaction while the
    // recovered host owns the protected interval.
    let keeper = if access == SqliteReplayAccess::HeldMemory {
        Some(SqliteStore::open(&path)?)
    } else {
        None
    };
    let mut store = SqliteStore::open(&path)?;
    world.seed_destination(&mut store)?;
    pin_policy(&mut store, &built.policy)?;
    assert_eq!(
        &store.import_verified(&request_for(world, built))?.admission,
        admission
    );
    if let Some(unrelated) = fixture.unrelated {
        pin_policy(&mut store, &unrelated.policy)?;
        store.import_verified(&request_for(world, unrelated))?;
        assert_eq!(
            store
                .read_own(world.child_at(1)?.id, SeqRange::all())?
                .len(),
            4
        );
    }
    let child = world.child_at(0)?.id;
    let committed = store.read_committed(child, 4)?;
    let requirement = ForkReplayRequirementV1::new(
        child,
        Seq::from_u64(4),
        committed.record_id,
        committed.authority_origin_digest,
    )?;
    drop(store);
    let verifier = Arc::new(ImportedVerifier {
        child,
        parent: world.root,
        requirement,
        secondary: None,
        fault: Fault::None,
        fault_target: None,
        limits_override: Some(limits),
        admissions: AtomicUsize::new(0),
    });
    let composition =
        ErasureCoordinatorCompositionV1::closed().with_world_replay_verifier(verifier.clone());
    let recovery = ErasureRecoveryLimitsV1::compiled_maximum();
    let host = if access == SqliteReplayAccess::ReadOnly {
        // The populated schema and empty erasure inventory support direct RO
        // recovery. No preceding writable Runtime host is needed.
        ErasureExecutionHostV1::open_read_only_with_authority(&path, &composition, recovery)?
    } else {
        ErasureExecutionHostV1::open_with_authority(
            StoreConfig::Sqlite { path },
            &composition,
            recovery,
        )?
    };
    exercise(host, world, &verifier, cut, succeeds)?;
    drop(keeper);
    Ok(())
}

fn sqlite_replay_budget_cases(access: SqliteReplayAccess, cut: Option<Seq>) -> Fallible<()> {
    let world = World::new(Shape::EmptyUnclassified, false)?;
    assert_eq!(world.children.len(), 1);
    let built = world.build(&Spec::default())?;
    let admission = ImportedForkAttributionAdmissionV1::from_envelope(&built.envelope, 1)?;
    // Only the staged fold follows the cut. Both validations still read the
    // complete four-Event signed publication, including its inherited prefix.
    let folded_events = usize::try_from(cut.unwrap_or(Seq::from_u64(4)).as_u64())?;
    let fixture = SqliteReplayFixture {
        world: &world,
        built: &built,
        admission: &admission,
        unrelated: None,
    };
    let (bytes, arm_rows, visits) = whole_sqlite_budget(&fixture, 0, folded_events)?;
    let rows = arm_rows + 1;
    assert_eq!((rows, visits), (183 + 2 * folded_events, 21));
    for (bytes, rows, visits, succeeds) in [
        (bytes, rows, visits, true),
        (bytes + 1, rows, visits, true),
        (bytes, rows + 1, visits, true),
        (bytes, rows, visits + 1, true),
        (bytes - 1, rows, visits, false),
        (bytes, rows - 1, visits, false),
        (bytes, rows, visits - 1, false),
    ] {
        sqlite_replay_case(
            access,
            &fixture,
            cut,
            ForkReplayReadLimitsV1::new(8, visits, rows, bytes, 30_000_000)?,
            succeeds,
        )?;
    }
    Ok(())
}

#[test]
fn imported_sqlite_rw_replay_keeps_one_exact_budget_through_final_validation() -> Fallible<()> {
    sqlite_replay_budget_cases(SqliteReplayAccess::ReadWrite, None)
}

#[test]
fn imported_sqlite_ro_replay_keeps_one_exact_budget_through_final_validation() -> Fallible<()> {
    sqlite_replay_budget_cases(SqliteReplayAccess::ReadOnly, None)
}

#[test]
fn imported_sqlite_held_memory_replay_keeps_one_exact_budget_through_final_validation(
) -> Fallible<()> {
    sqlite_replay_budget_cases(SqliteReplayAccess::HeldMemory, None)
}

fn sqlite_replay_at_budget_cases(access: SqliteReplayAccess) -> Fallible<()> {
    for cut in [2, 4] {
        sqlite_replay_budget_cases(access, Some(Seq::from_u64(cut)))?;
    }
    Ok(())
}

#[test]
fn imported_sqlite_rw_replay_at_keeps_full_authority_budget_at_both_cuts() -> Fallible<()> {
    sqlite_replay_at_budget_cases(SqliteReplayAccess::ReadWrite)
}

#[test]
fn imported_sqlite_ro_replay_at_keeps_full_authority_budget_at_both_cuts() -> Fallible<()> {
    sqlite_replay_at_budget_cases(SqliteReplayAccess::ReadOnly)
}

#[test]
fn imported_sqlite_held_memory_replay_at_keeps_full_authority_budget_at_both_cuts() -> Fallible<()>
{
    sqlite_replay_at_budget_cases(SqliteReplayAccess::HeldMemory)
}

#[test]
fn unrelated_valid_fork_preserves_replay_and_replay_at_exact_budgets() -> Fallible<()> {
    let mut world = World::new(Shape::EmptyUnclassified, false)?;
    world.add_child(Shape::Mixed)?;
    let built = world.build(&Spec::default())?;
    let unrelated = world.build(&Spec::distinct(1))?;
    let admission = ImportedForkAttributionAdmissionV1::from_envelope(&built.envelope, 1)?;
    for access in [
        SqliteReplayAccess::ReadWrite,
        SqliteReplayAccess::ReadOnly,
        SqliteReplayAccess::HeldMemory,
    ] {
        for cut in [None, Some(Seq::from_u64(2))] {
            let fixture = SqliteReplayFixture {
                world: &world,
                built: &built,
                admission: &admission,
                unrelated: Some(&unrelated),
            };
            // The existing independent whole-operation oracle is unchanged:
            // foreign Events/EOR/FIA must add no visits, rows or native copies.
            let folded = usize::try_from(cut.unwrap_or(Seq::from_u64(4)).as_u64())?;
            let (bytes, arm_rows, visits) = whole_sqlite_budget(&fixture, 0, folded)?;
            let rows = arm_rows + 1;
            for (bytes, rows, visits, succeeds) in [
                (bytes, rows, visits, true),
                (bytes - 1, rows, visits, false),
                (bytes, rows - 1, visits, false),
                (bytes, rows, visits - 1, false),
            ] {
                sqlite_replay_case(
                    access,
                    &fixture,
                    cut,
                    ForkReplayReadLimitsV1::new(8, visits, rows, bytes, 30_000_000)?,
                    succeeds,
                )?;
            }
        }
    }
    Ok(())
}
