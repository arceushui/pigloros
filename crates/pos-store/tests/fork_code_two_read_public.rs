#![cfg(feature = "sqlite")]

//! Public adapter-parity evidence for the ADR-105 r6 R6.9 code-2 trusted
//! reads and the R6.10 escalation barrier, each on `MemoryStore` and
//! file-backed `SqliteStore`.
//!
//! An imported Fork is readable through `read_fork_event_suffix` and
//! publication `read_committed` (validator b), while every issuance and write
//! path keeps the local-only validator (a). The tamper matrix runs on
//! `SQLite` through raw edits; the `MemoryStore` matrix needs private state
//! and lives beside its adapter.

#[path = "support/fae1_fixture.rs"]
pub mod fixture;

use std::cell::Cell;

use fixture::{
    attribution_identity, attribution_material, gateway_source, hash, open_session, pin_policy,
    Built, Fallible, Port, Shape, Spec, World, GATEWAY_REGISTRAR, PARENT_CUT,
};
use pos_core::{
    store::{EventStore, SeqRange},
    ForkAppendSourceIdentityV1, ForkAttributionImportClosureV1, ForkClassifierSourceInputV1,
    ForkClassifierSourceV1, ForkEventSourceDescriptorV1, ImportedForkAttributionAdmissionV1,
    ImportedForkPublicationOperationV1, ImportedKeyRecordV1, PublicKey, Signature, TimelineId,
};
use pos_store::{
    memory::MemoryStore, sqlite::SqliteStore, ForkAttributionAuthorityImportReceiptV1 as Receipt,
    ForkAttributionAuthorityImportRequestV1 as Request, ForkEventAuthorityErrorV1,
    ForkEventProvenanceAuthorityPortV1, ForkManifestPublicationErrorV1,
    ForkManifestPublicationPortV1, ForkManifestPublicationRequestV1,
};

/// One scenario that runs unchanged against each adapter.
trait Scenario {
    fn run<S: Port>(&self, store: &mut S) -> Fallible<()>;
}

/// Run one scenario against `MemoryStore` and file-backed `SqliteStore`.
fn on_both_adapters(scenario: &impl Scenario) -> Fallible<()> {
    scenario.run(&mut MemoryStore::new())?;
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("code-two-read.sqlite");
    let mut sqlite = SqliteStore::open(path.to_str().ok_or("utf-8 path")?)?;
    scenario.run(&mut sqlite)
}

fn request<'a>(world: &'a World, built: &'a Built) -> Request<'a> {
    fixture::request_for(world, built)
}

/// Seed the destination parent, install the admitting policy, and import. The
/// destination's live registry holds no attribution key: the publication read
/// takes the retained key from the stored `IKR1` (ADR-105 erratum E12).
fn imported<S: Port>(store: &mut S, world: &World, built: &Built) -> Fallible<Receipt> {
    world.seed_destination(store)?;
    pin_policy(store, &built.policy)?;
    Ok(store.import_verified(&request(world, built))?)
}

fn external_route_a() -> Fallible<ForkAppendSourceIdentityV1> {
    Ok(ForkAppendSourceIdentityV1::ExternalInput {
        adapter_identifier: "adapter-a".to_owned(),
        source: ForkEventSourceDescriptorV1::new("route-a", hash(0x51))?,
    })
}

/// Every read of a complete import, which must all accept it.
fn assert_reads_accept<S: Port>(
    store: &S,
    world: &World,
    shape: Shape,
    origin: pos_core::Hash,
) -> Fallible<()> {
    let child = world.child_at(0)?.id;
    let head = PARENT_CUT + shape.events();
    let suffix = store.read_fork_event_suffix(child, PARENT_CUT + 1)?;
    assert_eq!(u64::try_from(suffix.len())?, shape.events());
    let committed = store.read_committed(child, head)?;
    assert_eq!(committed.authority_origin_digest, Some(origin));
    assert_eq!(committed.receipt.child_timeline_id, child);
    assert_eq!(committed.receipt.final_logical_head, head);
    assert_eq!(committed.operation.input().child_timeline_id, child);
    Ok(())
}

struct Reads<'a> {
    world: &'a World,
    built: &'a Built,
    shape: Shape,
}

impl Scenario for Reads<'_> {
    fn run<S: Port>(&self, store: &mut S) -> Fallible<()> {
        let receipt = imported(store, self.world, self.built)?;
        let origin = receipt.admission.input().authority_origin_digest;
        assert_reads_accept(store, self.world, self.shape, origin)?;
        // A read writes nothing: the exact retry still returns the receipt.
        assert_eq!(
            store.import_verified(&request(self.world, self.built))?,
            receipt
        );
        assert_reads_accept(store, self.world, self.shape, origin)
    }
}

#[test]
fn a_complete_import_passes_every_code_two_read() -> Fallible<()> {
    for shape in [
        Shape::Mixed,
        Shape::EmptyClassified,
        Shape::EmptyUnclassified,
    ] {
        let world = World::new(shape, false)?;
        let built = world.build(&Spec::default())?;
        on_both_adapters(&Reads {
            world: &world,
            built: &built,
            shape,
        })?;
    }
    Ok(())
}

struct MixedSuffix<'a> {
    world: &'a World,
    built: &'a Built,
}

impl Scenario for MixedSuffix<'_> {
    fn run<S: Port>(&self, store: &mut S) -> Fallible<()> {
        imported(store, self.world, self.built)?;
        let child = self.world.child_at(0)?.id;
        let suffix = store.read_fork_event_suffix(child, PARENT_CUT + 1)?;
        // Events 3 and 4 are the `(1,1)` interventions of the mixed segment.
        let interventions = suffix
            .iter()
            .filter(|(_, intervention, _)| intervention.is_some())
            .count();
        assert_eq!(interventions, 2);
        let later = store.read_fork_event_suffix(child, PARENT_CUT + 3)?;
        assert_eq!(later.len(), 2);
        assert_eq!(
            store.read_fork_event_suffix(child, PARENT_CUT + 5)?.len(),
            0
        );
        Ok(())
    }
}

#[test]
fn the_suffix_read_keeps_the_classification_and_the_requested_start() -> Fallible<()> {
    let world = World::new(Shape::Mixed, false)?;
    let built = world.build(&Spec::default())?;
    on_both_adapters(&MixedSuffix {
        world: &world,
        built: &built,
    })
}

struct Barrier<'a> {
    world: &'a World,
    built: &'a Built,
    shape: Shape,
}

impl Barrier<'_> {
    /// The publication request that reaches the provenance sources.
    fn request(&self, head: u64) -> Fallible<ForkManifestPublicationRequestV1> {
        let material = attribution_material();
        Ok(ForkManifestPublicationRequestV1 {
            operation_id: hash(0xc1),
            child_timeline_id: self.world.child_at(0)?.id,
            expected_final_logical_head: head,
            signing_identity: attribution_identity("creator-a", 1),
            private_material_digest: material.material_digest(),
            public_verification_key: material.public_verification_key(),
            expected_registry: self
                .world
                .registry_with_attribution_key("creator-a", 0x71)?,
        })
    }

    /// Every local authority path that must refuse the imported child, run
    /// against a destination that already holds the import.
    ///
    /// The live registry gets the creator's key first, only so that
    /// publication issuance passes registry authorization and reaches the
    /// provenance sources, where validator (a) refuses it.
    fn refusals<S: Port>(&self, store: &mut S) -> Fallible<()> {
        store.save_key_registry(
            &self
                .world
                .registry_with_attribution_key("creator-a", 0x71)?,
        )?;
        let admission = ImportedForkAttributionAdmissionV1::from_envelope(&self.built.envelope, 1)?;
        let origin = admission.input().authority_origin_digest;
        let child = self.world.child_at(0)?.id;
        let head = PARENT_CUT + self.shape.events();
        let before = store.read_own(child, SeqRange::all())?;
        // The destination's activation profile (FCP1) selects this FCS1. The
        // profile is configuration for the read-only preflight, not a stored
        // row. The imported FCS1 is byte-equal to it; with the classifier
        // triple null (`EmptyUnclassified`) nothing is imported, so that
        // equality is vacuous for that shape and only the refusals count.
        let fcs1 = gateway_source()?;
        let closure = ForkAttributionImportClosureV1::validate(&self.built.envelope)?;
        let imported_source = closure.classifier().map(|graph| graph.source.clone());
        assert_eq!(
            imported_source.is_some(),
            self.shape != Shape::EmptyUnclassified
        );
        assert!(imported_source.is_none_or(|source| source == fcs1));
        store.preflight_fork_classifier_profile(std::slice::from_ref(&fcs1))?;
        // A live adapter scope for one of its routes.
        let mut session = open_session(store)?;
        let mut issuer = session.take_event_permit_issuer().ok_or("no issuer")?;
        issuer.trust_external_source(external_route_a()?);
        let corrupt = Some(ForkEventAuthorityErrorV1::CorruptAuthority);
        assert_eq!(
            store
                .issue_classifier_registrar_permit(&issuer, &session, child, fcs1.clone())
                .err(),
            corrupt
        );
        for source in [
            external_route_a()?,
            ForkAppendSourceIdentityV1::HostInternal,
        ] {
            assert_eq!(
                store
                    .issue_append_source_permit(&issuer, &session, child, &fcs1, source)
                    .err(),
                corrupt
            );
        }
        assert_eq!(
            store.read_validated_local_fork_admission(child).err(),
            corrupt
        );
        // Publication issuance is refused, and its signer never runs.
        let signed = Cell::new(false);
        let mut refused = |request| {
            store.commit_authorized(request, |_, _| {
                signed.set(true);
                Err::<Signature, &str>("the signer must not run")
            })
        };
        // `head + 1` reaches the provenance sources, where validator (a)
        // refuses the code-2 FAR1.
        assert_eq!(
            refused(self.request(head + 1)?),
            Err(ForkManifestPublicationErrorV1::CorruptAuthority)
        );
        // The import holds the binding at `head`, so this is the occupancy
        // preflight's conflict, not validator (a); it also refuses.
        assert_eq!(
            refused(self.request(head)?),
            Err(ForkManifestPublicationErrorV1::Conflict)
        );
        assert!(!signed.get());
        // Read (b) still accepts the import, and nothing about it changed.
        assert_reads_accept(store, self.world, self.shape, origin)?;
        assert_eq!(store.read_own(child, SeqRange::all())?, before);
        Ok(())
    }
}

impl Scenario for Barrier<'_> {
    fn run<S: Port>(&self, store: &mut S) -> Fallible<()> {
        imported(store, self.world, self.built)?;
        self.refusals(store)
    }
}

#[test]
fn an_imported_fcs1_equal_to_the_local_classifier_profile_grants_no_local_authority() -> Fallible<()>
{
    for shape in [
        Shape::Mixed,
        Shape::EmptyClassified,
        Shape::EmptyUnclassified,
    ] {
        let world = World::new(shape, false)?;
        let built = world.build(&Spec {
            registrar: GATEWAY_REGISTRAR,
            ..Spec::default()
        })?;
        on_both_adapters(&Barrier {
            world: &world,
            built: &built,
            shape,
        })?;
    }
    Ok(())
}

/// Reopen a file-backed store. A write by another connection makes a live
/// store fail closed, so every raw edit happens between two handles.
fn reopen(path: &str) -> Fallible<SqliteStore> {
    let mut store = SqliteStore::open(path)?;
    store.bind_erasure_gate(std::sync::Arc::new(
        pos_core::ErasureContainmentGateV1::new_test_open(),
    ))?;
    Ok(store)
}

/// One raw `SQLite` edit with its optional blob parameter and the two read
/// results it must produce: the suffix read, then the publication read.
struct Tamper {
    name: &'static str,
    sql: &'static str,
    blob: Option<Vec<u8>>,
    suffix: Option<ForkEventAuthorityErrorV1>,
    /// The closed errors the publication read may report; every one refuses.
    publication: &'static [ForkManifestPublicationErrorV1],
}

/// An edit that both reads must refuse.
const fn refused_by_both(name: &'static str, sql: &'static str, blob: Option<Vec<u8>>) -> Tamper {
    Tamper {
        name,
        sql,
        blob,
        suffix: Some(ForkEventAuthorityErrorV1::CorruptAuthority),
        publication: &[ForkManifestPublicationErrorV1::PublicationConflict],
    }
}

/// An edit of a stored imported Event: the suffix read refuses it as corrupt
/// authority, and the publication read also refuses the broken chain it
/// recomputes, as a conflict or as an unreadable storage row.
const fn event_tamper(name: &'static str, sql: &'static str) -> Tamper {
    Tamper {
        name,
        sql,
        blob: None,
        suffix: Some(ForkEventAuthorityErrorV1::CorruptAuthority),
        publication: &[
            ForkManifestPublicationErrorV1::PublicationConflict,
            ForkManifestPublicationErrorV1::StorageIndeterminate,
        ],
    }
}

/// An edit of the stored retained key or its selection: only the publication
/// read consults it (ADR-105 erratum E12), and it refuses it as a conflict.
const fn publication_tamper(
    name: &'static str,
    sql: &'static str,
    blob: Option<Vec<u8>>,
) -> Tamper {
    Tamper {
        name,
        sql,
        blob,
        suffix: None,
        publication: &[ForkManifestPublicationErrorV1::PublicationConflict],
    }
}

/// The edits of the retained key evidence and of its selection.
fn retained_key_tampers() -> Fallible<Vec<Tamper>> {
    let other_key = ImportedKeyRecordV1::new(
        attribution_identity("creator-a", 1),
        Some(hash(0x77)),
        PublicKey::from_bytes([0x78; 32]),
    )?;
    Ok(vec![
        publication_tamper(
            "missing retained key evidence",
            "DELETE FROM imported_fork_key_evidence",
            None,
        ),
        publication_tamper(
            "undecodable IKR1",
            "UPDATE imported_fork_key_evidence SET ikr1_cbor = x'00'",
            None,
        ),
        publication_tamper(
            "IKR1 naming another key than the FPO1",
            "UPDATE imported_fork_key_evidence SET ikr1_cbor = ?1",
            Some(other_key.to_canonical_cbor()),
        ),
        Tamper {
            name: "unreadable IKR1 column",
            sql: "UPDATE imported_fork_key_evidence SET ikr1_cbor = 'text'",
            blob: None,
            suffix: None,
            publication: &[ForkManifestPublicationErrorV1::StorageIndeterminate],
        },
        publication_tamper(
            "import admission with another full-envelope digest than the evidence",
            "UPDATE imported_fork_attribution_admissions SET full_envelope_digest = randomblob(32)",
            None,
        ),
    ])
}

/// The tampers of one committed mixed import.
fn tampers(
    admission: &ImportedForkAttributionAdmissionV1,
    closure: &ForkAttributionImportClosureV1,
) -> Fallible<Vec<Tamper>> {
    let mut origin = admission.input().clone();
    origin.authority_origin_digest = hash(0x99);
    let mut fork_digest = admission.input().clone();
    fork_digest.fork_admission_digest = hash(0x98);
    let other_source = ForkClassifierSourceV1::new(ForkClassifierSourceInputV1 {
        room_revision_descriptor_hash: hash(0x41),
        registrar_identifier: "other-registrar".to_owned(),
        routes: vec![],
    })?;
    let publication = closure.publication_operation();
    let foreign = ImportedForkPublicationOperationV1::from_local(
        publication.projection().clone(),
        hash(0x99),
    );
    let mut tampers = retained_key_tampers()?;
    tampers.extend(vec![
        refused_by_both(
            "missing import admission",
            "DELETE FROM imported_fork_attribution_admissions",
            None,
        ),
        refused_by_both(
            "undecodable import admission",
            "UPDATE imported_fork_attribution_admissions SET ifa1_cbor = x'00'",
            None,
        ),
        refused_by_both(
            "import admission naming another origin",
            "UPDATE imported_fork_attribution_admissions SET ifa1_cbor = ?1",
            Some(ImportedForkAttributionAdmissionV1::new(origin)?.to_canonical_cbor()),
        ),
        refused_by_both(
            "import admission naming another FAR1",
            "UPDATE imported_fork_attribution_admissions SET ifa1_cbor = ?1",
            Some(ImportedForkAttributionAdmissionV1::new(fork_digest)?.to_canonical_cbor()),
        ),
        refused_by_both(
            "undecodable FAR1",
            "UPDATE fork_admissions SET far1_cbor = x'00'",
            None,
        ),
        refused_by_both("missing FCT1", "DELETE FROM fork_classifier_tables", None),
        refused_by_both(
            "missing FCR1",
            "DELETE FROM fork_classifier_registrations",
            None,
        ),
        refused_by_both(
            "missing imported FCS1",
            "DELETE FROM imported_fork_classifier_sources",
            None,
        ),
        refused_by_both(
            "imported FCS1 substituted by another source",
            "UPDATE imported_fork_classifier_sources SET fcs1_cbor = ?1",
            Some(other_source.to_canonical_cbor()),
        ),
        event_tamper(
            "imported Event with its signature stripped",
            "UPDATE events SET signature = NULL
             WHERE event_id IN (SELECT event_id FROM fork_append_operations)",
        ),
        event_tamper(
            "imported Event with another WallTime than its FOP1",
            "UPDATE events SET wall_time = wall_time + 1
             WHERE event_id IN (SELECT event_id FROM fork_append_operations)",
        ),
        Tamper {
            name: "FPO1 carrying another origin than the FAR1",
            sql: "UPDATE fork_publication_operations SET fpo1_cbor = ?1",
            blob: Some(foreign.to_canonical_cbor()),
            suffix: None,
            publication: &[ForkManifestPublicationErrorV1::PublicationConflict],
        },
        Tamper {
            name: "undecodable FPO1",
            sql: "UPDATE fork_publication_operations SET fpo1_cbor = x'00'",
            blob: None,
            suffix: None,
            publication: &[ForkManifestPublicationErrorV1::PublicationConflict],
        },
    ]);
    Ok(tampers)
}

fn apply(path: &str, tamper: &Tamper) -> Fallible<()> {
    let connection = rusqlite::Connection::open(path)?;
    let changed = connection.execute(tamper.sql, rusqlite::params_from_iter(tamper.blob.iter()))?;
    assert!(changed > 0, "{} edited nothing", tamper.name);
    Ok(())
}

fn assert_tampered_reads(path: &str, child: TimelineId, tamper: &Tamper) -> Fallible<()> {
    let store = reopen(path)?;
    let head = PARENT_CUT + 4;
    assert_eq!(
        store.read_fork_event_suffix(child, PARENT_CUT + 1).err(),
        tamper.suffix,
        "{} suffix",
        tamper.name
    );
    let publication = store.read_committed(child, head).err();
    assert!(
        publication.is_some_and(|error| tamper.publication.contains(&error)),
        "{} publication {publication:?}",
        tamper.name
    );
    Ok(())
}

#[test]
fn every_tampered_imported_row_fails_both_sqlite_reads_closed() -> Fallible<()> {
    let world = World::new(Shape::Mixed, false)?;
    let built = world.build(&Spec::default())?;
    let closure = ForkAttributionImportClosureV1::validate(&built.envelope)?;
    let child = world.child_at(0)?.id;
    let admission = ImportedForkAttributionAdmissionV1::from_envelope(&built.envelope, 1)?;
    let directory = tempfile::tempdir()?;
    for (index, tamper) in tampers(&admission, &closure)?.iter().enumerate() {
        let path = directory.path().join(format!("tamper-{index}.sqlite"));
        let path = path.to_str().ok_or("utf-8 path")?;
        let mut store = SqliteStore::open(path)?;
        imported(&mut store, &world, &built)?;
        drop(store);
        apply(path, tamper)?;
        assert_tampered_reads(path, child, tamper)?;
    }
    Ok(())
}

#[test]
fn an_empty_imported_child_still_needs_its_import_admission_to_publish() -> Fallible<()> {
    let world = World::new(Shape::EmptyUnclassified, false)?;
    let built = world.build(&Spec::default())?;
    let child = world.child_at(0)?.id;
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("empty.sqlite");
    let path = path.to_str().ok_or("utf-8 path")?;
    imported(&mut SqliteStore::open(path)?, &world, &built)?;
    apply(
        path,
        &refused_by_both(
            "missing import admission",
            "DELETE FROM imported_fork_attribution_admissions",
            None,
        ),
    )?;
    let store = reopen(path)?;
    // An empty segment has no classified Event to read, so only the
    // publication read, which validates the admission, refuses it.
    assert_eq!(
        store.read_fork_event_suffix(child, PARENT_CUT + 1),
        Ok(vec![])
    );
    assert_eq!(
        store.read_committed(child, PARENT_CUT).err(),
        Some(ForkManifestPublicationErrorV1::PublicationConflict)
    );
    Ok(())
}

/// A destination whose live registry holds a record of the creator's key
/// identity made from `seed`, which the publication read must compare with
/// the retained `IKR1` (ADR-105 erratum E12).
struct LocalKey<'a> {
    world: &'a World,
    built: &'a Built,
    seed: u8,
    publication: Result<(), ForkManifestPublicationErrorV1>,
}

impl Scenario for LocalKey<'_> {
    fn run<S: Port>(&self, store: &mut S) -> Fallible<()> {
        imported(store, self.world, self.built)?;
        store.save_key_registry(
            &self
                .world
                .registry_with_attribution_key("creator-a", self.seed)?,
        )?;
        let child = self.world.child_at(0)?.id;
        // The suffix read never consults a key.
        assert!(store.read_fork_event_suffix(child, PARENT_CUT + 1).is_ok());
        assert_eq!(
            store.read_committed(child, PARENT_CUT + 4).map(|_| ()),
            self.publication
        );
        Ok(())
    }
}

#[test]
fn a_local_key_record_must_equal_the_retained_one_and_its_absence_is_no_error() -> Fallible<()> {
    let world = World::new(Shape::Mixed, false)?;
    let built = world.build(&Spec::default())?;
    for (seed, publication) in [
        (0x71, Ok(())),
        // A later local rotation or destruction changes the equal-identity
        // record the same way: the read fails closed.
        (
            0x72,
            Err(ForkManifestPublicationErrorV1::PublicationConflict),
        ),
    ] {
        on_both_adapters(&LocalKey {
            world: &world,
            built: &built,
            seed,
            publication,
        })?;
    }
    Ok(())
}

#[test]
fn a_local_fcs1_equal_to_the_imported_one_is_never_consulted() -> Fallible<()> {
    let world = World::new(Shape::Mixed, false)?;
    let built = world.build(&Spec {
        registrar: GATEWAY_REGISTRAR,
        ..Spec::default()
    })?;
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("local-fcs1.sqlite");
    let path = path.to_str().ok_or("utf-8 path")?;
    imported(&mut SqliteStore::open(path)?, &world, &built)?;
    // Seed the forbidden state: a durable local custody FCS1 equal to the
    // imported one, which the local registrar would have written.
    let fcs1 = gateway_source()?;
    rusqlite::Connection::open(path)?.execute(
        "INSERT INTO fork_classifier_sources (descriptor_hash, registrar_identifier, fcs1_cbor)
         VALUES (?1, ?2, ?3)",
        rusqlite::params![
            fcs1.input()
                .room_revision_descriptor_hash
                .as_bytes()
                .as_slice(),
            GATEWAY_REGISTRAR,
            fcs1.to_canonical_cbor()
        ],
    )?;
    let mut store = reopen(path)?;
    // The activation preflight accepts the local row (it equals the profile),
    // every local path still refuses the imported child, and read (b) accepts.
    Barrier {
        world: &world,
        built: &built,
        shape: Shape::Mixed,
    }
    .refusals(&mut store)?;
    drop(store);
    // A code-2 child resolves its FCS1 only from the imported store: with that
    // row gone, the equal local row does not stand in for it.
    let child = world.child_at(0)?.id;
    let deleted = refused_by_both(
        "imported FCS1 deleted while an equal local FCS1 exists",
        "DELETE FROM imported_fork_classifier_sources",
        None,
    );
    apply(path, &deleted)?;
    assert_tampered_reads(path, child, &deleted)
}

struct DestroyedKey<'a> {
    world: &'a World,
    built: &'a Built,
}

impl Scenario for DestroyedKey<'_> {
    fn run<S: Port>(&self, store: &mut S) -> Fallible<()> {
        let receipt = imported(store, self.world, self.built)?;
        let origin = receipt.admission.input().authority_origin_digest;
        assert_reads_accept(store, self.world, Shape::Mixed, origin)
    }
}

#[test]
fn a_destroyed_source_key_reads_through_its_retained_tombstone() -> Fallible<()> {
    let world = World::new(Shape::Mixed, false)?;
    let built = world.build(&Spec {
        destroyed_key: true,
        ..Spec::default()
    })?;
    on_both_adapters(&DestroyedKey {
        world: &world,
        built: &built,
    })
}
