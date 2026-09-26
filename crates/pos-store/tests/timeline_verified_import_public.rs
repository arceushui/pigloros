#![cfg(feature = "sqlite")]

use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

use pos_core::{
    ArtifactClaimInputV1, ArtifactDataClassV1, ArtifactOptionalityV1, ArtifactStateV1,
    ArtifactTransitionRuleV1, CanonicalBytes, CoreError, EntityId, ErasureArtifactClassV1,
    ErasureContainmentGateV1, ErasureReferenceV1, ErasureReplayClaimV1, Event, EventDraft,
    EventOriginV1, EventStore, Hash, KeyDestructionRequestV1, KeyIdentityV1, KeyRegistrationV1,
    KeyRegistryStateV1, KeyRoleV1, Kind, RegisteredArtifactV1, ReplayClaimEvaluatorV1, Seq,
    SeqRange, Timeline, TimelineEventEnvelopeV1, TimelineEventVerificationV1, TimelineId,
};
use pos_crypto::{
    key_roles::{sign_timeline_event_for_registered_role, SigningKeyMaterial},
    signing::generate_keypair,
};
use pos_store::{
    export_timeline_own, import_timeline_verified_v1, memory::MemoryStore, sqlite::SqliteStore,
    verify_signed_timeline_range_v1, TimelineSignedRangeClaimV1,
};

const EXPORT_DIGEST: ErasureReferenceV1 = ErasureReferenceV1::from_digest([201; 32]);

fn export_evaluation() -> Result<pos_core::ReplayClaimEvaluationV1, CoreError> {
    ReplayClaimEvaluatorV1::evaluate(
        ErasureReplayClaimV1::Exact,
        &[ArtifactClaimInputV1 {
            registration: RegisteredArtifactV1::new(
                ErasureArtifactClassV1::Export,
                EXPORT_DIGEST,
                ArtifactDataClassV1::StructuralAuditMetadata,
                None,
                ErasureReferenceV1::from_digest([202; 32]),
                ArtifactOptionalityV1::Required,
                ArtifactTransitionRuleV1::PreserveExact,
            ),
            current_claim: ErasureReplayClaimV1::Exact,
            state: ArtifactStateV1::Retained,
        }],
    )
    .map_err(|error| CoreError::Storage(error.to_string()))
}

fn gated(store: &mut dyn EventStore) -> Result<(), CoreError> {
    store.bind_erasure_gate(Arc::new(ErasureContainmentGateV1::new_test_open()))
}

fn append_signed(
    store: &mut dyn EventStore,
    timeline: pos_core::TimelineId,
    registry: &KeyRegistryStateV1,
    identity: KeyIdentityV1,
    material: &SigningKeyMaterial,
    value: &'static [u8],
) -> Result<(), CoreError> {
    let mut sign = |authorized: &mut KeyRegistryStateV1,
                    envelope: &TimelineEventEnvelopeV1,
                    payload: &CanonicalBytes| {
        sign_timeline_event_for_registered_role(authorized, material, envelope, payload)
            .map_err(|error| CoreError::Storage(error.to_string()))
    };
    store.append_timeline_signed_authorized(
        timeline,
        registry,
        EventDraft::new(
            EntityId::new(),
            Kind::new("timeline.verified.import.v1"),
            CanonicalBytes::from_static(value),
        ),
        identity,
        material.material_digest(),
        material.public_verification_key(),
        &mut sign,
    )?;
    Ok(())
}

struct Fixture {
    source: MemoryStore,
    root: pos_core::TimelineId,
    child: pos_core::TimelineId,
    nested: pos_core::TimelineId,
    initial_registry: KeyRegistryStateV1,
    rotated_registry: KeyRegistryStateV1,
    destruction_request: KeyDestructionRequestV1,
    registry: KeyRegistryStateV1,
    anchors: [(KeyIdentityV1, pos_core::PublicKey); 2],
}

struct SingleRegistryReadStore {
    registry: KeyRegistryStateV1,
    reads: AtomicUsize,
}

fn unexpected_store_call<T>() -> Result<T, CoreError> {
    Err(CoreError::Storage("unexpected store operation".to_owned()))
}

impl EventStore for SingleRegistryReadStore {
    fn create_timeline(&mut self, _name: &str) -> Result<Timeline, CoreError> {
        unexpected_store_call()
    }

    fn append(
        &mut self,
        _timeline: TimelineId,
        _drafts: &[EventDraft],
    ) -> Result<Vec<Event>, CoreError> {
        unexpected_store_call()
    }

    fn read(&self, _timeline: TimelineId, _range: SeqRange) -> Result<Vec<Event>, CoreError> {
        unexpected_store_call()
    }

    fn fork(
        &mut self,
        _parent: TimelineId,
        _at_seq: Seq,
        _name: &str,
    ) -> Result<Timeline, CoreError> {
        unexpected_store_call()
    }

    fn list_timelines(&self) -> Result<Vec<Timeline>, CoreError> {
        unexpected_store_call()
    }

    fn get_timeline(&self, _id: TimelineId) -> Result<Option<Timeline>, CoreError> {
        unexpected_store_call()
    }

    fn load_key_registry(&self) -> Result<Option<KeyRegistryStateV1>, CoreError> {
        if self.reads.fetch_add(1, Ordering::SeqCst) == 0 {
            Ok(Some(self.registry.clone()))
        } else {
            Err(CoreError::Storage(
                "registry loaded more than once".to_owned(),
            ))
        }
    }
}

#[derive(Clone, Copy)]
enum LineageFault {
    None,
    Missing,
    Mismatched,
    Cycle,
    ParentAhead,
    ReadError,
}

struct RangeFaultStore {
    inner: MemoryStore,
    lineage_fault: LineageFault,
    registry_error: bool,
    read_error: bool,
    head_error: bool,
    head_override: Option<Seq>,
}

impl RangeFaultStore {
    fn new(inner: MemoryStore) -> Self {
        Self {
            inner,
            lineage_fault: LineageFault::None,
            registry_error: false,
            read_error: false,
            head_error: false,
            head_override: None,
        }
    }
}

impl EventStore for RangeFaultStore {
    fn create_timeline(&mut self, name: &str) -> Result<Timeline, CoreError> {
        self.inner.create_timeline(name)
    }

    fn append(
        &mut self,
        timeline: TimelineId,
        drafts: &[EventDraft],
    ) -> Result<Vec<Event>, CoreError> {
        self.inner.append(timeline, drafts)
    }

    fn read(&self, timeline: TimelineId, range: SeqRange) -> Result<Vec<Event>, CoreError> {
        if self.read_error {
            Err(CoreError::Storage("injected range read failure".to_owned()))
        } else {
            self.inner.read(timeline, range)
        }
    }

    fn fork(&mut self, parent: TimelineId, at_seq: Seq, name: &str) -> Result<Timeline, CoreError> {
        self.inner.fork(parent, at_seq, name)
    }

    fn list_timelines(&self) -> Result<Vec<Timeline>, CoreError> {
        self.inner.list_timelines()
    }

    fn get_timeline(&self, id: TimelineId) -> Result<Option<Timeline>, CoreError> {
        if matches!(self.lineage_fault, LineageFault::ReadError) {
            return Err(CoreError::Storage(
                "injected lineage read failure".to_owned(),
            ));
        }
        if matches!(self.lineage_fault, LineageFault::Missing) {
            return Ok(None);
        }
        let mut found = self.inner.get_timeline(id)?;
        if let Some(timeline) = found.as_mut() {
            match self.lineage_fault {
                LineageFault::Mismatched => timeline.meta.id = TimelineId::new(),
                LineageFault::Cycle => timeline.meta.fork_point = Some((id, Seq::from_u64(1))),
                LineageFault::ParentAhead => {
                    timeline.meta.fork_point = Some((id, Seq::from_u64(3)));
                }
                LineageFault::None | LineageFault::Missing | LineageFault::ReadError => {}
            }
        }
        Ok(found)
    }

    fn load_key_registry(&self) -> Result<Option<KeyRegistryStateV1>, CoreError> {
        if self.registry_error {
            Err(CoreError::Storage(
                "injected registry read failure".to_owned(),
            ))
        } else {
            self.inner.load_key_registry()
        }
    }

    fn logical_head(&self, id: TimelineId) -> Result<Seq, CoreError> {
        if self.head_error {
            Err(CoreError::Storage("injected head read failure".to_owned()))
        } else if let Some(head) = self.head_override {
            Ok(head)
        } else {
            self.inner.logical_head(id)
        }
    }
}

fn fixture() -> Result<Fixture, Box<dyn std::error::Error>> {
    let (first_key, _) = generate_keypair();
    let first_material = SigningKeyMaterial::new(first_key);
    let first = KeyIdentityV1::new("import-owner", KeyRoleV1::TimelineIntegritySigning, 1);
    let mut registry = KeyRegistryStateV1::new();
    registry.register_key(KeyRegistrationV1::new(
        first,
        first_material.material_digest(),
        Some(first_material.public_verification_key()),
    ))?;
    let initial_registry = registry.clone();
    let mut source = MemoryStore::new();
    gated(&mut source)?;
    source.save_key_registry(&registry)?;
    let root = source.create_timeline("verified-root")?.id();
    append_signed(
        &mut source,
        root,
        &registry,
        first,
        &first_material,
        b"root",
    )?;
    append_signed(
        &mut source,
        root,
        &registry,
        first,
        &first_material,
        b"root-2",
    )?;
    let child = source.fork(root, Seq::from_u64(2), "verified-child")?.id();
    append_signed(
        &mut source,
        child,
        &registry,
        first,
        &first_material,
        b"child",
    )?;
    let nested = source
        .fork(child, Seq::from_u64(3), "verified-nested")?
        .id();

    let (second_key, _) = generate_keypair();
    let second_material = SigningKeyMaterial::new(second_key);
    let second = KeyIdentityV1::new("import-owner", KeyRoleV1::TimelineIntegritySigning, 2);
    registry.register_key(KeyRegistrationV1::new(
        second,
        second_material.material_digest(),
        Some(second_material.public_verification_key()),
    ))?;
    let rotated_registry = registry.clone();
    source.save_key_registry(&registry)?;
    append_signed(
        &mut source,
        nested,
        &registry,
        second,
        &second_material,
        b"nested",
    )?;

    let request = KeyDestructionRequestV1::new(
        first,
        first_material.material_digest(),
        Hash::from_bytes([203; 32]),
    );
    source.begin_key_registry_destruction(request)?;
    let (_, registry) =
        source.complete_key_registry_destruction(request, pos_core::deletion_receipt(&request))?;
    assert!(registry.tombstone(first).is_some());
    Ok(Fixture {
        source,
        root,
        child,
        nested,
        initial_registry,
        rotated_registry,
        destruction_request: request,
        registry,
        anchors: [
            (first, first_material.public_verification_key()),
            (second, second_material.public_verification_key()),
        ],
    })
}

fn seed_destination_registry(
    store: &mut dyn EventStore,
    fixture: &Fixture,
) -> Result<(), CoreError> {
    store.save_key_registry(&fixture.initial_registry)?;
    store.save_key_registry(&fixture.rotated_registry)?;
    store.begin_key_registry_destruction(fixture.destruction_request)?;
    let (_, registry) = store.complete_key_registry_destruction(
        fixture.destruction_request,
        pos_core::deletion_receipt(&fixture.destruction_request),
    )?;
    assert_eq!(registry, fixture.registry);
    Ok(())
}

fn verify_round_trip(store: &mut dyn EventStore) -> Result<(), Box<dyn std::error::Error>> {
    let fixture = fixture()?;
    gated(store)?;
    seed_destination_registry(store, &fixture)?;
    let evaluation = export_evaluation()?;
    for timeline in [fixture.root, fixture.child, fixture.nested] {
        let export = export_timeline_own(&fixture.source, timeline, EXPORT_DIGEST, &evaluation)?;
        assert_eq!(
            export.events.len(),
            usize::from(timeline == fixture.root) + 1
        );
        import_timeline_verified_v1(store, export, &fixture.anchors)?;
    }
    assert_eq!(
        store.read(fixture.nested, SeqRange::all())?,
        fixture.source.read(fixture.nested, SeqRange::all())?
    );
    for timeline in [fixture.root, fixture.child, fixture.nested] {
        let events = store.read(timeline, SeqRange::all())?;
        let head = store.logical_head(timeline)?;
        let report = verify_signed_timeline_range_v1(
            store,
            timeline,
            SeqRange::all(),
            &events,
            &fixture.anchors,
            Some(head),
        )?;
        assert_eq!(
            report.range_claim(),
            TimelineSignedRangeClaimV1::CompleteThroughHead
        );
        assert_eq!(report.per_event().len(), events.len());
        assert!(report
            .per_event()
            .iter()
            .all(|result| *result == TimelineEventVerificationV1::Verified));
    }
    let bounded = SeqRange::bounded(Seq::from_u64(2), Seq::from_u64(3));
    let events = store.read(fixture.nested, bounded)?;
    let head = store.logical_head(fixture.nested)?;
    let complete = verify_signed_timeline_range_v1(
        store,
        fixture.nested,
        bounded,
        &events,
        &fixture.anchors,
        Some(head),
    )?;
    assert_eq!(
        complete.range_claim(),
        TimelineSignedRangeClaimV1::CompleteBounded
    );
    let no_head = verify_signed_timeline_range_v1(
        store,
        fixture.nested,
        bounded,
        &events,
        &fixture.anchors,
        None,
    )?;
    assert_eq!(
        no_head.range_claim(),
        TimelineSignedRangeClaimV1::ContiguousOnly
    );
    Ok(())
}

#[test]
fn memory_and_sqlite_import_verified_nested_cow_with_rotated_destroyed_key(
) -> Result<(), Box<dyn std::error::Error>> {
    verify_round_trip(&mut MemoryStore::new())?;
    verify_round_trip(&mut SqliteStore::open_in_memory()?)?;
    Ok(())
}

#[test]
fn verified_import_resolves_and_verifies_against_one_registry_snapshot(
) -> Result<(), Box<dyn std::error::Error>> {
    let fixture = fixture()?;
    let export = export_timeline_own(
        &fixture.source,
        fixture.root,
        EXPORT_DIGEST,
        &export_evaluation()?,
    )?;
    let mut store = SingleRegistryReadStore {
        registry: fixture.registry.clone(),
        reads: AtomicUsize::new(0),
    };
    let error = import_timeline_verified_v1(&mut store, export, &fixture.anchors)
        .err()
        .ok_or("expected test store import rejection")?;
    assert!(error.to_string().contains("import_committed not supported"));
    assert_eq!(store.reads.load(Ordering::SeqCst), 1);
    Ok(())
}

fn reject_export(
    store: &mut dyn EventStore,
    fixture: &Fixture,
    export: pos_core::store::TimelineExport,
    anchors: &[(KeyIdentityV1, pos_core::PublicKey)],
) -> Result<(), Box<dyn std::error::Error>> {
    gated(store)?;
    seed_destination_registry(store, fixture)?;
    assert!(import_timeline_verified_v1(store, export, anchors).is_err());
    assert!(store.get_timeline(fixture.root)?.is_none());
    assert!(store.list_timelines()?.is_empty());
    Ok(())
}

#[test]
fn invalid_signature_origin_and_trust_reject_without_partial_import(
) -> Result<(), Box<dyn std::error::Error>> {
    let fixture = fixture()?;
    let evaluation = export_evaluation()?;
    let original = export_timeline_own(&fixture.source, fixture.root, EXPORT_DIGEST, &evaluation)?;
    assert_eq!(original.events.len(), 2);
    let mut bad_signature = original.clone();
    bad_signature.events[1].signature = Some(pos_core::Signature::from_bytes([0; 64]));
    reject_export(
        &mut MemoryStore::new(),
        &fixture,
        bad_signature,
        &fixture.anchors,
    )?;

    let mut bad_payload = original.clone();
    bad_payload.events[0].payload = CanonicalBytes::from_static(b"altered");
    reject_export(
        &mut SqliteStore::open_in_memory()?,
        &fixture,
        bad_payload,
        &fixture.anchors,
    )?;

    let mut transplanted = original.clone();
    transplanted.events[0].origin = Some(EventOriginV1 {
        origin_timeline_id: fixture.child,
        origin_logical_seq: Seq::from_u64(1),
    });
    reject_export(
        &mut MemoryStore::new(),
        &fixture,
        transplanted,
        &fixture.anchors,
    )?;

    let mut wrong_epoch = original.clone();
    wrong_epoch.events[1].signature_identity = Some(fixture.anchors[1].0);
    reject_export(
        &mut SqliteStore::open_in_memory()?,
        &fixture,
        wrong_epoch,
        &fixture.anchors,
    )?;

    let mut overflowed_fork = original.clone();
    overflowed_fork.timeline.meta.fork_point = Some((fixture.child, Seq::from_u64(u64::MAX)));
    reject_export(
        &mut MemoryStore::new(),
        &fixture,
        overflowed_fork,
        &fixture.anchors,
    )?;

    reject_export(
        &mut SqliteStore::open_in_memory()?,
        &fixture,
        original.clone(),
        &[],
    )?;
    let wrong_anchor = [(fixture.anchors[0].0, fixture.anchors[1].1)];
    reject_export(&mut MemoryStore::new(), &fixture, original, &wrong_anchor)?;
    Ok(())
}

#[test]
fn signed_range_rejects_reordering_duplicates_gaps_and_untrusted_head(
) -> Result<(), Box<dyn std::error::Error>> {
    let fixture = fixture()?;
    let store = &fixture.source;
    let range = SeqRange::bounded(Seq::from_u64(1), Seq::from_u64(2));
    let root = store.read(fixture.root, range)?;
    let head = store.logical_head(fixture.root)?;
    for supplied in [
        vec![root[1].clone(), root[0].clone()],
        vec![root[0].clone(), root[0].clone()],
        vec![root[1].clone()],
    ] {
        let report = verify_signed_timeline_range_v1(
            store,
            fixture.root,
            range,
            &supplied,
            &fixture.anchors,
            Some(head),
        )?;
        assert_eq!(report.range_claim(), TimelineSignedRangeClaimV1::Rejected);
        assert!(report
            .per_event()
            .iter()
            .all(|result| *result == TimelineEventVerificationV1::Verified));
    }
    let report = verify_signed_timeline_range_v1(
        store,
        fixture.root,
        range,
        &root,
        &fixture.anchors,
        Some(Seq::from_u64(1)),
    )?;
    assert_eq!(report.range_claim(), TimelineSignedRangeClaimV1::Rejected);
    assert!(report
        .per_event()
        .iter()
        .all(|result| *result == TimelineEventVerificationV1::Verified));

    let missing_anchor =
        verify_signed_timeline_range_v1(store, fixture.root, range, &root, &[], Some(head))?;
    assert_eq!(
        missing_anchor.range_claim(),
        TimelineSignedRangeClaimV1::Rejected
    );
    assert!(missing_anchor
        .per_event()
        .iter()
        .all(|result| *result == TimelineEventVerificationV1::MissingRequiredContext));
    let wrong_anchor = [(fixture.anchors[0].0, fixture.anchors[1].1)];
    let invalid = verify_signed_timeline_range_v1(
        store,
        fixture.root,
        range,
        &root,
        &wrong_anchor,
        Some(head),
    )?;
    assert_eq!(invalid.range_claim(), TimelineSignedRangeClaimV1::Rejected);
    assert!(invalid
        .per_event()
        .iter()
        .all(|result| *result == TimelineEventVerificationV1::Invalid));
    Ok(())
}

#[test]
fn signed_range_rejects_empty_input_invalid_anchors_and_missing_lineage(
) -> Result<(), Box<dyn std::error::Error>> {
    let fixture = fixture()?;
    let events = fixture.source.read(fixture.root, SeqRange::all())?;
    let head = fixture.source.logical_head(fixture.root)?;
    let empty = verify_signed_timeline_range_v1(
        &fixture.source,
        fixture.root,
        SeqRange::all(),
        &[],
        &fixture.anchors,
        Some(head),
    )?;
    assert_eq!(empty.range_claim(), TimelineSignedRangeClaimV1::Rejected);
    assert!(empty.per_event().is_empty());

    let (identity, key) = fixture.anchors[0];
    for invalid in [
        vec![(
            KeyIdentityV1::new("import-owner", KeyRoleV1::SubjectAttributionSigning, 1),
            key,
        )],
        vec![(
            KeyIdentityV1::new("import-owner", KeyRoleV1::TimelineIntegritySigning, 0),
            key,
        )],
        vec![(identity, key), (identity, key)],
    ] {
        assert!(verify_signed_timeline_range_v1(
            &fixture.source,
            fixture.root,
            SeqRange::all(),
            &events,
            &invalid,
            Some(head),
        )
        .is_err());
    }

    let mut missing_lineage = MemoryStore::new();
    gated(&mut missing_lineage)?;
    seed_destination_registry(&mut missing_lineage, &fixture)?;
    let report = verify_signed_timeline_range_v1(
        &missing_lineage,
        fixture.root,
        SeqRange::all(),
        &events,
        &fixture.anchors,
        Some(head),
    )?;
    assert_eq!(report.range_claim(), TimelineSignedRangeClaimV1::Rejected);
    assert!(report
        .per_event()
        .iter()
        .all(|result| *result == TimelineEventVerificationV1::Verified));
    Ok(())
}

#[test]
fn signed_range_rejects_inconsistent_trusted_lineage() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = fixture()?;
    let root = fixture.root;
    let events = fixture.source.read(root, SeqRange::all())?;
    let head = fixture.source.logical_head(root)?;
    let mut store = RangeFaultStore::new(fixture.source);
    for fault in [
        LineageFault::Missing,
        LineageFault::Mismatched,
        LineageFault::Cycle,
        LineageFault::ParentAhead,
    ] {
        store.lineage_fault = fault;
        let report = verify_signed_timeline_range_v1(
            &store,
            root,
            SeqRange::all(),
            &events,
            &fixture.anchors,
            Some(head),
        )?;
        assert_eq!(report.range_claim(), TimelineSignedRangeClaimV1::Rejected);
        assert!(report
            .per_event()
            .iter()
            .all(|result| *result == TimelineEventVerificationV1::Verified));
    }
    Ok(())
}

#[test]
fn signed_range_propagates_trusted_read_errors_and_rejects_a_moving_head(
) -> Result<(), Box<dyn std::error::Error>> {
    let fixture = fixture()?;
    let root = fixture.root;
    let events = fixture.source.read(root, SeqRange::all())?;
    let head = fixture.source.logical_head(root)?;
    let mut store = RangeFaultStore::new(fixture.source);
    let verify = |store: &RangeFaultStore, trusted_head| {
        verify_signed_timeline_range_v1(
            store,
            root,
            SeqRange::all(),
            &events,
            &fixture.anchors,
            trusted_head,
        )
    };

    store.registry_error = true;
    assert!(verify(&store, Some(head)).is_err());
    store.registry_error = false;
    store.lineage_fault = LineageFault::ReadError;
    assert!(verify(&store, Some(head)).is_err());
    store.lineage_fault = LineageFault::Cycle;
    store.head_error = true;
    assert!(verify(&store, Some(head)).is_err());
    store.lineage_fault = LineageFault::None;
    store.head_error = false;
    store.read_error = true;
    assert!(verify(&store, Some(head)).is_err());
    store.read_error = false;
    store.head_error = true;
    assert!(verify(&store, Some(head)).is_err());
    store.head_error = false;
    store.head_override = Some(head.next());
    let report = verify(&store, Some(head.next()))?;
    assert_eq!(report.range_claim(), TimelineSignedRangeClaimV1::Rejected);
    Ok(())
}

#[test]
fn signed_range_rejects_valid_event_from_other_fork() -> Result<(), Box<dyn std::error::Error>> {
    let (key, _) = generate_keypair();
    let material = SigningKeyMaterial::new(key);
    let identity = KeyIdentityV1::new("range-owner", KeyRoleV1::TimelineIntegritySigning, 1);
    let mut registry = KeyRegistryStateV1::new();
    registry.register_key(KeyRegistrationV1::new(
        identity,
        material.material_digest(),
        Some(material.public_verification_key()),
    ))?;
    let mut store = MemoryStore::new();
    gated(&mut store)?;
    store.save_key_registry(&registry)?;
    let root = store.create_timeline("range-root")?.id();
    append_signed(&mut store, root, &registry, identity, &material, b"root")?;
    let left = store.fork(root, Seq::from_u64(1), "left")?.id();
    let right = store.fork(root, Seq::from_u64(1), "right")?.id();
    append_signed(&mut store, left, &registry, identity, &material, b"left")?;
    append_signed(&mut store, right, &registry, identity, &material, b"right")?;
    let mut supplied = store.read(left, SeqRange::all())?;
    let right_event = store.read(right, SeqRange::all())?.remove(1);
    supplied[1] = right_event;
    let report = verify_signed_timeline_range_v1(
        &store,
        left,
        SeqRange::all(),
        &supplied,
        &[(identity, material.public_verification_key())],
        Some(store.logical_head(left)?),
    )?;
    assert_eq!(report.range_claim(), TimelineSignedRangeClaimV1::Rejected);
    assert!(report
        .per_event()
        .iter()
        .all(|result| *result == TimelineEventVerificationV1::Verified));
    Ok(())
}
