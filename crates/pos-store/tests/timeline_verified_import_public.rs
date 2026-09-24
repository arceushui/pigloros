#![cfg(feature = "sqlite")]

use std::sync::Arc;

use pos_core::{
    ArtifactClaimInputV1, ArtifactDataClassV1, ArtifactOptionalityV1, ArtifactStateV1,
    ArtifactTransitionRuleV1, CanonicalBytes, CoreError, EntityId, ErasureArtifactClassV1,
    ErasureContainmentGateV1, ErasureReferenceV1, ErasureReplayClaimV1, EventDraft, EventOriginV1,
    EventStore, Hash, KeyDestructionRequestV1, KeyIdentityV1, KeyRegistrationV1,
    KeyRegistryStateV1, KeyRoleV1, Kind, RegisteredArtifactV1, ReplayClaimEvaluatorV1, Seq,
    SeqRange, TimelineEventEnvelopeV1,
};
use pos_crypto::{
    key_roles::{sign_timeline_event_for_registered_role, SigningKeyMaterial},
    signing::generate_keypair,
};
use pos_store::{
    export_timeline_own, import_timeline_verified_v1, memory::MemoryStore, sqlite::SqliteStore,
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
    registry: KeyRegistryStateV1,
    anchors: [(KeyIdentityV1, pos_core::PublicKey); 2],
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
        registry,
        anchors: [
            (first, first_material.public_verification_key()),
            (second, second_material.public_verification_key()),
        ],
    })
}

fn verify_round_trip(store: &mut dyn EventStore) -> Result<(), Box<dyn std::error::Error>> {
    let fixture = fixture()?;
    gated(store)?;
    store.save_key_registry(&fixture.registry)?;
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
    Ok(())
}

#[test]
fn memory_and_sqlite_import_verified_nested_cow_with_rotated_destroyed_key(
) -> Result<(), Box<dyn std::error::Error>> {
    verify_round_trip(&mut MemoryStore::new())?;
    verify_round_trip(&mut SqliteStore::open_in_memory()?)?;
    Ok(())
}

fn reject_export(
    store: &mut dyn EventStore,
    fixture: &Fixture,
    export: pos_core::store::TimelineExport,
    anchors: &[(KeyIdentityV1, pos_core::PublicKey)],
) -> Result<(), Box<dyn std::error::Error>> {
    gated(store)?;
    store.save_key_registry(&fixture.registry)?;
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
