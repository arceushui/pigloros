#![cfg(all(feature = "sqlite", target_os = "linux"))]

//! Public contracts for durable authorized recipient-export publication.

use std::{os::unix::fs::PermissionsExt, sync::Arc};

use pos_core::{
    ArtifactClaimInputV1, ArtifactDataClassV1, ArtifactOptionalityV1, ArtifactStateV1,
    ArtifactTransitionRuleV1, CanonicalBytes, ConsentAuthority, ConsentGate, ConsentGrantedV1,
    CoreError, EntityId, ErasureArtifactClassV1, ErasureContainmentGateV1, ErasureReferenceV1,
    ErasureReplayClaimV1, EventDraft, EventStore, Hash, KeyDestructionRequestV1,
    KeyRegistryErrorV1, Kind, RegisteredArtifactV1, ReplayClaimEvaluatorV1, TimelineMeta,
};
use pos_store::sqlite::{
    RecipientExportPublicationErrorV1, RecipientExportRequestV1, RecipientKeyOwnerV1, SqliteStore,
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const EXPORT_DIGEST: ErasureReferenceV1 = ErasureReferenceV1::from_digest([241; 32]);

struct Fixture {
    temporary: tempfile::TempDir,
    store: SqliteStore,
    owner: RecipientKeyOwnerV1,
    authority: ConsentAuthority,
    token: pos_core::ConsentCapabilityToken,
    timeline: pos_core::TimelineId,
    descriptor: pos_core::RecipientKeyDescriptorV1,
    evaluation: pos_core::ReplayClaimEvaluationV1,
    gate: Arc<ErasureContainmentGateV1>,
}

fn evaluation() -> TestResult<pos_core::ReplayClaimEvaluationV1> {
    ReplayClaimEvaluatorV1::evaluate(
        ErasureReplayClaimV1::Exact,
        &[ArtifactClaimInputV1 {
            registration: RegisteredArtifactV1::new(
                ErasureArtifactClassV1::Export,
                EXPORT_DIGEST,
                ArtifactDataClassV1::StructuralAuditMetadata,
                None,
                ErasureReferenceV1::from_digest([242; 32]),
                ArtifactOptionalityV1::Required,
                ArtifactTransitionRuleV1::PreserveExact,
            ),
            current_claim: ErasureReplayClaimV1::Exact,
            state: ArtifactStateV1::Retained,
        }],
    )
    .map_err(|error| error.to_string().into())
}

fn grant(subject_id: EntityId, grantee_id: EntityId, export_permitted: bool) -> ConsentGrantedV1 {
    ConsentGrantedV1 {
        subject_id,
        grantee_id,
        purpose: "recipient-export-public-contract".to_owned(),
        modalities: pos_core::MODALITY_EXPORT,
        min_geo_resolution: 0,
        fork_permitted: false,
        export_permitted,
        retention_days: 1,
        expiry_secs: 0,
        grant_seq: 1,
    }
}

fn fixture(export_permitted: bool) -> TestResult<Fixture> {
    let temporary = tempfile::tempdir()?;
    let directory = temporary.path().join("recipient-private");
    std::fs::create_dir(&directory)?;
    std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700))?;
    let database = temporary.path().join("recipient.sqlite");
    let mut store = SqliteStore::open(database.to_str().ok_or("database path is not UTF-8")?)?;
    let gate = Arc::new(ErasureContainmentGateV1::new_test_open());
    store.bind_erasure_gate(Arc::clone(&gate))?;

    let subject = EntityId::new();
    let grantee = EntityId::new();
    let timeline =
        store.create_timeline_with_meta(TimelineMeta::root_owned("recipient-export", subject))?;
    store.append(
        timeline.id(),
        &[EventDraft::new(
            EntityId::new(),
            Kind::new("recipient.export.public.v1"),
            CanonicalBytes::from_static(b"encrypted-recipient-export"),
        )],
    )?;

    let authority = ConsentAuthority::new();
    store.bind_consent_authority(authority.append_permit())?;
    let grant = grant(subject, grantee, export_permitted);
    let token = authority.record_grant_on_timeline(timeline.id(), &grant);
    let owner = RecipientKeyOwnerV1::open(&directory, grantee)?;
    let descriptor = store.enroll_recipient_key(&owner)?;
    Ok(Fixture {
        temporary,
        store,
        owner,
        authority,
        token,
        timeline: timeline.id(),
        descriptor,
        evaluation: evaluation()?,
        gate,
    })
}

const fn request<'a>(
    timeline_id: pos_core::TimelineId,
    recipient: pos_core::RecipientKeyDescriptorV1,
    evaluation: &'a pos_core::ReplayClaimEvaluationV1,
    token: &'a pos_core::ConsentCapabilityToken,
) -> RecipientExportRequestV1<'a> {
    RecipientExportRequestV1 {
        timeline_id,
        recipient,
        artifact_digest: EXPORT_DIGEST,
        evaluation,
        token,
        now_secs: 1,
    }
}

#[test]
fn publication_is_catalog_visible_and_decryptable_without_importing() -> TestResult {
    let mut fixture = fixture(true)?;
    let request = request(
        fixture.timeline,
        fixture.descriptor,
        &fixture.evaluation,
        &fixture.token,
    );
    let publication =
        fixture
            .store
            .publish_recipient_export(&fixture.authority, &fixture.owner, &request)?;
    let encoded = fixture
        .store
        .read_recipient_export(&fixture.owner, publication.export_id)?;

    assert_eq!(u64::try_from(encoded.len())?, publication.ciphertext_length);
    let decrypted = fixture.store.decrypt_recipient_export(
        &fixture.owner,
        &encoded,
        publication.export_id,
        publication.recipient,
    )?;
    assert_eq!(decrypted.export.timeline.id(), fixture.timeline);
    assert_eq!(decrypted.export.timeline.head, publication.local_head);
    assert_eq!(decrypted.export.events.len(), 1);
    Ok(())
}

#[test]
fn publication_rejects_a_token_without_export_permission() -> TestResult {
    let mut fixture = fixture(false)?;
    let request = request(
        fixture.timeline,
        fixture.descriptor,
        &fixture.evaluation,
        &fixture.token,
    );
    let error = fixture
        .store
        .publish_recipient_export(&fixture.authority, &fixture.owner, &request)
        .err()
        .ok_or("publication unexpectedly succeeded")?;
    assert!(matches!(
        error,
        RecipientExportPublicationErrorV1::Consent(pos_core::ConsentError::ExportNotPermitted)
    ));
    Ok(())
}

#[test]
fn publication_rejects_an_authority_that_is_not_bound_to_the_store() -> TestResult {
    let mut fixture = fixture(true)?;
    let foreign_authority = ConsentAuthority::new();
    let foreign_token = foreign_authority.record_grant_on_timeline(
        fixture.timeline,
        &grant(fixture.token.subject_id(), fixture.token.grantee_id(), true),
    );
    let request = request(
        fixture.timeline,
        fixture.descriptor,
        &fixture.evaluation,
        &foreign_token,
    );

    assert!(matches!(
        fixture
            .store
            .publish_recipient_export(&foreign_authority, &fixture.owner, &request),
        Err(RecipientExportPublicationErrorV1::Consent(
            pos_core::ConsentError::NoConsent
        ))
    ));
    Ok(())
}

#[test]
fn publication_rejects_a_recipient_owner_for_another_consent_grantee() -> TestResult {
    let mut fixture = fixture(true)?;
    let foreign_directory = fixture.temporary.path().join("foreign-recipient-private");
    std::fs::create_dir(&foreign_directory)?;
    std::fs::set_permissions(&foreign_directory, std::fs::Permissions::from_mode(0o700))?;
    let foreign_owner = RecipientKeyOwnerV1::open(&foreign_directory, EntityId::new())?;
    let request = request(
        fixture.timeline,
        fixture.descriptor,
        &fixture.evaluation,
        &fixture.token,
    );

    assert!(matches!(
        fixture
            .store
            .publish_recipient_export(&fixture.authority, &foreign_owner, &request),
        Err(RecipientExportPublicationErrorV1::RecipientMismatch)
    ));
    Ok(())
}

#[test]
fn publication_holds_the_erasure_export_fence() -> TestResult {
    let mut fixture = fixture(true)?;
    fixture.gate.block_timeline(fixture.timeline);
    let request = request(
        fixture.timeline,
        fixture.descriptor,
        &fixture.evaluation,
        &fixture.token,
    );
    let error = fixture
        .store
        .publish_recipient_export(&fixture.authority, &fixture.owner, &request)
        .err()
        .ok_or("publication unexpectedly succeeded")?;
    assert!(matches!(
        error,
        RecipientExportPublicationErrorV1::Store(CoreError::ErasureContainmentUnavailable)
    ));
    Ok(())
}

#[test]
fn reader_treats_an_absent_catalog_as_an_unavailable_artifact() -> TestResult {
    let fixture = fixture(true)?;
    assert!(matches!(
        fixture
            .store
            .read_recipient_export(&fixture.owner, [99; 16]),
        Err(RecipientExportPublicationErrorV1::ArtifactUnavailable)
    ));
    Ok(())
}

#[test]
fn publication_rejects_a_token_for_another_timeline() -> TestResult {
    let mut fixture = fixture(true)?;
    let request = request(
        pos_core::TimelineId::new(),
        fixture.descriptor,
        &fixture.evaluation,
        &fixture.token,
    );
    assert!(matches!(
        fixture
            .store
            .publish_recipient_export(&fixture.authority, &fixture.owner, &request),
        Err(RecipientExportPublicationErrorV1::Consent(
            pos_core::ConsentError::NoConsent
        ))
    ));
    Ok(())
}

#[test]
fn publication_rejects_a_revoked_consent_capability() -> TestResult {
    let mut fixture = fixture(true)?;
    ConsentGate::fence_timeline_at(&fixture.authority, fixture.timeline, 1)?;
    let request = request(
        fixture.timeline,
        fixture.descriptor,
        &fixture.evaluation,
        &fixture.token,
    );
    assert!(matches!(
        fixture
            .store
            .publish_recipient_export(&fixture.authority, &fixture.owner, &request),
        Err(RecipientExportPublicationErrorV1::Consent(
            pos_core::ConsentError::Revoked
        ))
    ));
    Ok(())
}

#[test]
fn publication_rejects_an_inactive_recipient_key() -> TestResult {
    let mut fixture = fixture(true)?;
    let stale_descriptor = fixture.descriptor;
    let _replacement = fixture.store.enroll_recipient_key(&fixture.owner)?;
    let request = request(
        fixture.timeline,
        stale_descriptor,
        &fixture.evaluation,
        &fixture.token,
    );
    assert!(matches!(
        fixture
            .store
            .publish_recipient_export(&fixture.authority, &fixture.owner, &request),
        Err(RecipientExportPublicationErrorV1::Registry(
            KeyRegistryErrorV1::InactiveKey
        ))
    ));
    Ok(())
}

#[test]
fn publication_rejects_a_pending_recipient_key_destruction() -> TestResult {
    let mut fixture = fixture(true)?;
    let registry = fixture
        .store
        .load_key_registry()?
        .ok_or("recipient registry is unavailable")?;
    let digest = registry
        .key_record(fixture.descriptor.identity())
        .and_then(|record| record.private_material_digest)
        .ok_or("recipient material is unavailable")?;
    fixture
        .store
        .begin_key_registry_destruction(KeyDestructionRequestV1::new(
            fixture.descriptor.identity(),
            digest,
            Hash::from_bytes([51; 32]),
        ))?;
    let request = request(
        fixture.timeline,
        fixture.descriptor,
        &fixture.evaluation,
        &fixture.token,
    );
    assert!(matches!(
        fixture
            .store
            .publish_recipient_export(&fixture.authority, &fixture.owner, &request),
        Err(RecipientExportPublicationErrorV1::Registry(
            KeyRegistryErrorV1::DestructionPending
        ))
    ));
    Ok(())
}

#[test]
fn publication_rejects_a_destroyed_recipient_key() -> TestResult {
    let mut fixture = fixture(true)?;
    fixture.store.destroy_recipient_key(
        &fixture.owner,
        fixture.descriptor.identity().epoch,
        Hash::from_bytes([52; 32]),
    )?;
    let request = request(
        fixture.timeline,
        fixture.descriptor,
        &fixture.evaluation,
        &fixture.token,
    );
    assert!(matches!(
        fixture
            .store
            .publish_recipient_export(&fixture.authority, &fixture.owner, &request),
        Err(RecipientExportPublicationErrorV1::Registry(
            KeyRegistryErrorV1::Destroyed
        ))
    ));
    Ok(())
}
