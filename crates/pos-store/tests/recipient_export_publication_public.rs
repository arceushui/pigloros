#![cfg(all(feature = "sqlite", target_os = "linux"))]

//! Public contracts for durable authorized recipient-export publication.

use std::{os::unix::fs::PermissionsExt, sync::Arc};

use pos_core::{
    ArtifactClaimInputV1, ArtifactDataClassV1, ArtifactOptionalityV1, ArtifactStateV1,
    ArtifactTransitionRuleV1, CanonicalBytes, ConsentAuthority, ConsentGate, ConsentGrantedV1,
    CoreError, EntityId, ErasureArtifactClassV1, ErasureContainmentGateV1, ErasureErrorV1,
    ErasureInventoryPersistencePortV1, ErasureReferenceV1, ErasureReplayClaimV1, EventDraft,
    EventStore, Hash, KeyDestructionRequestV1, KeyRegistryErrorV1, Kind, OwnerIdV1,
    RecipientExportPublicationRowV1, RegisteredArtifactV1, ReplayClaimEvaluatorV1, TimelineId,
    TimelineMeta,
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
    unaffected_timeline: pos_core::TimelineId,
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
    let unaffected_timeline = store.create_timeline_with_meta(TimelineMeta::root_owned(
        "recipient-export-unaffected",
        subject,
    ))?;
    for source in [timeline.id(), unaffected_timeline.id()] {
        store.append(
            source,
            &[EventDraft::new(
                EntityId::new(),
                Kind::new("recipient.export.public.v1"),
                CanonicalBytes::from_static(b"encrypted-recipient-export"),
            )],
        )?;
    }

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
        unaffected_timeline: unaffected_timeline.id(),
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

fn publish_affected_and_unaffected(
    fixture: &mut Fixture,
) -> TestResult<(
    pos_store::sqlite::PublishedRecipientExportV1,
    pos_store::sqlite::PublishedRecipientExportV1,
)> {
    let affected = fixture.store.publish_recipient_export(
        &fixture.authority,
        &fixture.owner,
        &request(
            fixture.timeline,
            fixture.descriptor,
            &fixture.evaluation,
            &fixture.token,
        ),
    )?;
    let unaffected_token = fixture.authority.record_grant_on_timeline(
        fixture.unaffected_timeline,
        &grant(fixture.token.subject_id(), fixture.token.grantee_id(), true),
    );
    let unaffected = fixture.store.publish_recipient_export(
        &fixture.authority,
        &fixture.owner,
        &request(
            fixture.unaffected_timeline,
            fixture.descriptor,
            &fixture.evaluation,
            &unaffected_token,
        ),
    )?;
    Ok((affected, unaffected))
}

/// ADR-138 acceptance test 12: after `AccessFrozen`, an affected publication
/// is refused and an unaffected one is still served.
#[test]
fn reader_refuses_an_access_frozen_publication_and_serves_an_unaffected_one() -> TestResult {
    let mut fixture = fixture(true)?;
    let (affected, unaffected) = publish_affected_and_unaffected(&mut fixture)?;
    let held = fixture
        .store
        .read_recipient_export(&fixture.owner, affected.export_id)?;

    fixture.gate.freeze_timeline_for_test(fixture.timeline);

    assert!(matches!(
        fixture
            .store
            .read_recipient_export(&fixture.owner, affected.export_id),
        Err(RecipientExportPublicationErrorV1::ArtifactUnavailable)
    ));
    let served = fixture
        .store
        .read_recipient_export(&fixture.owner, unaffected.export_id)?;
    assert_eq!(u64::try_from(served.len())?, unaffected.ciphertext_length);
    let decrypted = fixture.store.decrypt_recipient_export(
        &fixture.owner,
        &served,
        unaffected.export_id,
        unaffected.recipient,
    )?;
    assert_eq!(decrypted.export.timeline.id(), fixture.unaffected_timeline);

    // Decryption stays unfenced: bytes the caller already holds still open.
    let decrypted = fixture.store.decrypt_recipient_export(
        &fixture.owner,
        &held,
        affected.export_id,
        affected.recipient,
    )?;
    assert_eq!(decrypted.export.timeline.id(), fixture.timeline);
    Ok(())
}

#[test]
fn reader_keeps_an_unrecoverable_containment_boundary_a_store_failure() -> TestResult {
    let mut fixture = fixture(true)?;
    let (affected, unaffected) = publish_affected_and_unaffected(&mut fixture)?;

    fixture.gate.block_timeline(fixture.timeline);

    assert!(matches!(
        fixture
            .store
            .read_recipient_export(&fixture.owner, affected.export_id),
        Err(RecipientExportPublicationErrorV1::Store(
            CoreError::ErasureContainmentUnavailable
        ))
    ));
    assert!(fixture
        .store
        .read_recipient_export(&fixture.owner, unaffected.export_id)
        .is_ok());
    Ok(())
}

/// Copy the published catalog row under another export identity, Timeline
/// and grantee owner, as a second publication would record it.
fn copy_publication(
    path: &std::path::Path,
    source: [u8; 16],
    copy: RecipientExportPublicationRowV1,
) -> TestResult {
    rusqlite::Connection::open(path)?.execute(
        "INSERT INTO recipient_export_catalog_v1
         SELECT ?1, ?2, recipient_epoch, recipient_descriptor, ?3, local_head, logical_head,
                ciphertext_length, ciphertext_digest
         FROM recipient_export_catalog_v1 WHERE export_id = ?4",
        rusqlite::params![
            copy.export_id.as_slice(),
            copy.grantee_owner.as_str(),
            copy.timeline.to_string(),
            source.as_slice(),
        ],
    )?;
    Ok(())
}

/// One real publication from Timeline A, then three catalog rows across
/// Timelines A and B and two grantees.
fn published_catalog() -> TestResult<(Fixture, Vec<RecipientExportPublicationRowV1>)> {
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
    let grantee = fixture.descriptor.identity().owner_id;
    let other_grantee = OwnerIdV1::new("recipient-export-second-grantee")?;
    let other_timeline = TimelineId::new();
    let path = fixture.temporary.path().join("recipient.sqlite");
    let mut expected = vec![RecipientExportPublicationRowV1 {
        export_id: publication.export_id,
        timeline: fixture.timeline,
        grantee_owner: grantee,
    }];
    for (export_id, timeline, grantee_owner) in [
        ([0x00; 16], fixture.timeline, other_grantee),
        ([0x01; 16], other_timeline, grantee),
        ([0xff; 16], other_timeline, other_grantee),
    ] {
        let copy = RecipientExportPublicationRowV1 {
            export_id,
            timeline,
            grantee_owner,
        };
        copy_publication(&path, publication.export_id, copy)?;
        expected.push(copy);
    }
    expected.sort_by_key(|row| (row.timeline, row.export_id));
    Ok((fixture, expected))
}

#[test]
fn erasure_reads_visible_publications_by_timeline_and_grantee() -> TestResult {
    let (mut fixture, expected) = published_catalog()?;
    let timeline = fixture.timeline;
    let other = expected
        .iter()
        .map(|row| row.timeline)
        .find(|candidate| *candidate != timeline)
        .ok_or("the catalog has no second Timeline")?;
    // Duplicate and unsorted Timelines read each Timeline once, in order.
    let requested = [other, timeline, other];
    assert_eq!(
        fixture.store.recipient_export_publications(&requested, 4)?,
        expected
    );
    assert_eq!(
        fixture.store.recipient_export_publications(&requested, 3),
        Err(ErasureErrorV1::ScopeInvalid)
    );
    let only_timeline: Vec<_> = expected
        .iter()
        .copied()
        .filter(|row| row.timeline == timeline)
        .collect();
    assert_eq!(only_timeline.len(), 2);
    assert_eq!(
        fixture
            .store
            .recipient_export_publications(&[timeline], 2)?,
        only_timeline
    );
    assert!(fixture
        .store
        .recipient_export_publications(&[TimelineId::new()], 0)?
        .is_empty());

    // A pending publication of the same Timeline is not visible.
    let path = fixture.temporary.path().join("recipient.sqlite");
    rusqlite::Connection::open(&path)?.execute(
        "INSERT INTO recipient_export_pending_v1 (export_id, owner_id) VALUES (?1, ?2)",
        rusqlite::params![[0x02_u8; 16].as_slice(), expected[0].grantee_owner.as_str()],
    )?;
    assert_eq!(
        fixture.store.recipient_export_publications(&requested, 4)?,
        expected
    );
    let index: i64 = rusqlite::Connection::open(&path)?.query_row(
        "SELECT COUNT(*) FROM sqlite_schema
         WHERE type = 'index' AND name = 'recipient_export_catalog_timeline_v1'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(index, 1);
    let mut reopened = SqliteStore::open(path.to_str().ok_or("database path is not UTF-8")?)?;
    assert_eq!(
        reopened.recipient_export_publications(&requested, 4)?,
        expected
    );
    Ok(())
}

#[test]
fn erasure_publication_reads_fail_closed_for_malformed_catalog_rows() -> TestResult {
    for (sql, expected) in [
        (
            "UPDATE recipient_export_catalog_v1 SET owner_id = ''",
            ErasureErrorV1::ProvenanceMissing,
        ),
        (
            "UPDATE recipient_export_catalog_v1 SET export_id = X'00'",
            ErasureErrorV1::ProvenanceMissing,
        ),
        (
            "UPDATE recipient_export_catalog_v1 SET export_id = 'sixteen-chars-id'",
            ErasureErrorV1::ReceiptCommitFailed,
        ),
    ] {
        let (mut fixture, expected_rows) = published_catalog()?;
        let path = fixture.temporary.path().join("recipient.sqlite");
        let connection = rusqlite::Connection::open(&path)?;
        connection.execute_batch("PRAGMA ignore_check_constraints = ON;")?;
        connection.execute(
            &format!("{sql} WHERE export_id = ?1"),
            rusqlite::params![expected_rows[0].export_id.as_slice()],
        )?;
        drop(connection);
        assert_eq!(
            fixture
                .store
                .recipient_export_publications(&[expected_rows[0].timeline], 4),
            Err(expected)
        );
    }
    Ok(())
}
