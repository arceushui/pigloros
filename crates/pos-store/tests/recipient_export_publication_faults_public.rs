#![cfg(all(feature = "sqlite", feature = "test-support", target_os = "linux"))]

//! Public failure contracts for durable recipient-export publication.

use std::{os::unix::fs::PermissionsExt, path::PathBuf, sync::Arc};

use pos_core::{
    ArtifactClaimInputV1, ArtifactDataClassV1, ArtifactOptionalityV1, ArtifactStateV1,
    ArtifactTransitionRuleV1, CanonicalBytes, ConsentAuthority, ConsentError, CoreError, EntityId,
    ErasureArtifactClassV1, ErasureContainmentGateV1, ErasureReferenceV1, ErasureReplayClaimV1,
    EventDraft, EventStore, Kind, RegisteredArtifactV1, ReplayClaimEvaluationV1,
    ReplayClaimEvaluatorV1, TimelineMeta,
};
use pos_store::sqlite::{
    RecipientExportPublicationErrorV1, RecipientExportPublicationTestArtifactsV1,
    RecipientExportPublicationTestFaultV1, RecipientExportRequestV1, RecipientKeyOwnerV1,
    SqliteStore,
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const EXPORT_DIGEST: ErasureReferenceV1 = ErasureReferenceV1::from_digest([241; 32]);

struct Fixture {
    temporary: tempfile::TempDir,
    database: PathBuf,
    directory: PathBuf,
    grantee: EntityId,
    store: SqliteStore,
    owner: RecipientKeyOwnerV1,
    authority: ConsentAuthority,
    token: pos_core::ConsentCapabilityToken,
    timeline: pos_core::TimelineId,
    descriptor: pos_core::RecipientKeyDescriptorV1,
    evaluation: ReplayClaimEvaluationV1,
}

fn evaluation() -> TestResult<ReplayClaimEvaluationV1> {
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

fn fixture() -> TestResult<Fixture> {
    let temporary = tempfile::tempdir()?;
    let directory = temporary.path().join("recipient-private");
    std::fs::create_dir(&directory)?;
    std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700))?;
    let database = temporary.path().join("recipient.sqlite");
    let mut store = SqliteStore::open(database.to_str().ok_or("database path is not UTF-8")?)?;
    store.bind_erasure_gate(Arc::new(ErasureContainmentGateV1::new_test_open()))?;

    let subject = EntityId::new();
    let grantee = EntityId::new();
    let timeline =
        store.create_timeline_with_meta(TimelineMeta::root_owned("recipient-faults", subject))?;
    store.append(
        timeline.id(),
        &[EventDraft::new(
            EntityId::new(),
            Kind::new("recipient.export.public-fault.v1"),
            CanonicalBytes::from_static(b"recipient-export-public-fault"),
        )],
    )?;

    let authority = ConsentAuthority::new();
    store.bind_consent_authority(authority.append_permit())?;
    let token = authority.record_grant_on_timeline(
        timeline.id(),
        &pos_core::ConsentGrantedV1 {
            subject_id: subject,
            grantee_id: grantee,
            purpose: "recipient-export-public-fault".to_owned(),
            modalities: pos_core::MODALITY_EXPORT,
            min_geo_resolution: 0,
            fork_permitted: false,
            export_permitted: true,
            retention_days: 1,
            expiry_secs: 0,
            grant_seq: 1,
        },
    );
    let owner = RecipientKeyOwnerV1::open(&directory, grantee)?;
    let descriptor = store.enroll_recipient_key(&owner)?;
    Ok(Fixture {
        temporary,
        database,
        directory,
        grantee,
        store,
        owner,
        authority,
        token,
        timeline: timeline.id(),
        descriptor,
        evaluation: evaluation()?,
    })
}

const fn request<'a>(
    timeline_id: pos_core::TimelineId,
    recipient: pos_core::RecipientKeyDescriptorV1,
    evaluation: &'a ReplayClaimEvaluationV1,
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

const fn artifacts(
    staging_ciphertext_exists: bool,
    final_ciphertext_exists: bool,
) -> RecipientExportPublicationTestArtifactsV1 {
    RecipientExportPublicationTestArtifactsV1 {
        staging_ciphertext_exists,
        final_ciphertext_exists,
        named_plaintext_observed: false,
    }
}

fn assert_not_public(
    store: &SqliteStore,
    owner: &RecipientKeyOwnerV1,
    export_id: [u8; 16],
    expected: RecipientExportPublicationTestArtifactsV1,
) -> TestResult {
    assert!(matches!(
        store.read_recipient_export(owner, export_id),
        Err(RecipientExportPublicationErrorV1::ArtifactUnavailable)
    ));
    assert_eq!(
        store.inspect_recipient_export_publication_test_artifacts(owner, export_id)?,
        expected
    );
    Ok(())
}

fn restart(fixture: Fixture) -> TestResult<(tempfile::TempDir, SqliteStore, RecipientKeyOwnerV1)> {
    let Fixture {
        temporary,
        database,
        directory,
        grantee,
        store,
        owner,
        ..
    } = fixture;
    drop(store);
    drop(owner);
    let store = SqliteStore::open(database.to_str().ok_or("database path is not UTF-8")?)?;
    let owner = RecipientKeyOwnerV1::open(directory, grantee)?;
    Ok((temporary, store, owner))
}

#[test]
fn publication_races_fail_closed_at_the_public_boundary() -> TestResult {
    for (fault, export_id) in [
        (
            RecipientExportPublicationTestFaultV1::SourceHeadChanged,
            [41; 16],
        ),
        (
            RecipientExportPublicationTestFaultV1::ConsentRevoked,
            [42; 16],
        ),
        (
            RecipientExportPublicationTestFaultV1::ErasureBlocked,
            [43; 16],
        ),
    ] {
        let mut fixture = fixture()?;
        fixture
            .store
            .set_recipient_export_publication_test_export_id(export_id)?;
        fixture
            .store
            .inject_recipient_export_publication_test_fault(fault)?;
        let publication = fixture.store.publish_recipient_export(
            &fixture.authority,
            &fixture.owner,
            &request(
                fixture.timeline,
                fixture.descriptor,
                &fixture.evaluation,
                &fixture.token,
            ),
        );
        match fault {
            RecipientExportPublicationTestFaultV1::SourceHeadChanged => {
                assert!(matches!(
                    publication,
                    Err(RecipientExportPublicationErrorV1::SourceChanged)
                ));
            }
            RecipientExportPublicationTestFaultV1::ConsentRevoked => {
                assert!(matches!(
                    publication,
                    Err(RecipientExportPublicationErrorV1::Consent(
                        ConsentError::Revoked
                    ))
                ));
            }
            RecipientExportPublicationTestFaultV1::ErasureBlocked => {
                assert!(matches!(
                    publication,
                    Err(RecipientExportPublicationErrorV1::Store(
                        CoreError::ErasureContainmentUnavailable
                    ))
                ));
            }
            _ => {
                return Err(std::io::Error::other("only public race faults are configured").into())
            }
        }
        assert_not_public(
            &fixture.store,
            &fixture.owner,
            export_id,
            artifacts(false, false),
        )?;
        fixture.store.recover_recipient_exports(&fixture.owner)?;
        assert_not_public(
            &fixture.store,
            &fixture.owner,
            export_id,
            artifacts(false, false),
        )?;
    }
    Ok(())
}

#[test]
fn interrupted_publications_stay_hidden_and_recover_after_restart() -> TestResult {
    for (fault, export_id, expected_before_recovery) in [
        (
            RecipientExportPublicationTestFaultV1::StagingWrite,
            [51; 16],
            artifacts(true, false),
        ),
        (
            RecipientExportPublicationTestFaultV1::FileSync,
            [52; 16],
            artifacts(true, false),
        ),
        (
            RecipientExportPublicationTestFaultV1::DirectorySync,
            [53; 16],
            artifacts(false, true),
        ),
        (
            RecipientExportPublicationTestFaultV1::CatalogCommit,
            [54; 16],
            artifacts(false, true),
        ),
    ] {
        let mut fixture = fixture()?;
        fixture
            .store
            .set_recipient_export_publication_test_export_id(export_id)?;
        fixture
            .store
            .inject_recipient_export_publication_test_fault(fault)?;
        assert!(fixture
            .store
            .publish_recipient_export(
                &fixture.authority,
                &fixture.owner,
                &request(
                    fixture.timeline,
                    fixture.descriptor,
                    &fixture.evaluation,
                    &fixture.token,
                ),
            )
            .is_err());
        assert_not_public(
            &fixture.store,
            &fixture.owner,
            export_id,
            expected_before_recovery,
        )?;

        let (_temporary, mut restarted, restarted_owner) = restart(fixture)?;
        assert_not_public(
            &restarted,
            &restarted_owner,
            export_id,
            expected_before_recovery,
        )?;
        restarted.recover_recipient_exports(&restarted_owner)?;
        assert_not_public(
            &restarted,
            &restarted_owner,
            export_id,
            artifacts(false, false),
        )?;
    }
    Ok(())
}

#[test]
fn identifier_collisions_preserve_the_existing_public_ciphertext() -> TestResult {
    let mut fixture = fixture()?;
    let export_id = [71; 16];
    fixture
        .store
        .set_recipient_export_publication_test_export_id(export_id)?;
    let publication = fixture.store.publish_recipient_export(
        &fixture.authority,
        &fixture.owner,
        &request(
            fixture.timeline,
            fixture.descriptor,
            &fixture.evaluation,
            &fixture.token,
        ),
    )?;
    assert_eq!(publication.export_id, export_id);
    let original = fixture
        .store
        .read_recipient_export(&fixture.owner, export_id)?;

    fixture
        .store
        .set_recipient_export_publication_test_export_id(export_id)?;
    assert!(matches!(
        fixture.store.publish_recipient_export(
            &fixture.authority,
            &fixture.owner,
            &request(
                fixture.timeline,
                fixture.descriptor,
                &fixture.evaluation,
                &fixture.token,
            ),
        ),
        Err(RecipientExportPublicationErrorV1::IdentifierCollision)
    ));
    assert_eq!(
        fixture
            .store
            .read_recipient_export(&fixture.owner, export_id)?,
        original
    );
    assert_eq!(
        fixture
            .store
            .inspect_recipient_export_publication_test_artifacts(&fixture.owner, export_id)?,
        artifacts(false, true)
    );
    Ok(())
}

#[test]
fn test_support_rejects_ambiguous_fault_configuration() -> TestResult {
    let mut fixture = fixture()?;
    assert!(fixture
        .store
        .set_recipient_export_publication_test_export_id([0; 16])
        .is_err());
    fixture
        .store
        .set_recipient_export_publication_test_export_id([61; 16])?;
    assert!(fixture
        .store
        .set_recipient_export_publication_test_export_id([62; 16])
        .is_err());
    fixture
        .store
        .inject_recipient_export_publication_test_fault(
            RecipientExportPublicationTestFaultV1::SourceHeadChanged,
        )?;
    assert!(fixture
        .store
        .inject_recipient_export_publication_test_fault(
            RecipientExportPublicationTestFaultV1::StagingWrite,
        )
        .is_err());
    assert!(matches!(
        fixture.store.publish_recipient_export(
            &fixture.authority,
            &fixture.owner,
            &request(
                fixture.timeline,
                fixture.descriptor,
                &fixture.evaluation,
                &fixture.token,
            ),
        ),
        Err(RecipientExportPublicationErrorV1::SourceChanged)
    ));
    Ok(())
}
