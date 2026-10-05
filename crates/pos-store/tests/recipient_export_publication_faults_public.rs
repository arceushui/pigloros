#![cfg(all(feature = "sqlite", feature = "test-support", target_os = "linux"))]

//! Public failure contracts for durable recipient-export publication.

use std::{
    io,
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    sync::{mpsc, Arc},
    thread,
    time::Duration,
};

use pos_core::{
    ArtifactClaimInputV1, ArtifactDataClassV1, ArtifactOptionalityV1, ArtifactStateV1,
    ArtifactTransitionRuleV1, CanonicalBytes, ConsentAuthority, ConsentGate, EntityId,
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
    gate: Arc<ErasureContainmentGateV1>,
}

struct PausedPublication {
    _temporary: tempfile::TempDir,
    entered: mpsc::Receiver<()>,
    release: mpsc::Sender<()>,
    join: thread::JoinHandle<Result<(), io::Error>>,
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
    let gate = Arc::new(ErasureContainmentGateV1::new_test_open());
    store.bind_erasure_gate(Arc::clone(&gate))?;

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
        gate,
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

fn start_paused_publication(fixture: Fixture) -> TestResult<PausedPublication> {
    let Fixture {
        temporary,
        store,
        owner,
        authority,
        token,
        timeline,
        descriptor,
        evaluation,
        ..
    } = fixture;
    let (entered_tx, entered) = mpsc::channel();
    let (release, release_rx) = mpsc::channel();
    store.pause_recipient_export_publication_after_fences_for_test(
        timeline, entered_tx, release_rx,
    )?;
    let join = thread::spawn(move || {
        let mut store = store;
        store
            .publish_recipient_export(
                &authority,
                &owner,
                &request(timeline, descriptor, &evaluation, &token),
            )
            .map(|_| ())
            .map_err(|error| io::Error::other(error.to_string()))
    });
    Ok(PausedPublication {
        _temporary: temporary,
        entered,
        release,
        join,
    })
}

fn join_publication(publication: PausedPublication) -> TestResult {
    let result = publication
        .join
        .join()
        .map_err(|_| io::Error::other("recipient publication thread panicked"))?;
    result?;
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
fn source_head_race_fails_closed_at_the_public_boundary() -> TestResult {
    let mut fixture = fixture()?;
    let export_id = [41; 16];
    fixture
        .store
        .set_recipient_export_publication_test_export_id(export_id)?;
    fixture
        .store
        .inject_recipient_export_publication_test_fault(
            RecipientExportPublicationTestFaultV1::SourceHeadChanged,
        )?;
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
    Ok(())
}

#[test]
fn consent_revocation_cannot_interleave_with_catalog_publication() -> TestResult {
    let fixture = fixture()?;
    let revocation_authority = fixture.authority.clone();
    let subject = fixture.token.subject_id();
    let timeline = fixture.timeline;
    let publication = start_paused_publication(fixture)?;
    publication.entered.recv_timeout(Duration::from_secs(1))?;

    let (started_tx, started) = mpsc::channel();
    let (finished_tx, finished) = mpsc::channel();
    let revoker = thread::spawn(move || -> Result<(), io::Error> {
        started_tx
            .send(())
            .map_err(|_| io::Error::other("revocation start observer is unavailable"))?;
        let mut append = || {};
        ConsentGate::with_revocation_fence(
            &revocation_authority,
            timeline,
            Some(subject),
            2,
            &mut append,
        )
        .map_err(|error| io::Error::other(error.to_string()))?;
        finished_tx
            .send(())
            .map_err(|_| io::Error::other("revocation completion observer is unavailable"))
    });
    started.recv_timeout(Duration::from_secs(1))?;
    assert!(finished.recv_timeout(Duration::from_millis(100)).is_err());
    assert!(!publication.join.is_finished());
    publication.release.send(())?;
    join_publication(publication)?;
    finished.recv_timeout(Duration::from_secs(1))?;
    let result = revoker
        .join()
        .map_err(|_| io::Error::other("revocation thread panicked"))?;
    result?;
    Ok(())
}

#[test]
fn erasure_block_cannot_interleave_with_catalog_publication() -> TestResult {
    let fixture = fixture()?;
    let blocking_gate = Arc::clone(&fixture.gate);
    let timeline = fixture.timeline;
    let publication = start_paused_publication(fixture)?;
    publication.entered.recv_timeout(Duration::from_secs(1))?;

    let (started_tx, started) = mpsc::channel();
    let (finished_tx, finished) = mpsc::channel();
    let blocker = thread::spawn(move || -> Result<(), io::Error> {
        started_tx
            .send(())
            .map_err(|_| io::Error::other("erasure-block start observer is unavailable"))?;
        blocking_gate.block_timeline(timeline);
        finished_tx
            .send(())
            .map_err(|_| io::Error::other("erasure-block completion observer is unavailable"))
    });
    started.recv_timeout(Duration::from_secs(1))?;
    assert!(finished.recv_timeout(Duration::from_millis(100)).is_err());
    assert!(!publication.join.is_finished());
    publication.release.send(())?;
    join_publication(publication)?;
    finished.recv_timeout(Duration::from_secs(1))?;
    let result = blocker
        .join()
        .map_err(|_| io::Error::other("erasure-block thread panicked"))?;
    result?;
    Ok(())
}

#[test]
fn test_support_pause_failures_stay_closed() -> TestResult {
    let mut first_fixture = fixture()?;
    let (entered_tx, entered) = mpsc::channel();
    let (_release, release_rx) = mpsc::channel();
    first_fixture
        .store
        .pause_recipient_export_publication_after_fences_for_test(
            first_fixture.timeline,
            entered_tx,
            release_rx,
        )?;
    let (duplicate_entered_tx, _duplicate_entered) = mpsc::channel();
    let (_duplicate_release, duplicate_release_rx) = mpsc::channel();
    assert!(first_fixture
        .store
        .pause_recipient_export_publication_after_fences_for_test(
            first_fixture.timeline,
            duplicate_entered_tx,
            duplicate_release_rx,
        )
        .is_err());
    drop(entered);
    assert!(first_fixture
        .store
        .publish_recipient_export(
            &first_fixture.authority,
            &first_fixture.owner,
            &request(
                first_fixture.timeline,
                first_fixture.descriptor,
                &first_fixture.evaluation,
                &first_fixture.token,
            ),
        )
        .is_err());

    let mut fixture = fixture()?;
    let (entered_tx, entered) = mpsc::channel();
    let (release, release_rx) = mpsc::channel();
    fixture
        .store
        .pause_recipient_export_publication_after_fences_for_test(
            fixture.timeline,
            entered_tx,
            release_rx,
        )?;
    drop(release);
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
    entered.recv_timeout(Duration::from_secs(1))?;
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
