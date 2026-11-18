#![cfg(all(feature = "sqlite", target_os = "linux"))]

//! ADR-138 W1 recipient-export withdrawal at the store and port seams:
//! durability refusals (acceptance test 2), crash windows (3), object
//! binding (4), custody (5), reads and targets (7 and 8), keys (9),
//! isolation (10), adapter parity (11) and the sweep (13).

use std::{
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    sync::Arc,
};

use pos_core::{
    local_erasure_export_recipient_v1, ArtifactClaimInputV1, ArtifactDataClassV1,
    ArtifactOptionalityV1, ArtifactStateV1, ArtifactTransitionRuleV1, CanonicalBytes,
    ConsentAuthority, ConsentGrantedV1, EntityId, ErasureArtifactClassV1, ErasureContainmentGateV1,
    ErasureErrorV1, ErasureInventoryPersistencePortV1, ErasureRecoveryLimitsV1, ErasureReferenceV1,
    ErasureReplayClaimV1, EventDraft, EventStore, Hash, Kind, LocalErasureOwnerResultV1,
    LocalErasureRecipientExportWithdrawalV1, LocalOwnerEffectV1, LocalOwnerResultBindingV1,
    OwnerIdV1, PreparedLocalOwnerEffectV1, RecipientExportPublicationRowV1,
    RecipientExportWithdrawalBindingV1, RecipientExportWithdrawalRowV1,
    RecipientExportWithdrawalStateV1, RecipientKeyDescriptorV1, RegisteredArtifactV1,
    ReplayClaimEvaluationV1, ReplayClaimEvaluatorV1, TimelineId, TimelineMeta,
    ERASURE_MAX_OBLIGATIONS_PER_CATEGORY,
};
use pos_store::{
    memory::MemoryStore,
    sqlite::{
        RecipientCustodyAttachErrorV1, RecipientExportPublicationErrorV1, RecipientExportRequestV1,
        RecipientKeyOwnerV1, SqliteStore,
    },
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const EXPORT_DIGEST: ErasureReferenceV1 = ErasureReferenceV1::from_digest([241; 32]);

/// The record tags of the ADR-136/#1431 startup sweep (owner decision Q13
/// on #1431); ELXW1 is not one of them (ADR-138 §5, L5).
const SWEPT_TAGS: [&str; 6] = ["ELS1", "ELO1", "ELAD1", "ELCG1", "ELNEG1", "ELRP1"];

const CAPTURED: RecipientExportWithdrawalStateV1 = RecipientExportWithdrawalStateV1::Retracted {
    capture_status: 0,
    objects_deleted: false,
};

const DELETED: RecipientExportWithdrawalStateV1 = RecipientExportWithdrawalStateV1::Retracted {
    capture_status: 0,
    objects_deleted: true,
};

const fn retracted(capture_status: u8) -> RecipientExportWithdrawalStateV1 {
    RecipientExportWithdrawalStateV1::Retracted {
        capture_status,
        objects_deleted: false,
    }
}

struct Fixture {
    temporary: tempfile::TempDir,
    store: SqliteStore,
    owner: RecipientKeyOwnerV1,
    authority: ConsentAuthority,
    grantee: EntityId,
    descriptor: RecipientKeyDescriptorV1,
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

fn private_directory(path: &Path) -> TestResult<PathBuf> {
    std::fs::create_dir(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    Ok(path.to_path_buf())
}

impl Fixture {
    fn new() -> TestResult<Self> {
        let temporary = tempfile::tempdir()?;
        let directory = private_directory(&temporary.path().join("recipient-private"))?;
        let database = temporary.path().join("recipient.sqlite");
        let mut store = SqliteStore::open(database.to_str().ok_or("database path is not UTF-8")?)?;
        store.bind_erasure_gate(Arc::new(ErasureContainmentGateV1::new_test_open()))?;
        let authority = ConsentAuthority::new();
        store.bind_consent_authority(authority.append_permit())?;
        let grantee = EntityId::new();
        let owner = RecipientKeyOwnerV1::open(directory, grantee)?;
        let descriptor = store.enroll_recipient_key(&owner)?;
        let evaluation = evaluation()?;
        Ok(Self {
            temporary,
            store,
            owner,
            authority,
            grantee,
            descriptor,
            evaluation,
        })
    }

    fn directory(&self) -> PathBuf {
        self.temporary.path().join("recipient-private")
    }

    fn database(&self) -> PathBuf {
        self.temporary.path().join("recipient.sqlite")
    }

    fn grantee_owner(&self) -> OwnerIdV1 {
        self.descriptor.identity().owner_id
    }

    /// Publish one export of a fresh Timeline of a fresh subject to the
    /// fixture's grantee.
    fn publish(&mut self) -> TestResult<(TimelineId, [u8; 16])> {
        let subject = EntityId::new();
        let timeline = self
            .store
            .create_timeline_with_meta(TimelineMeta::root_owned("withdrawal", subject))?
            .id();
        self.store.append(
            timeline,
            &[EventDraft::new(
                EntityId::new(),
                Kind::new("recipient.export.withdrawal.v1"),
                CanonicalBytes::from_static(b"recipient-export-withdrawal"),
            )],
        )?;
        let token = self.authority.record_grant_on_timeline(
            timeline,
            &ConsentGrantedV1 {
                subject_id: subject,
                grantee_id: self.grantee,
                purpose: "recipient-export-withdrawal".to_owned(),
                modalities: pos_core::MODALITY_EXPORT,
                min_geo_resolution: 0,
                fork_permitted: false,
                export_permitted: true,
                retention_days: 1,
                expiry_secs: 0,
                grant_seq: 1,
            },
        );
        let request = RecipientExportRequestV1 {
            timeline_id: timeline,
            recipient: self.descriptor,
            artifact_digest: EXPORT_DIGEST,
            evaluation: &self.evaluation,
            token: &token,
            now_secs: 1,
        };
        let publication =
            self.store
                .publish_recipient_export(&self.authority, &self.owner, &request)?;
        Ok((timeline, publication.export_id))
    }

    /// A fresh custody handle on the fixture's directory.
    fn custody(&self) -> TestResult<RecipientKeyOwnerV1> {
        Ok(RecipientKeyOwnerV1::open(self.directory(), self.grantee)?)
    }

    fn attach(&mut self) -> TestResult {
        let custody = self.custody()?;
        self.store.attach_recipient_custody(vec![custody])?;
        Ok(())
    }

    /// A new store on the fixture's database, as after a restart.
    fn reopen(&self) -> TestResult<SqliteStore> {
        Ok(SqliteStore::open(
            self.database()
                .to_str()
                .ok_or("database path is not UTF-8")?,
        )?)
    }

    fn final_path(&self, export_id: [u8; 16]) -> PathBuf {
        self.directory().join(object_name(export_id, ".trx1"))
    }

    fn staging_path(&self, export_id: [u8; 16]) -> PathBuf {
        self.directory()
            .join(object_name(export_id, ".trx1.staging"))
    }
}

fn object_name(export_id: [u8; 16], suffix: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let hex: String = export_id
        .iter()
        .flat_map(|byte| [HEX[usize::from(byte >> 4)], HEX[usize::from(byte & 0x0f)]])
        .map(char::from)
        .collect();
    format!("recipient-export-{hex}{suffix}")
}

/// One ELXW1 of the recorded withdrawal row of `export_id`.
fn elxw1(
    database: &Path,
    export_id: [u8; 16],
    timeline: TimelineId,
    command: u8,
) -> TestResult<Vec<u8>> {
    let (owner, length, digest, directory, final_identity): (
        String,
        i64,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
    ) = rusqlite::Connection::open(database)?.query_row(
        "SELECT owner_id, ciphertext_length, ciphertext_digest, directory_identity,
                    final_identity
             FROM recipient_export_withdrawals_v1 WHERE export_id = ?1",
        rusqlite::params![export_id.as_slice()],
        |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
            ))
        },
    )?;
    Ok(LocalErasureRecipientExportWithdrawalV1 {
        request: ErasureReferenceV1::from_digest([1; 32]),
        command: ErasureReferenceV1::from_digest([command; 32]),
        export_id,
        timeline_id: timeline,
        grantee_owner: OwnerIdV1::new(owner)?,
        ciphertext_digest: Hash::from_bytes(digest.as_slice().try_into()?),
        ciphertext_length: u64::try_from(length)?,
        directory_identity: directory.as_slice().try_into()?,
        final_identity: final_identity.as_slice().try_into()?,
    }
    .to_canonical_cbor()?)
}

/// A well-formed ELXW1 that names no recorded row.
fn unknown_elxw1(export_id: [u8; 16]) -> TestResult<Vec<u8>> {
    Ok(LocalErasureRecipientExportWithdrawalV1 {
        request: ErasureReferenceV1::from_digest([1; 32]),
        command: ErasureReferenceV1::from_digest([2; 32]),
        export_id,
        timeline_id: TimelineId::from_ulid(ulid::Ulid::from_bytes([3; 16])),
        grantee_owner: OwnerIdV1::new("recipient-export-unknown")?,
        ciphertext_digest: Hash::from_bytes([4; 32]),
        ciphertext_length: 5,
        directory_identity: [6; 16],
        final_identity: [7; 20],
    }
    .to_canonical_cbor()?)
}

/// The positive ELO1 preparation of `elxw1` under destruction command
/// `command`.
fn prepared(elxw1: Vec<u8>, command: u8) -> Result<PreparedLocalOwnerEffectV1, ErasureErrorV1> {
    PreparedLocalOwnerEffectV1::new(
        LocalOwnerEffectV1::RecipientExportWithdrawal(elxw1),
        LocalOwnerResultBindingV1 {
            request: ErasureReferenceV1::from_digest([1; 32]),
            attempt: ErasureReferenceV1::from_digest([8; 32]),
            obligation: ErasureReferenceV1::from_digest([9; 32]),
            command: ErasureReferenceV1::from_digest([command; 32]),
            owner_ref: ErasureReferenceV1::from_digest([10; 32]),
            error: None,
        },
    )
}

/// T1, the owner step, T1 again and T3 of one captured publication.
fn withdraw(
    store: &mut SqliteStore,
    database: &Path,
    grantee: &OwnerIdV1,
    (timeline, export_id): (TimelineId, [u8; 16]),
    command: u8,
) -> TestResult<(Vec<u8>, ErasureReferenceV1)> {
    assert_eq!(
        store.begin_recipient_export_withdrawal(export_id, grantee)?,
        CAPTURED
    );
    store.delete_recipient_export_ciphertext(export_id)?;
    assert_eq!(
        store.begin_recipient_export_withdrawal(export_id, grantee)?,
        DELETED
    );
    let elxw1 = elxw1(database, export_id, timeline, command)?;
    let elo1 = store.commit_local_owner_effect(prepared(elxw1.clone(), command)?)?;
    Ok((elxw1, elo1))
}

fn address(record: &[u8]) -> TestResult<ErasureReferenceV1> {
    Ok(pos_core::ErasureRetainedObjectV1::new(record, 1_024)?.reference())
}

const fn limits() -> Result<ErasureRecoveryLimitsV1, ErasureErrorV1> {
    ErasureRecoveryLimitsV1::from_maximum_requests(16)
}

/// Write a file of `bytes` with `mode` at `path` through a fresh inode that
/// replaces any existing name.
fn replace_file(path: &Path, bytes: &[u8], mode: u32) -> TestResult {
    let fresh = path.with_extension("replacement");
    std::fs::write(&fresh, bytes)?;
    std::fs::set_permissions(&fresh, std::fs::Permissions::from_mode(mode))?;
    std::fs::rename(fresh, path)?;
    Ok(())
}

/// One fixture with one publication and its custody attached.
fn published() -> TestResult<(Fixture, (TimelineId, [u8; 16]))> {
    let mut fixture = Fixture::new()?;
    let publication = fixture.publish()?;
    fixture.attach()?;
    Ok((fixture, publication))
}

#[test]
fn a_retracted_publication_is_enumerated_but_never_served_and_t1_repeats() -> TestResult {
    let (mut fixture, (timeline, export_id)) = published()?;
    let grantee = fixture.grantee_owner();
    let target = local_erasure_export_recipient_v1(export_id, &grantee)?;
    // Crash after T1: T1 again answers the same retracted state.
    for _ in 0..2 {
        assert_eq!(
            fixture
                .store
                .begin_recipient_export_withdrawal(export_id, &grantee)?,
            CAPTURED
        );
    }
    assert!(matches!(
        fixture
            .store
            .read_recipient_export(&fixture.owner, export_id),
        Err(RecipientExportPublicationErrorV1::ArtifactUnavailable)
    ));
    assert_eq!(
        fixture
            .store
            .recipient_export_publications(&[timeline], 4)?,
        [RecipientExportPublicationRowV1 {
            export_id,
            timeline,
            grantee_owner: grantee,
        }]
    );
    assert_eq!(
        fixture
            .store
            .erasure_authority_snapshot_with_limits(limits()?, &[target])?
            .recipient_export_withdrawals(),
        [RecipientExportWithdrawalRowV1 {
            target,
            export_id,
            disposition: None,
            committed_elo1: None,
        }]
    );
    // Crash after the unlink, and after T2: the owner step accepts the
    // absent captured name and records the deletion again.
    assert!(fixture.final_path(export_id).exists());
    fixture
        .store
        .delete_recipient_export_ciphertext(export_id)?;
    assert!(!fixture.final_path(export_id).exists());
    fixture
        .store
        .delete_recipient_export_ciphertext(export_id)?;
    assert_eq!(
        fixture
            .store
            .begin_recipient_export_withdrawal(export_id, &grantee)?,
        DELETED
    );
    Ok(())
}

#[test]
fn t3_withdraws_once_and_every_replay_is_byte_identical() -> TestResult {
    let (mut fixture, (timeline, export_id)) = published()?;
    let grantee = fixture.grantee_owner();
    let target = local_erasure_export_recipient_v1(export_id, &grantee)?;
    let database = fixture.database();
    fixture
        .store
        .begin_recipient_export_withdrawal(export_id, &grantee)?;
    let deleted = fixture
        .store
        .delete_recipient_export_ciphertext(export_id)?;
    // T3, then a crash after T3: the same ELXW1 and ELO1 commit again.
    let record = elxw1(&database, export_id, timeline, 5)?;
    // The owner step returns exactly the binding the recorded row's ELXW1
    // carries, and a repeat before T3 returns it again.
    assert_eq!(
        deleted,
        RecipientExportWithdrawalBindingV1::from(
            &LocalErasureRecipientExportWithdrawalV1::from_canonical_cbor(&record)?
        )
    );
    assert_eq!(
        fixture.store.delete_recipient_export_ciphertext(export_id),
        Ok(deleted)
    );
    let elo1 = fixture
        .store
        .commit_local_owner_effect(prepared(record.clone(), 5)?)?;
    assert_eq!(
        fixture
            .store
            .commit_local_owner_effect(prepared(record.clone(), 5)?)?,
        elo1
    );
    let disposition = address(&record)?;
    let committed = fixture.store.retained_erasure_objects("ELO1", 4)?;
    assert_eq!(committed.len(), 1);
    assert_eq!(
        LocalErasureOwnerResultV1::from_canonical_cbor(&committed[0])?.effect_digest,
        disposition
    );
    // The catalog row is gone, and the withdrawal row carries the
    // disposition and the first ELO1.
    assert!(fixture
        .store
        .recipient_export_publications(&[timeline], 4)?
        .is_empty());
    let row = RecipientExportWithdrawalRowV1 {
        target,
        export_id,
        disposition: Some(disposition),
        committed_elo1: Some(elo1),
    };
    assert_eq!(
        fixture
            .store
            .erasure_authority_snapshot_with_limits(limits()?, &[target, target])?
            .recipient_export_withdrawals(),
        [row]
    );
    // A later command binds a new positive ELO1 to the recorded
    // disposition; another ELXW1 and another owner step are refused.
    assert_ne!(
        fixture
            .store
            .commit_local_owner_effect(prepared(record.clone(), 6)?)?,
        elo1
    );
    assert_eq!(
        fixture
            .store
            .commit_local_owner_effect(prepared(elxw1(&database, export_id, timeline, 7)?, 7)?),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
    assert_eq!(
        fixture.store.delete_recipient_export_ciphertext(export_id),
        Err(ErasureErrorV1::ArtifactDeletionFailed)
    );
    // The startup sweep never deletes ELXW1, and the withdrawal survives a
    // reopen byte for byte.
    fixture
        .store
        .sweep_unreferenced_erasure_objects(&SWEPT_TAGS, &[], 64)?;
    let mut reopened = fixture.reopen()?;
    assert_eq!(
        reopened.retained_erasure_objects("ELXW1", 4)?,
        [record.clone()]
    );
    assert_eq!(
        reopened.begin_recipient_export_withdrawal(export_id, &grantee)?,
        RecipientExportWithdrawalStateV1::Withdrawn {
            disposition,
            elxw1: record,
        }
    );
    assert_eq!(
        reopened
            .erasure_authority_snapshot_with_limits(limits()?, &[target])?
            .recipient_export_withdrawals(),
        [row]
    );
    Ok(())
}

#[test]
fn a_withdrawal_needs_its_own_owner_and_a_matching_deleted_capture() -> TestResult {
    let (mut fixture, (timeline, export_id)) = published()?;
    let grantee = fixture.grantee_owner();
    let other = OwnerIdV1::new("recipient-export-other-grantee")?;
    let database = fixture.database();
    for owner in [other, grantee, other] {
        let answer = fixture
            .store
            .begin_recipient_export_withdrawal(export_id, &owner);
        if owner == grantee {
            assert_eq!(answer, Ok(CAPTURED));
        } else {
            assert_eq!(answer, Err(ErasureErrorV1::ProvenanceMissing));
        }
    }
    // T3 before the owner step is refused.
    let record = elxw1(&database, export_id, timeline, 5)?;
    assert_eq!(
        fixture
            .store
            .commit_local_owner_effect(prepared(record.clone(), 5)?),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
    fixture
        .store
        .delete_recipient_export_ciphertext(export_id)?;
    // An ELXW1 that differs from the row in any bound field is refused.
    let decoded = LocalErasureRecipientExportWithdrawalV1::from_canonical_cbor(&record)?;
    for differing in [
        LocalErasureRecipientExportWithdrawalV1 {
            grantee_owner: other,
            ..decoded
        },
        LocalErasureRecipientExportWithdrawalV1 {
            ciphertext_length: decoded.ciphertext_length + 1,
            ..decoded
        },
        LocalErasureRecipientExportWithdrawalV1 {
            ciphertext_digest: Hash::from_bytes([0; 32]),
            ..decoded
        },
        LocalErasureRecipientExportWithdrawalV1 {
            directory_identity: [0; 16],
            ..decoded
        },
        LocalErasureRecipientExportWithdrawalV1 {
            final_identity: [0; 20],
            ..decoded
        },
        LocalErasureRecipientExportWithdrawalV1 {
            timeline_id: TimelineId::new(),
            ..decoded
        },
    ] {
        assert_eq!(
            fixture
                .store
                .commit_local_owner_effect(prepared(differing.to_canonical_cbor()?, 5)?),
            Err(ErasureErrorV1::ProvenanceMissing)
        );
    }
    assert!(fixture
        .store
        .retained_erasure_objects("ELO1", 4)?
        .is_empty());
    fixture
        .store
        .commit_local_owner_effect(prepared(record, 5)?)?;
    Ok(())
}

#[test]
fn a_missing_final_object_stays_negative_even_when_an_impostor_appears() -> TestResult {
    let (mut fixture, (_, export_id)) = published()?;
    let grantee = fixture.grantee_owner();
    let length = std::fs::read(fixture.final_path(export_id))?.len();
    std::fs::remove_file(fixture.final_path(export_id))?;
    assert_eq!(
        fixture
            .store
            .begin_recipient_export_withdrawal(export_id, &grantee)?,
        retracted(2)
    );
    assert_eq!(
        fixture.store.delete_recipient_export_ciphertext(export_id),
        Err(ErasureErrorV1::ArtifactDeletionFailed)
    );
    // A same-length impostor later at that name is digest-mismatched.
    replace_file(&fixture.final_path(export_id), &vec![0x42; length], 0o600)?;
    assert_eq!(
        fixture
            .store
            .begin_recipient_export_withdrawal(export_id, &grantee)?,
        retracted(3)
    );
    assert!(matches!(
        fixture
            .store
            .read_recipient_export(&fixture.owner, export_id),
        Err(RecipientExportPublicationErrorV1::ArtifactUnavailable)
    ));
    Ok(())
}

/// One way to damage a publication's objects before its first capture.
type Damage = fn(&Fixture, [u8; 16]) -> TestResult;

/// Move the final object aside and leave a symbolic link to it.
fn symlink_final(fixture: &Fixture, export_id: [u8; 16]) -> TestResult {
    let moved = fixture.directory().join("moved");
    std::fs::rename(fixture.final_path(export_id), &moved)?;
    std::os::unix::fs::symlink(moved, fixture.final_path(export_id))?;
    Ok(())
}

#[test]
fn every_unsafe_object_is_captured_as_unsafe_and_never_deleted() -> TestResult {
    let damages: [Damage; 5] = [
        // A second link to the final object.
        |fixture, export_id| {
            std::fs::hard_link(
                fixture.final_path(export_id),
                fixture.directory().join("second-link"),
            )?;
            Ok(())
        },
        // The wrong length.
        |fixture, export_id| {
            let mut bytes = std::fs::read(fixture.final_path(export_id))?;
            bytes.push(0);
            replace_file(&fixture.final_path(export_id), &bytes, 0o600)
        },
        // A same-length impostor at the first capture.
        |fixture, export_id| {
            let length = std::fs::read(fixture.final_path(export_id))?.len();
            replace_file(&fixture.final_path(export_id), &vec![0x42; length], 0o600)
        },
        symlink_final,
        // An unsafe staging name beside a sound final object.
        |fixture, export_id| replace_file(&fixture.staging_path(export_id), b"staging", 0o644),
    ];
    for damage in damages {
        let (mut fixture, (_, export_id)) = published()?;
        damage(&fixture, export_id)?;
        assert_eq!(
            fixture
                .store
                .begin_recipient_export_withdrawal(export_id, &fixture.grantee_owner())?,
            retracted(3)
        );
        assert_eq!(
            fixture.store.delete_recipient_export_ciphertext(export_id),
            Err(ErasureErrorV1::ArtifactDeletionFailed)
        );
        assert!(fixture.final_path(export_id).exists());
    }
    Ok(())
}

#[test]
fn a_final_object_replaced_after_capture_is_kept_and_stays_retracted() -> TestResult {
    let damages: [Damage; 2] = [
        |fixture, export_id| {
            let bytes = std::fs::read(fixture.final_path(export_id))?;
            replace_file(&fixture.final_path(export_id), &bytes, 0o600)
        },
        symlink_final,
    ];
    for damage in damages {
        let (mut fixture, (_, export_id)) = published()?;
        let grantee = fixture.grantee_owner();
        assert_eq!(
            fixture
                .store
                .begin_recipient_export_withdrawal(export_id, &grantee)?,
            CAPTURED
        );
        damage(&fixture, export_id)?;
        assert_eq!(
            fixture.store.delete_recipient_export_ciphertext(export_id),
            Err(ErasureErrorV1::ArtifactDeletionFailed)
        );
        assert!(fixture.final_path(export_id).exists());
        assert_eq!(
            fixture
                .store
                .begin_recipient_export_withdrawal(export_id, &grantee)?,
            CAPTURED
        );
    }
    Ok(())
}

#[test]
fn a_safe_staging_object_is_captured_and_deleted_with_the_final_object() -> TestResult {
    let (mut fixture, publication) = published()?;
    let export_id = publication.1;
    replace_file(&fixture.staging_path(export_id), b"staging", 0o600)?;
    let database = fixture.database();
    let grantee = fixture.grantee_owner();
    let (record, _) = withdraw(&mut fixture.store, &database, &grantee, publication, 5)?;
    assert!(!fixture.final_path(export_id).exists());
    assert!(!fixture.staging_path(export_id).exists());
    assert!(matches!(
        fixture
            .store
            .begin_recipient_export_withdrawal(export_id, &grantee)?,
        RecipientExportWithdrawalStateV1::Withdrawn { elxw1, .. } if elxw1 == record
    ));
    Ok(())
}

#[test]
fn custody_survives_a_relative_path_and_a_rename_after_attach() -> TestResult {
    let mut fixture = Fixture::new()?;
    let publication = fixture.publish()?;
    let cwd = std::env::current_dir()?;
    let mut relative = PathBuf::new();
    for _ in cwd.components().skip(1) {
        relative.push("..");
    }
    relative.push(fixture.directory().strip_prefix("/")?);
    let custody = RecipientKeyOwnerV1::open(relative, fixture.grantee)?;
    fixture.store.attach_recipient_custody(vec![custody])?;
    std::fs::rename(
        fixture.directory(),
        fixture.temporary.path().join("renamed"),
    )?;
    let database = fixture.database();
    let grantee = fixture.grantee_owner();
    withdraw(&mut fixture.store, &database, &grantee, publication, 5)?;
    Ok(())
}

#[test]
fn attach_refuses_duplicate_grantees_bad_directories_and_a_second_call() -> TestResult {
    let mut fixture = Fixture::new()?;
    let second = private_directory(&fixture.temporary.path().join("second"))?;
    assert_eq!(
        fixture.store.attach_recipient_custody(vec![
            fixture.custody()?,
            RecipientKeyOwnerV1::open(&second, fixture.grantee)?,
        ]),
        Err(RecipientCustodyAttachErrorV1::DuplicateGrantee)
    );
    // A directory another grantee claims, then a directory that is no
    // longer private.
    assert_eq!(
        fixture
            .store
            .attach_recipient_custody(vec![RecipientKeyOwnerV1::open(
                fixture.directory(),
                EntityId::new()
            )?]),
        Err(RecipientCustodyAttachErrorV1::InvalidDirectory)
    );
    let unsafe_custody = fixture.custody()?;
    std::fs::set_permissions(fixture.directory(), std::fs::Permissions::from_mode(0o755))?;
    assert_eq!(
        fixture.store.attach_recipient_custody(vec![unsafe_custody]),
        Err(RecipientCustodyAttachErrorV1::InvalidDirectory)
    );
    std::fs::set_permissions(fixture.directory(), std::fs::Permissions::from_mode(0o700))?;
    // A refused call attached nothing; a second successful call is refused
    // and changes nothing.
    fixture.attach()?;
    assert_eq!(
        fixture
            .store
            .attach_recipient_custody(vec![RecipientKeyOwnerV1::open(second, EntityId::new())?]),
        Err(RecipientCustodyAttachErrorV1::AlreadyAttached)
    );
    let publication = fixture.publish()?;
    let database = fixture.database();
    let grantee = fixture.grantee_owner();
    withdraw(&mut fixture.store, &database, &grantee, publication, 5)?;
    Ok(())
}

#[test]
fn missing_custody_is_negative_until_a_restart_attaches_it() -> TestResult {
    let mut fixture = Fixture::new()?;
    let publication = fixture.publish()?;
    let export_id = publication.1;
    let grantee = fixture.grantee_owner();
    assert_eq!(
        fixture
            .store
            .begin_recipient_export_withdrawal(export_id, &grantee)?,
        retracted(1)
    );
    assert_eq!(
        fixture.store.delete_recipient_export_ciphertext(export_id),
        Err(ErasureErrorV1::ArtifactDeletionFailed)
    );
    let mut restarted = fixture.reopen()?;
    restarted.attach_recipient_custody(vec![fixture.custody()?])?;
    let database = fixture.database();
    withdraw(&mut restarted, &database, &grantee, publication, 5)?;
    Ok(())
}

#[test]
fn a_mode_change_after_attach_is_negative_until_it_is_repaired() -> TestResult {
    let (mut fixture, publication) = published()?;
    let export_id = publication.1;
    std::fs::set_permissions(fixture.directory(), std::fs::Permissions::from_mode(0o755))?;
    let grantee = fixture.grantee_owner();
    assert_eq!(
        fixture
            .store
            .begin_recipient_export_withdrawal(export_id, &grantee)?,
        retracted(1)
    );
    std::fs::set_permissions(fixture.directory(), std::fs::Permissions::from_mode(0o700))?;
    let database = fixture.database();
    withdraw(&mut fixture.store, &database, &grantee, publication, 5)?;
    Ok(())
}

#[test]
fn a_publication_in_a_second_claimed_directory_is_withdrawn_once_it_is_attached() -> TestResult {
    let mut fixture = Fixture::new()?;
    let publication = fixture.publish()?;
    let export_id = publication.1;
    let second = private_directory(&fixture.temporary.path().join("second"))?;
    let moved = second.join(object_name(export_id, ".trx1"));
    std::fs::rename(fixture.final_path(export_id), &moved)?;
    fixture.attach()?;
    let grantee = fixture.grantee_owner();
    assert_eq!(
        fixture
            .store
            .begin_recipient_export_withdrawal(export_id, &grantee)?,
        retracted(2)
    );
    let mut restarted = fixture.reopen()?;
    restarted
        .attach_recipient_custody(vec![RecipientKeyOwnerV1::open(second, fixture.grantee)?])?;
    let database = fixture.database();
    withdraw(&mut restarted, &database, &grantee, publication, 5)?;
    assert!(!moved.exists());
    Ok(())
}

#[test]
fn a_row_captured_in_one_directory_waits_for_that_directory() -> TestResult {
    let (fixture, (timeline, export_id)) = published()?;
    let second = private_directory(&fixture.temporary.path().join("second"))?;
    let grantee = fixture.grantee_owner();
    let mut store = fixture.reopen()?;
    store.attach_recipient_custody(vec![fixture.custody()?])?;
    assert_eq!(
        store.begin_recipient_export_withdrawal(export_id, &grantee)?,
        CAPTURED
    );
    let mut stranded = fixture.reopen()?;
    stranded.attach_recipient_custody(vec![RecipientKeyOwnerV1::open(second, fixture.grantee)?])?;
    assert_eq!(
        stranded.delete_recipient_export_ciphertext(export_id),
        Err(ErasureErrorV1::ArtifactDeletionFailed)
    );
    assert_eq!(
        stranded.begin_recipient_export_withdrawal(export_id, &grantee)?,
        CAPTURED
    );
    let mut recovered = fixture.reopen()?;
    recovered.attach_recipient_custody(vec![fixture.custody()?])?;
    recovered.delete_recipient_export_ciphertext(export_id)?;
    let database = fixture.database();
    recovered.commit_local_owner_effect(prepared(elxw1(&database, export_id, timeline, 5)?, 5)?)?;
    Ok(())
}

#[test]
fn withdrawal_touches_no_key_and_no_other_subject_s_publication() -> TestResult {
    let mut fixture = Fixture::new()?;
    let erased = fixture.publish()?;
    let kept = fixture.publish()?;
    fixture.attach()?;
    // The grantee's role-4 key epoch is destroyed first.
    let epoch = fixture.descriptor.identity().epoch;
    fixture
        .store
        .destroy_recipient_key(&fixture.owner, epoch, Hash::from_bytes([52; 32]))?;
    let database = fixture.database();
    let grantee = fixture.grantee_owner();
    withdraw(&mut fixture.store, &database, &grantee, erased, 5)?;
    assert!(!fixture.final_path(erased.1).exists());
    assert_eq!(
        fixture
            .store
            .recipient_export_publications(&[erased.0, kept.0], 4)?,
        [RecipientExportPublicationRowV1 {
            export_id: kept.1,
            timeline: kept.0,
            grantee_owner: grantee,
        }]
    );
    assert_eq!(
        fixture
            .store
            .read_recipient_export(&fixture.owner, kept.1)?,
        std::fs::read(fixture.final_path(kept.1))?
    );
    Ok(())
}

#[test]
fn the_grantee_still_decrypts_another_subject_s_export_after_a_withdrawal() -> TestResult {
    let mut fixture = Fixture::new()?;
    let erased = fixture.publish()?;
    let kept = fixture.publish()?;
    fixture.attach()?;
    let database = fixture.database();
    let grantee = fixture.grantee_owner();
    withdraw(&mut fixture.store, &database, &grantee, erased, 5)?;
    let encoded = fixture
        .store
        .read_recipient_export(&fixture.owner, kept.1)?;
    let decrypted = fixture.store.decrypt_recipient_export(
        &fixture.owner,
        &encoded,
        kept.1,
        fixture.descriptor,
    )?;
    assert_eq!(decrypted.export.timeline.id(), kept.0);
    Ok(())
}

#[test]
fn targets_resolve_through_the_scoped_catalog_then_the_withdrawal_row() -> TestResult {
    let mut fixture = Fixture::new()?;
    let first = fixture.publish()?;
    let second = fixture.publish()?;
    fixture.attach()?;
    let grantee = fixture.grantee_owner();
    let first_target = local_erasure_export_recipient_v1(first.1, &grantee)?;
    let second_target = local_erasure_export_recipient_v1(second.1, &grantee)?;
    let unknown = ErasureReferenceV1::from_digest([0x77; 32]);
    let scope = [second.0, first.0, second.0];
    for (target, timelines, expected) in [
        (first_target, &scope[..], Some((first.1, grantee))),
        (second_target, &scope[..], Some((second.1, grantee))),
        (first_target, &scope[..1], None),
        (unknown, &scope[..], None),
    ] {
        assert_eq!(
            fixture
                .store
                .recipient_export_by_target(target, timelines)?,
            expected
        );
    }
    // Once withdrawn or retracted, the withdrawal row resolves the target,
    // still only inside the scope: the other publication's Timeline alone
    // resolves neither.
    let database = fixture.database();
    let (record, elo1) = withdraw(&mut fixture.store, &database, &grantee, first, 5)?;
    assert_eq!(
        fixture
            .store
            .begin_recipient_export_withdrawal(second.1, &grantee)?,
        CAPTURED
    );
    for (target, expected, other) in [
        (first_target, first.1, second.0),
        (second_target, second.1, first.0),
    ] {
        assert_eq!(
            fixture.store.recipient_export_by_target(target, &scope)?,
            Some((expected, grantee))
        );
        assert_eq!(
            fixture.store.recipient_export_by_target(target, &[other])?,
            None
        );
        assert_eq!(fixture.store.recipient_export_by_target(target, &[])?, None);
    }
    let mut expected = [
        RecipientExportWithdrawalRowV1 {
            target: first_target,
            export_id: first.1,
            disposition: Some(address(&record)?),
            committed_elo1: Some(elo1),
        },
        RecipientExportWithdrawalRowV1 {
            target: second_target,
            export_id: second.1,
            disposition: None,
            committed_elo1: None,
        },
    ];
    expected.sort_by_key(|row| row.target);
    assert_eq!(
        fixture
            .store
            .erasure_authority_snapshot_with_limits(
                limits()?,
                &[second_target, unknown, first_target]
            )?
            .recipient_export_withdrawals(),
        expected
    );
    // Visible and retracted publications are enumerated; withdrawn ones are
    // not.
    assert_eq!(
        fixture.store.recipient_export_publications(&scope, 4)?,
        [RecipientExportPublicationRowV1 {
            export_id: second.1,
            timeline: second.0,
            grantee_owner: grantee,
        }]
    );
    Ok(())
}

#[test]
fn a_snapshot_reads_at_most_one_category_of_targets_on_both_adapters() -> TestResult {
    let (mut fixture, _) = published()?;
    let mut memory = MemoryStore::new();
    assert_target_bound(&mut fixture.store)?;
    assert_target_bound(&mut memory)?;
    Ok(())
}

/// Exactly 4,096 targets are read; one more is refused.
fn assert_target_bound(store: &mut impl ErasureInventoryPersistencePortV1) -> TestResult {
    let unknown = ErasureReferenceV1::from_digest([0x77; 32]);
    assert!(store
        .erasure_authority_snapshot_with_limits(
            limits()?,
            &vec![unknown; ERASURE_MAX_OBLIGATIONS_PER_CATEGORY]
        )?
        .recipient_export_withdrawals()
        .is_empty());
    assert_eq!(
        store
            .erasure_authority_snapshot_with_limits(
                limits()?,
                &vec![unknown; ERASURE_MAX_OBLIGATIONS_PER_CATEGORY + 1]
            )
            .err(),
        Some(ErasureErrorV1::ScopeInvalid)
    );
    Ok(())
}

/// The answers of T1, the owner step, T3 and the target lookup for an
/// unknown export, and the ELO1 and ELXW1 objects retained afterwards.
type UnknownAnswers = (
    Result<RecipientExportWithdrawalStateV1, ErasureErrorV1>,
    Result<RecipientExportWithdrawalBindingV1, ErasureErrorV1>,
    Result<ErasureReferenceV1, ErasureErrorV1>,
    Option<([u8; 16], OwnerIdV1)>,
    usize,
    usize,
);

fn unknown_answers(
    store: &mut impl ErasureInventoryPersistencePortV1,
    timelines: &[TimelineId],
) -> TestResult<UnknownAnswers> {
    let unknown = [0x5a; 16];
    let owner = OwnerIdV1::new("recipient-export-unknown")?;
    let target = local_erasure_export_recipient_v1(unknown, &owner)?;
    let answers = (
        store.begin_recipient_export_withdrawal(unknown, &owner),
        store.delete_recipient_export_ciphertext(unknown),
        store.commit_local_owner_effect(prepared(unknown_elxw1(unknown)?, 5)?),
        store.recipient_export_by_target(target, timelines)?,
        store.retained_erasure_objects("ELO1", 4)?.len(),
        store.retained_erasure_objects("ELXW1", 4)?.len(),
    );
    assert!(store
        .erasure_authority_snapshot_with_limits(limits()?, &[target])?
        .recipient_export_withdrawals()
        .is_empty());
    Ok(answers)
}

#[test]
fn unknown_exports_have_one_answer_on_every_adapter() -> TestResult {
    let expected: UnknownAnswers = (
        Err(ErasureErrorV1::ProvenanceMissing),
        Err(ErasureErrorV1::ArtifactDeletionFailed),
        Err(ErasureErrorV1::ProvenanceMissing),
        None,
        0,
        0,
    );
    assert_eq!(unknown_answers(&mut MemoryStore::new(), &[])?, expected);
    let temporary = tempfile::tempdir()?;
    let never_published = temporary.path().join("never-published.sqlite");
    let mut store = SqliteStore::open(
        never_published
            .to_str()
            .ok_or("database path is not UTF-8")?,
    )?;
    assert_eq!(unknown_answers(&mut store, &[])?, expected);
    let (mut fixture, (timeline, _)) = published()?;
    assert_eq!(unknown_answers(&mut fixture.store, &[timeline])?, expected);
    Ok(())
}

#[test]
fn a_read_only_handle_refuses_every_withdrawal_step() -> TestResult {
    let mut fixture = Fixture::new()?;
    let (_, export_id) = fixture.publish()?;
    let mut read_only = SqliteStore::open_read_only(
        fixture
            .database()
            .to_str()
            .ok_or("database path is not UTF-8")?,
    )?;
    let grantee = fixture.grantee_owner();
    assert_eq!(
        read_only.begin_recipient_export_withdrawal(export_id, &grantee),
        Err(ErasureErrorV1::ReceiptCommitFailed)
    );
    assert_eq!(
        read_only.delete_recipient_export_ciphertext(export_id),
        Err(ErasureErrorV1::ArtifactDeletionFailed)
    );
    assert_eq!(
        read_only.commit_local_owner_effect(prepared(unknown_elxw1(export_id)?, 5)?),
        Err(ErasureErrorV1::ReceiptCommitFailed)
    );
    assert_eq!(
        read_only.attach_recipient_custody(vec![fixture.custody()?]),
        Err(RecipientCustodyAttachErrorV1::Unwritable)
    );
    // Nothing was retracted.
    fixture.attach()?;
    assert_eq!(
        fixture
            .store
            .begin_recipient_export_withdrawal(export_id, &grantee)?,
        CAPTURED
    );
    Ok(())
}

#[test]
fn a_malformed_or_unreadable_catalog_row_fails_closed() -> TestResult {
    for (sql, expected) in [
        (
            "UPDATE recipient_export_catalog_v1 SET ciphertext_digest = X'00'",
            ErasureErrorV1::ProvenanceMissing,
        ),
        (
            "UPDATE recipient_export_catalog_v1 SET ciphertext_length = -1",
            ErasureErrorV1::ProvenanceMissing,
        ),
        (
            "UPDATE recipient_export_catalog_v1 SET ciphertext_length = 'x'",
            ErasureErrorV1::ReceiptCommitFailed,
        ),
    ] {
        let (mut fixture, (_, export_id)) = published()?;
        let connection = rusqlite::Connection::open(fixture.database())?;
        connection.execute_batch("PRAGMA ignore_check_constraints = ON;")?;
        connection.execute_batch(sql)?;
        drop(connection);
        assert_eq!(
            fixture
                .store
                .begin_recipient_export_withdrawal(export_id, &fixture.grantee_owner()),
            Err(expected)
        );
    }
    Ok(())
}

#[test]
fn a_malformed_or_unreadable_withdrawal_row_fails_closed() -> TestResult {
    let (mut fixture, (timeline, export_id)) = published()?;
    let grantee = fixture.grantee_owner();
    fixture
        .store
        .begin_recipient_export_withdrawal(export_id, &grantee)?;
    let target = local_erasure_export_recipient_v1(export_id, &grantee)?;
    let connection = rusqlite::Connection::open(fixture.database())?;
    connection.execute_batch(
        "PRAGMA ignore_check_constraints = ON;
         UPDATE recipient_export_withdrawals_v1 SET owner_id = '';",
    )?;
    assert_eq!(
        fixture
            .store
            .recipient_export_by_target(target, &[timeline]),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
    connection.execute_batch("DROP TABLE recipient_export_withdrawals_v1")?;
    drop(connection);
    assert!(matches!(
        fixture
            .store
            .read_recipient_export(&fixture.owner, export_id),
        Err(RecipientExportPublicationErrorV1::Store(_))
    ));
    Ok(())
}

/// Copy the catalog row of `export_id` under one fresh export identity per
/// index, as further publications of its Timeline would record them.
fn copy_catalog_rows(
    database: &Path,
    export_id: [u8; 16],
    indices: impl IntoIterator<Item = u32>,
) -> TestResult {
    let mut connection = rusqlite::Connection::open(database)?;
    let transaction = connection.transaction()?;
    for index in indices {
        let mut copy = [0xee; 16];
        copy[..4].copy_from_slice(&index.to_be_bytes());
        transaction.execute(
            "INSERT INTO recipient_export_catalog_v1
             SELECT ?1, owner_id, recipient_epoch, recipient_descriptor, timeline_id,
                    local_head, logical_head, ciphertext_length, ciphertext_digest
             FROM recipient_export_catalog_v1 WHERE export_id = ?2",
            rusqlite::params![copy.as_slice(), export_id.as_slice()],
        )?;
    }
    transaction.commit()?;
    Ok(())
}

#[test]
fn a_target_scan_reads_at_most_one_category_of_publications() -> TestResult {
    let (mut fixture, (timeline, export_id)) = published()?;
    let database = fixture.database();
    let unknown = ErasureReferenceV1::from_digest([0x77; 32]);
    // The published row and 4,095 copies: exactly one category.
    let bound = u32::try_from(ERASURE_MAX_OBLIGATIONS_PER_CATEGORY)?;
    copy_catalog_rows(&database, export_id, 1..bound)?;
    assert_eq!(
        fixture
            .store
            .recipient_export_by_target(unknown, &[timeline])?,
        None
    );
    copy_catalog_rows(&database, export_id, [bound])?;
    assert_eq!(
        fixture
            .store
            .recipient_export_by_target(unknown, &[timeline]),
        Err(ErasureErrorV1::ScopeInvalid)
    );
    Ok(())
}

#[test]
fn a_withdrawal_row_with_a_malformed_timeline_fails_closed() -> TestResult {
    let (mut fixture, (timeline, export_id)) = published()?;
    let grantee = fixture.grantee_owner();
    fixture
        .store
        .begin_recipient_export_withdrawal(export_id, &grantee)?;
    let target = local_erasure_export_recipient_v1(export_id, &grantee)?;
    rusqlite::Connection::open(fixture.database())?
        .execute_batch("UPDATE recipient_export_withdrawals_v1 SET timeline_id = 'x'")?;
    assert_eq!(
        fixture
            .store
            .recipient_export_by_target(target, &[timeline]),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
    assert_eq!(
        fixture
            .store
            .erasure_authority_snapshot_with_limits(limits()?, &[target])
            .err(),
        Some(ErasureErrorV1::ProvenanceMissing)
    );
    Ok(())
}
