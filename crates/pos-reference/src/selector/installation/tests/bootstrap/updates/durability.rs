use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};

use crate::evaluator_protocol::{encode, ProtocolError};
use crate::selector::installation::authority::update::ValidatedInstallationUpdate;
use ciborium::value::Value;

use super::*;

fn validated(
    fixture: &UpdateFixture,
) -> Result<ValidatedInstallationUpdate, Box<dyn std::error::Error>> {
    let challenge = fixture.authority.issue_update_challenge()?;
    let request = fixture.request(&challenge, None)?;
    Ok(fixture.authority.validate_update(challenge, &request)?)
}

fn exact_recovery(
    update: &ValidatedInstallationUpdate,
    snapshot: &InstallationRecoverySnapshot,
) -> Result<Vec<u8>, ProtocolError> {
    let unsigned = Value::Array(vec![
        Value::Text("SIR1".to_owned()),
        integer(1),
        Value::Bytes(update.previous_manifest_bytes().to_vec()),
        Value::Bytes(update.next_manifest_bytes().to_vec()),
        Value::Bytes(update.revocation_update_bytes().to_vec()),
        snapshot.previous_provider_value(),
        snapshot.recovery_slot_value(),
        Value::Array(
            snapshot
                .previous_live_attempt_ids()
                .iter()
                .map(|id| Value::Bytes(id.to_vec()))
                .collect(),
        ),
        Value::Array(
            snapshot
                .required_cancelled_attempt_ids()
                .iter()
                .map(|id| Value::Bytes(id.to_vec()))
                .collect(),
        ),
    ]);
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"PiglorOS.SIR1.v1\0");
    hasher.update(&encode(&unsigned)?);
    encode(&Value::Array(vec![
        unsigned,
        bytes(*hasher.finalize().as_bytes()),
    ]))
}

fn replace_current_manifest(
    fixture: &UpdateFixture,
    bytes: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    let path = fixture.installation.directory.path().join(MANIFEST_NAME);
    std::fs::remove_file(&path)?;
    std::fs::write(&path, bytes)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o400))?;
    Ok(())
}

#[test]
fn durable_commit_persists_the_exact_sir1_restart_floor() -> TestResult {
    let fixture = UpdateFixture::new()?;
    let update = validated(&fixture)?;
    let snapshot = recovery_snapshot(&fixture.authority)?;
    let expected = exact_recovery(&update, &snapshot)?;
    let previous = update.previous_manifest_bytes().to_vec();
    let next = update.next_manifest_bytes().to_vec();
    let rcu = update.revocation_update_bytes().to_vec();
    let UpdateFixture {
        installation,
        authority,
    } = fixture;
    let committed = authority.commit_update(update, snapshot)?;
    let recovery = installation
        .directory
        .path()
        .join("installation-update.cbor");
    let metadata = std::fs::metadata(&recovery)?;
    assert!(metadata.is_file());
    assert_eq!(metadata.uid(), installation.owner);
    assert_eq!(metadata.mode() & 0o7777, 0o400);
    assert_eq!(metadata.nlink(), 1);
    assert_eq!(std::fs::read(&recovery)?, expected);
    assert_eq!(committed.recovery_bytes(), expected);
    assert_eq!(committed.previous_manifest_bytes(), previous);
    assert_eq!(committed.next_manifest_bytes(), next);
    assert_eq!(committed.revocation_update_bytes(), rcu);
    assert_ne!(committed.sir1_digest(), [0; 32]);
    committed.verify_recovery_floor()?;
    assert_eq!(
        std::fs::read(installation.directory.path().join(MANIFEST_NAME))?,
        previous
    );
    let manifest = installation.directory.path().join(MANIFEST_NAME);
    std::fs::remove_file(&manifest)?;
    std::fs::write(&manifest, &next)?;
    std::fs::set_permissions(&manifest, std::fs::Permissions::from_mode(0o400))?;
    committed.verify_recovery_floor()?;
    let staging = installation
        .directory
        .path()
        .join(".installation-update-staging");
    let staging_metadata = std::fs::metadata(staging)?;
    assert!(staging_metadata.is_dir());
    assert_eq!(staging_metadata.uid(), installation.owner);
    assert_eq!(staging_metadata.mode() & 0o7777, 0o700);
    assert_eq!(staging_metadata.dev(), installation.root.metadata()?.dev());
    let context = committed.cancellation_context()?;
    let acknowledgement_bytes = recovery_acknowledgement(&context, &rcu)?;
    let acknowledgement =
        committed.authenticate_live_acknowledgement(&acknowledgement_bytes, 100)?;
    let installed = committed.complete_live_update(acknowledgement)?;
    assert_eq!(installed.manifest_bytes(), next);
    assert!(!recovery.exists());
    installed.authenticate_authority()?;
    Ok(())
}

#[test]
fn live_completion_rejects_an_authenticated_acknowledgement_from_another_transaction() -> TestResult
{
    let first = UpdateFixture::new()?;
    let first_update = validated(&first)?;
    let first_rcu = first_update.revocation_update_bytes().to_vec();
    let first_snapshot = recovery_snapshot(&first.authority)?;
    let first_committed = first
        .authority
        .commit_update(first_update, first_snapshot)?;
    let first_context = first_committed.cancellation_context()?;
    let first_acknowledgement = first_committed.authenticate_live_acknowledgement(
        &recovery_acknowledgement(&first_context, &first_rcu)?,
        100,
    )?;

    let second = UpdateFixture::new()?;
    let second_update = validated(&second)?;
    let second_snapshot = recovery_snapshot(&second.authority)?;
    let second_recovery = second
        .installation
        .directory
        .path()
        .join("installation-update.cbor");
    let second_committed = second
        .authority
        .commit_update(second_update, second_snapshot)?;
    assert!(matches!(
        second_committed.complete_live_update(first_acknowledgement),
        Err(SelectorBoundaryError::ArtifactInvalid)
    ));
    assert!(second_recovery.exists());
    Ok(())
}

#[test]
fn live_completion_rejects_late_or_foreign_acknowledgement_and_retains_sir1() -> TestResult {
    let fixture = UpdateFixture::new()?;
    let update = validated(&fixture)?;
    let rcu = update.revocation_update_bytes().to_vec();
    let snapshot = recovery_snapshot(&fixture.authority)?;
    let UpdateFixture {
        installation,
        authority,
    } = fixture;
    let committed = authority.commit_update(update, snapshot)?;
    let recovery = installation
        .directory
        .path()
        .join("installation-update.cbor");
    let context = committed.cancellation_context()?;
    let acknowledgement = recovery_acknowledgement(&context, &rcu)?;
    assert!(committed
        .authenticate_live_acknowledgement(&acknowledgement, 101)
        .is_err());
    let changed_context = RecoveryCancellationContext::for_committed_recovery(
        [99; 32],
        context.previous_provider_binding_digest,
        &rcu,
        context.previous_live_attempt_ids.clone(),
        context.required_cancelled_attempt_ids,
    )?;
    let foreign = recovery_acknowledgement(&changed_context, &rcu)?;
    assert!(committed
        .authenticate_live_acknowledgement(&foreign, 100)
        .is_err());
    assert!(recovery.exists());
    committed.verify_recovery_floor()?;
    Ok(())
}

#[test]
fn durable_commit_rejects_duplicate_and_unsafe_recovery_entries() -> TestResult {
    for existing in 0..2 {
        let fixture = UpdateFixture::new()?;
        let update = validated(&fixture)?;
        let snapshot = recovery_snapshot(&fixture.authority)?;
        let recovery = fixture
            .installation
            .directory
            .path()
            .join("installation-update.cbor");
        if existing == 0 {
            std::fs::write(&recovery, b"existing SIR1")?;
            std::fs::set_permissions(&recovery, std::fs::Permissions::from_mode(0o400))?;
        } else {
            symlink("missing-recovery", &recovery)?;
        }
        let UpdateFixture { authority, .. } = fixture;
        assert!(authority.commit_update(update, snapshot).is_err());
        if existing == 0 {
            assert_eq!(std::fs::read(&recovery)?, b"existing SIR1");
        } else {
            assert!(std::fs::symlink_metadata(&recovery)?
                .file_type()
                .is_symlink());
        }
    }
    Ok(())
}

#[test]
fn committed_recovery_rejects_manifest_outside_both_generations() -> TestResult {
    let fixture = UpdateFixture::new()?;
    let update = validated(&fixture)?;
    let snapshot = recovery_snapshot(&fixture.authority)?;
    let UpdateFixture {
        installation,
        authority,
    } = fixture;
    let committed = authority.commit_update(update, snapshot)?;
    let path = installation.directory.path().join(MANIFEST_NAME);
    std::fs::remove_file(&path)?;
    std::fs::write(&path, b"unrelated generation")?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400))?;
    assert_eq!(
        committed.verify_recovery_floor(),
        Err(SelectorBoundaryError::ArtifactInvalid)
    );
    assert_eq!(
        std::fs::read(
            installation
                .directory
                .path()
                .join("installation-update.cbor")
        )?,
        committed.recovery_bytes()
    );
    Ok(())
}

#[test]
fn durable_commit_rejects_stale_and_foreign_authority_pairs() -> TestResult {
    let fixture = UpdateFixture::new()?;
    let update = validated(&fixture)?;
    let snapshot = recovery_snapshot(&fixture.authority)?;
    replace_current_manifest(&fixture, update.next_manifest_bytes())?;
    let UpdateFixture { authority, .. } = fixture;
    assert!(authority.commit_update(update, snapshot).is_err());

    let fixture = UpdateFixture::new()?;
    let update = validated(&fixture)?;
    let snapshot = recovery_snapshot(&fixture.authority)?;
    let foreign = authenticated_fixture(|policy| policy[2] = integer(2))?;
    let foreign_authority = foreign.load()?.authenticate_authority()?;
    assert!(foreign_authority.commit_update(update, snapshot).is_err());
    assert!(!foreign
        .directory
        .path()
        .join("installation-update.cbor")
        .exists());

    let fixture = UpdateFixture::new()?;
    let update = validated(&fixture)?;
    let snapshot = recovery_snapshot(&fixture.authority)?;
    let foreign = UpdateFixture::new()?;
    let UpdateFixture {
        authority: foreign_authority,
        installation: foreign_installation,
    } = foreign;
    assert!(foreign_authority.commit_update(update, snapshot).is_err());
    assert!(!foreign_installation
        .directory
        .path()
        .join("installation-update.cbor")
        .exists());
    Ok(())
}

#[test]
fn recovery_floor_rejects_replaced_or_modified_records() -> TestResult {
    for alteration in 0..3 {
        let fixture = UpdateFixture::new()?;
        let update = validated(&fixture)?;
        let snapshot = recovery_snapshot(&fixture.authority)?;
        let UpdateFixture {
            installation,
            authority,
        } = fixture;
        let committed = authority.commit_update(update, snapshot)?;
        let path = installation
            .directory
            .path()
            .join("installation-update.cbor");
        let original = std::fs::read(&path)?;
        if alteration == 0 {
            std::fs::remove_file(&path)?;
            std::fs::write(&path, &original)?;
        } else {
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
            let mut changed = original;
            if alteration == 1 {
                changed[0] ^= 1;
            } else {
                changed.truncate(changed.len() - 1);
            }
            std::fs::write(&path, changed)?;
        }
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400))?;
        assert!(
            committed.verify_recovery_floor().is_err(),
            "alteration {alteration}"
        );
        assert!(
            path.exists(),
            "verification must preserve the recovery requirement"
        );
    }
    Ok(())
}

#[test]
fn durable_commit_rejects_successor_descriptor_replacement_after_validation() -> TestResult {
    for code in [1, 2] {
        let fixture = UpdateFixture::new()?;
        let update = validated(&fixture)?;
        let snapshot = recovery_snapshot(&fixture.authority)?;
        let identity = update.next_manifest().authority_digests()[usize::from(code)];
        let object = update
            .next_manifest()
            .object(InstallationObjectKind::from_code(code)?, identity)?;
        let path = fixture
            .installation
            .directory
            .path()
            .join("authority")
            .join(digest_name(object.content_digest()));
        let bytes = std::fs::read(&path)?;
        std::fs::remove_file(&path)?;
        std::fs::write(&path, bytes)?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400))?;
        let UpdateFixture {
            installation,
            authority,
        } = fixture;
        assert!(matches!(
            authority.commit_update(update, snapshot),
            Err(SelectorBoundaryError::ArtifactInvalid)
        ));
        assert!(!installation
            .directory
            .path()
            .join("installation-update.cbor")
            .exists());
    }
    Ok(())
}

#[test]
fn recovery_floor_rejects_missing_recovery_and_unsafe_current_manifest() -> TestResult {
    for missing_recovery in [false, true] {
        let fixture = UpdateFixture::new()?;
        let update = validated(&fixture)?;
        let snapshot = recovery_snapshot(&fixture.authority)?;
        let UpdateFixture {
            installation,
            authority,
        } = fixture;
        let committed = authority.commit_update(update, snapshot)?;
        let recovery = installation
            .directory
            .path()
            .join("installation-update.cbor");
        if missing_recovery {
            std::fs::remove_file(&recovery)?;
        } else {
            std::fs::set_permissions(
                installation.directory.path().join(MANIFEST_NAME),
                std::fs::Permissions::from_mode(0o600),
            )?;
        }
        assert_eq!(
            committed.verify_recovery_floor(),
            Err(SelectorBoundaryError::ArtifactInvalid)
        );
        assert_eq!(recovery.exists(), !missing_recovery);
    }
    Ok(())
}

#[test]
fn durable_commit_rejects_unsafe_staging_without_publishing_recovery() -> TestResult {
    for mode in [0o755, 0o777, 0o1700] {
        let fixture = UpdateFixture::new()?;
        let update = validated(&fixture)?;
        let snapshot = recovery_snapshot(&fixture.authority)?;
        let staging = fixture
            .installation
            .directory
            .path()
            .join(".installation-update-staging");
        std::fs::create_dir(&staging)?;
        std::fs::set_permissions(&staging, std::fs::Permissions::from_mode(mode))?;
        let UpdateFixture {
            installation,
            authority,
        } = fixture;
        assert!(
            authority.commit_update(update, snapshot).is_err(),
            "mode {mode:o}"
        );
        assert!(!installation
            .directory
            .path()
            .join("installation-update.cbor")
            .exists());
    }
    Ok(())
}
