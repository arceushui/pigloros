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

fn exact_recovery(update: &ValidatedInstallationUpdate) -> Result<Vec<u8>, ProtocolError> {
    encode(&Value::Array(vec![
        Value::Text("SIR1".to_owned()),
        integer(1),
        Value::Bytes(update.previous_manifest_bytes().to_vec()),
        Value::Bytes(update.next_manifest_bytes().to_vec()),
        Value::Bytes(update.revocation_update_bytes().to_vec()),
    ]))
}

#[test]
fn durable_commit_persists_the_exact_sir1_restart_floor() -> TestResult {
    let fixture = UpdateFixture::new()?;
    let update = validated(&fixture)?;
    let expected = exact_recovery(&update)?;
    let previous = update.previous_manifest_bytes().to_vec();
    let next = update.next_manifest_bytes().to_vec();
    let rcu = update.revocation_update_bytes().to_vec();
    let UpdateFixture {
        installation,
        authority,
    } = fixture;
    let committed = authority.commit_update(update)?;
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
    assert_eq!(
        std::fs::read(installation.directory.path().join(MANIFEST_NAME))?,
        previous
    );
    let staging = installation
        .directory
        .path()
        .join(".installation-update-staging");
    let staging_metadata = std::fs::metadata(staging)?;
    assert!(staging_metadata.is_dir());
    assert_eq!(staging_metadata.uid(), installation.owner);
    assert_eq!(staging_metadata.mode() & 0o7777, 0o700);
    assert_eq!(staging_metadata.dev(), installation.root.metadata()?.dev());
    Ok(())
}

#[test]
fn durable_commit_rejects_duplicate_and_unsafe_recovery_entries() -> TestResult {
    for existing in 0..2 {
        let fixture = UpdateFixture::new()?;
        let update = validated(&fixture)?;
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
        assert!(authority.commit_update(update).is_err());
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
fn durable_commit_rejects_stale_and_foreign_authority_pairs() -> TestResult {
    let fixture = UpdateFixture::new()?;
    let update = validated(&fixture)?;
    let foreign = authenticated_fixture(|policy| policy[2] = integer(2))?;
    let foreign_authority = foreign.load()?.authenticate_authority()?;
    assert!(foreign_authority.commit_update(update).is_err());
    assert!(!foreign
        .directory
        .path()
        .join("installation-update.cbor")
        .exists());

    let fixture = UpdateFixture::new()?;
    let update = validated(&fixture)?;
    let foreign = UpdateFixture::new()?;
    let UpdateFixture {
        authority: foreign_authority,
        installation: foreign_installation,
    } = foreign;
    assert!(foreign_authority.commit_update(update).is_err());
    assert!(!foreign_installation
        .directory
        .path()
        .join("installation-update.cbor")
        .exists());
    Ok(())
}
