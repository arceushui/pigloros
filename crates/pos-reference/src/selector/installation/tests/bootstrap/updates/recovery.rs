use std::os::unix::fs::PermissionsExt;

use crate::evaluator_protocol::{array, decode_canonical, encode, ProtocolError};
use crate::selector::installation::authority::update::durability::CommittedInstallationUpdate;
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

fn commit_recovery(
) -> Result<(InstallationFixture, Vec<u8>, Vec<u8>, Vec<u8>), Box<dyn std::error::Error>> {
    let fixture = UpdateFixture::new()?;
    let update = validated(&fixture)?;
    let previous = update.previous_manifest_bytes().to_vec();
    let next = update.next_manifest_bytes().to_vec();
    let rcu = update.revocation_update_bytes().to_vec();
    let UpdateFixture {
        installation,
        authority,
    } = fixture;
    let committed: CommittedInstallationUpdate = authority.commit_update(update)?;
    drop(committed);
    Ok((installation, previous, next, rcu))
}

fn replace_manifest(
    fixture: &InstallationFixture,
    bytes: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    let path = fixture.directory.path().join(MANIFEST_NAME);
    std::fs::remove_file(&path)?;
    std::fs::write(&path, bytes)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o400))?;
    Ok(())
}

fn replace_recovery(
    fixture: &InstallationFixture,
    bytes: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    let path = fixture.directory.path().join("installation-update.cbor");
    std::fs::remove_file(&path)?;
    std::fs::write(&path, bytes)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o400))?;
    Ok(())
}

#[test]
fn recovery_loader_authenticates_previous_and_next_sic_floors() -> TestResult {
    for floor in 0..2 {
        let (installation, previous, next, rcu) = commit_recovery()?;
        if floor == 1 {
            replace_manifest(&installation, &next)?;
        }
        let pending = installation.load()?.load_pending_recovery()?;
        assert_eq!(pending.revocation_update_bytes(), rcu);
        pending.verify_recovery_floor()?;
        let current = std::fs::read(installation.directory.path().join(MANIFEST_NAME))?;
        if floor == 0 {
            assert_eq!(current, previous);
        } else {
            assert_eq!(current, next);
        }
        assert!(installation.load()?.authenticate_authority().is_err());
    }
    Ok(())
}

#[test]
fn recovery_loader_rechecks_current_disk_manifest_after_object_loading() -> TestResult {
    let (installation, _, _, _) = commit_recovery()?;
    let loaded = installation.load()?;
    replace_manifest(&installation, b"replaced after loading")?;
    assert!(loaded.load_pending_recovery().is_err());
    assert!(installation
        .directory
        .path()
        .join("installation-update.cbor")
        .exists());
    Ok(())
}

#[test]
fn pending_recovery_rejects_replaced_changed_and_truncated_records() -> TestResult {
    for alteration in 0..3 {
        let (installation, _, _, _) = commit_recovery()?;
        let pending = installation.load()?.load_pending_recovery()?;
        let path = installation
            .directory
            .path()
            .join("installation-update.cbor");
        let bytes = std::fs::read(&path)?;
        if alteration == 0 {
            replace_recovery(&installation, &bytes)?;
        } else {
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
            let mut changed = bytes;
            if alteration == 1 {
                changed[0] ^= 1;
            } else {
                changed.truncate(changed.len() / 2);
            }
            std::fs::write(&path, changed)?;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400))?;
        }
        assert!(pending.verify_recovery_floor().is_err());
        assert!(path.exists());
    }
    Ok(())
}

#[test]
fn recovery_loader_rejects_malformed_truncated_and_tampered_sir1() -> TestResult {
    for alteration in 0..3 {
        let (installation, _, _, _) = commit_recovery()?;
        let path = installation
            .directory
            .path()
            .join("installation-update.cbor");
        let mut bytes = std::fs::read(&path)?;
        if alteration == 0 {
            bytes = b"not SIR1".to_vec();
        } else if alteration == 1 {
            bytes.truncate(bytes.len() / 2);
        } else {
            bytes[0] ^= 1;
        }
        replace_recovery(&installation, &bytes)?;
        assert!(installation.load()?.load_pending_recovery().is_err());
    }
    Ok(())
}

#[test]
fn recovery_loader_rejects_unsafe_recovery_file_metadata() -> TestResult {
    for alteration in 0..3 {
        let (installation, _, _, _) = commit_recovery()?;
        let path = installation
            .directory
            .path()
            .join("installation-update.cbor");
        if alteration == 0 {
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        } else if alteration == 1 {
            std::fs::hard_link(&path, path.with_extension("alias"))?;
        } else {
            std::fs::remove_file(&path)?;
            std::os::unix::fs::symlink("missing-recovery", &path)?;
        }
        assert!(installation.load()?.load_pending_recovery().is_err());
    }
    Ok(())
}

#[test]
fn recovery_loader_rejects_forged_rcu_signature() -> TestResult {
    let (installation, _, _, _) = commit_recovery()?;
    let path = installation
        .directory
        .path()
        .join("installation-update.cbor");
    let document = decode_canonical(&std::fs::read(&path)?)?;
    let mut fields = array(&document, 5)?.to_vec();
    let Value::Bytes(update) = &mut fields[4] else {
        return Err(Box::new(ProtocolError::InvalidEncoding));
    };
    let mut update_document = decode_canonical(update)?;
    let Value::Array(update_fields) = &mut update_document else {
        return Err(Box::new(ProtocolError::InvalidEncoding));
    };
    if update_fields.len() != 3 {
        return Err(Box::new(ProtocolError::InvalidEncoding));
    }
    let Value::Bytes(signature) = &mut update_fields[2] else {
        return Err(Box::new(ProtocolError::InvalidEncoding));
    };
    let Some(last) = signature.last_mut() else {
        return Err(Box::new(ProtocolError::InvalidEncoding));
    };
    *last ^= 1;
    *update = encode(&update_document)?;
    replace_recovery(&installation, &encode(&Value::Array(fields))?)?;
    assert!(installation.load()?.load_pending_recovery().is_err());
    Ok(())
}

#[test]
fn recovery_loader_rejects_a_valid_but_stale_current_sic() -> TestResult {
    let (installation, _, _, _) = commit_recovery()?;
    let foreign_installation = authenticated_fixture(|policy| {
        policy[5] = Value::Array(vec![bytes([77; 32])]);
    })?;
    let foreign_authority = foreign_installation.load()?.authenticate_authority()?;
    let foreign = UpdateFixture {
        installation: foreign_installation,
        authority: foreign_authority,
    };
    let foreign_update = validated(&foreign)?;
    for entry in std::fs::read_dir(foreign.installation.directory.path().join("authority"))? {
        let entry = entry?;
        let destination = installation
            .directory
            .path()
            .join("authority")
            .join(entry.file_name());
        if !destination.exists() {
            std::fs::copy(entry.path(), &destination)?;
            std::fs::set_permissions(destination, std::fs::Permissions::from_mode(0o400))?;
        }
    }
    replace_manifest(&installation, foreign_update.next_manifest_bytes())?;
    assert!(installation.load()?.load_pending_recovery().is_err());
    Ok(())
}
