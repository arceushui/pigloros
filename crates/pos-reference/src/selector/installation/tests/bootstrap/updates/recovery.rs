use std::os::unix::fs::PermissionsExt;

use crate::evaluator_protocol::{array, decode_canonical, encode, ProtocolError};
use crate::selector::installation::authority::recovery::{
    ProviderRuntimeSlot, ProviderTerminationAuthority,
};
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

struct RecoveryFixture {
    installation: InstallationFixture,
    previous: Vec<u8>,
    next: Vec<u8>,
    rcu: Vec<u8>,
}

fn commit_recovery() -> Result<RecoveryFixture, Box<dyn std::error::Error>> {
    let fixture = UpdateFixture::new()?;
    let update = validated(&fixture)?;
    let previous = update.previous_manifest_bytes().to_vec();
    let next = update.next_manifest_bytes().to_vec();
    let rcu = update.revocation_update_bytes().to_vec();
    let snapshot = recovery_snapshot(&fixture.authority)?;
    let UpdateFixture {
        installation,
        authority,
    } = fixture;
    let committed: CommittedInstallationUpdate = authority.commit_update(update, snapshot)?;
    drop(committed);
    Ok(RecoveryFixture {
        installation,
        previous,
        next,
        rcu,
    })
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

fn rewrite_recovery_fields(
    fixture: &InstallationFixture,
    mutate: impl FnOnce(&mut [Value]) -> TestResult,
) -> TestResult {
    let path = fixture.directory.path().join("installation-update.cbor");
    let document = decode_canonical(&std::fs::read(path)?)?;
    let wrapper = array(&document, 2)?;
    let mut fields = array(&wrapper[0], 9)?.to_vec();
    mutate(&mut fields)?;
    let unsigned = Value::Array(fields);
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"PiglorOS.SIR1.v1\0");
    hasher.update(&encode(&unsigned)?);
    replace_recovery(
        fixture,
        &encode(&Value::Array(vec![
            unsigned,
            bytes(*hasher.finalize().as_bytes()),
        ]))?,
    )
}

fn mutable_array(value: &mut Value) -> Result<&mut Vec<Value>, ProtocolError> {
    let Value::Array(values) = value else {
        return Err(ProtocolError::InvalidEncoding);
    };
    Ok(values)
}

#[test]
fn provider_runtime_identity_rejects_zero_pid_and_exposes_observed_identity() -> TestResult {
    let slot = ProviderRuntimeSlot::allocate([31; 32]);
    assert_ne!(slot.runtime_instance_id(), [0; 16]);
    assert_ne!(slot.lifecycle_scope_id(), [0; 16]);
    assert_ne!(slot.runtime_instance_id(), slot.lifecycle_scope_id());
    assert!(slot.bind_observed_process(0, 90).is_err());

    let runtime = ProviderRuntimeSlot::allocate([31; 32]).bind_observed_process(321, 0)?;
    assert_ne!(runtime.runtime_instance_id(), [0; 16]);
    assert_ne!(runtime.lifecycle_scope_id(), [0; 16]);
    assert_eq!(runtime.main_pid(), 321);
    assert_eq!(runtime.main_start_time_ticks(), 0);
    Ok(())
}

#[test]
fn recovery_snapshot_rejects_runtime_manifest_and_key_role_substitution() -> TestResult {
    let fixture = UpdateFixture::new()?;
    let selection = fixture.authority.policy().selection();
    let runtime_key = fixture
        .authority
        .trust()
        .keys()
        .iter()
        .find(|key| key.role == SandboxTrustRole::ProviderRuntimeAttestation)
        .ok_or("runtime key missing")?;
    let foreign_runtime =
        ProviderRuntimeSlot::allocate([99; 32]).bind_observed_process(401, 501)?;
    assert!(InstallationRecoverySnapshot::seal(
        "provider".to_owned(),
        selection.provider_manifest,
        selection.provider_binary,
        [12; 32],
        runtime_key,
        &foreign_runtime,
        vec![],
        vec![],
    )
    .is_err());

    let mut wrong_role = runtime_key.clone();
    wrong_role.role = SandboxTrustRole::ProviderRelease;
    let runtime = ProviderRuntimeSlot::allocate(selection.provider_manifest)
        .bind_observed_process(402, 502)?;
    assert!(InstallationRecoverySnapshot::seal(
        "provider".to_owned(),
        selection.provider_manifest,
        selection.provider_binary,
        [12; 32],
        &wrong_role,
        &runtime,
        vec![],
        vec![],
    )
    .is_err());
    Ok(())
}

#[test]
fn recovery_loader_authenticates_previous_and_next_sic_floors() -> TestResult {
    for floor in 0..2 {
        let RecoveryFixture {
            installation,
            previous,
            next,
            rcu,
        } = commit_recovery()?;
        if floor == 1 {
            replace_manifest(&installation, &next)?;
        }
        let pending = installation.load()?.load_pending_recovery()?;
        assert_eq!(pending.revocation_update_bytes(), rcu);
        assert_ne!(pending.sir1_digest(), [0; 32]);
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
fn restart_recovery_requires_both_termination_proofs_before_durable_completion() -> TestResult {
    let RecoveryFixture {
        installation,
        next,
        rcu,
        ..
    } = commit_recovery()?;
    let pending = installation.load()?.load_pending_recovery()?;
    let context = pending.cancellation_context()?;
    let acknowledgement_bytes = recovery_acknowledgement(&context, &rcu)?;
    let acknowledgement =
        pending.authenticate_recovery_acknowledgement(&acknowledgement_bytes, 100)?;
    let authority = ProviderTerminationAuthority { _private: () };
    let previous = authority.prove_previous_termination(&pending)?;
    let peer = authority.prove_recovery_peer_termination(
        &pending,
        &previous,
        &acknowledgement,
        101,
        202,
    )?;
    let installed = pending.complete_recovery(previous, acknowledgement, peer)?;
    assert_eq!(installed.manifest_bytes(), next);
    assert!(!installation
        .directory
        .path()
        .join("installation-update.cbor")
        .exists());
    installed.authenticate_authority()?;
    Ok(())
}

#[test]
fn restart_recovery_rejects_late_acknowledgement_without_clearing_sir1() -> TestResult {
    let RecoveryFixture {
        installation, rcu, ..
    } = commit_recovery()?;
    let pending = installation.load()?.load_pending_recovery()?;
    let acknowledgement = recovery_acknowledgement(&pending.cancellation_context()?, &rcu)?;
    assert!(pending
        .authenticate_recovery_acknowledgement(&acknowledgement, 101)
        .is_err());
    assert!(installation
        .directory
        .path()
        .join("installation-update.cbor")
        .exists());
    pending.verify_recovery_floor()?;
    Ok(())
}

#[test]
fn restart_recovery_rejects_cross_transaction_proofs_and_zero_peer_pid() -> TestResult {
    let first = commit_recovery()?;
    let first_pending = first.installation.load()?.load_pending_recovery()?;
    let first_acknowledgement_bytes =
        recovery_acknowledgement(&first_pending.cancellation_context()?, &first.rcu)?;
    let first_acknowledgement =
        first_pending.authenticate_recovery_acknowledgement(&first_acknowledgement_bytes, 100)?;
    let authority = ProviderTerminationAuthority { _private: () };
    let first_previous = authority.prove_previous_termination(&first_pending)?;
    assert!(authority
        .prove_recovery_peer_termination(
            &first_pending,
            &first_previous,
            &first_acknowledgement,
            0,
            200,
        )
        .is_err());
    let first_peer = authority.prove_recovery_peer_termination(
        &first_pending,
        &first_previous,
        &first_acknowledgement,
        100,
        200,
    )?;

    let second = commit_recovery()?;
    let second_pending = second.installation.load()?.load_pending_recovery()?;
    let second_acknowledgement_bytes =
        recovery_acknowledgement(&second_pending.cancellation_context()?, &second.rcu)?;
    let second_acknowledgement =
        second_pending.authenticate_recovery_acknowledgement(&second_acknowledgement_bytes, 100)?;
    assert!(second_pending
        .complete_recovery(first_previous, second_acknowledgement, first_peer)
        .is_err());
    assert!(second
        .installation
        .directory
        .path()
        .join("installation-update.cbor")
        .exists());
    Ok(())
}

#[test]
fn recovery_proofs_reject_cross_transaction_inputs_at_each_binding() -> TestResult {
    let first = commit_recovery()?;
    let first_pending = first.installation.load()?.load_pending_recovery()?;
    let first_acknowledgement_bytes =
        recovery_acknowledgement(&first_pending.cancellation_context()?, &first.rcu)?;
    let first_acknowledgement =
        first_pending.authenticate_recovery_acknowledgement(&first_acknowledgement_bytes, 100)?;

    let second = commit_recovery()?;
    let second_pending = second.installation.load()?.load_pending_recovery()?;
    let second_acknowledgement_bytes =
        recovery_acknowledgement(&second_pending.cancellation_context()?, &second.rcu)?;
    let second_acknowledgement =
        second_pending.authenticate_recovery_acknowledgement(&second_acknowledgement_bytes, 100)?;
    let authority = ProviderTerminationAuthority { _private: () };

    let first_previous = authority.prove_previous_termination(&first_pending)?;
    assert!(authority
        .prove_recovery_peer_termination(
            &second_pending,
            &first_previous,
            &second_acknowledgement,
            301,
            401,
        )
        .is_err());

    let second_previous = authority.prove_previous_termination(&second_pending)?;
    assert!(authority
        .prove_recovery_peer_termination(
            &second_pending,
            &second_previous,
            &first_acknowledgement,
            302,
            402,
        )
        .is_err());

    let second_previous = authority.prove_previous_termination(&second_pending)?;
    let second_peer = authority.prove_recovery_peer_termination(
        &second_pending,
        &second_previous,
        &second_acknowledgement,
        303,
        403,
    )?;
    let first_previous = authority.prove_previous_termination(&first_pending)?;
    assert!(first_pending
        .complete_recovery(first_previous, first_acknowledgement, second_peer)
        .is_err());
    assert!(first
        .installation
        .directory
        .path()
        .join("installation-update.cbor")
        .exists());
    Ok(())
}

#[test]
fn recovery_loader_rechecks_current_disk_manifest_after_object_loading() -> TestResult {
    let RecoveryFixture { installation, .. } = commit_recovery()?;
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
        let RecoveryFixture { installation, .. } = commit_recovery()?;
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
fn pending_recovery_rejects_a_removed_sir1_after_loading() -> TestResult {
    let RecoveryFixture { installation, .. } = commit_recovery()?;
    let pending = installation.load()?.load_pending_recovery()?;
    let path = installation
        .directory
        .path()
        .join("installation-update.cbor");
    std::fs::remove_file(&path)?;
    assert_eq!(
        pending.verify_recovery_floor(),
        Err(SelectorBoundaryError::ArtifactInvalid)
    );
    assert!(!path.exists());
    Ok(())
}

#[test]
fn pending_recovery_rejects_current_sic_outside_committed_floor() -> TestResult {
    let RecoveryFixture { installation, .. } = commit_recovery()?;
    let pending = installation.load()?.load_pending_recovery()?;
    replace_manifest(&installation, b"outside committed recovery floor")?;
    assert_eq!(
        pending.verify_recovery_floor(),
        Err(SelectorBoundaryError::ArtifactInvalid)
    );
    assert!(installation
        .directory
        .path()
        .join("installation-update.cbor")
        .exists());
    Ok(())
}

#[test]
fn recovery_loader_rejects_malformed_truncated_and_tampered_sir1() -> TestResult {
    for alteration in 0..3 {
        let RecoveryFixture { installation, .. } = commit_recovery()?;
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
fn recovery_loader_rejects_wrong_envelope_tags_versions_and_member_types() -> TestResult {
    for (index, replacement) in [
        (0, Value::Text("SIC1".to_owned())),
        (1, Value::Integer(2_u64.into())),
        (2, Value::Null),
        (3, Value::Null),
        (4, Value::Null),
        (5, Value::Null),
        (6, Value::Null),
        (7, Value::Null),
        (8, Value::Null),
    ] {
        let RecoveryFixture { installation, .. } = commit_recovery()?;
        let path = installation
            .directory
            .path()
            .join("installation-update.cbor");
        let document = decode_canonical(&std::fs::read(&path)?)?;
        let wrapper = array(&document, 2)?;
        let mut fields = array(&wrapper[0], 9)?.to_vec();
        fields[index] = replacement;
        replace_recovery(
            &installation,
            &encode(&Value::Array(vec![
                Value::Array(fields),
                wrapper[1].clone(),
            ]))?,
        )?;
        assert!(installation.load()?.load_pending_recovery().is_err());
        assert!(path.exists());
    }
    let RecoveryFixture { installation, .. } = commit_recovery()?;
    replace_recovery(
        &installation,
        &encode(&Value::Array(vec![
            Value::Text("SIR1".to_owned()),
            integer(1),
            Value::Bytes(vec![1]),
            Value::Bytes(vec![2]),
            Value::Bytes(vec![3]),
        ]))?,
    )?;
    assert!(installation.load()?.load_pending_recovery().is_err());
    Ok(())
}

#[test]
fn recovery_loader_reaches_record_bounds_and_self_digest_checks() -> TestResult {
    for alteration in 0..2 {
        let RecoveryFixture { installation, .. } = commit_recovery()?;
        rewrite_recovery_fields(&installation, |fields| {
            if alteration == 0 {
                fields[2] = Value::Bytes(vec![]);
            } else {
                fields[4] = Value::Bytes(vec![1; 16 * 1024 * 1024 + 1]);
            }
            Ok(())
        })?;
        assert!(installation.load()?.load_pending_recovery().is_err());
    }

    let RecoveryFixture { installation, .. } = commit_recovery()?;
    let path = installation
        .directory
        .path()
        .join("installation-update.cbor");
    let document = decode_canonical(&std::fs::read(path)?)?;
    let wrapper = array(&document, 2)?;
    replace_recovery(
        &installation,
        &encode(&Value::Array(vec![wrapper[0].clone(), bytes([99; 32])]))?,
    )?;
    assert!(installation.load()?.load_pending_recovery().is_err());
    Ok(())
}

#[test]
fn recovery_loader_reaches_malformed_provider_binding_checks() -> TestResult {
    for alteration in 0..14 {
        let RecoveryFixture { installation, .. } = commit_recovery()?;
        rewrite_recovery_fields(&installation, |fields| {
            let binding = mutable_array(&mut fields[5])?;
            match alteration {
                0 => {
                    binding.pop();
                }
                1 => {
                    let runtime_key = mutable_array(&mut binding[4])?;
                    runtime_key.pop();
                }
                2 => {
                    let runtime_key = mutable_array(&mut binding[4])?;
                    runtime_key[1] = integer(2);
                }
                3 => binding[0] = Value::Text(String::new()),
                4 => mutable_array(&mut binding[4])?[0] = Value::Text(String::new()),
                5 => binding[1] = bytes([0; 32]),
                6 => binding[2] = bytes([0; 32]),
                7 => binding[3] = bytes([0; 32]),
                8 => mutable_array(&mut binding[4])?[2] = bytes([0; 32]),
                9 => binding[5] = Value::Bytes(vec![0; 16]),
                10 => binding[6] = Value::Bytes(vec![0; 16]),
                11 => {
                    let runtime = binding[5].clone();
                    binding[6] = runtime;
                }
                12 => binding[7] = integer(0),
                _ => mutable_array(&mut binding[4])?[2] = bytes([255; 32]),
            }
            Ok(())
        })?;
        assert!(installation.load()?.load_pending_recovery().is_err());
    }
    Ok(())
}

#[test]
fn recovery_loader_reaches_malformed_slot_and_attempt_checks() -> TestResult {
    for alteration in 0..12 {
        let RecoveryFixture { installation, .. } = commit_recovery()?;
        rewrite_recovery_fields(&installation, |fields| {
            match alteration {
                0 => {
                    mutable_array(&mut fields[6])?.pop();
                }
                1 => mutable_array(&mut fields[6])?[0] = Value::Bytes(vec![0; 16]),
                2 => mutable_array(&mut fields[6])?[1] = Value::Bytes(vec![0; 16]),
                3 => mutable_array(&mut fields[6])?[2] = Value::Bytes(vec![0; 16]),
                4 => {
                    let slot = mutable_array(&mut fields[6])?;
                    let runtime = slot[0].clone();
                    slot[1] = runtime;
                }
                5 => {
                    let slot = mutable_array(&mut fields[6])?;
                    let runtime = slot[0].clone();
                    slot[2] = runtime;
                }
                6 => {
                    let slot = mutable_array(&mut fields[6])?;
                    let lifecycle = slot[1].clone();
                    slot[2] = lifecycle;
                }
                7 => {
                    let runtime = mutable_array(&mut fields[5])?[5].clone();
                    mutable_array(&mut fields[6])?[2] = runtime;
                }
                8 => fields[7] = Value::Array(vec![Value::Bytes(vec![0; 16])]),
                9 => {
                    fields[7] =
                        Value::Array(vec![Value::Bytes(vec![2; 16]), Value::Bytes(vec![1; 16])]);
                }
                10 => fields[8] = Value::Array(vec![Value::Bytes(vec![99; 16])]),
                _ => {
                    fields[7] = Value::Array(
                        (1_u128..=257)
                            .map(|id| Value::Bytes(id.to_be_bytes().to_vec()))
                            .collect(),
                    );
                }
            }
            Ok(())
        })?;
        assert!(installation.load()?.load_pending_recovery().is_err());
    }
    Ok(())
}

#[test]
fn recovery_loader_rejects_unsafe_recovery_file_metadata() -> TestResult {
    for alteration in 0..3 {
        let RecoveryFixture { installation, .. } = commit_recovery()?;
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
    let RecoveryFixture { installation, .. } = commit_recovery()?;
    let path = installation
        .directory
        .path()
        .join("installation-update.cbor");
    let document = decode_canonical(&std::fs::read(&path)?)?;
    let wrapper = array(&document, 2)?;
    let mut fields = array(&wrapper[0], 9)?.to_vec();
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
    replace_recovery(
        &installation,
        &encode(&Value::Array(vec![
            Value::Array(fields),
            wrapper[1].clone(),
        ]))?,
    )?;
    assert!(installation.load()?.load_pending_recovery().is_err());
    Ok(())
}

#[test]
fn recovery_loader_rejects_a_valid_but_stale_current_sic() -> TestResult {
    let RecoveryFixture { installation, .. } = commit_recovery()?;
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
