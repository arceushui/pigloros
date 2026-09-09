use super::*;

fn policy_record(
    trust: &SandboxTrustSnapshot,
    rvs: &SandboxRevocationSnapshot,
    epoch: u64,
    edit: impl FnOnce(&mut Vec<Value>),
) -> TestResult<Vec<u8>> {
    let mut fields = policy_fields(trust, rvs);
    fields[2] = integer(epoch);
    edit(&mut fields);
    sign_record(
        "APT1",
        Value::Array(fields),
        &SigningKey::from_bytes(&[7; 32]),
    )
}

fn snapshot_at(trust: &SandboxTrustSnapshot, epoch: u64) -> TestResult<SandboxRevocationSnapshot> {
    Ok(SandboxRevocationSnapshot::authenticate(
        &sign_record(
            "RVS1",
            revocation(trust, epoch, vec![]),
            &SigningKey::from_bytes(&[7; 32]),
        )?,
        trust,
    )?)
}

#[test]
fn policy_transition_accepts_only_successor_epochs_and_unchanged_selection() -> TestResult {
    let trust = trusted_registry(1)?;
    let previous = snapshot_at(&trust, 5)?;
    let next = snapshot_at(&trust, 6)?;
    let old = policy_record(&trust, &previous, 7, |_| {})?;
    let valid = policy_record(&trust, &next, 8, |_| {})?;
    SandboxAdministratorPolicy::validate_revocation_successor(
        &old, &valid, &trust, &previous, &next,
    )?;
    for epoch in [0, 6, 7] {
        let changed = policy_record(&trust, &next, epoch, |_| {})?;
        assert!(SandboxAdministratorPolicy::validate_revocation_successor(
            &old, &changed, &trust, &previous, &next
        )
        .is_err());
    }
    for epoch in [4, 5, 7] {
        let wrong_revocation = snapshot_at(&trust, epoch)?;
        let changed = policy_record(&trust, &wrong_revocation, 8, |_| {})?;
        assert!(SandboxAdministratorPolicy::validate_revocation_successor(
            &old,
            &changed,
            &trust,
            &previous,
            &wrong_revocation
        )
        .is_err());
    }
    for index in [3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14] {
        let changed = policy_record(&trust, &next, 8, |fields| {
            fields[index] = match index {
                5 | 6 => Value::Array(vec![Value::Bytes(vec![99; 32])]),
                12 | 13 => integer(99),
                _ => Value::Bytes(vec![99; 32]),
            };
        })?;
        assert!(
            SandboxAdministratorPolicy::validate_revocation_successor(
                &old, &changed, &trust, &previous, &next
            )
            .is_err(),
            "field {index}"
        );
    }
    for (old_bytes, next_bytes) in [
        (&b"invalid"[..], valid.as_slice()),
        (old.as_slice(), &b"invalid"[..]),
    ] {
        assert!(SandboxAdministratorPolicy::validate_revocation_successor(
            old_bytes, next_bytes, &trust, &previous, &next
        )
        .is_err());
    }
    Ok(())
}

#[test]
fn policy_transition_can_revoke_selected_provider_without_granting_admission() -> TestResult {
    let trust = trusted_registry(1)?;
    let previous = snapshot_at(&trust, 5)?;
    let old = policy_record(&trust, &previous, 7, |_| {})?;
    let Value::Array(mut fields) = revocation(&trust, 6, vec![]) else {
        return Err("revocation fixture must be array".into());
    };
    fields[5] = Value::Array(vec![
        Value::Bytes(vec![3; 32]),
        Value::Bytes(vec![10; 32]),
        Value::Bytes(vec![11; 32]),
    ]);
    let next = SandboxRevocationSnapshot::authenticate(
        &sign_record(
            "RVS1",
            Value::Array(fields),
            &SigningKey::from_bytes(&[7; 32]),
        )?,
        &trust,
    )?;
    let changed = policy_record(&trust, &next, 8, |_| {})?;
    SandboxAdministratorPolicy::validate_revocation_successor(
        &old, &changed, &trust, &previous, &next,
    )?;
    assert_eq!(
        SandboxAdministratorPolicy::authenticate(&changed, &trust, &next),
        Err(SandboxTrustError::Revoked)
    );
    Ok(())
}

#[test]
fn policy_signer_rotation_requires_old_signer_revocation_and_dual_authorization() -> TestResult {
    let root = SigningKey::from_bytes(&[1; 32]);
    let signer = SigningKey::from_bytes(&[7; 32]);
    let trust = SandboxTrustSnapshot::authenticate(
        &sign_trust_snapshot(
            snapshot(
                vec![key_record("next", 1), key_record("policy", 1)],
                vec![],
                "root",
            ),
            &root,
        )?,
        "root",
        &root.verifying_key(),
    )?;
    let previous = snapshot_at(&trust, 5)?;
    let old = policy_record(&trust, &previous, 7, |_| {})?;
    for revoked in [false, true] {
        let keys = if revoked {
            vec![Value::Text("policy".to_owned())]
        } else {
            vec![]
        };
        let next = SandboxRevocationSnapshot::authenticate(
            &sign_record("RVS1", revocation(&trust, 6, keys), &signer)?,
            &trust,
        )?;
        let changed = policy_record(&trust, &next, 8, |fields| {
            fields[15] = Value::Text("next".to_owned())
        })?;
        let result = SandboxAdministratorPolicy::validate_revocation_successor(
            &old, &changed, &trust, &previous, &next,
        );
        assert_eq!(result.is_ok(), revoked);
    }
    let previous = SandboxRevocationSnapshot::authenticate(
        &sign_record(
            "RVS1",
            revocation(&trust, 5, vec![Value::Text("next".to_owned())]),
            &signer,
        )?,
        &trust,
    )?;
    let next = SandboxRevocationSnapshot::authenticate(
        &sign_record(
            "RVS1",
            revocation(&trust, 6, vec![Value::Text("policy".to_owned())]),
            &signer,
        )?,
        &trust,
    )?;
    let old = policy_record(&trust, &previous, 7, |_| {})?;
    let changed = policy_record(&trust, &next, 8, |fields| {
        fields[15] = Value::Text("next".to_owned())
    })?;
    assert!(SandboxAdministratorPolicy::validate_revocation_successor(
        &old, &changed, &trust, &previous, &next
    )
    .is_err());
    Ok(())
}
