use ed25519_dalek::Signer;

use super::*;

mod updates;

fn sign_record(
    magic: &str,
    fields: Vec<Value>,
    key: &SigningKey,
) -> Result<(Vec<u8>, [u8; 32]), Box<dyn std::error::Error>> {
    let unsigned = Value::Array(fields);
    let mut hasher = blake3::Hasher::new();
    hasher.update(format!("PiglorOS.{magic}.v1\0").as_bytes());
    hasher.update(&encode(&unsigned)?);
    let digest = *hasher.finalize().as_bytes();
    let mut message = format!("PiglorOS.{magic}.Signature.v1\0").into_bytes();
    message.extend_from_slice(&digest);
    Ok((
        encode(&Value::Array(vec![
            unsigned,
            bytes(digest),
            Value::Bytes(key.sign(&message).to_bytes().to_vec()),
        ]))?,
        digest,
    ))
}

fn install_record(
    fixture: &InstallationFixture,
    fields: &mut [Value],
    code: u8,
    encoded: &[u8],
    identity: [u8; 32],
) -> TestResult {
    let digest = *blake3::hash(encoded).as_bytes();
    let path = fixture
        .directory
        .path()
        .join("authority")
        .join(digest_name(digest));
    if path.exists() {
        assert_eq!(std::fs::read(&path)?, encoded);
    } else {
        std::fs::write(&path, encoded)?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o400))?;
    }
    let mut entries = array_values(&fields[10])?.to_vec();
    entries[usize::from(code)] = Value::Array(vec![
        integer(u64::from(code)),
        bytes(identity),
        bytes(digest),
        integer(u64::try_from(encoded.len())?),
    ]);
    fields[10] = Value::Array(entries);
    fields[4 + usize::from(code)] = bytes(identity);
    Ok(())
}

fn install_manifest(fixture: &InstallationFixture, fields: Vec<Value>) -> TestResult {
    let path = fixture.directory.path().join(MANIFEST_NAME);
    std::fs::remove_file(&path)?;
    std::fs::write(&path, manifest_bytes(fields)?)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o400))?;
    Ok(())
}

fn authenticated_fixture(
    change_policy: impl FnOnce(&mut Vec<Value>),
) -> Result<InstallationFixture, Box<dyn std::error::Error>> {
    let fixture = InstallationFixture::new()?;
    let root = SigningKey::from_bytes(&[42; 32]);
    let administrator = SigningKey::from_bytes(&[43; 32]);
    let mut manifest = unsigned();
    let (trust, trust_digest) = sign_record(
        "TRS1",
        vec![
            Value::Text("TRS1".to_owned()),
            integer(1),
            integer(1),
            Value::Array(vec![Value::Array(vec![
                Value::Text("administrator".to_owned()),
                integer(1),
                bytes(administrator.verifying_key().to_bytes()),
                integer(1),
            ])]),
            Value::Array(Vec::new()),
            Value::Text("offline-root".to_owned()),
        ],
        &root,
    )?;
    install_record(&fixture, &mut manifest, 0, &trust, trust_digest)?;
    let (revocation, revocation_digest) = sign_record(
        "RVS1",
        vec![
            Value::Text("RVS1".to_owned()),
            integer(1),
            bytes(trust_digest),
            integer(1),
            Value::Array(Vec::new()),
            Value::Array(Vec::new()),
            Value::Array(Vec::new()),
            Value::Text("administrator".to_owned()),
        ],
        &administrator,
    )?;
    install_record(&fixture, &mut manifest, 1, &revocation, revocation_digest)?;
    let mut policy = vec![
        Value::Text("APT1".to_owned()),
        integer(1),
        integer(1),
        bytes([4; 32]),
        bytes(*blake3::hash(&[11; 32]).as_bytes()),
        Value::Array(vec![bytes([9; 32])]),
        Value::Array(vec![bytes([10; 32])]),
        bytes(*blake3::hash(&[10; 32]).as_bytes()),
        bytes([6; 32]),
        bytes([5; 32]),
        bytes(trust_digest),
        bytes(revocation_digest),
        integer(1),
        integer(1),
        bytes([8; 32]),
        Value::Text("administrator".to_owned()),
    ];
    change_policy(&mut policy);
    let (policy, policy_digest) = sign_record("APT1", policy, &administrator)?;
    install_record(&fixture, &mut manifest, 2, &policy, policy_digest)?;
    install_manifest(&fixture, manifest)?;
    Ok(fixture)
}

#[test]
fn bootstrap_authenticates_only_the_offline_pinned_authority_chain() -> TestResult {
    let fixture = authenticated_fixture(|_| {})?;
    let authority = fixture.load()?.authenticate_authority()?;
    let expected = authority.installed().manifest().authority_digests();
    assert_eq!(authority.trust().snapshot_digest(), expected[0]);
    assert_eq!(authority.revocation().snapshot_digest(), expected[1]);
    assert_eq!(authority.policy().policy_digest(), expected[2]);
    assert_eq!(authority.trust().trust_epoch(), 1);
    assert_eq!(authority.revocation().revocation_epoch(), 1);
    assert_eq!(authority.policy().policy_epoch(), 1);
    Ok(())
}

#[test]
fn bootstrap_rejects_pending_recovery_even_if_record_is_invalid() -> TestResult {
    for kind in 0..3 {
        let fixture = authenticated_fixture(|_| {})?;
        let loaded = fixture.load()?;
        let path = fixture.directory.path().join("installation-update.cbor");
        match kind {
            0 => std::fs::write(&path, b"invalid SIR1")?,
            1 => symlink("missing", &path)?,
            _ => std::fs::create_dir(&path)?,
        }
        // Presence is checked at authentication, not just at initial open.
        assert!(loaded.authenticate_authority().is_err());
    }
    Ok(())
}

#[test]
fn bootstrap_rejects_signed_but_mismatched_policy_and_missing_selection() -> TestResult {
    for (field, value) in [
        (3, bytes([99; 32])),
        (4, bytes([99; 32])),
        (7, bytes([99; 32])),
        (8, bytes([99; 32])),
        (9, bytes([99; 32])),
        (14, bytes([99; 32])),
        (10, bytes([99; 32])),
        (11, bytes([99; 32])),
        (12, integer(2)),
        (13, integer(2)),
        (15, Value::Text("unknown".to_owned())),
    ] {
        let fixture = authenticated_fixture(|policy| policy[field] = value)?;
        assert!(
            fixture.load()?.authenticate_authority().is_err(),
            "field {field}"
        );
    }
    Ok(())
}

#[test]
fn bootstrap_rejects_changed_pin_and_each_forged_authority_record() -> TestResult {
    for field in [2, 3] {
        let fixture = authenticated_fixture(|_| {})?;
        let loaded = fixture.load()?;
        let document = decode_canonical(loaded.manifest_bytes())?;
        let mut fields = array_values(&array(&document, 2)?[0])?.to_vec();
        let other_root = SigningKey::from_bytes(&[44; 32]);
        fields[field] = if field == 2 {
            Value::Text("other-root".to_owned())
        } else {
            bytes(other_root.verifying_key().to_bytes())
        };
        install_manifest(&fixture, fields)?;
        assert!(fixture.load()?.authenticate_authority().is_err());
    }
    for code in 0..3 {
        let fixture = authenticated_fixture(|_| {})?;
        let loaded = fixture.load()?;
        let identity = loaded.manifest().authority_digests()[usize::from(code)];
        let mut record = loaded
            .artifact(InstallationObjectKind::from_code(code)?, identity)?
            .read_bytes()?;
        *record.last_mut().ok_or("empty signed record")? ^= 1;
        let document = decode_canonical(loaded.manifest_bytes())?;
        let mut fields = array_values(&array(&document, 2)?[0])?.to_vec();
        install_record(&fixture, &mut fields, code, &record, identity)?;
        install_manifest(&fixture, fields)?;
        assert!(
            fixture.load()?.authenticate_authority().is_err(),
            "forged role {code}"
        );
    }
    Ok(())
}

#[test]
fn bootstrap_rejects_semantic_identity_substitution_after_valid_signature() -> TestResult {
    for code in 0..3 {
        let fixture = authenticated_fixture(|_| {})?;
        let loaded = fixture.load()?;
        let identity = loaded.manifest().authority_digests()[usize::from(code)];
        let record = loaded
            .artifact(InstallationObjectKind::from_code(code)?, identity)?
            .read_bytes()?;
        let document = decode_canonical(loaded.manifest_bytes())?;
        let mut fields = array_values(&array(&document, 2)?[0])?.to_vec();
        install_record(&fixture, &mut fields, code, &record, [99; 32])?;
        install_manifest(&fixture, fields)?;
        assert!(
            fixture.load()?.authenticate_authority().is_err(),
            "semantic role {code}"
        );
    }
    Ok(())
}
