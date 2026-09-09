use super::*;
use crate::selector::installation::authority::update::InstallationChallenge;
use crate::selector::installation::authority::InstalledSelectorAuthority;

fn appended_record(
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
    std::fs::write(&path, encoded)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o400))?;
    let mut values = array_values(&fields[10])?.to_vec();
    values.push(Value::Array(vec![
        integer(u64::from(code)),
        bytes(identity),
        bytes(digest),
        integer(u64::try_from(encoded.len())?),
    ]));
    let mut indexed = values
        .into_iter()
        .map(|value| {
            InstallationObject::decode(&value)
                .map(|entry| ((entry.kind(), entry.identity()), value))
        })
        .collect::<Result<Vec<_>, _>>()?;
    indexed.sort_by_key(|(key, _)| *key);
    fields[10] = Value::Array(indexed.into_iter().map(|(_, value)| value).collect());
    fields[4 + usize::from(code)] = bytes(identity);
    Ok(())
}

struct UpdateFixture {
    installation: InstallationFixture,
    authority: InstalledSelectorAuthority,
}

impl UpdateFixture {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let installation = authenticated_fixture(|_| {})?;
        let authority = installation.load()?.authenticate_authority()?;
        Ok(Self {
            installation,
            authority,
        })
    }

    fn request(
        &self,
        challenge: &InstallationChallenge,
        nonce_override: Option<[u8; 16]>,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let administrator = SigningKey::from_bytes(&[43; 32]);
        let challenge_document = decode_canonical(&challenge.to_cbor()?)?;
        let challenge_fields = array(&challenge_document, 5)?;
        assert_eq!(text(&challenge_fields[0])?, "SICN1");
        assert_eq!(uint(&challenge_fields[1])?, 1);
        assert_eq!(uint(&challenge_fields[4])?, 0);
        let nonce: [u8; 16] = nonce_override.unwrap_or(fixed_bytes(&challenge_fields[3])?);
        assert_ne!(nonce, [0; 16]);
        let current = self.authority.installed();
        let document = decode_canonical(current.manifest_bytes())?;
        let mut fields = array_values(&array(&document, 2)?[0])?.to_vec();
        let (next_revocation, revocation_digest) = sign_record(
            "RVS1",
            vec![
                Value::Text("RVS1".to_owned()),
                integer(1),
                bytes(self.authority.trust().snapshot_digest()),
                integer(2),
                Value::Array(vec![]),
                Value::Array(vec![]),
                Value::Array(vec![]),
                Value::Text("administrator".to_owned()),
            ],
            &administrator,
        )?;
        appended_record(
            &self.installation,
            &mut fields,
            1,
            &next_revocation,
            revocation_digest,
        )?;
        let policy = current
            .artifact(
                InstallationObjectKind::from_code(2)?,
                self.authority.policy().policy_digest(),
            )?
            .read_bytes()?;
        let policy = decode_canonical(&policy)?;
        let mut policy_fields = array_values(&array(&policy, 3)?[0])?.to_vec();
        policy_fields[2] = integer(2);
        policy_fields[11] = bytes(revocation_digest);
        policy_fields[13] = integer(2);
        let (next_policy, policy_digest) = sign_record("APT1", policy_fields, &administrator)?;
        appended_record(
            &self.installation,
            &mut fields,
            2,
            &next_policy,
            policy_digest,
        )?;
        let (rcu, _) = sign_record(
            "RCU1",
            vec![
                Value::Text("RCU1".to_owned()),
                integer(1),
                Value::Bytes(vec![70; 16]),
                bytes(self.authority.revocation().snapshot_digest()),
                Value::Bytes(next_revocation),
                bytes(revocation_digest),
                Value::Bytes(nonce.to_vec()),
                Value::Text("administrator".to_owned()),
            ],
            &administrator,
        )?;
        Ok(encode(&Value::Array(vec![
            Value::Text("SIU1".to_owned()),
            integer(1),
            bytes(current.manifest().digest()),
            Value::Bytes(manifest_bytes(fields)?),
            Value::Bytes(rcu),
        ]))?)
    }
}

#[test]
fn update_validation_retains_exact_records_without_installing_or_acknowledging() -> TestResult {
    let fixture = UpdateFixture::new()?;
    let challenge = fixture.authority.issue_update_challenge()?;
    let request = fixture.request(&challenge, None)?;
    let validated = fixture.authority.validate_update(challenge, &request)?;
    let document = decode_canonical(&request)?;
    let fields = array(&document, 5)?;
    assert_eq!(
        validated.previous_manifest_bytes(),
        fixture.authority.installed().manifest_bytes()
    );
    assert_eq!(
        &Value::Bytes(validated.next_manifest_bytes().to_vec()),
        &fields[3]
    );
    assert_eq!(
        &Value::Bytes(validated.revocation_update_bytes().to_vec()),
        &fields[4]
    );
    assert_ne!(
        validated.next_manifest().digest(),
        fixture.authority.installed().manifest().digest()
    );
    assert_eq!(
        validated
            .revocation_update()
            .next_revocation
            .revocation_epoch(),
        2
    );
    for file in validated.record_files() {
        assert_eq!(file.metadata()?.mode() & 0o7777, 0o400);
        assert_eq!(file.metadata()?.nlink(), 1);
    }
    assert_eq!(
        std::fs::read(fixture.installation.directory.path().join(MANIFEST_NAME))?,
        validated.previous_manifest_bytes()
    );
    assert!(!fixture
        .installation
        .directory
        .path()
        .join("installation-update.cbor")
        .exists());
    Ok(())
}

#[test]
fn update_validation_rejects_foreign_nonce_stale_state_and_malformed_frames() -> TestResult {
    let fixture = UpdateFixture::new()?;
    let challenge = fixture.authority.issue_update_challenge()?;
    let request = fixture.request(&challenge, Some([99; 16]))?;
    assert!(fixture
        .authority
        .validate_update(challenge, &request)
        .is_err());
    for replacement in [
        Value::Null,
        Value::Array(vec![]),
        Value::Array(vec![
            Value::Text("SIU1".to_owned()),
            integer(1),
            bytes([99; 32]),
            Value::Bytes(vec![]),
            Value::Bytes(vec![]),
        ]),
    ] {
        let challenge = fixture.authority.issue_update_challenge()?;
        assert!(fixture
            .authority
            .validate_update(challenge, &encode(&replacement)?)
            .is_err());
    }
    Ok(())
}

#[test]
fn update_challenge_and_validation_reject_pending_recovery() -> TestResult {
    let fixture = UpdateFixture::new()?;
    let challenge = fixture.authority.issue_update_challenge()?;
    let request = fixture.request(&challenge, None)?;
    std::fs::write(
        fixture
            .installation
            .directory
            .path()
            .join("installation-update.cbor"),
        b"pending",
    )?;
    assert!(fixture.authority.issue_update_challenge().is_err());
    assert!(fixture
        .authority
        .validate_update(challenge, &request)
        .is_err());
    Ok(())
}

#[test]
fn update_validation_requires_installed_immutable_successor_records() -> TestResult {
    for code in [1, 2] {
        let fixture = UpdateFixture::new()?;
        let challenge = fixture.authority.issue_update_challenge()?;
        let request = fixture.request(&challenge, None)?;
        let document = decode_canonical(&request)?;
        let Value::Bytes(next) = &array(&document, 5)?[3] else {
            return Err("missing next SIC1".into());
        };
        let manifest = InstallationManifest::from_cbor(next)?;
        let identity = manifest.authority_digests()[usize::from(code)];
        let object = manifest.object(InstallationObjectKind::from_code(code)?, identity)?;
        let path = fixture
            .installation
            .directory
            .path()
            .join("authority")
            .join(digest_name(object.content_digest()));
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        assert!(fixture
            .authority
            .validate_update(challenge, &request)
            .is_err());
    }
    Ok(())
}

#[test]
fn update_validation_rejects_each_frame_field_and_forged_update_signature() -> TestResult {
    for index in 0..5 {
        let fixture = UpdateFixture::new()?;
        let challenge = fixture.authority.issue_update_challenge()?;
        let request = fixture.request(&challenge, None)?;
        let document = decode_canonical(&request)?;
        let mut fields = array(&document, 5)?.to_vec();
        fields[index] = Value::Null;
        assert!(fixture
            .authority
            .validate_update(challenge, &encode(&Value::Array(fields))?)
            .is_err());
    }
    let fixture = UpdateFixture::new()?;
    let challenge = fixture.authority.issue_update_challenge()?;
    let request = fixture.request(&challenge, None)?;
    let document = decode_canonical(&request)?;
    let mut fields = array(&document, 5)?.to_vec();
    let Value::Bytes(update) = &mut fields[4] else {
        return Err("missing RCU1".into());
    };
    *update.last_mut().ok_or("empty RCU1")? ^= 1;
    assert!(fixture
        .authority
        .validate_update(challenge, &encode(&Value::Array(fields))?)
        .is_err());
    Ok(())
}

#[test]
fn update_validation_rejects_successor_control_content_corruption() -> TestResult {
    for code in [1, 2] {
        let fixture = UpdateFixture::new()?;
        let challenge = fixture.authority.issue_update_challenge()?;
        let request = fixture.request(&challenge, None)?;
        let document = decode_canonical(&request)?;
        let Value::Bytes(next) = &array(&document, 5)?[3] else {
            return Err("missing next SIC1".into());
        };
        let manifest = InstallationManifest::from_cbor(next)?;
        let identity = manifest.authority_digests()[usize::from(code)];
        let object = manifest.object(InstallationObjectKind::from_code(code)?, identity)?;
        let path = fixture
            .installation
            .directory
            .path()
            .join("authority")
            .join(digest_name(object.content_digest()));
        let mut corrupted = std::fs::read(&path)?;
        *corrupted.last_mut().ok_or("empty successor record")? ^= 1;
        std::fs::remove_file(&path)?;
        std::fs::write(&path, corrupted)?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o400))?;
        assert!(fixture
            .authority
            .validate_update(challenge, &request)
            .is_err());
    }
    Ok(())
}
