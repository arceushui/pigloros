use std::fs::{self, File};
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

use ciborium::value::Value;
use ed25519_dalek::SigningKey;

use super::*;
use crate::evaluator_protocol::{array, array_values, decode_canonical, fixed_bytes, text, uint};
use crate::selector::installation::authority::{
    AuthenticatedSelectorBootstrap, InstallationChallenge,
};

struct UpdateFixture {
    directory: tempfile::TempDir,
    bootstrap: AuthenticatedSelectorBootstrap,
    policy_signer: SigningKey,
}

impl UpdateFixture {
    fn new() -> TestResult<Self> {
        let directory = tempfile::tempdir()?;
        drop(materialize_root_selector_state(directory.path())?);
        let root = File::open(directory.path())?;
        let bootstrap =
            InstalledSelectorState::open_at_for_test(&root)?.authenticate_bootstrap()?;
        Ok(Self {
            directory,
            bootstrap,
            policy_signer: SigningKey::from_bytes(&[2; 32]),
        })
    }

    fn request(
        &self,
        challenge: &InstallationChallenge,
        nonce_override: Option<[u8; 16]>,
    ) -> TestResult<Vec<u8>> {
        let challenge_document = decode_canonical(&challenge.to_canonical_cbor()?)?;
        let challenge_fields = array(&challenge_document, 5)?;
        assert_eq!(text(&challenge_fields[0])?, "SICN1");
        assert_eq!(uint(&challenge_fields[1])?, 1);
        assert_eq!(uint(&challenge_fields[4])?, 0);
        let nonce = nonce_override.unwrap_or(fixed_bytes(&challenge_fields[3])?);
        assert_ne!(nonce, [0; 16]);

        let current = self.bootstrap.installed();
        let current_document = decode_canonical(current.manifest_bytes())?;
        let mut manifest_fields = array_values(&array(&current_document, 2)?[0])?.to_vec();
        let next_revocation = sign_record(
            "RVS1",
            Value::Array(vec![
                Value::Text("RVS1".to_owned()),
                integer(1),
                digest(self.bootstrap.trust().snapshot_digest()),
                integer(self.bootstrap.revocation().revocation_epoch() + 1),
                Value::Array(Vec::new()),
                Value::Array(Vec::new()),
                Value::Array(Vec::new()),
                Value::Text("policy".to_owned()),
            ]),
            &self.policy_signer,
        )?;
        let next_revocation_digest = signed_record_digest(&next_revocation)?;
        self.append_record(
            &mut manifest_fields,
            InstallationObjectKind::REVOCATION_SNAPSHOT,
            &next_revocation,
            next_revocation_digest,
        )?;

        let current_policy = current.control_record(
            InstallationObjectKind::ADMINISTRATOR_POLICY,
            self.bootstrap.policy().policy_digest(),
        )?;
        let policy_document = decode_canonical(&current_policy)?;
        let mut policy_fields = array_values(&array(&policy_document, 3)?[0])?.to_vec();
        policy_fields[2] = integer(self.bootstrap.policy().policy_epoch() + 1);
        policy_fields[11] = digest(next_revocation_digest);
        policy_fields[13] = integer(self.bootstrap.revocation().revocation_epoch() + 1);
        let next_policy = sign_record("APT1", Value::Array(policy_fields), &self.policy_signer)?;
        let next_policy_digest = signed_record_digest(&next_policy)?;
        self.append_record(
            &mut manifest_fields,
            InstallationObjectKind::ADMINISTRATOR_POLICY,
            &next_policy,
            next_policy_digest,
        )?;

        let next_manifest = encode_manifest(manifest_fields)?;
        let rcu1 = sign_record(
            "RCU1",
            Value::Array(vec![
                Value::Text("RCU1".to_owned()),
                integer(1),
                Value::Bytes(vec![70; 16]),
                digest(self.bootstrap.revocation().snapshot_digest()),
                Value::Bytes(next_revocation),
                digest(next_revocation_digest),
                Value::Bytes(nonce.to_vec()),
                Value::Text("policy".to_owned()),
            ]),
            &self.policy_signer,
        )?;
        Ok(encode(&Value::Array(vec![
            Value::Text("SIU1".to_owned()),
            integer(1),
            digest(current.manifest().digest()),
            Value::Bytes(next_manifest),
            Value::Bytes(rcu1),
        ]))?)
    }

    fn append_record(
        &self,
        manifest_fields: &mut [Value],
        kind: InstallationObjectKind,
        encoded: &[u8],
        identity: [u8; 32],
    ) -> TestResult {
        let content = *blake3::hash(encoded).as_bytes();
        let path = self
            .directory
            .path()
            .join(kind.directory())
            .join(hex_name(content));
        fs::write(&path, encoded)?;
        fs::set_permissions(path, fs::Permissions::from_mode(kind.required_mode()))?;

        let mut objects = array_values(&manifest_fields[10])?.to_vec();
        objects.push(Value::Array(vec![
            integer(u64::from(kind.code())),
            digest(identity),
            digest(content),
            integer(u64::try_from(encoded.len())?),
        ]));
        let mut indexed = objects
            .into_iter()
            .map(|value| {
                InstallationObject::decode(&value)
                    .map(|object| ((object.kind(), object.identity()), value))
            })
            .collect::<Result<Vec<_>, _>>()?;
        indexed.sort_by_key(|(key, _)| *key);
        manifest_fields[10] = Value::Array(indexed.into_iter().map(|(_, value)| value).collect());
        manifest_fields[4 + usize::from(kind.code())] = digest(identity);
        Ok(())
    }

    fn successor_object_path(
        &self,
        request: &[u8],
        kind: InstallationObjectKind,
    ) -> TestResult<std::path::PathBuf> {
        let document = decode_canonical(request)?;
        let Value::Bytes(next_manifest) = &array(&document, 5)?[3] else {
            return Err("SIU1 successor manifest is not bytes".into());
        };
        let manifest = InstallationManifest::from_canonical_cbor(next_manifest)?;
        let identity = manifest.authority_digests()[usize::from(kind.code())];
        let object = manifest.object(kind, identity)?;
        Ok(self
            .directory
            .path()
            .join(kind.directory())
            .join(hex_name(object.content_digest())))
    }
}

#[test]
fn challenge_bound_update_retains_exact_successor_without_installing_it() -> TestResult {
    let fixture = UpdateFixture::new()?;
    let challenge = fixture.bootstrap.issue_update_challenge()?;
    let challenge_bytes = challenge.to_canonical_cbor()?;
    let challenge_fields = array(&decode_canonical(&challenge_bytes)?, 5)?.to_vec();
    assert_ne!(fixed_bytes::<16>(&challenge_fields[3])?, [0; 16]);

    let request = fixture.request(&challenge, None)?;
    let validated = fixture.bootstrap.validate_update(challenge, &request)?;
    let request_document = decode_canonical(&request)?;
    let fields = array(&request_document, 5)?;
    assert_eq!(
        validated.previous_manifest_bytes(),
        fixture.bootstrap.installed().manifest_bytes()
    );
    assert_eq!(
        Value::Bytes(validated.next_manifest_bytes().to_vec()),
        fields[3]
    );
    assert_eq!(
        Value::Bytes(validated.revocation_update_bytes().to_vec()),
        fields[4]
    );
    assert_ne!(
        validated.next_manifest().digest(),
        fixture.bootstrap.installed().manifest().digest()
    );
    assert_eq!(
        validated
            .revocation_update()
            .next_revocation
            .revocation_epoch(),
        fixture.bootstrap.revocation().revocation_epoch() + 1
    );
    for file in validated.record_files() {
        let metadata = file.metadata()?;
        assert_eq!(metadata.mode() & 0o7777, 0o400);
        assert_eq!(metadata.nlink(), 1);
    }
    assert_eq!(
        fs::read(fixture.directory.path().join(MANIFEST_NAME))?,
        validated.previous_manifest_bytes()
    );
    assert!(!fixture.directory.path().join(RECOVERY_NAME).exists());
    Ok(())
}

#[test]
fn update_rejects_foreign_nonce_stale_manifest_and_malformed_frames() -> TestResult {
    let fixture = UpdateFixture::new()?;
    let challenge = fixture.bootstrap.issue_update_challenge()?;
    let foreign_nonce = fixture.request(&challenge, Some([99; 16]))?;
    assert!(fixture
        .bootstrap
        .validate_update(challenge, &foreign_nonce)
        .is_err());

    for malformed in [
        vec![0xff],
        encode(&Value::Null)?,
        encode(&Value::Array(Vec::new()))?,
        encode(&Value::Array(vec![
            Value::Text("SIU1".to_owned()),
            integer(1),
            digest([99; 32]),
            Value::Bytes(Vec::new()),
            Value::Bytes(Vec::new()),
        ]))?,
    ] {
        let challenge = fixture.bootstrap.issue_update_challenge()?;
        assert!(fixture
            .bootstrap
            .validate_update(challenge, &malformed)
            .is_err());
    }

    for index in 0..5 {
        let challenge = fixture.bootstrap.issue_update_challenge()?;
        let request = fixture.request(&challenge, None)?;
        let document = decode_canonical(&request)?;
        let mut fields = array(&document, 5)?.to_vec();
        fields[index] = Value::Null;
        assert!(fixture
            .bootstrap
            .validate_update(challenge, &encode(&Value::Array(fields))?)
            .is_err());
    }
    Ok(())
}

#[test]
fn update_rejects_forged_or_changed_successor_records() -> TestResult {
    let fixture = UpdateFixture::new()?;
    let challenge = fixture.bootstrap.issue_update_challenge()?;
    let request = fixture.request(&challenge, None)?;
    let document = decode_canonical(&request)?;
    let mut fields = array(&document, 5)?.to_vec();
    let Value::Bytes(rcu1) = &mut fields[4] else {
        return Err("SIU1 RCU1 is not bytes".into());
    };
    let last = rcu1.last_mut().ok_or("RCU1 cannot be empty")?;
    *last ^= 1;
    assert!(fixture
        .bootstrap
        .validate_update(challenge, &encode(&Value::Array(fields))?)
        .is_err());

    for kind in [
        InstallationObjectKind::REVOCATION_SNAPSHOT,
        InstallationObjectKind::ADMINISTRATOR_POLICY,
    ] {
        let fixture = UpdateFixture::new()?;
        let challenge = fixture.bootstrap.issue_update_challenge()?;
        let request = fixture.request(&challenge, None)?;
        let path = fixture.successor_object_path(&request, kind)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        assert!(fixture
            .bootstrap
            .validate_update(challenge, &request)
            .is_err());
    }
    Ok(())
}
