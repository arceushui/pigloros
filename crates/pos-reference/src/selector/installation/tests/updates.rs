use std::fs::{self, File};
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use ciborium::value::Value;
use ed25519_dalek::SigningKey;

use super::*;
use crate::evaluator_protocol::{array, array_values, decode_canonical, fixed_bytes, text, uint};
use crate::selector::installation::authority::{
    AdmittedSelectorProvider, AuthenticatedSelectorBootstrap, InstallationChallenge,
    InstallationRecoverySnapshot, ProviderRuntimeSlot, ValidatedInstallationUpdate,
};
use crate::selector::installation::RECOVERY_NAME;

enum UpdateDirectory {
    Owned(tempfile::TempDir),
    Fixed(PathBuf),
}

impl UpdateDirectory {
    fn path(&self) -> &Path {
        match self {
            Self::Owned(directory) => directory.path(),
            Self::Fixed(directory) => directory,
        }
    }
}

pub(crate) struct UpdateFixture {
    directory: UpdateDirectory,
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
            directory: UpdateDirectory::Owned(directory),
            bootstrap,
            policy_signer: SigningKey::from_bytes(&[2; 32]),
        })
    }

    pub(crate) fn at(directory: &Path) -> TestResult<Self> {
        let root = File::open(directory)?;
        let bootstrap =
            InstalledSelectorState::open_at_for_test(&root)?.authenticate_bootstrap()?;
        Ok(Self {
            directory: UpdateDirectory::Fixed(directory.to_path_buf()),
            bootstrap,
            policy_signer: SigningKey::from_bytes(&[2; 32]),
        })
    }

    fn admitted(&self) -> TestResult<AdmittedSelectorProvider> {
        let root = File::open(self.directory.path())?;
        Ok(InstalledSelectorState::open_at_for_test(&root)?
            .authenticate_bootstrap()?
            .admit_provider()?)
    }

    fn request(
        &self,
        challenge: &InstallationChallenge,
        nonce_override: Option<[u8; 16]>,
    ) -> TestResult<Vec<u8>> {
        self.request_from_challenge(&challenge.to_canonical_cbor()?, nonce_override)
    }

    pub(crate) fn request_from_challenge(
        &self,
        challenge: &[u8],
        nonce_override: Option<[u8; 16]>,
    ) -> TestResult<Vec<u8>> {
        let challenge_document = decode_canonical(challenge)?;
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
        if path.exists() {
            if fs::read(&path)? != encoded {
                return Err("successor object identity collision".into());
            }
        } else {
            fs::write(&path, encoded)?;
            fs::set_permissions(&path, fs::Permissions::from_mode(kind.required_mode()))?;
        }

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

fn live_acknowledgement(
    committed: &crate::selector::installation::authority::CommittedInstallationUpdate,
    signer: &SigningKey,
    cancelled_attempt_ids: Vec<[u8; 16]>,
) -> TestResult<Vec<u8>> {
    let rcu1 = decode_canonical(committed.revocation_update_bytes())?;
    let rcu1_fields = array(&array(&rcu1, 3)?[0], 8)?;
    let context = committed.cancellation_context()?;
    sign_record(
        "RCA1",
        Value::Array(vec![
            Value::Text("RCA1".to_owned()),
            integer(1),
            Value::Bytes(fixed_bytes::<16>(&rcu1_fields[2])?.to_vec()),
            digest(fixed_bytes(&rcu1_fields[5])?),
            digest(context.sir1_digest),
            digest(context.previous_provider_binding_digest),
            Value::Array(
                cancelled_attempt_ids
                    .into_iter()
                    .map(|attempt| Value::Bytes(attempt.to_vec()))
                    .collect(),
            ),
            integer(0),
            Value::Text("runtime".to_owned()),
        ]),
        signer,
    )
}

fn replace_nested_unsigned_field(
    encoded: &[u8],
    index: usize,
    replacement: Value,
) -> TestResult<Vec<u8>> {
    let document = decode_canonical(encoded)?;
    let mut wrapper = array_values(&document)?.to_vec();
    let mut unsigned = array_values(&wrapper[0])?.to_vec();
    unsigned[index] = replacement;
    wrapper[0] = Value::Array(unsigned);
    Ok(encode(&Value::Array(wrapper))?)
}

fn resign_rcu1_field(
    request: &[u8],
    index: usize,
    replacement: Value,
    signer: &SigningKey,
) -> TestResult<Vec<u8>> {
    let mut request_fields = array_values(&decode_canonical(request)?)?.to_vec();
    let Value::Bytes(rcu1) = &request_fields[4] else {
        return Err("SIU1 RCU1 is not bytes".into());
    };
    let rcu1_document = decode_canonical(rcu1)?;
    let mut unsigned = array_values(&array(&rcu1_document, 3)?[0])?.to_vec();
    unsigned[index] = replacement;
    request_fields[4] = Value::Bytes(sign_record("RCU1", Value::Array(unsigned), signer)?);
    Ok(encode(&Value::Array(request_fields))?)
}

fn encode_unbounded(value: &Value) -> TestResult<Vec<u8>> {
    let mut bytes = Vec::new();
    ciborium::into_writer(value, &mut bytes)?;
    Ok(bytes)
}

pub(crate) fn acknowledgement_for_control_frames(
    context_bytes: &[u8],
    update_bytes: &[u8],
) -> TestResult<Vec<u8>> {
    let context =
        crate::sandbox_provider_protocol::RecoveryCancellationContext::from_canonical_cbor(
            context_bytes,
        )?;
    let update = decode_canonical(update_bytes)?;
    let fields = array(&array(&update, 3)?[0], 8)?;
    sign_record(
        "RCA1",
        Value::Array(vec![
            Value::Text("RCA1".to_owned()),
            integer(1),
            Value::Bytes(fixed_bytes::<16>(&fields[2])?.to_vec()),
            digest(fixed_bytes(&fields[5])?),
            digest(context.sir1_digest),
            digest(context.previous_provider_binding_digest),
            Value::Array(
                context
                    .required_cancelled_attempt_ids
                    .into_iter()
                    .map(|attempt| Value::Bytes(attempt.to_vec()))
                    .collect(),
            ),
            integer(0),
            Value::Text("runtime".to_owned()),
        ]),
        &SigningKey::from_bytes(&[4; 32]),
    )
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
fn update_rejects_expired_challenge_and_empty_or_oversized_records() -> TestResult {
    let fixture = UpdateFixture::new()?;
    let mut expired = fixture.bootstrap.issue_update_challenge()?;
    let expired_request = fixture.request(&expired, None)?;
    expired.expire_for_test();
    assert!(expired.to_canonical_cbor().is_err());
    assert!(fixture
        .bootstrap
        .validate_update(expired, &expired_request)
        .is_err());

    for (field, bytes) in [
        (3, Vec::new()),
        (4, Vec::new()),
        (3, vec![0; usize::try_from(MANIFEST_LIMIT)? + 1]),
        (4, vec![0; usize::try_from(MANIFEST_LIMIT)? + 1]),
    ] {
        let challenge = fixture.bootstrap.issue_update_challenge()?;
        let request = fixture.request(&challenge, None)?;
        let mut fields = array(&decode_canonical(&request)?, 5)?.to_vec();
        fields[field] = Value::Bytes(bytes);
        assert!(fixture
            .bootstrap
            .validate_update(challenge, &encode_unbounded(&Value::Array(fields))?,)
            .is_err());
    }
    Ok(())
}

#[test]
fn update_rejects_every_malformed_rcu1_field() -> TestResult {
    let fixture = UpdateFixture::new()?;
    for index in 0..8 {
        let challenge = fixture.bootstrap.issue_update_challenge()?;
        let request = fixture.request(&challenge, None)?;
        let mut fields = array(&decode_canonical(&request)?, 5)?.to_vec();
        let Value::Bytes(rcu1) = &fields[4] else {
            return Err("SIU1 RCU1 is not bytes".into());
        };
        fields[4] = Value::Bytes(replace_nested_unsigned_field(rcu1, index, Value::Null)?);
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

#[test]
fn update_rejects_stale_challenges_and_semantically_invalid_signed_records() -> TestResult {
    let fixture = UpdateFixture::new()?;
    let mut challenge = fixture.bootstrap.issue_update_challenge()?;
    let request = fixture.request(&challenge, None)?;
    challenge.replace_installation_for_test([99; 32]);
    assert!(fixture
        .bootstrap
        .validate_update(challenge, &request)
        .is_err());

    for (index, replacement) in [
        (3, digest([99; 32])),
        (5, digest([99; 32])),
        (7, Value::Text("unknown-policy-key".to_owned())),
    ] {
        let fixture = UpdateFixture::new()?;
        let challenge = fixture.bootstrap.issue_update_challenge()?;
        let request = fixture.request(&challenge, None)?;
        let changed = resign_rcu1_field(&request, index, replacement, &fixture.policy_signer)?;
        assert!(fixture
            .bootstrap
            .validate_update(challenge, &changed)
            .is_err());
    }

    let fixture = UpdateFixture::new()?;
    let challenge = fixture.bootstrap.issue_update_challenge()?;
    let request = fixture.request(&challenge, None)?;
    let forged = resign_rcu1_field(
        &request,
        7,
        Value::Text("policy".to_owned()),
        &SigningKey::from_bytes(&[9; 32]),
    )?;
    assert!(fixture
        .bootstrap
        .validate_update(challenge, &forged)
        .is_err());
    Ok(())
}

#[test]
fn update_rejects_missing_or_changed_successor_artifacts() -> TestResult {
    let fixture = UpdateFixture::new()?;
    let challenge = fixture.bootstrap.issue_update_challenge()?;
    let request = fixture.request(&challenge, None)?;
    fs::rename(
        fixture.directory.path().join("authority"),
        fixture.directory.path().join("authority-away"),
    )?;
    assert!(fixture
        .bootstrap
        .validate_update(challenge, &request)
        .is_err());

    let fixture = UpdateFixture::new()?;
    let challenge = fixture.bootstrap.issue_update_challenge()?;
    let request = fixture.request(&challenge, None)?;
    let path =
        fixture.successor_object_path(&request, InstallationObjectKind::ADMINISTRATOR_POLICY)?;
    let mut changed = fs::read(&path)?;
    changed[0] ^= 1;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
    fs::write(&path, changed)?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o400))?;
    assert!(fixture
        .bootstrap
        .validate_update(challenge, &request)
        .is_err());
    Ok(())
}

#[test]
fn durable_live_update_commits_sir1_before_publishing_successor() -> TestResult {
    let fixture = UpdateFixture::new()?;
    let admitted = fixture.admitted()?;
    let challenge = admitted.bootstrap().issue_update_challenge()?;
    let request = fixture.request(&challenge, None)?;
    let update = admitted.bootstrap().validate_update(challenge, &request)?;
    let next_manifest = update.next_manifest().digest();
    let runtime = ProviderRuntimeSlot::allocate(&admitted)?.bind_observed_process(100, 200)?;
    let snapshot = InstallationRecoverySnapshot::seal(
        &admitted,
        &runtime,
        vec![[41; 16], [42; 16]],
        vec![[42; 16]],
    )?;
    let committed = Arc::new(admitted).commit_update(update, snapshot)?;
    assert_ne!(committed.sir1_digest(), [0; 32]);

    let recovery_path = fixture.directory.path().join(RECOVERY_NAME);
    let recovery_metadata = fs::metadata(&recovery_path)?;
    assert!(recovery_metadata.is_file());
    assert_eq!(recovery_metadata.mode() & 0o7777, 0o400);
    assert_eq!(recovery_metadata.nlink(), 1);
    assert_eq!(fs::read(&recovery_path)?, committed.recovery_bytes());
    committed.verify_recovery_floor()?;
    let context = committed.cancellation_context()?;
    assert_eq!(
        crate::sandbox_provider_protocol::RecoveryCancellationContext::from_canonical_cbor(
            &context.to_canonical_cbor()?
        )?,
        context
    );

    let runtime_signer = SigningKey::from_bytes(&[4; 32]);
    let rca1 = live_acknowledgement(&committed, &runtime_signer, vec![[42; 16]])?;
    let acknowledgement = committed.authenticate_live_acknowledgement(&rca1)?;
    let next = committed.complete_live_update(&acknowledgement)?;
    assert_eq!(
        next.bootstrap().installed().manifest().digest(),
        next_manifest
    );
    assert!(!recovery_path.exists());
    assert_eq!(
        InstallationManifest::from_canonical_cbor(&fs::read(
            fixture.directory.path().join(MANIFEST_NAME)
        )?)?
        .digest(),
        next_manifest
    );
    Ok(())
}

fn committed_update_fixture() -> TestResult<(
    UpdateFixture,
    Arc<crate::selector::installation::authority::CommittedInstallationUpdate>,
    SigningKey,
)> {
    let fixture = UpdateFixture::new()?;
    let admitted = fixture.admitted()?;
    let challenge = admitted.bootstrap().issue_update_challenge()?;
    let request = fixture.request(&challenge, None)?;
    let update = admitted.bootstrap().validate_update(challenge, &request)?;
    let runtime = ProviderRuntimeSlot::allocate(&admitted)?.bind_observed_process(100, 200)?;
    assert_ne!(runtime.runtime_instance_id(), [0; 16]);
    assert_ne!(runtime.lifecycle_scope_id(), [0; 16]);
    assert_ne!(runtime.runtime_instance_id(), runtime.lifecycle_scope_id());
    assert_eq!(runtime.main_pid(), 100);
    assert_eq!(runtime.main_start_time_ticks(), 200);
    let snapshot = InstallationRecoverySnapshot::seal(
        &admitted,
        &runtime,
        vec![[41; 16], [42; 16]],
        vec![[42; 16]],
    )?;
    let committed = Arc::new(Arc::new(admitted).commit_update(update, snapshot)?);
    Ok((fixture, committed, SigningKey::from_bytes(&[4; 32])))
}

fn pending_update_fixture() -> TestResult<(
    UpdateFixture,
    AdmittedSelectorProvider,
    ValidatedInstallationUpdate,
    InstallationRecoverySnapshot,
)> {
    let fixture = UpdateFixture::new()?;
    let admitted = fixture.admitted()?;
    let challenge = admitted.bootstrap().issue_update_challenge()?;
    let request = fixture.request(&challenge, None)?;
    let update = admitted.bootstrap().validate_update(challenge, &request)?;
    let runtime = ProviderRuntimeSlot::allocate(&admitted)?.bind_observed_process(100, 200)?;
    let snapshot =
        InstallationRecoverySnapshot::seal(&admitted, &runtime, vec![[41; 16]], vec![[41; 16]])?;
    Ok((fixture, admitted, update, snapshot))
}

#[test]
fn committed_update_rejects_every_malformed_rcc1_field() -> TestResult {
    let (_fixture, committed, _signer) = committed_update_fixture()?;
    let context = committed.cancellation_context()?.to_canonical_cbor()?;
    for index in 0..7 {
        assert!(
            crate::sandbox_provider_protocol::RecoveryCancellationContext::from_canonical_cbor(
                &replace_nested_unsigned_field(&context, index, Value::Null)?
            )
            .is_err()
        );
    }
    let mut wrapper = array_values(&decode_canonical(&context)?)?.to_vec();
    wrapper[1] = Value::Null;
    assert!(
        crate::sandbox_provider_protocol::RecoveryCancellationContext::from_canonical_cbor(
            &encode(&Value::Array(wrapper))?
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn committed_update_rejects_every_malformed_rca1_field() -> TestResult {
    let (_fixture, committed, signer) = committed_update_fixture()?;
    let acknowledgement = live_acknowledgement(&committed, &signer, vec![[42; 16]])?;
    for index in 0..9 {
        assert!(committed
            .authenticate_live_acknowledgement(&replace_nested_unsigned_field(
                &acknowledgement,
                index,
                Value::Null,
            )?)
            .is_err());
    }
    let mut wrapper = array_values(&decode_canonical(&acknowledgement)?)?.to_vec();
    for index in 1..3 {
        let original = std::mem::replace(&mut wrapper[index], Value::Null);
        assert!(committed
            .authenticate_live_acknowledgement(&encode(&Value::Array(wrapper.clone()))?)
            .is_err());
        wrapper[index] = original;
    }
    let forged = live_acknowledgement(
        &committed,
        &SigningKey::from_bytes(&[9; 32]),
        vec![[42; 16]],
    )?;
    assert!(committed
        .authenticate_live_acknowledgement(&forged)
        .is_err());
    Ok(())
}

#[test]
fn committed_update_rejects_changed_manifest_and_recovery_floor() -> TestResult {
    let (fixture, committed, _signer) = committed_update_fixture()?;
    let manifest_path = fixture.directory.path().join(MANIFEST_NAME);
    fs::set_permissions(&manifest_path, fs::Permissions::from_mode(0o600))?;
    assert!(committed.verify_recovery_floor().is_err());

    fs::set_permissions(&manifest_path, fs::Permissions::from_mode(0o400))?;
    let recovery_path = fixture.directory.path().join(RECOVERY_NAME);
    fs::set_permissions(&recovery_path, fs::Permissions::from_mode(0o600))?;
    assert!(committed.verify_recovery_floor().is_err());
    Ok(())
}

#[test]
fn durable_update_rejects_invalid_snapshots_and_foreign_acknowledgements() -> TestResult {
    let fixture = UpdateFixture::new()?;
    let admitted = fixture.admitted()?;
    assert!(ProviderRuntimeSlot::allocate(&admitted)?
        .bind_observed_process(0, 200)
        .is_err());

    for (live, cancelled) in [
        (vec![[0; 16]], Vec::new()),
        (vec![[42; 16]], vec![[41; 16]]),
        (vec![[42; 16], [41; 16]], Vec::new()),
        (vec![[41; 16]; 257], Vec::new()),
    ] {
        let fixture = UpdateFixture::new()?;
        let admitted = fixture.admitted()?;
        let runtime = ProviderRuntimeSlot::allocate(&admitted)?.bind_observed_process(100, 200)?;
        assert!(InstallationRecoverySnapshot::seal(&admitted, &runtime, live, cancelled).is_err());
    }

    let fixture = UpdateFixture::new()?;
    let admitted = fixture.admitted()?;
    let challenge = admitted.bootstrap().issue_update_challenge()?;
    let request = fixture.request(&challenge, None)?;
    let update = admitted.bootstrap().validate_update(challenge, &request)?;
    let runtime = ProviderRuntimeSlot::allocate(&admitted)?.bind_observed_process(100, 200)?;
    let snapshot =
        InstallationRecoverySnapshot::seal(&admitted, &runtime, vec![[41; 16]], vec![[41; 16]])?;
    let committed = Arc::new(admitted).commit_update(update, snapshot)?;
    let runtime_signer = SigningKey::from_bytes(&[4; 32]);
    let wrong_set = live_acknowledgement(&committed, &runtime_signer, Vec::new())?;
    assert!(committed
        .authenticate_live_acknowledgement(&wrong_set)
        .is_err());
    assert!(fixture.directory.path().join(RECOVERY_NAME).exists());
    Ok(())
}

#[test]
fn durable_commit_rejects_changed_inputs_and_successor_descriptors() -> TestResult {
    let (_fixture, admitted, mut update, snapshot) = pending_update_fixture()?;
    update.replace_previous_manifest_for_test(vec![0; 1]);
    assert!(Arc::new(admitted).commit_update(update, snapshot).is_err());

    let (_fixture, admitted, mut update, snapshot) = pending_update_fixture()?;
    update.clear_revocation_update_for_test();
    assert!(Arc::new(admitted).commit_update(update, snapshot).is_err());

    let (fixture, admitted, update, snapshot) = pending_update_fixture()?;
    let manifest = fixture.directory.path().join(MANIFEST_NAME);
    let mut changed = fs::read(&manifest)?;
    changed[0] ^= 1;
    fs::set_permissions(&manifest, fs::Permissions::from_mode(0o600))?;
    fs::write(&manifest, changed)?;
    fs::set_permissions(&manifest, fs::Permissions::from_mode(0o400))?;
    assert!(Arc::new(admitted).commit_update(update, snapshot).is_err());

    let (fixture, admitted, update, snapshot) = pending_update_fixture()?;
    let path = fixture.successor_object_path(
        &fixture.request(&admitted.bootstrap().issue_update_challenge()?, None)?,
        InstallationObjectKind::ADMINISTRATOR_POLICY,
    )?;
    fs::remove_file(path)?;
    assert!(Arc::new(admitted).commit_update(update, snapshot).is_err());

    let (fixture, admitted, update, snapshot) = pending_update_fixture()?;
    let object = update.record_files()[0];
    let identity = update.next_manifest().authority_digests()
        [usize::from(InstallationObjectKind::ADMINISTRATOR_POLICY.code())];
    let descriptor = update
        .next_manifest()
        .object(InstallationObjectKind::ADMINISTRATOR_POLICY, identity)?;
    let path = fixture
        .directory
        .path()
        .join(InstallationObjectKind::ADMINISTRATOR_POLICY.directory())
        .join(hex_name(descriptor.content_digest()));
    let bytes = fs::read(&path)?;
    let held = path.with_extension("held");
    fs::rename(&path, &held)?;
    fs::write(&path, bytes)?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o400))?;
    assert_ne!(object.metadata()?.ino(), fs::metadata(&path)?.ino());
    assert!(Arc::new(admitted).commit_update(update, snapshot).is_err());
    Ok(())
}

#[test]
fn committed_update_rejects_third_state_and_foreign_authenticated_acknowledgement() -> TestResult {
    let (fixture, committed, _signer) = committed_update_fixture()?;
    let manifest = fixture.directory.path().join(MANIFEST_NAME);
    let mut third_state = fs::read(&manifest)?;
    third_state[0] ^= 1;
    fs::set_permissions(&manifest, fs::Permissions::from_mode(0o600))?;
    fs::write(&manifest, third_state)?;
    fs::set_permissions(&manifest, fs::Permissions::from_mode(0o400))?;
    assert!(committed.verify_recovery_floor().is_err());

    let (_fixture_a, committed_a, _signer_a) = committed_update_fixture()?;
    let (_fixture_b, committed_b, signer_b) = committed_update_fixture()?;
    let bytes = live_acknowledgement(&committed_b, &signer_b, vec![[42; 16]])?;
    let acknowledgement = committed_b.authenticate_live_acknowledgement(&bytes)?;
    let committed_a = Arc::into_inner(committed_a).ok_or("committed update still shared")?;
    assert!(committed_a.complete_live_update(&acknowledgement).is_err());
    Ok(())
}

#[test]
fn committed_update_accepts_an_already_published_successor_manifest() -> TestResult {
    let fixture = UpdateFixture::new()?;
    let admitted = fixture.admitted()?;
    let challenge = admitted.bootstrap().issue_update_challenge()?;
    let request = fixture.request(&challenge, None)?;
    let request_document = decode_canonical(&request)?;
    let Value::Bytes(next_manifest) = &array(&request_document, 5)?[3] else {
        return Err("SIU1 successor manifest is not bytes".into());
    };
    let update = admitted.bootstrap().validate_update(challenge, &request)?;
    let runtime = ProviderRuntimeSlot::allocate(&admitted)?.bind_observed_process(100, 200)?;
    let snapshot =
        InstallationRecoverySnapshot::seal(&admitted, &runtime, vec![[41; 16]], vec![[41; 16]])?;
    let committed = Arc::new(admitted).commit_update(update, snapshot)?;

    let manifest = fixture.directory.path().join(MANIFEST_NAME);
    fs::set_permissions(&manifest, fs::Permissions::from_mode(0o600))?;
    fs::write(&manifest, next_manifest)?;
    fs::set_permissions(&manifest, fs::Permissions::from_mode(0o400))?;
    let bytes = live_acknowledgement(
        &committed,
        &SigningKey::from_bytes(&[4; 32]),
        vec![[41; 16]],
    )?;
    let acknowledgement = committed.authenticate_live_acknowledgement(&bytes)?;
    committed.complete_live_update(&acknowledgement)?;
    assert!(!fixture.directory.path().join(RECOVERY_NAME).exists());
    Ok(())
}
