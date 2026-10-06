use pos_core::{
    deletion_receipt, resolve_coordinator_key_evidence_v1, test_coordinator_key_evidence,
    test_coordinator_key_registration, test_coordinator_key_registry,
    CoordinatorKeyEvidenceErrorV1, CoordinatorKeyEvidenceV1, Hash, KeyDestructionRequestV1,
    KeyIdentityV1, KeyRecordV1, KeyRegistrationOutcomeV1, KeyRegistrationV1, KeyRegistryErrorV1,
    KeyRegistryPortV1, KeyRegistryStateV1, KeyRoleV1, KeyTombstoneV1, LocalCutOwnerErrorV1,
    ManifestOwnerAdmissionErrorV1, OwnerIdV1, PublicKey, WorldKeyEvidenceErrorV1,
    WorldKeyEvidenceInputV1, WorldKeyEvidenceV1, MAX_WORLD_KEY_EVIDENCE_BYTES_V1,
    TEST_COORDINATOR_OWNER,
};

type TestResult<T> = Result<T, Box<dyn std::error::Error>>;

fn vector() -> TestResult<WorldKeyEvidenceV1> {
    Ok(WorldKeyEvidenceV1::new(WorldKeyEvidenceInputV1 {
        identity: KeyIdentityV1::new("alice", KeyRoleV1::TimelineIntegritySigning, 1),
        private_material_digest: Hash::from_bytes([0x11; 32]),
        private_material_required: false,
        public_verification_key: Some(PublicKey::from_bytes([0x22; 32])),
    })?)
}

fn from_hex(text: &str) -> TestResult<Vec<u8>> {
    let mut bytes = Vec::new();
    for pair in text.as_bytes().chunks_exact(2) {
        let digits = std::str::from_utf8(pair)?;
        bytes.push(u8::from_str_radix(digits, 16)?);
    }
    Ok(bytes)
}

#[test]
fn normative_wke1_and_identity_vectors_are_exact() -> TestResult<()> {
    let record = vector()?;
    let bytes = from_hex(concat!(
        "8844574b45310165616c69636502015820",
        "1111111111111111111111111111111111111111111111111111111111111111",
        "f45820",
        "2222222222222222222222222222222222222222222222222222222222222222"
    ))?;
    assert_eq!(record.to_canonical_cbor(), bytes);
    assert_eq!(bytes.len(), 84);
    assert_eq!(WorldKeyEvidenceV1::from_canonical_cbor(&bytes), Ok(record));
    assert_eq!(record.as_input().identity.owner_id.as_str(), "alice");
    assert_eq!(
        record.digest().as_bytes().to_vec(),
        from_hex("cf9035220ee933b35c9c780282769640b3030ab17acc9adfa94ec906689d14cf")?
    );
    assert_eq!(
        record.identity_digest().as_bytes().to_vec(),
        from_hex("082c6f98ae370dd573ab184c6648c72e6ccb99cfa9cc229d60e21c968c9ecc58")?
    );
    Ok(())
}

#[test]
fn valid_signing_and_encryption_roles_round_trip_at_integer_boundaries() -> TestResult<()> {
    for (role, has_public_key) in [
        (KeyRoleV1::SubjectDataEncryption, false),
        (KeyRoleV1::SubjectAttributionSigning, true),
        (KeyRoleV1::TimelineIntegritySigning, true),
        (KeyRoleV1::PluginReleaseSigning, true),
        (KeyRoleV1::ExportRecipientEncryption, false),
    ] {
        for epoch in [1, 24, 256, 65_536, 4_294_967_296] {
            let record = WorldKeyEvidenceV1::new(WorldKeyEvidenceInputV1 {
                identity: KeyIdentityV1::new("a", role, epoch),
                private_material_digest: Hash::from_bytes([3; 32]),
                private_material_required: !has_public_key,
                public_verification_key: has_public_key.then(|| PublicKey::from_bytes([4; 32])),
            })?;
            assert_eq!(
                WorldKeyEvidenceV1::from_canonical_cbor(&record.to_canonical_cbor()),
                Ok(record)
            );
        }
    }
    for owner_length in [23, 24, 128] {
        let owner = OwnerIdV1::new("z".repeat(owner_length))?;
        let record = WorldKeyEvidenceV1::new(WorldKeyEvidenceInputV1 {
            identity: KeyIdentityV1::from_parts(owner, KeyRoleV1::SubjectDataEncryption, 1),
            private_material_digest: Hash::from_bytes([3; 32]),
            private_material_required: true,
            public_verification_key: None,
        })?;
        let bytes = record.to_canonical_cbor();
        assert!(bytes.len() <= MAX_WORLD_KEY_EVIDENCE_BYTES_V1);
        assert_eq!(WorldKeyEvidenceV1::from_canonical_cbor(&bytes), Ok(record));
    }
    Ok(())
}

#[test]
fn key_identity_and_material_constraints_reject_invalid_fields() -> TestResult<()> {
    let good = *vector()?.as_input();
    for input in [
        WorldKeyEvidenceInputV1 {
            identity: KeyIdentityV1::new("alice", good.identity.role, 0),
            ..good
        },
        WorldKeyEvidenceInputV1 {
            private_material_digest: Hash::zero(),
            ..good
        },
        WorldKeyEvidenceInputV1 {
            public_verification_key: None,
            ..good
        },
        WorldKeyEvidenceInputV1 {
            identity: KeyIdentityV1::new("alice", KeyRoleV1::SubjectDataEncryption, 1),
            ..good
        },
    ] {
        assert_eq!(
            WorldKeyEvidenceV1::new(input),
            Err(WorldKeyEvidenceErrorV1::InvalidKey)
        );
    }
    Ok(())
}

#[test]
fn decoder_rejects_missing_extra_and_invalid_evidence_bytes() -> TestResult<()> {
    let good = vector()?.to_canonical_cbor();
    let mut cases = Vec::new();
    cases.push((Vec::new(), WorldKeyEvidenceErrorV1::InvalidEncoding));
    cases.push((
        good[..20].to_vec(),
        WorldKeyEvidenceErrorV1::InvalidEncoding,
    ));
    cases.push((vec![0; 257], WorldKeyEvidenceErrorV1::FieldOutOfBounds));
    let mut modified = good.clone();
    modified.push(0);
    cases.push((modified, WorldKeyEvidenceErrorV1::InvalidEncoding));
    for (offset, value, expected) in [
        (0, 0x87, WorldKeyEvidenceErrorV1::InvalidEncoding),
        (2, b'X', WorldKeyEvidenceErrorV1::InvalidEncoding),
        (6, 2, WorldKeyEvidenceErrorV1::InvalidEncoding),
        (7, 0x60, WorldKeyEvidenceErrorV1::FieldOutOfBounds),
        (8, 0xff, WorldKeyEvidenceErrorV1::InvalidEncoding),
        (13, 0x20, WorldKeyEvidenceErrorV1::InvalidEncoding),
        (13, 5, WorldKeyEvidenceErrorV1::InvalidKey),
        (14, 0, WorldKeyEvidenceErrorV1::InvalidKey),
        (16, 31, WorldKeyEvidenceErrorV1::InvalidEncoding),
        (49, 0xf6, WorldKeyEvidenceErrorV1::InvalidEncoding),
        (51, 31, WorldKeyEvidenceErrorV1::InvalidEncoding),
    ] {
        let mut modified = good.clone();
        modified[offset] = value;
        cases.push((modified, expected));
    }
    let mut zero_digest = good.clone();
    zero_digest[17..49].fill(0);
    cases.push((zero_digest, WorldKeyEvidenceErrorV1::InvalidKey));
    let mut missing_public_key = good.clone();
    missing_public_key.truncate(50);
    missing_public_key.push(0xf6);
    cases.push((missing_public_key, WorldKeyEvidenceErrorV1::InvalidKey));
    let mut overlong_owner = good.clone();
    overlong_owner[7] = 0x78;
    overlong_owner.insert(8, 129);
    cases.push((overlong_owner, WorldKeyEvidenceErrorV1::FieldOutOfBounds));
    let mut overlong_epoch = good.clone();
    overlong_epoch[14] = 0x18;
    overlong_epoch.insert(15, 1);
    cases.push((overlong_epoch, WorldKeyEvidenceErrorV1::NonCanonical));
    let mut unsupported_integer = good.clone();
    unsupported_integer[14] = 0x1f;
    cases.push((
        unsupported_integer,
        WorldKeyEvidenceErrorV1::InvalidEncoding,
    ));
    let mut unsupported_role_width = good;
    unsupported_role_width[13] = 0x19;
    unsupported_role_width.insert(14, 1);
    unsupported_role_width.insert(15, 0);
    cases.push((unsupported_role_width, WorldKeyEvidenceErrorV1::InvalidKey));
    for (bytes, expected) in cases {
        assert_eq!(
            WorldKeyEvidenceV1::from_canonical_cbor(&bytes),
            Err(expected)
        );
    }
    Ok(())
}

/// The shared epoch-1 coordinator WKE1 with its identity's role replaced.
fn coordinator_with_role(role: KeyRoleV1, seed: u8) -> TestResult<WorldKeyEvidenceV1> {
    let input = *test_coordinator_key_evidence(1).as_input();
    let identity = KeyIdentityV1::from_parts(input.identity.owner_id, role, 1);
    Ok(WorldKeyEvidenceV1::new(WorldKeyEvidenceInputV1 {
        identity,
        private_material_digest: Hash::from_bytes([seed; 32]),
        public_verification_key: Some(PublicKey::from_bytes([seed; 32])),
        ..input
    })?)
}

fn registry(evidence: &[WorldKeyEvidenceV1]) -> TestResult<KeyRegistryStateV1> {
    let mut keys = KeyRegistryStateV1::new();
    for record in evidence {
        let registration = test_coordinator_key_registration(record);
        keys.register_key(registration)?;
    }
    Ok(keys)
}

/// Resolve the exact canonical bytes of `evidence` at its own address.
fn resolve(
    evidence: &WorldKeyEvidenceV1,
    keys: &dyn KeyRegistryPortV1,
) -> Result<WorldKeyEvidenceV1, CoordinatorKeyEvidenceErrorV1> {
    let retained = CoordinatorKeyEvidenceV1 {
        evidence_hash: evidence.digest(),
        bytes: evidence.to_canonical_cbor(),
    };
    retained.resolve(keys)
}

/// Hand-built canonical framing of the shared epoch-1 coordinator WKE1 with
/// `public_key` as its final field: a 32-byte string or CBOR null.
fn coordinator_framing(public_key: Option<[u8; 32]>) -> Vec<u8> {
    let owner = TEST_COORDINATOR_OWNER.as_bytes();
    let mut bytes = vec![0x88, 0x44];
    bytes.extend_from_slice(b"WKE1");
    // Version 1, then a text string head for the 16-byte owner.
    bytes.extend_from_slice(&[0x01, 0x70]);
    bytes.extend_from_slice(owner);
    // Role 2 and epoch 1, then the material digest and an unset
    // private_material_required flag.
    bytes.extend_from_slice(&[0x02, 0x01]);
    bytes.extend(byte_string([1; 32]));
    bytes.push(0xf4);
    let key_field = public_key.map_or_else(|| vec![0xf6], byte_string);
    bytes.extend(key_field);
    bytes
}

/// One preferred-CBOR 32-byte string.
fn byte_string(value: [u8; 32]) -> Vec<u8> {
    let mut field = vec![0x58, 0x20];
    field.extend_from_slice(&value);
    field
}

/// A registry port that answers every identity with one fixed live record.
struct FixedRecord(KeyRecordV1);

impl KeyRegistryPortV1 for FixedRecord {
    fn register_key(
        &mut self,
        _registration: KeyRegistrationV1,
    ) -> Result<KeyRegistrationOutcomeV1, KeyRegistryErrorV1> {
        Err(KeyRegistryErrorV1::RegistryUnavailable)
    }

    fn active_key(&self, _owner_id: &OwnerIdV1, _role: KeyRoleV1) -> Option<KeyRecordV1> {
        Some(self.0)
    }

    fn key_record(&self, _identity: KeyIdentityV1) -> Option<KeyRecordV1> {
        Some(self.0)
    }

    fn tombstone(&self, _identity: KeyIdentityV1) -> Option<KeyTombstoneV1> {
        None
    }
}

#[test]
fn shared_coordinator_fixtures_name_distinct_registered_epochs() {
    let first = test_coordinator_key_evidence(1);
    assert_eq!(test_coordinator_key_evidence(0), first);
    let identity = first.as_input().identity;
    assert_eq!(identity.owner_id.as_str(), TEST_COORDINATOR_OWNER);
    assert_eq!(identity.role, KeyRoleV1::TimelineIntegritySigning);
    assert_eq!(identity.epoch, 1);
    assert!(!first.as_input().private_material_required);
    let second = test_coordinator_key_evidence(2);
    let (earlier, later) = (first.as_input(), second.as_input());
    assert_eq!(later.identity.epoch, 2);
    assert_ne!(
        earlier.private_material_digest,
        later.private_material_digest
    );
    assert_ne!(
        earlier.public_verification_key,
        later.public_verification_key
    );
    let registration = test_coordinator_key_registration(&second);
    let registered = (
        registration.identity,
        registration.private_material_digest,
        registration.public_verification_key,
    );
    let expected = (
        later.identity,
        later.private_material_digest,
        later.public_verification_key,
    );
    assert_eq!(registered, expected);
    let keys = test_coordinator_key_registry();
    assert_eq!(resolve(&first, &keys), Ok(first));
    assert_eq!(
        resolve(&second, &keys),
        Err(CoordinatorKeyEvidenceErrorV1::UnregisteredKey)
    );
}

#[test]
fn coordinator_evidence_resolves_live_rotated_and_tombstoned_keys() -> TestResult<()> {
    let evidence = test_coordinator_key_evidence(1);
    let input = *evidence.as_input();
    let mut keys = test_coordinator_key_registry();
    assert_eq!(resolve(&evidence, &keys), Ok(evidence));

    let rotation = test_coordinator_key_registration(&test_coordinator_key_evidence(2));
    keys.register_key(rotation)?;
    assert_eq!(resolve(&evidence, &keys), Ok(evidence));

    let authorization = Hash::from_bytes([0xe1; 32]);
    let request =
        KeyDestructionRequestV1::new(input.identity, input.private_material_digest, authorization);
    keys.begin_key_destruction(request)?;
    let receipt = deletion_receipt(&request);
    keys.complete_key_destruction(request, receipt)?;
    let destroyed = keys.key_record(input.identity);
    let retained_material = destroyed.map(|record| record.private_material_digest);
    assert_eq!(retained_material, Some(None));
    assert_eq!(resolve(&evidence, &keys), Ok(evidence));

    let other_material = WorldKeyEvidenceV1::new(WorldKeyEvidenceInputV1 {
        private_material_digest: Hash::from_bytes([0xc9; 32]),
        ..input
    })?;
    assert_eq!(
        resolve(&other_material, &keys),
        Err(CoordinatorKeyEvidenceErrorV1::UnregisteredKey)
    );
    Ok(())
}

#[test]
fn coordinator_evidence_must_be_the_exact_verify_only_signing_record() -> TestResult<()> {
    let good = test_coordinator_key_evidence(1);
    let release = coordinator_with_role(KeyRoleV1::PluginReleaseSigning, 0xc5)?;
    let keys = registry(&[good, release])?;
    let bytes = good.to_canonical_cbor();
    let invalid = Err(CoordinatorKeyEvidenceErrorV1::InvalidEvidence);
    assert_eq!(
        resolve_coordinator_key_evidence_v1(&[0], good.digest(), &keys),
        invalid
    );
    let other_address = Hash::from_bytes([0x33; 32]);
    assert_eq!(
        resolve_coordinator_key_evidence_v1(&bytes, other_address, &keys),
        invalid
    );
    // The hand-built framing reproduces the canonical record, so its null
    // variant fails only because a signing role has no public key.
    assert_eq!(coordinator_framing(Some([1; 32])), bytes);
    let missing_public_key = coordinator_framing(None);
    assert_eq!(
        WorldKeyEvidenceV1::from_canonical_cbor(&missing_public_key),
        Err(WorldKeyEvidenceErrorV1::InvalidKey)
    );
    assert_eq!(
        resolve_coordinator_key_evidence_v1(&missing_public_key, good.digest(), &keys),
        invalid
    );

    let wrong_use = Err(CoordinatorKeyEvidenceErrorV1::WrongKeyUse);
    assert_eq!(resolve(&release, &keys), wrong_use);
    let attribution = coordinator_with_role(KeyRoleV1::SubjectAttributionSigning, 0xc7)?;
    assert_eq!(resolve(&attribution, &keys), wrong_use);
    let private_required = WorldKeyEvidenceV1::new(WorldKeyEvidenceInputV1 {
        private_material_required: true,
        ..*good.as_input()
    })?;
    assert_eq!(resolve(&private_required, &keys), wrong_use);
    Ok(())
}

#[test]
fn coordinator_evidence_must_match_one_registry_row() -> TestResult<()> {
    let evidence = test_coordinator_key_evidence(1);
    let input = *evidence.as_input();
    let unregistered = Err(CoordinatorKeyEvidenceErrorV1::UnregisteredKey);
    let empty = KeyRegistryStateV1::new();
    assert_eq!(resolve(&evidence, &empty), unregistered);
    let other_material = WorldKeyEvidenceV1::new(WorldKeyEvidenceInputV1 {
        private_material_digest: Hash::from_bytes([0xc3; 32]),
        ..input
    })?;
    let material_keys = registry(&[other_material])?;
    assert_eq!(resolve(&evidence, &material_keys), unregistered);
    let other_key = WorldKeyEvidenceV1::new(WorldKeyEvidenceInputV1 {
        public_verification_key: Some(PublicKey::from_bytes([0xc4; 32])),
        ..input
    })?;
    let public_keys = registry(&[other_key])?;
    assert_eq!(resolve(&evidence, &public_keys), unregistered);

    let fixed = FixedRecord(KeyRecordV1 {
        identity: KeyIdentityV1::from_parts(input.identity.owner_id, input.identity.role, 2),
        private_material_digest: Some(input.private_material_digest),
        public_verification_key: input.public_verification_key,
    });
    assert_eq!(resolve(&evidence, &fixed), unregistered);
    Ok(())
}

#[test]
fn coordinator_evidence_rejections_map_to_owner_commit_errors() {
    let cases = [
        (
            CoordinatorKeyEvidenceErrorV1::InvalidEvidence,
            ManifestOwnerAdmissionErrorV1::InvalidBatch,
            LocalCutOwnerErrorV1::InvalidBatch,
        ),
        (
            CoordinatorKeyEvidenceErrorV1::WrongKeyUse,
            ManifestOwnerAdmissionErrorV1::OwnerRejected,
            LocalCutOwnerErrorV1::OwnerRejected,
        ),
        (
            CoordinatorKeyEvidenceErrorV1::UnregisteredKey,
            ManifestOwnerAdmissionErrorV1::OwnerRejected,
            LocalCutOwnerErrorV1::OwnerRejected,
        ),
    ];
    for (error, admission, local_cut) in cases {
        assert_eq!(ManifestOwnerAdmissionErrorV1::from(error), admission);
        assert_eq!(LocalCutOwnerErrorV1::from(error), local_cut);
    }
}
