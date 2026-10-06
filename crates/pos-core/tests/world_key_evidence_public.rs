use pos_core::{
    deletion_receipt, resolve_coordinator_key_evidence_v1, CoordinatorKeyEvidenceErrorV1, Hash,
    KeyDestructionRequestV1, KeyIdentityV1, KeyRecordV1, KeyRegistrationOutcomeV1,
    KeyRegistrationV1, KeyRegistryErrorV1, KeyRegistryPortV1, KeyRegistryStateV1, KeyRoleV1,
    KeyTombstoneV1, LocalCutOwnerErrorV1, ManifestOwnerAdmissionErrorV1, OwnerIdV1, PublicKey,
    WorldKeyEvidenceErrorV1, WorldKeyEvidenceInputV1, WorldKeyEvidenceV1,
    MAX_WORLD_KEY_EVIDENCE_BYTES_V1,
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

const COORDINATOR: &str = "coordinator";

/// The verify-only WKE1 fields of the coordinator's epoch-1 key of `role`.
fn coordinator_input(role: KeyRoleV1) -> WorldKeyEvidenceInputV1 {
    WorldKeyEvidenceInputV1 {
        identity: KeyIdentityV1::new(COORDINATOR, role, 1),
        private_material_digest: Hash::from_bytes([0xc1; 32]),
        private_material_required: false,
        public_verification_key: Some(PublicKey::from_bytes([0xc2; 32])),
    }
}

/// The registry row that exactly matches `input`.
const fn registration(input: &WorldKeyEvidenceInputV1) -> KeyRegistrationV1 {
    KeyRegistrationV1::new(
        input.identity,
        input.private_material_digest,
        input.public_verification_key,
    )
}

fn registry(registrations: &[KeyRegistrationV1]) -> TestResult<KeyRegistryStateV1> {
    let mut keys = KeyRegistryStateV1::new();
    for registration in registrations {
        keys.register_key(*registration)?;
    }
    Ok(keys)
}

/// Resolve the exact canonical bytes of `evidence` at its own address.
fn resolve(
    evidence: &WorldKeyEvidenceV1,
    keys: &dyn KeyRegistryPortV1,
) -> Result<WorldKeyEvidenceV1, CoordinatorKeyEvidenceErrorV1> {
    resolve_coordinator_key_evidence_v1(&evidence.to_canonical_cbor(), evidence.digest(), keys)
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
fn coordinator_evidence_resolves_live_rotated_and_tombstoned_keys() -> TestResult<()> {
    let input = coordinator_input(KeyRoleV1::TimelineIntegritySigning);
    let evidence = WorldKeyEvidenceV1::new(input)?;
    let mut keys = registry(&[registration(&input)])?;
    assert_eq!(resolve(&evidence, &keys), Ok(evidence));

    let rotated = WorldKeyEvidenceInputV1 {
        identity: KeyIdentityV1::new(COORDINATOR, input.identity.role, 2),
        private_material_digest: Hash::from_bytes([0xd1; 32]),
        public_verification_key: Some(PublicKey::from_bytes([0xd2; 32])),
        ..input
    };
    keys.register_key(registration(&rotated))?;
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
    let input = coordinator_input(KeyRoleV1::TimelineIntegritySigning);
    let release = WorldKeyEvidenceInputV1 {
        private_material_digest: Hash::from_bytes([0xc5; 32]),
        public_verification_key: Some(PublicKey::from_bytes([0xc6; 32])),
        ..coordinator_input(KeyRoleV1::PluginReleaseSigning)
    };
    let keys = registry(&[registration(&input), registration(&release)])?;
    let good = WorldKeyEvidenceV1::new(input)?;
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
    let mut missing_public_key = bytes;
    missing_public_key.truncate(50);
    missing_public_key.push(0xf6);
    assert_eq!(
        resolve_coordinator_key_evidence_v1(&missing_public_key, good.digest(), &keys),
        invalid
    );

    let wrong_use = Err(CoordinatorKeyEvidenceErrorV1::WrongKeyUse);
    let wrong_role = WorldKeyEvidenceV1::new(release)?;
    assert_eq!(resolve(&wrong_role, &keys), wrong_use);
    let attribution = coordinator_input(KeyRoleV1::SubjectAttributionSigning);
    let attribution = WorldKeyEvidenceV1::new(attribution)?;
    assert_eq!(resolve(&attribution, &keys), wrong_use);
    let private_required = WorldKeyEvidenceV1::new(WorldKeyEvidenceInputV1 {
        private_material_required: true,
        ..input
    })?;
    assert_eq!(resolve(&private_required, &keys), wrong_use);
    Ok(())
}

#[test]
fn coordinator_evidence_must_match_one_registry_row() -> TestResult<()> {
    let input = coordinator_input(KeyRoleV1::TimelineIntegritySigning);
    let evidence = WorldKeyEvidenceV1::new(input)?;
    let unregistered = Err(CoordinatorKeyEvidenceErrorV1::UnregisteredKey);
    let empty = KeyRegistryStateV1::new();
    assert_eq!(resolve(&evidence, &empty), unregistered);
    let other_material = KeyRegistrationV1 {
        private_material_digest: Hash::from_bytes([0xc3; 32]),
        ..registration(&input)
    };
    let material_keys = registry(&[other_material])?;
    assert_eq!(resolve(&evidence, &material_keys), unregistered);
    let other_key = KeyRegistrationV1 {
        public_verification_key: Some(PublicKey::from_bytes([0xc4; 32])),
        ..registration(&input)
    };
    let public_keys = registry(&[other_key])?;
    assert_eq!(resolve(&evidence, &public_keys), unregistered);

    let record = KeyRecordV1 {
        identity: KeyIdentityV1::new(COORDINATOR, input.identity.role, 2),
        private_material_digest: Some(input.private_material_digest),
        public_verification_key: input.public_verification_key,
    };
    let mut fixed = FixedRecord(record);
    assert_eq!(resolve(&evidence, &fixed), unregistered);
    let owner = input.identity.owner_id;
    assert_eq!(fixed.active_key(&owner, input.identity.role), Some(record));
    assert_eq!(fixed.tombstone(input.identity), None);
    assert_eq!(
        fixed.register_key(registration(&input)),
        Err(KeyRegistryErrorV1::RegistryUnavailable)
    );
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
