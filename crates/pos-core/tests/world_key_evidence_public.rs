use pos_core::{
    Hash, KeyIdentityV1, KeyRoleV1, OwnerIdV1, PublicKey, WorldKeyEvidenceErrorV1,
    WorldKeyEvidenceInputV1, WorldKeyEvidenceV1, MAX_WORLD_KEY_EVIDENCE_BYTES_V1,
};

fn vector() -> WorldKeyEvidenceV1 {
    WorldKeyEvidenceV1::new(WorldKeyEvidenceInputV1 {
        identity: KeyIdentityV1::new("alice", KeyRoleV1::TimelineIntegritySigning, 1),
        private_material_digest: Hash::from_bytes([0x11; 32]),
        private_material_required: false,
        public_verification_key: Some(PublicKey::from_bytes([0x22; 32])),
    })
    .expect("normative WKE1 vector fields")
}

fn from_hex(text: &str) -> Vec<u8> {
    text.as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let digits = std::str::from_utf8(pair).expect("ASCII hex");
            u8::from_str_radix(digits, 16).expect("hex byte")
        })
        .collect()
}

#[test]
fn normative_wke1_and_identity_vectors_are_exact() {
    let record = vector();
    let bytes = from_hex(concat!(
        "8844574b45310165616c69636502015820",
        "1111111111111111111111111111111111111111111111111111111111111111",
        "f45820",
        "2222222222222222222222222222222222222222222222222222222222222222"
    ));
    assert_eq!(record.to_canonical_cbor(), bytes);
    assert_eq!(bytes.len(), 84);
    assert_eq!(WorldKeyEvidenceV1::from_canonical_cbor(&bytes), Ok(record));
    assert_eq!(record.as_input().identity.owner_id.as_str(), "alice");
    assert_eq!(
        record.digest().as_bytes().to_vec(),
        from_hex("cf9035220ee933b35c9c780282769640b3030ab17acc9adfa94ec906689d14cf")
    );
    assert_eq!(
        record.identity_digest().as_bytes().to_vec(),
        from_hex("082c6f98ae370dd573ab184c6648c72e6ccb99cfa9cc229d60e21c968c9ecc58")
    );
}

#[test]
fn valid_signing_and_encryption_roles_round_trip_at_integer_boundaries() {
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
            })
            .expect("valid role and epoch");
            assert_eq!(
                WorldKeyEvidenceV1::from_canonical_cbor(&record.to_canonical_cbor()),
                Ok(record)
            );
        }
    }
    for owner_length in [23, 24, 128] {
        let owner = OwnerIdV1::new("z".repeat(owner_length)).expect("bounded owner");
        let record = WorldKeyEvidenceV1::new(WorldKeyEvidenceInputV1 {
            identity: KeyIdentityV1::from_parts(owner, KeyRoleV1::SubjectDataEncryption, 1),
            private_material_digest: Hash::from_bytes([3; 32]),
            private_material_required: true,
            public_verification_key: None,
        })
        .expect("bounded evidence");
        let bytes = record.to_canonical_cbor();
        assert!(bytes.len() <= MAX_WORLD_KEY_EVIDENCE_BYTES_V1);
        assert_eq!(WorldKeyEvidenceV1::from_canonical_cbor(&bytes), Ok(record));
    }
}

#[test]
fn key_identity_and_material_constraints_reject_invalid_fields() {
    let good = *vector().as_input();
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
}

#[test]
fn decoder_rejects_missing_extra_and_invalid_evidence_bytes() {
    let good = vector().to_canonical_cbor();
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
    let mut unsupported_role_width = good.clone();
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
}
