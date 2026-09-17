use ciborium::value::Value;
use pos_core::{
    ArtifactDataClassV1, ArtifactOptionalityV1, ArtifactTransitionRuleV1, Hash, KeyRoleV1,
    WorldArtifactErrorV1, WorldArtifactKeyDependencyV1, WorldArtifactKindV1,
    WorldArtifactLeafInputV1, WorldArtifactLeafV1, MAX_WORLD_ARTIFACT_CHILDREN_V1,
    MAX_WORLD_ARTIFACT_KEYS_V1, MAX_WORLD_ARTIFACT_LEAF_BYTES_V1,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn input() -> WorldArtifactLeafInputV1 {
    WorldArtifactLeafInputV1 {
        scope: Hash::from_bytes([1; 32]),
        kind: WorldArtifactKindV1::TimelinePayload,
        native_digest: Hash::from_bytes([2; 32]),
        native_byte_length: 0,
        owner: [3; 32],
        data_class: ArtifactDataClassV1::PrivateSubjectData,
        optionality: ArtifactOptionalityV1::Required,
        transition: ArtifactTransitionRuleV1::PreserveExact,
        source_lease_hash: Hash::from_bytes([4; 32]),
        key_dependencies: Vec::new(),
        child_node_hashes: Vec::new(),
    }
}

fn wire() -> Vec<Value> {
    vec![
        Value::Bytes(b"WAL1".to_vec()),
        Value::Integer(1.into()),
        Value::Bytes(vec![1; 32]),
        Value::Integer(12.into()),
        Value::Bytes(vec![2; 32]),
        Value::Integer(0.into()),
        Value::Bytes(vec![3; 32]),
        Value::Integer(0.into()),
        Value::Integer(0.into()),
        Value::Integer(0.into()),
        Value::Bytes(vec![4; 32]),
        Value::Array(Vec::new()),
        Value::Array(Vec::new()),
    ]
}

fn encode(fields: Vec<Value>) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut bytes = Vec::new();
    ciborium::into_writer(&Value::Array(fields), &mut bytes)?;
    Ok(bytes)
}

fn ordered_hash(ordinal: u16) -> Hash {
    let mut bytes = [0; 32];
    bytes[30..].copy_from_slice(&ordinal.to_be_bytes());
    Hash::from_bytes(bytes)
}

const fn key(role: KeyRoleV1, identity: Hash, owner: u8) -> WorldArtifactKeyDependencyV1 {
    WorldArtifactKeyDependencyV1 {
        role,
        identity_digest: identity,
        owner: [owner; 32],
    }
}

#[test]
fn preferred_bytes_and_digest_are_independently_pinned() -> TestResult {
    let leaf = WorldArtifactLeafV1::new(input())?;
    let mut expected = vec![0x8d, 0x44, b'W', b'A', b'L', b'1', 1, 0x58, 32];
    expected.extend_from_slice(&[1; 32]);
    expected.extend_from_slice(&[12, 0x58, 32]);
    expected.extend_from_slice(&[2; 32]);
    expected.extend_from_slice(&[0, 0x58, 32]);
    expected.extend_from_slice(&[3; 32]);
    expected.extend_from_slice(&[0, 0, 0, 0x58, 32]);
    expected.extend_from_slice(&[4; 32]);
    expected.extend_from_slice(&[0x80, 0x80]);
    assert_eq!(expected.len(), 150);
    assert_eq!(encode(wire())?, expected);
    assert_eq!(leaf.to_canonical_cbor(), expected);
    assert_eq!(WorldArtifactLeafV1::from_canonical_cbor(&expected)?, leaf);
    assert_eq!(leaf.as_input(), &input());
    // Computed independently with b3sum over the literal domain/NUL/bytes.
    assert_eq!(
        leaf.digest().as_bytes(),
        &[
            0x22, 0x0c, 0x26, 0x6b, 0x3d, 0xfc, 0x0a, 0x17, 0x42, 0x3b, 0x2a, 0x3a, 0x85, 0x14,
            0x7e, 0x8b, 0xf1, 0xef, 0x90, 0x11, 0x7e, 0x3b, 0xba, 0xba, 0xb4, 0xbe, 0xf9, 0xde,
            0x9b, 0x2f, 0x66, 0xd2,
        ]
    );
    Ok(())
}

#[test]
fn all_closed_kind_codes_and_integer_width_boundaries_roundtrip() -> TestResult {
    let kinds = [
        WorldArtifactKindV1::OutputPolicy,
        WorldArtifactKindV1::ExecutableBudgetPolicy,
        WorldArtifactKindV1::RetentionPolicy,
        WorldArtifactKindV1::RetentionLease,
        WorldArtifactKindV1::BaseConfiguration,
        WorldArtifactKindV1::ExecutionProfile,
        WorldArtifactKindV1::AudiencePolicy,
        WorldArtifactKindV1::Schema,
        WorldArtifactKindV1::ReducerImplementation,
        WorldArtifactKindV1::RuntimeIdentity,
        WorldArtifactKindV1::PluginImplementationIdentity,
        WorldArtifactKindV1::KeyDependencyEvidence,
        WorldArtifactKindV1::TimelinePayload,
        WorldArtifactKindV1::OptionalView,
    ];
    for (ordinal, kind) in kinds.into_iter().enumerate() {
        let code = u8::try_from(ordinal)?;
        assert_eq!(kind.code(), code);
        assert_eq!(WorldArtifactKindV1::from_code(code)?, kind);
        for length in [
            0,
            23,
            24,
            255,
            256,
            65_535,
            65_536,
            4_294_967_295,
            4_294_967_296,
            u64::MAX,
        ] {
            let mut fields = input();
            fields.kind = kind;
            fields.native_byte_length = length;
            let leaf = WorldArtifactLeafV1::new(fields)?;
            let mut expected = wire();
            expected[3] = Value::Integer(code.into());
            expected[5] = Value::Integer(length.into());
            let encoded = encode(expected)?;
            assert_eq!(leaf.to_canonical_cbor(), encoded);
            assert_eq!(WorldArtifactLeafV1::from_canonical_cbor(&encoded)?, leaf);
        }
    }
    for code in [14, 18, 255] {
        assert_eq!(
            WorldArtifactKindV1::from_code(code),
            Err(WorldArtifactErrorV1::UnsupportedValue)
        );
    }
    Ok(())
}

#[test]
fn classifications_and_registry_roles_keep_their_exact_wire_codes() -> TestResult {
    let classes = [
        ArtifactDataClassV1::PrivateSubjectData,
        ArtifactDataClassV1::ConsentedSharedData,
        ArtifactDataClassV1::PublicRecord,
        ArtifactDataClassV1::AggregateData,
        ArtifactDataClassV1::StructuralAuditMetadata,
    ];
    let optionalities = [
        ArtifactOptionalityV1::Required,
        ArtifactOptionalityV1::Optional,
    ];
    let transitions = [
        ArtifactTransitionRuleV1::PreserveExact,
        ArtifactTransitionRuleV1::RedactViews,
        ArtifactTransitionRuleV1::RetainStructure,
        ArtifactTransitionRuleV1::Remove,
    ];
    let roles = [
        KeyRoleV1::SubjectDataEncryption,
        KeyRoleV1::SubjectAttributionSigning,
        KeyRoleV1::TimelineIntegritySigning,
        KeyRoleV1::PluginReleaseSigning,
        KeyRoleV1::ExportRecipientEncryption,
    ];
    for (class_code, data_class) in classes.into_iter().enumerate() {
        for (option_code, optionality) in optionalities.into_iter().enumerate() {
            for (transition_code, transition) in transitions.into_iter().enumerate() {
                for (role_code, role) in roles.into_iter().enumerate() {
                    let mut fields = input();
                    fields.data_class = data_class;
                    fields.optionality = optionality;
                    fields.transition = transition;
                    fields.key_dependencies = vec![key(role, ordered_hash(1), 9)];
                    fields.child_node_hashes = vec![ordered_hash(2)];
                    let leaf = WorldArtifactLeafV1::new(fields)?;
                    let mut expected = wire();
                    expected[7] = Value::Integer(u64::try_from(class_code)?.into());
                    expected[8] = Value::Integer(u64::try_from(option_code)?.into());
                    expected[9] = Value::Integer(u64::try_from(transition_code)?.into());
                    expected[11] = Value::Array(vec![Value::Array(vec![
                        Value::Integer(u64::try_from(role_code)?.into()),
                        Value::Bytes(ordered_hash(1).as_bytes().to_vec()),
                        Value::Bytes(vec![9; 32]),
                    ])]);
                    expected[12] =
                        Value::Array(vec![Value::Bytes(ordered_hash(2).as_bytes().to_vec())]);
                    let bytes = encode(expected)?;
                    assert_eq!(leaf.to_canonical_cbor(), bytes);
                    assert_eq!(WorldArtifactLeafV1::from_canonical_cbor(&bytes)?, leaf);
                }
            }
        }
    }
    Ok(())
}

#[test]
fn maximum_lists_and_full_triple_order_are_preserved() -> TestResult {
    assert_eq!(MAX_WORLD_ARTIFACT_KEYS_V1, 16);
    assert_eq!(MAX_WORLD_ARTIFACT_CHILDREN_V1, 256);
    assert_eq!(MAX_WORLD_ARTIFACT_LEAF_BYTES_V1, 16_384);
    for count in [0, 1, 16, 23, 24, 255, 256] {
        let mut fields = input();
        fields.key_dependencies = (1..=16)
            .map(|ordinal| key(KeyRoleV1::SubjectDataEncryption, ordered_hash(ordinal), 9))
            .collect();
        fields.child_node_hashes = (1..=count).map(ordered_hash).collect();
        let leaf = WorldArtifactLeafV1::new(fields)?;
        let bytes = leaf.to_canonical_cbor();
        assert!(bytes.len() <= MAX_WORLD_ARTIFACT_LEAF_BYTES_V1);
        assert_eq!(WorldArtifactLeafV1::from_canonical_cbor(&bytes)?, leaf);
        assert_eq!(leaf.as_input().child_node_hashes.len(), usize::from(count));
    }
    let mut fields = input();
    fields.key_dependencies = vec![
        key(KeyRoleV1::SubjectDataEncryption, ordered_hash(1), 1),
        key(KeyRoleV1::SubjectDataEncryption, ordered_hash(1), 2),
        key(KeyRoleV1::SubjectDataEncryption, ordered_hash(2), 0),
        key(KeyRoleV1::SubjectAttributionSigning, ordered_hash(1), 0),
    ];
    let leaf = WorldArtifactLeafV1::new(fields)?;
    assert_eq!(
        WorldArtifactLeafV1::from_canonical_cbor(&leaf.to_canonical_cbor())?,
        leaf
    );
    Ok(())
}

#[test]
fn zero_content_addresses_and_excessive_lists_are_rejected() {
    for field in 0..5 {
        let mut fields = input();
        match field {
            0 => fields.scope = Hash::zero(),
            1 => fields.native_digest = Hash::zero(),
            2 => fields.source_lease_hash = Hash::zero(),
            3 => {
                fields
                    .key_dependencies
                    .push(key(KeyRoleV1::SubjectDataEncryption, Hash::zero(), 1))
            }
            _ => fields.child_node_hashes.push(Hash::zero()),
        }
        assert_eq!(
            WorldArtifactLeafV1::new(fields),
            Err(WorldArtifactErrorV1::FieldOutOfBounds)
        );
    }
    let mut fields = input();
    fields.key_dependencies = (1..=17)
        .map(|ordinal| key(KeyRoleV1::SubjectDataEncryption, ordered_hash(ordinal), 9))
        .collect();
    assert_eq!(
        WorldArtifactLeafV1::new(fields),
        Err(WorldArtifactErrorV1::FieldOutOfBounds)
    );
    let mut fields = input();
    fields.child_node_hashes = (1..=257).map(ordered_hash).collect();
    assert_eq!(
        WorldArtifactLeafV1::new(fields),
        Err(WorldArtifactErrorV1::FieldOutOfBounds)
    );
}

#[test]
fn duplicate_and_reversed_lists_are_not_sorted_or_deduplicated() -> TestResult {
    let mut fields = input();
    fields.key_dependencies = vec![
        key(KeyRoleV1::SubjectDataEncryption, ordered_hash(1), 1),
        key(KeyRoleV1::SubjectDataEncryption, ordered_hash(1), 2),
        key(KeyRoleV1::SubjectAttributionSigning, ordered_hash(1), 1),
    ];
    fields.child_node_hashes = vec![ordered_hash(1), ordered_hash(2)];
    for pair in 0..2 {
        let mut reversed = fields.clone();
        reversed.key_dependencies.swap(pair, pair + 1);
        assert_eq!(
            WorldArtifactLeafV1::new(reversed),
            Err(WorldArtifactErrorV1::InvalidDependencyOrder)
        );
        let mut duplicate = fields.clone();
        duplicate.key_dependencies[pair + 1] = duplicate.key_dependencies[pair];
        assert_eq!(
            WorldArtifactLeafV1::new(duplicate),
            Err(WorldArtifactErrorV1::InvalidDependencyOrder)
        );
    }
    for children in [
        vec![ordered_hash(2), ordered_hash(1)],
        vec![ordered_hash(1); 2],
    ] {
        let mut changed = fields.clone();
        changed.child_node_hashes = children;
        assert_eq!(
            WorldArtifactLeafV1::new(changed),
            Err(WorldArtifactErrorV1::InvalidDependencyOrder)
        );
    }
    let bytes = WorldArtifactLeafV1::new(fields)?.to_canonical_cbor();
    let mut decoded: Value = ciborium::from_reader(bytes.as_slice())?;
    if let Value::Array(root) = &mut decoded {
        root[12] = Value::Array(vec![Value::Bytes(ordered_hash(1).as_bytes().to_vec()); 2]);
    }
    let mut malformed = Vec::new();
    ciborium::into_writer(&decoded, &mut malformed)?;
    assert_eq!(
        WorldArtifactLeafV1::from_canonical_cbor(&malformed),
        Err(WorldArtifactErrorV1::InvalidDependencyOrder)
    );
    Ok(())
}

#[test]
fn wrong_shapes_and_types_are_rejected_through_public_decode() -> TestResult {
    for count in [0, 12, 14] {
        let fields = vec![Value::Null; count];
        assert_eq!(
            WorldArtifactLeafV1::from_canonical_cbor(&encode(fields)?),
            Err(WorldArtifactErrorV1::InvalidEncoding)
        );
    }
    for index in 0..13 {
        for replacement in [
            Value::Null,
            Value::Bool(true),
            Value::Float(0.0),
            Value::Text("x".into()),
            Value::Integer((-1).into()),
        ] {
            let mut fields = wire();
            fields[index] = replacement;
            assert!(WorldArtifactLeafV1::from_canonical_cbor(&encode(fields)?).is_err());
        }
    }
    for index in [0, 2, 4, 6, 10] {
        for width in [0, 3, 5, 31, 33] {
            let mut fields = wire();
            fields[index] = Value::Bytes(vec![1; width]);
            assert_eq!(
                WorldArtifactLeafV1::from_canonical_cbor(&encode(fields)?),
                Err(WorldArtifactErrorV1::InvalidEncoding)
            );
        }
    }
    let mut fields = wire();
    fields[0] = Value::Bytes(b"WAL2".to_vec());
    assert_eq!(
        WorldArtifactLeafV1::from_canonical_cbor(&encode(fields)?),
        Err(WorldArtifactErrorV1::InvalidEncoding)
    );
    for (index, value) in [(1, 0), (1, 2), (3, 14), (7, 5), (8, 2), (9, 4)] {
        let mut fields = wire();
        fields[index] = Value::Integer(value.into());
        assert_eq!(
            WorldArtifactLeafV1::from_canonical_cbor(&encode(fields)?),
            Err(WorldArtifactErrorV1::UnsupportedValue)
        );
    }
    for index in [3, 7, 8, 9] {
        let mut fields = wire();
        fields[index] = Value::Integer(256.into());
        assert_eq!(
            WorldArtifactLeafV1::from_canonical_cbor(&encode(fields)?),
            Err(WorldArtifactErrorV1::FieldOutOfBounds)
        );
    }
    Ok(())
}

#[test]
fn nested_key_rows_and_counts_are_bounded_before_allocation() -> TestResult {
    let good_key = vec![
        Value::Integer(0.into()),
        Value::Bytes(vec![5; 32]),
        Value::Bytes(vec![6; 32]),
    ];
    for count in [0, 2, 4] {
        let mut fields = wire();
        fields[11] = Value::Array(vec![Value::Array(vec![Value::Null; count])]);
        assert_eq!(
            WorldArtifactLeafV1::from_canonical_cbor(&encode(fields)?),
            Err(WorldArtifactErrorV1::InvalidEncoding)
        );
    }
    for position in 0..3 {
        let mut row = good_key.clone();
        row[position] = Value::Null;
        let mut fields = wire();
        fields[11] = Value::Array(vec![Value::Array(row)]);
        assert_eq!(
            WorldArtifactLeafV1::from_canonical_cbor(&encode(fields)?),
            Err(WorldArtifactErrorV1::InvalidEncoding)
        );
    }
    for (role, error) in [
        (5, WorldArtifactErrorV1::UnsupportedValue),
        (256, WorldArtifactErrorV1::FieldOutOfBounds),
    ] {
        let mut row = good_key.clone();
        row[0] = Value::Integer(role.into());
        let mut fields = wire();
        fields[11] = Value::Array(vec![Value::Array(row)]);
        assert_eq!(
            WorldArtifactLeafV1::from_canonical_cbor(&encode(fields)?),
            Err(error)
        );
    }
    for (position, count) in [(11, 17), (12, 257)] {
        let mut fields = wire();
        fields[position] = Value::Array(vec![Value::Null; count]);
        assert_eq!(
            WorldArtifactLeafV1::from_canonical_cbor(&encode(fields)?),
            Err(WorldArtifactErrorV1::FieldOutOfBounds)
        );
    }
    for position in [11, 12] {
        let mut bytes = encode(wire())?;
        let offset = bytes.len() - if position == 11 { 2 } else { 1 };
        bytes.splice(
            offset..offset + 1,
            [0x9b, 255, 255, 255, 255, 255, 255, 255, 255],
        );
        assert_eq!(
            WorldArtifactLeafV1::from_canonical_cbor(&bytes),
            Err(WorldArtifactErrorV1::FieldOutOfBounds)
        );
    }
    Ok(())
}

#[test]
fn decoder_revalidates_addresses_and_key_triple_order() -> TestResult {
    for position in [2, 4, 10] {
        let mut fields = wire();
        fields[position] = Value::Bytes(vec![0; 32]);
        assert_eq!(
            WorldArtifactLeafV1::from_canonical_cbor(&encode(fields)?),
            Err(WorldArtifactErrorV1::FieldOutOfBounds)
        );
    }
    let row = vec![
        Value::Integer(0.into()),
        Value::Bytes(vec![5; 32]),
        Value::Bytes(vec![6; 32]),
    ];
    let mut zero_key = row.clone();
    zero_key[1] = Value::Bytes(vec![0; 32]);
    let mut fields = wire();
    fields[11] = Value::Array(vec![Value::Array(zero_key)]);
    assert_eq!(
        WorldArtifactLeafV1::from_canonical_cbor(&encode(fields)?),
        Err(WorldArtifactErrorV1::FieldOutOfBounds)
    );
    let mut fields = wire();
    fields[12] = Value::Array(vec![Value::Bytes(vec![0; 32])]);
    assert_eq!(
        WorldArtifactLeafV1::from_canonical_cbor(&encode(fields)?),
        Err(WorldArtifactErrorV1::FieldOutOfBounds)
    );
    for rows in [
        vec![Value::Array(row.clone()); 2],
        vec![
            Value::Array(vec![
                Value::Integer(0.into()),
                Value::Bytes(vec![5; 32]),
                Value::Bytes(vec![7; 32]),
            ]),
            Value::Array(row),
        ],
    ] {
        let mut fields = wire();
        fields[11] = Value::Array(rows);
        assert_eq!(
            WorldArtifactLeafV1::from_canonical_cbor(&encode(fields)?),
            Err(WorldArtifactErrorV1::InvalidDependencyOrder)
        );
    }
    Ok(())
}

#[test]
fn truncation_reserved_heads_nonpreferred_heads_and_trailing_bytes_reject() -> TestResult {
    let bytes = encode(wire())?;
    for end in 0..bytes.len() {
        assert!(WorldArtifactLeafV1::from_canonical_cbor(&bytes[..end]).is_err());
    }
    for initial in [0x9c, 0x9d, 0x9e, 0x9f, 0xbf, 0xc0] {
        let mut invalid = bytes.clone();
        invalid[0] = initial;
        assert_eq!(
            WorldArtifactLeafV1::from_canonical_cbor(&invalid),
            Err(WorldArtifactErrorV1::InvalidEncoding)
        );
    }
    for alternative in [
        vec![0x98, 13],
        vec![0x99, 0, 13],
        vec![0x9a, 0, 0, 0, 13],
        vec![0x9b, 0, 0, 0, 0, 0, 0, 0, 13],
    ] {
        let mut nonpreferred = alternative;
        nonpreferred.extend_from_slice(&bytes[1..]);
        assert_eq!(
            WorldArtifactLeafV1::from_canonical_cbor(&nonpreferred),
            Err(WorldArtifactErrorV1::NonCanonical)
        );
    }
    for (offset, length, replacement) in [
        (1, 1, vec![0x58, 4]),
        (6, 1, vec![0x18, 1]),
        (7, 2, vec![0x59, 0, 32]),
        (41, 1, vec![0x18, 12]),
        (76, 1, vec![0x18, 0]),
        (148, 1, vec![0x98, 0]),
        (149, 1, vec![0x98, 0]),
    ] {
        let mut nonpreferred = bytes.clone();
        nonpreferred.splice(offset..offset + length, replacement);
        assert_eq!(
            WorldArtifactLeafV1::from_canonical_cbor(&nonpreferred),
            Err(WorldArtifactErrorV1::NonCanonical)
        );
    }
    let mut trailing = bytes;
    trailing.push(0);
    assert_eq!(
        WorldArtifactLeafV1::from_canonical_cbor(&trailing),
        Err(WorldArtifactErrorV1::NonCanonical)
    );
    let oversized = vec![0; MAX_WORLD_ARTIFACT_LEAF_BYTES_V1 + 1];
    assert_eq!(
        WorldArtifactLeafV1::from_canonical_cbor(&oversized),
        Err(WorldArtifactErrorV1::FieldOutOfBounds)
    );
    Ok(())
}

#[test]
fn structural_registration_is_not_native_verification() -> TestResult {
    let mut fields = input();
    fields.owner = [0; 32];
    fields.native_byte_length = u64::MAX;
    // IDs are opaque fixed-width bytes, not content addresses. Actual owner,
    // native length, source lease and reference membership need native proofs.
    let leaf = WorldArtifactLeafV1::new(fields)?;
    assert_eq!(
        WorldArtifactLeafV1::from_canonical_cbor(&leaf.to_canonical_cbor())?,
        leaf
    );
    for error in [
        WorldArtifactErrorV1::InvalidEncoding,
        WorldArtifactErrorV1::NonCanonical,
        WorldArtifactErrorV1::UnsupportedValue,
        WorldArtifactErrorV1::FieldOutOfBounds,
        WorldArtifactErrorV1::InvalidDependencyOrder,
    ] {
        assert!(!error.to_string().is_empty());
    }
    Ok(())
}
