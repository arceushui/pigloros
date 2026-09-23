use ciborium::value::Value;
use pos_core::{
    CanonicalBytes, Hash, WorldArtifactKindV1, WorldDependencyDirectoryChildV1,
    WorldDependencyDirectoryErrorV1, WorldDependencyDirectoryInputV1, WorldDependencyDirectoryV1,
    WorldDependencyKeyV1, MAX_WORLD_DEPENDENCY_DIRECTORY_BYTES_V1,
    MAX_WORLD_DEPENDENCY_DIRECTORY_CHILDREN_V1, MAX_WORLD_DEPENDENCY_DIRECTORY_HEIGHT_V1,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

const fn hash(byte: u8) -> Hash {
    Hash::from_bytes([byte; 32])
}

fn indexed_hash(index: u64) -> Hash {
    let mut bytes = [0; 32];
    bytes[24..].copy_from_slice(&index.to_be_bytes());
    Hash::from_bytes(bytes)
}

fn key(
    kind: WorldArtifactKindV1,
    digest: Hash,
) -> Result<WorldDependencyKeyV1, WorldDependencyDirectoryErrorV1> {
    WorldDependencyKeyV1::new(kind, digest)
}

fn child(
    first_key: WorldDependencyKeyV1,
    last_key: WorldDependencyKeyV1,
    leaf_count: u64,
    node_hash: Hash,
) -> Result<WorldDependencyDirectoryChildV1, WorldDependencyDirectoryErrorV1> {
    WorldDependencyDirectoryChildV1::new(first_key, last_key, leaf_count, node_hash)
}

fn record() -> Result<WorldDependencyDirectoryV1, WorldDependencyDirectoryErrorV1> {
    let first = key(WorldArtifactKindV1::OutputPolicy, hash(10))?;
    let second = key(WorldArtifactKindV1::RetentionPolicy, hash(11))?;
    WorldDependencyDirectoryV1::new(WorldDependencyDirectoryInputV1 {
        scope: hash(1),
        height: 1,
        children: vec![
            child(first, first, 1, hash(50))?,
            child(second, second, 1, hash(51))?,
        ],
    })
}

fn key_value(key: WorldDependencyKeyV1) -> Value {
    Value::Array(vec![
        Value::Integer(u64::from(key.kind().code()).into()),
        Value::Bytes(key.native_digest().as_bytes().to_vec()),
    ])
}

fn child_value(
    first_key: WorldDependencyKeyV1,
    last_key: WorldDependencyKeyV1,
    leaf_count: u64,
    node_hash: Hash,
) -> Value {
    Value::Array(vec![
        key_value(first_key),
        key_value(last_key),
        Value::Integer(leaf_count.into()),
        Value::Bytes(node_hash.as_bytes().to_vec()),
    ])
}

fn wire_with(
    scope: Hash,
    height: u64,
    first_key: WorldDependencyKeyV1,
    last_key: WorldDependencyKeyV1,
    leaf_count: u64,
    children: Vec<Value>,
) -> Value {
    Value::Array(vec![
        Value::Bytes(b"WDB1".to_vec()),
        Value::Integer(1.into()),
        Value::Bytes(scope.as_bytes().to_vec()),
        Value::Integer(height.into()),
        key_value(first_key),
        key_value(last_key),
        Value::Integer(leaf_count.into()),
        Value::Array(children),
    ])
}

fn wire() -> Result<Value, WorldDependencyDirectoryErrorV1> {
    let first = key(WorldArtifactKindV1::OutputPolicy, hash(10))?;
    let second = key(WorldArtifactKindV1::RetentionPolicy, hash(11))?;
    Ok(wire_with(
        hash(1),
        1,
        first,
        second,
        2,
        vec![
            child_value(first, first, 1, hash(50)),
            child_value(second, second, 1, hash(51)),
        ],
    ))
}

fn encode(value: &Value) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut bytes = Vec::new();
    ciborium::into_writer(value, &mut bytes)?;
    Ok(bytes)
}

#[test]
fn public_wdb1_matches_independent_preferred_cbor_and_digest_oracles() -> TestResult {
    let expected = encode(&wire()?)?;
    let directory = record()?;
    assert_eq!(directory.encode().as_slice(), expected);
    assert_eq!(
        WorldDependencyDirectoryV1::decode(&CanonicalBytes::from_vec(expected))?,
        directory
    );
    // Fixed independently with b3sum over the ASCII domain, NUL, and the
    // independently encoded preferred-CBOR fixture.
    assert_eq!(
        directory.digest().as_bytes(),
        &[
            0x82, 0x71, 0x9e, 0xbe, 0xf9, 0xe5, 0xd6, 0xef, 0x73, 0xa1, 0xf7, 0x28, 0x57, 0x45,
            0x24, 0xf9, 0x07, 0x90, 0x8e, 0x9e, 0x61, 0x90, 0x0d, 0x25, 0x54, 0xd5, 0xe3, 0x33,
            0x35, 0x94, 0x57, 0x69,
        ]
    );
    assert_eq!(directory.scope(), hash(1));
    assert_eq!(directory.height(), 1);
    assert_eq!(directory.leaf_count(), 2);
    Ok(())
}

#[test]
fn public_constructor_enforces_leaf_scope_height_and_bounds() -> TestResult {
    assert_eq!(MAX_WORLD_DEPENDENCY_DIRECTORY_CHILDREN_V1, 256);
    assert_eq!(MAX_WORLD_DEPENDENCY_DIRECTORY_HEIGHT_V1, 31);
    assert_eq!(MAX_WORLD_DEPENDENCY_DIRECTORY_BYTES_V1, 65_536);

    let first = key(WorldArtifactKindV1::OutputPolicy, hash(1))?;
    let second = key(WorldArtifactKindV1::OutputPolicy, hash(2))?;
    assert_eq!(
        key(WorldArtifactKindV1::OutputPolicy, Hash::zero()),
        Err(WorldDependencyDirectoryErrorV1::ZeroContentAddress)
    );
    assert_eq!(
        child(first, first, 0, hash(40)),
        Err(WorldDependencyDirectoryErrorV1::InvalidRange)
    );
    assert_eq!(
        child(first, first, 2, hash(40)),
        Err(WorldDependencyDirectoryErrorV1::InvalidRange)
    );
    assert_eq!(
        child(first, second, 1, hash(40)),
        Err(WorldDependencyDirectoryErrorV1::InvalidRange)
    );
    assert_eq!(
        child(second, first, 1, hash(40)),
        Err(WorldDependencyDirectoryErrorV1::InvalidRange)
    );
    assert_eq!(
        child(first, first, 1, Hash::zero()),
        Err(WorldDependencyDirectoryErrorV1::ZeroContentAddress)
    );

    let leaf = child(first, first, 1, hash(40))?;
    assert_eq!(leaf.first_key(), first);
    assert_eq!(leaf.last_key(), first);
    assert_eq!(leaf.leaf_count(), 1);
    assert_eq!(leaf.node_hash(), hash(40));
    for height in [0, 32] {
        assert_eq!(
            WorldDependencyDirectoryV1::new(WorldDependencyDirectoryInputV1 {
                scope: hash(1),
                height,
                children: vec![leaf],
            }),
            Err(WorldDependencyDirectoryErrorV1::FieldOutOfBounds)
        );
    }
    assert_eq!(
        WorldDependencyDirectoryV1::new(WorldDependencyDirectoryInputV1 {
            scope: Hash::zero(),
            height: 1,
            children: vec![leaf],
        }),
        Err(WorldDependencyDirectoryErrorV1::ZeroContentAddress)
    );
    assert_eq!(
        WorldDependencyDirectoryV1::new(WorldDependencyDirectoryInputV1 {
            scope: hash(1),
            height: 1,
            children: Vec::new(),
        }),
        Err(WorldDependencyDirectoryErrorV1::FieldOutOfBounds)
    );

    let excessive = vec![leaf; MAX_WORLD_DEPENDENCY_DIRECTORY_CHILDREN_V1 + 1];
    assert_eq!(
        WorldDependencyDirectoryV1::new(WorldDependencyDirectoryInputV1 {
            scope: hash(1),
            height: 1,
            children: excessive,
        }),
        Err(WorldDependencyDirectoryErrorV1::FieldOutOfBounds)
    );
    Ok(())
}

#[test]
fn public_constructor_enforces_order_and_packed_ranges() -> TestResult {
    let first = key(WorldArtifactKindV1::OutputPolicy, hash(1))?;
    let second = key(WorldArtifactKindV1::OutputPolicy, hash(2))?;
    let third = key(WorldArtifactKindV1::RetentionPolicy, hash(3))?;
    let leaf = child(first, first, 1, hash(40))?;
    let wide_child = child(first, second, 2, hash(41))?;
    assert_eq!(
        WorldDependencyDirectoryV1::new(WorldDependencyDirectoryInputV1 {
            scope: hash(1),
            height: 1,
            children: vec![wide_child],
        }),
        Err(WorldDependencyDirectoryErrorV1::InvalidRange)
    );
    assert_eq!(
        WorldDependencyDirectoryV1::new(WorldDependencyDirectoryInputV1 {
            scope: hash(1),
            height: 1,
            children: vec![leaf, leaf],
        }),
        Err(WorldDependencyDirectoryErrorV1::NonCanonicalOrder)
    );
    let overlapping = child(second, third, 2, hash(42))?;
    assert_eq!(
        WorldDependencyDirectoryV1::new(WorldDependencyDirectoryInputV1 {
            scope: hash(1),
            height: 2,
            children: vec![wide_child, overlapping],
        }),
        Err(WorldDependencyDirectoryErrorV1::NonCanonicalOrder)
    );

    let not_packed = child(first, second, 255, hash(43))?;
    let final_leaf = child(third, third, 1, hash(44))?;
    assert_eq!(
        WorldDependencyDirectoryV1::new(WorldDependencyDirectoryInputV1 {
            scope: hash(1),
            height: 2,
            children: vec![not_packed, final_leaf],
        }),
        Err(WorldDependencyDirectoryErrorV1::InvalidRange)
    );
    let too_many_leaves = child(first, second, 257, hash(45))?;
    assert_eq!(
        WorldDependencyDirectoryV1::new(WorldDependencyDirectoryInputV1 {
            scope: hash(1),
            height: 2,
            children: vec![too_many_leaves],
        }),
        Err(WorldDependencyDirectoryErrorV1::InvalidRange)
    );
    let unrepresentable_full = child(first, second, u64::MAX, hash(46))?;
    assert_eq!(
        WorldDependencyDirectoryV1::new(WorldDependencyDirectoryInputV1 {
            scope: hash(1),
            height: 9,
            children: vec![unrepresentable_full, final_leaf],
        }),
        Err(WorldDependencyDirectoryErrorV1::InvalidRange)
    );

    Ok(())
}

#[test]
fn public_directory_checks_child_count_sums_and_all_uint_widths() -> TestResult {
    let child_capacity = 1_u64 << 56;
    let mut overflowing_children = Vec::new();
    for index in 0..256_u64 {
        let first = key(
            WorldArtifactKindV1::OutputPolicy,
            indexed_hash(index * 2 + 1),
        )?;
        let last = key(
            WorldArtifactKindV1::OutputPolicy,
            indexed_hash(index * 2 + 2),
        )?;
        overflowing_children.push(child(
            first,
            last,
            child_capacity,
            indexed_hash(index + 1_000),
        )?);
    }
    assert_eq!(
        WorldDependencyDirectoryV1::new(WorldDependencyDirectoryInputV1 {
            scope: hash(1),
            height: 8,
            children: overflowing_children,
        }),
        Err(WorldDependencyDirectoryErrorV1::LeafCountOverflow)
    );

    for leaf_count in [
        1,
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
        let first_key = key(WorldArtifactKindV1::OutputPolicy, indexed_hash(1))?;
        let mut last_key = first_key;
        let mut remaining = leaf_count;
        let mut children = Vec::new();
        let mut child_values = Vec::new();
        for index in 0..256_u64 {
            if remaining == 0 {
                break;
            }
            let child_leaves = remaining.min(child_capacity);
            let child_first = key(
                WorldArtifactKindV1::OutputPolicy,
                indexed_hash(index * 2 + 1),
            )?;
            let child_last = if child_leaves == 1 {
                child_first
            } else {
                key(
                    WorldArtifactKindV1::OutputPolicy,
                    indexed_hash(index * 2 + 2),
                )?
            };
            let child_hash = indexed_hash(index + 2_000);
            children.push(child(child_first, child_last, child_leaves, child_hash)?);
            child_values.push(child_value(
                child_first,
                child_last,
                child_leaves,
                child_hash,
            ));
            last_key = child_last;
            remaining -= child_leaves;
        }
        assert_eq!(remaining, 0);
        let directory = WorldDependencyDirectoryV1::new(WorldDependencyDirectoryInputV1 {
            scope: hash(1),
            height: 8,
            children,
        })?;
        let fixture = wire_with(hash(1), 8, first_key, last_key, leaf_count, child_values);
        let expected = encode(&fixture)?;
        assert_eq!(directory.encode().as_slice(), expected);
        assert_eq!(
            WorldDependencyDirectoryV1::decode(&CanonicalBytes::from_vec(expected))?,
            directory
        );
    }
    Ok(())
}

#[test]
fn public_wdb1_roundtrips_maximum_fanout_and_height() -> TestResult {
    let mut children = Vec::new();
    for index in 1..=256_u64 {
        let key = key(WorldArtifactKindV1::OutputPolicy, indexed_hash(index))?;
        children.push(child(key, key, 1, indexed_hash(index + 1_000))?);
    }
    let directory = WorldDependencyDirectoryV1::new(WorldDependencyDirectoryInputV1 {
        scope: hash(1),
        height: 1,
        children,
    })?;
    let encoded = directory.encode();
    assert!(encoded.as_slice().len() <= MAX_WORLD_DEPENDENCY_DIRECTORY_BYTES_V1);
    assert_eq!(directory.children().len(), 256);
    assert_eq!(directory.leaf_count(), 256);
    assert_eq!(WorldDependencyDirectoryV1::decode(&encoded)?, directory);

    let first = key(WorldArtifactKindV1::OutputPolicy, hash(1))?;
    let last = key(WorldArtifactKindV1::RetentionPolicy, hash(2))?;
    let root = WorldDependencyDirectoryV1::new(WorldDependencyDirectoryInputV1 {
        scope: hash(1),
        height: MAX_WORLD_DEPENDENCY_DIRECTORY_HEIGHT_V1,
        children: vec![child(first, last, 2, hash(3))?],
    })?;
    assert_eq!(root.first_key(), first);
    assert_eq!(root.last_key(), last);
    assert_eq!(WorldDependencyDirectoryV1::decode(&root.encode())?, root);
    Ok(())
}

#[test]
fn public_decoder_rejects_noncanonical_malformed_and_hostile_inputs() -> TestResult {
    let expected = encode(&wire()?)?;
    let decode =
        |bytes: Vec<u8>| WorldDependencyDirectoryV1::decode(&CanonicalBytes::from_vec(bytes));

    assert_eq!(
        decode(Vec::new()),
        Err(WorldDependencyDirectoryErrorV1::InvalidEncoding)
    );

    let mut wrong_magic = expected.clone();
    wrong_magic[2] = b'X';
    assert_eq!(
        decode(wrong_magic),
        Err(WorldDependencyDirectoryErrorV1::WrongMagic)
    );

    let mut wrong_version = expected.clone();
    wrong_version[6] = 2;
    assert_eq!(
        decode(wrong_version),
        Err(WorldDependencyDirectoryErrorV1::UnsupportedVersion)
    );

    let mut wrong_scope_type = expected.clone();
    wrong_scope_type[7] = 0x01;
    assert_eq!(
        decode(wrong_scope_type),
        Err(WorldDependencyDirectoryErrorV1::InvalidEncoding)
    );

    let mut nonpreferred = expected.clone();
    nonpreferred.splice(6..7, [0x18, 0x01]);
    assert_eq!(
        decode(nonpreferred),
        Err(WorldDependencyDirectoryErrorV1::NonCanonicalEncoding)
    );

    let mut truncated = expected.clone();
    truncated.pop();
    assert_eq!(
        decode(truncated),
        Err(WorldDependencyDirectoryErrorV1::InvalidEncoding)
    );
    let mut trailing = expected.clone();
    trailing.push(0);
    assert_eq!(
        decode(trailing),
        Err(WorldDependencyDirectoryErrorV1::InvalidEncoding)
    );

    let mut indefinite = expected.clone();
    indefinite[0] = 0x9f;
    assert_eq!(
        decode(indefinite),
        Err(WorldDependencyDirectoryErrorV1::InvalidEncoding)
    );
    let mut wrong_array = expected.clone();
    wrong_array[0] = 0x87;
    assert_eq!(
        decode(wrong_array),
        Err(WorldDependencyDirectoryErrorV1::InvalidEncoding)
    );
    assert_eq!(
        decode(vec![0; MAX_WORLD_DEPENDENCY_DIRECTORY_BYTES_V1 + 1]),
        Err(WorldDependencyDirectoryErrorV1::FieldOutOfBounds)
    );

    let first = key(WorldArtifactKindV1::OutputPolicy, hash(10))?;
    let second = key(WorldArtifactKindV1::RetentionPolicy, hash(11))?;
    assert_eq!(
        decode(encode(&wire_with(
            hash(1),
            1,
            first,
            second,
            3,
            vec![
                child_value(first, first, 1, hash(50)),
                child_value(second, second, 1, hash(51)),
            ]
        ))?),
        Err(WorldDependencyDirectoryErrorV1::InvalidRange)
    );
    assert_eq!(
        decode(encode(&wire_with(
            hash(1),
            1,
            first,
            second,
            2,
            Vec::new()
        ))?),
        Err(WorldDependencyDirectoryErrorV1::FieldOutOfBounds)
    );

    let mut wrong_digest_length = expected;
    wrong_digest_length[45] = 31;
    assert_eq!(
        decode(wrong_digest_length),
        Err(WorldDependencyDirectoryErrorV1::InvalidEncoding)
    );

    let too_many: Vec<Value> = (0..=MAX_WORLD_DEPENDENCY_DIRECTORY_CHILDREN_V1)
        .map(|_| child_value(first, first, 1, hash(50)))
        .collect();
    assert_eq!(
        decode(encode(&wire_with(hash(1), 1, first, first, 1, too_many))?),
        Err(WorldDependencyDirectoryErrorV1::FieldOutOfBounds)
    );
    Ok(())
}

#[test]
fn public_decoder_rejects_unknown_and_out_of_range_kinds() -> TestResult {
    let first = key(WorldArtifactKindV1::OutputPolicy, hash(10))?;
    let second = key(WorldArtifactKindV1::RetentionPolicy, hash(11))?;
    let unknown_kind = Value::Array(vec![
        Value::Integer(255_u64.into()),
        Value::Bytes(hash(10).as_bytes().to_vec()),
    ]);
    assert_eq!(
        WorldDependencyDirectoryV1::decode(&CanonicalBytes::from_vec(encode(&wire_with(
            hash(1),
            1,
            first,
            second,
            2,
            vec![
                child_value(first, first, 1, hash(50)),
                Value::Array(vec![
                    unknown_kind,
                    key_value(second),
                    Value::Integer(1.into()),
                    Value::Bytes(hash(51).as_bytes().to_vec())
                ]),
            ],
        ))?)),
        Err(WorldDependencyDirectoryErrorV1::UnsupportedKind)
    );

    let out_of_range_kind = Value::Array(vec![
        Value::Integer(256_u64.into()),
        Value::Bytes(hash(10).as_bytes().to_vec()),
    ]);
    assert_eq!(
        WorldDependencyDirectoryV1::decode(&CanonicalBytes::from_vec(encode(&wire_with(
            hash(1),
            1,
            first,
            second,
            2,
            vec![
                child_value(first, first, 1, hash(50)),
                Value::Array(vec![
                    out_of_range_kind,
                    key_value(second),
                    Value::Integer(1.into()),
                    Value::Bytes(hash(51).as_bytes().to_vec()),
                ]),
            ],
        ))?)),
        Err(WorldDependencyDirectoryErrorV1::FieldOutOfBounds)
    );

    Ok(())
}

#[test]
fn public_decoder_rejects_zero_addresses_and_bad_child_shapes() -> TestResult {
    let first = key(WorldArtifactKindV1::OutputPolicy, hash(10))?;
    let second = key(WorldArtifactKindV1::RetentionPolicy, hash(11))?;
    let zero_digest = Value::Array(vec![Value::Integer(0.into()), Value::Bytes(vec![0; 32])]);
    assert_eq!(
        WorldDependencyDirectoryV1::decode(&CanonicalBytes::from_vec(encode(&wire_with(
            hash(1),
            1,
            first,
            second,
            2,
            vec![
                Value::Array(vec![
                    zero_digest,
                    key_value(first),
                    Value::Integer(1.into()),
                    Value::Bytes(hash(50).as_bytes().to_vec())
                ]),
                child_value(second, second, 1, hash(51)),
            ],
        ))?)),
        Err(WorldDependencyDirectoryErrorV1::ZeroContentAddress)
    );

    assert_eq!(
        WorldDependencyDirectoryV1::decode(&CanonicalBytes::from_vec(encode(&wire_with(
            hash(1),
            1,
            first,
            second,
            2,
            vec![
                Value::Array(vec![
                    key_value(first),
                    key_value(first),
                    Value::Integer(1.into())
                ]),
                child_value(second, second, 1, hash(51)),
            ],
        ))?)),
        Err(WorldDependencyDirectoryErrorV1::InvalidEncoding)
    );

    Ok(())
}

#[test]
fn public_error_display_is_nonempty() {
    let errors = [
        WorldDependencyDirectoryErrorV1::InvalidEncoding,
        WorldDependencyDirectoryErrorV1::WrongMagic,
        WorldDependencyDirectoryErrorV1::UnsupportedVersion,
        WorldDependencyDirectoryErrorV1::UnsupportedKind,
        WorldDependencyDirectoryErrorV1::FieldOutOfBounds,
        WorldDependencyDirectoryErrorV1::ZeroContentAddress,
        WorldDependencyDirectoryErrorV1::InvalidRange,
        WorldDependencyDirectoryErrorV1::NonCanonicalOrder,
        WorldDependencyDirectoryErrorV1::LeafCountOverflow,
        WorldDependencyDirectoryErrorV1::NonCanonicalEncoding,
    ];
    for error in errors {
        assert!(!error.to_string().is_empty());
    }
}
