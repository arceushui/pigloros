use ciborium::value::Value;
use pos_core::{
    CanonicalBytes, Hash, WorldArtifactKindV1, WorldDependencyBranchChildV1,
    WorldDependencyBranchErrorV1, WorldDependencyBranchInputV1, WorldDependencyBranchV1,
    WorldDependencyKeyV1, MAX_WORLD_DEPENDENCY_DIRECTORY_BYTES_V1,
    MAX_WORLD_DEPENDENCY_DIRECTORY_CHILDREN_V1, MAX_WORLD_DEPENDENCY_DIRECTORY_HEIGHT_V1,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

// Literal preferred CBOR for the two-leaf WDB1 fixture, independent of
// production accessors and of the separate ciborium semantic oracle.
const EXPECTED_WDB1_CBOR: [u8; 332] = [
    0x88, 0x44, 0x57, 0x44, 0x42, 0x31, 0x01, 0x58, 0x20, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x82, 0x00, 0x58, 0x20, 0x0a, 0x0a,
    0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a,
    0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x82, 0x02,
    0x58, 0x20, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
    0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
    0x0b, 0x0b, 0x02, 0x82, 0x84, 0x82, 0x00, 0x58, 0x20, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a,
    0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a,
    0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x82, 0x00, 0x58, 0x20, 0x0a, 0x0a, 0x0a,
    0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a,
    0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x01, 0x58, 0x20,
    0x32, 0x32, 0x32, 0x32, 0x32, 0x32, 0x32, 0x32, 0x32, 0x32, 0x32, 0x32, 0x32, 0x32, 0x32, 0x32,
    0x32, 0x32, 0x32, 0x32, 0x32, 0x32, 0x32, 0x32, 0x32, 0x32, 0x32, 0x32, 0x32, 0x32, 0x32, 0x32,
    0x84, 0x82, 0x02, 0x58, 0x20, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
    0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
    0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x82, 0x02, 0x58, 0x20, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
    0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
    0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x01, 0x58, 0x20, 0x33, 0x33, 0x33, 0x33,
    0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33,
    0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33,
];

const fn hash(byte: u8) -> Hash {
    Hash::from_bytes([byte; 32])
}

fn indexed_hash(index: u64) -> Hash {
    let mut bytes = [0; 32];
    bytes[24..].copy_from_slice(&index.to_be_bytes());
    Hash::from_bytes(bytes)
}

fn wide_indexed_hash(index: u128) -> Hash {
    let mut bytes = [0; 32];
    bytes[16..].copy_from_slice(&index.to_be_bytes());
    Hash::from_bytes(bytes)
}

fn key(
    kind: WorldArtifactKindV1,
    digest: Hash,
) -> Result<WorldDependencyKeyV1, WorldDependencyBranchErrorV1> {
    WorldDependencyKeyV1::new(kind, digest)
}

fn child(
    first_key: WorldDependencyKeyV1,
    last_key: WorldDependencyKeyV1,
    leaf_count: u64,
    node_hash: Hash,
) -> Result<WorldDependencyBranchChildV1, WorldDependencyBranchErrorV1> {
    WorldDependencyBranchChildV1::new(first_key, last_key, leaf_count, node_hash)
}

fn record() -> Result<WorldDependencyBranchV1, WorldDependencyBranchErrorV1> {
    let first = key(WorldArtifactKindV1::OutputPolicy, hash(10))?;
    let second = key(WorldArtifactKindV1::RetentionPolicy, hash(11))?;
    WorldDependencyBranchV1::new(WorldDependencyBranchInputV1 {
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

fn wire() -> Result<Value, WorldDependencyBranchErrorV1> {
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
    let expected = &EXPECTED_WDB1_CBOR;
    assert_eq!(encode(&wire()?)?.as_slice(), expected.as_slice());
    let directory = record()?;
    assert_eq!(directory.encode().as_slice(), expected.as_slice());
    assert_eq!(
        WorldDependencyBranchV1::decode(&CanonicalBytes::from_vec(expected.to_vec()))?,
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
        Err(WorldDependencyBranchErrorV1::ZeroContentAddress)
    );
    assert_eq!(
        child(first, first, 0, hash(40)),
        Err(WorldDependencyBranchErrorV1::InvalidRange)
    );
    assert_eq!(
        child(first, first, 2, hash(40)),
        Err(WorldDependencyBranchErrorV1::InvalidRange)
    );
    assert_eq!(
        child(first, second, 1, hash(40)),
        Err(WorldDependencyBranchErrorV1::InvalidRange)
    );
    assert_eq!(
        child(second, first, 1, hash(40)),
        Err(WorldDependencyBranchErrorV1::InvalidRange)
    );
    assert_eq!(
        child(first, first, 1, Hash::zero()),
        Err(WorldDependencyBranchErrorV1::ZeroContentAddress)
    );

    let leaf = child(first, first, 1, hash(40))?;
    assert_eq!(leaf.first_key(), first);
    assert_eq!(leaf.last_key(), first);
    assert_eq!(leaf.leaf_count(), 1);
    assert_eq!(leaf.node_hash(), hash(40));
    for height in [0, 32] {
        assert_eq!(
            WorldDependencyBranchV1::new(WorldDependencyBranchInputV1 {
                scope: hash(1),
                height,
                children: vec![leaf],
            }),
            Err(WorldDependencyBranchErrorV1::FieldOutOfBounds)
        );
    }
    assert_eq!(
        WorldDependencyBranchV1::new(WorldDependencyBranchInputV1 {
            scope: Hash::zero(),
            height: 1,
            children: vec![leaf],
        }),
        Err(WorldDependencyBranchErrorV1::ZeroContentAddress)
    );
    assert_eq!(
        WorldDependencyBranchV1::new(WorldDependencyBranchInputV1 {
            scope: hash(1),
            height: 1,
            children: Vec::new(),
        }),
        Err(WorldDependencyBranchErrorV1::FieldOutOfBounds)
    );

    let excessive = vec![leaf; MAX_WORLD_DEPENDENCY_DIRECTORY_CHILDREN_V1 + 1];
    assert_eq!(
        WorldDependencyBranchV1::new(WorldDependencyBranchInputV1 {
            scope: hash(1),
            height: 1,
            children: excessive,
        }),
        Err(WorldDependencyBranchErrorV1::FieldOutOfBounds)
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
        WorldDependencyBranchV1::new(WorldDependencyBranchInputV1 {
            scope: hash(1),
            height: 1,
            children: vec![wide_child],
        }),
        Err(WorldDependencyBranchErrorV1::InvalidRange)
    );
    assert_eq!(
        WorldDependencyBranchV1::new(WorldDependencyBranchInputV1 {
            scope: hash(1),
            height: 1,
            children: vec![leaf, leaf],
        }),
        Err(WorldDependencyBranchErrorV1::NonCanonicalOrder)
    );
    let overlapping = child(second, third, 2, hash(42))?;
    assert_eq!(
        WorldDependencyBranchV1::new(WorldDependencyBranchInputV1 {
            scope: hash(1),
            height: 2,
            children: vec![wide_child, overlapping],
        }),
        Err(WorldDependencyBranchErrorV1::NonCanonicalOrder)
    );

    let not_packed = child(first, second, 255, hash(43))?;
    let final_leaf = child(third, third, 1, hash(44))?;
    assert_eq!(
        WorldDependencyBranchV1::new(WorldDependencyBranchInputV1 {
            scope: hash(1),
            height: 2,
            children: vec![not_packed, final_leaf],
        }),
        Err(WorldDependencyBranchErrorV1::InvalidRange)
    );
    let too_many_leaves = child(first, second, 257, hash(45))?;
    assert_eq!(
        WorldDependencyBranchV1::new(WorldDependencyBranchInputV1 {
            scope: hash(1),
            height: 2,
            children: vec![too_many_leaves],
        }),
        Err(WorldDependencyBranchErrorV1::InvalidRange)
    );
    let unrepresentable_full = child(first, second, u64::MAX, hash(46))?;
    assert_eq!(
        WorldDependencyBranchV1::new(WorldDependencyBranchInputV1 {
            scope: hash(1),
            height: 9,
            children: vec![unrepresentable_full, final_leaf],
        }),
        Err(WorldDependencyBranchErrorV1::InvalidRange)
    );

    Ok(())
}

#[test]
fn public_child_rejects_more_leaves_than_distinct_keys_in_range() -> TestResult {
    let first = key(WorldArtifactKindV1::OutputPolicy, indexed_hash(1))?;
    let second = key(WorldArtifactKindV1::OutputPolicy, indexed_hash(2))?;
    assert!(child(first, second, 2, hash(40)).is_ok());
    assert_eq!(
        child(first, second, 3, hash(40)),
        Err(WorldDependencyBranchErrorV1::InvalidRange)
    );

    let byte_edge = key(WorldArtifactKindV1::OutputPolicy, indexed_hash(255))?;
    let after_byte_edge = key(WorldArtifactKindV1::OutputPolicy, indexed_hash(256))?;
    assert!(child(byte_edge, after_byte_edge, 2, hash(40)).is_ok());
    assert_eq!(
        child(byte_edge, after_byte_edge, 3, hash(40)),
        Err(WorldDependencyBranchErrorV1::InvalidRange)
    );

    let kind_edge = key(
        WorldArtifactKindV1::OutputPolicy,
        Hash::from_bytes([u8::MAX; 32]),
    )?;
    let next_first = key(WorldArtifactKindV1::ExecutableBudgetPolicy, indexed_hash(1))?;
    let next_second = key(WorldArtifactKindV1::ExecutableBudgetPolicy, indexed_hash(2))?;
    let next_256 = key(
        WorldArtifactKindV1::ExecutableBudgetPolicy,
        indexed_hash(256),
    )?;
    assert!(child(kind_edge, next_first, 2, hash(40)).is_ok());
    assert_eq!(
        child(kind_edge, next_first, 3, hash(40)),
        Err(WorldDependencyBranchErrorV1::InvalidRange)
    );
    assert!(child(kind_edge, next_second, 3, hash(40)).is_ok());
    assert!(child(kind_edge, next_256, 257, hash(40)).is_ok());
    assert_eq!(
        child(kind_edge, next_256, 258, hash(40)),
        Err(WorldDependencyBranchErrorV1::InvalidRange)
    );

    let old_last = key(
        WorldArtifactKindV1::OptionalView,
        Hash::from_bytes([u8::MAX; 32]),
    )?;
    let closure_first = key(WorldArtifactKindV1::OutputPolicyClosure, indexed_hash(1))?;
    let closure_second = key(WorldArtifactKindV1::OutputPolicyClosure, indexed_hash(2))?;
    assert!(child(old_last, closure_first, 2, hash(40)).is_ok());
    assert_eq!(
        child(old_last, closure_first, 3, hash(40)),
        Err(WorldDependencyBranchErrorV1::InvalidRange)
    );
    assert!(child(old_last, closure_second, 3, hash(40)).is_ok());
    Ok(())
}

#[test]
fn public_wdb1_key_roundtrips_closure_and_rejects_next_kind() -> TestResult {
    let first = key(WorldArtifactKindV1::OutputPolicy, hash(10))?;
    let closure = key(WorldArtifactKindV1::OutputPolicyClosure, hash(11))?;
    let directory = WorldDependencyBranchV1::new(WorldDependencyBranchInputV1 {
        scope: hash(1),
        height: 1,
        children: vec![
            child(first, first, 1, hash(50))?,
            child(closure, closure, 1, hash(51))?,
        ],
    })?;
    let bytes = directory.encode().to_vec();
    assert_eq!(
        WorldDependencyBranchV1::decode(&CanonicalBytes::from_vec(bytes.clone()))?,
        directory
    );
    assert_eq!(directory.last_key(), closure);

    let mut unsupported = bytes;
    let kind_offset = unsupported
        .windows(4)
        .position(|window| window == [0x82, 14, 0x58, 0x20])
        .ok_or("missing encoded closure key")?;
    unsupported[kind_offset + 1] = 15;
    assert_eq!(
        WorldDependencyBranchV1::decode(&CanonicalBytes::from_vec(unsupported)),
        Err(WorldDependencyBranchErrorV1::UnsupportedKind)
    );
    Ok(())
}

#[test]
fn public_directory_checks_child_count_sums_and_all_uint_widths() -> TestResult {
    let child_capacity = 1_u64 << 56;
    let mut overflowing_children = Vec::new();
    for index in 0..256_u64 {
        let first_index = u128::from(index) * u128::from(child_capacity) + 1;
        let last_index = first_index + u128::from(child_capacity) - 1;
        let first = key(
            WorldArtifactKindV1::OutputPolicy,
            wide_indexed_hash(first_index),
        )?;
        let last = key(
            WorldArtifactKindV1::OutputPolicy,
            wide_indexed_hash(last_index),
        )?;
        overflowing_children.push(child(
            first,
            last,
            child_capacity,
            indexed_hash(index + 1_000),
        )?);
    }
    assert_eq!(
        WorldDependencyBranchV1::new(WorldDependencyBranchInputV1 {
            scope: hash(1),
            height: 8,
            children: overflowing_children,
        }),
        Err(WorldDependencyBranchErrorV1::LeafCountOverflow)
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
            let child_first_index = index * child_capacity + 1;
            let child_last_index = child_first_index + (child_leaves - 1);
            let child_first = key(
                WorldArtifactKindV1::OutputPolicy,
                indexed_hash(child_first_index),
            )?;
            let child_last = key(
                WorldArtifactKindV1::OutputPolicy,
                indexed_hash(child_last_index),
            )?;
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
        let directory = WorldDependencyBranchV1::new(WorldDependencyBranchInputV1 {
            scope: hash(1),
            height: 8,
            children,
        })?;
        let fixture = wire_with(hash(1), 8, first_key, last_key, leaf_count, child_values);
        let expected = encode(&fixture)?;
        assert_eq!(directory.encode().as_slice(), expected);
        assert_eq!(
            WorldDependencyBranchV1::decode(&CanonicalBytes::from_vec(expected))?,
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
    let directory = WorldDependencyBranchV1::new(WorldDependencyBranchInputV1 {
        scope: hash(1),
        height: 1,
        children,
    })?;
    let encoded = directory.encode();
    assert!(encoded.as_slice().len() <= MAX_WORLD_DEPENDENCY_DIRECTORY_BYTES_V1);
    assert_eq!(directory.children().len(), 256);
    assert_eq!(directory.leaf_count(), 256);
    assert_eq!(WorldDependencyBranchV1::decode(&encoded)?, directory);

    let first = key(WorldArtifactKindV1::OutputPolicy, hash(1))?;
    let last = key(WorldArtifactKindV1::RetentionPolicy, hash(2))?;
    let root = WorldDependencyBranchV1::new(WorldDependencyBranchInputV1 {
        scope: hash(1),
        height: MAX_WORLD_DEPENDENCY_DIRECTORY_HEIGHT_V1,
        children: vec![child(first, last, 2, hash(3))?],
    })?;
    assert_eq!(root.first_key(), first);
    assert_eq!(root.last_key(), last);
    assert_eq!(WorldDependencyBranchV1::decode(&root.encode())?, root);
    Ok(())
}

#[test]
fn public_decoder_rejects_noncanonical_malformed_and_hostile_inputs() -> TestResult {
    let expected = encode(&wire()?)?;
    let decode = |bytes: Vec<u8>| WorldDependencyBranchV1::decode(&CanonicalBytes::from_vec(bytes));

    assert_eq!(
        decode(Vec::new()),
        Err(WorldDependencyBranchErrorV1::InvalidEncoding)
    );

    let mut wrong_magic = expected.clone();
    wrong_magic[2] = b'X';
    assert_eq!(
        decode(wrong_magic),
        Err(WorldDependencyBranchErrorV1::WrongMagic)
    );

    let mut wrong_version = expected.clone();
    wrong_version[6] = 2;
    assert_eq!(
        decode(wrong_version),
        Err(WorldDependencyBranchErrorV1::UnsupportedVersion)
    );

    let mut wrong_scope_type = expected.clone();
    wrong_scope_type[7] = 0x01;
    assert_eq!(
        decode(wrong_scope_type),
        Err(WorldDependencyBranchErrorV1::InvalidEncoding)
    );

    let mut nonpreferred = expected.clone();
    nonpreferred.splice(6..7, [0x18, 0x01]);
    assert_eq!(
        decode(nonpreferred),
        Err(WorldDependencyBranchErrorV1::NonCanonicalEncoding)
    );

    let mut truncated = expected.clone();
    truncated.pop();
    assert_eq!(
        decode(truncated),
        Err(WorldDependencyBranchErrorV1::InvalidEncoding)
    );
    let mut trailing = expected.clone();
    trailing.push(0);
    assert_eq!(
        decode(trailing),
        Err(WorldDependencyBranchErrorV1::InvalidEncoding)
    );

    let mut indefinite = expected.clone();
    indefinite[0] = 0x9f;
    assert_eq!(
        decode(indefinite),
        Err(WorldDependencyBranchErrorV1::InvalidEncoding)
    );
    let mut wrong_array = expected.clone();
    wrong_array[0] = 0x87;
    assert_eq!(
        decode(wrong_array),
        Err(WorldDependencyBranchErrorV1::InvalidEncoding)
    );
    assert_eq!(
        decode(vec![0; MAX_WORLD_DEPENDENCY_DIRECTORY_BYTES_V1 + 1]),
        Err(WorldDependencyBranchErrorV1::FieldOutOfBounds)
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
        Err(WorldDependencyBranchErrorV1::InvalidRange)
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
        Err(WorldDependencyBranchErrorV1::FieldOutOfBounds)
    );

    let mut wrong_digest_length = expected;
    wrong_digest_length[45] = 31;
    assert_eq!(
        decode(wrong_digest_length),
        Err(WorldDependencyBranchErrorV1::InvalidEncoding)
    );

    let too_many: Vec<Value> = (0..=MAX_WORLD_DEPENDENCY_DIRECTORY_CHILDREN_V1)
        .map(|_| child_value(first, first, 1, hash(50)))
        .collect();
    assert_eq!(
        decode(encode(&wire_with(hash(1), 1, first, first, 1, too_many))?),
        Err(WorldDependencyBranchErrorV1::FieldOutOfBounds)
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
        WorldDependencyBranchV1::decode(&CanonicalBytes::from_vec(encode(&wire_with(
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
        Err(WorldDependencyBranchErrorV1::UnsupportedKind)
    );

    let out_of_range_kind = Value::Array(vec![
        Value::Integer(256_u64.into()),
        Value::Bytes(hash(10).as_bytes().to_vec()),
    ]);
    assert_eq!(
        WorldDependencyBranchV1::decode(&CanonicalBytes::from_vec(encode(&wire_with(
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
        Err(WorldDependencyBranchErrorV1::FieldOutOfBounds)
    );

    Ok(())
}

#[test]
fn public_decoder_rejects_zero_addresses_and_bad_child_shapes() -> TestResult {
    let first = key(WorldArtifactKindV1::OutputPolicy, hash(10))?;
    let second = key(WorldArtifactKindV1::RetentionPolicy, hash(11))?;
    let zero_digest = Value::Array(vec![Value::Integer(0.into()), Value::Bytes(vec![0; 32])]);
    assert_eq!(
        WorldDependencyBranchV1::decode(&CanonicalBytes::from_vec(encode(&wire_with(
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
        Err(WorldDependencyBranchErrorV1::ZeroContentAddress)
    );

    assert_eq!(
        WorldDependencyBranchV1::decode(&CanonicalBytes::from_vec(encode(&wire_with(
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
        Err(WorldDependencyBranchErrorV1::InvalidEncoding)
    );

    Ok(())
}

#[test]
fn public_error_display_is_nonempty() {
    let errors = [
        WorldDependencyBranchErrorV1::InvalidEncoding,
        WorldDependencyBranchErrorV1::WrongMagic,
        WorldDependencyBranchErrorV1::UnsupportedVersion,
        WorldDependencyBranchErrorV1::UnsupportedKind,
        WorldDependencyBranchErrorV1::FieldOutOfBounds,
        WorldDependencyBranchErrorV1::ZeroContentAddress,
        WorldDependencyBranchErrorV1::InvalidRange,
        WorldDependencyBranchErrorV1::NonCanonicalOrder,
        WorldDependencyBranchErrorV1::LeafCountOverflow,
        WorldDependencyBranchErrorV1::NonCanonicalEncoding,
    ];
    for error in errors {
        assert!(!error.to_string().is_empty());
    }
}
