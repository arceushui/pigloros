use pos_core::{
    CanonicalBytes, Hash, PluginId, WorldConsumerSetErrorV1, WorldConsumerSetInputV1,
    WorldConsumerSetV1, WorldConsumerV1, WorldProducerV1,
};
use ulid::Ulid;

fn hash(byte: u8) -> Hash {
    Hash::from_bytes([byte; 32])
}
fn indexed_hash(index: u16) -> Hash {
    let mut bytes = [0; 32];
    bytes[30..].copy_from_slice(&(index + 1).to_be_bytes());
    Hash::from_bytes(bytes)
}
fn plugin(byte: u8) -> PluginId {
    PluginId::from_ulid(Ulid::from(u128::from_be_bytes([byte; 16])))
}
fn consumer(id: &str, byte: u8) -> Result<WorldConsumerV1, WorldConsumerSetErrorV1> {
    WorldConsumerV1::new(id.to_owned(), hash(byte), hash(byte + 1), hash(byte + 2))
}
fn producer(byte: u8) -> Result<WorldProducerV1, WorldConsumerSetErrorV1> {
    WorldProducerV1::new(plugin(byte), hash(byte + 20))
}
fn record() -> Result<WorldConsumerSetV1, WorldConsumerSetErrorV1> {
    WorldConsumerSetV1::new(WorldConsumerSetInputV1 {
        scope: hash(1),
        consumers: vec![consumer("a", 2)?],
        producers: vec![producer(4)?],
        optional_view_roots: vec![hash(40)],
    })
}

#[test]
fn public_wcs1_matches_literal_preferred_cbor_and_fixed_blake3_oracle(
) -> Result<(), Box<dyn std::error::Error>> {
    let expected = [
        0x86, 0x44, b'W', b'C', b'S', b'1', 0x01, 0x58, 0x20, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0x81, 0x84, 0x61, b'a', 0x58,
        0x20, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
        2, 2, 2, 2, 0x58, 0x20, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
        3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 0x58, 0x20, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4,
        4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 0x81, 0x82, 0x50, 4, 4, 4, 4, 4, 4, 4, 4,
        4, 4, 4, 4, 4, 4, 4, 4, 0x58, 0x20, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24,
        24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 0x81, 0x58, 0x20,
        40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40,
        40, 40, 40, 40, 40, 40, 40, 40, 40,
    ];
    let record = record()?;
    let encoded = record.encode();
    assert_eq!(encoded.as_slice(), expected);
    // Fixed with `/usr/bin/b3sum` over the ASCII domain, NUL, and this literal
    // preferred-CBOR baseline; it is deliberately independent of the codec.
    let expected_digest = Hash::from_bytes([
        0xc9, 0x2c, 0xc9, 0x84, 0x47, 0x5e, 0xc1, 0xa6, 0xec, 0xc5, 0x10, 0x0f, 0x65, 0x82, 0x2c,
        0x59, 0x5e, 0x2c, 0xdc, 0x2c, 0xfc, 0x75, 0x57, 0xf9, 0x08, 0x5e, 0x55, 0xca, 0xa3, 0xb8,
        0x33, 0x2b,
    ]);
    assert_eq!(record.digest(), expected_digest);
    Ok(())
}

#[test]
fn public_decode_accepts_independently_encoded_ciborium_value(
) -> Result<(), Box<dyn std::error::Error>> {
    let value = ciborium::value::Value::Array(vec![
        ciborium::value::Value::Bytes(b"WCS1".to_vec()),
        ciborium::value::Value::Integer(1.into()),
        ciborium::value::Value::Bytes(vec![1; 32]),
        ciborium::value::Value::Array(vec![ciborium::value::Value::Array(vec![
            ciborium::value::Value::Text("a".to_owned()),
            ciborium::value::Value::Bytes(vec![2; 32]),
            ciborium::value::Value::Bytes(vec![3; 32]),
            ciborium::value::Value::Bytes(vec![4; 32]),
        ])]),
        ciborium::value::Value::Array(vec![ciborium::value::Value::Array(vec![
            ciborium::value::Value::Bytes(vec![4; 16]),
            ciborium::value::Value::Bytes(vec![24; 32]),
        ])]),
        ciborium::value::Value::Array(vec![ciborium::value::Value::Bytes(vec![40; 32])]),
    ]);
    let mut bytes = Vec::new();
    ciborium::into_writer(&value, &mut bytes)?;
    assert_eq!(
        WorldConsumerSetV1::decode(&CanonicalBytes::from_vec(bytes)),
        Ok(record()?)
    );
    Ok(())
}

#[test]
fn public_constructor_enforces_bounds_addresses_and_raw_order(
) -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(
        WorldConsumerV1::new(String::new(), hash(1), hash(2), hash(3)),
        Err(WorldConsumerSetErrorV1::FieldOutOfBounds)
    );
    assert_eq!(
        WorldConsumerV1::new("a".repeat(129), hash(1), hash(2), hash(3)),
        Err(WorldConsumerSetErrorV1::FieldOutOfBounds)
    );
    assert_eq!(
        WorldProducerV1::new(plugin(0), Hash::zero()),
        Err(WorldConsumerSetErrorV1::ZeroContentAddress)
    );
    assert_eq!(
        WorldConsumerSetV1::new(WorldConsumerSetInputV1 {
            scope: Hash::zero(),
            consumers: vec![consumer("a", 2)?],
            producers: vec![producer(4)?],
            optional_view_roots: Vec::new()
        }),
        Err(WorldConsumerSetErrorV1::ZeroContentAddress)
    );
    let unordered = WorldConsumerSetV1::new(WorldConsumerSetInputV1 {
        scope: hash(1),
        consumers: vec![consumer("b", 2)?, consumer("a", 5)?],
        producers: vec![producer(4)?],
        optional_view_roots: Vec::new(),
    });
    assert_eq!(unordered, Err(WorldConsumerSetErrorV1::NonCanonicalOrder));
    let duplicate_views = WorldConsumerSetV1::new(WorldConsumerSetInputV1 {
        scope: hash(1),
        consumers: vec![consumer("a", 2)?],
        producers: vec![producer(4)?],
        optional_view_roots: vec![hash(6), hash(6)],
    });
    assert_eq!(
        duplicate_views,
        Err(WorldConsumerSetErrorV1::NonCanonicalOrder)
    );
    let opaque_zero = WorldConsumerSetV1::new(WorldConsumerSetInputV1 {
        scope: hash(1),
        consumers: vec![consumer("a", 2)?],
        producers: vec![producer(0)?],
        optional_view_roots: Vec::new(),
    });
    assert!(opaque_zero.is_ok());
    assert_eq!(
        WorldConsumerSetV1::new(WorldConsumerSetInputV1 {
            scope: hash(1),
            consumers: vec![consumer("a", 2)?],
            producers: vec![producer(4)?],
            optional_view_roots: vec![hash(6), Hash::zero()],
        }),
        Err(WorldConsumerSetErrorV1::ZeroContentAddress)
    );
    Ok(())
}

#[test]
fn public_closed_error_display_variants_are_stable() {
    let errors = [
        WorldConsumerSetErrorV1::InvalidEncoding,
        WorldConsumerSetErrorV1::WrongMagic,
        WorldConsumerSetErrorV1::WrongVersion,
        WorldConsumerSetErrorV1::FieldOutOfBounds,
        WorldConsumerSetErrorV1::ZeroContentAddress,
        WorldConsumerSetErrorV1::NonCanonicalOrder,
        WorldConsumerSetErrorV1::NonCanonicalEncoding,
    ];
    for error in errors {
        assert!(!error.to_string().is_empty());
    }
}

#[test]
fn public_constructor_accepts_exact_limits_and_rejects_one_more(
) -> Result<(), Box<dyn std::error::Error>> {
    let max_id = "a".repeat(128);
    assert!(WorldConsumerV1::new(max_id, hash(1), hash(2), hash(3)).is_ok());
    let consumers = (0_u8..64)
        .map(|value| consumer(&format!("{value:03}{}", "a".repeat(125)), value + 1))
        .collect::<Result<Vec<_>, _>>()?;
    let producers = (0_u16..256)
        .map(|value| {
            WorldProducerV1::new(
                PluginId::from_ulid(Ulid::from(u128::from(value))),
                indexed_hash(value),
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    let views = (0_u16..256).map(indexed_hash).collect();
    let maximum = WorldConsumerSetV1::new(WorldConsumerSetInputV1 {
        scope: hash(1),
        consumers,
        producers,
        optional_view_roots: views,
    })?;
    let encoded_maximum = maximum.encode();
    // Independent preferred-CBOR size: header41 + consumer-array2 +
    // 64*(row1 + text130 + 3*hash34) + producer-array3 +
    // 256*(row1 + plugin17 + hash34) + view-array3 + 256*hash34.
    assert_eq!(encoded_maximum.len(), 36_977);
    assert_eq!(WorldConsumerSetV1::decode(&encoded_maximum), Ok(maximum));
    let too_many = (0_u8..65)
        .map(|value| consumer(&format!("{value:03}"), value + 1))
        .collect::<Result<Vec<_>, _>>()?;
    assert_eq!(
        WorldConsumerSetV1::new(WorldConsumerSetInputV1 {
            scope: hash(1),
            consumers: too_many,
            producers: vec![producer(1)?],
            optional_view_roots: Vec::new()
        }),
        Err(WorldConsumerSetErrorV1::FieldOutOfBounds)
    );
    let too_many_producers = (0_u16..257)
        .map(|value| {
            WorldProducerV1::new(
                PluginId::from_ulid(Ulid::from(u128::from(value))),
                indexed_hash(value),
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    assert_eq!(
        WorldConsumerSetV1::new(WorldConsumerSetInputV1 {
            scope: hash(1),
            consumers: vec![consumer("a", 2)?],
            producers: too_many_producers,
            optional_view_roots: Vec::new()
        }),
        Err(WorldConsumerSetErrorV1::FieldOutOfBounds)
    );
    let too_many_views = (0_u16..257).map(indexed_hash).collect();
    assert_eq!(
        WorldConsumerSetV1::new(WorldConsumerSetInputV1 {
            scope: hash(1),
            consumers: vec![consumer("a", 2)?],
            producers: vec![producer(1)?],
            optional_view_roots: too_many_views
        }),
        Err(WorldConsumerSetErrorV1::FieldOutOfBounds)
    );
    Ok(())
}

#[test]
fn public_decode_rejects_hostile_lengths_types_utf8_and_nonpreferred_forms(
) -> Result<(), Box<dyn std::error::Error>> {
    let valid = record()?.encode();
    let cases = [
        CanonicalBytes::from_vec(vec![0x9f]),
        CanonicalBytes::from_vec(vec![0x98, 6]),
        CanonicalBytes::from_vec(vec![
            0x86, 0x44, b'W', b'C', b'S', b'1', 1, 0x5a, 0xff, 0xff, 0xff, 0xff,
        ]),
        CanonicalBytes::from_vec(vec![0x86, 0x44, b'W', b'C', b'S', b'1', 1, 0x58, 0x20]),
        CanonicalBytes::from_vec(vec![
            0x86, 0x44, b'W', b'C', b'S', b'1', 1, 0x58, 0x20, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0x81, 0x84, 0x61, 0xff,
        ]),
    ];
    for case in cases {
        assert!(WorldConsumerSetV1::decode(&case).is_err());
    }
    let mut trailing = valid.as_slice().to_vec();
    trailing.push(0);
    assert_eq!(
        WorldConsumerSetV1::decode(&CanonicalBytes::from_vec(trailing)),
        Err(WorldConsumerSetErrorV1::InvalidEncoding)
    );
    let mut nonpreferred = valid.as_slice().to_vec();
    nonpreferred[0] = 0x98;
    nonpreferred.insert(1, 6);
    assert_eq!(
        WorldConsumerSetV1::decode(&CanonicalBytes::from_vec(nonpreferred)),
        Err(WorldConsumerSetErrorV1::NonCanonicalEncoding)
    );
    let mut invalid_utf8 = valid.as_slice().to_vec();
    let text_header = invalid_utf8
        .windows(2)
        .position(|window| window == [0x61, b'a'])
        .ok_or("consumer id present")?;
    invalid_utf8[text_header + 1] = 0xff;
    assert_eq!(
        WorldConsumerSetV1::decode(&CanonicalBytes::from_vec(invalid_utf8)),
        Err(WorldConsumerSetErrorV1::InvalidEncoding)
    );
    let mut wrong_magic = valid.as_slice().to_vec();
    wrong_magic[2] = b'X';
    assert_eq!(
        WorldConsumerSetV1::decode(&CanonicalBytes::from_vec(wrong_magic)),
        Err(WorldConsumerSetErrorV1::WrongMagic)
    );
    let mut wrong_version = valid.as_slice().to_vec();
    wrong_version[6] = 2;
    assert_eq!(
        WorldConsumerSetV1::decode(&CanonicalBytes::from_vec(wrong_version)),
        Err(WorldConsumerSetErrorV1::WrongVersion)
    );
    Ok(())
}

#[test]
fn public_decode_rejects_every_truncated_prefix_and_oversized_input(
) -> Result<(), Box<dyn std::error::Error>> {
    let valid = record()?.encode();
    for length in 0..valid.len() {
        let prefix = CanonicalBytes::from_vec(valid.as_slice()[..length].to_vec());
        assert!(
            WorldConsumerSetV1::decode(&prefix).is_err(),
            "prefix {length}"
        );
    }
    assert_eq!(WorldConsumerSetV1::decode(&valid), Ok(record()?));
    assert_eq!(
        WorldConsumerSetV1::decode(&CanonicalBytes::from_vec(vec![0; 65_537])),
        Err(WorldConsumerSetErrorV1::FieldOutOfBounds),
    );
    Ok(())
}

#[test]
fn public_consumer_validates_each_address_and_utf8_byte_limit(
) -> Result<(), Box<dyn std::error::Error>> {
    for zero_index in 0..3 {
        let mut addresses = [hash(1), hash(2), hash(3)];
        addresses[zero_index] = Hash::zero();
        assert_eq!(
            WorldConsumerV1::new("a".to_owned(), addresses[0], addresses[1], addresses[2]),
            Err(WorldConsumerSetErrorV1::ZeroContentAddress),
        );
    }
    let id = "é".repeat(64);
    let row = consumer(&id, 2)?;
    assert_eq!(row.consumer_id(), id);
    assert_eq!(row.reducer_hash(), hash(2));
    assert_eq!(row.schema_hash(), hash(3));
    assert_eq!(row.runtime_hash(), hash(4));
    assert_eq!(
        consumer(&"é".repeat(65), 2),
        Err(WorldConsumerSetErrorV1::FieldOutOfBounds),
    );
    let selector = WorldConsumerSetV1::new(WorldConsumerSetInputV1 {
        scope: hash(1),
        consumers: vec![row.clone()],
        producers: vec![producer(0)?],
        optional_view_roots: Vec::new(),
    })?;
    assert_eq!(selector.scope(), hash(1));
    assert_eq!(selector.consumers(), &[row]);
    assert_eq!(selector.producers()[0].plugin_id(), plugin(0));
    assert_eq!(selector.producers()[0].output_policy_hash(), hash(20));
    assert!(selector.optional_view_roots().is_empty());
    assert_eq!(WorldConsumerSetV1::decode(&selector.encode()), Ok(selector));
    Ok(())
}

#[test]
fn public_decode_rejects_empty_and_hostile_rosters_before_row_parsing(
) -> Result<(), Box<dyn std::error::Error>> {
    let valid = record()?.encode();
    // Fixed literal fixture offsets: consumers41, producers147, views200.
    for offset in [41, 147] {
        let mut empty = valid.as_slice()[..offset].to_vec();
        empty.push(0x80);
        assert_eq!(
            WorldConsumerSetV1::decode(&CanonicalBytes::from_vec(empty)),
            Err(WorldConsumerSetErrorV1::FieldOutOfBounds),
        );
    }
    for offset in [41, 147, 200] {
        let mut hostile = valid.as_slice()[..offset].to_vec();
        hostile.push(0x9b);
        hostile.extend_from_slice(&u64::MAX.to_be_bytes());
        assert_eq!(
            WorldConsumerSetV1::decode(&CanonicalBytes::from_vec(hostile)),
            Err(WorldConsumerSetErrorV1::FieldOutOfBounds),
        );
    }
    Ok(())
}
