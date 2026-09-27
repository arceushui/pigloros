use pos_core::{
    adapter_configuration_digest_v1, public_adapter_schema_digest_v1, AdapterAdmissionEntryV1,
    AdapterAdmissionErrorV1, AdapterAdmissionInputV1, AdapterAdmissionV1, Hash, PluginId,
    MAX_ADAPTER_ADMISSION_BYTES_V1, MAX_ADAPTER_ADMISSION_ENTRIES_V1,
    MAX_ADAPTER_CONFIGURATION_BYTES_V1,
};

type TestResult<T> = Result<T, Box<dyn std::error::Error>>;

fn from_hex(text: &str) -> TestResult<Vec<u8>> {
    text.as_bytes()
        .chunks_exact(2)
        .map(|pair| Ok(u8::from_str_radix(std::str::from_utf8(pair)?, 16)?))
        .collect()
}

fn vector() -> TestResult<Vec<u8>> {
    from_hex(concat!(
        "86444d414131015820365678ef2286c7e68ab7ada3f90f20feca822efbc88abc5a7bf60e950a6517",
        "6c015820515151515151515151515151515151515151515151515151515151515151515180"
    ))
}

fn input() -> TestResult<AdapterAdmissionInputV1> {
    let bytes = vector()?;
    Ok(AdapterAdmissionInputV1 {
        owner_reference: Hash::from_bytes(<[u8; 32]>::try_from(&bytes[9..41])?),
        configuration_generation: 1,
        scope_digest: Hash::from_bytes([0x51; 32]),
        entries: Vec::new(),
    })
}

fn entry(plugin: u128, version: u64, configuration: Vec<u8>) -> AdapterAdmissionEntryV1 {
    let schema = public_adapter_schema_digest_v1();
    let configuration_digest = adapter_configuration_digest_v1(&configuration);
    AdapterAdmissionEntryV1 {
        plugin_id: PluginId::from_ulid(ulid::Ulid::from(plugin)),
        adapter_id: "adapter.1".to_owned(),
        provider_id: "provider_1".to_owned(),
        operation_id: "read-only".to_owned(),
        protocol_version: version,
        request_schema_digest: schema,
        response_schema_digest: schema,
        exact_configuration_bytes: configuration,
        configuration_digest,
        input_data_class: 2,
        output_data_class: 2,
        effect_mode: 0,
    }
}

#[test]
fn normative_empty_maa1_bytes_and_native_digest() -> TestResult<()> {
    let admission = AdapterAdmissionV1::new(input()?)?;
    let bytes = vector()?;
    assert_eq!(bytes.len(), 77);
    assert_eq!(admission.to_canonical_cbor(), bytes);
    assert_eq!(
        AdapterAdmissionV1::from_canonical_cbor(&bytes),
        Ok(admission.clone())
    );
    assert_eq!(admission.as_input(), &input()?);
    assert_eq!(
        admission.digest().as_bytes().to_vec(),
        from_hex("c40ae5d5380762fb743e192e291b526832f982d6d5a58893163ff0b10bf81423")?
    );
    Ok(())
}

#[test]
fn ordered_entries_and_integer_and_configuration_boundaries_round_trip() -> TestResult<()> {
    for generation in [1, 23, 24, 255, 256, 65_535, 65_536, u64::MAX] {
        let admission = AdapterAdmissionV1::new(AdapterAdmissionInputV1 {
            configuration_generation: generation,
            entries: vec![entry(1, 1, Vec::new()), entry(2, u64::MAX, vec![42; 4_096])],
            ..input()?
        })?;
        let bytes = admission.to_canonical_cbor();
        assert!(bytes.len() < MAX_ADAPTER_ADMISSION_BYTES_V1);
        assert_eq!(
            AdapterAdmissionV1::from_canonical_cbor(&bytes),
            Ok(admission)
        );
    }
    for length in [0, 23, 24, 255, 256, MAX_ADAPTER_CONFIGURATION_BYTES_V1] {
        let admission = AdapterAdmissionV1::new(AdapterAdmissionInputV1 {
            entries: vec![entry(1, 24, vec![0x5a; length])],
            ..input()?
        })?;
        assert_eq!(
            AdapterAdmissionV1::from_canonical_cbor(&admission.to_canonical_cbor()),
            Ok(admission)
        );
    }
    let mut long_names = entry(1, 1, Vec::new());
    long_names.adapter_id = "a".repeat(128);
    long_names.provider_id = "p".repeat(128);
    long_names.operation_id = "o".repeat(128);
    long_names.effect_mode = 1;
    let admission = AdapterAdmissionV1::new(AdapterAdmissionInputV1 {
        entries: vec![long_names],
        ..input()?
    })?;
    assert_eq!(
        AdapterAdmissionV1::from_canonical_cbor(&admission.to_canonical_cbor()),
        Ok(admission)
    );
    let entries = (1..=MAX_ADAPTER_ADMISSION_ENTRIES_V1)
        .map(|version| entry(1, version as u64, Vec::new()))
        .collect();
    let maximum_count = AdapterAdmissionV1::new(AdapterAdmissionInputV1 {
        entries,
        ..input()?
    })?;
    assert_eq!(
        AdapterAdmissionV1::from_canonical_cbor(&maximum_count.to_canonical_cbor()),
        Ok(maximum_count)
    );
    Ok(())
}

#[test]
fn schema_and_configuration_digests_use_exact_length_framing() {
    let schema = b"pigloros.repro.public-bytes-v1";
    assert_eq!(schema.len(), 30);
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"pigloros.repro.adapter-schema.v1\0");
    hasher.update(&30_u64.to_be_bytes());
    hasher.update(schema);
    assert_eq!(
        public_adapter_schema_digest_v1().as_bytes(),
        hasher.finalize().as_bytes()
    );
    assert_ne!(
        adapter_configuration_digest_v1(b"a"),
        adapter_configuration_digest_v1(b"a\0")
    );
}

#[test]
fn invalid_identity_count_entry_and_order_reject() -> TestResult<()> {
    for (owner_reference, configuration_generation, scope_digest) in [
        (Hash::zero(), 1, Hash::from_bytes([0x51; 32])),
        (input()?.owner_reference, 0, Hash::from_bytes([0x51; 32])),
        (input()?.owner_reference, 1, Hash::zero()),
    ] {
        assert_eq!(
            AdapterAdmissionV1::new(AdapterAdmissionInputV1 {
                owner_reference,
                configuration_generation,
                scope_digest,
                entries: Vec::new(),
            }),
            Err(AdapterAdmissionErrorV1::InvalidIdentity)
        );
    }
    assert_eq!(
        AdapterAdmissionV1::new(AdapterAdmissionInputV1 {
            entries: vec![entry(1, 1, Vec::new()); MAX_ADAPTER_ADMISSION_ENTRIES_V1 + 1],
            ..input()?
        }),
        Err(AdapterAdmissionErrorV1::FieldOutOfBounds)
    );
    let good = entry(1, 1, Vec::new());
    for entries in [
        vec![good.clone(), good.clone()],
        vec![entry(2, 1, Vec::new()), good.clone()],
    ] {
        assert_eq!(
            AdapterAdmissionV1::new(AdapterAdmissionInputV1 {
                entries,
                ..input()?
            }),
            Err(AdapterAdmissionErrorV1::InvalidOrder)
        );
    }
    let mut same_plugin_later_version = good.clone();
    same_plugin_later_version.protocol_version = 2;
    assert!(AdapterAdmissionV1::new(AdapterAdmissionInputV1 {
        entries: vec![good.clone(), same_plugin_later_version],
        ..input()?
    })
    .is_ok());
    for bad in [
        AdapterAdmissionEntryV1 {
            adapter_id: String::new(),
            ..good.clone()
        },
        AdapterAdmissionEntryV1 {
            provider_id: "é".to_owned(),
            ..good.clone()
        },
        AdapterAdmissionEntryV1 {
            operation_id: "bad/operation".to_owned(),
            ..good.clone()
        },
        AdapterAdmissionEntryV1 {
            adapter_id: "a".repeat(129),
            ..good.clone()
        },
        AdapterAdmissionEntryV1 {
            protocol_version: 0,
            ..good.clone()
        },
        AdapterAdmissionEntryV1 {
            request_schema_digest: Hash::zero(),
            ..good.clone()
        },
        AdapterAdmissionEntryV1 {
            response_schema_digest: Hash::zero(),
            ..good.clone()
        },
        AdapterAdmissionEntryV1 {
            configuration_digest: Hash::zero(),
            ..good.clone()
        },
        AdapterAdmissionEntryV1 {
            input_data_class: 1,
            ..good.clone()
        },
        AdapterAdmissionEntryV1 {
            output_data_class: 4,
            ..good.clone()
        },
        AdapterAdmissionEntryV1 {
            effect_mode: 2,
            ..good.clone()
        },
    ] {
        assert_eq!(
            AdapterAdmissionV1::new(AdapterAdmissionInputV1 {
                entries: vec![bad],
                ..input()?
            }),
            Err(AdapterAdmissionErrorV1::InvalidEntry)
        );
    }
    assert_eq!(
        AdapterAdmissionV1::new(AdapterAdmissionInputV1 {
            entries: vec![entry(1, 1, vec![0; MAX_ADAPTER_CONFIGURATION_BYTES_V1 + 1])],
            ..input()?
        }),
        Err(AdapterAdmissionErrorV1::FieldOutOfBounds)
    );
    Ok(())
}

#[test]
fn malformed_noncanonical_and_oversized_maa1_reject() -> TestResult<()> {
    let good = vector()?;
    let mut cases = vec![
        (Vec::new(), AdapterAdmissionErrorV1::InvalidEncoding),
        (
            good[..40].to_vec(),
            AdapterAdmissionErrorV1::InvalidEncoding,
        ),
        (
            vec![0; MAX_ADAPTER_ADMISSION_BYTES_V1 + 1],
            AdapterAdmissionErrorV1::FieldOutOfBounds,
        ),
    ];
    for (offset, value) in [
        (0, 0x85),
        (2, b'X'),
        (6, 2),
        (7, 0x57),
        (42, 0x57),
        (76, 0x81),
    ] {
        let mut bytes = good.clone();
        bytes[offset] = value;
        cases.push((bytes, AdapterAdmissionErrorV1::InvalidEncoding));
    }
    let mut wrong_owner = good.clone();
    wrong_owner[9..41].fill(0);
    cases.push((wrong_owner, AdapterAdmissionErrorV1::InvalidIdentity));
    let mut zero_generation = good.clone();
    zero_generation[41] = 0;
    cases.push((zero_generation, AdapterAdmissionErrorV1::InvalidIdentity));
    let mut wrong_scope = good.clone();
    wrong_scope[44..76].fill(0);
    cases.push((wrong_scope, AdapterAdmissionErrorV1::InvalidIdentity));
    let mut overlong_generation = good.clone();
    overlong_generation[41] = 0x18;
    overlong_generation.insert(42, 1);
    cases.push((overlong_generation, AdapterAdmissionErrorV1::NonCanonical));
    let mut trailing = good.clone();
    trailing.push(0);
    cases.push((trailing, AdapterAdmissionErrorV1::NonCanonical));
    let mut excessive_count = good;
    excessive_count.truncate(76);
    excessive_count.extend_from_slice(&[0x19, 0x04, 0x01]);
    cases.push((excessive_count, AdapterAdmissionErrorV1::FieldOutOfBounds));
    for (bytes, expected) in cases {
        assert_eq!(
            AdapterAdmissionV1::from_canonical_cbor(&bytes),
            Err(expected)
        );
    }
    Ok(())
}

#[test]
fn malformed_adapter_entries_fail_at_the_public_decoder() -> TestResult<()> {
    let record = AdapterAdmissionV1::new(AdapterAdmissionInputV1 {
        entries: vec![entry(1, 1, vec![42; 4_096])],
        ..input()?
    })?;
    let good = record.to_canonical_cbor();
    let name = good
        .windows(b"adapter.1".len())
        .position(|window| window == b"adapter.1")
        .ok_or("missing adapter name")?;
    let mut invalid_utf8 = good.clone();
    invalid_utf8[name] = 0xff;
    assert_eq!(
        AdapterAdmissionV1::from_canonical_cbor(&invalid_utf8),
        Err(AdapterAdmissionErrorV1::InvalidEncoding)
    );
    let mut invalid_ascii = good.clone();
    invalid_ascii[name] = b'?';
    assert_eq!(
        AdapterAdmissionV1::from_canonical_cbor(&invalid_ascii),
        Err(AdapterAdmissionErrorV1::InvalidEntry)
    );
    let mut long_name = good.clone();
    long_name[name - 1] = 0x78;
    long_name.insert(name, 129);
    assert_eq!(
        AdapterAdmissionV1::from_canonical_cbor(&long_name),
        Err(AdapterAdmissionErrorV1::FieldOutOfBounds)
    );
    let config_header = good
        .windows(3)
        .position(|window| window == [0x59, 0x10, 0x00])
        .ok_or("missing configuration header")?;
    let mut long_config = good.clone();
    long_config[config_header + 2] = 1;
    assert_eq!(
        AdapterAdmissionV1::from_canonical_cbor(&long_config),
        Err(AdapterAdmissionErrorV1::FieldOutOfBounds)
    );
    let mut wrong_entry_shape = good.clone();
    wrong_entry_shape[77] = 0x8b;
    assert_eq!(
        AdapterAdmissionV1::from_canonical_cbor(&wrong_entry_shape),
        Err(AdapterAdmissionErrorV1::InvalidEncoding)
    );
    let mut excessive_code = good.clone();
    excessive_code.pop();
    excessive_code.extend_from_slice(&[0x19, 0x01, 0x00]);
    assert_eq!(
        AdapterAdmissionV1::from_canonical_cbor(&excessive_code),
        Err(AdapterAdmissionErrorV1::InvalidEntry)
    );
    let mut overlong_count = good;
    overlong_count[76] = 0x98;
    overlong_count.insert(77, 1);
    assert_eq!(
        AdapterAdmissionV1::from_canonical_cbor(&overlong_count),
        Err(AdapterAdmissionErrorV1::NonCanonical)
    );
    Ok(())
}
