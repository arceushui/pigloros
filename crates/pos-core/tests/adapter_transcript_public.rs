use pos_core::{
    adapter_configuration_digest_v1, adapter_output_digest_v1, public_adapter_schema_digest_v1,
    AdapterAdmissionEntryV1, AdapterAdmissionInputV1, AdapterAdmissionV1, AdapterInvocationInputV1,
    AdapterInvocationV1, AdapterTranscriptCallV1, AdapterTranscriptErrorV1,
    AdapterTranscriptInputV1, AdapterTranscriptV1, Hash, PluginId, WorldReplayHandleV1,
    MAX_ADAPTER_CALL_BYTES_V1, MAX_ADAPTER_TRANSCRIPT_CALLS_V1,
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
        "87444d415431015820365678ef2286c7e68ab7ada3f90f20feca822efbc88abc5a7bf60e950a6517",
        "6c58a2894457524831015820365678ef2286c7e68ab7ada3f90f20feca822efbc88abc5a7bf60e95",
        "0a65176c501010101010101010101010101010101007582021212121212121212121212121212121",
        "21212121212121212121212121212121582031313131313131313131313131313131313131313131",
        "31313131313131313131015820414141414141414141414141414141414141414141414141414141",
        "41414141415820424242424242424242424242424242424242424242424242424242424242424258",
        "20c40ae5d5380762fb743e192e291b526832f982d6d5a58893163ff0b10bf8142380",
    ))
}

fn input() -> TestResult<AdapterTranscriptInputV1> {
    let bytes = vector()?;
    Ok(AdapterTranscriptInputV1 {
        owner_reference: Hash::from_bytes(<[u8; 32]>::try_from(&bytes[9..41])?),
        world_handle: WorldReplayHandleV1::from_canonical_cbor(&bytes[43..205])?,
        run_operation_id: Hash::from_bytes([0x42; 32]),
        adapter_admission_digest: Hash::from_bytes(<[u8; 32]>::try_from(&bytes[241..273])?),
        calls: Vec::new(),
    })
}

fn invocation(global_index: u64, payload: Vec<u8>) -> TestResult<AdapterInvocationV1> {
    let schema = public_adapter_schema_digest_v1();
    Ok(AdapterInvocationV1::new(AdapterInvocationInputV1 {
        adapter_id: "adapter.1".to_owned(),
        provider_id: "provider_1".to_owned(),
        operation_id: "read-only".to_owned(),
        protocol_version: 1,
        request_schema_digest: schema,
        response_schema_digest: schema,
        configuration_digest: Hash::from_bytes([3; 32]),
        global_call_index: global_index,
        exact_request_payload: payload,
    })?)
}

fn call(
    plugin: u128,
    per_plugin_index: u64,
    global_index: u64,
) -> TestResult<AdapterTranscriptCallV1> {
    Ok(AdapterTranscriptCallV1 {
        plugin_id: PluginId::from_ulid(ulid::Ulid::from(plugin)),
        per_plugin_call_index: per_plugin_index,
        input: invocation(global_index, vec![u8::try_from(global_index)?])?,
        exact_output_bytes: vec![u8::try_from(plugin)?, u8::try_from(per_plugin_index)?],
        recorded_wall_time_micros: global_index,
    })
}

fn admitted_transcript() -> TestResult<(AdapterAdmissionV1, AdapterTranscriptV1)> {
    let base = input()?;
    let configuration = b"public configuration".to_vec();
    let configuration_digest = adapter_configuration_digest_v1(&configuration);
    let entries = [1_u128, 2].map(|plugin| AdapterAdmissionEntryV1 {
        plugin_id: PluginId::from_ulid(ulid::Ulid::from(plugin)),
        adapter_id: "adapter.1".to_owned(),
        provider_id: "provider_1".to_owned(),
        operation_id: "read-only".to_owned(),
        protocol_version: 1,
        request_schema_digest: public_adapter_schema_digest_v1(),
        response_schema_digest: public_adapter_schema_digest_v1(),
        exact_configuration_bytes: configuration.clone(),
        configuration_digest,
        input_data_class: 2,
        output_data_class: 2,
        effect_mode: 0,
    });
    let admission = AdapterAdmissionV1::new(AdapterAdmissionInputV1 {
        owner_reference: base.owner_reference,
        configuration_generation: 1,
        scope_digest: Hash::from_bytes([0x51; 32]),
        entries: entries.to_vec(),
    })?;
    let mut calls = vec![call(1, 0, 0)?, call(2, 0, 1)?, call(1, 1, 2)?];
    for call in &mut calls {
        call.input = AdapterInvocationV1::new(AdapterInvocationInputV1 {
            configuration_digest,
            ..call.input.as_input().clone()
        })?;
    }
    let transcript = AdapterTranscriptV1::new(AdapterTranscriptInputV1 {
        adapter_admission_digest: admission.digest(),
        calls,
        ..base
    })?;
    Ok((admission, transcript))
}

#[test]
fn admitted_call_contracts_match_exact_owner_plugin_tuple_and_configuration() -> TestResult<()> {
    let (admission, transcript) = admitted_transcript()?;
    assert_eq!(transcript.compare_call_contracts(&admission), Ok(()));

    let wrong_owner = AdapterAdmissionV1::new(AdapterAdmissionInputV1 {
        owner_reference: Hash::from_bytes([7; 32]),
        ..admission.as_input().clone()
    })?;
    assert_eq!(
        transcript.compare_call_contracts(&wrong_owner),
        Err(AdapterTranscriptErrorV1::InvalidIdentity)
    );
    let wrong_digest = AdapterAdmissionV1::new(AdapterAdmissionInputV1 {
        configuration_generation: 2,
        ..admission.as_input().clone()
    })?;
    assert_eq!(
        transcript.compare_call_contracts(&wrong_digest),
        Err(AdapterTranscriptErrorV1::InvalidIdentity)
    );

    let mut wrong_calls = Vec::new();
    let base = transcript.as_input().calls[0].input.as_input();
    wrong_calls.push((PluginId::from_ulid(ulid::Ulid::from(3_u128)), base.clone()));
    for changed in [
        AdapterInvocationInputV1 {
            adapter_id: "other".to_owned(),
            ..base.clone()
        },
        AdapterInvocationInputV1 {
            provider_id: "other".to_owned(),
            ..base.clone()
        },
        AdapterInvocationInputV1 {
            operation_id: "other".to_owned(),
            ..base.clone()
        },
        AdapterInvocationInputV1 {
            protocol_version: 2,
            ..base.clone()
        },
        AdapterInvocationInputV1 {
            configuration_digest: Hash::from_bytes([3; 32]),
            ..base.clone()
        },
    ] {
        wrong_calls.push((transcript.as_input().calls[0].plugin_id, changed));
    }
    for (plugin_id, changed) in wrong_calls {
        let mut candidate = transcript.as_input().clone();
        candidate.calls.truncate(1);
        candidate.calls[0].plugin_id = plugin_id;
        candidate.calls[0].input = AdapterInvocationV1::new(changed)?;
        let candidate = AdapterTranscriptV1::new(candidate)?;
        assert_eq!(
            candidate.compare_call_contracts(&admission),
            Err(AdapterTranscriptErrorV1::InvalidCall)
        );
    }
    Ok(())
}

#[test]
fn normative_empty_mat1_bytes_and_native_digest() -> TestResult<()> {
    let transcript = AdapterTranscriptV1::new(input()?)?;
    let bytes = vector()?;
    assert_eq!(bytes.len(), 274);
    assert_eq!(transcript.to_canonical_cbor(), bytes);
    assert_eq!(
        AdapterTranscriptV1::from_canonical_cbor(&bytes),
        Ok(transcript.clone())
    );
    assert_eq!(transcript.as_input(), &input()?);
    assert_eq!(
        transcript.digest().as_bytes().to_vec(),
        from_hex("5473435d6fe01b0ef3a6a8dc5e77380fafc4b06bb420bdf60f1d4f8502b95d3e")?
    );
    Ok(())
}

#[test]
fn canonical_air1_and_interleaved_plugin_calls_round_trip() -> TestResult<()> {
    let request = invocation(24, b"public request".to_vec())?;
    assert_eq!(request.as_input().global_call_index, 24);
    assert_eq!(
        AdapterInvocationV1::from_canonical_cbor(&request.to_canonical_cbor()),
        Ok(request.clone())
    );
    assert_ne!(
        request.digest(),
        invocation(25, b"public request".to_vec())?.digest()
    );
    let different_operation = AdapterInvocationV1::new(AdapterInvocationInputV1 {
        operation_id: "other-operation".to_owned(),
        ..request.as_input().clone()
    })?;
    assert_ne!(request.digest(), different_operation.digest());
    assert_ne!(
        adapter_output_digest_v1(b"a"),
        adapter_output_digest_v1(b"a\0")
    );
    let transcript = AdapterTranscriptV1::new(AdapterTranscriptInputV1 {
        calls: vec![call(1, 0, 0)?, call(2, 0, 1)?, call(1, 1, 2)?],
        ..input()?
    })?;
    let bytes = transcript.to_canonical_cbor();
    assert_eq!(
        AdapterTranscriptV1::from_canonical_cbor(&bytes),
        Ok(transcript)
    );
    Ok(())
}

#[test]
fn truncated_populated_air1_and_mat1_reject_at_every_field_boundary() -> TestResult<()> {
    let invocation_bytes = invocation(24, b"public request".to_vec())?.to_canonical_cbor();
    for end in 0..invocation_bytes.len() {
        assert!(
            AdapterInvocationV1::from_canonical_cbor(&invocation_bytes[..end]).is_err(),
            "truncated AIR1 prefix at byte {end} was accepted"
        );
    }

    let transcript = AdapterTranscriptV1::new(AdapterTranscriptInputV1 {
        calls: vec![call(1, 0, 0)?],
        ..input()?
    })?;
    let transcript_bytes = transcript.to_canonical_cbor();
    for end in 0..transcript_bytes.len() {
        assert!(
            AdapterTranscriptV1::from_canonical_cbor(&transcript_bytes[..end]).is_err(),
            "truncated MAT1 prefix at byte {end} was accepted"
        );
    }
    Ok(())
}

#[test]
fn air1_integer_widths_and_identity_lengths_round_trip() -> TestResult<()> {
    for number in [0, 23, 24, 255, 256, 65_535, 65_536, u64::MAX] {
        let schema = public_adapter_schema_digest_v1();
        let request = AdapterInvocationV1::new(AdapterInvocationInputV1 {
            adapter_id: "a".repeat(128),
            provider_id: "p".repeat(128),
            operation_id: "o".repeat(128),
            protocol_version: number.max(1),
            request_schema_digest: schema,
            response_schema_digest: schema,
            configuration_digest: Hash::from_bytes([3; 32]),
            global_call_index: number,
            exact_request_payload: vec![42; usize::try_from(number.min(256))?],
        })?;
        assert_eq!(
            AdapterInvocationV1::from_canonical_cbor(&request.to_canonical_cbor()),
            Ok(request)
        );
    }
    let transcript = AdapterTranscriptV1::new(AdapterTranscriptInputV1 {
        calls: vec![AdapterTranscriptCallV1 {
            recorded_wall_time_micros: u64::MAX,
            ..call(1, 0, 0)?
        }],
        ..input()?
    })?;
    assert_eq!(
        AdapterTranscriptV1::from_canonical_cbor(&transcript.to_canonical_cbor()),
        Ok(transcript)
    );
    Ok(())
}

#[test]
fn invalid_air1_profile_and_size_reject() -> TestResult<()> {
    let good = invocation(0, Vec::new())?;
    let fields = good.as_input().clone();
    for candidate in [
        AdapterInvocationInputV1 {
            adapter_id: String::new(),
            ..fields.clone()
        },
        AdapterInvocationInputV1 {
            provider_id: "é".to_owned(),
            ..fields.clone()
        },
        AdapterInvocationInputV1 {
            operation_id: "bad/name".to_owned(),
            ..fields.clone()
        },
        AdapterInvocationInputV1 {
            adapter_id: "a".repeat(129),
            ..fields.clone()
        },
        AdapterInvocationInputV1 {
            protocol_version: 0,
            ..fields.clone()
        },
        AdapterInvocationInputV1 {
            request_schema_digest: Hash::zero(),
            ..fields.clone()
        },
        AdapterInvocationInputV1 {
            response_schema_digest: Hash::zero(),
            ..fields.clone()
        },
        AdapterInvocationInputV1 {
            configuration_digest: Hash::zero(),
            ..fields.clone()
        },
    ] {
        assert_eq!(
            AdapterInvocationV1::new(candidate),
            Err(AdapterTranscriptErrorV1::InvalidCall)
        );
    }
    assert_eq!(
        AdapterInvocationV1::new(AdapterInvocationInputV1 {
            exact_request_payload: vec![0; MAX_ADAPTER_CALL_BYTES_V1 + 1],
            ..fields.clone()
        }),
        Err(AdapterTranscriptErrorV1::FieldOutOfBounds)
    );
    assert_eq!(
        AdapterInvocationV1::new(AdapterInvocationInputV1 {
            exact_request_payload: vec![0; MAX_ADAPTER_CALL_BYTES_V1],
            ..fields
        }),
        Err(AdapterTranscriptErrorV1::FieldOutOfBounds)
    );
    let exact_limit_payload = MAX_ADAPTER_CALL_BYTES_V1 - good.to_canonical_cbor().len() - 4;
    let accepted = AdapterInvocationV1::new(AdapterInvocationInputV1 {
        exact_request_payload: vec![0; exact_limit_payload],
        ..good.as_input().clone()
    })?;
    assert_eq!(
        accepted.to_canonical_cbor().len(),
        MAX_ADAPTER_CALL_BYTES_V1
    );
    Ok(())
}

#[test]
fn invalid_mat1_identity_order_and_output_size_reject() -> TestResult<()> {
    for candidate in [
        AdapterTranscriptInputV1 {
            owner_reference: Hash::zero(),
            ..input()?
        },
        AdapterTranscriptInputV1 {
            owner_reference: Hash::from_bytes([1; 32]),
            ..input()?
        },
        AdapterTranscriptInputV1 {
            run_operation_id: Hash::zero(),
            ..input()?
        },
        AdapterTranscriptInputV1 {
            adapter_admission_digest: Hash::zero(),
            ..input()?
        },
    ] {
        assert_eq!(
            AdapterTranscriptV1::new(candidate),
            Err(AdapterTranscriptErrorV1::InvalidIdentity)
        );
    }
    for calls in [
        vec![call(1, 0, 1)?],
        vec![call(1, 1, 0)?],
        vec![call(1, 0, 0)?, call(1, 0, 1)?],
        vec![call(1, 0, 0)?, call(2, 0, 0)?],
    ] {
        assert_eq!(
            AdapterTranscriptV1::new(AdapterTranscriptInputV1 { calls, ..input()? }),
            Err(AdapterTranscriptErrorV1::InvalidOrder)
        );
    }
    assert_eq!(
        AdapterTranscriptV1::new(AdapterTranscriptInputV1 {
            calls: vec![AdapterTranscriptCallV1 {
                exact_output_bytes: vec![0; MAX_ADAPTER_CALL_BYTES_V1 + 1],
                ..call(1, 0, 0)?
            }],
            ..input()?
        }),
        Err(AdapterTranscriptErrorV1::FieldOutOfBounds)
    );
    Ok(())
}

#[test]
fn aggregate_transcript_and_decoder_byte_limits_reject() -> TestResult<()> {
    let calls = (0..16)
        .map(|index| {
            Ok(AdapterTranscriptCallV1 {
                exact_output_bytes: vec![0; MAX_ADAPTER_CALL_BYTES_V1],
                ..call(1, index, index)?
            })
        })
        .collect::<TestResult<Vec<_>>>()?;
    assert_eq!(
        AdapterTranscriptV1::new(AdapterTranscriptInputV1 { calls, ..input()? }),
        Err(AdapterTranscriptErrorV1::FieldOutOfBounds)
    );
    assert_eq!(
        AdapterTranscriptV1::from_canonical_cbor(&vec![
            0;
            pos_core::MAX_ADAPTER_TRANSCRIPT_BYTES_V1
                + 1
        ]),
        Err(AdapterTranscriptErrorV1::FieldOutOfBounds)
    );
    assert_eq!(
        AdapterInvocationV1::from_canonical_cbor(&vec![0; MAX_ADAPTER_CALL_BYTES_V1 + 1]),
        Err(AdapterTranscriptErrorV1::FieldOutOfBounds)
    );
    Ok(())
}

#[test]
fn malformed_air1_reject_before_authority() -> TestResult<()> {
    let air = invocation(0, b"a".to_vec())?.to_canonical_cbor();
    let mut wrong_air_shape = air.clone();
    wrong_air_shape[0] = 0x8a;
    assert_eq!(
        AdapterInvocationV1::from_canonical_cbor(&wrong_air_shape),
        Err(AdapterTranscriptErrorV1::InvalidEncoding)
    );
    let mut trailing_air = air.clone();
    trailing_air.push(0);
    assert_eq!(
        AdapterInvocationV1::from_canonical_cbor(&trailing_air),
        Err(AdapterTranscriptErrorV1::NonCanonical)
    );
    let mut wrong_air_magic = air.clone();
    wrong_air_magic[2] = b'X';
    assert_eq!(
        AdapterInvocationV1::from_canonical_cbor(&wrong_air_magic),
        Err(AdapterTranscriptErrorV1::InvalidEncoding)
    );
    let operation_end = air
        .windows(b"read-only".len())
        .position(|window| window == b"read-only")
        .ok_or("missing operation identity")?
        + b"read-only".len();
    let mut overlong_protocol = air.clone();
    overlong_protocol[operation_end] = 0x18;
    overlong_protocol.insert(operation_end + 1, 1);
    assert_eq!(
        AdapterInvocationV1::from_canonical_cbor(&overlong_protocol),
        Err(AdapterTranscriptErrorV1::NonCanonical)
    );
    let mut bad_utf8 = air;
    bad_utf8[8] = 0xff;
    assert_eq!(
        AdapterInvocationV1::from_canonical_cbor(&bad_utf8),
        Err(AdapterTranscriptErrorV1::InvalidEncoding)
    );
    let mut huge_length = invocation(0, b"a".to_vec())?.to_canonical_cbor();
    huge_length.truncate(huge_length.len() - 2);
    huge_length.push(0x5b);
    huge_length.extend_from_slice(&4_294_967_296_u64.to_be_bytes());
    assert_eq!(
        AdapterInvocationV1::from_canonical_cbor(&huge_length),
        Err(AdapterTranscriptErrorV1::FieldOutOfBounds)
    );
    let mut overbound_length = invocation(0, b"a".to_vec())?.to_canonical_cbor();
    overbound_length.truncate(overbound_length.len() - 2);
    overbound_length.push(0x5a);
    overbound_length
        .extend_from_slice(&u32::try_from(MAX_ADAPTER_CALL_BYTES_V1 + 1)?.to_be_bytes());
    assert_eq!(
        AdapterInvocationV1::from_canonical_cbor(&overbound_length),
        Err(AdapterTranscriptErrorV1::FieldOutOfBounds)
    );
    Ok(())
}

#[test]
fn malformed_mat1_reject_before_authority() -> TestResult<()> {
    let good = vector()?;
    let mut cases = vec![
        (Vec::new(), AdapterTranscriptErrorV1::InvalidEncoding),
        (
            good[..205].to_vec(),
            AdapterTranscriptErrorV1::InvalidEncoding,
        ),
    ];
    for (offset, value) in [
        (0, 0x86),
        (2, b'X'),
        (6, 2),
        (7, 0x57),
        (41, 0x57),
        (43, 0x88),
        (205, 0x57),
        (239, 0x57),
        (273, 0x00),
        (273, 0x9c),
        (273, 0x81),
    ] {
        let mut bytes = good.clone();
        bytes[offset] = value;
        cases.push((bytes, AdapterTranscriptErrorV1::InvalidEncoding));
    }
    let mut overlong_count = good.clone();
    overlong_count[273] = 0x98;
    overlong_count.push(0);
    cases.push((overlong_count, AdapterTranscriptErrorV1::NonCanonical));
    let mut excessive_count = good.clone();
    excessive_count.truncate(273);
    excessive_count.extend_from_slice(&[0x9a, 0x00, 0x10, 0x00, 0x01]);
    assert_eq!(u64::try_from(MAX_ADAPTER_TRANSCRIPT_CALLS_V1)?, 1_048_576);
    cases.push((excessive_count, AdapterTranscriptErrorV1::FieldOutOfBounds));
    let mut wrong_owner = good.clone();
    wrong_owner[9] ^= 1;
    cases.push((wrong_owner, AdapterTranscriptErrorV1::InvalidIdentity));
    for range in [207..239, 241..273] {
        let mut bytes = good.clone();
        bytes[range].fill(0);
        cases.push((bytes, AdapterTranscriptErrorV1::InvalidIdentity));
    }
    let mut trailing_mat = good;
    trailing_mat.push(0);
    cases.push((trailing_mat, AdapterTranscriptErrorV1::NonCanonical));
    for (bytes, error) in cases {
        assert_eq!(AdapterTranscriptV1::from_canonical_cbor(&bytes), Err(error));
    }
    Ok(())
}

#[test]
fn modified_call_bytes_or_hashes_reject() -> TestResult<()> {
    let transcript = AdapterTranscriptV1::new(AdapterTranscriptInputV1 {
        calls: vec![call(1, 0, 0)?],
        ..input()?
    })?;
    let good = transcript.to_canonical_cbor();
    let input_digest = transcript.as_input().calls[0].input.digest();
    let input_at = good
        .windows(32)
        .position(|window| window == input_digest.as_bytes())
        .ok_or("missing input digest")?;
    let mut wrong_input_hash = good.clone();
    wrong_input_hash[input_at] ^= 1;
    assert_eq!(
        AdapterTranscriptV1::from_canonical_cbor(&wrong_input_hash),
        Err(AdapterTranscriptErrorV1::InvalidCall)
    );
    let exact_input = transcript.as_input().calls[0].input.to_canonical_cbor();
    let input_at = good
        .windows(exact_input.len())
        .position(|window| window == exact_input.as_slice())
        .ok_or("missing AIR1 input")?;
    let mut wrong_input_bytes = good.clone();
    wrong_input_bytes[input_at + exact_input.len() - 1] ^= 1;
    assert_eq!(
        AdapterTranscriptV1::from_canonical_cbor(&wrong_input_bytes),
        Err(AdapterTranscriptErrorV1::InvalidCall)
    );
    let output_digest =
        adapter_output_digest_v1(&transcript.as_input().calls[0].exact_output_bytes);
    let output_at = good
        .windows(32)
        .position(|window| window == output_digest.as_bytes())
        .ok_or("missing output digest")?;
    let mut wrong_output_hash = good.clone();
    wrong_output_hash[output_at] ^= 1;
    assert_eq!(
        AdapterTranscriptV1::from_canonical_cbor(&wrong_output_hash),
        Err(AdapterTranscriptErrorV1::InvalidCall)
    );
    let mut wrong_call_shape = good;
    wrong_call_shape[273] = 0x81;
    wrong_call_shape[274] = 0x86;
    assert_eq!(
        AdapterTranscriptV1::from_canonical_cbor(&wrong_call_shape),
        Err(AdapterTranscriptErrorV1::InvalidEncoding)
    );
    Ok(())
}
