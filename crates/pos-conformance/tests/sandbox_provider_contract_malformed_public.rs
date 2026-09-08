use ciborium::value::Value;
use pos_conformance::{
    AdmissionGrantV1, LaunchPolicyV1, SandboxCancelRequestV1, SandboxCancelResponseV1,
    SandboxDescribeRequestV1, SandboxDescribeResponseV1, SandboxExecuteRequestV1,
    SandboxLocalErrorV1, SandboxPayloadChunkV1, SandboxProviderErrorV1, SandboxProviderManifestV1,
    SandboxProviderReceiptV1, SandboxProviderResultV1, SandboxReconcileRequestV1,
    SandboxReconcileResponseV1, SandboxSyscallSetV1, SignedImageManifestV1,
};
use pos_reference::sandbox_provider_protocol as independent;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

#[derive(Clone, Copy)]
enum Record {
    Spm1,
    Scs1,
    Lps1,
    Sim1,
    Sdq1,
    Sdy1,
    Scq1,
    Scy1,
    Srq1,
    Sry1,
    Sle1,
    Spx1,
    Sbc1,
    Agr1,
    Spy1,
    Spe1,
    Spr1,
}

impl Record {
    const ALL: [Self; 17] = [
        Self::Spm1,
        Self::Scs1,
        Self::Lps1,
        Self::Sim1,
        Self::Sdq1,
        Self::Sdy1,
        Self::Scq1,
        Self::Scy1,
        Self::Srq1,
        Self::Sry1,
        Self::Sle1,
        Self::Spx1,
        Self::Sbc1,
        Self::Agr1,
        Self::Spy1,
        Self::Spe1,
        Self::Spr1,
    ];

    const fn name(self) -> &'static str {
        match self {
            Self::Spm1 => "spm1",
            Self::Scs1 => "scs1",
            Self::Lps1 => "lps1",
            Self::Sim1 => "sim1",
            Self::Sdq1 => "sdq1",
            Self::Sdy1 => "sdy1",
            Self::Scq1 => "scq1",
            Self::Scy1 => "scy1",
            Self::Srq1 => "srq1",
            Self::Sry1 => "sry1",
            Self::Sle1 => "sle1",
            Self::Spx1 => "spx1",
            Self::Sbc1 => "sbc1",
            Self::Agr1 => "agr1",
            Self::Spy1 => "spy1",
            Self::Spe1 => "spe1",
            Self::Spr1 => "spr1",
        }
    }

    const fn is_digest_protected(self) -> bool {
        !matches!(self, Self::Sle1)
    }

    const fn bytes(self) -> &'static [u8] {
        match self {
            Self::Spm1 => include_bytes!("../vectors/sandbox-provider-v1/spm1.cbor"),
            Self::Scs1 => include_bytes!("../vectors/sandbox-provider-v1/scs1.cbor"),
            Self::Lps1 => include_bytes!("../vectors/sandbox-provider-v1/lps1.cbor"),
            Self::Sim1 => include_bytes!("../vectors/sandbox-provider-v1/sim1.cbor"),
            Self::Sdq1 => include_bytes!("../vectors/sandbox-provider-v1/sdq1.cbor"),
            Self::Sdy1 => include_bytes!("../vectors/sandbox-provider-v1/sdy1.cbor"),
            Self::Scq1 => include_bytes!("../vectors/sandbox-provider-v1/scq1.cbor"),
            Self::Scy1 => include_bytes!("../vectors/sandbox-provider-v1/scy1.cbor"),
            Self::Srq1 => include_bytes!("../vectors/sandbox-provider-v1/srq1.cbor"),
            Self::Sry1 => include_bytes!("../vectors/sandbox-provider-v1/sry1.cbor"),
            Self::Sle1 => include_bytes!("../vectors/sandbox-provider-v1/sle1.cbor"),
            Self::Spx1 => include_bytes!("../vectors/sandbox-provider-v1/spx1.cbor"),
            Self::Sbc1 => include_bytes!("../vectors/sandbox-provider-v1/sbc1.cbor"),
            Self::Agr1 => include_bytes!("../vectors/sandbox-provider-v1/agr1.cbor"),
            Self::Spy1 => include_bytes!("../vectors/sandbox-provider-v1/spy1.cbor"),
            Self::Spe1 => include_bytes!("../vectors/sandbox-provider-v1/spe1.cbor"),
            Self::Spr1 => include_bytes!("../vectors/sandbox-provider-v1/spr1.cbor"),
        }
    }

    fn producer_accepts(self, bytes: &[u8]) -> bool {
        match self {
            Self::Spm1 => SandboxProviderManifestV1::from_canonical_cbor(bytes).is_ok(),
            Self::Scs1 => SandboxSyscallSetV1::from_canonical_cbor(bytes).is_ok(),
            Self::Lps1 => LaunchPolicyV1::from_canonical_cbor(bytes).is_ok(),
            Self::Sim1 => SignedImageManifestV1::from_canonical_cbor(bytes).is_ok(),
            Self::Sdq1 => SandboxDescribeRequestV1::from_canonical_cbor(bytes).is_ok(),
            Self::Sdy1 => SandboxDescribeResponseV1::from_canonical_cbor(bytes).is_ok(),
            Self::Scq1 => SandboxCancelRequestV1::from_canonical_cbor(bytes).is_ok(),
            Self::Scy1 => SandboxCancelResponseV1::from_canonical_cbor(bytes).is_ok(),
            Self::Srq1 => SandboxReconcileRequestV1::from_canonical_cbor(bytes).is_ok(),
            Self::Sry1 => SandboxReconcileResponseV1::from_canonical_cbor(bytes).is_ok(),
            Self::Sle1 => SandboxLocalErrorV1::from_canonical_cbor(bytes).is_ok(),
            Self::Spx1 => SandboxExecuteRequestV1::from_canonical_cbor(bytes).is_ok(),
            Self::Sbc1 => SandboxPayloadChunkV1::from_canonical_cbor(bytes).is_ok(),
            Self::Agr1 => AdmissionGrantV1::from_canonical_cbor(bytes).is_ok(),
            Self::Spy1 => SandboxProviderResultV1::from_canonical_cbor(bytes).is_ok(),
            Self::Spe1 => SandboxProviderErrorV1::from_canonical_cbor(bytes).is_ok(),
            Self::Spr1 => SandboxProviderReceiptV1::from_canonical_cbor(bytes).is_ok(),
        }
    }

    fn independent_accepts(self, bytes: &[u8]) -> bool {
        match self {
            Self::Spm1 => independent::SandboxProviderManifest::from_canonical_cbor(bytes).is_ok(),
            Self::Scs1 => independent::SandboxSyscallSet::from_canonical_cbor(bytes).is_ok(),
            Self::Lps1 => independent::LaunchPolicy::from_canonical_cbor(bytes).is_ok(),
            Self::Sim1 => independent::SignedImageManifest::from_canonical_cbor(bytes).is_ok(),
            Self::Sdq1 => independent::SandboxDescribeRequest::from_canonical_cbor(bytes).is_ok(),
            Self::Sdy1 => independent::SandboxDescribeResponse::from_canonical_cbor(bytes).is_ok(),
            Self::Scq1 => independent::SandboxCancelRequest::from_canonical_cbor(bytes).is_ok(),
            Self::Scy1 => independent::SandboxCancelResponse::from_canonical_cbor(bytes).is_ok(),
            Self::Srq1 => independent::SandboxReconcileRequest::from_canonical_cbor(bytes).is_ok(),
            Self::Sry1 => independent::SandboxReconcileResponse::from_canonical_cbor(bytes).is_ok(),
            Self::Sle1 => independent::SandboxLocalError::from_canonical_cbor(bytes).is_ok(),
            Self::Spx1 => independent::SandboxExecuteRequest::from_canonical_cbor(bytes).is_ok(),
            Self::Sbc1 => independent::SandboxPayloadChunk::from_canonical_cbor(bytes).is_ok(),
            Self::Agr1 => independent::AdmissionGrant::from_canonical_cbor(bytes).is_ok(),
            Self::Spy1 => independent::SandboxProviderResult::from_canonical_cbor(bytes).is_ok(),
            Self::Spe1 => independent::SandboxProviderError::from_canonical_cbor(bytes).is_ok(),
            Self::Spr1 => independent::SandboxProviderReceipt::from_canonical_cbor(bytes).is_ok(),
        }
    }
}

fn decode_value(bytes: &[u8]) -> Result<Value, ciborium::de::Error<std::io::Error>> {
    ciborium::from_reader(bytes)
}

fn encode_value(value: &Value) -> TestResult<Vec<u8>> {
    let mut bytes = Vec::new();
    ciborium::into_writer(value, &mut bytes)?;
    Ok(bytes)
}

fn digest_with_domain(domain: &[u8], unsigned_bytes: &[u8]) -> [u8; 32] {
    let mut preimage = Vec::with_capacity(domain.len() + unsigned_bytes.len());
    preimage.extend_from_slice(domain);
    preimage.extend_from_slice(unsigned_bytes);
    *blake3::hash(&preimage).as_bytes()
}

fn contract_digest(magic: &str, unsigned_bytes: &[u8]) -> [u8; 32] {
    let mut domain = Vec::with_capacity(magic.len() + 13);
    domain.extend_from_slice(b"PiglorOS.");
    domain.extend_from_slice(magic.as_bytes());
    domain.extend_from_slice(b".v1\0");
    digest_with_domain(&domain, unsigned_bytes)
}

fn network_plan_digest(unsigned_bytes: &[u8]) -> [u8; 32] {
    digest_with_domain(b"PiglorOS.NetworkExchangePlan.v1\0", unsigned_bytes)
}

fn refresh_record_digest(value: &mut Value, magic: &str) -> TestResult {
    let Value::Array(wrapper) = value else {
        return Err("record wrapper must be an array".into());
    };
    let unsigned = wrapper.first().ok_or("record must have an unsigned body")?;
    let unsigned_bytes = encode_value(unsigned)?;
    *wrapper.get_mut(1).ok_or("record must have a digest")? =
        Value::Bytes(contract_digest(magic, &unsigned_bytes).to_vec());
    Ok(())
}

fn refresh_network_plan_digest(value: &mut Value) -> TestResult {
    let Value::Array(fields) = value else {
        return Err("inline record must be an array".into());
    };
    let digest_index = fields
        .len()
        .checked_sub(1)
        .ok_or("inline record is empty")?;
    let unsigned_bytes = encode_value(&Value::Array(fields[..digest_index].to_vec()))?;
    fields[digest_index] = Value::Bytes(network_plan_digest(&unsigned_bytes).to_vec());
    Ok(())
}

fn collect_paths(value: &Value, arrays: &mut Vec<Vec<usize>>, scalars: &mut Vec<Vec<usize>>) {
    fn visit(
        value: &Value,
        path: &mut Vec<usize>,
        arrays: &mut Vec<Vec<usize>>,
        scalars: &mut Vec<Vec<usize>>,
    ) {
        if let Value::Array(values) = value {
            arrays.push(path.clone());
            for (index, child) in values.iter().enumerate() {
                path.push(index);
                visit(child, path, arrays, scalars);
                path.pop();
            }
        } else {
            scalars.push(path.clone());
        }
    }

    visit(value, &mut Vec::new(), arrays, scalars);
}

fn value_at_mut<'a>(value: &'a mut Value, path: &[usize]) -> Option<&'a mut Value> {
    let mut current = value;
    for index in path {
        let Value::Array(values) = current else {
            return None;
        };
        current = values.get_mut(*index)?;
    }
    Some(current)
}

fn scalar_replacements(value: &Value) -> Vec<Value> {
    match value {
        Value::Integer(_) => (0_u64..=18)
            .chain([u64::MAX])
            .map(|value| Value::Integer(value.into()))
            .chain([Value::Text("not-an-integer".to_owned())])
            .collect(),
        Value::Bytes(_) => [0, 1, 15, 16, 31, 32, 33, 64, 65]
            .map(|length| Value::Bytes(vec![0; length]))
            .into_iter()
            .chain([Value::Text("not-bytes".to_owned())])
            .collect(),
        Value::Text(_) => [
            Value::Text(String::new()),
            Value::Text("x".repeat(129)),
            Value::Text("x".repeat(256)),
            Value::Bytes(vec![0]),
        ]
        .into(),
        Value::Bool(value) => vec![Value::Bool(!value), Value::Null],
        Value::Null => vec![Value::Bool(false), Value::Integer(0.into())],
        _ => vec![Value::Null],
    }
}

fn assert_rejected(record: Record, value: &Value, mutation: &str) -> TestResult {
    let bytes = encode_value(value)?;
    let producer = record.producer_accepts(&bytes);
    let independent = record.independent_accepts(&bytes);
    assert_eq!(
        producer,
        independent,
        "{} decoders disagree for {mutation}",
        record.name()
    );
    assert!(!producer, "{} accepted {mutation}", record.name());
    Ok(())
}

#[test]
fn digest_protected_decoders_reject_every_scalar_mutation() -> TestResult {
    let mut exercised = 0_usize;
    for record in Record::ALL
        .into_iter()
        .filter(|record| record.is_digest_protected())
    {
        let original = decode_value(record.bytes())?;
        let mut arrays = Vec::new();
        let mut scalars = Vec::new();
        collect_paths(&original, &mut arrays, &mut scalars);
        for path in scalars {
            let mut scalar_source = original.clone();
            let original_scalar = value_at_mut(&mut scalar_source, &path)
                .ok_or("collected scalar path must resolve")?
                .clone();
            for replacement in scalar_replacements(&original_scalar) {
                if replacement == original_scalar {
                    continue;
                }
                let mut mutated = original.clone();
                *value_at_mut(&mut mutated, &path).ok_or("collected scalar path must resolve")? =
                    replacement;
                assert_rejected(record, &mutated, &format!("scalar path {path:?}"))?;
                exercised += 1;
            }
        }
    }
    assert!(exercised > 2_000, "mutation matrix unexpectedly narrowed");
    Ok(())
}

#[test]
fn unsigned_local_error_rejects_only_invalid_scalar_boundaries() -> TestResult {
    let record = Record::Sle1;
    let original = decode_value(record.bytes())?;
    let invalid_fields = [
        (vec![0], vec![Value::Text("not-sle1".to_owned())]),
        (
            vec![1],
            vec![Value::Integer(0.into()), Value::Integer(2.into())],
        ),
        (
            vec![2],
            vec![Value::Integer(4.into()), Value::Text("execute".to_owned())],
        ),
        (
            vec![3],
            vec![
                Value::Bytes(vec![0; 15]),
                Value::Bytes(vec![0; 16]),
                Value::Text("request-id".to_owned()),
            ],
        ),
        (
            vec![4],
            vec![Value::Integer(4.into()), Value::Text("failure".to_owned())],
        ),
        (
            vec![5],
            vec![
                Value::Text(String::new()),
                Value::Text("x".repeat(257)),
                Value::Bytes(vec![0]),
            ],
        ),
    ];
    for (path, replacements) in invalid_fields {
        for replacement in replacements {
            let mut mutated = original.clone();
            *value_at_mut(&mut mutated, &path).ok_or("SLE1 field path must resolve")? = replacement;
            assert_rejected(record, &mutated, &format!("invalid SLE1 field {path:?}"))?;
        }
    }

    let mut nullable = original;
    for path in [[2_usize], [3], [5]] {
        *value_at_mut(&mut nullable, &path).ok_or("SLE1 nullable field path must resolve")? =
            Value::Null;
    }
    let nullable_bytes = encode_value(&nullable)?;
    assert!(record.producer_accepts(&nullable_bytes));
    assert!(record.independent_accepts(&nullable_bytes));
    Ok(())
}

#[test]
fn local_error_decoders_reject_nul_safe_detail() -> TestResult {
    let record = Record::Sle1;
    let mut value = decode_value(record.bytes())?;
    *value_at_mut(&mut value, &[5]).ok_or("SLE1 safe-detail path must resolve")? =
        Value::Text("unsafe\0detail".to_owned());
    assert_rejected(record, &value, "NUL safe detail")
}

#[test]
fn safe_detail_decoders_reject_malformed_utf8() -> TestResult {
    for (record, path, magic) in [
        (Record::Sle1, vec![5], None),
        (Record::Spe1, vec![0, 7], Some("SPE1")),
    ] {
        let mut value = decode_value(record.bytes())?;
        *value_at_mut(&mut value, &path).ok_or("safe-detail path must resolve")? =
            Value::Text("x".to_owned());
        if let Some(magic) = magic {
            refresh_record_digest(&mut value, magic)?;
        }
        let mut bytes = encode_value(&value)?;
        let marker = if magic.is_some() {
            &[0x61, b'x', 0x6b][..]
        } else {
            &[0x61, b'x'][..]
        };
        let text_start = bytes
            .windows(marker.len())
            .position(|window| window == marker)
            .ok_or("one-byte safe detail must be encoded")?;
        bytes[text_start + 1] = 0xff;
        assert!(!record.producer_accepts(&bytes));
        assert!(!record.independent_accepts(&bytes));
    }
    Ok(())
}

#[test]
fn image_manifest_decoders_reject_nul_fixed_arguments() -> TestResult {
    let record = Record::Sim1;
    let mut value = decode_value(record.bytes())?;
    *value_at_mut(&mut value, &[0, 17, 0]).ok_or("SIM1 first argument path must resolve")? =
        Value::Text("--mode=local\0ignored".to_owned());
    assert_rejected(record, &value, "NUL fixed argument")
}

#[test]
fn producer_and_independent_decoders_reject_every_array_boundary_mutation() -> TestResult {
    let mut exercised = 0_usize;
    for record in Record::ALL {
        let original = decode_value(record.bytes())?;
        let mut arrays = Vec::new();
        let mut scalars = Vec::new();
        collect_paths(&original, &mut arrays, &mut scalars);
        for path in arrays {
            let mut array_source = original.clone();
            let original_values = match value_at_mut(&mut array_source, &path)
                .ok_or("collected array path must resolve")?
            {
                Value::Array(values) => values.clone(),
                _ => return Err("collected array path must resolve to an array".into()),
            };
            let mut longer = original.clone();
            let Some(Value::Array(values)) = value_at_mut(&mut longer, &path) else {
                return Err("collected array path must resolve to an array".into());
            };
            values.push(Value::Null);
            assert_rejected(record, &longer, &format!("long array path {path:?}"))?;
            exercised += 1;

            if !original_values.is_empty() {
                let mut shorter = original.clone();
                let Some(Value::Array(values)) = value_at_mut(&mut shorter, &path) else {
                    return Err("collected array path must resolve to an array".into());
                };
                values.pop();
                assert_rejected(record, &shorter, &format!("short array path {path:?}"))?;
                exercised += 1;
            }

            let mut wrong_type = original.clone();
            *value_at_mut(&mut wrong_type, &path).ok_or("collected array path must resolve")? =
                Value::Null;
            assert_rejected(
                record,
                &wrong_type,
                &format!("non-array at array path {path:?}"),
            )?;
            exercised += 1;
        }
    }
    assert!(
        exercised > 100,
        "array mutation matrix unexpectedly narrowed"
    );
    Ok(())
}

#[test]
fn every_decoder_rejects_non_record_and_trailing_frames() -> TestResult {
    let oversized = vec![0_u8; 16 * 1024 * 1024 + 1];
    let mut too_deep = vec![0x81; 34];
    too_deep.push(0xf6);
    for record in Record::ALL {
        for value in [
            Value::Null,
            Value::Map(Vec::new()),
            Value::Tag(1, Box::new(Value::Null)),
            Value::Float(1.5),
        ] {
            assert_rejected(record, &value, "non-record top-level value")?;
        }
        for bytes in [
            Vec::new(),
            vec![0x9f, 0xff],
            vec![0x81, 0x18, 0x01],
            vec![0x99, 0x01, 0x01],
            too_deep.clone(),
            {
                let mut trailing = record.bytes().to_vec();
                trailing.push(0);
                trailing
            },
        ] {
            assert!(!record.producer_accepts(&bytes));
            assert!(!record.independent_accepts(&bytes));
        }
        assert!(!record.producer_accepts(&oversized));
        assert!(!record.independent_accepts(&oversized));
    }
    Ok(())
}

#[test]
fn independent_preflight_accepts_the_four_byte_length_form_before_shape_rejection() {
    let mut bytes = vec![0x5a, 0x00, 0x01, 0x00, 0x00];
    bytes.resize(5 + 65_536, 0);
    assert!(independent::LaunchPolicy::from_canonical_cbor(&bytes).is_err());
}

#[test]
fn decoders_reject_semantically_invalid_self_digested_collections() -> TestResult {
    for (path, replacement, name) in [
        (
            vec![0, 3, 0],
            Value::Text("Execveat".to_owned()),
            "invalid syscall name",
        ),
        (
            vec![0, 3, 1],
            Value::Text("execveat".to_owned()),
            "duplicate syscall name",
        ),
        (
            vec![0, 4],
            Value::Array(vec![Value::Text("write".to_owned())]),
            "requested syscall absent from expected set",
        ),
        (
            vec![0, 3],
            Value::Array(
                (0..513)
                    .map(|index| Value::Text(format!("syscall_{index:03}")))
                    .collect(),
            ),
            "too many requested syscall names",
        ),
    ] {
        let mut scs1 = decode_value(Record::Scs1.bytes())?;
        *value_at_mut(&mut scs1, &path).ok_or("SCS1 field path must resolve")? = replacement;
        refresh_record_digest(&mut scs1, "SCS1")?;
        assert_rejected(Record::Scs1, &scs1, name)?;
    }

    let mut legacy_scs1 = decode_value(Record::Scs1.bytes())?;
    let unsigned = value_at_mut(&mut legacy_scs1, &[0]).ok_or("SCS1 body must exist")?;
    let Value::Array(unsigned) = unsigned else {
        return Err("SCS1 body must be an array".into());
    };
    unsigned.remove(2);
    refresh_record_digest(&mut legacy_scs1, "SCS1")?;
    assert_rejected(Record::Scs1, &legacy_scs1, "legacy four-field SCS1")?;

    let mut lps1 = decode_value(Record::Lps1.bytes())?;
    let network =
        value_at_mut(&mut lps1, &[0, 6]).ok_or("LPS1 network capability list must exist")?;
    let Value::Array(network) = network else {
        return Err("LPS1 network capabilities must be an array".into());
    };
    let duplicate = network
        .first()
        .ok_or("LPS1 vector must have a capability")?
        .clone();
    network.push(duplicate);
    refresh_record_digest(&mut lps1, "LPS1")?;
    assert_rejected(Record::Lps1, &lps1, "duplicate network capability")?;

    let mut spx1 = decode_value(Record::Spx1.bytes())?;
    let capabilities =
        value_at_mut(&mut spx1, &[0, 19]).ok_or("SPX1 capability list must exist")?;
    let Value::Array(capabilities) = capabilities else {
        return Err("SPX1 capabilities must be an array".into());
    };
    let duplicate = capabilities
        .first()
        .ok_or("SPX1 vector must have a capability")?
        .clone();
    capabilities.push(duplicate);
    refresh_record_digest(&mut spx1, "SPX1")?;
    assert_rejected(Record::Spx1, &spx1, "duplicate capability identifier")?;

    let mut occurrence_gap = decode_value(Record::Spx1.bytes())?;
    *value_at_mut(&mut occurrence_gap, &[0, 21, 1, 3])
        .ok_or("second NXP1 occurrence must exist")? = Value::Integer(0.into());
    let nested =
        value_at_mut(&mut occurrence_gap, &[0, 21, 1]).ok_or("second NXP1 record must exist")?;
    refresh_network_plan_digest(nested)?;
    refresh_record_digest(&mut occurrence_gap, "SPX1")?;
    assert_rejected(
        Record::Spx1,
        &occurrence_gap,
        "repeated exchange occurrence",
    )?;
    Ok(())
}

#[test]
fn decoders_reject_wrong_directional_digest_for_empty_payloads() -> TestResult {
    for (record, descriptor_path, magic) in [
        (Record::Spx1, [0, 20], "SPX1"),
        (Record::Spy1, [0, 5], "SPY1"),
    ] {
        let mut value = decode_value(record.bytes())?;
        let descriptor =
            value_at_mut(&mut value, &descriptor_path).ok_or("payload descriptor must exist")?;
        let Value::Array(fields) = descriptor else {
            return Err("payload descriptor must be an array".into());
        };
        fields[0] = Value::Integer(0.into());
        fields[1] = Value::Bytes(vec![0; 32]);
        refresh_record_digest(&mut value, magic)?;
        assert_rejected(record, &value, "wrong digest for empty payload")?;
    }
    Ok(())
}

#[test]
fn signed_error_decoders_reject_nul_detail_and_orphaned_digest() -> TestResult {
    for (path, replacement, name) in [
        (
            vec![0, 7],
            Value::Text("unsafe\0detail".to_owned()),
            "NUL-containing safe detail",
        ),
        (
            vec![0, 3],
            Value::Null,
            "request digest without request identity",
        ),
    ] {
        let mut spe1 = decode_value(Record::Spe1.bytes())?;
        *value_at_mut(&mut spe1, &path).ok_or("SPE1 field must exist")? = replacement;
        refresh_record_digest(&mut spe1, "SPE1")?;
        assert_rejected(Record::Spe1, &spe1, name)?;
    }
    Ok(())
}
