use ciborium::value::Value;
use pos_conformance::{
    AdmissionGrantV1, LaunchPolicyV1, SandboxCancelRequestV1, SandboxCancelResponseV1,
    SandboxDescribeRequestV1, SandboxDescribeResponseV1, SandboxExecuteRequestV1,
    SandboxLocalErrorV1, SandboxProviderErrorV1, SandboxProviderManifestV1,
    SandboxProviderReceiptV1, SandboxProviderResultV1, SandboxReconcileRequestV1,
    SandboxReconcileResponseV1, SignedImageManifestV1,
};
use pos_reference::sandbox_provider_protocol as independent;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

#[derive(Clone, Copy)]
enum Record {
    Spm1,
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
    Agr1,
    Spy1,
    Spe1,
    Spr1,
}

impl Record {
    const ALL: [Self; 15] = [
        Self::Spm1,
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
        Self::Agr1,
        Self::Spy1,
        Self::Spe1,
        Self::Spr1,
    ];

    const fn name(self) -> &'static str {
        match self {
            Self::Spm1 => "spm1",
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
            Self::Agr1 => "agr1",
            Self::Spy1 => "spy1",
            Self::Spe1 => "spe1",
            Self::Spr1 => "spr1",
        }
    }

    const fn bytes(self) -> &'static [u8] {
        match self {
            Self::Spm1 => include_bytes!("../vectors/sandbox-provider-v1/spm1.cbor"),
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
            Self::Agr1 => include_bytes!("../vectors/sandbox-provider-v1/agr1.cbor"),
            Self::Spy1 => include_bytes!("../vectors/sandbox-provider-v1/spy1.cbor"),
            Self::Spe1 => include_bytes!("../vectors/sandbox-provider-v1/spe1.cbor"),
            Self::Spr1 => include_bytes!("../vectors/sandbox-provider-v1/spr1.cbor"),
        }
    }

    fn producer_accepts(self, bytes: &[u8]) -> bool {
        match self {
            Self::Spm1 => SandboxProviderManifestV1::from_canonical_cbor(bytes).is_ok(),
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
            Self::Agr1 => AdmissionGrantV1::from_canonical_cbor(bytes).is_ok(),
            Self::Spy1 => SandboxProviderResultV1::from_canonical_cbor(bytes).is_ok(),
            Self::Spe1 => SandboxProviderErrorV1::from_canonical_cbor(bytes).is_ok(),
            Self::Spr1 => SandboxProviderReceiptV1::from_canonical_cbor(bytes).is_ok(),
        }
    }

    fn independent_accepts(self, bytes: &[u8]) -> bool {
        match self {
            Self::Spm1 => independent::SandboxProviderManifest::from_canonical_cbor(bytes).is_ok(),
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
        Value::Integer(_) => (0_u64..=17)
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
fn producer_and_independent_decoders_reject_every_scalar_mutation() -> TestResult {
    let mut exercised = 0_usize;
    for record in Record::ALL {
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
    for record in Record::ALL {
        for value in [
            Value::Null,
            Value::Map(Vec::new()),
            Value::Tag(1, Box::new(Value::Null)),
            Value::Float(1.5),
        ] {
            assert_rejected(record, &value, "non-record top-level value")?;
        }
        for bytes in [Vec::new(), {
            let mut trailing = record.bytes().to_vec();
            trailing.push(0);
            trailing
        }] {
            assert!(!record.producer_accepts(&bytes));
            assert!(!record.independent_accepts(&bytes));
        }
    }
    Ok(())
}
