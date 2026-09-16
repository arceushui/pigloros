use ciborium::value::Value;
use pos_conformance::{
    draft_trust_policy_snapshot_bytes_v1, MinimumArtifactVersionV1, TrustPolicyRootV1,
    TrustPolicySnapshotContractErrorV1 as SnapshotError, TrustPolicySnapshotV1,
    MAX_TRUST_POLICY_SNAPSHOT_BYTES_V1,
};
use std::io::Cursor;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const FIELD_TRUST_ROOTS: usize = 5;
const FIELD_REVOKED_KEYS: usize = 6;
const FIELD_REVOKED_ARTIFACTS: usize = 7;
const FIELD_MINIMUM_VERSIONS: usize = 8;

fn draft_snapshot() -> TestResult<(Vec<u8>, TrustPolicySnapshotV1)> {
    let bytes = draft_trust_policy_snapshot_bytes_v1()?;
    let snapshot = TrustPolicySnapshotV1::from_canonical_cbor(&bytes)?;
    Ok((bytes, snapshot))
}

fn encode(value: &Value) -> TestResult<Vec<u8>> {
    let mut bytes = Vec::new();
    ciborium::into_writer(value, &mut bytes)?;
    Ok(bytes)
}

fn draft_value() -> TestResult<Value> {
    let (bytes, _) = draft_snapshot()?;
    Ok(ciborium::from_reader(Cursor::new(bytes))?)
}

fn draft_bytes_with_field(field_index: usize, value: Value) -> TestResult<Vec<u8>> {
    let Value::Array(mut fields) = draft_value()? else {
        return Err("Draft TPS1 must be an array".into());
    };
    fields[field_index] = value;
    encode(&Value::Array(fields))
}

fn encoded_root(key_id: &str, public_key_seed: u8) -> Value {
    Value::Array(vec![
        Value::Text(key_id.to_owned()),
        Value::Integer(1_u64.into()),
        Value::Text("Ed25519".to_owned()),
        Value::Bytes(vec![public_key_seed; 32]),
    ])
}

fn encoded_minimum_version(kind: &str, version: &str) -> Value {
    Value::Array(vec![
        Value::Text(kind.to_owned()),
        Value::Text(version.to_owned()),
    ])
}

#[test]
fn public_codec_preserves_draft_tps1_bytes_and_hashes_the_complete_signed_record() -> TestResult {
    let (draft_bytes, mut snapshot) = draft_snapshot()?;
    assert_eq!(snapshot.policy_id, "pigloros.fixture.conformance-draft");
    assert_eq!(snapshot.epoch, 1);
    assert_eq!(snapshot.effective_timeline_position, 0);
    assert_eq!(snapshot.trust_roots.len(), 1);
    assert!(snapshot.revoked_key_ids.is_empty());
    assert!(snapshot.revoked_artifact_digests.is_empty());
    assert!(!snapshot.minimum_versions.is_empty());
    assert!(snapshot.previous_snapshot_digest.is_none());
    assert_eq!(snapshot.to_canonical_cbor()?, draft_bytes);
    assert_eq!(snapshot.digest()?, *blake3::hash(&draft_bytes).as_bytes());

    let mut chained_snapshot = snapshot.clone();
    chained_snapshot.previous_snapshot_digest = Some([0x5a; 32]);
    let chained_bytes = chained_snapshot.to_canonical_cbor()?;
    assert_eq!(
        TrustPolicySnapshotV1::from_canonical_cbor(&chained_bytes)?,
        chained_snapshot
    );

    let original_digest = snapshot.digest()?;
    snapshot.operator_signature[0] ^= 1;
    assert!(snapshot.validate().is_ok());
    assert_ne!(snapshot.digest()?, original_digest);
    Ok(())
}

#[test]
fn public_contract_accepts_every_declared_list_bound() -> TestResult {
    let (_, mut snapshot) = draft_snapshot()?;
    snapshot.trust_roots = (0_u8..64)
        .map(|index| TrustPolicyRootV1 {
            key_id: format!("root-{index:03}"),
            root_version: 1,
            algorithm: "Ed25519".to_owned(),
            public_key: [index; 32],
        })
        .collect();
    snapshot.revoked_key_ids = (0..4_096)
        .map(|index| format!("revoked-{index:04}"))
        .collect();
    snapshot.revoked_artifact_digests = (0_u16..4_096)
        .map(|index| {
            let mut digest = [0; 32];
            digest[..2].copy_from_slice(&index.to_be_bytes());
            digest
        })
        .collect();
    snapshot.minimum_versions = (0..256)
        .map(|index| MinimumArtifactVersionV1 {
            artifact_kind: format!("kind-{index:03}"),
            semantic_version: "1.2.3".to_owned(),
        })
        .collect();

    let encoded = snapshot.to_canonical_cbor()?;
    assert!(encoded.len() <= MAX_TRUST_POLICY_SNAPSHOT_BYTES_V1);
    assert_eq!(
        TrustPolicySnapshotV1::from_canonical_cbor(&encoded)?,
        snapshot
    );
    Ok(())
}

fn assert_oversized_typed_lists(snapshot: &TrustPolicySnapshotV1) {
    let mut oversized_roots = snapshot.clone();
    oversized_roots.trust_roots = (0_u8..65)
        .map(|index| TrustPolicyRootV1 {
            key_id: format!("root-{index:03}"),
            root_version: 1,
            algorithm: "Ed25519".to_owned(),
            public_key: [index; 32],
        })
        .collect();
    assert_eq!(
        oversized_roots.validate(),
        Err(SnapshotError::FieldOutOfBounds)
    );

    let mut oversized_keys = snapshot.clone();
    oversized_keys.revoked_key_ids = (0..4_097)
        .map(|index| format!("revoked-{index:04}"))
        .collect();
    assert_eq!(
        oversized_keys.validate(),
        Err(SnapshotError::FieldOutOfBounds)
    );

    let mut oversized_artifacts = snapshot.clone();
    oversized_artifacts.revoked_artifact_digests = (0_u32..4_097)
        .map(|index| {
            let mut digest = [0; 32];
            digest[..4].copy_from_slice(&index.to_be_bytes());
            digest
        })
        .collect();
    assert_eq!(
        oversized_artifacts.validate(),
        Err(SnapshotError::FieldOutOfBounds)
    );

    let mut oversized_versions = snapshot.clone();
    oversized_versions.minimum_versions = (0..257)
        .map(|index| MinimumArtifactVersionV1 {
            artifact_kind: format!("kind-{index:03}"),
            semantic_version: "1.2.3".to_owned(),
        })
        .collect();
    assert_eq!(
        oversized_versions.validate(),
        Err(SnapshotError::FieldOutOfBounds)
    );
}

fn assert_oversized_encoded_lists() -> TestResult {
    let oversized_roots = Value::Array(
        (0_u8..65)
            .map(|index| encoded_root(&format!("root-{index:03}"), index))
            .collect(),
    );
    assert_eq!(
        TrustPolicySnapshotV1::from_canonical_cbor(&draft_bytes_with_field(
            FIELD_TRUST_ROOTS,
            oversized_roots,
        )?)
        .map(|_| ()),
        Err(SnapshotError::FieldOutOfBounds)
    );

    let oversized_keys = Value::Array(
        (0..4_097)
            .map(|index| Value::Text(format!("key-{index:04}")))
            .collect(),
    );
    assert_eq!(
        TrustPolicySnapshotV1::from_canonical_cbor(&draft_bytes_with_field(
            FIELD_REVOKED_KEYS,
            oversized_keys,
        )?)
        .map(|_| ()),
        Err(SnapshotError::FieldOutOfBounds)
    );

    let oversized_artifacts = Value::Array(
        (0_u16..4_097)
            .map(|index| {
                let mut digest = [0; 32];
                digest[..2].copy_from_slice(&index.to_be_bytes());
                Value::Bytes(digest.to_vec())
            })
            .collect(),
    );
    assert_eq!(
        TrustPolicySnapshotV1::from_canonical_cbor(&draft_bytes_with_field(
            FIELD_REVOKED_ARTIFACTS,
            oversized_artifacts
        )?)
        .map(|_| ()),
        Err(SnapshotError::FieldOutOfBounds)
    );

    let oversized_versions = Value::Array(
        (0..257)
            .map(|index| encoded_minimum_version(&format!("kind-{index:03}"), "1.2.3"))
            .collect(),
    );
    assert_eq!(
        TrustPolicySnapshotV1::from_canonical_cbor(&draft_bytes_with_field(
            FIELD_MINIMUM_VERSIONS,
            oversized_versions,
        )?)
        .map(|_| ()),
        Err(SnapshotError::FieldOutOfBounds)
    );

    let too_many_items = Value::Array(vec![Value::Null; 4_098]);
    assert_eq!(
        TrustPolicySnapshotV1::from_canonical_cbor(&draft_bytes_with_field(
            FIELD_REVOKED_KEYS,
            too_many_items,
        )?)
        .map(|_| ()),
        Err(SnapshotError::FieldOutOfBounds)
    );
    Ok(())
}

#[test]
fn public_contract_rejects_each_list_above_its_bound() -> TestResult {
    let (_, snapshot) = draft_snapshot()?;
    assert_oversized_typed_lists(&snapshot);
    assert_oversized_encoded_lists()?;
    Ok(())
}

#[test]
fn public_codec_rejects_unknown_missing_trailing_and_noncanonical_bytes() -> TestResult {
    let (draft_bytes, _) = draft_snapshot()?;
    let value = draft_value()?;
    let Value::Array(mut fields) = value else {
        return Err("Draft TPS1 must be an array".into());
    };

    fields.push(Value::Null);
    assert_eq!(
        TrustPolicySnapshotV1::from_canonical_cbor(&encode(&Value::Array(fields))?),
        Err(SnapshotError::InvalidEncoding)
    );

    let Value::Array(mut fields) = draft_value()? else {
        return Err("Draft TPS1 must be an array".into());
    };
    fields.pop();
    assert_eq!(
        TrustPolicySnapshotV1::from_canonical_cbor(&encode(&Value::Array(fields))?),
        Err(SnapshotError::InvalidEncoding)
    );

    let mut trailing = draft_bytes.clone();
    trailing.push(0xf6);
    assert_eq!(
        TrustPolicySnapshotV1::from_canonical_cbor(&trailing),
        Err(SnapshotError::InvalidEncoding)
    );

    let mut indefinite = draft_bytes.clone();
    indefinite[0] = 0x9f;
    indefinite.push(0xff);
    assert_eq!(
        TrustPolicySnapshotV1::from_canonical_cbor(&indefinite),
        Err(SnapshotError::InvalidEncoding)
    );

    let mut nonminimal_integer = draft_bytes.clone();
    assert_eq!(nonminimal_integer[6], 1);
    nonminimal_integer.splice(6..7, [0x18, 0x01]);
    assert_eq!(
        TrustPolicySnapshotV1::from_canonical_cbor(&nonminimal_integer),
        Err(SnapshotError::InvalidEncoding)
    );

    let mut invalid_utf8 = draft_bytes;
    let (_, snapshot) = draft_snapshot()?;
    let policy_id_offset = invalid_utf8
        .windows(snapshot.policy_id.len())
        .position(|window| window == snapshot.policy_id.as_bytes())
        .ok_or("TPS1 policy identifier is absent from its encoded record")?;
    invalid_utf8[policy_id_offset] = 0xff;
    assert_eq!(
        TrustPolicySnapshotV1::from_canonical_cbor(&invalid_utf8),
        Err(SnapshotError::InvalidEncoding)
    );

    assert_eq!(
        TrustPolicySnapshotV1::from_canonical_cbor(&vec![
            0;
            MAX_TRUST_POLICY_SNAPSHOT_BYTES_V1 + 1
        ]),
        Err(SnapshotError::FieldOutOfBounds)
    );
    Ok(())
}

#[test]
fn public_codec_rejects_unsupported_magic_and_version() -> TestResult {
    for field in 0..2 {
        let Value::Array(mut fields) = draft_value()? else {
            return Err("Draft TPS1 must be an array".into());
        };
        fields[field] = if field == 0 {
            Value::Text("TPS2".to_owned())
        } else {
            Value::Integer(2_u64.into())
        };
        assert_eq!(
            TrustPolicySnapshotV1::from_canonical_cbor(&encode(&Value::Array(fields))?),
            Err(SnapshotError::UnsupportedSchemaVersion)
        );
    }
    Ok(())
}

#[test]
fn public_codec_rejects_malformed_top_level_fields() -> TestResult {
    for (index, value) in [
        (0, Value::Null),
        (1, Value::Text("one".to_owned())),
        (2, Value::Null),
        (3, Value::Text("one".to_owned())),
        (4, Value::Null),
        (5, Value::Null),
        (6, Value::Null),
        (7, Value::Null),
        (8, Value::Null),
        (9, Value::Null),
        (10, Value::Bool(false)),
        (11, Value::Bytes(vec![7; 63])),
    ] {
        let Value::Array(mut fields) = draft_value()? else {
            return Err("Draft TPS1 must be an array".into());
        };
        fields[index] = value;
        assert_eq!(
            TrustPolicySnapshotV1::from_canonical_cbor(&encode(&Value::Array(fields))?),
            Err(SnapshotError::InvalidEncoding),
            "field {index}"
        );
    }

    let Value::Array(mut fields) = draft_value()? else {
        return Err("Draft TPS1 must be an array".into());
    };
    fields[3] = Value::Integer((-1_i64).into());
    assert_eq!(
        TrustPolicySnapshotV1::from_canonical_cbor(&encode(&Value::Array(fields))?),
        Err(SnapshotError::InvalidEncoding)
    );

    let Value::Array(mut fields) = draft_value()? else {
        return Err("Draft TPS1 must be an array".into());
    };
    fields[FIELD_TRUST_ROOTS] =
        Value::Array(vec![Value::Array(vec![Value::Text("short".to_owned())])]);
    assert_eq!(
        TrustPolicySnapshotV1::from_canonical_cbor(&encode(&Value::Array(fields))?),
        Err(SnapshotError::InvalidEncoding)
    );

    Ok(())
}

#[test]
fn public_codec_rejects_malformed_root_entries() -> TestResult {
    for root in [
        Value::Array(vec![
            Value::Null,
            Value::Integer(1_u64.into()),
            Value::Text("Ed25519".to_owned()),
            Value::Bytes(vec![1; 32]),
        ]),
        Value::Array(vec![
            Value::Text("root".to_owned()),
            Value::Text("one".to_owned()),
            Value::Text("Ed25519".to_owned()),
            Value::Bytes(vec![1; 32]),
        ]),
        Value::Array(vec![
            Value::Text("root".to_owned()),
            Value::Integer(1_u64.into()),
            Value::Null,
            Value::Bytes(vec![1; 32]),
        ]),
        Value::Array(vec![
            Value::Text("root".to_owned()),
            Value::Integer(1_u64.into()),
            Value::Text("Ed25519".to_owned()),
            Value::Bytes(vec![1; 31]),
        ]),
    ] {
        assert_eq!(
            TrustPolicySnapshotV1::from_canonical_cbor(&draft_bytes_with_field(
                FIELD_TRUST_ROOTS,
                Value::Array(vec![root]),
            )?),
            Err(SnapshotError::InvalidEncoding)
        );
    }

    Ok(())
}

#[test]
fn public_codec_rejects_malformed_artifact_entries() -> TestResult {
    let Value::Array(mut fields) = draft_value()? else {
        return Err("Draft TPS1 must be an array".into());
    };
    fields[FIELD_MINIMUM_VERSIONS] =
        Value::Array(vec![Value::Array(vec![Value::Text("kind".to_owned())])]);
    assert_eq!(
        TrustPolicySnapshotV1::from_canonical_cbor(&encode(&Value::Array(fields))?),
        Err(SnapshotError::InvalidEncoding)
    );

    for version in [
        Value::Array(vec![Value::Null, Value::Text("1.0.0".to_owned())]),
        Value::Array(vec![Value::Text("kind".to_owned()), Value::Null]),
    ] {
        assert_eq!(
            TrustPolicySnapshotV1::from_canonical_cbor(&draft_bytes_with_field(
                FIELD_MINIMUM_VERSIONS,
                Value::Array(vec![version]),
            )?),
            Err(SnapshotError::InvalidEncoding)
        );
    }

    let Value::Array(mut fields) = draft_value()? else {
        return Err("Draft TPS1 must be an array".into());
    };
    fields[FIELD_REVOKED_ARTIFACTS] = Value::Array(vec![Value::Bytes(vec![8; 31])]);
    assert_eq!(
        TrustPolicySnapshotV1::from_canonical_cbor(&encode(&Value::Array(fields))?),
        Err(SnapshotError::InvalidEncoding)
    );
    Ok(())
}

#[test]
fn public_error_types_have_stable_safe_messages() {
    let errors = [
        (
            SnapshotError::InvalidEncoding,
            "invalid TPS1 trust-policy snapshot encoding",
        ),
        (
            SnapshotError::UnsupportedSchemaVersion,
            "unsupported TPS1 trust-policy snapshot schema version",
        ),
        (
            SnapshotError::FieldOutOfBounds,
            "TPS1 trust-policy snapshot field is out of bounds",
        ),
        (
            SnapshotError::NonCanonicalOrder,
            "TPS1 trust-policy snapshot lists are not canonical",
        ),
    ];
    for (error, message) in errors {
        assert_eq!(error.to_string(), message);
    }
}

#[test]
fn public_contract_rejects_invalid_values_and_root_algorithms() -> TestResult {
    let (_, snapshot) = draft_snapshot()?;

    let mut invalid_id = snapshot.clone();
    invalid_id.policy_id.clear();
    assert_eq!(invalid_id.validate(), Err(SnapshotError::FieldOutOfBounds));

    let mut invalid_epoch = snapshot.clone();
    invalid_epoch.epoch = 0;
    assert_eq!(
        invalid_epoch.validate(),
        Err(SnapshotError::FieldOutOfBounds)
    );

    let mut schema_valid_expiry = snapshot.clone();
    schema_valid_expiry.offline_valid_through = "2026-09-16T00:00:00+00:00".to_owned();
    assert_eq!(schema_valid_expiry.validate(), Ok(()));

    let mut empty_expiry = snapshot.clone();
    empty_expiry.offline_valid_through.clear();
    assert_eq!(
        empty_expiry.validate(),
        Err(SnapshotError::FieldOutOfBounds)
    );

    let mut oversized_expiry = snapshot.clone();
    oversized_expiry.offline_valid_through = "x".repeat(65);
    assert_eq!(
        oversized_expiry.validate(),
        Err(SnapshotError::FieldOutOfBounds)
    );

    let mut no_roots = snapshot.clone();
    no_roots.trust_roots.clear();
    assert_eq!(no_roots.validate(), Err(SnapshotError::FieldOutOfBounds));

    let mut invalid_root_id = snapshot.clone();
    invalid_root_id.trust_roots[0].key_id = "INVALID".to_owned();
    assert_eq!(
        invalid_root_id.validate(),
        Err(SnapshotError::FieldOutOfBounds)
    );

    let mut invalid_root_version = snapshot.clone();
    invalid_root_version.trust_roots[0].root_version = 0;
    assert_eq!(
        invalid_root_version.validate(),
        Err(SnapshotError::FieldOutOfBounds)
    );

    let mut unsupported_algorithm = snapshot.clone();
    unsupported_algorithm.trust_roots[0].algorithm = "future-signature".to_owned();
    assert_eq!(
        unsupported_algorithm.validate(),
        Err(SnapshotError::UnsupportedSchemaVersion)
    );

    let mut invalid_revoked_key = snapshot.clone();
    invalid_revoked_key.revoked_key_ids = vec!["INVALID".to_owned()];
    assert_eq!(
        invalid_revoked_key.validate(),
        Err(SnapshotError::FieldOutOfBounds)
    );

    let mut invalid_minimum_version = snapshot;
    invalid_minimum_version.minimum_versions[0].semantic_version = "01.0.0".to_owned();
    assert_eq!(
        invalid_minimum_version.validate(),
        Err(SnapshotError::FieldOutOfBounds)
    );
    Ok(())
}

#[test]
fn public_contract_rejects_unordered_or_duplicate_set_lists() -> TestResult {
    let unordered_roots = Value::Array(vec![encoded_root("root-b", 2), encoded_root("root-a", 1)]);
    assert_eq!(
        TrustPolicySnapshotV1::from_canonical_cbor(&draft_bytes_with_field(
            FIELD_TRUST_ROOTS,
            unordered_roots,
        )?)
        .map(|_| ()),
        Err(SnapshotError::NonCanonicalOrder)
    );

    let duplicate_root_keys =
        Value::Array(vec![encoded_root("root-a", 1), encoded_root("root-b", 1)]);
    assert_eq!(
        TrustPolicySnapshotV1::from_canonical_cbor(&draft_bytes_with_field(
            FIELD_TRUST_ROOTS,
            duplicate_root_keys
        )?)
        .map(|_| ()),
        Err(SnapshotError::NonCanonicalOrder)
    );

    let unordered_revoked_keys = Value::Array(vec![
        Value::Text("key-b".to_owned()),
        Value::Text("key-a".to_owned()),
    ]);
    assert_eq!(
        TrustPolicySnapshotV1::from_canonical_cbor(&draft_bytes_with_field(
            FIELD_REVOKED_KEYS,
            unordered_revoked_keys
        )?)
        .map(|_| ()),
        Err(SnapshotError::NonCanonicalOrder)
    );

    let duplicate_revoked_keys = Value::Array(vec![
        Value::Text("key-a".to_owned()),
        Value::Text("key-a".to_owned()),
    ]);
    assert_eq!(
        TrustPolicySnapshotV1::from_canonical_cbor(&draft_bytes_with_field(
            FIELD_REVOKED_KEYS,
            duplicate_revoked_keys
        )?)
        .map(|_| ()),
        Err(SnapshotError::NonCanonicalOrder)
    );

    let unordered_artifacts =
        Value::Array(vec![Value::Bytes(vec![2; 32]), Value::Bytes(vec![1; 32])]);
    assert_eq!(
        TrustPolicySnapshotV1::from_canonical_cbor(&draft_bytes_with_field(
            FIELD_REVOKED_ARTIFACTS,
            unordered_artifacts
        )?)
        .map(|_| ()),
        Err(SnapshotError::NonCanonicalOrder)
    );

    let duplicate_artifacts =
        Value::Array(vec![Value::Bytes(vec![1; 32]), Value::Bytes(vec![1; 32])]);
    assert_eq!(
        TrustPolicySnapshotV1::from_canonical_cbor(&draft_bytes_with_field(
            FIELD_REVOKED_ARTIFACTS,
            duplicate_artifacts
        )?)
        .map(|_| ()),
        Err(SnapshotError::NonCanonicalOrder)
    );

    let unordered_versions = Value::Array(vec![
        encoded_minimum_version("kind-b", "1.0.0"),
        encoded_minimum_version("kind-a", "1.0.0"),
    ]);
    assert_eq!(
        TrustPolicySnapshotV1::from_canonical_cbor(&draft_bytes_with_field(
            FIELD_MINIMUM_VERSIONS,
            unordered_versions,
        )?)
        .map(|_| ()),
        Err(SnapshotError::NonCanonicalOrder)
    );

    let duplicate_versions = Value::Array(vec![
        encoded_minimum_version("kind-a", "1.0.0"),
        encoded_minimum_version("kind-a", "2.0.0"),
    ]);
    assert_eq!(
        TrustPolicySnapshotV1::from_canonical_cbor(&draft_bytes_with_field(
            FIELD_MINIMUM_VERSIONS,
            duplicate_versions,
        )?)
        .map(|_| ()),
        Err(SnapshotError::NonCanonicalOrder)
    );
    Ok(())
}
