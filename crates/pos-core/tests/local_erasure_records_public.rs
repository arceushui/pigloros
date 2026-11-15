//! ADR-136 §4 canonical records: round trips, content addresses, the
//! canonical-only decoders and every record rule.

use ciborium::value::Value;
use pos_core::{
    local_erasure_bundle_signing_message_v1, local_erasure_signature_message_v1,
    local_erasure_signer_key_id_v1, EntityId, ErasureErrorV1, ErasureReferenceV1,
    ErasureRetainedObjectV1, LocalErasureAuthorizationV1, LocalErasureBundleSignatureV1,
    LocalErasureBundleV1, LocalErasureClassificationV1, LocalErasureDisclosureV1,
    LocalErasureExecutionBindingV1, LocalErasureIdempotencyV1, LocalErasureLineageRuleV1,
    LocalErasureOwnerResultV1, LocalErasureOwnerRowV1, LocalErasurePolicyV1,
    LocalErasureRejectionV1, LocalErasureSelectorV1, LocalErasureSignaturePurposeV1,
    LocalErasureSignatureV1, LocalErasureSignerIdentityV1, LocalErasureTrustAnchorV1, TimelineId,
    ERASURE_RETAINED_OBJECT_MAX_BYTES_V1, LOCAL_ERASURE_ATTEMPT_WINDOW_V1,
};
use ulid::Ulid;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const fn reference(seed: u8) -> ErasureReferenceV1 {
    ErasureReferenceV1::from_digest([seed; 32])
}

fn timeline(seed: u8) -> TimelineId {
    TimelineId::from_ulid(Ulid::from_bytes([seed; 16]))
}

fn encode(value: &Value) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut bytes = Vec::new();
    ciborium::into_writer(value, &mut bytes)?;
    Ok(bytes)
}

/// Every single-leaf corruption of a canonical record: each leaf becomes a
/// value of the wrong type, each fixed-size byte string grows by one, every
/// array gains a trailing integer and the record loses its last field.
fn corruptions(value: &Value, top: bool) -> Vec<Value> {
    let mut out = Vec::new();
    match value {
        Value::Array(items) => {
            for (index, item) in items.iter().enumerate() {
                for corrupted in corruptions(item, false) {
                    let mut copy = items.clone();
                    copy[index] = corrupted;
                    out.push(Value::Array(copy));
                }
            }
            let mut extended = items.clone();
            extended.push(Value::Integer(0.into()));
            out.push(Value::Array(extended));
            if top {
                let mut shortened = items.clone();
                shortened.pop();
                out.push(Value::Array(shortened));
            }
            out.push(Value::Bool(false));
        }
        Value::Bool(_) => out.push(Value::Null),
        Value::Bytes(bytes) => {
            out.push(Value::Bool(true));
            if matches!(bytes.len(), 16 | 32 | 64) {
                let mut longer = bytes.clone();
                longer.push(0);
                out.push(Value::Bytes(longer));
            }
        }
        _ => out.push(Value::Bool(true)),
    }
    out
}

/// Round trip, content address, canonical-only decoding and corruption
/// refusal for one record.
fn assert_codec<R: PartialEq + std::fmt::Debug>(
    record: &R,
    to_bytes: fn(&R) -> Result<Vec<u8>, ErasureErrorV1>,
    from_bytes: fn(&[u8]) -> Result<R, ErasureErrorV1>,
    address: fn(&R) -> Result<ErasureReferenceV1, ErasureErrorV1>,
) -> TestResult {
    let bytes = to_bytes(record)?;
    assert_eq!(&from_bytes(&bytes)?, record);
    assert_eq!(
        address(record)?,
        ErasureRetainedObjectV1::new(&bytes, ERASURE_RETAINED_OBJECT_MAX_BYTES_V1)?.reference()
    );
    let value: Value = ciborium::from_reader(bytes.as_slice())?;
    for corrupted in corruptions(&value, true) {
        let corrupted = encode(&corrupted)?;
        assert!(from_bytes(&corrupted).is_err(), "{corrupted:02x?}");
    }
    // A non-minimal integer head is not canonical.
    let mut padded = bytes.clone();
    padded.insert(1, 0x18);
    assert!(from_bytes(&padded).is_err());
    let mut wrong_version = value.clone();
    if let Value::Array(items) = &mut wrong_version {
        items[1] = Value::Integer(2.into());
    }
    assert_eq!(
        from_bytes(&encode(&wrong_version)?),
        Err(ErasureErrorV1::UnsupportedVersion)
    );
    let mut wrong_tag = value;
    if let Value::Array(items) = &mut wrong_tag {
        items[0] = Value::Text("XXXX1".to_owned());
    }
    assert_eq!(
        from_bytes(&encode(&wrong_tag)?),
        Err(ErasureErrorV1::InvalidEncoding)
    );
    Ok(())
}

fn signer() -> LocalErasureSignerIdentityV1 {
    LocalErasureSignerIdentityV1 {
        owner_id: b"local".to_vec(),
        epoch: 1,
    }
}

fn bundle() -> LocalErasureBundleV1 {
    let signer_public_key = [9; 32];
    LocalErasureBundleV1 {
        tps1: reference(1),
        store_identity: reference(2),
        authority_registry_digest: reference(3),
        host_timelines: vec![timeline(1), timeline(2)],
        policy: reference(4),
        owners: vec![
            LocalErasureOwnerRowV1 {
                category: 0,
                ack_class: "artifact-store".to_owned(),
                owner_ref: reference(5),
            },
            LocalErasureOwnerRowV1 {
                category: 1,
                ack_class: "key-registry".to_owned(),
                owner_ref: reference(6),
            },
        ],
        execution_binding: LocalErasureExecutionBindingV1 {
            executor_id: "local-erasure-executor".to_owned(),
            executor_version_digest: reference(7),
        },
        signer_identity: signer(),
        signer_public_key,
        signer_key_id: local_erasure_signer_key_id_v1(&signer_public_key),
        issued_by: "erasure-bundle/root-1".to_owned(),
        expiry: 0,
    }
}

fn policy() -> LocalErasurePolicyV1 {
    LocalErasurePolicyV1 {
        retained_classes: vec![2, 3, 4],
        classification: vec![
            LocalErasureClassificationV1 {
                artifact_class: 0,
                data_class: 0,
                category: 0,
                ack_class: "timeline-payload".to_owned(),
            },
            LocalErasureClassificationV1 {
                artifact_class: 4,
                data_class: 1,
                category: 0,
                ack_class: "export-recipient".to_owned(),
            },
        ],
        auto_retry_max: 16,
        quota_attempts: 4_096,
        store_request_reserve: 512,
        max_reprepare: 3,
    }
}

#[test]
fn bundle_and_signature_round_trip_and_refuse_corruption() -> TestResult {
    assert_codec(
        &bundle(),
        LocalErasureBundleV1::to_canonical_cbor,
        LocalErasureBundleV1::from_canonical_cbor,
        LocalErasureBundleV1::reference,
    )?;
    assert_codec(
        &LocalErasureBundleSignatureV1 {
            bundle: bundle().reference()?,
            admin_signature: [3; 64],
        },
        LocalErasureBundleSignatureV1::to_canonical_cbor,
        LocalErasureBundleSignatureV1::from_canonical_cbor,
        LocalErasureBundleSignatureV1::reference,
    )?;
    let message = local_erasure_bundle_signing_message_v1(reference(8))?;
    let mut expected = vec![0x83, 0x68];
    expected.extend_from_slice(b"ELB1-SIG");
    expected.extend_from_slice(&[0x01, 0x58, 0x20]);
    expected.extend_from_slice(&[8; 32]);
    assert_eq!(message, expected);
    Ok(())
}

#[test]
fn bundle_rules_are_enforced() {
    let unsorted = |mut bundle: LocalErasureBundleV1| {
        bundle.host_timelines.reverse();
        bundle
    };
    let mut cases = vec![unsorted(bundle())];
    let mut owners_unsorted = bundle();
    owners_unsorted.owners.reverse();
    cases.push(owners_unsorted);
    let mut too_many_timelines = bundle();
    too_many_timelines.host_timelines = (0..65).map(timeline).collect();
    too_many_timelines.host_timelines.sort_unstable();
    cases.push(too_many_timelines);
    let mut too_many_owners = bundle();
    too_many_owners.owners = (0..65)
        .map(|seed| LocalErasureOwnerRowV1 {
            category: 0,
            ack_class: "artifact-store".to_owned(),
            owner_ref: reference(seed),
        })
        .collect();
    cases.push(too_many_owners);
    let mut bad_category = bundle();
    bad_category.owners[0].category = 9;
    cases.push(bad_category);
    let mut bad_class = bundle();
    bad_class.owners[0].ack_class = "Artifact".to_owned();
    cases.push(bad_class);
    let mut empty_executor = bundle();
    empty_executor.execution_binding.executor_id.clear();
    cases.push(empty_executor);
    let mut long_executor = bundle();
    long_executor.execution_binding.executor_id = "e".repeat(65);
    cases.push(long_executor);
    let mut empty_owner = bundle();
    empty_owner.signer_identity.owner_id.clear();
    cases.push(empty_owner);
    let mut long_owner = bundle();
    long_owner.signer_identity.owner_id = vec![1; 129];
    cases.push(long_owner);
    let mut epoch_zero = bundle();
    epoch_zero.signer_identity.epoch = 0;
    cases.push(epoch_zero);
    let mut wrong_key_id = bundle();
    wrong_key_id.signer_key_id = local_erasure_signer_key_id_v1(&[8; 32]);
    cases.push(wrong_key_id);
    let mut long_issuer = bundle();
    long_issuer.issued_by = format!("erasure-bundle/{}", "r".repeat(114));
    cases.push(long_issuer);
    let mut bare_prefix = bundle();
    bare_prefix.issued_by = "erasure-bundle/".to_owned();
    cases.push(bare_prefix);
    let mut other_root = bundle();
    other_root.issued_by = "plugin-release/root-1".to_owned();
    cases.push(other_root);
    for case in cases {
        assert_eq!(
            case.to_canonical_cbor(),
            Err(ErasureErrorV1::ScopeInvalid),
            "{case:?}"
        );
    }
    let mut longest_issuer = bundle();
    longest_issuer.issued_by = format!("erasure-bundle/{}", "r".repeat(113));
    assert!(longest_issuer.to_canonical_cbor().is_ok());
}

#[test]
fn signer_key_ids_are_tps1_key_ids() {
    let mut key = [0; 32];
    key[0] = 0xab;
    key[31] = 0x0f;
    let id = local_erasure_signer_key_id_v1(&key);
    assert_eq!(id.len(), "erasure-signer/".len() + 64);
    assert!(id.starts_with("erasure-signer/ab00"));
    assert!(id.ends_with("000f"));
    assert!(!id.contains(':'));
}

#[test]
fn signer_identity_role_and_epoch_are_checked_on_decode() -> TestResult {
    let signature = LocalErasureSignatureV1 {
        purpose: LocalErasureSignaturePurposeV1::OwnerResult,
        signed_digest: reference(1),
        signer_identity: signer(),
        signature: [4; 64],
    };
    let value: Value = ciborium::from_reader(signature.to_canonical_cbor()?.as_slice())?;
    for (index, replacement) in [(1, 3_u64), (2, 0)] {
        let mut changed = value.clone();
        if let Value::Array(items) = &mut changed {
            if let Some(Value::Array(identity)) = items.get_mut(4) {
                identity[index] = Value::Integer(replacement.into());
            }
        }
        assert_eq!(
            LocalErasureSignatureV1::from_canonical_cbor(&encode(&changed)?),
            Err(ErasureErrorV1::ScopeInvalid)
        );
    }
    Ok(())
}

#[test]
fn trust_policy_and_rejection_records_round_trip() -> TestResult {
    assert_codec(
        &LocalErasureTrustAnchorV1 {
            tps1: reference(1),
            operator_key_id: "deployment-operator/1".to_owned(),
            operator_public_key: [2; 32],
        },
        LocalErasureTrustAnchorV1::to_canonical_cbor,
        LocalErasureTrustAnchorV1::from_canonical_cbor,
        LocalErasureTrustAnchorV1::reference,
    )?;
    assert_eq!(
        LocalErasureTrustAnchorV1 {
            tps1: reference(1),
            operator_key_id: String::new(),
            operator_public_key: [2; 32],
        }
        .to_canonical_cbor(),
        Err(ErasureErrorV1::ScopeInvalid)
    );
    assert_codec(
        &policy(),
        LocalErasurePolicyV1::to_canonical_cbor,
        LocalErasurePolicyV1::from_canonical_cbor,
        LocalErasurePolicyV1::reference,
    )?;
    for error in [
        ErasureErrorV1::Unauthorized,
        ErasureErrorV1::ScopeInvalid,
        ErasureErrorV1::PolicyConflict,
    ] {
        assert_codec(
            &LocalErasureRejectionV1 {
                request: reference(1),
                error,
            },
            LocalErasureRejectionV1::to_canonical_cbor,
            LocalErasureRejectionV1::from_canonical_cbor,
            LocalErasureRejectionV1::reference,
        )?;
    }
    assert_eq!(
        LocalErasureRejectionV1 {
            request: reference(1),
            error: ErasureErrorV1::ProvenanceMissing,
        }
        .to_canonical_cbor(),
        Err(ErasureErrorV1::ScopeInvalid)
    );
    Ok(())
}

#[test]
fn policy_rules_are_enforced() -> TestResult {
    let mut cases = Vec::new();
    let mut unsorted_retained = policy();
    unsorted_retained.retained_classes = vec![3, 2];
    cases.push(unsorted_retained);
    let mut low_retained = policy();
    low_retained.retained_classes = vec![1];
    cases.push(low_retained);
    let mut high_retained = policy();
    high_retained.retained_classes = vec![5];
    cases.push(high_retained);
    let mut unsorted_rows = policy();
    unsorted_rows.classification.reverse();
    cases.push(unsorted_rows);
    let mut too_many_rows = policy();
    too_many_rows.classification = (0..257)
        .map(|index| LocalErasureClassificationV1 {
            artifact_class: 0,
            data_class: 0,
            category: 0,
            ack_class: format!("c{index:03}"),
        })
        .collect();
    too_many_rows.classification.sort_unstable();
    cases.push(too_many_rows);
    let mut bad_artifact = policy();
    bad_artifact.classification[0].artifact_class = 99;
    cases.push(bad_artifact);
    let mut bad_data = policy();
    bad_data.classification[0].data_class = 5;
    cases.push(bad_data);
    let mut bad_category = policy();
    bad_category.classification[0].category = 4;
    cases.push(bad_category);
    let mut bad_class = policy();
    bad_class.classification[0].ack_class = "-payload".to_owned();
    cases.push(bad_class);
    let mut retries = policy();
    retries.auto_retry_max = 17;
    cases.push(retries);
    let mut quota = policy();
    quota.quota_attempts = 4_097;
    cases.push(quota);
    for case in cases {
        assert_eq!(
            case.to_canonical_cbor(),
            Err(ErasureErrorV1::ScopeInvalid),
            "{case:?}"
        );
    }
    let mut boundary = policy();
    boundary.classification[0].data_class = 4;
    boundary.classification[0].ack_class = "a".repeat(48);
    assert!(boundary.to_canonical_cbor().is_ok());
    boundary.classification[0].ack_class = "a".repeat(49);
    assert_eq!(
        boundary.to_canonical_cbor(),
        Err(ErasureErrorV1::ScopeInvalid)
    );

    let value: Value = ciborium::from_reader(policy().to_canonical_cbor()?.as_slice())?;
    let mut window = value;
    if let Value::Array(items) = &mut window {
        items[4] = Value::Integer((LOCAL_ERASURE_ATTEMPT_WINDOW_V1 - 1).into());
    }
    assert_eq!(
        LocalErasurePolicyV1::from_canonical_cbor(&encode(&window)?),
        Err(ErasureErrorV1::ScopeInvalid)
    );
    Ok(())
}

#[test]
fn request_binding_records_round_trip() -> TestResult {
    let authorization = LocalErasureAuthorizationV1 {
        principal_ref: reference(1),
        actor_entity: EntityId::from_ulid(Ulid::from_bytes([2; 16])),
        operation: "erasure.request".to_owned(),
        authority_registry_digest: reference(3),
        authority_chain: timeline(4),
        chain_head_position: 5,
        revocation_epoch: 0,
        erq1_request: reference(6),
    };
    assert_codec(
        &authorization,
        LocalErasureAuthorizationV1::to_canonical_cbor,
        LocalErasureAuthorizationV1::from_canonical_cbor,
        LocalErasureAuthorizationV1::reference,
    )?;
    for operation in [String::new(), "o".repeat(65)] {
        let mut invalid = authorization.clone();
        invalid.operation = operation;
        assert_eq!(
            invalid.to_canonical_cbor(),
            Err(ErasureErrorV1::ScopeInvalid)
        );
    }
    assert_codec(
        &LocalErasureSelectorV1 {
            subject: reference(1),
        },
        LocalErasureSelectorV1::to_canonical_cbor,
        LocalErasureSelectorV1::from_canonical_cbor,
        LocalErasureSelectorV1::reference,
    )?;
    let selector: Value = ciborium::from_reader(
        LocalErasureSelectorV1 {
            subject: reference(1),
        }
        .to_canonical_cbor()?
        .as_slice(),
    )?;
    for (index, replacement) in [
        (3, Value::Integer(1.into())),
        (4, Value::Bool(false)),
        (5, Value::Bool(false)),
    ] {
        let mut changed = selector.clone();
        if let Value::Array(items) = &mut changed {
            items[index] = replacement;
        }
        assert_eq!(
            LocalErasureSelectorV1::from_canonical_cbor(&encode(&changed)?),
            Err(ErasureErrorV1::ScopeInvalid)
        );
    }
    assert_codec(
        &LocalErasureIdempotencyV1 {
            idempotency_key_digest: reference(1),
            body_digest: reference(2),
        },
        LocalErasureIdempotencyV1::to_canonical_cbor,
        LocalErasureIdempotencyV1::from_canonical_cbor,
        LocalErasureIdempotencyV1::reference,
    )?;
    let lineage = LocalErasureLineageRuleV1 {
        subject: reference(1),
    };
    assert_codec(
        &lineage,
        LocalErasureLineageRuleV1::to_canonical_cbor,
        LocalErasureLineageRuleV1::from_canonical_cbor,
        LocalErasureLineageRuleV1::reference,
    )?;
    let mut rule: Value = ciborium::from_reader(lineage.to_canonical_cbor()?.as_slice())?;
    if let Value::Array(items) = &mut rule {
        items[3] = Value::Integer(1.into());
    }
    assert_eq!(
        LocalErasureLineageRuleV1::from_canonical_cbor(&encode(&rule)?),
        Err(ErasureErrorV1::ScopeInvalid)
    );
    Ok(())
}

#[test]
fn owner_result_signature_and_disclosure_records_round_trip() -> TestResult {
    for error in [None, Some(ErasureErrorV1::ArtifactDeletionFailed)] {
        assert_codec(
            &LocalErasureOwnerResultV1 {
                request: reference(1),
                attempt: reference(2),
                obligation: reference(3),
                command: reference(4),
                owner_ref: reference(5),
                error,
                effect_digest: reference(6),
            },
            LocalErasureOwnerResultV1::to_canonical_cbor,
            LocalErasureOwnerResultV1::from_canonical_cbor,
            LocalErasureOwnerResultV1::reference,
        )?;
    }
    let positive: Value = ciborium::from_reader(
        LocalErasureOwnerResultV1 {
            request: reference(1),
            attempt: reference(2),
            obligation: reference(3),
            command: reference(4),
            owner_ref: reference(5),
            error: None,
            effect_digest: reference(6),
        }
        .to_canonical_cbor()?
        .as_slice(),
    )?;
    for (outcome, code) in [
        (Value::Integer(0.into()), Value::Integer(8.into())),
        (Value::Integer(2.into()), Value::Null),
        (Value::Integer(1.into()), Value::Integer(99.into())),
    ] {
        let mut changed = positive.clone();
        if let Value::Array(items) = &mut changed {
            items[7] = outcome;
            items[8] = code;
        }
        assert!(LocalErasureOwnerResultV1::from_canonical_cbor(&encode(&changed)?).is_err());
    }

    for purpose in [
        LocalErasureSignaturePurposeV1::FreezeAuthorization,
        LocalErasureSignaturePurposeV1::OwnerResult,
        LocalErasureSignaturePurposeV1::ReceiptBody,
    ] {
        let signature = LocalErasureSignatureV1 {
            purpose,
            signed_digest: reference(1),
            signer_identity: signer(),
            signature: [4; 64],
        };
        assert_codec(
            &signature,
            LocalErasureSignatureV1::to_canonical_cbor,
            LocalErasureSignatureV1::from_canonical_cbor,
            LocalErasureSignatureV1::reference,
        )?;
        let message = local_erasure_signature_message_v1(purpose, reference(1))?;
        assert_eq!(message.get(..10), Some(&b"\x84\x68ELS1-SIG"[..]));
    }
    let mut purpose: Value = ciborium::from_reader(
        LocalErasureSignatureV1 {
            purpose: LocalErasureSignaturePurposeV1::ReceiptBody,
            signed_digest: reference(1),
            signer_identity: signer(),
            signature: [4; 64],
        }
        .to_canonical_cbor()?
        .as_slice(),
    )?;
    if let Value::Array(items) = &mut purpose {
        items[2] = Value::Integer(3.into());
    }
    assert!(LocalErasureSignatureV1::from_canonical_cbor(&encode(&purpose)?).is_err());
    for identity in [
        LocalErasureSignerIdentityV1 {
            owner_id: Vec::new(),
            epoch: 1,
        },
        LocalErasureSignerIdentityV1 {
            owner_id: vec![1; 129],
            epoch: 1,
        },
        LocalErasureSignerIdentityV1 {
            owner_id: b"local".to_vec(),
            epoch: 0,
        },
    ] {
        assert_eq!(
            LocalErasureSignatureV1 {
                purpose: LocalErasureSignaturePurposeV1::OwnerResult,
                signed_digest: reference(1),
                signer_identity: identity,
                signature: [4; 64],
            }
            .to_canonical_cbor(),
            Err(ErasureErrorV1::ScopeInvalid)
        );
    }

    assert_codec(
        &LocalErasureDisclosureV1 {
            ack_class: "local-backup-inventory".to_owned(),
            policy: reference(1),
        },
        LocalErasureDisclosureV1::to_canonical_cbor,
        LocalErasureDisclosureV1::from_canonical_cbor,
        LocalErasureDisclosureV1::reference,
    )?;
    for class in ["", "Backup", "9backup", "back_up"] {
        assert_eq!(
            LocalErasureDisclosureV1 {
                ack_class: class.to_owned(),
                policy: reference(1),
            }
            .to_canonical_cbor(),
            Err(ErasureErrorV1::ScopeInvalid),
            "{class}"
        );
    }
    Ok(())
}
