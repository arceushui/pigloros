//! ADR-136 §4 canonical records: round trips, content addresses, the
//! canonical-only decoders and every record rule.

use ciborium::value::Value;
use pos_core::{
    local_erasure_bundle_signing_message_v1, local_erasure_coordinator_v1,
    local_erasure_owner_ref_v1, local_erasure_signature_message_v1, local_erasure_signer_key_id_v1,
    ArtifactDataClassV1, EntityId, ErasureErrorV1, ErasureReferenceV1, ErasureRetainedObjectV1,
    LocalErasureAuthorizationV1, LocalErasureBundleSignatureV1, LocalErasureBundleV1,
    LocalErasureClassificationV1, LocalErasureDisclosureV1, LocalErasureExecutionBindingV1,
    LocalErasureIdempotencyV1, LocalErasureLineageRuleV1, LocalErasureOwnerResultV1,
    LocalErasureOwnerRowV1, LocalErasurePolicyV1, LocalErasureRejectionV1, LocalErasureSelectorV1,
    LocalErasureSignaturePurposeV1, LocalErasureSignatureV1, LocalErasureSignerIdentityV1,
    LocalErasureTrustAnchorV1, TimelineId, ERASURE_RETAINED_OBJECT_MAX_BYTES_V1,
    LOCAL_ERASURE_ATTEMPT_WINDOW_V1, LOCAL_ERASURE_MAX_QUOTA_ATTEMPTS_V1,
    LOCAL_ERASURE_MAX_REQUEST_RESERVE_V1,
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

fn owner(category: u64, ack_class: &str) -> Result<LocalErasureOwnerRowV1, ErasureErrorV1> {
    local_erasure_owner_ref_v1(reference(2), category, ack_class).map(|owner_ref| {
        LocalErasureOwnerRowV1 {
            category,
            ack_class: ack_class.to_owned(),
            owner_ref,
        }
    })
}

fn owners<I: IntoIterator<Item = String>>(
    classes: I,
) -> Result<Vec<LocalErasureOwnerRowV1>, ErasureErrorV1> {
    classes.into_iter().map(|class| owner(0, &class)).collect()
}

fn bundle() -> Result<LocalErasureBundleV1, ErasureErrorV1> {
    let signer_public_key = [9; 32];
    Ok(LocalErasureBundleV1 {
        tps1: reference(1),
        store_identity: reference(2),
        authority_registry_digest: reference(3),
        host_timelines: vec![timeline(1), timeline(2)],
        policy: reference(4),
        owners: vec![owner(0, "artifact-store")?, owner(1, "key-registry")?],
        execution_binding: LocalErasureExecutionBindingV1 {
            executor_id: "local-erasure-executor".to_owned(),
            executor_version_digest: reference(7),
        },
        signer_identity: signer(),
        signer_public_key,
        signer_key_id: local_erasure_signer_key_id_v1(&signer_public_key),
        issued_by: "erasure-bundle/root-1".to_owned(),
        expiry: 0x1234_5678,
    })
}

fn policy() -> LocalErasurePolicyV1 {
    LocalErasurePolicyV1 {
        retained_classes: vec![
            ArtifactDataClassV1::PublicRecord,
            ArtifactDataClassV1::AggregateData,
            ArtifactDataClassV1::StructuralAuditMetadata,
        ],
        classification: vec![
            LocalErasureClassificationV1 {
                artifact_class: 0,
                data_class: ArtifactDataClassV1::PrivateSubjectData,
                category: 0,
                ack_class: "timeline-payload".to_owned(),
            },
            LocalErasureClassificationV1 {
                artifact_class: 4,
                data_class: ArtifactDataClassV1::ConsentedSharedData,
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
        &bundle()?,
        LocalErasureBundleV1::to_canonical_cbor,
        LocalErasureBundleV1::from_canonical_cbor,
        LocalErasureBundleV1::reference,
    )?;
    assert_codec(
        &LocalErasureBundleSignatureV1 {
            bundle: bundle()?.reference()?,
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
fn bundle_rules_are_enforced() -> TestResult {
    let unsorted = |mut bundle: LocalErasureBundleV1| {
        bundle.host_timelines.reverse();
        bundle
    };
    let mut cases = vec![unsorted(bundle()?)];
    let mut owners_unsorted = bundle()?;
    owners_unsorted.owners.reverse();
    cases.push(owners_unsorted);
    let mut too_many_timelines = bundle()?;
    too_many_timelines.host_timelines = (0..65).map(timeline).collect();
    too_many_timelines.host_timelines.sort_unstable();
    cases.push(too_many_timelines);
    let mut too_many_owners = bundle()?;
    too_many_owners.owners = owners((0..65).map(|index| format!("c{index:03}")))?;
    cases.push(too_many_owners);
    let mut foreign_owner = bundle()?;
    foreign_owner.owners[0].owner_ref = reference(5);
    cases.push(foreign_owner);
    let mut uppercase_issuer = bundle()?;
    uppercase_issuer.issued_by = "erasure-bundle/Root".to_owned();
    cases.push(uppercase_issuer);
    let mut colon_issuer = bundle()?;
    colon_issuer.issued_by = "erasure-bundle:root".to_owned();
    cases.push(colon_issuer);
    let mut bad_category = bundle()?;
    bad_category.owners[0].category = 9;
    cases.push(bad_category);
    let mut bad_class = bundle()?;
    bad_class.owners[0].ack_class = "Artifact".to_owned();
    cases.push(bad_class);
    let mut empty_executor = bundle()?;
    empty_executor.execution_binding.executor_id.clear();
    cases.push(empty_executor);
    let mut long_executor = bundle()?;
    long_executor.execution_binding.executor_id = "e".repeat(65);
    cases.push(long_executor);
    let mut empty_owner = bundle()?;
    empty_owner.signer_identity.owner_id.clear();
    cases.push(empty_owner);
    let mut long_owner = bundle()?;
    long_owner.signer_identity.owner_id = vec![1; 129];
    cases.push(long_owner);
    let mut epoch_zero = bundle()?;
    epoch_zero.signer_identity.epoch = 0;
    cases.push(epoch_zero);
    let mut wrong_key_id = bundle()?;
    wrong_key_id.signer_key_id = local_erasure_signer_key_id_v1(&[8; 32]);
    cases.push(wrong_key_id);
    let mut long_issuer = bundle()?;
    long_issuer.issued_by = format!("erasure-bundle/{}", "r".repeat(114));
    cases.push(long_issuer);
    let mut bare_prefix = bundle()?;
    bare_prefix.issued_by = "erasure-bundle/".to_owned();
    cases.push(bare_prefix);
    let mut other_root = bundle()?;
    other_root.issued_by = "plugin-release/root-1".to_owned();
    cases.push(other_root);
    for case in cases {
        assert_eq!(
            case.to_canonical_cbor(),
            Err(ErasureErrorV1::ScopeInvalid),
            "{case:?}"
        );
    }
    let mut longest = bundle()?;
    longest.issued_by = format!("erasure-bundle/{}", "r".repeat(113));
    longest.host_timelines = (0..64).map(timeline).collect();
    longest.owners = owners((0..64).map(|index| format!("s3-cache{index:02}")))?;
    longest.execution_binding.executor_id = "e".repeat(64);
    longest.signer_identity.owner_id = vec![1; 128];
    assert!(longest.to_canonical_cbor().is_ok());
    let mut duplicate_pair = bundle()?;
    duplicate_pair.owners = vec![owner(0, "artifact-store")?, owner(0, "artifact-store")?];
    assert_eq!(
        duplicate_pair.to_canonical_cbor(),
        Err(ErasureErrorV1::ScopeInvalid)
    );
    Ok(())
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
    for operator_key_id in ["Operator", "operator:1", "-operator", &"o".repeat(129)] {
        assert_eq!(
            LocalErasureTrustAnchorV1 {
                tps1: reference(1),
                operator_key_id: operator_key_id.to_owned(),
                operator_public_key: [2; 32],
            }
            .to_canonical_cbor(),
            Err(ErasureErrorV1::ScopeInvalid),
            "{operator_key_id}"
        );
    }
    assert!(LocalErasureTrustAnchorV1 {
        tps1: reference(1),
        operator_key_id: format!("9.op_{}", "o".repeat(123)),
        operator_public_key: [2; 32],
    }
    .to_canonical_cbor()
    .is_ok());
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

fn rows(count: usize) -> Vec<LocalErasureClassificationV1> {
    (0..count)
        .map(|index| LocalErasureClassificationV1 {
            artifact_class: 0,
            data_class: ArtifactDataClassV1::PrivateSubjectData,
            category: 0,
            ack_class: format!("c{index:03}"),
        })
        .collect()
}

#[test]
fn policy_rules_are_enforced() -> TestResult {
    let mut cases = Vec::new();
    let mut unsorted_retained = policy();
    unsorted_retained.retained_classes.reverse();
    cases.push(unsorted_retained);
    for eligible in [
        ArtifactDataClassV1::PrivateSubjectData,
        ArtifactDataClassV1::ConsentedSharedData,
    ] {
        let mut retained_eligible = policy();
        retained_eligible.retained_classes = vec![eligible];
        cases.push(retained_eligible);
    }
    let mut unsorted_rows = policy();
    unsorted_rows.classification.reverse();
    cases.push(unsorted_rows);
    let mut too_many_rows = policy();
    too_many_rows.classification = rows(257);
    too_many_rows.classification.sort_unstable();
    cases.push(too_many_rows);
    let mut bad_artifact = policy();
    bad_artifact.classification[0].artifact_class = 99;
    cases.push(bad_artifact);
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
    quota.quota_attempts = LOCAL_ERASURE_MAX_QUOTA_ATTEMPTS_V1 + 1;
    cases.push(quota);
    let mut reserve = policy();
    reserve.store_request_reserve = LOCAL_ERASURE_MAX_REQUEST_RESERVE_V1 + 1;
    cases.push(reserve);
    for case in cases {
        assert_eq!(
            case.to_canonical_cbor(),
            Err(ErasureErrorV1::ScopeInvalid),
            "{case:?}"
        );
    }
    let mut boundary = policy();
    boundary.classification[0].ack_class = "a".repeat(48);
    assert!(boundary.to_canonical_cbor().is_ok());
    let mut widest = policy();
    widest.classification = rows(256);
    widest.store_request_reserve = LOCAL_ERASURE_MAX_REQUEST_RESERVE_V1;
    widest.quota_attempts = LOCAL_ERASURE_MAX_QUOTA_ATTEMPTS_V1;
    assert!(widest.to_canonical_cbor().is_ok());
    boundary.classification[0].ack_class = "a".repeat(49);
    assert_eq!(
        boundary.to_canonical_cbor(),
        Err(ErasureErrorV1::ScopeInvalid)
    );

    let value: Value = ciborium::from_reader(policy().to_canonical_cbor()?.as_slice())?;
    for code in [0_u64, 5] {
        let mut retained = value.clone();
        if let Value::Array(items) = &mut retained {
            items[2] = Value::Array(vec![Value::Integer(code.into())]);
        }
        assert!(LocalErasurePolicyV1::from_canonical_cbor(&encode(&retained)?).is_err());
    }
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
    let mut longest = authorization.clone();
    longest.operation = "o".repeat(64);
    assert!(longest.to_canonical_cbor().is_ok());
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
    assert!(LocalErasureDisclosureV1 {
        ack_class: "s3-cache2".to_owned(),
        policy: reference(1),
    }
    .to_canonical_cbor()
    .is_ok());
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

#[test]
fn data_class_codes_are_one_closed_mapping() {
    let classes = [
        ArtifactDataClassV1::PrivateSubjectData,
        ArtifactDataClassV1::ConsentedSharedData,
        ArtifactDataClassV1::PublicRecord,
        ArtifactDataClassV1::AggregateData,
        ArtifactDataClassV1::StructuralAuditMetadata,
    ];
    // Successor walk: every code up to one past the last decodes iff it
    // names a class, and decoding inverts encoding.
    for code in 0..=u64::try_from(classes.len()).unwrap_or(u64::MAX) {
        let decoded = ArtifactDataClassV1::from_code(code);
        assert_eq!(decoded.is_ok(), code < 5, "{code}");
        assert_eq!(decoded.map(u64::from).unwrap_or(code), code);
    }
    for (code, class) in (0_u64..).zip(classes) {
        assert_eq!(u64::from(class), code);
        assert_eq!(ArtifactDataClassV1::from_code(code), Ok(class));
        assert_eq!(class.is_always_retained(), code >= 2);
    }
}

/// An encoder independent of the codecs under test.
#[derive(Default)]
struct Cbor(Vec<u8>);

impl Cbor {
    fn head(mut self, major: u8, value: u64) -> Self {
        let tag = major << 5;
        match value {
            0..=23 => self.0.push(tag | u8::try_from(value).unwrap_or(0)),
            24..=0xff => self.0.extend([tag | 24, u8::try_from(value).unwrap_or(0)]),
            0x100..=0xffff => {
                self.0.push(tag | 25);
                self.0
                    .extend(u16::try_from(value).unwrap_or(0).to_be_bytes());
            }
            0x1_0000..=0xffff_ffff => {
                self.0.push(tag | 26);
                self.0
                    .extend(u32::try_from(value).unwrap_or(0).to_be_bytes());
            }
            _ => {
                self.0.push(tag | 27);
                self.0.extend(value.to_be_bytes());
            }
        }
        self
    }
    fn uint(self, value: u64) -> Self {
        self.head(0, value)
    }
    fn bytes(mut self, value: &[u8]) -> Self {
        self = self.head(2, u64::try_from(value.len()).unwrap_or(0));
        self.0.extend_from_slice(value);
        self
    }
    fn text(mut self, value: &str) -> Self {
        self = self.head(3, u64::try_from(value.len()).unwrap_or(0));
        self.0.extend_from_slice(value.as_bytes());
        self
    }
    fn array(self, length: u64) -> Self {
        self.head(4, length)
    }
    fn record(self, tag: &str, fields: u64) -> Self {
        self.array(fields + 2).text(tag).uint(1)
    }
    fn truth(mut self, value: bool) -> Self {
        self.0.push(if value { 0xf5 } else { 0xf4 });
        self
    }
    fn null(mut self) -> Self {
        self.0.push(0xf6);
        self
    }
}

fn assert_golden<R: PartialEq + std::fmt::Debug>(
    record: &R,
    tag: &str,
    golden: &[u8],
    to_bytes: fn(&R) -> Result<Vec<u8>, ErasureErrorV1>,
    from_bytes: fn(&[u8]) -> Result<R, ErasureErrorV1>,
    address: fn(&R) -> Result<ErasureReferenceV1, ErasureErrorV1>,
) -> TestResult {
    assert_eq!(to_bytes(record)?, golden, "{tag}");
    assert_eq!(&from_bytes(golden)?, record);
    let mut domain = tag.as_bytes().to_vec();
    domain.push(0);
    domain.extend_from_slice(golden);
    assert_eq!(
        address(record)?,
        ErasureReferenceV1::from_digest(*blake3::hash(&domain).as_bytes())
    );
    Ok(())
}

#[test]
fn records_match_hand_written_golden_vectors() -> TestResult {
    let bundle = bundle()?;
    let golden = Cbor::default()
        .record("ELB1", 12)
        .bytes(&[1; 32])
        .bytes(&[2; 32])
        .bytes(&[3; 32])
        .array(2)
        .bytes(&[1; 16])
        .bytes(&[2; 16])
        .bytes(&[4; 32])
        .array(2)
        .array(3)
        .uint(0)
        .text("artifact-store")
        .bytes(&bundle.owners[0].owner_ref.digest())
        .array(3)
        .uint(1)
        .text("key-registry")
        .bytes(&bundle.owners[1].owner_ref.digest())
        .array(2)
        .text("local-erasure-executor")
        .bytes(&[7; 32])
        .array(3)
        .bytes(b"local")
        .uint(2)
        .uint(1)
        .bytes(&[9; 32])
        .text(&local_erasure_signer_key_id_v1(&[9; 32]))
        .text("erasure-bundle/root-1")
        .uint(0x1234_5678);
    assert_golden(
        &bundle,
        "ELB1",
        &golden.0,
        LocalErasureBundleV1::to_canonical_cbor,
        LocalErasureBundleV1::from_canonical_cbor,
        LocalErasureBundleV1::reference,
    )?;
    let owner_ref_preimage = Cbor::default()
        .array(3)
        .bytes(&[2; 32])
        .uint(0)
        .text("artifact-store");
    let mut domain = b"ELOWN1\0".to_vec();
    domain.extend_from_slice(&owner_ref_preimage.0);
    assert_eq!(
        bundle.owners[0].owner_ref,
        ErasureReferenceV1::from_digest(*blake3::hash(&domain).as_bytes())
    );

    assert_golden(
        &LocalErasureBundleSignatureV1 {
            bundle: reference(11),
            admin_signature: [12; 64],
        },
        "ELB1S",
        &Cbor::default()
            .record("ELB1S", 2)
            .bytes(&[11; 32])
            .bytes(&[12; 64])
            .0,
        LocalErasureBundleSignatureV1::to_canonical_cbor,
        LocalErasureBundleSignatureV1::from_canonical_cbor,
        LocalErasureBundleSignatureV1::reference,
    )?;
    assert_golden(
        &LocalErasureRejectionV1 {
            request: reference(13),
            error: ErasureErrorV1::PolicyConflict,
        },
        "ELREJ1",
        &Cbor::default()
            .record("ELREJ1", 2)
            .bytes(&[13; 32])
            .uint(4)
            .0,
        LocalErasureRejectionV1::to_canonical_cbor,
        LocalErasureRejectionV1::from_canonical_cbor,
        LocalErasureRejectionV1::reference,
    )?;
    assert_golden(
        &LocalErasureTrustAnchorV1 {
            tps1: reference(14),
            operator_key_id: "deployment-operator/2".to_owned(),
            operator_public_key: [15; 32],
        },
        "ELTA1",
        &Cbor::default()
            .record("ELTA1", 3)
            .bytes(&[14; 32])
            .text("deployment-operator/2")
            .bytes(&[15; 32])
            .0,
        LocalErasureTrustAnchorV1::to_canonical_cbor,
        LocalErasureTrustAnchorV1::from_canonical_cbor,
        LocalErasureTrustAnchorV1::reference,
    )?;
    let policy = LocalErasurePolicyV1 {
        retained_classes: vec![ArtifactDataClassV1::AggregateData],
        classification: vec![LocalErasureClassificationV1 {
            artifact_class: 6,
            data_class: ArtifactDataClassV1::StructuralAuditMetadata,
            category: 3,
            ack_class: "local-backup-inventory".to_owned(),
        }],
        auto_retry_max: 5,
        quota_attempts: 300,
        store_request_reserve: 512,
        max_reprepare: 7,
    };
    assert_golden(
        &policy,
        "ELP1",
        &Cbor::default()
            .record("ELP1", 7)
            .array(1)
            .uint(3)
            .array(1)
            .array(4)
            .uint(6)
            .uint(4)
            .uint(3)
            .text("local-backup-inventory")
            .uint(16_386)
            .uint(5)
            .uint(300)
            .uint(512)
            .uint(7)
            .0,
        LocalErasurePolicyV1::to_canonical_cbor,
        LocalErasurePolicyV1::from_canonical_cbor,
        LocalErasurePolicyV1::reference,
    )?;
    assert_golden(
        &LocalErasureAuthorizationV1 {
            principal_ref: reference(16),
            actor_entity: EntityId::from_ulid(Ulid::from_bytes([17; 16])),
            operation: "erasure.request".to_owned(),
            authority_registry_digest: reference(18),
            authority_chain: timeline(19),
            chain_head_position: 20,
            revocation_epoch: 21,
            erq1_request: reference(22),
        },
        "ERAZ1",
        &Cbor::default()
            .record("ERAZ1", 8)
            .bytes(&[16; 32])
            .bytes(&[17; 16])
            .text("erasure.request")
            .bytes(&[18; 32])
            .bytes(&[19; 16])
            .uint(20)
            .uint(21)
            .bytes(&[22; 32])
            .0,
        LocalErasureAuthorizationV1::to_canonical_cbor,
        LocalErasureAuthorizationV1::from_canonical_cbor,
        LocalErasureAuthorizationV1::reference,
    )?;
    assert_golden(
        &LocalErasureSelectorV1 {
            subject: reference(23),
        },
        "ELSEL1",
        &Cbor::default()
            .record("ELSEL1", 4)
            .bytes(&[23; 32])
            .uint(0)
            .truth(true)
            .truth(true)
            .0,
        LocalErasureSelectorV1::to_canonical_cbor,
        LocalErasureSelectorV1::from_canonical_cbor,
        LocalErasureSelectorV1::reference,
    )?;
    assert_golden(
        &LocalErasureIdempotencyV1 {
            idempotency_key_digest: reference(24),
            body_digest: reference(25),
        },
        "ELIDEM1",
        &Cbor::default()
            .record("ELIDEM1", 2)
            .bytes(&[24; 32])
            .bytes(&[25; 32])
            .0,
        LocalErasureIdempotencyV1::to_canonical_cbor,
        LocalErasureIdempotencyV1::from_canonical_cbor,
        LocalErasureIdempotencyV1::reference,
    )?;
    for (error, golden) in [
        (
            None,
            Cbor::default()
                .record("ELO1", 8)
                .bytes(&[26; 32])
                .bytes(&[27; 32])
                .bytes(&[28; 32])
                .bytes(&[29; 32])
                .bytes(&[30; 32])
                .uint(0)
                .null()
                .bytes(&[31; 32]),
        ),
        (
            Some(ErasureErrorV1::BackupInventoryIncomplete),
            Cbor::default()
                .record("ELO1", 8)
                .bytes(&[26; 32])
                .bytes(&[27; 32])
                .bytes(&[28; 32])
                .bytes(&[29; 32])
                .bytes(&[30; 32])
                .uint(1)
                .uint(11)
                .bytes(&[31; 32]),
        ),
    ] {
        assert_golden(
            &LocalErasureOwnerResultV1 {
                request: reference(26),
                attempt: reference(27),
                obligation: reference(28),
                command: reference(29),
                owner_ref: reference(30),
                error,
                effect_digest: reference(31),
            },
            "ELO1",
            &golden.0,
            LocalErasureOwnerResultV1::to_canonical_cbor,
            LocalErasureOwnerResultV1::from_canonical_cbor,
            LocalErasureOwnerResultV1::reference,
        )?;
    }
    assert_golden(
        &LocalErasureSignatureV1 {
            purpose: LocalErasureSignaturePurposeV1::ReceiptBody,
            signed_digest: reference(32),
            signer_identity: LocalErasureSignerIdentityV1 {
                owner_id: b"signer".to_vec(),
                epoch: 33,
            },
            signature: [34; 64],
        },
        "ELS1",
        &Cbor::default()
            .record("ELS1", 4)
            .uint(2)
            .bytes(&[32; 32])
            .array(3)
            .bytes(b"signer")
            .uint(2)
            .uint(33)
            .bytes(&[34; 64])
            .0,
        LocalErasureSignatureV1::to_canonical_cbor,
        LocalErasureSignatureV1::from_canonical_cbor,
        LocalErasureSignatureV1::reference,
    )?;
    assert_golden(
        &LocalErasureDisclosureV1 {
            ack_class: "timeline-payload".to_owned(),
            policy: reference(35),
        },
        "ELD1",
        &Cbor::default()
            .record("ELD1", 2)
            .text("timeline-payload")
            .bytes(&[35; 32])
            .0,
        LocalErasureDisclosureV1::to_canonical_cbor,
        LocalErasureDisclosureV1::from_canonical_cbor,
        LocalErasureDisclosureV1::reference,
    )?;
    assert_golden(
        &LocalErasureLineageRuleV1 {
            subject: reference(36),
        },
        "ELLR1",
        &Cbor::default()
            .record("ELLR1", 2)
            .bytes(&[36; 32])
            .uint(0)
            .0,
        LocalErasureLineageRuleV1::to_canonical_cbor,
        LocalErasureLineageRuleV1::from_canonical_cbor,
        LocalErasureLineageRuleV1::reference,
    )?;
    assert_eq!(
        local_erasure_signature_message_v1(
            LocalErasureSignaturePurposeV1::OwnerResult,
            reference(37)
        )?,
        Cbor::default()
            .array(4)
            .text("ELS1-SIG")
            .uint(1)
            .uint(1)
            .bytes(&[37; 32])
            .0
    );
    Ok(())
}

fn receipt_input(
    policy: ErasureReferenceV1,
    signature: ErasureReferenceV1,
) -> pos_core::ErasureReceiptInputV1 {
    use pos_core::{
        ErasureAcknowledgementOutcomeV1, ErasureAcknowledgementV1, ErasureArtifactClassV1,
        ErasureArtifactTransitionV1, ErasureInventoryCategoryV1, ErasureInventoryResultV1,
        ErasureKeyRoleV1, ErasureLifecycleV1, ErasureReceiptInventoriesV1, ErasureReplayClaimV1,
        ErasureRequiredTargetV1,
    };
    let target = |seed: u8| ErasureRequiredTargetV1 {
        artifact_class: ErasureArtifactClassV1::TimelineReplay,
        artifact_digest: reference(seed),
        key_role: ErasureKeyRoleV1::DataEncryption,
        key_digest: reference(seed.wrapping_add(1)),
        replica_set: reference(90),
        replica_id: reference(91),
    };
    let inventory = |category, target, owner, seed: u8| ErasureInventoryResultV1 {
        category,
        target,
        transition: ErasureArtifactTransitionV1 {
            from: ErasureReplayClaimV1::Exact,
            to: ErasureReplayClaimV1::StructuralOnly,
            reason: reference(seed),
            owner,
            acknowledgements: reference(seed.wrapping_add(1)),
            provenance: reference(seed.wrapping_add(2)),
        },
        retained_disclosure: reference(seed.wrapping_add(3)),
    };
    let (replica, backup) = (target(10), target(20));
    pos_core::ErasureReceiptInputV1 {
        request: reference(1),
        terminal_state: reference(2),
        coordinator: reference(3),
        lifecycle: ErasureLifecycleV1::Complete,
        freeze_position: 5,
        acknowledgements: vec![
            ErasureAcknowledgementV1 {
                obligation: reference(130),
                target: replica,
                owner: reference(100),
                evidence: reference(140),
                outcome: ErasureAcknowledgementOutcomeV1::Acknowledged,
            },
            ErasureAcknowledgementV1 {
                obligation: reference(131),
                target: backup,
                owner: reference(101),
                evidence: reference(141),
                outcome: ErasureAcknowledgementOutcomeV1::Acknowledged,
            },
        ],
        frozen_targets: vec![replica, backup],
        pending_owners: Vec::new(),
        failed_owners: Vec::new(),
        inventories: ErasureReceiptInventoriesV1 {
            artifacts: Vec::new(),
            keys: Vec::new(),
            replicas: vec![inventory(
                ErasureInventoryCategoryV1::Replica,
                replica,
                reference(100),
                110,
            )],
            backups: vec![inventory(
                ErasureInventoryCategoryV1::Backup,
                backup,
                reference(101),
                120,
            )],
        },
        replay_claim: ErasureReplayClaimV1::StructuralOnly,
        policy,
        trust: reference(5),
        provenance: reference(6),
        issue_position: 7,
        signature,
        receipt_digest: reference(0),
    }
}

#[test]
fn receipt_body_is_the_erc1_array_without_its_self_binding_fields() -> TestResult {
    let receipt = pos_core::ErasureReceiptV1::new(receipt_input(reference(4), reference(8)))?;
    let body = pos_core::local_erasure_receipt_body_v1(&receipt)?;
    let erc1: Value = ciborium::from_reader(receipt.to_canonical_cbor()?.as_slice())?;
    let Value::Array(mut expected) = erc1 else {
        return Err("ERC1 is not an array".into());
    };
    assert_eq!(expected.len(), 19);
    expected.drain(16..18);
    assert_eq!(
        body,
        encode(&Value::Array(vec![
            Value::Text("ERCB1".to_owned()),
            Value::Integer(1.into()),
            Value::Array(expected),
        ]))?
    );
    let mut domain = b"ERCB1\0".to_vec();
    domain.extend_from_slice(&body);
    assert_eq!(
        pos_core::local_erasure_receipt_body_reference_v1(&receipt)?,
        ErasureReferenceV1::from_digest(*blake3::hash(&domain).as_bytes())
    );

    // The receipt's own signature is outside the preimage; its policy is in.
    let resigned = pos_core::ErasureReceiptV1::new(receipt_input(reference(4), reference(9)))?;
    assert_eq!(pos_core::local_erasure_receipt_body_v1(&resigned)?, body);
    let repoliced = pos_core::ErasureReceiptV1::new(receipt_input(reference(14), reference(8)))?;
    assert_ne!(pos_core::local_erasure_receipt_body_v1(&repoliced)?, body);
    Ok(())
}

#[test]
fn the_coordinator_identity_is_the_domain_tagged_digest_of_the_store_identity() -> TestResult {
    let store_identity = [0x5a; 32];
    // CA("ELCOORD1", [store_identity]): BLAKE3 over the tag, a zero byte and
    // the canonical one-element array holding the 32-byte identity.
    let mut preimage = b"ELCOORD1\0\x81\x58\x20".to_vec();
    preimage.extend_from_slice(&store_identity);
    assert_eq!(
        local_erasure_coordinator_v1(ErasureReferenceV1::from_digest(store_identity))?,
        ErasureReferenceV1::from_digest(*blake3::hash(&preimage).as_bytes())
    );
    assert_ne!(
        local_erasure_coordinator_v1(ErasureReferenceV1::from_digest([0x5b; 32]))?,
        local_erasure_coordinator_v1(ErasureReferenceV1::from_digest(store_identity))?
    );
    Ok(())
}
