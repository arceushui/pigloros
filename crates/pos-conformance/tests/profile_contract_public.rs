#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

use ciborium::value::Value;
use pos_conformance::{
    CapabilityPolicyV1, CaseOutcomeStatusV1, CaseOutcomeV1, ClaimLayerV1, ConformanceContractError,
    ConformanceProfileV1, ConformanceReportV1, ErasureDispositionV1, EvaluatorHardCapsV1,
    EvaluatorOutputCapabilityV1, EvaluatorProtocolV1, EvaluatorRequestV1, ExecutionModeV1,
    ExpectedResultV1, FixtureBoundsV1, FixtureDescriptorV1, FixtureInputMemberV1,
    FixtureProvenanceV1, ImplementationIdentityV1, IndependenceEvidenceV1,
    IndependenceRequirementsV1, RedactionStateV1, ReplayClaimV1, SubjectAdapterKindV1,
};

#[cfg_attr(coverage_nightly, coverage(off))]
pub mod fixtures {
    use super::*;

    fn text(value: &str) -> Value {
        Value::Text(value.to_owned())
    }

    fn uint(value: u64) -> Value {
        Value::Integer(value.into())
    }

    fn bytes(seed: u8) -> Value {
        Value::Bytes(vec![seed; 32])
    }

    fn bytes16(seed: u8) -> Value {
        Value::Bytes(vec![seed; 16])
    }

    fn identity(seed: u8) -> Value {
        Value::Array(vec![
            text("external-implementation"),
            bytes(seed),
            bytes(seed.saturating_add(1)),
            bytes(seed.saturating_add(2)),
            bytes(7),
            Value::Null,
        ])
    }

    fn independence(seed: u8) -> Value {
        Value::Array(vec![
            Value::Bool(true),
            Value::Bool(true),
            Value::Bool(false),
            bytes(seed),
            bytes(seed.saturating_add(1)),
            Value::Array(vec![text("external-reviewer")]),
        ])
    }

    fn strict_case(seed: u8) -> Value {
        Value::Array(vec![
            text("ART-001"),
            bytes(seed),
            bytes(1),
            uint(0),
            uint(0),
            uint(0),
            Value::Null,
            Value::Null,
            Value::Null,
            Value::Null,
            Value::Null,
            uint(0),
            uint(0),
            bytes(2),
        ])
    }

    fn report(seed: u8) -> Value {
        Value::Array(vec![
            text("CNR1"),
            uint(1),
            bytes16(1),
            bytes(seed),
            bytes(seed.saturating_add(1)),
            bytes(12),
            bytes(1),
            bytes(3),
            bytes(4),
            bytes(5),
            bytes(13),
            identity(seed),
            independence(seed.saturating_add(2)),
            Value::Array(vec![strict_case(seed)]),
            uint(1),
            uint(0),
            uint(0),
            uint(0),
            uint(0),
            uint(0),
            uint(0),
            bytes(18),
            bytes(19),
            bytes(20),
        ])
    }

    fn case(seed: u8) -> Value {
        Value::Array(vec![
            text("ART-001"),
            bytes(seed),
            bytes(1),
            uint(0),
            uint(0),
            uint(0),
            uint(0),
            Value::Null,
            Value::Null,
            Value::Null,
            Value::Null,
            uint(0),
            uint(0),
            bytes(2),
            uint(0),
            uint(0),
        ])
    }

    fn fixture() -> Value {
        Value::Array(vec![
            text("ART-001"),
            Value::Bool(true),
            uint(0),
            bytes(1),
            bytes(2),
            Value::Array(vec![uint(0), uint(1)]),
            uint(0),
            Value::Array(vec![Value::Array(vec![
                text("fixture.json"),
                uint(1),
                bytes(3),
                bytes(4),
            ])]),
            Value::Array(vec![
                uint(0),
                Value::Bytes(vec![1]),
                bytes(5),
                Value::Null,
                Value::Null,
            ]),
            uint(0),
            Value::Null,
            uint(0),
            uint(0),
            Value::Array(vec![
                uint(1),
                uint(1),
                uint(1),
                uint(1),
                uint(1),
                uint(1),
                uint(1),
                uint(1),
            ]),
            Value::Array(vec![
                Value::Bool(false),
                Value::Array(vec![text("read-public-bundle")]),
            ]),
            Value::Array(vec![
                text("MIT"),
                bytes(6),
                bytes(7),
                bytes(8),
                bytes(9),
                bytes(10),
                bytes(11),
            ]),
            bytes(12),
        ])
    }

    fn protocol() -> Value {
        Value::Array(vec![
            text("pigloros.evaluator.v1"),
            bytes(13),
            bytes(14),
            bytes(15),
            Value::Array(vec![
                uint(16_777_216),
                uint(65_536),
                uint(65_536),
                uint(256),
                uint(1_073_741_824),
                uint(1_073_741_824),
                uint(100),
                uint(32),
                uint(128),
                uint(1_048_576),
            ]),
        ])
    }

    fn requirements() -> Value {
        Value::Array(vec![
            Value::Bool(true),
            Value::Bool(true),
            Value::Bool(false),
            bytes(16),
            bytes(17),
        ])
    }

    fn stable_evidence() -> Value {
        Value::Array(vec![
            identity(30),
            independence(34),
            bytes(13),
            report(30),
            Value::Array(vec![case(30)]),
            Value::Array(vec![bytes(31), Value::Bytes(vec![1; 64]), bytes(32)]),
        ])
    }

    #[must_use]
    pub fn encode(value: &Value) -> Vec<u8> {
        let mut bytes = Vec::new();
        ciborium::into_writer(value, &mut bytes).unwrap_or_default();
        bytes
    }

    #[must_use]
    pub fn profile(lifecycle: u64, with_stable_evidence: bool) -> Vec<u8> {
        encode(&Value::Array(vec![
            text("CPF1"),
            uint(1),
            text("pigloros.w8.external"),
            text("1.0.0"),
            uint(lifecycle),
            bytes(12),
            Value::Array(vec![bytes(1)]),
            Value::Array(vec![bytes(2)]),
            Value::Array(vec![fixture()]),
            Value::Array(vec![Value::Array(vec![uint(0), bytes(99)])]),
            protocol(),
            requirements(),
            bytes(17),
            bytes(18),
            bytes(19),
            Value::Null,
            if with_stable_evidence {
                Value::Array(vec![stable_evidence()])
            } else {
                Value::Array(vec![])
            },
            Value::Bytes(vec![1]),
        ]))
    }

    #[must_use]
    pub fn request() -> Vec<u8> {
        encode(&Value::Array(vec![
            text("EVR1"),
            uint(1),
            bytes16(1),
            bytes(1),
            bytes(2),
            uint(0),
            bytes(3),
            identity(4),
            bytes(1),
            bytes(5),
            Value::Array(vec![bytes(6), uint(1), uint(1)]),
            bytes(13),
            bytes(14),
            Value::Bytes(vec![1]),
        ]))
    }
}

fn report_with_cases(count: usize) -> ConformanceReportV1 {
    let cases = (0..count)
        .map(|index| {
            let digest = [7; 32];
            CaseOutcomeV1 {
                case_id: format!("case-{index:05}"),
                fixture_digest: [3; 32],
                execution_profile_digest: [4; 32],
                mode: ExecutionModeV1::Local,
                claim_layer: ClaimLayerV1::ArtifactIntegrity,
                outcome: CaseOutcomeStatusV1::Pass,
                first_coordinate: None,
                expected_digest: Some(digest),
                actual_digest: Some(digest),
                expected_error: None,
                actual_error: None,
                replay_claim: ReplayClaimV1::Exact,
                redaction_state: RedactionStateV1::None,
                provenance_digest: [6; 32],
            }
        })
        .collect::<Vec<_>>();
    let mut report = ConformanceReportV1 {
        report_id: [1; 16],
        subject_artifact_digest: [2; 32],
        profile_digest: [3; 32],
        normative_spec_digest: [4; 32],
        execution_profile_digest: [5; 32],
        fixture_bundle_digest: [6; 32],
        evaluator_source_digest: [7; 32],
        evaluator_binary_digest: [8; 32],
        evaluator_protocol_digest: [9; 32],
        implementation: ImplementationIdentityV1 {
            implementation_id: "independent".to_owned(),
            source_digest: [10; 32],
            build_digest: [11; 32],
            binary_digest: [12; 32],
            public_contract_digest: [13; 32],
            organization_id: None,
        },
        independence: IndependenceEvidenceV1 {
            technical_independent: true,
            authorship_independent: true,
            organizational_independent: false,
            declaration_digest: [14; 32],
            shared_code_audit_digest: [15; 32],
            reviewer_ids: vec!["reviewer".to_owned()],
        },
        passed: u32::try_from(count).unwrap_or(u32::MAX),
        failed: 0,
        skipped: 0,
        unavailable: 0,
        not_applicable: 0,
        cases,
        replay_claim: ReplayClaimV1::Exact,
        redaction_state: RedactionStateV1::None,
        limitations_digest: [16; 32],
        provenance_digest: [17; 32],
        report_digest: [0; 32],
    };
    report.report_digest = report.digest().unwrap_or([0; 32]);
    report
}

fn profile_for_digest() -> ConformanceProfileV1 {
    let expected = b"expected".to_vec();
    let fixture = FixtureDescriptorV1 {
        case_id: "ART-001".to_owned(),
        mandatory: true,
        claim_layer: ClaimLayerV1::ArtifactIntegrity,
        execution_profile_digest: [1; 32],
        public_schema_digest: [2; 32],
        modes: vec![ExecutionModeV1::Local],
        subject_adapter: SubjectAdapterKindV1::ExportedArtifact,
        inputs: vec![FixtureInputMemberV1 {
            member_id: "fixture.json".to_owned(),
            size_bytes: expected.len() as u64,
            digest: [3; 32],
            provenance_digest: [4; 32],
        }],
        expected: ExpectedResultV1::CanonicalBytes {
            digest: *blake3::hash(&expected).as_bytes(),
            bytes: expected,
        },
        expected_verification_outcome: pos_conformance::VerificationOutcomeV1::VerifiedExact,
        expected_verification_error: None,
        replay_claim: ReplayClaimV1::Exact,
        redaction_state: RedactionStateV1::None,
        bounds: FixtureBoundsV1 {
            cpu_fuel: 1,
            memory_bytes: 1,
            event_count: 1,
            output_bytes: 1024,
            storage_bytes: 1,
            execution_steps: 1,
            simulation_time_ns: 1,
            watchdog_ms: 1,
        },
        capability_policy: CapabilityPolicyV1 {
            network_allowed: false,
            capability_ids: vec!["read-public-bundle".to_owned()],
        },
        provenance: FixtureProvenanceV1 {
            licence_id: "MIT".to_owned(),
            notices_digest: [5; 32],
            sbom_digest: [6; 32],
            source_digest: [7; 32],
            build_digest: [8; 32],
            publication_review_digest: [9; 32],
            limitations_digest: [10; 32],
        },
        compatibility_digest: [11; 32],
    };
    let mut profile = ConformanceProfileV1 {
        profile_id: "pigloros.test".to_owned(),
        semantic_version: "1.0.0".to_owned(),
        lifecycle: pos_conformance::ProfileLifecycleV1::Draft,
        normative_spec_digest: [12; 32],
        execution_profile_digests: vec![[1; 32]],
        public_schema_digests: vec![[2; 32]],
        fixtures: vec![fixture],
        allowed_divergences: vec![],
        evaluator_protocol: EvaluatorProtocolV1 {
            protocol_id: "pigloros.evaluator.v1".to_owned(),
            protocol_digest: [13; 32],
            request_schema_digest: [14; 32],
            report_schema_digest: [15; 32],
            hard_caps: EvaluatorHardCapsV1 {
                max_profile_bytes: 16 * 1024 * 1024,
                max_cases: 65_536,
                max_bundle_members: 65_536,
                max_member_path_bytes: 256,
                max_member_bytes: 1_073_741_824,
                max_total_bundle_bytes: 1_073_741_824,
                max_compression_expansion: 100,
                max_structural_nesting: 32,
                max_coordinate_bytes: 128,
                max_diagnostic_bytes: 1_048_576,
            },
        },
        independence_requirements: IndependenceRequirementsV1 {
            technical_independence_required: true,
            authorship_independence_required: true,
            organizational_independence_required: false,
            trust_policy_snapshot_digest: [16; 32],
            requirements_digest: [17; 32],
        },
        compatibility_digest: [18; 32],
        limitations_digest: [19; 32],
        provenance_digest: [20; 32],
        previous_profile_digest: None,
        stable_evidence: vec![],
        profile_digest: [0; 32],
    };
    profile.profile_digest = profile.digest();
    profile
}

fn request_for_caps(caps: &EvaluatorHardCapsV1) -> EvaluatorRequestV1 {
    let mut request = EvaluatorRequestV1 {
        request_id: [1; 16],
        conformance_profile_digest: [2; 32],
        fixture_bundle_digest: [3; 32],
        subject_adapter: SubjectAdapterKindV1::ExportedArtifact,
        subject_artifact_digest: [4; 32],
        implementation: ImplementationIdentityV1 {
            implementation_id: "independent".to_owned(),
            source_digest: [5; 32],
            build_digest: [6; 32],
            binary_digest: [7; 32],
            public_contract_digest: [8; 32],
            organization_id: None,
        },
        execution_profile_digest: [9; 32],
        trust_policy_snapshot_digest: [10; 32],
        output_capability: EvaluatorOutputCapabilityV1 {
            capability_digest: [0; 32],
            report_bytes_limit: caps.max_profile_bytes,
            diagnostic_bytes_limit: caps.max_diagnostic_bytes,
        },
        evaluator_protocol_digest: [11; 32],
        evaluator_hard_caps_digest: caps.digest(),
        request_digest: [0; 32],
    };
    request.output_capability.capability_digest = request.expected_output_capability_digest();
    request.request_digest = request.digest();
    request
}

#[test]
fn public_report_validation_and_encoding_cover_empty_and_large_boundaries() {
    let empty = report_with_cases(0);
    assert_eq!(
        empty.validate(),
        Err(pos_conformance::EvidenceError::InvalidConformanceReport)
    );

    let ordinary = report_with_cases(128);
    let ordinary_bytes = ordinary.to_canonical_cbor();
    assert!(ordinary_bytes.is_ok());
    assert!(ordinary_bytes
        .as_ref()
        .is_ok_and(|bytes| bytes.len() > 17_408));
    assert_eq!(
        ConformanceReportV1::from_canonical_cbor(&ordinary_bytes.unwrap_or_default()),
        Ok(ordinary)
    );

    let large = report_with_cases(7_000);
    let large_bytes = large.to_canonical_cbor();
    assert!(large_bytes.is_ok());
    assert!(large_bytes
        .as_ref()
        .is_ok_and(|bytes| bytes.len() > 1_048_592));

    let exact_case_cap = report_with_cases(65_536);
    assert_eq!(exact_case_cap.validate(), Ok(()));
}

#[test]
fn public_trusted_root_policy_accepts_exact_root_cap_and_rejects_one_more() {
    let mut exact = pos_conformance::TrustedRootPolicyV1 {
        trusted_root_public_keys: (1_u8..=64).map(|seed| [seed; 32]).collect(),
        trust_policy_snapshot_digest: [0; 32],
    };
    exact.trust_policy_snapshot_digest = exact.digest();
    assert_eq!(exact.validate(), Ok(()));

    let mut oversized = exact.clone();
    oversized.trusted_root_public_keys.push([65; 32]);
    oversized.trust_policy_snapshot_digest = oversized.digest();
    assert_eq!(
        oversized.validate(),
        Err(ConformanceContractError::IndependenceEvidenceMissing)
    );
}

#[test]
fn public_profile_digest_normalizes_stable_lifecycle_to_selected_identity() {
    let candidate = profile_for_digest();
    let mut stable = candidate.clone();
    stable.lifecycle = pos_conformance::ProfileLifecycleV1::Stable;
    stable.profile_digest = stable.digest();
    assert_eq!(stable.digest(), candidate.digest());
}

#[test]
fn public_request_output_limits_accept_exact_caps_and_reject_each_overflow() {
    let caps = EvaluatorHardCapsV1 {
        max_profile_bytes: 1024,
        max_cases: 1,
        max_bundle_members: 1,
        max_member_path_bytes: 1,
        max_member_bytes: 1,
        max_total_bundle_bytes: 1,
        max_compression_expansion: 1,
        max_structural_nesting: 1,
        max_coordinate_bytes: 1,
        max_diagnostic_bytes: 2048,
    };
    let exact = request_for_caps(&caps);
    assert_eq!(exact.validate_with_hard_caps(&caps), Ok(()));
    let protocol = EvaluatorProtocolV1 {
        protocol_id: "pigloros.evaluator.v1".to_owned(),
        protocol_digest: [11; 32],
        request_schema_digest: [12; 32],
        report_schema_digest: [13; 32],
        hard_caps: caps.clone(),
    };
    assert_eq!(exact.validate_with_protocol(&protocol), Ok(()));

    let mut report_overflow = exact.clone();
    report_overflow.output_capability.report_bytes_limit += 1;
    report_overflow.output_capability.capability_digest =
        report_overflow.expected_output_capability_digest();
    report_overflow.request_digest = report_overflow.digest();
    assert_eq!(
        report_overflow.validate_with_hard_caps(&caps),
        Err(ConformanceContractError::FieldOutOfBounds)
    );

    let mut diagnostic_overflow = exact;
    diagnostic_overflow.output_capability.diagnostic_bytes_limit += 1;
    diagnostic_overflow.output_capability.capability_digest =
        diagnostic_overflow.expected_output_capability_digest();
    diagnostic_overflow.request_digest = diagnostic_overflow.digest();
    assert_eq!(
        diagnostic_overflow.validate_with_hard_caps(&caps),
        Err(ConformanceContractError::FieldOutOfBounds)
    );

    let mut protocol_overflow = exact.clone();
    protocol_overflow.output_capability.diagnostic_bytes_limit += 1;
    protocol_overflow.output_capability.capability_digest =
        protocol_overflow.expected_output_capability_digest();
    protocol_overflow.request_digest = protocol_overflow.digest();
    assert_eq!(
        protocol_overflow.validate_with_protocol(&protocol),
        Err(ConformanceContractError::FieldOutOfBounds)
    );
}

#[test]
fn public_profile_caps_accept_exact_profile_and_member_path_limits() {
    let mut exact_profiles = profile_for_digest();
    exact_profiles.execution_profile_digests = (1_u8..=64).map(|seed| [seed; 32]).collect();
    exact_profiles.profile_digest = exact_profiles.digest();
    assert_eq!(exact_profiles.validate(), Ok(()));

    let mut too_many_profiles = exact_profiles.clone();
    too_many_profiles.execution_profile_digests.push([65; 32]);
    too_many_profiles.profile_digest = too_many_profiles.digest();
    assert_eq!(
        too_many_profiles.validate(),
        Err(ConformanceContractError::FieldOutOfBounds)
    );

    let mut exact_path = profile_for_digest();
    exact_path
        .evaluator_protocol
        .hard_caps
        .max_member_path_bytes = 11;
    exact_path.profile_digest = exact_path.digest();
    assert_eq!(exact_path.validate(), Ok(()));

    let mut short_path = exact_path;
    short_path
        .evaluator_protocol
        .hard_caps
        .max_member_path_bytes = 10;
    short_path.profile_digest = short_path.digest();
    assert_eq!(
        short_path.validate(),
        Err(ConformanceContractError::FieldOutOfBounds)
    );
}

#[test]
fn exported_decoders_reject_terminal_digest_after_nested_decode() {
    assert_eq!(
        ConformanceProfileV1::from_canonical_cbor(&fixtures::profile(0, false)),
        Err(ConformanceContractError::InvalidEncoding)
    );
    assert_eq!(
        ConformanceProfileV1::from_canonical_cbor(&fixtures::profile(2, true)),
        Err(ConformanceContractError::InvalidEncoding)
    );
    assert_eq!(
        EvaluatorRequestV1::from_canonical_cbor(&fixtures::request()),
        Err(ConformanceContractError::InvalidEncoding)
    );
}

#[test]
fn public_replay_claim_erasure_seam_only_preserves_or_weakens() {
    assert_eq!(
        ReplayClaimV1::Exact.after_erasure(ErasureDispositionV1::None),
        ReplayClaimV1::Exact
    );
    assert_eq!(
        ReplayClaimV1::Exact.after_erasure(ErasureDispositionV1::RedactedViews),
        ReplayClaimV1::ExactAuthoritativeWithRedactedViews
    );
    assert_eq!(
        ReplayClaimV1::Exact.after_erasure(ErasureDispositionV1::StructuralOnly),
        ReplayClaimV1::StructuralOnly
    );
    assert_eq!(
        ReplayClaimV1::StructuralOnly.after_erasure(ErasureDispositionV1::None),
        ReplayClaimV1::StructuralOnly
    );
    assert_eq!(
        ReplayClaimV1::StructuralOnly.after_erasure(ErasureDispositionV1::RedactedViews),
        ReplayClaimV1::StructuralOnly
    );
    assert_eq!(
        ReplayClaimV1::UnverifiableArtifactsMissing
            .after_erasure(ErasureDispositionV1::StructuralOnly),
        ReplayClaimV1::UnverifiableArtifactsMissing
    );
    assert_eq!(
        ReplayClaimV1::Exact.after_erasure(ErasureDispositionV1::ArtifactsMissing),
        ReplayClaimV1::UnverifiableArtifactsMissing
    );
    assert_eq!(
        ReplayClaimV1::IncompatibleProfile.after_erasure(ErasureDispositionV1::None),
        ReplayClaimV1::IncompatibleProfile
    );
    assert_eq!(
        ReplayClaimV1::Exact.after_erasure(ErasureDispositionV1::IncompatibleProfile),
        ReplayClaimV1::IncompatibleProfile
    );
}
