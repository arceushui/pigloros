#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

use ciborium::value::Value;
use pos_conformance::{
    CapabilityPolicyV1, CaseOutcomeStatusV1, CaseOutcomeV1, ClaimLayerV1, ConformanceContractError,
    ConformanceProfileV1, ConformanceReportV1, ErasureDispositionV1, EvaluatorHardCapsV1,
    EvaluatorOutputCapabilityV1, EvaluatorProtocolV1, EvaluatorRequestV1, ExecutionModeV1,
    ExpectedResultV1, FixtureBoundsV1, FixtureDescriptorV1, FixtureInputMemberV1,
    FixtureProvenanceV1, ImplementationIdentityV1, IndependenceEvidenceV1,
    IndependenceRequirementsV1, ProfileCaseOutcomeV1, RedactionStateV1, ReplayClaimV1,
    StableEvidenceAttestationV1, StableImplementationEvidenceV1, SubjectAdapterKindV1,
    TrustedRootPolicyV1, VerificationOutcomeV1,
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

    fn encoded_fixture_descriptor_value() -> Value {
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

    /// Serializes a fixture value as canonical CBOR bytes.
    ///
    /// # Errors
    ///
    /// Returns an error when CBOR serialization fails.
    #[must_use = "encoded fixture bytes must be used by the contract exercise"]
    pub fn encode(value: &Value) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let mut bytes = Vec::new();
        ciborium::into_writer(value, &mut bytes)?;
        Ok(bytes)
    }

    /// Builds a complete CPF1 profile fixture for rejection-path exercises.
    ///
    /// # Errors
    ///
    /// Returns an error when encoding the fixture as CBOR fails.
    #[must_use = "profile fixture bytes must be used by the contract exercise"]
    pub fn profile(
        lifecycle: u64,
        with_stable_evidence: bool,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let mut fields = vec![
            text("CPF1"),
            uint(1),
            text("pigloros.w8.knowledge-non-interference.1.0.0#matrix=0101010101010101010101010101010101010101010101010101010101010101"),
            text("1.0.0"),
            uint(lifecycle),
            bytes(12),
            Value::Array(vec![bytes(1)]),
            Value::Array(vec![bytes(2)]),
            Value::Array(vec![encoded_fixture_descriptor_value()]),
            Value::Array(vec![Value::Array(vec![uint(0), bytes(99)])]),
            protocol(),
            requirements(),
            bytes(17),
            bytes(18),
            bytes(19),
            Value::Null,
        ];
        if with_stable_evidence {
            // Stable evidence is a sidecar, not an undocumented CPF1 field.
            // Keep this optional fixture as an explicit extra-field rejection.
            fields.push(Value::Array(vec![stable_evidence()]));
        }
        fields.push(Value::Bytes(vec![1]));
        encode(&Value::Array(fields))
    }

    /// Builds a complete EVR1 verification-request fixture.
    ///
    /// # Errors
    ///
    /// Returns an error when encoding the fixture as CBOR fails.
    #[must_use = "request fixture bytes must be used by the contract exercise"]
    pub fn request() -> Result<Vec<u8>, Box<dyn std::error::Error>> {
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
    report.report_digest = report
        .digest()
        .expect("constructed public report fixture must be encodable");
    report
}

fn profile_without_matrix_binding() -> ConformanceProfileV1 {
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
        profile_id: "pigloros.w8.knowledge-non-interference.1.0.0".to_owned(),
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
                max_member_path_bytes: 128,
                max_member_bytes: 64 * 1024 * 1024,
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
        stable_evidence: Vec::new(),
        profile_digest: [0; 32],
    };
    profile.profile_digest = profile.digest();
    profile
}

fn profile_for_digest() -> ConformanceProfileV1 {
    let mut profile = profile_without_matrix_binding();
    assert_eq!(profile.bind_execution_matrix_digest([1; 32]), Ok(()));
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
fn public_report_validation_and_encoding_cover_empty_and_large_boundaries(
) -> Result<(), Box<dyn std::error::Error>> {
    let empty = report_with_cases(0);
    assert_eq!(
        empty.validate(),
        Err(pos_conformance::EvidenceError::InvalidConformanceReport)
    );

    let ordinary = report_with_cases(128);
    let ordinary_bytes = ordinary.to_canonical_cbor()?;
    assert!(ordinary_bytes.len() > 17_408);
    assert_eq!(
        ConformanceReportV1::from_canonical_cbor(&ordinary_bytes),
        Ok(ordinary)
    );

    let large = report_with_cases(7_000);
    let large_bytes = large.to_canonical_cbor()?;
    assert!(large_bytes.len() > 1_048_592);

    let exact_case_cap = report_with_cases(65_536);
    assert_eq!(exact_case_cap.validate(), Ok(()));
    Ok(())
}

#[test]
fn public_trusted_root_policy_accepts_exact_root_cap_and_rejects_one_more() {
    let mut exact = pos_conformance::TrustedRootPolicyV1 {
        trusted_root_public_keys: (1_u8..=64).map(|seed| [seed; 32]).collect(),
        trust_policy_snapshot_digest: [0; 32],
    };
    exact.trust_policy_snapshot_digest = exact.digest();
    assert_eq!(exact.validate(), Ok(()));

    let mut oversized = exact;
    oversized.trusted_root_public_keys.push([65; 32]);
    oversized.trust_policy_snapshot_digest = oversized.digest();
    assert_eq!(
        oversized.validate(),
        Err(ConformanceContractError::IndependenceEvidenceMissing)
    );
}

#[test]
fn public_profile_digest_normalizes_stable_lifecycle_to_selected_identity() {
    let mut candidate = profile_for_digest();
    candidate.lifecycle = pos_conformance::ProfileLifecycleV1::Candidate;
    candidate.profile_digest = candidate.digest();
    let mut stable = candidate.clone();
    stable.lifecycle = pos_conformance::ProfileLifecycleV1::Stable;
    stable.profile_digest = stable.digest();
    assert_eq!(stable.digest(), candidate.digest());
}

#[test]
fn public_profile_matrix_binding_is_content_addressed_and_fail_closed(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut bound = profile_without_matrix_binding();
    let unbound_digest = bound.digest();
    let matrix_digest = *blake3::hash(b"adr-059-execution-matrix").as_bytes();

    assert_eq!(
        bound.execution_matrix_digest(),
        Err(ConformanceContractError::FieldOutOfBounds)
    );
    assert_eq!(
        bound.validate(),
        Err(ConformanceContractError::FieldOutOfBounds)
    );
    assert_eq!(
        bound.bind_execution_matrix_digest([0; 32]),
        Err(ConformanceContractError::FieldOutOfBounds)
    );
    assert_eq!(
        bound.execution_matrix_digest(),
        Err(ConformanceContractError::FieldOutOfBounds)
    );

    assert_eq!(bound.bind_execution_matrix_digest(matrix_digest), Ok(()));
    assert!(bound
        .profile_id
        .starts_with("pigloros.w8.knowledge-non-interference.1.0.0#matrix="));
    assert_eq!(bound.execution_matrix_digest(), Ok(matrix_digest));
    assert_ne!(bound.profile_digest, unbound_digest);
    let encoded = bound.to_canonical_cbor()?;
    assert_eq!(
        ConformanceProfileV1::from_canonical_cbor(&encoded),
        Ok(bound.clone())
    );

    let mut different_matrix = profile_without_matrix_binding();
    assert_eq!(
        different_matrix.bind_execution_matrix_digest([7; 32]),
        Ok(())
    );
    assert_ne!(bound.profile_digest, different_matrix.profile_digest);

    for profile_id in [
        "pigloros.w8.artifact-integrity.1.0.0",
        "pigloros.w8.replay-conformance.1.0.0",
        "pigloros.w8.gateway-client-conformance.1.0.0",
        "pigloros.w8.plugin-conformance.1.0.0",
        "pigloros.w8.metric-conformance.1.0.0",
        "pigloros.w8.empirical-evaluation.1.0.0",
    ] {
        let mut non_knowledge = profile_without_matrix_binding();
        non_knowledge.profile_id = profile_id.to_owned();
        non_knowledge.profile_digest = non_knowledge.digest();
        assert_eq!(
            non_knowledge.bind_execution_matrix_digest([1; 32]),
            Err(ConformanceContractError::FieldOutOfBounds)
        );
        assert_eq!(non_knowledge.validate(), Ok(()));
    }

    let mut mismatched = bound.clone();
    assert_eq!(mismatched.bind_execution_matrix_digest([8; 32]), Ok(()));
    mismatched.profile_digest = bound.profile_digest;
    assert_eq!(
        mismatched.validate(),
        Err(ConformanceContractError::FixtureDigestMismatch)
    );
    Ok(())
}

#[test]
fn public_profile_matrix_binding_rejects_malformed_suffixes() {
    let mut malformed = profile_without_matrix_binding();
    malformed.profile_id.push_str("#matrix=not-a-digest");
    malformed.profile_digest = malformed.digest();
    assert_eq!(
        malformed.execution_matrix_digest(),
        Err(ConformanceContractError::FieldOutOfBounds)
    );
    assert_eq!(
        malformed.validate(),
        Err(ConformanceContractError::FieldOutOfBounds)
    );
}

#[test]
fn public_profile_matrix_binding_rejects_invalid_hex_zero_and_overlong_ids() {
    let mut invalid_hex = profile_without_matrix_binding();
    invalid_hex.profile_id.push_str("#matrix=");
    invalid_hex.profile_id.push_str(&"g".repeat(64));
    invalid_hex.profile_digest = invalid_hex.digest();
    assert_eq!(
        invalid_hex.execution_matrix_digest(),
        Err(ConformanceContractError::FieldOutOfBounds)
    );

    let mut uppercase = profile_without_matrix_binding();
    uppercase.profile_id = format!(
        "pigloros.w8.knowledge-non-interference.1.0.0#matrix={}",
        "AB".repeat(32)
    );
    assert_eq!(uppercase.execution_matrix_digest(), Ok([0xab; 32]));

    let mut duplicate_marker = profile_without_matrix_binding();
    duplicate_marker.profile_id.push_str("#matrix=");
    duplicate_marker.profile_id.push_str(&"0".repeat(32));
    duplicate_marker.profile_id.push_str("#matrix=");
    assert_eq!(
        duplicate_marker.execution_matrix_digest(),
        Err(ConformanceContractError::FieldOutOfBounds)
    );

    let mut empty_base = profile_without_matrix_binding();
    empty_base.profile_id = "#matrix=".to_owned();
    assert_eq!(
        empty_base.execution_matrix_digest(),
        Err(ConformanceContractError::FieldOutOfBounds)
    );

    let mut zero = profile_without_matrix_binding();
    zero.profile_id.push_str("#matrix=");
    zero.profile_id.push_str(&"0".repeat(64));
    zero.profile_digest = zero.digest();
    assert_eq!(
        zero.execution_matrix_digest(),
        Err(ConformanceContractError::FieldOutOfBounds)
    );

    let mut overlong = profile_without_matrix_binding();
    overlong.profile_id = "p".repeat(256);
    assert_eq!(
        overlong.bind_execution_matrix_digest([1; 32]),
        Err(ConformanceContractError::FieldOutOfBounds)
    );

    let mut malformed_rebind = profile_without_matrix_binding();
    malformed_rebind.profile_id.push_str("#matrix=short");
    assert_eq!(
        malformed_rebind.bind_execution_matrix_digest([1; 32]),
        Err(ConformanceContractError::FieldOutOfBounds)
    );
}

#[test]
fn public_stable_evidence_decoder_rejects_oversized_profile_before_policy_use() {
    let oversized = vec![0_u8; 16 * 1024 * 1024 + 1];
    let policy = TrustedRootPolicyV1 {
        trusted_root_public_keys: Vec::new(),
        trust_policy_snapshot_digest: [0; 32],
    };
    assert_eq!(
        ConformanceProfileV1::from_canonical_cbor_with_stable_evidence(
            &oversized,
            Vec::new(),
            &policy,
        ),
        Err(ConformanceContractError::FieldOutOfBounds)
    );
}

#[test]
fn public_profile_digest_encodes_every_closed_case_outcome_variant() {
    let mut profile = profile_for_digest();
    let implementation = ImplementationIdentityV1 {
        implementation_id: "independent".to_owned(),
        source_digest: [1; 32],
        build_digest: [2; 32],
        binary_digest: [3; 32],
        public_contract_digest: [4; 32],
        organization_id: None,
    };
    let independence = IndependenceEvidenceV1 {
        technical_independent: true,
        authorship_independent: true,
        organizational_independent: false,
        declaration_digest: [5; 32],
        shared_code_audit_digest: [6; 32],
        reviewer_ids: vec!["reviewer".to_owned()],
    };
    let case_outcomes = [
        CaseOutcomeStatusV1::Skip,
        CaseOutcomeStatusV1::Unavailable,
        CaseOutcomeStatusV1::NotApplicable,
    ]
    .into_iter()
    .enumerate()
    .map(|(index, outcome)| ProfileCaseOutcomeV1 {
        case_id: format!("case-{index}"),
        fixture_digest: [7; 32],
        execution_profile_digest: [8; 32],
        mode: ExecutionModeV1::Local,
        claim_layer: ClaimLayerV1::ArtifactIntegrity,
        outcome,
        verification_outcome: VerificationOutcomeV1::UnverifiableArtifactsMissing,
        divergence_kind: None,
        first_coordinate: None,
        expected_digest: None,
        actual_digest: None,
        expected_error: None,
        actual_error: None,
        replay_claim: ReplayClaimV1::Exact,
        redaction_state: RedactionStateV1::None,
        provenance_digest: [9; 32],
    })
    .collect();
    profile.stable_evidence = vec![StableImplementationEvidenceV1 {
        implementation,
        independence,
        evaluator_protocol_digest: [10; 32],
        report: report_with_cases(1),
        case_outcomes,
        attestation: StableEvidenceAttestationV1 {
            signer_public_key: [11; 32],
            signature: [12; 64],
            trust_root_digest: [13; 32],
        },
    }];
    assert_ne!(profile.digest(), [0; 32]);
}

#[test]
fn public_stable_case_outcome_type_can_be_constructed_externally() {
    let outcome = ProfileCaseOutcomeV1 {
        case_id: "ART-001".to_owned(),
        fixture_digest: [1; 32],
        execution_profile_digest: [2; 32],
        mode: ExecutionModeV1::Local,
        claim_layer: ClaimLayerV1::ArtifactIntegrity,
        outcome: CaseOutcomeStatusV1::Pass,
        verification_outcome: VerificationOutcomeV1::VerifiedExact,
        divergence_kind: None,
        first_coordinate: None,
        expected_digest: Some([3; 32]),
        actual_digest: Some([3; 32]),
        expected_error: None,
        actual_error: None,
        replay_claim: ReplayClaimV1::Exact,
        redaction_state: RedactionStateV1::None,
        provenance_digest: [4; 32],
    };
    assert_eq!(outcome.case_id, "ART-001");
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

    let mut diagnostic_overflow = exact.clone();
    diagnostic_overflow.output_capability.diagnostic_bytes_limit += 1;
    diagnostic_overflow.output_capability.capability_digest =
        diagnostic_overflow.expected_output_capability_digest();
    diagnostic_overflow.request_digest = diagnostic_overflow.digest();
    assert_eq!(
        diagnostic_overflow.validate_with_hard_caps(&caps),
        Err(ConformanceContractError::FieldOutOfBounds)
    );

    let mut protocol_overflow = exact;
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

    let mut too_many_profiles = exact_profiles;
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
        .max_member_path_bytes = 12;
    exact_path.profile_digest = exact_path.digest();
    assert_eq!(exact_path.validate(), Ok(()));

    let mut short_path = exact_path;
    short_path
        .evaluator_protocol
        .hard_caps
        .max_member_path_bytes = 11;
    short_path.profile_digest = short_path.digest();
    assert_eq!(
        short_path.validate(),
        Err(ConformanceContractError::FieldOutOfBounds)
    );
}

#[test]
fn exported_decoders_reject_terminal_digest_after_nested_decode(
) -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(
        ConformanceProfileV1::from_canonical_cbor(&fixtures::profile(0, false)?),
        Err(ConformanceContractError::InvalidEncoding)
    );
    assert_eq!(
        ConformanceProfileV1::from_canonical_cbor(&fixtures::profile(2, true)?),
        Err(ConformanceContractError::InvalidEncoding)
    );
    assert_eq!(
        EvaluatorRequestV1::from_canonical_cbor(&fixtures::request()?),
        Err(ConformanceContractError::InvalidEncoding)
    );
    Ok(())
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

fn profile_with_field(
    index: usize,
    replacement: Value,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut value = ciborium::from_reader(std::io::Cursor::new(fixtures::profile(0, false)?))?;
    let Value::Array(fields) = &mut value else {
        return Err("public profile fixture is not an array".into());
    };
    fields[index] = replacement;
    fixtures::encode(&value)
}

fn profile_with_fixture_field(
    index: usize,
    replacement: Value,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut value = ciborium::from_reader(std::io::Cursor::new(fixtures::profile(0, false)?))?;
    let Value::Array(fields) = &mut value else {
        return Err("public profile fixture is not an array".into());
    };
    let Value::Array(fixtures) = &mut fields[8] else {
        return Err("public profile fixture list is not an array".into());
    };
    let Value::Array(fixture) = &mut fixtures[0] else {
        return Err("public fixture descriptor is not an array".into());
    };
    fixture[index] = replacement;
    fixtures::encode(&value)
}

#[test]
fn public_profile_decoders_cover_nested_failure_shapes() -> Result<(), Box<dyn std::error::Error>> {
    let uint = |value: u64| Value::Integer(value.into());
    let bytes = |seed: u8| Value::Bytes(vec![seed; 32]);
    let expected_canonical = |first: Value, second: Value, digest: Value| {
        Value::Array(vec![first, second, digest, Value::Null, Value::Null])
    };
    let expected_divergence = |classification: Value, coordinate: Value| {
        Value::Array(vec![
            uint(2),
            Value::Null,
            Value::Null,
            Value::Null,
            Value::Array(vec![classification, coordinate]),
        ])
    };

    let malformed_profiles = [
        profile_with_field(9, Value::Array(vec![Value::Null]))?,
        profile_with_fixture_field(5, Value::Array(vec![uint(99)]))?,
        profile_with_fixture_field(8, Value::Array(vec![Value::Null; 5]))?,
        profile_with_fixture_field(8, expected_canonical(uint(0), Value::Null, bytes(5)))?,
        profile_with_fixture_field(8, expected_canonical(uint(0), bytes(5), Value::Null))?,
        profile_with_fixture_field(8, expected_divergence(Value::Null, Value::Bytes(vec![1])))?,
        profile_with_fixture_field(8, expected_divergence(uint(0), Value::Null))?,
        profile_with_field(16, Value::Null)?,
    ];

    for bytes in malformed_profiles {
        assert_eq!(
            ConformanceProfileV1::from_canonical_cbor(&bytes),
            Err(ConformanceContractError::InvalidEncoding)
        );
    }
    Ok(())
}

#[test]
fn public_profile_validation_covers_transition_and_authority_failures() {
    let profile = profile_for_digest();
    let policy = TrustedRootPolicyV1 {
        trusted_root_public_keys: vec![[42; 32]],
        trust_policy_snapshot_digest: [1; 32],
    };
    assert_eq!(
        profile.transition_to_with_trust_policy(
            pos_conformance::ProfileLifecycleV1::Draft,
            Vec::new(),
            &policy,
        ),
        Err(ConformanceContractError::ProfileLifecycleInvalid)
    );

    let caps = profile.evaluator_protocol.hard_caps.clone();
    let request = request_for_caps(&caps);
    let mut invalid_caps = caps;
    invalid_caps.max_profile_bytes = 0;
    assert_eq!(
        request.validate_with_hard_caps(&invalid_caps),
        Err(ConformanceContractError::FieldOutOfBounds)
    );

    let mut invalid_protocol = profile.evaluator_protocol.clone();
    invalid_protocol.protocol_id.clear();
    assert_eq!(
        request.validate_with_protocol(&invalid_protocol),
        Err(ConformanceContractError::ProvenanceMissing)
    );

    let mut invalid_protocol_caps = profile.evaluator_protocol;
    invalid_protocol_caps.hard_caps.max_profile_bytes = 0;
    assert_eq!(
        request.validate_with_protocol(&invalid_protocol_caps),
        Err(ConformanceContractError::FieldOutOfBounds)
    );
}
