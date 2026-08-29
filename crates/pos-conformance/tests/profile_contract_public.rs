#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

use ciborium::value::Value;
use pos_conformance::{
    ArtifactDescriptorV1, CapabilityPolicyV1, CaseOutcomeStatusV1, CaseOutcomeV1, ClaimLayerV1,
    ConformanceContractError, ConformanceProfileV1, ConformanceReportV1, DeterministicBudgetV1,
    ErasureDispositionV1, EvaluatorHardCapsV1, EvaluatorOutputCapabilityV1, EvaluatorProtocolV1,
    EvaluatorRequestV1, ExecutionModeV1, FixtureDescriptorV1, FixtureFamilyV1, FixtureProvenanceV1,
    FixtureProviderKeyV1, FixtureProviderRegistryBindingV1, ImplementationIdentityV1,
    IndependenceEvidenceV1, IndependenceRequirementsV1, OperationalSafetyV1, ProfileCaseOutcomeV1,
    RedactionStateV1, ReplayClaimV1, StableEvidenceAttestationV1, StableImplementationEvidenceV1,
    StrictOracleKindV1, StrictOracleV1, SubjectAdapterKindV1, TrustedRootPolicyV1,
    VerificationOutcomeV1,
};

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
            text("art-001"),
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
            text("art-001"),
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
            text("art-001"),
            Value::Bool(true),
            uint(0),
            uint(0),
            Value::Array(vec![
                text("pigloros.fixture.artifact-integrity"),
                text("1.0.0"),
                uint(1),
                uint(0),
            ]),
            uint(0),
            bytes(1),
            Value::Array(vec![uint(0), uint(1)]),
            Value::Array(vec![
                text("support/schemas/positive.schema.json"),
                text("application/schema+json"),
                uint(1),
                bytes(2),
            ]),
            Value::Array(vec![
                text("inputs/artifact-integrity/positive.json"),
                text("application/json"),
                uint(1),
                bytes(3),
            ]),
            Value::Array(vec![]),
            Value::Array(vec![
                uint(0),
                Value::Array(vec![
                    text("expected/artifact-integrity/positive.cbor"),
                    text("application/cbor"),
                    uint(1),
                    bytes(4),
                ]),
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
            Value::Array(vec![uint(1)]),
            Value::Array(vec![
                Value::Bool(false),
                Value::Array(vec![text("read-public-bundle")]),
            ]),
            Value::Null,
            Value::Null,
            Value::Array(vec![
                text("MIT"),
                bytes(6),
                bytes(7),
                bytes(8),
                bytes(9),
                bytes(10),
                bytes(11),
            ]),
            Value::Null,
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
    pub fn cpf1_profile_rejection_fixture(
        lifecycle: u64,
        with_stable_evidence: bool,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let mut fields = vec![
            text("CPF1"),
            uint(1),
            text("pigloros.w8.knowledge-non-interference.1.0.0"),
            text("1.0.0"),
            uint(lifecycle),
            bytes(12),
            bytes(20),
            Value::Array(vec![bytes(1)]),
            Value::Array(vec![
                Value::Array(vec![
                    text("authority/fixture-provider-registry.cbor"),
                    text("application/cbor"),
                    uint(1),
                    bytes(2),
                ]),
                Value::Array(vec![Value::Array(vec![
                    text("pigloros.fixture.artifact-integrity"),
                    text("1.0.0"),
                    uint(1),
                    uint(0),
                ])]),
            ]),
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

fn report_with_cases(count: usize) -> Result<ConformanceReportV1, pos_conformance::EvidenceError> {
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
    report.report_digest = report.digest()?;
    Ok(report)
}

fn knowledge_non_interference_profile() -> ConformanceProfileV1 {
    let expected = b"expected".to_vec();
    let provider_key = FixtureProviderKeyV1 {
        provider_id: "pigloros.fixture.artifact-integrity".to_owned(),
        contract_version: "1.0.0".to_owned(),
        abi_major: 1,
        abi_minor: 0,
    };
    let mut fixture = FixtureDescriptorV1 {
        case_id: "art-001".to_owned(),
        mandatory: true,
        claim_layer: ClaimLayerV1::ArtifactIntegrity,
        family: FixtureFamilyV1::Positive,
        provider_key: provider_key.clone(),
        subject_adapter: SubjectAdapterKindV1::ExportedArtifact,
        execution_profile_digest: [1; 32],
        modes: vec![ExecutionModeV1::Local],
        schema: ArtifactDescriptorV1 {
            member_path: "support/schemas/positive.schema.json".to_owned(),
            media_type: "application/schema+json".to_owned(),
            byte_length: 1,
            blake3_digest: [2; 32],
        },
        payload: ArtifactDescriptorV1 {
            member_path: "inputs/artifact-integrity/positive.json".to_owned(),
            media_type: "application/json".to_owned(),
            byte_length: 1,
            blake3_digest: [3; 32],
        },
        auxiliary: Vec::new(),
        strict_oracle: StrictOracleV1 {
            kind: StrictOracleKindV1::Output,
            output: Some(ArtifactDescriptorV1 {
                member_path: "expected/artifact-integrity/positive.cbor".to_owned(),
                media_type: "application/cbor".to_owned(),
                byte_length: expected.len() as u64,
                blake3_digest: *blake3::hash(&expected).as_bytes(),
            }),
            failure: None,
            divergence: None,
        },
        expected_verification_outcome: VerificationOutcomeV1::VerifiedExact,
        expected_verification_error: None,
        replay_claim: ReplayClaimV1::Exact,
        redaction_state: RedactionStateV1::None,
        deterministic_budget: DeterministicBudgetV1 {
            memory_bytes: 1,
            cpu_fuel: 1,
            host_calls: 1,
            event_count: 1,
            output_bytes: 1024,
            storage_bytes: 1,
            execution_steps: 1,
            simulation_time_ns: 1,
        },
        operational_safety: OperationalSafetyV1 { watchdog_ms: 1 },
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
        trust_policy_snapshot_digest: None,
        release_admission_digest: None,
        transition: None,
        fixture_digest: [0; 32],
    };
    fixture.fixture_digest = fixture.digest();
    knowledge_profile(provider_key, fixture)
}

fn knowledge_profile(
    provider_key: FixtureProviderKeyV1,
    fixture: FixtureDescriptorV1,
) -> ConformanceProfileV1 {
    let mut profile = ConformanceProfileV1 {
        profile_id: "pigloros.w8.knowledge-non-interference.1.0.0".to_owned(),
        semantic_version: "1.0.0".to_owned(),
        lifecycle: pos_conformance::ProfileLifecycleV1::Draft,
        normative_spec_digest: [12; 32],
        execution_matrix_digest: [21; 32],
        execution_profile_digests: vec![[1; 32]],
        fixture_provider_registry: FixtureProviderRegistryBindingV1 {
            registry_artifact: ArtifactDescriptorV1 {
                member_path: "authority/fixture-provider-registry.cbor".to_owned(),
                media_type: "application/cbor".to_owned(),
                byte_length: 1,
                blake3_digest: [11; 32],
            },
            required_provider_keys: vec![provider_key],
        },
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
        fixture_contract_policy_digest: [18; 32],
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
    knowledge_non_interference_profile()
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
    let empty = report_with_cases(0)?;
    assert_eq!(
        empty.validate(),
        Err(pos_conformance::EvidenceError::InvalidConformanceReport)
    );

    let ordinary = report_with_cases(128)?;
    let ordinary_bytes = ordinary.to_canonical_cbor()?;
    assert!(ordinary_bytes.len() > 17_408);
    assert_eq!(
        ConformanceReportV1::from_canonical_cbor(&ordinary_bytes),
        Ok(ordinary)
    );

    let large = report_with_cases(7_000)?;
    let large_bytes = large.to_canonical_cbor()?;
    assert!(large_bytes.len() > 1_048_592);

    let exact_case_cap = report_with_cases(65_536)?;
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
fn public_profile_digest_commits_the_exact_lifecycle() {
    let mut candidate = profile_for_digest();
    candidate.lifecycle = pos_conformance::ProfileLifecycleV1::Candidate;
    candidate.profile_digest = candidate.digest();
    let mut stable = candidate.clone();
    stable.lifecycle = pos_conformance::ProfileLifecycleV1::Stable;
    stable.profile_digest = stable.digest();
    assert_ne!(stable.digest(), candidate.digest());
}

#[test]
fn public_draft_profile_requires_the_mandatory_fixture_inventory() {
    let mut profile = knowledge_non_interference_profile();
    profile.fixtures.clear();
    profile.profile_digest = profile.digest();
    assert_eq!(
        profile.validate(),
        Err(ConformanceContractError::ExpectedResultMissing)
    );
}

#[test]
fn public_profile_matrix_binding_is_explicit_and_fail_closed(
) -> Result<(), Box<dyn std::error::Error>> {
    let profile = knowledge_non_interference_profile();
    assert_eq!(profile.validate(), Ok(()));
    assert_eq!(profile.execution_matrix_digest, [21; 32]);
    let encoded = profile.to_canonical_cbor()?;
    let Value::Array(fields) = ciborium::from_reader(encoded.as_slice())? else {
        return Err("CPF1 profile encoding must be an array".into());
    };
    assert_eq!(fields.len(), 18);
    assert_eq!(fields[0], Value::Text("CPF1".to_owned()));
    assert_eq!(fields[1], Value::Integer(1_u64.into()));
    assert_eq!(fields[2], Value::Text(profile.profile_id.clone()));
    assert_eq!(fields[6], Value::Bytes([21; 32].to_vec()));
    assert_eq!(
        ConformanceProfileV1::from_canonical_cbor(&encoded),
        Ok(profile.clone())
    );

    let mut missing = profile.clone();
    missing.execution_matrix_digest = [0; 32];
    missing.profile_digest = missing.digest();
    assert_eq!(
        missing.validate(),
        Err(ConformanceContractError::FieldOutOfBounds)
    );

    let mut substituted = profile.clone();
    substituted.execution_matrix_digest = [7; 32];
    substituted.profile_digest = profile.profile_digest;
    assert_eq!(
        substituted.validate(),
        Err(ConformanceContractError::FixtureDigestMismatch)
    );
    Ok(())
}

#[test]
fn public_profile_rejects_matrix_suffix_and_unknown_format(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut matrix_suffix = knowledge_non_interference_profile();
    matrix_suffix.profile_id.push_str("#matrix=0101");
    matrix_suffix.profile_digest = matrix_suffix.digest();
    assert_eq!(
        matrix_suffix.validate(),
        Err(ConformanceContractError::FieldOutOfBounds)
    );

    let profile_bytes = fixtures::cpf1_profile_rejection_fixture(0, false)?;
    let mut value: Value = ciborium::from_reader(profile_bytes.as_slice())?;
    let Value::Array(profile_fields) = &mut value else {
        return Err("profile fixture must be an array".into());
    };
    profile_fields.remove(6);
    profile_fields[0] = Value::Text("CPFX".to_owned());
    profile_fields[1] = Value::Integer(1_u64.into());
    let fields = fixtures::encode(&value)?;
    assert_eq!(
        ConformanceProfileV1::from_canonical_cbor(&fields),
        Err(ConformanceContractError::UnsupportedVersion)
    );
    Ok(())
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
fn public_profile_digest_encodes_every_closed_case_outcome_variant(
) -> Result<(), Box<dyn std::error::Error>> {
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
        report: report_with_cases(1)?,
        case_outcomes,
        attestation: StableEvidenceAttestationV1 {
            signer_public_key: [11; 32],
            signature: [12; 64],
            trust_root_digest: [13; 32],
        },
    }];
    assert_ne!(profile.digest(), [0; 32]);
    Ok(())
}

#[test]
fn public_stable_case_outcome_type_can_be_constructed_externally() {
    let outcome = ProfileCaseOutcomeV1 {
        case_id: "art-001".to_owned(),
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
    assert_eq!(outcome.case_id, "art-001");
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
fn public_profile_caps_accept_exact_profile_and_member_path_limits(
) -> Result<(), Box<dyn std::error::Error>> {
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
    let longest_path = exact_path
        .fixtures
        .iter()
        .flat_map(|fixture| {
            [&fixture.schema, &fixture.payload]
                .into_iter()
                .chain(fixture.auxiliary.iter())
                .chain(fixture.strict_oracle.output.iter())
        })
        .map(|artifact| artifact.member_path.len())
        .chain(std::iter::once(
            exact_path
                .fixture_provider_registry
                .registry_artifact
                .member_path
                .len(),
        ))
        .max()
        .ok_or("profile must contain public artifacts")?;
    exact_path
        .evaluator_protocol
        .hard_caps
        .max_member_path_bytes = u16::try_from(longest_path)?;
    exact_path.profile_digest = exact_path.digest();
    assert_eq!(exact_path.validate(), Ok(()));

    let mut short_path = exact_path;
    short_path
        .evaluator_protocol
        .hard_caps
        .max_member_path_bytes = u16::try_from(longest_path - 1)?;
    short_path.profile_digest = short_path.digest();
    assert_eq!(
        short_path.validate(),
        Err(ConformanceContractError::FieldOutOfBounds)
    );
    Ok(())
}

#[test]
fn public_profile_decoder_rejects_unsupported_and_oversized_encodings() {
    assert_eq!(
        ConformanceProfileV1::from_canonical_cbor(&[0x82, 0x64, b'B', b'A', b'D', b'1', 0x01]),
        Err(ConformanceContractError::UnsupportedVersion)
    );
    assert_eq!(
        ConformanceProfileV1::from_canonical_cbor(&[
            0x5b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        ]),
        Err(ConformanceContractError::FieldOutOfBounds)
    );
}

#[test]
fn exported_decoders_reject_terminal_digest_after_nested_decode(
) -> Result<(), Box<dyn std::error::Error>> {
    let canonical = profile_for_digest().to_canonical_cbor()?;
    let Value::Array(mut malformed_cpf1) = ciborium::from_reader(canonical.as_slice())? else {
        return Err("canonical CPF1 profile encoding must be an array".into());
    };
    malformed_cpf1.truncate(14);
    assert_eq!(
        ConformanceProfileV1::from_canonical_cbor(&fixtures::encode(&Value::Array(
            malformed_cpf1,
        ))?),
        Err(ConformanceContractError::InvalidEncoding)
    );
    assert_eq!(
        ConformanceProfileV1::from_canonical_cbor(&fixtures::cpf1_profile_rejection_fixture(
            0, false
        )?,),
        Err(ConformanceContractError::InvalidEncoding)
    );
    assert_eq!(
        ConformanceProfileV1::from_canonical_cbor(&fixtures::cpf1_profile_rejection_fixture(
            2, true
        )?,),
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
    let mut value = ciborium::from_reader(std::io::Cursor::new(
        fixtures::cpf1_profile_rejection_fixture(0, false)?,
    ))?;
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
    let mut value = ciborium::from_reader(std::io::Cursor::new(
        fixtures::cpf1_profile_rejection_fixture(0, false)?,
    ))?;
    let Value::Array(fields) = &mut value else {
        return Err("public profile fixture is not an array".into());
    };
    let Value::Array(fixtures) = &mut fields[9] else {
        return Err("public profile fixture list is not an array".into());
    };
    let Value::Array(fixture) = &mut fixtures[0] else {
        return Err("public fixture descriptor is not an array".into());
    };
    fixture[index] = replacement;
    fixtures::encode(&value)
}

fn profile_with_nested_field(
    path: &[usize],
    replacement: Value,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut value: Value =
        ciborium::from_reader(fixtures::cpf1_profile_rejection_fixture(0, false)?.as_slice())?;
    let (field, parents) = path.split_last().ok_or("profile path must not be empty")?;
    let mut selected = &mut value;
    for index in parents {
        let Value::Array(fields) = selected else {
            return Err("profile path must select arrays".into());
        };
        selected = fields
            .get_mut(*index)
            .ok_or("profile path is out of bounds")?;
    }
    let Value::Array(fields) = selected else {
        return Err("profile path parent must be an array".into());
    };
    fields[*field] = replacement;
    fixtures::encode(&value)
}

fn assert_public_profile_paths_rejected(
    paths: impl IntoIterator<Item = Vec<usize>>,
) -> Result<(), Box<dyn std::error::Error>> {
    for path in paths {
        let bytes = profile_with_nested_field(&path, Value::Null)?;
        assert_eq!(
            ConformanceProfileV1::from_canonical_cbor(&bytes),
            Err(ConformanceContractError::InvalidEncoding),
            "nested field {path:?} unexpectedly decoded"
        );
    }
    Ok(())
}

#[test]
fn public_profile_decoders_cover_nested_failure_shapes() -> Result<(), Box<dyn std::error::Error>> {
    let text = |value: &str| Value::Text(value.to_owned());
    let uint = |value: u64| Value::Integer(value.into());
    let bytes = |seed: u8| Value::Bytes(vec![seed; 32]);
    let artifact = |path: Value, media_type: Value, length: Value, digest: Value| {
        Value::Array(vec![path, media_type, length, digest])
    };
    let output_oracle =
        |output: Value, failure: Value| Value::Array(vec![uint(0), output, failure, Value::Null]);
    let divergence_oracle = |classification: Value, coordinate: Value| {
        Value::Array(vec![
            uint(2),
            Value::Null,
            Value::Null,
            Value::Array(vec![classification, coordinate]),
        ])
    };

    let malformed_profiles = [
        fixtures::encode(&Value::Null)?,
        profile_with_field(9, Value::Array(vec![Value::Null]))?,
        profile_with_fixture_field(7, Value::Array(vec![Value::Null]))?,
        profile_with_fixture_field(7, Value::Array(vec![uint(99)]))?,
        profile_with_fixture_field(8, Value::Array(vec![Value::Null; 4]))?,
        profile_with_fixture_field(
            8,
            artifact(Value::Null, text("application/json"), uint(1), bytes(5)),
        )?,
        profile_with_fixture_field(11, output_oracle(Value::Null, Value::Null))?,
        profile_with_fixture_field(
            11,
            output_oracle(
                artifact(
                    text("expected/result.cbor"),
                    text("application/cbor"),
                    uint(1),
                    bytes(5),
                ),
                Value::Array(vec![text("pigloros.core"), text("1.0.0"), text("failure")]),
            ),
        )?,
        profile_with_fixture_field(11, divergence_oracle(Value::Null, Value::Bytes(vec![1])))?,
        profile_with_fixture_field(11, divergence_oracle(uint(0), Value::Null))?,
    ];

    for bytes in malformed_profiles {
        assert_eq!(
            ConformanceProfileV1::from_canonical_cbor(&bytes),
            Err(ConformanceContractError::InvalidEncoding)
        );
    }

    let mut malformed_request: Value = ciborium::from_reader(fixtures::request()?.as_slice())?;
    let Value::Array(request_fields) = &mut malformed_request else {
        return Err("public request fixture is not an array".into());
    };
    let Some(Value::Array(identity)) = request_fields.get_mut(7) else {
        return Err("public request identity is not an array".into());
    };
    identity[5] = uint(1);
    assert_eq!(
        EvaluatorRequestV1::from_canonical_cbor(&fixtures::encode(&malformed_request)?),
        Err(ConformanceContractError::InvalidEncoding)
    );
    Ok(())
}

#[test]
fn public_profile_decoder_rejects_each_nested_record_field(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut paths = Vec::new();
    paths.extend((0..4).map(|index| vec![8, 0, index]));
    paths.extend((0..4).map(|index| vec![8, 1, 0, index]));
    paths.extend((0..4).map(|index| vec![9, 0, 4, index]));
    paths.extend((0..4).map(|index| vec![9, 0, 8, index]));
    paths.extend((0..4).map(|index| vec![9, 0, 9, index]));
    paths.extend((0..4).map(|index| vec![9, 0, 11, index]));
    paths.extend((0..4).map(|index| vec![9, 0, 11, 1, index]));
    paths.extend((0..8).map(|index| vec![9, 0, 16, index]));
    paths.extend((0..1).map(|index| vec![9, 0, 17, index]));
    paths.extend((0..2).map(|index| vec![9, 0, 18, index]));
    paths.extend((0..7).map(|index| vec![9, 0, 21, index]));
    paths.extend((0..5).map(|index| vec![11, index]));
    paths.extend((0..10).map(|index| vec![11, 4, index]));
    paths.extend((0..5).map(|index| vec![12, index]));
    assert_public_profile_paths_rejected(paths)?;

    for index in 0..18 {
        let bytes = profile_with_nested_field(&[index], Value::Bool(true))?;
        assert!(ConformanceProfileV1::from_canonical_cbor(&bytes).is_err());
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
