#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

use ciborium::value::Value;
use ed25519_dalek::{Signer, SigningKey};
use pos_conformance::{
    AllowedDivergenceV1, ArtifactDescriptorV1, CapabilityPolicyV1, CaseOutcomeStatusV1,
    CaseOutcomeV1, ClaimLayerV1, ConformanceContractError, ConformanceProfileV1,
    ConformanceReportV1, DeterministicBudgetV1, DivergenceMismatchKindV1, ErasureDispositionV1,
    EvaluatorHardCapsV1, EvaluatorOutputCapabilityV1, EvaluatorProtocolV1, EvaluatorRequestV1,
    ExecutionModeV1, FixtureDescriptorV1, FixtureFamilyV1, FixtureProvenanceV1,
    FixtureProviderKeyV1, FixtureProviderRegistryBindingV1, ImplementationIdentityV1,
    IndependenceEvidenceV1, IndependenceRequirementsV1, NamespacedFailureV1, OperationalSafetyV1,
    ProfileCaseOutcomeV1, RedactionStateV1, ReplayClaimV1, SafeErrorCodeV1,
    StableEvidenceAttestationV1, StableImplementationEvidenceV1, StrictOracleKindV1,
    StrictOracleV1, SubjectAdapterKindV1, TrustedRootPolicyV1, VerificationOutcomeV1,
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

fn canonical_value(value: &Value) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    fixtures::encode(value)
}

fn domain_digest(domain: &[u8], value: &Value) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    let bytes = canonical_value(value)?;
    let mut input = Vec::with_capacity(domain.len() + bytes.len() + 1);
    input.extend_from_slice(domain);
    input.push(0);
    input.extend_from_slice(&bytes);
    Ok(*blake3::hash(&input).as_bytes())
}

fn contract_digest(domain: &[u8], value: &Value) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    let bytes = canonical_value(value)?;
    let length = u64::try_from(bytes.len())?.to_be_bytes();
    let mut input = Vec::with_capacity(domain.len() + length.len() + bytes.len() + 1);
    input.extend_from_slice(domain);
    input.push(0);
    input.extend_from_slice(&length);
    input.extend_from_slice(&bytes);
    Ok(*blake3::hash(&input).as_bytes())
}

fn fixture_bundle_digest(
    profile: &ConformanceProfileV1,
) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    let mut encodable = profile.clone();
    encodable.lifecycle = pos_conformance::ProfileLifecycleV1::Draft;
    encodable.stable_evidence.clear();
    encodable.profile_digest = encodable.digest();
    let bytes = encodable.to_canonical_cbor()?;
    let Value::Array(fields) = ciborium::from_reader(bytes.as_slice())? else {
        return Err("CPF1 profile must encode as an array".into());
    };
    let Some(Value::Array(fixtures)) = fields.get(9) else {
        return Err("CPF1 fixture inventory must be an array".into());
    };
    contract_digest(
        b"PiglorOS.ConformanceFixtureBundle.v1",
        &Value::Array(fixtures.clone()),
    )
}

fn request_for_profile(
    profile: &ConformanceProfileV1,
) -> Result<EvaluatorRequestV1, Box<dyn std::error::Error>> {
    let caps = &profile.evaluator_protocol.hard_caps;
    let mut request = request_for_caps(caps);
    request.conformance_profile_digest = profile.profile_digest;
    request.fixture_bundle_digest = fixture_bundle_digest(profile)?;
    request.subject_adapter = profile.fixtures[0].subject_adapter;
    request.execution_profile_digest = profile.execution_profile_digests[0];
    request.trust_policy_snapshot_digest = profile
        .independence_requirements
        .trust_policy_snapshot_digest;
    request.evaluator_protocol_digest = profile.evaluator_protocol.protocol_digest;
    request.evaluator_hard_caps_digest = caps.digest();
    request.output_capability.capability_digest = request.expected_output_capability_digest();
    request.request_digest = request.digest();
    Ok(request)
}

fn refresh(profile: &mut ConformanceProfileV1) {
    for fixture in &mut profile.fixtures {
        fixture.fixture_digest = fixture.digest();
    }
    profile.profile_digest = profile.digest();
}

fn profile_case_value(case: &ProfileCaseOutcomeV1) -> Value {
    Value::Array(vec![
        Value::Text(case.case_id.clone()),
        Value::Bytes(case.fixture_digest.to_vec()),
        Value::Bytes(case.execution_profile_digest.to_vec()),
        wire_value(match case.mode {
            ExecutionModeV1::Local => 0,
            ExecutionModeV1::AirGapped => 1,
            ExecutionModeV1::Replay => 2,
            ExecutionModeV1::Fork => 3,
        }),
        Value::Integer(u64::from(case.claim_layer.wire_code()).into()),
        wire_value(match case.outcome {
            CaseOutcomeStatusV1::Pass => 0,
            CaseOutcomeStatusV1::Fail => 1,
            CaseOutcomeStatusV1::Skip => 2,
            CaseOutcomeStatusV1::Unavailable => 3,
            CaseOutcomeStatusV1::NotApplicable => 4,
        }),
        wire_value(match case.verification_outcome {
            VerificationOutcomeV1::VerifiedExact => 0,
            VerificationOutcomeV1::Diverged => 1,
            VerificationOutcomeV1::InvalidManifest => 2,
            VerificationOutcomeV1::UnverifiableArtifactsMissing => 3,
            VerificationOutcomeV1::IncompatibleProfile => 4,
            VerificationOutcomeV1::ResourceLimitExceeded => 5,
        }),
        case.divergence_kind.map_or(Value::Null, |kind| {
            wire_value(match kind {
                DivergenceMismatchKindV1::EventIdentity => 0,
                DivergenceMismatchKindV1::EventOrder => 1,
                DivergenceMismatchKindV1::CanonicalBytes => 2,
                DivergenceMismatchKindV1::ProjectionCheckpoint => 3,
                DivergenceMismatchKindV1::TypedFailure => 4,
                DivergenceMismatchKindV1::Artifact => 5,
                DivergenceMismatchKindV1::SchemaOrUpcaster => 6,
                DivergenceMismatchKindV1::NumericProfile => 7,
                DivergenceMismatchKindV1::ProhibitedOperationalInput => 8,
            })
        }),
        case.first_coordinate
            .as_ref()
            .map_or(Value::Null, |value| Value::Bytes(value.clone())),
        case.expected_digest
            .map_or(Value::Null, |digest| Value::Bytes(digest.to_vec())),
        case.actual_digest
            .map_or(Value::Null, |digest| Value::Bytes(digest.to_vec())),
        case.expected_error.map_or(Value::Null, safe_error_value),
        case.actual_error.map_or(Value::Null, safe_error_value),
        wire_value(match case.replay_claim {
            ReplayClaimV1::Exact => 0,
            ReplayClaimV1::ExactAuthoritativeWithRedactedViews => 1,
            ReplayClaimV1::StructuralOnly => 2,
            ReplayClaimV1::UnverifiableArtifactsMissing => 3,
            ReplayClaimV1::IncompatibleProfile => 4,
        }),
        wire_value(match case.redaction_state {
            RedactionStateV1::None => 0,
            RedactionStateV1::RedactedViews => 1,
            RedactionStateV1::StructuralOnly => 2,
            RedactionStateV1::EvidenceMissing => 3,
        }),
        Value::Bytes(case.provenance_digest.to_vec()),
    ])
}

fn wire_value(code: u64) -> Value {
    Value::Integer(code.into())
}

fn safe_error_value(error: SafeErrorCodeV1) -> Value {
    wire_value(match error {
        SafeErrorCodeV1::InvalidEncoding => 0,
        SafeErrorCodeV1::UnsupportedVersion => 1,
        SafeErrorCodeV1::FieldOutOfBounds => 2,
        SafeErrorCodeV1::NonCanonicalOrder => 3,
        SafeErrorCodeV1::DigestMismatch => 4,
        SafeErrorCodeV1::SignatureInvalid => 5,
        SafeErrorCodeV1::TrustRootUnknown => 6,
        SafeErrorCodeV1::TrustSnapshotRollback => 7,
        SafeErrorCodeV1::ArtifactRevoked => 8,
        SafeErrorCodeV1::ClosureIncomplete => 9,
        SafeErrorCodeV1::ProfileClassMismatch => 10,
        SafeErrorCodeV1::ProfileUnsupported => 11,
        SafeErrorCodeV1::ProvenanceMissing => 12,
        SafeErrorCodeV1::ResourceLimitExceeded => 13,
    })
}

type ProfileMutation = Box<dyn Fn(&mut ConformanceProfileV1)>;
type RequestMutation = Box<dyn Fn(&mut EvaluatorRequestV1)>;

fn fixture_provenance_digest(
    provenance: &FixtureProvenanceV1,
) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    domain_digest(
        b"PiglorOS.ConformanceFixtureProvenance.v1",
        &Value::Array(vec![
            Value::Text(provenance.licence_id.clone()),
            Value::Bytes(provenance.notices_digest.to_vec()),
            Value::Bytes(provenance.sbom_digest.to_vec()),
            Value::Bytes(provenance.source_digest.to_vec()),
            Value::Bytes(provenance.build_digest.to_vec()),
            Value::Bytes(provenance.publication_review_digest.to_vec()),
            Value::Bytes(provenance.limitations_digest.to_vec()),
        ]),
    )
}

fn stable_case(
    profile: &ConformanceProfileV1,
) -> Result<ProfileCaseOutcomeV1, Box<dyn std::error::Error>> {
    let fixture = profile
        .fixtures
        .first()
        .ok_or("stable profile needs a fixture")?;
    let exact_digest = fixture
        .strict_oracle
        .output
        .as_ref()
        .map_or(fixture.payload.blake3_digest, |output| output.blake3_digest);
    let divergence = fixture.strict_oracle.divergence.as_ref();
    let (expected_digest, actual_digest) = if divergence.is_some() {
        (
            Some(fixture.schema.blake3_digest),
            Some(fixture.payload.blake3_digest),
        )
    } else {
        (Some(exact_digest), Some(exact_digest))
    };
    Ok(ProfileCaseOutcomeV1 {
        case_id: fixture.case_id.clone(),
        fixture_digest: fixture.digest(),
        execution_profile_digest: fixture.execution_profile_digest,
        mode: ExecutionModeV1::Local,
        claim_layer: fixture.claim_layer,
        outcome: CaseOutcomeStatusV1::Pass,
        verification_outcome: fixture.expected_verification_outcome,
        divergence_kind: divergence.map(|value| value.classification),
        first_coordinate: divergence.map(|value| value.first_coordinate.clone()),
        expected_digest,
        actual_digest,
        expected_error: None,
        actual_error: None,
        replay_claim: fixture.replay_claim,
        redaction_state: fixture.redaction_state,
        provenance_digest: fixture_provenance_digest(&fixture.provenance)?,
    })
}

fn identity_value(identity: &ImplementationIdentityV1) -> Value {
    Value::Array(vec![
        Value::Text(identity.implementation_id.clone()),
        Value::Bytes(identity.source_digest.to_vec()),
        Value::Bytes(identity.build_digest.to_vec()),
        Value::Bytes(identity.binary_digest.to_vec()),
        Value::Bytes(identity.public_contract_digest.to_vec()),
        identity
            .organization_id
            .as_ref()
            .map_or(Value::Null, |value| Value::Text(value.clone())),
    ])
}

fn independence_value(evidence: &IndependenceEvidenceV1) -> Value {
    Value::Array(vec![
        Value::Bool(evidence.technical_independent),
        Value::Bool(evidence.authorship_independent),
        Value::Bool(evidence.organizational_independent),
        Value::Bytes(evidence.declaration_digest.to_vec()),
        Value::Bytes(evidence.shared_code_audit_digest.to_vec()),
        Value::Array(
            evidence
                .reviewer_ids
                .iter()
                .cloned()
                .map(Value::Text)
                .collect(),
        ),
    ])
}

fn stable_attestation_payload(
    evidence: &StableImplementationEvidenceV1,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    canonical_value(&Value::Array(vec![
        identity_value(&evidence.implementation),
        independence_value(&evidence.independence),
        Value::Bytes(evidence.evaluator_protocol_digest.to_vec()),
        Value::Bytes(evidence.report.report_digest.to_vec()),
        Value::Array(
            evidence
                .case_outcomes
                .iter()
                .map(profile_case_value)
                .collect(),
        ),
        Value::Bytes(evidence.attestation.signer_public_key.to_vec()),
        Value::Bytes(evidence.attestation.trust_root_digest.to_vec()),
    ]))
}

fn stable_evidence(
    profile: &ConformanceProfileV1,
    implementation_id: &str,
    seed: u8,
    signing_key: &SigningKey,
) -> Result<StableImplementationEvidenceV1, Box<dyn std::error::Error>> {
    let implementation = ImplementationIdentityV1 {
        implementation_id: implementation_id.to_owned(),
        source_digest: [seed; 32],
        build_digest: [seed.saturating_add(1); 32],
        binary_digest: [seed.saturating_add(2); 32],
        public_contract_digest: [77; 32],
        organization_id: None,
    };
    let independence = IndependenceEvidenceV1 {
        technical_independent: true,
        authorship_independent: true,
        organizational_independent: false,
        declaration_digest: [seed.saturating_add(3); 32],
        shared_code_audit_digest: [seed.saturating_add(4); 32],
        reviewer_ids: vec![format!("reviewer-{seed}")],
    };
    let profile_case = stable_case(profile)?;
    let report_case = CaseOutcomeV1 {
        case_id: profile_case.case_id.clone(),
        fixture_digest: profile_case.fixture_digest,
        execution_profile_digest: profile_case.execution_profile_digest,
        mode: profile_case.mode,
        claim_layer: profile_case.claim_layer,
        outcome: profile_case.outcome,
        first_coordinate: profile_case.first_coordinate.clone(),
        expected_digest: profile_case.expected_digest,
        actual_digest: profile_case.actual_digest,
        expected_error: profile_case.expected_error,
        actual_error: profile_case.actual_error,
        replay_claim: profile_case.replay_claim,
        redaction_state: profile_case.redaction_state,
        provenance_digest: profile_case.provenance_digest,
    };
    let mut report = ConformanceReportV1 {
        report_id: [seed; 16],
        subject_artifact_digest: [91; 32],
        profile_digest: profile.profile_digest,
        normative_spec_digest: profile.normative_spec_digest,
        execution_profile_digest: profile_case.execution_profile_digest,
        fixture_bundle_digest: fixture_bundle_digest(profile)?,
        evaluator_source_digest: [seed.saturating_add(5); 32],
        evaluator_binary_digest: [seed.saturating_add(6); 32],
        evaluator_protocol_digest: profile.evaluator_protocol.protocol_digest,
        implementation: implementation.clone(),
        independence: independence.clone(),
        cases: vec![report_case],
        passed: 1,
        failed: 0,
        skipped: 0,
        unavailable: 0,
        not_applicable: 0,
        replay_claim: profile_case.replay_claim,
        redaction_state: profile_case.redaction_state,
        limitations_digest: profile.limitations_digest,
        provenance_digest: profile.provenance_digest,
        report_digest: [0; 32],
    };
    report.report_digest = report.digest()?;
    let signer_public_key = signing_key.verifying_key().to_bytes();
    let trust_root_digest = domain_digest(
        b"PiglorOS.ConformanceTrustRoot.v1",
        &Value::Bytes(signer_public_key.to_vec()),
    )?;
    let mut evidence = StableImplementationEvidenceV1 {
        implementation,
        independence,
        evaluator_protocol_digest: profile.evaluator_protocol.protocol_digest,
        report,
        case_outcomes: vec![profile_case],
        attestation: StableEvidenceAttestationV1 {
            signer_public_key,
            signature: [0; 64],
            trust_root_digest,
        },
    };
    evidence.attestation.signature = signing_key
        .sign(&stable_attestation_payload(&evidence)?)
        .to_bytes();
    Ok(evidence)
}

fn stable_profile_from(
    mut profile: ConformanceProfileV1,
) -> Result<(ConformanceProfileV1, TrustedRootPolicyV1), Box<dyn std::error::Error>> {
    let first_key = SigningKey::from_bytes(&[31; 32]);
    let second_key = SigningKey::from_bytes(&[32; 32]);
    let mut trusted_root_public_keys = vec![
        first_key.verifying_key().to_bytes(),
        second_key.verifying_key().to_bytes(),
    ];
    trusted_root_public_keys.sort_unstable();
    let policy = TrustedRootPolicyV1 {
        trust_policy_snapshot_digest: domain_digest(
            b"PiglorOS.ConformanceTrustPolicy.v1",
            &Value::Array(
                trusted_root_public_keys
                    .iter()
                    .map(|key| Value::Bytes(key.to_vec()))
                    .collect(),
            ),
        )?,
        trusted_root_public_keys,
    };
    profile.lifecycle = pos_conformance::ProfileLifecycleV1::Stable;
    profile
        .independence_requirements
        .trust_policy_snapshot_digest = policy.trust_policy_snapshot_digest;
    profile.profile_digest = profile.digest();
    profile.stable_evidence = vec![
        stable_evidence(&profile, "implementation-a", 40, &first_key)?,
        stable_evidence(&profile, "implementation-b", 50, &second_key)?,
    ];
    Ok((profile, policy))
}

fn stable_profile(
) -> Result<(ConformanceProfileV1, TrustedRootPolicyV1), Box<dyn std::error::Error>> {
    stable_profile_from(profile_for_digest())
}

#[test]
fn public_stable_profile_requires_bound_independent_signed_evidence(
) -> Result<(), Box<dyn std::error::Error>> {
    let (profile, policy) = stable_profile()?;
    assert_eq!(policy.validate(), Ok(()));
    assert_eq!(
        profile.validate(),
        Err(ConformanceContractError::IndependenceEvidenceMissing)
    );
    assert_eq!(profile.validate_with_trust_policy(&policy), Ok(()));

    let bytes = profile.to_canonical_cbor_with_trust_policy(&policy)?;
    assert_eq!(
        ConformanceProfileV1::from_canonical_cbor_with_stable_evidence(
            &bytes,
            profile.stable_evidence.clone(),
            &policy,
        ),
        Ok(profile.clone())
    );

    let mut tampered = profile;
    tampered.stable_evidence[0].attestation.signature[0] ^= 1;
    assert_eq!(
        tampered.validate_with_trust_policy(&policy),
        Err(ConformanceContractError::IndependenceEvidenceMissing)
    );
    Ok(())
}

#[test]
fn public_stable_profile_accepts_each_valid_oracle_binding(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut failure_profile = profile_for_digest();
    let provider = failure_profile.fixtures[0].provider_key.clone();
    let failure = NamespacedFailureV1 {
        owner_id: provider.provider_id,
        contract_version: provider.contract_version,
        code_id: "invalid-input".to_owned(),
    };
    failure_profile.fixtures[0].strict_oracle = StrictOracleV1 {
        kind: StrictOracleKindV1::Failure,
        output: None,
        failure: Some(failure.clone()),
        divergence: None,
    };
    failure_profile.fixtures[0].expected_verification_outcome =
        VerificationOutcomeV1::InvalidManifest;
    failure_profile.fixtures[0].expected_verification_error = Some(failure);
    refresh(&mut failure_profile);
    let (failure_profile, policy) = stable_profile_from(failure_profile)?;
    assert_eq!(failure_profile.validate_with_trust_policy(&policy), Ok(()));

    let mut divergence_profile = profile_for_digest();
    let divergence = AllowedDivergenceV1 {
        classification: DivergenceMismatchKindV1::Artifact,
        first_coordinate: b"artifact/output".to_vec(),
    };
    divergence_profile.allowed_divergences = vec![divergence.clone()];
    divergence_profile.fixtures[0].strict_oracle = StrictOracleV1 {
        kind: StrictOracleKindV1::Divergence,
        output: None,
        failure: None,
        divergence: Some(divergence),
    };
    divergence_profile.fixtures[0].expected_verification_outcome = VerificationOutcomeV1::Diverged;
    divergence_profile.fixtures[0].expected_verification_error = None;
    refresh(&mut divergence_profile);
    let (divergence_profile, policy) = stable_profile_from(divergence_profile)?;
    assert_eq!(
        divergence_profile.validate_with_trust_policy(&policy),
        Ok(())
    );
    Ok(())
}

#[test]
fn public_stable_profile_accepts_bounded_organization_identities(
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut profile, policy) = stable_profile()?;
    for (evidence, (organization_id, signing_key)) in profile.stable_evidence.iter_mut().zip([
        ("organization-a", SigningKey::from_bytes(&[31; 32])),
        ("organization-b", SigningKey::from_bytes(&[32; 32])),
    ]) {
        evidence.implementation.organization_id = Some(organization_id.to_owned());
        evidence.report.implementation = evidence.implementation.clone();
        reseal_stable_evidence(evidence, &signing_key)?;
    }
    assert_eq!(profile.validate_with_trust_policy(&policy), Ok(()));
    Ok(())
}

#[test]
fn public_closed_catalogs_and_errors_exercise_every_current_variant() {
    let adapters = [
        ("exported-artifact", SubjectAdapterKindV1::ExportedArtifact),
        (
            "public-gateway-protocol",
            SubjectAdapterKindV1::PublicGatewayProtocol,
        ),
        (
            "public-plugin-protocol",
            SubjectAdapterKindV1::PublicPluginProtocol,
        ),
    ];
    for (name, expected) in adapters {
        assert_eq!(
            SubjectAdapterKindV1::from_catalog_name(name),
            Some(expected)
        );
    }
    assert_eq!(
        SubjectAdapterKindV1::from_catalog_name("private-rust"),
        None
    );

    let errors = [
        ConformanceContractError::InvalidEncoding,
        ConformanceContractError::UnsupportedVersion,
        ConformanceContractError::FieldOutOfBounds,
        ConformanceContractError::NonCanonicalOrder,
        ConformanceContractError::FixtureDigestMismatch,
        ConformanceContractError::ExpectedResultMissing,
        ConformanceContractError::IndependenceEvidenceMissing,
        ConformanceContractError::DivergenceClassificationMismatch,
        ConformanceContractError::ProfileLifecycleInvalid,
        ConformanceContractError::ProvenanceMissing,
        ConformanceContractError::UnknownExecutionProfile,
        ConformanceContractError::UnknownFixtureProvider,
        ConformanceContractError::ClaimRedactionMismatch,
    ];
    for error in errors {
        assert!(!error.to_string().is_empty());
        assert!(std::error::Error::source(&error).is_none());
    }
}

#[test]
fn public_profile_validation_rejects_required_fixture_contract_violations() {
    let profile = profile_for_digest();
    for (name, mutate) in required_fixture_contract_mutations() {
        let mut invalid = profile.clone();
        mutate(&mut invalid);
        refresh(&mut invalid);
        assert!(invalid.validate().is_err(), "{name} must be rejected");
    }

    for field in 0..8 {
        let mut invalid = profile.clone();
        match field {
            0 => invalid.fixtures[0].deterministic_budget.memory_bytes = 0,
            1 => invalid.fixtures[0].deterministic_budget.cpu_fuel = 0,
            2 => invalid.fixtures[0].deterministic_budget.host_calls = 0,
            3 => invalid.fixtures[0].deterministic_budget.event_count = 0,
            4 => invalid.fixtures[0].deterministic_budget.output_bytes = 0,
            5 => invalid.fixtures[0].deterministic_budget.storage_bytes = 0,
            6 => invalid.fixtures[0].deterministic_budget.execution_steps = 0,
            _ => invalid.fixtures[0].deterministic_budget.simulation_time_ns = 0,
        }
        refresh(&mut invalid);
        assert_eq!(
            invalid.validate(),
            Err(ConformanceContractError::FieldOutOfBounds)
        );
    }
}

#[test]
fn public_profile_validation_rejects_each_top_level_authority() {
    let profile = profile_for_digest();
    for mutation in 0..12 {
        let mut invalid = profile.clone();
        match mutation {
            0 => invalid.profile_id.clear(),
            1 => invalid.profile_id.push_str("#matrix=00"),
            2 => invalid.semantic_version = "01.0.0".to_owned(),
            3 => invalid.normative_spec_digest = [0; 32],
            4 => invalid.execution_matrix_digest = [0; 32],
            5 => invalid.fixture_contract_policy_digest = [0; 32],
            6 => invalid.limitations_digest = [0; 32],
            7 => invalid.provenance_digest = [0; 32],
            8 => invalid.execution_profile_digests.clear(),
            9 => invalid.execution_profile_digests[0] = [0; 32],
            10 => invalid.previous_profile_digest = Some([0; 32]),
            11 => invalid.execution_profile_digests = vec![[2; 32], [1; 32]],
            _ => return,
        }
        invalid.profile_digest = invalid.digest();
        assert!(invalid.validate().is_err(), "profile mutation {mutation}");
    }
}

#[test]
fn public_stable_transition_and_request_policy_paths_succeed(
) -> Result<(), Box<dyn std::error::Error>> {
    let (stable, policy) = stable_profile()?;
    let mut candidate = stable.clone();
    candidate.lifecycle = pos_conformance::ProfileLifecycleV1::Candidate;
    candidate.stable_evidence.clear();
    candidate.profile_digest = candidate.digest();
    assert_eq!(
        candidate.transition_to_with_trust_policy(
            pos_conformance::ProfileLifecycleV1::Stable,
            stable.stable_evidence.clone(),
            &policy,
        ),
        Ok(stable.clone())
    );

    let request = request_for_profile(&stable)?;
    assert_eq!(
        request.validate_against_profile_with_trust_policy(&stable, &policy),
        Ok(())
    );
    Ok(())
}

#[test]
fn public_transition_and_request_entrypoints_propagate_profile_validation_failures(
) -> Result<(), Box<dyn std::error::Error>> {
    let draft = profile_for_digest();
    let (_, policy) = stable_profile()?;
    assert!(draft
        .transition_to_with_trust_policy(
            pos_conformance::ProfileLifecycleV1::Candidate,
            Vec::new(),
            &policy,
        )
        .is_ok());

    let (stable, policy) = stable_profile()?;
    let mut candidate = draft;
    candidate.lifecycle = pos_conformance::ProfileLifecycleV1::Candidate;
    candidate.profile_digest = candidate.digest();
    let evidence = stable.stable_evidence.clone();
    let mut wrong_policy = policy.clone();
    wrong_policy.trust_policy_snapshot_digest = [90; 32];
    assert_eq!(
        candidate.transition_to_with_trust_policy(
            pos_conformance::ProfileLifecycleV1::Stable,
            evidence,
            &wrong_policy,
        ),
        Err(ConformanceContractError::IndependenceEvidenceMissing)
    );

    let mut invalid_draft = profile_for_digest();
    let request = request_for_profile(&invalid_draft)?;
    invalid_draft.profile_digest = [90; 32];
    assert_eq!(
        request.validate_against_profile(&invalid_draft),
        Err(ConformanceContractError::FixtureDigestMismatch)
    );

    let mut invalid_stable = stable;
    let request = request_for_profile(&invalid_stable)?;
    invalid_stable.profile_digest = [90; 32];
    assert_eq!(
        request.validate_against_profile_with_trust_policy(&invalid_stable, &policy),
        Err(ConformanceContractError::FixtureDigestMismatch)
    );
    Ok(())
}

fn required_fixture_contract_mutations() -> Vec<(&'static str, ProfileMutation)> {
    vec![
        (
            "unknown execution profile",
            Box::new(|value| {
                value.fixtures[0].execution_profile_digest = [99; 32];
            }),
        ),
        (
            "unknown provider",
            Box::new(|value| {
                value.fixtures[0].provider_key.provider_id = String::from("other.provider");
            }),
        ),
        (
            "empty fixture modes",
            Box::new(|value| {
                value.fixtures[0].modes.clear();
            }),
        ),
        (
            "duplicate modes",
            Box::new(|value| {
                value.fixtures[0].modes.push(ExecutionModeV1::Local);
            }),
        ),
        (
            "duplicate artifacts",
            Box::new(|value| {
                value.fixtures[0].payload.member_path =
                    value.fixtures[0].schema.member_path.clone();
            }),
        ),
        (
            "unsafe artifact path",
            Box::new(|value| {
                value.fixtures[0].payload.member_path = String::from("../outside.cbor");
            }),
        ),
        (
            "empty media type",
            Box::new(|value| {
                value.fixtures[0].payload.media_type.clear();
            }),
        ),
        (
            "zero artifact length",
            Box::new(|value| {
                value.fixtures[0].payload.byte_length = 0;
            }),
        ),
        (
            "zero artifact digest",
            Box::new(|value| {
                value.fixtures[0].payload.blake3_digest = [0; 32];
            }),
        ),
        (
            "zero watchdog",
            Box::new(|value| {
                value.fixtures[0].operational_safety.watchdog_ms = 0;
            }),
        ),
        (
            "unsorted capabilities",
            Box::new(|value| {
                value.fixtures[0].capability_policy.capability_ids =
                    vec!["zeta".to_owned(), "alpha".to_owned()];
            }),
        ),
        (
            "invalid capability",
            Box::new(|value| {
                value.fixtures[0].capability_policy.capability_ids = vec!["not valid".to_owned()];
            }),
        ),
        (
            "networked plugin",
            Box::new(|value| {
                value.fixtures[0].subject_adapter = SubjectAdapterKindV1::PublicPluginProtocol;
                value.fixtures[0].capability_policy.network_allowed = true;
            }),
        ),
        (
            "air-gapped network",
            Box::new(|value| {
                value.fixtures[0].modes.push(ExecutionModeV1::AirGapped);
                value.fixtures[0].capability_policy.network_allowed = true;
            }),
        ),
    ]
}

#[test]
fn public_request_and_compression_contracts_bind_the_selected_profile(
) -> Result<(), Box<dyn std::error::Error>> {
    let profile = profile_for_digest();
    let request = request_for_profile(&profile)?;
    assert_eq!(request.validate_against_profile(&profile), Ok(()));
    let canonical = request.to_canonical_cbor()?;
    assert_eq!(
        EvaluatorRequestV1::from_canonical_cbor(&canonical),
        Ok(request.clone())
    );

    let mutations: Vec<(&str, RequestMutation)> = vec![
        (
            "profile digest",
            Box::new(|value| value.conformance_profile_digest = [90; 32]),
        ),
        (
            "bundle digest",
            Box::new(|value| value.fixture_bundle_digest = [90; 32]),
        ),
        (
            "unknown execution profile",
            Box::new(|value| value.execution_profile_digest = [90; 32]),
        ),
        (
            "adapter",
            Box::new(|value| value.subject_adapter = SubjectAdapterKindV1::PublicGatewayProtocol),
        ),
        (
            "protocol",
            Box::new(|value| value.evaluator_protocol_digest = [90; 32]),
        ),
        (
            "caps",
            Box::new(|value| value.evaluator_hard_caps_digest = [90; 32]),
        ),
        (
            "trust snapshot",
            Box::new(|value| value.trust_policy_snapshot_digest = [90; 32]),
        ),
    ];
    for (name, mutate) in mutations {
        let mut invalid = request.clone();
        mutate(&mut invalid);
        invalid.output_capability.capability_digest = invalid.expected_output_capability_digest();
        invalid.request_digest = invalid.digest();
        assert!(
            invalid.validate_against_profile(&profile).is_err(),
            "{name} must bind to the selected profile"
        );
    }

    let caps = profile.evaluator_protocol.hard_caps;
    assert_eq!(caps.validate_compression_expansion(1, 100), Ok(()));
    for (compressed, expanded) in [(0, 1), (1, 0), (1, 101), (u64::MAX, 1)] {
        assert_eq!(
            caps.validate_compression_expansion(compressed, expanded),
            Err(ConformanceContractError::FieldOutOfBounds)
        );
    }
    Ok(())
}

#[test]
fn public_request_validation_rejects_each_closed_invalid_field(
) -> Result<(), Box<dyn std::error::Error>> {
    let request = request_for_profile(&profile_for_digest())?;
    for mutation in 0..15 {
        let mut invalid = request.clone();
        match mutation {
            0 => invalid.request_id = [0; 16],
            1 => invalid.conformance_profile_digest = [0; 32],
            2 => invalid.fixture_bundle_digest = [0; 32],
            3 => invalid.subject_artifact_digest = [0; 32],
            4 => invalid.execution_profile_digest = [0; 32],
            5 => invalid.trust_policy_snapshot_digest = [0; 32],
            6 => invalid.evaluator_protocol_digest = [0; 32],
            7 => invalid.evaluator_hard_caps_digest = [0; 32],
            8 => invalid.output_capability.capability_digest = [0; 32],
            9 => invalid.output_capability.report_bytes_limit = 0,
            10 => invalid.output_capability.report_bytes_limit = u64::MAX,
            11 => invalid.output_capability.diagnostic_bytes_limit = u64::MAX,
            12 => invalid.output_capability.capability_digest = [99; 32],
            13 => invalid.request_digest = [99; 32],
            14 => invalid.implementation.implementation_id.clear(),
            _ => return Err(format!("unsupported request mutation {mutation}").into()),
        }
        assert!(invalid.validate().is_err(), "request mutation {mutation}");
    }
    Ok(())
}

#[test]
fn public_fixture_oracles_cover_failure_divergence_and_claim_rejection(
) -> Result<(), Box<dyn std::error::Error>> {
    let profile = profile_for_digest();
    let provider = profile.fixtures[0].provider_key.clone();
    let failure = NamespacedFailureV1 {
        owner_id: provider.provider_id.clone(),
        contract_version: provider.contract_version,
        code_id: "invalid-input".to_owned(),
    };

    let mut failure_profile = profile.clone();
    failure_profile.fixtures[0].strict_oracle = StrictOracleV1 {
        kind: StrictOracleKindV1::Failure,
        output: None,
        failure: Some(failure.clone()),
        divergence: None,
    };
    failure_profile.fixtures[0].expected_verification_outcome =
        VerificationOutcomeV1::InvalidManifest;
    failure_profile.fixtures[0].expected_verification_error = Some(failure);
    refresh(&mut failure_profile);
    assert_eq!(failure_profile.validate(), Ok(()));
    let failure_bytes = failure_profile.to_canonical_cbor()?;
    assert_eq!(
        ConformanceProfileV1::from_canonical_cbor(&failure_bytes),
        Ok(failure_profile.clone())
    );

    let divergence = AllowedDivergenceV1 {
        classification: DivergenceMismatchKindV1::CanonicalBytes,
        first_coordinate: b"output/0".to_vec(),
    };
    let mut divergence_profile = profile.clone();
    divergence_profile.allowed_divergences = vec![divergence.clone()];
    divergence_profile.fixtures[0].strict_oracle = StrictOracleV1 {
        kind: StrictOracleKindV1::Divergence,
        output: None,
        failure: None,
        divergence: Some(divergence),
    };
    divergence_profile.fixtures[0].expected_verification_outcome = VerificationOutcomeV1::Diverged;
    refresh(&mut divergence_profile);
    assert_eq!(divergence_profile.validate(), Ok(()));
    let divergence_bytes = divergence_profile.to_canonical_cbor()?;
    assert_eq!(
        ConformanceProfileV1::from_canonical_cbor(&divergence_bytes),
        Ok(divergence_profile.clone())
    );

    let mut undeclared = divergence_profile;
    undeclared.allowed_divergences.clear();
    refresh(&mut undeclared);
    assert_eq!(
        undeclared.validate(),
        Err(ConformanceContractError::DivergenceClassificationMismatch)
    );

    for (redaction, claim) in [
        (RedactionStateV1::RedactedViews, ReplayClaimV1::Exact),
        (RedactionStateV1::StructuralOnly, ReplayClaimV1::Exact),
        (RedactionStateV1::EvidenceMissing, ReplayClaimV1::Exact),
    ] {
        let mut incoherent = profile.clone();
        incoherent.fixtures[0].redaction_state = redaction;
        incoherent.fixtures[0].replay_claim = claim;
        refresh(&mut incoherent);
        assert_eq!(
            incoherent.validate(),
            Err(ConformanceContractError::ClaimRedactionMismatch)
        );
    }
    Ok(())
}

fn assert_profile_round_trip(
    profile: ConformanceProfileV1,
) -> Result<(), Box<dyn std::error::Error>> {
    let bytes = profile.to_canonical_cbor()?;
    assert_eq!(
        ConformanceProfileV1::from_canonical_cbor(&bytes),
        Ok(profile)
    );
    Ok(())
}

#[test]
fn public_current_cpf1_catalog_round_trips_lifecycle_adapter_mode_and_family_variants(
) -> Result<(), Box<dyn std::error::Error>> {
    for lifecycle in [
        pos_conformance::ProfileLifecycleV1::Draft,
        pos_conformance::ProfileLifecycleV1::Candidate,
        pos_conformance::ProfileLifecycleV1::Retired,
    ] {
        let mut profile = profile_for_digest();
        profile.lifecycle = lifecycle;
        refresh(&mut profile);
        assert_profile_round_trip(profile)?;
    }

    for adapter in [
        SubjectAdapterKindV1::ExportedArtifact,
        SubjectAdapterKindV1::PublicGatewayProtocol,
        SubjectAdapterKindV1::PublicPluginProtocol,
    ] {
        let mut profile = profile_for_digest();
        profile.fixtures[0].subject_adapter = adapter;
        refresh(&mut profile);
        assert_profile_round_trip(profile)?;
    }

    for mode in [
        ExecutionModeV1::Local,
        ExecutionModeV1::AirGapped,
        ExecutionModeV1::Replay,
        ExecutionModeV1::Fork,
    ] {
        let mut profile = profile_for_digest();
        profile.fixtures[0].modes = vec![mode];
        refresh(&mut profile);
        assert_profile_round_trip(profile)?;
    }

    for family in [
        FixtureFamilyV1::Positive,
        FixtureFamilyV1::Denied,
        FixtureFamilyV1::Malformed,
        FixtureFamilyV1::ResourceExhaustion,
        FixtureFamilyV1::DeletionRedaction,
        FixtureFamilyV1::IndependentEvaluation,
    ] {
        let mut profile = profile_for_digest();
        profile.fixtures[0].family = family;
        refresh(&mut profile);
        assert_profile_round_trip(profile)?;
    }

    let mut downgrade = profile_for_digest();
    downgrade.fixtures[0].family = FixtureFamilyV1::Downgrade;
    downgrade.fixtures[0].trust_policy_snapshot_digest = Some([40; 32]);
    downgrade.fixtures[0].release_admission_digest = Some([41; 32]);
    downgrade.fixtures[0].transition = Some(pos_conformance::FixtureContractTransitionV1 {
        from: downgrade.fixtures[0].provider_key.clone(),
        to: FixtureProviderKeyV1 {
            provider_id: "pigloros.fixture.artifact-integrity".to_owned(),
            contract_version: "1.0.0".to_owned(),
            abi_major: 1,
            abi_minor: 1,
        },
    });
    refresh(&mut downgrade);
    assert_profile_round_trip(downgrade)
}

#[test]
fn public_current_cpf1_catalog_round_trips_every_declared_divergence_and_outcome(
) -> Result<(), Box<dyn std::error::Error>> {
    for classification in [
        DivergenceMismatchKindV1::EventIdentity,
        DivergenceMismatchKindV1::EventOrder,
        DivergenceMismatchKindV1::CanonicalBytes,
        DivergenceMismatchKindV1::ProjectionCheckpoint,
        DivergenceMismatchKindV1::TypedFailure,
        DivergenceMismatchKindV1::Artifact,
        DivergenceMismatchKindV1::SchemaOrUpcaster,
        DivergenceMismatchKindV1::NumericProfile,
        DivergenceMismatchKindV1::ProhibitedOperationalInput,
    ] {
        let divergence = AllowedDivergenceV1 {
            classification,
            first_coordinate: b"coordinate/0".to_vec(),
        };
        let mut profile = profile_for_digest();
        profile.allowed_divergences = vec![divergence.clone()];
        profile.fixtures[0].strict_oracle = StrictOracleV1 {
            kind: StrictOracleKindV1::Divergence,
            output: None,
            failure: None,
            divergence: Some(divergence),
        };
        profile.fixtures[0].expected_verification_outcome = VerificationOutcomeV1::Diverged;
        refresh(&mut profile);
        assert_profile_round_trip(profile)?;
    }

    for outcome in [
        VerificationOutcomeV1::InvalidManifest,
        VerificationOutcomeV1::UnverifiableArtifactsMissing,
        VerificationOutcomeV1::IncompatibleProfile,
        VerificationOutcomeV1::ResourceLimitExceeded,
    ] {
        let mut profile = profile_for_digest();
        let provider = profile.fixtures[0].provider_key.clone();
        let failure = NamespacedFailureV1 {
            owner_id: provider.provider_id,
            contract_version: provider.contract_version,
            code_id: "invalid-input".to_owned(),
        };
        profile.fixtures[0].strict_oracle = StrictOracleV1 {
            kind: StrictOracleKindV1::Failure,
            output: None,
            failure: Some(failure.clone()),
            divergence: None,
        };
        profile.fixtures[0].expected_verification_outcome = outcome;
        profile.fixtures[0].expected_verification_error = Some(failure);
        refresh(&mut profile);
        assert_profile_round_trip(profile)?;
    }
    Ok(())
}

#[test]
fn public_lifecycle_and_trust_policy_entry_points_are_closed_and_canonical(
) -> Result<(), Box<dyn std::error::Error>> {
    let draft = profile_for_digest();
    let candidate =
        draft.transition_to(pos_conformance::ProfileLifecycleV1::Candidate, Vec::new())?;
    assert_eq!(
        candidate.lifecycle,
        pos_conformance::ProfileLifecycleV1::Candidate
    );
    assert_eq!(
        candidate.transition_to(pos_conformance::ProfileLifecycleV1::Draft, Vec::new()),
        Err(ConformanceContractError::ProfileLifecycleInvalid)
    );
    assert_eq!(
        candidate.transition_to(pos_conformance::ProfileLifecycleV1::Stable, Vec::new()),
        Err(ConformanceContractError::IndependenceEvidenceMissing)
    );
    assert_eq!(
        candidate.transition_to(
            pos_conformance::ProfileLifecycleV1::Retired,
            vec![StableImplementationEvidenceV1 {
                implementation: ImplementationIdentityV1 {
                    implementation_id: "unused".to_owned(),
                    source_digest: [1; 32],
                    build_digest: [2; 32],
                    binary_digest: [3; 32],
                    public_contract_digest: [4; 32],
                    organization_id: None,
                },
                independence: IndependenceEvidenceV1 {
                    technical_independent: true,
                    authorship_independent: true,
                    organizational_independent: false,
                    declaration_digest: [5; 32],
                    shared_code_audit_digest: [6; 32],
                    reviewer_ids: vec!["reviewer".to_owned()],
                },
                evaluator_protocol_digest: [7; 32],
                report: report_with_cases(1)?,
                case_outcomes: Vec::new(),
                attestation: StableEvidenceAttestationV1 {
                    signer_public_key: [8; 32],
                    signature: [9; 64],
                    trust_root_digest: [10; 32],
                },
            }],
        ),
        Err(ConformanceContractError::ProfileLifecycleInvalid)
    );

    let (stable, policy) = stable_profile()?;
    let mut candidate = profile_for_digest();
    candidate.lifecycle = pos_conformance::ProfileLifecycleV1::Candidate;
    candidate
        .independence_requirements
        .trust_policy_snapshot_digest = policy.trust_policy_snapshot_digest;
    refresh(&mut candidate);
    let candidate_bytes = candidate.to_canonical_cbor_with_trust_policy(&policy)?;
    assert_eq!(
        ConformanceProfileV1::from_canonical_cbor_with_trust_policy(&candidate_bytes, &policy),
        Ok(candidate)
    );

    let mut untrusted_policy = policy;
    untrusted_policy.trusted_root_public_keys.reverse();
    assert_eq!(
        stable.validate_with_trust_policy(&untrusted_policy),
        Err(ConformanceContractError::IndependenceEvidenceMissing)
    );
    Ok(())
}

#[test]
fn public_current_cpf1_decoder_rejects_unknown_closed_codes(
) -> Result<(), Box<dyn std::error::Error>> {
    let rejected_paths = [
        vec![4],
        vec![9, 0, 2],
        vec![9, 0, 3],
        vec![9, 0, 5],
        vec![9, 0, 7, 0],
        vec![9, 0, 11, 0],
        vec![9, 0, 12],
        vec![9, 0, 14],
        vec![9, 0, 15],
    ];
    for path in rejected_paths {
        let bytes = profile_with_nested_field(&path, Value::Integer(99_u64.into()))?;
        let expected = if path.as_slice() == [4] {
            ConformanceContractError::UnsupportedVersion
        } else {
            ConformanceContractError::InvalidEncoding
        };
        assert_eq!(
            ConformanceProfileV1::from_canonical_cbor(&bytes),
            Err(expected),
            "unknown closed code at {path:?} must be rejected"
        );
    }
    Ok(())
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

fn exhaustive_profile_case_outcomes() -> Vec<ProfileCaseOutcomeV1> {
    let outcomes = [
        CaseOutcomeStatusV1::Pass,
        CaseOutcomeStatusV1::Fail,
        CaseOutcomeStatusV1::Skip,
        CaseOutcomeStatusV1::Unavailable,
        CaseOutcomeStatusV1::NotApplicable,
    ];
    let verification = [
        VerificationOutcomeV1::VerifiedExact,
        VerificationOutcomeV1::Diverged,
        VerificationOutcomeV1::InvalidManifest,
        VerificationOutcomeV1::UnverifiableArtifactsMissing,
        VerificationOutcomeV1::IncompatibleProfile,
        VerificationOutcomeV1::ResourceLimitExceeded,
    ];
    let divergences = [
        DivergenceMismatchKindV1::EventIdentity,
        DivergenceMismatchKindV1::EventOrder,
        DivergenceMismatchKindV1::CanonicalBytes,
        DivergenceMismatchKindV1::ProjectionCheckpoint,
        DivergenceMismatchKindV1::TypedFailure,
        DivergenceMismatchKindV1::Artifact,
        DivergenceMismatchKindV1::SchemaOrUpcaster,
        DivergenceMismatchKindV1::NumericProfile,
        DivergenceMismatchKindV1::ProhibitedOperationalInput,
    ];
    let replay = [
        ReplayClaimV1::Exact,
        ReplayClaimV1::ExactAuthoritativeWithRedactedViews,
        ReplayClaimV1::StructuralOnly,
        ReplayClaimV1::UnverifiableArtifactsMissing,
        ReplayClaimV1::IncompatibleProfile,
    ];
    let redaction = [
        RedactionStateV1::None,
        RedactionStateV1::RedactedViews,
        RedactionStateV1::StructuralOnly,
        RedactionStateV1::EvidenceMissing,
    ];
    [
        SafeErrorCodeV1::InvalidEncoding,
        SafeErrorCodeV1::UnsupportedVersion,
        SafeErrorCodeV1::FieldOutOfBounds,
        SafeErrorCodeV1::NonCanonicalOrder,
        SafeErrorCodeV1::DigestMismatch,
        SafeErrorCodeV1::SignatureInvalid,
        SafeErrorCodeV1::TrustRootUnknown,
        SafeErrorCodeV1::TrustSnapshotRollback,
        SafeErrorCodeV1::ArtifactRevoked,
        SafeErrorCodeV1::ClosureIncomplete,
        SafeErrorCodeV1::ProfileClassMismatch,
        SafeErrorCodeV1::ProfileUnsupported,
        SafeErrorCodeV1::ProvenanceMissing,
        SafeErrorCodeV1::ResourceLimitExceeded,
    ]
    .into_iter()
    .enumerate()
    .map(|(index, error)| ProfileCaseOutcomeV1 {
        case_id: format!("case-{index:02}"),
        fixture_digest: [7; 32],
        execution_profile_digest: [8; 32],
        mode: ExecutionModeV1::Local,
        claim_layer: ClaimLayerV1::ArtifactIntegrity,
        outcome: outcomes[index % outcomes.len()],
        verification_outcome: verification[index % verification.len()],
        divergence_kind: Some(divergences[index % divergences.len()]),
        first_coordinate: Some(format!("coordinate-{index}").into_bytes()),
        expected_digest: Some([10; 32]),
        actual_digest: Some([11; 32]),
        expected_error: Some(error),
        actual_error: Some(error),
        replay_claim: replay[index % replay.len()],
        redaction_state: redaction[index % redaction.len()],
        provenance_digest: [9; 32],
    })
    .collect()
}

#[test]
fn public_stable_attestation_encodes_every_closed_case_outcome_variant(
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut profile, policy) = stable_profile()?;
    let additional_cases = exhaustive_profile_case_outcomes();
    for (evidence, seed) in profile.stable_evidence.iter_mut().zip([31_u8, 32]) {
        evidence.case_outcomes.extend(additional_cases.clone());
        let signing_key = SigningKey::from_bytes(&[seed; 32]);
        evidence.attestation.signature = signing_key
            .sign(&stable_attestation_payload(evidence)?)
            .to_bytes();
    }
    assert_eq!(
        profile.validate_with_trust_policy(&policy),
        Err(ConformanceContractError::IndependenceEvidenceMissing)
    );
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

    let mut stale_caps_identity = request_for_caps(&caps);
    stale_caps_identity.evaluator_hard_caps_digest = [90; 32];
    stale_caps_identity.output_capability.capability_digest =
        stale_caps_identity.expected_output_capability_digest();
    stale_caps_identity.request_digest = stale_caps_identity.digest();
    assert_eq!(
        stale_caps_identity.validate_with_hard_caps(&caps),
        Err(ConformanceContractError::FixtureDigestMismatch)
    );

    let mut other_protocol = protocol;
    other_protocol.protocol_digest = [90; 32];
    assert_eq!(
        request_for_caps(&caps).validate_with_protocol(&other_protocol),
        Err(ConformanceContractError::FixtureDigestMismatch)
    );

    assert_eq!(
        caps.validate_case_count(caps.max_cases + 1),
        Err(ConformanceContractError::FieldOutOfBounds)
    );
}

#[test]
fn public_request_rejects_output_limits_above_the_selected_profile(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut profile = profile_for_digest();
    let mut request = request_for_profile(&profile)?;
    profile.evaluator_protocol.hard_caps.max_diagnostic_bytes = 1;
    profile.profile_digest = profile.digest();
    request.conformance_profile_digest = profile.profile_digest;
    request.evaluator_hard_caps_digest = profile.evaluator_protocol.hard_caps.digest();
    request.output_capability.capability_digest = request.expected_output_capability_digest();
    request.request_digest = request.digest();
    assert_eq!(
        request.validate_against_profile(&profile),
        Err(ConformanceContractError::FieldOutOfBounds)
    );
    Ok(())
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
fn public_profile_caps_reject_each_selected_resource_dimension() {
    for mutation in 0..7 {
        let mut invalid = profile_for_digest();
        match mutation {
            0 => invalid.evaluator_protocol.hard_caps.max_profile_bytes = 1,
            1 => invalid.evaluator_protocol.hard_caps.max_structural_nesting = 1,
            2 => invalid.evaluator_protocol.hard_caps.max_member_path_bytes = 1,
            3 => invalid.evaluator_protocol.hard_caps.max_member_bytes = 0,
            4 => invalid.evaluator_protocol.hard_caps.max_bundle_members = 1,
            5 => invalid.evaluator_protocol.hard_caps.max_total_bundle_bytes = 1,
            6 => {
                invalid.evaluator_protocol.hard_caps.max_coordinate_bytes = 0;
                invalid.allowed_divergences = vec![AllowedDivergenceV1 {
                    classification: DivergenceMismatchKindV1::Artifact,
                    first_coordinate: vec![1],
                }];
            }
            _ => return,
        }
        invalid.profile_digest = invalid.digest();
        assert!(invalid.validate().is_err(), "resource mutation {mutation}");
    }

    let mut stale_fixture_digest = profile_for_digest();
    stale_fixture_digest.fixtures[0].mandatory = false;
    stale_fixture_digest.profile_digest = stale_fixture_digest.digest();
    assert_eq!(
        stale_fixture_digest.validate(),
        Err(ConformanceContractError::FixtureDigestMismatch)
    );
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

    let oversized = vec![0; 16 * 1024 * 1024 + 1];
    assert_eq!(
        ConformanceProfileV1::from_canonical_cbor(&oversized),
        Err(ConformanceContractError::FieldOutOfBounds)
    );
    let policy = TrustedRootPolicyV1 {
        trusted_root_public_keys: vec![[42; 32]],
        trust_policy_snapshot_digest: [1; 32],
    };
    assert_eq!(
        ConformanceProfileV1::from_canonical_cbor_with_trust_policy(&oversized, &policy),
        Err(ConformanceContractError::FieldOutOfBounds)
    );
    assert_eq!(
        EvaluatorRequestV1::from_canonical_cbor(&oversized),
        Err(ConformanceContractError::FieldOutOfBounds)
    );
}

#[test]
fn public_profile_and_request_decoders_reject_truncated_and_trailing_records(
) -> Result<(), Box<dyn std::error::Error>> {
    for profile in [
        Value::Array(Vec::new()),
        Value::Array(vec![Value::Text("CPF1".to_owned())]),
    ] {
        assert_eq!(
            ConformanceProfileV1::from_canonical_cbor(&canonical_value(&profile)?),
            Err(ConformanceContractError::InvalidEncoding)
        );
    }

    let mut profile_bytes = profile_for_digest().to_canonical_cbor()?;
    profile_bytes.push(0);
    assert_eq!(
        ConformanceProfileV1::from_canonical_cbor(&profile_bytes),
        Err(ConformanceContractError::InvalidEncoding)
    );

    let mut request_value: Value = ciborium::from_reader(
        request_for_profile(&profile_for_digest())?
            .to_canonical_cbor()?
            .as_slice(),
    )?;
    let Value::Array(request_fields) = &mut request_value else {
        return Err("canonical evaluator request is not an array".into());
    };
    request_fields[0] = Value::Text("BAD1".to_owned());
    assert_eq!(
        EvaluatorRequestV1::from_canonical_cbor(&canonical_value(&request_value)?),
        Err(ConformanceContractError::UnsupportedVersion)
    );
    Ok(())
}

#[test]
fn public_profile_round_trip_covers_nondefault_replay_and_redaction_codes(
) -> Result<(), Box<dyn std::error::Error>> {
    for (replay, redaction) in [
        (
            ReplayClaimV1::ExactAuthoritativeWithRedactedViews,
            RedactionStateV1::RedactedViews,
        ),
        (
            ReplayClaimV1::StructuralOnly,
            RedactionStateV1::StructuralOnly,
        ),
        (ReplayClaimV1::IncompatibleProfile, RedactionStateV1::None),
    ] {
        let mut profile = profile_for_digest();
        profile.fixtures[0].replay_claim = replay;
        profile.fixtures[0].redaction_state = redaction;
        refresh(&mut profile);
        let bytes = profile.to_canonical_cbor()?;
        assert_eq!(ConformanceProfileV1::from_canonical_cbor(&bytes)?, profile);
    }
    Ok(())
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
    replace_nested_encoded_value(
        &fixtures::cpf1_profile_rejection_fixture(0, false)?,
        path,
        replacement,
    )
}

fn replace_nested_encoded_value(
    encoded: &[u8],
    path: &[usize],
    replacement: Value,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut value: Value = ciborium::from_reader(encoded)?;
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
        for replacement in [Value::Null, Value::Map(Vec::new())] {
            let bytes = profile_with_nested_field(&path, replacement)?;
            assert_eq!(
                ConformanceProfileV1::from_canonical_cbor(&bytes),
                Err(ConformanceContractError::InvalidEncoding),
                "nested field {path:?} unexpectedly decoded"
            );
        }
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
    paths.extend((0..24).map(|index| vec![9, 0, index]));
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
        for replacement in [Value::Bool(true), Value::Map(Vec::new())] {
            let bytes = profile_with_nested_field(&[index], replacement)?;
            assert!(ConformanceProfileV1::from_canonical_cbor(&bytes).is_err());
        }
    }
    Ok(())
}

#[test]
fn public_profile_decoder_rejects_active_failure_and_transition_fields(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut failure_profile = profile_for_digest();
    let provider = failure_profile.fixtures[0].provider_key.clone();
    let failure = NamespacedFailureV1 {
        owner_id: provider.provider_id,
        contract_version: provider.contract_version,
        code_id: "invalid-input".to_owned(),
    };
    failure_profile.fixtures[0].strict_oracle = StrictOracleV1 {
        kind: StrictOracleKindV1::Failure,
        output: None,
        failure: Some(failure.clone()),
        divergence: None,
    };
    failure_profile.fixtures[0].expected_verification_outcome =
        VerificationOutcomeV1::InvalidManifest;
    failure_profile.fixtures[0].expected_verification_error = Some(failure);
    refresh(&mut failure_profile);
    let failure_bytes = failure_profile.to_canonical_cbor()?;
    let mut failure_paths = (0..3)
        .map(|field| vec![9, 0, 11, 2, field])
        .collect::<Vec<_>>();
    failure_paths.extend((0..3).map(|field| vec![9, 0, 13, field]));
    for path in failure_paths {
        let malformed =
            replace_nested_encoded_value(&failure_bytes, &path, Value::Map(Vec::new()))?;
        assert!(ConformanceProfileV1::from_canonical_cbor(&malformed).is_err());
    }

    let mut downgrade = profile_for_digest();
    downgrade.fixtures[0].family = FixtureFamilyV1::Downgrade;
    downgrade.fixtures[0].trust_policy_snapshot_digest = Some([40; 32]);
    downgrade.fixtures[0].release_admission_digest = Some([41; 32]);
    downgrade.fixtures[0].transition = Some(pos_conformance::FixtureContractTransitionV1 {
        from: downgrade.fixtures[0].provider_key.clone(),
        to: FixtureProviderKeyV1 {
            provider_id: "pigloros.fixture.artifact-integrity".to_owned(),
            contract_version: "1.0.0".to_owned(),
            abi_major: 1,
            abi_minor: 1,
        },
    });
    refresh(&mut downgrade);
    let downgrade_bytes = downgrade.to_canonical_cbor()?;
    for endpoint in 0..2 {
        for field in 0..4 {
            let path = [9, 0, 22, endpoint, field];
            let malformed =
                replace_nested_encoded_value(&downgrade_bytes, &path, Value::Map(Vec::new()))?;
            assert!(ConformanceProfileV1::from_canonical_cbor(&malformed).is_err());
        }
    }
    Ok(())
}

#[test]
fn public_trust_validation_rejects_stale_digest_and_evidence_on_nonstable_profiles(
) -> Result<(), Box<dyn std::error::Error>> {
    let (signed_profile, policy) = stable_profile()?;

    let mut stale_profile = profile_for_digest();
    stale_profile.profile_digest = [99; 32];
    assert_eq!(
        stale_profile.validate_with_trust_policy(&policy),
        Err(ConformanceContractError::FixtureDigestMismatch)
    );

    let mut candidate = signed_profile;
    candidate.lifecycle = pos_conformance::ProfileLifecycleV1::Candidate;
    candidate.profile_digest = candidate.digest();
    assert_eq!(
        candidate.validate_with_trust_policy(&policy),
        Err(ConformanceContractError::ProfileLifecycleInvalid)
    );
    Ok(())
}

#[test]
fn public_stable_validation_rejects_each_cross_implementation_independence_violation(
) -> Result<(), Box<dyn std::error::Error>> {
    for mutation in 0..9 {
        let (mut profile, policy) = stable_profile()?;
        match mutation {
            0 => profile.stable_evidence[0]
                .implementation
                .implementation_id
                .clear(),
            1 => profile.stable_evidence[1]
                .implementation
                .implementation_id
                .clear(),
            2 => {
                profile.stable_evidence[0].implementation.implementation_id =
                    "implementation-z".to_owned();
            }
            3 => {
                let digest = profile.stable_evidence[0].implementation.source_digest;
                profile.stable_evidence[1].implementation.source_digest = digest;
            }
            4 => {
                let digest = profile.stable_evidence[0].implementation.build_digest;
                profile.stable_evidence[1].implementation.build_digest = digest;
            }
            5 => {
                let digest = profile.stable_evidence[0].implementation.binary_digest;
                profile.stable_evidence[1].implementation.binary_digest = digest;
            }
            6 => {
                profile.stable_evidence[1]
                    .implementation
                    .public_contract_digest = [88; 32];
            }
            7 => profile.stable_evidence[1].report.subject_artifact_digest = [92; 32],
            8 => {
                let digest = profile.stable_evidence[0].report.report_digest;
                profile.stable_evidence[1].report.report_digest = digest;
            }
            _ => return Err(format!("unsupported stable evidence mutation {mutation}").into()),
        }
        let expected = if mutation < 2 {
            ConformanceContractError::ProvenanceMissing
        } else {
            ConformanceContractError::IndependenceEvidenceMissing
        };
        assert_eq!(
            profile.validate_with_trust_policy(&policy),
            Err(expected),
            "stable evidence mutation {mutation} was accepted"
        );
    }
    Ok(())
}

#[test]
fn public_stable_validation_rejects_missing_cases_and_oversized_coordinates(
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut missing, policy) = stable_profile()?;
    missing.stable_evidence[0].case_outcomes.clear();
    assert_eq!(
        missing.validate_with_trust_policy(&policy),
        Err(ConformanceContractError::IndependenceEvidenceMissing)
    );

    let (mut oversized, policy) = stable_profile()?;
    oversized.stable_evidence[0].case_outcomes[0].first_coordinate = Some(vec![0; 4_097]);
    assert_eq!(
        oversized.validate_with_trust_policy(&policy),
        Err(ConformanceContractError::FieldOutOfBounds)
    );
    Ok(())
}

#[test]
fn public_stable_validation_rejects_each_independence_and_attestation_violation(
) -> Result<(), Box<dyn std::error::Error>> {
    for mutation in 0..13 {
        let (mut profile, policy) = stable_profile()?;
        let evidence = &mut profile.stable_evidence[0];
        match mutation {
            0 => evidence.independence.technical_independent = false,
            1 => evidence.independence.authorship_independent = false,
            2 => evidence.independence.reviewer_ids.clear(),
            3 => {
                evidence.independence.reviewer_ids = (0..33)
                    .map(|index| format!("reviewer-{index:02}"))
                    .collect();
            }
            4 => {
                evidence.independence.reviewer_ids =
                    vec!["reviewer-z".to_owned(), "reviewer-a".to_owned()];
            }
            5 => evidence.independence.reviewer_ids = vec!["Invalid Reviewer".to_owned()],
            6 => evidence.independence.declaration_digest = [0; 32],
            7 => evidence.independence.shared_code_audit_digest = [0; 32],
            8 => evidence.attestation.signer_public_key = [0; 32],
            9 => evidence.attestation.signature = [0; 64],
            10 => evidence.attestation.trust_root_digest = [0; 32],
            11 => evidence.attestation.trust_root_digest = [99; 32],
            12 => evidence.attestation.signer_public_key = [99; 32],
            _ => return Err(format!("unsupported attestation mutation {mutation}").into()),
        }
        assert_eq!(
            profile.validate_with_trust_policy(&policy),
            Err(ConformanceContractError::IndependenceEvidenceMissing),
            "independence mutation {mutation} was accepted"
        );
    }
    Ok(())
}

fn reseal_stable_evidence(
    evidence: &mut StableImplementationEvidenceV1,
    signing_key: &SigningKey,
) -> Result<(), Box<dyn std::error::Error>> {
    evidence.report.report_digest = evidence.report.digest()?;
    evidence.attestation.signature = signing_key
        .sign(&stable_attestation_payload(evidence)?)
        .to_bytes();
    Ok(())
}

#[test]
fn public_stable_validation_rejects_each_report_authority_substitution(
) -> Result<(), Box<dyn std::error::Error>> {
    for mutation in 0..10 {
        let (mut profile, policy) = stable_profile()?;
        let evidence = &mut profile.stable_evidence[0];
        match mutation {
            0 => evidence.report.implementation.implementation_id = "substitute".to_owned(),
            1 => evidence.report.independence.declaration_digest = [90; 32],
            2 => evidence.report.evaluator_protocol_digest = [90; 32],
            3 => evidence.evaluator_protocol_digest = [90; 32],
            4 => evidence.report.normative_spec_digest = [90; 32],
            5 => evidence.report.limitations_digest = [90; 32],
            6 => evidence.report.provenance_digest = [90; 32],
            7 => evidence.report.fixture_bundle_digest = [90; 32],
            8 => evidence.report.profile_digest = [90; 32],
            9 => evidence.report.execution_profile_digest = [90; 32],
            _ => return Err(format!("unsupported report substitution {mutation}").into()),
        }
        reseal_stable_evidence(evidence, &SigningKey::from_bytes(&[31; 32]))?;
        assert_eq!(
            profile.validate_with_trust_policy(&policy),
            Err(ConformanceContractError::IndependenceEvidenceMissing),
            "report substitution {mutation} was accepted"
        );
    }
    Ok(())
}

#[test]
fn public_stable_validation_rejects_each_case_binding_mismatch(
) -> Result<(), Box<dyn std::error::Error>> {
    for mutation in 0..9 {
        let (mut profile, policy) = stable_profile()?;
        let evidence = &mut profile.stable_evidence[0];
        let case = &mut evidence.case_outcomes[0];
        match mutation {
            0 => case.outcome = CaseOutcomeStatusV1::Fail,
            1 => case.replay_claim = ReplayClaimV1::StructuralOnly,
            2 => case.redaction_state = RedactionStateV1::StructuralOnly,
            3 => case.provenance_digest = [90; 32],
            4 => {
                case.verification_outcome = VerificationOutcomeV1::UnverifiableArtifactsMissing;
                case.expected_digest = None;
                case.actual_digest = None;
            }
            5 => {
                case.verification_outcome = VerificationOutcomeV1::UnverifiableArtifactsMissing;
            }
            6 => case.verification_outcome = VerificationOutcomeV1::Diverged,
            7 => case.expected_digest = Some([90; 32]),
            8 => case.actual_digest = Some([90; 32]),
            _ => return Err(format!("unsupported case mismatch {mutation}").into()),
        }
        evidence.attestation.signature = SigningKey::from_bytes(&[31; 32])
            .sign(&stable_attestation_payload(evidence)?)
            .to_bytes();
        assert_eq!(
            profile.validate_with_trust_policy(&policy),
            Err(ConformanceContractError::IndependenceEvidenceMissing),
            "case binding mismatch {mutation} was accepted"
        );
    }
    Ok(())
}

#[test]
fn public_stable_validation_rejects_report_case_parity_and_invalid_report(
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut parity, policy) = stable_profile()?;
    let evidence = &mut parity.stable_evidence[0];
    evidence.report.cases[0].expected_digest = Some([90; 32]);
    reseal_stable_evidence(evidence, &SigningKey::from_bytes(&[31; 32]))?;
    assert_eq!(
        parity.validate_with_trust_policy(&policy),
        Err(ConformanceContractError::IndependenceEvidenceMissing)
    );

    let (mut outcome_parity, policy) = stable_profile()?;
    let evidence = &mut outcome_parity.stable_evidence[0];
    evidence.report.cases[0].outcome = CaseOutcomeStatusV1::Fail;
    evidence.report.cases[0].actual_digest = Some([90; 32]);
    evidence.report.cases[0].first_coordinate = Some(b"output/0".to_vec());
    evidence.report.passed = 0;
    evidence.report.failed = 1;
    reseal_stable_evidence(evidence, &SigningKey::from_bytes(&[31; 32]))?;
    assert_eq!(
        outcome_parity.validate_with_trust_policy(&policy),
        Err(ConformanceContractError::IndependenceEvidenceMissing)
    );

    let (mut invalid_report, policy) = stable_profile()?;
    let evidence = &mut invalid_report.stable_evidence[0];
    evidence.report.report_id = [0; 16];
    evidence.attestation.signature = SigningKey::from_bytes(&[31; 32])
        .sign(&stable_attestation_payload(evidence)?)
        .to_bytes();
    assert_eq!(
        invalid_report.validate_with_trust_policy(&policy),
        Err(ConformanceContractError::IndependenceEvidenceMissing)
    );
    Ok(())
}

#[test]
fn public_profile_rejects_deep_divergence_downgrade_and_failure_violations() {
    let mut empty_version = profile_for_digest();
    empty_version.semantic_version.clear();
    empty_version.profile_digest = empty_version.digest();
    assert_eq!(
        empty_version.validate(),
        Err(ConformanceContractError::FieldOutOfBounds)
    );

    let mut divergence = profile_for_digest();
    divergence.evaluator_protocol.hard_caps.max_coordinate_bytes = 128;
    let oversized = AllowedDivergenceV1 {
        classification: DivergenceMismatchKindV1::Artifact,
        first_coordinate: vec![0; 129],
    };
    divergence.allowed_divergences = vec![oversized.clone()];
    divergence.fixtures[0].strict_oracle = StrictOracleV1 {
        kind: StrictOracleKindV1::Divergence,
        output: None,
        failure: None,
        divergence: Some(oversized),
    };
    divergence.fixtures[0].expected_verification_outcome = VerificationOutcomeV1::Diverged;
    divergence.fixtures[0].expected_verification_error = None;
    refresh(&mut divergence);
    assert_eq!(
        divergence.validate(),
        Err(ConformanceContractError::FieldOutOfBounds)
    );

    let mut downgrade = profile_for_digest();
    downgrade.fixtures[0].family = FixtureFamilyV1::Downgrade;
    downgrade.fixtures[0].trust_policy_snapshot_digest = Some([90; 32]);
    downgrade.fixtures[0].release_admission_digest = Some([91; 32]);
    refresh(&mut downgrade);
    assert_eq!(
        downgrade.validate(),
        Err(ConformanceContractError::ProvenanceMissing)
    );

    let mut incomplete_downgrade = profile_for_digest();
    incomplete_downgrade.fixtures[0].family = FixtureFamilyV1::Downgrade;
    incomplete_downgrade.fixtures[0].transition =
        Some(pos_conformance::FixtureContractTransitionV1 {
            from: incomplete_downgrade.fixtures[0].provider_key.clone(),
            to: FixtureProviderKeyV1 {
                provider_id: "pigloros.fixture.artifact-integrity".to_owned(),
                contract_version: "1.0.0".to_owned(),
                abi_major: 1,
                abi_minor: 1,
            },
        });
    refresh(&mut incomplete_downgrade);
    assert_eq!(
        incomplete_downgrade.validate(),
        Err(ConformanceContractError::ProvenanceMissing)
    );

    let mut ownership = profile_for_digest();
    let failure = NamespacedFailureV1 {
        owner_id: "other.provider".to_owned(),
        contract_version: "1.0.0".to_owned(),
        code_id: "rejected".to_owned(),
    };
    ownership.fixtures[0].strict_oracle = StrictOracleV1 {
        kind: StrictOracleKindV1::Failure,
        output: None,
        failure: Some(failure.clone()),
        divergence: None,
    };
    ownership.fixtures[0].expected_verification_outcome = VerificationOutcomeV1::InvalidManifest;
    ownership.fixtures[0].expected_verification_error = Some(failure);
    refresh(&mut ownership);
    assert_eq!(
        ownership.validate(),
        Err(ConformanceContractError::ProvenanceMissing)
    );
}

#[test]
fn public_stable_validation_enforces_organizational_independence_when_selected(
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut profile, policy) = stable_profile()?;
    profile
        .independence_requirements
        .organizational_independence_required = true;
    profile.profile_digest = profile.digest();
    assert_eq!(
        profile.validate_with_trust_policy(&policy),
        Err(ConformanceContractError::IndependenceEvidenceMissing)
    );
    Ok(())
}

#[test]
fn public_profile_rejects_invalid_failure_ownership_and_divergence_order() {
    let mut invalid_failure = profile_for_digest();
    let provider = invalid_failure.fixtures[0].provider_key.clone();
    invalid_failure.fixtures[0].strict_oracle = StrictOracleV1 {
        kind: StrictOracleKindV1::Failure,
        output: None,
        failure: Some(NamespacedFailureV1 {
            owner_id: provider.provider_id,
            contract_version: provider.contract_version,
            code_id: String::new(),
        }),
        divergence: None,
    };
    invalid_failure.fixtures[0].expected_verification_outcome =
        VerificationOutcomeV1::InvalidManifest;
    invalid_failure.fixtures[0].expected_verification_error =
        invalid_failure.fixtures[0].strict_oracle.failure.clone();
    refresh(&mut invalid_failure);
    assert_eq!(
        invalid_failure.validate(),
        Err(ConformanceContractError::FieldOutOfBounds)
    );

    let divergence = AllowedDivergenceV1 {
        classification: DivergenceMismatchKindV1::Artifact,
        first_coordinate: vec![1],
    };
    let mut duplicate = profile_for_digest();
    duplicate.allowed_divergences = vec![divergence.clone(), divergence];
    refresh(&mut duplicate);
    assert_eq!(
        duplicate.validate(),
        Err(ConformanceContractError::NonCanonicalOrder)
    );
}

#[test]
fn public_profile_decoder_rejects_each_raw_cbor_boundary() -> Result<(), Box<dyn std::error::Error>>
{
    let canonical = profile_for_digest().to_canonical_cbor()?;
    let marker = [0x64, b'C', b'P', b'F', b'1', 0x01];
    let version_index = canonical
        .windows(marker.len())
        .position(|window| window == marker)
        .map(|index| index + marker.len() - 1)
        .ok_or("canonical CPF1 version marker must exist")?;
    let mut noncanonical = canonical;
    noncanonical.splice(version_index..=version_index, [0x18, 0x01]);

    let mut over_nested = vec![0x81; 33];
    over_nested.push(0);
    for malformed in [
        noncanonical,
        vec![0x5f],
        vec![0x58],
        vec![0x41],
        vec![0x61, 0xff],
        vec![0xfa, 0, 0, 0, 0],
        vec![0x9a, 0, 0, 0x10, 0x01],
        vec![0x9a, 0, 1, 0, 1],
        vec![0xa0],
        over_nested,
    ] {
        assert!(ConformanceProfileV1::from_canonical_cbor(&malformed).is_err());
    }
    Ok(())
}

#[test]
fn public_request_decoder_rejects_each_top_level_and_nested_field(
) -> Result<(), Box<dyn std::error::Error>> {
    for length in [13, 15] {
        let malformed = fixtures::encode(&Value::Array(vec![Value::Null; length]))?;
        assert_eq!(
            EvaluatorRequestV1::from_canonical_cbor(&malformed),
            Err(ConformanceContractError::InvalidEncoding)
        );
    }
    let mut paths = (0..14).map(|index| vec![index]).collect::<Vec<_>>();
    paths.extend((0..6).map(|index| vec![7, index]));
    paths.extend((0..3).map(|index| vec![10, index]));
    for path in paths {
        for replacement in [Value::Null, Value::Map(Vec::new())] {
            let mut request: Value = ciborium::from_reader(fixtures::request()?.as_slice())?;
            let (field, parents) = path.split_last().ok_or("request path must not be empty")?;
            let mut selected = &mut request;
            for index in parents {
                let Value::Array(fields) = selected else {
                    return Err("request path must select arrays".into());
                };
                selected = fields
                    .get_mut(*index)
                    .ok_or("request path is out of bounds")?;
            }
            let Value::Array(fields) = selected else {
                return Err("request path parent must be an array".into());
            };
            fields[*field] = replacement;
            assert!(
                EvaluatorRequestV1::from_canonical_cbor(&fixtures::encode(&request)?).is_err(),
                "request field {path:?} unexpectedly decoded"
            );
        }
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
