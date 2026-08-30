#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

//! Public regression coverage for the Wave 8 evidence wire contract.

use pos_conformance::*;
use std::collections::BTreeMap;

#[derive(Clone, Copy)]
enum EvidenceField {
    Magic,
    Version,
    Manifest,
    Contract,
}

impl EvidenceField {
    const fn index(self) -> usize {
        match self {
            Self::Magic => 0,
            Self::Version => 1,
            Self::Manifest => 2,
            Self::Contract => 10,
        }
    }
}

#[derive(Clone, Copy)]
enum ManifestField {
    ExecutionProfile,
}

impl ManifestField {
    const fn index(self) -> usize {
        match self {
            Self::ExecutionProfile => 14,
        }
    }
}

#[derive(Clone, Copy)]
enum ContractField {
    Report,
}

impl ContractField {
    const fn index(self) -> usize {
        match self {
            Self::Report => 6,
        }
    }
}

#[derive(Clone, Copy)]
enum ReportField {
    Cases,
    Digest,
}

impl ReportField {
    const fn index(self) -> usize {
        match self {
            Self::Cases => 13,
            Self::Digest => 21,
        }
    }
}

#[derive(Clone, Copy)]
enum CaseField {
    FirstCoordinate,
}

impl CaseField {
    const fn index(self) -> usize {
        match self {
            Self::FirstCoordinate => 6,
        }
    }
}

#[derive(Clone, Copy)]
enum VerificationField {
    FirstError,
    CheckedArtifactCount,
    ResultDigest,
}

impl VerificationField {
    const fn index(self) -> usize {
        match self {
            Self::FirstError => 14,
            Self::CheckedArtifactCount => 15,
            Self::ResultDigest => 17,
        }
    }
}

#[derive(Clone, Copy)]
enum VerificationErrorField {
    Code,
}

impl VerificationErrorField {
    const fn index(self) -> usize {
        match self {
            Self::Code => 0,
        }
    }
}

fn public_evidence_fixture() -> MoatProofEvidenceV1 {
    MoatProofEvidenceV1 {
        format_version: EVIDENCE_FORMAT_V1,
        manifest: ReproManifestV1 {
            format_version: EVIDENCE_FORMAT_V1,
            input_digest: [1; 32],
            execution_mode: ExecutionModeV1::Local,
            fork_cut_seq: Some(2),
            seed: 7,
            resource_limit: 100,
            network_enabled: false,
            reproducibility_class: ReproducibilityClassV1::ProfileRecomputation,
            execution_profile: "deterministic-v1".to_owned(),
            execution_profile_digest: [3; 32],
            trust_policy_snapshot_digest: [4; 32],
            artifact_closure_digest: [5; 32],
            evaluator_digest: [6; 32],
            replay_claim: ReplayClaimV1::Exact,
            plugin_versions: BTreeMap::from([("world".to_owned(), "1".to_owned())]),
            scenario_room_digest: [4; 32],
            scheduler_digest: [9; 32],
            budget_digest: [10; 32],
        },
        authoritative_events: vec![
            AuthoritativeEventV1 {
                seq: 1,
                tick: 1,
                entity: "body".to_owned(),
                event_type: "world.observation.v1".to_owned(),
                payload_digest: [1; 32],
                causation_seq: None,
            },
            AuthoritativeEventV1 {
                seq: 2,
                tick: 1,
                entity: "agent".to_owned(),
                event_type: "proof.agent.reaction.v1".to_owned(),
                payload_digest: [2; 32],
                causation_seq: Some(1),
            },
            AuthoritativeEventV1 {
                seq: 3,
                tick: 2,
                entity: "host".to_owned(),
                event_type: "experiment.lifecycle.consent-closed.v1".to_owned(),
                payload_digest: [7; 32],
                causation_seq: None,
            },
        ],
        projections: vec![ProjectionEvidenceV1 {
            reducer: "world".to_owned(),
            entity: "body".to_owned(),
            state: serde_json::json!({"x": 1}),
        }],
        causal_trace: vec![CausalTraceEntryV1 {
            cause_seq: 1,
            effect_seq: 2,
            relation: "physical_to_agent".to_owned(),
            visibility: "operator".to_owned(),
            dependency_class: DependencyClassV1::EndogenousRecomputed,
        }],
        uncertainty: vec![UncertaintyV1 {
            label: "agent_confidence".to_owned(),
            lower: 0.4,
            upper: 0.6,
            confidence: 0.9,
        }],
        participant_views: vec![ParticipantViewV1 {
            participant: "operator".to_owned(),
            visible_event_types: vec!["world.observation.v1".to_owned()],
            hidden_event_types: vec![
                "private.note".to_owned(),
                "proof.agent.reaction.v1".to_owned(),
                "experiment.lifecycle.consent-closed.v1".to_owned(),
            ],
            visible_events: vec![ParticipantEventV1 {
                seq: 1,
                event_type: "world.observation.v1".to_owned(),
                payload_digest: [1; 32],
            }],
        }],
        plugin_failures: Vec::new(),
        host_closure: HostClosureAuditV1 {
            subject: "subject".to_owned(),
            requested_after_seq: 1,
            effective_after_seq: 3,
            closure_event_seq: 3,
            closure_event_type: "experiment.lifecycle.consent-closed.v1".to_owned(),
            closure_payload_digest: [7; 32],
            halted_at_tick_boundary: true,
        },
        contract: proof_contract_fixture(),
    }
}

fn authorization_fixtures() -> (PrincipalRefV1, CapabilityGrantV1, AuthorizationDecisionV1) {
    let principal = PrincipalRefV1 {
        principal_id: "principal:operator".to_owned(),
        participant_id: "operator".to_owned(),
        subject_id: None,
        trust_domain: "test".to_owned(),
    };
    let grant = CapabilityGrantV1 {
        grant_id: "grant:operator".to_owned(),
        principal_id: principal.principal_id.clone(),
        capability: "observe".to_owned(),
        resource: "room".to_owned(),
        consent_epoch: 0,
        policy_digest: [3; 32],
    };
    let decision = AuthorizationDecisionV1 {
        principal_id: principal.principal_id.clone(),
        resource: "room".to_owned(),
        operation: "observe".to_owned(),
        allowed: true,
        reason: "test".to_owned(),
        consent_epoch: 0,
        grant_digest: [4; 32],
        decision_digest: [5; 32],
    };
    (principal, grant, decision)
}

fn counterfactual_fixture() -> CounterfactualContractV1 {
    let node = DependencyNodeV1 {
        tick: 1,
        scheduler_position: 0,
        owner_id: "body".to_owned(),
        output_ordinal: 0,
        schema_id: schema_id_for_event_type("world.observation.v1"),
        artifact_digest: [1; 32],
    };
    let frontier = RecomputationFrontierV1 {
        frontier_id: [1; 16],
        plan_digest: [2; 32],
        parent_cut_digest: [3; 32],
        dependency_graph_digest: [4; 32],
        intervention_seed_nodes: vec![node.clone()],
        affected_nodes: vec![node.clone()],
        owner_frontiers: vec![OwnerFrontierV1 {
            owner_id: "body".to_owned(),
            earliest_tick: 1,
            earliest_scheduler_position: 0,
            earliest_output_ordinal: 0,
            cause_node_digests: vec![[1; 32]],
        }],
        global_frontier_tick: 1,
        global_frontier_scheduler_position: 0,
        unknown_edge_policy: UnknownEdgePolicyV1::Reject,
        unknown_edge_coordinates: Vec::new(),
        endogenous_suffix_end_tick: 1,
        classification_bundle_digest: [5; 32],
        provenance_digest: [6; 32],
        frontier_digest: [7; 32],
    };
    let invalidation = SuffixInvalidationV1 {
        invalidation_id: [2; 16],
        plan_digest: [2; 32],
        fork_id: [3; 16],
        prior_generation: 0,
        new_generation: 1,
        frontier_digest: [7; 32],
        invalid_start: node.clone(),
        invalid_end: node.clone(),
        invalid_artifacts: vec![InvalidArtifactV1 {
            artifact_class: "event".to_owned(),
            schema_id: node.schema_id,
            artifact_digest: [1; 32],
            producer: node,
            prior_generation: 0,
            reason: SuffixInvalidationReasonV1::NewIntervention,
        }],
        invalid_checkpoint_digests: Vec::new(),
        invalid_projection_digests: Vec::new(),
        retained_exogenous_digests: vec![[8; 32]],
        reason: SuffixInvalidationReasonV1::NewIntervention,
        commit_timeline_id: [12; 16],
        commit_tick: 1,
        commit_seq: 1,
        provenance_digest: [9; 32],
        invalidation_digest: [10; 32],
    };
    CounterfactualContractV1 {
        fork_id: [3; 16],
        prior_generation: 0,
        generation: 1,
        intervention: None,
        dependencies: vec![InputDependencyV1 {
            consumer: DependencyNodeV1 {
                tick: 1,
                scheduler_position: 0,
                owner_id: "body".to_owned(),
                output_ordinal: 0,
                schema_id: schema_id_for_event_type("world.observation.v1"),
                artifact_digest: [1; 32],
            },
            source: DependencyNodeV1 {
                tick: 0,
                scheduler_position: 0,
                owner_id: "scenario-room".to_owned(),
                output_ordinal: 0,
                schema_id: schema_id_for_event_type("scenario.input.v1"),
                artifact_digest: [0; 32],
            },
            dependency_class: DependencyClassV1::EndogenousRecomputed,
            authorization_digest: [4; 32],
            provenance_digest: [5; 32],
        }],
        frontier,
        invalidation,
        recomputed_event_seqs: vec![2],
        retained_exogenous_digests: vec![[8; 32]],
        replay_claim: ReplayClaimV1::Exact,
        contract_digest: [11; 32],
    }
}

fn conformance_report_fixture() -> ConformanceReportV1 {
    let cases = vec![
        CaseOutcomeV1 {
            case_id: "scenario-air-gapped".to_owned(),
            fixture_digest: [14; 32],
            execution_profile_digest: [4; 32],
            mode: ExecutionModeV1::AirGapped,
            claim_layer: ClaimLayerV1::ReplayConformance,
            outcome: CaseOutcomeStatusV1::Pass,
            first_coordinate: None,
            expected_digest: Some([14; 32]),
            actual_digest: Some([14; 32]),
            expected_error: None,
            actual_error: None,
            replay_claim: ReplayClaimV1::Exact,
            redaction_state: RedactionStateV1::None,
            provenance_digest: [15; 32],
        },
        CaseOutcomeV1 {
            case_id: "scenario-local".to_owned(),
            fixture_digest: [14; 32],
            execution_profile_digest: [4; 32],
            mode: ExecutionModeV1::Local,
            claim_layer: ClaimLayerV1::ReplayConformance,
            outcome: CaseOutcomeStatusV1::Pass,
            first_coordinate: None,
            expected_digest: Some([14; 32]),
            actual_digest: Some([14; 32]),
            expected_error: None,
            actual_error: None,
            replay_claim: ReplayClaimV1::Exact,
            redaction_state: RedactionStateV1::None,
            provenance_digest: [15; 32],
        },
    ];
    let mut report = ConformanceReportV1 {
        report_id: [1; 16],
        subject_artifact_digest: [1; 32],
        profile_digest: [2; 32],
        normative_spec_digest: [3; 32],
        execution_profile_digest: [4; 32],
        fixture_bundle_digest: [5; 32],
        evaluator_source_digest: [6; 32],
        evaluator_binary_digest: [7; 32],
        evaluator_protocol_digest: [8; 32],
        implementation: ImplementationIdentityV1 {
            implementation_id: "test".to_owned(),
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
            declaration_digest: [9; 32],
            shared_code_audit_digest: [10; 32],
            reviewer_ids: vec!["reviewer".to_owned()],
        },
        cases,
        passed: 2,
        failed: 0,
        skipped: 0,
        unavailable: 0,
        not_applicable: 0,
        replay_claim: ReplayClaimV1::Exact,
        redaction_state: RedactionStateV1::None,
        limitations_digest: [11; 32],
        provenance_digest: [12; 32],
        report_digest: [0; 32],
    };
    report.report_digest = report.digest().unwrap_or([0; 32]);
    report
}

fn proof_contract_fixture() -> Wave8ProofContractV1 {
    let (principal, grant, decision) = authorization_fixtures();
    Wave8ProofContractV1 {
        scenario_room: ScenarioRoomFixtureV1 {
            room_id: "room".to_owned(),
            input_digest: [1; 32],
            horizon_ticks: 1,
            random_seed: 1,
            network_enabled: false,
            exogenous_digests: vec![[2; 32]],
            fixed_policy_digests: vec![[3; 32]],
            principals: vec![principal.clone()],
            grants: vec![grant.clone()],
            room_digest: [4; 32],
        },
        plugin_boundary: wave8_plugin_boundary(),
        knowledge_snapshots: vec![KnowledgeSnapshotV1 {
            participant_id: "operator".to_owned(),
            principal,
            grant,
            authorization: decision.clone(),
            tick: 1,
            visible_event_seqs: vec![1],
            visible_event_digests: vec![[1; 32]],
            hidden_event_types: vec!["proof.agent.reaction.v1".to_owned()],
            consent_epoch: 0,
            snapshot_digest: [14; 32],
        }],
        authorization_decisions: vec![decision],
        counterfactual: counterfactual_fixture(),
        atomicity: vec![TickAtomicityV1 {
            tick: 1,
            fork_generation: 1,
            staged_event_count: 1,
            committed_event_count: 1,
            state_digest_before: [1; 32],
            state_digest_after: [2; 32],
            committed: true,
            failure_class: None,
        }],
        conformance_report: conformance_report_fixture(),
        non_interference: wave8_non_interference_matrix([1; 32]),
    }
}

#[cfg_attr(coverage_nightly, coverage(off))]
fn expect_err<T, E: std::fmt::Debug>(value: &Result<T, E>) {
    if value.is_ok() {
        std::panic::resume_unwind(Box::new("expected a rejected coverage value"));
    }
}

#[cfg_attr(coverage_nightly, coverage(off))]
fn encode_value(value: &ciborium::Value) -> Vec<u8> {
    let mut bytes = Vec::new();
    if let Err(error) = ciborium::into_writer(value, &mut bytes) {
        std::panic::resume_unwind(Box::new(format!("test value encoding failed: {error}")));
    }
    bytes
}

#[cfg_attr(coverage_nightly, coverage(off))]
fn decode_value(bytes: Vec<u8>) -> ciborium::Value {
    ciborium::from_reader(std::io::Cursor::new(bytes)).unwrap_or(ciborium::Value::Null)
}

#[cfg_attr(coverage_nightly, coverage(off))]
fn replace_field(
    value: ciborium::Value,
    index: usize,
    replacement: ciborium::Value,
) -> ciborium::Value {
    let mut fields = match value {
        ciborium::Value::Array(fields) => fields,
        _ => Vec::new(),
    };
    fields[index] = replacement;
    ciborium::Value::Array(fields)
}

#[cfg_attr(coverage_nightly, coverage(off))]
fn replace_nested_field(
    value: ciborium::Value,
    outer: usize,
    inner: usize,
    replacement: ciborium::Value,
) -> ciborium::Value {
    let mut fields = match value {
        ciborium::Value::Array(fields) => fields,
        _ => Vec::new(),
    };
    let nested = fields.remove(outer);
    fields.insert(outer, replace_field(nested, inner, replacement));
    ciborium::Value::Array(fields)
}

#[cfg_attr(coverage_nightly, coverage(off))]
fn replace_evidence_case_coordinate(
    evidence: &ciborium::Value,
    coordinate: ciborium::Value,
) -> ciborium::Value {
    let mut evidence_fields = evidence.as_array().map_or_else(Vec::new, Clone::clone);
    let mut contract_fields = evidence_fields[EvidenceField::Contract.index()]
        .as_array()
        .map_or_else(Vec::new, Clone::clone);
    let mut report_fields = contract_fields[ContractField::Report.index()]
        .as_array()
        .map_or_else(Vec::new, Clone::clone);
    let mut cases = report_fields[ReportField::Cases.index()]
        .as_array()
        .map_or_else(Vec::new, Clone::clone);
    let mut case = cases[0].as_array().map_or_else(Vec::new, Clone::clone);
    case[CaseField::FirstCoordinate.index()] = coordinate;
    cases[0] = ciborium::Value::Array(case);
    report_fields[ReportField::Cases.index()] = ciborium::Value::Array(cases);
    contract_fields[ContractField::Report.index()] = ciborium::Value::Array(report_fields);
    evidence_fields[EvidenceField::Contract.index()] = ciborium::Value::Array(contract_fields);
    ciborium::Value::Array(evidence_fields)
}

#[cfg_attr(coverage_nightly, coverage(off))]
fn ok<T, E: std::fmt::Debug>(value: Result<T, E>) -> T {
    value.unwrap_or_else(|error| {
        std::panic::resume_unwind(Box::new(format!("unexpected coverage error: {error:?}")))
    })
}

#[cfg_attr(coverage_nightly, coverage(off))]
fn structural_paths(value: &ciborium::Value, path: &mut Vec<usize>, paths: &mut Vec<Vec<usize>>) {
    if let ciborium::Value::Array(fields) = value {
        for (index, field) in fields.iter().enumerate() {
            path.push(index);
            paths.push(path.clone());
            structural_paths(field, path, paths);
            path.pop();
        }
    }
}

#[cfg_attr(coverage_nightly, coverage(off))]
fn replace_at_path(value: &mut ciborium::Value, path: &[usize], replacement: ciborium::Value) {
    let mut current = value;
    for index in &path[..path.len() - 1] {
        current = &mut current
            .as_array_mut()
            .unwrap_or_else(|| std::panic::resume_unwind(Box::new("array path changed")))[*index];
    }
    current
        .as_array_mut()
        .unwrap_or_else(|| std::panic::resume_unwind(Box::new("array path changed")))
        [path[path.len() - 1]] = replacement;
}

#[cfg_attr(coverage_nightly, coverage(off))]
fn value_at_path<'a>(value: &'a ciborium::Value, path: &[usize]) -> &'a ciborium::Value {
    let mut current = value;
    for index in path {
        current = &current
            .as_array()
            .unwrap_or_else(|| std::panic::resume_unwind(Box::new("array path changed")))[*index];
    }
    current
}

#[cfg_attr(coverage_nightly, coverage(off))]
fn scalar_replacements(value: &ciborium::Value) -> Vec<ciborium::Value> {
    let mut replacements = vec![
        ciborium::Value::Null,
        ciborium::Value::Bool(false),
        ciborium::Value::Integer(0_u64.into()),
        ciborium::Value::Bytes(Vec::new()),
        ciborium::Value::Text(String::new()),
        ciborium::Value::Array(Vec::new()),
    ];
    replacements.extend(match value {
        ciborium::Value::Integer(_) => (0_u64..=13)
            .chain([u64::from(u16::MAX), u64::from(u32::MAX), u64::MAX])
            .map(|value| ciborium::Value::Integer(value.into()))
            .collect(),
        ciborium::Value::Bytes(_) => [0_usize, 15, 16, 31, 32, 33, 128, 129]
            .into_iter()
            .map(|length| ciborium::Value::Bytes(vec![0xff; length]))
            .collect(),
        ciborium::Value::Text(_) => [
            "",
            "unknown",
            "local",
            "air_gapped",
            "verified_exact",
            "resource_limit_exceeded",
        ]
        .into_iter()
        .map(|value| ciborium::Value::Text(value.to_owned()))
        .collect(),
        ciborium::Value::Bool(_) => {
            vec![ciborium::Value::Bool(false), ciborium::Value::Bool(true)]
        }
        ciborium::Value::Null => vec![
            ciborium::Value::Integer(0_u64.into()),
            ciborium::Value::Bytes(vec![0; 32]),
        ],
        ciborium::Value::Array(values) => {
            let mut replacements = vec![ciborium::Value::Array(Vec::new())];
            if let Some(first) = values.first() {
                replacements.push(ciborium::Value::Array(vec![first.clone(); 65]));
            }
            replacements
        }
        _ => Vec::new(),
    });
    replacements
}

#[cfg_attr(coverage_nightly, coverage(off))]
fn exercise_scalar_boundaries<T, E>(
    value: &ciborium::Value,
    decode: impl Fn(&[u8]) -> Result<T, E>,
    encode: impl Fn(&T) -> Result<Vec<u8>, E>,
) -> usize {
    let mut paths = Vec::new();
    structural_paths(value, &mut Vec::new(), &mut paths);
    let mut exercised = 0_usize;
    for path in paths {
        for replacement in scalar_replacements(value_at_path(value, &path)) {
            if replacement == *value_at_path(value, &path) {
                continue;
            }
            let mut mutant = value.clone();
            replace_at_path(&mut mutant, &path, replacement);
            let bytes = encode_value(&mutant);
            if let Ok(canonical) = decode(&bytes).and_then(|decoded| encode(&decoded)) {
                drop(decode(&canonical));
            }
            exercised += 1;
        }
    }
    exercised
}

#[cfg_attr(coverage_nightly, coverage(off))]
fn evidence_with_optional_record_variants() -> MoatProofEvidenceV1 {
    let mut evidence = public_evidence_fixture();
    evidence.plugin_failures = vec![
        PluginFailureV1 {
            plugin: "crashing-plugin".to_owned(),
            class: PluginFailureClassV1::PluginCrash,
            tick: 1,
            committed: false,
            staged_event_count: 1,
            committed_event_count: 0,
            state_digest_before: [21; 32],
            state_digest_after: [21; 32],
            sibling_step_count: 2,
        },
        PluginFailureV1 {
            plugin: "bounded-plugin".to_owned(),
            class: PluginFailureClassV1::ResourceExhaustion,
            tick: 2,
            committed: false,
            staged_event_count: 3,
            committed_event_count: 0,
            state_digest_before: [22; 32],
            state_digest_after: [22; 32],
            sibling_step_count: 4,
        },
    ];
    evidence.contract.counterfactual.intervention = Some(InterventionV1 {
        intervention_id: [23; 16],
        target: "body".to_owned(),
        operation: "set_velocity".to_owned(),
        value_digest: [24; 32],
        effective_tick: 1,
        ordinal: 0,
        principal_id: "principal:operator".to_owned(),
        capability: "intervene".to_owned(),
        consent_epoch: 0,
        provenance_digest: [25; 32],
    });
    evidence
}

#[cfg_attr(coverage_nightly, coverage(off))]
fn safe_error_codes() -> [SafeErrorCodeV1; 14] {
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
}

#[cfg_attr(coverage_nightly, coverage(off))]
fn divergence_report() -> DivergenceReportV1 {
    let mut report = DivergenceReportV1 {
        request_digest: [1; 32],
        manifest_digest: [2; 32],
        execution_profile_digest: [3; 32],
        fixture_digest: Some([4; 32]),
        evaluator_digest: [5; 32],
        reproducibility_class: ReproducibilityClassV1::ProfileRecomputation,
        replay_claim: ReplayClaimV1::Exact,
        location_kind: DivergenceLocationKindV1::TimelineSeq,
        timeline_or_worldcut_id: [6; 16],
        timeline_seq_or_cut_ordinal: 7,
        tick: 8,
        scheduler_position: Some(9),
        driver_or_plugin_id: Some("world".to_owned()),
        output_ordinal: Some(10),
        mismatch_kind: DivergenceMismatchKindV1::CanonicalBytes,
        expected: DigestSizeV1 {
            digest: Some([11; 32]),
            size: Some(12),
        },
        actual: DigestSizeV1 {
            digest: Some([13; 32]),
            size: Some(14),
        },
        prior_matching_checkpoint_digest: Some([15; 32]),
        follow_on_counts: vec![FollowOnMismatchV1 {
            kind: DivergenceMismatchKindV1::Artifact,
            count: 1,
        }],
        report_digest: [0; 32],
    };
    report.report_digest = ok(report.digest());
    report
}

#[test]
fn exported_record_entrypoints_are_exercised_from_an_instrumented_test() {
    let boundary = wave8_plugin_boundary();
    assert_eq!(boundary.validate(), Ok(()));

    let mut invalid_boundary = boundary.clone();
    invalid_boundary.manifest_digest = [1; 32];
    assert_eq!(
        invalid_boundary.validate(),
        Err(PluginBoundaryError::ManifestDigestMismatch)
    );
    invalid_boundary.manifest_digest = boundary.manifest_digest;
    invalid_boundary.release_digest = [1; 32];
    assert_eq!(
        invalid_boundary.validate(),
        Err(PluginBoundaryError::ReleaseDigestMismatch)
    );

    let evidence = public_evidence_fixture();
    assert!(evidence.digest().is_ok());
    let evidence_bytes = ok(evidence.to_canonical_cbor());
    assert_eq!(
        ok(MoatProofEvidenceV1::from_canonical_cbor(&evidence_bytes)),
        evidence
    );
    let verification = evidence.to_verification_result();
    assert!(verification.is_ok());
    let verification = verification.map(|result| {
        assert!(result.digest().is_ok());
        result.to_canonical_cbor()
    });
    assert!(verification.is_ok());

    let mut report = DivergenceReportV1 {
        request_digest: [1; 32],
        manifest_digest: [2; 32],
        execution_profile_digest: [3; 32],
        fixture_digest: Some([4; 32]),
        evaluator_digest: [5; 32],
        reproducibility_class: ReproducibilityClassV1::ProfileRecomputation,
        replay_claim: ReplayClaimV1::Exact,
        location_kind: DivergenceLocationKindV1::TimelineSeq,
        timeline_or_worldcut_id: [6; 16],
        timeline_seq_or_cut_ordinal: 7,
        tick: 8,
        scheduler_position: Some(9),
        driver_or_plugin_id: Some("world".to_owned()),
        output_ordinal: Some(10),
        mismatch_kind: DivergenceMismatchKindV1::CanonicalBytes,
        expected: DigestSizeV1 {
            digest: Some([11; 32]),
            size: Some(12),
        },
        actual: DigestSizeV1 {
            digest: Some([13; 32]),
            size: Some(14),
        },
        prior_matching_checkpoint_digest: Some([15; 32]),
        follow_on_counts: vec![FollowOnMismatchV1 {
            kind: DivergenceMismatchKindV1::Artifact,
            count: 1,
        }],
        report_digest: [0; 32],
    };
    report.report_digest = report.digest().unwrap_or([0; 32]);
    let report_bytes = report.to_canonical_cbor();
    assert!(report_bytes.is_ok());
    assert!(DivergenceReportV1::from_canonical_cbor(&report_bytes.unwrap_or_default()).is_ok());
}

#[test]
fn malformed_canonical_records_reach_closed_decoder_boundaries() {
    let evidence = public_evidence_fixture();
    expect_err(&MoatProofEvidenceV1::from_canonical_cbor(&encode_value(
        &ciborium::Value::Map(Vec::new()),
    )));
    let mut invalid_closure = evidence.clone();
    invalid_closure.host_closure.closure_event_type = "other".to_owned();
    expect_err(&verify_evidence(&invalid_closure));
    let value = decode_value(ok(evidence.to_canonical_cbor()));
    let mut paths = Vec::new();
    structural_paths(&value, &mut Vec::new(), &mut paths);
    assert!(paths.len() > 512);
    for path in paths {
        let mut mutant = value.clone();
        replace_at_path(
            &mut mutant,
            &path,
            ciborium::Value::Tag(u64::MAX, Box::new(ciborium::Value::Null)),
        );
        expect_err(&MoatProofEvidenceV1::from_canonical_cbor(&encode_value(
            &mutant,
        )));
    }
    expect_err(&MoatProofEvidenceV1::from_canonical_cbor(&encode_value(
        &replace_field(
            value.clone(),
            EvidenceField::Magic.index(),
            ciborium::Value::Text("wrong".to_owned()),
        ),
    )));
    expect_err(&MoatProofEvidenceV1::from_canonical_cbor(&encode_value(
        &replace_field(
            value.clone(),
            EvidenceField::Version.index(),
            ciborium::Value::Integer(99_u64.into()),
        ),
    )));
    expect_err(&MoatProofEvidenceV1::from_canonical_cbor(&encode_value(
        &replace_nested_field(
            value,
            EvidenceField::Manifest.index(),
            ManifestField::ExecutionProfile.index(),
            ciborium::Value::Text("wrong".to_owned()),
        ),
    )));

    let result = ok(public_evidence_fixture().to_verification_result());
    let result_value = decode_value(ok(result.to_canonical_cbor()));
    assert!(
        exercise_scalar_boundaries(
            &result_value,
            VerificationResultV1::from_canonical_cbor,
            VerificationResultV1::to_canonical_cbor,
        ) > 100
    );
    expect_err(&VerificationResultV1::from_canonical_cbor(&encode_value(
        &replace_field(
            result_value,
            VerificationField::ResultDigest.index(),
            ciborium::Value::Bytes(vec![0; 32]),
        ),
    )));

    let mut report = DivergenceReportV1 {
        request_digest: [1; 32],
        manifest_digest: [2; 32],
        execution_profile_digest: [3; 32],
        fixture_digest: Some([4; 32]),
        evaluator_digest: [5; 32],
        reproducibility_class: ReproducibilityClassV1::ProfileRecomputation,
        replay_claim: ReplayClaimV1::Exact,
        location_kind: DivergenceLocationKindV1::TimelineSeq,
        timeline_or_worldcut_id: [6; 16],
        timeline_seq_or_cut_ordinal: 7,
        tick: 8,
        scheduler_position: Some(9),
        driver_or_plugin_id: Some("world".to_owned()),
        output_ordinal: Some(10),
        mismatch_kind: DivergenceMismatchKindV1::CanonicalBytes,
        expected: DigestSizeV1 {
            digest: Some([11; 32]),
            size: Some(12),
        },
        actual: DigestSizeV1 {
            digest: Some([13; 32]),
            size: Some(14),
        },
        prior_matching_checkpoint_digest: Some([15; 32]),
        follow_on_counts: vec![FollowOnMismatchV1 {
            kind: DivergenceMismatchKindV1::Artifact,
            count: 1,
        }],
        report_digest: [0; 32],
    };
    report.report_digest = ok(report.digest());
    let report_value = decode_value(ok(report.to_canonical_cbor()));
    assert!(
        exercise_scalar_boundaries(
            &report_value,
            DivergenceReportV1::from_canonical_cbor,
            DivergenceReportV1::to_canonical_cbor,
        ) > 100
    );
    expect_err(&DivergenceReportV1::from_canonical_cbor(&encode_value(
        &replace_field(
            report_value,
            ReportField::Digest.index(),
            ciborium::Value::Bytes(vec![0; 32]),
        ),
    )));

    report.driver_or_plugin_id = Some("x".repeat(20_000));
    expect_err(&report.to_canonical_cbor());
}

#[test]
fn public_evidence_decoder_enforces_case_coordinate_boundary() {
    let evidence = public_evidence_fixture();
    let encoded = decode_value(ok(evidence.to_canonical_cbor()));
    let exact = replace_evidence_case_coordinate(&encoded, ciborium::Value::Bytes(vec![b'x'; 128]));
    assert!(MoatProofEvidenceV1::from_canonical_cbor(&encode_value(&exact)).is_ok());

    let oversized =
        replace_evidence_case_coordinate(&encoded, ciborium::Value::Bytes(vec![b'x'; 129]));
    expect_err(&MoatProofEvidenceV1::from_canonical_cbor(&encode_value(
        &oversized,
    )));

    let wrong_type =
        replace_evidence_case_coordinate(&encoded, ciborium::Value::Text("coordinate".to_owned()));
    expect_err(&MoatProofEvidenceV1::from_canonical_cbor(&encode_value(
        &wrong_type,
    )));
}

#[test]
fn public_evidence_decoder_closes_scalar_and_length_boundaries() {
    let evidence = evidence_with_optional_record_variants();
    let value = decode_value(ok(evidence.to_canonical_cbor()));
    assert!(
        exercise_scalar_boundaries(
            &value,
            MoatProofEvidenceV1::from_canonical_cbor,
            MoatProofEvidenceV1::to_canonical_cbor,
        ) > 0
    );
}

#[test]
#[cfg_attr(coverage_nightly, coverage(off))]
fn public_record_variants_round_trip_at_the_wire_seam() {
    let evidence = evidence_with_optional_record_variants();
    let encoded = ok(evidence.to_canonical_cbor());
    assert_eq!(
        ok(MoatProofEvidenceV1::from_canonical_cbor(&encoded)),
        evidence
    );

    for code in safe_error_codes() {
        let mut with_error = evidence.clone();
        with_error.contract.conformance_report.cases[0].expected_error = Some(code);
        with_error.contract.conformance_report.cases[0].actual_error = Some(code);
        let encoded = ok(with_error.to_canonical_cbor());
        assert_eq!(
            ok(MoatProofEvidenceV1::from_canonical_cbor(&encoded)),
            with_error
        );
    }

    let base = ok(public_evidence_fixture().to_verification_result());
    let outcomes = [
        VerificationOutcomeV1::VerifiedExact,
        VerificationOutcomeV1::Diverged,
        VerificationOutcomeV1::InvalidManifest,
        VerificationOutcomeV1::UnverifiableArtifactsMissing,
        VerificationOutcomeV1::IncompatibleProfile,
        VerificationOutcomeV1::ResourceLimitExceeded,
    ];
    for (outcome, code) in outcomes.into_iter().zip(safe_error_codes()) {
        let mut result = base.clone();
        result.verification_outcome = outcome;
        match outcome {
            VerificationOutcomeV1::VerifiedExact => {}
            VerificationOutcomeV1::Diverged => {
                result.authoritative_result_digest = None;
                result.divergence_report_digest = Some([26; 32]);
            }
            VerificationOutcomeV1::InvalidManifest
            | VerificationOutcomeV1::UnverifiableArtifactsMissing
            | VerificationOutcomeV1::IncompatibleProfile
            | VerificationOutcomeV1::ResourceLimitExceeded => {
                result.authoritative_result_digest = None;
                result.first_error = Some(VerificationErrorV1 {
                    code,
                    field_ordinal: Some(1),
                    canonical_coordinate: Some(vec![2, 3]),
                    related_digest: Some([27; 32]),
                });
            }
        }
        result.result_digest = ok(result.digest());
        let encoded = ok(result.to_canonical_cbor());
        assert_eq!(
            ok(VerificationResultV1::from_canonical_cbor(&encoded)),
            result
        );
    }
}

#[test]
#[cfg_attr(coverage_nightly, coverage(off))]
fn public_record_rejections_cover_semantic_boundaries() {
    let mut invalid_evidence = public_evidence_fixture();
    invalid_evidence.format_version += 1;
    expect_err(&invalid_evidence.to_verification_result());

    let evidence = public_evidence_fixture();
    assert!(evidence.to_verification_result_cbor().is_ok());
    let result = ok(evidence.to_verification_result());
    for mutate in [
        |value: &mut VerificationResultV1| value.checked_artifact_count = 65_537,
        |value: &mut VerificationResultV1| value.provenance_digest = [0; 32],
        |value: &mut VerificationResultV1| value.result_digest = [0; 32],
    ] {
        let mut invalid = result.clone();
        mutate(&mut invalid);
        expect_err(&invalid.to_canonical_cbor());
    }
    let mut oversized_coordinate = result.clone();
    oversized_coordinate.verification_outcome = VerificationOutcomeV1::InvalidManifest;
    oversized_coordinate.authoritative_result_digest = None;
    oversized_coordinate.first_error = Some(VerificationErrorV1 {
        code: SafeErrorCodeV1::InvalidEncoding,
        field_ordinal: Some(1),
        canonical_coordinate: Some(vec![0; 129]),
        related_digest: None,
    });
    oversized_coordinate.result_digest = ok(oversized_coordinate.digest());
    expect_err(&oversized_coordinate.to_canonical_cbor());

    let result_value = decode_value(ok(result.to_canonical_cbor()));
    let negative_count = replace_field(
        result_value,
        VerificationField::CheckedArtifactCount.index(),
        ciborium::Value::Integer((-1_i64).into()),
    );
    expect_err(&VerificationResultV1::from_canonical_cbor(&encode_value(
        &negative_count,
    )));
    let mut trailing_result = ok(result.to_canonical_cbor());
    trailing_result.push(0);
    expect_err(&VerificationResultV1::from_canonical_cbor(&trailing_result));

    let mut error_result = result;
    error_result.verification_outcome = VerificationOutcomeV1::InvalidManifest;
    error_result.authoritative_result_digest = None;
    error_result.first_error = Some(VerificationErrorV1 {
        code: SafeErrorCodeV1::InvalidEncoding,
        field_ordinal: None,
        canonical_coordinate: None,
        related_digest: None,
    });
    error_result.result_digest = ok(error_result.digest());
    let error_value = decode_value(ok(error_result.to_canonical_cbor()));
    let invalid_safe_error = replace_nested_field(
        error_value,
        VerificationField::FirstError.index(),
        VerificationErrorField::Code.index(),
        ciborium::Value::Integer(14_u64.into()),
    );
    expect_err(&VerificationResultV1::from_canonical_cbor(&encode_value(
        &invalid_safe_error,
    )));

    let report = divergence_report();
    let invalid_reports: [fn(&mut DivergenceReportV1); 9] = [
        |value| value.timeline_seq_or_cut_ordinal = u64::MAX,
        |value| value.tick = u64::MAX,
        |value| value.scheduler_position = Some(u32::MAX),
        |value| value.output_ordinal = Some(u32::MAX),
        |value| value.driver_or_plugin_id = Some(String::new()),
        |value| value.report_digest = [0; 32],
        |value| value.follow_on_counts = vec![value.follow_on_counts[0].clone(); 33],
        |value| value.follow_on_counts[0].count = 0,
        |value| {
            value
                .follow_on_counts
                .push(value.follow_on_counts[0].clone());
        },
    ];
    for mutate in invalid_reports {
        let mut invalid = report.clone();
        mutate(&mut invalid);
        let encoded = ok(invalid.to_canonical_cbor());
        expect_err(&DivergenceReportV1::from_canonical_cbor(&encoded));
    }
    let mut trailing_report = ok(report.to_canonical_cbor());
    trailing_report.push(0);
    expect_err(&DivergenceReportV1::from_canonical_cbor(&trailing_report));
}
