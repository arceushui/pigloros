//! Public-interface tests for the ADR-064 CFP1 counterfactual-plan contract.

use ciborium::value::Value;
use pos_conformance::counterfactual::plan::{
    CounterfactualPlanContractErrorV1 as PlanError, CounterfactualPlanV1,
    FrozenArtifactDescriptorV1 as Descriptor, PlanExecutionProfileRefV1, PlanTrustPolicyRefV1,
    COUNTERFACTUAL_PLAN_MAGIC_V1, MAX_COUNTERFACTUAL_PLAN_BYTES_V1,
    MAX_EXOGENOUS_DESCRIPTORS_PER_PLAN_V1, MAX_FIXED_POLICY_DESCRIPTORS_PER_PLAN_V1,
};
use pos_conformance::counterfactual::{
    InterventionContractErrorV1 as InterventionError, InterventionOperationV1, InterventionV1,
    MAX_INTERVENTIONS_PER_PLAN_V1,
};
use pos_conformance::{
    draft_execution_profile_bytes_v1, draft_trust_policy_snapshot_bytes_v1,
    ExecutionProfileContractErrorV1, ExecutionProfileV1, ReplayClaimV1,
    TrustPolicySnapshotContractErrorV1, TrustPolicySnapshotV1,
};
use std::collections::BTreeSet;
use std::error::Error as _;
use std::io::Cursor;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
type Edit = fn(&mut CounterfactualPlanV1);

const FIELD_ROOM_ID: usize = 3;
const FIELD_INTERVENTIONS: usize = 11;
const FIELD_EXOGENOUS: usize = 12;
const FIELD_FIXED_POLICY: usize = 13;
const FIELD_EXECUTION_PROFILE: usize = 15;
const FIELD_TRUST_POLICY: usize = 16;
const FIELD_REPLAY_CLAIM: usize = 22;
const FIELD_PREVIOUS: usize = 23;
const FIELD_PLAN_DIGEST: usize = 24;

fn intervention(effective_tick: u64, ordinal: u32, id_seed: u32) -> InterventionV1 {
    let mut intervention_id = [0; 16];
    intervention_id[..4].copy_from_slice(&id_seed.to_be_bytes());
    InterventionV1 {
        intervention_id,
        target_schema_id: 7,
        target_entity_id: "body".to_owned(),
        target_field: "velocity".to_owned(),
        operation: InterventionOperationV1::AssignValue,
        value_digest: [2; 32],
        effective_tick,
        ordinal,
        principal_id: "principal:operator".to_owned(),
        capability: "intervene".to_owned(),
        consent_epoch: 3,
        consent_decision_digest: [4; 32],
        rationale: "what if".to_owned(),
        provenance_digest: [6; 32],
    }
}

const fn descriptor(schema_id: u32, seed: u8) -> Descriptor {
    Descriptor {
        schema_id,
        artifact_digest: [seed; 32],
        authorization_digest: [0x61; 32],
        provenance_digest: [0x62; 32],
    }
}

fn digest_from(index: u32) -> [u8; 32] {
    let mut digest = [0xa5; 32];
    digest[..4].copy_from_slice(&index.to_be_bytes());
    digest
}

fn draft_profile() -> TestResult<ExecutionProfileV1> {
    let bytes = draft_execution_profile_bytes_v1("deterministic-local-v1")?;
    Ok(ExecutionProfileV1::from_canonical_cbor(&bytes)?)
}

fn draft_snapshot() -> TestResult<TrustPolicySnapshotV1> {
    let bytes = draft_trust_policy_snapshot_bytes_v1()?;
    Ok(TrustPolicySnapshotV1::from_canonical_cbor(&bytes)?)
}

fn sealed(mut plan: CounterfactualPlanV1) -> Result<CounterfactualPlanV1, PlanError> {
    plan.plan_digest = plan.digest()?;
    Ok(plan)
}

fn plan() -> TestResult<CounterfactualPlanV1> {
    Ok(sealed(CounterfactualPlanV1 {
        plan_id: [1; 16],
        room_id: "room.alpha".to_owned(),
        room_digest: [2; 32],
        parent_timeline_id: [3; 16],
        parent_cut_seq: 41,
        parent_cut_tick: 9,
        parent_cut_digest: [4; 32],
        first_tick: 10,
        horizon_tick: 20,
        interventions: vec![intervention(10, 0, 1), intervention(12, 0, 2)],
        exogenous_descriptors: vec![descriptor(1, 0x50), descriptor(2, 0x40)],
        fixed_policy_descriptors: vec![descriptor(3, 0x30)],
        classification_bundle_digest: [5; 32],
        execution_profile: PlanExecutionProfileRefV1::from_execution_profile_v1(&draft_profile()?)?,
        trust_policy: PlanTrustPolicyRefV1::from_trust_policy_snapshot_v1(&draft_snapshot()?)?,
        plugin_composition_digest: [6; 32],
        scheduler_digest: [7; 32],
        numeric_profile_digest: [8; 32],
        budget_digest: [9; 32],
        failure_policy_digest: [10; 32],
        replay_claim: ReplayClaimV1::Exact,
        previous_plan_digest: Some([11; 32]),
        plan_digest: [0; 32],
    })?)
}

fn resealed_validation(
    base: &CounterfactualPlanV1,
    edit: impl Fn(&mut CounterfactualPlanV1),
) -> Result<(), PlanError> {
    let mut plan = base.clone();
    edit(&mut plan);
    sealed(plan)?.validate()
}

fn encode(value: &Value) -> TestResult<Vec<u8>> {
    let mut bytes = Vec::new();
    ciborium::into_writer(value, &mut bytes)?;
    Ok(bytes)
}

fn fields_of(bytes: &[u8]) -> TestResult<Vec<Value>> {
    match ciborium::from_reader(Cursor::new(bytes))? {
        Value::Array(fields) => Ok(fields),
        _ => Err("CFP1 must be an array".into()),
    }
}

fn with_field(bytes: &[u8], index: usize, value: Value) -> TestResult<Vec<u8>> {
    let mut fields = fields_of(bytes)?;
    fields[index] = value;
    encode(&Value::Array(fields))
}

fn uint(value: u64) -> Value {
    Value::Integer(value.into())
}

fn text(value: &str) -> Value {
    Value::Text(value.to_owned())
}

fn digest(seed: u8) -> Value {
    Value::Bytes(vec![seed; 32])
}

fn decoded(bytes: &[u8]) -> Result<CounterfactualPlanV1, PlanError> {
    CounterfactualPlanV1::from_canonical_cbor(bytes)
}

#[test]
fn plan_roundtrips_exact_wire_fields_and_domain_digest() -> TestResult {
    let plan = plan()?;
    assert_eq!(plan.validate(), Ok(()));
    let bytes = plan.to_canonical_cbor()?;
    assert_eq!(decoded(&bytes)?, plan);

    let mut expected = vec![
        text("CFP1"),
        uint(1),
        Value::Bytes(vec![1; 16]),
        text("room.alpha"),
        digest(2),
        Value::Bytes(vec![3; 16]),
        uint(41),
        uint(9),
        digest(4),
        uint(10),
        uint(20),
        Value::Array(vec![
            Value::Bytes(plan.interventions[0].to_canonical_cbor()?),
            Value::Bytes(plan.interventions[1].to_canonical_cbor()?),
        ]),
        Value::Array(vec![
            descriptor_value(&descriptor(1, 0x50)),
            descriptor_value(&descriptor(2, 0x40)),
        ]),
        Value::Array(vec![descriptor_value(&descriptor(3, 0x30))]),
        digest(5),
        Value::Array(vec![
            text(&plan.execution_profile.profile_id),
            text(&plan.execution_profile.semantic_version),
            Value::Bytes(plan.execution_profile.profile_digest.to_vec()),
        ]),
        Value::Array(vec![
            text(&plan.trust_policy.policy_id),
            uint(plan.trust_policy.epoch),
            Value::Bytes(plan.trust_policy.snapshot_digest.to_vec()),
        ]),
        digest(6),
        digest(7),
        digest(8),
        digest(9),
        digest(10),
        uint(0),
        digest(11),
    ];
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"PiglorOS.CounterfactualPlan.v1\0");
    hasher.update(&encode(&Value::Array(expected.clone()))?);
    assert_eq!(plan.digest()?, *hasher.finalize().as_bytes());
    expected.push(Value::Bytes(plan.plan_digest.to_vec()));
    assert_eq!(fields_of(&bytes)?, expected);
    assert_eq!(text(COUNTERFACTUAL_PLAN_MAGIC_V1), expected[0]);

    let mut first_plan = plan.clone();
    first_plan.previous_plan_digest = None;
    first_plan.exogenous_descriptors.clear();
    first_plan.fixed_policy_descriptors.clear();
    let first_plan = sealed(first_plan)?;
    let bytes = first_plan.to_canonical_cbor()?;
    let fields = fields_of(&bytes)?;
    assert_eq!(fields[FIELD_PREVIOUS], Value::Null);
    assert_eq!(fields[FIELD_EXOGENOUS], Value::Array(Vec::new()));
    assert_eq!(fields[FIELD_FIXED_POLICY], Value::Array(Vec::new()));
    assert_eq!(decoded(&bytes)?, first_plan);
    Ok(())
}

#[test]
fn identity_refs_bind_validated_epf1_and_tps1_records() -> TestResult {
    let profile = draft_profile()?;
    let profile_ref = PlanExecutionProfileRefV1::from_execution_profile_v1(&profile)?;
    assert_eq!(
        profile_ref,
        PlanExecutionProfileRefV1 {
            profile_id: "deterministic-local-v1".to_owned(),
            semantic_version: profile.semantic_version.clone(),
            profile_digest: profile.digest(),
        }
    );
    let mut tampered = profile;
    tampered.profile_digest[0] ^= 1;
    assert_eq!(
        PlanExecutionProfileRefV1::from_execution_profile_v1(&tampered),
        Err(ExecutionProfileContractErrorV1::DigestMismatch)
    );

    let snapshot = draft_snapshot()?;
    let snapshot_bytes = snapshot.to_canonical_cbor()?;
    let policy_ref = PlanTrustPolicyRefV1::from_trust_policy_snapshot_v1(&snapshot)?;
    assert_eq!(
        policy_ref,
        PlanTrustPolicyRefV1 {
            policy_id: snapshot.policy_id.clone(),
            epoch: snapshot.epoch,
            snapshot_digest: *blake3::hash(&snapshot_bytes).as_bytes(),
        }
    );
    let mut invalid = snapshot;
    invalid.epoch = 0;
    assert_eq!(
        PlanTrustPolicyRefV1::from_trust_policy_snapshot_v1(&invalid),
        Err(TrustPolicySnapshotContractErrorV1::FieldOutOfBounds)
    );
    Ok(())
}

#[test]
fn every_replay_claim_has_one_exact_wire_code() -> TestResult {
    let claims = [
        ReplayClaimV1::Exact,
        ReplayClaimV1::ExactAuthoritativeWithRedactedViews,
        ReplayClaimV1::StructuralOnly,
        ReplayClaimV1::UnverifiableArtifactsMissing,
        ReplayClaimV1::IncompatibleProfile,
    ];
    for (index, claim) in claims.into_iter().enumerate() {
        let mut plan = plan()?;
        plan.replay_claim = claim;
        let plan = sealed(plan)?;
        let bytes = plan.to_canonical_cbor()?;
        assert_eq!(
            fields_of(&bytes)?[FIELD_REPLAY_CLAIM],
            uint(u64::try_from(index)?)
        );
        assert_eq!(decoded(&bytes)?, plan);
    }
    let valid = plan()?.to_canonical_cbor()?;
    for code in [5, u64::MAX] {
        let bytes = with_field(&valid, FIELD_REPLAY_CLAIM, uint(code))?;
        assert_eq!(decoded(&bytes), Err(PlanError::UnknownEnum));
    }
    Ok(())
}

#[test]
fn digest_binds_every_field_and_the_declared_digest_is_checked() -> TestResult {
    let base = plan()?;
    let edits: [Edit; 27] = [
        |plan| plan.plan_id[0] ^= 1,
        |plan| plan.room_id.push('x'),
        |plan| plan.room_digest[0] ^= 1,
        |plan| plan.parent_timeline_id[0] ^= 1,
        |plan| plan.parent_cut_seq += 1,
        |plan| plan.parent_cut_digest[0] ^= 1,
        |plan| plan.horizon_tick += 1,
        |plan| plan.interventions[1].value_digest[0] ^= 1,
        |plan| plan.interventions[1].effective_tick += 1,
        |plan| plan.exogenous_descriptors[0].schema_id = 0,
        |plan| plan.exogenous_descriptors[0].artifact_digest[0] ^= 1,
        |plan| plan.exogenous_descriptors[0].authorization_digest[0] ^= 1,
        |plan| plan.exogenous_descriptors[0].provenance_digest[0] ^= 1,
        |plan| plan.fixed_policy_descriptors[0].provenance_digest[0] ^= 1,
        |plan| plan.classification_bundle_digest[0] ^= 1,
        |plan| plan.execution_profile.profile_id.push('x'),
        |plan| plan.execution_profile.semantic_version = "1.0.1".to_owned(),
        |plan| plan.execution_profile.profile_digest[0] ^= 1,
        |plan| plan.trust_policy.policy_id.push('x'),
        |plan| plan.trust_policy.epoch += 1,
        |plan| plan.trust_policy.snapshot_digest[0] ^= 1,
        |plan| plan.plugin_composition_digest[0] ^= 1,
        |plan| plan.scheduler_digest[0] ^= 1,
        |plan| plan.numeric_profile_digest[0] ^= 1,
        |plan| plan.budget_digest[0] ^= 1,
        |plan| plan.failure_policy_digest[0] ^= 1,
        |plan| plan.previous_plan_digest = None,
    ];
    for edit in edits {
        let mut plan = base.clone();
        edit(&mut plan);
        assert_ne!(plan.digest()?, base.digest()?);
        assert_eq!(plan.validate(), Err(PlanError::DigestMismatch));
        assert_eq!(sealed(plan)?.validate(), Ok(()));
    }
    let mut cut_moved = base.clone();
    cut_moved.parent_cut_tick += 1;
    cut_moved.first_tick += 1;
    cut_moved.interventions[0].effective_tick += 1;
    assert_ne!(cut_moved.digest()?, base.digest()?);
    assert_eq!(sealed(cut_moved)?.validate(), Ok(()));
    let mut claim = base.clone();
    claim.replay_claim = ReplayClaimV1::StructuralOnly;
    assert_ne!(claim.digest()?, base.digest()?);

    let mut tampered = base.clone();
    tampered.plan_digest[31] ^= 1;
    assert_eq!(tampered.validate(), Err(PlanError::DigestMismatch));
    assert_eq!(tampered.to_canonical_cbor(), Err(PlanError::DigestMismatch));
    let bytes = with_field(
        &base.to_canonical_cbor()?,
        FIELD_PLAN_DIGEST,
        Value::Bytes(tampered.plan_digest.to_vec()),
    )?;
    assert_eq!(decoded(&bytes), Err(PlanError::DigestMismatch));

    let mut unencodable = base;
    unencodable.interventions[0].rationale.clear();
    assert_eq!(
        unencodable.digest(),
        Err(PlanError::Intervention(InterventionError::FieldOutOfBounds))
    );
    Ok(())
}

fn identifier_cases() -> [(String, bool); 24] {
    [
        ("a".to_owned(), true),
        ("x".repeat(128), true),
        ("a/b".to_owned(), true),
        ("..a".to_owned(), true),
        ("a.b".to_owned(), true),
        ("a./.b".to_owned(), true),
        ("a~".to_owned(), true),
        ("ab:c".to_owned(), true),
        ("1:a".to_owned(), true),
        ("a/C:b".to_owned(), true),
        (String::new(), false),
        ("x".repeat(129), false),
        ("a\u{7}b".to_owned(), false),
        ("/abs".to_owned(), false),
        ("~home".to_owned(), false),
        ("a\\b".to_owned(), false),
        ("a/../b".to_owned(), false),
        ("C:room".to_owned(), false),
        ("z:".to_owned(), false),
        ("C:\\room".to_owned(), false),
        (".".to_owned(), false),
        ("./a".to_owned(), false),
        ("a/./b".to_owned(), false),
        ("a/.".to_owned(), false),
    ]
}

#[test]
fn identifiers_are_bounded_and_carry_no_operational_path() -> TestResult {
    let base = plan()?;
    let setters: [fn(&mut CounterfactualPlanV1, String); 3] = [
        |plan, value| plan.room_id = value,
        |plan, value| plan.execution_profile.profile_id = value,
        |plan, value| plan.trust_policy.policy_id = value,
    ];
    for setter in setters {
        for (value, accepted) in identifier_cases() {
            let expected = if accepted {
                Ok(())
            } else {
                Err(PlanError::FieldOutOfBounds)
            };
            assert_eq!(
                resealed_validation(&base, |plan| setter(plan, value.clone())),
                expected,
                "{value:?}"
            );
        }
    }
    // `1.0.0+` is six bytes, so the build suffix sets the total length.
    for (version, expected) in [
        ("2.0.0".to_owned(), Ok(())),
        (format!("1.0.0+{}", "a".repeat(58)), Ok(())),
        (
            format!("1.0.0+{}", "a".repeat(59)),
            Err(PlanError::FieldOutOfBounds),
        ),
        ("1.0".to_owned(), Err(PlanError::FieldOutOfBounds)),
        (String::new(), Err(PlanError::FieldOutOfBounds)),
    ] {
        assert_eq!(
            resealed_validation(&base, |plan| {
                plan.execution_profile.semantic_version.clone_from(&version);
            }),
            expected,
            "{} bytes",
            version.len()
        );
    }
    let bytes = with_field(
        &base.to_canonical_cbor()?,
        FIELD_ROOM_ID,
        text("/var/lib/room"),
    )?;
    assert_eq!(decoded(&bytes), Err(PlanError::FieldOutOfBounds));
    Ok(())
}

#[test]
fn scalar_bounds_are_enforced_at_each_edge() -> TestResult {
    let base = plan()?;
    let cases: [(Edit, Result<(), PlanError>); 8] = [
        (
            |plan| plan.trust_policy.epoch = 0,
            Err(PlanError::FieldOutOfBounds),
        ),
        (|plan| plan.trust_policy.epoch = u64::MAX, Ok(())),
        (
            |plan| plan.parent_cut_tick = 8,
            Err(PlanError::FieldOutOfBounds),
        ),
        (
            |plan| plan.parent_cut_tick = 10,
            Err(PlanError::FieldOutOfBounds),
        ),
        (|plan| plan.horizon_tick = 12, Ok(())),
        (
            |plan| {
                plan.horizon_tick = 10;
                plan.interventions.truncate(1);
            },
            Ok(()),
        ),
        (
            |plan| {
                plan.horizon_tick = 9;
                plan.interventions.clear();
            },
            Err(PlanError::FieldOutOfBounds),
        ),
        (
            |plan| {
                plan.parent_cut_tick = u64::MAX;
                plan.first_tick = 0;
            },
            Err(PlanError::FieldOutOfBounds),
        ),
    ];
    for (edit, expected) in cases {
        assert_eq!(resealed_validation(&base, edit), expected);
    }
    assert_eq!(
        resealed_validation(&base, |plan| {
            plan.parent_cut_tick = u64::MAX - 1;
            plan.first_tick = u64::MAX;
            plan.horizon_tick = u64::MAX;
            plan.interventions = vec![intervention(u64::MAX, 0, 1)];
        }),
        Ok(())
    );
    Ok(())
}

#[test]
fn a_plan_cannot_supersede_itself() -> TestResult {
    let base = plan()?;
    let mut self_superseding = base.clone();
    self_superseding.previous_plan_digest = Some(base.plan_digest);
    assert_eq!(
        self_superseding.validate(),
        Err(PlanError::FieldOutOfBounds)
    );
    assert_eq!(
        self_superseding.to_canonical_cbor(),
        Err(PlanError::FieldOutOfBounds)
    );
    let bytes = with_field(
        &base.to_canonical_cbor()?,
        FIELD_PREVIOUS,
        Value::Bytes(base.plan_digest.to_vec()),
    )?;
    assert_eq!(decoded(&bytes), Err(PlanError::FieldOutOfBounds));
    Ok(())
}

#[test]
fn interventions_are_validated_by_int1_and_stay_inside_the_window() -> TestResult {
    let base = plan()?;
    let cases: [(Edit, Result<(), PlanError>); 8] = [
        (
            |plan| plan.interventions.clear(),
            Err(PlanError::Intervention(InterventionError::FieldOutOfBounds)),
        ),
        (
            |plan| plan.interventions.reverse(),
            Err(PlanError::Intervention(
                InterventionError::NonCanonicalOrder,
            )),
        ),
        (
            |plan| plan.interventions[1].ordinal = 1,
            Err(PlanError::Intervention(
                InterventionError::NonContiguousOrdinal,
            )),
        ),
        (
            |plan| plan.interventions[0].target_field.clear(),
            Err(PlanError::Intervention(InterventionError::FieldOutOfBounds)),
        ),
        (
            |plan| plan.interventions[0].effective_tick = 9,
            Err(PlanError::InterventionBeforeCut),
        ),
        (|plan| plan.interventions[1].effective_tick = 20, Ok(())),
        (
            |plan| plan.interventions[1].effective_tick = 21,
            Err(PlanError::FieldOutOfBounds),
        ),
        (
            |plan| {
                plan.interventions[0].effective_tick = 9;
                plan.interventions[1].effective_tick = 21;
            },
            Err(PlanError::InterventionBeforeCut),
        ),
    ];
    for (edit, expected) in cases {
        assert_eq!(resealed_validation(&base, edit), expected);
    }
    Ok(())
}

#[test]
fn intervention_list_accepts_exactly_its_bound() -> TestResult {
    let mut plan = plan()?;
    plan.interventions = (0..u32::try_from(MAX_INTERVENTIONS_PER_PLAN_V1)?)
        .map(|index| intervention(10, index, index))
        .collect();
    let plan = sealed(plan)?;
    let bytes = plan.to_canonical_cbor()?;
    assert_eq!(decoded(&bytes)?, plan);

    let mut oversized = plan;
    let next = u32::try_from(MAX_INTERVENTIONS_PER_PLAN_V1)?;
    oversized.interventions.push(intervention(10, next, next));
    let oversized = sealed(oversized)?;
    let expected = Err(PlanError::Intervention(InterventionError::FieldOutOfBounds));
    assert_eq!(oversized.validate(), expected);
    let mut fields = fields_of(&bytes)?;
    fields[FIELD_INTERVENTIONS] = Value::Array(
        oversized
            .interventions
            .iter()
            .map(|intervention| intervention.to_canonical_cbor().map(Value::Bytes))
            .collect::<Result<_, _>>()?,
    );
    fields[FIELD_PLAN_DIGEST] = Value::Bytes(oversized.plan_digest.to_vec());
    assert_eq!(decoded(&encode(&Value::Array(fields))?), expected);
    Ok(())
}

#[test]
fn descriptors_are_strictly_ordered_and_classified_once() -> TestResult {
    let base = plan()?;
    let cases: [(Edit, Result<(), PlanError>); 9] = [
        (
            |plan| plan.exogenous_descriptors.reverse(),
            Err(PlanError::NonCanonicalOrder),
        ),
        (
            |plan| plan.exogenous_descriptors[1].schema_id = 1,
            Err(PlanError::NonCanonicalOrder),
        ),
        (
            |plan| plan.exogenous_descriptors[1] = descriptor(1, 0x51),
            Ok(()),
        ),
        (
            |plan| plan.exogenous_descriptors[1] = descriptor(1, 0x50),
            Err(PlanError::DuplicateIdentity),
        ),
        (
            |plan| plan.fixed_policy_descriptors.push(descriptor(3, 0x20)),
            Err(PlanError::NonCanonicalOrder),
        ),
        (
            |plan| plan.fixed_policy_descriptors.push(descriptor(3, 0x30)),
            Err(PlanError::DuplicateIdentity),
        ),
        (
            |plan| plan.fixed_policy_descriptors = vec![descriptor(2, 0x40)],
            Err(PlanError::DuplicateIdentity),
        ),
        (
            |plan| plan.fixed_policy_descriptors = vec![descriptor(3, 0x40)],
            Ok(()),
        ),
        (
            |plan| plan.fixed_policy_descriptors = vec![descriptor(1, 0x50), descriptor(9, 0)],
            Err(PlanError::DuplicateIdentity),
        ),
    ];
    for (edit, expected) in cases {
        assert_eq!(resealed_validation(&base, edit), expected);
    }
    Ok(())
}

fn descriptors(schema_id: u32, count: usize) -> TestResult<Vec<Descriptor>> {
    Ok((0..u32::try_from(count)?)
        .map(|index| Descriptor {
            artifact_digest: digest_from(index),
            ..descriptor(schema_id, 0)
        })
        .collect())
}

fn descriptor_value(descriptor: &Descriptor) -> Value {
    Value::Array(vec![
        uint(u64::from(descriptor.schema_id)),
        Value::Bytes(descriptor.artifact_digest.to_vec()),
        Value::Bytes(descriptor.authorization_digest.to_vec()),
        Value::Bytes(descriptor.provenance_digest.to_vec()),
    ])
}

#[test]
fn descriptor_lists_accept_exactly_their_bounds() -> TestResult {
    let mut plan = plan()?;
    plan.exogenous_descriptors = descriptors(1, MAX_EXOGENOUS_DESCRIPTORS_PER_PLAN_V1)?;
    plan.fixed_policy_descriptors = descriptors(2, MAX_FIXED_POLICY_DESCRIPTORS_PER_PLAN_V1)?;
    let mut plan = sealed(plan)?;
    let bytes = plan.to_canonical_cbor()?;
    assert!(bytes.len() <= MAX_COUNTERFACTUAL_PLAN_BYTES_V1);
    assert_eq!(decoded(&bytes)?, plan);

    // The oversized variants share the one at-bound fixture and its decoded
    // wire fields. Bounds are checked before the digest, so they are not
    // resealed: a stale digest cannot mask the bound error.
    let fields = fields_of(&bytes)?;
    let mut exogenous_fields = fields.clone();
    let Value::Array(values) = &mut exogenous_fields[FIELD_EXOGENOUS] else {
        return Err("CFP1 exogenous descriptors must be an array".into());
    };
    values.push(descriptor_value(&descriptor(1, 0xff)));
    plan.exogenous_descriptors.push(descriptor(1, 0xff));
    assert_eq!(plan.validate(), Err(PlanError::FieldOutOfBounds));
    assert_eq!(
        decoded(&encode(&Value::Array(exogenous_fields))?),
        Err(PlanError::FieldOutOfBounds)
    );
    plan.exogenous_descriptors
        .truncate(MAX_EXOGENOUS_DESCRIPTORS_PER_PLAN_V1);

    let mut fixed_fields = fields;
    let Value::Array(values) = &mut fixed_fields[FIELD_FIXED_POLICY] else {
        return Err("CFP1 FixedPolicy descriptors must be an array".into());
    };
    values.push(descriptor_value(&descriptor(2, 0xff)));
    plan.fixed_policy_descriptors.push(descriptor(2, 0xff));
    assert_eq!(plan.validate(), Err(PlanError::FieldOutOfBounds));
    assert_eq!(
        decoded(&encode(&Value::Array(fixed_fields))?),
        Err(PlanError::FieldOutOfBounds)
    );
    Ok(())
}

#[test]
fn decoder_enforces_size_limit_before_parsing() {
    let at_limit = vec![0; MAX_COUNTERFACTUAL_PLAN_BYTES_V1];
    assert_eq!(decoded(&at_limit), Err(PlanError::InvalidEncoding));
    let over_limit = vec![0; MAX_COUNTERFACTUAL_PLAN_BYTES_V1 + 1];
    assert_eq!(decoded(&over_limit), Err(PlanError::FieldOutOfBounds));
}

#[test]
fn decoder_rejects_closed_schema_and_malformed_cbor_forms() -> TestResult {
    let valid = plan()?.to_canonical_cbor()?;
    let mut trailing = valid.clone();
    trailing.push(0);
    let mut short = fields_of(&valid)?;
    short.pop();
    let mut long = fields_of(&valid)?;
    long.push(Value::Null);
    // Field 1 (version 1) follows the two-byte array header and five-byte magic.
    assert_eq!(valid[7], 0x01);
    let noncanonical = [&valid[..7], &[0x18_u8, 0x01][..], &valid[8..]].concat();
    let mut invalid_utf8 = valid.clone();
    invalid_utf8[3..7].copy_from_slice(&[0xff; 4]);
    // The deepest legal items are descriptor fields at depth 3 (record 0,
    // descriptor list 1, descriptor 2). An empty array in a descriptor field
    // sits at depth 3 and passes the preflight, failing only on its type; one
    // more item inside it reaches depth 4 and is rejected as too deep.
    let descriptor_with_field = |field: Value| {
        Value::Array(vec![Value::Array(vec![
            field,
            digest(1),
            digest(2),
            digest(3),
        ])])
    };
    let at_depth_limit = descriptor_with_field(Value::Array(Vec::new()));
    let beyond_depth_limit = descriptor_with_field(Value::Array(vec![uint(1)]));
    for (bytes, expected) in [
        (trailing, PlanError::InvalidEncoding),
        (encode(&Value::Array(short))?, PlanError::InvalidEncoding),
        (encode(&Value::Array(long))?, PlanError::InvalidEncoding),
        (noncanonical, PlanError::InvalidEncoding),
        (invalid_utf8, PlanError::InvalidEncoding),
        (vec![0xa0], PlanError::InvalidEncoding),
        (vec![0xf9, 0x3c, 0x00], PlanError::InvalidEncoding),
        (
            with_field(&valid, 0, text("CFP2"))?,
            PlanError::UnsupportedVersion,
        ),
        (
            with_field(&valid, 0, Value::Bytes(b"CFP1".to_vec()))?,
            PlanError::UnsupportedVersion,
        ),
        (
            with_field(&valid, 1, uint(2))?,
            PlanError::UnsupportedVersion,
        ),
        (
            with_field(&valid, 1, text("1"))?,
            PlanError::UnsupportedVersion,
        ),
        (
            with_field(&valid, FIELD_EXOGENOUS, at_depth_limit)?,
            PlanError::InvalidEncoding,
        ),
        (
            with_field(&valid, FIELD_EXOGENOUS, beyond_depth_limit)?,
            PlanError::FieldOutOfBounds,
        ),
    ] {
        assert_eq!(decoded(&bytes), Err(expected));
    }
    Ok(())
}

#[test]
fn decoder_rejects_malformed_field_types() -> TestResult {
    let valid = plan()?.to_canonical_cbor()?;
    let profile =
        |fields: Vec<Value>| with_field(&valid, FIELD_EXECUTION_PROFILE, Value::Array(fields));
    let policy = |fields: Vec<Value>| with_field(&valid, FIELD_TRUST_POLICY, Value::Array(fields));
    let one_descriptor = |fields: Vec<Value>| {
        with_field(
            &valid,
            FIELD_EXOGENOUS,
            Value::Array(vec![Value::Array(fields)]),
        )
    };
    for (bytes, expected) in [
        (
            with_field(&valid, 2, text("id"))?,
            PlanError::InvalidEncoding,
        ),
        (
            with_field(&valid, 2, Value::Bytes(vec![1; 15]))?,
            PlanError::InvalidEncoding,
        ),
        (
            with_field(&valid, FIELD_ROOM_ID, Value::Bytes(vec![1]))?,
            PlanError::InvalidEncoding,
        ),
        (
            with_field(&valid, 6, Value::Integer((-1).into()))?,
            PlanError::InvalidEncoding,
        ),
        (
            with_field(&valid, 9, text("10"))?,
            PlanError::InvalidEncoding,
        ),
        (
            with_field(&valid, FIELD_INTERVENTIONS, uint(0))?,
            PlanError::InvalidEncoding,
        ),
        (
            with_field(
                &valid,
                FIELD_INTERVENTIONS,
                Value::Array(vec![Value::Array(Vec::new())]),
            )?,
            PlanError::InvalidEncoding,
        ),
        (
            with_field(
                &valid,
                FIELD_INTERVENTIONS,
                Value::Array(vec![Value::Bytes(vec![0x80])]),
            )?,
            PlanError::Intervention(InterventionError::InvalidEncoding),
        ),
        (
            with_field(&valid, FIELD_FIXED_POLICY, uint(0))?,
            PlanError::InvalidEncoding,
        ),
        (
            one_descriptor(vec![uint(1), digest(1), digest(2)])?,
            PlanError::InvalidEncoding,
        ),
        (
            one_descriptor(vec![uint(1 << 32), digest(1), digest(2), digest(3)])?,
            PlanError::FieldOutOfBounds,
        ),
        (
            one_descriptor(vec![
                uint(1),
                Value::Bytes(vec![1; 31]),
                digest(2),
                digest(3),
            ])?,
            PlanError::InvalidEncoding,
        ),
        (
            with_field(&valid, FIELD_EXECUTION_PROFILE, uint(0))?,
            PlanError::InvalidEncoding,
        ),
        (
            profile(vec![text("p"), text("1.0.0")])?,
            PlanError::InvalidEncoding,
        ),
        (
            profile(vec![uint(1), text("1.0.0"), digest(1)])?,
            PlanError::InvalidEncoding,
        ),
        (
            profile(vec![text("p"), uint(1), digest(1)])?,
            PlanError::InvalidEncoding,
        ),
        (
            profile(vec![text("p"), text("1.0.0"), text("digest")])?,
            PlanError::InvalidEncoding,
        ),
        (
            policy(vec![text("p"), uint(1)])?,
            PlanError::InvalidEncoding,
        ),
        (
            policy(vec![uint(1), uint(1), digest(1)])?,
            PlanError::InvalidEncoding,
        ),
        (
            policy(vec![text("p"), text("1"), digest(1)])?,
            PlanError::InvalidEncoding,
        ),
        (
            policy(vec![text("p"), uint(1), uint(1)])?,
            PlanError::InvalidEncoding,
        ),
        (
            with_field(&valid, 14, Value::Bytes(vec![5; 33]))?,
            PlanError::InvalidEncoding,
        ),
        (
            with_field(&valid, FIELD_REPLAY_CLAIM, text("exact"))?,
            PlanError::InvalidEncoding,
        ),
        (
            with_field(&valid, FIELD_PREVIOUS, Value::Bool(true))?,
            PlanError::InvalidEncoding,
        ),
        (
            with_field(&valid, FIELD_PLAN_DIGEST, Value::Null)?,
            PlanError::InvalidEncoding,
        ),
    ] {
        assert_eq!(decoded(&bytes), Err(expected));
    }
    Ok(())
}

#[test]
fn contract_errors_have_distinct_safe_messages_and_intervention_sources() {
    let errors = [
        PlanError::InvalidEncoding,
        PlanError::UnsupportedVersion,
        PlanError::FieldOutOfBounds,
        PlanError::UnknownEnum,
        PlanError::NonCanonicalOrder,
        PlanError::DuplicateIdentity,
        PlanError::InterventionBeforeCut,
        PlanError::Intervention(InterventionError::DuplicateIdentity),
        PlanError::DigestMismatch,
    ];
    let messages = errors
        .iter()
        .map(ToString::to_string)
        .collect::<BTreeSet<_>>();
    assert_eq!(messages.len(), errors.len());
    assert!(messages.iter().all(|message| message.starts_with("CFP1")
        || message.starts_with("invalid CFP1")
        || message.starts_with("unsupported CFP1")));
    for error in &errors[..7] {
        assert!(error.source().is_none());
    }
    assert!(errors[8].source().is_none());
    assert_eq!(
        errors[7].source().map(ToString::to_string),
        Some(InterventionError::DuplicateIdentity.to_string())
    );
}
