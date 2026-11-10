//! Actual Runtime invocation/options bind every CIN1 field without heap clones.

use ciborium::value::Value;
use pos_core::community_lifecycle::{
    CommunityLifecycleErrorV1 as Error, CommunityPreparedInvocationV1 as Prepared,
};
use pos_core::Hash;
use pos_runtime::community_plugin_host::{
    ArtifactRefV1, HostInputs, InvocationOptionsV1, PluginInvocationV1, TimelinePositionV1,
    MAX_OBSERVATION_BYTES_V1, MAX_STATE_BYTES_V1,
};

type Fallible<T> = Result<T, Box<dyn std::error::Error>>;
type TestResult = Fallible<()>;

fn uint(value: u64) -> Value {
    Value::Integer(value.into())
}
fn bytes(value: &[u8]) -> Value {
    Value::Bytes(value.to_vec())
}
fn artifact(number: u8) -> ArtifactRefV1 {
    ArtifactRefV1 {
        schema_id: u32::from(number),
        byte_length: u64::from(number),
        digest: [number; 32],
    }
}
fn input() -> PluginInvocationV1 {
    PluginInvocationV1 {
        invocation_id: [1; 16],
        timeline_position: TimelinePositionV1 {
            timeline_id: [2; 16],
            seq: 3,
            tick: 4,
            scheduler_position: 5,
        },
        output_base_ordinal: 6,
        principal_ref: artifact(7),
        authorization_decision: artifact(8),
        observation_snapshot: artifact(9),
        observation_bytes: b"original observation".to_vec(),
        prior_state_schema: [10; 32],
        prior_state_bytes: b"original prior State".to_vec(),
        execution_profile_digest: [11; 32],
        trust_policy_snapshot_digest: [12; 32],
        deterministic_budget_id: "budget/a".into(),
        deterministic_random_domain: [13; 32],
        provenance_root: [14; 32],
    }
}
const fn options() -> InvocationOptionsV1 {
    InvocationOptionsV1 {
        host_inputs: HostInputs {
            simulation_time: 15,
        },
        watchdog_epochs: 16,
    }
}
fn ref_value(reference: ArtifactRefV1) -> Value {
    Value::Array(vec![
        uint(u64::from(reference.schema_id)),
        uint(reference.byte_length),
        bytes(&reference.digest),
    ])
}

#[test]
fn actual_runtime_fields_and_options_match_independent_twenty_field_wire() -> TestResult {
    let invocation = input();
    let options = options();
    let member = Hash::from_bytes([17; 32]);
    let prepared = invocation.prepared_record(member, options)?;
    let data = prepared.as_input();
    assert!(std::ptr::eq(
        data.observation_bytes.as_ptr(),
        invocation.observation_bytes.as_ptr()
    ));
    assert!(std::ptr::eq(
        data.prior_state_bytes.as_ptr(),
        invocation.prior_state_bytes.as_ptr()
    ));
    assert!(std::ptr::eq(
        data.deterministic_budget_id.as_ptr(),
        invocation.deterministic_budget_id.as_ptr()
    ));
    let position = invocation.timeline_position;
    let expected = Value::Array(vec![
        bytes(b"CIN1"),
        uint(1),
        bytes(member.as_bytes()),
        uint(0),
        bytes(&invocation.invocation_id),
        Value::Array(vec![
            bytes(&position.timeline_id),
            uint(position.seq),
            uint(position.tick),
            uint(u64::from(position.scheduler_position)),
        ]),
        uint(u64::from(invocation.output_base_ordinal)),
        ref_value(invocation.principal_ref),
        ref_value(invocation.authorization_decision),
        ref_value(invocation.observation_snapshot),
        bytes(&invocation.observation_bytes),
        bytes(&invocation.prior_state_schema),
        bytes(&invocation.prior_state_bytes),
        bytes(&invocation.execution_profile_digest),
        bytes(&invocation.trust_policy_snapshot_digest),
        Value::Text(invocation.deterministic_budget_id.clone()),
        bytes(&invocation.deterministic_random_domain),
        bytes(&invocation.provenance_root),
        uint(options.host_inputs.simulation_time),
        uint(u64::from(options.watchdog_epochs)),
    ]);
    let mut expected_bytes = Vec::new();
    ciborium::into_writer(&expected, &mut expected_bytes)?;
    assert_eq!(&*prepared.to_canonical_cbor(), &expected_bytes);
    assert!(*Prepared::from_canonical_cbor(&expected_bytes)?.as_input() == *data);
    // Preserve the actual shared type and its existing public Runtime name.
    let core_position: pos_core::community_lifecycle::TimelinePositionV1 = position;
    assert_eq!(core_position, position);
    assert!(format!("{position:?}").starts_with("TimelinePositionV1 {"));
    Ok(())
}

#[test]
fn changing_any_actual_invocation_or_option_changes_prepared_identity() -> TestResult {
    let original = input();
    let member = Hash::from_bytes([17; 32]);
    let baseline = original.prepared_record(member, options())?.digest();
    for field in 0..20 {
        let mut changed = original.clone();
        let mut options = options();
        let mut member = member;
        match field {
            0 => changed.invocation_id[0] += 1,
            1 => changed.timeline_position.timeline_id[0] += 1,
            2 => changed.timeline_position.seq += 1,
            3 => changed.timeline_position.tick += 1,
            4 => changed.timeline_position.scheduler_position += 1,
            5 => changed.output_base_ordinal += 1,
            6 => changed.principal_ref = artifact(20),
            7 => changed.authorization_decision = artifact(21),
            8 => changed.observation_snapshot = artifact(22),
            9 => changed.observation_bytes.push(1),
            10 => changed.prior_state_schema[0] += 1,
            11 => changed.prior_state_bytes.push(1),
            12 => changed.execution_profile_digest[0] += 1,
            13 => changed.trust_policy_snapshot_digest[0] += 1,
            14 => changed.deterministic_budget_id.push('b'),
            15 => changed.deterministic_random_domain[0] += 1,
            16 => changed.provenance_root[0] += 1,
            17 => options.host_inputs.simulation_time += 1,
            18 => options.watchdog_epochs += 1,
            _ => member = Hash::from_bytes([18; 32]),
        }
        assert_ne!(changed.prepared_record(member, options)?.digest(), baseline);
    }
    Ok(())
}

#[test]
fn invalid_actual_input_refuses_before_preparation_and_original_is_preserved() {
    let member = Hash::from_bytes([1; 32]);
    let mut invocation = input();
    invocation.observation_bytes = vec![0; MAX_OBSERVATION_BYTES_V1 + 1];
    let original = invocation.clone();
    assert_eq!(
        invocation.prepared_record(member, options()).err(),
        Some(Error::BoundsExceeded)
    );
    assert_eq!(invocation, original);
    invocation = input();
    invocation.prior_state_bytes = vec![0; MAX_STATE_BYTES_V1 + 1];
    assert_eq!(
        invocation.prepared_record(member, options()).err(),
        Some(Error::BoundsExceeded)
    );
    invocation = input();
    invocation.deterministic_budget_id = "Invalid".into();
    assert_eq!(
        invocation.prepared_record(member, options()).err(),
        Some(Error::InvalidBinding)
    );
    invocation = input();
    invocation.invocation_id = [0; 16];
    assert_eq!(
        invocation.prepared_record(member, options()).err(),
        Some(Error::InvalidBinding)
    );
    assert_eq!(
        input().prepared_record(Hash::zero(), options()).err(),
        Some(Error::InvalidBinding)
    );
}

#[test]
fn exact_wit_scalar_limits_empty_payload_and_zero_watchdog_round_trip() -> TestResult {
    let mut invocation = input();
    invocation.observation_bytes.clear();
    invocation.prior_state_bytes.clear();
    invocation.timeline_position.seq = u64::MAX;
    invocation.timeline_position.tick = u64::MAX;
    invocation.timeline_position.scheduler_position = u32::MAX;
    invocation.output_base_ordinal = u32::MAX;
    invocation.principal_ref.schema_id = u32::MAX;
    invocation.principal_ref.byte_length = u64::MAX;
    let mut options = options();
    options.host_inputs.simulation_time = u64::MAX;
    options.watchdog_epochs = 0;
    let prepared = invocation.prepared_record(Hash::from_bytes([1; 32]), options)?;
    let encoded = prepared.to_canonical_cbor();
    assert!(*Prepared::from_canonical_cbor(&encoded)?.as_input() == *prepared.as_input());
    assert_eq!(prepared.as_input().watchdog_epochs, 0);
    options.watchdog_epochs = u32::MAX;
    assert_eq!(
        invocation
            .prepared_record(Hash::from_bytes([1; 32]), options)?
            .as_input()
            .watchdog_epochs,
        u32::MAX
    );
    Ok(())
}
