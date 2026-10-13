use super::*;

fn inputs() -> PassInputsV1 {
    PassInputsV1 {
        invocation_id: [0x11; 16],
        random_domain: [0x22; 32],
        timeline_seq: 7,
        observation: b"observation".to_vec(),
        simulation_time: 9,
    }
}

#[test]
fn the_context_carries_the_inputs_the_constants_and_the_binding() {
    let timeline = TimelineId::new();
    let binding = InvocationBindingV1 {
        tick: 5,
        tps1_digest: [0x33; 32],
        execution_profile_digest: Some([0x44; 32]),
    };
    let context = build_context(inputs(), timeline, binding);
    let invocation = context.invocation;
    assert_eq!(invocation.invocation_id, [0x11; 16]);
    assert_eq!(
        invocation.timeline_position.timeline_id,
        timeline.inner().to_bytes()
    );
    assert_eq!(invocation.timeline_position.seq, 7);
    assert_eq!(invocation.timeline_position.tick, 5);
    assert_eq!(invocation.timeline_position.scheduler_position, 0);
    assert_eq!(invocation.output_base_ordinal, 0);
    for (reference, schema_id) in [
        (invocation.principal_ref, 1),
        (invocation.authorization_decision, 2),
        (invocation.observation_snapshot, 3),
    ] {
        assert_eq!(reference.schema_id, schema_id);
        assert_eq!(reference.byte_length, 0);
        assert_eq!(reference.digest, [0; 32]);
    }
    assert_eq!(invocation.observation_bytes, b"observation");
    assert_eq!(invocation.execution_profile_digest, [0x44; 32]);
    assert_eq!(invocation.trust_policy_snapshot_digest, [0x33; 32]);
    assert_eq!(invocation.deterministic_budget_id, "conformance");
    assert_eq!(invocation.deterministic_random_domain, [0x22; 32]);
    assert_eq!(invocation.provenance_root, [5; 32]);
    assert_eq!(context.host_inputs.simulation_time, 9);
}

#[test]
fn a_missing_profile_digest_is_written_as_zeros() {
    let binding = InvocationBindingV1 {
        tick: 0,
        tps1_digest: [0; 32],
        execution_profile_digest: None,
    };
    let context = build_context(PassInputsV1::default(), TimelineId::new(), binding);
    assert_eq!(context.invocation.execution_profile_digest, [0; 32]);
}

#[test]
fn the_plugin_owns_the_event_type_of_its_bind_step() {
    let plugin = ConformancePluginV1::new("prototype.driven");
    let capability = plugin.capability();
    assert_eq!(
        capability.owned_event_types,
        vec![Kind::new("prototype.driven")]
    );
    assert!(capability.has_driver);
    assert_eq!(plugin.name(), "conformance");
    assert_ne!(
        plugin.id(),
        ConformancePluginV1::new("prototype.driven").id()
    );
}
