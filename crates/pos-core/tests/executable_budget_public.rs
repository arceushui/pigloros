use pos_core::{
    ExecutableBudgetErrorV1, ExecutableBudgetPolicyInputV1, ExecutableBudgetPolicyV1,
    FidelityBudgetV1, Hash, PluginCpuReservationV1, WorkloadProfileV1,
};

fn policy_input() -> ExecutableBudgetPolicyInputV1 {
    ExecutableBudgetPolicyInputV1 {
        revision: 1,
        workload_profile: WorkloadProfileV1::Interactive,
        cut_budget_family: 0,
        max_event_bytes: 4096,
        fidelity_budgets: [
            FidelityBudgetV1 {
                level: 0,
                max_events: 100,
                max_bytes: 100_000,
                max_cpu_us: 500_000,
                shared_host_cpu_reservation_us: 100,
            },
            FidelityBudgetV1 {
                level: 1,
                max_events: 100,
                max_bytes: 100_000,
                max_cpu_us: 250_000,
                shared_host_cpu_reservation_us: 100,
            },
            FidelityBudgetV1 {
                level: 2,
                max_events: 100,
                max_bytes: 100_000,
                max_cpu_us: 50_000,
                shared_host_cpu_reservation_us: 100,
            },
        ],
        plugin_cpu_reservations: vec![PluginCpuReservationV1 {
            plugin_id: pos_core::PluginId::from_ulid(ulid::Ulid::from(1)),
            cpu_reservations_us: [100, 100, 100],
        }],
        accounting_semantics: 0,
        execution_profile_hash: Hash::from_bytes([7; 32]),
        max_pass_wall_duration_us: 1_000,
    }
}

fn policy() -> Result<ExecutableBudgetPolicyV1, ExecutableBudgetErrorV1> {
    ExecutableBudgetPolicyV1::new(policy_input())
}

#[test]
fn public_policy_round_trips_and_has_stable_identity() -> Result<(), Box<dyn std::error::Error>> {
    let policy = policy()?;
    let bytes = policy.to_canonical_cbor();
    assert_eq!(
        ExecutableBudgetPolicyV1::from_canonical_cbor(&bytes)?,
        policy
    );
    let mut changed = policy.fields().clone();
    changed.execution_profile_hash = Hash::from_bytes([8; 32]);
    assert_ne!(
        policy.digest(),
        ExecutableBudgetPolicyV1::new(changed)?.digest()
    );
    Ok(())
}

#[test]
fn public_policy_rejects_noncanonical_plugin_order() {
    let mut input = policy_input();
    input.plugin_cpu_reservations = vec![
        PluginCpuReservationV1 {
            plugin_id: pos_core::PluginId::from_ulid(ulid::Ulid::from(2)),
            cpu_reservations_us: [1, 1, 1],
        },
        PluginCpuReservationV1 {
            plugin_id: pos_core::PluginId::from_ulid(ulid::Ulid::from(1)),
            cpu_reservations_us: [1, 1, 1],
        },
    ];
    assert_eq!(
        ExecutableBudgetPolicyV1::new(input),
        Err(ExecutableBudgetErrorV1::NonCanonical)
    );
}

#[test]
fn public_policy_rejects_fidelity_values_above_adr049_caps() {
    let mut input = policy_input();
    input.fidelity_budgets[0].max_events = 65_537;
    assert_eq!(
        ExecutableBudgetPolicyV1::new(input),
        Err(ExecutableBudgetErrorV1::FieldOutOfBounds)
    );
}

#[test]
fn public_policy_rejects_noncanonical_integer_width() -> Result<(), Box<dyn std::error::Error>> {
    let mut bytes = policy()?.to_canonical_cbor();
    bytes[7] = 0x18;
    bytes.insert(8, 1);
    assert_eq!(
        ExecutableBudgetPolicyV1::from_canonical_cbor(&bytes),
        Err(ExecutableBudgetErrorV1::NonCanonical)
    );
    Ok(())
}

#[test]
fn public_decoder_closes_truncation_and_envelope_boundaries(
) -> Result<(), Box<dyn std::error::Error>> {
    let bytes = policy()?.to_canonical_cbor();
    for end in 0..bytes.len() {
        assert!(
            ExecutableBudgetPolicyV1::from_canonical_cbor(&bytes[..end]).is_err(),
            "truncated EBP1 prefix unexpectedly decoded at {end}"
        );
    }

    let mut oversized = bytes.clone();
    oversized.resize(65_537, 0);
    assert_eq!(
        ExecutableBudgetPolicyV1::from_canonical_cbor(&oversized),
        Err(ExecutableBudgetErrorV1::FieldOutOfBounds)
    );

    let mut unsupported = bytes.clone();
    unsupported[2] = b'X';
    assert_eq!(
        ExecutableBudgetPolicyV1::from_canonical_cbor(&unsupported),
        Err(ExecutableBudgetErrorV1::UnsupportedValue)
    );

    let mut trailing = bytes;
    trailing.push(0);
    assert_eq!(
        ExecutableBudgetPolicyV1::from_canonical_cbor(&trailing),
        Err(ExecutableBudgetErrorV1::NonCanonical)
    );
    Ok(())
}
