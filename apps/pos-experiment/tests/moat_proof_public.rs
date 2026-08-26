use pos_conformance::{ExecutionModeV1, MoatProofInputV1};
use pos_experiment::moat_proof::run_local_and_air_gapped;

fn public_input() -> MoatProofInputV1 {
    MoatProofInputV1 {
        scenario_id: "public-moat-proof".to_owned(),
        ticks: 4,
        initial_position: [0.0, 0.0],
        initial_velocity: [0.0, 0.0],
        agent_response_threshold: 0.5,
        fork_velocity: [1.0, 0.0],
        random_seed: 7,
        resource_limit: 100,
        network_enabled: false,
    }
}

#[test]
fn public_moat_proof_runs_both_execution_profiles() -> Result<(), Box<dyn std::error::Error>> {
    let (local, air_gapped, comparison) = run_local_and_air_gapped(public_input())?;
    assert!(local.passes_reaction_gates());
    assert!(air_gapped.passes_reaction_gates());
    assert!(comparison.equal);
    assert_eq!(
        local.baseline.authoritative_events,
        air_gapped.baseline.authoritative_events
    );
    assert_eq!(local.baseline.projections, air_gapped.baseline.projections);
    assert_eq!(
        local.baseline.manifest.execution_mode,
        ExecutionModeV1::Local
    );
    assert_eq!(
        air_gapped.baseline.manifest.execution_mode,
        ExecutionModeV1::AirGapped
    );
    Ok(())
}

#[test]
fn public_moat_proof_rejects_invalid_and_underbudget_inputs() {
    let mut invalid = public_input();
    invalid.ticks = 0;
    assert!(run_local_and_air_gapped(invalid).is_err());

    let mut underbudget = public_input();
    underbudget.resource_limit = 3;
    assert!(run_local_and_air_gapped(underbudget).is_err());
}
