//! R8-W3: the crate-private registry facade of the erasure execution host (ADR-061 revision 8
//! decision 5), on the shared signed-release test world.

use pos_crypto::plugin_trust::ValidatedPluginManifestProjectionV1;
use pos_plugin_publisher::test_support::{
    encoding::{Material, SCOPE, TICK},
    release::{pmf1_digest, Shape},
    world::{activation, wall, World},
    BoxResult,
};
use pos_plugin_release::ReleaseSourceV1;
use pos_store::plugin_trust_registry::TrustedUtcSecondV1;

use super::*;
use crate::community_plugin_host::{
    gate_for_driver, install_community_release_v1, ActivationTargetV1, CommunityInstallRequestV1,
    CommunityPluginExpectationV1, CommunityPluginTrustMaterialV1, FixedTrustMaterialSourceV1,
};

type TestResult = BoxResult<()>;

const PLUGIN_ID: &str = "plugin-a";

/// A host error as a boxed error: the host error type is payload-free and not an `Error`.
fn host<T>(result: Result<T, ErasureHostErrorV1>) -> BoxResult<T> {
    result.map_err(|error| format!("{error:?}").into())
}

fn limits() -> ErasureRecoveryLimitsV1 {
    ErasureRecoveryLimitsV1::compiled_maximum()
}

fn open_host() -> BoxResult<ErasureExecutionHostV1> {
    let composition = ErasureCoordinatorCompositionV1::closed();
    host(ErasureExecutionHostV1::open_with_authority(
        StoreConfig::Memory,
        &composition,
        limits(),
    ))
}

fn trust_material(world: &World, material: &Material) -> FixedTrustMaterialSourceV1 {
    FixedTrustMaterialSourceV1::new(CommunityPluginTrustMaterialV1::new(
        world.anchor.clone(),
        material.root_anchor().clone(),
        material.tps1.clone(),
        vec![material.ptr1().to_vec()],
        material.prv1_records().to_vec(),
    ))
}

fn expectation() -> CommunityPluginExpectationV1 {
    CommunityPluginExpectationV1 {
        plugin_id: PLUGIN_ID.to_owned(),
        release: None,
    }
}

/// What a scenario observed, as text, so that two hosts can be compared.
type Observed = Vec<String>;

/// The registry calls of one scenario that need no release: provision twice and the four reads
/// of a scope the first provision created.
fn provision_and_read(
    host_under_test: &mut ErasureExecutionHostV1,
    world: &World,
    material: &Material,
) -> BoxResult<Observed> {
    let (anchor, tps1) = (&world.anchor, &material.tps1);
    host(host_under_test.with_plugin_trust_registry(|registry| {
        vec![
            format!("{:?}", registry.provision(anchor, tps1)),
            format!("{:?}", registry.provision(anchor, tps1)),
            format!("{:?}", registry.retained_policy_state(SCOPE).is_ok()),
            format!("{:?}", registry.ledger(SCOPE).map(|rows| rows.len())),
            format!("{:?}", registry.active_release(SCOPE, PLUGIN_ID)),
        ]
    }))
}

/// Install the first release through the facade and gate it through the facade.
fn install_and_gate(
    host_under_test: &mut ErasureExecutionHostV1,
    world: &mut World,
    material: &Material,
) -> BoxResult<Observed> {
    let timeline = host(host_under_test.command_sender())
        .and_then(|mut sender| host(sender.create_timeline("activation")))?
        .id();
    let published = world.publish(Shape::first())?;
    let address = published.address().clone();
    let request = CommunityInstallRequestV1 {
        anchor: &world.anchor,
        tps1_bytes: &material.tps1,
        evidence: &material.evidence,
        target: ActivationTargetV1 {
            timeline,
            entity: EntityId::new(),
        },
    };
    let mut clock = wall(material.utc)?;
    let store = &world.store;
    host(host_under_test.with_plugin_trust_registry(|registry| {
        install_community_release_v1(store, &address, registry, &mut clock, &request)
    }))??;
    let source = trust_material(world, material);
    let mut clock = wall(material.utc)?;
    let gated = host(host_under_test.with_plugin_trust_registry(|registry| {
        let registry = &*registry;
        let expected = expectation();
        gate_for_driver(
            registry,
            &expected,
            store,
            &address,
            &source,
            &mut clock,
            TICK,
        )
    }))?;
    let bundle = store.read_verified(&address)?;
    let digest = pmf1_digest(&bundle);
    let projection = ValidatedPluginManifestProjectionV1::from_verified_bundle(&bundle)?;
    let utc = TrustedUtcSecondV1::from_source(&mut wall(material.utc)?)?;
    let (anchor, tps1, evidence) = (&world.anchor, &material.tps1, &material.evidence);
    host(host_under_test.with_plugin_trust_registry(|registry| {
        let advanced = registry.advance_policy(anchor, tps1, evidence, utc, TICK);
        let rolled = registry.rollback(
            anchor,
            tps1,
            evidence,
            &projection,
            utc,
            TICK,
            activation(timeline, 9),
        );
        let decision = registry.retained_release_decision(SCOPE, digest);
        let active = registry.active_release(SCOPE, PLUGIN_ID);
        vec![
            format!("gated={}", gated.is_ok()),
            format!("decision={}", matches!(decision, Ok(Some(_)))),
            format!("active={}", matches!(active, Ok(Some(_)))),
            format!("ledger={:?}", registry.ledger(SCOPE).map(|rows| rows.len())),
            format!("advanced={:?}", advanced.map(|done| done.outcome)),
            format!("rolled={:?}", rolled.err()),
        ]
    }))
}

/// Drive the whole registry port through the facade of `host_under_test` over a fresh world.
fn scenario(host_under_test: &mut ErasureExecutionHostV1) -> BoxResult<Observed> {
    let mut world = World::build(None, false)?;
    let material = world.material()?;
    let mut seen = provision_and_read(host_under_test, &world, &material)?;
    seen.extend(install_and_gate(host_under_test, &mut world, &material)?);
    Ok(seen)
}

#[test]
fn a_release_installed_through_the_facade_is_gated_through_it() -> TestResult {
    let mut plain = open_host()?;
    let seen = scenario(&mut plain)?;
    assert_eq!(seen[0], "Ok(Created)");
    assert_eq!(seen[1], "Ok(Unchanged)");
    for line in [
        "gated=true",
        "decision=true",
        "active=true",
    ] {
        let found = seen.iter().any(|seen_line| seen_line == line);
        assert!(found, "{line}: {seen:?}");
    }
    Ok(())
}

#[test]
fn the_fault_store_delegates_the_whole_registry_port() -> TestResult {
    let mut plain = open_host()?;
    let expected = scenario(&mut plain)?;
    let faulty = ErasureExecutionHostV1::recover_verified_empty(
        Box::new(fault_store(FaultModeV1::Passthrough)),
        4,
    );
    let mut faulty = host(faulty)?;
    assert_eq!(scenario(&mut faulty)?, expected);
    Ok(())
}

#[test]
fn a_closed_host_runs_no_closure() -> TestResult {
    let mut closed = host(ErasureExecutionHostV1::new_closed(Box::new(
        MemoryStore::new().without_erasure_gate(),
    )))?;
    let mut ran = false;
    let refused = closed.with_plugin_trust_registry(|_registry| ran = true);
    assert_eq!(refused, Err(ErasureHostErrorV1::RecoveryUnavailable));
    assert!(!ran);
    Ok(())
}

#[test]
fn a_gateway_store_has_no_registry_and_runs_no_closure() -> TestResult {
    let mut gateway = host(ErasureExecutionHostV1::open_gateway_verified_empty(
        StoreConfig::Memory,
        limits(),
    ))?;
    let mut ran = false;
    let refused = gateway.with_plugin_trust_registry(|_registry| ran = true);
    assert_eq!(refused, Err(ErasureHostErrorV1::AuthorizationDenied));
    assert!(!ran);
    Ok(())
}
