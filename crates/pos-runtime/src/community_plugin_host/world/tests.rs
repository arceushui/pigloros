//! R8-W2: the evaluation world, with a fake member and a fake Driver that stages one draft, on
//! the shared signed-release test world (installed at second 50 and Tick 5).

use pos_core::trusted_clock::ScriptedTrustedWallSourceV1;
use pos_core::{CanonicalBytes, Capability, EventDraft, Kind, Plugin, PluginId, TimelineId};
use pos_plugin_publisher::test_support::{
    encoding::{Material, TICK},
    release::Shape,
    world::World,
    BoxResult,
};
use pos_plugin_release::LocalOciPublisherV1;
use pos_store::plugin_trust_registry::PluginTrustCommitOutcomeV1;

use super::*;
use crate::community_plugin_host::{
    CommunityPassAuthorizationV1, FixedTrustMaterialSourceV1, PassResultV1,
    PLUGIN_RELEASE_ACTIVATED_EVENT_TYPE_V1,
};
use crate::{Driver, ObservationView, RuntimeError, StepOutput};

type TestResult = BoxResult<()>;

const PLUGIN_ID: &str = "plugin-a";
const EVENT_TYPE: &str = "world.test.staged";

/// The wall source of an install: the evidence sample, then the installer's.
fn install_wall() -> ScriptedTrustedWallSourceV1 {
    ScriptedTrustedWallSourceV1::from_micros([50_000_000, 50_000_000])
}

fn one_second() -> ScriptedTrustedWallSourceV1 {
    ScriptedTrustedWallSourceV1::from_micros([50_000_000])
}

fn trust_material(world: &World, material: &Material) -> CommunityPluginTrustMaterialV1 {
    CommunityPluginTrustMaterialV1::new(
        world.anchor.clone(),
        material.root_anchor().clone(),
        material.tps1.clone(),
        vec![material.ptr1().to_vec()],
        material.prv1_records().to_vec(),
    )
}

fn expectation() -> CommunityPluginExpectationV1 {
    CommunityPluginExpectationV1 {
        plugin_id: PLUGIN_ID.to_owned(),
        release: None,
    }
}

/// `ArtifactTrustDenied{PolicyMismatch}`: the registry is provisioned but has adopted no policy
/// (`PolicyNotAdvanced`), which is the state of a world before its first install or refresh.
const fn policy_unadopted() -> CommunityPluginHostErrorV1 {
    CommunityPluginHostErrorV1::ArtifactTrustDenied {
        basis: TrustDenialBasisV1::PolicyMismatch,
    }
}

struct StagingPlugin(PluginId);

impl Plugin for StagingPlugin {
    fn id(&self) -> PluginId {
        self.0
    }

    fn name(&self) -> &'static str {
        "staging"
    }

    fn capability(&self) -> Capability {
        Capability {
            owned_event_types: vec![Kind::new(EVENT_TYPE)],
            has_driver: true,
            ..Capability::default()
        }
    }
}

/// A Driver that stages one draft per step.
struct StagingDriver;

impl Driver for StagingDriver {
    fn name(&self) -> &'static str {
        "staging"
    }

    fn step(&mut self, _: TimelineId, _: ObservationView<'_>) -> Result<StepOutput, RuntimeError> {
        Ok(StepOutput::new(vec![EventDraft::new(
            EntityId::new(),
            Kind::new(EVENT_TYPE),
            CanonicalBytes::from_static(b"staged"),
        )]))
    }
}

/// A member over the release of the test world.
struct FakeMember {
    plugin: PluginId,
    expectation: CommunityPluginExpectationV1,
    source: LocalOciPublisherV1,
    address: BundleAddressV1,
    material: FixedTrustMaterialSourceV1,
}

impl CommunityPluginMemberV1 for FakeMember {
    fn plugin(&self) -> PluginId {
        self.plugin
    }

    fn expectation(&self) -> &CommunityPluginExpectationV1 {
        &self.expectation
    }

    fn release_source(&self) -> &dyn ReleaseSourceV1 {
        &self.source
    }

    fn release_address(&self) -> &BundleAddressV1 {
        &self.address
    }

    fn trust_material(&self) -> &dyn PluginTrustMaterialSourceV1 {
        &self.material
    }

    fn offer_authorization(
        &self,
        _authorization: CommunityPassAuthorizationV1,
    ) -> Result<(), CommunityPluginHostErrorV1> {
        Ok(())
    }

    fn record_refusal(&self, _error: CommunityPluginHostErrorV1) {}

    fn close_pass(&self) {}

    fn pass_failure(&self) -> Option<CommunityPluginHostErrorV1> {
        None
    }

    fn pass_invocation_id(&self) -> Option<[u8; 16]> {
        None
    }

    fn sync_registry(&self, _registry: &mut PluginRegistry) -> Result<(), RuntimeError> {
        Ok(())
    }
}

struct Rig {
    publisher: World,
    material: CommunityPluginTrustMaterialV1,
    address: BundleAddressV1,
    eval: CommunityEvaluationWorldV1,
}

impl Rig {
    fn new() -> BoxResult<Self> {
        let mut publisher = World::new()?;
        let current = publisher.material()?;
        let material = trust_material(&publisher, &current);
        let address = publisher.publish(Shape::first())?.address().clone();
        let eval = CommunityEvaluationWorldV1::open(&material).map_err(|e| format!("{e:?}"))?;
        Ok(Self {
            publisher,
            material,
            address,
            eval,
        })
    }

    fn install(&mut self) -> BoxResult<PluginTrustCommitOutcomeV1> {
        let installed = self
            .eval
            .install(
                &self.publisher.store,
                &self.address,
                &self.material,
                &mut install_wall(),
                TICK,
            )
            .map_err(|e| format!("{e:?}"))?;
        Ok(installed.admission().outcome())
    }

    fn member(&self) -> BoxResult<FakeMember> {
        Ok(FakeMember {
            plugin: PluginId::new(),
            expectation: expectation(),
            source: self.publisher.root.store()?,
            address: self.address.clone(),
            material: FixedTrustMaterialSourceV1::new(self.material.clone()),
        })
    }

    fn gate(&mut self) -> Result<GatedCommunityReleaseV1, CommunityPluginHostErrorV1> {
        let material = self.material.clone();
        self.gate_with(&material)
    }

    fn gate_with(
        &mut self,
        material: &CommunityPluginTrustMaterialV1,
    ) -> Result<GatedCommunityReleaseV1, CommunityPluginHostErrorV1> {
        let source = FixedTrustMaterialSourceV1::new(material.clone());
        self.eval.gate_for_driver(
            &expectation(),
            &self.publisher.store,
            &self.address,
            &source,
            &mut one_second(),
            TICK,
        )
    }
}

/// A world with the release installed and gated, a Driver that stages one Event per step, and
/// the host of one member.
fn staged_world() -> BoxResult<(Rig, CommunityPluginHostV1<FakeMember>)> {
    let mut rig = Rig::new()?;
    rig.install()?;
    rig.gate().map_err(|e| format!("{e:?}"))?;
    let member = rig.member()?;
    let plugin = StagingPlugin(member.plugin);
    rig.eval
        .plugins_mut()
        .register_generated(&plugin, None, Some(Box::new(StagingDriver)))?;
    rig.eval.plugins_mut().compose_non_participant_drivers()?;
    Ok((rig, CommunityPluginHostV1::new(vec![member])))
}

#[test]
fn consecutive_passes_commit_one_event_each_with_fresh_attempts() -> TestResult {
    let (mut rig, mut members) = staged_world()?;
    for expected in 1..=2 {
        let outcome = rig
            .eval
            .run_pass(&mut members, &mut one_second(), TICK)
            .map_err(|e| format!("{e:?}"))?;
        let committed = matches!(outcome.result, PassResultV1::Committed(Some(_)));
        assert!(committed, "{:?}", outcome.result);
        let events = rig.eval.committed_events().map_err(|e| format!("{e:?}"))?;
        assert_eq!(events.len(), expected);
    }
    Ok(())
}

#[test]
fn install_gate_and_one_pass_commit_one_event_on_each_store() -> TestResult {
    let (mut rig, mut members) = staged_world()?;
    let outcome = rig
        .eval
        .run_pass(&mut members, &mut one_second(), TICK)
        .map_err(|e| format!("{e:?}"))?;
    let committed = matches!(outcome.result, PassResultV1::Committed(Some(_)));
    assert!(committed, "{:?}", outcome.result);
    let events = rig.eval.committed_events().map_err(|e| format!("{e:?}"))?;
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].event_type.as_str(), EVENT_TYPE);
    let timeline = rig.eval.target.timeline;
    let activation = rig
        .eval
        .registry_host
        .read_sender()
        .and_then(|mut reader| reader.read_bounded(timeline, SeqRange::all(), unbounded()))
        .map_err(|e| format!("{e:?}"))?;
    assert_eq!(activation.len(), 1);
    assert_eq!(
        activation[0].event_type.as_str(),
        PLUGIN_RELEASE_ACTIVATED_EVENT_TYPE_V1
    );
    Ok(())
}

#[test]
fn a_second_install_of_the_same_release_is_an_idempotent_replay() -> TestResult {
    let mut rig = Rig::new()?;
    assert_eq!(rig.install()?, PluginTrustCommitOutcomeV1::Committed);
    assert_eq!(rig.install()?, PluginTrustCommitOutcomeV1::IdempotentReplay);
    Ok(())
}

#[test]
fn two_worlds_share_nothing() -> TestResult {
    let mut first = Rig::new()?;
    let mut second = Rig::new()?;
    first.install()?;
    first.gate().map_err(|e| format!("{e:?}"))?;
    assert_eq!(second.gate().err(), Some(policy_unadopted()));
    assert_eq!(second.eval.committed_events().map(|e| e.len()), Ok(0));
    Ok(())
}

/// Installing at the first expired second is refused by the trust verification or the registry,
/// and nothing is activated.
#[test]
fn an_install_at_the_expiry_second_is_refused() -> TestResult {
    let mut rig = Rig::new()?;
    let mut wall = ScriptedTrustedWallSourceV1::from_micros([60_000_000, 60_000_000]);
    let refused = rig.eval.install(
        &rig.publisher.store,
        &rig.address,
        &rig.material,
        &mut wall,
        TICK,
    );
    let basis = TrustDenialBasisV1::Expired;
    let expired = CommunityPluginHostErrorV1::ArtifactTrustDenied { basis };
    assert_eq!(refused.err(), Some(expired));
    assert_eq!(rig.gate().err(), Some(policy_unadopted()));
    Ok(())
}

/// The installer samples `wall` again: a source that moves to another second between the two
/// samples is refused, and nothing is activated. This pins the documented choice of `install`.
#[test]
fn an_install_whose_two_samples_differ_is_refused() -> TestResult {
    let mut rig = Rig::new()?;
    let mut wall = ScriptedTrustedWallSourceV1::from_micros([50_000_000, 51_000_000]);
    let refused = rig.eval.install(
        &rig.publisher.store,
        &rig.address,
        &rig.material,
        &mut wall,
        TICK,
    );
    assert!(refused.is_err());
    assert_eq!(rig.gate().err(), Some(policy_unadopted()));
    Ok(())
}

/// An address that holds no release of this store is refused by the installer.
#[test]
fn an_install_of_an_address_the_store_does_not_hold_is_refused() -> TestResult {
    let mut rig = Rig::new()?;
    let other = Rig::new()?;
    let refused = rig.eval.install(
        &rig.publisher.store,
        &other.address,
        &rig.material,
        &mut install_wall(),
        TICK,
    );
    assert!(refused.is_err());
    assert_eq!(rig.gate().err(), Some(policy_unadopted()));
    Ok(())
}

/// Unverifiable PTR1 bytes fail the trust verification before the installer runs.
#[test]
fn unverifiable_trust_material_is_refused_before_the_install() -> TestResult {
    let mut rig = Rig::new()?;
    let current = rig.publisher.material()?;
    let broken = CommunityPluginTrustMaterialV1::new(
        rig.publisher.anchor.clone(),
        current.root_anchor().clone(),
        current.tps1.clone(),
        vec![vec![0_u8; 4]],
        current.prv1_records().to_vec(),
    );
    let refused = rig.eval.install(
        &rig.publisher.store,
        &rig.address,
        &broken,
        &mut install_wall(),
        TICK,
    );
    assert!(refused.is_err());
    assert_ne!(refused.err(), Some(UNAVAILABLE));
    assert_eq!(rig.gate().err(), Some(policy_unadopted()));
    Ok(())
}

/// Newer policy is adopted by `refresh`: before it the newer material is a policy mismatch,
/// after it the gate accepts the newer material.
#[test]
fn a_refresh_adopts_a_newer_tps1() -> TestResult {
    let mut rig = Rig::new()?;
    rig.install()?;
    let newer = rig.publisher.unadopted_material(&[[0x77; 32]], TICK)?;
    let newer = trust_material(&rig.publisher, &newer);
    assert_eq!(rig.gate_with(&newer).err(), Some(policy_unadopted()));
    let mut members = CommunityPluginHostV1::new(vec![rig.member()?]);
    let adopted = rig
        .eval
        .refresh(&mut members, &newer, &mut one_second(), TICK);
    assert_eq!(adopted, Ok(()));
    assert!(rig.gate_with(&newer).is_ok());
    Ok(())
}

#[test]
fn a_failed_sample_is_refused_before_any_install() -> TestResult {
    let mut rig = Rig::new()?;
    let mut empty = ScriptedTrustedWallSourceV1::from_micros([]);
    let refused = rig.eval.install(
        &rig.publisher.store,
        &rig.address,
        &rig.material,
        &mut empty,
        TICK,
    );
    assert_eq!(refused.err(), Some(UNAVAILABLE));
    Ok(())
}

#[test]
fn a_refresh_with_the_adopted_policy_is_ok_and_a_failed_clock_is_refused() -> TestResult {
    let mut rig = Rig::new()?;
    rig.install()?;
    let mut members = CommunityPluginHostV1::new(vec![rig.member()?]);
    let adopted = rig
        .eval
        .refresh(&mut members, &rig.material, &mut one_second(), TICK);
    assert_eq!(adopted, Ok(()));
    let mut empty = ScriptedTrustedWallSourceV1::from_micros([]);
    let refused = rig
        .eval
        .refresh(&mut members, &rig.material, &mut empty, TICK);
    assert_eq!(refused, Err(UNAVAILABLE));
    Ok(())
}

#[test]
fn a_world_over_a_store_without_a_registry_is_unavailable() -> TestResult {
    let mut rig = Rig::new()?;
    rig.eval.registry_host = ErasureExecutionHostV1::open_gateway_verified_empty(
        StoreConfig::Memory,
        ErasureRecoveryLimitsV1::compiled_maximum(),
    )
    .map_err(|e| format!("{e:?}"))?;
    assert!(rig.install().is_err());
    assert_eq!(rig.gate().err(), Some(UNAVAILABLE));
    let mut members = CommunityPluginHostV1::new(vec![rig.member()?]);
    let outcome = rig.eval.run_pass(&mut members, &mut one_second(), TICK);
    assert_eq!(outcome.err(), Some(UNAVAILABLE));
    let refreshed = rig
        .eval
        .refresh(&mut members, &rig.material, &mut one_second(), TICK);
    assert_eq!(refreshed, Err(UNAVAILABLE));
    Ok(())
}
