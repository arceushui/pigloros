//! The in-memory community evaluation world (ADR-061 revision 8 decision 5). Linux only, like
//! the registry it carries, and compiled with the `local-admission-host` feature, like the
//! local admission host that admits its passes.
//!
//! The world is two [`ErasureExecutionHostV1`] instances over Memory stores. The pass store
//! supplies the admission port, the observations and the Timeline of the passes; the registry
//! store carries the Plugin trust policy registry and a Timeline for the activation Events.
//! Two stores are needed because `run_pass` takes the registry and the admission port at once
//! and the one-shot topology binding of a gate cannot be rebound. The world stops at
//! [`CommunityEvaluationWorldV1::gate_for_driver()`]: a Driver is built in
//! `pos-plugin-supervisor`, which depends on this crate, so the caller builds Drivers and
//! registers them in [`CommunityEvaluationWorldV1::plugins_mut()`].
//!
//! Every fault of the hosts themselves (a host that is not ready, an unavailable store) is
//! `ArtifactTrustDenied{TrustStateUnavailable}`: the state the world needs is unusable.

use pos_core::{
    store::EventReadBounds, trusted_clock::PluginTrustWallSourceV1, AppendDedupKey,
    AppendDedupScope, AppendIdentity, EntityId, ErasureHostErrorV1, ErasureRecoveryLimitsV1, Event,
    Hash, PipelineAttemptIdV1, PipelineEvidenceRefV1, PipelineSecurityRevisionsV1, Seq, SeqRange,
    TimelineId, TimelineMeta,
};
use pos_crypto::plugin_trust::verify_plugin_trust_v1;
use pos_plugin_publisher::InstalledPluginReleaseV1;
use pos_plugin_release::{BundleAddressV1, ReleaseSourceV1};
use pos_store::plugin_trust_registry::{PluginTrustPolicyRegistryErrorV1, TrustedUtcSecondV1};
use pos_store::StoreConfig;

use super::error::{CommunityPluginHostErrorV1, TrustDenialBasisV1};
use super::gate::{
    gate_for_driver, host_error_for_registry_v1, host_error_for_trust_verification_v1, slices,
    CommunityPluginExpectationV1, CommunityPluginTrustMaterialV1, GatedCommunityReleaseV1,
    PluginTrustMaterialSourceV1,
};
use super::host::{
    CommunityPassOutcomeV1, CommunityPassRequestV1, CommunityPluginHostV1, CommunityPluginMemberV1,
    CommunityStageV1,
};
use super::install::{
    host_error_for_install_v1, install_community_release_v1, ActivationTargetV1,
    CommunityInstallRequestV1,
};
use crate::{
    ErasureCoordinatorCompositionV1, ErasureExecutionHostV1, ErasureReadSenderV1,
    LocalScheduledAdmissionHostV1, PluginRegistry, ScheduledPassAdmissionV1,
};

/// `ArtifactTrustDenied{TrustStateUnavailable}`, the answer for every unusable host or store.
const UNAVAILABLE: CommunityPluginHostErrorV1 = CommunityPluginHostErrorV1::ArtifactTrustDenied {
    basis: TrustDenialBasisV1::TrustStateUnavailable,
};

/// The result of one world operation.
type WorldResult<T> = Result<T, CommunityPluginHostErrorV1>;

/// The commit time every pass of the world is admitted at. Any value works: the local
/// admission host only records it as the commit time of the Events, and no trust decision of
/// the world reads it (the gate samples its own second from the caller's wall source).
const COMMIT_NOW_SECS: u64 = 1;

/// The content of the provider validation evidence of every pass. Any value works: the local
/// admission host accepts a well-formed reference and the world never resolves it.
const PROVIDER_VALIDATION_BYTE: u8 = 60;

/// The content of the idempotency scope of every pass. Any value works: the scope only
/// separates the world's keys from other writers', and the world has none.
const SCOPE_BYTE: u8 = 62;

/// `ArtifactTrustDenied{TrustStateUnavailable}` for a fault whose payload is not needed.
fn unavailable<T, E>(result: Result<T, E>) -> WorldResult<T> {
    result.or(Err(UNAVAILABLE))
}

/// A host or store fault is `TrustStateUnavailable`; otherwise the operation's own result.
fn flat<T, E>(result: Result<WorldResult<T>, E>) -> WorldResult<T> {
    unavailable(result).and_then(std::convert::identity)
}

/// A registry operation whose outcome is not needed, mapped like the registry refusals.
fn registry_unit<T, E>(
    result: Result<Result<T, PluginTrustPolicyRegistryErrorV1>, E>,
) -> WorldResult<()> {
    flat(result.map(|inner| inner.map(|_outcome| ()).map_err(host_error_for_registry_v1)))
}

/// The two hosts, the registry the Drivers are registered in, and the Timelines of the world.
///
/// Two worlds share nothing: each opens its own hosts, stores and registry.
pub struct CommunityEvaluationWorldV1 {
    pass_host: ErasureExecutionHostV1,
    registry_host: ErasureExecutionHostV1,
    plugins: PluginRegistry,
    pass_timeline: TimelineId,
    target: ActivationTargetV1,
    attempts: u64,
}

/// What a pass observes before it is staged.
struct Observed {
    revisions: PipelineSecurityRevisionsV1,
    /// The local session grant the fence names; every admission must carry it.
    authority_grant: Hash,
    head: Seq,
    prefix: Vec<Event>,
    chain: Vec<TimelineMeta>,
}

impl CommunityEvaluationWorldV1 {
    /// A world whose registry is provisioned from `genesis`: its policy anchor and its signed
    /// TPS1, which must be the genesis TPS1 the anchor pins (`provision` creates the scope
    /// and no PTR1 or PRV1 floor, so the policy is adopted by the first [`Self::install()`]
    /// (the registry's `admit`) or by [`Self::refresh()`] (`advance_policy`); until then a
    /// gate is `PolicyMismatch`, the registry's `PolicyNotAdvanced`).
    ///
    /// # Errors
    /// Returns `TrustStateUnavailable` when a host cannot be opened, and the registry mapping of
    /// the refusal of `provision`.
    pub fn open(genesis: &CommunityPluginTrustMaterialV1) -> WorldResult<Self> {
        unavailable(open_parts()).and_then(|parts| {
            let plugins =
                PluginRegistry::new().with_erasure_gate(parts.pass_host.containment_gate());
            let mut world = Self {
                pass_host: parts.pass_host,
                registry_host: parts.registry_host,
                plugins,
                pass_timeline: parts.pass_timeline,
                target: ActivationTargetV1 {
                    timeline: parts.activation,
                    entity: EntityId::new(),
                },
                attempts: 0,
            };
            world.provision(genesis).map(|()| world)
        })
    }

    /// The registry the caller registers its Drivers in.
    pub const fn plugins_mut(&mut self) -> &mut PluginRegistry {
        &mut self.plugins
    }

    /// Install the community release at `address` with `material`, committing its activation
    /// Event on the registry store.
    ///
    /// The world builds the trust evidence at one sampled UTC second and `tick`, and the signed
    /// installer samples `wall` again for the registry's own second. The wall source is sealed,
    /// so the world cannot hand the installer the first sample as a one-shot source: the source
    /// must return the same second twice (the fixture instant does), and two seconds are
    /// refused (pinned by a test). Installing the same release again is the registry's
    /// idempotent replay.
    ///
    /// # Errors
    /// Returns the host error of the failed sample, of the trust verification, or of the install
    /// (`host_error_for_install_v1`); `TrustStateUnavailable` when the registry store is
    /// unusable.
    pub fn install(
        &mut self,
        source: &impl ReleaseSourceV1,
        address: &BundleAddressV1,
        material: &CommunityPluginTrustMaterialV1,
        wall: &mut impl PluginTrustWallSourceV1,
        tick: u64,
    ) -> WorldResult<InstalledPluginReleaseV1> {
        TrustedUtcSecondV1::from_source(wall)
            .map_err(host_error_for_registry_v1)
            .and_then(|utc| {
                verify_plugin_trust_v1(
                    material.root_anchor(),
                    &slices(material.roots()),
                    &slices(material.revocations()),
                    utc.as_i64(),
                    tick,
                )
                .map_err(host_error_for_trust_verification_v1)
            })
            .and_then(|evidence| {
                let request = CommunityInstallRequestV1 {
                    anchor: material.policy_anchor(),
                    tps1_bytes: material.tps1_bytes(),
                    evidence: &evidence,
                    target: self.target,
                };
                let installed = self.registry_host.with_plugin_trust_registry(|registry| {
                    install_community_release_v1(source, address, registry, wall, &request)
                });
                flat(installed.map(|result| result.map_err(host_error_for_install_v1)))
            })
    }

    /// Gate the release at `address` for the first Driver of its Plugin: [`gate_for_driver()`]
    /// on the world's registry.
    ///
    /// # Errors
    /// Returns the host error of the gate, or `TrustStateUnavailable` when the registry store is
    /// unusable.
    pub fn gate_for_driver(
        &mut self,
        expectation: &CommunityPluginExpectationV1,
        source: &(impl ReleaseSourceV1 + ?Sized),
        address: &BundleAddressV1,
        material: &(impl PluginTrustMaterialSourceV1 + ?Sized),
        wall: &mut impl PluginTrustWallSourceV1,
        tick: u64,
    ) -> WorldResult<GatedCommunityReleaseV1> {
        let gated = self.registry_host.with_plugin_trust_registry(|registry| {
            gate_for_driver(
                &*registry,
                expectation,
                source,
                address,
                material,
                wall,
                tick,
            )
        });
        flat(gated)
    }

    /// Adopt newer policy from `material`: the host's `refresh_policy` on the world's registry.
    ///
    /// # Errors
    /// Returns the registry mapping (`host_error_for_registry_v1`) of the refusal, or
    /// `TrustStateUnavailable` when the registry store is unusable.
    pub fn refresh<M: CommunityPluginMemberV1>(
        &mut self,
        members: &mut CommunityPluginHostV1<M>,
        material: &CommunityPluginTrustMaterialV1,
        wall: &mut impl PluginTrustWallSourceV1,
        tick: u64,
    ) -> WorldResult<()> {
        let refreshed = self.registry_host.with_plugin_trust_registry(|registry| {
            members.refresh_policy(registry, material, wall, tick)
        });
        registry_unit(refreshed)
    }

    /// Run one pass of `members` at `tick` on the pass Timeline, committing through the pass
    /// store's admission port and reading trust from the registry store.
    ///
    /// # Errors
    /// Returns `TrustStateUnavailable` when a store is unusable or the observation fails; the
    /// pass's own refusals and failures are in the outcome.
    pub fn run_pass<M: CommunityPluginMemberV1>(
        &mut self,
        members: &mut CommunityPluginHostV1<M>,
        wall: &mut impl PluginTrustWallSourceV1,
        tick: u64,
    ) -> WorldResult<CommunityPassOutcomeV1> {
        self.attempts += 1;
        let (attempt, timeline) = (self.attempts, self.pass_timeline);
        observe(&mut self.pass_host, &self.plugins, timeline)
            .and_then(|observed| {
                admission_for(attempt, &observed).map(|admission| (observed, admission))
            })
            .and_then(|(observed, admission)| {
                let (pass_host, plugins) = (&mut self.pass_host, &mut self.plugins);
                let passed = self.registry_host.with_plugin_trust_registry(|trust| {
                    pass_host.command_sender().and_then(|mut sender| {
                        sender.with_scheduled_admission(|ports| {
                            let request = CommunityPassRequestV1 {
                                tick,
                                timeline,
                                ancestry: &observed.chain,
                                observed_through: observed.head,
                                stage: CommunityStageV1::WithEvents(&observed.prefix),
                                admission,
                                port: ports,
                            };
                            members.run_pass(plugins, &*trust, wall, request)
                        })
                    })
                });
                unavailable(passed.and_then(std::convert::identity))
            })
    }

    /// Every Event committed on the pass Timeline.
    ///
    /// # Errors
    /// Returns `TrustStateUnavailable` when the pass store is unusable.
    pub fn committed_events(&mut self) -> WorldResult<Vec<Event>> {
        read_all(&mut self.pass_host, self.pass_timeline)
    }

    fn provision(&mut self, genesis: &CommunityPluginTrustMaterialV1) -> WorldResult<()> {
        let (anchor, tps1) = (genesis.policy_anchor(), genesis.tps1_bytes());
        let provisioned = self
            .registry_host
            .with_plugin_trust_registry(|registry| registry.provision(anchor, tps1));
        registry_unit(provisioned)
    }
}

/// Both hosts and their Timelines.
struct Parts {
    pass_host: ErasureExecutionHostV1,
    registry_host: ErasureExecutionHostV1,
    pass_timeline: TimelineId,
    activation: TimelineId,
}

/// Both hosts, each with one Timeline: the pass Timeline and the activation Timeline.
fn open_parts() -> Result<Parts, ErasureHostErrorV1> {
    open_host().and_then(|mut pass_host| {
        open_host().and_then(|mut registry_host| {
            create_timeline(&mut pass_host, "community-pass").and_then(|pass_timeline| {
                create_timeline(&mut registry_host, "plugin-activation").map(|activation| Parts {
                    pass_host,
                    registry_host,
                    pass_timeline,
                    activation,
                })
            })
        })
    })
}

/// A host over a Memory store with the closed coordinator composition.
fn open_host() -> Result<ErasureExecutionHostV1, ErasureHostErrorV1> {
    ErasureExecutionHostV1::open_with_authority(
        StoreConfig::Memory,
        &ErasureCoordinatorCompositionV1::closed(),
        ErasureRecoveryLimitsV1::compiled_maximum(),
    )
}

fn create_timeline(
    host: &mut ErasureExecutionHostV1,
    name: &str,
) -> Result<TimelineId, ErasureHostErrorV1> {
    host.command_sender()
        .and_then(|mut sender| sender.create_timeline(name))
        .map(|timeline| timeline.id())
}

/// No bound on a read: the world is a fixture of bounded size.
const fn unbounded() -> EventReadBounds {
    EventReadBounds::new(usize::MAX, usize::MAX, usize::MAX, usize::MAX)
}

/// The whole committed history of `timeline`, through an open reader.
fn read_whole(
    reader: &mut ErasureReadSenderV1<'_>,
    timeline: TimelineId,
) -> Result<Vec<Event>, ErasureHostErrorV1> {
    reader.read_bounded(timeline, SeqRange::all(), unbounded())
}

fn read_all(host: &mut ErasureExecutionHostV1, timeline: TimelineId) -> WorldResult<Vec<Event>> {
    unavailable(
        host.read_sender()
            .and_then(|mut reader| read_whole(&mut reader, timeline)),
    )
}

/// Observe the pass Timeline before the pass is staged: the admission fence revisions (the
/// first observation binds the store to the local admission host), the Logical Head, the
/// committed prefix and the Fork ancestry.
fn observe(
    host: &mut ErasureExecutionHostV1,
    plugins: &PluginRegistry,
    timeline: TimelineId,
) -> WorldResult<Observed> {
    host.command_sender()
        .and_then(|mut sender| {
            sender.with_scheduled_admission(|ports| {
                LocalScheduledAdmissionHostV1::shared().and_then(|local| {
                    local
                        .observe(plugins, ports, timeline)
                        .map(|revisions| (revisions, local.authority_grant()))
                })
            })
        })
        .or(Err(UNAVAILABLE))
        .and_then(|revisions| revisions.or(Err(UNAVAILABLE)))
        .and_then(|(revisions, authority_grant)| {
            unavailable(host.read_sender().and_then(|mut reader| {
                reader.logical_head(timeline).and_then(|head| {
                    read_whole(&mut reader, timeline).and_then(|prefix| {
                        reader.fork_ancestry(timeline).map(|chain| Observed {
                            revisions,
                            authority_grant,
                            head,
                            prefix,
                            chain,
                        })
                    })
                })
            }))
        })
}

/// The host's admission inputs for attempt number `attempt` over `observed`: a fresh attempt
/// identity and idempotency key per pass.
fn admission_for(attempt: u64, observed: &Observed) -> WorldResult<ScheduledPassAdmissionV1> {
    let id = u128::from(attempt).to_be_bytes();
    let key = *blake3::hash(&id).as_bytes();
    PipelineAttemptIdV1::try_new(id)
        .and_then(|attempt_id| {
            let content = Hash::from_bytes([PROVIDER_VALIDATION_BYTE; 32]);
            PipelineEvidenceRefV1::try_new(content).map(|validation| ScheduledPassAdmissionV1 {
                attempt_id,
                idempotency: AppendIdentity::new(
                    AppendDedupKey::from_keyed_hash(key),
                    AppendDedupScope::from_keyed_hash([SCOPE_BYTE; 32]),
                ),
                provider_validation: validation,
                security_revisions: observed.revisions,
                authority_grant: observed.authority_grant,
                commit_head: observed.head,
                commit_now_secs: COMMIT_NOW_SECS,
            })
        })
        .or(Err(UNAVAILABLE))
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests;
