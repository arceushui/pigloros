//! The pass world: a registry over an in-memory store, with community Drivers on the probe or
//! the real worker.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use pos_core::trusted_clock::TrustedWallSourceV1;
use pos_core::{
    AppendDedupKey, AppendDedupScope, AppendIdentity, ErasureContainmentGateV1, ErasureGate, Event,
    EventStore, Hash, PipelineAdmissionPortV1, PipelineAttemptIdV1, PipelineCommitReceiptV1,
    PipelineEvidenceRefV1, PipelineSecurityRevisionsV1, PluginId, Seq, SeqRange, TimelineId,
    TimelineMeta,
};
use pos_runtime::community_plugin_host::{
    CommunityPassOutcomeV1, CommunityPassRequestV1, CommunityPluginExpectationV1,
    CommunityPluginHostAbiV1, CommunityPluginHostErrorV1, CommunityPluginHostV1,
    CommunityPluginMemberV1, CommunityStageV1, GatedCommunityReleaseV1, HostInputs,
    NegotiatedCommunityPluginV1,
};
use pos_runtime::{
    LocalScheduledAdmissionHostV1, ObservationView, PluginRegistry, RuntimeError,
    ScheduledPassAdmissionV1,
};
use pos_store::memory::MemoryStore;
use pos_store::plugin_trust_registry::PluginTrustPolicyRegistryV1;

use crate::test_support::{self, community_pin, negotiated_with, ok, DriverPlugin, SMALL_BUDGET};
use crate::{
    register_community_driver, CommunityDriverConfigV1, CommunityDriverSettingsV1,
    CommunityDriverV1, CommunityPluginHandleV1, CommunityPluginSupervisorV1, CommunityStateV1,
    InvocationBindingV1, InvocationContextSourceV1, InvocationContextV1, WorkerProgramV1,
};

type Error = CommunityPluginHostErrorV1;

/// The Plugin state before a Driver's first committed step.
#[must_use]
pub fn initial() -> CommunityStateV1 {
    CommunityStateV1 {
        schema: [9; 32],
        bytes: b"initial".to_vec(),
    }
}

/// The host ABI that the signed-release world's PMF1 requires: ABI 0.0 to 0.1 and the `clock`
/// feature.
fn host_abi() -> CommunityPluginHostAbiV1 {
    ok(CommunityPluginHostAbiV1::new(
        0,
        1,
        vec!["clock".to_owned()],
    ))
}

/// The host's invocation inputs, one distinct invocation ID per member.
///
/// A source built with [`Self::switched`] refuses with `InvalidInvocation` while its flag is set.
#[derive(Debug)]
pub struct Source {
    invocation_id: [u8; 16],
    refuse: Option<Arc<AtomicBool>>,
}

impl Source {
    /// A source whose invocation ID is `byte` repeated.
    #[must_use]
    pub const fn numbered(byte: u8) -> Self {
        Self {
            invocation_id: [byte; 16],
            refuse: None,
        }
    }

    /// As [`Self::numbered`], refusing every context while `refuse` is set.
    #[must_use]
    pub const fn switched(byte: u8, refuse: Arc<AtomicBool>) -> Self {
        Self {
            invocation_id: [byte; 16],
            refuse: Some(refuse),
        }
    }
}

impl InvocationContextSourceV1 for Source {
    fn context(
        &mut self,
        timeline: TimelineId,
        observation: &ObservationView<'_>,
        binding: InvocationBindingV1,
    ) -> Result<InvocationContextV1, Error> {
        let refused = self
            .refuse
            .as_ref()
            .is_some_and(|flag| flag.load(Ordering::SeqCst));
        if refused {
            return Err(Error::InvalidInvocation);
        }
        let mut invocation = test_support::bound(test_support::invocation(b"observation"), binding);
        invocation.invocation_id = self.invocation_id;
        invocation.timeline_position.timeline_id = timeline.inner().to_bytes();
        invocation.timeline_position.seq = observation
            .anchor()
            .map_or(0, |anchor| anchor.observed_through().as_u64());
        Ok(InvocationContextV1 {
            invocation,
            host_inputs: HostInputs { simulation_time: 1 },
        })
    }
}

/// A source that panics while the Driver builds its invocation.
///
/// It unwinds with `std::panic::resume_unwind`, since `clippy::panic` is denied.
#[derive(Debug)]
pub struct PanickingSource;

impl InvocationContextSourceV1 for PanickingSource {
    fn context(
        &mut self,
        _timeline: TimelineId,
        _observation: &ObservationView<'_>,
        _binding: InvocationBindingV1,
    ) -> Result<InvocationContextV1, Error> {
        std::panic::resume_unwind(Box::new("the context source panicked"))
    }
}

/// One staged scheduled pass and the host inputs of its commit.
#[derive(Debug)]
pub struct Staged {
    head: Seq,
    revisions: PipelineSecurityRevisionsV1,
}

/// One registered member and what its pass authorization is for.
struct Member {
    handle: CommunityPluginHandleV1,
    negotiated: NegotiatedCommunityPluginV1,
    component: Vec<u8>,
}

/// What a pass observed before it is staged.
struct Observed {
    revisions: PipelineSecurityRevisionsV1,
    head: Seq,
    prefix: Vec<Event>,
    chain: Vec<TimelineMeta>,
}

/// The inputs of one `run_pass`, which its request borrows.
#[derive(Debug)]
pub struct Prepared {
    timeline: TimelineId,
    ancestry: Vec<TimelineMeta>,
    prefix: Vec<Event>,
    head: Seq,
    admission: ScheduledPassAdmissionV1,
}

impl Prepared {
    /// The request of a pass at `tick` that commits through `port`.
    #[must_use]
    pub fn request<'a>(
        &'a self,
        tick: u64,
        port: &'a mut dyn PipelineAdmissionPortV1,
    ) -> CommunityPassRequestV1<'a> {
        CommunityPassRequestV1 {
            tick,
            timeline: self.timeline,
            ancestry: &self.ancestry,
            observed_through: self.head,
            stage: CommunityStageV1::WithEvents(&self.prefix),
            admission: self.admission,
            port,
        }
    }

    /// As [`Self::request`], with the plain anchored stage call, which takes no committed prefix.
    #[must_use]
    pub fn anchored_request<'a>(
        &'a self,
        tick: u64,
        port: &'a mut dyn PipelineAdmissionPortV1,
    ) -> CommunityPassRequestV1<'a> {
        CommunityPassRequestV1 {
            stage: CommunityStageV1::Anchored,
            ..self.request(tick, port)
        }
    }
}

/// A Driver built from a gated release.
pub struct GatedSpec {
    /// The Plugin's diagnostic name.
    pub name: &'static str,
    /// The one Event type the Plugin owns.
    pub event_type: &'static str,
    /// The gated release the Driver is built from; its Component bytes name the probe's
    /// behaviour.
    pub gated: GatedCommunityReleaseV1,
    /// The worker watchdog.
    pub watchdog: Duration,
    /// The source of the Driver's invocations.
    pub source: Box<dyn InvocationContextSourceV1>,
    /// Whether to register the Driver in the registry; an unregistered Driver cannot be synced.
    pub register: bool,
}

/// What the composition keeps of a Driver built from a gated release.
#[derive(Debug)]
pub struct GatedMember {
    /// The Driver's handle.
    pub handle: CommunityPluginHandleV1,
    /// The Plugin ID text and release pair the Driver was built for.
    pub expected: CommunityPluginExpectationV1,
}

/// A registry over an in-memory store, and the Drivers registered in it.
pub struct World {
    program: PathBuf,
    fixture_members: Vec<Member>,
    /// The store the passes commit to.
    pub store: MemoryStore,
    /// The registry the Drivers are registered in.
    pub registry: PluginRegistry,
    /// The open erasure gate.
    pub gate: Arc<ErasureContainmentGateV1>,
    /// The Timeline the passes run on.
    pub timeline: TimelineId,
    member_count: u8,
    attempt_count: u8,
}

impl World {
    /// A world whose Drivers launch the worker at `program`.
    #[must_use]
    pub fn new(program: impl Into<PathBuf>) -> Self {
        let gate = Arc::new(ErasureContainmentGateV1::new_test_open());
        // The registry takes the trait object, so this clone must unsize: `Arc::clone(&gate)`
        // would infer the trait object as the clone's type and fail to type-check.
        let shared: Arc<dyn ErasureGate> = gate.clone();
        let mut store = MemoryStore::new();
        let () = ok(store.bind_erasure_gate(Arc::clone(&gate)));
        let timeline = ok(store.create_timeline("community-pass")).id();
        Self {
            program: program.into(),
            fixture_members: Vec::new(),
            store,
            registry: PluginRegistry::new().with_erasure_gate(shared),
            gate,
            timeline,
            member_count: 0,
            attempt_count: 0,
        }
    }

    fn supervisor(&self, watchdog: Duration) -> CommunityPluginSupervisorV1 {
        let supervisor = WorkerProgramV1::new(self.program.clone())
            .and_then(|program| CommunityPluginSupervisorV1::new(program, watchdog));
        supervisor.unwrap_or_else(|| std::panic::resume_unwind(Box::new("invalid supervisor")))
    }

    /// The settings of a Driver of `plugin` over `source`, on this world's worker.
    fn settings_for(
        &self,
        plugin: &DriverPlugin,
        watchdog: Duration,
        source: Box<dyn InvocationContextSourceV1>,
    ) -> CommunityDriverSettingsV1 {
        CommunityDriverSettingsV1 {
            plugin_id: plugin.id,
            name: plugin.name,
            tick_interval: Duration::from_millis(100),
            subscriptions: Vec::new(),
            supervisor: self.supervisor(watchdog),
            source,
            initial_state: initial(),
        }
    }

    /// Register `driver` of `plugin` under the pin of the member added last.
    fn register(&mut self, plugin: &DriverPlugin, driver: CommunityDriverV1) {
        let pin = community_pin(self.member_count, &format!("community-{}", plugin.name));
        let () = ok(register_community_driver(
            &mut self.registry,
            plugin,
            pin,
            driver,
        ));
    }

    /// Register one community Plugin whose Component bytes name the probe's behaviour.
    ///
    /// The Driver is built from the `test-support` fixtures: nothing was gated, and its
    /// authorizations come from `offer_all`.
    pub fn add(
        &mut self,
        name: &'static str,
        event_type: &'static str,
        component: &[u8],
        watchdog: Duration,
    ) -> CommunityPluginHandleV1 {
        self.member_count += 1;
        let plugin = DriverPlugin {
            id: PluginId::new(),
            name,
            event_type,
            has_driver: true,
        };
        let source = Box::new(Source::numbered(self.member_count));
        let settings = self.settings_for(&plugin, watchdog, source);
        let (driver, handle) =
            CommunityDriverV1::new(test_support::config_with(name, component, settings));
        self.fixture_members.push(Member {
            handle: handle.clone(),
            negotiated: negotiated_with(name, SMALL_BUDGET, Vec::new()),
            component: component.to_vec(),
        });
        self.register(&plugin, driver);
        handle
    }

    /// Build a Driver from a gated release, and register it when `spec.register` says so.
    ///
    /// # Errors
    /// Returns the refusal of `CommunityDriverConfigV1::from_gated`.
    pub fn add_gated(&mut self, spec: GatedSpec) -> Result<GatedMember, Error> {
        let GatedSpec {
            name,
            event_type,
            gated,
            watchdog,
            source,
            register,
        } = spec;
        self.member_count += 1;
        let identity = gated.identity();
        let expected = CommunityPluginExpectationV1 {
            plugin_id: gated.plugin_id().to_owned(),
            release: Some((identity.pmf1_digest, identity.release_digest)),
        };
        let plugin = DriverPlugin {
            id: PluginId::new(),
            name,
            event_type,
            has_driver: true,
        };
        let settings = self.settings_for(&plugin, watchdog, source);
        let config = CommunityDriverConfigV1::from_gated(
            gated,
            &host_abi(),
            &test_support::fixture_profile(),
            &expected.plugin_id,
            settings,
        )?;
        let (driver, handle) = CommunityDriverV1::new(config);
        if register {
            self.register(&plugin, driver);
        }
        Ok(GatedMember { handle, expected })
    }

    /// Start a pass for every member added by [`Self::add`]: drop what the last pass left in its
    /// slot and offer a fresh test authorization.
    pub fn offer_all(&self) {
        for member in &self.fixture_members {
            member.handle.close_pass();
            let authorization =
                test_support::authorization_for(&member.negotiated, &member.component);
            let () = ok(member.handle.offer_authorization(authorization));
        }
    }

    /// Observe the Timeline: the admission fence revisions, the Logical Head, the committed prefix
    /// and the Fork ancestry.
    fn observe(&mut self) -> Result<Observed, RuntimeError> {
        let revisions = LocalScheduledAdmissionHostV1::shared()?.observe(
            &self.registry,
            &mut self.store,
            self.timeline,
        )?;
        let head = self.store.logical_head(self.timeline)?;
        let prefix = self.store.read(self.timeline, SeqRange::all())?;
        let chain = pos_core::fork_ancestry(&self.store, self.timeline)?;
        Ok(Observed {
            revisions,
            head,
            prefix,
            chain,
        })
    }

    /// Observe, then stage one anchored pass over the committed prefix, with a fresh test
    /// authorization offered to every member added by [`Self::add`].
    ///
    /// # Errors
    /// Returns the registry's observation or staging error.
    pub fn stage(&mut self) -> Result<Staged, RuntimeError> {
        self.offer_all();
        self.stage_offered()
    }

    /// As [`Self::stage`], without offering: the Drivers find in their slots whatever the caller
    /// left there.
    ///
    /// # Errors
    /// Returns the registry's observation or staging error.
    pub fn stage_offered(&mut self) -> Result<Staged, RuntimeError> {
        let Observed {
            revisions,
            head,
            prefix,
            chain,
        } = self.observe()?;
        self.registry
            .step_all_anchored_with_events(self.timeline, &chain, head, &prefix)
            .map(|_| Staged { head, revisions })
    }

    /// The host's admission inputs for a pass observed at `head`, fresh each time.
    fn admission_at(
        &mut self,
        revisions: PipelineSecurityRevisionsV1,
        head: Seq,
    ) -> ScheduledPassAdmissionV1 {
        self.attempt_count += 1;
        let key = self.attempt_count;
        ScheduledPassAdmissionV1 {
            attempt_id: ok(PipelineAttemptIdV1::try_new([key; 16])),
            idempotency: AppendIdentity::new(
                AppendDedupKey::from_keyed_hash([key; 32]),
                AppendDedupScope::from_keyed_hash([62; 32]),
            ),
            provider_validation: ok(PipelineEvidenceRefV1::try_new(Hash::from_bytes([60; 32]))),
            security_revisions: revisions,
            commit_head: head,
            commit_now_secs: 1,
        }
    }

    /// The host's admission inputs for the staged pass, fresh each time.
    pub fn admission(&mut self, staged: &Staged) -> ScheduledPassAdmissionV1 {
        self.admission_at(staged.revisions, staged.head)
    }

    /// Admit the staged pass.
    ///
    /// # Errors
    /// Returns the registry's admission error.
    pub fn admit(
        &mut self,
        staged: &Staged,
    ) -> Result<Option<PipelineCommitReceiptV1>, RuntimeError> {
        let admission = self.admission(staged);
        self.registry
            .admit_scheduled_pass(&mut self.store, &admission)
    }

    /// Stage and atomically admit one whole pass.
    ///
    /// # Errors
    /// Returns the registry's staging or admission error.
    pub fn pass(&mut self) -> Result<Option<PipelineCommitReceiptV1>, RuntimeError> {
        let staged = self.stage()?;
        self.admit(&staged)
    }

    /// Observe the Timeline and prepare the inputs of one `run_pass` that the caller builds the
    /// request of with [`Prepared::request`], so that it can pick the admission port.
    ///
    /// # Errors
    /// Returns the registry's observation error.
    pub fn prepare(&mut self) -> Result<Prepared, RuntimeError> {
        let observed = self.observe()?;
        let admission = self.admission_at(observed.revisions, observed.head);
        Ok(Prepared {
            timeline: self.timeline,
            ancestry: observed.chain,
            prefix: observed.prefix,
            head: observed.head,
            admission,
        })
    }

    /// Run one host pass at `tick` that commits to this world's store.
    ///
    /// # Errors
    /// Returns the registry's observation error; the pass's own failures are in the outcome.
    pub fn run<M: CommunityPluginMemberV1>(
        &mut self,
        host: &mut CommunityPluginHostV1<M>,
        trust: &impl PluginTrustPolicyRegistryV1,
        wall: &mut impl TrustedWallSourceV1,
        tick: u64,
    ) -> Result<CommunityPassOutcomeV1, RuntimeError> {
        let prepared = self.prepare()?;
        let request = prepared.request(tick, &mut self.store);
        Ok(host.run_pass(&mut self.registry, trust, wall, request))
    }

    /// Every Event on the world's Timeline.
    #[must_use]
    pub fn events(&self) -> Vec<Event> {
        ok(self.store.read(self.timeline, SeqRange::all()))
    }

    /// Mirror each handle's availability into the registry.
    pub fn sync(&mut self, handles: &[&CommunityPluginHandleV1]) {
        for handle in handles {
            let () = ok(handle.sync_registry(&mut self.registry));
        }
    }
}
