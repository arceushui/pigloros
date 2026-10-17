//! PCF-CPH-019 of `PCH1` version 2: the ADR-119 composition boundary transaction on the real
//! worker (#667, ADR-119 section 6 cases 1, 2, 3 and 13).
//!
//! The entry's primary and its one declared candidate are real signed releases of the Rust
//! guest, composed through the supervisor's restart composer and declared through the runtime
//! `declare`. A trap is a `ComponentTrap` the host reports `Unverified`, so it activates
//! nothing until FU-7 (owner decision Q2 (c)). A revoked primary refuses the pass at its gate
//! (code 4, Q6 (a)); the boundary then commits the activation, swaps the registry entry and the
//! host member, and the next pass commits the candidate's Event: the relief from the revision 7
//! deadlock. An owner return to the revoked primary is refused at the trust gate. Each step
//! runs in Local and Air-Gapped mode on both stores; the Air-Gapped results must equal the
//! Local ones.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use pos_core::{
    CompositionPinV1, DomainFallbackPolicyV1, EntityId, FallbackActivatedPayloadV1,
    FallbackActivationModeV1, FallbackEntryV1, FallbackTriggerCodeV1, Hash, ImplementationKeyV1,
    PluginId, TimelineId,
};
use pos_plugin_publisher::test_support::encoding::{TICK, UTC};
use pos_plugin_publisher::test_support::world::{Config, World as SignedWorld};
use pos_plugin_publisher::test_support::{BoxResult, ReleaseSourceV1, ScriptedTrustedWallSourceV1};
use pos_plugin_supervisor::pass_harness::{initial, PassStoreV1, Source, StoreKind, World};
use pos_plugin_supervisor::test_support::DriverPlugin;
use pos_plugin_supervisor::{
    compose_restart_v1, CommunityDriverSettingsV1, CommunityMemberV1, CommunityPluginSupervisorV1,
    CompositionBoundaryV1, FallbackBoundaryContextV1, FallbackCandidateInputV1,
    FallbackEntryOutcomeV1 as Outcome, FallbackReferenceV1, FallbackReleaseSupplyV1,
    FallbackRestartSlotV1, InvocationBindingV1, InvocationContextSourceV1, InvocationContextV1,
    WorkerProgramV1, COMPOSITION_FALLBACK_ACTIVATE_GRANT_V1,
};
use pos_runtime::community_plugin_host::{
    CommunityPassOutcomeV1, CommunityPluginHostAbiV1, CommunityPluginHostErrorV1,
    CommunityPluginHostV1, CommunityPluginModeV1 as Mode, PassResultV1,
};
use pos_runtime::composition_fallback::{
    declare_composition_fallback_v1, required_plugin_v1, COMPOSITION_FALLBACK_DECLARE_GRANT_V1,
};
use pos_runtime::{
    FallbackCandidateFactsV1, FallbackDeclarationV1, FallbackDriverSettingsV1,
    FallbackEntryFactsV1, FallbackExecutionFactsV1, FallbackHostFactsV1, FallbackHostGrantsV1,
    FallbackTriggerCauseV1, ObservationView, PluginExecutionModeV1, RequiredPluginCompositionV1,
};
use pos_store::composition_fallback_registry::{
    CompositionFallbackRegistryV1, CompositionFallbackTargetV1,
};
use pos_store::memory::MemoryStore;
use pos_store::sqlite::SqliteStore;
use tempfile::TempDir;

use crate::harness::Capture;
use crate::parity::{on_every_store, StoreCapture};
use crate::support::lane::{
    gated_release, profile, publish, trust_material, Published, Spec, Swap, ALPHA,
    TRAP_OBSERVATION, WATCHDOG,
};
use crate::support::subcase::WORKER;

type Host = CommunityPluginHostV1<CommunityMemberV1>;

const SCOPE: &str = "pch1.activation";
const ENTRY: &str = "prototype";
const ROLE: &str = "prototype";
/// The version label of both implementations, which the test Plugins report.
const VERSION: &str = "0.1.0";
/// The Driver interval of both implementations.
const INTERVAL: Duration = Duration::from_millis(100);
/// The Stable passing-profile digest both releases hold (rule 7).
const STABLE: Hash = Hash::from_bytes([0x5a; 32]);
/// The trusted second of every sample, in microseconds.
const UTC_MICROS: u64 = UTC.unsigned_abs() * 1_000_000;
/// The declared candidate: a second Plugin ID on the Rust guest.
const BETA: Spec = Spec {
    plugin_id: "plugin-b",
    ..ALPHA
};

/// A trusted wall clock with enough samples for one pass or boundary transaction.
fn clock() -> ScriptedTrustedWallSourceV1 {
    ScriptedTrustedWallSourceV1::from_micros([UTC_MICROS; 8])
}

/// The pass harness's source, made to trap the real guest while `trap` is set.
struct Trapping {
    source: Source,
    trap: Arc<AtomicBool>,
}

impl InvocationContextSourceV1 for Trapping {
    fn context(
        &mut self,
        timeline: TimelineId,
        observation: &ObservationView<'_>,
        binding: InvocationBindingV1,
    ) -> Result<InvocationContextV1, CommunityPluginHostErrorV1> {
        let mut context = self.source.context(timeline, observation, binding)?;
        if self.trap.load(Ordering::SeqCst) {
            context.invocation.observation_bytes = TRAP_OBSERVATION.to_vec();
        }
        Ok(context)
    }
}

/// One implementation: its release, its declared pin and its PMF1 facts.
#[derive(Clone)]
struct Implementation {
    published: Published,
    pin: CompositionPinV1,
    execution: FallbackExecutionFactsV1,
}

impl Implementation {
    fn of(signed: &SignedWorld, published: Published, swap: &Swap) -> BoxResult<Self> {
        let digest = Hash::from_bytes(published.release);
        let text = published.spec.plugin_id.to_owned();
        let key = ImplementationKeyV1::new(text, VERSION.to_owned(), digest)?;
        let pin = CompositionPinV1::new(key, vec![ROLE.to_owned()])?;
        let gated = gated_release(signed, &published, swap)?;
        let execution = FallbackExecutionFactsV1::from_projection(gated.execution());
        Ok(Self {
            published,
            pin,
            execution,
        })
    }

    const fn plugin(&self, id: PluginId) -> DriverPlugin {
        DriverPlugin {
            id,
            name: self.published.spec.plugin_id,
            event_type: self.published.spec.event_type,
            has_driver: true,
        }
    }
}

/// The host facts of a release: one publisher and the Stable profile.
fn host_facts(active: Option<Hash>) -> FallbackHostFactsV1 {
    FallbackHostFactsV1 {
        active_release_digest: active,
        publisher: Some("acme".to_owned()),
        namespace_grants: Vec::new(),
        conformance_profiles: BTreeSet::from([STABLE]),
    }
}

/// The declaration facts of `implementation` under the run-local `id`.
fn facts_of(implementation: &Implementation, id: PluginId) -> BoxResult<FallbackCandidateFactsV1> {
    let settings = FallbackDriverSettingsV1 {
        tick_interval: INTERVAL,
        subscriptions: Vec::new(),
    };
    let active = Some(implementation.pin.implementation().release_digest());
    let execution = implementation.execution.clone();
    let plugin = implementation.plugin(id);
    let pin = implementation.pin.clone();
    let host = host_facts(active);
    Ok(FallbackCandidateFactsV1::collect(
        &plugin, pin, settings, execution, host,
    )?)
}

/// The host's supply over the signed world's closure store, on the real worker.
struct Supply {
    implementations: Vec<Implementation>,
    sources: Vec<Box<dyn ReleaseSourceV1>>,
    material: Swap,
    mode: Mode,
    trap: Arc<AtomicBool>,
    reference: Option<FallbackReferenceV1>,
    built: Vec<(PluginId, &'static str)>,
}

impl Supply {
    fn input(&mut self, implementation: &Implementation) -> BoxResult<FallbackCandidateInputV1> {
        let id = PluginId::new();
        let name = implementation.published.spec.plugin_id;
        self.built.push((id, name));
        let number = u8::try_from(self.built.len())?;
        let program = WorkerProgramV1::new(PathBuf::from(WORKER)).ok_or("invalid worker path")?;
        let supervisor = CommunityPluginSupervisorV1::new(program, WATCHDOG).ok_or("supervisor")?;
        let source = Trapping {
            source: Source::numbered(number),
            trap: Arc::clone(&self.trap),
        };
        let settings = CommunityDriverSettingsV1 {
            plugin_id: id,
            name,
            tick_interval: INTERVAL,
            subscriptions: Vec::new(),
            supervisor,
            source: Box::new(source),
            initial_state: initial(),
        };
        let release = self.sources.pop().ok_or("no release source left")?;
        let host_abi = CommunityPluginHostAbiV1::new(0, 1, vec!["clock".to_owned()]);
        Ok(FallbackCandidateInputV1 {
            plugin: Box::new(implementation.plugin(id)),
            source: release,
            address: implementation.published.address.clone(),
            material: Box::new(self.material.clone()),
            settings,
            host_abi: host_abi.map_err(|error| format!("{error:?}"))?,
            profile: profile(self.mode),
            host: host_facts(None),
        })
    }
}

impl FallbackReleaseSupplyV1 for Supply {
    fn candidate(
        &mut self,
        _entry_key: &str,
        key: &ImplementationKeyV1,
    ) -> Option<FallbackCandidateInputV1> {
        let found = self
            .implementations
            .iter()
            .find(|implementation| implementation.pin.implementation() == key)
            .cloned()?;
        self.input(&found).ok()
    }

    fn reference(&self, _entry_key: &str) -> Option<FallbackReferenceV1> {
        self.reference.clone()
    }
}

/// A store of `kind` with the composition fallback registry, and the directory that keeps a
/// file-backed `SQLite` store alive.
fn store_of(kind: StoreKind) -> BoxResult<(Box<dyn PassStoreV1>, Option<TempDir>)> {
    let (mut store, directory): (Box<dyn PassStoreV1>, _) = match kind {
        StoreKind::Memory => (Box::new(MemoryStore::new()), None),
        StoreKind::Sqlite => {
            let directory = tempfile::tempdir()?;
            let path = directory.path().join("activation.db");
            let path = path.to_str().ok_or("the temporary path is not UTF-8")?;
            (Box::new(SqliteStore::open(path)?), Some(directory))
        }
    };
    store.provision_fallback_registry()?;
    Ok((store, directory))
}

/// The signed world, the pass world, the supply and the composed boundary of one mode.
struct Rig {
    signed: SignedWorld,
    pass: World,
    _directory: Option<TempDir>,
    supply: Supply,
    boundary: CompositionBoundaryV1,
    host: Host,
    primary: Implementation,
    entity: EntityId,
}

impl Rig {
    fn new(kind: StoreKind, mode: Mode) -> BoxResult<Self> {
        let mut signed = SignedWorld::with_config(Config {
            extra_plugin_ids: &["plugin-b"],
            ..Config::default()
        })?;
        let swap = Swap::of(trust_material(&signed, &signed.material()?));
        let alpha = publish(&mut signed, ALPHA, 1)?;
        let beta = publish(&mut signed, BETA, 2)?;
        let primary = Implementation::of(&signed, alpha, &swap)?;
        let candidate = Implementation::of(&signed, beta, &swap)?;
        let sources = (0..8).map(|_| -> BoxResult<Box<dyn ReleaseSourceV1>> {
            Ok(Box::new(signed.root.store()?))
        });
        let (store, directory) = store_of(kind)?;
        let supply = Supply {
            implementations: vec![primary.clone(), candidate.clone()],
            sources: sources.collect::<BoxResult<Vec<_>>>()?,
            material: swap,
            mode,
            trap: Arc::new(AtomicBool::new(false)),
            reference: None,
            built: Vec::new(),
        };
        let pass = World::with_store(kind, store, WORKER);
        let entity = EntityId::new();
        let target = CompositionFallbackTargetV1 {
            timeline: pass.timeline,
            entity,
        };
        let mut rig = Self {
            signed,
            pass,
            _directory: directory,
            supply,
            boundary: CompositionBoundaryV1::new(SCOPE.to_owned(), target, BTreeMap::new()),
            host: CommunityPluginHostV1::new(Vec::new()),
            primary,
            entity,
        };
        rig.compose()?;
        rig.declare(&candidate)?;
        Ok(rig)
    }

    const fn target(&self) -> CompositionFallbackTargetV1 {
        CompositionFallbackTargetV1 {
            timeline: self.pass.timeline,
            entity: self.entity,
        }
    }

    /// Compose the entry's slot through the restart composer.
    fn compose(&mut self) -> BoxResult<()> {
        let slots = [FallbackRestartSlotV1 {
            entry_key: ENTRY.to_owned(),
            base: self.primary.pin.clone(),
        }];
        let target = self.target();
        let mut wall = clock();
        let mut context = FallbackBoundaryContextV1 {
            registry: &mut self.pass.registry,
            store: &mut *self.pass.store,
            trust: &self.signed.registry,
            wall: &mut wall,
            supply: &mut self.supply,
            tick: TICK,
        };
        let restart = compose_restart_v1(&mut context, SCOPE.to_owned(), target, &slots)?;
        self.boundary = restart.boundary;
        self.host = restart.host;
        Ok(())
    }

    /// Declare the primary with `candidate`, automatic on a revoked artifact or a trap.
    fn declare(&mut self, candidate: &Implementation) -> BoxResult<()> {
        let primary = facts_of(&self.primary, PluginId::new())?;
        let required = required_plugin_v1(primary.registry.plugin_id(), &primary.pin)?;
        let local = PluginExecutionModeV1::Local;
        let composition = RequiredPluginCompositionV1::try_new(local, vec![required])?;
        let candidate_facts = facts_of(candidate, PluginId::new())?;
        let triggers = vec![
            FallbackTriggerCodeV1::ComponentTrap,
            FallbackTriggerCodeV1::ArtifactRevoked,
        ];
        let automatic = FallbackActivationModeV1::Automatic;
        let pins = vec![candidate.pin.clone()];
        let base = self.primary.pin.clone();
        let entry = FallbackEntryV1::new(ENTRY.to_owned(), base, pins, triggers, automatic)?;
        let policy = DomainFallbackPolicyV1::new(SCOPE.to_owned(), vec![entry], None)?;
        let facts = FallbackEntryFactsV1 {
            primary: primary.clone(),
            candidates: vec![candidate_facts],
        };
        let timeline = self.pass.timeline;
        let running = self.primary.pin.implementation().clone();
        let declaration = FallbackDeclarationV1 {
            scope: SCOPE.to_owned(),
            target: self.target(),
            stepped_timeline: timeline,
            expected_state_revision: 0,
            expected_logical_head: self.pass.store.logical_head(timeline)?,
            policy_bytes: policy.to_canonical_cbor(),
            composition: composition.clone(),
            effective: BTreeMap::from([(ENTRY.to_owned(), running)]),
            facts: BTreeMap::from([(ENTRY.to_owned(), facts)]),
        };
        let grants = grants(COMPOSITION_FALLBACK_DECLARE_GRANT_V1);
        declare_composition_fallback_v1(&mut *self.pass.store, &grants, &declaration)?;
        self.supply.reference = Some(FallbackReferenceV1 {
            composition,
            primary,
        });
        Ok(())
    }

    fn pass(&mut self) -> BoxResult<CommunityPassOutcomeV1> {
        let mut wall = clock();
        let trust = &self.signed.registry;
        Ok(self.pass.run(&mut self.host, trust, &mut wall, TICK)?)
    }

    /// The boundary after `outcome`, described.
    fn boundary(&mut self, outcome: &CommunityPassOutcomeV1) -> String {
        let mut wall = clock();
        let mut context = FallbackBoundaryContextV1 {
            registry: &mut self.pass.registry,
            store: &mut *self.pass.store,
            trust: &self.signed.registry,
            wall: &mut wall,
            supply: &mut self.supply,
            tick: TICK,
        };
        let outcomes = self.boundary.run_boundary_v1(&mut context, &mut self.host, outcome);
        outcomes.map_or_else(
            |error| format!("error:{error:?}"),
            |outcomes| join(outcomes.iter().map(describe)),
        )
    }

    /// An owner return to the primary, described.
    fn owner_return(&mut self) -> String {
        let target = self.primary.pin.implementation().clone();
        let held = grants(COMPOSITION_FALLBACK_ACTIVATE_GRANT_V1);
        let mut wall = clock();
        let mut context = FallbackBoundaryContextV1 {
            registry: &mut self.pass.registry,
            store: &mut *self.pass.store,
            trust: &self.signed.registry,
            wall: &mut wall,
            supply: &mut self.supply,
            tick: TICK,
        };
        let host = &mut self.host;
        let returned = self.boundary.owner_activate_v1(&mut context, host, &held, ENTRY, &target);
        returned.map_or_else(|error| format!("error:{error:?}"), |outcome| describe(&outcome))
    }

    /// The Plugin ID text of the implementation the boundary binds the entry to.
    fn running(&self) -> &'static str {
        let bound = self.boundary.binding(ENTRY);
        let built = self.supply.built.iter().find(|(id, _)| Some(*id) == bound);
        built.map_or("unbound", |(_, name)| name)
    }

    /// The trigger code, cause, origin and closing tenure of the last Event, an activation.
    fn last_activation(&self) -> BoxResult<String> {
        let events = self.pass.events();
        let event = events.last().ok_or("no Event")?;
        let payload = FallbackActivatedPayloadV1::from_canonical_cbor(event.payload.as_slice())?;
        let input = payload.as_input();
        let cause = FallbackTriggerCauseV1::from_code(input.trigger_basis.cause);
        Ok(format!(
            "{:?}/{:?}/{:?}/{}",
            input.trigger_code,
            cause,
            input.trigger_basis.origin,
            input.closing_tenure_ordinal
        ))
    }

    /// Revoke the primary's release and make every member follow the new material.
    fn revoke_primary(&mut self) -> BoxResult<()> {
        let release = self.primary.published.release;
        self.signed.advance_revoking_artifacts(&[release])??;
        self.supply.material.set(Some(trust_material(&self.signed, &self.signed.material()?)));
        Ok(())
    }

    fn ledger_rows(&self) -> BoxResult<usize> {
        Ok(self.pass.store.fallback_ledger(SCOPE, self.pass.timeline)?.len())
    }
}

/// The host-native grants holding `grant` alone.
fn grants(grant: &str) -> FallbackHostGrantsV1 {
    FallbackHostGrantsV1 {
        grants: BTreeSet::from([grant.to_owned()]),
    }
}

/// `items` joined with commas, or `none`.
fn join(items: impl Iterator<Item = String>) -> String {
    let items: Vec<String> = items.collect();
    if items.is_empty() {
        "none".to_owned()
    } else {
        items.join(",")
    }
}

/// A short description of one entry outcome.
fn describe(outcome: &Outcome) -> String {
    let reasons = |skipped: &[pos_core::FallbackSkippedCandidateV1]| {
        join(skipped.iter().map(|skipped| format!("{:?}", skipped.reason)))
    };
    match outcome {
        Outcome::Activated { to, skipped, .. } => {
            format!("activated:{}:{}", to.plugin_id(), reasons(skipped))
        }
        Outcome::AwaitingOwner { code, .. } => format!("awaiting:{code:?}"),
        Outcome::Exhausted { skipped, .. } => format!("exhausted:{}", reasons(skipped)),
        Outcome::NotCommitted { error, .. } => format!("not-committed:{error:?}"),
    }
}

/// How a pass ended, with the number of committed Events.
fn result_of(outcome: &CommunityPassOutcomeV1) -> String {
    match &outcome.result {
        PassResultV1::Committed(Some(receipt)) => {
            format!("committed:{}", receipt.committed_events().len())
        }
        PassResultV1::Committed(None) => "committed:0".to_owned(),
        PassResultV1::Refused => "refused".to_owned(),
        PassResultV1::Failed { .. } => "failed".to_owned(),
        PassResultV1::InDoubt => "in-doubt".to_owned(),
    }
}

/// The member's failure in `outcome`, or `none`.
fn failure_of(outcome: &CommunityPassOutcomeV1) -> String {
    let failure = outcome.gates.first().and_then(|entry| entry.launch_failure);
    failure.map_or_else(|| "none".to_owned(), |error| error.name().to_owned())
}

/// Every observation of the case in one mode, in capture order.
fn observe(kind: StoreKind, mode: Mode) -> BoxResult<Vec<(&'static str, String)>> {
    let mut rig = Rig::new(kind, mode)?;
    let mut seen = Vec::new();
    let healthy = rig.pass()?;
    seen.push(("healthy.result", result_of(&healthy)));
    rig.supply.trap.store(true, Ordering::SeqCst);
    let trapped = rig.pass()?;
    rig.supply.trap.store(false, Ordering::SeqCst);
    seen.push(("trap.result", result_of(&trapped)));
    seen.push(("trap.failure", failure_of(&trapped)));
    seen.push(("trap.boundary", rig.boundary(&trapped)));
    rig.revoke_primary()?;
    let refused = rig.pass()?;
    seen.push(("revoked.result", result_of(&refused)));
    seen.push(("revoked.failure", failure_of(&refused)));
    seen.push(("revoked.boundary", rig.boundary(&refused)));
    seen.push(("revoked.activation", rig.last_activation()?));
    seen.push(("revoked.running", rig.running().to_owned()));
    seen.push(("ledger.rows", rig.ledger_rows()?.to_string()));
    let relieved = rig.pass()?;
    seen.push(("relief.result", result_of(&relieved)));
    let gated = relieved.gates.first().map(|entry| entry.gate.is_ok());
    seen.push(("relief.gate-ok", format!("{gated:?}")));
    seen.push(("return.revoked-primary", rig.owner_return()));
    seen.push(("return.running", rig.running().to_owned()));
    Ok(seen)
}

/// PCF-CPH-019: the ADR-119 composition boundary transaction on the real worker.
#[must_use]
pub fn boundary_activation() -> Capture {
    on_every_store(activation)
}

fn activation(kind: StoreKind, capture: &mut StoreCapture<'_>) -> BoxResult<()> {
    let local = observe(kind, Mode::Local)?;
    let air_gapped = observe(kind, Mode::AirGapped)?;
    for (key, value) in &local {
        capture.record(key, value);
    }
    capture.record("air-gapped-equals-local", local == air_gapped);
    Ok(())
}
