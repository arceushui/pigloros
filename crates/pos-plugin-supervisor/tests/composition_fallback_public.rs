//! The ADR-119 composition boundary transaction and chain at its public API (#667, ADR-119
//! section 6 cases 1-3, 7, 8, 9, 11-15), on the shared signed-release test world of
//! `pos-plugin-publisher` and the supervisor's pass harness.
//!
//! Every vector publishes and installs real signed releases, composes the community slots
//! through the restart composer, declares a policy through the runtime `declare`, and runs
//! whole passes through `CommunityPluginHostV1::run_pass` over the probe worker, whose
//! Component bytes name its behaviour (`draft:<type>` stages one Event, `fuel` exhausts its
//! fuel). Every vector runs on `MemoryStore` and on a file-backed `SqliteStore`, because the
//! composition fallback registry needs the WAL journal.
#![cfg(target_os = "linux")]

use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use pos_core::{
    Capability, CompositionPinV1, DomainFallbackPolicyV1, EntityId, ErasureContainmentGateV1,
    ErasureGate, FallbackActivatedInputV1, FallbackActivatedPayloadV1, FallbackActivationModeV1,
    FallbackActivationOriginV1, FallbackEntryV1, FallbackSkippedCandidateV1,
    FallbackTriggerBasisV1, FallbackTriggerCodeV1 as Code, Hash, ImplementationKeyV1, Kind, Plugin,
    PluginId, COMPOSITION_FALLBACK_ACTIVATED_EVENT_TYPE_V1,
};
use pos_plugin_publisher::test_support::{
    encoding::{TICK, UTC},
    release::Shape,
    world::{Config, World as SignedWorld},
    BoxResult, BundleAddressV1, ScriptedTrustedWallSourceV1,
};
use pos_plugin_release::LocalOciPublisherV1;
use pos_plugin_supervisor::pass_harness::{
    initial, LostPort, PassStoreV1, Source, StoreKind, World as PassWorld,
};
use pos_plugin_supervisor::test_support;
use pos_plugin_supervisor::{
    compose_restart_v1, fallback_trigger_cause_v1, CommunityDriverSettingsV1, CommunityMemberV1,
    CommunityPluginSupervisorV1, CompositionBoundaryV1, FallbackBoundaryContextV1,
    FallbackBoundaryErrorV1 as BoundaryError, FallbackCandidateInputV1,
    FallbackEntryOutcomeV1 as Outcome, FallbackReferenceV1, FallbackReleaseSupplyV1,
    FallbackRestartSlotV1, WorkerProgramV1, COMPOSITION_FALLBACK_ACTIVATE_GRANT_V1,
};
use pos_runtime::community_plugin_host::{
    gate_community_release_v1, CommunityPassOutcomeV1, CommunityPassV1,
    CommunityPluginExpectationV1, CommunityPluginHostAbiV1, CommunityPluginHostErrorV1,
    CommunityPluginHostV1, CommunityPluginTrustMaterialV1, MemberPassV1, PassResultV1,
    PluginTrustMaterialSourceV1, PluginTrustMaterialUnavailableV1,
};
use pos_runtime::composition_fallback::{
    declare_composition_fallback_v1, required_plugin_v1, COMPOSITION_FALLBACK_DECLARE_GRANT_V1,
};
use pos_runtime::{
    FallbackCandidateFactsV1, FallbackDeclarationV1, FallbackDriverSettingsV1,
    FallbackEntryFactsV1, FallbackExecutionFactsV1, FallbackHostFactsV1, FallbackHostGrantsV1,
    FallbackTriggerCauseV1, PluginExecutionModeV1, PluginRegistry, RequiredPluginCompositionV1,
};
use pos_store::composition_fallback_registry::{
    CompositionFallbackRegistryErrorV1 as RegistryError, CompositionFallbackRegistryV1,
    CompositionFallbackTargetV1, FallbackActivateRequestV1, FallbackConformanceSetsV1,
    FallbackDeclareRequestV1, FallbackLedgerBodyV1,
};
use pos_store::memory::MemoryStore;
use pos_store::sqlite::SqliteStore;

type TestResult = BoxResult<()>;
type Host = CommunityPluginHostV1<CommunityMemberV1>;
type Error = CommunityPluginHostErrorV1;
type Outcomes = Result<Vec<Outcome>, BoundaryError>;

const PROBE: &str = env!("CARGO_BIN_EXE_pos-plugin-worker-probe");
/// A generous watchdog for invocations that should finish promptly.
const PROMPT: Duration = Duration::from_mins(1);
/// The Driver interval of every implementation.
const INTERVAL: Duration = Duration::from_millis(100);
/// The trusted second of every sample, in microseconds.
const UTC_MICROS: u64 = UTC.unsigned_abs() * 1_000_000;
/// The Plugin IDs the world's PTR1 grants besides the default `plugin-a`.
const GRANTED: &[&str] = &["plugin-b", "plugin-c", "plugin-d"];
const SCOPE: &str = "cbt.fallback";
/// The one declared entry.
const ENTRY: &str = "forecast";
/// The undeclared sibling slot.
const SIBLING_SLOT: &str = "sibling";
const ROLE: &str = "forecaster";
/// The role of the undeclared sibling.
const SIBLING_ROLE: &str = "sibling";
/// The version label of every implementation, which the probe Plugins report.
const VERSION: &str = "0.1.0";
/// The Stable passing-profile digest every release holds (rule 7).
const STABLE: Hash = Hash::from_bytes([0x5a; 32]);
const PUBLISHER: &str = "acme";
/// A probe Component that stages one Event of the declared entry's type.
const DRAFT: &[u8] = b"draft:community.alpha";
/// A probe Component whose worker exhausts its fuel.
const FUEL: &[u8] = b"fuel";

/// One release: its Plugin ID, the Event type it owns and its probe behaviour.
#[derive(Clone, Copy)]
struct Spec {
    plugin_id: &'static str,
    event_type: &'static str,
    component: &'static [u8],
    role: &'static str,
}

impl Spec {
    const fn shape(&self) -> Shape {
        Shape {
            plugin_id: self.plugin_id,
            component: self.component,
            ..Shape::first()
        }
        .with_optional_capability()
    }
}

/// The behaviour of the entry's primary, first candidate and second candidate.
#[derive(Clone, Copy)]
struct Behaviour {
    primary: &'static [u8],
    candidate: &'static [u8],
    next: &'static [u8],
}

/// A failing primary in front of two healthy candidates.
const FAILING: Behaviour = Behaviour {
    primary: FUEL,
    candidate: DRAFT,
    next: DRAFT,
};
/// A healthy primary and healthy candidates.
const HEALTHY: Behaviour = Behaviour {
    primary: DRAFT,
    ..FAILING
};

/// A material source the test swaps between passes; a clone shares the material.
#[derive(Clone)]
struct Swap(Rc<RefCell<Option<CommunityPluginTrustMaterialV1>>>);

impl Swap {
    fn set(&self, material: Option<CommunityPluginTrustMaterialV1>) {
        *self.0.borrow_mut() = material;
    }
}

impl PluginTrustMaterialSourceV1 for Swap {
    fn material(&self) -> Result<CommunityPluginTrustMaterialV1, PluginTrustMaterialUnavailableV1> {
        let current = self.0.borrow().clone();
        current.ok_or(PluginTrustMaterialUnavailableV1)
    }
}

/// The signed world's current trust material.
fn material_of(world: &SignedWorld) -> BoxResult<CommunityPluginTrustMaterialV1> {
    let material = world.material()?;
    Ok(CommunityPluginTrustMaterialV1::new(
        world.anchor.clone(),
        material.root_anchor().clone(),
        material.tps1.clone(),
        vec![material.ptr1().to_vec()],
        material.prv1_records().to_vec(),
    ))
}

/// A trusted wall clock with enough samples for one boundary transaction.
fn clock() -> ScriptedTrustedWallSourceV1 {
    ScriptedTrustedWallSourceV1::from_micros([UTC_MICROS; 8])
}

/// A probe Plugin with a configurable version label.
struct Versioned {
    id: PluginId,
    name: &'static str,
    event_type: &'static str,
    version: &'static str,
}

impl Plugin for Versioned {
    fn id(&self) -> PluginId {
        self.id
    }

    fn name(&self) -> &'static str {
        self.name
    }

    fn capability(&self) -> Capability {
        Capability {
            owned_event_types: vec![Kind::new(self.event_type)],
            has_driver: true,
            ..Capability::default()
        }
    }

    fn version(&self) -> &'static str {
        self.version
    }
}

/// One published and installed release.
#[derive(Clone)]
struct Release {
    spec: Spec,
    digest: [u8; 32],
    address: BundleAddressV1,
    pin: CompositionPinV1,
    execution: FallbackExecutionFactsV1,
}

impl Release {
    fn key(&self) -> ImplementationKeyV1 {
        self.pin.implementation().clone()
    }

    const fn plugin(&self, id: PluginId, version: &'static str) -> Versioned {
        Versioned {
            id,
            name: self.spec.plugin_id,
            event_type: self.spec.event_type,
            version,
        }
    }

    const fn slot(&self, entry_key: &'static str) -> (&'static str, &CompositionPinV1) {
        (entry_key, &self.pin)
    }
}

/// Publish and install `spec` as the active release, and gate it once for its PMF1 facts.
fn publish(signed: &mut SignedWorld, spec: Spec, tag: u8, swap: &Swap) -> BoxResult<Release> {
    let published = signed.publish(spec.shape())?;
    let installed = signed.install(published.address(), tag)?;
    installed.map_err(|error| format!("install failed: {error}"))?;
    let digest = Hash::from_bytes(published.release_digest());
    let key = ImplementationKeyV1::new(spec.plugin_id.to_owned(), VERSION.to_owned(), digest)?;
    let pin = CompositionPinV1::new(key, vec![spec.role.to_owned()])?;
    let expected = CommunityPluginExpectationV1 {
        plugin_id: spec.plugin_id.to_owned(),
        release: None,
    };
    let open = CommunityPassV1::open_at_for_test(u32::try_from(UTC)?, TICK)?;
    let address = published.address();
    let registry = &signed.registry;
    let gate = gate_community_release_v1(registry, &expected, &signed.store, address, swap, &open);
    let (gated, _authorization) = gate?;
    Ok(Release {
        spec,
        digest: published.release_digest(),
        address: address.clone(),
        pin,
        execution: FallbackExecutionFactsV1::from_projection(gated.execution()),
    })
}

/// The host facts of a release: one publisher and the Stable profile.
fn host_facts(active: Option<Hash>) -> FallbackHostFactsV1 {
    FallbackHostFactsV1 {
        active_release_digest: active,
        publisher: Some(PUBLISHER.to_owned()),
        namespace_grants: Vec::new(),
        conformance_profiles: BTreeSet::from([STABLE]),
    }
}

/// The facts of `release` under the run-local `id`, as the host supplies them at declaration.
fn facts_of(release: &Release, id: PluginId) -> BoxResult<FallbackCandidateFactsV1> {
    let plugin = release.plugin(id, VERSION);
    let settings = FallbackDriverSettingsV1 {
        tick_interval: INTERVAL,
        subscriptions: Vec::new(),
    };
    let host = host_facts(Some(release.pin.implementation().release_digest()));
    let execution = release.execution.clone();
    let pin = release.pin.clone();
    Ok(FallbackCandidateFactsV1::collect(
        &plugin, pin, settings, execution, host,
    )?)
}

/// How the supply builds one implementation wrongly (ADR-119 section 6 case 15).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Tamper {
    /// The Plugin reports another version label than its IMK1.
    Version,
    /// The Plugin takes the run-local ID of the entry's live Plugin.
    SameId(PluginId),
    /// The Driver settings name another Plugin.
    ForeignSettings,
    /// The host ABI does not overlap the release's.
    IncompatibleAbi,
}

/// The test host's supply of releases and reference facts.
struct Supply {
    root: PathBuf,
    releases: Vec<Release>,
    material: Swap,
    reference: Option<FallbackReferenceV1>,
    refuse: Arc<AtomicBool>,
    missing: Vec<&'static str>,
    tamper: Option<(&'static str, Tamper)>,
    numbering: u8,
    hook: Option<Box<dyn FnOnce()>>,
    built: Vec<(PluginId, &'static str)>,
}

impl Supply {
    /// A supply of `releases` from `signed`'s closure store, with the material of `swap`.
    fn new(signed: &SignedWorld, releases: Vec<Release>, swap: Swap) -> Self {
        Self {
            root: signed.root.path().to_path_buf(),
            releases,
            material: swap,
            reference: None,
            refuse: Arc::new(AtomicBool::new(false)),
            missing: Vec::new(),
            tamper: None,
            numbering: 0,
            hook: None,
            built: Vec::new(),
        }
    }

    /// The inputs of `release`, built as `tamper` says.
    fn input(
        &mut self,
        release: &Release,
        tamper: Option<Tamper>,
    ) -> BoxResult<FallbackCandidateInputV1> {
        self.numbering += 1;
        let id = match tamper {
            Some(Tamper::SameId(id)) => id,
            _ => PluginId::new(),
        };
        self.built.push((id, release.spec.plugin_id));
        let version = if tamper == Some(Tamper::Version) {
            "9.9.9"
        } else {
            VERSION
        };
        let settings_id = if tamper == Some(Tamper::ForeignSettings) {
            PluginId::new()
        } else {
            id
        };
        let minor = if tamper == Some(Tamper::IncompatibleAbi) {
            5
        } else {
            0
        };
        let program = WorkerProgramV1::new(PathBuf::from(PROBE)).ok_or("invalid probe path")?;
        let supervisor =
            CommunityPluginSupervisorV1::new(program, PROMPT).ok_or("no supervisor")?;
        let source = Source::switched(self.numbering, Arc::clone(&self.refuse));
        let settings = CommunityDriverSettingsV1 {
            plugin_id: settings_id,
            name: release.spec.plugin_id,
            tick_interval: INTERVAL,
            subscriptions: Vec::new(),
            supervisor,
            source: Box::new(source),
            initial_state: initial(),
        };
        let host_abi = CommunityPluginHostAbiV1::new(minor, minor + 1, vec!["clock".to_owned()]);
        Ok(FallbackCandidateInputV1 {
            plugin: Box::new(release.plugin(id, version)),
            source: Box::new(LocalOciPublisherV1::open(&self.root)?),
            address: release.address.clone(),
            material: Box::new(self.material.clone()),
            settings,
            host_abi: host_abi.map_err(|error| format!("{error:?}"))?,
            profile: test_support::fixture_profile(),
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
        if let Some(hook) = self.hook.take() {
            hook();
        }
        let plugin_id = key.plugin_id();
        let release = self
            .releases
            .iter()
            .find(|release| release.spec.plugin_id == plugin_id)
            .filter(|release| !self.missing.contains(&release.spec.plugin_id))?
            .clone();
        let tamper = self.tamper.filter(|(target, _)| *target == plugin_id);
        self.input(&release, tamper.map(|(_, tamper)| tamper)).ok()
    }

    fn reference(&self, _entry_key: &str) -> Option<FallbackReferenceV1> {
        self.reference.clone()
    }
}

/// The number of temporary databases this process opened.
static DATABASES: AtomicU64 = AtomicU64::new(0);

/// A temporary `SQLite` database file, removed with its journals on drop.
struct TempDb(PathBuf);

impl TempDb {
    fn new() -> Self {
        let number = DATABASES.fetch_add(1, Ordering::SeqCst);
        let name = format!("pigloros-cbt-{}-{number}.db", std::process::id());
        Self(std::env::temp_dir().join(name))
    }

    fn path(&self) -> BoxResult<&str> {
        Ok(self.0.to_str().ok_or("the temporary path is not UTF-8")?)
    }

    /// Another connection to the database, behind the host's erasure gate.
    fn connect(&self, gate: &Arc<ErasureContainmentGateV1>) -> BoxResult<SqliteStore> {
        let mut store = SqliteStore::open(self.path()?)?;
        pos_core::store::EventStore::bind_erasure_gate(&mut store, Arc::clone(gate))?;
        Ok(store)
    }
}

impl Drop for TempDb {
    fn drop(&mut self) {
        for suffix in ["", "-wal", "-shm"] {
            let path = format!("{}{suffix}", self.0.display());
            drop(std::fs::remove_file(path));
        }
    }
}

/// A fresh store of `kind` with the composition fallback registry provisioned.
fn store_of(kind: StoreKind) -> BoxResult<(Box<dyn PassStoreV1>, Option<TempDb>)> {
    let (mut store, db): (Box<dyn PassStoreV1>, _) = match kind {
        StoreKind::Memory => (Box::new(MemoryStore::new()), None),
        StoreKind::Sqlite => {
            let db = TempDb::new();
            (Box::new(SqliteStore::open(db.path()?)?), Some(db))
        }
    };
    store.provision_fallback_registry()?;
    Ok((store, db))
}

/// The signed world, the pass world over a provisioned store, the supply, and the composition
/// of one declared entry and one undeclared sibling slot.
struct Rig {
    signed: SignedWorld,
    pass: PassWorld,
    db: Option<TempDb>,
    supply: Supply,
    boundary: CompositionBoundaryV1,
    host: Host,
    primary: Release,
    candidate: Release,
    next: Release,
    sibling: Release,
    entity: EntityId,
    policy: Option<Hash>,
}

impl Rig {
    /// A rig on `kind` whose entry's implementations behave as `behaviour`, composed but not
    /// declared.
    fn composed(kind: StoreKind, behaviour: Behaviour) -> BoxResult<Self> {
        let mut signed = SignedWorld::with_config(Config {
            extra_plugin_ids: GRANTED,
            ..Config::default()
        })?;
        let swap = Swap(Rc::new(RefCell::new(Some(material_of(&signed)?))));
        let specs = [
            ("plugin-a", "community.alpha", behaviour.primary),
            ("plugin-b", "community.alpha", behaviour.candidate),
            ("plugin-c", "community.alpha", behaviour.next),
            (
                "plugin-d",
                "community.sibling",
                b"draft:community.sibling".as_slice(),
            ),
        ];
        let mut releases = Vec::new();
        for (tag, (plugin_id, event_type, component)) in (1..).zip(specs) {
            // Roles are exclusive across registered Plugins: the sibling holds its own.
            let role = if plugin_id == "plugin-d" {
                SIBLING_ROLE
            } else {
                ROLE
            };
            let spec = Spec {
                plugin_id,
                event_type,
                component,
                role,
            };
            releases.push(publish(&mut signed, spec, tag, &swap)?);
        }
        let (store, db) = store_of(kind)?;
        let pass = PassWorld::with_store(kind, store, PROBE);
        let supply = Supply::new(&signed, releases.clone(), swap);
        let entity = EntityId::new();
        let target = CompositionFallbackTargetV1 {
            timeline: pass.timeline,
            entity,
        };
        let boundary = CompositionBoundaryV1::new(SCOPE.to_owned(), target, BTreeMap::new());
        let mut rig = Self {
            signed,
            pass,
            db,
            supply,
            boundary,
            host: CommunityPluginHostV1::new(Vec::new()),
            primary: releases[0].clone(),
            candidate: releases[1].clone(),
            next: releases[2].clone(),
            sibling: releases[3].clone(),
            entity,
            policy: None,
        };
        let outcomes = rig.compose()?;
        assert!(outcomes.is_empty(), "{outcomes:?}");
        Ok(rig)
    }

    /// As [`Self::composed`], with the entry declared over both candidates.
    fn declared(kind: StoreKind, behaviour: Behaviour, plan: Plan) -> BoxResult<Self> {
        let mut rig = Self::composed(kind, behaviour)?;
        let candidates = [rig.candidate.clone(), rig.next.clone()];
        let primary = rig.primary.clone();
        rig.declare(&primary, &candidates[..plan.candidates], plan)?;
        Ok(rig)
    }

    const fn target(&self) -> CompositionFallbackTargetV1 {
        CompositionFallbackTargetV1 {
            timeline: self.pass.timeline,
            entity: self.entity,
        }
    }

    /// Compose every slot through the restart composer, in recipe order.
    fn compose(&mut self) -> Result<Vec<Outcome>, BoundaryError> {
        let slots = [self.primary.slot(ENTRY), self.sibling.slot(SIBLING_SLOT)];
        let slots = slots.map(|(entry_key, base)| FallbackRestartSlotV1 {
            entry_key: entry_key.to_owned(),
            base: base.clone(),
        });
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
        Ok(restart.outcomes)
    }

    /// Restart: a fresh registry and host composed from the fold of the same store.
    fn restart(&mut self) -> Result<Vec<Outcome>, BoundaryError> {
        let gate: Arc<dyn ErasureGate> = self.pass.gate.clone();
        self.pass.registry = PluginRegistry::new().with_erasure_gate(gate);
        self.compose()
    }

    /// Declare `primary` with `candidates` as the entry's policy, the successor of the last.
    fn declare(&mut self, primary: &Release, candidates: &[Release], plan: Plan) -> TestResult {
        let primary_facts = facts_of(primary, PluginId::new())?;
        let required = required_plugin_v1(primary_facts.registry.plugin_id(), &primary_facts.pin)?;
        let mode = PluginExecutionModeV1::Local;
        let composition = RequiredPluginCompositionV1::try_new(mode, vec![required])?;
        let facts = candidates
            .iter()
            .map(|release| facts_of(release, PluginId::new()));
        let facts = facts.collect::<BoxResult<Vec<_>>>()?;
        let pins = candidates
            .iter()
            .map(|release| release.pin.clone())
            .collect();
        let (key, pin, triggers) = (
            ENTRY.to_owned(),
            primary.pin.clone(),
            plan.triggers.to_vec(),
        );
        let entry = FallbackEntryV1::new(key, pin, pins, triggers, plan.mode)?;
        let policy = DomainFallbackPolicyV1::new(SCOPE.to_owned(), vec![entry], self.policy)?;
        let entry_facts = FallbackEntryFactsV1 {
            primary: primary_facts.clone(),
            candidates: facts,
        };
        let declaration = FallbackDeclarationV1 {
            facts: BTreeMap::from([(ENTRY.to_owned(), entry_facts)]),
            ..self.declaration(&policy, composition.clone(), primary.key())?
        };
        self.commit_declaration(&declaration)?;
        self.supply.reference = Some(FallbackReferenceV1 {
            composition,
            primary: primary_facts,
        });
        Ok(())
    }

    /// Withdraw the policy: a successor with no entries.
    fn withdraw(&mut self) -> TestResult {
        let reference = self.supply.reference.clone().ok_or("nothing declared")?;
        let policy = DomainFallbackPolicyV1::new(SCOPE.to_owned(), Vec::new(), self.policy)?;
        let mut declaration =
            self.declaration(&policy, reference.composition, self.primary.key())?;
        declaration.effective.clear();
        self.commit_declaration(&declaration)
    }

    /// The declaration of `policy`, while the entry runs `running`, without facts.
    fn declaration(
        &self,
        policy: &DomainFallbackPolicyV1,
        composition: RequiredPluginCompositionV1,
        running: ImplementationKeyV1,
    ) -> BoxResult<FallbackDeclarationV1> {
        let timeline = self.pass.timeline;
        let row = self.pass.store.registry_row(SCOPE, timeline)?;
        Ok(FallbackDeclarationV1 {
            scope: SCOPE.to_owned(),
            target: self.target(),
            stepped_timeline: timeline,
            expected_state_revision: row.map_or(0, |row| row.state().state_revision()),
            expected_logical_head: self.pass.store.logical_head(timeline)?,
            policy_bytes: policy.to_canonical_cbor(),
            composition,
            effective: BTreeMap::from([(ENTRY.to_owned(), running)]),
            facts: BTreeMap::new(),
        })
    }

    fn commit_declaration(&mut self, declaration: &FallbackDeclarationV1) -> TestResult {
        let grants = grants(COMPOSITION_FALLBACK_DECLARE_GRANT_V1);
        let store = &mut *self.pass.store;
        let receipt = declare_composition_fallback_v1(store, &grants, declaration)?;
        self.policy = Some(receipt.row().policy_digest());
        Ok(())
    }

    /// One pass at the world's Tick.
    fn pass(&mut self) -> BoxResult<CommunityPassOutcomeV1> {
        let mut wall = clock();
        let trust = &self.signed.registry;
        Ok(self.pass.run(&mut self.host, trust, &mut wall, TICK)?)
    }

    /// One pass whose commit acknowledgement is lost, so the registry holds it in doubt.
    fn lost_pass(&mut self) -> BoxResult<CommunityPassOutcomeV1> {
        let mut wall = clock();
        let prepared = self.pass.prepare()?;
        let mut port = LostPort(self.pass.store.as_mut());
        let request = prepared.request(TICK, &mut port);
        let trust = &self.signed.registry;
        Ok(self
            .host
            .run_pass(&mut self.pass.registry, trust, &mut wall, request))
    }

    /// The composition boundary transaction after `outcome`.
    fn boundary(&mut self, outcome: &CommunityPassOutcomeV1) -> Outcomes {
        let mut wall = clock();
        let mut context = FallbackBoundaryContextV1 {
            registry: &mut self.pass.registry,
            store: &mut *self.pass.store,
            trust: &self.signed.registry,
            wall: &mut wall,
            supply: &mut self.supply,
            tick: TICK,
        };
        self.boundary
            .run_boundary_v1(&mut context, &mut self.host, outcome)
    }

    /// An owner activation of `target` for the declared entry, with the activate grant when
    /// `granted`.
    fn owner(
        &mut self,
        target: &ImplementationKeyV1,
        granted: bool,
    ) -> Result<Outcome, BoundaryError> {
        self.owner_at(ENTRY, target, granted)
    }

    /// An owner activation of `target` for `entry_key`.
    fn owner_at(
        &mut self,
        entry_key: &str,
        target: &ImplementationKeyV1,
        granted: bool,
    ) -> Result<Outcome, BoundaryError> {
        let held = if granted {
            grants(COMPOSITION_FALLBACK_ACTIVATE_GRANT_V1)
        } else {
            grants(COMPOSITION_FALLBACK_DECLARE_GRANT_V1)
        };
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
        self.boundary
            .owner_activate_v1(&mut context, host, &held, entry_key, target)
    }

    /// Make every member and candidate follow the signed world's current material.
    fn follow(&self) -> TestResult {
        self.supply.material.set(Some(material_of(&self.signed)?));
        Ok(())
    }

    /// Revoke `release` and follow the new material.
    fn revoke(&mut self, release: &Release) -> TestResult {
        self.signed
            .advance_revoking_artifacts(&[release.digest])??;
        self.follow()
    }

    /// The Plugin ID text of the entry's live implementation: the Plugin the boundary binds,
    /// which must be registered and have a host member.
    fn running(&self) -> BoxResult<&'static str> {
        let bound = self
            .boundary
            .binding(ENTRY)
            .ok_or("the entry is not bound")?;
        self.host.member_index(bound).ok_or("no host member")?;
        let composition = self.pass.registry.composition();
        let registered = composition.plugins.iter().any(|plugin| plugin.id == bound);
        assert!(registered, "the bound Plugin is not registered");
        let built = self.supply.built.iter().find(|(id, _)| *id == bound);
        Ok(built.ok_or("the bound Plugin was not built")?.1)
    }

    /// Every Event on the pass Timeline.
    fn event_count(&self) -> usize {
        self.pass.events().len()
    }

    /// The decoded payload of the last Event, which must be an activation.
    fn last_activation(&self) -> BoxResult<FallbackActivatedInputV1> {
        let events = self.pass.events();
        let event = events.last().ok_or("no Event")?;
        let activated = Kind::new(COMPOSITION_FALLBACK_ACTIVATED_EVENT_TYPE_V1);
        assert_eq!(event.event_type, activated);
        let payload = FallbackActivatedPayloadV1::from_canonical_cbor(event.payload.as_slice())?;
        Ok(payload.as_input().clone())
    }

    /// The registry's current state revision.
    fn revision(&self) -> BoxResult<u64> {
        let row = self.pass.store.registry_row(SCOPE, self.pass.timeline)?;
        Ok(row.map_or(0, |row| row.state().state_revision()))
    }
}

/// The declared entry's trigger list, mode and number of candidates.
#[derive(Clone, Copy)]
struct Plan {
    triggers: &'static [Code],
    mode: FallbackActivationModeV1,
    candidates: usize,
}

/// An automatic entry over both candidates that activates on a missing implementation, a
/// resource limit or a revocation.
const AUTOMATIC: Plan = Plan {
    triggers: &[
        Code::MissingImplementation,
        Code::ResourceLimit,
        Code::ArtifactRevoked,
    ],
    mode: FallbackActivationModeV1::Automatic,
    candidates: 2,
};
/// As [`AUTOMATIC`], with one candidate.
const ONE_CANDIDATE: Plan = Plan {
    candidates: 1,
    ..AUTOMATIC
};
/// As [`AUTOMATIC`], in manual mode.
const MANUAL: Plan = Plan {
    mode: FallbackActivationModeV1::Manual,
    ..AUTOMATIC
};

/// The host-native grants holding `grant` alone.
fn grants(grant: &str) -> FallbackHostGrantsV1 {
    FallbackHostGrantsV1 {
        grants: BTreeSet::from([grant.to_owned()]),
    }
}

/// The skip reasons of `skipped`, in order.
fn reasons(skipped: &[FallbackSkippedCandidateV1]) -> String {
    let name = |skipped: &FallbackSkippedCandidateV1| format!("{:?}", skipped.reason);
    let names: Vec<String> = skipped.iter().map(name).collect();
    names.join(",")
}

/// A short description of one entry outcome.
fn describe(outcome: &Outcome) -> String {
    match outcome {
        Outcome::Activated { to, skipped, .. } => {
            format!("activated:{}:[{}]", to.plugin_id(), reasons(skipped))
        }
        Outcome::AwaitingOwner { code, .. } => format!("awaiting:{code:?}"),
        Outcome::Exhausted { skipped, .. } => format!("exhausted:[{}]", reasons(skipped)),
        Outcome::NotCommitted { error, .. } => format!("not-committed:{error:?}"),
    }
}

/// A short description of one boundary transaction's result.
fn described(outcomes: &Outcomes) -> Vec<String> {
    match outcomes {
        Ok(outcomes) => outcomes.iter().map(describe).collect(),
        Err(error) => vec![format!("error:{error:?}")],
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

/// A refused pass whose only member, `plugin`, exhausted its fuel.
fn fuel_outcome(plugin: PluginId) -> CommunityPassOutcomeV1 {
    CommunityPassOutcomeV1 {
        tick: TICK,
        utc: Some(UTC),
        gates: vec![MemberPassV1 {
            plugin,
            expected_plugin_id: "plugin-a".to_owned(),
            gate: Err(Error::FuelExhausted),
            invocation_id: None,
            launch_failure: Some(Error::FuelExhausted),
            sync: Ok(()),
        }],
        result: PassResultV1::Refused,
    }
}

/// Run `vector` on every store kind.
fn on_every_store(vector: fn(StoreKind) -> TestResult) -> TestResult {
    for kind in StoreKind::ALL {
        vector(kind).map_err(|error| format!("{}: {error}", kind.tag()))?;
    }
    Ok(())
}

/// The description of one owner action's result.
fn described_one(outcome: &Result<Outcome, BoundaryError>) -> String {
    outcome
        .as_ref()
        .map_or_else(|error| format!("error:{error:?}"), describe)
}

/// The run-local Plugin the declared entry runs.
fn bound(rig: &Rig) -> BoxResult<PluginId> {
    Ok(rig
        .boundary
        .binding(ENTRY)
        .ok_or("the entry is not bound")?)
}

/// Case 1 and case 2 (code 3, `Failed`): the failed pass is discarded; the boundary appends
/// one activation Event and one ledger row at the pass's Tick, swaps the registry entry and the
/// host member, and the next pass gates and commits the candidate beside the untouched sibling,
/// with every member synced.
#[test]
fn a_resource_limit_activates_the_candidate_at_the_tick_boundary() -> TestResult {
    on_every_store(resource_limit)
}

fn resource_limit(kind: StoreKind) -> TestResult {
    let mut rig = Rig::declared(kind, FAILING, AUTOMATIC)?;
    let failed = rig.pass()?;
    assert_eq!(result_of(&failed), "failed");
    let (before, primary) = (rig.event_count(), bound(&rig)?);
    let outcomes = rig.boundary(&failed);
    assert_eq!(described(&outcomes), ["activated:plugin-b:[]"]);
    assert_eq!(rig.event_count(), before + 1);
    let activation = rig.last_activation()?;
    assert_eq!(activation.closing_tenure_ordinal, 0);
    assert_eq!(
        (activation.from, activation.to),
        (rig.primary.key(), rig.candidate.key())
    );
    assert_eq!(activation.trigger_code, Code::ResourceLimit);
    let automatic = FallbackActivationOriginV1::Automatic;
    let basis = FallbackTriggerCauseV1::FuelExhausted.basis(automatic);
    assert_eq!(activation.trigger_basis, basis);
    let ledger = rig.pass.store.fallback_ledger(SCOPE, rig.pass.timeline)?;
    assert_eq!(ledger.len(), 2);
    let body = ledger.last().map(|row| row.body().clone());
    let expected = FallbackLedgerBodyV1::Activation {
        entry_key: ENTRY.to_owned(),
        closing_tenure_ordinal: 0,
        activation_ordinal: 1,
        tick: TICK,
    };
    assert_eq!(body, Some(expected));
    assert_eq!(rig.running()?, "plugin-b");
    assert!(!rig.pass.registry.contains(&primary));
    assert_eq!(rig.host.member_index(primary), None);
    let next = rig.pass()?;
    assert_eq!(result_of(&next), "committed:2");
    let gated = next.gates[0]
        .gate
        .as_ref()
        .map(|summary| summary.plugin_id.as_str());
    assert_eq!(gated, Ok("plugin-b"));
    assert!(next.gates.iter().all(|entry| entry.sync.is_ok()));
    assert_eq!(next.tick, TICK);
    Ok(())
}

/// Case 2 (code 4, `Refused`) and case 13: a revoked primary refuses the pass at its gate; the
/// boundary activates the candidate, so the next pass commits (relief from the revision 7
/// deadlock), and an owner return to the revoked primary is refused at the trust gate with
/// nothing committed.
#[test]
fn a_revoked_primary_is_replaced_and_refused_on_return() -> TestResult {
    on_every_store(revoked_primary)
}

fn revoked_primary(kind: StoreKind) -> TestResult {
    let mut rig = Rig::declared(kind, HEALTHY, AUTOMATIC)?;
    assert_eq!(result_of(&rig.pass()?), "committed:2");
    let primary = rig.primary.clone();
    rig.revoke(&primary)?;
    let refused = rig.pass()?;
    assert_eq!(result_of(&refused), "refused");
    assert_eq!(
        described(&rig.boundary(&refused)),
        ["activated:plugin-b:[]"]
    );
    assert_eq!(rig.last_activation()?.trigger_code, Code::ArtifactRevoked);
    assert_eq!(result_of(&rig.pass()?), "committed:2");
    let before = rig.event_count();
    let returned = rig.owner(&primary.key(), true);
    assert_eq!(described_one(&returned), "exhausted:[ReleaseNotCurrent]");
    assert_eq!(rig.event_count(), before);
    assert_eq!(rig.running()?, "plugin-b");
    Ok(())
}

/// Case 2 (code 1): at restart a missing effective implementation activates the first later
/// candidate that validates, which is installed fresh in its place; a later restart composes
/// the activated candidate.
#[test]
fn a_missing_implementation_activates_at_restart_composition() -> TestResult {
    on_every_store(restart_activation)
}

fn restart_activation(kind: StoreKind) -> TestResult {
    let mut rig = Rig::declared(kind, HEALTHY, AUTOMATIC)?;
    rig.supply.missing = vec!["plugin-a", "plugin-b"];
    let before = rig.event_count();
    let outcomes = rig.restart();
    assert_eq!(
        described(&outcomes),
        ["activated:plugin-c:[SourceUnavailable]"]
    );
    assert_eq!(rig.event_count(), before + 1);
    let activation = rig.last_activation()?;
    assert_eq!(activation.trigger_code, Code::MissingImplementation);
    let cause = FallbackTriggerCauseV1::MissingImplementation.code();
    assert_eq!(activation.trigger_basis.cause, cause);
    assert_eq!(rig.running()?, "plugin-c");
    assert_eq!(result_of(&rig.pass()?), "committed:2");
    rig.supply.missing.clear();
    assert_eq!(described(&rig.restart()), Vec::<String>::new());
    assert_eq!(rig.running()?, "plugin-c");
    Ok(())
}

/// A restart fails closed when a slot cannot be composed: an undeclared slot, an exhausted
/// chain, a refused restart activation, a cause other than a missing implementation, and an
/// implementation key that does not bind.
#[test]
fn a_restart_fails_closed_when_no_implementation_composes() -> TestResult {
    on_every_store(restart_refusals)
}

fn restart_refusals(kind: StoreKind) -> TestResult {
    let mut rig = Rig::declared(kind, HEALTHY, AUTOMATIC)?;
    let unavailable = |reason: &str| vec![format!("error:SlotUnavailable({reason})")];
    rig.supply.missing = vec!["plugin-d"];
    assert_eq!(described(&rig.restart()), unavailable("SourceUnavailable"));
    rig.supply.missing = vec!["plugin-a", "plugin-b", "plugin-c"];
    assert_eq!(described(&rig.restart()), unavailable("SourceUnavailable"));
    rig.supply.missing.clear();
    rig.supply.tamper = Some(("plugin-a", Tamper::ForeignSettings));
    assert_eq!(described(&rig.restart()), unavailable("MemberBuildFailed"));
    rig.supply.tamper = Some(("plugin-a", Tamper::Version));
    assert_eq!(described(&rig.restart()), unavailable("PrepareRefused"));
    let mut manual = Rig::declared(kind, HEALTHY, MANUAL)?;
    manual.supply.missing = vec!["plugin-a"];
    let refused = manual.restart();
    assert_eq!(described(&refused), ["error:Registry(ManualEntry)"]);
    Ok(())
}

/// The trigger reader reads only a `Failed` or `Refused` pass's `launch_failure` of the member.
#[test]
fn only_a_failed_or_refused_pass_triggers() {
    let plugin = PluginId::new();
    let mut outcome = fuel_outcome(plugin);
    let fuel = Some(FallbackTriggerCauseV1::FuelExhausted);
    assert_eq!(fallback_trigger_cause_v1(&outcome, plugin), fuel);
    assert_eq!(fallback_trigger_cause_v1(&outcome, PluginId::new()), None);
    outcome.result = PassResultV1::Committed(None);
    assert_eq!(fallback_trigger_cause_v1(&outcome, plugin), None);
    outcome.result = PassResultV1::InDoubt;
    assert_eq!(fallback_trigger_cause_v1(&outcome, plugin), None);
    outcome.result = PassResultV1::Refused;
    outcome.gates[0].launch_failure = Some(Error::InvalidInvocation);
    let invalid = Some(FallbackTriggerCauseV1::InvalidInvocation);
    assert_eq!(fallback_trigger_cause_v1(&outcome, plugin), invalid);
    outcome.gates[0].launch_failure = None;
    assert_eq!(fallback_trigger_cause_v1(&outcome, plugin), None);
}

/// Case 3: nothing activates without a policy, after a committed pass, for a never-eligible
/// cause, or for an in-doubt pass; and while the pass is in doubt every candidate is skipped
/// before the commit (case 15).
#[test]
fn ineligible_and_in_doubt_passes_activate_nothing() -> TestResult {
    on_every_store(ineligible)
}

fn ineligible(kind: StoreKind) -> TestResult {
    let mut undeclared = Rig::composed(kind, FAILING)?;
    let failed = undeclared.pass()?;
    assert_eq!(
        described(&undeclared.boundary(&failed)),
        Vec::<String>::new()
    );
    let mut rig = Rig::declared(kind, HEALTHY, AUTOMATIC)?;
    let committed = rig.pass()?;
    assert_eq!(described(&rig.boundary(&committed)), Vec::<String>::new());
    rig.supply.refuse.store(true, Ordering::SeqCst);
    let invalid = rig.pass()?;
    assert_eq!(result_of(&invalid), "failed");
    assert_eq!(described(&rig.boundary(&invalid)), Vec::<String>::new());
    assert_eq!(rig.boundary.observation(ENTRY), None);
    let mut doubtful = Rig::declared(kind, HEALTHY, AUTOMATIC)?;
    let lost = doubtful.lost_pass()?;
    assert_eq!(result_of(&lost), "in-doubt");
    assert_eq!(described(&doubtful.boundary(&lost)), Vec::<String>::new());
    let before = doubtful.event_count();
    let refusal = fuel_outcome(bound(&doubtful)?);
    let skipped = described(&doubtful.boundary(&refusal));
    assert_eq!(skipped, ["exhausted:[SwapRefused,SwapRefused]"]);
    assert_eq!(doubtful.event_count(), before);
    assert_eq!(doubtful.running()?, "plugin-a");
    Ok(())
}

/// Case 8: a revoked candidate is recorded in `skipped`, exhausting the chain fails closed,
/// and the chain never moves back to the primary.
#[test]
fn the_chain_skips_revoked_candidates_and_fails_closed() -> TestResult {
    on_every_store(chain)
}

fn chain(kind: StoreKind) -> TestResult {
    let mut rig = Rig::declared(kind, FAILING, AUTOMATIC)?;
    let candidate = rig.candidate.clone();
    rig.revoke(&candidate)?;
    let failed = rig.pass()?;
    let outcomes = rig.boundary(&failed);
    assert_eq!(
        described(&outcomes),
        ["activated:plugin-c:[ReleaseNotCurrent]"]
    );
    let skipped = FallbackSkippedCandidateV1 {
        implementation_digest: candidate.pin.implementation().digest(),
        reason: pos_core::FallbackSkipReasonV1::ReleaseNotCurrent,
    };
    assert_eq!(rig.last_activation()?.skipped, [skipped]);
    let mut exhausted = Rig::declared(kind, FAILING, AUTOMATIC)?;
    let digests = [exhausted.candidate.digest, exhausted.next.digest];
    exhausted.signed.advance_revoking_artifacts(&digests)??;
    exhausted.follow()?;
    let failed = exhausted.pass()?;
    let before = exhausted.event_count();
    let outcomes = described(&exhausted.boundary(&failed));
    assert_eq!(
        outcomes,
        ["exhausted:[ReleaseNotCurrent,ReleaseNotCurrent]"]
    );
    assert_eq!(exhausted.event_count(), before);
    assert_eq!(exhausted.running()?, "plugin-a");
    let both_fail = Behaviour {
        candidate: FUEL,
        ..FAILING
    };
    let mut forward = Rig::declared(kind, both_fail, ONE_CANDIDATE)?;
    let failed = forward.pass()?;
    assert_eq!(
        described(&forward.boundary(&failed)),
        ["activated:plugin-b:[]"]
    );
    let failed = forward.pass()?;
    assert_eq!(described(&forward.boundary(&failed)), ["exhausted:[]"]);
    assert_eq!(forward.running()?, "plugin-b");
    Ok(())
}

/// Case 11 and case 9: a manual entry records the observation and waits; a later
/// `ImplementationUnavailable` is never a source; the owner needs the grant, may activate a
/// non-adjacent candidate, and may return to the primary, which records the closing tenure's
/// code; every other owner request is refused.
#[test]
fn manual_mode_waits_for_the_owner() -> TestResult {
    on_every_store(manual)
}

fn manual(kind: StoreKind) -> TestResult {
    let mut rig = Rig::declared(kind, FAILING, MANUAL)?;
    let failed = rig.pass()?;
    let before = rig.event_count();
    assert_eq!(
        described(&rig.boundary(&failed)),
        ["awaiting:ResourceLimit"]
    );
    assert_eq!(rig.event_count(), before);
    assert_eq!(rig.boundary.observation(ENTRY), Some(Code::ResourceLimit));
    let unavailable = rig.pass()?;
    assert_eq!(result_of(&unavailable), "failed");
    assert_eq!(described(&rig.boundary(&unavailable)), Vec::<String>::new());
    assert_eq!(rig.boundary.observation(ENTRY), Some(Code::ResourceLimit));
    let (next, candidate) = (rig.next.key(), rig.candidate.key());
    assert_eq!(rig.owner(&next, false), Err(BoundaryError::NotGranted));
    let unknown = rig.owner_at("elsewhere", &next, true);
    assert_eq!(unknown, Err(BoundaryError::UnknownEntry));
    assert_eq!(
        described_one(&rig.owner(&next, true)),
        "activated:plugin-c:[]"
    );
    let activation = rig.last_activation()?;
    assert_eq!(
        activation.trigger_basis.origin,
        FallbackActivationOriginV1::Owner
    );
    assert_eq!(activation.trigger_code, Code::ResourceLimit);
    assert_eq!(rig.boundary.observation(ENTRY), None);
    assert_eq!(rig.running()?, "plugin-c");
    assert_eq!(rig.owner(&next, true), Err(BoundaryError::InvalidTarget));
    let sibling = rig.sibling.key();
    assert_eq!(rig.owner(&sibling, true), Err(BoundaryError::InvalidTarget));
    assert_eq!(
        rig.owner(&candidate, true),
        Err(BoundaryError::NoObservation)
    );
    let primary = rig.primary.key();
    assert_eq!(
        described_one(&rig.owner(&primary, true)),
        "activated:plugin-a:[]"
    );
    let returned = rig.last_activation()?;
    assert_eq!(returned.closing_tenure_ordinal, 1);
    assert_eq!(returned.trigger_code, Code::ResourceLimit);
    assert_eq!(
        returned.trigger_basis.origin,
        FallbackActivationOriginV1::Owner
    );
    assert_eq!(rig.running()?, "plugin-a");
    Ok(())
}

/// Case 9: an owner activation whose observed code the entry does not declare is refused, and
/// an undeclared code never activates automatically.
#[test]
fn an_undeclared_code_activates_nothing() -> TestResult {
    on_every_store(undeclared_code)
}

fn undeclared_code(kind: StoreKind) -> TestResult {
    let plan = Plan {
        triggers: &[Code::ArtifactRevoked],
        ..AUTOMATIC
    };
    let mut rig = Rig::declared(kind, FAILING, plan)?;
    let failed = rig.pass()?;
    assert_eq!(described(&rig.boundary(&failed)), Vec::<String>::new());
    assert_eq!(rig.boundary.observation(ENTRY), Some(Code::ResourceLimit));
    let candidate = rig.candidate.key();
    let refused = rig.owner(&candidate, true);
    assert_eq!(refused, Err(BoundaryError::TriggerNotDeclared));
    Ok(())
}

/// Case 12: a refused erasure-guarded append leaves the old composition in force.
#[test]
fn a_refused_guarded_append_leaves_the_composition_in_force() -> TestResult {
    on_every_store(erasure)
}

fn erasure(kind: StoreKind) -> TestResult {
    let mut rig = Rig::declared(kind, FAILING, AUTOMATIC)?;
    let failed = rig.pass()?;
    let primary = bound(&rig)?;
    rig.pass.gate.block_timeline(rig.pass.timeline);
    let outcomes = described(&rig.boundary(&failed));
    let refused = outcomes.len() == 1
        && (outcomes[0].starts_with("not-committed:")
            || outcomes[0] == "exhausted:[SwapRefused,SwapRefused]");
    assert!(refused, "{outcomes:?}");
    assert_eq!(bound(&rig)?, primary);
    assert_eq!(rig.running()?, "plugin-a");
    Ok(())
}

/// The outcome of the boundary after a failed pass when the rig is changed by `change`.
fn refused_with(kind: StoreKind, change: Change) -> BoxResult<String> {
    let mut rig = Rig::declared(kind, FAILING, AUTOMATIC)?;
    let failed = rig.pass()?;
    change(&mut rig);
    let before = (rig.event_count(), rig.pass.registry.len());
    let outcomes = described(&rig.boundary(&failed)).join(";");
    let appended = usize::from(outcomes.starts_with("activated:"));
    assert_eq!(rig.event_count(), before.0 + appended, "{outcomes}");
    assert_eq!(rig.pass.registry.len(), before.1, "{outcomes}");
    Ok(outcomes)
}

fn source_missing(rig: &mut Rig) {
    rig.supply.missing = vec!["plugin-b"];
}

fn reference_missing(rig: &mut Rig) {
    rig.supply.reference = None;
}

const fn version_label(rig: &mut Rig) {
    rig.supply.tamper = Some(("plugin-b", Tamper::Version));
}

const fn foreign_settings(rig: &mut Rig) {
    rig.supply.tamper = Some(("plugin-b", Tamper::ForeignSettings));
}

const fn incompatible_abi(rig: &mut Rig) {
    rig.supply.tamper = Some(("plugin-b", Tamper::IncompatibleAbi));
}

fn primary_id(rig: &mut Rig) {
    let live = rig.boundary.binding(ENTRY).unwrap_or_default();
    rig.supply.tamper = Some(("plugin-b", Tamper::SameId(live)));
}

fn no_host_member(rig: &mut Rig) {
    rig.host = CommunityPluginHostV1::new(Vec::new());
}

/// One change to a rig before its boundary transaction.
type Change = fn(&mut Rig);

/// Every case-15 change and the outcome it leads to.
const PRE_COMMIT: [(Change, &str); 7] = [
    (source_missing, "activated:plugin-c:[SourceUnavailable]"),
    (reference_missing, "exhausted:[FactsMismatch,FactsMismatch]"),
    (version_label, "activated:plugin-c:[FactsMismatch]"),
    (foreign_settings, "activated:plugin-c:[MemberBuildFailed]"),
    (incompatible_abi, "activated:plugin-c:[MemberBuildFailed]"),
    (primary_id, "activated:plugin-c:[PrepareRefused]"),
    (no_host_member, "exhausted:[SwapRefused,SwapRefused]"),
];

/// Case 15: each pre-commit refusal skips its candidate, which is torn down; the next candidate
/// activates with the skip recorded, or nothing is committed. An owner return whose primary
/// reports another version label than its IMK1 is refused by the host-level `validate_swap`.
#[test]
fn pre_commit_refusals_skip_the_candidate() -> TestResult {
    on_every_store(pre_commit)
}

fn pre_commit(kind: StoreKind) -> TestResult {
    for (change, expected) in PRE_COMMIT {
        assert_eq!(refused_with(kind, change)?, expected);
    }
    let mut rig = Rig::declared(kind, FAILING, AUTOMATIC)?;
    let failed = rig.pass()?;
    assert_eq!(described(&rig.boundary(&failed)), ["activated:plugin-b:[]"]);
    rig.supply.tamper = Some(("plugin-a", Tamper::Version));
    let primary = rig.primary.key();
    let returned = rig.owner(&primary, true);
    assert_eq!(described_one(&returned), "exhausted:[SwapRefused]");
    assert_eq!(rig.running()?, "plugin-b");
    Ok(())
}

/// Case 14 (behaviour): a re-base in a candidate tenure continues the tenure with the new
/// candidates, and after a withdrawal nothing activates.
#[test]
fn a_rebase_continues_and_a_withdrawal_stops_the_chain() -> TestResult {
    on_every_store(rebase_and_withdrawal)
}

fn rebase_and_withdrawal(kind: StoreKind) -> TestResult {
    let both_fail = Behaviour {
        candidate: FUEL,
        ..FAILING
    };
    let mut rig = Rig::declared(kind, both_fail, ONE_CANDIDATE)?;
    let failed = rig.pass()?;
    assert_eq!(described(&rig.boundary(&failed)), ["activated:plugin-b:[]"]);
    let (candidate, next) = (rig.candidate.clone(), rig.next.clone());
    rig.declare(&candidate, &[next], ONE_CANDIDATE)?;
    let failed = rig.pass()?;
    assert_eq!(described(&rig.boundary(&failed)), ["activated:plugin-c:[]"]);
    let activation = rig.last_activation()?;
    assert_eq!(activation.closing_tenure_ordinal, 1);
    assert_eq!(activation.from, candidate.key());
    assert_eq!(result_of(&rig.pass()?), "committed:2");
    let mut withdrawn = Rig::declared(kind, both_fail, ONE_CANDIDATE)?;
    let failed = withdrawn.pass()?;
    assert_eq!(
        described(&withdrawn.boundary(&failed)),
        ["activated:plugin-b:[]"]
    );
    withdrawn.withdraw()?;
    let failed = withdrawn.pass()?;
    assert_eq!(
        described(&withdrawn.boundary(&failed)),
        Vec::<String>::new()
    );
    assert_eq!(withdrawn.running()?, "plugin-b");
    Ok(())
}

/// Case 7 and section 4.7: a boundary whose live registry differs from the effective
/// composition faults, and the fault latches.
#[test]
fn a_diverged_live_registry_faults_and_the_fault_latches() -> TestResult {
    on_every_store(diverged)
}

fn diverged(kind: StoreKind) -> TestResult {
    let mut rig = Rig::declared(kind, FAILING, AUTOMATIC)?;
    let failed = rig.pass()?;
    let sibling = rig.boundary.binding(SIBLING_SLOT).ok_or("no sibling")?;
    let bindings = BTreeMap::from([(ENTRY.to_owned(), sibling)]);
    rig.boundary = CompositionBoundaryV1::new(SCOPE.to_owned(), rig.target(), bindings);
    let faulted = rig.boundary(&failed);
    assert!(
        matches!(faulted, Err(BoundaryError::InvariantFault(_))),
        "{faulted:?}"
    );
    assert!(rig.boundary.is_faulted());
    assert_eq!(rig.boundary(&failed), Err(BoundaryError::Faulted));
    let candidate = rig.candidate.key();
    assert_eq!(rig.owner(&candidate, true), Err(BoundaryError::Faulted));
    Ok(())
}

/// Case 7 (end to end): an unprovisioned registry refuses the restart and the boundary.
#[test]
fn an_unprovisioned_registry_refuses_the_restart_and_the_boundary() -> TestResult {
    let signed = SignedWorld::new()?;
    let swap = Swap(Rc::new(RefCell::new(Some(material_of(&signed)?))));
    let mut supply = Supply::new(&signed, Vec::new(), swap);
    let mut pass = PassWorld::with_store(StoreKind::Memory, Box::new(MemoryStore::new()), PROBE);
    let target = CompositionFallbackTargetV1 {
        timeline: pass.timeline,
        entity: EntityId::new(),
    };
    let mut wall = clock();
    let mut context = FallbackBoundaryContextV1 {
        registry: &mut pass.registry,
        store: &mut *pass.store,
        trust: &signed.registry,
        wall: &mut wall,
        supply: &mut supply,
        tick: TICK,
    };
    let missing = BoundaryError::Registry(RegistryError::MissingState);
    let restart = compose_restart_v1(&mut context, SCOPE.to_owned(), target, &[]);
    assert_eq!(restart.err(), Some(missing));
    let mut boundary = CompositionBoundaryV1::new(SCOPE.to_owned(), target, BTreeMap::new());
    let mut host = CommunityPluginHostV1::new(Vec::new());
    let outcome = fuel_outcome(PluginId::new());
    let refused = boundary.run_boundary_v1(&mut context, &mut host, &outcome);
    assert_eq!(refused, Err(missing));
    Ok(())
}

/// Case 7 (end to end, `SQLite`): a concurrent activation of the same tenure makes the commit
/// a `Conflict`, which is not adopted, after which the boundary faults on the diverged fold; a
/// concurrent declaration makes it `StaleState`, and the next boundary re-derives and activates.
#[test]
fn concurrent_writes_refuse_the_commit() -> TestResult {
    conflict()?;
    stale()
}

/// A connection to the rig's database.
fn other_connection(rig: &Rig) -> BoxResult<SqliteStore> {
    rig.db.as_ref().ok_or("no database")?.connect(&rig.pass.gate)
}

/// The rig's Logical Head and the sequences of its Events, as this connection reads them.
fn prefix_of(rig: &Rig) -> BoxResult<String> {
    let timeline = rig.pass.timeline;
    let head = rig.pass.store.logical_head(timeline)?;
    let events = rig.pass.store.read(timeline, pos_core::SeqRange::all());
    let seqs: Vec<u64> = events?.iter().map(|event| event.seq.as_u64()).collect();
    Ok(format!("head {head:?}, Events {seqs:?}"))
}

fn conflict() -> TestResult {
    let mut rig = Rig::declared(StoreKind::Sqlite, FAILING, AUTOMATIC)?;
    let failed = rig.pass()?;
    let request = FallbackActivateRequestV1 {
        scope: SCOPE.to_owned(),
        target: rig.target(),
        expected_state_revision: rig.revision()?,
        expected_logical_head: rig.pass.store.logical_head(rig.pass.timeline)?,
        entry_key: ENTRY.to_owned(),
        closing_tenure_ordinal: 0,
        from: rig.primary.key(),
        to: rig.next.key(),
        trigger_code: Code::ResourceLimit,
        trigger_basis: FallbackTriggerBasisV1 {
            cause: FallbackTriggerCauseV1::FuelExhausted.code(),
            origin: FallbackActivationOriginV1::Automatic,
        },
        skipped: Vec::new(),
        tick: TICK + 1,
    };
    let mut other = other_connection(&rig)?;
    let ran = Rc::new(Cell::new(false));
    let flag = Rc::clone(&ran);
    rig.supply.hook = Some(Box::new(move || flag.set(other.activate(&request).is_ok())));
    let outcomes = rig.boundary(&failed);
    assert!(ran.get());
    let prefix = prefix_of(&rig)?;
    assert_eq!(described(&outcomes), ["not-committed:Conflict"], "{prefix}");
    assert_eq!(rig.running()?, "plugin-a");
    let faulted = rig.boundary(&failed);
    assert!(
        matches!(faulted, Err(BoundaryError::InvariantFault(_))),
        "{faulted:?}"
    );
    Ok(())
}

fn stale() -> TestResult {
    let mut rig = Rig::declared(StoreKind::Sqlite, FAILING, AUTOMATIC)?;
    let failed = rig.pass()?;
    let pins = vec![rig.candidate.pin.clone(), rig.next.pin.clone()];
    let triggers = vec![Code::ResourceLimit];
    let mode = FallbackActivationModeV1::Automatic;
    let primary = rig.primary.pin.clone();
    let entry = FallbackEntryV1::new(ENTRY.to_owned(), primary, pins, triggers, mode)?;
    let policy = DomainFallbackPolicyV1::new(SCOPE.to_owned(), vec![entry], rig.policy)?;
    let sets = BTreeMap::from([(ENTRY.to_owned(), BTreeSet::from([STABLE]))]);
    let request = FallbackDeclareRequestV1 {
        scope: SCOPE.to_owned(),
        target: rig.target(),
        expected_state_revision: rig.revision()?,
        expected_logical_head: rig.pass.store.logical_head(rig.pass.timeline)?,
        policy_bytes: policy.to_canonical_cbor(),
        conformance: FallbackConformanceSetsV1::new(sets),
    };
    let mut other = other_connection(&rig)?;
    let ran = Rc::new(Cell::new(false));
    let flag = Rc::clone(&ran);
    rig.supply.hook = Some(Box::new(move || flag.set(other.declare(&request).is_ok())));
    let outcomes = rig.boundary(&failed);
    assert!(ran.get());
    let prefix = prefix_of(&rig)?;
    assert_eq!(described(&outcomes), ["not-committed:StaleState"], "{prefix}");
    assert_eq!(rig.running()?, "plugin-a");
    assert_eq!(described(&rig.boundary(&failed)), ["activated:plugin-b:[]"]);
    Ok(())
}
