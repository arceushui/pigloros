//! PCF-CPH-016 to PCF-CPH-018 of `PCH1` version 2: the ADR-119 runtime declaration and the
//! reserved fallback Event types (#665, ADR-119 section 6 cases 4, 5 and the declaration part
//! of 14).
//!
//! The declaration cases call the runtime `declare` over the composition fallback registry of
//! each store kind: `MemoryStore`, and `SqliteStore` on a file, because the registry requires
//! the WAL journal, which an in-memory database cannot use. The facts of every implementation
//! come from the facts-only registration path, and the host facts, including the Stable
//! passing-profile digests of rule 7, are supplied by the case. The reserved-type case runs the
//! probe guest on the real worker, as PCF-CPH-013 does.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use pos_core::store::EventStore;
use pos_core::{
    CompositionPinV1, DomainFallbackPolicyV1, EntityId, ErasureContainmentGateV1,
    FallbackActivationModeV1, FallbackActivationOriginV1, FallbackEntryV1, FallbackTriggerBasisV1,
    FallbackTriggerCodeV1, Hash, ImplementationKeyV1, PluginId, Seq, TimelineId,
    COMPOSITION_FALLBACK_ACTIVATED_EVENT_TYPE_V1, COMPOSITION_FALLBACK_DECLARED_EVENT_TYPE_V1,
    MAX_FALLBACK_POLICY_BYTES_V1, MAX_FALLBACK_ROLES_V1,
};
use pos_crypto::plugin_execution::{DeterministicBudgetV1, PluginCapabilityDescriptorV1};
use pos_plugin_publisher::test_support::{world::World as SignedWorld, BoxResult};
use pos_plugin_supervisor::pass_harness::StoreKind;
use pos_plugin_supervisor::test_support::DriverPlugin;
use pos_runtime::composition_fallback::{
    declare_composition_fallback_v1, required_plugin_v1, COMPOSITION_FALLBACK_DECLARE_GRANT_V1,
};
use pos_runtime::{
    FallbackCandidateFactsV1, FallbackDeclarationV1, FallbackDeclareErrorV1,
    FallbackDriverSettingsV1, FallbackEntryFactsV1, FallbackExecutionFactsV1, FallbackHostFactsV1,
    FallbackHostGrantsV1, PluginExecutionModeV1, ProjectionKey, RequiredPluginCompositionV1,
};
use pos_store::composition_fallback_registry::{
    CompositionFallbackRegistryErrorV1, CompositionFallbackRegistryV1, CompositionFallbackTargetV1,
    FallbackActivateRequestV1, FallbackCommitReceiptV1,
};
use pos_store::memory::MemoryStore;
use pos_store::sqlite::SqliteStore;
use tempfile::TempDir;

use crate::authority::{reserved_claims_of, reserved_proposal_of, ReservedProposal};
use crate::harness::Capture;
use crate::parity::{on_every_store, StoreCapture};
use crate::support::lane::{publish, ALPHA};

/// The composition scope of every declaration.
const SCOPE: &str = "pch1.fallback";
/// The one declared entry.
const ENTRY: &str = "forecast";
/// The role every implementation's pin holds.
const ROLE: &str = "forecaster";
/// The Event type every implementation owns.
const OWNED: &str = "acme.forecast.v1";
/// The Driver interval every implementation shares.
const INTERVAL: Duration = Duration::from_millis(100);
/// The Stable passing-profile digest the host supplies for every release (rule 7).
const STABLE: Hash = Hash::from_bytes([0x5a; 32]);
/// A newer profile version's digest, which does not satisfy [`STABLE`].
const NEWER: Hash = Hash::from_bytes([0x5b; 32]);
/// The publisher the host names for every release.
const PUBLISHER: &str = "acme";
/// The PMF1 fuel limit of every release; a candidate over it breaks rule 4.
const FUEL: u64 = 1_000;

/// What one implementation looks like to the facts-only registration path.
#[derive(Clone, Copy)]
struct Shape {
    plugin_id: &'static str,
    release: u8,
    version: &'static str,
    role: &'static str,
    owned: &'static str,
    interval: Duration,
    subscribed: bool,
}

/// The declared primary.
const PRIMARY: Shape = Shape {
    plugin_id: "acme.primary",
    release: 1,
    version: "0.1.0",
    role: ROLE,
    owned: OWNED,
    interval: INTERVAL,
    subscribed: false,
};
/// The first candidate.
const CANDIDATE: Shape = Shape {
    plugin_id: "acme.candidate",
    release: 2,
    ..PRIMARY
};
/// The candidate a re-base declares after the first candidate is promoted.
const NEXT: Shape = Shape {
    plugin_id: "acme.next",
    release: 3,
    ..PRIMARY
};

/// One implementation: its run-local Plugin ID and its facts.
#[derive(Clone)]
struct Member {
    id: PluginId,
    facts: FallbackCandidateFactsV1,
}

impl Member {
    fn key(&self) -> ImplementationKeyV1 {
        self.facts.pin.implementation().clone()
    }
}

/// The host-supplied PMF1 facts of `pin`'s release.
fn execution(pin: &CompositionPinV1) -> FallbackExecutionFactsV1 {
    let key = pin.implementation();
    FallbackExecutionFactsV1 {
        plugin_id: key.plugin_id().to_owned(),
        release_digest: key.release_digest(),
        capabilities: Vec::new(),
        budget: DeterministicBudgetV1 {
            fuel: FUEL,
            ..DeterministicBudgetV1::MAXIMA
        },
    }
}

/// The trusted host's facts of `pin`'s release: admitted, one publisher, Stable conformance.
fn host(pin: &CompositionPinV1) -> FallbackHostFactsV1 {
    FallbackHostFactsV1 {
        active_release_digest: Some(pin.implementation().release_digest()),
        publisher: Some(PUBLISHER.to_owned()),
        namespace_grants: Vec::new(),
        conformance_profiles: BTreeSet::from([STABLE]),
    }
}

/// The Driver settings of `shape`.
fn settings(shape: Shape) -> FallbackDriverSettingsV1 {
    let subscription = ProjectionKey::new(EntityId::new());
    let subscriptions = if shape.subscribed {
        vec![subscription]
    } else {
        Vec::new()
    };
    FallbackDriverSettingsV1 {
        tick_interval: shape.interval,
        subscriptions,
    }
}

/// The member of `shape` under the run-local `id`.
///
/// # Errors
/// Returns the record error of its key or pin, or the facts-only registration's refusal.
fn member(shape: Shape, id: PluginId) -> BoxResult<Member> {
    let release = Hash::from_bytes([shape.release; 32]);
    let (plugin_id, version) = (shape.plugin_id.to_owned(), shape.version.to_owned());
    let key = ImplementationKeyV1::new(plugin_id, version, release)?;
    let pin = CompositionPinV1::new(key, vec![shape.role.to_owned()])?;
    let plugin = DriverPlugin {
        id,
        name: shape.plugin_id,
        event_type: shape.owned,
        has_driver: true,
    };
    let (execution, host) = (execution(&pin), host(&pin));
    let facts = FallbackCandidateFactsV1::collect(&plugin, pin, settings(shape), execution, host)?;
    Ok(Member { id, facts })
}

/// The effective required composition whose one Plugin is `primary`'s derived requirement.
///
/// # Errors
/// Returns the closed composition metadata error.
fn composition_of(primary: &Member) -> BoxResult<RequiredPluginCompositionV1> {
    let required = required_plugin_v1(primary.id, &primary.facts.pin)?;
    let mode = PluginExecutionModeV1::Local;
    Ok(RequiredPluginCompositionV1::try_new(mode, vec![required])?)
}

/// One declared entry: its primary, its candidates and the implementation the registry runs.
#[derive(Clone)]
struct EntryPlan {
    primary: Member,
    candidates: Vec<Member>,
    running: ImplementationKeyV1,
}

impl EntryPlan {
    /// The entry of `primary` and `candidates`, while the registry runs `primary`.
    fn of(primary: &Member, candidates: &[&Member]) -> Self {
        Self {
            primary: primary.clone(),
            candidates: candidates.iter().copied().cloned().collect(),
            running: primary.key(),
        }
    }

    fn entry(&self) -> BoxResult<FallbackEntryV1> {
        let pins = self
            .candidates
            .iter()
            .map(|member| member.facts.pin.clone());
        let pins = pins.collect();
        let triggers = vec![FallbackTriggerCodeV1::ResourceLimit];
        let mode = FallbackActivationModeV1::Automatic;
        let (key, primary) = (ENTRY.to_owned(), self.primary.facts.pin.clone());
        Ok(FallbackEntryV1::new(key, primary, pins, triggers, mode)?)
    }

    fn facts(&self) -> (String, FallbackEntryFactsV1) {
        let candidates = self.candidates.iter().map(|member| member.facts.clone());
        let facts = FallbackEntryFactsV1 {
            primary: self.primary.facts.clone(),
            candidates: candidates.collect(),
        };
        (ENTRY.to_owned(), facts)
    }
}

/// One declaration: its entries, its predecessor and the effective composition.
struct Plan {
    entries: Vec<EntryPlan>,
    previous: Option<Hash>,
    composition: RequiredPluginCompositionV1,
}

impl Plan {
    /// The one-entry plan of `entry`, whose primary the composition holds.
    fn single(entry: EntryPlan, previous: Option<Hash>) -> BoxResult<Self> {
        let composition = composition_of(&entry.primary)?;
        Ok(Self {
            entries: vec![entry],
            previous,
            composition,
        })
    }

    /// The withdrawal of the policy `previous`, over `composition`.
    const fn withdrawal(previous: Hash, composition: RequiredPluginCompositionV1) -> Self {
        Self {
            entries: Vec::new(),
            previous: Some(previous),
            composition,
        }
    }

    fn policy(&self) -> BoxResult<DomainFallbackPolicyV1> {
        let entries = self.entries.iter().map(EntryPlan::entry);
        let entries = entries.collect::<BoxResult<Vec<_>>>()?;
        let scope = SCOPE.to_owned();
        Ok(DomainFallbackPolicyV1::new(scope, entries, self.previous)?)
    }
}

/// A store that hosts the composition fallback registry, and how a case opens one.
trait FallbackStore: CompositionFallbackRegistryV1 + EventStore + Sized {
    /// A fresh store with an open erasure gate, and the directory that keeps it alive.
    fn fresh() -> BoxResult<(Self, Option<TempDir>)>;
}

impl FallbackStore for MemoryStore {
    fn fresh() -> BoxResult<(Self, Option<TempDir>)> {
        Ok((Self::new(), None))
    }
}

impl FallbackStore for SqliteStore {
    fn fresh() -> BoxResult<(Self, Option<TempDir>)> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("composition-fallback.db");
        let path = path.to_str().ok_or("the temporary path is not UTF-8")?;
        Ok((Self::open(path)?, Some(directory)))
    }
}

/// A provisioned store, the stepped Timeline that is also the declaration target, the host
/// entity, and the declare grant.
struct Scenario<S> {
    store: S,
    _directory: Option<TempDir>,
    timeline: TimelineId,
    entity: EntityId,
    grants: FallbackHostGrantsV1,
}

type Declared = Result<FallbackCommitReceiptV1, FallbackDeclareErrorV1>;

impl<S: FallbackStore> Scenario<S> {
    fn open() -> BoxResult<Self> {
        let (mut store, directory) = S::fresh()?;
        store.bind_erasure_gate(Arc::new(ErasureContainmentGateV1::new_test_open()))?;
        store.provision_fallback_registry()?;
        let timeline = store.create_timeline("composition")?.id();
        let grant = COMPOSITION_FALLBACK_DECLARE_GRANT_V1.to_owned();
        Ok(Self {
            store,
            _directory: directory,
            timeline,
            entity: EntityId::new(),
            grants: FallbackHostGrantsV1 {
                grants: BTreeSet::from([grant]),
            },
        })
    }

    const fn target(&self) -> CompositionFallbackTargetV1 {
        CompositionFallbackTargetV1 {
            timeline: self.timeline,
            entity: self.entity,
        }
    }

    fn revision(&self) -> BoxResult<u64> {
        let row = self.store.registry_row(SCOPE, self.timeline)?;
        Ok(row.map_or(0, |row| row.state().state_revision()))
    }

    fn head(&self) -> BoxResult<Seq> {
        Ok(self.store.logical_head(self.timeline)?)
    }

    /// The declaration of `plan` at the current revision and head.
    fn declaration(&self, plan: &Plan) -> BoxResult<FallbackDeclarationV1> {
        let policy = plan.policy()?;
        let effective = plan.entries.iter().map(|entry| {
            let running = entry.running.clone();
            (ENTRY.to_owned(), running)
        });
        Ok(FallbackDeclarationV1 {
            scope: SCOPE.to_owned(),
            target: self.target(),
            stepped_timeline: self.timeline,
            expected_state_revision: self.revision()?,
            expected_logical_head: self.head()?,
            policy_bytes: policy.to_canonical_cbor(),
            composition: plan.composition.clone(),
            effective: effective.collect(),
            facts: plan.entries.iter().map(EntryPlan::facts).collect(),
        })
    }

    fn declare(&mut self, declaration: &FallbackDeclarationV1) -> Declared {
        declare_composition_fallback_v1(&mut self.store, &self.grants, declaration)
    }

    /// The outcome of `declaration`, as `Committed`, `IdempotentReplay` or its refusal.
    fn outcome(&mut self, declaration: &FallbackDeclarationV1) -> String {
        let declared = self.declare(declaration);
        declared.map_or_else(|error| refusal(&error), |receipt| outcome(&receipt))
    }

    /// The automatic activation of the entry from `from` to `to`, closing `closing`.
    fn activate(
        &mut self,
        closing: u64,
        from: &Member,
        to: &Member,
    ) -> BoxResult<Result<FallbackCommitReceiptV1, CompositionFallbackRegistryErrorV1>> {
        let request = FallbackActivateRequestV1 {
            scope: SCOPE.to_owned(),
            target: self.target(),
            expected_state_revision: self.revision()?,
            expected_logical_head: self.head()?,
            entry_key: ENTRY.to_owned(),
            closing_tenure_ordinal: closing,
            from: from.key(),
            to: to.key(),
            trigger_code: FallbackTriggerCodeV1::ResourceLimit,
            trigger_basis: FallbackTriggerBasisV1 {
                cause: 16,
                origin: FallbackActivationOriginV1::Automatic,
            },
            skipped: Vec::new(),
            tick: 1,
        };
        Ok(self.store.activate(&request))
    }

    /// The entry's recorded `tenure/chain-position/effective`, naming the effective member.
    fn entry_state(&self, members: &[(&str, &Member)]) -> BoxResult<String> {
        let row = self.store.registry_row(SCOPE, self.timeline)?;
        let row = row.ok_or("no registry row")?;
        let entry = row
            .state()
            .entries()
            .get(ENTRY)
            .ok_or("no recorded entry")?;
        let digest = entry.effective_digest();
        let named = members
            .iter()
            .find(|(_, member)| member.key().digest() == digest);
        let name = named.map_or("unknown", |(name, _)| *name);
        let (tenure, chain) = (entry.tenure_ordinal(), entry.chain_position());
        Ok(format!("{tenure}/{chain}/{name}"))
    }
}

/// The name of a committed declaration's outcome.
fn outcome(receipt: &FallbackCommitReceiptV1) -> String {
    format!("{:?}", receipt.outcome())
}

/// The typed refusal of the runtime `declare`, without entry keys or Plugin IDs.
fn refusal(error: &FallbackDeclareErrorV1) -> String {
    match error {
        FallbackDeclareErrorV1::InvalidPolicy(invalid) => {
            format!("InvalidFallbackPolicy({:?})", invalid.field)
        }
        FallbackDeclareErrorV1::FactsMismatch { .. } => "FactsMismatch".to_owned(),
        other => format!("{other:?}"),
    }
}

/// The outcome of an activation request.
fn activation(
    activated: Result<FallbackCommitReceiptV1, CompositionFallbackRegistryErrorV1>,
) -> String {
    activated.map_or_else(|error| format!("{error:?}"), |receipt| outcome(&receipt))
}

/// One candidate-side change that breaks one section 4.1 rule, and its capture key.
struct Variant {
    key: &'static str,
    candidate: Shape,
    same_id: bool,
    foreign_composition: bool,
    edit: fn(&mut FallbackCandidateFactsV1),
}

const fn unchanged(_: &mut FallbackCandidateFactsV1) {}

/// The variant that breaks nothing.
const VALID: Variant = Variant {
    key: "rule.none",
    candidate: CANDIDATE,
    same_id: false,
    foreign_composition: false,
    edit: unchanged,
};

/// A capability descriptor the primary does not hold.
fn extra_capability() -> PluginCapabilityDescriptorV1 {
    PluginCapabilityDescriptorV1 {
        capability_id: "forecast.read".to_owned(),
        operation: "read".to_owned(),
        resource_pattern: "forecast/*".to_owned(),
        purpose: "forecast".to_owned(),
        audience: "local".to_owned(),
        required: false,
        max_calls: 1,
        max_request_bytes: 64,
        max_response_bytes: 64,
    }
}

/// One variant for each section 4.1 rule a case can break through public facts. The schema,
/// output-policy, profile and configuration-digest checks are not reachable through the
/// facts-only path with one Plugin type; the slice-3 unit tests cover them.
const RULES: [Variant; 13] = [
    Variant {
        key: "rule.identity",
        edit: |facts| facts.execution.plugin_id = "acme.elsewhere".to_owned(),
        ..VALID
    },
    Variant {
        key: "rule.roles",
        candidate: Shape {
            role: "other",
            ..CANDIDATE
        },
        ..VALID
    },
    Variant {
        key: "rule.distinctness",
        same_id: true,
        ..VALID
    },
    Variant {
        key: "rule.version",
        candidate: Shape {
            version: "9.9.9",
            ..CANDIDATE
        },
        ..VALID
    },
    Variant {
        key: "rule.composition",
        foreign_composition: true,
        ..VALID
    },
    Variant {
        key: "rule.event-types",
        candidate: Shape {
            owned: "acme.other.v1",
            ..CANDIDATE
        },
        ..VALID
    },
    Variant {
        key: "rule.namespace",
        edit: |facts| facts.host.publisher = Some("other".to_owned()),
        ..VALID
    },
    Variant {
        key: "rule.capabilities",
        edit: |facts| facts.execution.capabilities = vec![extra_capability()],
        ..VALID
    },
    Variant {
        key: "rule.subscriptions",
        candidate: Shape {
            subscribed: true,
            ..CANDIDATE
        },
        ..VALID
    },
    Variant {
        key: "rule.budgets",
        edit: |facts| facts.execution.budget.fuel = FUEL + 1,
        ..VALID
    },
    Variant {
        key: "rule.driver-interval",
        candidate: Shape {
            interval: Duration::from_millis(200),
            ..CANDIDATE
        },
        ..VALID
    },
    Variant {
        key: "rule.admission",
        edit: |facts| facts.host.active_release_digest = None,
        ..VALID
    },
    Variant {
        key: "rule.conformance",
        edit: |facts| facts.host.conformance_profiles = BTreeSet::from([NEWER]),
        ..VALID
    },
];

/// The one-entry first declaration of `primary` and the candidate `variant` builds.
fn rule_plan(primary: &Member, variant: &Variant) -> BoxResult<Plan> {
    let id = if variant.same_id {
        primary.id
    } else {
        PluginId::new()
    };
    let mut candidate = member(variant.candidate, id)?;
    (variant.edit)(&mut candidate.facts);
    let mut plan = Plan::single(EntryPlan::of(primary, &[&candidate]), None)?;
    if variant.foreign_composition {
        let stranger = member(PRIMARY, PluginId::new())?;
        plan.composition = composition_of(&stranger)?;
    }
    Ok(plan)
}

/// The record refusal of a pin with one role more than PPN1 allows.
fn oversized_pin() -> BoxResult<String> {
    let key = ImplementationKeyV1::new(
        PRIMARY.plugin_id.to_owned(),
        PRIMARY.version.to_owned(),
        Hash::from_bytes([PRIMARY.release; 32]),
    )?;
    let roles = (0..=MAX_FALLBACK_ROLES_V1).map(|role| format!("role-{role}"));
    let pin = CompositionPinV1::new(key, roles.collect());
    Ok(pin.map_or_else(|error| format!("{error:?}"), |_| "accepted".to_owned()))
}

/// A second primary whose Plugin ID text has the length of [`PRIMARY`]'s.
const TWIN_TEXT: &str = "acme.primarz";

/// `bytes` with the first occurrence of `from` replaced by the equally long `to`.
fn renamed(mut bytes: Vec<u8>, from: &str, to: &str) -> Vec<u8> {
    let at = bytes
        .windows(from.len())
        .position(|window| window == from.as_bytes());
    if let Some(at) = at {
        bytes[at..at + to.len()].copy_from_slice(to.as_bytes());
    }
    bytes
}

/// DFP1 bytes whose second entry's primary repeats the first entry's Plugin ID text.
///
/// The record rules refuse the repeat before the digest is checked, so the stale digest the
/// substitution leaves is never reached.
fn repeated_plugin_id_bytes(primary: &Member, candidate: &Member) -> BoxResult<Vec<u8>> {
    let first = EntryPlan::of(primary, &[candidate]).entry()?;
    let twin_shape = Shape {
        plugin_id: TWIN_TEXT,
        release: 4,
        ..PRIMARY
    };
    let twin = member(twin_shape, PluginId::new())?;
    let next = member(NEXT, PluginId::new())?;
    let (triggers, mode) = (first.triggers().to_vec(), first.activation_mode());
    let pins = vec![next.facts.pin];
    let key = format!("{ENTRY}-2");
    let second = FallbackEntryV1::new(key, twin.facts.pin, pins, triggers, mode)?;
    let scope = SCOPE.to_owned();
    let policy = DomainFallbackPolicyV1::new(scope, vec![first, second], None)?;
    Ok(renamed(
        policy.to_canonical_cbor(),
        TWIN_TEXT,
        PRIMARY.plugin_id,
    ))
}

/// PCF-CPH-016: every declaration refusal of ADR-119 section 6 case 4.
#[must_use]
pub fn declaration_refusals() -> Capture {
    on_every_store(|kind, capture| match kind {
        StoreKind::Memory => refusals::<MemoryStore>(capture),
        StoreKind::Sqlite => refusals::<SqliteStore>(capture),
    })
}

fn refusals<S: FallbackStore>(capture: &mut StoreCapture<'_>) -> BoxResult<()> {
    let mut scenario = Scenario::<S>::open()?;
    let primary = member(PRIMARY, PluginId::new())?;
    let candidate = member(CANDIDATE, PluginId::new())?;
    let next = member(NEXT, PluginId::new())?;
    for variant in &RULES {
        let declaration = scenario.declaration(&rule_plan(&primary, variant)?)?;
        capture.record(variant.key, scenario.outcome(&declaration));
    }
    capture.record("record.oversized-pin", oversized_pin()?);
    record_refusals(&mut scenario, capture, &primary, &candidate)?;
    let plan = Plan::single(EntryPlan::of(&primary, &[&candidate]), None)?;
    let valid = scenario.declaration(&plan)?;
    let first = scenario.declare(&valid)?;
    capture.record("first.outcome", outcome(&first));
    let retry = scenario.outcome(&valid);
    capture.record("retry-after-indeterminate-commit.outcome", retry);
    let first_digest = Some(first.row().policy_digest());
    let unchained = Plan::single(EntryPlan::of(&primary, &[&next]), None)?;
    let unchained = scenario.declaration(&unchained)?;
    capture.record("stale-policy", scenario.outcome(&unchained));
    let successor = Plan::single(EntryPlan::of(&primary, &[&next]), first_digest)?;
    let mut other_entity = scenario.declaration(&successor)?;
    other_entity.target.entity = EntityId::new();
    capture.record("entity-mismatch", scenario.outcome(&other_entity));
    let activated = scenario.activate(0, &primary, &candidate)?;
    capture.record("activation.outcome", activation(activated));
    let mut truthful = EntryPlan::of(&primary, &[&next]);
    truthful.running = candidate.key();
    let truthful = Plan::single(truthful, first_digest)?;
    let truthful = scenario.declaration(&truthful)?;
    let runtime = scenario.outcome(&truthful);
    capture.record("primary-not-effective.candidate-tenure.runtime", runtime);
    let stale_host = scenario.declaration(&successor)?;
    let port = scenario.outcome(&stale_host);
    capture.record("primary-not-effective.candidate-tenure.port", port);
    Ok(())
}

/// The refusals that precede the first commit: record bounds, the grant, the stepped
/// Timeline, a tenure-0 primary that is not the base implementation and an empty first policy.
fn record_refusals<S: FallbackStore>(
    scenario: &mut Scenario<S>,
    capture: &mut StoreCapture<'_>,
    primary: &Member,
    candidate: &Member,
) -> BoxResult<()> {
    let plan = Plan::single(EntryPlan::of(primary, &[candidate]), None)?;
    let valid = scenario.declaration(&plan)?;
    let mut declaration = valid.clone();
    declaration.policy_bytes = vec![0; MAX_FALLBACK_POLICY_BYTES_V1 + 1];
    capture.record("record.oversized-policy", scenario.outcome(&declaration));
    declaration.policy_bytes = repeated_plugin_id_bytes(primary, candidate)?;
    capture.record("record.repeated-plugin-id", scenario.outcome(&declaration));
    let grants = std::mem::take(&mut scenario.grants);
    capture.record("not-granted", scenario.outcome(&valid));
    scenario.grants = grants;
    let mut declaration = valid.clone();
    declaration.stepped_timeline = TimelineId::new();
    capture.record("target-not-stepped", scenario.outcome(&declaration));
    let mut declaration = valid.clone();
    declaration
        .effective
        .insert(ENTRY.to_owned(), candidate.key());
    let tenure_zero = scenario.outcome(&declaration);
    capture.record("primary-not-effective.tenure-zero", tenure_zero);
    let empty = DomainFallbackPolicyV1::new(SCOPE.to_owned(), Vec::new(), None)?;
    let mut declaration = valid;
    declaration.policy_bytes = empty.to_canonical_cbor();
    capture.record("empty-first-policy", scenario.outcome(&declaration));
    let row = scenario.store.registry_row(SCOPE, scenario.timeline)?;
    capture.record("refusals.registry-unchanged", row.is_none());
    Ok(())
}

/// PCF-CPH-017: the ADR-119 reserved Event types (ADR-119 section 6 case 5).
///
/// For each type, a first-party draft and a community draft through the probe guest's selector
/// are refused alike with `ReservedHostDraft`, as PCF-CPH-013 refuses the release-activation
/// type, and a claim of the type by either class is refused before the registry changes.
#[must_use]
pub fn reserved_fallback_types() -> Capture {
    on_every_store(reserved_types)
}

/// The two ADR-119 reserved types, their capture prefixes and their probe selectors.
const RESERVED_TYPES: [ReservedProposal; 2] = [
    ReservedProposal {
        prefix: "declared.",
        emitted: COMPOSITION_FALLBACK_DECLARED_EVENT_TYPE_V1,
        selector: b"fallback-declared",
    },
    ReservedProposal {
        prefix: "activated.",
        emitted: COMPOSITION_FALLBACK_ACTIVATED_EVENT_TYPE_V1,
        selector: b"fallback-activated",
    },
];

fn reserved_types(kind: StoreKind, capture: &mut StoreCapture<'_>) -> BoxResult<()> {
    for reserved in &RESERVED_TYPES {
        reserved_proposal_of(kind, capture, reserved)?;
        let mut signed = SignedWorld::new()?;
        let alpha = publish(&mut signed, ALPHA, 1)?;
        let claims = reserved_claims_of(&signed, &alpha, kind, reserved.emitted)?;
        let (native, community, unchanged) = claims;
        let prefix = reserved.prefix;
        capture.record(&format!("{prefix}claim.first-party.refusal"), native);
        capture.record(&format!("{prefix}claim.community.refusal"), community);
        capture.record(&format!("{prefix}claim.registry-unchanged"), unchanged);
    }
    Ok(())
}

/// PCF-CPH-018: a re-base and a withdrawal declared in a candidate tenure (ADR-119 section 6
/// case 14, declaration part).
///
/// A re-base promotes the effective candidate: its tenure continues with chain position 0, and
/// the new candidate is the next activation's target. A withdrawal in a candidate tenure freezes
/// the effective implementation, after it nothing activates, and the next policy must name the
/// withdrawal's digest as its predecessor.
#[must_use]
pub fn withdrawal_and_rebase() -> Capture {
    on_every_store(|kind, capture| match kind {
        StoreKind::Memory => rebase::<MemoryStore>(capture),
        StoreKind::Sqlite => rebase::<SqliteStore>(capture),
    })
}

fn rebase<S: FallbackStore>(capture: &mut StoreCapture<'_>) -> BoxResult<()> {
    let mut scenario = Scenario::<S>::open()?;
    let primary = member(PRIMARY, PluginId::new())?;
    let candidate = member(CANDIDATE, PluginId::new())?;
    let next = member(NEXT, PluginId::new())?;
    let named = [
        ("primary", &primary),
        ("candidate", &candidate),
        ("next", &next),
    ];
    let first = Plan::single(EntryPlan::of(&primary, &[&candidate]), None)?;
    let first = scenario.declare(&scenario.declaration(&first)?)?;
    capture.record("first.outcome", outcome(&first));
    let activated = scenario.activate(0, &primary, &candidate)?;
    capture.record("activation.outcome", activation(activated));
    capture.record("activation.entry", scenario.entry_state(&named)?);
    let previous = Some(first.row().policy_digest());
    let promoted = Plan::single(EntryPlan::of(&candidate, &[&next]), previous)?;
    let rebased = scenario.declare(&scenario.declaration(&promoted)?)?;
    capture.record("rebase.outcome", outcome(&rebased));
    capture.record("rebase.entry", scenario.entry_state(&named)?);
    let continued = scenario.activate(1, &candidate, &next)?;
    capture.record("rebase.next-activation.outcome", activation(continued));
    capture.record(
        "rebase.next-activation.entry",
        scenario.entry_state(&named)?,
    );
    let rebased_digest = rebased.row().policy_digest();
    let composition = composition_of(&next)?;
    let withdrawal = Plan::withdrawal(rebased_digest, composition);
    let withdrawn = scenario.declare(&scenario.declaration(&withdrawal)?)?;
    capture.record("withdrawal.outcome", outcome(&withdrawn));
    capture.record("withdrawal.entry", scenario.entry_state(&named)?);
    let after = scenario.activate(2, &next, &primary)?;
    capture.record("withdrawal.activation", activation(after));
    let stale = Plan::single(EntryPlan::of(&next, &[&primary]), Some(rebased_digest))?;
    let stale = scenario.declaration(&stale)?;
    capture.record("successor.naming-the-rebase", scenario.outcome(&stale));
    let withdrawn_digest = Some(withdrawn.row().policy_digest());
    let successor = Plan::single(EntryPlan::of(&next, &[&primary]), withdrawn_digest)?;
    let successor = scenario.declaration(&successor)?;
    capture.record(
        "successor.naming-the-withdrawal",
        scenario.outcome(&successor),
    );
    capture.record("successor.entry", scenario.entry_state(&named)?);
    Ok(())
}
