//! The sub-case interpreter and its port (ADR-061 revision 8 decisions 2, 3 and 8).
//!
//! [`interpret()`] runs the steps of one sub-case on a [`StepPortV1`]: the step dispatch
//! (`install`, `bind`, `refresh`, `pass`, `scan`), the carry of the Driver's state across
//! passes (the port keeps it), the stop at the first step that refuses or does not commit, the
//! `compute` of a `digest` expectation, and the comparison of the sub-case result with `expect`.
//! The port is a trait with one method per step so that the interpreter has a pure fake in its
//! tests; the real port, [`crate::runner::EvaluationStepPortV1`], is a logic-free adapter over
//! the S1c2 world.
//!
//! The sub-case result is the outcome of the first step that refuses or fails, otherwise the
//! outcome of the last `pass`; `steps_run` counts the refusing step; `index` comes from the
//! setup refusal only. Every digest of the payload is resolved, and every release source and
//! trust material is built, before the first step runs ([`PreparedV1::build()`]); a failure
//! there is `payload-invalid` and the sub-case does not run.

use std::collections::{BTreeMap, BTreeSet};

use pos_plugin_release::{
    BundleAddressV1, ContentValidationV1, InMemoryReleaseEntryV1, InMemoryReleaseSourceV1,
};
use pos_plugin_supervisor::{CommunityPluginSubjectOutcomeV1, CommunityPluginSubjectResultV1};
use pos_reference::evaluator::ResourceUsage;
use pos_runtime::community_plugin_host::{
    cbor, profile_digest_of, CeilingValuesV1, CommunityPluginHostErrorV1, CommunityPluginModeV1,
    CommunityPluginTrustMaterialV1, MeteringV1, PinnedComponentRuntimeV1, PinnedEngineConfigV1,
    ReleaseIdentityV1, TrapTableEntryV1,
};

use crate::composite::{decode_anchor, PiecesV1};
use crate::hex;
use crate::map::{of_outcome, of_record, SubResultV1};
pub use crate::payload::ScanSource;
use crate::payload::{
    AtV1, ComputeV1, ExpectV1, Hex32, IdentityFieldV1, InvalidCaseV1, MaterialV1, MemberV1,
    ProfileDigestV1, ReleaseV1, StepV1, SubCaseV1, Text,
};

/// The closed host error of a step.
pub type HostError = CommunityPluginHostErrorV1;

/// The result of one sub-case.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SubCaseRecordV1 {
    /// The sub-case ID.
    pub id: String,
    /// The steps that ran, the refusing step included.
    pub steps_run: u32,
    /// The outcome of each `pass` step that ran, in step order.
    pub outcomes: Vec<CommunityPluginSubjectOutcomeV1>,
    /// The refusal of the step that failed in setup (install, gate, Driver build), if any.
    pub setup_refusal: Option<CommunityPluginHostErrorV1>,
    /// The result of the `scan` step, if it ran.
    pub scan: Option<ScanResultV1>,
    /// The value of the `digest` expectation's `compute`, if it exists.
    pub computed: Option<[u8; 32]>,
    /// The output digest when the sub-result is `committed`.
    pub committed: Option<[u8; 32]>,
    /// The usage of the sub-case: zero unless it committed.
    pub usage: ResourceUsage,
    /// The worker launches of the passes: the count of outcomes that carry an execution profile
    /// digest. A proxy (decision 2 lists the field only): a Driver records the digest only
    /// after it reached the launch. Verified by `r8_s9_*` in
    /// `apps/pos-plugin-worker/tests/conformance_adapter_public.rs`.
    pub worker_launches: u32,
    /// Whether the sub-result equals `expect`.
    pub matched: bool,
}

impl SubCaseRecordV1 {
    /// The record of sub-case `id` before any step: nothing ran and nothing matched.
    #[must_use]
    pub fn empty(id: &str) -> Self {
        Self {
            id: id.to_owned(),
            steps_run: 0,
            outcomes: Vec::new(),
            setup_refusal: None,
            scan: None,
            computed: None,
            committed: None,
            usage: ResourceUsage::default(),
            worker_launches: 0,
            matched: false,
        }
    }
}

/// What a `scan` step found.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScanResultV1 {
    /// The sources that hold the marker, in the order Events, State, Outcome.
    pub found: Vec<ScanSource>,
    /// Whether the payload's retained metadata equals the observed Plugin ID and invocation ID.
    pub retained_ok: bool,
    /// The Plugin ID of the most recent `bind` step, or empty.
    pub observed_plugin_id: String,
    /// The invocation ID of the last `pass` step as hexadecimal, or empty.
    pub observed_invocation_id_hex: String,
}

/// What opens the world of a sub-case.
#[derive(Clone, Debug)]
pub struct SetupArgsV1 {
    /// Every release of the sub-case, or `None` when it names none.
    pub source: Option<InMemoryReleaseSourceV1>,
    /// The first non-null trust material of any step: the registry is provisioned from it.
    /// With none the world does not open: `TrustStateUnavailable`, `steps_run` 0.
    pub genesis: Option<CommunityPluginTrustMaterialV1>,
    /// The Execution Mode of the attempt.
    pub mode: CommunityPluginModeV1,
}

/// The `install` step.
#[derive(Clone, Debug)]
pub struct InstallArgsV1 {
    pub address: BundleAddressV1,
    pub material: Option<CommunityPluginTrustMaterialV1>,
    pub instant_micros: u64,
    pub tick: u64,
}

/// The `bind` step.
#[derive(Clone, Debug)]
pub struct BindArgsV1 {
    pub address: BundleAddressV1,
    pub material: Option<CommunityPluginTrustMaterialV1>,
    pub plugin_id: String,
    pub instant_micros: u64,
    pub tick: u64,
    pub initial_state_schema: [u8; 32],
    pub initial_state_bytes: Vec<u8>,
    pub event_type: String,
}

/// The `refresh` step.
#[derive(Clone, Debug)]
pub struct RefreshArgsV1 {
    pub material: Option<CommunityPluginTrustMaterialV1>,
    pub instant_micros: u64,
    pub tick: u64,
}

/// One member of a `pass`: the Plugin and the address the pass reads for it.
#[derive(Clone, Debug)]
pub struct PassMemberV1 {
    pub plugin_id: String,
    pub address: BundleAddressV1,
}

/// The `pass` step. `material` is the material of the most recent `bind` or `refresh`.
#[derive(Clone, Debug)]
pub struct PassArgsV1 {
    pub members: Vec<PassMemberV1>,
    pub material: Option<CommunityPluginTrustMaterialV1>,
    pub instant_micros: u64,
    pub tick: u64,
    pub invocation_id: [u8; 16],
    pub random_domain: [u8; 32],
    pub timeline_seq: u64,
    pub observation: Vec<u8>,
    pub simulation_time: u64,
}

/// The `scan` step.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScanArgsV1 {
    pub marker: String,
    pub sources: BTreeSet<ScanSource>,
    pub retained_plugin_id: String,
    pub retained_invocation_id_hex: String,
}

/// One step with every reference resolved.
#[derive(Clone, Debug)]
pub enum ResolvedStepV1 {
    Install(InstallArgsV1),
    Bind(BindArgsV1),
    Refresh(RefreshArgsV1),
    Pass(PassArgsV1),
    Scan(ScanArgsV1),
}

/// The world a sub-case runs on: one method per step, and the three read-backs of a `scan`.
///
/// A refusal is the closed host error of the step. The port keeps the Driver's committed state
/// across passes and reports the identity of the release that `bind` gated.
pub trait StepPortV1 {
    /// Open a fresh world for one sub-case.
    ///
    /// # Errors
    /// Returns the refusal of the world, which is the sub-case's setup refusal.
    fn open(&mut self, setup: SetupArgsV1) -> Result<(), CommunityPluginHostErrorV1>;

    /// `install_community_release_v1`.
    ///
    /// # Errors
    /// Returns the install refusal as a host error.
    fn install(&mut self, args: &InstallArgsV1) -> Result<(), CommunityPluginHostErrorV1>;

    /// `gate_for_driver`, then build and register the Driver; the identity of the gated release.
    ///
    /// # Errors
    /// Returns the gate or Driver build refusal.
    fn bind(&mut self, args: &BindArgsV1) -> Result<ReleaseIdentityV1, CommunityPluginHostErrorV1>;

    /// `refresh_policy`.
    ///
    /// # Errors
    /// Returns the registry refusal as a host error.
    fn refresh(&mut self, args: &RefreshArgsV1) -> Result<(), CommunityPluginHostErrorV1>;

    /// One `run_pass`: the outcome record of each member.
    ///
    /// # Errors
    /// Returns a host error when the pass could not run at all.
    fn pass(
        &mut self,
        args: &PassArgsV1,
    ) -> Result<Vec<CommunityPluginSubjectOutcomeV1>, CommunityPluginHostErrorV1>;

    /// The payload bytes of every committed Event.
    ///
    /// # Errors
    /// Returns a host error when the store cannot be read.
    fn committed_event_payloads(&mut self) -> Result<Vec<Vec<u8>>, CommunityPluginHostErrorV1>;

    /// The Driver's committed state bytes.
    fn committed_state(&mut self) -> Vec<u8>;

    /// The canonical bytes ([`outcome_bytes_of()`]) of the outcome records of the last pass.
    fn outcome_bytes(&self) -> Vec<u8>;
}

/// The canonical bytes of the outcome record.
///
/// It is the deterministic CBOR array `["POB1", 1,
/// plugin_id, pmf1_digest, release_digest, tps1_digest, execution_profile_digest, tick, mode,
/// content_validation, result]` (ADR-061 revision 8 decision 2).
#[must_use]
pub fn outcome_bytes_of(outcome: &CommunityPluginSubjectOutcomeV1) -> Vec<u8> {
    let mut out = Vec::new();
    cbor::array(&mut out, 11);
    cbor::text(&mut out, "POB1");
    cbor::unsigned(&mut out, 1);
    cbor::text(&mut out, &outcome.plugin_id);
    for digest in [
        outcome.pmf1_digest,
        outcome.release_digest,
        outcome.tps1_digest,
        outcome.execution_profile_digest,
    ] {
        optional_digest(&mut out, digest);
    }
    cbor::unsigned(&mut out, outcome.tick);
    cbor::unsigned(&mut out, mode_code(outcome.mode));
    cbor::unsigned(&mut out, validation_code(outcome.content_validation));
    result_bytes(&mut out, outcome.result);
    out
}

/// The CBOR null.
const NULL: u8 = 0xf6;

/// The wire code of an Execution Mode: 0 Local, 1 Air-Gapped.
const fn mode_code(mode: CommunityPluginModeV1) -> u64 {
    match mode {
        CommunityPluginModeV1::Local => 0,
        CommunityPluginModeV1::AirGapped => 1,
    }
}

/// The wire code of the content validation: 0 `NotPerformed`.
const fn validation_code(validation: ContentValidationV1) -> u64 {
    match validation {
        ContentValidationV1::NotPerformed => 0,
    }
}

/// A 32-byte digest, or null.
fn optional_digest(out: &mut Vec<u8>, digest: Option<[u8; 32]>) {
    match digest {
        Some(digest) => cbor::bytes(out, &digest),
        None => out.push(NULL),
    }
}

/// `[name, output_digest, metering]` of a `Staged` or `Committed` result.
fn settled_bytes(
    out: &mut Vec<u8>,
    name: &str,
    output_digest: Option<[u8; 32]>,
    metering: Option<MeteringV1>,
) {
    cbor::array(out, 3);
    cbor::text(out, name);
    optional_digest(out, output_digest);
    match metering {
        Some(metering) => {
            cbor::array(out, 4);
            for counter in [
                metering.startup_fuel,
                metering.call_fuel,
                metering.memory_bytes,
                metering.host_calls,
            ] {
                cbor::unsigned(out, counter);
            }
        }
        None => out.push(NULL),
    }
}

/// The `result` member of the outcome record.
fn result_bytes(out: &mut Vec<u8>, result: CommunityPluginSubjectResultV1) {
    match result {
        CommunityPluginSubjectResultV1::Staged {
            output_digest,
            metering,
        } => settled_bytes(out, "Staged", output_digest, metering),
        CommunityPluginSubjectResultV1::Committed {
            output_digest,
            metering,
        } => settled_bytes(out, "Committed", output_digest, metering),
        CommunityPluginSubjectResultV1::Refused {
            error,
            basis,
            class,
        } => {
            cbor::array(out, 4);
            cbor::text(out, "Refused");
            cbor::text(out, error);
            match basis {
                Some(basis) => cbor::text(out, basis),
                None => out.push(NULL),
            }
            cbor::text(out, class);
        }
        CommunityPluginSubjectResultV1::Failed { error, class } => {
            cbor::array(out, 3);
            cbor::text(out, "Failed");
            cbor::text(out, error);
            cbor::text(out, class);
        }
        CommunityPluginSubjectResultV1::NotRun => {
            cbor::array(out, 1);
            cbor::text(out, "NotRun");
        }
        CommunityPluginSubjectResultV1::Discarded => {
            cbor::array(out, 1);
            cbor::text(out, "Discarded");
        }
    }
}

/// A sub-case whose references are resolved and whose objects are built.
#[derive(Clone, Debug)]
pub struct PreparedV1 {
    /// Every release of the sub-case, deduplicated by manifest piece digest.
    pub source: Option<InMemoryReleaseSourceV1>,
    /// The first non-null trust material of the steps.
    pub genesis: Option<CommunityPluginTrustMaterialV1>,
    /// The steps, in order.
    pub steps: Vec<ResolvedStepV1>,
}

impl PreparedV1 {
    /// Resolve every digest of `subcase` against `pieces` and build the release source and the
    /// trust materials.
    ///
    /// # Errors
    /// Returns [`InvalidCaseV1`] for a digest that names no piece (the `nested` digest
    /// included), an undecodable `PCA1` anchor, an error of `from_bytes_v1`, an error of
    /// `InMemoryReleaseEntryV1::from_bytes` or `InMemoryReleaseSourceV1::new`, a `pass` member
    /// without `at` whose Plugin no earlier `bind` named, or a release that cannot be addressed.
    pub fn build(subcase: &SubCaseV1, pieces: &PiecesV1) -> Result<Self, InvalidCaseV1> {
        let mut resolver = Resolver {
            pieces,
            addresses: BTreeMap::new(),
            entries: Vec::new(),
            material: None,
            bound: BTreeMap::new(),
        };
        let steps = subcase
            .steps
            .iter()
            .map(|step| resolver.step(step))
            .collect::<Result<Vec<_>, _>>()?;
        let source = if resolver.entries.is_empty() {
            Ok(None)
        } else {
            InMemoryReleaseSourceV1::new(resolver.entries)
                .map(Some)
                .or(Err(InvalidCaseV1))
        };
        let nested = subcase
            .nested
            .is_none_or(|digest| pieces.get(&digest.0).is_some());
        let genesis = steps.iter().find_map(material_of_step).cloned();
        source.and_then(|source| {
            nested
                .then_some(Self {
                    source,
                    genesis,
                    steps,
                })
                .ok_or(InvalidCaseV1)
        })
    }
}

/// The trust material a step names, if it names one.
const fn material_of_step(step: &ResolvedStepV1) -> Option<&CommunityPluginTrustMaterialV1> {
    match step {
        ResolvedStepV1::Install(args) => args.material.as_ref(),
        ResolvedStepV1::Bind(args) => args.material.as_ref(),
        ResolvedStepV1::Refresh(args) => args.material.as_ref(),
        ResolvedStepV1::Pass(_) | ResolvedStepV1::Scan(_) => None,
    }
}

/// The entry of `release`: its manifest piece and layer pieces.
fn entry_of(release: &ReleaseV1, pieces: &PiecesV1) -> Option<InMemoryReleaseEntryV1> {
    let manifest = pieces.get(&release.manifest.0).map(<[u8]>::to_vec);
    let blobs = collect(&release.blobs, pieces);
    manifest
        .zip(blobs)
        .and_then(|(manifest, blobs)| InMemoryReleaseEntryV1::from_bytes(manifest, blobs).ok())
}

/// The pieces named by `digests`, or `None` when one names no piece.
fn collect(digests: &[Hex32], pieces: &PiecesV1) -> Option<Vec<Vec<u8>>> {
    digests
        .iter()
        .map(|digest| pieces.get(&digest.0).map(<[u8]>::to_vec))
        .collect()
}

/// The trust material of `material`, built from its pieces.
fn build_material(
    material: &MaterialV1,
    pieces: &PiecesV1,
) -> Result<CommunityPluginTrustMaterialV1, InvalidCaseV1> {
    let anchor = pieces.get(&material.anchor.0).and_then(decode_anchor);
    let tps1 = pieces.get(&material.tps1.0).map(<[u8]>::to_vec);
    let roots = collect(&material.ptr1, pieces);
    let revocations = collect(&material.prv1, pieces);
    match (anchor, tps1, roots, revocations) {
        (Some(anchor), Some(tps1), Some(roots), Some(revocations)) => {
            CommunityPluginTrustMaterialV1::from_bytes_v1(&anchor, tps1, roots, revocations)
                .or(Err(InvalidCaseV1))
        }
        _ => Err(InvalidCaseV1),
    }
}

/// The address that holds nothing: a well-formed digest that no release has.
fn nothing_address() -> Result<BundleAddressV1, InvalidCaseV1> {
    BundleAddressV1::new(format!("sha256:{}", "0".repeat(64)), 1).or(Err(InvalidCaseV1))
}

/// Resolves the steps in order, carrying the material and the bound addresses.
struct Resolver<'a> {
    pieces: &'a PiecesV1,
    /// The address of each release by manifest piece digest.
    addresses: BTreeMap<[u8; 32], BundleAddressV1>,
    /// One entry per distinct manifest piece digest, in first-use order.
    entries: Vec<InMemoryReleaseEntryV1>,
    /// The material of the most recent `bind` or `refresh`.
    material: Option<CommunityPluginTrustMaterialV1>,
    /// The address each Plugin's `bind` gated.
    bound: BTreeMap<String, BundleAddressV1>,
}

impl Resolver<'_> {
    /// The address of `release`, building its entry on first use: releases are deduplicated by
    /// their manifest piece digest.
    fn address(&mut self, release: &ReleaseV1) -> Result<BundleAddressV1, InvalidCaseV1> {
        if let Some(address) = self.addresses.get(&release.manifest.0) {
            return Ok(address.clone());
        }
        let entry = entry_of(release, self.pieces).ok_or(InvalidCaseV1)?;
        let address = entry.address().clone();
        self.addresses.insert(release.manifest.0, address.clone());
        self.entries.push(entry);
        Ok(address)
    }

    fn material_of(
        &self,
        material: Option<&MaterialV1>,
    ) -> Result<Option<CommunityPluginTrustMaterialV1>, InvalidCaseV1> {
        material
            .map(|material| build_material(material, self.pieces))
            .transpose()
    }

    /// The member of a pass. Whatever its `at`, its Plugin needs an earlier `bind` step (an
    /// unbound Plugin is `payload-invalid`); `at: absent` is an address that holds nothing.
    fn member(&mut self, member: &MemberV1) -> Result<PassMemberV1, InvalidCaseV1> {
        let plugin_id = member.plugin_id.as_str();
        let bound = self.bound.get(plugin_id).cloned().ok_or(InvalidCaseV1);
        let address = match &member.at {
            None => bound,
            Some(AtV1::Absent(_)) => bound.and_then(|_| nothing_address()),
            Some(AtV1::Release(release)) => bound.and_then(|_| self.address(release)),
        };
        address.map(|address| PassMemberV1 {
            plugin_id: plugin_id.to_owned(),
            address,
        })
    }

    /// Resolve one step. A second `bind` of one Plugin ID is `payload-invalid`; `bind` and
    /// `refresh` set the material that later passes use.
    fn step(&mut self, step: &StepV1) -> Result<ResolvedStepV1, InvalidCaseV1> {
        match step {
            StepV1::Install(install) => Ok(ResolvedStepV1::Install(InstallArgsV1 {
                address: self.address(&install.release)?,
                material: self.material_of(install.material.as_ref())?,
                instant_micros: install.instant_micros.0,
                tick: install.tick.0,
            })),
            StepV1::Bind(bind) => {
                if self.bound.contains_key(bind.plugin_id.as_str()) {
                    return Err(InvalidCaseV1);
                }
                let address = self.address(&bind.release)?;
                let material = self.material_of(bind.material.as_ref())?;
                self.material.clone_from(&material);
                self.bound
                    .insert(bind.plugin_id.as_str().to_owned(), address.clone());
                Ok(ResolvedStepV1::Bind(BindArgsV1 {
                    address,
                    material,
                    plugin_id: bind.plugin_id.as_str().to_owned(),
                    instant_micros: bind.instant_micros.0,
                    tick: bind.tick.0,
                    initial_state_schema: bind.initial_state.schema.0,
                    initial_state_bytes: bind.initial_state.bytes.0.clone(),
                    event_type: bind.event_type.as_str().to_owned(),
                }))
            }
            StepV1::Refresh(refresh) => {
                let material = self.material_of(refresh.material.as_ref())?;
                self.material.clone_from(&material);
                Ok(ResolvedStepV1::Refresh(RefreshArgsV1 {
                    material,
                    instant_micros: refresh.instant_micros.0,
                    tick: refresh.tick.0,
                }))
            }
            StepV1::Pass(pass) => {
                let members = pass
                    .members
                    .iter()
                    .map(|member| self.member(member))
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(ResolvedStepV1::Pass(PassArgsV1 {
                    members,
                    material: self.material.clone(),
                    instant_micros: pass.instant_micros.0,
                    tick: pass.tick.0,
                    invocation_id: pass.invocation_id.0,
                    random_domain: pass.random_domain.0,
                    timeline_seq: pass.timeline_seq.0,
                    observation: pass.observation.0.clone(),
                    simulation_time: pass.simulation_time.0,
                }))
            }
            StepV1::Scan(scan) => Ok(ResolvedStepV1::Scan(ScanArgsV1 {
                marker: scan.marker.as_str().to_owned(),
                sources: scan.sources.iter().copied().collect(),
                retained_plugin_id: scan.retained.plugin_id.as_str().to_owned(),
                retained_invocation_id_hex: scan.retained.invocation_id_hex.as_str().to_owned(),
            })),
        }
    }
}

/// Run `subcase` on `port` in `mode` and compare its result with `expect`.
///
/// The record of a sub-case that cannot be resolved ([`PreparedV1::build()`] fails) has no step
/// run and does not match; the case driver rejects such a payload as `payload-invalid` before
/// any sub-case runs.
#[must_use]
pub fn interpret(
    subcase: &SubCaseV1,
    pieces: &PiecesV1,
    port: &mut dyn StepPortV1,
    mode: CommunityPluginModeV1,
) -> SubCaseRecordV1 {
    let record = SubCaseRecordV1::empty(subcase.id.as_str());
    match PreparedV1::build(subcase, pieces) {
        Ok(prepared) => Run {
            port,
            record,
            bound: None,
            invocation: None,
        }
        .execute(prepared, subcase, pieces, mode),
        Err(InvalidCaseV1) => record,
    }
}

/// The Plugin the most recent `bind` gated.
struct Bound {
    plugin_id: String,
    identity: ReleaseIdentityV1,
}

/// The state of one sub-case run.
struct Run<'a> {
    port: &'a mut dyn StepPortV1,
    record: SubCaseRecordV1,
    bound: Option<Bound>,
    /// The invocation ID of the last `pass` step.
    invocation: Option<[u8; 16]>,
}

impl Run<'_> {
    fn execute(
        mut self,
        prepared: PreparedV1,
        subcase: &SubCaseV1,
        pieces: &PiecesV1,
        mode: CommunityPluginModeV1,
    ) -> SubCaseRecordV1 {
        let PreparedV1 {
            source,
            genesis,
            steps,
        } = prepared;
        if !steps.is_empty() {
            let setup = SetupArgsV1 {
                source,
                genesis,
                mode,
            };
            match self.port.open(setup) {
                Ok(()) => self.run_steps(&steps),
                Err(error) => {
                    self.refuse(error);
                }
            }
        }
        self.finish(subcase, pieces)
    }

    fn run_steps(&mut self, steps: &[ResolvedStepV1]) {
        for step in steps {
            self.record.steps_run += 1;
            if !self.step(step) {
                break;
            }
        }
    }

    /// Record the refusal of the step that just ran and stop the sub-case.
    const fn refuse(&mut self, error: CommunityPluginHostErrorV1) -> bool {
        self.record.setup_refusal = Some(error);
        false
    }

    /// Continue after `result`, or stop with its refusal.
    fn settle(&mut self, result: Result<(), CommunityPluginHostErrorV1>) -> bool {
        result.map_or_else(|error| self.refuse(error), |()| true)
    }

    /// Run one step; `false` stops the sub-case.
    fn step(&mut self, step: &ResolvedStepV1) -> bool {
        match step {
            ResolvedStepV1::Install(args) => {
                let result = self.port.install(args);
                self.settle(result)
            }
            ResolvedStepV1::Bind(args) => {
                let result = self.port.bind(args).map(|identity| {
                    self.bound = Some(Bound {
                        plugin_id: args.plugin_id.clone(),
                        identity,
                    });
                });
                self.settle(result)
            }
            ResolvedStepV1::Refresh(args) => {
                let result = self.port.refresh(args);
                self.settle(result)
            }
            ResolvedStepV1::Pass(args) => match self.port.pass(args) {
                Ok(outcomes) => self.record_pass(args, &outcomes),
                Err(error) => self.refuse(error),
            },
            ResolvedStepV1::Scan(scan) => self.scan(scan),
        }
    }

    /// Record the outcome of a pass: the first outcome that did not commit, else the last.
    /// Only a committed outcome lets the sub-case continue.
    fn record_pass(
        &mut self,
        args: &PassArgsV1,
        outcomes: &[CommunityPluginSubjectOutcomeV1],
    ) -> bool {
        self.invocation = Some(args.invocation_id);
        let launched = outcomes
            .iter()
            .filter(|outcome| outcome.execution_profile_digest.is_some())
            .count();
        self.record.worker_launches += u32::try_from(launched).unwrap_or(u32::MAX);
        let decisive = outcomes
            .iter()
            .find(|outcome| !is_committed(outcome))
            .or_else(|| outcomes.last());
        match decisive {
            Some(outcome) => {
                self.record.outcomes.push(outcome.clone());
                is_committed(outcome)
            }
            None => false,
        }
    }

    /// The bytes of the places a `scan` searches.
    fn haystacks(&mut self, source: ScanSource) -> Result<Vec<Vec<u8>>, HostError> {
        match source {
            ScanSource::Events => self.port.committed_event_payloads(),
            ScanSource::State => Ok(vec![self.port.committed_state()]),
            ScanSource::Outcome => Ok(vec![self.port.outcome_bytes()]),
        }
    }

    fn scan(&mut self, scan: &ScanArgsV1) -> bool {
        let mut found = Vec::new();
        for source in &scan.sources {
            match self.haystacks(*source) {
                Ok(haystacks) => {
                    let marker = scan.marker.as_bytes();
                    if haystacks.iter().any(|haystack| contains(haystack, marker)) {
                        found.push(*source);
                    }
                }
                Err(error) => return self.refuse(error),
            }
        }
        let plugin_id = self
            .bound
            .as_ref()
            .map(|bound| bound.plugin_id.clone())
            .unwrap_or_default();
        let invocation = self
            .invocation
            .map(|id| hex::encode(&id))
            .unwrap_or_default();
        self.record.scan = Some(ScanResultV1 {
            found,
            retained_ok: plugin_id == scan.retained_plugin_id
                && invocation == scan.retained_invocation_id_hex,
            observed_plugin_id: plugin_id,
            observed_invocation_id_hex: invocation,
        });
        true
    }

    /// Compute the `digest` value, set the result fields and compare with `expect`.
    fn finish(mut self, subcase: &SubCaseV1, pieces: &PiecesV1) -> SubCaseRecordV1 {
        let result = of_record(&self.record);
        if let Some(SubResultV1::Committed {
            output_digest,
            usage,
        }) = result
        {
            self.record.committed = Some(output_digest);
            self.record.usage = usage;
        }
        if let ExpectV1::Digest(digest) = &subcase.expect {
            self.record.computed = self.compute(&digest.compute);
        }
        self.record.matched = self.matches(subcase, result, pieces);
        self.record
    }

    /// The value of a `compute`; `None` when it does not exist.
    fn compute(&self, compute: &ComputeV1) -> Option<[u8; 32]> {
        match compute {
            ComputeV1::Blake3Of(of) => Some(blake3_of(of.input.as_str())),
            ComputeV1::ReleaseIdentity(identity) => {
                self.bound.as_ref().map(|bound| match identity.field {
                    IdentityFieldV1::Pmf1 => bound.identity.pmf1_digest,
                    IdentityFieldV1::Release => bound.identity.release_digest,
                })
            }
            ComputeV1::OutputDigest(output) => usize::try_from(output.pass_index.0)
                .ok()
                .and_then(|index| self.record.outcomes.get(index))
                .and_then(|outcome| match of_outcome(outcome) {
                    SubResultV1::Committed { output_digest, .. } => Some(output_digest),
                    SubResultV1::Refused { .. }
                    | SubResultV1::Failed { .. }
                    | SubResultV1::Operational => None,
                }),
            ComputeV1::ProfileDigest(profile) => profile_digest(profile),
        }
    }

    /// Whether the sub-result `result` and the record satisfy the expectation.
    fn matches(&self, subcase: &SubCaseV1, result: Option<SubResultV1>, pieces: &PiecesV1) -> bool {
        match (&subcase.expect, result) {
            (ExpectV1::Committed(expect), Some(SubResultV1::Committed { output_digest, .. })) => {
                output_digest == expect.output_digest.0
            }
            (
                ExpectV1::Refused(expect),
                Some(SubResultV1::Refused {
                    error,
                    basis,
                    class,
                    index,
                }),
            ) => {
                error == expect.error.as_str()
                    && class == expect.class.as_str()
                    && basis == expect.basis.as_ref().map(Text::as_str)
                    && index == expect.index.map(|index| index.0)
            }
            (ExpectV1::Failed(expect), Some(SubResultV1::Failed { error, class })) => {
                error == expect.error.as_str() && class == expect.class.as_str()
            }
            (ExpectV1::Malformed(_), _) => subcase
                .nested
                .and_then(|digest| pieces.get(&digest.0))
                .is_some_and(|bytes| SubCaseV1::parse_document(bytes).is_err()),
            (ExpectV1::Absent(_), _) => self
                .record
                .scan
                .as_ref()
                .is_some_and(|scan| scan.found.is_empty() && scan.retained_ok),
            (ExpectV1::Digest(expect), _) => self.record.computed == Some(expect.value.0),
            (ExpectV1::Committed(_) | ExpectV1::Refused(_) | ExpectV1::Failed(_), _) => false,
        }
    }
}

/// The unkeyed BLAKE3-256 of the UTF-8 bytes of `input`.
fn blake3_of(input: &str) -> [u8; 32] {
    *blake3::hash(input.as_bytes()).as_bytes()
}

/// Whether the outcome's sub-result is `committed`.
fn is_committed(outcome: &CommunityPluginSubjectOutcomeV1) -> bool {
    matches!(of_outcome(outcome), SubResultV1::Committed { .. })
}

/// Whether `haystack` holds `marker`; the empty marker is in every source.
fn contains(haystack: &[u8], marker: &[u8]) -> bool {
    marker.is_empty()
        || haystack
            .windows(marker.len())
            .any(|window| window == marker)
}

/// The execution profile digest of a payload's ceilings and runtime.
fn profile_digest(profile: &ProfileDigestV1) -> Option<[u8; 32]> {
    let runtime = &profile.runtime;
    let rows = runtime
        .traps
        .iter()
        .map(|(code, outcome)| TrapTableEntryV1::from_adr_outcome(code.as_str(), outcome.as_str()))
        .collect::<Option<Vec<_>>>();
    let features = runtime
        .features
        .iter()
        .map(|feature| feature.as_str().to_owned())
        .collect();
    let (stack, consume_fuel, epoch_interruption) = &runtime.engine;
    let engine = PinnedEngineConfigV1 {
        max_wasm_stack: stack.0,
        consume_fuel: *consume_fuel,
        epoch_interruption: *epoch_interruption,
    };
    let [memory_bytes, fuel, host_calls, event_bytes, log_bytes] =
        profile.ceilings.map(|ceiling| ceiling.0);
    let ceilings = CeilingValuesV1 {
        memory_bytes,
        fuel,
        host_calls,
        event_bytes,
        log_bytes,
    };
    rows.and_then(|rows| {
        let version = runtime.version.as_str().to_owned();
        PinnedComponentRuntimeV1::new(version, features, engine, rows).ok()
    })
    .and_then(|pinned| profile_digest_of(ceilings, pinned))
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests;
