//! Typed, slot-aligned comparison of two Plugin rosters, without any authority.
//!
//! [`compare_manifest_plugin_rosters_v1`] answers one question: do two runs
//! carry the same Plugin policies at the same stable slots? It decodes each
//! retained OPC1 closure member by member and compares typed fields, never
//! hashes or MPR1 bytes. `Ok` is a [`RosterEquivalenceV1`] marker. It is not an
//! Exact claim and not owner authentication; it only reports that these two
//! rosters are policy-equivalent.
//!
//! # What is compared
//!
//! Slot by slot, in this fixed order, and the first difference is returned:
//!
//! 1. the set of stable slots (`MissingPlugin`, then `UnexpectedPlugin`);
//! 2. each closure is present, framed, decodable and belongs to its entry
//!    (`ClosureUnavailable`), per slot in slot order, baseline then candidate;
//! 3. per slot (`PolicyMismatch`): registered version, owned Event-type set
//!    (derived from the EOP1 declarations), declarations, EOP1 revision,
//!    implementation, configuration and execution-profile artifact bytes,
//!    the decoded retention policy, the executable-budget scalar fields and
//!    the three fidelity budgets;
//! 4. the CPU reservation tables (`ReservationMismatch`): every reservation
//!    owner resolves to exactly one slot of its own roster, closures that share
//!    an `execution_profile_hash` agree on every non-ID budget field and on
//!    their reservation table, and the slot-keyed tables are equal across runs.
//!
//! # What is not compared
//!
//! Display names, raw `PluginId`s and every address that depends on them (the
//! EOP1 digest, the EBP1 digest, the closure bytes as a whole) are ignored. The
//! EOP1 hash fields are redundant with the artifacts compared above, so they
//! are ignored too. Equality of the reservation table with the actual owner's
//! enabled-Plugin roster, and the native hashes of the opaque artifacts, belong
//! to the owner verifier, not to this comparison.
//!
//! Configuration and implementation artifacts are compared as exact bytes, so
//! they must not embed a run-local `PluginId`.
//!
//! # Example
//!
//! Two runs register the same three Plugins at the same slots. Two share the
//! display name `Sensor`, `gamma` is a reducer that owns no Event type, the
//! second run gets fresh `PluginId`s and `alpha` is renamed. They still match.
//!
//! ```text
//! // `run(ids, alpha_name)` builds one roster: slots "alpha", "beta" and
//! // "gamma", their OPC1 closures and EBP1 reservations keyed by `ids`.
//! let baseline = run([1, 2, 3], "Sensor");
//! let candidate = run([30, 20, 10], "Probe");
//! let marker = compare_manifest_plugin_rosters_v1(&baseline, &candidate)?;
//! assert_eq!(marker.slot_count(), 3);
//!
//! // Change one Plugin's policy in the candidate and read the first mismatch.
//! let changed = run_with_declaration_limit([30, 20, 10], 8192);
//! let error = compare_manifest_plugin_rosters_v1(&baseline, &changed).unwrap_err();
//! assert!(matches!(
//!     error,
//!     RosterComparisonErrorV1::PolicyMismatch { field: ComparedFieldV1::Declarations, .. }
//! ));
//! // slot `alpha`: output declarations differ between baseline and candidate; ...
//! println!("{error}");
//! ```

use std::collections::{BTreeSet, HashMap};
use std::fmt;

use crate::executable_budget::{ExecutableBudgetPolicyInputV1, ExecutableBudgetPolicyV1};
use crate::manifest_owner_admission::OutputPolicyClosureEnvelopeV1;
use crate::output_policy::{OutputDeclarationV1, OutputPolicyV1};
use crate::retention::WorldRetentionPolicyV1;
use crate::{Hash, ManifestPluginEntryV1, ManifestPluginRosterV1, PluginId};

/// The run a diagnostic refers to.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ComparisonSideV1 {
    /// The reference roster, the first argument.
    Baseline,
    /// The roster checked against the baseline, the second argument.
    Candidate,
}

impl ComparisonSideV1 {
    const fn label(self) -> &'static str {
        match self {
            Self::Baseline => "baseline",
            Self::Candidate => "candidate",
        }
    }
}

impl fmt::Display for ComparisonSideV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.label())
    }
}

/// The compared field a `PolicyMismatch` names, in comparison order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ComparedFieldV1 {
    /// The registered Plugin version.
    Version,
    /// The set of Event types the Plugin declares.
    EventTypeSet,
    /// The EOP1 output declarations.
    Declarations,
    /// The EOP1 policy revision.
    PolicyRevision,
    /// The implementation artifact bytes.
    ImplementationArtifact,
    /// The base configuration artifact bytes.
    ConfigurationArtifact,
    /// The execution-profile artifact bytes.
    ExecutionProfileArtifact,
    /// The decoded retention policy.
    RetentionPolicy,
    /// The executable-budget scalar fields.
    BudgetScalars,
    /// The three executable-budget fidelity budgets.
    FidelityBudgets,
}

impl ComparedFieldV1 {
    const fn label(self) -> &'static str {
        match self {
            Self::Version => "registered version",
            Self::EventTypeSet => "owned Event-type set",
            Self::Declarations => "output declarations",
            Self::PolicyRevision => "policy revision",
            Self::ImplementationArtifact => "implementation artifact",
            Self::ConfigurationArtifact => "base configuration artifact",
            Self::ExecutionProfileArtifact => "execution-profile artifact",
            Self::RetentionPolicy => "retention policy",
            Self::BudgetScalars => "executable-budget scalar fields",
            Self::FidelityBudgets => "executable-budget fidelity budgets",
        }
    }
}

impl fmt::Display for ComparedFieldV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.label())
    }
}

/// Why a roster entry's retained closure cannot be compared.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ClosureProblemV1 {
    /// The entry carries no closure bytes.
    #[error("is empty; retain the complete OPC1 closure for this Plugin")]
    Empty,
    /// The bytes are not one exactly framed OPC1 envelope.
    #[error("is not a well-formed OPC1 envelope; retain the exact bytes the owner admitted")]
    Envelope,
    /// Member 0 is not a canonical EOP1.
    #[error("has an undecodable EOP1 member; retain the exact bytes the owner admitted")]
    UndecodableEop1,
    /// Member 0 is a valid EOP1 that does not belong to this roster entry.
    #[error(
        "carries an EOP1 that is not this entry's (its digest, PluginId or version differs); \
         retain the closure that was admitted for this slot"
    )]
    ForeignEop1,
    /// Member 1 is not a canonical EBP1.
    #[error(
        "has an undecodable executable-budget member; retain the exact bytes the owner admitted"
    )]
    UndecodableBudget,
    /// Member 5 is not a canonical RTP1.
    #[error("has an undecodable retention member; retain the exact bytes the owner admitted")]
    UndecodableRetention,
}

/// Which CPU reservation rule a `ReservationMismatch` broke.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ReservationMismatchKindV1 {
    /// A reservation row names a `PluginId` that no entry of its own roster has.
    #[error(
        "a CPU reservation names a PluginId that no roster entry owns; add the reserved Plugin \
         to the roster or drop the stale reservation"
    )]
    UnboundOwner,
    /// Closures sharing one execution profile disagree on budget or reservations.
    #[error(
        "closures sharing one execution profile disagree on a budget field or on the CPU \
         reservation table; rebuild them from one executable-budget policy"
    )]
    ConflictingProfile,
    /// The slot-keyed reservation tables differ between the runs.
    #[error(
        "the CPU reservation table differs between baseline and candidate (a changed, missing, \
         extra or swapped reservation); rebuild both runs from the same recorded recipe"
    )]
    TableDiffers,
}

/// The first difference found between two rosters.
///
/// Messages name the slot and the side or field, and say what to change. They
/// never include closure bytes or `PluginId`s.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum RosterComparisonErrorV1 {
    /// A baseline slot has no entry in the candidate.
    #[error(
        "slot `{slot}` is in the baseline but missing from the candidate; register a Plugin at \
         that slot in the candidate, or remove it from the baseline"
    )]
    MissingPlugin {
        /// The stable slot.
        slot: String,
    },
    /// A candidate slot has no entry in the baseline.
    #[error(
        "slot `{slot}` is in the candidate but not in the baseline; remove that Plugin from the \
         candidate, or add it to the baseline"
    )]
    UnexpectedPlugin {
        /// The stable slot.
        slot: String,
    },
    /// One side's closure cannot be decoded or does not belong to its entry.
    #[error("slot `{slot}`: the {side} closure {problem}")]
    ClosureUnavailable {
        /// The stable slot.
        slot: String,
        /// The run whose closure failed.
        side: ComparisonSideV1,
        /// What is wrong with it.
        problem: ClosureProblemV1,
    },
    /// A compared policy field differs at one slot.
    #[error(
        "slot `{slot}`: {field} differs between baseline and candidate; rebuild both runs from \
         the same recorded recipe, or record a new baseline for the changed policy"
    )]
    PolicyMismatch {
        /// The stable slot.
        slot: String,
        /// The first differing field.
        field: ComparedFieldV1,
    },
    /// A CPU reservation rule failed; `side` is `None` when the runs differ.
    #[error("slot `{slot}`: {kind} (in {})", .side.map_or("both runs", ComparisonSideV1::label))]
    ReservationMismatch {
        /// The stable slot of the closure that exposed the problem.
        slot: String,
        /// The run that broke the rule, or `None` for a difference across runs.
        side: Option<ComparisonSideV1>,
        /// The rule that failed.
        kind: ReservationMismatchKindV1,
    },
}

/// Marker that two rosters are policy-equivalent, slot for slot.
///
/// It carries no authority: it is not an Exact claim, owner authentication or
/// permission to use any retained bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RosterEquivalenceV1 {
    slot_count: usize,
}

impl RosterEquivalenceV1 {
    /// Number of slots that were compared; zero for two empty rosters.
    #[must_use]
    pub const fn slot_count(self) -> usize {
        self.slot_count
    }
}

/// One decoded closure.
struct Closure<'a> {
    policy: OutputPolicyV1,
    budget: ExecutableBudgetPolicyV1,
    retention: WorldRetentionPolicyV1,
    members: OutputPolicyClosureEnvelopeV1<'a>,
}

impl<'a> Closure<'a> {
    fn decode(
        entry: &'a ManifestPluginEntryV1,
        side: ComparisonSideV1,
    ) -> Result<Self, RosterComparisonErrorV1> {
        let parsed = Self::parse(entry);
        parsed.map_err(|problem| unavailable(entry, side, problem))
    }

    fn parse(entry: &'a ManifestPluginEntryV1) -> Result<Self, ClosureProblemV1> {
        let bytes = entry.closure_bytes();
        if bytes.is_empty() {
            return Err(ClosureProblemV1::Empty);
        }
        let members = OutputPolicyClosureEnvelopeV1::from_canonical_bytes_unbound_v1(bytes)
            .map_err(|_| ClosureProblemV1::Envelope)?;
        let policy = OutputPolicyV1::from_canonical_cbor(members.eop1_bytes())
            .map_err(|_| ClosureProblemV1::UndecodableEop1)?;
        if !belongs_to(&policy, entry) {
            return Err(ClosureProblemV1::ForeignEop1);
        }
        let budget_bytes = members.executable_budget_bytes();
        let budget = ExecutableBudgetPolicyV1::from_canonical_cbor(budget_bytes)
            .map_err(|_| ClosureProblemV1::UndecodableBudget)?;
        let retention_bytes = members.retention_policy_artifact();
        let retention = WorldRetentionPolicyV1::from_canonical_cbor(retention_bytes)
            .map_err(|_| ClosureProblemV1::UndecodableRetention)?;
        Ok(Self {
            policy,
            budget,
            retention,
            members,
        })
    }
}

fn unavailable(
    entry: &ManifestPluginEntryV1,
    side: ComparisonSideV1,
    problem: ClosureProblemV1,
) -> RosterComparisonErrorV1 {
    RosterComparisonErrorV1::ClosureUnavailable {
        slot: entry.stable_slot().to_owned(),
        side,
        problem,
    }
}

fn belongs_to(policy: &OutputPolicyV1, entry: &ManifestPluginEntryV1) -> bool {
    policy.digest() == entry.eop1_digest()
        && policy.fields().plugin_id == entry.plugin_id()
        && policy.fields().plugin_version == entry.plugin_version()
}

/// The two closures at one stable slot.
struct Pair<'a> {
    slot: &'a str,
    baseline: Closure<'a>,
    candidate: Closure<'a>,
}

impl<'a> Pair<'a> {
    const fn closure(&self, side: ComparisonSideV1) -> &Closure<'a> {
        match side {
            ComparisonSideV1::Baseline => &self.baseline,
            ComparisonSideV1::Candidate => &self.candidate,
        }
    }
}

type FieldCheck = fn(&Closure<'_>, &Closure<'_>) -> bool;

// Comparison order of the per-slot policy fields.
const FIELD_CHECKS: [(ComparedFieldV1, FieldCheck); 10] = [
    (ComparedFieldV1::Version, same_version),
    (ComparedFieldV1::EventTypeSet, same_event_types),
    (ComparedFieldV1::Declarations, same_declarations),
    (ComparedFieldV1::PolicyRevision, same_revision),
    (ComparedFieldV1::ImplementationArtifact, same_implementation),
    (ComparedFieldV1::ConfigurationArtifact, same_configuration),
    (
        ComparedFieldV1::ExecutionProfileArtifact,
        same_profile_artifact,
    ),
    (ComparedFieldV1::RetentionPolicy, same_retention),
    (ComparedFieldV1::BudgetScalars, same_budget_scalars),
    (ComparedFieldV1::FidelityBudgets, same_fidelity_budgets),
];

fn same_version(left: &Closure<'_>, right: &Closure<'_>) -> bool {
    left.policy.fields().plugin_version == right.policy.fields().plugin_version
}

fn event_types<'c>(closure: &'c Closure<'_>) -> BTreeSet<&'c str> {
    let declarations = &closure.policy.fields().output_declarations;
    declarations
        .iter()
        .map(OutputDeclarationV1::event_type)
        .collect()
}

fn same_event_types(left: &Closure<'_>, right: &Closure<'_>) -> bool {
    event_types(left) == event_types(right)
}

fn same_declarations(left: &Closure<'_>, right: &Closure<'_>) -> bool {
    left.policy.fields().output_declarations == right.policy.fields().output_declarations
}

const fn same_revision(left: &Closure<'_>, right: &Closure<'_>) -> bool {
    left.policy.fields().policy_revision == right.policy.fields().policy_revision
}

fn same_implementation(left: &Closure<'_>, right: &Closure<'_>) -> bool {
    left.members.implementation_artifact() == right.members.implementation_artifact()
}

fn same_configuration(left: &Closure<'_>, right: &Closure<'_>) -> bool {
    left.members.configuration_artifact() == right.members.configuration_artifact()
}

fn same_profile_artifact(left: &Closure<'_>, right: &Closure<'_>) -> bool {
    left.members.execution_profile_artifact() == right.members.execution_profile_artifact()
}

fn same_retention(left: &Closure<'_>, right: &Closure<'_>) -> bool {
    left.retention.as_input() == right.retention.as_input()
}

fn same_budget_scalars(left: &Closure<'_>, right: &Closure<'_>) -> bool {
    let (left, right) = (left.budget.fields(), right.budget.fields());
    left.revision == right.revision
        && left.workload_profile == right.workload_profile
        && left.cut_budget_family == right.cut_budget_family
        && left.max_event_bytes == right.max_event_bytes
        && left.accounting_semantics == right.accounting_semantics
        && left.execution_profile_hash == right.execution_profile_hash
        && left.max_pass_wall_duration_us == right.max_pass_wall_duration_us
}

fn same_fidelity_budgets(left: &Closure<'_>, right: &Closure<'_>) -> bool {
    left.budget.fields().fidelity_budgets == right.budget.fields().fidelity_budgets
}

fn first_difference(left: &Closure<'_>, right: &Closure<'_>) -> Option<ComparedFieldV1> {
    FIELD_CHECKS
        .iter()
        .find(|(_, same)| !same(left, right))
        .map(|(field, _)| *field)
}

type Table<'a> = Vec<(&'a str, [u32; 3])>;

fn has_slot(roster: &ManifestPluginRosterV1, slot: &str) -> bool {
    let entries = roster.entries();
    entries.iter().any(|entry| entry.stable_slot() == slot)
}

fn first_absent<'a>(
    from: &'a ManifestPluginRosterV1,
    other: &ManifestPluginRosterV1,
) -> Option<&'a str> {
    for entry in from.entries() {
        if !has_slot(other, entry.stable_slot()) {
            return Some(entry.stable_slot());
        }
    }
    None
}

fn check_slot_sets(
    baseline: &ManifestPluginRosterV1,
    candidate: &ManifestPluginRosterV1,
) -> Result<(), RosterComparisonErrorV1> {
    if let Some(slot) = first_absent(baseline, candidate) {
        let slot = slot.to_owned();
        return Err(RosterComparisonErrorV1::MissingPlugin { slot });
    }
    if let Some(slot) = first_absent(candidate, baseline) {
        let slot = slot.to_owned();
        return Err(RosterComparisonErrorV1::UnexpectedPlugin { slot });
    }
    Ok(())
}

fn decode_pairs<'a>(
    baseline: &'a ManifestPluginRosterV1,
    candidate: &'a ManifestPluginRosterV1,
) -> Result<Vec<Pair<'a>>, RosterComparisonErrorV1> {
    let mut pairs = Vec::new();
    // Both rosters are strictly slot-sorted with unique slots, and the slot
    // sets were just proven equal, so index pairing aligns every slot.
    for (left, right) in baseline.entries().iter().zip(candidate.entries()) {
        let slot = left.stable_slot();
        let before = Closure::decode(left, ComparisonSideV1::Baseline)?;
        let after = Closure::decode(right, ComparisonSideV1::Candidate)?;
        pairs.push(Pair {
            slot,
            baseline: before,
            candidate: after,
        });
    }
    Ok(pairs)
}

fn check_policy_fields(pairs: &[Pair<'_>]) -> Result<(), RosterComparisonErrorV1> {
    for pair in pairs {
        if let Some(field) = first_difference(&pair.baseline, &pair.candidate) {
            return Err(RosterComparisonErrorV1::PolicyMismatch {
                slot: pair.slot.to_owned(),
                field,
            });
        }
    }
    Ok(())
}

fn reservation_error(
    slot: &str,
    side: Option<ComparisonSideV1>,
    kind: ReservationMismatchKindV1,
) -> RosterComparisonErrorV1 {
    RosterComparisonErrorV1::ReservationMismatch {
        slot: slot.to_owned(),
        side,
        kind,
    }
}

// Replace each reservation owner with its slot and sort by slot; `None` when
// any owner is not in the roster.
fn normalize<'a>(
    owners: &HashMap<PluginId, &'a str>,
    budget: &ExecutableBudgetPolicyInputV1,
) -> Option<Table<'a>> {
    let mut table = budget
        .plugin_cpu_reservations
        .iter()
        .map(|row| {
            let slot = owners.get(&row.plugin_id)?;
            Some((*slot, row.cpu_reservations_us))
        })
        .collect::<Option<Table<'a>>>()?;
    table.sort_unstable_by_key(|row| row.0);
    Some(table)
}

const fn profile_hash(pair: &Pair<'_>, side: ComparisonSideV1) -> Hash {
    pair.closure(side).budget.fields().execution_profile_hash
}

// Whether two closures of one execution profile agree on every non-ID budget
// field and on their normalized reservation table.
fn agrees(
    side: ComparisonSideV1,
    pairs: &[Pair<'_>],
    tables: &[Table<'_>],
    (first, later): (usize, usize),
) -> bool {
    let earlier = pairs[first].closure(side);
    let current = pairs[later].closure(side);
    same_budget_scalars(earlier, current)
        && same_fidelity_budgets(earlier, current)
        && tables[first] == tables[later]
}

fn check_profile_groups(
    side: ComparisonSideV1,
    pairs: &[Pair<'_>],
    tables: &[Table<'_>],
) -> Result<(), RosterComparisonErrorV1> {
    for (index, pair) in pairs.iter().enumerate() {
        let hash = profile_hash(pair, side);
        let earlier = &pairs[..index];
        let first = earlier.iter().position(|p| profile_hash(p, side) == hash);
        if first.is_some_and(|at| !agrees(side, pairs, tables, (at, index))) {
            let kind = ReservationMismatchKindV1::ConflictingProfile;
            return Err(reservation_error(pair.slot, Some(side), kind));
        }
    }
    Ok(())
}

fn side_tables<'a>(
    side: ComparisonSideV1,
    roster: &'a ManifestPluginRosterV1,
    pairs: &[Pair<'_>],
) -> Result<Vec<Table<'a>>, RosterComparisonErrorV1> {
    let entries = roster.entries().iter();
    let owners: HashMap<PluginId, &str> = entries
        .map(|entry| (entry.plugin_id(), entry.stable_slot()))
        .collect();
    let kind = ReservationMismatchKindV1::UnboundOwner;
    let mut tables = Vec::with_capacity(pairs.len());
    for pair in pairs {
        let table = normalize(&owners, pair.closure(side).budget.fields());
        let table = table.ok_or_else(|| reservation_error(pair.slot, Some(side), kind))?;
        tables.push(table);
    }
    check_profile_groups(side, pairs, &tables)?;
    Ok(tables)
}

fn check_reservations(
    baseline: &ManifestPluginRosterV1,
    candidate: &ManifestPluginRosterV1,
    pairs: &[Pair<'_>],
) -> Result<(), RosterComparisonErrorV1> {
    let left = side_tables(ComparisonSideV1::Baseline, baseline, pairs)?;
    let right = side_tables(ComparisonSideV1::Candidate, candidate, pairs)?;
    for (pair, (before, after)) in pairs.iter().zip(left.iter().zip(&right)) {
        if before != after {
            let kind = ReservationMismatchKindV1::TableDiffers;
            return Err(reservation_error(pair.slot, None, kind));
        }
    }
    Ok(())
}

/// Compare two rosters slot by slot and return the first difference.
///
/// The check order is fixed, see the module documentation: slot sets, closure
/// decoding, per-slot policy fields, then CPU reservations. Display names, raw
/// `PluginId`s and every `PluginId`-dependent address are not compared, so two
/// fresh runs of one recipe compare equal. Two empty rosters are equal.
///
/// # Errors
/// Returns the first `MissingPlugin`, `UnexpectedPlugin`, `ClosureUnavailable`,
/// `PolicyMismatch` or `ReservationMismatch` in that order. The `Ok` marker
/// grants no authority.
pub fn compare_manifest_plugin_rosters_v1(
    baseline: &ManifestPluginRosterV1,
    candidate: &ManifestPluginRosterV1,
) -> Result<RosterEquivalenceV1, RosterComparisonErrorV1> {
    check_slot_sets(baseline, candidate)?;
    let pairs = decode_pairs(baseline, candidate)?;
    check_policy_fields(&pairs)?;
    check_reservations(baseline, candidate, &pairs)?;
    Ok(RosterEquivalenceV1 {
        slot_count: pairs.len(),
    })
}
