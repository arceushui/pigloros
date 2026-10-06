use pos_core::executable_budget::{
    ExecutableBudgetPolicyInputV1, ExecutableBudgetPolicyV1, FidelityBudgetV1,
    PluginCpuReservationV1, WorkloadProfileV1,
};
use pos_core::output_policy::{
    OutputAuthorityV1, OutputDeclarationV1, OutputFidelityV1, OutputPolicyInputV1, OutputPolicyV1,
};
use pos_core::retention::{WorldRetentionPolicyInputV1, WorldRetentionPolicyV1};
use pos_core::{
    compare_manifest_plugin_rosters_v1, ClosureProblemV1, ComparedFieldV1, ComparisonSideV1, Hash,
    ManifestPluginEntryV1, ManifestPluginRosterV1, PluginId, ReservationMismatchKindV1,
    RosterComparisonErrorV1, RosterEquivalenceV1,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;
type Error = RosterComparisonErrorV1;
type Field = ComparedFieldV1;
type Side = ComparisonSideV1;
type Problem = ClosureProblemV1;
type Kind = ReservationMismatchKindV1;
type Rows = Vec<(u16, [u32; 3])>;

const SECRET: &[u8] = b"SECRET-IMPLEMENTATION-BYTES";

const fn hash(byte: u8) -> Hash {
    Hash::from_bytes([byte; 32])
}

fn plugin_id(id: u16) -> PluginId {
    PluginId::from_ulid(ulid::Ulid::from(u128::from(id)))
}

// The CPU reservation each slot holds, keyed by slot so fresh ids keep it.
fn rates(slot: &str) -> [u32; 3] {
    match slot {
        "alpha" => [100, 200, 300],
        "beta" => [110, 210, 310],
        "gamma" => [120, 220, 320],
        _ => [130, 230, 330],
    }
}

#[derive(Clone)]
struct Budget {
    revision: u32,
    workload: WorkloadProfileV1,
    max_event_bytes: u32,
    profile_hash: u8,
    wall_us: u64,
    events: [u32; 3],
    bytes: [u64; 3],
    rows: Rows,
}

const fn standard_budget(rows: Rows) -> Budget {
    Budget {
        revision: 1,
        workload: WorkloadProfileV1::Interactive,
        max_event_bytes: 4096,
        profile_hash: 7,
        wall_us: 1_000,
        events: [100; 3],
        bytes: [100_000; 3],
        rows,
    }
}

const fn fidelity(level: u8, events: u32, bytes: u64, cpu: u32) -> FidelityBudgetV1 {
    FidelityBudgetV1 {
        level,
        max_events: events,
        max_bytes: bytes,
        max_cpu_us: cpu,
        shared_host_cpu_reservation_us: 100,
    }
}

fn budget_input(budget: &Budget) -> ExecutableBudgetPolicyInputV1 {
    let mut rows = budget.rows.clone();
    rows.sort_by_key(|row| row.0);
    let reservations = rows
        .iter()
        .map(|(id, levels)| PluginCpuReservationV1 {
            plugin_id: plugin_id(*id),
            cpu_reservations_us: *levels,
        })
        .collect();
    ExecutableBudgetPolicyInputV1 {
        revision: budget.revision,
        workload_profile: budget.workload,
        cut_budget_family: 0,
        max_event_bytes: budget.max_event_bytes,
        fidelity_budgets: [
            fidelity(0, budget.events[0], budget.bytes[0], 500_000),
            fidelity(1, budget.events[1], budget.bytes[1], 250_000),
            fidelity(2, budget.events[2], budget.bytes[2], 50_000),
        ],
        plugin_cpu_reservations: reservations,
        accounting_semantics: 0,
        execution_profile_hash: hash(budget.profile_hash),
        max_pass_wall_duration_us: budget.wall_us,
    }
}

#[derive(Clone)]
struct Plugin {
    slot: &'static str,
    id: u16,
    name: &'static str,
    version: &'static str,
    revision: u32,
    events: Vec<&'static str>,
    limit: u32,
    implementation: Vec<u8>,
    configuration: Vec<u8>,
    profile: Vec<u8>,
    total_days: u16,
    hint: u8,
    own: Option<Budget>,
}

fn plugin(slot: &'static str, id: u16, name: &'static str, events: &[&'static str]) -> Plugin {
    Plugin {
        slot,
        id,
        name,
        version: "1.0.0",
        revision: 1,
        events: events.to_vec(),
        limit: 4096,
        implementation: SECRET.to_vec(),
        configuration: b"configuration".to_vec(),
        profile: b"profile".to_vec(),
        total_days: 120,
        hint: 1,
        own: None,
    }
}

// Two same-name Plugins and one reducer-only Plugin that owns no Event type.
fn standard_plugins(ids: [u16; 3], first_name: &'static str) -> Vec<Plugin> {
    vec![
        plugin("alpha", ids[0], first_name, &["alpha.out"]),
        plugin("beta", ids[1], "Sensor", &["beta.out"]),
        plugin("gamma", ids[2], "Reducer", &[]),
    ]
}

#[derive(Clone)]
struct Run {
    plugins: Vec<Plugin>,
    budget: Budget,
}

fn run_of(plugins: Vec<Plugin>) -> Run {
    let rows: Rows = plugins.iter().map(|p| (p.id, rates(p.slot))).collect();
    Run {
        plugins,
        budget: standard_budget(rows),
    }
}

fn standard_run(ids: [u16; 3], first_name: &'static str) -> Run {
    run_of(standard_plugins(ids, first_name))
}

struct Draft {
    slot: &'static str,
    id: u16,
    name: &'static str,
    version: String,
    digest: Hash,
    members: [Vec<u8>; 6],
    raw: Option<Vec<u8>>,
}

fn opc1(members: &[Vec<u8>; 6]) -> Vec<u8> {
    let mut bytes = Vec::from(&b"OPC1"[..]);
    for member in members {
        let length = u64::try_from(member.len()).unwrap_or(u64::MAX);
        bytes.extend_from_slice(&length.to_be_bytes());
        bytes.extend_from_slice(member);
    }
    bytes
}

fn make_draft(plugin: &Plugin, shared: &Budget) -> Result<Draft, Box<dyn std::error::Error>> {
    let chosen = plugin.own.as_ref().unwrap_or(shared);
    let budget = ExecutableBudgetPolicyV1::new(budget_input(chosen))?;
    let retention = WorldRetentionPolicyV1::new(WorldRetentionPolicyInputV1 {
        policy_revision: 1,
        purpose: "world-replay-v1".to_owned(),
        audience_policy_hash: hash(0xa6),
        minimum_post_admission_days: 90,
        maximum_active_days: 30,
        maximum_total_days: plugin.total_days,
    })?;
    let mut declarations = Vec::new();
    for event in &plugin.events {
        let declaration = OutputDeclarationV1::new(
            (*event).to_owned(),
            OutputAuthorityV1::Authoritative,
            OutputFidelityV1::L0,
            plugin.limit,
            None,
            None,
        )?;
        declarations.push(declaration);
    }
    let policy = OutputPolicyV1::new(OutputPolicyInputV1 {
        plugin_id: plugin_id(plugin.id),
        plugin_version: plugin.version.to_owned(),
        implementation_hash: hash(plugin.hint),
        base_configuration_digest: hash(2),
        executable_profile_hash: budget.digest(),
        retention_policy_hash: retention.digest(),
        policy_revision: plugin.revision,
        output_declarations: declarations,
    })?;
    Ok(Draft {
        slot: plugin.slot,
        id: plugin.id,
        name: plugin.name,
        version: plugin.version.to_owned(),
        digest: policy.digest(),
        members: [
            policy.to_canonical_cbor(),
            budget.to_canonical_cbor(),
            plugin.implementation.clone(),
            plugin.configuration.clone(),
            plugin.profile.clone(),
            retention.to_canonical_cbor(),
        ],
        raw: None,
    })
}

fn finish_entry(draft: &Draft) -> Result<ManifestPluginEntryV1, Box<dyn std::error::Error>> {
    let closure = draft.raw.clone().unwrap_or_else(|| opc1(&draft.members));
    let entry = ManifestPluginEntryV1::new(
        draft.slot,
        plugin_id(draft.id),
        draft.name,
        draft.version.clone(),
        draft.digest,
        closure,
    )?;
    Ok(entry)
}

// Build the roster, letting `edit` change the draft of the one named slot.
fn make_roster_edited(
    run: &Run,
    slot: &str,
    edit: fn(&mut Draft),
) -> Result<ManifestPluginRosterV1, Box<dyn std::error::Error>> {
    let mut entries = Vec::new();
    for plugin in &run.plugins {
        let mut draft = make_draft(plugin, &run.budget)?;
        if plugin.slot == slot {
            edit(&mut draft);
        }
        entries.push(finish_entry(&draft)?);
    }
    Ok(ManifestPluginRosterV1::new(entries)?)
}

fn make_roster(run: &Run) -> Result<ManifestPluginRosterV1, Box<dyn std::error::Error>> {
    make_roster_edited(run, "", |_| {})
}

type Outcome = Result<usize, Error>;

fn compare_rosters(
    baseline: &ManifestPluginRosterV1,
    candidate: &ManifestPluginRosterV1,
) -> Outcome {
    compare_manifest_plugin_rosters_v1(baseline, candidate)
        .map(RosterEquivalenceV1::slot_count)
}

fn compare_runs(baseline: &Run, candidate: &Run) -> Result<Outcome, Box<dyn std::error::Error>> {
    let left = make_roster(baseline)?;
    let right = make_roster(candidate)?;
    Ok(compare_rosters(&left, &right))
}

// Require the baseline-against-candidate comparison to fail with `expected`.
fn expect(baseline: &Run, candidate: &Run, expected: Error) -> TestResult {
    assert_eq!(compare_runs(baseline, candidate)?, Err(expected));
    Ok(())
}

fn expect_equal(baseline: &Run, candidate: &Run, slots: usize) -> TestResult {
    assert_eq!(compare_runs(baseline, candidate)?, Ok(slots));
    assert_eq!(compare_runs(candidate, baseline)?, Ok(slots));
    Ok(())
}

fn expect_at(baseline: &Run, candidate: &Run, slot: &str, field: Field) -> TestResult {
    expect(baseline, candidate, mismatch(slot, field))
}

fn has_all(text: &str, parts: &[&str]) -> bool {
    parts.iter().all(|part| text.contains(part))
}

fn mismatch(slot: &str, field: Field) -> Error {
    Error::PolicyMismatch {
        slot: slot.to_owned(),
        field,
    }
}

fn closure_error(slot: &str, side: Side, problem: Problem) -> Error {
    Error::ClosureUnavailable {
        slot: slot.to_owned(),
        side,
        problem,
    }
}

fn reservation(slot: &str, side: Option<Side>, kind: Kind) -> Error {
    Error::ReservationMismatch {
        slot: slot.to_owned(),
        side,
        kind,
    }
}

fn missing(slot: &str) -> Error {
    Error::MissingPlugin {
        slot: slot.to_owned(),
    }
}

fn unexpected(slot: &str) -> Error {
    Error::UnexpectedPlugin {
        slot: slot.to_owned(),
    }
}

fn without(slot: &str) -> Run {
    let mut plugins = standard_plugins([1, 2, 3], "Sensor");
    plugins.retain(|plugin| plugin.slot != slot);
    run_of(plugins)
}

#[test]
fn fresh_plugin_ids_with_equal_slots_are_equal() -> TestResult {
    let baseline = standard_run([1, 2, 3], "Sensor");
    // Reversed ids put the EBP1 rows in a different order than the slots.
    let candidate = standard_run([30, 20, 10], "Sensor");
    expect_equal(&baseline, &candidate, 3)?;
    expect_equal(&baseline, &baseline, 3)
}

#[test]
fn display_names_and_redundant_eop1_hash_fields_do_not_matter() -> TestResult {
    let baseline = standard_run([1, 2, 3], "Sensor");
    let mut renamed = standard_run([1, 2, 3], "Probe");
    renamed.plugins[1].name = "Beta Display Name";
    expect_equal(&baseline, &renamed, 3)?;
    let mut rehashed = standard_run([1, 2, 3], "Sensor");
    rehashed.plugins[0].hint = 9;
    expect_equal(&baseline, &rehashed, 3)
}

#[test]
fn empty_rosters_are_equal_and_empty_against_nonempty_names_the_slot() -> TestResult {
    let empty = ManifestPluginRosterV1::new(Vec::new())?;
    let full = make_roster(&standard_run([1, 2, 3], "Sensor"))?;
    assert_eq!(compare_rosters(&empty, &empty), Ok(0));
    assert_eq!(compare_rosters(&empty, &full), Err(unexpected("alpha")));
    assert_eq!(compare_rosters(&full, &empty), Err(missing("alpha")));
    Ok(())
}

#[test]
fn missing_and_extra_rows_name_the_first_slot_in_slot_order() -> TestResult {
    let baseline = standard_run([1, 2, 3], "Sensor");
    expect(&baseline, &without("beta"), missing("beta"))?;
    let mut only_gamma = standard_plugins([1, 2, 3], "Sensor");
    only_gamma.retain(|plugin| plugin.slot == "gamma");
    expect(&baseline, &run_of(only_gamma), missing("alpha"))?;
    let mut with_delta = standard_plugins([1, 2, 3], "Sensor");
    with_delta.push(plugin("delta", 4, "Sensor", &["delta.out"]));
    expect(&baseline, &run_of(with_delta), unexpected("delta"))
}

#[test]
fn a_missing_slot_is_reported_before_an_unexpected_one() -> TestResult {
    expect(&without("gamma"), &without("beta"), missing("beta"))
}

type Edit = fn(&mut Run);

// Each case changes exactly one compared field of slot `alpha` and nothing else.
fn policy_cases() -> [(Field, &'static str, Edit); 15] {
    let scalars = "executable-budget scalar fields";
    let fidelities = "executable-budget fidelity budgets";
    [
        (Field::Version, "registered version", |run| {
            run.plugins[0].version = "2.0.0";
        }),
        (Field::EventTypeSet, "owned Event-type set", |run| {
            run.plugins[0].events = vec!["other.out"];
        }),
        (Field::Declarations, "output declarations", |run| {
            run.plugins[0].limit = 8192;
        }),
        (Field::PolicyRevision, "policy revision", |run| {
            run.plugins[0].revision = 2;
        }),
        (Field::ImplementationArtifact, "implementation artifact", |run| {
            run.plugins[0].implementation = b"implementation-2".to_vec();
        }),
        (Field::ConfigurationArtifact, "base configuration artifact", |run| {
            run.plugins[0].configuration = b"configuration-2".to_vec();
        }),
        (Field::ExecutionProfileArtifact, "execution-profile artifact", |run| {
            run.plugins[0].profile = Vec::new();
        }),
        (Field::RetentionPolicy, "retention policy", |run| {
            run.plugins[0].total_days = 400;
        }),
        (Field::BudgetScalars, scalars, |run| run.budget.revision = 2),
        (Field::BudgetScalars, scalars, |run| {
            run.budget.workload = WorkloadProfileV1::Research;
        }),
        (Field::BudgetScalars, scalars, |run| {
            run.budget.max_event_bytes = 2048;
        }),
        (Field::BudgetScalars, scalars, |run| run.budget.profile_hash = 8),
        (Field::BudgetScalars, scalars, |run| run.budget.wall_us = 2_000),
        (Field::FidelityBudgets, fidelities, |run| run.budget.events[0] = 101),
        (Field::FidelityBudgets, fidelities, |run| run.budget.bytes[2] = 200_000),
    ]
}

#[test]
fn every_compared_field_is_reported_with_its_slot_and_label() -> TestResult {
    for (field, label, edit) in policy_cases() {
        let baseline = standard_run([1, 2, 3], "Sensor");
        let mut candidate = standard_run([30, 20, 10], "Sensor");
        edit(&mut candidate);
        let expected = mismatch("alpha", field);
        expect(&baseline, &candidate, expected.clone())?;
        expect(&candidate, &baseline, expected.clone())?;
        let text = expected.to_string();
        let parts = ["slot `alpha`", label, "baseline and candidate"];
        assert!(has_all(&text, &parts), "{text}");
        assert!(!text.contains("SECRET"), "{text}");
    }
    Ok(())
}

#[test]
fn the_first_differing_field_in_table_order_wins() -> TestResult {
    let baseline = standard_run([1, 2, 3], "Sensor");
    let mut candidate = standard_run([1, 2, 3], "Sensor");
    candidate.plugins[0].version = "2.0.0";
    candidate.plugins[0].limit = 8192;
    candidate.plugins[0].revision = 2;
    expect_at(&baseline, &candidate, "alpha", Field::Version)?;
    candidate.plugins[0].version = "1.0.0";
    expect_at(&baseline, &candidate, "alpha", Field::Declarations)?;
    candidate.plugins[0].limit = 4096;
    candidate.plugins[0].implementation = b"implementation-2".to_vec();
    expect_at(&baseline, &candidate, "alpha", Field::PolicyRevision)?;
    candidate.plugins[0].revision = 1;
    candidate.budget.wall_us = 2_000;
    let field = Field::ImplementationArtifact;
    expect_at(&baseline, &candidate, "alpha", field)
}

#[test]
fn the_first_differing_slot_wins() -> TestResult {
    let baseline = standard_run([1, 2, 3], "Sensor");
    let mut candidate = standard_run([1, 2, 3], "Sensor");
    candidate.plugins[1].revision = 2;
    candidate.plugins[2].revision = 2;
    expect_at(&baseline, &candidate, "beta", Field::PolicyRevision)?;
    candidate.plugins[0].version = "2.0.0";
    expect_at(&baseline, &candidate, "alpha", Field::Version)
}

#[test]
fn a_slot_swap_is_a_policy_mismatch_at_the_first_swapped_slot() -> TestResult {
    let baseline = standard_run([1, 2, 3], "Sensor");
    let mut candidate = standard_run([1, 2, 3], "Sensor");
    candidate.plugins.swap(0, 1);
    // The two Plugins trade places: each slot now holds the other's policy.
    candidate.plugins[0].slot = "alpha";
    candidate.plugins[1].slot = "beta";
    expect_at(&baseline, &candidate, "alpha", Field::EventTypeSet)
}

#[test]
fn a_reducer_only_plugin_compares_by_its_empty_event_set() -> TestResult {
    let baseline = standard_run([1, 2, 3], "Sensor");
    let mut candidate = standard_run([1, 2, 3], "Sensor");
    candidate.plugins[2].events = vec!["gamma.out"];
    expect_at(&baseline, &candidate, "gamma", Field::EventTypeSet)
}

fn swapped_values(run: &mut Run) {
    let (first, second) = (run.budget.rows[0].1, run.budget.rows[1].1);
    run.budget.rows[0].1 = second;
    run.budget.rows[1].1 = first;
}

#[test]
fn reservation_tables_must_match_by_slot() -> TestResult {
    let baseline = standard_run([1, 2, 3], "Sensor");
    let differs = reservation("alpha", None, Kind::TableDiffers);
    let mut swapped = standard_run([30, 20, 10], "Sensor");
    swapped_values(&mut swapped);
    expect(&baseline, &swapped, differs.clone())?;
    let mut missing_row = standard_run([1, 2, 3], "Sensor");
    missing_row.budget.rows.truncate(2);
    expect(&baseline, &missing_row, differs.clone())?;
    expect(&missing_row, &baseline, differs.clone())?;
    let mut changed = standard_run([1, 2, 3], "Sensor");
    changed.budget.rows[2].1 = [121, 220, 320];
    expect(&baseline, &changed, differs.clone())?;
    let text = differs.to_string();
    assert!(has_all(&text, &["slot `alpha`", "both runs"]), "{text}");
    Ok(())
}

#[test]
fn an_unbound_reservation_owner_names_its_side() -> TestResult {
    let clean = standard_run([1, 2, 3], "Sensor");
    let mut extra = standard_run([1, 2, 3], "Sensor");
    extra.budget.rows.push((99, [1, 1, 1]));
    let unbound = |side| reservation("alpha", Some(side), Kind::UnboundOwner);
    expect(&clean, &extra, unbound(Side::Candidate))?;
    expect(&extra, &clean, unbound(Side::Baseline))?;
    let text = unbound(Side::Candidate).to_string();
    let parts = ["slot `alpha`", "(in candidate)"];
    assert!(has_all(&text, &parts), "{text}");
    Ok(())
}

fn with_own(run: &mut Run, edit: fn(&mut Budget)) {
    let mut own = run.budget.clone();
    edit(&mut own);
    run.plugins[1].own = Some(own);
}

#[test]
fn closures_sharing_a_profile_must_agree_on_budget_and_table() -> TestResult {
    let edits: [Edit; 3] = [
        |run| with_own(run, |own| own.max_event_bytes = 2048),
        |run| with_own(run, |own| own.events[1] = 50),
        |run| with_own(run, |own| own.rows[2].1 = [9, 9, 9]),
    ];
    let conflict = |side| reservation("beta", Some(side), Kind::ConflictingProfile);
    for edit in edits {
        let mut both = standard_run([1, 2, 3], "Sensor");
        edit(&mut both);
        expect(&both, &both, conflict(Side::Baseline))?;
    }
    let clean = standard_run([1, 2, 3], "Sensor");
    let mut table_only = standard_run([1, 2, 3], "Sensor");
    with_own(&mut table_only, |own| own.rows[2].1 = [9, 9, 9]);
    expect(&clean, &table_only, conflict(Side::Candidate))?;
    let text = conflict(Side::Baseline).to_string();
    assert!(has_all(&text, &["slot `beta`", "(in baseline)"]), "{text}");
    Ok(())
}

#[test]
fn different_execution_profiles_are_grouped_apart() -> TestResult {
    let mut baseline = standard_run([1, 2, 3], "Sensor");
    with_own(&mut baseline, |own| {
        own.profile_hash = 8;
        own.max_event_bytes = 2048;
        own.events[1] = 50;
        own.rows[2].1 = [9, 9, 9];
    });
    expect_equal(&baseline, &baseline, 3)
}

type DraftEdit = fn(&mut Draft);

fn closure_cases() -> [(Problem, DraftEdit); 8] {
    [
        (Problem::Empty, |draft| draft.raw = Some(Vec::new())),
        (Problem::Envelope, |draft| draft.raw = Some(SECRET.to_vec())),
        (Problem::UndecodableEop1, |draft| draft.members[0] = SECRET.to_vec()),
        (Problem::ForeignEop1, |draft| draft.digest = hash(9)),
        (Problem::ForeignEop1, |draft| draft.id = 77),
        (Problem::ForeignEop1, |draft| draft.version = "9.9.9".to_owned()),
        (Problem::UndecodableBudget, |draft| draft.members[1] = SECRET.to_vec()),
        (Problem::UndecodableRetention, |draft| draft.members[5] = SECRET.to_vec()),
    ]
}

#[test]
fn an_unusable_closure_names_its_slot_side_and_problem() -> TestResult {
    let run = standard_run([1, 2, 3], "Sensor");
    let clean = make_roster(&run)?;
    for (problem, edit) in closure_cases() {
        let broken = make_roster_edited(&run, "beta", edit)?;
        let later = closure_error("beta", Side::Candidate, problem);
        assert_eq!(compare_rosters(&clean, &broken), Err(later.clone()));
        let earlier = closure_error("beta", Side::Baseline, problem);
        assert_eq!(compare_rosters(&broken, &clean), Err(earlier.clone()));
        let (left, right) = (later.to_string(), earlier.to_string());
        assert!(has_all(&left, &["`beta`", "candidate closure"]), "{left}");
        assert!(has_all(&right, &["`beta`", "baseline closure"]), "{right}");
        assert!(!left.contains("SECRET"), "{left}");
        assert!(!right.contains("SECRET"), "{right}");
    }
    Ok(())
}

fn empty_closure(draft: &mut Draft) {
    draft.raw = Some(Vec::new());
}

#[test]
fn the_baseline_closure_is_checked_before_the_candidate_closure() -> TestResult {
    let run = standard_run([1, 2, 3], "Sensor");
    let baseline = make_roster_edited(&run, "alpha", empty_closure)?;
    let candidate = make_roster_edited(&run, "alpha", |draft| draft.raw = Some(vec![1]))?;
    let expected = closure_error("alpha", Side::Baseline, Problem::Empty);
    assert_eq!(compare_rosters(&baseline, &candidate), Err(expected));
    Ok(())
}

#[test]
fn check_order_is_slots_then_closures_then_policy_then_reservations() -> TestResult {
    let baseline = standard_run([1, 2, 3], "Sensor");
    let clean = make_roster(&baseline)?;
    let mut changed = standard_run([1, 2, 3], "Sensor");
    changed.plugins[0].version = "2.0.0";
    changed.budget.rows[0].1 = [1, 1, 1];
    // A closure problem at beta is reported before the policy change at alpha.
    let broken = make_roster_edited(&changed, "beta", empty_closure)?;
    let expected = closure_error("beta", Side::Candidate, Problem::Empty);
    assert_eq!(compare_rosters(&clean, &broken), Err(expected));
    // A policy change is reported before the reservation difference.
    expect(&baseline, &changed, mismatch("alpha", Field::Version))?;
    // A missing slot is reported before a closure problem at another slot.
    let partial = make_roster_edited(&without("beta"), "alpha", empty_closure)?;
    assert_eq!(compare_rosters(&clean, &partial), Err(missing("beta")));
    Ok(())
}

#[test]
fn error_messages_say_what_to_change_without_ids_or_bytes() {
    let cases = [
        (missing("alpha"), "register"),
        (unexpected("alpha"), "remove"),
        (mismatch("alpha", Field::Version), "rebuild both runs"),
        (closure_error("alpha", Side::Baseline, Problem::ForeignEop1), "retain"),
        (reservation("alpha", Some(Side::Candidate), Kind::UnboundOwner), "add the reserved"),
        (reservation("alpha", None, Kind::TableDiffers), "rebuild both runs"),
    ];
    for (error, hint) in cases {
        let text = error.to_string();
        assert!(has_all(&text, &["slot `alpha`", hint]), "{text}");
    }
}
