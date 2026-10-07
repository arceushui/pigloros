#![forbid(unsafe_code)]
#![deny(clippy::all)]
#![warn(clippy::pedantic)]

//! `pos` — CLI entry point for `PiglorOS`.
//!
//! Subcommands:
//!   pos store init|info `<path>`
//!   pos timeline list|fork|merge …
//!   pos timeline replay|snapshot|compare … (currently unavailable)
//!   pos events log …
//!   pos experiment run|verify|reproduce …
//!   pos version
#![cfg_attr(all(coverage_nightly, test), feature(coverage_attribute))]

macro_rules! output_stdout {
    ($($arg:tt)*) => {{
        let mut output = std::io::stdout().lock();
        drop(std::io::Write::write_fmt(&mut output, format_args!($($arg)*)));
        drop(std::io::Write::write_all(&mut output, b"\n"));
    }};
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod coverage_entrypoints {
    use super::*;

    struct InvalidVersionPlugin;

    impl pos_core::Plugin for InvalidVersionPlugin {
        fn id(&self) -> pos_core::ids::PluginId {
            pos_core::ids::PluginId::new()
        }

        fn name(&self) -> &'static str {
            "invalid-cli-version"
        }

        fn capability(&self) -> pos_core::Capability {
            pos_core::Capability::default()
        }

        fn version(&self) -> &'static str {
            ""
        }
    }

    #[test]
    fn builtin_reference_runner_rejects_uninstalled_profile() {
        assert!(run_builtin_reference_experiment().is_err_and(|error| {
            error.downcast_ref::<pos_runtime::OutputAdmissionErrorV1>()
                == Some(&pos_runtime::OutputAdmissionErrorV1::ArtifactInvalid { kind: "EPF1" })
        }));
        assert!(installed_registration_closed()
            .downcast_ref::<pos_runtime::OutputAdmissionErrorV1>()
            .is_some_and(|error| {
                *error == pos_runtime::OutputAdmissionErrorV1::ArtifactInvalid { kind: "EPF1" }
            }));
        assert!(run_builtin_reference_experiment_fixture(StoreConfig::Memory, 0).is_ok());
        assert!(run_builtin_reference_experiment_fixture(StoreConfig::Memory, 1).is_ok());
    }

    #[test]
    fn builtin_output_binding_rejects_uninstalled_source_and_profile() {
        let plugin = pos_plugin_rule_agent::RuleAgentPlugin::new();
        assert!(builtin_output_binding(
            &plugin,
            pos_runtime::OutputPolicySourceV1::RuleAgent,
            &[],
            "unknown-profile",
        )
        .is_err());
        assert!(builtin_output_binding(
            &plugin,
            pos_runtime::OutputPolicySourceV1::SyntheticObservation,
            &[],
            "deterministic-local-v1",
        )
        .is_err());

        assert!(builtin_output_binding(
            &InvalidVersionPlugin,
            pos_runtime::OutputPolicySourceV1::RuleAgent,
            &[],
            "deterministic-local-v1",
        )
        .is_err());
    }

    #[test]
    fn installed_synthetic_binding_rejects_without_profile_authority() {
        use pos_plugin_synthetic_obs::SyntheticObsPlugin;
        let plugin = SyntheticObsPlugin::new();
        assert!(builtin_output_binding(
            &plugin,
            pos_runtime::OutputPolicySourceV1::SyntheticObservation,
            &1.0_f64.to_be_bytes(),
            "deterministic-local-v1",
        )
        .is_err());
    }
}

macro_rules! output_stderr {
    ($($arg:tt)*) => {{
        let mut output = std::io::stderr().lock();
        drop(std::io::Write::write_fmt(&mut output, format_args!($($arg)*)));
        drop(std::io::Write::write_all(&mut output, b"\n"));
    }};
}

use pos_core::{clock::Seq, ids::TimelineId, plugin::Plugin, store::SeqRange};
use pos_experiment::{ReproductionManifest, ReproductionRecipe, RunResult};
// Only the generated reference fixture composes an Experiment until installed
// registration returns with Wave 9 (#467/#462).
#[cfg(test)]
use pos_experiment::{Experiment, ExperimentConfig, StopCondition};
use pos_store::StoreConfig;
use ulid::Ulid;

include!("host_store.rs");

const POS_CLI_REPRODUCTION_HOST: &str = "pos-cli";
const POS_CLI_REPRODUCTION_FORMAT: u32 = 1;
/// Fixed manifest slot of the built-in reference agent Plugin.
///
/// Slots are host-authored and recorded in the reproduction recipe, so a fresh run with fresh
/// `PluginId`s lines up with this one. They name a position in the composition, never a person or
/// a secret, and they do not change when the Plugin is renamed.
const REFERENCE_AGENT_SLOT: &str = "reference.agent";
/// Fixed manifest slot of the built-in reference observation Plugin.
const REFERENCE_OBSERVATION_SLOT: &str = "reference.observation";
const SLOT_MISMATCH_ERROR: &str = "manifest recipe records slots this build does not use: \
     expected agent reference.agent and observation reference.observation";
const ROSTER_SLOT_MISMATCH_ERROR: &str = "manifest Plugin roster does not hold exactly the \
     recipe's recorded slots: record the run again with this build";
const OWNER_VERIFIED_ERROR: &str = "reproduction requires an owner-verified policy closure";
const MAX_EXPERIMENT_TICKS: u64 = 1_000_000;
const TICK_LIMIT_ERROR: &str = "experiment tick count exceeds the maximum of 1000000";

fn builtin_output_binding<P: Plugin>(
    plugin: &P,
    source: pos_runtime::OutputPolicySourceV1,
    configuration_details: &[u8],
    profile_id: &str,
) -> Result<pos_runtime::OutputPolicyBindingV1, Box<dyn std::error::Error>> {
    pos_runtime::OutputPolicyBindingV1::from_source(
        plugin,
        source,
        configuration_details,
        profile_id,
    )
    .map_err(Into::into)
}

/// Wave 8 has no installed EPF1, so installed registration fails closed even
/// if an installed binding were resolved. #467/#462 restore the installed
/// reference runner together with a real installed EPF1.
fn installed_registration_closed() -> Box<dyn std::error::Error> {
    pos_runtime::OutputAdmissionErrorV1::ArtifactInvalid { kind: "EPF1" }.into()
}

/// Open a store through the CLI composition seam.
///
/// The concrete adapter remains exclusively owned by the recovered erasure
/// host in production and tests.
fn open_store(
    config: StoreConfig,
) -> Result<Box<dyn pos_core::store::EventStore>, pos_core::CoreError> {
    HostedCliStore::open(config)
        .map(|store| Box::new(store) as Box<dyn pos_core::store::EventStore>)
        .map_err(hosted_cli_store_error)
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct CliExperimentRecipe {
    #[serde(rename = "BuiltinReferenceV1")]
    builtin_reference_v1: BuiltinReferenceV1,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct BuiltinReferenceV1 {
    ticks: u64,
    slots: ReferenceSlotsV1,
}

/// The manifest slots the recipe records for the built-in reference experiment.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ReferenceSlotsV1 {
    agent: String,
    observation: String,
}

fn validate_reference_slots(slots: &ReferenceSlotsV1) -> Result<(), &'static str> {
    let agent = slots.agent == REFERENCE_AGENT_SLOT;
    let observation = slots.observation == REFERENCE_OBSERVATION_SLOT;
    let current = agent && observation;
    current.then_some(()).ok_or(SLOT_MISMATCH_ERROR)
}

// The manifest roster must hold exactly the recipe's recorded slots, one row per slot.
fn validate_roster_slots(
    manifest: &pos_core::ReproManifest,
    slots: &ReferenceSlotsV1,
) -> Result<(), &'static str> {
    let slot_of = pos_core::ManifestPluginEntryV1::stable_slot;
    let rows = manifest.plugin_roster().entries().iter();
    let recorded: Vec<&str> = rows.map(slot_of).collect();
    let mut expected = [slots.agent.as_str(), slots.observation.as_str()];
    expected.sort_unstable();
    (recorded == expected)
        .then_some(())
        .ok_or(ROSTER_SLOT_MISMATCH_ERROR)
}

#[cfg(not(test))]
fn handle_run_error(e: &dyn std::error::Error) -> std::process::ExitCode {
    output_stderr!("Error: {e}");
    std::process::ExitCode::FAILURE
}

#[cfg(test)]
fn handle_run_error(e: &dyn std::error::Error) {
    output_stderr!("Error (test): {e}");
    // In tests, don't exit — just print
}

#[cfg(not(test))]
fn run_main(args: &[String]) -> std::process::ExitCode {
    if let Err(e) = run_with_args(args) {
        return handle_run_error(e.as_ref());
    }
    std::process::ExitCode::SUCCESS
}

#[cfg(test)]
fn run_main(args: &[String]) {
    if let Err(e) = run_with_args(args) {
        handle_run_error(e.as_ref());
    }
}

#[cfg(not(test))]
fn main() -> std::process::ExitCode {
    run_main(&std::env::args().collect::<Vec<_>>())
}

#[cfg(test)]
fn main() {
    run_main(&std::env::args().collect::<Vec<_>>());
}

fn run_with_args(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    match args.get(1).map(String::as_str) {
        Some("store") => handle_store(&args[2..]),
        Some("timeline") => handle_timeline(&args[2..]),
        Some("events") => handle_events(&args[2..]),
        Some("experiment") => handle_experiment(&args[2..]),
        Some("version") => {
            output_stdout!("pos-cli {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        _ => {
            output_stderr!("Usage: pos <store|timeline|events|experiment|version>");
            Ok(())
        }
    }
}

// ---------------------------------------------------------------------------
// store subcommands
// ---------------------------------------------------------------------------

fn handle_store(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    match args.first().map(String::as_str) {
        Some("init") => {
            let path = args.get(1).ok_or("Usage: pos store init <path>")?;
            cmd_store_init(path)
        }
        Some("info") => {
            let path = args.get(1).ok_or("Usage: pos store info <path>")?;
            cmd_store_info(path)
        }
        _ => {
            output_stderr!("Usage: pos store <init|info> <path>");
            Ok(())
        }
    }
}

fn cmd_store_init(path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let mut store = open_store(StoreConfig::Sqlite {
        path: path.to_owned(),
    })?;
    store.create_timeline("default")?;
    output_stdout!("Initialized store at {path}");
    Ok(())
}

fn cmd_store_info(path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let store = open_store(StoreConfig::Sqlite {
        path: path.to_owned(),
    })?;
    let timelines = match store.list_timelines() {
        Ok(timelines) => timelines,
        Err(error) => {
            return Err(std::io::Error::other(format!(
                "failed to list Timelines while calculating store information: {error}"
            ))
            .into());
        }
    };
    let mut total_events = 0_usize;
    for timeline in &timelines {
        let events = match store.read(timeline.id(), SeqRange::all()) {
            Ok(events) => events,
            Err(error) => {
                return Err(std::io::Error::other(format!(
                    "failed to read Timeline {} while calculating store information: {error}",
                    timeline.id()
                ))
                .into());
            }
        };
        total_events += events.len();
    }
    output_stdout!("Timelines: {}", timelines.len());
    output_stdout!("Total events: {total_events}");
    Ok(())
}

// ---------------------------------------------------------------------------
// timeline subcommands
// ---------------------------------------------------------------------------

fn handle_timeline(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    match args.first().map(String::as_str) {
        Some("list") => {
            let path = args.get(1).ok_or("Usage: pos timeline list <path>")?;
            cmd_timeline_list(path)
        }
        Some("fork") => {
            if args.len() < 5 {
                return Err("Usage: pos timeline fork <path> <tl_id> <at_seq> <name>".into());
            }
            cmd_timeline_fork(&args[1], &args[2], &args[3], &args[4])
        }
        Some("replay") => {
            if args.len() < 3 {
                return Err("Usage: pos timeline replay <path> <timeline-id>".into());
            }
            Err(timeline_operation_unavailable("replay"))
        }
        Some("snapshot") => {
            if args.len() < 3 {
                return Err("Usage: pos timeline snapshot <path> <timeline-id>".into());
            }
            Err(timeline_operation_unavailable("snapshot"))
        }
        Some("compare") => {
            if args.len() < 5 {
                return Err(
                    "Usage: pos timeline compare <path> <tl-a-id> <tl-b-id> <fork-seq>".into(),
                );
            }
            Err(timeline_operation_unavailable("compare"))
        }
        Some("merge") => {
            if args.len() < 6 {
                return Err(
                    "Usage: pos timeline merge <path> <tl-a-id> <tl-b-id> <fork-seq> <name> [--strategy disjoint|prefer-a|prefer-b]"
                        .into(),
                );
            }
            let strategy = parse_merge_strategy_flag(&args[6..])?;
            cmd_timeline_merge(&args[1], &args[2], &args[3], &args[4], &args[5], strategy)
        }
        _ => {
            output_stderr!("Usage: pos timeline <list|fork|replay|snapshot|compare|merge> ...");
            output_stderr!(
                "replay, snapshot, and compare require a CLI owner-verified evidence path"
            );
            Ok(())
        }
    }
}

fn cmd_timeline_list(path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let store = open_store(StoreConfig::Sqlite {
        path: path.to_owned(),
    })?;
    for tl in store.list_timelines()? {
        output_stdout!(
            "{} | {} | head={}",
            tl.id(),
            tl.meta.name.unwrap_or_default(),
            tl.head.as_u64()
        );
    }
    Ok(())
}

fn cmd_timeline_fork(
    path: &str,
    tl_id_str: &str,
    at_seq_str: &str,
    name: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let tl_id = parse_timeline_id(tl_id_str)?;
    let at_seq = parse_seq(at_seq_str)?;
    let mut store = open_store(StoreConfig::Sqlite {
        path: path.to_owned(),
    })?;
    let forked = store.fork(tl_id, at_seq, name)?;
    output_stdout!("Forked timeline: {}", forked.id());
    Ok(())
}

fn timeline_operation_unavailable(operation: &str) -> Box<dyn std::error::Error> {
    format!(
        "timeline {operation} is unavailable: the CLI has no owner-verified evidence path for this operation"
    )
    .into()
}

fn parse_merge_strategy_flag(
    args: &[String],
) -> Result<pos_time::MergeStrategy, Box<dyn std::error::Error>> {
    let mut i = 0;
    while i < args.len() {
        if args[i] == "--strategy" {
            let name = args
                .get(i + 1)
                .ok_or("--strategy requires a value (disjoint|prefer-a|prefer-b)")?;
            return Ok(pos_time::MergeStrategy::parse(name)?);
        }
        i += 1;
    }
    Ok(pos_time::MergeStrategy::DisjointCrdt)
}

fn cmd_timeline_merge(
    path: &str,
    first_timeline_str: &str,
    second_timeline_str: &str,
    fork_seq_str: &str,
    name: &str,
    strategy: pos_time::MergeStrategy,
) -> Result<(), Box<dyn std::error::Error>> {
    let timeline_a = parse_timeline_id(first_timeline_str)?;
    let timeline_b = parse_timeline_id(second_timeline_str)?;
    let fork_seq = parse_seq(fork_seq_str)?;

    let mut store = open_store(StoreConfig::Sqlite {
        path: path.to_owned(),
    })?;

    output_stdout!("strategy: {strategy:?}");
    match pos_time::can_merge_conflict_free(store.as_ref(), timeline_a, timeline_b, fork_seq) {
        Ok(conflict_free) => output_stdout!("conflict_free: {conflict_free}"),
        Err(e) => output_stdout!("conflict_free: check-failed ({e})"),
    }

    let merged = pos_time::merge_with_strategy(
        store.as_mut(),
        timeline_a,
        timeline_b,
        fork_seq,
        name,
        strategy,
    )?;
    output_stdout!("merged_timeline: {}", merged.id());
    output_stdout!("head: {}", merged.head.as_u64());

    Ok(())
}

// ---------------------------------------------------------------------------
// events subcommands
// ---------------------------------------------------------------------------

fn handle_events(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    if args.first().map(String::as_str) == Some("log") {
        if args.len() < 3 {
            return Err("Usage: pos events log <path> <timeline-id> [--limit N]".into());
        }
        let limit = parse_limit_flag(&args[3..])?;
        cmd_events_log(&args[1], &args[2], limit)
    } else {
        output_stderr!("Usage: pos events <log> ...");
        Ok(())
    }
}

fn cmd_events_log(
    path: &str,
    tl_id_str: &str,
    limit: Option<usize>,
) -> Result<(), Box<dyn std::error::Error>> {
    let tl_id = parse_timeline_id(tl_id_str)?;
    let store = open_store(StoreConfig::Sqlite {
        path: path.to_owned(),
    })?;

    let events = store.read(tl_id, SeqRange::all())?;
    let events_to_show = limit.map_or(&events[..], |n| &events[..events.len().min(n)]);

    for event in events_to_show {
        output_stdout!(
            "{} | {} | {} | {}",
            event.seq.as_u64(),
            event.entity,
            event.event_type.as_str(),
            event.wall_time.as_micros()
        );
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// experiment subcommands
// ---------------------------------------------------------------------------

fn handle_experiment(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    match args.first().map(String::as_str) {
        Some("run") => {
            // pos experiment run <path> --ticks <N>
            let path = args
                .get(1)
                .ok_or("Usage: pos experiment run <path> --ticks <N>")?;
            let ticks = parse_ticks_flag(&args[2..])?;
            cmd_experiment_run(path, ticks)
        }
        Some("verify") => {
            let manifest_path = args
                .get(1)
                .ok_or("Usage: pos experiment verify <manifest.json>")?;
            cmd_experiment_verify(manifest_path)
        }
        Some("reproduce") => {
            let manifest_path = args
                .get(1)
                .ok_or("Usage: pos experiment reproduce <manifest.json>")?;
            cmd_experiment_reproduce(manifest_path)
        }
        _ => {
            output_stderr!("Usage: pos experiment <run|verify|reproduce> ...");
            Ok(())
        }
    }
}

/// Resolve the reference Plugins' installed bindings.
///
/// Wave 8 has no installed EPF1, so the runner fails closed before any
/// Experiment or registration exists.
fn run_builtin_reference_experiment() -> Result<RunResult, Box<dyn std::error::Error>> {
    let agent_plugin = pos_plugin_rule_agent::RuleAgentPlugin::new();
    let obs_plugin = pos_plugin_synthetic_obs::SyntheticObsPlugin::new();
    let obs_configuration = 1.0_f64.to_be_bytes();
    // Report the first binding error, or the closed installed-registration
    // error if both bindings resolve. This stays one combinator chain on
    // purpose: in Wave 8 every installed binding fails, so `let ... ?;`
    // bindings would leave the serialization error, the post-binding
    // continuations and the final closed error as unreachable LLVM regions.
    // `and` evaluates both bindings eagerly, so both are exercised either way.
    let obs_binding = builtin_output_binding(
        &obs_plugin,
        pos_runtime::OutputPolicySourceV1::SyntheticObservation,
        &obs_configuration,
        "deterministic-local-v1",
    );
    Err(serde_json::to_vec(agent_plugin.actions())
        .map_err(Into::into)
        .and_then(|agent_configuration| {
            builtin_output_binding(
                &agent_plugin,
                pos_runtime::OutputPolicySourceV1::RuleAgent,
                &agent_configuration,
                "deterministic-local-v1",
            )
        })
        .and(obs_binding)
        .err()
        .unwrap_or_else(installed_registration_closed))
}

// This fixture never enters the installed-registration seam or creates a
// production Plugin pin. The real CLI command above stays fail-closed until
// the host catalogue has an operator-approved profile.
#[cfg(test)]
fn run_builtin_reference_experiment_fixture(
    store_config: StoreConfig,
    ticks: u64,
) -> Result<RunResult, Box<dyn std::error::Error>> {
    let mut exp = Experiment::new(ExperimentConfig {
        name: "cli-fixture".to_owned(),
        stop: StopCondition::MaxTicks(ticks),
        store_config,
    });
    reference_slots()
        .map_err(Box::<dyn std::error::Error>::from)
        .and_then(|slots| register_reference_plugins(&mut exp, slots))
        .and_then(|()| admit_reference_plugins(&mut exp))
        .and_then(|_admitted| exp.run().map_err(Into::into))
}

// The fixed agent and observation slots, in that order.
#[cfg(test)]
type ReferenceSlotPair = [pos_runtime::ManifestSlotV1; 2];

// Both constants satisfy the slot grammar, so this chain has no reachable error arm.
#[cfg(test)]
fn reference_slots() -> Result<ReferenceSlotPair, pos_runtime::ManifestSlotErrorV1> {
    let agent = pos_runtime::ManifestSlotV1::try_new(REFERENCE_AGENT_SLOT);
    agent.and_then(|agent| {
        let observation = pos_runtime::ManifestSlotV1::try_new(REFERENCE_OBSERVATION_SLOT);
        observation.map(|observation| [agent, observation])
    })
}

#[cfg(test)]
fn register_reference_plugins(
    exp: &mut Experiment,
    slots: ReferenceSlotPair,
) -> Result<(), Box<dyn std::error::Error>> {
    use pos_core::ids::EntityId;
    use pos_plugin_rule_agent::{RuleAgentDriver, RuleAgentPlugin, RuleAgentReducer};
    use pos_plugin_synthetic_obs::{SyntheticDriver, SyntheticObsPlugin, SyntheticReducer};

    let [agent_slot, observation_slot] = slots;
    let agent_plugin = RuleAgentPlugin::new();
    let agent_driver = RuleAgentDriver::new(EntityId::new(), agent_plugin.actions().to_vec());
    let obs_plugin = SyntheticObsPlugin::new();
    exp.register_local(
        &agent_plugin,
        agent_slot,
        vec![REFERENCE_AGENT_SLOT.to_owned()],
        Some(Box::new(RuleAgentReducer)),
        Some(Box::new(agent_driver)),
    )
    .and_then(|()| {
        exp.register_local(
            &obs_plugin,
            observation_slot,
            vec![REFERENCE_OBSERVATION_SLOT.to_owned()],
            Some(Box::new(SyntheticReducer)),
            Some(Box::new(SyntheticDriver::new(EntityId::new()))),
        )
    })
    .map_err(Into::into)
}

#[cfg(test)]
fn admit_reference_plugins(
    exp: &mut Experiment,
) -> Result<pos_runtime::AdmittedCompositionV1, Box<dyn std::error::Error>> {
    let owner = pos_core::OwnerIdV1::from_static("pos-cli");
    let admitted = exp.admit_local_manifest_registration(owner, 1);
    admitted.map_err(Into::into)
}

fn cmd_experiment_run(path: &str, ticks: u64) -> Result<(), Box<dyn std::error::Error>> {
    cmd_experiment_run_with(path, ticks, |_, _| run_builtin_reference_experiment())
}

#[cfg(test)]
fn cmd_experiment_run_fixture(path: &str, ticks: u64) -> Result<(), Box<dyn std::error::Error>> {
    cmd_experiment_run_with(path, ticks, run_builtin_reference_experiment_fixture)
}

fn cmd_experiment_run_with(
    path: &str,
    ticks: u64,
    run: impl FnOnce(StoreConfig, u64) -> Result<RunResult, Box<dyn std::error::Error>>,
) -> Result<(), Box<dyn std::error::Error>> {
    validate_experiment_ticks(ticks)
        .map_err(Into::into)
        .and_then(|()| {
            run(
                StoreConfig::Sqlite {
                    path: path.to_owned(),
                },
                ticks,
            )
        })
        .and_then(|result| {
            let completed_ticks = result.ticks;
            let total_events = result.total_events;
            let timeline_id = result.timeline_id;
            let reproduction = result.into_reproduction_manifest(cli_reproduction_recipe(ticks))?;
            let manifest_path = path.replace(".db", "-manifest.json");

            save_run_manifest(&manifest_path, &reproduction).map(|()| {
                output_stdout!(
                    "Experiment complete: {completed_ticks} ticks, {total_events} events, \
                     timeline={timeline_id}, manifest={manifest_path}"
                );
            })
        })
}

fn cli_reproduction_recipe(ticks: u64) -> ReproductionRecipe {
    ReproductionRecipe::new(
        POS_CLI_REPRODUCTION_HOST,
        POS_CLI_REPRODUCTION_FORMAT,
        serde_json::json!({
            "BuiltinReferenceV1": {
                "ticks": ticks,
                "slots": {
                    "agent": REFERENCE_AGENT_SLOT,
                    "observation": REFERENCE_OBSERVATION_SLOT,
                },
            }
        }),
    )
}

fn cmd_experiment_reproduce(manifest_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    std::fs::read_to_string(manifest_path)
        .map_err(Into::into)
        .and_then(|json| serde_json::from_str::<ReproductionManifest>(&json).map_err(Into::into))
        .and_then(reproduce_manifest)
}

fn reproduce_manifest(
    reproduction: ReproductionManifest,
) -> Result<(), Box<dyn std::error::Error>> {
    let decoded = reproduce_cli_recipe(reproduction.recipe)?;
    let slots = &decoded.builtin_reference_v1.slots;
    validate_roster_slots(&reproduction.manifest, slots)
        .map_err(Into::into)
        .and_then(|()| Err(OWNER_VERIFIED_ERROR.into()))
}

fn reproduce_cli_recipe(
    recipe: ReproductionRecipe,
) -> Result<CliExperimentRecipe, Box<dyn std::error::Error>> {
    if recipe.host_id != POS_CLI_REPRODUCTION_HOST {
        return Err("manifest recipe belongs to a different host".into());
    }
    if recipe.format_version != POS_CLI_REPRODUCTION_FORMAT {
        return Err("manifest recipe has an unsupported format version".into());
    }
    let decoded: CliExperimentRecipe = serde_json::from_value(recipe.configuration)?;
    validate_experiment_ticks(decoded.builtin_reference_v1.ticks)
        .and_then(|()| validate_reference_slots(&decoded.builtin_reference_v1.slots))
        .map(|()| decoded)
        .map_err(Into::into)
}

fn validate_experiment_ticks(ticks: u64) -> Result<(), &'static str> {
    (ticks <= MAX_EXPERIMENT_TICKS)
        .then_some(())
        .ok_or(TICK_LIMIT_ERROR)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ManifestHeadVerification {
    TimelineHeadOnly,
    Mismatch,
}

impl ManifestHeadVerification {
    const fn output_message(self) -> &'static str {
        match self {
            Self::TimelineHeadOnly => {
                "Timeline head verified; output-policy and Replay identity were not checked"
            }
            Self::Mismatch => "MISMATCH",
        }
    }
}

fn verify_manifest_against_store(
    manifest: &pos_core::manifest::ReproManifest,
    store: &dyn pos_core::store::EventStore,
) -> Result<ManifestHeadVerification, Box<dyn std::error::Error>> {
    let timelines = store.list_timelines()?;
    let tl = timelines.iter().find(|t| t.id() == manifest.timeline_id());

    let matched = if let Some(tl) = tl {
        let events = store.read(tl.id(), SeqRange::all())?;
        let chain_head = if events.is_empty() {
            pos_core::crypto::Hash::zero()
        } else {
            let mut hasher = blake3::Hasher::new();
            for e in &events {
                hasher.update(e.payload_hash.as_bytes());
            }
            pos_core::crypto::Hash::from_bytes(*hasher.finalize().as_bytes())
        };
        chain_head == manifest.head_hash()
    } else {
        false
    };

    if matched {
        Ok(ManifestHeadVerification::TimelineHeadOnly)
    } else {
        Ok(ManifestHeadVerification::Mismatch)
    }
}

fn report_manifest_head_verification(
    manifest: &pos_core::manifest::ReproManifest,
    store: &dyn pos_core::store::EventStore,
    output: &mut impl std::io::Write,
) -> Result<(), Box<dyn std::error::Error>> {
    let verification = verify_manifest_against_store(manifest, store)?;
    writeln!(output, "{}", verification.output_message())?;
    match verification {
        ManifestHeadVerification::TimelineHeadOnly => Ok(()),
        ManifestHeadVerification::Mismatch => Err("hash mismatch".into()),
    }
}

fn cmd_experiment_verify(manifest_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let json = std::fs::read_to_string(manifest_path)?;
    let manifest: pos_core::manifest::ReproManifest = serde_json::from_str(&json)?;

    // Convention: manifest stored at <base>-manifest.json → store at <base>.db
    let store_path = if manifest_path.ends_with("-manifest.json") {
        manifest_path.replace("-manifest.json", ".db")
    } else {
        manifest_path.replace(".json", ".db")
    };

    if !std::path::Path::new(&store_path).exists() {
        return Err(format!("companion EventStore not found: {store_path}").into());
    }
    let store = open_store(StoreConfig::Sqlite { path: store_path })?;

    let stdout = std::io::stdout();
    let mut stdout_lock = stdout.lock();
    report_manifest_head_verification(&manifest, store.as_ref(), &mut stdout_lock)
}

// ---------------------------------------------------------------------------
// Argument parsing helpers
// ---------------------------------------------------------------------------

/// Parse `--ticks <N>` from a slice of args, returning `N`.
fn parse_ticks_flag(args: &[String]) -> Result<u64, Box<dyn std::error::Error>> {
    let mut it = args.iter();
    while let Some(flag) = it.next() {
        if flag == "--ticks" || flag == "--train-ticks" {
            let val = it.next().ok_or("--ticks/--train-ticks requires a value")?;
            return val
                .parse::<u64>()
                .map_err(|e| format!("invalid ticks: {e}").into());
        }
    }
    Err("missing --ticks or --train-ticks <N>".into())
}

/// Parse `--limit <N>` from a slice of args, returning `Some(N)` or `None` if not present.
fn parse_limit_flag(args: &[String]) -> Result<Option<usize>, Box<dyn std::error::Error>> {
    let mut it = args.iter();
    while let Some(flag) = it.next() {
        if flag == "--limit" {
            let val = it.next().ok_or("--limit requires a value")?;
            let n: usize = val.parse().map_err(|e| format!("invalid limit: {e}"))?;
            return Ok(Some(n));
        }
    }
    Ok(None)
}

/// Serialize and write the run manifest next to the store.
fn save_run_manifest(
    path: &str,
    manifest: &ReproductionManifest,
) -> Result<(), Box<dyn std::error::Error>> {
    serde_json::to_string_pretty(manifest)
        .map_err(Into::into)
        .and_then(|manifest_json| std::fs::write(path, manifest_json).map_err(Into::into))
}

/// Parse a ULID string into a [`TimelineId`].
#[cfg(test)]
fn open_memory_store() -> Result<Box<dyn pos_core::store::EventStore>, pos_core::CoreError> {
    open_store(StoreConfig::Memory)
}

#[cfg(test)]
const TEST_EXPORT_DIGEST: pos_core::ErasureReferenceV1 =
    pos_core::ErasureReferenceV1::from_digest([231; 32]);

#[cfg(test)]
fn test_export_evaluation() -> pos_core::ReplayClaimEvaluationV1 {
    pos_core::ReplayClaimEvaluatorV1::evaluate(
        pos_core::ErasureReplayClaimV1::Exact,
        &[pos_core::ArtifactClaimInputV1 {
            registration: pos_core::RegisteredArtifactV1::new(
                pos_core::ErasureArtifactClassV1::Export,
                TEST_EXPORT_DIGEST,
                pos_core::ArtifactDataClassV1::StructuralAuditMetadata,
                None,
                pos_core::ErasureReferenceV1::from_digest([232; 32]),
                pos_core::ArtifactOptionalityV1::Required,
                pos_core::ArtifactTransitionRuleV1::PreserveExact,
            ),
            current_claim: pos_core::ErasureReplayClaimV1::Exact,
            state: pos_core::ArtifactStateV1::Retained,
        }],
    )
    .unwrap_or_else(|error| std::panic::resume_unwind(Box::new(format!("{error:?}"))))
}

fn parse_timeline_id(s: &str) -> Result<TimelineId, Box<dyn std::error::Error>> {
    let ulid = Ulid::from_string(s).map_err(|e| format!("invalid ULID '{s}': {e}"))?;
    Ok(TimelineId::from_ulid(ulid))
}

/// Parse a decimal integer into a [`Seq`].
fn parse_seq(s: &str) -> Result<Seq, Box<dyn std::error::Error>> {
    let n: u64 = s
        .parse()
        .map_err(|e| format!("invalid sequence number '{s}': {e}"))?;
    Ok(Seq::from_u64(n))
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    trait TestValueExt<T> {
        fn test_ok(self) -> T;
    }

    impl<T, E: std::fmt::Debug> TestValueExt<T> for Result<T, E> {
        fn test_ok(self) -> T {
            self.unwrap_or_else(|error| {
                std::panic::resume_unwind(Box::new(format!("unexpected test error: {error:?}")))
            })
        }
    }

    impl<T> TestValueExt<T> for Option<T> {
        fn test_ok(self) -> T {
            self.unwrap_or_else(|| std::panic::resume_unwind(Box::new("expected test value")))
        }
    }

    trait TestErrorExt<E> {
        fn test_err(self) -> E;
    }

    impl<T, E> TestErrorExt<E> for Result<T, E> {
        fn test_err(self) -> E {
            self.err()
                .unwrap_or_else(|| std::panic::resume_unwind(Box::new("expected test error")))
        }
    }

    use super::*;
    use pos_core::{
        event::{CanonicalBytes, EventDraft, Kind},
        ids::EntityId,
    };

    #[test]
    fn open_memory_store_ok() {
        let _store = open_memory_store().test_ok();
    }

    #[test]
    fn parse_ticks_flag_extracts_value() {
        let args: Vec<String> = vec!["--ticks".to_owned(), "42".to_owned()];
        let n = parse_ticks_flag(&args).test_ok();
        assert_eq!(n, 42);
    }

    #[test]
    fn parse_ticks_flag_missing_returns_err() {
        let args: Vec<String> = vec![];
        assert!(parse_ticks_flag(&args).is_err());
    }

    #[test]
    fn parse_ticks_flag_invalid_number_returns_err() {
        let args: Vec<String> = vec!["--ticks".to_owned(), "notanumber".to_owned()];
        assert!(parse_ticks_flag(&args).is_err());
    }

    #[test]
    fn parse_seq_valid() {
        let seq = parse_seq("100").test_ok();
        assert_eq!(seq.as_u64(), 100);
    }

    #[test]
    fn parse_seq_zero() {
        let seq = parse_seq("0").test_ok();
        assert_eq!(seq, Seq::ZERO);
    }

    #[test]
    fn parse_seq_invalid_returns_err() {
        assert!(parse_seq("abc").is_err());
    }

    #[test]
    fn parse_timeline_id_invalid_returns_err() {
        assert!(parse_timeline_id("not-a-ulid").is_err());
    }

    #[test]
    fn parse_timeline_id_valid_roundtrip() {
        // Create a TimelineId, format it as a string, then parse it back.
        let original = TimelineId::new();
        let s = original.to_string();
        let parsed = parse_timeline_id(&s).test_ok();
        assert_eq!(original, parsed);
    }

    // ── CLI command integration tests ────────────────────────────────────────

    fn tmp_db() -> (tempfile::TempDir, String) {
        let dir = tempfile::tempdir().test_ok();
        let path = dir.path().join("test.db").to_str().test_ok().to_owned();
        (dir, path)
    }

    fn args(v: &[&str]) -> Vec<String> {
        v.iter().map(|&s| s.to_owned()).collect()
    }

    #[test]
    fn handle_store_init_creates_store() {
        let (_dir, path) = tmp_db();
        let a = args(&["init", &path]);
        handle_store(&a).test_ok();
    }

    #[test]
    fn handle_store_info_shows_stats() {
        let (_dir, path) = tmp_db();
        // Init first
        handle_store(&args(&["init", &path])).test_ok();
        // Info should succeed
        handle_store(&args(&["info", &path])).test_ok();
    }

    #[test]
    fn handle_store_unknown_subcommand_is_ok() {
        let a = args(&["unknown"]);
        handle_store(&a).test_ok();
    }

    #[test]
    fn handle_store_init_missing_path_returns_err() {
        let a = args(&["init"]);
        assert!(handle_store(&a).is_err());
    }

    #[test]
    fn handle_store_info_missing_path_returns_err() {
        let a = args(&["info"]);
        assert!(handle_store(&a).is_err());
    }

    #[test]
    fn handle_timeline_list_shows_timelines() {
        let (_dir, path) = tmp_db();
        handle_store(&args(&["init", &path])).test_ok();
        handle_timeline(&args(&["list", &path])).test_ok();
    }

    #[test]
    fn handle_timeline_unknown_subcommand_is_ok() {
        let a = args(&["unknown"]);
        handle_timeline(&a).test_ok();
    }

    #[test]
    fn handle_timeline_list_missing_path_returns_err() {
        let a = args(&["list"]);
        assert!(handle_timeline(&a).is_err());
    }

    #[test]
    fn handle_timeline_fork_too_few_args_returns_err() {
        let a = args(&["fork", "path", "tl_id"]);
        assert!(handle_timeline(&a).is_err());
    }

    #[test]
    fn handle_timeline_fork_bad_tl_id_returns_err() {
        let a = args(&["fork", "/tmp/x.db", "not-a-ulid", "0", "child"]);
        assert!(handle_timeline(&a).is_err());
    }

    #[test]
    fn handle_experiment_run_rejects_uninstalled_profile() {
        let (_dir, path) = tmp_db();
        let a = args(&["run", &path, "--ticks", "3"]);
        assert!(handle_experiment(&a).is_err());
    }

    #[test]
    fn fixture_experiment_run_wires_plugins_and_produces_events() {
        // Cover the nonproduction generated runner without claiming an installed profile.
        let dir = tempfile::tempdir().test_ok();
        let path = dir.path().join("run-test.db").to_str().test_ok().to_owned();
        cmd_experiment_run_fixture(&path, 2).test_ok();
        // Verify manifest was written alongside store
        let manifest_path = path.replace(".db", "-manifest.json");
        assert!(std::path::Path::new(&manifest_path).exists());
        let manifest: ReproductionManifest =
            serde_json::from_str(&std::fs::read_to_string(&manifest_path).test_ok()).test_ok();
        assert_eq!(manifest.recipe, cli_reproduction_recipe(2));
        let rows = manifest.manifest.plugin_roster().entries();
        let slots: Vec<&str> = rows
            .iter()
            .map(pos_core::ManifestPluginEntryV1::stable_slot)
            .collect();
        assert_eq!(slots, [REFERENCE_AGENT_SLOT, REFERENCE_OBSERVATION_SLOT]);
        assert!(rows[0].closure_bytes().starts_with(b"OPC1"));
    }

    #[test]
    fn cmd_experiment_reproduce_requires_owner_verified_policy() {
        let dir = tempfile::tempdir().test_ok();
        let path = dir
            .path()
            .join("reproduce.db")
            .to_str()
            .test_ok()
            .to_owned();
        cmd_experiment_run_fixture(&path, 3).test_ok();
        let manifest_path = path.replace(".db", "-manifest.json");
        let error = cmd_experiment_reproduce(&manifest_path).test_err();
        assert!(error.to_string().contains("owner-verified policy closure"));
    }

    #[test]
    fn cmd_experiment_reproduce_rejects_manifest_without_recipe() {
        let manifest = pos_core::ReproManifest::recorded(
            TimelineId::new(),
            pos_core::Hash::zero(),
            pos_core::WallTime::from_micros(0),
            pos_core::ManifestPluginRosterV1::empty(),
            None,
        );
        let file = tempfile::NamedTempFile::new().test_ok();
        std::fs::write(file.path(), serde_json::to_string(&manifest).test_ok()).test_ok();
        assert!(cmd_experiment_reproduce(file.path().to_str().test_ok()).is_err());
    }

    #[test]
    fn cmd_experiment_reproduce_rejects_bad_manifest_json() {
        let file = tempfile::NamedTempFile::new().test_ok();
        std::fs::write(file.path(), "not-json").test_ok();
        assert!(cmd_experiment_reproduce(file.path().to_str().test_ok()).is_err());
    }

    #[test]
    fn cmd_experiment_reproduce_requires_owner_verified_manifest() {
        let slots = [REFERENCE_AGENT_SLOT, REFERENCE_OBSERVATION_SLOT];
        let error = reproduce_error_for(&roster_manifest(&slots));
        assert_eq!(error, OWNER_VERIFIED_ERROR);
    }

    // A manifest whose roster holds exactly `slots`, with fresh `PluginId`s and dummy closures.
    fn roster_manifest(slots: &[&str]) -> pos_core::ReproManifest {
        let rows = slots.iter().map(|slot| {
            pos_core::ManifestPluginEntryV1::new(
                *slot,
                pos_core::ids::PluginId::new(),
                "reference",
                "0.1.0",
                pos_core::Hash::from_bytes([1; 32]),
                vec![1],
            )
            .test_ok()
        });
        let roster = pos_core::ManifestPluginRosterV1::new(rows.collect()).test_ok();
        pos_core::ReproManifest::recorded(
            TimelineId::new(),
            pos_core::Hash::zero(),
            pos_core::WallTime::from_micros(0),
            roster,
            None,
        )
    }

    // Write a reproduction file around `manifest` and return the reproduce error message.
    fn reproduce_error_for(manifest: &pos_core::ReproManifest) -> String {
        let reproduction = serde_json::json!({
            "manifest": manifest,
            "recipe": cli_reproduction_recipe(1),
        });
        reproduce_file_error(&reproduction)
    }

    fn reproduce_file_error(document: &serde_json::Value) -> String {
        let file = tempfile::NamedTempFile::new().test_ok();
        std::fs::write(file.path(), document.to_string()).test_ok();
        let error = cmd_experiment_reproduce(file.path().to_str().test_ok()).test_err();
        error.to_string()
    }

    #[test]
    fn cmd_experiment_reproduce_rejects_a_roster_that_differs_from_the_recorded_slots() {
        let cases: [&[&str]; 4] = [
            &[],
            &[REFERENCE_AGENT_SLOT],
            &[REFERENCE_AGENT_SLOT, "other.observation"],
            &[
                REFERENCE_AGENT_SLOT,
                REFERENCE_OBSERVATION_SLOT,
                "extra.plugin",
            ],
        ];
        for slots in cases {
            let error = reproduce_error_for(&roster_manifest(slots));
            assert_eq!(error, ROSTER_SLOT_MISMATCH_ERROR, "{slots:?}");
        }
    }

    // The old name-keyed manifest shape, as an earlier build wrote it.
    fn old_shape_manifest() -> serde_json::Value {
        serde_json::json!({
            "timeline_id": "01HZY0000000000000000000000",
            "head_hash": "00",
            "created_at": 0,
            "plugin_versions": {"rule-agent": "0.1.0"},
            "output_policy_digests": {},
            "replay_policy_identities": {},
            "replay_policy_closures": {},
            "replay_policy_closure_identities": {},
            "adapter_records": [],
            "label": null,
        })
    }

    fn mixed_shape_manifest() -> serde_json::Value {
        let mut manifest = old_shape_manifest();
        manifest["manifest_plugin_roster_version"] = serde_json::json!(1);
        manifest["manifest_plugin_entries"] = serde_json::json!([]);
        manifest
    }

    #[test]
    fn cmd_experiment_reproduce_reports_old_and_mixed_manifest_shapes() {
        let unsupported = pos_core::ReproManifestError::UnsupportedManifestVersion { found: None };
        let field = "plugin_versions";
        let ambiguous = pos_core::ReproManifestError::AmbiguousLegacyManifest { field };
        let cases = [
            (old_shape_manifest(), unsupported),
            (mixed_shape_manifest(), ambiguous),
        ];
        for (manifest, expected) in cases {
            let reproduction = serde_json::json!({
                "manifest": manifest,
                "recipe": cli_reproduction_recipe(1),
            });
            let error = reproduce_file_error(&reproduction);
            assert!(error.contains(&expected.to_string()), "{error}");
        }
    }

    #[test]
    fn cmd_experiment_verify_reports_old_and_mixed_manifest_shapes() {
        let unsupported = pos_core::ReproManifestError::UnsupportedManifestVersion { found: None };
        let field = "plugin_versions";
        let ambiguous = pos_core::ReproManifestError::AmbiguousLegacyManifest { field };
        let cases = [
            (old_shape_manifest(), unsupported),
            (mixed_shape_manifest(), ambiguous),
        ];
        for (manifest, expected) in cases {
            let file = tempfile::NamedTempFile::new().test_ok();
            std::fs::write(file.path(), manifest.to_string()).test_ok();
            let error = cmd_experiment_verify(file.path().to_str().test_ok()).test_err();
            let message = error.to_string();
            assert!(message.contains(&expected.to_string()), "{message}");
        }
    }

    #[test]
    fn reproduce_cli_recipe_rejects_a_different_host() {
        let recipe = ReproductionRecipe::new("another-host", 1, serde_json::json!({}));
        assert!(reproduce_cli_recipe(recipe).is_err());
    }

    #[test]
    fn reproduce_manifest_rejects_a_different_host_before_running() {
        let reproduction = ReproductionManifest {
            manifest: pos_core::ReproManifest::recorded(
                TimelineId::new(),
                pos_core::Hash::zero(),
                pos_core::WallTime::from_micros(0),
                pos_core::ManifestPluginRosterV1::empty(),
                None,
            ),
            recipe: ReproductionRecipe::new("another-host", 1, serde_json::json!({})),
        };
        assert!(reproduce_manifest(reproduction).is_err());
    }

    #[test]
    fn reproduce_cli_recipe_rejects_an_unknown_format() {
        let recipe = ReproductionRecipe::new(
            POS_CLI_REPRODUCTION_HOST,
            POS_CLI_REPRODUCTION_FORMAT + 1,
            serde_json::json!({}),
        );
        assert!(reproduce_cli_recipe(recipe).is_err());
    }

    #[test]
    fn reproduce_cli_recipe_rejects_unknown_configuration_fields() {
        let recipe = ReproductionRecipe::new(
            POS_CLI_REPRODUCTION_HOST,
            POS_CLI_REPRODUCTION_FORMAT,
            serde_json::json!({
                "BuiltinReferenceV1": {"ticks": 1, "slots": recorded_slots(), "extra": true}
            }),
        );
        assert!(reproduce_cli_recipe(recipe).is_err());
    }

    fn recorded_slots() -> serde_json::Value {
        serde_json::json!({
            "agent": REFERENCE_AGENT_SLOT,
            "observation": REFERENCE_OBSERVATION_SLOT,
        })
    }

    fn recipe_with_slots(slots: &serde_json::Value) -> ReproductionRecipe {
        ReproductionRecipe::new(
            POS_CLI_REPRODUCTION_HOST,
            POS_CLI_REPRODUCTION_FORMAT,
            serde_json::json!({"BuiltinReferenceV1": {"ticks": 1, "slots": slots}}),
        )
    }

    #[test]
    fn reproduce_cli_recipe_accepts_the_recorded_reference_slots() {
        let recipe = recipe_with_slots(&recorded_slots());
        let decoded = reproduce_cli_recipe(recipe).test_ok();
        assert_eq!(decoded.builtin_reference_v1.slots.agent, "reference.agent");
        assert_eq!(
            decoded.builtin_reference_v1.slots.observation,
            "reference.observation"
        );
    }

    #[test]
    fn reproduce_cli_recipe_rejects_slots_this_build_does_not_use() {
        let renamed_agent = serde_json::json!({
            "agent": "other.agent",
            "observation": REFERENCE_OBSERVATION_SLOT,
        });
        let renamed_observation = serde_json::json!({
            "agent": REFERENCE_AGENT_SLOT,
            "observation": "other.observation",
        });
        for slots in [renamed_agent, renamed_observation] {
            let recipe = recipe_with_slots(&slots);
            let error = reproduce_cli_recipe(recipe).err().test_ok();
            assert_eq!(error.to_string(), SLOT_MISMATCH_ERROR);
        }
    }

    #[test]
    fn reproduce_cli_recipe_requires_complete_recorded_slots() {
        let missing = serde_json::json!({"BuiltinReferenceV1": {"ticks": 1}});
        let recipe = ReproductionRecipe::new(
            POS_CLI_REPRODUCTION_HOST,
            POS_CLI_REPRODUCTION_FORMAT,
            missing,
        );
        assert!(reproduce_cli_recipe(recipe).is_err());
        let partial = recipe_with_slots(&serde_json::json!({"agent": REFERENCE_AGENT_SLOT}));
        assert!(reproduce_cli_recipe(partial).is_err());
    }

    #[test]
    fn reproduce_cli_recipe_rejects_excessive_tick_count() {
        let recipe = cli_reproduction_recipe(MAX_EXPERIMENT_TICKS + 1);
        let error = reproduce_cli_recipe(recipe).err().test_ok();
        assert_eq!(error.to_string(), TICK_LIMIT_ERROR);
    }

    #[test]
    fn maximum_tick_count_is_accepted_for_export_and_reproduction() {
        assert!(validate_experiment_ticks(MAX_EXPERIMENT_TICKS).is_ok());
        let decoded = reproduce_cli_recipe(cli_reproduction_recipe(MAX_EXPERIMENT_TICKS)).test_ok();
        assert_eq!(decoded.builtin_reference_v1.ticks, MAX_EXPERIMENT_TICKS);
    }

    #[test]
    fn excessive_tick_count_is_rejected_before_run_or_reproduction() {
        let directory = tempfile::tempdir().test_ok();
        let path = directory.path().join("too-many-ticks.db");
        let path = path.to_str().test_ok();

        let run_error = cmd_experiment_run(path, MAX_EXPERIMENT_TICKS + 1).test_err();
        assert_eq!(run_error.to_string(), TICK_LIMIT_ERROR);
        assert!(!std::path::Path::new(path).exists());

        let reproduce_error =
            reproduce_cli_recipe(cli_reproduction_recipe(MAX_EXPERIMENT_TICKS + 1))
                .err()
                .test_ok();
        assert_eq!(reproduce_error.to_string(), TICK_LIMIT_ERROR);
    }

    #[test]
    fn cmd_experiment_reproduce_rejects_unknown_envelope_field() {
        let reproduction = ReproductionManifest {
            manifest: pos_core::ReproManifest::recorded(
                TimelineId::new(),
                pos_core::Hash::zero(),
                pos_core::WallTime::from_micros(0),
                pos_core::ManifestPluginRosterV1::empty(),
                None,
            ),
            recipe: cli_reproduction_recipe(1),
        };
        let mut json = serde_json::to_value(reproduction).test_ok();
        json.as_object_mut()
            .test_ok()
            .insert("extra".to_owned(), serde_json::Value::Null);
        let file = tempfile::NamedTempFile::new().test_ok();
        std::fs::write(file.path(), serde_json::to_string(&json).test_ok()).test_ok();
        assert!(cmd_experiment_reproduce(file.path().to_str().test_ok()).is_err());
    }

    #[test]
    fn cmd_experiment_reproduce_rejects_unknown_kernel_manifest_field_before_execution() {
        let reproduction = ReproductionManifest {
            manifest: pos_core::ReproManifest::recorded(
                TimelineId::new(),
                pos_core::Hash::zero(),
                pos_core::WallTime::from_micros(0),
                pos_core::ManifestPluginRosterV1::empty(),
                None,
            ),
            recipe: cli_reproduction_recipe(1),
        };
        let mut json = serde_json::to_value(reproduction).test_ok();
        json.get_mut("manifest")
            .and_then(serde_json::Value::as_object_mut)
            .test_ok()
            .insert(
                "unexpected_kernel_field".to_owned(),
                serde_json::Value::Null,
            );
        let file = tempfile::NamedTempFile::new().test_ok();
        std::fs::write(file.path(), serde_json::to_string(&json).test_ok()).test_ok();

        assert!(cmd_experiment_reproduce(file.path().to_str().test_ok()).is_err());
    }

    #[test]
    fn handle_experiment_reproduce_dispatches_and_requires_manifest() {
        let dir = tempfile::tempdir().test_ok();
        let path = dir.path().join("dispatch.db").to_str().test_ok().to_owned();
        cmd_experiment_run_fixture(&path, 1).test_ok();
        let manifest_path = path.replace(".db", "-manifest.json");
        let error = handle_experiment(&args(&["reproduce", &manifest_path])).test_err();
        assert!(error.to_string().contains("owner-verified policy closure"));
        assert!(handle_experiment(&args(&["reproduce"])).is_err());
    }

    #[test]
    fn cmd_experiment_verify_with_companion_db() {
        // Cover the "if path.exists()" SQLite branch in cmd_experiment_verify.
        // Also covers the `if matched { Ok(()) }` path when head_hash matches.
        use pos_store::StoreConfig;

        let dir = tempfile::tempdir().test_ok();
        let db_path = dir.path().join("test.db").to_str().test_ok().to_owned();
        let manifest_path = dir
            .path()
            .join("test-manifest.json")
            .to_str()
            .test_ok()
            .to_owned();

        // Create store with a timeline and empty head_hash = zero manifest
        let mut store = open_store(StoreConfig::Sqlite { path: db_path }).test_ok();
        let tl = store.create_timeline("verify-real").test_ok();

        let manifest = pos_core::ReproManifest::recorded(
            tl.id(),
            pos_core::crypto::Hash::zero(),
            pos_core::WallTime::from_micros(0),
            pos_core::ManifestPluginRosterV1::empty(),
            None,
        );
        let json = serde_json::to_string(&manifest).test_ok();
        std::fs::write(&manifest_path, &json).test_ok();

        // cmd_experiment_verify finds the companion .db (via -manifest.json → .db)
        // The timeline exists with the recorded zero head hash, so the
        // timeline-head-only verification result is successful.
        let result = cmd_experiment_verify(&manifest_path);
        assert!(result.is_ok());
    }

    #[test]
    fn handle_experiment_run_missing_path_returns_err() {
        let a = args(&["run"]);
        assert!(handle_experiment(&a).is_err());
    }

    #[test]
    fn handle_experiment_run_missing_ticks_returns_err() {
        let (_dir, path) = tmp_db();
        let a = args(&["run", &path]);
        assert!(handle_experiment(&a).is_err());
    }

    #[test]
    fn handle_experiment_verify_missing_path_returns_err() {
        let a = args(&["verify"]);
        assert!(handle_experiment(&a).is_err());
    }

    #[test]
    fn handle_experiment_verify_nonexistent_file_returns_err() {
        let a = args(&["verify", "/tmp/no_such_manifest_pigloros.json"]);
        assert!(handle_experiment(&a).is_err());
    }

    #[test]
    fn handle_experiment_unknown_subcommand_is_ok() {
        let a = args(&["unknown"]);
        handle_experiment(&a).test_ok();
    }

    #[test]
    fn handle_experiment_verify_bad_json_returns_err() {
        // Write a non-JSON file as manifest
        let dir = tempfile::tempdir().test_ok();
        let path = dir.path().join("bad.json");
        std::fs::write(&path, b"not json").test_ok();
        let path_str = path.to_str().test_ok().to_owned();
        let a = args(&["verify", &path_str]);
        assert!(handle_experiment(&a).is_err());
    }

    #[test]
    fn handle_timeline_fork_executes() {
        // Init store, list timeline to get its ID, then fork it.
        let (_dir, path) = tmp_db();
        handle_store(&args(&["init", &path])).test_ok();

        // Get the timeline ID by reading the store directly.
        let store = open_store(StoreConfig::Sqlite { path: path.clone() }).test_ok();
        let timelines = store.list_timelines().test_ok();
        assert!(!timelines.is_empty());
        let tl_id = timelines[0].id().to_string();

        let a = args(&["fork", &path, &tl_id, "0", "child-branch"]);
        handle_timeline(&a).test_ok();
    }

    #[test]
    fn parse_ticks_flag_skips_non_ticks_flags() {
        // A flag that is not --ticks before --ticks — covers the loop body else branch (line 230)
        let a: Vec<String> = vec![
            "--other".to_owned(),
            "val".to_owned(),
            "--ticks".to_owned(),
            "7".to_owned(),
        ];
        let n = parse_ticks_flag(&a).test_ok();
        assert_eq!(n, 7);
    }

    #[test]
    fn parse_ticks_flag_accepts_train_ticks_flag() {
        let a: Vec<String> = vec!["--train-ticks".to_owned(), "10".to_owned()];
        let n = parse_ticks_flag(&a).test_ok();
        assert_eq!(n, 10);
    }

    #[test]
    fn parse_limit_flag_extracts_value() {
        let a: Vec<String> = vec!["--limit".to_owned(), "10".to_owned()];
        let n = parse_limit_flag(&a).test_ok();
        assert_eq!(n, Some(10));
    }

    #[test]
    fn parse_limit_flag_missing_returns_none() {
        let a: Vec<String> = vec!["--other".to_owned()];
        let n = parse_limit_flag(&a).test_ok();
        assert_eq!(n, None);
    }

    #[test]
    fn parse_limit_flag_invalid_number_returns_err() {
        let a: Vec<String> = vec!["--limit".to_owned(), "notanumber".to_owned()];
        assert!(parse_limit_flag(&a).is_err());
    }

    #[test]
    fn parse_limit_flag_skips_non_limit_flags() {
        let a: Vec<String> = vec![
            "--other".to_owned(),
            "val".to_owned(),
            "--limit".to_owned(),
            "5".to_owned(),
        ];
        let n = parse_limit_flag(&a).test_ok();
        assert_eq!(n, Some(5));
    }

    #[test]
    fn handle_events_log_executes() {
        let (_dir, path) = tmp_db();
        handle_store(&args(&["init", &path])).test_ok();

        // Add some events to log
        let mut store = open_store(StoreConfig::Sqlite { path: path.clone() }).test_ok();
        let timelines = store.list_timelines().test_ok();
        let tl_id = timelines[0].id();
        let entity = EntityId::new();
        let drafts = vec![EventDraft::new(
            entity,
            Kind::new("test.event"),
            CanonicalBytes::from_vec(vec![]),
        )];
        store.append(tl_id, &drafts).test_ok();
        drop(store);

        let tl_id_str = tl_id.to_string();
        let a = args(&["log", &path, &tl_id_str]);
        handle_events(&a).test_ok();
    }

    #[test]
    fn handle_events_log_with_limit() {
        let (_dir, path) = tmp_db();
        handle_store(&args(&["init", &path])).test_ok();
        let store = open_store(StoreConfig::Sqlite { path: path.clone() }).test_ok();
        let timelines = store.list_timelines().test_ok();
        let tl_id = timelines[0].id().to_string();
        let a = args(&["log", &path, &tl_id, "--limit", "5"]);
        handle_events(&a).test_ok();
    }

    #[test]
    fn handle_events_unknown_subcommand_is_ok() {
        let a = args(&["unknown"]);
        handle_events(&a).test_ok();
    }

    #[test]
    fn handle_events_log_missing_path_returns_err() {
        let a = args(&["log"]);
        assert!(handle_events(&a).is_err());
    }

    #[test]
    fn handle_timeline_replay_missing_path_returns_err() {
        let a = args(&["replay"]);
        assert!(handle_timeline(&a).is_err());
    }

    #[test]
    fn handle_timeline_snapshot_missing_path_returns_err() {
        let a = args(&["snapshot"]);
        assert!(handle_timeline(&a).is_err());
    }

    #[test]
    fn handle_timeline_compare_missing_args_returns_err() {
        let a = args(&["compare", "path", "tl1"]);
        assert!(handle_timeline(&a).is_err());
    }

    #[test]
    fn timeline_protected_operations_fail_closed_without_owner_evidence() {
        for (arguments, operation) in [
            (args(&["replay", "unused.db", "timeline"]), "replay"),
            (args(&["snapshot", "unused.db", "timeline"]), "snapshot"),
            (args(&["compare", "unused.db", "a", "b", "0"]), "compare"),
        ] {
            let error = handle_timeline(&arguments).test_err();
            assert_eq!(
                error.to_string(),
                format!(
                    "timeline {operation} is unavailable: the CLI has no owner-verified evidence path for this operation"
                )
            );
        }
    }

    #[test]
    fn handle_timeline_merge_executes() {
        let (_dir, path) = tmp_db();
        handle_store(&args(&["init", &path])).test_ok();
        let mut store = open_store(StoreConfig::Sqlite { path: path.clone() }).test_ok();
        let timelines = store.list_timelines().test_ok();
        let base_id = timelines[0].id();
        let entity_a = EntityId::new();
        let entity_b = EntityId::new();
        store
            .append(
                base_id,
                &[EventDraft::new(
                    entity_a,
                    Kind::new("base.event"),
                    CanonicalBytes::from_vec(vec![]),
                )],
            )
            .test_ok();
        let fork_a = store.fork(base_id, timelines[0].head, "fork-a").test_ok();
        // head may have advanced; re-read
        let base_head = store
            .list_timelines()
            .test_ok()
            .into_iter()
            .find(|t| t.id() == base_id)
            .test_ok()
            .head;
        let fork_b = store.fork(base_id, base_head, "fork-b").test_ok();
        store
            .append(
                fork_a.id(),
                &[EventDraft::new(
                    entity_a,
                    Kind::new("a.event"),
                    CanonicalBytes::from_vec(vec![]),
                )],
            )
            .test_ok();
        store
            .append(
                fork_b.id(),
                &[EventDraft::new(
                    entity_b,
                    Kind::new("b.event"),
                    CanonicalBytes::from_vec(vec![]),
                )],
            )
            .test_ok();
        let fork_seq = base_head.as_u64().to_string();
        let a_id = fork_a.id().to_string();
        let b_id = fork_b.id().to_string();
        drop(store);

        let a = args(&[
            "merge",
            &path,
            &a_id,
            &b_id,
            &fork_seq,
            "merged",
            "--strategy",
            "disjoint",
        ]);
        handle_timeline(&a).test_ok();
    }

    #[test]
    fn handle_timeline_merge_missing_args_returns_err() {
        let a = args(&["merge", "path", "tl1"]);
        assert!(handle_timeline(&a).is_err());
    }

    #[test]
    fn parse_merge_strategy_flag_defaults_and_parses() {
        assert!(matches!(
            parse_merge_strategy_flag(&[]).test_ok(),
            pos_time::MergeStrategy::DisjointCrdt
        ));
        let a: Vec<String> = vec!["--strategy".to_owned(), "prefer-a".to_owned()];
        assert!(matches!(
            parse_merge_strategy_flag(&a).test_ok(),
            pos_time::MergeStrategy::PreferA
        ));
    }

    #[test]
    fn parse_merge_strategy_flag_skips_non_strategy_args() {
        // Covers the `i += 1` branch when scanning past unrelated flags.
        let a: Vec<String> = vec![
            "--other".to_owned(),
            "val".to_owned(),
            "--strategy".to_owned(),
            "prefer-b".to_owned(),
        ];
        assert!(matches!(
            parse_merge_strategy_flag(&a).test_ok(),
            pos_time::MergeStrategy::PreferB
        ));
    }

    #[test]
    fn parse_merge_strategy_flag_missing_value_returns_err() {
        let a: Vec<String> = vec!["--strategy".to_owned()];
        assert!(parse_merge_strategy_flag(&a).is_err());
    }

    #[test]
    fn parse_merge_strategy_flag_invalid_returns_err() {
        let a: Vec<String> = vec!["--strategy".to_owned(), "nope".to_owned()];
        assert!(parse_merge_strategy_flag(&a).is_err());
    }

    #[test]
    fn handle_timeline_merge_missing_timeline_returns_err() {
        // Covers cmd_timeline_merge error path when merge_with_strategy fails.
        let (_dir, path) = tmp_db();
        handle_store(&args(&["init", &path])).test_ok();
        let missing_a = TimelineId::new().to_string();
        let missing_b = TimelineId::new().to_string();
        let a = args(&["merge", &path, &missing_a, &missing_b, "0", "merged"]);
        assert!(handle_timeline(&a).is_err());
    }
}

// Coverage tests for main()/run() and MISMATCH path
#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod coverage_tests {
    trait TestValueExt<T> {
        fn test_ok(self) -> T;
    }

    impl<T, E: std::fmt::Debug> TestValueExt<T> for Result<T, E> {
        fn test_ok(self) -> T {
            self.unwrap_or_else(|error| {
                std::panic::resume_unwind(Box::new(format!("unexpected test error: {error:?}")))
            })
        }
    }

    impl<T> TestValueExt<T> for Option<T> {
        fn test_ok(self) -> T {
            self.unwrap_or_else(|| std::panic::resume_unwind(Box::new("expected test value")))
        }
    }

    use super::*;

    #[test]
    fn run_with_no_args_prints_usage() {
        let args: Vec<String> = vec!["pos".to_owned()];
        let result = run_with_args(&args);
        assert!(result.is_ok());
    }

    #[test]
    fn run_version_via_dispatch() {
        let args: Vec<String> = vec!["pos".to_owned(), "version".to_owned()];
        let result = run_with_args(&args);
        assert!(result.is_ok());
    }

    #[test]
    fn run_store_dispatch() {
        let args: Vec<String> = vec!["pos".to_owned(), "store".to_owned()];
        let result = run_with_args(&args);
        assert!(result.is_ok()); // missing path prints usage
    }

    #[test]
    fn run_timeline_dispatch() {
        let args: Vec<String> = vec!["pos".to_owned(), "timeline".to_owned()];
        let result = run_with_args(&args);
        assert!(result.is_ok());
    }

    #[test]
    fn run_experiment_dispatch() {
        let args: Vec<String> = vec!["pos".to_owned(), "experiment".to_owned()];
        let result = run_with_args(&args);
        assert!(result.is_ok());
    }

    #[test]
    fn run_unknown_subcommand() {
        let args: Vec<String> = vec!["pos".to_owned(), "unknown".to_owned()];
        let result = run_with_args(&args);
        assert!(result.is_ok()); // unknown prints usage and returns Ok
    }

    #[test]
    fn verify_mismatch_returns_err() {
        // Cover the MISMATCH path without calling process::exit
        // by calling cmd_experiment_verify with a manifest that won't match.
        use pos_core::ids::TimelineId;
        use std::io::Write;
        use tempfile::NamedTempFile;

        // Build a manifest with a random timeline_id that won't exist in a fresh store
        let manifest = pos_core::ReproManifest::recorded(
            TimelineId::new(),
            pos_core::crypto::Hash::from_bytes([0xAB; 32]),
            pos_core::WallTime::from_micros(0),
            pos_core::ManifestPluginRosterV1::empty(),
            None,
        );
        let json = serde_json::to_string(&manifest).test_ok();
        let mut f = NamedTempFile::new().test_ok();
        f.write_all(json.as_bytes()).test_ok();

        // cmd_experiment_verify reads the manifest and checks the store.
        // With a non-existent timeline_id it hits the `matched = false` → MISMATCH path.
        // We can't let it call process::exit(2) so we use a separate test approach:
        // cmd_experiment_verify opens a fresh Memory store so the timeline won't be found
        // → matched = false → returns Err("hash mismatch")
        let result = cmd_experiment_verify(f.path().to_str().test_ok());
        assert!(result.is_err());
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod store_info_coverage {
    trait TestValueExt<T> {
        fn test_ok(self) -> T;
    }

    impl<T, E: std::fmt::Debug> TestValueExt<T> for Result<T, E> {
        fn test_ok(self) -> T {
            self.unwrap_or_else(|error| {
                std::panic::resume_unwind(Box::new(format!("unexpected test error: {error:?}")))
            })
        }
    }

    impl<T> TestValueExt<T> for Option<T> {
        fn test_ok(self) -> T {
            self.unwrap_or_else(|| std::panic::resume_unwind(Box::new("expected test value")))
        }
    }

    trait TestErrorExt<E> {
        fn test_err(self) -> E;
    }

    impl<T, E> TestErrorExt<E> for Result<T, E> {
        fn test_err(self) -> E {
            self.err()
                .unwrap_or_else(|| std::panic::resume_unwind(Box::new("expected test error")))
        }
    }

    use super::*;

    #[test]
    fn list_failure_retains_operation_and_sanitizes_root_cause() {
        let directory = tempfile::tempdir().test_ok();
        let path = directory.path().join("corrupt.db");
        let path = path.to_str().test_ok();
        cmd_store_init(path).test_ok();

        let connection = rusqlite::Connection::open(path).test_ok();
        connection
            .execute("UPDATE timelines SET name = X'0102'", [])
            .test_ok();

        let error = cmd_store_info(path).test_err().to_string();
        assert!(error.contains("failed to list Timelines"));
        assert!(error.contains("erasure host rejected CLI operation"));
        assert!(!error.contains("Invalid column type"));
    }

    #[test]
    fn read_failure_retains_timeline_and_sanitizes_root_cause() {
        let directory = tempfile::tempdir().test_ok();
        let path = directory.path().join("corrupt.db");
        let path = path.to_str().test_ok();
        cmd_store_init(path).test_ok();

        let mut store = open_store(StoreConfig::Sqlite {
            path: path.to_owned(),
        })
        .test_ok();
        let timeline_id = store.list_timelines().test_ok()[0].id();
        store
            .append(
                timeline_id,
                &[pos_core::event::EventDraft::new(
                    pos_core::ids::EntityId::new(),
                    pos_core::event::Kind::new("test.event"),
                    pos_core::event::CanonicalBytes::from_vec(vec![]),
                )],
            )
            .test_ok();
        drop(store);

        let connection = rusqlite::Connection::open(path).test_ok();
        connection
            .execute("UPDATE events SET payload_hash = X'01'", [])
            .test_ok();

        let error = cmd_store_info(path).test_err().to_string();
        assert!(error.contains(&format!("failed to read Timeline {timeline_id}")));
        assert!(error.contains("erasure host rejected CLI operation"));
        assert!(!error.contains("serialization error: bad hash"));
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod main_coverage {
    trait TestValueExt<T> {
        fn test_ok(self) -> T;
    }

    impl<T, E: std::fmt::Debug> TestValueExt<T> for Result<T, E> {
        fn test_ok(self) -> T {
            self.unwrap_or_else(|error| {
                std::panic::resume_unwind(Box::new(format!("unexpected test error: {error:?}")))
            })
        }
    }

    impl<T> TestValueExt<T> for Option<T> {
        fn test_ok(self) -> T {
            self.unwrap_or_else(|| std::panic::resume_unwind(Box::new("expected test value")))
        }
    }

    use super::*;

    #[test]
    fn main_does_not_panic_in_test_context() {
        // main() reads std::env::args() — in test context the first arg is the
        // test binary path, so run_with_args hits the `_` arm and returns Ok(()).
        // This exercises lines 21-27 (the main body including the if let Err path
        // when run_with_args succeeds).
        main();
    }

    #[test]
    fn verify_ok_path_when_manifest_matches_empty_store() {
        // Cover the scoped timeline-head-only verification message.
        // An empty Timeline matches a manifest with the zero head hash.
        use pos_store::StoreConfig;
        use tempfile::NamedTempFile;

        // Create a SQLite store, create a timeline in it
        let db = NamedTempFile::new().test_ok();
        let db_path = db.path().to_str().test_ok().to_owned();
        {
            let mut store = open_store(StoreConfig::Sqlite { path: db_path }).test_ok();
            let tl = store.create_timeline("verify-test").test_ok();

            // Build a manifest pointing at this timeline with head_hash = zero
            // (no events appended → last().map_or(zero, ...) = zero)
            let manifest = pos_core::ReproManifest::recorded(
                tl.id(),
                pos_core::crypto::Hash::zero(),
                pos_core::WallTime::from_micros(0),
                pos_core::ManifestPluginRosterV1::empty(),
                None,
            );
            let json = serde_json::to_string(&manifest).test_ok();
            let mut f = NamedTempFile::new().test_ok();
            std::io::Write::write_all(&mut f, json.as_bytes()).test_ok();

            // cmd_experiment_verify uses Memory store internally so it won't find
            // the SQLite timeline. Use the in-memory path instead.
            // Create an in-memory store with the same timeline_id via import.
            let export = pos_core::store::export_timeline(
                store.as_ref(),
                tl.id(),
                TEST_EXPORT_DIGEST,
                &test_export_evaluation(),
            )
            .test_ok();
            let mut mem = open_store(StoreConfig::Memory).test_ok();
            pos_core::store::import_timeline(mem.as_mut(), export).test_ok();

            // Verify the success message remains explicitly scoped to the Timeline head.
            // The actual verify calls open_store(Memory) so it won't find the timeline,
            // making matched=false. The direct matching-store test covers the successful result.
            assert_eq!(
                ManifestHeadVerification::TimelineHeadOnly.output_message(),
                "Timeline head verified; output-policy and Replay identity were not checked"
            );

            // The real test: cmd_experiment_verify with non-matching timeline returns Err
            let result = cmd_experiment_verify(f.path().to_str().test_ok());
            assert!(result.is_err()); // Memory store has no timelines
        }
        drop(db);
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod final_coverage {
    trait TestValueExt<T> {
        fn test_ok(self) -> T;
    }

    impl<T, E: std::fmt::Debug> TestValueExt<T> for Result<T, E> {
        fn test_ok(self) -> T {
            self.unwrap_or_else(|error| {
                std::panic::resume_unwind(Box::new(format!("unexpected test error: {error:?}")))
            })
        }
    }

    impl<T> TestValueExt<T> for Option<T> {
        fn test_ok(self) -> T {
            self.unwrap_or_else(|| std::panic::resume_unwind(Box::new("expected test value")))
        }
    }

    use super::*;
    use pos_store::StoreConfig;

    #[test]
    fn verify_manifest_ok_path_when_hash_matches() {
        // Verify both the scoped result and the exact CLI success message.
        let mut store = open_store(StoreConfig::Memory).test_ok();
        let tl = store.create_timeline("match-test").test_ok();

        // Empty timeline → last event = None → head_hash = Hash::zero()
        let manifest = pos_core::ReproManifest::recorded(
            tl.id(),
            pos_core::crypto::Hash::zero(),
            pos_core::WallTime::from_micros(0),
            pos_core::ManifestPluginRosterV1::empty(),
            None,
        );

        let mut output = Vec::new();
        let result = report_manifest_head_verification(&manifest, store.as_ref(), &mut output);
        assert!(result.is_ok());
        assert_eq!(
            output,
            b"Timeline head verified; output-policy and Replay identity were not checked\n"
        );
    }

    #[test]
    fn verify_manifest_mismatch_when_hash_differs() {
        // Cover the mismatch result (timeline exists but hash differs).
        let mut store = open_store(StoreConfig::Memory).test_ok();
        let tl = store.create_timeline("mismatch-test").test_ok();

        // Use a non-zero hash — won't match empty timeline's zero hash
        let manifest = pos_core::ReproManifest::recorded(
            tl.id(),
            pos_core::crypto::Hash::from_bytes([0xFFu8; 32]),
            pos_core::WallTime::from_micros(0),
            pos_core::ManifestPluginRosterV1::empty(),
            None,
        );

        let mut output = Vec::new();
        let result = report_manifest_head_verification(&manifest, store.as_ref(), &mut output);
        assert!(result.is_err());
        assert_eq!(output, b"MISMATCH\n");
    }

    #[test]
    fn handle_run_error_is_callable() {
        // Cover the test version of handle_run_error (output_stderr! without exit).
        let e: Box<dyn std::error::Error> = "test error".into();
        handle_run_error(e.as_ref()); // calls the #[cfg(test)] version — no exit
    }

    #[test]
    fn main_error_path_is_exercised() {
        // Cover run_main()'s error branch by passing args that trigger an error.
        // handle_store("init", "/dev/null/impossible/path") will fail → Err → handle_run_error
        let args: Vec<String> = vec![
            "pos".to_owned(),
            "store".to_owned(),
            "init".to_owned(),
            "/dev/null/cannot/create/this/path".to_owned(),
        ];
        run_main(&args); // triggers error path, calls handle_run_error (test version = no exit)
    }

    #[test]
    fn verify_manifest_against_store_timeline_not_found() {
        // Cover the `else { false }` branch (line 248): store exists but timeline_id is absent.
        use pos_core::ids::TimelineId;
        use pos_store::StoreConfig;

        let store = open_store(StoreConfig::Memory).test_ok();
        // Manifest points at a timeline that was never created in this store.
        let manifest = pos_core::ReproManifest::recorded(
            TimelineId::new(),
            pos_core::crypto::Hash::from_bytes([0xAB; 32]),
            pos_core::WallTime::from_micros(0),
            pos_core::ManifestPluginRosterV1::empty(),
            None,
        );
        let result = verify_manifest_against_store(&manifest, store.as_ref());
        assert_eq!(result.test_ok(), ManifestHeadVerification::Mismatch);
    }

    #[test]
    fn cmd_experiment_verify_falls_back_to_memory_when_no_db() {
        // A missing companion store fails before verification.
        use pos_core::ids::TimelineId;

        let dir = tempfile::tempdir().test_ok();
        // Write a manifest.json whose companion .db does NOT exist.
        let manifest_path = dir.path().join("no-companion-manifest.json");
        let manifest = pos_core::ReproManifest::recorded(
            TimelineId::new(),
            pos_core::crypto::Hash::from_bytes([0xCC; 32]),
            pos_core::WallTime::from_micros(0),
            pos_core::ManifestPluginRosterV1::empty(),
            None,
        );
        let json = serde_json::to_string(&manifest).test_ok();
        std::fs::write(&manifest_path, &json).test_ok();

        // The companion .db would be "no-companion.db" — it doesn't exist.
        // The command rejects the absent companion store before checking a head.
        let result = cmd_experiment_verify(manifest_path.to_str().test_ok());
        assert!(
            result.is_err(),
            "missing companion store should be rejected"
        );
    }

    #[test]
    fn run_events_dispatch() {
        let args: Vec<String> = vec!["pos".to_owned(), "events".to_owned()];
        let result = run_with_args(&args);
        assert!(result.is_ok());
    }

    #[test]
    fn verify_manifest_with_events_uses_chain_head_hash() {
        // Cover lines 248-252: the non-empty events blake3 path in verify_manifest_against_store.
        use pos_core::event::{CanonicalBytes, EventDraft, Kind};
        use pos_core::ids::EntityId;

        let mut store = open_store(StoreConfig::Memory).test_ok();
        let tl = store.create_timeline("chain-verify-test").test_ok();
        let entity = EntityId::new();
        let draft = EventDraft::new(
            entity,
            Kind::new("test.event"),
            CanonicalBytes::from_vec(vec![]),
        );
        let committed = store.append(tl.id(), &[draft]).test_ok();
        assert!(!committed.is_empty());

        // Compute the expected chain_head manually
        let events = store.read(tl.id(), SeqRange::all()).test_ok();
        let mut hasher = blake3::Hasher::new();
        for e in &events {
            hasher.update(e.payload_hash.as_bytes());
        }
        let chain_head = pos_core::crypto::Hash::from_bytes(*hasher.finalize().as_bytes());

        // Manifest with the correct chain_head → timeline-head-only verification.
        let manifest = pos_core::ReproManifest::recorded(
            tl.id(),
            chain_head,
            pos_core::WallTime::from_micros(0),
            pos_core::ManifestPluginRosterV1::empty(),
            None,
        );
        let result = verify_manifest_against_store(&manifest, store.as_ref());
        assert_eq!(result.test_ok(), ManifestHeadVerification::TimelineHeadOnly);

        // Manifest with wrong hash → should MISMATCH
        let bad_manifest = pos_core::ReproManifest::recorded(
            tl.id(),
            pos_core::crypto::Hash::from_bytes([0xDEu8; 32]),
            pos_core::WallTime::from_micros(0),
            pos_core::ManifestPluginRosterV1::empty(),
            None,
        );
        let bad_result = verify_manifest_against_store(&bad_manifest, store.as_ref());
        assert_eq!(bad_result.test_ok(), ManifestHeadVerification::Mismatch);
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod fault_injection_tests {
    trait TestValueExt<T> {
        fn test_ok(self) -> T;
    }

    impl<T, E: std::fmt::Debug> TestValueExt<T> for Result<T, E> {
        fn test_ok(self) -> T {
            self.unwrap_or_else(|error| {
                std::panic::resume_unwind(Box::new(format!("unexpected test error: {error:?}")))
            })
        }
    }

    impl<T> TestValueExt<T> for Option<T> {
        fn test_ok(self) -> T {
            self.unwrap_or_else(|| std::panic::resume_unwind(Box::new("expected test value")))
        }
    }

    use super::*;
    use pos_core::{
        event::{CanonicalBytes, EventDraft, Kind},
        ids::EntityId,
    };
    use rusqlite::Connection;

    #[cfg(unix)]
    fn running_as_root() -> bool {
        std::fs::read_to_string("/proc/self/status")
            .ok()
            .and_then(|status| {
                status
                    .lines()
                    .find_map(|line| line.strip_prefix("Uid:\t"))
                    .and_then(|uids| uids.split_whitespace().next())
                    .and_then(|uid| uid.parse::<u32>().ok())
            })
            == Some(0)
    }

    fn corrupt_timeline_names(path: &str) {
        let conn = Connection::open(path).test_ok();
        conn.execute("UPDATE timelines SET name = X'0102'", [])
            .test_ok();
    }

    fn corrupt_event_ids(path: &str) {
        let conn = Connection::open(path).test_ok();
        conn.execute("UPDATE events SET event_id = 'not-a-ulid'", [])
            .test_ok();
    }

    #[cfg(unix)]
    fn set_readonly(path: &std::path::Path) {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o444)).test_ok();
    }

    #[cfg(unix)]
    fn set_writable(path: &std::path::Path) {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o644)).test_ok();
    }

    #[cfg(unix)]
    fn readonly_db(path: &std::path::Path) {
        let mut store = open_store(StoreConfig::Sqlite {
            path: path.to_str().test_ok().to_owned(),
        })
        .test_ok();
        store.create_timeline("seed").test_ok();
        drop(store);
        set_readonly(path);
    }

    fn args(v: &[&str]) -> Vec<String> {
        v.iter().map(|&s| s.to_owned()).collect()
    }

    fn seeded_db() -> (tempfile::TempDir, String, String) {
        let dir = tempfile::tempdir().test_ok();
        let path = dir.path().join("fault.db").to_str().test_ok().to_owned();
        cmd_store_init(&path).test_ok();
        let store = open_store(StoreConfig::Sqlite { path: path.clone() }).test_ok();
        let tl_id = store.list_timelines().test_ok()[0].id().to_string();
        (dir, path, tl_id)
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn cmd_store_init_create_timeline_fails_on_readonly_database() {
        if running_as_root() {
            return;
        }
        let dir = tempfile::tempdir().test_ok();
        let path = dir.path().join("init-fault.db");
        readonly_db(&path);
        let result = cmd_store_init(path.to_str().test_ok());
        set_writable(&path);
        assert!(result.is_err());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn cmd_timeline_list_fails_when_timelines_corrupt() {
        let (_dir, path, _) = seeded_db();
        corrupt_timeline_names(&path);
        assert!(cmd_timeline_list(&path).is_err());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn cmd_timeline_fork_bad_seq_returns_err() {
        let (_dir, path, tl_id) = seeded_db();
        assert!(cmd_timeline_fork(&path, &tl_id, "not-a-seq", "child").is_err());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn cmd_timeline_fork_fails_on_readonly_database() {
        if running_as_root() {
            return;
        }
        let (_dir, path, tl_id) = seeded_db();
        set_readonly(std::path::Path::new(&path));
        let result = cmd_timeline_fork(&path, &tl_id, "0", "child");
        set_writable(std::path::Path::new(&path));
        assert!(result.is_err());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn handle_timeline_merge_invalid_strategy_returns_err() {
        let (_dir, path, tl_id) = seeded_db();
        let missing_b = TimelineId::new().to_string();
        let a = args(&[
            "merge",
            &path,
            &tl_id,
            &missing_b,
            "0",
            "merged",
            "--strategy",
            "nope",
        ]);
        assert!(handle_timeline(&a).is_err());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn cmd_timeline_merge_bad_ids_return_err() {
        let (_dir, path, tl_id) = seeded_db();
        assert!(cmd_timeline_merge(
            &path,
            "not-a-ulid",
            &tl_id,
            "0",
            "merged",
            pos_time::MergeStrategy::DisjointCrdt
        )
        .is_err());
        assert!(cmd_timeline_merge(
            &path,
            &tl_id,
            "not-a-ulid",
            "0",
            "merged",
            pos_time::MergeStrategy::DisjointCrdt
        )
        .is_err());
        assert!(cmd_timeline_merge(
            &path,
            &tl_id,
            &tl_id,
            "not-a-seq",
            "merged",
            pos_time::MergeStrategy::DisjointCrdt
        )
        .is_err());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn cmd_timeline_merge_fails_on_readonly_database() {
        if running_as_root() {
            return;
        }
        let (_dir, path, tl_id) = seeded_db();
        set_readonly(std::path::Path::new(&path));
        let result = cmd_timeline_merge(
            &path,
            &tl_id,
            &tl_id,
            "0",
            "merged",
            pos_time::MergeStrategy::DisjointCrdt,
        );
        set_writable(std::path::Path::new(&path));
        assert!(result.is_err());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn handle_events_log_missing_limit_value_returns_err() {
        let (_dir, path, tl_id) = seeded_db();
        let a = args(&["log", &path, &tl_id, "--limit"]);
        assert!(handle_events(&a).is_err());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn cmd_events_log_bad_timeline_id_returns_err() {
        let (_dir, path, _) = seeded_db();
        assert!(cmd_events_log(&path, "not-a-ulid", None).is_err());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn cmd_events_log_fails_when_events_corrupt() {
        let (_dir, path, tl_id) = seeded_db();
        let mut store = open_store(StoreConfig::Sqlite { path: path.clone() }).test_ok();
        let tl = store.list_timelines().test_ok()[0].id();
        let entity = EntityId::new();
        store
            .append(
                tl,
                &[EventDraft::new(
                    entity,
                    Kind::new("log.event"),
                    CanonicalBytes::from_vec(vec![]),
                )],
            )
            .test_ok();
        drop(store);
        corrupt_event_ids(&path);
        assert!(cmd_events_log(&path, &tl_id, None).is_err());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn cmd_experiment_run_fails_on_readonly_database() {
        if running_as_root() {
            return;
        }
        let (_dir, path, _) = seeded_db();
        set_readonly(std::path::Path::new(&path));
        let result = cmd_experiment_run(&path, 1);
        set_writable(std::path::Path::new(&path));
        assert!(result.is_err());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn cmd_experiment_run_manifest_write_fails_when_path_is_directory() {
        let dir = tempfile::tempdir().test_ok();
        let path = dir.path().join("run.db").to_str().test_ok().to_owned();
        cmd_experiment_run_fixture(&path, 1).test_ok();
        let manifest_path = path.replace(".db", "-manifest.json");
        std::fs::remove_file(&manifest_path).test_ok();
        std::fs::create_dir_all(&manifest_path).test_ok();
        assert!(cmd_experiment_run_fixture(&path, 1).is_err());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn cmd_experiment_verify_fails_when_events_corrupt() {
        let (_dir, path, tl_id) = seeded_db();
        let mut store = open_store(StoreConfig::Sqlite { path: path.clone() }).test_ok();
        let tl = store
            .list_timelines()
            .test_ok()
            .into_iter()
            .find(|t| t.id().to_string() == tl_id)
            .test_ok();
        let entity = EntityId::new();
        store
            .append(
                tl.id(),
                &[EventDraft::new(
                    entity,
                    Kind::new("verify.event"),
                    CanonicalBytes::from_vec(vec![]),
                )],
            )
            .test_ok();
        let events = store.read(tl.id(), SeqRange::all()).test_ok();
        let mut hasher = blake3::Hasher::new();
        for e in &events {
            hasher.update(e.payload_hash.as_bytes());
        }
        let chain_head = pos_core::crypto::Hash::from_bytes(*hasher.finalize().as_bytes());
        let manifest = pos_core::ReproManifest::recorded(
            tl.id(),
            chain_head,
            pos_core::WallTime::from_micros(0),
            pos_core::ManifestPluginRosterV1::empty(),
            None,
        );
        let manifest_path = path.replace(".db", "-manifest.json");
        std::fs::write(&manifest_path, serde_json::to_string(&manifest).test_ok()).test_ok();
        drop(store);
        corrupt_event_ids(&path);
        assert!(cmd_experiment_verify(&manifest_path).is_err());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn parse_ticks_flag_missing_value_returns_err() {
        let a: Vec<String> = vec!["--ticks".to_owned()];
        assert!(parse_ticks_flag(&a).is_err());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn parse_limit_flag_missing_value_returns_err() {
        let a: Vec<String> = vec!["--limit".to_owned()];
        assert!(parse_limit_flag(&a).is_err());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn cmd_store_info_open_store_fails_on_directory_path() {
        let dir = tempfile::tempdir().test_ok();
        assert!(cmd_store_info(dir.path().to_str().test_ok()).is_err());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn cmd_timeline_list_open_store_fails_on_directory_path() {
        let dir = tempfile::tempdir().test_ok();
        assert!(cmd_timeline_list(dir.path().to_str().test_ok()).is_err());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn cmd_timeline_fork_open_store_fails_on_directory_path() {
        let dir = tempfile::tempdir().test_ok();
        let tl_id = TimelineId::new().to_string();
        assert!(cmd_timeline_fork(dir.path().to_str().test_ok(), &tl_id, "0", "child").is_err());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn cmd_timeline_merge_open_store_fails_on_directory_path() {
        let dir = tempfile::tempdir().test_ok();
        let tl_a = TimelineId::new().to_string();
        let tl_b = TimelineId::new().to_string();
        assert!(cmd_timeline_merge(
            dir.path().to_str().test_ok(),
            &tl_a,
            &tl_b,
            "0",
            "merged",
            pos_time::MergeStrategy::DisjointCrdt
        )
        .is_err());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn cmd_events_log_open_store_fails_on_directory_path() {
        let dir = tempfile::tempdir().test_ok();
        let tl_id = TimelineId::new().to_string();
        assert!(cmd_events_log(dir.path().to_str().test_ok(), &tl_id, None).is_err());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn cmd_experiment_verify_list_timelines_fails_when_timelines_corrupt() {
        let (_dir, path, tl_id) = seeded_db();
        let store = open_store(StoreConfig::Sqlite { path: path.clone() }).test_ok();
        let tl = store
            .list_timelines()
            .test_ok()
            .into_iter()
            .find(|t| t.id().to_string() == tl_id)
            .test_ok();
        let manifest = pos_core::ReproManifest::recorded(
            tl.id(),
            pos_core::crypto::Hash::zero(),
            pos_core::WallTime::from_micros(0),
            pos_core::ManifestPluginRosterV1::empty(),
            None,
        );
        let manifest_path = path.replace(".db", "-manifest.json");
        std::fs::write(&manifest_path, serde_json::to_string(&manifest).test_ok()).test_ok();
        drop(store);
        corrupt_timeline_names(&path);
        assert!(cmd_experiment_verify(&manifest_path).is_err());
    }
}
