#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

use pos_core::{EntityId, TimelineId};
use pos_experiment::{Experiment, ExperimentConfig, ExperimentError, StopCondition, TickOutcome};
use pos_plugin_agent::{
    AgentAction, AgentContext, AgentDriver, AgentPlugin, AgentPolicy, AgentReducer,
    RoundRobinPolicy,
};
use pos_plugin_society::{SocietyPlugin, SocietyReducer};
use pos_store::StoreConfig;
use serde_json::Value;
use std::{
    process::ExitCode,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};

const USAGE: &str = "Usage:\n  pos-experiment multi-rate-demo <sqlite-path> <timeline-id> [--ticks N] [--quantum-ms N] [--pace-ms N]\n\nDefaults: --ticks 20 --quantum-ms 100 --pace-ms 100";

#[derive(Debug)]
enum Command {
    Help,
    MultiRate(DemoArgs),
}

#[derive(Debug)]
struct DemoArgs {
    sqlite_path: String,
    timeline_id: TimelineId,
    ticks: u64,
    quantum_ms: u64,
    pace_ms: u64,
}

#[derive(Debug, PartialEq, Eq)]
struct BoundaryOutcome {
    now_ns: u128,
    outcome: TickOutcome,
}

#[derive(Debug)]
struct DemoSummary {
    boundaries: u64,
    fast_actions: u64,
    slow_actions: u64,
    outcomes: Vec<BoundaryOutcome>,
}

#[derive(Debug, thiserror::Error)]
enum DemoError {
    #[error("{0}")]
    Usage(String),
    #[error("invalid Timeline id: {0}")]
    InvalidTimeline(String),
    #[error("ticks must be greater than zero")]
    ZeroTicks,
    #[error("quantum-ms must be greater than zero")]
    ZeroQuantum,
    #[error("simulation time overflow")]
    SimulationTimeOverflow,
    #[error(transparent)]
    Experiment(#[from] ExperimentError),
}

struct CountingPolicy {
    inner: RoundRobinPolicy,
    decisions: Arc<AtomicU64>,
}

impl AgentPolicy for CountingPolicy {
    fn name(&self) -> &'static str {
        "counting-round-robin"
    }

    fn decide(&mut self, context: &AgentContext) -> AgentAction {
        self.decisions.fetch_add(1, Ordering::SeqCst);
        self.inner.decide(context)
    }
}

fn parse_args(args: &[String]) -> Result<Command, DemoError> {
    if args.is_empty() || matches!(args.first().map(String::as_str), Some("--help" | "-h")) {
        return Ok(Command::Help);
    }
    if args.first().map(String::as_str) != Some("multi-rate-demo") {
        return Err(DemoError::Usage(format!("unknown command: {}", args[0])));
    }
    if args
        .get(1)
        .is_some_and(|value| value == "--help" || value == "-h")
    {
        return Ok(Command::Help);
    }
    let sqlite_path = args
        .get(1)
        .filter(|value| !value.starts_with('-'))
        .ok_or_else(|| DemoError::Usage("missing SQLite path".to_owned()))?
        .clone();
    let timeline_text = args
        .get(2)
        .filter(|value| !value.starts_with('-'))
        .ok_or_else(|| DemoError::Usage("missing Timeline id".to_owned()))?;
    let timeline_id = serde_json::from_value::<TimelineId>(Value::String(timeline_text.clone()))
        .map_err(|_| DemoError::InvalidTimeline(timeline_text.clone()))?;

    let mut ticks = 20;
    let mut quantum_ms = 100;
    let mut pace_ms = 100;
    let mut seen_ticks = false;
    let mut seen_quantum = false;
    let mut seen_pace = false;
    let mut index = 3;
    while index < args.len() {
        let option = args[index].as_str();
        if !option.starts_with('-') {
            return Err(DemoError::Usage(format!("unexpected argument: {option}")));
        }
        match option {
            "--ticks" => {
                if seen_ticks {
                    return Err(DemoError::Usage(format!("duplicate option: {option}")));
                }
                ticks = parse_option_value(args, index, option)?;
                seen_ticks = true;
            }
            "--quantum-ms" => {
                if seen_quantum {
                    return Err(DemoError::Usage(format!("duplicate option: {option}")));
                }
                quantum_ms = parse_option_value(args, index, option)?;
                seen_quantum = true;
            }
            "--pace-ms" => {
                if seen_pace {
                    return Err(DemoError::Usage(format!("duplicate option: {option}")));
                }
                pace_ms = parse_option_value(args, index, option)?;
                seen_pace = true;
            }
            unknown => {
                return Err(DemoError::Usage(format!("unknown option: {unknown}")));
            }
        }
        index += 2;
    }
    if ticks == 0 {
        return Err(DemoError::ZeroTicks);
    }
    if quantum_ms == 0 {
        return Err(DemoError::ZeroQuantum);
    }
    Ok(Command::MultiRate(DemoArgs {
        sqlite_path,
        timeline_id,
        ticks,
        quantum_ms,
        pace_ms,
    }))
}

fn parse_option_value(args: &[String], index: usize, option: &str) -> Result<u64, DemoError> {
    let value = args
        .get(index + 1)
        .ok_or_else(|| DemoError::Usage(format!("missing value for {option}")))?;
    value
        .parse::<u64>()
        .map_err(|_| DemoError::Usage(format!("invalid value for {option}: {value}")))
}

fn simulation_time_ns(index: u64, quantum_ms: u64) -> Result<u128, DemoError> {
    u128::from(index)
        .checked_mul(u128::from(quantum_ms))
        .and_then(|millis| millis.checked_mul(1_000_000))
        .ok_or(DemoError::SimulationTimeOverflow)
}

fn register_multi_rate_plugins(
    experiment: &mut Experiment,
    society: &SocietyPlugin,
    fast: &AgentPlugin,
    slow: &AgentPlugin,
    fast_actions: &Arc<AtomicU64>,
    slow_actions: &Arc<AtomicU64>,
) -> Result<(), ExperimentError> {
    experiment.register(society, Some(Box::new(SocietyReducer)), None)?;
    experiment.register(
        fast,
        Some(Box::new(AgentReducer)),
        Some(Box::new(AgentDriver::new(
            EntityId::new(),
            Box::new(CountingPolicy {
                inner: RoundRobinPolicy::new(vec!["fast".to_owned()]),
                decisions: Arc::clone(fast_actions),
            }),
            vec!["fast".to_owned()],
        ))),
    )?;
    experiment.register(
        slow,
        Some(Box::new(AgentReducer)),
        Some(Box::new(
            AgentDriver::new(
                EntityId::new(),
                Box::new(CountingPolicy {
                    inner: RoundRobinPolicy::new(vec!["slow".to_owned()]),
                    decisions: Arc::clone(slow_actions),
                }),
                vec!["slow".to_owned()],
            )
            .with_tick_interval(Duration::from_millis(200)),
        )),
    )?;
    Ok(())
}

fn run_multi_rate_demo(args: &DemoArgs) -> Result<DemoSummary, DemoError> {
    if args.ticks == 0 {
        return Err(DemoError::ZeroTicks);
    }
    if args.quantum_ms == 0 {
        return Err(DemoError::ZeroQuantum);
    }
    let last_simulation_ns = simulation_time_ns(args.ticks - 1, args.quantum_ms)?;
    let fast_actions = Arc::new(AtomicU64::new(0));
    let slow_actions = Arc::new(AtomicU64::new(0));
    let society = SocietyPlugin::new();
    let fast = AgentPlugin::new();
    let slow = AgentPlugin::new();
    let mut experiment = Experiment::new(ExperimentConfig {
        name: "multi-rate-demo".to_owned(),
        stop: StopCondition::MaxTicks(args.ticks),
        store_config: StoreConfig::Sqlite {
            path: args.sqlite_path.clone(),
        },
    });
    register_multi_rate_plugins(
        &mut experiment,
        &society,
        &fast,
        &slow,
        &fast_actions,
        &slow_actions,
    )?;

    let mut session = experiment.resume(args.timeline_id)?;
    let mut outcomes = Vec::new();
    let quantum_ns = u128::from(args.quantum_ms) * 1_000_000;
    for index in 0..args.ticks {
        // The final boundary was checked before opening the store, so every
        // earlier index is also representable and this multiplication is safe.
        let now_ns = u128::from(index) * quantum_ns;
        let outcome = session.step_cadenced(now_ns)?;
        println!("boundary {index}: simulation_ns={now_ns} outcome={outcome:?}");
        outcomes.push(BoundaryOutcome { now_ns, outcome });
        if args.pace_ms != 0 {
            std::thread::sleep(Duration::from_millis(args.pace_ms));
        }
    }
    let summary = DemoSummary {
        boundaries: args.ticks,
        fast_actions: fast_actions.load(Ordering::SeqCst),
        slow_actions: slow_actions.load(Ordering::SeqCst),
        outcomes,
    };
    println!(
        "complete: boundaries={} recorded_outcomes={} last_simulation_ns={} fast_actions={} slow_actions={}",
        summary.boundaries,
        summary.outcomes.len(),
        last_simulation_ns,
        summary.fast_actions,
        summary.slow_actions
    );
    Ok(summary)
}

fn run_cli(args: &[String]) -> Result<(), DemoError> {
    match parse_args(args)? {
        Command::Help => {
            println!("{USAGE}");
            Ok(())
        }
        Command::MultiRate(args) => run_multi_rate_demo(&args).map(|_| ()),
    }
}

fn exit_for(args: &[String]) -> ExitCode {
    match run_cli(args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error}\n\n{USAGE}");
            ExitCode::FAILURE
        }
    }
}

#[cfg_attr(coverage_nightly, coverage(off))]
fn main() -> ExitCode {
    exit_for(&std::env::args().skip(1).collect::<Vec<_>>())
}

#[cfg(test)]
mod tests {
    use super::*;
    use pos_experiment::TickOutcome;
    use pos_store::{open_store, StoreConfig};

    fn strings(values: &[&str]) -> Vec<String> {
        values.iter().map(ToString::to_string).collect()
    }

    fn timeline_text() -> String {
        pos_core::TimelineId::new().to_string()
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn parse_multi_rate(values: &[&str]) -> DemoArgs {
        match parse_args(&strings(values)).expect("arguments parse") {
            Command::MultiRate(args) => args,
            Command::Help => panic!("expected multi-rate command"),
        }
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn multi_rate_demo_help_and_no_command_are_help() {
        assert!(matches!(parse_args(&[]).unwrap(), Command::Help));
        assert!(matches!(
            parse_args(&strings(&["--help"])).unwrap(),
            Command::Help
        ));
        assert!(matches!(
            parse_args(&strings(&["multi-rate-demo", "--help"])).unwrap(),
            Command::Help
        ));
        assert!(matches!(
            parse_args(&strings(&["-h"])).unwrap(),
            Command::Help
        ));
        assert!(matches!(
            parse_args(&strings(&["multi-rate-demo", "-h"])).unwrap(),
            Command::Help
        ));
        assert!(run_cli(&[]).is_ok());
        assert_eq!(exit_for(&[]), ExitCode::SUCCESS);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn multi_rate_demo_cli_reports_usage_errors() {
        assert!(matches!(
            parse_args(&strings(&["unknown"])),
            Err(DemoError::Usage(message)) if message.contains("unknown command")
        ));
        assert!(matches!(
            parse_args(&strings(&["multi-rate-demo"])),
            Err(DemoError::Usage(message)) if message.contains("SQLite path")
        ));
        assert!(matches!(
            parse_args(&strings(&["multi-rate-demo", "/tmp/demo.db"])),
            Err(DemoError::Usage(message)) if message.contains("Timeline id")
        ));
        assert_eq!(exit_for(&strings(&["unknown"])), ExitCode::FAILURE);
        let _ = super::main();
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn multi_rate_demo_parser_uses_exact_defaults() {
        let timeline = timeline_text();
        let parsed = parse_multi_rate(&["multi-rate-demo", "/tmp/demo.db", &timeline]);
        assert_eq!(parsed.sqlite_path, "/tmp/demo.db");
        assert_eq!(parsed.timeline_id.to_string(), timeline);
        assert_eq!(parsed.ticks, 20);
        assert_eq!(parsed.quantum_ms, 100);
        assert_eq!(parsed.pace_ms, 100);
        let policy = CountingPolicy {
            inner: RoundRobinPolicy::new(vec!["observe".to_owned()]),
            decisions: Arc::new(AtomicU64::new(0)),
        };
        assert_eq!(policy.name(), "counting-round-robin");
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn multi_rate_demo_parser_accepts_each_reordered_override() {
        let timeline = timeline_text();
        let parsed = parse_multi_rate(&[
            "multi-rate-demo",
            "/tmp/demo.db",
            &timeline,
            "--pace-ms",
            "0",
            "--ticks",
            "3",
            "--quantum-ms",
            "250",
        ]);
        assert_eq!(parsed.ticks, 3);
        assert_eq!(parsed.quantum_ms, 250);
        assert_eq!(parsed.pace_ms, 0);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn multi_rate_demo_parser_rejects_duplicate_flags() {
        let timeline = timeline_text();
        for flag in ["--ticks", "--quantum-ms", "--pace-ms"] {
            let error = parse_args(&strings(&[
                "multi-rate-demo",
                "/tmp/demo.db",
                &timeline,
                flag,
                "1",
                flag,
                "2",
            ]))
            .unwrap_err();
            assert!(error.to_string().contains("duplicate"), "{error}");
        }
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn multi_rate_demo_parser_rejects_unknown_flags_and_extra_positionals() {
        let timeline = timeline_text();
        let unknown = parse_args(&strings(&[
            "multi-rate-demo",
            "/tmp/demo.db",
            &timeline,
            "--unknown",
        ]))
        .unwrap_err();
        assert!(unknown.to_string().contains("unknown option"));

        let extra = parse_args(&strings(&[
            "multi-rate-demo",
            "/tmp/demo.db",
            &timeline,
            "extra",
        ]))
        .unwrap_err();
        assert!(extra.to_string().contains("unexpected argument"));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn multi_rate_demo_parser_rejects_missing_values_and_bad_numbers() {
        let timeline = timeline_text();
        for values in [
            vec![
                "multi-rate-demo",
                "/tmp/demo.db",
                timeline.as_str(),
                "--ticks",
            ],
            vec![
                "multi-rate-demo",
                "/tmp/demo.db",
                timeline.as_str(),
                "--quantum-ms",
                "many",
            ],
            vec![
                "multi-rate-demo",
                "/tmp/demo.db",
                timeline.as_str(),
                "--pace-ms",
                "eventually",
            ],
        ] {
            assert!(matches!(
                parse_args(&strings(&values)),
                Err(DemoError::Usage(_))
            ));
        }
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn multi_rate_plugin_registration_propagates_duplicate_plugin_errors() {
        let mut experiment = Experiment::new(ExperimentConfig {
            name: "registration-failure".to_owned(),
            stop: StopCondition::MaxTicks(1),
            store_config: StoreConfig::Memory,
        });
        let society = SocietyPlugin::new();
        let fast = AgentPlugin::new();
        let slow = AgentPlugin::new();
        let fast_actions = Arc::new(AtomicU64::new(0));
        let slow_actions = Arc::new(AtomicU64::new(0));

        register_multi_rate_plugins(
            &mut experiment,
            &society,
            &fast,
            &slow,
            &fast_actions,
            &slow_actions,
        )
        .unwrap();
        assert!(matches!(
            register_multi_rate_plugins(
                &mut experiment,
                &society,
                &fast,
                &slow,
                &fast_actions,
                &slow_actions,
            ),
            Err(ExperimentError::Runtime(_))
        ));

        let mut fast_duplicate_experiment = Experiment::new(ExperimentConfig {
            name: "fast-duplicate".to_owned(),
            stop: StopCondition::MaxTicks(1),
            store_config: StoreConfig::Memory,
        });
        register_multi_rate_plugins(
            &mut fast_duplicate_experiment,
            &SocietyPlugin::new(),
            &fast,
            &AgentPlugin::new(),
            &fast_actions,
            &slow_actions,
        )
        .unwrap();
        assert!(register_multi_rate_plugins(
            &mut fast_duplicate_experiment,
            &SocietyPlugin::new(),
            &fast,
            &AgentPlugin::new(),
            &fast_actions,
            &slow_actions,
        )
        .is_err());

        let mut slow_duplicate_experiment = Experiment::new(ExperimentConfig {
            name: "slow-duplicate".to_owned(),
            stop: StopCondition::MaxTicks(1),
            store_config: StoreConfig::Memory,
        });
        register_multi_rate_plugins(
            &mut slow_duplicate_experiment,
            &SocietyPlugin::new(),
            &AgentPlugin::new(),
            &slow,
            &fast_actions,
            &slow_actions,
        )
        .unwrap();
        assert!(register_multi_rate_plugins(
            &mut slow_duplicate_experiment,
            &SocietyPlugin::new(),
            &AgentPlugin::new(),
            &slow,
            &fast_actions,
            &slow_actions,
        )
        .is_err());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn multi_rate_demo_parser_rejects_invalid_timeline_and_zero_bounds() {
        assert!(matches!(
            parse_args(&strings(&["multi-rate-demo", "/tmp/demo.db", "not-a-ulid"])),
            Err(DemoError::InvalidTimeline(value)) if value == "not-a-ulid"
        ));

        let timeline = timeline_text();
        assert!(matches!(
            parse_args(&strings(&[
                "multi-rate-demo",
                "/tmp/demo.db",
                &timeline,
                "--ticks",
                "0",
            ])),
            Err(DemoError::ZeroTicks)
        ));
        assert!(matches!(
            parse_args(&strings(&[
                "multi-rate-demo",
                "/tmp/demo.db",
                &timeline,
                "--quantum-ms",
                "0",
            ])),
            Err(DemoError::ZeroQuantum)
        ));
        assert_eq!(
            parse_multi_rate(&[
                "multi-rate-demo",
                "/tmp/demo.db",
                &timeline,
                "--pace-ms",
                "0",
            ])
            .pace_ms,
            0
        );
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn multi_rate_demo_finite_loop_returns_exact_times_and_counts() {
        let database = tempfile::NamedTempFile::new().unwrap();
        let path = database.path().to_string_lossy().into_owned();
        let timeline = {
            let mut store = open_store(StoreConfig::Sqlite { path: path.clone() }).unwrap();
            store.create_timeline("multi-rate-demo").unwrap().id()
        };
        let summary = run_multi_rate_demo(&DemoArgs {
            sqlite_path: path,
            timeline_id: timeline,
            ticks: 3,
            quantum_ms: 100,
            pace_ms: 0,
        })
        .unwrap();

        assert_eq!(summary.boundaries, 3);
        assert_eq!(summary.fast_actions, 3);
        assert_eq!(summary.slow_actions, 2);
        assert_eq!(
            summary
                .outcomes
                .iter()
                .map(|boundary| boundary.now_ns)
                .collect::<Vec<_>>(),
            vec![0, 100_000_000, 200_000_000]
        );
        assert!(summary
            .outcomes
            .iter()
            .all(|boundary| matches!(boundary.outcome, TickOutcome::Advanced { .. })));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn multi_rate_demo_cli_runs_one_paced_boundary() {
        let database = tempfile::NamedTempFile::new().unwrap();
        let path = database.path().to_string_lossy().into_owned();
        let timeline = {
            let mut store = open_store(StoreConfig::Sqlite { path: path.clone() }).unwrap();
            store.create_timeline("cli-demo").unwrap().id()
        };
        assert!(run_cli(&strings(&[
            "multi-rate-demo",
            &path,
            &timeline.to_string(),
            "--ticks",
            "1",
            "--pace-ms",
            "1",
        ]))
        .is_ok());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn multi_rate_demo_reports_missing_timeline() {
        let database = tempfile::NamedTempFile::new().unwrap();
        let error = run_multi_rate_demo(&DemoArgs {
            sqlite_path: database.path().to_string_lossy().into_owned(),
            timeline_id: pos_core::TimelineId::new(),
            ticks: 1,
            quantum_ms: 100,
            pace_ms: 0,
        })
        .unwrap_err();
        assert!(error.to_string().contains("timeline not found"), "{error}");
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn multi_rate_demo_rejects_simulation_time_overflow() {
        let database = tempfile::NamedTempFile::new().unwrap();
        let path = database.path().to_string_lossy().into_owned();
        let timeline = {
            let mut store = open_store(StoreConfig::Sqlite { path: path.clone() }).unwrap();
            store.create_timeline("overflow-demo").unwrap().id()
        };
        let error = run_multi_rate_demo(&DemoArgs {
            sqlite_path: path,
            timeline_id: timeline,
            ticks: u64::MAX,
            quantum_ms: u64::MAX,
            pace_ms: 0,
        })
        .unwrap_err();
        assert!(matches!(error, DemoError::SimulationTimeOverflow));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn multi_rate_demo_runner_rejects_zero_bounds_without_panicking() {
        let base = DemoArgs {
            sqlite_path: "/tmp/not-opened.db".to_owned(),
            timeline_id: pos_core::TimelineId::new(),
            ticks: 0,
            quantum_ms: 100,
            pace_ms: 0,
        };
        assert!(matches!(
            run_multi_rate_demo(&base),
            Err(DemoError::ZeroTicks)
        ));
        assert!(matches!(
            run_multi_rate_demo(&DemoArgs {
                ticks: 1,
                quantum_ms: 0,
                ..base
            }),
            Err(DemoError::ZeroQuantum)
        ));
    }
}
