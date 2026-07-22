#![forbid(unsafe_code)]
#![deny(clippy::all)]
#![warn(clippy::pedantic)]

//! `PiglorOS` Single-User MVP: decision preview.
//!
//! Shows the general loop — preferences → scored options → recommendation →
//! calibrated outcomes — using a pluggable example scenario (not trip-only).
//!
//! ```text
//! cargo run -p pos-mvp -- --scenario places
//! cargo run -p pos-mvp -- --scenario work --prefer autonomy=1.0
//! ```
#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

mod fork_compare;
mod gateway_context;

use fork_compare::{print_fork_compare, run_personal_fork_compare};
use gateway_context::{apply_society_context, fetch_society_means, plain_language_context};
use pos_core::ids::EntityId;
use pos_experiment::{BacktestConfig, BacktestRunner};
use pos_plugin_eval::{EvalPlugin, EvalReducer};
use pos_plugin_geo::{GeoPlugin, GeoReducer, SpatialCloaker};
use pos_plugin_persona::{
    PersonaEvalDriver, PersonaModel, PersonaPlugin, PersonaReducer, PreferencePair,
};
use pos_runtime::PluginRegistry;
use pos_store::StoreConfig;

/// One choice in a binary decision preview.
struct OptionSpec {
    /// Human label shown in the recommendation.
    label: &'static str,
    /// Text matched against preference dimension names.
    tags: &'static str,
    /// Short hint for why this option tends to win.
    lean: &'static str,
    /// Optional real-world coordinates (privacy-cloaked when present).
    coords: Option<(f64, f64)>,
}

/// A domain-agnostic binary decision the MVP can preview.
struct Scenario {
    /// CLI id (`--scenario <id>`).
    id: &'static str,
    /// One-line domain description (English).
    blurb: &'static str,
    option_a: OptionSpec,
    option_b: OptionSpec,
    default_prefs: &'static [(&'static str, f64)],
    /// Ground-truth pairs for the eval loop (`option_a` preferred when `prefers_a`).
    eval_pairs: &'static [(&'static str, &'static str, bool)],
}

const SCENARIO_PLACES: Scenario = Scenario {
    id: "places",
    blurb: "Where to spend a weekend — any two tagged options work the same way.",
    option_a: OptionSpec {
        label: "Kyoto",
        tags: "kyoto nature quiet temples",
        lean: "nature / quiet",
        coords: Some((35.0116, 135.7681)),
    },
    option_b: OptionSpec {
        label: "Osaka",
        tags: "osaka city food nightlife",
        lean: "city / food",
        coords: Some((34.6937, 135.5023)),
    },
    default_prefs: &[
        ("nature", 0.8),
        ("city", 0.5),
        ("food", 0.9),
        ("quiet", 0.7),
    ],
    eval_pairs: &[
        (
            "kyoto nature quiet temples",
            "osaka city food nightlife",
            true,
        ),
        ("kyoto gardens quiet", "osaka street food city", true),
        ("osaka city nightlife", "kyoto nature temples", false),
        ("kyoto quiet nature", "osaka food city", true),
        ("osaka food nightlife", "kyoto quiet temples", false),
    ],
};

const SCENARIO_WORK: Scenario = Scenario {
    id: "work",
    blurb: "How to structure next quarter — same preview loop, different domain.",
    option_a: OptionSpec {
        label: "Remote-first",
        tags: "remote autonomy focus deep-work",
        lean: "autonomy / focus",
        coords: None,
    },
    option_b: OptionSpec {
        label: "Office-first",
        tags: "office collaboration energy hallway",
        lean: "collaboration / energy",
        coords: None,
    },
    default_prefs: &[
        ("autonomy", 0.8),
        ("focus", 0.7),
        ("collaboration", 0.5),
        ("energy", 0.6),
    ],
    eval_pairs: &[
        (
            "remote autonomy focus deep-work",
            "office collaboration energy hallway",
            true,
        ),
        ("remote focus autonomy", "office collaboration energy", true),
        (
            "office collaboration energy",
            "remote autonomy focus",
            false,
        ),
        (
            "remote deep-work focus",
            "office hallway collaboration",
            true,
        ),
        (
            "office energy collaboration",
            "remote autonomy focus",
            false,
        ),
    ],
};

const SCENARIOS: &[&Scenario] = &[&SCENARIO_PLACES, &SCENARIO_WORK];

fn scenario_by_id(id: &str) -> Option<&'static Scenario> {
    SCENARIOS.iter().copied().find(|s| s.id == id)
}

fn default_scenario() -> &'static Scenario {
    &SCENARIO_PLACES
}

fn prefs_from_scenario(scenario: &Scenario) -> Vec<(String, f64)> {
    scenario
        .default_prefs
        .iter()
        .map(|(k, v)| ((*k).to_owned(), *v))
        .collect()
}

enum CliAction {
    Run {
        scenario: &'static Scenario,
        preferences: Vec<(String, f64)>,
        gateway: Option<String>,
        timeline: Option<String>,
        fork_compare: bool,
    },
    Help,
}

/// Parse CLI flags into a scenario + preference set, or help.
fn parse_cli(args: &[String]) -> Result<CliAction, String> {
    // Pass 1: resolve scenario (and help) so defaults match the chosen domain.
    let mut scenario = default_scenario();
    let mut i = 0;
    while i < args.len() {
        if args[i] == "--help" || args[i] == "-h" {
            return Ok(CliAction::Help);
        }
        if args[i] == "--scenario" {
            if let Some(id) = args.get(i + 1) {
                if let Some(s) = scenario_by_id(id) {
                    scenario = s;
                } else {
                    let known = SCENARIOS
                        .iter()
                        .map(|s| s.id)
                        .collect::<Vec<_>>()
                        .join(", ");
                    return Err(format!("unknown --scenario {id} (try: {known})"));
                }
                i += 2;
            } else {
                return Err("--scenario: expected an id".to_owned());
            }
            continue;
        }
        i += 1;
    }

    // Pass 2: start from scenario defaults, then apply --prefer overrides.
    let mut prefs = prefs_from_scenario(scenario);
    let mut gateway: Option<String> = None;
    let mut timeline: Option<String> = None;
    let mut fork_compare = false;
    i = 0;
    while i < args.len() {
        if args[i] == "--fork-compare" {
            fork_compare = true;
            i += 1;
            continue;
        }
        if args[i] == "--gateway" {
            if let Some(url) = args.get(i + 1) {
                gateway = Some(url.clone());
                i += 2;
            } else {
                return Err("--gateway: expected base URL".to_owned());
            }
            continue;
        }
        if args[i] == "--timeline" {
            if let Some(id) = args.get(i + 1) {
                timeline = Some(id.clone());
                i += 2;
            } else {
                return Err("--timeline: expected timeline id".to_owned());
            }
            continue;
        }
        if args[i] == "--prefer" {
            if let Some(spec) = args.get(i + 1) {
                match parse_prefer_spec(spec) {
                    Ok((key, value)) => apply_prefer(&mut prefs, key, value),
                    Err(msg) => eprintln!("ignoring --prefer {spec}: {msg}"),
                }
                i += 2;
            } else {
                eprintln!("ignoring --prefer: expected key=value");
                i += 1;
            }
            continue;
        }
        if args[i] == "--scenario" {
            i += args.get(i + 1).map_or(1, |_| 2);
            continue;
        }
        if args[i].starts_with('-') {
            eprintln!("ignoring unknown argument: {}", args[i]);
        }
        i += 1;
    }
    if (gateway.is_some() || timeline.is_some())
        && gateway.as_ref().zip(timeline.as_ref()).is_none()
    {
        return Err("--gateway and --timeline must be used together".to_owned());
    }
    Ok(CliAction::Run {
        scenario,
        preferences: prefs,
        gateway,
        timeline,
        fork_compare,
    })
}

fn apply_prefer(prefs: &mut Vec<(String, f64)>, key: String, value: f64) {
    if let Some((_, existing)) = prefs.iter_mut().find(|(k, _)| k.eq_ignore_ascii_case(&key)) {
        *existing = value;
    } else {
        prefs.push((key, value));
    }
}

fn parse_prefer_spec(spec: &str) -> Result<(String, f64), String> {
    let (key, raw) = spec
        .split_once('=')
        .ok_or_else(|| "expected key=value (example: focus=0.9)".to_owned())?;
    let key = key.trim().to_ascii_lowercase();
    if key.is_empty() {
        return Err("empty preference name".to_owned());
    }
    let value: f64 = raw
        .trim()
        .parse()
        .map_err(|_| format!("'{raw}' is not a number"))?;
    if !(-1.0..=1.0).contains(&value) {
        return Err("score must be between -1.0 and 1.0".to_owned());
    }
    Ok((key, value))
}

fn print_help() {
    println!("PiglorOS MVP — Decision preview");
    println!();
    println!("Preview which option fits your preferences, then check whether");
    println!("those predictions hold up against recorded outcomes.");
    println!();
    println!("Usage:");
    println!("  cargo run -p pos-mvp -- [OPTIONS]");
    println!();
    println!("Options:");
    println!("  --scenario <id>      Example decision domain (default: places)");
    for s in SCENARIOS {
        println!("                        {} — {}", s.id, s.blurb);
    }
    println!("  --prefer key=value   Override a preference score in [-1, 1]");
    println!("  --gateway <url>      Shared-world context (with --timeline)");
    println!("  --timeline <id>      Timeline ULID on the gateway");
    println!("  --fork-compare       Dual-future personal fork (#75) instead of backtest");
    println!("  -h, --help           Show this help");
    println!();
    println!("Examples:");
    println!("  cargo run -p pos-mvp");
    println!("  cargo run -p pos-mvp -- --scenario work --prefer autonomy=1.0 --prefer collaboration=0.2");
    println!("  cargo run -p pos-mvp -- --scenario places --prefer food=1.0 --prefer nature=0.2");
    println!(
        "  cargo run -p pos-mvp -- --scenario work --gateway http://127.0.0.1:8080 --timeline <id>"
    );
    println!("  cargo run -p pos-mvp -- --scenario work --fork-compare");
}

fn build_registry_with(
    preferences: Vec<(String, f64)>,
    pairs: Vec<PreferencePair>,
) -> PluginRegistry {
    let entity = EntityId::new();
    let model = PersonaModel::new(preferences);

    let mut registry = PluginRegistry::new();

    let persona = PersonaPlugin::new();
    registry
        .register(
            &persona,
            Some(Box::new(PersonaReducer)),
            Some(Box::new(PersonaEvalDriver::new(entity, model, pairs))),
        )
        .expect("persona plugin registration failed");

    let eval = EvalPlugin::new();
    registry
        .register(&eval, Some(Box::new(EvalReducer)), None)
        .expect("eval plugin registration failed");

    let geo = GeoPlugin::new();
    registry
        .register(&geo, Some(Box::new(GeoReducer)), None)
        .expect("geo plugin registration failed");

    registry
}

fn eval_pairs_for(scenario: &Scenario) -> Vec<PreferencePair> {
    scenario
        .eval_pairs
        .iter()
        .map(|(a, b, prefers_a)| PreferencePair {
            option_a: (*a).to_owned(),
            option_b: (*b).to_owned(),
            prefers_a: *prefers_a,
        })
        .collect()
}

fn format_prefs(prefs: &[(String, f64)]) -> String {
    prefs
        .iter()
        .map(|(k, v)| format!("{k}={v:.2}"))
        .collect::<Vec<_>>()
        .join(" · ")
}

fn recommend(
    score_a: f64,
    score_b: f64,
    label_a: &str,
    label_b: &str,
    lean_a: &str,
    lean_b: &str,
) -> (String, String) {
    let margin = (score_a - score_b).abs();
    if margin < 0.02 {
        (
            "Toss-up".to_owned(),
            format!(
                "Scores are nearly tied — raise ({lean_a}) for {label_a}, or ({lean_b}) for {label_b}."
            ),
        )
    } else if score_a > score_b {
        (
            label_a.to_owned(),
            format!("Closer fit to your ({lean_a}) lean. Raise ({lean_b}) if you want {label_b} to win."),
        )
    } else {
        (
            label_b.to_owned(),
            format!("Closer fit to your ({lean_b}) lean. Raise ({lean_a}) if you want {label_a} to win."),
        )
    }
}

fn explain_calibration(brier: f64, lift: f64, n_resolved: u64, n_predictions: u64) {
    println!("Did this preview hold up? (calibration check)");
    println!("  {n_resolved} of {n_predictions} predictions got real outcomes.");
    println!(
        "  Brier score {brier:.2} — lower is better (0 = perfect, 0.25 ≈ coin-flip on balanced data)."
    );
    if lift > 0.02 {
        println!(
            "  Beats a base-rate guess by {:.0}% — the preference signal helped.",
            lift * 100.0
        );
    } else if lift < -0.02 {
        println!(
            "  Trails a base-rate guess by {:.0}% — prefs shape the choice, but calibration is still rough.",
            lift.abs() * 100.0
        );
    } else {
        println!("  About even with a base-rate guess — signal is present, not yet sharp.");
    }
}

fn print_privacy(scenario: &Scenario) {
    let cloaker = SpatialCloaker::new(0.1);
    let mut any = false;
    for opt in [&scenario.option_a, &scenario.option_b] {
        if let Some((lat, lng)) = opt.coords {
            if !any {
                println!(
                    "Privacy: location-bearing options are shown as coarse grid cells (exact pins stay private)"
                );
                any = true;
            }
            let (clat, clng) = cloaker.cloak(lat, lng);
            println!("  {} ≈ ({clat:.1}, {clng:.1})", opt.label);
        }
    }
    if any {
        println!();
    }
}

fn run_mvp(
    scenario: &Scenario,
    mut preferences: Vec<(String, f64)>,
    gateway: Option<&str>,
    timeline: Option<&str>,
    fork_compare: bool,
) {
    println!("PiglorOS — Decision preview");
    println!("Scenario: {} — {}", scenario.id, scenario.blurb);
    println!();

    if let (Some(gw), Some(tl)) = (gateway, timeline) {
        match fetch_society_means(gw, tl) {
            Ok(means) if means.is_empty() => {
                println!("Shared context: no society signals on timeline {tl}");
                println!();
            }
            Ok(means) => {
                println!("Shared context (from {gw}):");
                for (dim, mean) in &means {
                    println!("  {dim} mean={mean:.2}");
                }
                println!("  In plain language:");
                for line in plain_language_context(&means) {
                    println!("    • {line}");
                }
                apply_society_context(&mut preferences, &means);
                println!("  Preferences after context nudge:");
                println!("    {}", format_prefs(&preferences));
                println!();
            }
            Err(err) => {
                eprintln!("Warning: could not load shared context: {err}");
                println!();
            }
        }
    }

    println!("Your preferences:");
    println!("  {}", format_prefs(&preferences));
    println!(
        "  Override: cargo run -p pos-mvp -- --scenario {} --prefer <key>=<value>",
        scenario.id
    );
    println!();

    let model = PersonaModel::new(preferences.clone());
    let score_a = model.score_option(scenario.option_a.tags);
    let score_b = model.score_option(scenario.option_b.tags);

    println!("Match scores:");
    println!(
        "  {:<12} {score_a:.3}  ({})",
        scenario.option_a.label, scenario.option_a.tags
    );
    println!(
        "  {:<12} {score_b:.3}  ({})",
        scenario.option_b.label, scenario.option_b.tags
    );
    println!();

    let (pick, why) = recommend(
        score_a,
        score_b,
        scenario.option_a.label,
        scenario.option_b.label,
        scenario.option_a.lean,
        scenario.option_b.lean,
    );
    println!("→ Recommendation: {pick}");
    println!("  {why}");
    println!();

    print_privacy(scenario);

    if fork_compare {
        let summary =
            run_personal_fork_compare(&preferences, scenario.option_a.tags, scenario.option_b.tags);
        print_fork_compare(&summary, scenario.option_a.label, scenario.option_b.label);
        println!();
        println!("Same loop without fork:");
        println!("  cargo run -p pos-mvp -- --scenario {}", scenario.id);
        return;
    }

    let pairs = eval_pairs_for(scenario);
    let prefs_for_registry = preferences;
    let config = BacktestConfig {
        experiment_name: format!("mvp-{}", scenario.id),
        train_ticks: 5,
        eval_ticks: 5,
        store_config: StoreConfig::Memory,
    };

    let result = BacktestRunner::new(config, move || {
        build_registry_with(prefs_for_registry.clone(), pairs.clone())
    })
    .run()
    .expect("backtest run failed");

    let report = &result.eval_report;
    assert!(
        report.n_resolved > 0,
        "MVP must close the eval loop (n_resolved > 0)"
    );

    explain_calibration(
        report.brier_score,
        report.lift_vs_persistence,
        report.n_resolved,
        report.n_predictions,
    );
    println!();
    println!("Same loop, other domains:");
    println!("  cargo run -p pos-mvp -- --scenario work --prefer autonomy=1.0 --prefer collaboration=0.2");
    println!("  cargo run -p pos-mvp -- --scenario places --prefer food=1.0 --prefer nature=0.2");
}

fn run_from_args(args: &[String]) -> Result<(), String> {
    match parse_cli(args)? {
        CliAction::Help => print_help(),
        CliAction::Run {
            scenario,
            preferences,
            gateway,
            timeline,
            fork_compare,
        } => run_mvp(
            scenario,
            preferences,
            gateway.as_deref(),
            timeline.as_deref(),
            fork_compare,
        ),
    }
    Ok(())
}

fn main() -> Result<(), String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    run_from_args(&args)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn mvp_smoke_test() {
        let model = PersonaModel::new(vec![("nature".to_owned(), 0.8), ("food".to_owned(), 0.9)]);
        let score = model.score_option("kyoto nature");
        assert!(score > 0.0);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn mvp_backtest_resolves_predictions() {
        let scenario = default_scenario();
        let prefs = prefs_from_scenario(scenario);
        let pairs = eval_pairs_for(scenario);
        let config = BacktestConfig {
            experiment_name: "mvp-test".to_owned(),
            train_ticks: 3,
            eval_ticks: 3,
            store_config: StoreConfig::Memory,
        };
        let result = BacktestRunner::new(config, move || {
            build_registry_with(prefs.clone(), pairs.clone())
        })
        .run()
        .expect("backtest");
        assert!(result.eval_report.n_resolved >= 3);
        assert!(result.eval_report.brier_score >= 0.0);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn main_does_not_panic() {
        let _ = main();
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn help_flag_prints_usage() {
        run_from_args(&["--help".to_owned()]).expect("help");
        run_from_args(&["-h".to_owned()]).expect("help");
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn prefer_overrides_update_scores_for_places() {
        let args = vec![
            "--scenario".to_owned(),
            "places".to_owned(),
            "--prefer".to_owned(),
            "nature=0.1".to_owned(),
            "--prefer".to_owned(),
            "food=1.0".to_owned(),
            "--prefer".to_owned(),
            "city=0.95".to_owned(),
        ];
        let CliAction::Run {
            scenario,
            preferences,
            ..
        } = parse_cli(&args).expect("parse ok")
        else {
            panic!("expected Run");
        };
        assert_eq!(scenario.id, "places");
        let model = PersonaModel::new(preferences);
        let a = model.score_option(scenario.option_a.tags);
        let b = model.score_option(scenario.option_b.tags);
        assert!(b > a, "food/city prefs should favor Osaka");
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn work_scenario_autonomy_favors_remote() {
        let args = vec![
            "--scenario".to_owned(),
            "work".to_owned(),
            "--prefer".to_owned(),
            "autonomy=1.0".to_owned(),
            "--prefer".to_owned(),
            "focus=0.9".to_owned(),
            "--prefer".to_owned(),
            "collaboration=0.1".to_owned(),
            "--prefer".to_owned(),
            "energy=0.1".to_owned(),
        ];
        let CliAction::Run {
            scenario,
            preferences,
            ..
        } = parse_cli(&args).expect("parse ok")
        else {
            panic!("expected Run");
        };
        assert_eq!(scenario.id, "work");
        let model = PersonaModel::new(preferences);
        let remote = model.score_option(scenario.option_a.tags);
        let office = model.score_option(scenario.option_b.tags);
        assert!(remote > office);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn parse_prefer_spec_rejects_bad_input() {
        assert!(parse_prefer_spec("food").is_err());
        assert!(parse_prefer_spec("=1").is_err());
        assert!(parse_prefer_spec("food=nope").is_err());
        assert!(parse_prefer_spec("food=2.0").is_err());
        assert_eq!(parse_prefer_spec("Food=0.5").unwrap().0, "food");
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn recommend_covers_all_branches() {
        let (pick, _) = recommend(0.9, 0.5, "A", "B", "lean-a", "lean-b");
        assert_eq!(pick, "A");
        let (pick, _) = recommend(0.5, 0.9, "A", "B", "lean-a", "lean-b");
        assert_eq!(pick, "B");
        let (pick, _) = recommend(0.5, 0.51, "A", "B", "lean-a", "lean-b");
        assert_eq!(pick, "Toss-up");
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn parse_cli_rejects_unknown_scenario() {
        match parse_cli(&["--scenario".to_owned(), "nope".to_owned()]) {
            Err(err) => assert!(err.contains("unknown --scenario nope"), "{err}"),
            Ok(_) => panic!("expected error for unknown scenario"),
        }
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn run_from_args_rejects_unknown_scenario() {
        let err = run_from_args(&["--scenario".to_owned(), "nope".to_owned()])
            .expect_err("unknown scenario must hard-fail");
        assert!(err.contains("unknown --scenario nope"), "{err}");
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn parse_cli_handles_noise_and_soft_prefer_errors() {
        let args = vec![
            "--prefer".to_owned(),
            "adventure=0.6".to_owned(),
            "--prefer".to_owned(),
            "broken".to_owned(),
            "harness_filter".to_owned(),
            "--unknown-flag".to_owned(),
            "--prefer".to_owned(), // dangling prefer value
        ];
        let CliAction::Run { preferences, .. } = parse_cli(&args).expect("parse ok") else {
            panic!("expected Run");
        };
        assert!(preferences
            .iter()
            .any(|(k, v)| k == "adventure" && (*v - 0.6).abs() < f64::EPSILON));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn explain_calibration_runs_for_lift_signs() {
        explain_calibration(0.2, 0.1, 5, 5);
        explain_calibration(0.2, -0.1, 5, 5);
        explain_calibration(0.2, 0.0, 5, 5);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn format_prefs_lists_pairs() {
        let s = format_prefs(&[("nature".to_owned(), 0.8)]);
        assert!(s.contains("nature=0.80"));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn run_places_and_work_scenarios() {
        run_from_args(&[
            "--scenario".to_owned(),
            "places".to_owned(),
            "--prefer".to_owned(),
            "food=1.0".to_owned(),
            "--prefer".to_owned(),
            "city=0.9".to_owned(),
            "--prefer".to_owned(),
            "nature=0.2".to_owned(),
            "--prefer".to_owned(),
            "quiet=0.2".to_owned(),
        ])
        .expect("places");
        run_from_args(&[
            "--scenario".to_owned(),
            "work".to_owned(),
            "--prefer".to_owned(),
            "autonomy=1.0".to_owned(),
            "--prefer".to_owned(),
            "collaboration=0.2".to_owned(),
        ])
        .expect("work");
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn parse_cli_dangling_flags() {
        match parse_cli(&["--scenario".to_owned()]) {
            Err(err) => assert!(err.contains("expected an id"), "{err}"),
            Ok(_) => panic!("expected error for dangling --scenario"),
        }
        let CliAction::Run { .. } = parse_cli(&["--prefer".to_owned()]).expect("soft prefer")
        else {
            panic!("expected Run");
        };
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn run_mvp_gateway_warning_on_unreachable() {
        run_mvp(
            default_scenario(),
            prefs_from_scenario(default_scenario()),
            Some("http://127.0.0.1:1"),
            Some("01ARZ3NDEKTSV4RRFFQ69G5FAV"),
            false,
        );
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn run_mvp_gateway_empty_means() {
        use std::io::{Read, Write};
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let body = r#"{"events":[]}"#;
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let _ = stream.read(&mut [0u8; 1024]);
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(response.as_bytes());
        });
        run_mvp(
            default_scenario(),
            prefs_from_scenario(default_scenario()),
            Some(&format!("http://{addr}")),
            Some("01ARZ3NDEKTSV4RRFFQ69G5FAV"),
            false,
        );
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn run_mvp_gateway_applies_context() {
        use std::io::{Read, Write};
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let body = r#"{"events":[{"event_type":"society.signal","payload":{"dimension":"nature","value":0.9}}]}"#;
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let _ = stream.read(&mut [0u8; 1024]);
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(response.as_bytes());
        });
        run_mvp(
            default_scenario(),
            prefs_from_scenario(default_scenario()),
            Some(&format!("http://{addr}")),
            Some("01ARZ3NDEKTSV4RRFFQ69G5FAV"),
            false,
        );
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn run_mvp_fork_compare_path() {
        run_mvp(
            default_scenario(),
            prefs_from_scenario(default_scenario()),
            None,
            None,
            true,
        );
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn parse_cli_fork_compare_flag() {
        let CliAction::Run { fork_compare, .. } =
            parse_cli(&["--fork-compare".to_owned()]).unwrap()
        else {
            panic!("expected Run");
        };
        assert!(fork_compare);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn parse_cli_dangling_gateway_and_timeline() {
        match parse_cli(&["--gateway".to_owned()]) {
            Err(err) => assert!(err.contains("expected base URL"), "{err}"),
            Ok(_) => panic!("expected dangling --gateway error"),
        }
        match parse_cli(&["--timeline".to_owned()]) {
            Err(err) => assert!(err.contains("expected timeline id"), "{err}"),
            Ok(_) => panic!("expected dangling --timeline error"),
        }
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn parse_cli_accepts_gateway_and_timeline() {
        let CliAction::Run {
            scenario,
            preferences,
            gateway,
            timeline,
            fork_compare,
        } = parse_cli(&[
            "--scenario".to_owned(),
            "places".to_owned(),
            "--gateway".to_owned(),
            "http://127.0.0.1:8080".to_owned(),
            "--timeline".to_owned(),
            "01ARZ3NDEKTSV4RRFFQ69G5FAV".to_owned(),
        ])
        .unwrap()
        else {
            panic!("expected Run action");
        };
        assert_eq!(scenario.id, "places");
        assert!(!preferences.is_empty());
        assert_eq!(gateway.as_deref(), Some("http://127.0.0.1:8080"));
        assert_eq!(timeline.as_deref(), Some("01ARZ3NDEKTSV4RRFFQ69G5FAV"));
        assert!(!fork_compare);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn parse_cli_gateway_requires_timeline() {
        match parse_cli(&["--gateway".to_owned(), "http://127.0.0.1:8080".to_owned()]) {
            Err(err) => assert!(err.contains("together"), "{err}"),
            Ok(_) => panic!("expected error when timeline missing"),
        }
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn scenario_by_id_finds_known() {
        assert!(scenario_by_id("places").is_some());
        assert!(scenario_by_id("work").is_some());
        assert!(scenario_by_id("nope").is_none());
    }
}
