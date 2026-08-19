#![forbid(unsafe_code)]
#![deny(clippy::all)]
#![warn(clippy::pedantic)]

//! `PiglorOS` Single-User MVP: decision preview.
//!
//! Shows the general loop — preferences → scored options → recommendation.
//!
//! ```text
//! cargo run -p pos-mvp -- --prefer nature=0.8 --prefer food=0.9
//! cargo run -p pos-mvp -- --a-label "Option A" --a-tags "nature quiet" \
//!                         --b-label "Option B" --b-tags "city food" \
//!                         --prefer nature=0.8
//! ```
#![cfg_attr(all(coverage_nightly, test), feature(coverage_attribute))]

mod ai_influence;
mod fork_compare;
mod gateway_context;

use ai_influence::{format_ai_influence_lines, local_ai_influence, unavailable_ai_influence};
use fork_compare::{print_fork_compare, run_personal_fork_compare};
use gateway_context::{apply_society_context, fetch_timeline_context, plain_language_context};
use pos_core::ids::EntityId;
use pos_plugin_persona::{PersonaEvalDriver, PersonaModel, PersonaPlugin, PersonaReducer};
use pos_runtime::PluginRegistry;

enum CliAction {
    Run {
        option_a_label: String,
        option_a_tags: String,
        option_b_label: String,
        option_b_tags: String,
        preferences: Vec<(String, f64)>,
        gateway: Option<String>,
        timeline: Option<String>,
        fork_compare: bool,
    },
    Help,
}

/// Parse CLI flags into an action.
fn parse_cli(args: &[String]) -> Result<CliAction, String> {
    let mut option_a_label = "Option A".to_owned();
    let mut option_a_tags = String::new();
    let mut option_b_label = "Option B".to_owned();
    let mut option_b_tags = String::new();
    let mut prefs: Vec<(String, f64)> = Vec::new();
    let mut gateway: Option<String> = None;
    let mut timeline: Option<String> = None;
    let mut fork_compare = false;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--help" | "-h" => return Ok(CliAction::Help),
            "--a-label" => {
                option_a_label = args.get(i + 1).ok_or("--a-label: expected text")?.clone();
                i += 2;
            }
            "--a-tags" => {
                option_a_tags = args
                    .get(i + 1)
                    .ok_or("--a-tags: expected tag string")?
                    .clone();
                i += 2;
            }
            "--b-label" => {
                option_b_label = args.get(i + 1).ok_or("--b-label: expected text")?.clone();
                i += 2;
            }
            "--b-tags" => {
                option_b_tags = args
                    .get(i + 1)
                    .ok_or("--b-tags: expected tag string")?
                    .clone();
                i += 2;
            }
            "--prefer" => {
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
            }
            "--gateway" => {
                gateway = Some(
                    args.get(i + 1)
                        .ok_or("--gateway: expected base URL")?
                        .clone(),
                );
                i += 2;
            }
            "--timeline" => {
                timeline = Some(
                    args.get(i + 1)
                        .ok_or("--timeline: expected timeline id")?
                        .clone(),
                );
                i += 2;
            }
            "--fork-compare" => {
                fork_compare = true;
                i += 1;
            }
            flag if flag.starts_with('-') => {
                eprintln!("ignoring unknown argument: {flag}");
                i += 1;
            }
            _ => {
                i += 1;
            }
        }
    }
    if (gateway.is_some() || timeline.is_some())
        && gateway.as_ref().zip(timeline.as_ref()).is_none()
    {
        return Err("--gateway and --timeline must be used together".to_owned());
    }
    Ok(CliAction::Run {
        option_a_label,
        option_a_tags,
        option_b_label,
        option_b_tags,
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
    println!("Preview which option fits your preferences best.");
    println!();
    println!("Usage:");
    println!("  cargo run -p pos-mvp -- [OPTIONS]");
    println!();
    println!("Options:");
    println!("  --a-label TEXT       Label for option A (default: \"Option A\")");
    println!("  --a-tags TEXT        Space-separated tags for option A");
    println!("  --b-label TEXT       Label for option B (default: \"Option B\")");
    println!("  --b-tags TEXT        Space-separated tags for option B");
    println!("  --prefer key=value   Set a preference score in [-1, 1]");
    println!("  --gateway <url>      Shared-world context + AI Influence (with --timeline)");
    println!("  --timeline <id>      Timeline ULID on the gateway");
    println!("  --fork-compare       Dual-future personal fork (#75 thin slice)");
    println!("  -h, --help           Show this help");
    println!();
    println!("Examples:");
    println!("  cargo run -p pos-mvp -- --prefer focus=0.9 --prefer collaboration=0.3");
    println!(
        "  cargo run -p pos-mvp -- --a-label Remote --a-tags \"autonomy focus\" \\
           --b-label Office --b-tags \"collaboration energy\" --prefer autonomy=0.8"
    );
}

fn build_registry(preferences: Vec<(String, f64)>) -> PluginRegistry {
    let entity = EntityId::new();
    let model = PersonaModel::new(preferences);
    let mut registry = PluginRegistry::new();
    let persona = PersonaPlugin::new();
    registry
        .register(
            &persona,
            Some(Box::new(PersonaReducer)),
            Some(Box::new(PersonaEvalDriver::new(entity, model, vec![]))),
        )
        .expect("persona plugin registration failed");
    registry
}

fn recommend(score_a: f64, score_b: f64, label_a: &str, label_b: &str) -> (String, String) {
    let margin = (score_a - score_b).abs();
    if margin < 0.02 {
        (
            "Toss-up".to_owned(),
            format!("Scores are nearly tied — adjust preferences to break the tie."),
        )
    } else if score_a > score_b {
        (
            label_a.to_owned(),
            format!("Closer fit to your preferences. Raise preferences for {label_b} to switch."),
        )
    } else {
        (
            label_b.to_owned(),
            format!("Closer fit to your preferences. Raise preferences for {label_a} to switch."),
        )
    }
}

fn format_prefs(prefs: &[(String, f64)]) -> String {
    if prefs.is_empty() {
        return "(none set — use --prefer key=value)".to_owned();
    }
    prefs
        .iter()
        .map(|(k, v)| format!("{k}={v:.2}"))
        .collect::<Vec<_>>()
        .join(" · ")
}

fn print_ai_influence_headline(index: &ai_influence::AiInfluenceIndex) {
    for line in format_ai_influence_lines(index) {
        println!("{line}");
    }
}

fn apply_and_print_society(
    gateway: &str,
    timeline_id: &str,
    means: &std::collections::HashMap<String, f64>,
    preferences: &mut [(String, f64)],
) {
    if means.is_empty() {
        println!("Shared context: no society signals on timeline {timeline_id}");
        println!();
        return;
    }
    println!("Shared context (from {gateway}):");
    let mut dims: Vec<(&String, f64)> = means.iter().map(|(k, v)| (k, *v)).collect();
    dims.sort_by(|a, b| a.0.cmp(b.0));
    for (dim, mean) in dims {
        println!("  {dim} mean={mean:.2}");
    }
    println!("  In plain language:");
    for line in plain_language_context(means) {
        println!("    • {line}");
    }
    apply_society_context(preferences, means);
    println!("  Preferences after context nudge:");
    println!("    {}", format_prefs(preferences));
    println!();
}

fn print_gateway_block(
    gateway: Option<&str>,
    timeline: Option<&str>,
    preferences: &mut [(String, f64)],
) {
    if let (Some(gw), Some(tl)) = (gateway, timeline) {
        match fetch_timeline_context(gw, tl) {
            Ok(ctx) => {
                print_ai_influence_headline(&ctx.ai_influence);
                println!();
                apply_and_print_society(gw, tl, &ctx.society_means, preferences);
            }
            Err(err) => {
                print_ai_influence_headline(&unavailable_ai_influence());
                eprintln!("Warning: could not load shared context: {err}");
                println!();
            }
        }
    } else {
        print_ai_influence_headline(&local_ai_influence());
        println!();
    }
}

fn run_mvp(
    option_a_label: &str,
    option_a_tags: &str,
    option_b_label: &str,
    option_b_tags: &str,
    mut preferences: Vec<(String, f64)>,
    gateway: Option<&str>,
    timeline: Option<&str>,
    fork_compare: bool,
) {
    println!("PiglorOS — Decision preview");
    println!();

    print_gateway_block(gateway, timeline, &mut preferences);

    println!("Your preferences:");
    println!("  {}", format_prefs(&preferences));
    println!();

    let model = PersonaModel::new(preferences.clone());
    let score_a = model.score_option(option_a_tags);
    let score_b = model.score_option(option_b_tags);

    println!("Match scores:");
    println!("  {option_a_label:<16} {score_a:.3}  tags: [{option_a_tags}]");
    println!("  {option_b_label:<16} {score_b:.3}  tags: [{option_b_tags}]");
    println!();

    let (pick, why) = recommend(score_a, score_b, option_a_label, option_b_label);
    println!("→ Recommendation: {pick}");
    println!("  {why}");
    println!();

    if fork_compare {
        let summary = run_personal_fork_compare(&preferences, option_a_tags, option_b_tags);
        print_fork_compare(&summary, option_a_label, option_b_label);
        println!();
    }
}

fn run_from_args(args: &[String]) -> Result<(), String> {
    match parse_cli(args)? {
        CliAction::Help => print_help(),
        CliAction::Run {
            option_a_label,
            option_a_tags,
            option_b_label,
            option_b_tags,
            preferences,
            gateway,
            timeline,
            fork_compare,
        } => run_mvp(
            &option_a_label,
            &option_a_tags,
            &option_b_label,
            &option_b_tags,
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
        let score = model.score_option("nature quiet");
        assert!(score > 0.0);
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
    fn prefer_overrides_affect_scores() {
        let args = vec![
            "--a-tags".to_owned(),
            "nature quiet".to_owned(),
            "--b-tags".to_owned(),
            "city food".to_owned(),
            "--prefer".to_owned(),
            "food=1.0".to_owned(),
            "--prefer".to_owned(),
            "city=0.95".to_owned(),
        ];
        let CliAction::Run {
            option_a_tags,
            option_b_tags,
            preferences,
            ..
        } = parse_cli(&args).expect("parse ok")
        else {
            panic!("expected Run");
        };
        let model = PersonaModel::new(preferences);
        let a = model.score_option(&option_a_tags);
        let b = model.score_option(&option_b_tags);
        assert!(b > a, "food/city prefs should favor option B");
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
        let (pick, _) = recommend(0.9, 0.5, "A", "B");
        assert_eq!(pick, "A");
        let (pick, _) = recommend(0.5, 0.9, "A", "B");
        assert_eq!(pick, "B");
        let (pick, _) = recommend(0.5, 0.51, "A", "B");
        assert_eq!(pick, "Toss-up");
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn parse_cli_handles_noise_and_soft_prefer_errors() {
        let args = vec![
            "--prefer".to_owned(),
            "adventure=0.6".to_owned(),
            "--prefer".to_owned(),
            "broken".to_owned(),
            "--unknown-flag".to_owned(),
            "--prefer".to_owned(),
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
    fn format_prefs_lists_pairs() {
        let s = format_prefs(&[("nature".to_owned(), 0.8)]);
        assert!(s.contains("nature=0.80"));
        let empty = format_prefs(&[]);
        assert!(empty.contains("none set"));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn run_mvp_basic_smoke() {
        run_from_args(&[
            "--a-label".to_owned(),
            "Remote".to_owned(),
            "--a-tags".to_owned(),
            "autonomy focus".to_owned(),
            "--b-label".to_owned(),
            "Office".to_owned(),
            "--b-tags".to_owned(),
            "collaboration energy".to_owned(),
            "--prefer".to_owned(),
            "autonomy=1.0".to_owned(),
        ])
        .expect("smoke run");
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn parse_cli_dangling_flags() {
        assert!(parse_cli(&["--a-label".to_owned()]).is_err());
        assert!(parse_cli(&["--b-tags".to_owned()]).is_err());
        assert!(parse_cli(&["--gateway".to_owned()]).is_err());
        assert!(parse_cli(&["--timeline".to_owned()]).is_err());
        let CliAction::Run { .. } = parse_cli(&["--prefer".to_owned()]).expect("soft prefer")
        else {
            panic!("expected Run");
        };
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
    fn run_mvp_gateway_warning_on_unreachable() {
        let lines = format_ai_influence_lines(&unavailable_ai_influence());
        assert!(lines[0].contains("n/a") && lines[0].contains("gateway poll failed"));
        run_mvp(
            "A",
            "focus",
            "B",
            "energy",
            vec![("focus".to_owned(), 0.8)],
            Some("http://127.0.0.1:1"),
            Some("01ARZ3NDEKTSV4RRFFQ69G5FAV"),
            false,
        );
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn run_mvp_fork_compare_path() {
        run_mvp(
            "A",
            "autonomy",
            "B",
            "collaboration",
            vec![("autonomy".to_owned(), 0.9)],
            None,
            None,
            true,
        );
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn parse_cli_accepts_gateway_and_timeline() {
        let CliAction::Run {
            gateway, timeline, ..
        } = parse_cli(&[
            "--gateway".to_owned(),
            "http://127.0.0.1:8080".to_owned(),
            "--timeline".to_owned(),
            "01ARZ3NDEKTSV4RRFFQ69G5FAV".to_owned(),
        ])
        .unwrap()
        else {
            panic!("expected Run action");
        };
        assert_eq!(gateway.as_deref(), Some("http://127.0.0.1:8080"));
        assert_eq!(timeline.as_deref(), Some("01ARZ3NDEKTSV4RRFFQ69G5FAV"));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn run_mvp_gateway_applies_context() {
        use std::io::{Read, Write};
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let body = r#"{"events":[
            {"event_type":"society.signal","payload":{"dimension":"trust","value":0.9}},
            {"event_type":"agent.action","payload":{"archetype":"scout"}},
            {"event_type":"agent.decision","payload":{}}
        ]}"#;
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
            "A",
            "focus",
            "B",
            "energy",
            vec![],
            Some(&format!("http://{addr}")),
            Some("01ARZ3NDEKTSV4RRFFQ69G5FAV"),
            false,
        );
    }
}
