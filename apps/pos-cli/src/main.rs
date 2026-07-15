#![forbid(unsafe_code)]
#![deny(clippy::all)]
#![warn(clippy::pedantic)]

//! `pos` — CLI entry point for `PiglorOS`.
//!
//! Subcommands:
//!   pos store init `<path>`
//!   pos store info `<path>`
//!   pos timeline list `<path>`
//!   pos timeline fork `<path>` `<tl_id>` `<at_seq>` `<name>`
//!   pos experiment run `<path>` --ticks `<N>`
//!   pos experiment verify `<manifest.json>`
//!   pos version

use pos_core::{clock::Seq, ids::TimelineId, store::SeqRange};
use pos_experiment::{Experiment, ExperimentConfig, StopCondition};
use pos_store::{open_store, StoreConfig};
use ulid::Ulid;

fn main() {
    if let Err(e) = run() {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("store") => handle_store(&args[2..]),
        Some("timeline") => handle_timeline(&args[2..]),
        Some("experiment") => handle_experiment(&args[2..]),
        Some("version") => {
            println!("pos-cli {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        _ => {
            eprintln!("Usage: pos <store|timeline|experiment|version>");
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
            eprintln!("Usage: pos store <init|info> <path>");
            Ok(())
        }
    }
}

fn cmd_store_init(path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let mut store = open_store(StoreConfig::Sqlite {
        path: path.to_owned(),
    })?;
    store.create_timeline("default")?;
    println!("Initialized store at {path}");
    Ok(())
}

fn cmd_store_info(path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let store = open_store(StoreConfig::Sqlite {
        path: path.to_owned(),
    })?;
    let timelines = store.list_timelines()?;
    println!("Timelines: {}", timelines.len());
    let total_events: usize = timelines
        .iter()
        .map(|t| {
            store
                .read(t.id(), SeqRange::all())
                .unwrap_or_default()
                .len()
        })
        .sum();
    println!("Total events: {total_events}");
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
        _ => {
            eprintln!("Usage: pos timeline <list|fork> ...");
            Ok(())
        }
    }
}

fn cmd_timeline_list(path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let store = open_store(StoreConfig::Sqlite {
        path: path.to_owned(),
    })?;
    for tl in store.list_timelines()? {
        println!(
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
    println!("Forked timeline: {}", forked.id());
    Ok(())
}

// ---------------------------------------------------------------------------
// experiment subcommands
// ---------------------------------------------------------------------------

fn handle_experiment(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    match args.first().map(String::as_str) {
        Some("run") => {
            // pos experiment run <path> --ticks <N>
            let path = args.get(1).ok_or("Usage: pos experiment run <path> --ticks <N>")?;
            let ticks = parse_ticks_flag(&args[2..])?;
            cmd_experiment_run(path, ticks)
        }
        Some("verify") => {
            let manifest_path = args
                .get(1)
                .ok_or("Usage: pos experiment verify <manifest.json>")?;
            cmd_experiment_verify(manifest_path)
        }
        _ => {
            eprintln!("Usage: pos experiment <run|verify> ...");
            Ok(())
        }
    }
}

fn cmd_experiment_run(path: &str, ticks: u64) -> Result<(), Box<dyn std::error::Error>> {
    let exp = Experiment::new(ExperimentConfig {
        name: "cli-run".to_owned(),
        stop: StopCondition::MaxTicks(ticks),
        store_config: StoreConfig::Sqlite {
            path: path.to_owned(),
        },
    });
    let result = exp.run()?;
    println!(
        "Experiment complete: {} ticks, {} events, timeline={}",
        result.ticks, result.total_events, result.timeline_id
    );
    Ok(())
}

fn cmd_experiment_verify(manifest_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let json = std::fs::read_to_string(manifest_path)?;
    let manifest: pos_core::manifest::ReproManifest = serde_json::from_str(&json)?;

    // Open a temp in-memory store to read the timeline events.
    let store = open_store(StoreConfig::Memory)?;
    let timelines = store.list_timelines()?;
    let tl = timelines
        .iter()
        .find(|t| t.id() == manifest.timeline_id);

    if let Some(tl) = tl {
        let events = store.read(tl.id(), SeqRange::all())?;
        // Use last event's payload_hash as head hash.
        let head_hash = events
            .last()
            .map_or(pos_core::crypto::Hash::zero(), |e| e.payload_hash);
        if head_hash == manifest.head_hash {
            println!("OK");
        } else {
            println!("MISMATCH");
            std::process::exit(2);
        }
    } else {
        println!("MISMATCH");
        std::process::exit(2);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Argument parsing helpers
// ---------------------------------------------------------------------------

/// Parse `--ticks <N>` from a slice of args, returning `N`.
fn parse_ticks_flag(args: &[String]) -> Result<u64, Box<dyn std::error::Error>> {
    let mut it = args.iter();
    while let Some(flag) = it.next() {
        if flag == "--ticks" {
            let val = it.next().ok_or("--ticks requires a value")?;
            return val.parse::<u64>().map_err(|e| format!("invalid ticks: {e}").into());
        }
    }
    Err("missing --ticks <N>".into())
}

/// Parse a ULID string into a [`TimelineId`].
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
mod tests {
    use super::*;

    #[test]
    fn parse_ticks_flag_extracts_value() {
        let args: Vec<String> = vec!["--ticks".to_owned(), "42".to_owned()];
        let n = parse_ticks_flag(&args).unwrap();
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
        let seq = parse_seq("100").unwrap();
        assert_eq!(seq.as_u64(), 100);
    }

    #[test]
    fn parse_seq_zero() {
        let seq = parse_seq("0").unwrap();
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
        let parsed = parse_timeline_id(&s).unwrap();
        assert_eq!(original, parsed);
    }
}
