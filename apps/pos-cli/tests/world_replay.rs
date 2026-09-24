#![forbid(unsafe_code)]

use std::process::{Command, Output};

fn run_pos(args: &[&str]) -> Result<Output, Box<dyn std::error::Error>> {
    Ok(Command::new(env!("CARGO_BIN_EXE_pos"))
        .args(args)
        .output()?)
}

fn assert_timeline_operation_unavailable(
    args: &[&str],
    expected_error: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let output = run_pos(args)?;
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert_eq!(String::from_utf8(output.stderr)?, expected_error);
    Ok(())
}

#[test]
fn replay_unavailable_without_evidence() -> Result<(), Box<dyn std::error::Error>> {
    assert_timeline_operation_unavailable(
        &["timeline", "replay", "unused", "unused"],
        "Error: timeline replay is unavailable: the CLI has no owner-verified evidence path for this operation\n",
    )
}

#[test]
fn snapshot_unavailable_without_evidence() -> Result<(), Box<dyn std::error::Error>> {
    assert_timeline_operation_unavailable(
        &["timeline", "snapshot", "unused", "unused"],
        "Error: timeline snapshot is unavailable: the CLI has no owner-verified evidence path for this operation\n",
    )
}

#[test]
fn compare_unavailable_without_evidence() -> Result<(), Box<dyn std::error::Error>> {
    assert_timeline_operation_unavailable(
        &[
            "timeline", "compare", "unused", "unused", "unused", "unused",
        ],
        "Error: timeline compare is unavailable: the CLI has no owner-verified evidence path for this operation\n",
    )
}
