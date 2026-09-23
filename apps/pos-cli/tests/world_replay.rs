#![forbid(unsafe_code)]

use std::process::{Command, Output};

fn run_pos(args: &[&str]) -> Result<Output, Box<dyn std::error::Error>> {
    Ok(Command::new(env!("CARGO_BIN_EXE_pos"))
        .args(args)
        .output()?)
}

fn assert_world_operation_unavailable(
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
fn timeline_replay_fails_closed_without_native_verifier() -> Result<(), Box<dyn std::error::Error>>
{
    assert_world_operation_unavailable(
        &["timeline", "replay", "unused", "unused"],
        "Error: World Replay is unavailable until the native recording, retrieval, clock, disposition, and closure verifier owners are installed\n",
    )
}

#[test]
fn timeline_snapshot_fails_closed_without_native_verifier() -> Result<(), Box<dyn std::error::Error>>
{
    assert_world_operation_unavailable(
        &["timeline", "snapshot", "unused", "unused"],
        "Error: World Snapshot is unavailable until the native recording, retrieval, clock, disposition, and closure verifier owners are installed\n",
    )
}

#[test]
fn timeline_compare_fails_closed_without_native_verifier() -> Result<(), Box<dyn std::error::Error>>
{
    assert_world_operation_unavailable(
        &[
            "timeline", "compare", "unused", "unused", "unused", "unused",
        ],
        "Error: Fork Compare is unavailable until the native recording, retrieval, clock, disposition, and closure verifier owners are installed\n",
    )
}
