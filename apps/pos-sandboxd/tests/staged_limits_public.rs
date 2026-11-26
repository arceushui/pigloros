//! `StagedInstallation::stage_provider_execution_limited` through the public
//! seams (#216): the limits a conformance case probes are the attempt's
//! effective limits, and the default staging is unchanged.
//!
//! As root in the isolated container, the staged execution is admitted and its
//! input verified by the production execute path, whose policy carries the
//! seventeen ELM1 limits (each the least of the broker cap, the launch policy
//! and the case's own budget).
#![cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64"),
    feature = "test-support"
))]

#[path = "support/staged_execution.rs"]
pub mod staged_execution;

use std::{error::Error, fs, path::Path, process::Command};

use pos_conformance::{
    ProviderConformanceCase, MEMORY_CEILING_BYTES, OUTPUT_CEILING_BYTES, TASK_CEILING,
    WATCHDOG_CEILING_MS, WORK_CEILING_BYTES,
};
use pos_reference::provider_admission::test_support::{
    StagedImage, StagedInstallation, StagedLimits, StagedProvider,
};
use pos_reference::sandbox_provider_protocol::SandboxArchitecture;
use pos_sandboxd::{StagingLedger, StagingLimits};

type TestResult = Result<(), Box<dyn Error + Send + Sync>>;

/// R11 §11 SPI1-A: 256 attempt slots, the key file named below.
const SPI1_A: &str = "828764535049310184440a5800001650fd7069676c6f72000000000000000000187782440a59fffc199c401a40000000851901f41903e81905dc190bb8191388781b72756e74696d652d6174746573746174696f6e2e6564323535313958209d057c99cd949ef52cdcbeb13d26fd43f747d80ab26d539a11a31dd72e972003";
const KEY_FILE: &str = "runtime-attestation.ed25519";
const KEY_DESCRIPTION: &str =
    "PiglorOS SIM1 DDI fixture x86-64: e0b3c91db94dc506da3652b0ace1603e49009f3e";

/// Run `name` again as root in the isolated container and report whether
/// this process already is that run.
fn require_isolated_root(name: &str) -> Result<bool, Box<dyn Error + Send + Sync>> {
    if std::env::var_os("PIGLOROS_PRIVILEGED_COMPOSITION_TEST").is_some() {
        return Ok(true);
    }
    let runner = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/run-isolated-test.sh");
    let output = Command::new(runner)
        .arg(std::env::current_exe()?)
        .arg(name)
        .output()?;
    if output.status.success() {
        return Ok(false);
    }
    Err(format!(
        "isolated test {name} failed with {}:\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
    .into())
}

fn hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&text[index..index + 2], 16).unwrap_or_default())
        .collect()
}

/// The effective ELM1 limits of the case that `limits` stages, read from the
/// production execute path, and the staged SPX1 request.
fn staged_effective_limits(
    limits: &StagedLimits,
    arguments: &[String],
) -> Result<(Vec<u64>, Vec<u8>), Box<dyn Error + Send + Sync>> {
    let vectors = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../crates/pos-reference/tests/vectors/sim1-ddi/x86-64");
    let expanded = Command::new("gzip")
        .arg("-dc")
        .arg(vectors.join("image.raw.gz"))
        .output()?;
    assert!(expanded.status.success());
    let directory = tempfile::tempdir()?;
    let binary = directory.path().join("provider-binary");
    fs::write(&binary, b"#!/bin/sh\nexit 0\n staged provider binary")?;
    let certificate = fs::read(vectors.join("signer.der"))?;
    let spi1 = hex(SPI1_A);
    let provider = StagedProvider {
        image: StagedImage {
            architecture: if cfg!(target_arch = "aarch64") {
                SandboxArchitecture::Aarch64
            } else {
                SandboxArchitecture::X86_64
            },
            image: &expanded.stdout,
            certificate: &certificate,
            key_description: KEY_DESCRIPTION,
            executable: b"staged adapter stand-in",
            arguments,
        },
        binary: &binary,
        installation: &spi1,
        key_file_name: KEY_FILE,
    };
    let staged = StagedInstallation::stage_provider_execution_limited(&provider, limits)
        .map_err(|error| error.to_string())?;
    let ledger = StagingLedger::new(StagingLimits {
        aggregate_bytes: 512 * 1024 * 1024,
    });
    let (_directory, input) = staged_execution::verified_input(&staged, &ledger)?;
    let effective = input
        .entry()
        .policy()
        .effective_limits()
        .iter()
        .map(|limit| limit.value)
        .collect();
    Ok((effective, staged.request().to_vec()))
}

#[test]
fn the_probed_ceilings_are_the_effective_limits_and_the_default_is_unchanged() -> TestResult {
    if !require_isolated_root(
        "the_probed_ceilings_are_the_effective_limits_and_the_default_is_unchanged",
    )? {
        return Ok(());
    }
    let arguments = ProviderConformanceCase::MemoryExhaustion
        .adapter_plan()
        .arguments();

    // The default staging: every limit 2000 (256 concurrent attempts), the
    // case's budget 100 and its watchdog 1000 ms.
    let (default, default_request) = staged_effective_limits(&StagedLimits::DEFAULT, &arguments)?;
    let mut expected = vec![2_000_u64; 17];
    expected[13] = 256;
    expected[0] = 100;
    expected[4] = 1_000;
    expected[8] = 100;
    expected[9] = 100;
    assert_eq!(default, expected);

    // The conformance ceilings: memory, tasks, watchdog, output and /work are
    // each the attempt's effective limit, and nothing else moves.
    let probing = StagedLimits::probing(
        MEMORY_CEILING_BYTES,
        TASK_CEILING,
        WATCHDOG_CEILING_MS,
        OUTPUT_CEILING_BYTES,
        WORK_CEILING_BYTES,
    );
    let (limited, limited_request) = staged_effective_limits(&probing, &arguments)?;
    expected[0] = MEMORY_CEILING_BYTES;
    expected[2] = TASK_CEILING;
    expected[4] = WATCHDOG_CEILING_MS;
    expected[8] = OUTPUT_CEILING_BYTES;
    expected[9] = WORK_CEILING_BYTES;
    assert_eq!(limited, expected);
    assert_ne!(limited_request, default_request);
    Ok(())
}

#[test]
fn the_probing_limits_set_exactly_the_five_probed_limits() {
    let probing = StagedLimits::probing(7, 6, 5, 4, 3);
    let mut limits = StagedLimits::DEFAULT.broker;
    for (id, value) in [(0, 7), (2, 6), (4, 5), (8, 4), (9, 3)] {
        limits[id] = value;
    }
    assert_eq!(probing.broker, limits);
    assert_eq!(probing.launch, limits);
    assert_eq!(probing.watchdog_ms, 5);
    assert_eq!(probing.budget, [7, 100, 100, 100, 4, 3, 100, 100]);
    assert_eq!(StagedLimits::DEFAULT.watchdog_ms, 1_000);
    assert_eq!(StagedLimits::DEFAULT.budget, [100; 8]);
    assert_eq!(StagedLimits::DEFAULT.broker[13], 256);
    assert_eq!(StagedLimits::DEFAULT.launch[3], 2_000);
}
