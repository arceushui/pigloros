//! `StagedInstallation::stage_provider` through the public seams (#444).
//!
//! As root in the isolated container, the staged provider host files are read
//! back by the production readers: the SIC1 installation and its admission,
//! the SPI1 file, and the runtime-attestation key file. The staged provider
//! executable must be the caller's binary, installed where the SIC1
//! provider-executable descriptor names it, so that a runtime started from it
//! passes its self-binding step.
#![cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64"),
    feature = "test-support"
))]

use std::{
    error::Error,
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::Path,
    process::Command,
};

use pos_reference::provider_admission::test_support::{
    StagedImage, StagedInstallation, StagedProvider,
};
use pos_reference::sandbox_provider_protocol::SandboxArchitecture;
use pos_reference::selector::installation::InstalledSelectorState;
use pos_sandboxd::{ProviderInstallation, RuntimeKey};

type TestResult = Result<(), Box<dyn Error>>;

/// R11 §11 SPI1-A: 256 attempt slots, the key file named below.
const SPI1_A: &str = "828764535049310184440a5800001650fd7069676c6f72000000000000000000187782440a59fffc199c401a40000000851901f41903e81905dc190bb8191388781b72756e74696d652d6174746573746174696f6e2e6564323535313958209d057c99cd949ef52cdcbeb13d26fd43f747d80ab26d539a11a31dd72e972003";
const KEY_FILE: &str = "runtime-attestation.ed25519";
const KEY_DESCRIPTION: &str =
    "PiglorOS SIM1 DDI fixture x86-64: e0b3c91db94dc506da3652b0ace1603e49009f3e";
const FIXED: &str = "/var/lib/pigloros";

/// Run `name` again as root in the isolated container and report whether
/// this process already is that run.
fn require_isolated_root(name: &str) -> Result<bool, Box<dyn Error>> {
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

/// Everything `stage_provider` takes, built from the x86-64 DDI vector and a
/// binary of distinctive bytes.
struct Inputs {
    image: Vec<u8>,
    certificate: Vec<u8>,
    binary: std::path::PathBuf,
    adapter: Vec<u8>,
    arguments: Vec<String>,
    spi1: Vec<u8>,
}

impl Inputs {
    fn new(directory: &Path) -> Result<Self, Box<dyn Error>> {
        let vectors = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../crates/pos-reference/tests/vectors/sim1-ddi/x86-64");
        let expanded = Command::new("gzip")
            .arg("-dc")
            .arg(vectors.join("image.raw.gz"))
            .output()?;
        assert!(expanded.status.success());
        let binary = directory.join("provider-binary");
        fs::write(&binary, b"#!/bin/sh\nexit 0\n staged provider binary")?;
        Ok(Self {
            image: expanded.stdout,
            certificate: fs::read(vectors.join("signer.der"))?,
            binary,
            // Staging only digests the adapter into SIM1; it is not run here.
            adapter: b"staged adapter stand-in".to_vec(),
            arguments: vec!["honest".to_owned()],
            spi1: hex(SPI1_A),
        })
    }

    fn provider(&self) -> StagedProvider<'_> {
        StagedProvider {
            image: StagedImage {
                architecture: if cfg!(target_arch = "aarch64") {
                    SandboxArchitecture::Aarch64
                } else {
                    SandboxArchitecture::X86_64
                },
                image: &self.image,
                certificate: &self.certificate,
                key_description: KEY_DESCRIPTION,
                executable: &self.adapter,
                arguments: &self.arguments,
            },
            binary: &self.binary,
            installation: &self.spi1,
            key_file_name: KEY_FILE,
        }
    }
}

#[test]
fn the_staged_provider_files_are_read_back_by_the_production_readers() -> TestResult {
    if !require_isolated_root("the_staged_provider_files_are_read_back_by_the_production_readers")?
    {
        return Ok(());
    }
    let inputs = Inputs::new(Path::new("/tmp"))?;
    let staged = StagedInstallation::stage_provider(&inputs.provider())?;

    // The SIC1 installation admits, and its provider-executable descriptor
    // names the caller's binary at the path the stage reports.
    let admitted = InstalledSelectorState::open()?
        .authenticate_bootstrap()?
        .admit_provider()?;
    let binary = fs::read(&inputs.binary)?;
    assert_eq!(
        admitted.bootstrap().policy().selection().provider_binary,
        *blake3::hash(&binary).as_bytes()
    );
    let executable = staged.provider_executable();
    assert!(executable.starts_with("/var/lib/pigloros/sandbox/providers"));
    assert_eq!(fs::read(executable)?, binary);
    let metadata = fs::metadata(executable)?;
    assert_eq!((metadata.uid(), metadata.mode() & 0o7777), (0, 0o500));
    let held = admitted
        .bootstrap()
        .installed()
        .artifact(
            pos_reference::selector::installation::InstallationObjectKind::PROVIDER_EXECUTABLE,
            admitted.bootstrap().policy().selection().provider_binary,
        )?
        .file()
        .metadata()?;
    assert_eq!(
        (held.dev(), held.ino()),
        (metadata.dev(), metadata.ino()),
        "the held descriptor is the staged file"
    );

    // SPI1 and the key file read through the production readers, and the key
    // is the admitted runtime-attestation key.
    let installation = ProviderInstallation::open()?;
    assert_eq!(installation.attempt_range().slots(), 256);
    assert_eq!(installation.runtime_key_file(), KEY_FILE);
    RuntimeKey::open(&installation)?
        .require_admitted(admitted.provider().runtime_attestation_key())?;

    // The staged request is the one the staged authority admits, and dropping
    // the stage removes the whole fixed tree again.
    assert!(!staged.request().is_empty());
    drop(staged);
    assert!(!Path::new(FIXED).exists());
    Ok(())
}

#[test]
fn bad_provider_inputs_are_refused_and_leave_no_installation() -> TestResult {
    if !require_isolated_root("bad_provider_inputs_are_refused_and_leave_no_installation")? {
        return Ok(());
    }
    let inputs = Inputs::new(Path::new("/tmp"))?;
    let good = inputs.provider();
    let too_long = vec![0_u8; 4097];
    let missing = Path::new("/tmp/no-such-provider-binary");
    // Validation runs before anything is staged, so its refusals are told
    // apart by their message from a later create or write failure.
    let refusals = [
        (
            StagedProvider {
                key_file_name: "",
                ..good
            },
            "plain file name",
        ),
        (
            StagedProvider {
                key_file_name: ".",
                ..good
            },
            "plain file name",
        ),
        (
            StagedProvider {
                key_file_name: "..",
                ..good
            },
            "plain file name",
        ),
        (
            StagedProvider {
                key_file_name: "a/b",
                ..good
            },
            "plain file name",
        ),
        (
            StagedProvider {
                key_file_name: "a\0b",
                ..good
            },
            "plain file name",
        ),
        (
            StagedProvider {
                installation: &[],
                ..good
            },
            "between 1 and 4096",
        ),
        (
            StagedProvider {
                installation: &too_long,
                ..good
            },
            "between 1 and 4096",
        ),
    ];
    for (refused, message) in refusals {
        let error = StagedInstallation::stage_provider(&refused).err();
        assert!(
            error.is_some_and(|error| error.to_string().contains(message)),
            "{message}"
        );
        assert!(!Path::new(FIXED).exists());
    }
    assert!(StagedInstallation::stage_provider(&StagedProvider {
        binary: missing,
        ..good
    })
    .is_err());
    assert!(!Path::new(FIXED).exists());

    // The SPI1 bound is 1 to 4096 bytes inclusive: both ends stage.
    for length in [1, 4096] {
        let installation = vec![7_u8; length];
        let staged = StagedInstallation::stage_provider(&StagedProvider {
            installation: &installation,
            ..good
        })?;
        let written = fs::read(Path::new(FIXED).join("sandbox/provider-installation.cbor"))?;
        assert_eq!(written, installation);
        drop(staged);
    }

    // An existing fixed installation is never adopted or replaced.
    fs::create_dir(FIXED)?;
    fs::set_permissions(FIXED, fs::Permissions::from_mode(0o700))?;
    assert!(StagedInstallation::stage_provider(&good).is_err());
    assert!(Path::new(FIXED).exists());
    Ok(())
}
