//! R11 §5.1 steps 2 to 6 against the signed test installation, staged at
//! the fixed path as root in the isolated container.

use std::error::Error;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use ciborium::value::Value;
use ed25519_dalek::SigningKey;
use pos_reference::provider_admission::test_support::StagedInstallation;
use pos_reference::selector::installation::authority::AdmittedSelectorProvider;
use pos_reference::selector::installation::{
    InstallationObjectKind, InstalledSelectorState, SANDBOX_ARTIFACT_ROOT,
};
use pos_reference::selector::SelectorBoundaryError;

use pos_reference::sandbox_provider_protocol::SandboxLimit;

use super::{required_slots, ProviderRuntimeAuthority, ProviderStartupError};
use crate::{ProviderInstallation, ProviderInstallationError, ReleaseSigner};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

/// The fixture's runtime-attestation seed and SPM1 key ID.
const RUNTIME_SEED: [u8; 32] = [4; 32];
const RUNTIME_KEY_ID: &str = "runtime";
const KEY_FILE: &str = "runtime-attestation.ed25519";

/// SPI1 with the R11 §11 common values and an attempt IPv4 range of
/// `ipv4_length` bits.
fn spi1(ipv4_length: u64) -> TestResult<Vec<u8>> {
    let int = |number: u64| Value::Integer(number.into());
    let unsigned = Value::Array(vec![
        Value::Text("SPI1".to_owned()),
        int(1),
        Value::Array(vec![
            Value::Bytes(vec![10, 88, 0, 0]),
            int(ipv4_length),
            Value::Bytes(vec![
                0xfd, 0x70, 0x69, 0x67, 0x6c, 0x6f, 0x72, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            ]),
            int(119),
        ]),
        Value::Array(vec![Value::Bytes(vec![10, 89, 255, 252]), int(40000)]),
        int(1 << 30),
        Value::Array([500, 1000, 1500, 3000, 5000].map(int).to_vec()),
        Value::Text(KEY_FILE.to_owned()),
    ]);
    let mut preimage = b"PiglorOS.SPI1.v1\0".to_vec();
    preimage.extend(encode(&unsigned)?);
    let digest = Value::Bytes(blake3::hash(&preimage).as_bytes().to_vec());
    encode(&Value::Array(vec![unsigned, digest]))
}

fn encode(value: &Value) -> TestResult<Vec<u8>> {
    let mut encoded = Vec::new();
    ciborium::into_writer(value, &mut encoded)?;
    Ok(encoded)
}

/// Write `bytes` to `path` with `mode`.
fn write_file(path: &Path, bytes: &[u8], mode: u32) -> TestResult {
    fs::write(path, bytes)?;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    Ok(())
}

/// Install SPI1 and `seed` as its key file beside the staged SIC1.
fn install_spi1(document: &[u8], seed: &[u8; 32]) -> TestResult {
    let root = Path::new(SANDBOX_ARTIFACT_ROOT);
    write_file(&root.join("provider-installation.cbor"), document, 0o400)?;
    fs::create_dir(root.join("provider-keys"))?;
    fs::set_permissions(
        root.join("provider-keys"),
        fs::Permissions::from_mode(0o700),
    )?;
    write_file(&root.join("provider-keys").join(KEY_FILE), seed, 0o400)
}

/// Remove the SPI1 file and its key directory again.
fn remove_spi1() -> TestResult {
    let root = Path::new(SANDBOX_ARTIFACT_ROOT);
    fs::remove_file(root.join("provider-installation.cbor"))?;
    fs::remove_dir_all(root.join("provider-keys"))?;
    Ok(())
}

/// The admitted provider of the staged SIC1.
fn admitted() -> TestResult<AdmittedSelectorProvider> {
    Ok(InstalledSelectorState::open()?
        .authenticate_bootstrap()?
        .admit_provider()?)
}

/// The installed path of the admitted provider binary.
fn provider_binary(admitted: &AdmittedSelectorProvider) -> TestResult<PathBuf> {
    let bootstrap = admitted.bootstrap();
    let digest = bootstrap
        .installed()
        .artifact(
            InstallationObjectKind::PROVIDER_EXECUTABLE,
            bootstrap.policy().selection().provider_binary,
        )?
        .object()
        .content_digest();
    let name: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
    Ok(Path::new(SANDBOX_ARTIFACT_ROOT)
        .join("providers")
        .join(name))
}

/// Bind against the staged SIC1, running as the provider binary itself.
fn bind_as_provider() -> TestResult<Result<ProviderRuntimeAuthority, ProviderStartupError>> {
    let admitted = admitted()?;
    let binary = provider_binary(&admitted)?;
    Ok(ProviderRuntimeAuthority::bind(
        admitted,
        &binary,
        ProviderInstallation::open,
    ))
}

#[test]
fn startup_binds_only_the_admitted_binary_installation_and_key() -> TestResult {
    if std::env::var_os("PIGLOROS_PRIVILEGED_COMPOSITION_TEST").is_none() {
        let runner =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/run-isolated-test.sh");
        let output = std::process::Command::new(runner)
            .arg(std::env::current_exe()?)
            .arg("provider_runtime::tests::startup_binds_only_the_admitted_binary_installation_and_key")
            .output()?;
        assert!(
            output.status.success(),
            "isolated provider runtime test failed: {:?}\n{}\n{}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return Ok(());
    }
    // Step 2: no SIC1.
    assert!(matches!(
        ProviderRuntimeAuthority::start(),
        Err(ProviderStartupError::Installation(_))
    ));
    let staged = StagedInstallation::stage()?;
    // Step 3: this test binary is not the admitted provider binary, so
    // startup stops before it reads SPI1.
    assert_eq!(
        ProviderRuntimeAuthority::start().err(),
        Some(ProviderStartupError::SelfBinding)
    );
    let mut read = false;
    let refused = ProviderRuntimeAuthority::bind(admitted()?, Path::new("/proc/self/exe"), || {
        read = true;
        ProviderInstallation::open()
    });
    assert_eq!(refused.err(), Some(ProviderStartupError::SelfBinding));
    assert!(!read);
    // Another file on the very device of the held binary.
    let manifest = Path::new(SANDBOX_ARTIFACT_ROOT).join("installation.cbor");
    let refused =
        ProviderRuntimeAuthority::bind(admitted()?, &manifest, ProviderInstallation::open);
    assert_eq!(refused.err(), Some(ProviderStartupError::SelfBinding));
    // Step 4: no SPI1.
    assert_eq!(
        bind_as_provider()?.err(),
        Some(ProviderStartupError::ProviderInstallation(
            ProviderInstallationError::UnsafeFile
        ))
    );
    // Step 5: a /23 holds 128 slots, fewer than BHC1 limit 13 (256).
    install_spi1(&spi1(23)?, &RUNTIME_SEED)?;
    assert_eq!(
        bind_as_provider()?.err(),
        Some(ProviderStartupError::SlotCount)
    );
    remove_spi1()?;
    // Step 6: a key file that is not the admitted key.
    install_spi1(&spi1(22)?, &[5; 32])?;
    assert_eq!(
        bind_as_provider()?.err(),
        Some(ProviderStartupError::ProviderInstallation(
            ProviderInstallationError::KeyMismatch
        ))
    );
    remove_spi1()?;
    // Exactly 256 slots and the admitted key.
    install_spi1(&spi1(22)?, &RUNTIME_SEED)?;
    let authority = bind_as_provider()??;
    let expected = SigningKey::from_bytes(&RUNTIME_SEED).verifying_key();
    assert_eq!(*authority.runtime_key(), expected);
    assert_eq!(
        authority.signer().runtime_attestation_key_id(),
        RUNTIME_KEY_ID
    );
    let signature = authority.signer().sign(b"message");
    expected.verify_strict(
        b"message",
        &ed25519_dalek::Signature::from_bytes(&signature),
    )?;
    assert_eq!(authority.installation().attempt_range().slots(), 256);
    assert_eq!(
        authority
            .admitted()
            .provider()
            .manifest()
            .runtime_attestation_key_id,
        RUNTIME_KEY_ID
    );
    // SIR1 pending: SIC1 itself is refused, before any other step.
    write_file(
        &Path::new(SANDBOX_ARTIFACT_ROOT).join("installation-update.cbor"),
        b"pending",
        0o400,
    )?;
    assert_eq!(
        ProviderRuntimeAuthority::start().err(),
        Some(ProviderStartupError::Installation(
            SelectorBoundaryError::ArtifactInvalid
        ))
    );
    drop(staged);
    for (error, text) in [
        (
            ProviderStartupError::SelfBinding,
            "the running executable is not the admitted provider binary",
        ),
        (
            ProviderStartupError::SlotCount,
            "the attempt range holds fewer slots than admission can use",
        ),
    ] {
        assert_eq!(error.to_string(), text);
    }
    Ok(())
}

#[test]
fn the_slot_requirement_is_bhc1_limit_13_capped_at_256() {
    let limit = |limit_id, value| SandboxLimit { limit_id, value };
    for (caps, expected) in [
        (vec![limit(12, 1), limit(13, 300)], 256),
        (vec![limit(12, 1), limit(13, 100), limit(14, 1)], 100),
        (vec![limit(13, 256)], 256),
        (vec![limit(1, 2000)], 256),
        (Vec::new(), 256),
    ] {
        assert_eq!(required_slots(&caps), expected);
    }
}
