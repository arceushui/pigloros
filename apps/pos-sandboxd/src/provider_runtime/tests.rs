//! R11 §5.1 steps 2 to 6 against the signed test installation, staged at
//! the fixed path as root in the isolated container.

use std::error::Error;
use std::fs::{self, File};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::sync::{mpsc, Arc, OnceLock};
use std::time::{Duration, Instant};

use ciborium::value::Value;
use ed25519_dalek::{Signer, SigningKey};
use pos_reference::provider_admission::test_support::StagedInstallation;
use pos_reference::sandbox_provider_protocol::{
    ExecutionReleaseFields, RecoveryCancellationContext, RevocationUpdateRequest, SandboxLimit,
};
use pos_reference::selector::installation::authority::AdmittedSelectorProvider;
use pos_reference::selector::installation::{
    InstallationObjectKind, InstalledSelectorState, SANDBOX_ARTIFACT_ROOT,
};

use super::port::ExecutePort;
use super::reconcile::{Reconcile, ReconcileError};
use super::{
    bind, reconcile_in_background, required_slots, start_reconciliation, AdmissionState,
    ProviderStartupError, RuntimeAuthority,
};
use pos_reference::sandbox_provider_protocol::NetworkCaptureStore;

use crate::{
    issue_release, AdmittedRuntimeKey, AttemptLifecycle, CleanupBudget, ProviderInstallation,
    ProviderInstallationError, ReconciledRestart, RuntimeAttestationSigner, StagingDirectory,
    StagingLedger, StagingLimits, SystemdAttemptRegistry, SystemdTransientUnitTransport,
};

pub(super) type TestResult<T = ()> = Result<T, Box<dyn Error>>;

/// The fixture's runtime-attestation seed and SPM1 key ID.
pub(super) const RUNTIME_SEED: [u8; 32] = [4; 32];
const RUNTIME_KEY_ID: &str = "runtime";
const KEY_FILE: &str = "runtime-attestation.ed25519";

/// SPI1 with the R11 §11 common values and an attempt IPv4 range of
/// `ipv4_length` bits.
pub(super) fn spi1(ipv4_length: u64) -> TestResult<Vec<u8>> {
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

pub(super) fn encode(value: &Value) -> TestResult<Vec<u8>> {
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
pub(super) fn install_spi1(document: &[u8], seed: &[u8; 32]) -> TestResult {
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
pub(super) fn remove_spi1() -> TestResult {
    let root = Path::new(SANDBOX_ARTIFACT_ROOT);
    fs::remove_file(root.join("provider-installation.cbor"))?;
    fs::remove_dir_all(root.join("provider-keys"))?;
    Ok(())
}

/// The admitted provider of the staged SIC1.
pub(super) fn admitted() -> TestResult<AdmittedSelectorProvider> {
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
    Ok(Path::new(SANDBOX_ARTIFACT_ROOT)
        .join("providers")
        .join(hex_name(&digest)))
}

/// The lowercase hexadecimal name of an installed object.
fn hex_name(digest: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    digest
        .iter()
        .flat_map(|byte| [HEX[usize::from(byte >> 4)], HEX[usize::from(byte & 0x0f)]])
        .map(char::from)
        .collect()
}

/// A complete RLS1 body for the fixture's runtime key.
fn release_fields() -> ExecutionReleaseFields {
    ExecutionReleaseFields {
        attempt_id: [1; 16],
        nonce: [2; 32],
        ready1_digest: [3; 32],
        trs1_digest: [4; 32],
        rvs1_digest: [5; 32],
        apt1_digest: [6; 32],
        trust_epoch: 1,
        revocation_epoch: 2,
        policy_epoch: 3,
        expected_readback_digest: [7; 32],
        observed_readback_digest: [8; 32],
        deadline_monotonic_ns: 9,
        runtime_attestation_key_id: RUNTIME_KEY_ID.to_owned(),
    }
}

/// Bind against the staged SIC1, running as the provider binary itself.
pub(super) fn bind_as_provider() -> TestResult<Result<RuntimeAuthority, ProviderStartupError>> {
    let admitted = admitted()?;
    let binary = provider_binary(&admitted)?;
    Ok(bind(admitted, &binary, ProviderInstallation::open))
}

/// Step 3: an executable other than the held provider binary is refused
/// before SPI1 is read.
fn refuses_another_executable_before_spi1() -> TestResult {
    // Step 3: this test binary is not the admitted provider binary, so
    // startup stops before it reads SPI1.
    let mut read = false;
    let refused = bind(admitted()?, Path::new("/proc/self/exe"), || {
        read = true;
        ProviderInstallation::open()
    });
    assert_eq!(refused.err(), Some(ProviderStartupError::SelfBinding));
    assert!(!read);
    // Another file on the very device of the held binary.
    let manifest = Path::new(SANDBOX_ARTIFACT_ROOT).join("installation.cbor");
    let refused = bind(admitted()?, &manifest, ProviderInstallation::open);
    assert_eq!(refused.err(), Some(ProviderStartupError::SelfBinding));
    Ok(())
}

/// Run the test `name` again as root in the isolated container, or report
/// that this process already is that run.
pub(super) fn in_isolated_root(name: &str) -> TestResult<bool> {
    if std::env::var_os("PIGLOROS_PRIVILEGED_COMPOSITION_TEST").is_some() {
        return Ok(true);
    }
    let runner = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/run-isolated-test.sh");
    let output = std::process::Command::new(runner)
        .arg(std::env::current_exe()?)
        .arg(name)
        .output()?;
    assert!(
        output.status.success(),
        "isolated provider runtime test {name} failed: {:?}\n{}\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(false)
}

#[test]
fn startup_binds_only_the_admitted_binary_installation_and_key() -> TestResult {
    if !in_isolated_root(
        "provider_runtime::tests::startup_binds_only_the_admitted_binary_installation_and_key",
    )? {
        return Ok(());
    }
    let staged = StagedInstallation::stage()?;
    refuses_another_executable_before_spi1()?;
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
    // Step 5 comes before step 6: too few slots and a foreign key.
    install_spi1(&spi1(23)?, &[5; 32])?;
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
    let (admitted, installation, signer) = bind_as_provider()??;
    let expected = SigningKey::from_bytes(&RUNTIME_SEED).verifying_key();
    assert_eq!(*admitted.provider().runtime_attestation_key(), expected);
    assert_eq!(signer.runtime_attestation_key_id(), RUNTIME_KEY_ID);
    // The signer signs an RLS1 that verifies under the admitted key.
    let release = issue_release(
        &signer,
        AdmittedRuntimeKey::new(RUNTIME_KEY_ID, &expected),
        release_fields(),
    )?;
    release.verify_signature(&expected)?;
    assert_eq!(installation.attempt_range().slots(), 256);
    assert_eq!(
        admitted.provider().manifest().runtime_attestation_key_id,
        RUNTIME_KEY_ID
    );
    drop(staged);
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

#[test]
fn startup_refusals_name_no_secret() {
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
}

/// A restart reconciliation whose outcome the test sends; a dropped sender
/// fails it.
pub(super) struct Scripted(pub(super) mpsc::Receiver<Result<ExecutePort, ReconcileError>>);

impl Reconcile for Scripted {
    fn reconcile(self) -> Result<ExecutePort, ReconcileError> {
        self.0.recv().unwrap_or(Err(ReconcileError::Staging))
    }
}

/// A systemd manager that accepts the subscription and knows no unit.
struct SubscribingManager(AtomicBool);

#[zbus::interface(name = "org.freedesktop.systemd1.Manager")]
impl SubscribingManager {
    fn subscribe(&self) {
        self.0.store(true, std::sync::atomic::Ordering::SeqCst);
    }
}

/// What a test execute port borrows: its private runtime tree and the fake
/// manager's end of the bus.
pub(super) struct PortFixture {
    /// The runtime tree: `registry`, `attempts`, `staging` and `captures`.
    _directory: tempfile::TempDir,
    _manager: zbus::Connection,
}

/// A private directory `name` beneath `parent`, mode `0700`.
fn private_child(parent: &Path, name: &str) -> TestResult<PathBuf> {
    let path = parent.join(name);
    fs::create_dir(&path)?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
    Ok(path)
}

/// An execute port over an empty registry, a private staging directory and
/// capture store, and a fake manager, with the ledger `limits`.
pub(super) fn test_port(limits: StagingLimits) -> TestResult<(PortFixture, ExecutePort)> {
    let directory = tempfile::tempdir()?;
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
    for child in ["registry", "attempts"] {
        private_child(directory.path(), child)?;
    }
    let parent = File::open(directory.path())?;
    let owner = parent.metadata()?.uid();
    let registry = SystemdAttemptRegistry::from_runtime_directory(&parent, owner)?;
    let staging = StagingDirectory::from_held_directory(
        File::open(private_child(directory.path(), "staging")?)?,
        owner,
    )?;
    let captures =
        NetworkCaptureStore::open(&File::open(private_child(directory.path(), "captures")?)?)?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?;
    let (manager, transport): (zbus::Connection, _) = runtime.block_on(async {
        let (manager, client) = crate::test_fixtures::peer_connections(|server| {
            server.serve_at(
                "/org/freedesktop/systemd1",
                SubscribingManager(AtomicBool::new(false)),
            )
        })
        .await?;
        let transport = SystemdTransientUnitTransport::from_connection(client).await?;
        Ok::<_, Box<dyn Error>>((manager, transport))
    })?;
    let ledger = StagingLedger::new(limits);
    let port = ExecutePort {
        lifecycle: AttemptLifecycle::new(registry, ledger.clone(), &ReconciledRestart::for_test()),
        ledger,
        staging,
        captures: Arc::new(captures),
        namespaces: crate::ProviderNamespaces::observe()?,
        budget: CleanupBudget::new(
            Duration::from_millis(100),
            Duration::from_millis(200),
            Duration::from_millis(300),
            Duration::from_millis(400),
            Duration::from_millis(500),
        )?,
        closed: AtomicBool::new(false),
        transport,
        runtime,
    };
    Ok((
        PortFixture {
            _directory: directory,
            _manager: manager,
        },
        port,
    ))
}

/// The admission state once background reconciliation set it.
pub(super) fn settled(admission: &OnceLock<AdmissionState>) -> TestResult<&AdmissionState> {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(state) = admission.get() {
            return Ok(state);
        }
        if Instant::now() > deadline {
            return Err("restart reconciliation never ended".into());
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn background_reconciliation_opens_or_closes_admission() -> TestResult {
    let (runtime, lifecycle) = test_port(StagingLimits {
        aggregate_bytes: 1 << 30,
    })?;
    // While reconciliation runs, the runtime is `Starting`.
    let (sender, receiver) = mpsc::channel();
    let admission = Arc::new(OnceLock::new());
    reconcile_in_background(Scripted(receiver), Arc::clone(&admission));
    assert!(admission.get().is_none());
    sender.send(Ok(lifecycle))?;
    assert!(matches!(settled(&admission)?, AdmissionState::Open { .. }));
    // A failure is `ReconcileFailed`, with no retry.
    let failed = Arc::new(OnceLock::new());
    reconcile_in_background(Scripted(mpsc::channel().1), Arc::clone(&failed));
    assert!(matches!(settled(&failed)?, AdmissionState::ReconcileFailed));
    drop(runtime);
    Ok(())
}

#[test]
fn a_reconciliation_that_cannot_start_stays_starting() {
    // The job is dropped unrun, so the state is never set: `Starting` for
    // good, which answers as `ReconcileFailed` does.
    let admission = Arc::new(OnceLock::new());
    start_reconciliation(Scripted(mpsc::channel().1), Arc::clone(&admission), |_| {
        Err(std::io::Error::other("injected spawn failure"))
    });
    assert!(admission.get().is_none());
}

/// The fixture's administrator-policy signer, which signs RVS1 and RCU1.
const POLICY_SEED: [u8; 32] = [2; 32];

/// A record signed by the policy key: `[unsigned, digest, signature]`, and
/// its self-digest.
fn policy_signed(magic: &str, unsigned: Value) -> TestResult<(Vec<u8>, [u8; 32])> {
    let mut preimage = format!("PiglorOS.{magic}.v1\0").into_bytes();
    preimage.extend(encode(&unsigned)?);
    let digest = *blake3::hash(&preimage).as_bytes();
    let mut message = format!("PiglorOS.{magic}.Signature.v1\0").into_bytes();
    message.extend(digest);
    let signature = SigningKey::from_bytes(&POLICY_SEED)
        .sign(&message)
        .to_bytes();
    let bytes = encode(&Value::Array(vec![
        unsigned,
        Value::Bytes(digest.to_vec()),
        Value::Bytes(signature.to_vec()),
    ]))?;
    Ok((bytes, digest))
}

/// An RCU1 of the staged installation to the next RVS1 epoch, revoking the
/// sorted `providers`, with the nonce `update_nonce` derives from `seed`;
/// and that next RVS1's digest.
pub(super) fn revocation_update(
    admitted: &AdmittedSelectorProvider,
    providers: &[[u8; 32]],
    seed: u8,
) -> TestResult<(Vec<u8>, [u8; 32])> {
    key_and_provider_revocation_update(admitted, &[], providers, seed)
}

/// As `revocation_update`, also revoking the sorted key IDs `keys`.
pub(super) fn key_and_provider_revocation_update(
    admitted: &AdmittedSelectorProvider,
    keys: &[&str],
    providers: &[[u8; 32]],
    seed: u8,
) -> TestResult<(Vec<u8>, [u8; 32])> {
    let bootstrap = admitted.bootstrap();
    let text = |value: &str| Value::Text(value.to_owned());
    let (next, next_digest) = policy_signed(
        "RVS1",
        Value::Array(vec![
            text("RVS1"),
            Value::Integer(1.into()),
            Value::Bytes(bootstrap.trust().snapshot_digest().to_vec()),
            Value::Integer((bootstrap.revocation().revocation_epoch() + 1).into()),
            Value::Array(keys.iter().copied().map(text).collect()),
            Value::Array(
                providers
                    .iter()
                    .map(|digest| Value::Bytes(digest.to_vec()))
                    .collect(),
            ),
            Value::Array(Vec::new()),
            text("policy"),
        ]),
    )?;
    let (rcu1, _) = policy_signed(
        "RCU1",
        Value::Array(vec![
            text("RCU1"),
            Value::Integer(1.into()),
            Value::Bytes(vec![70; 16]),
            Value::Bytes(bootstrap.revocation().snapshot_digest().to_vec()),
            Value::Bytes(next),
            Value::Bytes(next_digest.to_vec()),
            Value::Bytes(update_nonce(seed).to_vec()),
            text("policy"),
        ]),
    )?;
    Ok((rcu1, next_digest))
}

/// A distinct RCU1 nonce for each `seed`, derived through a labelled hash.
fn update_nonce(seed: u8) -> [u8; 16] {
    let digest = blake3::Hasher::new()
        .update(b"PiglorOS.SandboxdRevocationUpdateFixtureNonce.v1\0")
        .update(&[seed])
        .finalize();
    std::array::from_fn(|index| digest.as_bytes()[index])
}

/// The RCC1 of a committed update to `rcu1`, with the `live` and
/// `required` attempt sets.
pub(super) fn cancellation_context(
    admitted: &AdmittedSelectorProvider,
    rcu1: &[u8],
    live: Vec<[u8; 16]>,
    required: Vec<[u8; 16]>,
) -> TestResult<RecoveryCancellationContext> {
    let request = RevocationUpdateRequest::authenticate(
        rcu1,
        admitted.bootstrap().trust(),
        admitted.bootstrap().revocation(),
    )?;
    Ok(RecoveryCancellationContext::for_committed_recovery(
        [11; 32], [12; 32], &request, live, required,
    )?)
}
