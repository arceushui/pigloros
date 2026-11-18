//! `serve --require-local-erasure` composition, startup sweep and driver
//! task (#1448).

use std::path::{Path, PathBuf};
use std::time::Duration;

use ed25519_dalek::{Signer as _, SigningKey};
use pos_core::{
    local_erasure_bundle_signing_message_v1, EntityId, ErasureHostErrorV1, ErasureLifecycleV1,
    ErasureReferenceV1, ErasureScopeV1, LocalErasureBundleSignatureV1, LocalErasureBundleV1,
    PrincipalRefV1,
};
use pos_runtime::{
    ErasureCoordinatorCompositionV1, ErasureExecutionHostV1, LocalErasureCompositionErrorV1,
    LocalErasureSubmissionV1, LocalErasureSubmitErrorV1, LocalErasureSweepV1,
};
use pos_store::trust_policy_registry::TrustPolicyRegistryErrorV1;
use pos_store::StoreConfig;
use ulid::Ulid;

use super::{
    LocalErasureDriverTaskV1, LocalErasureServeErrorV1, LocalErasureServeInputsV1,
    LocalErasureServeV1, LOCAL_ERASURE_BUNDLE_CREDENTIAL_NAME,
    LOCAL_ERASURE_BUNDLE_SIGNATURE_CREDENTIAL_NAME,
};
use crate::authorization::GatewayOperationV1;
use crate::deployment_trust::{DeploymentTrustErrorV1, RELEASE_TRUST_CREDENTIAL_NAME};
use crate::local_erasure_provision::tests::{
    bundle_root, signer, Deployment, Fixture, TestResult, ROTATED_SEED, SIGNER_SEED,
};
use crate::local_erasure_provision::{
    provision_local_erasure, LOCAL_ERASURE_SIGNER_CREDENTIAL_NAME,
};
use crate::local_fork_authentication::MANAGED_CREDENTIAL_NAMES;
use crate::local_principal::{local_gateway, provision_on_host, LocalPrincipalProvisionV1};
use crate::mode_profile::{test_attach_host, test_binding, GatewayModeProfileIdV1};
use crate::startup::{open_recovered_erasure_host, GatewayHostStoreV1};
use crate::Gateway;

const PRINCIPAL_ID: &str = "01JC0GATEWAYQ0CA1PR1NC1PA1";
const ACTOR: &str = "01JC0GATEWAYQ0CA1ACT0R0000";

/// The provisioning clock: before the fixture TPS1 expires.
const PROVISIONED_AT: u64 = 1_800_000_000;

/// ELB1S over `bundle` by `root`.
fn signed(bundle: &[u8], root: &SigningKey) -> TestResult<Vec<u8>> {
    let reference = LocalErasureBundleV1::from_canonical_cbor(bundle)?.reference()?;
    let message = local_erasure_bundle_signing_message_v1(reference)?;
    Ok(LocalErasureBundleSignatureV1 {
        bundle: reference,
        admin_signature: root.sign(&message).to_bytes(),
    }
    .to_canonical_cbor()?)
}

/// A Gateway store with its Local Principal, provisioned for Local erasure
/// under a signed bundle, and its deployment trust state.
struct World {
    deployment: Deployment,
    fixture: Fixture,
    bundle: Vec<u8>,
    signature: Vec<u8>,
}

impl World {
    /// The Local Principal of the provisioning fixture.
    fn new() -> TestResult<Self> {
        Self::over(Fixture::new(true)?)
    }

    /// Provision Local erasure on `fixture`, which records its Local
    /// Principal, and sign the bundle with the TPS1 bundle root.
    fn over(fixture: Fixture) -> TestResult<Self> {
        let deployment = Deployment::new(&[])?;
        let bundle = provision_local_erasure(
            &fixture.request("bundle.elb1"),
            &signer(SIGNER_SEED),
            &deployment.trust()?,
            PROVISIONED_AT,
        )?;
        let signature = signed(&bundle, &bundle_root())?;
        Ok(Self {
            deployment,
            fixture,
            bundle,
            signature,
        })
    }

    /// A protected credential directory `name` holding the four erasure
    /// credentials, with the signer seed `seed`, and `extra`.
    fn credentials(&self, name: &str, seed: &[u8], extra: &[(&str, &[u8])]) -> TestResult<PathBuf> {
        let mut credentials: Vec<(&str, &[u8])> = vec![
            (LOCAL_ERASURE_BUNDLE_CREDENTIAL_NAME, self.bundle.as_slice()),
            (
                LOCAL_ERASURE_BUNDLE_SIGNATURE_CREDENTIAL_NAME,
                self.signature.as_slice(),
            ),
            (LOCAL_ERASURE_SIGNER_CREDENTIAL_NAME, seed),
            (
                RELEASE_TRUST_CREDENTIAL_NAME,
                self.deployment.release.as_bytes(),
            ),
        ];
        credentials.extend_from_slice(extra);
        self.fixture.credentials(name, &credentials)
    }

    /// The serve inputs over this world's store and trust state.
    fn inputs<'a>(&'a self, credentials: &'a Path) -> LocalErasureServeInputsV1<'a> {
        LocalErasureServeInputsV1 {
            sqlite_path: &self.fixture.path,
            credential_directory: credentials,
            trust_state: &self.deployment.state,
            with_fork_authority: false,
        }
    }

    /// Open this world's erasure host with `composition`, attached to the
    /// Local mode the fixture bound.
    fn host(
        &self,
        composition: &ErasureCoordinatorCompositionV1,
    ) -> TestResult<ErasureExecutionHostV1> {
        let host = open_recovered_erasure_host(
            StoreConfig::Sqlite {
                path: self.fixture.path.clone(),
            },
            GatewayHostStoreV1::Standard,
            composition,
        )?;
        Ok(test_attach_host(
            host,
            &test_binding(GatewayModeProfileIdV1::Local, []),
        ))
    }
}

fn principal() -> TestResult<PrincipalRefV1> {
    Ok(PrincipalRefV1::try_new(
        Ulid::from_string(PRINCIPAL_ID)?.to_bytes(),
        "local",
    )?)
}

fn actor() -> TestResult<EntityId> {
    Ok(EntityId::from_ulid(Ulid::from_string(ACTOR)?))
}

/// The submission of the fixture actor for private subject data.
fn submission() -> TestResult<LocalErasureSubmissionV1> {
    Ok(LocalErasureSubmissionV1 {
        principal: principal()?,
        actor: actor()?,
        scope: ErasureScopeV1::PrivateSubjectData,
        idempotency_key_digest: ErasureReferenceV1::from_digest([0x11; 32]),
    })
}

/// The refusal of a serve with `inputs`, if any.
fn refused(inputs: LocalErasureServeInputsV1<'_>) -> Option<LocalErasureServeErrorV1> {
    LocalErasureServeV1::for_serve(Some(inputs)).err()
}

/// `inputs` for a deployment that also requires the Local Fork authority.
const fn with_fork(inputs: LocalErasureServeInputsV1<'_>) -> LocalErasureServeInputsV1<'_> {
    LocalErasureServeInputsV1 {
        with_fork_authority: true,
        ..inputs
    }
}

/// D1, D2, D17: valid credentials compose the Local erasure authority on
/// `SQLite`; the startup sweep runs once, the production Gateway composes
/// over the host, and the driver starts and stops with it.
#[tokio::test]
async fn valid_credentials_compose_the_local_erasure_authority() -> TestResult {
    let world = World::new()?;
    let credentials = world.credentials("credentials", &SIGNER_SEED, &[])?;
    let erasure = LocalErasureServeV1::for_serve(Some(world.inputs(&credentials)))?;
    let mut host = world.host(erasure.composition())?;
    let started = erasure.start(&mut host);
    assert_eq!(started.sweep(), Some(LocalErasureSweepV1::Swept(0)));
    let mode = test_binding(GatewayModeProfileIdV1::Local, []);
    let gateway = local_gateway(host, None, &mode)?;
    let driver = LocalErasureDriverTaskV1::spawn(&gateway, started);
    assert!(driver.trigger().is_some());
    driver.stop().await;
    assert!(gateway.shutdown().await.is_ok());
    Ok(())
}

/// D9: without `--require-local-erasure` the Gateway keeps the closed
/// composition, which admits no Local submission, runs no sweep and starts
/// no driver.
#[tokio::test]
async fn without_the_flag_the_composition_stays_closed() -> TestResult {
    let world = World::new()?;
    let erasure = LocalErasureServeV1::for_serve(None)?;
    let mut host = world.host(erasure.composition())?;
    assert_eq!(
        host.command_sender()?
            .submit_local_erasure(&submission()?)
            .err(),
        Some(LocalErasureSubmitErrorV1::Host(
            ErasureHostErrorV1::AuthorizationDenied
        ))
    );
    let started = erasure.start(&mut host);
    assert_eq!(started.sweep(), None);
    let gateway = Gateway::new_with_erasure_host(host, None)?;
    let driver = LocalErasureDriverTaskV1::spawn(&gateway, started);
    assert!(driver.trigger().is_none());
    driver.stop().await;
    assert!(gateway.shutdown().await.is_ok());
    Ok(())
}

/// D9: every credential, trust, store and bundle failure refuses startup
/// with its typed, payload-free error.
#[test]
fn each_credential_trust_store_or_bundle_failure_refuses_startup() -> TestResult {
    let world = World::new()?;
    let missing = world.fixture.directory.path().join("missing");
    assert_eq!(
        refused(world.inputs(&missing)),
        Some(LocalErasureServeErrorV1::Credentials)
    );
    let extra = world.credentials(
        "extra",
        &SIGNER_SEED,
        &[("pigloros.extra", b"x".as_slice())],
    )?;
    assert_eq!(
        refused(world.inputs(&extra)),
        Some(LocalErasureServeErrorV1::Credentials)
    );
    let unsigned = world.fixture.credentials(
        "unsigned",
        &[
            (
                LOCAL_ERASURE_BUNDLE_CREDENTIAL_NAME,
                world.bundle.as_slice(),
            ),
            (LOCAL_ERASURE_SIGNER_CREDENTIAL_NAME, SIGNER_SEED.as_slice()),
            (
                RELEASE_TRUST_CREDENTIAL_NAME,
                world.deployment.release.as_bytes(),
            ),
        ],
    )?;
    assert_eq!(
        refused(world.inputs(&unsigned)),
        Some(LocalErasureServeErrorV1::Credentials)
    );
    let short_seed = world.credentials("short-seed", &SIGNER_SEED[..31], &[])?;
    assert_eq!(
        refused(world.inputs(&short_seed)),
        Some(LocalErasureServeErrorV1::SignerCredentialInvalid)
    );
    let release = world.fixture.credentials(
        "release",
        &[
            (
                LOCAL_ERASURE_BUNDLE_CREDENTIAL_NAME,
                world.bundle.as_slice(),
            ),
            (
                LOCAL_ERASURE_BUNDLE_SIGNATURE_CREDENTIAL_NAME,
                world.signature.as_slice(),
            ),
            (LOCAL_ERASURE_SIGNER_CREDENTIAL_NAME, SIGNER_SEED.as_slice()),
            (RELEASE_TRUST_CREDENTIAL_NAME, b"policy_id = 1".as_slice()),
        ],
    )?;
    assert_eq!(
        refused(world.inputs(&release)),
        Some(LocalErasureServeErrorV1::Trust(
            DeploymentTrustErrorV1::ReleaseTrustInvalid
        ))
    );
    let valid = world.credentials("valid", &SIGNER_SEED, &[])?;
    let absent_trust = world.fixture.directory.path().join("absent-trust.db");
    assert_eq!(
        refused(LocalErasureServeInputsV1 {
            trust_state: &absent_trust,
            ..world.inputs(&valid)
        }),
        Some(LocalErasureServeErrorV1::Trust(
            DeploymentTrustErrorV1::TrustState(TrustPolicyRegistryErrorV1::MissingState)
        ))
    );
    let directory_path = world
        .fixture
        .directory
        .path()
        .to_str()
        .ok_or("temporary path is not UTF-8")?
        .to_owned();
    assert_eq!(
        refused(LocalErasureServeInputsV1 {
            sqlite_path: &directory_path,
            ..world.inputs(&valid)
        }),
        Some(LocalErasureServeErrorV1::StoreUnavailable)
    );
    let unprovisioned = Fixture::new(false)?;
    assert_eq!(
        refused(LocalErasureServeInputsV1 {
            sqlite_path: &unprovisioned.path,
            ..world.inputs(&valid)
        }),
        Some(LocalErasureServeErrorV1::PrincipalMissing)
    );
    let foreign_root = signed(&world.bundle, &SigningKey::from_bytes(&[0x63; 32]))?;
    let forged = world.fixture.credentials(
        "forged",
        &[
            (
                LOCAL_ERASURE_BUNDLE_CREDENTIAL_NAME,
                world.bundle.as_slice(),
            ),
            (
                LOCAL_ERASURE_BUNDLE_SIGNATURE_CREDENTIAL_NAME,
                foreign_root.as_slice(),
            ),
            (LOCAL_ERASURE_SIGNER_CREDENTIAL_NAME, SIGNER_SEED.as_slice()),
            (
                RELEASE_TRUST_CREDENTIAL_NAME,
                world.deployment.release.as_bytes(),
            ),
        ],
    )?;
    assert_eq!(
        refused(world.inputs(&forged)),
        Some(LocalErasureServeErrorV1::Composition(
            LocalErasureCompositionErrorV1::BundleInvalid
        ))
    );
    let other_signer = world.credentials("other-signer", &ROTATED_SEED, &[])?;
    assert_eq!(
        refused(world.inputs(&other_signer)),
        Some(LocalErasureServeErrorV1::SignerMismatch)
    );
    assert_eq!(
        LocalErasureServeErrorV1::Credentials.to_string(),
        "the local erasure credentials are unavailable or invalid"
    );
    Ok(())
}

/// With `--require-local-fork-authority` too, the unit's one directory
/// holds exactly the erasure and the Fork-admission credentials.
#[test]
fn the_erasure_credentials_share_the_directory_with_the_fork_credentials() -> TestResult {
    let world = World::new()?;
    let fork = MANAGED_CREDENTIAL_NAMES.map(|name| (name, b"fork".as_slice()));
    let shared = world.credentials("shared", &SIGNER_SEED, &fork)?;
    assert!(LocalErasureServeV1::for_serve(Some(with_fork(world.inputs(&shared)))).is_ok());
    assert_eq!(
        LocalErasureServeV1::for_serve(Some(world.inputs(&shared))).err(),
        Some(LocalErasureServeErrorV1::Credentials)
    );
    let alone = world.credentials("alone", &SIGNER_SEED, &[])?;
    assert_eq!(
        LocalErasureServeV1::for_serve(Some(with_fork(world.inputs(&alone)))).err(),
        Some(LocalErasureServeErrorV1::Credentials)
    );
    Ok(())
}

/// A sweep that cannot read its objects is skipped and never fails
/// startup (#1431 Q13).
#[tokio::test]
async fn a_skipped_startup_sweep_does_not_fail_startup() -> TestResult {
    let world = World::new()?;
    // A retained ELO1 row without its evidence makes the sweep's read fail.
    rusqlite::Connection::open(&world.fixture.path)?.execute(
        "INSERT INTO erasure_retained_objects (reference_digest, tag) VALUES (?1, 'ELO1')",
        rusqlite::params![[0x5a_u8; 32].as_slice()],
    )?;
    let credentials = world.credentials("credentials", &SIGNER_SEED, &[])?;
    let erasure = LocalErasureServeV1::for_serve(Some(world.inputs(&credentials)))?;
    let mut host = world.host(erasure.composition())?;
    let started = erasure.start(&mut host);
    assert_eq!(started.sweep(), Some(LocalErasureSweepV1::Skipped));
    let mode = test_binding(GatewayModeProfileIdV1::Local, []);
    let gateway = local_gateway(host, None, &mode)?;
    let driver = LocalErasureDriverTaskV1::spawn(&gateway, started);
    driver.stop().await;
    assert!(gateway.shutdown().await.is_ok());
    Ok(())
}

/// A Local Principal store whose root grant lets the fixture actor request
/// erasure, provisioned for Local erasure.
fn erasure_world() -> TestResult<World> {
    let fixture = Fixture::new(false)?;
    let provision = LocalPrincipalProvisionV1::try_new(
        &principal()?,
        [actor()?],
        [
            GatewayOperationV1::CREATE_TIMELINE,
            GatewayOperationV1::new("erasure.request", "erasure", "request", "operation"),
        ],
    )?;
    let mut host = open_recovered_erasure_host(
        StoreConfig::Sqlite {
            path: fixture.path.clone(),
        },
        GatewayHostStoreV1::Standard,
        &ErasureCoordinatorCompositionV1::closed(),
    )?;
    provision_on_host(&mut host, &provision)?;
    drop(host);
    World::over(fixture)
}

/// D7: a request submitted through the host seam is driven to its first
/// receipt by the driver task's startup run, one step per store command;
/// once the executor stops, the next admission wake ends the task.
#[tokio::test]
async fn the_driver_task_drives_a_submitted_request_end_to_end() -> TestResult {
    let world = erasure_world()?;
    let credentials = world.credentials("credentials", &SIGNER_SEED, &[])?;
    let erasure = LocalErasureServeV1::for_serve(Some(world.inputs(&credentials)))?;
    let mut host = world.host(erasure.composition())?;
    host.command_sender()?
        .create_owned_timeline("owned", actor()?)?;
    let request = host
        .command_sender()?
        .submit_local_erasure(&submission()?)
        .map_err(|error| format!("{error:?}"))?
        .request();
    let started = erasure.start(&mut host);
    let gateway = Gateway::new_with_erasure_host(host, None)?;
    // A tick far beyond the deadline: only the startup run and the
    // admission hook wake this driver.
    let driver =
        LocalErasureDriverTaskV1::spawn_every(&gateway, started, Duration::from_secs(3_600));
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    loop {
        let lifecycle = gateway
            .store
            .probe_host_for_test(move |host| {
                host.read_sender()
                    .and_then(|mut reads| reads.erasure_state(request))
                    .ok()
                    .flatten()
                    .map(|state| state.lifecycle())
            })
            .await
            .map_err(|error| format!("{error:?}"))?
            .flatten();
        if matches!(
            lifecycle,
            Some(ErasureLifecycleV1::Complete | ErasureLifecycleV1::PartialFailure)
        ) {
            break;
        }
        if tokio::time::Instant::now() > deadline {
            return Err(format!("the driver left the request {lifecycle:?}").into());
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    // Once the executor stops, the next wake ends the driver.
    let trigger = driver.trigger().ok_or("a Local driver has a trigger")?;
    assert!(gateway.shutdown().await.is_ok());
    trigger.admitted();
    let finished = || {
        driver
            .running
            .as_ref()
            .is_some_and(|(_, task)| task.is_finished())
    };
    while !finished() {
        if tokio::time::Instant::now() > deadline {
            return Err("the driver outlived its executor".into());
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    driver.stop().await;
    Ok(())
}
