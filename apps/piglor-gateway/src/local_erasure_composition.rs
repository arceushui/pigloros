//! The serve composition of the Local erasure authority (ADR-136 §4a and
//! §5; #1448, owner decisions D1, D2, D7, D9 and D17 of 2026-11-18 on
//! #1413).
//!
//! `serve --require-local-erasure` reads four credentials from the serve
//! unit's credential directory, `/run/credentials/piglor-gateway.service`:
//!
//! - [`LOCAL_ERASURE_BUNDLE_CREDENTIAL_NAME`]: the installed ELB1 bytes,
//!   as `provision-local-erasure` wrote them;
//! - [`LOCAL_ERASURE_BUNDLE_SIGNATURE_CREDENTIAL_NAME`]: the ELB1S bytes the
//!   holder of the `erasure-bundle/` TPS1 root signed offline;
//! - [`LOCAL_ERASURE_SIGNER_CREDENTIAL_NAME`]: the role-2 signer's 32-byte
//!   Ed25519 seed, the key the bundle pins;
//! - [`RELEASE_TRUST_CREDENTIAL_NAME`]: the deployment release anchor.
//!
//! The directory holds exactly these, plus the three Fork-admission
//! credentials when the deployment also requires the Local Fork authority.
//! Both serve modes load the installed TPS1 through the shared deployment
//! trust loader ([`crate::deployment_trust`]); an Air-Gapped deployment seeds
//! the same trust state store with its bundled TPS1 (D17).
//!
//! Composition runs under the store's shared mode lock, before the erasure
//! host opens: it reads the Local Principal's registry digest from the raw
//! store and calls [`ErasureCoordinatorCompositionV1::local`] with this
//! binary's executor binding. Any credential, trust, store or bundle error
//! refuses startup with a payload-free [`LocalErasureServeErrorV1`]; the
//! Gateway never falls back to the closed composition when the flag is
//! given (D9). Without the flag every serve composes
//! [`ErasureCoordinatorCompositionV1::closed`].
//!
//! Once the host is recovered and bound, [`LocalErasureServeV1::start`]
//! runs the startup sweep ([`LocalErasureDriverV1::sweep`]) once; a skipped
//! sweep never fails startup. [`LocalErasureDriverTaskV1`] then drives the
//! lifecycle: once at startup, on every [`LOCAL_ERASURE_DRIVER_TICK`], and
//! whenever [`LocalErasureTriggerV1::admitted`] reports a new admission (the
//! erasure admission route of the next slice calls it; until then only the
//! startup run and the tick wake the driver). Each wake submits one driver step per store
//! command until no request has a step due, so every other Gateway command
//! interleaves between two steps, and reports on standard error how many
//! requests had a step fail, whenever that count changes.
//! A step that purges the local replica runs `VACUUM` inside its one
//! command and holds every other Gateway command for its duration.

use std::{
    collections::BTreeSet,
    io::{self, Write as _},
    path::Path,
    sync::Arc,
    time::Duration,
};

use pos_core::{ErasureReferenceV1, LocalErasureBundleV1, OwnerIdV1};
use pos_crypto::key_roles::SigningKeyMaterial;
use pos_runtime::{
    local_erasure_execution_binding_v1, ErasureCoordinatorCompositionV1, ErasureExecutionHostV1,
    LocalErasureCompositionErrorV1, LocalErasureCompositionInputsV1, LocalErasureDriverV1,
    LocalErasureSignerV1, LocalErasureStepV1, LocalErasureSweepV1,
};
use pos_store::{sqlite::SqliteStore, trust_policy_registry::OperatorReleaseTrustV1};
use thiserror::Error;
use tokio::{sync::Notify, task::JoinHandle, time::MissedTickBehavior};
use zeroize::Zeroizing;

pub use crate::deployment_trust::DEPLOYMENT_TRUST_STATE_PATH;
use crate::deployment_trust::{
    load_deployment_trust_v1, release_trust_from_credential, DeploymentTrustErrorV1,
    MAX_RELEASE_TRUST_CREDENTIAL_BYTES, RELEASE_TRUST_CREDENTIAL_NAME,
};
use crate::executor::{StoreExecutor, WeakStoreExecutor};
use crate::local_erasure_provision::{
    signer_material, unix_now, LOCAL_ERASURE_SIGNER_CREDENTIAL_NAME,
};
use crate::local_principal::{
    local_principal_authority_timeline, local_principal_grant_id, recorded_registry_digest,
};
use crate::Gateway;

/// The systemd credential holding the installed ELB1 bytes.
pub const LOCAL_ERASURE_BUNDLE_CREDENTIAL_NAME: &str = "pigloros.local-erasure-bundle";

/// The systemd credential holding the ELB1S bytes over the installed ELB1.
pub const LOCAL_ERASURE_BUNDLE_SIGNATURE_CREDENTIAL_NAME: &str =
    "pigloros.local-erasure-bundle-signature";

/// The four credentials `serve --require-local-erasure` reads, sorted.
pub const LOCAL_ERASURE_SERVE_CREDENTIAL_NAMES: [&str; 4] = [
    LOCAL_ERASURE_BUNDLE_CREDENTIAL_NAME,
    LOCAL_ERASURE_BUNDLE_SIGNATURE_CREDENTIAL_NAME,
    LOCAL_ERASURE_SIGNER_CREDENTIAL_NAME,
    RELEASE_TRUST_CREDENTIAL_NAME,
];

/// The largest bundle or bundle-signature credential accepted: the ELB1
/// record bound, 64 KiB.
pub const MAX_LOCAL_ERASURE_BUNDLE_CREDENTIAL_BYTES: usize = 64 * 1024;

/// The length of the signer credential, a 32-byte Ed25519 seed.
const LOCAL_ERASURE_SIGNER_SEED_BYTES: usize = 32;

/// How often the driver wakes without an admission, to resume deferred
/// steps and the automatic retries of transient negatives.
pub const LOCAL_ERASURE_DRIVER_TICK: Duration = Duration::from_secs(10);

/// Closed, payload-free reasons `serve --require-local-erasure` refuses to
/// start.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Error)]
pub enum LocalErasureServeErrorV1 {
    /// The credential directory is missing, is not protected, or does not
    /// hold exactly the expected credentials, or one of them is unreadable
    /// or over its bound.
    #[error("the local erasure credentials are unavailable or invalid")]
    Credentials,
    /// The signer credential is not a readable, protected 32-byte Ed25519
    /// seed; a longer credential is refused without reading it.
    #[error("the local erasure signer credential is not a 32-byte Ed25519 seed")]
    SignerCredentialInvalid,
    /// The signer credential is not the signer key the bundle pins.
    #[error("the local erasure signer credential is not the signer key the bundle pins")]
    SignerMismatch,
    /// The release anchor or the trust state store is unavailable.
    #[error(transparent)]
    Trust(DeploymentTrustErrorV1),
    /// The store records no Local Principal.
    #[error("the store records no Local Principal; run provision-local-principal first")]
    PrincipalMissing,
    /// The store does not exist (composition never creates it), cannot be
    /// opened, is not bound to a compiled execution mode, or its Local
    /// Principal record cannot be read.
    #[error("the local erasure store cannot be read")]
    StoreUnavailable,
    /// The installed bundle keeps the Local erasure authority closed.
    #[error(transparent)]
    Composition(LocalErasureCompositionErrorV1),
}

/// The inputs of `serve --require-local-erasure`.
#[derive(Clone, Copy, Debug)]
pub struct LocalErasureServeInputsV1<'a> {
    /// The Gateway's `SQLite` store.
    pub sqlite_path: &'a str,
    /// The serve unit's validated credential directory.
    pub credential_directory: &'a Path,
    /// The deployment trust state store, [`DEPLOYMENT_TRUST_STATE_PATH`]
    /// in production.
    pub trust_state: &'a Path,
    /// Whether the directory also holds the three Fork-admission
    /// credentials of `--require-local-fork-authority`.
    pub with_fork_authority: bool,
}

/// The decoded erasure credentials of the serve unit.
struct LocalErasureCredentialsV1 {
    bundle: Zeroizing<Vec<u8>>,
    bundle_signature: Zeroizing<Vec<u8>>,
    signer: SigningKeyMaterial,
    release: OperatorReleaseTrustV1,
}

/// Read and decode the four erasure credentials of `directory`, which holds
/// exactly them and `alongside`.
fn credentials(
    directory: &Path,
    alongside: &[&str],
) -> Result<LocalErasureCredentialsV1, LocalErasureServeErrorV1> {
    let names = LOCAL_ERASURE_SERVE_CREDENTIAL_NAMES
        .iter()
        .chain(alongside)
        .copied()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    crate::local_fork_authentication::open_exact_credentials(
        directory,
        &names,
        rustix::process::geteuid().as_raw(),
    )
    .map_err(|_| LocalErasureServeErrorV1::Credentials)
    .and_then(|credentials| {
        let read = |name: &str, maximum: usize| {
            credentials
                .read(name, maximum)
                .map_err(|_| LocalErasureServeErrorV1::Credentials)
        };
        let bundle_bytes = MAX_LOCAL_ERASURE_BUNDLE_CREDENTIAL_BYTES;
        read(LOCAL_ERASURE_BUNDLE_CREDENTIAL_NAME, bundle_bytes)
            .and_then(|bundle| {
                read(LOCAL_ERASURE_BUNDLE_SIGNATURE_CREDENTIAL_NAME, bundle_bytes)
                    .map(|signature| (bundle, signature))
            })
            .and_then(|bundles| {
                read(
                    RELEASE_TRUST_CREDENTIAL_NAME,
                    MAX_RELEASE_TRUST_CREDENTIAL_BYTES,
                )
                .map(|release| (bundles, release))
            })
            .and_then(|(bundles, release)| {
                credentials
                    .read(
                        LOCAL_ERASURE_SIGNER_CREDENTIAL_NAME,
                        LOCAL_ERASURE_SIGNER_SEED_BYTES,
                    )
                    .ok()
                    .and_then(|seed| signer_material(&seed).ok())
                    .ok_or(LocalErasureServeErrorV1::SignerCredentialInvalid)
                    .map(|signer| (bundles, signer, release))
            })
    })
    .and_then(|((bundle, bundle_signature), signer, release)| {
        release_trust_from_credential(&release)
            .map_err(LocalErasureServeErrorV1::Trust)
            .map(|release| LocalErasureCredentialsV1 {
                bundle,
                bundle_signature,
                signer,
                release,
            })
    })
}

/// The role-2 signer of `signer` under the identity the verified `bundle`
/// pins, or [`LocalErasureServeErrorV1::SignerMismatch`] when the bundle
/// pins another key.
fn bundle_signer(
    bundle: &[u8],
    signer: SigningKeyMaterial,
) -> Result<LocalErasureSignerV1, LocalErasureServeErrorV1> {
    LocalErasureBundleV1::from_canonical_cbor(bundle)
        .ok()
        .filter(|pinned| pinned.signer_public_key == *signer.public_verification_key().as_bytes())
        .and_then(|pinned| {
            std::str::from_utf8(&pinned.signer_identity.owner_id)
                .ok()
                .and_then(|owner| OwnerIdV1::new(owner).ok())
                .map(|owner| (owner, pinned.signer_identity.epoch))
        })
        .map(|(owner, epoch)| LocalErasureSignerV1::new(signer, owner, epoch))
        .ok_or(LocalErasureServeErrorV1::SignerMismatch)
}

/// Open the existing store at `sqlite_path` as provisioning does: attached
/// to its binding, which must be a compiled execution mode (ADR-134 §8).
/// A path that names no file is refused before the store opens, so
/// composition never creates a database.
fn open_bound_store(sqlite_path: &str) -> Result<SqliteStore, LocalErasureServeErrorV1> {
    Some(sqlite_path)
        .filter(|path| Path::new(path).is_file())
        .and_then(|path| SqliteStore::open(path).ok())
        .and_then(|mut store| {
            crate::mode_profile::attach_offline_writer_v1(&mut store)
                .ok()
                .map(|_| store)
        })
        .ok_or(LocalErasureServeErrorV1::StoreUnavailable)
}

/// The erasure authority one serve composes: the closed authority, or the
/// Local erasure authority with the driver of its signer.
pub struct LocalErasureServeV1 {
    composition: ErasureCoordinatorCompositionV1,
    driver: Option<LocalErasureDriverV1>,
}

impl LocalErasureServeV1 {
    /// The closed erasure authority of a serve without
    /// `--require-local-erasure`.
    #[must_use]
    pub fn closed() -> Self {
        Self {
            composition: ErasureCoordinatorCompositionV1::closed(),
            driver: None,
        }
    }

    /// The Local erasure authority of `inputs`, or the closed authority
    /// without them.
    ///
    /// # Errors
    /// Returns the [`LocalErasureServeErrorV1`] that refuses startup.
    pub fn for_serve(
        inputs: Option<LocalErasureServeInputsV1<'_>>,
    ) -> Result<Self, LocalErasureServeErrorV1> {
        inputs.map_or_else(|| Ok(Self::closed()), Self::local)
    }

    /// Compose the Local erasure authority over the store of `inputs`.
    fn local(inputs: LocalErasureServeInputsV1<'_>) -> Result<Self, LocalErasureServeErrorV1> {
        let alongside: &[&str] = if inputs.with_fork_authority {
            &crate::local_fork_authentication::MANAGED_CREDENTIAL_NAMES
        } else {
            &[]
        };
        credentials(inputs.credential_directory, alongside).and_then(
            |LocalErasureCredentialsV1 {
                 bundle,
                 bundle_signature,
                 signer,
                 release,
             }| {
                let operator_public_key = release.operator_public_key();
                load_deployment_trust_v1(inputs.trust_state, release)
                    .map_err(LocalErasureServeErrorV1::Trust)
                    .and_then(|trust| {
                        open_bound_store(inputs.sqlite_path).and_then(|mut store| {
                            recorded_registry_digest(&store)
                                .ok()
                                .ok_or(LocalErasureServeErrorV1::StoreUnavailable)
                                .and_then(|registry| {
                                    registry.ok_or(LocalErasureServeErrorV1::PrincipalMissing)
                                })
                                .and_then(|registry| {
                                    let binding = local_erasure_execution_binding_v1();
                                    ErasureCoordinatorCompositionV1::local(
                                        &LocalErasureCompositionInputsV1 {
                                            bundle: &bundle,
                                            bundle_signature: &bundle_signature,
                                            trust: &trust,
                                            operator_public_key,
                                            authority_registry_digest:
                                                ErasureReferenceV1::from_digest(
                                                    *registry.as_bytes(),
                                                ),
                                            execution_binding: Some(&binding),
                                            principal_grant: local_principal_grant_id(),
                                            authority_timeline: local_principal_authority_timeline(
                                            ),
                                            clock: unix_now,
                                        },
                                        &mut store,
                                    )
                                    .map_err(LocalErasureServeErrorV1::Composition)
                                })
                        })
                    })
                    .and_then(|composition| {
                        bundle_signer(&bundle, signer).map(|signer| Self {
                            composition,
                            driver: Some(LocalErasureDriverV1::new(signer)),
                        })
                    })
            },
        )
    }

    /// The composition the erasure host opens with.
    #[must_use]
    pub const fn composition(&self) -> &ErasureCoordinatorCompositionV1 {
        &self.composition
    }

    /// After the host is recovered and bound, run the Local startup sweep
    /// once and announce its count on standard error; a closed composition
    /// runs none.
    #[must_use]
    pub fn start(self, host: &mut ErasureExecutionHostV1) -> LocalErasureStartV1 {
        LocalErasureStartV1 {
            started: self.driver.map(|driver| {
                let sweep = LocalErasureDriverV1::sweep(host);
                announce(&format!(
                    "piglor-gateway local erasure startup sweep: {sweep:?}"
                ));
                (driver, sweep)
            }),
        }
    }
}

/// A started erasure authority: the driver and the startup sweep outcome
/// of a Local composition, nothing for a closed one.
#[derive(Default)]
pub struct LocalErasureStartV1 {
    started: Option<(LocalErasureDriverV1, LocalErasureSweepV1)>,
}

impl LocalErasureStartV1 {
    /// The startup sweep outcome, `None` for a closed composition.
    #[must_use]
    pub fn sweep(&self) -> Option<LocalErasureSweepV1> {
        self.started.as_ref().map(|(_, sweep)| *sweep)
    }
}

/// The hook a served erasure admission calls so the driver runs at once
/// instead of at its next tick.
#[derive(Clone, Debug)]
pub struct LocalErasureTriggerV1(Arc<Notify>);

impl LocalErasureTriggerV1 {
    /// Report a new erasure admission.
    pub fn admitted(&self) {
        self.0.notify_one();
    }
}

/// The background driver of a Local composition; inert for a closed one.
pub struct LocalErasureDriverTaskV1 {
    running: Option<(LocalErasureTriggerV1, JoinHandle<()>)>,
}

impl LocalErasureDriverTaskV1 {
    /// Spawn the driver of `started` over `gateway`'s store executor. It
    /// runs once at once, then on every tick and every admission, and
    /// ends once the executor is no longer open.
    #[must_use]
    pub fn spawn(gateway: &Gateway, started: LocalErasureStartV1) -> Self {
        Self::spawn_every(gateway, started, LOCAL_ERASURE_DRIVER_TICK)
    }

    /// [`Self::spawn`] with the tick `every`.
    fn spawn_every(gateway: &Gateway, started: LocalErasureStartV1, every: Duration) -> Self {
        Self {
            running: started.started.map(|(driver, _)| {
                let wake = Arc::new(Notify::new());
                let task = tokio::spawn(drive(
                    gateway.store.downgrade(),
                    Arc::new(driver),
                    Arc::clone(&wake),
                    every,
                ));
                (LocalErasureTriggerV1(wake), task)
            }),
        }
    }

    /// The admission hook, `None` for a closed composition.
    #[must_use]
    pub fn trigger(&self) -> Option<LocalErasureTriggerV1> {
        self.running.as_ref().map(|(trigger, _)| trigger.clone())
    }

    /// Stop the driver before the executor drains, and report on standard
    /// error whether it had panicked.
    pub async fn stop(self) {
        if let Some((_, task)) = self.running {
            task.abort();
            let panicked = task.await.is_err_and(|error| error.is_panic());
            announce(&format!(
                "piglor-gateway local erasure driver stopped (panicked: {panicked})"
            ));
        }
    }
}

/// The driver loop: wake on a tick or an admission, then submit one step
/// per store command until no request has one due; end once the executor
/// is gone or no longer open.
async fn drive(
    executor: WeakStoreExecutor,
    driver: Arc<LocalErasureDriverV1>,
    wake: Arc<Notify>,
    every: Duration,
) {
    let mut tick = tokio::time::interval(every);
    tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
    let mut previous = 0;
    loop {
        // Each arm binds its future's output: the tick's instant, the
        // notification's unit.
        tokio::select! {
            _instant = tick.tick() => {}
            () = wake.notified() => {}
        }
        let Some(store) = executor.upgrade().filter(StoreExecutor::is_ready) else {
            break;
        };
        previous = wake_once(&store, &driver, previous).await;
    }
}

/// One wake of the driver: one step per store command until no request has
/// one due or a command fails. It returns how many distinct requests had a
/// step fail and deferred to a later wake, and reports that count on
/// standard error when it differs from the `previous` wake's.
async fn wake_once(
    store: &StoreExecutor,
    driver: &Arc<LocalErasureDriverV1>,
    previous: usize,
) -> usize {
    let mut deferred = BTreeSet::new();
    while let Ok(Ok(advanced)) = store.advance_local_erasure(driver).await {
        deferred.extend(advanced.deferred);
        if advanced.step == LocalErasureStepV1::Idle {
            break;
        }
    }
    if let Some(report) = deferred_report(deferred.len(), previous) {
        announce(&report);
    }
    deferred.len()
}

/// Write one payload-free line to standard error; the stream's lock is
/// released at the end of the write.
fn announce(line: &str) {
    drop(writeln!(io::stderr().lock(), "{line}"));
}

/// The payload-free report of a wake that deferred `deferred` requests,
/// `None` when the previous wake deferred as many.
fn deferred_report(deferred: usize, previous: usize) -> Option<String> {
    (deferred != previous)
        .then(|| format!("piglor-gateway local erasure driver deferred {deferred} requests"))
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests;
