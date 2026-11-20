#![forbid(unsafe_code)]
#![cfg_attr(all(coverage_nightly, test), feature(coverage_attribute))]
//! `pos-local-erasure-loader`: the shared trust, Local Principal and
//! credential loader of the Local erasure authority (ADR-136 §4a; #1450,
//! owner decisions of 2026-11-20 on #1450).
//!
//! The Gateway composes the Local erasure authority with its executor,
//! signer and driver ([`composition::compose_local_erasure`] with its
//! execution binding). The key-less roots (`pos-cli`, `pos-experiment` and
//! `piglor-ledger`) compose it for verification and recovery only, with no
//! signer, driver or executor: [`LocalErasureRecoveryV1`].
//!
//! A key-less root reads the installed ELB1
//! ([`LOCAL_ERASURE_BUNDLE_CREDENTIAL_NAME`]), its ELB1S
//! ([`LOCAL_ERASURE_BUNDLE_SIGNATURE_CREDENTIAL_NAME`]) and the release
//! anchor ([`deployment_trust::RELEASE_TRUST_CREDENTIAL_NAME`]) from its
//! systemd credential directory, `$CREDENTIALS_DIRECTORY`, which holds
//! exactly these three ([`KEYLESS_CREDENTIAL_NAMES`]); it takes no flag. The
//! installed TPS1 comes from the fixed deployment trust state store,
//! [`deployment_trust::DEPLOYMENT_TRUST_STATE_PATH`].
//!
//! A store that records no erasure store identity (every `MemoryStore`, and
//! every store never provisioned for Local erasure) composes
//! [`ErasureCoordinatorCompositionV1::closed`]. A store that records one
//! composes the Local erasure authority or fails closed with a typed
//! [`LocalErasureLoadErrorV1`]; it never falls back to the closed
//! composition. Off Linux, which has neither systemd credentials nor the
//! trust state store, such a store is refused with
//! `LocalErasureLoadErrorV1::PlatformUnsupported`.

use std::path::PathBuf;

use pos_core::{
    AuthorityPersistencePortV1, ErasureHostErrorV1, ErasureInventoryPersistencePortV1,
    ErasurePersistencePortV1, ErasureRecoveryLimitsV1, EventStore,
};
#[cfg(target_os = "linux")]
use pos_runtime::LocalErasureCompositionErrorV1;
use pos_runtime::{ErasureCoordinatorCompositionV1, ErasureExecutionHostV1};
use pos_store::{sqlite::SqliteStore, StoreConfig};

#[cfg(target_os = "linux")]
pub mod composition;
#[cfg(target_os = "linux")]
pub mod credentials;
pub mod deployment_trust;
pub mod local_principal;

/// The systemd credential holding the installed ELB1 bytes.
pub const LOCAL_ERASURE_BUNDLE_CREDENTIAL_NAME: &str = "pigloros.local-erasure-bundle";

/// The systemd credential holding the ELB1S bytes over the installed ELB1.
pub const LOCAL_ERASURE_BUNDLE_SIGNATURE_CREDENTIAL_NAME: &str =
    "pigloros.local-erasure-bundle-signature";

/// The largest bundle or bundle-signature credential accepted: the ELB1
/// record bound, 64 KiB.
pub const MAX_LOCAL_ERASURE_BUNDLE_CREDENTIAL_BYTES: usize = 64 * 1024;

/// The three credentials a key-less root's credential directory holds,
/// sorted.
pub const KEYLESS_CREDENTIAL_NAMES: [&str; 3] = [
    LOCAL_ERASURE_BUNDLE_CREDENTIAL_NAME,
    LOCAL_ERASURE_BUNDLE_SIGNATURE_CREDENTIAL_NAME,
    deployment_trust::RELEASE_TRUST_CREDENTIAL_NAME,
];

/// The environment variable systemd names the unit's credential directory
/// in. Only a root's binary entry point reads it, through
/// [`LocalErasureTrustSourceV1::from_environment`].
pub const CREDENTIALS_DIRECTORY_VARIABLE: &str = "CREDENTIALS_DIRECTORY";

/// Closed, payload-free reasons a store's Local erasure authority cannot be
/// composed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LocalErasureLoadErrorV1 {
    /// The store cannot be opened or its erasure store identity cannot be
    /// read.
    StoreUnavailable,
    /// The store records an erasure store identity but the root has no
    /// credential directory.
    CredentialsMissing,
    /// The credential directory is not protected or does not hold exactly
    /// the expected credentials, or one of them is unreadable or over its
    /// bound.
    Credentials,
    /// The release anchor or the trust state store is unavailable.
    #[cfg(target_os = "linux")]
    Trust(deployment_trust::DeploymentTrustErrorV1),
    /// The store's Local Principal record cannot be read.
    Principal(local_principal::LocalPrincipalReadErrorV1),
    /// The store records no Local Principal.
    PrincipalMissing,
    /// The installed bundle keeps the Local erasure authority closed.
    #[cfg(target_os = "linux")]
    Composition(LocalErasureCompositionErrorV1),
    /// This target has no systemd credentials and no trust state store.
    #[cfg(not(target_os = "linux"))]
    PlatformUnsupported,
}

impl std::fmt::Display for LocalErasureLoadErrorV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::StoreUnavailable => formatter.write_str("the local erasure store cannot be read"),
            Self::CredentialsMissing => formatter.write_str(
                "the store records an erasure store identity but no credential directory is set",
            ),
            Self::Credentials => {
                formatter.write_str("the local erasure credentials are unavailable or invalid")
            }
            #[cfg(target_os = "linux")]
            Self::Trust(error) => std::fmt::Display::fmt(error, formatter),
            Self::Principal(error) => std::fmt::Display::fmt(error, formatter),
            Self::PrincipalMissing => formatter.write_str(
                "the store records no Local Principal; run provision-local-principal first",
            ),
            #[cfg(target_os = "linux")]
            Self::Composition(error) => std::fmt::Display::fmt(error, formatter),
            #[cfg(not(target_os = "linux"))]
            Self::PlatformUnsupported => {
                formatter.write_str("local erasure requires Linux systemd credentials")
            }
        }
    }
}

impl std::error::Error for LocalErasureLoadErrorV1 {}

/// Why a key-less root cannot open its store: the composition is refused,
/// or the host cannot recover the store under it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LocalErasureOpenErrorV1 {
    /// The store's erasure authority cannot be composed.
    Load(LocalErasureLoadErrorV1),
    /// The erasure host refuses the store under the composed authority.
    Host(ErasureHostErrorV1),
}

impl std::fmt::Display for LocalErasureOpenErrorV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Load(error) => std::fmt::Display::fmt(error, formatter),
            Self::Host(error) => std::fmt::Display::fmt(error, formatter),
        }
    }
}

impl std::error::Error for LocalErasureOpenErrorV1 {}

/// Where a key-less root reads its Local erasure trust inputs: its
/// credential directory, if any, and the deployment trust state store.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalErasureTrustSourceV1 {
    /// The unit's systemd credential directory, `None` when unset.
    pub credential_directory: Option<PathBuf>,
    /// The deployment trust state store.
    pub trust_state: PathBuf,
}

impl LocalErasureTrustSourceV1 {
    /// The deployment source: `credential_directory` and the fixed
    /// [`deployment_trust::DEPLOYMENT_TRUST_STATE_PATH`].
    #[must_use]
    pub fn deployment(credential_directory: Option<PathBuf>) -> Self {
        Self {
            credential_directory,
            trust_state: PathBuf::from(deployment_trust::DEPLOYMENT_TRUST_STATE_PATH),
        }
    }

    /// The deployment source of this process: the directory its
    /// [`CREDENTIALS_DIRECTORY_VARIABLE`] names, if set.
    #[must_use]
    pub fn from_environment() -> Self {
        Self::deployment(std::env::var_os(CREDENTIALS_DIRECTORY_VARIABLE).map(PathBuf::from))
    }
}

/// The verification-and-recovery composition of a key-less root.
pub struct LocalErasureRecoveryV1;

impl LocalErasureRecoveryV1 {
    /// The erasure authority a key-less root opens `store` with.
    ///
    /// That is the closed composition when the store records no erasure
    /// store identity, else the Local erasure authority with no executor,
    /// from `source`.
    ///
    /// # Errors
    /// Returns the [`LocalErasureLoadErrorV1`] that refuses a store with an
    /// erasure store identity; it never falls back to the closed
    /// composition.
    pub fn for_store<S>(
        store: &mut S,
        source: &LocalErasureTrustSourceV1,
    ) -> Result<ErasureCoordinatorCompositionV1, LocalErasureLoadErrorV1>
    where
        S: ErasureInventoryPersistencePortV1
            + ErasurePersistencePortV1
            + EventStore
            + AuthorityPersistencePortV1
            + ?Sized,
    {
        store
            .erasure_store_identity()
            .ok()
            .ok_or(LocalErasureLoadErrorV1::StoreUnavailable)
            .and_then(|identity| {
                identity.map_or_else(
                    || Ok(ErasureCoordinatorCompositionV1::closed()),
                    |_| recovered(store, source),
                )
            })
    }

    /// [`Self::for_store`] over the store `config` names: a Memory store
    /// records no identity and composes the closed authority; a `SQLite`
    /// file is opened read-write.
    ///
    /// # Errors
    /// Returns [`LocalErasureLoadErrorV1::StoreUnavailable`] when the file
    /// cannot be opened, else the [`Self::for_store`] refusals.
    pub fn for_config(
        config: &StoreConfig,
        source: &LocalErasureTrustSourceV1,
    ) -> Result<ErasureCoordinatorCompositionV1, LocalErasureLoadErrorV1> {
        match config {
            StoreConfig::Sqlite { path } => SqliteStore::open(path)
                .ok()
                .ok_or(LocalErasureLoadErrorV1::StoreUnavailable)
                .and_then(|mut store| Self::for_store(&mut store, source)),
            StoreConfig::Memory | StoreConfig::SqliteInMemory => {
                Ok(ErasureCoordinatorCompositionV1::closed())
            }
        }
    }

    /// [`Self::for_store`] over the `SQLite` file `path`, opened read-only.
    ///
    /// # Errors
    /// Returns [`LocalErasureLoadErrorV1::StoreUnavailable`] when the file
    /// cannot be opened, else the [`Self::for_store`] refusals.
    pub fn for_read_only(
        path: &str,
        source: &LocalErasureTrustSourceV1,
    ) -> Result<ErasureCoordinatorCompositionV1, LocalErasureLoadErrorV1> {
        SqliteStore::open_read_only(path)
            .ok()
            .ok_or(LocalErasureLoadErrorV1::StoreUnavailable)
            .and_then(|mut store| Self::for_store(&mut store, source))
    }

    /// Open the store `config` names the way every key-less root does.
    ///
    /// It composes the store's authority ([`Self::for_config`]), then
    /// recovers the erasure host under it with the compiled recovery limits.
    ///
    /// # Errors
    /// Returns [`LocalErasureOpenErrorV1::Load`] for a refused composition
    /// and [`LocalErasureOpenErrorV1::Host`] when the host refuses the
    /// store.
    pub fn open_host(
        config: StoreConfig,
        source: &LocalErasureTrustSourceV1,
    ) -> Result<ErasureExecutionHostV1, LocalErasureOpenErrorV1> {
        Self::for_config(&config, source)
            .map_err(LocalErasureOpenErrorV1::Load)
            .and_then(|composition| {
                ErasureExecutionHostV1::open_with_authority(
                    config,
                    &composition,
                    ErasureRecoveryLimitsV1::compiled_maximum(),
                )
                .map_err(LocalErasureOpenErrorV1::Host)
            })
    }

    /// [`Self::open_host`] over the `SQLite` file `path`, read-only: the
    /// composition reads a read-only handle ([`Self::for_read_only`]).
    ///
    /// # Errors
    /// Returns the [`Self::open_host`] refusals.
    pub fn open_read_only_host(
        path: &str,
        source: &LocalErasureTrustSourceV1,
    ) -> Result<ErasureExecutionHostV1, LocalErasureOpenErrorV1> {
        Self::for_read_only(path, source)
            .map_err(LocalErasureOpenErrorV1::Load)
            .and_then(|composition| {
                ErasureExecutionHostV1::open_read_only_with_authority(
                    path,
                    &composition,
                    ErasureRecoveryLimitsV1::compiled_maximum(),
                )
                .map_err(LocalErasureOpenErrorV1::Host)
            })
    }
}

/// The Local erasure authority of a store that records an erasure store
/// identity, with no executor; off Linux, the refusal.
fn recovered<S>(
    store: &mut S,
    source: &LocalErasureTrustSourceV1,
) -> Result<ErasureCoordinatorCompositionV1, LocalErasureLoadErrorV1>
where
    S: ErasureInventoryPersistencePortV1
        + ErasurePersistencePortV1
        + EventStore
        + AuthorityPersistencePortV1
        + ?Sized,
{
    #[cfg(target_os = "linux")]
    {
        source
            .credential_directory
            .as_deref()
            .ok_or(LocalErasureLoadErrorV1::CredentialsMissing)
            .and_then(|directory| {
                credentials::open_exact_credentials(
                    directory,
                    &KEYLESS_CREDENTIAL_NAMES,
                    rustix::process::geteuid().as_raw(),
                )
                .ok()
                .ok_or(LocalErasureLoadErrorV1::Credentials)
            })
            .and_then(|credentials| composition::LocalErasureTrustCredentialsV1::read(&credentials))
            .and_then(|trust| {
                composition::compose_local_erasure(
                    store,
                    &composition::LocalErasureLoadInputsV1 {
                        bundle: &trust.bundle,
                        bundle_signature: &trust.bundle_signature,
                        trust_state: &source.trust_state,
                        execution_binding: None,
                    },
                    trust.release,
                )
            })
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (store, source);
        Err(LocalErasureLoadErrorV1::PlatformUnsupported)
    }
}

/// The current Unix second (UTC); a clock before the epoch reads as the
/// largest second, so it fails closed against every TPS1 and bundle expiry.
#[must_use]
pub fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(u64::MAX, |elapsed| elapsed.as_secs())
}

#[cfg(target_os = "linux")]
#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
#[path = "../tests/support/signing.rs"]
pub mod signing_fixture;

#[cfg(target_os = "linux")]
#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use std::path::Path;

    use pos_core::Hash;
    use pos_store::trust_policy_registry::TrustPolicyRegistryErrorV1;

    use super::deployment_trust::{
        DeploymentTrustErrorV1, DEPLOYMENT_TRUST_STATE_PATH, RELEASE_TRUST_CREDENTIAL_NAME,
    };
    use super::signing_fixture::{credential_directory, Deployment, TestResult};
    use super::*;

    /// A store file in `directory`.
    fn store_path(directory: &Path) -> TestResult<String> {
        Ok(directory
            .join("store.db")
            .to_str()
            .ok_or("temporary path is not UTF-8")?
            .to_owned())
    }

    /// A `SQLite` store at `path` that records an erasure store identity.
    fn identified(path: &str) -> TestResult<SqliteStore> {
        let mut store = SqliteStore::open(path)?;
        store.init_erasure_store_identity(Hash::from_bytes([0x5a; 32]))?;
        Ok(store)
    }

    /// The source of the credential directory `directory` and the trust
    /// state store `trust_state`.
    fn source(directory: Option<&Path>, trust_state: &Path) -> LocalErasureTrustSourceV1 {
        LocalErasureTrustSourceV1 {
            credential_directory: directory.map(Path::to_path_buf),
            trust_state: trust_state.to_path_buf(),
        }
    }

    /// The refusal of composing `store` from `source`, if any.
    fn refused(
        store: &mut SqliteStore,
        source: &LocalErasureTrustSourceV1,
    ) -> Option<LocalErasureLoadErrorV1> {
        LocalErasureRecoveryV1::for_store(store, source).err()
    }

    #[test]
    fn a_store_without_an_identity_composes_the_closed_authority() -> TestResult {
        let directory = tempfile::tempdir()?;
        let none = source(None, &directory.path().join("absent-trust.db"));
        for config in [StoreConfig::Memory, StoreConfig::SqliteInMemory] {
            assert!(LocalErasureRecoveryV1::for_config(&config, &none).is_ok());
        }
        let path = store_path(directory.path())?;
        let config = StoreConfig::Sqlite { path: path.clone() };
        assert!(LocalErasureRecoveryV1::for_config(&config, &none).is_ok());
        assert!(LocalErasureRecoveryV1::for_read_only(&path, &none).is_ok());
        Ok(())
    }

    #[test]
    fn a_store_without_an_identity_opens_under_the_closed_authority() -> TestResult {
        let directory = tempfile::tempdir()?;
        let none = source(None, &directory.path().join("absent-trust.db"));
        assert!(LocalErasureRecoveryV1::open_host(StoreConfig::Memory, &none).is_ok());
        let path = store_path(directory.path())?;
        let config = StoreConfig::Sqlite { path: path.clone() };
        assert!(LocalErasureRecoveryV1::open_host(config, &none).is_ok());
        assert!(LocalErasureRecoveryV1::open_read_only_host(&path, &none).is_ok());
        drop(identified(&path)?);
        let config = StoreConfig::Sqlite { path: path.clone() };
        for refusal in [
            LocalErasureRecoveryV1::open_host(config, &none).err(),
            LocalErasureRecoveryV1::open_read_only_host(&path, &none).err(),
        ] {
            assert_eq!(
                refusal,
                Some(LocalErasureOpenErrorV1::Load(
                    LocalErasureLoadErrorV1::CredentialsMissing
                ))
            );
        }
        for (error, message) in [
            (
                LocalErasureOpenErrorV1::Load(LocalErasureLoadErrorV1::StoreUnavailable),
                LocalErasureLoadErrorV1::StoreUnavailable.to_string(),
            ),
            (
                LocalErasureOpenErrorV1::Host(ErasureHostErrorV1::RecoveryUnavailable),
                ErasureHostErrorV1::RecoveryUnavailable.to_string(),
            ),
        ] {
            assert_eq!(error.to_string(), message);
        }
        Ok(())
    }

    #[test]
    fn an_unreadable_store_is_unavailable() -> TestResult {
        let directory = tempfile::tempdir()?;
        let none = source(None, &directory.path().join("absent-trust.db"));
        let absent = directory.path().join("absent").join("store.db");
        let absent = absent.to_str().ok_or("temporary path is not UTF-8")?;
        let config = StoreConfig::Sqlite {
            path: absent.to_owned(),
        };
        for refusal in [
            LocalErasureRecoveryV1::for_config(&config, &none).err(),
            LocalErasureRecoveryV1::for_read_only(absent, &none).err(),
        ] {
            assert_eq!(refusal, Some(LocalErasureLoadErrorV1::StoreUnavailable));
        }
        let path = store_path(directory.path())?;
        let mut store = identified(&path)?;
        rusqlite::Connection::open(&path)?.execute("DROP TABLE erasure_store_identity", [])?;
        assert_eq!(
            refused(&mut store, &none),
            Some(LocalErasureLoadErrorV1::StoreUnavailable)
        );
        Ok(())
    }

    /// An identified store never falls back to the closed authority: without
    /// a credential directory, or with one that does not hold exactly the
    /// three credentials, it is refused.
    #[test]
    fn an_identified_store_without_its_credentials_fails_closed() -> TestResult {
        let directory = tempfile::tempdir()?;
        let trust_state = directory.path().join("absent-trust.db");
        let mut store = identified(&store_path(directory.path())?)?;
        assert_eq!(
            refused(&mut store, &source(None, &trust_state)),
            Some(LocalErasureLoadErrorV1::CredentialsMissing)
        );
        let partial = credential_directory(
            &directory.path().join("partial"),
            &[(LOCAL_ERASURE_BUNDLE_CREDENTIAL_NAME, b"elb1".as_slice())],
        )?;
        for credentials in [directory.path().join("missing"), partial] {
            assert_eq!(
                refused(&mut store, &source(Some(&credentials), &trust_state)),
                Some(LocalErasureLoadErrorV1::Credentials)
            );
        }
        Ok(())
    }

    /// The trust inputs of an identified store refuse it with their typed
    /// errors, in order: the bundle bounds, the release anchor, the trust
    /// state store, then the Local Principal.
    #[test]
    fn each_trust_input_of_an_identified_store_is_a_typed_refusal() -> TestResult {
        let directory = tempfile::tempdir()?;
        let deployment = Deployment::new(&[])?;
        let mut store = identified(&store_path(directory.path())?)?;
        let at_bound = vec![0x5a; MAX_LOCAL_ERASURE_BUNDLE_CREDENTIAL_BYTES];
        let over_bound = vec![0x5a; MAX_LOCAL_ERASURE_BUNDLE_CREDENTIAL_BYTES + 1];
        let cases: [(&str, &[u8], &[u8], LocalErasureLoadErrorV1); 3] = [
            (
                "over-bound",
                &over_bound,
                deployment.release.as_bytes(),
                LocalErasureLoadErrorV1::Credentials,
            ),
            (
                "release",
                &at_bound,
                b"policy_id = 1",
                LocalErasureLoadErrorV1::Trust(DeploymentTrustErrorV1::ReleaseTrustInvalid),
            ),
            (
                "unprovisioned",
                &at_bound,
                deployment.release.as_bytes(),
                LocalErasureLoadErrorV1::PrincipalMissing,
            ),
        ];
        for (name, bundle, release, error) in cases {
            let credentials = credential_directory(
                &directory.path().join(name),
                &[
                    (LOCAL_ERASURE_BUNDLE_CREDENTIAL_NAME, bundle),
                    (
                        LOCAL_ERASURE_BUNDLE_SIGNATURE_CREDENTIAL_NAME,
                        b"elb1s".as_slice(),
                    ),
                    (RELEASE_TRUST_CREDENTIAL_NAME, release),
                ],
            )?;
            assert_eq!(
                refused(&mut store, &source(Some(&credentials), &deployment.state)),
                Some(error),
                "{name}"
            );
        }
        let credentials = directory.path().join("unprovisioned");
        assert_eq!(
            refused(
                &mut store,
                &source(
                    Some(&credentials),
                    &directory.path().join("absent-trust.db")
                )
            ),
            Some(LocalErasureLoadErrorV1::Trust(
                DeploymentTrustErrorV1::TrustState(TrustPolicyRegistryErrorV1::MissingState)
            ))
        );
        Ok(())
    }

    #[test]
    fn the_deployment_source_reads_the_fixed_trust_state_store() {
        let deployment = LocalErasureTrustSourceV1::deployment(None);
        assert_eq!(
            deployment.trust_state,
            Path::new(DEPLOYMENT_TRUST_STATE_PATH)
        );
        assert_eq!(deployment.credential_directory, None);
        // Only read, never set: the variable is process-global.
        let environment = LocalErasureTrustSourceV1::from_environment();
        assert_eq!(
            environment.credential_directory,
            std::env::var_os(CREDENTIALS_DIRECTORY_VARIABLE).map(PathBuf::from)
        );
        assert_eq!(environment.trust_state, deployment.trust_state);
    }

    #[test]
    fn the_unix_clock_reads_the_present() {
        let now = unix_now();
        assert!(now > 1_700_000_000 && now < 4_000_000_000, "{now}");
    }

    #[test]
    fn each_refusal_reads_as_its_payload_free_message() {
        let corrupt = local_principal::LocalPrincipalReadErrorV1::Corrupt;
        for (error, message) in [
            (
                LocalErasureLoadErrorV1::StoreUnavailable,
                "the local erasure store cannot be read".to_owned(),
            ),
            (
                LocalErasureLoadErrorV1::CredentialsMissing,
                "the store records an erasure store identity but no credential directory is set"
                    .to_owned(),
            ),
            (
                LocalErasureLoadErrorV1::Credentials,
                "the local erasure credentials are unavailable or invalid".to_owned(),
            ),
            (
                LocalErasureLoadErrorV1::Trust(DeploymentTrustErrorV1::ReleaseTrustInvalid),
                "the release trust credential is invalid".to_owned(),
            ),
            (
                LocalErasureLoadErrorV1::Principal(corrupt),
                corrupt.to_string(),
            ),
            (
                LocalErasureLoadErrorV1::PrincipalMissing,
                "the store records no Local Principal; run provision-local-principal first"
                    .to_owned(),
            ),
            (
                LocalErasureLoadErrorV1::Composition(LocalErasureCompositionErrorV1::BundleInvalid),
                "local erasure bundle is invalid".to_owned(),
            ),
        ] {
            assert_eq!(error.to_string(), message);
        }
    }
}
