//! Test-only key-less root store fixture (#1450, ADR-136 acceptance test
//! 11): a Gateway `SQLite` store provisioned the way an operator provisions
//! one, holding one Local erasure request, and the credential directories a
//! key-less root reads.
//!
//! The store is bound to the Local execution mode, its Local Principal is
//! provisioned with the production `provision_on_host`, the production
//! `provision_local_erasure` registers the fixture signer and builds the
//! bundle, and the fixture `erasure-bundle/` root signs it. The Gateway's
//! own `serve --require-local-erasure` composition then admits one erasure
//! request, so the store records an erasure store identity and a request the
//! closed composition cannot recover. Only the keys and the Principal are
//! fixture data; the signing fixtures are the shared `signing.rs`, which
//! every includer declares beside this file as `signing`.

use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::path::PathBuf;

use piglor_gateway::local_erasure_composition::{LocalErasureServeInputsV1, LocalErasureServeV1};
use piglor_gateway::local_erasure_provision::{
    provision_local_erasure, LocalErasureProvisionRequestV1, LOCAL_ERASURE_SIGNER_CREDENTIAL_NAME,
};
use piglor_gateway::local_principal::{provision_on_host, LocalPrincipalProvisionV1};
use piglor_gateway::mode_profile::{
    bind_gateway_mode_v1, GatewayModeProfileIdV1, GatewayServeCompositionV1,
};
use piglor_gateway::startup::{open_recovered_erasure_host, GatewayHostStoreV1};
use piglor_gateway::GatewayOperationV1;
use pos_core::{EntityId, ErasureReferenceV1, ErasureScopeV1, PrincipalRefV1};
use pos_local_erasure_loader::deployment_trust::RELEASE_TRUST_CREDENTIAL_NAME;
use pos_local_erasure_loader::{
    LocalErasureTrustSourceV1, LOCAL_ERASURE_BUNDLE_CREDENTIAL_NAME,
    LOCAL_ERASURE_BUNDLE_SIGNATURE_CREDENTIAL_NAME,
};
use pos_runtime::{
    ErasureCoordinatorCompositionV1, ErasureExecutionHostV1, LocalErasureSignerRotationV1,
    LocalErasureSubmissionV1,
};
use pos_store::StoreConfig;

use super::signing::{
    bundle_root, credential_directory, signed, signer, unprefixed_root, Deployment, TestResult,
    BUNDLE_ROOT, SIGNER_OWNER, SIGNER_SEED,
};

/// The provisioning clock: before the fixture TPS1 expires.
const PROVISIONED_AT: u64 = 1_800_000_000;

/// The fixture Local Principal.
fn principal() -> TestResult<PrincipalRefV1> {
    Ok(PrincipalRefV1::try_new([0x31; 16], "local")?)
}

/// The fixture actor, whose subject the held request erases.
fn actor() -> EntityId {
    EntityId::from_ulid(ulid::Ulid::from_bytes([0x32; 16]))
}

/// Bind the store of `host` to the Local execution mode over a loopback
/// composition, as every `serve` does: the first binds the empty store, a
/// later one attaches to that binding.
fn bind_local(host: &mut ErasureExecutionHostV1) -> TestResult {
    bind_gateway_mode_v1(
        GatewayModeProfileIdV1::Local,
        GatewayServeCompositionV1 {
            tcp_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
            owntracks_owner_key: None,
            fork_admission_socket: None,
            ledger_source: None,
            network_grants: BTreeSet::new(),
        },
        host,
    )?;
    Ok(())
}

/// A provisioned Gateway store that holds one Local erasure request.
pub struct KeylessStore {
    /// The fixture's files; removed on drop.
    pub directory: tempfile::TempDir,
    /// The store file.
    pub path: String,
    /// The deployment trust state store and release anchor.
    pub deployment: Deployment,
    /// The installed ELB1.
    pub bundle: Vec<u8>,
    /// The ELB1S of the fixture bundle root over it.
    pub signature: Vec<u8>,
    /// The held request.
    pub request: ErasureReferenceV1,
}

impl KeylessStore {
    /// Provision the store and admit its one request.
    ///
    /// # Errors
    /// Returns an error when a provisioning step fails.
    pub fn new() -> TestResult<Self> {
        let directory = tempfile::tempdir()?;
        let path = directory
            .path()
            .join("gateway.db")
            .to_str()
            .ok_or("temporary path is not UTF-8")?
            .to_owned();
        let mut host = Self::host(&path, &ErasureCoordinatorCompositionV1::closed())?;
        bind_local(&mut host)?;
        let provision = LocalPrincipalProvisionV1::try_new(
            &principal()?,
            [actor()],
            [
                GatewayOperationV1::CREATE_TIMELINE,
                GatewayOperationV1::REQUEST_ERASURE,
            ],
        )?;
        provision_on_host(&mut host, &provision)?;
        drop(host);
        let deployment = Deployment::new(&[])?;
        let bundle = provision_local_erasure(
            &LocalErasureProvisionRequestV1 {
                sqlite_path: path.clone(),
                out: directory.path().join("bundle.elb1"),
                issued_by: BUNDLE_ROOT.to_owned(),
                expiry: 0,
                signer_owner: SIGNER_OWNER.to_owned(),
                signer_epoch: 1,
                rotation: LocalErasureSignerRotationV1::Routine,
            },
            &signer(SIGNER_SEED),
            &deployment.trust()?,
            PROVISIONED_AT,
        )?;
        let signature = signed(&bundle, &bundle_root())?;
        let mut store = Self {
            directory,
            path,
            deployment,
            bundle,
            signature,
            request: ErasureReferenceV1::from_digest([0; 32]),
        };
        store.request = store.hold()?;
        Ok(store)
    }

    /// The recovered Gateway host of the store at `path` under
    /// `composition`.
    fn host(
        path: &str,
        composition: &ErasureCoordinatorCompositionV1,
    ) -> TestResult<ErasureExecutionHostV1> {
        Ok(open_recovered_erasure_host(
            StoreConfig::Sqlite {
                path: path.to_owned(),
            },
            GatewayHostStoreV1::Standard,
            composition,
        )?)
    }

    /// Admit one erasure of the fixture actor's subject through the
    /// Gateway's serve composition, and return its request.
    fn hold(&self) -> TestResult<ErasureReferenceV1> {
        let credentials = credential_directory(
            &self.directory.path().join("serve-credentials"),
            &[
                (LOCAL_ERASURE_BUNDLE_CREDENTIAL_NAME, self.bundle.as_slice()),
                (
                    LOCAL_ERASURE_BUNDLE_SIGNATURE_CREDENTIAL_NAME,
                    self.signature.as_slice(),
                ),
                (LOCAL_ERASURE_SIGNER_CREDENTIAL_NAME, SIGNER_SEED.as_slice()),
                (
                    RELEASE_TRUST_CREDENTIAL_NAME,
                    self.deployment.release.as_bytes(),
                ),
            ],
        )?;
        let serve = LocalErasureServeV1::for_serve(Some(LocalErasureServeInputsV1 {
            sqlite_path: &self.path,
            credential_directory: &credentials,
            trust_state: &self.deployment.state,
            with_fork_authority: false,
        }))?;
        let mut host = Self::host(&self.path, serve.composition())?;
        bind_local(&mut host)?;
        host.command_sender()?
            .create_owned_timeline("owned", actor())?;
        let admitted = host
            .command_sender()?
            .submit_local_erasure(&LocalErasureSubmissionV1 {
                principal: principal()?,
                actor: actor(),
                scope: ErasureScopeV1::PrivateSubjectData,
                idempotency_key_digest: ErasureReferenceV1::from_digest([0x11; 32]),
                mode_profile: ErasureReferenceV1::from_digest([0x12; 32]),
                binding_epoch: 1,
            })
            .map_err(|error| format!("{error:?}"))?;
        Ok(admitted.state.request())
    }

    /// The store's configuration.
    #[must_use]
    pub fn config(&self) -> StoreConfig {
        StoreConfig::Sqlite {
            path: self.path.clone(),
        }
    }

    /// A key-less root's source with the credential directory `name`
    /// holding exactly `bundle`, `signature` and the release anchor.
    ///
    /// # Errors
    /// Returns an error when the directory cannot be written.
    pub fn source_with(
        &self,
        name: &str,
        bundle: &[u8],
        signature: &[u8],
    ) -> TestResult<LocalErasureTrustSourceV1> {
        let credentials = credential_directory(
            &self.directory.path().join(name),
            &[
                (LOCAL_ERASURE_BUNDLE_CREDENTIAL_NAME, bundle),
                (LOCAL_ERASURE_BUNDLE_SIGNATURE_CREDENTIAL_NAME, signature),
                (
                    RELEASE_TRUST_CREDENTIAL_NAME,
                    self.deployment.release.as_bytes(),
                ),
            ],
        )?;
        Ok(self.source(Some(credentials)))
    }

    /// A key-less root's source with the valid credentials in the directory
    /// `name`.
    ///
    /// # Errors
    /// Returns an error when the directory cannot be written.
    pub fn valid_source(&self, name: &str) -> TestResult<LocalErasureTrustSourceV1> {
        self.source_with(name, &self.bundle, &self.signature)
    }

    /// A key-less root's source with no credential directory.
    #[must_use]
    pub fn missing_source(&self) -> LocalErasureTrustSourceV1 {
        self.source(None)
    }

    /// A key-less root's source whose bundle is not an ELB1, in the
    /// directory `name`.
    ///
    /// # Errors
    /// Returns an error when the directory cannot be written.
    pub fn invalid_bundle_source(&self, name: &str) -> TestResult<LocalErasureTrustSourceV1> {
        self.source_with(name, b"not an ELB1", &self.signature)
    }

    /// A key-less root's source whose ELB1S another root signed, in the
    /// directory `name`.
    ///
    /// # Errors
    /// Returns an error when the directory cannot be written.
    pub fn forged_signature_source(&self, name: &str) -> TestResult<LocalErasureTrustSourceV1> {
        let forged = signed(&self.bundle, &unprefixed_root())?;
        self.source_with(name, &self.bundle, &forged)
    }

    /// The source of `credential_directory` and this deployment's trust
    /// state store.
    fn source(&self, credential_directory: Option<PathBuf>) -> LocalErasureTrustSourceV1 {
        LocalErasureTrustSourceV1 {
            credential_directory,
            trust_state: self.deployment.state.clone(),
        }
    }
}
