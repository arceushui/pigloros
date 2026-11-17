use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::PathBuf;

use ed25519_dalek::{Signer as _, SigningKey};
use pos_conformance::{TrustPolicyRootV1, TrustPolicySnapshotV1};
use pos_core::{
    local_erasure_bundle_signing_message_v1, local_erasure_host_timeline_v1,
    local_erasure_signer_key_id_v1, ErasureInventoryPersistencePortV1, ErasureRecoveryLimitsV1,
    ErasureReferenceV1, EventStore, KeyIdentityV1, KeyRoleV1, LocalErasureBundleSignatureV1,
    LocalErasureBundleV1, OwnerIdV1, TimelineId,
};
use pos_crypto::key_roles::SigningKeyMaterial;
use pos_runtime::{
    local_erasure_execution_binding_v1, ErasureCoordinatorCompositionV1,
    LocalErasureCompositionErrorV1, LocalErasureCompositionInputsV1,
    LOCAL_ERASURE_POLICY_REFERENCE_V1,
};
use pos_store::sqlite::SqliteStore;
use pos_store::trust_policy_registry::{
    CurrentTrustPolicyV1, DeploymentTrustPolicyRegistryV1, OperatorReleaseTrustV1,
};
use pos_store::StoreConfig;

use super::{
    provision_local_erasure, provision_local_erasure_from_credentials,
    LocalErasureProvisionErrorV1, LocalErasureProvisionRequestV1,
    LOCAL_ERASURE_SIGNER_CREDENTIAL_NAME,
};
use crate::deployment_trust::{
    load_deployment_trust_v1, release_trust_from_credential, RELEASE_TRUST_CREDENTIAL_NAME,
};
use crate::local_principal::{
    local_principal_authority_timeline, local_principal_consent_timeline, local_principal_grant_id,
    provision_on_host, recorded_registry_digest, LocalPrincipalProvisionV1,
};
use crate::mode_profile::{bind_test_store, GatewayModeProfileIdV1, GatewayModeStoreLockV1};
use crate::startup::{open_recovered_erasure_host, GatewayHostStoreV1};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const BUNDLE_ROOT: &str = "erasure-bundle/local";
const UNPREFIXED_ROOT: &str = "local-root";
const SIGNER_OWNER: &str = "pigloros.local-erasure-signer";
const SIGNER_SEED: [u8; 32] = [0x64; 32];
const ROTATED_SEED: [u8; 32] = [0x65; 32];
const PRINCIPAL: &str = "principal_id = \"01JC0GATEWAYQ0CA1PR1NC1PA1\"\n\
    trust_domain = \"local\"\n\
    actor_entity_ids = [\"01JC0GATEWAYQ0CA1ACT0R0000\"]\n\
    operations = [\"timeline.create\"]\n";

fn operator() -> SigningKey {
    SigningKey::from_bytes(&[0x61; 32])
}

fn bundle_root() -> SigningKey {
    SigningKey::from_bytes(&[0x62; 32])
}

fn unprefixed_root() -> SigningKey {
    SigningKey::from_bytes(&[0x63; 32])
}

fn signer(seed: [u8; 32]) -> SigningKeyMaterial {
    SigningKeyMaterial::new(SigningKey::from_bytes(&seed))
}

fn signer_key_id(seed: [u8; 32]) -> String {
    local_erasure_signer_key_id_v1(&SigningKey::from_bytes(&seed).verifying_key().to_bytes())
}

fn hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .flat_map(|byte| {
            [byte >> 4, byte & 0x0f]
                .map(|nibble| char::from_digit(u32::from(nibble), 16).unwrap_or_default())
        })
        .collect()
}

fn root(key_id: &str, key: &SigningKey) -> TrustPolicyRootV1 {
    TrustPolicyRootV1 {
        key_id: key_id.to_owned(),
        root_version: 1,
        algorithm: "Ed25519".to_owned(),
        public_key: key.verifying_key().to_bytes(),
    }
}

/// A provisioned deployment trust state store and its release anchor
/// credential.
struct Deployment {
    _directory: tempfile::TempDir,
    state: PathBuf,
    release: String,
}

impl Deployment {
    /// A genesis TPS1 whose roots are an `erasure-bundle/` root and an
    /// unprefixed root and which revokes `revoked` (sorted).
    fn new(revoked: &[&str]) -> TestResult<Self> {
        let draft = pos_conformance::draft_trust_policy_snapshot_bytes_v1()?;
        let mut snapshot = TrustPolicySnapshotV1::from_canonical_cbor(&draft)?;
        snapshot.trust_roots = vec![
            root(BUNDLE_ROOT, &bundle_root()),
            root(UNPREFIXED_ROOT, &unprefixed_root()),
        ];
        snapshot.revoked_key_ids = revoked.iter().map(|id| (*id).to_owned()).collect();
        "9999-12-31T23:59:59Z".clone_into(&mut snapshot.offline_valid_through);
        let message = snapshot.operator_signature_message_v1()?;
        snapshot.operator_signature = operator().sign(&message).to_bytes();
        let genesis = snapshot.to_canonical_cbor()?;
        let digest = *blake3::hash(&genesis).as_bytes();
        let operator_key = operator().verifying_key().to_bytes();
        let release = OperatorReleaseTrustV1::new(snapshot.policy_id.clone(), operator_key, digest);
        let directory = tempfile::tempdir()?;
        let state = directory.path().join("trust-state.db");
        DeploymentTrustPolicyRegistryV1::provision_explicit(&state, &release, &genesis)?;
        Ok(Self {
            release: format!(
                "policy_id = \"{}\"\noperator_public_key = \"{}\"\ngenesis_digest = \"{}\"\n",
                snapshot.policy_id,
                hex(&operator_key),
                hex(&digest)
            ),
            state,
            _directory: directory,
        })
    }

    fn trust(&self) -> TestResult<CurrentTrustPolicyV1> {
        let release = release_trust_from_credential(self.release.as_bytes())?;
        Ok(load_deployment_trust_v1(&self.state, release)?)
    }
}

/// A Gateway store bound to the Local mode, with or without its Local
/// Principal.
struct Fixture {
    directory: tempfile::TempDir,
    path: String,
}

impl Fixture {
    fn new(principal: bool) -> TestResult<Self> {
        let directory = tempfile::tempdir()?;
        let path = directory
            .path()
            .join("gateway.db")
            .to_str()
            .ok_or("temporary path is not UTF-8")?
            .to_owned();
        bind_test_store(
            &mut SqliteStore::open(&path)?,
            GatewayModeProfileIdV1::Local,
        )?;
        if principal {
            let provision = LocalPrincipalProvisionV1::from_toml(PRINCIPAL)?;
            let mut host = open_recovered_erasure_host(
                StoreConfig::Sqlite { path: path.clone() },
                GatewayHostStoreV1::Standard,
                &ErasureCoordinatorCompositionV1::closed(),
            )?;
            provision_on_host(&mut host, &provision)?;
        }
        Ok(Self { directory, path })
    }

    fn request(&self, out: &str) -> LocalErasureProvisionRequestV1 {
        LocalErasureProvisionRequestV1 {
            sqlite_path: self.path.clone(),
            out: self.directory.path().join(out),
            issued_by: BUNDLE_ROOT.to_owned(),
            expiry: 0,
            signer_owner: SIGNER_OWNER.to_owned(),
            signer_epoch: 1,
        }
    }

    /// A protected credential directory `directory` holding `credentials`.
    fn credentials(&self, directory: &str, credentials: &[(&str, &[u8])]) -> TestResult<PathBuf> {
        let directory = self.directory.path().join(directory);
        std::fs::create_dir(&directory)?;
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700))?;
        for (name, bytes) in credentials {
            let credential = directory.join(name);
            std::fs::write(&credential, bytes)?;
            std::fs::set_permissions(&credential, std::fs::Permissions::from_mode(0o400))?;
        }
        Ok(directory)
    }

    fn store_identity(&self) -> TestResult<Option<pos_core::Hash>> {
        Ok(SqliteStore::open(&self.path)?.erasure_store_identity()?)
    }

    /// The public key the key registry holds for the signer at `epoch`.
    fn registered_signer(&self, epoch: u64) -> TestResult<Option<[u8; 32]>> {
        let identity = KeyIdentityV1::from_parts(
            OwnerIdV1::new(SIGNER_OWNER)?,
            KeyRoleV1::TimelineIntegritySigning,
            epoch,
        );
        Ok(SqliteStore::open(&self.path)?
            .load_key_registry()?
            .and_then(|registry| registry.key_record(identity))
            .and_then(|record| record.public_verification_key)
            .map(|key| *key.as_bytes()))
    }

    fn holds_timeline(&self, timeline: TimelineId) -> TestResult<bool> {
        Ok(SqliteStore::open(&self.path)?
            .erasure_authority_snapshot_with_limits(ErasureRecoveryLimitsV1::compiled_maximum())?
            .timeline(timeline)
            .is_some())
    }

    /// Sign `bundle` with the bundle root and compose the Local erasure
    /// root over this store with the binary's executor.
    fn compose(
        &self,
        deployment: &Deployment,
        bundle: &[u8],
    ) -> TestResult<Option<LocalErasureCompositionErrorV1>> {
        let reference = LocalErasureBundleV1::from_canonical_cbor(bundle)?.reference()?;
        let message = local_erasure_bundle_signing_message_v1(reference)?;
        let signature = LocalErasureBundleSignatureV1 {
            bundle: reference,
            admin_signature: bundle_root().sign(&message).to_bytes(),
        }
        .to_canonical_cbor()?;
        let mut store = SqliteStore::open(&self.path)?;
        let registry = recorded_registry_digest(&store)?.ok_or("no Local Principal")?;
        let trust = deployment.trust()?;
        let binding = local_erasure_execution_binding_v1();
        let operator_public_key = operator().verifying_key().to_bytes();
        Ok(ErasureCoordinatorCompositionV1::local(
            &LocalErasureCompositionInputsV1 {
                bundle,
                bundle_signature: &signature,
                trust: &trust,
                operator_public_key,
                authority_registry_digest: ErasureReferenceV1::from_digest(*registry.as_bytes()),
                execution_binding: Some(&binding),
                principal_grant: local_principal_grant_id(),
                authority_timeline: local_principal_authority_timeline(),
                clock: present,
            },
            &mut store,
        )
        .err())
    }
}

const fn present() -> u64 {
    1_800_000_000
}

fn args(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

fn refusal(result: std::io::Result<Vec<u8>>) -> Option<LocalErasureProvisionErrorV1> {
    result
        .err()
        .and_then(std::io::Error::into_inner)
        .and_then(|inner| inner.downcast::<LocalErasureProvisionErrorV1>().ok())
        .map(|refusal| *refusal)
}

#[test]
fn the_command_line_parses_its_flags_and_defaults() {
    let parsed = LocalErasureProvisionRequestV1::parse(&args(&[
        "/var/lib/pigloros/gateway.db",
        "--out",
        "/tmp/bundle.elb1",
        "--signer-owner",
        "signer",
        "--issued-by",
        "erasure-bundle/root",
    ]));
    assert_eq!(
        parsed,
        Ok(LocalErasureProvisionRequestV1 {
            sqlite_path: "/var/lib/pigloros/gateway.db".to_owned(),
            out: PathBuf::from("/tmp/bundle.elb1"),
            issued_by: "erasure-bundle/root".to_owned(),
            expiry: 0,
            signer_owner: "signer".to_owned(),
            signer_epoch: 1,
        })
    );
    let explicit = LocalErasureProvisionRequestV1::parse(&args(&[
        "db",
        "--issued-by",
        "erasure-bundle/root",
        "--expiry",
        "1900000000",
        "--signer-owner",
        "signer",
        "--signer-epoch",
        "2",
        "--out",
        "/bundle",
    ]));
    assert_eq!(
        explicit.map(|request| (request.expiry, request.signer_epoch)),
        Ok((1_900_000_000, 2))
    );
}

#[test]
fn a_malformed_command_line_is_a_usage_error() {
    // Each case changes one thing in a valid command line.
    let valid = [
        "db",
        "--out",
        "/o",
        "--issued-by",
        "r",
        "--signer-owner",
        "s",
    ];
    assert!(LocalErasureProvisionRequestV1::parse(&args(&valid)).is_ok());
    for invalid in [
        args(&[]),
        args(&valid[..1]),
        args(&valid[..2]),
        args(&valid[..5]),
        args(&["db", "--issued-by", "r", "--signer-owner", "s"]),
        args(&["db", "--out", "/o", "--signer-owner", "s"]),
        args(&[
            "db",
            "--out",
            "relative",
            "--issued-by",
            "r",
            "--signer-owner",
            "s",
        ]),
        args(&[
            "--db",
            "--out",
            "/o",
            "--issued-by",
            "r",
            "--signer-owner",
            "s",
        ]),
        args(&[valid.as_slice(), ["--other", "x"].as_slice()].concat()),
        args(&[valid.as_slice(), ["--out", "/p"].as_slice()].concat()),
        args(&[valid.as_slice(), ["--expiry", "-1"].as_slice()].concat()),
        args(&[valid.as_slice(), ["--signer-epoch", "x"].as_slice()].concat()),
    ] {
        assert_eq!(
            LocalErasureProvisionRequestV1::parse(&invalid),
            Err(LocalErasureProvisionErrorV1::Usage),
            "{invalid:?}"
        );
    }
}

/// #1429 acceptance: provision, sign with the TPS1 root, and `local()`
/// composes; an exact re-run emits the same bundle.
#[test]
fn a_provisioned_bundle_signed_by_its_root_composes() -> TestResult {
    let deployment = Deployment::new(&[])?;
    let fixture = Fixture::new(true)?;
    let credentials = fixture.credentials(
        "credentials",
        &[
            (LOCAL_ERASURE_SIGNER_CREDENTIAL_NAME, SIGNER_SEED.as_slice()),
            (RELEASE_TRUST_CREDENTIAL_NAME, deployment.release.as_bytes()),
        ],
    )?;
    let request = fixture.request("bundle.elb1");
    provision_local_erasure_from_credentials(&request, &credentials, &deployment.state)?;
    assert_eq!(std::fs::metadata(&request.out)?.mode() & 0o777, 0o600);
    let bytes = std::fs::read(&request.out)?;
    let bundle = LocalErasureBundleV1::from_canonical_cbor(&bytes)?;

    let identity = fixture.store_identity()?.ok_or("no store identity")?;
    let store_identity = ErasureReferenceV1::from_digest(*identity.as_bytes());
    let host_timeline = local_erasure_host_timeline_v1(store_identity)?;
    let mut host_timelines = vec![
        local_principal_consent_timeline(),
        host_timeline,
        local_principal_authority_timeline(),
    ];
    host_timelines.sort_unstable();
    let signer_public_key = SigningKey::from_bytes(&SIGNER_SEED)
        .verifying_key()
        .to_bytes();
    assert_eq!(
        bundle.tps1,
        ErasureReferenceV1::from_digest(deployment.trust()?.digest())
    );
    assert_eq!(bundle.store_identity, store_identity);
    assert_eq!(bundle.host_timelines, host_timelines);
    assert_eq!(bundle.policy, LOCAL_ERASURE_POLICY_REFERENCE_V1);
    assert_eq!(
        bundle
            .owners
            .iter()
            .map(|owner| (owner.category, owner.ack_class.as_str()))
            .collect::<Vec<_>>(),
        [
            (0, "artifact-store"),
            (0, "client-cache-signal"),
            (0, "export-recipient"),
            (0, "managed-report"),
            (0, "timeline-payload"),
            (1, "key-registry"),
            (2, "local-replica"),
            (3, "local-backup-inventory"),
        ]
    );
    assert_eq!(
        bundle.execution_binding,
        local_erasure_execution_binding_v1()
    );
    assert_eq!(bundle.signer_identity.owner_id, SIGNER_OWNER.as_bytes());
    assert_eq!(bundle.signer_identity.epoch, 1);
    assert_eq!(bundle.signer_public_key, signer_public_key);
    assert_eq!(bundle.signer_key_id, signer_key_id(SIGNER_SEED));
    assert_eq!(bundle.issued_by, BUNDLE_ROOT);
    assert_eq!(bundle.expiry, 0);
    assert!(fixture.holds_timeline(host_timeline)?);
    assert_eq!(fixture.registered_signer(1)?, Some(signer_public_key));
    assert_eq!(fixture.compose(&deployment, &bytes)?, None);

    // An exact re-run reuses the identity and the Erasure Host Timeline and
    // emits the same bundle; it never overwrites an existing file.
    let rerun = fixture.request("rerun.elb1");
    provision_local_erasure_from_credentials(&rerun, &credentials, &deployment.state)?;
    assert_eq!(std::fs::read(&rerun.out)?, bytes);
    assert_eq!(fixture.store_identity()?, Some(identity));
    let exists = provision_local_erasure_from_credentials(&rerun, &credentials, &deployment.state)
        .err()
        .ok_or("an existing --out file is refused")?;
    assert_eq!(exists.kind(), std::io::ErrorKind::AlreadyExists);
    assert_eq!(std::fs::read(&rerun.out)?, bytes);
    Ok(())
}

/// Owner decision Q15: a routine rotation re-runs provisioning with a new
/// credential at a higher epoch, through the raw store only.
#[test]
fn a_routine_rotation_registers_the_next_signer_epoch() -> TestResult {
    let deployment = Deployment::new(&[])?;
    let trust = deployment.trust()?;
    let fixture = Fixture::new(true)?;
    let first = provision_local_erasure(&fixture.request("a"), &signer(SIGNER_SEED), &trust)?;
    let mut rotation = fixture.request("b");
    rotation.signer_epoch = 2;
    let rotated = provision_local_erasure(&rotation, &signer(ROTATED_SEED), &trust)?;
    let first = LocalErasureBundleV1::from_canonical_cbor(&first)?;
    let decoded = LocalErasureBundleV1::from_canonical_cbor(&rotated)?;
    assert_eq!(decoded.store_identity, first.store_identity);
    assert_eq!(decoded.host_timelines, first.host_timelines);
    assert_eq!(decoded.owners, first.owners);
    assert_eq!(decoded.signer_identity.epoch, 2);
    assert_eq!(decoded.signer_key_id, signer_key_id(ROTATED_SEED));
    assert_eq!(fixture.compose(&deployment, &rotated)?, None);

    // Two stores provisioned from one document get different identities,
    // so different bundles (ADR-136 Q16).
    let sibling = Fixture::new(true)?;
    let other = provision_local_erasure(&sibling.request("a"), &signer(SIGNER_SEED), &trust)?;
    let other = LocalErasureBundleV1::from_canonical_cbor(&other)?;
    assert_ne!(other.store_identity, first.store_identity);
    assert_ne!(other.host_timelines, first.host_timelines);

    // The registry refuses another key for a registered identity, a lower
    // epoch, and a key already registered under another epoch.
    for (seed, epoch) in [(SIGNER_SEED, 2), (ROTATED_SEED, 1), (SIGNER_SEED, 3)] {
        let mut request = fixture.request("refused");
        request.signer_epoch = epoch;
        assert_eq!(
            refusal(provision_local_erasure(&request, &signer(seed), &trust)),
            Some(LocalErasureProvisionErrorV1::SignerRefused)
        );
    }
    Ok(())
}

/// Every refusal but the key registry's comes before the first write.
#[test]
fn refusals_before_any_write_leave_the_store_unprovisioned() -> TestResult {
    let deployment = Deployment::new(&[])?;
    let trust = deployment.trust()?;
    let no_principal = Fixture::new(false)?;
    assert_eq!(
        refusal(provision_local_erasure(
            &no_principal.request("o"),
            &signer(SIGNER_SEED),
            &trust
        )),
        Some(LocalErasureProvisionErrorV1::PrincipalMissing)
    );
    assert_eq!(no_principal.store_identity()?, None);

    let fixture = Fixture::new(true)?;
    let mut absent_root = fixture.request("o");
    "erasure-bundle/absent".clone_into(&mut absent_root.issued_by);
    let mut unprefixed = fixture.request("o");
    UNPREFIXED_ROOT.clone_into(&mut unprefixed.issued_by);
    let mut epoch_zero = fixture.request("o");
    epoch_zero.signer_epoch = 0;
    let mut long_owner = fixture.request("o");
    long_owner.signer_owner = "o".repeat(129);
    let mut empty_owner = fixture.request("o");
    empty_owner.signer_owner = String::new();
    for (request, expected) in [
        (absent_root, LocalErasureProvisionErrorV1::IssuerUntrusted),
        (unprefixed, LocalErasureProvisionErrorV1::BundleInvalid),
        (epoch_zero, LocalErasureProvisionErrorV1::BundleInvalid),
        (long_owner, LocalErasureProvisionErrorV1::BundleInvalid),
        (empty_owner, LocalErasureProvisionErrorV1::BundleInvalid),
    ] {
        assert_eq!(
            refusal(provision_local_erasure(
                &request,
                &signer(SIGNER_SEED),
                &trust
            )),
            Some(expected)
        );
    }
    for (revoked, expected) in [
        (
            BUNDLE_ROOT.to_owned(),
            LocalErasureProvisionErrorV1::IssuerUntrusted,
        ),
        (
            signer_key_id(SIGNER_SEED),
            LocalErasureProvisionErrorV1::SignerRevoked,
        ),
    ] {
        let revoking = Deployment::new(&[revoked.as_str()])?.trust()?;
        assert_eq!(
            refusal(provision_local_erasure(
                &fixture.request("o"),
                &signer(SIGNER_SEED),
                &revoking
            )),
            Some(expected)
        );
    }
    assert_eq!(fixture.store_identity()?, None);
    assert_eq!(fixture.registered_signer(1)?, None);
    Ok(())
}

/// ADR-134 §8: an offline writer refuses an unbound store, a store
/// `migrate-mode` holds, and a path that is no store.
#[test]
fn provisioning_is_an_offline_writer() -> TestResult {
    let trust = Deployment::new(&[])?.trust()?;
    let directory = tempfile::tempdir()?;
    let unbound = directory.path().join("unbound.db");
    let mut request = Fixture::new(true)?.request("o");
    request.sqlite_path = unbound.to_str().ok_or("not UTF-8")?.to_owned();
    assert!(provision_local_erasure(&request, &signer(SIGNER_SEED), &trust).is_err());
    request.sqlite_path = directory.path().to_str().ok_or("not UTF-8")?.to_owned();
    assert!(provision_local_erasure(&request, &signer(SIGNER_SEED), &trust).is_err());

    let fixture = Fixture::new(true)?;
    let migrating = GatewayModeStoreLockV1::exclusive(&fixture.path)?;
    assert!(provision_local_erasure(&fixture.request("o"), &signer(SIGNER_SEED), &trust).is_err());
    drop(migrating);
    assert_eq!(fixture.store_identity()?, None);
    Ok(())
}

/// The unit's two credentials, with the Fork-authority custody checks.
#[test]
fn the_unit_reads_exactly_its_two_credentials() -> TestResult {
    let deployment = Deployment::new(&[])?;
    let fixture = Fixture::new(true)?;
    let request = fixture.request("o");
    let release = deployment.release.as_bytes();
    let short_seed = fixture.credentials(
        "short",
        &[
            (LOCAL_ERASURE_SIGNER_CREDENTIAL_NAME, &SIGNER_SEED[..31]),
            (RELEASE_TRUST_CREDENTIAL_NAME, release),
        ],
    )?;
    let error = provision_local_erasure_from_credentials(&request, &short_seed, &deployment.state)
        .err()
        .ok_or("a 31-byte seed is refused")?;
    assert_eq!(
        error.to_string(),
        LocalErasureProvisionErrorV1::SignerCredentialInvalid.to_string()
    );
    let only_signer = fixture.credentials(
        "only-signer",
        &[(LOCAL_ERASURE_SIGNER_CREDENTIAL_NAME, SIGNER_SEED.as_slice())],
    )?;
    let extra = fixture.credentials(
        "extra",
        &[
            (LOCAL_ERASURE_SIGNER_CREDENTIAL_NAME, SIGNER_SEED.as_slice()),
            (RELEASE_TRUST_CREDENTIAL_NAME, release),
            ("pigloros.other", b"".as_slice()),
        ],
    )?;
    let bad_release = fixture.credentials(
        "bad-release",
        &[
            (LOCAL_ERASURE_SIGNER_CREDENTIAL_NAME, SIGNER_SEED.as_slice()),
            (RELEASE_TRUST_CREDENTIAL_NAME, b"policy_id = 1".as_slice()),
        ],
    )?;
    for directory in [&only_signer, &extra, &bad_release] {
        assert!(
            provision_local_erasure_from_credentials(&request, directory, &deployment.state)
                .is_err()
        );
    }
    let valid = fixture.credentials(
        "valid",
        &[
            (LOCAL_ERASURE_SIGNER_CREDENTIAL_NAME, SIGNER_SEED.as_slice()),
            (RELEASE_TRUST_CREDENTIAL_NAME, release),
        ],
    )?;
    let absent_state = fixture.directory.path().join("absent-trust-state.db");
    assert!(provision_local_erasure_from_credentials(&request, &valid, &absent_state).is_err());
    assert_eq!(fixture.store_identity()?, None);
    assert!(!request.out.exists());
    Ok(())
}

#[test]
fn refusals_have_stable_operator_messages() {
    for (error, fragment) in [
        (
            LocalErasureProvisionErrorV1::Usage,
            "Usage: piglor-gateway provision-local-erasure",
        ),
        (LocalErasureProvisionErrorV1::OutExists, "--out"),
        (
            LocalErasureProvisionErrorV1::SignerCredentialInvalid,
            "32-byte Ed25519 seed",
        ),
        (LocalErasureProvisionErrorV1::IssuerUntrusted, "--issued-by"),
        (LocalErasureProvisionErrorV1::SignerRevoked, "revokes"),
        (
            LocalErasureProvisionErrorV1::PrincipalMissing,
            "provision-local-principal",
        ),
        (
            LocalErasureProvisionErrorV1::BundleInvalid,
            "erasure-bundle/",
        ),
        (
            LocalErasureProvisionErrorV1::SignerRefused,
            "--signer-epoch",
        ),
    ] {
        assert!(error.to_string().contains(fragment), "{error}");
    }
}

// ---------------------------------------------------------------------------
// Stores that already hold an erasure request.
// ---------------------------------------------------------------------------

use pos_core::{
    ErasureAcknowledgementProvenanceV1, ErasureAdministrativeResolutionV1,
    ErasureAtomicFreezeResultV1, ErasureAttemptQuotaReservationV1, ErasureAuthorizationDecisionV1,
    ErasureCorrectionProvenanceV1, ErasureDestructionCommandV1, ErasureErrorV1,
    ErasureForkAdmissionInputV1, ErasureForkScopeRequirementV1, ErasureFreezeAdmissionEvidenceV1,
    ErasureFreezeAuthorizationEvidenceV1, ErasureReceiptInputV1, ErasureRequestInputV1,
    ErasureRequestV1, ErasureRetryAdmissionV1, ErasureScopeExtensionV1, ErasureScopeV1,
    ErasureStateTransitionV1, ErasureVerifiedTopologyObservationV1, TimelineMeta,
};
use pos_runtime::{
    ErasureAuthorityReadViewV1, ErasureCoordinatorAuthorityV1, ErasureExecutionHostV1,
};

/// A test authority that admits one submission and proves every Timeline
/// unaffected; it refuses every later lifecycle step.
struct SubmissionAuthority;

const REFUSED: ErasureErrorV1 = ErasureErrorV1::PolicyConflict;

impl ErasureCoordinatorAuthorityV1 for SubmissionAuthority {
    fn validate_freeze_authorization_with_view(
        &self,
        _view: &dyn ErasureAuthorityReadViewV1,
        _admission: &ErasureFreezeAdmissionEvidenceV1,
        _authorization: &ErasureFreezeAuthorizationEvidenceV1,
    ) -> Result<(), ErasureErrorV1> {
        Err(REFUSED)
    }

    fn validate_scope_extension_with_view(
        &self,
        _view: &dyn ErasureAuthorityReadViewV1,
        _extension: &ErasureScopeExtensionV1,
    ) -> Result<(), ErasureErrorV1> {
        Err(REFUSED)
    }

    fn validate_administrative_resolution_with_view(
        &self,
        _view: &dyn ErasureAuthorityReadViewV1,
        _resolution: &ErasureAdministrativeResolutionV1,
    ) -> Result<(), ErasureErrorV1> {
        Err(REFUSED)
    }

    fn verified_topology_observation(
        &self,
        view: &dyn ErasureAuthorityReadViewV1,
        _request: ErasureReferenceV1,
        manifest_digest: ErasureReferenceV1,
    ) -> Result<Option<ErasureVerifiedTopologyObservationV1>, ErasureErrorV1> {
        Ok(Some(ErasureVerifiedTopologyObservationV1::new(
            manifest_digest,
            Vec::new(),
            view.topology().to_vec(),
        )))
    }

    fn authenticate(
        &self,
        _view: &dyn ErasureAuthorityReadViewV1,
        _request: &ErasureRequestV1,
    ) -> Result<(), ErasureErrorV1> {
        Ok(())
    }

    fn admit_authorization(
        &self,
        _view: &dyn ErasureAuthorityReadViewV1,
        _request: ErasureReferenceV1,
        _provenance: ErasureReferenceV1,
        _decision: ErasureAuthorizationDecisionV1,
    ) -> Result<(), ErasureErrorV1> {
        Err(REFUSED)
    }

    fn admit_corrected_submission(
        &self,
        _view: &dyn ErasureAuthorityReadViewV1,
        _request: &ErasureRequestV1,
        _correction: &ErasureCorrectionProvenanceV1,
    ) -> Result<(), ErasureErrorV1> {
        Err(REFUSED)
    }

    fn admit_atomic_freeze(
        &self,
        _view: &dyn ErasureAuthorityReadViewV1,
        _request: ErasureReferenceV1,
        _requested: &ErasureStateTransitionV1,
    ) -> Result<ErasureAtomicFreezeResultV1, ErasureErrorV1> {
        Err(REFUSED)
    }

    fn admit_scope_extension(
        &self,
        _view: &dyn ErasureAuthorityReadViewV1,
        _extension: &ErasureScopeExtensionV1,
    ) -> Result<(), ErasureErrorV1> {
        Err(REFUSED)
    }

    fn admit_fork_scope_extension(
        &self,
        _view: &dyn ErasureAuthorityReadViewV1,
        _extension: &ErasureScopeExtensionV1,
        _input: &ErasureForkAdmissionInputV1,
    ) -> Result<(), ErasureErrorV1> {
        Err(REFUSED)
    }

    fn resolve_fork_child_scope(
        &self,
        _view: &dyn ErasureAuthorityReadViewV1,
        _parent: TimelineId,
        _child: &TimelineMeta,
    ) -> Result<ErasureReferenceV1, ErasureErrorV1> {
        Err(REFUSED)
    }

    fn resolve_fork_scope_extension(
        &self,
        _view: &dyn ErasureAuthorityReadViewV1,
        _requirement: ErasureForkScopeRequirementV1,
        _input: &ErasureForkAdmissionInputV1,
    ) -> Result<ErasureScopeExtensionV1, ErasureErrorV1> {
        Err(REFUSED)
    }

    fn admit_administrative_resolution(
        &self,
        _view: &dyn ErasureAuthorityReadViewV1,
        _resolution: &ErasureAdministrativeResolutionV1,
    ) -> Result<(), ErasureErrorV1> {
        Err(REFUSED)
    }

    fn dispatch_destruction(
        &self,
        _view: &dyn ErasureAuthorityReadViewV1,
        _request: ErasureReferenceV1,
        _commands: &[ErasureDestructionCommandV1],
    ) -> Result<(), ErasureErrorV1> {
        Err(REFUSED)
    }

    fn admit_attempt(
        &self,
        _view: &dyn ErasureAuthorityReadViewV1,
        _admission: &ErasureRetryAdmissionV1,
    ) -> Result<ErasureAttemptQuotaReservationV1, ErasureErrorV1> {
        Err(REFUSED)
    }

    fn admit_acknowledgement(
        &self,
        _view: &dyn ErasureAuthorityReadViewV1,
        _acknowledgement: &ErasureAcknowledgementProvenanceV1,
    ) -> Result<(), ErasureErrorV1> {
        Err(REFUSED)
    }

    fn admit_receipt(
        &self,
        _view: &dyn ErasureAuthorityReadViewV1,
        _input: &ErasureReceiptInputV1,
    ) -> Result<(), ErasureErrorV1> {
        Err(REFUSED)
    }
}

const fn digest(value: u8) -> ErasureReferenceV1 {
    ErasureReferenceV1::from_digest([value; 32])
}

impl Fixture {
    /// Commit one erasure request into the store through a host composed
    /// with [`SubmissionAuthority`].
    fn commit_request(&self) -> TestResult {
        let composition = ErasureCoordinatorCompositionV1::new(
            std::sync::Arc::new(SubmissionAuthority),
            digest(30),
        )?;
        let mut host = ErasureExecutionHostV1::open_with_authority(
            StoreConfig::Sqlite {
                path: self.path.clone(),
            },
            &composition,
            ErasureRecoveryLimitsV1::compiled_maximum(),
        )?;
        crate::mode_profile::attach_offline_writer_v1(host.gateway_mode_binding())?;
        let request = ErasureRequestV1::new(ErasureRequestInputV1 {
            request: digest(1),
            subject: digest(2),
            scope: ErasureScopeV1::PrivateSubjectData,
            selectors: vec![digest(3)],
            requester: digest(4),
            authorization: digest(5),
            policy: digest(6),
            request_position: 9,
            horizon_position: 20,
            provenance: digest(7),
        })?;
        host.command_sender()?
            .submit_erasure_request(request.clone(), request.provenance())?;
        Ok(())
    }

    fn request_count(&self) -> TestResult<usize> {
        Ok(SqliteStore::open(&self.path)?
            .erasure_authority_snapshot_with_limits(ErasureRecoveryLimitsV1::compiled_maximum())?
            .inventory()
            .request_heads()
            .len())
    }
}

/// Owner decision Q15: a routine rotation on a store that holds an erasure
/// request opens no host, so it succeeds through the raw store.
#[test]
fn a_rotation_on_a_store_holding_a_request_needs_no_host() -> TestResult {
    let deployment = Deployment::new(&[])?;
    let trust = deployment.trust()?;
    let fixture = Fixture::new(true)?;
    let first = provision_local_erasure(&fixture.request("a"), &signer(SIGNER_SEED), &trust)?;
    let first = LocalErasureBundleV1::from_canonical_cbor(&first)?;
    let host_timeline = local_erasure_host_timeline_v1(first.store_identity)?;
    fixture.commit_request()?;
    assert_eq!(fixture.request_count()?, 1);
    assert!(fixture.holds_timeline(host_timeline)?);

    let mut rotation = fixture.request("b");
    rotation.signer_epoch = 2;
    let rotated = provision_local_erasure(&rotation, &signer(ROTATED_SEED), &trust)?;
    let rotated = LocalErasureBundleV1::from_canonical_cbor(&rotated)?;
    assert_eq!(rotated.store_identity, first.store_identity);
    assert_eq!(rotated.host_timelines, first.host_timelines);
    assert_eq!(rotated.signer_identity.epoch, 2);
    assert_eq!(
        fixture.registered_signer(2)?,
        Some(
            SigningKey::from_bytes(&ROTATED_SEED)
                .verifying_key()
                .to_bytes()
        )
    );
    assert_eq!(fixture.request_count()?, 1);
    Ok(())
}

/// A store that holds an erasure request but no Erasure Host Timeline is
/// refused: the closed host that would open it does not serve the store.
#[test]
fn a_store_holding_a_request_without_its_host_timeline_is_refused() -> TestResult {
    let trust = Deployment::new(&[])?.trust()?;
    let fixture = Fixture::new(true)?;
    fixture.commit_request()?;
    let refused =
        crate::startup::erasure_host_failure(pos_core::ErasureHostErrorV1::RecoveryUnavailable)
            .to_string();
    let error = provision_local_erasure(&fixture.request("o"), &signer(SIGNER_SEED), &trust)
        .err()
        .ok_or("the closed host refuses a store that holds a request")?;
    assert_eq!(error.to_string(), refused);
    // The refusal comes after the idempotent signer and identity writes.
    let identity = fixture.store_identity()?.ok_or("no store identity")?;
    let public_key = SigningKey::from_bytes(&SIGNER_SEED)
        .verifying_key()
        .to_bytes();
    assert_eq!(fixture.registered_signer(1)?, Some(public_key));
    let host_timeline =
        local_erasure_host_timeline_v1(ErasureReferenceV1::from_digest(*identity.as_bytes()))?;
    assert!(!fixture.holds_timeline(host_timeline)?);
    assert_eq!(fixture.request_count()?, 1);
    // A re-run repeats both writes unchanged and is refused the same way.
    let again = provision_local_erasure(&fixture.request("o"), &signer(SIGNER_SEED), &trust)
        .err()
        .ok_or("a re-run is refused the same way")?;
    assert_eq!(again.to_string(), refused);
    assert_eq!(fixture.store_identity()?, Some(identity));
    assert_eq!(fixture.registered_signer(1)?, Some(public_key));
    Ok(())
}

/// A pre-existing `--out` is refused before the store is touched and is
/// left in place.
#[test]
fn an_existing_out_file_is_refused_before_any_store_write() -> TestResult {
    let deployment = Deployment::new(&[])?;
    let fixture = Fixture::new(true)?;
    let credentials = fixture.credentials(
        "credentials",
        &[
            (LOCAL_ERASURE_SIGNER_CREDENTIAL_NAME, SIGNER_SEED.as_slice()),
            (RELEASE_TRUST_CREDENTIAL_NAME, deployment.release.as_bytes()),
        ],
    )?;
    let request = fixture.request("existing.elb1");
    std::fs::write(&request.out, b"operator file")?;
    let error = provision_local_erasure_from_credentials(&request, &credentials, &deployment.state)
        .err()
        .ok_or("an existing --out file is refused")?;
    assert_eq!(error.kind(), std::io::ErrorKind::AlreadyExists);
    assert_eq!(
        error.to_string(),
        LocalErasureProvisionErrorV1::OutExists.to_string()
    );
    assert_eq!(std::fs::read(&request.out)?, b"operator file");
    assert_eq!(fixture.store_identity()?, None);
    assert_eq!(fixture.registered_signer(1)?, None);

    // A missing directory is the same refusal, with its own error kind.
    let mut orphan = fixture.request("missing");
    orphan.out = orphan.out.join("bundle.elb1");
    let error = provision_local_erasure_from_credentials(&orphan, &credentials, &deployment.state)
        .err()
        .ok_or("an --out in a missing directory is refused")?;
    assert_eq!(error.kind(), std::io::ErrorKind::NotFound);
    assert_eq!(
        error.to_string(),
        LocalErasureProvisionErrorV1::OutExists.to_string()
    );
    assert_eq!(fixture.store_identity()?, None);
    Ok(())
}

/// A crash after the signer registration and before the identity write
/// leaves a store a full re-run provisions.
#[test]
fn a_run_interrupted_after_the_signer_registration_completes() -> TestResult {
    let deployment = Deployment::new(&[])?;
    let fixture = Fixture::new(true)?;
    let mut store = SqliteStore::open(&fixture.path)?;
    super::register_signer(
        &mut store,
        OwnerIdV1::new(SIGNER_OWNER)?,
        1,
        &signer(SIGNER_SEED),
    )?;
    drop(store);
    assert_eq!(fixture.store_identity()?, None);

    let bundle = provision_local_erasure(
        &fixture.request("o"),
        &signer(SIGNER_SEED),
        &deployment.trust()?,
    )?;
    assert!(fixture.store_identity()?.is_some());
    assert_eq!(fixture.compose(&deployment, &bundle)?, None);
    Ok(())
}
