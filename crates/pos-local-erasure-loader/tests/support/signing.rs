//! Test-only Local erasure signing fixtures shared by the loader's own
//! tests, the Gateway's provisioning and serve-composition tests and the
//! key-less root store fixture (`apps/piglor-gateway/tests/support/`
//! `keyless_store.rs`), each including this file by `#[path]` (#1450).
//!
//! A [`Deployment`] is a deployment trust state store whose genesis TPS1,
//! signed by the fixture operator key, has the fixture `erasure-bundle/`
//! root and an unprefixed root, with its release anchor credential. Every
//! key is fixed test data and grants no authority outside a test.

use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};

use ed25519_dalek::{Signer as _, SigningKey};
use pos_conformance::{TrustPolicyRootV1, TrustPolicySnapshotV1};
use pos_core::{
    local_erasure_bundle_signing_message_v1, LocalErasureBundleSignatureV1, LocalErasureBundleV1,
};
use pos_crypto::key_roles::SigningKeyMaterial;
use pos_store::trust_policy_registry::{
    CurrentTrustPolicyV1, DeploymentTrustPolicyRegistryV1, OperatorReleaseTrustV1,
};

/// The result of a fixture step.
pub type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// The key id of the fixture `erasure-bundle/` TPS1 root.
pub const BUNDLE_ROOT: &str = "erasure-bundle/local";
/// The key id of the fixture unprefixed TPS1 root, which may not sign a
/// bundle.
pub const UNPREFIXED_ROOT: &str = "local-root";
/// The key-registry owner of the fixture role-2 signer.
pub const SIGNER_OWNER: &str = "pigloros.local-erasure-signer";
/// The seed of the fixture role-2 signer.
pub const SIGNER_SEED: [u8; 32] = [0x64; 32];
/// The seed of the rotated fixture role-2 signer.
pub const ROTATED_SEED: [u8; 32] = [0x65; 32];

/// The fixture release operator key.
#[must_use]
pub fn operator() -> SigningKey {
    SigningKey::from_bytes(&[0x61; 32])
}

/// The fixture `erasure-bundle/` root key.
#[must_use]
pub fn bundle_root() -> SigningKey {
    SigningKey::from_bytes(&[0x62; 32])
}

/// The fixture unprefixed root key.
#[must_use]
pub fn unprefixed_root() -> SigningKey {
    SigningKey::from_bytes(&[0x63; 32])
}

/// The role-2 signer of `seed`.
#[must_use]
pub fn signer(seed: [u8; 32]) -> SigningKeyMaterial {
    SigningKeyMaterial::new(SigningKey::from_bytes(&seed))
}

/// Lowercase hex of `bytes`.
#[must_use]
pub fn hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .flat_map(|byte| {
            [byte >> 4, byte & 0x0f]
                .map(|nibble| char::from_digit(u32::from(nibble), 16).unwrap_or_default())
        })
        .collect()
}

/// The TPS1 root `key_id` of `key`.
#[must_use]
pub fn root(key_id: &str, key: &SigningKey) -> TrustPolicyRootV1 {
    TrustPolicyRootV1 {
        key_id: key_id.to_owned(),
        root_version: 1,
        algorithm: "Ed25519".to_owned(),
        public_key: key.verifying_key().to_bytes(),
    }
}

/// A provisioned deployment trust state store and its release anchor
/// credential.
pub struct Deployment {
    _directory: tempfile::TempDir,
    /// The trust state store.
    pub state: PathBuf,
    /// The release anchor, as its systemd credential document.
    pub release: String,
    policy_id: String,
    genesis_digest: [u8; 32],
}

impl Deployment {
    /// A genesis TPS1 whose roots are the `erasure-bundle/` root and the
    /// unprefixed root and which revokes `revoked` (sorted).
    ///
    /// # Errors
    /// Returns an error when the fixture cannot be written.
    pub fn new(revoked: &[&str]) -> TestResult<Self> {
        Self::valid_through(revoked, "9999-12-31T23:59:59Z")
    }

    /// [`Self::new`] with the TPS1 `offline_valid_through` `valid_through`.
    ///
    /// # Errors
    /// Returns an error when the fixture cannot be written.
    pub fn valid_through(revoked: &[&str], valid_through: &str) -> TestResult<Self> {
        let draft = pos_conformance::draft_trust_policy_snapshot_bytes_v1()?;
        let mut snapshot = TrustPolicySnapshotV1::from_canonical_cbor(&draft)?;
        snapshot.trust_roots = vec![
            root(BUNDLE_ROOT, &bundle_root()),
            root(UNPREFIXED_ROOT, &unprefixed_root()),
        ];
        snapshot.revoked_key_ids = revoked.iter().map(|id| (*id).to_owned()).collect();
        valid_through.clone_into(&mut snapshot.offline_valid_through);
        let message = snapshot.operator_signature_message_v1()?;
        snapshot.operator_signature = operator().sign(&message).to_bytes();
        let genesis = snapshot.to_canonical_cbor()?;
        let genesis_digest = *blake3::hash(&genesis).as_bytes();
        let operator_key = operator().verifying_key().to_bytes();
        let directory = tempfile::tempdir()?;
        let deployment = Self {
            release: format!(
                "policy_id = \"{}\"\noperator_public_key = \"{}\"\ngenesis_digest = \"{}\"\n",
                snapshot.policy_id,
                hex(&operator_key),
                hex(&genesis_digest)
            ),
            state: directory.path().join("trust-state.db"),
            _directory: directory,
            policy_id: snapshot.policy_id,
            genesis_digest,
        };
        DeploymentTrustPolicyRegistryV1::provision_explicit(
            &deployment.state,
            &deployment.release_trust(),
            &genesis,
        )?;
        Ok(deployment)
    }

    /// The release anchor the credential encodes.
    #[must_use]
    pub fn release_trust(&self) -> OperatorReleaseTrustV1 {
        OperatorReleaseTrustV1::new(
            self.policy_id.clone(),
            operator().verifying_key().to_bytes(),
            self.genesis_digest,
        )
    }

    /// The current TPS1 of the trust state store.
    ///
    /// # Errors
    /// Returns an error when the store does not authenticate.
    pub fn trust(&self) -> TestResult<CurrentTrustPolicyV1> {
        Ok(
            DeploymentTrustPolicyRegistryV1::open_current(&self.state, self.release_trust())
                .and_then(|registry| registry.current_trust_policy())?,
        )
    }
}

/// ELB1S over `bundle` by `root`.
///
/// # Errors
/// Returns an error when `bundle` is not a canonical ELB1.
pub fn signed(bundle: &[u8], root: &SigningKey) -> TestResult<Vec<u8>> {
    let reference = LocalErasureBundleV1::from_canonical_cbor(bundle)?.reference()?;
    let message = local_erasure_bundle_signing_message_v1(reference)?;
    Ok(LocalErasureBundleSignatureV1 {
        bundle: reference,
        admin_signature: root.sign(&message).to_bytes(),
    }
    .to_canonical_cbor()?)
}

/// A protected credential directory `directory` (created `0700`) holding
/// `credentials`, each `0400`.
///
/// # Errors
/// Returns an error when the directory cannot be written.
pub fn credential_directory(
    directory: &Path,
    credentials: &[(&str, &[u8])],
) -> TestResult<PathBuf> {
    std::fs::create_dir(directory)?;
    std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700))?;
    for (name, bytes) in credentials {
        let credential = directory.join(name);
        std::fs::write(&credential, bytes)?;
        std::fs::set_permissions(&credential, std::fs::Permissions::from_mode(0o400))?;
    }
    Ok(directory.to_path_buf())
}
