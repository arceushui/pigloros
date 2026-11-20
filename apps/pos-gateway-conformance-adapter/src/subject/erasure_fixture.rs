//! The Local erasure authority of the `authorized-erasure` compositions (requirements section
//! 3; #1449, ADR-136 §4).
//!
//! A sub-case's store is provisioned the way an operator provisions one: a fixture deployment
//! trust state holds an operator-signed TPS1 whose one root is the fixture `erasure-bundle/`
//! root, the production `provision_local_erasure` registers the fixture role-2 signer and builds
//! the bundle, the fixture root signs it, and the Gateway's own `serve --require-local-erasure`
//! loader composes the authority from a protected credential directory holding exactly the four
//! serve credentials. Only the keys and the document are fixture data.

use std::fs::Permissions;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};

use ed25519_dalek::{Signer as _, SigningKey};
use piglor_gateway::local_erasure_composition::{LocalErasureServeInputsV1, LocalErasureServeV1};
use piglor_gateway::local_erasure_provision::{
    provision_local_erasure, LocalErasureProvisionRequestV1, LOCAL_ERASURE_SIGNER_CREDENTIAL_NAME,
};
use pos_conformance::{
    draft_trust_policy_snapshot_bytes_v1, TrustPolicyRootV1, TrustPolicySnapshotV1,
};
use pos_core::{
    local_erasure_bundle_signing_message_v1, EntityId, ErasureReferenceV1, ErasureScopeV1,
    LocalErasureBundleSignatureV1, LocalErasureBundleV1, PrincipalRefV1,
};
use pos_crypto::key_roles::SigningKeyMaterial;
use pos_local_erasure_loader::deployment_trust::{
    load_deployment_trust_v1, RELEASE_TRUST_CREDENTIAL_NAME,
};
use pos_local_erasure_loader::{
    LOCAL_ERASURE_BUNDLE_CREDENTIAL_NAME, LOCAL_ERASURE_BUNDLE_SIGNATURE_CREDENTIAL_NAME,
};
use pos_runtime::{ErasureExecutionHostV1, LocalErasureSignerRotationV1, LocalErasureSubmissionV1};
use pos_store::trust_policy_registry::{DeploymentTrustPolicyRegistryV1, OperatorReleaseTrustV1};

/// The seed of the fixture release operator key.
const OPERATOR_SEED: [u8; 32] = [0x71; 32];
/// The seed of the fixture `erasure-bundle/` TPS1 root key.
const BUNDLE_ROOT_SEED: [u8; 32] = [0x72; 32];
/// The seed of the fixture role-2 erasure signer.
const SIGNER_SEED: [u8; 32] = [0x73; 32];
/// The key id of the fixture bundle root.
const BUNDLE_ROOT: &str = "erasure-bundle/fixture";
/// The key-registry owner of the fixture signer.
const SIGNER_OWNER: &str = "pigloros.fixture-erasure-signer";
/// The fixture TPS1 never expires within any test run.
const VALID_THROUGH: &str = "9999-12-31T23:59:59Z";
/// The Idempotency-Key of the erasure an `authorized-erasure-held` actor already has.
const HELD_KEY: &[u8] = b"fixture-held-erasure";

fn key(seed: [u8; 32]) -> SigningKey {
    SigningKey::from_bytes(&seed)
}

fn hex(bytes: [u8; 32]) -> String {
    blake3::Hash::from_bytes(bytes).to_hex().to_string()
}

/// The fixture TPS1: the draft snapshot whose one root is the fixture bundle root, valid
/// through 9999 and signed by the fixture operator.
fn trust_snapshot() -> Option<TrustPolicySnapshotV1> {
    draft_trust_policy_snapshot_bytes_v1()
        .ok()
        .and_then(|draft| TrustPolicySnapshotV1::from_canonical_cbor(&draft).ok())
        .and_then(|mut snapshot| {
            snapshot.trust_roots = vec![TrustPolicyRootV1 {
                key_id: BUNDLE_ROOT.to_owned(),
                root_version: 1,
                algorithm: "Ed25519".to_owned(),
                public_key: key(BUNDLE_ROOT_SEED).verifying_key().to_bytes(),
            }];
            snapshot.revoked_key_ids = Vec::new();
            VALID_THROUGH.clone_into(&mut snapshot.offline_valid_through);
            snapshot
                .operator_signature_message_v1()
                .ok()
                .map(|message| {
                    snapshot.operator_signature = key(OPERATOR_SEED).sign(&message).to_bytes();
                    snapshot
                })
        })
}

/// The fixture deployment trust state of one sub-case: its store and release anchor.
struct DeploymentV1 {
    state: PathBuf,
    policy_id: String,
    genesis_digest: [u8; 32],
}

impl DeploymentV1 {
    /// The release anchor of the fixture operator.
    fn release(&self) -> OperatorReleaseTrustV1 {
        OperatorReleaseTrustV1::new(
            self.policy_id.clone(),
            key(OPERATOR_SEED).verifying_key().to_bytes(),
            self.genesis_digest,
        )
    }

    /// The release anchor as its systemd credential document.
    fn credential(&self) -> String {
        format!(
            "policy_id = \"{}\"\noperator_public_key = \"{}\"\ngenesis_digest = \"{}\"\n",
            self.policy_id,
            hex(key(OPERATOR_SEED).verifying_key().to_bytes()),
            hex(self.genesis_digest)
        )
    }
}

/// Provision the deployment trust state store in `directory` with the fixture TPS1.
fn deployment(directory: &Path) -> Option<DeploymentV1> {
    trust_snapshot()
        .and_then(|snapshot| {
            snapshot
                .to_canonical_cbor()
                .ok()
                .map(|genesis| (snapshot.policy_id, genesis))
        })
        .and_then(|(policy_id, genesis)| {
            let deployment = DeploymentV1 {
                state: directory.join("trust-state.db"),
                policy_id,
                genesis_digest: *blake3::hash(&genesis).as_bytes(),
            };
            DeploymentTrustPolicyRegistryV1::provision_explicit(
                &deployment.state,
                &deployment.release(),
                &genesis,
            )
            .ok()
            .map(|()| deployment)
        })
}

/// The ELB1S of the fixture bundle root over `bundle`.
fn bundle_signature(bundle: &[u8]) -> Option<Vec<u8>> {
    LocalErasureBundleV1::from_canonical_cbor(bundle)
        .and_then(|bundle| bundle.reference())
        .and_then(|reference| {
            local_erasure_bundle_signing_message_v1(reference).map(|message| (reference, message))
        })
        .and_then(|(bundle, message)| {
            LocalErasureBundleSignatureV1 {
                bundle,
                admin_signature: key(BUNDLE_ROOT_SEED).sign(&message).to_bytes(),
            }
            .to_canonical_cbor()
        })
        .ok()
}

/// Provision Local erasure on the store at `sqlite_path` for the fixture signer under a
/// bundle expiring at Unix second `expiry`, and return the ELB1 and its ELB1S.
fn signed_bundle(
    sqlite_path: &str,
    directory: &Path,
    deployment: &DeploymentV1,
    expiry: u64,
) -> Option<(Vec<u8>, Vec<u8>)> {
    load_deployment_trust_v1(&deployment.state, deployment.release())
        .ok()
        .and_then(|trust| {
            provision_local_erasure(
                &LocalErasureProvisionRequestV1 {
                    sqlite_path: sqlite_path.to_owned(),
                    out: directory.join("bundle.elb1"),
                    issued_by: BUNDLE_ROOT.to_owned(),
                    expiry,
                    signer_owner: SIGNER_OWNER.to_owned(),
                    signer_epoch: 1,
                    rotation: LocalErasureSignerRotationV1::Routine,
                },
                &SigningKeyMaterial::new(key(SIGNER_SEED)),
                &trust,
                0,
            )
            .ok()
        })
        .and_then(|bundle| bundle_signature(&bundle).map(|signature| (bundle, signature)))
}

/// A protected credential directory in `directory` holding exactly `credentials`.
fn credential_directory(directory: &Path, credentials: &[(&str, &[u8])]) -> Option<PathBuf> {
    let path = directory.join("credentials");
    std::fs::create_dir(&path)
        .and_then(|()| std::fs::set_permissions(&path, Permissions::from_mode(0o700)))
        .and_then(|()| {
            credentials.iter().try_for_each(|(name, bytes)| {
                let credential = path.join(name);
                std::fs::write(&credential, bytes).and_then(|()| {
                    std::fs::set_permissions(&credential, Permissions::from_mode(0o400))
                })
            })
        })
        .ok()
        .map(|()| path)
}

/// The Local erasure authority of the provisioned, bound store at `sqlite_path`, with its
/// fixture files in the empty directory `directory`, under a bundle that expires at Unix
/// second `expiry` (0: never), composed by the Gateway's `serve` loader.
pub(super) fn local_erasure(
    sqlite_path: &str,
    directory: &Path,
    expiry: u64,
) -> Option<LocalErasureServeV1> {
    deployment(directory)
        .and_then(|deployment| {
            signed_bundle(sqlite_path, directory, &deployment, expiry)
                .map(|bundles| (deployment, bundles))
        })
        .and_then(|(deployment, (bundle, signature))| {
            credential_directory(
                directory,
                &[
                    (LOCAL_ERASURE_BUNDLE_CREDENTIAL_NAME, bundle.as_slice()),
                    (
                        LOCAL_ERASURE_BUNDLE_SIGNATURE_CREDENTIAL_NAME,
                        signature.as_slice(),
                    ),
                    (LOCAL_ERASURE_SIGNER_CREDENTIAL_NAME, SIGNER_SEED.as_slice()),
                    (
                        RELEASE_TRUST_CREDENTIAL_NAME,
                        deployment.credential().as_bytes(),
                    ),
                ],
            )
            .and_then(|credentials| {
                LocalErasureServeV1::for_serve(Some(LocalErasureServeInputsV1 {
                    sqlite_path,
                    credential_directory: &credentials,
                    trust_state: &deployment.state,
                    with_fork_authority: false,
                }))
                .ok()
            })
        })
}

/// Admit one erasure of `actor`'s subject on `host` before it serves, so that subject has an
/// erasure in progress. Its mode-profile binding is never read back.
pub(super) fn hold_subject(
    host: &mut ErasureExecutionHostV1,
    principal: &PrincipalRefV1,
    actor: EntityId,
) -> Option<()> {
    host.command_sender()
        .ok()
        .and_then(|mut sender| {
            sender
                .submit_local_erasure(&LocalErasureSubmissionV1 {
                    principal: principal.clone(),
                    actor,
                    scope: ErasureScopeV1::PrivateSubjectData,
                    idempotency_key_digest: ErasureReferenceV1::from_digest(
                        *blake3::hash(HELD_KEY).as_bytes(),
                    ),
                    mode_profile: ErasureReferenceV1::from_digest([0; 32]),
                    binding_epoch: 1,
                })
                .ok()
        })
        .map(drop)
}
