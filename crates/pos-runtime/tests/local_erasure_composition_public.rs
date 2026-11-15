//! ADR-136 §4 bundle verification at the public composition seam
//! `ErasureCoordinatorCompositionV1::local` (acceptance test 6, bundle and
//! TPS1 parts).
#![cfg(target_os = "linux")]

use std::sync::Arc;

use ed25519_dalek::{Signer, SigningKey};
use pos_conformance::{TrustPolicyRootV1, TrustPolicySnapshotV1};
use pos_core::{
    deletion_receipt, local_erasure_bundle_signing_message_v1, local_erasure_signer_key_id_v1,
    ErasureAcknowledgementProvenanceV1, ErasureAdministrativeResolutionV1,
    ErasureAtomicFreezeResultV1, ErasureAttemptQuotaReservationV1, ErasureAuthorizationDecisionV1,
    ErasureContainmentGateV1, ErasureCorrectionProvenanceV1, ErasureDestructionCommandV1,
    ErasureErrorV1, ErasureForkAdmissionInputV1, ErasureForkScopeRequirementV1,
    ErasureFreezeAdmissionEvidenceV1, ErasureFreezeAuthorizationEvidenceV1,
    ErasureInventoryPersistencePortV1, ErasureReceiptInputV1, ErasureRecoveryLimitsV1,
    ErasureReferenceV1, ErasureRequestInputV1, ErasureRequestV1, ErasureRetryAdmissionV1,
    ErasureScopeExtensionV1, ErasureScopeV1, ErasureStateTransitionV1,
    ErasureVerifiedTopologyObservationV1, EventStore, Hash, KeyDestructionRequestV1, KeyIdentityV1,
    KeyRegistrationV1, KeyRegistryStateV1, KeyRoleV1, LocalErasureBundleSignatureV1,
    LocalErasureBundleV1, LocalErasureExecutionBindingV1, LocalErasureSignerIdentityV1, TimelineId,
    TimelineMeta, ERASURE_RETAINED_OBJECT_MAX_BYTES_V1,
};
use pos_crypto::key_roles::SigningKeyMaterial;
use pos_runtime::{
    ErasureAuthorityReadViewV1, ErasureCoordinatorAuthorityV1, ErasureCoordinatorCompositionV1,
    ErasureExecutionHostV1, LocalErasureCompositionErrorV1, LocalErasureCompositionInputsV1,
};
use pos_store::memory::MemoryStore;
use pos_store::sqlite::SqliteStore;
use pos_store::trust_policy_registry::{
    CurrentTrustPolicyV1, DeploymentTrustPolicyRegistryV1, OperatorReleaseTrustV1,
};
use pos_store::StoreConfig;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const BUNDLE_ROOT: &str = "erasure-bundle/root-1";
const OTHER_ROOT: &str = "erasure-bundle/root-2";
const SIGNER_OWNER: &str = "local-erasure-signer";
const STORE_IDENTITY: [u8; 32] = [0x51; 32];
const POLICY: [u8; 32] = [0x52; 32];
const REGISTRY: [u8; 32] = [0x55; 32];

fn operator() -> SigningKey {
    SigningKey::from_bytes(&[0x61; 32])
}

/// The operator key after a rotation.
fn rotated_operator() -> SigningKey {
    SigningKey::from_bytes(&[0x65; 32])
}

fn bundle_root() -> SigningKey {
    SigningKey::from_bytes(&[0x62; 32])
}

fn other_root() -> SigningKey {
    SigningKey::from_bytes(&[0x63; 32])
}

fn erasure_signer() -> SigningKey {
    SigningKey::from_bytes(&[0x64; 32])
}

fn root(key_id: &str, key: &SigningKey) -> TrustPolicyRootV1 {
    TrustPolicyRootV1 {
        key_id: key_id.to_owned(),
        root_version: 1,
        algorithm: "Ed25519".to_owned(),
        public_key: key.verifying_key().to_bytes(),
    }
}

/// The current TPS1 of a freshly provisioned deployment trust state store
/// whose roots are the two `erasure-bundle/` roots and which revokes
/// `revoked` (sorted).
fn trust(revoked: &[&str]) -> TestResult<CurrentTrustPolicyV1> {
    trust_under(&operator(), revoked)
}

/// As [`trust`], under the deployment operator key `operator`.
fn trust_under(operator: &SigningKey, revoked: &[&str]) -> TestResult<CurrentTrustPolicyV1> {
    let draft = pos_conformance::draft_trust_policy_snapshot_bytes_v1()?;
    let mut snapshot = TrustPolicySnapshotV1::from_canonical_cbor(&draft)?;
    snapshot.trust_roots = vec![
        root(BUNDLE_ROOT, &bundle_root()),
        root(OTHER_ROOT, &other_root()),
    ];
    snapshot.revoked_key_ids = revoked.iter().map(|id| (*id).to_owned()).collect();
    "9999-12-31T23:59:59Z".clone_into(&mut snapshot.offline_valid_through);
    let message = snapshot.operator_signature_message_v1()?;
    snapshot.operator_signature = operator.sign(&message).to_bytes();
    let genesis = snapshot.to_canonical_cbor()?;
    let release = || {
        OperatorReleaseTrustV1::new(
            snapshot.policy_id.clone(),
            operator.verifying_key().to_bytes(),
            *blake3::hash(&genesis).as_bytes(),
        )
    };
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("trust.db");
    DeploymentTrustPolicyRegistryV1::provision_explicit(&path, &release(), &genesis)?;
    let registry = DeploymentTrustPolicyRegistryV1::open_current(&path, release())?;
    let current = registry.current_trust_policy()?;
    Ok(current)
}

fn execution_binding() -> LocalErasureExecutionBindingV1 {
    LocalErasureExecutionBindingV1 {
        executor_id: "local-erasure-executor".to_owned(),
        executor_version_digest: ErasureReferenceV1::from_digest([0x53; 32]),
    }
}

fn bundle() -> LocalErasureBundleV1 {
    let signer_public_key = erasure_signer().verifying_key().to_bytes();
    LocalErasureBundleV1 {
        tps1: ErasureReferenceV1::from_digest([0x54; 32]),
        store_identity: ErasureReferenceV1::from_digest(STORE_IDENTITY),
        authority_registry_digest: ErasureReferenceV1::from_digest(REGISTRY),
        host_timelines: Vec::new(),
        policy: ErasureReferenceV1::from_digest(POLICY),
        owners: Vec::new(),
        execution_binding: execution_binding(),
        signer_identity: LocalErasureSignerIdentityV1 {
            owner_id: SIGNER_OWNER.as_bytes().to_vec(),
            epoch: 1,
        },
        signer_public_key,
        signer_key_id: local_erasure_signer_key_id_v1(&signer_public_key),
        issued_by: BUNDLE_ROOT.to_owned(),
        expiry: 0,
    }
}

/// ELB1S over `bundle` by `key`.
fn signature(bundle: &LocalErasureBundleV1, key: &SigningKey) -> TestResult<Vec<u8>> {
    let reference = bundle.reference()?;
    let message = local_erasure_bundle_signing_message_v1(reference)?;
    Ok(LocalErasureBundleSignatureV1 {
        bundle: reference,
        admin_signature: key.sign(&message).to_bytes(),
    }
    .to_canonical_cbor()?)
}

fn signer_identity(epoch: u64) -> KeyIdentityV1 {
    KeyIdentityV1::new(SIGNER_OWNER, KeyRoleV1::TimelineIntegritySigning, epoch)
}

fn register_signer(store: &mut impl EventStore, key: &SigningKey, epoch: u64) -> TestResult {
    let material = SigningKeyMaterial::new(key.clone());
    let mut registry = KeyRegistryStateV1::new();
    registry.register_key(KeyRegistrationV1::new(
        signer_identity(epoch),
        material.material_digest(),
        Some(material.public_verification_key()),
    ))?;
    store.save_key_registry(&registry)?;
    Ok(())
}

/// A store with the bundle's identity and signer key registered.
fn provisioned_store() -> TestResult<MemoryStore> {
    let mut store = MemoryStore::new();
    store.init_erasure_store_identity(Hash::from_bytes(STORE_IDENTITY))?;
    register_signer(&mut store, &erasure_signer(), 1)?;
    Ok(store)
}

struct Case {
    bundle: Vec<u8>,
    signature: Vec<u8>,
    trust: CurrentTrustPolicyV1,
    operator_public_key: [u8; 32],
    authority_registry_digest: ErasureReferenceV1,
    policy: ErasureReferenceV1,
    execution_binding: Option<LocalErasureExecutionBindingV1>,
}

impl Case {
    fn valid() -> TestResult<Self> {
        Self::signed(&bundle(), &bundle_root(), &[])
    }

    fn signed(
        bundle: &LocalErasureBundleV1,
        key: &SigningKey,
        revoked: &[&str],
    ) -> TestResult<Self> {
        Ok(Self {
            bundle: bundle.to_canonical_cbor()?,
            signature: signature(bundle, key)?,
            trust: trust(revoked)?,
            operator_public_key: operator().verifying_key().to_bytes(),
            authority_registry_digest: ErasureReferenceV1::from_digest(REGISTRY),
            policy: ErasureReferenceV1::from_digest(POLICY),
            execution_binding: Some(execution_binding()),
        })
    }

    fn compose<S>(
        &self,
        store: &mut S,
    ) -> Result<ErasureCoordinatorCompositionV1, LocalErasureCompositionErrorV1>
    where
        S: ErasureInventoryPersistencePortV1 + EventStore,
    {
        ErasureCoordinatorCompositionV1::local(
            &LocalErasureCompositionInputsV1 {
                bundle: &self.bundle,
                bundle_signature: &self.signature,
                trust: &self.trust,
                operator_public_key: self.operator_public_key,
                authority_registry_digest: self.authority_registry_digest,
                policy: self.policy,
                execution_binding: self.execution_binding.as_ref(),
            },
            store,
        )
    }

    fn refusal<S>(&self, store: &mut S) -> Option<LocalErasureCompositionErrorV1>
    where
        S: ErasureInventoryPersistencePortV1 + EventStore,
    {
        self.compose(store).err()
    }
}

#[test]
fn a_root_signed_bundle_that_matches_the_binary_and_store_composes() -> TestResult {
    let case = Case::valid()?;
    assert!(case.compose(&mut provisioned_store()?).is_ok());
    Ok(())
}

#[test]
fn a_key_less_root_skips_only_the_execution_binding() -> TestResult {
    let mut case = Case::valid()?;
    case.execution_binding = None;
    assert!(case.compose(&mut provisioned_store()?).is_ok());
    let mut other = bundle();
    other.execution_binding.executor_id = "another-executor".to_owned();
    let mut case = Case::signed(&other, &bundle_root(), &[])?;
    case.execution_binding = None;
    assert!(case.compose(&mut provisioned_store()?).is_ok());
    case.policy = ErasureReferenceV1::from_digest([0x99; 32]);
    assert_eq!(
        case.refusal(&mut provisioned_store()?),
        Some(LocalErasureCompositionErrorV1::BundleMismatch)
    );
    Ok(())
}

#[test]
fn malformed_or_unbound_bundle_records_are_invalid() -> TestResult {
    let mut store = provisioned_store()?;
    let mut case = Case::valid()?;
    case.bundle.push(0);
    assert_eq!(
        case.refusal(&mut store),
        Some(LocalErasureCompositionErrorV1::BundleInvalid)
    );
    let mut case = Case::valid()?;
    case.signature.push(0);
    assert_eq!(
        case.refusal(&mut store),
        Some(LocalErasureCompositionErrorV1::BundleInvalid)
    );
    // An ELB1S that names another bundle, even one the root signed.
    let mut other = bundle();
    other.expiry = 7;
    let mut case = Case::valid()?;
    case.signature = signature(&other, &bundle_root())?;
    assert_eq!(
        case.refusal(&mut store),
        Some(LocalErasureCompositionErrorV1::BundleInvalid)
    );
    // An ELB1S naming another bundle although its signature is the root's
    // valid signature over this bundle's message.
    let reference = bundle().reference()?;
    let mut case = Case::valid()?;
    case.signature = LocalErasureBundleSignatureV1 {
        bundle: other.reference()?,
        admin_signature: bundle_root()
            .sign(&local_erasure_bundle_signing_message_v1(reference)?)
            .to_bytes(),
    }
    .to_canonical_cbor()?;
    assert_eq!(
        case.refusal(&mut store),
        Some(LocalErasureCompositionErrorV1::BundleInvalid)
    );
    Ok(())
}

#[test]
fn a_bundle_not_signed_by_its_named_tps1_root_is_invalid() -> TestResult {
    let mut store = provisioned_store()?;
    // Signed by another current root than the one `issued_by` names.
    let case = Case::signed(&bundle(), &other_root(), &[])?;
    assert_eq!(
        case.refusal(&mut store),
        Some(LocalErasureCompositionErrorV1::BundleInvalid)
    );
    // `issued_by` names a key id that is not a TPS1 root.
    let mut unrooted = bundle();
    unrooted.issued_by = "erasure-bundle/root-3".to_owned();
    let case = Case::signed(&unrooted, &bundle_root(), &[])?;
    assert_eq!(
        case.refusal(&mut store),
        Some(LocalErasureCompositionErrorV1::BundleInvalid)
    );
    // The root names it correctly but the key that signed is no TPS1 root.
    let case = Case::signed(&bundle(), &operator(), &[])?;
    assert_eq!(
        case.refusal(&mut store),
        Some(LocalErasureCompositionErrorV1::BundleInvalid)
    );
    Ok(())
}

#[test]
fn a_revoked_bundle_root_or_signer_key_is_refused() -> TestResult {
    let mut store = provisioned_store()?;
    let signer_key_id =
        local_erasure_signer_key_id_v1(&erasure_signer().verifying_key().to_bytes());
    for revoked in [vec![BUNDLE_ROOT], vec![signer_key_id.as_str()]] {
        let case = Case::signed(&bundle(), &bundle_root(), &revoked)?;
        assert_eq!(
            case.refusal(&mut store),
            Some(LocalErasureCompositionErrorV1::TrustRevoked)
        );
    }
    // Revoking an unrelated root leaves the bundle usable.
    let case = Case::signed(&bundle(), &bundle_root(), &[OTHER_ROOT])?;
    assert!(case.compose(&mut store).is_ok());
    Ok(())
}

#[test]
fn a_bundle_for_another_policy_or_executor_is_a_mismatch() -> TestResult {
    let mut store = provisioned_store()?;
    let mut case = Case::valid()?;
    case.authority_registry_digest = ErasureReferenceV1::from_digest([0x97; 32]);
    assert_eq!(
        case.refusal(&mut store),
        Some(LocalErasureCompositionErrorV1::BundleMismatch)
    );
    let mut case = Case::valid()?;
    case.policy = ErasureReferenceV1::from_digest([0x99; 32]);
    assert_eq!(
        case.refusal(&mut store),
        Some(LocalErasureCompositionErrorV1::BundleMismatch)
    );
    let mut case = Case::valid()?;
    let mut binding = execution_binding();
    binding.executor_version_digest = ErasureReferenceV1::from_digest([0x98; 32]);
    case.execution_binding = Some(binding);
    assert_eq!(
        case.refusal(&mut store),
        Some(LocalErasureCompositionErrorV1::BundleMismatch)
    );
    Ok(())
}

#[test]
fn a_bundle_for_another_store_is_a_mismatch() -> TestResult {
    let case = Case::valid()?;
    let mut unprovisioned = MemoryStore::new();
    register_signer(&mut unprovisioned, &erasure_signer(), 1)?;
    assert_eq!(
        case.refusal(&mut unprovisioned),
        Some(LocalErasureCompositionErrorV1::BundleMismatch)
    );
    let mut sibling = MemoryStore::new();
    sibling.init_erasure_store_identity(Hash::from_bytes([0x5f; 32]))?;
    register_signer(&mut sibling, &erasure_signer(), 1)?;
    assert_eq!(
        case.refusal(&mut sibling),
        Some(LocalErasureCompositionErrorV1::BundleMismatch)
    );
    Ok(())
}

#[test]
fn a_signer_key_the_key_registry_does_not_hold_is_a_mismatch() -> TestResult {
    let case = Case::valid()?;
    let identity = Hash::from_bytes(STORE_IDENTITY);
    let mut no_registry = MemoryStore::new();
    no_registry.init_erasure_store_identity(identity)?;
    assert_eq!(
        case.refusal(&mut no_registry),
        Some(LocalErasureCompositionErrorV1::BundleMismatch)
    );
    let mut other_key = MemoryStore::new();
    other_key.init_erasure_store_identity(identity)?;
    register_signer(&mut other_key, &other_root(), 1)?;
    assert_eq!(
        case.refusal(&mut other_key),
        Some(LocalErasureCompositionErrorV1::BundleMismatch)
    );
    let mut other_epoch = MemoryStore::new();
    other_epoch.init_erasure_store_identity(identity)?;
    register_signer(&mut other_epoch, &erasure_signer(), 2)?;
    assert_eq!(
        case.refusal(&mut other_epoch),
        Some(LocalErasureCompositionErrorV1::BundleMismatch)
    );
    Ok(())
}

#[test]
fn a_destroyed_signer_key_is_a_mismatch() -> TestResult {
    let case = Case::valid()?;
    let mut store = MemoryStore::new();
    store.init_erasure_store_identity(Hash::from_bytes(STORE_IDENTITY))?;
    let material = SigningKeyMaterial::new(erasure_signer());
    let mut registry = KeyRegistryStateV1::new();
    registry.register_key(KeyRegistrationV1::new(
        signer_identity(1),
        material.material_digest(),
        Some(material.public_verification_key()),
    ))?;
    let request = KeyDestructionRequestV1::new(
        signer_identity(1),
        material.material_digest(),
        Hash::from_bytes([0x66; 32]),
    );
    registry.begin_key_destruction(request)?;
    registry.complete_key_destruction(request, deletion_receipt(&request))?;
    store.save_key_registry(&registry)?;
    assert_eq!(
        case.refusal(&mut store),
        Some(LocalErasureCompositionErrorV1::BundleMismatch)
    );
    Ok(())
}

#[test]
fn a_signer_owner_id_that_is_no_key_registry_owner_is_a_mismatch() -> TestResult {
    let mut store = provisioned_store()?;
    let mut not_text = bundle();
    not_text.signer_identity.owner_id = vec![0xff];
    let case = Case::signed(&not_text, &bundle_root(), &[])?;
    assert_eq!(
        case.refusal(&mut store),
        Some(LocalErasureCompositionErrorV1::BundleMismatch)
    );
    Ok(())
}

#[test]
fn composition_errors_have_stable_payload_free_messages() {
    for (error, message) in [
        (
            LocalErasureCompositionErrorV1::BundleInvalid,
            "local erasure bundle is invalid",
        ),
        (
            LocalErasureCompositionErrorV1::BundleMismatch,
            "local erasure bundle does not match this deployment",
        ),
        (
            LocalErasureCompositionErrorV1::TrustRevoked,
            "local erasure bundle trust is revoked",
        ),
        (
            LocalErasureCompositionErrorV1::ErasureTrustAnchorRotated,
            "erasure trust anchor was rotated",
        ),
    ] {
        assert_eq!(error.to_string(), message);
    }
}

/// An authority that admits only submission, so a test can put one ERQ1 in
/// a store; every other decision refuses.
struct SubmitOnlyAuthority;

impl ErasureCoordinatorAuthorityV1 for SubmitOnlyAuthority {
    fn validate_freeze_authorization_with_view(
        &self,
        _view: &dyn ErasureAuthorityReadViewV1,
        _admission: &ErasureFreezeAdmissionEvidenceV1,
        _authorization: &ErasureFreezeAuthorizationEvidenceV1,
    ) -> Result<(), ErasureErrorV1> {
        Err(ErasureErrorV1::PolicyConflict)
    }

    fn validate_scope_extension_with_view(
        &self,
        _view: &dyn ErasureAuthorityReadViewV1,
        _extension: &ErasureScopeExtensionV1,
    ) -> Result<(), ErasureErrorV1> {
        Err(ErasureErrorV1::PolicyConflict)
    }

    fn validate_administrative_resolution_with_view(
        &self,
        _view: &dyn ErasureAuthorityReadViewV1,
        _resolution: &ErasureAdministrativeResolutionV1,
    ) -> Result<(), ErasureErrorV1> {
        Err(ErasureErrorV1::PolicyConflict)
    }

    fn verified_topology_observation(
        &self,
        _view: &dyn ErasureAuthorityReadViewV1,
        _request: ErasureReferenceV1,
        manifest_digest: ErasureReferenceV1,
    ) -> Result<Option<ErasureVerifiedTopologyObservationV1>, ErasureErrorV1> {
        Ok(Some(ErasureVerifiedTopologyObservationV1::new(
            manifest_digest,
            Vec::new(),
            Vec::new(),
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
        Err(ErasureErrorV1::PolicyConflict)
    }

    fn admit_corrected_submission(
        &self,
        _view: &dyn ErasureAuthorityReadViewV1,
        _request: &ErasureRequestV1,
        _correction: &ErasureCorrectionProvenanceV1,
    ) -> Result<(), ErasureErrorV1> {
        Err(ErasureErrorV1::PolicyConflict)
    }

    fn admit_atomic_freeze(
        &self,
        _view: &dyn ErasureAuthorityReadViewV1,
        _request: ErasureReferenceV1,
        _requested: &ErasureStateTransitionV1,
    ) -> Result<ErasureAtomicFreezeResultV1, ErasureErrorV1> {
        Err(ErasureErrorV1::PolicyConflict)
    }

    fn admit_scope_extension(
        &self,
        _view: &dyn ErasureAuthorityReadViewV1,
        _extension: &ErasureScopeExtensionV1,
    ) -> Result<(), ErasureErrorV1> {
        Err(ErasureErrorV1::PolicyConflict)
    }

    fn admit_fork_scope_extension(
        &self,
        _view: &dyn ErasureAuthorityReadViewV1,
        _extension: &ErasureScopeExtensionV1,
        _input: &ErasureForkAdmissionInputV1,
    ) -> Result<(), ErasureErrorV1> {
        Err(ErasureErrorV1::PolicyConflict)
    }

    fn resolve_fork_child_scope(
        &self,
        _view: &dyn ErasureAuthorityReadViewV1,
        _parent: TimelineId,
        _child: &TimelineMeta,
    ) -> Result<ErasureReferenceV1, ErasureErrorV1> {
        Err(ErasureErrorV1::PolicyConflict)
    }

    fn resolve_fork_scope_extension(
        &self,
        _view: &dyn ErasureAuthorityReadViewV1,
        _requirement: ErasureForkScopeRequirementV1,
        _input: &ErasureForkAdmissionInputV1,
    ) -> Result<ErasureScopeExtensionV1, ErasureErrorV1> {
        Err(ErasureErrorV1::PolicyConflict)
    }

    fn admit_administrative_resolution(
        &self,
        _view: &dyn ErasureAuthorityReadViewV1,
        _resolution: &ErasureAdministrativeResolutionV1,
    ) -> Result<(), ErasureErrorV1> {
        Err(ErasureErrorV1::PolicyConflict)
    }

    fn dispatch_destruction(
        &self,
        _view: &dyn ErasureAuthorityReadViewV1,
        _request: ErasureReferenceV1,
        _commands: &[ErasureDestructionCommandV1],
    ) -> Result<(), ErasureErrorV1> {
        Err(ErasureErrorV1::PolicyConflict)
    }

    fn admit_attempt(
        &self,
        _view: &dyn ErasureAuthorityReadViewV1,
        _admission: &ErasureRetryAdmissionV1,
    ) -> Result<ErasureAttemptQuotaReservationV1, ErasureErrorV1> {
        Err(ErasureErrorV1::PolicyConflict)
    }

    fn admit_acknowledgement(
        &self,
        _view: &dyn ErasureAuthorityReadViewV1,
        _acknowledgement: &ErasureAcknowledgementProvenanceV1,
    ) -> Result<(), ErasureErrorV1> {
        Err(ErasureErrorV1::PolicyConflict)
    }

    fn admit_receipt(
        &self,
        _view: &dyn ErasureAuthorityReadViewV1,
        _input: &ErasureReceiptInputV1,
    ) -> Result<(), ErasureErrorV1> {
        Err(ErasureErrorV1::PolicyConflict)
    }
}

fn reference(byte: u8) -> ErasureReferenceV1 {
    ErasureReferenceV1::from_digest([byte; 32])
}

/// A provisioned `SQLite` store that retains `retained` as TPS1 evidence
/// and, when `with_request`, holds one submitted ERQ1.
fn sqlite_store(
    directory: &tempfile::TempDir,
    retained: &[Vec<u8>],
    with_request: bool,
) -> TestResult<SqliteStore> {
    let path = directory
        .path()
        .join("erasure.sqlite3")
        .to_str()
        .ok_or("temporary database path is not UTF-8")?
        .to_owned();
    if with_request {
        let composition =
            ErasureCoordinatorCompositionV1::new(Arc::new(SubmitOnlyAuthority), reference(0x70))?;
        let mut host = ErasureExecutionHostV1::open_with_authority(
            StoreConfig::Sqlite { path: path.clone() },
            &composition,
            ErasureRecoveryLimitsV1::compiled_maximum(),
        )?;
        let request = ErasureRequestV1::new(ErasureRequestInputV1 {
            request: reference(1),
            subject: reference(2),
            scope: ErasureScopeV1::PrivateSubjectData,
            selectors: vec![reference(3)],
            requester: reference(4),
            authorization: reference(5),
            policy: reference(6),
            request_position: 9,
            horizon_position: 20,
            provenance: reference(7),
        })?;
        let provenance = request.provenance();
        host.command_sender()?
            .submit_erasure_request(request, provenance)?;
    }
    let mut store = SqliteStore::open(&path)?;
    store.bind_erasure_gate(Arc::new(ErasureContainmentGateV1::new_test_open()))?;
    store.init_erasure_store_identity(Hash::from_bytes(STORE_IDENTITY))?;
    register_signer(&mut store, &erasure_signer(), 1)?;
    for tps1 in retained {
        store.retain_erasure_object(tps1, ERASURE_RETAINED_OBJECT_MAX_BYTES_V1)?;
    }
    Ok(store)
}

#[test]
fn retained_trust_needs_no_check_while_the_store_holds_no_request() -> TestResult {
    let case = Case::valid()?;
    // A TPS1 an earlier operator key signed, but no ERQ1: composition opens.
    let earlier = trust_under(&rotated_operator(), &[])?;
    let directory = tempfile::tempdir()?;
    let mut store = sqlite_store(&directory, &[earlier.bytes().to_vec()], false)?;
    assert!(case.compose(&mut store).is_ok());
    Ok(())
}

#[test]
fn a_submitted_request_that_pins_no_trust_needs_no_retained_tps1() -> TestResult {
    // ERQ1 pins no trust revision, so a store whose only request is
    // submitted holds no retained TPS1, and composition opens.
    let case = Case::valid()?;
    let directory = tempfile::tempdir()?;
    let mut store = sqlite_store(&directory, &[], true)?;
    assert!(case.compose(&mut store).is_ok());
    Ok(())
}

#[test]
fn a_store_with_requests_opens_only_when_every_retained_tps1_verifies() -> TestResult {
    let case = Case::valid()?;
    let directory = tempfile::tempdir()?;
    let mut store = sqlite_store(&directory, &[case.trust.bytes().to_vec()], true)?;
    assert!(case.compose(&mut store).is_ok());

    // One retained TPS1 the pinned operator key cannot verify.
    let foreign = trust_under(&rotated_operator(), &[])?;
    store.retain_erasure_object(foreign.bytes(), ERASURE_RETAINED_OBJECT_MAX_BYTES_V1)?;
    assert_eq!(
        case.refusal(&mut store),
        Some(LocalErasureCompositionErrorV1::ErasureTrustAnchorRotated)
    );
    Ok(())
}

#[test]
fn an_operator_key_rotation_closes_a_store_with_requests_until_restored() -> TestResult {
    let mut case = Case::valid()?;
    let directory = tempfile::tempdir()?;
    let mut store = sqlite_store(&directory, &[case.trust.bytes().to_vec()], true)?;
    // The release now pins another operator key, under which the bundle's
    // current TPS1 is reissued.
    let restored = case.operator_public_key;
    case.trust = trust_under(&rotated_operator(), &[])?;
    case.operator_public_key = rotated_operator().verifying_key().to_bytes();
    assert_eq!(
        case.refusal(&mut store),
        Some(LocalErasureCompositionErrorV1::ErasureTrustAnchorRotated)
    );
    // Restoring the previous anchor opens the store again.
    case.trust = trust(&[])?;
    case.operator_public_key = restored;
    assert!(case.compose(&mut store).is_ok());
    Ok(())
}
