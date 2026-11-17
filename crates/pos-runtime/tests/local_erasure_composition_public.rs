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
    compiled_local_erasure_policy_v1, ErasureAuthorityReadViewV1, ErasureCoordinatorAuthorityV1,
    ErasureCoordinatorCompositionV1, ErasureExecutionHostV1, LocalErasureCompositionErrorV1,
    LocalErasureCompositionInputsV1, LOCAL_ERASURE_CLASSIFICATION_COUNT_V1,
    LOCAL_ERASURE_CLASSIFICATION_V1, LOCAL_ERASURE_POLICY_REFERENCE_V1,
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
        policy: LOCAL_ERASURE_POLICY_REFERENCE_V1,
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
    execution_binding: Option<LocalErasureExecutionBindingV1>,
    principal_grant: Hash,
    authority_timeline: TimelineId,
    clock: fn() -> u64,
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
            execution_binding: Some(execution_binding()),
            principal_grant: grant_id(),
            authority_timeline: authority_timeline(),
            clock: present,
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
                execution_binding: self.execution_binding.as_ref(),
                principal_grant: self.principal_grant,
                authority_timeline: self.authority_timeline,
                clock: self.clock,
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
    other.policy = ErasureReferenceV1::from_digest([0x99; 32]);
    let mut case = Case::signed(&other, &bundle_root(), &[])?;
    case.execution_binding = None;
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
    let mut repoliced = bundle();
    repoliced.policy = ErasureReferenceV1::from_digest([0x99; 32]);
    let case = Case::signed(&repoliced, &bundle_root(), &[])?;
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

const fn reference(byte: u8) -> ErasureReferenceV1 {
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

#[test]
fn the_compiled_policy_carries_the_owner_constants() -> TestResult {
    let policy = compiled_local_erasure_policy_v1();
    assert_eq!(
        policy.retained_classes,
        [
            pos_core::ArtifactDataClassV1::PublicRecord,
            pos_core::ArtifactDataClassV1::AggregateData,
            pos_core::ArtifactDataClassV1::StructuralAuditMetadata,
        ]
    );
    assert_eq!(
        (
            policy.auto_retry_max,
            policy.quota_attempts,
            policy.store_request_reserve,
            policy.max_reprepare,
        ),
        (3, 64, 512, 3)
    );
    // The encoded ELP1 carries the owner's attempt window, 2 + 16,384.
    let encoded: ciborium::value::Value =
        ciborium::from_reader(policy.to_canonical_cbor()?.as_slice())?;
    let ciborium::value::Value::Array(fields) = encoded else {
        return Err("ELP1 is not an array".into());
    };
    assert_eq!(
        fields.get(4),
        Some(&ciborium::value::Value::Integer(16_386.into()))
    );
    // The pinned digest is the content address of exactly this policy.
    assert_eq!(policy.reference()?, LOCAL_ERASURE_POLICY_REFERENCE_V1);
    Ok(())
}

/// The owner's 48-row table (decisions D1-a to D5 of 2026-11-16 on #1403),
/// as `[artifact_class, data_class, category, ack_class]` codes, written
/// independently of the compiled constant.
const OWNER_CLASSIFICATION: &str = "\
    0,0,0,artifact-store 0,0,0,client-cache-signal 0,0,0,timeline-payload \
    0,0,1,key-registry 0,0,2,local-replica 0,0,3,local-backup-inventory \
    0,1,0,artifact-store 0,1,0,client-cache-signal 0,1,1,key-registry \
    0,1,2,local-replica 0,1,3,local-backup-inventory \
    1,0,0,artifact-store 1,0,1,key-registry 1,0,3,local-backup-inventory \
    1,1,0,artifact-store 1,1,1,key-registry 1,1,3,local-backup-inventory \
    2,0,0,artifact-store 2,0,1,key-registry 2,0,3,local-backup-inventory \
    2,1,0,artifact-store 2,1,1,key-registry 2,1,3,local-backup-inventory \
    3,0,0,managed-report 3,0,1,key-registry 3,0,3,local-backup-inventory \
    3,1,0,managed-report 3,1,1,key-registry 3,1,3,local-backup-inventory \
    4,0,0,artifact-store 4,0,1,key-registry 4,0,3,local-backup-inventory \
    4,1,0,artifact-store 4,1,0,export-recipient 4,1,1,key-registry \
    4,1,3,local-backup-inventory \
    5,0,0,artifact-store 5,0,1,key-registry 5,0,3,local-backup-inventory \
    5,1,0,artifact-store 5,1,1,key-registry 5,1,3,local-backup-inventory \
    6,0,0,managed-report 6,0,1,key-registry 6,0,3,local-backup-inventory \
    6,1,0,managed-report 6,1,1,key-registry 6,1,3,local-backup-inventory";

const ACK_CLASSES: [&str; 8] = [
    "artifact-store",
    "client-cache-signal",
    "export-recipient",
    "key-registry",
    "local-backup-inventory",
    "local-replica",
    "managed-report",
    "timeline-payload",
];

#[test]
fn the_classification_is_exactly_the_owner_table() {
    let owner: Vec<&str> = OWNER_CLASSIFICATION.split_whitespace().collect();
    assert_eq!(owner.len(), 48);
    assert_eq!(LOCAL_ERASURE_CLASSIFICATION_COUNT_V1, 48);
    let rows = compiled_local_erasure_policy_v1().classification;
    assert_eq!(rows.len(), LOCAL_ERASURE_CLASSIFICATION_V1.len());
    // Every combination of the seven artifact classes, five data classes,
    // four categories and eight acknowledgement classes is permitted
    // exactly when the owner table lists it.
    let mut permitted = 0;
    for artifact_class in 0..7_u64 {
        for data_class in 0..5_u64 {
            for category in 0..4_u64 {
                for ack_class in ACK_CLASSES {
                    let key = format!("{artifact_class},{data_class},{category},{ack_class}");
                    let listed = owner.contains(&key.as_str());
                    let compiled = rows.iter().any(|row| {
                        row.artifact_class == artifact_class
                            && u64::from(row.data_class) == data_class
                            && row.category == category
                            && row.ack_class == ack_class
                    });
                    assert_eq!(compiled, listed, "{key}");
                    permitted += usize::from(compiled);
                }
            }
        }
    }
    assert_eq!(permitted, 48);
}

// ---------------------------------------------------------------------------
// ADR-136 §5/§6: `LocalErasureAuthorityV1` and `submit_local_erasure`
// (acceptance tests 3b, 5 and 6, authority parts).
// ---------------------------------------------------------------------------

use pos_core::{
    local_erasure_body_digest_v1, local_erasure_id_v1, local_erasure_request_v1,
    local_erasure_requester_v1, local_erasure_subject_v1, AuthorityGranteeV1,
    AuthorityPersistenceHostV1, AuthorityPersistencePortV1, AuthorityRegistrySnapshotV1,
    AuthorityRoleV1, CapabilityGrantDraftV1, CapabilityGrantV1, CapabilityRevocationDraftV1,
    CapabilityRevocationV1, CapabilityScopeDraftV1, CapabilityScopeV1, DelegateClassV1, EntityId,
    ErasureAcknowledgementOutcomeV1, ErasureAcknowledgementProvenanceInputV1,
    ErasureAdministrativeResolutionActionV1, ErasureAdministrativeResolutionInputV1,
    ErasureApplicabilityDecisionV1, ErasureArtifactClassV1, ErasureCorrectionProvenanceInputV1,
    ErasureFreezeAdmissionEvidenceInputV1, ErasureFreezeApplicabilityRowV1,
    ErasureFreezeAuthorizationEvidenceInputV1, ErasureHostErrorV1, ErasureInventoryCategoryV1,
    ErasureKeyRoleV1, ErasureLifecycleV1, ErasureReceiptInventoriesV1, ErasureReplayClaimV1,
    ErasureRequiredTargetV1, ErasureRetryAdmissionInputV1, ErasureScopeExtensionInputV1,
    LocalErasureAuthorizationV1, LocalErasureIdempotencyV1, LocalErasureOwnerRowV1,
    LocalErasureRejectionV1, LocalErasureSelectorV1, PrincipalRefV1, Seq,
    LOCAL_ERASURE_ATTEMPT_WINDOW_V1,
};
use pos_runtime::{LocalErasureSubmissionV1, LocalErasureSubmitErrorV1};
use ulid::Ulid;

/// The clock of an open deployment, in Unix seconds.
const PRESENT: u64 = 1_000;
/// The test TPS1 `offline_valid_through`, 9999-12-31T23:59:59Z.
const TPS1_EXPIRY: u64 = 253_402_300_799;
/// A nonzero ELB1 expiry.
const BUNDLE_EXPIRY: u64 = 5_000;
/// The compiled request-head reserve.
const RESERVE: usize = 512;

const fn present() -> u64 {
    PRESENT
}

const fn at_trust_expiry() -> u64 {
    TPS1_EXPIRY
}

const fn after_trust_expiry() -> u64 {
    TPS1_EXPIRY + 1
}

const fn at_bundle_expiry() -> u64 {
    BUNDLE_EXPIRY
}

const fn after_bundle_expiry() -> u64 {
    BUNDLE_EXPIRY + 1
}

fn fail<E: std::fmt::Debug>(error: E) -> Box<dyn std::error::Error> {
    format!("{error:?}").into()
}

const fn grant_id() -> Hash {
    Hash::from_bytes([0x71; 32])
}

const fn authority_timeline() -> TimelineId {
    TimelineId::from_ulid(Ulid::from_bytes([0x72; 16]))
}

const fn other_timeline() -> TimelineId {
    TimelineId::from_ulid(Ulid::from_bytes([0x7a; 16]))
}

fn principal() -> TestResult<PrincipalRefV1> {
    PrincipalRefV1::try_new([0x73; 16], "local").map_err(fail)
}

const fn actor() -> EntityId {
    EntityId::from_ulid(Ulid::from_bytes([0x74; 16]))
}

const fn other_actor() -> EntityId {
    EntityId::from_ulid(Ulid::from_bytes([0x7b; 16]))
}

fn principal_ref() -> TestResult<ErasureReferenceV1> {
    let digest = pos_core::fork_authentication::principal_digest_v1(&principal()?).map_err(fail)?;
    Ok(ErasureReferenceV1::from_digest(*digest.as_bytes()))
}

/// A principal the Local Principal delegates to.
fn delegate() -> TestResult<PrincipalRefV1> {
    PrincipalRefV1::try_new([0x7f; 16], "local").map_err(fail)
}

/// The recorded root grant: its resources, actions, actors, Timeline,
/// registry, validity window and delegation depth.
struct GrantShape {
    resources: Vec<String>,
    actions: Vec<String>,
    actors: Vec<EntityId>,
    timeline: TimelineId,
    registry: [u8; 32],
    /// `valid_from_position` and `valid_until_position`.
    valid: (u64, u64),
    max_delegation_depth: u8,
}

impl GrantShape {
    fn standard() -> Self {
        Self {
            resources: vec!["erasure".to_owned(), "timeline".to_owned()],
            actions: vec!["request".to_owned()],
            actors: vec![actor()],
            timeline: authority_timeline(),
            registry: REGISTRY,
            valid: (1, u64::MAX),
            max_delegation_depth: 0,
        }
    }

    fn root_grant(&self) -> TestResult<CapabilityGrantV1> {
        self.grant(grant_id(), 1, None)
    }

    /// A grant of this shape issued at `issuance`: the Principal's root
    /// grant to itself, or with `parent` the Principal's delegation of
    /// `parent` to [`delegate`].
    fn grant(
        &self,
        id: Hash,
        issuance: u64,
        parent: Option<Hash>,
    ) -> TestResult<CapabilityGrantV1> {
        let principal = principal()?;
        let grantee = if parent.is_some() {
            delegate()?
        } else {
            principal.clone()
        };
        let depth = u8::from(parent.is_some());
        let scope = CapabilityScopeV1::try_from_draft(CapabilityScopeDraftV1 {
            resources: self.resources.clone(),
            actions: self.actions.clone(),
            purposes: vec!["operation".to_owned()],
            audiences: vec!["gateway".to_owned()],
            actor_entity_ids: self.actors.clone(),
            subject_ids: Vec::new(),
            participant_ids: Vec::new(),
            plugin_id: None,
            principal_roles: vec![AuthorityRoleV1::Actor],
            max_uses: 1,
            budget: 1,
            environment_constraints: Vec::new(),
        })
        .map_err(fail)?;
        CapabilityGrantV1::try_from_draft(CapabilityGrantDraftV1 {
            grant_id: id,
            grantor: principal.clone(),
            grantee: AuthorityGranteeV1::Principal(grantee),
            trust_domain: principal.trust_domain().to_owned(),
            scope,
            valid_from_position: Seq::from_u64(self.valid.0.max(issuance)),
            valid_until_position: Seq::from_u64(self.valid.1),
            parent_grant_id: parent,
            delegation_depth: depth,
            max_delegation_depth: self.max_delegation_depth,
            permitted_delegate_classes: if self.max_delegation_depth > depth {
                vec![DelegateClassV1::Principal]
            } else {
                Vec::new()
            },
            consent_references: Vec::new(),
            policy_revision: Hash::from_bytes([0x75; 32]),
            issuance_timeline: self.timeline,
            issuance_seq: Seq::from_u64(issuance),
            revocation_epoch: 0,
            revocation_fence: None,
            authority_registry_digest: Hash::from_bytes(self.registry),
        })
        .map_err(fail)
    }
}

/// An authority-persistence host over the registry of the first of
/// `grants` that attests all of them, bound to `store`.
fn bound_authority_host(
    store: &mut SqliteStore,
    grants: &[&CapabilityGrantV1],
) -> TestResult<AuthorityPersistenceHostV1> {
    let mut bindings = Vec::with_capacity(grants.len());
    for grant in grants {
        bindings.push(grant.binding_digest().map_err(fail)?);
    }
    bindings.sort_unstable();
    let registry = AuthorityRegistrySnapshotV1::try_new(
        grants
            .first()
            .ok_or("no grant")?
            .authority_registry_digest(),
        vec![Hash::from_bytes([0x76; 32])],
        bindings,
        Vec::new(),
    )
    .map_err(fail)?;
    let host = AuthorityPersistenceHostV1::new(&registry);
    store
        .bind_authority_persistence(host.persistence_binding())
        .map_err(fail)?;
    Ok(host)
}

/// A provisioned `SQLite` store that records the root grant of `shape`.
struct LocalStore {
    _directory: tempfile::TempDir,
    path: String,
    /// The root-grant chain head the store records.
    head: u64,
}

impl LocalStore {
    fn new(shape: &GrantShape) -> TestResult<Self> {
        Self::with_later_grants(shape, &[])
    }

    /// A store that records the root grant of `shape`, then each of
    /// `later` in order.
    fn with_later_grants(shape: &GrantShape, later: &[CapabilityGrantV1]) -> TestResult<Self> {
        let directory = tempfile::tempdir()?;
        let path = directory
            .path()
            .join("local-erasure.sqlite3")
            .to_str()
            .ok_or("temporary database path is not UTF-8")?
            .to_owned();
        let mut store = SqliteStore::open(&path)?;
        store.bind_erasure_gate(Arc::new(ErasureContainmentGateV1::new_test_open()))?;
        store.init_erasure_store_identity(Hash::from_bytes(STORE_IDENTITY))?;
        register_signer(&mut store, &erasure_signer(), 1)?;
        let grant = shape.root_grant()?;
        let grants = std::iter::once(&grant).chain(later).collect::<Vec<_>>();
        let host = bound_authority_host(&mut store, &grants)?;
        for grant in grants {
            let permit = host.authorize_grant(grant).map_err(fail)?;
            store.issue_capability_grant(permit, grant).map_err(fail)?;
        }
        let head = store
            .load_authority(grant_id())
            .map_err(fail)?
            .head_position()
            .as_u64();
        Ok(Self {
            _directory: directory,
            path,
            head,
        })
    }

    /// Revoke the root grant of `shape` with a fence one past the recorded
    /// chain head; the chain head advances to that fence.
    fn revoke(&self, shape: &GrantShape) -> TestResult {
        let mut store = SqliteStore::open(&self.path)?;
        store.bind_erasure_gate(Arc::new(ErasureContainmentGateV1::new_test_open()))?;
        let grant = shape.root_grant()?;
        let host = bound_authority_host(&mut store, &[&grant])?;
        let revocation = CapabilityRevocationV1::try_from_draft(CapabilityRevocationDraftV1 {
            grant_id: grant.grant_id(),
            authority_timeline: grant.issuance_timeline(),
            fence_position: Seq::from_u64(self.head + 1),
            revocation_epoch: 1,
            policy_revision: grant.policy_revision(),
            authority_registry_digest: grant.authority_registry_digest(),
        })
        .map_err(fail)?;
        let permit = host
            .authorize_revocation(&grant, &revocation)
            .map_err(fail)?;
        store
            .revoke_capability_grant(permit, &revocation)
            .map_err(fail)?;
        Ok(())
    }

    /// Retain `objects` in the store's erasure object store.
    fn retain(&self, objects: &[Vec<u8>]) -> TestResult {
        let mut store = SqliteStore::open(&self.path)?;
        store.bind_erasure_gate(Arc::new(ErasureContainmentGateV1::new_test_open()))?;
        for object in objects {
            store.retain_erasure_object(object, ERASURE_RETAINED_OBJECT_MAX_BYTES_V1)?;
        }
        Ok(())
    }

    /// Compose `case` over the store and open a host over it.
    fn host(&self, case: &Case, maximum_requests: usize) -> TestResult<ErasureExecutionHostV1> {
        let composition = {
            let mut store = SqliteStore::open(&self.path)?;
            store.bind_erasure_gate(Arc::new(ErasureContainmentGateV1::new_test_open()))?;
            case.compose(&mut store).map_err(fail)?
        };
        Ok(ErasureExecutionHostV1::open_with_authority(
            StoreConfig::Sqlite {
                path: self.path.clone(),
            },
            &composition,
            ErasureRecoveryLimitsV1::from_maximum_requests(maximum_requests)?,
        )?)
    }
}

fn submission(key: u8, scope: ErasureScopeV1) -> TestResult<LocalErasureSubmissionV1> {
    Ok(LocalErasureSubmissionV1 {
        principal: principal()?,
        actor: actor(),
        scope,
        idempotency_key_digest: reference(key),
    })
}

/// The ERQ1 request reference the host derives for Idempotency-Key `key`.
fn request_of(key: u8) -> TestResult<ErasureReferenceV1> {
    Ok(local_erasure_request_v1(local_erasure_id_v1(
        principal_ref()?,
        actor(),
        reference(key),
    )?)?)
}

/// The ERAZ1 the host builds for key `key` at chain head `head`.
fn authorization(key: u8, head: u64) -> TestResult<LocalErasureAuthorizationV1> {
    authorization_at(key, head, 0)
}

/// The ERAZ1 the host builds for key `key` at chain head `head` and
/// revocation epoch `epoch`.
fn authorization_at(key: u8, head: u64, epoch: u64) -> TestResult<LocalErasureAuthorizationV1> {
    Ok(LocalErasureAuthorizationV1 {
        principal_ref: principal_ref()?,
        actor_entity: actor(),
        operation: "erasure.request".to_owned(),
        authority_registry_digest: ErasureReferenceV1::from_digest(REGISTRY),
        authority_chain: authority_timeline(),
        chain_head_position: head,
        revocation_epoch: epoch,
        erq1_request: request_of(key)?,
    })
}

/// An authorize-stage ELREJ1 for the request of key `key`.
fn rejection(key: u8) -> TestResult<LocalErasureRejectionV1> {
    Ok(LocalErasureRejectionV1 {
        request: request_of(key)?,
        error: ErasureErrorV1::Unauthorized,
    })
}

fn rejected(store: &LocalStore, keys: &[u8]) -> TestResult {
    let mut objects = Vec::new();
    for key in keys {
        objects.push(rejection(*key)?.to_canonical_cbor()?);
    }
    store.retain(&objects)
}

fn local_case() -> TestResult<Case> {
    Case::valid()
}

#[test]
fn a_local_submission_is_derived_idempotent_and_bound_to_its_body() -> TestResult {
    let store = LocalStore::new(&GrantShape::standard())?;
    let mut host = store.host(&local_case()?, 4_096)?;
    let mut sender = host.command_sender()?;
    let state = sender
        .submit_local_erasure(&submission(1, ErasureScopeV1::PrivateSubjectData)?)
        .map_err(fail)?;
    assert_eq!(state.lifecycle(), ErasureLifecycleV1::Submitted);
    // An exact retry returns the original state.
    assert_eq!(
        sender.submit_local_erasure(&submission(1, ErasureScopeV1::PrivateSubjectData)?),
        Ok(state)
    );
    // The same key with another body, or a retained-only scope, conflicts.
    assert_eq!(
        sender.submit_local_erasure(&submission(1, ErasureScopeV1::ConsentedSharedData)?),
        Err(LocalErasureSubmitErrorV1::Host(
            ErasureHostErrorV1::Conflict
        ))
    );
    assert_eq!(
        sender.submit_local_erasure(&submission(2, ErasureScopeV1::PublicRecord)?),
        Err(LocalErasureSubmitErrorV1::Host(
            ErasureHostErrorV1::Conflict
        ))
    );
    // A Timeline created while the request is submitted stays unaffected,
    // and the store recovers with the request after a restart.
    let _created = sender.create_timeline("after-submission")?;
    drop(host);
    let host = store.host(&local_case()?, 4_096)?;
    assert_eq!(host.status(), pos_runtime::ErasureHostStatusV1::Ready);
    Ok(())
}

#[test]
fn a_subject_has_one_pre_terminal_request() -> TestResult {
    let store = LocalStore::new(&GrantShape::standard())?;
    let mut host = store.host(&local_case()?, 4_096)?;
    let mut sender = host.command_sender()?;
    sender
        .submit_local_erasure(&submission(1, ErasureScopeV1::PrivateSubjectData)?)
        .map_err(fail)?;
    assert_eq!(
        sender.submit_local_erasure(&submission(2, ErasureScopeV1::ConsentedSharedData)?),
        Err(LocalErasureSubmitErrorV1::Concurrent)
    );
    let authorized = sender
        .authorize_erasure_request(request_of(1)?, authorization(1, store.head)?.reference()?)?;
    assert_eq!(authorized.lifecycle(), ErasureLifecycleV1::Authorized);
    assert_eq!(
        sender.submit_local_erasure(&submission(2, ErasureScopeV1::PrivateSubjectData)?),
        Err(LocalErasureSubmitErrorV1::Concurrent)
    );
    Ok(())
}

#[test]
fn the_subject_quota_admits_exactly_its_share() -> TestResult {
    // One actor and 514 request heads: q_subject = (514 - 512) / 1 = 2.
    let store = LocalStore::new(&GrantShape::standard())?;
    rejected(&store, &[1, 2])?;
    let mut host = store.host(&local_case()?, RESERVE + 2)?;
    let mut sender = host.command_sender()?;
    for key in [1, 2] {
        sender
            .submit_local_erasure(&submission(key, ErasureScopeV1::PrivateSubjectData)?)
            .map_err(fail)?;
        let state =
            sender.reject_erasure_request(request_of(key)?, rejection(key)?.reference()?)?;
        assert_eq!(state.lifecycle(), ErasureLifecycleV1::Rejected);
    }
    assert_eq!(
        sender.submit_local_erasure(&submission(3, ErasureScopeV1::PrivateSubjectData)?),
        Err(LocalErasureSubmitErrorV1::QuotaExhausted)
    );
    Ok(())
}

#[test]
fn the_quota_is_shared_by_the_principals_actors() -> TestResult {
    // Two actors and 514 request heads: q_subject = (514 - 512) / 2 = 1.
    let mut shape = GrantShape::standard();
    shape.actors = [actor(), other_actor()].into_iter().collect();
    shape.actors.sort_unstable();
    let store = LocalStore::new(&shape)?;
    rejected(&store, &[1])?;
    let mut host = store.host(&local_case()?, RESERVE + 2)?;
    let mut sender = host.command_sender()?;
    sender
        .submit_local_erasure(&submission(1, ErasureScopeV1::PrivateSubjectData)?)
        .map_err(fail)?;
    sender.reject_erasure_request(request_of(1)?, rejection(1)?.reference()?)?;
    assert_eq!(
        sender.submit_local_erasure(&submission(2, ErasureScopeV1::PrivateSubjectData)?),
        Err(LocalErasureSubmitErrorV1::QuotaExhausted)
    );
    Ok(())
}

#[test]
fn authorization_names_the_requests_own_evidence() -> TestResult {
    let store = LocalStore::new(&GrantShape::standard())?;
    // An ELREJ1 of another request is retained, not one of request 1.
    rejected(&store, &[2])?;
    let mut host = store.host(&local_case()?, 4_096)?;
    let mut sender = host.command_sender()?;
    sender
        .submit_local_erasure(&submission(1, ErasureScopeV1::PrivateSubjectData)?)
        .map_err(fail)?;
    let request = request_of(1)?;
    assert_eq!(
        sender.authorize_erasure_request(request, reference(0x99)),
        Err(ErasureHostErrorV1::Conflict)
    );
    assert_eq!(
        sender.reject_erasure_request(request, reference(0x99)),
        Err(ErasureHostErrorV1::Conflict)
    );
    assert_eq!(
        sender.reject_erasure_request(request, rejection(2)?.reference()?),
        Err(ErasureHostErrorV1::Conflict)
    );
    assert_eq!(
        sender
            .authorize_erasure_request(request, authorization(1, store.head)?.reference()?)?
            .lifecycle(),
        ErasureLifecycleV1::Authorized
    );
    Ok(())
}

#[test]
fn a_root_grant_revocation_leaves_older_requests_authorized() -> TestResult {
    let shape = GrantShape::standard();
    let store = LocalStore::new(&shape)?;
    {
        let mut host = store.host(&local_case()?, 4_096)?;
        host.command_sender()?
            .submit_local_erasure(&submission(1, ErasureScopeV1::PrivateSubjectData)?)
            .map_err(fail)?;
    }
    // The revocation is fenced at position + 1 of the head request 1 is
    // bound to, the last fence that still leaves that position authorized.
    store.revoke(&shape)?;
    let mut host = store.host(&local_case()?, 4_096)?;
    let mut sender = host.command_sender()?;
    assert_eq!(
        sender
            .authorize_erasure_request(request_of(1)?, authorization(1, store.head)?.reference()?)?
            .lifecycle(),
        ErasureLifecycleV1::Authorized
    );
    Ok(())
}

#[test]
fn a_fresh_submission_after_a_root_grant_revocation_is_unauthorized() -> TestResult {
    let shape = GrantShape::standard();
    let store = LocalStore::new(&shape)?;
    store.revoke(&shape)?;
    let mut host = store.host(&local_case()?, 4_096)?;
    assert_eq!(
        host.command_sender()?
            .submit_local_erasure(&submission(1, ErasureScopeV1::PrivateSubjectData)?),
        Err(LocalErasureSubmitErrorV1::Host(
            ErasureHostErrorV1::AuthorizationDenied
        ))
    );
    Ok(())
}

#[test]
fn a_replay_is_answered_only_to_an_authorized_caller() -> TestResult {
    let shape = GrantShape::standard();
    let store = LocalStore::new(&shape)?;
    let state = {
        let mut host = store.host(&local_case()?, 4_096)?;
        let mut sender = host.command_sender()?;
        let state = sender
            .submit_local_erasure(&submission(1, ErasureScopeV1::PrivateSubjectData)?)
            .map_err(fail)?;
        // While the root grant authorizes the actor, the exact retry
        // returns the original state.
        assert_eq!(
            sender.submit_local_erasure(&submission(1, ErasureScopeV1::PrivateSubjectData)?),
            Ok(state.clone())
        );
        // While the grant is still valid, another Principal replaying the
        // key is refused for the Principal mismatch alone.
        let mut stranger = submission(1, ErasureScopeV1::PrivateSubjectData)?;
        stranger.principal = delegate()?;
        assert_eq!(
            sender.submit_local_erasure(&stranger),
            Err(LocalErasureSubmitErrorV1::Host(
                ErasureHostErrorV1::AuthorizationDenied
            ))
        );
        state
    };
    assert_eq!(state.lifecycle(), ErasureLifecycleV1::Submitted);
    // Once the root grant is revoked, neither the exact retry nor the same
    // key with another body learns the installed request: both are refused
    // as unauthorized, not answered with the state or a conflict.
    store.revoke(&shape)?;
    let mut host = store.host(&local_case()?, 4_096)?;
    let mut sender = host.command_sender()?;
    for scope in [
        ErasureScopeV1::PrivateSubjectData,
        ErasureScopeV1::ConsentedSharedData,
    ] {
        assert_eq!(
            sender.submit_local_erasure(&submission(1, scope)?),
            Err(LocalErasureSubmitErrorV1::Host(
                ErasureHostErrorV1::AuthorizationDenied
            ))
        );
    }
    Ok(())
}

#[test]
fn an_exact_retry_is_answered_after_new_admissions_close() -> TestResult {
    let mut case = local_case()?;
    let store = LocalStore::new(&GrantShape::standard())?;
    case.clock = at_trust_expiry;
    let state = {
        let mut host = store.host(&case, 4_096)?;
        host.command_sender()?
            .submit_local_erasure(&submission(1, ErasureScopeV1::PrivateSubjectData)?)
            .map_err(fail)?
    };
    // Expiry closes new admissions only: the exact retry of the installed
    // request returns its original state, while a fresh request is refused
    // before the subject checks would answer `Concurrent`.
    case.clock = after_trust_expiry;
    let mut host = store.host(&case, 4_096)?;
    let mut sender = host.command_sender()?;
    assert_eq!(
        sender.submit_local_erasure(&submission(1, ErasureScopeV1::PrivateSubjectData)?),
        Ok(state)
    );
    assert_eq!(
        sender.submit_local_erasure(&submission(2, ErasureScopeV1::PrivateSubjectData)?),
        Err(LocalErasureSubmitErrorV1::Host(
            ErasureHostErrorV1::RecoveryUnavailable
        ))
    );
    Ok(())
}

#[test]
fn a_root_grant_admits_the_last_position_of_its_window() -> TestResult {
    // `valid_until` one past the recorded chain head still admits: the
    // window is half-open. A later grant moving the head onto
    // `valid_until` refuses (`the_root_grant_must_match_...`).
    let mut shape = GrantShape::standard();
    shape.valid = (1, 2);
    let store = LocalStore::new(&shape)?;
    assert_eq!(store.head + 1, 2);
    let mut host = store.host(&local_case()?, 4_096)?;
    let state = host
        .command_sender()?
        .submit_local_erasure(&submission(1, ErasureScopeV1::PrivateSubjectData)?)
        .map_err(fail)?;
    assert_eq!(state.lifecycle(), ErasureLifecycleV1::Submitted);
    Ok(())
}

#[test]
fn an_expired_bundle_closes_new_admissions_but_not_a_rejection() -> TestResult {
    let mut expiring = bundle();
    expiring.expiry = BUNDLE_EXPIRY;
    let mut case = Case::signed(&expiring, &bundle_root(), &[])?;
    let store = LocalStore::new(&GrantShape::standard())?;
    rejected(&store, &[1])?;
    // At the expiry instant the bundle still admits.
    case.clock = at_bundle_expiry;
    {
        let mut host = store.host(&case, 4_096)?;
        host.command_sender()?
            .submit_local_erasure(&submission(1, ErasureScopeV1::PrivateSubjectData)?)
            .map_err(fail)?;
    }
    // One second later it authorizes nothing new, rejects, and admits no
    // new submission.
    case.clock = after_bundle_expiry;
    let mut host = store.host(&case, 4_096)?;
    let mut sender = host.command_sender()?;
    assert_eq!(
        sender
            .authorize_erasure_request(request_of(1)?, authorization(1, store.head)?.reference()?),
        Err(ErasureHostErrorV1::RecoveryUnavailable)
    );
    assert_eq!(
        sender
            .reject_erasure_request(request_of(1)?, rejection(1)?.reference()?)?
            .lifecycle(),
        ErasureLifecycleV1::Rejected
    );
    assert_eq!(
        sender.submit_local_erasure(&submission(2, ErasureScopeV1::PrivateSubjectData)?),
        Err(LocalErasureSubmitErrorV1::Host(
            ErasureHostErrorV1::RecoveryUnavailable
        ))
    );
    Ok(())
}

#[test]
fn an_expired_tps1_closes_new_admissions() -> TestResult {
    let mut case = local_case()?;
    assert_eq!(case.trust.expiry(), TPS1_EXPIRY);
    let store = LocalStore::new(&GrantShape::standard())?;
    rejected(&store, &[1])?;
    case.clock = at_trust_expiry;
    {
        let mut host = store.host(&case, 4_096)?;
        let mut sender = host.command_sender()?;
        sender
            .submit_local_erasure(&submission(1, ErasureScopeV1::PrivateSubjectData)?)
            .map_err(fail)?;
        sender.reject_erasure_request(request_of(1)?, rejection(1)?.reference()?)?;
    }
    case.clock = after_trust_expiry;
    let mut host = store.host(&case, 4_096)?;
    assert_eq!(
        host.command_sender()?
            .submit_local_erasure(&submission(2, ErasureScopeV1::PrivateSubjectData)?),
        Err(LocalErasureSubmitErrorV1::Host(
            ErasureHostErrorV1::RecoveryUnavailable
        ))
    );
    Ok(())
}

#[test]
fn submission_needs_a_local_composition_and_its_principal() -> TestResult {
    let mut closed = ErasureExecutionHostV1::open_verified_empty(
        StoreConfig::Memory,
        ErasureRecoveryLimitsV1::compiled_maximum(),
    )?;
    assert_eq!(
        closed
            .command_sender()?
            .submit_local_erasure(&submission(1, ErasureScopeV1::PrivateSubjectData)?),
        Err(LocalErasureSubmitErrorV1::Host(
            ErasureHostErrorV1::AuthorizationDenied
        ))
    );
    // A composition naming a root grant the store does not record.
    let store = LocalStore::new(&GrantShape::standard())?;
    let mut case = local_case()?;
    case.principal_grant = Hash::from_bytes([0x7c; 32]);
    let mut host = store.host(&case, 4_096)?;
    assert_eq!(
        host.command_sender()?
            .submit_local_erasure(&submission(1, ErasureScopeV1::PrivateSubjectData)?),
        Err(LocalErasureSubmitErrorV1::Host(
            ErasureHostErrorV1::AuthorizationDenied
        ))
    );
    Ok(())
}

/// Assert that `submission` is refused with `error` and retains no ELIDEM1
/// of key 1, nor the ELSEL1 and the ERAZ1 the Principal's own submission
/// of key 1 would, at the recorded head or after a revocation moved the
/// head one past it.
fn refused_without_retention(
    store: &LocalStore,
    host: &mut ErasureExecutionHostV1,
    submission: &LocalErasureSubmissionV1,
    error: ErasureHostErrorV1,
) -> TestResult {
    assert_eq!(
        host.command_sender()?.submit_local_erasure(submission),
        Err(LocalErasureSubmitErrorV1::Host(error))
    );
    let subject = local_erasure_subject_v1(principal_ref()?, actor())?;
    let view = host.authority_view()?;
    for object in [
        authorization(1, store.head)?.reference()?,
        authorization_at(1, store.head + 1, 1)?.reference()?,
        LocalErasureSelectorV1 { subject }.reference()?,
        idempotency(1)?.reference()?,
    ] {
        assert_eq!(view.retained_object(object), None);
    }
    Ok(())
}

#[test]
fn the_root_grant_must_match_the_composition_and_name_the_operation() -> TestResult {
    let refused = |shape: GrantShape, later: &[CapabilityGrantV1], case: &Case| -> TestResult {
        let store = LocalStore::with_later_grants(&shape, later)?;
        let mut host = store.host(case, 4_096)?;
        refused_without_retention(
            &store,
            &mut host,
            &submission(1, ErasureScopeV1::PrivateSubjectData)?,
            ErasureHostErrorV1::AuthorizationDenied,
        )
    };
    let case = local_case()?;
    let mut shape = GrantShape::standard();
    shape.resources = vec!["timeline".to_owned()];
    refused(shape, &[], &case)?;
    let mut shape = GrantShape::standard();
    shape.actions = vec!["read".to_owned()];
    refused(shape, &[], &case)?;
    let mut shape = GrantShape::standard();
    shape.actors = vec![other_actor()];
    refused(shape, &[], &case)?;
    let mut shape = GrantShape::standard();
    shape.registry = [0x77; 32];
    refused(shape, &[], &case)?;
    // A root grant on another authority Timeline than the composition's.
    let mut shape = GrantShape::standard();
    shape.timeline = other_timeline();
    refused(shape, &[], &case)?;
    // A root grant not yet valid at the chain head.
    let mut shape = GrantShape::standard();
    shape.valid = (2, u64::MAX);
    refused(shape, &[], &case)?;
    // A root grant whose window closed when a later grant on its Timeline
    // moved the chain head to 2.
    let later = GrantShape::standard().grant(Hash::from_bytes([0x7e; 32]), 2, None)?;
    let mut shape = GrantShape::standard();
    shape.valid = (1, 2);
    refused(shape, &[later], &case)?;
    // A delegated grant is no root grant, although its grantor is the
    // Principal.
    let mut shape = GrantShape::standard();
    shape.actions = vec![
        pos_core::DELEGATE_ACTION_V1.to_owned(),
        "request".to_owned(),
    ];
    shape.max_delegation_depth = 1;
    let child = shape.grant(Hash::from_bytes([0x7d; 32]), 2, Some(grant_id()))?;
    let mut delegated = local_case()?;
    delegated.principal_grant = child.grant_id();
    refused(shape, &[child], &delegated)?;
    Ok(())
}

#[test]
fn a_refused_submission_retains_nothing() -> TestResult {
    // Another Principal than the root grant's.
    let store = LocalStore::new(&GrantShape::standard())?;
    let mut host = store.host(&local_case()?, 4_096)?;
    let mut stranger = submission(1, ErasureScopeV1::PrivateSubjectData)?;
    stranger.principal = delegate()?;
    refused_without_retention(
        &store,
        &mut host,
        &stranger,
        ErasureHostErrorV1::AuthorizationDenied,
    )?;
    // A composition whose TPS1 has expired.
    drop(host);
    let mut expired = local_case()?;
    expired.clock = after_trust_expiry;
    let mut host = store.host(&expired, 4_096)?;
    refused_without_retention(
        &store,
        &mut host,
        &submission(1, ErasureScopeV1::PrivateSubjectData)?,
        ErasureHostErrorV1::RecoveryUnavailable,
    )?;
    // A revoked root grant.
    let shape = GrantShape::standard();
    let store = LocalStore::new(&shape)?;
    store.revoke(&shape)?;
    let mut host = store.host(&local_case()?, 4_096)?;
    refused_without_retention(
        &store,
        &mut host,
        &submission(1, ErasureScopeV1::PrivateSubjectData)?,
        ErasureHostErrorV1::AuthorizationDenied,
    )?;
    // The same store admits the Principal's own submission.
    let store = LocalStore::new(&GrantShape::standard())?;
    let mut host = store.host(&local_case()?, 4_096)?;
    host.command_sender()?
        .submit_local_erasure(&submission(1, ErasureScopeV1::PrivateSubjectData)?)
        .map_err(fail)?;
    assert!(host
        .authority_view()?
        .retained_object(idempotency(1)?.reference()?)
        .is_some());
    Ok(())
}

/// The parts of one ERQ1 a root submits through the plain
/// `submit_erasure_request`.
struct PlainRequest {
    input: ErasureRequestInputV1,
}

impl PlainRequest {
    /// The valid ERQ1 of key `key`, whose ERAZ1, ELSEL1 and ELIDEM1 are
    /// retained by [`Self::objects`].
    fn valid(key: u8, head: u64) -> TestResult<Self> {
        let subject = local_erasure_subject_v1(principal_ref()?, actor())?;
        Ok(Self {
            input: ErasureRequestInputV1 {
                request: request_of(key)?,
                subject,
                scope: ErasureScopeV1::PrivateSubjectData,
                selectors: vec![LocalErasureSelectorV1 { subject }.reference()?],
                requester: local_erasure_requester_v1(principal_ref()?)?,
                authorization: authorization(key, head)?.reference()?,
                policy: LOCAL_ERASURE_POLICY_REFERENCE_V1,
                request_position: 0,
                horizon_position: LOCAL_ERASURE_ATTEMPT_WINDOW_V1,
                provenance: idempotency(key)?.reference()?,
            },
        })
    }

    fn with_authorization(
        key: u8,
        authorization: &LocalErasureAuthorizationV1,
        head: u64,
    ) -> TestResult<Self> {
        let mut request = Self::valid(key, head)?;
        request.input.authorization = authorization.reference()?;
        Ok(request)
    }

    fn submit(
        self,
        host: &mut ErasureExecutionHostV1,
    ) -> Result<ErasureLifecycleV1, ErasureHostErrorV1> {
        let request =
            ErasureRequestV1::new(self.input).map_err(|_| ErasureHostErrorV1::Conflict)?;
        let provenance = request.provenance();
        host.command_sender()?
            .submit_erasure_request(request, provenance)
            .map(|state| state.lifecycle())
    }
}

fn idempotency(key: u8) -> TestResult<LocalErasureIdempotencyV1> {
    Ok(LocalErasureIdempotencyV1 {
        idempotency_key_digest: reference(key),
        body_digest: local_erasure_body_digest_v1(ErasureScopeV1::PrivateSubjectData)?,
    })
}

/// A store retaining the valid ERAZ1, ELSEL1 and ELIDEM1 of key 1 plus
/// `extra`, and a host over it.
fn plain_host(
    extra: &[LocalErasureAuthorizationV1],
) -> TestResult<(LocalStore, ErasureExecutionHostV1)> {
    let store = LocalStore::new(&GrantShape::standard())?;
    let subject = local_erasure_subject_v1(principal_ref()?, actor())?;
    let mut objects = vec![
        authorization(1, store.head)?.to_canonical_cbor()?,
        LocalErasureSelectorV1 { subject }.to_canonical_cbor()?,
        idempotency(1)?.to_canonical_cbor()?,
    ];
    for record in extra {
        objects.push(record.to_canonical_cbor()?);
    }
    store.retain(&objects)?;
    let host = store.host(&local_case()?, 4_096)?;
    Ok((store, host))
}

#[test]
fn the_authority_recomputes_every_eraz1_rule_of_a_plain_submission() -> TestResult {
    let head = LocalStore::new(&GrantShape::standard())?.head;
    let changes: [&dyn Fn(&mut LocalErasureAuthorizationV1); 8] = [
        &|record| record.principal_ref = reference(0x81),
        &|record| "erasure.read".clone_into(&mut record.operation),
        &|record| record.authority_registry_digest = reference(0x82),
        &|record| record.authority_chain = other_timeline(),
        &|record| record.erq1_request = reference(0x83),
        &|record| record.actor_entity = other_actor(),
        &|record| record.chain_head_position = head + 1,
        &|record| record.revocation_epoch = 1,
    ];
    let mut tampered = Vec::new();
    for change in changes {
        let mut record = authorization(1, head)?;
        change(&mut record);
        tampered.push(record);
    }
    let (store, mut host) = plain_host(&tampered)?;
    assert_eq!(store.head, head);
    // Every ERAZ1 that breaks a rule, or is not retained, is unauthorized.
    for record in &tampered {
        assert_eq!(
            PlainRequest::with_authorization(1, record, head)?.submit(&mut host),
            Err(ErasureHostErrorV1::AuthorizationDenied)
        );
    }
    let mut missing = PlainRequest::valid(1, head)?;
    missing.input.authorization = reference(0x85);
    assert_eq!(
        missing.submit(&mut host),
        Err(ErasureHostErrorV1::AuthorizationDenied)
    );
    Ok(())
}

#[test]
fn the_authority_recomputes_every_erq1_field_of_a_plain_submission() -> TestResult {
    let head = LocalStore::new(&GrantShape::standard())?.head;
    let mut rebound = authorization(1, head)?;
    rebound.erq1_request = reference(0x84);
    let (_store, mut host) = plain_host(std::slice::from_ref(&rebound))?;
    // Every ERQ1 field the host derives is recomputed; a mismatch conflicts.
    let changes: [&dyn Fn(&mut ErasureRequestInputV1); 8] = [
        &|input| input.subject = reference(0x86),
        &|input| input.selectors = vec![reference(0x87)],
        &|input| input.requester = reference(0x88),
        &|input| input.policy = reference(0x89),
        &|input| input.scope = ErasureScopeV1::ConsentedSharedData,
        &|input| input.request_position = 1,
        &|input| input.horizon_position = LOCAL_ERASURE_ATTEMPT_WINDOW_V1 + 1,
        &|input| input.provenance = reference(0x8a),
    ];
    for change in changes {
        let mut request = PlainRequest::valid(1, head)?;
        change(&mut request.input);
        assert_eq!(request.submit(&mut host), Err(ErasureHostErrorV1::Conflict));
    }
    // An ERAZ1 bound to a request id the key does not derive conflicts.
    let mut rebound_request = PlainRequest::with_authorization(1, &rebound, head)?;
    rebound_request.input.request = reference(0x84);
    assert_eq!(
        rebound_request.submit(&mut host),
        Err(ErasureHostErrorV1::Conflict)
    );
    // The valid plain submission is admitted; a second one for the subject
    // is refused while the first is pre-terminal.
    assert_eq!(
        PlainRequest::valid(1, head)?.submit(&mut host),
        Ok(ErasureLifecycleV1::Submitted)
    );
    assert_eq!(
        host.command_sender()?
            .submit_local_erasure(&submission(2, ErasureScopeV1::PrivateSubjectData)?),
        Err(LocalErasureSubmitErrorV1::Concurrent)
    );
    Ok(())
}

#[test]
fn a_plain_submission_cannot_bypass_the_subject_checks() -> TestResult {
    let store = LocalStore::new(&GrantShape::standard())?;
    let head = store.head;
    let subject = local_erasure_subject_v1(principal_ref()?, actor())?;
    store.retain(&[
        authorization(2, head)?.to_canonical_cbor()?,
        LocalErasureSelectorV1 { subject }.to_canonical_cbor()?,
        idempotency(2)?.to_canonical_cbor()?,
        rejection(1)?.to_canonical_cbor()?,
    ])?;
    // One request head over the reserve: the subject's quota is 1.
    let mut host = store.host(&local_case()?, RESERVE + 1)?;
    {
        let mut sender = host.command_sender()?;
        sender
            .submit_local_erasure(&submission(1, ErasureScopeV1::PrivateSubjectData)?)
            .map_err(fail)?;
    }
    // While request 1 is pre-terminal a plain request 2 is refused.
    assert_eq!(
        PlainRequest::valid(2, head)?.submit(&mut host),
        Err(ErasureHostErrorV1::Conflict)
    );
    // Once request 1 is rejected the quota still refuses it.
    host.command_sender()?
        .reject_erasure_request(request_of(1)?, rejection(1)?.reference()?)?;
    assert_eq!(
        PlainRequest::valid(2, head)?.submit(&mut host),
        Err(ErasureHostErrorV1::Conflict)
    );
    Ok(())
}

/// The bundle naming `owner` as its one `key-registry` owner.
fn single_owner_bundle(owner: ErasureReferenceV1) -> LocalErasureBundleV1 {
    let mut with_owner = bundle();
    with_owner.owners = vec![LocalErasureOwnerRowV1 {
        category: 1,
        ack_class: "key-registry".to_owned(),
        owner_ref: owner,
    }];
    with_owner
}

/// The composed Local authority over a provisioned store whose bundle
/// names one `key-registry` owner, and a host-built view of that store.
fn local_authority() -> TestResult<(
    LocalStore,
    ErasureCoordinatorCompositionV1,
    ErasureExecutionHostV1,
    ErasureReferenceV1,
)> {
    let store = LocalStore::new(&GrantShape::standard())?;
    let owner = pos_core::local_erasure_owner_ref_v1(
        ErasureReferenceV1::from_digest(STORE_IDENTITY),
        1,
        "key-registry",
    )?;
    let case = Case::signed(&single_owner_bundle(owner), &bundle_root(), &[])?;
    let composition = {
        let mut sqlite = SqliteStore::open(&store.path)?;
        sqlite.bind_erasure_gate(Arc::new(ErasureContainmentGateV1::new_test_open()))?;
        case.compose(&mut sqlite).map_err(fail)?
    };
    let host = store.host(&case, 4_096)?;
    Ok((store, composition, host, owner))
}

#[test]
fn the_local_authority_refuses_an_unbound_freeze() -> TestResult {
    let (_store, composition, mut host, _owner) = local_authority()?;
    let view = host.authority_view()?;
    let authority = composition.authority();
    let request = reference(0x90);
    let transition = |lifecycle, freeze_position| ErasureStateTransitionV1 {
        lifecycle,
        freeze_position,
        pending_owners: Vec::new(),
        failed_owners: Vec::new(),
        acknowledged_targets: Vec::new(),
        replay_claim: ErasureReplayClaimV1::Exact,
        provenance: reference(0x98),
    };
    // Only `AccessFrozen` at the Local freeze position is admitted, and only
    // for a request the installed inventory holds.
    for (lifecycle, position) in [
        (ErasureLifecycleV1::AccessFrozen, Some(2)),
        (ErasureLifecycleV1::AccessFrozen, None),
        (ErasureLifecycleV1::Authorized, Some(1)),
        (ErasureLifecycleV1::AccessFrozen, Some(1)),
    ] {
        assert_eq!(
            authority
                .admit_atomic_freeze(&view, request, &transition(lifecycle, position))
                .map(drop),
            Err(ErasureErrorV1::PolicyConflict)
        );
    }
    // The view built outside a host command reads no scope, so it observes
    // no partition, and no ARD1 row, publication or key.
    let missing = Err(ErasureErrorV1::ProvenanceMissing);
    assert_eq!(
        authority
            .verified_topology_observation(&view, request, reference(0x99))
            .map(drop),
        missing
    );
    assert_eq!(view.recorded_scope(request).map(drop), missing);
    let unread = Err(ErasureViewListErrorV1::Read(
        ErasureErrorV1::ProvenanceMissing,
    ));
    assert_eq!(
        view.artifact_registrations(authority_timeline()).map(drop),
        unread
    );
    assert_eq!(
        view.recipient_export_publications(&[authority_timeline()])
            .map(drop),
        unread
    );
    assert_eq!(
        view.key_identities(&pos_core::OwnerIdV1::from_static("subject:owner"))
            .map(drop),
        unread
    );
    Ok(())
}

#[test]
fn the_local_authority_recomputes_every_fork_scope_extension() -> TestResult {
    let (_store, composition, mut host, _owner) = local_authority()?;
    let view = host.authority_view()?;
    let authority = composition.authority();
    let request = reference(0x90);
    let parent = TimelineMeta::root("local-authority-parent");
    let root_child = TimelineMeta::root("local-authority-child");
    let fork_child = TimelineMeta::forked_from(parent.id, Seq::ZERO, "local-authority-fork");
    let child_scope = pos_core::local_erasure_fork_scope_v1(fork_child.id)?;
    let extension = |child: &TimelineMeta, fork| {
        ErasureScopeExtensionV1::new(ErasureScopeExtensionInputV1 {
            request,
            scope_commitment: reference(0x91),
            fork,
            child_timeline: child.id,
            lineage_rule: reference(0x93),
            predecessor_extension: None,
            admission_provenance: pos_core::local_erasure_fork_admission_v1(
                request,
                parent.id,
                child.id,
                reference(0x93),
            )?,
        })
    };
    let fork_input = |child: &TimelineMeta, child_scope| ErasureForkAdmissionInputV1 {
        operation: reference(0x95),
        expected_inventory_generation: reference(0x96),
        child_scope,
        child: child.clone(),
    };
    let missing = Err(ErasureErrorV1::ProvenanceMissing);
    // A child the view does not record has no parent to recompute from.
    let recorded = extension(&fork_child, child_scope)?;
    assert_eq!(authority.admit_scope_extension(&view, &recorded), missing);
    assert_eq!(
        authority.validate_scope_extension_with_view(&view, &recorded),
        missing
    );
    // An identified Fork recomputes `ELFS1` and `ELFX1` from its own child.
    assert_eq!(
        authority.admit_fork_scope_extension(
            &view,
            &recorded,
            &fork_input(&fork_child, child_scope)
        ),
        Ok(())
    );
    for (candidate, input) in [
        (recorded, fork_input(&fork_child, reference(0x97))),
        (recorded, fork_input(&root_child, child_scope)),
        (
            extension(&fork_child, reference(0x97))?,
            fork_input(&fork_child, reference(0x97)),
        ),
        (
            extension(&root_child, child_scope)?,
            fork_input(&root_child, child_scope),
        ),
    ] {
        assert_eq!(
            authority.admit_fork_scope_extension(&view, &candidate, &input),
            missing
        );
    }
    assert_eq!(
        authority.resolve_fork_child_scope(&view, parent.id, &fork_child),
        Ok(child_scope)
    );
    for (fork_parent, child) in [(root_child.id, &fork_child), (parent.id, &root_child)] {
        assert_eq!(
            authority
                .resolve_fork_child_scope(&view, fork_parent, child)
                .map(drop),
            missing
        );
    }
    Ok(())
}

#[test]
fn the_local_authority_admits_no_attempt_or_acknowledgement_yet() -> TestResult {
    let (_store, composition, mut host, _owner) = local_authority()?;
    let view = host.authority_view()?;
    let authority = composition.authority();
    let request = reference(0x90);
    let mut matrix = Vec::new();
    for category in ErasureInventoryCategoryV1::CANONICAL {
        matrix.push(ErasureFreezeApplicabilityRowV1::new(
            category,
            0,
            ErasureApplicabilityDecisionV1::Inapplicable,
            None,
        )?);
    }
    let admission = ErasureFreezeAdmissionEvidenceV1::new(ErasureFreezeAdmissionEvidenceInputV1 {
        request,
        scope_commitment: reference(0xc0),
        obligation_set: reference(0xc1),
        applicability_matrix: matrix,
        freeze_position: 1,
        policy: LOCAL_ERASURE_POLICY_REFERENCE_V1,
        trust: reference(0xc2),
        authorization_provenance: reference(0xc3),
    })?;
    let freeze_authorization =
        ErasureFreezeAuthorizationEvidenceV1::new(ErasureFreezeAuthorizationEvidenceInputV1 {
            admission_body_digest: admission.authorization_body_digest()?,
            policy: LOCAL_ERASURE_POLICY_REFERENCE_V1,
            trust: reference(0xc2),
            evidence: vec![0xc4],
        })?;
    let attempt = ErasureRetryAdmissionV1::new(ErasureRetryAdmissionInputV1 {
        request,
        attempt_ordinal: 0,
        source_receipt: None,
        unresolved_obligations: vec![reference(0xc5)],
        command_identities: vec![reference(0xc6)],
        policy: LOCAL_ERASURE_POLICY_REFERENCE_V1,
        trust: reference(0xc2),
        admitted_position: 2,
        deadline_position: LOCAL_ERASURE_ATTEMPT_WINDOW_V1,
        authorization_provenance: reference(0xc7),
    })?;
    let acknowledgement =
        ErasureAcknowledgementProvenanceV1::new(ErasureAcknowledgementProvenanceInputV1 {
            request,
            command: reference(0xc6),
            attempt: attempt.reference(),
            obligation: reference(0xc5),
            owner: reference(0xc8),
            scope: reference(0xc0),
            outcome: ErasureAcknowledgementOutcomeV1::Acknowledged,
            evidence: reference(0xc9),
            policy: LOCAL_ERASURE_POLICY_REFERENCE_V1,
            trust: reference(0xc2),
        })?;
    let missing = Err(ErasureErrorV1::ProvenanceMissing);
    // Freeze evidence must name the bundle it pins; this one names none.
    assert_eq!(
        authority.validate_freeze_authorization_with_view(&view, &admission, &freeze_authorization),
        Err(ErasureErrorV1::Unauthorized)
    );
    assert_eq!(authority.admit_attempt(&view, &attempt).map(drop), missing);
    assert_eq!(
        authority.admit_acknowledgement(&view, &acknowledgement),
        missing
    );
    Ok(())
}

#[test]
fn the_local_authority_refuses_correction_resolution_and_receipts_yet() -> TestResult {
    let (store, composition, mut host, _owner) = local_authority()?;
    let view = host.authority_view()?;
    let authority = composition.authority();
    let request = reference(0x90);
    let resolution =
        ErasureAdministrativeResolutionV1::new(ErasureAdministrativeResolutionInputV1 {
            request,
            affected_digests: vec![reference(0x99)],
            action: ErasureAdministrativeResolutionActionV1::RecoverExactEvidence,
            scope_commitment: reference(0x9a),
            policy: reference(0x9b),
            trust: reference(0x9c),
            principal: reference(0x9d),
            authorization_provenance: reference(0x9e),
            reason: reference(0x9f),
            issue_position: 1,
            predecessor_resolution: None,
        })?;
    let correction =
        pos_core::ErasureCorrectionProvenanceV1::new(ErasureCorrectionProvenanceInputV1 {
            rejected_request: request,
            rejected_terminal_state: reference(0xa0),
            correction_reason: reference(0xa1),
            authorization_provenance: reference(0xa2),
        })?;
    let erq1 = ErasureRequestV1::new(PlainRequest::valid(1, store.head)?.input)?;
    let receipt = ErasureReceiptInputV1 {
        request,
        terminal_state: reference(0xa3),
        coordinator: reference(0xa4),
        lifecycle: ErasureLifecycleV1::Complete,
        freeze_position: 1,
        acknowledgements: Vec::new(),
        frozen_targets: Vec::new(),
        pending_owners: Vec::new(),
        failed_owners: Vec::new(),
        inventories: ErasureReceiptInventoriesV1 {
            artifacts: Vec::new(),
            keys: Vec::new(),
            replicas: Vec::new(),
            backups: Vec::new(),
        },
        replay_claim: ErasureReplayClaimV1::Exact,
        policy: reference(0xa5),
        trust: reference(0xa6),
        provenance: reference(0xa7),
        issue_position: 2,
        signature: reference(0xa8),
        receipt_digest: reference(0),
    };
    assert_eq!(
        authority.admit_receipt(&view, &receipt),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
    // Corrected submission and administrative resolution are refused (Q14, Q4).
    let conflict = Err(ErasureErrorV1::PolicyConflict);
    assert_eq!(
        authority.admit_corrected_submission(&view, &erq1, &correction),
        conflict
    );
    assert_eq!(
        authority.admit_administrative_resolution(&view, &resolution),
        conflict
    );
    assert_eq!(
        authority.validate_administrative_resolution_with_view(&view, &resolution),
        conflict
    );
    Ok(())
}

#[test]
fn destruction_goes_only_to_an_owner_the_bundle_names() -> TestResult {
    let (_store, composition, mut host, owner) = local_authority()?;
    let view = host.authority_view()?;
    let authority = composition.authority();
    let request = reference(0x90);
    let command = |owner| ErasureDestructionCommandV1 {
        obligation: reference(0xb0),
        category: ErasureInventoryCategoryV1::Key,
        target: ErasureRequiredTargetV1 {
            artifact_class: ErasureArtifactClassV1::TimelineReplay,
            artifact_digest: reference(0xb1),
            key_role: ErasureKeyRoleV1::DataEncryption,
            key_digest: reference(0xb2),
            replica_set: reference(0xb3),
            replica_id: reference(0xb4),
        },
        owner,
        command: reference(0xb5),
        provenance: reference(0xb6),
    };
    assert_eq!(authority.dispatch_destruction(&view, request, &[]), Ok(()));
    assert_eq!(
        authority.dispatch_destruction(&view, request, &[command(owner)]),
        Ok(())
    );
    assert_eq!(
        authority.dispatch_destruction(&view, request, &[command(owner), command(reference(0xb7))]),
        Err(ErasureErrorV1::ScopeInvalid)
    );
    // The view built outside a host command reads no stored object.
    assert_eq!(view.retained_object(reference(0xb8)), None);
    assert!(view.local_principal_authority(grant_id()).is_none());
    assert_eq!(view.maximum_requests(), 4_096);
    assert!(view.verified_requests().is_empty());
    assert!(view.verified_request(request).is_none());
    Ok(())
}

// ---------------------------------------------------------------------------
// Freeze and Fork scope extension at the public seams (ADR-136 amendment
// decisions 1B, 4A and 5A; acceptance tests 2, 3, 3b, 5 and 6).
// ---------------------------------------------------------------------------

use pos_core::erasure::target_closure_digest;
use pos_core::{
    destruction_command_reference, ErasureObligationInputV1, ErasureObligationSetInputV1,
    ErasureObligationSetV1, ErasureObligationV1, ErasurePersistencePortV1,
};
use pos_core::{
    local_erasure_replica_id_v1, local_erasure_replica_set_v1, local_erasure_signature_message_v1,
    local_erasure_store_target_v1, local_erasure_timeline_payload_v1, CanonicalBytes,
    LocalErasureLineageRuleV1, LocalErasureSignaturePurposeV1, LocalErasureSignatureV1, OwnerIdV1,
};
use pos_crypto::key_roles::sign_for_registered_role;
use pos_runtime::ErasureViewListErrorV1;

/// The signer key of a rotated bundle.
fn rotated_signer() -> SigningKey {
    SigningKey::from_bytes(&[0x66; 32])
}

impl LocalStore {
    fn sqlite(&self) -> TestResult<SqliteStore> {
        let mut store = SqliteStore::open(&self.path)?;
        store.bind_erasure_gate(Arc::new(ErasureContainmentGateV1::new_test_open()))?;
        Ok(store)
    }

    /// Create `count` root Timelines owned by `owner`.
    fn owned_roots(&self, owner: EntityId, count: usize) -> TestResult<Vec<TimelineId>> {
        let mut store = self.sqlite()?;
        let mut roots = Vec::with_capacity(count);
        for index in 0..count {
            let meta = TimelineMeta::root_owned(format!("owned-{index}"), owner);
            roots.push(store.create_timeline_with_meta(meta)?.id());
        }
        Ok(roots)
    }

    /// Add `registration` to the store's key registry.
    fn register(&self, registration: KeyRegistrationV1) -> TestResult {
        let mut store = self.sqlite()?;
        let mut registry = store.load_key_registry()?.ok_or("no key registry")?;
        registry.register_key(registration).map_err(fail)?;
        store.save_key_registry(&registry)?;
        Ok(())
    }
}

/// The actor's ADR-091 role-0 subject key at `epoch`.
fn subject_key(epoch: u64) -> TestResult<KeyIdentityV1> {
    let owner = pos_crypto::subject_key::subject_owner_id(actor()).map_err(fail)?;
    Ok(KeyIdentityV1::from_parts(
        OwnerIdV1::new(owner).map_err(fail)?,
        KeyRoleV1::SubjectDataEncryption,
        epoch,
    ))
}

/// ELS1 of `purpose` over `digest`, signed for the signer identity at
/// `epoch` with `key`.
fn signature_record(
    purpose: LocalErasureSignaturePurposeV1,
    digest: ErasureReferenceV1,
    key: &SigningKey,
    epoch: u64,
) -> TestResult<Vec<u8>> {
    let material = SigningKeyMaterial::new(key.clone());
    let mut registry = KeyRegistryStateV1::new();
    registry
        .register_key(KeyRegistrationV1::new(
            signer_identity(epoch),
            material.material_digest(),
            Some(material.public_verification_key()),
        ))
        .map_err(fail)?;
    let message = local_erasure_signature_message_v1(purpose, digest)?;
    let signature = sign_for_registered_role(
        &mut registry,
        &material,
        signer_identity(epoch),
        &CanonicalBytes::from_vec(message),
    )
    .map_err(fail)?;
    Ok(LocalErasureSignatureV1 {
        purpose,
        signed_digest: digest,
        signer_identity: LocalErasureSignerIdentityV1 {
            owner_id: SIGNER_OWNER.as_bytes().to_vec(),
            epoch,
        },
        signature: *signature.as_bytes(),
    }
    .to_canonical_cbor()?)
}

/// The address an ELS1 is retained under.
fn signature_address(record: &[u8]) -> TestResult<ErasureReferenceV1> {
    Ok(LocalErasureSignatureV1::from_canonical_cbor(record)?.reference()?)
}

const fn freeze(provenance: ErasureReferenceV1) -> ErasureStateTransitionV1 {
    ErasureStateTransitionV1 {
        lifecycle: ErasureLifecycleV1::AccessFrozen,
        freeze_position: Some(1),
        pending_owners: Vec::new(),
        failed_owners: Vec::new(),
        acknowledged_targets: Vec::new(),
        replay_claim: ErasureReplayClaimV1::Exact,
        provenance,
    }
}

/// One Local target of the bundle's store (decision 1B).
fn local_target(
    artifact_class: ErasureArtifactClassV1,
    artifact_digest: ErasureReferenceV1,
    key_digest: ErasureReferenceV1,
) -> TestResult<ErasureRequiredTargetV1> {
    let store = ErasureReferenceV1::from_digest(STORE_IDENTITY);
    Ok(ErasureRequiredTargetV1 {
        artifact_class,
        artifact_digest,
        key_role: ErasureKeyRoleV1::DataEncryption,
        key_digest,
        replica_set: local_erasure_replica_set_v1(store)?,
        replica_id: local_erasure_replica_id_v1(store)?,
    })
}

/// The one store target every request carries.
fn store_target() -> TestResult<ErasureRequiredTargetV1> {
    local_target(
        ErasureArtifactClassV1::TimelineReplay,
        local_erasure_store_target_v1(ErasureReferenceV1::from_digest(STORE_IDENTITY))?,
        reference(0),
    )
}

/// Submit and authorize request `key` for `scope`, and prepare its freeze.
fn prepared(
    store: &LocalStore,
    host: &mut ErasureExecutionHostV1,
    key: u8,
    scope: ErasureScopeV1,
) -> TestResult<ErasureReferenceV1> {
    let mut sender = host.command_sender()?;
    sender
        .submit_local_erasure(&submission(key, scope)?)
        .map_err(fail)?;
    let request = request_of(key)?;
    sender.authorize_erasure_request(request, authorization(key, store.head)?.reference()?)?;
    Ok(sender.prepare_local_freeze(request)?)
}

fn lifecycle(
    host: &mut ErasureExecutionHostV1,
    request: ErasureReferenceV1,
) -> TestResult<ErasureLifecycleV1> {
    Ok(host
        .read_sender()?
        .erasure_state(request)?
        .ok_or("request missing")?
        .lifecycle())
}

fn assert_frozen(
    host: &mut ErasureExecutionHostV1,
    frozen: &[TimelineId],
    open: TimelineId,
) -> TestResult {
    let mut reads = host.read_sender()?;
    for timeline in frozen {
        assert_eq!(
            reads.timeline(*timeline).map(drop),
            Err(ErasureHostErrorV1::AccessFrozen)
        );
    }
    assert!(reads.timeline(open)?.is_some());
    Ok(())
}

/// A store whose actor owns one root Timeline and holds a role-0 subject
/// key, beside a root Timeline of another actor.
struct OwnedStore {
    store: LocalStore,
    owned: TimelineId,
    other: TimelineId,
}

impl OwnedStore {
    fn new() -> TestResult<Self> {
        let store = LocalStore::new(&GrantShape::standard())?;
        let owned = store.owned_roots(actor(), 1)?[0];
        let other = store.owned_roots(other_actor(), 1)?[0];
        store.register(KeyRegistrationV1::new(
            subject_key(1)?,
            Hash::from_bytes([0x81; 32]),
            None,
        ))?;
        Ok(Self {
            store,
            owned,
            other,
        })
    }
}

/// Freeze request `key` for `scope` with a purpose-0 ELS1 over the
/// prepared body, after `before` ran on the open host; the freeze runs on
/// a restarted host, which first refuses every ELS1 of `refused`.
fn signed_freeze(
    store: &LocalStore,
    key: u8,
    scope: ErasureScopeV1,
    before: impl FnOnce(&mut ErasureExecutionHostV1) -> TestResult,
    refused: impl FnOnce(ErasureReferenceV1) -> TestResult<Vec<Vec<u8>>>,
) -> TestResult<(ErasureExecutionHostV1, Vec<u8>)> {
    let digest = {
        let mut host = store.host(&local_case()?, 4_096)?;
        before(&mut host)?;
        let digest = prepared(store, &mut host, key, scope)?;
        // The body is a pure function of the snapshot.
        assert_eq!(
            host.command_sender()?
                .prepare_local_freeze(request_of(key)?)?,
            digest
        );
        digest
    };
    let signed = signature_record(
        LocalErasureSignaturePurposeV1::FreezeAuthorization,
        digest,
        &erasure_signer(),
        1,
    )?;
    let refused = refused(digest)?;
    store.retain(std::slice::from_ref(&signed))?;
    store.retain(&refused)?;
    let mut host = store.host(&local_case()?, 4_096)?;
    let request = request_of(key)?;
    let mut sender = host.command_sender()?;
    // Even under a verifying ELS1, only `AccessFrozen` at the Local freeze
    // position is admitted.
    let provenance = signature_address(&signed)?;
    for transition in [
        ErasureStateTransitionV1 {
            freeze_position: Some(2),
            ..freeze(provenance)
        },
        ErasureStateTransitionV1 {
            lifecycle: ErasureLifecycleV1::Authorized,
            ..freeze(provenance)
        },
    ] {
        assert_eq!(
            sender.freeze_access(request, &transition).map(drop),
            Err(ErasureHostErrorV1::Conflict)
        );
    }
    for record in &refused {
        assert_eq!(
            sender
                .freeze_access(request, &freeze(signature_address(record)?))
                .map(drop),
            Err(ErasureHostErrorV1::AuthorizationDenied)
        );
    }
    assert_eq!(
        sender
            .freeze_access(request, &freeze(signature_address(&signed)?))?
            .lifecycle(),
        ErasureLifecycleV1::AccessFrozen
    );
    Ok((host, signed))
}

/// A purpose-0 ELS1 over `digest` by the bundle's signer whose own labels
/// `relabel` then rewrites: its signature still verifies over the expected
/// message, so only the label check refuses it.
fn relabelled_signature(
    digest: ErasureReferenceV1,
    relabel: impl FnOnce(&mut LocalErasureSignatureV1),
) -> TestResult<Vec<u8>> {
    let mut signature = LocalErasureSignatureV1::from_canonical_cbor(&signature_record(
        LocalErasureSignaturePurposeV1::FreezeAuthorization,
        digest,
        &erasure_signer(),
        1,
    )?)?;
    relabel(&mut signature);
    Ok(signature.to_canonical_cbor()?)
}

/// A forged key, purpose confusion, a stale body, and a valid signature
/// under a wrong purpose, digest or signer label: none freezes.
fn refused_signatures(digest: ErasureReferenceV1) -> TestResult<Vec<Vec<u8>>> {
    let purpose = LocalErasureSignaturePurposeV1::FreezeAuthorization;
    Ok(vec![
        signature_record(purpose, digest, &other_root(), 1)?,
        signature_record(
            LocalErasureSignaturePurposeV1::OwnerResult,
            digest,
            &erasure_signer(),
            1,
        )?,
        signature_record(purpose, reference(0x77), &erasure_signer(), 1)?,
        relabelled_signature(digest, |signature| {
            signature.purpose = LocalErasureSignaturePurposeV1::OwnerResult;
        })?,
        relabelled_signature(digest, |signature| {
            signature.signed_digest = reference(0x77);
        })?,
        relabelled_signature(digest, |signature| {
            signature.signer_identity.epoch = 2;
        })?,
    ])
}

/// Committed freeze evidence verifies only when ERFAA1 and ERFA1 pin the
/// compiled ELP1 and one trust revision, even under a purpose-0 ELS1 over
/// the ERFA1 body that the pinned bundle's signer made.
#[test]
fn committed_freeze_evidence_pins_one_policy_and_trust() -> TestResult {
    let (_store, composition, mut host, owner) = local_authority()?;
    let view = host.authority_view()?;
    let authority = composition.authority();
    let trust = single_owner_bundle(owner).reference()?;
    let mut matrix = Vec::new();
    for category in ErasureInventoryCategoryV1::CANONICAL {
        matrix.push(ErasureFreezeApplicabilityRowV1::new(
            category,
            0,
            ErasureApplicabilityDecisionV1::Inapplicable,
            None,
        )?);
    }
    let admission = ErasureFreezeAdmissionEvidenceV1::new(ErasureFreezeAdmissionEvidenceInputV1 {
        request: reference(0x90),
        scope_commitment: reference(0xc0),
        obligation_set: reference(0xc1),
        applicability_matrix: matrix,
        freeze_position: 1,
        policy: LOCAL_ERASURE_POLICY_REFERENCE_V1,
        trust,
        authorization_provenance: reference(0xc3),
    })?;
    let body = admission.authorization_body_digest()?;
    let signed = signature_record(
        LocalErasureSignaturePurposeV1::FreezeAuthorization,
        body,
        &erasure_signer(),
        1,
    )?;
    let validated = |policy, pinned| {
        ErasureFreezeAuthorizationEvidenceV1::new(ErasureFreezeAuthorizationEvidenceInputV1 {
            admission_body_digest: body,
            policy,
            trust: pinned,
            evidence: signed.clone(),
        })
        .and_then(|authorization| {
            authority.validate_freeze_authorization_with_view(&view, &admission, &authorization)
        })
    };
    assert_eq!(validated(LOCAL_ERASURE_POLICY_REFERENCE_V1, trust), Ok(()));
    assert_eq!(
        validated(reference(0xc4), trust),
        Err(ErasureErrorV1::Unauthorized)
    );
    assert_eq!(
        validated(LOCAL_ERASURE_POLICY_REFERENCE_V1, reference(0xc5)),
        Err(ErasureErrorV1::Unauthorized)
    );
    Ok(())
}

/// One expected `(target, category, ack_class)` cell.
type Cell = (
    ErasureRequiredTargetV1,
    ErasureInventoryCategoryV1,
    &'static str,
);

/// The committed freeze of `request`: ERSC1 binds the subject to `affected`
/// under ELLR1 over exactly the targets of `cells`, and the store holds the
/// EROS1, each ERO1 and the ERFA1/ERFAA1 rebuilt from `cells` alone, so
/// every Applicable cell has its ELOWN1 owner and its target's command
/// identity, and every other cell is Inapplicable.
fn assert_committed_freeze(
    store: &LocalStore,
    mut host: ErasureExecutionHostV1,
    request: ErasureReferenceV1,
    mut affected: Vec<TimelineId>,
    cells: &[Cell],
    signed: &[u8],
) -> TestResult {
    let subject = local_erasure_subject_v1(principal_ref()?, actor())?;
    let state = host
        .read_sender()?
        .erasure_state(request)?
        .ok_or("request missing")?;
    drop(host);
    let scope = state.scope().ok_or("no committed scope")?;
    let targets = cells
        .iter()
        .map(|cell| cell.0)
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    affected.sort_unstable();
    assert_eq!(scope.scope_members(), [subject]);
    assert_eq!(scope.scope_timeline_ids(), affected.as_slice());
    assert_eq!(
        scope.lineage_rule(),
        Some(LocalErasureLineageRuleV1 { subject }.reference()?)
    );
    assert_eq!(scope.target_closure(), target_closure_digest(&targets));
    let obligations = expected_obligations(request, cells)?;
    let trust = bundle().reference()?;
    let set = ErasureObligationSetV1::new(ErasureObligationSetInputV1 {
        request,
        obligations: obligations
            .iter()
            .map(ErasureObligationV1::reference)
            .collect(),
        policy: LOCAL_ERASURE_POLICY_REFERENCE_V1,
        trust,
    })?;
    let matrix = expected_matrix(&targets, &obligations)?;
    let admission = |authorization_provenance| {
        ErasureFreezeAdmissionEvidenceV1::new(ErasureFreezeAdmissionEvidenceInputV1 {
            request,
            scope_commitment: scope.reference(),
            obligation_set: set.reference(),
            applicability_matrix: matrix.clone(),
            freeze_position: 1,
            policy: LOCAL_ERASURE_POLICY_REFERENCE_V1,
            trust,
            authorization_provenance,
        })
    };
    let authorization =
        ErasureFreezeAuthorizationEvidenceV1::new(ErasureFreezeAuthorizationEvidenceInputV1 {
            admission_body_digest: admission(reference(0))?.authorization_body_digest()?,
            policy: LOCAL_ERASURE_POLICY_REFERENCE_V1,
            trust,
            evidence: signed.to_vec(),
        })?;
    let admission = admission(authorization.reference())?;
    let sqlite = store.sqlite()?;
    let mut expected = vec![
        (set.reference(), set.to_canonical_cbor()?),
        (
            authorization.reference(),
            authorization.to_canonical_cbor()?,
        ),
        (admission.reference(), admission.to_canonical_cbor()?),
    ];
    for obligation in &obligations {
        expected.push((obligation.reference(), obligation.to_canonical_cbor()?));
    }
    for (address, bytes) in expected {
        assert_eq!(
            ErasurePersistencePortV1::read_object(&sqlite, address)?,
            bytes
        );
    }
    Ok(())
}

/// The store target's two cells.
fn store_cells() -> TestResult<Vec<Cell>> {
    let target = store_target()?;
    Ok(vec![
        (
            target,
            ErasureInventoryCategoryV1::Artifact,
            "client-cache-signal",
        ),
        (target, ErasureInventoryCategoryV1::Replica, "local-replica"),
    ])
}

/// The ERO1 of every cell, owned by its ELOWN1 owner under the store
/// identity and naming its target's command identity, in reference order.
fn expected_obligations(
    request: ErasureReferenceV1,
    cells: &[Cell],
) -> TestResult<Vec<ErasureObligationV1>> {
    let store_identity = ErasureReferenceV1::from_digest(STORE_IDENTITY);
    let mut obligations = cells
        .iter()
        .map(|&(target, category, ack_class)| {
            ErasureObligationV1::new(ErasureObligationInputV1 {
                category,
                target,
                owner: pos_core::local_erasure_owner_ref_v1(
                    store_identity,
                    u64::from(category),
                    ack_class,
                )?,
                command_identity: destruction_command_reference(request, target),
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    obligations.sort_unstable_by_key(ErasureObligationV1::reference);
    Ok(obligations)
}

/// The applicability matrix over `targets`: a cell with an obligation is
/// Applicable with that obligation's owner, every other cell Inapplicable.
fn expected_matrix(
    targets: &[ErasureRequiredTargetV1],
    obligations: &[ErasureObligationV1],
) -> TestResult<Vec<ErasureFreezeApplicabilityRowV1>> {
    let mut matrix = Vec::new();
    for category in ErasureInventoryCategoryV1::CANONICAL {
        for (index, target) in targets.iter().enumerate() {
            let owner = obligations
                .iter()
                .find(|obligation| {
                    obligation.category() == category && obligation.target() == *target
                })
                .map(ErasureObligationV1::owner);
            matrix.push(ErasureFreezeApplicabilityRowV1::new(
                category,
                u64::try_from(index)?,
                if owner.is_some() {
                    ErasureApplicabilityDecisionV1::Applicable
                } else {
                    ErasureApplicabilityDecisionV1::Inapplicable
                },
                owner,
            )?);
        }
    }
    Ok(matrix)
}

/// The Key and Backup cells of one key target.
const fn key_cells(target: ErasureRequiredTargetV1) -> [Cell; 2] {
    [
        (target, ErasureInventoryCategoryV1::Key, "key-registry"),
        (
            target,
            ErasureInventoryCategoryV1::Backup,
            "local-backup-inventory",
        ),
    ]
}

fn payload_cell(timeline: TimelineId) -> TestResult<Cell> {
    Ok((
        local_target(
            ErasureArtifactClassV1::TimelineReplay,
            local_erasure_timeline_payload_v1(timeline)?,
            reference(0),
        )?,
        ErasureInventoryCategoryV1::Artifact,
        "timeline-payload",
    ))
}

fn subject_key_cells() -> TestResult<[Cell; 2]> {
    Ok(key_cells(local_target(
        ErasureArtifactClassV1::TimelineReplay,
        reference(0),
        pos_core::local_erasure_key_digest_v1(&subject_key(1)?)?,
    )?))
}

#[test]
fn a_signed_private_freeze_commits_the_subject_closure() -> TestResult {
    let owned = OwnedStore::new()?;
    let mut descendant = None;
    let (mut host, signed) = signed_freeze(
        &owned.store,
        1,
        ErasureScopeV1::PrivateSubjectData,
        |host| {
            // A Fork of the owned Timeline before freeze is a descendant.
            descendant = Some(
                host.command_sender()?
                    .fork_timeline(owned.owned, Seq::ZERO, "existing-descendant")?
                    .id(),
            );
            Ok(())
        },
        refused_signatures,
    )?;
    let descendant = descendant.ok_or("no descendant")?;
    let request = request_of(1)?;
    assert_eq!(
        host.command_sender()?
            .freeze_access(request, &freeze(reference(0x78)))?
            .lifecycle(),
        ErasureLifecycleV1::AccessFrozen
    );
    assert_frozen(&mut host, &[owned.owned, descendant], owned.other)?;
    // A request the installed inventory does not hold prepares nothing.
    assert_eq!(
        host.command_sender()?
            .prepare_local_freeze(reference(0x79))
            .map(drop),
        Err(ErasureHostErrorV1::Conflict)
    );
    let mut cells = store_cells()?;
    cells.push(payload_cell(owned.owned)?);
    cells.push(payload_cell(descendant)?);
    cells.extend(subject_key_cells()?);
    assert_committed_freeze(
        &owned.store,
        host,
        request,
        vec![owned.owned, descendant],
        &cells,
        &signed,
    )
}

#[test]
fn a_host_timeline_stays_outside_the_frozen_scope_but_its_owned_fork_does_not() -> TestResult {
    let owned = OwnedStore::new()?;
    // A host Timeline the actor owns, and a Fork of it that inherits the
    // actor as owner, as every Fork does.
    let (host_timeline, host_fork) = {
        let mut sqlite = owned.store.sqlite()?;
        let host_timeline = sqlite
            .create_timeline_with_meta(TimelineMeta::root_owned("host", actor()))?
            .id();
        let host_fork = sqlite
            .create_timeline_with_meta(TimelineMeta::forked_from_owned(
                host_timeline,
                Seq::ZERO,
                "host-fork",
                actor(),
            ))?
            .id();
        (host_timeline, host_fork)
    };
    let mut hosting = bundle();
    hosting.host_timelines = vec![host_timeline];
    let case = Case::signed(&hosting, &bundle_root(), &[])?;
    let digest = {
        let mut host = owned.store.host(&case, 4_096)?;
        prepared(
            &owned.store,
            &mut host,
            1,
            ErasureScopeV1::PrivateSubjectData,
        )?
    };
    let signed = signature_record(
        LocalErasureSignaturePurposeV1::FreezeAuthorization,
        digest,
        &erasure_signer(),
        1,
    )?;
    owned.store.retain(std::slice::from_ref(&signed))?;
    let mut host = owned.store.host(&case, 4_096)?;
    assert_eq!(
        host.command_sender()?
            .freeze_access(request_of(1)?, &freeze(signature_address(&signed)?))?
            .lifecycle(),
        ErasureLifecycleV1::AccessFrozen
    );
    // The listed host Timeline stays readable. Its Fork is no host
    // Timeline: the actor owns it, so it freezes with the actor's own.
    assert_frozen(&mut host, &[owned.owned, host_fork], host_timeline)?;
    assert!(host.read_sender()?.timeline(owned.other)?.is_some());
    Ok(())
}

#[test]
fn identified_forks_extend_a_frozen_scope_across_restart_and_rotation() -> TestResult {
    let owned = OwnedStore::new()?;
    let request = request_of(1)?;
    let (mut host, _) = signed_freeze(
        &owned.store,
        1,
        ErasureScopeV1::PrivateSubjectData,
        |_| Ok(()),
        |_| Ok(Vec::new()),
    )?;
    // An identified Fork of an affected parent extends the scope under
    // ELFS1/ELFX1, and its exact retry returns the same child.
    let child = {
        let mut sender = host.command_sender()?;
        let child = sender
            .fork_timeline_identified(reference(0x45), owned.owned, Seq::ZERO, "late-fork")?
            .id();
        assert_eq!(
            sender
                .fork_timeline_identified(reference(0x45), owned.owned, Seq::ZERO, "late-fork")?
                .id(),
            child
        );
        child
    };
    assert_frozen(&mut host, &[owned.owned, child], owned.other)?;
    drop(host);
    // Recovery re-verifies the ELS1, ERSC1 and every ERSE1.
    let mut host = owned.store.host(&local_case()?, 4_096)?;
    assert_frozen(&mut host, &[owned.owned, child], owned.other)?;
    assert_eq!(
        lifecycle(&mut host, request)?,
        ErasureLifecycleV1::AccessFrozen
    );
    drop(host);
    // After a routine bundle rotation, recovery verifies the old freeze
    // against the bundle it pinned, retained at prepare.
    let rotated_key = rotated_signer().verifying_key().to_bytes();
    let material = SigningKeyMaterial::new(rotated_signer());
    owned.store.register(KeyRegistrationV1::new(
        signer_identity(2),
        material.material_digest(),
        Some(material.public_verification_key()),
    ))?;
    let mut rotated = bundle();
    rotated.signer_identity.epoch = 2;
    rotated.signer_public_key = rotated_key;
    rotated.signer_key_id = local_erasure_signer_key_id_v1(&rotated_key);
    let mut host = owned
        .store
        .host(&Case::signed(&rotated, &bundle_root(), &[])?, 4_096)?;
    assert_frozen(&mut host, &[owned.owned, child], owned.other)
}

/// Publish one recipient export of the actor's `timeline` to `grantee`
/// under the actor's export consent, and return its export id.
fn publish_export(
    store: &LocalStore,
    timeline: TimelineId,
    grantee: EntityId,
) -> TestResult<[u8; 16]> {
    use std::os::unix::fs::PermissionsExt;

    let directory = tempfile::tempdir()?;
    let private = directory.path().join("recipient-private");
    std::fs::create_dir(&private)?;
    std::fs::set_permissions(&private, std::fs::Permissions::from_mode(0o700))?;
    let mut sqlite = store.sqlite()?;
    sqlite.append(
        timeline,
        &[pos_core::EventDraft::new(
            EntityId::new(),
            pos_core::Kind::new("recipient.export.public.v1"),
            CanonicalBytes::from_static(b"encrypted-recipient-export"),
        )],
    )?;
    let consent = pos_core::ConsentAuthority::new();
    sqlite.bind_consent_authority(consent.append_permit())?;
    let token = consent.record_grant_on_timeline(
        timeline,
        &pos_core::ConsentGrantedV1 {
            subject_id: actor(),
            grantee_id: grantee,
            purpose: "local-erasure-export".to_owned(),
            modalities: pos_core::MODALITY_EXPORT,
            min_geo_resolution: 0,
            fork_permitted: false,
            export_permitted: true,
            retention_days: 1,
            expiry_secs: 0,
            grant_seq: 1,
        },
    );
    let owner = pos_store::sqlite::RecipientKeyOwnerV1::open(&private, grantee)?;
    let recipient = sqlite.enroll_recipient_key(&owner)?;
    let evaluation = pos_core::ReplayClaimEvaluatorV1::evaluate(
        ErasureReplayClaimV1::Exact,
        &[pos_core::ArtifactClaimInputV1 {
            registration: pos_core::RegisteredArtifactV1::new(
                ErasureArtifactClassV1::Export,
                reference(0xf1),
                pos_core::ArtifactDataClassV1::StructuralAuditMetadata,
                None,
                reference(0xf2),
                pos_core::ArtifactOptionalityV1::Required,
                pos_core::ArtifactTransitionRuleV1::PreserveExact,
            ),
            current_claim: ErasureReplayClaimV1::Exact,
            state: pos_core::ArtifactStateV1::Retained,
        }],
    )
    .map_err(fail)?;
    let publication = sqlite.publish_recipient_export(
        &consent,
        &owner,
        &pos_store::sqlite::RecipientExportRequestV1 {
            timeline_id: timeline,
            recipient,
            artifact_digest: reference(0xf1),
            evaluation: &evaluation,
            token: &token,
            now_secs: 1,
        },
    )?;
    Ok(publication.export_id)
}

#[test]
fn a_consented_freeze_covers_the_store_target_and_each_export_grantee() -> TestResult {
    let owned = OwnedStore::new()?;
    let export_id = publish_export(&owned.store, owned.owned, other_actor())?;
    let (mut host, signed) = signed_freeze(
        &owned.store,
        2,
        ErasureScopeV1::ConsentedSharedData,
        |_| Ok(()),
        |_| Ok(Vec::new()),
    )?;
    assert_frozen(&mut host, &[owned.owned], owned.other)?;
    // Role-0 keys and Timeline payloads are private-subject-data targets;
    // the export to the grantee is one `export-recipient` target.
    let grantee = pos_core::recipient_owner_id_from_grantee(other_actor()).map_err(fail)?;
    let mut cells = store_cells()?;
    cells.push((
        local_target(
            ErasureArtifactClassV1::Export,
            pos_core::local_erasure_export_recipient_v1(export_id, &grantee)?,
            reference(0),
        )?,
        ErasureInventoryCategoryV1::Artifact,
        "export-recipient",
    ));
    assert_committed_freeze(
        &owned.store,
        host,
        request_of(2)?,
        vec![owned.owned],
        &cells,
        &signed,
    )
}

#[test]
fn the_closure_bound_is_exact_at_submit_and_freeze() -> TestResult {
    let store = LocalStore::new(&GrantShape::standard())?;
    // 4,095 `timeline-payload` targets and the store target: exactly the
    // 4,096-target bound.
    let roots = store.owned_roots(actor(), 4_095)?;
    let mut host = store.host(&local_case()?, 4_096)?;
    prepared(&store, &mut host, 1, ErasureScopeV1::PrivateSubjectData)?;
    let request = request_of(1)?;
    // Growth after submission: a Fork of an affected Timeline is one more
    // target, so the freeze commits `Rejected` without a signature.
    let mut sender = host.command_sender()?;
    sender.fork_timeline(roots[0], Seq::ZERO, "growth")?;
    assert_eq!(
        sender.prepare_local_freeze(request).map(drop),
        Err(ErasureHostErrorV1::Conflict)
    );
    assert_eq!(
        sender
            .freeze_access(request, &freeze(reference(0x78)))?
            .lifecycle(),
        ErasureLifecycleV1::Rejected
    );
    // A new request over the bound is refused before any ERQ1 exists; a
    // consented one, whose closure holds no Timeline payload, fits.
    assert_eq!(
        sender
            .submit_local_erasure(&submission(2, ErasureScopeV1::PrivateSubjectData)?)
            .map(drop),
        Err(LocalErasureSubmitErrorV1::ScopeTooLarge)
    );
    assert_eq!(
        sender
            .submit_local_erasure(&submission(3, ErasureScopeV1::ConsentedSharedData)?)
            .map_err(fail)?
            .lifecycle(),
        ErasureLifecycleV1::Submitted
    );
    assert!(host.read_sender()?.erasure_state(request_of(2)?)?.is_none());
    drop(host);
    let mut host = store.host(&local_case()?, 4_096)?;
    assert_eq!(lifecycle(&mut host, request)?, ErasureLifecycleV1::Rejected);
    Ok(())
}

// ---------------------------------------------------------------------------
// ARD1 rows bound to an affected Timeline (decision 2A over C1′). The MRM1
// closure fixture follows `pos-store/tests/artifact_registration_persistence_public.rs`.
// ---------------------------------------------------------------------------

use pos_core::{
    extract_adapter_admission_registration_v1, extract_adapter_transcript_registration_v1,
    extract_repro_manifest_root_registration_v1, prepare_artifact_registration_batch_v1,
    AdapterAdmissionInputV1, AdapterAdmissionV1, AdapterRecordingSessionV1,
    AdapterRecordingStoreErrorV1, AdapterRecordingStoreV1, AdapterTranscriptInputV1,
    AdapterTranscriptV1, ArtifactDataClassV1, ArtifactRegistrationFieldsV1,
    ArtifactRegistrationInputV1, ArtifactRegistrationOwnerVerificationErrorV1,
    ArtifactRegistrationOwnerVerifierV1, ArtifactRegistrationV1, ArtifactTransitionRuleV1,
    PreparedArtifactRegistrationBatchV1, ReproManifestRootInputV1,
    ReproManifestRootRegistrationInputV1, ReproManifestRootV1, WorldRecordingReceiptInputV1,
    WorldRecordingReceiptV1, WorldReplayHandleInputV1, WorldReplayHandleV1,
};

// This fixture isolates the store's transactional port. Its synthetic WCR1
// registration is not Wave 8 owner-verification evidence.
struct TestOnlyStructuralOwnerVerifier {
    recording_data_class: ArtifactDataClassV1,
    recording_keys: Vec<pos_core::ArtifactKeyDependencyV1>,
}

impl ArtifactRegistrationOwnerVerifierV1 for TestOnlyStructuralOwnerVerifier {
    fn derive_native_registration(
        &self,
        owner_id: &OwnerIdV1,
        artifact_class: ErasureArtifactClassV1,
        artifact_bytes: &[u8],
    ) -> Result<ArtifactRegistrationV1, ArtifactRegistrationOwnerVerificationErrorV1> {
        if artifact_class != ErasureArtifactClassV1::TimelineReplay
            || WorldRecordingReceiptV1::from_canonical_cbor(artifact_bytes).is_err()
        {
            return Err(ArtifactRegistrationOwnerVerificationErrorV1::Rejected);
        }
        ArtifactRegistrationV1::new(ArtifactRegistrationFieldsV1 {
            artifact_class,
            artifact_digest: ArtifactRegistrationV1::artifact_digest(
                artifact_class,
                artifact_bytes,
            ),
            owner_reference: ArtifactRegistrationV1::owner_reference(owner_id),
            data_class: self.recording_data_class,
            optionality: pos_core::ArtifactOptionalityV1::Required,
            transition_rule: ArtifactTransitionRuleV1::PreserveExact,
            required_key_roles: self
                .recording_keys
                .iter()
                .map(|dependency| dependency.identity.role)
                .collect::<std::collections::BTreeSet<_>>()
                .into_iter()
                .collect(),
            key_dependencies: self.recording_keys.clone(),
            child_artifacts: Vec::new(),
        })
        .map_err(|_| ArtifactRegistrationOwnerVerificationErrorV1::Rejected)
    }

    fn classify_repro_manifest_label(
        &self,
        _owner_id: &OwnerIdV1,
        _label: &str,
    ) -> Result<ArtifactDataClassV1, ArtifactRegistrationOwnerVerificationErrorV1> {
        Ok(ArtifactDataClassV1::PublicRecord)
    }

    fn verify_committed_artifact(
        &self,
        _owner_id: &OwnerIdV1,
        _artifact_bytes: &[u8],
        _registration: &ArtifactRegistrationV1,
    ) -> Result<(), ArtifactRegistrationOwnerVerificationErrorV1> {
        Ok(())
    }
}

type ReproManifestInputs = (OwnerIdV1, Hash, Vec<ArtifactRegistrationInputV1>);

fn prepare_repro_manifest_inputs(
    seed: u8,
    world_timeline: TimelineId,
    verifier: &TestOnlyStructuralOwnerVerifier,
) -> Result<ReproManifestInputs, Box<dyn std::error::Error>> {
    let owner_id = OwnerIdV1::from_static("wave8-store-owner");
    let owner_reference = ArtifactRegistrationV1::owner_reference(&owner_id);
    let operation_id = Hash::from_bytes([seed; 32]);
    let commit_receipt_digest = Hash::from_bytes([0x52; 32]);
    let recording = WorldRecordingReceiptV1::new(WorldRecordingReceiptInputV1 {
        binding_hash: Hash::from_bytes([0x53; 32]),
        operation_id,
        actual_commit_receipt_digest: commit_receipt_digest,
        installed_inventory_generation: Hash::from_bytes([0x54; 32]),
    })?;
    let world_handle = WorldReplayHandleV1::new(WorldReplayHandleInputV1 {
        owner_reference,
        timeline_id: world_timeline,
        cut_id: 2,
        commit_receipt_digest,
        recording_receipt_digest: recording.digest(),
        logical_head: 0,
        stitched_head_hash: Hash::from_bytes([0x55; 32]),
    })?;
    let admission = AdapterAdmissionV1::new(AdapterAdmissionInputV1 {
        owner_reference,
        configuration_generation: 1,
        scope_digest: Hash::from_bytes([0x56; 32]),
        entries: Vec::new(),
    })?;
    let transcript = AdapterTranscriptV1::new(AdapterTranscriptInputV1 {
        owner_reference,
        world_handle,
        run_operation_id: operation_id,
        adapter_admission_digest: admission.digest(),
        calls: Vec::new(),
    })?;
    let root = ReproManifestRootV1::new(ReproManifestRootInputV1 {
        owner_reference,
        world_handle,
        run_operation_id: operation_id,
        plugin_roster_digest: admission.as_input().scope_digest,
        adapter_transcript_digest: transcript.digest(),
        created_at_micros: 2,
        label: None,
    })?;
    let admission_bytes = admission.to_canonical_cbor();
    let transcript_bytes = transcript.to_canonical_cbor();
    let recording_bytes = recording.to_canonical_cbor();
    let root_bytes = root.to_canonical_cbor();
    let admission_registration = extract_adapter_admission_registration_v1(&admission_bytes)?;
    let transcript_registration = extract_adapter_transcript_registration_v1(
        &transcript_bytes,
        &admission_bytes,
        &admission_registration,
    )?;
    let recording_registration = verifier.derive_native_registration(
        &owner_id,
        ErasureArtifactClassV1::TimelineReplay,
        &recording_bytes,
    )?;
    let root_registration =
        extract_repro_manifest_root_registration_v1(ReproManifestRootRegistrationInputV1 {
            root_bytes: &root_bytes,
            recording_receipt_bytes: &recording_bytes,
            recording_registration: &recording_registration,
            transcript_bytes: &transcript_bytes,
            admission_bytes: &admission_bytes,
            admission_registration: &admission_registration,
            transcript_registration: &transcript_registration,
            owner_id: &owner_id,
            label_data_class: None,
        })?;
    let root_address = root_registration.address();
    let inputs = [
        (owner_id, admission_bytes, admission_registration),
        (owner_id, transcript_bytes, transcript_registration),
        (owner_id, recording_bytes, recording_registration),
        (owner_id, root_bytes, root_registration),
    ]
    .into_iter()
    .map(
        |(owner_id, artifact_bytes, registration)| ArtifactRegistrationInputV1 {
            owner_id,
            artifact_bytes,
            registration_cbor: registration.canonical_cbor().to_vec(),
        },
    )
    .collect();
    Ok((owner_id, root_address, inputs))
}

fn close_repro_manifest_recording<R: AdapterRecordingStoreV1 + ?Sized>(
    store: &mut R,
    batch: &PreparedArtifactRegistrationBatchV1,
) -> Result<(), AdapterRecordingStoreErrorV1> {
    let root = batch
        .records()
        .iter()
        .find(|record| record.registration_address() == batch.root_registration_address())
        .and_then(|record| ReproManifestRootV1::from_canonical_cbor(record.artifact_bytes()).ok())
        .ok_or(AdapterRecordingStoreErrorV1::CorruptState)?;
    let admission = batch
        .records()
        .iter()
        .find(|record| record.artifact_bytes().get(2..6) == Some(b"MAA1"))
        .and_then(|record| AdapterAdmissionV1::from_canonical_cbor(record.artifact_bytes()).ok())
        .ok_or(AdapterRecordingStoreErrorV1::CorruptState)?;
    let session = AdapterRecordingSessionV1::new(
        root.as_input().owner_reference,
        root.as_input().world_handle,
        root.as_input().run_operation_id,
        admission,
    )?;
    store.open_adapter_recording_session(session)?;
    store
        .close_adapter_recording_session(
            root.as_input().owner_reference,
            root.as_input().run_operation_id,
        )
        .map(|_| ())
}

/// Commit one MRM1 closure of run `seed`, recorded from the World run of
/// `timeline` and bound to it, whose WCR1 recording is `verifier`'s.
fn commit_bound_closure(
    store: &LocalStore,
    seed: u8,
    timeline: TimelineId,
    verifier: &TestOnlyStructuralOwnerVerifier,
) -> TestResult {
    let (owner_id, root_address, inputs) = prepare_repro_manifest_inputs(seed, timeline, verifier)?;
    let batch = prepare_artifact_registration_batch_v1(
        owner_id,
        root_address,
        Some(timeline),
        inputs,
        verifier,
    )?;
    let mut sqlite = store.sqlite()?;
    close_repro_manifest_recording(&mut sqlite, &batch)?;
    EventStore::commit_artifact_registration_batch(&mut sqlite, batch)?;
    Ok(())
}

/// The cells decision 1B gives every bound ARD1 row of `class`: its owner
/// cell, and the Key and Backup cells of each role-7 dependency's target.
fn ard1_cells(
    store: &LocalStore,
    timeline: TimelineId,
    class: ArtifactDataClassV1,
) -> TestResult<Vec<Cell>> {
    let rows = EventStore::artifact_registrations_for_timeline(&store.sqlite()?, timeline, 4_096)?;
    let mut cells = Vec::new();
    for row in rows
        .iter()
        .filter(|row| row.registration().fields().data_class == class)
    {
        let digest = ErasureReferenceV1::from_digest(*row.artifact_digest().as_bytes());
        // No MRM1 closure record is a report class, so each is an
        // `artifact-store` cell (D5).
        cells.push((
            local_target(row.artifact_class(), digest, reference(0))?,
            ErasureInventoryCategoryV1::Artifact,
            "artifact-store",
        ));
        for dependency in &row.registration().fields().key_dependencies {
            if dependency.identity.role == KeyRoleV1::CommunityArtifactEncryption {
                cells.extend(key_cells(local_target(
                    row.artifact_class(),
                    digest,
                    pos_core::local_erasure_key_digest_v1(&dependency.identity)?,
                )?));
            }
        }
    }
    Ok(cells)
}

/// An owned store with two private closures, one whose recording depends
/// on a role-7 key, and one consented closure, all bound to the owned
/// Timeline.
fn ard1_store() -> TestResult<OwnedStore> {
    let owned = OwnedStore::new()?;
    let community = pos_core::ArtifactKeyDependencyV1 {
        identity: KeyIdentityV1::new("community:x", KeyRoleV1::CommunityArtifactEncryption, 1),
        material_digest: Hash::from_bytes([0x91; 32]),
        private_material_required: true,
    };
    commit_bound_closure(
        &owned.store,
        0x51,
        owned.owned,
        &TestOnlyStructuralOwnerVerifier {
            recording_data_class: ArtifactDataClassV1::PrivateSubjectData,
            recording_keys: vec![community],
        },
    )?;
    commit_bound_closure(
        &owned.store,
        0x71,
        owned.owned,
        &TestOnlyStructuralOwnerVerifier {
            recording_data_class: ArtifactDataClassV1::PrivateSubjectData,
            recording_keys: Vec::new(),
        },
    )?;
    commit_bound_closure(
        &owned.store,
        0x61,
        owned.owned,
        &TestOnlyStructuralOwnerVerifier {
            recording_data_class: ArtifactDataClassV1::ConsentedSharedData,
            recording_keys: Vec::new(),
        },
    )?;
    Ok(owned)
}

#[test]
fn bound_ard1_rows_of_the_private_class_and_their_role_7_keys_are_targets() -> TestResult {
    let owned = ard1_store()?;
    let mut cells = store_cells()?;
    cells.push(payload_cell(owned.owned)?);
    cells.extend(subject_key_cells()?);
    let ard1 = ard1_cells(
        &owned.store,
        owned.owned,
        ArtifactDataClassV1::PrivateSubjectData,
    )?;
    // Two private recordings, one with a role-7 key: two Artifact cells and
    // that key's Key and Backup cells; the consented recording is filtered
    // out.
    assert_eq!(ard1.len(), 4);
    cells.extend(ard1);
    let (host, signed) = signed_freeze(
        &owned.store,
        1,
        ErasureScopeV1::PrivateSubjectData,
        |_| Ok(()),
        |_| Ok(Vec::new()),
    )?;
    assert_committed_freeze(
        &owned.store,
        host,
        request_of(1)?,
        vec![owned.owned],
        &cells,
        &signed,
    )
}

#[test]
fn bound_ard1_rows_of_the_consented_class_are_targets() -> TestResult {
    let owned = ard1_store()?;
    let mut cells = store_cells()?;
    let ard1 = ard1_cells(
        &owned.store,
        owned.owned,
        ArtifactDataClassV1::ConsentedSharedData,
    )?;
    assert_eq!(ard1.len(), 1);
    cells.extend(ard1);
    let (host, signed) = signed_freeze(
        &owned.store,
        2,
        ErasureScopeV1::ConsentedSharedData,
        |_| Ok(()),
        |_| Ok(Vec::new()),
    )?;
    assert_committed_freeze(
        &owned.store,
        host,
        request_of(2)?,
        vec![owned.owned],
        &cells,
        &signed,
    )
}

impl LocalStore {
    /// Register the actor's role-0 subject keys of epochs `epochs`.
    fn register_subject_keys(&self, epochs: std::ops::RangeInclusive<u64>) -> TestResult {
        self.register_subject_owner_keys(KeyRoleV1::SubjectDataEncryption, epochs)
    }

    /// Register keys of `role` and `epochs` under the actor's ADR-091
    /// subject owner.
    fn register_subject_owner_keys(
        &self,
        role: KeyRoleV1,
        epochs: std::ops::RangeInclusive<u64>,
    ) -> TestResult {
        let mut sqlite = self.sqlite()?;
        let mut registry = sqlite.load_key_registry()?.ok_or("no key registry")?;
        let owner = subject_key(1)?.owner_id;
        for epoch in epochs {
            let mut material = [0x80; 32];
            material[..8].copy_from_slice(&epoch.to_be_bytes());
            material[8] = role.code();
            registry
                .register_key(KeyRegistrationV1::new(
                    KeyIdentityV1::from_parts(owner, role, epoch),
                    Hash::from_bytes(material),
                    None,
                ))
                .map_err(fail)?;
        }
        sqlite.save_key_registry(&registry)?;
        Ok(())
    }
}

#[test]
fn the_key_and_backup_bound_is_exact_at_submit() -> TestResult {
    let store = LocalStore::new(&GrantShape::standard())?;
    rejected(&store, &[1])?;
    // No owned Timeline: the store target and one key target per role-0
    // key, each with a Key and a Backup cell. 4,095 keys fill the 4,096
    // targets.
    store.register_subject_keys(1..=4_095)?;
    {
        let mut host = store.host(&local_case()?, 4_096)?;
        let mut sender = host.command_sender()?;
        assert_eq!(
            sender
                .submit_local_erasure(&submission(1, ErasureScopeV1::PrivateSubjectData)?)
                .map_err(fail)?
                .lifecycle(),
            ErasureLifecycleV1::Submitted
        );
        sender.reject_erasure_request(request_of(1)?, rejection(1)?.reference()?)?;
    }
    // A 4,096th key is a 4,097th target.
    store.register_subject_keys(4_096..=4_096)?;
    let over = |store: &LocalStore, key| -> TestResult {
        let mut host = store.host(&local_case()?, 4_096)?;
        assert_eq!(
            host.command_sender()?
                .submit_local_erasure(&submission(key, ErasureScopeV1::PrivateSubjectData)?)
                .map(drop),
            Err(LocalErasureSubmitErrorV1::ScopeTooLarge)
        );
        Ok(())
    };
    over(&store, 2)?;
    // 4,097 identities are over the key list's own bound.
    store.register_subject_keys(4_097..=4_097)?;
    over(&store, 3)
}

#[test]
fn the_key_list_is_bounded_on_its_own() -> TestResult {
    let store = LocalStore::new(&GrantShape::standard())?;
    rejected(&store, &[1])?;
    // One role-0 key and 4,095 role-7 keys of the subject owner: 4,096
    // identities, a closure of two targets.
    store.register_subject_keys(1..=1)?;
    store.register_subject_owner_keys(KeyRoleV1::CommunityArtifactEncryption, 1..=4_095)?;
    {
        let mut host = store.host(&local_case()?, 4_096)?;
        let mut sender = host.command_sender()?;
        assert_eq!(
            sender
                .submit_local_erasure(&submission(1, ErasureScopeV1::PrivateSubjectData)?)
                .map_err(fail)?
                .lifecycle(),
            ErasureLifecycleV1::Submitted
        );
        sender.reject_erasure_request(request_of(1)?, rejection(1)?.reference()?)?;
    }
    // A 4,097th identity is over the list's bound, though the closure would
    // still hold two targets.
    store.register_subject_owner_keys(KeyRoleV1::CommunityArtifactEncryption, 4_096..=4_096)?;
    let mut host = store.host(&local_case()?, 4_096)?;
    assert_eq!(
        host.command_sender()?
            .submit_local_erasure(&submission(2, ErasureScopeV1::PrivateSubjectData)?)
            .map(drop),
        Err(LocalErasureSubmitErrorV1::ScopeTooLarge)
    );
    Ok(())
}

#[test]
fn no_timeline_is_deletable_under_the_host_and_the_partition_survives() -> TestResult {
    let owned = OwnedStore::new()?;
    let request = request_of(1)?;
    let (host, signed) = signed_freeze(
        &owned.store,
        1,
        ErasureScopeV1::PrivateSubjectData,
        |_| Ok(()),
        |_| Ok(Vec::new()),
    )?;
    drop(host);
    // The fence is binding-level: a store bound to a fail-closed gate, as
    // the erasure host binds it, refuses every direct deletion before any
    // lookup, so an affected, an unaffected and a nonexistent Timeline are
    // refused alike, whatever the request's state.
    {
        let mut sqlite = SqliteStore::open(&owned.store.path)?;
        sqlite.bind_erasure_gate(Arc::new(ErasureContainmentGateV1::new_fail_closed()))?;
        for timeline in [owned.owned, owned.other, TimelineId::new()] {
            assert!(matches!(
                sqlite.delete_timeline(timeline),
                Err(pos_core::CoreError::ErasureContainmentUnavailable)
            ));
        }
    }
    // After a restart the committed freeze still verifies, record for record.
    let mut host = owned.store.host(&local_case()?, 4_096)?;
    assert_eq!(
        lifecycle(&mut host, request)?,
        ErasureLifecycleV1::AccessFrozen
    );
    assert_frozen(&mut host, &[owned.owned], owned.other)?;
    let mut cells = store_cells()?;
    cells.push(payload_cell(owned.owned)?);
    cells.extend(subject_key_cells()?);
    assert_committed_freeze(
        &owned.store,
        host,
        request,
        vec![owned.owned],
        &cells,
        &signed,
    )
}

#[test]
fn an_anchor_only_scope_freezes_and_recovers() -> TestResult {
    // An actor with a role-0 key and no owned Timeline: ERSC1 is the
    // subject anchor alone.
    let store = LocalStore::new(&GrantShape::standard())?;
    let other = store.owned_roots(other_actor(), 1)?[0];
    store.register_subject_keys(1..=1)?;
    let request = request_of(1)?;
    let (host, signed) = signed_freeze(
        &store,
        1,
        ErasureScopeV1::PrivateSubjectData,
        |_| Ok(()),
        |_| Ok(Vec::new()),
    )?;
    drop(host);
    let mut host = store.host(&local_case()?, 4_096)?;
    assert_eq!(
        lifecycle(&mut host, request)?,
        ErasureLifecycleV1::AccessFrozen
    );
    assert_frozen(&mut host, &[], other)?;
    let mut cells = store_cells()?;
    cells.extend(subject_key_cells()?);
    assert_committed_freeze(&store, host, request, Vec::new(), &cells, &signed)
}
