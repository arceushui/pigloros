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

    fn validate_attempt_with_view(
        &self,
        _view: &dyn ErasureAuthorityReadViewV1,
        _request: &pos_core::ErasureRequestV1,
        _admission: &pos_core::ErasureRetryAdmissionV1,
    ) -> Result<(), ErasureErrorV1> {
        Err(ErasureErrorV1::PolicyConflict)
    }

    fn validate_acknowledgement_with_view(
        &self,
        _view: &dyn ErasureAuthorityReadViewV1,
        _acknowledgement: &pos_core::ErasureAcknowledgementProvenanceV1,
    ) -> Result<(), ErasureErrorV1> {
        Err(ErasureErrorV1::PolicyConflict)
    }

    fn validate_receipt_with_view(
        &self,
        _view: &dyn ErasureAuthorityReadViewV1,
        _attempt: &pos_core::ErasureRetryAdmissionV1,
        _receipt: &pos_core::ErasureReceiptV1,
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
    CapabilityRevocationV1, CapabilityScopeDraftV1, CapabilityScopeV1, EntityId,
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

/// The recorded root grant: its resources, actors, Timeline and registry.
struct GrantShape {
    resources: Vec<String>,
    actors: Vec<EntityId>,
    timeline: TimelineId,
    registry: [u8; 32],
}

impl GrantShape {
    fn standard() -> Self {
        Self {
            resources: vec!["erasure".to_owned(), "timeline".to_owned()],
            actors: vec![actor()],
            timeline: authority_timeline(),
            registry: REGISTRY,
        }
    }

    fn root_grant(&self) -> TestResult<CapabilityGrantV1> {
        let principal = principal()?;
        let scope = CapabilityScopeV1::try_from_draft(CapabilityScopeDraftV1 {
            resources: self.resources.clone(),
            actions: vec!["request".to_owned()],
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
            grant_id: grant_id(),
            grantor: principal.clone(),
            grantee: AuthorityGranteeV1::Principal(principal.clone()),
            trust_domain: principal.trust_domain().to_owned(),
            scope,
            valid_from_position: Seq::from_u64(1),
            valid_until_position: Seq::from_u64(u64::MAX),
            parent_grant_id: None,
            delegation_depth: 0,
            max_delegation_depth: 0,
            permitted_delegate_classes: Vec::new(),
            consent_references: Vec::new(),
            policy_revision: Hash::from_bytes([0x75; 32]),
            issuance_timeline: self.timeline,
            issuance_seq: Seq::from_u64(1),
            revocation_epoch: 0,
            revocation_fence: None,
            authority_registry_digest: Hash::from_bytes(self.registry),
        })
        .map_err(fail)
    }
}

/// An authority-persistence host over the registry that attests `grant`,
/// bound to `store`.
fn bound_authority_host(
    store: &mut SqliteStore,
    grant: &CapabilityGrantV1,
) -> TestResult<AuthorityPersistenceHostV1> {
    let registry = AuthorityRegistrySnapshotV1::try_new(
        grant.authority_registry_digest(),
        vec![Hash::from_bytes([0x76; 32])],
        vec![grant.binding_digest().map_err(fail)?],
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
        let host = bound_authority_host(&mut store, &grant)?;
        let permit = host.authorize_grant(&grant).map_err(fail)?;
        store.issue_capability_grant(permit, &grant).map_err(fail)?;
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
        let host = bound_authority_host(&mut store, &grant)?;
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
    Ok(LocalErasureAuthorizationV1 {
        principal_ref: principal_ref()?,
        actor_entity: actor(),
        operation: "erasure.request".to_owned(),
        authority_registry_digest: ErasureReferenceV1::from_digest(REGISTRY),
        authority_chain: authority_timeline(),
        chain_head_position: head,
        revocation_epoch: 0,
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
    // The revocation is fenced after the head request 1 is bound to.
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

#[test]
fn the_root_grant_must_match_the_composition_and_name_the_operation() -> TestResult {
    let refused = |shape: GrantShape, case: &Case| -> TestResult {
        let store = LocalStore::new(&shape)?;
        let mut host = store.host(case, 4_096)?;
        assert_eq!(
            host.command_sender()?
                .submit_local_erasure(&submission(1, ErasureScopeV1::PrivateSubjectData)?),
            Err(LocalErasureSubmitErrorV1::Host(
                ErasureHostErrorV1::AuthorizationDenied
            ))
        );
        Ok(())
    };
    let case = local_case()?;
    let mut shape = GrantShape::standard();
    shape.resources = vec!["timeline".to_owned()];
    refused(shape, &case)?;
    let mut shape = GrantShape::standard();
    shape.actors = vec![other_actor()];
    refused(shape, &case)?;
    let mut shape = GrantShape::standard();
    shape.registry = [0x77; 32];
    refused(shape, &case)?;
    // A root grant on another authority Timeline than the composition's.
    let mut shape = GrantShape::standard();
    shape.timeline = other_timeline();
    refused(shape, &case)?;
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
    let mut with_owner = bundle();
    with_owner.owners = vec![LocalErasureOwnerRowV1 {
        category: 1,
        ack_class: "key-registry".to_owned(),
        owner_ref: owner,
    }];
    let case = Case::signed(&with_owner, &bundle_root(), &[])?;
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
fn the_local_authority_refuses_an_unknown_attempt_or_unpinned_acknowledgement() -> TestResult {
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
    // The installed inventory holds no such request, and the detached view
    // reads no bundle the acknowledgement could pin, nor any attempt.
    assert_eq!(
        authority.admit_attempt(&view, &attempt).map(drop),
        Err(ErasureErrorV1::PolicyConflict)
    );
    assert_eq!(
        authority.admit_acknowledgement(&view, &acknowledgement),
        Err(ErasureErrorV1::TrustSnapshotInvalid)
    );
    assert_eq!(view.active_attempt(request).map(drop), missing);
    assert_eq!(view.frozen_trust(request).map(drop), missing);
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

/// A forged key, purpose confusion, a stale body: none freezes.
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
    ])
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

// ---------------------------------------------------------------------------
// Attempt, acknowledgement and receipt admission at the public seams
// (ADR-136 §5 and §6; acceptance tests 4, 6 and 8, authority parts). The
// tests play the C4 driver and signer: owner results are retained ELO1
// records, and every signature is made with the fixture signer key the
// bundle pins.
// ---------------------------------------------------------------------------

use std::sync::Mutex;

use pos_core::{
    local_erasure_coordinator_v1, local_erasure_receipt_body_reference_v1,
    ErasureAcknowledgementV1, ErasureArtifactTransitionV1, ErasureInventoryResultV1,
    ErasureReceiptV1, LocalErasureOwnerResultV1,
};

/// Every acknowledgement class of the compiled ELP1, with its category code.
const ALL_CLASSES: [(u64, &str); 8] = [
    (0, "artifact-store"),
    (0, "client-cache-signal"),
    (0, "export-recipient"),
    (0, "managed-report"),
    (0, "timeline-payload"),
    (1, "key-registry"),
    (2, "local-replica"),
    (3, "local-backup-inventory"),
];

/// The default bundle, with an owner for each of `classes`.
fn owned_bundle(classes: &[(u64, &str)]) -> TestResult<LocalErasureBundleV1> {
    let store = ErasureReferenceV1::from_digest(STORE_IDENTITY);
    let mut owners = Vec::new();
    for &(category, ack_class) in classes {
        owners.push(LocalErasureOwnerRowV1 {
            category,
            ack_class: ack_class.to_owned(),
            owner_ref: pos_core::local_erasure_owner_ref_v1(store, category, ack_class)?,
        });
    }
    owners.sort();
    let mut owned = bundle();
    owned.owners = owners;
    Ok(owned)
}

/// The ELO1 of `obligation` in `attempt`, negative with `error`.
const fn owner_result(
    attempt: &ErasureRetryAdmissionV1,
    obligation: &ErasureObligationV1,
    error: Option<ErasureErrorV1>,
) -> LocalErasureOwnerResultV1 {
    LocalErasureOwnerResultV1 {
        request: attempt.request(),
        attempt: attempt.reference(),
        obligation: obligation.reference(),
        command: obligation.command_identity(),
        owner_ref: obligation.owner(),
        error,
        effect_digest: reference(0xe0),
    }
}

/// ELO1 `result` and an ELS1 of `purpose` over it by `key` for the signer
/// identity at `epoch`: the records to retain, and the ELS1 address.
fn signed_result(
    result: &LocalErasureOwnerResultV1,
    purpose: LocalErasureSignaturePurposeV1,
    (key, epoch): (&SigningKey, u64),
) -> TestResult<(Vec<Vec<u8>>, ErasureReferenceV1)> {
    let signed = signature_record(purpose, result.reference()?, key, epoch)?;
    let address = signature_address(&signed)?;
    Ok((vec![result.to_canonical_cbor()?, signed], address))
}

/// The acknowledgement of `obligation` naming `evidence`.
const fn acknowledgement(
    obligation: &ErasureObligationV1,
    evidence: ErasureReferenceV1,
    outcome: ErasureAcknowledgementOutcomeV1,
) -> ErasureAcknowledgementV1 {
    ErasureAcknowledgementV1 {
        obligation: obligation.reference(),
        target: obligation.target(),
        owner: obligation.owner(),
        evidence,
        outcome,
    }
}

/// The receipt input of an attempt over `obligations`, one preserving
/// inventory row per obligation, issuing at `issue_position` under
/// `signature`. Core fills every field it derives from the record.
fn receipt_input(
    obligations: &[ErasureObligationV1],
    issue_position: u64,
    signature: ErasureReferenceV1,
) -> ErasureReceiptInputV1 {
    let mut inventories = ErasureReceiptInventoriesV1 {
        artifacts: Vec::new(),
        keys: Vec::new(),
        replicas: Vec::new(),
        backups: Vec::new(),
    };
    for obligation in obligations {
        let row = ErasureInventoryResultV1 {
            category: obligation.category(),
            target: obligation.target(),
            transition: ErasureArtifactTransitionV1 {
                from: ErasureReplayClaimV1::Exact,
                to: ErasureReplayClaimV1::Exact,
                reason: reference(0xd0),
                owner: obligation.owner(),
                acknowledgements: reference(0xd1),
                provenance: reference(0xd2),
            },
            retained_disclosure: reference(0xd3),
        };
        match obligation.category() {
            ErasureInventoryCategoryV1::Artifact => inventories.artifacts.push(row),
            ErasureInventoryCategoryV1::Key => inventories.keys.push(row),
            ErasureInventoryCategoryV1::Replica => inventories.replicas.push(row),
            ErasureInventoryCategoryV1::Backup => inventories.backups.push(row),
        }
    }
    ErasureReceiptInputV1 {
        request: reference(0),
        terminal_state: reference(0),
        coordinator: reference(0),
        lifecycle: ErasureLifecycleV1::Complete,
        freeze_position: 0,
        acknowledgements: Vec::new(),
        frozen_targets: Vec::new(),
        pending_owners: Vec::new(),
        failed_owners: Vec::new(),
        inventories,
        replay_claim: ErasureReplayClaimV1::Exact,
        policy: reference(0),
        trust: reference(0),
        provenance: reference(0),
        issue_position,
        signature,
        receipt_digest: reference(0),
    }
}

/// A frozen private request 1 of `actor()`, who owns one root Timeline and
/// holds a role-0 key, under `bundle`; its frozen obligations and its
/// attempt 0 as ADR-136 §5 and §6 derive it.
struct Attempted {
    store: LocalStore,
    owned: TimelineId,
    bundle: LocalErasureBundleV1,
    case: Case,
    request: ErasureReferenceV1,
    obligations: Vec<ErasureObligationV1>,
    input: ErasureRetryAdmissionInputV1,
    attempt: ErasureRetryAdmissionV1,
}

impl Attempted {
    fn new(mut actors: Vec<EntityId>, bundle: LocalErasureBundleV1) -> TestResult<Self> {
        actors.sort_unstable();
        let store = LocalStore::new(&GrantShape {
            actors,
            ..GrantShape::standard()
        })?;
        let owned = store.owned_roots(actor(), 1)?[0];
        store.register(KeyRegistrationV1::new(
            subject_key(1)?,
            Hash::from_bytes([0x81; 32]),
            None,
        ))?;
        let case = Case::signed(&bundle, &bundle_root(), &[])?;
        Self::freeze(&store, &case)?;
        let request = request_of(1)?;
        let mut cells = store_cells()?;
        cells.push(payload_cell(owned)?);
        cells.extend(subject_key_cells()?);
        let mut obligations = Vec::new();
        for (target, category, ack_class) in cells {
            obligations.push(ErasureObligationV1::new(ErasureObligationInputV1 {
                category,
                target,
                owner: pos_core::local_erasure_owner_ref_v1(
                    ErasureReferenceV1::from_digest(STORE_IDENTITY),
                    u64::from(category),
                    ack_class,
                )?,
                command_identity: destruction_command_reference(request, target),
            })?);
        }
        obligations.sort_unstable_by_key(ErasureObligationV1::reference);
        let input = Self::attempt_input(store.head, bundle.reference()?, &obligations, None)?;
        let attempt = ErasureRetryAdmissionV1::new(input.clone())?;
        Ok(Self {
            store,
            owned,
            bundle,
            case,
            request,
            obligations,
            input,
            attempt,
        })
    }

    /// Freeze request 1 for private subject data under `case`, with a
    /// purpose-0 ELS1 by the fixture signer over the prepared body.
    fn freeze(store: &LocalStore, case: &Case) -> TestResult {
        let digest = {
            let mut host = store.host(case, 4_096)?;
            prepared(store, &mut host, 1, ErasureScopeV1::PrivateSubjectData)?
        };
        let signed = signature_record(
            LocalErasureSignaturePurposeV1::FreezeAuthorization,
            digest,
            &erasure_signer(),
            1,
        )?;
        store.retain(std::slice::from_ref(&signed))?;
        let mut host = store.host(case, 4_096)?;
        let state = host
            .command_sender()?
            .freeze_access(request_of(1)?, &freeze(signature_address(&signed)?))?;
        assert_eq!(state.lifecycle(), ErasureLifecycleV1::AccessFrozen);
        Ok(())
    }

    /// ERRA1 of request 1 over `obligations` under `trust`: attempt 0 at 2
    /// with the horizon as deadline, or the retry after `source`, one past
    /// its issue position, with the deadline one attempt window later.
    fn attempt_input(
        head: u64,
        trust: ErasureReferenceV1,
        obligations: &[ErasureObligationV1],
        source: Option<&ErasureReceiptV1>,
    ) -> TestResult<ErasureRetryAdmissionInputV1> {
        let (attempt_ordinal, admitted_position, deadline_position) =
            source.map_or((0, 2, LOCAL_ERASURE_ATTEMPT_WINDOW_V1), |receipt| {
                let admitted = receipt.issue_position() + 1;
                (1, admitted, admitted + LOCAL_ERASURE_ATTEMPT_WINDOW_V1)
            });
        Ok(ErasureRetryAdmissionInputV1 {
            request: request_of(1)?,
            attempt_ordinal,
            source_receipt: source.map(ErasureReceiptV1::receipt_digest),
            unresolved_obligations: obligations
                .iter()
                .map(ErasureObligationV1::reference)
                .collect(),
            command_identities: obligations
                .iter()
                .map(ErasureObligationV1::command_identity)
                .collect(),
            policy: LOCAL_ERASURE_POLICY_REFERENCE_V1,
            trust,
            admitted_position,
            deadline_position,
            authorization_provenance: authorization(1, head)?.reference()?,
        })
    }

    /// The case of this bundle with admissions read at `clock`.
    fn case_at(&self, clock: fn() -> u64) -> TestResult<Case> {
        let mut case = Case::signed(&self.bundle, &bundle_root(), &[])?;
        case.clock = clock;
        Ok(case)
    }

    fn host(&self) -> TestResult<ErasureExecutionHostV1> {
        self.store.host(&self.case, 4_096)
    }

    /// The obligation of `category`.
    fn obligation_of(
        &self,
        category: ErasureInventoryCategoryV1,
    ) -> TestResult<ErasureObligationV1> {
        Ok(*self
            .obligations
            .iter()
            .find(|obligation| obligation.category() == category)
            .ok_or("no obligation of the category")?)
    }

    /// Retain an ELO1 of attempt 0 for each obligation of `obligations`,
    /// negative with its `error_of` and signed by the fixture signer, and
    /// return the matching acknowledgements.
    fn owner_results(
        &self,
        obligations: &[ErasureObligationV1],
        error_of: impl Fn(&ErasureObligationV1) -> Option<ErasureErrorV1>,
    ) -> TestResult<Vec<ErasureAcknowledgementV1>> {
        self.signed_results(&self.attempt, obligations, (&erasure_signer(), 1), error_of)
    }

    /// As [`Self::owner_results`], for `attempt` and signed by `signer`.
    fn signed_results(
        &self,
        attempt: &ErasureRetryAdmissionV1,
        obligations: &[ErasureObligationV1],
        signer: (&SigningKey, u64),
        error_of: impl Fn(&ErasureObligationV1) -> Option<ErasureErrorV1>,
    ) -> TestResult<Vec<ErasureAcknowledgementV1>> {
        let mut retained = Vec::new();
        let mut acknowledgements = Vec::new();
        for obligation in obligations {
            let error = error_of(obligation);
            let (records, address) = signed_result(
                &owner_result(attempt, obligation, error),
                LocalErasureSignaturePurposeV1::OwnerResult,
                signer,
            )?;
            retained.extend(records);
            let outcome = if error.is_some() {
                ErasureAcknowledgementOutcomeV1::Negative
            } else {
                ErasureAcknowledgementOutcomeV1::Acknowledged
            };
            acknowledgements.push(acknowledgement(obligation, address, outcome));
        }
        self.store.retain(&retained)?;
        Ok(acknowledgements)
    }

    /// Dispatch attempt 0 and admit `acknowledgements` on a fresh host.
    fn acknowledged(&self, acknowledgements: &[ErasureAcknowledgementV1]) -> TestResult {
        self.acknowledged_under(&self.case, acknowledgements)
    }

    /// As [`Self::acknowledged`], on a host of `case`.
    fn acknowledged_under(
        &self,
        case: &Case,
        acknowledgements: &[ErasureAcknowledgementV1],
    ) -> TestResult {
        let mut host = self.store.host(case, 4_096)?;
        let mut sender = host.command_sender()?;
        sender.dispatch_erasure_destruction(self.request, &self.attempt)?;
        for acknowledged in acknowledgements {
            sender.acknowledge_erasure(self.request, *acknowledged)?;
        }
        Ok(())
    }

    /// A host over this store whose authority is a [`Probe`] of the Local
    /// authority `case` composes, evaluating `attempts` on every attempt
    /// admission.
    fn probe_host(
        &self,
        case: &Case,
        attempts: Vec<ErasureRetryAdmissionV1>,
    ) -> TestResult<(ErasureExecutionHostV1, Arc<Probe>)> {
        self.probe_host_with(case, attempts, false)
    }

    /// A host over this store whose authority is a lenient [`Probe`] of
    /// this case's Local authority: it commits attempts, acknowledgements
    /// and receipts the Local authority refuses.
    fn lenient_host(&self) -> TestResult<ErasureExecutionHostV1> {
        Ok(self.probe_host_with(&self.case, Vec::new(), true)?.0)
    }

    fn probe_host_with(
        &self,
        case: &Case,
        attempts: Vec<ErasureRetryAdmissionV1>,
        lenient: bool,
    ) -> TestResult<(ErasureExecutionHostV1, Arc<Probe>)> {
        let probe = Arc::new(Probe {
            local: case.compose(&mut self.store.sqlite()?).map_err(fail)?,
            attempts,
            attempt_results: Mutex::new(Vec::new()),
            frozen_trusts: Mutex::new(Vec::new()),
            lenient,
        });
        let composition = ErasureCoordinatorCompositionV1::new(
            Arc::clone(&probe) as Arc<dyn ErasureCoordinatorAuthorityV1>,
            local_erasure_coordinator_v1(ErasureReferenceV1::from_digest(STORE_IDENTITY))?,
        )?;
        let host = ErasureExecutionHostV1::open_with_authority(
            StoreConfig::Sqlite {
                path: self.store.path.clone(),
            },
            &composition,
            ErasureRecoveryLimitsV1::from_maximum_requests(4_096)?,
        )?;
        Ok((host, probe))
    }

    /// `CA(ERCB1)` of the receipt that finalizing the active attempt with
    /// `input` would commit under this case.
    fn receipt_body(&self, input: &ErasureReceiptInputV1) -> TestResult<ErasureReferenceV1> {
        self.receipt_body_under(&self.case, input)
    }

    /// `CA(ERCB1)` of the receipt that finalizing the active attempt with
    /// `input` would commit under `case`, previewed by the host from the
    /// committed record as a signer re-derives it. The Local authority
    /// refuses the unsigned input itself.
    fn receipt_body_under(
        &self,
        case: &Case,
        input: &ErasureReceiptInputV1,
    ) -> TestResult<ErasureReferenceV1> {
        let mut host = self.store.host(case, 4_096)?;
        let mut sender = host.command_sender()?;
        let receipt = sender.preview_erasure_receipt(self.request, input)?;
        assert_eq!(
            sender
                .finalize_erasure_request(self.request, input)
                .map(drop),
            Err(ErasureHostErrorV1::AuthorizationDenied)
        );
        // The refused finalize committed nothing: the preview is unchanged.
        assert_eq!(
            sender.preview_erasure_receipt(self.request, input)?,
            receipt
        );
        Ok(local_erasure_receipt_body_reference_v1(&receipt)?)
    }
}

/// The Local authority, probed inside real host commands: each attempt
/// admission also evaluates `attempts` and records the frozen trust of its
/// request over the same host-built view.
///
/// A `lenient` probe accepts every attempt, acknowledgement and receipt,
/// at admission and at recovery, whatever the Local authority decides. It
/// plays a host that skipped those checks, so a test can commit evidence
/// the Local authority must then refuse at recovery.
struct Probe {
    local: ErasureCoordinatorCompositionV1,
    attempts: Vec<ErasureRetryAdmissionV1>,
    attempt_results: Mutex<Vec<Result<(), ErasureErrorV1>>>,
    frozen_trusts: Mutex<Vec<Result<Option<ErasureReferenceV1>, ErasureErrorV1>>>,
    lenient: bool,
}

impl Probe {
    /// The Local authority's `decision`, or acceptance for a lenient probe.
    const fn decide(&self, decision: Result<(), ErasureErrorV1>) -> Result<(), ErasureErrorV1> {
        if self.lenient {
            Ok(())
        } else {
            decision
        }
    }
}

impl ErasureCoordinatorAuthorityV1 for Probe {
    fn validate_freeze_authorization_with_view(
        &self,
        view: &dyn ErasureAuthorityReadViewV1,
        admission: &ErasureFreezeAdmissionEvidenceV1,
        authorization: &ErasureFreezeAuthorizationEvidenceV1,
    ) -> Result<(), ErasureErrorV1> {
        self.local
            .authority()
            .validate_freeze_authorization_with_view(view, admission, authorization)
    }

    fn validate_scope_extension_with_view(
        &self,
        view: &dyn ErasureAuthorityReadViewV1,
        extension: &ErasureScopeExtensionV1,
    ) -> Result<(), ErasureErrorV1> {
        self.local
            .authority()
            .validate_scope_extension_with_view(view, extension)
    }

    fn validate_administrative_resolution_with_view(
        &self,
        view: &dyn ErasureAuthorityReadViewV1,
        resolution: &ErasureAdministrativeResolutionV1,
    ) -> Result<(), ErasureErrorV1> {
        self.local
            .authority()
            .validate_administrative_resolution_with_view(view, resolution)
    }

    fn validate_attempt_with_view(
        &self,
        view: &dyn ErasureAuthorityReadViewV1,
        request: &pos_core::ErasureRequestV1,
        admission: &pos_core::ErasureRetryAdmissionV1,
    ) -> Result<(), ErasureErrorV1> {
        self.decide(
            self.local
                .authority()
                .validate_attempt_with_view(view, request, admission),
        )
    }

    fn validate_acknowledgement_with_view(
        &self,
        view: &dyn ErasureAuthorityReadViewV1,
        acknowledgement: &pos_core::ErasureAcknowledgementProvenanceV1,
    ) -> Result<(), ErasureErrorV1> {
        self.decide(
            self.local
                .authority()
                .validate_acknowledgement_with_view(view, acknowledgement),
        )
    }

    fn validate_receipt_with_view(
        &self,
        view: &dyn ErasureAuthorityReadViewV1,
        attempt: &pos_core::ErasureRetryAdmissionV1,
        receipt: &pos_core::ErasureReceiptV1,
    ) -> Result<(), ErasureErrorV1> {
        self.decide(
            self.local
                .authority()
                .validate_receipt_with_view(view, attempt, receipt),
        )
    }

    fn verified_topology_observation(
        &self,
        view: &dyn ErasureAuthorityReadViewV1,
        request: ErasureReferenceV1,
        manifest_digest: ErasureReferenceV1,
    ) -> Result<Option<ErasureVerifiedTopologyObservationV1>, ErasureErrorV1> {
        self.local
            .authority()
            .verified_topology_observation(view, request, manifest_digest)
    }

    fn verified_topology_observation_for_candidate(
        &self,
        view: &dyn ErasureAuthorityReadViewV1,
        request: ErasureReferenceV1,
        manifest_digest: ErasureReferenceV1,
        candidate: &TimelineMeta,
    ) -> Result<Option<ErasureVerifiedTopologyObservationV1>, ErasureErrorV1> {
        self.local
            .authority()
            .verified_topology_observation_for_candidate(view, request, manifest_digest, candidate)
    }

    fn authenticate(
        &self,
        view: &dyn ErasureAuthorityReadViewV1,
        request: &ErasureRequestV1,
    ) -> Result<(), ErasureErrorV1> {
        self.local.authority().authenticate(view, request)
    }

    fn admit_authorization(
        &self,
        view: &dyn ErasureAuthorityReadViewV1,
        request: ErasureReferenceV1,
        provenance: ErasureReferenceV1,
        decision: ErasureAuthorizationDecisionV1,
    ) -> Result<(), ErasureErrorV1> {
        self.local
            .authority()
            .admit_authorization(view, request, provenance, decision)
    }

    fn admit_corrected_submission(
        &self,
        view: &dyn ErasureAuthorityReadViewV1,
        request: &ErasureRequestV1,
        correction: &ErasureCorrectionProvenanceV1,
    ) -> Result<(), ErasureErrorV1> {
        self.local
            .authority()
            .admit_corrected_submission(view, request, correction)
    }

    fn admit_atomic_freeze(
        &self,
        view: &dyn ErasureAuthorityReadViewV1,
        request: ErasureReferenceV1,
        requested: &ErasureStateTransitionV1,
    ) -> Result<ErasureAtomicFreezeResultV1, ErasureErrorV1> {
        self.local
            .authority()
            .admit_atomic_freeze(view, request, requested)
    }

    fn admit_scope_extension(
        &self,
        view: &dyn ErasureAuthorityReadViewV1,
        extension: &ErasureScopeExtensionV1,
    ) -> Result<(), ErasureErrorV1> {
        self.local
            .authority()
            .admit_scope_extension(view, extension)
    }

    fn admit_fork_scope_extension(
        &self,
        view: &dyn ErasureAuthorityReadViewV1,
        extension: &ErasureScopeExtensionV1,
        input: &ErasureForkAdmissionInputV1,
    ) -> Result<(), ErasureErrorV1> {
        self.local
            .authority()
            .admit_fork_scope_extension(view, extension, input)
    }

    fn resolve_fork_child_scope(
        &self,
        view: &dyn ErasureAuthorityReadViewV1,
        parent: TimelineId,
        child: &TimelineMeta,
    ) -> Result<ErasureReferenceV1, ErasureErrorV1> {
        self.local
            .authority()
            .resolve_fork_child_scope(view, parent, child)
    }

    fn resolve_fork_scope_extension(
        &self,
        view: &dyn ErasureAuthorityReadViewV1,
        requirement: ErasureForkScopeRequirementV1,
        input: &ErasureForkAdmissionInputV1,
    ) -> Result<ErasureScopeExtensionV1, ErasureErrorV1> {
        self.local
            .authority()
            .resolve_fork_scope_extension(view, requirement, input)
    }

    fn admit_administrative_resolution(
        &self,
        view: &dyn ErasureAuthorityReadViewV1,
        resolution: &ErasureAdministrativeResolutionV1,
    ) -> Result<(), ErasureErrorV1> {
        self.local
            .authority()
            .admit_administrative_resolution(view, resolution)
    }

    fn dispatch_destruction(
        &self,
        view: &dyn ErasureAuthorityReadViewV1,
        request: ErasureReferenceV1,
        commands: &[ErasureDestructionCommandV1],
    ) -> Result<(), ErasureErrorV1> {
        self.local
            .authority()
            .dispatch_destruction(view, request, commands)
    }

    fn admit_attempt(
        &self,
        view: &dyn ErasureAuthorityReadViewV1,
        admission: &ErasureRetryAdmissionV1,
    ) -> Result<ErasureAttemptQuotaReservationV1, ErasureErrorV1> {
        let probed = self
            .attempts
            .iter()
            .map(|attempt| {
                self.local
                    .authority()
                    .admit_attempt(view, attempt)
                    .map(drop)
            })
            .collect::<Vec<_>>();
        let frozen = view.frozen_trust(admission.request());
        self.attempt_results
            .lock()
            .map_err(|_| ErasureErrorV1::ProvenanceMissing)
            .map(|mut results| results.extend(probed))
            .and_then(|()| {
                self.frozen_trusts
                    .lock()
                    .map_err(|_| ErasureErrorV1::ProvenanceMissing)
                    .map(|mut trusts| trusts.push(frozen))
            })
            .and_then(|()| {
                // The Local reservation is the admission itself.
                self.decide(
                    self.local
                        .authority()
                        .admit_attempt(view, admission)
                        .map(drop),
                )
                .map(|()| {
                    ErasureAttemptQuotaReservationV1::new(
                        admission.reference(),
                        admission.reference(),
                    )
                })
            })
    }

    fn admit_acknowledgement(
        &self,
        view: &dyn ErasureAuthorityReadViewV1,
        acknowledgement: &ErasureAcknowledgementProvenanceV1,
    ) -> Result<(), ErasureErrorV1> {
        self.decide(
            self.local
                .authority()
                .admit_acknowledgement(view, acknowledgement),
        )
    }

    fn admit_receipt(
        &self,
        view: &dyn ErasureAuthorityReadViewV1,
        input: &ErasureReceiptInputV1,
    ) -> Result<(), ErasureErrorV1> {
        self.decide(self.local.authority().admit_receipt(view, input))
    }
}

#[test]
fn an_attempt_must_be_the_one_its_request_derives() -> TestResult {
    let mut expiring = owned_bundle(&ALL_CLASSES)?;
    expiring.expiry = BUNDLE_EXPIRY;
    let attempted = Attempted::new(vec![actor(), other_actor()], expiring)?;
    let request = attempted.request;
    let mut host = attempted.host()?;
    {
        let mut sender = host.command_sender()?;
        for wrong in [
            ErasureRetryAdmissionInputV1 {
                policy: reference(0x41),
                ..attempted.input.clone()
            },
            ErasureRetryAdmissionInputV1 {
                trust: reference(0x42),
                ..attempted.input.clone()
            },
            ErasureRetryAdmissionInputV1 {
                authorization_provenance: reference(0x43),
                ..attempted.input.clone()
            },
            ErasureRetryAdmissionInputV1 {
                admitted_position: 3,
                ..attempted.input.clone()
            },
            ErasureRetryAdmissionInputV1 {
                deadline_position: LOCAL_ERASURE_ATTEMPT_WINDOW_V1 + 1,
                ..attempted.input.clone()
            },
        ] {
            assert_eq!(
                sender
                    .dispatch_erasure_destruction(request, &ErasureRetryAdmissionV1::new(wrong)?)
                    .map(drop),
                Err(ErasureHostErrorV1::Conflict)
            );
        }
        // Another actor of the Principal is another subject, so its
        // pre-terminal request does not hold this one.
        sender
            .submit_local_erasure(&LocalErasureSubmissionV1 {
                actor: other_actor(),
                ..submission(9, ErasureScopeV1::PrivateSubjectData)?
            })
            .map_err(fail)?;
    }
    drop(host);
    // Attempt 0 continues the frozen request, so it is admitted after the
    // bundle expires (owner decision of 2026-11-16).
    assert_eq!(
        attempted
            .store
            .host(&attempted.case_at(after_bundle_expiry)?, 4_096)?
            .command_sender()?
            .dispatch_erasure_destruction(request, &attempted.attempt)?
            .lifecycle(),
        ErasureLifecycleV1::AwaitingAcknowledgements
    );
    let mut host = attempted.host()?;
    let mut sender = host.command_sender()?;
    // The subject's active attempt holds it.
    assert_eq!(
        sender.submit_local_erasure(&submission(2, ErasureScopeV1::PrivateSubjectData)?),
        Err(LocalErasureSubmitErrorV1::Concurrent)
    );
    Ok(())
}

impl Attempted {
    /// Owner results that must never acknowledge the first obligation
    /// positively, retained: an ELO1 of another request, of another
    /// (earlier) attempt, obligation, command or owner; a negative ELO1; a
    /// forged signer; purpose confusion; an ELS1 over an ELO1 that is not
    /// retained; and evidence that is not retained at all.
    fn refused_results(&self) -> TestResult<Vec<ErasureReferenceV1>> {
        let first = self.obligations[0];
        let second = self.obligations[1];
        let positive = owner_result(&self.attempt, &first, None);
        let owner_signed = LocalErasureSignaturePurposeV1::OwnerResult;
        let variants = [
            (
                LocalErasureOwnerResultV1 {
                    request: reference(0x31),
                    ..positive
                },
                owner_signed,
                erasure_signer(),
            ),
            (
                LocalErasureOwnerResultV1 {
                    attempt: reference(0x32),
                    ..positive
                },
                owner_signed,
                erasure_signer(),
            ),
            (
                LocalErasureOwnerResultV1 {
                    obligation: second.reference(),
                    ..positive
                },
                owner_signed,
                erasure_signer(),
            ),
            (
                LocalErasureOwnerResultV1 {
                    command: reference(0x33),
                    ..positive
                },
                owner_signed,
                erasure_signer(),
            ),
            (
                LocalErasureOwnerResultV1 {
                    owner_ref: second.owner(),
                    ..positive
                },
                owner_signed,
                erasure_signer(),
            ),
            (
                owner_result(
                    &self.attempt,
                    &first,
                    Some(ErasureErrorV1::KeyRegistryUnavailable),
                ),
                owner_signed,
                erasure_signer(),
            ),
            (positive, owner_signed, other_root()),
            (
                positive,
                LocalErasureSignaturePurposeV1::FreezeAuthorization,
                erasure_signer(),
            ),
        ];
        let mut retained = Vec::new();
        let mut refused = Vec::new();
        for (result, purpose, key) in variants {
            let (records, address) = signed_result(&result, purpose, (&key, 1))?;
            retained.extend(records);
            refused.push(address);
        }
        let unretained = signature_record(owner_signed, reference(0x34), &erasure_signer(), 1)?;
        refused.push(signature_address(&unretained)?);
        retained.push(unretained);
        refused.push(reference(0x35));
        self.store.retain(&retained)?;
        Ok(refused)
    }
}

#[test]
fn only_a_signed_owner_result_that_binds_it_acknowledges() -> TestResult {
    let attempted = Attempted::new(vec![actor()], owned_bundle(&ALL_CLASSES)?)?;
    let request = attempted.request;
    let acknowledgements = attempted.owner_results(&attempted.obligations, |_| None)?;
    let refused = attempted.refused_results()?;
    attempted.acknowledged(&[])?;
    // Completing admitted work does not close on expiry.
    let mut host = attempted
        .store
        .host(&attempted.case_at(after_trust_expiry)?, 4_096)?;
    let mut sender = host.command_sender()?;
    let first = attempted.obligations[0];
    let positive = ErasureAcknowledgementOutcomeV1::Acknowledged;
    for address in refused {
        assert_eq!(
            sender
                .acknowledge_erasure(request, acknowledgement(&first, address, positive))
                .map(drop),
            Err(ErasureHostErrorV1::AuthorizationDenied)
        );
    }
    // A positive ELO1 is no negative acknowledgement, and no ELO1 stands
    // for a stale one: Local owners are synchronous.
    for outcome in [
        ErasureAcknowledgementOutcomeV1::Negative,
        ErasureAcknowledgementOutcomeV1::Stale,
    ] {
        assert_eq!(
            sender
                .acknowledge_erasure(
                    request,
                    acknowledgement(&first, acknowledgements[0].evidence, outcome)
                )
                .map(drop),
            Err(ErasureHostErrorV1::AuthorizationDenied)
        );
    }
    for acknowledged in acknowledgements {
        assert_eq!(
            sender
                .acknowledge_erasure(request, acknowledged)?
                .lifecycle(),
            ErasureLifecycleV1::AwaitingAcknowledgements
        );
    }
    Ok(())
}

#[test]
fn a_complete_receipt_issues_signed_at_its_reached_position() -> TestResult {
    let attempted = Attempted::new(vec![actor()], owned_bundle(&ALL_CLASSES)?)?;
    let request = attempted.request;
    let obligations = &attempted.obligations;
    let acknowledgements = attempted.owner_results(obligations, |_| None)?;
    // Attempt 0 is admitted and completes after the TPS1 expires.
    let expired = attempted.case_at(after_trust_expiry)?;
    attempted.acknowledged_under(&expired, &acknowledgements)?;
    // Five executed obligations: the complete receipt issues at 2 + 5.
    let body = attempted.receipt_body(&receipt_input(obligations, 7, reference(0xee)))?;
    let receipt_signed = LocalErasureSignaturePurposeV1::ReceiptBody;
    let signed = signature_record(receipt_signed, body, &erasure_signer(), 1)?;
    let forged = signature_record(receipt_signed, body, &other_root(), 1)?;
    let confused = signature_record(
        LocalErasureSignaturePurposeV1::OwnerResult,
        body,
        &erasure_signer(),
        1,
    )?;
    attempted
        .store
        .retain(&[signed.clone(), forged.clone(), confused.clone()])?;
    let address = signature_address(&signed)?;
    // Completing admitted work does not close on expiry.
    let mut host = attempted
        .store
        .host(&attempted.case_at(after_trust_expiry)?, 4_096)?;
    let mut sender = host.command_sender()?;
    assert_eq!(
        sender
            .finalize_erasure_request(request, &receipt_input(obligations, 8, address))
            .map(drop),
        Err(ErasureHostErrorV1::Conflict)
    );
    for refused in [&forged, &confused] {
        assert_eq!(
            sender
                .finalize_erasure_request(
                    request,
                    &receipt_input(obligations, 7, signature_address(refused)?)
                )
                .map(drop),
            Err(ErasureHostErrorV1::AuthorizationDenied)
        );
    }
    let signed_input = receipt_input(obligations, 7, address);
    let previewed = sender.preview_erasure_receipt(request, &signed_input)?;
    let receipt = sender.finalize_erasure_request(request, &signed_input)?;
    // The host previews exactly the receipt finalize commits, byte for byte,
    // and after the commit the preview is finalize's exact retry.
    assert_eq!(previewed.to_canonical_cbor()?, receipt.to_canonical_cbor()?);
    assert_eq!(local_erasure_receipt_body_reference_v1(&previewed)?, body);
    assert_eq!(
        sender.preview_erasure_receipt(request, &signed_input)?,
        receipt
    );
    assert_eq!(
        sender
            .preview_erasure_receipt(request, &receipt_input(obligations, 7, reference(0xee)))
            .map(drop),
        Err(ErasureHostErrorV1::Conflict)
    );
    assert_eq!(receipt.lifecycle(), ErasureLifecycleV1::Complete);
    assert_eq!(receipt.issue_position(), 7);
    assert_eq!(receipt.signature(), address);
    assert_eq!(receipt.trust(), attempted.bundle.reference()?);
    drop(host);
    let mut host = attempted.host()?;
    assert_eq!(lifecycle(&mut host, request)?, ErasureLifecycleV1::Complete);
    Ok(())
}

impl Attempted {
    /// Run attempt 0 to a partial failure: Timeline payloads and backups are
    /// always negative (ADR-136 Q3, Q5). Returns its receipt and the
    /// unresolved obligations.
    fn partially_failed(&self) -> TestResult<(ErasureReceiptV1, Vec<ErasureObligationV1>)> {
        let payload = local_erasure_timeline_payload_v1(self.owned)?;
        let negative = |obligation: &ErasureObligationV1| {
            if obligation.category() == ErasureInventoryCategoryV1::Backup {
                Some(ErasureErrorV1::BackupInventoryIncomplete)
            } else if obligation.target().artifact_digest == payload {
                Some(ErasureErrorV1::ArtifactDeletionFailed)
            } else {
                None
            }
        };
        let acknowledgements = self.owner_results(&self.obligations, negative)?;
        self.acknowledged(&acknowledgements)?;
        let unresolved = self
            .obligations
            .iter()
            .filter(|obligation| negative(*obligation).is_some())
            .copied()
            .collect::<Vec<_>>();
        // A partial failure issues exactly at the attempt deadline.
        let deadline = LOCAL_ERASURE_ATTEMPT_WINDOW_V1;
        let body =
            self.receipt_body(&receipt_input(&self.obligations, deadline, reference(0xee)))?;
        let signed = signature_record(
            LocalErasureSignaturePurposeV1::ReceiptBody,
            body,
            &erasure_signer(),
            1,
        )?;
        self.store.retain(&[signed.clone()])?;
        let address = signature_address(&signed)?;
        let mut host = self.host()?;
        let mut sender = host.command_sender()?;
        assert_eq!(
            sender
                .finalize_erasure_request(
                    self.request,
                    &receipt_input(&self.obligations, deadline + 1, address)
                )
                .map(drop),
            Err(ErasureHostErrorV1::Conflict)
        );
        let receipt = sender.finalize_erasure_request(
            self.request,
            &receipt_input(&self.obligations, deadline, address),
        )?;
        assert_eq!(receipt.lifecycle(), ErasureLifecycleV1::PartialFailure);
        Ok((receipt, unresolved))
    }
}

#[test]
fn a_partial_failure_retries_only_while_its_subject_is_free() -> TestResult {
    let mut expiring = owned_bundle(&ALL_CLASSES)?;
    expiring.expiry = BUNDLE_EXPIRY;
    let attempted = Attempted::new(vec![actor()], expiring)?;
    rejected(&attempted.store, &[2])?;
    let request = attempted.request;
    let (receipt, unresolved) = attempted.partially_failed()?;
    assert_eq!(unresolved.len(), 2);
    let retry_input = Attempted::attempt_input(
        attempted.store.head,
        attempted.bundle.reference()?,
        &unresolved,
        Some(&receipt),
    )?;
    let retry = ErasureRetryAdmissionV1::new(retry_input.clone())?;
    let admitted = LOCAL_ERASURE_ATTEMPT_WINDOW_V1 + 1;
    assert_eq!(retry.admitted_position(), admitted);
    let mut host = attempted.host()?;
    let mut sender = host.command_sender()?;
    // Without an active attempt a partial failure does not hold its
    // subject, but the subject's newer pre-terminal request holds the retry.
    sender
        .submit_local_erasure(&submission(2, ErasureScopeV1::PrivateSubjectData)?)
        .map_err(fail)?;
    assert_eq!(
        sender
            .dispatch_erasure_destruction(request, &retry)
            .map(drop),
        Err(ErasureHostErrorV1::Conflict)
    );
    sender.reject_erasure_request(request_of(2)?, rejection(2)?.reference()?)?;
    // The ordinal must follow its source receipt's; core refuses any other.
    for wrong in [
        ErasureRetryAdmissionInputV1 {
            attempt_ordinal: 2,
            ..retry_input.clone()
        },
        ErasureRetryAdmissionInputV1 {
            admitted_position: admitted + 1,
            deadline_position: admitted + 1 + LOCAL_ERASURE_ATTEMPT_WINDOW_V1,
            ..retry_input.clone()
        },
        ErasureRetryAdmissionInputV1 {
            deadline_position: admitted + admitted,
            ..retry_input.clone()
        },
    ] {
        assert_eq!(
            sender
                .dispatch_erasure_destruction(request, &ErasureRetryAdmissionV1::new(wrong)?)
                .map(drop),
            Err(ErasureHostErrorV1::Conflict)
        );
    }
    drop(sender);
    drop(host);
    // A retry is a new admission, so an expired TPS1 or bundle closes it.
    for clock in [after_trust_expiry as fn() -> u64, after_bundle_expiry] {
        assert_eq!(
            attempted
                .store
                .host(&attempted.case_at(clock)?, 4_096)?
                .command_sender()?
                .dispatch_erasure_destruction(request, &retry)
                .map(drop),
            Err(ErasureHostErrorV1::RecoveryUnavailable)
        );
    }
    let mut host = attempted.host()?;
    let mut sender = host.command_sender()?;
    assert_eq!(
        sender
            .dispatch_erasure_destruction(request, &retry)?
            .lifecycle(),
        ErasureLifecycleV1::PartialFailure
    );
    // A partial failure with an active retry holds its subject, also after
    // a restart.
    assert_eq!(
        sender.submit_local_erasure(&submission(3, ErasureScopeV1::PrivateSubjectData)?),
        Err(LocalErasureSubmitErrorV1::Concurrent)
    );
    drop(sender);
    drop(host);
    let mut host = attempted.host()?;
    assert_eq!(
        host.command_sender()?
            .submit_local_erasure(&submission(3, ErasureScopeV1::PrivateSubjectData)?),
        Err(LocalErasureSubmitErrorV1::Concurrent)
    );
    Ok(())
}

#[test]
fn a_revoked_pinned_bundle_signs_nothing_and_frees_its_subject() -> TestResult {
    let signer_key_id = owned_bundle(&ALL_CLASSES)?.signer_key_id;
    for revoked in [signer_key_id, BUNDLE_ROOT.to_owned()] {
        let attempted = Attempted::new(vec![actor()], owned_bundle(&ALL_CLASSES)?)?;
        let request = attempted.request;
        let acknowledgements = attempted.owner_results(&attempted.obligations[..1], |_| None)?;
        attempted.acknowledged(&[])?;
        // Compromise: the installed TPS1 revokes the old signer or its
        // root, and a new bundle under another root and signer is
        // installed.
        let mut new = rotated_bundle(&attempted.store)?;
        new.issued_by = OTHER_ROOT.to_owned();
        let case = Case::signed(&new, &other_root(), &[revoked.as_str()])?;
        let mut host = attempted.store.host(&case, 4_096)?;
        let mut sender = host.command_sender()?;
        // The attempt pinned to the revoked bundle can never complete.
        assert_eq!(
            sender
                .acknowledge_erasure(request, acknowledgements[0])
                .map(drop),
            Err(ErasureHostErrorV1::RecoveryUnavailable)
        );
        // An attempt that cannot be read still holds its subject.
        let admission = attempted.attempt.reference();
        let original = overwrite_object(&attempted.store, admission, &[0])?;
        assert_eq!(
            sender
                .submit_local_erasure(&submission(2, ErasureScopeV1::PrivateSubjectData)?)
                .map(drop),
            Err(LocalErasureSubmitErrorV1::Concurrent)
        );
        overwrite_object(&attempted.store, admission, &original)?;
        // Readable, it stays contained but no longer holds its subject.
        assert_eq!(
            sender
                .submit_local_erasure(&submission(2, ErasureScopeV1::PrivateSubjectData)?)
                .map_err(fail)?
                .lifecycle(),
            ErasureLifecycleV1::Submitted
        );
        drop(sender);
        assert_eq!(
            lifecycle(&mut host, request)?,
            ErasureLifecycleV1::AwaitingAcknowledgements
        );
    }
    Ok(())
}

#[test]
fn an_owner_the_pinned_bundle_does_not_name_acknowledges_nothing() -> TestResult {
    // The bundle names no `local-backup-inventory` owner, so the attempt
    // commits but its dispatch is refused, and that owner's result is never
    // admitted.
    let attempted = Attempted::new(vec![actor()], owned_bundle(&ALL_CLASSES[..7])?)?;
    let request = attempted.request;
    let acknowledgements = attempted.owner_results(
        &[
            attempted.obligation_of(ErasureInventoryCategoryV1::Backup)?,
            attempted.obligation_of(ErasureInventoryCategoryV1::Replica)?,
        ],
        |_| None,
    )?;
    let mut host = attempted.host()?;
    assert_eq!(
        host.command_sender()?
            .dispatch_erasure_destruction(request, &attempted.attempt)
            .map(drop),
        Err(ErasureHostErrorV1::Conflict)
    );
    let mut sender = host.command_sender()?;
    assert_eq!(
        sender
            .acknowledge_erasure(request, acknowledgements[0])
            .map(drop),
        Err(ErasureHostErrorV1::AuthorizationDenied)
    );
    assert_eq!(
        sender
            .acknowledge_erasure(request, acknowledgements[1])?
            .lifecycle(),
        ErasureLifecycleV1::AwaitingAcknowledgements
    );
    Ok(())
}

/// Overwrite the stored bytes of erasure object `reference` with `bytes`,
/// and return the bytes it held.
fn overwrite_object(
    store: &LocalStore,
    reference: ErasureReferenceV1,
    bytes: &[u8],
) -> TestResult<Vec<u8>> {
    let connection = rusqlite::Connection::open(&store.path)?;
    let digest = reference.digest();
    let original: Vec<u8> = connection.query_row(
        "SELECT object_cbor FROM erasure_evidence WHERE reference_digest = ?1",
        [digest.as_slice()],
        |row| row.get(0),
    )?;
    let changed = connection.execute(
        "UPDATE erasure_evidence SET object_cbor = ?2 WHERE reference_digest = ?1",
        rusqlite::params![digest.as_slice(), bytes],
    )?;
    assert_eq!(changed, 1);
    Ok(original)
}

/// A bundle naming every owner whose signer is the rotated key at epoch 2,
/// after registering that key in the store.
fn rotated_bundle(store: &LocalStore) -> TestResult<LocalErasureBundleV1> {
    let material = SigningKeyMaterial::new(rotated_signer());
    store.register(KeyRegistrationV1::new(
        signer_identity(2),
        material.material_digest(),
        Some(material.public_verification_key()),
    ))?;
    let rotated_key = rotated_signer().verifying_key().to_bytes();
    let mut rotated = owned_bundle(&ALL_CLASSES)?;
    rotated.signer_identity.epoch = 2;
    rotated.signer_public_key = rotated_key;
    rotated.signer_key_id = local_erasure_signer_key_id_v1(&rotated_key);
    Ok(rotated)
}

impl Attempted {
    /// Acknowledge `retry` positively for each of `unresolved`, and
    /// finalize its complete receipt at its two executed obligations past
    /// admission.
    fn complete_retry(
        &self,
        retry: &ErasureRetryAdmissionV1,
        unresolved: &[ErasureObligationV1],
    ) -> TestResult {
        let acknowledgements =
            self.signed_results(retry, unresolved, (&erasure_signer(), 1), |_| None)?;
        {
            let mut host = self.host()?;
            let mut sender = host.command_sender()?;
            for acknowledged in acknowledgements {
                sender.acknowledge_erasure(self.request, acknowledged)?;
            }
        }
        let issue = retry.admitted_position() + 2;
        let body = self.receipt_body(&receipt_input(&self.obligations, issue, reference(0xee)))?;
        let signed = signature_record(
            LocalErasureSignaturePurposeV1::ReceiptBody,
            body,
            &erasure_signer(),
            1,
        )?;
        self.store.retain(&[signed.clone()])?;
        let mut host = self.host()?;
        let complete = host.command_sender()?.finalize_erasure_request(
            self.request,
            &receipt_input(&self.obligations, issue, signature_address(&signed)?),
        )?;
        assert_eq!(complete.lifecycle(), ErasureLifecycleV1::Complete);
        assert_eq!(complete.issue_position(), issue);
        assert_eq!(complete.trust(), self.bundle.reference()?);
        Ok(())
    }
}

#[test]
fn a_retry_pins_only_the_frozen_bundle_and_completes_at_its_reached_position() -> TestResult {
    let attempted = Attempted::new(vec![actor()], owned_bundle(&ALL_CLASSES)?)?;
    let request = attempted.request;
    let (receipt, unresolved) = attempted.partially_failed()?;
    let input = Attempted::attempt_input(
        attempted.store.head,
        attempted.bundle.reference()?,
        &unresolved,
        Some(&receipt),
    )?;
    let retry = ErasureRetryAdmissionV1::new(input.clone())?;
    // After a routine rotation no retry is admitted. One pinning the new
    // bundle, even retained, differs from the trust the frozen obligation
    // set pins, which core recovery requires every attempt to pin. One
    // pinning the frozen bundle pins a bundle that is no longer current.
    let rotated = rotated_bundle(&attempted.store)?;
    attempted.store.retain(&[rotated.to_canonical_cbor()?])?;
    let rotated_retry = ErasureRetryAdmissionV1::new(ErasureRetryAdmissionInputV1 {
        trust: rotated.reference()?,
        ..input.clone()
    })?;
    let frozen = attempted.bundle.reference()?;
    let current = rotated.reference()?;
    let (mut host, rotated_probe) =
        attempted.probe_host(&Case::signed(&rotated, &bundle_root(), &[])?, Vec::new())?;
    {
        let mut sender = host.command_sender()?;
        for refused in [&rotated_retry, &retry] {
            assert_eq!(
                sender
                    .dispatch_erasure_destruction(request, refused)
                    .map(drop),
                Err(ErasureHostErrorV1::Conflict)
            );
        }
    }
    drop(host);
    // The view inside each admission records the frozen trust as the
    // original bundle. The retry pinning the current, retained bundle is
    // therefore refused by the frozen-trust check; the retry pinning the
    // frozen trust passes it and is refused because that bundle is not
    // current.
    let observed = rotated_probe
        .frozen_trusts
        .lock()
        .map_err(|_| "probe poisoned")?
        .clone();
    assert_eq!(observed, [Ok(Some(frozen)), Ok(Some(frozen))]);
    assert_eq!(rotated_retry.trust(), current);
    assert_ne!(current, frozen);
    assert_eq!(retry.trust(), frozen);
    // Under the frozen bundle the retry is admitted. Inside its admission
    // the authority admits ordinal 63 and refuses ordinal 64: the quota is
    // 64 attempts per request.
    let mut probes = Vec::new();
    for attempt_ordinal in [63, 64] {
        probes.push(ErasureRetryAdmissionV1::new(
            ErasureRetryAdmissionInputV1 {
                attempt_ordinal,
                ..input.clone()
            },
        )?);
    }
    let (mut host, probe) = attempted.probe_host(&attempted.case, probes)?;
    assert_eq!(
        host.command_sender()?
            .dispatch_erasure_destruction(request, &retry)?
            .lifecycle(),
        ErasureLifecycleV1::PartialFailure
    );
    drop(host);
    let results = probe
        .attempt_results
        .lock()
        .map_err(|_| "probe poisoned")?
        .clone();
    assert_eq!(results, [Ok(()), Err(ErasureErrorV1::PolicyConflict)]);
    attempted.complete_retry(&retry, &unresolved)?;
    let mut host = attempted.host()?;
    assert_eq!(lifecycle(&mut host, request)?, ErasureLifecycleV1::Complete);
    Ok(())
}

#[test]
fn a_bundle_owner_of_another_class_is_unencodable() -> TestResult {
    // The ELB1 codec derives each owner from its store, category and class,
    // so a bundle cannot name an owner under another class.
    let store = ErasureReferenceV1::from_digest(STORE_IDENTITY);
    let mut wrong = bundle();
    wrong.owners = vec![LocalErasureOwnerRowV1 {
        category: 1,
        ack_class: "key-registry".to_owned(),
        owner_ref: pos_core::local_erasure_owner_ref_v1(store, 0, "client-cache-signal")?,
    }];
    assert!(wrong.to_canonical_cbor().is_err());
    assert!(Case::signed(&wrong, &bundle_root(), &[]).is_err());
    Ok(())
}

impl Attempted {
    /// Complete request 1: every owner result positive, and the receipt
    /// finalized at 2 + the obligations.
    fn completed(&self) -> TestResult {
        self.completed_under(&self.case)
    }

    /// As [`Self::completed`], with every step on a host of `case`.
    fn completed_under(&self, case: &Case) -> TestResult {
        let acknowledgements = self.owner_results(&self.obligations, |_| None)?;
        self.acknowledged_under(case, &acknowledgements)?;
        let issue = 2 + u64::try_from(self.obligations.len())?;
        let body = self.receipt_body_under(
            case,
            &receipt_input(&self.obligations, issue, reference(0xee)),
        )?;
        let signed = signature_record(
            LocalErasureSignaturePurposeV1::ReceiptBody,
            body,
            &erasure_signer(),
            1,
        )?;
        self.store.retain(&[signed.clone()])?;
        let receipt = self
            .store
            .host(case, 4_096)?
            .command_sender()?
            .finalize_erasure_request(
                self.request,
                &receipt_input(&self.obligations, issue, signature_address(&signed)?),
            )?;
        assert_eq!(receipt.lifecycle(), ErasureLifecycleV1::Complete);
        Ok(())
    }
}

/// Overwrite the stored ERCRP1 manifest of erasure request `request` with
/// `bytes`, and return the bytes it held.
fn overwrite_manifest(
    store: &LocalStore,
    request: ErasureReferenceV1,
    bytes: &[u8],
) -> TestResult<Vec<u8>> {
    let connection = rusqlite::Connection::open(&store.path)?;
    let digest = request.digest();
    let original: Vec<u8> = connection.query_row(
        "SELECT manifest_cbor FROM erasure_records WHERE request_digest = ?1",
        [digest.as_slice()],
        |row| row.get(0),
    )?;
    let changed = connection.execute(
        "UPDATE erasure_records SET manifest_cbor = ?2 WHERE request_digest = ?1",
        rusqlite::params![digest.as_slice(), bytes],
    )?;
    assert_eq!(changed, 1);
    Ok(original)
}

/// With terminal `request`'s manifest unreadable on an open host, a new
/// submission of key `key` still passes the subject check, because a
/// complete or rejected request is never read; reading it would hold the
/// subject (`Concurrent`). The submission's commit then fails the host's
/// recovery of that manifest, and once the manifest is restored the new
/// request is installed.
fn assert_unread_terminal_frees_subject(
    store: &LocalStore,
    case: &Case,
    request: ErasureReferenceV1,
    key: u8,
) -> TestResult {
    let mut host = store.host(case, 4_096)?;
    let original = overwrite_manifest(store, request, &[0])?;
    let submitted = host
        .command_sender()?
        .submit_local_erasure(&submission(key, ErasureScopeV1::PrivateSubjectData)?)
        .map(drop);
    assert_ne!(submitted, Err(LocalErasureSubmitErrorV1::Concurrent));
    drop(host);
    overwrite_manifest(store, request, &original)?;
    let mut host = store.host(case, 4_096)?;
    assert_eq!(
        lifecycle(&mut host, request_of(key)?)?,
        ErasureLifecycleV1::Submitted
    );
    Ok(())
}

#[test]
fn a_complete_request_frees_its_subject() -> TestResult {
    let attempted = Attempted::new(vec![actor()], owned_bundle(&ALL_CLASSES)?)?;
    attempted.completed()?;
    assert_eq!(
        attempted
            .host()?
            .command_sender()?
            .submit_local_erasure(&submission(2, ErasureScopeV1::PrivateSubjectData)?)
            .map_err(fail)?
            .lifecycle(),
        ErasureLifecycleV1::Submitted
    );
    Ok(())
}

#[test]
fn an_unreadable_complete_request_never_holds_its_subject() -> TestResult {
    let attempted = Attempted::new(vec![actor()], owned_bundle(&ALL_CLASSES)?)?;
    attempted.completed()?;
    assert_unread_terminal_frees_subject(&attempted.store, &attempted.case, attempted.request, 2)
}

#[test]
fn an_unreadable_rejected_request_never_holds_its_subject() -> TestResult {
    let store = LocalStore::new(&GrantShape::standard())?;
    rejected(&store, &[1])?;
    let case = local_case()?;
    {
        let mut host = store.host(&case, 4_096)?;
        let mut sender = host.command_sender()?;
        sender
            .submit_local_erasure(&submission(1, ErasureScopeV1::PrivateSubjectData)?)
            .map_err(fail)?;
        let state = sender.reject_erasure_request(request_of(1)?, rejection(1)?.reference()?)?;
        assert_eq!(state.lifecycle(), ErasureLifecycleV1::Rejected);
    }
    assert_unread_terminal_frees_subject(&store, &case, request_of(1)?, 2)
}

#[test]
fn attempt_0_completes_after_the_bundle_expires() -> TestResult {
    let mut expiring = owned_bundle(&ALL_CLASSES)?;
    expiring.expiry = BUNDLE_EXPIRY;
    let attempted = Attempted::new(vec![actor()], expiring)?;
    attempted.completed_under(&attempted.case_at(after_bundle_expiry)?)?;
    let mut host = attempted.host()?;
    assert_eq!(
        lifecycle(&mut host, attempted.request)?,
        ErasureLifecycleV1::Complete
    );
    Ok(())
}

#[test]
fn attempt_0_is_refused_once_its_bundle_is_revoked_and_rotated() -> TestResult {
    let attempted = Attempted::new(vec![actor()], owned_bundle(&ALL_CLASSES)?)?;
    // Control: under the original bundle, attempt 0 is admitted. A probe
    // evaluates it inside a dispatch whose own admission is refused, so
    // nothing is committed.
    let (mut host, probe) =
        attempted.probe_host(&attempted.case, vec![attempted.attempt.clone()])?;
    let refused = ErasureRetryAdmissionV1::new(ErasureRetryAdmissionInputV1 {
        policy: reference(0x41),
        ..attempted.input.clone()
    })?;
    assert_eq!(
        host.command_sender()?
            .dispatch_erasure_destruction(attempted.request, &refused)
            .map(drop),
        Err(ErasureHostErrorV1::Conflict)
    );
    drop(host);
    let results = probe
        .attempt_results
        .lock()
        .map_err(|_| "probe poisoned")?
        .clone();
    assert_eq!(results, [Ok(())]);
    // The revoke-and-rotate makes the original bundle non-current. Attempt
    // 0 pins only the bundle current at admission, so the same attempt 0 is
    // now refused (PolicyConflict).
    let revoked = attempted.bundle.signer_key_id.clone();
    let mut new = rotated_bundle(&attempted.store)?;
    new.issued_by = OTHER_ROOT.to_owned();
    let case = Case::signed(&new, &other_root(), &[revoked.as_str()])?;
    assert_eq!(
        attempted
            .store
            .host(&case, 4_096)?
            .command_sender()?
            .dispatch_erasure_destruction(attempted.request, &attempted.attempt)
            .map(drop),
        Err(ErasureHostErrorV1::Conflict)
    );
    Ok(())
}

// ADR-136 acceptance test 6, recovery leg (#1425): evidence that admission
// refuses is refused at recovery too. A lenient probe plays a host that
// skipped the admission checks and commits the evidence; a host of the
// Local authority then refuses to recover the store.

/// The number of evidence refusals each recovery test runs: a forged
/// ELS1, the wrong signer key, purpose confusion and a stale body.
const REFUSED_EVIDENCE: usize = 4;

impl LocalStore {
    /// Open a host of `case` over the store, keeping the host error: an
    /// error means recovery refused a committed record.
    fn recovered(&self, case: &Case) -> TestResult<Result<(), ErasureHostErrorV1>> {
        let composition = case.compose(&mut self.sqlite()?).map_err(fail)?;
        Ok(ErasureExecutionHostV1::open_with_authority(
            StoreConfig::Sqlite {
                path: self.path.clone(),
            },
            &composition,
            ErasureRecoveryLimitsV1::from_maximum_requests(4_096)?,
        )
        .map(drop))
    }
}

/// `input` with every inventory row's reason restated: a receipt whose body
/// has changed since an ERCB1 of `input` was signed.
fn restated(mut input: ErasureReceiptInputV1) -> ErasureReceiptInputV1 {
    let inventories = &mut input.inventories;
    for row in inventories
        .artifacts
        .iter_mut()
        .chain(inventories.keys.iter_mut())
        .chain(inventories.replicas.iter_mut())
        .chain(inventories.backups.iter_mut())
    {
        row.transition.reason = reference(0xd9);
    }
    input
}

impl Attempted {
    /// Positive acknowledgements of the first obligation whose evidence
    /// admission refuses, retained: a forged ELS1 that claims the bundle's
    /// signer, a valid ELS1 by the wrong signer key, the bundle's signer
    /// under another purpose, and a stale body (an ELO1 of another
    /// attempt).
    fn refused_owner_evidence(&self) -> TestResult<Vec<ErasureAcknowledgementV1>> {
        let first = self.obligations[0];
        let positive = owner_result(&self.attempt, &first, None);
        let owner_signed = LocalErasureSignaturePurposeV1::OwnerResult;
        let (forger, rotated, signer) = (other_root(), rotated_signer(), erasure_signer());
        let mut retained = Vec::new();
        let mut refused = Vec::new();
        for (result, purpose, key) in [
            (positive, owner_signed, (&forger, 1)),
            (positive, owner_signed, (&rotated, 2)),
            (
                positive,
                LocalErasureSignaturePurposeV1::FreezeAuthorization,
                (&signer, 1),
            ),
            (
                LocalErasureOwnerResultV1 {
                    attempt: reference(0x32),
                    ..positive
                },
                owner_signed,
                (&signer, 1),
            ),
        ] {
            let (records, address) = signed_result(&result, purpose, key)?;
            retained.extend(records);
            refused.push(acknowledgement(
                &first,
                address,
                ErasureAcknowledgementOutcomeV1::Acknowledged,
            ));
        }
        self.store.retain(&retained)?;
        Ok(refused)
    }

    /// Receipt signatures admission refuses, retained, by address: over
    /// `body`, the complete receipt's ERCB1, a forged ELS1, one by the
    /// wrong signer key and one of another purpose; and the bundle's signer
    /// over `stale`, the ERCB1 of a body that has since changed.
    fn refused_receipt_evidence(
        &self,
        body: ErasureReferenceV1,
        stale: ErasureReferenceV1,
    ) -> TestResult<Vec<ErasureReferenceV1>> {
        let receipt_signed = LocalErasureSignaturePurposeV1::ReceiptBody;
        let (forger, rotated, signer) = (other_root(), rotated_signer(), erasure_signer());
        let mut retained = Vec::new();
        let mut refused = Vec::new();
        for (purpose, digest, key, epoch) in [
            (receipt_signed, body, &forger, 1),
            (receipt_signed, body, &rotated, 2),
            (
                LocalErasureSignaturePurposeV1::OwnerResult,
                body,
                &signer,
                1,
            ),
            (receipt_signed, stale, &signer, 1),
        ] {
            let record = signature_record(purpose, digest, key, epoch)?;
            refused.push(signature_address(&record)?);
            retained.push(record);
        }
        self.store.retain(&retained)?;
        Ok(refused)
    }
}

#[test]
fn recovery_refuses_an_attempt_its_request_does_not_derive() -> TestResult {
    let attempted = Attempted::new(vec![actor()], owned_bundle(&ALL_CLASSES)?)?;
    let request = attempted.request;
    let underived = ErasureRetryAdmissionV1::new(ErasureRetryAdmissionInputV1 {
        authorization_provenance: reference(0x43),
        ..attempted.input.clone()
    })?;
    assert_eq!(
        attempted
            .host()?
            .command_sender()?
            .dispatch_erasure_destruction(request, &underived)
            .map(drop),
        Err(ErasureHostErrorV1::Conflict)
    );
    assert_eq!(
        attempted
            .lenient_host()?
            .command_sender()?
            .dispatch_erasure_destruction(request, &underived)?
            .lifecycle(),
        ErasureLifecycleV1::AwaitingAcknowledgements
    );
    assert_eq!(
        attempted.store.recovered(&attempted.case)?,
        Err(ErasureHostErrorV1::Conflict)
    );
    Ok(())
}

#[test]
fn recovery_refuses_owner_evidence_admission_refuses() -> TestResult {
    for index in 0..REFUSED_EVIDENCE {
        let attempted = Attempted::new(vec![actor()], owned_bundle(&ALL_CLASSES)?)?;
        let request = attempted.request;
        let refused = attempted.refused_owner_evidence()?[index];
        attempted.acknowledged(&[])?;
        assert_eq!(
            attempted
                .host()?
                .command_sender()?
                .acknowledge_erasure(request, refused)
                .map(drop),
            Err(ErasureHostErrorV1::AuthorizationDenied)
        );
        assert_eq!(
            attempted
                .lenient_host()?
                .command_sender()?
                .acknowledge_erasure(request, refused)?
                .lifecycle(),
            ErasureLifecycleV1::AwaitingAcknowledgements
        );
        assert_eq!(
            attempted.store.recovered(&attempted.case)?,
            Err(ErasureHostErrorV1::AuthorizationDenied)
        );
    }
    Ok(())
}

#[test]
fn recovery_refuses_receipt_evidence_admission_refuses() -> TestResult {
    for index in 0..REFUSED_EVIDENCE {
        let attempted = Attempted::new(vec![actor()], owned_bundle(&ALL_CLASSES)?)?;
        let request = attempted.request;
        let obligations = &attempted.obligations;
        let acknowledgements = attempted.owner_results(obligations, |_| None)?;
        attempted.acknowledged(&acknowledgements)?;
        // Five executed obligations: the complete receipt issues at 2 + 5.
        let input = receipt_input(obligations, 7, reference(0xee));
        let body = attempted.receipt_body(&input)?;
        let stale = attempted.receipt_body(&restated(input))?;
        assert_ne!(body, stale);
        let signature = attempted.refused_receipt_evidence(body, stale)?[index];
        let refused = receipt_input(obligations, 7, signature);
        assert_eq!(
            attempted
                .host()?
                .command_sender()?
                .finalize_erasure_request(request, &refused)
                .map(drop),
            Err(ErasureHostErrorV1::AuthorizationDenied)
        );
        assert_eq!(
            attempted
                .lenient_host()?
                .command_sender()?
                .finalize_erasure_request(request, &refused)?
                .lifecycle(),
            ErasureLifecycleV1::Complete
        );
        assert_eq!(
            attempted.store.recovered(&attempted.case)?,
            Err(ErasureHostErrorV1::AuthorizationDenied)
        );
    }
    Ok(())
}

impl Attempted {
    /// The request's lifecycle on a host recovered after a bundle rotation:
    /// a routine one when `revoked` is empty, otherwise a compromise, where
    /// the installed TPS1 revokes `revoked` and another root issues the new
    /// bundle.
    fn lifecycle_after_rotation(&self, revoked: &[&str]) -> TestResult<ErasureLifecycleV1> {
        let mut new = rotated_bundle(&self.store)?;
        let root = if revoked.is_empty() {
            bundle_root()
        } else {
            new.issued_by = OTHER_ROOT.to_owned();
            other_root()
        };
        let mut host = self
            .store
            .host(&Case::signed(&new, &root, revoked)?, 4_096)?;
        lifecycle(&mut host, self.request)
    }
}

#[test]
fn committed_evidence_still_verifies_after_a_bundle_rotation() -> TestResult {
    let signer_key_id = owned_bundle(&ALL_CLASSES)?.signer_key_id;
    let compromised = [signer_key_id.as_str()];
    // A complete request's attempt, owner results and receipt verify
    // against the retained ELB1 after a routine rotation and after a
    // compromise.
    for revoked in [&[][..], &compromised[..]] {
        let complete = Attempted::new(vec![actor()], owned_bundle(&ALL_CLASSES)?)?;
        complete.completed()?;
        assert_eq!(
            complete.lifecycle_after_rotation(revoked)?,
            ErasureLifecycleV1::Complete
        );
    }
    // After a compromise, an owner result committed into the active
    // attempt pinned to the revoked bundle still verifies: the attempt
    // stays contained, and recovery succeeds.
    let active = Attempted::new(vec![actor()], owned_bundle(&ALL_CLASSES)?)?;
    let acknowledgements = active.owner_results(&active.obligations[..1], |_| None)?;
    active.acknowledged(&acknowledgements)?;
    assert_eq!(
        active.lifecycle_after_rotation(&compromised)?,
        ErasureLifecycleV1::AwaitingAcknowledgements
    );
    Ok(())
}

#[test]
fn recovery_needs_a_resolvable_bundle_and_the_issue_position() -> TestResult {
    let (_store, composition, mut host, owner) = local_authority()?;
    let view = host.authority_view()?;
    let authority = composition.authority();
    let mut current = bundle();
    current.owners = vec![LocalErasureOwnerRowV1 {
        category: 1,
        ack_class: "key-registry".to_owned(),
        owner_ref: owner,
    }];
    let erq1 = ErasureRequestV1::new(ErasureRequestInputV1 {
        request: reference(0x90),
        subject: reference(0xca),
        scope: ErasureScopeV1::PrivateSubjectData,
        selectors: vec![reference(0xcb)],
        requester: reference(0xcc),
        authorization: reference(0xc7),
        policy: LOCAL_ERASURE_POLICY_REFERENCE_V1,
        request_position: 0,
        horizon_position: LOCAL_ERASURE_ATTEMPT_WINDOW_V1,
        provenance: reference(0xcd),
    })?;
    // Attempt 0 as its request derives it, pinning the composed bundle.
    let pinned = ErasureRetryAdmissionInputV1 {
        request: erq1.reference(),
        attempt_ordinal: 0,
        source_receipt: None,
        unresolved_obligations: vec![reference(0xc5)],
        command_identities: vec![reference(0xc6)],
        policy: LOCAL_ERASURE_POLICY_REFERENCE_V1,
        trust: current.reference()?,
        admitted_position: 2,
        deadline_position: LOCAL_ERASURE_ATTEMPT_WINDOW_V1,
        authorization_provenance: reference(0xc7),
    };
    let attempt = ErasureRetryAdmissionV1::new(pinned.clone())?;
    // The same attempt pinning a bundle that is neither composed nor
    // retained.
    let unresolved = ErasureRetryAdmissionV1::new(ErasureRetryAdmissionInputV1 {
        trust: reference(0xc2),
        ..pinned
    })?;
    assert_eq!(
        authority.validate_attempt_with_view(&view, &erq1, &attempt),
        Ok(())
    );
    assert_eq!(
        authority.validate_attempt_with_view(&view, &erq1, &unresolved),
        Err(ErasureErrorV1::PolicyConflict)
    );
    let acknowledgement =
        ErasureAcknowledgementProvenanceV1::new(ErasureAcknowledgementProvenanceInputV1 {
            request: erq1.reference(),
            command: reference(0xc6),
            attempt: unresolved.reference(),
            obligation: reference(0xc5),
            owner,
            scope: reference(0xc0),
            outcome: ErasureAcknowledgementOutcomeV1::Acknowledged,
            evidence: reference(0xc9),
            policy: LOCAL_ERASURE_POLICY_REFERENCE_V1,
            trust: reference(0xc2),
        })?;
    assert_eq!(
        authority.validate_acknowledgement_with_view(&view, &acknowledgement),
        Err(ErasureErrorV1::TrustSnapshotInvalid)
    );
    // One executed obligation: a complete receipt of attempt 0 issues at
    // 2 + 1. Another position is refused before its signature is read;
    // at that position the unretained signature is refused.
    let late = ErasureReceiptV1::new(receipt_input(&[], 7, reference(0xce)))?;
    let reached = ErasureReceiptV1::new(receipt_input(&[], 3, reference(0xce)))?;
    assert_eq!(
        authority.validate_receipt_with_view(&view, &unresolved, &reached),
        Err(ErasureErrorV1::TrustSnapshotInvalid)
    );
    assert_eq!(
        authority.validate_receipt_with_view(&view, &attempt, &late),
        Err(ErasureErrorV1::PolicyConflict)
    );
    assert_eq!(
        authority.validate_receipt_with_view(&view, &attempt, &reached),
        Err(ErasureErrorV1::Unauthorized)
    );
    Ok(())
}

#[test]
fn a_retry_recovers_on_its_retained_frozen_bundle_after_a_rotation() -> TestResult {
    let attempted = Attempted::new(vec![actor()], owned_bundle(&ALL_CLASSES)?)?;
    let (receipt, unresolved) = attempted.partially_failed()?;
    let retry = ErasureRetryAdmissionV1::new(Attempted::attempt_input(
        attempted.store.head,
        attempted.bundle.reference()?,
        &unresolved,
        Some(&receipt),
    )?)?;
    assert_eq!(retry.attempt_ordinal(), 1);
    assert_eq!(
        attempted
            .host()?
            .command_sender()?
            .dispatch_erasure_destruction(attempted.request, &retry)?
            .lifecycle(),
        ErasureLifecycleV1::PartialFailure
    );
    attempted.complete_retry(&retry, &unresolved)?;
    // After a routine rotation, recovery re-verifies both attempts, the
    // retry's derivation from its source receipt included, and their
    // evidence against the retained frozen bundle.
    assert_eq!(
        attempted.lifecycle_after_rotation(&[])?,
        ErasureLifecycleV1::Complete
    );
    Ok(())
}
