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
    LocalErasureCompositionInputsV1, LocalFreezePreparationV1,
    LOCAL_ERASURE_CLASSIFICATION_COUNT_V1, LOCAL_ERASURE_CLASSIFICATION_V1,
    LOCAL_ERASURE_POLICY_REFERENCE_V1,
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

/// The TPS1 whose roots are the two `erasure-bundle/` roots and which
/// revokes `revoked` (sorted), signed by the deployment operator key
/// `operator`.
fn signed_snapshot(operator: &SigningKey, revoked: &[&str]) -> TestResult<TrustPolicySnapshotV1> {
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
    Ok(snapshot)
}

/// As [`trust`], under the deployment operator key `operator`.
fn trust_under(operator: &SigningKey, revoked: &[&str]) -> TestResult<CurrentTrustPolicyV1> {
    let snapshot = signed_snapshot(operator, revoked)?;
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
        host_timelines: erasure_host_timelines(),
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

/// The Erasure Host Timeline of the fixture store identity.
fn erasure_host_timelines() -> Vec<TimelineId> {
    pos_core::local_erasure_host_timeline_v1(ErasureReferenceV1::from_digest(STORE_IDENTITY))
        .into_iter()
        .collect()
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
        S: ErasureInventoryPersistencePortV1 + ErasurePersistencePortV1 + EventStore,
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
        S: ErasureInventoryPersistencePortV1 + ErasurePersistencePortV1 + EventStore,
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

/// Owner decision Q14 (2026-11-17, #1412): the bundle must list its store's
/// Erasure Host Timeline among `host_timelines`, with or without a composed
/// executor; other host Timelines beside it do not matter.
#[test]
fn a_bundle_without_its_erasure_host_timeline_is_a_mismatch() -> TestResult {
    let mut store = provisioned_store()?;
    assert_eq!(erasure_host_timelines().len(), 1);
    let mut listed = bundle();
    listed
        .host_timelines
        .insert(0, TimelineId::from_ulid(Ulid::nil()));
    listed
        .host_timelines
        .push(TimelineId::from_ulid(Ulid::from_bytes([0xff; 16])));
    let case = Case::signed(&listed, &bundle_root(), &[])?;
    assert!(case.compose(&mut store).is_ok());
    let mut omitted = bundle();
    omitted.host_timelines = vec![TimelineId::from_ulid(Ulid::nil())];
    let mut case = Case::signed(&omitted, &bundle_root(), &[])?;
    assert_eq!(
        case.refusal(&mut store),
        Some(LocalErasureCompositionErrorV1::BundleMismatch)
    );
    case.execution_binding = None;
    assert_eq!(
        case.refusal(&mut store),
        Some(LocalErasureCompositionErrorV1::BundleMismatch)
    );
    // Another store's Erasure Host Timeline is not this store's.
    omitted.host_timelines = vec![pos_core::local_erasure_host_timeline_v1(reference(0x5f))?];
    let case = Case::signed(&omitted, &bundle_root(), &[])?;
    assert_eq!(
        case.refusal(&mut store),
        Some(LocalErasureCompositionErrorV1::BundleMismatch)
    );
    Ok(())
}

/// Owner decision Q6 (2026-11-17, #1412): the pinned executor binding is
/// `CA("ELEXV1", [executor_id, version])` of exactly these values.
#[test]
fn the_executor_binding_is_the_pinned_executor_version_digest() -> TestResult {
    assert_eq!(
        pos_runtime::LOCAL_ERASURE_EXECUTOR_ID_V1,
        "pigloros.local-erasure-executor"
    );
    assert_eq!(pos_runtime::LOCAL_ERASURE_EXECUTOR_VERSION_V1, 1);
    assert_eq!(
        pos_core::local_erasure_executor_version_v1(
            pos_runtime::LOCAL_ERASURE_EXECUTOR_ID_V1,
            pos_runtime::LOCAL_ERASURE_EXECUTOR_VERSION_V1,
        )?,
        pos_runtime::LOCAL_ERASURE_EXECUTOR_VERSION_DIGEST_V1
    );
    assert_eq!(
        pos_runtime::local_erasure_execution_binding_v1(),
        LocalErasureExecutionBindingV1 {
            executor_id: pos_runtime::LOCAL_ERASURE_EXECUTOR_ID_V1.to_owned(),
            executor_version_digest: pos_runtime::LOCAL_ERASURE_EXECUTOR_VERSION_DIGEST_V1,
        }
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
fn bound_authority_host<S: AuthorityPersistencePortV1>(
    store: &mut S,
    grants: &[&CapabilityGrantV1],
) -> TestResult<AuthorityPersistenceHostV1> {
    let mut bindings = Vec::with_capacity(grants.len());
    for grant in grants {
        bindings.push(grant.binding_digest().map_err(fail)?);
    }
    bindings.sort_unstable();
    let registry = AuthorityRegistrySnapshotV1::try_new(
        &pos_core::AuthorityTrustRootSealV1::for_composition_root(),
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

/// Provision `store` as every Local fixture store is, and return its
/// recorded chain head.
///
/// It gets an open test gate, the fixture store identity and signer key,
/// and the root grant of `shape` followed by each of `later`.
fn provisioned<S>(store: &mut S, shape: &GrantShape, later: &[CapabilityGrantV1]) -> TestResult<u64>
where
    S: EventStore + ErasureInventoryPersistencePortV1 + AuthorityPersistencePortV1,
{
    store.bind_erasure_gate(Arc::new(ErasureContainmentGateV1::new_test_open()))?;
    store.init_erasure_store_identity(Hash::from_bytes(STORE_IDENTITY))?;
    register_signer(store, &erasure_signer(), 1)?;
    let grant = shape.root_grant()?;
    let grants = std::iter::once(&grant).chain(later).collect::<Vec<_>>();
    let host = bound_authority_host(store, &grants)?;
    for grant in grants {
        let permit = host.authorize_grant(grant).map_err(fail)?;
        store.issue_capability_grant(permit, grant).map_err(fail)?;
    }
    Ok(store
        .load_authority(grant_id())
        .map_err(fail)?
        .head_position()
        .as_u64())
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
        let head = provisioned(&mut SqliteStore::open(&path)?, shape, later)?;
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
        mode_profile: reference(0x6d),
        binding_epoch: 1,
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
    retain_rejections(&mut store.sqlite()?, keys)
}

fn local_case() -> TestResult<Case> {
    Case::valid()
}

#[test]
fn a_local_submission_is_derived_idempotent_and_bound_to_its_body() -> TestResult {
    for adapter in ADAPTERS {
        let (mut fixture, ()) =
            Fixture::local(adapter, &GrantShape::standard(), 4_096, |_| Ok(()))?;
        let mut sender = fixture.host.command_sender()?;
        let state = sender
            .submit_local_erasure(&submission(1, ErasureScopeV1::PrivateSubjectData)?)
            .map_err(fail)?;
        assert_eq!(state.state.lifecycle(), ErasureLifecycleV1::Submitted);
        // An exact retry returns the original state.
        assert_eq!(
            sender.submit_local_erasure(&submission(1, ErasureScopeV1::PrivateSubjectData)?),
            Ok(state)
        );
        // The same key with another body, or a retained-only scope, conflicts.
        for (key, scope) in [
            (1, ErasureScopeV1::ConsentedSharedData),
            (2, ErasureScopeV1::PublicRecord),
        ] {
            assert_eq!(
                sender.submit_local_erasure(&submission(key, scope)?),
                Err(LocalErasureSubmitErrorV1::Host(
                    ErasureHostErrorV1::Conflict
                ))
            );
        }
        // A Timeline created while the request is submitted stays
        // unaffected, and the store recovers with the request after a
        // restart (`SQLite`; a Memory store has no close and reopen).
        let _created = sender.create_timeline("after-submission")?;
        let fixture = fixture.restarted()?;
        assert_eq!(
            fixture.host.status(),
            pos_runtime::ErasureHostStatusV1::Ready
        );
    }
    Ok(())
}

#[test]
fn a_subject_has_one_pre_terminal_request() -> TestResult {
    for adapter in ADAPTERS {
        let (mut fixture, ()) =
            Fixture::local(adapter, &GrantShape::standard(), 4_096, |_| Ok(()))?;
        let head = fixture.head;
        let mut sender = fixture.host.command_sender()?;
        sender
            .submit_local_erasure(&submission(1, ErasureScopeV1::PrivateSubjectData)?)
            .map_err(fail)?;
        assert_eq!(
            sender.submit_local_erasure(&submission(2, ErasureScopeV1::ConsentedSharedData)?),
            Err(LocalErasureSubmitErrorV1::Concurrent)
        );
        let authorized = sender
            .authorize_erasure_request(request_of(1)?, authorization(1, head)?.reference()?)?;
        assert_eq!(authorized.lifecycle(), ErasureLifecycleV1::Authorized);
        assert_eq!(
            sender.submit_local_erasure(&submission(2, ErasureScopeV1::PrivateSubjectData)?),
            Err(LocalErasureSubmitErrorV1::Concurrent)
        );
    }
    Ok(())
}

#[test]
fn the_subject_quota_admits_exactly_its_share() -> TestResult {
    // One actor and 514 request heads: q_subject = (514 - 512) / 1 = 2.
    for adapter in ADAPTERS {
        let (mut fixture, ()) =
            Fixture::local(adapter, &GrantShape::standard(), RESERVE + 2, |store| {
                retain_rejections(store, &[1, 2])
            })?;
        let mut sender = fixture.host.command_sender()?;
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
    }
    Ok(())
}

#[test]
fn the_quota_is_shared_by_the_principals_actors() -> TestResult {
    // Two actors and 514 request heads: q_subject = (514 - 512) / 2 = 1.
    let mut shape = GrantShape::standard();
    shape.actors = [actor(), other_actor()].into_iter().collect();
    shape.actors.sort_unstable();
    for adapter in ADAPTERS {
        let (mut fixture, ()) = Fixture::local(adapter, &shape, RESERVE + 2, |store| {
            retain_rejections(store, &[1])
        })?;
        let mut sender = fixture.host.command_sender()?;
        sender
            .submit_local_erasure(&submission(1, ErasureScopeV1::PrivateSubjectData)?)
            .map_err(fail)?;
        sender.reject_erasure_request(request_of(1)?, rejection(1)?.reference()?)?;
        assert_eq!(
            sender.submit_local_erasure(&submission(2, ErasureScopeV1::PrivateSubjectData)?),
            Err(LocalErasureSubmitErrorV1::QuotaExhausted)
        );
    }
    Ok(())
}

#[test]
fn authorization_names_the_requests_own_evidence() -> TestResult {
    for adapter in ADAPTERS {
        // An ELREJ1 of another request is retained, not one of request 1.
        let (mut fixture, ()) = Fixture::local(adapter, &GrantShape::standard(), 4_096, |store| {
            retain_rejections(store, &[2])
        })?;
        let head = fixture.head;
        let mut sender = fixture.host.command_sender()?;
        sender
            .submit_local_erasure(&submission(1, ErasureScopeV1::PrivateSubjectData)?)
            .map_err(fail)?;
        let request = request_of(1)?;
        assert_eq!(
            sender.authorize_erasure_request(request, reference(0x99)),
            Err(ErasureHostErrorV1::Conflict)
        );
        for provenance in [reference(0x99), rejection(2)?.reference()?] {
            assert_eq!(
                sender.reject_erasure_request(request, provenance),
                Err(ErasureHostErrorV1::Conflict)
            );
        }
        assert_eq!(
            sender
                .authorize_erasure_request(request, authorization(1, head)?.reference()?)?
                .lifecycle(),
            ErasureLifecycleV1::Authorized
        );
    }
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

/// Assert that the submission of key 2 is refused with `error`, not with
/// the subject's `Concurrent`, and retains neither its ELIDEM1 nor the
/// ERAZ1 it would bind at the recorded head or, after a revocation, at the
/// head one past it and revocation epoch 1.
fn refused_before_the_subject_checks(
    store: &LocalStore,
    host: &mut ErasureExecutionHostV1,
    error: LocalErasureSubmitErrorV1,
) -> TestResult {
    assert_eq!(
        host.command_sender()?
            .submit_local_erasure(&submission(2, ErasureScopeV1::PrivateSubjectData)?),
        Err(error)
    );
    // The host's own authority view reads no object, so read the store.
    let sqlite = store.sqlite()?;
    for (head, epoch) in [(store.head, 0), (store.head + 1, 1)] {
        let authorization = authorization_at(2, head, epoch)?.reference()?;
        assert!(ErasurePersistencePortV1::read_object(&sqlite, authorization).is_err());
    }
    assert!(ErasurePersistencePortV1::read_object(&sqlite, idempotency(2)?.reference()?).is_err());
    Ok(())
}

#[test]
fn an_unauthenticated_submission_learns_nothing_of_a_held_subject() -> TestResult {
    let shape = GrantShape::standard();
    let store = LocalStore::new(&shape)?;
    {
        let mut host = store.host(&local_case()?, 4_096)?;
        let mut sender = host.command_sender()?;
        sender
            .submit_local_erasure(&submission(1, ErasureScopeV1::PrivateSubjectData)?)
            .map_err(fail)?;
        // While new admissions are open, request 1 holds the subject.
        assert_eq!(
            sender.submit_local_erasure(&submission(2, ErasureScopeV1::PrivateSubjectData)?),
            Err(LocalErasureSubmitErrorV1::Concurrent)
        );
    }
    // Once the TPS1 has expired, the closed admission answers first.
    let mut expired = local_case()?;
    expired.clock = after_trust_expiry;
    let mut host = store.host(&expired, 4_096)?;
    refused_before_the_subject_checks(
        &store,
        &mut host,
        LocalErasureSubmitErrorV1::AdmissionsClosed,
    )?;
    drop(host);
    // Once the root grant is revoked, the authentication failure answers
    // first, although request 1 still holds the subject.
    store.revoke(&shape)?;
    let mut host = store.host(&local_case()?, 4_096)?;
    refused_before_the_subject_checks(
        &store,
        &mut host,
        LocalErasureSubmitErrorV1::Host(ErasureHostErrorV1::AuthorizationDenied),
    )
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
    assert_eq!(state.state.lifecycle(), ErasureLifecycleV1::Submitted);
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
        Err(LocalErasureSubmitErrorV1::AdmissionsClosed)
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
    for adapter in ADAPTERS {
        let (mut fixture, ()) = Fixture::local(adapter, &shape, 4_096, |_| Ok(()))?;
        assert_eq!(fixture.head + 1, 2);
        let state = fixture
            .host
            .command_sender()?
            .submit_local_erasure(&submission(1, ErasureScopeV1::PrivateSubjectData)?)
            .map_err(fail)?;
        assert_eq!(state.state.lifecycle(), ErasureLifecycleV1::Submitted);
    }
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
        Err(LocalErasureSubmitErrorV1::AdmissionsClosed)
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
        Err(LocalErasureSubmitErrorV1::AdmissionsClosed)
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
        Err(LocalErasureSubmitErrorV1::Unserved)
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
    error: LocalErasureSubmitErrorV1,
) -> TestResult {
    assert_eq!(
        host.command_sender()?.submit_local_erasure(submission),
        Err(error)
    );
    // The host's own authority view reads no object, so read the store.
    let subject = local_erasure_subject_v1(principal_ref()?, actor())?;
    let sqlite = store.sqlite()?;
    for object in [
        authorization(1, store.head)?.reference()?,
        authorization_at(1, store.head + 1, 1)?.reference()?,
        LocalErasureSelectorV1 { subject }.reference()?,
        idempotency(1)?.reference()?,
    ] {
        assert!(ErasurePersistencePortV1::read_object(&sqlite, object).is_err());
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
            LocalErasureSubmitErrorV1::Host(ErasureHostErrorV1::AuthorizationDenied),
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
        LocalErasureSubmitErrorV1::Host(ErasureHostErrorV1::AuthorizationDenied),
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
        LocalErasureSubmitErrorV1::AdmissionsClosed,
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
        LocalErasureSubmitErrorV1::Host(ErasureHostErrorV1::AuthorizationDenied),
    )?;
    // The same store admits the Principal's own submission.
    let store = LocalStore::new(&GrantShape::standard())?;
    let mut host = store.host(&local_case()?, 4_096)?;
    host.command_sender()?
        .submit_local_erasure(&submission(1, ErasureScopeV1::PrivateSubjectData)?)
        .map_err(fail)?;
    assert_eq!(
        ErasurePersistencePortV1::read_object(&store.sqlite()?, idempotency(1)?.reference()?)?,
        idempotency(1)?.to_canonical_cbor()?
    );
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

/// The local fixture on `adapter` retaining the valid ERAZ1, ELSEL1 and
/// ELIDEM1 of key 1 at chain head `head`, plus `extra`.
fn plain_fixture(
    adapter: Adapter,
    head: u64,
    extra: &[LocalErasureAuthorizationV1],
) -> TestResult<Fixture> {
    let subject = local_erasure_subject_v1(principal_ref()?, actor())?;
    let mut objects = vec![
        authorization(1, head)?.to_canonical_cbor()?,
        LocalErasureSelectorV1 { subject }.to_canonical_cbor()?,
        idempotency(1)?.to_canonical_cbor()?,
    ];
    for record in extra {
        objects.push(record.to_canonical_cbor()?);
    }
    let (fixture, ()) = Fixture::local(adapter, &GrantShape::standard(), 4_096, |store| {
        retain_objects(store, &objects)
    })?;
    assert_eq!(fixture.head, head);
    Ok(fixture)
}

/// The chain head every fixture of the standard grant shape records.
fn standard_head() -> TestResult<u64> {
    provisioned(&mut MemoryStore::new(), &GrantShape::standard(), &[])
}

#[test]
fn the_authority_recomputes_every_eraz1_rule_of_a_plain_submission() -> TestResult {
    let head = standard_head()?;
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
    for adapter in ADAPTERS {
        let mut fixture = plain_fixture(adapter, head, &tampered)?;
        // Every ERAZ1 that breaks a rule, or is not retained, is
        // unauthorized.
        for record in &tampered {
            assert_eq!(
                PlainRequest::with_authorization(1, record, head)?.submit(&mut fixture.host),
                Err(ErasureHostErrorV1::AuthorizationDenied)
            );
        }
        let mut missing = PlainRequest::valid(1, head)?;
        missing.input.authorization = reference(0x85);
        assert_eq!(
            missing.submit(&mut fixture.host),
            Err(ErasureHostErrorV1::AuthorizationDenied)
        );
    }
    Ok(())
}

#[test]
fn the_authority_recomputes_every_erq1_field_of_a_plain_submission() -> TestResult {
    let head = standard_head()?;
    let mut rebound = authorization(1, head)?;
    rebound.erq1_request = reference(0x84);
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
    for adapter in ADAPTERS {
        let mut fixture = plain_fixture(adapter, head, std::slice::from_ref(&rebound))?;
        let host = &mut fixture.host;
        for change in &changes {
            let mut request = PlainRequest::valid(1, head)?;
            change(&mut request.input);
            assert_eq!(request.submit(host), Err(ErasureHostErrorV1::Conflict));
        }
        // An ERAZ1 bound to a request id the key does not derive conflicts.
        let mut rebound_request = PlainRequest::with_authorization(1, &rebound, head)?;
        rebound_request.input.request = reference(0x84);
        assert_eq!(
            rebound_request.submit(host),
            Err(ErasureHostErrorV1::Conflict)
        );
        // The valid plain submission is admitted; a second one for the
        // subject is refused while the first is pre-terminal.
        assert_eq!(
            PlainRequest::valid(1, head)?.submit(host),
            Ok(ErasureLifecycleV1::Submitted)
        );
        assert_eq!(
            host.command_sender()?
                .submit_local_erasure(&submission(2, ErasureScopeV1::PrivateSubjectData)?),
            Err(LocalErasureSubmitErrorV1::Concurrent)
        );
    }
    Ok(())
}

#[test]
fn a_plain_submission_cannot_bypass_the_subject_checks() -> TestResult {
    let head = standard_head()?;
    let subject = local_erasure_subject_v1(principal_ref()?, actor())?;
    let objects = [
        authorization(2, head)?.to_canonical_cbor()?,
        LocalErasureSelectorV1 { subject }.to_canonical_cbor()?,
        idempotency(2)?.to_canonical_cbor()?,
        rejection(1)?.to_canonical_cbor()?,
    ];
    for adapter in ADAPTERS {
        // One request head over the reserve: the subject's quota is 1.
        let (mut fixture, ()) =
            Fixture::local(adapter, &GrantShape::standard(), RESERVE + 1, |store| {
                retain_objects(store, &objects)
            })?;
        assert_eq!(fixture.head, head);
        let host = &mut fixture.host;
        host.command_sender()?
            .submit_local_erasure(&submission(1, ErasureScopeV1::PrivateSubjectData)?)
            .map_err(fail)?;
        // While request 1 is pre-terminal a plain request 2 is refused.
        assert_eq!(
            PlainRequest::valid(2, head)?.submit(host),
            Err(ErasureHostErrorV1::Conflict)
        );
        // Once request 1 is rejected the quota still refuses it.
        host.command_sender()?
            .reject_erasure_request(request_of(1)?, rejection(1)?.reference()?)?;
        assert_eq!(
            PlainRequest::valid(2, head)?.submit(host),
            Err(ErasureHostErrorV1::Conflict)
        );
    }
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

/// The Local authority whose bundle names one `key-registry` owner, and
/// a fixture of that bundle on `adapter` whose host builds the views.
///
/// The authority is composed over an identically provisioned Memory store,
/// since a Memory store is gone into its host once that host opens. Both
/// stores hold no request and no retained object, and composing such an
/// empty store reads only its store identity and signer key; the retained
/// objects `matches_store`, `rotation_admitted` and
/// `retained_trust_verifies` also read are absent from both.
fn local_authority(
    adapter: Adapter,
) -> TestResult<(Fixture, ErasureCoordinatorCompositionV1, ErasureReferenceV1)> {
    let owner = pos_core::local_erasure_owner_ref_v1(
        ErasureReferenceV1::from_digest(STORE_IDENTITY),
        1,
        "key-registry",
    )?;
    let case = Case::signed(&single_owner_bundle(owner), &bundle_root(), &[])?;
    let composition = {
        let mut scratch = MemoryStore::new();
        provisioned(&mut scratch, &GrantShape::standard(), &[])?;
        case.compose(&mut scratch).map_err(fail)?
    };
    let (fixture, ()) = Fixture::open(adapter, &GrantShape::standard(), (case, 4_096), |_| Ok(()))?;
    Ok((fixture, composition, owner))
}

#[test]
fn the_local_authority_refuses_an_unbound_freeze() -> TestResult {
    for adapter in ADAPTERS {
        let (mut fixture, composition, _owner) = local_authority(adapter)?;
        let view = fixture.host.authority_view()?;
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
    }
    Ok(())
}

#[test]
fn the_local_authority_recomputes_every_fork_scope_extension() -> TestResult {
    for adapter in ADAPTERS {
        let (mut fixture, composition, _owner) = local_authority(adapter)?;
        let view = fixture.host.authority_view()?;
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
    }
    Ok(())
}

#[test]
fn the_local_authority_refuses_an_unknown_attempt_or_unpinned_acknowledgement() -> TestResult {
    for adapter in ADAPTERS {
        let (mut fixture, composition, _owner) = local_authority(adapter)?;
        let view = fixture.host.authority_view()?;
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
        let admission =
            ErasureFreezeAdmissionEvidenceV1::new(ErasureFreezeAdmissionEvidenceInputV1 {
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
            authority.validate_freeze_authorization_with_view(
                &view,
                &admission,
                &freeze_authorization
            ),
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
    }
    Ok(())
}

#[test]
fn a_receipt_needs_an_active_attempt_and_correction_and_resolution_are_refused() -> TestResult {
    for adapter in ADAPTERS {
        let (mut fixture, composition, _owner) = local_authority(adapter)?;
        let view = fixture.host.authority_view()?;
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
        let erq1 = ErasureRequestV1::new(PlainRequest::valid(1, fixture.head)?.input)?;
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
        // Receipts are served, but only for a request with a readable active
        // attempt; this request has none.
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
    }
    Ok(())
}

#[test]
fn destruction_goes_only_to_an_owner_the_bundle_names() -> TestResult {
    for adapter in ADAPTERS {
        let (mut fixture, composition, owner) = local_authority(adapter)?;
        let view = fixture.host.authority_view()?;
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
            authority.dispatch_destruction(
                &view,
                request,
                &[command(owner), command(reference(0xb7))]
            ),
            Err(ErasureErrorV1::ScopeInvalid)
        );
        // The view built outside a host command reads no stored object.
        assert_eq!(view.retained_object(reference(0xb8)), None);
        assert!(view.local_principal_authority(grant_id()).is_none());
        assert_eq!(view.maximum_requests(), 4_096);
        assert!(view.verified_requests().is_empty());
        assert!(view.verified_request(request).is_none());
    }
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
        owned_roots_on(&mut self.sqlite()?, owner, count)
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

/// Create `count` root Timelines owned by `owner` on `store`.
fn owned_roots_on(
    store: &mut (impl EventStore + ?Sized),
    owner: EntityId,
    count: usize,
) -> TestResult<Vec<TimelineId>> {
    let mut roots = Vec::with_capacity(count);
    for index in 0..count {
        let meta = TimelineMeta::root_owned(format!("owned-{index}"), owner);
        roots.push(store.create_timeline_with_meta(meta)?.id());
    }
    Ok(roots)
}

/// The actor's ADR-091 role-0 subject key at `epoch`.
fn subject_key(epoch: u64) -> TestResult<KeyIdentityV1> {
    subject_key_of(actor(), epoch)
}

/// The ADR-091 role-0 subject key of `subject` at `epoch`.
fn subject_key_of(subject: EntityId, epoch: u64) -> TestResult<KeyIdentityV1> {
    let owner = pos_crypto::subject_key::subject_owner_id(subject).map_err(fail)?;
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
    signed_body(sender.prepare_local_freeze(request)?)
}

/// The body a prepared freeze needs signed.
fn signed_body(preparation: LocalFreezePreparationV1) -> TestResult<ErasureReferenceV1> {
    match preparation {
        LocalFreezePreparationV1::Sign(body) => Ok(body),
        LocalFreezePreparationV1::CommitsRejection => Err("the freeze commits a rejection".into()),
    }
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
            LocalFreezePreparationV1::Sign(digest)
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
    for adapter in ADAPTERS {
        let (mut fixture, composition, owner) = local_authority(adapter)?;
        let view = fixture.host.authority_view()?;
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
        let admission =
            ErasureFreezeAdmissionEvidenceV1::new(ErasureFreezeAdmissionEvidenceInputV1 {
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
    }
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
    // Listed beside the bundle's Erasure Host Timeline, which every Local
    // bundle must list; ELB1 keeps its host Timelines sorted.
    let mut hosting = bundle();
    hosting.host_timelines.push(host_timeline);
    hosting.host_timelines.sort_unstable();
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

fn cbor(value: &ciborium::value::Value) -> TestResult<Vec<u8>> {
    let mut bytes = Vec::new();
    ciborium::into_writer(value, &mut bytes)?;
    Ok(bytes)
}

/// The FAC1 the Fork admission service sends for its own principal: a POC1
/// binding it to an owner name when `parent` is `None`, else an FCC1 Fork
/// of `parent` at cut zero.
fn service_command(
    host: &mut ErasureExecutionHostV1,
    session: &pos_store::ForkAdmissionAuthoritySessionV1,
    operation: u8,
    parent: Option<TimelineId>,
) -> TestResult<pos_core::ForkAdmissionHostCommandV1> {
    use ciborium::value::Value;
    let (signer, adapter, policy) = service_keys()?;
    let evidence = adapter.sign_authenticated_principal(
        pos_core::fork_authentication::AuthenticatedPrincipalRecordV1 {
            principal: pos_core::PrincipalRefV1::try_new([4; 16], "service.local")?,
            adapter_id: "service-adapter".to_owned(),
            assurance: 1,
            issued_at: 0,
            expires_at: u64::MAX,
            registry_binding: Hash::from_bytes([3; 32]),
            operation_nonce: [5; 32],
        },
    )?;
    let verified = pos_crypto::fork_authentication::verify_authenticated_principal_evidence_v1(
        &policy, evidence,
    )?;
    let principal = pos_core::fork_authentication::principal_digest_v1(
        &verified.evidence().record().principal,
    )?;
    let store_id = host
        .fork_admission_bootstrap()
        .fork_admission_host_record()?
        .store_id();
    let mut fields = vec![
        Value::Text(if parent.is_some() { "FCC1" } else { "POC1" }.to_owned()),
        Value::Integer(1.into()),
        Value::Bytes(store_id.as_bytes().to_vec()),
        Value::Bytes(session.identity().as_bytes().to_vec()),
        Value::Bytes(vec![operation; 32]),
        Value::Bytes(verified.evidence().digest()?.as_bytes().to_vec()),
        Value::Bytes(principal.as_bytes().to_vec()),
    ];
    fields.extend(parent.map_or_else(
        || vec![Value::Text("service".to_owned())],
        |parent| {
            vec![
                Value::Bytes(parent.inner().to_bytes().to_vec()),
                Value::Integer(0.into()),
                Value::Integer(0.into()),
                Value::Bytes(vec![8; 32]),
                Value::Bytes(vec![9; 32]),
                Value::Integer(1.into()),
                Value::Text("service-fork".to_owned()),
            ]
        },
    ));
    let inner = cbor(&Value::Array(fields))?;
    let signature = signer.sign_command(&inner, &verified)?;
    Ok(pos_core::ForkAdmissionHostCommandV1::from_canonical_cbor(
        &cbor(&Value::Array(vec![
            Value::Text("FAC1".to_owned()),
            Value::Integer(1.into()),
            Value::Bytes(inner),
            Value::Bytes(verified.evidence().to_canonical_cbor()?),
            Value::Bytes(signature.as_bytes().to_vec()),
        ]))?,
    )?)
}

/// The Fork admission service's host key, its authentication adapter and
/// the policy that trusts that adapter.
fn service_keys() -> TestResult<(
    pos_crypto::fork_authentication::ForkHostSigningKeyV1,
    pos_crypto::fork_authentication::ForkAuthenticationAdapterSigningKeyV1,
    pos_core::fork_authentication::ForkAuthenticationPolicyV1,
)> {
    let signer = pos_crypto::fork_authentication::ForkHostSigningKeyV1::from_seed([0x71; 32])?;
    let adapter =
        pos_crypto::fork_authentication::ForkAuthenticationAdapterSigningKeyV1::from_seed(
            [0x72; 32],
        )?;
    let policy = pos_core::fork_authentication::ForkAuthenticationPolicyV1::new(vec![
        pos_core::fork_authentication::ForkAuthenticationAdapterPolicyV1 {
            adapter_id: "service-adapter".to_owned(),
            verifying_key: adapter.public_key(),
            minimum_assurance: 1,
            registry_bindings: vec![Hash::from_bytes([3; 32])],
        },
    ])?;
    Ok((signer, adapter, policy))
}

/// Provision the Fork admission service on `host`, bind its own principal
/// and admit its Fork of `parent` (an FCC1): the child's id.
fn service_admitted_fork(
    host: &mut ErasureExecutionHostV1,
    parent: TimelineId,
) -> TestResult<TimelineId> {
    let (signer, _, policy) = service_keys()?;
    let key = pos_core::PublicKey::from_bytes(signer.public_key());
    let bootstrap = host.fork_admission_bootstrap();
    let initialize = bootstrap.begin_fork_admission_initialize(key, policy.digest()?)?;
    bootstrap.finalize_fork_admission_initialize(
        &initialize,
        &signer.sign_initialize(&initialize.to_canonical_cbor()?)?,
    )?;
    let open = bootstrap.begin_fork_admission_open(key, policy.digest()?)?;
    let session = bootstrap
        .finalize_fork_admission_open(&open, &signer.sign_open(&open.to_canonical_cbor()?)?)?;
    let bind = service_command(host, &session, 1, None)?;
    host.execute_fork_admission_command(&session, &policy, &bind)?;
    let fork = service_command(host, &session, 2, Some(parent))?;
    match host.execute_fork_admission_command(&session, &policy, &fork)? {
        pos_core::ForkAdmissionOperationResultV1::Fork(receipt) => Ok(receipt.child_id),
        other @ pos_core::ForkAdmissionOperationResultV1::PrincipalOwner(_) => {
            Err(format!("expected an admitted Fork, got {other:?}").into())
        }
    }
}

/// ADR-136 §1 and §3 (#1477): a Fork the Fork admission service admits for
/// its own principal inherits its parent's owner, so it freezes by owner.
///
/// The parent is a listed host Timeline, which the freeze leaves out, so no
/// `fork_point` lineage reaches the child: only its owner, the actor, does.
#[test]
fn a_service_admitted_fork_of_a_host_timeline_freezes_by_its_inherited_owner() -> TestResult {
    let owned = OwnedStore::new()?;
    let host_timeline = owned
        .store
        .sqlite()?
        .create_timeline_with_meta(TimelineMeta::root_owned("host", actor()))?
        .id();
    let mut hosting = bundle();
    hosting.host_timelines.push(host_timeline);
    hosting.host_timelines.sort_unstable();
    let case = Case::signed(&hosting, &bundle_root(), &[])?;
    let (child, digest) = {
        let mut host = owned.store.host(&case, 4_096)?;
        let child = service_admitted_fork(&mut host, host_timeline)?;
        assert_eq!(
            host.read_sender()?
                .timeline(child)?
                .ok_or("no admitted child")?
                .meta
                .owner,
            Some(actor())
        );
        let digest = prepared(
            &owned.store,
            &mut host,
            1,
            ErasureScopeV1::PrivateSubjectData,
        )?;
        (child, digest)
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
    assert_frozen(&mut host, &[owned.owned, child], host_timeline)?;
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
    // A routine bundle rotation is refused while the frozen request pins
    // the old bundle (owner decision Q12 on #1431).
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
    assert_eq!(
        Case::signed(&rotated, &bundle_root(), &[])?.refusal(&mut owned.store.sqlite()?),
        Some(LocalErasureCompositionErrorV1::BundleMismatch)
    );
    // After a compromise that revokes the old signer, the rotation is
    // accepted, and recovery verifies the old freeze against the bundle it
    // pinned, retained at prepare.
    let old_signer = bundle().signer_key_id;
    let mut host = owned.store.host(
        &Case::signed(&rotated, &bundle_root(), &[old_signer.as_str()])?,
        4_096,
    )?;
    assert_frozen(&mut host, &[owned.owned, child], owned.other)
}

/// A fresh recipient-key custody directory of mode 0700 inside a temporary
/// directory, which the caller keeps for as long as it needs the keys.
fn custody_directory() -> TestResult<(tempfile::TempDir, std::path::PathBuf)> {
    use std::os::unix::fs::PermissionsExt;

    let directory = tempfile::tempdir()?;
    let private = directory.path().join("recipient-private");
    std::fs::create_dir(&private)?;
    std::fs::set_permissions(&private, std::fs::Permissions::from_mode(0o700))?;
    Ok((directory, private))
}

/// One recipient export to a grantee, with the grantee's private directory
/// kept for the life of the test.
///
/// The directory must outlive every later publication: a dropped
/// directory's inode can be reused, and the store would then see the next
/// grantee's directory as already claimed.
struct PublishedExport {
    _directory: tempfile::TempDir,
    private: std::path::PathBuf,
    grantee: EntityId,
    export_id: [u8; 16],
}

/// Publish one recipient export of the actor's `timeline` to `grantee`
/// under the actor's export consent.
fn publish_export(
    store: &LocalStore,
    timeline: TimelineId,
    grantee: EntityId,
) -> TestResult<PublishedExport> {
    let (directory, private) = custody_directory()?;
    let owner = pos_store::sqlite::RecipientKeyOwnerV1::open(&private, grantee)?;
    let export_id = publish_export_as(store, timeline, actor(), grantee, &owner)?.0;
    Ok(PublishedExport {
        _directory: directory,
        private,
        grantee,
        export_id,
    })
}

/// Publish one recipient export of `subject`'s `timeline` to `grantee`.
///
/// The grantee's recipient keys are `owner`'s, and the export is under
/// `subject`'s export consent. Return its export id and the grantee's
/// enrolled recipient key.
fn publish_export_as(
    store: &LocalStore,
    timeline: TimelineId,
    subject: EntityId,
    grantee: EntityId,
    owner: &pos_store::sqlite::RecipientKeyOwnerV1,
) -> TestResult<([u8; 16], pos_core::RecipientKeyDescriptorV1)> {
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
            subject_id: subject,
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
    let recipient = sqlite.enroll_recipient_key(owner)?;
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
        owner,
        &pos_store::sqlite::RecipientExportRequestV1 {
            timeline_id: timeline,
            recipient,
            artifact_digest: reference(0xf1),
            evaluation: &evaluation,
            token: &token,
            now_secs: 1,
        },
    )?;
    Ok((publication.export_id, recipient))
}

#[test]
fn a_consented_freeze_covers_the_store_target_and_each_export_grantee() -> TestResult {
    let owned = OwnedStore::new()?;
    let export_id = publish_export(&owned.store, owned.owned, other_actor())?.export_id;
    let (mut host, signed) = signed_freeze(
        &owned.store,
        2,
        ErasureScopeV1::ConsentedSharedData,
        |_| Ok(()),
        |_| Ok(Vec::new()),
    )?;
    assert_frozen(&mut host, &[owned.owned], owned.other)?;
    // Role-0 keys and Timeline payloads are private-subject-data targets;
    // the export to the grantee is one `export-recipient` target, positive
    // after its recipient-export withdrawal (ADR-136 acceptance test 3 as
    // ADR-138 §2 amends it; executed in
    // `a_consented_erasure_withdraws_the_grantee_export_positively`).
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

/// Acceptance test 3b on both adapters: the bound is 4,096 targets per
/// category, and the store target counts toward it (owner decision of
/// 2026-11-20).
///
/// 4,095 affected Timelines and the store target are admitted; growth to
/// 4,096 after submission commits `Rejected` at freeze, and a new request
/// over 4,096 affected Timelines is refused at submit.
#[test]
fn the_closure_bound_is_exact_at_submit_and_freeze() -> TestResult {
    for adapter in ADAPTERS {
        let (mut fixture, roots) =
            Fixture::local(adapter, &GrantShape::standard(), 4_096, |store| {
                owned_roots_on(store, actor(), 4_095)
            })?;
        let request = request_of(1)?;
        let eraz1 = authorization(1, fixture.head)?.reference()?;
        let mut sender = fixture.host.command_sender()?;
        sender
            .submit_local_erasure(&submission(1, ErasureScopeV1::PrivateSubjectData)?)
            .map_err(fail)?;
        sender.authorize_erasure_request(request, eraz1)?;
        assert!(matches!(
            sender.prepare_local_freeze(request)?,
            LocalFreezePreparationV1::Sign(_)
        ));
        // Growth after submission: a Fork of an affected Timeline is one
        // more target, so the freeze commits `Rejected` without a
        // signature.
        sender.fork_timeline(roots[0], Seq::ZERO, "growth")?;
        assert_eq!(
            sender.prepare_local_freeze(request)?,
            LocalFreezePreparationV1::CommitsRejection
        );
        assert_eq!(
            sender.freeze_access(request, &freeze(eraz1))?.lifecycle(),
            ErasureLifecycleV1::Rejected
        );
        // A new request over the bound is refused before any ERQ1 exists;
        // a consented one, whose closure holds no Timeline payload, fits.
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
                .state
                .lifecycle(),
            ErasureLifecycleV1::Submitted
        );
        assert!(fixture
            .host
            .read_sender()?
            .erasure_state(request_of(2)?)?
            .is_none());
        let mut fixture = fixture.restarted()?;
        assert_eq!(
            lifecycle(&mut fixture.host, request)?,
            ErasureLifecycleV1::Rejected
        );
    }
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
        register_subject_owner_keys_on(
            &mut self.sqlite()?,
            KeyRoleV1::SubjectDataEncryption,
            epochs,
        )
    }
}

/// Register keys of `role` and `epochs` under the actor's ADR-091 subject
/// owner on `store`.
fn register_subject_owner_keys_on(
    store: &mut (impl EventStore + ?Sized),
    role: KeyRoleV1,
    epochs: std::ops::RangeInclusive<u64>,
) -> TestResult {
    let mut registry = store.load_key_registry()?.ok_or("no key registry")?;
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
    store.save_key_registry(&registry)?;
    Ok(())
}

// Both adapters: the closure's keys are `key_identities` of the host's
// authority view, one per record of the registry `load_key_registry` returns,
// which `MemoryStore` and `SqliteStore` both implement. So each registered key
// is one Key target on either adapter.
/// The lifecycle of the private submission of request 1 on a local
/// fixture of `adapter` whose actor's subject owner holds `keys`, or its
/// refusal.
fn submission_with_keys(
    adapter: Adapter,
    keys: &[(KeyRoleV1, std::ops::RangeInclusive<u64>)],
) -> TestResult<Result<ErasureLifecycleV1, LocalErasureSubmitErrorV1>> {
    let (mut fixture, ()) = Fixture::local(adapter, &GrantShape::standard(), 4_096, |store| {
        for (role, epochs) in keys {
            register_subject_owner_keys_on(store, *role, epochs.clone())?;
        }
        Ok(())
    })?;
    Ok(fixture
        .host
        .command_sender()?
        .submit_local_erasure(&submission(1, ErasureScopeV1::PrivateSubjectData)?)
        .map(|admitted| admitted.state.lifecycle()))
}

#[test]
fn the_key_and_backup_bound_is_exact_at_submit() -> TestResult {
    // No owned Timeline: the store target and one key target per role-0
    // key, each with a Key and a Backup cell. 4,095 keys fill the 4,096
    // targets; a 4,096th key is a 4,097th target, and 4,097 identities are
    // also over the key list's own bound.
    let role_0 = KeyRoleV1::SubjectDataEncryption;
    for adapter in ADAPTERS {
        assert_eq!(
            submission_with_keys(adapter, &[(role_0, 1..=4_095)])?,
            Ok(ErasureLifecycleV1::Submitted)
        );
        for last in [4_096, 4_097] {
            assert_eq!(
                submission_with_keys(adapter, &[(role_0, 1..=last)])?,
                Err(LocalErasureSubmitErrorV1::ScopeTooLarge)
            );
        }
    }
    Ok(())
}

#[test]
fn the_key_list_is_bounded_on_its_own() -> TestResult {
    // One role-0 key and 4,095 role-7 keys of the subject owner: 4,096
    // identities, a closure of two targets. A 4,097th identity is over the
    // list's bound, though the closure would still hold two targets.
    let role_0 = (KeyRoleV1::SubjectDataEncryption, 1..=1);
    let role_7 = KeyRoleV1::CommunityArtifactEncryption;
    for adapter in ADAPTERS {
        assert_eq!(
            submission_with_keys(adapter, &[role_0.clone(), (role_7, 1..=4_095)])?,
            Ok(ErasureLifecycleV1::Submitted)
        );
        assert_eq!(
            submission_with_keys(adapter, &[role_0.clone(), (role_7, 1..=4_096)])?,
            Err(LocalErasureSubmitErrorV1::ScopeTooLarge)
        );
    }
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
        Self::frozen(store, owned, Vec::new(), bundle)
    }

    /// Request 1 of `store`, whose actor owns `owned`, frozen under
    /// `bundle` with the store, payload and subject-key cells and `extra`.
    fn frozen(
        store: LocalStore,
        owned: TimelineId,
        extra: Vec<Cell>,
        bundle: LocalErasureBundleV1,
    ) -> TestResult<Self> {
        let case = Case::signed(&bundle, &bundle_root(), &[])?;
        Self::freeze(&store, &case)?;
        let request = request_of(1)?;
        let mut cells = store_cells()?;
        cells.push(payload_cell(owned)?);
        cells.extend(subject_key_cells()?);
        cells.extend(extra);
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
            .filter(|obligation| negative(obligation).is_some())
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
        self.store.retain(std::slice::from_ref(&signed))?;
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
            ..retry_input
        },
    ] {
        assert_eq!(
            sender
                .dispatch_erasure_destruction(request, &ErasureRetryAdmissionV1::new(wrong)?)
                .map(drop),
            Err(ErasureHostErrorV1::Conflict)
        );
    }
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
                .state
                .lifecycle(),
            ErasureLifecycleV1::Submitted
        );
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
        self.store.retain(std::slice::from_ref(&signed))?;
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
        self.store.retain(std::slice::from_ref(&signed))?;
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
            .state
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
            OTHER_ROOT.clone_into(&mut new.issued_by);
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
    for adapter in ADAPTERS {
        let (mut fixture, composition, owner) = local_authority(adapter)?;
        let view = fixture.host.authority_view()?;
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
    }
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

// ---------------------------------------------------------------------------
// ADR-136 §4a: `LocalErasureExecutorV1`, `destroy_key_for_erasure` and the
// dispatch outbox, with MemoryStore/SQLite parity, and the Q18 subject-fence
// exemption (#1430).
// ---------------------------------------------------------------------------

use pos_core::{
    ErasureAuthorityExecutionV1, ErasureOwnerCommandV1, ErasureOwnerResultV1,
    ErasureRecordedScopeReadV1, LocalErasureArtifactDispositionV1, LocalErasureCacheGenerationV1,
    LocalErasureNegativeResultV1, LocalErasureRedactionV1, LocalErasureReplicaPurgeV1,
    LocalOwnerEffectV1, LocalOwnerResultBindingV1, PreparedLocalOwnerEffectV1,
};
use pos_runtime::LocalErasureExecutorV1;

/// The Erasure Host Timeline of these stores: the unowned root Timeline at
/// `ELHT1` of the fixture store identity, which the host derives and fences
/// key destruction on.
fn erasure_host_timeline() -> TestResult<TimelineId> {
    Ok(pos_core::local_erasure_host_timeline_v1(
        ErasureReferenceV1::from_digest(STORE_IDENTITY),
    )?)
}

/// The actor's owned root Timeline of the Memory store, at a fixed
/// identity, so that two builds of that store are equal.
const fn memory_owned_timeline() -> TimelineId {
    TimelineId::from_ulid(Ulid::from_bytes([0x8e; 16]))
}

const fn executor() -> LocalErasureExecutorV1 {
    LocalErasureExecutorV1
}

fn host_timeline_meta() -> TestResult<TimelineMeta> {
    Ok(TimelineMeta {
        id: erasure_host_timeline()?,
        ..TimelineMeta::root("erasure-host")
    })
}

/// The bundle naming every owner and listing the Erasure Host Timeline.
fn executor_bundle() -> TestResult<LocalErasureBundleV1> {
    let mut bundle = owned_bundle(&ALL_CLASSES)?;
    bundle.host_timelines = vec![erasure_host_timeline()?];
    Ok(bundle)
}

/// Request 1 of `owned`, frozen under the executor bundle with `extra`
/// cells, after the store's Erasure Host Timeline is opened.
fn executor_attempted(owned: OwnedStore, extra: Vec<Cell>) -> TestResult<Attempted> {
    owned
        .store
        .sqlite()?
        .create_timeline_with_meta(host_timeline_meta()?)?;
    Attempted::frozen(owned.store, owned.owned, extra, executor_bundle()?)
}

/// The acknowledgement class whose ELOWN1 owner is `owner`.
fn class_of(owner: ErasureReferenceV1) -> TestResult<&'static str> {
    let store = ErasureReferenceV1::from_digest(STORE_IDENTITY);
    for (category, ack_class) in ALL_CLASSES {
        if pos_core::local_erasure_owner_ref_v1(store, category, ack_class)? == owner {
            return Ok(ack_class);
        }
    }
    Err("no acknowledgement class owns the command".into())
}

/// Each owner result as its class and outcome, in class order.
fn outcomes(
    results: &[ErasureOwnerResultV1],
) -> TestResult<Vec<(&'static str, Option<ErasureErrorV1>)>> {
    let mut outcomes = Vec::new();
    for result in results {
        outcomes.push((
            class_of(result.command().destruction.owner)?,
            result.error(),
        ));
    }
    outcomes.sort_unstable_by_key(|(ack_class, _)| *ack_class);
    Ok(outcomes)
}

/// The outcomes of the store, payload and subject-key owners, with the
/// local replica's `replica` outcome.
const fn expected_outcomes(
    replica: Option<ErasureErrorV1>,
) -> [(&'static str, Option<ErasureErrorV1>); 5] {
    [
        ("client-cache-signal", None),
        ("key-registry", None),
        (
            "local-backup-inventory",
            Some(ErasureErrorV1::BackupInventoryIncomplete),
        ),
        ("local-replica", replica),
        (
            "timeline-payload",
            Some(ErasureErrorV1::ArtifactDeletionFailed),
        ),
    ]
}

/// The dispatched command of `category` in `request`'s outbox.
fn command_of(
    host: &mut ErasureExecutionHostV1,
    request: ErasureReferenceV1,
    category: ErasureInventoryCategoryV1,
) -> TestResult<ErasureOwnerCommandV1> {
    Ok(host
        .command_sender()?
        .dispatched_owner_commands(request)?
        .into_iter()
        .find(|command| command.destruction.category == category)
        .ok_or("no dispatched command of the category")?)
}

/// The destruction of the actor's subject key under `authorization`.
fn subject_key_destruction(authorization: Hash) -> TestResult<KeyDestructionRequestV1> {
    Ok(KeyDestructionRequestV1::new(
        subject_key(1)?,
        Hash::from_bytes([0x81; 32]),
        authorization,
    ))
}

impl LocalStore {
    /// The ELO1 `result` names, read back from the store.
    fn elo1(&self, result: &ErasureOwnerResultV1) -> TestResult<LocalErasureOwnerResultV1> {
        Ok(LocalErasureOwnerResultV1::from_canonical_cbor(
            &ErasurePersistencePortV1::read_object(&self.sqlite()?, result.owner_result())?,
        )?)
    }

    /// The effect record `elo1` binds, read back by its digest.
    fn effect(&self, elo1: &LocalErasureOwnerResultV1) -> TestResult<Vec<u8>> {
        Ok(ErasurePersistencePortV1::read_object(
            &self.sqlite()?,
            elo1.effect_digest,
        )?)
    }
}

impl Attempted {
    /// A host over this store on which attempt 0 is dispatched.
    fn dispatched(&self) -> TestResult<ErasureExecutionHostV1> {
        let mut host = self.host()?;
        host.command_sender()?
            .dispatch_erasure_destruction(self.request, &self.attempt)?;
        Ok(host)
    }

    /// Assert that the committed ELO1 of `result` binds its command and
    /// outcome, and that its effect digest names the effect its class
    /// commits: an ELNEG1 for a negative outcome, else the class's record or
    /// the subject key's tombstone receipt.
    fn assert_effect(&self, result: &ErasureOwnerResultV1) -> TestResult {
        let destruction = result.command().destruction;
        let elo1 = self.store.elo1(result)?;
        assert_eq!(
            elo1,
            LocalErasureOwnerResultV1 {
                request: self.request,
                attempt: self.attempt.reference(),
                obligation: destruction.obligation,
                command: destruction.command,
                owner_ref: destruction.owner,
                error: result.error(),
                effect_digest: elo1.effect_digest,
            }
        );
        if let Some(error) = result.error() {
            let negative = LocalErasureNegativeResultV1 {
                command: destruction.command,
                owner_ref: destruction.owner,
                error,
            };
            assert_eq!(elo1.effect_digest, negative.reference()?);
            assert_eq!(self.store.effect(&elo1)?, negative.to_canonical_cbor()?);
            return Ok(());
        }
        match class_of(destruction.owner)? {
            "key-registry" => {
                let receipt = deletion_receipt(&subject_key_destruction(Hash::from_bytes(
                    destruction.command.digest(),
                ))?);
                assert_eq!(
                    elo1.effect_digest,
                    ErasureReferenceV1::from_digest(*receipt.as_bytes())
                );
                let registry = self
                    .store
                    .sqlite()?
                    .load_key_registry()?
                    .ok_or("no key registry")?;
                assert_eq!(
                    registry
                        .tombstone(subject_key(1)?)
                        .map(|tombstone| tombstone.deletion_receipt),
                    Some(receipt)
                );
            }
            "client-cache-signal" => {
                let (scope, _) = self
                    .store
                    .sqlite()?
                    .recorded_scope(self.request)?
                    .ok_or("no committed scope")?;
                // Q8: the generation is the attempt's admitted position.
                let record = LocalErasureCacheGenerationV1 {
                    request: self.request,
                    scope_commitment: scope.reference(),
                    generation: 2,
                };
                assert_eq!(self.attempt.admitted_position(), 2);
                assert_eq!(elo1.effect_digest, record.reference()?);
                assert_eq!(self.store.effect(&elo1)?, record.to_canonical_cbor()?);
            }
            "local-replica" => {
                let record = LocalErasureReplicaPurgeV1 {
                    request: self.request,
                    command: destruction.command,
                    replica_id: destruction.target.replica_id,
                };
                assert_eq!(elo1.effect_digest, record.reference()?);
                assert_eq!(self.store.effect(&elo1)?, record.to_canonical_cbor()?);
            }
            _ => {
                let record = LocalErasureArtifactDispositionV1 {
                    request: self.request,
                    artifact_class: destruction.target.artifact_class,
                    artifact_digest: destruction.target.artifact_digest,
                    redaction: LocalErasureRedactionV1::Redacted,
                    replay_claim_to: ErasureReplayClaimV1::ExactAuthoritativeWithRedactedViews,
                };
                assert_eq!(elo1.effect_digest, record.reference()?);
                assert_eq!(self.store.effect(&elo1)?, record.to_canonical_cbor()?);
            }
        }
        Ok(())
    }
}

#[test]
fn every_owner_class_commits_its_effect_and_elo1_at_the_host_seam() -> TestResult {
    let attempted = executor_attempted(OwnedStore::new()?, Vec::new())?;
    let request = attempted.request;
    {
        // No attempt is active yet, and an unknown request has no manifest:
        // both outboxes are empty.
        let mut host = attempted.host()?;
        let mut sender = host.command_sender()?;
        assert!(sender.dispatched_owner_commands(request)?.is_empty());
        assert!(sender
            .dispatched_owner_commands(reference(0x42))?
            .is_empty());
    }
    let mut host = attempted.dispatched()?;
    // The outbox is every obligation of attempt 0, keys first and the local
    // replica last, otherwise in the attempt's order.
    let mut expected = Vec::new();
    for obligation in &attempted.obligations {
        expected.push(ErasureOwnerCommandV1 {
            request,
            destruction: ErasureDestructionCommandV1::from_obligation(
                obligation,
                attempted.attempt.reference(),
            ),
        });
    }
    expected.sort_by_key(|command| match command.destruction.category {
        ErasureInventoryCategoryV1::Key => 0,
        ErasureInventoryCategoryV1::Artifact => 1,
        ErasureInventoryCategoryV1::Backup => 2,
        ErasureInventoryCategoryV1::Replica => 3,
    });
    assert_eq!(
        host.command_sender()?.dispatched_owner_commands(request)?,
        expected
    );
    let results = LocalErasureExecutorV1::replay(&mut host, request).map_err(fail)?;
    // Keys first, the local replica after every other owner.
    assert_eq!(
        results
            .first()
            .map(|result| result.command().destruction.category),
        Some(ErasureInventoryCategoryV1::Key)
    );
    assert_eq!(
        results
            .last()
            .map(|result| result.command().destruction.category),
        Some(ErasureInventoryCategoryV1::Replica)
    );
    assert_eq!(outcomes(&results)?, expected_outcomes(None));
    // A replay is idempotent: every owner returns the same owner result.
    assert_eq!(
        LocalErasureExecutorV1::replay(&mut host, request).map_err(fail)?,
        results
    );
    // No owner outcome poisoned the host.
    assert_eq!(
        lifecycle(&mut host, request)?,
        ErasureLifecycleV1::AwaitingAcknowledgements
    );
    drop(host);
    for result in &results {
        attempted.assert_effect(result)?;
    }
    Ok(())
}

#[test]
fn the_outbox_replays_only_unacknowledged_commands() -> TestResult {
    let attempted = executor_attempted(OwnedStore::new()?, Vec::new())?;
    let request = attempted.request;
    let backup = {
        let mut host = attempted.dispatched()?;
        let results = LocalErasureExecutorV1::replay(&mut host, request).map_err(fail)?;
        *results
            .iter()
            .find(|result| {
                result.command().destruction.category == ErasureInventoryCategoryV1::Backup
            })
            .ok_or("no backup owner result")?
    };
    // The signer's part: a purpose-1 ELS1 over the backup ELO1.
    let signed = signature_record(
        LocalErasureSignaturePurposeV1::OwnerResult,
        backup.owner_result(),
        &erasure_signer(),
        1,
    )?;
    attempted.store.retain(std::slice::from_ref(&signed))?;
    let obligation = attempted.obligation_of(ErasureInventoryCategoryV1::Backup)?;
    let mut host = attempted.host()?;
    host.command_sender()?.acknowledge_erasure(
        request,
        acknowledgement(
            &obligation,
            signature_address(&signed)?,
            ErasureAcknowledgementOutcomeV1::Negative,
        ),
    )?;
    let outbox = host.command_sender()?.dispatched_owner_commands(request)?;
    assert_eq!(outbox.len(), attempted.obligations.len() - 1);
    assert!(outbox
        .iter()
        .all(|command| command.destruction.obligation != obligation.reference()));
    assert_eq!(
        LocalErasureExecutorV1::replay(&mut host, request)
            .map_err(fail)?
            .len(),
        outbox.len()
    );
    Ok(())
}

/// A Memory store with the content the `SQLite` executor fixture holds before
/// its freeze, at fixed identities, plus `retained`; and its root-grant
/// chain head.
fn memory_store(retained: &[Vec<u8>]) -> TestResult<(MemoryStore, u64)> {
    let mut store = MemoryStore::new();
    let head = provisioned(&mut store, &GrantShape::standard(), &[])?;
    driver_content(&mut store)?;
    for object in retained {
        store.retain_erasure_object(object, ERASURE_RETAINED_OBJECT_MAX_BYTES_V1)?;
    }
    Ok((store, head))
}

/// The content of the driver fixture, at fixed identities: the actor's
/// owned root Timeline, the Erasure Host Timeline and the actor's role-0
/// subject key.
fn driver_content(store: &mut (impl EventStore + ?Sized)) -> TestResult {
    store.create_timeline_with_meta(TimelineMeta {
        id: memory_owned_timeline(),
        ..TimelineMeta::root_owned("owned-0", actor())
    })?;
    store.create_timeline_with_meta(host_timeline_meta()?)?;
    let mut registry = store.load_key_registry()?.ok_or("no key registry")?;
    registry
        .register_key(KeyRegistrationV1::new(
            subject_key(1)?,
            Hash::from_bytes([0x81; 32]),
            None,
        ))
        .map_err(fail)?;
    store.save_key_registry(&registry)?;
    Ok(())
}

/// A Memory host over `store` composed under `case`.
fn memory_host(mut store: MemoryStore, case: &Case) -> TestResult<ErasureExecutionHostV1> {
    let composition = case.compose(&mut store).map_err(fail)?;
    Ok(
        ErasureExecutionHostV1::recover_memory_fixture_with_authority(
            store,
            &composition,
            ErasureRecoveryLimitsV1::from_maximum_requests(4_096)?,
        )?,
    )
}

/// Submit and authorize request 1 on `host` at chain head `head`, and
/// prepare its freeze.
fn memory_prepared(host: &mut ErasureExecutionHostV1, head: u64) -> TestResult<ErasureReferenceV1> {
    let mut sender = host.command_sender()?;
    sender
        .submit_local_erasure(&submission(1, ErasureScopeV1::PrivateSubjectData)?)
        .map_err(fail)?;
    let request = request_of(1)?;
    sender.authorize_erasure_request(request, authorization(1, head)?.reference()?)?;
    signed_body(sender.prepare_local_freeze(request)?)
}

#[test]
fn a_memory_store_runs_every_owner_class_as_sqlite_does() -> TestResult {
    let bundle = executor_bundle()?;
    let case = Case::signed(&bundle, &bundle_root(), &[])?;
    // The freeze body is a pure function of the store, so a second build of
    // the Memory store, holding the ELS1 over it, freezes to the same body.
    let digest = {
        let (store, head) = memory_store(&[])?;
        memory_prepared(&mut memory_host(store, &case)?, head)?
    };
    let signed = signature_record(
        LocalErasureSignaturePurposeV1::FreezeAuthorization,
        digest,
        &erasure_signer(),
        1,
    )?;
    let (store, head) = memory_store(std::slice::from_ref(&signed))?;
    let mut host = memory_host(store, &case)?;
    assert_eq!(memory_prepared(&mut host, head)?, digest);
    let request = request_of(1)?;
    let mut cells = store_cells()?;
    cells.push(payload_cell(memory_owned_timeline())?);
    cells.extend(subject_key_cells()?);
    let obligations = expected_obligations(request, &cells)?;
    let attempt = ErasureRetryAdmissionV1::new(Attempted::attempt_input(
        head,
        bundle.reference()?,
        &obligations,
        None,
    )?)?;
    {
        let mut sender = host.command_sender()?;
        assert_eq!(
            sender
                .freeze_access(request, &freeze(signature_address(&signed)?))?
                .lifecycle(),
            ErasureLifecycleV1::AccessFrozen
        );
        sender.dispatch_erasure_destruction(request, &attempt)?;
    }
    let results = LocalErasureExecutorV1::replay(&mut host, request).map_err(fail)?;
    // A Memory store has no file a purge could prove clean, so its local
    // replica is the permanent negative; every other class answers as on
    // SQLite.
    assert_eq!(
        outcomes(&results)?,
        expected_outcomes(Some(ErasureErrorV1::ReplicaNegativeAcknowledgement))
    );
    assert_eq!(
        LocalErasureExecutorV1::replay(&mut host, request).map_err(fail)?,
        results
    );
    let attempted = executor_attempted(OwnedStore::new()?, Vec::new())?;
    let sqlite = LocalErasureExecutorV1::replay(&mut attempted.dispatched()?, attempted.request)
        .map_err(fail)?;
    assert_eq!(outcomes(&sqlite)?, expected_outcomes(None));
    Ok(())
}

#[test]
fn the_local_replica_runs_last_and_a_held_store_is_a_transient_negative() -> TestResult {
    let attempted = executor_attempted(OwnedStore::new()?, Vec::new())?;
    let mut host = attempted.dispatched()?;
    let outbox = host
        .command_sender()?
        .dispatched_owner_commands(attempted.request)?;
    let (replica, others) = outbox.split_last().ok_or("the outbox is empty")?;
    assert_eq!(
        replica.destruction.category,
        ErasureInventoryCategoryV1::Replica
    );
    // F1: the purge waits for every other owner of the attempt.
    for (index, other) in others.iter().enumerate() {
        assert_eq!(
            executor().execute(replica, &mut host),
            Err(ErasureErrorV1::PolicyConflict),
            "before owner {index}"
        );
        executor().execute(other, &mut host).map_err(fail)?;
    }
    let reader = rusqlite::Connection::open(&attempted.store.path)?;
    reader.execute_batch("BEGIN")?;
    let timelines: i64 =
        reader.query_row("SELECT count(*) FROM timelines", [], |row| row.get(0))?;
    assert!(timelines > 0);
    // The purge runs outside every fence; a held store is the one
    // transient code.
    let held = executor().execute(replica, &mut host).map_err(fail)?;
    assert_eq!(held.error(), Some(ErasureErrorV1::ReplicaTimeout));
    reader.execute_batch("COMMIT")?;
    drop(reader);
    let purged = executor().execute(replica, &mut host).map_err(fail)?;
    assert_eq!(purged.error(), None);
    drop(host);
    attempted.assert_effect(&held)?;
    attempted.assert_effect(&purged)
}

#[test]
fn a_replica_check_that_cannot_read_the_store_is_a_host_error() -> TestResult {
    let attempted = executor_attempted(OwnedStore::new()?, Vec::new())?;
    let mut host = attempted.dispatched()?;
    let outbox = host
        .command_sender()?
        .dispatched_owner_commands(attempted.request)?;
    let (replica, others) = outbox.split_last().ok_or("the outbox is empty")?;
    let mut key = None;
    for other in others {
        let result = executor().execute(other, &mut host).map_err(fail)?;
        if other.destruction.category == ErasureInventoryCategoryV1::Key {
            key = Some(result.owner_result());
        }
    }
    let digest = key.ok_or("no key owner result")?.digest();
    let peer = rusqlite::Connection::open(&attempted.store.path)?;
    let saved: Vec<u8> = peer.query_row(
        "SELECT object_cbor FROM erasure_evidence WHERE reference_digest = ?1",
        [digest.as_slice()],
        |row| row.get(0),
    )?;
    // An owner result the store cannot read is a host error, never a
    // refusal of the replica.
    peer.execute(
        "UPDATE erasure_evidence SET object_cbor = 7 WHERE reference_digest = ?1",
        [digest.as_slice()],
    )?;
    assert_eq!(
        executor().execute(replica, &mut host),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
    peer.execute(
        "UPDATE erasure_evidence SET object_cbor = ?2 WHERE reference_digest = ?1",
        rusqlite::params![digest.as_slice(), saved],
    )?;
    // So is a key registry it cannot read.
    let registry: Vec<u8> = peer.query_row(
        "SELECT state_cbor FROM key_registry WHERE singleton = 1",
        [],
        |row| row.get(0),
    )?;
    peer.execute(
        "UPDATE key_registry SET state_cbor = X'00' WHERE singleton = 1",
        [],
    )?;
    assert_eq!(
        executor().execute(replica, &mut host),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
    peer.execute(
        "UPDATE key_registry SET state_cbor = ?1 WHERE singleton = 1",
        rusqlite::params![registry],
    )?;
    drop(peer);
    // Readable again, the replica runs.
    assert_eq!(
        executor()
            .execute(replica, &mut host)
            .map_err(fail)?
            .error(),
        None
    );
    Ok(())
}

/// The ELO1 a negative `error` of `command` would commit.
fn negative_owner_result(
    command: &ErasureOwnerCommandV1,
    error: ErasureErrorV1,
) -> TestResult<ErasureReferenceV1> {
    let destruction = command.destruction;
    let prepared = PreparedLocalOwnerEffectV1::new(
        LocalOwnerEffectV1::Negative(
            LocalErasureNegativeResultV1 {
                command: destruction.command,
                owner_ref: destruction.owner,
                error,
            }
            .to_canonical_cbor()?,
        ),
        LocalOwnerResultBindingV1 {
            request: command.request,
            attempt: destruction.provenance,
            obligation: destruction.obligation,
            command: destruction.command,
            owner_ref: destruction.owner,
            error: Some(error),
        },
    )?;
    Ok(prepared.owner_result().reference())
}

#[test]
fn an_unreadable_key_registry_commits_no_owner_result() -> TestResult {
    let attempted = executor_attempted(OwnedStore::new()?, Vec::new())?;
    let mut host = attempted.dispatched()?;
    let key = command_of(
        &mut host,
        attempted.request,
        ErasureInventoryCategoryV1::Key,
    )?;
    let peer = rusqlite::Connection::open(&attempted.store.path)?;
    let saved: Vec<u8> = peer.query_row(
        "SELECT state_cbor FROM key_registry WHERE singleton = 1",
        [],
        |row| row.get(0),
    )?;
    peer.execute(
        "UPDATE key_registry SET state_cbor = X'00' WHERE singleton = 1",
        [],
    )?;
    // A store failure is a host error, never a durable negative.
    assert_eq!(
        executor().execute(&key, &mut host),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
    assert_eq!(
        host.command_sender()?
            .destroy_key_for_erasure(&key, subject_key(1)?)
            .map(drop),
        Err(ErasureHostErrorV1::AdapterFailure)
    );
    assert_eq!(
        LocalErasureExecutorV1::replay(&mut host, attempted.request).map(drop),
        Err(ErasureHostErrorV1::AdapterFailure)
    );
    peer.execute(
        "UPDATE key_registry SET state_cbor = ?1 WHERE singleton = 1",
        rusqlite::params![saved],
    )?;
    drop(peer);
    drop(host);
    assert_eq!(
        ErasurePersistencePortV1::read_object(
            &attempted.store.sqlite()?,
            negative_owner_result(&key, ErasureErrorV1::KeyDestructionFailed)?
        ),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
    // Once the registry reads again, the same command destroys the key.
    let mut host = attempted.host()?;
    let destroyed = executor().execute(&key, &mut host).map_err(fail)?;
    assert_eq!(destroyed.error(), None);
    drop(host);
    attempted.assert_effect(&destroyed)
}

#[test]
fn a_host_without_an_authority_has_no_outbox() -> TestResult {
    let mut host = ErasureExecutionHostV1::open_verified_empty(
        StoreConfig::Memory,
        ErasureRecoveryLimitsV1::compiled_maximum(),
    )?;
    assert_eq!(
        host.command_sender()?
            .dispatched_owner_commands(reference(0x42))
            .map(drop),
        Err(ErasureHostErrorV1::AuthorizationDenied)
    );
    assert_eq!(
        LocalErasureExecutorV1::replay(&mut host, reference(0x42)).map(drop),
        Err(ErasureHostErrorV1::AuthorizationDenied)
    );
    Ok(())
}

#[test]
fn key_destruction_completes_a_pending_phase_left_by_a_crash() -> TestResult {
    let attempted = executor_attempted(OwnedStore::new()?, Vec::new())?;
    let mut host = attempted.dispatched()?;
    let key = command_of(
        &mut host,
        attempted.request,
        ErasureInventoryCategoryV1::Key,
    )?;
    // The crash: the pending phase of the command's destruction committed,
    // its tombstone did not.
    host.command_sender()?.begin_key_registry_destruction(
        erasure_host_timeline()?,
        subject_key_destruction(Hash::from_bytes(key.destruction.command.digest()))?,
    )?;
    let completed = executor().execute(&key, &mut host).map_err(fail)?;
    assert_eq!(completed.error(), None);
    // A repeat is the same owner result, bound to the same tombstone.
    assert_eq!(
        executor().execute(&key, &mut host).map_err(fail)?,
        completed
    );
    drop(host);
    attempted.assert_effect(&completed)
}

#[test]
fn a_key_destroyed_under_another_authorization_binds_its_existing_receipt() -> TestResult {
    let attempted = executor_attempted(OwnedStore::new()?, Vec::new())?;
    let mut host = attempted.dispatched()?;
    let key = command_of(
        &mut host,
        attempted.request,
        ErasureInventoryCategoryV1::Key,
    )?;
    let foreign = subject_key_destruction(Hash::from_bytes([0x99; 32]))?;
    host.command_sender()?
        .begin_key_registry_destruction(erasure_host_timeline()?, foreign)?;
    // Pending under another authorization: the permanent negative.
    let refused = executor().execute(&key, &mut host).map_err(fail)?;
    assert_eq!(refused.error(), Some(ErasureErrorV1::KeyDestructionFailed));
    let receipt = deletion_receipt(&foreign);
    host.command_sender()?.complete_key_registry_destruction(
        erasure_host_timeline()?,
        foreign,
        receipt,
    )?;
    // Tombstoned under that authorization: positive, bound to its receipt.
    let destroyed = executor().execute(&key, &mut host).map_err(fail)?;
    assert_eq!(destroyed.error(), None);
    assert_eq!(
        executor().execute(&key, &mut host).map_err(fail)?,
        destroyed
    );
    drop(host);
    attempted.assert_effect(&refused)?;
    assert_eq!(
        attempted.store.elo1(&destroyed)?.effect_digest,
        ErasureReferenceV1::from_digest(*receipt.as_bytes())
    );
    Ok(())
}

#[test]
fn only_a_dispatched_key_command_destroys_and_only_under_an_open_fence() -> TestResult {
    let attempted = executor_attempted(OwnedStore::new()?, Vec::new())?;
    let request = attempted.request;
    let attempt = attempted.attempt.reference();
    let command_for = |category| -> TestResult<ErasureOwnerCommandV1> {
        Ok(ErasureOwnerCommandV1 {
            request,
            destruction: ErasureDestructionCommandV1::from_obligation(
                &attempted.obligation_of(category)?,
                attempt,
            ),
        })
    };
    let key = command_for(ErasureInventoryCategoryV1::Key)?;
    let mut host = attempted.host()?;
    // Before dispatch no attempt is active: nothing runs.
    assert_eq!(
        executor().execute(&key, &mut host),
        Err(ErasureErrorV1::PolicyConflict)
    );
    assert_eq!(
        host.command_sender()?
            .destroy_key_for_erasure(&key, subject_key(1)?)
            .map(drop),
        Err(ErasureHostErrorV1::Conflict)
    );
    host.command_sender()?
        .dispatch_erasure_destruction(request, &attempted.attempt)?;
    let mut sender = host.command_sender()?;
    let backup = command_for(ErasureInventoryCategoryV1::Backup)?;
    let other_attempt = ErasureOwnerCommandV1 {
        request,
        destruction: ErasureDestructionCommandV1 {
            provenance: reference(0x43),
            ..key.destruction
        },
    };
    // Another key than the target, a backup command of the same target,
    // and a command of another attempt destroy nothing.
    for (command, identity) in [
        (&key, signer_identity(1)),
        (&backup, subject_key(1)?),
        (&other_attempt, subject_key(1)?),
    ] {
        assert_eq!(
            sender.destroy_key_for_erasure(command, identity).map(drop),
            Err(ErasureHostErrorV1::Conflict)
        );
    }
    let destroyed = sender.destroy_key_for_erasure(&key, subject_key(1)?)?;
    assert_eq!(destroyed.error(), None);
    drop(host);
    attempted.assert_effect(&destroyed)
}

#[test]
fn a_consistent_command_outside_the_attempt_is_not_dispatched() -> TestResult {
    let attempted = executor_attempted(OwnedStore::new()?, Vec::new())?;
    let request = attempted.request;
    // A `local-backup-inventory` obligation of the store target: every
    // field derives correctly, but the frozen closure has no Backup cell
    // for that target, so the attempt never dispatched it.
    let target = store_target()?;
    let category = ErasureInventoryCategoryV1::Backup;
    let outside = ErasureObligationV1::new(ErasureObligationInputV1 {
        category,
        target,
        owner: pos_core::local_erasure_owner_ref_v1(
            ErasureReferenceV1::from_digest(STORE_IDENTITY),
            u64::from(category),
            "local-backup-inventory",
        )?,
        command_identity: destruction_command_reference(request, target),
    })?;
    assert!(!attempted.obligations.contains(&outside));
    let command = ErasureOwnerCommandV1 {
        request,
        destruction: ErasureDestructionCommandV1::from_obligation(
            &outside,
            attempted.attempt.reference(),
        ),
    };
    let mut host = attempted.dispatched()?;
    // The attempt has other unresolved obligations, none of them this one.
    assert!(!host
        .command_sender()?
        .dispatched_owner_commands(request)?
        .is_empty());
    assert_eq!(
        executor().execute(&command, &mut host),
        Err(ErasureErrorV1::PolicyConflict)
    );
    Ok(())
}

/// The actor's role-7 community key the bound ARD1 recording depends on.
fn community_key() -> KeyIdentityV1 {
    KeyIdentityV1::new("community:x", KeyRoleV1::CommunityArtifactEncryption, 1)
}

#[test]
fn an_artifact_is_redacted_only_once_every_key_it_depends_on_is_tombstoned() -> TestResult {
    for registered in [false, true] {
        let owned = ard1_store()?;
        if registered {
            owned.store.register(KeyRegistrationV1::new(
                community_key(),
                Hash::from_bytes([0x91; 32]),
                None,
            ))?;
        }
        let extra = ard1_cells(
            &owned.store,
            owned.owned,
            ArtifactDataClassV1::PrivateSubjectData,
        )?;
        let keyed = extra
            .iter()
            .find(|(_, category, _)| *category == ErasureInventoryCategoryV1::Key)
            .map(|(target, _, _)| target.artifact_digest)
            .ok_or("no keyed recording")?;
        let attempted = executor_attempted(owned, extra)?;
        let results =
            LocalErasureExecutorV1::replay(&mut attempted.dispatched()?, attempted.request)
                .map_err(fail)?;
        let community = pos_core::local_erasure_key_digest_v1(&community_key())?;
        let mut artifacts = 0;
        for result in &results {
            let destruction = result.command().destruction;
            let expected = match class_of(destruction.owner)? {
                // An unregistered key cannot be destroyed.
                "key-registry" if destruction.target.key_digest == community => {
                    (!registered).then_some(ErasureErrorV1::KeyDestructionFailed)
                }
                // Q7: only the recording whose one key the attempt destroyed
                // is redacted; a recording without a key never is.
                "artifact-store" => {
                    artifacts += 1;
                    (!(registered && destruction.target.artifact_digest == keyed))
                        .then_some(ErasureErrorV1::ArtifactDeletionFailed)
                }
                _ => continue,
            };
            assert_eq!(result.error(), expected);
            // A positive community-key result binds that key's own
            // tombstone, which `assert_effect` does not model.
            if destruction.target.key_digest != community || expected.is_some() {
                attempted.assert_effect(result)?;
            }
        }
        assert_eq!(artifacts, 2);
        assert_signer_rechecks_q7(&attempted, &results, keyed, registered)?;
    }
    Ok(())
}

/// The signer signs every artifact owner result the executor committed, and
/// a positive ELAD1 only while Q7 holds: the keyed recording's fabricated
/// positive ELAD1 is refused while its key is not tombstoned.
fn assert_signer_rechecks_q7(
    attempted: &Attempted,
    results: &[ErasureOwnerResultV1],
    keyed: ErasureReferenceV1,
    registered: bool,
) -> TestResult {
    let signer = signer_of(erasure_signer(), 1);
    let mut host = attempted.host()?;
    for result in results {
        let destruction = result.command().destruction;
        if class_of(destruction.owner)? != "artifact-store" {
            continue;
        }
        let sign = |host: &mut ErasureExecutionHostV1, owner_result| {
            signer.sign(
                host,
                LocalErasureSigningRequestV1::OwnerResult { owner_result },
            )
        };
        assert!(sign(&mut host, result.owner_result()).is_ok());
        if registered || destruction.target.artifact_digest != keyed {
            continue;
        }
        let prepared = PreparedLocalOwnerEffectV1::new(
            LocalOwnerEffectV1::ArtifactDisposition(
                LocalErasureArtifactDispositionV1 {
                    request: attempted.request,
                    artifact_class: destruction.target.artifact_class,
                    artifact_digest: destruction.target.artifact_digest,
                    redaction: LocalErasureRedactionV1::Redacted,
                    replay_claim_to: ErasureReplayClaimV1::ExactAuthoritativeWithRedactedViews,
                }
                .to_canonical_cbor()?,
            ),
            LocalOwnerResultBindingV1 {
                request: attempted.request,
                attempt: destruction.provenance,
                obligation: destruction.obligation,
                command: destruction.command,
                owner_ref: destruction.owner,
                error: None,
            },
        )?;
        let effect = prepared.effect_object().ok_or("no effect record")?;
        attempted.store.retain(&[
            effect.canonical_cbor().to_vec(),
            prepared.owner_result().canonical_cbor().to_vec(),
        ])?;
        assert_eq!(
            sign(&mut host, prepared.owner_result().reference()),
            Err(ErasureHostErrorV1::AuthorizationDenied)
        );
    }
    Ok(())
}

#[test]
fn a_frozen_request_whose_bundle_is_revoked_no_longer_holds_its_subject() -> TestResult {
    let attempted = Attempted::new(vec![actor()], owned_bundle(&ALL_CLASSES)?)?;
    // Frozen, with no attempt yet, the request holds its subject.
    assert_eq!(
        attempted
            .host()?
            .command_sender()?
            .submit_local_erasure(&submission(2, ErasureScopeV1::PrivateSubjectData)?)
            .map(drop),
        Err(LocalErasureSubmitErrorV1::Concurrent)
    );
    // Compromise: the installed TPS1 revokes its signer and a new bundle
    // is installed. The frozen bundle can never sign again (Q18).
    let revoked = attempted.bundle.signer_key_id.clone();
    let mut new = rotated_bundle(&attempted.store)?;
    new.issued_by = OTHER_ROOT.to_owned();
    let case = Case::signed(&new, &other_root(), &[revoked.as_str()])?;
    let mut host = attempted.store.host(&case, 4_096)?;
    assert_eq!(
        host.command_sender()?
            .submit_local_erasure(&submission(2, ErasureScopeV1::PrivateSubjectData)?)
            .map_err(fail)?
            .state
            .lifecycle(),
        ErasureLifecycleV1::Submitted
    );
    // It stays contained.
    assert_eq!(
        lifecycle(&mut host, attempted.request)?,
        ErasureLifecycleV1::AccessFrozen
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// ADR-136 §5/§6: `LocalErasureSignerV1` and `LocalErasureDriverV1`, the
// rotation rule and the startup sweep (#1431; acceptance tests 1, 4, 7 and
// the signer parts of 6).
// ---------------------------------------------------------------------------

use pos_runtime::{
    LocalErasureAdvanceV1, LocalErasureDriverV1, LocalErasureSignerV1,
    LocalErasureSigningRequestV1, LocalErasureStepV1, LocalErasureSweepV1,
};

/// A signer of `key`, registered as the fixture signer at `epoch`.
fn signer_of(key: SigningKey, epoch: u64) -> LocalErasureSignerV1 {
    LocalErasureSignerV1::new(
        SigningKeyMaterial::new(key),
        OwnerIdV1::from_static(SIGNER_OWNER),
        epoch,
    )
}

/// The driver of the fixture signer.
fn driver() -> LocalErasureDriverV1 {
    LocalErasureDriverV1::new(signer_of(erasure_signer(), 1))
}

/// The case of the bundle naming every owner and the derived Erasure Host
/// Timeline.
fn driver_case() -> TestResult<Case> {
    Case::signed(&owned_bundle(&ALL_CLASSES)?, &bundle_root(), &[])
}

/// A `SQLite` store with the Memory fixture's content at the same fixed
/// identities: the actor's owned root Timeline, the fixed unowned root,
/// the derived Erasure Host Timeline and the actor's role-0 subject key.
fn driver_store() -> TestResult<LocalStore> {
    let store = LocalStore::new(&GrantShape::standard())?;
    driver_content(&mut store.sqlite()?)?;
    Ok(store)
}

/// A Memory host with the same content, composed under `case`.
fn driver_memory_host(case: &Case) -> TestResult<ErasureExecutionHostV1> {
    let (store, _) = memory_store(&[])?;
    memory_host(store, case)
}

/// A store a fixture seeds before its host opens over it.
trait SeedStore: EventStore + ErasureInventoryPersistencePortV1 + ErasureAdmissionsPortV1 {}

impl<T: EventStore + ErasureInventoryPersistencePortV1 + ErasureAdmissionsPortV1> SeedStore for T {}

/// The store adapter a test runs over.
#[derive(Clone, Copy, Debug)]
enum Adapter {
    Memory,
    Sqlite,
}

/// Both adapters, Memory first.
///
/// A test runs over both unless its doc names why it cannot: the Q16
/// replica row, a `SQLite` close and reopen, the recipient-export catalog,
/// or a write into the store behind its host.
const ADAPTERS: [Adapter; 2] = [Adapter::Memory, Adapter::Sqlite];

/// One host over a provisioned store on either adapter.
struct Fixture {
    host: ErasureExecutionHostV1,
    /// The `SQLite` store, which outlives its host and reopens it; `None`
    /// on Memory, whose store the host owns.
    sqlite: Option<LocalStore>,
    case: Case,
    maximum_requests: usize,
    /// The root-grant chain head every ERAZ1 binds.
    head: u64,
}

impl Fixture {
    /// The store of `shape` on `adapter`, after `seed` ran on it, under a
    /// host composed of `case` with `maximum_requests` request heads.
    fn open<T>(
        adapter: Adapter,
        shape: &GrantShape,
        (case, maximum_requests): (Case, usize),
        seed: impl FnOnce(&mut dyn SeedStore) -> TestResult<T>,
    ) -> TestResult<(Self, T)> {
        let (host, sqlite, head, seeded) = match adapter {
            Adapter::Memory => {
                let mut store = MemoryStore::new();
                let head = provisioned(&mut store, shape, &[])?;
                let seeded = seed(&mut store)?;
                let composition = case.compose(&mut store).map_err(fail)?;
                let host = ErasureExecutionHostV1::recover_memory_fixture_with_authority(
                    store,
                    &composition,
                    ErasureRecoveryLimitsV1::from_maximum_requests(maximum_requests)?,
                )?;
                (host, None, head, seeded)
            }
            Adapter::Sqlite => {
                let store = LocalStore::new(shape)?;
                let seeded = seed(&mut store.sqlite()?)?;
                let host = store.host(&case, maximum_requests)?;
                let head = store.head;
                (host, Some(store), head, seeded)
            }
        };
        let fixture = Self {
            host,
            sqlite,
            case,
            maximum_requests,
            head,
        };
        Ok((fixture, seeded))
    }

    /// The store of `shape` under the bundle without owners and
    /// `maximum_requests` request heads, after `seed`.
    fn local<T>(
        adapter: Adapter,
        shape: &GrantShape,
        maximum_requests: usize,
        seed: impl FnOnce(&mut dyn SeedStore) -> TestResult<T>,
    ) -> TestResult<(Self, T)> {
        Self::open(adapter, shape, (local_case()?, maximum_requests), seed)
    }

    /// The driver fixture on `adapter`: the driver content and then `seed`,
    /// under the bundle naming every owner.
    fn new<T>(
        adapter: Adapter,
        seed: impl FnOnce(&mut dyn SeedStore) -> TestResult<T>,
    ) -> TestResult<(Self, T)> {
        Self::open(
            adapter,
            &GrantShape::standard(),
            (driver_case()?, 4_096),
            |store| {
                driver_content(&mut *store)?;
                seed(store)
            },
        )
    }

    /// The driver fixture on `adapter`, unseeded.
    fn plain(adapter: Adapter) -> TestResult<Self> {
        Ok(Self::new(adapter, |_| Ok(()))?.0)
    }

    /// The fixture after a restart: a `SQLite` host is closed and recovered
    /// from its store.
    ///
    /// A Memory store lives only inside its host, so it has no close and
    /// reopen and keeps its host.
    fn restarted(self) -> TestResult<Self> {
        let Self {
            host,
            sqlite,
            case,
            maximum_requests,
            head,
        } = self;
        let host = match &sqlite {
            Some(store) => {
                drop(host);
                store.host(&case, maximum_requests)?
            }
            None => host,
        };
        Ok(Self {
            host,
            sqlite,
            case,
            maximum_requests,
            head,
        })
    }
}

/// The driver fixture on `adapter` with request 1 submitted for private
/// subject data and driven on its host until `until`; and the steps.
fn driven_fixture(
    adapter: Adapter,
    until: impl Fn(&LocalErasureStepV1) -> bool,
) -> TestResult<(Fixture, Vec<LocalErasureStepV1>)> {
    let mut fixture = Fixture::plain(adapter)?;
    submitted(&mut fixture.host, 1, ErasureScopeV1::PrivateSubjectData)?;
    let steps = driven_steps(&mut fixture.host, until)?;
    Ok((fixture, steps))
}

/// The host of [`driven_fixture`], with the `SQLite` store it needs kept
/// alive, and the steps.
fn driven_host(
    adapter: Adapter,
    until: impl Fn(&LocalErasureStepV1) -> bool,
) -> TestResult<(
    ErasureExecutionHostV1,
    Option<LocalStore>,
    Vec<LocalErasureStepV1>,
)> {
    let (fixture, steps) = driven_fixture(adapter, until)?;
    Ok((fixture.host, fixture.sqlite, steps))
}

/// Drive request 1 of the driver fixture on `adapter` for private subject
/// data on one host, and return its receipt and ERS1 history.
fn straight_fixture_run(
    adapter: Adapter,
) -> TestResult<(ErasureReceiptV1, Vec<ErasureReferenceV1>)> {
    let request = request_of(1)?;
    let mut fixture = Fixture::plain(adapter)?;
    submitted(&mut fixture.host, 1, ErasureScopeV1::PrivateSubjectData)?;
    let receipt = finalized(driver().drive(&mut fixture.host, request)?)?;
    Ok((receipt, history(&mut fixture.host, request)?))
}

/// Retain the ELREJ1 of each request of `keys` on `store`.
fn retain_rejections(store: &mut dyn SeedStore, keys: &[u8]) -> TestResult {
    let mut records = Vec::new();
    for key in keys {
        records.push(rejection(*key)?.to_canonical_cbor()?);
    }
    retain_objects(store, &records)
}

/// Retain each of `objects` on `store`.
fn retain_objects(store: &mut dyn SeedStore, objects: &[Vec<u8>]) -> TestResult {
    for object in objects {
        store.retain_erasure_object(object, ERASURE_RETAINED_OBJECT_MAX_BYTES_V1)?;
    }
    Ok(())
}

/// Submit request `key` for `scope` on `host`.
fn submitted(host: &mut ErasureExecutionHostV1, key: u8, scope: ErasureScopeV1) -> TestResult {
    host.command_sender()?
        .submit_local_erasure(&submission(key, scope)?)
        .map_err(fail)?;
    Ok(())
}

/// The receipt a finalize step committed.
fn finalized(step: LocalErasureStepV1) -> TestResult<ErasureReceiptV1> {
    match step {
        LocalErasureStepV1::Finalized(receipt) => Ok(*receipt),
        other => Err(format!("expected a receipt, got {other:?}").into()),
    }
}

/// The ERS1 digests of `request`'s history, newest first.
fn history(
    host: &mut ErasureExecutionHostV1,
    request: ErasureReferenceV1,
) -> TestResult<Vec<ErasureReferenceV1>> {
    Ok(host
        .read_sender()?
        .erasure_state_history(request)?
        .ok_or("request missing")?
        .iter()
        .map(pos_core::ErasureStateV1::state_digest)
        .collect())
}

/// Drive request 1 of `store` for private subject data on one host, and
/// return its receipt and ERS1 history.
fn straight_run(store: &LocalStore) -> TestResult<(ErasureReceiptV1, Vec<ErasureReferenceV1>)> {
    let request = request_of(1)?;
    let mut host = store.host(&driver_case()?, 4_096)?;
    submitted(&mut host, 1, ErasureScopeV1::PrivateSubjectData)?;
    let receipt = finalized(driver().drive(&mut host, request)?)?;
    Ok((receipt, history(&mut host, request)?))
}

/// The steps, the receipt and the ERS1 history of one reopened run.
type ReopenedRun = (
    Vec<LocalErasureStepV1>,
    ErasureReceiptV1,
    Vec<ErasureReferenceV1>,
);

/// Step request 1 of `store` on a host reopened before every step, after
/// `interrupt` ran once on a fresh host before the first step, and return
/// the steps, the receipt and the ERS1 history.
fn reopened_run(
    store: &LocalStore,
    interrupt: impl FnOnce(&mut ErasureExecutionHostV1) -> TestResult,
) -> TestResult<ReopenedRun> {
    let request = request_of(1)?;
    let case = driver_case()?;
    interrupt(&mut store.host(&case, 4_096)?)?;
    let mut steps = Vec::new();
    let driver = driver();
    loop {
        let mut host = store.host(&case, 4_096)?;
        match driver.step(&mut host, request)? {
            LocalErasureStepV1::Idle => break,
            step => steps.push(step),
        }
    }
    let receipt = finalized(steps.last().cloned().ok_or("no step")?)?;
    let mut host = store.host(&case, 4_096)?;
    Ok((steps, receipt, history(&mut host, request)?))
}

/// The class of each acknowledged owner result in `steps`, in order.
fn acknowledged_classes(steps: &[LocalErasureStepV1]) -> TestResult<Vec<&'static str>> {
    let mut classes = Vec::new();
    for step in steps {
        if let LocalErasureStepV1::Acknowledged(result) = step {
            classes.push(class_of(result.command().destruction.owner)?);
        }
    }
    Ok(classes)
}

/// Assert every inventory row of `receipt` carries the replay claim the
/// #185 `ReplayClaimEvaluatorV1` derives for its class and outcome, and
/// `CA(ELD1)` only on backup and timeline-payload rows (ADR-136 §7).
fn assert_evaluated_rows(receipt: &ErasureReceiptV1) -> TestResult {
    let rows = receipt.inventories();
    let positives = receipt
        .acknowledgements()
        .iter()
        .filter(|acknowledgement| {
            acknowledgement.outcome == ErasureAcknowledgementOutcomeV1::Acknowledged
        })
        .map(|acknowledgement| (acknowledgement.target, acknowledgement.owner))
        .collect::<Vec<_>>();
    let mut weakest = ErasureReplayClaimV1::Exact;
    for row in rows
        .artifacts
        .iter()
        .chain(&rows.keys)
        .chain(&rows.replicas)
        .chain(&rows.backups)
    {
        let class = class_of(row.transition.owner)?;
        let positive = positives.contains(&(row.target, row.transition.owner));
        let expected = match (class, positive) {
            ("key-registry", true) => ErasureReplayClaimV1::UnverifiableArtifactsMissing,
            ("client-cache-signal" | "artifact-store" | "managed-report", true) => {
                ErasureReplayClaimV1::ExactAuthoritativeWithRedactedViews
            }
            _ => ErasureReplayClaimV1::Exact,
        };
        assert_eq!(row.transition.from, ErasureReplayClaimV1::Exact, "{class}");
        assert_eq!(row.transition.to, expected, "{class}");
        weakest = weakest.weakened_to(expected);
        let disclosure = if matches!(class, "local-backup-inventory" | "timeline-payload") {
            pos_core::LocalErasureDisclosureV1 {
                ack_class: class.to_owned(),
                policy: LOCAL_ERASURE_POLICY_REFERENCE_V1,
            }
            .reference()?
        } else {
            reference(0)
        };
        assert_eq!(row.retained_disclosure, disclosure, "{class}");
    }
    assert_eq!(receipt.replay_claim(), weakest);
    Ok(())
}

/// Acceptance test 1 (Q16): a full lifecycle on `SQLite`, closed and
/// reopened before every step, commits exactly the ERS1 and ERC1 bytes of
/// an uninterrupted run.
#[test]
fn a_driven_lifecycle_has_identical_bytes_across_close_and_reopen() -> TestResult {
    let (receipt, states) = straight_run(&driver_store()?)?;
    let store = driver_store()?;
    let (steps, reopened, reopened_states) = reopened_run(&store, |host| {
        submitted(host, 1, ErasureScopeV1::PrivateSubjectData)
    })?;
    assert_eq!(reopened.to_canonical_cbor()?, receipt.to_canonical_cbor()?);
    assert_eq!(reopened_states, states);
    // One durable transition per step: authorize, freeze, dispatch, one
    // acknowledgement per owner (keys first, the local replica last), and
    // the receipt.
    assert_eq!(steps[0], LocalErasureStepV1::Authorized);
    assert_eq!(steps[1], LocalErasureStepV1::Frozen);
    assert!(matches!(steps[2], LocalErasureStepV1::Dispatched(_)));
    let mut classes = acknowledged_classes(&steps)?;
    assert_eq!(classes.len(), 5);
    assert_eq!(classes[0], "key-registry");
    assert_eq!(classes[3..], ["local-backup-inventory", "local-replica"]);
    classes[1..3].sort_unstable();
    assert_eq!(classes[1..3], ["client-cache-signal", "timeline-payload"]);
    assert_eq!(steps.len(), 9);
    // `timeline-payload` and the backup are permanent negatives, so the
    // request ends in a partial failure at its attempt's deadline, and is
    // never retried automatically.
    assert_eq!(receipt.lifecycle(), ErasureLifecycleV1::PartialFailure);
    assert_eq!(receipt.issue_position(), LOCAL_ERASURE_ATTEMPT_WINDOW_V1);
    // The destroyed key leaves its evidence missing.
    assert_evaluated_rows(&receipt)?;
    assert_eq!(
        receipt.replay_claim(),
        ErasureReplayClaimV1::UnverifiableArtifactsMissing
    );
    let mut host = store.host(&driver_case()?, 4_096)?;
    assert_eq!(
        driver().step(&mut host, request_of(1)?)?,
        LocalErasureStepV1::Idle
    );
    // The key was destroyed during the request's own access freeze.
    let registry = store.sqlite()?.load_key_registry()?.ok_or("no registry")?;
    assert!(registry.tombstone(subject_key(1)?).is_some());
    Ok(())
}

/// Acceptance test 1 across adapters (Q16): Memory and `SQLite` commit the
/// same receipt except the local-replica row. A Memory store has no file a
/// purge could prove clean, so its replica is the permanent negative.
#[test]
fn memory_and_sqlite_differ_only_in_the_local_replica_row() -> TestResult {
    let (sqlite, _) = straight_run(&driver_store()?)?;
    let mut host = driver_memory_host(&driver_case()?)?;
    let request = request_of(1)?;
    submitted(&mut host, 1, ErasureScopeV1::PrivateSubjectData)?;
    let memory = finalized(driver().drive(&mut host, request)?)?;
    assert_eq!(driver().step(&mut host, request)?, LocalErasureStepV1::Idle);
    for receipt in [&memory, &sqlite] {
        assert_evaluated_rows(receipt)?;
        assert_eq!(
            receipt.replay_claim(),
            ErasureReplayClaimV1::UnverifiableArtifactsMissing
        );
        assert_eq!(receipt.lifecycle(), ErasureLifecycleV1::PartialFailure);
        assert_eq!(receipt.issue_position(), LOCAL_ERASURE_ATTEMPT_WINDOW_V1);
        assert_eq!(receipt.inventories().replicas.len(), 1);
    }
    assert_eq!(memory.frozen_targets(), sqlite.frozen_targets());
    assert_eq!(memory.trust(), sqlite.trust());
    assert_eq!(memory.policy(), sqlite.policy());
    let (memory_rows, sqlite_rows) = (memory.inventories(), sqlite.inventories());
    assert_eq!(memory_rows.artifacts, sqlite_rows.artifacts);
    assert_eq!(memory_rows.keys, sqlite_rows.keys);
    assert_eq!(memory_rows.backups, sqlite_rows.backups);
    // The replica rows differ exactly in the acknowledgement evidence.
    let (memory_replica, sqlite_replica) = (memory_rows.replicas[0], sqlite_rows.replicas[0]);
    assert_ne!(
        memory_replica.transition.acknowledgements,
        sqlite_replica.transition.acknowledgements
    );
    assert_eq!(
        ErasureInventoryResultV1 {
            transition: ErasureArtifactTransitionV1 {
                acknowledgements: sqlite_replica.transition.acknowledgements,
                ..memory_replica.transition
            },
            ..memory_replica
        },
        sqlite_replica
    );
    // So do the acknowledgements: every other one is the same; the replica
    // is negative on Memory and positive on `SQLite`.
    let replica_owner = sqlite_replica.transition.owner;
    let others = |receipt: &ErasureReceiptV1| {
        receipt
            .acknowledgements()
            .iter()
            .filter(|acknowledgement| acknowledgement.owner != replica_owner)
            .copied()
            .collect::<Vec<_>>()
    };
    assert_eq!(others(&memory), others(&sqlite));
    let replica_outcome = |receipt: &ErasureReceiptV1| {
        receipt
            .acknowledgements()
            .iter()
            .find(|acknowledgement| acknowledgement.owner == replica_owner)
            .map(|acknowledgement| acknowledgement.outcome)
    };
    assert_eq!(
        replica_outcome(&memory),
        Some(ErasureAcknowledgementOutcomeV1::Negative)
    );
    assert_eq!(
        replica_outcome(&sqlite),
        Some(ErasureAcknowledgementOutcomeV1::Acknowledged)
    );
    Ok(())
}

/// The ADR-136 §5 positions and pins of `admission`, attempt `ordinal`
/// after `source`.
fn assert_attempt(
    step: &LocalErasureStepV1,
    ordinal: u64,
    source: Option<&ErasureReceiptV1>,
    head: u64,
) -> TestResult {
    let LocalErasureStepV1::Dispatched(admission) = step else {
        return Err(format!("expected a dispatch, got {step:?}").into());
    };
    let (admitted, deadline) = source.map_or((2, LOCAL_ERASURE_ATTEMPT_WINDOW_V1), |receipt| {
        let admitted = receipt.issue_position() + 1;
        (admitted, admitted + LOCAL_ERASURE_ATTEMPT_WINDOW_V1)
    });
    assert_eq!(admission.attempt_ordinal(), ordinal);
    assert_eq!(
        admission.source_receipt(),
        source.map(ErasureReceiptV1::receipt_digest)
    );
    assert_eq!(
        (admission.admitted_position(), admission.deadline_position()),
        (admitted, deadline)
    );
    assert_eq!(admission.policy(), LOCAL_ERASURE_POLICY_REFERENCE_V1);
    assert_eq!(admission.trust(), owned_bundle(&ALL_CLASSES)?.reference()?);
    assert_eq!(
        admission.authorization_provenance(),
        authorization(1, head)?.reference()?
    );
    Ok(())
}

/// Drive request 1 to its first receipt with every step recorded.
fn driven_steps(
    host: &mut ErasureExecutionHostV1,
    until: impl Fn(&LocalErasureStepV1) -> bool,
) -> TestResult<Vec<LocalErasureStepV1>> {
    let request = request_of(1)?;
    let mut steps = Vec::new();
    loop {
        let step = driver().step(host, request)?;
        if step == LocalErasureStepV1::Idle {
            return Ok(steps);
        }
        let done = until(&step);
        steps.push(step);
        if done {
            return Ok(steps);
        }
    }
}

/// A held reader keeps the `SQLite` checkpoint busy: the local replica's
/// purge is then the one transient negative.
fn held_reader(store: &LocalStore) -> TestResult<rusqlite::Connection> {
    let reader = rusqlite::Connection::open(&store.path)?;
    reader.execute_batch("BEGIN")?;
    let timelines: i64 =
        reader.query_row("SELECT count(*) FROM timelines", [], |row| row.get(0))?;
    assert!(timelines > 0);
    Ok(reader)
}

/// Drive `count` attempts of request 1 while a reader holds the store, so
/// every one's replica purge times out: each attempt runs at its §6
/// positions and ends in a partial failure exactly at its deadline.
fn held_attempts(
    store: &LocalStore,
    host: &mut ErasureExecutionHostV1,
    count: u64,
) -> TestResult<Vec<ErasureReceiptV1>> {
    let is_receipt = |step: &LocalErasureStepV1| matches!(step, LocalErasureStepV1::Finalized(_));
    let reader = held_reader(store)?;
    let mut receipts = Vec::new();
    for ordinal in 0..count {
        let steps = driven_steps(host, is_receipt)?;
        let dispatch = steps
            .iter()
            .find(|step| matches!(step, LocalErasureStepV1::Dispatched(_)))
            .ok_or("no dispatch")?;
        assert_attempt(dispatch, ordinal, receipts.last(), store.head)?;
        let LocalErasureStepV1::Dispatched(admission) = dispatch else {
            return Err("no dispatch".into());
        };
        let receipt = finalized(steps.last().cloned().ok_or("no step")?)?;
        assert_eq!(receipt.lifecycle(), ErasureLifecycleV1::PartialFailure);
        assert_eq!(receipt.issue_position(), admission.deadline_position());
        receipts.push(receipt);
    }
    reader.execute_batch("COMMIT")?;
    drop(reader);
    Ok(receipts)
}

/// Acceptance test 4 (Q10): a transient negative is retried automatically,
/// each retry at its §6 positions, every partial failure issues exactly at
/// its deadline, and a retry that succeeds completes the request at its
/// reached position. The retry cap is
/// `acceptance::the_retry_cap_ends_a_transient_failure_in_partial_failure`.
#[test]
fn a_transient_negative_is_retried_until_it_succeeds() -> TestResult {
    let store = driver_store()?;
    let mut host = store.host(&driver_case()?, 4_096)?;
    submitted(&mut host, 1, ErasureScopeV1::ConsentedSharedData)?;
    // Held for attempt 0 and retry 1: both purges time out.
    let receipts = held_attempts(&store, &mut host, 2)?;
    // Released: retry 2 purges the replica and completes the consented
    // request at its one executed obligation past admission.
    let steps = driven_steps(&mut host, |_| false)?;
    assert_attempt(&steps[0], 2, receipts.last(), store.head)?;
    assert_eq!(acknowledged_classes(&steps)?, ["local-replica"]);
    let complete = finalized(steps.last().cloned().ok_or("no step")?)?;
    assert_eq!(complete.lifecycle(), ErasureLifecycleV1::Complete);
    let last = receipts.last().ok_or("no receipt")?;
    assert_eq!(complete.issue_position(), last.issue_position() + 1 + 1);
    assert_eq!(driver().run(&mut host)?, 0);
    drop(host);
    // Every receipt of the three-receipt chain survives the startup sweep.
    assert_sweep_keeps_committed_evidence(&store)
}

/// Acceptance test 4: a consented request whose two owners both succeed on
/// `SQLite` completes in attempt 0 at its reached position.
#[test]
fn a_request_whose_every_owner_succeeds_completes() -> TestResult {
    let store = driver_store()?;
    let mut host = store.host(&driver_case()?, 4_096)?;
    submitted(&mut host, 1, ErasureScopeV1::ConsentedSharedData)?;
    let receipt = finalized(driver().drive(&mut host, request_of(1)?)?)?;
    assert_eq!(receipt.lifecycle(), ErasureLifecycleV1::Complete);
    assert_eq!(receipt.issue_position(), 2 + 2);
    // The cache generation redacts the views; no row discloses an ELD1.
    assert_evaluated_rows(&receipt)?;
    assert_eq!(
        receipt.replay_claim(),
        ErasureReplayClaimV1::ExactAuthoritativeWithRedactedViews
    );
    Ok(())
}

/// The sweep keeps every committed reference and deletes only the
/// unreferenced objects retained beside them.
fn assert_sweep_keeps_committed_evidence(store: &LocalStore) -> TestResult {
    let purpose = LocalErasureSignaturePurposeV1::FreezeAuthorization;
    let stray_result = LocalErasureOwnerResultV1 {
        request: reference(0x33),
        attempt: reference(0x34),
        obligation: reference(0x35),
        command: reference(0x36),
        owner_ref: reference(0x37),
        error: None,
        effect_digest: reference(0x38),
    };
    let stray = vec![
        signature_record(purpose, reference(0x31), &erasure_signer(), 1)?,
        signature_record(
            LocalErasureSignaturePurposeV1::ReceiptBody,
            reference(0x32),
            &erasure_signer(),
            1,
        )?,
        stray_result.to_canonical_cbor()?,
        signature_record(
            LocalErasureSignaturePurposeV1::OwnerResult,
            stray_result.reference()?,
            &erasure_signer(),
            1,
        )?,
        LocalErasureNegativeResultV1 {
            command: reference(0x39),
            owner_ref: reference(0x3a),
            error: ErasureErrorV1::ArtifactDeletionFailed,
        }
        .to_canonical_cbor()?,
    ];
    store.retain(&stray)?;
    let before = {
        let mut host = store.host(&driver_case()?, 4_096)?;
        history(&mut host, request_of(1)?)?
    };
    let mut host = store.host(&driver_case()?, 4_096)?;
    // The retained purpose-0 ELS1 of the committed freeze goes too: the
    // freeze carries its bytes inside ERFA1 and references no ELS1 object.
    assert_eq!(
        LocalErasureDriverV1::sweep(&mut host),
        LocalErasureSweepV1::Swept(stray.len() + 1)
    );
    assert_eq!(
        LocalErasureDriverV1::sweep(&mut host),
        LocalErasureSweepV1::Swept(0)
    );
    drop(host);
    let sqlite = store.sqlite()?;
    for object in &stray {
        let address =
            pos_core::ErasureRetainedObjectV1::new(object, ERASURE_RETAINED_OBJECT_MAX_BYTES_V1)?;
        assert!(ErasurePersistencePortV1::read_object(&sqlite, address.reference()).is_err());
    }
    drop(sqlite);
    // Recovery re-verifies every attempt, acknowledgement and receipt, so
    // none of their evidence was swept.
    let mut host = store.host(&driver_case()?, 4_096)?;
    assert_eq!(history(&mut host, request_of(1)?)?, before);
    Ok(())
}

/// The fixed acceptance store, driven to `until` on one host.
fn driven_until(
    until: impl Fn(&LocalErasureStepV1) -> bool,
) -> TestResult<(LocalStore, Vec<LocalErasureStepV1>)> {
    let store = driver_store()?;
    let steps = {
        let mut host = store.host(&driver_case()?, 4_096)?;
        submitted(&mut host, 1, ErasureScopeV1::PrivateSubjectData)?;
        driven_steps(&mut host, until)?
    };
    Ok((store, steps))
}

/// Acceptance test 6, signer part: the signer signs a freeze only of an
/// authorized request and only over the body its snapshot admits, and only
/// with the key the registry holds for its identity.
#[test]
fn the_signer_signs_a_freeze_only_of_an_authorized_request_and_its_body() -> TestResult {
    for adapter in ADAPTERS {
        let request = request_of(1)?;
        let signer = signer_of(erasure_signer(), 1);
        let fabricated = reference(0x77);
        let refused = Err(ErasureHostErrorV1::AuthorizationDenied);
        // Authorized, not yet frozen: only the body the snapshot admits signs.
        let (mut host, _store, _) =
            driven_host(adapter, |step| *step == LocalErasureStepV1::Authorized)?;
        let freeze_of = |body| LocalErasureSigningRequestV1::FreezeAuthorization { request, body };
        assert_eq!(signer.sign(&mut host, freeze_of(fabricated)), refused);
        let LocalFreezePreparationV1::Sign(body) =
            host.command_sender()?.prepare_local_freeze(request)?
        else {
            return Err("the freeze commits a rejection".into());
        };
        assert!(signer.sign(&mut host, freeze_of(body)).is_ok());
        // A signer whose key the registry does not hold for its identity
        // signs nothing.
        assert_eq!(
            signer_of(rotated_signer(), 1).sign(&mut host, freeze_of(body)),
            refused
        );
        // Once frozen, the request is no longer authorized: even its own body
        // signs no second freeze.
        assert_eq!(
            driver().step(&mut host, request)?,
            LocalErasureStepV1::Frozen
        );
        assert_eq!(signer.sign(&mut host, freeze_of(body)), refused);
    }
    Ok(())
}

/// Acceptance test 6, signer part: an owner result signs only when its
/// ELO1 binds an effect the dispatched command's own class commits, and
/// that effect is committed.
#[test]
fn the_signer_signs_an_owner_result_only_over_its_class_committed_effect() -> TestResult {
    let request = request_of(1)?;
    let signer = signer_of(erasure_signer(), 1);
    let refused = Err(ErasureHostErrorV1::AuthorizationDenied);
    // Dispatched: each owner result is checked against its committed
    // effect.
    let (store, _) = driven_until(|step| matches!(step, LocalErasureStepV1::Dispatched(_)))?;
    let mut host = store.host(&driver_case()?, 4_096)?;
    let backup = command_of(&mut host, request, ErasureInventoryCategoryV1::Backup)?;
    let destruction = backup.destruction;
    let error = ErasureErrorV1::BackupInventoryIncomplete;
    let negative = LocalErasureNegativeResultV1 {
        command: destruction.command,
        owner_ref: destruction.owner,
        error,
    }
    .to_canonical_cbor()?;
    let prepared = PreparedLocalOwnerEffectV1::new(
        LocalOwnerEffectV1::Negative(negative.clone()),
        LocalOwnerResultBindingV1 {
            request,
            attempt: destruction.provenance,
            obligation: destruction.obligation,
            command: destruction.command,
            owner_ref: destruction.owner,
            error: Some(error),
        },
    )?;
    let elo1 = prepared.owner_result();
    // The same owner result naming another effect digest.
    let mut forged = LocalErasureOwnerResultV1::from_canonical_cbor(elo1.canonical_cbor())?;
    forged.effect_digest = reference(0x99);
    store.retain(&[elo1.canonical_cbor().to_vec(), forged.to_canonical_cbor()?])?;
    let owner_result = |owner_result| LocalErasureSigningRequestV1::OwnerResult { owner_result };
    for unsigned in [reference(0x55), elo1.reference(), forged.reference()?] {
        assert_eq!(signer.sign(&mut host, owner_result(unsigned)), refused);
    }
    // An effect the backup owner never commits is refused even when it is
    // retained: a negative code of another class, and another class's
    // positive record.
    let binding = |error| LocalOwnerResultBindingV1 {
        request,
        attempt: destruction.provenance,
        obligation: destruction.obligation,
        command: destruction.command,
        owner_ref: destruction.owner,
        error,
    };
    let foreign_code = ErasureErrorV1::ArtifactDeletionFailed;
    let cross_class = [
        PreparedLocalOwnerEffectV1::new(
            LocalOwnerEffectV1::Negative(
                LocalErasureNegativeResultV1 {
                    command: destruction.command,
                    owner_ref: destruction.owner,
                    error: foreign_code,
                }
                .to_canonical_cbor()?,
            ),
            binding(Some(foreign_code)),
        )?,
        PreparedLocalOwnerEffectV1::new(
            LocalOwnerEffectV1::ReplicaPurge(
                LocalErasureReplicaPurgeV1 {
                    request,
                    command: destruction.command,
                    replica_id: destruction.target.replica_id,
                }
                .to_canonical_cbor()?,
            ),
            binding(None),
        )?,
    ];
    for prepared in &cross_class {
        let effect = prepared.effect_object().ok_or("no effect record")?;
        store.retain(&[
            effect.canonical_cbor().to_vec(),
            prepared.owner_result().canonical_cbor().to_vec(),
        ])?;
        assert_eq!(
            signer.sign(&mut host, owner_result(prepared.owner_result().reference())),
            refused
        );
    }
    // Once its ELNEG1 is committed, the backup owner's own ELO1 signs.
    store.retain(&[negative])?;
    assert!(signer
        .sign(&mut host, owner_result(elo1.reference()))
        .is_ok());
    Ok(())
}

/// Acceptance test 6, signer part: only the ERCB1 of the committed record
/// signs, and an owner result of a closed attempt is not dispatched.
#[test]
fn the_signer_signs_only_the_committed_receipt_body() -> TestResult {
    for adapter in ADAPTERS {
        let request = request_of(1)?;
        let signer = signer_of(erasure_signer(), 1);
        let fabricated = reference(0x77);
        let refused = Err(ErasureHostErrorV1::AuthorizationDenied);
        let owner_result =
            |owner_result| LocalErasureSigningRequestV1::OwnerResult { owner_result };
        // Every command acknowledged: only the ERCB1 of the committed record
        // signs.
        let (mut host, _store, steps) = driven_host(adapter, |step| {
            matches!(step, LocalErasureStepV1::Acknowledged(result)
                if result.command().destruction.category == ErasureInventoryCategoryV1::Replica)
        })?;
        assert_eq!(steps.len(), 8);
        let LocalErasureStepV1::Acknowledged(replica) = &steps[7] else {
            return Err("no replica acknowledgement".into());
        };
        let receipt_of = |body| LocalErasureSigningRequestV1::ReceiptBody { request, body };
        assert_eq!(signer.sign(&mut host, receipt_of(fabricated)), refused);
        // An owner result of the closed attempt is no longer dispatched.
        let finalized_receipt = finalized(driver().step(&mut host, request)?)?;
        assert_eq!(
            signer.sign(&mut host, owner_result(replica.owner_result())),
            Err(ErasureHostErrorV1::Conflict)
        );
        assert_eq!(
            finalized_receipt.lifecycle(),
            ErasureLifecycleV1::PartialFailure
        );
    }
    Ok(())
}

/// The driver refuses to advance a request it cannot sign for: a refused
/// signature is prepared again at most `max_reprepare` times and then
/// defers the step, committing nothing.
#[test]
fn a_refused_signature_defers_the_step() -> TestResult {
    for adapter in ADAPTERS {
        let (mut host, _store, _) =
            driven_host(adapter, |step| *step == LocalErasureStepV1::Authorized)?;
        let foreign = LocalErasureDriverV1::new(signer_of(rotated_signer(), 1));
        assert_eq!(
            foreign.drive(&mut host, request_of(1)?),
            Err(ErasureHostErrorV1::AuthorizationDenied)
        );
        assert_eq!(foreign.run(&mut host)?, 1);
        assert_eq!(
            lifecycle(&mut host, request_of(1)?)?,
            ErasureLifecycleV1::Authorized
        );
        // The deployment's own signer then freezes it.
        assert_eq!(
            driver().step(&mut host, request_of(1)?)?,
            LocalErasureStepV1::Frozen
        );
    }
    Ok(())
}

/// `advance` commits one transition per call, in the order `step` would,
/// and answers `Idle` once nothing is due (owner decision D7 on #1413).
#[test]
fn advance_commits_one_transition_per_call_until_idle() -> TestResult {
    for adapter in ADAPTERS {
        let (receipt, states) = straight_fixture_run(adapter)?;
        let Fixture {
            mut host,
            sqlite: _store,
            ..
        } = Fixture::plain(adapter)?;
        assert_eq!(
            driver().advance(&mut host)?,
            LocalErasureAdvanceV1 {
                step: LocalErasureStepV1::Idle,
                deferred: Vec::new()
            }
        );
        submitted(&mut host, 1, ErasureScopeV1::PrivateSubjectData)?;
        let mut steps = Vec::new();
        loop {
            let advanced = driver().advance(&mut host)?;
            assert!(advanced.deferred.is_empty());
            match advanced.step {
                LocalErasureStepV1::Idle => break,
                step => steps.push(step),
            }
        }
        assert_eq!(steps[0], LocalErasureStepV1::Authorized);
        assert_eq!(steps[1], LocalErasureStepV1::Frozen);
        let advanced = finalized(steps.last().cloned().ok_or("no step")?)?;
        assert_eq!(advanced.to_canonical_cbor()?, receipt.to_canonical_cbor()?);
        assert_eq!(history(&mut host, request_of(1)?)?, states);
    }
    Ok(())
}

/// `advance` passes over a request whose step fails and commits nothing
/// for it; a later call with the deployment's signer resumes it.
#[test]
fn advance_passes_over_a_request_it_cannot_step() -> TestResult {
    for adapter in ADAPTERS {
        let (mut host, _store, _) =
            driven_host(adapter, |step| *step == LocalErasureStepV1::Authorized)?;
        let foreign = LocalErasureDriverV1::new(signer_of(rotated_signer(), 1));
        assert_eq!(
            foreign.advance(&mut host)?,
            LocalErasureAdvanceV1 {
                step: LocalErasureStepV1::Idle,
                deferred: vec![request_of(1)?]
            }
        );
        assert_eq!(
            lifecycle(&mut host, request_of(1)?)?,
            ErasureLifecycleV1::Authorized
        );
        assert_eq!(
            driver().advance(&mut host)?,
            LocalErasureAdvanceV1 {
                step: LocalErasureStepV1::Frozen,
                deferred: Vec::new()
            }
        );
    }
    Ok(())
}

/// Acceptance test 5 through the driver: a submitted request whose ERAZ1
/// no longer verifies is rejected under a retained ELREJ1, and an expired
/// TPS1 defers authorization without committing anything.
#[test]
fn the_driver_rejects_an_unverifiable_authorization_and_defers_an_expired_one() -> TestResult {
    let store = driver_store()?;
    submitted(
        &mut store.host(&driver_case()?, 4_096)?,
        1,
        ErasureScopeV1::PrivateSubjectData,
    )?;
    let request = request_of(1)?;
    // An expired TPS1 closes new admissions: the step fails and the
    // request stays submitted.
    let mut expired = driver_case()?;
    expired.clock = after_trust_expiry;
    let mut host = store.host(&expired, 4_096)?;
    assert_eq!(
        driver().step(&mut host, request),
        Err(ErasureHostErrorV1::RecoveryUnavailable)
    );
    assert_eq!(
        lifecycle(&mut host, request)?,
        ErasureLifecycleV1::Submitted
    );
    drop(host);
    // A composition whose root grant is another one cannot verify the
    // request's ERAZ1, so the driver rejects it at the authorize stage.
    let mut regranted = driver_case()?;
    regranted.principal_grant = Hash::from_bytes([0x7e; 32]);
    let mut host = store.host(&regranted, 4_096)?;
    assert_eq!(
        driver().drive(&mut host, request)?,
        LocalErasureStepV1::Rejected
    );
    let rejection = LocalErasureRejectionV1 {
        request,
        error: ErasureErrorV1::Unauthorized,
    };
    // The committed ERS1 is the core rejection record over `CA(ELREJ1)`.
    let committed = host
        .read_sender()?
        .erasure_state(request)?
        .ok_or("request missing")?
        .state()
        .clone();
    assert_eq!(committed.lifecycle(), ErasureLifecycleV1::Rejected);
    let recorded = pos_core::ErasureAuthorizationRejectionV1::new(
        pos_core::ErasureAuthorizationRejectionInputV1 {
            request,
            authorization_provenance: rejection.reference()?,
        },
    )?;
    assert_eq!(committed.provenance(), recorded.reference());
    // An exact retry reproduces the committed rejection and commits nothing.
    assert_eq!(
        host.command_sender()?
            .reject_erasure_request(request, rejection.reference()?)?,
        committed
    );
    assert_eq!(driver().step(&mut host, request)?, LocalErasureStepV1::Idle);
    assert_eq!(history(&mut host, request)?.len(), 2);
    drop(host);
    assert!(
        ErasurePersistencePortV1::read_object(&store.sqlite()?, rejection.reference()?).is_ok()
    );
    Ok(())
}

/// Acceptance test 7: a crash after the ERQ1 CAS, between an ELS1 and its
/// lifecycle command, between the pending key-destruction phase and the
/// tombstone, and between an owner effect with its ELO1 and the
/// acknowledgement each resume to exactly the bytes of an uninterrupted
/// run, and so does a duplicated acknowledgement (acceptance test 4).
#[test]
fn every_crash_window_resumes_to_identical_bytes() -> TestResult {
    let (receipt, states) = straight_run(&driver_store()?)?;
    let request = request_of(1)?;
    let signer = signer_of(erasure_signer(), 1);
    // Between a purpose-0 ELS1 and the freeze.
    let interrupted = |crash: &dyn Fn(&mut ErasureExecutionHostV1) -> TestResult| {
        let store = driver_store()?;
        let (_, resumed, resumed_states) = reopened_run(&store, |host| {
            submitted(host, 1, ErasureScopeV1::PrivateSubjectData)?;
            crash(host)
        })?;
        assert_eq!(resumed.to_canonical_cbor()?, receipt.to_canonical_cbor()?);
        assert_eq!(resumed_states, states);
        TestResult::Ok(())
    };
    interrupted(&|host: &mut ErasureExecutionHostV1| {
        driver().step(host, request)?;
        let LocalFreezePreparationV1::Sign(body) =
            host.command_sender()?.prepare_local_freeze(request)?
        else {
            return Err("the freeze commits a rejection".into());
        };
        signer.sign(
            host,
            LocalErasureSigningRequestV1::FreezeAuthorization { request, body },
        )?;
        Ok(())
    })?;
    // Between the pending key-destruction phase and its tombstone.
    interrupted(&|host: &mut ErasureExecutionHostV1| {
        for _ in 0..3 {
            driver().step(host, request)?;
        }
        let key = command_of(host, request, ErasureInventoryCategoryV1::Key)?;
        host.command_sender()?.begin_key_registry_destruction(
            erasure_host_timeline()?,
            subject_key_destruction(Hash::from_bytes(key.destruction.command.digest()))?,
        )?;
        Ok(())
    })?;
    // Between an owner effect with its ELO1 and the acknowledgement, and
    // between a purpose-1 ELS1 and the acknowledgement.
    interrupted(&|host: &mut ErasureExecutionHostV1| {
        for _ in 0..3 {
            driver().step(host, request)?;
        }
        let key = command_of(host, request, ErasureInventoryCategoryV1::Key)?;
        let executed = LocalErasureExecutorV1.execute(&key, host).map_err(fail)?;
        signer.sign(
            host,
            LocalErasureSigningRequestV1::OwnerResult {
                owner_result: executed.owner_result(),
            },
        )?;
        Ok(())
    })?;
    // A duplicated acknowledgement commits nothing new.
    interrupted(&|host: &mut ErasureExecutionHostV1| {
        let mut acknowledged = None;
        for _ in 0..4 {
            if let LocalErasureStepV1::Acknowledged(result) = driver().step(host, request)? {
                acknowledged = Some(*result);
            }
        }
        let key = acknowledged.ok_or("no acknowledgement")?;
        let evidence = signer.sign(
            host,
            LocalErasureSigningRequestV1::OwnerResult {
                owner_result: key.owner_result(),
            },
        )?;
        let destruction = key.command().destruction;
        host.command_sender()?.acknowledge_erasure(
            request,
            ErasureAcknowledgementV1 {
                obligation: destruction.obligation,
                target: destruction.target,
                owner: destruction.owner,
                evidence,
                outcome: ErasureAcknowledgementOutcomeV1::Acknowledged,
            },
        )?;
        Ok(())
    })
}

/// ADR-136 §5 rotation rule (Q12): a routine rotation is refused while a
/// request's active attempt pins the old bundle, a compromise is accepted,
/// and once the attempt closed the routine rotation is accepted too.
#[test]
fn a_routine_rotation_waits_for_every_pin_and_a_compromise_does_not() -> TestResult {
    let (store, _) = driven_until(|step| matches!(step, LocalErasureStepV1::Dispatched(_)))?;
    let rotated = rotated_bundle(&store)?;
    let routine = Case::signed(&rotated, &bundle_root(), &[])?;
    assert_eq!(
        routine.refusal(&mut store.sqlite()?),
        Some(LocalErasureCompositionErrorV1::BundleMismatch)
    );
    let old_signer = owned_bundle(&ALL_CLASSES)?.signer_key_id;
    let compromise = Case::signed(&rotated, &bundle_root(), &[old_signer.as_str()])?;
    assert!(compromise.compose(&mut store.sqlite()?).is_ok());
    // A request whose attempt closed under the old bundle pins nothing, and
    // the routine rotation composes. Registering the rotated signer makes it
    // the registry's active role-2 key, so the old signer can sign no more:
    // the attempt closes before the rotation is registered.
    let (closed, _) = driven_until(|step| matches!(step, LocalErasureStepV1::Finalized(_)))?;
    let mut host = closed.host(&driver_case()?, 4_096)?;
    assert_eq!(
        lifecycle(&mut host, request_of(1)?)?,
        ErasureLifecycleV1::PartialFailure
    );
    drop(host);
    let rotated = rotated_bundle(&closed)?;
    assert!(Case::signed(&rotated, &bundle_root(), &[])?
        .compose(&mut closed.sqlite()?)
        .is_ok());
    Ok(())
}

/// Q13: a startup sweep that would read more than 4,096 objects of one tag
/// is skipped, and startup goes on.
#[test]
fn an_overflowing_sweep_is_skipped() -> TestResult {
    let mut stray = Vec::with_capacity(4_097);
    for index in 0..4_097_u32 {
        let mut digest = [0xd0; 32];
        digest[..4].copy_from_slice(&index.to_be_bytes());
        stray.push(
            LocalErasureSignatureV1 {
                purpose: LocalErasureSignaturePurposeV1::ReceiptBody,
                signed_digest: ErasureReferenceV1::from_digest(digest),
                signer_identity: LocalErasureSignerIdentityV1 {
                    owner_id: SIGNER_OWNER.as_bytes().to_vec(),
                    epoch: 1,
                },
                signature: [0; 64],
            }
            .to_canonical_cbor()?,
        );
    }
    let (store, _) = memory_store(&stray)?;
    let mut host = memory_host(store, &driver_case()?)?;
    assert_eq!(
        LocalErasureDriverV1::sweep(&mut host),
        LocalErasureSweepV1::Skipped
    );
    assert_eq!(driver().run(&mut host)?, 0);
    Ok(())
}

// ---------------------------------------------------------------------------
// ADR-138 §5 and §7: the `export-recipient` owner withdraws the grantee's
// publication at the host seam (acceptance tests 1, 3, 6 and 7, and ADR-136
// acceptance test 3 as ADR-138 §2 amends it; #1446).
// ---------------------------------------------------------------------------

use pos_core::LocalErasureRecipientExportWithdrawalV1;
use pos_store::sqlite::{RecipientExportPublicationErrorV1, RecipientKeyOwnerV1};

/// The `export-recipient` owner of the fixture store.
fn export_owner() -> TestResult<ErasureReferenceV1> {
    Ok(pos_core::local_erasure_owner_ref_v1(
        ErasureReferenceV1::from_digest(STORE_IDENTITY),
        u64::from(ErasureInventoryCategoryV1::Artifact),
        "export-recipient",
    )?)
}

impl PublishedExport {
    /// A fresh custody handle on the grantee's private directory.
    fn custody(&self) -> TestResult<RecipientKeyOwnerV1> {
        Ok(RecipientKeyOwnerV1::open(&self.private, self.grantee)?)
    }

    /// The grantee's recipient owner.
    fn grantee_owner(&self) -> TestResult<OwnerIdV1> {
        pos_core::recipient_owner_id_from_grantee(self.grantee).map_err(fail)
    }

    /// The stored ciphertext, `recipient-export-<hex>.trx1`.
    fn final_path(&self) -> std::path::PathBuf {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let hex: String = self
            .export_id
            .iter()
            .flat_map(|byte| [HEX[usize::from(byte >> 4)], HEX[usize::from(byte & 0x0f)]])
            .map(char::from)
            .collect();
        self.private.join(format!("recipient-export-{hex}.trx1"))
    }

    /// Whether a serving read of `store` refuses the export as unavailable.
    fn unavailable(&self, store: &LocalStore) -> TestResult<bool> {
        Ok(matches!(
            store
                .sqlite()?
                .read_recipient_export(&self.custody()?, self.export_id),
            Err(RecipientExportPublicationErrorV1::ArtifactUnavailable)
        ))
    }
}

impl LocalStore {
    /// Compose `case` and recover a host over the store with `custody`
    /// attached at composition, as the composition root that serves
    /// recipient export does (ADR-138 §4).
    fn custody_host(
        &self,
        case: &Case,
        custody: Vec<RecipientKeyOwnerV1>,
    ) -> TestResult<ErasureExecutionHostV1> {
        let composition = {
            let mut store = self.sqlite()?;
            case.compose(&mut store).map_err(fail)?
        };
        let mut store = SqliteStore::open(&self.path)?;
        store.attach_recipient_custody(custody)?;
        Ok(
            ErasureExecutionHostV1::recover_sqlite_fixture_with_authority(
                store,
                &composition,
                ErasureRecoveryLimitsV1::from_maximum_requests(4_096)?,
            )?,
        )
    }
}

/// The driver store with one recipient export of the actor's owned
/// Timeline to `other_actor()`.
fn export_store() -> TestResult<(LocalStore, PublishedExport)> {
    let store = driver_store()?;
    let export = publish_export(&store, memory_owned_timeline(), other_actor())?;
    Ok((store, export))
}

/// Submit consented request 1 on `host` and step it until its attempt 0
/// is dispatched.
fn dispatch_consented(host: &mut ErasureExecutionHostV1) -> TestResult {
    submitted(host, 1, ErasureScopeV1::ConsentedSharedData)?;
    let steps = driven_steps(host, |step| {
        matches!(step, LocalErasureStepV1::Dispatched(_))
    })?;
    assert!(matches!(
        steps.last(),
        Some(LocalErasureStepV1::Dispatched(_))
    ));
    Ok(())
}

/// The export store with consented request 1 dispatched, and its
/// dispatched `export-recipient` command.
fn dispatched_export_store() -> TestResult<(LocalStore, PublishedExport, ErasureOwnerCommandV1)> {
    let (store, export) = export_store()?;
    let mut host = store.host(&driver_case()?, 4_096)?;
    dispatch_consented(&mut host)?;
    let owner = export_owner()?;
    let command = host
        .command_sender()?
        .dispatched_owner_commands(request_of(1)?)?
        .into_iter()
        .find(|command| command.destruction.owner == owner)
        .ok_or("no dispatched export-recipient command")?;
    Ok((store, export, command))
}

/// The `export-recipient` owner result among `results`.
fn export_result(results: &[ErasureOwnerResultV1]) -> TestResult<ErasureOwnerResultV1> {
    let owner = export_owner()?;
    Ok(*results
        .iter()
        .find(|result| result.command().destruction.owner == owner)
        .ok_or("no export-recipient owner result")?)
}

/// Replay request 1 on `host` and return its `export-recipient` owner
/// result.
fn replayed_export(host: &mut ErasureExecutionHostV1) -> TestResult<ErasureOwnerResultV1> {
    export_result(&LocalErasureExecutorV1::replay(host, request_of(1)?).map_err(fail)?)
}

/// The ELXW1 of `command` over the withdrawal row of `export`, built
/// independently from the row's captured fields.
fn expected_elxw1(
    store: &LocalStore,
    export: &PublishedExport,
    command: &ErasureOwnerCommandV1,
) -> TestResult<LocalErasureRecipientExportWithdrawalV1> {
    let (length, digest, directory, final_identity): (i64, Vec<u8>, Vec<u8>, Vec<u8>) =
        rusqlite::Connection::open(&store.path)?.query_row(
            "SELECT ciphertext_length, ciphertext_digest, directory_identity, final_identity
             FROM recipient_export_withdrawals_v1 WHERE export_id = ?1",
            rusqlite::params![export.export_id.as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )?;
    Ok(LocalErasureRecipientExportWithdrawalV1 {
        request: command.request,
        command: command.destruction.command,
        export_id: export.export_id,
        timeline_id: memory_owned_timeline(),
        grantee_owner: export.grantee_owner()?,
        ciphertext_digest: Hash::from_bytes(digest.as_slice().try_into()?),
        ciphertext_length: u64::try_from(length)?,
        directory_identity: directory.as_slice().try_into()?,
        final_identity: final_identity.as_slice().try_into()?,
    })
}

/// The positive ELO1 binding of `command`.
const fn positive_binding(command: &ErasureOwnerCommandV1) -> LocalOwnerResultBindingV1 {
    LocalOwnerResultBindingV1 {
        request: command.request,
        attempt: command.destruction.provenance,
        obligation: command.destruction.obligation,
        command: command.destruction.command,
        owner_ref: command.destruction.owner,
        error: None,
    }
}

/// `record` and the ELO1 of `binding` over it.
fn prepared_withdrawal(
    record: &LocalErasureRecipientExportWithdrawalV1,
    binding: LocalOwnerResultBindingV1,
) -> TestResult<PreparedLocalOwnerEffectV1> {
    Ok(PreparedLocalOwnerEffectV1::new(
        LocalOwnerEffectV1::RecipientExportWithdrawal(record.to_canonical_cbor()?),
        binding,
    )?)
}

/// Retain the effect record and ELO1 of `prepared` without committing
/// either, and return the ELO1 address.
fn retain_prepared(
    store: &LocalStore,
    prepared: &PreparedLocalOwnerEffectV1,
) -> TestResult<ErasureReferenceV1> {
    let effect = prepared.effect_object().ok_or("no effect record")?;
    store.retain(&[
        effect.canonical_cbor().to_vec(),
        prepared.owner_result().canonical_cbor().to_vec(),
    ])?;
    Ok(prepared.owner_result().reference())
}

/// Ask the fixture signer, on a host reopened over `store`, to sign the
/// owner result `owner_result`.
fn sign_owner_result(
    store: &LocalStore,
    owner_result: ErasureReferenceV1,
) -> TestResult<Result<ErasureReferenceV1, ErasureHostErrorV1>> {
    let signer = signer_of(erasure_signer(), 1);
    let mut host = store.host(&driver_case()?, 4_096)?;
    let answer = signer.sign(
        &mut host,
        LocalErasureSigningRequestV1::OwnerResult { owner_result },
    );
    Ok(answer)
}

/// ADR-138 acceptance test 1, and ADR-136 acceptance test 3 as ADR-138 §2
/// amends it: the grantee's publication of an affected Timeline is one
/// `export-recipient` obligation, positive after its recipient-export
/// withdrawal. The driven request completes, its ELO1 binds `CA(ELXW1)`,
/// the catalog row and the stored ciphertext are gone, no serving read
/// returns the export, and the committed bytes read back the same after the
/// store is closed and reopened.
#[test]
fn a_consented_erasure_withdraws_the_grantee_export_positively() -> TestResult {
    let (store, export) = export_store()?;
    let steps = {
        let mut host = store.custody_host(&driver_case()?, vec![export.custody()?])?;
        submitted(&mut host, 1, ErasureScopeV1::ConsentedSharedData)?;
        driven_steps(&mut host, |_| false)?
    };
    let receipt = finalized(steps.last().cloned().ok_or("no step")?)?;
    assert_eq!(receipt.lifecycle(), ErasureLifecycleV1::Complete);
    assert_evaluated_rows(&receipt)?;
    let mut classes = acknowledged_classes(&steps)?;
    classes.sort_unstable();
    assert_eq!(
        classes,
        ["client-cache-signal", "export-recipient", "local-replica"]
    );
    let mut acknowledged = Vec::new();
    for step in &steps {
        if let LocalErasureStepV1::Acknowledged(result) = step {
            acknowledged.push(**result);
        }
    }
    let result = export_result(&acknowledged)?;
    assert_eq!(result.error(), None);
    let elo1 = store.elo1(&result)?;
    let elxw1 =
        LocalErasureRecipientExportWithdrawalV1::from_canonical_cbor(&store.effect(&elo1)?)?;
    assert_eq!(elxw1, expected_elxw1(&store, &export, result.command())?);
    assert_eq!(elxw1.reference()?, elo1.effect_digest);
    // The withdrawn row records the disposition and its first ELO1.
    let (disposition, committed_elo1): (Vec<u8>, Vec<u8>) =
        rusqlite::Connection::open(&store.path)?.query_row(
            "SELECT disposition, committed_elo1 FROM recipient_export_withdrawals_v1
             WHERE export_id = ?1",
            rusqlite::params![export.export_id.as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
    assert_eq!(disposition, elo1.effect_digest.digest().to_vec());
    assert_eq!(committed_elo1, result.owner_result().digest().to_vec());
    // The catalog row and the stored ciphertext are gone, and no serving
    // read returns the export.
    assert!(store
        .sqlite()?
        .recipient_export_publications(&[memory_owned_timeline()], 4)?
        .is_empty());
    assert!(!export.final_path().exists());
    assert!(export.unavailable(&store)?);
    // Each read reopens the store: the committed bytes are unchanged.
    assert_eq!(store.effect(&elo1)?, elxw1.to_canonical_cbor()?);
    assert_eq!(
        ErasurePersistencePortV1::read_object(&store.sqlite()?, result.owner_result())?,
        elo1.to_canonical_cbor()?
    );
    Ok(())
}

/// ADR-138 acceptance tests 3 (a crash after T3) and 7: a replay after a
/// committed positive ELO1 commits it again byte for byte, also on a host
/// restarted without custody, and once acknowledged the command is not
/// dispatched again.
#[test]
fn a_replay_after_a_committed_withdrawal_commits_the_same_owner_result() -> TestResult {
    let (store, export, _) = dispatched_export_store()?;
    let case = driver_case()?;
    let request = request_of(1)?;
    let committed = {
        let mut host = store.custody_host(&case, vec![export.custody()?])?;
        let results = LocalErasureExecutorV1::replay(&mut host, request).map_err(fail)?;
        assert_eq!(
            LocalErasureExecutorV1::replay(&mut host, request).map_err(fail)?,
            results
        );
        export_result(&results)?
    };
    assert_eq!(committed.error(), None);
    let mut host = store.host(&case, 4_096)?;
    assert_eq!(replayed_export(&mut host)?, committed);
    let owner = export_owner()?;
    let steps = driven_steps(&mut host, |step| {
        matches!(
            step,
            LocalErasureStepV1::Acknowledged(result)
                if result.command().destruction.owner == owner
        )
    })?;
    assert!(matches!(
        steps.last(),
        Some(LocalErasureStepV1::Acknowledged(result)) if **result == committed
    ));
    assert!(host
        .command_sender()?
        .dispatched_owner_commands(request)?
        .iter()
        .all(|command| command.destruction.owner != owner));
    Ok(())
}

/// ADR-138 acceptance test 7 and §7: without custody the withdrawal is a
/// negative result and the export stays retracted, never served; replaying
/// that unacknowledged negative on a host restarted with custody re-executes
/// the command and commits a positive owner result of the same attempt,
/// which signs and completes the request.
#[test]
fn an_unacknowledged_negative_re_executes_and_turns_positive_with_custody() -> TestResult {
    let (store, export, command) = dispatched_export_store()?;
    let case = driver_case()?;
    let negative = replayed_export(&mut store.host(&case, 4_096)?)?;
    assert_eq!(
        negative.error(),
        Some(ErasureErrorV1::ArtifactDeletionFailed)
    );
    assert_eq!(*negative.command(), command);
    assert!(export.final_path().exists());
    assert!(export.unavailable(&store)?);
    let mut host = store.custody_host(&case, vec![export.custody()?])?;
    let positive = replayed_export(&mut host)?;
    assert_eq!(positive.error(), None);
    assert_eq!(*positive.command(), command);
    assert_ne!(positive.owner_result(), negative.owner_result());
    assert!(!export.final_path().exists());
    let signer = signer_of(erasure_signer(), 1);
    for result in [negative, positive] {
        assert!(signer
            .sign(
                &mut host,
                LocalErasureSigningRequestV1::OwnerResult {
                    owner_result: result.owner_result(),
                },
            )
            .is_ok());
    }
    let receipt = finalized(driver().drive(&mut host, request_of(1)?)?)?;
    assert_eq!(receipt.lifecycle(), ErasureLifecycleV1::Complete);
    Ok(())
}

/// ADR-138 acceptance test 7, §7 and the #1446 journal: a target that names
/// no publication, a publication of a Timeline outside the request's scope
/// and a malformed catalog row each resolve to nothing, so the command is
/// the permanent negative `ArtifactDeletionFailed` and nothing is deleted.
#[test]
fn an_unresolvable_export_target_is_a_permanent_negative() -> TestResult {
    let outside = TimelineId::new().to_string();
    for tamper in [
        "DELETE FROM recipient_export_catalog_v1".to_owned(),
        format!("UPDATE recipient_export_catalog_v1 SET timeline_id = '{outside}'"),
        "UPDATE recipient_export_catalog_v1 SET owner_id = ''".to_owned(),
    ] {
        let (store, export, _) = dispatched_export_store()?;
        rusqlite::Connection::open(&store.path)?.execute_batch(&tamper)?;
        let mut host = store.custody_host(&driver_case()?, vec![export.custody()?])?;
        assert_eq!(
            replayed_export(&mut host)?.error(),
            Some(ErasureErrorV1::ArtifactDeletionFailed),
            "{tamper}"
        );
        assert!(export.final_path().exists(), "{tamper}");
    }
    Ok(())
}

/// ADR-138 acceptance test 3: a crash after T1, after the unlink or after
/// T2 leaves a retracted export no serving read returns, and the replay
/// completes the withdrawal with exactly the ELXW1 and ELO1 an uninterrupted
/// run computes from the recorded capture.
///
/// Before T2 the owner step must still run, and it accepts an absent name
/// only through the captured directory's custody (§5): a replay on a host
/// restarted without that custody is negative until custody is attached.
/// After T2 the file work is done, so the replay completes without custody.
#[test]
fn a_crash_inside_a_withdrawal_completes_with_identical_bytes() -> TestResult {
    for crash in ["after T1", "after the unlink", "after T2"] {
        let (store, export, command) = dispatched_export_store()?;
        {
            let mut sqlite = store.sqlite()?;
            sqlite.attach_recipient_custody(vec![export.custody()?])?;
            sqlite.begin_recipient_export_withdrawal(export.export_id, &export.grantee_owner()?)?;
            if crash == "after the unlink" {
                std::fs::remove_file(export.final_path())?;
            }
            if crash == "after T2" {
                sqlite.delete_recipient_export_ciphertext(export.export_id)?;
            }
        }
        assert!(export.unavailable(&store)?, "{crash}");
        let without_custody = replayed_export(&mut store.host(&driver_case()?, 4_096)?)?;
        let result = if crash == "after T2" {
            without_custody
        } else {
            assert_eq!(
                without_custody.error(),
                Some(ErasureErrorV1::ArtifactDeletionFailed),
                "{crash}"
            );
            replayed_export(&mut store.custody_host(&driver_case()?, vec![export.custody()?])?)?
        };
        let expected = prepared_withdrawal(
            &expected_elxw1(&store, &export, &command)?,
            positive_binding(&command),
        )?;
        assert_eq!(result.error(), None, "{crash}");
        assert_eq!(
            result.owner_result(),
            expected.owner_result().reference(),
            "{crash}"
        );
        assert_eq!(
            store.effect(&store.elo1(&result)?)?,
            expected.effect_object().ok_or("no ELXW1")?.canonical_cbor(),
            "{crash}"
        );
        assert!(!export.final_path().exists(), "{crash}");
    }
    Ok(())
}

/// ADR-138 acceptance test 6: the signer signs the committed positive ELO1,
/// and refuses an ELO1 bound to another attempt and, while the row's
/// disposition names it, an ELXW1 whose recomputed `ELXR1` is not the row's
/// target, one whose Timeline lies outside the request's scope, and other
/// ELXW1 bytes stored at the disposition's address.
#[test]
fn the_signer_signs_a_withdrawal_only_bound_to_its_recorded_disposition() -> TestResult {
    let (store, export, command) = dispatched_export_store()?;
    let committed =
        replayed_export(&mut store.custody_host(&driver_case()?, vec![export.custody()?])?)?;
    assert_eq!(committed.error(), None);
    assert!(sign_owner_result(&store, committed.owner_result())?.is_ok());
    let recorded = expected_elxw1(&store, &export, &command)?;
    let disposition = recorded.reference()?;
    let denied = Err(ErasureHostErrorV1::AuthorizationDenied);
    // An ELO1 of another attempt answers no dispatched command.
    let other_attempt = prepared_withdrawal(
        &recorded,
        LocalOwnerResultBindingV1 {
            attempt: reference(0x5a),
            ..positive_binding(&command)
        },
    )?;
    assert_eq!(
        sign_owner_result(&store, retain_prepared(&store, &other_attempt)?)?,
        Err(ErasureHostErrorV1::Conflict)
    );
    let connection = rusqlite::Connection::open(&store.path)?;
    let set_disposition = |digest: ErasureReferenceV1| {
        connection.execute(
            "UPDATE recipient_export_withdrawals_v1 SET disposition = ?1",
            rusqlite::params![digest.digest().as_slice()],
        )
    };
    // Each forged ELXW1 breaks one rule while the row names it.
    for forged in [
        LocalErasureRecipientExportWithdrawalV1 {
            export_id: [0x99; 16],
            ..recorded
        },
        LocalErasureRecipientExportWithdrawalV1 {
            timeline_id: TimelineId::new(),
            ..recorded
        },
    ] {
        let owner_result = retain_prepared(
            &store,
            &prepared_withdrawal(&forged, positive_binding(&command))?,
        )?;
        set_disposition(forged.reference()?)?;
        assert_eq!(sign_owner_result(&store, owner_result)?, denied);
        set_disposition(disposition)?;
    }
    // Other ELXW1 bytes at the disposition's address are no evidence: the
    // impostor's ELO1 and the committed one are both refused until the
    // address holds its own record again.
    let impostor = LocalErasureRecipientExportWithdrawalV1 {
        ciphertext_length: recorded.ciphertext_length + 1,
        ..recorded
    };
    let owner_result = retain_prepared(
        &store,
        &prepared_withdrawal(&impostor, positive_binding(&command))?,
    )?;
    let set_evidence = |record: &LocalErasureRecipientExportWithdrawalV1| -> TestResult<usize> {
        Ok(connection.execute(
            "UPDATE erasure_evidence SET object_cbor = ?1 WHERE reference_digest = ?2",
            rusqlite::params![record.to_canonical_cbor()?, disposition.digest().as_slice()],
        )?)
    };
    set_evidence(&impostor)?;
    assert_eq!(sign_owner_result(&store, owner_result)?, denied);
    assert_eq!(sign_owner_result(&store, committed.owner_result())?, denied);
    set_evidence(&recorded)?;
    assert!(sign_owner_result(&store, committed.owner_result())?.is_ok());
    Ok(())
}

/// ADR-138 acceptance test 6, the `committed_elo1` rule: a withdrawal first
/// committed by another request binds that request's command, so this
/// command's positive ELO1 bound to the same disposition signs; a first
/// commit whose ELO1 is this command's own but whose ELXW1 names another
/// command is refused.
#[test]
fn the_signer_checks_the_command_only_of_the_first_committed_owner_result() -> TestResult {
    let foreign = LocalOwnerResultBindingV1 {
        request: reference(0x61),
        attempt: reference(0x63),
        obligation: reference(0x64),
        command: reference(0x62),
        owner_ref: reference(0x65),
        error: None,
    };
    for first_is_ours in [false, true] {
        let (store, export, command) = dispatched_export_store()?;
        let first = {
            let mut sqlite = store.sqlite()?;
            sqlite.attach_recipient_custody(vec![export.custody()?])?;
            sqlite.begin_recipient_export_withdrawal(export.export_id, &export.grantee_owner()?)?;
            let binding = sqlite.delete_recipient_export_ciphertext(export.export_id)?;
            let record = LocalErasureRecipientExportWithdrawalV1 {
                request: foreign.request,
                command: foreign.command,
                export_id: binding.export_id,
                timeline_id: binding.timeline_id,
                grantee_owner: binding.grantee_owner,
                ciphertext_digest: binding.ciphertext_digest,
                ciphertext_length: binding.ciphertext_length,
                directory_identity: binding.directory_identity,
                final_identity: binding.final_identity,
            };
            let prepared = prepared_withdrawal(
                &record,
                if first_is_ours {
                    positive_binding(&command)
                } else {
                    foreign
                },
            )?;
            sqlite.commit_local_owner_effect(prepared.clone())?;
            prepared
        };
        // Withdrawn, the command commits a positive ELO1 bound to the
        // recorded disposition, with or without custody.
        let result = replayed_export(&mut store.host(&driver_case()?, 4_096)?)?;
        assert_eq!(result.error(), None);
        assert_eq!(
            Some(store.elo1(&result)?.effect_digest),
            first
                .effect_object()
                .map(pos_core::ErasureRetainedObjectV1::reference)
        );
        let signed = sign_owner_result(&store, result.owner_result())?;
        assert_eq!(
            result.owner_result() == first.owner_result().reference(),
            first_is_ours
        );
        assert_eq!(signed.is_ok(), !first_is_ours);
    }
    Ok(())
}

/// ADR-138 acceptance test 6: while the row is only retracted, no positive
/// ELO1 signs, even one retained with its ELXW1; the negative the executor
/// committed signs.
#[test]
fn the_signer_refuses_a_positive_owner_result_of_a_retracted_row() -> TestResult {
    let (store, export, command) = dispatched_export_store()?;
    let negative = replayed_export(&mut store.host(&driver_case()?, 4_096)?)?;
    assert_eq!(
        negative.error(),
        Some(ErasureErrorV1::ArtifactDeletionFailed)
    );
    let record = LocalErasureRecipientExportWithdrawalV1 {
        request: command.request,
        command: command.destruction.command,
        export_id: export.export_id,
        timeline_id: memory_owned_timeline(),
        grantee_owner: export.grantee_owner()?,
        ciphertext_digest: Hash::from_bytes([0x71; 32]),
        ciphertext_length: 1,
        directory_identity: [0x72; 16],
        final_identity: [0x73; 20],
    };
    let forged = retain_prepared(
        &store,
        &prepared_withdrawal(&record, positive_binding(&command))?,
    )?;
    assert_eq!(
        sign_owner_result(&store, forged)?,
        Err(ErasureHostErrorV1::AuthorizationDenied)
    );
    assert!(sign_owner_result(&store, negative.owner_result())?.is_ok());
    Ok(())
}

/// `withdraw_recipient_export_for_erasure` serves only a dispatched
/// `export-recipient` command: another class's dispatched command is a
/// conflict on `SQLite` and on Memory alike, and nothing is withdrawn.
/// Memory holds no publication, so it dispatches no `export-recipient`
/// command at all (ADR-138 §6).
#[test]
fn only_an_export_recipient_command_withdraws() -> TestResult {
    let (store, export, _) = dispatched_export_store()?;
    let request = request_of(1)?;
    let mut host = store.custody_host(&driver_case()?, vec![export.custody()?])?;
    let replica = command_of(&mut host, request, ErasureInventoryCategoryV1::Replica)?;
    assert_eq!(
        host.command_sender()?
            .withdraw_recipient_export_for_erasure(&replica)
            .map(drop),
        Err(ErasureHostErrorV1::Conflict)
    );
    assert!(export.final_path().exists());
    assert!(export.unavailable(&store).map(|unavailable| !unavailable)?);
    let mut memory = driver_memory_host(&driver_case()?)?;
    dispatch_consented(&mut memory)?;
    let replica = command_of(&mut memory, request, ErasureInventoryCategoryV1::Replica)?;
    assert_eq!(
        memory
            .command_sender()?
            .withdraw_recipient_export_for_erasure(&replica)
            .map(drop),
        Err(ErasureHostErrorV1::Conflict)
    );
    let owner = export_owner()?;
    assert!(memory
        .command_sender()?
        .dispatched_owner_commands(request)?
        .iter()
        .all(|command| command.destruction.owner != owner));
    Ok(())
}

use pos_runtime::{
    local_erasure_signer_rotation_v1, LocalErasureRotationRefusalV1, LocalErasureSignerRotationV1,
};

/// Whether `store` may register `key` as a role-2 key of the fixture
/// signer owner under `rotation` and the revoked key ids `revoked`.
fn signer_rotation(
    store: &mut SqliteStore,
    key: [u8; 32],
    rotation: LocalErasureSignerRotationV1,
    revoked: &[String],
) -> Result<(), LocalErasureRotationRefusalV1> {
    local_erasure_signer_rotation_v1(
        store,
        OwnerIdV1::from_static(SIGNER_OWNER),
        key,
        rotation,
        revoked,
    )
}

/// Owner decision of 2026-11-18 on #1431: a new role-2 signer key is
/// registered only while no request pins a bundle, or as a compromise the
/// installed TPS1 reflects; the registered key itself is an exact re-run.
#[test]
fn a_new_signer_key_waits_for_every_pin_unless_the_tps1_revokes_it() -> TestResult {
    let new_key = rotated_signer().verifying_key().to_bytes();
    let old_key = erasure_signer().verifying_key().to_bytes();
    let revoked = [local_erasure_signer_key_id_v1(&old_key)];
    let routine = LocalErasureSignerRotationV1::Routine;
    let compromise = LocalErasureSignerRotationV1::Compromise;
    let (pinned, _) = driven_until(|step| matches!(step, LocalErasureStepV1::Dispatched(_)))?;
    let mut store = pinned.sqlite()?;
    assert_eq!(
        signer_rotation(&mut store, new_key, routine, &[]),
        Err(LocalErasureRotationRefusalV1::Pinned)
    );
    assert_eq!(
        signer_rotation(&mut store, new_key, compromise, &[]),
        Err(LocalErasureRotationRefusalV1::NotRevoked)
    );
    assert_eq!(
        signer_rotation(&mut store, new_key, compromise, &revoked),
        Ok(())
    );
    assert_eq!(signer_rotation(&mut store, old_key, routine, &[]), Ok(()));
    assert_eq!(
        LocalErasureRotationRefusalV1::Pinned.to_string(),
        "an erasure request pins the current signer's bundle"
    );
    assert_eq!(
        LocalErasureRotationRefusalV1::NotRevoked.to_string(),
        "the installed TPS1 does not revoke the old signer's bundle"
    );
    // Once the attempt closed, nothing pins a bundle; a compromise still
    // needs the TPS1 to revoke the old signer.
    let (closed, _) = driven_until(|step| matches!(step, LocalErasureStepV1::Finalized(_)))?;
    assert_eq!(
        signer_rotation(&mut closed.sqlite()?, new_key, routine, &[]),
        Ok(())
    );
    assert_eq!(
        signer_rotation(&mut closed.sqlite()?, new_key, compromise, &[]),
        Err(LocalErasureRotationRefusalV1::NotRevoked)
    );
    // Only the owner's role-2 keys name its current signer: a later
    // encryption key of the owner, which has no public key, leaves the old
    // signer current.
    closed.register(KeyRegistrationV1::new(
        KeyIdentityV1::new(SIGNER_OWNER, KeyRoleV1::ExportRecipientEncryption, 9),
        Hash::from_bytes([0x9a; 32]),
        None,
    ))?;
    assert_eq!(
        signer_rotation(&mut closed.sqlite()?, old_key, routine, &[]),
        Ok(())
    );
    Ok(())
}

/// The rotation rule fails closed: pins that cannot be read refuse both a
/// routine rotation and a compromise, and composition refuses the rotated
/// bundle; a key registry that cannot be read leaves the old signer
/// unknown and refuses every new key.
#[test]
fn an_unreadable_pin_or_signer_refuses_every_rotation() -> TestResult {
    let new_key = rotated_signer().verifying_key().to_bytes();
    let old_key = erasure_signer().verifying_key().to_bytes();
    let revoked = [local_erasure_signer_key_id_v1(&old_key)];
    let (pinned, steps) = driven_until(|step| matches!(step, LocalErasureStepV1::Dispatched(_)))?;
    let Some(LocalErasureStepV1::Dispatched(admission)) = steps.last() else {
        return Err("no dispatch".into());
    };
    overwrite_object(&pinned, admission.reference(), &[0])?;
    for (rotation, revoked) in [
        (LocalErasureSignerRotationV1::Routine, &[][..]),
        (LocalErasureSignerRotationV1::Compromise, &revoked[..]),
    ] {
        assert_eq!(
            signer_rotation(&mut pinned.sqlite()?, new_key, rotation, revoked),
            Err(LocalErasureRotationRefusalV1::Pinned)
        );
    }
    let rotated = rotated_bundle(&pinned)?;
    assert_eq!(
        Case::signed(&rotated, &bundle_root(), &[revoked[0].as_str()])?
            .refusal(&mut pinned.sqlite()?),
        Some(LocalErasureCompositionErrorV1::BundleMismatch)
    );

    let unread = driver_store()?;
    rusqlite::Connection::open(&unread.path)?.execute(
        "UPDATE key_registry SET state_cbor = X'00' WHERE singleton = 1",
        [],
    )?;
    for rotation in [
        LocalErasureSignerRotationV1::Routine,
        LocalErasureSignerRotationV1::Compromise,
    ] {
        assert_eq!(
            signer_rotation(&mut unread.sqlite()?, new_key, rotation, &revoked),
            Err(LocalErasureRotationRefusalV1::SignerUnknown)
        );
    }
    assert_eq!(
        LocalErasureRotationRefusalV1::SignerUnknown.to_string(),
        "the key registry or its current signer's public key cannot be read"
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// #1449: the ELADM1 submission binding (owner decision D5 on #1413), the
// typed admission refusals (D3, D9) and the `getErasure` projection
// (ADR-136 §7).
// ---------------------------------------------------------------------------

use pos_core::LocalErasureAdmissionV1;
use pos_runtime::{LocalErasureClassCountV1, LocalErasureProjectionV1};

/// The `erasure_id` of the fixture actor's request `key`.
fn erasure_id_of(key: u8) -> TestResult<Ulid> {
    Ok(local_erasure_id_v1(
        principal_ref()?,
        actor(),
        reference(key),
    )?)
}

/// `CA(ELB1)` of `case`'s bundle.
fn trust_of(case: &Case) -> TestResult<ErasureReferenceV1> {
    Ok(LocalErasureBundleV1::from_canonical_cbor(&case.bundle)?.reference()?)
}

/// The projection of the fixture actor's request `key` on `host`.
fn projection(
    host: &mut ErasureExecutionHostV1,
    actor: EntityId,
    key: u8,
) -> TestResult<Option<LocalErasureProjectionV1>> {
    Ok(host.command_sender()?.local_erasure_projection(
        &principal()?,
        actor,
        erasure_id_of(key)?,
    )?)
}

/// Delete every retained ELADM1 of `store`.
fn drop_admissions(store: &LocalStore) -> TestResult<usize> {
    Ok(store
        .sqlite()?
        .sweep_unreferenced_erasure_objects(&["ELADM1"], &[], 16)?)
}

/// D5: a submission retains its ELADM1 with the bundle, mode profile and
/// binding epoch it was admitted under; the exact replay answers that same
/// binding however the replay's own binding differs.
#[test]
fn a_submission_binds_its_bundle_and_mode_and_a_replay_keeps_them() -> TestResult {
    let store = LocalStore::new(&GrantShape::standard())?;
    let case = local_case()?;
    let mut host = store.host(&case, 4_096)?;
    let mut sender = host.command_sender()?;
    let admitted = sender
        .submit_local_erasure(&submission(1, ErasureScopeV1::PrivateSubjectData)?)
        .map_err(fail)?;
    let admission = LocalErasureAdmissionV1 {
        request: request_of(1)?,
        trust: trust_of(&case)?,
        mode_profile: reference(0x6d),
        binding_epoch: 1,
    };
    assert_eq!(admitted.erasure_id, erasure_id_of(1)?);
    assert_eq!(admitted.policy, LOCAL_ERASURE_POLICY_REFERENCE_V1);
    assert_eq!(admitted.admission, admission);
    assert_eq!(
        ErasurePersistencePortV1::read_object(&store.sqlite()?, admission.reference()?)?,
        admission.to_canonical_cbor()?
    );
    let rebound = LocalErasureSubmissionV1 {
        mode_profile: reference(0x6e),
        binding_epoch: 2,
        ..submission(1, ErasureScopeV1::PrivateSubjectData)?
    };
    assert_eq!(sender.submit_local_erasure(&rebound), Ok(admitted));
    Ok(())
}

/// D5: an ELADM1 a crash retained before the ERQ1 committed is the one the
/// later submission of that `erasure_id` binds, so an id never has two.
#[test]
fn a_crash_left_admission_binds_the_resubmission() -> TestResult {
    let store = LocalStore::new(&GrantShape::standard())?;
    let left = LocalErasureAdmissionV1 {
        request: request_of(1)?,
        trust: reference(0x41),
        mode_profile: reference(0x42),
        binding_epoch: 7,
    };
    // Another request's ELADM1 is never taken for this one.
    let other = LocalErasureAdmissionV1 {
        request: request_of(2)?,
        ..left
    };
    store.retain(&[left.to_canonical_cbor()?, other.to_canonical_cbor()?])?;
    let mut host = store.host(&local_case()?, 4_096)?;
    let admitted = host
        .command_sender()?
        .submit_local_erasure(&submission(1, ErasureScopeV1::PrivateSubjectData)?)
        .map_err(fail)?;
    assert_eq!(admitted.admission, left);
    Ok(())
}

/// A retained ELADM1 that does not decode may be the request's own, so the
/// submission fails closed rather than retain a second one.
#[test]
fn an_undecodable_admission_fails_the_submission_closed() -> TestResult {
    let store = LocalStore::new(&GrantShape::standard())?;
    let mut corrupt = Vec::new();
    ciborium::into_writer(
        &ciborium::value::Value::Array(vec![
            ciborium::value::Value::Text("ELADM1".to_owned()),
            ciborium::value::Value::Integer(1.into()),
        ]),
        &mut corrupt,
    )?;
    store.retain(&[corrupt])?;
    let mut host = store.host(&local_case()?, 4_096)?;
    refused_without_retention(
        &store,
        &mut host,
        &submission(1, ErasureScopeV1::PrivateSubjectData)?,
        LocalErasureSubmitErrorV1::Host(ErasureHostErrorV1::RecoveryUnavailable),
    )
}

/// A binding epoch of zero names no binding: the submission is refused and
/// retains nothing.
#[test]
fn a_submission_without_a_binding_epoch_retains_nothing() -> TestResult {
    let store = LocalStore::new(&GrantShape::standard())?;
    let mut host = store.host(&local_case()?, 4_096)?;
    let unbound = LocalErasureSubmissionV1 {
        binding_epoch: 0,
        ..submission(1, ErasureScopeV1::PrivateSubjectData)?
    };
    refused_without_retention(
        &store,
        &mut host,
        &unbound,
        LocalErasureSubmitErrorV1::Host(ErasureHostErrorV1::Conflict),
    )?;
    assert_eq!(drop_admissions(&store)?, 0);
    Ok(())
}

/// An installed request whose ELADM1 is gone is answered neither as a
/// replay nor as a projection.
#[test]
fn a_request_without_its_admission_is_unavailable() -> TestResult {
    let store = LocalStore::new(&GrantShape::standard())?;
    {
        let mut host = store.host(&local_case()?, 4_096)?;
        submitted(&mut host, 1, ErasureScopeV1::PrivateSubjectData)?;
    }
    assert_eq!(drop_admissions(&store)?, 1);
    let mut host = store.host(&local_case()?, 4_096)?;
    assert_eq!(
        host.command_sender()?
            .submit_local_erasure(&submission(1, ErasureScopeV1::PrivateSubjectData)?),
        Err(LocalErasureSubmitErrorV1::Host(
            ErasureHostErrorV1::RecoveryUnavailable
        ))
    );
    assert_eq!(
        host.command_sender()?
            .local_erasure_projection(&principal()?, actor(), erasure_id_of(1)?),
        Err(ErasureHostErrorV1::RecoveryUnavailable)
    );
    Ok(())
}

/// D9 and ADR-136 §7: a host without a Local composition, an unknown id and
/// another subject's id are all answered `None`.
#[test]
fn the_projection_never_tells_an_unknown_id_from_another_subjects() -> TestResult {
    let mut closed = ErasureExecutionHostV1::open_verified_empty(
        StoreConfig::Memory,
        ErasureRecoveryLimitsV1::compiled_maximum(),
    )?;
    assert_eq!(projection(&mut closed, actor(), 1)?, None);
    let mut shape = GrantShape::standard();
    shape.actors = vec![actor(), other_actor()];
    shape.actors.sort_unstable();
    for adapter in ADAPTERS {
        let (mut fixture, ()) = Fixture::local(adapter, &shape, 4_096, |_| Ok(()))?;
        let host = &mut fixture.host;
        assert_eq!(projection(host, actor(), 1)?, None);
        submitted(host, 1, ErasureScopeV1::PrivateSubjectData)?;
        assert!(projection(host, actor(), 1)?.is_some());
        assert_eq!(projection(host, actor(), 2)?, None);
        // The other actor names the same `erasure_id`: another subject.
        assert_eq!(
            host.command_sender()?.local_erasure_projection(
                &principal()?,
                other_actor(),
                erasure_id_of(1)?
            )?,
            None
        );
    }
    Ok(())
}

/// ADR-136 §7: the projection of a driven request, step by step. Its
/// generation is the ERS1 ordinal times 2^16 plus the acknowledgements of
/// the active attempt, so it rises
/// with every committed step and never decreases; the acknowledgement
/// counts are the frozen obligations and the effective positives, per
/// class.
#[test]
fn the_projection_follows_a_driven_request() -> TestResult {
    let store = driver_store()?;
    let case = driver_case()?;
    let mut host = store.host(&case, 4_096)?;
    submitted(&mut host, 1, ErasureScopeV1::PrivateSubjectData)?;
    let first = projection(&mut host, actor(), 1)?.ok_or("no projection")?;
    assert_eq!(first.erasure_id, erasure_id_of(1)?);
    assert_eq!(first.state.lifecycle(), ErasureLifecycleV1::Submitted);
    assert_eq!(first.scope, ErasureScopeV1::PrivateSubjectData);
    assert_eq!(first.generation, 0);
    assert_eq!(
        (first.required, first.positive),
        (0, 0),
        "nothing is frozen yet"
    );
    assert!(first.classes.is_empty());
    assert_eq!(first.admission.trust, trust_of(&case)?);
    let request = request_of(1)?;
    let mut previous = first.generation;
    let mut generations = vec![previous];
    let mut acknowledged = 0_u64;
    loop {
        let step = driver().step(&mut host, request)?;
        if step == LocalErasureStepV1::Idle {
            break;
        }
        let current = projection(&mut host, actor(), 1)?.ok_or("no projection")?;
        assert!(current.generation > previous, "{step:?}");
        if matches!(step, LocalErasureStepV1::Acknowledged(_)) {
            acknowledged += 1;
            // Within the attempt each acknowledgement adds one, unless the
            // first one moved the head to awaiting acknowledgements.
            assert!(
                current.generation == previous + 1
                    || current.state.lifecycle() == ErasureLifecycleV1::AwaitingAcknowledgements,
                "{step:?}"
            );
        }
        previous = current.generation;
        generations.push(previous);
        // The head is the projection's state, digest included.
        assert_eq!(
            Some(current.state.clone()),
            host.read_sender()?
                .erasure_state(request)?
                .map(|verified| verified.state().clone())
        );
    }
    assert_eq!(generations[1..3], [1_u64 << 16, 2 << 16]);
    let last = projection(&mut host, actor(), 1)?.ok_or("no projection")?;
    let ordinal = u64::try_from(history(&mut host, request)?.len())? - 1;
    assert_eq!(last.generation, ordinal << 16);
    assert_eq!(last.state.lifecycle(), ErasureLifecycleV1::PartialFailure);
    assert_eq!(
        last.state.replay_claim(),
        ErasureReplayClaimV1::UnverifiableArtifactsMissing
    );
    let count = |class: &str, required, positive| LocalErasureClassCountV1 {
        class: class.to_owned(),
        required,
        positive,
    };
    // The key, the cache signal and the replica are positive; the Timeline
    // payload and the backup are the permanent negatives.
    assert_eq!(
        last.classes,
        [
            count("client-cache-signal", 1, 1),
            count("key-registry", 1, 1),
            count("local-backup-inventory", 1, 0),
            count("local-replica", 1, 1),
            count("timeline-payload", 1, 0),
        ]
    );
    assert_eq!((last.required, last.positive), (5, 3));
    assert_eq!(acknowledged, 5);
    Ok(())
}

/// #1407 (ADR-136 follow-up F2): the store's redaction generation is 0
/// until the first ELCG1 commits, never decreases while a request is
/// driven, and rises again with the next request's ELCG1; every projection
/// reads the same store-wide value. Each ELCG1 still carries its own
/// request's attempt position, 2 for attempt 0 (Q8).
#[test]
fn the_redaction_generation_rises_across_requests() -> TestResult {
    let store = driver_store()?;
    let mut host = store.host(&driver_case()?, 4_096)?;
    submitted(&mut host, 1, ErasureScopeV1::PrivateSubjectData)?;
    let redaction = |host: &mut ErasureExecutionHostV1, key: u8| -> TestResult<u64> {
        Ok(projection(host, actor(), key)?
            .ok_or("no projection")?
            .redaction_generation)
    };
    let mut previous = redaction(&mut host, 1)?;
    assert_eq!(previous, 0);
    loop {
        let step = driver().step(&mut host, request_of(1)?)?;
        if step == LocalErasureStepV1::Idle {
            break;
        }
        let current = redaction(&mut host, 1)?;
        assert!(current >= previous, "{step:?}");
        previous = current;
    }
    assert_eq!(previous, 1);
    submitted(&mut host, 2, ErasureScopeV1::ConsentedSharedData)?;
    assert_eq!(redaction(&mut host, 2)?, 1);
    finalized(driver().drive(&mut host, request_of(2)?)?)?;
    assert_eq!(redaction(&mut host, 1)?, 2);
    assert_eq!(redaction(&mut host, 2)?, 2);
    let mut records = store
        .sqlite()?
        .retained_erasure_objects("ELCG1", 16)?
        .iter()
        .map(|bytes| LocalErasureCacheGenerationV1::from_canonical_cbor(bytes))
        .map(|record| record.map(|record| (record.request, record.generation)))
        .collect::<Result<Vec<_>, _>>()?;
    records.sort_unstable();
    let mut expected = vec![(request_of(1)?, 2), (request_of(2)?, 2)];
    expected.sort_unstable();
    assert_eq!(records, expected);
    Ok(())
}

// ---------------------------------------------------------------------------
// ADR-136 acceptance test 10 (owner decision D12 of 2026-11-18 on #1413):
// a subject-scoped export through core `export_timeline`, then erasure,
// then the export again through the public offline evaluator.
// ---------------------------------------------------------------------------

use pos_core::{
    store::export_timeline, ArtifactClaimInputV1, ArtifactOptionalityV1, ArtifactStateV1,
    CoreError, RegisteredArtifactV1, ReplayClaimEvaluationV1, ReplayClaimEvaluatorV1,
};

/// The export artifact of the subject's owned Timeline.
const SUBJECT_EXPORT: ErasureReferenceV1 = ErasureReferenceV1::from_digest([0xe7; 32]);

/// The offline evaluation of the subject's export under the erasure state
/// `claim`, from the store's own facts: the export depends on the subject's
/// role-0 key, so it is missing once the key registry tombstones that key.
fn export_evaluation(
    store: &LocalStore,
    claim: ErasureReplayClaimV1,
) -> TestResult<ReplayClaimEvaluationV1> {
    let registry = store.sqlite()?.load_key_registry()?.ok_or("no registry")?;
    let state = if registry.tombstone(subject_key(1)?).is_some() {
        ArtifactStateV1::MissingKey
    } else {
        ArtifactStateV1::Retained
    };
    Ok(ReplayClaimEvaluatorV1::evaluate(
        claim,
        &[ArtifactClaimInputV1 {
            registration: RegisteredArtifactV1::new(
                ErasureArtifactClassV1::Export,
                SUBJECT_EXPORT,
                ArtifactDataClassV1::PrivateSubjectData,
                None,
                reference(0xe8),
                ArtifactOptionalityV1::Required,
                ArtifactTransitionRuleV1::Remove,
            ),
            current_claim: claim,
            state,
        }],
    )?)
}

/// Acceptance test 10: before the erasure the export is exact and core
/// exports the Timeline; after it the evaluator reports the export
/// unavailable under the receipt's weakened claim, and core refuses it.
#[test]
fn an_export_after_the_erasure_reports_its_unavailable_artifact() -> TestResult {
    let store = driver_store()?;
    store.sqlite()?.append(
        memory_owned_timeline(),
        &[pos_core::EventDraft::new(
            actor(),
            pos_core::Kind::new("subject.note.v1"),
            CanonicalBytes::from_static(b"subject-note"),
        )],
    )?;
    let before = export_evaluation(&store, ErasureReplayClaimV1::Exact)?;
    assert_eq!(before.replay_claim(), ErasureReplayClaimV1::Exact);
    let exported = export_timeline(
        &store.sqlite()?,
        memory_owned_timeline(),
        SUBJECT_EXPORT,
        &before,
    )?;
    assert_eq!(exported.events.len(), 1);
    let receipt = {
        let mut host = store.host(&driver_case()?, 4_096)?;
        submitted(&mut host, 1, ErasureScopeV1::PrivateSubjectData)?;
        finalized(driver().drive(&mut host, request_of(1)?)?)?
    };
    let after = export_evaluation(&store, receipt.replay_claim())?;
    assert_eq!(
        after.replay_claim(),
        ErasureReplayClaimV1::UnverifiableArtifactsMissing
    );
    let [export] = after.artifacts() else {
        return Err("one evaluated artifact".into());
    };
    assert_eq!(export.artifact_digest(), SUBJECT_EXPORT);
    assert_eq!(
        export.from(),
        ErasureReplayClaimV1::UnverifiableArtifactsMissing
    );
    assert_eq!(
        export.to(),
        ErasureReplayClaimV1::UnverifiableArtifactsMissing
    );
    assert!(!export.authoritative_use_permitted());
    assert!(matches!(
        export_timeline(
            &store.sqlite()?,
            memory_owned_timeline(),
            SUBJECT_EXPORT,
            &after
        ),
        Err(CoreError::ArtifactUnavailable)
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// The ADR-136 acceptance matrix, slice C6a (#1469): the runtime gaps of
// acceptance tests 2 to 6, over both adapters. It reuses every fixture
// above; `docs/erasure/adr-136-acceptance-matrix.md` maps each bullet.
// ---------------------------------------------------------------------------

#[path = "local_erasure_composition/acceptance.rs"]
mod acceptance;

// ---------------------------------------------------------------------------
// ADR-141 P6 and P7 (#306 C1): a root created under its identity and the
// closed composition's refusal of a store with active requests.
// ---------------------------------------------------------------------------

#[path = "local_erasure_composition/owned_root_with_id.rs"]
mod owned_root_with_id;

// ---------------------------------------------------------------------------
// ADR-129 revision 13 (#560 A4b-2, R13-1): the Memory community
// erasure-budget counters against the authority's closure.
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
#[path = "local_erasure_composition/community_budget.rs"]
mod community_budget;

// ---------------------------------------------------------------------------
// ADR-136 follow-up F3 (#1408): the operator's admissions record closes
// fresh Local submissions only. An exact replay, the driver and its startup
// sweep never read it, so every admitted request still freezes and
// completes.
// ---------------------------------------------------------------------------

use pos_core::{ErasureAdmissionsPortV1, ErasureAdmissionsStateV1};

impl LocalStore {
    /// Write the operator's admissions record while no host is open, as the
    /// offline `piglor-gateway erasure-admissions` writer does.
    fn set_admissions(&self, state: ErasureAdmissionsStateV1) -> TestResult {
        self.sqlite()?.set_erasure_admissions(state)?;
        Ok(())
    }

    /// Submit request 1 for private subject data on a host composed of
    /// `case`, and return its admission.
    fn admitted(&self, case: &Case) -> TestResult<pos_runtime::LocalErasureAdmittedV1> {
        let mut host = self.host(case, 4_096)?;
        let admitted = host
            .command_sender()?
            .submit_local_erasure(&submission(1, ErasureScopeV1::PrivateSubjectData)?)
            .map_err(fail)?;
        Ok(admitted)
    }
}

/// #1408: while the record is closed, a fresh submission is refused
/// `OperatorClosed` on both adapters. The Memory store is closed before its
/// host owns it.
#[test]
fn a_closed_record_refuses_a_fresh_submission() -> TestResult {
    for adapter in ADAPTERS {
        let (mut fixture, previous) =
            Fixture::local(adapter, &GrantShape::standard(), 4_096, |store| {
                Ok(store.set_erasure_admissions(ErasureAdmissionsStateV1::Closed)?)
            })?;
        assert_eq!(previous, ErasureAdmissionsStateV1::Open, "{adapter:?}");
        assert_eq!(
            fixture
                .host
                .command_sender()?
                .submit_local_erasure(&submission(1, ErasureScopeV1::PrivateSubjectData)?),
            Err(LocalErasureSubmitErrorV1::OperatorClosed),
            "{adapter:?}"
        );
    }
    Ok(())
}

/// #1408 on `SQLite`, closed and reopened behind the host: the exact replay
/// of an admitted request still answers its state and the same key with
/// another body its conflict; a fresh request is refused before the
/// subject checks and retains nothing; reopening admits it to the subject
/// checks again.
#[test]
fn a_closed_record_answers_the_exact_replay_and_retains_nothing() -> TestResult {
    let store = LocalStore::new(&GrantShape::standard())?;
    let state = store.admitted(&local_case()?)?;
    store.set_admissions(ErasureAdmissionsStateV1::Closed)?;
    let mut host = store.host(&local_case()?, 4_096)?;
    {
        let mut sender = host.command_sender()?;
        assert_eq!(
            sender.submit_local_erasure(&submission(1, ErasureScopeV1::PrivateSubjectData)?),
            Ok(state)
        );
        assert_eq!(
            sender.submit_local_erasure(&submission(1, ErasureScopeV1::ConsentedSharedData)?),
            Err(LocalErasureSubmitErrorV1::Host(
                ErasureHostErrorV1::Conflict
            ))
        );
    }
    // Request 1 still holds the subject, yet the closed record answers
    // first, so the refusal is not `Concurrent`.
    refused_before_the_subject_checks(
        &store,
        &mut host,
        LocalErasureSubmitErrorV1::OperatorClosed,
    )?;
    drop(host);
    store.set_admissions(ErasureAdmissionsStateV1::Open)?;
    let mut host = store.host(&local_case()?, 4_096)?;
    assert_eq!(
        host.command_sender()?
            .submit_local_erasure(&submission(2, ErasureScopeV1::PrivateSubjectData)?),
        Err(LocalErasureSubmitErrorV1::Concurrent)
    );
    Ok(())
}

/// #1408 on `SQLite`: a request admitted before the record closed survives
/// the startup sweep, freezes and completes on a host restarted while it is
/// closed, which still refuses a fresh request of the released subject.
#[test]
fn an_admitted_request_freezes_and_completes_while_admissions_are_closed() -> TestResult {
    let store = driver_store()?;
    {
        let mut host = store.host(&driver_case()?, 4_096)?;
        submitted(&mut host, 1, ErasureScopeV1::ConsentedSharedData)?;
    }
    store.set_admissions(ErasureAdmissionsStateV1::Closed)?;
    let mut host = store.host(&driver_case()?, 4_096)?;
    assert!(matches!(
        LocalErasureDriverV1::sweep(&mut host),
        LocalErasureSweepV1::Swept(_)
    ));
    let steps = driven_steps(&mut host, |_| false)?;
    assert_eq!(steps[0], LocalErasureStepV1::Authorized);
    assert_eq!(steps[1], LocalErasureStepV1::Frozen);
    let receipt = finalized(steps.last().cloned().ok_or("no step")?)?;
    assert_eq!(receipt.lifecycle(), ErasureLifecycleV1::Complete);
    assert_eq!(
        host.command_sender()?
            .submit_local_erasure(&submission(2, ErasureScopeV1::PrivateSubjectData)?),
        Err(LocalErasureSubmitErrorV1::OperatorClosed)
    );
    Ok(())
}

/// #1408 on `SQLite`: a record the host cannot read (a row the `CHECK`
/// refuses, written with the checks off) fails closed for a fresh request
/// as `AdapterFailure`, retaining nothing, while the exact replay is still
/// answered.
#[test]
fn an_unreadable_record_fails_closed_for_a_fresh_submission_only() -> TestResult {
    let store = LocalStore::new(&GrantShape::standard())?;
    let state = store.admitted(&local_case()?)?;
    rusqlite::Connection::open(&store.path)?.execute_batch(
        "PRAGMA ignore_check_constraints = ON;
         INSERT INTO erasure_admissions (singleton, closed) VALUES (1, 'unreadable');",
    )?;
    let mut host = store.host(&local_case()?, 4_096)?;
    assert_eq!(
        host.command_sender()?
            .submit_local_erasure(&submission(1, ErasureScopeV1::PrivateSubjectData)?),
        Ok(state)
    );
    refused_before_the_subject_checks(
        &store,
        &mut host,
        LocalErasureSubmitErrorV1::Host(ErasureHostErrorV1::AdapterFailure),
    )
}
