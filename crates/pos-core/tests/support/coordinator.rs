//! Shared raw persistence and host-port fixture for ADR-060 public tests.

use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::rc::Rc;

use ciborium::value::Value;
use pos_core::erasure::{
    target_closure_digest, ErasureAuthorizationDecisionV1, ERASURE_ATTEMPT_HISTORY_TAG_V1,
};
use pos_core::{
    ErasureAcknowledgementProvenanceV1, ErasureAdministrativeResolutionV1,
    ErasureAtomicFreezeAdmissionInputV1, ErasureAtomicFreezeAdmissionV1,
    ErasureAtomicFreezeResultV1, ErasureAttemptQuotaReservationV1, ErasureCasOutcomeV1,
    ErasureCoordinatorPortV1, ErasureDestructionCommandV1, ErasureErrorV1,
    ErasureFreezeAdmissionEvidenceV1, ErasureFreezeAuthorizationEvidenceV1,
    ErasureFreezeAuthorizationVerifierV1, ErasureFreezeFailureV1, ErasureIndexInsertV1,
    ErasureInventoryCategoryV1, ErasureObligationInputV1, ErasureObligationSetInputV1,
    ErasureObligationSetV1, ErasureObligationV1, ErasurePersistencePortV1, ErasureReceiptInputV1,
    ErasureReferenceV1, ErasureRequestV1, ErasureRequiredTargetV1, ErasureRetryAdmissionV1,
    ErasureScopeCommitmentInputV1, ErasureScopeCommitmentV1, ErasureScopeExtensionV1,
    ErasureStateResolverV1, ErasureStateTransitionV1, ErasureStateV1,
};

use crate::erasure_support::{freeze_evidence_fixture, FreezeEvidenceFixtureInput};

/// Configuration for the host side of the public coordinator fixture.
#[derive(Clone)]
pub struct PublicCoordinatorPortConfig {
    pub targets: Vec<ErasureRequiredTargetV1>,
    pub fail_commits: bool,
    pub policy: ErasureReferenceV1,
    pub trust: ErasureReferenceV1,
    pub scope_member: ErasureReferenceV1,
    pub freeze_evidence: ErasureReferenceV1,
    pub lineage_rule: Option<ErasureReferenceV1>,
    pub freeze_rejection: Option<(ErasureErrorV1, ErasureReferenceV1)>,
    pub operation_fault: Option<PublicCoordinatorFault>,
}

/// One coordinator dependency operation selected for deterministic failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PublicCoordinatorOperation {
    LoadManifest,
    ReadObject,
    ResolveState,
    EffectManifest,
    ReadEffect,
    AttemptIndexCount,
    AttemptPageRef,
    ScopeIndexCount,
    ScopeNodeRef,
    ResolutionIndexCount,
    ResolutionRef,
    CompareAndSwap,
    ValidateFreezeAuthorization,
    AdmitAuthorization,
    AdmitCorrectedSubmission,
    AdmitAtomicFreeze,
    AdmitAttempt,
    AdmitAcknowledgement,
    AdmitReceipt,
    AdmitScopeExtension,
    AdmitAdministrativeResolution,
}

/// Fail one zero-based occurrence of a selected dependency operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublicCoordinatorFault {
    pub operation: PublicCoordinatorOperation,
    pub occurrence: u64,
}

#[derive(Default)]
struct RawStorage {
    manifests: BTreeMap<ErasureReferenceV1, (ErasureReferenceV1, Vec<u8>)>,
    objects: BTreeMap<ErasureReferenceV1, Vec<u8>>,
    states: BTreeMap<ErasureReferenceV1, Vec<u8>>,
    attempts: BTreeMap<(ErasureReferenceV1, u64), ErasureReferenceV1>,
    scopes: BTreeMap<(ErasureReferenceV1, u64), ErasureReferenceV1>,
    resolutions: BTreeMap<(ErasureReferenceV1, u64), ErasureReferenceV1>,
    effects: BTreeMap<ErasureReferenceV1, Vec<u8>>,
    effect_subjects: BTreeMap<ErasureReferenceV1, ErasureReferenceV1>,
}

fn addressed(tag: &str, bytes: &[u8]) -> ErasureReferenceV1 {
    let mut input = tag.as_bytes().to_vec();
    input.push(0);
    input.extend_from_slice(bytes);
    ErasureReferenceV1::from_digest(*blake3::hash(&input).as_bytes())
}

fn replace_array_field(
    bytes: &[u8],
    index: usize,
    replacement: Value,
) -> Result<Vec<u8>, ErasureErrorV1> {
    let mut value: Value =
        ciborium::from_reader(bytes).map_err(|_| ErasureErrorV1::InvalidEncoding)?;
    let Value::Array(fields) = &mut value else {
        return Err(ErasureErrorV1::InvalidEncoding);
    };
    *fields
        .get_mut(index)
        .ok_or(ErasureErrorV1::InvalidEncoding)? = replacement;
    let mut changed = Vec::new();
    ciborium::into_writer(&value, &mut changed).map_err(|_| ErasureErrorV1::InvalidEncoding)?;
    Ok(changed)
}

fn array_reference_field(bytes: &[u8], index: usize) -> Result<ErasureReferenceV1, ErasureErrorV1> {
    let value: Value = ciborium::from_reader(bytes).map_err(|_| ErasureErrorV1::InvalidEncoding)?;
    let Value::Array(fields) = value else {
        return Err(ErasureErrorV1::InvalidEncoding);
    };
    let Value::Bytes(bytes) = fields.get(index).ok_or(ErasureErrorV1::InvalidEncoding)? else {
        return Err(ErasureErrorV1::InvalidEncoding);
    };
    let digest: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| ErasureErrorV1::InvalidEncoding)?;
    Ok(ErasureReferenceV1::from_digest(digest))
}

fn replace_attempt_page_field(
    storage: &mut RawStorage,
    request: ErasureReferenceV1,
    ordinal: u64,
    index: usize,
    replacement: Value,
) -> Result<(), ErasureErrorV1> {
    let previous = *storage
        .attempts
        .get(&(request, ordinal))
        .ok_or(ErasureErrorV1::ProvenanceMissing)?;
    let page = storage
        .objects
        .get(&previous)
        .cloned()
        .ok_or(ErasureErrorV1::ProvenanceMissing)?;
    let changed = replace_array_field(&page, index, replacement)?;
    let changed_reference = addressed(ERASURE_ATTEMPT_HISTORY_TAG_V1, &changed);
    storage.objects.remove(&previous);
    storage.objects.insert(changed_reference, changed);
    storage
        .attempts
        .insert((request, ordinal), changed_reference);

    let (_, manifest) = storage
        .manifests
        .get(&request)
        .cloned()
        .ok_or(ErasureErrorV1::ProvenanceMissing)?;
    let changed_manifest = replace_array_field(
        &manifest,
        15,
        Value::Bytes(changed_reference.digest().to_vec()),
    )?;
    storage.manifests.insert(
        request,
        (addressed("ERCRP1", &changed_manifest), changed_manifest),
    );
    Ok(())
}

/// In-memory implementation of the raw persistence and host capability SPIs.
///
/// The storage is shared by clones so tests can retain an adapter handle while
/// a state machine owns another handle. The last prepared delta is also kept
/// for an explicit exact-retry assertion without exposing coordinator state.
#[derive(Clone)]
pub struct PublicCoordinatorPort {
    storage: Rc<RefCell<RawStorage>>,
    last_mutation: Rc<RefCell<Option<pos_core::PreparedErasureCasV1>>>,
    attempt_admissions: Rc<RefCell<u64>>,
    operation_fault_hits: Rc<Cell<u64>>,
    config: PublicCoordinatorPortConfig,
}

impl PublicCoordinatorPort {
    #[must_use]
    pub fn new(config: PublicCoordinatorPortConfig) -> Self {
        Self {
            storage: Rc::new(RefCell::new(RawStorage::default())),
            last_mutation: Rc::new(RefCell::new(None)),
            attempt_admissions: Rc::new(RefCell::new(0)),
            operation_fault_hits: Rc::new(Cell::new(0)),
            config,
        }
    }

    #[must_use]
    pub fn with_operation_fault(mut self, fault: PublicCoordinatorFault) -> Self {
        self.config.operation_fault = Some(fault);
        self.operation_fault_hits.set(0);
        self
    }

    #[must_use]
    pub fn operation_fault_hits(&self) -> u64 {
        self.operation_fault_hits.get()
    }

    fn maybe_fail(&self, operation: PublicCoordinatorOperation) -> Result<(), ErasureErrorV1> {
        let Some(fault) = self.config.operation_fault else {
            return Ok(());
        };
        if fault.operation != operation {
            return Ok(());
        }
        let occurrence = self.operation_fault_hits.get();
        self.operation_fault_hits.set(occurrence.saturating_add(1));
        if occurrence == fault.occurrence {
            Err(ErasureErrorV1::TrustSnapshotInvalid)
        } else {
            Ok(())
        }
    }

    #[must_use]
    pub fn current_manifest(
        &self,
        request: ErasureReferenceV1,
    ) -> Option<pos_core::StoredErasureManifestV1> {
        self.storage
            .borrow()
            .manifests
            .get(&request)
            .and_then(|(digest, bytes)| {
                pos_core::StoredErasureManifestV1::new(*digest, bytes.clone()).ok()
            })
    }

    #[must_use]
    pub fn last_mutation(&self) -> Option<pos_core::PreparedErasureCasV1> {
        self.last_mutation.borrow().clone()
    }

    #[must_use]
    pub fn effect(&self, manifest: ErasureReferenceV1) -> Option<ErasureReferenceV1> {
        self.storage
            .borrow()
            .effects
            .get(&manifest)
            .and_then(|bytes| pos_core::ErasureCasEffectV1::from_canonical_cbor(bytes).ok())
            .map(|effect| effect.identity())
    }

    #[must_use]
    pub fn attempt_admission_count(&self) -> u64 {
        *self.attempt_admissions.borrow()
    }

    pub fn remove_effect_for_subject(&self, subject: ErasureReferenceV1) {
        let mut storage = self.storage.borrow_mut();
        if let Some(manifest) = storage.effect_subjects.remove(&subject) {
            storage.effects.remove(&manifest);
        }
    }

    /// Replace one raw manifest field while retaining a valid content address.
    ///
    /// # Errors
    ///
    /// Returns a closed encoding or provenance error when the stored manifest
    /// is absent, malformed, or does not contain `index`.
    pub fn replace_manifest_field(
        &self,
        request: ErasureReferenceV1,
        index: usize,
        replacement: Value,
    ) -> Result<(), ErasureErrorV1> {
        let mut storage = self.storage.borrow_mut();
        let (_, bytes) = storage
            .manifests
            .get(&request)
            .cloned()
            .ok_or(ErasureErrorV1::ProvenanceMissing)?;
        let changed = replace_array_field(&bytes, index, replacement)?;
        let digest = addressed("ERCRP1", &changed);
        storage.manifests.insert(request, (digest, changed));
        Ok(())
    }

    /// Replace one field of a manifest-owned object and repair both addresses.
    ///
    /// # Errors
    ///
    /// Returns a closed encoding or provenance error when the manifest or
    /// selected object is absent or malformed.
    pub fn replace_manifest_object_field(
        &self,
        request: ErasureReferenceV1,
        manifest_field: usize,
        object_tag: &str,
        object_field: usize,
        replacement: Value,
    ) -> Result<(), ErasureErrorV1> {
        let mut storage = self.storage.borrow_mut();
        let (_, manifest) = storage
            .manifests
            .get(&request)
            .cloned()
            .ok_or(ErasureErrorV1::ProvenanceMissing)?;
        let previous = array_reference_field(&manifest, manifest_field)?;
        let object = storage
            .objects
            .get(&previous)
            .cloned()
            .ok_or(ErasureErrorV1::ProvenanceMissing)?;
        let changed_object = replace_array_field(&object, object_field, replacement)?;
        let changed_reference = addressed(object_tag, &changed_object);
        storage.objects.remove(&previous);
        storage.objects.insert(changed_reference, changed_object);
        let changed_manifest = replace_array_field(
            &manifest,
            manifest_field,
            Value::Bytes(changed_reference.digest().to_vec()),
        )?;
        storage.manifests.insert(
            request,
            (addressed("ERCRP1", &changed_manifest), changed_manifest),
        );
        Ok(())
    }

    /// Insert one deliberately selected immutable object for recovery tests.
    pub fn insert_object(&self, reference: ErasureReferenceV1, canonical_cbor: Vec<u8>) {
        self.storage
            .borrow_mut()
            .objects
            .insert(reference, canonical_cbor);
    }

    /// Replace one field in the single completed attempt page and re-address
    /// the page, its index entry, and the manifest history head.
    ///
    /// # Errors
    ///
    /// Returns a closed error when the page or manifest is absent or malformed.
    pub fn replace_attempt_page_field(
        &self,
        request: ErasureReferenceV1,
        ordinal: u64,
        index: usize,
        replacement: Value,
    ) -> Result<(), ErasureErrorV1> {
        replace_attempt_page_field(
            &mut self.storage.borrow_mut(),
            request,
            ordinal,
            index,
            replacement,
        )
    }

    /// Replace and re-address one attempt component, then repair the page link.
    ///
    /// # Errors
    ///
    /// Returns a closed error when the component, page, or manifest is absent
    /// or malformed.
    pub fn replace_attempt_component_field(
        &self,
        request: ErasureReferenceV1,
        ordinal: u64,
        page_field: usize,
        object_tag: &str,
        object_field: usize,
        replacement: Value,
    ) -> Result<(), ErasureErrorV1> {
        let mut storage = self.storage.borrow_mut();
        let page = *storage
            .attempts
            .get(&(request, ordinal))
            .ok_or(ErasureErrorV1::ProvenanceMissing)?;
        let page_bytes = storage
            .objects
            .get(&page)
            .ok_or(ErasureErrorV1::ProvenanceMissing)?;
        let component = array_reference_field(page_bytes, page_field)?;
        let component_bytes = storage
            .objects
            .get(&component)
            .cloned()
            .ok_or(ErasureErrorV1::ProvenanceMissing)?;
        let changed = replace_array_field(&component_bytes, object_field, replacement)?;
        let changed_reference = addressed(object_tag, &changed);
        storage.objects.remove(&component);
        storage.objects.insert(changed_reference, changed);
        replace_attempt_page_field(
            &mut storage,
            request,
            ordinal,
            page_field,
            Value::Bytes(changed_reference.digest().to_vec()),
        )
    }

    pub fn remove_object(&self, reference: ErasureReferenceV1) {
        self.storage.borrow_mut().objects.remove(&reference);
    }

    pub fn remove_state(&self, reference: ErasureReferenceV1) {
        self.storage.borrow_mut().states.remove(&reference);
    }

    pub fn remove_attempt_page(&self, request: ErasureReferenceV1, ordinal: u64) {
        self.storage
            .borrow_mut()
            .attempts
            .remove(&(request, ordinal));
    }

    pub fn remove_scope_node(&self, request: ErasureReferenceV1, ordinal: u64) {
        self.storage.borrow_mut().scopes.remove(&(request, ordinal));
    }

    pub fn remove_resolution(&self, request: ErasureReferenceV1, ordinal: u64) {
        self.storage
            .borrow_mut()
            .resolutions
            .remove(&(request, ordinal));
    }

    fn verify_delta_exists(
        storage: &RawStorage,
        mutation: &pos_core::PreparedErasureCasV1,
    ) -> Result<(), ErasureErrorV1> {
        for object in mutation.new_objects() {
            if storage.objects.get(&object.reference()).map(Vec::as_slice)
                != Some(object.canonical_cbor())
            {
                return Err(ErasureErrorV1::ProvenanceMissing);
            }
        }
        for state in mutation.new_states() {
            if storage.states.get(&state.reference()).map(Vec::as_slice)
                != Some(state.canonical_cbor())
            {
                return Err(ErasureErrorV1::ProvenanceMissing);
            }
        }
        for index in mutation.index_inserts() {
            let (map, ordinal, reference) = match *index {
                ErasureIndexInsertV1::AttemptPage { ordinal, reference } => {
                    (&storage.attempts, ordinal, reference)
                }
                ErasureIndexInsertV1::ScopeNode { ordinal, reference } => {
                    (&storage.scopes, ordinal, reference)
                }
                ErasureIndexInsertV1::AdministrativeResolution { ordinal, reference } => {
                    (&storage.resolutions, ordinal, reference)
                }
            };
            if map.get(&(mutation.request(), ordinal)) != Some(&reference) {
                return Err(ErasureErrorV1::ProvenanceMissing);
            }
        }
        let effect = storage
            .effects
            .get(&mutation.next_manifest().digest())
            .ok_or(ErasureErrorV1::ProvenanceMissing)
            .and_then(|bytes| pos_core::ErasureCasEffectV1::from_canonical_cbor(bytes))?;
        if &effect != mutation.effect()
            || mutation.effect().subject().is_some_and(|subject| {
                storage.effect_subjects.get(&subject) != Some(&mutation.next_manifest().digest())
            })
        {
            return Err(ErasureErrorV1::ProvenanceMissing);
        }
        Ok(())
    }
}

fn insert_exact(
    map: &mut BTreeMap<ErasureReferenceV1, Vec<u8>>,
    reference: ErasureReferenceV1,
    bytes: &[u8],
) -> Result<(), ErasureErrorV1> {
    match map.get(&reference) {
        Some(existing) if existing.as_slice() != bytes => Err(ErasureErrorV1::ProvenanceMissing),
        Some(_) => Ok(()),
        None => {
            map.insert(reference, bytes.to_vec());
            Ok(())
        }
    }
}

fn insert_index(
    map: &mut BTreeMap<(ErasureReferenceV1, u64), ErasureReferenceV1>,
    request: ErasureReferenceV1,
    ordinal: u64,
    reference: ErasureReferenceV1,
) -> Result<(), ErasureErrorV1> {
    match map.get(&(request, ordinal)) {
        Some(existing) if *existing != reference => Err(ErasureErrorV1::PolicyConflict),
        Some(_) => Ok(()),
        None => {
            map.insert((request, ordinal), reference);
            Ok(())
        }
    }
}

fn index_count(
    map: &BTreeMap<(ErasureReferenceV1, u64), ErasureReferenceV1>,
    request: ErasureReferenceV1,
) -> u64 {
    u64::try_from(
        map.keys()
            .filter(|(candidate, _)| *candidate == request)
            .count(),
    )
    .unwrap_or(u64::MAX)
}

impl ErasureStateResolverV1 for PublicCoordinatorPort {
    fn resolve_state(
        &self,
        digest: ErasureReferenceV1,
    ) -> Result<Option<ErasureStateV1>, ErasureErrorV1> {
        self.maybe_fail(PublicCoordinatorOperation::ResolveState)?;
        self.storage
            .borrow()
            .states
            .get(&digest)
            .map(|bytes| {
                ErasureStateV1::from_canonical_cbor(bytes).and_then(|state| {
                    (state.state_digest() == digest)
                        .then_some(state)
                        .ok_or(ErasureErrorV1::ProvenanceMissing)
                })
            })
            .transpose()
    }
}

impl ErasurePersistencePortV1 for PublicCoordinatorPort {
    fn read_manifest(
        &self,
        request: ErasureReferenceV1,
    ) -> Result<Option<pos_core::StoredErasureManifestV1>, ErasureErrorV1> {
        self.maybe_fail(PublicCoordinatorOperation::LoadManifest)?;
        Ok(self.current_manifest(request))
    }

    fn read_object(&self, reference: ErasureReferenceV1) -> Result<Vec<u8>, ErasureErrorV1> {
        self.maybe_fail(PublicCoordinatorOperation::ReadObject)?;
        self.storage
            .borrow()
            .objects
            .get(&reference)
            .cloned()
            .ok_or(ErasureErrorV1::ProvenanceMissing)
    }

    fn read_effect(
        &self,
        manifest: ErasureReferenceV1,
    ) -> Result<pos_core::ErasureCasEffectV1, ErasureErrorV1> {
        self.maybe_fail(PublicCoordinatorOperation::ReadEffect)?;
        self.storage
            .borrow()
            .effects
            .get(&manifest)
            .ok_or(ErasureErrorV1::ProvenanceMissing)
            .and_then(|bytes| pos_core::ErasureCasEffectV1::from_canonical_cbor(bytes))
    }

    fn effect_manifest(
        &self,
        subject: ErasureReferenceV1,
    ) -> Result<Option<ErasureReferenceV1>, ErasureErrorV1> {
        self.maybe_fail(PublicCoordinatorOperation::EffectManifest)?;
        Ok(self.storage.borrow().effect_subjects.get(&subject).copied())
    }

    fn attempt_page_ref(
        &self,
        request: ErasureReferenceV1,
        ordinal: u64,
    ) -> Result<Option<ErasureReferenceV1>, ErasureErrorV1> {
        self.maybe_fail(PublicCoordinatorOperation::AttemptPageRef)?;
        Ok(self
            .storage
            .borrow()
            .attempts
            .get(&(request, ordinal))
            .copied())
    }

    fn attempt_index_count(&self, request: ErasureReferenceV1) -> Result<u64, ErasureErrorV1> {
        self.maybe_fail(PublicCoordinatorOperation::AttemptIndexCount)?;
        Ok(index_count(&self.storage.borrow().attempts, request))
    }

    fn scope_node_ref(
        &self,
        request: ErasureReferenceV1,
        ordinal: u64,
    ) -> Result<Option<ErasureReferenceV1>, ErasureErrorV1> {
        self.maybe_fail(PublicCoordinatorOperation::ScopeNodeRef)?;
        Ok(self
            .storage
            .borrow()
            .scopes
            .get(&(request, ordinal))
            .copied())
    }

    fn scope_index_count(&self, request: ErasureReferenceV1) -> Result<u64, ErasureErrorV1> {
        self.maybe_fail(PublicCoordinatorOperation::ScopeIndexCount)?;
        Ok(index_count(&self.storage.borrow().scopes, request))
    }

    fn administrative_resolution_ref(
        &self,
        request: ErasureReferenceV1,
        ordinal: u64,
    ) -> Result<Option<ErasureReferenceV1>, ErasureErrorV1> {
        self.maybe_fail(PublicCoordinatorOperation::ResolutionRef)?;
        Ok(self
            .storage
            .borrow()
            .resolutions
            .get(&(request, ordinal))
            .copied())
    }

    fn administrative_resolution_index_count(
        &self,
        request: ErasureReferenceV1,
    ) -> Result<u64, ErasureErrorV1> {
        self.maybe_fail(PublicCoordinatorOperation::ResolutionIndexCount)?;
        Ok(index_count(&self.storage.borrow().resolutions, request))
    }

    fn compare_and_swap(
        &mut self,
        mutation: pos_core::PreparedErasureCasV1,
    ) -> Result<ErasureCasOutcomeV1, ErasureErrorV1> {
        self.maybe_fail(PublicCoordinatorOperation::CompareAndSwap)?;
        *self.last_mutation.borrow_mut() = Some(mutation.clone());
        if self.config.fail_commits {
            return Err(ErasureErrorV1::ReceiptCommitFailed);
        }
        let request = mutation.request();
        let next = mutation.next_manifest();
        let mut storage = self.storage.borrow_mut();
        if storage
            .manifests
            .get(&request)
            .is_some_and(|(digest, bytes)| {
                *digest == next.digest() && bytes.as_slice() == next.canonical_cbor()
            })
        {
            Self::verify_delta_exists(&storage, &mutation)?;
            return Ok(ErasureCasOutcomeV1::ExactRetry);
        }
        if storage.manifests.get(&request).map(|value| value.0)
            != mutation.expected_manifest_digest()
        {
            return Err(ErasureErrorV1::PolicyConflict);
        }

        let mut staged = RawStorage {
            manifests: storage.manifests.clone(),
            objects: storage.objects.clone(),
            states: storage.states.clone(),
            attempts: storage.attempts.clone(),
            scopes: storage.scopes.clone(),
            resolutions: storage.resolutions.clone(),
            effects: storage.effects.clone(),
            effect_subjects: storage.effect_subjects.clone(),
        };
        for object in mutation.new_objects() {
            insert_exact(
                &mut staged.objects,
                object.reference(),
                object.canonical_cbor(),
            )?;
        }
        for state in mutation.new_states() {
            if let Some(previous) = state.state().previous_state() {
                let bytes = staged
                    .states
                    .get(&previous)
                    .ok_or(ErasureErrorV1::ProvenanceMissing)?;
                state
                    .state()
                    .validate_predecessor(&ErasureStateV1::from_canonical_cbor(bytes)?)?;
            }
            insert_exact(
                &mut staged.states,
                state.reference(),
                state.canonical_cbor(),
            )?;
        }
        for index in mutation.index_inserts() {
            match *index {
                ErasureIndexInsertV1::AttemptPage { ordinal, reference } => {
                    insert_index(&mut staged.attempts, request, ordinal, reference)?;
                }
                ErasureIndexInsertV1::ScopeNode { ordinal, reference } => {
                    insert_index(&mut staged.scopes, request, ordinal, reference)?;
                }
                ErasureIndexInsertV1::AdministrativeResolution { ordinal, reference } => {
                    insert_index(&mut staged.resolutions, request, ordinal, reference)?;
                }
            }
        }
        staged
            .manifests
            .insert(request, (next.digest(), next.canonical_cbor().to_vec()));
        insert_exact(
            &mut staged.effects,
            next.digest(),
            &mutation.effect().to_canonical_cbor()?,
        )?;
        if let Some(subject) = mutation.effect().subject() {
            match staged.effect_subjects.get(&subject) {
                Some(existing) if *existing != next.digest() => {
                    return Err(ErasureErrorV1::PolicyConflict);
                }
                Some(_) => {}
                None => {
                    staged.effect_subjects.insert(subject, next.digest());
                }
            }
        }
        *storage = staged;
        Ok(ErasureCasOutcomeV1::Applied)
    }
}

impl ErasureFreezeAuthorizationVerifierV1 for PublicCoordinatorPort {
    fn validate_freeze_authorization(
        &self,
        admission: &ErasureFreezeAdmissionEvidenceV1,
        authorization: &ErasureFreezeAuthorizationEvidenceV1,
    ) -> Result<(), ErasureErrorV1> {
        self.maybe_fail(PublicCoordinatorOperation::ValidateFreezeAuthorization)?;
        authorization.verify_admission_body_binding(admission)
    }
}

impl ErasureCoordinatorPortV1 for PublicCoordinatorPort {
    fn authenticate(&self, _request: &ErasureRequestV1) -> Result<(), ErasureErrorV1> {
        Ok(())
    }

    fn admit_authorization(
        &self,
        _request: ErasureReferenceV1,
        _provenance: ErasureReferenceV1,
        _decision: ErasureAuthorizationDecisionV1,
    ) -> Result<(), ErasureErrorV1> {
        self.maybe_fail(PublicCoordinatorOperation::AdmitAuthorization)?;
        Ok(())
    }

    fn admit_corrected_submission(
        &self,
        _request: &ErasureRequestV1,
        _correction: &pos_core::ErasureCorrectionProvenanceV1,
    ) -> Result<(), ErasureErrorV1> {
        self.maybe_fail(PublicCoordinatorOperation::AdmitCorrectedSubmission)?;
        Ok(())
    }

    fn admit_atomic_freeze(
        &self,
        request: ErasureReferenceV1,
        _requested: &ErasureStateTransitionV1,
    ) -> Result<ErasureAtomicFreezeResultV1, ErasureErrorV1> {
        self.maybe_fail(PublicCoordinatorOperation::AdmitAtomicFreeze)?;
        if let Some((error, authorization_provenance)) = self.config.freeze_rejection {
            return ErasureFreezeFailureV1::new(pos_core::ErasureFreezeFailureInputV1 {
                request,
                error,
                authorization_provenance,
                evidence: self.config.freeze_evidence,
            })
            .map(ErasureAtomicFreezeResultV1::Rejected);
        }
        let mut obligations = self
            .config
            .targets
            .iter()
            .copied()
            .map(|target| {
                ErasureObligationV1::new(ErasureObligationInputV1 {
                    category: ErasureInventoryCategoryV1::Artifact,
                    target,
                    owner: target.replica_id,
                    command_identity: pos_core::erasure::destruction_command_reference(
                        request, target,
                    ),
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        obligations.sort_unstable_by_key(ErasureObligationV1::reference);
        let obligation_set = ErasureObligationSetV1::new(ErasureObligationSetInputV1 {
            request,
            obligations: obligations
                .iter()
                .map(ErasureObligationV1::reference)
                .collect(),
            policy: self.config.policy,
            trust: self.config.trust,
        })?;
        let scope = ErasureScopeCommitmentInputV1 {
            request,
            scope_members: vec![self.config.scope_member],
            target_closure: target_closure_digest(&self.config.targets),
            lineage_rule: self.config.lineage_rule,
        };
        let scope_reference = ErasureScopeCommitmentV1::new(scope.clone())?.reference();
        let evidence = self.config.freeze_evidence.digest();
        let (freeze_admission_evidence, freeze_authorization_evidence) =
            freeze_evidence_fixture(FreezeEvidenceFixtureInput {
                request,
                scope_commitment: scope_reference,
                obligation_set: &obligation_set,
                targets: &self.config.targets,
                obligations: &obligations,
                freeze_position: 10,
                evidence: &evidence,
            })?;
        ErasureAtomicFreezeAdmissionV1::new(ErasureAtomicFreezeAdmissionInputV1 {
            targets: self.config.targets.clone(),
            scope,
            obligations,
            obligation_set,
            freeze_position: 10,
            freeze_admission_evidence,
            freeze_authorization_evidence,
        })
        .map(Box::new)
        .map(ErasureAtomicFreezeResultV1::Admitted)
    }

    fn admit_scope_extension(
        &self,
        _extension: &ErasureScopeExtensionV1,
    ) -> Result<(), ErasureErrorV1> {
        self.maybe_fail(PublicCoordinatorOperation::AdmitScopeExtension)?;
        Ok(())
    }

    fn admit_administrative_resolution(
        &self,
        _resolution: &ErasureAdministrativeResolutionV1,
    ) -> Result<(), ErasureErrorV1> {
        self.maybe_fail(PublicCoordinatorOperation::AdmitAdministrativeResolution)?;
        Ok(())
    }

    fn dispatch_destruction(
        &self,
        _request: ErasureReferenceV1,
        _commands: &[ErasureDestructionCommandV1],
    ) -> Result<(), ErasureErrorV1> {
        Ok(())
    }

    fn admit_attempt(
        &self,
        admission: &ErasureRetryAdmissionV1,
    ) -> Result<ErasureAttemptQuotaReservationV1, ErasureErrorV1> {
        self.maybe_fail(PublicCoordinatorOperation::AdmitAttempt)?;
        *self.attempt_admissions.borrow_mut() += 1;
        Ok(ErasureAttemptQuotaReservationV1::new(
            admission.reference(),
            admission.reference(),
        ))
    }

    fn admit_acknowledgement(
        &self,
        _acknowledgement: &ErasureAcknowledgementProvenanceV1,
    ) -> Result<(), ErasureErrorV1> {
        self.maybe_fail(PublicCoordinatorOperation::AdmitAcknowledgement)?;
        Ok(())
    }

    fn admit_receipt(&self, _input: &ErasureReceiptInputV1) -> Result<(), ErasureErrorV1> {
        self.maybe_fail(PublicCoordinatorOperation::AdmitReceipt)?;
        Ok(())
    }
}
