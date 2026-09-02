//! Bounded, core-owned ERCRP1 persistence graph.

use super::codec::{
    bytes32, digest, optional_bytes32, optional_digest, references_value, target_from_value,
    target_value, text, uint, unordered_references_from_value, unsigned,
};
use super::{
    decode_limited, domain_digest, encode_limited, exact_array, verify_predecessor_chain, BTreeMap,
    BTreeSet, ErasureAcknowledgementOutcomeV1, ErasureAcknowledgementProvenanceV1,
    ErasureAdministrativeResolutionV1, ErasureAttemptOutcomeV1, ErasureAuthorizationRejectionV1,
    ErasureCasEffectV1, ErasureCorrectionProvenanceV1, ErasureErrorV1,
    ErasureFreezeAdmissionEvidenceV1, ErasureFreezeAuthorizationEvidenceV1,
    ErasureFreezeAuthorizationVerifierV1, ErasureFreezeFailureV1, ErasureFreezeProvenanceV1,
    ErasureIndexInsertV1, ErasureObligationSetV1, ErasureObligationV1, ErasurePersistedStateV1,
    ErasurePersistenceObjectV1, ErasurePersistencePortV1, ErasureReceiptProvenanceV1,
    ErasureReceiptV1, ErasureReferenceV1, ErasureRequestV1, ErasureRequiredTargetV1,
    ErasureRetryAdmissionV1, ErasureScopeCommitmentV1, ErasureScopeExtensionV1, ErasureStateV1,
    PreparedErasureCasV1, StoredErasureManifestV1, ERASURE_ACKNOWLEDGEMENT_INVENTORY_TAG_V1,
    ERASURE_ADMINISTRATIVE_RESOLUTION_TAG_V1, ERASURE_ATTEMPT_HISTORY_TAG_V1,
    ERASURE_AUTHORIZATION_REJECTION_TAG_V1, ERASURE_COORDINATOR_RECORD_MAX_BYTES,
    ERASURE_CORRECTION_PROVENANCE_TAG_V1, ERASURE_FREEZE_ADMISSION_AUTHORIZATION_TAG_V1,
    ERASURE_FREEZE_ADMISSION_EVIDENCE_TAG_V1, ERASURE_FREEZE_AUTHORIZATION_EVIDENCE_TAG_V1,
    ERASURE_FREEZE_FAILURE_TAG_V1, ERASURE_FREEZE_PROVENANCE_TAG_V1,
    ERASURE_MAX_ACKNOWLEDGEMENTS_PER_ATTEMPT, ERASURE_MAX_ADMINISTRATIVE_RESOLUTIONS,
    ERASURE_MAX_ATTEMPT_OUTCOMES, ERASURE_MAX_SCOPE_EXTENSIONS, ERASURE_MAX_TARGETS,
    ERASURE_OBLIGATION_SET_TAG_V1, ERASURE_OBLIGATION_TAG_V1, ERASURE_PORTABLE_RECORD_MAX_BYTES,
    ERASURE_RECEIPT_PROVENANCE_TAG_V1, ERASURE_RETRY_ADMISSION_TAG_V1,
    ERASURE_SCOPE_EXTENSION_HEAD_TAG_V1, ERASURE_SCOPE_EXTENSION_TAG_V1,
    ERASURE_TARGET_CLOSURE_TAG_V1, ERCRP1, ERQ1, VERSION,
};
use ciborium::value::Value;

const INVENTORY_ADMITTED: u64 = 0;
const INVENTORY_EFFECTIVE: u64 = 1;

#[derive(Clone, Debug, Eq, PartialEq)]
struct ManifestV1 {
    request: ErasureReferenceV1,
    state: ErasureReferenceV1,
    target_closure: Option<ErasureReferenceV1>,
    correction: Option<ErasureReferenceV1>,
    rejection: Option<ErasureReferenceV1>,
    scope: Option<ErasureReferenceV1>,
    freeze_admission: Option<ErasureReferenceV1>,
    freeze_authorization: Option<ErasureReferenceV1>,
    freeze_provenance: Option<ErasureReferenceV1>,
    freeze_failure: Option<ErasureReferenceV1>,
    obligation_set: Option<ErasureReferenceV1>,
    scope_extension_head: Option<ErasureReferenceV1>,
    active: Option<ActiveAttemptRefV1>,
    attempt_history_head: Option<ErasureReferenceV1>,
    completed_attempt_count: u64,
    latest_receipt: Option<ErasureReferenceV1>,
    administrative_resolution_head: Option<ErasureReferenceV1>,
    authorize_provenance: Option<ErasureReferenceV1>,
    dispatch_provenance: Option<ErasureReferenceV1>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ActiveAttemptRefV1 {
    ordinal: u64,
    admission: ErasureReferenceV1,
    acknowledgements: Vec<ErasureReferenceV1>,
}

impl ManifestV1 {
    fn decode(bytes: &[u8]) -> Result<Self, ErasureErrorV1> {
        decode_limited(
            bytes,
            ERASURE_COORDINATOR_RECORD_MAX_BYTES,
            ERASURE_MAX_ACKNOWLEDGEMENTS_PER_ATTEMPT,
        )
        .and_then(|value| {
            let fields = exact_array(&value, 21)?;
            super::header(fields, ERCRP1)?;
            let active = match &fields[14] {
                Value::Null => None,
                value => {
                    let fields = exact_array(value, 3)?;
                    Some(ActiveAttemptRefV1 {
                        ordinal: unsigned(&fields[0])?,
                        admission: bytes32(&fields[1])?,
                        acknowledgements: unordered_references_from_value(
                            &fields[2],
                            ERASURE_MAX_ACKNOWLEDGEMENTS_PER_ATTEMPT,
                        )?,
                    })
                }
            };
            let manifest = Self {
                request: bytes32(&fields[2])?,
                state: bytes32(&fields[3])?,
                target_closure: optional_bytes32(&fields[4])?,
                correction: optional_bytes32(&fields[5])?,
                rejection: optional_bytes32(&fields[6])?,
                scope: optional_bytes32(&fields[7])?,
                freeze_admission: optional_bytes32(&fields[8])?,
                freeze_authorization: optional_bytes32(&fields[9])?,
                freeze_provenance: optional_bytes32(&fields[10])?,
                freeze_failure: optional_bytes32(&fields[11])?,
                obligation_set: optional_bytes32(&fields[12])?,
                scope_extension_head: optional_bytes32(&fields[13])?,
                active,
                attempt_history_head: optional_bytes32(&fields[15])?,
                completed_attempt_count: unsigned(&fields[16])?,
                latest_receipt: optional_bytes32(&fields[17])?,
                administrative_resolution_head: optional_bytes32(&fields[18])?,
                authorize_provenance: optional_bytes32(&fields[19])?,
                dispatch_provenance: optional_bytes32(&fields[20])?,
            };
            manifest.validate_shape()?;
            Ok(manifest)
        })
    }

    fn validate_shape(&self) -> Result<(), ErasureErrorV1> {
        if self.completed_attempt_count > ERASURE_MAX_ATTEMPT_OUTCOMES as u64
            || (self.completed_attempt_count == 0) != self.attempt_history_head.is_none()
            || self
                .active
                .as_ref()
                .is_some_and(|active| active.ordinal != self.completed_attempt_count)
        {
            return Err(ErasureErrorV1::ProvenanceMissing);
        }
        Ok(())
    }

    fn canonical_cbor(&self) -> Result<Vec<u8>, ErasureErrorV1> {
        let active = self.active.as_ref().map_or(Value::Null, |active| {
            Value::Array(vec![
                uint(active.ordinal),
                digest(active.admission),
                references_value(&active.acknowledgements),
            ])
        });
        encode_limited(
            &Value::Array(vec![
                text(ERCRP1),
                uint(VERSION),
                digest(self.request),
                digest(self.state),
                optional_digest(self.target_closure),
                optional_digest(self.correction),
                optional_digest(self.rejection),
                optional_digest(self.scope),
                optional_digest(self.freeze_admission),
                optional_digest(self.freeze_authorization),
                optional_digest(self.freeze_provenance),
                optional_digest(self.freeze_failure),
                optional_digest(self.obligation_set),
                optional_digest(self.scope_extension_head),
                active,
                optional_digest(self.attempt_history_head),
                uint(self.completed_attempt_count),
                optional_digest(self.latest_receipt),
                optional_digest(self.administrative_resolution_head),
                optional_digest(self.authorize_provenance),
                optional_digest(self.dispatch_provenance),
            ]),
            ERASURE_COORDINATOR_RECORD_MAX_BYTES,
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct TargetClosureV1 {
    request: ErasureReferenceV1,
    targets: Vec<ErasureRequiredTargetV1>,
    reference: ErasureReferenceV1,
}

impl TargetClosureV1 {
    fn new(
        request: ErasureReferenceV1,
        targets: Vec<ErasureRequiredTargetV1>,
    ) -> Result<Self, ErasureErrorV1> {
        if targets.len() > ERASURE_MAX_TARGETS || targets.windows(2).any(|pair| pair[0] >= pair[1])
        {
            return Err(ErasureErrorV1::ScopeInvalid);
        }
        let mut value = Self {
            request,
            targets,
            reference: super::reference_zero(),
        };
        let bytes = value.canonical_cbor()?;
        value.reference = addressed(ERASURE_TARGET_CLOSURE_TAG_V1, &bytes);
        Ok(value)
    }

    fn canonical_cbor(&self) -> Result<Vec<u8>, ErasureErrorV1> {
        encode_limited(
            &Value::Array(vec![
                text(ERASURE_TARGET_CLOSURE_TAG_V1),
                uint(VERSION),
                digest(self.request),
                Value::Array(self.targets.iter().map(target_value).collect()),
            ]),
            ERASURE_PORTABLE_RECORD_MAX_BYTES,
        )
    }

    fn decode(bytes: &[u8]) -> Result<Self, ErasureErrorV1> {
        decode_limited(
            bytes,
            ERASURE_PORTABLE_RECORD_MAX_BYTES,
            ERASURE_MAX_TARGETS,
        )
        .and_then(|value| {
            let fields = exact_array(&value, 4)?;
            super::header(fields, ERASURE_TARGET_CLOSURE_TAG_V1)?;
            let values = exact_bounded_array(&fields[3], ERASURE_MAX_TARGETS)?;
            let targets = values
                .iter()
                .map(target_from_value)
                .collect::<Result<Vec<_>, _>>()?;
            let closure = Self::new(bytes32(&fields[2])?, targets)?;
            (closure.canonical_cbor()?.as_slice() == bytes)
                .then_some(closure)
                .ok_or(ErasureErrorV1::InvalidEncoding)
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct InventoryV1 {
    request: ErasureReferenceV1,
    ordinal: u64,
    kind: u64,
    references: Vec<ErasureReferenceV1>,
    reference: ErasureReferenceV1,
}

impl InventoryV1 {
    fn new(
        request: ErasureReferenceV1,
        ordinal: u64,
        kind: u64,
        references: Vec<ErasureReferenceV1>,
    ) -> Result<Self, ErasureErrorV1> {
        if kind > INVENTORY_EFFECTIVE || references.len() > ERASURE_MAX_ACKNOWLEDGEMENTS_PER_ATTEMPT
        {
            return Err(ErasureErrorV1::ScopeInvalid);
        }
        let mut value = Self {
            request,
            ordinal,
            kind,
            references,
            reference: super::reference_zero(),
        };
        let bytes = value.canonical_cbor()?;
        value.reference = addressed(ERASURE_ACKNOWLEDGEMENT_INVENTORY_TAG_V1, &bytes);
        Ok(value)
    }

    fn canonical_cbor(&self) -> Result<Vec<u8>, ErasureErrorV1> {
        encode_limited(
            &Value::Array(vec![
                text(ERASURE_ACKNOWLEDGEMENT_INVENTORY_TAG_V1),
                uint(VERSION),
                digest(self.request),
                uint(self.ordinal),
                uint(self.kind),
                references_value(&self.references),
            ]),
            ERASURE_PORTABLE_RECORD_MAX_BYTES,
        )
    }

    fn decode(bytes: &[u8]) -> Result<Self, ErasureErrorV1> {
        decode_limited(
            bytes,
            ERASURE_PORTABLE_RECORD_MAX_BYTES,
            ERASURE_MAX_ACKNOWLEDGEMENTS_PER_ATTEMPT,
        )
        .and_then(|value| {
            let fields = exact_array(&value, 6)?;
            super::header(fields, ERASURE_ACKNOWLEDGEMENT_INVENTORY_TAG_V1)?;
            let inventory = Self::new(
                bytes32(&fields[2])?,
                unsigned(&fields[3])?,
                unsigned(&fields[4])?,
                unordered_references_from_value(
                    &fields[5],
                    ERASURE_MAX_ACKNOWLEDGEMENTS_PER_ATTEMPT,
                )?,
            )?;
            (inventory.canonical_cbor()?.as_slice() == bytes)
                .then_some(inventory)
                .ok_or(ErasureErrorV1::InvalidEncoding)
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct AttemptPageV1 {
    request: ErasureReferenceV1,
    ordinal: u64,
    retry_admission: ErasureReferenceV1,
    admitted_inventory: ErasureReferenceV1,
    effective_inventory: ErasureReferenceV1,
    outcome: ErasureReferenceV1,
    receipt: ErasureReferenceV1,
    receipt_provenance: ErasureReferenceV1,
    terminal_state: ErasureReferenceV1,
    predecessor: Option<ErasureReferenceV1>,
    reference: ErasureReferenceV1,
}

impl AttemptPageV1 {
    fn canonical_cbor(&self) -> Result<Vec<u8>, ErasureErrorV1> {
        encode_limited(
            &Value::Array(vec![
                text(ERASURE_ATTEMPT_HISTORY_TAG_V1),
                uint(VERSION),
                digest(self.request),
                uint(self.ordinal),
                digest(self.retry_admission),
                digest(self.admitted_inventory),
                digest(self.effective_inventory),
                digest(self.outcome),
                digest(self.receipt),
                digest(self.receipt_provenance),
                digest(self.terminal_state),
                optional_digest(self.predecessor),
            ]),
            ERASURE_PORTABLE_RECORD_MAX_BYTES,
        )
    }

    fn decode(bytes: &[u8]) -> Result<Self, ErasureErrorV1> {
        decode_limited(bytes, ERASURE_PORTABLE_RECORD_MAX_BYTES, 12).and_then(|value| {
            let fields = exact_array(&value, 12)?;
            super::header(fields, ERASURE_ATTEMPT_HISTORY_TAG_V1)?;
            Ok(Self {
                request: bytes32(&fields[2])?,
                ordinal: unsigned(&fields[3])?,
                retry_admission: bytes32(&fields[4])?,
                admitted_inventory: bytes32(&fields[5])?,
                effective_inventory: bytes32(&fields[6])?,
                outcome: bytes32(&fields[7])?,
                receipt: bytes32(&fields[8])?,
                receipt_provenance: bytes32(&fields[9])?,
                terminal_state: bytes32(&fields[10])?,
                predecessor: optional_bytes32(&fields[11])?,
                reference: addressed(ERASURE_ATTEMPT_HISTORY_TAG_V1, bytes),
            })
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ScopeNodeV1 {
    request: ErasureReferenceV1,
    scope: ErasureReferenceV1,
    extension: ErasureReferenceV1,
    ordinal: u64,
    predecessor: Option<ErasureReferenceV1>,
    reference: ErasureReferenceV1,
}

impl ScopeNodeV1 {
    fn canonical_cbor(&self) -> Result<Vec<u8>, ErasureErrorV1> {
        encode_limited(
            &Value::Array(vec![
                text(ERASURE_SCOPE_EXTENSION_HEAD_TAG_V1),
                uint(VERSION),
                digest(self.request),
                digest(self.scope),
                digest(self.extension),
                uint(self.ordinal),
                optional_digest(self.predecessor),
            ]),
            ERASURE_PORTABLE_RECORD_MAX_BYTES,
        )
    }

    fn decode(bytes: &[u8]) -> Result<Self, ErasureErrorV1> {
        decode_limited(bytes, ERASURE_PORTABLE_RECORD_MAX_BYTES, 7).and_then(|value| {
            let fields = exact_array(&value, 7)?;
            super::header(fields, ERASURE_SCOPE_EXTENSION_HEAD_TAG_V1)?;
            Ok(Self {
                request: bytes32(&fields[2])?,
                scope: bytes32(&fields[3])?,
                extension: bytes32(&fields[4])?,
                ordinal: unsigned(&fields[5])?,
                predecessor: optional_bytes32(&fields[6])?,
                reference: addressed(ERASURE_SCOPE_EXTENSION_HEAD_TAG_V1, bytes),
            })
        })
    }
}

fn addressed(tag: &str, bytes: &[u8]) -> ErasureReferenceV1 {
    ErasureReferenceV1::from_digest(domain_digest(tag, bytes))
}

fn exact_bounded_array(value: &Value, maximum: usize) -> Result<&[Value], ErasureErrorV1> {
    match value {
        Value::Array(values) if values.len() <= maximum => Ok(values),
        _ => Err(ErasureErrorV1::InvalidEncoding),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RecoveredScopeHeadV1 {
    pub(crate) node: ErasureReferenceV1,
    pub(crate) extension: ErasureReferenceV1,
    pub(crate) ordinal: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RecoveredAttemptV1 {
    pub(crate) ordinal: u64,
    pub(crate) admission: ErasureRetryAdmissionV1,
    pub(crate) admitted:
        BTreeMap<(ErasureReferenceV1, ErasureReferenceV1), ErasureAcknowledgementProvenanceV1>,
}

/// Bounded working state returned only after the complete persistence graph verifies.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RecoveredErasureV1 {
    manifest: ManifestV1,
    pub(crate) manifest_digest: ErasureReferenceV1,
    pub(crate) request: ErasureRequestV1,
    pub(crate) state: ErasureStateV1,
    pub(crate) targets: Vec<ErasureRequiredTargetV1>,
    pub(crate) correction: Option<ErasureCorrectionProvenanceV1>,
    pub(crate) rejection: Option<ErasureAuthorizationRejectionV1>,
    pub(crate) scope: Option<ErasureScopeCommitmentV1>,
    pub(crate) freeze_admission: Option<ErasureFreezeAdmissionEvidenceV1>,
    pub(crate) freeze_authorization: Option<ErasureFreezeAuthorizationEvidenceV1>,
    pub(crate) freeze_provenance: Option<ErasureFreezeProvenanceV1>,
    pub(crate) freeze_failure: Option<ErasureFreezeFailureV1>,
    pub(crate) obligation_set: Option<ErasureObligationSetV1>,
    pub(crate) obligations: Vec<ErasureObligationV1>,
    pub(crate) active: Option<RecoveredAttemptV1>,
    pub(crate) effective:
        BTreeMap<(ErasureReferenceV1, ErasureReferenceV1), ErasureAcknowledgementProvenanceV1>,
    pub(crate) attempt_history_head: Option<ErasureReferenceV1>,
    pub(crate) completed_attempt_count: u64,
    pub(crate) latest_receipt: Option<ErasureReferenceV1>,
    pub(crate) scope_head: Option<RecoveredScopeHeadV1>,
    pub(crate) administrative_resolution_head: Option<ErasureReferenceV1>,
    pub(crate) administrative_resolution_count: u64,
    pub(crate) authorize_provenance: Option<ErasureReferenceV1>,
    pub(crate) dispatch_provenance: Option<ErasureReferenceV1>,
}

fn load<T>(
    port: &dyn ErasurePersistencePortV1,
    reference: ErasureReferenceV1,
    decode: impl FnOnce(&[u8]) -> Result<T, ErasureErrorV1>,
    address: impl FnOnce(&T) -> ErasureReferenceV1,
) -> Result<T, ErasureErrorV1> {
    port.read_object(reference).and_then(|bytes| {
        decode(&bytes).and_then(|value| {
            (address(&value) == reference)
                .then_some(value)
                .ok_or(ErasureErrorV1::ProvenanceMissing)
        })
    })
}

fn optional<T>(
    port: &dyn ErasurePersistencePortV1,
    reference: Option<ErasureReferenceV1>,
    decode: impl FnOnce(&[u8]) -> Result<T, ErasureErrorV1> + Copy,
    address: impl FnOnce(&T) -> ErasureReferenceV1 + Copy,
) -> Result<Option<T>, ErasureErrorV1> {
    reference.map_or(Ok(None), |reference| {
        load(port, reference, decode, address).map(Some)
    })
}

impl RecoveredErasureV1 {
    pub(crate) fn initial(request: ErasureRequestV1, state: ErasureStateV1) -> Self {
        let manifest = ManifestV1 {
            request: request.reference(),
            state: state.state_digest(),
            target_closure: None,
            correction: None,
            rejection: None,
            scope: None,
            freeze_admission: None,
            freeze_authorization: None,
            freeze_provenance: None,
            freeze_failure: None,
            obligation_set: None,
            scope_extension_head: None,
            active: None,
            attempt_history_head: None,
            completed_attempt_count: 0,
            latest_receipt: None,
            administrative_resolution_head: None,
            authorize_provenance: None,
            dispatch_provenance: None,
        };
        Self {
            manifest,
            manifest_digest: super::reference_zero(),
            request,
            state,
            targets: Vec::new(),
            correction: None,
            rejection: None,
            scope: None,
            freeze_admission: None,
            freeze_authorization: None,
            freeze_provenance: None,
            freeze_failure: None,
            obligation_set: None,
            obligations: Vec::new(),
            active: None,
            effective: BTreeMap::new(),
            attempt_history_head: None,
            completed_attempt_count: 0,
            latest_receipt: None,
            scope_head: None,
            administrative_resolution_head: None,
            administrative_resolution_count: 0,
            authorize_provenance: None,
            dispatch_provenance: None,
        }
    }

    pub(crate) fn recover(
        port: &dyn ErasurePersistencePortV1,
        verifier: &dyn ErasureFreezeAuthorizationVerifierV1,
        requested: ErasureReferenceV1,
        stored: StoredErasureManifestV1,
    ) -> Result<Self, ErasureErrorV1> {
        let manifest = ManifestV1::decode(stored.canonical_cbor())?;
        if manifest.request != requested {
            return Err(ErasureErrorV1::ProvenanceMissing);
        }
        let request = load(
            port,
            requested,
            ErasureRequestV1::from_canonical_cbor,
            ErasureRequestV1::reference,
        )?;
        let state = port
            .resolve_state(manifest.state)?
            .ok_or(ErasureErrorV1::ProvenanceMissing)?;
        if request.reference() != requested || state.request() != requested {
            return Err(ErasureErrorV1::ProvenanceMissing);
        }
        verify_predecessor_chain(state.clone(), port)?;

        let closure = optional(
            port,
            manifest.target_closure,
            TargetClosureV1::decode,
            |value| value.reference,
        )?;
        if closure
            .as_ref()
            .is_some_and(|value| value.request != requested)
        {
            return Err(ErasureErrorV1::ProvenanceMissing);
        }
        let targets = closure.map_or_else(Vec::new, |value| value.targets);
        let correction = optional(
            port,
            manifest.correction,
            ErasureCorrectionProvenanceV1::from_canonical_cbor,
            ErasureCorrectionProvenanceV1::reference,
        )?;
        let rejection = optional(
            port,
            manifest.rejection,
            ErasureAuthorizationRejectionV1::from_canonical_cbor,
            ErasureAuthorizationRejectionV1::reference,
        )?;
        let scope = optional(
            port,
            manifest.scope,
            ErasureScopeCommitmentV1::from_canonical_cbor,
            ErasureScopeCommitmentV1::reference,
        )?;
        let freeze_admission = optional(
            port,
            manifest.freeze_admission,
            ErasureFreezeAdmissionEvidenceV1::from_canonical_cbor,
            ErasureFreezeAdmissionEvidenceV1::reference,
        )?;
        let freeze_authorization = optional(
            port,
            manifest.freeze_authorization,
            ErasureFreezeAuthorizationEvidenceV1::from_canonical_cbor,
            ErasureFreezeAuthorizationEvidenceV1::reference,
        )?;
        let freeze_provenance = optional(
            port,
            manifest.freeze_provenance,
            ErasureFreezeProvenanceV1::from_canonical_cbor,
            ErasureFreezeProvenanceV1::reference,
        )?;
        let freeze_failure = optional(
            port,
            manifest.freeze_failure,
            ErasureFreezeFailureV1::from_canonical_cbor,
            ErasureFreezeFailureV1::reference,
        )?;
        let obligation_set = optional(
            port,
            manifest.obligation_set,
            ErasureObligationSetV1::from_canonical_cbor,
            ErasureObligationSetV1::reference,
        )?;
        let obligations = obligation_set.as_ref().map_or(Ok(Vec::new()), |set| {
            set.obligations()
                .iter()
                .copied()
                .map(|reference| {
                    load(
                        port,
                        reference,
                        ErasureObligationV1::from_canonical_cbor,
                        ErasureObligationV1::reference,
                    )
                })
                .collect()
        })?;
        validate_fixed_graph(
            requested,
            &request,
            &targets,
            rejection.as_ref(),
            scope.as_ref(),
            freeze_admission.as_ref(),
            freeze_authorization.as_ref(),
            freeze_provenance.as_ref(),
            freeze_failure.as_ref(),
            obligation_set.as_ref(),
            &obligations,
            verifier,
        )?;

        let mut recovered = Self {
            manifest: manifest.clone(),
            manifest_digest: stored.digest(),
            request,
            state,
            targets,
            correction,
            rejection,
            scope,
            freeze_admission,
            freeze_authorization,
            freeze_provenance,
            freeze_failure,
            obligation_set,
            obligations,
            active: None,
            effective: BTreeMap::new(),
            attempt_history_head: manifest.attempt_history_head,
            completed_attempt_count: manifest.completed_attempt_count,
            latest_receipt: manifest.latest_receipt,
            scope_head: None,
            administrative_resolution_head: manifest.administrative_resolution_head,
            administrative_resolution_count: 0,
            authorize_provenance: manifest.authorize_provenance,
            dispatch_provenance: manifest.dispatch_provenance,
        };
        recovered.recover_attempts(port)?;
        recovered.recover_scope(port)?;
        recovered.recover_administrative_resolutions(port)?;
        Ok(recovered)
    }

    pub(crate) const fn state(&self) -> &ErasureStateV1 {
        &self.state
    }

    pub(crate) fn prepare(
        &self,
        expected_manifest_digest: Option<ErasureReferenceV1>,
        new_objects: Vec<ErasurePersistenceObjectV1>,
        new_states: Vec<ErasurePersistedStateV1>,
        index_inserts: Vec<ErasureIndexInsertV1>,
        effect: ErasureCasEffectV1,
    ) -> Result<PreparedErasureCasV1, ErasureErrorV1> {
        self.manifest.validate_shape()?;
        let bytes = self.manifest.canonical_cbor()?;
        let digest = addressed(ERCRP1, &bytes);
        let next_manifest = StoredErasureManifestV1::new(digest, bytes)?;
        Ok(PreparedErasureCasV1::new(
            self.request.reference(),
            expected_manifest_digest,
            next_manifest,
            new_objects,
            new_states,
            index_inserts,
            effect,
        ))
    }

    pub(crate) fn request_object(&self) -> Result<ErasurePersistenceObjectV1, ErasureErrorV1> {
        self.request
            .to_canonical_cbor()
            .map(|bytes| ErasurePersistenceObjectV1::new(ERQ1, self.request.reference(), bytes))
    }

    pub(crate) fn state_object(&self) -> Result<ErasurePersistedStateV1, ErasureErrorV1> {
        self.state
            .to_canonical_cbor()
            .map(|bytes| ErasurePersistedStateV1::new(self.state.clone(), bytes))
    }

    pub(crate) fn replace_state(&mut self, state: ErasureStateV1) {
        self.manifest.state = state.state_digest();
        self.state = state;
    }

    pub(crate) fn set_authorize_provenance(&mut self, provenance: ErasureReferenceV1) {
        self.manifest.authorize_provenance = Some(provenance);
        self.authorize_provenance = Some(provenance);
    }

    pub(crate) fn set_authorization_rejection(
        &mut self,
        rejection: ErasureAuthorizationRejectionV1,
    ) -> Result<ErasurePersistenceObjectV1, ErasureErrorV1> {
        let bytes = rejection.to_canonical_cbor()?;
        self.manifest.rejection = Some(rejection.reference());
        self.rejection = Some(rejection);
        Ok(ErasurePersistenceObjectV1::new(
            ERASURE_AUTHORIZATION_REJECTION_TAG_V1,
            self.rejection
                .as_ref()
                .map(ErasureAuthorizationRejectionV1::reference)
                .ok_or(ErasureErrorV1::ProvenanceMissing)?,
            bytes,
        ))
    }

    pub(crate) fn set_correction(
        &mut self,
        correction: ErasureCorrectionProvenanceV1,
    ) -> Result<ErasurePersistenceObjectV1, ErasureErrorV1> {
        let bytes = correction.to_canonical_cbor()?;
        self.manifest.correction = Some(correction.reference());
        self.correction = Some(correction);
        Ok(ErasurePersistenceObjectV1::new(
            ERASURE_CORRECTION_PROVENANCE_TAG_V1,
            self.correction
                .as_ref()
                .map(ErasureCorrectionProvenanceV1::reference)
                .ok_or(ErasureErrorV1::ProvenanceMissing)?,
            bytes,
        ))
    }

    fn recover_attempts(
        &mut self,
        port: &dyn ErasurePersistencePortV1,
    ) -> Result<(), ErasureErrorV1> {
        if port.attempt_index_count(self.request.reference())? != self.completed_attempt_count {
            return Err(ErasureErrorV1::ProvenanceMissing);
        }
        let mut predecessor = None;
        let mut predecessor_receipt = None;
        for ordinal in 0..self.completed_attempt_count {
            let reference = port
                .attempt_page_ref(self.request.reference(), ordinal)?
                .ok_or(ErasureErrorV1::ProvenanceMissing)?;
            let page = load(port, reference, AttemptPageV1::decode, |value| {
                value.reference
            })?;
            if (page.request, page.ordinal, page.predecessor)
                != (self.request.reference(), ordinal, predecessor)
            {
                return Err(ErasureErrorV1::ProvenanceMissing);
            }
            predecessor_receipt = Some(self.replay_page(port, page, predecessor_receipt)?);
            predecessor = Some(reference);
        }
        if predecessor != self.attempt_history_head || predecessor_receipt != self.latest_receipt {
            return Err(ErasureErrorV1::ProvenanceMissing);
        }
        if let Some(active) = self.manifest.active.clone() {
            let admission = load(
                port,
                active.admission,
                ErasureRetryAdmissionV1::from_canonical_cbor,
                ErasureRetryAdmissionV1::reference,
            )?;
            if admission.request() != self.request.reference()
                || admission.attempt_ordinal() != active.ordinal
                || admission.source_receipt() != self.latest_receipt
            {
                return Err(ErasureErrorV1::ProvenanceMissing);
            }
            self.effective.retain(|_, value| {
                value.outcome() == ErasureAcknowledgementOutcomeV1::Acknowledged
            });
            let admitted =
                self.load_acknowledgements(port, &admission, &active.acknowledgements)?;
            self.apply_acknowledgements(admitted.clone());
            self.active = Some(RecoveredAttemptV1 {
                ordinal: active.ordinal,
                admission,
                admitted,
            });
        }
        Ok(())
    }

    fn replay_page(
        &mut self,
        port: &dyn ErasurePersistencePortV1,
        page: AttemptPageV1,
        predecessor_receipt: Option<ErasureReferenceV1>,
    ) -> Result<ErasureReferenceV1, ErasureErrorV1> {
        let admission = load(
            port,
            page.retry_admission,
            ErasureRetryAdmissionV1::from_canonical_cbor,
            ErasureRetryAdmissionV1::reference,
        )?;
        let admitted = load(
            port,
            page.admitted_inventory,
            InventoryV1::decode,
            |value| value.reference,
        )?;
        let effective = load(
            port,
            page.effective_inventory,
            InventoryV1::decode,
            |value| value.reference,
        )?;
        if admission.request() != self.request.reference()
            || admission.attempt_ordinal() != page.ordinal
            || admission.source_receipt() != predecessor_receipt
            || (admitted.request, admitted.ordinal, admitted.kind)
                != (self.request.reference(), page.ordinal, INVENTORY_ADMITTED)
            || (effective.request, effective.ordinal, effective.kind)
                != (self.request.reference(), page.ordinal, INVENTORY_EFFECTIVE)
        {
            return Err(ErasureErrorV1::ProvenanceMissing);
        }
        self.effective
            .retain(|_, value| value.outcome() == ErasureAcknowledgementOutcomeV1::Acknowledged);
        let admitted_values = self.load_acknowledgements(port, &admission, &admitted.references)?;
        self.apply_acknowledgements(admitted_values);
        if canonical_acknowledgement_references(self.effective.values().copied())
            != effective.references
        {
            return Err(ErasureErrorV1::ProvenanceMissing);
        }

        let outcome = load(
            port,
            page.outcome,
            ErasureAttemptOutcomeV1::from_canonical_cbor,
            ErasureAttemptOutcomeV1::reference,
        )?;
        let receipt = load(
            port,
            page.receipt,
            ErasureReceiptV1::from_canonical_cbor,
            ErasureReceiptV1::receipt_digest,
        )?;
        let provenance = load(
            port,
            page.receipt_provenance,
            ErasureReceiptProvenanceV1::from_canonical_cbor,
            ErasureReceiptProvenanceV1::reference,
        )?;
        let terminal = port
            .resolve_state(page.terminal_state)?
            .ok_or(ErasureErrorV1::ProvenanceMissing)?;
        if terminal.request() != self.request.reference()
            || outcome.request() != self.request.reference()
            || outcome.attempt() != admission.reference()
            || outcome.source_receipt() != predecessor_receipt
            || outcome.acknowledgement_inventory() != effective.reference
            || outcome.lifecycle() != terminal.lifecycle()
            || provenance.request() != self.request.reference()
            || provenance.attempt() != admission.reference()
            || provenance.attempt_ordinal() != page.ordinal
            || provenance.predecessor_receipt() != predecessor_receipt
            || provenance.terminal_state() != page.terminal_state
            || receipt.request() != self.request.reference()
            || receipt.receipt_digest() != page.receipt
            || receipt.terminal_state() != page.terminal_state
            || receipt.provenance() != page.receipt_provenance
            || receipt.lifecycle() != terminal.lifecycle()
        {
            return Err(ErasureErrorV1::ProvenanceMissing);
        }
        receipt.validate_frozen_obligations(&self.obligations)?;
        Ok(receipt.receipt_digest())
    }

    fn load_acknowledgements(
        &self,
        port: &dyn ErasurePersistencePortV1,
        admission: &ErasureRetryAdmissionV1,
        references: &[ErasureReferenceV1],
    ) -> Result<
        BTreeMap<(ErasureReferenceV1, ErasureReferenceV1), ErasureAcknowledgementProvenanceV1>,
        ErasureErrorV1,
    > {
        let mut values = BTreeMap::new();
        for reference in references {
            let acknowledgement = load(
                port,
                *reference,
                ErasureAcknowledgementProvenanceV1::from_canonical_cbor,
                ErasureAcknowledgementProvenanceV1::reference,
            )?;
            let key = (acknowledgement.obligation(), acknowledgement.owner());
            if acknowledgement.request() != self.request.reference()
                || acknowledgement.attempt() != admission.reference()
                || values.insert(key, acknowledgement).is_some()
            {
                return Err(ErasureErrorV1::ProvenanceMissing);
            }
        }
        Ok(values)
    }

    fn apply_acknowledgements(
        &mut self,
        values: BTreeMap<
            (ErasureReferenceV1, ErasureReferenceV1),
            ErasureAcknowledgementProvenanceV1,
        >,
    ) {
        for (key, acknowledgement) in values {
            if acknowledgement.outcome() == ErasureAcknowledgementOutcomeV1::Acknowledged
                || !self.effective.contains_key(&key)
            {
                self.effective.insert(key, acknowledgement);
            }
        }
    }

    fn recover_scope(&mut self, port: &dyn ErasurePersistencePortV1) -> Result<(), ErasureErrorV1> {
        let count = port.scope_index_count(self.request.reference())?;
        if count > ERASURE_MAX_SCOPE_EXTENSIONS as u64
            || (count == 0) != self.manifest.scope_extension_head.is_none()
        {
            return Err(ErasureErrorV1::ProvenanceMissing);
        }
        let mut predecessor_node = None;
        let mut predecessor_extension = None;
        let mut forks = BTreeSet::new();
        for ordinal in 0..count {
            let reference = port
                .scope_node_ref(self.request.reference(), ordinal)?
                .ok_or(ErasureErrorV1::ProvenanceMissing)?;
            let node = load(port, reference, ScopeNodeV1::decode, |value| {
                value.reference
            })?;
            let extension = load(
                port,
                node.extension,
                ErasureScopeExtensionV1::from_canonical_cbor,
                ErasureScopeExtensionV1::reference,
            )?;
            if node.request != self.request.reference()
                || Some(node.scope) != self.manifest.scope
                || node.ordinal != ordinal
                || node.predecessor != predecessor_node
                || extension.request() != self.request.reference()
                || extension.scope_commitment() != node.scope
                || extension.predecessor_extension() != predecessor_extension
                || !forks.insert(extension.fork())
            {
                return Err(ErasureErrorV1::ProvenanceMissing);
            }
            predecessor_node = Some(reference);
            predecessor_extension = Some(extension.reference());
            self.scope_head = Some(RecoveredScopeHeadV1 {
                node: reference,
                extension: extension.reference(),
                ordinal,
            });
        }
        if predecessor_node != self.manifest.scope_extension_head {
            return Err(ErasureErrorV1::ProvenanceMissing);
        }
        Ok(())
    }

    fn recover_administrative_resolutions(
        &mut self,
        port: &dyn ErasurePersistencePortV1,
    ) -> Result<(), ErasureErrorV1> {
        let count = port.administrative_resolution_index_count(self.request.reference())?;
        if count > ERASURE_MAX_ADMINISTRATIVE_RESOLUTIONS as u64
            || (count == 0) != self.administrative_resolution_head.is_none()
        {
            return Err(ErasureErrorV1::ProvenanceMissing);
        }
        let mut predecessor = None;
        for ordinal in 0..count {
            let reference = port
                .administrative_resolution_ref(self.request.reference(), ordinal)?
                .ok_or(ErasureErrorV1::ProvenanceMissing)?;
            let resolution = load(
                port,
                reference,
                ErasureAdministrativeResolutionV1::from_canonical_cbor,
                ErasureAdministrativeResolutionV1::reference,
            )?;
            if resolution.request() != self.request.reference()
                || resolution.predecessor_resolution() != predecessor
            {
                return Err(ErasureErrorV1::ProvenanceMissing);
            }
            predecessor = Some(reference);
        }
        if predecessor != self.administrative_resolution_head {
            return Err(ErasureErrorV1::ProvenanceMissing);
        }
        self.administrative_resolution_count = count;
        Ok(())
    }
}

fn canonical_acknowledgement_references(
    values: impl Iterator<Item = ErasureAcknowledgementProvenanceV1>,
) -> Vec<ErasureReferenceV1> {
    let mut values = values.collect::<Vec<_>>();
    values.sort_unstable_by_key(|value| {
        (
            value.obligation(),
            value.owner(),
            value.command(),
            value.attempt(),
            value.evidence(),
            match value.outcome() {
                ErasureAcknowledgementOutcomeV1::Acknowledged => 0_u8,
                ErasureAcknowledgementOutcomeV1::Negative => 1,
                ErasureAcknowledgementOutcomeV1::Stale => 2,
            },
        )
    });
    values.into_iter().map(|value| value.reference()).collect()
}

#[allow(clippy::too_many_arguments)]
fn validate_fixed_graph(
    request: ErasureReferenceV1,
    erq: &ErasureRequestV1,
    targets: &[ErasureRequiredTargetV1],
    rejection: Option<&ErasureAuthorizationRejectionV1>,
    scope: Option<&ErasureScopeCommitmentV1>,
    admission: Option<&ErasureFreezeAdmissionEvidenceV1>,
    authorization: Option<&ErasureFreezeAuthorizationEvidenceV1>,
    freeze: Option<&ErasureFreezeProvenanceV1>,
    failure: Option<&ErasureFreezeFailureV1>,
    obligation_set: Option<&ErasureObligationSetV1>,
    obligations: &[ErasureObligationV1],
    verifier: &dyn ErasureFreezeAuthorizationVerifierV1,
) -> Result<(), ErasureErrorV1> {
    if erq.reference() != request
        || rejection.is_some_and(|value| value.request() != request)
        || failure.is_some_and(|value| value.request() != request)
        || scope.is_some_and(|value| value.request() != request)
        || admission.is_some_and(|value| value.request() != request)
        || obligation_set.is_some_and(|value| value.request() != request)
        || freeze.is_some_and(|value| value.request() != request)
    {
        return Err(ErasureErrorV1::ProvenanceMissing);
    }
    match (admission, authorization) {
        (Some(admission), Some(authorization)) => {
            verifier.validate_freeze_authorization(admission, authorization)?;
        }
        (None, None) => {}
        _ => return Err(ErasureErrorV1::ProvenanceMissing),
    }
    if let (Some(scope), Some(admission), Some(freeze), Some(set)) =
        (scope, admission, freeze, obligation_set)
    {
        if admission.scope_commitment() != scope.reference()
            || admission.obligation_set() != set.reference()
            || freeze.scope_commitment() != scope.reference()
            || freeze.obligation_set() != set.reference()
            || freeze.host_evidence() != admission.reference()
            || set.policy() != erq.policy()
            || obligations.len() != set.obligations().len()
            || obligations
                .iter()
                .zip(set.obligations())
                .any(|(object, reference)| object.reference() != *reference)
            || obligations
                .iter()
                .any(|obligation| !targets.contains(&obligation.target()))
        {
            return Err(ErasureErrorV1::ProvenanceMissing);
        }
    } else if scope.is_some()
        || admission.is_some()
        || freeze.is_some()
        || obligation_set.is_some()
        || !targets.is_empty()
        || !obligations.is_empty()
    {
        return Err(ErasureErrorV1::ProvenanceMissing);
    }
    Ok(())
}
