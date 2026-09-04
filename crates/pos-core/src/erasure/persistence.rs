//! Bounded, core-owned ERCRP1 persistence graph.

use super::evidence::{
    bytes32, digest, header, optional_bytes32, optional_digest, references_value,
    target_from_value, target_value, text, uint, unordered_references_from_value, unsigned,
};
use super::{
    acknowledgement_inventory_reference, decode_limited, domain_digest, encode_limited,
    erasure_evidence_set_reference, exact_array, selected_obligations_reference,
    target_closure_digest, verify_predecessor_chain, BTreeMap, BTreeSet,
    ErasureAcknowledgementOutcomeV1, ErasureAcknowledgementProvenanceV1,
    ErasureAdministrativeResolutionV1, ErasureAtomicFreezeAdmissionInputV1,
    ErasureAtomicFreezeAdmissionV1, ErasureAttemptOutcomeV1, ErasureAuthorizationRejectionV1,
    ErasureCasEffectV1, ErasureCorrectionProvenanceV1, ErasureDestructionCommandV1, ErasureErrorV1,
    ErasureFreezeAdmissionEvidenceV1, ErasureFreezeAuthorizationEvidenceV1,
    ErasureFreezeAuthorizationVerifierV1, ErasureFreezeFailureV1, ErasureFreezeProvenanceV1,
    ErasureIndexInsertV1, ErasureLifecycleV1, ErasureObligationSetV1, ErasureObligationV1,
    ErasurePersistedStateV1, ErasurePersistenceObjectV1, ErasurePersistencePortV1,
    ErasureReceiptProvenanceV1, ErasureReceiptV1, ErasureRecoveryAuthorizationVerifierV1,
    ErasureReferenceV1, ErasureRequestV1, ErasureRequiredTargetV1, ErasureRetryAdmissionV1,
    ErasureScopeCommitmentInputV1, ErasureScopeCommitmentV1, ErasureScopeExtensionV1,
    ErasureStateV1, ErasureVerifiedStateV1, PreparedErasureCasV1, StoredErasureManifestV1,
    ERASURE_ACKNOWLEDGEMENT_INVENTORY_TAG_V1, ERASURE_ATTEMPT_HISTORY_TAG_V1,
    ERASURE_COORDINATOR_RECORD_MAX_BYTES, ERASURE_MAX_ACKNOWLEDGEMENTS_PER_ATTEMPT,
    ERASURE_MAX_ADMINISTRATIVE_RESOLUTIONS, ERASURE_MAX_ATTEMPT_OUTCOMES,
    ERASURE_MAX_SCOPE_EXTENSIONS, ERASURE_MAX_TARGETS, ERASURE_PORTABLE_RECORD_MAX_BYTES,
    ERASURE_SCOPE_EXTENSION_HEAD_TAG_V1, ERASURE_TARGET_CLOSURE_TAG_V1, ERCRP1, VERSION,
};
use ciborium::value::Value;

const INVENTORY_ADMITTED: u64 = 0;
const INVENTORY_EFFECTIVE: u64 = 1;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct ManifestV1 {
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
    pub(super) fn decode(bytes: &[u8]) -> Result<Self, ErasureErrorV1> {
        decode_limited(
            bytes,
            ERASURE_COORDINATOR_RECORD_MAX_BYTES,
            ERASURE_MAX_ACKNOWLEDGEMENTS_PER_ATTEMPT,
        )
        .and_then(|value| {
            let fields = exact_array(&value, 21)?;
            header(fields, ERCRP1)?;
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
pub(super) struct TargetClosureV1 {
    request: ErasureReferenceV1,
    targets: Vec<ErasureRequiredTargetV1>,
    reference: ErasureReferenceV1,
}

impl TargetClosureV1 {
    pub(super) fn new(
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

    pub(super) fn canonical_cbor(&self) -> Result<Vec<u8>, ErasureErrorV1> {
        encode_limited(
            &Value::Array(vec![
                text(ERASURE_TARGET_CLOSURE_TAG_V1),
                uint(VERSION),
                digest(self.request),
                Value::Array(self.targets.iter().copied().map(target_value).collect()),
            ]),
            ERASURE_PORTABLE_RECORD_MAX_BYTES,
        )
    }

    pub(super) fn decode(bytes: &[u8]) -> Result<Self, ErasureErrorV1> {
        decode_limited(
            bytes,
            ERASURE_PORTABLE_RECORD_MAX_BYTES,
            ERASURE_MAX_TARGETS,
        )
        .and_then(|value| {
            let fields = exact_array(&value, 4)?;
            header(fields, ERASURE_TARGET_CLOSURE_TAG_V1)?;
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
pub(super) struct InventoryV1 {
    request: ErasureReferenceV1,
    ordinal: u64,
    kind: u64,
    references: Vec<ErasureReferenceV1>,
    reference: ErasureReferenceV1,
}

impl InventoryV1 {
    pub(super) fn new(
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

    pub(super) fn canonical_cbor(&self) -> Result<Vec<u8>, ErasureErrorV1> {
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

    pub(super) fn decode(bytes: &[u8]) -> Result<Self, ErasureErrorV1> {
        decode_limited(
            bytes,
            ERASURE_PORTABLE_RECORD_MAX_BYTES,
            ERASURE_MAX_ACKNOWLEDGEMENTS_PER_ATTEMPT,
        )
        .and_then(|value| {
            let fields = exact_array(&value, 6)?;
            header(fields, ERASURE_ACKNOWLEDGEMENT_INVENTORY_TAG_V1)?;
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
pub(super) struct AttemptPageV1 {
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
    pub(super) fn canonical_cbor(&self) -> Result<Vec<u8>, ErasureErrorV1> {
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

    pub(super) fn decode(bytes: &[u8]) -> Result<Self, ErasureErrorV1> {
        decode_limited(bytes, ERASURE_PORTABLE_RECORD_MAX_BYTES, 12).and_then(|value| {
            let fields = exact_array(&value, 12)?;
            header(fields, ERASURE_ATTEMPT_HISTORY_TAG_V1)?;
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
pub(super) struct ScopeNodeV1 {
    request: ErasureReferenceV1,
    scope: ErasureReferenceV1,
    extension: ErasureReferenceV1,
    ordinal: u64,
    predecessor: Option<ErasureReferenceV1>,
    reference: ErasureReferenceV1,
}

impl ScopeNodeV1 {
    pub(super) fn canonical_cbor(&self) -> Result<Vec<u8>, ErasureErrorV1> {
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

    pub(super) fn decode(bytes: &[u8]) -> Result<Self, ErasureErrorV1> {
        decode_limited(bytes, ERASURE_PORTABLE_RECORD_MAX_BYTES, 7).and_then(|value| {
            let fields = exact_array(&value, 7)?;
            header(fields, ERASURE_SCOPE_EXTENSION_HEAD_TAG_V1)?;
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
pub(super) struct RecoveredScopeHeadV1 {
    pub(super) node: ErasureReferenceV1,
    pub(super) extension: ErasureReferenceV1,
    pub(super) ordinal: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct RecoveredAttemptV1 {
    pub(super) ordinal: u64,
    pub(super) admission: ErasureRetryAdmissionV1,
    pub(super) admitted:
        BTreeMap<(ErasureReferenceV1, ErasureReferenceV1), ErasureAcknowledgementProvenanceV1>,
}

/// Bounded working state returned only after the complete persistence graph verifies.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct RecoveredErasureV1 {
    manifest: ManifestV1,
    pub(super) manifest_digest: ErasureReferenceV1,
    pub(super) request: ErasureRequestV1,
    pub(super) state: ErasureStateV1,
    pub(super) targets: Vec<ErasureRequiredTargetV1>,
    pub(super) correction: Option<ErasureCorrectionProvenanceV1>,
    pub(super) rejection: Option<ErasureAuthorizationRejectionV1>,
    pub(super) scope: Option<ErasureScopeCommitmentV1>,
    pub(super) freeze_admission: Option<ErasureFreezeAdmissionEvidenceV1>,
    pub(super) freeze_authorization: Option<ErasureFreezeAuthorizationEvidenceV1>,
    pub(super) freeze_provenance: Option<ErasureFreezeProvenanceV1>,
    pub(super) freeze_failure: Option<ErasureFreezeFailureV1>,
    pub(super) obligation_set: Option<ErasureObligationSetV1>,
    pub(super) obligations: Vec<ErasureObligationV1>,
    pub(super) active: Option<RecoveredAttemptV1>,
    pub(super) effective:
        BTreeMap<(ErasureReferenceV1, ErasureReferenceV1), ErasureAcknowledgementProvenanceV1>,
    pub(super) attempt_history_head: Option<ErasureReferenceV1>,
    pub(super) completed_attempt_count: u64,
    pub(super) latest_receipt: Option<ErasureReferenceV1>,
    pub(super) scope_head: Option<RecoveredScopeHeadV1>,
    pub(super) administrative_resolution_head: Option<ErasureReferenceV1>,
    pub(super) administrative_resolution_count: u64,
    pub(super) authorize_provenance: Option<ErasureReferenceV1>,
    pub(super) dispatch_provenance: Option<ErasureReferenceV1>,
    pub(super) scope_extensions: Vec<ErasureScopeExtensionV1>,
}

struct RecoveredFoundationV1 {
    request: ErasureRequestV1,
    state: ErasureStateV1,
    targets: Vec<ErasureRequiredTargetV1>,
}

struct RecoveredFixedEvidenceV1 {
    correction: Option<ErasureCorrectionProvenanceV1>,
    rejection: Option<ErasureAuthorizationRejectionV1>,
    scope: Option<ErasureScopeCommitmentV1>,
    freeze_admission: Option<ErasureFreezeAdmissionEvidenceV1>,
    freeze_authorization: Option<ErasureFreezeAuthorizationEvidenceV1>,
    freeze_provenance: Option<ErasureFreezeProvenanceV1>,
    freeze_failure: Option<ErasureFreezeFailureV1>,
    obligation_set: Option<ErasureObligationSetV1>,
    obligations: Vec<ErasureObligationV1>,
}

struct RecoveredFreezeEvidenceV1 {
    admission: Option<ErasureFreezeAdmissionEvidenceV1>,
    authorization: Option<ErasureFreezeAuthorizationEvidenceV1>,
    provenance: Option<ErasureFreezeProvenanceV1>,
    failure: Option<ErasureFreezeFailureV1>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct RecoveryFailureV1 {
    error: ErasureErrorV1,
    subject: ErasureReferenceV1,
}

impl RecoveryFailureV1 {
    const fn new(error: ErasureErrorV1, subject: ErasureReferenceV1) -> Self {
        Self { error, subject }
    }

    pub(super) const fn error(self) -> ErasureErrorV1 {
        self.error
    }

    pub(super) const fn subject(self) -> ErasureReferenceV1 {
        self.subject
    }
}

impl From<ErasureErrorV1> for RecoveryFailureV1 {
    fn from(error: ErasureErrorV1) -> Self {
        Self::new(error, super::reference_zero())
    }
}

fn load<T>(
    port: &dyn ErasurePersistencePortV1,
    reference: ErasureReferenceV1,
    decode: impl FnOnce(&[u8]) -> Result<T, ErasureErrorV1>,
    address: impl FnOnce(&T) -> ErasureReferenceV1,
) -> Result<T, RecoveryFailureV1> {
    load_recovery_object(port, reference, decode, address)
}

fn load_recovery_object<T>(
    port: &dyn ErasurePersistencePortV1,
    reference: ErasureReferenceV1,
    decode: impl FnOnce(&[u8]) -> Result<T, ErasureErrorV1>,
    address: impl FnOnce(&T) -> ErasureReferenceV1,
) -> Result<T, RecoveryFailureV1> {
    let bytes = port
        .read_object(reference)
        .map_err(|error| RecoveryFailureV1::new(error, reference))?;
    let value = decode(&bytes).map_err(|error| RecoveryFailureV1::new(error, reference))?;
    (address(&value) == reference)
        .then_some(value)
        .ok_or_else(|| RecoveryFailureV1::new(ErasureErrorV1::ProvenanceMissing, reference))
}

fn optional<T>(
    port: &dyn ErasurePersistencePortV1,
    reference: Option<ErasureReferenceV1>,
    decode: impl FnOnce(&[u8]) -> Result<T, ErasureErrorV1> + Copy,
    address: impl FnOnce(&T) -> ErasureReferenceV1 + Copy,
) -> Result<Option<T>, RecoveryFailureV1> {
    reference.map_or(Ok(None), |reference| {
        load(port, reference, decode, address).map(Some)
    })
}

fn recover_foundation(
    port: &dyn ErasurePersistencePortV1,
    requested: ErasureReferenceV1,
    manifest: &ManifestV1,
) -> Result<RecoveredFoundationV1, RecoveryFailureV1> {
    let request = load(
        port,
        requested,
        ErasureRequestV1::from_canonical_cbor,
        ErasureRequestV1::reference,
    )?;
    let state = port
        .resolve_state(manifest.state)
        .map_err(|error| RecoveryFailureV1::new(error, manifest.state))?
        .ok_or_else(|| RecoveryFailureV1::new(ErasureErrorV1::ProvenanceMissing, manifest.state))?;
    if request.reference() != requested || state.request() != requested {
        let subject = if request.reference() == requested {
            state.state_digest()
        } else {
            request.reference()
        };
        return Err(RecoveryFailureV1::new(
            ErasureErrorV1::ProvenanceMissing,
            subject,
        ));
    }
    verify_predecessor_chain(state.clone(), port)
        .map_err(|error| RecoveryFailureV1::new(error, state.state_digest()))?;
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
        return Err(RecoveryFailureV1::new(
            ErasureErrorV1::ProvenanceMissing,
            closure
                .as_ref()
                .map_or(manifest.state, |value| value.reference),
        ));
    }
    Ok(RecoveredFoundationV1 {
        request,
        state,
        targets: closure.map_or_else(Vec::new, |value| value.targets),
    })
}

fn recover_fixed_evidence(
    port: &dyn ErasurePersistencePortV1,
    manifest: &ManifestV1,
) -> Result<RecoveredFixedEvidenceV1, RecoveryFailureV1> {
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
    let freeze = recover_freeze_evidence(port, manifest)?;
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
    Ok(RecoveredFixedEvidenceV1 {
        correction,
        rejection,
        scope,
        freeze_admission: freeze.admission,
        freeze_authorization: freeze.authorization,
        freeze_provenance: freeze.provenance,
        freeze_failure: freeze.failure,
        obligation_set,
        obligations,
    })
}

fn recover_freeze_evidence(
    port: &dyn ErasurePersistencePortV1,
    manifest: &ManifestV1,
) -> Result<RecoveredFreezeEvidenceV1, RecoveryFailureV1> {
    Ok(RecoveredFreezeEvidenceV1 {
        admission: optional(
            port,
            manifest.freeze_admission,
            ErasureFreezeAdmissionEvidenceV1::from_canonical_cbor,
            ErasureFreezeAdmissionEvidenceV1::reference,
        )?,
        authorization: optional(
            port,
            manifest.freeze_authorization,
            ErasureFreezeAuthorizationEvidenceV1::from_canonical_cbor,
            ErasureFreezeAuthorizationEvidenceV1::reference,
        )?,
        provenance: optional(
            port,
            manifest.freeze_provenance,
            ErasureFreezeProvenanceV1::from_canonical_cbor,
            ErasureFreezeProvenanceV1::reference,
        )?,
        failure: optional(
            port,
            manifest.freeze_failure,
            ErasureFreezeFailureV1::from_canonical_cbor,
            ErasureFreezeFailureV1::reference,
        )?,
    })
}

impl RecoveredErasureV1 {
    pub(super) const fn initial(request: ErasureRequestV1, state: ErasureStateV1) -> Self {
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
            scope_extensions: Vec::new(),
        }
    }

    pub(super) fn recover(
        port: &dyn ErasurePersistencePortV1,
        verifier: &dyn ErasureFreezeAuthorizationVerifierV1,
        recovery_verifier: &dyn ErasureRecoveryAuthorizationVerifierV1,
        requested: ErasureReferenceV1,
        stored: &StoredErasureManifestV1,
    ) -> Result<Self, RecoveryFailureV1> {
        let manifest = ManifestV1::decode(stored.canonical_cbor())
            .map_err(|error| RecoveryFailureV1::new(error, stored.digest()))?;
        if manifest.request != requested {
            return Err(RecoveryFailureV1::new(
                ErasureErrorV1::ProvenanceMissing,
                stored.digest(),
            ));
        }
        let foundation = recover_foundation(port, requested, &manifest)?;
        let evidence = recover_fixed_evidence(port, &manifest)?;
        validate_fixed_graph(&FixedGraphV1 {
            requested,
            erq: &foundation.request,
            state: &foundation.state,
            targets: &foundation.targets,
            correction: evidence.correction.as_ref(),
            rejection: evidence.rejection.as_ref(),
            scope: evidence.scope.as_ref(),
            admission: evidence.freeze_admission.as_ref(),
            authorization: evidence.freeze_authorization.as_ref(),
            freeze: evidence.freeze_provenance.as_ref(),
            failure: evidence.freeze_failure.as_ref(),
            obligation_set: evidence.obligation_set.as_ref(),
            obligations: &evidence.obligations,
            authorize_provenance: manifest.authorize_provenance,
            verifier,
        })
        .map_err(|error| RecoveryFailureV1::new(error, stored.digest()))?;
        let correction_subject = evidence.correction.as_ref().map_or_else(
            || foundation.request.reference(),
            ErasureCorrectionProvenanceV1::reference,
        );
        validate_correction(port, &foundation.request, evidence.correction.as_ref())
            .map_err(|error| RecoveryFailureV1::new(error, correction_subject))?;
        validate_state_provenance(port, &foundation.state, &manifest)
            .map_err(|error| RecoveryFailureV1::new(error, foundation.state.state_digest()))?;

        let RecoveredFoundationV1 {
            request,
            state,
            targets,
        } = foundation;
        let RecoveredFixedEvidenceV1 {
            correction,
            rejection,
            scope,
            freeze_admission,
            freeze_authorization,
            freeze_provenance,
            freeze_failure,
            obligation_set,
            obligations,
        } = evidence;

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
            scope_extensions: Vec::new(),
        };
        recovered.recover_attempts(port)?;
        recovered.recover_scope(port, recovery_verifier)?;
        recovered.recover_administrative_resolutions(port, recovery_verifier)?;
        Ok(recovered)
    }

    pub(super) const fn state(&self) -> &ErasureStateV1 {
        &self.state
    }

    pub(super) fn verified_state(&self) -> ErasureVerifiedStateV1 {
        ErasureVerifiedStateV1::from_parts(
            self.manifest_digest,
            self.request.clone(),
            self.state.clone(),
            self.scope.clone(),
            self.scope_extensions.clone(),
        )
    }

    pub(super) fn prepare(
        &self,
        expected_manifest_digest: Option<ErasureReferenceV1>,
        new_objects: Vec<ErasurePersistenceObjectV1>,
        new_states: Vec<ErasurePersistedStateV1>,
        index_inserts: Vec<ErasureIndexInsertV1>,
        effect: ErasureCasEffectV1,
    ) -> Result<PreparedErasureCasV1, ErasureErrorV1> {
        self.manifest.validate_shape()?;
        self.manifest.canonical_cbor().and_then(|bytes| {
            let digest = addressed(ERCRP1, &bytes);
            StoredErasureManifestV1::new(digest, bytes).map(|next_manifest| {
                PreparedErasureCasV1::new(
                    self.request.reference(),
                    expected_manifest_digest,
                    next_manifest,
                    new_objects,
                    new_states,
                    index_inserts,
                    effect,
                )
            })
        })
    }

    pub(super) fn request_object(&self) -> Result<ErasurePersistenceObjectV1, ErasureErrorV1> {
        self.request
            .to_canonical_cbor()
            .map(|bytes| ErasurePersistenceObjectV1::new(self.request.reference(), bytes))
    }

    pub(super) fn state_object(&self) -> Result<ErasurePersistedStateV1, ErasureErrorV1> {
        self.state
            .to_canonical_cbor()
            .map(|bytes| ErasurePersistedStateV1::new(self.state.clone(), bytes))
    }

    pub(super) fn replace_state(&mut self, state: ErasureStateV1) {
        self.manifest.state = state.state_digest();
        self.state = state;
    }

    pub(super) const fn set_authorize_provenance(&mut self, provenance: ErasureReferenceV1) {
        self.manifest.authorize_provenance = Some(provenance);
        self.authorize_provenance = Some(provenance);
    }

    pub(super) fn set_authorization_rejection(
        &mut self,
        rejection: ErasureAuthorizationRejectionV1,
    ) -> Result<ErasurePersistenceObjectV1, ErasureErrorV1> {
        let reference = rejection.reference();
        rejection.to_canonical_cbor().map(|bytes| {
            self.manifest.rejection = Some(reference);
            self.rejection = Some(rejection);
            ErasurePersistenceObjectV1::new(reference, bytes)
        })
    }

    pub(super) fn set_correction(
        &mut self,
        correction: ErasureCorrectionProvenanceV1,
    ) -> Result<ErasurePersistenceObjectV1, ErasureErrorV1> {
        let reference = correction.reference();
        correction.to_canonical_cbor().map(|bytes| {
            self.manifest.correction = Some(reference);
            self.correction = Some(correction);
            ErasurePersistenceObjectV1::new(reference, bytes)
        })
    }

    pub(super) fn retain_atomic_freeze(
        &mut self,
        admission: &ErasureAtomicFreezeAdmissionV1,
        scope: ErasureScopeCommitmentV1,
        freeze: ErasureFreezeProvenanceV1,
    ) -> Result<Vec<ErasurePersistenceObjectV1>, ErasureErrorV1> {
        let closure = TargetClosureV1::new(self.request.reference(), admission.targets().to_vec())?;
        let mut objects = [
            encoded_persistence_object(closure.reference, closure.canonical_cbor()),
            encoded_persistence_object(scope.reference(), scope.to_canonical_cbor()),
            encoded_persistence_object(
                admission.freeze_admission_evidence().reference(),
                admission.freeze_admission_evidence().to_canonical_cbor(),
            ),
            encoded_persistence_object(
                admission.freeze_authorization_evidence().reference(),
                admission
                    .freeze_authorization_evidence()
                    .to_canonical_cbor(),
            ),
            encoded_persistence_object(freeze.reference(), freeze.to_canonical_cbor()),
            encoded_persistence_object(
                admission.obligation_set().reference(),
                admission.obligation_set().to_canonical_cbor(),
            ),
        ]
        .into_iter()
        .collect::<Result<Vec<_>, _>>()?;
        objects.extend(
            admission
                .obligations()
                .iter()
                .map(|obligation| {
                    encoded_persistence_object(
                        obligation.reference(),
                        obligation.to_canonical_cbor(),
                    )
                })
                .collect::<Result<Vec<_>, _>>()?,
        );
        self.manifest.target_closure = Some(closure.reference);
        self.manifest.scope = Some(scope.reference());
        self.manifest.freeze_admission = Some(admission.freeze_admission_evidence().reference());
        self.manifest.freeze_authorization =
            Some(admission.freeze_authorization_evidence().reference());
        self.manifest.freeze_provenance = Some(freeze.reference());
        self.manifest.obligation_set = Some(admission.obligation_set().reference());
        self.targets = closure.targets;
        self.scope = Some(scope);
        self.freeze_admission = Some(admission.freeze_admission_evidence().clone());
        self.freeze_authorization = Some(admission.freeze_authorization_evidence().clone());
        self.freeze_provenance = Some(freeze);
        self.obligation_set = Some(admission.obligation_set().clone());
        self.obligations = admission.obligations().to_vec();
        Ok(objects)
    }

    pub(super) fn set_freeze_failure(
        &mut self,
        failure: ErasureFreezeFailureV1,
    ) -> Result<ErasurePersistenceObjectV1, ErasureErrorV1> {
        let reference = failure.reference();
        failure.to_canonical_cbor().map(|bytes| {
            self.manifest.freeze_failure = Some(reference);
            self.freeze_failure = Some(failure);
            persistence_object(reference, bytes)
        })
    }

    pub(super) fn begin_attempt(
        &mut self,
        admission: ErasureRetryAdmissionV1,
    ) -> Result<ErasurePersistenceObjectV1, ErasureErrorV1> {
        if self.active.is_some()
            || admission.request() != self.request.reference()
            || admission.attempt_ordinal() != self.completed_attempt_count
            || admission.source_receipt() != self.latest_receipt
        {
            return Err(ErasureErrorV1::PolicyConflict);
        }
        let reference = admission.reference();
        let ordinal = admission.attempt_ordinal();
        admission.to_canonical_cbor().map(|bytes| {
            self.effective.retain(|_, value| {
                value.outcome() == ErasureAcknowledgementOutcomeV1::Acknowledged
            });
            self.manifest.active = Some(ActiveAttemptRefV1 {
                ordinal,
                admission: reference,
                acknowledgements: Vec::new(),
            });
            if ordinal == 0 {
                self.manifest.dispatch_provenance = Some(reference);
                self.dispatch_provenance = Some(reference);
            }
            self.active = Some(RecoveredAttemptV1 {
                ordinal,
                admission,
                admitted: BTreeMap::new(),
            });
            persistence_object(reference, bytes)
        })
    }

    pub(super) fn retain_acknowledgement(
        &mut self,
        acknowledgement: &ErasureAcknowledgementProvenanceV1,
    ) -> Result<ErasurePersistenceObjectV1, ErasureErrorV1> {
        let (active, manifest_active) = self
            .active
            .as_mut()
            .zip(self.manifest.active.as_mut())
            .ok_or(ErasureErrorV1::ProvenanceMissing)?;
        if acknowledgement.request() != self.request.reference()
            || acknowledgement.attempt() != active.admission.reference()
        {
            return Err(ErasureErrorV1::ProvenanceMissing);
        }
        let identity = (acknowledgement.obligation(), acknowledgement.owner());
        if active.admitted.contains_key(&identity) {
            return Err(ErasureErrorV1::PolicyConflict);
        }
        let reference = acknowledgement.reference();
        acknowledgement.to_canonical_cbor().map(|bytes| {
            active.admitted.insert(identity, *acknowledgement);
            self.effective.insert(identity, *acknowledgement);
            manifest_active.acknowledgements =
                canonical_acknowledgement_references(active.admitted.values().copied());
            persistence_object(reference, bytes)
        })
    }

    pub(super) fn append_scope_extension(
        &mut self,
        extension: ErasureScopeExtensionV1,
    ) -> Result<
        (
            ErasurePersistenceObjectV1,
            ErasurePersistenceObjectV1,
            ErasureIndexInsertV1,
        ),
        ErasureErrorV1,
    > {
        let ordinal = self.scope_head.map_or(0, |head| head.ordinal + 1);
        if ordinal >= ERASURE_MAX_SCOPE_EXTENSIONS as u64 {
            return Err(ErasureErrorV1::PolicyConflict);
        }
        let node = ScopeNodeV1 {
            request: self.request.reference(),
            scope: extension.scope_commitment(),
            extension: extension.reference(),
            ordinal,
            predecessor: self.scope_head.map(|head| head.node),
            reference: super::reference_zero(),
        };
        let extension_reference = extension.reference();
        node.canonical_cbor().and_then(|node_bytes| {
            extension.to_canonical_cbor().map(|extension_bytes| {
                let node_reference = addressed(ERASURE_SCOPE_EXTENSION_HEAD_TAG_V1, &node_bytes);
                self.manifest.scope_extension_head = Some(node_reference);
                self.scope_head = Some(RecoveredScopeHeadV1 {
                    node: node_reference,
                    extension: extension_reference,
                    ordinal,
                });
                (
                    persistence_object(extension_reference, extension_bytes),
                    persistence_object(node_reference, node_bytes),
                    ErasureIndexInsertV1::ScopeNode {
                        ordinal,
                        reference: node_reference,
                    },
                )
            })
        })
    }

    pub(super) fn append_administrative_resolution(
        &mut self,
        resolution: &ErasureAdministrativeResolutionV1,
    ) -> Result<(ErasurePersistenceObjectV1, ErasureIndexInsertV1), ErasureErrorV1> {
        let ordinal = self.administrative_resolution_count;
        if ordinal >= ERASURE_MAX_ADMINISTRATIVE_RESOLUTIONS as u64 {
            return Err(ErasureErrorV1::PolicyConflict);
        }
        let reference = resolution.reference();
        let next_count = ordinal + 1;
        resolution.to_canonical_cbor().map(|bytes| {
            let object = persistence_object(reference, bytes);
            self.manifest.administrative_resolution_head = Some(reference);
            self.administrative_resolution_head = Some(reference);
            self.administrative_resolution_count = next_count;
            (
                object,
                ErasureIndexInsertV1::AdministrativeResolution { ordinal, reference },
            )
        })
    }

    pub(super) fn finish_attempt(
        &mut self,
        outcome: &ErasureAttemptOutcomeV1,
        receipt_provenance: &ErasureReceiptProvenanceV1,
        receipt: &ErasureReceiptV1,
    ) -> Result<(Vec<ErasurePersistenceObjectV1>, ErasureIndexInsertV1), ErasureErrorV1> {
        let active = self
            .active
            .as_ref()
            .ok_or(ErasureErrorV1::ProvenanceMissing)?;
        let ordinal = active.ordinal;
        let admitted = InventoryV1::new(
            self.request.reference(),
            ordinal,
            INVENTORY_ADMITTED,
            canonical_acknowledgement_references(active.admitted.values().copied()),
        )?;
        let effective = InventoryV1::new(
            self.request.reference(),
            ordinal,
            INVENTORY_EFFECTIVE,
            canonical_acknowledgement_references(self.effective.values().copied()),
        )?;
        let page = AttemptPageV1 {
            request: self.request.reference(),
            ordinal,
            retry_admission: active.admission.reference(),
            admitted_inventory: admitted.reference,
            effective_inventory: effective.reference,
            outcome: outcome.reference(),
            receipt: receipt.receipt_digest(),
            receipt_provenance: receipt_provenance.reference(),
            terminal_state: self.state.state_digest(),
            predecessor: self.attempt_history_head,
            reference: super::reference_zero(),
        };
        let page_bytes = page.canonical_cbor()?;
        let page_reference = addressed(ERASURE_ATTEMPT_HISTORY_TAG_V1, &page_bytes);
        let mut objects = [
            encoded_persistence_object(admitted.reference, admitted.canonical_cbor()),
            encoded_persistence_object(effective.reference, effective.canonical_cbor()),
            encoded_persistence_object(outcome.reference(), outcome.to_canonical_cbor()),
            encoded_persistence_object(
                receipt_provenance.reference(),
                receipt_provenance.to_canonical_cbor(),
            ),
            encoded_persistence_object(receipt.receipt_digest(), receipt.to_canonical_cbor()),
        ]
        .into_iter()
        .collect::<Result<Vec<_>, _>>()?;
        objects.push(persistence_object(page_reference, page_bytes));
        self.manifest.active = None;
        self.manifest.attempt_history_head = Some(page_reference);
        let completed = ordinal + 1;
        self.manifest.completed_attempt_count = completed;
        self.manifest.latest_receipt = Some(receipt.receipt_digest());
        self.active = None;
        self.attempt_history_head = Some(page_reference);
        self.completed_attempt_count = completed;
        self.latest_receipt = Some(receipt.receipt_digest());
        Ok((
            objects,
            ErasureIndexInsertV1::AttemptPage {
                ordinal,
                reference: page_reference,
            },
        ))
    }

    fn recover_active_attempt(
        &mut self,
        port: &dyn ErasurePersistencePortV1,
        active: ActiveAttemptRefV1,
        latest_terminal_state: Option<ErasureReferenceV1>,
    ) -> Result<(), RecoveryFailureV1> {
        let admission = load(
            port,
            active.admission,
            ErasureRetryAdmissionV1::from_canonical_cbor,
            ErasureRetryAdmissionV1::reference,
        )?;
        let active_admission_matches = [
            admission.request() == self.request.reference(),
            admission.attempt_ordinal() == active.ordinal,
            admission.source_receipt() == self.latest_receipt,
        ]
        .into_iter()
        .all(|matches| matches);
        if !active_admission_matches {
            return Err(RecoveryFailureV1::new(
                ErasureErrorV1::ProvenanceMissing,
                active.admission,
            ));
        }
        if active.ordinal == 0 && self.dispatch_provenance != Some(admission.reference()) {
            return Err(RecoveryFailureV1::new(
                ErasureErrorV1::ProvenanceMissing,
                admission.reference(),
            ));
        }
        let active_state_matches = if active.ordinal == 0 {
            self.state.lifecycle() == ErasureLifecycleV1::AwaitingAcknowledgements
                && self.state.provenance() == admission.reference()
        } else {
            latest_terminal_state == Some(self.manifest.state)
        };
        if !active_state_matches {
            return Err(RecoveryFailureV1::new(
                ErasureErrorV1::ProvenanceMissing,
                self.manifest.state,
            ));
        }
        self.validate_attempt_effect(port, &admission)?;
        self.effective
            .retain(|_, value| value.outcome() == ErasureAcknowledgementOutcomeV1::Acknowledged);
        let admitted = self.load_acknowledgements(
            port,
            &admission,
            &active.acknowledgements,
            active.admission,
        )?;
        self.apply_acknowledgements(admitted.clone());
        self.active = Some(RecoveredAttemptV1 {
            ordinal: active.ordinal,
            admission,
            admitted,
        });
        Ok(())
    }

    fn recover_attempts(
        &mut self,
        port: &dyn ErasurePersistencePortV1,
    ) -> Result<(), RecoveryFailureV1> {
        let index_count = port
            .attempt_index_count(self.request.reference())
            .map_err(|error| {
                RecoveryFailureV1::new(
                    error,
                    self.manifest
                        .attempt_history_head
                        .unwrap_or(self.manifest.state),
                )
            })?;
        if index_count != self.completed_attempt_count {
            return Err(RecoveryFailureV1::new(
                ErasureErrorV1::ProvenanceMissing,
                self.manifest
                    .attempt_history_head
                    .unwrap_or(self.manifest.state),
            ));
        }
        let mut predecessor = None;
        let mut predecessor_receipt = None;
        let mut latest_terminal_state = None;
        for ordinal in 0..self.completed_attempt_count {
            let reference = port
                .attempt_page_ref(self.request.reference(), ordinal)
                .map_err(|error| {
                    RecoveryFailureV1::new(
                        error,
                        self.manifest
                            .attempt_history_head
                            .unwrap_or(self.manifest.state),
                    )
                })?
                .ok_or_else(|| {
                    RecoveryFailureV1::new(
                        ErasureErrorV1::ProvenanceMissing,
                        self.manifest
                            .attempt_history_head
                            .unwrap_or(self.manifest.state),
                    )
                })?;
            let page = load(port, reference, AttemptPageV1::decode, |value| {
                value.reference
            })?;
            if (page.request, page.ordinal, page.predecessor)
                != (self.request.reference(), ordinal, predecessor)
            {
                return Err(RecoveryFailureV1::new(
                    ErasureErrorV1::ProvenanceMissing,
                    reference,
                ));
            }
            let (receipt, terminal_state) = self.replay_page(port, &page, predecessor_receipt)?;
            predecessor_receipt = Some(receipt);
            latest_terminal_state = Some(terminal_state);
            predecessor = Some(reference);
        }
        if predecessor != self.attempt_history_head {
            return Err(RecoveryFailureV1::new(
                ErasureErrorV1::ProvenanceMissing,
                self.attempt_history_head.unwrap_or(self.manifest.state),
            ));
        }
        if predecessor_receipt != self.latest_receipt {
            return Err(RecoveryFailureV1::new(
                ErasureErrorV1::ProvenanceMissing,
                self.latest_receipt.unwrap_or(self.manifest.state),
            ));
        }
        if self.completed_attempt_count > 0 && latest_terminal_state != Some(self.manifest.state) {
            return Err(RecoveryFailureV1::new(
                ErasureErrorV1::ProvenanceMissing,
                self.manifest.state,
            ));
        }
        if let Some(active) = self.manifest.active.clone() {
            self.recover_active_attempt(port, active, latest_terminal_state)?;
        }
        Ok(())
    }

    fn replay_page(
        &mut self,
        port: &dyn ErasurePersistencePortV1,
        page: &AttemptPageV1,
        predecessor_receipt: Option<ErasureReferenceV1>,
    ) -> Result<(ErasureReferenceV1, ErasureReferenceV1), RecoveryFailureV1> {
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
        let page_admission_matches = [
            admission.request() == self.request.reference(),
            admission.attempt_ordinal() == page.ordinal,
            admission.source_receipt() == predecessor_receipt,
            (admitted.request, admitted.ordinal, admitted.kind)
                == (self.request.reference(), page.ordinal, INVENTORY_ADMITTED),
            (effective.request, effective.ordinal, effective.kind)
                == (self.request.reference(), page.ordinal, INVENTORY_EFFECTIVE),
        ]
        .into_iter()
        .all(|matches| matches);
        if !page_admission_matches {
            return Err(RecoveryFailureV1::new(
                ErasureErrorV1::ProvenanceMissing,
                page.reference,
            ));
        }
        if page.ordinal == 0 && self.dispatch_provenance != Some(admission.reference()) {
            return Err(RecoveryFailureV1::new(
                ErasureErrorV1::ProvenanceMissing,
                admission.reference(),
            ));
        }
        self.validate_attempt_effect(port, &admission)?;
        self.effective
            .retain(|_, value| value.outcome() == ErasureAcknowledgementOutcomeV1::Acknowledged);
        let admitted_values = self.load_acknowledgements(
            port,
            &admission,
            &admitted.references,
            page.admitted_inventory,
        )?;
        self.apply_acknowledgements(admitted_values);
        if canonical_acknowledgement_references(self.effective.values().copied())
            != effective.references
        {
            return Err(RecoveryFailureV1::new(
                ErasureErrorV1::ProvenanceMissing,
                page.effective_inventory,
            ));
        }

        self.validate_completed_attempt(port, page, &admission, &effective, predecessor_receipt)
    }

    fn validate_completed_attempt(
        &self,
        port: &dyn ErasurePersistencePortV1,
        page: &AttemptPageV1,
        admission: &ErasureRetryAdmissionV1,
        effective: &InventoryV1,
        predecessor_receipt: Option<ErasureReferenceV1>,
    ) -> Result<(ErasureReferenceV1, ErasureReferenceV1), RecoveryFailureV1> {
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
            .resolve_state(page.terminal_state)
            .map_err(|error| RecoveryFailureV1::new(error, page.terminal_state))?
            .ok_or_else(|| {
                RecoveryFailureV1::new(ErasureErrorV1::ProvenanceMissing, page.terminal_state)
            })?;
        let terminal_bindings_match = [
            terminal.request() == self.request.reference(),
            outcome.request() == self.request.reference(),
            outcome.attempt() == admission.reference(),
            outcome.source_receipt() == predecessor_receipt,
            outcome.selected_obligations()
                == selected_obligations_reference(admission.unresolved_obligations()),
            outcome.acknowledgement_inventory()
                == acknowledgement_inventory_reference(&effective.references),
            outcome.lifecycle() == terminal.lifecycle(),
            outcome.terminal_position() == provenance.issue_position(),
            outcome.policy() == admission.policy(),
            outcome.trust() == admission.trust(),
            provenance.request() == self.request.reference(),
            provenance.attempt() == admission.reference(),
            provenance.attempt_ordinal() == page.ordinal,
            provenance.predecessor_receipt() == predecessor_receipt,
            provenance.terminal_state() == page.terminal_state,
            provenance.evidence_set() == erasure_evidence_set_reference(&effective.references),
            provenance.policy() == admission.policy(),
            provenance.trust() == admission.trust(),
            receipt.request() == self.request.reference(),
            receipt.receipt_digest() == page.receipt,
            receipt.terminal_state() == page.terminal_state,
            receipt.provenance() == page.receipt_provenance,
            receipt.lifecycle() == terminal.lifecycle(),
            receipt.coordinator() == terminal.coordinator(),
            receipt.policy() == admission.policy(),
            receipt.trust() == admission.trust(),
            receipt.issue_position() == provenance.issue_position(),
        ]
        .into_iter()
        .all(|matches| matches);
        if !terminal_bindings_match {
            return Err(RecoveryFailureV1::new(
                ErasureErrorV1::ProvenanceMissing,
                page.reference,
            ));
        }
        Self::validate_effect_subject(
            port,
            receipt.receipt_digest(),
            &ErasureCasEffectV1::ReceiptAdmission {
                receipt: receipt.receipt_digest(),
            },
        )?;
        receipt
            .validate_frozen_obligations(&self.obligations)
            .map_err(|error| RecoveryFailureV1::new(error, receipt.receipt_digest()))?;
        Ok((receipt.receipt_digest(), page.terminal_state))
    }

    fn load_acknowledgements(
        &self,
        port: &dyn ErasurePersistencePortV1,
        admission: &ErasureRetryAdmissionV1,
        references: &[ErasureReferenceV1],
        failure_subject: ErasureReferenceV1,
    ) -> Result<
        BTreeMap<(ErasureReferenceV1, ErasureReferenceV1), ErasureAcknowledgementProvenanceV1>,
        RecoveryFailureV1,
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
            if !self.acknowledgement_matches_admission(&acknowledgement, admission)
                || values.insert(key, acknowledgement).is_some()
            {
                return Err(RecoveryFailureV1::new(
                    ErasureErrorV1::ProvenanceMissing,
                    *reference,
                ));
            }
            Self::validate_effect_subject(
                port,
                *reference,
                &ErasureCasEffectV1::AcknowledgementAdmission {
                    acknowledgement: *reference,
                },
            )?;
        }
        (canonical_acknowledgement_references(values.values().copied()) == references)
            .then_some(values)
            .ok_or_else(|| {
                RecoveryFailureV1::new(ErasureErrorV1::ProvenanceMissing, failure_subject)
            })
    }

    fn validate_attempt_effect(
        &self,
        port: &dyn ErasurePersistencePortV1,
        admission: &ErasureRetryAdmissionV1,
    ) -> Result<(), RecoveryFailureV1> {
        let obligation_set = self.obligation_set.as_ref().ok_or_else(|| {
            RecoveryFailureV1::new(ErasureErrorV1::ProvenanceMissing, admission.reference())
        })?;
        let acknowledged = self
            .effective
            .values()
            .filter(|value| value.outcome() == ErasureAcknowledgementOutcomeV1::Acknowledged)
            .map(ErasureAcknowledgementProvenanceV1::obligation)
            .collect::<BTreeSet<_>>();
        let unresolved = self
            .obligations
            .iter()
            .filter(|obligation| !acknowledged.contains(&obligation.reference()))
            .collect::<Vec<_>>();
        let expected_obligations = unresolved
            .iter()
            .map(|obligation| obligation.reference())
            .collect::<Vec<_>>();
        let expected_identities = unresolved
            .iter()
            .map(|obligation| obligation.command_identity())
            .collect::<Vec<_>>();
        let obligations_match =
            admission.unresolved_obligations() == expected_obligations.as_slice();
        let identities_match = admission.command_identities() == expected_identities.as_slice();
        let admission_matches = admission.policy() == obligation_set.policy()
            && admission.trust() == obligation_set.trust()
            && obligations_match
            && identities_match;
        if !admission_matches {
            return Err(RecoveryFailureV1::new(
                ErasureErrorV1::ProvenanceMissing,
                admission.reference(),
            ));
        }
        let expected_commands = unresolved
            .into_iter()
            .map(|obligation| {
                ErasureDestructionCommandV1::from_obligation(obligation, admission.reference())
            })
            .collect::<Vec<_>>();
        let manifest = port
            .effect_manifest(admission.reference())
            .map_err(|error| RecoveryFailureV1::new(error, admission.reference()))?
            .ok_or_else(|| {
                RecoveryFailureV1::new(ErasureErrorV1::ProvenanceMissing, admission.reference())
            })?;
        match port
            .read_effect(manifest)
            .map_err(|error| RecoveryFailureV1::new(error, manifest))?
        {
            ErasureCasEffectV1::AttemptAdmission {
                reservation,
                commands,
            } => {
                let reservation_matches = reservation.admission() == admission.reference();
                if reservation_matches && commands == expected_commands {
                    Ok(())
                } else {
                    Err(RecoveryFailureV1::new(
                        ErasureErrorV1::ProvenanceMissing,
                        manifest,
                    ))
                }
            }
            _ => Err(RecoveryFailureV1::new(
                ErasureErrorV1::ProvenanceMissing,
                manifest,
            )),
        }
    }

    fn validate_effect_subject(
        port: &dyn ErasurePersistencePortV1,
        subject: ErasureReferenceV1,
        expected: &ErasureCasEffectV1,
    ) -> Result<(), RecoveryFailureV1> {
        let manifest = port
            .effect_manifest(subject)
            .map_err(|error| RecoveryFailureV1::new(error, subject))?
            .ok_or_else(|| RecoveryFailureV1::new(ErasureErrorV1::ProvenanceMissing, subject))?;
        let effect = port
            .read_effect(manifest)
            .map_err(|error| RecoveryFailureV1::new(error, manifest))?;
        if &effect == expected {
            Ok(())
        } else {
            Err(RecoveryFailureV1::new(
                ErasureErrorV1::ProvenanceMissing,
                manifest,
            ))
        }
    }

    fn acknowledgement_matches_admission(
        &self,
        acknowledgement: &ErasureAcknowledgementProvenanceV1,
        admission: &ErasureRetryAdmissionV1,
    ) -> bool {
        let Some(scope) = self.scope.as_ref() else {
            return false;
        };
        let Some(obligation) = self
            .obligations
            .iter()
            .find(|value| value.reference() == acknowledgement.obligation())
        else {
            return false;
        };
        let selected = admission
            .unresolved_obligations()
            .binary_search(&acknowledgement.obligation())
            .is_ok_and(|index| admission.command_identities()[index] == acknowledgement.command());
        acknowledgement.request() == self.request.reference()
            && acknowledgement.attempt() == admission.reference()
            && acknowledgement.scope() == scope.reference()
            && acknowledgement.policy() == admission.policy()
            && acknowledgement.trust() == admission.trust()
            && acknowledgement.owner() == obligation.owner()
            && acknowledgement.command() == obligation.command_identity()
            && selected
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

    fn recover_scope(
        &mut self,
        port: &dyn ErasurePersistencePortV1,
        verifier: &dyn ErasureRecoveryAuthorizationVerifierV1,
    ) -> Result<(), RecoveryFailureV1> {
        let fallback_subject = self
            .manifest
            .scope_extension_head
            .unwrap_or(self.manifest.state);
        let count = port
            .scope_index_count(self.request.reference())
            .map_err(|error| RecoveryFailureV1::new(error, fallback_subject))?;
        if count > ERASURE_MAX_SCOPE_EXTENSIONS as u64
            || (count == 0) != self.manifest.scope_extension_head.is_none()
        {
            return Err(RecoveryFailureV1::new(
                ErasureErrorV1::ProvenanceMissing,
                fallback_subject,
            ));
        }
        let mut predecessor_node = None;
        let mut predecessor_extension = None;
        let mut forks = BTreeSet::new();
        let lineage_rule = self
            .scope
            .as_ref()
            .and_then(ErasureScopeCommitmentV1::lineage_rule);
        for ordinal in 0..count {
            let reference = port
                .scope_node_ref(self.request.reference(), ordinal)
                .map_err(|error| RecoveryFailureV1::new(error, fallback_subject))?
                .ok_or_else(|| {
                    RecoveryFailureV1::new(ErasureErrorV1::ProvenanceMissing, fallback_subject)
                })?;
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
                || Some(extension.lineage_rule()) != lineage_rule
                || extension.predecessor_extension() != predecessor_extension
                || !forks.insert(extension.fork())
            {
                return Err(RecoveryFailureV1::new(
                    ErasureErrorV1::ProvenanceMissing,
                    reference,
                ));
            }
            verifier
                .validate_scope_extension(&extension)
                .map_err(|error| RecoveryFailureV1::new(error, extension.reference()))?;
            predecessor_node = Some(reference);
            predecessor_extension = Some(extension.reference());
            self.scope_extensions.push(extension);
            self.scope_head = Some(RecoveredScopeHeadV1 {
                node: reference,
                extension: extension.reference(),
                ordinal,
            });
        }
        if predecessor_node != self.manifest.scope_extension_head {
            return Err(RecoveryFailureV1::new(
                ErasureErrorV1::ProvenanceMissing,
                fallback_subject,
            ));
        }
        Ok(())
    }

    fn recover_administrative_resolutions(
        &mut self,
        port: &dyn ErasurePersistencePortV1,
        verifier: &dyn ErasureRecoveryAuthorizationVerifierV1,
    ) -> Result<(), RecoveryFailureV1> {
        let fallback_subject = self
            .manifest
            .administrative_resolution_head
            .unwrap_or(self.manifest.state);
        let count = port
            .administrative_resolution_index_count(self.request.reference())
            .map_err(|error| RecoveryFailureV1::new(error, fallback_subject))?;
        if count > ERASURE_MAX_ADMINISTRATIVE_RESOLUTIONS as u64
            || (count == 0) != self.administrative_resolution_head.is_none()
        {
            return Err(RecoveryFailureV1::new(
                ErasureErrorV1::ProvenanceMissing,
                fallback_subject,
            ));
        }
        if count == 0 {
            return Ok(());
        }
        let scope = self.scope.as_ref().ok_or_else(|| {
            RecoveryFailureV1::new(ErasureErrorV1::ProvenanceMissing, fallback_subject)
        })?;
        let obligation_set = self.obligation_set.as_ref().ok_or_else(|| {
            RecoveryFailureV1::new(ErasureErrorV1::ProvenanceMissing, fallback_subject)
        })?;
        let mut predecessor = None;
        for ordinal in 0..count {
            let reference = port
                .administrative_resolution_ref(self.request.reference(), ordinal)
                .map_err(|error| RecoveryFailureV1::new(error, fallback_subject))?
                .ok_or_else(|| {
                    RecoveryFailureV1::new(ErasureErrorV1::ProvenanceMissing, fallback_subject)
                })?;
            let resolution = load(
                port,
                reference,
                ErasureAdministrativeResolutionV1::from_canonical_cbor,
                ErasureAdministrativeResolutionV1::reference,
            )?;
            if resolution.request() != self.request.reference()
                || resolution.predecessor_resolution() != predecessor
                || resolution.scope_commitment() != scope.reference()
                || resolution.policy() != self.request.policy()
                || resolution.trust() != obligation_set.trust()
            {
                return Err(RecoveryFailureV1::new(
                    ErasureErrorV1::ProvenanceMissing,
                    reference,
                ));
            }
            verifier
                .validate_administrative_resolution(&resolution)
                .map_err(|error| RecoveryFailureV1::new(error, resolution.reference()))?;
            predecessor = Some(reference);
        }
        if predecessor != self.administrative_resolution_head {
            return Err(RecoveryFailureV1::new(
                ErasureErrorV1::ProvenanceMissing,
                fallback_subject,
            ));
        }
        self.administrative_resolution_count = count;
        Ok(())
    }
}

const fn persistence_object(
    reference: ErasureReferenceV1,
    canonical_cbor: Vec<u8>,
) -> ErasurePersistenceObjectV1 {
    ErasurePersistenceObjectV1::new(reference, canonical_cbor)
}

fn encoded_persistence_object(
    reference: ErasureReferenceV1,
    canonical_cbor: Result<Vec<u8>, ErasureErrorV1>,
) -> Result<ErasurePersistenceObjectV1, ErasureErrorV1> {
    canonical_cbor.map(|bytes| persistence_object(reference, bytes))
}

fn canonical_acknowledgement_references(
    values: impl Iterator<Item = ErasureAcknowledgementProvenanceV1>,
) -> Vec<ErasureReferenceV1> {
    let mut values = values.collect::<Vec<_>>();
    values.sort_unstable_by_key(|value| {
        (
            value.command(),
            value.attempt(),
            value.owner(),
            value.obligation(),
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

struct FixedGraphV1<'a> {
    requested: ErasureReferenceV1,
    erq: &'a ErasureRequestV1,
    state: &'a ErasureStateV1,
    targets: &'a [ErasureRequiredTargetV1],
    correction: Option<&'a ErasureCorrectionProvenanceV1>,
    rejection: Option<&'a ErasureAuthorizationRejectionV1>,
    scope: Option<&'a ErasureScopeCommitmentV1>,
    admission: Option<&'a ErasureFreezeAdmissionEvidenceV1>,
    authorization: Option<&'a ErasureFreezeAuthorizationEvidenceV1>,
    freeze: Option<&'a ErasureFreezeProvenanceV1>,
    failure: Option<&'a ErasureFreezeFailureV1>,
    obligation_set: Option<&'a ErasureObligationSetV1>,
    obligations: &'a [ErasureObligationV1],
    authorize_provenance: Option<ErasureReferenceV1>,
    verifier: &'a dyn ErasureFreezeAuthorizationVerifierV1,
}

fn validate_fixed_graph(graph: &FixedGraphV1<'_>) -> Result<(), ErasureErrorV1> {
    let fixed_bindings_match = [
        graph.erq.reference() == graph.requested,
        graph.state.request() == graph.requested,
        graph
            .correction
            .is_none_or(|value| graph.erq.provenance() == value.reference()),
        graph
            .rejection
            .is_none_or(|value| value.request() == graph.requested),
        graph
            .failure
            .is_none_or(|value| value.request() == graph.requested),
        graph
            .scope
            .is_none_or(|value| value.request() == graph.requested),
        graph
            .admission
            .is_none_or(|value| value.request() == graph.requested),
        graph
            .obligation_set
            .is_none_or(|value| value.request() == graph.requested),
        graph
            .freeze
            .is_none_or(|value| value.request() == graph.requested),
    ]
    .into_iter()
    .all(|matches| matches);
    if !fixed_bindings_match {
        return Err(ErasureErrorV1::ProvenanceMissing);
    }
    match (graph.admission, graph.authorization) {
        (Some(admission), Some(authorization)) => {
            graph
                .verifier
                .validate_freeze_authorization(admission, authorization)?;
        }
        (None, None) => {}
        _ => return Err(ErasureErrorV1::ProvenanceMissing),
    }
    if let (Some(scope), Some(admission), Some(authorization), Some(freeze), Some(set)) = (
        graph.scope,
        graph.admission,
        graph.authorization,
        graph.freeze,
        graph.obligation_set,
    ) {
        let reconstructed =
            ErasureAtomicFreezeAdmissionV1::new(ErasureAtomicFreezeAdmissionInputV1 {
                targets: graph.targets.to_vec(),
                scope: ErasureScopeCommitmentInputV1 {
                    request: scope.request(),
                    scope_members: scope.scope_members().to_vec(),
                    target_closure: scope.target_closure(),
                    lineage_rule: scope.lineage_rule(),
                },
                obligations: graph.obligations.to_vec(),
                obligation_set: set.clone(),
                freeze_position: admission.freeze_position(),
                freeze_admission_evidence: admission.clone(),
                freeze_authorization_evidence: authorization.clone(),
            })?;
        let frozen_bindings_match = [
            reconstructed.targets() == graph.targets,
            scope.target_closure() == target_closure_digest(graph.targets),
            freeze.scope_commitment() == scope.reference(),
            freeze.obligation_set() == set.reference(),
            freeze.host_evidence() == admission.reference(),
            freeze.freeze_position() == admission.freeze_position(),
            graph.state.freeze_position() == Some(admission.freeze_position()),
            set.policy() == graph.erq.policy(),
            graph.authorize_provenance.is_some(),
            graph.rejection.is_none(),
            graph.failure.is_none(),
            matches!(
                graph.state.lifecycle(),
                ErasureLifecycleV1::AccessFrozen
                    | ErasureLifecycleV1::DestructionDispatched
                    | ErasureLifecycleV1::AwaitingAcknowledgements
                    | ErasureLifecycleV1::PartialFailure
                    | ErasureLifecycleV1::Complete
            ),
            graph.state.lifecycle() != ErasureLifecycleV1::AccessFrozen
                || graph.state.provenance() == freeze.reference(),
        ]
        .into_iter()
        .all(|matches| matches);
        if !frozen_bindings_match {
            return Err(ErasureErrorV1::ProvenanceMissing);
        }
    } else if graph.scope.is_some()
        || graph.admission.is_some()
        || graph.freeze.is_some()
        || graph.obligation_set.is_some()
        || !graph.targets.is_empty()
        || !graph.obligations.is_empty()
    {
        return Err(ErasureErrorV1::ProvenanceMissing);
    }
    validate_unfrozen_graph(graph)?;
    Ok(())
}

fn validate_unfrozen_graph(graph: &FixedGraphV1<'_>) -> Result<(), ErasureErrorV1> {
    if graph.freeze.is_some() {
        return Ok(());
    }
    match (graph.rejection, graph.failure, graph.state.lifecycle()) {
        (Some(rejection), None, ErasureLifecycleV1::Rejected)
            if graph.authorize_provenance.is_none()
                && graph.state.provenance() == rejection.reference() =>
        {
            Ok(())
        }
        (None, Some(failure), ErasureLifecycleV1::Rejected)
            if graph.authorize_provenance == Some(failure.authorization_provenance())
                && graph.state.provenance() == failure.reference() =>
        {
            Ok(())
        }
        (None, None, ErasureLifecycleV1::Submitted)
            if graph.authorize_provenance.is_none()
                && graph.state.provenance() == graph.erq.provenance() =>
        {
            Ok(())
        }
        (None, None, ErasureLifecycleV1::Authorized)
            if graph.authorize_provenance == Some(graph.state.provenance()) =>
        {
            Ok(())
        }
        _ => Err(ErasureErrorV1::ProvenanceMissing),
    }
}

fn validate_correction(
    port: &dyn ErasurePersistencePortV1,
    request: &ErasureRequestV1,
    correction: Option<&ErasureCorrectionProvenanceV1>,
) -> Result<(), ErasureErrorV1> {
    let Some(correction) = correction else {
        return Ok(());
    };
    if request.provenance() != correction.reference()
        || request.reference() == correction.rejected_request()
    {
        return Err(ErasureErrorV1::ProvenanceMissing);
    }
    let rejected = port
        .resolve_state(correction.rejected_terminal_state())?
        .ok_or(ErasureErrorV1::ProvenanceMissing)?;
    if rejected.request() == correction.rejected_request()
        && rejected.lifecycle() == ErasureLifecycleV1::Rejected
    {
        Ok(())
    } else {
        Err(ErasureErrorV1::ProvenanceMissing)
    }
}

fn validate_state_provenance(
    port: &dyn ErasurePersistencePortV1,
    state: &ErasureStateV1,
    manifest: &ManifestV1,
) -> Result<(), ErasureErrorV1> {
    let mut current = state.clone();
    let mut authorization = None;
    let mut dispatch = None;
    for _ in 0..ERASURE_MAX_ATTEMPT_OUTCOMES.saturating_add(8) {
        match current.lifecycle() {
            ErasureLifecycleV1::Authorized => authorization = Some(current.provenance()),
            ErasureLifecycleV1::DestructionDispatched => dispatch = Some(current.provenance()),
            _ => {}
        }
        let Some(previous) = current.previous_state() else {
            if authorization == manifest.authorize_provenance
                && dispatch == manifest.dispatch_provenance
            {
                return Ok(());
            }
            return Err(ErasureErrorV1::ProvenanceMissing);
        };
        current = port
            .resolve_state(previous)?
            .ok_or(ErasureErrorV1::ProvenanceMissing)?;
    }
    Err(ErasureErrorV1::ProvenanceMissing)
}
