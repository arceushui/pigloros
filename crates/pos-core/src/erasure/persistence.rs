//! Bounded, core-owned ERCRP1 persistence graph.

use super::evidence::{
    bytes32, digest, header, optional_bytes32, optional_digest, references_value,
    target_from_value, target_value, text, uint, unordered_references_from_value, unsigned,
};
use super::{
    acknowledgement_inventory_reference, decode_limited, destruction_command_reference,
    domain_digest, encode_limited, erasure_evidence_set_reference, exact_array,
    selected_obligations_reference, target_closure_digest, verify_predecessor_chain_with_subject,
    BTreeMap, BTreeSet, ErasureAcknowledgementOutcomeV1, ErasureAcknowledgementProvenanceV1,
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
    ErasureStateResolverV1, ErasureStateV1, ErasureVerifiedStateV1, PreparedErasureCasV1,
    RecoveryFailureV1, StoredErasureManifestV1, ERASURE_ACKNOWLEDGEMENT_INVENTORY_TAG_V1,
    ERASURE_ATTEMPT_HISTORY_TAG_V1, ERASURE_COORDINATOR_RECORD_MAX_BYTES,
    ERASURE_MAX_ACKNOWLEDGEMENTS_PER_ATTEMPT, ERASURE_MAX_ADMINISTRATIVE_RESOLUTIONS,
    ERASURE_MAX_ATTEMPT_OUTCOMES, ERASURE_MAX_SCOPE_EXTENSIONS, ERASURE_MAX_TARGETS,
    ERASURE_PORTABLE_RECORD_MAX_BYTES, ERASURE_SCOPE_EXTENSION_HEAD_TAG_V1,
    ERASURE_TARGET_CLOSURE_TAG_V1, ERCRP1, VERSION,
};
use ciborium::value::Value;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct InventoryKindV1(u64);

const INVENTORY_ADMITTED: InventoryKindV1 = InventoryKindV1(0);
const INVENTORY_EFFECTIVE: InventoryKindV1 = InventoryKindV1(1);

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
        value.canonical_cbor().map(|bytes| {
            value.reference = addressed(ERASURE_TARGET_CLOSURE_TAG_V1, &bytes);
            value
        })
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
            Self::new(bytes32(&fields[2])?, targets)
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
        if kind > INVENTORY_EFFECTIVE.0
            || references.len() > ERASURE_MAX_ACKNOWLEDGEMENTS_PER_ATTEMPT
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
        value.canonical_cbor().map(|bytes| {
            value.reference = addressed(ERASURE_ACKNOWLEDGEMENT_INVENTORY_TAG_V1, &bytes);
            value
        })
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
            Ok(inventory)
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

struct CompletedAttemptEvidenceV1 {
    outcome: ErasureAttemptOutcomeV1,
    receipt: ErasureReceiptV1,
    provenance: ErasureReceiptProvenanceV1,
    terminal: ErasureStateV1,
}

struct CompletedAttemptContextV1<'a> {
    request: ErasureReferenceV1,
    page: &'a AttemptPageV1,
    admission: &'a ErasureRetryAdmissionV1,
    effective: &'a InventoryV1,
    predecessor_receipt: Option<ErasureReferenceV1>,
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

fn load_completed_attempt_evidence(
    port: &dyn ErasurePersistencePortV1,
    page: &AttemptPageV1,
) -> Result<CompletedAttemptEvidenceV1, RecoveryFailureV1> {
    let outcome = load_recovery_object(
        port,
        page.outcome,
        ErasureAttemptOutcomeV1::from_canonical_cbor,
        ErasureAttemptOutcomeV1::reference,
    )?;
    let receipt = load_recovery_object(
        port,
        page.receipt,
        ErasureReceiptV1::from_canonical_cbor,
        ErasureReceiptV1::receipt_digest,
    )?;
    let provenance = load_recovery_object(
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
    Ok(CompletedAttemptEvidenceV1 {
        outcome,
        receipt,
        provenance,
        terminal,
    })
}

fn optional<T>(
    port: &dyn ErasurePersistencePortV1,
    reference: Option<ErasureReferenceV1>,
    decode: impl FnOnce(&[u8]) -> Result<T, ErasureErrorV1> + Copy,
    address: impl FnOnce(&T) -> ErasureReferenceV1 + Copy,
) -> Result<Option<T>, RecoveryFailureV1> {
    reference.map_or(Ok(None), |reference| {
        load_recovery_object(port, reference, decode, address).map(Some)
    })
}

fn recover_foundation(
    port: &dyn ErasurePersistencePortV1,
    requested: ErasureReferenceV1,
    manifest: &ManifestV1,
) -> Result<RecoveredFoundationV1, RecoveryFailureV1> {
    let request = load_recovery_object(
        port,
        requested,
        ErasureRequestV1::from_canonical_cbor,
        ErasureRequestV1::reference,
    )?;
    let state = port
        .resolve_state(manifest.state)
        .map_err(|error| RecoveryFailureV1::new(error, manifest.state))?
        .ok_or_else(|| RecoveryFailureV1::new(ErasureErrorV1::ProvenanceMissing, manifest.state))?;
    if state.request() != requested {
        return Err(RecoveryFailureV1::new(
            ErasureErrorV1::ProvenanceMissing,
            state.state_digest(),
        ));
    }
    verify_predecessor_chain_with_subject(state.clone(), port)
        .map_err(|failure| RecoveryFailureV1::new(failure.error(), failure.subject()))?;
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
                load_recovery_object(
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

fn recover_manifest(
    requested: ErasureReferenceV1,
    stored: &StoredErasureManifestV1,
) -> Result<ManifestV1, RecoveryFailureV1> {
    if !stored.content_address_matches() {
        return Err(RecoveryFailureV1::new(
            ErasureErrorV1::ProvenanceMissing,
            stored.digest(),
        ));
    }
    let manifest = ManifestV1::decode(stored.canonical_cbor())
        .map_err(|error| RecoveryFailureV1::new(error, stored.digest()))?;
    if manifest.request != requested {
        return Err(RecoveryFailureV1::new(
            ErasureErrorV1::ProvenanceMissing,
            stored.digest(),
        ));
    }
    Ok(manifest)
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
        let manifest = recover_manifest(requested, stored)?;
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
            target_closure: manifest.target_closure,
            manifest: stored.digest(),
            verifier,
        })?;
        validate_correction(port, &foundation.request, evidence.correction.as_ref())?;
        validate_state_provenance(port, &foundation.state, &manifest, stored.digest())?;

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
        self.manifest.validate_shape().and_then(|()| {
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
        TargetClosureV1::new(self.request.reference(), admission.targets().to_vec()).and_then(
            |closure| {
                [
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
                .collect::<Result<Vec<_>, _>>()
                .and_then(|mut objects| {
                    admission
                        .obligations()
                        .iter()
                        .map(|obligation| {
                            encoded_persistence_object(
                                obligation.reference(),
                                obligation.to_canonical_cbor(),
                            )
                        })
                        .collect::<Result<Vec<_>, _>>()
                        .map(|obligation_objects| {
                            objects.extend(obligation_objects);
                            objects
                        })
                })
                .map(|objects| {
                    self.manifest.target_closure = Some(closure.reference);
                    self.manifest.scope = Some(scope.reference());
                    self.manifest.freeze_admission =
                        Some(admission.freeze_admission_evidence().reference());
                    self.manifest.freeze_authorization =
                        Some(admission.freeze_authorization_evidence().reference());
                    self.manifest.freeze_provenance = Some(freeze.reference());
                    self.manifest.obligation_set = Some(admission.obligation_set().reference());
                    self.targets = closure.targets;
                    self.scope = Some(scope);
                    self.freeze_admission = Some(admission.freeze_admission_evidence().clone());
                    self.freeze_authorization =
                        Some(admission.freeze_authorization_evidence().clone());
                    self.freeze_provenance = Some(freeze);
                    self.obligation_set = Some(admission.obligation_set().clone());
                    self.obligations = admission.obligations().to_vec();
                    objects
                })
            },
        )
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
        self.active
            .as_mut()
            .zip(self.manifest.active.as_mut())
            .map_or_else(
                || Err(ErasureErrorV1::ProvenanceMissing),
                |(active, manifest_active)| {
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
                },
            )
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
        self.active.as_ref().map_or_else(
            || Err(ErasureErrorV1::ProvenanceMissing),
            |active| {
                let ordinal = active.ordinal;
                let retry_admission = active.admission.reference();
                let admitted_references =
                    canonical_acknowledgement_references(active.admitted.values().copied());
                InventoryV1::new(
                    self.request.reference(),
                    ordinal,
                    INVENTORY_ADMITTED.0,
                    admitted_references,
                )
                .and_then(|admitted| {
                    InventoryV1::new(
                        self.request.reference(),
                        ordinal,
                        INVENTORY_EFFECTIVE.0,
                        canonical_acknowledgement_references(self.effective.values().copied()),
                    )
                    .and_then(|effective| {
                        let page = AttemptPageV1 {
                            request: self.request.reference(),
                            ordinal,
                            retry_admission,
                            admitted_inventory: admitted.reference,
                            effective_inventory: effective.reference,
                            outcome: outcome.reference(),
                            receipt: receipt.receipt_digest(),
                            receipt_provenance: receipt_provenance.reference(),
                            terminal_state: self.state.state_digest(),
                            predecessor: self.attempt_history_head,
                            reference: super::reference_zero(),
                        };
                        page.canonical_cbor().and_then(|page_bytes| {
                            let page_reference =
                                addressed(ERASURE_ATTEMPT_HISTORY_TAG_V1, &page_bytes);
                            [
                                encoded_persistence_object(
                                    admitted.reference,
                                    admitted.canonical_cbor(),
                                ),
                                encoded_persistence_object(
                                    effective.reference,
                                    effective.canonical_cbor(),
                                ),
                                encoded_persistence_object(
                                    outcome.reference(),
                                    outcome.to_canonical_cbor(),
                                ),
                                encoded_persistence_object(
                                    receipt_provenance.reference(),
                                    receipt_provenance.to_canonical_cbor(),
                                ),
                                encoded_persistence_object(
                                    receipt.receipt_digest(),
                                    receipt.to_canonical_cbor(),
                                ),
                            ]
                            .into_iter()
                            .collect::<Result<Vec<_>, _>>()
                            .map(|mut objects| {
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
                                (
                                    objects,
                                    ErasureIndexInsertV1::AttemptPage {
                                        ordinal,
                                        reference: page_reference,
                                    },
                                )
                            })
                        })
                    })
                })
            },
        )
    }

    fn recover_active_attempt(
        &mut self,
        port: &dyn ErasurePersistencePortV1,
        active: &ActiveAttemptRefV1,
        latest_terminal_state: Option<ErasureReferenceV1>,
    ) -> Result<(), RecoveryFailureV1> {
        let admission = load_recovery_object(
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
            .map_err(|error| RecoveryFailureV1::new(error, self.manifest_digest))?;
        if index_count != self.completed_attempt_count {
            return Err(RecoveryFailureV1::new(
                ErasureErrorV1::ProvenanceMissing,
                self.manifest_digest,
            ));
        }
        let mut predecessor = None;
        let mut predecessor_receipt = None;
        let mut latest_terminal_state = None;
        for ordinal in 0..self.completed_attempt_count {
            let reference = port
                .attempt_page_ref(self.request.reference(), ordinal)
                .map_err(|error| RecoveryFailureV1::new(error, self.manifest_digest))?
                .ok_or_else(|| {
                    RecoveryFailureV1::new(ErasureErrorV1::ProvenanceMissing, self.manifest_digest)
                })?;
            let page = load_recovery_object(port, reference, AttemptPageV1::decode, |value| {
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
                self.manifest_digest,
            ));
        }
        if predecessor_receipt != self.latest_receipt {
            return Err(RecoveryFailureV1::new(
                ErasureErrorV1::ProvenanceMissing,
                self.manifest_digest,
            ));
        }
        if self.completed_attempt_count > 0 && latest_terminal_state != Some(self.manifest.state) {
            return Err(RecoveryFailureV1::new(
                ErasureErrorV1::ProvenanceMissing,
                self.manifest_digest,
            ));
        }
        if let Some(active) = self.manifest.active.clone() {
            self.recover_active_attempt(port, &active, latest_terminal_state)?;
        }
        Ok(())
    }

    fn replay_page(
        &mut self,
        port: &dyn ErasurePersistencePortV1,
        page: &AttemptPageV1,
        predecessor_receipt: Option<ErasureReferenceV1>,
    ) -> Result<(ErasureReferenceV1, ErasureReferenceV1), RecoveryFailureV1> {
        let admission = load_recovery_object(
            port,
            page.retry_admission,
            ErasureRetryAdmissionV1::from_canonical_cbor,
            ErasureRetryAdmissionV1::reference,
        )?;
        let admitted = load_recovery_object(
            port,
            page.admitted_inventory,
            InventoryV1::decode,
            |value| value.reference,
        )?;
        let effective = load_recovery_object(
            port,
            page.effective_inventory,
            InventoryV1::decode,
            |value| value.reference,
        )?;
        self.validate_replay_page_bindings(
            page,
            &admission,
            &admitted,
            &effective,
            predecessor_receipt,
        )?;
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

        let context = CompletedAttemptContextV1 {
            request: self.request.reference(),
            page,
            admission: &admission,
            effective: &effective,
            predecessor_receipt,
        };
        self.validate_completed_attempt(port, &context)
    }

    fn validate_replay_page_bindings(
        &self,
        page: &AttemptPageV1,
        admission: &ErasureRetryAdmissionV1,
        admitted: &InventoryV1,
        effective: &InventoryV1,
        predecessor_receipt: Option<ErasureReferenceV1>,
    ) -> Result<(), RecoveryFailureV1> {
        let admission_matches = [
            admission.request() == self.request.reference(),
            admission.attempt_ordinal() == page.ordinal,
            admission.source_receipt() == predecessor_receipt,
        ]
        .into_iter()
        .all(|matches| matches);
        if !admission_matches {
            return Err(RecoveryFailureV1::new(
                ErasureErrorV1::ProvenanceMissing,
                admission.reference(),
            ));
        }
        Self::validate_replay_inventory(
            self.request.reference(),
            page,
            admitted,
            INVENTORY_ADMITTED,
        )?;
        Self::validate_replay_inventory(
            self.request.reference(),
            page,
            effective,
            INVENTORY_EFFECTIVE,
        )?;
        if page.ordinal == 0 && self.dispatch_provenance != Some(admission.reference()) {
            return Err(RecoveryFailureV1::new(
                ErasureErrorV1::ProvenanceMissing,
                admission.reference(),
            ));
        }
        Ok(())
    }

    fn validate_replay_inventory(
        request: ErasureReferenceV1,
        page: &AttemptPageV1,
        inventory: &InventoryV1,
        expected_kind: InventoryKindV1,
    ) -> Result<(), RecoveryFailureV1> {
        ((inventory.request, inventory.ordinal, inventory.kind)
            == (request, page.ordinal, expected_kind.0))
            .then_some(())
            .ok_or_else(|| {
                RecoveryFailureV1::new(ErasureErrorV1::ProvenanceMissing, inventory.reference)
            })
    }

    fn validate_completed_attempt(
        &self,
        port: &dyn ErasurePersistencePortV1,
        context: &CompletedAttemptContextV1<'_>,
    ) -> Result<(ErasureReferenceV1, ErasureReferenceV1), RecoveryFailureV1> {
        load_completed_attempt_evidence(port, context.page).and_then(
            |CompletedAttemptEvidenceV1 {
                 outcome,
                 receipt,
                 provenance,
                 terminal,
             }| {
                validate_recovery_bindings([(
                    terminal.request() == context.request,
                    terminal.state_digest(),
                )])
                .and_then(|()| {
                    Self::validate_completed_outcome(&outcome, &terminal, &provenance, context)
                })
                .and_then(|()| Self::validate_completed_provenance(&provenance, context))
                .and_then(|()| {
                    Self::validate_completed_receipt(
                        &receipt,
                        context.page,
                        &terminal,
                        &provenance,
                        context.admission,
                    )
                })
                .and_then(|()| {
                    Self::validate_effect_subject(
                        port,
                        receipt.receipt_digest(),
                        &ErasureCasEffectV1::ReceiptAdmission {
                            receipt: receipt.receipt_digest(),
                        },
                    )
                })
                .and_then(|()| {
                    receipt
                        .validate_frozen_obligations(&self.obligations)
                        .map_err(|error| RecoveryFailureV1::new(error, receipt.receipt_digest()))
                })
                .map(|()| (receipt.receipt_digest(), context.page.terminal_state))
            },
        )
    }

    fn validate_completed_outcome(
        outcome: &ErasureAttemptOutcomeV1,
        terminal: &ErasureStateV1,
        provenance: &ErasureReceiptProvenanceV1,
        context: &CompletedAttemptContextV1<'_>,
    ) -> Result<(), RecoveryFailureV1> {
        validate_recovery_bindings([
            (outcome.request() == context.request, outcome.reference()),
            (
                outcome.attempt() == context.admission.reference(),
                outcome.reference(),
            ),
            (
                outcome.source_receipt() == context.predecessor_receipt,
                outcome.reference(),
            ),
            (
                outcome.selected_obligations()
                    == selected_obligations_reference(context.admission.unresolved_obligations()),
                outcome.reference(),
            ),
            (
                outcome.acknowledgement_inventory()
                    == acknowledgement_inventory_reference(&context.effective.references),
                outcome.reference(),
            ),
            (
                outcome.lifecycle() == terminal.lifecycle(),
                outcome.reference(),
            ),
            (
                outcome.terminal_position() == provenance.issue_position(),
                outcome.reference(),
            ),
            (
                outcome.policy() == context.admission.policy(),
                outcome.reference(),
            ),
            (
                outcome.trust() == context.admission.trust(),
                outcome.reference(),
            ),
        ])
    }

    fn validate_completed_provenance(
        provenance: &ErasureReceiptProvenanceV1,
        context: &CompletedAttemptContextV1<'_>,
    ) -> Result<(), RecoveryFailureV1> {
        validate_recovery_bindings([
            (
                provenance.request() == context.request,
                provenance.reference(),
            ),
            (
                provenance.attempt() == context.admission.reference(),
                provenance.reference(),
            ),
            (
                provenance.attempt_ordinal() == context.page.ordinal,
                provenance.reference(),
            ),
            (
                provenance.predecessor_receipt() == context.predecessor_receipt,
                provenance.reference(),
            ),
            (
                provenance.terminal_state() == context.page.terminal_state,
                provenance.reference(),
            ),
            (
                provenance.evidence_set()
                    == erasure_evidence_set_reference(&context.effective.references),
                provenance.reference(),
            ),
            (
                provenance.policy() == context.admission.policy(),
                provenance.reference(),
            ),
            (
                provenance.trust() == context.admission.trust(),
                provenance.reference(),
            ),
        ])
    }

    fn validate_completed_receipt(
        receipt: &ErasureReceiptV1,
        page: &AttemptPageV1,
        terminal: &ErasureStateV1,
        provenance: &ErasureReceiptProvenanceV1,
        admission: &ErasureRetryAdmissionV1,
    ) -> Result<(), RecoveryFailureV1> {
        let receipt_reference = receipt.receipt_digest();
        validate_recovery_bindings([
            (receipt.request() == admission.request(), receipt_reference),
            (receipt_reference == page.receipt, receipt_reference),
            (
                receipt.terminal_state() == page.terminal_state,
                receipt_reference,
            ),
            (
                receipt.provenance() == page.receipt_provenance,
                receipt_reference,
            ),
            (
                receipt.lifecycle() == terminal.lifecycle(),
                receipt_reference,
            ),
            (
                receipt.coordinator() == terminal.coordinator(),
                receipt_reference,
            ),
            (receipt.policy() == admission.policy(), receipt_reference),
            (receipt.trust() == admission.trust(), receipt_reference),
            (
                receipt.issue_position() == provenance.issue_position(),
                receipt_reference,
            ),
        ])
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
            let acknowledgement = load_recovery_object(
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

    fn validate_attempt_admission(
        &self,
        admission: &ErasureRetryAdmissionV1,
    ) -> Result<Vec<ErasureDestructionCommandV1>, RecoveryFailureV1> {
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
        if admission.policy() != obligation_set.policy()
            || admission.trust() != obligation_set.trust()
        {
            return Err(RecoveryFailureV1::new(
                ErasureErrorV1::ProvenanceMissing,
                obligation_set.reference(),
            ));
        }
        let obligations_match =
            admission.unresolved_obligations() == expected_obligations.as_slice();
        let identities_match = admission.command_identities() == expected_identities.as_slice();
        if !obligations_match || !identities_match {
            return Err(RecoveryFailureV1::new(
                ErasureErrorV1::ProvenanceMissing,
                admission.reference(),
            ));
        }
        Ok(unresolved
            .into_iter()
            .map(|obligation| {
                ErasureDestructionCommandV1::from_obligation(obligation, admission.reference())
            })
            .collect())
    }

    fn validate_attempt_effect(
        &self,
        port: &dyn ErasurePersistencePortV1,
        admission: &ErasureRetryAdmissionV1,
    ) -> Result<(), RecoveryFailureV1> {
        let expected_commands = self.validate_attempt_admission(admission)?;
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
        let fallback_subject = self.manifest_digest;
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
            let node = load_recovery_object(port, reference, ScopeNodeV1::decode, |value| {
                value.reference
            })?;
            let extension = load_recovery_object(
                port,
                node.extension,
                ErasureScopeExtensionV1::from_canonical_cbor,
                ErasureScopeExtensionV1::reference,
            )?;
            if node.request != self.request.reference()
                || Some(node.scope) != self.manifest.scope
                || node.ordinal != ordinal
                || node.predecessor != predecessor_node
            {
                return Err(RecoveryFailureV1::new(
                    ErasureErrorV1::ProvenanceMissing,
                    reference,
                ));
            }
            if extension.request() != self.request.reference()
                || extension.scope_commitment() != node.scope
                || Some(extension.lineage_rule()) != lineage_rule
                || extension.predecessor_extension() != predecessor_extension
                || !forks.insert(extension.fork())
            {
                return Err(RecoveryFailureV1::new(
                    ErasureErrorV1::ProvenanceMissing,
                    extension.reference(),
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
        let fallback_subject = self.manifest_digest;
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
            let resolution = load_recovery_object(
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

#[derive(Clone, Copy)]
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
    target_closure: Option<ErasureReferenceV1>,
    manifest: ErasureReferenceV1,
    verifier: &'a dyn ErasureFreezeAuthorizationVerifierV1,
}

fn validate_recovery_bindings(
    bindings: impl IntoIterator<Item = (bool, ErasureReferenceV1)>,
) -> Result<(), RecoveryFailureV1> {
    bindings
        .into_iter()
        .find_map(|(valid, subject)| (!valid).then_some(subject))
        .map_or(Ok(()), |subject| {
            Err(RecoveryFailureV1::new(
                ErasureErrorV1::ProvenanceMissing,
                subject,
            ))
        })
}

fn freeze_reconstruction_failure_subject(
    graph: &FixedGraphV1<'_>,
    scope: &ErasureScopeCommitmentV1,
    admission: &ErasureFreezeAdmissionEvidenceV1,
    freeze: &ErasureFreezeProvenanceV1,
    obligation_set: &ErasureObligationSetV1,
) -> ErasureReferenceV1 {
    if scope.target_closure() != target_closure_digest(graph.targets) {
        return scope.reference();
    }
    let obligation_references = graph
        .obligations
        .iter()
        .map(ErasureObligationV1::reference)
        .collect::<Vec<_>>();
    if obligation_set.obligations() != obligation_references.as_slice()
        || obligation_set.policy() != graph.erq.policy()
        || obligation_set.trust() != admission.trust()
    {
        return obligation_set.reference();
    }
    if !freeze_fields_match_graph(freeze, scope, admission, obligation_set) {
        return freeze.reference();
    }
    if let Some(obligation) = graph.obligations.iter().find(|obligation| {
        graph.targets.binary_search(&obligation.target()).is_err()
            || obligation.command_identity()
                != destruction_command_reference(graph.requested, obligation.target())
    }) {
        return obligation.reference();
    }
    admission.reference()
}

fn freeze_fields_match_graph(
    freeze: &ErasureFreezeProvenanceV1,
    scope: &ErasureScopeCommitmentV1,
    admission: &ErasureFreezeAdmissionEvidenceV1,
    obligation_set: &ErasureObligationSetV1,
) -> bool {
    freeze.scope_commitment() == scope.reference()
        && freeze.obligation_set() == obligation_set.reference()
        && freeze.freeze_position() == admission.freeze_position()
        && freeze.host_evidence() == admission.reference()
}

fn validate_fixed_bindings(graph: &FixedGraphV1<'_>) -> Result<(), RecoveryFailureV1> {
    validate_recovery_bindings([
        (
            graph.erq.reference() == graph.requested,
            graph.erq.reference(),
        ),
        (
            graph.state.request() == graph.requested,
            graph.state.state_digest(),
        ),
        (
            graph
                .correction
                .is_none_or(|value| graph.erq.provenance() == value.reference()),
            graph
                .correction
                .map_or(graph.manifest, ErasureCorrectionProvenanceV1::reference),
        ),
        (
            graph
                .rejection
                .is_none_or(|value| value.request() == graph.requested),
            graph
                .rejection
                .map_or(graph.manifest, ErasureAuthorizationRejectionV1::reference),
        ),
        (
            graph
                .failure
                .is_none_or(|value| value.request() == graph.requested),
            graph
                .failure
                .map_or(graph.manifest, ErasureFreezeFailureV1::reference),
        ),
        (
            graph
                .scope
                .is_none_or(|value| value.request() == graph.requested),
            graph
                .scope
                .map_or(graph.manifest, ErasureScopeCommitmentV1::reference),
        ),
        (
            graph
                .admission
                .is_none_or(|value| value.request() == graph.requested),
            graph
                .admission
                .map_or(graph.manifest, ErasureFreezeAdmissionEvidenceV1::reference),
        ),
        (
            graph
                .obligation_set
                .is_none_or(|value| value.request() == graph.requested),
            graph
                .obligation_set
                .map_or(graph.manifest, ErasureObligationSetV1::reference),
        ),
        (
            graph
                .freeze
                .is_none_or(|value| value.request() == graph.requested),
            graph
                .freeze
                .map_or(graph.manifest, ErasureFreezeProvenanceV1::reference),
        ),
    ])?;
    Ok(())
}

fn validate_freeze_authorization(graph: &FixedGraphV1<'_>) -> Result<(), RecoveryFailureV1> {
    match (graph.admission, graph.authorization) {
        (Some(admission), Some(authorization)) => graph
            .verifier
            .validate_freeze_authorization(admission, authorization)
            .map_err(|error| RecoveryFailureV1::new(error, authorization.reference()))
            .map(|()| ()),
        (None, None) => Ok(()),
        _ => {
            let subject = graph
                .admission
                .map_or(graph.manifest, ErasureFreezeAdmissionEvidenceV1::reference);
            Err(RecoveryFailureV1::new(
                ErasureErrorV1::ProvenanceMissing,
                subject,
            ))
        }
    }
}

fn reconstruct_frozen_graph(
    graph: &FixedGraphV1<'_>,
) -> Result<ErasureAtomicFreezeAdmissionV1, RecoveryFailureV1> {
    let (Some(scope), Some(admission), Some(authorization), Some(freeze), Some(set)) = (
        graph.scope,
        graph.admission,
        graph.authorization,
        graph.freeze,
        graph.obligation_set,
    ) else {
        return Err(RecoveryFailureV1::new(
            ErasureErrorV1::ProvenanceMissing,
            partial_fixed_graph_subject(graph),
        ));
    };
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
    })
    .map_err(|error| {
        RecoveryFailureV1::new(
            error,
            freeze_reconstruction_failure_subject(graph, scope, admission, freeze, set),
        )
    })
}

fn validate_frozen_bindings(
    graph: &FixedGraphV1<'_>,
    reconstructed: &ErasureAtomicFreezeAdmissionV1,
) -> Result<(), RecoveryFailureV1> {
    let (Some(scope), Some(admission), Some(_authorization), Some(freeze), Some(set)) = (
        graph.scope,
        graph.admission,
        graph.authorization,
        graph.freeze,
        graph.obligation_set,
    ) else {
        return Err(RecoveryFailureV1::new(
            ErasureErrorV1::ProvenanceMissing,
            partial_fixed_graph_subject(graph),
        ));
    };
    validate_recovery_bindings([
        (
            reconstructed.targets() == graph.targets,
            graph.target_closure.unwrap_or(graph.manifest),
        ),
        (
            scope.target_closure() == target_closure_digest(graph.targets),
            scope.reference(),
        ),
        (
            freeze.scope_commitment() == scope.reference(),
            freeze.reference(),
        ),
        (
            freeze.obligation_set() == set.reference(),
            freeze.reference(),
        ),
        (
            freeze.host_evidence() == admission.reference(),
            freeze.reference(),
        ),
        (
            freeze.freeze_position() == admission.freeze_position(),
            freeze.reference(),
        ),
        (
            graph.state.freeze_position() == Some(admission.freeze_position()),
            graph.state.state_digest(),
        ),
        (set.policy() == graph.erq.policy(), set.reference()),
        (graph.authorize_provenance.is_some(), graph.manifest),
        (
            graph.rejection.is_none(),
            graph
                .rejection
                .map_or(graph.manifest, ErasureAuthorizationRejectionV1::reference),
        ),
        (
            graph.failure.is_none(),
            graph
                .failure
                .map_or(graph.manifest, ErasureFreezeFailureV1::reference),
        ),
        (
            matches!(
                graph.state.lifecycle(),
                ErasureLifecycleV1::AccessFrozen
                    | ErasureLifecycleV1::DestructionDispatched
                    | ErasureLifecycleV1::AwaitingAcknowledgements
                    | ErasureLifecycleV1::PartialFailure
                    | ErasureLifecycleV1::Complete
            ),
            graph.state.state_digest(),
        ),
        (
            graph.state.lifecycle() != ErasureLifecycleV1::AccessFrozen
                || graph.state.provenance() == freeze.reference(),
            graph.state.state_digest(),
        ),
    ])
}

fn partial_fixed_graph_subject(graph: &FixedGraphV1<'_>) -> ErasureReferenceV1 {
    graph
        .scope
        .map(ErasureScopeCommitmentV1::reference)
        .or_else(|| {
            graph
                .admission
                .map(ErasureFreezeAdmissionEvidenceV1::reference)
        })
        .or_else(|| graph.freeze.map(ErasureFreezeProvenanceV1::reference))
        .or_else(|| graph.obligation_set.map(ErasureObligationSetV1::reference))
        .or(graph.target_closure)
        .unwrap_or(graph.manifest)
}

fn validate_fixed_graph(graph: &FixedGraphV1<'_>) -> Result<(), RecoveryFailureV1> {
    validate_fixed_bindings(graph)?;
    validate_freeze_authorization(graph)?;
    if graph.scope.is_some()
        && graph.admission.is_some()
        && graph.authorization.is_some()
        && graph.freeze.is_some()
        && graph.obligation_set.is_some()
    {
        let reconstructed = reconstruct_frozen_graph(graph)?;
        validate_frozen_bindings(graph, &reconstructed)?;
    } else if graph.scope.is_some()
        || graph.admission.is_some()
        || graph.freeze.is_some()
        || graph.obligation_set.is_some()
        || !graph.targets.is_empty()
        || !graph.obligations.is_empty()
    {
        return Err(RecoveryFailureV1::new(
            ErasureErrorV1::ProvenanceMissing,
            partial_fixed_graph_subject(graph),
        ));
    }
    validate_unfrozen_graph(graph)?;
    Ok(())
}

fn validate_unfrozen_graph(graph: &FixedGraphV1<'_>) -> Result<(), RecoveryFailureV1> {
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
        _ => Err(RecoveryFailureV1::new(
            ErasureErrorV1::ProvenanceMissing,
            graph
                .rejection
                .map(ErasureAuthorizationRejectionV1::reference)
                .or_else(|| graph.failure.map(ErasureFreezeFailureV1::reference))
                .unwrap_or_else(|| graph.state.state_digest()),
        )),
    }
}

fn validate_correction(
    port: &dyn ErasurePersistencePortV1,
    request: &ErasureRequestV1,
    correction: Option<&ErasureCorrectionProvenanceV1>,
) -> Result<(), RecoveryFailureV1> {
    let Some(correction) = correction else {
        return Ok(());
    };
    if request.provenance() != correction.reference()
        || request.reference() == correction.rejected_request()
    {
        return Err(RecoveryFailureV1::new(
            ErasureErrorV1::ProvenanceMissing,
            correction.reference(),
        ));
    }
    let rejected_terminal_state = correction.rejected_terminal_state();
    let rejected = port
        .resolve_state(rejected_terminal_state)
        .map_err(|error| RecoveryFailureV1::new(error, rejected_terminal_state))?
        .ok_or_else(|| {
            RecoveryFailureV1::new(ErasureErrorV1::ProvenanceMissing, rejected_terminal_state)
        })?;
    if rejected.request() == correction.rejected_request()
        && rejected.lifecycle() == ErasureLifecycleV1::Rejected
    {
        Ok(())
    } else {
        Err(RecoveryFailureV1::new(
            ErasureErrorV1::ProvenanceMissing,
            rejected_terminal_state,
        ))
    }
}

fn validate_state_provenance(
    resolver: &dyn ErasureStateResolverV1,
    state: &ErasureStateV1,
    manifest: &ManifestV1,
    manifest_digest: ErasureReferenceV1,
) -> Result<(), RecoveryFailureV1> {
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
            return validate_state_provenance_root(
                authorization,
                dispatch,
                manifest,
                manifest_digest,
            );
        };
        current = resolve_state_provenance_predecessor(resolver, previous)?;
    }
    Err(RecoveryFailureV1::new(
        ErasureErrorV1::ProvenanceMissing,
        manifest_digest,
    ))
}

fn validate_state_provenance_root(
    authorization: Option<ErasureReferenceV1>,
    dispatch: Option<ErasureReferenceV1>,
    manifest: &ManifestV1,
    manifest_digest: ErasureReferenceV1,
) -> Result<(), RecoveryFailureV1> {
    if authorization == manifest.authorize_provenance && dispatch == manifest.dispatch_provenance {
        Ok(())
    } else {
        Err(RecoveryFailureV1::new(
            ErasureErrorV1::ProvenanceMissing,
            manifest_digest,
        ))
    }
}

fn resolve_state_provenance_predecessor(
    resolver: &dyn ErasureStateResolverV1,
    previous: ErasureReferenceV1,
) -> Result<ErasureStateV1, RecoveryFailureV1> {
    resolver
        .resolve_state(previous)
        .map_err(|error| RecoveryFailureV1::new(error, previous))
        .and_then(|state| {
            state.map_or_else(
                || {
                    Err(RecoveryFailureV1::new(
                        ErasureErrorV1::ProvenanceMissing,
                        previous,
                    ))
                },
                Ok,
            )
        })
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::{
        ErasureAcknowledgementProvenanceInputV1, ErasureAdministrativeResolutionInputV1,
        ErasureApplicabilityDecisionV1, ErasureAttemptQuotaReservationV1, ErasureCasOutcomeV1,
        ErasureFreezeAdmissionEvidenceInputV1, ErasureFreezeApplicabilityRowV1,
        ErasureFreezeAuthorizationEvidenceInputV1, ErasureFreezeProvenanceInputV1,
        ErasureInventoryCategoryV1, ErasureKeyRoleV1, ErasureObligationInputV1,
        ErasureObligationSetInputV1, ErasureRequestInputV1, ErasureRetryAdmissionInputV1,
        ErasureScopeExtensionInputV1, ErasureScopeV1,
    };

    const fn reference(value: u8) -> ErasureReferenceV1 {
        ErasureReferenceV1::from_digest([value; 32])
    }

    const fn target() -> ErasureRequiredTargetV1 {
        ErasureRequiredTargetV1 {
            artifact_class: super::super::ErasureArtifactClassV1::TimelineReplay,
            artifact_digest: reference(10),
            key_role: ErasureKeyRoleV1::DataEncryption,
            key_digest: reference(11),
            replica_set: reference(12),
            replica_id: reference(13),
        }
    }

    fn request() -> Result<ErasureRequestV1, ErasureErrorV1> {
        ErasureRequestV1::new(ErasureRequestInputV1 {
            request: reference(1),
            subject: reference(2),
            scope: ErasureScopeV1::PrivateSubjectData,
            selectors: vec![reference(3)],
            requester: reference(4),
            authorization: reference(5),
            policy: reference(6),
            request_position: 7,
            horizon_position: 8,
            provenance: reference(9),
        })
    }

    fn admission_fixture(
        request: ErasureReferenceV1,
        attempt_ordinal: u64,
        source_receipt: Option<ErasureReferenceV1>,
        unresolved_obligations: Vec<ErasureReferenceV1>,
        command_identities: Vec<ErasureReferenceV1>,
        policy: ErasureReferenceV1,
        trust: ErasureReferenceV1,
    ) -> Result<ErasureRetryAdmissionV1, ErasureErrorV1> {
        ErasureRetryAdmissionV1::new(ErasureRetryAdmissionInputV1 {
            request,
            attempt_ordinal,
            source_receipt,
            unresolved_obligations,
            command_identities,
            policy,
            trust,
            admitted_position: 10,
            deadline_position: 20,
            authorization_provenance: reference(30),
        })
    }

    fn obligation(request: ErasureReferenceV1) -> Result<ErasureObligationV1, ErasureErrorV1> {
        ErasureObligationV1::new(ErasureObligationInputV1 {
            category: ErasureInventoryCategoryV1::Artifact,
            target: target(),
            owner: reference(13),
            command_identity: destruction_command_reference(request, target()),
        })
    }

    fn acknowledgement_fixture(
        request: ErasureReferenceV1,
        attempt: ErasureReferenceV1,
        obligation: ErasureReferenceV1,
        command: ErasureReferenceV1,
        scope: ErasureReferenceV1,
    ) -> Result<ErasureAcknowledgementProvenanceV1, ErasureErrorV1> {
        ErasureAcknowledgementProvenanceV1::new(ErasureAcknowledgementProvenanceInputV1 {
            request,
            command,
            attempt,
            obligation,
            owner: reference(13),
            scope,
            outcome: ErasureAcknowledgementOutcomeV1::Acknowledged,
            evidence: reference(41),
            policy: reference(6),
            trust: reference(7),
        })
    }

    fn scope(request: ErasureReferenceV1) -> Result<ErasureScopeCommitmentV1, ErasureErrorV1> {
        ErasureScopeCommitmentV1::new(ErasureScopeCommitmentInputV1 {
            request,
            scope_members: vec![reference(42)],
            target_closure: target_closure_digest(&[target()]),
            lineage_rule: Some(reference(43)),
        })
    }

    struct AcceptFreezeVerifier;

    impl ErasureFreezeAuthorizationVerifierV1 for AcceptFreezeVerifier {
        fn validate_freeze_authorization(
            &self,
            _admission: &ErasureFreezeAdmissionEvidenceV1,
            _authorization: &ErasureFreezeAuthorizationEvidenceV1,
        ) -> Result<(), ErasureErrorV1> {
            Ok(())
        }
    }

    struct FrozenFixture {
        target: ErasureRequiredTargetV1,
        scope: ErasureScopeCommitmentV1,
        admission: ErasureFreezeAdmissionEvidenceV1,
        authorization: ErasureFreezeAuthorizationEvidenceV1,
        freeze: ErasureFreezeProvenanceV1,
        obligation_set: ErasureObligationSetV1,
        atomic: ErasureAtomicFreezeAdmissionV1,
    }

    fn frozen_fixture(request: ErasureReferenceV1) -> Result<FrozenFixture, ErasureErrorV1> {
        let target = target();
        let target_closure = target_closure_digest(&[target]);
        let scope = ErasureScopeCommitmentV1::new(ErasureScopeCommitmentInputV1 {
            request,
            scope_members: vec![reference(42)],
            target_closure,
            lineage_rule: None,
        })?;
        let obligation_set = ErasureObligationSetV1::new(ErasureObligationSetInputV1 {
            request,
            obligations: Vec::new(),
            policy: reference(6),
            trust: reference(7),
        })?;
        let matrix = ErasureInventoryCategoryV1::CANONICAL
            .into_iter()
            .map(|category| {
                ErasureFreezeApplicabilityRowV1::new(
                    category,
                    0,
                    ErasureApplicabilityDecisionV1::Inapplicable,
                    None,
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        let admission_input = ErasureFreezeAdmissionEvidenceInputV1 {
            request,
            scope_commitment: scope.reference(),
            obligation_set: obligation_set.reference(),
            applicability_matrix: matrix,
            freeze_position: 10,
            policy: reference(6),
            trust: reference(7),
            authorization_provenance: reference(0),
        };
        let provisional = ErasureFreezeAdmissionEvidenceV1::new(admission_input.clone())?;
        let authorization =
            ErasureFreezeAuthorizationEvidenceV1::new(ErasureFreezeAuthorizationEvidenceInputV1 {
                admission_body_digest: provisional.authorization_body_digest()?,
                policy: reference(6),
                trust: reference(7),
                evidence: vec![1],
            })?;
        let admission =
            ErasureFreezeAdmissionEvidenceV1::new(ErasureFreezeAdmissionEvidenceInputV1 {
                authorization_provenance: authorization.reference(),
                ..admission_input
            })?;
        let freeze = ErasureFreezeProvenanceV1::new(ErasureFreezeProvenanceInputV1 {
            request,
            scope_commitment: scope.reference(),
            obligation_set: obligation_set.reference(),
            freeze_position: 10,
            host_evidence: admission.reference(),
        })?;
        let atomic = ErasureAtomicFreezeAdmissionV1::new(ErasureAtomicFreezeAdmissionInputV1 {
            targets: vec![target],
            scope: ErasureScopeCommitmentInputV1 {
                request,
                scope_members: vec![reference(42)],
                target_closure,
                lineage_rule: None,
            },
            obligations: Vec::new(),
            obligation_set: obligation_set.clone(),
            freeze_position: 10,
            freeze_admission_evidence: admission.clone(),
            freeze_authorization_evidence: authorization.clone(),
        })?;
        Ok(FrozenFixture {
            target,
            scope,
            admission,
            authorization,
            freeze,
            obligation_set,
            atomic,
        })
    }

    #[derive(Clone, Copy)]
    struct FixedGraphInput<'a> {
        request: &'a ErasureRequestV1,
        state: &'a ErasureStateV1,
        targets: &'a [ErasureRequiredTargetV1],
        scope: Option<&'a ErasureScopeCommitmentV1>,
        admission: Option<&'a ErasureFreezeAdmissionEvidenceV1>,
        authorization: Option<&'a ErasureFreezeAuthorizationEvidenceV1>,
        freeze: Option<&'a ErasureFreezeProvenanceV1>,
        obligation_set: Option<&'a ErasureObligationSetV1>,
        obligations: &'a [ErasureObligationV1],
        manifest: ErasureReferenceV1,
        verifier: &'a dyn ErasureFreezeAuthorizationVerifierV1,
    }

    fn fixed_graph(input: FixedGraphInput<'_>) -> FixedGraphV1<'_> {
        FixedGraphV1 {
            requested: input.request.reference(),
            erq: input.request,
            state: input.state,
            targets: input.targets,
            correction: None,
            rejection: None,
            scope: input.scope,
            admission: input.admission,
            authorization: input.authorization,
            freeze: input.freeze,
            failure: None,
            obligation_set: input.obligation_set,
            obligations: input.obligations,
            authorize_provenance: None,
            target_closure: None,
            manifest: input.manifest,
            verifier: input.verifier,
        }
    }

    fn record_fixture(request: &ErasureRequestV1) -> Result<RecoveredErasureV1, ErasureErrorV1> {
        Ok(RecoveredErasureV1::initial(
            request.clone(),
            ErasureStateV1::submitted(request.reference(), reference(44), request.provenance())?,
        ))
    }

    fn manifest_value(active: Value) -> Value {
        let mut fields = vec![
            text(ERCRP1),
            uint(VERSION),
            digest(reference(1)),
            digest(reference(2)),
        ];
        fields.extend((0..10).map(|_| Value::Null));
        fields.push(active);
        fields.push(Value::Null);
        fields.push(uint(0));
        fields.extend((0..4).map(|_| Value::Null));
        Value::Array(fields)
    }

    #[test]
    fn persistence_decoders_reject_wrong_shapes_and_active_fields() -> Result<(), ErasureErrorV1> {
        let wrong_shape = encode_limited(&Value::Null, ERASURE_PORTABLE_RECORD_MAX_BYTES)?;
        assert_eq!(
            TargetClosureV1::decode(&wrong_shape),
            Err(ErasureErrorV1::InvalidEncoding)
        );
        assert_eq!(
            InventoryV1::decode(&wrong_shape),
            Err(ErasureErrorV1::InvalidEncoding)
        );
        assert_eq!(
            AttemptPageV1::decode(&wrong_shape),
            Err(ErasureErrorV1::InvalidEncoding)
        );
        assert_eq!(
            ScopeNodeV1::decode(&wrong_shape),
            Err(ErasureErrorV1::InvalidEncoding)
        );

        let wrong_manifest = encode_limited(&Value::Null, ERASURE_COORDINATOR_RECORD_MAX_BYTES)?;
        assert_eq!(
            ManifestV1::decode(&wrong_manifest),
            Err(ErasureErrorV1::InvalidEncoding)
        );
        let invalid_ordinal = encode_limited(
            &manifest_value(Value::Array(vec![
                Value::Null,
                digest(reference(3)),
                Value::Array(Vec::new()),
            ])),
            ERASURE_COORDINATOR_RECORD_MAX_BYTES,
        )?;
        assert_eq!(
            ManifestV1::decode(&invalid_ordinal),
            Err(ErasureErrorV1::InvalidEncoding)
        );
        let invalid_admission = encode_limited(
            &manifest_value(Value::Array(vec![
                uint(0),
                Value::Null,
                Value::Array(Vec::new()),
            ])),
            ERASURE_COORDINATOR_RECORD_MAX_BYTES,
        )?;
        assert_eq!(
            ManifestV1::decode(&invalid_admission),
            Err(ErasureErrorV1::InvalidEncoding)
        );
        Ok(())
    }

    #[test]
    fn recovered_attempt_mutations_reject_conflicts() -> Result<(), ErasureErrorV1> {
        let request = request()?;
        let admission = admission_fixture(
            request.reference(),
            0,
            None,
            Vec::new(),
            Vec::new(),
            reference(6),
            reference(7),
        )?;

        let mut wrong_request = record_fixture(&request)?;
        let foreign = admission_fixture(
            reference(2),
            0,
            None,
            Vec::new(),
            Vec::new(),
            reference(6),
            reference(7),
        )?;
        assert_eq!(
            wrong_request.begin_attempt(foreign).map(|_| ()),
            Err(ErasureErrorV1::PolicyConflict)
        );

        let mut wrong_ordinal = record_fixture(&request)?;
        let retry = admission_fixture(
            request.reference(),
            1,
            Some(reference(45)),
            Vec::new(),
            Vec::new(),
            reference(6),
            reference(7),
        )?;
        assert_eq!(
            wrong_ordinal.begin_attempt(retry).map(|_| ()),
            Err(ErasureErrorV1::PolicyConflict)
        );

        let mut active = record_fixture(&request)?;
        active.begin_attempt(admission.clone())?;
        assert_eq!(
            active.begin_attempt(admission).map(|_| ()),
            Err(ErasureErrorV1::PolicyConflict)
        );
        Ok(())
    }

    #[test]
    fn recovered_acknowledgements_and_bounds_reject_conflicts() -> Result<(), ErasureErrorV1> {
        let request = request()?;
        let mut acknowledgements = record_fixture(&request)?;
        let admission = admission_fixture(
            request.reference(),
            0,
            None,
            Vec::new(),
            Vec::new(),
            reference(6),
            reference(7),
        )?;
        acknowledgements.begin_attempt(admission.clone())?;
        let valid = acknowledgement_fixture(
            request.reference(),
            admission.reference(),
            reference(46),
            reference(47),
            reference(40),
        )?;
        let wrong_request = acknowledgement_fixture(
            reference(2),
            admission.reference(),
            reference(46),
            reference(47),
            reference(40),
        )?;
        assert_eq!(
            acknowledgements
                .retain_acknowledgement(&wrong_request)
                .map(|_| ()),
            Err(ErasureErrorV1::ProvenanceMissing)
        );
        acknowledgements.retain_acknowledgement(&valid)?;
        assert_eq!(
            acknowledgements.retain_acknowledgement(&valid).map(|_| ()),
            Err(ErasureErrorV1::PolicyConflict)
        );

        let extension = ErasureScopeExtensionV1::new(ErasureScopeExtensionInputV1 {
            request: request.reference(),
            scope_commitment: reference(48),
            fork: reference(49),
            lineage_rule: reference(50),
            predecessor_extension: None,
            admission_provenance: reference(51),
        })?;
        let mut scope_bound = record_fixture(&request)?;
        scope_bound.scope_head = Some(RecoveredScopeHeadV1 {
            node: reference(52),
            extension: reference(53),
            ordinal: ERASURE_MAX_SCOPE_EXTENSIONS as u64 - 1,
        });
        assert_eq!(
            scope_bound.append_scope_extension(extension).map(|_| ()),
            Err(ErasureErrorV1::PolicyConflict)
        );

        let resolution =
            ErasureAdministrativeResolutionV1::new(ErasureAdministrativeResolutionInputV1 {
                request: request.reference(),
                affected_digests: vec![reference(54)],
                action: super::super::ErasureAdministrativeResolutionActionV1::RecoverExactEvidence,
                scope_commitment: reference(55),
                policy: reference(6),
                trust: reference(7),
                principal: reference(56),
                authorization_provenance: reference(57),
                reason: reference(58),
                issue_position: 59,
                predecessor_resolution: None,
            })?;
        let mut resolution_bound = record_fixture(&request)?;
        resolution_bound.administrative_resolution_count =
            ERASURE_MAX_ADMINISTRATIVE_RESOLUTIONS as u64;
        assert_eq!(
            resolution_bound
                .append_administrative_resolution(&resolution)
                .map(|_| ()),
            Err(ErasureErrorV1::PolicyConflict)
        );
        Ok(())
    }

    #[test]
    fn replay_bindings_reject_admissions_inventories_and_dispatch_heads(
    ) -> Result<(), ErasureErrorV1> {
        let request = request()?;
        let mut record = record_fixture(&request)?;
        let page = AttemptPageV1 {
            request: request.reference(),
            ordinal: 0,
            retry_admission: reference(60),
            admitted_inventory: reference(61),
            effective_inventory: reference(62),
            outcome: reference(63),
            receipt: reference(64),
            receipt_provenance: reference(65),
            terminal_state: reference(66),
            predecessor: None,
            reference: reference(67),
        };
        let admitted = InventoryV1::new(request.reference(), 0, INVENTORY_ADMITTED.0, Vec::new())?;
        let effective =
            InventoryV1::new(request.reference(), 0, INVENTORY_EFFECTIVE.0, Vec::new())?;
        let admission = admission_fixture(
            request.reference(),
            0,
            None,
            Vec::new(),
            Vec::new(),
            reference(6),
            reference(7),
        )?;
        let foreign = admission_fixture(
            reference(2),
            0,
            None,
            Vec::new(),
            Vec::new(),
            reference(6),
            reference(7),
        )?;
        assert_eq!(
            record
                .validate_replay_page_bindings(&page, &foreign, &admitted, &effective, None)
                .err()
                .map(RecoveryFailureV1::error),
            Some(ErasureErrorV1::ProvenanceMissing)
        );

        assert_eq!(
            record
                .validate_replay_page_bindings(&page, &admission, &admitted, &admitted, None)
                .err()
                .map(RecoveryFailureV1::error),
            Some(ErasureErrorV1::ProvenanceMissing)
        );
        record.dispatch_provenance = Some(admission.reference());
        record
            .validate_replay_page_bindings(&page, &admission, &admitted, &effective, None)
            .map_err(RecoveryFailureV1::error)?;
        Ok(())
    }

    #[test]
    fn attempt_admission_matching_rejects_incomplete_bindings() -> Result<(), ErasureErrorV1> {
        let request = request()?;
        let obligation = obligation(request.reference())?;
        let obligation_set = ErasureObligationSetV1::new(ErasureObligationSetInputV1 {
            request: request.reference(),
            obligations: vec![obligation.reference()],
            policy: reference(6),
            trust: reference(7),
        })?;
        let mut record = record_fixture(&request)?;
        let empty_admission = admission_fixture(
            request.reference(),
            0,
            None,
            Vec::new(),
            Vec::new(),
            reference(6),
            reference(7),
        )?;
        assert_eq!(
            record
                .validate_attempt_admission(&empty_admission)
                .err()
                .map(RecoveryFailureV1::error),
            Some(ErasureErrorV1::ProvenanceMissing)
        );

        record.obligation_set = Some(obligation_set);
        record.obligations = vec![obligation];
        let wrong_policy = admission_fixture(
            request.reference(),
            0,
            None,
            vec![obligation.reference()],
            vec![obligation.command_identity()],
            reference(8),
            reference(7),
        )?;
        assert_eq!(
            record
                .validate_attempt_admission(&wrong_policy)
                .err()
                .map(RecoveryFailureV1::error),
            Some(ErasureErrorV1::ProvenanceMissing)
        );
        let wrong_obligations = admission_fixture(
            request.reference(),
            0,
            None,
            Vec::new(),
            Vec::new(),
            reference(6),
            reference(7),
        )?;
        assert_eq!(
            record
                .validate_attempt_admission(&wrong_obligations)
                .err()
                .map(RecoveryFailureV1::error),
            Some(ErasureErrorV1::ProvenanceMissing)
        );
        let matching = admission_fixture(
            request.reference(),
            0,
            None,
            vec![obligation.reference()],
            vec![obligation.command_identity()],
            reference(6),
            reference(7),
        )?;
        assert_eq!(
            record
                .validate_attempt_admission(&matching)
                .map_err(RecoveryFailureV1::error)?
                .len(),
            1
        );

        Ok(())
    }

    #[test]
    fn acknowledgement_matching_rejects_incomplete_bindings() -> Result<(), ErasureErrorV1> {
        let request = request()?;
        let obligation = obligation(request.reference())?;
        let obligation_set = ErasureObligationSetV1::new(ErasureObligationSetInputV1 {
            request: request.reference(),
            obligations: vec![obligation.reference()],
            policy: reference(6),
            trust: reference(7),
        })?;
        let mut record = record_fixture(&request)?;
        record.obligation_set = Some(obligation_set);
        record.obligations = vec![obligation];
        let matching = admission_fixture(
            request.reference(),
            0,
            None,
            vec![obligation.reference()],
            vec![obligation.command_identity()],
            reference(6),
            reference(7),
        )?;
        let acknowledgement = acknowledgement_fixture(
            request.reference(),
            matching.reference(),
            obligation.reference(),
            obligation.command_identity(),
            reference(40),
        )?;
        assert!(!record.acknowledgement_matches_admission(&acknowledgement, &matching));
        record.scope = Some(scope(request.reference())?);
        let scope_reference = record
            .scope
            .as_ref()
            .map(ErasureScopeCommitmentV1::reference)
            .ok_or(ErasureErrorV1::ProvenanceMissing)?;
        let matching_acknowledgement = acknowledgement_fixture(
            request.reference(),
            matching.reference(),
            obligation.reference(),
            obligation.command_identity(),
            scope_reference,
        )?;
        assert!(record.acknowledgement_matches_admission(&matching_acknowledgement, &matching));
        let no_selection = admission_fixture(
            request.reference(),
            0,
            None,
            Vec::new(),
            Vec::new(),
            reference(6),
            reference(7),
        )?;
        assert!(!record.acknowledgement_matches_admission(&matching_acknowledgement, &no_selection));
        record.obligations.clear();
        assert!(!record.acknowledgement_matches_admission(&matching_acknowledgement, &matching));
        record.obligation_set = None;
        assert_eq!(
            record
                .validate_attempt_admission(&matching)
                .err()
                .map(RecoveryFailureV1::error),
            Some(ErasureErrorV1::ProvenanceMissing)
        );
        Ok(())
    }

    struct RepeatingStateResolver(ErasureStateV1);

    impl ErasureStateResolverV1 for RepeatingStateResolver {
        fn resolve_state(
            &self,
            _digest: ErasureReferenceV1,
        ) -> Result<Option<ErasureStateV1>, ErasureErrorV1> {
            Ok(Some(self.0.clone()))
        }
    }

    struct RecoveryVerifier;

    impl ErasureRecoveryAuthorizationVerifierV1 for RecoveryVerifier {
        fn validate_scope_extension(
            &self,
            _extension: &ErasureScopeExtensionV1,
        ) -> Result<(), ErasureErrorV1> {
            Ok(())
        }

        fn validate_administrative_resolution(
            &self,
            _resolution: &ErasureAdministrativeResolutionV1,
        ) -> Result<(), ErasureErrorV1> {
            Ok(())
        }
    }

    struct TestPersistencePort {
        effect_manifest: Option<ErasureReferenceV1>,
        effect: ErasureCasEffectV1,
        resolution_count: u64,
    }

    impl ErasureStateResolverV1 for TestPersistencePort {
        fn resolve_state(
            &self,
            _digest: ErasureReferenceV1,
        ) -> Result<Option<ErasureStateV1>, ErasureErrorV1> {
            Ok(None)
        }
    }

    impl ErasurePersistencePortV1 for TestPersistencePort {
        fn read_manifest(
            &self,
            _request: ErasureReferenceV1,
        ) -> Result<Option<StoredErasureManifestV1>, ErasureErrorV1> {
            Ok(None)
        }

        fn read_object(&self, _reference: ErasureReferenceV1) -> Result<Vec<u8>, ErasureErrorV1> {
            Err(ErasureErrorV1::ProvenanceMissing)
        }

        fn read_effect(
            &self,
            _manifest: ErasureReferenceV1,
        ) -> Result<ErasureCasEffectV1, ErasureErrorV1> {
            Ok(self.effect.clone())
        }

        fn effect_manifest(
            &self,
            _subject: ErasureReferenceV1,
        ) -> Result<Option<ErasureReferenceV1>, ErasureErrorV1> {
            Ok(self.effect_manifest)
        }

        fn attempt_page_ref(
            &self,
            _request: ErasureReferenceV1,
            _ordinal: u64,
        ) -> Result<Option<ErasureReferenceV1>, ErasureErrorV1> {
            Ok(None)
        }

        fn attempt_index_count(&self, _request: ErasureReferenceV1) -> Result<u64, ErasureErrorV1> {
            Ok(0)
        }

        fn scope_node_ref(
            &self,
            _request: ErasureReferenceV1,
            _ordinal: u64,
        ) -> Result<Option<ErasureReferenceV1>, ErasureErrorV1> {
            Ok(None)
        }

        fn scope_index_count(&self, _request: ErasureReferenceV1) -> Result<u64, ErasureErrorV1> {
            Ok(0)
        }

        fn administrative_resolution_ref(
            &self,
            _request: ErasureReferenceV1,
            _ordinal: u64,
        ) -> Result<Option<ErasureReferenceV1>, ErasureErrorV1> {
            Ok(None)
        }

        fn administrative_resolution_index_count(
            &self,
            _request: ErasureReferenceV1,
        ) -> Result<u64, ErasureErrorV1> {
            Ok(self.resolution_count)
        }

        fn recovery_error_refs(
            &self,
            _request: ErasureReferenceV1,
        ) -> Result<Vec<ErasureReferenceV1>, ErasureErrorV1> {
            Ok(Vec::new())
        }

        fn append_recovery_error(
            &mut self,
            _object: crate::PreparedErasureRecoveryErrorV1,
        ) -> Result<(), ErasureErrorV1> {
            Ok(())
        }

        fn compare_and_swap(
            &mut self,
            _mutation: PreparedErasureCasV1,
        ) -> Result<ErasureCasOutcomeV1, ErasureErrorV1> {
            Err(ErasureErrorV1::PolicyConflict)
        }
    }

    #[test]
    fn state_provenance_rejects_a_bounded_cycle() -> Result<(), ErasureErrorV1> {
        let request = request()?;
        let state = ErasureStateV1 {
            request: request.reference(),
            lifecycle: ErasureLifecycleV1::Authorized,
            freeze_position: None,
            coordinator: reference(44),
            pending_owners: Vec::new(),
            failed_owners: Vec::new(),
            replay_claim: super::super::ErasureReplayClaimV1::Exact,
            previous_state: Some(reference(68)),
            provenance: reference(69),
            state_digest: reference(70),
        };
        let recovered = record_fixture(&request)?;
        let failure = validate_state_provenance(
            &RepeatingStateResolver(state.clone()),
            &state,
            &recovered.manifest,
            reference(71),
        )
        .err()
        .ok_or(ErasureErrorV1::PolicyConflict)?;
        assert_eq!(failure.error(), ErasureErrorV1::ProvenanceMissing);
        assert_eq!(failure.subject(), reference(71));
        Ok(())
    }

    #[test]
    fn attempt_effect_and_resolution_recovery_reject_incomplete_adapters(
    ) -> Result<(), ErasureErrorV1> {
        let request = request()?;
        let obligation = obligation(request.reference())?;
        let obligation_set = ErasureObligationSetV1::new(ErasureObligationSetInputV1 {
            request: request.reference(),
            obligations: vec![obligation.reference()],
            policy: reference(6),
            trust: reference(7),
        })?;
        let mut record = record_fixture(&request)?;
        record.obligation_set = Some(obligation_set);
        record.obligations = vec![obligation];
        let admission = admission_fixture(
            request.reference(),
            0,
            None,
            vec![obligation.reference()],
            vec![obligation.command_identity()],
            reference(6),
            reference(7),
        )?;
        let commands = record
            .validate_attempt_admission(&admission)
            .map_err(RecoveryFailureV1::error)?;
        let wrong_reservation = ErasureCasEffectV1::AttemptAdmission {
            reservation: ErasureAttemptQuotaReservationV1::new(reference(79), reference(80)),
            commands,
        };
        let port = TestPersistencePort {
            effect_manifest: Some(reference(81)),
            effect: wrong_reservation,
            resolution_count: 0,
        };
        assert_eq!(
            record
                .validate_attempt_effect(&port, &admission)
                .err()
                .map(RecoveryFailureV1::error),
            Some(ErasureErrorV1::ProvenanceMissing)
        );

        let port = TestPersistencePort {
            effect_manifest: Some(reference(81)),
            effect: ErasureCasEffectV1::None,
            resolution_count: 0,
        };
        assert_eq!(
            record
                .validate_attempt_effect(&port, &admission)
                .err()
                .map(RecoveryFailureV1::error),
            Some(ErasureErrorV1::ProvenanceMissing)
        );

        let mut missing_resolution_set = record_fixture(&request)?;
        missing_resolution_set.scope = Some(scope(request.reference())?);
        missing_resolution_set.administrative_resolution_head = Some(reference(82));
        let port = TestPersistencePort {
            effect_manifest: None,
            effect: ErasureCasEffectV1::None,
            resolution_count: 1,
        };
        assert_eq!(
            missing_resolution_set
                .recover_administrative_resolutions(&port, &RecoveryVerifier)
                .err()
                .map(RecoveryFailureV1::error),
            Some(ErasureErrorV1::ProvenanceMissing)
        );
        Ok(())
    }

    #[test]
    fn fixed_graph_recovery_checks_missing_and_mismatched_evidence() -> Result<(), ErasureErrorV1> {
        let request = request()?;
        let submitted =
            ErasureStateV1::submitted(request.reference(), reference(44), request.provenance())?;
        let verifier = AcceptFreezeVerifier;
        let fixture = frozen_fixture(request.reference())?;
        let empty_targets = Vec::new();
        let partial = fixed_graph(FixedGraphInput {
            request: &request,
            state: &submitted,
            targets: &empty_targets,
            scope: None,
            admission: None,
            authorization: None,
            freeze: None,
            obligation_set: None,
            obligations: &[],
            manifest: reference(72),
            verifier: &verifier,
        });
        assert_eq!(
            reconstruct_frozen_graph(&partial)
                .err()
                .map(RecoveryFailureV1::error),
            Some(ErasureErrorV1::ProvenanceMissing)
        );
        assert_eq!(
            validate_frozen_bindings(&partial, &fixture.atomic)
                .err()
                .map(RecoveryFailureV1::error),
            Some(ErasureErrorV1::ProvenanceMissing)
        );

        let targets = vec![fixture.target];
        let frozen_state = ErasureStateV1 {
            request: request.reference(),
            lifecycle: ErasureLifecycleV1::AccessFrozen,
            freeze_position: Some(10),
            coordinator: reference(44),
            pending_owners: Vec::new(),
            failed_owners: Vec::new(),
            replay_claim: super::super::ErasureReplayClaimV1::Exact,
            previous_state: None,
            provenance: fixture.freeze.reference(),
            state_digest: reference(73),
        };
        let mut graph = fixed_graph(FixedGraphInput {
            request: &request,
            state: &frozen_state,
            targets: &targets,
            scope: Some(&fixture.scope),
            admission: Some(&fixture.admission),
            authorization: Some(&fixture.authorization),
            freeze: Some(&fixture.freeze),
            obligation_set: Some(&fixture.obligation_set),
            obligations: &[],
            manifest: reference(74),
            verifier: &verifier,
        });
        graph.authorize_provenance = Some(reference(75));
        graph.target_closure = Some(target_closure_digest(&targets));
        validate_fixed_graph(&graph).map_err(RecoveryFailureV1::error)?;

        let wrong_scope = ErasureScopeCommitmentV1::new(ErasureScopeCommitmentInputV1 {
            request: request.reference(),
            scope_members: vec![reference(42)],
            target_closure: reference(76),
            lineage_rule: None,
        })?;
        assert_eq!(
            freeze_reconstruction_failure_subject(
                &graph,
                &wrong_scope,
                &fixture.admission,
                &fixture.freeze,
                &fixture.obligation_set,
            ),
            wrong_scope.reference()
        );

        Ok(())
    }

    #[test]
    fn fixed_graph_recovery_rejects_obligation_and_freeze_mismatches() -> Result<(), ErasureErrorV1>
    {
        let request = request()?;
        let verifier = AcceptFreezeVerifier;
        let fixture = frozen_fixture(request.reference())?;
        let targets = vec![fixture.target];
        let frozen_state = ErasureStateV1 {
            request: request.reference(),
            lifecycle: ErasureLifecycleV1::AccessFrozen,
            freeze_position: Some(10),
            coordinator: reference(44),
            pending_owners: Vec::new(),
            failed_owners: Vec::new(),
            replay_claim: super::super::ErasureReplayClaimV1::Exact,
            previous_state: None,
            provenance: fixture.freeze.reference(),
            state_digest: reference(73),
        };
        let mut graph = fixed_graph(FixedGraphInput {
            request: &request,
            state: &frozen_state,
            targets: &targets,
            scope: Some(&fixture.scope),
            admission: Some(&fixture.admission),
            authorization: Some(&fixture.authorization),
            freeze: Some(&fixture.freeze),
            obligation_set: Some(&fixture.obligation_set),
            obligations: &[],
            manifest: reference(74),
            verifier: &verifier,
        });
        graph.authorize_provenance = Some(reference(75));
        graph.target_closure = Some(target_closure_digest(&targets));
        validate_fixed_graph(&graph).map_err(RecoveryFailureV1::error)?;

        let mismatched_obligations = vec![obligation(request.reference())?];
        assert_eq!(
            freeze_reconstruction_failure_subject(
                &FixedGraphV1 {
                    obligations: &mismatched_obligations,
                    ..graph
                },
                &fixture.scope,
                &fixture.admission,
                &fixture.freeze,
                &fixture.obligation_set,
            ),
            fixture.obligation_set.reference()
        );

        let wrong_freeze = ErasureFreezeProvenanceV1::new(ErasureFreezeProvenanceInputV1 {
            request: request.reference(),
            scope_commitment: reference(77),
            obligation_set: fixture.obligation_set.reference(),
            freeze_position: 10,
            host_evidence: fixture.admission.reference(),
        })?;
        assert_eq!(
            freeze_reconstruction_failure_subject(
                &graph,
                &fixture.scope,
                &fixture.admission,
                &wrong_freeze,
                &fixture.obligation_set,
            ),
            wrong_freeze.reference()
        );
        Ok(())
    }

    #[test]
    fn fixed_graph_recovery_rejects_invalid_obligation_and_falls_back() -> Result<(), ErasureErrorV1>
    {
        let request = request()?;
        let verifier = AcceptFreezeVerifier;
        let fixture = frozen_fixture(request.reference())?;
        let targets = vec![fixture.target];
        let frozen_state = ErasureStateV1 {
            request: request.reference(),
            lifecycle: ErasureLifecycleV1::AccessFrozen,
            freeze_position: Some(10),
            coordinator: reference(44),
            pending_owners: Vec::new(),
            failed_owners: Vec::new(),
            replay_claim: super::super::ErasureReplayClaimV1::Exact,
            previous_state: None,
            provenance: fixture.freeze.reference(),
            state_digest: reference(73),
        };
        let mut graph = fixed_graph(FixedGraphInput {
            request: &request,
            state: &frozen_state,
            targets: &targets,
            scope: Some(&fixture.scope),
            admission: Some(&fixture.admission),
            authorization: Some(&fixture.authorization),
            freeze: Some(&fixture.freeze),
            obligation_set: Some(&fixture.obligation_set),
            obligations: &[],
            manifest: reference(74),
            verifier: &verifier,
        });
        graph.authorize_provenance = Some(reference(75));
        graph.target_closure = Some(target_closure_digest(&targets));
        validate_fixed_graph(&graph).map_err(RecoveryFailureV1::error)?;

        let invalid_obligation = ErasureObligationV1::new(ErasureObligationInputV1 {
            category: ErasureInventoryCategoryV1::Artifact,
            target: fixture.target,
            owner: fixture.target.replica_id,
            command_identity: reference(78),
        })?;
        let invalid_obligations = vec![invalid_obligation];
        let invalid_set = ErasureObligationSetV1::new(ErasureObligationSetInputV1 {
            request: request.reference(),
            obligations: vec![invalid_obligation.reference()],
            policy: reference(6),
            trust: reference(7),
        })?;
        let invalid_freeze = ErasureFreezeProvenanceV1::new(ErasureFreezeProvenanceInputV1 {
            request: request.reference(),
            scope_commitment: fixture.scope.reference(),
            obligation_set: invalid_set.reference(),
            freeze_position: 10,
            host_evidence: fixture.admission.reference(),
        })?;
        assert_eq!(
            freeze_reconstruction_failure_subject(
                &FixedGraphV1 {
                    obligations: &invalid_obligations,
                    ..graph
                },
                &fixture.scope,
                &fixture.admission,
                &invalid_freeze,
                &invalid_set,
            ),
            invalid_obligation.reference()
        );
        assert_eq!(
            freeze_reconstruction_failure_subject(
                &graph,
                &fixture.scope,
                &fixture.admission,
                &fixture.freeze,
                &fixture.obligation_set,
            ),
            fixture.admission.reference()
        );
        graph.scope = None;
        assert_eq!(
            partial_fixed_graph_subject(&graph),
            fixture.admission.reference()
        );
        Ok(())
    }
}
