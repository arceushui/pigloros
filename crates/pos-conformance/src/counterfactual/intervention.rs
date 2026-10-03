//! Immutable INT1 counterfactual Interventions defined by ADR-064.
//!
//! `InterventionV1` is the single public Intervention schema. The proof-local
//! [`crate::InterventionV1`] evidence record is not a second wire schema: it is
//! converted explicitly through [`InterventionV1::from_proof_evidence_v1`],
//! which requires the caller to supply every binding the evidence lacks.
//!
//! Authorization lookup, plan admission, dependency-graph traversal, suffix
//! invalidation, and execution belong to later ADR-064 contracts.

use crate::domain_digest;
use ciborium::value::Value;
use std::collections::BTreeSet;
use std::io::Cursor;

/// Magic for the immutable Intervention record.
pub const INTERVENTION_MAGIC_V1: &str = "INT1";
/// Maximum encoded size of one INT1 Intervention.
pub const MAX_INTERVENTION_BYTES_V1: usize = 64 * 1024;
/// Maximum number of Interventions admitted by one counterfactual plan.
pub const MAX_INTERVENTIONS_PER_PLAN_V1: usize = 1_024;

const FIELD_COUNT: usize = 16;
const MAX_FIELD_ITEMS: u64 = 16;
const MAX_NESTING_DEPTH: u8 = 1;
const MAX_IDENTIFIER_BYTES: usize = 128;
const MAX_RATIONALE_BYTES: usize = 4_096;
const DIGEST_DOMAIN_V1: &[u8] = b"PiglorOS.Intervention.v1";

/// Closed safe errors exposed by the INT1 contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InterventionContractErrorV1 {
    /// The bytes are malformed, noncanonical, or contain a forbidden CBOR type.
    InvalidEncoding,
    /// The record magic or schema version is not supported.
    UnsupportedVersion,
    /// A required value, list, or encoded record exceeds its specified bound.
    FieldOutOfBounds,
    /// The operation code is not a member of the closed operation set.
    UnknownEnum,
    /// Plan Interventions are not strictly ordered by `(effective_tick, ordinal, id)`.
    NonCanonicalOrder,
    /// Two plan Interventions share one Intervention ID.
    DuplicateIdentity,
    /// Ordinals do not count contiguously from zero within one effective tick.
    NonContiguousOrdinal,
}

impl std::fmt::Display for InterventionContractErrorV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::InvalidEncoding => "invalid INT1 intervention encoding",
            Self::UnsupportedVersion => "unsupported INT1 intervention version",
            Self::FieldOutOfBounds => "INT1 intervention field is out of bounds",
            Self::UnknownEnum => "unknown INT1 intervention operation",
            Self::NonCanonicalOrder => "INT1 plan interventions are not canonically ordered",
            Self::DuplicateIdentity => "INT1 plan intervention ID is duplicated",
            Self::NonContiguousOrdinal => "INT1 plan intervention ordinals are not contiguous",
        })
    }
}

impl std::error::Error for InterventionContractErrorV1 {}

/// Closed INT1 operation set; the wire code is the documented discriminant.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum InterventionOperationV1 {
    /// `0`: assign the canonical value identified by the value digest.
    AssignValue,
    /// `1`: assign the admitted artifact identified by the value digest.
    AssignArtifact,
}

impl InterventionOperationV1 {
    const fn code(self) -> u64 {
        match self {
            Self::AssignValue => 0,
            Self::AssignArtifact => 1,
        }
    }

    const fn from_code(code: u64) -> Result<Self, InterventionContractErrorV1> {
        match code {
            0 => Ok(Self::AssignValue),
            1 => Ok(Self::AssignArtifact),
            _ => Err(InterventionContractErrorV1::UnknownEnum),
        }
    }
}

/// One ordered counterfactual Intervention represented by an INT1 record.
///
/// The exact deterministic-CBOR array has 16 fields: magic `INT1`, version
/// `1`, then the fields below in declaration order. Text fields are non-empty
/// UTF-8 without control characters; identifiers hold at most 128 bytes and the
/// rationale at most 4,096 bytes. The complete record holds at most 65,536
/// bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InterventionV1 {
    /// Stable 16-byte Intervention ID.
    pub intervention_id: [u8; 16],
    /// Schema ID of the intervened target.
    pub target_schema_id: u32,
    /// Entity ID of the intervened target.
    pub target_entity_id: String,
    /// Field of the target entity assigned by this Intervention.
    pub target_field: String,
    /// Closed assignment operation.
    pub operation: InterventionOperationV1,
    /// Digest of the assigned canonical value or admitted artifact.
    pub value_digest: [u8; 32],
    /// Tick Boundary from which the assignment is effective.
    pub effective_tick: u64,
    /// Contiguous zero-based ordinal within the effective tick.
    pub ordinal: u32,
    /// Principal responsible for the Intervention.
    pub principal_id: String,
    /// Capability the Principal exercises to intervene.
    pub capability: String,
    /// Consent epoch the consent decision was evaluated under.
    pub consent_epoch: u64,
    /// Digest of the bound consent decision.
    pub consent_decision_digest: [u8; 32],
    /// Human-readable rationale recorded with the Intervention.
    pub rationale: String,
    /// Digest of the Intervention provenance record.
    pub provenance_digest: [u8; 32],
}

/// INT1 bindings absent from proof-local Intervention evidence.
///
/// The proof-local free-form `operation` label is not an INT1 operation and is
/// not carried; the caller names the closed operation explicitly instead.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProofInterventionBindingV1 {
    /// Schema ID of the intervened target.
    pub target_schema_id: u32,
    /// Field of the target entity assigned by the Intervention.
    pub target_field: String,
    /// Closed assignment operation.
    pub operation: InterventionOperationV1,
    /// Digest of the bound consent decision.
    pub consent_decision_digest: [u8; 32],
    /// Rationale recorded with the Intervention.
    pub rationale: String,
}

impl InterventionV1 {
    /// Convert proof-local Intervention evidence into the public INT1 record.
    ///
    /// The evidence target becomes the target entity ID; every other evidence
    /// field maps to its same-named INT1 field. Missing bindings come only from
    /// `binding`, never from defaults.
    ///
    /// # Errors
    /// Returns a closed safe error when the converted record is invalid.
    pub fn from_proof_evidence_v1(
        evidence: &crate::InterventionV1,
        binding: ProofInterventionBindingV1,
    ) -> Result<Self, InterventionContractErrorV1> {
        let intervention = Self {
            intervention_id: evidence.intervention_id,
            target_schema_id: binding.target_schema_id,
            target_entity_id: evidence.target.clone(),
            target_field: binding.target_field,
            operation: binding.operation,
            value_digest: evidence.value_digest,
            effective_tick: evidence.effective_tick,
            ordinal: evidence.ordinal,
            principal_id: evidence.principal_id.clone(),
            capability: evidence.capability.clone(),
            consent_epoch: evidence.consent_epoch,
            consent_decision_digest: binding.consent_decision_digest,
            rationale: binding.rationale,
            provenance_digest: evidence.provenance_digest,
        };
        intervention.validate().map(|()| intervention)
    }

    /// Validate INT1 text field bounds.
    ///
    /// # Errors
    /// Returns [`InterventionContractErrorV1::FieldOutOfBounds`] when a text
    /// field is empty, too long, or contains a control character.
    pub fn validate(&self) -> Result<(), InterventionContractErrorV1> {
        if [
            &self.target_entity_id,
            &self.target_field,
            &self.principal_id,
            &self.capability,
        ]
        .into_iter()
        .all(|value| bounded_text(value, MAX_IDENTIFIER_BYTES))
            && bounded_text(&self.rationale, MAX_RATIONALE_BYTES)
        {
            Ok(())
        } else {
            Err(InterventionContractErrorV1::FieldOutOfBounds)
        }
    }

    /// Encode this Intervention as an exact deterministic-CBOR INT1 array.
    ///
    /// # Errors
    /// Returns a closed safe error when validation or canonical encoding fails.
    pub fn to_canonical_cbor(&self) -> Result<Vec<u8>, InterventionContractErrorV1> {
        self.validate()
            .and_then(|()| encode_value(&encode_intervention(self)))
    }

    /// Decode and validate exact canonical INT1 bytes.
    ///
    /// # Errors
    /// Returns a closed safe error for malformed, noncanonical, oversized,
    /// unsupported, or structurally invalid INT1 records.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, InterventionContractErrorV1> {
        if bytes.len() > MAX_INTERVENTION_BYTES_V1 {
            Err(InterventionContractErrorV1::FieldOutOfBounds)
        } else {
            decode_value(bytes)
                .and_then(|value| decode_intervention(&value))
                .and_then(|intervention| intervention.validate().map(|()| intervention))
        }
    }

    /// Compute the BLAKE3 digest of the canonical INT1 bytes, domain-separated
    /// by `PiglorOS.Intervention.v1\0`.
    ///
    /// # Errors
    /// Returns a closed safe error when the Intervention is invalid.
    pub fn digest(&self) -> Result<[u8; 32], InterventionContractErrorV1> {
        self.to_canonical_cbor()
            .map(|bytes| domain_digest(DIGEST_DOMAIN_V1, &bytes))
    }
}

/// Validate the ordered Intervention list of one counterfactual plan.
///
/// A plan holds 1 to 1,024 valid Interventions strictly ordered by
/// `(effective_tick, ordinal, intervention_id)`. Ordinals restart at zero for
/// every effective tick and count contiguously, and Intervention IDs are
/// unique across the plan.
///
/// # Errors
/// Returns a closed safe error for an out-of-bounds list or record, a
/// noncanonical order, a noncontiguous ordinal, or a duplicate ID.
pub fn validate_plan_interventions_v1(
    interventions: &[InterventionV1],
) -> Result<(), InterventionContractErrorV1> {
    if interventions.is_empty() || interventions.len() > MAX_INTERVENTIONS_PER_PLAN_V1 {
        return Err(InterventionContractErrorV1::FieldOutOfBounds);
    }
    interventions
        .iter()
        .try_for_each(InterventionV1::validate)?;
    if !interventions
        .windows(2)
        .all(|pair| order_key(&pair[0]) < order_key(&pair[1]))
    {
        return Err(InterventionContractErrorV1::NonCanonicalOrder);
    }
    validate_contiguous_ordinals(interventions).and_then(|()| validate_unique_ids(interventions))
}

const fn order_key(intervention: &InterventionV1) -> (u64, u32, [u8; 16]) {
    (
        intervention.effective_tick,
        intervention.ordinal,
        intervention.intervention_id,
    )
}

fn validate_contiguous_ordinals(
    interventions: &[InterventionV1],
) -> Result<(), InterventionContractErrorV1> {
    let mut previous_tick = None;
    let mut expected_ordinal = 0_u32;
    for intervention in interventions {
        if previous_tick != Some(intervention.effective_tick) {
            expected_ordinal = 0;
        }
        if intervention.ordinal != expected_ordinal {
            return Err(InterventionContractErrorV1::NonContiguousOrdinal);
        }
        previous_tick = Some(intervention.effective_tick);
        expected_ordinal = expected_ordinal.saturating_add(1);
    }
    Ok(())
}

fn validate_unique_ids(
    interventions: &[InterventionV1],
) -> Result<(), InterventionContractErrorV1> {
    let mut identities = BTreeSet::new();
    if interventions
        .iter()
        .all(|intervention| identities.insert(intervention.intervention_id))
    {
        Ok(())
    } else {
        Err(InterventionContractErrorV1::DuplicateIdentity)
    }
}

fn bounded_text(value: &str, maximum_bytes: usize) -> bool {
    !value.is_empty() && value.len() <= maximum_bytes && !value.chars().any(char::is_control)
}

fn encode_intervention(intervention: &InterventionV1) -> Value {
    Value::Array(vec![
        Value::Text(INTERVENTION_MAGIC_V1.to_owned()),
        Value::Integer(1_u64.into()),
        Value::Bytes(intervention.intervention_id.to_vec()),
        Value::Integer(intervention.target_schema_id.into()),
        Value::Text(intervention.target_entity_id.clone()),
        Value::Text(intervention.target_field.clone()),
        Value::Integer(intervention.operation.code().into()),
        Value::Bytes(intervention.value_digest.to_vec()),
        Value::Integer(intervention.effective_tick.into()),
        Value::Integer(intervention.ordinal.into()),
        Value::Text(intervention.principal_id.clone()),
        Value::Text(intervention.capability.clone()),
        Value::Integer(intervention.consent_epoch.into()),
        Value::Bytes(intervention.consent_decision_digest.to_vec()),
        Value::Text(intervention.rationale.clone()),
        Value::Bytes(intervention.provenance_digest.to_vec()),
    ])
}

fn decode_intervention(value: &Value) -> Result<InterventionV1, InterventionContractErrorV1> {
    let fields = array(value, FIELD_COUNT)?;
    if text_value(&fields[0])? != INTERVENTION_MAGIC_V1 || uint_value(&fields[1])? != 1 {
        return Err(InterventionContractErrorV1::UnsupportedVersion);
    }
    Ok(InterventionV1 {
        intervention_id: fixed_bytes::<16>(&fields[2])?,
        target_schema_id: u32_value(&fields[3])?,
        target_entity_id: text_value(&fields[4])?,
        target_field: text_value(&fields[5])?,
        operation: InterventionOperationV1::from_code(uint_value(&fields[6])?)?,
        value_digest: fixed_bytes::<32>(&fields[7])?,
        effective_tick: uint_value(&fields[8])?,
        ordinal: u32_value(&fields[9])?,
        principal_id: text_value(&fields[10])?,
        capability: text_value(&fields[11])?,
        consent_epoch: uint_value(&fields[12])?,
        consent_decision_digest: fixed_bytes::<32>(&fields[13])?,
        rationale: text_value(&fields[14])?,
        provenance_digest: fixed_bytes::<32>(&fields[15])?,
    })
}

fn decode_value(bytes: &[u8]) -> Result<Value, InterventionContractErrorV1> {
    preflight_cbor(bytes).and_then(|()| {
        ciborium::from_reader(Cursor::new(bytes))
            .map_err(|_| InterventionContractErrorV1::InvalidEncoding)
            .and_then(|value| {
                encode_value(&value).and_then(|canonical| {
                    if canonical == bytes {
                        Ok(value)
                    } else {
                        Err(InterventionContractErrorV1::InvalidEncoding)
                    }
                })
            })
    })
}

fn preflight_cbor(bytes: &[u8]) -> Result<(), InterventionContractErrorV1> {
    crate::preflight_array_cbor(bytes, MAX_NESTING_DEPTH, MAX_FIELD_ITEMS, false).map_err(|error| {
        match error {
            crate::CborPreflightError::InvalidEncoding => {
                InterventionContractErrorV1::InvalidEncoding
            }
            crate::CborPreflightError::FieldOutOfBounds => {
                InterventionContractErrorV1::FieldOutOfBounds
            }
        }
    })
}

fn encode_value(value: &Value) -> Result<Vec<u8>, InterventionContractErrorV1> {
    let mut bytes = Vec::new();
    ciborium::into_writer(value, &mut bytes)
        .map(|()| bytes)
        .or(Err(InterventionContractErrorV1::InvalidEncoding))
}

fn array(value: &Value, length: usize) -> Result<&[Value], InterventionContractErrorV1> {
    match value {
        Value::Array(values) if values.len() == length => Ok(values),
        _ => Err(InterventionContractErrorV1::InvalidEncoding),
    }
}

fn text_value(value: &Value) -> Result<String, InterventionContractErrorV1> {
    match value {
        Value::Text(value) => Ok(value.clone()),
        _ => Err(InterventionContractErrorV1::InvalidEncoding),
    }
}

fn uint_value(value: &Value) -> Result<u64, InterventionContractErrorV1> {
    match value {
        Value::Integer(value) => {
            u64::try_from(*value).map_err(|_| InterventionContractErrorV1::InvalidEncoding)
        }
        _ => Err(InterventionContractErrorV1::InvalidEncoding),
    }
}

fn u32_value(value: &Value) -> Result<u32, InterventionContractErrorV1> {
    uint_value(value).and_then(|value| {
        u32::try_from(value).map_err(|_| InterventionContractErrorV1::FieldOutOfBounds)
    })
}

fn fixed_bytes<const LENGTH: usize>(
    value: &Value,
) -> Result<[u8; LENGTH], InterventionContractErrorV1> {
    match value {
        Value::Bytes(value) => value
            .as_slice()
            .try_into()
            .map_err(|_| InterventionContractErrorV1::InvalidEncoding),
        _ => Err(InterventionContractErrorV1::InvalidEncoding),
    }
}
