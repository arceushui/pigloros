//! Immutable EPF1 execution profiles defined by ADR-058.

use crate::{domain_digest, ReproducibilityClassV1};
use ciborium::value::Value;
use std::cmp::Ordering;
use std::collections::BTreeSet;
use std::io::Cursor;

/// Magic for the immutable execution-profile record.
pub const EXECUTION_PROFILE_MAGIC_V1: &str = "EPF1";
/// Maximum encoded size of an EPF1 execution profile.
pub const MAX_EXECUTION_PROFILE_BYTES_V1: usize = 1024 * 1024;

const MAX_IDENTIFIER_BYTES: usize = 128;
const MAX_SEMANTIC_VERSION_BYTES: usize = 64;
const MAX_REPRODUCIBILITY_CLASSES: usize = 4;
const MAX_SCHEDULER_DRIVER_ORDER: usize = 256;
const MAX_SCHEMAS_AND_UPCASTERS: usize = 256;
const MAX_CAPABILITY_IDS: usize = 256;
const MAX_ALLOWED_OPERATIONAL_DIFFERENCES: usize = 64;
const PROFILE_FIELDS: usize = 17;

/// Closed safe errors exposed by the EPF1 contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecutionProfileContractErrorV1 {
    /// The bytes are malformed, noncanonical, or contain a forbidden CBOR type.
    InvalidEncoding,
    /// The record magic, schema version, or enum code is not supported.
    UnsupportedVersion,
    /// A required value or encoded record exceeds its specified bound.
    FieldOutOfBounds,
    /// A set-like record list is not strictly ordered or contains a duplicate.
    NonCanonicalOrder,
    /// The content does not match its declared profile digest.
    DigestMismatch,
}

impl std::fmt::Display for ExecutionProfileContractErrorV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::InvalidEncoding => "invalid EPF1 execution profile encoding",
            Self::UnsupportedVersion => "unsupported EPF1 execution profile version",
            Self::FieldOutOfBounds => "EPF1 execution profile field is out of bounds",
            Self::NonCanonicalOrder => "EPF1 execution profile lists are not canonical",
            Self::DigestMismatch => "EPF1 execution profile digest does not match",
        })
    }
}

impl std::error::Error for ExecutionProfileContractErrorV1 {}

/// Network and capability policy embedded in an EPF1 execution profile.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutionProfileCapabilitiesV1 {
    pub network_allowed: bool,
    pub capability_ids: Vec<String>,
}

/// Inclusive evaluator-version compatibility metadata embedded in EPF1.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutionProfileCompatibilityV1 {
    pub minimum_evaluator_version: String,
    pub maximum_evaluator_version: String,
}

/// The complete immutable execution contract represented by an EPF1 record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutionProfileV1 {
    pub profile_id: String,
    pub semantic_version: String,
    pub reproducibility_classes: Vec<ReproducibilityClassV1>,
    pub architecture_rules: Vec<String>,
    pub numeric_rules: Vec<String>,
    /// This list is an execution sequence; its order is semantically significant.
    pub scheduler_driver_order: Vec<String>,
    pub tick_policy: String,
    pub schemas_and_upcasters: Vec<String>,
    pub artifact_rules: Vec<String>,
    pub capabilities_and_network: ExecutionProfileCapabilitiesV1,
    pub deterministic_budgets: [u64; 8],
    pub allowed_operational_differences: Vec<String>,
    pub compatibility: ExecutionProfileCompatibilityV1,
    pub previous_profile_digest: Option<[u8; 32]>,
    pub profile_digest: [u8; 32],
}

impl ExecutionProfileV1 {
    /// Validate the closed EPF1 contract, its encoded-size limit, and its digest.
    ///
    /// # Errors
    ///
    /// Returns a closed safe error when any field, ordering, size, or digest is invalid.
    pub fn validate(&self) -> Result<(), ExecutionProfileContractErrorV1> {
        encode_validated_profile(self).map(|_| ())
    }

    /// Encode this profile as an exact deterministic-CBOR EPF1 array.
    ///
    /// # Errors
    ///
    /// Returns a closed safe error when validation or canonical encoding fails.
    pub fn to_canonical_cbor(&self) -> Result<Vec<u8>, ExecutionProfileContractErrorV1> {
        encode_validated_profile(self)
    }

    /// Decode and validate exact canonical EPF1 bytes.
    ///
    /// # Errors
    ///
    /// Returns a closed safe error for malformed, noncanonical, oversized, or invalid EPF1.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, ExecutionProfileContractErrorV1> {
        if bytes.len() > MAX_EXECUTION_PROFILE_BYTES_V1 {
            Err(ExecutionProfileContractErrorV1::FieldOutOfBounds)
        } else {
            decode_value(bytes)
                .and_then(|value| decode_profile(&value))
                .and_then(|profile| profile.validate().map(|()| profile))
        }
    }

    /// Compute the EPF1 domain-separated digest over fields 0 through 15.
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        let unsigned =
            encode_value(&encode_profile_fields(self)).unwrap_or_else(|_| std::process::abort());
        domain_digest(b"PiglorOS.ExecutionProfile.v1", &unsigned)
    }
}

fn encode_validated_profile(
    profile: &ExecutionProfileV1,
) -> Result<Vec<u8>, ExecutionProfileContractErrorV1> {
    validate_profile_fields(profile).and_then(|()| {
        encode_value(&encode_profile_fields(profile)).and_then(|unsigned| {
            if unsigned.len() > MAX_EXECUTION_PROFILE_BYTES_V1 {
                Err(ExecutionProfileContractErrorV1::FieldOutOfBounds)
            } else if domain_digest(b"PiglorOS.ExecutionProfile.v1", &unsigned)
                != profile.profile_digest
            {
                Err(ExecutionProfileContractErrorV1::DigestMismatch)
            } else {
                encode_value(&encode_profile(profile)).and_then(|encoded| {
                    if encoded.len() > MAX_EXECUTION_PROFILE_BYTES_V1 {
                        Err(ExecutionProfileContractErrorV1::FieldOutOfBounds)
                    } else {
                        Ok(encoded)
                    }
                })
            }
        })
    })
}

fn validate_profile_fields(
    profile: &ExecutionProfileV1,
) -> Result<(), ExecutionProfileContractErrorV1> {
    let invalid_bounds = ExecutionProfileContractErrorV1::FieldOutOfBounds;
    if !crate::identifier(&profile.profile_id, MAX_IDENTIFIER_BYTES)
        || !valid_semantic_version(&profile.semantic_version)
        || profile.reproducibility_classes.is_empty()
        || profile.reproducibility_classes.len() > MAX_REPRODUCIBILITY_CLASSES
        || !valid_identifier_list(&profile.architecture_rules)
        || !valid_identifier_list(&profile.numeric_rules)
        || profile.scheduler_driver_order.is_empty()
        || profile.scheduler_driver_order.len() > MAX_SCHEDULER_DRIVER_ORDER
        || !profile
            .scheduler_driver_order
            .iter()
            .all(|value| crate::identifier(value, MAX_IDENTIFIER_BYTES))
        || !crate::identifier(&profile.tick_policy, MAX_IDENTIFIER_BYTES)
        || profile.schemas_and_upcasters.is_empty()
        || profile.schemas_and_upcasters.len() > MAX_SCHEMAS_AND_UPCASTERS
        || !valid_identifier_list(&profile.schemas_and_upcasters)
        || !valid_identifier_list(&profile.artifact_rules)
        || profile.capabilities_and_network.capability_ids.len() > MAX_CAPABILITY_IDS
        || !valid_identifier_values(&profile.capabilities_and_network.capability_ids)
        || profile.deterministic_budgets.contains(&0)
        || profile.allowed_operational_differences.len() > MAX_ALLOWED_OPERATIONAL_DIFFERENCES
        || !valid_identifier_values(&profile.allowed_operational_differences)
        || !valid_compatibility(&profile.compatibility)
    {
        return Err(invalid_bounds);
    }
    if !strictly_ordered(&profile.reproducibility_classes)
        || !strictly_ordered(&profile.capabilities_and_network.capability_ids)
        || !unique_values(&profile.architecture_rules)
        || !unique_values(&profile.numeric_rules)
        || !unique_values(&profile.scheduler_driver_order)
        || !unique_values(&profile.schemas_and_upcasters)
        || !unique_values(&profile.artifact_rules)
        || !unique_values(&profile.allowed_operational_differences)
    {
        Err(ExecutionProfileContractErrorV1::NonCanonicalOrder)
    } else {
        Ok(())
    }
}

fn valid_identifier_list(values: &[String]) -> bool {
    !values.is_empty()
        && values
            .iter()
            .all(|value| crate::identifier(value, MAX_IDENTIFIER_BYTES))
}

fn valid_identifier_values(values: &[String]) -> bool {
    values
        .iter()
        .all(|value| crate::identifier(value, MAX_IDENTIFIER_BYTES))
}

fn valid_semantic_version(value: &str) -> bool {
    crate::semantic_version(value, MAX_SEMANTIC_VERSION_BYTES, None)
}

fn valid_compatibility(value: &ExecutionProfileCompatibilityV1) -> bool {
    valid_semantic_version(&value.minimum_evaluator_version)
        && valid_semantic_version(&value.maximum_evaluator_version)
        && semantic_version_precedence(
            &value.minimum_evaluator_version,
            &value.maximum_evaluator_version,
        ) != Ordering::Greater
}

fn semantic_version_precedence(left: &str, right: &str) -> Ordering {
    let left_without_build = left.split_once('+').map_or(left, |(version, _)| version);
    let right_without_build = right.split_once('+').map_or(right, |(version, _)| version);
    let (left_core, left_prerelease) = version_core_and_prerelease(left_without_build);
    let (right_core, right_prerelease) = version_core_and_prerelease(right_without_build);
    for (left_component, right_component) in left_core.split('.').zip(right_core.split('.')) {
        let comparison = numeric_identifier_precedence(left_component, right_component);
        if comparison != Ordering::Equal {
            return comparison;
        }
    }
    prerelease_precedence(left_prerelease, right_prerelease)
}

fn version_core_and_prerelease(value: &str) -> (&str, Option<&str>) {
    value
        .split_once('-')
        .map_or((value, None), |(core, prerelease)| (core, Some(prerelease)))
}

fn prerelease_precedence(left: Option<&str>, right: Option<&str>) -> Ordering {
    match (left, right) {
        (None, None) => Ordering::Equal,
        (None, Some(_)) => Ordering::Greater,
        (Some(_), None) => Ordering::Less,
        (Some(left), Some(right)) => {
            let mut left_identifiers = left.split('.');
            let mut right_identifiers = right.split('.');
            loop {
                match (left_identifiers.next(), right_identifiers.next()) {
                    (Some(left), Some(right)) => {
                        let comparison = prerelease_identifier_precedence(left, right);
                        if comparison != Ordering::Equal {
                            return comparison;
                        }
                    }
                    (None, None) => return Ordering::Equal,
                    (None, Some(_)) => return Ordering::Less,
                    (Some(_), None) => return Ordering::Greater,
                }
            }
        }
    }
}

fn prerelease_identifier_precedence(left: &str, right: &str) -> Ordering {
    let left_is_numeric = left.bytes().all(|byte| byte.is_ascii_digit());
    let right_is_numeric = right.bytes().all(|byte| byte.is_ascii_digit());
    match (left_is_numeric, right_is_numeric) {
        (true, true) => numeric_identifier_precedence(left, right),
        (true, false) => Ordering::Less,
        (false, true) => Ordering::Greater,
        (false, false) => left.cmp(right),
    }
}

fn numeric_identifier_precedence(left: &str, right: &str) -> Ordering {
    left.len().cmp(&right.len()).then_with(|| left.cmp(right))
}

fn strictly_ordered<T: Ord>(values: &[T]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

fn unique_values<T: Ord>(values: &[T]) -> bool {
    values.iter().collect::<BTreeSet<_>>().len() == values.len()
}

fn encode_profile(profile: &ExecutionProfileV1) -> Value {
    let mut fields = profile_fields(profile);
    fields.push(bytes(&profile.profile_digest));
    Value::Array(fields)
}

fn encode_profile_fields(profile: &ExecutionProfileV1) -> Value {
    Value::Array(profile_fields(profile))
}

fn profile_fields(profile: &ExecutionProfileV1) -> Vec<Value> {
    vec![
        text(EXECUTION_PROFILE_MAGIC_V1),
        uint(1),
        text(&profile.profile_id),
        text(&profile.semantic_version),
        Value::Array(
            profile
                .reproducibility_classes
                .iter()
                .map(|class| uint(reproducibility_code(*class)))
                .collect(),
        ),
        strings(&profile.architecture_rules),
        strings(&profile.numeric_rules),
        strings(&profile.scheduler_driver_order),
        text(&profile.tick_policy),
        strings(&profile.schemas_and_upcasters),
        strings(&profile.artifact_rules),
        Value::Array(vec![
            Value::Bool(profile.capabilities_and_network.network_allowed),
            strings(&profile.capabilities_and_network.capability_ids),
        ]),
        Value::Array(
            profile
                .deterministic_budgets
                .iter()
                .copied()
                .map(uint)
                .collect(),
        ),
        strings(&profile.allowed_operational_differences),
        Value::Array(vec![
            text(&profile.compatibility.minimum_evaluator_version),
            text(&profile.compatibility.maximum_evaluator_version),
        ]),
        optional_digest(profile.previous_profile_digest.as_ref()),
    ]
}

fn decode_profile(value: &Value) -> Result<ExecutionProfileV1, ExecutionProfileContractErrorV1> {
    array(value, PROFILE_FIELDS).and_then(|fields| {
        decode_header(&fields[0], &fields[1]).and_then(|()| decode_profile_fields(fields))
    })
}

fn decode_header(magic: &Value, version: &Value) -> Result<(), ExecutionProfileContractErrorV1> {
    text_value(magic).and_then(|magic| {
        uint_value(version).and_then(|version| {
            if magic == EXECUTION_PROFILE_MAGIC_V1 && version == 1 {
                Ok(())
            } else {
                Err(ExecutionProfileContractErrorV1::UnsupportedVersion)
            }
        })
    })
}

fn decode_profile_fields(
    fields: &[Value],
) -> Result<ExecutionProfileV1, ExecutionProfileContractErrorV1> {
    let profile_id = text_value(&fields[2])?;
    let semantic_version = text_value(&fields[3])?;
    let reproducibility_classes = decode_reproducibility_classes(&fields[4])?;
    let architecture_rules = strings_value(&fields[5])?;
    let numeric_rules = strings_value(&fields[6])?;
    let scheduler_driver_order = strings_value(&fields[7])?;
    let tick_policy = text_value(&fields[8])?;
    let schemas_and_upcasters = strings_value(&fields[9])?;
    let artifact_rules = strings_value(&fields[10])?;
    let capabilities_and_network = decode_capabilities(&fields[11])?;
    let deterministic_budgets = decode_budgets(&fields[12])?;
    let allowed_operational_differences = strings_value(&fields[13])?;
    let compatibility = decode_compatibility(&fields[14])?;
    let previous_profile_digest = optional_digest_value(&fields[15])?;
    let profile_digest = digest_value(&fields[16])?;

    Ok(ExecutionProfileV1 {
        profile_id,
        semantic_version,
        reproducibility_classes,
        architecture_rules,
        numeric_rules,
        scheduler_driver_order,
        tick_policy,
        schemas_and_upcasters,
        artifact_rules,
        capabilities_and_network,
        deterministic_budgets,
        allowed_operational_differences,
        compatibility,
        previous_profile_digest,
        profile_digest,
    })
}

fn decode_reproducibility_classes(
    value: &Value,
) -> Result<Vec<ReproducibilityClassV1>, ExecutionProfileContractErrorV1> {
    array_values(value).and_then(|values| values.iter().map(decode_reproducibility_class).collect())
}

fn decode_reproducibility_class(
    value: &Value,
) -> Result<ReproducibilityClassV1, ExecutionProfileContractErrorV1> {
    uint_value(value).and_then(|code| match code {
        0 => Ok(ReproducibilityClassV1::RecordedReplay),
        1 => Ok(ReproducibilityClassV1::ProfileRecomputation),
        2 => Ok(ReproducibilityClassV1::CrossProfileConformance),
        3 => Ok(ReproducibilityClassV1::LiveUnverified),
        _ => Err(ExecutionProfileContractErrorV1::UnsupportedVersion),
    })
}

fn decode_capabilities(
    value: &Value,
) -> Result<ExecutionProfileCapabilitiesV1, ExecutionProfileContractErrorV1> {
    array(value, 2).and_then(|fields| {
        bool_value(&fields[0]).and_then(|network_allowed| {
            strings_value(&fields[1]).map(|capability_ids| ExecutionProfileCapabilitiesV1 {
                network_allowed,
                capability_ids,
            })
        })
    })
}

fn decode_budgets(value: &Value) -> Result<[u64; 8], ExecutionProfileContractErrorV1> {
    array(value, 8).and_then(|values| {
        let mut budgets = [0; 8];
        values
            .iter()
            .zip(budgets.iter_mut())
            .try_for_each(|(value, budget)| uint_value(value).map(|value| *budget = value))
            .map(|()| budgets)
    })
}

fn decode_compatibility(
    value: &Value,
) -> Result<ExecutionProfileCompatibilityV1, ExecutionProfileContractErrorV1> {
    array(value, 2).and_then(|fields| {
        text_value(&fields[0]).and_then(|minimum_evaluator_version| {
            text_value(&fields[1]).map(|maximum_evaluator_version| {
                ExecutionProfileCompatibilityV1 {
                    minimum_evaluator_version,
                    maximum_evaluator_version,
                }
            })
        })
    })
}

fn encode_value(value: &Value) -> Result<Vec<u8>, ExecutionProfileContractErrorV1> {
    let mut bytes = Vec::new();
    ciborium::into_writer(value, &mut bytes)
        .map(|()| bytes)
        .map_err(|_| ExecutionProfileContractErrorV1::InvalidEncoding)
}

fn decode_value(bytes: &[u8]) -> Result<Value, ExecutionProfileContractErrorV1> {
    preflight_cbor(bytes).and_then(|()| {
        ciborium::from_reader(Cursor::new(bytes))
            .map_err(|_| ExecutionProfileContractErrorV1::InvalidEncoding)
            .and_then(|value| {
                encode_value(&value).and_then(|canonical| {
                    if canonical == bytes {
                        Ok(value)
                    } else {
                        Err(ExecutionProfileContractErrorV1::InvalidEncoding)
                    }
                })
            })
    })
}

fn preflight_cbor(bytes: &[u8]) -> Result<(), ExecutionProfileContractErrorV1> {
    crate::preflight_array_cbor(bytes, 3, MAX_EXECUTION_PROFILE_BYTES_V1 as u64, true).map_err(
        |error| match error {
            crate::CborPreflightError::InvalidEncoding => {
                ExecutionProfileContractErrorV1::InvalidEncoding
            }
            crate::CborPreflightError::FieldOutOfBounds => {
                ExecutionProfileContractErrorV1::FieldOutOfBounds
            }
        },
    )
}

fn array(value: &Value, length: usize) -> Result<&[Value], ExecutionProfileContractErrorV1> {
    match value {
        Value::Array(values) if values.len() == length => Ok(values),
        _ => Err(ExecutionProfileContractErrorV1::InvalidEncoding),
    }
}

fn array_values(value: &Value) -> Result<&[Value], ExecutionProfileContractErrorV1> {
    match value {
        Value::Array(values) => Ok(values),
        _ => Err(ExecutionProfileContractErrorV1::InvalidEncoding),
    }
}

fn text_value(value: &Value) -> Result<String, ExecutionProfileContractErrorV1> {
    match value {
        Value::Text(value) => Ok(value.clone()),
        _ => Err(ExecutionProfileContractErrorV1::InvalidEncoding),
    }
}

fn strings_value(value: &Value) -> Result<Vec<String>, ExecutionProfileContractErrorV1> {
    array_values(value).and_then(|values| values.iter().map(text_value).collect())
}

fn uint_value(value: &Value) -> Result<u64, ExecutionProfileContractErrorV1> {
    match value {
        Value::Integer(value) => {
            u64::try_from(*value).map_err(|_| ExecutionProfileContractErrorV1::InvalidEncoding)
        }
        _ => Err(ExecutionProfileContractErrorV1::InvalidEncoding),
    }
}

const fn bool_value(value: &Value) -> Result<bool, ExecutionProfileContractErrorV1> {
    match value {
        Value::Bool(value) => Ok(*value),
        _ => Err(ExecutionProfileContractErrorV1::InvalidEncoding),
    }
}

fn bytes_value(value: &Value) -> Result<Vec<u8>, ExecutionProfileContractErrorV1> {
    match value {
        Value::Bytes(value) => Ok(value.clone()),
        _ => Err(ExecutionProfileContractErrorV1::InvalidEncoding),
    }
}

fn digest_value(value: &Value) -> Result<[u8; 32], ExecutionProfileContractErrorV1> {
    bytes_value(value).and_then(|value| {
        value
            .as_slice()
            .try_into()
            .map_err(|_| ExecutionProfileContractErrorV1::InvalidEncoding)
    })
}

fn optional_digest_value(
    value: &Value,
) -> Result<Option<[u8; 32]>, ExecutionProfileContractErrorV1> {
    if matches!(value, Value::Null) {
        Ok(None)
    } else {
        digest_value(value).map(Some)
    }
}

const fn reproducibility_code(value: ReproducibilityClassV1) -> u64 {
    match value {
        ReproducibilityClassV1::RecordedReplay => 0,
        ReproducibilityClassV1::ProfileRecomputation => 1,
        ReproducibilityClassV1::CrossProfileConformance => 2,
        ReproducibilityClassV1::LiveUnverified => 3,
    }
}

fn text(value: &str) -> Value {
    Value::Text(value.to_owned())
}

fn uint(value: u64) -> Value {
    Value::Integer(value.into())
}

fn bytes(value: &[u8; 32]) -> Value {
    Value::Bytes(value.to_vec())
}

fn optional_digest(value: Option<&[u8; 32]>) -> Value {
    value.map_or(Value::Null, bytes)
}

fn strings(values: &[String]) -> Value {
    Value::Array(values.iter().map(|value| text(value)).collect())
}
