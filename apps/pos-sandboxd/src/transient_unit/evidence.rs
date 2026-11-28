//! The RQE1 of one requested start (ADR-069 R9 §4.3): status 0 for a
//! verified start, 2 for a readback the verifier rejected and 3 for one that
//! could not be obtained.
//!
//! The values come only from the typed request and its typed readback: the
//! requested properties as submitted (descriptor names only), and the
//! readback the verifier compared plus, once verified, the manager-only
//! `RootImagePolicy`. Both lists are sorted by the canonical encoding of
//! their names.

use pos_reference::sandbox_provider_protocol::{
    DbusProperty, DbusValue, RequestedConfigurationEvidence, RequestedConfigurationEvidenceFields,
    RequestedConfigurationStatus, SandboxProviderProtocolError,
};

use super::{
    RequestedConfigurationProperty, RequestedConfigurationValue, SystemdManagerReadback,
    SystemdTransientUnitReadback, SystemdTransientUnitReadbackValue,
};
use crate::SystemdHardeningReadbackValue;

/// A start whose requested state was read back and verified, as RQE1.
pub trait RequestedConfiguration {
    /// The RQE1 of this start for the attempt and its AGR1.
    ///
    /// # Errors
    /// Any R9 rule the record fails; nothing is then released.
    fn requested_configuration_evidence(
        &self,
        attempt_id: [u8; 16],
        agr1_digest: [u8; 32],
    ) -> Result<RequestedConfigurationEvidence, SandboxProviderProtocolError>;
}

/// The status-0 RQE1 of a verified start.
///
/// # Errors
/// Any R9 rule the record fails.
pub fn verified_requested_configuration(
    attempt_id: [u8; 16],
    agr1_digest: [u8; 32],
    requested: &[RequestedConfigurationProperty],
    readback: &[SystemdTransientUnitReadback],
    manager: &SystemdManagerReadback,
) -> Result<RequestedConfigurationEvidence, SandboxProviderProtocolError> {
    let requested = requested_properties(requested);
    let readback = sorted(
        readback
            .iter()
            .map(|property| DbusProperty {
                name: property.name().to_owned(),
                value: readback_value(property.value()),
            })
            .chain([DbusProperty {
                name: manager.property().name().to_owned(),
                value: DbusValue::String(manager.value().to_owned()),
            }])
            .collect(),
    );
    RequestedConfigurationEvidence::new(&RequestedConfigurationEvidenceFields {
        attempt_id,
        agr1_digest,
        status: RequestedConfigurationStatus::Verified,
        requested: Some(requested),
        readback: Some(readback),
    })
}

/// The status-2 or status-3 RQE1 of a start that was requested and not
/// verified: `readback` is the complete readback the verifier rejected, or
/// `None` when it could not be obtained.
///
/// # Errors
/// Any R9 rule the record fails.
pub fn unverified_requested_configuration(
    attempt_id: [u8; 16],
    agr1_digest: [u8; 32],
    requested: &[RequestedConfigurationProperty],
    readback: Option<&[SystemdTransientUnitReadback]>,
) -> Result<RequestedConfigurationEvidence, SandboxProviderProtocolError> {
    let status = readback.map_or(RequestedConfigurationStatus::ReadbackUnavailable, |_| {
        RequestedConfigurationStatus::Mismatch
    });
    RequestedConfigurationEvidence::new(&RequestedConfigurationEvidenceFields {
        attempt_id,
        agr1_digest,
        status,
        requested: Some(requested_properties(requested)),
        readback: readback.map(|readback| {
            sorted(
                readback
                    .iter()
                    .map(|property| DbusProperty {
                        name: property.name().to_owned(),
                        value: readback_value(property.value()),
                    })
                    .collect(),
            )
        }),
    })
}

/// The requested properties as RQE1 records them, sorted.
fn requested_properties(requested: &[RequestedConfigurationProperty]) -> Vec<DbusProperty> {
    sorted(
        requested
            .iter()
            .map(|property| DbusProperty {
                name: property.name().to_owned(),
                value: requested_value(property.value()),
            })
            .collect(),
    )
}

/// Sorted as RQE1 requires: by the canonical CBOR encoding of the name,
/// which orders text by length first.
fn sorted(mut properties: Vec<DbusProperty>) -> Vec<DbusProperty> {
    properties
        .sort_by(|left, right| (left.name.len(), &left.name).cmp(&(right.name.len(), &right.name)));
    properties
}

fn requested_value(value: &RequestedConfigurationValue) -> DbusValue {
    match value {
        RequestedConfigurationValue::Typed(value) => readback_value(value),
        descriptors => descriptor_value(descriptors),
    }
}

/// The descriptor array's names, or a standard descriptor of which nothing
/// is recorded.
fn descriptor_value(value: &RequestedConfigurationValue) -> DbusValue {
    match value {
        RequestedConfigurationValue::DescriptorNames(names) => {
            DbusValue::DescriptorNames(names.clone())
        }
        _ => DbusValue::Descriptor,
    }
}

fn readback_value(value: &SystemdTransientUnitReadbackValue) -> DbusValue {
    match value {
        SystemdTransientUnitReadbackValue::Static(value) => hardening_value(value),
        SystemdTransientUnitReadbackValue::String(value) => DbusValue::String(value.clone()),
        SystemdTransientUnitReadbackValue::BindReadOnlyPaths(paths) => {
            DbusValue::BindPaths(paths.clone())
        }
        SystemdTransientUnitReadbackValue::BoolStringArray((flag, names)) => {
            DbusValue::FlaggedStrings(*flag, names.clone())
        }
        SystemdTransientUnitReadbackValue::StringArray(values) => {
            DbusValue::StringArray(values.clone())
        }
        SystemdTransientUnitReadbackValue::TemporaryFileSystem(mounts) => {
            DbusValue::StringPairs(mounts.clone())
        }
        SystemdTransientUnitReadbackValue::ExecStart(commands) => {
            DbusValue::Commands(commands.clone())
        }
        SystemdTransientUnitReadbackValue::U32(value) => DbusValue::U32(*value),
        SystemdTransientUnitReadbackValue::U64(value) => DbusValue::U64(*value),
    }
}

fn hardening_value(value: &SystemdHardeningReadbackValue) -> DbusValue {
    match value {
        SystemdHardeningReadbackValue::Bool(value) => DbusValue::Bool(*value),
        SystemdHardeningReadbackValue::String(value) => DbusValue::String(value.clone()),
        SystemdHardeningReadbackValue::U64(value) => DbusValue::U64(*value),
        SystemdHardeningReadbackValue::U32(value) => DbusValue::U32(*value),
        SystemdHardeningReadbackValue::StringArray(values) => {
            DbusValue::StringArray(values.clone())
        }
        SystemdHardeningReadbackValue::ExitStatuses(statuses, signals) => {
            DbusValue::ExitStatusSet(statuses.clone(), signals.clone())
        }
    }
}
