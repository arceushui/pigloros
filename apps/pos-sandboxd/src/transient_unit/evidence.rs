//! The RQE1 of one verified start (ADR-069 R9 §4.3, status 0).
//!
//! The values come only from the typed request and its typed readback: the
//! requested properties as submitted (descriptor names only), and the
//! readback the verifier compared plus the manager-only `RootImagePolicy`.
//! Both lists are sorted by the canonical encoding of their names.

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
    let requested = sorted(
        requested
            .iter()
            .map(|property| DbusProperty {
                name: property.name().to_owned(),
                value: requested_value(property.value()),
            })
            .collect(),
    );
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
        RequestedConfigurationValue::DescriptorNames(names) => {
            DbusValue::DescriptorNames(names.clone())
        }
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
    }
}
