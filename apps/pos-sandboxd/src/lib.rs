//! Backend-specific components of the ADR-069 systemd Sandbox Provider Adapter.
//!
//! This library does not implement the provider daemon or grant admission.
//! The existing signed admission boundary must supply the selected SCS1 digest
//! and architecture before these requested-state components are used.

mod hardening;
mod transient_unit;

pub use hardening::{
    SystemdHardeningProperty, SystemdHardeningReadback, SystemdHardeningReadbackValue,
    SystemdHardeningValue, TransientUnitHardening, TransientUnitHardeningError,
};
pub use transient_unit::{
    ActivatedRootDirectory, LaunchMode, LauncherSource, SystemdManagerReadbackOnlyProperty,
    SystemdTransientUnitProperty, SystemdTransientUnitReadback, SystemdTransientUnitReadbackValue,
    SystemdTransientUnitValue, TransientUnitLaunchInputs, TransientUnitRequest,
    TransientUnitRequestError,
};

use pos_reference::sandbox_provider_protocol::{
    SandboxArchitecture, SandboxProviderProtocolError, SandboxSyscallSet,
};

/// A validated systemd syscall-filter request and its distinct expected readback.
///
/// Fields are private so callers cannot replace validated names or invert the
/// allow-list mode after compiling a selected canonical record.
pub struct SystemCallFilter {
    record: SandboxSyscallSet,
}

/// Closed failures at the syscall-filter requested-state boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum SystemCallFilterError {
    /// The selected bytes are not a valid canonical SCS1 record.
    #[error(transparent)]
    InvalidRecord(#[from] SandboxProviderProtocolError),
    /// The canonical record is not the exact selected SCS1 identity.
    #[error("systemd syscall-filter record differs from selected digest")]
    DigestMismatch,
    /// The canonical record is not for the selected admitted architecture.
    #[error("systemd syscall-filter architecture differs from selected architecture")]
    ArchitectureMismatch,
    /// Mode or exact ordered names differ from the prescribed property readback.
    #[error("systemd syscall-filter readback differs from selected authority")]
    ReadbackMismatch,
}

impl SystemCallFilter {
    /// Compile the exact canonical SCS1 selected by signed provider admission.
    ///
    /// `selected_digest` and `architecture` must come from the existing
    /// authenticated admission boundary, not evaluator-supplied claims. This
    /// method validates a request component; it does not grant admission or
    /// prove kernel enforcement.
    ///
    /// # Errors
    /// Rejects malformed bytes, an unequal SCS1 digest, or an unequal architecture.
    pub fn from_selected_record(
        bytes: &[u8],
        selected_digest: [u8; 32],
        architecture: SandboxArchitecture,
    ) -> Result<Self, SystemCallFilterError> {
        SandboxSyscallSet::from_canonical_cbor(bytes)
            .map_err(SystemCallFilterError::from)
            .and_then(|record| {
                if record.syscall_set_digest != selected_digest {
                    return Err(SystemCallFilterError::DigestMismatch);
                }
                if record.architecture != architecture {
                    return Err(SystemCallFilterError::ArchitectureMismatch);
                }
                Ok(Self { record })
            })
    }

    /// Return the exact `(bas)` value for systemd's `SystemCallFilter` property.
    ///
    /// Only requested names are sent; implicit backend additions belong solely
    /// in the expected readback. No groups, host lookups, or normalization occur.
    #[must_use]
    pub fn requested_property(&self) -> (bool, Vec<String>) {
        (true, self.record.requested_names.clone())
    }

    /// Compare typed D-Bus readback with the complete prescribed ordered array.
    ///
    /// The typed systemd proxy must deserialize `(bas)` before calling this
    /// method. Successful comparison is requested-state evidence only, not
    /// proof of native syscall rules or permission to release adapter bytes.
    ///
    /// # Errors
    /// Rejects inverted mode or any missing, extra, duplicated, or reordered name.
    pub fn verify_readback(
        &self,
        readback: &(bool, Vec<String>),
    ) -> Result<(), SystemCallFilterError> {
        if readback.0 && readback.1 == self.record.expected_effective_names {
            Ok(())
        } else {
            Err(SystemCallFilterError::ReadbackMismatch)
        }
    }
}
