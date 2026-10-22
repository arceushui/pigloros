//! The admitted and the active attempt records of the execute path (#441).
//!
//! [`AdmittedAttempt`] copies the facts of one reserved, admitted entry and
//! the directory prepared for it. [`ActiveAttempt`] is the record of a unit
//! that was started for it and not yet released; the Local binding token is
//! minted only from it.

use std::time::Instant;

use pos_reference::{
    provider_admission::AdmittedAuthority, sandbox_provider_protocol::SandboxExecutionMode,
};

use crate::{AdmittedEntry, ExecuteError, PreparedAttemptDirectory, TransientServiceUnitName};

/// The facts of one reserved, admitted attempt that the execute path binds.
///
/// Only [`Self::from_entry`] creates one, from an entry whose reservation is
/// held and a directory prepared for that same attempt, so no caller can
/// present facts the admission did not produce.
#[derive(Clone, Debug)]
pub struct AdmittedAttempt {
    attempt_id: [u8; 16],
    unit_name: TransientServiceUnitName,
    sim1_digest: [u8; 32],
    authority: AdmittedAuthority,
    mode: SandboxExecutionMode,
}

impl AdmittedAttempt {
    /// Take the facts of `entry` and require `directory` to be its own.
    ///
    /// # Errors
    /// [`ExecuteError::DirectoryIdentity`] when the directory was prepared for
    /// another attempt or another SIM1.
    pub fn from_entry(
        entry: &AdmittedEntry<'_>,
        directory: &PreparedAttemptDirectory,
    ) -> Result<Self, ExecuteError> {
        let admission = entry.admission();
        let request = admission.snapshot().request();
        let intent = directory.intent();
        if intent.attempt_id() != request.attempt_id
            || intent.sim1_digest() != request.authority.sim1_digest
        {
            return Err(ExecuteError::DirectoryIdentity);
        }
        Ok(Self {
            attempt_id: request.attempt_id,
            unit_name: intent.unit_name().clone(),
            sim1_digest: request.authority.sim1_digest,
            authority: admission.authority(),
            mode: admission.snapshot().launch_policy().execution_mode,
        })
    }

    /// The attempt identity.
    #[must_use]
    pub const fn attempt_id(&self) -> [u8; 16] {
        self.attempt_id
    }

    /// The deterministic transient unit name of the attempt.
    #[must_use]
    pub const fn unit_name(&self) -> &TransientServiceUnitName {
        &self.unit_name
    }

    /// The execution mode of the admitted launch policy.
    #[must_use]
    pub const fn mode(&self) -> SandboxExecutionMode {
        self.mode
    }

    /// Facts for tests that have no privileged installation to admit from.
    #[cfg(test)]
    pub(crate) fn for_test(
        attempt_id: [u8; 16],
        authority: AdmittedAuthority,
        mode: SandboxExecutionMode,
    ) -> Result<Self, crate::TransientServiceUnitNameError> {
        TransientServiceUnitName::from_attempt_id(attempt_id).map(|unit_name| Self {
            attempt_id,
            unit_name,
            sim1_digest: [0x51; 32],
            authority,
            mode,
        })
    }
}

/// The record of a started, not yet released attempt.
///
/// It exists once the transient unit was started and its requested state
/// verified. The provider records the attempt, the authority heads it was
/// admitted with (the last-moment recheck confirmed them), and the broker watchdog deadline here, and
/// binds everything that must belong to this attempt to it. It has no public
/// constructor.
#[derive(Clone, Debug)]
pub struct ActiveAttempt {
    admitted: AdmittedAttempt,
    deadline: Instant,
}

impl ActiveAttempt {
    pub(crate) const fn record(admitted: AdmittedAttempt, deadline: Instant) -> Self {
        Self { admitted, deadline }
    }

    /// The attempt identity.
    #[must_use]
    pub const fn attempt_id(&self) -> [u8; 16] {
        self.admitted.attempt_id
    }

    /// The deterministic transient unit name of the attempt.
    #[must_use]
    pub const fn unit_name(&self) -> &TransientServiceUnitName {
        &self.admitted.unit_name
    }

    /// The SIM1 identity the attempt was admitted for.
    #[must_use]
    pub const fn sim1_digest(&self) -> [u8; 32] {
        self.admitted.sim1_digest
    }

    /// The authority heads and epochs the attempt was admitted and rechecked
    /// against.
    #[must_use]
    pub const fn authority(&self) -> AdmittedAuthority {
        self.admitted.authority
    }

    /// The broker's monotonic watchdog deadline for the whole attempt.
    #[must_use]
    pub const fn deadline(&self) -> Instant {
        self.deadline
    }
}
