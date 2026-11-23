//! The operator's Local erasure admissions record (ADR-136 follow-up F3,
//! Redmine #1408).
//!
//! One durable singleton per store says whether `requestErasure` admits new
//! requests. A store without the record is open. The operator closes and
//! reopens admissions offline with `piglor-gateway erasure-admissions`, and
//! the Local erasure host reads the record on every submission.
//!
//! Closing admissions refuses only fresh requests: the host reads the
//! record before a submission but applies it after the exact-replay check,
//! so an exact replay of an installed request keeps its answer, and
//! `getErasure`, the erasure driver and its startup sweep never read the
//! record, so every admitted request still freezes and completes.

use crate::CoreError;

/// Whether the store admits new Local erasure requests.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum ErasureAdmissionsStateV1 {
    /// New requests are admitted; a store without the record is open.
    #[default]
    Open,
    /// The operator closed new admissions.
    Closed,
}

/// The durable operator record of [`ErasureAdmissionsStateV1`].
pub trait ErasureAdmissionsPortV1 {
    /// The persisted admissions state.
    ///
    /// # Errors
    /// Returns the adapter's storage error when the record cannot be read;
    /// a caller must then treat admissions as closed.
    fn erasure_admissions(&self) -> Result<ErasureAdmissionsStateV1, CoreError>;

    /// Persist `state` durably and return the state it replaced.
    ///
    /// # Errors
    /// Returns the adapter's storage error when the record cannot be read
    /// or written; the persisted state is then unchanged.
    fn set_erasure_admissions(
        &mut self,
        state: ErasureAdmissionsStateV1,
    ) -> Result<ErasureAdmissionsStateV1, CoreError>;
}
