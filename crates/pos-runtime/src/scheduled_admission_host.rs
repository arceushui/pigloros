//! Host ports for ADR-021 scheduled-pass admission (#480).
//!
//! [`ScheduledAdmissionPortsV1`] is the narrow store capability a trusted host
//! needs to admit a scheduled pass: the admitted-batch port, the
//! admission-fence publisher, and authority persistence. It deliberately has
//! no [`EventStore`] supertrait, so a holder cannot raw-append, create, or
//! Fork a Timeline through it. [`ScheduledAdmissionStoreV1`] is a complete
//! store that also provides those ports.
//!
//! With the `local-admission-host` feature, [`LocalScheduledAdmissionHostV1`]
//! composes the local experiment session root over these ports. That feature
//! and Rust visibility keep the host out of the deployable Plugin, Driver,
//! and provider dependency graphs; they are not a security boundary against
//! code in the same process, which can reach the host whenever the feature is
//! enabled anywhere in its build (including through Cargo feature
//! unification). Admission is enforced by the store, which compares the
//! published fence and the persisted authority inside its admission
//! transaction.

use pos_core::{
    store::EventStore, AuthorityPersistencePortV1, PipelineAdmissionFencePublisherV1,
    PipelineAdmissionPortV1,
};

#[cfg(feature = "local-admission-host")]
mod local;

#[cfg(feature = "local-admission-host")]
pub use local::LocalScheduledAdmissionHostV1;

/// Store ports a trusted host needs to admit scheduled passes, and nothing
/// else.
///
/// The admitted-batch port, the admission-fence publisher, and authority
/// persistence must belong to the same store as the Timeline, so the store
/// compares the fence and persisted authority inside its admission
/// transaction.
pub trait ScheduledAdmissionPortsV1:
    PipelineAdmissionPortV1 + PipelineAdmissionFencePublisherV1 + AuthorityPersistencePortV1
{
}

impl<T> ScheduledAdmissionPortsV1 for T where
    T: PipelineAdmissionPortV1 + PipelineAdmissionFencePublisherV1 + AuthorityPersistencePortV1
{
}

/// A complete Event store that also provides the scheduled-admission ports.
pub trait ScheduledAdmissionStoreV1: EventStore + ScheduledAdmissionPortsV1 {}

impl<T> ScheduledAdmissionStoreV1 for T where T: EventStore + ScheduledAdmissionPortsV1 {}
