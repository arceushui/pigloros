//! The host Timelines of a Gateway store (ADR-136 §1 and §4a; #1447).
//!
//! A host Timeline is a root that only the host creates, under an identity
//! no client can claim: the Local Principal's Consent Timeline and its
//! authority Timeline, and the Erasure Host Timeline (ELHT1) once
//! `provision-local-erasure` has recorded the store's erasure store
//! identity. No client route reaches one: a read, a signal or action append
//! and a Fork-admission parent naming one are answered exactly as for a
//! Timeline the store does not hold, and none of them counts against the
//! client root-Timeline ceiling.
//!
//! The set is read once, when the Gateway's executor takes ownership of the
//! host. The erasure store identity is write-once and only
//! `provision-local-erasure` writes it, whose unit conflicts with `serve`,
//! so the set cannot change while the Gateway serves.

use pos_core::{ErasureHostErrorV1, TimelineId};
use pos_runtime::ErasureExecutionHostV1;

use crate::local_principal::{
    local_principal_authority_timeline, local_principal_consent_timeline,
};

/// The host Timelines of one store.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct HostTimelinesV1 {
    /// The Erasure Host Timeline, once the store records its identity.
    erasure_host: Option<TimelineId>,
}

impl HostTimelinesV1 {
    /// The host Timelines of a store whose Erasure Host Timeline is
    /// `erasure_host`, if it records one.
    pub(crate) const fn new(erasure_host: Option<TimelineId>) -> Self {
        Self { erasure_host }
    }

    /// The host Timelines of the store `host` owns.
    ///
    /// # Errors
    /// Returns the payload-free host error of an unreadable erasure store
    /// identity.
    pub(crate) fn of_host(host: &mut ErasureExecutionHostV1) -> Result<Self, ErasureHostErrorV1> {
        host.read_sender()
            .and_then(|mut reads| reads.local_erasure_host_timeline())
            .map(Self::new)
    }

    /// Every host Timeline identity, each once.
    pub(crate) fn roots(self) -> Vec<TimelineId> {
        [
            local_principal_consent_timeline(),
            local_principal_authority_timeline(),
        ]
        .into_iter()
        .chain(self.erasure_host)
        .collect()
    }

    /// Whether `timeline` is a host Timeline.
    pub(crate) fn contains(self, timeline: TimelineId) -> bool {
        timeline == local_principal_consent_timeline()
            || timeline == local_principal_authority_timeline()
            || self.erasure_host == Some(timeline)
    }
}
