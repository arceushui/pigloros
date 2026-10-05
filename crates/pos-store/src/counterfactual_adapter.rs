//! Pieces shared by the Memory and `SQLite` ADR-064 counterfactual storage
//! adapters.
//!
//! The adapter seal is crate-private and never re-exported: only the two
//! adapters in this crate mint counterfactual commit evidence.

use pos_core::{CoreError, CounterfactualAdapterSealV1, CounterfactualStoreErrorV1};

/// The seal both adapters build receipts and committed Tick outcomes with.
pub(super) const COUNTERFACTUAL_SEAL: CounterfactualAdapterSealV1 =
    CounterfactualAdapterSealV1::for_adapter();

/// Map a backend failure onto the closed port errors: a missing Timeline is
/// `ForkNotFound`, a write whose commit may or may not have landed is
/// `OutcomeUnknown`, and every other backend failure is `StorageFailure`,
/// which committed nothing.
pub(super) const fn counterfactual_port_error(error: &CoreError) -> CounterfactualStoreErrorV1 {
    match error {
        CoreError::TimelineNotFound(_) => CounterfactualStoreErrorV1::ForkNotFound,
        CoreError::StorageOutcomeUnknown(_) => CounterfactualStoreErrorV1::OutcomeUnknown,
        _ => CounterfactualStoreErrorV1::StorageFailure,
    }
}

#[cfg(test)]
mod tests {
    use pos_core::TimelineId;

    use super::*;

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn backend_failures_map_onto_the_closed_port_errors() {
        assert_eq!(
            counterfactual_port_error(&CoreError::TimelineNotFound(TimelineId::new())),
            CounterfactualStoreErrorV1::ForkNotFound
        );
        assert_eq!(
            counterfactual_port_error(&CoreError::StorageOutcomeUnknown(String::new())),
            CounterfactualStoreErrorV1::OutcomeUnknown
        );
        assert_eq!(
            counterfactual_port_error(&CoreError::Storage(String::new())),
            CounterfactualStoreErrorV1::StorageFailure
        );
        assert_eq!(
            counterfactual_port_error(&CoreError::ErasureContainmentUnavailable),
            CounterfactualStoreErrorV1::StorageFailure
        );
    }
}
