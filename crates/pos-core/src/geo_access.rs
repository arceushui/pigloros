//! Core reservation for geographic evidence.
//!
//! V1 reserves the geographic Event kinds and rejects them from every generic
//! admission path. It deliberately has no geographic admission or audit API:
//! ADR-034 requires a future snapshot-linkage transaction before either can be
//! exposed safely.

use crate::event::Kind;

/// Accepted V1 degree-grid geographic evidence.
pub const GEOGRAPHIC_EVENT_TYPE: &str = "geo.location";

/// Reserved future geographic-cell evidence.
///
/// ADR-034 reserves this name now so an untrusted Plugin cannot create an
/// alternate sensitive-event route before its enclosing Event contract exists.
pub const GEOGRAPHIC_CELL_EVENT_TYPE: &str = "geo.cell";

/// Returns whether an Event kind is protected geographic evidence.
#[must_use]
pub fn is_geographic_event_type(kind: &Kind) -> bool {
    matches!(
        kind.as_str(),
        GEOGRAPHIC_EVENT_TYPE | GEOGRAPHIC_CELL_EVENT_TYPE
    )
}
