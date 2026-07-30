//! Core-owned access boundary for geographic evidence.

use crate::{
    event::Kind,
    ids::TimelineId,
    store::{EventReadBounds, GeographicEvidenceStore, SeqRange},
    CoreError,
};

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

/// Unforgeable authority accepted by the geographic repository seam.
///
/// It has no public constructor, so generic consumers cannot invoke that
/// seam directly.
pub struct GeoEvidenceReader {
    _private: (),
}

impl GeoEvidenceReader {
    pub(crate) const fn for_projector() -> Self {
        Self { _private: () }
    }
}

/// Unforgeable authority held by the disabled Core Geographic Admission seam.
///
/// The constructor is core-private. Until ADR-034's admission-snapshot and
/// atomic-linkage prerequisites exist, concrete stores intentionally decline
/// every admission through this capability.
pub struct GeoEvidenceWriter {
    _private: (),
}

impl GeoEvidenceWriter {
    #[allow(dead_code)]
    pub(crate) const fn for_admission() -> Self {
        Self { _private: () }
    }
}

/// A projector deliberately reveals no geographic evidence to its caller.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DisclosureDecision {
    Withheld,
}

/// Evidence that one core-authorized bounded geographic inspection was performed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GeographicAuditRecord {
    pub timeline_id: TimelineId,
    pub event_id: crate::EventId,
}

/// Core-owned privileged reader for geographic evidence.
pub struct CoreGeographicVisibilityProjector {
    reader: GeoEvidenceReader,
}

impl CoreGeographicVisibilityProjector {
    #[allow(dead_code)]
    #[must_use]
    pub(crate) const fn new() -> Self {
        Self {
            reader: GeoEvidenceReader::for_projector(),
        }
    }

    /// Inspect geographic evidence with the V1 work bounds while withholding it.
    ///
    /// # Errors
    /// Propagates repository, bound, and integrity failures; they are never
    /// converted into a successful withholding decision.
    pub fn project(
        &self,
        store: &dyn GeographicEvidenceStore,
        timeline: TimelineId,
    ) -> Result<DisclosureDecision, CoreError> {
        self.project_bounded(store, timeline, default_bounds())
    }

    /// Inspect bounded geographic evidence while withholding it from the caller.
    ///
    /// # Errors
    /// Propagates repository, bound, and integrity failures; they are never
    /// converted into a successful withholding decision.
    pub fn project_bounded(
        &self,
        store: &dyn GeographicEvidenceStore,
        timeline: TimelineId,
        bounds: EventReadBounds,
    ) -> Result<DisclosureDecision, CoreError> {
        store
            .read_geographic_evidence_bounded(&self.reader, timeline, SeqRange::all(), bounds)
            .map(|_| DisclosureDecision::Withheld)
    }

    /// Confirm that one protected Event was present in a core-authorized inspection.
    ///
    /// This existence check is intentionally available only through this
    /// core-constructed projector; callers outside `pos-core` cannot construct
    /// the capability.
    ///
    /// # Errors
    /// Returns an integrity, bound, or repository error. A missing Event is
    /// represented as [`CoreError::TimelineNotFound`] to avoid a distinct
    /// existence-oracle result.
    pub fn audit(
        &self,
        store: &dyn GeographicEvidenceStore,
        timeline: TimelineId,
        event_id: crate::EventId,
    ) -> Result<GeographicAuditRecord, CoreError> {
        self.audit_bounded(store, timeline, event_id, default_bounds())
    }

    /// Confirm one protected Event using explicit work bounds.
    ///
    /// # Errors
    /// See [`Self::audit`].
    pub fn audit_bounded(
        &self,
        store: &dyn GeographicEvidenceStore,
        timeline: TimelineId,
        event_id: crate::EventId,
        bounds: EventReadBounds,
    ) -> Result<GeographicAuditRecord, CoreError> {
        let evidence = store.read_geographic_evidence_bounded(
            &self.reader,
            timeline,
            SeqRange::all(),
            bounds,
        )?;
        if evidence.iter().any(|event| event.id == event_id) {
            Ok(GeographicAuditRecord {
                timeline_id: timeline,
                event_id,
            })
        } else {
            Err(CoreError::TimelineNotFound(timeline))
        }
    }
}

const fn default_bounds() -> EventReadBounds {
    EventReadBounds::new(1 << 20, 64 << 10, 64, 1024)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        clock::{Seq, WallTime},
        crypto::Hash,
        event::{CanonicalBytes, Event, SchemaVersion},
        ids::{EntityId, EventId},
    };

    struct FixtureStore {
        evidence: Vec<Event>,
        fails: bool,
    }

    impl GeographicEvidenceStore for FixtureStore {
        fn read_geographic_evidence_bounded(
            &self,
            _: &GeoEvidenceReader,
            _: TimelineId,
            _: SeqRange,
            _: EventReadBounds,
        ) -> Result<Vec<Event>, CoreError> {
            if self.fails {
                Err(CoreError::Storage("unavailable".to_owned()))
            } else {
                Ok(self.evidence.clone())
            }
        }

        fn append_geographic_evidence(
            &mut self,
            _: &GeoEvidenceWriter,
            _: TimelineId,
            event: Event,
        ) -> Result<(), CoreError> {
            self.evidence.push(event);
            Ok(())
        }
    }

    fn geographic_event() -> Event {
        Event {
            id: EventId::new(),
            entity: EntityId::new(),
            event_type: Kind::new(GEOGRAPHIC_EVENT_TYPE),
            payload: CanonicalBytes::from_static(b"protected"),
            wall_time: WallTime::from_micros(1),
            seq: Seq::from_u64(1),
            causation_id: None,
            correlation_id: None,
            schema_version: SchemaVersion::V1,
            signature: None,
            payload_hash: Hash::from_bytes([7; 32]),
        }
    }

    fn bounds() -> EventReadBounds {
        EventReadBounds::new(1024, 1024, 8, 8)
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn only_geo_location_is_protected() {
        assert!(is_geographic_event_type(&Kind::new(GEOGRAPHIC_EVENT_TYPE)));
        assert!(is_geographic_event_type(&Kind::new(
            GEOGRAPHIC_CELL_EVENT_TYPE
        )));
        assert!(matches!(
            CoreGeographicVisibilityProjector::new(),
            CoreGeographicVisibilityProjector { .. }
        ));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn projector_withholds_evidence() {
        let event = geographic_event();
        let store = FixtureStore {
            evidence: vec![event.clone()],
            fails: false,
        };
        let projector = CoreGeographicVisibilityProjector::new();
        let timeline = TimelineId::new();

        assert_eq!(
            projector
                .project_bounded(&store, timeline, bounds())
                .unwrap(),
            DisclosureDecision::Withheld
        );
        assert_eq!(
            projector
                .audit_bounded(&store, timeline, event.id, bounds())
                .unwrap(),
            GeographicAuditRecord {
                timeline_id: timeline,
                event_id: event.id,
            }
        );
        assert_eq!(
            projector.audit(&store, timeline, event.id).unwrap(),
            GeographicAuditRecord {
                timeline_id: timeline,
                event_id: event.id,
            }
        );
        assert!(projector
            .audit_bounded(&store, timeline, EventId::new(), bounds())
            .is_err());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn projector_fails_closed_when_the_repository_fails() {
        let store = FixtureStore {
            evidence: Vec::new(),
            fails: true,
        };
        let projector = CoreGeographicVisibilityProjector::new();
        let timeline = TimelineId::new();
        assert!(projector
            .project_bounded(&store, timeline, bounds())
            .is_err());
        assert!(projector
            .audit_bounded(&store, timeline, EventId::new(), bounds())
            .is_err());
    }
}
