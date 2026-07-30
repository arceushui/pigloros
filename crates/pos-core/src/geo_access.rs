//! Core-owned access boundary for geographic evidence.

use crate::{
    event::Kind,
    ids::{EventId, TimelineId},
    store::{EventReadBounds, GeographicEvidenceStore, SeqRange},
    CoreError,
};

/// The only protected V1 geographic Event type.
pub const GEOGRAPHIC_EVENT_TYPE: &str = "geo.location";

/// Returns whether an Event kind is protected geographic evidence.
#[must_use]
pub fn is_geographic_event_type(kind: &Kind) -> bool {
    kind.as_str() == GEOGRAPHIC_EVENT_TYPE
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

/// A projector deliberately reveals no geographic evidence to its caller.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DisclosureDecision {
    Withheld,
}

/// Evidence that one bounded geographic inspection was performed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GeographicAuditRecord {
    pub timeline_id: TimelineId,
    pub event_id: EventId,
}

/// Core-owned privileged reader for geographic evidence.
pub struct CoreGeographicVisibilityProjector {
    reader: GeoEvidenceReader,
}

impl CoreGeographicVisibilityProjector {
    #[must_use]
    pub const fn new() -> Self {
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

    /// Confirm that one protected Event was present in a bounded inspection.
    ///
    /// # Errors
    /// Propagates repository, bound, and integrity failures. A missing Event
    /// is reported as `TimelineNotFound` so it reveals no evidence metadata.
    pub fn audit(
        &self,
        store: &dyn GeographicEvidenceStore,
        timeline: TimelineId,
        event_id: EventId,
    ) -> Result<GeographicAuditRecord, CoreError> {
        self.audit_bounded(store, timeline, event_id, default_bounds())
    }

    /// Confirm that one protected Event was present in an explicitly bounded inspection.
    ///
    /// # Errors
    /// Propagates repository, bound, and integrity failures. A missing Event
    /// is reported as `TimelineNotFound` so it reveals no evidence metadata.
    pub fn audit_bounded(
        &self,
        store: &dyn GeographicEvidenceStore,
        timeline: TimelineId,
        event_id: EventId,
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

impl Default for CoreGeographicVisibilityProjector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        clock::{Seq, WallTime},
        crypto::Hash,
        event::{CanonicalBytes, Event, SchemaVersion},
        ids::EntityId,
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
        assert!(!is_geographic_event_type(&Kind::new("geo.cell")));
        assert!(matches!(
            CoreGeographicVisibilityProjector::default(),
            CoreGeographicVisibilityProjector { .. }
        ));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn projector_withholds_evidence_and_audits_a_bounded_match() {
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
        assert!(CoreGeographicVisibilityProjector::new()
            .project_bounded(&store, TimelineId::new(), bounds())
            .is_err());
    }
}
