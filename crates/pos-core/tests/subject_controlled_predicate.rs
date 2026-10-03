//! Predicate parity for subject-controlled Event types (ADR-021 Revision 4
//! Decision 2, #494).
//!
//! The table pins the exact sets of the shared predicates, so a change to
//! either one fails here rather than silently moving the Gateway Event-read
//! filter, the runtime's Driver visibility or the experiment's public
//! filter.

use pos_core::{
    is_consent_event_type, is_consent_sensitive_event_type, is_geographic_event_type,
    is_subject_controlled_event_type, Kind, HOST_CONSENT_CLOSED_EVENT_TYPE,
};

/// One Event type and whether it is consent-sensitive and subject-controlled.
const TABLE: [(&str, bool, bool); 22] = [
    ("persona.prediction", true, true),
    ("persona.outcome.v1", true, true),
    ("geo.location", true, true),
    ("geo.cell", true, true),
    ("geo.location.v1", true, true),
    ("location.coordinate.v1", true, true),
    ("model.fit.v1", true, true),
    ("export.bundle.v1", true, true),
    ("timeline.fork.requested", true, true),
    ("timeline.fork.v1", true, true),
    ("retention.extended", true, true),
    ("consent.granted.v1", false, true),
    ("consent.revoked.v1", false, true),
    ("consent.other", false, true),
    (HOST_CONSENT_CLOSED_EVENT_TYPE, false, false),
    ("eval.prediction", false, false),
    ("timeline.forked", false, false),
    ("retention", false, false),
    ("persona", false, false),
    ("consentx.granted", false, false),
    ("world.observation.v1", false, false),
    ("ordinary.event", false, false),
];

#[test]
fn the_shared_predicates_pin_the_exact_sets() {
    for (event_type, sensitive, subject_controlled) in TABLE {
        let kind = Kind::new(event_type);
        assert_eq!(
            is_consent_sensitive_event_type(&kind),
            sensitive,
            "{event_type}"
        );
        assert_eq!(
            is_subject_controlled_event_type(&kind),
            subject_controlled,
            "{event_type}"
        );
    }
}

#[test]
fn subject_controlled_is_consent_sensitive_or_consent() {
    for (event_type, _, _) in TABLE {
        let kind = Kind::new(event_type);
        assert_eq!(
            is_subject_controlled_event_type(&kind),
            is_consent_sensitive_event_type(&kind) || is_consent_event_type(&kind),
            "{event_type}"
        );
    }
}

#[test]
fn every_geographic_type_is_consent_sensitive() {
    for event_type in ["geo.location", "geo.cell"] {
        let kind = Kind::new(event_type);
        assert!(is_geographic_event_type(&kind), "{event_type}");
        assert!(is_consent_sensitive_event_type(&kind), "{event_type}");
    }
}
