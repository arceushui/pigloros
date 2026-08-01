//! Core-private values for admitting V1 `geo.location` evidence.
//!
//! The request cannot carry writer-generated Event metadata. A storage adapter
//! receives only a core-issued request and must verify the immutable admission
//! snapshot/link before it can treat a retained admission as a duplicate.

use crate::{CanonicalBytes, CoreError, EntityId, EventId, Seq, TimelineId};

/// Unforgeable authority required to issue geographic admission values.
///
/// The core creates this capability internally. Its private field prevents a
/// Plugin or a generic `EventStore` caller from manufacturing admission values.
pub struct GeoLocationAdmissionAuthorityV1 {
    _core_private: (),
}

/// Immutable consent state captured at the geographic admission fence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GeoLocationConsentStateV1 {
    identity: [u8; 32],
    revision: u64,
    hash: [u8; 32],
    policy_version: u32,
    withdrawn: bool,
    admission_epoch: u64,
}

impl GeoLocationConsentStateV1 {
    #[must_use]
    pub const fn from_verified_state(
        _authority: &GeoLocationAdmissionAuthorityV1,
        identity: [u8; 32],
        revision: u64,
        hash: [u8; 32],
        policy_version: u32,
        withdrawn: bool,
        admission_epoch: u64,
    ) -> Self {
        Self {
            identity,
            revision,
            hash,
            policy_version,
            withdrawn,
            admission_epoch,
        }
    }
}

/// Immutable authorization state captured at the geographic admission fence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GeoLocationAdmissionSnapshotV1 {
    timeline: TimelineId,
    entity: EntityId,
    binding_revision: u64,
    consent: GeoLocationConsentStateV1,
}

impl GeoLocationAdmissionSnapshotV1 {
    #[must_use]
    pub const fn from_verified_state(
        _authority: &GeoLocationAdmissionAuthorityV1,
        timeline: TimelineId,
        entity: EntityId,
        binding_revision: u64,
        consent: GeoLocationConsentStateV1,
    ) -> Self {
        Self {
            timeline,
            entity,
            binding_revision,
            consent,
        }
    }

    fn deterministic_cbor(&self) -> CanonicalBytes {
        let mut bytes = Vec::new();
        ciborium::into_writer(
            &(
                self.timeline,
                self.entity,
                self.binding_revision,
                self.consent.identity,
                self.consent.revision,
                self.consent.hash,
                self.consent.policy_version,
                self.consent.withdrawn,
                self.consent.admission_epoch,
            ),
            &mut bytes,
        )
        .expect("writing deterministic CBOR to a Vec cannot fail");
        CanonicalBytes::from_vec(bytes)
    }
}

/// Immutable sidecar linking a geographic Event to its admission snapshot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GeoLocationAdmissionLinkV1 {
    timeline: TimelineId,
    event_id: EventId,
    event_seq: Seq,
    snapshot_cbor: CanonicalBytes,
}

impl GeoLocationAdmissionLinkV1 {
    #[must_use]
    pub fn for_snapshot(
        _authority: &GeoLocationAdmissionAuthorityV1,
        timeline: TimelineId,
        event_id: EventId,
        event_seq: Seq,
        snapshot: &GeoLocationAdmissionSnapshotV1,
    ) -> Self {
        Self {
            timeline,
            event_id,
            event_seq,
            snapshot_cbor: snapshot.deterministic_cbor(),
        }
    }

    /// Verify this retained link against its Event metadata and immutable snapshot.
    ///
    /// # Errors
    /// Returns [`CoreError::GeographicAdmissionValidationFailed`] when any
    /// retained admission value differs from the original commit fence.
    pub fn validate_for(
        &self,
        snapshot: &GeoLocationAdmissionSnapshotV1,
        timeline: TimelineId,
        event_id: EventId,
        event_seq: Seq,
    ) -> Result<(), CoreError> {
        if self.timeline == timeline
            && self.event_id == event_id
            && self.event_seq == event_seq
            && self.snapshot_cbor == snapshot.deterministic_cbor()
        {
            Ok(())
        } else {
            Err(CoreError::GeographicAdmissionValidationFailed)
        }
    }
}

/// Opaque owner-keyed canonical intent used for retry comparison.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GeoLocationAdmissionIntentV1([u8; 32]);

impl GeoLocationAdmissionIntentV1 {
    #[must_use]
    pub const fn from_owner_keyed_bytes(
        _authority: &GeoLocationAdmissionAuthorityV1,
        bytes: [u8; 32],
    ) -> Self {
        Self(bytes)
    }
}

/// Opaque owner-keyed fingerprint used as the retained deduplication key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GeoLocationAdmissionFingerprintV1([u8; 32]);

impl GeoLocationAdmissionFingerprintV1 {
    #[must_use]
    pub const fn from_owner_keyed_bytes(
        _authority: &GeoLocationAdmissionAuthorityV1,
        bytes: [u8; 32],
    ) -> Self {
        Self(bytes)
    }
}

/// A core-issued request for one V1 `geo.location` admission transaction.
///
/// It contains no caller-provided Event ID, sequence, or wall time; the
/// storage transaction owns those generated metadata values.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GeoLocationAdmissionRequestV1 {
    timeline: TimelineId,
    entity: EntityId,
    payload: CanonicalBytes,
    snapshot: GeoLocationAdmissionSnapshotV1,
    intent: GeoLocationAdmissionIntentV1,
    fingerprint: GeoLocationAdmissionFingerprintV1,
}

impl GeoLocationAdmissionRequestV1 {
    #[must_use]
    pub fn new(
        _authority: &GeoLocationAdmissionAuthorityV1,
        timeline: TimelineId,
        entity: EntityId,
        payload: CanonicalBytes,
        snapshot: GeoLocationAdmissionSnapshotV1,
        intent: GeoLocationAdmissionIntentV1,
        fingerprint: GeoLocationAdmissionFingerprintV1,
    ) -> Self {
        Self {
            timeline,
            entity,
            payload,
            snapshot,
            intent,
            fingerprint,
        }
    }
}

/// The definite or explicitly indeterminate result of one admission attempt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GeoLocationAdmissionOutcome {
    kind: GeoLocationAdmissionOutcomeKind,
    event_id: Option<EventId>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum GeoLocationAdmissionOutcomeKind {
    Accepted,
    Duplicate,
    Conflict,
    Unavailable,
    OutcomeUnknown,
}

impl GeoLocationAdmissionOutcome {
    #[must_use]
    pub const fn accepted(_authority: &GeoLocationAdmissionAuthorityV1, event_id: EventId) -> Self {
        Self {
            kind: GeoLocationAdmissionOutcomeKind::Accepted,
            event_id: Some(event_id),
        }
    }

    #[must_use]
    pub fn classify_retained_intent(
        _authority: &GeoLocationAdmissionAuthorityV1,
        requested: GeoLocationAdmissionIntentV1,
        retained: GeoLocationAdmissionIntentV1,
        event_id: EventId,
    ) -> Self {
        if requested == retained {
            Self {
                kind: GeoLocationAdmissionOutcomeKind::Duplicate,
                event_id: Some(event_id),
            }
        } else {
            Self {
                kind: GeoLocationAdmissionOutcomeKind::Conflict,
                event_id: None,
            }
        }
    }

    #[must_use]
    pub const fn unavailable(_authority: &GeoLocationAdmissionAuthorityV1) -> Self {
        Self {
            kind: GeoLocationAdmissionOutcomeKind::Unavailable,
            event_id: None,
        }
    }

    #[must_use]
    pub const fn outcome_unknown(_authority: &GeoLocationAdmissionAuthorityV1) -> Self {
        Self {
            kind: GeoLocationAdmissionOutcomeKind::OutcomeUnknown,
            event_id: None,
        }
    }

    #[must_use]
    pub fn is_accepted(&self) -> bool {
        self.kind == GeoLocationAdmissionOutcomeKind::Accepted
    }

    #[must_use]
    pub fn is_duplicate(&self) -> bool {
        self.kind == GeoLocationAdmissionOutcomeKind::Duplicate
    }

    #[must_use]
    pub fn is_conflict(&self) -> bool {
        self.kind == GeoLocationAdmissionOutcomeKind::Conflict
    }

    #[must_use]
    pub fn is_unavailable(&self) -> bool {
        self.kind == GeoLocationAdmissionOutcomeKind::Unavailable
    }

    #[must_use]
    pub fn is_outcome_unknown(&self) -> bool {
        self.kind == GeoLocationAdmissionOutcomeKind::OutcomeUnknown
    }

    #[must_use]
    pub const fn event_id(&self) -> Option<EventId> {
        self.event_id
    }

    #[must_use]
    pub fn error(&self) -> Option<CoreError> {
        match self.kind {
            GeoLocationAdmissionOutcomeKind::Accepted
            | GeoLocationAdmissionOutcomeKind::Duplicate
            | GeoLocationAdmissionOutcomeKind::Conflict => None,
            GeoLocationAdmissionOutcomeKind::Unavailable => {
                Some(CoreError::GeographicAdmissionUnavailable)
            }
            GeoLocationAdmissionOutcomeKind::OutcomeUnknown => {
                Some(CoreError::GeographicAdmissionOutcomeUnknown)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{EntityId, EventId, Seq, TimelineId};

    fn authority() -> GeoLocationAdmissionAuthorityV1 {
        GeoLocationAdmissionAuthorityV1 { _core_private: () }
    }

    fn snapshot(
        authority: &GeoLocationAdmissionAuthorityV1,
        timeline: TimelineId,
    ) -> GeoLocationAdmissionSnapshotV1 {
        let consent = GeoLocationConsentStateV1::from_verified_state(
            authority, [1; 32], 8, [2; 32], 1, false, 9,
        );
        GeoLocationAdmissionSnapshotV1::from_verified_state(
            authority,
            timeline,
            EntityId::new(),
            7,
            consent,
        )
    }

    #[test]
    fn canonical_link_validation_rejects_changed_admission_state() {
        let authority = authority();
        let timeline = TimelineId::new();
        let snapshot = snapshot(&authority, timeline);
        let event_id = EventId::new();
        let event_seq = Seq::from_u64(3);
        let link = GeoLocationAdmissionLinkV1::for_snapshot(
            &authority, timeline, event_id, event_seq, &snapshot,
        );

        assert!(link
            .validate_for(&snapshot, timeline, event_id, event_seq)
            .is_ok());
        assert!(link
            .validate_for(&snapshot, TimelineId::new(), event_id, event_seq)
            .is_err());
        assert!(link
            .validate_for(&snapshot, timeline, event_id, Seq::from_u64(4))
            .is_err());

        let mut changed_consent_hash = snapshot.clone();
        changed_consent_hash.consent.hash = [3; 32];
        assert!(link
            .validate_for(&changed_consent_hash, timeline, event_id, event_seq)
            .is_err());

        let mut changed_policy_version = snapshot.clone();
        changed_policy_version.consent.policy_version = 2;
        assert!(link
            .validate_for(&changed_policy_version, timeline, event_id, event_seq)
            .is_err());

        let mut changed_epoch = snapshot;
        changed_epoch.consent.admission_epoch = 10;
        assert!(link
            .validate_for(&changed_epoch, timeline, event_id, event_seq)
            .is_err());
    }

    #[test]
    fn owner_keyed_retry_classification_distinguishes_duplicate_conflict_and_unknown() {
        let authority = authority();
        let timeline = TimelineId::new();
        let snapshot = snapshot(&authority, timeline);
        let expected_snapshot = snapshot.clone();
        let intent = GeoLocationAdmissionIntentV1::from_owner_keyed_bytes(&authority, [4; 32]);
        let fingerprint =
            GeoLocationAdmissionFingerprintV1::from_owner_keyed_bytes(&authority, [5; 32]);
        let entity = EntityId::new();
        let request = GeoLocationAdmissionRequestV1::new(
            &authority,
            timeline,
            entity,
            CanonicalBytes::from_static(b"existing-v1-geo-location-payload"),
            snapshot,
            intent,
            fingerprint,
        );
        assert_eq!(request.timeline, timeline);
        assert_eq!(request.entity, entity);
        assert_eq!(
            request.payload.as_slice(),
            b"existing-v1-geo-location-payload"
        );
        assert_eq!(request.snapshot, expected_snapshot);
        assert_eq!(request.fingerprint, fingerprint);
        let event_id = EventId::new();

        let accepted = GeoLocationAdmissionOutcome::accepted(&authority, event_id);
        assert!(accepted.is_accepted());
        assert_eq!(accepted.event_id(), Some(event_id));
        assert!(accepted.error().is_none());

        let duplicate = GeoLocationAdmissionOutcome::classify_retained_intent(
            &authority,
            request.intent,
            request.intent,
            event_id,
        );
        assert!(duplicate.is_duplicate());
        assert_eq!(duplicate.event_id(), Some(event_id));
        assert!(duplicate.error().is_none());

        let conflict = GeoLocationAdmissionOutcome::classify_retained_intent(
            &authority,
            request.intent,
            GeoLocationAdmissionIntentV1::from_owner_keyed_bytes(&authority, [6; 32]),
            event_id,
        );
        assert!(conflict.is_conflict());
        assert_eq!(conflict.event_id(), None);
        assert!(conflict.error().is_none());

        let unavailable = GeoLocationAdmissionOutcome::unavailable(&authority);
        assert!(unavailable.is_unavailable());
        assert!(unavailable
            .error()
            .expect("unavailable outcome has an explicit error category")
            .to_string()
            .contains("unavailable"));
        assert_eq!(unavailable.event_id(), None);

        let unknown = GeoLocationAdmissionOutcome::outcome_unknown(&authority);
        assert!(unknown.is_outcome_unknown());
        assert!(unknown
            .error()
            .expect("unknown outcome has an explicit error category")
            .to_string()
            .contains("outcome unknown"));
        assert_eq!(unknown.event_id(), None);
    }
}
