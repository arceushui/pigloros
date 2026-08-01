//! Core-owned values for admitting V1 `geo.location` evidence.
//!
//! A gateway supplies one already-minimized input value. Core turns it into an
//! opaque request, and only a storage adapter with the dedicated capability
//! may admit it. Generic event storage has no geographic-admission API.

use crate::{CanonicalBytes, CoreError, EntityId, EventId, Hash, Seq, TimelineId};

/// Already-minimized gateway input for one V1 geographic admission attempt.
///
/// Its fields are deliberately private: callers can create it, but cannot
/// mutate a request after core has captured the admission state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GeoLocationAdmissionInputV1 {
    timeline: TimelineId,
    entity: EntityId,
    payload: CanonicalBytes,
    binding_revision: u64,
    consent_identity: [u8; 32],
    consent_revision: u64,
    consent_hash: [u8; 32],
    policy_version: u32,
    withdrawn: bool,
    admission_epoch: u64,
    intent: [u8; 32],
    fingerprint: [u8; 32],
}

impl GeoLocationAdmissionInputV1 {
    /// Create the bounded input captured by the gateway before storage begins.
    #[must_use]
    pub fn new(
        timeline: TimelineId,
        entity: EntityId,
        payload: CanonicalBytes,
        binding_revision: u64,
        consent: ([u8; 32], u64, [u8; 32]),
        policy: (u32, bool, u64),
        dedup: ([u8; 32], [u8; 32]),
    ) -> Self {
        Self {
            timeline,
            entity,
            payload,
            binding_revision,
            consent_identity: consent.0,
            consent_revision: consent.1,
            consent_hash: consent.2,
            policy_version: policy.0,
            withdrawn: policy.1,
            admission_epoch: policy.2,
            intent: dedup.0,
            fingerprint: dedup.1,
        }
    }
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
    pub const fn identity(&self) -> &[u8; 32] {
        &self.identity
    }

    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    #[must_use]
    pub const fn hash(&self) -> &[u8; 32] {
        &self.hash
    }

    #[must_use]
    pub const fn policy_version(&self) -> u32 {
        self.policy_version
    }

    #[must_use]
    pub const fn withdrawn(&self) -> bool {
        self.withdrawn
    }

    #[must_use]
    pub const fn admission_epoch(&self) -> u64 {
        self.admission_epoch
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

/// Current trusted authorization state for one `(TimelineId, EntityId)` pair.
///
/// This operational state is not retained with accepted evidence. A backend
/// compares it to the request snapshot before deduplication and again while
/// holding its commit fence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GeoLocationAdmissionFenceV1 {
    binding_revision: u64,
    consent: GeoLocationConsentStateV1,
}

impl GeoLocationAdmissionFenceV1 {
    /// Create current core-owned state for a trusted composition root.
    #[must_use]
    pub fn new(
        binding_revision: u64,
        consent: ([u8; 32], u64, [u8; 32]),
        policy: (u32, bool, u64),
    ) -> Self {
        Self {
            binding_revision,
            consent: GeoLocationConsentStateV1 {
                identity: consent.0,
                revision: consent.1,
                hash: consent.2,
                policy_version: policy.0,
                withdrawn: policy.1,
                admission_epoch: policy.2,
            },
        }
    }

    /// Return whether the immutable request still matches current state.
    #[must_use]
    pub fn permits(&self, request: &GeoLocationAdmissionRequestV1) -> bool {
        let snapshot = request.snapshot();
        self.consent.admission_epoch != 0
            && !self.consent.withdrawn
            && self.binding_revision == snapshot.binding_revision
            && self.consent == snapshot.consent
    }

    #[must_use]
    pub const fn binding_revision(&self) -> u64 {
        self.binding_revision
    }

    #[must_use]
    pub const fn consent(&self) -> &GeoLocationConsentStateV1 {
        &self.consent
    }
}

impl GeoLocationAdmissionSnapshotV1 {
    #[must_use]
    pub const fn timeline(&self) -> TimelineId {
        self.timeline
    }

    #[must_use]
    pub const fn entity(&self) -> EntityId {
        self.entity
    }

    #[must_use]
    pub const fn binding_revision(&self) -> u64 {
        self.binding_revision
    }

    #[must_use]
    pub const fn consent(&self) -> &GeoLocationConsentStateV1 {
        &self.consent
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

    /// Decode the canonical snapshot form retained by a V1 admission link.
    ///
    /// # Errors
    /// Returns a serialization error when the retained bytes are not a valid
    /// V1 admission snapshot.
    pub fn from_deterministic_cbor(bytes: &CanonicalBytes) -> Result<Self, CoreError> {
        let decoded: (
            TimelineId,
            EntityId,
            u64,
            [u8; 32],
            u64,
            [u8; 32],
            u32,
            bool,
            u64,
        ) = match ciborium::from_reader(bytes.as_slice()) {
            Ok(decoded) => decoded,
            Err(error) => return Err(CoreError::Serialization(error.to_string())),
        };
        Ok(Self {
            timeline: decoded.0,
            entity: decoded.1,
            binding_revision: decoded.2,
            consent: GeoLocationConsentStateV1 {
                identity: decoded.3,
                revision: decoded.4,
                hash: decoded.5,
                policy_version: decoded.6,
                withdrawn: decoded.7,
                admission_epoch: decoded.8,
            },
        })
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

    /// Return the canonical immutable snapshot bytes retained by this link.
    #[must_use]
    pub const fn snapshot_cbor(&self) -> &CanonicalBytes {
        &self.snapshot_cbor
    }
}

/// Opaque owner-keyed canonical intent used for retry comparison.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GeoLocationAdmissionIntentV1([u8; 32]);

impl GeoLocationAdmissionIntentV1 {
    /// Reconstitute a retained opaque owner-keyed intent from backend storage.
    #[must_use]
    pub const fn from_owner_keyed_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn as_owner_keyed_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Opaque owner-keyed fingerprint used as the retained deduplication key.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub struct GeoLocationAdmissionFingerprintV1([u8; 32]);

impl GeoLocationAdmissionFingerprintV1 {
    #[must_use]
    pub const fn as_owner_keyed_bytes(&self) -> &[u8; 32] {
        &self.0
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
    /// Convert already-minimized gateway input into an immutable core request.
    #[must_use]
    pub fn from_input(input: GeoLocationAdmissionInputV1) -> Self {
        let GeoLocationAdmissionInputV1 {
            timeline,
            entity,
            payload,
            binding_revision,
            consent_identity,
            consent_revision,
            consent_hash,
            policy_version,
            withdrawn,
            admission_epoch,
            intent,
            fingerprint,
        } = input;
        Self {
            timeline,
            entity,
            payload,
            snapshot: GeoLocationAdmissionSnapshotV1 {
                timeline,
                entity,
                binding_revision,
                consent: GeoLocationConsentStateV1 {
                    identity: consent_identity,
                    revision: consent_revision,
                    hash: consent_hash,
                    policy_version,
                    withdrawn,
                    admission_epoch,
                },
            },
            intent: GeoLocationAdmissionIntentV1(intent),
            fingerprint: GeoLocationAdmissionFingerprintV1(fingerprint),
        }
    }

    #[must_use]
    pub const fn timeline(&self) -> TimelineId {
        self.timeline
    }

    #[must_use]
    pub const fn entity(&self) -> EntityId {
        self.entity
    }

    #[must_use]
    pub const fn payload(&self) -> &CanonicalBytes {
        &self.payload
    }

    #[must_use]
    pub const fn snapshot(&self) -> &GeoLocationAdmissionSnapshotV1 {
        &self.snapshot
    }

    #[must_use]
    pub const fn intent(&self) -> GeoLocationAdmissionIntentV1 {
        self.intent
    }

    #[must_use]
    pub const fn fingerprint(&self) -> GeoLocationAdmissionFingerprintV1 {
        self.fingerprint
    }
}

/// Separate core-owned capability for one V1 geographic admission transaction.
///
/// Generic [`crate::EventStore`] APIs do not expose this trait, so ordinary
/// callers cannot use them to append protected geographic evidence.
pub trait GeoLocationAdmissionStore {
    /// Admit one already-minimized V1 location request atomically.
    ///
    /// # Errors
    /// Returns a bounded geographic-admission error when the commit fence or
    /// storage transaction cannot establish a definite outcome.
    fn admit_geo_location(
        &mut self,
        request: GeoLocationAdmissionRequestV1,
    ) -> Result<GeoLocationAdmissionOutcome, CoreError>;
}

/// Administrative capability for current, removable geographic admission state.
///
/// This trait is intentionally outside [`crate::EventStore`]. Only a trusted
/// composition root imports this module to install or replace an admission
/// fence; implementations must not mutate accepted Timeline evidence.
pub trait GeoLocationAdmissionAdmin {
    /// Install or replace current authorization state for one Timeline entity.
    ///
    /// # Errors
    /// Returns an error when the Timeline cannot be used as an admission key.
    fn set_geo_location_admission_fence(
        &mut self,
        timeline: TimelineId,
        entity: EntityId,
        fence: GeoLocationAdmissionFenceV1,
    ) -> Result<(), CoreError>;
}

/// Opaque evidence expected to be present in a V1 geographic replay record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GeoLocationReplayEvidenceV1 {
    timeline: TimelineId,
    event_id: EventId,
    event_seq: Seq,
    event_payload_hash: Hash,
    snapshot_hash: Hash,
}

impl GeoLocationReplayEvidenceV1 {
    /// Create verification-only evidence from already-durable replay metadata.
    #[must_use]
    pub const fn new(
        timeline: TimelineId,
        event_id: EventId,
        event_seq: Seq,
        event_payload_hash: Hash,
        snapshot_hash: Hash,
    ) -> Self {
        Self {
            timeline,
            event_id,
            event_seq,
            event_payload_hash,
            snapshot_hash,
        }
    }

    #[must_use]
    pub const fn timeline(&self) -> TimelineId {
        self.timeline
    }

    #[must_use]
    pub const fn event_id(&self) -> EventId {
        self.event_id
    }

    #[must_use]
    pub const fn event_seq(&self) -> Seq {
        self.event_seq
    }

    #[must_use]
    pub const fn event_payload_hash(&self) -> Hash {
        self.event_payload_hash
    }

    #[must_use]
    pub const fn snapshot_hash(&self) -> Hash {
        self.snapshot_hash
    }
}

/// Verification-only port for durable V1 geographic admission linkage.
///
/// Implementations return no protected Event, payload, or snapshot data.
pub trait GeoLocationReplayVerifier: Send {
    /// Verify one durable V1 Event-to-snapshot link from persisted state only.
    ///
    /// # Errors
    /// Returns [`CoreError::GeographicAdmissionValidationFailed`] on a broken
    /// Event/snapshot/link relationship.
    fn verify_v1_event_snapshot_link(
        &self,
        evidence: GeoLocationReplayEvidenceV1,
    ) -> Result<(), CoreError>;
}

/// The definite or explicitly indeterminate result of one admission attempt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GeoLocationAdmissionOutcome {
    kind: GeoLocationAdmissionOutcomeKind,
    event_id: Option<EventId>,
    event_seq: Option<Seq>,
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
    pub const fn accepted(event_id: EventId, event_seq: Seq) -> Self {
        Self {
            kind: GeoLocationAdmissionOutcomeKind::Accepted,
            event_id: Some(event_id),
            event_seq: Some(event_seq),
        }
    }

    #[must_use]
    pub fn classify_retained_intent(
        requested: GeoLocationAdmissionIntentV1,
        retained: GeoLocationAdmissionIntentV1,
        event_id: EventId,
    ) -> Self {
        if requested == retained {
            Self {
                kind: GeoLocationAdmissionOutcomeKind::Duplicate,
                event_id: Some(event_id),
                event_seq: None,
            }
        } else {
            Self {
                kind: GeoLocationAdmissionOutcomeKind::Conflict,
                event_id: None,
                event_seq: None,
            }
        }
    }

    #[must_use]
    pub const fn unavailable() -> Self {
        Self {
            kind: GeoLocationAdmissionOutcomeKind::Unavailable,
            event_id: None,
            event_seq: None,
        }
    }

    #[must_use]
    pub const fn outcome_unknown() -> Self {
        Self {
            kind: GeoLocationAdmissionOutcomeKind::OutcomeUnknown,
            event_id: None,
            event_seq: None,
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
    pub const fn event_seq(&self) -> Option<Seq> {
        self.event_seq
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

    fn input(timeline: TimelineId) -> GeoLocationAdmissionInputV1 {
        GeoLocationAdmissionInputV1::new(
            timeline,
            EntityId::new(),
            CanonicalBytes::from_static(b"existing-v1-geo-location-payload"),
            7,
            ([1; 32], 8, [2; 32]),
            (1, false, 9),
            ([4; 32], [5; 32]),
        )
    }

    fn request(timeline: TimelineId) -> GeoLocationAdmissionRequestV1 {
        GeoLocationAdmissionRequestV1::from_input(input(timeline))
    }

    struct CoreAdmissionProbe;

    impl GeoLocationAdmissionStore for CoreAdmissionProbe {
        fn admit_geo_location(
            &mut self,
            _request: GeoLocationAdmissionRequestV1,
        ) -> Result<GeoLocationAdmissionOutcome, CoreError> {
            Err(CoreError::GeographicAdmissionUnavailable)
        }
    }

    #[test]
    fn exposes_a_separate_core_admission_capability() {
        fn requires_capability<T: GeoLocationAdmissionStore>() {}

        requires_capability::<CoreAdmissionProbe>();
    }

    #[test]
    fn gateway_can_build_an_opaque_request_without_core_authority() {
        let timeline = TimelineId::new();
        let entity = EntityId::new();
        let input = GeoLocationAdmissionInputV1::new(
            timeline,
            entity,
            CanonicalBytes::from_static(b"existing-v1-geo-location-payload"),
            7,
            ([1; 32], 8, [2; 32]),
            (1, false, 9),
            ([4; 32], [5; 32]),
        );

        let request = GeoLocationAdmissionRequestV1::from_input(input);

        assert_eq!(request.timeline(), timeline);
        assert_eq!(request.entity(), entity);
        assert_eq!(
            request.payload().as_slice(),
            b"existing-v1-geo-location-payload"
        );
        assert_eq!(request.snapshot().binding_revision(), 7);
        assert_eq!(request.intent().as_owner_keyed_bytes(), &[4; 32]);
        assert_eq!(request.fingerprint().as_owner_keyed_bytes(), &[5; 32]);
    }

    #[test]
    fn canonical_link_validation_rejects_changed_admission_state() {
        let timeline = TimelineId::new();
        let request = request(timeline);
        let snapshot = request.snapshot().clone();
        let event_id = EventId::new();
        let event_seq = Seq::from_u64(3);
        let link =
            GeoLocationAdmissionLinkV1::for_snapshot(timeline, event_id, event_seq, &snapshot);

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
    fn canonical_snapshot_round_trip_retains_identity_and_consent_state() {
        let request = GeoLocationAdmissionRequestV1::from_input(input(TimelineId::new()));
        let snapshot = request.snapshot();
        let decoded =
            GeoLocationAdmissionSnapshotV1::from_deterministic_cbor(&snapshot.deterministic_cbor())
                .unwrap();

        assert_eq!(decoded, *snapshot);
    }

    #[test]
    fn canonical_snapshot_decode_rejects_malformed_bytes() {
        let result = GeoLocationAdmissionSnapshotV1::from_deterministic_cbor(
            &CanonicalBytes::from_static(b"not-canonical-cbor"),
        );

        assert!(result
            .unwrap_err()
            .to_string()
            .contains("serialization error"));
    }

    #[test]
    fn owner_keyed_retry_classification_distinguishes_duplicate_conflict_and_unknown() {
        let timeline = TimelineId::new();
        let request = request(timeline);
        let event_id = EventId::new();

        let accepted = GeoLocationAdmissionOutcome::accepted(event_id, Seq::from_u64(3));
        assert!(accepted.is_accepted());
        assert_eq!(accepted.event_id(), Some(event_id));
        assert_eq!(accepted.event_seq(), Some(Seq::from_u64(3)));
        assert!(accepted.error().is_none());

        let duplicate = GeoLocationAdmissionOutcome::classify_retained_intent(
            request.intent(),
            request.intent(),
            event_id,
        );
        assert!(duplicate.is_duplicate());
        assert_eq!(duplicate.event_id(), Some(event_id));
        assert!(duplicate.error().is_none());

        let conflict = GeoLocationAdmissionOutcome::classify_retained_intent(
            request.intent(),
            GeoLocationAdmissionIntentV1([6; 32]),
            event_id,
        );
        assert!(conflict.is_conflict());
        assert_eq!(conflict.event_id(), None);
        assert!(conflict.error().is_none());

        let unavailable = GeoLocationAdmissionOutcome::unavailable();
        assert!(unavailable.is_unavailable());
        assert!(unavailable
            .error()
            .expect("unavailable outcome has an explicit error category")
            .to_string()
            .contains("unavailable"));
        assert_eq!(unavailable.event_id(), None);

        let unknown = GeoLocationAdmissionOutcome::outcome_unknown();
        assert!(unknown.is_outcome_unknown());
        assert!(unknown
            .error()
            .expect("unknown outcome has an explicit error category")
            .to_string()
            .contains("outcome unknown"));
        assert_eq!(unknown.event_id(), None);
    }
}
