//! Core values for the one V1 `OwnTracks` enrollment.

use crate::{
    geo_admission::{GeoLocationAdmissionInputV1, GeoLocationAdmissionRequestV1},
    owntracks_ingress::{OwnTracksIngressInputV1, PreparedOwnTracksIngressV1},
    CoreError, EntityId, GeoLocationAdmissionFenceV1, TimelineId,
};
use serde::{Deserialize, Serialize};

const OWNTRACKS_ENROLLMENT_SCHEMA_VERSION: u8 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum OwnTracksEnrollmentStatusV1 {
    Absent,
    Active,
    Revoked,
}

/// Bounded enrollment status for local administration and diagnostics.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OwnTracksEnrollmentStatusViewV1 {
    status: OwnTracksEnrollmentStatusV1,
    policy_version: Option<u32>,
}

impl OwnTracksEnrollmentStatusViewV1 {
    #[must_use]
    pub const fn status(&self) -> OwnTracksEnrollmentStatusV1 {
        self.status
    }

    #[must_use]
    pub const fn policy_version(&self) -> Option<u32> {
        self.policy_version
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OwnTracksEnrollmentRequestV1 {
    timeline: TimelineId,
    entity: EntityId,
    fence: GeoLocationAdmissionFenceV1,
    verifier: [u8; 32],
}

impl OwnTracksEnrollmentRequestV1 {
    #[must_use]
    pub const fn new(
        timeline: TimelineId,
        entity: EntityId,
        fence: GeoLocationAdmissionFenceV1,
        verifier: [u8; 32],
    ) -> Self {
        Self {
            timeline,
            entity,
            fence,
            verifier,
        }
    }

    #[must_use]
    pub const fn timeline(&self) -> TimelineId {
        self.timeline
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OwnTracksEnrollmentStateV1 {
    schema_version: u8,
    status: OwnTracksEnrollmentStatusV1,
    timeline: Option<TimelineId>,
    entity: Option<EntityId>,
    fence: Option<GeoLocationAdmissionFenceV1>,
    verifier: Option<[u8; 32]>,
}

/// Narrow storage capability for the one local `OwnTracks` enrollment.
pub trait OwnTracksEnrollmentStore {
    /// Pair the single local device and return its bounded resulting status.
    ///
    /// # Errors
    /// Returns an error when the active enrollment cannot be replaced safely.
    fn pair_owntracks_enrollment(
        &mut self,
        request: OwnTracksEnrollmentRequestV1,
    ) -> Result<OwnTracksEnrollmentStatusV1, CoreError>;

    /// Report bounded enrollment status without exposing its verifier.
    ///
    /// # Errors
    /// Returns a storage error when the enrollment state is unavailable.
    fn owntracks_enrollment_status(&self) -> Result<OwnTracksEnrollmentStatusViewV1, CoreError>;

    /// Replace the active pairing verifier and invalidate prior admission.
    ///
    /// # Errors
    /// Returns an error unless the enrollment is active and durable replacement succeeds.
    fn rotate_owntracks_enrollment_verifier(
        &mut self,
        verifier: [u8; 32],
    ) -> Result<OwnTracksEnrollmentStatusV1, CoreError>;

    /// Revoke the active enrollment and invalidate prior admission.
    ///
    /// # Errors
    /// Returns an error unless the enrollment is active and durable replacement succeeds.
    fn revoke_owntracks_enrollment(&mut self) -> Result<OwnTracksEnrollmentStatusV1, CoreError>;
}

impl OwnTracksEnrollmentStateV1 {
    /// Bind authenticated ingress material to the current active enrollment.
    ///
    /// This keeps verifier and fence details within core while the private
    /// executor owns keyed derivation and the adapter owns durable lookup.
    ///
    /// # Errors
    /// Returns a bounded validation error unless this is an active enrollment
    /// whose verifier and current consent fence accept the supplied input.
    pub fn prepare_owntracks_ingress(
        &self,
        input: &OwnTracksIngressInputV1,
    ) -> Result<PreparedOwnTracksIngressV1, CoreError> {
        let (timeline, entity, fence, verifier) = match (
            self.timeline,
            self.entity,
            self.fence.as_ref(),
            self.verifier,
        ) {
            (Some(timeline), Some(entity), Some(fence), Some(verifier))
                if self.status == OwnTracksEnrollmentStatusV1::Active =>
            {
                (timeline, entity, fence, verifier)
            }
            _ => return Err(CoreError::GeographicAdmissionAuthenticationFailed),
        };
        if !constant_time_equal(&verifier, input.candidate_verifier()) {
            return Err(CoreError::GeographicAdmissionAuthenticationFailed);
        }
        let consent = fence.consent();
        if consent.withdrawn() || consent.admission_epoch() == 0 {
            return Err(CoreError::GeographicAdmissionValidationFailed);
        }
        Ok(PreparedOwnTracksIngressV1::from_authenticated_parts(
            *input.rate_key(),
            GeoLocationAdmissionRequestV1::from_input(GeoLocationAdmissionInputV1::new(
                timeline,
                entity,
                input.payload().clone(),
                fence.binding_revision(),
                (*consent.identity(), consent.revision(), *consent.hash()),
                (
                    consent.policy_version(),
                    consent.withdrawn(),
                    consent.admission_epoch(),
                ),
                (*input.intent(), *input.fingerprint()),
            )),
        ))
    }
    #[must_use]
    pub const fn absent() -> Self {
        Self {
            schema_version: OWNTRACKS_ENROLLMENT_SCHEMA_VERSION,
            status: OwnTracksEnrollmentStatusV1::Absent,
            timeline: None,
            entity: None,
            fence: None,
            verifier: None,
        }
    }
    #[must_use]
    pub const fn status(&self) -> OwnTracksEnrollmentStatusV1 {
        self.status
    }

    /// Return the bounded status representation safe for administration.
    #[must_use]
    pub fn status_view(&self) -> OwnTracksEnrollmentStatusViewV1 {
        OwnTracksEnrollmentStatusViewV1 {
            status: self.status,
            policy_version: self
                .fence
                .as_ref()
                .map(|fence| fence.consent().policy_version()),
        }
    }

    /// Encode the opaque, versioned durable state for a trusted storage adapter.
    ///
    /// # Errors
    /// Returns a bounded storage error if serialization fails.
    pub fn persistence_bytes(&self) -> Result<Vec<u8>, CoreError> {
        let mut bytes = Vec::new();
        ciborium::into_writer(self, &mut bytes)
            .map_err(|_| CoreError::Storage("invalid OwnTracks enrollment state".to_owned()))?;
        Ok(bytes)
    }

    /// Decode and validate the opaque durable state from a trusted storage adapter.
    ///
    /// # Errors
    /// Returns a bounded storage error for invalid or unsupported persisted state.
    pub fn from_persistence_bytes(bytes: &[u8]) -> Result<Self, CoreError> {
        let state: Self = ciborium::from_reader(bytes)
            .map_err(|_| CoreError::Storage("invalid OwnTracks enrollment state".to_owned()))?;
        if state.schema_version != OWNTRACKS_ENROLLMENT_SCHEMA_VERSION || !state.is_valid() {
            return Err(CoreError::Storage(
                "invalid OwnTracks enrollment state".to_owned(),
            ));
        }
        Ok(state)
    }
    #[must_use]
    pub const fn has_pairing_verifier(&self) -> bool {
        self.verifier.is_some()
    }
    #[must_use]
    pub fn admission_epoch(&self) -> u64 {
        self.fence
            .as_ref()
            .map_or(0, |fence| fence.consent().admission_epoch())
    }

    /// Check whether this enrollment remains the authority for an admission request.
    #[must_use]
    pub fn permits_geographic_admission(&self, request: &GeoLocationAdmissionRequestV1) -> bool {
        self.status == OwnTracksEnrollmentStatusV1::Active
            && self.timeline == Some(request.timeline())
            && self.entity == Some(request.entity())
            && self
                .fence
                .as_ref()
                .is_some_and(|fence| fence.permits(request))
    }

    /// Whether this active enrollment targets `timeline`.
    #[must_use]
    pub fn permits_geographic_admission_target(&self, timeline: TimelineId) -> bool {
        self.status == OwnTracksEnrollmentStatusV1::Active && self.timeline == Some(timeline)
    }
    /// Activate an absent or revoked enrollment.
    ///
    /// # Errors
    /// Returns a validation error when an active enrollment already exists or
    /// the supplied consent fence is withdrawn or has no epoch.
    pub fn pair(self, request: &OwnTracksEnrollmentRequestV1) -> Result<Self, CoreError> {
        if self.status == OwnTracksEnrollmentStatusV1::Active {
            return Err(CoreError::GeographicAdmissionValidationFailed);
        }
        let consent = request.fence.consent();
        if consent.withdrawn() || consent.admission_epoch() == 0 {
            return Err(CoreError::GeographicAdmissionValidationFailed);
        }
        let epoch = self
            .admission_epoch()
            .max(consent.admission_epoch())
            .checked_add(1)
            .filter(|epoch| *epoch != 0)
            .ok_or(CoreError::GeographicAdmissionValidationFailed)?;
        Ok(Self {
            schema_version: OWNTRACKS_ENROLLMENT_SCHEMA_VERSION,
            status: OwnTracksEnrollmentStatusV1::Active,
            timeline: Some(request.timeline),
            entity: Some(request.entity),
            fence: Some(GeoLocationAdmissionFenceV1::new(
                request.fence.binding_revision(),
                (*consent.identity(), consent.revision(), *consent.hash()),
                (consent.policy_version(), consent.withdrawn(), epoch),
            )),
            verifier: Some(request.verifier),
        })
    }

    /// Replace the verifier and advance the admission epoch.
    ///
    /// # Errors
    /// Returns a validation error unless the enrollment is active.
    pub fn rotate(mut self, verifier: [u8; 32]) -> Result<Self, CoreError> {
        let fence = self.active_fence()?;
        self.fence = Some(Self::advance_epoch(fence)?);
        self.verifier = Some(verifier);
        Ok(self)
    }

    /// Revoke the active enrollment and remove its verifier.
    ///
    /// # Errors
    /// Returns a validation error unless the enrollment is active.
    pub fn revoke(mut self) -> Result<Self, CoreError> {
        let fence = self.active_fence()?;
        self.fence = Some(Self::advance_epoch(fence)?);
        self.status = OwnTracksEnrollmentStatusV1::Revoked;
        self.verifier = None;
        Ok(self)
    }

    fn active_fence(&self) -> Result<&GeoLocationAdmissionFenceV1, CoreError> {
        if self.status != OwnTracksEnrollmentStatusV1::Active {
            return Err(CoreError::GeographicAdmissionValidationFailed);
        }
        self.fence
            .as_ref()
            .ok_or(CoreError::GeographicAdmissionValidationFailed)
    }

    fn is_valid(&self) -> bool {
        match self.status {
            OwnTracksEnrollmentStatusV1::Absent => {
                self.timeline.is_none()
                    && self.entity.is_none()
                    && self.fence.is_none()
                    && self.verifier.is_none()
            }
            OwnTracksEnrollmentStatusV1::Active => self.fence.as_ref().is_some_and(|fence| {
                self.timeline.is_some()
                    && self.entity.is_some()
                    && self.verifier.is_some()
                    && !fence.consent().withdrawn()
                    && fence.consent().admission_epoch() != 0
            }),
            OwnTracksEnrollmentStatusV1::Revoked => self.fence.as_ref().is_some_and(|fence| {
                self.timeline.is_some()
                    && self.entity.is_some()
                    && self.verifier.is_none()
                    && fence.consent().admission_epoch() != 0
            }),
        }
    }

    fn advance_epoch(
        fence: &GeoLocationAdmissionFenceV1,
    ) -> Result<GeoLocationAdmissionFenceV1, CoreError> {
        let consent = fence.consent();
        let epoch = consent
            .admission_epoch()
            .checked_add(1)
            .filter(|epoch| *epoch != 0)
            .ok_or(CoreError::GeographicAdmissionValidationFailed)?;
        Ok(GeoLocationAdmissionFenceV1::new(
            fence.binding_revision(),
            (*consent.identity(), consent.revision(), *consent.hash()),
            (consent.policy_version(), consent.withdrawn(), epoch),
        ))
    }
}

fn constant_time_equal(left: &[u8; 32], right: &[u8; 32]) -> bool {
    left.iter()
        .zip(right)
        .fold(0_u8, |difference, (left, right)| {
            difference | (left ^ right)
        })
        == 0
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::CanonicalBytes;

    fn ok<T, E: std::fmt::Debug>(value: Result<T, E>) -> T {
        value.unwrap_or_else(|error| {
            std::panic::resume_unwind(Box::new(format!(
                "unexpected enrollment fixture error: {error:?}"
            )))
        })
    }

    fn dummy_input() -> OwnTracksIngressInputV1 {
        OwnTracksIngressInputV1::new(
            [0; 32],
            [0; 32],
            [0; 32],
            [0; 32],
            CanonicalBytes::from_static(b""),
        )
    }

    #[test]
    fn cover_prepare_ingress_auth_failure_when_absent() {
        // Absent enrollment → _ arm → GeographicAdmissionAuthenticationFailed
        assert!(OwnTracksEnrollmentStateV1::absent()
            .prepare_owntracks_ingress(&dummy_input())
            .is_err());
    }

    #[test]
    fn cover_from_persistence_bytes_error_path() {
        // Invalid bytes → Serialization error
        assert!(OwnTracksEnrollmentStateV1::from_persistence_bytes(b"not-valid-cbor").is_err());
    }

    #[test]
    fn cover_from_persistence_bytes_validation_path() {
        let invalid = OwnTracksEnrollmentStateV1 {
            schema_version: OWNTRACKS_ENROLLMENT_SCHEMA_VERSION,
            status: OwnTracksEnrollmentStatusV1::Active,
            timeline: None,
            entity: None,
            fence: None,
            verifier: None,
        };
        let mut bytes = Vec::new();
        ciborium::into_writer(&invalid, &mut bytes).unwrap_or_else(|error| {
            std::panic::resume_unwind(Box::new(format!("unexpected CBOR error: {error:?}")))
        });
        assert!(OwnTracksEnrollmentStateV1::from_persistence_bytes(&bytes).is_err());
    }

    #[test]
    fn cover_prepare_ingress_rejects_withdrawn_consent() {
        let state = OwnTracksEnrollmentStateV1 {
            schema_version: OWNTRACKS_ENROLLMENT_SCHEMA_VERSION,
            status: OwnTracksEnrollmentStatusV1::Active,
            timeline: Some(TimelineId::new()),
            entity: Some(EntityId::new()),
            fence: Some(GeoLocationAdmissionFenceV1::new(
                1,
                ([0; 32], 1, [0; 32]),
                (1, true, 1),
            )),
            verifier: Some([0; 32]),
        };
        assert!(matches!(
            state.prepare_owntracks_ingress(&dummy_input()),
            Err(CoreError::GeographicAdmissionValidationFailed)
        ));
    }

    #[test]
    fn active_enrollment_rotates_and_revokes_with_epoch_progression() {
        let state = OwnTracksEnrollmentStateV1 {
            schema_version: OWNTRACKS_ENROLLMENT_SCHEMA_VERSION,
            status: OwnTracksEnrollmentStatusV1::Active,
            timeline: Some(TimelineId::new()),
            entity: Some(EntityId::new()),
            fence: Some(GeoLocationAdmissionFenceV1::new(
                1,
                ([0; 32], 1, [0; 32]),
                (1, false, 1),
            )),
            verifier: Some([0; 32]),
        };
        let rotated = ok(state.rotate([1; 32]));
        assert_eq!(rotated.status(), OwnTracksEnrollmentStatusV1::Active);
        assert_eq!(rotated.admission_epoch(), 2);
        let revoked = ok(rotated.revoke());
        assert_eq!(revoked.status(), OwnTracksEnrollmentStatusV1::Revoked);
        assert!(!revoked.has_pairing_verifier());
    }

    #[test]
    fn enrollment_epoch_overflow_is_rejected() {
        let request = OwnTracksEnrollmentRequestV1::new(
            TimelineId::new(),
            EntityId::new(),
            GeoLocationAdmissionFenceV1::new(1, ([0; 32], 1, [0; 32]), (1, false, u64::MAX)),
            [0; 32],
        );
        assert!(matches!(
            OwnTracksEnrollmentStateV1::absent().pair(&request),
            Err(CoreError::GeographicAdmissionValidationFailed)
        ));

        let active = OwnTracksEnrollmentStateV1 {
            schema_version: OWNTRACKS_ENROLLMENT_SCHEMA_VERSION,
            status: OwnTracksEnrollmentStatusV1::Active,
            timeline: Some(TimelineId::new()),
            entity: Some(EntityId::new()),
            fence: Some(GeoLocationAdmissionFenceV1::new(
                1,
                ([0; 32], 1, [0; 32]),
                (1, false, u64::MAX),
            )),
            verifier: Some([0; 32]),
        };
        assert!(active.clone().rotate([1; 32]).is_err());
        assert!(active.revoke().is_err());
    }
}
