//! Core values for the one V1 `OwnTracks` enrollment.

use crate::{CoreError, EntityId, GeoLocationAdmissionFenceV1, TimelineId};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OwnTracksEnrollmentStatusV1 {
    Absent,
    Active,
    Revoked,
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
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OwnTracksEnrollmentStateV1 {
    status: OwnTracksEnrollmentStatusV1,
    timeline: Option<TimelineId>,
    entity: Option<EntityId>,
    fence: Option<GeoLocationAdmissionFenceV1>,
    verifier: Option<[u8; 32]>,
}

impl OwnTracksEnrollmentStateV1 {
    #[must_use]
    pub const fn absent() -> Self {
        Self {
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
        let epoch = consent
            .admission_epoch()
            .checked_add(1)
            .filter(|epoch| *epoch != 0)
            .ok_or(CoreError::GeographicAdmissionValidationFailed)?;
        Ok(Self {
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
