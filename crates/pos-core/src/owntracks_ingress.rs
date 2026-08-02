//! Opaque authenticated ingress values for one V1 `OwnTracks` location update.

use crate::{geo_admission::GeoLocationAdmissionRequestV1, CanonicalBytes, CoreError};

/// Bounded input passed from the private gateway executor to a store adapter.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OwnTracksIngressInputV1 {
    owner_key: [u8; 32],
    basic_handle: [u8; 32],
    basic_secret: [u8; 32],
    payload: CanonicalBytes,
}

impl OwnTracksIngressInputV1 {
    #[must_use]
    pub const fn new(
        owner_key: [u8; 32],
        basic_handle: [u8; 32],
        basic_secret: [u8; 32],
        payload: CanonicalBytes,
    ) -> Self {
        Self {
            owner_key,
            basic_handle,
            basic_secret,
            payload,
        }
    }

    #[must_use]
    pub const fn owner_key(&self) -> &[u8; 32] {
        &self.owner_key
    }

    #[must_use]
    pub const fn basic_handle(&self) -> &[u8; 32] {
        &self.basic_handle
    }

    #[must_use]
    pub const fn basic_secret(&self) -> &[u8; 32] {
        &self.basic_secret
    }

    #[must_use]
    pub const fn payload(&self) -> &CanonicalBytes {
        &self.payload
    }
}

/// Opaque per-enrollment key used only by the executor's in-memory rate limiter.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub struct OwnTracksIngressRateKeyV1(pub(crate) [u8; 32]);

/// Authenticated ingress that is ready for the executor to rate-limit and admit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedOwnTracksIngressV1 {
    rate_key: OwnTracksIngressRateKeyV1,
    admission_request: GeoLocationAdmissionRequestV1,
}

impl PreparedOwnTracksIngressV1 {
    #[must_use]
    pub const fn rate_key(&self) -> OwnTracksIngressRateKeyV1 {
        self.rate_key
    }

    #[must_use]
    pub fn into_admission_request(self) -> GeoLocationAdmissionRequestV1 {
        self.admission_request
    }

    #[must_use]
    pub fn from_authenticated_parts(
        rate_key: [u8; 32],
        admission_request: GeoLocationAdmissionRequestV1,
    ) -> Self {
        Self {
            rate_key: OwnTracksIngressRateKeyV1(rate_key),
            admission_request,
        }
    }
}

/// Dedicated store capability for authenticating and preparing V1 `OwnTracks` ingress.
pub trait OwnTracksIngressStore {
    /// Authenticate the active enrollment and build one geographic admission request.
    ///
    /// # Errors
    /// Returns a bounded error unless the current enrollment accepts the credentials.
    fn prepare_owntracks_ingress(
        &mut self,
        input: OwnTracksIngressInputV1,
    ) -> Result<PreparedOwnTracksIngressV1, CoreError>;
}
