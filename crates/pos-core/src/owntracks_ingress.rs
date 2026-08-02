//! Opaque authenticated ingress values for one V1 `OwnTracks` location update.

use crate::{geo_admission::GeoLocationAdmissionRequestV1, CanonicalBytes, CoreError};

/// Bounded input passed from the private gateway executor to a store adapter.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OwnTracksIngressInputV1 {
    candidate_verifier: [u8; 32],
    rate_key: [u8; 32],
    intent: [u8; 32],
    fingerprint: [u8; 32],
    payload: CanonicalBytes,
}

impl OwnTracksIngressInputV1 {
    /// Build an ingress value from executor-derived opaque material.
    #[must_use]
    pub const fn new(
        candidate_verifier: [u8; 32],
        rate_key: [u8; 32],
        intent: [u8; 32],
        fingerprint: [u8; 32],
        payload: CanonicalBytes,
    ) -> Self {
        Self {
            candidate_verifier,
            rate_key,
            intent,
            fingerprint,
            payload,
        }
    }

    #[must_use]
    pub const fn candidate_verifier(&self) -> &[u8; 32] {
        &self.candidate_verifier
    }

    #[must_use]
    pub const fn rate_key(&self) -> &[u8; 32] {
        &self.rate_key
    }

    #[must_use]
    pub const fn intent(&self) -> &[u8; 32] {
        &self.intent
    }

    #[must_use]
    pub const fn fingerprint(&self) -> &[u8; 32] {
        &self.fingerprint
    }

    #[must_use]
    pub const fn payload(&self) -> &CanonicalBytes {
        &self.payload
    }
}

/// Opaque per-enrollment key used only by the executor's in-memory rate limiter.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub struct OwnTracksIngressRateKeyV1(pub(crate) [u8; 32]);

impl OwnTracksIngressRateKeyV1 {
    /// Reconstitute an opaque rate key from a trusted executor boundary.
    #[must_use]
    pub const fn from_owner_keyed_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

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
    pub(crate) fn from_authenticated_parts(
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
