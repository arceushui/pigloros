//! The immutable-descriptor HTTPS release source (#426).

use std::collections::BTreeMap;

use url::Url;

use super::config::{requestable, RemoteConfigErrorV1, RemoteTransportConfigV1};
use super::engine::Engine;
use crate::oci::{
    verify_oci_closure_v1, BundleAddressV1, ReleaseSourceErrorV1, ReleaseSourceV1,
    VerifiedReleaseBundleV1,
};

/// A release source over HTTPS, bound to exactly one immutable bundle address.
///
/// The operator supplies the manifest locator and a blob base. The manifest
/// is fetched with the exact size of the bound address and verified against
/// its digest before parsing. Each blob is then fetched in digest order from
/// `<blob base><lowercase SHA-256 hex>`; no URL inside a descriptor is used.
/// The complete closure is finished by the same verifier as every other
/// source, so the result is the same verified bundle view. Partial downloads
/// are discarded, and nothing about the location enters bundle identity.
pub struct HttpsReleaseSourceV1 {
    address: BundleAddressV1,
    manifest: Url,
    blob_base: Url,
    engine: Engine,
}

impl HttpsReleaseSourceV1 {
    /// Bind one HTTPS source to `address`.
    ///
    /// `manifest_locator` may carry a query (for example a pre-signed URL);
    /// `blob_base` must have no query and must end in `/`. Both must be HTTPS
    /// URLs of at most 8 KiB without userinfo or fragment, on allowed origins.
    ///
    /// # Errors
    /// Returns `InvalidLocator` for an invalid locator and
    /// `UnconfiguredOrigin` for a locator outside the allowed origins.
    pub fn new(
        address: BundleAddressV1,
        manifest_locator: &str,
        blob_base: &str,
        transport: RemoteTransportConfigV1,
    ) -> Result<Self, RemoteConfigErrorV1> {
        let manifest = locator(manifest_locator, &transport)?;
        let blob_base = locator(blob_base, &transport)?;
        if blob_base.query().is_some() || !blob_base.path().ends_with('/') {
            return Err(RemoteConfigErrorV1::InvalidLocator);
        }
        Ok(Self {
            address,
            manifest,
            blob_base,
            engine: Engine::new(transport),
        })
    }

    fn blob_url(&self, digest: &str) -> Url {
        let mut url = self.blob_base.clone();
        url.set_path(&format!(
            "{}{}",
            self.blob_base.path(),
            &digest["sha256:".len()..]
        ));
        url
    }
}

fn locator(text: &str, transport: &RemoteTransportConfigV1) -> Result<Url, RemoteConfigErrorV1> {
    let url = Url::parse(text)
        .ok()
        .filter(requestable)
        .ok_or(RemoteConfigErrorV1::InvalidLocator)?;
    if transport.allows(&url) {
        Ok(url)
    } else {
        Err(RemoteConfigErrorV1::UnconfiguredOrigin)
    }
}

impl ReleaseSourceV1 for HttpsReleaseSourceV1 {
    /// Fetch and verify the bound closure.
    ///
    /// # Errors
    /// Returns `NotFound` without any request for an address other than the
    /// bound one, and otherwise a closed transport or verifier error.
    fn read_verified(
        &self,
        address: &BundleAddressV1,
    ) -> Result<VerifiedReleaseBundleV1, ReleaseSourceErrorV1> {
        if address != &self.address {
            return Err(ReleaseSourceErrorV1::NotFound);
        }
        let config = self.engine.config();
        let manifest_authorization = config.authorization(&self.manifest)?;
        let blob_authorization = config.authorization(&self.blob_base)?;
        let read = self.engine.begin();
        let manifest = read.fetch(
            &self.manifest,
            manifest_authorization.as_deref(),
            self.address.size(),
        )?;
        let mut blobs = BTreeMap::new();
        for (digest, size) in self.address.plan_closure(&manifest)? {
            let bytes = read.fetch(&self.blob_url(&digest), blob_authorization.as_deref(), size)?;
            blobs.insert(digest, bytes);
        }
        verify_oci_closure_v1(self.address.clone(), manifest, blobs)
    }
}
