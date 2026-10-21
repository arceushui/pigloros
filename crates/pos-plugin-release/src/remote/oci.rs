//! The immutable-digest OCI registry release source (#427).

use std::cell::RefCell;
use std::collections::BTreeMap;

use ureq::http::HeaderMap;
use url::Url;

use super::challenge::{bearer_challenge, token_of};
use super::config::{
    bearer_authorization, exact_origin, requestable, RemoteConfigErrorV1, RemoteTransportConfigV1,
    LENGTH_PROBE_DIGEST,
};
use super::engine::{ClosureRead, Engine};
use crate::oci::{
    verify_oci_closure_v1, BundleAddressV1, ReleaseSourceErrorV1, ReleaseSourceV1,
    VerifiedReleaseBundleV1,
};
use crate::MANIFEST_MEDIA_TYPE;

/// The longest repository name of the OCI distribution specification.
const MAX_REPOSITORY_BYTES: usize = 255;

/// A release source over one OCI registry repository.
///
/// The requested [`BundleAddressV1`] is the only identity: the manifest is
/// fetched from `/v2/<repository>/manifests/<digest>` with the exact size of
/// the address and verified against its digest before parsing, and each blob
/// from `/v2/<repository>/blobs/<digest>` in digest order. A tag is never
/// used, and no registry header or descriptor-supplied URL is trusted. The
/// complete closure is finished by the same verifier as every other source,
/// so the result is the same verified bundle view, and nothing about the
/// registry enters bundle identity.
///
/// Authentication follows the registry Bearer flow with finite authority. A
/// first 401 answer is accepted only as one unambiguous Bearer challenge
/// with an allowed realm; the source makes one token request for exactly
/// `repository:<repository>:pull` and retries once. A redirect target never
/// receives a credential and never starts authentication.
pub struct OciReleaseSourceV1 {
    registry: Url,
    repository: String,
    scope: String,
    service: Option<String>,
    engine: Engine,
}

impl OciReleaseSourceV1 {
    /// Create a source for `repository` on the HTTPS `registry_origin`
    /// (`https://host[:port]`).
    ///
    /// `expected_service` is the token service the registry's challenge must
    /// name exactly; with `None` the challenge must name no service. The
    /// repository must follow the distribution-specification name grammar
    /// and be at most 255 bytes.
    ///
    /// # Errors
    /// Returns `InvalidLocator` for an invalid registry origin, repository
    /// or service, or when a request URL would exceed 8 KiB, and
    /// `UnconfiguredOrigin` when the registry origin is not allowed.
    pub fn new(
        registry_origin: &str,
        repository: &str,
        expected_service: Option<&str>,
        transport: RemoteTransportConfigV1,
    ) -> Result<Self, RemoteConfigErrorV1> {
        let registry = exact_origin(registry_origin).ok_or(RemoteConfigErrorV1::InvalidLocator)?;
        if !valid_repository(repository)
            || expected_service.is_some_and(|service| {
                service.is_empty() || !service.bytes().all(|b| b.is_ascii_graphic())
            })
        {
            return Err(RemoteConfigErrorV1::InvalidLocator);
        }
        if !transport.allows(&registry) {
            return Err(RemoteConfigErrorV1::UnconfiguredOrigin);
        }
        // Every request URL is the registry, the repository, a kind and a
        // digest, so one probe with the longest kind bounds them all.
        if !requestable(&object_url(
            &registry,
            repository,
            "manifests",
            LENGTH_PROBE_DIGEST,
        )) {
            return Err(RemoteConfigErrorV1::InvalidLocator);
        }
        Ok(Self {
            registry,
            repository: repository.to_owned(),
            scope: format!("repository:{repository}:pull"),
            service: expected_service.map(str::to_owned),
            engine: Engine::new(transport),
        })
    }

    /// Read the closure of `address`. The registry credential `bootstrap`
    /// opens each request until a token replaces it; the token lives only
    /// for this read.
    fn read_closure(
        &self,
        address: &BundleAddressV1,
        bootstrap: Option<&str>,
    ) -> Result<VerifiedReleaseBundleV1, ReleaseSourceErrorV1> {
        let token = RefCell::new(None::<String>);
        let read = self.engine.begin();
        let reauthorize = |headers: &HeaderMap| {
            self.token_authorization(&read, headers)
                .inspect(|value| *token.borrow_mut() = Some(value.clone()))
        };
        let fetch = |kind: &str, digest: &str, accept: Option<&str>, size: u64| {
            let url = object_url(&self.registry, &self.repository, kind, digest);
            let current = token
                .borrow()
                .clone()
                .or_else(|| bootstrap.map(str::to_owned));
            read.fetch_challenged(&url, current.as_deref(), accept, size, &reauthorize)
        };
        let manifest = fetch(
            "manifests",
            address.digest(),
            Some(MANIFEST_MEDIA_TYPE),
            address.size(),
        )?;
        let mut blobs = BTreeMap::new();
        for (digest, size) in address.plan_closure(&manifest)? {
            let bytes = fetch("blobs", &digest, None, size)?;
            blobs.insert(digest, bytes);
        }
        verify_oci_closure_v1(address.clone(), manifest, blobs)
    }

    /// Answer a 401 challenge: one token request for the exact pull scope,
    /// and the `Authorization` of the one authenticated retry.
    fn token_authorization(
        &self,
        read: &ClosureRead<'_>,
        headers: &HeaderMap,
    ) -> Result<String, ReleaseSourceErrorV1> {
        let config = self.engine.config();
        let challenge = bearer_challenge(headers).ok_or(ReleaseSourceErrorV1::Io)?;
        if challenge.service != self.service
            || challenge
                .scope
                .as_ref()
                .is_some_and(|scope| *scope != self.scope)
        {
            return Err(ReleaseSourceErrorV1::Io);
        }
        let mut token_url = Url::parse(&challenge.realm)
            .ok()
            .filter(|realm| config.allows(realm) && realm.query().is_none())
            .ok_or(ReleaseSourceErrorV1::Io)?;
        {
            let mut query = token_url.query_pairs_mut();
            if let Some(service) = &self.service {
                query.append_pair("service", service);
            }
            query.append_pair("scope", &self.scope);
        }
        config
            .authorization(&token_url)
            .and_then(|credential| read.fetch_token(&token_url, credential.as_deref()))
            .and_then(|body| token_of(&body).ok_or(ReleaseSourceErrorV1::Io))
            .and_then(|token| bearer_authorization(&token))
    }
}

/// `/v2/<repository>/<kind>/<digest>` on the registry origin.
fn object_url(registry: &Url, repository: &str, kind: &str, digest: &str) -> Url {
    let mut url = registry.clone();
    url.set_path(&format!("/v2/{repository}/{kind}/{digest}"));
    url
}

/// The distribution-specification name grammar: slash-separated components
/// of lowercase alphanumeric runs joined by `.`, `_`, `__` or one or more
/// `-`, at most 255 bytes in all.
fn valid_repository(name: &str) -> bool {
    name.len() <= MAX_REPOSITORY_BYTES && name.split('/').all(valid_component)
}

fn valid_component(component: &str) -> bool {
    let bytes = component.as_bytes();
    let mut index = 0;
    loop {
        let start = index;
        while bytes
            .get(index)
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        {
            index += 1;
        }
        if index == start {
            return false;
        }
        match bytes.get(index) {
            None => return true,
            Some(b'.') => index += 1,
            Some(b'_') => {
                index += 1;
                if bytes.get(index) == Some(&b'_') {
                    index += 1;
                }
            }
            Some(b'-') => {
                while bytes.get(index) == Some(&b'-') {
                    index += 1;
                }
            }
            Some(_) => return false,
        }
    }
}

impl ReleaseSourceV1 for OciReleaseSourceV1 {
    /// Fetch and verify the closure of `address`.
    ///
    /// # Errors
    /// Returns a closed transport or verifier error. A registry that
    /// answers 404 or 410 is `NotFound`; an authentication failure is `Io`.
    fn read_verified(
        &self,
        address: &BundleAddressV1,
    ) -> Result<VerifiedReleaseBundleV1, ReleaseSourceErrorV1> {
        self.engine
            .config()
            .authorization(&self.registry)
            .and_then(|bootstrap| self.read_closure(address, bootstrap.as_deref()))
    }
}
