//! The private bounded HTTP engine shared by the remote release sources.
//!
//! It owns routing, redirects, deadlines, credentials and byte bounds. It
//! fetches exact descriptor-sized bytes only; descriptor digests and the
//! closure are verified by the shared OCI verifier, never by this engine.

use std::io::Read as _;
use std::sync::Arc;
use std::time::Instant;

use ureq::http::{header, Response};
use ureq::tls::{TlsConfig, TlsProvider};
use ureq::unversioned::transport::DefaultConnector;
use ureq::{Agent, Body};
use url::Url;

use super::config::RemoteTransportConfigV1;
use super::resolver::BoundedResolver;
use crate::oci::ReleaseSourceErrorV1;

/// Redirect hops followed for one logical content fetch.
const MAX_REDIRECTS: usize = 3;
/// The largest response header block accepted.
const MAX_RESPONSE_HEADER_BYTES: usize = 32_768;

/// One configured transport: an HTTP agent with no proxy, no automatic
/// redirect, no connection reuse, no decompression and no cookie store.
pub(super) struct Engine {
    agent: Agent,
    config: RemoteTransportConfigV1,
}

impl Engine {
    pub(super) fn new(config: RemoteTransportConfigV1) -> Self {
        // The ring provider is set on this transport's own TLS configuration,
        // so a process-wide default provider is neither used nor installed.
        let tls = TlsConfig::builder()
            .provider(TlsProvider::Rustls)
            .root_certs(config.roots().clone())
            .unversioned_rustls_crypto_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .build();
        let agent_config = Agent::config_builder()
            .http_status_as_error(false)
            .https_only(true)
            .proxy(None)
            .max_redirects(0)
            .max_response_header_size(MAX_RESPONSE_HEADER_BYTES)
            .max_idle_connections(0)
            .max_idle_connections_per_host(0)
            .tls_config(tls)
            .build();
        Self {
            agent: Agent::with_parts(
                agent_config,
                DefaultConnector::new(),
                BoundedResolver::shared(),
            ),
            config,
        }
    }

    pub(super) const fn config(&self) -> &RemoteTransportConfigV1 {
        &self.config
    }

    /// Start one closure read under one monotonic deadline.
    pub(super) fn begin(&self) -> ClosureRead<'_> {
        ClosureRead {
            engine: self,
            deadline: Instant::now() + self.config.deadlines().closure,
        }
    }
}

/// One closure read. Its downloads are serial, and every request is capped
/// by the time left before the closure deadline.
pub(super) struct ClosureRead<'a> {
    engine: &'a Engine,
    deadline: Instant,
}

impl ClosureRead<'_> {
    /// Fetch exactly `size` bytes from `url`.
    ///
    /// `authorization` is sent to `url` only. A redirect target must be an
    /// allowed origin, receives no credential, and is never revisited.
    pub(super) fn fetch(
        &self,
        url: &Url,
        authorization: Option<&str>,
        size: u64,
    ) -> Result<Vec<u8>, ReleaseSourceErrorV1> {
        let mut visited = vec![url.clone()];
        let mut current = url.clone();
        let mut authorization = authorization;
        for _ in 0..=MAX_REDIRECTS {
            let response = self.get(&current, authorization)?;
            match response.status().as_u16() {
                200 => return read_exact(response, size),
                301 | 302 | 303 | 307 | 308 => {
                    current = self.redirect_target(&current, &response, &visited)?;
                    visited.push(current.clone());
                    authorization = None;
                }
                404 | 410 => return Err(ReleaseSourceErrorV1::NotFound),
                _ => return Err(ReleaseSourceErrorV1::Io),
            }
        }
        Err(ReleaseSourceErrorV1::Io)
    }

    fn get(
        &self,
        url: &Url,
        authorization: Option<&str>,
    ) -> Result<Response<Body>, ReleaseSourceErrorV1> {
        let remaining = self.deadline.saturating_duration_since(Instant::now());
        let deadlines = self.engine.config.deadlines();
        let request = self.engine.agent.get(url.as_str());
        let request = match authorization {
            Some(value) => request.header(header::AUTHORIZATION, value),
            None => request,
        };
        request
            .config()
            .timeout_global(Some(remaining))
            .timeout_resolve(Some(remaining.min(deadlines.dns)))
            .timeout_connect(Some(remaining.min(deadlines.connect)))
            .timeout_recv_response(Some(remaining.min(deadlines.response_headers)))
            .timeout_recv_body(Some(remaining.min(deadlines.response_body)))
            .build()
            .call()
            .map_err(|error| transport_error(&error))
    }

    /// Validate one redirect's single `Location` before any further
    /// resolution or connection.
    fn redirect_target(
        &self,
        current: &Url,
        response: &Response<Body>,
        visited: &[Url],
    ) -> Result<Url, ReleaseSourceErrorV1> {
        let mut locations = response.headers().get_all(header::LOCATION).iter();
        match (locations.next(), locations.next()) {
            (Some(location), None) => location
                .to_str()
                .ok()
                .and_then(|location| current.join(location).ok())
                .filter(|next| self.engine.config.allows(next) && !visited.contains(next))
                .ok_or(ReleaseSourceErrorV1::Io),
            _ => Err(ReleaseSourceErrorV1::Io),
        }
    }
}

/// Read exactly `size` identity-coded bytes, with a one-byte excess sentinel.
fn read_exact(response: Response<Body>, size: u64) -> Result<Vec<u8>, ReleaseSourceErrorV1> {
    if response
        .headers()
        .get_all(header::CONTENT_ENCODING)
        .iter()
        .any(|coding| coding != "identity")
    {
        return Err(ReleaseSourceErrorV1::Io);
    }
    if response
        .body()
        .content_length()
        .is_some_and(|length| length != size)
    {
        return Err(ReleaseSourceErrorV1::SizeMismatch);
    }
    let mut bytes = Vec::new();
    response
        .into_body()
        .into_reader()
        .take(size + 1)
        .read_to_end(&mut bytes)
        .or(Err(ReleaseSourceErrorV1::Io))?;
    if bytes.len() as u64 == size {
        Ok(bytes)
    } else {
        Err(ReleaseSourceErrorV1::SizeMismatch)
    }
}

/// Map a transport failure to a closed error, without its upstream message.
fn transport_error(error: &ureq::Error) -> ReleaseSourceErrorV1 {
    match error {
        ureq::Error::LargeResponseHeader(..) => ReleaseSourceErrorV1::BoundsExceeded,
        _ => ReleaseSourceErrorV1::Io,
    }
}
