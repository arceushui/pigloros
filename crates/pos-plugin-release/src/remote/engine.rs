//! The private bounded HTTP engine shared by the remote release sources.
//!
//! It owns routing, redirects, deadlines, credentials and byte bounds. It
//! fetches exact descriptor-sized bytes only; descriptor digests and the
//! closure are verified by the shared OCI verifier, never by this engine.

use std::cell::Cell;
use std::io::Read as _;
use std::sync::Arc;
use std::time::Instant;

use ureq::http::{header, HeaderMap, Response};
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
/// The largest token-service response body accepted.
const MAX_TOKEN_BYTES: u64 = 65_536;

/// One class of the per-closure request budget (ADR-061 amendment revision 1).
#[derive(Clone, Copy)]
enum Charge {
    /// A GET attempt, charged before any network activity.
    Attempt,
    /// A successful content response.
    Content,
    /// A redirect response.
    Redirect,
    /// A 401 challenge response.
    Challenge,
    /// A token-service response.
    Token,
}

/// The V1 limit of each `Charge`, in declaration order. A closure has at most
/// 359 objects, and each takes at most one successful content response, three
/// redirects, one challenge and one token response, which is at most six GET
/// attempts: 359 + 1,077 + 359 + 359 responses and 2,154 attempts.
const BUDGET_LIMITS: [usize; 5] = [2_154, 359, 1_077, 359, 359];

/// The request counters of one closure read. A charge past its limit fails
/// closed before that request is made.
struct Budget {
    used: [Cell<usize>; 5],
    limits: [usize; 5],
}

impl Budget {
    const fn new(limits: [usize; 5]) -> Self {
        Self {
            used: [
                Cell::new(0),
                Cell::new(0),
                Cell::new(0),
                Cell::new(0),
                Cell::new(0),
            ],
            limits,
        }
    }

    fn charge(&self, charge: Charge) -> Result<(), ReleaseSourceErrorV1> {
        let index = charge as usize;
        let used = self.used[index].get();
        if used >= self.limits[index] {
            return Err(ReleaseSourceErrorV1::BoundsExceeded);
        }
        self.used[index].set(used + 1);
        Ok(())
    }
}

/// Turns a 401 response's headers into the `Authorization` value of the one
/// authenticated retry. It may make its own requests through the same
/// closure read, so they are counted in the same budget.
pub(super) type Reauthorize<'a> = &'a dyn Fn(&HeaderMap) -> Result<String, ReleaseSourceErrorV1>;

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
            budget: Budget::new(BUDGET_LIMITS),
        }
    }
}

/// One closure read. Its downloads are serial, and every request is capped
/// by the time left before the closure deadline.
pub(super) struct ClosureRead<'a> {
    engine: &'a Engine,
    deadline: Instant,
    budget: Budget,
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
        self.fetch_object(url, authorization, None, size, None)
    }

    /// Fetch exactly `size` bytes from `url`, sending `accept` when given.
    ///
    /// Like `fetch`, and a 401 answer to the first request (before any
    /// redirect) is answered once by `reauthorize` with the `Authorization`
    /// of one retry of the same URL. A second 401, or a 401 at a redirect
    /// target, fails closed.
    pub(super) fn fetch_challenged(
        &self,
        url: &Url,
        authorization: Option<&str>,
        accept: Option<&str>,
        size: u64,
        reauthorize: Reauthorize<'_>,
    ) -> Result<Vec<u8>, ReleaseSourceErrorV1> {
        self.fetch_object(url, authorization, accept, size, Some(reauthorize))
    }

    /// One token-service GET: no redirect, no challenge, and a body of at
    /// most 64 KiB.
    pub(super) fn fetch_token(
        &self,
        url: &Url,
        authorization: Option<&str>,
    ) -> Result<Vec<u8>, ReleaseSourceErrorV1> {
        let response = self.get(url, authorization, None)?;
        self.budget.charge(Charge::Token).and_then(|()| {
            if response.status().as_u16() == 200 {
                read_body(response, MAX_TOKEN_BYTES, false)
            } else {
                Err(ReleaseSourceErrorV1::Io)
            }
        })
    }

    fn fetch_object(
        &self,
        url: &Url,
        authorization: Option<&str>,
        accept: Option<&str>,
        size: u64,
        reauthorize: Option<Reauthorize<'_>>,
    ) -> Result<Vec<u8>, ReleaseSourceErrorV1> {
        let mut visited = vec![url.clone()];
        let mut current = url.clone();
        let mut authorization = authorization.map(str::to_owned);
        let mut hops = 0;
        let mut challenged = false;
        loop {
            let response = self.get(&current, authorization.as_deref(), accept)?;
            match (response.status().as_u16(), reauthorize) {
                (200, _) => {
                    return self
                        .budget
                        .charge(Charge::Content)
                        .and_then(|()| read_body(response, size, true));
                }
                (301 | 302 | 303 | 307 | 308, _) if hops < MAX_REDIRECTS => {
                    current = self
                        .budget
                        .charge(Charge::Redirect)
                        .and_then(|()| self.redirect_target(&current, &response, &visited))?;
                    visited.push(current.clone());
                    authorization = None;
                    hops += 1;
                }
                (401, Some(reauthorize)) if hops == 0 && !challenged => {
                    authorization = Some(
                        self.budget
                            .charge(Charge::Challenge)
                            .and_then(|()| reauthorize(response.headers()))?,
                    );
                    challenged = true;
                }
                (404 | 410, _) => return Err(ReleaseSourceErrorV1::NotFound),
                _ => return Err(ReleaseSourceErrorV1::Io),
            }
        }
    }

    fn get(
        &self,
        url: &Url,
        authorization: Option<&str>,
        accept: Option<&str>,
    ) -> Result<Response<Body>, ReleaseSourceErrorV1> {
        self.budget
            .charge(Charge::Attempt)
            .and_then(|()| self.send(url, authorization, accept))
    }

    fn send(
        &self,
        url: &Url,
        authorization: Option<&str>,
        accept: Option<&str>,
    ) -> Result<Response<Body>, ReleaseSourceErrorV1> {
        let remaining = self.deadline.saturating_duration_since(Instant::now());
        let deadlines = self.engine.config.deadlines();
        let request = self.engine.agent.get(url.as_str());
        let request = match authorization {
            Some(value) => request.header(header::AUTHORIZATION, value),
            None => request,
        };
        let request = match accept {
            Some(value) => request.header(header::ACCEPT, value),
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

/// Read the identity-coded body of at most `size` bytes, or of exactly `size`
/// bytes when `exact`, with a one-byte excess sentinel.
fn read_body(
    response: Response<Body>,
    size: u64,
    exact: bool,
) -> Result<Vec<u8>, ReleaseSourceErrorV1> {
    if response
        .headers()
        .get_all(header::CONTENT_ENCODING)
        .iter()
        .any(|coding| coding != "identity")
    {
        return Err(ReleaseSourceErrorV1::Io);
    }
    let mismatch = if exact {
        ReleaseSourceErrorV1::SizeMismatch
    } else {
        ReleaseSourceErrorV1::BoundsExceeded
    };
    let mut bytes = Vec::new();
    response
        .into_body()
        .into_reader()
        .take(size + 1)
        .read_to_end(&mut bytes)
        .or(Err(ReleaseSourceErrorV1::Io))?;
    let length = bytes.len() as u64;
    if length > size || (exact && length < size) {
        Err(mismatch)
    } else {
        Ok(bytes)
    }
}

/// Map a transport failure to a closed error, without its upstream message.
const fn transport_error(error: &ureq::Error) -> ReleaseSourceErrorV1 {
    match error {
        ureq::Error::LargeResponseHeader(..) => ReleaseSourceErrorV1::BoundsExceeded,
        _ => ReleaseSourceErrorV1::Io,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CLASSES: [Charge; 5] = [
        Charge::Attempt,
        Charge::Content,
        Charge::Redirect,
        Charge::Challenge,
        Charge::Token,
    ];

    #[test]
    fn the_v1_limits_are_the_adr_request_budget() {
        // 359 objects, each at most one content, three redirect, one
        // challenge and one token response, and six GET attempts.
        assert_eq!(BUDGET_LIMITS, [359 * 6, 359, 359 * 3, 359, 359]);
    }

    #[test]
    fn each_class_fails_closed_exactly_past_its_own_limit() {
        for class in CLASSES {
            let budget = Budget::new([2, 2, 2, 2, 2]);
            assert_eq!(budget.charge(class), Ok(()));
            assert_eq!(budget.charge(class), Ok(()));
            assert_eq!(
                budget.charge(class),
                Err(ReleaseSourceErrorV1::BoundsExceeded)
            );
            // The other classes are unaffected.
            for other in CLASSES
                .iter()
                .filter(|other| **other as usize != class as usize)
            {
                assert_eq!(budget.charge(*other), Ok(()));
            }
        }
    }
}
