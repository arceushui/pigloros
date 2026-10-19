//! Operator-owned outbound, TLS, deadline and credential configuration shared
//! by every remote release source (ADR-061 amendment revision 1).
//!
//! This configuration decides which origins are reachable and how long a read
//! may take. It never decides which bytes are trusted: only descriptor sizes,
//! digests and the shared closure verifier do.

use std::collections::BTreeSet;
use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use rustls::pki_types::CertificateDer;
use ureq::tls::{Certificate, RootCerts};
use url::Url;

use crate::oci::ReleaseSourceErrorV1;

const MAX_ORIGINS: usize = 32;
const MAX_URL_BYTES: usize = 8_192;
const MAX_ROOTS: usize = 64;
const MAX_ROOT_BYTES: usize = 65_536;
const MAX_ROOT_SET_BYTES: usize = 1_048_576;
const MAX_AUTHORIZATION_BYTES: usize = 8_192;

/// One exact HTTPS origin: its canonical host and effective port.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct OriginV1 {
    host: String,
    port: u16,
}

impl OriginV1 {
    /// Return the canonical host as the URL parser serializes it.
    #[must_use]
    pub fn host(&self) -> &str {
        &self.host
    }

    /// Return the effective port (443 when the URL names none).
    #[must_use]
    pub const fn port(&self) -> u16 {
        self.port
    }

    /// The origin of an HTTPS URL. A parsed `https` URL always has a host and
    /// a known default port.
    pub(super) fn of(url: &Url) -> Self {
        Self {
            host: url.host_str().unwrap_or_default().to_owned(),
            port: url.port_or_known_default().unwrap_or(443),
        }
    }
}

/// The TLS root set of one remote transport. Certificate and host-name
/// verification are always on; there is no host or environment CA discovery
/// and no insecure mode.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TrustRootsV1 {
    /// The compiled `WebPki` root set. It is static: it has no automatic root
    /// updates and no online revocation checking.
    WebPki,
    /// An explicit DER root set: 1 to 64 distinct certificates, each at most
    /// 64 KiB and at most 1 MiB in total, every one parsed by the TLS stack.
    Der(Vec<Vec<u8>>),
}

impl TrustRootsV1 {
    fn validated(&self) -> Result<RootCerts, RemoteConfigErrorV1> {
        match self {
            Self::WebPki => Ok(RootCerts::WebPki),
            Self::Der(roots) => validated_der_roots(roots).map(RootCerts::from),
        }
    }
}

/// Validate the whole explicit set before use: never accept part of it and
/// never fall back to another root mode.
fn validated_der_roots(
    roots: &[Vec<u8>],
) -> Result<Vec<Certificate<'static>>, RemoteConfigErrorV1> {
    let distinct = roots.iter().map(Vec::as_slice).collect::<BTreeSet<_>>();
    if roots.is_empty()
        || roots.len() > MAX_ROOTS
        || distinct.len() != roots.len()
        || roots.iter().any(|root| root.len() > MAX_ROOT_BYTES)
        || roots.iter().map(Vec::len).sum::<usize>() > MAX_ROOT_SET_BYTES
    {
        return Err(RemoteConfigErrorV1::InvalidTrustRoots);
    }
    // `RootCertStore::add` rejects every certificate that the TLS client's own
    // `add_parsable_certificates` would silently ignore.
    let mut store = rustls::RootCertStore::empty();
    for root in roots {
        store
            .add(CertificateDer::from(root.as_slice()))
            .or(Err(RemoteConfigErrorV1::InvalidTrustRoots))?;
    }
    Ok(roots
        .iter()
        .map(|root| Certificate::from_der(root).to_owned())
        .collect())
}

/// Operational deadlines of one remote transport. Every value must be
/// non-zero and at most its `MAXIMUM`. They bound a read; they never change
/// artifact identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransportDeadlinesV1 {
    /// One monotonic deadline for a complete closure read.
    pub closure: Duration,
    /// The caller's wait for one name resolution.
    pub dns: Duration,
    /// TCP connection and TLS handshake together.
    pub connect: Duration,
    /// Receipt of one response's headers.
    pub response_headers: Duration,
    /// Receipt of one whole response body (not an inactivity timeout).
    pub response_body: Duration,
}

impl TransportDeadlinesV1 {
    /// The V1 maxima, which are also the defaults.
    pub const MAXIMUM: Self = Self {
        closure: Duration::from_mins(5),
        dns: Duration::from_secs(10),
        connect: Duration::from_secs(10),
        response_headers: Duration::from_secs(30),
        response_body: Duration::from_secs(30),
    };

    fn within_maximum(&self) -> bool {
        [
            (self.closure, Self::MAXIMUM.closure),
            (self.dns, Self::MAXIMUM.dns),
            (self.connect, Self::MAXIMUM.connect),
            (self.response_headers, Self::MAXIMUM.response_headers),
            (self.response_body, Self::MAXIMUM.response_body),
        ]
        .iter()
        .all(|(value, maximum)| !value.is_zero() && value <= maximum)
    }
}

impl Default for TransportDeadlinesV1 {
    fn default() -> Self {
        Self::MAXIMUM
    }
}

/// Typed transport credential material. It is never read from the
/// environment, netrc, container configuration or any key store, and its
/// `Debug` form never shows the secret.
#[derive(Clone, Eq, PartialEq)]
pub enum CredentialV1 {
    /// No `Authorization` header.
    Anonymous,
    /// HTTP Basic material. The username must not contain `:`; neither part
    /// may contain a control character.
    Basic {
        /// The user name.
        username: String,
        /// The password.
        password: String,
    },
    /// An HTTP Bearer token of visible ASCII characters.
    Bearer {
        /// The token.
        token: String,
    },
}

impl fmt::Debug for CredentialV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Anonymous => "Anonymous",
            Self::Basic { .. } => "Basic(<redacted>)",
            Self::Bearer { .. } => "Bearer(<redacted>)",
        })
    }
}

impl CredentialV1 {
    /// The encoded `Authorization` value, at most 8 KiB.
    fn authorization(&self) -> Result<Option<String>, ReleaseSourceErrorV1> {
        let value = match self {
            Self::Anonymous => return Ok(None),
            Self::Basic { username, password }
                if !username.contains(':')
                    && !username
                        .chars()
                        .chain(password.chars())
                        .any(char::is_control) =>
            {
                format!(
                    "Basic {}",
                    base64::engine::general_purpose::STANDARD
                        .encode(format!("{username}:{password}"))
                )
            }
            Self::Bearer { token }
                if !token.is_empty() && token.bytes().all(|byte| byte.is_ascii_graphic()) =>
            {
                format!("Bearer {token}")
            }
            Self::Basic { .. } | Self::Bearer { .. } => return Err(ReleaseSourceErrorV1::Io),
        };
        if value.len() > MAX_AUTHORIZATION_BYTES {
            Err(ReleaseSourceErrorV1::BoundsExceeded)
        } else {
            Ok(Some(value))
        }
    }
}

/// Trusted application code that supplies in-memory credentials.
///
/// A source asks once per configured locator on every closure read, retains
/// the answer only for that read, and sends it only to that locator's exact
/// origin. Redirected requests never carry it.
pub trait CredentialProviderV1: Send + Sync {
    /// The credential for one exact configured origin.
    fn credential(&self, origin: &OriginV1) -> CredentialV1;
}

/// Closed failures when configuring a remote release source.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum RemoteConfigErrorV1 {
    /// An allowed origin is not exactly `https://host[:port]`.
    #[error("remote origin is not an exact HTTPS origin")]
    InvalidOrigin,
    /// The allowed origin set is empty, has a duplicate, or exceeds 32.
    #[error("remote origin set is empty, duplicated or over its V1 bound")]
    InvalidOriginSet,
    /// The trust root set is invalid.
    #[error("remote trust roots are invalid")]
    InvalidTrustRoots,
    /// A deadline is zero or above its V1 maximum.
    #[error("remote deadline is zero or above its V1 maximum")]
    InvalidDeadline,
    /// A locator is not a valid HTTPS locator for its role.
    #[error("remote locator is invalid")]
    InvalidLocator,
    /// A locator's origin is not in the allowed origin set.
    #[error("remote locator origin is not allowed")]
    UnconfiguredOrigin,
}

/// The outbound authority of one remote transport: its exact allowed
/// origins, TLS roots, deadlines and optional credential provider.
///
/// Redirect targets must also be allowed origins: no response can extend
/// this set, and name resolution grants no authority.
#[derive(Clone)]
pub struct RemoteTransportConfigV1 {
    origins: BTreeSet<OriginV1>,
    roots: RootCerts,
    deadlines: TransportDeadlinesV1,
    credentials: Option<Arc<dyn CredentialProviderV1>>,
}

impl RemoteTransportConfigV1 {
    /// Create one validated transport configuration, with anonymous access.
    ///
    /// # Errors
    /// Returns `InvalidDeadline`, `InvalidOrigin`, `InvalidOriginSet` or
    /// `InvalidTrustRoots` for the first invalid part.
    pub fn new(
        allowed_origins: &[&str],
        roots: &TrustRootsV1,
        deadlines: TransportDeadlinesV1,
    ) -> Result<Self, RemoteConfigErrorV1> {
        if !deadlines.within_maximum() {
            return Err(RemoteConfigErrorV1::InvalidDeadline);
        }
        Ok(Self {
            origins: parse_origins(allowed_origins)?,
            roots: roots.validated()?,
            deadlines,
            credentials: None,
        })
    }

    /// Use `provider` for credentials instead of anonymous access.
    #[must_use]
    pub fn with_credentials(mut self, provider: Arc<dyn CredentialProviderV1>) -> Self {
        self.credentials = Some(provider);
        self
    }

    pub(super) const fn roots(&self) -> &RootCerts {
        &self.roots
    }

    pub(super) const fn deadlines(&self) -> &TransportDeadlinesV1 {
        &self.deadlines
    }

    /// Whether `url` may be requested: a valid request URL whose exact
    /// origin is allowed.
    pub(super) fn allows(&self, url: &Url) -> bool {
        requestable(url) && self.origins.contains(&OriginV1::of(url))
    }

    /// The `Authorization` value for a request to `url`'s origin.
    pub(super) fn authorization(&self, url: &Url) -> Result<Option<String>, ReleaseSourceErrorV1> {
        self.credentials.as_ref().map_or(Ok(None), |provider| {
            provider.credential(&OriginV1::of(url)).authorization()
        })
    }
}

/// Whether `url` is an HTTPS URL without userinfo or fragment, at most 8 KiB.
pub(super) fn requestable(url: &Url) -> bool {
    url.scheme() == "https"
        && url.username().is_empty()
        && url.password().is_none()
        && url.fragment().is_none()
        && url.as_str().len() <= MAX_URL_BYTES
}

fn parse_origins(allowed: &[&str]) -> Result<BTreeSet<OriginV1>, RemoteConfigErrorV1> {
    if allowed.is_empty() || allowed.len() > MAX_ORIGINS {
        return Err(RemoteConfigErrorV1::InvalidOriginSet);
    }
    let mut origins = BTreeSet::new();
    for text in allowed {
        let url = Url::parse(text)
            .ok()
            .filter(|url| requestable(url) && url.path() == "/" && url.query().is_none())
            .ok_or(RemoteConfigErrorV1::InvalidOrigin)?;
        if !origins.insert(OriginV1::of(&url)) {
            return Err(RemoteConfigErrorV1::InvalidOriginSet);
        }
    }
    Ok(origins)
}
