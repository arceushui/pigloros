#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

//! #426: the immutable-descriptor HTTPS release source at its public seam
//! (ADR-061 amendment revision 1).
//!
//! Every network case talks to an in-process TLS server on 127.0.0.1 that
//! uses the committed test-only fixtures in `vectors/https-tls` (see its
//! README). No case reaches the internet.
//!
//! The transport has one process-shared resolver that fails closed while a
//! lookup is outstanding, so network cases hold one process-wide lock: a
//! genuine shared resource, not test convenience.

use std::collections::BTreeMap;
use std::io::{Read as _, Write as _};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError};
use std::thread;
use std::time::{Duration, Instant};

use log::{Level, LevelFilter, Log, Metadata, Record};
use pos_plugin_release::{
    build_oci_closure_v1, CredentialProviderV1, CredentialV1, HttpsReleaseSourceV1, OriginV1,
    ReleaseClosureInputV1, ReleaseSourceErrorV1 as S, ReleaseSourceV1, RemoteConfigErrorV1 as C,
    RemoteTransportConfigV1, TransportDeadlinesV1, TrustRootsV1, VerifiedReleaseBundleV1,
    TRANSPORT_LOG_TARGETS_V1,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

type BoxError = Box<dyn std::error::Error>;
type TestResult = Result<(), BoxError>;

const TEST_CA: &[u8] = include_bytes!("vectors/https-tls/test-ca.der");
const OTHER_CA: &[u8] = include_bytes!("vectors/https-tls/other-ca.der");
const SERVER_CERT: &[u8] = include_bytes!("vectors/https-tls/server.der");
/// Test-only key of `SERVER_CERT`; it authorizes nothing outside these tests.
const SERVER_KEY: &[u8] = include_bytes!("vectors/https-tls/server.key.der");
const ROOT_SMALL: &[u8] = include_bytes!("vectors/https-tls/pad-root-small.der");
const ROOT_65536: &[u8] = include_bytes!("vectors/https-tls/pad-root-65536.der");
const ROOT_65537: &[u8] = include_bytes!("vectors/https-tls/pad-root-65537.der");
const ROOT_MARKER: &[u8] = b"PIGLOROS-ROOT-00";

const MANIFEST_PATH: &str = "/releases/manifest.json";
const BLOB_PREFIX: &str = "/blobs/";

static NETWORK: Mutex<()> = Mutex::new(());

#[cfg_attr(coverage_nightly, coverage(off))]
fn network() -> MutexGuard<'static, ()> {
    NETWORK.lock().unwrap_or_else(PoisonError::into_inner)
}

// ── In-process TLS server ───────────────────────────────────────────────

/// One scripted response: wait `delay`, write `head`, wait `stall`, write
/// `rest`, then close the TLS session.
#[derive(Clone)]
struct Reply {
    delay: Duration,
    head: Vec<u8>,
    stall: Duration,
    rest: Vec<u8>,
}

impl Reply {
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn raw(head: &str, rest: &[u8]) -> Self {
        Self {
            delay: Duration::ZERO,
            head: head.as_bytes().to_vec(),
            stall: Duration::ZERO,
            rest: rest.to_vec(),
        }
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn ok(body: &[u8]) -> Self {
        Self::raw(
            &format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            ),
            body,
        )
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn status(code: u16) -> Self {
        Self::raw(
            &format!("HTTP/1.1 {code} Status\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"),
            b"",
        )
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn redirect(code: u16, location: &str) -> Self {
        Self::raw(
            &format!(
                "HTTP/1.1 {code} Redirect\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            ),
            b"",
        )
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    const fn delayed(mut self, delay: Duration) -> Self {
        self.delay = delay;
        self
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    const fn stalled(mut self, stall: Duration) -> Self {
        self.stall = stall;
        self
    }
}

/// One request as the server saw it.
#[derive(Clone, Debug, Eq, PartialEq)]
struct Seen {
    target: String,
    authorization: Option<String>,
}

type Routes = Arc<Mutex<BTreeMap<String, Reply>>>;
type SeenLog = Arc<Mutex<Vec<Seen>>>;

struct Server {
    port: u16,
    routes: Routes,
    seen: SeenLog,
}

impl Server {
    /// A server presenting `chain` (the test-CA leaf by default).
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn start() -> Result<Self, BoxError> {
        Self::start_with(&[SERVER_CERT])
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn start_with(chain: &[&[u8]]) -> Result<Self, BoxError> {
        let certificates = chain
            .iter()
            .map(|certificate| CertificateDer::from(certificate.to_vec()))
            .collect();
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(SERVER_KEY.to_vec()));
        let config = Arc::new(
            rustls::ServerConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()?
            .with_no_client_auth()
            .with_single_cert(certificates, key)?,
        );
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let port = listener.local_addr()?.port();
        let routes = Routes::default();
        let seen = SeenLog::default();
        let (thread_routes, thread_seen) = (Arc::clone(&routes), Arc::clone(&seen));
        thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let (config, routes, seen) = (
                    Arc::clone(&config),
                    Arc::clone(&thread_routes),
                    Arc::clone(&thread_seen),
                );
                thread::spawn(move || drop(serve(stream, config, &routes, &seen)));
            }
        });
        Ok(Self { port, routes, seen })
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn origin(&self) -> String {
        format!("https://127.0.0.1:{}", self.port)
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.origin())
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn route(&self, target: &str, reply: Reply) {
        self.routes
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(target.to_owned(), reply);
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn seen(&self) -> Vec<Seen> {
        self.seen
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Serve every blob of `bundle` under `BLOB_PREFIX`, and its manifest at
    /// `MANIFEST_PATH`.
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn publish(&self, bundle: &VerifiedReleaseBundleV1) {
        self.route(MANIFEST_PATH, Reply::ok(bundle.manifest()));
        for blob in bundle.blobs() {
            self.route(&blob_path(blob.digest()), Reply::ok(blob.bytes()));
        }
    }
}

#[cfg_attr(coverage_nightly, coverage(off))]
fn serve(
    stream: TcpStream,
    config: Arc<rustls::ServerConfig>,
    routes: &Routes,
    seen: &SeenLog,
) -> Result<(), BoxError> {
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    let mut tls = rustls::StreamOwned::new(rustls::ServerConnection::new(config)?, stream);
    let mut request = Vec::new();
    let mut byte = [0_u8; 1];
    while !request.ends_with(b"\r\n\r\n") && request.len() < 65_536 {
        tls.read_exact(&mut byte)?;
        request.push(byte[0]);
    }
    let text = String::from_utf8_lossy(&request).into_owned();
    let target = text.split(' ').nth(1).unwrap_or_default().to_owned();
    let authorization = text.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.eq_ignore_ascii_case("authorization")
            .then(|| value.trim().to_owned())
    });
    seen.lock()
        .unwrap_or_else(PoisonError::into_inner)
        .push(Seen {
            target: target.clone(),
            authorization,
        });
    let reply = routes
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .get(&target)
        .cloned()
        .unwrap_or_else(|| Reply::status(404));
    thread::sleep(reply.delay);
    tls.write_all(&reply.head)?;
    tls.flush()?;
    thread::sleep(reply.stall);
    tls.write_all(&reply.rest)?;
    tls.conn.send_close_notify();
    tls.flush()?;
    Ok(())
}

// ── Fixtures ────────────────────────────────────────────────────────────

#[cfg_attr(coverage_nightly, coverage(off))]
fn bundle() -> Result<VerifiedReleaseBundleV1, BoxError> {
    bundle_with(b"pmf1")
}

#[cfg_attr(coverage_nightly, coverage(off))]
fn bundle_with(pmf1: &[u8]) -> Result<VerifiedReleaseBundleV1, BoxError> {
    Ok(build_oci_closure_v1(&ReleaseClosureInputV1 {
        pmf1,
        component: b"component",
        wit: b"wit",
        schemas: Vec::new(),
        provenance: b"provenance",
        sbom: b"sbom",
        licences: vec![b"licence"],
        migration_fixtures: Vec::new(),
    })?)
}

#[cfg_attr(coverage_nightly, coverage(off))]
fn blob_path(digest: &str) -> String {
    format!("{BLOB_PREFIX}{}", &digest["sha256:".len()..])
}

/// Short deadlines, so that every timeout case ends in seconds.
#[cfg_attr(coverage_nightly, coverage(off))]
const fn quick() -> TransportDeadlinesV1 {
    TransportDeadlinesV1 {
        closure: Duration::from_secs(20),
        dns: Duration::from_secs(5),
        connect: Duration::from_secs(5),
        response_headers: Duration::from_secs(5),
        response_body: Duration::from_secs(5),
    }
}

#[cfg_attr(coverage_nightly, coverage(off))]
fn test_roots() -> TrustRootsV1 {
    TrustRootsV1::Der(vec![TEST_CA.to_vec()])
}

#[cfg_attr(coverage_nightly, coverage(off))]
fn transport(origins: &[&str]) -> Result<RemoteTransportConfigV1, BoxError> {
    Ok(RemoteTransportConfigV1::new(
        origins,
        &test_roots(),
        quick(),
    )?)
}

/// A source for `bundle` with its manifest and blobs on `server`.
#[cfg_attr(coverage_nightly, coverage(off))]
fn source_on(
    server: &Server,
    bundle: &VerifiedReleaseBundleV1,
    transport: RemoteTransportConfigV1,
) -> Result<HttpsReleaseSourceV1, BoxError> {
    Ok(HttpsReleaseSourceV1::new(
        bundle.address().clone(),
        &server.url(MANIFEST_PATH),
        &server.url(BLOB_PREFIX),
        transport,
    )?)
}

/// Read `bundle` from `server` with only that origin allowed.
#[cfg_attr(coverage_nightly, coverage(off))]
fn read(
    server: &Server,
    bundle: &VerifiedReleaseBundleV1,
) -> Result<Result<VerifiedReleaseBundleV1, S>, BoxError> {
    let source = source_on(server, bundle, transport(&[&server.origin()])?)?;
    Ok(source.read_verified(bundle.address()))
}

/// The credential of each origin port, recording every origin asked.
struct Provider {
    credentials: BTreeMap<u16, CredentialV1>,
    asked: Mutex<Vec<(String, u16)>>,
}

impl Provider {
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn new(credentials: &[(u16, CredentialV1)]) -> Arc<Self> {
        Arc::new(Self {
            credentials: credentials.iter().cloned().collect(),
            asked: Mutex::new(Vec::new()),
        })
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn asked(&self) -> Vec<(String, u16)> {
        self.asked
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

impl CredentialProviderV1 for Provider {
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn credential(&self, origin: &OriginV1) -> CredentialV1 {
        self.asked
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push((origin.host().to_owned(), origin.port()));
        self.credentials
            .get(&origin.port())
            .cloned()
            .unwrap_or(CredentialV1::Anonymous)
    }
}

#[cfg_attr(coverage_nightly, coverage(off))]
fn bearer(token: &str) -> CredentialV1 {
    CredentialV1::Bearer {
        token: token.to_owned(),
    }
}

/// Read `bundle` from `server` with `credential` for its origin.
#[cfg_attr(coverage_nightly, coverage(off))]
fn read_as(
    server: &Server,
    bundle: &VerifiedReleaseBundleV1,
    credential: CredentialV1,
) -> Result<Result<VerifiedReleaseBundleV1, S>, BoxError> {
    let provider = Provider::new(&[(server.port, credential)]);
    let transport = transport(&[&server.origin()])?.with_credentials(provider);
    let source = source_on(server, bundle, transport)?;
    Ok(source.read_verified(bundle.address()))
}

// ── Reads through the public seam ───────────────────────────────────────

#[test]
#[cfg_attr(coverage_nightly, coverage(off))]
fn reads_the_same_verified_bundle_as_every_other_source() -> TestResult {
    let _network = network();
    let bundle = bundle()?;
    let server = Server::start()?;
    server.publish(&bundle);

    assert_eq!(read(&server, &bundle)??, bundle);

    // The manifest first, then every blob in digest order at
    // `<blob base><hex>`, all anonymous.
    let mut expected = vec![MANIFEST_PATH.to_owned()];
    expected.extend(bundle.blobs().iter().map(|blob| blob_path(blob.digest())));
    let seen = server.seen();
    assert_eq!(
        seen.iter()
            .map(|seen| seen.target.clone())
            .collect::<Vec<_>>(),
        expected
    );
    assert!(seen.iter().all(|seen| seen.authorization.is_none()));
    Ok(())
}

#[test]
#[cfg_attr(coverage_nightly, coverage(off))]
fn another_address_is_not_found_without_any_request() -> TestResult {
    let _network = network();
    let bundle = bundle()?;
    let other = bundle_with(b"other pmf1")?;
    let server = Server::start()?;
    server.publish(&bundle);
    let source = source_on(&server, &bundle, transport(&[&server.origin()])?)?;

    assert_eq!(source.read_verified(other.address()), Err(S::NotFound));
    assert!(server.seen().is_empty());
    Ok(())
}

#[test]
#[cfg_attr(coverage_nightly, coverage(off))]
fn missing_content_is_not_found_and_other_statuses_are_io() -> TestResult {
    let _network = network();
    let bundle = bundle()?;
    let server = Server::start()?;
    assert_eq!(read(&server, &bundle)?, Err(S::NotFound));

    server.route(MANIFEST_PATH, Reply::status(410));
    assert_eq!(read(&server, &bundle)?, Err(S::NotFound));

    for code in [204, 206, 304, 401, 403, 500] {
        server.route(MANIFEST_PATH, Reply::status(code));
        assert_eq!(read(&server, &bundle)?, Err(S::Io), "status {code}");
    }

    server.publish(&bundle);
    server.route(&blob_path(bundle.blobs()[1].digest()), Reply::status(404));
    assert_eq!(read(&server, &bundle)?, Err(S::NotFound));
    Ok(())
}

#[test]
#[cfg_attr(coverage_nightly, coverage(off))]
fn the_manifest_size_and_digest_are_checked_before_parsing() -> TestResult {
    let _network = network();
    let bundle = bundle()?;
    let server = Server::start()?;
    server.publish(&bundle);
    let manifest = bundle.manifest();

    // Same size, other bytes: the digest is compared before any parse.
    let mut altered = manifest.to_vec();
    altered[0] ^= 1;
    server.route(MANIFEST_PATH, Reply::ok(&altered));
    assert_eq!(read(&server, &bundle)?, Err(S::DigestMismatch));

    // A declared length other than the descriptor size, shorter or longer.
    let longer = [manifest, b" ".as_slice()].concat();
    for body in [&manifest[1..], &longer[..]] {
        server.route(MANIFEST_PATH, Reply::ok(body));
        assert_eq!(read(&server, &bundle)?, Err(S::SizeMismatch));
    }

    // Close-delimited bodies: one byte short, or one byte over the bound.
    let close = "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n";
    for body in [&manifest[1..], &longer[..]] {
        server.route(MANIFEST_PATH, Reply::raw(close, body));
        assert_eq!(read(&server, &bundle)?, Err(S::SizeMismatch));
    }

    // The exact bytes, close-delimited, are accepted.
    server.route(MANIFEST_PATH, Reply::raw(close, manifest));
    assert_eq!(read(&server, &bundle)??, bundle);
    Ok(())
}

#[test]
#[cfg_attr(coverage_nightly, coverage(off))]
fn a_truncated_download_fails_closed() -> TestResult {
    let _network = network();
    let bundle = bundle()?;
    let server = Server::start()?;
    server.publish(&bundle);
    let blob = &bundle.blobs()[2];
    let head = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        blob.bytes().len()
    );
    server.route(
        &blob_path(blob.digest()),
        Reply::raw(&head, &blob.bytes()[1..]),
    );
    assert_eq!(read(&server, &bundle)?, Err(S::Io));
    Ok(())
}

#[test]
#[cfg_attr(coverage_nightly, coverage(off))]
fn a_substituted_blob_is_a_digest_mismatch() -> TestResult {
    let _network = network();
    let bundle = bundle()?;
    let server = Server::start()?;
    server.publish(&bundle);
    let blob = &bundle.blobs()[3];
    let mut substituted = blob.bytes().to_vec();
    substituted[0] ^= 1;
    server.route(&blob_path(blob.digest()), Reply::ok(&substituted));
    assert_eq!(read(&server, &bundle)?, Err(S::DigestMismatch));
    Ok(())
}

#[test]
#[cfg_attr(coverage_nightly, coverage(off))]
fn only_identity_content_coding_is_accepted() -> TestResult {
    let _network = network();
    let bundle = bundle()?;
    let server = Server::start()?;
    server.publish(&bundle);
    let manifest = bundle.manifest();
    let coded = |coding: &str| {
        Reply::raw(
            &format!(
                "HTTP/1.1 200 OK\r\nContent-Encoding: {coding}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                manifest.len()
            ),
            manifest,
        )
    };
    server.route(MANIFEST_PATH, coded("gzip"));
    assert_eq!(read(&server, &bundle)?, Err(S::Io));
    server.route(MANIFEST_PATH, coded("identity"));
    assert_eq!(read(&server, &bundle)??, bundle);
    Ok(())
}

#[test]
#[cfg_attr(coverage_nightly, coverage(off))]
fn oversized_response_headers_exceed_the_bound() -> TestResult {
    let _network = network();
    let bundle = bundle()?;
    let server = Server::start()?;
    let padding = "a".repeat(40 * 1024);
    server.route(
        MANIFEST_PATH,
        Reply::raw(
            &format!("HTTP/1.1 200 OK\r\nX-Padding: {padding}\r\nContent-Length: 0\r\n\r\n"),
            b"",
        ),
    );
    assert_eq!(read(&server, &bundle)?, Err(S::BoundsExceeded));
    Ok(())
}

// ── Redirects ───────────────────────────────────────────────────────────

#[test]
#[cfg_attr(coverage_nightly, coverage(off))]
fn every_redirect_status_reaches_an_allowed_origin_without_credentials() -> TestResult {
    let _network = network();
    let bundle = bundle()?;
    let origin = Server::start()?;
    let mirror = Server::start()?;
    origin.publish(&bundle);
    mirror.publish(&bundle);
    for code in [301, 302, 303, 307, 308] {
        let target = format!("/mirror/{code}");
        mirror.route(&target, Reply::ok(bundle.manifest()));
        origin.route(MANIFEST_PATH, Reply::redirect(code, &mirror.url(&target)));
        let provider = Provider::new(&[
            (origin.port, bearer("origin-token")),
            (mirror.port, bearer("mirror-token")),
        ]);
        let transport =
            transport(&[&origin.origin(), &mirror.origin()])?.with_credentials(provider);
        let source = source_on(&origin, &bundle, transport)?;
        assert_eq!(source.read_verified(bundle.address())?, bundle, "{code}");
        let redirected = mirror
            .seen()
            .into_iter()
            .find(|seen| seen.target == target)
            .ok_or("the redirect was not followed")?;
        assert_eq!(redirected.authorization, None, "{code}");
    }
    assert!(origin
        .seen()
        .iter()
        .all(|seen| seen.authorization.as_deref() == Some("Bearer origin-token")));
    Ok(())
}

#[test]
#[cfg_attr(coverage_nightly, coverage(off))]
fn three_redirect_hops_are_followed_and_a_fourth_fails_closed() -> TestResult {
    let _network = network();
    let bundle = bundle()?;
    let server = Server::start()?;
    server.publish(&bundle);
    server.route("/hop/1", Reply::redirect(302, "/hop/2"));
    server.route("/hop/2", Reply::redirect(302, "3"));
    server.route("/hop/3", Reply::ok(bundle.manifest()));

    server.route(MANIFEST_PATH, Reply::redirect(302, "/hop/1"));
    assert_eq!(read(&server, &bundle)??, bundle);

    server.route("/hop/3", Reply::redirect(302, "/hop/4"));
    server.route("/hop/4", Reply::ok(bundle.manifest()));
    assert_eq!(read(&server, &bundle)?, Err(S::Io));
    assert!(!server.seen().iter().any(|seen| seen.target == "/hop/4"));
    Ok(())
}

#[test]
#[cfg_attr(coverage_nightly, coverage(off))]
fn a_redirect_loop_fails_closed() -> TestResult {
    let _network = network();
    let bundle = bundle()?;
    let server = Server::start()?;
    server.route(MANIFEST_PATH, Reply::redirect(307, "/loop"));
    server.route("/loop", Reply::redirect(307, MANIFEST_PATH));
    assert_eq!(read(&server, &bundle)?, Err(S::Io));
    assert_eq!(server.seen().len(), 2);
    Ok(())
}

#[test]
#[cfg_attr(coverage_nightly, coverage(off))]
fn a_redirect_cannot_extend_the_allowed_origins() -> TestResult {
    let _network = network();
    let bundle = bundle()?;
    let server = Server::start()?;
    let outsider = Server::start()?;
    outsider.publish(&bundle);
    server.route(
        MANIFEST_PATH,
        Reply::redirect(302, &outsider.url(MANIFEST_PATH)),
    );
    assert_eq!(read(&server, &bundle)?, Err(S::Io));
    assert!(outsider.seen().is_empty());
    Ok(())
}

#[test]
#[cfg_attr(coverage_nightly, coverage(off))]
fn invalid_redirects_fail_closed_before_any_connection() -> TestResult {
    let _network = network();
    let bundle = bundle()?;
    let server = Server::start()?;
    let port = server.port;
    let overlong = format!("/{}", "a".repeat(8_200));
    let invalid = [
        format!("http://127.0.0.1:{port}/plain"),
        format!("https://user@127.0.0.1:{port}/userinfo"),
        format!("https://:secret@127.0.0.1:{port}/password"),
        format!("https://127.0.0.1:{port}/fragment#part"),
        "https://[::1".to_owned(),
        overlong,
    ];
    for location in &invalid {
        server.route(MANIFEST_PATH, Reply::redirect(302, location));
        assert_eq!(read(&server, &bundle)?, Err(S::Io), "{location}");
    }
    let missing = "HTTP/1.1 302 Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
    let twice = "HTTP/1.1 302 Found\r\nLocation: /a\r\nLocation: /b\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
    for head in [missing, twice] {
        server.route(MANIFEST_PATH, Reply::raw(head, b""));
        assert_eq!(read(&server, &bundle)?, Err(S::Io));
    }
    let mut not_text = b"HTTP/1.1 302 Found\r\nLocation: /caf".to_vec();
    not_text.extend_from_slice(&[0xc3, 0xa9]);
    not_text.extend_from_slice(b"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
    server.route(
        MANIFEST_PATH,
        Reply {
            head: not_text,
            ..Reply::raw("", b"")
        },
    );
    assert_eq!(read(&server, &bundle)?, Err(S::Io));
    // Only the redirecting manifest requests ever reached the server.
    assert!(server
        .seen()
        .iter()
        .all(|seen| seen.target == MANIFEST_PATH));
    Ok(())
}

// ── Deadlines ───────────────────────────────────────────────────────────

#[cfg_attr(coverage_nightly, coverage(off))]
fn read_within(
    server: &Server,
    bundle: &VerifiedReleaseBundleV1,
    deadlines: TransportDeadlinesV1,
) -> Result<(Result<VerifiedReleaseBundleV1, S>, Duration), BoxError> {
    let transport = RemoteTransportConfigV1::new(&[&server.origin()], &test_roots(), deadlines)?;
    let source = source_on(server, bundle, transport)?;
    let started = Instant::now();
    let result = source.read_verified(bundle.address());
    Ok((result, started.elapsed()))
}

#[test]
#[cfg_attr(coverage_nightly, coverage(off))]
fn a_stalled_response_header_or_body_times_out() -> TestResult {
    let _network = network();
    let bundle = bundle()?;
    let server = Server::start()?;
    server.publish(&bundle);
    let deadlines = TransportDeadlinesV1 {
        response_headers: Duration::from_secs(1),
        response_body: Duration::from_secs(1),
        ..quick()
    };

    server.route(
        MANIFEST_PATH,
        Reply::ok(bundle.manifest()).delayed(Duration::from_secs(4)),
    );
    let (result, elapsed) = read_within(&server, &bundle, deadlines)?;
    assert_eq!(result, Err(S::Io));
    assert!(elapsed < Duration::from_secs(3), "{elapsed:?}");

    server.route(
        MANIFEST_PATH,
        Reply::ok(bundle.manifest()).stalled(Duration::from_secs(4)),
    );
    let (result, elapsed) = read_within(&server, &bundle, deadlines)?;
    assert_eq!(result, Err(S::Io));
    assert!(elapsed < Duration::from_secs(3), "{elapsed:?}");
    Ok(())
}

#[test]
#[cfg_attr(coverage_nightly, coverage(off))]
fn one_closure_deadline_bounds_every_request() -> TestResult {
    let _network = network();
    let bundle = bundle()?;
    let server = Server::start()?;
    // Each response alone is well inside its own deadline; together the
    // eight responses exceed the two-second closure deadline.
    let delay = Duration::from_millis(600);
    server.route(MANIFEST_PATH, Reply::ok(bundle.manifest()).delayed(delay));
    for blob in bundle.blobs() {
        server.route(
            &blob_path(blob.digest()),
            Reply::ok(blob.bytes()).delayed(delay),
        );
    }
    let deadlines = TransportDeadlinesV1 {
        closure: Duration::from_secs(2),
        ..quick()
    };
    let (result, elapsed) = read_within(&server, &bundle, deadlines)?;
    assert_eq!(result, Err(S::Io));
    assert!(elapsed < Duration::from_secs(4), "{elapsed:?}");
    assert!(server.seen().len() < bundle.blobs().len() + 1);
    Ok(())
}

#[test]
#[cfg_attr(coverage_nightly, coverage(off))]
fn a_refused_connection_fails_closed() -> TestResult {
    let _network = network();
    let bundle = bundle()?;
    let port = TcpListener::bind("127.0.0.1:0")?.local_addr()?.port();
    let origin = format!("https://127.0.0.1:{port}");
    let source = HttpsReleaseSourceV1::new(
        bundle.address().clone(),
        &format!("{origin}{MANIFEST_PATH}"),
        &format!("{origin}{BLOB_PREFIX}"),
        transport(&[&origin])?,
    )?;
    assert_eq!(source.read_verified(bundle.address()), Err(S::Io));
    Ok(())
}

// ── TLS roots ───────────────────────────────────────────────────────────

#[test]
#[cfg_attr(coverage_nightly, coverage(off))]
fn a_server_outside_the_configured_roots_is_refused() -> TestResult {
    let _network = network();
    let bundle = bundle()?;
    let server = Server::start()?;
    server.publish(&bundle);
    for roots in [
        TrustRootsV1::Der(vec![OTHER_CA.to_vec()]),
        TrustRootsV1::WebPki,
    ] {
        let transport = RemoteTransportConfigV1::new(&[&server.origin()], &roots, quick())?;
        let source = source_on(&server, &bundle, transport)?;
        assert_eq!(source.read_verified(bundle.address()), Err(S::Io));
    }
    // The TLS handshake failed, so no request was ever sent.
    assert!(server.seen().is_empty());
    Ok(())
}

// ── Credentials ─────────────────────────────────────────────────────────

#[test]
#[cfg_attr(coverage_nightly, coverage(off))]
fn typed_credentials_are_sent_only_to_their_own_origin() -> TestResult {
    let _network = network();
    let bundle = bundle()?;
    let manifests = Server::start()?;
    let blobs = Server::start()?;
    manifests.publish(&bundle);
    blobs.publish(&bundle);
    let provider = Provider::new(&[
        (
            manifests.port,
            CredentialV1::Basic {
                username: "reader".to_owned(),
                password: "pässword".to_owned(),
            },
        ),
        (blobs.port, bearer("blob-token")),
    ]);
    let transport = transport(&[&manifests.origin(), &blobs.origin()])?
        .with_credentials(Arc::clone(&provider) as Arc<dyn CredentialProviderV1>);
    let source = HttpsReleaseSourceV1::new(
        bundle.address().clone(),
        &manifests.url(MANIFEST_PATH),
        &blobs.url(BLOB_PREFIX),
        transport,
    )?;
    assert_eq!(source.read_verified(bundle.address())?, bundle);

    // base64("reader:pässword"), computed independently.
    assert_eq!(
        manifests.seen(),
        vec![Seen {
            target: MANIFEST_PATH.to_owned(),
            authorization: Some("Basic cmVhZGVyOnDDpHNzd29yZA==".to_owned()),
        }]
    );
    let blob_requests = blobs.seen();
    assert_eq!(blob_requests.len(), bundle.blobs().len());
    assert!(blob_requests
        .iter()
        .all(|seen| seen.authorization.as_deref() == Some("Bearer blob-token")));
    // Asked once per locator for the read, with each exact origin.
    assert_eq!(
        provider.asked(),
        vec![
            ("127.0.0.1".to_owned(), manifests.port),
            ("127.0.0.1".to_owned(), blobs.port),
        ]
    );
    Ok(())
}

#[test]
#[cfg_attr(coverage_nightly, coverage(off))]
fn an_anonymous_credential_sends_no_authorization() -> TestResult {
    let _network = network();
    let bundle = bundle()?;
    let server = Server::start()?;
    server.publish(&bundle);
    assert_eq!(read_as(&server, &bundle, CredentialV1::Anonymous)??, bundle);
    assert!(server
        .seen()
        .iter()
        .all(|seen| seen.authorization.is_none()));
    Ok(())
}

#[test]
#[cfg_attr(coverage_nightly, coverage(off))]
fn an_invalid_credential_fails_closed_before_any_request() -> TestResult {
    let _network = network();
    let bundle = bundle()?;
    let server = Server::start()?;
    server.publish(&bundle);
    let basic = |username: &str, password: &str| CredentialV1::Basic {
        username: username.to_owned(),
        password: password.to_owned(),
    };
    for credential in [
        bearer(""),
        bearer("two words"),
        bearer("control\u{7f}"),
        basic("user:name", "password"),
        basic("user\nname", "password"),
        basic("user", "pass\u{0}word"),
    ] {
        assert_eq!(
            read_as(&server, &bundle, credential.clone())?,
            Err(S::Io),
            "{credential:?}"
        );
    }
    // The encoded value is bounded to 8 KiB: exactly 8 KiB is sent.
    let bound = 8_192 - "Bearer ".len();
    assert_eq!(
        read_as(&server, &bundle, bearer(&"t".repeat(bound + 1)))?,
        Err(S::BoundsExceeded)
    );
    assert!(server.seen().is_empty());
    assert_eq!(
        read_as(&server, &bundle, bearer(&"t".repeat(bound)))??,
        bundle
    );
    Ok(())
}

#[test]
#[cfg_attr(coverage_nightly, coverage(off))]
fn a_credential_never_shows_its_secret_in_debug_output() {
    let shown = [
        format!("{:?}", bearer("bearer-secret")),
        format!(
            "{:?}",
            CredentialV1::Basic {
                username: "user-secret".to_owned(),
                password: "password-secret".to_owned(),
            }
        ),
        format!("{:?}", CredentialV1::Anonymous),
    ];
    assert_eq!(
        shown,
        [
            "Bearer(<redacted>)".to_owned(),
            "Basic(<redacted>)".to_owned(),
            "Anonymous".to_owned()
        ]
    );
}

// ── Configuration ───────────────────────────────────────────────────────

#[cfg_attr(coverage_nightly, coverage(off))]
fn configure(origins: &[&str]) -> Result<RemoteTransportConfigV1, C> {
    RemoteTransportConfigV1::new(origins, &test_roots(), TransportDeadlinesV1::default())
}

#[cfg_attr(coverage_nightly, coverage(off))]
fn configure_err(origins: &[&str]) -> Option<C> {
    configure(origins).err()
}

#[test]
#[cfg_attr(coverage_nightly, coverage(off))]
fn allowed_origins_are_exact_bounded_and_distinct() {
    for invalid in [
        "http://a.test",
        "https://a.test/path",
        "https://a.test/?query",
        "https://user@a.test",
        "https://:password@a.test",
        "https://a.test/#fragment",
        "not a url",
    ] {
        assert_eq!(
            configure_err(&[invalid]),
            Some(C::InvalidOrigin),
            "{invalid}"
        );
    }
    assert_eq!(configure_err(&[]), Some(C::InvalidOriginSet));
    assert_eq!(
        configure_err(&["https://a.test", "https://A.test:443/"]),
        Some(C::InvalidOriginSet)
    );
    let origins = (0..33)
        .map(|index| format!("https://origin-{index}.test"))
        .collect::<Vec<_>>();
    let origins = origins.iter().map(String::as_str).collect::<Vec<_>>();
    assert!(configure(&origins[..32]).is_ok());
    assert_eq!(configure_err(&origins), Some(C::InvalidOriginSet));
}

#[test]
#[cfg_attr(coverage_nightly, coverage(off))]
fn deadlines_are_non_zero_and_within_their_maxima() {
    let maximum = TransportDeadlinesV1::MAXIMUM;
    assert_eq!(TransportDeadlinesV1::default(), maximum);
    let check = |deadlines: TransportDeadlinesV1| {
        RemoteTransportConfigV1::new(&["https://a.test"], &test_roots(), deadlines).err()
    };
    assert_eq!(check(maximum), None);
    let over = Duration::from_nanos(1);
    for deadlines in [
        TransportDeadlinesV1 {
            closure: maximum.closure + over,
            ..maximum
        },
        TransportDeadlinesV1 {
            dns: maximum.dns + over,
            ..maximum
        },
        TransportDeadlinesV1 {
            connect: maximum.connect + over,
            ..maximum
        },
        TransportDeadlinesV1 {
            response_headers: maximum.response_headers + over,
            ..maximum
        },
        TransportDeadlinesV1 {
            response_body: maximum.response_body + over,
            ..maximum
        },
        TransportDeadlinesV1 {
            dns: Duration::ZERO,
            ..maximum
        },
    ] {
        assert_eq!(check(deadlines), Some(C::InvalidDeadline), "{deadlines:?}");
    }
    assert_eq!(
        maximum,
        TransportDeadlinesV1 {
            closure: Duration::from_mins(5),
            dns: Duration::from_secs(10),
            connect: Duration::from_secs(10),
            response_headers: Duration::from_secs(30),
            response_body: Duration::from_secs(30),
        }
    );
}

/// A distinct copy of a padded root fixture. The marker sits inside a
/// non-critical extension, and root parsing does not check the signature.
#[cfg_attr(coverage_nightly, coverage(off))]
fn root_variant(template: &[u8], index: usize) -> Result<Vec<u8>, BoxError> {
    let at = template
        .windows(ROOT_MARKER.len())
        .position(|window| window == ROOT_MARKER)
        .ok_or("the root fixture has no marker")?;
    let mut root = template.to_vec();
    let suffix = format!("{index:02x}");
    root[at + ROOT_MARKER.len() - 2..at + ROOT_MARKER.len()].copy_from_slice(suffix.as_bytes());
    Ok(root)
}

#[cfg_attr(coverage_nightly, coverage(off))]
fn roots_err(roots: Vec<Vec<u8>>) -> Option<C> {
    RemoteTransportConfigV1::new(
        &["https://a.test"],
        &TrustRootsV1::Der(roots),
        TransportDeadlinesV1::default(),
    )
    .err()
}

#[test]
#[cfg_attr(coverage_nightly, coverage(off))]
fn explicit_roots_are_bounded_distinct_and_fully_parsed() -> TestResult {
    let invalid = Some(C::InvalidTrustRoots);
    assert_eq!(roots_err(Vec::new()), invalid);
    assert_eq!(roots_err(vec![b"not a certificate".to_vec()]), invalid);
    assert_eq!(
        roots_err(vec![TEST_CA.to_vec(), b"not a certificate".to_vec()]),
        invalid
    );
    assert_eq!(roots_err(vec![TEST_CA.to_vec(), TEST_CA.to_vec()]), invalid);
    assert_eq!(roots_err(vec![TEST_CA.to_vec(), OTHER_CA.to_vec()]), None);

    // At most 64 certificates.
    let small = (0..65)
        .map(|index| root_variant(ROOT_SMALL, index))
        .collect::<Result<Vec<_>, _>>()?;
    assert_eq!(roots_err(small[..64].to_vec()), None);
    assert_eq!(roots_err(small), invalid);

    // At most 64 KiB each.
    assert_eq!(ROOT_65536.len(), 65_536);
    assert_eq!(ROOT_65537.len(), 65_537);
    assert_eq!(roots_err(vec![ROOT_65536.to_vec()]), None);
    assert_eq!(roots_err(vec![ROOT_65537.to_vec()]), invalid);

    // At most 1 MiB in total.
    let mut large = (0..16)
        .map(|index| root_variant(ROOT_65536, index))
        .collect::<Result<Vec<_>, _>>()?;
    assert_eq!(roots_err(large.clone()), None);
    large.push(ROOT_SMALL.to_vec());
    assert_eq!(roots_err(large), invalid);
    Ok(())
}

#[cfg_attr(coverage_nightly, coverage(off))]
fn locate(manifest: &str, blobs: &str) -> Result<Option<C>, BoxError> {
    let bundle = bundle()?;
    Ok(HttpsReleaseSourceV1::new(
        bundle.address().clone(),
        manifest,
        blobs,
        configure(&["https://a.test"])?,
    )
    .err())
}

#[test]
#[cfg_attr(coverage_nightly, coverage(off))]
fn locators_are_immutable_https_locations_on_allowed_origins() -> TestResult {
    let blobs = "https://a.test/blobs/";
    assert_eq!(locate("https://a.test/m?signature=x", blobs)?, None);
    for manifest in [
        "http://a.test/m",
        "https://user@a.test/m",
        "https://:password@a.test/m",
        "https://a.test/m#fragment",
        "not a url",
    ] {
        assert_eq!(
            locate(manifest, blobs)?,
            Some(C::InvalidLocator),
            "{manifest}"
        );
    }
    for blob_base in ["https://a.test/blobs", "https://a.test/blobs/?query"] {
        assert_eq!(
            locate("https://a.test/m", blob_base)?,
            Some(C::InvalidLocator),
            "{blob_base}"
        );
    }
    assert_eq!(
        locate("https://b.test/m", blobs)?,
        Some(C::UnconfiguredOrigin)
    );
    assert_eq!(
        locate("https://a.test/m", "https://a.test:8443/blobs/")?,
        Some(C::UnconfiguredOrigin)
    );

    // A locator is at most 8 KiB.
    let prefix = "https://a.test/";
    let exact = format!("{prefix}{}", "m".repeat(8_192 - prefix.len()));
    assert_eq!(exact.len(), 8_192);
    assert_eq!(locate(&exact, blobs)?, None);
    assert_eq!(
        locate(&format!("{exact}m"), blobs)?,
        Some(C::InvalidLocator)
    );
    Ok(())
}

// ── Diagnostic disclosure ───────────────────────────────────────────────

/// Every log record of this process, at every level.
struct Capture(Mutex<Vec<(Level, String, String)>>);

impl Log for Capture {
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn enabled(&self, _metadata: &Metadata<'_>) -> bool {
        true
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn log(&self, record: &Record<'_>) {
        self.0.lock().unwrap_or_else(PoisonError::into_inner).push((
            record.level(),
            record.target().to_owned(),
            record.args().to_string(),
        ));
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn flush(&self) {}
}

#[cfg_attr(coverage_nightly, coverage(off))]
fn capture() -> Result<&'static Capture, BoxError> {
    static CAPTURE: OnceLock<Capture> = OnceLock::new();
    let capture = CAPTURE.get_or_init(|| Capture(Mutex::new(Vec::new())));
    log::set_logger(capture).map_err(|error| error.to_string())?;
    log::set_max_level(LevelFilter::Trace);
    Ok(capture)
}

#[test]
#[cfg_attr(coverage_nightly, coverage(off))]
fn the_production_log_ceiling_hides_every_secret_and_names_every_target() -> TestResult {
    let _network = network();
    let capture = capture()?;
    let secrets = [
        "LOG-SECRET-TOKEN",
        "LOG-SECRET-PASSWORD",
        // base64("reader:LOG-SECRET-PASSWORD")
        "cmVhZGVyOkxPRy1TRUNSRVQtUEFTU1dPUkQ",
        "LOG-SECRET-SIGNATURE",
        "LOG-SECRET-BODY",
    ];
    let bundle = bundle_with(b"LOG-SECRET-BODY")?;
    let server = Server::start()?;
    server.publish(&bundle);
    let signed = "/signed?X-Signature=LOG-SECRET-SIGNATURE";
    server.route(signed, Reply::ok(bundle.manifest()));
    server.route(MANIFEST_PATH, Reply::redirect(307, signed));

    // A Bearer read through a signed redirect, a Basic read, and a failure.
    assert_eq!(
        read_as(&server, &bundle, bearer("LOG-SECRET-TOKEN"))??,
        bundle
    );
    let basic = CredentialV1::Basic {
        username: "reader".to_owned(),
        password: "LOG-SECRET-PASSWORD".to_owned(),
    };
    assert_eq!(read_as(&server, &bundle, basic.clone())??, bundle);
    server.route(signed, Reply::status(404));
    assert_eq!(read_as(&server, &bundle, basic)?, Err(S::NotFound));

    let records = capture
        .0
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .clone();
    // The probe is live: the transport libraries did log below INFO.
    assert!(records
        .iter()
        .any(|(level, target, _)| *level > Level::Info && target.starts_with("ureq")));
    // Every target emitted below INFO is one the host must cap.
    let capped = |target: &str| {
        TRANSPORT_LOG_TARGETS_V1.iter().any(|prefix| {
            target == *prefix
                || target
                    .strip_prefix(prefix)
                    .is_some_and(|rest| rest.starts_with("::"))
        })
    };
    for (level, target, _) in &records {
        assert!(
            *level <= Level::Info || capped(target.as_str()),
            "{level} {target}"
        );
    }
    // At the INFO ceiling, no secret, signed query value or body is shown.
    for (level, target, message) in records.iter().filter(|(level, ..)| *level <= Level::Info) {
        for secret in secrets {
            assert!(
                !message.contains(secret) && !target.contains(secret),
                "{level} {target}"
            );
        }
    }
    Ok(())
}
