#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

//! #427: the immutable-digest OCI registry release source at its public seam
//! (ADR-061 amendment revision 1).
//!
//! Every network case talks to in-process TLS servers on 127.0.0.1 that use
//! the committed test-only fixtures in `vectors/https-tls` (see its README).
//! No case reaches the internet.
//!
//! The transport has one process-shared resolver that fails closed while a
//! lookup is outstanding, so network cases hold one process-wide lock: a
//! genuine shared resource, not test convenience.

use std::collections::BTreeMap;
use std::io::{Read as _, Write as _};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError};
use std::thread;
use std::time::Duration;

use log::{Level, LevelFilter, Log, Metadata, Record};
use pos_plugin_release::{
    build_oci_closure_v1, CredentialProviderV1, CredentialV1, OciReleaseSourceV1, OriginV1,
    ReleaseClosureInputV1, ReleaseSourceErrorV1 as S, ReleaseSourceV1, RemoteConfigErrorV1 as C,
    RemoteTransportConfigV1, TransportDeadlinesV1, TrustRootsV1, VerifiedReleaseBundleV1,
    TRANSPORT_LOG_TARGETS_V1,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

type BoxError = Box<dyn std::error::Error>;
type TestResult = Result<(), BoxError>;
type Read = Result<Result<VerifiedReleaseBundleV1, S>, BoxError>;

const TEST_CA: &[u8] = include_bytes!("vectors/https-tls/test-ca.der");
const OTHER_CA: &[u8] = include_bytes!("vectors/https-tls/other-ca.der");
const SERVER_CERT: &[u8] = include_bytes!("vectors/https-tls/server.der");
/// Test-only key of `SERVER_CERT`; it authorizes nothing outside these tests.
const SERVER_KEY: &[u8] = include_bytes!("vectors/https-tls/server.key.der");

const REPOSITORY: &str = "acme/plugin";
const SERVICE: &str = "registry.test";
const MANIFEST_MEDIA_TYPE: &str = "application/vnd.oci.image.manifest.v1+json";
/// The `Accept` the HTTP client sends when none is set.
const DEFAULT_ACCEPT: &str = "*/*";
const SCOPE: &str = "repository:acme/plugin:pull";
/// The query of every token request: `service` first, then the exact scope.
const TOKEN_QUERY: &str = "service=registry.test&scope=repository%3Aacme%2Fplugin%3Apull";

static NETWORK: Mutex<()> = Mutex::new(());

#[cfg_attr(coverage_nightly, coverage(off))]
fn network() -> MutexGuard<'static, ()> {
    NETWORK.lock().unwrap_or_else(PoisonError::into_inner)
}

// ── In-process TLS server ───────────────────────────────────────────────

/// One scripted response: write `head`, then `rest`, then close the session.
#[derive(Clone)]
struct Reply {
    head: Vec<u8>,
    rest: Vec<u8>,
}

impl Reply {
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn raw(head: &str, rest: &[u8]) -> Self {
        Self {
            head: head.as_bytes().to_vec(),
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

    /// A 401 answer carrying one `WWW-Authenticate` header per value.
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn unauthorized(challenges: &[&[u8]]) -> Self {
        let mut head = b"HTTP/1.1 401 Unauthorized\r\n".to_vec();
        for challenge in challenges {
            head.extend_from_slice(b"WWW-Authenticate: ");
            head.extend_from_slice(challenge);
            head.extend_from_slice(b"\r\n");
        }
        head.extend_from_slice(b"Content-Length: 0\r\nConnection: close\r\n\r\n");
        Self {
            head,
            rest: Vec::new(),
        }
    }
}

/// One request as the server saw it.
#[derive(Clone, Debug, Eq, PartialEq)]
struct Seen {
    target: String,
    authorization: Option<String>,
    accept: Option<String>,
}

/// The scripted replies of one target. Each request takes the next reply;
/// the last one repeats.
struct Script {
    replies: Vec<Reply>,
    hits: usize,
}

/// `(target, Some(authorization))` matches only that `Authorization`;
/// `(target, None)` matches any other request.
type Routes = Arc<Mutex<BTreeMap<(String, Option<String>), Script>>>;
type SeenLog = Arc<Mutex<Vec<Seen>>>;

struct Server {
    port: u16,
    routes: Routes,
    seen: SeenLog,
}

impl Server {
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn start() -> Result<Self, BoxError> {
        let certificates = vec![CertificateDer::from(SERVER_CERT.to_vec())];
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
                thread::spawn(move || drop(serve(stream, &config, &routes, &seen)));
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

    /// Answer every request for `target` with `reply`, unless a more
    /// specific `route_for` applies.
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn route(&self, target: &str, reply: Reply) {
        self.route_sequence(target, None, vec![reply]);
    }

    /// Answer only requests for `target` carrying exactly `authorization`.
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn route_for(&self, target: &str, authorization: &str, reply: Reply) {
        self.route_sequence(target, Some(authorization), vec![reply]);
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn route_sequence(&self, target: &str, authorization: Option<&str>, replies: Vec<Reply>) {
        self.routes
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(
                (target.to_owned(), authorization.map(str::to_owned)),
                Script { replies, hits: 0 },
            );
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn seen(&self) -> Vec<Seen> {
        self.seen
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn targets(&self) -> Vec<String> {
        self.seen().into_iter().map(|seen| seen.target).collect()
    }

    /// Serve the manifest and every blob of `bundle` to any request.
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn publish(&self, bundle: &VerifiedReleaseBundleV1) {
        for (path, bytes) in objects(bundle) {
            self.route(&path, Reply::ok(&bytes));
        }
    }
}

#[cfg_attr(coverage_nightly, coverage(off))]
fn serve(
    stream: TcpStream,
    config: &Arc<rustls::ServerConfig>,
    routes: &Routes,
    seen: &SeenLog,
) -> Result<(), BoxError> {
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    let mut tls =
        rustls::StreamOwned::new(rustls::ServerConnection::new(Arc::clone(config))?, stream);
    let mut request = Vec::new();
    let mut byte = [0_u8; 1];
    while !request.ends_with(b"\r\n\r\n") && request.len() < 65_536 {
        tls.read_exact(&mut byte)?;
        request.push(byte[0]);
    }
    let text = String::from_utf8_lossy(&request).into_owned();
    let target = text.split(' ').nth(1).unwrap_or_default().to_owned();
    let header = |wanted: &str| {
        text.lines().find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case(wanted)
                .then(|| value.trim().to_owned())
        })
    };
    let authorization = header("authorization");
    seen.lock()
        .unwrap_or_else(PoisonError::into_inner)
        .push(Seen {
            target: target.clone(),
            authorization: authorization.clone(),
            accept: header("accept"),
        });
    let reply = {
        let mut routes = routes.lock().unwrap_or_else(PoisonError::into_inner);
        let key = [(target.clone(), authorization), (target, None)]
            .into_iter()
            .find(|key| routes.contains_key(key));
        key.and_then(|key| routes.get_mut(&key)).map_or_else(
            || Reply::status(404),
            |script| {
                let reply = script.replies[script.hits.min(script.replies.len() - 1)].clone();
                script.hits += 1;
                reply
            },
        )
    };
    tls.write_all(&reply.head)?;
    tls.flush()?;
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
fn manifest_path(digest: &str) -> String {
    format!("/v2/{REPOSITORY}/manifests/{digest}")
}

#[cfg_attr(coverage_nightly, coverage(off))]
fn blob_path(digest: &str) -> String {
    format!("/v2/{REPOSITORY}/blobs/{digest}")
}

/// The request path and bytes of the manifest, then every blob.
#[cfg_attr(coverage_nightly, coverage(off))]
fn objects(bundle: &VerifiedReleaseBundleV1) -> Vec<(String, Vec<u8>)> {
    let mut objects = vec![(
        manifest_path(bundle.address().digest()),
        bundle.manifest().to_vec(),
    )];
    objects.extend(
        bundle
            .blobs()
            .iter()
            .map(|blob| (blob_path(blob.digest()), blob.bytes().to_vec())),
    );
    objects
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
fn transport(servers: &[&Server]) -> Result<RemoteTransportConfigV1, BoxError> {
    let origins = servers
        .iter()
        .map(|server| server.origin())
        .collect::<Vec<_>>();
    let origins = origins.iter().map(String::as_str).collect::<Vec<_>>();
    Ok(RemoteTransportConfigV1::new(
        &origins,
        &test_roots(),
        quick(),
    )?)
}

/// The credential of each origin port, recording every origin asked.
struct Provider {
    credentials: BTreeMap<u16, CredentialV1>,
    asked: Mutex<Vec<u16>>,
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
    fn asked(&self) -> Vec<u16> {
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
            .push(origin.port());
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

#[cfg_attr(coverage_nightly, coverage(off))]
fn basic(username: &str, password: &str) -> CredentialV1 {
    CredentialV1::Basic {
        username: username.to_owned(),
        password: password.to_owned(),
    }
}

/// Read `bundle` anonymously from the repository on `server`, which is the
/// only allowed origin.
#[cfg_attr(coverage_nightly, coverage(off))]
fn read(server: &Server, bundle: &VerifiedReleaseBundleV1) -> Read {
    let source =
        OciReleaseSourceV1::new(&server.origin(), REPOSITORY, None, transport(&[server])?)?;
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
    // The ring provider was set on the transport only, never process-wide.
    assert!(rustls::crypto::CryptoProvider::get_default().is_none());

    // The manifest first, then every blob in digest order, all anonymous and
    // addressed by digest. Only the manifest names its media type.
    let seen = server.seen();
    let expected = objects(&bundle)
        .into_iter()
        .map(|(path, _)| path)
        .collect::<Vec<_>>();
    assert_eq!(
        seen.iter()
            .map(|seen| seen.target.clone())
            .collect::<Vec<_>>(),
        expected
    );
    assert!(seen.iter().all(|seen| seen.authorization.is_none()));
    assert_eq!(seen[0].accept.as_deref(), Some(MANIFEST_MEDIA_TYPE));
    // The HTTP client's own default `Accept` is all a blob request carries.
    assert!(seen[1..]
        .iter()
        .all(|seen| seen.accept.as_deref() == Some(DEFAULT_ACCEPT)));
    Ok(())
}

#[test]
#[cfg_attr(coverage_nightly, coverage(off))]
fn the_requested_address_is_the_only_identity() -> TestResult {
    let _network = network();
    let (first, second) = (bundle_with(b"first")?, bundle_with(b"second")?);
    assert_ne!(first.address(), second.address());
    let server = Server::start()?;
    server.publish(&first);
    server.publish(&second);
    let source =
        OciReleaseSourceV1::new(&server.origin(), REPOSITORY, None, transport(&[&server])?)?;

    // One source serves any address by digest; a tag is never used.
    assert_eq!(source.read_verified(first.address())?, first);
    assert_eq!(source.read_verified(second.address())?, second);
    let third = bundle_with(b"third")?;
    assert_eq!(source.read_verified(third.address()), Err(S::NotFound));
    assert_eq!(
        server.targets().last().cloned(),
        Some(manifest_path(third.address().digest()))
    );
    assert!(server
        .targets()
        .iter()
        .all(|target| target.contains("sha256:")));
    Ok(())
}

#[test]
#[cfg_attr(coverage_nightly, coverage(off))]
fn nested_repositories_are_addressed_exactly() -> TestResult {
    let _network = network();
    let bundle = bundle()?;
    let server = Server::start()?;
    let repository = "team.one/sub_dir__x/plug-in---y";
    let digest = bundle.address().digest();
    server.route(
        &format!("/v2/{repository}/manifests/{digest}"),
        Reply::ok(bundle.manifest()),
    );
    for blob in bundle.blobs() {
        server.route(
            &format!("/v2/{repository}/blobs/{}", blob.digest()),
            Reply::ok(blob.bytes()),
        );
    }
    let source =
        OciReleaseSourceV1::new(&server.origin(), repository, None, transport(&[&server])?)?;
    assert_eq!(source.read_verified(bundle.address())?, bundle);
    Ok(())
}

#[test]
#[cfg_attr(coverage_nightly, coverage(off))]
fn missing_content_is_not_found_and_other_statuses_are_io() -> TestResult {
    let _network = network();
    let bundle = bundle()?;
    let server = Server::start()?;
    let manifest = manifest_path(bundle.address().digest());
    assert_eq!(read(&server, &bundle)?, Err(S::NotFound));

    server.route(&manifest, Reply::status(410));
    assert_eq!(read(&server, &bundle)?, Err(S::NotFound));

    for code in [204, 206, 304, 403, 500] {
        server.route(&manifest, Reply::status(code));
        assert_eq!(read(&server, &bundle)?, Err(S::Io), "status {code}");
    }

    // Without a configured challenge flow, a 401 is no reason to continue.
    server.route(&manifest, Reply::unauthorized(&[]));
    assert_eq!(read(&server, &bundle)?, Err(S::Io));

    server.publish(&bundle);
    server.route(&blob_path(bundle.blobs()[1].digest()), Reply::status(404));
    assert_eq!(read(&server, &bundle)?, Err(S::NotFound));
    Ok(())
}

#[test]
#[cfg_attr(coverage_nightly, coverage(off))]
fn registry_bytes_are_verified_against_the_descriptors() -> TestResult {
    let _network = network();
    let bundle = bundle()?;
    let server = Server::start()?;
    server.publish(&bundle);
    let manifest = manifest_path(bundle.address().digest());

    // Same size, other bytes: the digest is compared before any parse.
    let mut altered = bundle.manifest().to_vec();
    altered[0] ^= 1;
    server.route(&manifest, Reply::ok(&altered));
    assert_eq!(read(&server, &bundle)?, Err(S::DigestMismatch));

    // A declared length other than the descriptor size.
    server.route(&manifest, Reply::ok(&bundle.manifest()[1..]));
    assert_eq!(read(&server, &bundle)?, Err(S::SizeMismatch));
    server.route(&manifest, Reply::ok(bundle.manifest()));

    // A substituted blob of the right size.
    let blob = &bundle.blobs()[3];
    let mut substituted = blob.bytes().to_vec();
    substituted[0] ^= 1;
    server.route(&blob_path(blob.digest()), Reply::ok(&substituted));
    assert_eq!(read(&server, &bundle)?, Err(S::DigestMismatch));

    // A truncated download.
    let blob = &bundle.blobs()[2];
    let head = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        blob.bytes().len()
    );
    server.publish(&bundle);
    server.route(
        &blob_path(blob.digest()),
        Reply::raw(&head, &blob.bytes()[1..]),
    );
    assert_eq!(read(&server, &bundle)?, Err(S::Io));
    Ok(())
}

// ── Redirects ───────────────────────────────────────────────────────────

#[test]
#[cfg_attr(coverage_nightly, coverage(off))]
fn a_blob_redirect_to_a_configured_origin_carries_no_credential() -> TestResult {
    let _network = network();
    let bundle = bundle()?;
    let (registry, cdn) = (Server::start()?, Server::start()?);
    registry.publish(&bundle);
    let blob = &bundle.blobs()[1];
    registry.route(
        &blob_path(blob.digest()),
        Reply::redirect(307, &cdn.url("/cdn/blob?X-Signature=signed")),
    );
    cdn.route("/cdn/blob?X-Signature=signed", Reply::ok(blob.bytes()));

    let provider = Provider::new(&[(registry.port, bearer("registry-secret"))]);
    let transport = transport(&[&registry, &cdn])?.with_credentials(provider);
    let source = OciReleaseSourceV1::new(&registry.origin(), REPOSITORY, None, transport)?;
    assert_eq!(source.read_verified(bundle.address())?, bundle);
    assert!(registry
        .seen()
        .iter()
        .all(|seen| seen.authorization.as_deref() == Some("Bearer registry-secret")));
    assert_eq!(
        cdn.seen(),
        vec![Seen {
            target: "/cdn/blob?X-Signature=signed".to_owned(),
            authorization: None,
            accept: Some(DEFAULT_ACCEPT.to_owned()),
        }]
    );
    Ok(())
}

#[test]
#[cfg_attr(coverage_nightly, coverage(off))]
fn a_redirect_target_never_starts_authentication() -> TestResult {
    let _network = network();
    let bundle = bundle()?;
    let (registry, tokens, cdn) = (Server::start()?, Server::start()?, Server::start()?);
    let manifest = manifest_path(bundle.address().digest());
    registry.route(&manifest, Reply::redirect(302, &cdn.url("/m")));
    let realm = tokens.url("/token");
    cdn.route(
        "/m",
        Reply::unauthorized(
            &[format!("Bearer realm=\"{realm}\",service=\"{SERVICE}\"").as_bytes()],
        ),
    );
    tokens.route(
        &format!("/token?{TOKEN_QUERY}"),
        Reply::ok(br#"{"token":"never-used"}"#),
    );
    let source = OciReleaseSourceV1::new(
        &registry.origin(),
        REPOSITORY,
        Some(SERVICE),
        transport(&[&registry, &cdn, &tokens])?,
    )?;
    assert_eq!(source.read_verified(bundle.address()), Err(S::Io));
    assert_eq!(cdn.targets(), vec!["/m".to_owned()]);
    assert!(tokens.seen().is_empty());
    Ok(())
}

// ── The registry Bearer flow ────────────────────────────────────────────

/// The `WWW-Authenticate` value of a well-formed challenge for `realm`.
#[cfg_attr(coverage_nightly, coverage(off))]
fn challenge(realm: &str) -> String {
    format!("Bearer realm=\"{realm}\",service=\"{SERVICE}\",scope=\"{SCOPE}\"")
}

/// Make `registry` answer every request to the closure of `bundle` with
/// `unauthorized`, except one carrying exactly `Bearer <token>` for a token in
/// `tokens`, which gets the object.
#[cfg_attr(coverage_nightly, coverage(off))]
fn guard(
    registry: &Server,
    bundle: &VerifiedReleaseBundleV1,
    unauthorized: &Reply,
    tokens: &[&str],
) {
    for (path, bytes) in objects(bundle) {
        registry.route(&path, unauthorized.clone());
        for token in tokens {
            registry.route_for(&path, &format!("Bearer {token}"), Reply::ok(&bytes));
        }
    }
}

/// A token service that issues `tokens` in turn, as `{"token": ...}`.
#[cfg_attr(coverage_nightly, coverage(off))]
fn issue(issuer: &Server, tokens: &[&str]) {
    issuer.route_sequence(
        &format!("/token?{TOKEN_QUERY}"),
        None,
        tokens
            .iter()
            .map(|token| Reply::ok(format!("{{\"token\":\"{token}\"}}").as_bytes()))
            .collect(),
    );
}

/// A registry guarded by a well-formed challenge, and the token service its
/// realm names, issuing `tokens` in turn.
#[cfg_attr(coverage_nightly, coverage(off))]
fn protected(
    bundle: &VerifiedReleaseBundleV1,
    tokens: &[&str],
) -> Result<(Server, Server), BoxError> {
    let (registry, issuer) = (Server::start()?, Server::start()?);
    let unauthorized = Reply::unauthorized(&[challenge(&issuer.url("/token")).as_bytes()]);
    guard(&registry, bundle, &unauthorized, tokens);
    issue(&issuer, tokens);
    Ok((registry, issuer))
}

/// Read `bundle` from `registry`, with `issuer` also an allowed origin and
/// `provider` supplying credentials.
#[cfg_attr(coverage_nightly, coverage(off))]
fn read_authenticated(
    registry: &Server,
    issuer: &Server,
    bundle: &VerifiedReleaseBundleV1,
    provider: Arc<Provider>,
) -> Read {
    let transport = transport(&[registry, issuer])?.with_credentials(provider);
    let source = OciReleaseSourceV1::new(&registry.origin(), REPOSITORY, Some(SERVICE), transport)?;
    Ok(source.read_verified(bundle.address()))
}

#[test]
#[cfg_attr(coverage_nightly, coverage(off))]
fn one_challenge_one_token_request_and_one_authenticated_retry() -> TestResult {
    let _network = network();
    let bundle = bundle()?;
    let (registry, issuer) = protected(&bundle, &["token-one"])?;
    let provider = Provider::new(&[
        (registry.port, bearer("registry-bootstrap")),
        (issuer.port, basic("reader", "pässword")),
    ]);

    assert_eq!(
        read_authenticated(&registry, &issuer, &bundle, Arc::clone(&provider))??,
        bundle
    );

    // The registry credential opens the first request. The one 401 is
    // answered by one retry with the token, and the token then serves every
    // later object without a second challenge.
    let seen = registry.seen();
    let manifest = manifest_path(bundle.address().digest());
    assert_eq!(seen.len(), 2 + bundle.blobs().len());
    assert_eq!(seen[0].target, manifest);
    assert_eq!(
        seen[0].authorization.as_deref(),
        Some("Bearer registry-bootstrap")
    );
    assert_eq!(seen[1].target, manifest);
    assert!(seen[1..]
        .iter()
        .all(|seen| seen.authorization.as_deref() == Some("Bearer token-one")));
    assert_eq!(seen[1].accept.as_deref(), Some(MANIFEST_MEDIA_TYPE));

    // Exactly one token request, with exactly the pull scope, carrying only
    // the token service's own credential (base64("reader:pässword")).
    assert_eq!(
        issuer.seen(),
        vec![Seen {
            target: format!("/token?{TOKEN_QUERY}"),
            authorization: Some("Basic cmVhZGVyOnDDpHNzd29yZA==".to_owned()),
            accept: Some(DEFAULT_ACCEPT.to_owned()),
        }]
    );
    // The registry origin once per read, the token service once per token.
    assert_eq!(provider.asked(), vec![registry.port, issuer.port]);
    Ok(())
}

#[test]
#[cfg_attr(coverage_nightly, coverage(off))]
fn an_anonymous_pull_asks_for_no_credentials_beyond_its_origins() -> TestResult {
    let _network = network();
    let bundle = bundle()?;
    let (registry, issuer) = protected(&bundle, &["anonymous-token"])?;
    let provider = Provider::new(&[]);
    assert_eq!(
        read_authenticated(&registry, &issuer, &bundle, provider)??,
        bundle
    );
    assert_eq!(registry.seen()[0].authorization, None);
    assert_eq!(issuer.seen()[0].authorization, None);
    Ok(())
}

#[test]
#[cfg_attr(coverage_nightly, coverage(off))]
fn an_expired_token_is_replaced_by_a_new_challenge_for_that_object() -> TestResult {
    let _network = network();
    let bundle = bundle()?;
    // The manifest accepts only the first token and every blob only the
    // second, so the first blob request is challenged again.
    let (registry, issuer) = (Server::start()?, Server::start()?);
    let unauthorized = Reply::unauthorized(&[challenge(&issuer.url("/token")).as_bytes()]);
    for (path, bytes) in objects(&bundle) {
        let token = if path.contains("/manifests/") {
            "first"
        } else {
            "second"
        };
        registry.route(&path, unauthorized.clone());
        registry.route_for(&path, &format!("Bearer {token}"), Reply::ok(&bytes));
    }
    issue(&issuer, &["first", "second"]);
    assert_eq!(
        read_authenticated(&registry, &issuer, &bundle, Provider::new(&[]))??,
        bundle
    );
    assert_eq!(issuer.seen().len(), 2);
    Ok(())
}

#[test]
#[cfg_attr(coverage_nightly, coverage(off))]
fn a_second_401_after_the_token_fails_closed() -> TestResult {
    let _network = network();
    let bundle = bundle()?;
    // The token is never accepted.
    let (registry, issuer) = protected(&bundle, &[])?;
    issue(&issuer, &["rejected"]);
    assert_eq!(
        read_authenticated(&registry, &issuer, &bundle, Provider::new(&[]))?,
        Err(S::Io)
    );
    assert_eq!(registry.seen().len(), 2);
    assert_eq!(issuer.seen().len(), 1);
    Ok(())
}

#[test]
#[cfg_attr(coverage_nightly, coverage(off))]
fn redirect_hops_are_counted_across_the_authentication_retry() -> TestResult {
    let _network = network();
    let bundle = bundle()?;
    let (registry, issuer) = (Server::start()?, Server::start()?);
    let manifest = manifest_path(bundle.address().digest());
    let unauthorized = Reply::unauthorized(&[challenge(&issuer.url("/token")).as_bytes()]);
    registry.route(&manifest, unauthorized);
    registry.route_for(&manifest, "Bearer hop", Reply::redirect(307, "/h1"));
    registry.route("/h1", Reply::redirect(307, "/h2"));
    registry.route("/h2", Reply::redirect(307, "/h3"));
    registry.route("/h3", Reply::ok(bundle.manifest()));
    for blob in bundle.blobs() {
        registry.route(&blob_path(blob.digest()), Reply::ok(blob.bytes()));
    }
    issue(&issuer, &["hop"]);

    // Three hops after the retry are followed, without a credential.
    assert_eq!(
        read_authenticated(&registry, &issuer, &bundle, Provider::new(&[]))??,
        bundle
    );
    let seen = registry.seen();
    assert_eq!(&seen[0].target, &manifest);
    assert_eq!(seen[1].authorization.as_deref(), Some("Bearer hop"));
    assert!(seen[2..5].iter().all(|seen| seen.authorization.is_none()));

    // A fourth hop fails closed.
    registry.route("/h3", Reply::redirect(307, "/h4"));
    registry.route("/h4", Reply::ok(bundle.manifest()));
    assert_eq!(
        read_authenticated(&registry, &issuer, &bundle, Provider::new(&[]))?,
        Err(S::Io)
    );
    Ok(())
}

// ── Hostile challenges ──────────────────────────────────────────────────

/// Read from a registry guarded by a 401 that carries the headers `headers`
/// builds for the token service's realm, with a working token service.
/// Returns the result and the number of token requests.
#[cfg_attr(coverage_nightly, coverage(off))]
fn read_challenged(
    bundle: &VerifiedReleaseBundleV1,
    headers: &dyn Fn(&str) -> Vec<Vec<u8>>,
) -> Result<(Result<VerifiedReleaseBundleV1, S>, usize), BoxError> {
    let (registry, issuer) = (Server::start()?, Server::start()?);
    let values = headers(&issuer.url("/token"));
    let values = values.iter().map(Vec::as_slice).collect::<Vec<_>>();
    guard(&registry, bundle, &Reply::unauthorized(&values), &["T"]);
    issue(&issuer, &["T"]);
    let result = read_authenticated(&registry, &issuer, bundle, Provider::new(&[]))?;
    Ok((result, issuer.seen().len()))
}

#[cfg_attr(coverage_nightly, coverage(off))]
fn one_header(template: &str) -> impl Fn(&str) -> Vec<Vec<u8>> + '_ {
    move |realm| vec![template.replace("<realm>", realm).into_bytes()]
}

#[test]
#[cfg_attr(coverage_nightly, coverage(off))]
fn only_one_unambiguous_bearer_challenge_is_accepted() -> TestResult {
    let _network = network();
    let bundle = bundle()?;
    let accepted = [
        // The registry's usual form.
        r#"Bearer realm="<realm>",service="registry.test",scope="repository:acme/plugin:pull""#,
        // Case-insensitive scheme and names, token values, loose spacing.
        r#"bearer REALM="<realm>" ,  Service=registry.test,scope="repository:acme/plugin:pull""#,
        // The scope may be omitted: the client supplies the exact scope.
        r#"Bearer realm="<realm>",service="registry.test""#,
        // Unknown parameters and quoted pairs are tolerated.
        r#"Bearer realm="<realm>",service="registry.test",error="invalid_token",error_description="a \"quoted\" \\ word""#,
    ];
    for header in accepted {
        let (result, tokens) = read_challenged(&bundle, &one_header(header))?;
        assert_eq!(result, Ok(bundle.clone()), "{header}");
        assert_eq!(tokens, 1, "{header}");
    }

    let rejected = [
        // Basic is never a fallback, alone or next to a Bearer challenge.
        r#"Basic realm="<realm>""#,
        r#"Basic realm="x", Bearer realm="<realm>",service="registry.test""#,
        r#"Bearer realm="<realm>",service="registry.test", Basic realm="x""#,
        // Missing, duplicated or malformed parameters.
        r#"Bearer service="registry.test""#,
        r#"Bearer realm="<realm>",realm="<realm>",service="registry.test""#,
        r#"Bearer realm="<realm>",service="registry.test",SERVICE="registry.test""#,
        r#"Bearer realm="<realm>",service="registry.test",scope="repository:acme/plugin:pull",scope="repository:acme/plugin:pull""#,
        r"Bearer realm=",
        r#"Bearer realm="<realm>"#,
        r#"Bearer realm="<realm>\"#,
        r#"Bearer realm "<realm>""#,
        r"Bearer abc==",
        r#"Bearer realm="<realm>","#,
        r#"Bearer realm="<realm>" service="registry.test""#,
        r"Bearer realm=<realm>;x",
        "Bearer",
        "Bearer ",
        "",
        // The service must be exactly the configured one.
        r#"Bearer realm="<realm>""#,
        r#"Bearer realm="<realm>",service="other.test""#,
        r#"Bearer realm="<realm>",service="registry.test ""#,
        // The scope must be exactly the pull scope of the configured repository.
        r#"Bearer realm="<realm>",service="registry.test",scope="repository:acme/other:pull""#,
        r#"Bearer realm="<realm>",service="registry.test",scope="repository:acme/plugin:pull,push""#,
        r#"Bearer realm="<realm>",service="registry.test",scope="""#,
        // The realm must be an allowed, plain HTTPS token endpoint.
        r#"Bearer realm="http://127.0.0.1:9/token",service="registry.test""#,
        r#"Bearer realm="https://127.0.0.1:1/token",service="registry.test""#,
        r#"Bearer realm="not a url",service="registry.test""#,
        r#"Bearer realm="<realm>?extra=1",service="registry.test""#,
        r#"Bearer realm="<realm>?",service="registry.test""#,
        r#"Bearer realm="<realm>#fragment",service="registry.test""#,
    ];
    for header in rejected {
        let (result, tokens) = read_challenged(&bundle, &one_header(header))?;
        assert_eq!(result, Err(S::Io), "{header}");
        assert_eq!(tokens, 0, "{header}");
    }

    // No challenge header, two challenge headers, and a non-ASCII value.
    let (result, tokens) = read_challenged(&bundle, &|_| Vec::new())?;
    assert_eq!((result, tokens), (Err(S::Io), 0));
    let twice = |realm: &str| vec![challenge(realm).into_bytes(), challenge(realm).into_bytes()];
    let (result, tokens) = read_challenged(&bundle, &twice)?;
    assert_eq!((result, tokens), (Err(S::Io), 0));
    let non_ascii =
        |realm: &str| vec![format!("Bearer realm=\"{realm}\",service=\"é\"").into_bytes()];
    let (result, tokens) = read_challenged(&bundle, &non_ascii)?;
    assert_eq!((result, tokens), (Err(S::Io), 0));
    Ok(())
}

#[test]
#[cfg_attr(coverage_nightly, coverage(off))]
fn the_challenge_realm_userinfo_and_unconfigured_services_are_refused() -> TestResult {
    let _network = network();
    let bundle = bundle()?;
    let (registry, issuer) = (Server::start()?, Server::start()?);
    // The realm names the allowed token origin, but with userinfo.
    let userinfo = issuer
        .url("/token")
        .replace("https://", "https://user:secret@");
    let unauthorized = Reply::unauthorized(&[challenge(&userinfo).as_bytes()]);
    guard(&registry, &bundle, &unauthorized, &["T"]);
    issue(&issuer, &["T"]);
    assert_eq!(
        read_authenticated(&registry, &issuer, &bundle, Provider::new(&[]))?,
        Err(S::Io)
    );
    assert!(issuer.seen().is_empty());

    // A challenge naming a service while none is configured is refused,
    // and a configured service the challenge omits is refused too.
    let realm = issuer.url("/token");
    let named = Reply::unauthorized(&[challenge(&realm).as_bytes()]);
    guard(&registry, &bundle, &named, &["T"]);
    let unnamed = OciReleaseSourceV1::new(
        &registry.origin(),
        REPOSITORY,
        None,
        transport(&[&registry, &issuer])?,
    )?;
    assert_eq!(unnamed.read_verified(bundle.address()), Err(S::Io));
    assert!(issuer.seen().is_empty());
    Ok(())
}

#[test]
#[cfg_attr(coverage_nightly, coverage(off))]
fn a_challenge_without_a_configured_service_needs_no_service_parameter() -> TestResult {
    let _network = network();
    let bundle = bundle()?;
    let (registry, issuer) = (Server::start()?, Server::start()?);
    let header = format!("Bearer realm=\"{}\"", issuer.url("/token"));
    guard(
        &registry,
        &bundle,
        &Reply::unauthorized(&[header.as_bytes()]),
        &["T"],
    );
    issuer.route(
        "/token?scope=repository%3Aacme%2Fplugin%3Apull",
        Reply::ok(br#"{"token":"T"}"#),
    );
    let source = OciReleaseSourceV1::new(
        &registry.origin(),
        REPOSITORY,
        None,
        transport(&[&registry, &issuer])?,
    )?;
    assert_eq!(source.read_verified(bundle.address())?, bundle);
    Ok(())
}

// ── Token responses ─────────────────────────────────────────────────────

/// The result of a read whose token service answers with `reply`.
#[cfg_attr(coverage_nightly, coverage(off))]
fn read_with_token_reply(
    bundle: &VerifiedReleaseBundleV1,
    reply: Reply,
) -> Result<Result<VerifiedReleaseBundleV1, S>, BoxError> {
    let (registry, issuer) = (Server::start()?, Server::start()?);
    guard(
        &registry,
        bundle,
        &Reply::unauthorized(&[challenge(&issuer.url("/token")).as_bytes()]),
        &["T"],
    );
    issuer.route(&format!("/token?{TOKEN_QUERY}"), reply);
    read_authenticated(&registry, &issuer, bundle, Provider::new(&[]))
}

#[test]
#[cfg_attr(coverage_nightly, coverage(off))]
fn only_one_well_formed_token_is_accepted() -> TestResult {
    let _network = network();
    let bundle = bundle()?;
    let accepted: [&[u8]; 8] = [
        br#"{"token":"T"}"#,
        br#"{"access_token":"T"}"#,
        br#"{"token":"T","access_token":"T"}"#,
        br#"{"token":"T","expires_in":300,"issued_at":"2026-10-21T00:00:00Z"}"#,
        // Equal keys in different objects are not duplicates.
        br#"{"token":"T","x":[{"a":1},{"a":2},"a","a"],"y":{"a":1}}"#,
        // An escaped quote and an escaped backslash end keys correctly.
        br#"{"token":"T","k\"":1,"k\"x":2,"b\\":3,"b":4}"#,
        b" \n{\"token\" : \"T\"}\n",
        br#"{"token":"T"}"#,
    ];
    for body in accepted {
        let result = read_with_token_reply(&bundle, Reply::ok(body))?;
        assert_eq!(
            result,
            Ok(bundle.clone()),
            "{}",
            String::from_utf8_lossy(body)
        );
    }

    let rejected: [&[u8]; 17] = [
        b"",
        b"not json",
        b"[]",
        b"{}",
        br#"{"token":1}"#,
        br#"{"token":null}"#,
        br#"{"token":""}"#,
        br#"{"token":"two words"}"#,
        br#"{"token":"bell\u0007"}"#,
        // Conflicting token fields.
        br#"{"token":"T","access_token":"U"}"#,
        br#"{"token":"T","access_token":null}"#,
        // Duplicate keys, also as escaped aliases and at any depth.
        br#"{"token":"T","token":"T"}"#,
        br#"{"token":"T","token":"T"}"#,
        br#"{"token":"T","x":{"a":1,"a":2}}"#,
        br#"{"token":"T","x":[{"a":1,"a":1}]}"#,
        br#"{"token":"T","x":{"y":{"z":1,"z":1}}}"#,
        br#"{"token":"T","k\"":1,"k\"":2}"#,
    ];
    for body in rejected {
        let result = read_with_token_reply(&bundle, Reply::ok(body))?;
        assert_eq!(result, Err(S::Io), "{}", String::from_utf8_lossy(body));
    }

    // The encoded Authorization is at most 8 KiB: a token of exactly that
    // size is sent, and a longer one is out of bounds.
    let bound = 8_192 - "Bearer ".len();
    let exact = format!("{{\"token\":\"{}\"}}", "t".repeat(bound));
    let result = read_with_token_reply(&bundle, Reply::ok(exact.as_bytes()))?;
    assert_eq!(result, Err(S::Io), "the registry only knows token T");
    let longer = format!("{{\"token\":\"{}\"}}", "t".repeat(bound + 1));
    let result = read_with_token_reply(&bundle, Reply::ok(longer.as_bytes()))?;
    assert_eq!(result, Err(S::BoundsExceeded));
    Ok(())
}

#[test]
#[cfg_attr(coverage_nightly, coverage(off))]
fn a_token_response_is_bounded_and_not_redirected() -> TestResult {
    let _network = network();
    let bundle = bundle()?;

    // At most 64 KiB, declared or close-delimited.
    let padded = |length: usize| {
        let prefix = r#"{"token":"T","pad":""#;
        let suffix = r#""}"#;
        format!(
            "{prefix}{}{suffix}",
            "p".repeat(length - prefix.len() - suffix.len())
        )
    };
    assert_eq!(
        read_with_token_reply(&bundle, Reply::ok(padded(65_536).as_bytes()))?,
        Ok(bundle.clone())
    );
    assert_eq!(
        read_with_token_reply(&bundle, Reply::ok(padded(65_537).as_bytes()))?,
        Err(S::BoundsExceeded)
    );
    let close = "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n";
    assert_eq!(
        read_with_token_reply(&bundle, Reply::raw(close, padded(65_536).as_bytes()))?,
        Ok(bundle.clone())
    );
    assert_eq!(
        read_with_token_reply(&bundle, Reply::raw(close, padded(65_537).as_bytes()))?,
        Err(S::BoundsExceeded)
    );

    // Only a 200 answer is a token: a failure, a redirect and a coded body
    // are all closed errors, and the token service is never followed.
    for code in [401, 403, 404, 500] {
        assert_eq!(
            read_with_token_reply(&bundle, Reply::status(code))?,
            Err(S::Io),
            "status {code}"
        );
    }
    let (registry, issuer, elsewhere) = (Server::start()?, Server::start()?, Server::start()?);
    guard(
        &registry,
        &bundle,
        &Reply::unauthorized(&[challenge(&issuer.url("/token")).as_bytes()]),
        &["T"],
    );
    issuer.route(
        &format!("/token?{TOKEN_QUERY}"),
        Reply::redirect(307, &elsewhere.url("/token")),
    );
    elsewhere.route("/token", Reply::ok(br#"{"token":"T"}"#));
    let transport = transport(&[&registry, &issuer, &elsewhere])?;
    let source = OciReleaseSourceV1::new(&registry.origin(), REPOSITORY, Some(SERVICE), transport)?;
    assert_eq!(source.read_verified(bundle.address()), Err(S::Io));
    assert!(elsewhere.seen().is_empty());

    let body = br#"{"token":"T"}"#;
    let coded = Reply::raw(
        &format!(
            "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        ),
        body,
    );
    assert_eq!(read_with_token_reply(&bundle, coded)?, Err(S::Io));
    Ok(())
}

// ── Configuration ───────────────────────────────────────────────────────

#[cfg_attr(coverage_nightly, coverage(off))]
fn configured() -> Result<RemoteTransportConfigV1, BoxError> {
    Ok(RemoteTransportConfigV1::new(
        &["https://registry.test"],
        &test_roots(),
        quick(),
    )?)
}

#[cfg_attr(coverage_nightly, coverage(off))]
fn construct(origin: &str, repository: &str, service: Option<&str>) -> Result<Option<C>, BoxError> {
    Ok(OciReleaseSourceV1::new(origin, repository, service, configured()?).err())
}

#[test]
#[cfg_attr(coverage_nightly, coverage(off))]
fn the_registry_origin_is_an_exact_allowed_https_origin() -> TestResult {
    for origin in [
        "https://registry.test",
        "https://registry.test/",
        "https://registry.test:443",
    ] {
        assert_eq!(construct(origin, "a", None)?, None, "{origin}");
    }
    for origin in [
        "http://registry.test",
        "https://registry.test/path",
        "https://registry.test/?query",
        "https://registry.test/#fragment",
        "https://user@registry.test",
        "registry.test",
        "",
    ] {
        assert_eq!(
            construct(origin, "a", None)?,
            Some(C::InvalidLocator),
            "{origin}"
        );
    }
    for origin in ["https://other.test", "https://registry.test:8443"] {
        assert_eq!(
            construct(origin, "a", None)?,
            Some(C::UnconfiguredOrigin),
            "{origin}"
        );
    }
    Ok(())
}

#[test]
#[cfg_attr(coverage_nightly, coverage(off))]
fn the_repository_follows_the_distribution_name_grammar() -> TestResult {
    let longest = "a".repeat(255);
    let too_long = "a".repeat(256);
    for repository in [
        "a",
        "0a9",
        "a/b",
        "a.b",
        "a_b",
        "a__b",
        "a-b",
        "a---b",
        "a/b.c_d__e-f/g",
        longest.as_str(),
    ] {
        assert_eq!(
            construct("https://registry.test", repository, None)?,
            None,
            "{repository}"
        );
    }
    for repository in [
        "",
        "/a",
        "a/",
        "a//b",
        "A",
        "a b",
        "a..b",
        "a___b",
        "a-",
        "-a",
        "a_",
        "_a",
        ".a",
        "a.",
        "a._b",
        "a/./b",
        "a:tag",
        "a@sha256:0",
        "a?x",
        "a%2fb",
        "é",
        too_long.as_str(),
    ] {
        assert_eq!(
            construct("https://registry.test", repository, None)?,
            Some(C::InvalidLocator),
            "{repository}"
        );
    }
    Ok(())
}

#[test]
#[cfg_attr(coverage_nightly, coverage(off))]
fn the_expected_service_is_a_non_empty_visible_name() -> TestResult {
    for service in ["registry.test", "ghcr.io", "a"] {
        assert_eq!(
            construct("https://registry.test", "a", Some(service))?,
            None,
            "{service}"
        );
    }
    for service in ["", "a b", "a\tb", "a\u{7f}", "é"] {
        assert_eq!(
            construct("https://registry.test", "a", Some(service))?,
            Some(C::InvalidLocator),
            "{service:?}"
        );
    }
    Ok(())
}

#[test]
#[cfg_attr(coverage_nightly, coverage(off))]
fn every_request_url_is_at_most_8_kib() -> TestResult {
    // The longest request path is `/v2/<repository>/manifests/<digest>`.
    let repository = "a".repeat(255);
    let path = "/v2/".len() + repository.len() + "/manifests/".len() + "sha256:".len() + 64;
    // Labels of 63 characters, so that the host is a valid name.
    let host = |length: usize| {
        (0..length)
            .map(|index| if index % 64 == 63 { '.' } else { 'a' })
            .collect::<String>()
    };
    let largest = 8_192 - "https://".len() - path;
    for (length, expected) in [(largest, None), (largest + 1, Some(C::InvalidLocator))] {
        let origin = format!("https://{}", host(length));
        let transport = RemoteTransportConfigV1::new(&[origin.as_str()], &test_roots(), quick())?;
        assert_eq!(
            OciReleaseSourceV1::new(&origin, &repository, None, transport).err(),
            expected,
            "host of {length} characters"
        );
    }
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
        "LOG-SECRET-BOOTSTRAP",
        "LOG-SECRET-TOKEN",
        "LOG-SECRET-PASSWORD",
        // base64("reader:LOG-SECRET-PASSWORD")
        "cmVhZGVyOkxPRy1TRUNSRVQtUEFTU1dPUkQ",
        "LOG-SECRET-SIGNATURE",
        "LOG-SECRET-BODY",
    ];
    let bundle = bundle_with(b"LOG-SECRET-BODY")?;
    let (registry, issuer) = protected(&bundle, &["LOG-SECRET-TOKEN"])?;
    let provider = Provider::new(&[
        (registry.port, bearer("LOG-SECRET-BOOTSTRAP")),
        (issuer.port, basic("reader", "LOG-SECRET-PASSWORD")),
    ]);

    // A token read with a signed redirect for one blob, then a failed read.
    let cdn = Server::start()?;
    let blob = &bundle.blobs()[1];
    let signed = "/blob?X-Signature=LOG-SECRET-SIGNATURE";
    cdn.route(signed, Reply::ok(blob.bytes()));
    registry.route_for(
        &blob_path(blob.digest()),
        "Bearer LOG-SECRET-TOKEN",
        Reply::redirect(307, &cdn.url(signed)),
    );
    let transport = transport(&[&registry, &issuer, &cdn])?.with_credentials(provider);
    let source = OciReleaseSourceV1::new(&registry.origin(), REPOSITORY, Some(SERVICE), transport)?;
    assert_eq!(source.read_verified(bundle.address())?, bundle);
    cdn.route(signed, Reply::status(404));
    assert_eq!(source.read_verified(bundle.address()), Err(S::NotFound));
    // A TLS failure under the same credentials.
    let untrusted = RemoteTransportConfigV1::new(
        &[&registry.origin()],
        &TrustRootsV1::Der(vec![OTHER_CA.to_vec()]),
        quick(),
    )?
    .with_credentials(Provider::new(&[(
        registry.port,
        bearer("LOG-SECRET-BOOTSTRAP"),
    )]));
    let source = OciReleaseSourceV1::new(&registry.origin(), REPOSITORY, None, untrusted)?;
    assert_eq!(source.read_verified(bundle.address()), Err(S::Io));

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
