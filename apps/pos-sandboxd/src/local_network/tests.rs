use std::{
    error::Error,
    io::{self, Read, Write},
    net::SocketAddr,
    os::unix::net::UnixStream,
    sync::Arc,
    thread,
    time::{Duration, Instant},
};

use pos_reference::sandbox_provider_protocol::{
    AdmissionAuthority, NetworkCaptureStore, NetworkEndpointConnector, NetworkExchangePlan,
    NetworkExchangeReply, NetworkExchangeRequest,
};

use super::*;
use crate::test_fixtures::{
    active, admission, bound_proxy, capture_store, grant_authority, plan, remote,
    LoopbackConnector, TestResult, ATTEMPT, OTHER, REQUEST, RESPONSE,
};

fn bind(
    attempt: [u8; 16],
    authority: AdmissionAuthority,
    epochs: [u64; 3],
    namespace: [u8; 16],
    channel: [u8; 16],
) -> TestResult<Result<(BoundLocalProxy, RefusingConnector), LocalProxyBindError>> {
    let (_adapter, channel) = HostServiceChannel::pair(channel)?;
    Ok(active()?.bind_local_proxy(
        admission(attempt, authority, epochs, Vec::new()),
        FailClosedLocalNetwork.establish(namespace),
        channel,
    ))
}

#[test]
fn only_the_matching_attempt_authority_namespace_and_channel_bind() -> TestResult {
    let epochs = [4, 5, 6];
    let bound = bind(ATTEMPT, grant_authority(), epochs, ATTEMPT, ATTEMPT)?;
    assert!(bound.is_ok());

    assert_eq!(
        bind(OTHER, grant_authority(), epochs, ATTEMPT, ATTEMPT)?.err(),
        Some(LocalProxyBindError::Attempt)
    );
    let mutations: [fn(&mut AdmissionAuthority); 4] = [
        |authority| authority.sim1_digest = [0xee; 32],
        |authority| authority.apt1_digest = [0xee; 32],
        |authority| authority.trs1_digest = [0xee; 32],
        |authority| authority.rvs1_digest = [0xee; 32],
    ];
    for mutate in mutations {
        let mut authority = grant_authority();
        mutate(&mut authority);
        assert_eq!(
            bind(ATTEMPT, authority, epochs, ATTEMPT, ATTEMPT)?.err(),
            Some(LocalProxyBindError::Authority)
        );
    }
    for stale in [[3, 5, 6], [4, 4, 6], [4, 5, 5]] {
        assert_eq!(
            bind(ATTEMPT, grant_authority(), stale, ATTEMPT, ATTEMPT)?.err(),
            Some(LocalProxyBindError::Authority)
        );
    }
    assert_eq!(
        bind(ATTEMPT, grant_authority(), epochs, OTHER, ATTEMPT)?.err(),
        Some(LocalProxyBindError::Namespace)
    );
    assert_eq!(
        bind(ATTEMPT, grant_authority(), epochs, ATTEMPT, OTHER)?.err(),
        Some(LocalProxyBindError::Channel)
    );
    Ok(())
}

#[test]
fn the_fail_closed_network_owns_no_namespace_and_refuses_every_connection() -> TestResult {
    let bound = bind(ATTEMPT, grant_authority(), [4, 5, 6], ATTEMPT, ATTEMPT)?;
    let (_binding, mut connector) = bound.map_err(|error| error.to_string())?;
    let refusal = connector
        .connect(
            SocketAddr::from(([127, 0, 0, 1], 9)),
            Duration::from_secs(1),
        )
        .err()
        .ok_or("the fail-closed connector connected")?;
    assert_eq!(refusal.kind(), io::ErrorKind::PermissionDenied);
    Ok(())
}

#[test]
fn the_stream_reads_writes_and_flushes_the_bound_channel() -> TestResult {
    let (adapter, channel) = HostServiceChannel::pair(ATTEMPT)?;
    let mut adapter = UnixStream::from(std::os::fd::OwnedFd::from(adapter));
    let mut stream = HostServiceStream(Arc::new(channel.provider));
    stream.write_all(b"to the adapter")?;
    stream.flush()?;
    let mut received = [0_u8; 14];
    adapter.read_exact(&mut received)?;
    assert_eq!(&received, b"to the adapter");
    adapter.write_all(b"to the provider")?;
    let mut received = [0_u8; 15];
    stream.read_exact(&mut received)?;
    assert_eq!(&received, b"to the provider");
    Ok(())
}

const UNUSED_ENDPOINT: SocketAddr =
    SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 9);

/// The remote, the plan and the thread that answers the plan.
struct Parties {
    address: SocketAddr,
    server: thread::JoinHandle<io::Result<Vec<u8>>>,
    plan: NetworkExchangePlan,
}

impl Parties {
    fn start() -> TestResult<Self> {
        let (address, server) = remote()?;
        Ok(Self {
            address,
            server,
            plan: plan()?,
        })
    }
}

/// Send the planned request over the adapter end and return the response.
fn adapter_exchange(
    adapter: zvariant::OwnedFd,
    plan: &NetworkExchangePlan,
) -> Result<Vec<u8>, String> {
    let mut stream = UnixStream::from(std::os::fd::OwnedFd::from(adapter));
    NetworkExchangeRequest::new(plan, REQUEST)
        .map_err(|error| error.to_string())?
        .write_to(&mut stream)
        .map_err(|error| error.to_string())?;
    NetworkExchangeReply::read_from(&mut stream, ATTEMPT, plan)
        .map_err(|error| error.to_string())?
        .response_bytes()
        .map(<[u8]>::to_vec)
        .ok_or_else(|| "the reply was not captured".to_owned())
}

fn join_pair(
    server: thread::JoinHandle<io::Result<Vec<u8>>>,
    adapter: thread::JoinHandle<Result<Vec<u8>, String>>,
) -> TestResult<(Vec<u8>, Vec<u8>)> {
    Ok((
        server.join().map_err(|_| "remote thread")??,
        adapter.join().map_err(|_| "adapter thread")??,
    ))
}

/// A capture store and what serving a binding against it ended with.
struct Served {
    root: tempfile::TempDir,
    store: Arc<NetworkCaptureStore>,
    outcome: Result<ServedProxy, ServeError>,
}

/// Serve `binding` against a fresh capture store until `deadline_ms`.
async fn serve_with<C>(
    binding: BoundLocalProxy,
    connector: C,
    deadline_ms: u64,
) -> TestResult<Served>
where
    C: NetworkEndpointConnector + Send + 'static,
{
    let (root, store) = capture_store()?;
    let deadline = Instant::now() + Duration::from_millis(deadline_ms);
    let outcome = binding
        .serve_until(connector, Arc::clone(&store), deadline)
        .await;
    Ok(Served {
        root,
        store,
        outcome,
    })
}

/// Check what one served exchange left behind.
fn check_exchange(
    parties: Parties,
    adapter: thread::JoinHandle<Result<Vec<u8>, String>>,
    served: Served,
) -> TestResult {
    assert!(served.root.path().is_dir());
    let outcome = served.outcome?;
    assert!(!outcome.watchdog_expired);
    assert_eq!(outcome.session.termination(), None);
    assert_eq!(outcome.session.transcripts().len(), 1);
    let (request, response) = join_pair(parties.server, adapter)?;
    assert_eq!(request, REQUEST.to_vec());
    assert_eq!(response, RESPONSE.to_vec());
    let digest = outcome.session.transcripts()[0].digest();
    let replayed = served.store.replay(ATTEMPT, &parties.plan, digest)?;
    assert_eq!(replayed.response_bytes(), RESPONSE);
    Ok(())
}

#[tokio::test]
async fn a_bound_proxy_serves_one_verified_exchange_and_retains_its_capture() -> TestResult {
    let parties = Parties::start()?;
    let (adapter, binding, connector) =
        bound_proxy(parties.plan.clone(), parties.address, LoopbackConnector)?;
    let plan = parties.plan.clone();
    let adapter = thread::spawn(move || adapter_exchange(adapter, &plan));
    let served = serve_with(binding, connector, 30_000).await?;
    check_exchange(parties, adapter, served)
}

#[tokio::test]
async fn a_stalled_adapter_is_closed_at_the_attempt_deadline() -> TestResult {
    // The adapter holds its end open and never sends a frame.
    let (_adapter, binding, connector) = bound_proxy(plan()?, UNUSED_ENDPOINT, LoopbackConnector)?;
    let started = Instant::now();
    let outcome = serve_with(binding, connector, 200).await?.outcome?;
    assert!(outcome.watchdog_expired);
    assert!(started.elapsed() >= Duration::from_millis(200));
    assert!(outcome.session.transcripts().is_empty());
    // The closed channel reads as the adapter closing at a frame boundary;
    // the flag, not the termination, records the watchdog.
    assert_eq!(outcome.session.termination(), None);
    Ok(())
}

struct PanickingConnector;

impl NetworkEndpointConnector for PanickingConnector {
    fn connect(&mut self, _endpoint: SocketAddr, _timeout: Duration) -> io::Result<TcpStream> {
        std::panic::resume_unwind(Box::new("the connector failed"))
    }
}

#[tokio::test]
async fn a_failed_proxy_task_is_reported() -> TestResult {
    let plan = plan()?;
    let (adapter, binding, connector) =
        bound_proxy(plan.clone(), UNUSED_ENDPOINT, PanickingConnector)?;
    let adapter = thread::spawn(move || adapter_exchange(adapter, &plan));
    let error = serve_with(binding, connector, 30_000).await?.outcome.err();
    assert_eq!(
        error.as_ref().map(ToString::to_string).as_deref(),
        Some("the proxy task did not finish")
    );
    assert!(error.is_some_and(|error| error.source().is_some()));
    // The task died with the channel, so the adapter saw no reply.
    assert!(adapter.join().map_err(|_| "adapter thread")?.is_err());
    Ok(())
}
