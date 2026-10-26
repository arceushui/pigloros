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
    AdmissionAuthority, NetworkCapability, NetworkCaptureStore, NetworkEndpointConnector,
    NetworkExchangePlan, NetworkExchangeReply, NetworkExchangeRequest,
};

use super::*;
use crate::test_fixtures::{
    admission, admitted, bound_proxy, capability, capture_store, grant_authority, plan, remote,
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
    let admitted = admitted()?;
    Ok(admitted
        .check_local(
            admission(attempt, authority, epochs, Vec::new()),
            FailClosedLocalNetwork.establish(namespace)?,
            channel,
        )
        .map(CheckedLocal::bind))
}

const EPOCHS: [u64; 3] = [4, 5, 6];

fn refusal(
    attempt: [u8; 16],
    authority: AdmissionAuthority,
    epochs: [u64; 3],
    namespace: [u8; 16],
    channel: [u8; 16],
) -> TestResult<Option<LocalProxyBindError>> {
    Ok(bind(attempt, authority, epochs, namespace, channel)?.err())
}

#[test]
fn the_matching_inputs_bind_the_attempt_they_were_checked_against() -> TestResult {
    let bound = bind(ATTEMPT, grant_authority(), EPOCHS, ATTEMPT, ATTEMPT)?;
    assert_eq!(bound.map(|(binding, _)| binding.attempt_id()), Ok(ATTEMPT));
    Ok(())
}

#[test]
fn a_grant_for_another_attempt_is_refused() -> TestResult {
    assert_eq!(
        refusal(OTHER, grant_authority(), EPOCHS, ATTEMPT, ATTEMPT)?,
        Some(LocalProxyBindError::Attempt)
    );
    Ok(())
}

#[test]
fn a_grant_with_other_digests_is_refused() -> TestResult {
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
            refusal(ATTEMPT, authority, EPOCHS, ATTEMPT, ATTEMPT)?,
            Some(LocalProxyBindError::Authority)
        );
    }
    Ok(())
}

/// Check `admission` against the fixture attempt, which allows `allowed`.
fn refusal_with(
    admission: LocalNetworkAdmission,
    allowed: Vec<NetworkCapability>,
) -> TestResult<Option<LocalProxyBindError>> {
    let (_adapter, channel) = HostServiceChannel::pair(ATTEMPT)?;
    let admitted = admitted()?.allowing(allowed);
    Ok(admitted
        .check_local(
            admission,
            FailClosedLocalNetwork.establish(ATTEMPT)?,
            channel,
        )
        .err())
}

fn matching_admission() -> LocalNetworkAdmission {
    admission(ATTEMPT, grant_authority(), EPOCHS, Vec::new())
}

#[test]
fn a_grant_for_another_request_is_refused() -> TestResult {
    let other = matching_admission().with_request_id([0xee; 16]);
    assert_eq!(
        refusal_with(other, Vec::new())?,
        Some(LocalProxyBindError::Request)
    );
    Ok(())
}

#[test]
fn a_grant_expecting_another_launch_policy_is_refused() -> TestResult {
    let other = matching_admission().with_expected_launch_policy_digest([0xee; 32]);
    assert_eq!(
        refusal_with(other, Vec::new())?,
        Some(LocalProxyBindError::LaunchPolicy)
    );
    Ok(())
}

#[test]
fn every_authority_digest_of_the_grant_must_match_the_request() -> TestResult {
    let mutations: [fn(&mut AdmissionAuthority); 9] = [
        |authority| authority.evr1_digest = [0xee; 32],
        |authority| authority.fixture_contract_digest = [0xee; 32],
        |authority| authority.fixture_digest = [0xee; 32],
        |authority| authority.execution_profile_digest = [0xee; 32],
        |authority| authority.lps1_digest = [0xee; 32],
        |authority| authority.spm1_digest = [0xee; 32],
        |authority| authority.pcf1_digest = [0xee; 32],
        |authority| authority.pcr1_digest = [0xee; 32],
        |authority| authority.hcp1_digest = [0xee; 32],
    ];
    for mutate in mutations {
        let mut authority = grant_authority();
        mutate(&mut authority);
        let other = admission(ATTEMPT, authority, EPOCHS, Vec::new());
        assert_eq!(
            refusal_with(other, Vec::new())?,
            Some(LocalProxyBindError::Authority)
        );
    }
    Ok(())
}

#[test]
fn an_endpoint_the_launch_policy_does_not_allow_is_refused() -> TestResult {
    let planned = admission(
        ATTEMPT,
        grant_authority(),
        EPOCHS,
        vec![(plan()?, capability(UNUSED_ENDPOINT))],
    );
    assert_eq!(
        refusal_with(planned, Vec::new())?,
        Some(LocalProxyBindError::Capability)
    );
    Ok(())
}

#[test]
fn an_endpoint_the_launch_policy_allows_is_accepted() -> TestResult {
    let planned = admission(
        ATTEMPT,
        grant_authority(),
        EPOCHS,
        vec![(plan()?, capability(UNUSED_ENDPOINT))],
    );
    assert_eq!(
        refusal_with(planned, vec![capability(UNUSED_ENDPOINT)])?,
        None
    );
    Ok(())
}

#[test]
fn a_grant_with_stale_epochs_is_refused() -> TestResult {
    for stale in [[3, 5, 6], [4, 4, 6], [4, 5, 5]] {
        assert_eq!(
            refusal(ATTEMPT, grant_authority(), stale, ATTEMPT, ATTEMPT)?,
            Some(LocalProxyBindError::Authority)
        );
    }
    Ok(())
}

#[test]
fn a_namespace_of_another_attempt_is_refused() -> TestResult {
    assert_eq!(
        refusal(ATTEMPT, grant_authority(), EPOCHS, OTHER, ATTEMPT)?,
        Some(LocalProxyBindError::Namespace)
    );
    Ok(())
}

#[test]
fn a_channel_of_another_attempt_is_refused() -> TestResult {
    assert_eq!(
        refusal(ATTEMPT, grant_authority(), EPOCHS, ATTEMPT, OTHER)?,
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
fn adapter_exchange(adapter: zbus::OwnedFd, plan: &NetworkExchangePlan) -> Result<Vec<u8>, String> {
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

/// Like [`serve_with`], but a watchdog that never closes the channel fails the
/// test instead of waiting forever.
async fn serve_bounded<C>(
    binding: BoundLocalProxy,
    connector: C,
    deadline_ms: u64,
) -> TestResult<Served>
where
    C: NetworkEndpointConnector + Send + 'static,
{
    let served = serve_with(binding, connector, deadline_ms);
    tokio::time::timeout(Duration::from_secs(10), served).await?
}

#[tokio::test]
async fn a_stalled_adapter_is_closed_at_the_attempt_deadline() -> TestResult {
    // The adapter holds its end open and never sends a frame.
    let (_adapter, binding, connector) = bound_proxy(plan()?, UNUSED_ENDPOINT, LoopbackConnector)?;
    let started = Instant::now();
    let outcome = serve_bounded(binding, connector, 200).await?.outcome?;
    assert!(outcome.watchdog_expired);
    assert!(started.elapsed() >= Duration::from_millis(200));
    assert!(outcome.session.transcripts().is_empty());
    // The closed channel reads as the adapter closing at a frame boundary;
    // the flag, not the termination, records the watchdog.
    assert_eq!(outcome.session.termination(), None);
    Ok(())
}

#[tokio::test]
async fn dropping_the_serving_future_closes_the_channel() -> TestResult {
    let (adapter, binding, connector) = bound_proxy(plan()?, UNUSED_ENDPOINT, LoopbackConnector)?;
    let mut adapter = UnixStream::from(std::os::fd::OwnedFd::from(adapter));
    adapter.set_read_timeout(Some(Duration::from_secs(5)))?;
    let (_root, store) = capture_store()?;
    let deadline = Instant::now() + Duration::from_mins(1);
    let serving = binding.serve_until(connector, store, deadline);
    // The caller gives up while the proxy waits for the adapter.
    assert!(tokio::time::timeout(Duration::from_millis(100), serving)
        .await
        .is_err());
    let mut byte = [0_u8; 1];
    assert_eq!(adapter.read(&mut byte)?, 0);
    Ok(())
}

/// Ready only after it was polled `polls` times.
async fn after_polls(polls: usize, output: u8) -> u8 {
    for _ in 0..polls {
        tokio::task::yield_now().await;
    }
    output
}

#[tokio::test]
async fn both_futures_finish_whichever_is_slower() {
    assert_eq!(both(after_polls(3, 1), after_polls(0, 2)).await, (1, 2));
    assert_eq!(both(after_polls(0, 1), after_polls(3, 2)).await, (1, 2));
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
