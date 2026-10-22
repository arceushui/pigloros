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
    AdmissionAuthority, NetworkEndpointConnector, NetworkExchangeReply, NetworkExchangeRequest,
};

use super::*;
use crate::test_fixtures::{
    active, admission, capability, capture_store, grant_authority, plan, remote, LoopbackConnector,
    TestResult, ATTEMPT, OTHER, REQUEST, RESPONSE,
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

#[tokio::test]
async fn a_bound_proxy_serves_one_verified_exchange_and_retains_its_capture() -> TestResult {
    let (address, server) = remote()?;
    let plan = plan()?;
    let admission = admission(
        ATTEMPT,
        grant_authority(),
        [4, 5, 6],
        vec![(plan.clone(), capability(address))],
    );
    let (adapter, channel) = HostServiceChannel::pair(ATTEMPT)?;
    let (binding, connector) = active()?.bind_local_proxy(
        admission,
        EstablishedNetwork::new(ATTEMPT, LoopbackConnector),
        channel,
    )?;
    let adapter_plan = plan.clone();
    let adapter = thread::spawn(move || -> Result<Vec<u8>, String> {
        let mut adapter = UnixStream::from(std::os::fd::OwnedFd::from(adapter));
        NetworkExchangeRequest::new(&adapter_plan, REQUEST)
            .map_err(|error| error.to_string())?
            .write_to(&mut adapter)
            .map_err(|error| error.to_string())?;
        NetworkExchangeReply::read_from(&mut adapter, ATTEMPT, &adapter_plan)
            .map_err(|error| error.to_string())?
            .response_bytes()
            .map(<[u8]>::to_vec)
            .ok_or_else(|| "the reply was not captured".to_owned())
    });
    let (_root, store) = capture_store()?;
    let served = binding
        .serve_until(
            connector,
            Arc::clone(&store),
            Instant::now() + Duration::from_secs(30),
        )
        .await?;

    assert!(!served.watchdog_expired);
    assert_eq!(served.session.termination(), None);
    assert_eq!(served.session.transcripts().len(), 1);
    assert_eq!(
        server.join().map_err(|_| "remote thread")??,
        REQUEST.to_vec()
    );
    assert_eq!(
        adapter.join().map_err(|_| "adapter thread")??,
        RESPONSE.to_vec()
    );
    let replayed = store.replay(ATTEMPT, &plan, served.session.transcripts()[0].digest())?;
    assert_eq!(replayed.response_bytes(), RESPONSE);
    Ok(())
}

#[tokio::test]
async fn a_stalled_adapter_is_closed_at_the_attempt_deadline() -> TestResult {
    let (_adapter, channel) = HostServiceChannel::pair(ATTEMPT)?;
    let plan = plan()?;
    let (binding, connector) = active()?.bind_local_proxy(
        admission(
            ATTEMPT,
            grant_authority(),
            [4, 5, 6],
            vec![(plan, capability(SocketAddr::from(([127, 0, 0, 1], 9))))],
        ),
        EstablishedNetwork::new(ATTEMPT, LoopbackConnector),
        channel,
    )?;
    let (_root, store) = capture_store()?;
    let started = Instant::now();
    // The adapter holds its end open and never sends a frame.
    let served = binding
        .serve_until(
            connector,
            store,
            Instant::now() + Duration::from_millis(200),
        )
        .await?;
    assert!(served.watchdog_expired);
    assert!(started.elapsed() >= Duration::from_millis(200));
    assert!(served.session.transcripts().is_empty());
    // The closed channel reads as the adapter closing at a frame boundary;
    // the flag, not the termination, records the watchdog.
    assert_eq!(served.session.termination(), None);
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
    let (adapter, channel) = HostServiceChannel::pair(ATTEMPT)?;
    let (binding, connector) = active()?.bind_local_proxy(
        admission(
            ATTEMPT,
            grant_authority(),
            [4, 5, 6],
            vec![(
                plan.clone(),
                capability(SocketAddr::from(([127, 0, 0, 1], 9))),
            )],
        ),
        EstablishedNetwork::new(ATTEMPT, PanickingConnector),
        channel,
    )?;
    let mut adapter = UnixStream::from(std::os::fd::OwnedFd::from(adapter));
    NetworkExchangeRequest::new(&plan, REQUEST)?.write_to(&mut adapter)?;
    let (_root, store) = capture_store()?;
    let error = binding
        .serve_until(connector, store, Instant::now() + Duration::from_secs(30))
        .await
        .err()
        .ok_or("a panicking connector was served")?;
    assert_eq!(error.to_string(), "the proxy task did not finish");
    assert!(error.source().is_some());
    Ok(())
}
