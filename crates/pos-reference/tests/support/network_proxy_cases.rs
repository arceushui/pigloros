// Public Local FD 3 proxy sessions over authenticated admission and loopback-only TCP.
use std::fs::File;
use std::io::{self, Cursor, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::os::unix::net::UnixStream;
use std::sync::mpsc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use std::os::fd::AsFd;

use pos_reference::sandbox_provider_protocol::{
    serve_proxy, LocalNetworkSession, LocalNetworkTermination, LocalProxyBinding,
    NetworkCaptureStore, NetworkEndpointConnector, NetworkExchangeFailure, NetworkExchangeReply,
    NetworkExchangeRequest,
};

const PROXY_DEADLINE_MS: u64 = 30_000;
const PROXY_SERVER_TIMEOUT: Duration = Duration::from_secs(10);
const PROXY_FIRST: (&[u8], &[u8]) = (b"first request", b"first response");
const PROXY_SECOND: (&[u8], &[u8]) = (b"second request!", b"second answer");

#[derive(Default)]
struct ProxyConnector {
    connections: usize,
    redirect: Option<SocketAddr>,
    timeouts: Vec<Duration>,
}

impl NetworkEndpointConnector for ProxyConnector {
    fn connect(&mut self, endpoint: SocketAddr, timeout: Duration) -> io::Result<TcpStream> {
        self.connections += 1;
        self.timeouts.push(timeout);
        TcpStream::connect_timeout(&self.redirect.unwrap_or(endpoint), timeout)
    }
}

/// The provider's binding of an admission to its FD 3 channel, as the tests
/// of the proxy itself need it. A real provider mints this from its active
/// attempt record.
struct ProxyBinding<'a, C> {
    admission: &'a LocalNetworkAdmission,
    channel: &'a mut C,
}

impl<C: Read + Write + AsFd> LocalProxyBinding for ProxyBinding<'_, C> {
    type Channel = C;

    fn parts(&mut self) -> (&LocalNetworkAdmission, &mut C) {
        (self.admission, &mut *self.channel)
    }
}

fn serve_bound<C: Read + Write + AsFd>(
    admission: &LocalNetworkAdmission,
    channel: &mut C,
    connector: &mut impl NetworkEndpointConnector,
    store: &NetworkCaptureStore,
) -> LocalNetworkSession {
    serve_proxy(&mut ProxyBinding { admission, channel }, connector, store)
}

enum AdapterStep {
    Send(Vec<u8>),
    AwaitReply,
    CloseRead,
    Wait(mpsc::Receiver<()>),
    Signal(mpsc::Sender<()>),
}

/// The adapter's end of a real FD 3 socket pair, driven by a script.
struct ProxyChannel {
    provider: UnixStream,
    adapter: Option<JoinHandle<Vec<u8>>>,
    output: Vec<u8>,
}

impl ProxyChannel {
    /// Send every byte at once, then close the adapter's write side.
    fn new(input: Vec<u8>) -> TestResult<Self> {
        Self::scripted(vec![AdapterStep::Send(input)])
    }

    /// Keep one NXQ1 outstanding: send each frame only after the last reply.
    fn interactive(frames: Vec<Vec<u8>>) -> TestResult<Self> {
        Self::scripted(
            frames
                .into_iter()
                .flat_map(|frame| [AdapterStep::Send(frame), AdapterStep::AwaitReply])
                .collect(),
        )
    }

    fn scripted(steps: Vec<AdapterStep>) -> TestResult<Self> {
        let (provider, mut adapter) = UnixStream::pair()?;
        let handle = thread::spawn(move || {
            let mut output = Vec::new();
            for step in steps {
                let completed = match step {
                    AdapterStep::Send(bytes) => adapter.write_all(&bytes).is_ok(),
                    AdapterStep::AwaitReply => proxy_read_reply(&mut adapter, &mut output),
                    AdapterStep::CloseRead => adapter.shutdown(Shutdown::Read).is_ok(),
                    AdapterStep::Wait(signal) => signal.recv_timeout(PROXY_SERVER_TIMEOUT).is_ok(),
                    AdapterStep::Signal(signal) => signal.send(()).is_ok(),
                };
                if !completed {
                    break;
                }
            }
            adapter.shutdown(Shutdown::Write).ok();
            adapter.read_to_end(&mut output).ok();
            output
        });
        Ok(Self {
            provider,
            adapter: Some(handle),
            output: Vec::new(),
        })
    }

    /// Close the provider end and collect every byte the adapter received.
    fn finish(&mut self) -> TestResult {
        self.provider.shutdown(Shutdown::Both).ok();
        let adapter = self.adapter.take().ok_or("adapter already finished")?;
        self.output = adapter.join().map_err(|_| "adapter thread")?;
        Ok(())
    }
}

fn proxy_read_reply(adapter: &mut UnixStream, output: &mut Vec<u8>) -> bool {
    let mut prefix = [0_u8; 4];
    if adapter.read_exact(&mut prefix).is_err() {
        return false;
    }
    let mut body = vec![0_u8; usize::try_from(u32::from_be_bytes(prefix)).unwrap_or_default()];
    let completed = adapter.read_exact(&mut body).is_ok();
    output.extend(prefix);
    output.extend(body);
    completed
}

struct ProxyCase {
    admission: LocalNetworkAdmission,
    plans: Vec<NetworkExchangePlan>,
    root: tempfile::TempDir,
    store: NetworkCaptureStore,
}

impl ProxyCase {
    fn new(
        address: SocketAddr,
        exchanges: &[(&[u8], &[u8])],
        limits: [u64; 3],
    ) -> TestResult<Self> {
        let plans = exchanges
            .iter()
            .enumerate()
            .map(|(occurrence, (request, response))| {
                proxy_plan(occurrence as u64, request, response, response.len() as u64)
            })
            .collect::<TestResult<Vec<_>>>()?;
        Self::with_plans(address, plans, limits)
    }

    fn with_plans(
        address: SocketAddr,
        plans: Vec<NetworkExchangePlan>,
        limits: [u64; 3],
    ) -> TestResult<Self> {
        let ip = match address {
            SocketAddr::V4(address) => address.ip().octets().to_vec(),
            SocketAddr::V6(address) => address.ip().octets().to_vec(),
        };
        let admission = LocalBindingFixture::new(
            ExecutionMode::Local,
            vec![local_endpoint(
                &ip,
                u64::from(address.port()),
                32 << 20,
                32 << 20,
            )],
            plans.clone(),
            limits,
        )?
        .bind()?;
        let root = tempfile::tempdir()?;
        let store = NetworkCaptureStore::open(&File::open(root.path())?)?;
        Ok(Self {
            admission,
            plans,
            root,
            store,
        })
    }

    fn attempt(&self) -> [u8; 16] {
        self.admission.grant().attempt_id
    }

    fn requests(&self, exchanges: &[(&[u8], &[u8])]) -> TestResult<Vec<u8>> {
        let mut frames = Vec::new();
        for (plan, (request, _)) in self.plans.iter().zip(exchanges) {
            NetworkExchangeRequest::new(plan, request)?.write_to(&mut frames)?;
        }
        Ok(frames)
    }

    fn frames(&self, exchanges: &[(&[u8], &[u8])]) -> TestResult<Vec<Vec<u8>>> {
        self.plans
            .iter()
            .zip(exchanges)
            .map(|(plan, (request, _))| {
                let mut frame = Vec::new();
                NetworkExchangeRequest::new(plan, request)?.write_to(&mut frame)?;
                Ok(frame)
            })
            .collect()
    }

    fn serve(
        &self,
        channel: &mut ProxyChannel,
        connector: &mut ProxyConnector,
    ) -> TestResult<LocalNetworkSession> {
        let session = serve_bound(
            &self.admission,
            &mut channel.provider,
            connector,
            &self.store,
        );
        channel.finish()?;
        Ok(session)
    }

    fn replies(&self, output: &[u8]) -> TestResult<Vec<NetworkExchangeReply>> {
        let mut reader = Cursor::new(output);
        let mut replies = Vec::new();
        for plan in &self.plans {
            if reader.position() == output.len() as u64 {
                break;
            }
            replies.push(NetworkExchangeReply::read_from(
                &mut reader,
                self.attempt(),
                plan,
            )?);
        }
        assert_eq!(reader.position(), output.len() as u64);
        Ok(replies)
    }

    fn retained(&self) -> TestResult<[usize; 2]> {
        let count = |directory: &str| -> TestResult<usize> {
            Ok(std::fs::read_dir(self.root.path().join(directory))?.count())
        };
        Ok([count("responses")?, count("transcripts")?])
    }
}

#[test]
fn proxy_forwards_verified_requests_and_retains_captures_before_replying() -> TestResult {
    let exchanges = [PROXY_FIRST, PROXY_SECOND];
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let address = listener.local_addr()?;
    let server = proxy_server(listener, &exchanges);
    // The cumulative ceilings exactly fit both exchanges.
    let case = ProxyCase::new(
        address,
        &exchanges,
        [
            proxy_total(&exchanges, 0),
            proxy_total(&exchanges, 1),
            PROXY_DEADLINE_MS,
        ],
    )?;
    let (mut provider, adapter) = UnixStream::pair()?;
    let frames = exchanges
        .iter()
        .zip(&case.plans)
        .map(|((request, _), plan)| {
            let mut frame = Vec::new();
            NetworkExchangeRequest::new(plan, request)?.write_to(&mut frame)?;
            Ok((frame, plan.clone()))
        })
        .collect::<TestResult<Vec<_>>>()?;
    let attempt = case.attempt();
    // The adapter keeps one NXQ1 outstanding and waits for each NXY1.
    let adapter = thread::spawn(move || -> Result<Vec<Vec<u8>>, String> {
        let mut adapter = adapter;
        frames
            .into_iter()
            .map(|(frame, plan)| {
                adapter
                    .write_all(&frame)
                    .map_err(|error| ToString::to_string(&error))?;
                let reply = NetworkExchangeReply::read_from(&mut adapter, attempt, &plan)
                    .map_err(|error| ToString::to_string(&error))?;
                reply
                    .response_bytes()
                    .map(<[u8]>::to_vec)
                    .ok_or_else(|| "captured reply".to_owned())
            })
            .collect()
    });
    let mut connector = ProxyConnector::default();
    let session = serve_bound(&case.admission, &mut provider, &mut connector, &case.store);
    assert_eq!(session.termination(), None);
    let responses = adapter.join().map_err(|_| "adapter thread")??;
    assert_eq!(
        responses,
        exchanges.map(|(_, response)| response.to_vec()).to_vec()
    );
    let received = server.join().map_err(|_| "server thread")??;
    assert_eq!(
        received,
        exchanges.map(|(request, _)| request.to_vec()).to_vec()
    );
    assert_eq!(connector.connections, 2);
    assert!(connector
        .timeouts
        .iter()
        .all(|timeout| !timeout.is_zero() && *timeout <= Duration::from_millis(PROXY_DEADLINE_MS)));
    assert_eq!(session.transcripts().len(), 2);
    for ((plan, transcript), (_, response)) in
        case.plans.iter().zip(session.transcripts()).zip(exchanges)
    {
        let replayed = case.store.replay(attempt, plan, transcript.digest())?;
        assert_eq!(replayed.transcript(), transcript);
        assert_eq!(replayed.response_bytes(), response);
    }
    Ok(())
}

#[test]
fn proxy_serves_every_plan_within_larger_ceilings() -> TestResult {
    let exchanges = [PROXY_FIRST, PROXY_SECOND];
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let address = listener.local_addr()?;
    let server = proxy_server(listener, &exchanges);
    let case = ProxyCase::new(address, &exchanges, [100, 100, PROXY_DEADLINE_MS])?;
    let mut channel = ProxyChannel::interactive(case.frames(&exchanges)?)?;
    let mut connector = ProxyConnector::default();
    let session = case.serve(&mut channel, &mut connector)?;
    assert_eq!(session.termination(), None);
    assert_eq!(session.transcripts().len(), 2);
    let replies = case.replies(&channel.output)?;
    for (reply, (_, response)) in replies.iter().zip(exchanges) {
        assert_eq!(reply.response_bytes(), Some(response));
    }
    assert_eq!(connector.connections, 2);
    assert_eq!(case.retained()?, [2, 2]);
    server.join().map_err(|_| "server thread")??;
    Ok(())
}

#[test]
fn proxy_reaches_exact_ipv6_endpoints() -> TestResult {
    let exchanges = [PROXY_FIRST];
    let listener = TcpListener::bind("[::1]:0")?;
    let address = listener.local_addr()?;
    let server = proxy_server(listener, &exchanges);
    let case = ProxyCase::new(address, &exchanges, [100, 100, PROXY_DEADLINE_MS])?;
    let mut channel = ProxyChannel::new(case.requests(&exchanges)?)?;
    let session = case.serve(&mut channel, &mut ProxyConnector::default())?;
    assert_eq!(session.termination(), None);
    assert_eq!(session.transcripts().len(), 1);
    let replies = case.replies(&channel.output)?;
    assert_eq!(replies[0].response_bytes(), Some(PROXY_FIRST.1));
    assert_eq!(
        server.join().map_err(|_| "server thread")??,
        [PROXY_FIRST.0]
    );
    Ok(())
}

#[test]
fn proxy_ends_cleanly_when_the_adapter_closes_before_later_plans() -> TestResult {
    let exchanges = [PROXY_FIRST, PROXY_SECOND];
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let address = listener.local_addr()?;
    let server = proxy_server(listener, &exchanges[..1]);
    let case = ProxyCase::new(address, &exchanges, [100, 100, PROXY_DEADLINE_MS])?;
    let mut channel = ProxyChannel::new(case.requests(&exchanges[..1])?)?;
    let mut connector = ProxyConnector::default();
    let session = case.serve(&mut channel, &mut connector)?;
    assert_eq!(session.termination(), None);
    assert_eq!(session.transcripts().len(), 1);
    assert_eq!(case.replies(&channel.output)?.len(), 1);
    assert_eq!(connector.connections, 1);
    server.join().map_err(|_| "server thread")??;

    // A channel closed before any frame serves nothing.
    let mut channel = ProxyChannel::new(Vec::new())?;
    let session = case.serve(&mut channel, &mut connector)?;
    assert_eq!(session.termination(), None);
    assert!(session.transcripts().is_empty());
    assert!(channel.output.is_empty());
    Ok(())
}

#[test]
fn proxy_rejects_frames_that_do_not_match_the_next_plan_before_connecting() -> TestResult {
    let exchanges = [PROXY_FIRST, PROXY_SECOND];
    let address = proxy_unused_address()?;
    let case = ProxyCase::new(address, &exchanges, [100, 100, PROXY_DEADLINE_MS])?;
    let mut out_of_order = Vec::new();
    NetworkExchangeRequest::new(&case.plans[1], PROXY_SECOND.0)?.write_to(&mut out_of_order)?;
    let foreign = proxy_plan(0, b"other request", PROXY_FIRST.1, 100)?;
    let mut substituted = Vec::new();
    NetworkExchangeRequest::new(&foreign, b"other request")?.write_to(&mut substituted)?;
    let mut reply = Vec::new();
    NetworkExchangeRequest::new(&case.plans[0], PROXY_FIRST.0)?
        .failed(NetworkExchangeFailure::RemoteUnavailable)
        .write_to(&mut reply)?;
    let valid = case.requests(&exchanges[..1])?;
    for input in [
        vec![0, 0, 0, 0],
        vec![0, 0, 0, 9, 1, 2],
        vec![0, 0],
        valid[..valid.len() - 1].to_vec(),
        out_of_order,
        substituted,
        reply,
    ] {
        let mut channel = ProxyChannel::new(input)?;
        let mut connector = ProxyConnector::default();
        let session = case.serve(&mut channel, &mut connector)?;
        assert_eq!(
            session.termination(),
            Some(LocalNetworkTermination::ProtocolFailure)
        );
        assert!(session.transcripts().is_empty());
        assert!(channel.output.is_empty());
        assert_eq!(connector.connections, 0);
    }
    assert_eq!(case.retained()?, [0, 0]);
    Ok(())
}

#[test]
fn proxy_fails_closed_when_a_second_request_is_already_outstanding() -> TestResult {
    let exchanges = [PROXY_FIRST, PROXY_SECOND];
    let case = ProxyCase::new(
        proxy_unused_address()?,
        &exchanges,
        [100, 100, PROXY_DEADLINE_MS],
    )?;
    let frames = case.frames(&exchanges)?;
    let mut partial = frames[1].clone();
    partial.truncate(2);
    // The next NXQ1, or even one byte of it, queued before the first is answered.
    for early in [frames[1].clone(), partial] {
        let mut input = frames[0].clone();
        input.extend(early);
        let mut channel = ProxyChannel::new(input)?;
        let mut connector = ProxyConnector::default();
        let session = case.serve(&mut channel, &mut connector)?;
        assert_eq!(
            session.termination(),
            Some(LocalNetworkTermination::ProtocolFailure)
        );
        assert!(session.transcripts().is_empty());
        assert!(channel.output.is_empty());
        assert_eq!(connector.connections, 0);
    }
    assert_eq!(case.retained()?, [0, 0]);
    Ok(())
}

#[test]
fn proxy_fails_closed_when_a_second_request_arrives_during_an_exchange() -> TestResult {
    let exchanges = [PROXY_FIRST, PROXY_SECOND];
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let address = listener.local_addr()?;
    let (forwarded, forwarded_wait) = mpsc::channel::<()>();
    let (queued, queued_wait) = mpsc::channel::<()>();
    // The peer answers only after the adapter has queued its next request.
    let server = thread::spawn(move || -> io::Result<Vec<u8>> {
        let mut stream = proxy_accept(&listener)?;
        stream.set_read_timeout(Some(PROXY_SERVER_TIMEOUT))?;
        let mut received = Vec::new();
        stream.read_to_end(&mut received)?;
        forwarded.send(()).ok();
        queued_wait.recv_timeout(PROXY_SERVER_TIMEOUT).ok();
        stream.write_all(PROXY_FIRST.1)?;
        Ok(received)
    });
    let case = ProxyCase::new(address, &exchanges, [100, 100, PROXY_DEADLINE_MS])?;
    let frames = case.frames(&exchanges)?;
    let mut channel = ProxyChannel::scripted(vec![
        AdapterStep::Send(frames[0].clone()),
        AdapterStep::Wait(forwarded_wait),
        AdapterStep::Send(frames[1].clone()),
        AdapterStep::Signal(queued),
        AdapterStep::AwaitReply,
    ])?;
    let mut connector = ProxyConnector::default();
    let session = case.serve(&mut channel, &mut connector)?;
    assert_eq!(
        session.termination(),
        Some(LocalNetworkTermination::ProtocolFailure)
    );
    assert!(session.transcripts().is_empty());
    assert!(channel.output.is_empty());
    assert_eq!(connector.connections, 1);
    assert_eq!(case.retained()?, [0, 0]);
    assert_eq!(server.join().map_err(|_| "server thread")??, PROXY_FIRST.0);
    Ok(())
}

#[test]
fn proxy_treats_a_closed_adapter_write_side_as_no_outstanding_request() -> TestResult {
    let exchanges = [PROXY_FIRST];
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let address = listener.local_addr()?;
    let server = proxy_server(listener, &exchanges);
    let case = ProxyCase::new(address, &exchanges, [100, 100, PROXY_DEADLINE_MS])?;
    // The adapter's write side is already closed before the proxy starts.
    let (mut provider, mut adapter) = UnixStream::pair()?;
    adapter.write_all(&case.requests(&exchanges)?)?;
    adapter.shutdown(Shutdown::Write)?;
    let session = serve_bound(
        &case.admission,
        &mut provider,
        &mut ProxyConnector::default(),
        &case.store,
    );
    assert_eq!(session.termination(), None);
    assert_eq!(session.transcripts().len(), 1);
    drop(provider);
    let mut output = Vec::new();
    adapter.read_to_end(&mut output)?;
    assert_eq!(
        case.replies(&output)?[0].response_bytes(),
        Some(PROXY_FIRST.1)
    );
    server.join().map_err(|_| "server thread")??;
    Ok(())
}

#[test]
fn proxy_fails_closed_on_a_channel_whose_queue_cannot_be_inspected() -> TestResult {
    let exchanges = [PROXY_FIRST];
    let case = ProxyCase::new(
        proxy_unused_address()?,
        &exchanges,
        [100, 100, PROXY_DEADLINE_MS],
    )?;
    // A regular file reads like a channel but cannot be peeked as a socket.
    let path = case.root.path().join("channel");
    std::fs::write(&path, case.requests(&exchanges)?)?;
    let mut channel = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&path)?;
    let mut connector = ProxyConnector::default();
    let session = serve_bound(&case.admission, &mut channel, &mut connector, &case.store);
    assert_eq!(
        session.termination(),
        Some(LocalNetworkTermination::ProtocolFailure)
    );
    assert_eq!(connector.connections, 0);
    assert_eq!(std::fs::read(&path)?, case.requests(&exchanges)?);
    Ok(())
}

#[test]
fn proxy_rejects_any_frame_after_every_plan_was_served() -> TestResult {
    let exchanges = [PROXY_FIRST];
    for trailing in [vec![0, 0, 0, 1, 0], vec![0]] {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let address = listener.local_addr()?;
        let server = proxy_server(listener, &exchanges);
        let case = ProxyCase::new(address, &exchanges, [100, 100, PROXY_DEADLINE_MS])?;
        // The trailing bytes arrive only after the last reply was received.
        let mut channel = ProxyChannel::scripted(vec![
            AdapterStep::Send(case.requests(&exchanges)?),
            AdapterStep::AwaitReply,
            AdapterStep::Send(trailing),
        ])?;
        let session = case.serve(&mut channel, &mut ProxyConnector::default())?;
        assert_eq!(
            session.termination(),
            Some(LocalNetworkTermination::ProtocolFailure)
        );
        assert_eq!(session.transcripts().len(), 1);
        assert_eq!(case.replies(&channel.output)?.len(), 1);
        server.join().map_err(|_| "server thread")??;
    }
    Ok(())
}

#[test]
fn proxy_reports_remote_unavailable_for_refused_or_substituted_peers() -> TestResult {
    let exchanges = [PROXY_FIRST];
    let address = proxy_unused_address()?;
    let decoy = TcpListener::bind("127.0.0.1:0")?;
    let decoy_address = decoy.local_addr()?;
    let decoy = thread::spawn(move || -> io::Result<Vec<u8>> {
        let mut stream = proxy_accept(&decoy)?;
        stream.set_read_timeout(Some(PROXY_SERVER_TIMEOUT))?;
        let mut received = Vec::new();
        stream.read_to_end(&mut received)?;
        Ok(received)
    });
    for redirect in [None, Some(decoy_address)] {
        let case = ProxyCase::new(address, &exchanges, [100, 100, PROXY_DEADLINE_MS])?;
        let mut channel = ProxyChannel::new(case.requests(&exchanges)?)?;
        let mut connector = ProxyConnector {
            redirect,
            ..ProxyConnector::default()
        };
        let session = case.serve(&mut channel, &mut connector)?;
        proxy_assert_failed(
            &case,
            &session,
            &channel,
            NetworkExchangeFailure::RemoteUnavailable,
        )?;
        assert_eq!(connector.connections, 1);
    }
    // The substituted peer was rejected before any request byte was written.
    assert!(decoy.join().map_err(|_| "decoy thread")??.is_empty());
    Ok(())
}

#[test]
fn proxy_enforces_the_monotonic_network_deadline() -> TestResult {
    let exchanges = [PROXY_FIRST];
    // A zero deadline denies every exchange before any connection is attempted.
    let case = ProxyCase::new(proxy_unused_address()?, &exchanges, [100, 100, 0])?;
    let mut channel = ProxyChannel::new(case.requests(&exchanges)?)?;
    let mut connector = ProxyConnector::default();
    let session = case.serve(&mut channel, &mut connector)?;
    proxy_assert_failed(
        &case,
        &session,
        &channel,
        NetworkExchangeFailure::RemoteUnavailable,
    )?;
    assert_eq!(connector.connections, 0);

    // A silent peer cannot hold the exchange past the deadline.
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let address = listener.local_addr()?;
    let (release, waiter) = mpsc::channel::<()>();
    let server = thread::spawn(move || -> io::Result<Vec<u8>> {
        let mut stream = proxy_accept(&listener)?;
        stream.set_read_timeout(Some(PROXY_SERVER_TIMEOUT))?;
        let mut received = Vec::new();
        stream.read_to_end(&mut received)?;
        // Without a deadline the proxy would read this close as an empty response.
        waiter.recv_timeout(PROXY_SERVER_TIMEOUT).ok();
        Ok(received)
    });
    let case = ProxyCase::new(address, &exchanges, [100, 100, 1_500])?;
    let mut channel = ProxyChannel::new(case.requests(&exchanges)?)?;
    let started = Instant::now();
    let session = case.serve(&mut channel, &mut ProxyConnector::default())?;
    assert!(started.elapsed() < PROXY_SERVER_TIMEOUT / 2);
    release.send(())?;
    proxy_assert_failed(
        &case,
        &session,
        &channel,
        NetworkExchangeFailure::RemoteUnavailable,
    )?;
    assert_eq!(server.join().map_err(|_| "server thread")??, PROXY_FIRST.0);
    Ok(())
}

#[test]
fn proxy_deadline_bounds_a_request_the_peer_never_reads() -> TestResult {
    let request = vec![5_u8; 15 * 1024 * 1024];
    let response = b"never sent".as_slice();
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let address = listener.local_addr()?;
    let (release, waiter) = mpsc::channel::<()>();
    let server = thread::spawn(move || -> io::Result<()> {
        let _stream = proxy_accept(&listener)?;
        waiter.recv_timeout(PROXY_SERVER_TIMEOUT).ok();
        Ok(())
    });
    let plan = proxy_plan(0, &request, response, 16)?;
    let case = ProxyCase::with_plans(address, vec![plan], [32 << 20, 100, 500])?;
    let mut channel = ProxyChannel::new(case.requests(&[(request.as_slice(), response)])?)?;
    let started = Instant::now();
    let session = case.serve(&mut channel, &mut ProxyConnector::default())?;
    assert!(started.elapsed() < PROXY_SERVER_TIMEOUT / 2);
    release.send(())?;
    proxy_assert_failed(
        &case,
        &session,
        &channel,
        NetworkExchangeFailure::RemoteUnavailable,
    )?;
    server.join().map_err(|_| "server thread")??;
    Ok(())
}

#[test]
fn proxy_enforces_cumulative_request_and_response_ceilings() -> TestResult {
    let exchanges = [PROXY_FIRST, PROXY_SECOND];
    for (limits, connections) in [
        ([proxy_total(&exchanges, 0) - 1, 100, PROXY_DEADLINE_MS], 1),
        ([100, proxy_total(&exchanges, 1) - 1, PROXY_DEADLINE_MS], 2),
    ] {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let address = listener.local_addr()?;
        let server = proxy_server(listener, &exchanges[..connections]);
        let case = ProxyCase::new(address, &exchanges, limits)?;
        let mut channel = ProxyChannel::interactive(case.frames(&exchanges)?)?;
        let mut connector = ProxyConnector::default();
        let session = case.serve(&mut channel, &mut connector)?;
        assert_eq!(
            session.termination(),
            Some(LocalNetworkTermination::RemoteUnavailable)
        );
        assert_eq!(session.transcripts().len(), 1);
        let replies = case.replies(&channel.output)?;
        assert_eq!(replies[0].response_bytes(), Some(PROXY_FIRST.1));
        assert_eq!(
            replies[1].failure(),
            Some(NetworkExchangeFailure::RemoteUnavailable)
        );
        assert_eq!(connector.connections, connections);
        assert_eq!(case.retained()?, [1, 1]);
        server.join().map_err(|_| "server thread")??;
    }
    Ok(())
}

#[test]
fn proxy_reports_digest_mismatch_without_retaining_evidence() -> TestResult {
    let (request, response) = PROXY_FIRST;
    let mut overlong = response.to_vec();
    overlong.extend_from_slice(b" and more");
    for served in [b"first responsE".to_vec(), overlong, Vec::new()] {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let address = listener.local_addr()?;
        let server = proxy_server(listener, &[(request, served.as_slice())]);
        let case = ProxyCase::new(address, &[PROXY_FIRST], [100, 100, PROXY_DEADLINE_MS])?;
        let mut channel = ProxyChannel::new(case.requests(&[PROXY_FIRST])?)?;
        let session = case.serve(&mut channel, &mut ProxyConnector::default())?;
        proxy_assert_failed(
            &case,
            &session,
            &channel,
            NetworkExchangeFailure::DigestMismatch,
        )?;
        server.join().map_err(|_| "server thread")??;
    }
    Ok(())
}

#[test]
fn proxy_rejects_a_response_whose_reply_exceeds_the_control_frame_ceiling() -> TestResult {
    let response = vec![7_u8; 16 * 1024 * 1024];
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let address = listener.local_addr()?;
    let server = proxy_server(listener, &[(PROXY_FIRST.0, response.as_slice())]);
    let plan = proxy_plan(0, PROXY_FIRST.0, &response, response.len() as u64)?;
    let case = ProxyCase::with_plans(address, vec![plan], [100, 32 << 20, PROXY_DEADLINE_MS])?;
    let mut channel = ProxyChannel::new(case.requests(&[(PROXY_FIRST.0, response.as_slice())])?)?;
    let session = case.serve(&mut channel, &mut ProxyConnector::default())?;
    proxy_assert_failed(
        &case,
        &session,
        &channel,
        NetworkExchangeFailure::RemoteUnavailable,
    )?;
    server.join().map_err(|_| "server thread")??;
    Ok(())
}

#[test]
fn proxy_withholds_replies_whose_capture_cannot_be_retained() -> TestResult {
    let exchanges = [PROXY_FIRST];
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let address = listener.local_addr()?;
    let server = proxy_server(listener, &exchanges);
    let case = ProxyCase::new(address, &exchanges, [100, 100, PROXY_DEADLINE_MS])?;
    // A conflicting record already occupies the response artifact's address.
    let name = proxy_digest(b"PiglorOS.NetworkResponseBytes.v1\0", PROXY_FIRST.1)
        .iter()
        .flat_map(|byte| [byte >> 4, byte & 0x0f])
        .map(|nibble| char::from(b"0123456789abcdef"[usize::from(nibble)]))
        .collect::<String>();
    std::fs::write(case.root.path().join("responses").join(name), b"conflict")?;
    let mut channel = ProxyChannel::new(case.requests(&exchanges)?)?;
    let session = case.serve(&mut channel, &mut ProxyConnector::default())?;
    assert_eq!(
        session.termination(),
        Some(LocalNetworkTermination::CaptureFailure)
    );
    assert!(session.transcripts().is_empty());
    assert!(channel.output.is_empty());
    assert_eq!(case.retained()?, [1, 0]);
    server.join().map_err(|_| "server thread")??;
    Ok(())
}

#[test]
fn proxy_reports_channel_failure_when_a_reply_cannot_be_written() -> TestResult {
    let exchanges = [PROXY_FIRST];
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let address = listener.local_addr()?;
    let server = proxy_server(listener, &exchanges);
    for endpoint in [address, proxy_unused_address()?] {
        let case = ProxyCase::new(endpoint, &exchanges, [100, 100, PROXY_DEADLINE_MS])?;
        let mut channel = ProxyChannel::scripted(vec![
            AdapterStep::CloseRead,
            AdapterStep::Send(case.requests(&exchanges)?),
        ])?;
        let session = case.serve(&mut channel, &mut ProxyConnector::default())?;
        assert_eq!(
            session.termination(),
            Some(LocalNetworkTermination::ChannelFailure)
        );
        assert!(session.transcripts().is_empty());
        assert!(channel.output.is_empty());
    }
    server.join().map_err(|_| "server thread")??;
    Ok(())
}

fn proxy_assert_failed(
    case: &ProxyCase,
    session: &LocalNetworkSession,
    channel: &ProxyChannel,
    failure: NetworkExchangeFailure,
) -> TestResult {
    let expected = match failure {
        NetworkExchangeFailure::RemoteUnavailable => LocalNetworkTermination::RemoteUnavailable,
        NetworkExchangeFailure::DigestMismatch => LocalNetworkTermination::DigestMismatch,
    };
    assert_eq!(session.termination(), Some(expected));
    assert!(session.transcripts().is_empty());
    let replies = case.replies(&channel.output)?;
    assert_eq!(replies.len(), 1);
    assert_eq!(replies[0].failure(), Some(failure));
    assert_eq!(replies[0].response_bytes(), None);
    assert_eq!(case.retained()?, [0, 0]);
    Ok(())
}

fn proxy_server(
    listener: TcpListener,
    exchanges: &[(&[u8], &[u8])],
) -> JoinHandle<io::Result<Vec<Vec<u8>>>> {
    let responses = exchanges
        .iter()
        .map(|(_, response)| response.to_vec())
        .collect::<Vec<_>>();
    thread::spawn(move || {
        responses
            .into_iter()
            .map(|response| {
                let mut stream = proxy_accept(&listener)?;
                stream.set_read_timeout(Some(PROXY_SERVER_TIMEOUT))?;
                let mut received = Vec::new();
                stream.read_to_end(&mut received)?;
                stream.write_all(&response)?;
                Ok(received)
            })
            .collect()
    })
}

/// Accept one connection, or fail instead of hanging when none arrives.
fn proxy_accept(listener: &TcpListener) -> io::Result<TcpStream> {
    listener.set_nonblocking(true)?;
    let deadline = Instant::now() + PROXY_SERVER_TIMEOUT;
    loop {
        let accepted = listener.accept();
        match accepted {
            Ok((stream, _)) => {
                stream.set_nonblocking(false)?;
                return Ok(stream);
            }
            Err(error)
                if error.kind() == io::ErrorKind::WouldBlock && Instant::now() < deadline =>
            {
                thread::sleep(Duration::from_millis(5));
            }
            Err(error) => return Err(error),
        }
    }
}

fn proxy_unused_address() -> TestResult<SocketAddr> {
    Ok(TcpListener::bind("127.0.0.1:0")?.local_addr()?)
}

fn proxy_total(exchanges: &[(&[u8], &[u8])], side: usize) -> u64 {
    exchanges
        .iter()
        .map(|exchange| [exchange.0, exchange.1][side].len() as u64)
        .sum()
}

fn proxy_plan(
    occurrence: u64,
    request: &[u8],
    response: &[u8],
    response_maximum: u64,
) -> TestResult<NetworkExchangePlan> {
    let mut plan = local_plan(occurrence, request.len() as u64, response_maximum)?;
    plan.request_digest = proxy_digest(b"PiglorOS.NetworkRequestBytes.v1\0", request);
    plan.expected_response_digest = proxy_digest(b"PiglorOS.NetworkResponseBytes.v1\0", response);
    seal_local_plan(&mut plan)?;
    Ok(plan)
}

fn proxy_digest(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(bytes);
    *hasher.finalize().as_bytes()
}
