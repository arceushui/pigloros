//! Provider-neutral Local FD 3 proxy: one exact-endpoint TCP exchange per NXQ1.
//!
//! The proxy serves the adapter's host-service channel. For each authenticated
//! NXP1 occurrence, in caller order, it verifies the complete request before
//! any connection exists. It then connects once to the admitted endpoint,
//! writes exactly those bytes, shuts down its write side and reads to TCP EOF
//! within the response bound and the attempt's monotonic network deadline. A
//! response becomes a Captured reply only after its capture is durably retained.
//! Only one NXQ1 may be outstanding; an early second request fails closed.

use std::io::{self, Read, Write};
use std::net::{IpAddr, Shutdown, SocketAddr, TcpStream};
use std::ops::ControlFlow;
use std::os::fd::AsFd;
use std::time::{Duration, Instant};

use rustix::io::Errno;
use rustix::net::{recv, RecvFlags};

use super::{
    NetworkCaptureStore, NetworkExchangeFailure, NetworkExchangeReply, NetworkExchangeRequest,
    NetworkExchangeTranscript,
};
use crate::control_framing;
use crate::sandbox_provider_protocol::codec::MAX_DOCUMENT_BYTES;
use crate::sandbox_provider_protocol::{
    LocalNetworkAdmission, NetworkCapability, NetworkExchangePlan, SandboxProviderProtocolError,
};

/// Opens the one outbound TCP connection of an exchange to an admitted endpoint.
///
/// The provider implements this port where its namespace and firewall policy
/// apply, so provider-specific socket creation stays outside the proxy. The
/// proxy chooses the endpoint and rejects a connection to any other peer.
pub trait NetworkEndpointConnector {
    /// Connect to exactly `endpoint` within `timeout`.
    ///
    /// # Errors
    /// Any failure makes the exchange `RemoteUnavailable`.
    fn connect(&mut self, endpoint: SocketAddr, timeout: Duration) -> io::Result<TcpStream>;
}

/// Why a proxy session ended before its host-service channel closed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LocalNetworkTermination {
    /// An NXY1 `RemoteUnavailable` reply was written; the attempt terminates.
    RemoteUnavailable,
    /// An NXY1 `DigestMismatch` reply was written; the attempt terminates.
    DigestMismatch,
    /// A zero, oversized, truncated, malformed, unplanned or mismatched frame
    /// arrived, or another frame was already waiting behind an unanswered
    /// NXQ1. No reply was written.
    ProtocolFailure,
    /// A verified capture could not be durably retained. No reply was written.
    CaptureFailure,
    /// A reply could not be written to the host-service channel.
    ChannelFailure,
}

/// The ordered captures of one proxy session and how the session ended.
///
/// Transcripts are an in-order prefix of the admitted plans; each was retained
/// before its Captured reply was written. A `None` termination means the
/// adapter closed the channel at a frame boundary. Classifying the attempt and
/// signing evidence remain the provider lifecycle's responsibility.
#[derive(Clone, Debug, PartialEq)]
#[must_use]
pub struct LocalNetworkSession {
    transcripts: Vec<NetworkExchangeTranscript>,
    termination: Option<LocalNetworkTermination>,
}

impl LocalNetworkSession {
    /// The retained transcripts, in admitted plan order.
    #[must_use]
    pub fn transcripts(&self) -> &[NetworkExchangeTranscript] {
        &self.transcripts
    }

    /// The terminal condition, or `None` after a clean channel close.
    #[must_use]
    pub const fn termination(&self) -> Option<LocalNetworkTermination> {
        self.termination
    }
}

impl LocalNetworkAdmission {
    /// Serve this attempt's FD 3 host-service channel until it closes or ends.
    ///
    /// The ELM1 network deadline starts when this call starts. Cumulative ELM1
    /// request and response byte ceilings apply across all exchanges. The
    /// provider must already have bound this admission to its active attempt,
    /// current authority heads, namespace and firewall, and FD 3; the channel
    /// itself is bounded by the attempt watchdog, not by the network deadline.
    ///
    /// The channel must be a stream socket. Only one NXQ1 may be outstanding:
    /// the proxy peeks without blocking before forwarding each request and
    /// again before retaining or releasing its response. A byte already queued
    /// at either point means a second NXQ1 was sent before the reply, and the
    /// session fails closed as [`LocalNetworkTermination::ProtocolFailure`]
    /// with no reply; so does a channel whose queue cannot be inspected. Bytes
    /// that arrive after the second peek are read only after the reply.
    pub fn serve_proxy(
        &self,
        channel: &mut (impl Read + Write + AsFd),
        connector: &mut impl NetworkEndpointConnector,
        store: &NetworkCaptureStore,
    ) -> LocalNetworkSession {
        let limits = self.limits();
        let mut proxy = Proxy {
            attempt_id: self.grant().attempt_id,
            deadline: Instant::now() + Duration::from_millis(limits.milliseconds),
            request_budget: limits.request_bytes,
            response_budget: limits.response_bytes,
            transcripts: Vec::new(),
        };
        let served =
            self.exchanges().try_for_each(
                |(plan, endpoint)| match NetworkExchangeRequest::read_next(channel, plan) {
                    // Only one NXQ1 may be outstanding: any byte already waiting
                    // behind this request ends the session before forwarding.
                    Ok(Some(_)) if request_pending(&*channel) => {
                        ControlFlow::Break(Some(LocalNetworkTermination::ProtocolFailure))
                    }
                    Ok(Some(request)) => {
                        proxy.exchange(&request, plan, endpoint, channel, connector, store)
                    }
                    Ok(None) => ControlFlow::Break(None),
                    Err(_) => ControlFlow::Break(Some(LocalNetworkTermination::ProtocolFailure)),
                },
            );
        let termination = match served {
            ControlFlow::Break(termination) => termination,
            // Every plan was served: only a clean close may follow.
            ControlFlow::Continue(()) => (control_framing::read_frame(channel, MAX_DOCUMENT_BYTES)
                != Ok(None))
            .then_some(LocalNetworkTermination::ProtocolFailure),
        };
        LocalNetworkSession {
            transcripts: proxy.transcripts,
            termination,
        }
    }
}

struct Proxy {
    attempt_id: [u8; 16],
    deadline: Instant,
    request_budget: u64,
    response_budget: u64,
    transcripts: Vec<NetworkExchangeTranscript>,
}

impl Proxy {
    /// Serve one verified request; `Break` ends the session with that outcome.
    fn exchange(
        &mut self,
        request: &NetworkExchangeRequest,
        plan: &NetworkExchangePlan,
        endpoint: &NetworkCapability,
        channel: &mut (impl Write + AsFd),
        connector: &mut impl NetworkEndpointConnector,
        store: &NetworkCaptureStore,
    ) -> ControlFlow<Option<LocalNetworkTermination>> {
        match self.forward(request, plan, endpoint, connector) {
            Ok((reply, response_length)) => {
                // A frame sent while this exchange was in flight was a second
                // outstanding NXQ1: nothing is retained or released.
                if request_pending(&*channel) {
                    return ControlFlow::Break(Some(LocalNetworkTermination::ProtocolFailure));
                }
                if store.persist(&reply).is_err() {
                    return ControlFlow::Break(Some(LocalNetworkTermination::CaptureFailure));
                }
                if reply.write_to(channel).is_err() {
                    return ControlFlow::Break(Some(LocalNetworkTermination::ChannelFailure));
                }
                self.request_budget -= plan.request_length;
                self.response_budget -= response_length;
                self.transcripts.extend(reply.transcript().cloned());
                ControlFlow::Continue(())
            }
            Err(failure) => ControlFlow::Break(Some(
                if request.failed(failure).write_to(channel).is_err() {
                    LocalNetworkTermination::ChannelFailure
                } else {
                    match failure {
                        NetworkExchangeFailure::RemoteUnavailable => {
                            LocalNetworkTermination::RemoteUnavailable
                        }
                        NetworkExchangeFailure::DigestMismatch => {
                            LocalNetworkTermination::DigestMismatch
                        }
                    }
                },
            )),
        }
    }

    /// Perform the single remote exchange and validate its complete response.
    fn forward(
        &self,
        request: &NetworkExchangeRequest,
        plan: &NetworkExchangePlan,
        endpoint: &NetworkCapability,
        connector: &mut impl NetworkEndpointConnector,
    ) -> Result<(NetworkExchangeReply, u64), NetworkExchangeFailure> {
        if plan.request_length > self.request_budget {
            return Err(NetworkExchangeFailure::RemoteUnavailable);
        }
        let address = endpoint_address(endpoint);
        let limit = plan.response_maximum.min(self.response_budget);
        remaining(self.deadline)
            .and_then(|timeout| connector.connect(address, timeout))
            .and_then(|stream| {
                stream.peer_addr().and_then(|peer| {
                    if peer == address {
                        exchange_bytes(&stream, self.deadline, request.request_bytes(), limit)
                    } else {
                        Err(io::ErrorKind::AddrNotAvailable.into())
                    }
                })
            })
            .map_err(|_| NetworkExchangeFailure::RemoteUnavailable)
            .and_then(|response| {
                let length = response.len() as u64;
                if length > self.response_budget {
                    return Err(NetworkExchangeFailure::RemoteUnavailable);
                }
                request
                    .capture(self.attempt_id, &response)
                    .map(|reply| (reply, length))
                    .map_err(|error| match error {
                        SandboxProviderProtocolError::DigestMismatch => {
                            NetworkExchangeFailure::DigestMismatch
                        }
                        _ => NetworkExchangeFailure::RemoteUnavailable,
                    })
            })
    }
}

fn endpoint_address(endpoint: &NetworkCapability) -> SocketAddr {
    // Authenticated LPS1 admits only exact four- or sixteen-byte addresses.
    let address = &endpoint.address;
    let ip = <[u8; 16]>::try_from(address.as_slice()).map_or_else(
        |_| IpAddr::from([address[0], address[1], address[2], address[3]]),
        IpAddr::from,
    );
    SocketAddr::new(ip, endpoint.destination_port)
}

/// Write the request, end the write side, then read at most `limit + 1` bytes.
fn exchange_bytes(
    stream: &TcpStream,
    deadline: Instant,
    request: &[u8],
    limit: u64,
) -> io::Result<Vec<u8>> {
    send(stream, deadline, request)
        .and_then(|()| stream.shutdown(Shutdown::Write))
        .and_then(|()| {
            let mut response = Vec::new();
            DeadlineReader { stream, deadline }
                .take(limit.saturating_add(1))
                .read_to_end(&mut response)
                .map(|_| response)
        })
}

/// Write every request byte, applying the remaining deadline to each write.
fn send(stream: &TcpStream, deadline: Instant, request: &[u8]) -> io::Result<()> {
    let mut writer = stream;
    let mut sent = 0;
    while sent < request.len() {
        sent += remaining(deadline)
            .and_then(|timeout| stream.set_write_timeout(Some(timeout)))
            .and_then(|()| writer.write(&request[sent..]))?;
    }
    Ok(())
}

/// Applies the remaining attempt deadline before every response read.
struct DeadlineReader<'a> {
    stream: &'a TcpStream,
    deadline: Instant,
}

impl Read for DeadlineReader<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        remaining(self.deadline)
            .and_then(|timeout| self.stream.set_read_timeout(Some(timeout)))
            .and_then(|()| self.stream.read(buffer))
    }
}

/// Whether bytes already wait behind the request just read. A channel that
/// cannot be peeked counts as pending, so the check fails closed.
fn request_pending(channel: &impl AsFd) -> bool {
    let mut byte = [0_u8; 1];
    recv(
        channel,
        &mut byte,
        RecvFlags::PEEK.union(RecvFlags::DONTWAIT),
    )
    .map_or_else(|errno| errno != Errno::AGAIN, |(read, _)| read != 0)
}

fn remaining(deadline: Instant) -> io::Result<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|timeout| !timeout.is_zero())
        .ok_or(io::ErrorKind::TimedOut)
        .map_err(io::Error::from)
}
