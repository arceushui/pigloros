//! Netlink requests over a rustix socket, in the network namespace of the
//! thread that opened it (#911, owner decision 2026-11-09).
//!
//! A [`NetlinkSession`] numbers each request, sends it, and reads the
//! kernel's replies until every acknowledged request is answered or a dump
//! ends. Any reply it cannot attribute to an outstanding request, any
//! interrupted dump and any truncated datagram is an error: the session never
//! guesses. A session that returned an error may still have replies queued,
//! so its caller discards it and opens a new one. [`in_namespace`] runs work on a dedicated thread that has entered
//! a namespace, so a socket opened there stays bound to that namespace.
//!
//! No other netlink crate performs I/O: `netlink-packet-*` only encodes and
//! decodes, and netlink-sys, netlink-proto and rtnetlink are not used.

use std::collections::BTreeSet;
use std::os::fd::{BorrowedFd, OwnedFd};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use netlink_packet_core::{
    NetlinkDeserializable, NetlinkHeader, NetlinkMessage, NetlinkPayload, NetlinkSerializable,
    NLM_F_ACK, NLM_F_DUMP, NLM_F_DUMP_INTR, NLM_F_REQUEST,
};
use netlink_packet_route::link::{InfoKind, LinkAttribute, LinkFlags, LinkInfo, LinkMessage};
use netlink_packet_route::RouteNetlinkMessage;
use rustix::io::{retry_on_intr, Errno};
use rustix::net::netlink::{self, SocketAddrNetlink};
use rustix::net::sockopt::{set_socket_timeout, Timeout};
use rustix::net::{AddressFamily, RecvFlags, SendFlags, SocketFlags, SocketType};
use rustix::thread::{move_into_link_name_space, LinkNameSpaceType};

use super::{LinkKind, ObservedLink};

/// The largest datagram a session reads. The kernel sizes dump datagrams
/// well below it; a larger one is refused as truncated.
const RECEIVE_BUFFER: usize = 1 << 16;

// Each flag set below adds disjoint single-bit flags, so the sum is their
// union; `|` would read the same, but `^` would too, and a mutation of it
// could never be told apart.
/// The flags of a request the kernel acknowledges.
const ACKNOWLEDGED_REQUEST: u16 = NLM_F_REQUEST + NLM_F_ACK;
/// The flags of a dump request (`NLM_F_DUMP` is `NLM_F_ROOT` and
/// `NLM_F_MATCH`, neither of which is `NLM_F_REQUEST`).
const DUMP_REQUEST: u16 = NLM_F_REQUEST + NLM_F_DUMP;

/// How long a session waits for any one reply datagram before it fails.
pub const RECEIVE_TIMEOUT: Duration = Duration::from_secs(10);

/// Why a netlink exchange failed.
#[derive(Debug, thiserror::Error)]
pub enum NetlinkError {
    /// A socket call failed, or no reply arrived in time.
    #[error("a netlink socket call failed")]
    Io(#[from] Errno),
    /// An exchange held no request.
    #[error("a netlink exchange held no request")]
    Empty,
    /// A reply did not fit the receive buffer.
    #[error("a netlink reply did not fit the receive buffer")]
    Truncated,
    /// A reply could not be decoded.
    #[error("a netlink reply could not be decoded")]
    Decode,
    /// The kernel refused a request with this negative errno.
    #[error("the kernel refused a netlink request with error {0}")]
    Kernel(i32),
    /// The state changed while a dump was read.
    #[error("a netlink dump was interrupted by a concurrent change")]
    Interrupted,
    /// A reply answered no outstanding request.
    #[error("a netlink reply answered no outstanding request")]
    Unexpected,
    /// The kernel reported state the provider's types cannot represent.
    #[error("the kernel reported state the provider cannot represent")]
    Unrepresentable,
    /// The thread that entered a namespace panicked.
    #[error("the thread inside the network namespace panicked")]
    Panicked,
    /// Provider-owned network state remained after it was removed.
    #[error("provider network state remained after its removal")]
    Residual,
}

/// One netlink socket: whole datagrams out, whole datagrams in.
pub trait NetlinkTransport {
    /// Send one datagram to the kernel.
    ///
    /// # Errors
    /// Fails if the kernel does not accept the datagram.
    fn send(&self, datagram: &[u8]) -> Result<(), NetlinkError>;

    /// Receive one datagram from the kernel.
    ///
    /// # Errors
    /// Fails if the socket call fails, no datagram arrives in time, or the
    /// datagram does not fit.
    fn receive(&self) -> Result<Vec<u8>, NetlinkError>;
}

/// A close-on-exec netlink socket bound to a kernel-assigned port.
#[derive(Debug)]
pub struct NetlinkSocket(OwnedFd);

impl NetlinkSocket {
    /// Open a socket of `protocol`, such as [`ROUTE`] or [`NETFILTER`], in
    /// the calling thread's network namespace,
    /// whose receives fail after `receive_timeout`.
    ///
    /// # Errors
    /// Fails if the socket cannot be created, bound or given its timeout.
    pub fn open(
        protocol: Option<rustix::net::Protocol>,
        receive_timeout: Duration,
    ) -> Result<Self, NetlinkError> {
        let socket = rustix::net::socket_with(
            AddressFamily::NETLINK,
            SocketType::RAW,
            SocketFlags::CLOEXEC,
            protocol,
        )?;
        rustix::net::bind(&socket, &SocketAddrNetlink::new(0, 0))
            .and_then(|()| set_socket_timeout(&socket, Timeout::Recv, Some(receive_timeout)))
            .map(|()| Self(socket))
            .map_err(NetlinkError::from)
    }
}

impl NetlinkTransport for NetlinkSocket {
    fn send(&self, datagram: &[u8]) -> Result<(), NetlinkError> {
        // A netlink socket sends a datagram whole or not at all, so the
        // count it returns is always the datagram's length.
        retry_on_intr(|| rustix::net::send(&self.0, datagram, SendFlags::empty()))
            .map(drop)
            .map_err(NetlinkError::from)
    }

    fn receive(&self) -> Result<Vec<u8>, NetlinkError> {
        let mut buffer = vec![0; RECEIVE_BUFFER];
        // With `MSG_TRUNC` the kernel reports the whole datagram's length.
        let (_, length) =
            retry_on_intr(|| rustix::net::recv(&self.0, &mut buffer[..], RecvFlags::TRUNC))?;
        buffer.truncate(length);
        (length <= RECEIVE_BUFFER)
            .then_some(buffer)
            .ok_or(NetlinkError::Truncated)
    }
}

/// One request of a [`NetlinkSession::execute`] datagram.
#[derive(Debug)]
pub struct Request<I> {
    pub(super) message: I,
    pub(super) flags: u16,
    pub(super) acknowledged: bool,
}

impl<I> Request<I> {
    /// A request the kernel must acknowledge, with `NLM_F_*` `flags` beyond
    /// `NLM_F_REQUEST` and `NLM_F_ACK`.
    pub const fn acknowledged(message: I, flags: u16) -> Self {
        Self {
            message,
            flags,
            acknowledged: true,
        }
    }

    /// A request the kernel does not acknowledge, such as the delimiters of
    /// an nftables batch.
    pub const fn unacknowledged(message: I) -> Self {
        Self {
            message,
            flags: 0,
            acknowledged: false,
        }
    }
}

/// Numbered requests and their replies over one transport.
///
/// After an error, replies to the failed exchange may still be queued and
/// would be misread as replies to the next one, so a caller discards a
/// session that returned an error.
#[derive(Debug)]
pub struct NetlinkSession<T> {
    transport: T,
    sequence: AtomicU32,
}

impl NetlinkSession<NetlinkSocket> {
    /// A session over a new socket of `protocol` in the calling thread's
    /// network namespace, waiting at most [`RECEIVE_TIMEOUT`] for each reply.
    ///
    /// # Errors
    /// Fails if the socket cannot be opened.
    pub fn open(protocol: Option<rustix::net::Protocol>) -> Result<Self, NetlinkError> {
        NetlinkSocket::open(protocol, RECEIVE_TIMEOUT).map(Self::new)
    }
}

impl<T: NetlinkTransport> NetlinkSession<T> {
    /// A session over `transport`, numbering requests from 1.
    pub const fn new(transport: T) -> Self {
        Self {
            transport,
            sequence: AtomicU32::new(0),
        }
    }

    /// A request header with the next sequence number and `flags`.
    fn header(&self, flags: u16) -> NetlinkHeader {
        let mut header = NetlinkHeader::default();
        header.flags = flags;
        header.sequence_number = self
            .sequence
            .fetch_add(1, Ordering::Relaxed)
            .wrapping_add(1);
        header
    }

    /// Send `requests` in one datagram, and wait until the kernel has
    /// acknowledged every acknowledged one.
    ///
    /// # Errors
    /// Fails if `requests` is empty, on the first refusal, which the kernel
    /// may report for any request of the datagram, and on any reply that
    /// acknowledges no outstanding request.
    pub fn execute<I>(&self, requests: Vec<Request<I>>) -> Result<(), NetlinkError>
    where
        I: NetlinkSerializable + NetlinkDeserializable,
    {
        if requests.is_empty() {
            return Err(NetlinkError::Empty);
        }
        let mut datagram = Vec::new();
        let mut outstanding = BTreeSet::new();
        for request in requests {
            let base = if request.acknowledged {
                ACKNOWLEDGED_REQUEST
            } else {
                NLM_F_REQUEST
            };
            let header = self.header(base | request.flags);
            if request.acknowledged {
                outstanding.insert(header.sequence_number);
            }
            emit(header, request.message, &mut datagram);
        }
        self.transport.send(&datagram)?;
        while !outstanding.is_empty() {
            for message in parse::<I>(&self.transport.receive()?)? {
                acknowledge(&mut outstanding, &message)?;
            }
        }
        Ok(())
    }

    /// Send `request`, which the kernel answers with exactly one message,
    /// such as a `GET` of one object, and return that message.
    ///
    /// # Errors
    /// Fails if the kernel refuses the request or the reply is not exactly
    /// one message answering it.
    pub fn request<I>(&self, request: I) -> Result<I, NetlinkError>
    where
        I: NetlinkSerializable + NetlinkDeserializable,
    {
        let header = self.header(NLM_F_REQUEST);
        let sequence = header.sequence_number;
        let mut datagram = Vec::new();
        emit(header, request, &mut datagram);
        self.transport.send(&datagram)?;
        let replies = parse::<I>(&self.transport.receive()?)?;
        let [reply] =
            <[NetlinkMessage<I>; 1]>::try_from(replies).map_err(|_| NetlinkError::Unexpected)?;
        let answered = reply.header.sequence_number == sequence;
        match reply.payload {
            NetlinkPayload::InnerMessage(message) if answered => Ok(message),
            NetlinkPayload::Error(error) if answered => {
                Err(error.code.map_or(NetlinkError::Unexpected, |code| {
                    NetlinkError::Kernel(code.get())
                }))
            }
            _ => Err(NetlinkError::Unexpected),
        }
    }

    /// Send `request` as a dump and return every message of the reply.
    ///
    /// # Errors
    /// Fails if the kernel refuses the dump, interrupts it, or sends a reply
    /// to another request.
    pub fn dump<I>(&self, request: I) -> Result<Vec<I>, NetlinkError>
    where
        I: NetlinkSerializable + NetlinkDeserializable,
    {
        let header = self.header(DUMP_REQUEST);
        let sequence = header.sequence_number;
        let mut datagram = Vec::new();
        emit(header, request, &mut datagram);
        self.transport.send(&datagram)?;
        let mut replies = Vec::new();
        loop {
            for message in parse::<I>(&self.transport.receive()?)? {
                let interrupted = message.header.flags & NLM_F_DUMP_INTR != 0;
                match message.payload {
                    _ if message.header.sequence_number != sequence => {
                        return Err(NetlinkError::Unexpected)
                    }
                    _ if interrupted => return Err(NetlinkError::Interrupted),
                    NetlinkPayload::InnerMessage(reply) => replies.push(reply),
                    NetlinkPayload::Done(done) => {
                        return (done.code == 0)
                            .then_some(replies)
                            .ok_or(NetlinkError::Kernel(done.code));
                    }
                    NetlinkPayload::Error(error) => {
                        return Err(NetlinkError::Kernel(error.raw_code()))
                    }
                    _ => return Err(NetlinkError::Unexpected),
                }
            }
        }
    }
}

/// How often [`consistent`] reads state that keeps changing.
const DUMP_ATTEMPTS: usize = 3;

/// Run `read`, which opens its own session, again while a dump it makes is
/// interrupted by a concurrent change, at most three times in all.
///
/// Another namespace's changes interrupt dumps of the shared host
/// namespace; a fresh session discards the interrupted dump's replies.
///
/// # Errors
/// Fails with `read`'s first other error, or if every attempt is
/// interrupted.
pub fn consistent<T>(mut read: impl FnMut() -> Result<T, NetlinkError>) -> Result<T, NetlinkError> {
    (1..DUMP_ATTEMPTS).fold(read(), |result, _| match result {
        Err(NetlinkError::Interrupted) => read(),
        settled => settled,
    })
}

/// Append `message` with `header` to `datagram`.
fn emit<I: NetlinkSerializable>(header: NetlinkHeader, message: I, datagram: &mut Vec<u8>) {
    let mut message = NetlinkMessage::new(header, NetlinkPayload::InnerMessage(message));
    message.finalize();
    let start = datagram.len();
    datagram.resize(start + message.buffer_len(), 0);
    message.serialize(&mut datagram[start..]);
}

/// Every message of one received datagram.
fn parse<I: NetlinkDeserializable>(
    datagram: &[u8],
) -> Result<Vec<NetlinkMessage<I>>, NetlinkError> {
    let mut messages = Vec::new();
    let mut rest = datagram;
    while !rest.is_empty() {
        let message = NetlinkMessage::<I>::deserialize(rest).map_err(|_| NetlinkError::Decode)?;
        // `deserialize` refuses a header length below the header's own 16
        // bytes, so every step advances; the last message may omit its
        // padding.
        let aligned = (message.header.length as usize).next_multiple_of(4);
        rest = rest.get(aligned..).unwrap_or_default();
        messages.push(message);
    }
    Ok(messages)
}

/// Retire the outstanding request `message` acknowledges.
fn acknowledge<I>(
    outstanding: &mut BTreeSet<u32>,
    message: &NetlinkMessage<I>,
) -> Result<(), NetlinkError> {
    match &message.payload {
        NetlinkPayload::Error(error) => error.code.map_or_else(
            || {
                outstanding
                    .remove(&message.header.sequence_number)
                    .then_some(())
                    .ok_or(NetlinkError::Unexpected)
            },
            |code| Err(NetlinkError::Kernel(code.get())),
        ),
        _ => Err(NetlinkError::Unexpected),
    }
}

/// Run `work` on a new thread that has entered the network namespace
/// `namespace`, and return its result. Sockets `work` opens belong to that
/// namespace; the calling thread's namespace never changes.
///
/// # Errors
/// Fails if the thread cannot enter the namespace or panics.
pub fn in_namespace<R: Send>(
    namespace: BorrowedFd<'_>,
    work: impl FnOnce() -> R + Send,
) -> Result<R, NetlinkError> {
    std::thread::scope(|scope| {
        scope
            .spawn(move || -> Result<R, NetlinkError> {
                move_into_link_name_space(namespace, Some(LinkNameSpaceType::Network))?;
                Ok(work())
            })
            .join()
            .unwrap_or(Err(NetlinkError::Panicked))
    })
}

/// Every link of the session's namespace.
///
/// # Errors
/// Fails if the dump fails, or a link has no name or is a veth end without
/// its peer's index.
pub fn links<T: NetlinkTransport>(
    session: &NetlinkSession<T>,
) -> Result<Vec<ObservedLink>, NetlinkError> {
    session
        .dump(RouteNetlinkMessage::GetLink(LinkMessage::default()))?
        .into_iter()
        .map(|reply| match reply {
            RouteNetlinkMessage::NewLink(link) => observed_link(link),
            _ => Err(NetlinkError::Unexpected),
        })
        .collect()
}

/// The link `message` reports.
pub(super) fn observed_link(message: LinkMessage) -> Result<ObservedLink, NetlinkError> {
    let mut name = None;
    let mut veth = false;
    let mut peer_index = None;
    let mut peer_netnsid = None;
    for attribute in message.attributes {
        match attribute {
            LinkAttribute::IfName(value) => name = Some(value),
            LinkAttribute::LinkInfo(infos) => {
                veth |= infos
                    .iter()
                    .any(|info| matches!(info, LinkInfo::Kind(InfoKind::Veth)));
            }
            LinkAttribute::Link(index) => peer_index = Some(index),
            LinkAttribute::LinkNetNsId(id) => peer_netnsid = Some(id),
            _ => {}
        }
    }
    let flags = message.header.flags;
    let kind = match (flags.contains(LinkFlags::Loopback), veth, peer_index) {
        (true, _, _) => Ok(LinkKind::Loopback),
        (false, true, Some(peer_index)) => Ok(LinkKind::Veth {
            peer_index,
            peer_netnsid,
        }),
        (false, true, None) => Err(NetlinkError::Unrepresentable),
        (false, false, _) => Ok(LinkKind::Other),
    }?;
    name.map(|name| ObservedLink {
        index: message.header.index,
        name,
        kind,
        up: flags.contains(LinkFlags::Up),
    })
    .ok_or(NetlinkError::Unrepresentable)
}

/// The route netlink protocol, for callers that open sessions:
/// `NETLINK_ROUTE` is protocol 0, the default.
pub const ROUTE: Option<rustix::net::Protocol> = None;
/// The netfilter netlink protocol, for callers that open sessions.
pub const NETFILTER: Option<rustix::net::Protocol> = Some(netlink::NETFILTER);

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests;
