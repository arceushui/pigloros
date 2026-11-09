use std::{
    cell::RefCell, collections::VecDeque, error::Error, fs::File, num::NonZeroI32, os::fd::AsFd,
    time::Duration,
};

use netlink_packet_core::{DoneMessage, ErrorMessage, NLM_F_CREATE, NLM_F_EXCL, NLM_F_MULTIPART};
use netlink_packet_route::link::LinkHeader;

use super::*;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

/// Whether an error is the one a case expects.
type Expected = fn(&NetlinkError) -> bool;

/// A transport that records every datagram and replays scripted replies.
#[derive(Default)]
struct Scripted {
    sent: RefCell<Vec<Vec<u8>>>,
    replies: RefCell<VecDeque<Result<Vec<u8>, NetlinkError>>>,
    refuse_send: bool,
}

impl Scripted {
    fn replying(replies: Vec<Vec<u8>>) -> Self {
        Self {
            replies: RefCell::new(replies.into_iter().map(Ok).collect()),
            ..Self::default()
        }
    }
}

impl NetlinkTransport for Scripted {
    fn send(&self, datagram: &[u8]) -> Result<(), NetlinkError> {
        if self.refuse_send {
            return Err(NetlinkError::Io(Errno::MSGSIZE));
        }
        self.sent.borrow_mut().push(datagram.to_vec());
        Ok(())
    }

    fn receive(&self) -> Result<Vec<u8>, NetlinkError> {
        self.replies
            .borrow_mut()
            .pop_front()
            .unwrap_or(Err(NetlinkError::Truncated))
    }
}

/// One reply message with `sequence`, `flags` and `payload`.
fn reply(sequence: u32, flags: u16, payload: NetlinkPayload<RouteNetlinkMessage>) -> Vec<u8> {
    let mut header = NetlinkHeader::default();
    header.sequence_number = sequence;
    header.flags = flags;
    let mut message = NetlinkMessage::new(header, payload);
    message.finalize();
    let mut bytes = vec![0; message.buffer_len()];
    message.serialize(&mut bytes);
    bytes
}

fn ack(sequence: u32, code: i32) -> Vec<u8> {
    let mut error = ErrorMessage::default();
    error.code = NonZeroI32::new(code);
    reply(sequence, 0, NetlinkPayload::Error(error))
}

fn done(sequence: u32, code: i32) -> Vec<u8> {
    let mut done = DoneMessage::default();
    done.code = code;
    reply(sequence, NLM_F_MULTIPART, NetlinkPayload::Done(done))
}

fn link_reply(sequence: u32, flags: u16, link: LinkMessage) -> Vec<u8> {
    reply(
        sequence,
        flags,
        NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewLink(link)),
    )
}

fn link(index: u32, flags: LinkFlags, attributes: Vec<LinkAttribute>) -> LinkMessage {
    let header = LinkHeader {
        index,
        flags,
        ..LinkHeader::default()
    };
    let mut message = LinkMessage::default();
    message.header = header;
    message.attributes = attributes;
    message
}

fn get_link() -> RouteNetlinkMessage {
    RouteNetlinkMessage::GetLink(LinkMessage::default())
}

fn sent_headers(transport: &Scripted) -> TestResult<Vec<NetlinkHeader>> {
    let sent = transport.sent.borrow();
    let datagram = sent.first().ok_or("nothing was sent")?;
    Ok(parse::<RouteNetlinkMessage>(datagram)?
        .into_iter()
        .map(|message| message.header)
        .collect())
}

#[test]
fn an_acknowledged_request_waits_for_its_acknowledgement() -> TestResult {
    let session = NetlinkSession::new(Scripted::replying(vec![ack(1, 0)]));
    session.execute(vec![Request::acknowledged(
        get_link(),
        NLM_F_CREATE | NLM_F_EXCL,
    )])?;
    let headers = sent_headers(&session.transport)?;
    assert_eq!(headers.len(), 1);
    assert_eq!(headers[0].sequence_number, 1);
    assert_eq!(
        headers[0].flags,
        NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL
    );
    Ok(())
}

#[test]
fn request_flags_add_to_the_request_and_acknowledgement_flags() -> TestResult {
    // Flags that repeat a bit the session sets leave it set.
    let session = NetlinkSession::new(Scripted::replying(vec![ack(1, 0)]));
    session.execute(vec![Request::acknowledged(
        get_link(),
        NLM_F_REQUEST | NLM_F_ACK,
    )])?;
    assert_eq!(
        sent_headers(&session.transport)?[0].flags,
        NLM_F_REQUEST | NLM_F_ACK
    );
    Ok(())
}

#[test]
fn a_batch_waits_only_for_its_acknowledged_requests() -> TestResult {
    // Sequence 1 and 4 delimit the batch; 2 and 3 are acknowledged in two
    // datagrams, in either order.
    let session = NetlinkSession::new(Scripted::replying(vec![ack(3, 0), ack(2, 0)]));
    session.execute(vec![
        Request::unacknowledged(get_link()),
        Request::acknowledged(get_link(), 0),
        Request::acknowledged(get_link(), 0),
        Request::unacknowledged(get_link()),
    ])?;
    let headers = sent_headers(&session.transport)?;
    let flags: Vec<u16> = headers.iter().map(|header| header.flags).collect();
    assert_eq!(
        flags,
        [
            NLM_F_REQUEST,
            NLM_F_REQUEST | NLM_F_ACK,
            NLM_F_REQUEST | NLM_F_ACK,
            NLM_F_REQUEST
        ]
    );
    // Sequences 1 and 2 are outstanding, so an acknowledgement of 3 is
    // unexpected even after 2 is retired.
    let mut both = ack(2, 0);
    both.extend(ack(3, 0));
    let session = NetlinkSession::new(Scripted::replying(vec![both]));
    assert!(matches!(
        session.execute(vec![
            Request::acknowledged(get_link(), 0),
            Request::acknowledged(get_link(), 0),
        ]),
        Err(NetlinkError::Unexpected)
    ));
    Ok(())
}

#[test]
fn refusals_and_unattributable_replies_fail() {
    let cases: Vec<(Vec<Vec<u8>>, Expected)> = vec![
        (vec![ack(1, -17)], |error| {
            matches!(error, NetlinkError::Kernel(-17))
        }),
        // A refusal of an unacknowledged request, such as a batch start.
        (vec![ack(9, -1)], |error| {
            matches!(error, NetlinkError::Kernel(-1))
        }),
        (vec![ack(9, 0)], |error| {
            matches!(error, NetlinkError::Unexpected)
        }),
        (vec![link_reply(1, 0, LinkMessage::default())], |error| {
            matches!(error, NetlinkError::Unexpected)
        }),
        (vec![vec![1, 2, 3]], |error| {
            matches!(error, NetlinkError::Decode)
        }),
        // A header whose length is below the header's own size.
        (vec![vec![0; 16]], |error| {
            matches!(error, NetlinkError::Decode)
        }),
        (Vec::new(), |error| matches!(error, NetlinkError::Truncated)),
    ];
    for (replies, expected) in cases {
        let session = NetlinkSession::new(Scripted::replying(replies));
        let result = session.execute(vec![Request::acknowledged(get_link(), 0)]);
        assert!(result.as_ref().is_err_and(expected), "{result:?}");
    }
    let refusing = NetlinkSession::new(Scripted {
        refuse_send: true,
        ..Scripted::default()
    });
    assert!(matches!(
        refusing.execute(vec![Request::acknowledged(get_link(), 0)]),
        Err(NetlinkError::Io(Errno::MSGSIZE))
    ));
    assert!(matches!(
        refusing.dump(get_link()),
        Err(NetlinkError::Io(Errno::MSGSIZE))
    ));
    let empty = NetlinkSession::new(Scripted::default());
    assert!(matches!(
        empty.execute(Vec::<Request<RouteNetlinkMessage>>::new()),
        Err(NetlinkError::Empty)
    ));
    assert!(empty.transport.sent.borrow().is_empty());
}

#[test]
fn a_dump_collects_every_reply_until_done() -> TestResult {
    let lo = link(
        1,
        LinkFlags::Loopback,
        vec![LinkAttribute::IfName("lo".to_owned())],
    );
    let other = link(
        2,
        LinkFlags::Up,
        vec![LinkAttribute::IfName("x".to_owned())],
    );
    let mut second = link_reply(1, NLM_F_MULTIPART, other.clone());
    // The last message of a datagram may omit its padding.
    second.extend(done(1, 0));
    let session = NetlinkSession::new(Scripted::replying(vec![
        link_reply(1, NLM_F_MULTIPART, lo.clone()),
        second,
    ]));
    assert_eq!(
        session.dump(get_link())?,
        [
            RouteNetlinkMessage::NewLink(lo),
            RouteNetlinkMessage::NewLink(other)
        ]
    );
    assert_eq!(
        sent_headers(&session.transport)?[0].flags,
        NLM_F_REQUEST | NLM_F_DUMP
    );
    Ok(())
}

#[test]
fn a_refused_interrupted_or_foreign_dump_fails() {
    let cases: Vec<(Vec<u8>, Expected)> = vec![
        (done(1, -4), |error| {
            matches!(error, NetlinkError::Kernel(-4))
        }),
        (ack(1, -1), |error| {
            matches!(error, NetlinkError::Kernel(-1))
        }),
        (done(2, 0), |error| {
            matches!(error, NetlinkError::Unexpected)
        }),
        (
            link_reply(1, NLM_F_MULTIPART | NLM_F_DUMP_INTR, LinkMessage::default()),
            |error| matches!(error, NetlinkError::Interrupted),
        ),
        (reply(1, 0, NetlinkPayload::Noop), |error| {
            matches!(error, NetlinkError::Unexpected)
        }),
        (vec![1, 2, 3], |error| matches!(error, NetlinkError::Decode)),
    ];
    for (datagram, expected) in cases {
        let session = NetlinkSession::new(Scripted::replying(vec![datagram]));
        let result = session.dump(get_link());
        assert!(result.as_ref().is_err_and(expected), "{result:?}");
    }
    // A dump whose reply never arrives.
    let silent = NetlinkSession::new(Scripted::default());
    assert!(matches!(
        silent.dump(get_link()),
        Err(NetlinkError::Truncated)
    ));
}

#[test]
fn a_socket_of_no_netlink_protocol_is_refused() {
    let protocol = Some(rustix::net::Protocol::from_raw(
        rustix::net::RawProtocol::MAX,
    ));
    assert!(matches!(
        NetlinkSocket::open(protocol, RECEIVE_TIMEOUT),
        Err(NetlinkError::Io(_))
    ));
}

#[test]
fn a_socket_fails_on_an_oversized_request_a_silent_kernel_and_an_oversized_reply() -> TestResult {
    let socket = NetlinkSocket::open(ROUTE, Duration::from_millis(1))?;
    // Larger than the socket's send buffer.
    assert!(matches!(
        socket.send(&vec![0; 1 << 20]),
        Err(NetlinkError::Io(Errno::MSGSIZE))
    ));
    // Nothing was sent, so the receive times out.
    assert!(matches!(socket.receive(), Err(NetlinkError::Io(_))));
    // An `RTM_NEWLINK` request of 100 000 bytes that the kernel refuses: its
    // error reply echoes the whole request, which exceeds the receive buffer.
    let mut request = vec![0; 100_000];
    request[..4].copy_from_slice(&100_000_u32.to_ne_bytes());
    request[4..6].copy_from_slice(&16_u16.to_ne_bytes());
    request[6..8].copy_from_slice(&(NLM_F_REQUEST | NLM_F_ACK).to_ne_bytes());
    let socket = NetlinkSocket::open(ROUTE, RECEIVE_TIMEOUT)?;
    socket.send(&request)?;
    assert!(matches!(socket.receive(), Err(NetlinkError::Truncated)));
    Ok(())
}

#[test]
fn a_request_returns_its_one_reply() -> TestResult {
    let session = NetlinkSession::new(Scripted::replying(vec![link_reply(
        1,
        0,
        LinkMessage::default(),
    )]));
    assert_eq!(
        session.request(get_link())?,
        RouteNetlinkMessage::NewLink(LinkMessage::default())
    );
    assert_eq!(sent_headers(&session.transport)?[0].flags, NLM_F_REQUEST);
    Ok(())
}

#[test]
fn a_refused_foreign_or_ambiguous_request_fails() {
    let mut two = link_reply(1, 0, LinkMessage::default());
    two.extend(link_reply(1, 0, LinkMessage::default()));
    let cases: Vec<(Vec<Vec<u8>>, Expected)> = vec![
        (vec![ack(1, -19)], |error| {
            matches!(error, NetlinkError::Kernel(-19))
        }),
        // A refusal of another request.
        (vec![ack(2, -19)], |error| {
            matches!(error, NetlinkError::Unexpected)
        }),
        // An acknowledgement answers no `GET`.
        (vec![ack(1, 0)], |error| {
            matches!(error, NetlinkError::Unexpected)
        }),
        (vec![reply(1, 0, NetlinkPayload::Noop)], |error| {
            matches!(error, NetlinkError::Unexpected)
        }),
        (vec![link_reply(2, 0, LinkMessage::default())], |error| {
            matches!(error, NetlinkError::Unexpected)
        }),
        (vec![two], |error| matches!(error, NetlinkError::Unexpected)),
        (vec![vec![1, 2, 3]], |error| {
            matches!(error, NetlinkError::Decode)
        }),
        (Vec::new(), |error| matches!(error, NetlinkError::Truncated)),
    ];
    for (replies, expected) in cases {
        let session = NetlinkSession::new(Scripted::replying(replies));
        let result = session.request(get_link());
        assert!(result.as_ref().is_err_and(expected), "{result:?}");
    }
    let refusing = NetlinkSession::new(Scripted {
        refuse_send: true,
        ..Scripted::default()
    });
    assert!(matches!(
        refusing.request(get_link()),
        Err(NetlinkError::Io(Errno::MSGSIZE))
    ));
}

#[test]
fn consistent_reads_retry_only_interrupted_dumps_and_at_most_three_times() {
    let attempts = RefCell::new(0);
    let interrupted_once = consistent(|| {
        *attempts.borrow_mut() += 1;
        if *attempts.borrow() == 1 {
            Err(NetlinkError::Interrupted)
        } else {
            Ok(*attempts.borrow())
        }
    });
    assert!(matches!(interrupted_once, Ok(2)));
    let attempts = RefCell::new(0);
    let always = consistent(|| -> Result<(), NetlinkError> {
        *attempts.borrow_mut() += 1;
        Err(NetlinkError::Interrupted)
    });
    assert!(matches!(always, Err(NetlinkError::Interrupted)));
    assert_eq!(*attempts.borrow(), 3);
    let attempts = RefCell::new(0);
    let refused = consistent(|| -> Result<(), NetlinkError> {
        *attempts.borrow_mut() += 1;
        Err(NetlinkError::Kernel(-1))
    });
    assert!(matches!(refused, Err(NetlinkError::Kernel(-1))));
    assert_eq!(*attempts.borrow(), 1);
}

#[test]
fn links_decode_loopback_veth_and_other_kinds() -> TestResult {
    let veth = vec![
        LinkAttribute::IfName("piglor-n0".to_owned()),
        LinkAttribute::LinkInfo(vec![LinkInfo::Kind(InfoKind::Veth)]),
        LinkAttribute::Link(41),
        LinkAttribute::LinkNetNsId(5),
    ];
    let mut datagram = link_reply(
        1,
        NLM_F_MULTIPART,
        link(
            1,
            LinkFlags::Loopback,
            vec![LinkAttribute::IfName("lo".to_owned())],
        ),
    );
    datagram.extend(link_reply(
        1,
        NLM_F_MULTIPART,
        link(2, LinkFlags::Up | LinkFlags::LowerUp, veth),
    ));
    datagram.extend(link_reply(
        1,
        NLM_F_MULTIPART,
        link(
            3,
            LinkFlags::empty(),
            vec![
                LinkAttribute::IfName("dummy0".to_owned()),
                LinkAttribute::LinkInfo(vec![LinkInfo::Kind(InfoKind::Dummy)]),
                LinkAttribute::Mtu(1500),
            ],
        ),
    ));
    datagram.extend(done(1, 0));
    let session = NetlinkSession::new(Scripted::replying(vec![datagram]));
    assert_eq!(
        links(&session)?,
        [
            ObservedLink {
                index: 1,
                name: "lo".to_owned(),
                kind: LinkKind::Loopback,
                up: false,
            },
            ObservedLink {
                index: 2,
                name: "piglor-n0".to_owned(),
                kind: LinkKind::Veth {
                    peer_index: 41,
                    peer_netnsid: Some(5),
                },
                up: true,
            },
            ObservedLink {
                index: 3,
                name: "dummy0".to_owned(),
                kind: LinkKind::Other,
                up: false,
            },
        ]
    );
    Ok(())
}

#[test]
fn unrepresentable_links_and_foreign_replies_fail() {
    let peerless = link(
        2,
        LinkFlags::Up,
        vec![
            LinkAttribute::IfName("piglor-n0".to_owned()),
            LinkAttribute::LinkInfo(vec![LinkInfo::Kind(InfoKind::Veth)]),
        ],
    );
    let unnamed = link(2, LinkFlags::Up, Vec::new());
    for message in [peerless, unnamed] {
        let mut datagram = link_reply(1, NLM_F_MULTIPART, message);
        datagram.extend(done(1, 0));
        let session = NetlinkSession::new(Scripted::replying(vec![datagram]));
        assert!(matches!(
            links(&session),
            Err(NetlinkError::Unrepresentable)
        ));
    }
    let mut foreign = reply(
        1,
        NLM_F_MULTIPART,
        NetlinkPayload::InnerMessage(RouteNetlinkMessage::DelLink(LinkMessage::default())),
    );
    foreign.extend(done(1, 0));
    let session = NetlinkSession::new(Scripted::replying(vec![foreign]));
    assert!(matches!(links(&session), Err(NetlinkError::Unexpected)));
}

#[test]
fn a_descriptor_that_is_no_namespace_is_not_entered() -> TestResult {
    let null = File::open("/dev/null")?;
    assert!(matches!(
        in_namespace(null.as_fd(), || ()),
        Err(NetlinkError::Io(_))
    ));
    Ok(())
}

#[test]
fn netlink_errors_say_what_failed() {
    for (error, message) in [
        (
            NetlinkError::Io(Errno::PERM),
            "a netlink socket call failed",
        ),
        (NetlinkError::Empty, "a netlink exchange held no request"),
        (
            NetlinkError::Truncated,
            "a netlink reply did not fit the receive buffer",
        ),
        (NetlinkError::Decode, "a netlink reply could not be decoded"),
        (
            NetlinkError::Kernel(-17),
            "the kernel refused a netlink request with error -17",
        ),
        (
            NetlinkError::Interrupted,
            "a netlink dump was interrupted by a concurrent change",
        ),
        (
            NetlinkError::Unexpected,
            "a netlink reply answered no outstanding request",
        ),
        (
            NetlinkError::Unrepresentable,
            "the kernel reported state the provider cannot represent",
        ),
        (
            NetlinkError::Panicked,
            "the thread inside the network namespace panicked",
        ),
        (
            NetlinkError::Residual,
            "provider network state remained after its removal",
        ),
    ] {
        assert_eq!(error.to_string(), message);
    }
}

/// Tests that need `NET_ADMIN` and `SYS_ADMIN`. Each re-runs itself in the
/// isolated container that grants exactly those, and runs its body there.
mod privileged {
    use std::{
        io::{BufRead, BufReader},
        process::{Command, Stdio},
    };

    use super::*;

    /// Whether this process is the isolated one; otherwise run `name` there
    /// and require it to pass.
    fn isolated(name: &str) -> TestResult<bool> {
        if std::env::var_os("PIGLOROS_PRIVILEGED_COMPOSITION_TEST").is_some() {
            return Ok(true);
        }
        let runner = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../scripts/run-isolated-with-net-admin-test.sh");
        let output = Command::new(runner)
            .arg(std::env::current_exe()?)
            .arg(format!(
                "namespace_network::netlink::tests::privileged::{name}"
            ))
            .output()?;
        assert!(
            output.status.success(),
            "isolated namespace test failed: {:?}\n{}\n{}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        Ok(false)
    }

    /// A new, empty network namespace, created by `unshare(1)` and held by
    /// its descriptor alone.
    fn fresh_namespace() -> TestResult<File> {
        let mut holder = Command::new("unshare")
            .args(["--net", "sh", "-c", "echo ready; exec sleep 30"])
            .stdout(Stdio::piped())
            .spawn()?;
        let mut ready = String::new();
        let read = holder
            .stdout
            .take()
            .map_or(Ok(0), |stdout| BufReader::new(stdout).read_line(&mut ready));
        let namespace = File::open(format!("/proc/{}/ns/net", holder.id()));
        let stopped = holder.kill().and_then(|()| holder.wait());
        assert_eq!(ready, "ready\n", "{read:?}");
        assert!(stopped.is_ok(), "{stopped:?}");
        Ok(namespace?)
    }

    #[test]
    fn a_fresh_namespace_holds_only_its_down_loopback() -> TestResult {
        if !isolated("a_fresh_namespace_holds_only_its_down_loopback")? {
            return Ok(());
        }
        let namespace = fresh_namespace()?;
        let observed = in_namespace(namespace.as_fd(), || {
            NetlinkSession::open(ROUTE).and_then(|session| links(&session))
        })??;
        assert_eq!(observed.len(), 1);
        assert_eq!(observed[0].name, "lo");
        assert_eq!(observed[0].kind, LinkKind::Loopback);
        assert!(!observed[0].up);
        // A netfilter socket opens in the namespace as well.
        in_namespace(namespace.as_fd(), || {
            NetlinkSession::open(NETFILTER).map(drop)
        })??;
        Ok(())
    }

    #[test]
    fn a_panic_inside_the_namespace_is_reported() -> TestResult {
        if !isolated("a_panic_inside_the_namespace_is_reported")? {
            return Ok(());
        }
        let namespace = fresh_namespace()?;
        assert!(matches!(
            in_namespace(namespace.as_fd(), || std::panic::resume_unwind(Box::new(
                "inside"
            ))),
            Err(NetlinkError::Panicked)
        ));
        Ok(())
    }
}
