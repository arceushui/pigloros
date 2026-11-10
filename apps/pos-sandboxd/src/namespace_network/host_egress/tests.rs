use std::{
    cell::RefCell,
    collections::VecDeque,
    error::Error,
    net::{Ipv4Addr, Ipv6Addr},
    rc::Rc,
};

use netlink_packet_core::{
    DoneMessage, ErrorMessage, NetlinkHeader, NetlinkMessage, NetlinkPayload, NetlinkSerializable,
    NLM_F_MULTIPART,
};
use netlink_packet_netfilter::nftables::{ChainFlags, TableFlags};
use netlink_packet_route::link::InetDevConf;

use super::*;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const ENDPOINT: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)), 443);

fn attempt(seed: u8, slot: u16, endpoints: Vec<SocketAddr>) -> TestResult<AttemptEgress> {
    Ok(AttemptEgress {
        namespace: NamespaceName::for_attempt([seed; 16]),
        host_link: LinkName::new(&format!("piglor-h{slot}"))?,
        endpoints,
    })
}

/// `message` as a table dump reports it, if it creates a table.
fn dumped_table(message: &NetfilterMessage) -> Option<NetfilterMessage> {
    match message.inner.clone() {
        NetfilterMessageInner::NfTables(NfTablesMessage::NewTable(mut table)) => {
            table
                .attributes
                .push(TableAttribute::Flags(TableFlags::empty()));
            Some(inet(NfTablesMessage::NewTable(table)))
        }
        _ => None,
    }
}

/// `message` as a chain dump reports it, if it creates a chain.
fn dumped_chain(message: &NetfilterMessage) -> Option<NetfilterMessage> {
    match message.inner.clone() {
        NetfilterMessageInner::NfTables(NfTablesMessage::NewChain(mut chain)) => {
            chain
                .attributes
                .push(ChainAttribute::Flags(ChainFlags::Base));
            Some(inet(NfTablesMessage::NewChain(chain)))
        }
        _ => None,
    }
}

/// `message` as a rule dump reports it with `handle`, if it creates a rule.
fn dumped_rule(message: &NetfilterMessage, handle: u64) -> Option<NetfilterMessage> {
    match message.inner.clone() {
        NetfilterMessageInner::NfTables(NfTablesMessage::NewRule(mut rule)) => {
            rule.attributes.push(RuleAttribute::Handle(handle));
            Some(inet(NfTablesMessage::NewRule(rule)))
        }
        _ => None,
    }
}

/// The batches' tables, chains and rules as the kernel's dumps report them.
fn as_dumped(
    batches: &[Vec<Request<NetfilterMessage>>],
) -> (
    Vec<NetfilterMessage>,
    Vec<NetfilterMessage>,
    Vec<NetfilterMessage>,
) {
    let requests: Vec<&Request<NetfilterMessage>> = batches.iter().flatten().collect();
    let tables = requests
        .iter()
        .filter_map(|request| dumped_table(&request.message))
        .collect();
    let chains = requests
        .iter()
        .filter_map(|request| dumped_chain(&request.message))
        .collect();
    let mut rules = Vec::new();
    for (handle, request) in (1..).zip(&requests) {
        // A rule created without `NLM_F_APPEND` goes to its chain's head;
        // the dumps group rules by chain in the order they come.
        let at_head = request.flags == NLM_F_CREATE;
        rules.extend(dumped_rule(&request.message, handle).map(|rule| (at_head, rule)));
    }
    let (mut ordered, appended): (Vec<_>, Vec<_>) = rules.into_iter().partition(|(head, _)| *head);
    ordered.reverse();
    ordered.extend(appended);
    (
        tables,
        chains,
        ordered.into_iter().map(|(_, rule)| rule).collect(),
    )
}

#[test]
fn host_rules_match_the_veth_end_and_the_exact_endpoint() -> TestResult {
    let link = LinkName::new("piglor-h3")?;
    let dispatch = expressions(&HostRule::Dispatch {
        link: link.clone(),
        chain: "c".to_owned(),
    });
    let mut name = b"piglor-h3".to_vec();
    name.resize(16, 0);
    assert_eq!(dispatch.len(), 3);
    assert_eq!(
        dispatch[1],
        expression(Expressions::Cmp(vec![
            Cmp::SourceRegister(Register::Reg1),
            Cmp::Op(Operator::Equal),
            Cmp::Data(DataAttribute::Value(name)),
        ]))
    );
    assert_eq!(
        dispatch[2],
        verdict(vec![
            VerdictAttribute::Code(Verdict::Jump),
            VerdictAttribute::Chain("c".to_owned()),
        ])
    );
    let drop = expressions(&HostRule::DropUnmatched);
    assert_eq!(drop[..2], input_link_is(b"piglor-h"));
    assert_eq!(
        drop[2],
        verdict(vec![VerdictAttribute::Code(Verdict::Other(0))])
    );
    assert_eq!(
        expressions(&HostRule::Allow(ENDPOINT)),
        encode_firewall_rule(&FirewallRule::AcceptTcp(ENDPOINT))
    );
    let masquerade = expressions(&HostRule::Masquerade {
        link,
        endpoint: ENDPOINT,
    });
    let tcp = encode_firewall_rule(&FirewallRule::AcceptTcp(ENDPOINT));
    assert_eq!(masquerade[2..masquerade.len() - 1], tcp[..tcp.len() - 1]);
    assert_eq!(
        masquerade.last(),
        Some(&expression(Expressions::Other {
            expression_type: "masq".to_owned(),
            attributes: Vec::new(),
        }))
    );
    Ok(())
}

#[test]
fn the_table_and_an_attempt_are_installed_in_one_batch_each() -> TestResult {
    let table = create_table();
    let flags: Vec<u16> = table.iter().map(|request| request.flags).collect();
    let (create_new, append) = (NLM_F_CREATE | NLM_F_EXCL, NLM_F_CREATE | NLM_F_APPEND);
    assert_eq!(flags, [0, create_new, create_new, create_new, append, 0]);
    let attempt = attempt(
        1,
        3,
        vec![ENDPOINT, SocketAddr::from((Ipv6Addr::LOCALHOST, 80))],
    )?;
    let installed = install_attempt(&attempt);
    let flags: Vec<u16> = installed.iter().map(|request| request.flags).collect();
    // The chain, its one IPv4 rule, one masquerade and the dispatch at the
    // forward chain's head; the on-host IPv6 endpoint needs neither.
    assert_eq!(flags, [0, create_new, append, append, NLM_F_CREATE, 0]);
    assert_eq!(
        installed[4].message,
        inet(new_rule(
            FORWARD,
            &HostRule::Dispatch {
                link: attempt.host_link.clone(),
                chain: attempt.namespace.as_str().to_owned(),
            }
        ))
    );
    assert_eq!(
        delete_table()[1].message,
        inet(NfTablesMessage::DeleteTable(TableMessage {
            attributes: vec![TableAttribute::Name(HOST_TABLE.to_owned())],
        }))
    );
    Ok(())
}

/// Two attempts installed in turn, as the dumps report them.
fn two_attempts() -> TestResult<(ReadTable, BTreeMap<String, AttemptEgress>)> {
    let first = attempt(1, 3, vec![ENDPOINT])?;
    let second = attempt(
        2,
        4,
        vec![ENDPOINT, SocketAddr::from(([198, 51, 100, 7], 8443))],
    )?;
    let (tables, chains, rules) = as_dumped(&[
        create_table(),
        install_attempt(&first),
        install_attempt(&second),
    ]);
    let table = read_table(tables, chains, rules)?.ok_or("no host table")?;
    let attempts = [first, second]
        .into_iter()
        .map(|attempt| (attempt.namespace.as_str().to_owned(), attempt))
        .collect();
    Ok((table, attempts))
}

#[test]
fn the_dumps_read_back_exactly_the_installed_attempts() -> TestResult {
    let (table, mut attempts) = two_attempts()?;
    assert!(is_exact(&table, &attempts));
    // A third attempt that was never installed, or one fewer, differs.
    let missing = attempt(3, 5, vec![ENDPOINT])?;
    attempts.insert(missing.namespace.as_str().to_owned(), missing);
    assert!(!is_exact(&table, &attempts));
    attempts.pop_first();
    attempts.pop_last();
    assert!(!is_exact(&table, &attempts));
    Ok(())
}

#[test]
fn a_changed_host_table_reads_back_differently() -> TestResult {
    let (table, attempts) = two_attempts()?;
    let mutations: [fn(&mut ReadTable); 9] = [
        // A dispatch twice while the drop stays last.
        |table| {
            if let Some(forward) = table.chains.get_mut(FORWARD) {
                forward.rules[0] = forward.rules[1].clone();
            }
        },
        // An attempt chain that became a base chain, rules unchanged.
        |table| {
            for chain in table
                .chains
                .values_mut()
                .filter(|chain| chain.base.is_none())
            {
                chain.base = Some((0, 0, 0, "filter".to_owned()));
            }
        },
        // An attempt chain whose one rule differs.
        |table| {
            for chain in table
                .chains
                .values_mut()
                .filter(|chain| chain.base.is_none())
            {
                chain.rules[0].1.clear();
            }
        },
        |table| table.flags = 1,
        |table| {
            table
                .chains
                .insert("extra".to_owned(), ReadChain::default());
        },
        |table| {
            if let Some(forward) = table.chains.get_mut(FORWARD) {
                forward.rules.rotate_left(1);
            }
        },
        |table| {
            if let Some(forward) = table.chains.get_mut(FORWARD) {
                forward.base = None;
            }
        },
        |table| {
            if let Some(postrouting) = table.chains.get_mut(POSTROUTING) {
                postrouting.rules.pop();
            }
        },
        |table| {
            for chain in table
                .chains
                .values_mut()
                .filter(|chain| chain.base.is_none())
            {
                chain.rules.reverse();
                chain.rules.push((0, Vec::new()));
            }
        },
    ];
    for mutate in mutations {
        let mut changed = table.clone();
        mutate(&mut changed);
        assert!(!is_exact(&changed, &attempts), "{changed:?}");
    }
    Ok(())
}

#[test]
fn a_dormant_host_table_reads_back_its_flags() -> TestResult {
    let (_, chains, rules) = as_dumped(&[create_table()]);
    let dormant = inet(NfTablesMessage::NewTable(TableMessage {
        attributes: vec![
            TableAttribute::Name(HOST_TABLE.to_owned()),
            TableAttribute::Flags(TableFlags::Dormant),
        ],
    }));
    let table = read_table(vec![dormant], chains, rules)?.ok_or("no host table")?;
    assert_eq!(table.flags, 1);
    assert!(!is_exact(&table, &BTreeMap::new()));
    Ok(())
}

#[test]
fn other_tables_are_not_read_and_an_absent_table_reads_as_none() -> TestResult {
    let foreign = |message| {
        NetfilterMessage::new(
            NetfilterHeader::new(NetfilterProtoFamily::IPv4, 0, 0),
            message,
        )
    };
    let named = |name: &str| TableMessage {
        attributes: vec![TableAttribute::Name(name.to_owned())],
    };
    // The same name in another family is another table.
    let tables = vec![
        foreign(NfTablesMessage::NewTable(named(HOST_TABLE))),
        inet(NfTablesMessage::NewTable(named("docker"))),
    ];
    let chains = vec![foreign(NfTablesMessage::NewChain(ChainMessage {
        attributes: vec![
            ChainAttribute::Table(HOST_TABLE.to_owned()),
            ChainAttribute::Name(FORWARD.to_owned()),
        ],
    }))];
    let rules = vec![inet(NfTablesMessage::NewRule(RuleMessage {
        attributes: vec![RuleAttribute::Table("docker".to_owned())],
    }))];
    assert_eq!(read_table(tables, chains, rules)?, None);
    Ok(())
}

#[test]
fn unrepresentable_or_foreign_replies_fail_the_read() {
    let ours = || {
        inet(NfTablesMessage::NewTable(TableMessage {
            attributes: vec![TableAttribute::Name(HOST_TABLE.to_owned())],
        }))
    };
    let chain = |attributes| inet(NfTablesMessage::NewChain(ChainMessage { attributes }));
    let table_name = || ChainAttribute::Table(HOST_TABLE.to_owned());
    let failures = [
        read_table(
            vec![inet(NfTablesMessage::GetTable(TableMessage {
                attributes: Vec::new(),
            }))],
            Vec::new(),
            Vec::new(),
        ),
        read_table(vec![ours()], vec![ours()], Vec::new()),
        read_table(vec![ours()], Vec::new(), vec![ours()]),
        // A hook of another kind, a partial base chain and a nameless chain.
        read_table(
            vec![ours()],
            vec![chain(vec![
                table_name(),
                ChainAttribute::Name("c".to_owned()),
                ChainAttribute::Hook(vec![Hook::NetDeviceName("eth0".to_owned())]),
            ])],
            Vec::new(),
        ),
        read_table(
            vec![ours()],
            vec![chain(vec![
                table_name(),
                ChainAttribute::Name("c".to_owned()),
                ChainAttribute::Policy(1),
            ])],
            Vec::new(),
        ),
        read_table(vec![ours()], vec![chain(vec![table_name()])], Vec::new()),
        // A rule of a chain the dump did not report.
        read_table(
            vec![ours()],
            Vec::new(),
            vec![inet(NfTablesMessage::NewRule(RuleMessage {
                attributes: vec![
                    RuleAttribute::Table(HOST_TABLE.to_owned()),
                    RuleAttribute::Chain("c".to_owned()),
                    RuleAttribute::Handle(1),
                    RuleAttribute::Expressions(Vec::new()),
                ],
            }))],
        ),
    ];
    for failure in failures {
        assert!(failure.is_err(), "{failure:?}");
    }
}

#[test]
fn removal_deletes_the_attempts_rules_by_handle_then_its_chain() -> TestResult {
    let (table, attempts) = two_attempts()?;
    let second = attempts.values().last().ok_or("no attempt")?;
    let removal = remove_attempt(&table, second);
    // One dispatch, two masquerades, the chain's flush and the chain.
    assert_eq!(removal.len(), 2 + 1 + 2 + 2);
    let handles: Vec<Option<u64>> = removal
        .iter()
        .filter_map(|request| match &request.message.inner {
            NetfilterMessageInner::NfTables(NfTablesMessage::DeleteRule(rule)) => Some(
                rule.attributes
                    .iter()
                    .find_map(|attribute| match attribute {
                        RuleAttribute::Handle(handle) => Some(*handle),
                        _ => None,
                    }),
            ),
            _ => None,
        })
        .collect();
    assert_eq!(handles.len(), 4);
    assert!(handles[..3].iter().all(Option::is_some));
    assert_eq!(handles[3], None);
    // A table without the attempt's chains deletes only the chain.
    assert_eq!(remove_attempt(&ReadTable::default(), second).len(), 2 + 2);
    Ok(())
}

/// The replies a [`Scripted`] transport has not given yet.
type Unread = Rc<RefCell<VecDeque<Vec<u8>>>>;

/// A transport that replies with scripted datagrams.
#[derive(Default)]
struct Scripted {
    replies: Unread,
}

impl NetlinkTransport for Scripted {
    fn send(&self, _datagram: &[u8]) -> Result<(), NetlinkError> {
        Ok(())
    }

    fn receive(&self) -> Result<Vec<u8>, NetlinkError> {
        self.replies
            .borrow_mut()
            .pop_front()
            .ok_or(NetlinkError::Truncated)
    }
}

/// A route reply of `kind` through link `index`, answering request
/// `sequence`.
fn route_found(sequence: u32, kind: RouteType, index: u32) -> Vec<u8> {
    let mut route = RouteMessage::default();
    route.header.kind = kind;
    route.attributes = vec![RouteAttribute::Oif(index)];
    let mut header = NetlinkHeader::default();
    header.sequence_number = sequence;
    let mut message = NetlinkMessage::new(
        header,
        NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewRoute(route)),
    );
    message.finalize();
    let mut bytes = vec![0; message.buffer_len()];
    message.serialize(&mut bytes);
    bytes
}

/// A session that answers each request with the next of `replies`.
fn scripted(replies: Vec<Vec<u8>>) -> NetlinkSession<Scripted> {
    scripted_with_unread(replies).0
}

/// [`scripted`], and the replies it has not given yet.
fn scripted_with_unread(replies: Vec<Vec<u8>>) -> (NetlinkSession<Scripted>, Unread) {
    let unread = Rc::new(RefCell::new(VecDeque::from(replies)));
    let session = NetlinkSession::new(Scripted {
        replies: Rc::clone(&unread),
    });
    (session, unread)
}

#[test]
fn ingress_links_are_the_veth_end_and_each_off_host_ipv4_endpoints_link() -> TestResult {
    let session = scripted(vec![
        route_found(1, RouteType::Unicast, 7),
        route_found(2, RouteType::Local, 1),
        route_found(3, RouteType::Unicast, 7),
    ]);
    // The IPv6 endpoint is looked up by admission, not here.
    let endpoints = [
        ENDPOINT,
        SocketAddr::from(([127, 0, 0, 1], 80)),
        SocketAddr::from((Ipv6Addr::LOCALHOST, 80)),
        SocketAddr::from(([198, 51, 100, 7], 443)),
    ];
    assert_eq!(ingress_links(&session, 9, &endpoints)?, [7, 9]);
    Ok(())
}

#[test]
fn admission_refuses_only_ipv6_endpoints_off_the_host() -> TestResult {
    let ipv6 = SocketAddr::from((Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1), 443));
    // IPv4 endpoints need no lookup; an on-host IPv6 endpoint passes.
    admit_on(
        &scripted(vec![route_found(1, RouteType::Local, 1)]),
        &[ENDPOINT, ipv6],
    )?;
    let remote = scripted(vec![route_found(1, RouteType::Unicast, 7)]);
    assert!(matches!(
        admit_on(&remote, &[ENDPOINT, ipv6]),
        Err(HostEgressError::Ipv6Egress)
    ));
    Ok(())
}

#[test]
fn route_and_link_requests_and_replies() -> TestResult {
    let RouteNetlinkMessage::GetRoute(lookup) = route_to(IpAddr::V6(Ipv6Addr::LOCALHOST)) else {
        return Err("not a route lookup".into());
    };
    assert_eq!(lookup.header.address_family, AddressFamily::Inet6);
    assert_eq!(lookup.header.destination_prefix_length, 128);
    let RouteNetlinkMessage::GetRoute(lookup) = route_to(ENDPOINT.ip()) else {
        return Err("not a route lookup".into());
    };
    assert_eq!(lookup.header.destination_prefix_length, 32);
    assert!(matches!(
        route_reply(RouteNetlinkMessage::NewRoute(RouteMessage::default())),
        Err(NetlinkError::Unrepresentable)
    ));
    assert!(matches!(
        route_reply(get_link(1)),
        Err(NetlinkError::Unexpected)
    ));
    // Forwarding is set as one IFLA_INET_CONF entry, and read back from the
    // device configuration with the device's name.
    for on in [true, false] {
        let RouteNetlinkMessage::SetLink(set) = set_forwarding(5, on).message else {
            return Err("not a link change".into());
        };
        assert_eq!(set.header.index, 5);
        let mut nested = vec![0; 8];
        DefaultNla::new(1, u32::from(on).to_ne_bytes().to_vec()).emit(&mut nested);
        assert_eq!(
            set.attributes,
            [LinkAttribute::AfSpecUnspec(vec![AfSpecUnspec::Inet(vec![
                AfSpecInet::Other(DefaultNla::new(1, nested))
            ])])]
        );
    }
    let mut forwarding = LinkMessage::default();
    let mut conf = InetDevConf::default();
    conf.forwarding = 1;
    forwarding.attributes = vec![
        LinkAttribute::IfName("eth0".to_owned()),
        LinkAttribute::AfSpecUnspec(vec![AfSpecUnspec::Inet(vec![AfSpecInet::DevConf(conf)])]),
    ];
    assert_eq!(
        link_forwarding(RouteNetlinkMessage::NewLink(forwarding))?,
        ("eth0".to_owned(), true)
    );
    let mut quiet = LinkMessage::default();
    quiet.attributes = vec![LinkAttribute::IfName("eth0".to_owned())];
    assert_eq!(
        link_forwarding(RouteNetlinkMessage::NewLink(quiet))?,
        ("eth0".to_owned(), false)
    );
    assert!(matches!(
        link_forwarding(RouteNetlinkMessage::NewLink(LinkMessage::default())),
        Err(NetlinkError::Unrepresentable)
    ));
    assert!(matches!(
        link_forwarding(route_to(ENDPOINT.ip())),
        Err(NetlinkError::Unexpected)
    ));
    Ok(())
}

#[test]
fn forwarding_records_survive_as_files_and_ignore_unfinished_ones() -> TestResult {
    let directory = tempfile::tempdir()?;
    let records = ForwardingRecords::in_directory(directory.path().join("forwarding"));
    assert!(records.recorded()?.is_empty());
    records.record(7, "eth0")?;
    records.record(9, "uplink")?;
    std::fs::write(directory.path().join("forwarding/3.partial"), b"half")?;
    std::fs::write(directory.path().join("forwarding/notes"), b"x")?;
    let mut recorded = records.recorded()?;
    recorded.sort_unstable();
    assert_eq!(recorded, [(7, "eth0".to_owned()), (9, "uplink".to_owned())]);
    records.forget(7)?;
    records.forget(7)?;
    assert_eq!(records.recorded()?, [(9, "uplink".to_owned())]);
    // A directory that is a file holds nothing readable.
    let file = ForwardingRecords::in_directory(directory.path().join("forwarding/9"));
    assert!(file.recorded().is_err());
    assert!(file.record(1, "x").is_err());
    // Only a missing record counts as forgotten; any other failure to
    // remove one (here the record path is under a file) is reported.
    assert_eq!(
        file.forget(1).map_err(|error| error.kind()),
        Err(std::io::ErrorKind::NotADirectory)
    );
    assert_eq!(
        ForwardingRecords::default(),
        ForwardingRecords::in_directory(FORWARDING_RECORDS)
    );
    Ok(())
}

#[test]
fn host_egress_errors_say_what_failed() {
    for (error, message) in [
        (
            HostEgressError::Netlink(NetlinkError::Unexpected),
            "a host egress netlink exchange failed",
        ),
        (
            HostEgressError::Ipv6Egress,
            "an IPv6 endpoint is not on this host, and egress is IPv4 only",
        ),
        (
            HostEgressError::Readback,
            "the host egress table read back differently",
        ),
        (
            HostEgressError::Forwarding,
            "a device the attempt's traffic enters by does not have its expected IPv4 forwarding",
        ),
        (
            HostEgressError::State(std::io::ErrorKind::NotFound.into()),
            "the provider's egress forwarding record failed",
        ),
    ] {
        assert_eq!(error.to_string(), message);
    }
}

/// One reply message answering request `sequence`, with `flags`.
fn message<I: NetlinkSerializable>(
    sequence: u32,
    flags: u16,
    payload: NetlinkPayload<I>,
) -> Vec<u8> {
    let mut header = NetlinkHeader::default();
    header.sequence_number = sequence;
    header.flags = flags;
    let mut message = NetlinkMessage::new(header, payload);
    message.finalize();
    let mut bytes = vec![0; message.buffer_len()];
    message.serialize(&mut bytes);
    bytes
}

/// The kernel's acknowledgement of request `sequence`, or its refusal with
/// `code`.
fn ack(sequence: u32, code: i32) -> Vec<u8> {
    let mut error = ErrorMessage::default();
    error.code = std::num::NonZeroI32::new(code);
    message::<RouteNetlinkMessage>(sequence, 0, NetlinkPayload::Error(error))
}

/// The end of dump `sequence`.
fn done(sequence: u32) -> Vec<u8> {
    message::<RouteNetlinkMessage>(
        sequence,
        NLM_F_MULTIPART,
        NetlinkPayload::Done(DoneMessage::default()),
    )
}

/// The host table, as dump `sequence` reports it.
fn our_table(sequence: u32) -> TestResult<Vec<u8>> {
    let table = create_table()
        .iter()
        .find_map(|request| dumped_table(&request.message))
        .ok_or("no table")?;
    Ok(message(
        sequence,
        NLM_F_MULTIPART,
        NetlinkPayload::InnerMessage(table),
    ))
}

/// Link `name`'s reply to request `sequence`, forwarding or not. Its device
/// configuration comes before its name.
fn link_named(sequence: u32, name: &str, forwarding: bool) -> Vec<u8> {
    let mut conf = InetDevConf::default();
    conf.forwarding = i32::from(forwarding);
    let mut link = LinkMessage::default();
    link.attributes = vec![
        LinkAttribute::AfSpecUnspec(vec![AfSpecUnspec::Inet(vec![AfSpecInet::DevConf(conf)])]),
        LinkAttribute::IfName(name.to_owned()),
    ];
    message(
        sequence,
        0,
        NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewLink(link)),
    )
}

/// Records in a new directory, holding link 7 as `eth0`.
fn eth0_recorded() -> TestResult<(tempfile::TempDir, ForwardingRecords)> {
    let directory = tempfile::tempdir()?;
    let records = ForwardingRecords::in_directory(directory.path().join("forwarding"));
    records.record(7, "eth0")?;
    Ok((directory, records))
}

/// Restore recorded link 7, `eth0`, against `replies`, and whether its
/// record remains.
fn restored(replies: Vec<Vec<u8>>) -> TestResult<(Result<(), HostEgressError>, bool)> {
    let (_directory, records) = eth0_recorded()?;
    let outcome = restore(&scripted(replies), &records, 7, "eth0");
    Ok((outcome, !records.recorded()?.is_empty()))
}

#[test]
fn a_record_is_forgotten_once_its_device_is_restored_or_gone() -> TestResult {
    // Gone, or the index now names another device: nothing to restore.
    for replies in [
        vec![ack(1, super::super::route::NO_SUCH_LINK)],
        vec![link_named(1, "other", true)],
    ] {
        assert!(matches!(restored(replies)?, (Ok(()), false)));
    }
    let restoring = vec![
        link_named(1, "eth0", true),
        ack(2, 0),
        link_named(3, "eth0", false),
    ];
    assert!(matches!(restored(restoring)?, (Ok(()), false)));
    Ok(())
}

#[test]
fn a_record_stays_while_its_device_cannot_be_restored() -> TestResult {
    let unreadable = vec![ack(1, -1)];
    let refused = vec![link_named(1, "eth0", true)];
    let unverified = vec![link_named(1, "eth0", true), ack(2, 0)];
    for replies in [unreadable, refused, unverified] {
        assert!(matches!(
            restored(replies)?,
            (Err(HostEgressError::Netlink(_)), true)
        ));
    }
    let still_forwarding = vec![
        link_named(1, "eth0", true),
        ack(2, 0),
        link_named(3, "eth0", true),
    ];
    assert!(matches!(
        restored(still_forwarding)?,
        (Err(HostEgressError::Forwarding), true)
    ));
    Ok(())
}

#[test]
fn restoring_every_record_fails_on_the_first_that_cannot_be_read_or_restored() -> TestResult {
    let (directory, records) = eth0_recorded()?;
    assert!(matches!(
        restore_forwarding(&scripted(Vec::new()), &records),
        Err(HostEgressError::Netlink(_))
    ));
    let file = ForwardingRecords::in_directory(directory.path().join("forwarding/7"));
    assert!(matches!(
        restore_forwarding(&scripted(Vec::new()), &file),
        Err(HostEgressError::State(_))
    ));
    restore_forwarding(
        &scripted(vec![ack(1, super::super::route::NO_SUCH_LINK)]),
        &records,
    )?;
    assert!(records.recorded()?.is_empty());
    Ok(())
}

#[test]
fn failed_route_lookups_fail_admission_and_ingress() {
    let ipv6 = SocketAddr::from((Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1), 443));
    assert!(matches!(
        admit_on(&scripted(Vec::new()), &[ipv6]),
        Err(HostEgressError::Netlink(_))
    ));
    assert!(matches!(
        ingress_links(&scripted(Vec::new()), 9, &[ENDPOINT]),
        Err(HostEgressError::Netlink(_))
    ));
}

/// Install an attempt through link 9 to [`ENDPOINT`], which leaves by link
/// 7, against `route` and `netfilter` replies, recording in `records`.
fn install_against(
    records: &ForwardingRecords,
    route: Vec<Vec<u8>>,
    netfilter: Vec<Vec<u8>>,
) -> TestResult<Result<(), HostEgressError>> {
    let attempt = attempt(1, 0, vec![ENDPOINT])?;
    Ok(install_locked(
        &mut Installed::default(),
        records,
        (&scripted(route), &scripted(netfilter)),
        9,
        &attempt,
    ))
}

#[test]
fn an_install_stops_at_the_first_exchange_that_fails() -> TestResult {
    let (directory, records) = eth0_recorded()?;
    let leaves = || route_found(1, RouteType::Unicast, 7);
    let absent = || vec![done(1), done(2), done(3)];
    let present =
        || -> TestResult<Vec<Vec<u8>>> { Ok(vec![our_table(1)?, done(1), done(2), done(3)]) };
    let forwarding = || {
        vec![
            leaves(),
            link_named(2, "eth0", true),
            link_named(3, "piglor-h0", true),
            link_named(4, "eth0", true),
            link_named(5, "piglor-h0", true),
        ]
    };
    let installing = acks(4, &install_attempt(&attempt(1, 0, vec![ENDPOINT])?));
    let failures = [
        // No route to the endpoint.
        (Vec::new(), Vec::new()),
        // The table cannot be read.
        (vec![leaves()], Vec::new()),
        // The table cannot be created.
        (vec![leaves()], absent()),
        // The table is there; a device cannot be read.
        (vec![leaves(), link_named(2, "eth0", true)], present()?),
        // Forwarding cannot be turned on for the devices that lack it.
        (
            vec![
                leaves(),
                link_named(2, "eth0", false),
                link_named(3, "piglor-h0", false),
            ],
            present()?,
        ),
        // Every device already forwards, so none is written to, but one
        // cannot be read back.
        (
            vec![
                leaves(),
                link_named(2, "eth0", true),
                link_named(3, "piglor-h0", true),
            ],
            present()?,
        ),
        // Every device already forwards; the attempt's rules then cannot be
        // installed.
        (forwarding(), present()?),
        // The rules are installed, but the table cannot be read back.
        (forwarding(), [present()?, vec![installing]].concat()),
    ];
    for (route, netfilter) in failures {
        assert!(matches!(
            install_against(&records, route, netfilter)?,
            Err(HostEgressError::Netlink(_))
        ));
    }
    // Only the egress device was recorded; the veth end leaves with its
    // attempt.
    assert_eq!(records.recorded()?, [(7, "eth0".to_owned())]);
    // Forwarding was turned on for the veth end alone, but the egress device
    // reads back without it.
    let unforwarded = vec![
        leaves(),
        link_named(2, "eth0", true),
        link_named(3, "piglor-h0", false),
        ack(4, 0),
        link_named(5, "eth0", false),
    ];
    assert!(matches!(
        install_against(&records, unforwarded, present()?)?,
        Err(HostEgressError::Forwarding)
    ));
    // A device whose forwarding cannot be recorded is not turned on.
    let unrecordable = ForwardingRecords::in_directory(directory.path().join("forwarding/7"));
    assert!(matches!(
        install_against(
            &unrecordable,
            vec![leaves(), link_named(2, "eth0", false)],
            present()?
        )?,
        Err(HostEgressError::State(_))
    ));
    Ok(())
}

#[test]
fn a_removal_leaves_other_records_and_a_table_without_the_attempt_alone() -> TestResult {
    let (_directory, records) = eth0_recorded()?;
    let attempt = attempt(1, 0, vec![ENDPOINT])?;
    let route = scripted(Vec::new());
    // No table: nothing to remove, and link 7 is not this attempt's.
    let absent = scripted((1..=6).map(done).collect());
    remove_locked(
        &mut Installed::default(),
        &records,
        (&route, &absent),
        &attempt,
    )?;
    assert_eq!(records.recorded()?, [(7, "eth0".to_owned())]);
    // A table without the attempt's chain is left as it is, and then reads
    // back without the host's chains.
    let bare = scripted(vec![
        our_table(1)?,
        done(1),
        done(2),
        done(3),
        our_table(4)?,
        done(4),
        done(5),
        done(6),
    ]);
    assert!(matches!(
        remove_locked(
            &mut Installed::default(),
            &records,
            (&route, &bare),
            &attempt
        ),
        Err(HostEgressError::Readback)
    ));
    Ok(())
}

#[test]
fn foreign_chains_and_rules_beside_the_host_table_are_skipped() -> TestResult {
    let tables = vec![inet(NfTablesMessage::NewTable(TableMessage {
        attributes: vec![
            TableAttribute::Flags(TableFlags::empty()),
            TableAttribute::Name(HOST_TABLE.to_owned()),
        ],
    }))];
    let chains = vec![inet(NfTablesMessage::NewChain(ChainMessage {
        attributes: vec![
            ChainAttribute::Table("docker".to_owned()),
            ChainAttribute::Name(FORWARD.to_owned()),
        ],
    }))];
    let rules = vec![inet(NfTablesMessage::NewRule(RuleMessage {
        attributes: vec![RuleAttribute::Table("docker".to_owned())],
    }))];
    assert_eq!(
        read_table(tables, chains, rules)?,
        Some(ReadTable {
            flags: 0,
            chains: BTreeMap::new(),
        })
    );
    Ok(())
}

#[test]
fn an_expression_that_is_not_one_named_element_has_no_canonical_form() {
    let unnamed = ListAttribute::Element(vec![ExpressionAttribute::Name("masq".to_owned())]);
    assert_eq!(canonical(&[unnamed]), None);
    assert_eq!(canonical(&[ListAttribute::Unspec]), None);
}

/// The acknowledgement, in one datagram, of every acknowledged one of
/// `requests`, numbered from `first`.
fn acks(first: u32, requests: &[Request<NetfilterMessage>]) -> Vec<u8> {
    (first..)
        .zip(requests)
        .filter(|(_, request)| request.acknowledged)
        .flat_map(|(sequence, _)| ack(sequence, 0))
        .collect()
}

/// The three dumps of [`observe`], numbered from `first`, reporting what
/// `batches` created.
fn dumps_of(first: u32, batches: &[Vec<Request<NetfilterMessage>>]) -> Vec<Vec<u8>> {
    let mut replies = Vec::new();
    for (sequence, objects) in (first..).zip(<[_; 3]>::from(as_dumped(batches))) {
        replies.extend(objects.into_iter().map(|object| {
            message(
                sequence,
                NLM_F_MULTIPART,
                NetlinkPayload::InnerMessage(object),
            )
        }));
        replies.push(done(sequence));
    }
    replies
}

/// The host table `batches` created, as [`observe`] reads it.
fn table_of(batches: &[Vec<Request<NetfilterMessage>>]) -> TestResult<ReadTable> {
    let (tables, chains, rules) = as_dumped(batches);
    Ok(read_table(tables, chains, rules)?.ok_or("no host table")?)
}

/// The reply to request `sequence` for the veth end `piglor-h0`, link 9.
fn host_end(sequence: u32) -> Vec<u8> {
    let mut link = LinkMessage::default();
    link.header.index = 9;
    link.attributes = vec![LinkAttribute::IfName("piglor-h0".to_owned())];
    message(
        sequence,
        0,
        NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewLink(link)),
    )
}

/// Opens, in turn, a session for each of `sessions`' protocols that
/// answers with its replies; opening one more fails.
fn opened(
    sessions: Vec<(SessionProtocol, Vec<Vec<u8>>)>,
) -> impl Fn(SessionProtocol) -> Result<NetlinkSession<Scripted>, NetlinkError> {
    let sessions = RefCell::new(VecDeque::from(sessions));
    move |protocol| {
        let (expected, replies) = sessions
            .borrow_mut()
            .pop_front()
            .ok_or(NetlinkError::Unexpected)?;
        assert_eq!(protocol, expected, "a session of another protocol");
        Ok(scripted(replies))
    }
}

/// Host egress recording in `records`, with nothing installed.
fn egress_recording_in(records: ForwardingRecords) -> HostEgress {
    HostEgress {
        installed: Mutex::default(),
        records,
    }
}

#[test]
fn admission_and_changes_fail_when_a_session_cannot_be_opened() -> TestResult {
    let directory = tempfile::tempdir()?;
    let egress = egress_recording_in(ForwardingRecords::in_directory(directory.path()));
    let attempt = attempt(1, 0, vec![ENDPOINT])?;
    let ipv6 = SocketAddr::from((Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1), 443));
    // Admission looks an IPv6 endpoint up through a route session.
    HostEgress::admit_through(opened(vec![(ROUTE, Vec::new())]), &[ENDPOINT])?;
    assert!(matches!(
        HostEgress::admit_through(
            opened(vec![(ROUTE, vec![route_found(1, RouteType::Unicast, 7)])]),
            &[ipv6]
        ),
        Err(HostEgressError::Ipv6Egress)
    ));
    assert!(matches!(
        HostEgress::admit_through(opened(Vec::new()), &[ENDPOINT]),
        Err(HostEgressError::Netlink(NetlinkError::Unexpected))
    ));
    // Neither session, or only the route session, opens.
    for sessions in [Vec::new(), vec![(ROUTE, Vec::new())]] {
        assert!(matches!(
            egress.install_through(opened(sessions.clone()), &attempt),
            Err(HostEgressError::Netlink(NetlinkError::Unexpected))
        ));
        assert!(matches!(
            egress.remove_through(opened(sessions), &attempt),
            Err(HostEgressError::Netlink(NetlinkError::Unexpected))
        ));
    }
    // The veth end cannot be read, or is gone.
    let unreadable = vec![(ROUTE, Vec::new()), (NETFILTER, Vec::new())];
    assert!(matches!(
        egress.install_through(opened(unreadable), &attempt),
        Err(HostEgressError::Netlink(NetlinkError::Truncated))
    ));
    let gone = vec![
        (ROUTE, vec![ack(1, super::super::route::NO_SUCH_LINK)]),
        (NETFILTER, Vec::new()),
    ];
    assert!(matches!(
        egress.install_through(opened(gone), &attempt),
        Err(HostEgressError::Netlink(NetlinkError::Unrepresentable))
    ));
    assert!(std::fs::read_dir(directory.path())?.next().is_none());
    Ok(())
}

#[test]
fn an_attempt_installed_through_fresh_sessions_reads_back_and_is_removed() -> TestResult {
    let directory = tempfile::tempdir()?;
    let records = ForwardingRecords::in_directory(directory.path().join("forwarding"));
    let egress = egress_recording_in(records.clone());
    let attempt = attempt(1, 0, vec![ENDPOINT])?;
    let rules = || install_attempt(&attempt);
    let after_rules = 10 + u32::try_from(rules().len())?;
    // Neither the egress device, link 7, nor the veth end, link 9,
    // forwards yet; both are turned on in one change.
    let route = vec![
        host_end(1),
        route_found(2, RouteType::Unicast, 7),
        link_named(3, "eth0", false),
        link_named(4, "piglor-h0", false),
        ack(5, 0),
        ack(6, 0),
        link_named(7, "eth0", true),
        link_named(8, "piglor-h0", true),
    ];
    let netfilter = [
        vec![
            done(1),
            done(2),
            done(3),
            acks(4, &create_table()),
            acks(10, &rules()),
        ],
        dumps_of(after_rules, &[create_table(), rules()]),
    ]
    .concat();
    egress.install_through(
        opened(vec![(ROUTE, route), (NETFILTER, netfilter)]),
        &attempt,
    )?;
    assert_eq!(records.recorded()?, [(7, "eth0".to_owned())]);
    // Removal deletes the attempt's rules, reads back the bare table and
    // turns the egress device's forwarding back off.
    let installed = table_of(&[create_table(), rules()])?;
    let removal = remove_attempt(&installed, &attempt);
    let after_removal = 4 + u32::try_from(removal.len())?;
    let restoring = vec![
        link_named(1, "eth0", true),
        ack(2, 0),
        link_named(3, "eth0", false),
    ];
    let netfilter = [
        dumps_of(1, &[create_table(), rules()]),
        vec![acks(4, &removal)],
        dumps_of(after_removal, &[create_table()]),
    ]
    .concat();
    egress.remove_through(
        opened(vec![(ROUTE, restoring), (NETFILTER, netfilter)]),
        &attempt,
    )?;
    assert!(records.recorded()?.is_empty());
    Ok(())
}

/// Remove an attempt through link 9 to [`ENDPOINT`] from `installed`
/// against `route` and `netfilter` replies, restoring from `records`.
fn remove_against(
    installed: &mut Installed,
    records: &ForwardingRecords,
    route: Vec<Vec<u8>>,
    netfilter: Vec<Vec<u8>>,
) -> TestResult<Result<(), HostEgressError>> {
    let attempt = attempt(1, 0, vec![ENDPOINT])?;
    Ok(remove_locked(
        installed,
        records,
        (&scripted(route), &scripted(netfilter)),
        &attempt,
    ))
}

/// What is installed when the attempt of [`remove_against`] and, if
/// `shared`, another attempt return by link 7.
fn returning_by_link_7(shared: bool) -> TestResult<Installed> {
    let name = attempt(1, 0, vec![ENDPOINT])?.namespace.as_str().to_owned();
    let mut devices = BTreeMap::from([(name, vec![7])]);
    if shared {
        let other = attempt(2, 1, vec![ENDPOINT])?.namespace.as_str().to_owned();
        devices.insert(other, vec![7]);
    }
    Ok(Installed {
        attempts: BTreeMap::new(),
        devices,
    })
}

#[test]
fn a_removal_stops_at_the_first_exchange_that_fails() -> TestResult {
    let (directory, records) = eth0_recorded()?;
    let attempt = attempt(1, 0, vec![ENDPOINT])?;
    let with_attempt = dumps_of(1, &[create_table(), install_attempt(&attempt)]);
    let absent: Vec<Vec<u8>> = (1..=6).map(done).collect();
    // The table cannot be read, the attempt's rules cannot be deleted, or
    // the table cannot be read back: each refusal ends the removal, and the
    // reply after it is never read.
    for (netfilter, code) in [
        (vec![ack(1, -1)], -1),
        ([with_attempt, vec![ack(4, -2)]].concat(), -2),
        ([absent[..3].to_vec(), vec![ack(4, -3)]].concat(), -3),
    ] {
        let (session, unread) = scripted_with_unread([netfilter, vec![done(99)]].concat());
        let removed = remove_locked(
            &mut Installed::default(),
            &records,
            (&scripted(Vec::new()), &session),
            &attempt,
        );
        assert!(
            matches!(
                removed,
                Err(HostEgressError::Netlink(NetlinkError::Kernel(refused))) if refused == code
            ),
            "{removed:?}"
        );
        assert_eq!(*unread.borrow(), [done(99)]);
    }
    // The records cannot be read.
    let unreadable = ForwardingRecords::in_directory(directory.path().join("forwarding/7"));
    assert!(matches!(
        remove_against(
            &mut Installed::default(),
            &unreadable,
            Vec::new(),
            absent.clone()
        )?,
        Err(HostEgressError::State(_))
    ));
    // The attempt's egress device cannot be restored, and stays recorded.
    assert!(matches!(
        remove_against(
            &mut returning_by_link_7(false)?,
            &records,
            Vec::new(),
            absent.clone()
        )?,
        Err(HostEgressError::Netlink(_))
    ));
    assert_eq!(records.recorded()?, [(7, "eth0".to_owned())]);
    // An egress device another attempt still returns by is left as it is.
    let mut shared = returning_by_link_7(true)?;
    remove_against(&mut shared, &records, Vec::new(), absent)??;
    assert_eq!(records.recorded()?, [(7, "eth0".to_owned())]);
    assert_eq!(shared.devices.len(), 1);
    Ok(())
}

#[test]
fn a_removal_whose_restore_failed_restores_the_device_when_retried() -> TestResult {
    let (_directory, records) = eth0_recorded()?;
    let absent = || (1..=6).map(done).collect::<Vec<_>>();
    let mut installed = returning_by_link_7(false)?;
    // Link 7 cannot be read, so its forwarding stays on: the attempt keeps
    // the device it returns by, and its record stays.
    assert!(matches!(
        remove_against(&mut installed, &records, Vec::new(), absent())?,
        Err(HostEgressError::Netlink(NetlinkError::Truncated))
    ));
    assert_eq!(installed.devices, returning_by_link_7(false)?.devices);
    assert_eq!(records.recorded()?, [(7, "eth0".to_owned())]);
    // The retry restores it, and only then forgets the device.
    let restoring = vec![
        link_named(1, "eth0", true),
        ack(2, 0),
        link_named(3, "eth0", false),
    ];
    remove_against(&mut installed, &records, restoring, absent())??;
    assert!(records.recorded()?.is_empty());
    assert!(installed.devices.is_empty());
    Ok(())
}

#[test]
fn the_host_table_is_deleted_if_it_exists_and_read_back_absent() -> TestResult {
    let deleted = acks(1, &delete_table());
    let absent = || (1..=3).map(done).collect::<Vec<_>>();
    let present =
        || -> TestResult<Vec<Vec<u8>>> { Ok(vec![our_table(1)?, done(1), done(2), done(3)]) };
    let removed = |sessions: Vec<Vec<Vec<u8>>>| {
        let open = opened(
            sessions
                .into_iter()
                .map(|replies| (NETFILTER, replies))
                .collect(),
        );
        remove_table(|| open(NETFILTER))
    };
    removed(vec![vec![deleted.clone()], absent()])?;
    // A table that is already gone needs no deletion.
    removed(vec![vec![ack(2, NO_SUCH_OBJECT)], absent()])?;
    assert!(matches!(
        removed(vec![vec![deleted], present()?]),
        Err(NetlinkError::Residual)
    ));
    assert!(matches!(
        removed(vec![vec![ack(2, -1)]]),
        Err(NetlinkError::Kernel(-1))
    ));
    Ok(())
}
