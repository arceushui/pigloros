use std::{
    cell::RefCell,
    collections::VecDeque,
    error::Error,
    net::{Ipv4Addr, Ipv6Addr},
};

use netlink_packet_core::{NetlinkHeader, NetlinkMessage, NetlinkPayload};
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
    assert_eq!(masquerade.len(), 2 + tcp_to(ENDPOINT).len() + 1);
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
    assert_eq!(flags, [0, CREATE_NEW, CREATE_NEW, CREATE_NEW, APPEND, 0]);
    let attempt = attempt(
        1,
        3,
        vec![ENDPOINT, SocketAddr::from((Ipv6Addr::LOCALHOST, 80))],
    )?;
    let installed = install_attempt(&attempt);
    let flags: Vec<u16> = installed.iter().map(|request| request.flags).collect();
    // The chain, its one IPv4 rule, one masquerade and the dispatch at the
    // forward chain's head; the on-host IPv6 endpoint needs neither.
    assert_eq!(flags, [0, CREATE_NEW, APPEND, APPEND, NLM_F_CREATE, 0]);
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
    let mutations: [fn(&mut ReadTable); 6] = [
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
fn unrepresentable_or_foreign_replies_fail_the_read() -> TestResult {
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
    Ok(())
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

/// A transport that replies with scripted datagrams.
#[derive(Default)]
struct Scripted {
    replies: RefCell<VecDeque<Vec<u8>>>,
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

#[test]
fn ingress_links_are_the_veth_end_and_each_off_host_endpoints_link() -> TestResult {
    let session = NetlinkSession::new(Scripted {
        replies: RefCell::new(VecDeque::from([
            route_found(1, RouteType::Unicast, 7),
            route_found(2, RouteType::Local, 1),
            route_found(3, RouteType::Unicast, 7),
            route_found(4, RouteType::Local, 1),
        ])),
    });
    let endpoints = [
        ENDPOINT,
        SocketAddr::from(([127, 0, 0, 1], 80)),
        SocketAddr::from(([198, 51, 100, 7], 443)),
        SocketAddr::from((Ipv6Addr::LOCALHOST, 80)),
    ];
    assert_eq!(ingress_links(&session, 9, &endpoints)?, [7, 9]);
    // An IPv6 endpoint off the host is refused.
    let remote = NetlinkSession::new(Scripted {
        replies: RefCell::new(VecDeque::from([route_found(1, RouteType::Unicast, 7)])),
    });
    let ipv6 = [SocketAddr::from((
        Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
        443,
    ))];
    assert!(matches!(
        ingress_links(&remote, 9, &ipv6),
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
    // device configuration.
    let RouteNetlinkMessage::SetLink(set) = forward_from(5).message else {
        return Err("not a link change".into());
    };
    assert_eq!(set.header.index, 5);
    let mut forwarding = LinkMessage::default();
    let mut conf = InetDevConf::default();
    conf.forwarding = 1;
    forwarding.attributes = vec![LinkAttribute::AfSpecUnspec(vec![AfSpecUnspec::Inet(vec![
        AfSpecInet::DevConf(conf),
    ])])];
    assert!(forwards(RouteNetlinkMessage::NewLink(forwarding))?);
    assert!(!forwards(RouteNetlinkMessage::NewLink(
        LinkMessage::default()
    ))?);
    assert!(matches!(
        forwards(route_to(ENDPOINT.ip())),
        Err(NetlinkError::Unexpected)
    ));
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
            "a device the attempt's traffic enters by does not forward IPv4",
        ),
    ] {
        assert_eq!(error.to_string(), message);
    }
}
