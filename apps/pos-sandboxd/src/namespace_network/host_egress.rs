//! Host egress for attempt namespaces (#911, owner decisions 2026-11-09 and
//! 2026-11-10): the provider-owned host table `inet piglor_sandbox`, IPv4
//! forwarding on exactly the devices the attempts' traffic enters by, and
//! masquerade, all limited to each attempt's veth end and its exact
//! authenticated endpoints, and read back whole after every change.
//!
//! The table holds a `forward` base chain (filter, policy accept, so other
//! host traffic is untouched) that jumps from each attempt's veth end to that
//! attempt's own chain and ends by dropping anything else from any
//! `piglor-h*` end, the attempt chains themselves, which accept TCP to the
//! attempt's endpoints, and a `postrouting` base chain (nat, policy accept)
//! that masquerades exactly that traffic. Egress is IPv4 only: an IPv6
//! endpoint is reached only when it is an address of the host itself, which
//! needs no forwarding. No other table is ever read for policy or changed.

use std::collections::BTreeMap;
use std::io::Write;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::{Mutex, PoisonError};

use netlink_packet_core::{
    DefaultNla, Emitable, NlasIterator, NLM_F_APPEND, NLM_F_CREATE, NLM_F_EXCL,
};
use netlink_packet_netfilter::nftables::{
    ChainAttribute, ChainMessage, Cmp, DataAttribute, ExpressionAttribute, Expressions, Hook,
    HookNumber, Immediate, InetHookNumber, ListAttribute, Meta, MetaKey, NfTablesMessage, Operator,
    Register, RuleAttribute, RuleMessage, TableAttribute, TableMessage, Verdict, VerdictAttribute,
};
use netlink_packet_netfilter::none::ControlMessage;
use netlink_packet_netfilter::{
    NetfilterHeader, NetfilterMessage, NetfilterMessageInner, NetfilterProtoFamily,
};
use netlink_packet_route::link::{AfSpecInet, AfSpecUnspec, LinkAttribute, LinkMessage};
use netlink_packet_route::route::{RouteAddress, RouteAttribute, RouteMessage, RouteType};
use netlink_packet_route::{AddressFamily, RouteNetlinkMessage};

use super::netlink::{
    consistent, NetlinkError, NetlinkSession, NetlinkTransport, Request, NETFILTER, ROUTE,
};
use super::{encode_firewall_rule, FirewallRule, LinkName, NamespaceName};

/// The netlink protocol a session is opened for: [`ROUTE`] or
/// [`NETFILTER`].
type SessionProtocol = Option<rustix::net::Protocol>;

/// The provider's host table, of family `inet`.
pub const HOST_TABLE: &str = "piglor_sandbox";
/// The base chain every forwarded attempt packet passes.
const FORWARD: &str = "forward";
/// The base chain that masquerades attempt traffic.
const POSTROUTING: &str = "postrouting";
/// The name prefix of every attempt's host veth end.
const ATTEMPT_LINK_PREFIX: &[u8] = b"piglor-h";
/// `IFNAMSIZ`: an interface name as `meta iifname` loads it.
const IFNAMSIZ: usize = 16;
/// `NFNL_SUBSYS_NFTABLES`, the resource a batch's delimiters name.
const NFTABLES: u16 = 10;
/// `NF_DROP`.
const NF_DROP: u32 = 0;
/// `NF_ACCEPT`.
const NF_ACCEPT: u32 = 1;
/// The priority of the forward chain (`filter`).
const FILTER_PRIORITY: u32 = 0;
/// The priority of the postrouting chain (`srcnat`).
const SRCNAT_PRIORITY: u32 = 100;
/// `IFLA_INET_CONF`.
const IFLA_INET_CONF: u16 = 1;
/// `IPV4_DEVCONF_FORWARDING`.
const IPV4_DEVCONF_FORWARDING: u16 = 1;
/// `-ENOENT`: the kernel has no such table.
const NO_SUCH_OBJECT: i32 = -2;
// The flag sets add disjoint single-bit flags, so each sum is their union
// and, unlike `|`, no mutation of the operator leaves it unchanged.
/// Create an object, and fail if it exists.
const CREATE_NEW: u16 = NLM_F_CREATE + NLM_F_EXCL;
/// Create a rule after the chain's last.
const APPEND: u16 = NLM_F_CREATE + NLM_F_APPEND;

/// Why host egress could not be established or removed.
#[derive(Debug, thiserror::Error)]
pub enum HostEgressError {
    /// A netlink exchange failed.
    #[error("a host egress netlink exchange failed")]
    Netlink(#[from] NetlinkError),
    /// An IPv6 endpoint is not an address of the host, and egress is IPv4
    /// only.
    #[error("an IPv6 endpoint is not on this host, and egress is IPv4 only")]
    Ipv6Egress,
    /// The host table read back differently from the installed attempts.
    #[error("the host egress table read back differently")]
    Readback,
    /// A device the attempt's traffic enters by does not forward, or one
    /// whose forwarding was restored still does.
    #[error("a device the attempt's traffic enters by does not have its expected IPv4 forwarding")]
    Forwarding,
    /// The record of a device's forwarding could not be written, read or
    /// removed.
    #[error("the provider's egress forwarding record failed")]
    State(#[source] std::io::Error),
}

/// One attempt's egress: its chain, named after its namespace, its host veth
/// end and the exact endpoints it may reach.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AttemptEgress {
    /// The attempt's namespace, which names its chain.
    pub namespace: NamespaceName,
    /// The attempt's host veth end.
    pub host_link: LinkName,
    /// The authenticated endpoints, IPv4 or on-host IPv6.
    pub endpoints: Vec<SocketAddr>,
}

/// One rule of the host table.
#[derive(Clone, Debug, Eq, PartialEq)]
enum HostRule {
    /// `iifname <link> jump <chain>`.
    Dispatch { link: LinkName, chain: String },
    /// `iifname "piglor-h*" drop`.
    DropUnmatched,
    /// TCP to exactly `endpoint`, accepted.
    Allow(SocketAddr),
    /// `iifname <link>` TCP to exactly `endpoint`, masqueraded.
    Masquerade {
        link: LinkName,
        endpoint: SocketAddr,
    },
}

/// An expression with its name and data.
fn expression(data: Expressions) -> ListAttribute<ExpressionAttribute> {
    ListAttribute::from(data)
}

/// Load the input interface name and compare it with `name`.
fn input_link_is(name: &[u8]) -> [ListAttribute<ExpressionAttribute>; 2] {
    [
        expression(Expressions::Meta(vec![
            Meta::Key(MetaKey::Iifname),
            Meta::DestinationRegister(Register::Reg1),
        ])),
        expression(Expressions::Cmp(vec![
            Cmp::SourceRegister(Register::Reg1),
            Cmp::Op(Operator::Equal),
            Cmp::Data(DataAttribute::Value(name.to_vec())),
        ])),
    ]
}

/// The name of `link` as `meta iifname` loads it, padded with NUL bytes.
fn padded(link: &LinkName) -> Vec<u8> {
    let mut name = link.as_str().as_bytes().to_vec();
    name.resize(IFNAMSIZ, 0);
    name
}

/// A verdict expression.
fn verdict(attributes: Vec<VerdictAttribute>) -> ListAttribute<ExpressionAttribute> {
    expression(Expressions::Immediate(vec![
        Immediate::DestinationRegister(Register::Verdict),
        Immediate::Data(DataAttribute::Verdict(attributes)),
    ]))
}

/// TCP to exactly `endpoint`, without a verdict.
fn tcp_to(endpoint: SocketAddr) -> Vec<ListAttribute<ExpressionAttribute>> {
    let mut expressions = encode_firewall_rule(&FirewallRule::AcceptTcp(endpoint));
    expressions.pop();
    expressions
}

/// The expressions of `rule`.
fn expressions(rule: &HostRule) -> Vec<ListAttribute<ExpressionAttribute>> {
    match rule {
        HostRule::Dispatch { link, chain } => input_link_is(&padded(link))
            .into_iter()
            .chain([verdict(vec![
                VerdictAttribute::Code(Verdict::Jump),
                VerdictAttribute::Chain(chain.clone()),
            ])])
            .collect(),
        HostRule::DropUnmatched => input_link_is(ATTEMPT_LINK_PREFIX)
            .into_iter()
            .chain([verdict(vec![VerdictAttribute::Code(Verdict::Other(
                NF_DROP,
            ))])])
            .collect(),
        HostRule::Allow(endpoint) => encode_firewall_rule(&FirewallRule::AcceptTcp(*endpoint)),
        HostRule::Masquerade { link, endpoint } => input_link_is(&padded(link))
            .into_iter()
            .chain(tcp_to(*endpoint))
            .chain([expression(Expressions::Other {
                expression_type: "masq".to_owned(),
                attributes: Vec::new(),
            })])
            .collect(),
    }
}

/// One expression reduced to what decides it: its name and its attributes
/// as `(type, value)` pairs, sorted.
type CanonicalExpression = (String, Vec<(u16, Vec<u8>)>);

/// The canonical form of `expressions`, or `None` if an element is not
/// exactly one named expression.
fn canonical(
    expressions: &[ListAttribute<ExpressionAttribute>],
) -> Option<Vec<CanonicalExpression>> {
    expressions
        .iter()
        .map(|element| match element {
            ListAttribute::Element(attributes) => match attributes.as_slice() {
                [ExpressionAttribute::Name(name), ExpressionAttribute::Data(data)] => {
                    let mut bytes = vec![0; data.buffer_len()];
                    data.emit(&mut bytes);
                    let mut values: Vec<(u16, Vec<u8>)> = NlasIterator::new(&bytes)
                        .map(|attribute| {
                            attribute.map_or((u16::MAX, Vec::new()), |attribute| {
                                (attribute.kind(), attribute.value().to_vec())
                            })
                        })
                        .collect();
                    values.sort_unstable();
                    Some((name.clone(), values))
                }
                _ => None,
            },
            _ => None,
        })
        .collect()
}

/// The canonical form of `rule`.
fn canonical_rule(rule: &HostRule) -> Vec<CanonicalExpression> {
    canonical(&expressions(rule)).unwrap_or_default()
}

/// A netfilter message of family `inet`.
fn inet(message: NfTablesMessage) -> NetfilterMessage {
    NetfilterMessage::new(
        NetfilterHeader::new(NetfilterProtoFamily::Inet, 0, 0),
        message,
    )
}

/// A batch of `requests`.
fn batch(requests: Vec<Request<NetfilterMessage>>) -> Vec<Request<NetfilterMessage>> {
    let delimiter = |control| {
        Request::unacknowledged(NetfilterMessage::new(
            NetfilterHeader::new(NetfilterProtoFamily::Unspec, 0, NFTABLES),
            control,
        ))
    };
    std::iter::once(delimiter(ControlMessage::BatchBegin))
        .chain(requests)
        .chain([delimiter(ControlMessage::BatchEnd)])
        .collect()
}

/// A base chain of the host table.
fn base_chain(name: &str, hook: InetHookNumber, priority: u32, kind: &str) -> NfTablesMessage {
    NfTablesMessage::NewChain(ChainMessage {
        attributes: vec![
            ChainAttribute::Table(HOST_TABLE.to_owned()),
            ChainAttribute::Name(name.to_owned()),
            ChainAttribute::Hook(vec![
                Hook::Number(HookNumber::Inet(hook)),
                Hook::Priority(priority),
            ]),
            ChainAttribute::Policy(NF_ACCEPT),
            ChainAttribute::Type(kind.to_owned()),
        ],
    })
}

/// A rule of chain `chain`.
fn new_rule(chain: &str, rule: &HostRule) -> NfTablesMessage {
    NfTablesMessage::NewRule(RuleMessage {
        attributes: vec![
            RuleAttribute::Table(HOST_TABLE.to_owned()),
            RuleAttribute::Chain(chain.to_owned()),
            RuleAttribute::Expressions(expressions(rule)),
        ],
    })
}

/// Create the host table with its base chains and the final drop.
fn create_table() -> Vec<Request<NetfilterMessage>> {
    batch(vec![
        Request::acknowledged(
            inet(NfTablesMessage::NewTable(TableMessage {
                attributes: vec![TableAttribute::Name(HOST_TABLE.to_owned())],
            })),
            CREATE_NEW,
        ),
        Request::acknowledged(
            inet(base_chain(
                FORWARD,
                InetHookNumber::Forward,
                FILTER_PRIORITY,
                "filter",
            )),
            CREATE_NEW,
        ),
        Request::acknowledged(
            inet(base_chain(
                POSTROUTING,
                InetHookNumber::PostRouting,
                SRCNAT_PRIORITY,
                "nat",
            )),
            CREATE_NEW,
        ),
        Request::acknowledged(inet(new_rule(FORWARD, &HostRule::DropUnmatched)), APPEND),
    ])
}

/// The rules of `attempt`: its dispatch, its chain's and its masquerades.
fn attempt_rules(attempt: &AttemptEgress) -> (HostRule, Vec<HostRule>, Vec<HostRule>) {
    let forwarded: Vec<SocketAddr> = attempt
        .endpoints
        .iter()
        .copied()
        .filter(SocketAddr::is_ipv4)
        .collect();
    (
        HostRule::Dispatch {
            link: attempt.host_link.clone(),
            chain: attempt.namespace.as_str().to_owned(),
        },
        forwarded.iter().copied().map(HostRule::Allow).collect(),
        forwarded
            .iter()
            .map(|&endpoint| HostRule::Masquerade {
                link: attempt.host_link.clone(),
                endpoint,
            })
            .collect(),
    )
}

/// Install `attempt`'s chain and rules. The dispatch rule goes to the head
/// of the forward chain, before the final drop.
fn install_attempt(attempt: &AttemptEgress) -> Vec<Request<NetfilterMessage>> {
    let chain = attempt.namespace.as_str();
    let (dispatch, allowed, masquerades) = attempt_rules(attempt);
    let mut requests = vec![Request::acknowledged(
        inet(NfTablesMessage::NewChain(ChainMessage {
            attributes: vec![
                ChainAttribute::Table(HOST_TABLE.to_owned()),
                ChainAttribute::Name(chain.to_owned()),
            ],
        })),
        CREATE_NEW,
    )];
    requests.extend(
        allowed
            .iter()
            .map(|rule| Request::acknowledged(inet(new_rule(chain, rule)), APPEND)),
    );
    requests.extend(
        masquerades
            .iter()
            .map(|rule| Request::acknowledged(inet(new_rule(POSTROUTING, rule)), APPEND)),
    );
    // Without `NLM_F_APPEND` a rule is inserted at the chain's head.
    requests.push(Request::acknowledged(
        inet(new_rule(FORWARD, &dispatch)),
        NLM_F_CREATE,
    ));
    batch(requests)
}

/// One chain of the host table as read back.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct ReadChain {
    /// Hook number, priority, policy and type of a base chain.
    base: Option<(u32, u32, u32, String)>,
    /// Each rule's handle and canonical expressions, in order.
    rules: Vec<(u64, Vec<CanonicalExpression>)>,
}

/// The host table as read back, by chain name, with its flags.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct ReadTable {
    flags: u32,
    chains: BTreeMap<String, ReadChain>,
}

/// Whether an object of `family` in table `table` belongs to the host table.
fn ours(table: Option<&String>, family: NetfilterProtoFamily) -> bool {
    family == NetfilterProtoFamily::Inet && table.is_some_and(|table| table == HOST_TABLE)
}

/// The host table the three dumps report, or `None` if it does not exist.
///
/// # Errors
/// Fails on another reply, and on a chain or rule of the host table that is
/// not representable.
fn read_table(
    tables: Vec<NetfilterMessage>,
    chains: Vec<NetfilterMessage>,
    rules: Vec<NetfilterMessage>,
) -> Result<Option<ReadTable>, NetlinkError> {
    let mut table: Option<ReadTable> = None;
    for reply in tables {
        let family = reply.header.family;
        let NetfilterMessageInner::NfTables(NfTablesMessage::NewTable(message)) = reply.inner
        else {
            return Err(NetlinkError::Unexpected);
        };
        let name = message
            .attributes
            .iter()
            .find_map(|attribute| match attribute {
                TableAttribute::Name(name) => Some(name.clone()),
                _ => None,
            });
        if ours(name.as_ref(), family) {
            let flags = message
                .attributes
                .iter()
                .find_map(|attribute| match attribute {
                    TableAttribute::Flags(flags) => Some(flags.bits()),
                    _ => None,
                });
            table = Some(ReadTable {
                flags: flags.unwrap_or(0),
                chains: BTreeMap::new(),
            });
        }
    }
    let Some(mut table) = table else {
        return Ok(None);
    };
    for reply in chains {
        let family = reply.header.family;
        let NetfilterMessageInner::NfTables(NfTablesMessage::NewChain(message)) = reply.inner
        else {
            return Err(NetlinkError::Unexpected);
        };
        let (mut owner, mut name, mut hook, mut priority, mut policy, mut kind) =
            (None, None, None, None, None, None);
        for attribute in message.attributes {
            match attribute {
                ChainAttribute::Table(value) => owner = Some(value),
                ChainAttribute::Name(value) => name = Some(value),
                ChainAttribute::Hook(hooks) => {
                    for part in hooks {
                        match part {
                            Hook::Number(HookNumber::Inet(number)) => {
                                hook = Some(u32::from(number));
                            }
                            Hook::Priority(value) => priority = Some(value),
                            _ => return Err(NetlinkError::Unrepresentable),
                        }
                    }
                }
                ChainAttribute::Policy(value) => policy = Some(value),
                ChainAttribute::Type(value) => kind = Some(value),
                _ => {}
            }
        }
        if ours(owner.as_ref(), family) {
            let base = match (hook, priority, policy, kind) {
                (None, None, None, None) => None,
                (Some(hook), Some(priority), Some(policy), Some(kind)) => {
                    Some((hook, priority, policy, kind))
                }
                _ => return Err(NetlinkError::Unrepresentable),
            };
            table.chains.insert(
                name.ok_or(NetlinkError::Unrepresentable)?,
                ReadChain {
                    base,
                    rules: Vec::new(),
                },
            );
        }
    }
    for reply in rules {
        let family = reply.header.family;
        let NetfilterMessageInner::NfTables(NfTablesMessage::NewRule(message)) = reply.inner else {
            return Err(NetlinkError::Unexpected);
        };
        let (mut owner, mut chain, mut handle, mut found) = (None, None, None, None);
        for attribute in message.attributes {
            match attribute {
                RuleAttribute::Table(value) => owner = Some(value),
                RuleAttribute::Chain(value) => chain = Some(value),
                RuleAttribute::Handle(value) => handle = Some(value),
                RuleAttribute::Expressions(value) => found = Some(canonical(&value)),
                _ => {}
            }
        }
        if ours(owner.as_ref(), family) {
            let read = chain
                .and_then(|chain| table.chains.get_mut(&chain))
                .zip(handle.zip(found.flatten()))
                .ok_or(NetlinkError::Unrepresentable)?;
            read.0.rules.push(read.1);
        }
    }
    Ok(Some(table))
}

/// Whether `observed` holds exactly the rules of `expected`, each as often,
/// in any order.
fn same_rules(expected: &[HostRule], observed: &[(u64, Vec<CanonicalExpression>)]) -> bool {
    let mut expected: Vec<Vec<CanonicalExpression>> = expected.iter().map(canonical_rule).collect();
    let mut observed: Vec<Vec<CanonicalExpression>> =
        observed.iter().map(|(_, rule)| rule.clone()).collect();
    expected.sort_unstable();
    observed.sort_unstable();
    expected == observed
}

/// Whether `table` is exactly the host table of `attempts`.
fn is_exact(table: &ReadTable, attempts: &BTreeMap<String, AttemptEgress>) -> bool {
    let forward_base = Some((
        u32::from(InetHookNumber::Forward),
        FILTER_PRIORITY,
        NF_ACCEPT,
        "filter".to_owned(),
    ));
    let postrouting_base = Some((
        u32::from(InetHookNumber::PostRouting),
        SRCNAT_PRIORITY,
        NF_ACCEPT,
        "nat".to_owned(),
    ));
    let mut dispatches = Vec::new();
    let mut masquerades = Vec::new();
    let attempt_chains = attempts.iter().all(|(chain, attempt)| {
        let (dispatch, allowed, masquerade) = attempt_rules(attempt);
        dispatches.push(dispatch);
        masquerades.extend(masquerade);
        table.chains.get(chain).is_some_and(|read| {
            read.base.is_none()
                && read.rules.len() == allowed.len()
                && read
                    .rules
                    .iter()
                    .zip(&allowed)
                    .all(|((_, observed), rule)| *observed == canonical_rule(rule))
        })
    });
    let forward = table.chains.get(FORWARD).is_some_and(|read| {
        read.base == forward_base
            && read.rules.split_last().is_some_and(|(last, dispatched)| {
                last.1 == canonical_rule(&HostRule::DropUnmatched)
                    && same_rules(&dispatches, dispatched)
            })
    });
    let postrouting = table
        .chains
        .get(POSTROUTING)
        .is_some_and(|read| read.base == postrouting_base && same_rules(&masquerades, &read.rules));
    table.flags == 0
        && table.chains.len() == attempts.len() + 2
        && attempt_chains
        && forward
        && postrouting
}

/// The dumps of every table, chain and rule.
fn dumps() -> [NetfilterMessage; 3] {
    let unspec = |message| {
        NetfilterMessage::new(
            NetfilterHeader::new(NetfilterProtoFamily::Unspec, 0, 0),
            message,
        )
    };
    [
        unspec(NfTablesMessage::GetTable(TableMessage {
            attributes: Vec::new(),
        })),
        unspec(NfTablesMessage::GetChain(ChainMessage {
            attributes: Vec::new(),
        })),
        unspec(NfTablesMessage::GetRule(RuleMessage {
            attributes: Vec::new(),
        })),
    ]
}

/// Read the host table through `session`.
fn observe<T: NetlinkTransport>(
    session: &NetlinkSession<T>,
) -> Result<Option<ReadTable>, NetlinkError> {
    let [tables, chains, rules] = dumps();
    session.dump(tables).and_then(|tables| {
        session.dump(chains).and_then(|chains| {
            session
                .dump(rules)
                .and_then(|rules| read_table(tables, chains, rules))
        })
    })
}

/// Remove `attempt`'s dispatch and masquerade rules, by the handles `table`
/// reports, its chain's rules and its chain.
fn remove_attempt(table: &ReadTable, attempt: &AttemptEgress) -> Vec<Request<NetfilterMessage>> {
    let (dispatch, _, masquerades) = attempt_rules(attempt);
    let by_handle = |chain: &str, rules: &[HostRule]| -> Vec<Request<NetfilterMessage>> {
        let wanted: Vec<Vec<CanonicalExpression>> = rules.iter().map(canonical_rule).collect();
        table
            .chains
            .get(chain)
            .map(|read| {
                read.rules
                    .iter()
                    .filter(|(_, rule)| wanted.contains(rule))
                    .map(|&(handle, _)| {
                        Request::acknowledged(
                            inet(NfTablesMessage::DeleteRule(RuleMessage {
                                attributes: vec![
                                    RuleAttribute::Table(HOST_TABLE.to_owned()),
                                    RuleAttribute::Chain(chain.to_owned()),
                                    RuleAttribute::Handle(handle),
                                ],
                            })),
                            0,
                        )
                    })
                    .collect()
            })
            .unwrap_or_default()
    };
    let chain = attempt.namespace.as_str();
    let mut requests = by_handle(FORWARD, &[dispatch]);
    requests.extend(by_handle(POSTROUTING, &masquerades));
    // A rule deletion without a handle flushes the chain.
    requests.push(Request::acknowledged(
        inet(NfTablesMessage::DeleteRule(RuleMessage {
            attributes: vec![
                RuleAttribute::Table(HOST_TABLE.to_owned()),
                RuleAttribute::Chain(chain.to_owned()),
            ],
        })),
        0,
    ));
    requests.push(Request::acknowledged(
        inet(NfTablesMessage::DeleteChain(ChainMessage {
            attributes: vec![
                ChainAttribute::Table(HOST_TABLE.to_owned()),
                ChainAttribute::Name(chain.to_owned()),
            ],
        })),
        0,
    ));
    batch(requests)
}

/// Delete the host table and everything in it.
fn delete_table() -> Vec<Request<NetfilterMessage>> {
    batch(vec![Request::acknowledged(
        inet(NfTablesMessage::DeleteTable(TableMessage {
            attributes: vec![TableAttribute::Name(HOST_TABLE.to_owned())],
        })),
        0,
    )])
}

/// A route lookup of `address` in the session's namespace.
fn route_to(address: IpAddr) -> RouteNetlinkMessage {
    let mut message = RouteMessage::default();
    message.header.address_family = match address {
        IpAddr::V4(_) => AddressFamily::Inet,
        IpAddr::V6(_) => AddressFamily::Inet6,
    };
    message.header.destination_prefix_length = if address.is_ipv4() { 32 } else { 128 };
    message.attributes = vec![RouteAttribute::Destination(RouteAddress::from(address))];
    RouteNetlinkMessage::GetRoute(message)
}

/// Whether a [`route_to`] reply delivers locally, and the link it leaves
/// by.
fn route_reply(reply: RouteNetlinkMessage) -> Result<(bool, u32), NetlinkError> {
    match reply {
        RouteNetlinkMessage::NewRoute(message) => message
            .attributes
            .iter()
            .find_map(|attribute| match attribute {
                RouteAttribute::Oif(index) => Some(*index),
                _ => None,
            })
            .map(|index| (message.header.kind == RouteType::Local, index))
            .ok_or(NetlinkError::Unrepresentable),
        _ => Err(NetlinkError::Unexpected),
    }
}

/// Turn IPv4 forwarding on or off for packets that enter by link `index`.
pub(super) fn set_forwarding(index: u32, on: bool) -> Request<RouteNetlinkMessage> {
    let forwarding = DefaultNla::new(
        IPV4_DEVCONF_FORWARDING,
        u32::from(on).to_ne_bytes().to_vec(),
    );
    let mut nested = vec![0; forwarding.buffer_len()];
    forwarding.emit(&mut nested);
    let mut message = LinkMessage::default();
    message.header.index = index;
    message.attributes = vec![LinkAttribute::AfSpecUnspec(vec![AfSpecUnspec::Inet(vec![
        AfSpecInet::Other(DefaultNla::new(IFLA_INET_CONF, nested)),
    ])])];
    Request::acknowledged(RouteNetlinkMessage::SetLink(message), 0)
}

/// The link of index `index`.
fn get_link(index: u32) -> RouteNetlinkMessage {
    let mut message = LinkMessage::default();
    message.header.index = index;
    RouteNetlinkMessage::GetLink(message)
}

/// The name of the link a [`get_link`] reply reports, and whether it
/// forwards IPv4.
pub(super) fn link_forwarding(reply: RouteNetlinkMessage) -> Result<(String, bool), NetlinkError> {
    match reply {
        RouteNetlinkMessage::NewLink(message) => {
            let forwarding = message.attributes.iter().any(|attribute| {
                matches!(attribute, LinkAttribute::AfSpecUnspec(specs) if specs.iter().any(|spec| {
                    matches!(spec, AfSpecUnspec::Inet(inet) if inet.iter().any(|value| {
                        matches!(value, AfSpecInet::DevConf(conf) if conf.forwarding == 1)
                    }))
                }))
            });
            message
                .attributes
                .into_iter()
                .find_map(|attribute| match attribute {
                    LinkAttribute::IfName(name) => Some(name),
                    _ => None,
                })
                .map(|name| (name, forwarding))
                .ok_or(NetlinkError::Unrepresentable)
        }
        _ => Err(NetlinkError::Unexpected),
    }
}

/// Every link index the IPv4 traffic of an attempt enters the host by: its
/// veth end, `host_link`, and the link each off-host IPv4 endpoint's
/// replies come back by. IPv6 endpoints, admitted only on the host, need
/// none.
fn ingress_links<T: NetlinkTransport>(
    session: &NetlinkSession<T>,
    host_link: u32,
    endpoints: &[SocketAddr],
) -> Result<Vec<u32>, HostEgressError> {
    let mut links = vec![host_link];
    for endpoint in endpoints.iter().filter(|endpoint| endpoint.is_ipv4()) {
        let (local, link) = session
            .request(route_to(endpoint.ip()))
            .and_then(route_reply)?;
        if !local {
            links.push(link);
        }
    }
    links.sort_unstable();
    links.dedup();
    Ok(links)
}

/// Refuse every IPv6 endpoint the host does not hold, by the session's
/// route lookups: egress is IPv4 only.
fn admit_on<T: NetlinkTransport>(
    session: &NetlinkSession<T>,
    endpoints: &[SocketAddr],
) -> Result<(), HostEgressError> {
    for endpoint in endpoints.iter().filter(|endpoint| endpoint.is_ipv6()) {
        let (local, _) = session
            .request(route_to(endpoint.ip()))
            .and_then(route_reply)?;
        if !local {
            return Err(HostEgressError::Ipv6Egress);
        }
    }
    Ok(())
}

/// The chains of the host table, by name, or `None` if it does not exist.
///
/// # Errors
/// Fails if the table cannot be read.
#[cfg(test)]
pub(super) fn host_chains<T: NetlinkTransport>(
    session: &NetlinkSession<T>,
) -> Result<Option<Vec<String>>, NetlinkError> {
    observe(session).map(|table| table.map(|table| table.chains.into_keys().collect()))
}

/// Where the provider records the egress devices it turned forwarding on
/// for.
pub const FORWARDING_RECORDS: &str = "/run/pigloros/sandbox/egress-forwarding";

/// The provider's durable record of every egress device whose IPv4
/// forwarding it turned on.
///
/// There is one file per device, named by its index and holding its
/// name. A record is written and synced before forwarding is
/// turned on, and removed only after it is turned off again, so after a
/// crash restart reconciliation knows what to restore. A device that
/// already forwarded is never recorded, and so never turned off.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ForwardingRecords {
    directory: PathBuf,
}

impl Default for ForwardingRecords {
    fn default() -> Self {
        Self::in_directory(FORWARDING_RECORDS)
    }
}

impl ForwardingRecords {
    /// Records kept in `directory`.
    #[must_use]
    pub fn in_directory(directory: impl Into<PathBuf>) -> Self {
        Self {
            directory: directory.into(),
        }
    }

    /// Record that the provider turns forwarding on for link `index`, named
    /// `name`.
    pub(super) fn record(&self, index: u32, name: &str) -> std::io::Result<()> {
        let partial = self.directory.join(format!("{index}.partial"));
        std::fs::create_dir_all(&self.directory)
            .and_then(|()| std::fs::File::create(&partial))
            .and_then(|mut file| {
                file.write_all(name.as_bytes())
                    .and_then(|()| file.sync_all())
            })
            .and_then(|()| std::fs::rename(&partial, self.directory.join(index.to_string())))
            .and_then(|()| std::fs::File::open(&self.directory))
            .and_then(|directory| directory.sync_all())
    }

    /// Every recorded device's index and name. A missing directory holds
    /// none, and a record that was never completed is no record.
    pub(super) fn recorded(&self) -> std::io::Result<Vec<(u32, String)>> {
        match std::fs::read_dir(&self.directory) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
            listed => listed.and_then(|entries| {
                entries
                    .filter_map(|entry| {
                        entry
                            .map(|entry| {
                                entry
                                    .file_name()
                                    .to_str()
                                    .and_then(|name| name.parse::<u32>().ok())
                                    .map(|index| (index, entry.path()))
                            })
                            .transpose()
                    })
                    .map(|entry| {
                        entry.and_then(|(index, path)| {
                            std::fs::read_to_string(path).map(|name| (index, name))
                        })
                    })
                    .collect()
            }),
        }
    }

    /// Remove the record of link `index`, if any.
    fn forget(&self, index: u32) -> std::io::Result<()> {
        match std::fs::remove_file(self.directory.join(index.to_string())) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            removed => removed,
        }
    }
}

/// Turn forwarding back off on recorded link `index`, named `name`, if it
/// still exists under that name, read that back, and forget the record.
fn restore<T: NetlinkTransport>(
    route: &NetlinkSession<T>,
    records: &ForwardingRecords,
    index: u32,
    name: &str,
) -> Result<(), HostEgressError> {
    let current = match route.request(get_link(index)) {
        Err(NetlinkError::Kernel(super::route::NO_SUCH_LINK)) => None,
        reply => Some(reply.and_then(link_forwarding)?),
    };
    // A device that is gone, or whose index now names another device, has
    // nothing left to restore.
    if current.is_some_and(|(current_name, _)| current_name == name) {
        route.execute(vec![set_forwarding(index, false)])?;
        if route.request(get_link(index)).and_then(link_forwarding)?.1 {
            return Err(HostEgressError::Forwarding);
        }
    }
    records.forget(index).map_err(HostEgressError::State)
}

/// Restore every recorded device's forwarding through `route` and forget
/// its record.
/// Restart reconciliation calls this with the other orphan removals.
///
/// # Errors
/// Fails if a record cannot be read or removed, or a device cannot be
/// restored.
pub(super) fn restore_forwarding<T: NetlinkTransport>(
    route: &NetlinkSession<T>,
    records: &ForwardingRecords,
) -> Result<(), HostEgressError> {
    for (index, name) in records.recorded().map_err(HostEgressError::State)? {
        restore(route, records, index, &name)?;
    }
    Ok(())
}

/// The host side of attempt networks: it admits endpoints, gives an
/// installed attempt egress and takes it away again.
pub trait EgressControl {
    /// Check that `endpoints` can be reached: IPv4 endpoints, and IPv6
    /// endpoints that are addresses of the host.
    ///
    /// # Errors
    /// Fails on an IPv6 endpoint off the host, before anything changes.
    fn admit(&self, endpoints: &[SocketAddr]) -> Result<(), HostEgressError>;

    /// Give `attempt`, whose namespace and veth pair exist, egress, and read
    /// it back.
    ///
    /// # Errors
    /// Fails on any refused change or differing read-back; the caller then
    /// removes the attempt.
    fn install(&self, attempt: &AttemptEgress) -> Result<(), HostEgressError>;

    /// Take `attempt`'s egress away, whichever part exists, and read it back.
    ///
    /// # Errors
    /// Fails on a refused change or a differing read-back.
    fn remove(&self, attempt: &AttemptEgress) -> Result<(), HostEgressError>;
}

/// What the provider installed: each attempt's egress, and the egress
/// devices its traffic returns by.
#[derive(Debug, Default)]
struct Installed {
    attempts: BTreeMap<String, AttemptEgress>,
    devices: BTreeMap<String, Vec<u32>>,
}

/// The provider's host egress in the calling thread's network namespace.
///
/// It holds the attempts it installed, whose table it reads back after
/// every change, and the record of the egress devices it turned forwarding
/// on for. One change runs at a time.
#[derive(Debug, Default)]
pub struct HostEgress {
    installed: Mutex<Installed>,
    records: ForwardingRecords,
}

impl HostEgress {
    /// No attempt has egress yet; forwarding is recorded in
    /// [`FORWARDING_RECORDS`].
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Check `endpoints` through a route session from `open`.
    fn admit_through<T: NetlinkTransport>(
        open: impl Fn(SessionProtocol) -> Result<NetlinkSession<T>, NetlinkError>,
        endpoints: &[SocketAddr],
    ) -> Result<(), HostEgressError> {
        let route = open(ROUTE)?;
        admit_on(&route, endpoints)
    }

    /// Give `attempt` egress through route and netfilter sessions from
    /// `open`, holding the installed attempts for the whole change.
    fn install_through<T: NetlinkTransport>(
        &self,
        open: impl Fn(SessionProtocol) -> Result<NetlinkSession<T>, NetlinkError>,
        attempt: &AttemptEgress,
    ) -> Result<(), HostEgressError> {
        let route = open(ROUTE)?;
        let netfilter = open(NETFILTER)?;
        let host_link =
            super::route::link_reply(route.request(super::route::get_link(&attempt.host_link)))?
                .ok_or(NetlinkError::Unrepresentable)?;
        let mut installed = self
            .installed
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        install_locked(
            &mut installed,
            &self.records,
            (&route, &netfilter),
            host_link.index,
            attempt,
        )
    }

    /// Take `attempt`'s egress away through route and netfilter sessions
    /// from `open`, holding the installed attempts for the whole change.
    fn remove_through<T: NetlinkTransport>(
        &self,
        open: impl Fn(SessionProtocol) -> Result<NetlinkSession<T>, NetlinkError>,
        attempt: &AttemptEgress,
    ) -> Result<(), HostEgressError> {
        let route = open(ROUTE)?;
        let netfilter = open(NETFILTER)?;
        let mut installed = self
            .installed
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        remove_locked(&mut installed, &self.records, (&route, &netfilter), attempt)
    }
}

/// [`HostEgress::install_through`] with what is `installed`.
///
/// The table, with its final drop, exists before any forwarding is turned
/// on, so a forwarded packet never meets a host without the drop. An egress
/// device that does not forward yet is recorded before it is turned on.
fn install_locked<R: NetlinkTransport, N: NetlinkTransport>(
    installed: &mut Installed,
    records: &ForwardingRecords,
    (route, netfilter): (&NetlinkSession<R>, &NetlinkSession<N>),
    host_link: u32,
    attempt: &AttemptEgress,
) -> Result<(), HostEgressError> {
    let links = ingress_links(route, host_link, &attempt.endpoints)?;
    let egress: Vec<u32> = links
        .iter()
        .copied()
        .filter(|&link| link != host_link)
        .collect();
    let name = attempt.namespace.as_str().to_owned();
    installed.attempts.insert(name.clone(), attempt.clone());
    installed.devices.insert(name, egress);
    if observe(netfilter)?.is_none() {
        netfilter.execute(create_table())?;
    }
    enable_forwarding(route, records, host_link, &links)?;
    netfilter.execute(install_attempt(attempt))?;
    observe(netfilter)?
        .is_some_and(|table| is_exact(&table, &installed.attempts))
        .then_some(())
        .ok_or(HostEgressError::Readback)
}

/// Turn IPv4 forwarding on for every one of `links` that does not forward
/// yet, recording each such egress device first, and read it back on all of
/// them. A device that already forwards is never written to, and the veth
/// end `host_link` leaves with its attempt, so it is never recorded.
fn enable_forwarding<R: NetlinkTransport>(
    route: &NetlinkSession<R>,
    records: &ForwardingRecords,
    host_link: u32,
    links: &[u32],
) -> Result<(), HostEgressError> {
    let mut off = Vec::new();
    for &link in links {
        let (device, forwarding) = route.request(get_link(link)).and_then(link_forwarding)?;
        if !forwarding {
            if link != host_link {
                records
                    .record(link, &device)
                    .map_err(HostEgressError::State)?;
            }
            off.push(set_forwarding(link, true));
        }
    }
    if !off.is_empty() {
        route.execute(off)?;
    }
    for &link in links {
        if !route.request(get_link(link)).and_then(link_forwarding)?.1 {
            return Err(HostEgressError::Forwarding);
        }
    }
    Ok(())
}

/// [`HostEgress::remove_through`] with what is `installed`: the attempt's rules
/// go first, then each recorded egress device no other attempt still uses
/// gets its forwarding back. The attempt's devices are forgotten only once
/// all of them are restored, so a retried removal restores what is left.
fn remove_locked<R: NetlinkTransport, N: NetlinkTransport>(
    installed: &mut Installed,
    records: &ForwardingRecords,
    (route, netfilter): (&NetlinkSession<R>, &NetlinkSession<N>),
    attempt: &AttemptEgress,
) -> Result<(), HostEgressError> {
    let name = attempt.namespace.as_str();
    installed.attempts.remove(name);
    let devices = installed.devices.get(name).cloned().unwrap_or_default();
    if let Some(table) = observe(netfilter)? {
        if table.chains.contains_key(attempt.namespace.as_str()) {
            netfilter.execute(remove_attempt(&table, attempt))?;
        }
    }
    let table_read_back =
        observe(netfilter)?.is_none_or(|table| is_exact(&table, &installed.attempts));
    let in_use: Vec<u32> = installed
        .devices
        .iter()
        .filter(|(other, _)| other.as_str() != name)
        .flat_map(|(_, used)| used)
        .copied()
        .collect();
    for (index, device) in records.recorded().map_err(HostEgressError::State)? {
        if devices.contains(&index) && !in_use.contains(&index) {
            restore(route, records, index, &device)?;
        }
    }
    installed.devices.remove(name);
    table_read_back
        .then_some(())
        .ok_or(HostEgressError::Readback)
}

impl EgressControl for HostEgress {
    fn admit(&self, endpoints: &[SocketAddr]) -> Result<(), HostEgressError> {
        Self::admit_through(NetlinkSession::open, endpoints)
    }

    fn install(&self, attempt: &AttemptEgress) -> Result<(), HostEgressError> {
        self.install_through(NetlinkSession::open, attempt)
    }

    fn remove(&self, attempt: &AttemptEgress) -> Result<(), HostEgressError> {
        self.remove_through(NetlinkSession::open, attempt)
    }
}

/// Delete the whole host table, if it exists, and read its absence back.
/// Restart reconciliation calls this with the other orphan removals.
///
/// # Errors
/// Fails if the table cannot be deleted or remains.
pub(super) fn remove_table<N: NetlinkTransport>(
    netfilter_session: impl Fn() -> Result<NetlinkSession<N>, NetlinkError>,
) -> Result<(), NetlinkError> {
    netfilter_session()
        .and_then(|session| match session.execute(delete_table()) {
            Err(NetlinkError::Kernel(NO_SUCH_OBJECT)) => Ok(()),
            deleted => deleted,
        })
        .and_then(|()| consistent(|| netfilter_session().and_then(|session| observe(&session))))
        .and_then(|table| table.map_or(Ok(()), |_| Err(NetlinkError::Residual)))
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests;
