//! The nftables expressions of each [`FirewallRule`], in both directions
//! (#911, owner decision 2026-11-09).
//!
//! Every rule loads into register 1 and ends in an `accept` verdict. A match
//! on an IPv6 address or hop limit follows a `meta nfproto` match, and a
//! match on a TCP port or `ICMPv6` type follows a `meta l4proto` match, so no
//! payload is read from a packet of another protocol.
//!
//! `netlink-packet-netfilter` has no typed conntrack expression, so the `ct
//! state` load is encoded by hand as raw attributes, pinned by golden byte
//! vectors. An `accept` verdict is the raw verdict code `NF_ACCEPT`.
//!
//! Decoding is structural rather than byte-for-byte: the kernel reports each
//! expression's attributes in its own order, and kernels since 5.6 add
//! `NFTA_BITWISE_OP` with the boolean operation to every `bitwise`
//! expression. A read-back rule decodes only if, after those two
//! normalisations, it equals the encoding of exactly one rule; any other
//! attribute, value or expression leaves it undecodable.

use std::net::{IpAddr, Ipv6Addr, SocketAddr};

use netlink_packet_core::{DefaultNla, Emitable, NlasIterator};
use netlink_packet_netfilter::nftables::{
    Bitwise, Cmp, DataAttribute, ExpressionAttribute, Expressions, Immediate, ListAttribute, Meta,
    MetaKey, Operator, Payload, Register, Verdict, VerdictAttribute,
};

use super::FirewallRule;

/// `NFPROTO_IPV4`.
const NFPROTO_IPV4: u8 = 2;
/// `NFPROTO_IPV6`.
const NFPROTO_IPV6: u8 = 10;
/// `IPPROTO_TCP`.
const IPPROTO_TCP: u8 = 6;
/// `IPPROTO_ICMPV6`.
const IPPROTO_ICMPV6: u8 = 58;
/// `NFT_PAYLOAD_NETWORK_HEADER`.
const NETWORK_HEADER: u32 = 1;
/// `NFT_PAYLOAD_TRANSPORT_HEADER`.
const TRANSPORT_HEADER: u32 = 2;
/// The offset of the destination address in an IPv4 header.
const IPV4_DESTINATION: u32 = 16;
/// The offset of the destination address in an IPv6 header.
const IPV6_DESTINATION: u32 = 24;
/// The offset of the hop limit in an IPv6 header.
const IPV6_HOP_LIMIT: u32 = 7;
/// The offset of the destination port in a TCP header.
const TCP_DESTINATION_PORT: u32 = 2;
/// `ICMPv6` neighbour solicitation.
const NEIGHBOUR_SOLICITATION: u8 = 135;
/// `ICMPv6` neighbour advertisement.
const NEIGHBOUR_ADVERTISEMENT: u8 = 136;
/// The `ct` expression's `NFTA_CT_DREG` attribute.
const NFTA_CT_DREG: u16 = 1;
/// The `ct` expression's `NFTA_CT_KEY` attribute.
const NFTA_CT_KEY: u16 = 2;
/// `NFT_CT_STATE`.
const NFT_CT_STATE: u32 = 0;
/// `NFT_REG_1`, as the kernel numbers it in a `ct` expression.
const NFT_REG_1: u32 = 1;
/// The conntrack state bits of `established` and `related`
/// (`NF_CT_STATE_BIT(IP_CT_ESTABLISHED) | NF_CT_STATE_BIT(IP_CT_RELATED)`),
/// in host byte order as the kernel loads them.
const ESTABLISHED_OR_RELATED: u32 = 0b110;
/// `NF_ACCEPT`.
const NF_ACCEPT: u32 = 1;
/// `NFTA_BITWISE_OP`, which kernels since 5.6 report on every `bitwise`.
const NFTA_BITWISE_OP: u16 = 6;
/// `NFT_BITWISE_BOOL`, the operation of a mask-and-xor `bitwise`.
const NFT_BITWISE_BOOL: u32 = 0;
/// The attribute type that stands for an attribute that does not parse.
const UNPARSED: u16 = u16::MAX;

/// A read-back rule that is not the encoding of any [`FirewallRule`].
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("the firewall rule holds expressions no provider rule has")]
pub struct UndecodableRule;

/// One expression of a provider rule.
#[derive(Debug)]
enum Expr {
    /// Load the meta value `key` into register 1.
    Meta(MetaKey),
    /// Load `len` bytes at `offset` of header `base` into register 1.
    Payload { base: u32, offset: u32, len: u32 },
    /// Mask register 1 with `mask`, and clear no bit.
    Mask(Vec<u8>),
    /// Compare register 1 with `data` by `op`.
    Cmp(Operator, Vec<u8>),
    /// Load the conntrack state into register 1.
    CtState,
    /// Accept the packet.
    Accept,
}

impl Expr {
    /// The netfilter expression, with its attributes in the order the kernel
    /// reports them.
    fn encode(self) -> Expressions {
        match self {
            Self::Meta(key) => Expressions::Meta(vec![
                Meta::Key(key),
                Meta::DestinationRegister(Register::Reg1),
            ]),
            Self::Payload { base, offset, len } => Expressions::Payload(vec![
                Payload::DestinationRegister(Register::Reg1),
                Payload::Base(base),
                Payload::Offset(offset),
                Payload::Len(len),
            ]),
            Self::Mask(mask) => {
                let xor = vec![0; mask.len()];
                Expressions::Bitwise(vec![
                    Bitwise::SourceRegister(Register::Reg1),
                    Bitwise::DestinationRegister(Register::Reg1),
                    Bitwise::Length(byte_length(&mask)),
                    Bitwise::Mask(DataAttribute::Value(mask)),
                    Bitwise::Xor(DataAttribute::Value(xor)),
                ])
            }
            Self::Cmp(op, data) => Expressions::Cmp(vec![
                Cmp::SourceRegister(Register::Reg1),
                Cmp::Op(op),
                Cmp::Data(DataAttribute::Value(data)),
            ]),
            Self::CtState => Expressions::Other {
                expression_type: "ct".to_owned(),
                attributes: vec![
                    DefaultNla::new(NFTA_CT_DREG, NFT_REG_1.to_be_bytes().to_vec()),
                    DefaultNla::new(NFTA_CT_KEY, NFT_CT_STATE.to_be_bytes().to_vec()),
                ],
            },
            Self::Accept => Expressions::Immediate(vec![
                Immediate::DestinationRegister(Register::Verdict),
                Immediate::Data(DataAttribute::Verdict(vec![VerdictAttribute::Code(
                    Verdict::Other(NF_ACCEPT),
                )])),
            ]),
        }
    }
}

/// `meta <key>` equal to the one byte `value`.
fn meta_is(key: MetaKey, value: u8) -> [Expr; 2] {
    [Expr::Meta(key), Expr::Cmp(Operator::Equal, vec![value])]
}

/// The length of `bytes`, which is at most 16.
fn byte_length(bytes: &[u8]) -> u32 {
    u32::try_from(bytes.len()).unwrap_or(u32::MAX)
}

/// `len` bytes at `offset` of header `base` equal to `value`.
fn payload_is(base: u32, offset: u32, value: Vec<u8>) -> [Expr; 2] {
    [
        Expr::Payload {
            base,
            offset,
            len: byte_length(&value),
        },
        Expr::Cmp(Operator::Equal, value),
    ]
}

/// The expressions of an IPv6 neighbour discovery rule, with `destination`
/// matches between the protocol and the hop-limit match.
fn neighbour_discovery(destination: Vec<Expr>) -> Vec<Expr> {
    let mut expressions = Vec::from(meta_is(MetaKey::Nfproto, NFPROTO_IPV6));
    expressions.extend(destination);
    expressions.extend(payload_is(NETWORK_HEADER, IPV6_HOP_LIMIT, vec![255]));
    expressions.extend(meta_is(MetaKey::L4Proto, IPPROTO_ICMPV6));
    expressions.extend([
        Expr::Payload {
            base: TRANSPORT_HEADER,
            offset: 0,
            len: 1,
        },
        Expr::Cmp(Operator::GreatherThanEqual, vec![NEIGHBOUR_SOLICITATION]),
        Expr::Cmp(Operator::LessThanEqual, vec![NEIGHBOUR_ADVERTISEMENT]),
        Expr::Accept,
    ]);
    expressions
}

/// The mask of an IPv6 prefix of `length` bits; a length above 128 is a
/// single host.
fn prefix_mask(length: u8) -> u128 {
    u128::MAX
        .checked_shl(128_u32.saturating_sub(u32::from(length)))
        .unwrap_or(0)
}

/// The expressions of `rule`.
fn rule_expressions(rule: &FirewallRule) -> Vec<Expr> {
    match *rule {
        FirewallRule::AcceptEstablished => vec![
            Expr::CtState,
            Expr::Mask(ESTABLISHED_OR_RELATED.to_ne_bytes().to_vec()),
            Expr::Cmp(Operator::NotEqual, vec![0; 4]),
            Expr::Accept,
        ],
        FirewallRule::AcceptNeighbourDiscovery => neighbour_discovery(Vec::new()),
        FirewallRule::SendNeighbourDiscovery {
            destination,
            length,
        } => {
            let mask = prefix_mask(length);
            neighbour_discovery(vec![
                Expr::Payload {
                    base: NETWORK_HEADER,
                    offset: IPV6_DESTINATION,
                    len: 16,
                },
                Expr::Mask(mask.to_be_bytes().to_vec()),
                Expr::Cmp(
                    Operator::Equal,
                    (u128::from(destination) & mask).to_be_bytes().to_vec(),
                ),
            ])
        }
        FirewallRule::AcceptTcp(endpoint) => {
            let (family, offset, address) = match endpoint.ip() {
                IpAddr::V4(address) => (NFPROTO_IPV4, IPV4_DESTINATION, address.octets().to_vec()),
                IpAddr::V6(address) => (NFPROTO_IPV6, IPV6_DESTINATION, address.octets().to_vec()),
            };
            let mut expressions = Vec::from(meta_is(MetaKey::Nfproto, family));
            expressions.extend(payload_is(NETWORK_HEADER, offset, address));
            expressions.extend(meta_is(MetaKey::L4Proto, IPPROTO_TCP));
            expressions.extend(payload_is(
                TRANSPORT_HEADER,
                TCP_DESTINATION_PORT,
                endpoint.port().to_be_bytes().to_vec(),
            ));
            expressions.push(Expr::Accept);
            expressions
        }
    }
}

/// The nftables expressions of `rule`, ready for `NFTA_RULE_EXPRESSIONS`.
#[must_use]
pub fn encode_firewall_rule(rule: &FirewallRule) -> Vec<ListAttribute<ExpressionAttribute>> {
    rule_expressions(rule)
        .into_iter()
        .map(|expression| ListAttribute::from(expression.encode()))
        .collect()
}

/// One expression reduced to what decides it: its name and its attributes as
/// `(type, value)` pairs, sorted, without the boolean `NFTA_BITWISE_OP`.
type CanonicalExpression = (String, Vec<(u16, Vec<u8>)>);

/// The name and data of every expression, or `None` if an element is not
/// exactly one named expression.
fn elements(
    expressions: &[ListAttribute<ExpressionAttribute>],
) -> Option<Vec<(&str, &Expressions)>> {
    expressions
        .iter()
        .map(|element| match element {
            ListAttribute::Element(attributes) => match attributes.as_slice() {
                [ExpressionAttribute::Name(name), ExpressionAttribute::Data(data)] => {
                    Some((name.as_str(), data))
                }
                _ => None,
            },
            _ => None,
        })
        .collect()
}

/// The canonical form of `elements`.
fn canonical(elements: &[(&str, &Expressions)]) -> Vec<CanonicalExpression> {
    let boolean = (NFTA_BITWISE_OP, NFT_BITWISE_BOOL.to_be_bytes().to_vec());
    elements
        .iter()
        .map(|&(name, data)| {
            let mut bytes = vec![0; data.buffer_len()];
            data.emit(&mut bytes);
            // An attribute that does not parse becomes a type no attribute
            // has (`NLA_TYPE_MASK` clears the top bits of every real one), so
            // the expression can match no encoding.
            let mut attributes: Vec<(u16, Vec<u8>)> = NlasIterator::new(&bytes)
                .map(|attribute| {
                    attribute.map_or((UNPARSED, Vec::new()), |attribute| {
                        (attribute.kind(), attribute.value().to_vec())
                    })
                })
                .filter(|attribute| name != "bitwise" || *attribute != boolean)
                .collect();
            attributes.sort_unstable();
            (name.to_owned(), attributes)
        })
        .collect()
}

/// Every compared value and mask in `elements`: the only places a rule's
/// addresses, prefix lengths and ports appear.
fn values<'a>(elements: &[(&str, &'a Expressions)]) -> Vec<&'a [u8]> {
    elements
        .iter()
        .flat_map(|&(_, data)| match data {
            Expressions::Cmp(attributes) => attributes
                .iter()
                .filter_map(|attribute| match attribute {
                    Cmp::Data(DataAttribute::Value(value)) => Some(value.as_slice()),
                    _ => None,
                })
                .collect(),
            Expressions::Bitwise(attributes) => attributes
                .iter()
                .filter_map(|attribute| match attribute {
                    Bitwise::Mask(DataAttribute::Value(value)) => Some(value.as_slice()),
                    _ => None,
                })
                .collect(),
            _ => Vec::new(),
        })
        .collect()
}

/// The address of four or sixteen `bytes`.
fn address(bytes: &[u8]) -> Option<IpAddr> {
    <[u8; 4]>::try_from(bytes)
        .map(IpAddr::from)
        .or_else(|_| <[u8; 16]>::try_from(bytes).map(IpAddr::from))
        .ok()
}

/// Every rule `values` could encode. A decodable read-back is the encoding
/// of exactly one of them.
fn candidates(values: &[&[u8]]) -> Vec<FirewallRule> {
    let sixteen: Vec<u128> = values
        .iter()
        .filter_map(|value| <[u8; 16]>::try_from(*value).ok())
        .map(u128::from_be_bytes)
        .collect();
    let addresses: Vec<IpAddr> = values.iter().filter_map(|value| address(value)).collect();
    let ports: Vec<u16> = values
        .iter()
        .filter_map(|value| <[u8; 2]>::try_from(*value).ok())
        .map(u16::from_be_bytes)
        .collect();
    let neighbour_discovery = sixteen.iter().flat_map(|&destination| {
        sixteen
            .iter()
            .filter_map(|mask| u8::try_from(mask.count_ones()).ok())
            .map(move |length| FirewallRule::SendNeighbourDiscovery {
                destination: Ipv6Addr::from(destination),
                length,
            })
    });
    let tcp = addresses.iter().flat_map(|&address| {
        ports
            .iter()
            .map(move |&port| FirewallRule::AcceptTcp(SocketAddr::new(address, port)))
    });
    [
        FirewallRule::AcceptEstablished,
        FirewallRule::AcceptNeighbourDiscovery,
    ]
    .into_iter()
    .chain(neighbour_discovery)
    .chain(tcp)
    .collect()
}

/// The rule whose encoding `expressions` is.
///
/// # Errors
/// Fails if `expressions` is not, up to attribute order and the boolean
/// `NFTA_BITWISE_OP`, the encoding of any rule.
pub fn decode_firewall_rule(
    expressions: &[ListAttribute<ExpressionAttribute>],
) -> Result<FirewallRule, UndecodableRule> {
    let observed = elements(expressions).ok_or(UndecodableRule)?;
    let wanted = canonical(&observed);
    candidates(&values(&observed))
        .into_iter()
        .find(|rule| {
            let encoded = encode_firewall_rule(rule);
            elements(&encoded).is_some_and(|encoded| canonical(&encoded) == wanted)
        })
        .ok_or(UndecodableRule)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests;
