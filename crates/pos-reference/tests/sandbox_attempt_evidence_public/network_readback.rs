//! KOE1 `network-readback` (ADR-069 R14 §3.1): the R14 §4.1 to §4.4
//! vectors, and the R14 §3.5 rule 4 checks that the record alone decides.
//! The checks that follow the mode and the planned endpoints are in
//! `bundle`.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use ciborium::value::Value;
use pos_reference::sandbox_provider_protocol::{
    KernelObservationEvidence, KernelObservationEvidenceFields, KernelObservationStatus,
    LocalNetworkReadback, ObservedKernelState, ReadbackFirewallBase, ReadbackFirewallChain,
    ReadbackFirewallHook, ReadbackFirewallPolicy, ReadbackFirewallRule, ReadbackPrefix,
    ReadbackRoute, ReadbackVethEnd, SandboxProviderProtocolError as ProtocolError,
};

use super::observed::{decode, digest, namespace, vector_a_fields, vector_observation};
use super::oracle::{
    edit, encode, filled, integer, rejects_every_retyped_node, set, text, unhex, unsigned, with,
    wrapped_digest, TestResult,
};
use super::vectors::{
    KOE1_A, KOE1_A_DIGEST, KOE1_A_UNSIGNED, KOE1_C, KOE1_C_DIGEST, KOE1_C_READBACK,
    KOE1_C_SAU1_EVENT_11_AUTHORITY, KOE1_C_UNSIGNED, KOE1_D, KOE1_D_DIGEST, KOE1_D_UNSIGNED,
    KOE1_N1, KOE1_N1_DIGEST,
};

/// The path of `network-readback` in a KOE1's unsigned fields.
pub(super) const READBACK: [usize; 2] = [7, 12];

/// The R14 §4.3 planned endpoints.
pub(super) const fn vector_d_endpoints() -> [SocketAddr; 2] {
    [
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)), 443),
        SocketAddr::new(
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 5)),
            8443,
        ),
    ]
}

/// `10.200.0.<host>`, in the R14 §4.2 range `10.200.0.0/24`.
const fn ipv4(host: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(10, 200, 0, host))
}

/// `fd70:6967:6c6f::<host>`, in the R14 §4.2 range.
const fn ipv6(host: u16) -> IpAddr {
    IpAddr::V6(Ipv6Addr::new(0xfd70, 0x6967, 0x6c6f, 0, 0, 0, 0, host))
}

const fn prefix(address: IpAddr, length: u8) -> ReadbackPrefix {
    ReadbackPrefix { address, length }
}

const fn connected(destination: ReadbackPrefix) -> ReadbackRoute {
    ReadbackRoute {
        destination,
        gateway: None,
    }
}

fn chain(
    name: &str,
    hook: ReadbackFirewallHook,
    rules: Vec<ReadbackFirewallRule>,
) -> ReadbackFirewallChain {
    ReadbackFirewallChain {
        name: name.to_owned(),
        base: Some(ReadbackFirewallBase {
            hook,
            priority: 0,
            policy: ReadbackFirewallPolicy::Drop,
        }),
        rules,
    }
}

fn veth(index: u32, name: &str, peer_index: u32, peer_netnsid: u32) -> ReadbackVethEnd {
    ReadbackVethEnd {
        index,
        name: name.to_owned(),
        peer_index,
        peer_netnsid,
    }
}

/// The R14 §4.2 KOE1-C readback, written out from the R14 text: slot 3
/// of `10.200.0.0/24` and `fd70:6967:6c6f::/64`, generation 7.
fn vector_c_readback() -> LocalNetworkReadback {
    let solicited = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 1, 0xff00, 0);
    let network = Ipv6Addr::new(0xfd70, 0x6967, 0x6c6f, 0, 0, 0, 0, 6);
    LocalNetworkReadback {
        namespace: namespace(4_026_532_300),
        namespace_netnsid: 4,
        host_netnsid: 0,
        loopback_index: 1,
        inner: veth(2, "piglor-n3", 57, 0),
        host: veth(57, "piglor-h3", 2, 4),
        inner_addresses: vec![prefix(ipv4(14), 30), prefix(ipv6(7), 127)],
        host_addresses: vec![prefix(ipv4(13), 30), prefix(ipv6(6), 127)],
        routes: vec![
            connected(prefix(ipv4(12), 30)),
            connected(prefix(ipv6(6), 127)),
        ],
        firewall_generation: 7,
        chains: vec![
            chain(
                "input",
                ReadbackFirewallHook::Input,
                vec![
                    ReadbackFirewallRule::AcceptEstablished,
                    ReadbackFirewallRule::AcceptNeighbourDiscovery,
                ],
            ),
            chain(
                "output",
                ReadbackFirewallHook::Output,
                vec![
                    ReadbackFirewallRule::SendNeighbourDiscovery {
                        destination: solicited,
                        length: 104,
                    },
                    ReadbackFirewallRule::SendNeighbourDiscovery {
                        destination: network,
                        length: 128,
                    },
                ],
            ),
            chain("forward", ReadbackFirewallHook::Forward, Vec::new()),
        ],
        egress_allowed: Vec::new(),
        egress_masqueraded: Vec::new(),
    }
}

/// The R14 §4.3 KOE1-D readback: KOE1-C with two planned endpoints.
fn vector_d_readback() -> LocalNetworkReadback {
    let [web, ipv6_endpoint] = vector_d_endpoints();
    let mut readback = vector_c_readback();
    readback.routes = vec![
        connected(prefix(ipv4(12), 30)),
        ReadbackRoute {
            destination: prefix(web.ip(), 32),
            gateway: Some(ipv4(13)),
        },
        ReadbackRoute {
            destination: prefix(ipv6_endpoint.ip(), 128),
            gateway: Some(ipv6(6)),
        },
        connected(prefix(ipv6(6), 127)),
    ];
    readback.chains[1].rules.extend([
        ReadbackFirewallRule::AcceptTcp(web),
        ReadbackFirewallRule::AcceptTcp(ipv6_endpoint),
    ]);
    readback.egress_allowed = vec![web];
    readback.egress_masqueraded = vec![web];
    readback
}

fn local_fields(readback: LocalNetworkReadback) -> TestResult<KernelObservationEvidenceFields> {
    Ok(KernelObservationEvidenceFields {
        status: KernelObservationStatus::Observed {
            ready1_digest: [0x44; 32],
            observation: Box::new(ObservedKernelState {
                network_readback: Some(readback),
                ..vector_observation()
            }),
        },
        ..vector_a_fields()?
    })
}

#[test]
fn r14_koe1_vectors_decode_and_encode_byte_for_byte() -> TestResult {
    for (vector, unsigned_prefix, self_digest, fields) in [
        (KOE1_A, KOE1_A_UNSIGNED, KOE1_A_DIGEST, vector_a_fields()?),
        (
            KOE1_C,
            KOE1_C_UNSIGNED,
            KOE1_C_DIGEST,
            local_fields(vector_c_readback())?,
        ),
        (
            KOE1_D,
            KOE1_D_UNSIGNED,
            KOE1_D_DIGEST,
            local_fields(vector_d_readback())?,
        ),
    ] {
        let bytes = unhex(vector)?;
        let decoded = KernelObservationEvidence::from_canonical_cbor(&bytes)?;
        assert_eq!(decoded.fields(), &fields);
        assert_eq!(decoded.digest(), digest(self_digest)?);
        assert_eq!(decoded.canonical_bytes(), bytes.as_slice());
        let encoded = KernelObservationEvidence::new(&fields)?;
        assert_eq!(encoded, decoded);
        // The record is `[unsigned, self_digest]`.
        let unsigned_prefix = unhex(unsigned_prefix)?;
        assert_eq!(
            &bytes[1..=unsigned_prefix.len()],
            unsigned_prefix.as_slice()
        );
        assert_eq!(wrapped_digest(&bytes)?, decoded.digest());
    }
    let readback = super::oracle::at(&mut unsigned(&unhex(KOE1_C)?)?, &READBACK)?.clone();
    assert_eq!(encode(&readback)?, unhex(KOE1_C_READBACK)?);
    // The record is at most 597 bytes.
    assert_eq!(unhex(KOE1_C)?.len(), 597);
    Ok(())
}

#[test]
fn r14_koe1_c_digest_is_the_sau1_event_11_observed_state_digest() -> TestResult {
    let observed = KernelObservationEvidence::from_canonical_cbor(&unhex(KOE1_C)?)?;
    let authority = Value::Array(vec![
        filled(0x22, 32),
        filled(0x44, 32),
        Value::Bytes(observed.digest().to_vec()),
    ]);
    assert_eq!(encode(&authority)?, unhex(KOE1_C_SAU1_EVENT_11_AUTHORITY)?);
    Ok(())
}

/// The list at `path` of a record's unsigned fields.
pub(super) fn list_at(bytes: &[u8], path: &[usize]) -> TestResult<Vec<Value>> {
    Ok(super::oracle::at(&mut unsigned(bytes)?, path)?
        .as_array()
        .cloned()
        .ok_or("not a list")?)
}

/// The path of one `network-readback` field.
fn at(path: &[usize]) -> Vec<usize> {
    READBACK.iter().chain(path).copied().collect()
}

/// KOE1-C with one `network-readback` field replaced.
fn koe1_c(path: &[usize], value: Value) -> TestResult<Vec<u8>> {
    with(&unhex(KOE1_C)?, &at(path), value)
}

/// KOE1-C with several `network-readback` fields replaced.
fn koe1_c_with(changes: Vec<(Vec<usize>, Value)>) -> TestResult<Vec<u8>> {
    edit(&unhex(KOE1_C)?, |fields| {
        for (path, value) in changes {
            set(fields, &at(&path), value)?;
        }
        Ok(())
    })
}

fn negative(value: i64) -> Value {
    Value::Integer(value.into())
}

fn bytes(value: &[u8]) -> Value {
    Value::Bytes(value.to_vec())
}

fn address(address: IpAddr) -> Value {
    match address {
        IpAddr::V4(address) => bytes(&address.octets()),
        IpAddr::V6(address) => bytes(&address.octets()),
    }
}

fn prefix_value(prefix: ReadbackPrefix) -> Value {
    Value::Array(vec![
        address(prefix.address),
        integer(u64::from(prefix.length)),
    ])
}

const fn array(values: Vec<Value>) -> Value {
    Value::Array(values)
}

/// The R14 §4.4 KOE1-N1: KOE1-C whose attempt namespace is the unit's
/// network namespace. It decodes as CBOR with the stated self-digest, and
/// rule 4 rejects it.
#[test]
fn r14_koe1_n1_is_the_unit_network_namespace_and_rejected() -> TestResult {
    let bytes = unhex(KOE1_N1)?;
    assert_eq!(wrapped_digest(&bytes)?, digest(KOE1_N1_DIGEST)?);
    assert_eq!(koe1_c(&[0, 1], integer(4_026_532_006))?, bytes);
    assert_eq!(decode(&bytes), Err(ProtocolError::InconsistentFields));
    // The provider's network namespace is refused in the same way.
    assert_eq!(
        decode(&koe1_c(&[0, 1], integer(4_026_531_840))?),
        Err(ProtocolError::InconsistentFields)
    );
    // Any other namespace of the unit is not the attempt namespace's type.
    assert_eq!(decode(&koe1_c(&[0, 1], integer(4_026_532_005))?), Ok(()));
    Ok(())
}

#[test]
fn r14_network_readback_identities_and_names_are_bounded() -> TestResult {
    for (path, value, expected) in [
        // (b) and the other NSIDs: a negative or a too-large NSID.
        (vec![2], negative(-1), Err(ProtocolError::FieldOutOfBounds)),
        (vec![1], negative(-1), Err(ProtocolError::FieldOutOfBounds)),
        (
            vec![1],
            integer(2_147_483_648),
            Err(ProtocolError::FieldOutOfBounds),
        ),
        (
            vec![4, 3],
            negative(-1),
            Err(ProtocolError::FieldOutOfBounds),
        ),
        // Interface indices are positive `s32`.
        (vec![3], integer(0), Err(ProtocolError::FieldOutOfBounds)),
        (
            vec![3],
            integer(2_147_483_648),
            Err(ProtocolError::FieldOutOfBounds),
        ),
        (vec![3], integer(2_147_483_647), Ok(())),
        (vec![4, 0], integer(0), Err(ProtocolError::FieldOutOfBounds)),
        (
            vec![5, 2],
            negative(-2),
            Err(ProtocolError::InvalidEncoding),
        ),
        // (g) the generation is a `u32`.
        (
            vec![9],
            integer(1 << 32),
            Err(ProtocolError::FieldOutOfBounds),
        ),
        (vec![9], integer(u64::from(u32::MAX)), Ok(())),
        // Slot link names.
        (
            vec![4, 1],
            text("piglor-n"),
            Err(ProtocolError::FieldOutOfBounds),
        ),
        (
            vec![4, 1],
            text("piglor-n03"),
            Err(ProtocolError::FieldOutOfBounds),
        ),
        (
            vec![4, 1],
            text("piglor-n100000"),
            Err(ProtocolError::FieldOutOfBounds),
        ),
        (
            vec![4, 1],
            text("piglor-n3a"),
            Err(ProtocolError::FieldOutOfBounds),
        ),
        (
            vec![4, 1],
            text("piglor-x3"),
            Err(ProtocolError::FieldOutOfBounds),
        ),
        (
            vec![4, 1],
            text("pigler-n3"),
            Err(ProtocolError::FieldOutOfBounds),
        ),
    ] {
        assert_eq!(decode(&koe1_c(&path, value)?), expected, "{path:?}");
    }
    Ok(())
}

#[test]
fn r14_network_readback_addresses_and_lists_are_bounded() -> TestResult {
    for (path, value, expected) in [
        (
            vec![6, 0, 0],
            bytes(&[10, 200, 0, 14, 0]),
            Err(ProtocolError::FieldOutOfBounds),
        ),
        (
            vec![6, 0, 1],
            integer(33),
            Err(ProtocolError::FieldOutOfBounds),
        ),
        (
            vec![6, 1, 1],
            integer(129),
            Err(ProtocolError::FieldOutOfBounds),
        ),
        (
            vec![8, 0, 1],
            bytes(&[10, 200, 0]),
            Err(ProtocolError::FieldOutOfBounds),
        ),
        // List lengths.
        (
            vec![6],
            array(vec![prefix_value(prefix(ipv4(14), 30))]),
            Err(ProtocolError::FieldOutOfBounds),
        ),
        (
            vec![8],
            array(vec![prefix_value(prefix(ipv4(12), 30))]),
            Err(ProtocolError::FieldOutOfBounds),
        ),
    ] {
        assert_eq!(decode(&koe1_c(&path, value)?), expected, "{path:?}");
    }
    Ok(())
}

#[test]
fn r14_network_readback_chains_are_bounded() -> TestResult {
    let long_name = "f".repeat(64);
    for (path, value, expected) in [
        (
            vec![10, 0, 0],
            text(""),
            Err(ProtocolError::FieldOutOfBounds),
        ),
        (vec![10, 2, 0], text(&long_name), Ok(())),
        (
            vec![10, 2, 0],
            text(&format!("{long_name}f")),
            Err(ProtocolError::FieldOutOfBounds),
        ),
        (
            vec![10, 0, 1, 0],
            integer(3),
            Err(ProtocolError::FieldOutOfBounds),
        ),
        (
            vec![10, 0, 1, 2],
            integer(2),
            Err(ProtocolError::FieldOutOfBounds),
        ),
        (vec![10, 0, 1, 1], negative(i64::from(i32::MIN)), Ok(())),
        (
            vec![10, 0, 1, 1],
            negative(i64::from(i32::MIN) - 1),
            Err(ProtocolError::FieldOutOfBounds),
        ),
        (
            vec![10, 0, 1, 1],
            integer(1 << 31),
            Err(ProtocolError::FieldOutOfBounds),
        ),
        (vec![10, 0, 1], Value::Null, Ok(())),
        (
            vec![10, 0, 2, 0],
            array(vec![]),
            Err(ProtocolError::FieldOutOfBounds),
        ),
        (
            vec![10, 0, 2, 0],
            array(vec![integer(4)]),
            Err(ProtocolError::FieldOutOfBounds),
        ),
        (
            vec![10, 0, 2, 0],
            array(vec![integer(0), integer(0)]),
            Err(ProtocolError::InvalidEncoding),
        ),
        (
            vec![10, 0, 2, 0],
            array(vec![integer(1), integer(0), integer(0)]),
            Err(ProtocolError::InvalidEncoding),
        ),
        (
            vec![10, 0, 2, 0],
            array(vec![integer(2), integer(0), integer(0), integer(0)]),
            Err(ProtocolError::FieldOutOfBounds),
        ),
        (
            vec![10, 1, 2, 0, 1],
            bytes(&[0xff, 2, 0, 0]),
            Err(ProtocolError::FieldOutOfBounds),
        ),
        (
            vec![10, 1, 2, 0, 2],
            integer(129),
            Err(ProtocolError::FieldOutOfBounds),
        ),
        (vec![10, 1, 2, 0, 2], integer(128), Ok(())),
    ] {
        assert_eq!(decode(&koe1_c(&path, value)?), expected, "{path:?}");
    }
    // Every node retyped is refused, and so is a record without the field.
    rejects_every_retyped_node(&unhex(KOE1_C)?, decode)?;
    rejects_every_retyped_node(&unhex(KOE1_D)?, decode)?;
    let observation = list_at(&unhex(KOE1_A)?, &[7])?;
    let short = with(&unhex(KOE1_A)?, &[7], array(observation[..12].to_vec()))?;
    assert_eq!(decode(&short), Err(ProtocolError::InvalidEncoding));
    Ok(())
}

#[test]
fn r14_network_readback_endpoint_bounds() -> TestResult {
    let tcp = |address: Value, port: u64| array(vec![integer(3), address, integer(port)]);
    let web = bytes(&[203, 0, 113, 10]);
    let endpoint = |port: u64| array(vec![web.clone(), integer(port)]);
    for (path, value, expected) in [
        (
            vec![10, 1, 2, 2],
            tcp(web.clone(), 0),
            Err(ProtocolError::FieldOutOfBounds),
        ),
        (
            vec![10, 1, 2, 2],
            tcp(web.clone(), 65_536),
            Err(ProtocolError::FieldOutOfBounds),
        ),
        (
            vec![10, 1, 2, 2],
            tcp(bytes(&[203, 0, 113]), 443),
            Err(ProtocolError::FieldOutOfBounds),
        ),
        (vec![10, 1, 2, 2], tcp(web.clone(), 65_535), Ok(())),
        (
            vec![11, 0],
            endpoint(0),
            Err(ProtocolError::FieldOutOfBounds),
        ),
        (
            vec![12, 0],
            endpoint(65_536),
            Err(ProtocolError::FieldOutOfBounds),
        ),
        (vec![12, 0], endpoint(1), Ok(())),
    ] {
        assert_eq!(
            decode(&with(&unhex(KOE1_D)?, &at(&path), value)?),
            expected,
            "{path:?}"
        );
    }
    Ok(())
}

#[test]
fn r14_network_readback_lists_are_sorted_and_unique() -> TestResult {
    for index in [6, 7, 8, 10, 11, 12] {
        let entries = list_at(&unhex(KOE1_D)?, &at(&[index]))?;
        let mut reversed = entries.clone();
        reversed.reverse();
        let mut duplicated = entries.clone();
        duplicated.insert(0, entries[0].clone());
        // A one-entry list is its own reversal.
        let variants = if entries.len() > 1 {
            vec![reversed, duplicated]
        } else {
            vec![duplicated]
        };
        for change in variants {
            let expected = if index == 6 || index == 7 || index == 10 {
                // A fixed-length list grown by a duplicate is out of bounds.
                if change.len() == entries.len() {
                    Err(ProtocolError::NonCanonicalOrder)
                } else {
                    Err(ProtocolError::FieldOutOfBounds)
                }
            } else {
                Err(ProtocolError::NonCanonicalOrder)
            };
            let changed = with(&unhex(KOE1_D)?, &at(&[index]), array(change))?;
            assert_eq!(decode(&changed), expected, "list {index}");
        }
    }
    // (c) reversed routes in KOE1-C.
    let routes = koe1_c_with(vec![(
        vec![8],
        array(vec![
            array(vec![prefix_value(prefix(ipv6(6), 127)), Value::Null]),
            array(vec![prefix_value(prefix(ipv4(12), 30)), Value::Null]),
        ]),
    )])?;
    assert_eq!(decode(&routes), Err(ProtocolError::NonCanonicalOrder));
    // A fourth chain is out of bounds, and the rules keep their order.
    let mut chains = list_at(&unhex(KOE1_C)?, &at(&[10]))?;
    chains.push(array(vec![text("zzzzzzzz"), Value::Null, array(vec![])]));
    let chains = koe1_c(&[10], array(chains))?;
    assert_eq!(decode(&chains), Err(ProtocolError::FieldOutOfBounds));
    let mut reordered = list_at(&unhex(KOE1_D)?, &at(&[10, 1, 2]))?;
    reordered.reverse();
    let changed = with(&unhex(KOE1_D)?, &at(&[10, 1, 2]), array(reordered))?;
    assert_eq!(decode(&changed), Ok(()));
    Ok(())
}

#[test]
fn r14_rule_4_cross_links_and_link_names() -> TestResult {
    for (changes, expected) in [
        // (a) a swapped `inner.peer-index`, and each other cross-link.
        (
            vec![(vec![4, 2], integer(58))],
            Err(ProtocolError::InconsistentFields),
        ),
        (
            vec![(vec![5, 2], integer(3))],
            Err(ProtocolError::InconsistentFields),
        ),
        (
            vec![(vec![4, 3], integer(1))],
            Err(ProtocolError::InconsistentFields),
        ),
        (
            vec![(vec![5, 3], integer(5))],
            Err(ProtocolError::InconsistentFields),
        ),
        (
            vec![
                (vec![1], integer(2_147_483_647)),
                (vec![5, 3], integer(2_147_483_647)),
            ],
            Ok(()),
        ),
        // The names are `piglor-n<k>` and `piglor-h<k>` for one `k`.
        (
            vec![(vec![4, 1], text("piglor-h3"))],
            Err(ProtocolError::InconsistentFields),
        ),
        (
            vec![(vec![5, 1], text("piglor-n3"))],
            Err(ProtocolError::InconsistentFields),
        ),
        (
            vec![(vec![4, 1], text("piglor-n4"))],
            Err(ProtocolError::InconsistentFields),
        ),
        (
            vec![
                (vec![4, 1], text("piglor-n99999")),
                (vec![5, 1], text("piglor-h99999")),
            ],
            Ok(()),
        ),
        (
            vec![
                (vec![4, 1], text("piglor-n0")),
                (vec![5, 1], text("piglor-h0")),
            ],
            Ok(()),
        ),
    ] {
        let description = format!("{changes:?}");
        assert_eq!(decode(&koe1_c_with(changes)?), expected, "{description}");
    }
    Ok(())
}

/// The host and inner addresses as `[ipv4, ipv6]` prefix lists.
fn addresses(host: [ReadbackPrefix; 2], inner: [ReadbackPrefix; 2]) -> Vec<(Vec<usize>, Value)> {
    vec![
        (vec![7], array(host.map(prefix_value).to_vec())),
        (vec![6], array(inner.map(prefix_value).to_vec())),
    ]
}

fn v4(octets: [u8; 4]) -> IpAddr {
    IpAddr::V4(Ipv4Addr::from(octets))
}

fn v6(segments: [u16; 8]) -> IpAddr {
    IpAddr::V6(Ipv6Addr::from(segments))
}

/// One address case: the changes, whether rule 4 accepts them, and why.
type AddressCase = (Vec<(Vec<usize>, Value)>, bool, &'static str);

/// Single-condition cases of one host or inner prefix over KOE1-C.
fn prefix_cases() -> Vec<AddressCase> {
    let host = [prefix(ipv4(13), 30), prefix(ipv6(6), 127)];
    let inner = [prefix(ipv4(14), 30), prefix(ipv6(7), 127)];
    let fd = |host: u16| v6([0xfd70, 0x6967, 0x6c6f, 0, 0, 0, 0, host]);
    let changed = |end: [ReadbackPrefix; 2], index: usize, value| {
        let mut end = end;
        end[index] = value;
        end
    };
    [
        (
            host,
            changed(inner, 0, prefix(ipv4(15), 30)),
            "inner IPv4 not N+2",
        ),
        (
            host,
            changed(inner, 1, prefix(fd(8), 127)),
            "inner IPv6 not M+1",
        ),
        (
            host,
            changed(inner, 0, prefix(ipv4(14), 29)),
            "inner IPv4 not /30",
        ),
        (
            host,
            changed(inner, 1, prefix(ipv6(7), 126)),
            "inner IPv6 not /127",
        ),
        (
            changed(host, 0, prefix(ipv4(13), 29)),
            inner,
            "host IPv4 not /30",
        ),
        (
            changed(host, 1, prefix(ipv6(6), 128)),
            inner,
            "host IPv6 not /127",
        ),
        (
            changed(host, 1, prefix(ipv4(17), 30)),
            inner,
            "two host IPv4 addresses",
        ),
        (
            changed(host, 0, prefix(v4([0, 0, 0, 0]), 30)),
            inner,
            "a host address below its network",
        ),
    ]
    .into_iter()
    .map(|(host, inner, case)| (addresses(host, inner), false, case))
    .collect()
}

/// Single-condition slot cases over KOE1-C.
fn address_cases() -> Vec<AddressCase> {
    const ULA: [u16; 8] = [0xfd70, 0x6967, 0x6c6f, 0, 0, 0, 0, 6];
    let slot = |ipv4_network: [u8; 4], ipv6_network: [u16; 8]| {
        let [a, b, c, d] = ipv4_network;
        let mut inner6 = ipv6_network;
        inner6[7] += 1;
        addresses(
            [
                prefix(v4([a, b, c, d + 1]), 30),
                prefix(v6(ipv6_network), 127),
            ],
            [prefix(v4([a, b, c, d + 2]), 30), prefix(v6(inner6), 127)],
        )
    };
    let mut other_ula = ULA;
    other_ula[0] = 0xfc00;
    let mut global = ULA;
    global[0] = 0x2001;
    let mut odd = ULA;
    odd[7] = 7;
    vec![
        (slot([10, 200, 0, 12], ULA), true, "the vector's slot"),
        (slot([172, 16, 0, 0], ULA), true, "172.16/12"),
        (slot([192, 168, 255, 252], ULA), true, "192.168/16"),
        (slot([10, 200, 0, 12], other_ula), true, "fc00::/8"),
        (
            slot([10, 200, 0, 13], ULA),
            false,
            "an unaligned IPv4 network",
        ),
        (slot([11, 0, 0, 12], ULA), false, "a public IPv4 network"),
        (slot([172, 32, 0, 12], ULA), false, "outside 172.16/12"),
        (
            slot([10, 200, 0, 12], global),
            false,
            "a global IPv6 network",
        ),
        (
            slot([10, 200, 0, 12], odd),
            false,
            "an unaligned IPv6 network",
        ),
    ]
}

#[test]
fn r14_rule_4_addresses_are_one_slots() -> TestResult {
    for (changes, accepted, case) in address_cases().into_iter().chain(prefix_cases()) {
        let expected = if accepted {
            Ok(())
        } else {
            Err(ProtocolError::InconsistentFields)
        };
        assert_eq!(decode(&koe1_c_with(changes)?), expected, "{case}");
    }
    Ok(())
}

#[test]
fn r14_the_encoder_applies_the_decoder_rules() -> TestResult {
    let mut swapped = vector_c_readback();
    swapped.inner.peer_index = 58;
    assert_eq!(
        KernelObservationEvidence::new(&local_fields(swapped)?),
        Err(ProtocolError::InconsistentFields)
    );
    let mut unsorted = vector_d_readback();
    unsorted.routes.reverse();
    assert_eq!(
        KernelObservationEvidence::new(&local_fields(unsorted)?),
        Err(ProtocolError::NonCanonicalOrder)
    );
    let mut regular = vector_c_readback();
    regular.chains[2].base = None;
    let encoded = KernelObservationEvidence::new(&local_fields(regular.clone())?)?;
    assert_eq!(encoded.fields(), &local_fields(regular)?);
    Ok(())
}
