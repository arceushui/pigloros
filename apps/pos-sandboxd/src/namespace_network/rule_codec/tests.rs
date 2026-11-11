use std::{error::Error, net::Ipv4Addr};

use netlink_packet_core::Parseable;

use super::*;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

/// The hand-encoded `ct state` load into register 1: `NFTA_CT_DREG` 1 and
/// `NFTA_CT_KEY` `NFT_CT_STATE`, in the order the kernel reports them.
const CT_STATE: [u8; 32] = [
    0x20, 0x00, 0x01, 0x80, 0x07, 0x00, 0x01, 0x00, 0x63, 0x74, 0x00, 0x00, 0x14, 0x00, 0x02, 0x80,
    0x08, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x01, 0x08, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
];

/// `ct state established,related accept` as the provider emits it, with
/// `NLA_F_NESTED` on every nested attribute. The four state-mask bytes at
/// [`ESTABLISHED_MASK`] are zero here; [`with_state_mask`] fills them in host
/// byte order, as the kernel loads conntrack state.
const ESTABLISHED: [u8; 192] = [
    0x20, 0x00, 0x01, 0x80, 0x07, 0x00, 0x01, 0x00, 0x63, 0x74, 0x00, 0x00, 0x14, 0x00, 0x02, 0x80,
    0x08, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x01, 0x08, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x44, 0x00, 0x01, 0x80, 0x0c, 0x00, 0x01, 0x00, 0x62, 0x69, 0x74, 0x77, 0x69, 0x73, 0x65, 0x00,
    0x34, 0x00, 0x02, 0x80, 0x08, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x01, 0x08, 0x00, 0x02, 0x00,
    0x00, 0x00, 0x00, 0x01, 0x08, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x04, 0x0c, 0x00, 0x04, 0x80,
    0x08, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x05, 0x80, 0x08, 0x00, 0x01, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x2c, 0x00, 0x01, 0x80, 0x08, 0x00, 0x01, 0x00, 0x63, 0x6d, 0x70, 0x00,
    0x20, 0x00, 0x02, 0x80, 0x08, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x01, 0x08, 0x00, 0x02, 0x00,
    0x00, 0x00, 0x00, 0x01, 0x0c, 0x00, 0x03, 0x80, 0x08, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x30, 0x00, 0x01, 0x80, 0x0e, 0x00, 0x01, 0x00, 0x69, 0x6d, 0x6d, 0x65, 0x64, 0x69, 0x61, 0x74,
    0x65, 0x00, 0x00, 0x00, 0x1c, 0x00, 0x02, 0x80, 0x08, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x10, 0x00, 0x02, 0x80, 0x0c, 0x00, 0x02, 0x80, 0x08, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x01,
];

/// The same rule as a kernel since 5.6 dumps it: nests without
/// `NLA_F_NESTED`, and `NFTA_BITWISE_OP` `NFT_BITWISE_BOOL` in the `bitwise`.
/// Its state mask lies at [`KERNEL_ESTABLISHED_MASK`].
const KERNEL_ESTABLISHED: [u8; 200] = [
    0x20, 0x00, 0x01, 0x00, 0x07, 0x00, 0x01, 0x00, 0x63, 0x74, 0x00, 0x00, 0x14, 0x00, 0x02, 0x00,
    0x08, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x01, 0x08, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x4c, 0x00, 0x01, 0x00, 0x0c, 0x00, 0x01, 0x00, 0x62, 0x69, 0x74, 0x77, 0x69, 0x73, 0x65, 0x00,
    0x3c, 0x00, 0x02, 0x00, 0x08, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x01, 0x08, 0x00, 0x02, 0x00,
    0x00, 0x00, 0x00, 0x01, 0x08, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x04, 0x08, 0x00, 0x06, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x04, 0x00, 0x08, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x0c, 0x00, 0x05, 0x00, 0x08, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2c, 0x00, 0x01, 0x00,
    0x08, 0x00, 0x01, 0x00, 0x63, 0x6d, 0x70, 0x00, 0x20, 0x00, 0x02, 0x00, 0x08, 0x00, 0x01, 0x00,
    0x00, 0x00, 0x00, 0x01, 0x08, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x01, 0x0c, 0x00, 0x03, 0x00,
    0x08, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x30, 0x00, 0x01, 0x00, 0x0e, 0x00, 0x01, 0x00,
    0x69, 0x6d, 0x6d, 0x65, 0x64, 0x69, 0x61, 0x74, 0x65, 0x00, 0x00, 0x00, 0x1c, 0x00, 0x02, 0x00,
    0x08, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x02, 0x00, 0x0c, 0x00, 0x02, 0x00,
    0x08, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x01,
];

/// Where the state mask lies in [`ESTABLISHED`].
const ESTABLISHED_MASK: usize = 84;
/// Where the state mask lies in [`KERNEL_ESTABLISHED`].
const KERNEL_ESTABLISHED_MASK: usize = 92;

/// `golden` with the `established,related` state mask at `at`, in host byte
/// order.
fn with_state_mask(golden: &[u8], at: usize) -> Vec<u8> {
    let mut bytes = golden.to_vec();
    bytes[at..at + 4].copy_from_slice(&0b110_u32.to_ne_bytes());
    bytes
}

fn emit(expressions: &[ListAttribute<ExpressionAttribute>]) -> Vec<u8> {
    let mut bytes = vec![0; expressions.buffer_len()];
    expressions.emit(&mut bytes);
    bytes
}

fn parse(bytes: &[u8]) -> TestResult<Vec<ListAttribute<ExpressionAttribute>>> {
    NlasIterator::new(bytes)
        .map(|element| Ok(ListAttribute::parse(&element?)?))
        .collect()
}

const SOLICITED_NODE: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 1, 0xff00, 0);

fn rules() -> [FirewallRule; 7] {
    [
        FirewallRule::AcceptEstablished,
        FirewallRule::AcceptNeighbourDiscovery,
        FirewallRule::SendNeighbourDiscovery {
            destination: SOLICITED_NODE,
            length: 104,
        },
        FirewallRule::SendNeighbourDiscovery {
            destination: Ipv6Addr::new(0xfd00, 0x77, 0, 0, 0, 0, 0, 6),
            length: 128,
        },
        FirewallRule::SendNeighbourDiscovery {
            destination: Ipv6Addr::new(0xfd00, 0x77, 0, 0, 0, 0, 0, 0),
            length: 61,
        },
        FirewallRule::AcceptTcp(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)),
            8443,
        )),
        FirewallRule::AcceptTcp(SocketAddr::new(
            IpAddr::V6(Ipv6Addr::new(0xfd12, 0, 0, 0, 0, 0, 0, 5)),
            443,
        )),
    ]
}

/// `rule`'s encoding with element `index` replaced by `expression`.
fn replaced(
    rule: &FirewallRule,
    index: usize,
    expression: Expressions,
) -> Vec<ListAttribute<ExpressionAttribute>> {
    let mut expressions = encode_firewall_rule(rule);
    expressions[index] = ListAttribute::from(expression);
    expressions
}

#[test]
fn the_conntrack_state_load_matches_its_golden_bytes() {
    let expressions = encode_firewall_rule(&FirewallRule::AcceptEstablished);
    assert_eq!(emit(&expressions[..1]), CT_STATE);
    assert_eq!(
        emit(&expressions),
        with_state_mask(&ESTABLISHED, ESTABLISHED_MASK)
    );
}

#[test]
fn the_kernel_dump_of_the_established_rule_decodes() -> TestResult {
    for bytes in [
        with_state_mask(&ESTABLISHED, ESTABLISHED_MASK),
        with_state_mask(&KERNEL_ESTABLISHED, KERNEL_ESTABLISHED_MASK),
    ] {
        assert_eq!(
            decode_firewall_rule(&parse(&bytes)?),
            Ok(FirewallRule::AcceptEstablished)
        );
    }
    Ok(())
}

#[test]
fn every_rule_decodes_from_its_emitted_bytes() -> TestResult {
    for rule in rules() {
        let expressions = parse(&emit(&encode_firewall_rule(&rule)))?;
        assert_eq!(decode_firewall_rule(&expressions), Ok(rule), "{rule:?}");
    }
    Ok(())
}

#[test]
fn protocol_matches_precede_the_matches_that_depend_on_them() {
    let names = |rule: &FirewallRule| -> Vec<String> {
        encode_firewall_rule(rule)
            .iter()
            .map(|element| match element {
                ListAttribute::Element(attributes) => match attributes.first() {
                    Some(ExpressionAttribute::Name(name)) => name.clone(),
                    _ => String::new(),
                },
                _ => String::new(),
            })
            .collect()
    };
    let [_, receive, send, ..] = rules();
    for rule in [receive, send] {
        let names = names(&rule);
        assert_eq!(names[..2], ["meta", "cmp"], "{rule:?}");
        assert_eq!(names.last().map(String::as_str), Some("immediate"));
    }
    assert_eq!(
        names(&rules()[5]),
        [
            "meta",
            "cmp",
            "payload",
            "cmp",
            "meta",
            "cmp",
            "payload",
            "cmp",
            "immediate"
        ]
    );
}

#[test]
fn attributes_in_another_order_decode() {
    let rule = rules()[5];
    let expressions = replaced(
        &rule,
        0,
        Expressions::Meta(vec![
            Meta::DestinationRegister(Register::Reg1),
            Meta::Key(MetaKey::Nfproto),
        ]),
    );
    assert_eq!(decode_firewall_rule(&expressions), Ok(rule));
}

#[test]
fn a_masked_destination_decodes_to_its_network() {
    let rule = FirewallRule::SendNeighbourDiscovery {
        destination: Ipv6Addr::new(0xff02, 0, 0, 0, 0, 1, 0xff00, 1),
        length: 104,
    };
    assert_eq!(
        decode_firewall_rule(&encode_firewall_rule(&rule)),
        Ok(FirewallRule::SendNeighbourDiscovery {
            destination: SOLICITED_NODE,
            length: 104,
        })
    );
    let host = FirewallRule::SendNeighbourDiscovery {
        destination: SOLICITED_NODE,
        length: 200,
    };
    assert_eq!(
        decode_firewall_rule(&encode_firewall_rule(&host)),
        Ok(FirewallRule::SendNeighbourDiscovery {
            destination: SOLICITED_NODE,
            length: 128,
        })
    );
}

#[test]
fn other_expressions_are_undecodable() {
    let established = FirewallRule::AcceptEstablished;
    let tcp = rules()[5];
    let other_bitwise_operation = replaced(
        &established,
        1,
        Expressions::Bitwise(vec![
            Bitwise::SourceRegister(Register::Reg1),
            Bitwise::DestinationRegister(Register::Reg1),
            Bitwise::Length(4),
            Bitwise::Op(1),
            Bitwise::Mask(DataAttribute::Value(0b110_u32.to_ne_bytes().to_vec())),
            Bitwise::Xor(DataAttribute::Value(vec![0; 4])),
        ]),
    );
    let ct_status = replaced(
        &established,
        0,
        Expressions::Other {
            expression_type: "ct".to_owned(),
            attributes: vec![
                DefaultNla::new(1, 1_u32.to_be_bytes().to_vec()),
                DefaultNla::new(2, 1_u32.to_be_bytes().to_vec()),
            ],
        },
    );
    let drop = replaced(
        &established,
        3,
        Expressions::Immediate(vec![
            Immediate::DestinationRegister(Register::Verdict),
            Immediate::Data(DataAttribute::Verdict(vec![VerdictAttribute::Code(
                Verdict::Other(0),
            )])),
        ]),
    );
    let other_family = replaced(
        &tcp,
        1,
        Expressions::Cmp(vec![
            Cmp::SourceRegister(Register::Reg1),
            Cmp::Op(Operator::Equal),
            Cmp::Data(DataAttribute::Value(vec![10])),
        ]),
    );
    let mut extra = encode_firewall_rule(&tcp);
    extra.insert(
        8,
        ListAttribute::from(Expressions::Other {
            expression_type: "counter".to_owned(),
            attributes: Vec::new(),
        }),
    );
    let mut unnamed = encode_firewall_rule(&tcp);
    unnamed[0] = ListAttribute::Element(vec![ExpressionAttribute::Data(Expressions::Unknown(
        Vec::new(),
    ))]);
    let mut unspecified = encode_firewall_rule(&tcp);
    unspecified[0] = ListAttribute::Unspec;
    for expressions in [
        Vec::new(),
        other_bitwise_operation,
        ct_status,
        drop,
        other_family,
        extra,
        unnamed,
        unspecified,
    ] {
        assert_eq!(
            decode_firewall_rule(&expressions),
            Err(UndecodableRule),
            "{expressions:?}"
        );
    }
}

#[test]
fn an_undecodable_rule_says_so() {
    assert_eq!(
        UndecodableRule.to_string(),
        "the firewall rule holds expressions no provider rule has"
    );
}
