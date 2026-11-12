use std::{
    error::Error,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
};

use netlink_packet_core::DefaultNla;
use netlink_packet_netfilter::nftables::{DevHookNumber, NfTablesMessageType, TableFlags};

use super::*;
use crate::namespace_network::{ExpectedNamespace, NetworkRange};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

fn expected() -> TestResult<ExpectedNamespace> {
    let range = NetworkRange::new(
        Ipv4Addr::new(10, 213, 0, 0),
        24,
        Ipv6Addr::new(0xfd00, 0x913, 0, 0, 0, 0, 0, 0),
        120,
    )?;
    let endpoints = [
        SocketAddr::from(([192, 0, 2, 10], 443)),
        SocketAddr::from((Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x10), 8443)),
    ];
    Ok(ExpectedNamespace::for_attempt(
        [7; 16], &range, 3, &endpoints,
    )?)
}

fn nft(message: NfTablesMessage) -> NetfilterMessage {
    NetfilterMessage::new(
        NetfilterHeader::new(NetfilterProtoFamily::Inet, 0, 0),
        message,
    )
}

/// `message` as the kernel's dumps report it: with handles, use counts and
/// the base-chain flag added.
fn decorated(message: NetfilterMessage) -> NetfilterMessage {
    match message.inner {
        NetfilterMessageInner::NfTables(NfTablesMessage::NewTable(mut table)) => {
            table.attributes.extend([
                TableAttribute::Flags(TableFlags::empty()),
                TableAttribute::Use(3),
                TableAttribute::Handle(1),
            ]);
            nft(NfTablesMessage::NewTable(table))
        }
        NetfilterMessageInner::NfTables(NfTablesMessage::NewChain(mut chain)) => {
            chain.attributes.extend([
                ChainAttribute::Handle(2),
                ChainAttribute::Use(1),
                ChainAttribute::Flags(ChainFlags::Base),
            ]);
            nft(NfTablesMessage::NewChain(chain))
        }
        NetfilterMessageInner::NfTables(NfTablesMessage::NewRule(mut rule)) => {
            rule.attributes.push(RuleAttribute::Handle(9));
            nft(NfTablesMessage::NewRule(rule))
        }
        inner => NetfilterMessage::new(message.header, inner),
    }
}

/// The batch's messages of type `wanted`, as the dumps report them.
fn replies(
    batch: &[Request<NetfilterMessage>],
    wanted: NfTablesMessageType,
) -> Vec<NetfilterMessage> {
    batch
        .iter()
        .filter(|request| {
            matches!(&request.message.inner, NetfilterMessageInner::NfTables(message) if message.message_type() == wanted)
        })
        .map(|request| decorated(request.message.clone()))
        .collect()
}

#[test]
fn the_batch_creates_the_table_its_chains_and_their_rules_in_one_transaction() -> TestResult {
    let expected = expected()?;
    let batch = install(&expected.table, &expected.chains);
    let rules: usize = expected.chains.iter().map(|chain| chain.rules.len()).sum();
    assert_eq!(batch.len(), 2 + 1 + expected.chains.len() + rules);
    let flags: Vec<(u16, bool)> = batch
        .iter()
        .map(|request| (request.flags, request.acknowledged))
        .collect();
    assert_eq!(flags[0], (0, false));
    assert_eq!(flags[1], (NLM_F_CREATE | NLM_F_EXCL, true));
    assert_eq!(flags[2], (NLM_F_CREATE | NLM_F_EXCL, true));
    assert_eq!(flags[3], (NLM_F_CREATE | NLM_F_APPEND, true));
    assert_eq!(flags[batch.len() - 1], (0, false));
    let begin = &batch[0].message;
    assert_eq!(
        begin.header,
        NetfilterHeader::new(NetfilterProtoFamily::Unspec, 0, 10)
    );
    assert_eq!(
        begin.inner,
        NetfilterMessageInner::None(ControlMessage::BatchBegin)
    );
    assert_eq!(
        batch[batch.len() - 1].message.inner,
        NetfilterMessageInner::None(ControlMessage::BatchEnd)
    );
    assert_eq!(
        batch[1].message,
        nft(NfTablesMessage::NewTable(TableMessage {
            attributes: vec![TableAttribute::Name("piglor_attempt".to_owned())],
        }))
    );
    Ok(())
}

#[test]
fn base_chains_carry_their_hook_priority_policy_and_type() {
    let chain = |base| FirewallChain {
        name: "c".to_owned(),
        base,
        rules: Vec::new(),
    };
    let base = FirewallBaseChain {
        hook: FirewallHook::Output,
        priority: -150,
        policy: FirewallVerdict::Accept,
    };
    assert_eq!(
        new_chain("t", &chain(Some(base))),
        NfTablesMessage::NewChain(ChainMessage {
            attributes: vec![
                ChainAttribute::Table("t".to_owned()),
                ChainAttribute::Name("c".to_owned()),
                ChainAttribute::Hook(vec![
                    Hook::Number(HookNumber::Inet(InetHookNumber::LocalOut)),
                    Hook::Priority(u32::from_ne_bytes((-150_i32).to_ne_bytes())),
                ]),
                ChainAttribute::Policy(1),
                ChainAttribute::Type("filter".to_owned()),
            ],
        })
    );
    assert_eq!(
        new_chain("t", &chain(None)),
        NfTablesMessage::NewChain(ChainMessage {
            attributes: vec![
                ChainAttribute::Table("t".to_owned()),
                ChainAttribute::Name("c".to_owned()),
            ],
        })
    );
    assert_eq!(hook_number(FirewallHook::Input), InetHookNumber::LocalIn);
    assert_eq!(hook_number(FirewallHook::Forward), InetHookNumber::Forward);
    assert_eq!(verdict_code(FirewallVerdict::Drop), 0);
}

#[test]
fn the_dumps_read_back_exactly_what_the_batch_installs() -> TestResult {
    let expected = expected()?;
    let batch = install(&expected.table, &expected.chains);
    let observed = observed_tables(
        replies(&batch, NfTablesMessageType::NewTable),
        replies(&batch, NfTablesMessageType::NewChain),
        replies(&batch, NfTablesMessageType::NewRule),
    )?;
    assert_eq!(
        observed,
        [ObservedTable {
            family: FirewallTableFamily::Inet,
            name: expected.table.clone(),
            flags: 0,
            chains: expected.chains,
        }]
    );
    Ok(())
}

#[test]
fn other_families_regular_chains_and_flags_read_back() -> TestResult {
    let table = |family, flags| {
        NetfilterMessage::new(
            NetfilterHeader::new(family, 0, 0),
            NfTablesMessage::NewTable(TableMessage {
                attributes: vec![
                    TableAttribute::Name("t".to_owned()),
                    TableAttribute::Flags(flags),
                    TableAttribute::Owner(7),
                    TableAttribute::UserData(vec![1]),
                ],
            }),
        )
    };
    let accepting = nft(NfTablesMessage::NewChain(ChainMessage {
        attributes: vec![
            ChainAttribute::Table("t".to_owned()),
            ChainAttribute::Name("a".to_owned()),
            ChainAttribute::Hook(vec![
                Hook::Number(HookNumber::Inet(InetHookNumber::LocalOut)),
                Hook::Priority(u32::from_ne_bytes((-150_i32).to_ne_bytes())),
            ]),
            ChainAttribute::Policy(1),
            ChainAttribute::Type("filter".to_owned()),
        ],
    }));
    let regular = nft(NfTablesMessage::NewChain(ChainMessage {
        attributes: vec![
            ChainAttribute::Table("t".to_owned()),
            ChainAttribute::Name("r".to_owned()),
            ChainAttribute::Counter(Vec::new()),
            ChainAttribute::Id(3),
            ChainAttribute::UserData(vec![1]),
        ],
    }));
    let observed = observed_tables(
        vec![
            table(NetfilterProtoFamily::IPv4, TableFlags::empty()),
            table(NetfilterProtoFamily::Inet, TableFlags::Dormant),
        ],
        vec![regular, accepting],
        Vec::new(),
    )?;
    assert_eq!(observed[0].family, FirewallTableFamily::Other);
    assert!(observed[0].chains.is_empty());
    assert_eq!(observed[1].flags, 1);
    assert_eq!(
        observed[1].chains,
        [
            FirewallChain {
                name: "r".to_owned(),
                base: None,
                rules: Vec::new(),
            },
            FirewallChain {
                name: "a".to_owned(),
                base: Some(FirewallBaseChain {
                    hook: FirewallHook::Output,
                    priority: -150,
                    policy: FirewallVerdict::Accept,
                }),
                rules: Vec::new(),
            },
        ]
    );
    Ok(())
}

fn table_named(attributes: Vec<TableAttribute>) -> NetfilterMessage {
    nft(NfTablesMessage::NewTable(TableMessage { attributes }))
}

fn chain_with(attributes: Vec<ChainAttribute>) -> NetfilterMessage {
    let mut all = vec![
        ChainAttribute::Table("t".to_owned()),
        ChainAttribute::Name("c".to_owned()),
    ];
    all.extend(attributes);
    nft(NfTablesMessage::NewChain(ChainMessage { attributes: all }))
}

fn rule_with(attributes: Vec<RuleAttribute>) -> NetfilterMessage {
    nft(NfTablesMessage::NewRule(RuleMessage { attributes }))
}

#[test]
fn unrepresentable_tables_and_chains_fail() {
    let input = Hook::Number(HookNumber::Inet(InetHookNumber::LocalIn));
    let tables = [
        table_named(vec![TableAttribute::Flags(TableFlags::empty())]),
        table_named(vec![
            TableAttribute::Name("t".to_owned()),
            TableAttribute::Other(DefaultNla::new(99, vec![0; 4])),
        ]),
    ];
    for table in tables {
        assert!(matches!(
            observed_tables(vec![table], Vec::new(), Vec::new()),
            Err(NetlinkError::Unrepresentable)
        ));
    }
    let chains = [
        // A base chain of another type, policy or hook, or without part of
        // its hook, flags beyond the base flag, and unknown attributes.
        chain_with(vec![
            ChainAttribute::Hook(vec![input.clone(), Hook::Priority(0)]),
            ChainAttribute::Policy(0),
            ChainAttribute::Type("nat".to_owned()),
        ]),
        chain_with(vec![
            ChainAttribute::Hook(vec![input.clone(), Hook::Priority(0)]),
            ChainAttribute::Policy(3),
            ChainAttribute::Type("filter".to_owned()),
        ]),
        chain_with(vec![
            ChainAttribute::Hook(vec![input.clone(), Hook::Priority(0)]),
            ChainAttribute::Type("filter".to_owned()),
        ]),
        chain_with(vec![ChainAttribute::Hook(vec![
            Hook::Number(HookNumber::Inet(InetHookNumber::PreRouting)),
            Hook::Priority(0),
        ])]),
        chain_with(vec![ChainAttribute::Hook(vec![
            Hook::Number(HookNumber::Dev(DevHookNumber::Ingress)),
            Hook::Priority(0),
        ])]),
        chain_with(vec![ChainAttribute::Hook(vec![input])]),
        chain_with(vec![ChainAttribute::Policy(0)]),
        chain_with(vec![ChainAttribute::Flags(
            ChainFlags::Base | ChainFlags::HwOffload,
        )]),
        chain_with(vec![ChainAttribute::Other(DefaultNla::new(99, vec![0; 4]))]),
        nft(NfTablesMessage::NewChain(ChainMessage {
            attributes: vec![ChainAttribute::Name("c".to_owned())],
        })),
    ];
    // The table exists, so each chain fails on its own.
    for chain in chains {
        let table = table_named(vec![TableAttribute::Name("t".to_owned())]);
        assert!(matches!(
            observed_tables(vec![table], vec![chain], Vec::new()),
            Err(NetlinkError::Unrepresentable)
        ));
    }
}

#[test]
fn unrepresentable_rules_and_orphans_fail() -> TestResult {
    let accept = encode_firewall_rule(&FirewallRule::AcceptEstablished);
    let mut undecodable = accept.clone();
    undecodable.pop();
    let placed = |extra: RuleAttribute| {
        rule_with(vec![
            RuleAttribute::Table("t".to_owned()),
            RuleAttribute::Chain("c".to_owned()),
            extra,
        ])
    };
    let rules = [
        placed(RuleAttribute::Expressions(undecodable)),
        placed(RuleAttribute::Compat(Vec::new())),
        rule_with(vec![
            RuleAttribute::Table("t".to_owned()),
            RuleAttribute::Expressions(accept.clone()),
        ]),
        // A rule of a chain the dump did not report.
        placed(RuleAttribute::Expressions(accept.clone())),
    ];
    for rule in rules {
        assert!(matches!(
            observed_tables(Vec::new(), Vec::new(), vec![rule]),
            Err(NetlinkError::Unrepresentable)
        ));
    }
    // A chain of a table the dump did not report.
    assert!(matches!(
        observed_tables(Vec::new(), vec![chain_with(Vec::new())], Vec::new()),
        Err(NetlinkError::Unrepresentable)
    ));
    let positioned = rule_with(vec![
        RuleAttribute::Table("t".to_owned()),
        RuleAttribute::Chain("c".to_owned()),
        RuleAttribute::Expressions(accept),
        RuleAttribute::Position(1),
        RuleAttribute::UserData(vec![1]),
        RuleAttribute::Id(2),
    ]);
    let observed = observed_tables(
        vec![table_named(vec![TableAttribute::Name("t".to_owned())])],
        vec![chain_with(Vec::new())],
        vec![positioned],
    )?;
    assert_eq!(
        observed[0].chains[0].rules,
        [FirewallRule::AcceptEstablished]
    );
    Ok(())
}

#[test]
fn replies_of_another_kind_are_unexpected() {
    let control = NetfilterMessage::new(
        NetfilterHeader::new(NetfilterProtoFamily::Unspec, 0, 10),
        ControlMessage::BatchBegin,
    );
    let rule = rule_with(Vec::new());
    let cases = [
        observed_tables(vec![control.clone()], Vec::new(), Vec::new()),
        observed_tables(vec![rule.clone()], Vec::new(), Vec::new()),
        observed_tables(Vec::new(), vec![control.clone()], Vec::new()),
        observed_tables(Vec::new(), vec![rule], Vec::new()),
        observed_tables(Vec::new(), Vec::new(), vec![control]),
        observed_tables(Vec::new(), Vec::new(), vec![table_named(Vec::new())]),
    ];
    for result in cases {
        assert!(
            matches!(result, Err(NetlinkError::Unexpected)),
            "{result:?}"
        );
    }
}

#[test]
fn the_dumps_ask_for_every_family() {
    let [tables, chains, rules] = dumps();
    let unspec = NetfilterHeader::new(NetfilterProtoFamily::Unspec, 0, 0);
    assert_eq!(tables.header, unspec);
    assert_eq!(
        tables.inner,
        NetfilterMessageInner::NfTables(NfTablesMessage::GetTable(TableMessage {
            attributes: Vec::new()
        }))
    );
    assert_eq!(
        chains.inner,
        NetfilterMessageInner::NfTables(NfTablesMessage::GetChain(ChainMessage {
            attributes: Vec::new()
        }))
    );
    assert_eq!(
        rules.inner,
        NetfilterMessageInner::NfTables(NfTablesMessage::GetRule(RuleMessage {
            attributes: Vec::new()
        }))
    );
}
