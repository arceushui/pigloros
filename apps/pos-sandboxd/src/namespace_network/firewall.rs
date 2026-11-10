//! The nftables batch that installs one attempt's firewall, and the
//! decoder that reads every table, chain and rule of a namespace back
//! (#911, owner decision 2026-11-09).
//!
//! The batch creates the table, its chains and their rules in one
//! transaction: the kernel applies all of it or none. Each rule's
//! expressions come from [`encode_firewall_rule`] and are read back through
//! [`decode_firewall_rule`]. The decoder fails on anything the port's types
//! cannot represent: a chain of another type or hook, a policy other than
//! accept or drop, `xt` compatibility matches, attributes it does not know,
//! and a chain or rule whose table or chain the dumps did not report.

use netlink_packet_core::{NLM_F_APPEND, NLM_F_CREATE, NLM_F_EXCL};
use netlink_packet_netfilter::nftables::{
    ChainAttribute, ChainFlags, ChainMessage, Hook, HookNumber, InetHookNumber, NfTablesMessage,
    RuleAttribute, RuleMessage, TableAttribute, TableMessage,
};
use netlink_packet_netfilter::none::ControlMessage;
use netlink_packet_netfilter::{
    NetfilterHeader, NetfilterMessage, NetfilterMessageInner, NetfilterProtoFamily,
};

use super::netlink::{NetlinkError, Request};
use super::{
    decode_firewall_rule, encode_firewall_rule, FirewallBaseChain, FirewallChain, FirewallHook,
    FirewallRule, FirewallTableFamily, FirewallVerdict, ObservedTable,
};

/// `NFNL_SUBSYS_NFTABLES`, the resource a batch's delimiters name.
const NFTABLES: u16 = 10;
/// `NF_DROP`.
const NF_DROP: u32 = 0;
/// `NF_ACCEPT`.
const NF_ACCEPT: u32 = 1;
/// The type of every provider chain.
const FILTER: &str = "filter";
// The flag sets add disjoint single-bit flags, so each sum is their union
// and, unlike `|`, no mutation of the operator leaves it unchanged.
/// Create an object, and fail if it exists.
const CREATE_NEW: u16 = NLM_F_CREATE + NLM_F_EXCL;
/// Create a rule after the chain's last.
const APPEND: u16 = NLM_F_CREATE + NLM_F_APPEND;

/// A netfilter message of `family` carrying `message`.
fn message(family: NetfilterProtoFamily, message: NfTablesMessage) -> NetfilterMessage {
    NetfilterMessage::new(NetfilterHeader::new(family, 0, 0), message)
}

/// A batch delimiter.
fn delimiter(control: ControlMessage) -> Request<NetfilterMessage> {
    Request::unacknowledged(NetfilterMessage::new(
        NetfilterHeader::new(NetfilterProtoFamily::Unspec, 0, NFTABLES),
        control,
    ))
}

/// The netfilter hook number of `hook`.
const fn hook_number(hook: FirewallHook) -> InetHookNumber {
    match hook {
        FirewallHook::Input => InetHookNumber::LocalIn,
        FirewallHook::Forward => InetHookNumber::Forward,
        FirewallHook::Output => InetHookNumber::LocalOut,
    }
}

/// The verdict code of `verdict`.
const fn verdict_code(verdict: FirewallVerdict) -> u32 {
    match verdict {
        FirewallVerdict::Accept => NF_ACCEPT,
        FirewallVerdict::Drop => NF_DROP,
    }
}

/// Create chain `chain` of table `table`.
fn new_chain(table: &str, chain: &FirewallChain) -> NfTablesMessage {
    let mut attributes = vec![
        ChainAttribute::Table(table.to_owned()),
        ChainAttribute::Name(chain.name.clone()),
    ];
    if let Some(base) = chain.base {
        attributes.extend([
            ChainAttribute::Hook(vec![
                Hook::Number(HookNumber::Inet(hook_number(base.hook))),
                Hook::Priority(u32::from_ne_bytes(base.priority.to_ne_bytes())),
            ]),
            ChainAttribute::Policy(verdict_code(base.policy)),
            ChainAttribute::Type(FILTER.to_owned()),
        ]);
    }
    NfTablesMessage::NewChain(ChainMessage { attributes })
}

/// Append `rule` to chain `chain` of table `table`.
fn new_rule(table: &str, chain: &str, rule: &FirewallRule) -> NfTablesMessage {
    NfTablesMessage::NewRule(RuleMessage {
        attributes: vec![
            RuleAttribute::Table(table.to_owned()),
            RuleAttribute::Chain(chain.to_owned()),
            RuleAttribute::Expressions(encode_firewall_rule(rule)),
        ],
    })
}

/// One transaction that creates the `inet` table `table` with exactly
/// `chains`, each with its rules in order. `NLM_F_EXCL` refuses an existing
/// table or chain, so the batch never extends another firewall.
pub(super) fn install(table: &str, chains: &[FirewallChain]) -> Vec<Request<NetfilterMessage>> {
    let inet = NetfilterProtoFamily::Inet;
    let mut requests = vec![
        delimiter(ControlMessage::BatchBegin),
        Request::acknowledged(
            message(
                inet,
                NfTablesMessage::NewTable(TableMessage {
                    attributes: vec![TableAttribute::Name(table.to_owned())],
                }),
            ),
            CREATE_NEW,
        ),
    ];
    for chain in chains {
        requests.push(Request::acknowledged(
            message(inet, new_chain(table, chain)),
            CREATE_NEW,
        ));
        requests.extend(chain.rules.iter().map(|rule| {
            Request::acknowledged(message(inet, new_rule(table, &chain.name, rule)), APPEND)
        }));
    }
    requests.push(delimiter(ControlMessage::BatchEnd));
    requests
}

/// The dumps of every table, chain and rule of every family, in the order
/// [`observed_tables`] takes their replies.
pub(super) fn dumps() -> [NetfilterMessage; 3] {
    let unspec = NetfilterProtoFamily::Unspec;
    [
        message(
            unspec,
            NfTablesMessage::GetTable(TableMessage {
                attributes: Vec::new(),
            }),
        ),
        message(
            unspec,
            NfTablesMessage::GetChain(ChainMessage {
                attributes: Vec::new(),
            }),
        ),
        message(
            unspec,
            NfTablesMessage::GetRule(RuleMessage {
                attributes: Vec::new(),
            }),
        ),
    ]
}

/// A table, chain or rule of one family, as the dumps report it.
struct Owned<T> {
    family: NetfilterProtoFamily,
    table: String,
    chain: String,
    item: T,
}

/// The nftables message of a dump reply.
fn nftables(reply: NetfilterMessage) -> (NetfilterProtoFamily, Option<NfTablesMessage>) {
    let family = reply.header.family;
    match reply.inner {
        NetfilterMessageInner::NfTables(message) => (family, Some(message)),
        _ => (family, None),
    }
}

/// The table one reply of a table dump reports, with its name.
fn table(reply: NetfilterMessage) -> Result<Owned<ObservedTable>, NetlinkError> {
    let (family, message) = nftables(reply);
    let NfTablesMessage::NewTable(table) = message.ok_or(NetlinkError::Unexpected)? else {
        return Err(NetlinkError::Unexpected);
    };
    let mut name = None;
    let mut flags = 0;
    for attribute in table.attributes {
        match attribute {
            TableAttribute::Name(value) => name = Some(value),
            TableAttribute::Flags(value) => flags = value.bits(),
            TableAttribute::Use(_)
            | TableAttribute::Handle(_)
            | TableAttribute::UserData(_)
            | TableAttribute::Owner(_) => {}
            _ => return Err(NetlinkError::Unrepresentable),
        }
    }
    let name = name.ok_or(NetlinkError::Unrepresentable)?;
    Ok(Owned {
        family,
        table: name.clone(),
        chain: String::new(),
        item: ObservedTable {
            family: if family == NetfilterProtoFamily::Inet {
                FirewallTableFamily::Inet
            } else {
                FirewallTableFamily::Other
            },
            name,
            flags,
            chains: Vec::new(),
        },
    })
}

/// The hook and priority of a base chain's `NFTA_CHAIN_HOOK`.
fn hook(hooks: Vec<Hook>) -> Result<(FirewallHook, i32), NetlinkError> {
    let mut number = None;
    let mut priority = None;
    for hook in hooks {
        match hook {
            Hook::Number(HookNumber::Inet(InetHookNumber::LocalIn)) => {
                number = Some(FirewallHook::Input);
            }
            Hook::Number(HookNumber::Inet(InetHookNumber::Forward)) => {
                number = Some(FirewallHook::Forward);
            }
            Hook::Number(HookNumber::Inet(InetHookNumber::LocalOut)) => {
                number = Some(FirewallHook::Output);
            }
            Hook::Priority(value) => priority = Some(i32::from_ne_bytes(value.to_ne_bytes())),
            _ => return Err(NetlinkError::Unrepresentable),
        }
    }
    number.zip(priority).ok_or(NetlinkError::Unrepresentable)
}

/// The chain one reply of a chain dump reports, without its rules.
fn chain(reply: NetfilterMessage) -> Result<Owned<FirewallChain>, NetlinkError> {
    let (family, message) = nftables(reply);
    let NfTablesMessage::NewChain(chain) = message.ok_or(NetlinkError::Unexpected)? else {
        return Err(NetlinkError::Unexpected);
    };
    let (mut table, mut name, mut hooks, mut policy, mut kind) = (None, None, None, None, None);
    for attribute in chain.attributes {
        match attribute {
            ChainAttribute::Table(value) => table = Some(value),
            ChainAttribute::Name(value) => name = Some(value),
            ChainAttribute::Hook(value) => hooks = Some(hook(value)?),
            ChainAttribute::Policy(value) => policy = Some(value),
            ChainAttribute::Type(value) => kind = Some(value),
            ChainAttribute::Flags(value) if (value - ChainFlags::Base).is_empty() => {}
            ChainAttribute::Handle(_)
            | ChainAttribute::Use(_)
            | ChainAttribute::Counter(_)
            | ChainAttribute::Id(_)
            | ChainAttribute::UserData(_) => {}
            _ => return Err(NetlinkError::Unrepresentable),
        }
    }
    let base = match (hooks, policy, kind.as_deref()) {
        (None, None, None) => None,
        (Some((hook, priority)), Some(NF_ACCEPT), Some(FILTER)) => {
            Some((hook, priority, FirewallVerdict::Accept))
        }
        (Some((hook, priority)), Some(NF_DROP), Some(FILTER)) => {
            Some((hook, priority, FirewallVerdict::Drop))
        }
        _ => return Err(NetlinkError::Unrepresentable),
    };
    table
        .zip(name)
        .map(|(table, name)| Owned {
            family,
            table,
            chain: name.clone(),
            item: FirewallChain {
                name,
                base: base.map(|(hook, priority, policy)| FirewallBaseChain {
                    hook,
                    priority,
                    policy,
                }),
                rules: Vec::new(),
            },
        })
        .ok_or(NetlinkError::Unrepresentable)
}

/// The rule one reply of a rule dump reports.
fn rule(reply: NetfilterMessage) -> Result<Owned<FirewallRule>, NetlinkError> {
    let (family, message) = nftables(reply);
    let NfTablesMessage::NewRule(rule) = message.ok_or(NetlinkError::Unexpected)? else {
        return Err(NetlinkError::Unexpected);
    };
    let (mut table, mut chain, mut decoded) = (None, None, None);
    for attribute in rule.attributes {
        match attribute {
            RuleAttribute::Table(value) => table = Some(value),
            RuleAttribute::Chain(value) => chain = Some(value),
            RuleAttribute::Expressions(value) => {
                decoded =
                    Some(decode_firewall_rule(&value).map_err(|_| NetlinkError::Unrepresentable)?);
            }
            RuleAttribute::Handle(_)
            | RuleAttribute::Position(_)
            | RuleAttribute::UserData(_)
            | RuleAttribute::Id(_) => {}
            _ => return Err(NetlinkError::Unrepresentable),
        }
    }
    match (table, chain, decoded) {
        (Some(table), Some(chain), Some(item)) => Ok(Owned {
            family,
            table,
            chain,
            item,
        }),
        _ => Err(NetlinkError::Unrepresentable),
    }
}

/// Every table the three [`dumps`] report, each with its chains in dump
/// order and each chain with its rules in evaluation order.
///
/// # Errors
/// Fails on another reply, on anything the port cannot represent, and on a
/// chain or rule whose table or chain is not in the dumps.
pub(super) fn observed_tables(
    tables: Vec<NetfilterMessage>,
    chains: Vec<NetfilterMessage>,
    rules: Vec<NetfilterMessage>,
) -> Result<Vec<ObservedTable>, NetlinkError> {
    let mut tables = tables
        .into_iter()
        .map(table)
        .collect::<Result<Vec<_>, _>>()?;
    let mut chains = chains
        .into_iter()
        .map(chain)
        .collect::<Result<Vec<_>, _>>()?;
    for rule in rules.into_iter().map(rule) {
        let rule = rule?;
        chains
            .iter_mut()
            .find(|chain| {
                chain.family == rule.family
                    && chain.table == rule.table
                    && chain.chain == rule.chain
            })
            .ok_or(NetlinkError::Unrepresentable)?
            .item
            .rules
            .push(rule.item);
    }
    for chain in chains {
        tables
            .iter_mut()
            .find(|table| table.family == chain.family && table.table == chain.table)
            .ok_or(NetlinkError::Unrepresentable)?
            .item
            .chains
            .push(chain.item);
    }
    Ok(tables.into_iter().map(|table| table.item).collect())
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests;
