//! GMP1 startup predicate 6, `air-gapped-no-route` (ADR-135 §4).
//!
//! The predicate holds only for a process in a loopback-only network
//! namespace that holds no network capability, cannot regain one and runs
//! under a seccomp filter. It is evaluated from host-owned facts, never from
//! caller input: production reads only `/proc/self` (plus whether
//! `/proc/sys/net/ipv6` exists), and no feature, environment variable or
//! argument can override it. [`check_air_gapped_no_route_v1`] is the pure
//! parser over the text of those files; an absent, unreadable or unparsable
//! file denies.

use std::{fmt, fs, net::Ipv4Addr, path::Path};

/// The kernel's fallback tunnel devices, present in every network namespace
/// while their module is loaded (ADR-135 §4 item 1). A name alone proves
/// nothing: the address, route and membership checks close a renamed real
/// interface.
const FALLBACK_DEVICES: [&str; 9] = [
    "sit0", "tunl0", "ip6tnl0", "gre0", "gretap0", "erspan0", "ip_vti0", "ip6_vti0", "ip6gre0",
];
/// `CAP_NET_ADMIN`, `CAP_NET_RAW` and `CAP_SYS_ADMIN`.
const NETWORK_CAPABILITIES: u64 = (1 << 12) | (1 << 13) | (1 << 21);
/// `Seccomp: 2`: a seccomp filter is installed.
const SECCOMP_MODE_FILTER: &str = "2";

/// One host fact the predicate reads.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AirGappedHostFactV1 {
    /// `/proc/self/net/dev`.
    Dev,
    /// `/proc/self/net/route`.
    Route,
    /// `/proc/self/net/ipv6_route`.
    Ipv6Route,
    /// `/proc/self/net/if_inet6`.
    IfInet6,
    /// `/proc/self/net/fib_trie`.
    FibTrie,
    /// `/proc/self/net/igmp`.
    Igmp,
    /// `/proc/self/net/igmp6`.
    Igmp6,
    /// `/proc/self/status`.
    Status,
}

impl AirGappedHostFactV1 {
    /// The `/proc/self` path of the fact.
    #[must_use]
    pub const fn path(self) -> &'static str {
        match self {
            Self::Dev => "/proc/self/net/dev",
            Self::Route => "/proc/self/net/route",
            Self::Ipv6Route => "/proc/self/net/ipv6_route",
            Self::IfInet6 => "/proc/self/net/if_inet6",
            Self::FibTrie => "/proc/self/net/fib_trie",
            Self::Igmp => "/proc/self/net/igmp",
            Self::Igmp6 => "/proc/self/net/igmp6",
            Self::Status => "/proc/self/status",
        }
    }
}

impl fmt::Display for AirGappedHostFactV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.path())
    }
}

/// Why `air-gapped-no-route` denied.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum AirGappedNoRouteDenialV1 {
    /// A fact is absent, unreadable or unparsable.
    #[error("{0} is absent, unreadable or unparsable")]
    Unreadable(AirGappedHostFactV1),
    /// An interface other than `lo` or a fallback tunnel device exists.
    #[error("an interface other than lo or a fallback tunnel device exists")]
    Interface,
    /// A route other than through `lo` exists.
    #[error("a route other than through lo exists")]
    Route,
    /// A local address outside loopback exists.
    #[error("an address outside loopback exists")]
    Address,
    /// A device other than `lo` holds a multicast membership.
    #[error("a device other than lo holds a multicast membership")]
    Membership,
    /// The process holds a network capability.
    #[error(
        "the process holds a network capability (network or system administration, raw sockets)"
    )]
    Capability,
    /// The process could regain a network capability by `execve`.
    #[error("the bounding set keeps a network capability without no_new_privs")]
    BoundingSet,
    /// No seccomp filter is installed.
    #[error("no seccomp filter is installed")]
    Seccomp,
}

/// The text of every fact `air-gapped-no-route` reads; `None` is a file
/// that is absent or unreadable.
#[derive(Debug)]
pub struct AirGappedHostFactsV1 {
    /// `/proc/self/net/dev`.
    pub dev: Option<String>,
    /// `/proc/self/net/route`.
    pub route: Option<String>,
    /// `/proc/self/net/ipv6_route`.
    pub ipv6_route: Option<String>,
    /// `/proc/self/net/if_inet6`.
    pub if_inet6: Option<String>,
    /// `/proc/self/net/fib_trie`.
    pub fib_trie: Option<String>,
    /// `/proc/self/net/igmp`.
    pub igmp: Option<String>,
    /// `/proc/self/net/igmp6`.
    pub igmp6: Option<String>,
    /// `/proc/self/status`.
    pub status: Option<String>,
    /// IPv6 is disabled (`/proc/sys/net/ipv6` is absent): `ipv6_route`,
    /// `if_inet6` and `igmp6` then count as empty.
    pub ipv6_disabled: bool,
}

impl AirGappedHostFactsV1 {
    /// Read this process's facts from `/proc/self`.
    pub(crate) fn read() -> Self {
        let read = |fact: AirGappedHostFactV1| fs::read_to_string(fact.path()).ok();
        Self {
            dev: read(AirGappedHostFactV1::Dev),
            route: read(AirGappedHostFactV1::Route),
            ipv6_route: read(AirGappedHostFactV1::Ipv6Route),
            if_inet6: read(AirGappedHostFactV1::IfInet6),
            fib_trie: read(AirGappedHostFactV1::FibTrie),
            igmp: read(AirGappedHostFactV1::Igmp),
            igmp6: read(AirGappedHostFactV1::Igmp6),
            status: read(AirGappedHostFactV1::Status),
            ipv6_disabled: !Path::new("/proc/sys/net/ipv6").exists(),
        }
    }
}

/// Evaluate `air-gapped-no-route` over `facts` (ADR-135 §4 items 1 to 4).
///
/// # Errors
/// Returns the first denial, in the order of the facts.
pub fn check_air_gapped_no_route_v1<'a>(
    facts: &'a AirGappedHostFactsV1,
) -> Result<(), AirGappedNoRouteDenialV1> {
    use AirGappedHostFactV1 as Fact;
    let ipv6 = |text: Option<&'a str>| facts.ipv6_disabled.then_some("").or(text);
    fact(facts.dev.as_deref(), Fact::Dev)
        .and_then(devices)
        .and_then(|()| fact(facts.route.as_deref(), Fact::Route).and_then(routes))
        .and_then(|()| {
            fact(ipv6(facts.ipv6_route.as_deref()), Fact::Ipv6Route).and_then(ipv6_routes)
        })
        .and_then(|()| {
            fact(ipv6(facts.if_inet6.as_deref()), Fact::IfInet6).and_then(ipv6_addresses)
        })
        .and_then(|()| fact(facts.fib_trie.as_deref(), Fact::FibTrie).and_then(fib_trie))
        .and_then(|()| fact(facts.igmp.as_deref(), Fact::Igmp).and_then(igmp))
        .and_then(|()| fact(ipv6(facts.igmp6.as_deref()), Fact::Igmp6).and_then(igmp6))
        .and_then(|()| fact(facts.status.as_deref(), Fact::Status).and_then(status))
}

const fn fact(
    text: Option<&str>,
    fact: AirGappedHostFactV1,
) -> Result<&str, AirGappedNoRouteDenialV1> {
    match text {
        Some(text) => Ok(text),
        None => Err(AirGappedNoRouteDenialV1::Unreadable(fact)),
    }
}

const fn deny(
    denied: bool,
    denial: AirGappedNoRouteDenialV1,
) -> Result<(), AirGappedNoRouteDenialV1> {
    if denied {
        Err(denial)
    } else {
        Ok(())
    }
}

/// The non-empty lines of `text`.
fn lines(text: &str) -> impl Iterator<Item = &str> {
    text.lines().filter(|line| !line.trim().is_empty())
}

/// `dev`: two header lines, then `name: counters` per interface; `lo` is
/// listed, and every other name is a fallback tunnel device.
fn devices(text: &str) -> Result<(), AirGappedNoRouteDenialV1> {
    let unreadable = AirGappedNoRouteDenialV1::Unreadable(AirGappedHostFactV1::Dev);
    let mut rows = text.lines();
    let headers = rows.next().zip(rows.next());
    deny(
        !headers.is_some_and(|(first, second)| first.contains('|') && second.contains('|')),
        unreadable,
    )
    .and_then(|()| {
        rows.filter(|line| !line.trim().is_empty())
            .try_fold(false, |listed_lo, line| {
                // A name may itself hold `:`; the counters never do.
                line.rsplit_once(':')
                    .map(|(name, _)| name.trim())
                    .filter(|name| !name.is_empty())
                    .ok_or(unreadable)
                    .and_then(|name| {
                        deny(
                            name != "lo" && !FALLBACK_DEVICES.contains(&name),
                            AirGappedNoRouteDenialV1::Interface,
                        )
                        .map(|()| listed_lo || name == "lo")
                    })
            })
            .and_then(|listed_lo| deny(!listed_lo, unreadable))
    })
}

/// `route`: its header line and no route.
fn routes(text: &str) -> Result<(), AirGappedNoRouteDenialV1> {
    let mut rows = lines(text);
    deny(
        !rows
            .next()
            .is_some_and(|header| header.starts_with("Iface")),
        AirGappedNoRouteDenialV1::Unreadable(AirGappedHostFactV1::Route),
    )
    .and_then(|()| deny(rows.next().is_some(), AirGappedNoRouteDenialV1::Route))
}

/// Every whitespace-separated row of `text` has `columns` fields, the last a
/// device that must be `lo`.
fn lo_rows(
    text: &str,
    columns: usize,
    fact: AirGappedHostFactV1,
    denial: AirGappedNoRouteDenialV1,
) -> Result<(), AirGappedNoRouteDenialV1> {
    lines(text).try_for_each(|line| {
        let fields = line.split_whitespace().collect::<Vec<_>>();
        deny(
            fields.len() != columns,
            AirGappedNoRouteDenialV1::Unreadable(fact),
        )
        .and_then(|()| deny(fields.last() != Some(&"lo"), denial))
    })
}

/// `ipv6_route`: every route is through `lo`.
fn ipv6_routes(text: &str) -> Result<(), AirGappedNoRouteDenialV1> {
    lo_rows(
        text,
        10,
        AirGappedHostFactV1::Ipv6Route,
        AirGappedNoRouteDenialV1::Route,
    )
}

/// `if_inet6`: every address is on `lo`.
fn ipv6_addresses(text: &str) -> Result<(), AirGappedNoRouteDenialV1> {
    lo_rows(
        text,
        6,
        AirGappedHostFactV1::IfInet6,
        AirGappedNoRouteDenialV1::Address,
    )
}

/// `fib_trie`: every `LOCAL` entry belongs to a leaf inside `127.0.0.0/8`.
fn fib_trie(text: &str) -> Result<(), AirGappedNoRouteDenialV1> {
    let unreadable = AirGappedNoRouteDenialV1::Unreadable(AirGappedHostFactV1::FibTrie);
    lines(text)
        .map(str::trim)
        .try_fold(None::<Ipv4Addr>, |leaf, line| {
            if let Some(address) = line.strip_prefix("|-- ") {
                address
                    .parse::<Ipv4Addr>()
                    .map(Some)
                    .map_err(|_| unreadable)
            } else if line.starts_with('/') && line.ends_with(" LOCAL") {
                leaf.ok_or(unreadable).and_then(|address| {
                    deny(
                        address.octets()[0] != 127,
                        AirGappedNoRouteDenialV1::Address,
                    )
                    .map(|()| Some(address))
                })
            } else {
                Ok(leaf)
            }
        })
        .map(drop)
}

/// `igmp`: its header line, then a `index name : count …` line per device
/// with memberships, each followed by indented group lines; every device is
/// `lo`.
fn igmp(text: &str) -> Result<(), AirGappedNoRouteDenialV1> {
    let unreadable = AirGappedNoRouteDenialV1::Unreadable(AirGappedHostFactV1::Igmp);
    let mut rows = lines(text);
    deny(
        !rows.next().is_some_and(|header| header.starts_with("Idx")),
        unreadable,
    )
    .and_then(|()| {
        rows.try_fold(false, |device, line| {
            if line.starts_with(char::is_whitespace) {
                deny(!device, unreadable).map(|()| true)
            } else {
                line.rsplit_once(':')
                    .map(|(head, _)| head.split_whitespace().collect::<Vec<_>>())
                    .filter(|head| head.len() == 2 && head[0].parse::<u32>().is_ok())
                    .ok_or(unreadable)
                    .and_then(|head| deny(head[1] != "lo", AirGappedNoRouteDenialV1::Membership))
                    .map(|()| true)
            }
        })
        .map(drop)
    })
}

/// `igmp6`: one `index name group users flags timer` line per membership;
/// every device is `lo`.
fn igmp6(text: &str) -> Result<(), AirGappedNoRouteDenialV1> {
    let unreadable = AirGappedNoRouteDenialV1::Unreadable(AirGappedHostFactV1::Igmp6);
    lines(text).try_for_each(|line| {
        let fields = line.split_whitespace().collect::<Vec<_>>();
        deny(
            fields.len() != 6 || fields[0].parse::<u32>().is_err(),
            unreadable,
        )
        .and_then(|()| deny(fields[1] != "lo", AirGappedNoRouteDenialV1::Membership))
    })
}

/// `status`: no network capability in `CapEff`, `CapPrm` or `CapAmb`; none
/// in `CapBnd` unless `NoNewPrivs` is `1`; `Seccomp` is `2`.
fn status(text: &str) -> Result<(), AirGappedNoRouteDenialV1> {
    let unreadable = AirGappedNoRouteDenialV1::Unreadable(AirGappedHostFactV1::Status);
    let field = |key: &str| {
        text.lines()
            .find_map(|line| line.strip_prefix(key)?.strip_prefix(':'))
            .map(str::trim)
            .ok_or(unreadable)
    };
    let capability =
        |key: &str| field(key).and_then(|hex| u64::from_str_radix(hex, 16).map_err(|_| unreadable));
    capability("CapEff")
        .and_then(|effective| capability("CapPrm").map(|permitted| effective | permitted))
        .and_then(|held| capability("CapAmb").map(|ambient| held | ambient))
        .and_then(|held| {
            deny(
                held & NETWORK_CAPABILITIES != 0,
                AirGappedNoRouteDenialV1::Capability,
            )
        })
        .and_then(|()| capability("CapBnd"))
        .and_then(|bounding| {
            field("NoNewPrivs")
                .and_then(|value| match value {
                    "0" => Ok(false),
                    "1" => Ok(true),
                    _ => Err(unreadable),
                })
                .and_then(|no_new_privs| {
                    deny(
                        bounding & NETWORK_CAPABILITIES != 0 && !no_new_privs,
                        AirGappedNoRouteDenialV1::BoundingSet,
                    )
                })
        })
        .and_then(|()| field("Seccomp"))
        .and_then(|seccomp| {
            deny(
                seccomp != SECCOMP_MODE_FILTER,
                AirGappedNoRouteDenialV1::Seccomp,
            )
        })
}
