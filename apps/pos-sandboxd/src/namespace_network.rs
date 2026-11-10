//! The Local attempt's network namespace: the exact kernel state it must
//! have, the port that installs, reads back and removes it, and the strict
//! read-back that must pass before the attempt is released (ADR-069 sections
//! 7 and 8, #911).
//!
//! The port speaks kernel state, not commands. An adapter installs an
//! [`ExpectedNamespace`] and reports the complete [`ObservedNamespace`] it
//! reads back. [`establish_namespace`] accepts the namespace only when the
//! read-back equals the expectation exactly: every link, address, route,
//! nftables table, chain and rule, with nothing missing and nothing extra.
//! Anything the adapter cannot represent in these types is an adapter error,
//! so unknown state also fails closed. Every failure removes what was
//! installed.

use std::error::Error;
use std::fmt;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};

mod attempt_network;
mod control;
mod firewall;
mod host_egress;
pub mod netlink;
mod pinned;
mod plan;
mod route;
mod rule_codec;

pub use attempt_network::{
    AttemptNetworkError, EgressProbe, EgressProbeError, NamespaceConnector, NamespacedLocalNetwork,
};
pub use control::{NetlinkNamespaceControl, OrphanSweepError};
pub use host_egress::{
    AttemptEgress, EgressControl, ForwardingRecords, HostEgress, HostEgressError,
    FORWARDING_RECORDS, HOST_TABLE,
};
pub use pinned::NetworkNamespaces;
pub use plan::{NetworkPlanError, NetworkRange, NAMESPACE_TABLE};
pub use rule_codec::{decode_firewall_rule, encode_firewall_rule, UndecodableRule};

/// The name of one attempt's network namespace: `piglor-` followed by the
/// attempt identity in lowercase hexadecimal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NamespaceName(String);

impl NamespaceName {
    /// The namespace name of `attempt_id`.
    #[must_use]
    pub fn for_attempt(attempt_id: [u8; 16]) -> Self {
        use std::fmt::Write;

        Self(
            attempt_id
                .iter()
                .fold(String::from("piglor-"), |mut name, byte| {
                    // Writing to a `String` cannot fail.
                    write!(name, "{byte:02x}").ok();
                    name
                }),
        )
    }

    /// The name as the kernel and `/run/netns` see it.
    #[must_use]
    pub const fn as_str(&self) -> &str {
        self.0.as_str()
    }

    /// The attempt namespace named `name`, if `name` is `piglor-` followed
    /// by 32 lowercase hexadecimal digits.
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        name.strip_prefix("piglor-")
            .filter(|hex| {
                hex.len() == 32
                    && hex
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            })
            .map(|_| Self(name.to_owned()))
    }
}

/// A network interface name: 1 to 15 bytes (the kernel's `IFNAMSIZ` less
/// its terminator) of ASCII letters, digits, `-` and `_`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LinkName(String);

impl LinkName {
    /// Check `name` as an interface name.
    ///
    /// # Errors
    /// Rejects an empty name, a name longer than 15 bytes and a name with any
    /// other byte.
    pub fn new(name: &str) -> Result<Self, InvalidLinkName> {
        let valid = (1..=15).contains(&name.len())
            && name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_');
        if valid {
            Ok(Self(name.to_owned()))
        } else {
            Err(InvalidLinkName)
        }
    }

    /// The name as the kernel sees it.
    #[must_use]
    pub const fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

/// A rejected interface name.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("invalid network interface name")]
pub struct InvalidLinkName;

/// An address, or a route destination, with its prefix length.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct IpPrefix {
    /// The address.
    pub address: IpAddr,
    /// The prefix length in bits.
    pub length: u8,
}

/// One main-table route, expected or read back.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct NamespaceRoute {
    /// The destination.
    pub destination: IpPrefix,
    /// The next hop, or `None` for a directly connected destination.
    pub gateway: Option<IpAddr>,
}

/// The nftables family of a table read back.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FirewallTableFamily {
    /// The `inet` family, which covers IPv4 and IPv6.
    Inet,
    /// Any other family.
    Other,
}

/// The netfilter hook of a base chain.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum FirewallHook {
    /// Packets addressed to the namespace.
    Input,
    /// Packets routed through the namespace.
    Forward,
    /// Packets the namespace sends.
    Output,
}

/// The verdict of a base chain's policy.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum FirewallVerdict {
    /// Let the packet pass.
    Accept,
    /// Discard the packet.
    Drop,
}

/// The hook, priority and policy of a base chain.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct FirewallBaseChain {
    /// Where the chain is attached.
    pub hook: FirewallHook,
    /// Its priority at that hook.
    pub priority: i32,
    /// The verdict for a packet no rule decides.
    pub policy: FirewallVerdict,
}

/// The only rules a provider-owned namespace firewall holds.
///
/// An adapter decodes each read-back rule into exactly one of these, or
/// fails; a rule with any other expression is never read back as one of them.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum FirewallRule {
    /// `ct state established,related accept`: return traffic of a connection
    /// the namespace opened.
    AcceptEstablished,
    /// Accept IPv6 with hop limit 255 carrying `ICMPv6` type 135 or 136
    /// (neighbour solicitation or advertisement): neighbour discovery
    /// arriving on the veth. A hop limit of 255 proves the packet was not
    /// routed, so it came from the host end.
    AcceptNeighbourDiscovery,
    /// Accept IPv6 to `destination/length` with hop limit 255 carrying `ICMPv6`
    /// type 135 or 136: neighbour discovery the namespace sends, only to
    /// `destination/length`. The namespace uses it for the solicited-node
    /// multicast range `ff02::1:ff00:0/104` and for the host end's address,
    /// so it can never carry data to an endpoint.
    SendNeighbourDiscovery {
        /// The destination network.
        destination: Ipv6Addr,
        /// Its prefix length.
        length: u8,
    },
    /// Accept TCP to exactly this authenticated endpoint address and port.
    AcceptTcp(SocketAddr),
}

/// One nftables chain, expected or read back.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct FirewallChain {
    /// The chain name.
    pub name: String,
    /// The hook, priority and policy of a base chain; `None` for a regular
    /// chain.
    pub base: Option<FirewallBaseChain>,
    /// The rules, in evaluation order.
    pub rules: Vec<FirewallRule>,
}

/// The complete state one attempt's namespace must have before release.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExpectedNamespace {
    /// The namespace.
    pub name: NamespaceName,
    /// The veth end inside the namespace.
    pub inner_link: LinkName,
    /// The veth end left in the host namespace.
    pub host_link: LinkName,
    /// Every address on the inner veth end.
    pub inner_addresses: Vec<IpPrefix>,
    /// Every address on the host veth end.
    pub host_addresses: Vec<IpPrefix>,
    /// Every main-table route inside the namespace, all through the inner
    /// veth end.
    pub routes: Vec<NamespaceRoute>,
    /// The name of the namespace's only nftables table, of family `inet`.
    pub table: String,
    /// Every chain of that table.
    pub chains: Vec<FirewallChain>,
}

/// The kind of a link read back.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LinkKind {
    /// A loopback device.
    Loopback,
    /// One end of a veth pair.
    Veth {
        /// The interface index of the other end, in that end's namespace.
        peer_index: u32,
        /// The identifier of the other end's namespace, as the namespace of
        /// this end numbers it (`IFLA_LINK_NETNSID`); `None` when the kernel
        /// reports none.
        peer_netnsid: Option<i32>,
    },
    /// Any other kind.
    Other,
}

/// One link read back.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObservedLink {
    /// The interface index in the link's namespace.
    pub index: u32,
    /// The interface name.
    pub name: String,
    /// What kind of link it is.
    pub kind: LinkKind,
    /// Whether it is administratively up.
    pub up: bool,
}

/// One interface address read back.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ObservedAddress {
    /// The index of the link that holds it.
    pub link_index: u32,
    /// The address and its prefix length.
    pub address: IpPrefix,
}

/// One main-table route read back.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ObservedRoute {
    /// The index of the output link.
    pub link_index: u32,
    /// The route.
    pub route: NamespaceRoute,
}

/// One nftables table read back.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObservedTable {
    /// Its family.
    pub family: FirewallTableFamily,
    /// Its name.
    pub name: String,
    /// Its `NFTA_TABLE_FLAGS`. A provider-owned table sets none: a dormant
    /// table, for example, would install rules that filter nothing.
    pub flags: u32,
    /// Every chain it holds.
    pub chains: Vec<FirewallChain>,
}

/// Everything an adapter read back for one attempt's namespace.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObservedNamespace {
    /// Every link inside the namespace.
    pub links: Vec<ObservedLink>,
    /// Every address inside the namespace, of both families.
    pub addresses: Vec<ObservedAddress>,
    /// Every main-table route inside the namespace, of both families.
    pub routes: Vec<ObservedRoute>,
    /// Every nftables table inside the namespace, of every family.
    pub tables: Vec<ObservedTable>,
    /// The host-namespace link with the expected host veth name, if any.
    pub host_link: Option<ObservedLink>,
    /// Every address on that host link, of both families.
    pub host_addresses: Vec<ObservedAddress>,
    /// The identifier the host namespace assigns to the attempt namespace.
    /// The adapter resolves it from the host namespace with `RTM_GETNSID`
    /// on a descriptor of namespace `name` itself (`NETNSA_FD`), never from
    /// a link attribute, so it names that namespace and no other.
    pub namespace_netnsid: i32,
    /// The identifier the attempt namespace assigns to the host namespace,
    /// resolved the same way from inside the attempt namespace on a
    /// descriptor of the host namespace.
    ///
    /// Both identifiers must be assigned: a negative identifier, such as
    /// `NETNSA_NSID_NOT_ASSIGNED` (-1), never verifies.
    pub host_netnsid: i32,
}

/// The first part of a read-back that differs from its expectation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ReadbackMismatch {
    /// The namespace holds other links than its down loopback and one veth
    /// end.
    #[error("the namespace holds other links than its loopback and veth end")]
    Links,
    /// The inner veth end is missing, down or not a veth.
    #[error("the namespace's veth end is missing, down or not a veth")]
    InnerLink,
    /// The host veth end is missing, down or not a veth.
    #[error("the host's veth end is missing, down or not a veth")]
    HostLink,
    /// The two veth ends are not each other's peer, by interface index and
    /// namespace.
    #[error("the veth ends are not each other's peer")]
    Peer,
    /// The inner veth end holds other addresses, or another link holds one.
    #[error("the namespace holds other addresses")]
    Addresses,
    /// The host veth end holds other addresses.
    #[error("the host's veth end holds other addresses")]
    HostAddresses,
    /// The namespace holds other routes, or one leaves through another link.
    #[error("the namespace holds other routes")]
    Routes,
    /// The namespace holds another table, chain or rule.
    #[error("the namespace holds another firewall")]
    Firewall,
}

impl ExpectedNamespace {
    /// Check that `observed` is exactly this namespace.
    ///
    /// Addresses, routes and chains are compared as sets, because the kernel
    /// reports them in its own order; the rules of each chain are compared in
    /// order, because their order decides each packet.
    ///
    /// # Errors
    /// Names the first part of `observed` that differs.
    pub fn verify(&self, observed: &ObservedNamespace) -> Result<(), ReadbackMismatch> {
        self.links(observed).and_then(|(inner, host)| {
            holds(
                same_addresses(&self.inner_addresses, inner, &observed.addresses),
                ReadbackMismatch::Addresses,
            )
            .and_then(|()| {
                holds(
                    same_addresses(&self.host_addresses, host, &observed.host_addresses),
                    ReadbackMismatch::HostAddresses,
                )
            })
            .and_then(|()| {
                holds(
                    observed
                        .routes
                        .iter()
                        .all(|route| route.link_index == inner)
                        && same_set(
                            &self.routes,
                            observed.routes.iter().map(|route| route.route),
                        ),
                    ReadbackMismatch::Routes,
                )
            })
            .and_then(|()| {
                holds(
                    self.same_firewall(&observed.tables),
                    ReadbackMismatch::Firewall,
                )
            })
        })
    }

    /// Check the links and return the interface indexes of the inner and the
    /// host veth end.
    fn links(&self, observed: &ObservedNamespace) -> Result<(u32, u32), ReadbackMismatch> {
        let loopback = observed
            .links
            .iter()
            .any(|link| link.kind == LinkKind::Loopback && link.name == "lo" && !link.up);
        let inner = observed
            .links
            .iter()
            .find(|link| link.name == self.inner_link.0)
            .and_then(up_veth);
        let host = observed
            .host_link
            .as_ref()
            .filter(|link| link.name == self.host_link.0)
            .and_then(up_veth);
        match (observed.links.len() == 2 && loopback, inner, host) {
            (false, _, _) => Err(ReadbackMismatch::Links),
            (true, None, _) => Err(ReadbackMismatch::InnerLink),
            (true, Some(_), None) => Err(ReadbackMismatch::HostLink),
            (true, Some((inner, inner_peer)), Some((host, host_peer))) => holds(
                observed.host_netnsid.min(observed.namespace_netnsid) >= 0
                    && inner_peer == (host, Some(observed.host_netnsid))
                    && host_peer == (inner, Some(observed.namespace_netnsid)),
                ReadbackMismatch::Peer,
            )
            .map(|()| (inner, host)),
        }
    }

    /// Whether `tables` is exactly this namespace's one `inet` table.
    fn same_firewall(&self, tables: &[ObservedTable]) -> bool {
        match tables {
            [table] => {
                table.family == FirewallTableFamily::Inet
                    && table.name == self.table
                    && table.flags == 0
                    && same_set(&self.chains, table.chains.iter().cloned())
            }
            _ => false,
        }
    }
}

/// `Ok` when `condition` holds, and `mismatch` otherwise.
const fn holds(condition: bool, mismatch: ReadbackMismatch) -> Result<(), ReadbackMismatch> {
    if condition {
        Ok(())
    } else {
        Err(mismatch)
    }
}

/// The index of a veth end that is up, with its peer's index and namespace.
const fn up_veth(link: &ObservedLink) -> Option<(u32, (u32, Option<i32>))> {
    match link.kind {
        LinkKind::Veth {
            peer_index,
            peer_netnsid,
        } if link.up => Some((link.index, (peer_index, peer_netnsid))),
        _ => None,
    }
}

/// Whether `observed` holds exactly the `expected` prefixes, all on link
/// `index`.
fn same_addresses(expected: &[IpPrefix], index: u32, observed: &[ObservedAddress]) -> bool {
    observed.iter().all(|address| address.link_index == index)
        && same_set(expected, observed.iter().map(|address| address.address))
}

/// Whether `observed` holds exactly the elements of `expected`, each as often,
/// in any order.
fn same_set<T: Clone + Ord>(expected: &[T], observed: impl Iterator<Item = T>) -> bool {
    let mut expected = expected.to_vec();
    let mut observed: Vec<T> = observed.collect();
    expected.sort_unstable();
    observed.sort_unstable();
    expected == observed
}

/// The kernel-facing port of one attempt's namespace.
///
/// An adapter changes and reads kernel state only; it never decides what the
/// state should be. It must remove whatever part of its own namespace exists,
/// so a failed install can be undone, and never touch another attempt's.
///
/// A crash between install and removal leaves no journal. Restart
/// reconciliation therefore sweeps every `piglor-` namespace and every
/// `piglor-` host link whose peer namespace is gone, by name prefix, before
/// admission opens.
pub trait NamespaceControl {
    /// Why the kernel refused or could not report a change.
    type Error: Error + Send + Sync + 'static;

    /// Create the namespace, veth pair, addresses, routes and firewall of
    /// `expected`.
    ///
    /// The adapter must:
    /// - create the namespace exclusively, and fail if a namespace named
    ///   `name` exists, so [`NamespaceControl::remove`] never deletes a
    ///   namespace this attempt does not own;
    /// - create the veth pair in one request, so it never adopts an existing
    ///   `host_link`, and fail if that name exists;
    /// - assign each namespace an identifier for the other, so both veth
    ///   ends report their peer's namespace;
    /// - set `addr_gen_mode` to `none` on both ends before either is up, so
    ///   the kernel adds no link-local address or route, and add the
    ///   addresses with `IFA_F_NODAD`, so none is tentative;
    /// - install the firewall before either end is up, so no packet passes
    ///   before the policy exists;
    /// - encode each [`FirewallRule`] with the protocol matches its other
    ///   matches depend on: the `nfproto` match before an IPv6 address or
    ///   hop-limit match, and the `l4proto` match before a TCP port or
    ///   `ICMPv6` type match.
    ///
    /// Host forwarding, `rp_filter` and the host firewall are not part of
    /// this namespace.
    ///
    /// # Errors
    /// Fails if any part cannot be created. A partial namespace may remain.
    fn install(&self, expected: &ExpectedNamespace) -> Result<(), Self::Error>;

    /// Read back the complete state of namespace `name` and of the host veth
    /// end `host_link`.
    ///
    /// # Errors
    /// Fails if any part cannot be read, or holds state these types cannot
    /// represent.
    fn observe(
        &self,
        name: &NamespaceName,
        host_link: &LinkName,
    ) -> Result<ObservedNamespace, Self::Error>;

    /// Remove namespace `name`, whichever parts of it exist.
    ///
    /// A host link named `host_link` is removed only while its peer lies in
    /// namespace `name`. A host link of that name whose peer lies elsewhere
    /// belongs to another attempt, or to an orphan reconciliation owns, and is
    /// left untouched.
    ///
    /// # Errors
    /// Fails if a part that exists cannot be removed.
    fn remove(&self, name: &NamespaceName, host_link: &LinkName) -> Result<(), Self::Error>;
}

/// What failed while a namespace was established.
#[derive(Debug, thiserror::Error)]
pub enum EstablishFailure<E> {
    /// The namespace could not be installed.
    #[error("the attempt namespace could not be installed")]
    Install(#[source] E),
    /// The namespace could not be read back.
    #[error("the attempt namespace could not be read back")]
    Observe(#[source] E),
    /// The namespace read back differently from its expectation.
    #[error("the attempt namespace read back differently")]
    Readback(#[source] ReadbackMismatch),
}

/// A namespace that could not be established.
#[derive(Debug)]
pub struct EstablishError<E> {
    /// What failed.
    pub failure: EstablishFailure<E>,
    /// Why the namespace could not be removed afterwards, if it could not.
    /// Restart reconciliation must then remove it.
    pub removal: Option<E>,
}

impl<E: fmt::Display> fmt::Display for EstablishError<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .write_str("the attempt namespace could not be established")
            .and_then(|()| {
                self.removal.as_ref().map_or(Ok(()), |removal| {
                    write!(formatter, ", and removing it failed: {removal}")
                })
            })
    }
}

impl<E: Error + 'static> Error for EstablishError<E> {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.failure)
    }
}

/// Install `expected` through `control`, read it back, and accept it only if
/// the read-back is exactly `expected`.
///
/// # Errors
/// Fails if installation, read-back or verification fails. The namespace is
/// removed first; the error records a removal that failed as well.
pub fn establish_namespace<C: NamespaceControl>(
    control: &C,
    expected: &ExpectedNamespace,
) -> Result<(), EstablishError<C::Error>> {
    let (name, host_link) = (&expected.name, &expected.host_link);
    control
        .install(expected)
        .map_err(EstablishFailure::Install)
        .and_then(|()| {
            control
                .observe(name, host_link)
                .map_err(EstablishFailure::Observe)
        })
        .and_then(|observed| {
            expected
                .verify(&observed)
                .map_err(EstablishFailure::Readback)
        })
        .map_err(|failure| EstablishError {
            failure,
            removal: control.remove(name, host_link).err(),
        })
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests;
