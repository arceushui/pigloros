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
use std::net::{IpAddr, SocketAddr};

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
    /// `icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert } accept`: the
    /// minimum neighbour discovery IPv6 needs on the veth.
    AcceptNeighbourDiscovery,
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
    /// The two veth ends are not each other's peer.
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
                inner_peer == host && host_peer == inner,
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

/// The index and peer index of a veth end that is up.
const fn up_veth(link: &ObservedLink) -> Option<(u32, u32)> {
    match link.kind {
        LinkKind::Veth { peer_index } if link.up => Some((link.index, peer_index)),
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
/// state should be. It must remove whatever part of a namespace exists, so a
/// failed install can be undone.
pub trait NamespaceControl {
    /// Why the kernel refused or could not report a change.
    type Error: Error + Send + Sync + 'static;

    /// Create the namespace, veth pair, addresses, routes and firewall of
    /// `expected`.
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

    /// Remove namespace `name` and the host veth end `host_link`, whichever
    /// parts of them exist.
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
#[derive(Debug, thiserror::Error)]
#[error("the attempt namespace could not be established")]
pub struct EstablishError<E> {
    /// What failed.
    #[source]
    pub failure: EstablishFailure<E>,
    /// Why the namespace could not be removed afterwards, if it could not.
    /// Restart reconciliation must then remove it.
    pub removal: Option<E>,
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
