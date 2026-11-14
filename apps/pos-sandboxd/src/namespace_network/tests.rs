use std::{
    cell::RefCell,
    error::Error,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
};

use super::*;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const ATTEMPT: [u8; 16] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0xdd, 0xee, 0xff,
];
const INNER: u32 = 2;
const HOST: u32 = 41;
/// The identifier the host assigns to the attempt namespace.
const NAMESPACE_ID: i32 = 5;
/// The identifier the attempt namespace assigns to the host namespace.
const HOST_ID: i32 = 0;

const fn v4(last: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(10, 77, 0, last))
}

const fn v6(last: u16) -> IpAddr {
    IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, last))
}

const fn prefix(address: IpAddr, length: u8) -> IpPrefix {
    IpPrefix { address, length }
}

const fn endpoint() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7)), 8443)
}

fn base(hook: FirewallHook, rules: Vec<FirewallRule>) -> FirewallChain {
    FirewallChain {
        name: format!("{hook:?}").to_lowercase(),
        base: Some(FirewallBaseChain {
            hook,
            priority: 0,
            policy: FirewallVerdict::Drop,
        }),
        rules,
    }
}

fn chains() -> Vec<FirewallChain> {
    vec![
        base(
            FirewallHook::Input,
            vec![
                FirewallRule::AcceptEstablished,
                FirewallRule::AcceptNeighbourDiscovery,
            ],
        ),
        base(
            FirewallHook::Output,
            vec![
                FirewallRule::SendNeighbourDiscovery {
                    destination: Ipv6Addr::new(0xff02, 0, 0, 0, 0, 1, 0xff00, 0),
                    length: 104,
                },
                FirewallRule::SendNeighbourDiscovery {
                    destination: Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0),
                    length: 128,
                },
                FirewallRule::AcceptTcp(endpoint()),
            ],
        ),
        base(FirewallHook::Forward, Vec::new()),
    ]
}

fn routes() -> Vec<NamespaceRoute> {
    vec![
        NamespaceRoute {
            destination: prefix(v4(0), 30),
            gateway: None,
        },
        NamespaceRoute {
            destination: prefix(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
            gateway: Some(v4(1)),
        },
        NamespaceRoute {
            destination: prefix(v6(0), 127),
            gateway: None,
        },
        NamespaceRoute {
            destination: prefix(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
            gateway: Some(v6(0)),
        },
    ]
}

fn expected() -> TestResult<ExpectedNamespace> {
    Ok(ExpectedNamespace {
        name: NamespaceName::for_attempt(ATTEMPT),
        inner_link: LinkName::new("piglor-n0")?,
        host_link: LinkName::new("piglor-h0")?,
        inner_addresses: vec![prefix(v4(2), 30), prefix(v6(1), 127)],
        host_addresses: vec![prefix(v4(1), 30), prefix(v6(0), 127)],
        routes: routes(),
        table: "piglor_attempt".to_owned(),
        chains: chains(),
    })
}

fn link(index: u32, name: &str, kind: LinkKind, up: bool) -> ObservedLink {
    ObservedLink {
        index,
        name: name.to_owned(),
        kind,
        up,
    }
}

const fn on(link_index: u32, address: IpPrefix) -> ObservedAddress {
    ObservedAddress {
        link_index,
        address,
    }
}

/// The exact read-back of `expected()`, listed in another order than the
/// expectation wherever order does not matter.
fn observed() -> ObservedNamespace {
    let mut chains = chains();
    chains.reverse();
    let mut routes: Vec<ObservedRoute> = routes()
        .into_iter()
        .map(|route| ObservedRoute {
            link_index: INNER,
            route,
        })
        .collect();
    routes.reverse();
    ObservedNamespace {
        links: vec![
            link(
                INNER,
                "piglor-n0",
                LinkKind::Veth {
                    peer_index: HOST,
                    peer_netnsid: Some(HOST_ID),
                },
                true,
            ),
            link(1, "lo", LinkKind::Loopback, false),
        ],
        addresses: vec![on(INNER, prefix(v6(1), 127)), on(INNER, prefix(v4(2), 30))],
        routes,
        tables: vec![ObservedTable {
            family: FirewallTableFamily::Inet,
            name: "piglor_attempt".to_owned(),
            flags: 0,
            chains,
        }],
        host_link: Some(link(
            HOST,
            "piglor-h0",
            LinkKind::Veth {
                peer_index: INNER,
                peer_netnsid: Some(NAMESPACE_ID),
            },
            true,
        )),
        host_addresses: vec![on(HOST, prefix(v6(0), 127)), on(HOST, prefix(v4(1), 30))],
        namespace_netnsid: NAMESPACE_ID,
        host_netnsid: HOST_ID,
    }
}

fn mismatch(
    change: impl FnOnce(&mut ObservedNamespace),
) -> TestResult<Result<(), ReadbackMismatch>> {
    let mut observed = observed();
    change(&mut observed);
    Ok(expected()?.verify(&observed))
}

#[test]
fn namespace_name_is_the_prefixed_lowercase_attempt_identity() {
    assert_eq!(
        NamespaceName::for_attempt(ATTEMPT).as_str(),
        "piglor-000102030405060708090a0b0cddeeff"
    );
}

#[test]
fn link_names_are_short_kernel_interface_names() -> TestResult {
    for name in ["a", "piglor-h0", "under_score-1", "fifteen-bytes15"] {
        assert_eq!(LinkName::new(name)?.as_str(), name);
    }
    for name in ["", "sixteen-bytes-16", "dot.ted", "sp ace", "slash/", "ünï"] {
        assert_eq!(LinkName::new(name), Err(InvalidLinkName));
    }
    assert_eq!(
        InvalidLinkName.to_string(),
        "invalid network interface name"
    );
    Ok(())
}

#[test]
fn an_exact_readback_in_kernel_order_verifies() -> TestResult {
    assert_eq!(mismatch(|_| ())?, Ok(()));
    Ok(())
}

#[test]
fn extra_missing_or_wrong_namespace_links_are_refused() -> TestResult {
    let extra = |observed: &mut ObservedNamespace| {
        observed.links.push(link(3, "eth0", LinkKind::Other, false));
    };
    let missing_loopback = |observed: &mut ObservedNamespace| {
        observed.links.truncate(1);
    };
    let loopback_up = |observed: &mut ObservedNamespace| observed.links[1].up = true;
    let loopback_renamed = |observed: &mut ObservedNamespace| observed.links[1].name = "lo0".into();
    let loopback_kind = |observed: &mut ObservedNamespace| observed.links[1].kind = LinkKind::Other;
    for change in [
        &extra as &dyn Fn(&mut ObservedNamespace),
        &missing_loopback,
        &loopback_up,
        &loopback_renamed,
        &loopback_kind,
    ] {
        assert_eq!(mismatch(change)?, Err(ReadbackMismatch::Links));
    }
    Ok(())
}

#[test]
fn a_missing_down_or_foreign_inner_veth_is_refused() -> TestResult {
    let renamed = |observed: &mut ObservedNamespace| observed.links[0].name = "piglor-n1".into();
    let down = |observed: &mut ObservedNamespace| observed.links[0].up = false;
    let not_veth = |observed: &mut ObservedNamespace| observed.links[0].kind = LinkKind::Other;
    for change in [
        &renamed as &dyn Fn(&mut ObservedNamespace),
        &down,
        &not_veth,
    ] {
        assert_eq!(mismatch(change)?, Err(ReadbackMismatch::InnerLink));
    }
    Ok(())
}

#[test]
fn a_missing_down_or_foreign_host_veth_is_refused() -> TestResult {
    let absent = |observed: &mut ObservedNamespace| observed.host_link = None;
    let renamed = |observed: &mut ObservedNamespace| {
        if let Some(host) = observed.host_link.as_mut() {
            host.name = "piglor-h1".into();
        }
    };
    let down = |observed: &mut ObservedNamespace| {
        if let Some(host) = observed.host_link.as_mut() {
            host.up = false;
        }
    };
    let loopback = |observed: &mut ObservedNamespace| {
        if let Some(host) = observed.host_link.as_mut() {
            host.kind = LinkKind::Loopback;
        }
    };
    for change in [
        &absent as &dyn Fn(&mut ObservedNamespace),
        &renamed,
        &down,
        &loopback,
    ] {
        assert_eq!(mismatch(change)?, Err(ReadbackMismatch::HostLink));
    }
    Ok(())
}

#[test]
fn veth_ends_that_are_not_each_others_peer_are_refused() -> TestResult {
    let inner = |peer_index, peer_netnsid| {
        move |observed: &mut ObservedNamespace| {
            observed.links[0].kind = LinkKind::Veth {
                peer_index,
                peer_netnsid,
            };
        }
    };
    let host = |peer_index, peer_netnsid| {
        move |observed: &mut ObservedNamespace| {
            if let Some(host) = observed.host_link.as_mut() {
                host.kind = LinkKind::Veth {
                    peer_index,
                    peer_netnsid,
                };
            }
        }
    };
    // Interface indexes are per namespace: the same index in another
    // namespace is another link.
    let inner_index = inner(HOST + 1, Some(HOST_ID));
    let inner_namespace = inner(HOST, Some(HOST_ID + 1));
    let inner_unnamed = inner(HOST, None);
    let host_index = host(INNER + 1, Some(NAMESPACE_ID));
    let host_namespace = host(INNER, Some(NAMESPACE_ID + 1));
    let host_unnamed = host(INNER, None);
    let renumbered_namespace = |observed: &mut ObservedNamespace| observed.namespace_netnsid = 6;
    let renumbered_host = |observed: &mut ObservedNamespace| observed.host_netnsid = 1;
    for change in [
        &inner_index as &dyn Fn(&mut ObservedNamespace),
        &inner_namespace,
        &inner_unnamed,
        &host_index,
        &host_namespace,
        &host_unnamed,
        &renumbered_namespace,
        &renumbered_host,
    ] {
        assert_eq!(mismatch(change)?, Err(ReadbackMismatch::Peer));
    }
    Ok(())
}

#[test]
fn unassigned_namespace_identifiers_are_refused() -> TestResult {
    // Both ends agree, but on `NETNSA_NSID_NOT_ASSIGNED`, which names no
    // namespace.
    let unassigned = |namespace: i32, host: i32| {
        move |observed: &mut ObservedNamespace| {
            observed.links[0].kind = LinkKind::Veth {
                peer_index: HOST,
                peer_netnsid: Some(host),
            };
            if let Some(link) = observed.host_link.as_mut() {
                link.kind = LinkKind::Veth {
                    peer_index: INNER,
                    peer_netnsid: Some(namespace),
                };
            }
            observed.namespace_netnsid = namespace;
            observed.host_netnsid = host;
        }
    };
    assert_eq!(
        mismatch(unassigned(-1, HOST_ID))?,
        Err(ReadbackMismatch::Peer)
    );
    assert_eq!(
        mismatch(unassigned(NAMESPACE_ID, -1))?,
        Err(ReadbackMismatch::Peer)
    );
    assert_eq!(mismatch(unassigned(NAMESPACE_ID, HOST_ID))?, Ok(()));
    Ok(())
}

#[test]
fn other_inner_addresses_are_refused() -> TestResult {
    let extra = |observed: &mut ObservedNamespace| {
        observed.addresses.push(on(INNER, prefix(v4(3), 30)));
    };
    let missing = |observed: &mut ObservedNamespace| {
        observed.addresses.pop();
    };
    let duplicated = |observed: &mut ObservedNamespace| {
        observed.addresses[1] = observed.addresses[0];
    };
    let length = |observed: &mut ObservedNamespace| observed.addresses[0].address.length = 64;
    let on_loopback = |observed: &mut ObservedNamespace| observed.addresses[0].link_index = 1;
    for change in [
        &extra as &dyn Fn(&mut ObservedNamespace),
        &missing,
        &duplicated,
        &length,
        &on_loopback,
    ] {
        assert_eq!(mismatch(change)?, Err(ReadbackMismatch::Addresses));
    }
    Ok(())
}

#[test]
fn other_host_addresses_are_refused() -> TestResult {
    let extra = |observed: &mut ObservedNamespace| {
        observed.host_addresses.push(on(HOST, prefix(v6(2), 127)));
    };
    let foreign = |observed: &mut ObservedNamespace| observed.host_addresses[0].link_index = INNER;
    let changed = |observed: &mut ObservedNamespace| {
        observed.host_addresses[1].address = prefix(v4(5), 30);
    };
    for change in [
        &extra as &dyn Fn(&mut ObservedNamespace),
        &foreign,
        &changed,
    ] {
        assert_eq!(mismatch(change)?, Err(ReadbackMismatch::HostAddresses));
    }
    Ok(())
}

#[test]
fn other_routes_are_refused() -> TestResult {
    let extra = |observed: &mut ObservedNamespace| {
        observed.routes.push(ObservedRoute {
            link_index: INNER,
            route: NamespaceRoute {
                destination: prefix(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 0)), 24),
                gateway: Some(v4(1)),
            },
        });
    };
    let missing = |observed: &mut ObservedNamespace| {
        observed.routes.pop();
    };
    let gateway = |observed: &mut ObservedNamespace| observed.routes[0].route.gateway = Some(v6(9));
    let through_loopback = |observed: &mut ObservedNamespace| observed.routes[0].link_index = 1;
    for change in [
        &extra as &dyn Fn(&mut ObservedNamespace),
        &missing,
        &gateway,
        &through_loopback,
    ] {
        assert_eq!(mismatch(change)?, Err(ReadbackMismatch::Routes));
    }
    Ok(())
}

#[test]
fn another_table_chain_or_rule_is_refused() -> TestResult {
    let no_table = |observed: &mut ObservedNamespace| observed.tables.clear();
    let second_table = |observed: &mut ObservedNamespace| {
        let copy = observed.tables[0].clone();
        observed.tables.push(copy);
    };
    let family = |observed: &mut ObservedNamespace| {
        observed.tables[0].family = FirewallTableFamily::Other;
    };
    let name = |observed: &mut ObservedNamespace| observed.tables[0].name = "filter".into();
    // `NFT_TABLE_F_DORMANT`: the rules would filter nothing.
    let dormant = |observed: &mut ObservedNamespace| observed.tables[0].flags = 1;
    let missing_chain = |observed: &mut ObservedNamespace| {
        observed.tables[0].chains.pop();
    };
    let regular_chain = |observed: &mut ObservedNamespace| {
        observed.tables[0].chains[0].base = None;
    };
    let accept_policy = |observed: &mut ObservedNamespace| {
        if let Some(base) = observed.tables[0].chains[0].base.as_mut() {
            base.policy = FirewallVerdict::Accept;
        }
    };
    let priority = |observed: &mut ObservedNamespace| {
        if let Some(base) = observed.tables[0].chains[0].base.as_mut() {
            base.priority = -1;
        }
    };
    let hook = |observed: &mut ObservedNamespace| {
        if let Some(base) = observed.tables[0].chains[0].base.as_mut() {
            base.hook = FirewallHook::Output;
        }
    };
    // The reversed chains put output second.
    let reordered_rules = |observed: &mut ObservedNamespace| {
        observed.tables[0].chains[1].rules.reverse();
    };
    let other_endpoint = |observed: &mut ObservedNamespace| {
        observed.tables[0].chains[1].rules[2] =
            FirewallRule::AcceptTcp(SocketAddr::new(endpoint().ip(), 8444));
    };
    let wider_discovery = |observed: &mut ObservedNamespace| {
        observed.tables[0].chains[1].rules[1] = FirewallRule::SendNeighbourDiscovery {
            destination: Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0),
            length: 64,
        };
    };
    let discovery_elsewhere = |observed: &mut ObservedNamespace| {
        observed.tables[0].chains[1].rules[0] = FirewallRule::SendNeighbourDiscovery {
            destination: Ipv6Addr::new(0xff05, 0, 0, 0, 0, 0, 0, 0),
            length: 16,
        };
    };
    let unrestricted_discovery = |observed: &mut ObservedNamespace| {
        observed.tables[0].chains[1].rules[0] = FirewallRule::AcceptNeighbourDiscovery;
    };
    let extra_rule = |observed: &mut ObservedNamespace| {
        observed.tables[0].chains[0]
            .rules
            .push(FirewallRule::AcceptEstablished);
    };
    for change in [
        &no_table as &dyn Fn(&mut ObservedNamespace),
        &second_table,
        &family,
        &name,
        &dormant,
        &missing_chain,
        &regular_chain,
        &accept_policy,
        &priority,
        &hook,
        &reordered_rules,
        &other_endpoint,
        &wider_discovery,
        &discovery_elsewhere,
        &unrestricted_discovery,
        &extra_rule,
    ] {
        assert_eq!(mismatch(change)?, Err(ReadbackMismatch::Firewall));
    }
    Ok(())
}

#[test]
fn mismatches_name_the_part_that_differs() {
    let messages = [
        (
            ReadbackMismatch::Links,
            "the namespace holds other links than its loopback and veth end",
        ),
        (
            ReadbackMismatch::InnerLink,
            "the namespace's veth end is missing, down or not a veth",
        ),
        (
            ReadbackMismatch::HostLink,
            "the host's veth end is missing, down or not a veth",
        ),
        (
            ReadbackMismatch::Peer,
            "the veth ends are not each other's peer",
        ),
        (
            ReadbackMismatch::Addresses,
            "the namespace holds other addresses",
        ),
        (
            ReadbackMismatch::HostAddresses,
            "the host's veth end holds other addresses",
        ),
        (ReadbackMismatch::Routes, "the namespace holds other routes"),
        (
            ReadbackMismatch::Firewall,
            "the namespace holds another firewall",
        ),
    ];
    for (mismatch, message) in messages {
        assert_eq!(mismatch.to_string(), message);
    }
}

#[derive(Debug, thiserror::Error)]
#[error("kernel refused {0}")]
struct KernelError(&'static str);

/// A namespace control that records every call, fails where told to, and
/// models host links as `(name, peer namespace)` pairs.
struct FakeControl {
    fail: Vec<&'static str>,
    observed: ObservedNamespace,
    calls: RefCell<Vec<(&'static str, String, String)>>,
    host_links: RefCell<Vec<(String, String)>>,
}

impl FakeControl {
    fn new(fail: &[&'static str]) -> Self {
        Self {
            fail: fail.to_vec(),
            observed: observed(),
            calls: RefCell::default(),
            host_links: RefCell::default(),
        }
    }

    fn call(
        &self,
        step: &'static str,
        name: &NamespaceName,
        host_link: &LinkName,
    ) -> Result<(), KernelError> {
        self.calls.borrow_mut().push((
            step,
            name.as_str().to_owned(),
            host_link.as_str().to_owned(),
        ));
        if self.fail.contains(&step) {
            Err(KernelError(step))
        } else {
            Ok(())
        }
    }

    fn steps(&self) -> Vec<&'static str> {
        self.calls.borrow().iter().map(|call| call.0).collect()
    }
}

impl NamespaceControl for FakeControl {
    type Error = KernelError;

    fn install(&self, expected: &ExpectedNamespace) -> Result<(), KernelError> {
        let host = expected.host_link.as_str().to_owned();
        let taken = self.host_links.borrow().iter().any(|link| link.0 == host);
        self.call("install", &expected.name, &expected.host_link)
            .and_then(|()| {
                (!taken)
                    .then_some(())
                    .ok_or(KernelError("existing host link"))
            })
            .map(|()| {
                self.host_links
                    .borrow_mut()
                    .push((host, expected.name.as_str().to_owned()));
            })
    }

    fn observe(
        &self,
        name: &NamespaceName,
        host_link: &LinkName,
    ) -> Result<ObservedNamespace, KernelError> {
        self.call("observe", name, host_link)
            .map(|()| self.observed.clone())
    }

    fn remove(&self, name: &NamespaceName, host_link: &LinkName) -> Result<(), KernelError> {
        self.call("remove", name, host_link).map(|()| {
            self.host_links.borrow_mut().retain(|link| {
                (link.0.as_str(), link.1.as_str()) != (host_link.as_str(), name.as_str())
            });
        })
    }
}

#[test]
fn establishing_installs_then_reads_back_and_keeps_an_exact_namespace() -> TestResult {
    let control = FakeControl::new(&[]);
    let expected = expected()?;
    establish_namespace(&control, &expected)?;
    let name = expected.name.as_str().to_owned();
    let host = "piglor-h0".to_owned();
    assert_eq!(
        *control.calls.borrow(),
        vec![
            ("install", name.clone(), host.clone()),
            ("observe", name, host),
        ]
    );
    Ok(())
}

#[test]
fn a_failed_install_is_removed() -> TestResult {
    let control = FakeControl::new(&["install"]);
    let error = establish_namespace(&control, &expected()?)
        .err()
        .ok_or("a failed install must not establish")?;
    assert!(matches!(
        error.failure,
        EstablishFailure::Install(KernelError("install"))
    ));
    assert!(error.removal.is_none());
    assert_eq!(control.steps(), ["install", "remove"]);
    assert_eq!(
        error.to_string(),
        "the attempt namespace could not be established"
    );
    assert!(control.host_links.borrow().is_empty());
    assert_eq!(
        error.source().map(ToString::to_string).as_deref(),
        Some("the attempt namespace could not be installed")
    );
    Ok(())
}

#[test]
fn a_failed_readback_is_removed() -> TestResult {
    let control = FakeControl::new(&["observe"]);
    let error = establish_namespace(&control, &expected()?)
        .err()
        .ok_or("a failed read-back must not establish")?;
    assert!(matches!(
        error.failure,
        EstablishFailure::Observe(KernelError("observe"))
    ));
    assert!(error.removal.is_none());
    assert_eq!(control.steps(), ["install", "observe", "remove"]);
    assert_eq!(
        error.failure.to_string(),
        "the attempt namespace could not be read back"
    );
    // The removal took the link this install created.
    assert!(control.host_links.borrow().is_empty());
    Ok(())
}

#[test]
fn a_differing_readback_is_removed() -> TestResult {
    let mut control = FakeControl::new(&[]);
    let mut differing = observed();
    differing.routes.clear();
    control.observed = differing;
    let error = establish_namespace(&control, &expected()?)
        .err()
        .ok_or("a differing read-back must not establish")?;
    assert!(matches!(
        error.failure,
        EstablishFailure::Readback(ReadbackMismatch::Routes)
    ));
    assert!(error.removal.is_none());
    assert_eq!(control.steps(), ["install", "observe", "remove"]);
    assert_eq!(
        error.failure.to_string(),
        "the attempt namespace read back differently"
    );
    Ok(())
}

#[test]
fn a_failed_removal_is_reported_for_reconciliation() -> TestResult {
    let control = FakeControl::new(&["install", "remove"]);
    let error = establish_namespace(&control, &expected()?)
        .err()
        .ok_or("a failed install must not establish")?;
    assert!(matches!(error.failure, EstablishFailure::Install(_)));
    assert_eq!(
        error.removal.as_ref().map(ToString::to_string).as_deref(),
        Some("kernel refused remove")
    );
    assert_eq!(control.steps(), ["install", "remove"]);
    assert_eq!(
        error.to_string(),
        "the attempt namespace could not be established, and removing it failed: \
         kernel refused remove"
    );
    Ok(())
}

#[test]
fn another_attempts_host_link_survives_a_failed_establish() -> TestResult {
    let control = FakeControl::new(&[]);
    let other = ("piglor-h0".to_owned(), "piglor-other".to_owned());
    control.host_links.borrow_mut().push(other.clone());
    let error = establish_namespace(&control, &expected()?)
        .err()
        .ok_or("a taken host link must not establish")?;
    assert!(matches!(
        error.failure,
        EstablishFailure::Install(KernelError("existing host link"))
    ));
    assert!(error.removal.is_none());
    assert_eq!(control.steps(), ["install", "remove"]);
    assert_eq!(*control.host_links.borrow(), [other]);
    Ok(())
}

#[test]
fn only_prefixed_lowercase_attempt_identities_parse_as_namespace_names() {
    let name = NamespaceName::for_attempt([0xab; 16]);
    assert_eq!(NamespaceName::parse(name.as_str()), Some(name));
    for other in [
        "piglor-",
        "piglor-abababababababababababababababab00",
        "piglor-ABABABABABABABABABABABABABABABAB",
        "piglor-abababababababababababababababag",
        "other-abababababababababababababababab",
    ] {
        assert_eq!(NamespaceName::parse(other), None, "{other}");
    }
}
