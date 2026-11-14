use std::{cell::RefCell, collections::VecDeque, error::Error, num::NonZeroI32};

use netlink_packet_core::{ErrorMessage, NetlinkHeader, NetlinkMessage, NetlinkPayload};
use netlink_packet_route::RouteNetlinkMessage;

use super::super::host_egress::{ForwardingRecords, HostEgressError};
use super::*;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

/// A transport that answers with scripted datagrams, then fails.
struct Scripted(RefCell<VecDeque<Vec<u8>>>);

impl NetlinkTransport for Scripted {
    fn send(&self, _datagram: &[u8]) -> Result<(), NetlinkError> {
        Ok(())
    }

    fn receive(&self) -> Result<Vec<u8>, NetlinkError> {
        self.0
            .borrow_mut()
            .pop_front()
            .ok_or(NetlinkError::Truncated)
    }
}

/// A session that answers each request with the next of `replies`.
fn scripted(replies: Vec<Vec<u8>>) -> NetlinkSession<Scripted> {
    NetlinkSession::new(Scripted(RefCell::new(VecDeque::from(replies))))
}

/// The kernel's refusal of request `sequence` with `code`.
fn refusal(sequence: u32, code: i32) -> Vec<u8> {
    let mut error = ErrorMessage::default();
    error.code = NonZeroI32::new(code);
    let mut header = NetlinkHeader::default();
    header.sequence_number = sequence;
    let mut message =
        NetlinkMessage::<RouteNetlinkMessage>::new(header, NetlinkPayload::Error(error));
    message.finalize();
    let mut bytes = vec![0; message.buffer_len()];
    message.serialize(&mut bytes);
    bytes
}

#[test]
fn the_sweep_restores_forwarding_before_it_touches_the_host_table() -> TestResult {
    let directory = tempfile::tempdir()?;
    let control = NetlinkNamespaceControl::new(NetworkNamespaces::pinned_under(
        directory.path().join("netns"),
    ));
    let records = ForwardingRecords::in_directory(directory.path().join("forwarding"));
    records.record(7, "eth0")?;
    let opened = RefCell::new(Vec::new());
    let route_opened = |replies: Vec<Vec<u8>>| -> Result<NetlinkSession<Scripted>, NetlinkError> {
        opened.borrow_mut().push("route");
        Ok(scripted(replies))
    };
    let netfilter = || -> Result<NetlinkSession<Scripted>, NetlinkError> {
        opened.borrow_mut().push("netfilter");
        Ok(scripted(Vec::new()))
    };
    // Link 7 cannot be read, so its forwarding cannot be restored: the host
    // table, whose drop rule still guards, is never opened, and the record
    // stays.
    let unrestored =
        control.remove_orphans_through(|| route_opened(Vec::new()), netfilter, &records);
    assert!(
        matches!(
            unrestored,
            Err(OrphanSweepError::Forwarding(HostEgressError::Netlink(
                NetlinkError::Truncated
            )))
        ),
        "{unrestored:?}"
    );
    assert_eq!(*opened.borrow(), ["route"]);
    assert_eq!(records.recorded()?, [(7, "eth0".to_owned())]);
    // Link 7 is gone, so its record goes; only then is the table deleted,
    // here by a session that never answers.
    let gone = || route_opened(vec![refusal(1, route::NO_SUCH_LINK)]);
    let swept = control.remove_orphans_through(gone, netfilter, &records);
    assert!(
        matches!(
            swept,
            Err(OrphanSweepError::Netlink(NetlinkError::Truncated))
        ),
        "{swept:?}"
    );
    assert_eq!(*opened.borrow(), ["route", "route", "netfilter"]);
    assert!(records.recorded()?.is_empty());
    Ok(())
}

#[test]
fn a_missing_namespace_is_not_observed_and_removes_as_nothing() -> TestResult {
    let directory = tempfile::tempdir()?;
    let control = NetlinkNamespaceControl::new(NetworkNamespaces::pinned_under(directory.path()));
    let name = NamespaceName::for_attempt([3; 16]);
    let host_link = LinkName::new("piglor-h3")?;
    assert!(matches!(
        control.observe(&name, &host_link),
        Err(NetlinkError::Io(Errno::NOENT))
    ));
    assert!(control.remove(&name, &host_link).is_ok());
    Ok(())
}

#[test]
fn only_attempt_and_probe_veth_ends_are_the_providers_and_nothing_may_remain() {
    let link = |name: &str, kind| ObservedLink {
        index: 1,
        name: name.to_owned(),
        kind,
        up: true,
    };
    let veth = LinkKind::Veth {
        peer_index: 2,
        peer_netnsid: None,
    };
    assert!(is_attempt_host_link(&link("piglor-h3", veth)));
    assert!(!is_attempt_host_link(&link("piglor-h3", LinkKind::Other)));
    assert!(!is_attempt_host_link(&link("other-h0", veth)));
    assert!(is_attempt_host_link(&link("piglor-t0", veth)));
    assert!(!is_attempt_host_link(&link("piglor-t0", LinkKind::Other)));
    assert!(!is_attempt_host_link(&link("piglor-t1", veth)));
    assert!(none_remain(&[], &[]).is_ok());
    assert!(matches!(
        none_remain(&[NamespaceName::for_attempt([1; 16])], &[]),
        Err(NetlinkError::Residual)
    ));
    assert!(matches!(
        none_remain(&[], &[link("piglor-h3", veth)]),
        Err(NetlinkError::Residual)
    ));
}

#[test]
fn sweep_errors_say_what_failed() {
    let forwarding =
        OrphanSweepError::Forwarding(super::super::host_egress::HostEgressError::Forwarding);
    assert_eq!(
        forwarding.to_string(),
        "a recorded egress device's forwarding could not be restored, so the host egress table stays"
    );
    assert!(std::error::Error::source(&forwarding).is_some());
    assert_eq!(
        OrphanSweepError::from(NetlinkError::Residual).to_string(),
        "orphaned provider network state could not be removed"
    );
}

#[test]
fn a_link_already_gone_counts_as_deleted() {
    assert!(already_gone(Ok(())).is_ok());
    assert!(already_gone(Err(NetlinkError::Kernel(-19))).is_ok());
    assert!(matches!(
        already_gone(Err(NetlinkError::Kernel(-1))),
        Err(NetlinkError::Kernel(-1))
    ));
}

#[tokio::test]
async fn the_reconciliation_sweep_fails_closed_without_privilege() -> TestResult {
    let directory = tempfile::tempdir()?;
    let control = NetlinkNamespaceControl::new(NetworkNamespaces::pinned_under(directory.path()));
    // nf_tables refuses every request without `CAP_NET_ADMIN`.
    let swept = crate::OrphanNetworkCleanup::remove_orphans(&control).await;
    assert!(swept.is_err(), "{swept:?}");
    Ok(())
}

#[tokio::test]
async fn the_blocking_sweep_reports_its_outcome_and_a_panic_as_panicked() {
    assert!(on_blocking_pool(|| Ok(())).await.is_ok());
    let failed = on_blocking_pool(|| Err(OrphanSweepError::Netlink(NetlinkError::Residual))).await;
    assert!(
        matches!(
            failed,
            Err(OrphanSweepError::Netlink(NetlinkError::Residual))
        ),
        "{failed:?}"
    );
    let panicked =
        on_blocking_pool(|| std::panic::resume_unwind(Box::new("the sweep panicked"))).await;
    assert!(
        matches!(
            panicked,
            Err(OrphanSweepError::Netlink(NetlinkError::Panicked))
        ),
        "{panicked:?}"
    );
}

/// Tests that need `NET_ADMIN`, `SYS_ADMIN` and mounts. Each re-runs itself
/// in the isolated container that grants exactly those, and runs its body
/// there, where the container's own network namespace is the host's.
mod privileged {
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
    use std::process::Command;

    use rustix::fs::fstat;

    use super::*;
    use crate::namespace_network::{establish_namespace, NetworkRange};

    /// Whether this process is the isolated one; otherwise run `name` there
    /// and require it to pass.
    fn isolated(name: &str) -> TestResult<bool> {
        if std::env::var_os("PIGLOROS_PRIVILEGED_COMPOSITION_TEST").is_some() {
            return Ok(true);
        }
        let runner = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../scripts/run-isolated-with-net-admin-test.sh");
        let output = Command::new(runner)
            .arg(std::env::current_exe()?)
            .arg(format!(
                "namespace_network::control::tests::privileged::{name}"
            ))
            .output()?;
        assert!(
            output.status.success(),
            "isolated namespace test failed: {:?}\n{}\n{}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        Ok(false)
    }

    /// The namespace of attempt `[seed; 16]` in `slot`, reaching one IPv4
    /// and one IPv6 endpoint.
    fn planned(seed: u8, slot: u16) -> TestResult<ExpectedNamespace> {
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
            [seed; 16], &range, slot, &endpoints,
        )?)
    }

    /// The host link named `name`, if any.
    fn host_link(name: &LinkName) -> TestResult<Option<ObservedLink>> {
        Ok(with_session(ROUTE, |session| {
            route::link_reply(session.request(route::get_link(name)))
        })?)
    }

    #[test]
    fn an_attempt_namespace_reads_back_exactly_as_planned() -> TestResult {
        if !isolated("an_attempt_namespace_reads_back_exactly_as_planned")? {
            return Ok(());
        }
        let expected = planned(1, 3)?;
        let control = NetlinkNamespaceControl::new(NetworkNamespaces::system());
        let installed = control.install(&expected);
        let observed = control.observe(&expected.name, &expected.host_link);
        let removed = control.remove(&expected.name, &expected.host_link);
        assert!(installed.is_ok(), "{installed:?}");
        let verified = observed.as_ref().map(|observed| expected.verify(observed));
        assert!(
            matches!(verified, Ok(Ok(()))),
            "{verified:?}\n{observed:#?}\n{expected:#?}"
        );
        assert!(removed.is_ok(), "{removed:?}");
        assert!(matches!(
            NetworkNamespaces::system().open(&expected.name),
            Ok(None)
        ));
        assert!(matches!(host_link(&expected.host_link), Ok(None)));
        Ok(())
    }

    #[test]
    fn establishing_installs_verifies_and_a_repeat_is_refused() -> TestResult {
        if !isolated("establishing_installs_verifies_and_a_repeat_is_refused")? {
            return Ok(());
        }
        let expected = planned(2, 4)?;
        let control = NetlinkNamespaceControl::new(NetworkNamespaces::system());
        let established = establish_namespace(&control, &expected);
        // The name is taken, so a second installation fails before it
        // changes anything.
        let repeated = control.install(&expected);
        let observed = control.observe(&expected.name, &expected.host_link);
        let removed = control.remove(&expected.name, &expected.host_link);
        assert!(established.is_ok(), "{established:?}");
        assert!(
            matches!(repeated, Err(NetlinkError::Io(Errno::EXIST))),
            "{repeated:?}"
        );
        let verified = observed.map(|observed| expected.verify(&observed));
        assert!(matches!(verified, Ok(Ok(()))), "{verified:?}");
        assert!(removed.is_ok(), "{removed:?}");
        Ok(())
    }

    #[test]
    fn removal_keeps_a_host_link_whose_peer_lies_in_another_namespace() -> TestResult {
        if !isolated("removal_keeps_a_host_link_whose_peer_lies_in_another_namespace")? {
            return Ok(());
        }
        let namespaces = NetworkNamespaces::system();
        let control = NetlinkNamespaceControl::new(namespaces.clone());
        let (attempt, foreign) = (planned(3, 5)?, planned(4, 6)?);
        // The foreign namespace holds the peer of the attempt's host link
        // name; the attempt's own namespace holds nothing.
        let peer = namespaces.create(&foreign.name);
        let created = peer
            .as_ref()
            .map_err(|_| NetlinkError::Unexpected)
            .and_then(|peer| {
                namespaces.create(&attempt.name).and_then(|own| {
                    // The attempt's own namespace has an identifier too, so
                    // only the comparison tells the namespaces apart.
                    with_session(ROUTE, |session| {
                        session.execute(vec![
                            route::assign_nsid(own.as_fd()),
                            route::veth_pair(&attempt.host_link, &foreign.inner_link, peer.as_fd()),
                        ])
                    })
                })
            });
        let kept = control.remove(&attempt.name, &attempt.host_link);
        let survivor = host_link(&attempt.host_link);
        let owned = control.remove(&foreign.name, &attempt.host_link);
        assert!(created.is_ok(), "{peer:?} {created:?}");
        assert!(kept.is_ok(), "{kept:?}");
        assert!(matches!(survivor, Ok(Some(_))), "{survivor:?}");
        assert!(owned.is_ok(), "{owned:?}");
        assert!(matches!(host_link(&attempt.host_link), Ok(None)));
        Ok(())
    }

    #[test]
    fn a_pinned_namespace_is_new_exclusive_and_deleted_whole() -> TestResult {
        if !isolated("a_pinned_namespace_is_new_exclusive_and_deleted_whole")? {
            return Ok(());
        }
        let namespaces = NetworkNamespaces::system();
        let name = NamespaceName::for_attempt([5; 16]);
        let created = namespaces.create(&name);
        let opened = namespaces.open(&name);
        let repeated = namespaces.create(&name);
        let deleted = namespaces
            .delete(&name)
            .and_then(|()| namespaces.delete(&name));
        let inodes = created
            .as_ref()
            .ok()
            .zip(host_namespace().ok())
            .and_then(|(created, host)| fstat(created).ok().zip(fstat(&host).ok()))
            .map(|(created, host)| (created.st_ino, host.st_ino));
        assert!(
            inodes.is_some_and(|(created, host)| created != host),
            "{created:?} {inodes:?}"
        );
        assert!(matches!(opened, Ok(Some(_))), "{opened:?}");
        assert!(matches!(repeated, Err(NetlinkError::Io(Errno::EXIST))));
        assert!(deleted.is_ok(), "{deleted:?}");
        assert!(matches!(namespaces.open(&name), Ok(None)));
        Ok(())
    }

    /// Two attempts' plans and a host veth pair of another name.
    fn orphan_fixture() -> TestResult<(ExpectedNamespace, ExpectedNamespace, LinkName, LinkName)> {
        Ok((
            planned(7, 9)?,
            planned(8, 10)?,
            LinkName::new("other-h0")?,
            LinkName::new("other-n0")?,
        ))
    }

    #[test]
    fn orphans_are_removed_and_other_links_kept() -> TestResult {
        if !isolated("orphans_are_removed_and_other_links_kept")? {
            return Ok(());
        }
        let namespaces = NetworkNamespaces::system();
        let control = NetlinkNamespaceControl::new(namespaces.clone());
        let (first, second, other_host, other_inner) = orphan_fixture()?;
        let (probe_host, probe_inner) = (LinkName::new("piglor-t0")?, LinkName::new("piglor-u0")?);
        // Both ends of the other pair stay in the host namespace.
        let created = namespaces.create(&first.name).and_then(|peer| {
            namespaces.create(&second.name).and_then(|_| {
                host_namespace().and_then(|host| {
                    with_session(ROUTE, |session| {
                        session.execute(vec![
                            route::veth_pair(&first.host_link, &first.inner_link, peer.as_fd()),
                            route::veth_pair(&other_host, &other_inner, host.as_fd()),
                            // An egress probe's target pair left by a crash.
                            route::veth_pair(&probe_host, &probe_inner, host.as_fd()),
                        ])
                    })
                })
            })
        });
        let removed = control.remove_orphans();
        assert!(created.is_ok(), "{created:?}");
        assert!(removed.is_ok(), "{removed:?}");
        assert!(matches!(namespaces.attempt_names(), Ok(names) if names.is_empty()));
        assert!(matches!(host_link(&first.host_link), Ok(None)));
        assert!(matches!(host_link(&probe_host), Ok(None)));
        // A veth end of another name is not the provider's.
        assert!(matches!(host_link(&other_host), Ok(Some(_))));
        Ok(())
    }

    #[test]
    fn the_reconciliation_sweep_removes_orphans_on_the_blocking_pool() -> TestResult {
        if !isolated("the_reconciliation_sweep_removes_orphans_on_the_blocking_pool")? {
            return Ok(());
        }
        let namespaces = NetworkNamespaces::system();
        let control = NetlinkNamespaceControl::new(namespaces.clone());
        let orphan = planned(9, 11)?;
        let created = namespaces.create(&orphan.name);
        let runtime = tokio::runtime::Builder::new_current_thread().build()?;
        let swept = runtime.block_on(crate::OrphanNetworkCleanup::remove_orphans(&control));
        assert!(created.is_ok(), "{created:?}");
        assert!(swept.is_ok(), "{swept:?}");
        assert!(matches!(namespaces.attempt_names(), Ok(names) if names.is_empty()));
        Ok(())
    }
}
