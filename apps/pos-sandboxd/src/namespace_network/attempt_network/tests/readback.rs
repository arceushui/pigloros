//! The readback of an established attempt network (ADR-069 R14 §3.2).

use std::fs::File;
use std::time::{Duration, Instant};

use pos_reference::sandbox_provider_protocol::{
    KernelObservationEvidence, KernelObservationEvidenceFields, KernelObservationStatus,
    LocalNetworkReadback,
};

use super::super::readback::{
    assemble, base, changed, egress_failure, identity, netlink_failure, rule,
};
use super::*;
use crate::{KernelObservation, NetworkReadback, ReadbackError};

type Connector = NamespaceConnector<FakeControl, FakeEgress>;

/// What is wrong with a read, and the change that makes it so.
type Breakage = (&'static str, fn(&mut ObservedNamespace));

fn in_a_minute() -> Instant {
    Instant::now() + Duration::from_mins(1)
}

/// The established connector of attempt `[1; 16]` over the given fakes,
/// whose namespace is pinned as this process's own.
fn established(
    directory: &std::path::Path,
    control: FakeControl,
    egress: &FakeEgress,
) -> TestResult<Connector> {
    let (network, _) = network_with(directory, control, egress, 24)?;
    Ok(network.connector([1; 16], &[ENDPOINT])?)
}

fn pinned(directory: &std::path::Path) -> FakeControl {
    pinning(directory)
}

/// The identity of this process's own network namespace.
fn own_identity() -> TestResult<pos_reference::sandbox_provider_protocol::NamespaceIdentity> {
    let file = File::open("/proc/self/ns/net")?;
    Ok(identity(std::os::fd::AsFd::as_fd(&file)).map_err(|error| format!("{error:?}"))?)
}

#[test]
fn an_established_network_reads_back_as_a_record_the_verifier_accepts() -> TestResult {
    let directory = tempfile::tempdir()?;
    let connector = established(
        directory.path(),
        pinned(directory.path()),
        &FakeEgress::default(),
    )?;
    let readback = connector
        .readback(in_a_minute())
        .map_err(|error| format!("{error:?}"))?;
    assert_eq!(readback.namespace, own_identity()?);
    assert_eq!(readback.firewall_generation, 7);
    assert_eq!((readback.namespace_netnsid, readback.host_netnsid), (1, 0));
    assert_eq!(readback.loopback_index, 1);
    assert_eq!(readback.inner.name, "piglor-n0");
    assert_eq!(
        (
            readback.inner.index,
            readback.inner.peer_index,
            readback.inner.peer_netnsid
        ),
        (2, 3, 0)
    );
    assert_eq!(readback.host.name, "piglor-h0");
    assert_eq!(
        (
            readback.host.index,
            readback.host.peer_index,
            readback.host.peer_netnsid
        ),
        (3, 2, 1)
    );
    assert_eq!(readback.egress_allowed, [ENDPOINT]);
    assert_eq!(readback.egress_masqueraded, [ENDPOINT]);
    assert_eq!(
        readback
            .chains
            .iter()
            .map(|chain| chain.name.as_str())
            .collect::<Vec<_>>(),
        ["input", "output", "forward"]
    );
    // Reading again gives the same bytes.
    assert_eq!(connector.readback(in_a_minute()), Ok(readback.clone()));
    // The record decodes under rule 4: producer equals verifier.
    let mut state = KernelObservation::fixture([9; 16]).evidence_state();
    state.network_readback = Some(readback);
    let record = KernelObservationEvidence::new(&KernelObservationEvidenceFields {
        attempt_id: [1; 16],
        agr1_digest: [2; 32],
        status: KernelObservationStatus::Observed {
            ready1_digest: [3; 32],
            observation: Box::new(state),
        },
        requested_configuration_evidence: [4; 32],
    })?;
    let decoded = KernelObservationEvidence::from_canonical_cbor(record.canonical_bytes())?;
    assert_eq!(decoded, record);
    Ok(())
}

#[test]
fn netlink_failures_are_transport_unless_the_object_is_missing_or_unreadable() {
    for (failure, class) in [
        (NetlinkError::Io(Errno::IO), ReadbackError::Transport),
        (NetlinkError::Io(Errno::TIMEDOUT), ReadbackError::Transport),
        (NetlinkError::Torn, ReadbackError::Transport),
        (NetlinkError::Interrupted, ReadbackError::Transport),
        (NetlinkError::Io(Errno::NOENT), ReadbackError::Changed),
        (NetlinkError::Kernel(-1), ReadbackError::Changed),
        (NetlinkError::Unexpected, ReadbackError::Changed),
        (NetlinkError::Empty, ReadbackError::Changed),
        (NetlinkError::Panicked, ReadbackError::Changed),
        (NetlinkError::Truncated, ReadbackError::Changed),
        (NetlinkError::Decode, ReadbackError::Changed),
        (NetlinkError::Unrepresentable, ReadbackError::Changed),
    ] {
        let text = failure.to_string();
        assert_eq!(netlink_failure(&failure), class, "{text}");
    }
    // Steps 1 and 6 know no transport class: whatever fails there is a
    // change.
    assert_eq!(changed(Errno::IO), ReadbackError::Changed);
    assert_eq!(changed(NetlinkError::Torn), ReadbackError::Changed);
    for (failure, class) in [
        (
            HostEgressError::Netlink(NetlinkError::Io(Errno::TIMEDOUT)),
            ReadbackError::Transport,
        ),
        (
            HostEgressError::Netlink(NetlinkError::Torn),
            ReadbackError::Transport,
        ),
        (
            HostEgressError::Netlink(NetlinkError::Unrepresentable),
            ReadbackError::Changed,
        ),
        (HostEgressError::Readback, ReadbackError::Changed),
        (HostEgressError::Forwarding, ReadbackError::Changed),
        (HostEgressError::Ipv6Egress, ReadbackError::Changed),
    ] {
        assert_eq!(egress_failure(failure), class);
    }
}

#[test]
fn a_failed_read_of_the_namespace_or_the_host_slice_keeps_its_class() -> TestResult {
    let directory = tempfile::tempdir()?;
    for (failure, class) in [
        (
            (|| NetlinkError::Io(Errno::TIMEDOUT)) as fn() -> NetlinkError,
            ReadbackError::Transport,
        ),
        (|| NetlinkError::Io(Errno::NOENT), ReadbackError::Changed),
        (|| NetlinkError::Torn, ReadbackError::Transport),
    ] {
        let control = FakeControl {
            observe_failure: Some(failure),
            ..pinned(directory.path())
        };
        let armed = Arc::clone(&control.armed);
        let connector = established(directory.path(), control, &FakeEgress::default())?;
        armed.store(true, std::sync::atomic::Ordering::SeqCst);
        assert_eq!(connector.readback(in_a_minute()), Err(class));
        drop(connector);
    }
    for (failure, class) in [
        (
            (|| HostEgressError::Netlink(NetlinkError::Io(Errno::TIMEDOUT)))
                as fn() -> HostEgressError,
            ReadbackError::Transport,
        ),
        (|| HostEgressError::Readback, ReadbackError::Changed),
    ] {
        let egress = FakeEgress {
            readback_failure: Some(failure),
            ..FakeEgress::default()
        };
        let connector = established(directory.path(), pinned(directory.path()), &egress)?;
        assert_eq!(connector.readback(in_a_minute()), Err(class));
        drop(connector);
    }
    Ok(())
}

#[test]
fn a_namespace_that_verifies_differently_reads_back_as_changed() -> TestResult {
    let directory = tempfile::tempdir()?;
    let tamperings: [fn(&mut ObservedNamespace); 3] = [
        |observed| observed.routes.clear(),
        |observed| observed.firewall_generation = 8,
        |observed| observed.namespace_netnsid = -1,
    ];
    for (index, tamper) in tamperings.into_iter().enumerate() {
        let control = FakeControl {
            tamper: Some(tamper),
            ..pinned(directory.path())
        };
        let armed = Arc::clone(&control.armed);
        let connector = established(directory.path(), control, &FakeEgress::default())?;
        armed.store(true, std::sync::atomic::Ordering::SeqCst);
        let read = connector.readback(in_a_minute());
        // A moved generation alone is not a mismatch: it is recorded.
        let expected = if index == 1 {
            Ok(8)
        } else {
            Err(ReadbackError::Changed)
        };
        assert_eq!(read.map(|record| record.firewall_generation), expected);
        drop(connector);
    }
    Ok(())
}

#[test]
fn the_name_must_still_bind_the_descriptor_the_proxy_holds() -> TestResult {
    let directory = tempfile::tempdir()?;
    let connector = established(
        directory.path(),
        pinned(directory.path()),
        &FakeEgress::default(),
    )?;
    let pin = directory
        .path()
        .join(NamespaceName::for_attempt([1; 16]).as_str());
    // Re-pinned to another namespace: the name binds something else.
    std::fs::remove_file(&pin)?;
    std::os::unix::fs::symlink("/proc/self/ns/user", &pin)?;
    assert_eq!(
        connector.readback(in_a_minute()),
        Err(ReadbackError::Changed)
    );
    // Unpinned: the name binds nothing.
    std::fs::remove_file(&pin)?;
    assert_eq!(
        connector.readback(in_a_minute()),
        Err(ReadbackError::Changed)
    );
    // A pin that is no namespace file binds nothing (invariant 4, wrong
    // `f_type`).
    std::os::unix::fs::symlink("/", &pin)?;
    assert_eq!(
        connector.readback(in_a_minute()),
        Err(ReadbackError::Changed)
    );
    // A pin that cannot be opened is a change too: R14 lists only steps 2
    // to 5 as transport.
    std::fs::remove_file(&pin)?;
    std::os::unix::fs::symlink(&pin, &pin)?;
    assert_eq!(
        connector.readback(in_a_minute()),
        Err(ReadbackError::Changed)
    );
    // The pin of the held namespace is a match again.
    std::fs::remove_file(&pin)?;
    std::os::unix::fs::symlink("/proc/self/ns/net", &pin)?;
    assert!(connector.readback(in_a_minute()).is_ok());
    Ok(())
}

#[test]
fn a_descriptor_that_is_no_namespace_file_reads_back_as_changed() -> TestResult {
    let directory = tempfile::tempdir()?;
    let mut connector = established(
        directory.path(),
        pinned(directory.path()),
        &FakeEgress::default(),
    )?;
    connector.namespace = File::open("/")?.into();
    assert_eq!(
        connector.readback(in_a_minute()),
        Err(ReadbackError::Changed)
    );
    Ok(())
}

/// The read-back of attempt `[1; 16]`'s own plan, as the fake kernel gives it.
fn observed() -> TestResult<ObservedNamespace> {
    Ok(observed_for(&expected_for(1)?))
}

fn assembled(observed: &ObservedNamespace) -> Option<LocalNetworkReadback> {
    let slice = EgressSlice {
        allowed: vec![ENDPOINT],
        masqueraded: vec![ENDPOINT],
    };
    own_identity()
        .ok()
        .and_then(|identity| assemble(identity, observed, slice))
}

#[test]
fn a_record_is_assembled_only_from_a_read_that_holds_every_part() -> TestResult {
    assert!(assembled(&observed()?).is_some());
    let broken: [Breakage; 11] = [
        ("no loopback", |observed| {
            observed
                .links
                .retain(|link| link.kind != LinkKind::Loopback);
        }),
        ("no veth end inside", |observed| {
            observed
                .links
                .retain(|link| link.kind == LinkKind::Loopback);
        }),
        ("no host end", |observed| observed.host_link = None),
        ("host end is no veth", |observed| {
            if let Some(link) = observed.host_link.as_mut() {
                link.kind = LinkKind::Other;
            }
        }),
        ("host end has no peer namespace", |observed| {
            if let Some(link) = observed.host_link.as_mut() {
                link.kind = LinkKind::Veth {
                    peer_index: 2,
                    peer_netnsid: None,
                };
            }
        }),
        ("host end has a negative peer namespace", |observed| {
            if let Some(link) = observed.host_link.as_mut() {
                link.kind = LinkKind::Veth {
                    peer_index: 2,
                    peer_netnsid: Some(-1),
                };
            }
        }),
        ("negative namespace id", |observed| {
            observed.namespace_netnsid = -1;
        }),
        ("negative host id", |observed| observed.host_netnsid = -1),
        ("no table", |observed| observed.tables.clear()),
        ("two tables", |observed| {
            let again = observed.tables[0].clone();
            observed.tables.push(again);
        }),
        ("inner end has no peer namespace", |observed| {
            for link in &mut observed.links {
                if let LinkKind::Veth { peer_netnsid, .. } = &mut link.kind {
                    *peer_netnsid = None;
                }
            }
        }),
    ];
    for (what, change) in broken {
        let mut read = observed()?;
        change(&mut read);
        assert!(assembled(&read).is_none(), "{what}");
    }
    Ok(())
}

#[test]
fn a_descriptor_whose_nsfs_identity_is_the_kernels_is_named_by_its_device_and_inode() -> TestResult
{
    let own = own_identity()?;
    assert_ne!(own.inode, 0);
    let file = File::open("/proc/self/ns/net")?;
    let status = rustix::fs::fstat(&file)?;
    assert_eq!(own.inode, status.st_ino);
    assert_eq!(own.major, rustix::fs::major(status.st_dev));
    assert_eq!(own.minor, rustix::fs::minor(status.st_dev));
    Ok(())
}

#[test]
fn every_firewall_code_has_its_record_code() {
    use pos_reference::sandbox_provider_protocol::{
        ReadbackFirewallBase, ReadbackFirewallHook, ReadbackFirewallPolicy, ReadbackFirewallRule,
    };

    use crate::namespace_network::{
        FirewallBaseChain, FirewallHook, FirewallRule, FirewallVerdict,
    };

    for (hook, expected) in [
        (FirewallHook::Input, ReadbackFirewallHook::Input),
        (FirewallHook::Forward, ReadbackFirewallHook::Forward),
        (FirewallHook::Output, ReadbackFirewallHook::Output),
    ] {
        for (policy, expected_policy) in [
            (FirewallVerdict::Accept, ReadbackFirewallPolicy::Accept),
            (FirewallVerdict::Drop, ReadbackFirewallPolicy::Drop),
        ] {
            assert_eq!(
                base(FirewallBaseChain {
                    hook,
                    priority: -5,
                    policy,
                }),
                ReadbackFirewallBase {
                    hook: expected,
                    priority: -5,
                    policy: expected_policy,
                }
            );
        }
    }
    assert_eq!(
        rule(FirewallRule::AcceptEstablished),
        ReadbackFirewallRule::AcceptEstablished
    );
    assert_eq!(
        rule(FirewallRule::AcceptNeighbourDiscovery),
        ReadbackFirewallRule::AcceptNeighbourDiscovery
    );
    assert_eq!(
        rule(FirewallRule::AcceptTcp(ENDPOINT)),
        ReadbackFirewallRule::AcceptTcp(ENDPOINT)
    );
}
