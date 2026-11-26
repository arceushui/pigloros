//! The attempt's slice of the host table, read under the change lock and
//! bracketed by `NFT_MSG_GETGEN` (ADR-069 R14 §3.2 step 5).

use std::error::Error;
use std::net::{Ipv6Addr, SocketAddr};
use std::time::{Duration, Instant};

use rustix::io::Errno;

use super::tests::{as_dumped, attempt, two_attempts, ENDPOINT};
use super::*;
use crate::namespace_network::netfilter_fake::{kernel, passed, session, Shared};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

/// A fake kernel that holds the host table with `attempts` installed in turn
/// and answers `generations`.
fn holding(attempts: &[&AttemptEgress], generations: &[u32]) -> Shared {
    let batches: Vec<_> = std::iter::once(create_table())
        .chain(attempts.iter().map(|attempt| install_attempt(attempt)))
        .collect();
    let (tables, chains, rules) = as_dumped(&batches);
    let fake = kernel(generations);
    let mut held = fake.borrow_mut();
    held.tables = tables;
    held.chains = chains;
    held.rules = rules;
    drop(held);
    fake
}

fn in_a_year() -> Instant {
    Instant::now() + Duration::from_hours(365 * 24)
}

#[test]
fn the_slice_is_read_under_the_change_lock_and_returns_the_ipv4_endpoints_in_order() -> TestResult {
    let ipv6 = SocketAddr::from((Ipv6Addr::LOCALHOST, 443));
    let later = SocketAddr::from(([198, 51, 100, 7], 8443));
    let first = attempt(1, 3, vec![later, ipv6, ENDPOINT])?;
    let second = attempt(2, 4, vec![ENDPOINT])?;
    let fake = holding(&[&first, &second], &[12, 12]);
    let egress = HostEgress::new();
    let slice = egress.readback_through(
        |protocol| {
            assert_eq!(protocol, NETFILTER);
            // Other attempts' installs and removals wait while it reads.
            assert!(egress.installed.try_lock().is_err());
            Ok(session(&fake))
        },
        &first,
        in_a_year(),
    )?;
    assert_eq!(slice.allowed, [ENDPOINT, later]);
    assert_eq!(slice.masqueraded, [ENDPOINT, later]);
    // The lock is released once the read ended, and the read was one session.
    assert!(egress.installed.try_lock().is_ok());
    assert_eq!(fake.borrow().opened, 1);
    Ok(())
}

#[test]
fn another_attempts_entries_are_read_and_not_judged() -> TestResult {
    let (mut table, _) = two_attempts()?;
    let first = attempt(1, 3, vec![ENDPOINT])?;
    let second = attempt(
        2,
        4,
        vec![ENDPOINT, SocketAddr::from(([198, 51, 100, 7], 8443))],
    )?;
    assert!(slice_exact(&table, &first));
    assert!(slice_exact(&table, &second));
    let spoiled = table
        .chains
        .get_mut(second.namespace.as_str())
        .ok_or("no chain")?;
    spoiled.rules.clear();
    assert!(slice_exact(&table, &first));
    assert!(!slice_exact(&table, &second));
    Ok(())
}

type Change = Box<dyn Fn(&mut ReadTable)>;

/// A change to the chain `name` of a table, if it has one.
fn in_chain(name: &str, change: impl Fn(&mut ReadChain) + 'static) -> Change {
    let name = name.to_owned();
    Box::new(move |table| {
        if let Some(read) = table.chains.get_mut(&name) {
            change(read);
        }
    })
}

#[test]
fn a_slice_that_is_not_exactly_the_attempts_reads_back_differently() -> TestResult {
    let (table, _) = two_attempts()?;
    let first = attempt(1, 3, vec![ENDPOINT])?;
    let own = first.namespace.as_str().to_owned();
    let elsewhere = canonical_rule(&HostRule::Dispatch {
        link: first.host_link.clone(),
        chain: "elsewhere".to_owned(),
    });
    let stray = canonical_rule(&HostRule::Masquerade {
        link: first.host_link.clone(),
        endpoint: SocketAddr::from(([203, 0, 113, 9], 443)),
    });
    let gone = |name: &'static str| -> Change {
        Box::new(move |table| {
            table.chains.remove(name);
        })
    };
    let changes: Vec<(&str, Change)> = vec![
        ("the attempt's chain is gone", {
            let own = own.clone();
            Box::new(move |table| {
                table.chains.remove(&own);
            })
        }),
        (
            "the attempt's chain is a base chain",
            in_chain(&own, |read| {
                read.base = Some((0, 0, 0, "filter".to_owned()));
            }),
        ),
        (
            "the attempt's chain accepts more",
            in_chain(&own, |read| read.rules.push((0, Vec::new()))),
        ),
        (
            "the attempt's chain accepts something else",
            in_chain(&own, |read| read.rules[0].1.clear()),
        ),
        ("the dormant flag is set", Box::new(|table| table.flags = 1)),
        ("the forward chain is gone", gone(FORWARD)),
        (
            "the forward chain is no base chain",
            in_chain(FORWARD, |read| read.base = None),
        ),
        (
            "the final drop is gone",
            in_chain(FORWARD, |read| {
                read.rules.pop();
            }),
        ),
        (
            "the attempt is not dispatched",
            // The later attempt's dispatch is at the head.
            in_chain(FORWARD, |read| {
                read.rules.remove(1);
            }),
        ),
        (
            "the attempt is dispatched twice",
            in_chain(FORWARD, |read| {
                let again = read.rules[1].clone();
                read.rules.insert(0, again);
            }),
        ),
        (
            "the attempt's link is also dispatched elsewhere",
            in_chain(FORWARD, move |read| {
                read.rules.insert(0, (0, elsewhere.clone()));
            }),
        ),
        ("the postrouting chain is gone", gone(POSTROUTING)),
        (
            "the postrouting chain is no base chain",
            in_chain(POSTROUTING, |read| read.base = None),
        ),
        (
            "a masquerade is missing",
            in_chain(POSTROUTING, |read| {
                read.rules.remove(0);
            }),
        ),
        (
            "another masquerade is on the attempt's link",
            in_chain(POSTROUTING, move |read| {
                read.rules.push((0, stray.clone()));
            }),
        ),
    ];
    assert!(slice_exact(&table, &first));
    for (what, change) in changes {
        let mut spoiled = table.clone();
        change(&mut spoiled);
        assert!(!slice_exact(&spoiled, &first), "{what}: {spoiled:?}");
    }
    Ok(())
}

#[test]
fn a_read_that_finds_another_slice_or_no_table_is_a_readback_mismatch() -> TestResult {
    let first = attempt(1, 3, vec![ENDPOINT])?;
    let second = attempt(2, 4, vec![ENDPOINT])?;
    // The kernel holds only the second attempt.
    let other = holding(&[&second], &[2, 2]);
    let egress = HostEgress::new();
    let differing = egress.readback_through(|_| Ok(session(&other)), &first, in_a_year());
    assert!(matches!(differing, Err(HostEgressError::Readback)));
    let absent = holding(&[], &[2, 2]);
    absent.borrow_mut().tables.clear();
    let missing = egress.readback_through(|_| Ok(session(&absent)), &first, in_a_year());
    assert!(matches!(missing, Err(HostEgressError::Readback)));
    Ok(())
}

#[test]
fn a_dangling_reference_under_a_stable_generation_is_unrepresentable() -> TestResult {
    let first = attempt(1, 3, vec![ENDPOINT])?;
    let fake = holding(&[&first], &[5, 5]);
    // Drop the chains the rules name.
    fake.borrow_mut().chains.clear();
    let egress = HostEgress::new();
    let read = egress.readback_through(|_| Ok(session(&fake)), &first, in_a_year());
    assert!(
        matches!(
            read,
            Err(HostEgressError::Netlink(NetlinkError::Unrepresentable))
        ),
        "{:?}",
        read.err()
    );
    Ok(())
}

#[test]
fn a_foreign_change_is_retried_and_three_torn_reads_are_a_transport_failure() -> TestResult {
    let first = attempt(1, 3, vec![ENDPOINT])?;
    let egress = HostEgress::new();
    // Another tool moved the generation once; the second read settles.
    let once = holding(&[&first], &[3, 4, 4, 4]);
    let slice = egress.readback_through(|_| Ok(session(&once)), &first, in_a_year())?;
    assert_eq!(slice.allowed, [ENDPOINT]);
    assert_eq!(once.borrow().opened, 2);
    // It keeps moving: three reads, then Torn, never a mismatch.
    let moving = holding(&[&first], &[1, 2, 3, 4, 5, 6]);
    let torn = egress.readback_through(|_| Ok(session(&moving)), &first, in_a_year());
    assert!(
        matches!(torn, Err(HostEgressError::Netlink(NetlinkError::Torn))),
        "{:?}",
        torn.err()
    );
    assert_eq!(moving.borrow().opened, 3);
    Ok(())
}

#[test]
fn the_release_deadline_bounds_the_read_and_expiry_is_a_receive_timeout() -> TestResult {
    let first = attempt(1, 3, vec![ENDPOINT])?;
    let past = passed();
    // The real port opens no session once the deadline passed.
    let expired = HostEgress::new().readback_slice(&first, past);
    assert!(
        matches!(
            expired,
            Err(HostEgressError::Netlink(NetlinkError::Io(Errno::TIMEDOUT)))
        ),
        "{:?}",
        expired.err()
    );
    Ok(())
}
