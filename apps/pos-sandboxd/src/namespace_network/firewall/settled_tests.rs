//! The generation-bracketed read of ADR-069 R14 §3.2 steps 4 and 5.

use std::error::Error;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{Duration, Instant};

use netlink_packet_netfilter::nftables::NfTablesMessageType;
use rustix::io::Errno;

use super::*;
use crate::namespace_network::netfilter_fake::{kernel, passed, session, Fault, Shared, Wire};
use crate::namespace_network::{ExpectedNamespace, NetworkRange};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

/// Fill `fake` with the table, chains and rules of one attempt namespace.
fn holding_a_ruleset(fake: &Shared) -> TestResult {
    let range = NetworkRange::new(
        Ipv4Addr::new(10, 213, 0, 0),
        24,
        Ipv6Addr::new(0xfd00, 0x913, 0, 0, 0, 0, 0, 0),
        120,
    )?;
    let endpoints = [SocketAddr::from(([192, 0, 2, 10], 443))];
    let expected = ExpectedNamespace::for_attempt([7; 16], &range, 3, &endpoints)?;
    let batch = install(&expected.table, &expected.chains);
    let of = |wanted: NfTablesMessageType| -> Vec<NetfilterMessage> {
        batch
            .iter()
            .filter_map(|request| match &request.message.inner {
                NetfilterMessageInner::NfTables(message) if message.message_type() == wanted => {
                    Some(NetfilterMessage::new(
                        NetfilterHeader::new(NetfilterProtoFamily::Inet, 0, 0),
                        message.clone(),
                    ))
                }
                _ => None,
            })
            .collect()
    };
    let mut held = fake.borrow_mut();
    held.tables = of(NfTablesMessageType::NewTable);
    held.chains = of(NfTablesMessageType::NewChain);
    held.rules = of(NfTablesMessageType::NewRule);
    Ok(())
}

fn failure<T>(result: &Result<T, NetlinkError>) -> String {
    format!("{:?}", result.as_ref().err())
}

#[test]
fn a_stable_generation_settles_with_its_dumps_in_one_session() -> TestResult {
    let fake = kernel(&[7, 7]);
    holding_a_ruleset(&fake)?;
    let (generation, dumps) = settled(|| Ok(session(&fake)), None)?;
    assert_eq!(generation, 7);
    assert_eq!(fake.borrow().opened, 1);
    assert_eq!(dumps.tables.len(), 1);
    assert_eq!(dumps.chains.len(), 3);
    assert_eq!(dumps.rules.len(), 5);
    Ok(())
}

#[test]
fn a_moved_generation_discards_the_read_and_the_next_one_settles() -> TestResult {
    // The first read sees 4 then 5, the second 5 twice.
    let fake = kernel(&[4, 5, 5, 5]);
    holding_a_ruleset(&fake)?;
    let (generation, _) = settled(|| Ok(session(&fake)), None)?;
    assert_eq!(generation, 5);
    assert_eq!(fake.borrow().opened, 2);
    Ok(())
}

#[test]
fn an_interrupted_dump_is_torn_too() -> TestResult {
    // The first read's table dump ends flagged, so its closing generation is
    // never asked for; the second read settles.
    let fake = kernel(&[9, 9, 9]);
    holding_a_ruleset(&fake)?;
    fake.borrow_mut().interrupted = 1;
    let (generation, _) = settled(|| Ok(session(&fake)), None)?;
    assert_eq!(generation, 9);
    assert_eq!(fake.borrow().opened, 2);
    Ok(())
}

#[test]
fn three_torn_reads_are_torn_and_a_fourth_is_never_made() -> TestResult {
    let fake = kernel(&[1, 2, 3, 4, 5, 6, 7, 7]);
    holding_a_ruleset(&fake)?;
    let torn = settled(|| Ok(session(&fake)), None);
    assert!(
        matches!(torn, Err(NetlinkError::Torn)),
        "{}",
        failure(&torn)
    );
    assert_eq!(fake.borrow().opened, 3);
    Ok(())
}

#[test]
fn any_other_failure_is_returned_at_once() {
    // No generation is ever answered: the first receive times out.
    let fake = kernel(&[]);
    let timed_out = settled(|| Ok(session(&fake)), None);
    assert!(
        matches!(timed_out, Err(NetlinkError::Io(Errno::TIMEDOUT))),
        "{}",
        failure(&timed_out)
    );
    assert_eq!(fake.borrow().opened, 1);
    let refused = settled(
        || Err::<NetlinkSession<Wire>, _>(NetlinkError::Kernel(-1)),
        None,
    );
    assert!(
        matches!(refused, Err(NetlinkError::Kernel(-1))),
        "{}",
        failure(&refused)
    );
}

#[test]
fn a_passed_deadline_fails_before_a_read_and_a_future_one_does_not() -> TestResult {
    let fake = kernel(&[3, 3]);
    holding_a_ruleset(&fake)?;
    let past = passed();
    let expired = settled(|| Ok(session(&fake)), Some(past));
    assert!(
        matches!(expired, Err(NetlinkError::Io(Errno::TIMEDOUT))),
        "{}",
        failure(&expired)
    );
    assert_eq!(fake.borrow().opened, 0);
    let future = Instant::now() + Duration::from_mins(1);
    let (generation, _) = settled(|| Ok(session(&fake)), Some(future))?;
    assert_eq!(generation, 3);
    Ok(())
}

#[test]
fn a_generation_reply_must_be_a_generation_with_an_id() -> TestResult {
    let fake = kernel(&[11, 12, 13, 14]);
    assert_eq!(generation(&session(&fake))?, 11);
    fake.borrow_mut().fault = Fault::NoId;
    let anonymous = generation(&session(&fake));
    assert!(
        matches!(anonymous, Err(NetlinkError::Unexpected)),
        "{}",
        failure(&anonymous)
    );
    fake.borrow_mut().fault = Fault::NotAGeneration;
    let other = generation(&session(&fake));
    assert!(
        matches!(other, Err(NetlinkError::Unexpected)),
        "{}",
        failure(&other)
    );
    // Other attributes may come first: the id is found among them.
    fake.borrow_mut().fault = Fault::ProcessFirst;
    assert_eq!(generation(&session(&fake))?, 14);
    Ok(())
}

#[test]
fn torn_reads_say_what_failed() {
    assert_eq!(
        NetlinkError::Torn.to_string(),
        "every bracketed read of the nftables ruleset was torn by a change"
    );
}
