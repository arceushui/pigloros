//! The attempt namespace's firewall read with its settled generation.

use std::error::Error;

use netlink_packet_netfilter::nftables::{
    ChainAttribute, NfTablesMessage, RuleAttribute, RuleMessage, TableAttribute, TableMessage,
};
use netlink_packet_netfilter::{NetfilterHeader, NetfilterMessage, NetfilterProtoFamily};

use super::*;
use crate::namespace_network::netfilter_fake::{kernel, session};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

fn inet(message: NfTablesMessage) -> NetfilterMessage {
    NetfilterMessage::new(
        NetfilterHeader::new(NetfilterProtoFamily::Inet, 0, 0),
        message,
    )
}

#[test]
fn the_tables_come_with_the_generation_the_read_settled_at() -> TestResult {
    let fake = kernel(&[41, 41]);
    fake.borrow_mut().tables = vec![inet(NfTablesMessage::NewTable(TableMessage {
        attributes: vec![TableAttribute::Name("piglor_attempt".to_owned())],
    }))];
    fake.borrow_mut().chains = vec![inet(NfTablesMessage::NewChain(
        netlink_packet_netfilter::nftables::ChainMessage {
            attributes: vec![
                ChainAttribute::Table("piglor_attempt".to_owned()),
                ChainAttribute::Name("regular".to_owned()),
            ],
        },
    ))];
    let (generation, tables) = tables(|| Ok(session(&fake)))?;
    assert_eq!(generation, 41);
    assert_eq!(tables.len(), 1);
    assert_eq!(tables[0].name, "piglor_attempt");
    assert_eq!(tables[0].chains.len(), 1);
    Ok(())
}

#[test]
fn a_dangling_reference_under_a_stable_generation_is_a_contradiction() {
    // The rule names a chain no dump reported, and the generation did not
    // move: that is unrepresentable state, not a torn read to retry.
    let fake = kernel(&[5, 5]);
    fake.borrow_mut().rules = vec![inet(NfTablesMessage::NewRule(RuleMessage {
        attributes: vec![
            RuleAttribute::Table("piglor_attempt".to_owned()),
            RuleAttribute::Chain("missing".to_owned()),
        ],
    }))];
    let read = tables(|| Ok(session(&fake)));
    assert!(
        matches!(read, Err(NetlinkError::Unrepresentable)),
        "{:?}",
        read.err()
    );
    assert_eq!(fake.borrow().opened, 1);
}

#[test]
fn a_dangling_reference_in_a_torn_read_is_retried_before_it_is_judged() {
    // The first read is torn (4 then 6), so its dangling rule is never
    // decoded; the settled second read (6 and 6) holds it still, and that is
    // the contradiction.
    let fake = kernel(&[4, 6, 6, 6]);
    fake.borrow_mut().rules = vec![inet(NfTablesMessage::NewRule(RuleMessage {
        attributes: vec![
            RuleAttribute::Table("piglor_attempt".to_owned()),
            RuleAttribute::Chain("missing".to_owned()),
        ],
    }))];
    let read = tables(|| Ok(session(&fake)));
    assert!(
        matches!(read, Err(NetlinkError::Unrepresentable)),
        "{:?}",
        read.err()
    );
    assert_eq!(fake.borrow().opened, 2);
}
