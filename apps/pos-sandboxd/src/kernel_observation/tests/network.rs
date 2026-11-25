//! The Local network readback inside the unit's observation (ADR-069 R14
//! §3.2): a Local attempt's observation records it, and a failed readback
//! fails the observation with its class.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use pos_reference::sandbox_provider_protocol::{
    NamespaceIdentity, ReadbackPrefix, ReadbackVethEnd,
};

use super::*;

/// A readback that answers `result` and keeps the deadline it was given.
struct Fake {
    result: Result<LocalNetworkReadback, ReadbackError>,
    asked: Mutex<Option<Instant>>,
}

impl Fake {
    fn answering(result: Result<LocalNetworkReadback, ReadbackError>) -> Self {
        Self {
            result,
            asked: Mutex::new(None),
        }
    }

    fn deadline(&self) -> Option<Instant> {
        self.asked.lock().ok().and_then(|asked| *asked)
    }
}

impl NetworkReadback for Fake {
    fn readback(&self, deadline: Instant) -> Result<LocalNetworkReadback, ReadbackError> {
        if let Ok(mut asked) = self.asked.lock() {
            *asked = Some(deadline);
        }
        self.result.clone()
    }
}

/// Some readback; the observation carries it without judging it.
fn readback() -> LocalNetworkReadback {
    let end = |index, peer| ReadbackVethEnd {
        index,
        name: format!("piglor-n{index}"),
        peer_index: peer,
        peer_netnsid: 0,
    };
    LocalNetworkReadback {
        namespace: NamespaceIdentity {
            major: 0,
            minor: 4,
            inode: 4_026_532_300,
        },
        namespace_netnsid: 1,
        host_netnsid: 0,
        loopback_index: 1,
        inner: end(2, 3),
        host: end(3, 2),
        inner_addresses: vec![ReadbackPrefix {
            address: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            length: 30,
        }],
        host_addresses: Vec::new(),
        routes: Vec::new(),
        firewall_generation: 7,
        chains: Vec::new(),
        egress_allowed: Vec::new(),
        egress_masqueraded: Vec::new(),
    }
}

#[test]
fn a_local_attempts_observation_records_the_readback_and_hands_it_the_deadline() -> TestResult {
    let (_directory, cgroup) = cgroup_listing(own_pid())?;
    let provider = foreign_provider()?;
    let fake = Fake::answering(Ok(readback()));
    let deadline = Instant::now() + Duration::from_secs(30);
    let observed = observe_unit(
        &this_unit(),
        &context(&cgroup, false)?.with_network(&fake, deadline),
        &provider,
        &isolated(),
    )?;
    assert_eq!(fake.deadline(), Some(deadline));
    assert_eq!(observed.observation().network(), Some(&readback()));
    // The KOE1 observation carries it.
    assert_eq!(
        observed.observation().evidence_state().network_readback,
        Some(readback())
    );
    Ok(())
}

#[test]
fn another_mode_reads_no_network_back() -> TestResult {
    let (_directory, cgroup) = cgroup_listing(own_pid())?;
    let observed = observe_unit(
        &this_unit(),
        &context(&cgroup, false)?,
        &foreign_provider()?,
        &isolated(),
    )?;
    assert_eq!(observed.observation().network(), None);
    assert_eq!(
        observed.observation().evidence_state().network_readback,
        None
    );
    Ok(())
}

#[test]
fn a_readback_that_fails_fails_the_observation_with_its_class() -> TestResult {
    let (_directory, cgroup) = cgroup_listing(own_pid())?;
    let provider = foreign_provider()?;
    for class in [ReadbackError::Transport, ReadbackError::Changed] {
        let fake = Fake::answering(Err(class));
        let failed = observe_unit(
            &this_unit(),
            &context(&cgroup, false)?.with_network(&fake, Instant::now()),
            &provider,
            &isolated(),
        );
        assert_eq!(failed.err(), Some(KernelObservationError::Network(class)));
    }
    assert_eq!(
        KernelObservationError::Network(ReadbackError::Changed).to_string(),
        "the Local network could not be read back"
    );
    assert_eq!(
        ReadbackError::Transport.to_string(),
        "the Local network could not be read back"
    );
    assert_eq!(
        ReadbackError::Changed.to_string(),
        "the Local network reads back as other state"
    );
    Ok(())
}

#[test]
fn an_observation_context_names_whether_it_reads_a_network() -> TestResult {
    let (_directory, cgroup) = cgroup_listing(own_pid())?;
    let fake = Fake::answering(Ok(readback()));
    let bare = format!("{:?}", context(&cgroup, false)?);
    let local = format!(
        "{:?}",
        context(&cgroup, false)?.with_network(&fake, Instant::now())
    );
    assert!(bare.contains("network: false"), "{bare}");
    assert!(local.contains("network: true"), "{local}");
    Ok(())
}
