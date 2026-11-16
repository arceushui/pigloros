//! GMP1 startup predicate 6, `air-gapped-no-route` (ADR-135 §4, #1423).
//!
//! The pure parser is exercised with fixture text for every denial; the
//! Air-Gapped composition is exercised end to end inside the #1422 test
//! shape, where it holds, and in a user namespace that still holds
//! `CAP_NET_ADMIN`, where it is refused before any store is opened.
#![cfg(target_os = "linux")]

use std::{net::SocketAddr, path::Path, process::Command};

use piglor_gateway::mode_profile::{
    bind_gateway_mode_v1, check_air_gapped_no_route_v1, verify_gateway_serve_composition_v1,
    AirGappedHostFactV1 as Fact, AirGappedHostFactsV1, AirGappedNoRouteDenialV1 as Denial,
    GatewayModeErrorV1, GatewayModeProfileIdV1, GatewayServeCompositionV1,
};
use pos_runtime::{ErasureCoordinatorCompositionV1, ErasureExecutionHostV1};
use pos_store::StoreConfig;

type TestResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;

/// Set only for a test re-executed inside the Air-Gapped test shape.
const INSIDE: &str = "PIGLOROS_AIR_GAPPED_TEST_NAMESPACE";
/// Set only for a test re-executed in a user namespace holding its capabilities.
const CAPABLE: &str = "PIGLOROS_CAPABLE_TEST_NAMESPACE";

const DEV: &str = "Inter-|   Receive                            |  Transmit\n \
    face |bytes    packets errs drop fifo frame compressed multicast|bytes\n    \
    lo:       0       0    0    0    0     0          0         0        0\n  \
    sit0:       0       0    0    0    0     0          0         0        0\n";
const ROUTE: &str =
    "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n";
const IPV6_ROUTE: &str = "00000000000000000000000000000001 80 00000000000000000000000000000000 00 \
    00000000000000000000000000000000 00000000 00000001 00000000 80200001       lo\n";
const IF_INET6: &str = "00000000000000000000000000000001 01 80 10 80       lo\n";
const FIB_TRIE: &str =
    "Main:\n  +-- 0.0.0.0/0 3 0 4\n     |-- 127.0.0.0\n        /8 host LOCAL\n     \
    |-- 127.0.0.1\n        /32 host LOCAL\nLocal:\n  +-- 0.0.0.0/0 3 0 4\n";
const IGMP: &str = "Idx\tDevice    : Count Querier\tGroup    Users Timer\tReporter\n\
    1\tlo        :     1      V3\n\t\t\t\t010000E0     1 0:00000000\t\t0\n";
const IGMP6: &str = "1    lo              ff020000000000000000000000000001     1 0000000C 0\n";
const STATUS: &str = "Name:\tgateway\nCapInh:\t0000000000000000\nCapPrm:\t0000000000000000\n\
    CapEff:\t0000000000000000\nCapBnd:\t0000000000000000\nCapAmb:\t0000000000000000\n\
    NoNewPrivs:\t1\nSeccomp:\t2\nSeccomp_filters:\t1\n";

/// The facts of a loopback-only namespace without network capabilities.
fn air_gapped() -> AirGappedHostFactsV1 {
    AirGappedHostFactsV1 {
        dev: Some(DEV.to_owned()),
        route: Some(ROUTE.to_owned()),
        ipv6_route: Some(IPV6_ROUTE.to_owned()),
        if_inet6: Some(IF_INET6.to_owned()),
        fib_trie: Some(FIB_TRIE.to_owned()),
        igmp: Some(IGMP.to_owned()),
        igmp6: Some(IGMP6.to_owned()),
        status: Some(STATUS.to_owned()),
        ipv6_disabled: false,
    }
}

fn with(change: impl FnOnce(&mut AirGappedHostFactsV1)) -> AirGappedHostFactsV1 {
    let mut facts = air_gapped();
    change(&mut facts);
    facts
}

fn appended(text: Option<&str>, line: &str) -> Option<String> {
    text.map(|text| format!("{text}{line}\n"))
}

fn replaced(text: Option<&str>, from: &str, to: &str) -> Option<String> {
    let text = text.unwrap_or_default();
    assert!(text.contains(from), "{from}");
    Some(text.replacen(from, to, 1))
}

#[test]
fn a_loopback_only_namespace_without_network_capabilities_passes() {
    assert_eq!(check_air_gapped_no_route_v1(&air_gapped()), Ok(()));
    // Every fallback tunnel device name passes on its own.
    for device in [
        "sit0", "tunl0", "ip6tnl0", "gre0", "gretap0", "erspan0", "ip_vti0", "ip6_vti0", "ip6gre0",
    ] {
        let facts =
            with(|facts| facts.dev = appended(facts.dev.as_deref(), &format!("{device}: 0 0")));
        assert_eq!(check_air_gapped_no_route_v1(&facts), Ok(()), "{device}");
    }
    // A bounding set may keep a capability while no_new_privs is set.
    let facts = with(|facts| {
        facts.status = replaced(
            facts.status.as_deref(),
            "CapBnd:\t0000000000000000",
            "CapBnd:\t000001ffffffffff",
        );
    });
    assert_eq!(check_air_gapped_no_route_v1(&facts), Ok(()));
    // Empty memberships, addresses and IPv6 routes pass.
    let facts = with(|facts| {
        facts.igmp =
            Some("Idx\tDevice    : Count Querier\tGroup    Users Timer\tReporter\n".to_owned());
        facts.igmp6 = Some(String::new());
        facts.if_inet6 = Some(String::new());
        facts.ipv6_route = Some(String::new());
        facts.fib_trie = Some(String::new());
    });
    assert_eq!(check_air_gapped_no_route_v1(&facts), Ok(()));
}

#[test]
fn with_ipv6_disabled_the_three_ipv6_files_count_as_empty() {
    let facts = with(|facts| {
        facts.ipv6_disabled = true;
        facts.ipv6_route = None;
        facts.if_inet6 = None;
        facts.igmp6 = None;
    });
    assert_eq!(check_air_gapped_no_route_v1(&facts), Ok(()));
    // Only the IPv6 files: a missing IPv4 fact still denies.
    let facts = with(|facts| {
        facts.ipv6_disabled = true;
        facts.igmp = None;
    });
    assert_eq!(
        check_air_gapped_no_route_v1(&facts),
        Err(Denial::Unreadable(Fact::Igmp))
    );
}

#[test]
fn every_absent_fact_denies() {
    type Clear = fn(&mut AirGappedHostFactsV1);
    let cases: [(Fact, Clear); 8] = [
        (Fact::Dev, |facts| facts.dev = None),
        (Fact::Route, |facts| facts.route = None),
        (Fact::Ipv6Route, |facts| facts.ipv6_route = None),
        (Fact::IfInet6, |facts| facts.if_inet6 = None),
        (Fact::FibTrie, |facts| facts.fib_trie = None),
        (Fact::Igmp, |facts| facts.igmp = None),
        (Fact::Igmp6, |facts| facts.igmp6 = None),
        (Fact::Status, |facts| facts.status = None),
    ];
    for (fact, clear) in cases {
        assert_eq!(
            check_air_gapped_no_route_v1(&with(clear)),
            Err(Denial::Unreadable(fact)),
            "{fact}"
        );
        assert!(fact.path().starts_with("/proc/self/"), "{fact}");
        assert_eq!(
            Denial::Unreadable(fact).to_string(),
            format!("{} is absent, unreadable or unparsable", fact.path())
        );
        assert_eq!(fact.to_string(), fact.path());
    }
}

#[test]
fn unparsable_facts_deny() {
    type Change = fn(&mut AirGappedHostFactsV1);
    let cases: [(Fact, Change); 20] = [
        (Fact::Dev, |facts| facts.dev = Some("lo: 0\n".to_owned())),
        (Fact::Dev, |facts| facts.dev = Some("a|b\n".to_owned())),
        (Fact::Dev, |facts| {
            facts.dev = appended(facts.dev.as_deref(), "no-colon")
        }),
        (Fact::Dev, |facts| {
            facts.dev = appended(facts.dev.as_deref(), "   : 0 0")
        }),
        // `lo` must be listed (ADR-135 §4 item 1).
        (Fact::Dev, |facts| {
            facts.dev = replaced(facts.dev.as_deref(), "    lo:", "  sit0:");
        }),
        (Fact::Route, |facts| {
            facts.route = Some("Destination\n".to_owned())
        }),
        // A row with more fields than its format is unparsable too.
        (Fact::Ipv6Route, |facts| {
            facts.ipv6_route = Some(IPV6_ROUTE.replace("       lo", " extra lo"));
        }),
        (Fact::Igmp6, |facts| {
            facts.igmp6 = Some(IGMP6.replace(" 0\n", " 0 extra\n"));
        }),
        (Fact::Route, |facts| facts.route = Some(String::new())),
        (Fact::Ipv6Route, |facts| {
            facts.ipv6_route = Some("00 lo\n".to_owned())
        }),
        (Fact::IfInet6, |facts| {
            facts.if_inet6 = Some("::1 lo\n".to_owned())
        }),
        (Fact::FibTrie, |facts| {
            facts.fib_trie = Some("     |-- not-an-address\n".to_owned())
        }),
        (Fact::FibTrie, |facts| {
            facts.fib_trie = Some("        /32 host LOCAL\n".to_owned())
        }),
        (Fact::Igmp, |facts| {
            facts.igmp = Some("1\tlo :     1      V3\n".to_owned())
        }),
        (Fact::Igmp, |facts| {
            facts.igmp = Some("Idx\tDevice\n\t\t\t\t010000E0     1 0:00000000\t\t0\n".to_owned());
        }),
        (Fact::Igmp, |facts| {
            facts.igmp = appended(facts.igmp.as_deref(), "x\tlo        :     1      V3")
        }),
        (Fact::Igmp, |facts| {
            facts.igmp = appended(facts.igmp.as_deref(), "no colon here")
        }),
        (Fact::Igmp6, |facts| {
            facts.igmp6 = Some("1 lo ff02\n".to_owned())
        }),
        (Fact::Igmp6, |facts| {
            facts.igmp6 = Some("x lo ff020000000000000000000000000001 1 0000000C 0\n".to_owned());
        }),
        (Fact::Status, |facts| {
            facts.status = replaced(
                facts.status.as_deref(),
                "CapEff:\t0000000000000000",
                "CapEff:\tzz",
            );
        }),
    ];
    for (fact, change) in cases {
        assert_eq!(
            check_air_gapped_no_route_v1(&with(change)),
            Err(Denial::Unreadable(fact)),
            "{fact}"
        );
    }
    for (from, to) in [
        ("CapPrm:\t0000000000000000\n", ""),
        ("CapAmb:\t0000000000000000\n", ""),
        ("CapBnd:\t0000000000000000\n", ""),
        ("NoNewPrivs:\t1\n", ""),
        ("NoNewPrivs:\t1", "NoNewPrivs:\t2"),
        ("Seccomp:\t2\n", ""),
    ] {
        let facts = with(|facts| facts.status = replaced(facts.status.as_deref(), from, to));
        assert_eq!(
            check_air_gapped_no_route_v1(&facts),
            Err(Denial::Unreadable(Fact::Status)),
            "{from}"
        );
    }
}

#[test]
fn every_network_path_denies() {
    type Change = fn(&mut AirGappedHostFactsV1);
    let cases: [(Denial, Change); 12] = [
        (Denial::Interface, |facts| {
            facts.dev = appended(facts.dev.as_deref(), "  eth0: 0 0 0 0 0 0 0 0 0");
        }),
        // A device whose name holds a colon is never read as `lo`.
        (Denial::Interface, |facts| {
            facts.dev = appended(facts.dev.as_deref(), "  lo:x: 0 0 0 0 0 0 0 0 0");
        }),
        (Denial::Membership, |facts| {
            facts.igmp = appended(facts.igmp.as_deref(), "2\tlo:x      :     1      V3");
        }),
        (Denial::Route, |facts| {
            facts.route = appended(
                facts.route.as_deref(),
                "eth0\t00000000\t0100000A\t0003\t0\t0\t0\t00000000\t0\t0\t0",
            );
        }),
        (Denial::Route, |facts| {
            facts.ipv6_route = appended(
                facts.ipv6_route.as_deref(),
                "fe800000000000000000000000000000 40 00000000000000000000000000000000 00 \
                 00000000000000000000000000000000 00000100 00000001 00000000 00000001     gre0",
            );
        }),
        (Denial::Address, |facts| {
            facts.if_inet6 = appended(
                facts.if_inet6.as_deref(),
                "fe800000000000000000000000000001 02 40 20 80     gre0",
            );
        }),
        // A real interface renamed to a fallback device name has an address.
        (Denial::Address, |facts| {
            facts.fib_trie = appended(
                facts.fib_trie.as_deref(),
                "     |-- 10.0.0.2\n        /32 host LOCAL",
            );
        }),
        // An interface that is up but has no address joins the all-hosts groups.
        (Denial::Membership, |facts| {
            facts.igmp = appended(
                facts.igmp.as_deref(),
                "2\tgre0      :     1      V3\n\t\t\t\t010000E0     1 0:00000000\t\t0",
            );
        }),
        (Denial::Membership, |facts| {
            facts.igmp6 = appended(
                facts.igmp6.as_deref(),
                "2    gre0            ff020000000000000000000000000001     1 0000000C 0",
            );
        }),
        (Denial::Capability, |facts| {
            facts.status = replaced(
                facts.status.as_deref(),
                "CapEff:\t0000000000000000",
                "CapEff:\t0000000000001000",
            );
        }),
        (Denial::BoundingSet, |facts| {
            facts.status = Some(
                STATUS
                    .replace("CapBnd:\t0000000000000000", "CapBnd:\t0000000000002000")
                    .replace("NoNewPrivs:\t1", "NoNewPrivs:\t0"),
            );
        }),
        (Denial::Seccomp, |facts| {
            facts.status = replaced(facts.status.as_deref(), "Seccomp:\t2", "Seccomp:\t0");
        }),
    ];
    for (denial, change) in cases {
        assert!(!denial.to_string().is_empty());
        assert_eq!(
            check_air_gapped_no_route_v1(&with(change)),
            Err(denial),
            "{denial}"
        );
    }
    // Each of the three capabilities, in each of the three held sets.
    for set in ["CapEff", "CapPrm", "CapAmb"] {
        for bit in ["0000000000001000", "0000000000002000", "0000000000200000"] {
            let facts = with(|facts| {
                facts.status = replaced(
                    facts.status.as_deref(),
                    &format!("{set}:\t0000000000000000"),
                    &format!("{set}:\t{bit}"),
                );
            });
            assert_eq!(
                check_air_gapped_no_route_v1(&facts),
                Err(Denial::Capability),
                "{set} {bit}"
            );
        }
    }
    // Any other capability is not a network capability.
    let facts = with(|facts| {
        facts.status = replaced(
            facts.status.as_deref(),
            "CapEff:\t0000000000000000",
            "CapEff:\t0000000000000800",
        );
    });
    assert_eq!(check_air_gapped_no_route_v1(&facts), Ok(()));
}

fn loopback() -> GatewayServeCompositionV1 {
    GatewayServeCompositionV1 {
        tcp_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
        owntracks_owner_key: None,
        fork_admission_socket: None,
        ledger_source: None,
        network_grants: std::collections::BTreeSet::new(),
    }
}

/// Re-execute `test` of this binary under `program` with `marker` set and
/// require it to pass.
fn reexecute(program: &mut Command, marker: &str, test: &str) -> TestResult {
    let status = program
        .arg(std::env::current_exe()?)
        .args(["--exact", test, "--nocapture"])
        .env(marker, "1")
        .status()?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("{test} failed when re-executed: {status}").into())
    }
}

#[test]
fn the_air_gapped_mode_binds_inside_the_test_shape() -> TestResult {
    const TEST: &str = "the_air_gapped_mode_binds_inside_the_test_shape";
    if std::env::var_os(INSIDE).is_none() {
        let script =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/air-gapped-namespace.sh");
        return reexecute(&mut Command::new(script), INSIDE, TEST);
    }
    verify_gateway_serve_composition_v1(GatewayModeProfileIdV1::AirGapped, &loopback())?;
    let mut host = ErasureExecutionHostV1::open_with_authority(
        StoreConfig::Memory,
        &ErasureCoordinatorCompositionV1::closed(),
        pos_core::ErasureRecoveryLimitsV1::compiled_maximum(),
    )?;
    bind_gateway_mode_v1(GatewayModeProfileIdV1::AirGapped, loopback(), &mut host)?;
    Ok(())
}

/// ADR-135 §4 and the owner decision of 2026-11-16: in a user namespace that
/// still holds `CAP_NET_ADMIN`, the Air-Gapped composition is refused in
/// step 2, before any store, while the Local one is not.
#[test]
fn the_air_gapped_mode_is_refused_where_a_network_capability_is_held() -> TestResult {
    const TEST: &str = "the_air_gapped_mode_is_refused_where_a_network_capability_is_held";
    if std::env::var_os(CAPABLE).is_none() {
        let mut unshare = Command::new("unshare");
        unshare.args(["--user", "--map-root-user", "--net"]);
        return reexecute(&mut unshare, CAPABLE, TEST);
    }
    let refused =
        verify_gateway_serve_composition_v1(GatewayModeProfileIdV1::AirGapped, &loopback());
    // The fresh namespace holds only `lo`, so the held capability is the refusal.
    let refusal = refused
        .err()
        .ok_or("the Air-Gapped composition was not refused")?;
    assert_eq!(
        refusal,
        GatewayModeErrorV1::NetworkPathPresent(Denial::Capability)
    );
    assert!(
        refusal
            .to_string()
            .starts_with("air-gapped-no-route refused"),
        "{refusal}"
    );
    verify_gateway_serve_composition_v1(GatewayModeProfileIdV1::Local, &loopback())?;
    Ok(())
}
