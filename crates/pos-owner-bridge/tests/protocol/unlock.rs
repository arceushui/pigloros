//! Unlock: Get ceremony, wait for exit, open, persist the binding update, then release.

use super::{
    bytes32, eligible, expected_prf, honest, unlock_binding as binding, Call, FakeUnlock, Hook,
    Moment, Rig, TestResult,
};
use pos_owner_bridge::fake::buffers::LogEntry;
use pos_owner_bridge::fake::clock::FakeRandom;
use pos_owner_bridge::fake::honest::HonestConfig;
use pos_owner_bridge::fake::signer::ReplyShape;
use pos_owner_bridge::{
    BindingUpdate, BridgeConfig, BridgeError, BridgeStatus, OwnerError, OwnerErrorKind,
    ProtocolCode, RejectedCode, UnavailableCode,
};

type Tweak = fn(&mut ReplyShape);

fn rig(page: HonestConfig) -> Result<Rig, Box<dyn std::error::Error>> {
    Rig::new(page, FakeRandom::seeded(9))
}

#[test]
fn unlock_opens_persists_and_only_then_releases() -> TestResult {
    let page = honest(0);
    let prf = expected_prf(&page);
    let mut rig = rig(page)?;
    let mut port = FakeUnlock::new();
    let binding = binding("owner", 0)?;
    let session = rig.bridge.unlock(&binding, &bytes32(0x60), &mut port)?;
    assert_eq!(session, prf);
    assert_eq!(port.calls, [Call::Open, Call::Persist, Call::Release]);
    assert_eq!(port.prf, Some(prf));
    assert_eq!(
        port.updates,
        [BindingUpdate {
            sign_count: 1,
            backup_state: false
        }]
    );
    assert_eq!(rig.bridge.status(), BridgeStatus::Ready);
    Ok(())
}

#[test]
fn consecutive_ceremonies_never_reuse_a_generation() -> TestResult {
    let mut rig = rig(honest(0))?;
    let mut port = FakeUnlock::new();
    let first = binding("owner", 0)?;
    rig.bridge.unlock(&first, &bytes32(0x60), &mut port)?;
    let second = binding("owner", 1)?;
    rig.bridge.unlock(&second, &bytes32(0x60), &mut port)?;
    let generations: Vec<u32> = rig
        .surface
        .log()
        .iter()
        .filter_map(|entry| match entry {
            LogEntry::Post { generation, .. } => Some(*generation),
            _ => None,
        })
        .collect();
    assert_eq!(generations, [1, 2]);
    Ok(())
}

#[test]
fn a_ceremony_ending_at_the_last_generation_succeeds_and_the_next_is_refused() -> TestResult {
    let config = BridgeConfig::default().with_start_generation(u32::MAX - 1);
    let mut rig = Rig::with_hook(honest(0), Hook::None, FakeRandom::seeded(9), config)?;
    let mut port = FakeUnlock::new();
    let first = binding("owner", 0)?;
    rig.bridge.unlock(&first, &bytes32(0x60), &mut port)?;
    assert_eq!(rig.bridge.status(), BridgeStatus::Ready);
    let second = binding("owner", 1)?;
    let exhausted = BridgeError::Unavailable(UnavailableCode::GenerationExhausted);
    assert_eq!(
        rig.bridge.unlock(&second, &bytes32(0x60), &mut port),
        Err(exhausted)
    );
    assert_eq!(
        rig.bridge.status(),
        BridgeStatus::Unavailable(UnavailableCode::GenerationExhausted)
    );
    Ok(())
}

#[test]
fn an_illegal_observation_after_verification_discards_the_result_and_calls_no_port() -> TestResult {
    let mut rig = Rig::with_hook(
        honest(0),
        Hook::Storm(vec![9]),
        FakeRandom::seeded(9),
        BridgeConfig::default(),
    )?;
    let mut port = FakeUnlock::new();
    let binding = binding("owner", 0)?;
    let outcome = rig.bridge.unlock(&binding, &bytes32(0x60), &mut port);
    assert_eq!(
        outcome.err(),
        Some(BridgeError::Protocol(ProtocolCode::UnexpectedState))
    );
    // The reply was consumed and its copies compared before the illegal word appeared.
    let log = rig.surface.log();
    assert!(log
        .iter()
        .any(|entry| matches!(entry, LogEntry::HostCopy { state: 3, .. })));
    assert!(port.calls.is_empty());
    assert!(port.prf.is_none());
    Ok(())
}

#[test]
fn a_second_document_completion_after_consumption_discards_the_result_before_the_port() -> TestResult
{
    for moment in [Moment::Consumed, Moment::Closing] {
        let mut rig = Rig::with_hook(
            honest(0),
            Hook::SecondCompletion(moment),
            FakeRandom::seeded(9),
            BridgeConfig::default(),
        )?;
        let mut port = FakeUnlock::new();
        let binding = binding("owner", 0)?;
        let outcome = rig.bridge.unlock(&binding, &bytes32(0x60), &mut port);
        assert_eq!(
            outcome.err(),
            Some(BridgeError::Protocol(ProtocolCode::DuplicateDocumentLoad)),
            "{moment:?}"
        );
        assert!(port.calls.is_empty(), "{moment:?}");
        assert!(port.prf.is_none(), "{moment:?}");
        let log = rig.surface.log();
        assert!(log.contains(&LogEntry::ExitObserved), "{moment:?}");
        assert!(log.contains(&LogEntry::Finished), "{moment:?}");
        assert_eq!(rig.bridge.status(), BridgeStatus::Ready);
    }
    Ok(())
}

#[test]
fn a_failed_binding_update_releases_no_root() -> TestResult {
    let mut rig = rig(honest(0))?;
    let mut port = FakeUnlock::new();
    port.persist_error = Some(OwnerError::new(OwnerErrorKind::DurableWrite));
    let binding = binding("owner", 0)?;
    let outcome = rig.bridge.unlock(&binding, &bytes32(0x60), &mut port);
    assert_eq!(
        outcome,
        Err(BridgeError::Owner(OwnerError::new(
            OwnerErrorKind::DurableWrite
        )))
    );
    assert_eq!(port.calls, [Call::Open, Call::Persist]);
    Ok(())
}

#[test]
fn a_failed_open_stops_before_the_update() -> TestResult {
    let mut rig = rig(honest(0))?;
    let mut port = FakeUnlock::new();
    port.open_error = Some(OwnerError::new(OwnerErrorKind::Wrap));
    let binding = binding("owner", 0)?;
    let outcome = rig.bridge.unlock(&binding, &bytes32(0x60), &mut port);
    assert_eq!(
        outcome,
        Err(BridgeError::Owner(OwnerError::new(OwnerErrorKind::Wrap)))
    );
    assert_eq!(port.calls, [Call::Open]);
    Ok(())
}

#[test]
fn a_rejected_assertion_never_reaches_the_owner_port() -> TestResult {
    let cases: [(Tweak, u32, RejectedCode); 2] = [
        (eligible, 0, RejectedCode::Signature),
        (|_| {}, 5, RejectedCode::Signature),
    ];
    for (tweak, counter, code) in cases {
        let page = HonestConfig {
            tweak: Some(tweak),
            ..honest(0)
        };
        let mut rig = rig(page)?;
        let mut port = FakeUnlock::new();
        let binding = binding("owner", counter)?;
        let outcome = rig.bridge.unlock(&binding, &bytes32(0x60), &mut port);
        assert_eq!(outcome, Err(BridgeError::Rejected(code)));
        assert!(port.calls.is_empty());
    }
    Ok(())
}

#[test]
fn an_unavailable_surface_refuses_unlock() -> TestResult {
    let mut rig = rig(honest(0))?;
    rig.loopback.fail_probes_from(Some(1));
    let mut port = FakeUnlock::new();
    let binding = binding("owner", 0)?;
    let changed = BridgeError::Unavailable(UnavailableCode::LoopbackChanged);
    assert_eq!(
        rig.bridge.unlock(&binding, &bytes32(0x60), &mut port),
        Err(changed)
    );
    assert_eq!(
        rig.bridge.unlock(&binding, &bytes32(0x60), &mut port),
        Err(changed)
    );
    assert!(port.calls.is_empty());
    Ok(())
}

#[test]
fn an_rng_failure_refuses_unlock_before_any_environment_exists() -> TestResult {
    let mut rig = Rig::new(honest(0), FakeRandom::failing_after(2, 0))?;
    let mut port = FakeUnlock::new();
    let binding = binding("owner", 0)?;
    let outcome = rig.bridge.unlock(&binding, &bytes32(0x60), &mut port);
    assert_eq!(
        outcome,
        Err(BridgeError::Unavailable(UnavailableCode::RngUnavailable))
    );
    assert!(port.calls.is_empty());
    assert!(rig.surface.log().is_empty());
    Ok(())
}
