//! Enrollment with D2 confirmation: call order, abandonment, budget and status (ADR-110 §8).

use std::cell::RefCell;
use std::rc::Rc;
use std::time::Duration;

use pos_owner_bridge::fake::buffers::LogEntry;
use pos_owner_bridge::fake::clock::{FakeClock, FakeRandom};
use pos_owner_bridge::fake::honest::{CreatePrf, HonestConfig, HonestPage};
use pos_owner_bridge::fake::host::{FakeLoopback, FakeStore};
use pos_owner_bridge::fake::stepper::FakeHost;
use pos_owner_bridge::fake::surface::{FakeSurface, SurfaceConfig};
use pos_owner_bridge::{
    BridgeConfig, BridgeError, BridgeStatus, LifecycleCode, OwnerBridge, OwnerError,
    OwnerErrorKind, ProtocolCode, QuarantineCode, RejectedCode, SecureRandom, SurfaceEvent,
    UnavailableCode,
};

use super::{
    context, honest, no_prf, wrong_key, Boxed, Call, FakeEnrollment, Hook, Moment, Rig, TestResult,
    CREDENTIAL_ID,
};

type Request = ([u8; 16], [u8; 32], [u8; 32], Option<[u8; 32]>);

const OWNER_FAILURE: OwnerError = OwnerError::new(OwnerErrorKind::Wrap);

fn rig_with(page: HonestConfig) -> Result<(Rig, FakeEnrollment), Box<dyn std::error::Error>> {
    let rig = Rig::new(page, FakeRandom::seeded(1))?;
    let mut port = FakeEnrollment::new();
    port.surface = Some(rig.surface.clone());
    Ok((rig, port))
}

#[test]
fn enrollment_runs_e1_to_e5_with_a_fresh_unlock_assertion_before_the_binding_commits() -> TestResult
{
    let (mut rig, mut port) = rig_with(honest(0))?;
    rig.bridge.enroll(&context(), &mut port)?;
    assert_eq!(
        port.calls,
        [Call::Unbound, Call::Seal, Call::Confirm, Call::Commit]
    );
    assert!(port.seal_prf.is_some());
    assert_eq!(port.seal_prf, port.confirm_prf);
    assert_eq!(port.at_calls, [(1, 1), (2, 2)]);
    let committed = port.committed.ok_or("nothing was committed")?;
    let binding = committed.binding().boxed()?;
    assert_eq!(binding.credential_id(), CREDENTIAL_ID);
    assert_eq!(binding.sign_count(), 1);
    assert!(!binding.backup_state());
    assert_eq!(binding.owner_id(), "owner");
    assert_eq!(rig.bridge.status(), BridgeStatus::Ready);
    Ok(())
}

#[test]
fn a_create_without_a_prf_needs_a_restricted_assertion_as_the_source() -> TestResult {
    let page = HonestConfig {
        create_prf: CreatePrf::EnabledOnly,
        ..honest(0)
    };
    let (mut rig, mut port) = rig_with(page)?;
    rig.bridge.enroll(&context(), &mut port)?;
    assert_eq!(
        port.calls,
        [Call::Unbound, Call::Seal, Call::Confirm, Call::Commit]
    );
    assert_eq!(port.at_calls, [(2, 2), (3, 3)]);
    assert!(port.seal_prf.is_some());
    assert_eq!(port.seal_prf, port.confirm_prf);
    let committed = port.committed.ok_or("nothing was committed")?;
    assert_eq!(committed.binding().boxed()?.sign_count(), 2);
    Ok(())
}

#[test]
fn a_substituted_prf_at_confirmation_leaves_no_binding() -> TestResult {
    let page = HonestConfig {
        substitute_get_prf: Some([0xee; 32]),
        ..honest(0)
    };
    let (mut rig, mut port) = rig_with(page)?;
    let outcome = rig.bridge.enroll(&context(), &mut port);
    assert_eq!(
        outcome,
        Err(BridgeError::Owner(OwnerError::new(OwnerErrorKind::Wrap)))
    );
    assert_eq!(
        port.calls,
        [Call::Unbound, Call::Seal, Call::Confirm, Call::Abandon]
    );
    assert!(port.committed.is_none());
    Ok(())
}

#[test]
fn an_illegal_observation_after_the_create_verification_calls_no_port_method() -> TestResult {
    let mut rig = Rig::with_hook(
        honest(0),
        Hook::Storm(vec![9]),
        FakeRandom::seeded(1),
        BridgeConfig::default(),
    )?;
    let mut port = FakeEnrollment::new();
    let outcome = rig.bridge.enroll(&context(), &mut port);
    assert_eq!(
        outcome,
        Err(BridgeError::Protocol(ProtocolCode::UnexpectedState))
    );
    assert!(rig
        .surface
        .log()
        .iter()
        .any(|entry| matches!(entry, LogEntry::HostCopy { state: 3, .. })));
    assert!(port.calls.is_empty());
    assert!(port.seal_prf.is_none());
    Ok(())
}

#[test]
fn a_second_document_completion_after_the_create_consumption_calls_no_port_method() -> TestResult {
    for moment in [Moment::Consumed, Moment::Closing] {
        let mut rig = Rig::with_hook(
            honest(0),
            Hook::SecondCompletion(moment),
            FakeRandom::seeded(1),
            BridgeConfig::default(),
        )?;
        let mut port = FakeEnrollment::new();
        let outcome = rig.bridge.enroll(&context(), &mut port);
        assert_eq!(
            outcome,
            Err(BridgeError::Protocol(ProtocolCode::DuplicateDocumentLoad)),
            "{moment:?}"
        );
        assert!(port.calls.is_empty(), "{moment:?}");
        let log = rig.surface.log();
        assert!(log.contains(&LogEntry::ExitObserved), "{moment:?}");
        assert!(log.contains(&LogEntry::Finished), "{moment:?}");
        assert_eq!(rig.bridge.status(), BridgeStatus::Ready);
    }
    Ok(())
}

#[test]
fn a_fingerprint_that_differs_is_an_enrollment_confirmation_failure() -> TestResult {
    let (mut rig, mut port) = rig_with(honest(0))?;
    port.lie_in_confirm = true;
    let outcome = rig.bridge.enroll(&context(), &mut port);
    assert_eq!(
        outcome,
        Err(BridgeError::Rejected(RejectedCode::EnrollmentConfirmation))
    );
    assert_eq!(port.calls.last(), Some(&Call::Abandon));
    assert!(!port.calls.contains(&Call::Commit));
    Ok(())
}

#[test]
fn an_already_bound_credential_is_rejected_before_sealing() -> TestResult {
    let (mut rig, mut port) = rig_with(honest(0))?;
    port.already_bound = true;
    let outcome = rig.bridge.enroll(&context(), &mut port);
    assert_eq!(
        outcome,
        Err(BridgeError::Rejected(RejectedCode::CredentialAlreadyBound))
    );
    assert_eq!(port.calls, [Call::Unbound]);
    Ok(())
}

#[test]
fn owner_port_failures_are_wrapped_and_abandon_only_a_sealed_candidate_before_commit() -> TestResult
{
    type Prepare = fn(&mut FakeEnrollment);
    let cases: [(Prepare, Vec<Call>); 3] = [
        (
            |port| port.unbound_error = Some(OWNER_FAILURE),
            vec![Call::Unbound],
        ),
        (
            |port| port.seal_error = Some(OWNER_FAILURE),
            vec![Call::Unbound, Call::Seal],
        ),
        (
            |port| port.commit_error = Some(OWNER_FAILURE),
            vec![Call::Unbound, Call::Seal, Call::Confirm, Call::Commit],
        ),
    ];
    for (prepare, expected) in cases {
        let (mut rig, mut port) = rig_with(honest(0))?;
        prepare(&mut port);
        let outcome = rig.bridge.enroll(&context(), &mut port);
        assert_eq!(outcome, Err(BridgeError::Owner(OWNER_FAILURE)));
        assert_eq!(port.calls, expected);
        assert_eq!(rig.bridge.status(), BridgeStatus::Ready);
    }
    Ok(())
}

#[test]
fn a_failed_create_never_reaches_the_owner_port_beyond_abandon() -> TestResult {
    let page = HonestConfig {
        cancel: true,
        ..honest(0)
    };
    let (mut rig, mut port) = rig_with(page)?;
    let outcome = rig.bridge.enroll(&context(), &mut port);
    assert_eq!(
        outcome,
        Err(BridgeError::Lifecycle(LifecycleCode::ClientFailed))
    );
    assert!(port.calls.is_empty());
    Ok(())
}

#[test]
fn a_confirmation_that_fails_verification_abandons_the_sealed_candidate() -> TestResult {
    let page = HonestConfig {
        tweak: Some(wrong_key),
        ..honest(0)
    };
    let (mut rig, mut port) = rig_with(page)?;
    let outcome = rig.bridge.enroll(&context(), &mut port);
    assert_eq!(outcome, Err(BridgeError::Rejected(RejectedCode::Signature)));
    assert_eq!(port.calls, [Call::Unbound, Call::Seal, Call::Abandon]);
    Ok(())
}

#[test]
fn a_source_assertion_without_a_prf_fails_closed_before_sealing() -> TestResult {
    let page = HonestConfig {
        create_prf: CreatePrf::EnabledOnly,
        tweak: Some(no_prf),
        ..honest(0)
    };
    let (mut rig, mut port) = rig_with(page)?;
    let outcome = rig.bridge.enroll(&context(), &mut port);
    assert_eq!(
        outcome,
        Err(BridgeError::Unavailable(UnavailableCode::PrfUnsupported))
    );
    assert_eq!(port.calls, [Call::Unbound]);
    Ok(())
}

#[test]
fn the_total_enrollment_budget_fails_the_confirmation_ceremony() -> TestResult {
    let (mut rig, mut port) = rig_with(honest(0))?;
    port.seal_delay = Some((rig.clock.clone(), Duration::from_secs(301)));
    let outcome = rig.bridge.enroll(&context(), &mut port);
    assert_eq!(
        outcome,
        Err(BridgeError::Lifecycle(
            LifecycleCode::EnrollmentBudgetExceeded
        ))
    );
    assert_eq!(port.calls, [Call::Unbound, Call::Seal, Call::Abandon]);
    Ok(())
}

#[test]
fn an_rng_failure_starts_no_environment_and_is_not_sticky() -> TestResult {
    let mut rig = Rig::new(honest(0), FakeRandom::failing_after(1, 0))?;
    let mut port = FakeEnrollment::new();
    port.surface = Some(rig.surface.clone());
    let outcome = rig.bridge.enroll(&context(), &mut port);
    assert_eq!(
        outcome,
        Err(BridgeError::Unavailable(UnavailableCode::RngUnavailable))
    );
    assert!(rig.surface.log().is_empty());
    assert_eq!(rig.bridge.status(), BridgeStatus::Ready);
    Ok(())
}

#[test]
fn generation_exhaustion_makes_the_surface_unavailable_until_restart() -> TestResult {
    let config = BridgeConfig::default().with_start_generation(u32::MAX);
    let mut rig = Rig::with_hook(honest(0), Hook::None, FakeRandom::seeded(1), config)?;
    let mut port = FakeEnrollment::new();
    let exhausted = BridgeError::Unavailable(UnavailableCode::GenerationExhausted);
    assert_eq!(rig.bridge.enroll(&context(), &mut port), Err(exhausted));
    assert_eq!(
        rig.bridge.status(),
        BridgeStatus::Unavailable(UnavailableCode::GenerationExhausted)
    );
    port.calls.clear();
    assert_eq!(rig.bridge.enroll(&context(), &mut port), Err(exhausted));
    assert!(port.calls.is_empty());
    Ok(())
}

#[test]
fn a_changed_loopback_makes_the_surface_unavailable_until_restart() -> TestResult {
    let (mut rig, mut port) = rig_with(honest(0))?;
    rig.loopback.fail_probes_from(Some(1));
    let changed = BridgeError::Unavailable(UnavailableCode::LoopbackChanged);
    assert_eq!(rig.bridge.enroll(&context(), &mut port), Err(changed));
    assert_eq!(
        rig.bridge.status(),
        BridgeStatus::Unavailable(UnavailableCode::LoopbackChanged)
    );
    assert_eq!(rig.bridge.enroll(&context(), &mut port), Err(changed));
    Ok(())
}

#[test]
fn a_quarantined_surface_refuses_ceremonies_until_the_exit_arrives() -> TestResult {
    let surface = SurfaceConfig {
        exit_delay: None,
        ..SurfaceConfig::default()
    };
    let mut rig = Rig::with_surface(
        honest(0),
        Hook::None,
        FakeRandom::seeded(1),
        BridgeConfig::default(),
        surface,
    )?;
    let mut port = FakeEnrollment::new();
    let quarantined = BridgeError::Quarantine(QuarantineCode::CleanupTimeout);
    assert_eq!(rig.bridge.enroll(&context(), &mut port), Err(quarantined));
    assert_eq!(
        rig.bridge.status(),
        BridgeStatus::Quarantined(QuarantineCode::CleanupTimeout)
    );
    assert!(port.calls.is_empty());
    port.calls.clear();
    assert_eq!(rig.bridge.enroll(&context(), &mut port), Err(quarantined));
    assert!(port.calls.is_empty());
    assert_eq!(
        rig.bridge.poll_quarantine(),
        BridgeStatus::Quarantined(QuarantineCode::CleanupTimeout)
    );
    rig.surface.schedule(
        rig.clock.elapsed(),
        SurfaceEvent::BrowserExited { browser_pid: 4242 },
    );
    assert_eq!(rig.bridge.poll_quarantine(), BridgeStatus::Ready);
    assert!(rig.store.records_now().is_empty());
    assert_eq!(rig.bridge.poll_quarantine(), BridgeStatus::Ready);
    Ok(())
}

#[test]
fn a_binding_that_violates_the_closed_schema_abandons_the_sealed_candidate() -> TestResult {
    let (mut rig, mut port) = rig_with(honest(0))?;
    let mut oversized = context();
    oversized.owner_id = "x".repeat(5_000);
    let outcome = rig.bridge.enroll(&oversized, &mut port);
    assert_eq!(
        outcome,
        Err(BridgeError::Protocol(ProtocolCode::LengthOutOfBounds))
    );
    assert_eq!(
        port.calls,
        [Call::Unbound, Call::Seal, Call::Confirm, Call::Abandon]
    );
    Ok(())
}

#[test]
fn an_rng_failure_at_a_later_ceremony_abandons_the_enrollment() -> TestResult {
    let mut rig = Rig::new(honest(0), FakeRandom::failing_after(1, 1))?;
    let mut port = FakeEnrollment::new();
    let outcome = rig.bridge.enroll(&context(), &mut port);
    assert_eq!(
        outcome,
        Err(BridgeError::Unavailable(UnavailableCode::RngUnavailable))
    );
    assert_eq!(port.calls, [Call::Unbound, Call::Seal, Call::Abandon]);
    Ok(())
}

/// A random source that records how many bytes each draw asked for.
struct Recording {
    inner: FakeRandom,
    lengths: Rc<RefCell<Vec<usize>>>,
}

impl SecureRandom for Recording {
    fn fill(&mut self, out: &mut [u8]) -> Result<(), UnavailableCode> {
        self.lengths.borrow_mut().push(out.len());
        self.inner.fill(out)
    }
}

#[test]
fn each_ceremony_draws_its_random_block_in_the_documented_layout() -> TestResult {
    let clock = FakeClock::start();
    let loopback = FakeLoopback::default();
    let page = HonestPage::new(honest(0)).boxed()?;
    let surface = FakeSurface::new(
        clock.clone(),
        loopback.clone(),
        Box::new(page),
        SurfaceConfig::default(),
    );
    let handle = surface.handle();
    let lengths = Rc::new(RefCell::new(Vec::new()));
    let random = Recording {
        inner: FakeRandom::seeded(7),
        lengths: Rc::clone(&lengths),
    };
    let host = FakeHost::new(clock.clone(), surface, loopback, FakeStore::default());
    let mut bridge = OwnerBridge::new(host, random, clock, BridgeConfig::default());
    let mut port = FakeEnrollment::new();
    bridge.enroll(&context(), &mut port)?;
    assert_eq!(*lengths.borrow(), [112, 48]);
    let mut expected = FakeRandom::seeded(7);
    let (mut create, mut get) = ([0_u8; 112], [0_u8; 48]);
    expected
        .fill(&mut create)
        .map_err(BridgeError::Unavailable)?;
    expected.fill(&mut get).map_err(BridgeError::Unavailable)?;
    let requests: Vec<Request> = handle
        .log()
        .into_iter()
        .filter_map(|entry| match entry {
            LogEntry::PageWebAuthn {
                ceremony_id,
                challenge,
                prf_input,
                user_handle,
                ..
            } => Some((ceremony_id, challenge, prf_input, user_handle)),
            _ => None,
        })
        .collect();
    let (id, rest) = create.split_at(16);
    let (challenge, rest) = rest.split_at(32);
    let (user_handle, rest) = rest.split_at(32);
    let (prf_input, _) = rest.split_at(32);
    let (get_id, get_challenge) = get.split_at(16);
    let first = requests.first().ok_or("no create request")?;
    let second = requests.get(1).ok_or("no get request")?;
    assert_eq!(
        (first.0.as_slice(), first.1.as_slice(), first.2.as_slice()),
        (id, challenge, prf_input)
    );
    assert_eq!(
        first.3.as_ref().map(<[u8; 32]>::as_slice),
        Some(user_handle)
    );
    assert_eq!(
        (
            second.0.as_slice(),
            second.1.as_slice(),
            second.2.as_slice()
        ),
        (get_id, get_challenge, prf_input)
    );
    assert_eq!(second.3, None);
    Ok(())
}

#[test]
fn the_confirmation_counter_must_advance_past_the_source_assertion_counter() -> TestResult {
    let regress = HonestConfig {
        create_prf: CreatePrf::EnabledOnly,
        get_counters: vec![5, 3],
        ..honest(0)
    };
    let (mut rig, mut port) = rig_with(regress)?;
    let outcome = rig.bridge.enroll(&context(), &mut port);
    // The codec reports every Get verification failure alike (Redmine #563).
    assert_eq!(outcome, Err(BridgeError::Rejected(RejectedCode::Signature)));
    assert_eq!(port.calls, [Call::Unbound, Call::Seal, Call::Abandon]);
    let advance = HonestConfig {
        create_prf: CreatePrf::EnabledOnly,
        get_counters: vec![5, 6],
        ..honest(0)
    };
    let (mut rig, mut port) = rig_with(advance)?;
    rig.bridge.enroll(&context(), &mut port)?;
    let committed = port.committed.ok_or("nothing was committed")?;
    assert_eq!(committed.binding().boxed()?.sign_count(), 6);
    Ok(())
}
