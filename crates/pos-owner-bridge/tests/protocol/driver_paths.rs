//! Every path of the ceremony state machine, with `FakeSurface` and the honest page.

use std::time::Duration;

use pos_owner_bridge::ceremony::driver::Step;
use pos_owner_bridge::ceremony::plan::{Budget, CeremonyPlan, Registration, Verified};
use pos_owner_bridge::ceremony::timing::SERVED_SETTLE;
use pos_owner_bridge::fake::buffers::{Actor, LogEntry};
use pos_owner_bridge::fake::honest::{AbortBehavior, CreatePrf, Delivery, HonestConfig, Tamper};
use pos_owner_bridge::fake::signer::{ReplyShape, FIXTURE_COSE_KEY};
use pos_owner_bridge::fake::surface::{SurfaceConfig, SurfaceFaults};
use pos_owner_bridge::{
    BridgeError, LifecycleCode, MonotonicClock, NavigationId, ProtocolCode, QuarantineCode,
    RejectedCode, ServedSnapshot, SurfaceEvent, UnavailableCode,
};
use pos_owner_bridge_codec::{
    decode_cleanup_record, decode_create_options, encode_attestation_reply, AttestationReplyV1,
    CeremonyId, CoseEs256PublicKey, TransportCodes,
};

use super::{
    bytes16, create_plan, eligible, expected_prf, get_plan, honest, malformed_prf, new_driver,
    no_prf, stored_fixture, wrong_key, wrong_raw_id, wrong_user_handle, Boxed, DriverRig, Hook,
    Moment, TestResult, CREDENTIAL_ID,
};

type Tweak = fn(&mut ReplyShape);

const fn lifecycle(code: LifecycleCode) -> BridgeError {
    BridgeError::Lifecycle(code)
}

const fn protocol(code: ProtocolCode) -> BridgeError {
    BridgeError::Protocol(code)
}

const fn rejected(code: RejectedCode) -> BridgeError {
    BridgeError::Rejected(code)
}

fn failure(
    result: &Result<Verified, BridgeError>,
) -> Result<BridgeError, Box<dyn std::error::Error>> {
    match result {
        Ok(_) => Err("the ceremony unexpectedly succeeded".into()),
        Err(error) => Ok(*error),
    }
}

fn position(log: &[LogEntry], wanted: &LogEntry) -> Result<usize, Box<dyn std::error::Error>> {
    log.iter()
        .position(|entry| entry == wanted)
        .ok_or_else(|| format!("{wanted:?} was never logged").into())
}

fn get_rig(
    page: HonestConfig,
    sign_count: u32,
) -> Result<(DriverRig, CeremonyPlan), Box<dyn std::error::Error>> {
    let rig = DriverRig::new(page, SurfaceConfig::default())?;
    let plan = get_plan(&rig.clock, stored_fixture(sign_count)?);
    Ok((rig, plan))
}

#[test]
fn an_honest_create_registers_the_credential_and_cleans_up() -> TestResult {
    let page = honest(0);
    let prf = expected_prf(&page);
    let mut rig = DriverRig::new(page, SurfaceConfig::default())?;
    let plan = create_plan(&rig.clock);
    let (result, driver) = rig.run(plan);
    let Verified::Registration(registration) = result? else {
        return Err("a Create ceremony must register".into());
    };
    assert_eq!(registration.credential_id, CREDENTIAL_ID);
    assert!(registration.prf_present);
    assert_eq!(registration.sign_count, 0);
    assert_eq!(*driver.prf(), prf);
    assert!(driver.request_clear());
    let log = rig.handle.log();
    assert_eq!(rig.handle.pair_count(), 1);
    let opened = log
        .iter()
        .position(|entry| matches!(entry, LogEntry::Opened { .. }))
        .ok_or("the environment was never opened")?;
    let order = [
        LogEntry::ControllerClosed,
        LogEntry::ExitObserved,
        LogEntry::Finished,
    ];
    let mut positions = vec![opened];
    for entry in &order {
        positions.push(position(&log, entry)?);
    }
    assert!(positions.windows(2).all(|pair| pair[0] < pair[1]));
    assert!(log
        .iter()
        .any(|entry| matches!(entry, LogEntry::ZeroClose { pair: 0, .. })));
    assert!(rig.store.records_now().is_empty());
    assert_eq!(rig.handle.finished(), 1);
    assert_eq!(rig.handle.folder().map(|name| name.len()), Some(32));
    Ok(())
}

#[test]
fn an_honest_get_verifies_the_assertion_and_advances_the_counter() -> TestResult {
    let (mut rig, plan) = get_rig(honest(0), 0)?;
    let (result, _) = rig.run(plan);
    let Verified::Assertion(assertion) = result? else {
        return Err("a Get ceremony must assert".into());
    };
    assert_eq!(assertion.sign_count, 1);
    assert!(!assertion.backup_state);
    Ok(())
}

#[test]
fn a_late_listener_makes_the_host_retire_and_repost_under_a_new_generation() -> TestResult {
    let mut rig = DriverRig::new(honest(600), SurfaceConfig::default())?;
    let plan = create_plan(&rig.clock);
    let (result, driver) = rig.run(plan);
    result?;
    assert!(driver.posts() >= 2);
    // One bump per re-post, and one when the browser exit consumes the finished ceremony.
    assert_eq!(driver.generation(), u32::from(driver.posts()) + 1);
    let log = rig.handle.log();
    let retired = log
        .iter()
        .position(|entry| {
            matches!(
                entry,
                LogEntry::Cas {
                    actor: Actor::Host,
                    pair: 0,
                    current: 0,
                    new: 4,
                    won: true,
                    ..
                }
            )
        })
        .ok_or("the first pair was never retired")?;
    let closed = log
        .iter()
        .position(|entry| {
            matches!(
                entry,
                LogEntry::ZeroClose {
                    pair: 0,
                    state: 4,
                    ..
                }
            )
        })
        .ok_or("the retired pair was never zeroed")?;
    let second_post = log
        .iter()
        .position(|entry| {
            matches!(
                entry,
                LogEntry::Post {
                    pair: 1,
                    generation: 2,
                    ..
                }
            )
        })
        .ok_or("the second pair was never posted")?;
    assert!(retired < closed && closed < second_post);
    Ok(())
}

#[test]
fn a_page_that_never_registers_exhausts_eight_posts_within_the_readiness_bound() -> TestResult {
    let mut rig = DriverRig::new(honest(6_000), SurfaceConfig::default())?;
    let plan = create_plan(&rig.clock);
    let (result, driver) = rig.run(plan);
    assert_eq!(
        failure(&result)?,
        lifecycle(LifecycleCode::ReadinessTimeout)
    );
    assert_eq!(driver.posts(), 8);
    let elapsed = rig.clock.elapsed();
    assert!(elapsed >= Duration::from_millis(7_600), "{elapsed:?}");
    assert!(elapsed < Duration::from_secs(15), "{elapsed:?}");
    let log = rig.handle.log();
    let posts: Vec<Duration> = log
        .iter()
        .filter_map(|entry| match entry {
            LogEntry::Post { at, .. } => Some(*at),
            _ => None,
        })
        .collect();
    let windows = [250, 250, 500, 500, 1_000, 1_000, 2_000];
    for (gap, window) in posts.windows(2).zip(windows) {
        let [first, second] = gap else { continue };
        assert!(second.saturating_sub(*first) >= Duration::from_millis(window));
    }
    Ok(())
}

#[test]
fn the_readiness_bound_fails_a_ceremony_whose_document_never_loads() -> TestResult {
    let surface = SurfaceConfig {
        load_delay: Duration::from_secs(20),
        ..SurfaceConfig::default()
    };
    let mut rig = DriverRig::new(honest(0), surface)?;
    let plan = create_plan(&rig.clock);
    let (result, driver) = rig.run(plan);
    assert_eq!(
        failure(&result)?,
        lifecycle(LifecycleCode::ReadinessTimeout)
    );
    assert_eq!(driver.posts(), 0);
    assert_eq!(rig.handle.pair_count(), 0);
    let log = rig.handle.log();
    assert!(log.contains(&LogEntry::ControllerClosed));
    assert!(log.contains(&LogEntry::Finished));
    Ok(())
}

#[test]
fn a_silent_page_ends_at_the_interaction_bound_and_the_page_aborts() -> TestResult {
    let page = HonestConfig {
        respond_after: None,
        ..honest(0)
    };
    let mut rig = DriverRig::new(page, SurfaceConfig::default())?;
    let plan = create_plan(&rig.clock);
    let (result, _) = rig.run(plan);
    assert_eq!(
        failure(&result)?,
        lifecycle(LifecycleCode::InteractionTimeout)
    );
    assert!(rig.clock.elapsed() >= Duration::from_mins(2));
    assert!(rig.clock.elapsed() < Duration::from_secs(125));
    let log = rig.handle.log();
    assert!(log
        .iter()
        .any(|entry| matches!(entry, LogEntry::PageAbort { pair: 0, .. })));
    assert!(log.contains(&LogEntry::PageHandler {
        pair: 0,
        type_error: false
    }));
    assert!(log.iter().any(|entry| matches!(
        entry,
        LogEntry::Store {
            actor: Actor::Page,
            value: 5,
            ..
        }
    )));
    Ok(())
}

#[test]
fn a_cancelled_ceremony_is_client_failed_never_unexpected_state() -> TestResult {
    let page = HonestConfig {
        cancel: true,
        ..honest(0)
    };
    let mut rig = DriverRig::new(page, SurfaceConfig::default())?;
    let plan = create_plan(&rig.clock);
    let (result, _) = rig.run(plan);
    assert_eq!(failure(&result)?, lifecycle(LifecycleCode::ClientFailed));
    Ok(())
}

#[test]
fn a_challenge_past_its_time_to_live_is_refused_at_the_compare_exchange() -> TestResult {
    let mut rig = DriverRig::new(honest(0), SurfaceConfig::default())?;
    let plan = create_plan(&rig.clock);
    let mut driver = new_driver(plan);
    driver.step(&mut rig.env());
    rig.clock.advance(Duration::from_millis(100));
    driver.step(&mut rig.env());
    assert_eq!(driver.posts(), 1);
    rig.clock.advance(Duration::from_secs(151));
    let result = rig.step_to_end(&mut driver);
    assert_eq!(
        failure(&result)?,
        lifecycle(LifecycleCode::ChallengeExpired)
    );
    Ok(())
}

#[test]
fn a_challenge_that_expires_during_verification_is_refused_before_secrets_exist() -> TestResult {
    let hook = Hook::SlowSecondCopy(Duration::from_secs(151));
    let mut rig = DriverRig::with_hook(honest(0), hook, SurfaceConfig::default())?;
    let plan = create_plan(&rig.clock);
    let (result, driver) = rig.run(plan);
    assert_eq!(
        failure(&result)?,
        lifecycle(LifecycleCode::ChallengeExpired)
    );
    assert_eq!(*driver.prf(), [0; 32]);
    assert!(driver.request_clear());
    Ok(())
}

fn tampered(tamper: Tamper) -> HonestConfig {
    HonestConfig {
        tamper,
        ..honest(0)
    }
}

#[test]
fn every_reply_tamper_is_rejected_with_its_protocol_code() -> TestResult {
    let cases = [
        (Tamper::PayloadId, ProtocolCode::CeremonyIdMismatch),
        (Tamper::HeaderId, ProtocolCode::CeremonyIdMismatch),
        (Tamper::HeaderGeneration, ProtocolCode::GenerationMismatch),
        (Tamper::HeaderKind, ProtocolCode::KindMismatch),
        (Tamper::HeaderRole, ProtocolCode::HeaderTampered),
        (Tamper::LengthZero, ProtocolCode::LengthOutOfBounds),
        (Tamper::LengthHuge, ProtocolCode::LengthOutOfBounds),
        (Tamper::Raw(vec![0xff]), ProtocolCode::Malformed),
        (Tamper::Raw(vec![0x98, 0x0a]), ProtocolCode::NonCanonical),
    ];
    for (tamper, code) in cases {
        let (mut rig, plan) = get_rig(tampered(tamper.clone()), 0)?;
        let (result, _) = rig.run(plan);
        assert_eq!(failure(&result)?, protocol(code), "{tamper:?}");
    }
    Ok(())
}

#[test]
fn every_verification_failure_is_classified() -> TestResult {
    let cases: [(Tweak, u32, BridgeError); 6] = [
        (wrong_key, 0, rejected(RejectedCode::Signature)),
        (wrong_raw_id, 0, rejected(RejectedCode::CredentialMismatch)),
        (
            wrong_user_handle,
            0,
            rejected(RejectedCode::UserHandleMismatch),
        ),
        (eligible, 0, rejected(RejectedCode::Signature)),
        (|_| {}, 5, rejected(RejectedCode::Signature)),
        (
            no_prf,
            0,
            BridgeError::Unavailable(UnavailableCode::PrfUnsupported),
        ),
    ];
    for (index, (tweak, counter, expected)) in cases.into_iter().enumerate() {
        let page = HonestConfig {
            tweak: Some(tweak),
            ..honest(0)
        };
        let (mut rig, plan) = get_rig(page, counter)?;
        let (result, _) = rig.run(plan);
        assert_eq!(failure(&result)?, expected, "case {index}");
    }
    Ok(())
}

#[test]
fn an_absent_or_malformed_required_prf_is_prf_unsupported_end_to_end() -> TestResult {
    let unsupported = BridgeError::Unavailable(UnavailableCode::PrfUnsupported);
    // A Create may omit the PRF (the source assertion then supplies it), but not malform it.
    let cases: [(Tweak, bool); 2] = [(no_prf, true), (malformed_prf, false)];
    for (tweak, create_registers) in cases {
        let page = HonestConfig {
            tweak: Some(tweak),
            ..honest(0)
        };
        let (mut rig, plan) = get_rig(page.clone(), 0)?;
        let (result, _) = rig.run(plan);
        assert_eq!(failure(&result)?, unsupported, "get");
        let mut rig = DriverRig::new(page, SurfaceConfig::default())?;
        let plan = create_plan(&rig.clock);
        let (result, _) = rig.run(plan);
        if create_registers {
            assert!(matches!(result?, Verified::Registration(r) if !r.prf_present));
        } else {
            assert_eq!(failure(&result)?, unsupported, "create");
        }
    }
    Ok(())
}

#[test]
fn a_zero_counter_pair_is_accepted_and_a_missing_prf_on_create_is_unsupported() -> TestResult {
    let zero = HonestConfig {
        zero_counter: true,
        ..honest(0)
    };
    let (mut rig, plan) = get_rig(zero, 0)?;
    let (result, _) = rig.run(plan);
    assert!(matches!(result?, Verified::Assertion(assertion) if assertion.sign_count == 0));
    let unsupported = HonestConfig {
        create_prf: CreatePrf::Unsupported,
        ..honest(0)
    };
    let mut rig = DriverRig::new(unsupported, SurfaceConfig::default())?;
    let plan = create_plan(&rig.clock);
    let (result, _) = rig.run(plan);
    assert_eq!(
        failure(&result)?,
        BridgeError::Unavailable(UnavailableCode::PrfUnsupported)
    );
    Ok(())
}

#[test]
fn a_create_without_a_returned_prf_registers_without_one() -> TestResult {
    let page = HonestConfig {
        create_prf: CreatePrf::EnabledOnly,
        ..honest(0)
    };
    let mut rig = DriverRig::new(page, SurfaceConfig::default())?;
    let plan = create_plan(&rig.clock);
    let (result, _) = rig.run(plan);
    assert!(matches!(result?, Verified::Registration(registration) if !registration.prf_present));
    Ok(())
}

#[test]
fn an_attestation_that_fails_verification_is_rejected() -> TestResult {
    let reply = AttestationReplyV1::new(
        CeremonyId::from_bytes(bytes16(0)),
        &CREDENTIAL_ID,
        b"{}",
        &[0xa0],
        TransportCodes::new(&[0]).boxed()?,
        true,
        None,
    )
    .boxed()?;
    let mut payload = vec![0; 1_024];
    let length = encode_attestation_reply(&reply, &mut payload).boxed()?;
    payload.truncate(length);
    let mut rig = DriverRig::new(tampered(Tamper::Raw(payload)), SurfaceConfig::default())?;
    let plan = create_plan(&rig.clock);
    let (result, _) = rig.run(plan);
    assert_eq!(failure(&result)?, rejected(RejectedCode::AttestationFormat));
    Ok(())
}

#[test]
fn copy_tearing_and_a_state_change_between_copies_are_copy_mismatches() -> TestResult {
    let cases = [
        (Hook::TearBetweenCopies, ProtocolCode::CopyMismatch),
        (Hook::StateAfterFirstCopy(2), ProtocolCode::UnexpectedState),
    ];
    for (hook, expected) in cases {
        let mut rig = DriverRig::with_hook(honest(0), hook.clone(), SurfaceConfig::default())?;
        let plan = get_plan(&rig.clock, stored_fixture(0)?);
        let (result, _) = rig.run(plan);
        assert_eq!(failure(&result)?, protocol(expected), "{hook:?}");
    }
    Ok(())
}

#[test]
fn a_page_writing_the_read_only_request_crashes_the_renderer() -> TestResult {
    let mut rig = DriverRig::with_hook(honest(0), Hook::RequestWrite, SurfaceConfig::default())?;
    let plan = create_plan(&rig.clock);
    let (result, _) = rig.run(plan);
    assert_eq!(failure(&result)?, lifecycle(LifecycleCode::RendererFailed));
    assert!(rig
        .handle
        .log()
        .iter()
        .any(|entry| matches!(entry, LogEntry::RequestWritten { .. })));
    Ok(())
}

#[test]
fn lifecycle_events_consume_the_ceremony_and_bump_the_generation() -> TestResult {
    let cases = [
        (
            SurfaceEvent::NavigationViolation,
            LifecycleCode::NavigationViolation,
        ),
        (SurfaceEvent::FrameCreated, LifecycleCode::FrameCreated),
        (SurfaceEvent::RendererFailed, LifecycleCode::RendererFailed),
        (SurfaceEvent::ControllerLost, LifecycleCode::ControllerLost),
        (
            SurfaceEvent::BrowserExited { browser_pid: 4242 },
            LifecycleCode::RendererFailed,
        ),
        (
            SurfaceEvent::DomContentLoaded(NavigationId(1)),
            LifecycleCode::NavigationViolation,
        ),
    ];
    for (event, code) in cases {
        let mut rig = DriverRig::new(honest(0), SurfaceConfig::default())?;
        rig.handle.schedule(Duration::from_millis(150), event);
        let plan = create_plan(&rig.clock);
        let (result, driver) = rig.run(plan);
        assert_eq!(failure(&result)?, lifecycle(code), "{event:?}");
        // The event consumes the ceremony and the browser exit that follows consumes it once more.
        let bumps = 3;
        assert_eq!(driver.generation(), bumps, "{event:?}");
    }
    Ok(())
}

#[test]
fn a_different_navigation_id_consumes_the_ceremony() -> TestResult {
    let mut rig = DriverRig::new(honest(0), SurfaceConfig::default())?;
    rig.handle.schedule(
        Duration::from_millis(50),
        SurfaceEvent::DomContentLoaded(NavigationId(2)),
    );
    let plan = create_plan(&rig.clock);
    let (result, driver) = rig.run(plan);
    assert_eq!(
        failure(&result)?,
        lifecycle(LifecycleCode::NavigationViolation)
    );
    assert_eq!(driver.generation(), 3);
    assert_eq!(driver.posts(), 0);
    Ok(())
}

#[test]
fn another_browsers_exit_and_events_during_release_are_ignored() -> TestResult {
    let mut rig = DriverRig::new(honest(0), SurfaceConfig::default())?;
    rig.handle.schedule(
        Duration::from_millis(150),
        SurfaceEvent::BrowserExited { browser_pid: 1 },
    );
    let plan = create_plan(&rig.clock);
    let (result, _) = rig.run(plan);
    result?;
    let page = HonestConfig {
        cancel: true,
        ..honest(0)
    };
    let mut rig = DriverRig::new(page, SurfaceConfig::default())?;
    rig.handle
        .schedule(Duration::from_millis(500), SurfaceEvent::RendererFailed);
    let plan = create_plan(&rig.clock);
    let (result, _) = rig.run(plan);
    assert_eq!(failure(&result)?, lifecycle(LifecycleCode::ClientFailed));
    Ok(())
}

#[test]
fn the_served_count_rule_gates_every_post() -> TestResult {
    let cases = [
        (
            0,
            true,
            BridgeError::Unavailable(UnavailableCode::AssetIntegrity),
        ),
        (
            1,
            false,
            BridgeError::Unavailable(UnavailableCode::AssetIntegrity),
        ),
        (2, true, protocol(ProtocolCode::DuplicateDocumentLoad)),
    ];
    for (count, integrity, expected) in cases {
        let surface = SurfaceConfig {
            served_completions: count,
            served_integrity_ok: integrity,
            ..SurfaceConfig::default()
        };
        let mut rig = DriverRig::new(honest(0), surface)?;
        let plan = create_plan(&rig.clock);
        let (result, driver) = rig.run(plan);
        assert_eq!(failure(&result)?, expected, "count {count}");
        assert_eq!(driver.posts(), 0);
    }
    Ok(())
}

#[test]
fn a_second_document_load_before_a_repost_is_a_duplicate() -> TestResult {
    let mut rig = DriverRig::new(honest(600), SurfaceConfig::default())?;
    let plan = create_plan(&rig.clock);
    let mut driver = new_driver(plan);
    driver.step(&mut rig.env());
    rig.clock.advance(Duration::from_millis(100));
    driver.step(&mut rig.env());
    assert_eq!(driver.posts(), 1);
    rig.loopback.set_served(2, true);
    let result = rig.step_to_end(&mut driver);
    assert_eq!(
        failure(&result)?,
        protocol(ProtocolCode::DuplicateDocumentLoad)
    );
    Ok(())
}

#[test]
fn the_ipv6_probe_runs_before_navigation_and_again_before_the_first_post() -> TestResult {
    for (from, probes) in [(1, 1), (2, 2)] {
        let mut rig = DriverRig::new(honest(0), SurfaceConfig::default())?;
        rig.loopback.fail_probes_from(Some(from));
        let plan = create_plan(&rig.clock);
        let (result, driver) = rig.run(plan);
        assert_eq!(
            failure(&result)?,
            BridgeError::Unavailable(UnavailableCode::LoopbackChanged)
        );
        assert_eq!(rig.loopback.probes(), probes);
        assert_eq!(driver.posts(), 0);
    }
    let mut rig = DriverRig::new(honest(0), SurfaceConfig::default())?;
    let plan = create_plan(&rig.clock);
    let (result, _) = rig.run(plan);
    result?;
    assert_eq!(rig.loopback.probes(), 2);
    assert_eq!(rig.loopback.resets(), 1);
    Ok(())
}

#[test]
fn generation_exhaustion_is_reported_and_zero_is_refused() -> TestResult {
    let exhausted = BridgeError::Unavailable(UnavailableCode::GenerationExhausted);
    let mut rig = DriverRig::new(honest(600), SurfaceConfig::default())?;
    let plan = create_plan(&rig.clock).with_generation(u32::MAX - 1);
    let (result, _) = rig.run(plan);
    assert_eq!(failure(&result)?, exhausted);
    let mut rig = DriverRig::new(honest(0), SurfaceConfig::default())?;
    let plan = create_plan(&rig.clock).with_generation(u32::MAX - 1);
    let (result, driver) = rig.run(plan);
    result?;
    assert_eq!(driver.generation(), u32::MAX);
    let mut rig = DriverRig::new(honest(0), SurfaceConfig::default())?;
    let plan = create_plan(&rig.clock).with_generation(0);
    let (result, _) = rig.run(plan);
    assert_eq!(failure(&result)?, protocol(ProtocolCode::LengthOutOfBounds));
    Ok(())
}

#[test]
fn a_get_without_a_stored_credential_cannot_be_posted() -> TestResult {
    let mut rig = DriverRig::new(honest(0), SurfaceConfig::default())?;
    let plan = get_plan(&rig.clock, stored_fixture(0)?).with_stored(None);
    let (result, driver) = rig.run(plan);
    assert_eq!(failure(&result)?, protocol(ProtocolCode::LengthOutOfBounds));
    assert_eq!(driver.posts(), 0);
    assert_eq!(rig.handle.pair_count(), 0);
    Ok(())
}

#[test]
fn the_enrollment_budget_fails_the_ceremony_in_progress() -> TestResult {
    for (page, surface) in [
        (
            HonestConfig {
                respond_after: None,
                ..honest(0)
            },
            SurfaceConfig::default(),
        ),
        (
            honest(0),
            SurfaceConfig {
                load_delay: Duration::from_secs(10),
                ..SurfaceConfig::default()
            },
        ),
    ] {
        let mut rig = DriverRig::new(page, surface)?;
        let plan = create_plan(&rig.clock)
            .with_budget(Budget::with_limit(rig.clock.now(), Duration::from_secs(5)));
        let (result, _) = rig.run(plan);
        assert_eq!(
            failure(&result)?,
            lifecycle(LifecycleCode::EnrollmentBudgetExceeded)
        );
        assert!(rig.clock.elapsed() >= Duration::from_secs(5));
    }
    Ok(())
}

#[test]
fn delivery_orders_and_abort_behaviours_still_complete_or_fail_closed() -> TestResult {
    for delivery in [Delivery::Normal, Delivery::ReplyFirst] {
        let page = HonestConfig {
            delivery,
            ..honest(0)
        };
        let (mut rig, plan) = get_rig(page, 0)?;
        let (result, _) = rig.run(plan);
        result?;
    }
    for abort in [
        AbortBehavior::Runs,
        AbortBehavior::Ignored,
        AbortBehavior::Late,
        AbortBehavior::ReleaseFirst,
    ] {
        let page = HonestConfig {
            abort,
            respond_after: None,
            ..honest(0)
        };
        let mut rig = DriverRig::new(page, SurfaceConfig::default())?;
        let plan = create_plan(&rig.clock);
        let (result, _) = rig.run(plan);
        assert_eq!(
            failure(&result)?,
            lifecycle(LifecycleCode::InteractionTimeout),
            "{abort:?}"
        );
    }
    Ok(())
}

#[test]
fn surface_faults_before_buffers_exist_fail_closed_with_their_own_code() -> TestResult {
    let refused = BridgeError::Unavailable(UnavailableCode::InterfaceUnavailable);
    let faults = [
        SurfaceFaults {
            open: Some(refused),
            ..SurfaceFaults::default()
        },
        SurfaceFaults {
            navigate: Some(refused),
            ..SurfaceFaults::default()
        },
        SurfaceFaults {
            create: Some(refused),
            ..SurfaceFaults::default()
        },
    ];
    for (index, faults) in faults.into_iter().enumerate() {
        let surface = SurfaceConfig {
            faults,
            ..SurfaceConfig::default()
        };
        let mut rig = DriverRig::new(honest(0), surface)?;
        let plan = create_plan(&rig.clock);
        let (result, driver) = rig.run(plan);
        assert_eq!(failure(&result)?, refused, "case {index}");
        assert_eq!(driver.posts(), 0);
        assert!(rig.store.records_now().is_empty());
    }
    Ok(())
}

#[test]
fn a_failed_post_and_an_unreadable_state_word_still_clean_up_on_timers() -> TestResult {
    let refused = BridgeError::Unavailable(UnavailableCode::InterfaceUnavailable);
    for faults in [
        SurfaceFaults {
            post: Some(refused),
            ..SurfaceFaults::default()
        },
        SurfaceFaults {
            state: Some(refused),
            ..SurfaceFaults::default()
        },
    ] {
        let surface = SurfaceConfig {
            faults,
            ..SurfaceConfig::default()
        };
        let mut rig = DriverRig::new(honest(0), surface)?;
        let plan = create_plan(&rig.clock);
        let (result, _) = rig.run(plan);
        assert_eq!(failure(&result)?, refused);
        assert!(rig.clock.elapsed() >= Duration::from_secs(2));
        let log = rig.handle.log();
        assert!(log
            .iter()
            .any(|entry| matches!(entry, LogEntry::ZeroClose { .. })));
        assert!(log.contains(&LogEntry::Finished));
    }
    Ok(())
}

#[test]
fn a_page_racing_the_retirement_compare_exchange_is_never_overwritten() -> TestResult {
    let cases = [
        (7, lifecycle(LifecycleCode::InteractionTimeout)),
        (1, lifecycle(LifecycleCode::InteractionTimeout)),
        (6, lifecycle(LifecycleCode::ClientFailed)),
        (2, protocol(ProtocolCode::LengthOutOfBounds)),
    ];
    for (landed, expected) in cases {
        let mut rig = DriverRig::with_hook(
            honest(6_000),
            Hook::RaceRetire(landed),
            SurfaceConfig::default(),
        )?;
        let plan = create_plan(&rig.clock);
        let (result, _) = rig.run(plan);
        assert_eq!(failure(&result)?, expected, "landed {landed}");
        let log = rig.handle.log();
        assert!(!log.iter().any(|entry| matches!(
            entry,
            LogEntry::Store {
                actor: Actor::Host,
                ..
            }
        )));
    }
    Ok(())
}

#[test]
fn a_page_cas_after_the_retirement_cas_always_loses() -> TestResult {
    let mut rig = DriverRig::with_hook(honest(600), Hook::AfterRetire, SurfaceConfig::default())?;
    let plan = create_plan(&rig.clock);
    let (result, _) = rig.run(plan);
    result?;
    let log = rig.handle.log();
    let late: Vec<bool> = log
        .iter()
        .filter_map(|entry| match entry {
            LogEntry::Cas {
                actor: Actor::Page,
                pair: 0,
                current: 0,
                new: 7,
                won,
                ..
            } => Some(*won),
            _ => None,
        })
        .collect();
    assert_eq!(late, [false]);
    assert!(log.iter().all(|entry| !matches!(
        entry,
        LogEntry::Store {
            pair: 0,
            value: 0,
            ..
        }
    )));
    Ok(())
}

#[test]
fn a_page_storing_arbitrary_values_ends_the_release_loop_within_eight_attempts() -> TestResult {
    let storms: [Vec<u32>; 4] = [vec![5, 5], vec![3], vec![9], vec![1, 2, 7]];
    for storm in storms {
        let page = HonestConfig {
            respond_after: None,
            ..honest(0)
        };
        let mut rig =
            DriverRig::with_hook(page, Hook::Storm(storm.clone()), SurfaceConfig::default())?;
        let plan = create_plan(&rig.clock);
        let (result, _) = rig.run(plan);
        assert_eq!(
            failure(&result)?,
            protocol(ProtocolCode::UnexpectedState),
            "{storm:?}"
        );
        let attempts = rig
            .handle
            .log()
            .iter()
            .filter(|entry| {
                matches!(
                    entry,
                    LogEntry::Cas {
                        actor: Actor::Host,
                        new: 4,
                        ..
                    }
                )
            })
            .count();
        assert!(attempts <= 8, "{attempts} attempts for {storm:?}");
        assert!(rig.handle.log().contains(&LogEntry::Finished));
    }
    Ok(())
}

#[test]
fn cleanup_failures_quarantine_the_ceremony_without_reviving_secrets() -> TestResult {
    let cases = [
        SurfaceFaults {
            zero_close: true,
            ..SurfaceFaults::default()
        },
        SurfaceFaults {
            close_controller: true,
            ..SurfaceFaults::default()
        },
    ];
    for faults in cases {
        let surface = SurfaceConfig {
            faults,
            ..SurfaceConfig::default()
        };
        let mut rig = DriverRig::new(honest(0), surface)?;
        let plan = create_plan(&rig.clock);
        let (result, driver) = rig.run(plan);
        let expected = BridgeError::Quarantine(QuarantineCode::ControllerCloseFailed);
        assert_eq!(failure(&result)?, expected);
        assert_eq!(*driver.prf(), [0; 32]);
        assert!(driver.request_clear());
        assert!(driver.plan_secrets_clear());
    }
    Ok(())
}

#[test]
fn an_exit_timeout_quarantines_and_a_late_exit_completes_cleanup() -> TestResult {
    let surface = SurfaceConfig {
        exit_delay: None,
        ..SurfaceConfig::default()
    };
    let mut rig = DriverRig::new(honest(0), surface)?;
    let plan = create_plan(&rig.clock);
    let mut driver = new_driver(plan);
    let result = rig.step_to_end(&mut driver);
    let expected = BridgeError::Quarantine(QuarantineCode::CleanupTimeout);
    assert_eq!(failure(&result)?, expected);
    assert!(!driver.poll_cleanup(&mut rig.env()));
    let stored = rig.store.records_now();
    assert_eq!(stored.len(), 1);
    let record = decode_cleanup_record(stored.first().ok_or("no record")?).boxed()?;
    assert_eq!(record.ceremony_id(), CeremonyId::from_bytes(bytes16(0)));
    assert_eq!(record.folder_name(), "000102030405060708090a0b0c0d0e0f");
    assert_eq!(record.browser_pid(), 4242);
    assert_eq!(record.creation_filetime(), 133_000_000_000_000_000);
    assert_eq!(record.image_path_sha256().as_bytes(), &[7; 32]);
    rig.handle.schedule(
        rig.clock.elapsed(),
        SurfaceEvent::BrowserExited { browser_pid: 4242 },
    );
    assert!(driver.poll_cleanup(&mut rig.env()));
    assert!(rig.store.records_now().is_empty());
    assert!(!driver.poll_cleanup(&mut rig.env()));
    Ok(())
}

#[test]
fn unfinished_cleanup_keeps_waiting_until_it_can_finish() -> TestResult {
    use pos_owner_bridge::fake::host::StoreOp;
    let mut rig = DriverRig::new(honest(0), SurfaceConfig::default())?;
    rig.handle.set_faults(SurfaceFaults {
        finish: true,
        ..SurfaceFaults::default()
    });
    let plan = create_plan(&rig.clock);
    let mut driver = new_driver(plan);
    let result = rig.step_to_end(&mut driver);
    assert_eq!(
        failure(&result)?,
        BridgeError::Quarantine(QuarantineCode::CleanupTimeout)
    );
    assert!(!driver.poll_cleanup(&mut rig.env()));
    rig.handle.set_faults(SurfaceFaults::default());
    rig.store.set_failing(&[StoreOp::Delete]);
    assert!(!driver.poll_cleanup(&mut rig.env()));
    rig.store.set_failing(&[]);
    assert!(driver.poll_cleanup(&mut rig.env()));
    assert!(rig.store.records_now().is_empty());
    assert_eq!(rig.handle.finished(), 1);
    Ok(())
}

#[test]
fn a_cleanup_store_that_cannot_write_or_delete_fails_closed() -> TestResult {
    use pos_owner_bridge::fake::host::StoreOp;
    let mut rig = DriverRig::new(honest(0), SurfaceConfig::default())?;
    rig.store.set_failing(&[StoreOp::Write]);
    let plan = create_plan(&rig.clock);
    let (result, driver) = rig.run(plan);
    let unavailable = BridgeError::Unavailable(UnavailableCode::InterfaceUnavailable);
    assert_eq!(failure(&result)?, unavailable);
    assert_eq!(driver.posts(), 0);
    let mut rig = DriverRig::new(honest(0), SurfaceConfig::default())?;
    rig.store.set_failing(&[StoreOp::Delete]);
    let plan = create_plan(&rig.clock);
    let (result, _) = rig.run(plan);
    assert_eq!(
        failure(&result)?,
        BridgeError::Quarantine(QuarantineCode::CleanupTimeout)
    );
    Ok(())
}

#[test]
fn a_finished_or_quarantined_driver_stays_pending_and_never_wakes() -> TestResult {
    let mut rig = DriverRig::new(honest(0), SurfaceConfig::default())?;
    let plan = create_plan(&rig.clock);
    let mut driver = new_driver(plan);
    let result = rig.step_to_end(&mut driver);
    result?;
    assert!(matches!(driver.step(&mut rig.env()), Step::Done));
    assert_eq!(driver.next_wake(), None);
    let surface = SurfaceConfig {
        exit_delay: None,
        ..SurfaceConfig::default()
    };
    let mut rig = DriverRig::new(honest(0), surface)?;
    let plan = create_plan(&rig.clock);
    let mut driver = new_driver(plan);
    let result = rig.step_to_end(&mut driver);
    assert_eq!(
        failure(&result)?,
        BridgeError::Quarantine(QuarantineCode::CleanupTimeout)
    );
    assert!(matches!(driver.step(&mut rig.env()), Step::Done));
    assert_eq!(driver.next_wake(), None);
    Ok(())
}

#[test]
fn polling_twice_at_the_same_instant_reads_the_state_word_once() -> TestResult {
    let mut rig = DriverRig::new(honest(0), SurfaceConfig::default())?;
    let plan = create_plan(&rig.clock);
    let mut driver = new_driver(plan);
    driver.step(&mut rig.env());
    rig.clock.advance(Duration::from_millis(100));
    driver.step(&mut rig.env());
    driver.step(&mut rig.env());
    let loads = |handle: &pos_owner_bridge::fake::surface::FakeSurfaceHandle| {
        handle
            .log()
            .iter()
            .filter(|entry| matches!(entry, LogEntry::HostLoad { .. }))
            .count()
    };
    let before = loads(&rig.handle);
    driver.step(&mut rig.env());
    assert_eq!(loads(&rig.handle), before);
    Ok(())
}

#[test]
fn a_page_racing_the_last_receipt_window_or_the_retirement_with_an_illegal_value_is_unexpected(
) -> TestResult {
    let cases = [
        (
            Hook::RaceNthRetire { nth: 8, value: 6 },
            lifecycle(LifecycleCode::ClientFailed),
        ),
        (
            Hook::RaceNthRetire { nth: 8, value: 3 },
            protocol(ProtocolCode::UnexpectedState),
        ),
        (Hook::RaceRetire(3), protocol(ProtocolCode::UnexpectedState)),
    ];
    for (hook, expected) in cases {
        let mut rig = DriverRig::with_hook(honest(6_000), hook.clone(), SurfaceConfig::default())?;
        let plan = create_plan(&rig.clock);
        let (result, _) = rig.run(plan);
        assert_eq!(failure(&result)?, expected, "{hook:?}");
    }
    Ok(())
}

#[test]
fn state_word_failures_at_consumption_are_unexpected_state() -> TestResult {
    let refused = BridgeError::Unavailable(UnavailableCode::InterfaceUnavailable);
    let mut rig = DriverRig::with_hook(honest(0), Hook::RaceConsume(6), SurfaceConfig::default())?;
    let plan = create_plan(&rig.clock);
    let (result, _) = rig.run(plan);
    assert_eq!(failure(&result)?, protocol(ProtocolCode::UnexpectedState));
    let surface = SurfaceConfig {
        faults: SurfaceFaults {
            exchange: Some(refused),
            ..SurfaceFaults::default()
        },
        ..SurfaceConfig::default()
    };
    let mut rig = DriverRig::new(honest(0), surface)?;
    let plan = create_plan(&rig.clock);
    let (result, _) = rig.run(plan);
    assert_eq!(failure(&result)?, refused);
    Ok(())
}

#[test]
fn a_failed_copy_or_an_undecodable_state_after_a_copy_fails_the_ceremony() -> TestResult {
    let refused = BridgeError::Unavailable(UnavailableCode::InterfaceUnavailable);
    let surface = SurfaceConfig {
        faults: SurfaceFaults {
            copy: Some(refused),
            ..SurfaceFaults::default()
        },
        ..SurfaceConfig::default()
    };
    let mut rig = DriverRig::new(honest(0), surface)?;
    let plan = create_plan(&rig.clock);
    let (result, _) = rig.run(plan);
    assert_eq!(failure(&result)?, refused);
    let mut rig = DriverRig::with_hook(
        honest(0),
        Hook::StateAfterFirstCopy(9),
        SurfaceConfig::default(),
    )?;
    let plan = create_plan(&rig.clock);
    let (result, _) = rig.run(plan);
    assert_eq!(failure(&result)?, protocol(ProtocolCode::UnexpectedState));
    Ok(())
}

#[test]
fn a_page_whose_call_resolves_just_after_the_release_request_loses_its_compare_exchange(
) -> TestResult {
    for cancel in [false, true] {
        let page = HonestConfig {
            cancel,
            ..honest(0)
        };
        let mut rig = DriverRig::new(page, SurfaceConfig::default())?;
        rig.handle
            .schedule(Duration::from_millis(395), SurfaceEvent::FrameCreated);
        let plan = create_plan(&rig.clock);
        let (result, _) = rig.run(plan);
        assert_eq!(
            failure(&result)?,
            lifecycle(LifecycleCode::FrameCreated),
            "cancel {cancel}"
        );
        let log = rig.handle.log();
        let lost = log.iter().any(|entry| {
            matches!(
                entry,
                LogEntry::Cas {
                    actor: Actor::Page,
                    current: 7,
                    won: false,
                    ..
                }
            )
        });
        assert!(lost, "cancel {cancel}");
    }
    Ok(())
}

#[test]
fn a_verified_registration_does_not_convert_to_an_assertion() -> TestResult {
    let registration = Registration {
        credential_id: vec![1],
        public_key: CoseEs256PublicKey::from_canonical_encoding(&FIXTURE_COSE_KEY).boxed()?,
        transports: TransportCodes::new(&[]).boxed()?,
        backup_eligible: false,
        backup_state: false,
        sign_count: 0,
        prf_present: false,
    };
    let converted = Verified::Registration(registration).into_assertion();
    assert_eq!(converted.err(), Some(protocol(ProtocolCode::KindMismatch)));
    Ok(())
}

#[test]
fn an_equal_counter_or_a_zero_after_a_nonzero_counter_is_a_regression() -> TestResult {
    for (zero_counter, stored) in [(false, 1), (true, 5)] {
        let page = HonestConfig {
            zero_counter,
            ..honest(0)
        };
        let (mut rig, plan) = get_rig(page, stored)?;
        let (result, _) = rig.run(plan);
        assert_eq!(failure(&result)?, rejected(RejectedCode::Signature));
    }
    Ok(())
}

const fn served(count: u32) -> ServedSnapshot {
    ServedSnapshot {
        count,
        integrity_ok: true,
    }
}

fn release_requested(rig: &DriverRig) -> bool {
    rig.handle.log().iter().any(|entry| {
        matches!(
            entry,
            LogEntry::Cas {
                actor: Actor::Host,
                new: 4,
                won: true,
                ..
            }
        )
    })
}

fn controller_closed(rig: &DriverRig) -> bool {
    rig.handle.log().contains(&LogEntry::ControllerClosed)
}

#[test]
fn a_zero_served_count_that_settles_to_one_is_a_benign_race() -> TestResult {
    let mut rig = DriverRig::new(honest(0), SurfaceConfig::default())?;
    rig.loopback
        .script_served(&[served(0), served(0), served(1)]);
    let plan = create_plan(&rig.clock);
    let mut driver = new_driver(plan);
    driver.step(&mut rig.env());
    rig.clock.advance(Duration::from_millis(100));
    driver.step(&mut rig.env());
    assert_eq!(driver.posts(), 0);
    assert_eq!(
        driver.next_wake(),
        Some(rig.clock.now() + SERVED_SETTLE),
        "the driver must wake when the settle window ends"
    );
    rig.clock.advance(Duration::from_millis(10));
    driver.step(&mut rig.env());
    assert_eq!(driver.posts(), 0);
    rig.clock.advance(Duration::from_millis(10));
    driver.step(&mut rig.env());
    assert_eq!(driver.posts(), 1);
    assert!(!controller_closed(&rig));
    let result = rig.step_to_end(&mut driver);
    assert!(matches!(result?, Verified::Registration(_)));
    Ok(())
}

#[test]
fn a_zero_served_count_that_persists_is_asset_integrity_after_the_settle_window() -> TestResult {
    let surface = SurfaceConfig {
        served_completions: 0,
        ..SurfaceConfig::default()
    };
    let mut rig = DriverRig::new(honest(0), surface)?;
    let plan = create_plan(&rig.clock);
    let mut driver = new_driver(plan);
    driver.step(&mut rig.env());
    rig.clock.advance(Duration::from_millis(100));
    driver.step(&mut rig.env());
    rig.clock.advance(Duration::from_millis(90));
    driver.step(&mut rig.env());
    assert!(!controller_closed(&rig), "the window has not ended yet");
    rig.clock.advance(Duration::from_millis(10));
    driver.step(&mut rig.env());
    assert!(controller_closed(&rig), "the window ended with a zero");
    let result = rig.step_to_end(&mut driver);
    assert_eq!(
        failure(&result)?,
        BridgeError::Unavailable(UnavailableCode::AssetIntegrity)
    );
    assert_eq!(driver.posts(), 0);
    Ok(())
}

#[test]
fn a_bad_digest_is_never_a_race_and_fails_without_waiting() -> TestResult {
    let surface = SurfaceConfig {
        served_completions: 0,
        served_integrity_ok: false,
        ..SurfaceConfig::default()
    };
    let mut rig = DriverRig::new(honest(0), surface)?;
    let plan = create_plan(&rig.clock);
    let mut driver = new_driver(plan);
    driver.step(&mut rig.env());
    rig.clock.advance(Duration::from_millis(100));
    driver.step(&mut rig.env());
    assert!(controller_closed(&rig));
    let result = rig.step_to_end(&mut driver);
    assert_eq!(
        failure(&result)?,
        BridgeError::Unavailable(UnavailableCode::AssetIntegrity)
    );
    Ok(())
}

#[test]
fn a_late_second_completion_is_caught_before_the_reply_is_consumed() -> TestResult {
    let bad_digest = ServedSnapshot {
        count: 1,
        integrity_ok: false,
    };
    let integrity = BridgeError::Unavailable(UnavailableCode::AssetIntegrity);
    let cases = [
        (
            vec![served(1), served(1), served(1), served(2)],
            protocol(ProtocolCode::DuplicateDocumentLoad),
        ),
        (vec![served(1), served(1), served(1), bad_digest], integrity),
        (vec![served(1), served(1), served(1), served(0)], integrity),
    ];
    for (script, expected) in cases {
        let mut rig = DriverRig::new(honest(0), SurfaceConfig::default())?;
        rig.loopback.script_served(&script);
        let plan = create_plan(&rig.clock);
        let (result, driver) = rig.run(plan);
        assert_eq!(failure(&result)?, expected, "{script:?}");
        assert_eq!(driver.posts(), 1);
        assert_eq!(*driver.prf(), [0; 32]);
        assert!(driver.request_clear());
        let log = rig.handle.log();
        // It surfaced while the page was still working: the reply never became ready.
        assert!(
            !log.iter().any(|entry| matches!(
                entry,
                LogEntry::Cas {
                    actor: Actor::Page,
                    new: 2,
                    ..
                } | LogEntry::Cas {
                    actor: Actor::Host,
                    new: 3,
                    ..
                }
            )),
            "{script:?} {log:?}"
        );
    }
    Ok(())
}

#[test]
fn a_completion_that_arrives_between_the_writes_and_the_post_stops_the_post() -> TestResult {
    let mut rig = DriverRig::new(honest(0), SurfaceConfig::default())?;
    // Reads: the settle check, the check before the writes, then the one just before the post.
    rig.loopback
        .script_served(&[served(1), served(1), served(2)]);
    let plan = create_plan(&rig.clock);
    let (result, driver) = rig.run(plan);
    assert_eq!(
        failure(&result)?,
        protocol(ProtocolCode::DuplicateDocumentLoad)
    );
    assert_eq!(driver.posts(), 0);
    let log = rig.handle.log();
    assert_eq!(rig.handle.pair_count(), 1, "the buffers were created");
    assert!(!log
        .iter()
        .any(|entry| matches!(entry, LogEntry::Post { .. })));
    assert!(log
        .iter()
        .any(|entry| matches!(entry, LogEntry::ZeroClose { pair: 0, .. })));
    Ok(())
}

#[test]
fn a_second_completion_after_consumption_fails_the_ceremony_and_cleanup_still_runs() -> TestResult {
    let duplicate = protocol(ProtocolCode::DuplicateDocumentLoad);
    for moment in [Moment::Consumed, Moment::Closing] {
        for create in [true, false] {
            let hook = Hook::SecondCompletion(moment);
            let mut rig = DriverRig::with_hook(honest(0), hook, SurfaceConfig::default())?;
            let plan = if create {
                create_plan(&rig.clock)
            } else {
                get_plan(&rig.clock, stored_fixture(0)?)
            };
            let (result, driver) = rig.run(plan);
            assert_eq!(failure(&result)?, duplicate, "{moment:?} create {create}");
            assert_eq!(*driver.prf(), [0; 32], "{moment:?} create {create}");
            assert!(driver.request_clear(), "{moment:?} create {create}");
            let log = rig.handle.log();
            assert!(log.contains(&LogEntry::ExitObserved), "{moment:?}");
            assert!(log.contains(&LogEntry::Finished), "{moment:?}");
            assert!(rig.store.records_now().is_empty(), "{moment:?}");
        }
    }
    Ok(())
}

#[test]
fn a_late_second_completion_surfaces_at_the_next_step_while_the_page_is_still_working() -> TestResult
{
    let mut rig = DriverRig::new(honest(0), SurfaceConfig::default())?;
    rig.loopback
        .script_served(&[served(1), served(1), served(1), served(1), served(2)]);
    let plan = create_plan(&rig.clock);
    let mut driver = new_driver(plan);
    driver.step(&mut rig.env());
    rig.clock.advance(Duration::from_millis(100));
    driver.step(&mut rig.env());
    assert_eq!(driver.posts(), 1);
    rig.clock.advance(Duration::from_millis(10));
    driver.step(&mut rig.env());
    assert!(!release_requested(&rig), "one completion is still fine");
    rig.clock.advance(Duration::from_millis(10));
    driver.step(&mut rig.env());
    assert!(
        release_requested(&rig),
        "the second completion ended the ceremony"
    );
    let result = rig.step_to_end(&mut driver);
    assert_eq!(
        failure(&result)?,
        protocol(ProtocolCode::DuplicateDocumentLoad)
    );
    // The page was still waiting to answer, so the reply never became ready.
    assert!(!rig.handle.log().iter().any(|entry| matches!(
        entry,
        LogEntry::Cas {
            actor: Actor::Page,
            new: 2,
            ..
        }
    )));
    Ok(())
}

#[test]
fn a_page_landing_at_the_end_of_the_ceremony_never_makes_the_host_unexpected() -> TestResult {
    let silent = HonestConfig {
        respond_after: None,
        ..honest(0)
    };
    for (from, to) in [(7, 6), (7, 1), (7, 2)] {
        let hook = Hook::RaceEnd { from, to };
        let mut rig = DriverRig::with_hook(silent.clone(), hook, SurfaceConfig::default())?;
        let plan = create_plan(&rig.clock);
        let (result, _) = rig.run(plan);
        let expected = lifecycle(LifecycleCode::InteractionTimeout);
        assert_eq!(failure(&result)?, expected, "{from} -> {to}");
        assert!(rig.handle.log().iter().any(|entry| matches!(
            entry,
            LogEntry::Cas {
                actor: Actor::Page,
                current,
                new,
                won: true,
                ..
            } if (*current, *new) == (from, to)
        )));
    }
    let hook = Hook::RaceEnd { from: 1, to: 2 };
    let page = tampered(Tamper::HeaderGeneration);
    let mut rig = DriverRig::with_hook(page, hook, SurfaceConfig::default())?;
    let plan = create_plan(&rig.clock);
    let (result, _) = rig.run(plan);
    let mismatch = protocol(ProtocolCode::GenerationMismatch);
    assert_eq!(failure(&result)?, mismatch);
    assert!(rig.handle.log().iter().any(|entry| matches!(
        entry,
        LogEntry::Cas {
            actor: Actor::Page,
            current: 1,
            new: 2,
            won: false,
            ..
        }
    )));
    Ok(())
}

#[test]
fn a_posted_pair_keeps_its_request_payload_after_the_host_zeroes_the_buffer() -> TestResult {
    let mut rig = DriverRig::new(honest(0), SurfaceConfig::default())?;
    let plan = create_plan(&rig.clock);
    let challenge = *plan.challenge().as_bytes();
    let (result, _) = rig.run(plan);
    result?;
    let (payload, request) = rig.handle.with_buffers(|buffers| {
        let pair = buffers.pair_at(0);
        (pair.payload.clone(), pair.request.clone())
    });
    assert!(request.iter().all(|byte| *byte == 0));
    let options = decode_create_options(&payload).boxed()?;
    assert_eq!(options.challenge().as_bytes(), &challenge);
    assert_eq!(options.ceremony_id(), CeremonyId::from_bytes(bytes16(0)));
    Ok(())
}
