//! The ADR-110 section 6 bounds and the host polling cadence, checked as plain values and over a
//! manually stepped ceremony.

use std::time::{Duration, Instant};

use pos_owner_bridge::ceremony::plan::Budget;
use pos_owner_bridge::ceremony::timing::{
    expired, poll_interval, receipt_window, CHALLENGE_TTL, ENROLLMENT_BUDGET, EXIT_WINDOW,
    FAST_POLL, FAST_POLL_SPAN, INTERACTION, MAX_POSTS, READINESS, RECEIPT_WINDOWS_MS,
    RELEASE_WINDOW, SERVED_SETTLE, SLOW_POLL, TIMER_INTERVAL,
};
use pos_owner_bridge::fake::buffers::LogEntry;
use pos_owner_bridge::fake::honest::{AbortBehavior, HonestConfig};
use pos_owner_bridge::fake::surface::SurfaceConfig;
use pos_owner_bridge::{BridgeError, LifecycleCode, MonotonicClock, QuarantineCode, SurfaceEvent};

use super::{create_plan, honest, new_driver, DriverRig, TestResult};

#[test]
fn the_bounds_are_the_adr_values() {
    assert_eq!(READINESS, Duration::from_secs(15));
    assert_eq!(INTERACTION, Duration::from_mins(2));
    assert_eq!(CHALLENGE_TTL, Duration::from_secs(150));
    assert_eq!(RELEASE_WINDOW, Duration::from_secs(2));
    assert_eq!(EXIT_WINDOW, Duration::from_secs(5));
    assert_eq!(ENROLLMENT_BUDGET, Duration::from_mins(5));
    assert_eq!(
        (FAST_POLL, SLOW_POLL, FAST_POLL_SPAN),
        (
            Duration::from_millis(10),
            Duration::from_millis(50),
            Duration::from_secs(1)
        )
    );
    assert_eq!(TIMER_INTERVAL, FAST_POLL);
    assert_eq!(SERVED_SETTLE, Duration::from_millis(100));
    assert!(SERVED_SETTLE < READINESS);
    assert_eq!(MAX_POSTS, 8);
    let origin = Instant::now();
    assert_eq!(Budget::enrollment(origin).start(), origin);
    assert_eq!(Budget::enrollment(origin).limit(), ENROLLMENT_BUDGET);
    assert_eq!(RECEIPT_WINDOWS_MS.iter().sum::<u64>(), 7_500);
}

#[test]
fn receipt_windows_follow_the_backoff_and_later_posts_reuse_the_last() {
    let expected = [250, 250, 500, 500, 1_000, 1_000, 2_000, 2_000, 2_000];
    for (post, millis) in (1_u8..).zip(expected) {
        assert_eq!(
            receipt_window(post),
            Duration::from_millis(millis),
            "post {post}"
        );
    }
    assert_eq!(receipt_window(0), Duration::from_millis(250));
}

#[test]
fn the_poll_cadence_slows_exactly_one_second_after_the_first_observation() {
    assert_eq!(poll_interval(None), FAST_POLL);
    assert_eq!(poll_interval(Some(Duration::ZERO)), FAST_POLL);
    assert_eq!(
        poll_interval(Some(FAST_POLL_SPAN.saturating_sub(Duration::from_nanos(1)))),
        FAST_POLL
    );
    assert_eq!(poll_interval(Some(FAST_POLL_SPAN)), SLOW_POLL);
    assert_eq!(poll_interval(Some(Duration::from_mins(1))), SLOW_POLL);
}

#[test]
fn a_bound_has_passed_exactly_when_the_limit_has_elapsed() {
    let start = Instant::now();
    let limit = Duration::from_secs(2);
    assert!(expired(start + limit, start, limit));
    assert!(!expired(
        (start + limit)
            .checked_sub(Duration::from_nanos(1))
            .unwrap_or(start),
        start,
        limit
    ));
    assert!(expired(
        start + limit + Duration::from_nanos(1),
        start,
        limit
    ));
    assert!(!expired(start, start + limit, limit));
}

#[test]
fn the_host_polls_every_10_ms_for_a_second_and_every_50_ms_after() -> TestResult {
    let page = HonestConfig {
        respond_after: None,
        ..honest(0)
    };
    let mut rig = DriverRig::new(page, SurfaceConfig::default())?;
    let plan = create_plan(&rig.clock);
    let mut driver = new_driver(plan);
    for _ in 0..400 {
        driver.step(&mut rig.env());
        rig.clock.advance(Duration::from_millis(10));
    }
    let loads = rig
        .handle
        .log()
        .iter()
        .filter(|entry| matches!(entry, LogEntry::HostLoad { .. }))
        .count();
    assert!(
        (150..=170).contains(&loads),
        "{loads} polls in four seconds"
    );
    Ok(())
}

#[test]
fn the_driver_reports_the_next_instant_it_needs_attention() -> TestResult {
    let page = HonestConfig {
        respond_after: None,
        ..honest(0)
    };
    let mut rig = DriverRig::new(page, SurfaceConfig::default())?;
    let origin = rig.clock.now();
    let plan = create_plan(&rig.clock);
    let mut driver = new_driver(plan);
    assert_eq!(driver.next_wake(), Some(origin + READINESS));
    driver.step(&mut rig.env());
    assert_eq!(driver.next_wake(), Some(origin + READINESS));
    rig.clock.advance(Duration::from_millis(100));
    driver.step(&mut rig.env());
    assert_eq!(
        driver.next_wake(),
        Some(origin + Duration::from_millis(100) + receipt_window(1))
    );
    rig.clock.advance(Duration::from_millis(10));
    driver.step(&mut rig.env());
    assert_eq!(
        driver.next_wake(),
        Some(origin + Duration::from_millis(110) + INTERACTION)
    );
    rig.handle
        .schedule(Duration::from_millis(150), SurfaceEvent::FrameCreated);
    rig.clock.advance(Duration::from_millis(40));
    driver.step(&mut rig.env());
    assert_eq!(
        driver.next_wake(),
        Some(origin + Duration::from_millis(150) + RELEASE_WINDOW)
    );
    Ok(())
}

#[test]
fn an_enrollment_budget_pulls_the_wake_forward() -> TestResult {
    let rig = DriverRig::new(honest(0), SurfaceConfig::default())?;
    let origin = rig.clock.now();
    let plan =
        create_plan(&rig.clock).with_budget(Budget::with_limit(origin, Duration::from_secs(5)));
    let driver = new_driver(plan);
    assert_eq!(driver.next_wake(), Some(origin + Duration::from_secs(5)));
    let plan =
        create_plan(&rig.clock).with_budget(Budget::with_limit(origin, Duration::from_secs(50)));
    let driver = new_driver(plan);
    assert_eq!(driver.next_wake(), Some(origin + READINESS));
    Ok(())
}

#[test]
fn the_enrollment_budget_ends_at_verification_so_release_and_exit_ignore_it() -> TestResult {
    let page = HonestConfig {
        respond_after: None,
        ..honest(0)
    };
    let mut rig = DriverRig::new(page, SurfaceConfig::default())?;
    let origin = rig.clock.now();
    let plan =
        create_plan(&rig.clock).with_budget(Budget::with_limit(origin, Duration::from_secs(1)));
    let mut driver = new_driver(plan);
    let budget_end = origin + Duration::from_secs(1);
    driver.step(&mut rig.env());
    rig.clock.advance(Duration::from_millis(100));
    driver.step(&mut rig.env());
    assert_eq!(
        driver.next_wake(),
        Some(origin + Duration::from_millis(100) + receipt_window(1))
    );
    rig.clock.advance(Duration::from_millis(900));
    driver.step(&mut rig.env());
    let mut wakes = Vec::new();
    for _ in 0..80 {
        rig.clock.advance(Duration::from_millis(20));
        driver.step(&mut rig.env());
        wakes.extend(driver.next_wake());
    }
    assert!(wakes.len() > 3, "the ceremony must still be releasing");
    assert!(
        wakes.iter().all(|wake| *wake > budget_end),
        "an expired budget must not be reported as a wake: {wakes:?}"
    );
    Ok(())
}

fn finished_by_timers(
    page: HonestConfig,
    surface: SurfaceConfig,
) -> Result<(BridgeError, Duration), Box<dyn std::error::Error>> {
    let mut rig = DriverRig::new(page, surface)?;
    let plan = create_plan(&rig.clock);
    let (result, _) = rig.run(plan);
    match result {
        Ok(_) => Err("the ceremony unexpectedly succeeded".into()),
        Err(error) => Ok((error, rig.clock.elapsed())),
    }
}

#[test]
fn every_phase_of_a_ceremony_ends_by_its_own_timer() -> TestResult {
    let silent = HonestConfig {
        respond_after: None,
        ..honest(0)
    };
    // Loading: the document never loads, so the readiness bound ends the ceremony.
    let never_loads = SurfaceConfig {
        load_delay: Duration::from_mins(10),
        ..SurfaceConfig::default()
    };
    let (error, elapsed) = finished_by_timers(honest(0), never_loads)?;
    assert_eq!(
        error,
        BridgeError::Lifecycle(LifecycleCode::ReadinessTimeout)
    );
    assert!(elapsed >= READINESS && elapsed < READINESS + Duration::from_secs(1));
    // Awaiting receipt: the page's listener never registers, so eight posts and the bound end it.
    let (error, elapsed) = finished_by_timers(honest(6_000), SurfaceConfig::default())?;
    assert_eq!(
        error,
        BridgeError::Lifecycle(LifecycleCode::ReadinessTimeout)
    );
    assert!(elapsed < READINESS + Duration::from_secs(1));
    // Interaction: the page receives the pair and then stays silent.
    let (error, elapsed) = finished_by_timers(silent.clone(), SurfaceConfig::default())?;
    assert_eq!(
        error,
        BridgeError::Lifecycle(LifecycleCode::InteractionTimeout)
    );
    assert!(elapsed >= INTERACTION && elapsed < INTERACTION + Duration::from_secs(1));
    // Release: the page ignores the release request, so the two-second window ends it.
    let hostile = HonestConfig {
        abort: AbortBehavior::NeverRelease,
        ..silent
    };
    let (error, elapsed) = finished_by_timers(hostile, SurfaceConfig::default())?;
    assert_eq!(
        error,
        BridgeError::Lifecycle(LifecycleCode::InteractionTimeout)
    );
    let released = INTERACTION + RELEASE_WINDOW;
    assert!(elapsed >= released && elapsed < released + Duration::from_secs(2));
    // Exit: the browser never exits, so the five-second window quarantines the surface.
    let never_exits = SurfaceConfig {
        exit_delay: None,
        ..SurfaceConfig::default()
    };
    let (error, elapsed) = finished_by_timers(honest(0), never_exits)?;
    assert_eq!(
        error,
        BridgeError::Quarantine(QuarantineCode::CleanupTimeout)
    );
    assert!(elapsed >= EXIT_WINDOW && elapsed < EXIT_WINDOW + Duration::from_secs(2));
    Ok(())
}
