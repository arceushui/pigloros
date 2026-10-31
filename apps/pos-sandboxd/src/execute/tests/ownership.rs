use super::*;
use crate::{
    PlannedAttemptIntent, StagingLedger, StagingLimits, StagingUsage, SystemdAttemptRegistry,
};

fn job(scenario: &Scenario, attempt: &AdmittedAttempt) -> ExecuteJob {
    ExecuteJob {
        attempt: attempt.clone(),
        mode: ModePlan::AirGapped,
        capture_store: Arc::clone(&scenario.store),
    }
}

async fn refused_owner(scenario: &mut Scenario, attempt: &AdmittedAttempt) -> TestResult {
    let before = scenario.entries();
    let result = scenario
        .run_on(
            &LoopbackNetwork,
            job(scenario, attempt),
            root_for(&scenario.log, attempt),
        )
        .await;
    let failed = failure(result)?;
    assert!(matches!(failed.error, ExecuteError::AttemptAlreadyClaimed));
    assert_eq!(failed.unit, UnitState::NotStarted);
    assert_eq!(scenario.entries(), before);
    Ok(())
}

#[tokio::test]
async fn a_completed_or_failed_execution_cannot_be_started_again() -> TestResult {
    for fault in [None, Some(Fault::Start), Some(Fault::ReadCgroup)] {
        let mut scenario = Scenario::new()?;
        scenario.host.faults.extend(fault);
        let original = scenario.job(
            ATTEMPT,
            SandboxExecutionMode::AirGapped,
            ModePlan::AirGapped,
            GENEROUS_WATCHDOG_MS,
        )?;
        let attempt = original.attempt.clone();
        let result = scenario
            .run_on(
                &LoopbackNetwork,
                original,
                root_for(&scenario.log, &attempt),
            )
            .await;
        assert_eq!(result.is_err(), fault.is_some());
        // Drop the entire result and its started/cgroup handles before retrying.
        drop(result);
        refused_owner(&mut scenario, &attempt).await?;
    }
    Ok(())
}

#[tokio::test]
async fn cancellation_keeps_the_execution_owner_spent() -> TestResult {
    let mut scenario = Scenario::new()?;
    scenario.barrier.fault = BarrierFault::Hang;
    let original = scenario.job(
        ATTEMPT,
        SandboxExecutionMode::AirGapped,
        ModePlan::AirGapped,
        GENEROUS_WATCHDOG_MS,
    )?;
    let attempt = original.attempt.clone();
    {
        let run = scenario.run_on(
            &LoopbackNetwork,
            original,
            root_for(&scenario.log, &attempt),
        );
        let mut run = std::pin::pin!(run);
        let ready = std::future::poll_fn(|context| {
            std::task::Poll::Ready(run.as_mut().poll(context).is_ready())
        })
        .await;
        assert!(!ready);
    }
    assert!(logged(&scenario.log, "guard_kill").await);
    refused_owner(&mut scenario, &attempt).await?;
    Ok(())
}

#[tokio::test]
async fn an_unpolled_execution_has_not_prepared_or_claimed_anything() -> TestResult {
    let mut scenario = Scenario::new()?;
    let original = scenario.job(
        ATTEMPT,
        SandboxExecutionMode::AirGapped,
        ModePlan::AirGapped,
        GENEROUS_WATCHDOG_MS,
    )?;
    let attempt = original.attempt.clone();
    drop(scenario.run_on(
        &LoopbackNetwork,
        original,
        root_for(&scenario.log, &attempt),
    ));
    assert!(scenario.entries().is_empty());
    scenario
        .run_on(
            &LoopbackNetwork,
            job(&scenario, &attempt),
            root_for(&scenario.log, &attempt),
        )
        .await?;
    Ok(())
}

#[test]
fn simultaneous_execution_claims_have_exactly_one_owner() -> TestResult {
    let first = Scenario::new()?;
    let second = Scenario::sharing(&first.store);
    let original = first.job(
        ATTEMPT,
        SandboxExecutionMode::AirGapped,
        ModePlan::AirGapped,
        GENEROUS_WATCHDOG_MS,
    )?;
    let attempt = original.attempt;
    let deadline = Instant::now() + Duration::from_secs(5);
    let (left_ready, right_peer) = std::sync::mpsc::channel();
    let (right_ready, left_peer) = std::sync::mpsc::channel();
    let admitted = &attempt;
    let outcomes = std::thread::scope(|scope| {
        let run = move |mut scenario: Scenario, attempt: &AdmittedAttempt, ready, peer| {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_time()
                .build()
                .map_err(|error| error.to_string())?;
            await_contender(&ready, &peer, deadline).map_err(|error| error.to_string())?;
            drop((ready, peer));
            let outcome = runtime.block_on(scenario.run_on(
                &LoopbackNetwork,
                job(&scenario, attempt),
                root_for(&scenario.log, attempt),
            ));
            Ok::<_, String>((outcome, scenario.entries()))
        };
        let left = scope.spawn(move || run(first, admitted, left_ready, left_peer));
        let right = scope.spawn(move || run(second, admitted, right_ready, right_peer));
        [left.join(), right.join()]
    });
    let mut successes = 0;
    let mut refusals = 0;
    for outcome in outcomes {
        let (result, entries) = outcome.map_err(|_| "execution contender panicked")??;
        match result {
            Ok(_) => {
                successes += 1;
                assert_eq!(entries.iter().filter(|entry| *entry == "start").count(), 1);
            }
            Err(failed) => {
                refusals += 1;
                assert!(matches!(failed.error, ExecuteError::AttemptAlreadyClaimed));
                assert!(entries.is_empty());
            }
        }
    }
    assert_eq!((successes, refusals), (1, 1));
    Ok(())
}

fn await_contender(
    ready: &std::sync::mpsc::Sender<()>,
    peer: &std::sync::mpsc::Receiver<()>,
    deadline: Instant,
) -> Result<(), std::sync::mpsc::RecvTimeoutError> {
    ready
        .send(())
        .map_err(|_| std::sync::mpsc::RecvTimeoutError::Disconnected)?;
    peer.recv_timeout(deadline.saturating_duration_since(Instant::now()))
}

#[test]
fn a_missing_or_unready_contender_cannot_hold_its_peer_forever() -> TestResult {
    use std::sync::mpsc::{channel, RecvTimeoutError};

    let (ready, observed) = channel();
    let (missing, peer) = channel();
    drop(missing);
    assert_eq!(
        await_contender(&ready, &peer, Instant::now() + Duration::from_secs(5)),
        Err(RecvTimeoutError::Disconnected)
    );
    observed.try_recv()?;

    let (ready, observed) = channel();
    let (_unready, peer) = channel();
    assert_eq!(
        await_contender(&ready, &peer, Instant::now()),
        Err(RecvTimeoutError::Timeout)
    );
    observed.try_recv()?;

    let (ready, missing) = channel();
    let (_unready, peer) = channel();
    drop(missing);
    assert_eq!(
        await_contender(&ready, &peer, Instant::now() + Duration::from_secs(5)),
        Err(RecvTimeoutError::Disconnected)
    );
    Ok(())
}

#[tokio::test]
async fn concurrent_contenders_cannot_prepare_a_second_execution() -> TestResult {
    let mut first = Scenario::new()?;
    first.barrier.fault = BarrierFault::Hang;
    let original = first.job(
        ATTEMPT,
        SandboxExecutionMode::AirGapped,
        ModePlan::AirGapped,
        GENEROUS_WATCHDOG_MS,
    )?;
    let attempt = original.attempt.clone();
    let mut second = Scenario::sharing(&first.store);
    {
        let run = first.run_on(&LoopbackNetwork, original, root_for(&first.log, &attempt));
        let mut run = std::pin::pin!(run);
        let ready = std::future::poll_fn(|context| {
            std::task::Poll::Ready(run.as_mut().poll(context).is_ready())
        })
        .await;
        assert!(!ready);
        refused_owner(&mut second, &attempt).await?;
    }
    assert!(logged(&first.log, "guard_kill").await);
    refused_owner(&mut second, &attempt).await?;
    Ok(())
}

#[tokio::test]
async fn authenticated_reconstruction_preserves_a_refused_execution_owner() -> TestResult {
    use crate::test_fixtures::attempt_directory::{fixed_registry, require_isolated_root};
    use pos_reference::provider_admission::test_support::StagedInstallation;

    if !require_isolated_root(
        "execute::tests::ownership::authenticated_reconstruction_preserves_a_refused_execution_owner",
    )
    .map_err(|error| error.to_string())?
    {
        return Ok(());
    }
    let staged = StagedInstallation::stage_execution().map_err(|error| error.to_string())?;
    let ledger = StagingLedger::new(StagingLimits {
        aggregate_bytes: 512 * 1024 * 1024,
    });
    let (_staging, input) =
        crate::test_fixtures::staged_execution::verified_input(&staged, &ledger)
            .map_err(|error| error.to_string())?;
    let entry = input.entry();
    let request = entry.admission().snapshot().request().clone();
    fixed_registry().map_err(|error| error.to_string())?;
    let registry = SystemdAttemptRegistry::open()?;
    let directory = registry
        .commit_planned(&PlannedAttemptIntent::new(
            request.attempt_id,
            request.authority.sim1_digest,
        )?)?
        .prepare_directory()?;
    let attempt = AdmittedAttempt::from_entry(&entry, &directory)?;
    let mut scenario = Scenario::new()?;
    let mismatched = if attempt.mode() == SandboxExecutionMode::AirGapped {
        ModePlan::Fork
    } else {
        ModePlan::AirGapped
    };
    let failed = failure(
        scenario
            .run_on(
                &LoopbackNetwork,
                ExecuteJob {
                    attempt,
                    mode: mismatched,
                    capture_store: Arc::clone(&scenario.store),
                },
                || Err(ImageActivationError::EvidenceMismatch),
            )
            .await,
    )?;
    assert!(matches!(failed.error, ExecuteError::ModeMismatch));
    assert!(scenario.entries().is_empty());
    drop(failed);
    let reconstructed = AdmittedAttempt::from_entry(&entry, &directory)?;
    assert_eq!(ledger.usage().attempts, 1);
    drop(input);
    assert_eq!(ledger.usage().attempts, 1);
    refused_owner(&mut scenario, &reconstructed).await?;
    drop(reconstructed);
    assert_eq!(ledger.usage(), StagingUsage::default());
    // Dropping the admitted handles does not reset the prepared directory owner.
    let (_next_staging, next_input) =
        crate::test_fixtures::staged_execution::verified_input(&staged, &ledger)
            .map_err(|error| error.to_string())?;
    let next = AdmittedAttempt::from_entry(&next_input.entry(), &directory)?;
    refused_owner(&mut scenario, &next).await?;
    Ok(())
}
