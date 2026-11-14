//! Cancellation of one execution (ADR-069 §4 `cancel` and §8).

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod cases {

    use super::super::*;

    /// Run `scenario` in `mode` under `watchdog_ms`, requesting cancellation once
    /// the launcher release was logged.
    async fn cancelled_after_release(
        scenario: &mut Scenario,
        mode: SandboxExecutionMode,
        plan: ModePlan,
        watchdog_ms: u64,
    ) -> TestResult<Outcome> {
        let job = scenario.job(ATTEMPT, mode, plan, watchdog_ms)?;
        let cancel = std::mem::take(&mut scenario.cancel);
        let log = Arc::clone(&scenario.log);
        let recheck = root_for(&scenario.log, &job.attempt);
        let canceller = async move {
            let released = logged(&log, "release").await;
            cancel.cancel();
            released
        };
        let run = scenario.run_on(&LoopbackNetwork, job, recheck);
        let (outcome, released) = tokio::join!(run, canceller);
        assert!(released);
        Ok(outcome)
    }

    #[tokio::test]
    async fn a_cancellation_before_the_release_kills_the_unit_and_keeps_its_cgroup() -> TestResult {
        let mut scenario = Scenario::new()?;
        scenario.cancel.cancel();
        assert!(scenario.cancel.is_requested());
        let failed = scenario.fails().await?;
        assert!(matches!(failed.error, ExecuteError::Cancelled));
        assert_eq!(failed.unit, UnitState::Killed);
        assert!(failed
            .cgroup
            .is_some_and(|retained| Arc::ptr_eq(&retained.kills, &scenario.host.cgroup_kills)));
        assert!(scenario
            .entries()
            .ends_with(&names(&["release", "kill", "cgroup_kill", "stop"])));
        Ok(())
    }

    #[tokio::test]
    async fn a_barrier_that_hangs_is_abandoned_when_the_attempt_is_cancelled() -> TestResult {
        let mut scenario = Scenario::new()?;
        scenario.barrier.fault = BarrierFault::Hang;
        let outcome = cancelled_after_release(
            &mut scenario,
            SandboxExecutionMode::AirGapped,
            ModePlan::AirGapped,
            GENEROUS_WATCHDOG_MS,
        );
        let failed = failure(tokio::time::timeout(Duration::from_secs(10), outcome).await??)?;
        assert!(matches!(failed.error, ExecuteError::Cancelled));
        assert_eq!(failed.unit, UnitState::Killed);
        Ok(())
    }

    #[tokio::test]
    async fn a_cancellation_after_the_release_requests_a_stop_and_keeps_the_cgroup() -> TestResult {
        let mut scenario = Scenario::new()?;
        scenario.host.empty_after = usize::MAX;
        let outcome = cancelled_after_release(
            &mut scenario,
            SandboxExecutionMode::AirGapped,
            ModePlan::AirGapped,
            GENEROUS_WATCHDOG_MS,
        );
        let execution = tokio::time::timeout(Duration::from_secs(10), outcome).await???;
        assert_eq!(
            execution.ending,
            AttemptEnding::Cancelled { watchdog: None }
        );
        assert!(Arc::ptr_eq(
            &execution.cgroup.kills,
            &scenario.host.cgroup_kills
        ));
        // Only a stop is requested: grace and escalation belong to the cleanup.
        assert!(scenario.entries().ends_with(&names(&["release", "stop"])));
        assert_eq!(scenario.cgroup_kills(), 0);
        assert!(!scenario.host.killed.load(Ordering::SeqCst));
        Ok(())
    }

    #[tokio::test]
    async fn a_cancelled_local_attempt_keeps_its_proxy_evidence() -> TestResult {
        let (_, mode) = local_plan(UNUSED_ENDPOINT)?;
        let mut scenario = Scenario::new()?;
        scenario.host.adapter = AdapterScript::Silent;
        let outcome =
            cancelled_after_release(&mut scenario, SandboxExecutionMode::Local, mode, 200);
        let execution = tokio::time::timeout(Duration::from_secs(10), outcome).await???;
        // Cancellation outranks the watchdog that later closed the silent
        // channel, and keeps its acknowledged SIGKILL as evidence.
        assert_eq!(
            execution.ending,
            AttemptEnding::Cancelled {
                watchdog: Some(true)
            }
        );
        assert!(matches!(&execution.network, NetworkEvidence::Local(_)));
        let entries = scenario.entries();
        let stop = entries.iter().position(|entry| entry == "stop");
        let release = entries.iter().position(|entry| entry == "release");
        assert!(release < stop);
        assert_eq!(scenario.cgroup_kills(), 0);
        Ok(())
    }

    #[tokio::test]
    async fn a_dropped_cancel_handle_never_cancels() -> TestResult {
        let mut scenario = Scenario::new()?;
        let job = scenario.job(
            ATTEMPT,
            SandboxExecutionMode::AirGapped,
            ModePlan::AirGapped,
            GENEROUS_WATCHDOG_MS,
        )?;
        scenario.cancel = AttemptCancel::default();
        let recheck = root_for(&scenario.log, &job.attempt);
        let execution = scenario.run_on(&LoopbackNetwork, job, recheck).await?;
        assert_eq!(execution.ending, AttemptEnding::CgroupEmpty);
        assert!(!scenario.cancel.is_requested());
        Ok(())
    }

    /// Run a Local attempt whose cancellation is requested as the launcher
    /// release completes, with `adapter` on FD 3 under `watchdog_ms`.
    async fn cancelled_at_release(
        adapter: AdapterScript,
        watchdog_ms: u64,
    ) -> TestResult<AttemptExecution<String, FakeCgroup, u64>> {
        let (_, mode) = local_plan(UNUSED_ENDPOINT)?;
        let mut scenario = Scenario::new()?;
        scenario.host.adapter = adapter;
        let cancel = Arc::new(AttemptCancel::new());
        scenario.cancel = AttemptCancel::new();
        let mut job = scenario.job(ATTEMPT, SandboxExecutionMode::Local, mode, watchdog_ms)?;
        job.cancel = cancel.signal();
        scenario.barrier.cancel_on_release = Some(cancel);
        let recheck = root_for(&scenario.log, &job.attempt);
        let run = scenario.run_on(&LoopbackNetwork, job, recheck);
        let execution = tokio::time::timeout(Duration::from_secs(10), run).await??;
        Ok(execution)
    }

    #[tokio::test]
    async fn a_cancellation_outranks_a_watchdog_expiry_and_keeps_its_kill() -> TestResult {
        let execution = cancelled_at_release(AdapterScript::Silent, 150).await?;
        assert_eq!(
            execution.ending,
            AttemptEnding::Cancelled {
                watchdog: Some(true)
            }
        );
        Ok(())
    }

    #[tokio::test]
    async fn a_cancellation_outranks_a_proxy_protocol_failure() -> TestResult {
        let execution = cancelled_at_release(AdapterScript::ProtocolViolation, 30_000).await?;
        assert_eq!(
            execution.ending,
            AttemptEnding::Cancelled { watchdog: None }
        );
        assert_eq!(
            execution.network.termination(),
            Some(LocalNetworkTermination::ProtocolFailure)
        );
        Ok(())
    }

    #[tokio::test]
    async fn an_unreadable_cgroup_after_a_clean_local_session_terminates_the_unit() -> TestResult {
        let (remote, plan, mode) = local_setup()?;
        let mut scenario = Scenario::new()?;
        scenario.host.adapter = AdapterScript::Exchange(plan);
        scenario.host.faults.push(Fault::ReadCgroup);
        let failed = failure(scenario.run(SandboxExecutionMode::Local, mode).await?)?;
        assert!(matches!(failed.error, ExecuteError::Cgroup(_)));
        assert_eq!(failed.unit, UnitState::Killed);
        drop(remote);
        Ok(())
    }
}
