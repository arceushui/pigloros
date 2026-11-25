//! The adapter's stdin feed and stdout capture through the execute path
//! (ADR-069 R10 §4.5, §4.6 and §8.1, #1357).
//!
//! The fake host plays systemd and the adapter: it duplicates the unit ends
//! of the standard descriptors from the submitted request and runs a scripted
//! adapter on them, which reads its input and writes its output once the
//! provider feeds it.

use std::io::Read as _;
use std::os::unix::fs::MetadataExt as _;

use pos_reference::sandbox_provider_protocol::{OutputCaptureRecord, SandboxLimit};

use super::*;
use crate::test_fixtures::TestPayload;
use crate::{OutputReservationRefused, StagingLedger, StagingLimits};

/// R10 §8.1 `S`: a 70-byte valid Unavailable observation, an EAO1 frame
/// then an EOE1 frame.
const S: &str = "00000007826445414f3101000000378964454f45310103f6f6f6f688000000000000000058209cd8b956c8795d49680acf9b4a3e44ead3889f3e1f2caf8edbcb156e0d6dc02d";

const INPUT: &[u8] = b"input";

fn hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .filter_map(|index| u8::from_str_radix(&text[index..index + 2], 16).ok())
        .collect()
}

fn stream() -> Vec<u8> {
    hex(S)
}

/// What the scripted adapter does with its stdin.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(super) enum InputUse {
    /// Read it to end of file before writing any output.
    #[default]
    Read,
    /// Close it at once.
    Close,
    /// Keep it open and never read it.
    Ignore,
}

/// What the scripted adapter does with its standard streams.
#[derive(Clone, Debug, Default)]
pub(super) struct StdioScript {
    /// Written to stdout once the input was handled.
    output: Vec<u8>,
    input: InputUse,
    /// Keep a duplicate of the stdout write end, as systemd does until the
    /// unit's resources are released, so end of file never comes.
    hold_output: bool,
    /// Keep every channel open and never finish, so the cgroup never empties.
    never_finish: bool,
}

/// What the scripted adapter observed.
#[derive(Clone, Debug, Default)]
pub(super) struct StdioReport {
    /// The input bytes it read.
    input: Vec<u8>,
    /// Whether `ReleaseV1` was sent before its first input byte.
    released_before_input: Option<bool>,
    /// How many descriptors of the process held the stdin read end and the
    /// stdout write end once input arrived, outside the adapter and systemd.
    provider_unit_ends: Option<(usize, usize)>,
}

/// The device, inode and access mode of `descriptor`.
fn identity(descriptor: &StdOwnedFd) -> std::io::Result<(u64, u64)> {
    File::from(descriptor.try_clone()?)
        .metadata()
        .map(|metadata| (metadata.dev(), metadata.ino()))
}

/// The `O_ACCMODE` bits of open descriptor `number`, from its fdinfo.
fn access_mode(number: &str) -> Option<u32> {
    std::fs::read_to_string(format!("/proc/self/fdinfo/{number}"))
        .ok()?
        .lines()
        .find_map(|line| line.strip_prefix("flags:"))
        .and_then(|flags| u32::from_str_radix(flags.trim(), 8).ok())
        .map(|flags| flags & 0o3)
}

/// The descriptor numbers of this process open on `identity` with `mode`,
/// other than `except`.
fn holders(identity: (u64, u64), mode: u32, except: &[String]) -> usize {
    std::fs::read_dir("/proc/self/fd")
        .map(|entries| {
            entries
                .filter_map(Result::ok)
                .filter_map(|entry| entry.file_name().into_string().ok())
                .filter(|number| !except.contains(number))
                .filter(|number| {
                    std::fs::metadata(format!("/proc/self/fd/{number}"))
                        .is_ok_and(|metadata| (metadata.dev(), metadata.ino()) == identity)
                })
                .filter(|number| access_mode(number) == Some(mode))
                .count()
        })
        .unwrap_or_default()
}

/// The number of `descriptor` as `/proc/self/fd` lists it.
fn number(descriptor: &impl std::os::fd::AsRawFd) -> String {
    descriptor.as_raw_fd().to_string()
}

impl FakeHost {
    /// Duplicate the unit ends of the standard descriptors, as systemd does,
    /// and run the scripted adapter on them. Without a script, the unit ends
    /// close with the request and no unit task remains.
    pub(super) fn run_stdio(&self, request: &TransientUnitRequest) {
        let Some(script) = self.stdio.clone() else {
            self.adapter_done.store(true, Ordering::SeqCst);
            return;
        };
        let ends = request
            .requested_properties()
            .iter()
            .filter_map(|property| match property.value() {
                SystemdTransientUnitValue::StandardDescriptor(Some(descriptor)) => {
                    descriptor.as_fd().try_clone_to_owned().ok()
                }
                _other => None,
            })
            .collect::<Vec<_>>();
        let Ok([input, output, _error]) = <[StdOwnedFd; 3]>::try_from(ends) else {
            return;
        };
        if script.hold_output {
            if let (Ok(held), Ok(mut systemd)) = (output.try_clone(), self.systemd_held.lock()) {
                systemd.push(held);
            }
        }
        let mut held = self
            .systemd_held
            .lock()
            .map(|held| held.iter().map(number).collect::<Vec<_>>())
            .unwrap_or_default();
        if let Ok(watched) = self.adapter_stdout.lock() {
            held.extend(watched.iter().map(number));
        }
        let done = Arc::clone(&self.adapter_done);
        let report = Arc::clone(&self.stdio_report);
        let released = Arc::clone(&self.released);
        let kept = Arc::clone(&self.systemd_held);
        let stdout = Arc::clone(&self.adapter_stdout);
        let reads_input = script.input == InputUse::Read;
        let adapter = move || {
            let identities = (identity(&input), identity(&output));
            let mine = [number(&input), number(&output)];
            let mut input = File::from(input);
            let mut read = Vec::new();
            if script.input == InputUse::Close {
                drop(input);
            } else if script.input == InputUse::Ignore {
                if let Ok(mut kept) = kept.lock() {
                    kept.push(StdOwnedFd::from(input));
                }
            } else {
                let mut first = [0; 1];
                if input.read(&mut first).is_ok_and(|count| count == 1) {
                    read.push(first[0]);
                    let released = released.lock().is_ok_and(|released| !released.is_empty());
                    let except = [&mine[..], &held[..]].concat();
                    let unit_ends = match identities {
                        (Ok(stdin), Ok(stdout)) => {
                            Some((holders(stdin, 0, &except), holders(stdout, 1, &except)))
                        }
                        _ => None,
                    };
                    if let Ok(mut report) = report.lock() {
                        report.released_before_input = Some(released);
                        report.provider_unit_ends = unit_ends;
                    }
                }
                input.read_to_end(&mut read).ok();
            }
            let mut output = File::from(output);
            output.write_all(&script.output).ok();
            if let Ok(mut report) = report.lock() {
                report.input = read;
            }
            if script.never_finish {
                let output = StdOwnedFd::from(output);
                // A duplicate lets the fake's kill watch the channel.
                if let (Ok(watched), Ok(mut stdout)) = (output.try_clone(), stdout.lock()) {
                    stdout.push(watched);
                }
                if let Ok(mut kept) = kept.lock() {
                    kept.push(output);
                }
                return;
            }
            drop(output);
            done.store(true, Ordering::SeqCst);
        };
        // An adapter that never reads its input writes its output before the
        // unit starts, so it is on the channel however early the attempt
        // ends; one that reads waits for the feed on its own thread.
        if reads_input {
            thread::spawn(adapter);
        } else {
            adapter();
        }
    }

    fn stdio_report(&self) -> StdioReport {
        self.stdio_report
            .lock()
            .map(|report| report.clone())
            .unwrap_or_default()
    }
}

/// A scenario whose adapter runs `script` on `payload`, with ELM1\[8\] =
/// `output_limit`.
struct StdioRun {
    scenario: Scenario,
    outcome: Outcome,
}

/// The fixture limits with ELM1\[8\] and ELM1\[16\] replaced.
fn limits(output_limit: u64, input_window_ms: u64, watchdog_ms: u64) -> Vec<SandboxLimit> {
    crate::test_fixtures::execution_limits(watchdog_ms)
        .into_iter()
        .map(|limit| SandboxLimit {
            value: match limit.limit_id {
                8 => output_limit,
                16 => input_window_ms,
                _ => limit.value,
            },
            ..limit
        })
        .collect()
}

impl StdioRun {
    async fn with(
        script: StdioScript,
        payload: TestPayload,
        limits: Vec<SandboxLimit>,
    ) -> TestResult<Self> {
        let mut scenario = Scenario::new()?;
        scenario.host.stdio = Some(script);
        scenario.host.released = Arc::clone(&scenario.barrier.released);
        let mut job = scenario.job(
            ATTEMPT,
            SandboxExecutionMode::AirGapped,
            ModePlan::AirGapped,
            GENEROUS_WATCHDOG_MS,
        )?;
        job.attempt = job
            .attempt
            .with_limits(limits)
            .with_payload(Arc::new(payload));
        let recheck = root_for(&scenario.log, &job.attempt);
        let outcome = scenario.run_on(&LoopbackNetwork, job, recheck).await;
        Ok(Self { scenario, outcome })
    }

    /// The adapter writes `output` after reading the input, under ELM1\[8\] =
    /// `output_limit`.
    async fn writing(output: Vec<u8>, output_limit: u64) -> TestResult<Self> {
        let script = StdioScript {
            output,
            ..StdioScript::default()
        };
        let limits = limits(output_limit, 1_000, GENEROUS_WATCHDOG_MS);
        Self::with(script, TestPayload::with_input(INPUT), limits).await
    }

    fn execution(self) -> TestResult<AttemptExecution<String, FakeCgroup, u64>> {
        self.outcome
            .map_err(|failure| format!("the execution failed: {}", failure.error).into())
    }
}

const fn capture_record(
    accepted_bytes: u64,
    ceiling_reached: bool,
    complete_frame: bool,
) -> OutputCaptureRecord {
    OutputCaptureRecord {
        accepted_bytes,
        ceiling_reached,
        complete_frame,
    }
}

/// One R10 §8.1 row: `output` then end of stream, under ELM1\[8\] = `limit`.
async fn captured(output: Vec<u8>, limit: u64) -> TestResult<OutputCaptureRecord> {
    let run = StdioRun::writing(output, limit).await?;
    Ok(run.execution()?.adapter.output().capture())
}

#[tokio::test]
async fn a_complete_framed_output_is_captured_after_the_whole_input_was_fed() -> TestResult {
    let run = StdioRun::writing(stream(), 100).await?;
    let report = run.scenario.host.stdio_report();
    let execution = run.execution()?;
    // The adapter read exactly the verified input, after the release only.
    assert_eq!(report.input, INPUT);
    assert_eq!(report.released_before_input, Some(true));
    let fed = execution.adapter.input().ok_or("the feed was not timed")?;
    assert_eq!((fed.expected_bytes, fed.accepted_bytes), (5, 5));
    assert!(fed.complete);
    assert_eq!(fed.deadline - fed.start, 1_000_000_000);
    assert!(fed.start <= fed.finish && fed.finish <= fed.deadline);
    let output = execution.adapter.output();
    assert_eq!(output.capture(), capture_record(70, false, true));
    let descriptor = output.descriptor();
    assert_eq!(descriptor.byte_length, 70);
    let mut digest = blake3::Hasher::new();
    digest.update(b"PiglorOS.SandboxOutputBytes.v1\0");
    digest.update(&stream());
    assert_eq!(&descriptor.digest, digest.finalize().as_bytes());
    assert_eq!(execution.ending, AttemptEnding::CgroupEmpty);
    Ok(())
}

#[tokio::test]
async fn the_provider_holds_no_unit_end_once_the_unit_was_started() -> TestResult {
    for hold_output in [false, true] {
        let script = StdioScript {
            output: stream(),
            hold_output,
            ..StdioScript::default()
        };
        let limits = limits(100, 1_000, GENEROUS_WATCHDOG_MS);
        let run = StdioRun::with(script, TestPayload::with_input(INPUT), limits).await?;
        // Neither the stdin read end nor the stdout write end is held by the
        // provider: only by the adapter and by systemd's duplicate.
        assert_eq!(
            run.scenario.host.stdio_report().provider_unit_ends,
            Some((0, 0))
        );
        run.execution()?;
    }
    Ok(())
}

#[tokio::test]
async fn exactly_elm1_8_framed_bytes_then_end_of_stream_is_complete() -> TestResult {
    assert_eq!(
        captured(stream(), 70).await?,
        capture_record(70, false, true)
    );
    Ok(())
}

#[tokio::test]
async fn one_byte_over_elm1_8_reaches_the_ceiling() -> TestResult {
    assert_eq!(
        captured(stream(), 69).await?,
        capture_record(69, true, false)
    );
    let mut over = stream();
    over.push(0);
    assert_eq!(captured(over, 70).await?, capture_record(70, true, false));
    Ok(())
}

#[tokio::test]
async fn malformed_and_truncated_output_is_no_complete_frame() -> TestResult {
    let mut trailing = stream();
    trailing.push(0);
    assert_eq!(
        captured(trailing, 100).await?,
        capture_record(71, false, false)
    );
    assert_eq!(
        captured(vec![0; 4], 100).await?,
        capture_record(4, false, false)
    );
    let header = hex("00000007826445414f3101");
    assert_eq!(
        captured(header, 100).await?,
        capture_record(11, false, false)
    );
    Ok(())
}

#[tokio::test]
async fn an_adapter_that_exits_mid_frame_leaves_no_complete_frame() -> TestResult {
    let truncated = stream()[..69].to_vec();
    assert_eq!(
        captured(truncated, 100).await?,
        capture_record(69, false, false)
    );
    Ok(())
}

#[tokio::test]
async fn a_zero_output_limit_accepts_no_byte() -> TestResult {
    assert_eq!(
        captured(Vec::new(), 0).await?,
        capture_record(0, false, false)
    );
    assert_eq!(captured(vec![0], 0).await?, capture_record(0, true, false));
    Ok(())
}

#[tokio::test]
async fn an_empty_cgroup_drains_the_output_while_systemd_still_holds_its_end() -> TestResult {
    // The adapter exits after a complete frame without closing fd 1, and
    // systemd's duplicate keeps end of file away: the drain ends the capture.
    let script = StdioScript {
        output: stream(),
        hold_output: true,
        ..StdioScript::default()
    };
    let limits = limits(100, 1_000, GENEROUS_WATCHDOG_MS);
    let run = StdioRun::with(script, TestPayload::with_input(INPUT), limits).await?;
    let execution = run.execution()?;
    assert_eq!(execution.ending, AttemptEnding::CgroupEmpty);
    assert_eq!(
        execution.adapter.output().capture(),
        capture_record(70, false, true)
    );
    Ok(())
}

/// How a hung attempt is driven to its ending.
#[derive(Clone, Copy, Default)]
struct Ending {
    /// A Local attempt whose FD 3 adapter does this; Air-Gapped otherwise.
    local: Option<Fd3>,
    /// Injected host faults.
    faults: &'static [Fault],
    /// Cancel the attempt as it is released.
    cancel: bool,
    /// Report an activation so long ago that the watchdog's `D + G` has
    /// passed when the release arrives: the supervision ends at its first
    /// poll, as on a host that stalled the provider after the release.
    late: bool,
}

/// What a hung Local adapter does on FD 3.
#[derive(Clone, Copy)]
enum Fd3 {
    /// Send a zero-length frame: a protocol failure kills the unit.
    Violation,
    /// Hold FD 3 open: the watchdog closes it.
    Silent,
}

impl Ending {
    /// Script `scenario`'s adapter to write `S` at once and then never exit,
    /// with this ending's faults, cancellation and FD 3 adapter; the
    /// attempt's mode and plan.
    fn script(self, scenario: &mut Scenario) -> TestResult<(SandboxExecutionMode, ModePlan)> {
        // The output is queued before the release, so the ending, however
        // early, finds it on the channel.
        scenario.host.stdio = Some(StdioScript {
            output: stream(),
            input: InputUse::Ignore,
            never_finish: true,
            ..StdioScript::default()
        });
        scenario.host.faults.extend_from_slice(self.faults);
        if self.late {
            let stalled = u64::try_from(2 * NANOSECONDS_PER_SECOND).unwrap_or_default();
            scenario.host.activated = Some(monotonic_now_ns().saturating_sub(stalled));
        }
        if self.cancel {
            scenario.barrier.cancel_on_release = Some(Arc::new(AttemptCancel::new()));
        }
        match self.local {
            Some(fd3) => {
                scenario.host.adapter = fd3.script();
                Ok((SandboxExecutionMode::Local, local_plan(UNUSED_ENDPOINT)?.1))
            }
            None => Ok((SandboxExecutionMode::AirGapped, ModePlan::AirGapped)),
        }
    }
}

impl Fd3 {
    const fn script(self) -> AdapterScript {
        match self {
            Self::Violation => AdapterScript::ProtocolViolation,
            Self::Silent => AdapterScript::Silent,
        }
    }
}

/// The job of a hung attempt under a 200 ms watchdog, cancelled as its
/// release is if `scenario` cancels on release.
fn hung_job(
    scenario: &Scenario,
    mode: SandboxExecutionMode,
    plan: ModePlan,
) -> TestResult<ExecuteJob> {
    let mut job = scenario.job(ATTEMPT, mode, plan, 200)?;
    if let Some(cancel) = &scenario.barrier.cancel_on_release {
        job.cancel = cancel.signal();
    }
    job.attempt = job
        .attempt
        .with_limits(limits(100, 1_000, 200))
        .with_payload(Arc::new(TestPayload::with_input(INPUT)));
    Ok(job)
}

/// A scenario whose adapter writes `S` at once and then never exits, under a
/// 200 ms watchdog, driven to its ending as `ending` says; the execution and
/// how long it took.
async fn hung(ending: Ending) -> TestResult<(Duration, AttemptExecution<String, FakeCgroup, u64>)> {
    let mut scenario = Scenario::new()?;
    let (mode, plan) = ending.script(&mut scenario)?;
    let job = hung_job(&scenario, mode, plan)?;
    let recheck = root_for(&scenario.log, &job.attempt);
    let started = Instant::now();
    let outcome = scenario.run_on(&LoopbackNetwork, job, recheck).await;
    let elapsed = started.elapsed();
    outcome
        .map(|execution| (elapsed, execution))
        .map_err(|failure| format!("the execution failed: {}", failure.error).into())
}

/// The capture of an attempt that ended as `ending` with ending code
/// `expected`.
async fn captured_at(ending: Ending, expected: AttemptEnding) -> TestResult<OutputCaptureRecord> {
    let (_, execution) = hung(ending).await?;
    assert_eq!(execution.ending, expected);
    Ok(execution.adapter.output().capture())
}

/// ADR-069 R14 N7: a Local network whose removal failed is reported by each
/// ending that serves the proxy: the watchdog, a protocol failure and a
/// cancellation.
#[tokio::test]
async fn a_failed_removal_is_reported_on_every_ending_that_serves_the_proxy() -> TestResult {
    let endings = [
        (
            "watchdog",
            Ending {
                local: Some(Fd3::Silent),
                ..Ending::default()
            },
        ),
        (
            "protocol failure",
            Ending {
                local: Some(Fd3::Violation),
                ..Ending::default()
            },
        ),
        (
            "cancellation",
            Ending {
                cancel: true,
                local: Some(Fd3::Silent),
                ..Ending::default()
            },
        ),
    ];
    for (name, ending) in endings {
        for removal_fails in [false, true] {
            let mut scenario = Scenario::new()?;
            let (mode, plan) = ending.script(&mut scenario)?;
            let job = hung_job(&scenario, mode, plan)?;
            let recheck = root_for(&scenario.log, &job.attempt);
            let torn_down = Arc::new(AtomicUsize::new(0));
            let network = TornDownNetwork::new(&torn_down, removal_fails);
            let execution = scenario
                .run_on(&network, job, recheck)
                .await
                .map_err(|failed| failed.error)?;
            assert_eq!(torn_down.load(Ordering::SeqCst), 1, "{name}");
            assert_eq!(execution.network_removal.is_some(), removal_fails, "{name}");
        }
    }
    Ok(())
}

const DRAINED: OutputCaptureRecord = capture_record(70, false, true);
const ABORTED: OutputCaptureRecord = capture_record(70, false, false);

#[tokio::test]
async fn every_acknowledged_kill_or_stop_drains_the_output_once_the_cgroup_is_empty() -> TestResult
{
    // R10 §4.6 (E), m6: endings 1, 3, 5 and 6 observe the cgroup empty.
    let watchdog = Ending::default();
    assert_eq!(
        captured_at(watchdog, AttemptEnding::WatchdogKilled).await?,
        DRAINED
    );
    let violation = Ending {
        local: Some(Fd3::Violation),
        ..Ending::default()
    };
    assert_eq!(
        captured_at(violation, AttemptEnding::ProtocolFailureKilled).await?,
        DRAINED
    );
    let cancelled = Ending {
        cancel: true,
        ..Ending::default()
    };
    assert_eq!(
        captured_at(cancelled, AttemptEnding::Cancelled { watchdog: None }).await?,
        DRAINED
    );
    let cancelled_then_killed = Ending {
        local: Some(Fd3::Silent),
        cancel: true,
        ..Ending::default()
    };
    assert_eq!(
        captured_at(
            cancelled_then_killed,
            AttemptEnding::Cancelled {
                watchdog: Some(true)
            }
        )
        .await?,
        DRAINED
    );
    Ok(())
}

#[tokio::test]
async fn every_unacknowledged_kill_aborts_the_capture() -> TestResult {
    // Endings 2, 4 and 7: the cgroup is never observed empty. Every byte
    // read is kept, but an aborted capture is no complete frame.
    let unkilled = Ending {
        faults: &[Fault::Kill],
        ..Ending::default()
    };
    assert_eq!(
        captured_at(unkilled, AttemptEnding::WatchdogKillFailed).await?,
        ABORTED
    );
    let violation = Ending {
        local: Some(Fd3::Violation),
        faults: &[Fault::Kill],
        ..Ending::default()
    };
    assert_eq!(
        captured_at(violation, AttemptEnding::ProtocolFailureKillFailed).await?,
        ABORTED
    );
    let cancelled = Ending {
        local: Some(Fd3::Silent),
        faults: &[Fault::Kill],
        cancel: true,
        ..Ending::default()
    };
    assert_eq!(
        captured_at(
            cancelled,
            AttemptEnding::Cancelled {
                watchdog: Some(false)
            }
        )
        .await?,
        ABORTED
    );
    // The supervision ends at its first poll, before the capture was ever
    // told the channel is readable; the kill answers once the queued output
    // was read, so the abort keeps it.
    let late = Ending {
        late: true,
        ..unkilled
    };
    assert_eq!(
        captured_at(late, AttemptEnding::WatchdogKillFailed).await?,
        ABORTED
    );
    Ok(())
}

#[tokio::test]
async fn a_cgroup_still_busy_after_one_termination_call_aborts_the_capture() -> TestResult {
    // The kill is acknowledged but the tasks linger: the cgroup is observed
    // for one termination call (the 200 ms watchdog clamped to 1 s), no
    // longer, and the capture aborts.
    let lingering = Ending {
        faults: &[Fault::Lingering],
        ..Ending::default()
    };
    let (elapsed, execution) = hung(lingering).await?;
    assert_eq!(execution.ending, AttemptEnding::WatchdogKilled);
    assert_eq!(execution.adapter.output().capture(), ABORTED);
    // D (200 ms) and G (1 s) pass before the kill, then one 1 s call.
    let call = Duration::from_secs(1);
    assert!(elapsed >= Duration::from_millis(200) + ESCALATION_GRACE + call);
    assert!(elapsed < Duration::from_millis(200) + ESCALATION_GRACE + 3 * call);
    Ok(())
}

#[test]
fn reservation_and_channel_refusals_keep_their_launch_failure() {
    use pos_reference::sandbox_provider_protocol::LaunchFailure;
    let cases = [
        (
            ExecuteError::OutputReservation(OutputReservationRefused::AggregateExceeded),
            Some(LaunchFailure::OutputReservationRefused),
        ),
        (
            ExecuteError::OutputReservation(OutputReservationRefused::AdmissionClosed),
            Some(LaunchFailure::AdmissionClosed),
        ),
        (
            ExecuteError::StdioChannel(crate::StdioChannelError::NotNullDevice),
            Some(LaunchFailure::StdioChannelFailed),
        ),
        (
            ExecuteError::Recheck(crate::ImageActivationError::Transport),
            Some(LaunchFailure::PreStartRecheckFailed),
        ),
        (
            ExecuteError::RootIdentity,
            Some(LaunchFailure::PreStartRecheckFailed),
        ),
        (
            ExecuteError::Cgroup(Box::new(
                crate::SystemdTransientUnitTransportError::UnitRef(zbus::Error::IncorrectType),
            )),
            Some(LaunchFailure::UnitRefFailed),
        ),
        (
            ExecuteError::Cgroup(Box::new(
                crate::SystemdTransientUnitTransportError::UnitUnref(zbus::Error::IncorrectType),
            )),
            None,
        ),
        (
            ExecuteError::Cgroup(Box::new(std::io::Error::other("not a transport error"))),
            None,
        ),
        (ExecuteError::OutputAlreadyReserved, None),
        (ExecuteError::HostTimeout, None),
    ];
    for (error, expected) in cases {
        assert_eq!(error.launch_failure(), expected, "{error}");
    }
}

/// ADR-069 R14 §3.4: a creation, transport or resource failure of the Local
/// network, its FD 3 channel or a Replay exchange has a launch failure; a
/// contradiction of the provider's own state falls back to O6.
#[test]
fn network_and_replay_setup_refusals_have_their_launch_failure() {
    use crate::execute::NetworkSetupFailure;
    use crate::{LocalProxyBindError, SetupClass};
    use pos_reference::sandbox_provider_protocol::{LaunchFailure, NetworkCaptureStoreError};

    #[derive(Debug, thiserror::Error)]
    #[error("classified")]
    struct Classified(SetupClass);
    impl crate::SetupError for Classified {
        fn setup_class(&self) -> SetupClass {
            self.0
        }

        fn removal(&self) -> Option<crate::NetworkRemovalFailure> {
            None
        }
    }
    let network = |class| ExecuteError::Network(NetworkSetupFailure::new(Classified(class)));
    let setup = Some(LaunchFailure::NetworkSetupFailed);
    let cases = [
        (network(SetupClass::Creation), setup),
        (network(SetupClass::Contradiction), None),
        (
            ExecuteError::HostService(std::io::Error::other("pair")),
            setup,
        ),
        (ExecuteError::Bind(LocalProxyBindError::Namespace), setup),
        (ExecuteError::Bind(LocalProxyBindError::Channel), setup),
        (ExecuteError::Bind(LocalProxyBindError::Attempt), None),
        (ExecuteError::Bind(LocalProxyBindError::Request), None),
        (ExecuteError::Bind(LocalProxyBindError::Authority), None),
        (ExecuteError::Bind(LocalProxyBindError::LaunchPolicy), None),
        (ExecuteError::Bind(LocalProxyBindError::Capability), None),
        (
            ExecuteError::ReplayUnavailable(NetworkCaptureStoreError::ReplayUnavailable),
            Some(LaunchFailure::ReplayUnavailable),
        ),
    ];
    for (error, expected) in cases {
        assert_eq!(error.launch_failure(), expected, "{error}");
    }
}

#[tokio::test]
async fn an_adapter_that_closes_stdin_leaves_the_feed_incomplete() -> TestResult {
    let script = StdioScript {
        output: stream(),
        input: InputUse::Close,
        ..StdioScript::default()
    };
    let limits = limits(100, 1_000, GENEROUS_WATCHDOG_MS);
    let run = StdioRun::with(script, TestPayload::with_input(INPUT), limits).await?;
    let fed = run
        .execution()?
        .adapter
        .input()
        .ok_or("the feed was not timed")?;
    // EPIPE: nothing was accepted, and the feed stopped well before its deadline.
    assert_eq!((fed.expected_bytes, fed.accepted_bytes), (5, 0));
    assert!(!fed.complete);
    assert!(fed.finish <= fed.deadline);
    Ok(())
}

#[tokio::test]
async fn a_zero_input_window_is_a_literal_zero_window() -> TestResult {
    let script = StdioScript {
        output: stream(),
        ..StdioScript::default()
    };
    let limits = limits(100, 0, GENEROUS_WATCHDOG_MS);
    let run = StdioRun::with(script, TestPayload::with_input(INPUT), limits).await?;
    let fed = run
        .execution()?
        .adapter
        .input()
        .ok_or("the feed was not timed")?;
    // The closed window stops the feed before its first write.
    assert_eq!(fed.deadline, fed.start);
    assert_eq!(fed.accepted_bytes, 0);
    assert!(!fed.complete);
    Ok(())
}

#[tokio::test]
async fn an_input_the_adapter_never_reads_closes_the_feed_at_its_deadline() -> TestResult {
    // More than a pipe holds: the feed blocks until its window closes.
    let script = StdioScript {
        output: stream(),
        input: InputUse::Ignore,
        never_finish: true,
        ..StdioScript::default()
    };
    let input = vec![0x5a; 4 * 1024 * 1024];
    let limits = limits(100, 50, 400);
    let run = StdioRun::with(script, TestPayload::with_input(&input), limits).await?;
    let fed = run
        .execution()?
        .adapter
        .input()
        .ok_or("the feed was not timed")?;
    assert_eq!(fed.expected_bytes, input.len() as u64);
    assert!(fed.accepted_bytes < fed.expected_bytes);
    assert!(fed.finish >= fed.deadline);
    assert!(!fed.complete);
    Ok(())
}

async fn refused(payload: TestPayload) -> TestResult<ExecuteFailure<FakeCgroup, u64, String>> {
    let script = StdioScript::default();
    let limits = limits(100, 1_000, GENEROUS_WATCHDOG_MS);
    let run = StdioRun::with(script, payload, limits).await?;
    // The unit is never started when the reservation is refused (I4).
    assert_eq!(run.scenario.entries(), ["take_unit_end", "recheck"]);
    failure(run.outcome)
}

/// The output reservation is refused after the network was established: the
/// network is removed and a failed removal is reported with the launch
/// failure (3 or 5).
#[tokio::test]
async fn a_failed_removal_is_reported_when_the_output_reservation_is_refused() -> TestResult {
    for removal_fails in [false, true] {
        let full = TestPayload {
            ledger: StagingLedger::new(StagingLimits {
                aggregate_bytes: 99,
            }),
            output: 100,
            ..TestPayload::with_input(INPUT)
        };
        let closed = TestPayload::with_input(INPUT);
        closed.ledger.close_for_reconciliation();
        for payload in [full, closed] {
            let (_, mode) = local_plan(UNUSED_ENDPOINT)?;
            let mut scenario = Scenario::new()?;
            let mut job = scenario.job(
                ATTEMPT,
                SandboxExecutionMode::Local,
                mode,
                GENEROUS_WATCHDOG_MS,
            )?;
            job.attempt = job
                .attempt
                .with_limits(limits(100, 1_000, GENEROUS_WATCHDOG_MS))
                .with_payload(Arc::new(payload));
            let recheck = root_for(&scenario.log, &job.attempt);
            let torn_down = Arc::new(AtomicUsize::new(0));
            let network = TornDownNetwork::new(&torn_down, removal_fails);
            let failed = failure(scenario.run_on(&network, job, recheck).await)?;
            assert!(matches!(failed.error, ExecuteError::OutputReservation(_)));
            assert_eq!(torn_down.load(Ordering::SeqCst), 1);
            assert_eq!(failed.network_removal.is_some(), removal_fails);
        }
    }
    Ok(())
}

#[tokio::test]
async fn a_full_aggregate_ledger_refuses_the_output_and_starts_no_unit() -> TestResult {
    let full = TestPayload {
        ledger: StagingLedger::new(StagingLimits {
            aggregate_bytes: 99,
        }),
        output: 100,
        ..TestPayload::with_input(INPUT)
    };
    let failed = refused(full).await?;
    assert!(matches!(
        failed.error,
        ExecuteError::OutputReservation(OutputReservationRefused::AggregateExceeded)
    ));
    assert_eq!(failed.unit, UnitState::NotStarted);
    Ok(())
}

#[tokio::test]
async fn a_ledger_closed_after_a_cleanup_failure_refuses_the_output() -> TestResult {
    let closed = TestPayload::with_input(INPUT);
    closed.ledger.close_for_reconciliation();
    let failed = refused(closed).await?;
    assert!(matches!(
        failed.error,
        ExecuteError::OutputReservation(OutputReservationRefused::AdmissionClosed)
    ));
    Ok(())
}

#[tokio::test]
async fn an_output_reserved_by_another_execution_is_never_reserved_again() -> TestResult {
    let taken = TestPayload::with_input(INPUT);
    taken.reserved.store(true, Ordering::SeqCst);
    let failed = refused(taken).await?;
    assert!(matches!(failed.error, ExecuteError::OutputAlreadyReserved));
    Ok(())
}

#[tokio::test]
async fn the_output_reservation_is_held_until_the_output_is_released() -> TestResult {
    let payload = Arc::new(TestPayload::with_input(INPUT));
    let ledger = payload.ledger.clone();
    let mut scenario = Scenario::new()?;
    scenario.host.stdio = Some(StdioScript {
        output: stream(),
        ..StdioScript::default()
    });
    let mut job = scenario.job(
        ATTEMPT,
        SandboxExecutionMode::AirGapped,
        ModePlan::AirGapped,
        GENEROUS_WATCHDOG_MS,
    )?;
    job.attempt = job
        .attempt
        .with_limits(limits(100, 1_000, GENEROUS_WATCHDOG_MS))
        .with_payload(payload);
    let recheck = root_for(&scenario.log, &job.attempt);
    let execution = scenario.run_on(&LoopbackNetwork, job, recheck).await?;
    assert_eq!(ledger.usage().reserved_bytes, 1_000);
    let output = execution.adapter.into_output();
    let terminal = crate::TerminalResources::new(
        Err(crate::AttemptCgroupError::WrongFilesystem),
        None,
        Err(crate::TerminalServiceError::Unstarted),
        Ok(()),
    );
    let released = output.release(&terminal);
    assert_eq!(released.bytes(), stream());
    assert_eq!(ledger.usage().reserved_bytes, 1_000);
    drop(released);
    assert_eq!(ledger.usage().reserved_bytes, 0);
    Ok(())
}
