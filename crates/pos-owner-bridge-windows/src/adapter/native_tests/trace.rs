#![cfg(windows)]
#![forbid(unsafe_code)]

use std::io::Write as _;
use std::process::Command;
use std::time::{Duration, Instant};

use pos_owner_bridge::ceremony::driver::CeremonyDriver;
use pos_owner_bridge::{BridgeError, LoopbackPort as _};

use crate::adapter::loopback::SharedLoopback;
use crate::adapter::surface::Surface;

pub(super) fn worker_stage(worker: usize, stage: &str) {
    let _logged_or_unavailable = writeln!(
        std::io::stderr(),
        "NATIVE_WORKER_RETIRE worker={worker} stage={stage}",
    );
}

/// One flushed line per window lifecycle or readiness setup phase. A native
/// call that never returns is then named by the last marker printed before it.
pub(super) fn lifecycle_stage(stage: &str) {
    let mut stderr = std::io::stderr().lock();
    let _logged_or_unavailable = writeln!(stderr, "NATIVE_LIFECYCLE stage={stage}");
    let _flushed_or_unavailable = stderr.flush();
}

pub(super) struct Trace {
    case: u64,
    started: Instant,
    reported: Instant,
    previous: String,
}

impl Trace {
    pub(super) fn new(case: u64, started: Instant) -> Self {
        Self {
            case,
            started,
            reported: started,
            previous: String::new(),
        }
    }

    pub(super) fn update(
        &mut self,
        stage: &str,
        surface: &Surface,
        driver: &CeremonyDriver,
        loopback: &SharedLoopback,
    ) {
        let served = loopback.served();
        let progress = format!(
            "stage={stage} posts={} request_clear={} receipt={:?} reads={:?} served={} integrity={} {}",
            driver.posts(),
            driver.request_clear(),
            driver
                .first_receipt_at()
                .map(|at| at.saturating_duration_since(self.started)),
            loopback.received_request_count(),
            served.count,
            served.integrity_ok,
            surface.fixture_progress(),
        );
        self.report(progress, Some(loopback));
    }

    pub(super) fn queued(&mut self, surface: &Surface) {
        self.report(
            format!("stage=before-plan {}", surface.fixture_progress()),
            None,
        );
    }

    fn report(&mut self, progress: String, loopback: Option<&SharedLoopback>) {
        let now = Instant::now();
        if progress != self.previous || now.duration_since(self.reported) >= Duration::from_secs(5)
        {
            let _logged_or_unavailable = writeln!(
                std::io::stderr(),
                "NATIVE_PROGRESS case={} elapsed={:?} {progress} listener={:?}",
                self.case,
                now.duration_since(self.started),
                loopback.map(SharedLoopback::observation),
            );
            self.previous = progress;
            self.reported = now;
        }
    }
}

/// Read-only snapshot of live WebView2 processes (roles only, no user paths)
/// and top CPU consumers, emitted only on a cleanup or retirement stall (#1468).
const STALL_PROCESS_SNAPSHOT_SCRIPT: &str = concat!(
    "$ErrorActionPreference = 'SilentlyContinue'; ",
    "$wv = @(Get-CimInstance Win32_Process -Filter \"Name='msedgewebview2.exe'\" ",
    "| Sort-Object ProcessId | ForEach-Object { ",
    "$cmd = [string]$_.CommandLine; ",
    "$role = if ($cmd -match '--type=([A-Za-z0-9_-]+)') { $Matches[1] } else { 'browser' }; ",
    "if ($cmd -match '--utility-sub-type=([A-Za-z0-9_.-]+)') { $role = \"$role/$($Matches[1])\" }; ",
    "\"$($_.ProcessId)(ppid=$($_.ParentProcessId),role=$role,threads=$($_.ThreadCount))\" ",
    "}); ",
    "$top = @(Get-Process | Sort-Object CPU -Descending | Select-Object -First 8 | ForEach-Object { ",
    "$cpu = if ($null -ne $_.CPU) { [math]::Round($_.CPU, 1) } else { 0 }; ",
    "\"$($_.ProcessName):$($_.Id)(cpu=${cpu}s,threads=$($_.Threads.Count))\" ",
    "}); ",
    "Write-Output (\"webview2=[$($wv -join ', ')] top_cpu=[$($top -join ', ')]\")",
);

fn parse_progress_pid(progress: &str) -> Option<u32> {
    progress
        .split_once("pid=Some(")
        .and_then(|(_, rest)| rest.split_once(')'))
        .and_then(|(digits, _)| digits.parse().ok())
}

fn run_snapshot_command(program: &str, args: &[&str]) -> String {
    match Command::new(program).args(args).output() {
        Ok(output) if output.status.success() => {
            let text = String::from_utf8_lossy(&output.stdout);
            let trimmed = text.trim();
            if trimmed.is_empty() {
                "empty".to_owned()
            } else {
                trimmed.to_owned()
            }
        }
        Ok(output) => format!("exit={:?}", output.status.code()),
        Err(error) => format!("unavailable({:?})", error.kind()),
    }
}

/// Emit one bounded read-only process snapshot while a stalled browser is still owned.
pub(super) fn report_stalled_processes(context: &str, pid: Option<u32>) {
    let browser = pid.map(|id| (id, crate::Native::inspect_process_with_image(id)));
    let snapshot = run_snapshot_command(
        "pwsh",
        &[
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            STALL_PROCESS_SNAPSHOT_SCRIPT,
        ],
    );
    let mut stderr = std::io::stderr().lock();
    let _logged_or_unavailable = writeln!(
        stderr,
        "NATIVE_STALL_PROCESSES context={context} browser={browser:?} {snapshot}",
    );
    let _flushed_or_unavailable = stderr.flush();
}

/// Emit the process snapshot only when a readiness case ended in quarantine.
pub(super) fn report_if_quarantined(result_error: Option<BridgeError>, case: u64, progress: &str) {
    if matches!(result_error, Some(BridgeError::Quarantine(_))) {
        let context = format!("readiness-case-{case}");
        report_stalled_processes(&context, parse_progress_pid(progress));
    }
}

#[cfg(test)]
mod tests {
    use pos_owner_bridge::{BridgeError, LifecycleCode, QuarantineCode};

    use super::{
        parse_progress_pid, report_if_quarantined, run_snapshot_command,
        STALL_PROCESS_SNAPSHOT_SCRIPT,
    };

    #[test]
    fn parse_progress_pid_reads_valid_pid_and_rejects_absent_or_malformed() {
        assert_eq!(
            parse_progress_pid("ownership=ControllerClosed pid=Some(3392) exited=None"),
            Some(3392)
        );
        assert_eq!(parse_progress_pid("ownership=Idle pid=None"), None);
        assert_eq!(parse_progress_pid("pid=Some(abc) exited=None"), None);
        assert_eq!(parse_progress_pid("pid=Some(42"), None);
    }

    #[test]
    fn run_snapshot_command_reports_live_empty_nonzero_and_missing() {
        let live = run_snapshot_command(
            "pwsh",
            &[
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                STALL_PROCESS_SNAPSHOT_SCRIPT,
            ],
        );
        assert!(live.contains("webview2=["), "unexpected snapshot: {live}");
        assert!(live.contains("top_cpu=["), "unexpected snapshot: {live}");

        let empty = run_snapshot_command(
            "pwsh",
            &["-NoLogo", "-NoProfile", "-NonInteractive", "-Command", ""],
        );
        assert_eq!(empty, "empty");

        let failed = run_snapshot_command(
            "pwsh",
            &[
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "exit 1",
            ],
        );
        assert_eq!(failed, "exit=Some(1)");

        let missing = run_snapshot_command("pigloros-nonexistent-stall-snapshot", &[]);
        assert!(
            missing.starts_with("unavailable("),
            "unexpected missing result: {missing}"
        );
    }

    #[test]
    fn report_if_quarantined_exercises_non_quarantine_and_quarantine_paths() {
        report_if_quarantined(None, 1, "pid=None");
        report_if_quarantined(
            Some(BridgeError::Lifecycle(LifecycleCode::ControllerLost)),
            2,
            "pid=Some(42)",
        );
        report_if_quarantined(
            Some(BridgeError::Quarantine(QuarantineCode::CleanupTimeout)),
            3,
            "pid=Some(42) exited=None",
        );
        report_if_quarantined(
            Some(BridgeError::Quarantine(QuarantineCode::CleanupTimeout)),
            4,
            "pid=None",
        );
    }
}
