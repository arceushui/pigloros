#![cfg(windows)]
#![forbid(unsafe_code)]

use std::io::{Read as _, Write as _};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

use pos_owner_bridge::ceremony::driver::CeremonyDriver;
use pos_owner_bridge::{BridgeError, LoopbackPort as _};

use crate::adapter::loopback::SharedLoopback;
use crate::adapter::surface::Surface;

fn emit_stderr_line(line: &str) {
    let mut stderr = std::io::stderr().lock();
    let _logged_or_unavailable = writeln!(stderr, "{line}");
    let _flushed_or_unavailable = stderr.flush();
}

pub(super) fn worker_stage(worker: usize, stage: &str) {
    let _logged_or_unavailable = writeln!(
        std::io::stderr(),
        "NATIVE_WORKER_RETIRE worker={worker} stage={stage}",
    );
}

/// One flushed line per window lifecycle or readiness setup phase. A native
/// call that never returns is then named by the last marker printed before it.
pub(super) fn lifecycle_stage(stage: &str) {
    emit_stderr_line(&format!("NATIVE_LIFECYCLE stage={stage}"));
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

    pub(super) fn report_if_quarantined(&self, result_error: Option<BridgeError>) {
        report_if_quarantined(result_error, self.case, &self.previous);
    }
}

/// Upper bound for the read-only stall snapshot command so a wedged host or
/// WMI service cannot delay retirement abort or block sibling workers (#1468).
const STALL_SNAPSHOT_TIMEOUT: Duration = Duration::from_secs(10);

/// Read-only snapshot of live `WebView2` processes (roles only, no user paths)
/// and top CPU consumers, emitted only on a cleanup or retirement stall (#1468).
/// Capping the listed `WebView2` entries to 32 keeps stdout strictly below the
/// 4 KiB Windows pipe buffer even during a process-leak storm.
const STALL_PROCESS_SNAPSHOT_SCRIPT: &str = concat!(
    "$ErrorActionPreference = 'SilentlyContinue'; ",
    "$wvCount = 'err'; ",
    "$wv = try { ",
    "$wvAll = @(Get-CimInstance Win32_Process -Filter \"Name='msedgewebview2.exe'\" ",
    "-ErrorAction Stop | Sort-Object ProcessId); ",
    "$wvCount = $wvAll.Count; ",
    "@($wvAll | Select-Object -First 32 | ForEach-Object { ",
    "$cmd = [string]$_.CommandLine; ",
    "$role = if ([string]::IsNullOrWhiteSpace($cmd)) { 'unknown' } ",
    "elseif ($cmd -match '--type=([A-Za-z0-9_-]+)') { $Matches[1] } else { 'browser' }; ",
    "if ($cmd -match '--utility-sub-type=([A-Za-z0-9_.-]+)') { $role = \"$role/$($Matches[1])\" }; ",
    "\"$($_.ProcessId)(ppid=$($_.ParentProcessId),role=$role,threads=$($_.ThreadCount))\" ",
    "}) } catch { @('cim-error') }; ",
    "$top = @(Get-Process | Sort-Object CPU -Descending ",
    "| Select-Object -First 8 | ForEach-Object { ",
    "$name = [string]$_.ProcessName; ",
    "if ($name -notmatch '^[A-Za-z0-9_.-]{1,80}$') { $name = 'unknown' }; ",
    "$cpu = if ($null -ne $_.CPU) { [math]::Round($_.CPU, 1) } else { 0 }; ",
    "$threads = if ($null -ne $_.Threads) { $_.Threads.Count } else { 'unknown' }; ",
    "\"${name}:$($_.Id)(cpu=${cpu}s,threads=$threads)\" ",
    "}); ",
    "Write-Output (\"webview2_count=$wvCount ",
    "webview2=[$($wv -join ', ')] top_cpu=[$($top -join ', ')]\")",
);

fn parse_progress_pid(progress: &str) -> Option<u32> {
    progress
        .split_once("pid=Some(")
        .and_then(|(_, rest)| rest.split_once(')'))
        .and_then(|(digits, _)| digits.parse().ok())
}

fn format_snapshot_output(bytes: &[u8]) -> String {
    let text = String::from_utf8_lossy(bytes);
    let trimmed = text.trim();
    if trimmed.is_empty() {
        "empty".to_owned()
    } else {
        trimmed.to_owned()
    }
}

fn wait_bounded(child: &mut Child, timeout: Duration) -> Option<ExitStatus> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Ok(Some(status)) = child.try_wait() {
            return Some(status);
        }
        if Instant::now() >= deadline {
            let _killed_or_exited = child.kill();
            let _reaped_or_failed = child.wait();
            return None;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn run_snapshot_command(program: &str, args: &[&str], timeout: Duration) -> String {
    let mut command = Command::new(program);
    command
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    match command.spawn() {
        Ok(mut child) => match wait_bounded(&mut child, timeout) {
            Some(status) if status.success() => {
                let mut bytes = Vec::new();
                let stdout = child.stdout.take();
                let _read_or_failed = stdout.map(|mut pipe| pipe.read_to_end(&mut bytes));
                format_snapshot_output(&bytes)
            }
            Some(status) => format!("exit={:?}", status.code()),
            None => "timeout".to_owned(),
        },
        Err(error) => format!("unavailable({:?})", error.kind()),
    }
}

fn live_process_snapshot() -> String {
    run_snapshot_command(
        "pwsh",
        &[
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            STALL_PROCESS_SNAPSHOT_SCRIPT,
        ],
        STALL_SNAPSHOT_TIMEOUT,
    )
}

fn format_process_snapshot(
    tag: &str,
    context: &str,
    pid: Option<u32>,
    snapshot: impl FnOnce() -> String,
) -> String {
    let browser = pid.map(|id| (id, crate::Native::inspect_process(id)));
    let snapshot = snapshot();
    format!("{tag} context={context} browser={browser:?} {snapshot}")
}

/// Emit one bounded read-only process snapshot while a stalled browser is still owned.
/// Runs the snapshot command before locking stderr so sibling workers are never blocked.
pub(super) fn report_process_snapshot(tag: &str, context: &str) {
    let line = format_process_snapshot(tag, context, None, live_process_snapshot);
    emit_stderr_line(&line);
}

fn format_if_quarantined(
    result_error: Option<BridgeError>,
    case: u64,
    progress: &str,
    snapshot: impl FnOnce() -> String,
) -> Option<String> {
    matches!(result_error, Some(BridgeError::Quarantine(_))).then(|| {
        let context = format!("readiness-case-{case}");
        format_process_snapshot(
            "NATIVE_STALL_PROCESSES",
            &context,
            parse_progress_pid(progress),
            snapshot,
        )
    })
}

fn report_if_quarantined_with(
    result_error: Option<BridgeError>,
    case: u64,
    progress: &str,
    snapshot: impl FnOnce() -> String,
    emit: impl FnOnce(&str),
) {
    if let Some(line) = format_if_quarantined(result_error, case, progress, snapshot) {
        emit(&line);
    }
}

/// Emit the process snapshot only when a readiness case ended in quarantine.
fn report_if_quarantined(result_error: Option<BridgeError>, case: u64, progress: &str) {
    report_if_quarantined_with(
        result_error,
        case,
        progress,
        live_process_snapshot,
        emit_stderr_line,
    );
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use pos_owner_bridge::{LifecycleCode, QuarantineCode};

    use super::*;

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
    fn run_snapshot_command_reports_live_empty_nonzero_timeout_and_missing() {
        let _port = crate::Native::fixed_port_fixture();
        let live = live_process_snapshot();
        assert!(live.contains("webview2_count="));
        assert!(live.contains("webview2=["));
        assert!(live.contains("top_cpu=["));

        let empty = run_snapshot_command(
            "pwsh",
            &["-NoLogo", "-NoProfile", "-NonInteractive", "-Command", ""],
            STALL_SNAPSHOT_TIMEOUT,
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
            STALL_SNAPSHOT_TIMEOUT,
        );
        assert_eq!(failed, "exit=Some(1)");

        let timed_out = run_snapshot_command(
            "pwsh",
            &[
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "Start-Sleep -Seconds 10",
            ],
            Duration::from_millis(50),
        );
        assert_eq!(timed_out, "timeout");

        let missing = run_snapshot_command(
            "pigloros-nonexistent-stall-snapshot",
            &[],
            STALL_SNAPSHOT_TIMEOUT,
        );
        assert!(missing.starts_with("unavailable("));

        report_process_snapshot("NATIVE_STALL_MODEL", "qualified=false");
    }

    #[test]
    fn report_if_quarantined_emits_only_on_quarantine_and_redacts_paths() {
        let snapshot_calls = Cell::new(0_u8);
        let mut snapshot = || {
            snapshot_calls.set(snapshot_calls.get() + 1);
            "stub-snapshot".to_owned()
        };
        let mut emitted = Vec::new();
        let mut emit = |line: &str| emitted.push(line.to_owned());

        report_if_quarantined_with(None, 1, "pid=None", &mut snapshot, &mut emit);
        report_if_quarantined_with(
            Some(BridgeError::Lifecycle(LifecycleCode::ControllerLost)),
            2,
            "pid=Some(42)",
            &mut snapshot,
            &mut emit,
        );
        assert_eq!(snapshot_calls.get(), 0);
        assert!(emitted.is_empty());

        let current_pid = std::process::id();
        let with_pid = format!("pid=Some({current_pid}) exited=None");
        report_if_quarantined_with(
            Some(BridgeError::Quarantine(QuarantineCode::CleanupTimeout)),
            3,
            &with_pid,
            &mut snapshot,
            &mut emit,
        );
        assert_eq!(snapshot_calls.get(), 1);
        assert_eq!(emitted.len(), 1);
        let expected_browser = format!("browser=Some(({current_pid}, Ok(Some(");
        assert!(emitted[0].contains("NATIVE_STALL_PROCESSES context=readiness-case-3 "));
        assert!(emitted[0].contains(&expected_browser));
        assert!(emitted[0].contains("stub-snapshot"));
        assert!(!emitted[0].contains('\\'));

        emitted.clear();
        report_if_quarantined_with(
            Some(BridgeError::Quarantine(QuarantineCode::CleanupTimeout)),
            4,
            "pid=None",
            &mut snapshot,
            &mut emit,
        );
        assert_eq!(snapshot_calls.get(), 2);
        let expected_no_pid =
            "NATIVE_STALL_PROCESSES context=readiness-case-4 browser=None stub-snapshot";
        assert_eq!(emitted, [expected_no_pid]);

        Trace::new(5, Instant::now()).report_if_quarantined(None);
    }
}
