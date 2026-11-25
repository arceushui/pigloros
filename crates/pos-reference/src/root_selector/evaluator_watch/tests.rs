use std::io::Write;
use std::sync::{mpsc, Arc};
use std::time::{Duration, Instant};

use rustix::io::Errno;

use super::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const DIGEST: [u8; 32] = [5; 32];

fn no_wait() -> Timespec {
    Timespec {
        tv_sec: 0,
        tv_nsec: 0,
    }
}

/// A diagnostics sink that discards everything.
fn quiet() -> DiagnosticSink {
    Mutex::new(Box::new(std::io::sink()))
}

/// A diagnostics sink whose lines the test can read back.
#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);

impl Capture {
    fn sink(&self) -> DiagnosticSink {
        Mutex::new(Box::new(self.clone()))
    }

    fn text(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().unwrap_or_else(PoisonError::into_inner)).into_owned()
    }
}

impl Write for Capture {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Wait until a watcher blocks on the grant, so the caller can be sure the
/// watcher reached `wait_for_running_grant` before the execute ends.
fn wait_for_watcher(in_flight: &InFlightAttempt) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while in_flight.waiting() == 0 && Instant::now() < deadline {
        thread::yield_now();
    }
    assert!(in_flight.waiting() > 0, "no watcher arrived");
}

/// Whether `run` finished within ten seconds. A watcher that is never woken
/// would keep it from finishing, so a missing wake fails the test instead of
/// hanging it.
fn finishes(run: impl FnOnce() + Send + 'static) -> bool {
    let (done, finished) = mpsc::channel();
    thread::spawn(move || {
        run();
        done.send(()).ok();
    });
    finished.recv_timeout(Duration::from_secs(10)).is_ok()
}

#[test]
fn a_peer_that_only_shut_down_its_write_side_has_not_hung_up() -> TestResult {
    let (evaluator, peer) = UnixStream::pair()?;
    let (wake, woken) = UnixStream::pair()?;
    peer.shutdown(std::net::Shutdown::Write)?;
    assert_eq!(
        wait_for_hang_up(&evaluator, &woken, Some(&no_wait())),
        Ok(false)
    );
    drop((peer, wake));
    Ok(())
}

#[test]
fn a_peer_that_closed_its_end_has_hung_up() -> TestResult {
    let (evaluator, peer) = UnixStream::pair()?;
    let (wake, woken) = UnixStream::pair()?;
    drop(peer);
    assert_eq!(
        wait_for_hang_up(&evaluator, &woken, Some(&no_wait())),
        Ok(true)
    );
    drop(wake);
    Ok(())
}

/// The ordering invariant of the module: after the peer's half-close, the
/// selector's own write shutdown raises the same hang-up as a close.
#[test]
fn the_selectors_own_write_shutdown_after_a_half_close_looks_like_a_hang_up() -> TestResult {
    let (evaluator, peer) = UnixStream::pair()?;
    let (wake, woken) = UnixStream::pair()?;
    peer.shutdown(std::net::Shutdown::Write)?;
    assert_eq!(
        wait_for_hang_up(&evaluator, &woken, Some(&no_wait())),
        Ok(false)
    );
    evaluator.shutdown(std::net::Shutdown::Write)?;
    assert_eq!(
        wait_for_hang_up(&evaluator, &woken, Some(&no_wait())),
        Ok(true)
    );
    drop((peer, wake));
    Ok(())
}

#[test]
fn the_wake_wins_over_a_hang_up() -> TestResult {
    let (evaluator, peer) = UnixStream::pair()?;
    let (mut wake, woken) = UnixStream::pair()?;
    drop(peer);
    wake.write_all(&[1])?;
    assert_eq!(
        wait_for_hang_up(&evaluator, &woken, Some(&no_wait())),
        Ok(false)
    );
    drop(wake);
    assert_eq!(
        wait_for_hang_up(&evaluator, &woken, Some(&no_wait())),
        Ok(false)
    );
    Ok(())
}

/// A negative timeout is invalid for `ppoll`.
#[cfg(target_os = "linux")]
#[test]
fn a_failed_poll_is_reported_and_cancels_nothing() -> TestResult {
    let (evaluator, peer) = UnixStream::pair()?;
    let (wake, woken) = UnixStream::pair()?;
    let invalid = Timespec {
        tv_sec: -1,
        tv_nsec: 0,
    };
    assert_eq!(
        wait_for_hang_up(&evaluator, &woken, Some(&invalid)),
        Err(Errno::INVAL)
    );
    let capture = Capture::default();
    let mut cancelled = Vec::new();
    watch_evaluator(
        &evaluator,
        &woken,
        Some(&invalid),
        &InFlightAttempt::default(),
        |digest| cancelled.push(digest),
        &capture.sink(),
    );
    assert!(capture.text().contains("evaluator watch failed"));
    assert!(cancelled.is_empty());
    drop((peer, wake));
    Ok(())
}

/// The evaluator end, the watcher's wake end, and the end that stays open:
/// the peer's when the evaluator did not hang up (the wake then ends the
/// watch), the wake's otherwise.
fn streams(
    hung_up: bool,
) -> Result<(UnixStream, UnixStream, UnixStream), Box<dyn std::error::Error>> {
    let (evaluator, peer) = UnixStream::pair()?;
    let (wake, woken) = UnixStream::pair()?;
    let open = if hung_up { wake } else { peer };
    Ok((evaluator, woken, open))
}

/// An attempt that was granted and finished as scripted.
fn attempt(granted: bool, finished: bool) -> InFlightAttempt {
    let in_flight = InFlightAttempt::default();
    if granted {
        in_flight.granted(DIGEST);
    }
    if finished {
        in_flight.finish();
    }
    in_flight
}

/// What `watch_evaluator` cancelled, for a scripted evaluator and attempt.
fn cancelled(
    hung_up: bool,
    granted: bool,
    finished: bool,
) -> Result<Vec<[u8; 32]>, Box<dyn std::error::Error>> {
    let (evaluator, woken, _open) = streams(hung_up)?;
    let in_flight = attempt(granted, finished);
    let mut cancelled = Vec::new();
    watch_evaluator(
        &evaluator,
        &woken,
        None,
        &in_flight,
        |digest| cancelled.push(digest),
        &quiet(),
    );
    Ok(cancelled)
}

#[test]
fn only_a_hung_up_evaluator_with_a_running_granted_attempt_is_cancelled() -> TestResult {
    assert_eq!(cancelled(true, true, false)?, vec![DIGEST]);
    assert!(cancelled(true, true, true)?.is_empty());
    assert!(cancelled(true, false, true)?.is_empty());
    assert!(cancelled(false, true, false)?.is_empty());
    Ok(())
}

#[test]
fn a_hang_up_before_the_grant_cancels_once_the_grant_arrives() -> TestResult {
    let (evaluator, peer) = UnixStream::pair()?;
    let (wake, woken) = UnixStream::pair()?;
    let in_flight = InFlightAttempt::default();
    drop(peer);
    let (sender, receiver) = mpsc::channel();
    thread::scope(|scope| {
        scope.spawn(|| {
            watch_evaluator(
                &evaluator,
                &woken,
                None,
                &in_flight,
                |digest| {
                    sender.send(digest).ok();
                },
                &quiet(),
            );
        });
        wait_for_watcher(&in_flight);
        in_flight.granted(DIGEST);
    });
    assert_eq!(receiver.try_recv()?, DIGEST);
    drop(wake);
    Ok(())
}

#[test]
fn a_finished_execute_ends_a_watch_that_waits_for_a_grant() -> TestResult {
    let (evaluator, peer) = UnixStream::pair()?;
    let (wake, woken) = UnixStream::pair()?;
    let in_flight = InFlightAttempt::default();
    drop(peer);
    let (sender, receiver) = mpsc::channel();
    thread::scope(|scope| {
        scope.spawn(|| {
            watch_evaluator(
                &evaluator,
                &woken,
                None,
                &in_flight,
                |digest| {
                    sender.send(digest).ok();
                },
                &quiet(),
            );
        });
        wait_for_watcher(&in_flight);
        in_flight.finish();
    });
    assert!(receiver.try_recv().is_err());
    drop(wake);
    Ok(())
}

#[test]
fn an_execute_with_a_live_evaluator_returns_its_result_and_is_never_cancelled() -> TestResult {
    let (evaluator, peer) = UnixStream::pair()?;
    let (done, finished) = mpsc::channel();
    // Run apart: without the wake, the watcher would keep waiting on the live
    // evaluator and the call would never return.
    thread::spawn(move || {
        let in_flight = InFlightAttempt::default();
        let cancels = AtomicUsize::new(0);
        let result = execute_watched(
            &evaluator,
            &in_flight,
            |_| {
                cancels.fetch_add(1, Ordering::SeqCst);
            },
            &quiet(),
            || {
                in_flight.granted(DIGEST);
                7
            },
        );
        done.send((result.ok(), cancels.load(Ordering::SeqCst)))
            .ok();
        drop(peer);
    });
    assert_eq!(
        finished.recv_timeout(Duration::from_secs(10)),
        Ok((Some(7), 0))
    );
    Ok(())
}

/// The hazard the module documents: a write shutdown of the selector's own
/// end, after the peer's half-close, while the watcher runs, cancels the
/// attempt. That is why the selector shuts down only after the join.
#[test]
fn a_write_shutdown_of_the_selectors_end_during_the_watch_cancels_the_attempt() -> TestResult {
    let (evaluator, peer) = UnixStream::pair()?;
    let in_flight = InFlightAttempt::default();
    let (sender, receiver) = mpsc::channel();
    let sender = Mutex::new(sender);
    let attempt = &in_flight;
    let watched = &evaluator;
    let cancelled = execute_watched(
        &evaluator,
        &in_flight,
        |digest| {
            sender
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .send(digest)
                .ok();
        },
        &quiet(),
        move || {
            attempt.granted(DIGEST);
            peer.shutdown(std::net::Shutdown::Write).ok();
            watched.shutdown(std::net::Shutdown::Write).ok();
            receiver.recv_timeout(Duration::from_secs(10))
        },
    )?;
    assert_eq!(cancelled, Ok(DIGEST));
    Ok(())
}

#[test]
fn an_evaluator_that_drops_mid_execute_has_its_attempt_cancelled_while_it_runs() -> TestResult {
    let (evaluator, peer) = UnixStream::pair()?;
    let in_flight = InFlightAttempt::default();
    let (sender, receiver) = mpsc::channel();
    let sender = Mutex::new(sender);
    let attempt = &in_flight;
    let cancelled_while_running = execute_watched(
        &evaluator,
        &in_flight,
        |digest| {
            sender
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .send(digest)
                .ok();
        },
        &quiet(),
        move || {
            attempt.granted(DIGEST);
            drop(peer);
            receiver.recv_timeout(Duration::from_secs(10))
        },
    )?;
    assert_eq!(cancelled_while_running, Ok(DIGEST));
    Ok(())
}

#[test]
fn an_execute_that_ends_with_a_hung_up_evaluator_and_no_grant_still_returns() -> TestResult {
    let (evaluator, peer) = UnixStream::pair()?;
    drop(peer);
    assert!(finishes(move || {
        let in_flight = InFlightAttempt::default();
        execute_watched(
            &evaluator,
            &in_flight,
            |_| {},
            &quiet(),
            || {
                // The watcher is blocked on the grant before the execute ends,
                // so only `finish()` can release it.
                wait_for_watcher(&in_flight);
            },
        )
        .ok();
    }));
    Ok(())
}

#[test]
fn an_execute_that_panics_with_a_hung_up_evaluator_still_wakes_the_watcher() -> TestResult {
    let (evaluator, peer) = UnixStream::pair()?;
    drop(peer);
    let (outcome, receiver) = mpsc::channel();
    thread::spawn(move || {
        let in_flight = InFlightAttempt::default();
        let panicked = catch_unwind(AssertUnwindSafe(|| {
            execute_watched(
                &evaluator,
                &in_flight,
                |_| {},
                &quiet(),
                || {
                    wait_for_watcher(&in_flight);
                    resume_unwind(Box::new("the execute failed"))
                },
            )
            .ok();
        }))
        .is_err();
        outcome.send(panicked).ok();
    });
    // The panic reaches the caller; a watcher left waiting would hang it.
    assert_eq!(receiver.recv_timeout(Duration::from_secs(10)), Ok(true));
    Ok(())
}

#[test]
fn a_panicking_cancel_discards_the_execute_result_and_unwinds_the_caller() -> TestResult {
    let (evaluator, peer) = UnixStream::pair()?;
    drop(peer);
    let (outcome, receiver) = mpsc::channel();
    thread::spawn(move || {
        let in_flight = InFlightAttempt::default();
        let (cancelled, cancel_ran) = mpsc::channel();
        let cancelled = Mutex::new(cancelled);
        let returned = catch_unwind(AssertUnwindSafe(|| {
            execute_watched(
                &evaluator,
                &in_flight,
                |_| {
                    cancelled
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .send(())
                        .ok();
                    resume_unwind(Box::new("the cancel failed"))
                },
                &quiet(),
                || {
                    in_flight.granted(DIGEST);
                    cancel_ran.recv_timeout(Duration::from_secs(10)).ok();
                    7
                },
            )
        }));
        // The scope raised the watcher's panic; no result came back.
        outcome.send(returned.is_err()).ok();
    });
    assert_eq!(receiver.recv_timeout(Duration::from_secs(10)), Ok(true));
    Ok(())
}

#[test]
fn each_poll_flag_that_means_the_peer_is_gone_counts_alone_and_combined() {
    let gone = [PollFlags::HUP, PollFlags::ERR, PollFlags::NVAL];
    for flag in gone {
        assert!(is_gone(flag));
        assert!(is_gone(flag | PollFlags::IN));
    }
    assert!(is_gone(PollFlags::HUP | PollFlags::ERR | PollFlags::NVAL));
    assert!(is_gone(PollFlags::ERR | PollFlags::NVAL));
    assert!(!is_gone(PollFlags::empty()));
    assert!(!is_gone(PollFlags::IN));
    assert!(!is_gone(PollFlags::IN | PollFlags::OUT));
}
