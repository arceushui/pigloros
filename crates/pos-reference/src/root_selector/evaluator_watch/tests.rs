use std::io::Write;
use std::sync::mpsc;
use std::time::Duration;

use super::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const DIGEST: [u8; 32] = [5; 32];

fn no_wait() -> Timespec {
    Timespec {
        tv_sec: 0,
        tv_nsec: 0,
    }
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
    let mut reported = Vec::new();
    let mut cancelled = Vec::new();
    watch_evaluator(
        &evaluator,
        &woken,
        Some(&invalid),
        &InFlightAttempt::default(),
        |digest| cancelled.push(digest),
        |errno| reported.push(errno),
    );
    assert_eq!(reported, [Errno::INVAL]);
    assert!(cancelled.is_empty());
    drop((peer, wake));
    Ok(())
}

/// What `watch_evaluator` cancelled, for a scripted evaluator and attempt.
fn cancelled(
    hung_up: bool,
    granted: bool,
    finished: bool,
) -> Result<Vec<[u8; 32]>, Box<dyn std::error::Error>> {
    let (evaluator, peer) = UnixStream::pair()?;
    let (wake, woken) = UnixStream::pair()?;
    let in_flight = InFlightAttempt::default();
    if hung_up {
        drop(peer);
    }
    if granted {
        in_flight.granted(DIGEST);
    }
    if finished {
        in_flight.finish();
    }
    // Without a hang-up, the wake ends the watch.
    if !hung_up {
        drop(wake);
    }
    let mut cancelled = Vec::new();
    watch_evaluator(
        &evaluator,
        &woken,
        None,
        &in_flight,
        |digest| cancelled.push(digest),
        |_| {},
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
                |_| {},
            );
        });
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
                |_| {},
            );
        });
        in_flight.finish();
    });
    assert!(receiver.try_recv().is_err());
    drop(wake);
    Ok(())
}

#[test]
fn an_execute_with_a_live_evaluator_is_never_cancelled() -> TestResult {
    let (evaluator, peer) = UnixStream::pair()?;
    let in_flight = InFlightAttempt::default();
    let (sender, receiver) = mpsc::channel();
    let result = execute_watched(
        &evaluator,
        &in_flight,
        |digest| {
            sender.send(digest).ok();
        },
        |_| {},
        || {
            in_flight.granted(DIGEST);
            7
        },
    )?;
    assert_eq!(result, 7);
    assert!(receiver.try_recv().is_err());
    // The watcher was joined: a later write shutdown cancels nothing.
    peer.shutdown(std::net::Shutdown::Write)?;
    evaluator.shutdown(std::net::Shutdown::Write)?;
    assert!(receiver.try_recv().is_err());
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
        |_| {},
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
        execute_watched(&evaluator, &in_flight, |_| {}, |_| {}, || ()).ok();
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
                |_| {},
                || resume_unwind(Box::new("the execute failed")),
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
