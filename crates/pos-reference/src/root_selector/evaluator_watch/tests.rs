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

#[test]
fn a_peer_that_only_shut_down_its_write_side_has_not_hung_up() -> TestResult {
    let (evaluator, peer) = UnixStream::pair()?;
    let (wake, woken) = UnixStream::pair()?;
    peer.shutdown(std::net::Shutdown::Write)?;
    assert!(!wait_for_hang_up(&evaluator, &woken, Some(&no_wait())));
    drop((peer, wake));
    Ok(())
}

#[test]
fn a_peer_that_closed_its_end_has_hung_up() -> TestResult {
    let (evaluator, peer) = UnixStream::pair()?;
    let (wake, woken) = UnixStream::pair()?;
    drop(peer);
    assert!(wait_for_hang_up(&evaluator, &woken, Some(&no_wait())));
    drop(wake);
    Ok(())
}

#[test]
fn the_wake_wins_over_a_hang_up() -> TestResult {
    let (evaluator, peer) = UnixStream::pair()?;
    let (mut wake, woken) = UnixStream::pair()?;
    drop(peer);
    wake.write_all(&[1])?;
    assert!(!wait_for_hang_up(&evaluator, &woken, Some(&no_wait())));
    drop(wake);
    assert!(!wait_for_hang_up(&evaluator, &woken, Some(&no_wait())));
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
    watch_evaluator(&evaluator, &woken, &in_flight, |digest| {
        cancelled.push(digest);
    });
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
            watch_evaluator(&evaluator, &woken, &in_flight, |digest| {
                sender.send(digest).ok();
            });
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
            watch_evaluator(&evaluator, &woken, &in_flight, |digest| {
                sender.send(digest).ok();
            });
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
        || {
            in_flight.granted(DIGEST);
            7
        },
    )?;
    assert_eq!(result, 7);
    assert!(receiver.try_recv().is_err());
    drop(peer);
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
        move || {
            attempt.granted(DIGEST);
            drop(peer);
            receiver.recv_timeout(Duration::from_secs(10))
        },
    )?;
    assert_eq!(cancelled_while_running, Ok(DIGEST));
    Ok(())
}
