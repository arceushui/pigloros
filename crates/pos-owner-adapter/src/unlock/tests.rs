#![cfg(any(test, feature = "test-support"))]
//! The binding mutex: a poisoned mutex refuses without running the update,
//! and a held mutex blocks a second update until it is released.

use std::panic;
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::Mutex;
use std::thread;
use std::time::Duration;

use super::{serialized, DURABLE_WRITE};

/// Long enough for any healthy step, short enough that a broken run ends.
const BOUND: Duration = Duration::from_secs(10);
/// How long the second update is watched for not starting.
const WATCH: Duration = Duration::from_millis(200);

#[test]
fn a_poisoned_binding_mutex_refuses_and_runs_no_update() {
    let mutex = Mutex::new(());
    let poisoned = thread::scope(|scope| {
        scope
            .spawn(|| {
                let held = mutex.lock();
                if held.is_ok() {
                    panic::resume_unwind(Box::new("poison the binding mutex"));
                }
                drop(held);
            })
            .join()
    });
    assert!(poisoned.is_err());
    assert!(mutex.is_poisoned());
    let mut ran = false;
    let outcome = serialized(&mutex, || {
        ran = true;
        Ok(())
    });
    assert_eq!(outcome, Err(DURABLE_WRITE));
    assert!(!ran);
}

#[test]
fn a_held_binding_mutex_blocks_a_second_update_until_it_is_released() {
    let mutex = &Mutex::new(());
    let (entered, first_entered) = mpsc::sync_channel(1);
    let (release, released) = mpsc::sync_channel(1);
    let (second, second_ran) = mpsc::sync_channel(1);
    thread::scope(|scope| {
        let first = scope.spawn(move || {
            serialized(mutex, || {
                assert!(entered.send(()).is_ok());
                // Bounded: the update ends even if the release never comes.
                assert_eq!(released.recv_timeout(BOUND), Ok(()));
                Ok(())
            })
        });
        assert_eq!(first_entered.recv_timeout(BOUND), Ok(()));
        let blocked = scope.spawn(move || {
            serialized(mutex, || {
                assert!(second.send(()).is_ok());
                Ok(())
            })
        });
        // While the first update holds the mutex, the second cannot start.
        assert_eq!(
            second_ran.recv_timeout(WATCH),
            Err(RecvTimeoutError::Timeout)
        );
        assert!(release.send(()).is_ok());
        assert_eq!(second_ran.recv_timeout(BOUND), Ok(()));
        assert_eq!(first.join().ok(), Some(Ok(())));
        assert_eq!(blocked.join().ok(), Some(Ok(())));
    });
}
