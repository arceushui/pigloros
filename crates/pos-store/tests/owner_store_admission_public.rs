//! Public controller conformance; no owner-read adapter or `SQLite` qualification.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{mpsc, Arc};
use std::time::Duration;

use pos_crypto::subject_field_read::SubjectFieldOwnerReadErrorV1 as Refusal;
use pos_store::owner_store_admission::{OwnerStoreAdmissionV1, OwnerStoreOperationV1};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn enter(admission: &OwnerStoreAdmissionV1) -> OwnerStoreOperationV1<'_> {
    match admission.try_enter() {
        Ok(operation) => operation,
        Err(error) => std::panic::resume_unwind(Box::new(error)),
    }
}

// Both facades deliberately use the same public admission seam before the
// simulated lower effect. This is not an implementation of the field-read port.
struct View {
    admission: Arc<OwnerStoreAdmissionV1>,
    effects: Arc<AtomicUsize>,
}

impl View {
    fn run(&self, callback: impl FnOnce()) -> Result<(), Refusal> {
        self.admission.try_enter().map(|operation| {
            self.effects.fetch_add(1, Ordering::Relaxed);
            callback();
            operation.complete_cleanly();
        })
    }
}

#[test]
fn clean_completion_allows_reuse_without_blocking_an_unrelated_context() {
    let admission = OwnerStoreAdmissionV1::new();
    let unrelated = OwnerStoreAdmissionV1::default();
    let operation = enter(&admission);
    assert_eq!(admission.try_enter().err(), Some(Refusal::OperationActive));
    enter(&unrelated).complete_cleanly();
    operation.complete_cleanly();
    enter(&admission).complete_cleanly();
    enter(&admission).complete_cleanly();
}

#[test]
fn ordinary_and_callback_aliases_refuse_reentry_before_lower_effects() {
    let admission = Arc::new(OwnerStoreAdmissionV1::new());
    let effects = Arc::new(AtomicUsize::new(0));
    let owner = View {
        admission: Arc::clone(&admission),
        effects: Arc::clone(&effects),
    };
    let ordinary = View { admission, effects };
    assert_eq!(
        owner.run(|| {
            assert_eq!(ordinary.run(|| {}), Err(Refusal::OperationActive));
            assert_eq!(owner.run(|| {}), Err(Refusal::OperationActive));
            assert_eq!(owner.effects.load(Ordering::Relaxed), 1);
        }),
        Ok(())
    );
    assert_eq!(ordinary.run(|| {}), Ok(()));
    assert_eq!(owner.effects.load(Ordering::Relaxed), 2);
}

#[test]
fn explicit_drop_quarantines_before_the_caller_releases_lower_resources() {
    let admission = Arc::new(OwnerStoreAdmissionV1::new());
    let effects = Arc::new(AtomicUsize::new(0));
    let operation = enter(&admission);
    let lower_resource = std::sync::Mutex::new(());
    let lower_guard = lower_resource.lock().map_err(|_| "unexpected poison");
    assert!(lower_guard.is_ok());
    drop(operation);
    let alias = View { admission, effects };
    assert_eq!(alias.run(|| {}), Err(Refusal::ContextQuarantined));
    assert_eq!(alias.effects.load(Ordering::Relaxed), 0);
    drop(lower_guard);
    assert_eq!(alias.run(|| {}), Err(Refusal::ContextQuarantined));
}

#[test]
fn unwind_preserves_the_original_panic_and_quarantines() {
    let admission = OwnerStoreAdmissionV1::new();
    let result = std::panic::catch_unwind(|| {
        let _operation = enter(&admission);
        std::panic::resume_unwind(Box::new("original owner callback panic"));
    });
    let Err(payload) = result else {
        std::panic::resume_unwind(Box::new("expected unwind"));
    };
    assert_eq!(
        payload.downcast_ref::<&str>(),
        Some(&"original owner callback panic")
    );
    assert_eq!(
        admission.try_enter().err(),
        Some(Refusal::ContextQuarantined)
    );
}

#[test]
fn cross_thread_contention_never_runs_lower_work_or_resets_the_active_owner() -> TestResult {
    let admission = Arc::new(OwnerStoreAdmissionV1::new());
    let worker_admission = Arc::clone(&admission);
    let (entered_tx, entered_rx) = mpsc::sync_channel(1);
    let (finish_tx, finish_rx) = mpsc::sync_channel(1);
    let worker = std::thread::spawn(move || -> Result<(), String> {
        let operation = worker_admission
            .try_enter()
            .map_err(|error| format!("unexpected admission refusal: {error:?}"))?;
        entered_tx.send(()).map_err(|error| error.to_string())?;
        finish_rx
            .recv_timeout(Duration::from_secs(10))
            .map_err(|error| error.to_string())?;
        operation.complete_cleanly();
        Ok(())
    });
    entered_rx.recv_timeout(Duration::from_secs(10))?;
    let view = View {
        admission: Arc::clone(&admission),
        effects: Arc::new(AtomicUsize::new(0)),
    };
    assert_eq!(view.run(|| {}), Err(Refusal::OperationActive));
    assert_eq!(view.run(|| {}), Err(Refusal::OperationActive));
    assert_eq!(view.effects.load(Ordering::Relaxed), 0);
    finish_tx.send(())?;
    worker.join().map_err(|_| "admission worker panicked")??;
    assert_eq!(view.run(|| {}), Ok(()));
    assert_eq!(view.effects.load(Ordering::Relaxed), 1);
    Ok(())
}
