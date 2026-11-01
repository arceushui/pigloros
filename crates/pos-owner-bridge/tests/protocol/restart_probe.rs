//! Public restart-cleanup uncertainty and collection ownership contracts (ADR-125).

use std::cell::RefCell;
use std::rc::Rc;
use std::time::Duration;

use pos_owner_bridge::fake::clock::FakeRandom;
use pos_owner_bridge::fake::host::{FakeProbe, FakeStore};
use pos_owner_bridge::{
    folder_name, BridgeError, BridgeStatus, CleanupError, CleanupStore, MonotonicClock,
    ProbeResult, ProcessProbe, QuarantineCode, RestartProgress, UnavailableCode,
};
use pos_owner_bridge_codec::{encode_cleanup_record, CeremonyId, CleanupRecordV1, ImagePathSha256};

use super::{context, honest, unlock_binding, Boxed, FakeEnrollment, FakeUnlock, Rig, TestResult};

const CREATED: u64 = 133_000_000_000_000_000;
const IMAGE: ImagePathSha256 = ImagePathSha256::from_bytes([7; 32]);
const UNAVAILABLE: BridgeError = BridgeError::Unavailable(UnavailableCode::InterfaceUnavailable);
const STALE: BridgeError = BridgeError::Quarantine(QuarantineCode::StaleProcessPresent);

#[derive(Clone, Debug, Eq, PartialEq)]
enum Operation {
    Records,
    Folders,
    Probe(u32, u64, ImagePathSha256),
    Remove(String),
    Delete(Vec<u8>),
}

type Log = Rc<RefCell<Vec<Operation>>>;

// Observe only public port calls; store semantics and probe scripts use the normal fakes.
struct ObservedStore {
    inner: FakeStore,
    log: Log,
}

impl CleanupStore for ObservedStore {
    fn write_record(&mut self, record: &[u8]) -> Result<(), CleanupError> {
        self.inner.write_record(record)
    }

    fn delete_record(&mut self, record: &[u8]) -> Result<(), CleanupError> {
        self.log
            .borrow_mut()
            .push(Operation::Delete(record.to_vec()));
        self.inner.delete_record(record)
    }

    fn records(&mut self) -> Result<Vec<Vec<u8>>, CleanupError> {
        self.log.borrow_mut().push(Operation::Records);
        self.inner.records()
    }

    fn folders(&mut self) -> Result<Vec<String>, CleanupError> {
        self.log.borrow_mut().push(Operation::Folders);
        self.inner.folders()
    }

    fn remove_folder(&mut self, name: &str) -> Result<(), CleanupError> {
        self.log
            .borrow_mut()
            .push(Operation::Remove(name.to_owned()));
        self.inner.remove_folder(name)
    }
}

struct ObservedProbe {
    inner: FakeProbe,
    log: Log,
}

impl ProcessProbe for ObservedProbe {
    fn probe(&mut self, pid: u32, created: u64, image: &ImagePathSha256) -> ProbeResult {
        self.log
            .borrow_mut()
            .push(Operation::Probe(pid, created, *image));
        self.inner.probe(pid, created, image)
    }
}

fn record(id: u8, pid: u32) -> Result<(Vec<u8>, String), Box<dyn std::error::Error>> {
    let id = CeremonyId::from_bytes([id; 16]);
    let folder = folder_name(&id);
    let record = CleanupRecordV1::new(id, &folder, pid, CREATED, IMAGE).boxed()?;
    let mut bytes = vec![0; 4_096];
    let length = encode_cleanup_record(&record, &mut bytes).boxed()?;
    bytes.truncate(length);
    Ok((bytes, folder))
}

fn observed(rig: &Rig, script: Vec<ProbeResult>) -> (ObservedStore, ObservedProbe, Log) {
    let log = Log::default();
    (
        ObservedStore {
            inner: rig.store.clone(),
            log: log.clone(),
        },
        ObservedProbe {
            inner: FakeProbe::new(script),
            log: log.clone(),
        },
        log,
    )
}

fn assert_admission_refused(rig: &mut Rig, error: BridgeError) -> TestResult {
    let mut enrollment = FakeEnrollment::new();
    assert_eq!(rig.bridge.enroll(&context(), &mut enrollment), Err(error));
    assert!(enrollment.calls.is_empty());
    let mut unlock = FakeUnlock::new();
    assert_eq!(
        rig.bridge
            .unlock(&unlock_binding("owner", 0)?, &[0x60; 32], &mut unlock),
        Err(error)
    );
    assert!(unlock.calls.is_empty());
    assert_eq!(rig.steps.get(), 0);
    assert!(rig.t0s.borrow().is_empty());
    Ok(())
}

#[test]
fn an_indeterminate_first_probe_retains_data_and_latches_until_a_fresh_absence_check() -> TestResult
{
    let mut rig = Rig::new(honest(0), FakeRandom::seeded(3))?;
    let (bytes, folder) = record(1, 101)?;
    let (mut store, mut probe, log) = observed(&rig, vec![ProbeResult::Indeterminate]);
    store.write_record(&bytes)?;
    rig.store.preload_folder(&folder);

    assert_eq!(
        rig.bridge.start_restart_check(&mut store, &mut probe),
        Err(UNAVAILABLE)
    );
    assert_eq!(
        rig.bridge.status(),
        BridgeStatus::Unavailable(UnavailableCode::InterfaceUnavailable)
    );
    assert_eq!(
        *log.borrow(),
        [
            Operation::Records,
            Operation::Folders,
            Operation::Probe(101, CREATED, IMAGE)
        ]
    );
    assert_eq!(rig.store.records_now(), [bytes.clone()]);
    assert_eq!(rig.store.folders_now(), [folder.clone()]);
    assert_admission_refused(&mut rig, UNAVAILABLE)?;

    log.borrow_mut().clear();
    rig.clock.advance(Duration::from_secs(60));
    for _ in 0..2 {
        assert_eq!(
            rig.bridge.poll_restart_check(&mut store, &mut probe),
            Err(UNAVAILABLE)
        );
    }
    assert!(log.borrow().is_empty());
    assert_eq!(probe.inner.calls(), 1);
    assert_eq!(
        rig.bridge.status(),
        BridgeStatus::Unavailable(UnavailableCode::InterfaceUnavailable)
    );

    let mut absent = ObservedProbe {
        inner: FakeProbe::new(vec![ProbeResult::Absent]),
        log: log.clone(),
    };
    assert_eq!(
        rig.bridge.start_restart_check(&mut store, &mut absent),
        Ok(RestartProgress::Done { deferred: 0 })
    );
    assert_eq!(
        *log.borrow(),
        [
            Operation::Records,
            Operation::Folders,
            Operation::Probe(101, CREATED, IMAGE),
            Operation::Remove(folder),
            Operation::Delete(bytes)
        ]
    );
    assert!(rig.store.records_now().is_empty());
    assert!(rig.store.folders_now().is_empty());
    assert_eq!(rig.bridge.status(), BridgeStatus::Ready);
    Ok(())
}

#[test]
fn both_initial_and_due_sweeps_stop_before_later_entries_after_uncertainty() -> TestResult {
    for due_poll in [false, true] {
        let mut rig = Rig::new(honest(0), FakeRandom::seeded(3))?;
        let entries = [
            record(1, 101)?,
            record(2, 202)?,
            record(3, 303)?,
            record(4, 404)?,
        ];
        let mut script = Vec::new();
        if due_poll {
            script.extend([ProbeResult::Present; 4]);
        }
        script.extend([
            ProbeResult::Present,
            ProbeResult::Absent,
            ProbeResult::Indeterminate,
            ProbeResult::Absent,
        ]);
        let (mut store, mut probe, log) = observed(&rig, script);
        for (bytes, folder) in &entries {
            store.write_record(bytes)?;
            rig.store.preload_folder(folder);
        }

        let outcome = if due_poll {
            start_mixed_pending(&mut rig, &mut store, &mut probe, &log)?;
            rig.bridge.poll_restart_check(&mut store, &mut probe)
        } else {
            rig.bridge.start_restart_check(&mut store, &mut probe)
        };
        assert_eq!(outcome, Err(UNAVAILABLE));
        let mut expected = Vec::new();
        if !due_poll {
            expected.extend([Operation::Records, Operation::Folders]);
        }
        expected.extend([
            Operation::Probe(101, CREATED, IMAGE),
            Operation::Probe(202, CREATED, IMAGE),
            Operation::Remove(entries[1].1.clone()),
            Operation::Delete(entries[1].0.clone()),
            Operation::Probe(303, CREATED, IMAGE),
        ]);
        assert_eq!(*log.borrow(), expected);
        assert_eq!(
            rig.store.records_now(),
            [
                entries[0].0.clone(),
                entries[2].0.clone(),
                entries[3].0.clone()
            ]
        );
        assert_eq!(
            rig.store.folders_now(),
            [
                entries[0].1.clone(),
                entries[2].1.clone(),
                entries[3].1.clone()
            ]
        );
        assert_admission_refused(&mut rig, UNAVAILABLE)?;
        log.borrow_mut().clear();
        rig.clock.advance(Duration::from_secs(60));
        assert_eq!(
            rig.bridge.poll_restart_check(&mut store, &mut probe),
            Err(UNAVAILABLE)
        );
        assert!(log.borrow().is_empty());
        assert_eq!(
            rig.bridge.status(),
            BridgeStatus::Unavailable(UnavailableCode::InterfaceUnavailable)
        );
    }
    Ok(())
}

fn start_mixed_pending(
    rig: &mut Rig,
    store: &mut ObservedStore,
    probe: &mut ObservedProbe,
    log: &Log,
) -> TestResult {
    let waiting = RestartProgress::Waiting {
        wake: rig.clock.now() + Duration::from_secs(1),
    };
    assert_eq!(rig.bridge.start_restart_check(store, probe), Ok(waiting));
    assert_eq!(
        *log.borrow(),
        [
            Operation::Records,
            Operation::Folders,
            Operation::Probe(101, CREATED, IMAGE),
            Operation::Probe(202, CREATED, IMAGE),
            Operation::Probe(303, CREATED, IMAGE),
            Operation::Probe(404, CREATED, IMAGE)
        ]
    );
    log.borrow_mut().clear();
    assert_eq!(rig.bridge.poll_restart_check(store, probe), Ok(waiting));
    assert!(log.borrow().is_empty());
    rig.clock.advance(Duration::from_secs(1));
    Ok(())
}

#[test]
fn a_fresh_present_check_replaces_unavailable_with_waiting_before_normal_recovery() -> TestResult {
    let mut rig = Rig::new(honest(0), FakeRandom::seeded(3))?;
    let (bytes, folder) = record(1, 101)?;
    let (mut store, mut probe, log) = observed(
        &rig,
        vec![
            ProbeResult::Indeterminate,
            ProbeResult::Present,
            ProbeResult::Absent,
        ],
    );
    store.write_record(&bytes)?;
    rig.store.preload_folder(&folder);
    assert_eq!(
        rig.bridge.start_restart_check(&mut store, &mut probe),
        Err(UNAVAILABLE)
    );
    log.borrow_mut().clear();
    let waiting = RestartProgress::Waiting {
        wake: rig.clock.now() + Duration::from_secs(1),
    };
    assert_eq!(
        rig.bridge.start_restart_check(&mut store, &mut probe),
        Ok(waiting)
    );
    assert_eq!(
        rig.bridge.status(),
        BridgeStatus::Quarantined(QuarantineCode::StaleProcessPresent)
    );
    assert_admission_refused(&mut rig, STALE)?;
    assert_eq!(
        *log.borrow(),
        [
            Operation::Records,
            Operation::Folders,
            Operation::Probe(101, CREATED, IMAGE)
        ]
    );
    log.borrow_mut().clear();
    rig.clock.advance(Duration::from_secs(1));
    assert_eq!(
        rig.bridge.poll_restart_check(&mut store, &mut probe),
        Ok(RestartProgress::Done { deferred: 0 })
    );
    assert_eq!(
        *log.borrow(),
        [
            Operation::Probe(101, CREATED, IMAGE),
            Operation::Remove(folder),
            Operation::Delete(bytes)
        ]
    );
    assert_eq!(rig.bridge.status(), BridgeStatus::Ready);
    Ok(())
}

#[test]
fn uncertainty_at_the_last_due_repeat_is_unavailable_instead_of_present_quarantine() -> TestResult {
    let mut rig = Rig::new(honest(0), FakeRandom::seeded(3))?;
    let (bytes, folder) = record(1, 101)?;
    let mut script = vec![ProbeResult::Present; 30];
    script.push(ProbeResult::Indeterminate);
    let (mut store, mut probe, log) = observed(&rig, script);
    store.write_record(&bytes)?;
    rig.store.preload_folder(&folder);
    rig.bridge.start_restart_check(&mut store, &mut probe)?;
    for _ in 1..30 {
        rig.clock.advance(Duration::from_secs(1));
        assert_eq!(
            rig.bridge.poll_restart_check(&mut store, &mut probe),
            Ok(RestartProgress::Waiting {
                wake: rig.clock.now() + Duration::from_secs(1)
            })
        );
    }
    log.borrow_mut().clear();
    rig.clock.advance(Duration::from_secs(1));
    assert_eq!(
        rig.bridge.poll_restart_check(&mut store, &mut probe),
        Err(UNAVAILABLE)
    );
    assert_eq!(*log.borrow(), [Operation::Probe(101, CREATED, IMAGE)]);
    assert_eq!(probe.inner.calls(), 31);
    assert_eq!(rig.clock.elapsed(), Duration::from_secs(30));
    assert_eq!(rig.store.records_now(), [bytes]);
    assert_eq!(rig.store.folders_now(), [folder]);
    assert_admission_refused(&mut rig, UNAVAILABLE)?;
    Ok(())
}

#[test]
fn duplicate_folders_are_refused_before_any_probe_or_orphan_cleanup() -> TestResult {
    let (a, folder) = record(1, 101)?;
    let (b, _) = record(1, 202)?;
    let orphan = "ffffffffffffffffffffffffffffffff";
    for records in [
        [a.clone(), a.clone()],
        [a.clone(), b.clone()],
        [b.clone(), a.clone()],
    ] {
        let mut rig = Rig::new(honest(0), FakeRandom::seeded(3))?;
        let (mut store, mut probe, log) =
            observed(&rig, vec![ProbeResult::Absent, ProbeResult::Indeterminate]);
        for bytes in &records {
            store.write_record(bytes)?;
        }
        rig.store.preload_folder(&folder);
        rig.store.preload_folder(orphan);
        assert_eq!(
            rig.bridge.start_restart_check(&mut store, &mut probe),
            Err(STALE)
        );
        assert_eq!(*log.borrow(), [Operation::Records]);
        assert_eq!(probe.inner.calls(), 0);
        assert_eq!(rig.store.records_now(), records);
        assert_eq!(rig.store.folders_now(), [folder.clone(), orphan.to_owned()]);
        assert_eq!(
            rig.bridge.status(),
            BridgeStatus::Quarantined(QuarantineCode::StaleProcessPresent)
        );
        assert_admission_refused(&mut rig, STALE)?;
        log.borrow_mut().clear();
        assert_eq!(
            rig.bridge.poll_restart_check(&mut store, &mut probe),
            Err(STALE)
        );
        assert!(log.borrow().is_empty());

        // The host corrects the collection through the public store, then explicitly retries.
        store.delete_record(&a)?;
        store.delete_record(&b)?;
        store.write_record(&a)?;
        log.borrow_mut().clear();
        assert_eq!(
            rig.bridge.start_restart_check(&mut store, &mut probe),
            Ok(RestartProgress::Done { deferred: 0 })
        );
        assert_eq!(
            *log.borrow(),
            [
                Operation::Records,
                Operation::Folders,
                Operation::Remove(orphan.to_owned()),
                Operation::Probe(101, CREATED, IMAGE),
                Operation::Remove(folder.clone()),
                Operation::Delete(a.clone())
            ]
        );
        assert!(rig.store.records_now().is_empty());
        assert!(rig.store.folders_now().is_empty());
        assert_eq!(rig.bridge.status(), BridgeStatus::Ready);
    }
    Ok(())
}
