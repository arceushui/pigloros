//! Restart check and recovery of stale cleanup records (ADR-110 §16).

use std::time::Duration;

use pos_owner_bridge::fake::clock::FakeRandom;
use pos_owner_bridge::fake::host::{FakeProbe, StoreOp};
use pos_owner_bridge::{
    folder_name, BridgeError, BridgeStatus, MonotonicClock, ProbeResult, QuarantineCode,
    RestartProgress, UnavailableCode,
};
use pos_owner_bridge_codec::{encode_cleanup_record, CeremonyId, CleanupRecordV1, ImagePathSha256};

use super::{bytes16, context, honest, Boxed, FakeEnrollment, Rig, TestResult};

fn record() -> Result<(Vec<u8>, String), Box<dyn std::error::Error>> {
    let id = CeremonyId::from_bytes(bytes16(0));
    let name = folder_name(&id);
    let entry = CleanupRecordV1::new(
        id,
        &name,
        4242,
        133_000_000_000_000_000,
        ImagePathSha256::from_bytes([7; 32]),
    )
    .boxed()?;
    let mut buffer = vec![0; 4_096];
    let length = encode_cleanup_record(&entry, &mut buffer).boxed()?;
    buffer.truncate(length);
    Ok((buffer, name))
}

fn rig() -> Result<Rig, Box<dyn std::error::Error>> {
    Rig::new(honest(0), FakeRandom::seeded(3))
}

/// Run a restart check to its end: start it, then poll at each wake the way a host timer would.
fn restart(rig: &mut Rig, probe: &mut FakeProbe) -> Result<usize, BridgeError> {
    let first = rig.bridge.start_restart_check(&mut rig.store, probe)?;
    restart_rest(rig, probe, first)
}

#[test]
fn an_absent_process_has_its_folder_removed_and_its_record_deleted() -> TestResult {
    let mut rig = rig()?;
    let (bytes, name) = record()?;
    rig.store.preload(bytes);
    let mut probe = FakeProbe::new(vec![ProbeResult::Absent]);
    assert_eq!(
        rig.bridge.start_restart_check(&mut rig.store, &mut probe),
        Ok(RestartProgress::Done { deferred: 0 })
    );
    assert_eq!(rig.store.removed_folders(), [name]);
    assert!(rig.store.records_now().is_empty());
    assert_eq!(probe.calls(), 1);
    assert_eq!(rig.bridge.status(), BridgeStatus::Ready);
    Ok(())
}

#[test]
fn a_present_process_is_probed_every_second_until_it_exits() -> TestResult {
    let mut rig = rig()?;
    let (bytes, _) = record()?;
    rig.store.preload(bytes);
    let mut probe = FakeProbe::new(vec![
        ProbeResult::Present,
        ProbeResult::Present,
        ProbeResult::Present,
        ProbeResult::Absent,
    ]);
    let started = rig.clock.now();
    let first = rig.bridge.start_restart_check(&mut rig.store, &mut probe)?;
    assert_eq!(
        first,
        RestartProgress::Waiting {
            wake: started + Duration::from_secs(1)
        }
    );
    assert_eq!(
        rig.bridge.status(),
        BridgeStatus::Quarantined(QuarantineCode::StaleProcessPresent)
    );
    // Polling before the wake neither probes nor changes the wake.
    assert_eq!(
        rig.bridge.poll_restart_check(&mut rig.store, &mut probe)?,
        first
    );
    assert_eq!(probe.calls(), 1);
    assert_eq!(restart_rest(&mut rig, &mut probe, first)?, 0);
    assert_eq!(probe.calls(), 4);
    assert_eq!(rig.clock.elapsed(), Duration::from_secs(3));
    assert!(rig.store.records_now().is_empty());
    assert_eq!(rig.bridge.status(), BridgeStatus::Ready);
    Ok(())
}

/// Continue a restart check that already has a first `progress`.
fn restart_rest(
    rig: &mut Rig,
    probe: &mut FakeProbe,
    mut progress: RestartProgress,
) -> Result<usize, BridgeError> {
    loop {
        match progress {
            RestartProgress::Done { deferred } => return Ok(deferred),
            RestartProgress::Waiting { wake } => {
                rig.clock
                    .advance(wake.saturating_duration_since(rig.clock.now()));
                progress = rig.bridge.poll_restart_check(&mut rig.store, probe)?;
            }
        }
    }
}

#[test]
fn a_process_that_stays_present_leaves_the_surface_quarantined() -> TestResult {
    let mut rig = rig()?;
    let (bytes, _) = record()?;
    rig.store.preload(bytes.clone());
    let mut probe = FakeProbe::new(vec![ProbeResult::Present]);
    let outcome = restart(&mut rig, &mut probe);
    assert_eq!(
        outcome,
        Err(BridgeError::Quarantine(QuarantineCode::StaleProcessPresent))
    );
    // One probe at start and thirty repeats, one second apart.
    assert_eq!(probe.calls(), 31);
    assert_eq!(rig.clock.elapsed(), Duration::from_secs(30));
    assert_eq!(
        rig.bridge.status(),
        BridgeStatus::Quarantined(QuarantineCode::StaleProcessPresent)
    );
    assert_eq!(rig.store.records_now(), [bytes]);
    // The check has ended: nothing is pending any more.
    assert_eq!(
        rig.bridge.poll_restart_check(&mut rig.store, &mut probe),
        Ok(RestartProgress::Done { deferred: 0 })
    );
    assert_eq!(probe.calls(), 31);
    Ok(())
}

#[test]
fn sharing_violations_defer_the_cleanup_to_the_next_start_and_never_block_the_surface() -> TestResult
{
    let mut rig = rig()?;
    let (bytes, name) = record()?;
    rig.store.preload(bytes.clone());
    rig.store.set_failing(&[StoreOp::Remove]);
    let mut probe = FakeProbe::new(vec![ProbeResult::Absent]);
    assert_eq!(restart(&mut rig, &mut probe), Ok(1));
    assert_eq!(rig.bridge.status(), BridgeStatus::Ready);
    assert_eq!(rig.store.records_now(), std::slice::from_ref(&bytes));
    assert!(rig.store.removed_folders().is_empty());
    rig.store.set_failing(&[StoreOp::Delete]);
    assert_eq!(restart(&mut rig, &mut probe), Ok(1));
    assert_eq!(rig.store.removed_folders(), [name]);
    assert_eq!(rig.store.records_now(), [bytes]);
    rig.store.set_failing(&[]);
    assert_eq!(restart(&mut rig, &mut probe), Ok(0));
    assert!(rig.store.records_now().is_empty());
    assert_eq!(rig.bridge.status(), BridgeStatus::Ready);
    Ok(())
}

#[test]
fn a_deferred_cleanup_is_counted_whenever_the_process_exits() -> TestResult {
    let mut rig = rig()?;
    let (bytes, _) = record()?;
    rig.store.preload(bytes);
    rig.store.set_failing(&[StoreOp::Remove]);
    let mut probe = FakeProbe::new(vec![ProbeResult::Present, ProbeResult::Absent]);
    assert_eq!(restart(&mut rig, &mut probe), Ok(1));
    Ok(())
}

#[test]
fn an_undecodable_record_fails_closed_and_stays_in_the_store() -> TestResult {
    let mut rig = rig()?;
    let (bytes, _) = record()?;
    rig.store.preload(vec![0xff, 0x00]);
    rig.store.preload(bytes.clone());
    let mut probe = FakeProbe::new(vec![ProbeResult::Absent]);
    let stale = BridgeError::Quarantine(QuarantineCode::StaleProcessPresent);
    assert_eq!(
        rig.bridge.start_restart_check(&mut rig.store, &mut probe),
        Err(stale)
    );
    assert_eq!(
        rig.bridge.status(),
        BridgeStatus::Quarantined(QuarantineCode::StaleProcessPresent)
    );
    // Nothing is probed or removed before every record is known to be trustworthy.
    assert_eq!(rig.store.records_now(), [vec![0xff, 0x00], bytes]);
    assert!(rig.store.removed_folders().is_empty());
    assert_eq!(probe.calls(), 0);
    assert_eq!(rig.clock.elapsed(), Duration::ZERO);
    let mut port = FakeEnrollment::new();
    assert_eq!(rig.bridge.enroll(&context(), &mut port), Err(stale));
    assert!(port.calls.is_empty());
    Ok(())
}

#[test]
fn an_unreadable_store_makes_the_surface_unavailable_until_a_check_succeeds() -> TestResult {
    let mut rig = rig()?;
    rig.store.set_failing(&[StoreOp::List]);
    let mut probe = FakeProbe::new(Vec::new());
    let unavailable = BridgeError::Unavailable(UnavailableCode::InterfaceUnavailable);
    assert_eq!(restart(&mut rig, &mut probe), Err(unavailable));
    assert_eq!(probe.calls(), 0);
    assert_eq!(
        rig.bridge.status(),
        BridgeStatus::Unavailable(UnavailableCode::InterfaceUnavailable)
    );
    let mut port = FakeEnrollment::new();
    assert_eq!(rig.bridge.enroll(&context(), &mut port), Err(unavailable));
    assert!(port.calls.is_empty());
    rig.store.set_failing(&[]);
    assert_eq!(restart(&mut rig, &mut probe), Ok(0));
    assert_eq!(rig.bridge.status(), BridgeStatus::Ready);
    Ok(())
}

#[test]
fn polling_without_a_pending_check_reports_nothing_to_do() -> TestResult {
    let mut rig = rig()?;
    let mut probe = FakeProbe::new(Vec::new());
    assert_eq!(
        rig.bridge.poll_restart_check(&mut rig.store, &mut probe),
        Ok(RestartProgress::Done { deferred: 0 })
    );
    assert_eq!(probe.calls(), 0);
    assert_eq!(rig.bridge.status(), BridgeStatus::Ready);
    Ok(())
}

const ORPHAN: &str = "ffeeddccbbaa99887766554433221100";

#[test]
fn a_ceremony_folder_without_a_record_is_swept_and_other_folders_are_left_alone() -> TestResult {
    let mut rig = rig()?;
    rig.store.preload_folder(ORPHAN);
    let others = [
        "not-a-ceremony-folder",
        "FFEEDDCCBBAA99887766554433221100",
        "ffeeddccbbaa9988776655443322110",
        "ffeeddccbbaa99887766554433221100aa",
        "ffeeddccbbaa9988776655443322110g",
    ];
    for other in others {
        rig.store.preload_folder(other);
    }
    let mut probe = FakeProbe::new(Vec::new());
    assert_eq!(restart(&mut rig, &mut probe), Ok(0));
    assert_eq!(rig.store.removed_folders(), [ORPHAN]);
    assert_eq!(rig.store.folders_now(), others);
    assert_eq!(rig.bridge.status(), BridgeStatus::Ready);
    Ok(())
}

#[test]
fn a_failed_orphan_removal_is_deferred_and_counted() -> TestResult {
    let mut rig = rig()?;
    rig.store.preload_folder(ORPHAN);
    rig.store.set_failing(&[StoreOp::Remove]);
    let mut probe = FakeProbe::new(Vec::new());
    assert_eq!(restart(&mut rig, &mut probe), Ok(1));
    assert_eq!(rig.store.folders_now(), [ORPHAN]);
    assert_eq!(rig.bridge.status(), BridgeStatus::Ready);
    rig.store.set_failing(&[]);
    assert_eq!(restart(&mut rig, &mut probe), Ok(0));
    assert!(rig.store.folders_now().is_empty());
    Ok(())
}

#[test]
fn a_folder_that_a_record_names_is_left_to_its_record() -> TestResult {
    let mut rig = rig()?;
    let (bytes, name) = record()?;
    rig.store.preload(bytes);
    rig.store.preload_folder(&name);
    let mut probe = FakeProbe::new(vec![ProbeResult::Present, ProbeResult::Present]);
    let first = rig.bridge.start_restart_check(&mut rig.store, &mut probe)?;
    assert!(matches!(first, RestartProgress::Waiting { .. }));
    assert_eq!(rig.store.folders_now(), std::slice::from_ref(&name));
    assert!(rig.store.removed_folders().is_empty());
    // Once the process is gone, the record removes its folder exactly once.
    let mut probe = FakeProbe::new(vec![ProbeResult::Absent]);
    assert_eq!(restart(&mut rig, &mut probe), Ok(0));
    assert_eq!(rig.store.removed_folders(), [name]);
    assert!(rig.store.folders_now().is_empty());
    Ok(())
}

#[test]
fn folders_that_cannot_be_listed_defer_the_sweep_and_never_block_a_fresh_ceremony() -> TestResult {
    let mut rig = rig()?;
    rig.store.preload_folder(ORPHAN);
    rig.store.set_failing(&[StoreOp::Folders]);
    let mut probe = FakeProbe::new(Vec::new());
    assert_eq!(restart(&mut rig, &mut probe), Ok(1));
    assert_eq!(rig.bridge.status(), BridgeStatus::Ready);
    assert_eq!(rig.store.folders_now(), [ORPHAN]);
    let mut port = FakeEnrollment::new();
    rig.bridge.enroll(&context(), &mut port)?;
    assert_eq!(rig.bridge.status(), BridgeStatus::Ready);
    Ok(())
}

#[test]
fn an_unreadable_record_stops_the_sweep_before_any_folder_is_removed() -> TestResult {
    let mut rig = rig()?;
    rig.store.preload(vec![0xff]);
    rig.store.preload_folder(ORPHAN);
    let mut probe = FakeProbe::new(Vec::new());
    let stale = BridgeError::Quarantine(QuarantineCode::StaleProcessPresent);
    assert_eq!(restart(&mut rig, &mut probe), Err(stale));
    assert_eq!(rig.store.folders_now(), [ORPHAN]);
    Ok(())
}

fn record_naming(folder: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let entry = CleanupRecordV1::new(
        CeremonyId::from_bytes(bytes16(0)),
        folder,
        4242,
        133_000_000_000_000_000,
        ImagePathSha256::from_bytes([7; 32]),
    )
    .boxed()?;
    let mut buffer = vec![0; 4_096];
    let length = encode_cleanup_record(&entry, &mut buffer).boxed()?;
    buffer.truncate(length);
    Ok(buffer)
}

#[test]
fn a_record_that_names_a_folder_other_than_its_ceremony_id_derives_is_unreadable() -> TestResult {
    let long = "a".repeat(300);
    let names = [
        "..\\..\\x",
        "a/b",
        "../x",
        "/etc/passwd",
        "C:\\Windows\\System32",
        "",
        "ffeeddccbbaa99887766554433221100",
        long.as_str(),
    ];
    let stale = BridgeError::Quarantine(QuarantineCode::StaleProcessPresent);
    for name in names {
        let mut rig = rig()?;
        let bytes = record_naming(name)?;
        rig.store.preload(bytes.clone());
        rig.store.preload_folder(ORPHAN);
        let mut probe = FakeProbe::new(vec![ProbeResult::Absent]);
        assert_eq!(restart(&mut rig, &mut probe), Err(stale), "{name:?}");
        assert!(rig.store.removed_folders().is_empty(), "{name:?}");
        assert_eq!(rig.store.records_now(), [bytes], "{name:?}");
        assert_eq!(probe.calls(), 0, "{name:?}");
    }
    Ok(())
}

#[test]
fn a_start_after_any_ceremony_is_refused_and_leaves_the_status_alone() -> TestResult {
    let mut rig = rig()?;
    rig.store.preload_folder(ORPHAN);
    let mut port = FakeEnrollment::new();
    rig.bridge.enroll(&context(), &mut port)?;
    let mut probe = FakeProbe::new(Vec::new());
    let unavailable = BridgeError::Unavailable(UnavailableCode::InterfaceUnavailable);
    assert_eq!(
        rig.bridge.start_restart_check(&mut rig.store, &mut probe),
        Err(unavailable)
    );
    assert_eq!(rig.bridge.status(), BridgeStatus::Ready);
    assert_eq!(
        rig.store.folders_now(),
        [ORPHAN],
        "a live folder must survive"
    );
    assert_eq!(probe.calls(), 0);
    Ok(())
}

#[test]
fn a_store_that_fails_on_a_missing_folder_only_defers_the_record() -> TestResult {
    let (bytes, _) = record()?;
    for (strict, deferred, left) in [(false, 0, 0), (true, 1, 1)] {
        let mut rig = rig()?;
        rig.store.preload(bytes.clone());
        rig.store.fail_on_missing_folders(strict);
        let mut probe = FakeProbe::new(vec![ProbeResult::Absent]);
        assert_eq!(
            restart(&mut rig, &mut probe),
            Ok(deferred),
            "strict {strict}"
        );
        assert_eq!(rig.store.records_now().len(), left, "strict {strict}");
        assert_eq!(rig.bridge.status(), BridgeStatus::Ready);
    }
    Ok(())
}
