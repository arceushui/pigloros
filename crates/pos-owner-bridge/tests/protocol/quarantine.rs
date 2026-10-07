//! Restart check and recovery of stale cleanup records (ADR-110 §16).

use pos_owner_bridge::fake::clock::{FakeClock, FakeRandom};
use pos_owner_bridge::fake::host::{FakeProbe, StoreOp};
use pos_owner_bridge::restart::{restart_check, PROBE_ATTEMPTS};
use pos_owner_bridge::{
    folder_name, BridgeError, BridgeStatus, ProbeResult, QuarantineCode, UnavailableCode,
};
use pos_owner_bridge_codec::{encode_cleanup_record, CeremonyId, CleanupRecordV1, ImagePathSha256};

use super::{bytes16, honest, Boxed, Rig, TestResult};

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

#[test]
fn an_absent_process_has_its_folder_removed_and_its_record_deleted() -> TestResult {
    let mut rig = rig()?;
    let (bytes, name) = record()?;
    rig.store.preload(bytes);
    let mut probe = FakeProbe::new(vec![ProbeResult::Absent]);
    rig.bridge.restart_check(&mut probe)?;
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
    rig.bridge.restart_check(&mut probe)?;
    assert_eq!(probe.calls(), 4);
    assert_eq!(rig.clock.elapsed(), std::time::Duration::from_secs(3));
    assert!(rig.store.records_now().is_empty());
    Ok(())
}

#[test]
fn a_process_that_stays_present_leaves_the_surface_quarantined() -> TestResult {
    let mut rig = rig()?;
    let (bytes, _) = record()?;
    rig.store.preload(bytes.clone());
    let mut probe = FakeProbe::new(vec![ProbeResult::Present]);
    let outcome = rig.bridge.restart_check(&mut probe);
    assert_eq!(
        outcome,
        Err(BridgeError::Quarantine(QuarantineCode::StaleProcessPresent))
    );
    assert_eq!(probe.calls(), usize::try_from(PROBE_ATTEMPTS)? + 1);
    assert_eq!(rig.clock.elapsed(), std::time::Duration::from_secs(30));
    assert_eq!(
        rig.bridge.status(),
        BridgeStatus::Quarantined(QuarantineCode::StaleProcessPresent)
    );
    assert_eq!(rig.store.records_now(), [bytes]);
    Ok(())
}

#[test]
fn undecodable_records_and_sharing_violations_never_block_the_surface() -> TestResult {
    let mut rig = rig()?;
    let (bytes, _) = record()?;
    rig.store.preload(vec![0xff, 0x00]);
    rig.store.preload(bytes);
    rig.store.set_failing(&[StoreOp::Remove]);
    let mut probe = FakeProbe::new(vec![ProbeResult::Absent]);
    rig.bridge.restart_check(&mut probe)?;
    assert_eq!(rig.store.records_now().len(), 2);
    assert!(rig.store.removed_folders().is_empty());
    rig.store.set_failing(&[StoreOp::Delete]);
    rig.bridge.restart_check(&mut probe)?;
    assert_eq!(rig.store.records_now().len(), 2);
    Ok(())
}

#[test]
fn an_unreadable_store_makes_the_surface_unavailable() -> TestResult {
    let mut rig = rig()?;
    rig.store.set_failing(&[StoreOp::List]);
    let mut probe = FakeProbe::new(Vec::new());
    let outcome = rig.bridge.restart_check(&mut probe);
    assert_eq!(
        outcome,
        Err(BridgeError::Unavailable(
            UnavailableCode::InterfaceUnavailable
        ))
    );
    assert_eq!(probe.calls(), 0);
    Ok(())
}

#[test]
fn the_free_function_probes_without_a_bridge() -> TestResult {
    let clock = FakeClock::start();
    let mut store = pos_owner_bridge::fake::host::FakeStore::default();
    let mut probe = FakeProbe::new(Vec::new());
    restart_check(&mut store, &mut probe, &clock)?;
    assert_eq!(probe.calls(), 0);
    Ok(())
}
