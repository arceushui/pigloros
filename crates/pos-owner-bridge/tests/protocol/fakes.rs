//! Contract tests for the shared types and the fakes other crates reuse.

use std::time::{Duration, Instant};

use pos_owner_bridge::ceremony::driver::CeremonyDriver;
use pos_owner_bridge::ceremony::plan::{Assertion, CeremonyPlan, Verified};
use pos_owner_bridge::fake::buffers::{Actor, Buffers, LogEntry, Pair, Role};
use pos_owner_bridge::fake::clock::{FakeClock, FakeRandom};
use pos_owner_bridge::fake::honest::HonestPage;
use pos_owner_bridge::fake::host::{FakeLoopback, FakeProbe, FakeStore, StoreOp};
use pos_owner_bridge::fake::signer::{
    base64url, Backup, FixtureSigner, ReplyShape, FIXTURE_SCALAR, OTHER_SCALAR,
};
use pos_owner_bridge::fake::stepper::{FakeHost, FakeStepper, DEFAULT_STEP_LIMIT};
use pos_owner_bridge::fake::surface::{FakeSurface, PageModel, SurfaceFaults};
use pos_owner_bridge::{
    cleanup_record_bytes, folder_name, BridgeError, BridgeStatus, CeremonyHost, CleanupStore,
    ErrorClass, LifecycleCode, LoopbackPort, MonotonicClock, NavigationId, OsRandom, OwnerError,
    OwnerErrorKind, OwnerWebSurface, PostGuard, PrfOutput, ProbeResult, ProcessIdentity,
    ProcessProbe, ProtocolCode, QuarantineCode, RejectedCode, ReplyImage, RequestImage,
    RootFingerprint, SecureRandom, ServedSnapshot, SurfaceError, SurfaceEvent, SurfaceSpec,
    SystemClock, UnavailableCode,
};
use pos_owner_bridge_codec::{
    decode_assertion_reply, decode_cleanup_record, CeremonyId, CeremonyKind, ImagePathSha256,
    OwnerBridgeControlV1, OwnerUserHandle, PrfInput, WebAuthnChallenge,
};
use zeroize::Zeroizing;

use super::{bytes16, bytes32, create_plan, honest, new_driver, Boxed, DriverRig, TestResult};
use pos_owner_bridge::fake::surface::SurfaceConfig;

#[test]
fn the_fake_random_is_deterministic_and_can_fail() {
    let (mut first, mut second) = (FakeRandom::seeded(5), FakeRandom::seeded(5));
    let (mut a, mut b) = ([0; 17], [0; 17]);
    assert_eq!(first.fill(&mut a), Ok(()));
    assert_eq!(second.fill(&mut b), Ok(()));
    assert_eq!(a, b);
    assert_ne!(a, [0; 17]);
    let mut failing = FakeRandom::failing_after(5, 2);
    let mut small = [0; 3];
    assert_eq!(failing.fill(&mut small), Ok(()));
    assert_eq!(failing.fill(&mut small), Ok(()));
    assert_eq!(
        failing.fill(&mut small),
        Err(UnavailableCode::RngUnavailable)
    );
}

#[test]
fn the_operating_system_random_and_clock_work() {
    let mut random = OsRandom;
    let (mut a, mut b) = ([0; 32], [0; 32]);
    assert_eq!(random.fill(&mut a), Ok(()));
    assert_eq!(random.fill(&mut b), Ok(()));
    assert_ne!(a, b);
    let clock = SystemClock;
    let (first, second) = (clock.now(), clock.now());
    assert!(second >= first);
}

#[test]
fn the_fake_clock_skips_dead_time_only_up_to_the_next_event() {
    let clock = FakeClock::start();
    let origin: Instant = clock.now();
    clock.advance(Duration::from_millis(10));
    assert_eq!(clock.elapsed(), Duration::from_millis(10));
    clock.skip(Duration::from_millis(10), None);
    assert_eq!(clock.elapsed(), Duration::from_millis(20));
    clock.skip(
        Duration::from_millis(10),
        Some(origin + Duration::from_millis(500)),
    );
    assert_eq!(clock.elapsed(), Duration::from_millis(500));
    clock.set_activity_source(Box::new(|| Some(Duration::from_millis(700))));
    clock.skip(
        Duration::from_millis(10),
        Some(origin + Duration::from_secs(9)),
    );
    assert_eq!(clock.elapsed(), Duration::from_millis(700));
    clock.skip(Duration::from_millis(10), Some(origin));
    assert_eq!(clock.elapsed(), Duration::from_millis(710));
    assert_eq!(clock.now().duration_since(origin), clock.elapsed());
}

#[test]
fn the_image_buffers_never_print_their_bytes() {
    let mut request = RequestImage::zeroed();
    request.as_mut_bytes().fill(0xab);
    let mut reply = ReplyImage::zeroed();
    reply.as_mut_bytes().fill(0xcd);
    let text = format!("{request:?} {reply:?}");
    assert!(!text.contains("171") && !text.contains("205"), "{text}");
    assert!(
        text.contains("RequestImage") && text.contains("len: 4096"),
        "{text}"
    );
    assert!(text.contains("dirty: true"), "{text}");
    reply.wipe();
    assert!(format!("{reply:?}").contains("dirty: false"));
}

#[test]
fn aligning_a_clock_moves_its_origin_and_keeps_the_elapsed_time() {
    let clock = FakeClock::start();
    clock.advance(Duration::from_secs(7));
    let target = clock.now() + Duration::from_secs(1_000);
    clock.align_to(target);
    assert_eq!(clock.now(), target);
    assert_eq!(clock.elapsed(), Duration::from_secs(7));
    assert_eq!(clock.offset_of(target), Duration::from_secs(7));
}

#[test]
fn a_host_starts_every_run_at_the_t0_the_owner_thread_drew() -> TestResult {
    // T0 comes from a clock with another origin, 1,000 seconds before this one's: the bounds of
    // the ceremony must run from T0, not from where this clock happens to start.
    let clock = FakeClock::start();
    let t0 = clock
        .now()
        .checked_sub(Duration::from_secs(1_000))
        .ok_or("the platform clock is too young for this test")?;
    let plan = CeremonyPlan::for_test(
        CeremonyKind::Create,
        CeremonyId::from_bytes(bytes16(0)),
        WebAuthnChallenge::from_bytes(bytes32(0x20)),
        OwnerUserHandle::from_bytes(bytes32(0x40)),
        PrfInput::from_bytes(bytes32(0x60)),
        t0,
    );
    let loopback = FakeLoopback::default();
    let page = HonestPage::new(honest(0)).boxed()?;
    let surface = FakeSurface::new(
        clock.clone(),
        loopback.clone(),
        Box::new(page),
        SurfaceConfig::default(),
    );
    let mut host = FakeHost::new(clock.clone(), surface, loopback, FakeStore::default());
    let log = host.t0_log();
    let reply = host.run(CeremonyDriver::for_test(plan));
    assert!(reply.result.is_ok(), "{:?}", reply.result.err());
    assert_eq!(*log.borrow(), [Duration::from_secs(0)]);
    assert!(clock.now() >= t0);
    Ok(())
}

#[test]
fn the_fake_stepper_counts_its_steps_and_gives_up_at_its_limit() -> TestResult {
    let mut rig = DriverRig::new(honest(0), SurfaceConfig::default())?;
    let plan = create_plan(&rig.clock);
    let mut driver = new_driver(plan);
    let mut stepper = FakeStepper::new(rig.clock.clone()).with_step_limit(3);
    let outcome = stepper.run(&mut driver, &mut rig.env());
    assert_eq!(
        outcome.err(),
        Some(BridgeError::Protocol(ProtocolCode::UnexpectedState))
    );
    assert_eq!(stepper.steps(), 3);
    let mut stepper = FakeStepper::new(rig.clock.clone());
    assert!(stepper.run(&mut driver, &mut rig.env()).is_ok());
    assert!(stepper.steps() > 0 && stepper.steps() < DEFAULT_STEP_LIMIT);
    // A driver that already finished cannot be stepped again.
    assert_eq!(
        stepper.run(&mut driver, &mut rig.env()).err(),
        Some(BridgeError::Protocol(ProtocolCode::UnexpectedState))
    );
    Ok(())
}

#[test]
fn the_fake_loopback_scripts_the_served_count_and_the_probe() {
    let mut loopback = FakeLoopback::default();
    assert_eq!(loopback.served().count, 0);
    loopback.set_served(2, false);
    assert_eq!(loopback.served().count, 2);
    assert!(!loopback.served().integrity_ok);
    loopback.begin_navigation();
    assert_eq!(loopback.served().count, 0);
    assert_eq!(loopback.resets(), 1);
    assert_eq!(loopback.probe_ipv6(), Ok(()));
    loopback.fail_probes_from(Some(2));
    assert_eq!(
        loopback.probe_ipv6(),
        Err(BridgeError::Unavailable(UnavailableCode::LoopbackChanged))
    );
    assert_eq!(loopback.probes(), 2);
}

#[test]
fn a_scripted_served_count_advances_one_read_at_a_time_and_repeats_its_last_entry() {
    let snapshot = |count| ServedSnapshot {
        count,
        integrity_ok: true,
    };
    let mut loopback = FakeLoopback::default();
    loopback.script_served(&[snapshot(0), snapshot(1), snapshot(2)]);
    let reads: Vec<u32> = (0..5).map(|_| loopback.served().count).collect();
    assert_eq!(reads, [0, 1, 2, 2, 2]);
    loopback.begin_navigation();
    assert_eq!(loopback.served().count, 0);
    loopback.script_served(&[]);
    loopback.set_served(4, true);
    assert_eq!(loopback.served().count, 4);
    assert_eq!(loopback.served().count, 4);
}

#[test]
fn a_cleanup_record_that_cannot_be_encoded_makes_the_surface_unavailable() -> TestResult {
    let identity = ProcessIdentity {
        browser_pid: 7,
        creation_filetime: 8,
        image_path_sha256: ImagePathSha256::from_bytes([9; 32]),
    };
    let id = CeremonyId::from_bytes(bytes16(0));
    let name = folder_name(&id);
    let bytes = cleanup_record_bytes(id, &name, &identity)?;
    let record = decode_cleanup_record(&bytes).boxed()?;
    assert_eq!(record.folder_name(), name);
    assert_eq!(record.browser_pid(), 7);
    assert_eq!(record.creation_filetime(), 8);
    assert_eq!(record.image_path_sha256().as_bytes(), &[9; 32]);
    let too_long = "x".repeat(4_096);
    assert_eq!(
        cleanup_record_bytes(id, &too_long, &identity),
        Err(BridgeError::Unavailable(
            UnavailableCode::InterfaceUnavailable
        ))
    );
    Ok(())
}

#[test]
fn the_fake_store_and_probe_replay_their_scripts() -> TestResult {
    let mut store = FakeStore::default();
    store.write_record(b"one")?;
    store.write_record(b"two")?;
    store.delete_record(b"one")?;
    assert_eq!(store.records()?, [b"two".to_vec()]);
    store.remove_folder("folder")?;
    assert_eq!(store.removed_folders(), ["folder"]);
    store.set_failing(&[
        StoreOp::Write,
        StoreOp::Delete,
        StoreOp::List,
        StoreOp::Remove,
    ]);
    assert!(store.write_record(b"x").is_err());
    assert!(store.delete_record(b"x").is_err());
    assert!(store.records().is_err());
    assert!(store.remove_folder("x").is_err());
    let digest = ImagePathSha256::from_bytes([0; 32]);
    let mut probe = FakeProbe::new(vec![ProbeResult::Present, ProbeResult::Absent]);
    let verdicts = [
        probe.probe(1, 2, &digest),
        probe.probe(1, 2, &digest),
        probe.probe(1, 2, &digest),
    ];
    assert_eq!(
        verdicts,
        [
            ProbeResult::Present,
            ProbeResult::Absent,
            ProbeResult::Absent
        ]
    );
    assert_eq!(
        FakeProbe::new(Vec::new()).probe(1, 2, &digest),
        ProbeResult::Absent
    );
    Ok(())
}

#[test]
fn base64url_matches_the_golden_challenge_and_the_signer_is_cached_and_validated() -> TestResult {
    let challenge: Vec<u8> = (0x20..0x40).collect();
    assert_eq!(
        base64url(&challenge),
        "ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8"
    );
    assert_eq!(base64url(&[0xfb, 0xff]), "-_8");
    assert!(FixtureSigner::with_scalars(&[0; 32], &[2; 32], &[1]).is_err());
    let signer = FixtureSigner::new(&[0x80, 0x81]).boxed()?;
    assert_eq!(signer.credential_id(), [0x80, 0x81]);
    let id = CeremonyId::from_bytes(bytes16(0));
    let challenge = WebAuthnChallenge::from_bytes(bytes32(0x20));
    let shape = ReplyShape::honest(1, Some(bytes32(0xa0)));
    let first = signer.assertion_payload(id, &challenge, &shape).boxed()?;
    let second = signer.assertion_payload(id, &challenge, &shape).boxed()?;
    assert_eq!(first, second);
    let wrong = ReplyShape {
        wrong_key: true,
        ..shape.clone()
    };
    assert_ne!(
        signer.assertion_payload(id, &challenge, &wrong).boxed()?,
        first
    );
    // A missing PRF is encoded the way the packaged page does it: as CBOR null, so the closed
    // decoder refuses the payload and the bridge classifies it.
    let missing = ReplyShape { prf: None, ..shape };
    let absent = signer.assertion_payload(id, &challenge, &missing).boxed()?;
    assert!(decode_assertion_reply(&absent).is_err());
    let malformed = ReplyShape {
        prf_item: Some(vec![0x41, 1]),
        ..missing
    };
    let odd = signer
        .assertion_payload(id, &challenge, &malformed)
        .boxed()?;
    assert_ne!(odd, absent);
    assert!(decode_assertion_reply(&odd).is_err());
    assert!(signer
        .attestation_payload(id, &challenge, &ReplyShape::honest(0, None))
        .is_ok());
    Ok(())
}

fn request_with_header(
    generation: u32,
) -> Result<(RequestImage, [u8; 64]), Box<dyn std::error::Error>> {
    let id = CeremonyId::from_bytes(bytes16(0));
    let mut request = RequestImage::zeroed();
    let header =
        OwnerBridgeControlV1::new_request(CeremonyKind::Create, generation, id, 148).boxed()?;
    let (head, _) = request.as_mut_bytes().split_at_mut(64);
    head.copy_from_slice(&header.encode());
    let reply = OwnerBridgeControlV1::new_reply(CeremonyKind::Create, generation, id).boxed()?;
    Ok((request, reply.encode()))
}

#[test]
fn a_surface_refuses_every_state_call_without_a_live_pair() -> TestResult {
    let mut rig = DriverRig::new(honest(0), SurfaceConfig::default())?;
    let refused = SurfaceError::new(BridgeError::Protocol(ProtocolCode::UnexpectedState));
    assert_eq!(rig.surface.reply_load_state(), Err(refused));
    assert_eq!(rig.surface.reply_compare_exchange(0, 4), Err(refused));
    assert_eq!(
        rig.surface.reply_copy(&mut ReplyImage::zeroed()),
        Err(refused)
    );
    assert_eq!(rig.surface.zero_close_buffers(), Err(refused));
    let guard = PostGuard {
        generation: 1,
        navigation_id: NavigationId(1),
        served_count: 1,
    };
    assert_eq!(rig.surface.post(&guard), Err(refused));
    let violations = rig
        .handle
        .log()
        .iter()
        .filter(|entry| matches!(entry, LogEntry::Violation(_)))
        .count();
    assert_eq!(violations, 5);
    Ok(())
}

#[test]
fn a_surface_re_checks_the_guard_and_exposes_the_state_word() -> TestResult {
    let mut rig = DriverRig::new(honest(0), SurfaceConfig::default())?;
    let spec = SurfaceSpec {
        ceremony_id: CeremonyId::from_bytes(bytes16(0)),
        folder_name: "folder".to_owned(),
        owner_window: None,
    };
    rig.surface.open(&spec).map_err(SurfaceError::error)?;
    let navigation = rig.surface.navigate().map_err(SurfaceError::error)?;
    let (request, header) = request_with_header(1)?;
    rig.surface
        .create_and_write(&request, &header)
        .map_err(SurfaceError::error)?;
    rig.loopback.set_served(1, true);
    let stale = BridgeError::Lifecycle(LifecycleCode::NavigationViolation);
    for guard in [
        PostGuard {
            generation: 2,
            navigation_id: navigation,
            served_count: 1,
        },
        PostGuard {
            generation: 1,
            navigation_id: NavigationId(9),
            served_count: 1,
        },
        PostGuard {
            generation: 1,
            navigation_id: navigation,
            served_count: 2,
        },
    ] {
        assert_eq!(rig.surface.post(&guard), Err(SurfaceError::new(stale)));
    }
    let good = PostGuard {
        generation: 1,
        navigation_id: navigation,
        served_count: 1,
    };
    assert_eq!(rig.surface.post(&good), Ok(()));
    assert_eq!(rig.surface.reply_load_state(), Ok(0));
    assert_eq!(rig.surface.reply_compare_exchange(0, 4), Ok(true));
    assert_eq!(rig.surface.reply_compare_exchange(0, 4), Ok(false));
    rig.surface
        .create_and_write(&request, &header)
        .map_err(SurfaceError::error)?;
    assert!(rig.handle.log().iter().any(
        |entry| matches!(entry, LogEntry::Violation(text) if text.contains("another is open"))
    ));
    rig.handle.set_served(3, false);
    assert_eq!(rig.handle.pair_count(), 2);
    assert_eq!(rig.surface.take_event(), None);
    Ok(())
}

#[test]
fn surface_faults_are_returned_per_call() -> TestResult {
    let refused = BridgeError::Unavailable(UnavailableCode::InterfaceUnavailable);
    let mut rig = DriverRig::new(honest(0), SurfaceConfig::default())?;
    rig.handle.set_faults(SurfaceFaults {
        zero_close: true,
        close_controller: true,
        finish: true,
        ..SurfaceFaults::default()
    });
    let unexpected = SurfaceError::new(BridgeError::Protocol(ProtocolCode::UnexpectedState));
    assert_eq!(rig.surface.close_controller(), Err(unexpected));
    assert_eq!(rig.surface.finish(), Err(unexpected));
    let (request, header) = request_with_header(1)?;
    rig.handle.set_faults(SurfaceFaults {
        create: Some(refused),
        ..SurfaceFaults::default()
    });
    assert_eq!(
        rig.surface.create_and_write(&request, &header),
        Err(SurfaceError::new(refused))
    );
    rig.handle.set_faults(SurfaceFaults::default());
    rig.surface
        .create_and_write(&request, &header)
        .map_err(SurfaceError::error)?;
    rig.handle.set_faults(SurfaceFaults {
        zero_close: true,
        ..SurfaceFaults::default()
    });
    assert_eq!(rig.surface.zero_close_buffers(), Err(unexpected));
    Ok(())
}

#[test]
fn error_classes_retry_policy_and_messages_follow_the_taxonomy() {
    let cases = [
        (
            BridgeError::Unavailable(UnavailableCode::PortUnavailable),
            ErrorClass::Unavailable,
            false,
        ),
        (
            BridgeError::Rejected(RejectedCode::Signature),
            ErrorClass::Rejected,
            true,
        ),
        (
            BridgeError::Protocol(ProtocolCode::Malformed),
            ErrorClass::Protocol,
            true,
        ),
        (
            BridgeError::Lifecycle(LifecycleCode::ClientFailed),
            ErrorClass::Lifecycle,
            true,
        ),
        (
            BridgeError::Quarantine(QuarantineCode::CleanupTimeout),
            ErrorClass::Quarantine,
            false,
        ),
        (
            BridgeError::Owner(OwnerError::new(OwnerErrorKind::Registry)),
            ErrorClass::Owner,
            false,
        ),
    ];
    for (error, class, retryable) in cases {
        assert_eq!(error.class(), class);
        assert_eq!(error.is_user_retryable(), retryable);
        assert!(!error.to_string().is_empty());
    }
    assert_eq!(
        OwnerError::new(OwnerErrorKind::Registry).kind(),
        OwnerErrorKind::Registry
    );
}

#[test]
fn status_admission_and_transitions_follow_the_error_class() {
    assert_eq!(BridgeStatus::Ready.admission(), Ok(()));
    assert_eq!(
        BridgeStatus::Busy.admission(),
        Err(BridgeError::Unavailable(
            UnavailableCode::InterfaceUnavailable
        ))
    );
    assert_eq!(
        BridgeStatus::Quarantined(QuarantineCode::CleanupTimeout).admission(),
        Err(BridgeError::Quarantine(QuarantineCode::CleanupTimeout))
    );
    assert_eq!(
        BridgeStatus::Unavailable(UnavailableCode::AssetIntegrity).admission(),
        Err(BridgeError::Unavailable(UnavailableCode::AssetIntegrity))
    );
    assert_eq!(BridgeStatus::after(None), BridgeStatus::Ready);
    for code in [
        UnavailableCode::LoopbackChanged,
        UnavailableCode::AssetIntegrity,
        UnavailableCode::GenerationExhausted,
    ] {
        assert_eq!(
            BridgeStatus::after(Some(BridgeError::Unavailable(code))),
            BridgeStatus::Unavailable(code)
        );
    }
    assert_eq!(
        BridgeStatus::after(Some(BridgeError::Unavailable(
            UnavailableCode::RngUnavailable
        ))),
        BridgeStatus::Ready
    );
    assert_eq!(
        BridgeStatus::after(Some(BridgeError::Quarantine(
            QuarantineCode::ControllerCloseFailed
        ))),
        BridgeStatus::Quarantined(QuarantineCode::ControllerCloseFailed)
    );
    assert_eq!(
        BridgeStatus::after(Some(BridgeError::Protocol(ProtocolCode::Malformed))),
        BridgeStatus::Ready
    );
    assert_eq!(BridgeStatus::after_restart(None), BridgeStatus::Ready);
    for code in [
        UnavailableCode::InterfaceUnavailable,
        UnavailableCode::RngUnavailable,
        UnavailableCode::LoopbackChanged,
    ] {
        assert_eq!(
            BridgeStatus::after_restart(Some(BridgeError::Unavailable(code))),
            BridgeStatus::Unavailable(code)
        );
    }
    assert_eq!(
        BridgeStatus::after_restart(Some(BridgeError::Quarantine(
            QuarantineCode::StaleProcessPresent
        ))),
        BridgeStatus::Quarantined(QuarantineCode::StaleProcessPresent)
    );
    assert_eq!(
        BridgeStatus::after_restart(Some(BridgeError::Protocol(ProtocolCode::Malformed))),
        BridgeStatus::Ready
    );
}

#[test]
fn secrets_are_redacted_wiped_and_compared_in_constant_time() {
    let slot = Zeroizing::new([7_u8; 32]);
    let prf = PrfOutput::new(&slot);
    assert_eq!(format!("{prf:?}"), "PrfOutput(<redacted>)");
    assert_eq!(prf.as_bytes(), &[7; 32]);
    let (one, other) = (
        RootFingerprint::from_bytes([1; 32]),
        RootFingerprint::from_bytes([2; 32]),
    );
    assert!(one.constant_time_eq(&RootFingerprint::from_bytes([1; 32])));
    assert!(!one.constant_time_eq(&other));
    assert_eq!(one.as_bytes(), &[1; 32]);
}

#[test]
fn a_verified_result_converts_only_to_its_own_kind() {
    let assertion = Verified::Assertion(Assertion {
        sign_count: 1,
        backup_state: false,
    });
    assert_eq!(
        assertion.clone().into_assertion(),
        Ok(Assertion {
            sign_count: 1,
            backup_state: false
        })
    );
    assert_eq!(
        assertion.into_registration().err(),
        Some(BridgeError::Protocol(ProtocolCode::KindMismatch))
    );
}

#[test]
fn the_folder_name_is_the_lowercase_hex_ceremony_id() {
    assert_eq!(
        folder_name(&CeremonyId::from_bytes(bytes16(0))),
        "000102030405060708090a0b0c0d0e0f"
    );
    assert_eq!(
        folder_name(&CeremonyId::from_bytes([0xab; 16])),
        "ab".repeat(16)
    );
}

#[test]
fn the_signer_handles_long_credential_ids_synced_backups_and_oversized_fields() -> TestResult {
    let id = CeremonyId::from_bytes(bytes16(0));
    let challenge = WebAuthnChallenge::from_bytes(bytes32(0x20));
    let long = FixtureSigner::new(&[7; 300]).boxed()?;
    let synced = ReplyShape {
        backup: Backup::Synced,
        ..ReplyShape::honest(0, Some(bytes32(1)))
    };
    assert!(long.attestation_payload(id, &challenge, &synced).is_ok());
    let oversized = FixtureSigner::new(&[7; 1_025]).boxed()?;
    assert!(oversized
        .attestation_payload(id, &challenge, &synced)
        .is_err());
    let custom = FixtureSigner::with_scalars(&FIXTURE_SCALAR, &OTHER_SCALAR, &[1]).boxed()?;
    assert_eq!(custom.credential_id(), [1]);
    Ok(())
}

fn crafted_pair(request_payload: &[u8]) -> Result<Buffers, Box<dyn std::error::Error>> {
    let id = CeremonyId::from_bytes(bytes16(0));
    let header = OwnerBridgeControlV1::new_request(CeremonyKind::Create, 1, id, 1).boxed()?;
    let mut request = vec![0; 4_096];
    let (head, payload) = request.split_at_mut(64);
    head.copy_from_slice(&header.encode());
    payload
        .get_mut(..request_payload.len())
        .ok_or("payload too long")?
        .copy_from_slice(request_payload);
    let reply_header = OwnerBridgeControlV1::new_reply(CeremonyKind::Create, 1, id).boxed()?;
    let mut reply = vec![0; 73_728];
    reply
        .split_at_mut(64)
        .0
        .copy_from_slice(&reply_header.encode());
    let mut buffers = Buffers::default();
    buffers.add_pair(Pair {
        generation: 1,
        ceremony_id: bytes16(0),
        request,
        payload: Vec::new(),
        reply,
        state: 0,
        state_changed_at: Duration::ZERO,
        host_closed: false,
        delivered: [false; 2],
        released: [false; 2],
    });
    Ok(buffers)
}

#[test]
fn a_page_releases_a_pair_whose_request_payload_cannot_be_decoded() -> TestResult {
    let mut buffers = crafted_pair(&[0xff])?;
    let mut page = HonestPage::new(honest(0)).boxed()?;
    page.on_script_start(&mut buffers, Duration::ZERO);
    page.on_post(&mut buffers, Duration::ZERO, 0);
    page.advance(&mut buffers, Duration::from_millis(1));
    let pair = buffers.pair_at(0);
    assert_eq!(pair.delivered, [true, true]);
    assert_eq!(pair.released, [true, true]);
    assert_eq!(pair.state, 0);
    assert!(!buffers
        .log
        .iter()
        .any(|entry| matches!(entry, LogEntry::PageWebAuthn { .. })));
    assert_eq!(buffers.pair_at(9).generation, 0);
    assert_eq!(buffers.state_of(9), None);
    Ok(())
}

#[test]
fn page_mutations_on_a_missing_pair_are_ignored() {
    let mut buffers = Buffers::default();
    buffers.store(Actor::Page, 3, 5);
    buffers.deliver(3, Role::Reply);
    buffers.release(3, Role::Request);
    buffers.write_payload(3, &[1]);
    buffers.set_reply_word(3, 0, 1);
    buffers.set_reply_byte(3, 0, 1);
    buffers.zero_reply_payload(3);
    buffers.teardown_page();
    assert!(!buffers.cas(Actor::Host, 3, 0, 1));
    assert!(buffers.pairs.is_empty());
    assert_eq!(buffers.next_event_time(), None);
    assert_eq!(buffers.take_due(Duration::MAX), None);
    buffers.schedule(Duration::from_secs(1), SurfaceEvent::FrameCreated);
    assert_eq!(buffers.next_event_time(), Some(Duration::from_secs(1)));
    assert_eq!(buffers.take_due(Duration::ZERO), None);
    assert_eq!(
        buffers.take_due(Duration::from_secs(1)),
        Some(SurfaceEvent::FrameCreated)
    );
}
