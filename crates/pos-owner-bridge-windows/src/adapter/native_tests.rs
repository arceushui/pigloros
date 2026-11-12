#![cfg(windows)]
#![forbid(unsafe_code)]

use std::cell::Cell;
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use pos_owner_bridge::ceremony::driver::CeremonyDriver;
use pos_owner_bridge::ceremony::plan::CeremonyPlan;
use pos_owner_bridge::ceremony::timing::RELEASE_WINDOW;
use pos_owner_bridge::listener::{ListenerConfig, LoopbackListener};
use pos_owner_bridge::{CeremonyHost, CleanupStore, LoopbackPort, ReplyImage};
use pos_owner_bridge_codec::{
    CeremonyId, CeremonyKind, ControlState, OwnerBridgeControlV1, OwnerUserHandle, PrfInput,
    WebAuthnChallenge,
};

use super::events::Events;
use crate::{BufferSlot, EventSink, NativeOperations, NativePulse, NativeResult, StaPump};

pub(in crate::adapter) type TestResult = Result<(), Box<dyn std::error::Error>>;

mod controls;
mod denial;
mod foreground;
mod process_fault;
mod readiness;
mod retirement;
mod session;
mod trace;

fn assert_resource_counts(listener: &LoopbackListener, before: u64, expected: u32) {
    assert_eq!(
        listener.served().count,
        expected,
        "unexpected completed resource response"
    );
    assert_eq!(
        listener.received_request_count() - before,
        u64::from(expected),
        "unexpected request bytes reached the listener"
    );
}

struct ResourceProbe {
    policy: Rc<Events>,
    deny: bool,
    requested: Cell<bool>,
    completed: Cell<bool>,
    failures: Cell<u32>,
}

impl ResourceProbe {
    fn new(deny: bool) -> Self {
        Self {
            policy: Rc::new(Events::default()),
            deny,
            requested: Cell::new(false),
            completed: Cell::new(false),
            failures: Cell::new(0),
        }
    }
}

impl EventSink for ResourceProbe {
    fn event(&self, event: crate::NativeEvent) -> crate::NativeAction {
        if matches!(&event, crate::NativeEvent::Resource { document: true, .. }) {
            self.requested.set(true);
            if self.deny {
                return crate::NativeAction::BlockResource;
            }
        }
        if matches!(&event, crate::NativeEvent::NavigationCompleted { .. }) {
            self.completed.set(true);
        }
        self.policy.event(event)
    }
    fn failed(&self, kind: crate::EventKind, error: crate::NativeError) -> crate::NativeAction {
        self.failures.set(self.failures.get() + 1);
        self.policy.failed(kind, error)
    }
}

struct ResourceProbeGuard;
impl ResourceProbeGuard {
    fn new(mode: crate::ResourceDenialFixture) -> Self {
        crate::Native::set_resource_denial_fixture(mode);
        Self
    }
}
impl Drop for ResourceProbeGuard {
    fn drop(&mut self) {
        crate::Native::set_resource_denial_fixture(crate::ResourceDenialFixture::Normal);
    }
}

const RESOURCE_CASES: [(u8, bool, crate::ResourceDenialFixture, u32); 7] = [
    (0x20, false, crate::ResourceDenialFixture::Normal, 1),
    (0x21, true, crate::ResourceDenialFixture::Normal, 0),
    // Reproduce the former swallowed error against the real pinned listener.
    (0x22, true, crate::ResourceDenialFixture::SwallowFailure, 1),
    (
        0x23,
        true,
        crate::ResourceDenialFixture::PropagateFailure,
        0,
    ),
    (0x24, true, crate::ResourceDenialFixture::RetryStop, 0),
    (
        0x25,
        true,
        crate::ResourceDenialFixture::UncertainComplete,
        0,
    ),
    (0x26, true, crate::ResourceDenialFixture::MissingDeferral, 0),
];

pub(in crate::adapter) struct FixtureRoot(pub(in crate::adapter) PathBuf);

impl FixtureRoot {
    pub(in crate::adapter) fn new() -> Result<Self, Box<dyn std::error::Error>> {
        static SEQUENCE: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "piglor-native-{}-{}-{}",
            std::process::id(),
            SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        crate::create_private_directory(&path)?;
        Ok(Self(path))
    }

    // Only successful, explicitly retired fixtures may erase recovery metadata.
    // Errors and unwinds leave the protected root available for diagnosis/restart.
    pub(in crate::adapter) fn remove(self) -> TestResult {
        std::fs::remove_dir_all(self.0)?;
        Ok(())
    }
}

#[test]
fn failed_fixture_preserves_recovery_files_until_explicit_retirement() -> TestResult {
    fn failing_fixture(root: FixtureRoot) -> TestResult {
        std::fs::metadata(&root.0)?;
        drop(root);
        Err("modeled fixture failure".into())
    }

    let root = FixtureRoot::new()?;
    let path = root.0.clone();
    let record = path.join("recovery-record");
    std::fs::write(&record, b"retained cleanup evidence")?;
    let failed = failing_fixture(root);
    assert!(failed.is_err());
    assert_eq!(std::fs::read(&record)?, b"retained cleanup evidence");
    FixtureRoot(path.clone()).remove()?;
    assert!(!path.exists());
    Ok(())
}

fn pump_until(
    factory: &dyn StaPump,
    stage: &str,
    mut observed: impl FnMut() -> bool,
) -> TestResult {
    let deadline = Instant::now() + Duration::from_secs(15);
    while !observed() {
        if Instant::now() >= deadline {
            return Err(
                format!("native fixture deadline expired while waiting for {stage}").into(),
            );
        }
        if factory.next()? == NativePulse::Quit {
            return Err(format!("native fixture received quit while waiting for {stage}").into());
        }
    }
    Ok(())
}

fn completion(
    factory: &dyn StaPump,
    stage: &str,
    mut take: impl FnMut() -> Option<NativeResult<()>>,
) -> TestResult {
    let mut result = None;
    pump_until(factory, stage, || {
        result = take();
        result.is_some()
    })?;
    result.ok_or("native completion disappeared")??;
    Ok(())
}

fn empty_session(native: &mut dyn NativeOperations) {
    assert!(native.window().is_err());
    assert!(native.resize_window(480, 640, 96).is_err());
    assert!(native.show_window().is_err());
    assert!(native.fit_controller().is_err());
    assert!(native.focus_controller().is_err());
    assert!(native.environment().is_err());
    assert!(native.create_controller().is_err());
    assert!(native.browser_pid().is_err());
    assert!(native.require_shared_interfaces().is_err());
    assert!(native.navigate_owner().is_err());
    assert!(native.source().is_err());
    assert!(native.load_state().is_err());
    assert!(native.compare_exchange(0, 1).is_err());
    assert!(native.copy_reply(&mut ReplyImage::zeroed()).is_err());
    assert!(native.post(BufferSlot::Request).is_err());
    assert!(native.post(BufferSlot::Reply).is_err());
    assert!(native.environment_completion().is_none());
    assert!(native.controller_completion().is_none());
    assert!(!native.pending());
    assert!(!native.buffer_close_uncertain());
}

fn hold_resource_denial(
    native: &mut dyn NativeOperations,
    factory: &dyn StaPump,
    listener: &LoopbackListener,
    received_before: u64,
) -> TestResult {
    for _ in 0..2 {
        // Only another existing STA progression permits another retry; every
        // teardown request within one progression must keep the owners held.
        for _ in 0..3 {
            assert!(native.unsubscribe_view().is_err());
            assert!(native.close_controller().is_err());
            assert_eq!(crate::Native::resource_deferral_completion_attempts(), 0);
        }
        factory.next()?;
        assert_resource_counts(listener, received_before, 0);
    }
    Ok(())
}

/// Real SDK ownership and mappings, with deliberately malformed input and
/// bounded host cleanup without a page acknowledgement. Malformed CBOR is
/// discarded before EMPTY -> RECEIVED, so it cannot produce FAILED/RELEASING.
impl crate::Native {
    pub(crate) fn native_delivery_adversaries() -> TestResult {
        let _port = Self::fixed_port_fixture();
        let root = FixtureRoot::new()?;
        let runtime = std::env::var_os("OWNER_BRIDGE_TEST_RUNTIME")
            .map(PathBuf::from)
            .ok_or("canonical retained runtime is required by delivery qualification")?;
        denial::run_delivery(&runtime, &root.0)?;
        root.remove()
    }

    pub(crate) fn native_readonly_renderer_failure() -> TestResult {
        let _port = Self::fixed_port_fixture();
        let root = FixtureRoot::new()?;
        let runtime = std::env::var_os("OWNER_BRIDGE_TEST_RUNTIME")
            .map(PathBuf::from)
            .ok_or("canonical retained runtime is required by renderer qualification")?;
        denial::run_renderer(&runtime, &root.0)?;
        root.remove()
    }

    pub(crate) fn native_control_denials() -> TestResult {
        let _port = Self::fixed_port_fixture();
        let root = FixtureRoot::new()?;
        let runtime = std::env::var_os("OWNER_BRIDGE_TEST_RUNTIME")
            .map(PathBuf::from)
            .ok_or("canonical retained runtime is required by control qualification")?;
        controls::run(&runtime, &root.0)?;
        root.remove()
    }

    pub(crate) fn native_resource_denial_failure() -> TestResult {
        let _port = Self::fixed_port_fixture();
        let root = FixtureRoot::new()?;
        let runtime_path = std::env::var_os("OWNER_BRIDGE_TEST_RUNTIME")
            .map(PathBuf::from)
            .ok_or("canonical retained runtime is required by resource denial fixture")?;
        let runtime = crate::verify_fixed_runtime(&runtime_path, &root.0)?;
        let mut listener = LoopbackListener::start(
            Box::new(crate::WindowsLoopbackBinder::default()),
            ListenerConfig::adr(),
        )?;
        let mut factory = Self::owner_factory()?;
        for (value, deny, mode, served) in RESOURCE_CASES {
            let _mode = ResourceProbeGuard::new(mode);
            let received_before = listener.received_request_count();
            let folder = root
                .0
                .join(pos_owner_bridge::folder_name(&CeremonyId::from_bytes(
                    [value; 16],
                )));
            crate::create_private_directory(&folder)?;
            let probe = Rc::new(ResourceProbe::new(deny));
            let mut native = session::Session::new(&factory, Rc::clone(&probe.policy))?;
            native.create_window(None, 480, 640)?;
            let sink: Rc<dyn EventSink> = probe.clone();
            native.create_environment(runtime.root(), &folder, super::settings::OPTIONS, sink)?;
            completion(&factory, "resource environment creation", || {
                native.environment_completion()
            })?;
            let snapshot = native.environment()?;
            assert_eq!(
                snapshot.folder.as_path().canonicalize()?,
                folder.canonicalize()?
            );
            assert_eq!(snapshot.version.as_str(), "153.0.4234.48");
            native.create_controller()?;
            completion(&factory, "resource controller creation", || {
                native.controller_completion()
            })?;
            let identity = runtime.browser_identity(native.browser_pid()?)?;
            probe.policy.expect_browser(identity.browser_pid);
            native.require_shared_interfaces()?;
            let sink: Rc<dyn EventSink> = probe.clone();
            native.subscribe_view(sink)?;
            super::settings::apply(native.as_ref())
                .map_err(pos_owner_bridge::SurfaceError::error)?;
            listener.begin_navigation();
            probe.policy.begin();
            native.navigate_owner()?;
            pump_until(&factory, "resource callback", || probe.requested.get())?;
            if mode == crate::ResourceDenialFixture::RetryStop {
                hold_resource_denial(native.as_mut(), &factory, &listener, received_before)?;
            }
            if matches!(
                mode,
                crate::ResourceDenialFixture::Normal | crate::ResourceDenialFixture::SwallowFailure
            ) {
                pump_until(&factory, "resource navigation completion", || {
                    probe.completed.get()
                })?;
            }
            if served == 1 {
                pump_until(&factory, "positive control reaching the listener", || {
                    listener.served().count == 1
                })?;
            }
            assert_resource_counts(&listener, received_before, served);
            if mode != crate::ResourceDenialFixture::Normal {
                assert!(probe.failures.get() > 0);
            }
            native.unsubscribe_view()?;
            native.close_controller()?;
            pump_until(&factory, "resource browser exit", || {
                probe.policy.exited() == Some(identity.browser_pid)
            })?;
            assert_resource_counts(&listener, received_before, served);
            let completions = u32::from(matches!(
                mode,
                crate::ResourceDenialFixture::PropagateFailure
                    | crate::ResourceDenialFixture::RetryStop
                    | crate::ResourceDenialFixture::UncertainComplete
            ));
            assert_eq!(Self::resource_deferral_completion_attempts(), completions);
            native.unsubscribe_exit()?;
            native.drop_environment()?;
            native.destroy_window()?;
        }
        factory.stop()?;
        drop(factory);
        listener.shutdown();
        drop(listener);
        let driver_root = root.0.join("resource-driver");
        crate::create_private_directory(&driver_root)?;
        denial::run(&runtime_path, &driver_root)?;
        root.remove()?;
        Ok(())
    }

    pub(crate) fn native_host_lifecycle(owner_window: u64) -> TestResult {
        let _port = Self::fixed_port_fixture();
        let root = FixtureRoot::new()?;
        let runtime_path = std::env::var_os("OWNER_BRIDGE_TEST_RUNTIME")
            .map(PathBuf::from)
            .ok_or("canonical retained runtime is required by the host fixture")?;
        let runtime = crate::verify_fixed_runtime(&runtime_path, &root.0)?;
        let mut store = crate::WindowsCleanupStore::open(root.0.clone())?;
        let mut host = match crate::WindowsOwnerHost::start(runtime, root.0.clone(), store.clone())
        {
            Ok(host) => host,
            Err(pos_owner_bridge::BridgeError::Unavailable(
                pos_owner_bridge::UnavailableCode::PlatformUnsupported,
            )) => {
                // Hosted Windows Server is deliberately refused by the public
                // desktop profile. Exercise the same STA worker beneath that
                // admission boundary without qualifying Server as a product OS.
                let runtime = crate::verify_fixed_runtime(&runtime_path, &root.0)?;
                crate::WindowsOwnerHost::start_fixture(runtime, root.0.clone(), store.clone())?
            }
            Err(error) => return Err(error.into()),
        };
        // A second host cannot acquire this host's exclusive listener.
        assert!(matches!(
            super::loopback::SharedLoopback::start(),
            Err(pos_owner_bridge::BridgeError::Unavailable(
                pos_owner_bridge::UnavailableCode::PortUnavailable
            ))
        ));
        for value in [0x10, 0x11] {
            // Narrow impossible-state injection: Get has no stored credential.
            // Opening, settings, real document navigation and durable recording
            // must finish before encoding rejects it, before any mapping or
            // authenticator call can exist. No fake credential adapter is used.
            let plan = CeremonyPlan::for_test(
                CeremonyKind::Get,
                CeremonyId::from_bytes([value; 16]),
                WebAuthnChallenge::from_bytes([1; 32]),
                OwnerUserHandle::from_bytes([2; 32]),
                PrfInput::from_bytes([3; 32]),
                Instant::now(),
            )
            .with_test_owner_window(owner_window);
            let reply = host.run(CeremonyDriver::for_test(plan));
            assert!(matches!(
                reply.result,
                Err(pos_owner_bridge::BridgeError::Protocol(
                    pos_owner_bridge::ProtocolCode::LengthOutOfBounds
                ))
            ));
            let driver = reply
                .driver
                .ok_or("completed host did not return its driver")?;
            assert!(driver.request_clear());
            assert!(store.records()?.is_empty());
            assert!(store.folders()?.is_empty());
            let poll = host.poll_quarantine();
            assert!(!poll.remaining && poll.driver.is_none());
        }
        drop(host);
        drop(store);
        root.remove()?;
        Ok(())
    }

    pub(crate) fn native_window_environment_and_buffers_lifecycle() -> TestResult {
        let _port = Self::fixed_port_fixture();
        let root = FixtureRoot::new()?;
        let runtime_path = std::env::var_os("OWNER_BRIDGE_TEST_RUNTIME")
            .map(PathBuf::from)
            .ok_or("canonical retained runtime is required by this native fixture")?;
        let runtime = crate::verify_fixed_runtime(&runtime_path, &root.0)?;
        let folder = root.0.join("01010101010101010101010101010101");
        crate::create_private_directory(&folder)?;
        let mut listener = LoopbackListener::start(
            Box::new(crate::WindowsLoopbackBinder::default()),
            ListenerConfig::adr(),
        )?;
        let mut factory = Self::owner_factory()?;
        let events = Rc::new(Events::default());
        let mut native = session::Session::new(&factory, Rc::clone(&events))?;
        empty_session(native.as_mut());
        native.create_window(None, 480, 640)?;
        assert!(native.create_window(None, 480, 640).is_err());
        let window = native.window()?;
        assert!(window.exists);
        assert!(window.dpi > 0);
        native.resize_window(480, 640, window.dpi)?;
        let sink: Rc<dyn EventSink> = events.clone();
        native.create_environment(runtime.root(), &folder, super::settings::OPTIONS, sink)?;
        assert!(native.pending());
        let closed = crate::NativeError {
            operation: crate::Operation::Controller,
            failure: crate::Failure::Closed,
        };
        assert_eq!(native.destroy_window(), Err(closed));
        assert!(native.pending());
        assert!(native.window()?.exists);
        assert!(!native.has_controller()?);
        completion(&factory, "environment creation", || {
            native.environment_completion()
        })?;
        let snapshot = native.environment()?;
        assert_eq!(snapshot.version.as_str(), "153.0.4234.48");
        assert_eq!(
            snapshot.folder.as_path().canonicalize()?,
            folder.canonicalize()?
        );
        super::settings::verify_options(&snapshot)
            .map_err(pos_owner_bridge::SurfaceError::error)?;
        let sink: Rc<dyn EventSink> = events.clone();
        assert!(native
            .create_environment(runtime.root(), &folder, super::settings::OPTIONS, sink)
            .is_err());
        native.create_controller()?;
        completion(&factory, "controller creation", || {
            native.controller_completion()
        })?;
        assert_eq!(native.destroy_window(), Err(closed));
        assert!(native.has_controller()?);
        assert!(native.window()?.exists);
        assert!(native.create_controller().is_err());
        let identity = runtime.browser_identity(native.browser_pid()?)?;
        events.expect_browser(identity.browser_pid);
        native.require_shared_interfaces()?;
        let sink: Rc<dyn EventSink> = events.clone();
        native.subscribe_view(sink)?;
        super::settings::apply(native.as_ref()).map_err(pos_owner_bridge::SurfaceError::error)?;
        native.fit_controller()?;
        native.show_window()?;
        native.focus_controller()?;
        listener.begin_navigation();
        events.begin();
        native.navigate_owner()?;
        pump_until(&factory, "owner document completion", || {
            events.loaded().is_some()
        })?;
        assert!(!events.invalid());
        assert_eq!(listener.served().count, 1);
        assert_eq!(native.source()?.as_str(), crate::OWNER_URL);
        exercise_unacknowledged_buffers(&factory, native.as_mut())?;
        exercise_packaged_get_receipt(&factory, native.as_mut())?;
        native.unsubscribe_view()?;
        native.unsubscribe_view()?;
        native.close_controller()?;
        native.close_controller()?;
        pump_until(&factory, "browser exit", || {
            events.exited() == Some(identity.browser_pid)
        })?;
        assert!(native.drop_environment().is_err()); // Exit subscription still owned.
        native.unsubscribe_exit()?;
        native.unsubscribe_exit()?;
        native.drop_environment()?;
        native.destroy_window()?;
        native.destroy_window()?;
        empty_session(native.as_mut());
        drop(native);
        factory.stop()?;
        listener.shutdown();
        drop(listener);
        readiness::run(&runtime_path, &root.0)?;
        root.remove()?;
        Ok(())
    }
}

fn exercise_packaged_get_receipt(
    factory: &dyn StaPump,
    native: &mut dyn NativeOperations,
) -> TestResult {
    let id = CeremonyId::from_bytes([1; 16]);
    let options = pos_owner_bridge_codec::GetOptionsV1::new(
        id,
        WebAuthnChallenge::from_bytes([2; 32]),
        &[0x80, 0x81],
        PrfInput::from_bytes([3; 32]),
    )
    .map_err(|error| error.to_string())?;
    let mut request = pos_owner_bridge::RequestImage::zeroed();
    let length =
        pos_owner_bridge_codec::encode_get_options(&options, &mut request.as_mut_bytes()[64..])
            .map_err(|error| error.to_string())?;
    receive_packaged_get(factory, native, &mut request, u32::try_from(length)?, id)?;
    // Receipt is transport evidence only. Immediately cancel the synthetic Get;
    // no authenticator result is needed or accepted by this fixture.
    let mut retired = false;
    for _ in 0..8 {
        let state = native.load_state()?;
        assert!([1, 2, 6, 7].contains(&state));
        if native.compare_exchange(state, ControlState::ReleaseRequested as u32)? {
            retired = true;
            break;
        }
    }
    assert!(
        retired,
        "packaged Get state did not retire within the fixed CAS bound"
    );
    let deadline = Instant::now() + RELEASE_WINDOW;
    while native.load_state()? != ControlState::Releasing as u32 && Instant::now() < deadline {
        if factory.next()? == NativePulse::Quit {
            return Err("native fixture quit while cancelling the synthetic Get".into());
        }
    }
    assert_eq!(native.load_state()?, ControlState::Releasing as u32);
    native.close_buffers()?;
    Ok(())
}

fn receive_packaged_get(
    factory: &dyn StaPump,
    native: &mut dyn NativeOperations,
    request: &mut pos_owner_bridge::RequestImage,
    length: u32,
    id: CeremonyId,
) -> TestResult {
    // Independent ADR110 receipt windows. The earlier malformed generation was
    // never accepted; every repost has a new mapping and a preserved retired header.
    for (attempt, millis) in [250, 250, 500, 500, 1_000, 1_000, 2_000, 2_000]
        .into_iter()
        .enumerate()
    {
        let generation = 2 + u32::try_from(attempt)?;
        let header = OwnerBridgeControlV1::new_request(CeremonyKind::Get, generation, id, length)
            .map_err(|error| error.to_string())?
            .encode();
        request.as_mut_bytes()[..64].copy_from_slice(&header);
        let reply = OwnerBridgeControlV1::new_reply(CeremonyKind::Get, generation, id)
            .map_err(|error| error.to_string())?
            .encode();
        native.create_buffers(CeremonyKind::Get, request.as_bytes(), &reply)?;
        assert_eq!(native.source()?.as_str(), crate::OWNER_URL);
        native.post(BufferSlot::Request)?;
        assert_eq!(native.source()?.as_str(), crate::OWNER_URL);
        native.post(BufferSlot::Reply)?;
        let deadline = Instant::now() + Duration::from_millis(millis);
        while native.load_state()? == ControlState::Empty as u32 && Instant::now() < deadline {
            if factory.next()? == NativePulse::Quit {
                return Err("native fixture quit before the packaged page accepted a pair".into());
            }
        }
        if native.load_state()? != ControlState::Empty as u32
            || !native.compare_exchange(
                ControlState::Empty as u32,
                ControlState::ReleaseRequested as u32,
            )?
        {
            return Ok(());
        }
        native.close_buffers()?;
    }
    Err("packaged page never accepted a Get pair within eight posts".into())
}

fn exercise_unacknowledged_buffers(
    factory: &dyn StaPump,
    native: &mut dyn NativeOperations,
) -> TestResult {
    let id = CeremonyId::from_bytes([1; 16]);
    let mut request = [0; 4096];
    request[..64].copy_from_slice(
        &OwnerBridgeControlV1::new_request(CeremonyKind::Create, 1, id, 1)
            .map_err(|error| error.to_string())?
            .encode(),
    );
    request[64] = 0xff; // Invalid closed CBOR, independent of WebAuthn hardware.
    let reply_header = OwnerBridgeControlV1::new_reply(CeremonyKind::Create, 1, id)
        .map_err(|error| error.to_string())?
        .encode();
    assert!(native
        .create_buffers(
            CeremonyKind::Create,
            &request[..request.len() - 1],
            &reply_header
        )
        .is_err());
    native.create_buffers(CeremonyKind::Create, &request, &reply_header)?;
    assert!(native
        .create_buffers(CeremonyKind::Create, &request, &reply_header)
        .is_err());
    assert_eq!(native.load_state()?, ControlState::Empty as u32);
    assert!(native.compare_exchange(ControlState::Empty as u32, ControlState::Writing as u32)?);
    assert!(!native.compare_exchange(ControlState::Empty as u32, ControlState::Failed as u32)?);
    assert!(native.compare_exchange(ControlState::Writing as u32, ControlState::Empty as u32)?);
    let mut copied = ReplyImage::zeroed();
    copied.select(CeremonyKind::Get);
    copied.as_mut_bytes().fill(0xa5);
    assert_eq!(
        native.copy_reply(&mut copied),
        Err(crate::NativeError {
            operation: crate::Operation::Buffers,
            failure: crate::Failure::CallFailed,
        })
    );
    assert!(copied.as_bytes().iter().all(|byte| *byte == 0xa5));
    copied.select(CeremonyKind::Create);
    native.copy_reply(&mut copied)?;
    assert_eq!(&copied.as_bytes()[..64], &reply_header);
    native.post(BufferSlot::Request)?;
    native.post(BufferSlot::Reply)?;
    // The packaged page releases a malformed pair without accepting it or
    // invoking WebAuthn. Retire it through the same EMPTY CAS and fixed release
    // window used when a page never acknowledges; do not invent a page write.
    assert!(native.compare_exchange(
        ControlState::Empty as u32,
        ControlState::ReleaseRequested as u32
    )?);
    let release_deadline = Instant::now() + RELEASE_WINDOW;
    while Instant::now() < release_deadline {
        assert_eq!(native.load_state()?, ControlState::ReleaseRequested as u32);
        if factory.next()? == NativePulse::Quit {
            return Err("native fixture received quit during unacknowledged release".into());
        }
    }
    native.close_buffers()?;
    native.close_buffers()?;
    assert!(native.load_state().is_err());
    Ok(())
}
