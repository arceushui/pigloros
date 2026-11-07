#![cfg(windows)]
#![forbid(unsafe_code)]

use std::cell::Cell;
use std::io::Write as _;
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
use crate::{
    BufferSlot, EventSink, NativeFactory, NativeOperations, NativePulse, NativeResult, StaPump,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn record_resource_outcome(
    value: u8,
    expected: u32,
    before: (u32, u64),
    listener: &LoopbackListener,
    baseline: u64,
) -> std::io::Result<bool> {
    let after = (
        listener.served().count,
        listener.received_request_count() - baseline,
    );
    writeln!(std::io::stderr(),
        "PROTOTYPE resource case={value} expected={expected} before={before:?} after={after:?} exited=true")?;
    Ok(after == (expected, u64::from(expected)))
}

const fn resource_cases() -> [(u8, bool, crate::ResourceDenialFixture, u32); 9] {
    use crate::ResourceDenialFixture::{
        Normal, PropagateFailure, PrototypeCloseFirst, PrototypeCompleteAllowed,
        PrototypeCompleteDenied, PrototypeDrop, PrototypeHeld, SwallowFailure,
    };
    [
        (0x20, false, Normal, 1),
        (0x21, true, Normal, 0),
        (0x22, true, SwallowFailure, 1),
        // PROTOTYPE: actual e1a3 observation, not a containment fix.
        (0x23, true, PropagateFailure, 1),
        (0x25, true, PrototypeCompleteAllowed, 1),
        (0x26, true, PrototypeCompleteDenied, 0),
        (0x28, true, PrototypeCloseFirst, 0),
        (0x24, true, PrototypeHeld, 0),
        (0x27, true, PrototypeDrop, 0),
    ]
}

const fn resource_stays_deferred(mode: crate::ResourceDenialFixture) -> bool {
    matches!(
        mode,
        crate::ResourceDenialFixture::PrototypeHeld
            | crate::ResourceDenialFixture::PrototypeDrop
            | crate::ResourceDenialFixture::PrototypeCloseFirst
    )
}

fn restore_denial(
    native: &mut dyn NativeOperations,
    mode: crate::ResourceDenialFixture,
) -> TestResult {
    if mode == crate::ResourceDenialFixture::PrototypeHeld {
        assert!(native.unsubscribe_view().is_err());
        assert!(native.close_controller().is_err());
        crate::Native::prototype_complete_resource(true)?;
    }
    Ok(())
}

struct ResourceProbe {
    policy: Events,
    deny: bool,
    requested: Cell<bool>,
    completed: Cell<bool>,
    failures: Cell<u32>,
}

impl ResourceProbe {
    fn new(deny: bool) -> Self {
        Self {
            policy: Events::default(),
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

struct FixtureRoot(PathBuf);

impl FixtureRoot {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
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
}

impl Drop for FixtureRoot {
    fn drop(&mut self) {
        let _removed = std::fs::remove_dir_all(&self.0);
    }
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

/// Real SDK ownership and mappings, with deliberately malformed input and
/// bounded host cleanup without a page acknowledgement. Malformed CBOR is
/// discarded before EMPTY -> RECEIVED, so it cannot produce FAILED/RELEASING.
impl crate::Native {
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
        let mut verdicts = Vec::new();
        for (value, deny, mode, served) in resource_cases() {
            let _mode = ResourceProbeGuard::new(mode);
            let received_before = listener.received_request_count();
            let folder = root
                .0
                .join(pos_owner_bridge::folder_name(&CeremonyId::from_bytes(
                    [value; 16],
                )));
            crate::create_private_directory(&folder)?;
            let mut native = factory.session()?;
            native.create_window(None, 480, 640)?;
            let probe = Rc::new(ResourceProbe::new(deny));
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
            pump_until(&factory, "prototype resource callback", || {
                probe.requested.get()
            })?;
            if matches!(
                mode,
                crate::ResourceDenialFixture::PrototypeCompleteAllowed
                    | crate::ResourceDenialFixture::PrototypeCompleteDenied
            ) {
                Self::prototype_complete_resource(
                    mode == crate::ResourceDenialFixture::PrototypeCompleteDenied,
                )?;
            }
            if !resource_stays_deferred(mode) {
                pump_until(
                    &factory,
                    "resource callback and navigation completion",
                    || probe.requested.get() && probe.completed.get(),
                )?;
            }
            if served == 1 {
                pump_until(&factory, "positive control reaching the listener", || {
                    listener.served().count == 1
                })?;
            }
            let before = (
                listener.served().count,
                listener.received_request_count() - received_before,
            );
            if mode != crate::ResourceDenialFixture::Normal {
                assert!(probe.failures.get() > 0);
            }
            restore_denial(native.as_mut(), mode)?;
            if mode != crate::ResourceDenialFixture::PrototypeCloseFirst {
                native.unsubscribe_view()?;
            }
            native.close_controller()?;
            pump_until(&factory, "resource browser exit", || {
                probe.policy.exited() == Some(identity.browser_pid)
            })?;
            verdicts.push(record_resource_outcome(
                value,
                served,
                before,
                &listener,
                received_before,
            )?);
            native.unsubscribe_exit()?;
            native.drop_environment()?;
            native.destroy_window()?;
        }
        factory.stop()?;
        listener.shutdown();
        assert!(verdicts.into_iter().all(std::convert::identity));
        Ok(())
    }

    pub(crate) fn native_host_lifecycle() -> TestResult {
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
                let loopback = super::loopback::SharedLoopback::start()?;
                crate::WindowsOwnerHost::spawn(runtime, root.0.clone(), loopback, store.clone())?
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
            );
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
        let mut native = factory.session()?;
        empty_session(native.as_mut());
        native.create_window(None, 480, 640)?;
        assert!(native.create_window(None, 480, 640).is_err());
        let window = native.window()?;
        assert!(window.exists);
        assert!(window.dpi > 0);
        native.resize_window(480, 640, window.dpi)?;
        let events = Rc::new(Events::default());
        let sink: Rc<dyn EventSink> = events.clone();
        native.create_environment(runtime.root(), &folder, super::settings::OPTIONS, sink)?;
        assert!(native.pending());
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
        Ok(())
    }
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
    native.create_buffers(CeremonyKind::Create, &request, &reply_header)?;
    assert!(native
        .create_buffers(CeremonyKind::Create, &request, &reply_header)
        .is_err());
    assert_eq!(native.load_state()?, ControlState::Empty as u32);
    assert!(native.compare_exchange(ControlState::Empty as u32, ControlState::Writing as u32)?);
    assert!(!native.compare_exchange(ControlState::Empty as u32, ControlState::Failed as u32)?);
    assert!(native.compare_exchange(ControlState::Writing as u32, ControlState::Empty as u32)?);
    let mut copied = ReplyImage::zeroed();
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
