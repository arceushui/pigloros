#![cfg(windows)]
#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::rc::Rc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use pos_owner_bridge::listener::{ListenerConfig, LoopbackListener};
use pos_owner_bridge::{LoopbackPort, ReplyImage};
use pos_owner_bridge_codec::{CeremonyId, CeremonyKind, ControlState, OwnerBridgeControlV1};

use super::events::Events;
use crate::native_api::{
    BufferSlot, EventSink, NativeFactory, NativeOperations, NativePulse, NativeResult, StaPump,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

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

fn pump_until(factory: &dyn StaPump, mut observed: impl FnMut() -> bool) -> TestResult {
    let deadline = Instant::now() + Duration::from_secs(15);
    while !observed() {
        if Instant::now() >= deadline {
            return Err("native fixture deadline expired".into());
        }
        if factory.next()? == NativePulse::Quit {
            return Err("native fixture received quit".into());
        }
    }
    Ok(())
}

fn completion(
    factory: &dyn StaPump,
    mut take: impl FnMut() -> Option<NativeResult<()>>,
) -> TestResult {
    let mut result = None;
    pump_until(factory, || {
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

/// Real SDK ownership and mappings, with malformed fixture input that the
/// packaged page refuses before any authenticator request can begin.
pub(crate) fn native_window_environment_and_buffers_lifecycle() -> TestResult {
    let _port = crate::tests::fixed_port_fixture();
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
    let mut factory = crate::Native::owner_factory()?;
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
    completion(&factory, || native.environment_completion())?;
    let snapshot = native.environment()?;
    assert_eq!(snapshot.version.as_str(), "153.0.4234.48");
    assert_eq!(
        snapshot.folder.as_path().canonicalize()?,
        folder.canonicalize()?
    );
    super::settings::verify_options(&snapshot).map_err(pos_owner_bridge::SurfaceError::error)?;
    let sink: Rc<dyn EventSink> = events.clone();
    assert!(native
        .create_environment(runtime.root(), &folder, super::settings::OPTIONS, sink)
        .is_err());
    native.create_controller()?;
    completion(&factory, || native.controller_completion())?;
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
    pump_until(&factory, || events.loaded().is_some())?;
    assert!(!events.invalid());
    assert_eq!(listener.served().count, 1);
    assert_eq!(native.source()?.as_str(), crate::native_api::OWNER_URL);
    exercise_buffers(&factory, native.as_mut())?;
    native.unsubscribe_view()?;
    native.unsubscribe_view()?;
    native.close_controller()?;
    native.close_controller()?;
    pump_until(&factory, || events.exited() == Some(identity.browser_pid))?;
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

fn exercise_buffers(factory: &dyn StaPump, native: &mut dyn NativeOperations) -> TestResult {
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
    let mut observed = Ok(0);
    pump_until(factory, || {
        observed = native.load_state();
        observed
            .as_ref()
            .is_ok_and(|value| *value == ControlState::Failed as u32)
    })?;
    assert_eq!(observed?, ControlState::Failed as u32);
    assert!(native.compare_exchange(
        ControlState::Failed as u32,
        ControlState::ReleaseRequested as u32
    )?);
    pump_until(factory, || {
        native
            .load_state()
            .is_ok_and(|value| value == ControlState::Releasing as u32)
    })?;
    native.close_buffers()?;
    native.close_buffers()?;
    assert!(native.load_state().is_err());
    Ok(())
}
