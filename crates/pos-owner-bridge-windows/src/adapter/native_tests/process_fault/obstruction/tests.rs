#![cfg(windows)]
#![forbid(unsafe_code)]

use std::rc::Rc;

use pos_owner_bridge::fake::clock::FakeClock;
use pos_owner_bridge::ReplyImage;
use pos_owner_bridge_codec::CeremonyKind;

use super::{ObstructionFactory, ObstructionSession};
use crate::adapter::events::Events;
use crate::adapter::native_tests::{FixtureRoot, TestResult};
use crate::adapter::surface::tests::native::{Creation, Factory};
use crate::{BoolProperty, BufferSlot, NativeFactory, NativeOperations, NativePulse, StaPump};

#[test]
fn obstruction_delegates_the_native_contract_to_the_owned_model() -> TestResult {
    let root = FixtureRoot::new()?;
    let folder = root.0.join("obstructed-model");
    crate::create_private_directory(&folder)?;
    let model = Factory::new(Creation::Ready, FakeClock::start());
    let mut factory = ObstructionFactory::new(Rc::clone(&model), folder.clone());
    assert_eq!(factory.next()?, NativePulse::Timer);
    let mut session = factory.session()?;
    session.create_window(None, 480, 640)?;
    assert!(session.window()?.exists);
    session.resize_window(480, 640, 96)?;
    session.show_window()?;
    session.fit_controller()?;
    session.focus_controller()?;
    session.create_environment(
        &root.0,
        &folder,
        crate::adapter::settings::OPTIONS,
        Rc::new(Events::default()),
    )?;
    assert!(folder.join("EBWebView").is_file());
    assert!(session.pending());
    assert!(session.environment_creation_completion().is_none());
    session
        .environment_completion()
        .ok_or("missing modeled environment completion")??;
    assert_eq!(session.environment()?.folder.as_path(), folder);
    session.create_controller()?;
    session
        .controller_completion()
        .ok_or("missing modeled controller completion")??;
    assert!(session.has_controller()?);
    assert!(!session.pending());
    assert_eq!(session.browser_pid()?, 42);
    session.require_shared_interfaces()?;
    session.subscribe_view(Rc::new(Events::default()))?;
    session.set_bool(BoolProperty::Script, true)?;
    assert!(session.get_bool(BoolProperty::Script)?);
    assert!(session.navigate_owner().is_err());
    assert_eq!(session.source()?.as_str(), crate::OWNER_URL);
    session.create_buffers(CeremonyKind::Create, &[0; 64], &[0; 64])?;
    session.post(BufferSlot::Reply)?;
    session.post(BufferSlot::Request)?;
    assert_eq!(session.load_state()?, 0);
    assert!(session.compare_exchange(0, 7)?);
    assert_eq!(session.load_state()?, 7);
    let mut reply = ReplyImage::zeroed();
    session.copy_reply(&mut reply)?;
    assert!(reply.as_bytes().iter().all(|byte| *byte == 0x5a));
    session.close_buffers()?;
    assert!(!session.buffer_close_uncertain());
    session.unsubscribe_view()?;
    session.close_controller()?;
    assert!(!session.has_controller()?);
    session.unsubscribe_exit()?;
    session.drop_environment()?;
    session.destroy_window()?;
    drop(session);
    factory.stop()?;
    let calls = model.calls.borrow();
    for expected in [
        "create_window",
        "resize_window",
        "show_window",
        "fit_controller",
        "focus_controller",
        "create_environment",
        "require_shared_interfaces",
        "subscribe_view",
        "navigate",
        "create_buffers",
        "post_reply",
        "post_request",
        "close_buffers",
        "unsubscribe_view",
        "close_controller",
        "unsubscribe_exit",
        "drop_environment",
        "destroy_window",
    ] {
        assert!(calls.contains(&expected), "missing delegation {expected}");
    }
    drop(calls);
    root.remove()
}

#[test]
fn obstruction_preserves_fail_closed_defaults_for_unsupported_fault_capabilities() -> TestResult {
    let model = Factory::new(Creation::Ready, FakeClock::start());
    let session = ObstructionSession {
        inner: model.session()?,
        expected: std::path::PathBuf::new(),
    };
    assert!(session.environment_creation_completion().is_none());
    assert!(session.early_renderer_presence().is_err());
    assert!(!session.pending_opening_owners_retained());
    assert!(session.pending_opening_browser_candidate().is_err());
    assert!(session.recordless_controller_completion().is_none());
    assert!(!session.preload_fault_owners_retained());
    assert!(!session.exit_fault_owners_retained());
    assert!(session.recordless_browser_candidate().is_err());
    assert!(!session.recordless_fault_owners_retained());
    assert!(!session.fault_owners_retained());
    Ok(())
}
