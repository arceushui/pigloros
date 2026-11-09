#![cfg(windows)]
#![forbid(unsafe_code)]

use std::cell::Cell;
use std::path::Path;
use std::rc::Rc;

use pos_owner_bridge::listener::{FixtureProfile, ListenerConfig, LoopbackListener};
use pos_owner_bridge::LoopbackPort;

use super::{completion, pump_until, session, Events, TestResult};
use crate::{
    ControlFault, ControlObservation, EventKind, EventSink, NativeAction, NativeError, NativeEvent,
    StaPump,
};

struct Probe {
    events: Rc<Events>,
    kind: EventKind,
    delivered: Cell<bool>,
    failures: Cell<u32>,
}

impl EventSink for Probe {
    fn event(&self, event: NativeEvent) -> NativeAction {
        let kind = match &event {
            NativeEvent::NewWindow => Some(EventKind::NewWindow),
            NativeEvent::Permission => Some(EventKind::Permission),
            NativeEvent::Download => Some(EventKind::Download),
            NativeEvent::ExternalUri => Some(EventKind::ExternalUri),
            NativeEvent::Authentication => Some(EventKind::Authentication),
            NativeEvent::Navigation { uri, .. } if uri.as_str() != crate::OWNER_URL => {
                Some(EventKind::Navigation)
            }
            _ => None,
        };
        if kind == Some(self.kind) {
            self.delivered.set(true);
        }
        self.events.event(event)
    }

    fn failed(&self, kind: EventKind, error: NativeError) -> NativeAction {
        self.failures.set(self.failures.get() + 1);
        self.events.failed(kind, error)
    }
}

pub(super) struct Fault;

impl Fault {
    pub(super) fn new(kind: EventKind, mode: ControlFault) -> Self {
        crate::Native::set_control_fault(kind, mode);
        Self
    }
}

impl Drop for Fault {
    fn drop(&mut self) {
        crate::Native::set_control_fault(EventKind::NewWindow, ControlFault::Normal);
    }
}

const CASES: [(FixtureProfile, EventKind, ControlFault); 9] = [
    (
        FixtureProfile::Popup,
        EventKind::NewWindow,
        ControlFault::Normal,
    ),
    (
        FixtureProfile::Permission,
        EventKind::Permission,
        ControlFault::Normal,
    ),
    (
        FixtureProfile::Download,
        EventKind::Download,
        ControlFault::Normal,
    ),
    (
        FixtureProfile::External,
        EventKind::ExternalUri,
        ControlFault::Normal,
    ),
    (
        FixtureProfile::Authentication,
        EventKind::Authentication,
        ControlFault::Normal,
    ),
    (
        FixtureProfile::Navigation,
        EventKind::Navigation,
        ControlFault::Normal,
    ),
    (
        FixtureProfile::Popup,
        EventKind::NewWindow,
        ControlFault::RetryDenial,
    ),
    (
        FixtureProfile::Popup,
        EventKind::NewWindow,
        ControlFault::MissingDeferral,
    ),
    (
        FixtureProfile::Popup,
        EventKind::NewWindow,
        ControlFault::UncertainComplete,
    ),
];

pub(super) fn run(runtime_path: &Path, root: &Path) -> TestResult {
    let runtime = crate::verify_fixed_runtime(runtime_path, root)?;
    let mut factory = crate::Native::owner_factory()?;
    for (index, (profile, kind, mode)) in CASES.into_iter().enumerate() {
        let _fault = Fault::new(kind, mode);
        let folder = root.join(format!("control-{index}"));
        crate::create_private_directory(&folder)?;
        let mut listener = LoopbackListener::start(
            Box::new(crate::WindowsLoopbackBinder::default()),
            ListenerConfig::fixture(profile),
        )?;
        let events = Rc::new(Events::default());
        let probe = Rc::new(Probe {
            events: Rc::clone(&events),
            kind,
            delivered: Cell::new(false),
            failures: Cell::new(0),
        });
        let mut native = session::Session::new(&factory, events)?;
        native.create_window(None, 480, 640)?;
        let sink: Rc<dyn EventSink> = probe.clone();
        native.create_environment(
            runtime.root(),
            &folder,
            super::super::settings::OPTIONS,
            sink,
        )?;
        completion(&factory, "control environment", || {
            native.environment_completion()
        })?;
        native.create_controller()?;
        completion(&factory, "control controller", || {
            native.controller_completion()
        })?;
        let identity = runtime.browser_identity(native.browser_pid()?)?;
        native.require_shared_interfaces()?;
        let sink: Rc<dyn EventSink> = probe.clone();
        native.subscribe_view(sink)?;
        super::super::settings::apply(native.as_ref())
            .map_err(pos_owner_bridge::SurfaceError::error)?;
        listener.begin_navigation();
        probe.events.begin();
        native.navigate_owner()?;
        pump_until(&factory, "actual native control callback", || {
            probe.delivered.get()
        })?;
        if mode == ControlFault::RetryDenial {
            for attempts in [2, 3] {
                // Repeated teardown and event-drain calls in one progression
                // cannot authorize extra retries or release any owner.
                for _ in 0..3 {
                    assert!(native.unsubscribe_view().is_err());
                    assert!(native.close_controller().is_err());
                    let observations = crate::Native::control_observations();
                    assert_eq!(observations.len(), 1);
                    assert!(observations[0].deferred);
                    assert_eq!(observations[0].attempts, attempts);
                    assert_eq!(observations[0].completions, 0);
                    assert!(!observations[0].retired);
                }
                factory.next()?;
            }
        }
        native.unsubscribe_view()?;
        let before_exit = crate::Native::control_observations();
        native.close_controller()?;
        pump_until(&factory, "control own browser exit", || {
            probe.events.exited() == Some(identity.browser_pid)
        })?;
        let after_exit = crate::Native::control_observations();
        // Every assertion after observing actual retirement; Session also
        // retains on every error/unwind before this point.
        assert_denials(&before_exit, &after_exit, kind, mode);
        assert_eq!(
            probe.failures.get(),
            match mode {
                ControlFault::Normal => 0,
                ControlFault::RetryDenial => 3,
                ControlFault::MissingDeferral | ControlFault::UncertainComplete => 1,
            }
        );
        assert!(listener.received_request_count() >= 1);
        assert!(listener.served().integrity_ok);
        native.unsubscribe_exit()?;
        native.drop_environment()?;
        native.destroy_window()?;
        drop(native);
        listener.shutdown();
    }
    factory.stop()?;
    drop(factory);
    let composed_root = root.join("composed-control");
    crate::create_private_directory(&composed_root)?;
    super::denial::run_control(runtime_path, &composed_root)?;
    Ok(())
}

fn assert_denials(
    before_exit: &[ControlObservation],
    after_exit: &[ControlObservation],
    kind: EventKind,
    mode: ControlFault,
) {
    assert!(!before_exit.is_empty());
    assert_eq!(before_exit.len(), after_exit.len());
    for (before, after) in before_exit.iter().zip(after_exit) {
        assert_eq!(before.kind, kind);
        assert_eq!(before.readback, Some(true));
        assert_eq!(
            before.attempts,
            if mode == ControlFault::RetryDenial {
                4
            } else {
                1
            }
        );
        assert_eq!(
            before.deferred,
            kind != EventKind::Navigation && mode != ControlFault::MissingDeferral
        );
        assert_eq!(before.completions, u32::from(before.deferred));
        assert_eq!(before.retired, mode != ControlFault::UncertainComplete);
        assert!(after.retired);
        assert_eq!(after.completions, before.completions);
    }
}
