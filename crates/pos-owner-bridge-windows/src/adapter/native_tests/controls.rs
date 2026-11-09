#![cfg(windows)]
#![forbid(unsafe_code)]

use std::cell::{Cell, RefCell};
use std::io::Write as _;
use std::path::Path;
use std::rc::Rc;

use pos_owner_bridge::listener::{FixtureProfile, ListenerConfig, LoopbackListener};
use pos_owner_bridge::LoopbackPort;

use super::{completion, pump_until, session, Events, TestResult};
use crate::{
    ControlFault, ControlObservation, EventKind, EventSink, NativeAction, NativeError, NativeEvent,
    StaPump,
};

const EXTERNAL_URI: &str = "ms-settings:privacy-location";

// Held by one fresh Probe, whose sink is installed on one fresh owned view.
// The owner navigation ID binds the allowance to that document generation.
struct ExternalAllowance {
    generation: pos_owner_bridge::NavigationId,
}

struct Probe {
    events: Rc<Events>,
    kind: EventKind,
    delivered: Cell<bool>,
    failures: Cell<u32>,
    external_profile: bool,
    isolated_external: bool,
    allowance: RefCell<Option<ExternalAllowance>>,
    external_navigation_seen: Cell<bool>,
    unexpected_navigation: Cell<bool>,
}

impl Probe {
    fn external_navigation(&self, event: &NativeEvent) -> Option<NativeAction> {
        let NativeEvent::Navigation {
            uri, redirected, ..
        } = event
        else {
            return None;
        };
        if !self.external_profile || self.events.started().is_none() {
            return None;
        }
        let expected = uri.as_str() == EXTERNAL_URI && !*redirected;
        if !expected || self.external_navigation_seen.get() {
            self.unexpected_navigation.set(true);
        }
        if !self.isolated_external {
            self.external_navigation_seen.set(true);
            return None;
        }
        let allowance = self.allowance.borrow_mut().take();
        let valid = allowance.is_some_and(|marker| {
            self.events.loaded() == Some(marker.generation)
                && uri.as_str() == EXTERNAL_URI
                && !*redirected
                && !self.external_navigation_seen.replace(true)
        });
        if valid {
            // Consumed before returning to the native setter or any reentry.
            Some(NativeAction::Allow)
        } else {
            self.unexpected_navigation.set(true);
            None
        }
    }
}

impl EventSink for Probe {
    fn event(&self, event: NativeEvent) -> NativeAction {
        if let Some(action) = self.external_navigation(&event) {
            return action;
        }
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

type Case = (FixtureProfile, EventKind, ControlFault);

const CASES: [Case; 10] = [
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
        FixtureProfile::External,
        EventKind::Navigation,
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
    for (index, case) in CASES.into_iter().enumerate() {
        let (profile, kind, mode) = case;
        log_start(index, case)?;
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
            external_profile: profile == FixtureProfile::External,
            isolated_external: profile == FixtureProfile::External
                && kind == EventKind::ExternalUri,
            allowance: RefCell::new(None),
            external_navigation_seen: Cell::new(false),
            unexpected_navigation: Cell::new(false),
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
        prepare_control_view(native.as_ref())?;
        listener.begin_navigation();
        probe.events.begin();
        native.navigate_owner()?;
        let mut armed = false;
        let callback = pump_until(&factory, "actual native control callback", || {
            let served = listener.served();
            let generation = probe.events.loaded().filter(|_| {
                probe.isolated_external
                    && !armed
                    && !probe.events.invalid()
                    && !probe.unexpected_navigation.get()
                    && served.count == 1
                    && served.integrity_ok
            });
            if let Some(generation) = generation {
                *probe.allowance.borrow_mut() = Some(ExternalAllowance { generation });
                armed = true;
            }
            probe.delivered.get()
        });
        log_callback(index, case, &probe, &listener, &callback)?;
        if let Err(error) = callback {
            drop(native);
            log_retired(index, identity.browser_pid, &probe)?;
            return Err(error);
        }
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
        if probe.external_profile {
            assert!(probe.external_navigation_seen.get());
            assert!(!probe.unexpected_navigation.get());
            if probe.isolated_external {
                assert!(armed);
                assert!(probe.allowance.borrow().is_none());
            }
        }
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

fn prepare_control_view(native: &dyn crate::NativeOperations) -> TestResult {
    super::super::settings::apply(native).map_err(pos_owner_bridge::SurfaceError::error)?;
    native.fit_controller()?;
    native.show_window()?;
    native.focus_controller()?;
    Ok(())
}

fn log_start(index: usize, (profile, kind, mode): Case) -> TestResult {
    writeln!(
        std::io::stderr(),
        "NATIVE_CONTROL case={index} profile={profile:?} kind={kind:?} mode={mode:?} stage=start"
    )?;
    Ok(())
}

fn log_callback(
    index: usize,
    (profile, kind, mode): Case,
    probe: &Probe,
    listener: &LoopbackListener,
    callback: &TestResult,
) -> TestResult {
    let served = listener.served();
    writeln!(
        std::io::stderr(),
        "NATIVE_CONTROL case={index} profile={profile:?} kind={kind:?} mode={mode:?} stage=callback-wait delivered={} failures={} requests={} served={} integrity={} started={:?} loaded={:?} invalid={} result={:?}",
        probe.delivered.get(),
        probe.failures.get(),
        listener.received_request_count(),
        served.count,
        served.integrity_ok,
        probe.events.started(),
        probe.events.loaded(),
        probe.events.invalid(),
        callback.as_ref().map_err(ToString::to_string)
    )?;
    Ok(())
}

fn log_retired(index: usize, expected_pid: u32, probe: &Probe) -> TestResult {
    writeln!(
        std::io::stderr(),
        "NATIVE_CONTROL case={index} stage=retired expected_pid={expected_pid} exited={:?}",
        probe.events.exited()
    )?;
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

#[cfg(test)]
mod tests {
    use super::{Events, ExternalAllowance, Probe, EXTERNAL_URI};
    use crate::{EventKind, EventSink, NativeAction, NativeEvent, NativeText, OWNER_URL};
    use std::cell::{Cell, RefCell};
    use std::rc::Rc;

    fn probe() -> Probe {
        let events = Rc::new(Events::default());
        events.begin();
        assert_eq!(
            navigation(events.as_ref(), OWNER_URL, false),
            NativeAction::Allow
        );
        events.event(NativeEvent::DomLoaded {
            id: 1,
            uri: NativeText::fixture(OWNER_URL),
        });
        Probe {
            events,
            kind: EventKind::ExternalUri,
            delivered: Cell::new(false),
            failures: Cell::new(0),
            external_profile: true,
            isolated_external: true,
            allowance: RefCell::new(None),
            external_navigation_seen: Cell::new(false),
            unexpected_navigation: Cell::new(false),
        }
    }

    fn navigation(sink: &dyn EventSink, uri: &str, redirected: bool) -> NativeAction {
        sink.event(NativeEvent::Navigation {
            uri: NativeText::fixture(uri),
            id: 1,
            redirected,
        })
    }

    #[test]
    fn external_allowance_is_owned_once_and_rejects_mismatch() {
        let allowed = probe();
        *allowed.allowance.borrow_mut() = Some(ExternalAllowance {
            generation: pos_owner_bridge::NavigationId(1),
        });
        assert_eq!(
            navigation(&allowed, EXTERNAL_URI, false),
            NativeAction::Allow
        );
        assert_eq!(
            navigation(&allowed, EXTERNAL_URI, false),
            NativeAction::Cancel
        );
        assert!(allowed.unexpected_navigation.get());

        for (uri, redirected, generation) in [
            (EXTERNAL_URI, true, 1),
            ("ms-settings:privacy-location?x=1", false, 1),
            (EXTERNAL_URI, false, 2),
        ] {
            let denied = probe();
            *denied.allowance.borrow_mut() = Some(ExternalAllowance {
                generation: pos_owner_bridge::NavigationId(generation),
            });
            assert_eq!(navigation(&denied, uri, redirected), NativeAction::Cancel);
            assert!(denied.unexpected_navigation.get());
            assert!(denied.allowance.borrow().is_none());
        }
        let other_view = probe();
        assert_eq!(
            navigation(&other_view, EXTERNAL_URI, false),
            NativeAction::Cancel
        );
        assert!(other_view.unexpected_navigation.get());
    }
}
