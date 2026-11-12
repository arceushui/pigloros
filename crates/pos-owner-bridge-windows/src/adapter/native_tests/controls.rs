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
    verified_owner: Cell<Option<pos_owner_bridge::NavigationId>>,
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
        if !self.external_profile {
            return None;
        }
        if uri.as_str() == crate::OWNER_URL && self.events.started().is_none() {
            return None;
        }
        let verified = self.verified_owner.get().is_some()
            && self.verified_owner.get() == self.events.loaded()
            && !self.events.invalid();
        let expected = uri.as_str() == EXTERNAL_URI && !*redirected;
        if !verified || !expected || self.external_navigation_seen.get() {
            self.unexpected_navigation.set(true);
        }
        if !self.isolated_external {
            self.external_navigation_seen.set(true);
            return None;
        }
        let allowance = self.allowance.borrow_mut().take();
        let valid = allowance.is_some_and(|marker| {
            verified
                && self.events.loaded() == Some(marker.generation)
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
            verified_owner: Cell::new(None),
            allowance: RefCell::new(None),
            external_navigation_seen: Cell::new(false),
            unexpected_navigation: Cell::new(false),
        });
        let mut native = session::Session::new(&factory, events)?;
        create_control_session(&mut native, &factory, &probe, runtime.root(), &folder)?;
        let identity = runtime.browser_identity(native.browser_pid()?)?;
        native.require_shared_interfaces()?;
        let sink: Rc<dyn EventSink> = probe.clone();
        native.subscribe_view(sink)?;
        prepare_control_view(native.as_ref())?;
        listener.begin_navigation();
        probe.events.begin();
        native.navigate_owner()?;
        let mut armed = false;
        let callback = wait_for_control(&factory, &probe, &listener, &mut armed);
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
        assert_control_retired(&probe, &listener, &before_exit, &after_exit, case, armed);
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

// Keep the owning Session alive on every error; its Drop performs the same
// retained native retirement as the surrounding qualification run.
fn create_control_session(
    native: &mut session::Session<'_>,
    factory: &dyn StaPump,
    probe: &Rc<Probe>,
    runtime: &Path,
    folder: &Path,
) -> TestResult {
    native.create_window(None, 480, 640)?;
    let sink: Rc<dyn EventSink> = probe.clone();
    native.create_environment(runtime, folder, super::super::settings::OPTIONS, sink)?;
    completion(factory, "control environment", || {
        native.environment_completion()
    })?;
    native.create_controller()?;
    completion(factory, "control controller", || {
        native.controller_completion()
    })?;
    Ok(())
}

fn wait_for_control(
    factory: &dyn StaPump,
    probe: &Probe,
    listener: &LoopbackListener,
    armed: &mut bool,
) -> TestResult {
    pump_until(factory, "actual native control callback", || {
        let served = listener.served();
        let generation = probe.events.loaded().filter(|_| {
            probe.external_profile
                && probe.verified_owner.get().is_none()
                && !probe.events.invalid()
                && !probe.unexpected_navigation.get()
                && served.count == 1
                && served.integrity_ok
        });
        if let Some(generation) = generation {
            probe.verified_owner.set(Some(generation));
            if probe.isolated_external {
                *probe.allowance.borrow_mut() = Some(ExternalAllowance { generation });
                *armed = true;
            }
        }
        probe.delivered.get()
    })
}

fn assert_control_retired(
    probe: &Probe,
    listener: &LoopbackListener,
    before_exit: &[ControlObservation],
    after_exit: &[ControlObservation],
    (_, kind, mode): Case,
    armed: bool,
) {
    // Every assertion after observing actual retirement; Session also
    // retains on every error/unwind before this point.
    assert_denials(before_exit, after_exit, kind, mode);
    if probe.external_profile {
        assert!(probe.verified_owner.get().is_some());
        assert_eq!(probe.verified_owner.get(), probe.events.loaded());
        assert_eq!(listener.served().count, 1);
        assert!(listener.served().integrity_ok);
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
        "NATIVE_CONTROL case={index} profile={profile:?} kind={kind:?} mode={mode:?} stage=callback-wait delivered={} failures={} requests={} served={} integrity={} started={:?} loaded={:?} invalid={} listener_observation={:?} result={:?}",
        probe.delivered.get(),
        probe.failures.get(),
        listener.received_request_count(),
        served.count,
        served.integrity_ok,
        probe.events.started(),
        probe.events.loaded(),
        probe.events.invalid(),
        listener.observation(),
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
        assert!(!before.overflowed);
        assert!(!after.overflowed);
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
    use super::{assert_denials, Events, ExternalAllowance, Probe, EXTERNAL_URI};
    use crate::{
        ControlFault, ControlObservation, EventKind, EventSink, NativeAction, NativeEvent,
        NativeText, OWNER_URL,
    };
    use std::cell::{Cell, RefCell};
    use std::rc::Rc;

    #[test]
    fn denial_oracle_rejects_overflow_even_when_both_snapshots_have_two_entries() {
        let valid = ControlObservation {
            kind: EventKind::Navigation,
            deferred: false,
            attempts: 1,
            readback: Some(true),
            completions: 0,
            retired: true,
            overflowed: false,
        };
        let before = [valid; 2];
        let after = [valid; 2];
        assert_denials(&before, &after, EventKind::Navigation, ControlFault::Normal);
        for overflow_before in [false, true] {
            let mut changed_before = before;
            let mut changed_after = after;
            if overflow_before {
                changed_before[1].overflowed = true;
            } else {
                changed_after[1].overflowed = true;
            }
            assert!(std::panic::catch_unwind(|| {
                assert_denials(
                    &changed_before,
                    &changed_after,
                    EventKind::Navigation,
                    ControlFault::Normal,
                );
            })
            .is_err());
        }
    }

    #[test]
    fn modeled_control_view_setup_stops_at_the_first_failure() -> super::TestResult {
        use crate::adapter::surface::tests::native::{Creation, Factory};
        use crate::NativeFactory as _;
        use pos_owner_bridge::fake::clock::FakeClock;

        // These are modeled NativeOperations responses, not SDK failures.
        for (failure, expected, success) in [
            (
                None,
                &["fit_controller", "show_window", "focus_controller"][..],
                true,
            ),
            (Some("set_bool"), &[][..], false),
            (Some("fit_controller"), &["fit_controller"][..], false),
            (
                Some("show_window"),
                &["fit_controller", "show_window"][..],
                false,
            ),
            (
                Some("focus_controller"),
                &["fit_controller", "show_window", "focus_controller"][..],
                false,
            ),
        ] {
            let model = Factory::new(Creation::Ready, FakeClock::start());
            model.failure.set(failure);
            let native = model.session().map_err(|error| format!("{error:?}"))?;
            assert_eq!(
                super::prepare_control_view(native.as_ref()).is_ok(),
                success,
                "{failure:?}"
            );
            assert_eq!(model.calls.borrow().as_slice(), expected, "{failure:?}");
            assert!(!model.calls.borrow().contains(&"navigate"));
        }
        Ok(())
    }

    #[test]
    fn modeled_control_creation_stops_at_failure_and_retires_owners() -> super::TestResult {
        use crate::adapter::surface::tests::native::{Creation, Factory};
        use pos_owner_bridge::fake::clock::FakeClock;
        use std::path::Path;

        // Fake responses model setup failure; they are not native SDK results.
        for (creation, failure, expected, success) in [
            (
                Creation::Ready,
                None,
                &["create_window", "create_environment", "create_controller"][..],
                true,
            ),
            (
                Creation::Ready,
                Some("create_window"),
                &["create_window"][..],
                false,
            ),
            (
                Creation::Ready,
                Some("create_environment"),
                &["create_window", "create_environment"][..],
                false,
            ),
            (
                Creation::SynchronousFailure,
                None,
                &["create_window", "create_environment", "create_controller"][..],
                false,
            ),
            (
                Creation::CallbackFailure,
                None,
                &["create_window", "create_environment", "create_controller"][..],
                false,
            ),
        ] {
            let factory = Factory::new(creation, FakeClock::start());
            factory.failure.set(failure);
            let probe = Rc::new(probe());
            let events = Rc::clone(&probe.events);
            let mut native = super::session::Session::new(&factory, Rc::clone(&events))
                .map_err(|error| format!("{error:?}"))?;
            let result = super::create_control_session(
                &mut native,
                &factory,
                &probe,
                Path::new("modeled-runtime"),
                Path::new("modeled-folder"),
            );
            let calls_before_retirement = factory.calls.borrow().clone();
            if success {
                assert_eq!(
                    native.browser_pid().map_err(|error| format!("{error:?}"))?,
                    42
                );
                events.event(NativeEvent::BrowserExited { pid: 42 });
            }
            factory.failure.set(None);
            drop(native);
            assert_eq!(result.is_ok(), success);
            assert_eq!(calls_before_retirement.as_slice(), expected);
            assert!(!calls_before_retirement.contains(&"navigate"));
            assert!(factory.calls.borrow().contains(&"drop_environment"));
        }
        Ok(())
    }

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
            verified_owner: Cell::new(Some(pos_owner_bridge::NavigationId(1))),
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
        let invalidated = probe();
        *invalidated.allowance.borrow_mut() = Some(ExternalAllowance {
            generation: pos_owner_bridge::NavigationId(1),
        });
        // Defensive logical-event test: no claim that this sequence occurred on WebView2.
        invalidated.events.event(NativeEvent::Frame);
        assert_eq!(
            navigation(&invalidated, EXTERNAL_URI, false),
            NativeAction::Cancel
        );
        assert!(invalidated.unexpected_navigation.get());
        assert!(invalidated.allowance.borrow().is_none());

        let early = probe();
        early.verified_owner.set(None);
        assert_eq!(
            navigation(&early, EXTERNAL_URI, false),
            NativeAction::Cancel
        );
        assert!(early.unexpected_navigation.get());
        early
            .verified_owner
            .set(Some(pos_owner_bridge::NavigationId(1)));
        assert!(early.unexpected_navigation.get());

        let composed_early = Probe {
            isolated_external: false,
            ..probe()
        };
        composed_early.verified_owner.set(None);
        assert_eq!(
            navigation(&composed_early, EXTERNAL_URI, false),
            NativeAction::Cancel
        );
        composed_early
            .verified_owner
            .set(Some(pos_owner_bridge::NavigationId(1)));
        assert!(composed_early.unexpected_navigation.get());

        let composed = probe();
        // The composed case uses the unchanged real policy after recording its precondition.
        let composed = Probe {
            isolated_external: false,
            ..composed
        };
        assert_eq!(
            navigation(&composed, EXTERNAL_URI, false),
            NativeAction::Cancel
        );
        assert!(composed.external_navigation_seen.get());
        assert!(!composed.unexpected_navigation.get());

        let other_view = probe();
        assert_eq!(
            navigation(&other_view, EXTERNAL_URI, false),
            NativeAction::Cancel
        );
        assert!(other_view.unexpected_navigation.get());
    }
}
