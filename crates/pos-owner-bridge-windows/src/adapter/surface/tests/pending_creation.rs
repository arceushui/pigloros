#![cfg(windows)]
#![forbid(unsafe_code)]

use std::rc::Rc;
use std::task::Poll;

use pos_owner_bridge::{MonotonicClock, OwnerWebSurface, SurfaceSpec};

use super::{spec, Creation, Fixture, TestResult};
use crate::NativeEvent;

#[test]
fn modeled_session_refusal_keeps_public_open_idle_and_allows_a_fresh_open() -> TestResult {
    let mut fixture = Fixture::new(Creation::Ready)?;
    let selected = spec(40);
    let before = fixture.factory.calls.borrow().clone();
    fixture.factory.failure.set(Some("session"));
    assert_eq!(
        fixture.surface.open(&selected),
        Poll::Ready(Err(pos_owner_bridge::SurfaceError::new(
            pos_owner_bridge::BridgeError::Unavailable(
                pos_owner_bridge::UnavailableCode::InterfaceUnavailable,
            ),
        ))),
    );
    assert!(fixture.surface.idle());
    assert!(!fixture.root.join(&selected.folder_name).exists());
    assert_eq!(*fixture.factory.calls.borrow(), before);
    fixture.assert_no_ceremony_data();
    fixture.factory.failure.set(None);
    let identity = fixture
        .open(&selected)
        .map_err(pos_owner_bridge::SurfaceError::error)?;
    assert_eq!(identity.browser_pid, 42);
    fixture.finish()
}

#[test]
fn modeled_mismatched_folder_refuses_before_window_creation_and_allows_fresh_open() -> TestResult {
    let mut fixture = Fixture::new(Creation::Ready)?;
    let correct = spec(40);
    let mut wrong = spec(40);
    wrong.folder_name = spec(41).folder_name;
    assert!(matches!(fixture.surface.open(&wrong), Poll::Ready(Err(_))));
    assert!(fixture.surface.idle());
    assert!(!fixture.root.join(&wrong.folder_name).exists());
    assert!(!fixture.root.join(&correct.folder_name).exists());
    fixture.assert_no_ceremony_data();
    for call in ["create_window", "create_environment"] {
        assert!(!fixture.factory.calls.borrow().contains(&call));
    }
    let identity = fixture
        .open(&correct)
        .map_err(pos_owner_bridge::SurfaceError::error)?;
    assert_eq!(identity.browser_pid, 42);
    fixture.finish()
}

#[test]
fn pending_environment_repoll_retains_owners_until_normal_completion() -> TestResult {
    let mut fixture = Fixture::new(Creation::Ready)?;
    fixture.factory.environment_creation.set(Creation::Pending);
    let selected = spec(112);
    let readiness = pos_owner_bridge::ceremony::timing::READINESS;
    let deadline = fixture.clock.now() + readiness;
    fixture.surface.set_deadline(deadline);
    assert!(fixture.surface.open(&selected).is_pending());
    fixture.clock.advance(readiness / 2);
    for _ in 0..2 {
        assert!(fixture.surface.open(&selected).is_pending());
        pending_owners_are_retained(&fixture, Stage::Environment);
        assert!(fixture.root.join(&selected.folder_name).is_dir());
    }
    assert!(fixture.clock.now() < deadline);
    fixture.factory.environment_creation.set(Creation::Ready);
    let identity = fixture
        .open(&selected)
        .map_err(pos_owner_bridge::SurfaceError::error)?;
    assert_eq!(identity.browser_pid, 42);
    assert_eq!(count(&fixture, "create_environment"), 1);
    assert_eq!(count(&fixture, "create_controller"), 1);
    assert_eq!(fixture.factory.environment_completions.get(), 1);
    assert_eq!(fixture.factory.controller_completions.get(), 1);
    fixture.assert_no_ceremony_data();
    fixture.finish()
}

#[test]
fn modeled_controller_qualification_retains_pending_owners_on_refusal() -> TestResult {
    let mut fixture = Fixture::new(Creation::Pending)?;
    let selected = spec(113);
    assert!(fixture.surface.open(&selected).is_pending());
    assert!(fixture.surface.open(&selected).is_pending());
    let ceremony = selected.ceremony_id;
    assert_eq!(
        fixture.surface.controller_creation_retention(&ceremony),
        Some(super::super::PreEnvironmentRetention::Active)
    );
    assert!(fixture
        .surface
        .abandoned_completed_browser(&ceremony)
        .is_err());

    fixture.factory.failure.set(Some("pending-owner"));
    assert!(fixture
        .surface
        .controller_creation_retention(&ceremony)
        .is_none());
    assert!(fixture
        .surface
        .lose_pending_controller_parent(&ceremony)
        .is_err());
    fixture.factory.failure.set(None);
    let _candidate = fixture
        .surface
        .native
        .pending_opening_browser_candidate()
        .map_err(|()| "modeled candidate")?;
    fixture.factory.failure.set(Some("pending-callback-after"));
    assert!(fixture
        .surface
        .controller_creation_retention(&ceremony)
        .is_none());
    assert_eq!(
        fixture.surface.controller_result_retention(&ceremony),
        Some((super::super::PreEnvironmentRetention::Active, true))
    );
    assert!(fixture
        .surface
        .lose_pending_controller_parent(&ceremony)
        .is_err());
    assert!(!fixture.surface.idle());
    assert!(fixture.store.records_now().is_empty());
    fixture.assert_no_ceremony_data();

    fixture.factory.failure.set(None);
    fixture.surface.abandon_opening();
    fixture.factory.creation.set(Creation::CallbackFailure);
    assert!(fixture
        .surface
        .poll_failed_open()
        .map_err(pos_owner_bridge::SurfaceError::error)?);
    assert!(fixture.surface.idle());
    Ok(())
}

#[test]
fn modeled_abandoned_controller_rechecks_the_selected_browser() -> TestResult {
    let mut fixture = Fixture::new(Creation::Pending)?;
    let selected = spec(114);
    assert!(fixture.surface.open(&selected).is_pending());
    assert!(fixture.surface.open(&selected).is_pending());
    let browser = fixture
        .surface
        .runtime
        .identity(42)
        .map_err(|_| "modeled browser")?;
    fixture.factory.pending_browser.set(Some(browser));
    let _candidate = fixture
        .surface
        .native
        .pending_opening_browser_candidate()
        .map_err(|()| "modeled candidate")?;
    fixture.factory.failure.set(Some("pending-callback-after"));
    fixture.surface.abandon_opening();
    super::fault_states::change_identity(&mut fixture, 0);
    assert!(fixture
        .surface
        .abandoned_completed_browser(&selected.ceremony_id)
        .is_err());
    assert!(!fixture.surface.idle());
    assert!(fixture.store.records_now().is_empty());
    fixture.assert_no_ceremony_data();

    fixture.surface.runtime = std::sync::Arc::new(super::Runtime(fixture.root.clone()));
    fixture.factory.failure.set(None);
    fixture.factory.creation.set(Creation::CallbackFailure);
    assert!(fixture
        .surface
        .poll_failed_open()
        .map_err(pos_owner_bridge::SurfaceError::error)?);
    assert!(fixture.surface.idle());
    Ok(())
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Stage {
    Environment,
    Controller,
}

fn count(fixture: &Fixture, name: &str) -> usize {
    fixture
        .factory
        .calls
        .borrow()
        .iter()
        .filter(|call| **call == name)
        .count()
}

fn competing_open_is_refused(fixture: &mut Fixture, competing: &SurfaceSpec) {
    assert!(matches!(
        fixture.surface.open(competing),
        Poll::Ready(Err(_))
    ));
}

fn pending_owners_are_retained(fixture: &Fixture, stage: Stage) {
    assert!(!fixture.surface.idle());
    assert!(fixture.surface.native.pending());
    assert!(Rc::strong_count(&fixture.factory) >= 2);
    assert_eq!(count(fixture, "create_environment"), 1);
    assert_eq!(
        count(fixture, "create_controller"),
        usize::from(stage == Stage::Controller)
    );
    assert_eq!(fixture.factory.controller_completions.get(), 0);
    assert_eq!(
        fixture.factory.environment_completions.get(),
        u32::from(stage == Stage::Controller)
    );
    for operation in [
        "close_buffers",
        "unsubscribe_view",
        "close_controller",
        "unsubscribe_exit",
        "drop_environment",
        "destroy_window",
    ] {
        assert_eq!(count(fixture, operation), 0);
    }
    fixture.assert_no_ceremony_data();
}

fn settle_modeled_completion(
    fixture: &mut Fixture,
    stage: Stage,
    succeeds: bool,
    selected: &SurfaceSpec,
    competing: &SurfaceSpec,
) -> TestResult {
    let settled = fixture
        .surface
        .poll_failed_open()
        .map_err(pos_owner_bridge::SurfaceError::error)?;
    if stage == Stage::Controller && succeeds {
        assert!(!settled);
        assert!(!fixture.surface.idle());
        competing_open_is_refused(fixture, competing);
        assert!(matches!(
            fixture.surface.open(selected),
            Poll::Ready(Err(_))
        ));
        let sink = fixture
            .factory
            .sink
            .borrow()
            .clone()
            .ok_or("missing modeled environment sink")?;
        sink.event(NativeEvent::BrowserExited { pid: 43 });
        assert!(!fixture
            .surface
            .poll_failed_open()
            .map_err(pos_owner_bridge::SurfaceError::error)?);
        assert!(!fixture.surface.idle());
        assert!(fixture.store.removed_folders().is_empty());
        competing_open_is_refused(fixture, competing);
        fixture.exit();
        assert!(fixture
            .surface
            .poll_failed_open()
            .map_err(pos_owner_bridge::SurfaceError::error)?);
        assert_eq!(
            fixture.store.removed_folders(),
            vec![selected.folder_name.clone()]
        );
    } else {
        assert!(settled);
        assert!(fixture.root.join(&selected.folder_name).is_dir());
        assert!(fixture.store.removed_folders().is_empty());
    }
    Ok(())
}

fn modeled_pending_case(stage: Stage, timeout: bool, succeeds: bool) -> TestResult {
    let mut fixture = Fixture::new(Creation::Pending)?;
    if stage == Stage::Environment {
        fixture.factory.environment_creation.set(Creation::Pending);
    }
    let selected = spec(110);
    let competing = spec(111);
    let readiness = pos_owner_bridge::ceremony::timing::READINESS;
    let original_deadline = fixture.clock.now() + readiness;
    fixture.surface.set_deadline(original_deadline);
    assert!(fixture.surface.open(&selected).is_pending());
    if stage == Stage::Controller {
        assert!(fixture.surface.open(&selected).is_pending());
    }
    pending_owners_are_retained(&fixture, stage);
    competing_open_is_refused(&mut fixture, &competing);
    pending_owners_are_retained(&fixture, stage);

    if timeout {
        fixture.clock.advance(readiness);
        assert_eq!(fixture.clock.now(), original_deadline);
        assert!(matches!(
            fixture.surface.open(&selected),
            Poll::Ready(Err(_))
        ));
    } else {
        fixture.surface.abandon_opening();
    }
    assert!(matches!(
        fixture.surface.open(&selected),
        Poll::Ready(Err(_))
    ));
    competing_open_is_refused(&mut fixture, &competing);
    assert!(!fixture
        .surface
        .poll_failed_open()
        .map_err(pos_owner_bridge::SurfaceError::error)?);
    assert!(fixture.surface.pump().is_ok());
    pending_owners_are_retained(&fixture, stage);
    competing_open_is_refused(&mut fixture, &competing);

    let outcome = if succeeds {
        Creation::Ready
    } else {
        Creation::CallbackFailure
    };
    if stage == Stage::Environment {
        fixture.factory.environment_creation.set(outcome);
    } else {
        fixture.factory.creation.set(outcome);
    }
    settle_modeled_completion(&mut fixture, stage, succeeds, &selected, &competing)?;
    assert!(fixture.surface.idle());
    assert_eq!(fixture.factory.environment_completions.get(), 1);
    assert_eq!(
        fixture.factory.controller_completions.get(),
        u32::from(stage == Stage::Controller)
    );
    assert!(fixture
        .surface
        .poll_failed_open()
        .map_err(pos_owner_bridge::SurfaceError::error)?);
    assert_eq!(fixture.factory.environment_completions.get(), 1);
    assert_eq!(
        fixture.factory.controller_completions.get(),
        u32::from(stage == Stage::Controller)
    );
    assert_eq!(count(&fixture, "create_environment"), 1);
    assert_eq!(
        count(&fixture, "create_controller"),
        usize::from(stage == Stage::Controller)
    );
    fixture.assert_no_ceremony_data();

    fixture.factory.environment_creation.set(Creation::Ready);
    fixture.factory.creation.set(Creation::Ready);
    fixture
        .surface
        .set_deadline(fixture.clock.now() + readiness);
    assert_eq!(
        fixture
            .open(&competing)
            .map_err(pos_owner_bridge::SurfaceError::error)?
            .browser_pid,
        42
    );
    fixture.assert_no_ceremony_data();
    fixture.finish()?;
    Ok(())
}

#[test]
fn pending_creation_models_late_success_and_failure_after_abandonment_and_timeout() -> TestResult {
    for stage in [Stage::Environment, Stage::Controller] {
        for timeout in [false, true] {
            for succeeds in [false, true] {
                modeled_pending_case(stage, timeout, succeeds)?;
            }
        }
    }
    Ok(())
}

#[test]
fn immediate_precontroller_failure_blocks_admission_until_recordless_retirement() -> TestResult {
    for failure in ["create_window", "create_environment"] {
        let mut fixture = Fixture::new(Creation::Ready)?;
        let selected = spec(120);
        let competing = spec(121);
        fixture.factory.failure.set(Some(failure));
        assert!(matches!(
            fixture.surface.open(&selected),
            Poll::Ready(Err(_))
        ));
        assert!(!fixture.surface.idle());
        competing_open_is_refused(&mut fixture, &competing);
        fixture.assert_no_ceremony_data();
        assert!(fixture.root.join(&selected.folder_name).is_dir());
        fixture.factory.failure.set(None);
        assert!(fixture
            .surface
            .poll_failed_open()
            .map_err(pos_owner_bridge::SurfaceError::error)?);
        assert!(fixture.surface.idle());
        assert!(fixture.root.join(&selected.folder_name).is_dir());
        assert!(fixture.store.removed_folders().is_empty());
        assert_eq!(
            fixture
                .open(&competing)
                .map_err(pos_owner_bridge::SurfaceError::error)?
                .browser_pid,
            42
        );
        fixture.assert_no_ceremony_data();
        fixture.finish()?;
    }
    Ok(())
}

#[test]
fn modeled_failed_open_retains_its_folder_and_retries_each_cleanup_refusal() {
    let operations = [
        "unsubscribe_view",
        "unsubscribe_exit",
        "drop_environment",
        "destroy_window",
    ];
    for (creation, startup_failure, observes_exit) in [
        (Creation::Ready, Some("create_window"), false),
        (Creation::Ready, Some("create_environment"), false),
        (Creation::SynchronousFailure, None, false),
        (Creation::MissingView, None, true),
    ] {
        for (index, failure) in operations.iter().enumerate() {
            let result = Fixture::new(creation).map(|mut fixture| {
                let selected = spec(126);
                let competing = spec(127);
                fixture.factory.failure.set(startup_failure);
                assert!(fixture.open(&selected).is_err());
                if observes_exit {
                    assert_eq!(fixture.surface.poll_failed_open(), Ok(false));
                    fixture.exit();
                }
                let before = fixture.factory.calls.borrow().len();
                fixture.factory.failure.set(Some(failure));
                assert_eq!(
                    fixture.surface.poll_failed_open(),
                    Err(pos_owner_bridge::SurfaceError::new(
                        pos_owner_bridge::BridgeError::Unavailable(
                            pos_owner_bridge::UnavailableCode::InterfaceUnavailable,
                        ),
                    )),
                );
                assert_eq!(
                    &fixture.factory.calls.borrow()[before..],
                    &operations[..=index],
                );
                assert!(!fixture.surface.idle());
                assert!(fixture.root.join(&selected.folder_name).is_dir());
                assert!(fixture.store.removed_folders().is_empty());
                competing_open_is_refused(&mut fixture, &competing);
                fixture.assert_no_ceremony_data();
                assert_eq!(
                    &fixture.factory.calls.borrow()[before..],
                    &operations[..=index],
                );

                fixture.factory.failure.set(None);
                let retry = fixture.factory.calls.borrow().len();
                assert_eq!(fixture.surface.poll_failed_open(), Ok(true));
                assert_eq!(&fixture.factory.calls.borrow()[retry..], &operations,);
                assert!(fixture.surface.idle());
                if observes_exit {
                    assert_eq!(fixture.store.removed_folders(), [selected.folder_name]);
                } else {
                    assert!(fixture.store.removed_folders().is_empty());
                    assert!(fixture.root.join(&selected.folder_name).is_dir());
                }
                fixture.assert_no_ceremony_data();
                fixture.factory.creation.set(Creation::Ready);
                let opened = fixture.open(&competing);
                assert!(opened.is_ok(), "fresh modeled open: {opened:?}");
                fixture.assert_no_ceremony_data();
                let finished = fixture.finish();
                assert!(finished.is_ok(), "fresh modeled retirement: {finished:?}");
            });
            assert!(result.is_ok(), "modeled fixture: {result:?}");
        }
    }
}

#[test]
fn modeled_controller_presence_refusal_preserves_failed_open_for_retry() {
    let result = Fixture::new(Creation::SynchronousFailure).map(|mut fixture| {
        let selected = spec(128);
        assert!(fixture.open(&selected).is_err());
        let before = fixture.factory.calls.borrow().clone();
        fixture.factory.failure.set(Some("has_controller"));
        assert!(fixture.surface.poll_failed_open().is_err());
        assert!(!fixture.surface.idle());
        assert!(fixture.root.join(&selected.folder_name).is_dir());
        assert!(fixture.store.removed_folders().is_empty());
        competing_open_is_refused(&mut fixture, &spec(129));
        assert_eq!(*fixture.factory.calls.borrow(), before);
        fixture.assert_no_ceremony_data();
        fixture.factory.failure.set(None);
        assert_eq!(fixture.surface.poll_failed_open(), Ok(true));
        assert!(fixture.surface.idle());
        assert!(fixture.root.join(&selected.folder_name).is_dir());
        assert!(fixture.store.removed_folders().is_empty());
        fixture.assert_no_ceremony_data();
    });
    assert!(result.is_ok(), "modeled fixture: {result:?}");
}

#[test]
fn modeled_late_controller_close_refusal_retains_owners_until_retry_and_exit() {
    let result = Fixture::new(Creation::Pending).map(|mut fixture| {
        let selected = spec(130);
        assert!(fixture.surface.open(&selected).is_pending());
        assert!(fixture.surface.open(&selected).is_pending());
        fixture.surface.abandon_opening();
        fixture.factory.creation.set(Creation::Ready);
        fixture.factory.failure.set(Some("close_controller"));
        for _ in 0..2 {
            let before = fixture.factory.calls.borrow().len();
            assert_eq!(fixture.surface.poll_failed_open(), Ok(false));
            assert_eq!(
                &fixture.factory.calls.borrow()[before..],
                &["close_buffers", "unsubscribe_view", "close_controller"],
            );
            assert!(!fixture.surface.idle());
            assert!(fixture.root.join(&selected.folder_name).is_dir());
            assert!(fixture.store.removed_folders().is_empty());
            competing_open_is_refused(&mut fixture, &spec(131));
            fixture.assert_no_ceremony_data();
        }
        fixture.factory.failure.set(None);
        assert_eq!(fixture.surface.poll_failed_open(), Ok(false));
        assert!(!fixture.surface.idle());
        assert!(fixture.store.removed_folders().is_empty());
        fixture.exit();
        assert_eq!(fixture.surface.poll_failed_open(), Ok(true));
        assert!(fixture.surface.idle());
        assert_eq!(fixture.store.removed_folders(), [selected.folder_name]);
        fixture.assert_no_ceremony_data();
    });
    assert!(result.is_ok(), "modeled fixture: {result:?}");
}

#[test]
fn insecure_environment_readback_refuses_controller_and_retires_recordless() -> TestResult {
    let required = super::super::super::settings::OPTIONS;
    for (case, arguments, options) in [
        ("arguments", "--unexpected", required),
        (
            "extensions",
            "",
            crate::EnvironmentOptions {
                extensions: true,
                ..required
            },
        ),
        (
            "crash reporting",
            "",
            crate::EnvironmentOptions {
                custom_crash_reporting: false,
                ..required
            },
        ),
        (
            "exclusive folder",
            "",
            crate::EnvironmentOptions {
                exclusive_folder: false,
                ..required
            },
        ),
    ] {
        let mut fixture = Fixture::new(Creation::Ready)?;
        let selected = spec(122);
        let competing = spec(123);
        fixture.factory.environment_arguments.set(arguments);
        fixture.factory.environment_options.set(options);
        assert_eq!(
            fixture
                .open(&selected)
                .map_err(pos_owner_bridge::SurfaceError::error),
            Err(pos_owner_bridge::BridgeError::Unavailable(
                pos_owner_bridge::UnavailableCode::InterfaceUnavailable,
            )),
            "case {case}",
        );
        assert_eq!(
            fixture.factory.environment_completions.get(),
            1,
            "case {case}"
        );
        assert_eq!(count(&fixture, "create_controller"), 0, "case {case}");
        assert!(!fixture.surface.idle(), "case {case}");
        competing_open_is_refused(&mut fixture, &competing);
        fixture.assert_no_ceremony_data();
        assert!(fixture.root.join(&selected.folder_name).is_dir());
        assert!(fixture
            .surface
            .poll_failed_open()
            .map_err(pos_owner_bridge::SurfaceError::error)?);
        assert!(fixture.surface.idle());
        assert!(fixture.root.join(&selected.folder_name).is_dir());
        assert!(fixture.store.removed_folders().is_empty());
        fixture.factory.environment_arguments.set("");
        fixture.factory.environment_options.set(required);
        assert_eq!(
            fixture
                .open(&competing)
                .map_err(pos_owner_bridge::SurfaceError::error)?
                .browser_pid,
            42
        );
        fixture.finish()?;
    }
    Ok(())
}

#[test]
fn mismatched_environment_identity_refuses_controller_and_retires_recordless() -> TestResult {
    #[derive(Clone, Copy, Debug)]
    enum Case {
        Version,
        RelativeFolder,
        OtherFolder,
        MissingFolder,
    }
    for case in [
        Case::Version,
        Case::RelativeFolder,
        Case::OtherFolder,
        Case::MissingFolder,
    ] {
        let mut fixture = Fixture::new(Creation::Ready)?;
        let selected = spec(124);
        let competing = spec(125);
        match case {
            Case::Version => fixture.factory.environment_version.set("153.0.4234.47"),
            Case::RelativeFolder => {
                *fixture.factory.environment_folder.borrow_mut() = Some("relative".into());
            }
            Case::OtherFolder => {
                *fixture.factory.environment_folder.borrow_mut() = Some(fixture.root.clone());
            }
            Case::MissingFolder => {
                *fixture.factory.environment_folder.borrow_mut() =
                    Some(fixture.root.join("missing"));
            }
        }
        assert_eq!(
            fixture
                .open(&selected)
                .map_err(pos_owner_bridge::SurfaceError::error),
            Err(pos_owner_bridge::BridgeError::Unavailable(
                pos_owner_bridge::UnavailableCode::RuntimeIntegrity,
            )),
            "case {case:?}",
        );
        assert_eq!(
            fixture.factory.environment_completions.get(),
            1,
            "case {case:?}"
        );
        assert_eq!(count(&fixture, "create_controller"), 0, "case {case:?}");
        assert!(!fixture.surface.idle(), "case {case:?}");
        competing_open_is_refused(&mut fixture, &competing);
        fixture.assert_no_ceremony_data();
        assert!(
            fixture.root.join(&selected.folder_name).is_dir(),
            "case {case:?}"
        );
        assert!(
            fixture
                .surface
                .poll_failed_open()
                .map_err(pos_owner_bridge::SurfaceError::error)?,
            "case {case:?}"
        );
        assert!(fixture.surface.idle(), "case {case:?}");
        assert!(
            fixture.root.join(&selected.folder_name).is_dir(),
            "case {case:?}"
        );
        assert!(fixture.store.removed_folders().is_empty(), "case {case:?}");
        fixture.factory.environment_version.set("153.0.4234.48");
        *fixture.factory.environment_folder.borrow_mut() = None;
        assert_eq!(
            fixture
                .open(&competing)
                .map_err(pos_owner_bridge::SurfaceError::error)?
                .browser_pid,
            42,
            "case {case:?}"
        );
        fixture.finish()?;
    }
    Ok(())
}

fn refused<T>() -> Result<T, pos_owner_bridge::SurfaceError> {
    Err(super::super::unavailable(()))
}

#[test]
fn modeled_reopen_of_a_ready_surface_is_refused_and_retires_through_its_own_exit() -> TestResult {
    let mut fixture = Fixture::new(Creation::Ready)?;
    let selected = spec(116);
    fixture
        .open(&selected)
        .map_err(pos_owner_bridge::SurfaceError::error)?;
    assert_eq!(fixture.surface.open(&selected), Poll::Ready(refused()));
    assert!(!fixture.surface.idle());
    fixture.assert_no_ceremony_data();
    assert_eq!(fixture.surface.poll_failed_open(), Ok(false));
    assert_eq!(count(&fixture, "close_controller"), 1);
    assert!(fixture.store.removed_folders().is_empty());
    fixture.exit();
    assert_eq!(fixture.surface.poll_failed_open(), Ok(true));
    assert!(fixture.surface.idle());
    assert_eq!(fixture.store.removed_folders(), vec![selected.folder_name]);
    Ok(())
}

#[test]
fn modeled_open_refuses_a_non_idle_surface_and_an_unprotectable_folder() -> TestResult {
    let mut fixture = Fixture::new(Creation::Ready)?;
    let selected = spec(117);
    let before = fixture.factory.calls.borrow().clone();
    fixture.surface.ownership = super::super::Ownership::Window;
    assert_eq!(fixture.surface.open(&selected), Poll::Ready(refused()));
    fixture.surface.ownership = super::super::Ownership::Idle;
    let root = std::mem::replace(
        &mut fixture.surface.root,
        std::path::PathBuf::from("relative-owner-root"),
    );
    assert_eq!(fixture.surface.open(&selected), Poll::Ready(refused()));
    fixture.surface.root = root;
    assert!(fixture.surface.idle());
    assert_eq!(*fixture.factory.calls.borrow(), before);
    assert!(!fixture.root.join(&selected.folder_name).exists());
    fixture.assert_no_ceremony_data();
    let identity = fixture
        .open(&selected)
        .map_err(pos_owner_bridge::SurfaceError::error)?;
    assert_eq!(identity.browser_pid, 42);
    fixture.finish()
}

#[test]
fn modeled_environment_failure_retries_each_failed_retirement_effect() -> TestResult {
    for failure in [
        "unsubscribe_view",
        "unsubscribe_exit",
        "drop_environment",
        "destroy_window",
    ] {
        let mut fixture = Fixture::new(Creation::Ready)?;
        fixture
            .factory
            .environment_creation
            .set(Creation::CallbackFailure);
        let failed = spec(118);
        assert_eq!(fixture.open(&failed), refused(), "{failure}");
        assert!(!fixture.surface.idle(), "{failure}");
        fixture.factory.failure.set(Some(failure));
        assert_eq!(fixture.surface.poll_failed_open(), refused(), "{failure}");
        assert!(!fixture.surface.idle(), "{failure}");
        fixture.factory.failure.set(None);
        assert_eq!(fixture.surface.poll_failed_open(), Ok(true), "{failure}");
        assert!(fixture.surface.idle(), "{failure}");
        assert!(fixture.root.join(&failed.folder_name).is_dir());
        assert!(fixture.store.removed_folders().is_empty());
        assert_eq!(count(&fixture, "create_controller"), 0);
        fixture.assert_no_ceremony_data();
    }
    Ok(())
}

#[test]
fn modeled_failed_controller_retirement_retries_ownership_query_and_cleanup() -> TestResult {
    for failure in ["has_controller", "drop_environment"] {
        let mut fixture = Fixture::new(Creation::CallbackFailure)?;
        let failed = spec(119);
        assert_eq!(fixture.open(&failed), refused(), "{failure}");
        fixture.factory.failure.set(Some(failure));
        assert_eq!(fixture.surface.poll_failed_open(), refused(), "{failure}");
        assert!(!fixture.surface.idle(), "{failure}");
        fixture.factory.failure.set(None);
        assert_eq!(fixture.surface.poll_failed_open(), Ok(true), "{failure}");
        assert!(fixture.surface.idle(), "{failure}");
        assert!(fixture.root.join(&failed.folder_name).is_dir());
        assert!(fixture.store.removed_folders().is_empty());
        fixture.assert_no_ceremony_data();
    }
    Ok(())
}

#[test]
fn modeled_exited_controller_retirement_retries_a_failed_cleanup_effect() -> TestResult {
    let mut fixture = Fixture::new(Creation::MissingView)?;
    let failed = spec(120);
    assert_eq!(fixture.open(&failed), refused());
    assert_eq!(fixture.surface.poll_failed_open(), Ok(false));
    fixture.exit();
    fixture.factory.failure.set(Some("unsubscribe_exit"));
    assert_eq!(fixture.surface.poll_failed_open(), refused());
    assert!(!fixture.surface.idle());
    assert!(fixture.store.removed_folders().is_empty());
    fixture.factory.failure.set(None);
    assert_eq!(fixture.surface.poll_failed_open(), Ok(true));
    assert!(fixture.surface.idle());
    assert_eq!(fixture.store.removed_folders(), vec![failed.folder_name]);
    fixture.assert_no_ceremony_data();
    Ok(())
}

#[test]
fn modeled_late_identified_controller_waits_past_a_foreign_exit_for_its_own() -> TestResult {
    let mut fixture = Fixture::new(Creation::Pending)?;
    let selected = spec(122);
    assert!(fixture.surface.open(&selected).is_pending());
    assert!(fixture.surface.open(&selected).is_pending());
    let sink = fixture
        .factory
        .sink
        .borrow()
        .clone()
        .ok_or("missing modeled environment sink")?;
    sink.event(NativeEvent::BrowserExited { pid: 43 });
    fixture.surface.abandon_opening();
    fixture.factory.creation.set(Creation::Ready);
    assert_eq!(fixture.surface.poll_failed_open(), Ok(false));
    assert_eq!(
        fixture
            .surface
            .identity
            .map(|identity| identity.browser_pid),
        Some(42)
    );
    assert!(!fixture.surface.idle());
    assert!(fixture.store.removed_folders().is_empty());
    fixture.exit();
    assert_eq!(fixture.surface.poll_failed_open(), Ok(true));
    assert!(fixture.surface.idle());
    assert_eq!(fixture.store.removed_folders(), vec![selected.folder_name]);
    fixture.assert_no_ceremony_data();
    Ok(())
}
