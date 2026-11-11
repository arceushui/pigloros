#![cfg(windows)]

use crate::{
    EventKind, EventSink, Failure, NativeAction, NativeError, NativeEvent, NativeResult, Operation,
};
use std::rc::Rc;
use webview2_com::Microsoft::Web::WebView2::Win32::{ICoreWebView2, ICoreWebView2Environment};

mod control_denial;
#[cfg(test)]
mod control_fixture;
mod controls;
mod denial;
mod navigation;
mod resource;
pub(super) use denial::{track_exit, Recovery};
pub(super) use navigation::source;
type Result<T> = NativeResult<T>;

fn observe(sink: &dyn EventSink, kind: EventKind, result: Result<NativeEvent>) -> NativeAction {
    match result {
        Ok(event) => sink.event(event),
        Err(error) => sink.failed(kind, error),
    }
}

fn action(sink: &dyn EventSink, kind: EventKind, actual: NativeAction, expected: NativeAction) {
    if actual != expected {
        sink.failed(
            kind,
            NativeError {
                operation: Operation::Subscription,
                failure: Failure::InvalidAction,
            },
        );
    }
}

type Remove = Box<dyn FnMut() -> windows::core::Result<()>>;

#[derive(Default)]
pub(super) struct Subscriptions {
    removers: Vec<Remove>,
}

impl Subscriptions {
    fn register(
        &mut self,
        add: impl FnOnce(*mut i64) -> windows::core::Result<()>,
        mut remove: impl FnMut(i64) -> windows::core::Result<()> + 'static,
    ) -> Result<()> {
        let mut token = 0;
        add(&raw mut token).map_err(|_| unavailable())?;
        self.removers.push(Box::new(move || remove(token)));
        Ok(())
    }

    /// A successful controller `Close` releases the `WebView`'s event handlers.
    /// Drop only the retained view removers; environment and denial owners are separate.
    pub(super) fn view_closed(&mut self) {
        self.removers.clear();
    }

    pub(super) fn close(&mut self) -> Result<()> {
        let mut pending = Vec::new();
        for mut remove in self.removers.drain(..).rev() {
            if remove().is_err() {
                pending.push(remove);
            }
        }
        self.removers = pending;
        if self.removers.is_empty() {
            Ok(())
        } else {
            Err(unavailable())
        }
    }
}

impl Drop for Subscriptions {
    fn drop(&mut self) {
        // Normal cleanup maps this result. Opening failure has no shared secret;
        // its environment remains owned by the native surface's retirement path.
        let _removed = self.close();
    }
}

pub(super) fn install(
    view: &ICoreWebView2,
    environment: &ICoreWebView2Environment,
    signals: &Rc<dyn EventSink>,
    recovery: &Rc<Recovery>,
    subscriptions: &mut Subscriptions,
) -> Result<()> {
    navigation::install(view, signals, recovery, subscriptions)?;
    resource::install(view, environment, signals, recovery, subscriptions)?;
    controls::install(view, signals, recovery, subscriptions)
}

pub(super) const fn unavailable() -> NativeError {
    NativeError {
        operation: Operation::Subscription,
        failure: Failure::CallFailed,
    }
}

#[cfg(test)]
mod tests {
    #![forbid(unsafe_code)]

    use std::cell::{Cell, RefCell};
    use std::rc::Rc;

    use super::{action, observe, Subscriptions};
    use crate::{EventKind, EventSink, Failure, NativeAction, NativeError, NativeEvent, Operation};
    use windows::core::{Error, HRESULT};

    #[derive(Default)]
    struct Sink {
        events: RefCell<Vec<NativeEvent>>,
        failures: RefCell<Vec<(EventKind, NativeError)>>,
    }

    impl EventSink for Sink {
        fn event(&self, event: NativeEvent) -> NativeAction {
            self.events.borrow_mut().push(event);
            NativeAction::Handled
        }

        fn failed(&self, kind: EventKind, error: NativeError) -> NativeAction {
            self.failures.borrow_mut().push((kind, error));
            NativeAction::BlockResource
        }
    }

    #[test]
    fn modeled_event_observations_keep_failure_classification_and_validate_actions() {
        let sink = Sink::default();
        let error = NativeError {
            operation: Operation::Subscription,
            failure: Failure::CallFailed,
        };
        assert_eq!(
            observe(&sink, EventKind::NewWindow, Ok(NativeEvent::NewWindow)),
            NativeAction::Handled
        );
        assert!(matches!(
            sink.events.borrow().as_slice(),
            [NativeEvent::NewWindow]
        ));
        assert_eq!(
            observe(&sink, EventKind::Resource, Err(error)),
            NativeAction::BlockResource
        );
        action(
            &sink,
            EventKind::NewWindow,
            NativeAction::Handled,
            NativeAction::Handled,
        );
        assert_eq!(*sink.failures.borrow(), [(EventKind::Resource, error)]);
        action(
            &sink,
            EventKind::NewWindow,
            NativeAction::Allow,
            NativeAction::Handled,
        );
        assert_eq!(
            *sink.failures.borrow(),
            [
                (EventKind::Resource, error),
                (
                    EventKind::NewWindow,
                    NativeError {
                        operation: Operation::Subscription,
                        failure: Failure::InvalidAction,
                    },
                ),
            ]
        );
    }

    #[test]
    fn modeled_subscription_add_failure_never_installs_a_remover() {
        let removed = Rc::new(Cell::new(false));
        let observed = Rc::clone(&removed);
        let mut subscriptions = Subscriptions::default();
        assert_eq!(
            subscriptions.register(
                |_| Err(Error::from_hresult(HRESULT(-1))),
                move |_| {
                    observed.set(true);
                    Ok(())
                },
            ),
            Err(NativeError {
                operation: Operation::Subscription,
                failure: Failure::CallFailed,
            })
        );
        assert!(subscriptions.removers.is_empty());
        assert_eq!(subscriptions.close(), Ok(()));
        drop(subscriptions);
        assert!(!removed.get());
    }

    #[test]
    fn modeled_subscription_removal_retries_failures_and_close_retires_callbacks() {
        let calls = Rc::new(RefCell::new(Vec::new()));
        let first = Rc::clone(&calls);
        let mut fail_first = true;
        let mut subscriptions = Subscriptions::default();
        assert_eq!(
            subscriptions.register(
                |_| Ok(()),
                move |_| {
                    first.borrow_mut().push("first");
                    if std::mem::take(&mut fail_first) {
                        Err(Error::from_hresult(HRESULT(-1)))
                    } else {
                        Ok(())
                    }
                },
            ),
            Ok(())
        );
        let second = Rc::clone(&calls);
        assert_eq!(
            subscriptions.register(
                |_| Ok(()),
                move |_| {
                    second.borrow_mut().push("second");
                    Ok(())
                },
            ),
            Ok(())
        );
        assert_eq!(
            subscriptions.close(),
            Err(NativeError {
                operation: Operation::Subscription,
                failure: Failure::CallFailed,
            })
        );
        assert_eq!(*calls.borrow(), ["second", "first"]);
        assert_eq!(subscriptions.removers.len(), 1);
        assert_eq!(subscriptions.close(), Ok(()));
        assert!(subscriptions.removers.is_empty());
        assert_eq!(*calls.borrow(), ["second", "first", "first"]);
        let third = Rc::clone(&calls);
        assert_eq!(
            subscriptions.register(
                |_| Ok(()),
                move |_| {
                    third.borrow_mut().push("third");
                    Ok(())
                },
            ),
            Ok(())
        );
        subscriptions.view_closed();
        assert!(subscriptions.removers.is_empty());
        assert_eq!(subscriptions.close(), Ok(()));
        drop(subscriptions);
        assert_eq!(*calls.borrow(), ["second", "first", "first"]);
    }
}
