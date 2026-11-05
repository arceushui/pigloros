#![cfg(windows)]

use crate::native_api::{
    EventKind, EventSink, Failure, NativeAction, NativeError, NativeEvent, NativeResult, Operation,
};
use std::rc::Rc;
use webview2_com::Microsoft::Web::WebView2::Win32::{ICoreWebView2, ICoreWebView2Environment};

mod controls;
mod navigation;
mod resource;
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
    subscriptions: &mut Subscriptions,
) -> Result<()> {
    navigation::install(view, signals, subscriptions)?;
    resource::install(view, environment, signals, subscriptions)?;
    controls::install(view, signals, subscriptions)
}

pub(super) const fn unavailable() -> NativeError {
    NativeError {
        operation: Operation::Subscription,
        failure: Failure::CallFailed,
    }
}
