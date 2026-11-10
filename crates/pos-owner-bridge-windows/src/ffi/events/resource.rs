#![cfg(windows)]

use std::rc::Rc;
use webview2_com::Microsoft::Web::WebView2::Win32::{
    ICoreWebView2, ICoreWebView2Environment, ICoreWebView2WebResourceRequestedEventArgs,
    ICoreWebView2WebResourceResponse, COREWEBVIEW2_WEB_RESOURCE_CONTEXT_ALL,
    COREWEBVIEW2_WEB_RESOURCE_CONTEXT_DOCUMENT,
};
use webview2_com::WebResourceRequestedEventHandler;
use windows::core::w;
use windows::Win32::Foundation::E_ABORT;

use super::{action, observe, unavailable, Recovery, Result, Subscriptions};
use crate::{EventKind, EventSink, NativeAction, NativeEvent};

#[cfg(test)]
std::thread_local! {
    static DENIAL_FIXTURE: std::cell::Cell<crate::ResourceDenialFixture> =
        const { std::cell::Cell::new(crate::ResourceDenialFixture::Normal) };
    static READINESS_RESOURCE: std::cell::RefCell<ResourceRegistry> = const { std::cell::RefCell::new(ResourceRegistry::new()) };
}

#[cfg(test)]
impl crate::Native {
    pub(crate) fn set_resource_denial_fixture(mode: crate::ResourceDenialFixture) {
        DENIAL_FIXTURE.with(|current| current.set(mode));
        super::denial::reset_fixture();
    }
}

#[cfg(test)]
#[derive(Default)]
struct ResourceRegistry {
    trace: Option<Rc<ResourceTrace>>,
    subscriptions: u8,
}

#[cfg(test)]
impl ResourceRegistry {
    const fn new() -> Self {
        Self {
            trace: None,
            subscriptions: 0,
        }
    }

    fn register(&mut self, trace: Rc<ResourceTrace>) {
        self.trace = Some(trace);
        self.subscriptions = self.subscriptions.saturating_add(1);
    }

    fn snapshot(&self) -> Option<(Option<u64>, u8, bool, u8)> {
        self.trace
            .as_ref()
            .map(|trace| trace.snapshot(self.subscriptions))
    }
}

#[cfg(test)]
pub(super) fn reset_readiness_resource() {
    READINESS_RESOURCE.with(|current| *current.borrow_mut() = ResourceRegistry::new());
}

#[cfg(test)]
impl crate::Native {
    // None means no recorded subscription; a captured case may also be absent.
    pub(crate) fn readiness_resource_snapshot() -> Option<(Option<u64>, u8, bool, u8)> {
        READINESS_RESOURCE.with(|current| current.borrow().snapshot())
    }
}

#[cfg(test)]
pub(super) fn fixture() -> crate::ResourceDenialFixture {
    DENIAL_FIXTURE.with(std::cell::Cell::get)
}

/// One subscription's bounded, case-bound readiness observations.
#[cfg(test)]
struct ResourceTrace {
    prefix: &'static str,
    case: Option<(u64, std::time::Instant)>,
    callbacks: std::cell::Cell<u8>,
}

#[cfg(test)]
impl ResourceTrace {
    fn snapshot(&self, subscriptions: u8) -> (Option<u64>, u8, bool, u8) {
        let count = self.callbacks.get();
        (
            self.case.map(|(case, _)| case),
            count.min(8),
            count > 8,
            subscriptions,
        )
    }

    fn begin(&self) -> Option<u8> {
        use std::io::Write as _;
        let count = self.callbacks.get();
        if count >= 9 {
            return None;
        }
        self.callbacks.set(count + 1);
        let (case, started) = self.case?;
        if count == 8 {
            let _logged_or_unavailable = writeln!(
                std::io::stderr(),
                "{} case={case} elapsed={:?} overflow=true",
                self.prefix,
                started.elapsed()
            );
            return None;
        }
        let _logged_or_unavailable = writeln!(
            std::io::stderr(),
            "{} case={case} elapsed={:?} callback={} stage=entered",
            self.prefix,
            started.elapsed(),
            count + 1
        );
        Some(count + 1)
    }

    fn decision(&self, report: Option<u8>, document: Option<bool>, selected: NativeAction) {
        let Some(callback) = report else {
            return;
        };
        if let Some((case, started)) = self.case {
            use std::io::Write as _;
            let _logged_or_unavailable = writeln!(std::io::stderr(),
                "{} case={case} elapsed={:?} callback={callback} stage=decision document={document:?} allow={}",
                self.prefix, started.elapsed(), selected == NativeAction::Allow);
        }
    }

    fn returning(&self, report: Option<u8>, success: bool) {
        let Some(callback) = report else {
            return;
        };
        if let Some((case, started)) = self.case {
            use std::io::Write as _;
            let _logged_or_unavailable = writeln!(
                std::io::stderr(),
                "{} case={case} elapsed={:?} callback={callback} stage=returning success={success}",
                self.prefix,
                started.elapsed()
            );
        }
    }
}

#[test]
fn resource_trace_retains_its_case_and_bounds_callback_output() {
    let start = std::time::Instant::now();
    crate::Native::readiness_navigation_case(Some((11, start)));
    let trace = Rc::new(ResourceTrace {
        prefix: "NATIVE_RESOURCE_UNIT",
        case: super::navigation::readiness_context(),
        callbacks: std::cell::Cell::new(0),
    });
    let mut registry = ResourceRegistry::new();
    registry.register(Rc::clone(&trace));
    crate::Native::readiness_navigation_case(Some((12, start)));
    assert_eq!(trace.case, Some((11, start)));
    for _ in 0..8 {
        assert!(trace.begin().is_some());
    }
    assert!(trace.begin().is_none());
    assert!(trace.begin().is_none());
    assert_eq!(trace.callbacks.get(), 9);
    assert_eq!(registry.snapshot(), Some((Some(11), 8, true, 1)));
    registry.register(Rc::clone(&trace));
    assert_eq!(registry.snapshot(), Some((Some(11), 8, true, 2)));
    registry = ResourceRegistry::new();
    assert!(registry.snapshot().is_none());
    trace.decision(Some(1), Some(true), NativeAction::Allow);
    trace.returning(Some(1), true);
    let disabled = ResourceTrace {
        prefix: "NATIVE_RESOURCE_UNIT",
        case: None,
        callbacks: std::cell::Cell::new(0),
    };
    assert!(disabled.begin().is_none());
    assert_eq!(disabled.callbacks.get(), 1);
    for _ in 0..10 {
        assert!(disabled.begin().is_none());
    }
    assert_eq!(disabled.callbacks.get(), 9);
    assert_eq!(disabled.snapshot(1), (None, 8, true, 1));
    assert!(crate::Native::readiness_resource_snapshot().is_none());
    crate::Native::readiness_navigation_case(None);
}

pub(super) fn install(
    view: &ICoreWebView2,
    environment: &ICoreWebView2Environment,
    signals: &Rc<dyn EventSink>,
    recovery: &Rc<Recovery>,
    subscriptions: &mut Subscriptions,
) -> Result<()> {
    // Prepare the immutable, bodyless denial before subscribing or navigating.
    // Allocation failure here refuses activation before any request is in flight.
    // SAFETY: retained STA environment; null body and fixed status/header strings
    // create only a host-owned denial response with no network or input data.
    let response = unsafe {
        environment.CreateWebResourceResponse(
            None,
            403,
            w!("Forbidden"),
            w!("Content-Length: 0\r\nCache-Control: no-store\r\n"),
        )
    }
    .map_err(|_| unavailable())?;
    let observed = Rc::clone(signals);
    let cancellation = Rc::clone(recovery);
    let intercepted = view.clone();
    let remove = view.clone();
    #[cfg(test)]
    let trace = Rc::new(ResourceTrace {
        prefix: "NATIVE_RESOURCE",
        case: super::navigation::readiness_context(),
        callbacks: std::cell::Cell::new(0),
    });
    #[cfg(test)]
    let retained_trace = Rc::clone(&trace);
    let handler = WebResourceRequestedEventHandler::create(Box::new(move |_sender, args| {
        #[cfg(test)]
        let reporting = trace.begin();
        if let Err(error) = filter(
            args.clone(),
            &response,
            observed.as_ref(),
            #[cfg(test)]
            (&trace, reporting),
        ) {
            observed.failed(EventKind::Resource, error);
            // The negative control deliberately reproduces the former swallowed
            // failure. It exists only in the native qualification test binary.
            #[cfg(test)]
            if DENIAL_FIXTURE
                .with(|mode| mode.get() == crate::ResourceDenialFixture::SwallowFailure)
            {
                trace.returning(reporting, true);
                return Ok(());
            }
            cancellation.deny(args, intercepted.clone(), Rc::clone(&observed));
            #[cfg(test)]
            trace.returning(reporting, false);
            return Err(windows::core::Error::from_hresult(E_ABORT));
        }
        #[cfg(test)]
        trace.returning(reporting, true);
        Ok(())
    }));
    subscriptions.register(
        |token| {
            // SAFETY: live STA interface/handler and initialized unique token output.
            unsafe { view.add_WebResourceRequested(&handler, token) }
        },
        move |token| {
            // SAFETY: exact subscription token on its retained STA interface.
            unsafe { remove.remove_WebResourceRequested(token) }
        },
    )?;
    #[cfg(test)]
    {
        READINESS_RESOURCE.with(|current| current.borrow_mut().register(retained_trace));
    }
    // SAFETY: fixed wildcard and ALL context; the installed handler selects
    // the pre-created denial unless the exact owner document is admitted.
    unsafe { view.AddWebResourceRequestedFilter(w!("*"), COREWEBVIEW2_WEB_RESOURCE_CONTEXT_ALL) }
        .map_err(|_| unavailable())
}

fn filter(
    args: Option<ICoreWebView2WebResourceRequestedEventArgs>,
    response: &ICoreWebView2WebResourceResponse,
    signals: &dyn EventSink,
    #[cfg(test)] diagnostic: (&ResourceTrace, Option<u8>),
) -> Result<()> {
    let args = args.ok_or_else(unavailable)?;
    let request = owner_request(&args);
    #[cfg(test)]
    let document = match &request {
        Ok(NativeEvent::Resource { document, .. }) => Some(*document),
        _ => None,
    };
    let selected = observe(signals, EventKind::Resource, request);
    // Reach the production Surface/driver/keeper cleanup chain with a real
    // request/deferral, without changing the pinned owner asset or network URL.
    #[cfg(test)]
    let selected = if fixture() == crate::ResourceDenialFixture::DriverRetry {
        NativeAction::BlockResource
    } else {
        selected
    };
    #[cfg(test)]
    diagnostic.0.decision(diagnostic.1, document, selected);
    if selected != NativeAction::Allow {
        action(
            signals,
            EventKind::Resource,
            selected,
            NativeAction::BlockResource,
        );
        #[cfg(test)]
        if DENIAL_FIXTURE.with(|mode| mode.get() != crate::ResourceDenialFixture::Normal) {
            return Err(unavailable());
        }
        // SAFETY: live event arguments and host-created denial response; COM
        // retains its own reference for this intercepted request.
        unsafe { args.SetResponse(response) }.map_err(|_| unavailable())?;
    }
    Ok(())
}

fn owner_request(args: &ICoreWebView2WebResourceRequestedEventArgs) -> Result<NativeEvent> {
    // SAFETY: live event arguments on the callback STA; COM-owned request result.
    let request = unsafe { args.Request() }.map_err(|_| unavailable())?;
    let uri = super::super::text::read_text(|out| {
        // SAFETY: the string helper provides initialized uniquely writable output.
        unsafe { request.Uri(out) }
    })?;
    let mut context = COREWEBVIEW2_WEB_RESOURCE_CONTEXT_ALL;
    // SAFETY: live arguments and initialized writable context scalar.
    unsafe { args.ResourceContext(&raw mut context) }.map_err(|_| unavailable())?;
    Ok(NativeEvent::Resource {
        uri,
        document: context == COREWEBVIEW2_WEB_RESOURCE_CONTEXT_DOCUMENT,
    })
}
