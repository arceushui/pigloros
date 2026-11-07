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

use super::{action, observe, unavailable, Result, Subscriptions};
use crate::{EventKind, EventSink, NativeAction, NativeEvent};

#[cfg(test)]
type PrototypeHeldResource = (
    webview2_com::Microsoft::Web::WebView2::Win32::ICoreWebView2Deferral,
    ICoreWebView2WebResourceRequestedEventArgs,
    ICoreWebView2WebResourceResponse,
);

#[cfg(test)]
std::thread_local! {
    static DENIAL_FIXTURE: std::cell::Cell<crate::ResourceDenialFixture> =
        const { std::cell::Cell::new(crate::ResourceDenialFixture::Normal) };
    // PROTOTYPE ONLY: deliberately retained until an observed browser exit or
    // an explicit controlled Complete. Never an automatically completing guard.
    static PROTOTYPE_HELD: std::cell::RefCell<Vec<PrototypeHeldResource>> =
        const { std::cell::RefCell::new(Vec::new()) };
}

#[cfg(test)]
impl crate::Native {
    pub(crate) fn prototype_before_close() -> Result<()> {
        if DENIAL_FIXTURE.with(|mode| mode.get() == crate::ResourceDenialFixture::PrototypeHeld)
            && PROTOTYPE_HELD.with(|held| !held.borrow().is_empty())
        {
            return Err(unavailable());
        }
        Ok(())
    }

    pub(crate) fn set_resource_denial_fixture(mode: crate::ResourceDenialFixture) {
        DENIAL_FIXTURE.with(|current| current.set(mode));
        PROTOTYPE_HELD.with(|held| held.borrow_mut().clear());
        super::response_prototype::reset();
    }
    pub(crate) fn prototype_complete_resource(deny: bool) -> Result<()> {
        PROTOTYPE_HELD.with(|held| {
            let (deferral, args, response) = held.borrow_mut().pop().ok_or_else(unavailable)?;
            if deny {
                // SAFETY: test-only retained arguments and response, on their callback STA.
                unsafe { args.SetResponse(&response) }.map_err(|_| unavailable())?;
            }
            // SAFETY: test-only retained deferral, completed exactly once on its STA.
            unsafe { deferral.Complete() }.map_err(|_| unavailable())
        })
    }
}

pub(super) fn install(
    view: &ICoreWebView2,
    environment: &ICoreWebView2Environment,
    signals: &Rc<dyn EventSink>,
    subscriptions: &mut Subscriptions,
) -> Result<()> {
    #[cfg(test)]
    super::response_prototype::install(view, subscriptions)?;
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
    let remove = view.clone();
    let handler = WebResourceRequestedEventHandler::create(Box::new(move |_sender, args| {
        if let Err(error) = filter(args, &response, observed.as_ref()) {
            observed.failed(EventKind::Resource, error);
            // The negative control deliberately reproduces the former swallowed
            // failure. It exists only in the native qualification test binary.
            #[cfg(test)]
            if DENIAL_FIXTURE.with(|mode| {
                mode.get() != crate::ResourceDenialFixture::PropagateFailure
                    && mode.get() != crate::ResourceDenialFixture::Normal
            }) {
                return Ok(());
            }
            return Err(windows::core::Error::from_hresult(E_ABORT));
        }
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
    // SAFETY: fixed wildcard and ALL context; the installed handler selects
    // the pre-created denial unless the exact owner document is admitted.
    unsafe { view.AddWebResourceRequestedFilter(w!("*"), COREWEBVIEW2_WEB_RESOURCE_CONTEXT_ALL) }
        .map_err(|_| unavailable())
}

fn filter(
    args: Option<ICoreWebView2WebResourceRequestedEventArgs>,
    response: &ICoreWebView2WebResourceResponse,
    signals: &dyn EventSink,
) -> Result<()> {
    let args = args.ok_or_else(unavailable)?;
    let selected = observe(signals, EventKind::Resource, owner_request(&args));
    if selected != NativeAction::Allow {
        action(
            signals,
            EventKind::Resource,
            selected,
            NativeAction::BlockResource,
        );
        #[cfg(test)]
        if DENIAL_FIXTURE.with(|mode| mode.get() != crate::ResourceDenialFixture::Normal) {
            if DENIAL_FIXTURE.with(|mode| {
                matches!(
                    mode.get(),
                    crate::ResourceDenialFixture::PrototypeHeld
                        | crate::ResourceDenialFixture::PrototypeResponseBarrier
                        | crate::ResourceDenialFixture::PrototypeCloseFirst
                        | crate::ResourceDenialFixture::PrototypeDrop
                        | crate::ResourceDenialFixture::PrototypeCompleteAllowed
                        | crate::ResourceDenialFixture::PrototypeCompleteDenied
                )
            }) {
                // SAFETY: live event arguments on their callback STA; prototype
                // retains the owned deferral and args instead of completing it.
                let deferral = unsafe { args.GetDeferral() }.map_err(|_| unavailable())?;
                if DENIAL_FIXTURE
                    .with(|mode| mode.get() == crate::ResourceDenialFixture::PrototypeDrop)
                {
                    drop(deferral);
                } else {
                    PROTOTYPE_HELD.with(|held| {
                        held.borrow_mut().push((deferral, args, response.clone()));
                    });
                }
            }
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
    #[cfg(test)]
    super::response_prototype::requested(&request)?;
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
