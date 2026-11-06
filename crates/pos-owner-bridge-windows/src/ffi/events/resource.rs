#![cfg(windows)]

use std::rc::Rc;
use webview2_com::Microsoft::Web::WebView2::Win32::{
    ICoreWebView2, ICoreWebView2Environment, ICoreWebView2WebResourceRequestedEventArgs,
    ICoreWebView2WebResourceResponse, COREWEBVIEW2_WEB_RESOURCE_CONTEXT_ALL,
    COREWEBVIEW2_WEB_RESOURCE_CONTEXT_DOCUMENT,
};
use webview2_com::WebResourceRequestedEventHandler;
use windows::core::w;

use super::{action, observe, unavailable, Result, Subscriptions};
use crate::{EventKind, EventSink, NativeAction, NativeEvent};

pub(super) fn install(
    view: &ICoreWebView2,
    environment: &ICoreWebView2Environment,
    signals: &Rc<dyn EventSink>,
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
    let remove = view.clone();
    let handler = WebResourceRequestedEventHandler::create(Box::new(move |_sender, args| {
        if let Err(error) = filter(args, &response, observed.as_ref()) {
            observed.failed(EventKind::Resource, error);
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
