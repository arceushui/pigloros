#![cfg(windows)]

// Throwaway native observation: no response bodies, injection or wire markers.
use std::cell::RefCell;
use webview2_com::Microsoft::Web::WebView2::Win32::{
    ICoreWebView2, ICoreWebView2WebResourceRequest,
    ICoreWebView2WebResourceResponseReceivedEventArgs, ICoreWebView2_2,
};
use webview2_com::WebResourceResponseReceivedEventHandler;
use windows::core::{IUnknown, Interface};

use super::{unavailable, Result, Subscriptions};

#[derive(Default)]
struct Observation {
    requests: Vec<IUnknown>,
    response: Option<(bool, i32)>,
}

std::thread_local! {
    static OBSERVATION: RefCell<Observation> = const {
        RefCell::new(Observation { requests: Vec::new(), response: None })
    };
}

pub(super) fn reset() {
    OBSERVATION.with(|state| *state.borrow_mut() = Observation::default());
}

pub(super) fn requested(request: &ICoreWebView2WebResourceRequest) -> Result<()> {
    let identity = request.cast::<IUnknown>().map_err(|_| unavailable())?;
    OBSERVATION.with(|state| state.borrow_mut().requests.push(identity));
    Ok(())
}

impl crate::Native {
    pub(crate) fn prototype_resource_response() -> Option<(bool, i32)> {
        OBSERVATION.with(|state| state.borrow().response)
    }
}

pub(super) fn install(view: &ICoreWebView2, subscriptions: &mut Subscriptions) -> Result<()> {
    let view: ICoreWebView2_2 = view.cast().map_err(|_| unavailable())?;
    let remove = view.clone();
    let handler =
        WebResourceResponseReceivedEventHandler::create(Box::new(move |_sender, args| {
            observe_response(args)
                .map_err(|_| windows::core::Error::from_hresult(windows::Win32::Foundation::E_FAIL))
        }));
    subscriptions.register(
        |token| {
            // SAFETY: live STA interface/handler; uniquely writable token output.
            unsafe { view.add_WebResourceResponseReceived(&handler, token) }
        },
        move |token| {
            // SAFETY: exact retained subscription and invoking STA interface.
            unsafe { remove.remove_WebResourceResponseReceived(token) }
        },
    )
}

fn observe_response(args: Option<ICoreWebView2WebResourceResponseReceivedEventArgs>) -> Result<()> {
    let args = args.ok_or_else(unavailable)?;
    // SAFETY: live invoking-STA event arguments; returned request is owned COM.
    let request = unsafe { args.Request() }.map_err(|_| unavailable())?;
    let uri = super::super::text::read_text(|out| {
        // SAFETY: helper owns the initialized unique string output.
        unsafe { request.Uri(out) }
    })?;
    if uri.as_str() != crate::OWNER_URL {
        return Ok(());
    }
    let identity = request.cast::<IUnknown>().map_err(|_| unavailable())?;
    // SAFETY: live invoking-STA arguments; owned response view, no body read.
    let response = unsafe { args.Response() }.map_err(|_| unavailable())?;
    let mut status = 0;
    // SAFETY: retained live STA response view and initialized unique scalar output.
    unsafe { response.StatusCode(&raw mut status) }.map_err(|_| unavailable())?;
    OBSERVATION.with(|state| {
        let mut state = state.borrow_mut();
        let matched = state.requests.contains(&identity);
        state.response = Some((matched, status));
    });
    Ok(())
}
