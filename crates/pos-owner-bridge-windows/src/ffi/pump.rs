#![cfg(windows)]

use std::cell::Cell;
use std::marker::PhantomData;
use std::rc::Rc;

use crate::{Failure, NativeError, NativePulse, NativeResult, Operation};
use windows::Win32::System::Com::{
    CoInitializeEx, CoUninitialize, COINIT_APARTMENTTHREADED, COINIT_DISABLE_OLE1DDE,
};
use windows::Win32::UI::WindowsAndMessaging::{
    DispatchMessageW, GetMessageW, KillTimer, SetTimer, TranslateMessage, MSG, WM_TIMER,
};

type Result<T> = NativeResult<T>;

struct Apartment(PhantomData<Rc<()>>);

impl Apartment {
    fn new() -> Result<Self> {
        // SAFETY: initialize this dedicated surface thread as a COM STA. Both
        // S_OK and S_FALSE require one matching CoUninitialize on this thread;
        // an existing incompatible apartment is refused.
        unsafe { CoInitializeEx(None, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE) }
            .ok()
            .map_err(|_| unavailable())?;
        Ok(Self(PhantomData))
    }
}

impl Drop for Apartment {
    fn drop(&mut self) {
        // SAFETY: !Send affinity and stack/field order keep this on the thread
        // initialized above, after every WebView COM owner has been released.
        unsafe { CoUninitialize() };
    }
}

pub(super) struct StaToken {
    thread: std::thread::ThreadId,
    progress: Cell<u64>,
    // The final session/factory token is released after every COM owner.
    _apartment: Apartment,
}

impl StaToken {
    pub(super) const fn progress(&self) -> u64 {
        self.progress.get()
    }

    pub(super) fn check(&self) -> Result<()> {
        if std::thread::current().id() == self.thread {
            Ok(())
        } else {
            Err(NativeError {
                operation: Operation::Sta,
                failure: Failure::WrongSta,
            })
        }
    }
}

pub(super) struct Pump {
    timer: usize,
    pub(super) token: Rc<StaToken>,
}

impl Pump {
    pub(super) fn new() -> Result<Self> {
        let apartment = Apartment::new()?;
        // SAFETY: create a thread timer without any callback pointer or HWND.
        // Its WM_TIMER messages survive ceremony-window loss, so every release
        // and browser-exit timeout can still advance the portable driver.
        let timer = unsafe { SetTimer(None, 0, 10, None) };
        if timer == 0 {
            return Err(unavailable());
        }
        Ok(Self {
            timer,
            token: Rc::new(StaToken {
                thread: std::thread::current().id(),
                progress: Cell::new(0),
                _apartment: apartment,
            }),
        })
    }

    pub(super) fn next(&self) -> Result<NativePulse> {
        self.token.check()?;
        // One sequence for the existing outer pump invocation, including COM
        // callbacks dispatched by GetMessage. Cleanup and queue-drain calls
        // within that progression cannot create additional retry authority.
        self.token
            .progress
            .set(self.token.progress.get().wrapping_add(1));
        let mut message = MSG::default();
        // SAFETY: initialized writable MSG; this dedicated STA owns this queue;
        // no HWND restriction, so thread timers and COM callbacks are serviced.
        let status = unsafe { GetMessageW(&raw mut message, None, 0, 0) };
        if status.0 == -1 {
            return Err(unavailable());
        }
        if status.0 == 0 {
            return Ok(NativePulse::Quit);
        }
        if message.message == WM_TIMER && message.hwnd.0.is_null() && message.wParam.0 == self.timer
        {
            return Ok(NativePulse::Timer);
        }
        if super::window::intercept(&message) {
            return Ok(NativePulse::Dispatched);
        }
        // SAFETY: only a successful GetMessage result is translated. Its BOOL
        // reports whether translation occurred, not success/failure.
        let _translated = unsafe { TranslateMessage(&raw const message) };
        // SAFETY: the same valid initialized message is dispatched on its
        // owning STA. The LRESULT is the procedure's message-specific result.
        let _result = unsafe { DispatchMessageW(&raw const message) };
        Ok(NativePulse::Dispatched)
    }

    pub(super) fn stop_timer(&mut self) -> Result<()> {
        self.token.check()?;
        if self.timer != 0 {
            // SAFETY: this thread owns the still-live timer identifier.
            unsafe { KillTimer(None, self.timer) }.map_err(|_| unavailable())?;
            self.timer = 0;
        }
        Ok(())
    }
}

impl Drop for Pump {
    fn drop(&mut self) {
        // Normal shutdown checks this result explicitly. The fallback cannot
        // turn destruction into a new operation; ending the STA removes its
        // timer even if the explicit final cleanup call failed.
        let _stopped = self.stop_timer();
    }
}

const fn unavailable() -> NativeError {
    NativeError {
        operation: Operation::Sta,
        failure: Failure::CallFailed,
    }
}

#[cfg(test)]
impl crate::Native {
    pub(crate) fn retain_fault_apartment() -> Result<impl Drop> {
        Apartment::new()
    }
}
