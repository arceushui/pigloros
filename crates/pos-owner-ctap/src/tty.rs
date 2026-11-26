//! The Linux terminal `PinPrompt` (ADR-110 E20 LP5, G3, G6).
//!
//! The owner root opens `/dev/tty` with `O_RDWR | O_NOCTTY | O_CLOEXEC` and passes the fd in;
//! tests pass a pseudo-terminal. Each PIN entry turns echo and signal characters off, shows the
//! prompt, reads the line one byte at a time into the caller's fixed [`PinBuffer`], and then
//! restores the terminal settings and discards unread input on every path that runs destructors,
//! including unwinding. The PIN is never a `String`, a log line, an argument or an environment
//! value. A newline ends the entry, Ctrl-C (read as a byte, because signals are off) cancels it,
//! and a PIN beyond the buffer is refused.
//!
//! The terminal stays in canonical mode, so the kernel's line editing (erase, kill) applies and
//! Ctrl-D is the end-of-file character: on an empty line it cancels the entry, and after typed
//! characters it only hands them over and the entry goes on until a newline or a second Ctrl-D.
//! Flow-control characters (Ctrl-S, Ctrl-Q) and the extended characters (Ctrl-V, Ctrl-O) are
//! turned off so that they reach the PIN like any other byte.
//!
//! Restoring needs a destructor to run. `SIGKILL` and an unhandled `SIGTERM` or `SIGHUP` end the
//! process without one, so a terminal that outlives the owner process can be left with echo off.
//! That is outside LP5's "every path, including unwinding": the owner installs no handlers, and
//! the shell's own `stty sane` or `reset` brings echo back.

use std::os::fd::OwnedFd;
use std::time::Instant;

use pos_owner_bridge::{BridgeError, LifecycleCode, MonotonicClock, UnavailableCode};
use rustix::fs::{fcntl_setfl, OFlags};
use rustix::io::{read, write};
use rustix::termios::{tcgetattr, tcsetattr, InputModes, LocalModes, OptionalActions, Termios};
use zeroize::Zeroizing;

use crate::fdwait::{wait_readable, Wait};
use crate::prompt::{Notice, PinBuffer, PinPrompt};

const CLIENT_FAILED: BridgeError = BridgeError::Lifecycle(LifecycleCode::ClientFailed);
const TIMEOUT: BridgeError = BridgeError::Lifecycle(LifecycleCode::InteractionTimeout);
const NO_TERMINAL: BridgeError = BridgeError::Unavailable(UnavailableCode::InterfaceUnavailable);

/// Ctrl-C, which arrives as a byte because the terminal's signal characters are off.
const CANCEL: u8 = 0x03;

/// The local modes an entry turns off: no echo, no signal characters, no extended characters.
const QUIET_LOCAL: LocalModes = LocalModes::ECHO
    .union(LocalModes::ISIG)
    .union(LocalModes::IEXTEN);

/// Puts the settings the terminal had at the start of the entry back, and discards unread input,
/// when dropped.
struct Restore<'a> {
    fd: &'a OwnedFd,
    saved: Termios,
}

impl Drop for Restore<'_> {
    fn drop(&mut self) {
        tcsetattr(self.fd, OptionalActions::Flush, &self.saved).ok();
    }
}

/// A PIN prompt on a terminal file descriptor.
pub struct TtyPrompt {
    fd: OwnedFd,
}

impl TtyPrompt {
    /// Prompt on `fd`, which must be a terminal.
    ///
    /// The descriptor is made non-blocking, so a read that `poll` did not announce cannot hang.
    ///
    /// # Errors
    ///
    /// Returns `Unavailable(InterfaceUnavailable)` when `fd` is not a terminal.
    pub fn new(fd: OwnedFd) -> Result<Self, BridgeError> {
        tcgetattr(&fd).or(Err(NO_TERMINAL))?;
        fcntl_setfl(&fd, OFlags::NONBLOCK).ok();
        Ok(Self { fd })
    }

    /// Show `text` on the terminal, continuing after a partial write. A terminal that cannot take
    /// the rest, because it is gone or full, is not an error: the entry that follows fails or
    /// times out on its own. A zero-byte write is not detected: a terminal never reports one for
    /// non-empty text.
    fn show(&self, mut text: &[u8]) {
        while !text.is_empty() {
            match write(&self.fd, text) {
                Ok(written) => text = text.get(written..).unwrap_or_default(),
                Err(_) => return,
            }
        }
    }

    /// Read one line into `pin` until `deadline`.
    fn collect(
        &self,
        pin: &mut PinBuffer,
        deadline: Instant,
        clock: &dyn MonotonicClock,
    ) -> Result<(), BridgeError> {
        let mut byte = Zeroizing::new([0_u8; 1]);
        loop {
            let remaining = deadline.saturating_duration_since(clock.now());
            if remaining.is_zero() {
                return Err(TIMEOUT);
            }
            // The poll is bounded by the time left, so an idle wait is the deadline itself.
            match wait_readable(&self.fd, remaining) {
                Wait::Idle => return Err(TIMEOUT),
                Wait::Gone => return Err(CLIENT_FAILED),
                Wait::Readable => match read(&self.fd, &mut byte[..]) {
                    Ok(1) => match byte[0] {
                        b'\n' | b'\r' => return Ok(()),
                        CANCEL => return Err(CLIENT_FAILED),
                        other => {
                            if !pin.push(other) {
                                return Err(CLIENT_FAILED);
                            }
                        }
                    },
                    _ => return Err(CLIENT_FAILED),
                },
            }
        }
    }
}

impl PinPrompt for TtyPrompt {
    fn read_pin(
        &mut self,
        retries: u64,
        pin: &mut PinBuffer,
        deadline: Instant,
        clock: &dyn MonotonicClock,
    ) -> Result<(), BridgeError> {
        let saved = tcgetattr(&self.fd)
            .and_then(|saved| {
                let mut quiet = saved.clone();
                quiet.local_modes.remove(QUIET_LOCAL);
                quiet.input_modes.remove(InputModes::IXON);
                tcsetattr(&self.fd, OptionalActions::Flush, &quiet).map(|()| saved)
            })
            .or(Err(CLIENT_FAILED))?;
        let restore = Restore {
            fd: &self.fd,
            saved,
        };
        self.show(format!("Security key PIN ({retries} attempts left): ").as_bytes());
        let result = self.collect(pin, deadline, clock);
        self.show(b"\n");
        drop(restore);
        result
    }

    fn notice(&mut self, notice: Notice) {
        let text = match notice {
            Notice::Touch => "Touch your security key.\n".to_owned(),
            Notice::UserVerification { retries } => {
                format!("Verify on your security key ({retries} attempts left).\n")
            }
            Notice::PinBlocked => {
                "The security key PIN is blocked: reset the key or power-cycle it.\n".to_owned()
            }
        };
        self.show(text.as_bytes());
    }
}
