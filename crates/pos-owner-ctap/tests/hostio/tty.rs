//! The terminal prompt over pseudo-terminals: echo, restoring, cancelling, bounds and unwinding.

use std::cell::Cell;
use std::fs::File;
use std::os::fd::OwnedFd;
use std::panic::{catch_unwind, resume_unwind, AssertUnwindSafe};
use std::thread;
use std::time::{Duration, Instant};

use pos_owner_bridge::fake::clock::FakeClock;
use pos_owner_bridge::{BridgeError, LifecycleCode, MonotonicClock, UnavailableCode};
use pos_owner_ctap::fdwait::{wait_readable, Wait};
use pos_owner_ctap::{
    CtapAuthenticator, Drbg, MemoryHid, Notice, PinBuffer, PinPrompt, SoftAuthenticator, TtyPrompt,
};
use rustix::fs::{fcntl_getfl, OFlags};
use rustix::io::{dup, write};
use rustix::termios::{tcgetattr, tcsetattr, InputModes, LocalModes, OptionalActions};

use super::{
    contains, enroll_and_unlock, pty, run_prompt, Pty, TestResult, Ticking, User, PIN, PROMPT,
};

const CLIENT_FAILED: BridgeError = BridgeError::Lifecycle(LifecycleCode::ClientFailed);
const TIMEOUT: BridgeError = BridgeError::Lifecycle(LifecycleCode::InteractionTimeout);
const NO_TERMINAL: BridgeError = BridgeError::Unavailable(UnavailableCode::InterfaceUnavailable);
const FIVE_SECONDS: Duration = Duration::from_secs(5);
const MILLISECOND: Duration = Duration::from_millis(1);

#[test]
fn a_pin_is_read_without_echo_and_the_terminal_is_restored() -> TestResult {
    let run = run_prompt(MILLISECOND, FIVE_SECONDS, |user| {
        user.wait_for(PROMPT)?;
        user.type_line(b"2468\n")
    })?;
    assert_eq!(run.result, Ok(()));
    assert!(contains(
        &run.output,
        b"Security key PIN (4 attempts left): "
    ));
    assert!(!contains(&run.output, PIN));
    assert!(run.before.contains(LocalModes::ECHO | LocalModes::ISIG));
    assert_eq!(run.after, run.before);
    Ok(())
}

#[test]
fn a_pin_beyond_the_buffer_is_refused() -> TestResult {
    let run = run_prompt(MILLISECOND, FIVE_SECONDS, |user| {
        user.wait_for(PROMPT)?;
        user.type_line(&[b'a'; 70])?;
        user.type_line(b"\n")
    })?;
    assert_eq!(run.result, Err(CLIENT_FAILED));
    assert_eq!(run.after, run.before);
    Ok(())
}

#[test]
fn ctrl_c_cancels_the_entry() -> TestResult {
    let run = run_prompt(MILLISECOND, FIVE_SECONDS, |user| {
        user.wait_for(PROMPT)?;
        user.type_line(b"ab\x03\n")
    })?;
    assert_eq!(run.result, Err(CLIENT_FAILED));
    assert_eq!(run.after, run.before);
    Ok(())
}

#[test]
fn ctrl_d_at_the_start_of_a_line_cancels_the_entry() -> TestResult {
    let run = run_prompt(MILLISECOND, FIVE_SECONDS, |user| {
        user.wait_for(PROMPT)?;
        user.type_line(b"\x04")
    })?;
    assert_eq!(run.result, Err(CLIENT_FAILED));
    assert_eq!(run.after, run.before);
    Ok(())
}

#[test]
fn the_entry_gives_up_at_the_deadline() -> TestResult {
    // The deadline is 50 ms away and the clock moves 40 ms a read: the first wait has 10 ms
    // left, nobody types, and the idle poll is itself the timeout.
    let run = run_prompt(
        Duration::from_millis(40),
        Duration::from_millis(50),
        |user| user.wait_for(PROMPT),
    )?;
    assert_eq!(run.result, Err(TIMEOUT));
    assert_eq!(run.after, run.before);
    Ok(())
}

/// A clock whose first read types `line` at the terminal and waits until the owner's side has it,
/// and then reports `late`. The deadline of the entry is the start, so it has passed by then.
struct TypesThenExpires<'a> {
    master: &'a OwnedFd,
    probe: OwnedFd,
    line: &'a [u8],
    late: Instant,
    typed: Cell<bool>,
}

impl MonotonicClock for TypesThenExpires<'_> {
    fn now(&self) -> Instant {
        if !self.typed.replace(true) {
            let written = write(self.master, self.line).unwrap_or(0);
            assert_eq!(written, self.line.len());
            assert_eq!(wait_readable(&self.probe, FIVE_SECONDS), Wait::Readable);
        }
        self.late
    }
}

#[test]
fn a_deadline_that_has_passed_reads_nothing() -> TestResult {
    let Pty { master, slave } = pty()?;
    let probe = dup(&slave)?;
    let mut prompt = TtyPrompt::new(slave)?;
    let start = FakeClock::start().now();
    let clock = TypesThenExpires {
        master: &master,
        probe,
        line: b"2468\n",
        late: start + Duration::from_secs(1),
        typed: Cell::new(false),
    };
    let mut pin = PinBuffer::new();
    // A whole line waits on the terminal when the entry looks at the clock, and the entry still
    // reads none of it.
    assert_eq!(prompt.read_pin(4, &mut pin, start, &clock), Err(TIMEOUT));
    Ok(())
}

#[test]
fn echo_flow_control_and_extended_characters_are_off_during_the_entry() -> TestResult {
    let run = run_prompt(MILLISECOND, FIVE_SECONDS, |user| {
        user.wait_for(PROMPT)?;
        let modes = tcgetattr(user.master).map_err(|error| error.to_string())?;
        let loud = LocalModes::ECHO | LocalModes::ISIG | LocalModes::IEXTEN;
        let quiet = !modes.local_modes.intersects(loud);
        let flow = modes.input_modes.contains(InputModes::IXON);
        user.type_line(b"2468\n")?;
        if quiet && !flow {
            Ok(())
        } else {
            Err("the terminal was not quiet".to_owned())
        }
    })?;
    assert_eq!(run.result, Ok(()));
    let loud = LocalModes::ECHO | LocalModes::ISIG | LocalModes::IEXTEN;
    assert!(run.before.contains(loud));
    assert_eq!(run.after, run.before);
    Ok(())
}

#[test]
fn the_terminal_is_restored_to_what_it_was_at_the_start_of_the_entry() -> TestResult {
    let Pty { master, slave } = pty()?;
    let mut prompt = TtyPrompt::new(slave)?;
    // Another program changes the terminal after the prompt was made.
    let mut changed = tcgetattr(&master)?;
    changed.local_modes.insert(LocalModes::ECHONL);
    changed.input_modes.remove(InputModes::IXON);
    tcsetattr(&master, OptionalActions::Now, &changed)?;
    let clock = Ticking::new(FakeClock::start(), MILLISECOND);
    let deadline = clock.now() + FIVE_SECONDS;
    let result = thread::scope(|scope| {
        let user = scope.spawn(|| {
            let mut user = User::new(&master);
            user.wait_for(PROMPT)?;
            user.type_line(b"2468\n")
        });
        let result = prompt.read_pin(4, &mut PinBuffer::new(), deadline, &clock);
        (result, user.join())
    });
    assert_eq!(result.0, Ok(()));
    assert_eq!(result.1.map_err(|_| ()), Ok(Ok(())));
    let after = tcgetattr(&master)?;
    assert!(after.local_modes.contains(LocalModes::ECHONL));
    assert!(!after.input_modes.contains(InputModes::IXON));
    Ok(())
}

#[test]
fn ctrl_d_after_typed_characters_only_hands_them_over() -> TestResult {
    // Thirty bytes, Ctrl-D, thirty more and a newline: the first Ctrl-D delivers the typed bytes
    // and the entry goes on to the newline, so the sixty bytes fit the buffer.
    let run = run_prompt(MILLISECOND, FIVE_SECONDS, |user| {
        user.wait_for(PROMPT)?;
        user.type_line(&[b'a'; 30])?;
        user.type_line(b"\x04")?;
        user.type_line(&[b'b'; 30])?;
        user.type_line(b"\n")
    })?;
    assert_eq!(run.result, Ok(()));
    assert_eq!(run.after, run.before);
    Ok(())
}

#[test]
fn a_terminal_that_hangs_up_during_the_entry_fails_it() -> TestResult {
    let Pty { master, slave } = pty()?;
    let mut prompt = TtyPrompt::new(slave)?;
    let clock = Ticking::new(FakeClock::start(), MILLISECOND);
    let deadline = clock.now() + FIVE_SECONDS;
    let mut pin = PinBuffer::new();
    let result = thread::scope(|scope| {
        let hangup = scope.spawn(move || {
            let played = User::new(&master).wait_for(PROMPT);
            drop(master);
            played
        });
        let result = prompt.read_pin(4, &mut pin, deadline, &clock);
        (result, hangup.join())
    });
    assert_eq!(result.0, Err(CLIENT_FAILED));
    assert_eq!(result.1.map_err(|_| ()), Ok(Ok(())));
    Ok(())
}

#[test]
fn a_terminal_that_is_gone_before_the_entry_fails_it() -> TestResult {
    let Pty { master, slave } = pty()?;
    let mut prompt = TtyPrompt::new(slave)?;
    drop(master);
    let clock = Ticking::new(FakeClock::start(), MILLISECOND);
    let deadline = clock.now() + FIVE_SECONDS;
    let result = prompt.read_pin(4, &mut PinBuffer::new(), deadline, &clock);
    assert_eq!(result, Err(CLIENT_FAILED));
    Ok(())
}

/// A clock that unwinds when it is read.
struct Unwinding;

impl MonotonicClock for Unwinding {
    fn now(&self) -> Instant {
        resume_unwind(Box::new("the clock unwound"))
    }
}

#[test]
fn the_terminal_is_restored_when_the_entry_unwinds() -> TestResult {
    let Pty { master, slave } = pty()?;
    let mut prompt = TtyPrompt::new(slave)?;
    let before = tcgetattr(&master)?.local_modes;
    let outcome = catch_unwind(AssertUnwindSafe(|| {
        prompt.read_pin(4, &mut PinBuffer::new(), Instant::now(), &Unwinding)
    }));
    assert!(outcome.is_err());
    assert_eq!(tcgetattr(&master)?.local_modes, before);
    assert!(before.contains(LocalModes::ECHO));
    Ok(())
}

#[test]
fn a_descriptor_that_is_not_a_terminal_is_unavailable() -> TestResult {
    let not_a_terminal = OwnedFd::from(File::open("/dev/null")?);
    assert_eq!(TtyPrompt::new(not_a_terminal).err(), Some(NO_TERMINAL));
    Ok(())
}

#[test]
fn the_terminal_descriptor_is_made_non_blocking() -> TestResult {
    let Pty {
        master: _master,
        slave,
    } = pty()?;
    let probe = dup(&slave)?;
    assert!(!fcntl_getfl(&probe)?.contains(OFlags::NONBLOCK));
    let _prompt = TtyPrompt::new(slave)?;
    assert!(fcntl_getfl(&probe)?.contains(OFlags::NONBLOCK));
    Ok(())
}

#[test]
fn notices_show_fixed_text() -> TestResult {
    let Pty { master, slave } = pty()?;
    let mut prompt = TtyPrompt::new(slave)?;
    prompt.notice(Notice::Touch);
    prompt.notice(Notice::UserVerification { retries: 2 });
    prompt.notice(Notice::PinBlocked);
    let mut user = User::new(&master);
    user.wait_for(b"power-cycle it.")?;
    assert!(contains(user.seen(), b"Touch your security key."));
    assert!(contains(
        user.seen(),
        b"Verify on your security key (2 attempts left)."
    ));
    Ok(())
}

#[test]
fn a_pin_typed_at_a_terminal_enrolls_and_unlocks_with_the_software_key() -> TestResult {
    let Pty { master, slave } = pty()?;
    let fake = FakeClock::start();
    let device = MemoryHid::new(SoftAuthenticator::new("tty-tier", PIN, false), fake.clone());
    let mut port = CtapAuthenticator::new(device, TtyPrompt::new(slave)?, Drbg::new("tty-client"));
    let clock = Ticking::new(fake, MILLISECOND);
    let (outcome, typed) = thread::scope(|scope| {
        let user = scope.spawn(|| {
            let mut user = User::new(&master);
            for _ in 0..3 {
                user.wait_for(PROMPT)?;
                user.type_line(b"2468\n")?;
            }
            Ok::<(), String>(())
        });
        (
            enroll_and_unlock(&mut port, &clock, 2, FIVE_SECONDS * 2),
            user.join(),
        )
    });
    let outputs = outcome?;
    assert_eq!(outputs.len(), 2);
    assert_eq!(outputs[0], outputs[1]);
    assert_eq!(typed.map_err(|_| ()), Ok(Ok(())));
    Ok(())
}
