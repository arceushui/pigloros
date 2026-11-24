//! R11 §8 against the signed test installation staged as root in the
//! isolated container (invariants 20 to 22 and 26, live side).

use std::future::Future;
use std::io::{Cursor, ErrorKind, Read, Write};
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use pos_reference::provider_admission::test_support::StagedInstallation;
use pos_reference::sandbox_provider_protocol::{
    RevocationAcknowledgement, SandboxRevocationSnapshot, SandboxTrustSnapshot,
};
use pos_reference::selector::installation::authority::{
    AdmittedSelectorProvider, AuthorityResolution,
};

use super::{
    AttemptCleanupState, AttemptStateSource, ExchangeObserver, ExchangeOutcome,
    RevocationUpdateResponder,
};
use crate::provider_runtime::tests::{
    bind_as_provider, cancellation_context, in_isolated_root, install_spi1, revocation_update,
    spi1, test_port, TestResult, RUNTIME_SEED,
};
use crate::provider_runtime::{AdmissionState, LiveAttempts};
use crate::{AdmittedRuntimeKey, KeyFileRuntimeSigner};

/// The exchange bound.
const BOUND: Duration = Duration::from_millis(100);

/// A view that is always `view`, counting how often it was taken.
struct Fixed {
    view: Option<Vec<AttemptCleanupState>>,
    taken: AtomicUsize,
}

impl Fixed {
    const fn new(view: Option<Vec<AttemptCleanupState>>) -> Self {
        Self {
            view,
            taken: AtomicUsize::new(0),
        }
    }
}

impl AttemptStateSource for &Fixed {
    fn attempt_states(&self) -> impl Future<Output = Option<Vec<AttemptCleanupState>>> + Send {
        self.taken.fetch_add(1, Ordering::SeqCst);
        std::future::ready(self.view.clone())
    }
}

/// A view that is never taken: a running attempt.
struct Running;

impl AttemptStateSource for Running {
    fn attempt_states(&self) -> impl Future<Output = Option<Vec<AttemptCleanupState>>> + Send {
        std::future::pending()
    }
}

/// An empty view taken once, then refused, as the live fence is.
struct Once(AtomicBool);

impl AttemptStateSource for Once {
    fn attempt_states(&self) -> impl Future<Output = Option<Vec<AttemptCleanupState>>> + Send {
        std::future::ready((!self.0.swap(true, Ordering::SeqCst)).then(Vec::new))
    }
}

/// An observer with nothing to advance.
struct Quiet;

impl ExchangeObserver for Quiet {
    fn fencing(&self) {}

    fn acknowledging(&self, _: &SandboxTrustSnapshot, _: &SandboxRevocationSnapshot) {}
}

const fn proved(id: u8, cleanup_proved: bool) -> AttemptCleanupState {
    AttemptCleanupState {
        attempt_id: [id; 16],
        cleanup_proved,
    }
}

fn responder<'a, A: AttemptStateSource, O: ExchangeObserver>(
    admitted: &'a AdmittedSelectorProvider,
    signer: &'a KeyFileRuntimeSigner,
    source: A,
    observer: O,
) -> RevocationUpdateResponder<'a, KeyFileRuntimeSigner, A, O> {
    RevocationUpdateResponder::new(
        signer,
        AdmittedRuntimeKey::new("runtime", admitted.provider().runtime_attestation_key()),
        AuthorityResolution::Live {
            retained_revocation_digest: admitted.bootstrap().revocation().snapshot_digest(),
        },
        source,
        observer,
    )
}

/// Write `frames` to `client`, then EOF when `eof`.
fn send(client: &mut UnixStream, frames: &[&[u8]], eof: bool) -> TestResult {
    for frame in frames {
        client.write_all(&u32::try_from(frame.len())?.to_be_bytes())?;
        client.write_all(frame)?;
    }
    if eof {
        client.shutdown(std::net::Shutdown::Write)?;
    }
    Ok(())
}

/// Send `frames`, then EOF when `eof`, and answer them; the outcome and
/// every byte the client read.
fn exchange<A: AttemptStateSource, O: ExchangeObserver>(
    responder: &RevocationUpdateResponder<'_, KeyFileRuntimeSigner, A, O>,
    frames: &[&[u8]],
    eof: bool,
) -> TestResult<(ExchangeOutcome, Vec<u8>)> {
    let (mut client, server) = UnixStream::pair()?;
    send(&mut client, frames, eof)?;
    server.set_read_timeout(Some(BOUND))?;
    let outcome = responder.respond(&mut &server, Instant::now() + BOUND);
    drop(server);
    client.set_read_timeout(Some(BOUND))?;
    let mut read = Vec::new();
    client.read_to_end(&mut read)?;
    Ok((outcome, read))
}

/// The one RCA1 frame of `response`.
fn unframe(response: &[u8]) -> TestResult<&[u8]> {
    let (prefix, record) = response.split_at_checked(4).ok_or("no RCA1")?;
    assert_eq!(
        usize::try_from(u32::from_be_bytes(prefix.try_into()?))?,
        record.len()
    );
    Ok(record)
}

/// Invariants 20 and 22 and R11 §8.4: an acknowledgement, its resend, and
/// zero bytes for every malformed exchange (with no fence taken) and for
/// every exchange after the acknowledgement that is not byte-identical.
fn acknowledges_once_and_resends(
    admitted: &AdmittedSelectorProvider,
    signer: &KeyFileRuntimeSigner,
) -> TestResult {
    let (update, next) = revocation_update(admitted, &[], 1)?;
    let context = cancellation_context(admitted, &update, vec![[5; 16]], vec![[5; 16]])?;
    let context_bytes = context.to_canonical_cbor()?;
    let source = Fixed::new(Some(vec![proved(5, true)]));
    let responder = responder(admitted, signer, &source, Quiet);
    let (other_update, _) = revocation_update(admitted, &[], 2)?;
    let mut corrupt = context_bytes.clone();
    *corrupt.last_mut().ok_or("empty RCC1")? ^= 1;
    for (frames, eof) in [
        (
            vec![context_bytes.as_slice(), other_update.as_slice()],
            true,
        ),
        (vec![corrupt.as_slice(), update.as_slice()], true),
        (vec![context_bytes.as_slice(), &b"\xff"[..]], true),
        (
            vec![context_bytes.as_slice(), update.as_slice(), &b"extra"[..]],
            true,
        ),
        (vec![context_bytes.as_slice(), update.as_slice()], false),
        (vec![context_bytes.as_slice()], true),
    ] {
        let (outcome, read) = exchange(&responder, &frames, eof)?;
        assert_eq!(outcome, ExchangeOutcome::Refused { fenced: false });
        assert!(read.is_empty());
    }
    assert_eq!(source.taken.load(Ordering::SeqCst), 0);
    let pair = [context_bytes.as_slice(), update.as_slice()];
    let (outcome, read) = exchange(&responder, &pair, true)?;
    assert_eq!(outcome, ExchangeOutcome::Acknowledged);
    let acknowledgement = RevocationAcknowledgement::authenticate_for_context(
        unframe(&read)?,
        "runtime",
        admitted.provider().runtime_attestation_key(),
        &context,
        [70; 16],
        next,
    )?;
    assert_eq!(acknowledgement.cancelled_attempt_ids(), [[5; 16]]);
    // A byte-identical exchange gets the same bytes, without a fence.
    let (outcome, resent) = exchange(&responder, &pair, true)?;
    assert_eq!(outcome, ExchangeOutcome::Resent);
    assert_eq!(resent, read);
    // Another valid exchange gets zero bytes: nothing is signed again.
    let other = cancellation_context(admitted, &other_update, Vec::new(), Vec::new())?;
    let other_bytes = other.to_canonical_cbor()?;
    let (outcome, read) = exchange(
        &responder,
        &[other_bytes.as_slice(), other_update.as_slice()],
        true,
    )?;
    assert_eq!(outcome, ExchangeOutcome::Refused { fenced: false });
    assert!(read.is_empty());
    // A pair that differs in only one frame is no resend either.
    for frames in [
        [context_bytes.as_slice(), other_update.as_slice()],
        [other_bytes.as_slice(), update.as_slice()],
    ] {
        let (outcome, read) = exchange(&responder, &frames, true)?;
        assert_eq!(outcome, ExchangeOutcome::Refused { fenced: false });
        assert!(read.is_empty());
    }
    assert_eq!(source.taken.load(Ordering::SeqCst), 1);
    let (outcome, again) = exchange(&responder, &pair, true)?;
    assert_eq!(outcome, ExchangeOutcome::Resent);
    assert_eq!(again, resent);
    Ok(())
}

/// Invariant 21: an unproved, unlisted or running attempt, or a view that
/// cannot be taken, means no RCA1 once the fence was reached.
fn refuses_unclean_views(
    admitted: &AdmittedSelectorProvider,
    signer: &KeyFileRuntimeSigner,
) -> TestResult {
    let (update, _) = revocation_update(admitted, &[], 3)?;
    let context_bytes =
        cancellation_context(admitted, &update, vec![[5; 16]], Vec::new())?.to_canonical_cbor()?;
    let pair = [context_bytes.as_slice(), update.as_slice()];
    for view in [
        Some(vec![proved(5, false)]),
        Some(vec![proved(6, true)]),
        None,
    ] {
        let source = Fixed::new(view);
        let (outcome, read) = exchange(&responder(admitted, signer, &source, Quiet), &pair, true)?;
        assert_eq!(outcome, ExchangeOutcome::Refused { fenced: true });
        assert!(read.is_empty());
    }
    // A running attempt is cut at the deadline, not waited for.
    let started = Instant::now();
    let (outcome, read) = exchange(&responder(admitted, signer, Running, Quiet), &pair, true)?;
    assert!(started.elapsed() < BOUND * 10);
    assert_eq!(outcome, ExchangeOutcome::Refused { fenced: true });
    assert!(read.is_empty());
    Ok(())
}

/// An RCA1 that cannot be written is not retained, and the fence yields no
/// second view: the retry gets zero bytes, and recovery follows.
fn an_unwritten_acknowledgement_is_lost(
    admitted: &AdmittedSelectorProvider,
    signer: &KeyFileRuntimeSigner,
) -> TestResult {
    let (update, _) = revocation_update(admitted, &[], 4)?;
    let context_bytes =
        cancellation_context(admitted, &update, Vec::new(), Vec::new())?.to_canonical_cbor()?;
    let pair = [context_bytes.as_slice(), update.as_slice()];
    let responder = responder(admitted, signer, Once(AtomicBool::new(false)), Quiet);
    // The client is gone before the answer: the write fails.
    let (mut client, server) = UnixStream::pair()?;
    send(&mut client, &pair, true)?;
    drop(client);
    assert_eq!(
        responder.respond(&mut &server, Instant::now() + BOUND),
        ExchangeOutcome::Refused { fenced: true }
    );
    let (outcome, read) = exchange(&responder, &pair, true)?;
    assert_eq!(outcome, ExchangeOutcome::Refused { fenced: true });
    assert!(read.is_empty());
    Ok(())
}

/// A 2 MiB frame is within the 16 MiB frame bound (ADR-069 §4): the whole
/// exchange is read to the client's EOF before the frame fails to decode as
/// RCC1, and no fence is taken.
fn reads_a_frame_above_one_mebibyte(
    admitted: &AdmittedSelectorProvider,
    signer: &KeyFileRuntimeSigner,
) -> TestResult {
    let (update, _) = revocation_update(admitted, &[], 6)?;
    let mut bytes = Vec::new();
    for frame in [vec![0xff; 2 << 20], update] {
        bytes.extend(u32::try_from(frame.len())?.to_be_bytes());
        bytes.extend(frame);
    }
    let length = u64::try_from(bytes.len())?;
    let mut stream = Cursor::new(bytes);
    let source = Fixed::new(Some(Vec::new()));
    assert_eq!(
        responder(admitted, signer, &source, Quiet).respond(&mut stream, Instant::now() + BOUND),
        ExchangeOutcome::Refused { fenced: false }
    );
    assert_eq!(stream.position(), length);
    assert_eq!(source.taken.load(Ordering::SeqCst), 0);
    Ok(())
}

/// The steps an observer saw, and what the client had read by then.
struct Recording<'a> {
    events: &'a Mutex<Vec<&'static str>>,
    client: UnixStream,
}

impl ExchangeObserver for Recording<'_> {
    fn fencing(&self) {
        self.events
            .lock()
            .map(|mut events| events.push("fencing"))
            .ok();
    }

    fn acknowledging(&self, _: &SandboxTrustSnapshot, _: &SandboxRevocationSnapshot) {
        // Nothing is written yet.
        let mut byte = [0; 1];
        let unwritten = self.client.set_nonblocking(true).is_ok()
            && matches!(
                (&self.client).read(&mut byte),
                Err(error) if error.kind() == ErrorKind::WouldBlock
            );
        let event = if unwritten {
            "acknowledging"
        } else {
            "acknowledging after the write"
        };
        self.events.lock().map(|mut events| events.push(event)).ok();
    }
}

/// A view that records when it is taken.
struct Logged<'a>(&'a Mutex<Vec<&'static str>>);

impl AttemptStateSource for Logged<'_> {
    fn attempt_states(&self) -> impl Future<Output = Option<Vec<AttemptCleanupState>>> + Send {
        self.0.lock().map(|mut events| events.push("viewed")).ok();
        std::future::ready(Some(Vec::new()))
    }
}

/// The observer learns of the fence before the view is taken, and of the
/// acknowledgement before its bytes are written.
fn observes_each_step_before_it_happens(
    admitted: &AdmittedSelectorProvider,
    signer: &KeyFileRuntimeSigner,
) -> TestResult {
    let (update, _) = revocation_update(admitted, &[], 5)?;
    let context_bytes =
        cancellation_context(admitted, &update, Vec::new(), Vec::new())?.to_canonical_cbor()?;
    let events = Mutex::new(Vec::new());
    let (mut client, server) = UnixStream::pair()?;
    let observer = Recording {
        events: &events,
        client: client.try_clone()?,
    };
    let responder = responder(admitted, signer, Logged(&events), observer);
    send(
        &mut client,
        &[context_bytes.as_slice(), update.as_slice()],
        true,
    )?;
    assert_eq!(
        responder.respond(&mut &server, Instant::now() + BOUND),
        ExchangeOutcome::Acknowledged
    );
    assert_eq!(
        *events.lock().map_err(|_| "poisoned")?,
        ["fencing", "viewed", "acknowledging"]
    );
    Ok(())
}

/// Invariant 26, live side: the lifecycle's fence before and after the
/// runtime is `Open`.
fn the_live_view_is_the_fenced_lifecycle() -> TestResult {
    let runtime = tokio::runtime::Builder::new_current_thread().build()?;
    let starting = OnceLock::new();
    assert_eq!(
        runtime.block_on(LiveAttempts(&starting).attempt_states()),
        Some(Vec::new())
    );
    let (directory, port) = test_port(crate::StagingLimits {
        aggregate_bytes: 1 << 30,
    })?;
    let open = OnceLock::from(AdmissionState::Open(Box::new(port)));
    assert_eq!(
        runtime.block_on(LiveAttempts(&open).attempt_states()),
        Some(Vec::new())
    );
    // The fence is permanent: no second view.
    assert_eq!(runtime.block_on(LiveAttempts(&open).attempt_states()), None);
    drop(open);
    drop(directory);
    Ok(())
}

#[test]
fn the_responder_acknowledges_only_clean_fenced_updates() -> TestResult {
    if !in_isolated_root(
        "provider_runtime::revocation::tests::the_responder_acknowledges_only_clean_fenced_updates",
    )? {
        return Ok(());
    }
    let staged = StagedInstallation::stage()?;
    install_spi1(&spi1(22)?, &RUNTIME_SEED)?;
    let (admitted, _, signer) = bind_as_provider()??;
    acknowledges_once_and_resends(&admitted, &signer)?;
    refuses_unclean_views(&admitted, &signer)?;
    an_unwritten_acknowledgement_is_lost(&admitted, &signer)?;
    reads_a_frame_above_one_mebibyte(&admitted, &signer)?;
    observes_each_step_before_it_happens(&admitted, &signer)?;
    the_live_view_is_the_fenced_lifecycle()?;
    drop(staged);
    Ok(())
}
