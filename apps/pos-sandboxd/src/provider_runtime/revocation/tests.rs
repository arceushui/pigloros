//! R11 §8 against the signed test installation staged as root in the
//! isolated container (invariants 20 to 22 and 26, live side).

use std::future::Future;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use pos_reference::provider_admission::test_support::StagedInstallation;
use pos_reference::sandbox_provider_protocol::RevocationAcknowledgement;
use pos_reference::selector::installation::authority::{
    AdmittedSelectorProvider, AuthorityResolution,
};

use super::{AttemptCleanupState, AttemptStateSource, ExchangeOutcome, RevocationUpdateResponder};
use crate::provider_runtime::tests::{
    bind_as_provider, cancellation_context, in_isolated_root, install_spi1, revocation_update,
    spi1, test_lifecycle, TestResult, RUNTIME_SEED,
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

const fn proved(id: u8, cleanup_proved: bool) -> AttemptCleanupState {
    AttemptCleanupState {
        attempt_id: [id; 16],
        cleanup_proved,
    }
}

fn responder<'a, A: AttemptStateSource>(
    admitted: &'a AdmittedSelectorProvider,
    signer: &'a KeyFileRuntimeSigner,
    source: A,
) -> RevocationUpdateResponder<'a, KeyFileRuntimeSigner, A> {
    RevocationUpdateResponder::new(
        signer,
        AdmittedRuntimeKey::new("runtime", admitted.provider().runtime_attestation_key()),
        AuthorityResolution::Live {
            retained_revocation_digest: admitted.bootstrap().revocation().snapshot_digest(),
        },
        source,
    )
}

/// Send `frames`, then EOF when `eof`, and answer them; the outcome and
/// every byte the client read.
fn exchange<A: AttemptStateSource>(
    responder: &RevocationUpdateResponder<'_, KeyFileRuntimeSigner, A>,
    frames: &[&[u8]],
    eof: bool,
) -> TestResult<(ExchangeOutcome, Vec<u8>)> {
    let (mut client, server) = UnixStream::pair()?;
    for frame in frames {
        client.write_all(&u32::try_from(frame.len())?.to_be_bytes())?;
        client.write_all(frame)?;
    }
    if eof {
        client.shutdown(std::net::Shutdown::Write)?;
    }
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

/// Invariants 20 and 22: an acknowledgement, its resend, and zero bytes for
/// every malformed exchange, with no fence taken.
fn acknowledges_once_and_resends(
    admitted: &AdmittedSelectorProvider,
    signer: &KeyFileRuntimeSigner,
) -> TestResult {
    let (update, next) = revocation_update(admitted, &[], 1)?;
    let context = cancellation_context(admitted, &update, vec![[5; 16]], vec![[5; 16]])?;
    let context_bytes = context.to_canonical_cbor()?;
    let source = Fixed::new(Some(vec![proved(5, true)]));
    let responder = responder(admitted, signer, &source);
    // Malformed exchanges write nothing and take no fence.
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
        assert!(matches!(
            outcome,
            ExchangeOutcome::Refused { fenced: false }
        ));
        assert!(read.is_empty());
    }
    assert_eq!(source.taken.load(Ordering::SeqCst), 0);
    let (outcome, read) = exchange(
        &responder,
        &[context_bytes.as_slice(), update.as_slice()],
        true,
    )?;
    assert!(matches!(outcome, ExchangeOutcome::Acknowledged { .. }));
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
    let (outcome, resent) = exchange(
        &responder,
        &[context_bytes.as_slice(), update.as_slice()],
        true,
    )?;
    assert!(matches!(outcome, ExchangeOutcome::Resent));
    assert_eq!(resent, read);
    assert_eq!(source.taken.load(Ordering::SeqCst), 1);
    // Once signing is closed only the resend remains.
    responder.close_signing();
    let other = cancellation_context(admitted, &other_update, Vec::new(), Vec::new())?;
    let (outcome, read) = exchange(
        &responder,
        &[
            other.to_canonical_cbor()?.as_slice(),
            other_update.as_slice(),
        ],
        true,
    )?;
    assert!(matches!(outcome, ExchangeOutcome::Refused { fenced: false }) && read.is_empty());
    let (outcome, again) = exchange(
        &responder,
        &[context_bytes.as_slice(), update.as_slice()],
        true,
    )?;
    assert!(matches!(outcome, ExchangeOutcome::Resent));
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
    for view in [
        Some(vec![proved(5, false)]),
        Some(vec![proved(6, true)]),
        None,
    ] {
        let source = Fixed::new(view);
        let (outcome, read) = exchange(
            &responder(admitted, signer, &source),
            &[context_bytes.as_slice(), update.as_slice()],
            true,
        )?;
        assert!(matches!(outcome, ExchangeOutcome::Refused { fenced: true }));
        assert!(read.is_empty());
    }
    let started = Instant::now();
    let (outcome, read) = exchange(
        &responder(admitted, signer, Running),
        &[context_bytes.as_slice(), update.as_slice()],
        true,
    )?;
    assert!(matches!(outcome, ExchangeOutcome::Refused { fenced: true }) && read.is_empty());
    assert!(started.elapsed() < BOUND * 10);
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
    let (directory, lifecycle) = test_lifecycle()?;
    let open = OnceLock::from(AdmissionState::Open { lifecycle });
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
    the_live_view_is_the_fenced_lifecycle()?;
    drop(staged);
    Ok(())
}
