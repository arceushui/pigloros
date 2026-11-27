//! The selector's provider client against the composed provider port (#1503):
//! status, and cancel and reconcile of an unknown attempt and of a retained
//! terminal attempt, with the tuple the client recomputes from the retained
//! frames (ADR-069 R15 §3.3, §3.5 and N8).
//!
//! Execute end to end needs a real attached root and stays with the #444 guest
//! lane.

use std::num::NonZeroU64;

use pos_reference::provider_transport::guest::{
    GuestControlError, GuestProviderClient, GuestRefusal,
};
use pos_reference::sandbox_provider_protocol::{
    AdmittedSandboxProvider, ReconciliationEvidence, ReconciliationEvidenceFields,
    SandboxAdmissionError, SandboxCancellationResult, SandboxProviderProtocolError,
    SandboxProviderReceipt, TerminalEvidenceCheck,
};

use super::*;
use crate::RetainedResponse;

/// The time one exchange with the composed port may take.
const LIMIT: Duration = Duration::from_secs(10);

/// A 32-byte value derived from `text`, never written out.
fn digest_of(text: &str) -> [u8; 32] {
    *blake3::hash(text.as_bytes()).as_bytes()
}

/// A 16-byte identity derived from `text`.
fn identity_of(text: &str) -> [u8; 16] {
    let digest = digest_of(text);
    std::array::from_fn(|position| digest[position])
}

/// The selector's client for the provider process that runs this test.
fn client() -> TestResult<GuestProviderClient> {
    let pid = NonZeroU64::new(u64::from(std::process::id())).ok_or("pid zero")?;
    Ok(GuestProviderClient::for_provider_process(
        std::path::Path::new(EXECUTE),
        pid,
    )?)
}

/// Status: an SDQ1 whose runtime-signed SDY1 binds the admitted policy.
fn status_is_proved(
    client: &GuestProviderClient,
    provider: &AdmittedSandboxProvider,
) -> TestResult {
    Ok(client.describe(
        provider,
        identity_of("status request"),
        identity_of("status nonce"),
        LIMIT,
    )?)
}

/// SCQ1 and SRQ1 for an attempt the provider never saw: SPE1 `15`.
fn an_unknown_attempt_is_refused(
    client: &GuestProviderClient,
    provider: &AdmittedSandboxProvider,
) -> TestResult {
    let attempt = identity_of("unknown attempt");
    let grant = digest_of("unknown grant");
    let (cancel, cancel_bytes) = provider.cancel_request(
        identity_of("unknown cancel"),
        identity_of("unknown cancel nonce"),
        attempt,
        grant,
    )?;
    let (reconcile, reconcile_bytes) = provider.reconcile_request(
        identity_of("unknown reconcile"),
        identity_of("unknown reconcile nonce"),
        attempt,
        grant,
    )?;
    let refused = Some(GuestControlError::Refused(GuestRefusal::UnknownAttempt));
    assert_eq!(
        client
            .cancel(provider, &cancel, &cancel_bytes, None, LIMIT)
            .err(),
        refused
    );
    assert_eq!(
        client
            .reconcile(provider, &reconcile, &reconcile_bytes, None, LIMIT)
            .err(),
        refused
    );
    Ok(())
}

/// The digests the selector would hold for `stored`, recomputed from its
/// retained SPY1 and SPR1 frames and not read from the provider's own
/// bookkeeping.
fn accepted_from(stored: &RetainedResponse) -> TestResult<ReconciliationEvidenceFields> {
    let frames = stored.response();
    let result = SandboxProviderResult::from_canonical_cbor(frames.result)?;
    let receipt = SandboxProviderReceipt::from_canonical_cbor(frames.receipt)?;
    Ok(ReconciliationEvidenceFields {
        attempt_id: result.attempt_id,
        agr1_digest: stored.agr1_digest(),
        terminal_spy1_digest: result.result_digest(),
        final_sau1_digest: receipt.sau1_digest,
    })
}

/// SCQ1 on the retained terminal attempt: `AlreadyTerminal`, bound to the
/// SPY1 the selector accepted.
fn a_terminal_attempt_is_already_cancelled(
    client: &GuestProviderClient,
    provider: &AdmittedSandboxProvider,
    accepted: &ReconciliationEvidenceFields,
) -> TestResult {
    let (request, bytes) = provider.cancel_request(
        identity_of("retained cancel"),
        identity_of("retained cancel nonce"),
        accepted.attempt_id,
        accepted.agr1_digest,
    )?;
    let verified = client.cancel(
        provider,
        &request,
        &bytes,
        Some(accepted.terminal_spy1_digest),
        LIMIT,
    )?;
    assert_eq!(
        verified.response().result,
        SandboxCancellationResult::AlreadyTerminal
    );
    assert_eq!(
        verified.response().terminal_spy1_digest,
        accepted.terminal_spy1_digest
    );
    assert_eq!(verified.check(), TerminalEvidenceCheck::Compared);
    Ok(())
}

/// SRQ1 on the retained terminal attempt: a tuple that is not the one
/// recomputed from the frames is refused, and the right one is compared. The
/// provider reconciled the attempt at the first request, so the second is its
/// replay under a new request ID.
fn a_wrong_tuple_is_refused_and_the_right_one_compared(
    client: &GuestProviderClient,
    provider: &AdmittedSandboxProvider,
    accepted: &ReconciliationEvidenceFields,
) -> TestResult {
    let (wrong_request, wrong_bytes) = provider.reconcile_request(
        identity_of("wrong tuple"),
        identity_of("wrong tuple nonce"),
        accepted.attempt_id,
        accepted.agr1_digest,
    )?;
    let wrong = ReconciliationEvidenceFields {
        final_sau1_digest: digest_of("another last SAU1"),
        ..*accepted
    };
    assert_eq!(
        client
            .reconcile(provider, &wrong_request, &wrong_bytes, Some(&wrong), LIMIT)
            .err(),
        Some(GuestControlError::Rejected(
            SandboxAdmissionError::Protocol(SandboxProviderProtocolError::InconsistentFields)
        ))
    );
    let (request, bytes) = provider.reconcile_request(
        identity_of("right tuple"),
        identity_of("right tuple nonce"),
        accepted.attempt_id,
        accepted.agr1_digest,
    )?;
    let verified = client.reconcile(provider, &request, &bytes, Some(accepted), LIMIT)?;
    assert_eq!(verified.check(), TerminalEvidenceCheck::Compared);
    assert_eq!(
        verified.response().reconciliation_evidence_digest,
        ReconciliationEvidence::new(accepted)?.digest()
    );
    Ok(())
}

/// What the client sees of a port that holds no attempt it knows.
fn answers_without_a_terminal_attempt(
    client: &GuestProviderClient,
    provider: &AdmittedSandboxProvider,
) -> TestResult {
    status_is_proved(client, provider)?;
    an_unknown_attempt_is_refused(client, provider)
}

/// What the client sees of a port that holds one retained terminal attempt.
fn answers_for_a_terminal_attempt(
    client: &GuestProviderClient,
    provider: &AdmittedSandboxProvider,
    accepted: &ReconciliationEvidenceFields,
) -> TestResult {
    a_terminal_attempt_is_already_cancelled(client, provider, accepted)?;
    a_wrong_tuple_is_refused_and_the_right_one_compared(client, provider, accepted)
}

/// Every check the selector's client makes against the composed port.
fn the_composed_port_answers_the_selector_client(
    provider: &AdmittedSandboxProvider,
    stored: &RetainedResponse,
) -> TestResult {
    let client = client()?;
    let accepted = accepted_from(stored)?;
    answers_without_a_terminal_attempt(&client, provider)?;
    answers_for_a_terminal_attempt(&client, provider, &accepted)
}

/// The composed runtime serves the selector's client: status, the typed
/// refusal of an unknown attempt, and one retained terminal attempt that the
/// client cancels as already terminal and reconciles against the tuple it
/// recomputed, refusing a wrong tuple (ADR-069 R15 §3.3 and N8).
#[test]
fn the_selector_client_checks_the_composed_port() -> TestResult {
    if !in_isolated_root(
        "provider_runtime::serving::tests::selector_client::the_selector_client_checks_the_composed_port",
    )? {
        return Ok(());
    }
    let staged = stage()?;
    let authority = bind_as_provider()??;
    let (admitted, _, _) = &authority;
    let key = *admitted.provider().runtime_attestation_key();
    let provider = admitted.provider().clone();
    let retained = Authority {
        apt1: admitted.bootstrap().policy().policy_digest(),
        epoch: admitted.bootstrap().policy().policy_epoch(),
    };
    let (fixture, port) = test_port(StagingLimits {
        aggregate_bytes: 512 * 1024 * 1024,
    })?;
    let stored = port
        .lifecycle
        .completed_for_test()
        .map_err(|error| error.to_string())?;
    let (reconciled, reconciling) = mpsc::channel();
    reconciled.send(Ok(port))?;
    let served = std::thread::spawn(move || {
        serve_with(
            move || Ok(authority),
            move |_| Ok(Scripted(reconciling)),
            None,
        )
    });
    let checked = await_bound()
        .and_then(|()| await_open(&key, retained))
        .and_then(|()| the_composed_port_answers_the_selector_client(&provider, &stored));
    let (replacement, woken) = replace_execute_leaf()?;
    assert_eq!(
        served.join().map_err(|_| "the runtime panicked")?,
        ProviderRuntimeError::UnsafeEndpoint
    );
    assert_unanswered(woken)?;
    drop(replacement);
    fs::remove_file(EXECUTE).ok();
    drop(fixture);
    drop(staged);
    checked
}
