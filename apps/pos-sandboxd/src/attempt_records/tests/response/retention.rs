//! The lifecycle retains each ended attempt's signed response until it is
//! reconciled, serves it to the daemon and re-issues it (Redmine #443
//! journal 22723, 8c).

use std::cell::OnceCell;
use std::fs::{self, File};
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::sync::Arc;

use pos_reference::provider_admission::execution::FailedInput;
use pos_reference::sandbox_provider_protocol::{
    PayloadDirection, PayloadStreamValidator, RequestAuthority, RuntimeSigned, SandboxPayloadChunk,
    SandboxProviderResult, SandboxReconcileRequest, SelfDigested,
};

use super::super::{
    signed_grant, signer, signing_key, Released, TestResult, AGR1, ATTEMPT, KEY_ID,
};
use super::{timed_out_transfer, verified};
use crate::{
    AdmittedRuntimeKey, AttemptLifecycle, AttemptLifecycleError, EvidenceFault,
    KeyFileRuntimeSigner, ResponseFault, RetainedResponse, RuntimeAttestationSigner,
    RuntimeSignerError, StagingLedger, StagingLimits, SystemdAttemptRegistry,
};

/// A lifecycle over a fresh registry tree, and its ledger.
fn lifecycle() -> TestResult<(tempfile::TempDir, AttemptLifecycle, StagingLedger)> {
    let directory = tempfile::tempdir()?;
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
    for child in ["registry", "attempts"] {
        fs::create_dir(directory.path().join(child))?;
        fs::set_permissions(
            directory.path().join(child),
            fs::Permissions::from_mode(0o700),
        )?;
    }
    let parent = File::open(directory.path())?;
    let registry =
        SystemdAttemptRegistry::from_runtime_directory(&parent, parent.metadata()?.uid())?;
    let ledger = StagingLedger::new(StagingLimits {
        aggregate_bytes: 1024,
    });
    let lifecycle = AttemptLifecycle::new(
        registry,
        ledger.clone(),
        &crate::ReconciledRestart::for_test(),
    );
    Ok((directory, lifecycle, ledger))
}

/// The SPX1 digest the test grants claim their attempts under.
const REQUEST: [u8; 32] = [0x5d; 32];

/// The frames of `retained` past AGR1, the SAU1 chain and SPR1: its output
/// SBC1 records, then SPY1.
fn after_receipt(retained: &RetainedResponse) -> Vec<Vec<u8>> {
    let skipped = 2 + retained.response().audit.len();
    retained
        .frames()
        .skip(skipped)
        .map(<[u8]>::to_vec)
        .collect()
}

/// A Completed attempt under the signed test grant.
fn completed() -> TestResult<crate::EndedAttempt<String>> {
    Released {
        grant: Some(signed_grant()?),
        ..Released::default()
    }
    .ended()
}

const fn reconcile(agr1_digest: [u8; 32]) -> SandboxReconcileRequest {
    SandboxReconcileRequest {
        request: RequestAuthority {
            request_id: [3; 16],
            apt1_digest: [1; 32],
            policy_epoch: 6,
            nonce: [3; 16],
        },
        attempt_id: ATTEMPT,
        agr1_digest,
        request_digest: [4; 32],
    }
}

#[test]
fn the_response_is_retained_served_reissued_and_released() -> TestResult {
    let (_directory, lifecycle, _ledger) = lifecycle()?;
    let grant = signed_grant()?;
    let digest = grant.grant.grant_digest();
    // An ended attempt whose response is not retained yet is pending.
    lifecycle.failed_granted(&FailedInput::fixture(ATTEMPT, digest))?;
    assert!(matches!(
        lifecycle.terminal_response(ATTEMPT, digest),
        Err(AttemptLifecycleError::ResponsePending)
    ));
    assert!(matches!(
        lifecycle.terminal_response(ATTEMPT, AGR1),
        Err(AttemptLifecycleError::GrantMismatch)
    ));
    assert!(matches!(
        lifecycle.terminal_response([1; 16], digest),
        Err(AttemptLifecycleError::UnknownAttempt)
    ));
    let ended = Released {
        grant: Some(grant),
        ..Released::default()
    }
    .ended()?;
    let public = signing_key().verifying_key();
    let admitted = AdmittedRuntimeKey::new(KEY_ID, &public);
    let retained = lifecycle.retain_response(ended, &signer(), admitted)?;
    verified(&retained)?;
    assert!(Arc::ptr_eq(
        &lifecycle.terminal_response(ATTEMPT, digest)?,
        &retained
    ));
    // It is signed once.
    assert!(Arc::ptr_eq(
        &lifecycle.retain_response(completed()?, &signer(), admitted)?,
        &retained
    ));
    // A transfer that completed re-issues nothing and keeps the response.
    let complete = pos_reference::sandbox_provider_protocol::TransferRecord {
        accepted_bytes: 70,
        complete: true,
        ..timed_out_transfer()
    };
    assert!(matches!(
        lifecycle.reissue_response(ATTEMPT, digest, Some(complete), &signer(), admitted),
        Err(AttemptLifecycleError::Response(ResponseFault::Evidence(
            EvidenceFault::NotReissuable
        )))
    ));
    assert!(Arc::ptr_eq(
        &lifecycle.terminal_response(ATTEMPT, digest)?,
        &retained
    ));
    let successor = lifecycle.reissue_response(
        ATTEMPT,
        digest,
        Some(timed_out_transfer()),
        &signer(),
        admitted,
    )?;
    verified(&successor)?;
    assert!(Arc::ptr_eq(
        &lifecycle.terminal_response(ATTEMPT, digest)?,
        &successor
    ));
    // Reconciling releases it.
    lifecycle.reconcile(&reconcile(digest))?;
    assert!(matches!(
        lifecycle.terminal_response(ATTEMPT, digest),
        Err(AttemptLifecycleError::UnknownAttempt)
    ));
    assert!(matches!(
        lifecycle.retain_response(completed()?, &signer(), admitted),
        Err(AttemptLifecycleError::UnknownAttempt)
    ));
    assert!(matches!(
        lifecycle.reissue_response(
            ATTEMPT,
            digest,
            Some(timed_out_transfer()),
            &signer(),
            admitted
        ),
        Err(AttemptLifecycleError::UnknownAttempt)
    ));
    Ok(())
}

/// A signer whose first signature waits for a concurrent re-issue of the
/// same response to store its successor first.
struct Racing<'a> {
    lifecycle: &'a AttemptLifecycle,
    agr1_digest: [u8; 32],
    admitted: AdmittedRuntimeKey<'a>,
    signer: KeyFileRuntimeSigner,
    winner: OnceCell<Result<Arc<RetainedResponse>, AttemptLifecycleError>>,
}

impl RuntimeAttestationSigner for Racing<'_> {
    fn runtime_attestation_key_id(&self) -> &str {
        self.signer.runtime_attestation_key_id()
    }

    fn sign<M: RuntimeSigned>(&self, record: &SelfDigested<M>) -> [u8; 64] {
        self.winner.get_or_init(|| {
            self.lifecycle.reissue_response(
                ATTEMPT,
                self.agr1_digest,
                Some(timed_out_transfer()),
                &self.signer,
                self.admitted,
            )
        });
        self.signer.sign(record)
    }
}

/// Of two concurrent re-issues, the first to store wins: the other keeps
/// and returns the winner's successor instead of its own.
#[test]
fn the_first_concurrent_reissue_to_store_wins() -> TestResult {
    let (_directory, lifecycle, _ledger) = lifecycle()?;
    let grant = signed_grant()?;
    let digest = grant.grant.grant_digest();
    lifecycle.failed_granted(&FailedInput::fixture(ATTEMPT, digest))?;
    let ended = Released {
        grant: Some(grant),
        ..Released::default()
    }
    .ended()?;
    let public = signing_key().verifying_key();
    let admitted = AdmittedRuntimeKey::new(KEY_ID, &public);
    lifecycle.retain_response(ended, &signer(), admitted)?;
    let racing = Racing {
        lifecycle: &lifecycle,
        agr1_digest: digest,
        admitted,
        signer: signer(),
        winner: OnceCell::new(),
    };
    let returned = lifecycle.reissue_response(
        ATTEMPT,
        digest,
        Some(timed_out_transfer()),
        &racing,
        admitted,
    )?;
    let winner = racing
        .winner
        .into_inner()
        .ok_or("no concurrent re-issue")??;
    verified(&winner)?;
    assert!(Arc::ptr_eq(&returned, &winner));
    assert!(Arc::ptr_eq(
        &lifecycle.terminal_response(ATTEMPT, digest)?,
        &winner
    ));
    Ok(())
}

/// A response that cannot be signed is a provider fault: the lifecycle is
/// quarantined and the response stays unavailable.
#[test]
fn an_unsignable_response_quarantines_the_lifecycle() -> TestResult {
    let (_directory, lifecycle, ledger) = lifecycle()?;
    let failed = FailedInput::fixture(ATTEMPT, AGR1);
    let ended = lifecycle.failed_granted(&failed)?;
    let public = signing_key().verifying_key();
    let admitted = AdmittedRuntimeKey::new(KEY_ID, &public);
    // The fixture's AGR1 bytes are filler that no verifier decodes.
    assert!(matches!(
        lifecycle.retain_response(ended, &signer(), admitted),
        Err(AttemptLifecycleError::Response(ResponseFault::Sign(
            RuntimeSignerError::Protocol(_)
        )))
    ));
    assert!(ledger.reserve_storage(0).is_err());
    for _ in 0..2 {
        assert!(matches!(
            lifecycle.terminal_response(ATTEMPT, AGR1),
            Err(AttemptLifecycleError::ResponseUnavailable)
        ));
    }
    assert!(matches!(
        lifecycle.retain_response(Released::default().ended()?, &signer(), admitted),
        Err(AttemptLifecycleError::ResponseUnavailable)
    ));
    Ok(())
}

/// A successor whose signature does not verify faults the response.
#[test]
fn an_unsignable_successor_quarantines_the_lifecycle() -> TestResult {
    let (_directory, lifecycle, ledger) = lifecycle()?;
    let grant = signed_grant()?;
    let digest = grant.grant.grant_digest();
    lifecycle.failed_granted(&FailedInput::fixture(ATTEMPT, digest))?;
    let ended = Released {
        grant: Some(grant),
        ..Released::default()
    }
    .ended()?;
    let public = signing_key().verifying_key();
    let admitted = AdmittedRuntimeKey::new(KEY_ID, &public);
    lifecycle.retain_response(ended, &signer(), admitted)?;
    let foreign = KeyFileRuntimeSigner::from_signing_key(
        ed25519_dalek::SigningKey::from_bytes(&[7; 32]),
        KEY_ID.to_owned(),
    );
    assert!(matches!(
        lifecycle.reissue_response(
            ATTEMPT,
            digest,
            Some(timed_out_transfer()),
            &foreign,
            admitted
        ),
        Err(AttemptLifecycleError::Response(ResponseFault::Sign(
            RuntimeSignerError::Unverified
        )))
    ));
    assert!(ledger.reserve_storage(0).is_err());
    assert!(matches!(
        lifecycle.terminal_response(ATTEMPT, digest),
        Err(AttemptLifecycleError::ResponseUnavailable)
    ));
    Ok(())
}

/// An `output-transfer` time the clock could not report is a provider fault
/// (R9 Amendment 1 change F): no successor is signed, the retained response
/// is replaced by the fault and the lifecycle is quarantined.
#[test]
fn an_unreadable_output_transfer_time_quarantines_the_lifecycle() -> TestResult {
    let (_directory, lifecycle, ledger) = lifecycle()?;
    let grant = signed_grant()?;
    let digest = grant.grant.grant_digest();
    lifecycle.failed_granted(&FailedInput::fixture(ATTEMPT, digest))?;
    let ended = Released {
        grant: Some(grant),
        ..Released::default()
    }
    .ended()?;
    let public = signing_key().verifying_key();
    let admitted = AdmittedRuntimeKey::new(KEY_ID, &public);
    lifecycle.retain_response(ended, &signer(), admitted)?;
    assert!(ledger.reserve_storage(0).is_ok());
    assert!(matches!(
        lifecycle.reissue_response(ATTEMPT, digest, None, &signer(), admitted),
        Err(AttemptLifecycleError::Response(ResponseFault::Evidence(
            EvidenceFault::Clock
        )))
    ));
    assert!(ledger.reserve_storage(0).is_err());
    assert!(matches!(
        lifecycle.terminal_response(ATTEMPT, digest),
        Err(AttemptLifecycleError::ResponseUnavailable)
    ));
    assert!(matches!(
        lifecycle.reissue_response(
            ATTEMPT,
            digest,
            Some(timed_out_transfer()),
            &signer(),
            admitted
        ),
        Err(AttemptLifecycleError::ResponseUnavailable)
    ));
    Ok(())
}

/// A response for another AGR1 is refused and leaves the slot pending;
/// reconciling a slot whose response never came clears it.
#[test]
fn a_foreign_grant_is_refused_and_a_pending_slot_reconciles() -> TestResult {
    let (_directory, lifecycle, ledger) = lifecycle()?;
    let digest = signed_grant()?.grant.grant_digest();
    lifecycle.failed_granted(&FailedInput::fixture(ATTEMPT, digest))?;
    let foreign = Released {
        grant: Some(signed_grant()?),
        ..Released::default()
    }
    .ended()?;
    let other = Released::default().ended()?;
    let public = signing_key().verifying_key();
    let admitted = AdmittedRuntimeKey::new(KEY_ID, &public);
    assert!(matches!(
        lifecycle.retain_response(other, &signer(), admitted),
        Err(AttemptLifecycleError::GrantMismatch)
    ));
    assert!(ledger.reserve_storage(0).is_ok());
    assert!(matches!(
        lifecycle.terminal_response(ATTEMPT, digest),
        Err(AttemptLifecycleError::ResponsePending)
    ));
    lifecycle.reconcile(&reconcile(digest))?;
    assert!(matches!(
        lifecycle.terminal_response(ATTEMPT, digest),
        Err(AttemptLifecycleError::UnknownAttempt)
    ));
    assert!(matches!(
        lifecycle.retain_response(foreign, &signer(), admitted),
        Err(AttemptLifecycleError::UnknownAttempt)
    ));
    Ok(())
}

/// A retained response whose classification quarantines closes admission:
/// a D5 contradiction, and a code-2 missing service result (R9 §4.6.4 and
/// §4.6.5).
#[test]
fn a_quarantining_classification_closes_admission() -> TestResult {
    for (terminal_cgroup, service) in [((26, 9999), Some(("success", 1, 0))), ((26, 5678), None)] {
        let (_directory, lifecycle, ledger) = lifecycle()?;
        let grant = signed_grant()?;
        let digest = grant.grant.grant_digest();
        lifecycle.failed_granted(&FailedInput::fixture(ATTEMPT, digest))?;
        let ended = Released {
            grant: Some(grant),
            terminal_cgroup,
            service,
            ..Released::default()
        }
        .ended()?;
        let public = signing_key().verifying_key();
        let retained = lifecycle.retain_response(
            ended,
            &signer(),
            AdmittedRuntimeKey::new(KEY_ID, &public),
        )?;
        verified(&retained)?;
        assert!(retained.records().classification().quarantined());
        assert!(ledger.reserve_storage(0).is_err());
    }
    Ok(())
}

/// The lifecycle quarantines on the post-release provider fault (owner
/// decision 2026-11-19, Q2), and the response stays unavailable.
#[test]
fn the_post_release_fault_quarantines_the_lifecycle() -> TestResult {
    let (_directory, lifecycle, ledger) = lifecycle()?;
    lifecycle.failed_granted(&FailedInput::fixture(ATTEMPT, AGR1))?;
    let ended = super::super::failed_after_release()?;
    let public = signing_key().verifying_key();
    assert!(matches!(
        lifecycle.retain_response(ended, &signer(), AdmittedRuntimeKey::new(KEY_ID, &public)),
        Err(AttemptLifecycleError::Response(ResponseFault::Evidence(
            EvidenceFault::Record(_)
        )))
    ));
    assert!(ledger.reserve_storage(0).is_err());
    assert!(matches!(
        lifecycle.terminal_response(ATTEMPT, AGR1),
        Err(AttemptLifecycleError::ResponseUnavailable)
    ));
    Ok(())
}

/// The retained response is the stored full response: AGR1, the SAU1 chain,
/// SPR1, the output SBC1 records parented by SPY1, and SPY1. An exact
/// repeat that joined while it was pending receives the very same response;
/// one with other bytes conflicts, and once reconciled the attempt is
/// unknown (ADR-069 §4).
#[tokio::test]
async fn an_exact_repeat_replays_the_stored_full_response() -> TestResult {
    let (_directory, lifecycle, ledger) = lifecycle()?;
    let grant = signed_grant()?;
    let digest = grant.grant.grant_digest();
    lifecycle.failed_granted(&FailedInput::fixture(ATTEMPT, digest))?;
    assert!(matches!(
        lifecycle.join(ATTEMPT, [0x77; 32]).await,
        Err(AttemptLifecycleError::RequestConflict)
    ));
    let public = signing_key().verifying_key();
    let admitted = AdmittedRuntimeKey::new(KEY_ID, &public);
    let ended = completed()?;
    let joined = lifecycle.join(ATTEMPT, REQUEST);
    let retained = async {
        tokio::task::yield_now().await;
        lifecycle.retain_response(ended, &signer(), admitted)
    };
    let (joined, retained) = tokio::join!(joined, retained);
    let retained = retained?;
    assert!(joined?.is_some_and(|joined| Arc::ptr_eq(&joined, &retained)));
    let (result, _) = verified(&retained)?;
    let response = retained.response();
    let frames = retained.frames().map(<[u8]>::to_vec).collect::<Vec<_>>();
    assert_eq!(frames[0], response.grant);
    assert_eq!(frames[1..=response.audit.len()], response.audit[..]);
    assert_eq!(frames[response.audit.len() + 1], response.receipt);
    let [chunk, spy1] = &after_receipt(&retained)[..] else {
        return Err("one output record, then SPY1".into());
    };
    assert_eq!(spy1, response.result);
    let output = result.output.clone().ok_or("a Completed SPY1 has output")?;
    let mut validator = PayloadStreamValidator::new(
        result.result_digest(),
        result.request_id,
        ATTEMPT,
        PayloadDirection::Output,
        output,
    )?;
    validator.accept(&SandboxPayloadChunk::from_canonical_cbor(chunk)?)?;
    validator.finish()?;
    // The output stays charged while it is retained.
    let before = ledger.usage().reserved_bytes;
    // A later exact repeat replays the same response.
    assert!(lifecycle
        .join(ATTEMPT, REQUEST)
        .await?
        .is_some_and(|again| Arc::ptr_eq(&again, &retained)));
    // A re-issued successor is not Completed and carries no output.
    let successor = lifecycle.reissue_response(
        ATTEMPT,
        digest,
        Some(timed_out_transfer()),
        &signer(),
        admitted,
    )?;
    let [spy1] = &after_receipt(&successor)[..] else {
        return Err("a successor has no output records".into());
    };
    assert!(SandboxProviderResult::from_canonical_cbor(spy1)?
        .output
        .is_none());
    assert!(lifecycle
        .join(ATTEMPT, REQUEST)
        .await?
        .is_some_and(|again| Arc::ptr_eq(&again, &successor)));
    drop(retained);
    assert_eq!(ledger.usage().reserved_bytes, before);
    lifecycle.reconcile(&reconcile(digest))?;
    assert!(matches!(
        lifecycle.join(ATTEMPT, REQUEST).await,
        Err(AttemptLifecycleError::UnknownAttempt)
    ));
    Ok(())
}

/// A repeat of an attempt whose response faulted learns that none will be
/// signed.
#[tokio::test]
async fn a_repeat_of_a_faulted_response_is_refused() -> TestResult {
    let (_directory, lifecycle, _ledger) = lifecycle()?;
    let ended = lifecycle.failed_granted(&FailedInput::fixture(ATTEMPT, AGR1))?;
    let public = signing_key().verifying_key();
    let admitted = AdmittedRuntimeKey::new(KEY_ID, &public);
    let joined = lifecycle.join(ATTEMPT, REQUEST);
    let refused = async {
        tokio::task::yield_now().await;
        lifecycle.retain_response(ended, &signer(), admitted)
    };
    let (joined, refused) = tokio::join!(joined, refused);
    assert!(refused.is_err());
    assert!(matches!(
        joined,
        Err(AttemptLifecycleError::ResponseUnavailable)
    ));
    Ok(())
}

/// The retained output stays charged while it is retained, also while a
/// joined repeat holds it, and is released at reconcile (ADR-069 R11
/// Amendment 1, item P12).
#[tokio::test]
async fn retained_output_stays_charged_until_reconcile() -> TestResult {
    let (_directory, lifecycle, _ledger) = lifecycle()?;
    let grant = signed_grant()?;
    let digest = grant.grant.grant_digest();
    lifecycle.failed_granted(&FailedInput::fixture(ATTEMPT, digest))?;
    let output = crate::StagingLedger::new(StagingLimits {
        aggregate_bytes: 1024,
    });
    let ended = Released {
        grant: Some(grant),
        output_ledger: Some(output.clone()),
        ..Released::default()
    }
    .ended()?;
    let public = signing_key().verifying_key();
    let retained =
        lifecycle.retain_response(ended, &signer(), AdmittedRuntimeKey::new(KEY_ID, &public))?;
    assert_eq!(output.usage().reserved_bytes, 70);
    drop(retained);
    let joined = lifecycle
        .join(ATTEMPT, REQUEST)
        .await?
        .ok_or("no response")?;
    assert_eq!(output.usage().reserved_bytes, 70);
    drop(joined);
    assert_eq!(output.usage().reserved_bytes, 70);
    lifecycle.reconcile(&reconcile(digest))?;
    assert_eq!(output.usage().reserved_bytes, 0);
    Ok(())
}

/// A re-issued successor retains no output, so the charge ends with the
/// first response; a connection still writing its frames keeps them, and
/// their charge, until it is done.
#[test]
fn a_reissue_releases_the_output_once_its_frames_are_written() -> TestResult {
    let (_directory, lifecycle, _ledger) = lifecycle()?;
    let grant = signed_grant()?;
    let digest = grant.grant.grant_digest();
    lifecycle.failed_granted(&FailedInput::fixture(ATTEMPT, digest))?;
    let output = crate::StagingLedger::new(StagingLimits {
        aggregate_bytes: 1024,
    });
    let ended = Released {
        grant: Some(grant),
        output_ledger: Some(output.clone()),
        ..Released::default()
    }
    .ended()?;
    let public = signing_key().verifying_key();
    let admitted = AdmittedRuntimeKey::new(KEY_ID, &public);
    let serving = lifecycle.retain_response(ended, &signer(), admitted)?;
    let frames = serving.frames().map(<[u8]>::to_vec).collect::<Vec<_>>();
    lifecycle.reissue_response(
        ATTEMPT,
        digest,
        Some(timed_out_transfer()),
        &signer(),
        admitted,
    )?;
    // The connection writing the first response still holds its frames.
    assert_eq!(output.usage().reserved_bytes, 70);
    assert_eq!(
        serving.frames().map(<[u8]>::to_vec).collect::<Vec<_>>(),
        frames
    );
    drop(serving);
    assert_eq!(output.usage().reserved_bytes, 0);
    Ok(())
}

/// A response already retained is returned without signing anything again.
#[test]
fn a_retained_response_is_never_signed_again() -> TestResult {
    let (_directory, lifecycle, _ledger) = lifecycle()?;
    let digest = signed_grant()?.grant.grant_digest();
    lifecycle.failed_granted(&FailedInput::fixture(ATTEMPT, digest))?;
    let public = signing_key().verifying_key();
    let admitted = AdmittedRuntimeKey::new(KEY_ID, &public);
    let retained = lifecycle.retain_response(completed()?, &signer(), admitted)?;
    // A signer that could not sign is never asked.
    let foreign = KeyFileRuntimeSigner::from_signing_key(
        ed25519_dalek::SigningKey::from_bytes(&[7; 32]),
        KEY_ID.to_owned(),
    );
    assert!(Arc::ptr_eq(
        &lifecycle.retain_response(completed()?, &foreign, admitted)?,
        &retained
    ));
    Ok(())
}
