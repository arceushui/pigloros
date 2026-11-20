//! The signed terminal response, authenticated by the shared full-response
//! verifier (R9 §6 rules 5, 6, 8 and 10; Redmine #443 journal 22723, 8b).

use pos_reference::sandbox_provider_protocol::{
    AttemptEvidence, CancelSource, SandboxAuditRecord, SandboxProviderResult,
    SandboxTerminalOutcome,
};

use super::{
    admission_of, cleanup, evidence, input, release_of, signed_grant, signer, signing_key, start,
    terminal, Released, SignedGrant, TestResult, ATTEMPT, CLEANED_AT, KEY_ID,
};
use crate::{
    AdmittedRuntimeKey, AttemptProgress, EndedAttempt, ExecuteError, KeyFileRuntimeSigner,
    ResponseFault, RetainedResponse, RuntimeSignerError, UnitState,
};

/// The negative-probe digest `IssuedGrant::fixture` admits (HCP1 ordinal 7).
const NEGATIVE_PROBE: [u8; 32] = [0x97; 32];

fn sign(ended: &EndedAttempt<String>) -> Result<RetainedResponse, ResponseFault> {
    let public = signing_key().verifying_key();
    ended.signed_response(&signer(), AdmittedRuntimeKey::new(KEY_ID, &public))
}

/// Authenticate `retained` with the verifier every selector and auditor
/// runs, and return its SPY1 and the event codes of its SAU1 chain.
fn verified(retained: &RetainedResponse) -> TestResult<(SandboxProviderResult, Vec<u8>)> {
    let records = retained.records();
    AttemptEvidence::fixture(
        records.requested().clone(),
        records.observed().clone(),
        records.termination().clone(),
    )
    .verify_response(
        &retained.response(),
        NEGATIVE_PROBE,
        &signing_key().verifying_key(),
    )?;
    let response = retained.response();
    let events = response
        .audit
        .iter()
        .map(|bytes| SandboxAuditRecord::from_canonical_cbor(bytes).map(|record| record.event_code))
        .collect::<Result<_, _>>()?;
    Ok((
        SandboxProviderResult::from_canonical_cbor(response.result)?,
        events,
    ))
}

#[test]
fn a_completed_response_carries_the_output_descriptor() -> TestResult {
    let grant = signed_grant()?;
    let (digest, bytes) = (grant.grant.grant_digest(), grant.bytes.clone());
    let retained = sign(
        &Released {
            grant: Some(grant),
            ..Released::default()
        }
        .ended()?,
    )?;
    assert_eq!(retained.agr1_digest(), digest);
    assert_eq!(retained.response().grant, bytes.as_slice());
    assert!(retained.response().release.is_some());
    let (result, events) = verified(&retained)?;
    assert_eq!(result.outcome, SandboxTerminalOutcome::Completed);
    assert_eq!(events, [11, 12]);
    assert_eq!(result.operational_events, events);
    assert_eq!(result.output.map(|output| output.byte_length), Some(70));
    Ok(())
}

#[test]
fn a_released_failure_ends_the_chain_with_its_code() -> TestResult {
    let retained = sign(
        &Released {
            grant: Some(signed_grant()?),
            output: Some(vec![0; 100]),
            ceiling: true,
            ..Released::default()
        }
        .ended()?,
    )?;
    let (result, events) = verified(&retained)?;
    assert_eq!(
        result.outcome,
        SandboxTerminalOutcome::UnavailableAfterAdmission
    );
    assert_eq!(events, [11, 12, 7]);
    assert!(result.output.is_none());
    Ok(())
}

#[test]
fn a_denied_release_is_event_13() -> TestResult {
    let grant = signed_grant()?;
    let run = Released::default();
    let progress = AttemptProgress::Failed {
        error: ExecuteError::ReleaseTimeout,
        unit: UnitState::Killed,
        started: Some(start()),
        evidence: Some(evidence(
            release_of(Some(&grant), None, false)?,
            super::quiet(),
            terminal(&run)?,
        )?),
    };
    let ended = EndedAttempt::for_test(
        ATTEMPT,
        admission_of(
            Some(&grant),
            pos_reference::sandbox_provider_protocol::SandboxExecutionMode::AirGapped,
            Some(input(true)),
        ),
        None,
        progress,
        (cleanup(true)?, Some(CLEANED_AT)),
    );
    let retained = sign(&ended)?;
    let (result, events) = verified(&retained)?;
    assert_eq!(events, [11, 13, 10]);
    assert_eq!(
        result.outcome,
        SandboxTerminalOutcome::UnavailableAfterAdmission
    );
    assert!(retained.response().release.is_none());
    Ok(())
}

/// Events 11 and 13 bind a status-2 KOE1, whose observation failed after
/// `ReadyV1` (owner decision 2026-11-19, Q3).
#[test]
fn a_failed_observation_is_bound_by_events_11_and_13() -> TestResult {
    let grant = signed_grant()?;
    let run = Released::default();
    let progress = AttemptProgress::Failed {
        error: ExecuteError::ReleaseTimeout,
        unit: UnitState::Killed,
        started: Some(start()),
        evidence: Some(evidence(
            crate::ReleaseOutcome::new(Some(super::READY1), None, None),
            super::quiet(),
            terminal(&run)?,
        )?),
    };
    let ended = EndedAttempt::for_test(
        ATTEMPT,
        admission_of(
            Some(&grant),
            pos_reference::sandbox_provider_protocol::SandboxExecutionMode::AirGapped,
            Some(input(true)),
        ),
        None,
        progress,
        (cleanup(true)?, Some(CLEANED_AT)),
    );
    let retained = sign(&ended)?;
    let koe1 = retained.records().observed();
    assert!(matches!(
        koe1.fields().status,
        pos_reference::sandbox_provider_protocol::KernelObservationStatus::ObservationFailed { .. }
    ));
    let (_, events) = verified(&retained)?;
    assert_eq!(events, [11, 13, 10]);
    for bytes in &retained.response().audit[..2] {
        let record = SandboxAuditRecord::from_canonical_cbor(bytes)?;
        assert_eq!(record.authority_digests.last(), Some(&koe1.digest()));
    }
    Ok(())
}

#[test]
fn a_withdrawn_attempt_is_one_cancelled_event() -> TestResult {
    let grant: SignedGrant = signed_grant()?;
    let ended = EndedAttempt::<String>::for_test(
        ATTEMPT,
        admission_of(
            Some(&grant),
            pos_reference::sandbox_provider_protocol::SandboxExecutionMode::Local,
            Some(input(true)),
        ),
        Some(CancelSource::Revocation),
        AttemptProgress::Withdrawn,
        (Ok(None), Some(CLEANED_AT)),
    );
    let (result, events) = verified(&sign(&ended)?)?;
    assert_eq!(events, [1]);
    assert_eq!(result.outcome, SandboxTerminalOutcome::Cancelled);
    Ok(())
}

/// Nothing is emitted for records that cannot be assembled, filler AGR1
/// bytes, another key ID, or a signature that does not verify.
#[test]
fn every_fault_emits_nothing() -> TestResult {
    let unrecorded = Released {
        grant: Some(signed_grant()?),
        cleaned_at: None,
        ..Released::default()
    }
    .ended()?;
    assert!(matches!(sign(&unrecorded), Err(ResponseFault::Evidence(_))));
    let filler = Released::default().ended()?;
    assert!(matches!(
        sign(&filler),
        Err(ResponseFault::Sign(RuntimeSignerError::Protocol(_)))
    ));
    let ended = Released {
        grant: Some(signed_grant()?),
        ..Released::default()
    }
    .ended()?;
    let public = signing_key().verifying_key();
    let other_id = KeyFileRuntimeSigner::from_signing_key(signing_key(), "other".to_owned());
    assert!(matches!(
        ended.signed_response(&other_id, AdmittedRuntimeKey::new(KEY_ID, &public)),
        Err(ResponseFault::Sign(RuntimeSignerError::KeyIdMismatch))
    ));
    let other_key = KeyFileRuntimeSigner::from_signing_key(
        ed25519_dalek::SigningKey::from_bytes(&[7; 32]),
        KEY_ID.to_owned(),
    );
    assert!(matches!(
        ended.signed_response(&other_key, AdmittedRuntimeKey::new(KEY_ID, &public)),
        Err(ResponseFault::Sign(RuntimeSignerError::Unverified))
    ));
    Ok(())
}
