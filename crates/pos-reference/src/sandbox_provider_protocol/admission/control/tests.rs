use ciborium::value::Value;

use super::*;
use crate::selector_transport_test_fixture::{
    authenticated_transport_fixture, derived_nonce, TransportAdmissionFixture,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

const REQUEST_ID: [u8; 16] = [5; 16];
const ATTEMPT: [u8; 16] = [7; 16];
const AGR1: [u8; 32] = [8; 32];
const SPY1: [u8; 32] = [9; 32];
const SAU1: [u8; 32] = [10; 32];

fn nonce() -> [u8; 16] {
    derived_nonce("admission control tests")
}

fn accepted() -> ReconciliationEvidenceFields {
    ReconciliationEvidenceFields {
        attempt_id: ATTEMPT,
        agr1_digest: AGR1,
        terminal_spy1_digest: SPY1,
        final_sau1_digest: SAU1,
    }
}

fn uint(value: u64) -> Value {
    Value::Integer(value.into())
}

fn key_id(fixture: &TransportAdmissionFixture) -> Value {
    Value::Text(
        fixture
            .provider
            .manifest()
            .runtime_attestation_key_id
            .clone(),
    )
}

fn sry1(
    fixture: &TransportAdmissionFixture,
    request_id: [u8; 16],
    evidence_digest: [u8; 32],
    key: Value,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    fixture.sign_runtime_record(
        "SRY1",
        Value::Array(vec![
            Value::Text("SRY1".to_owned()),
            uint(1),
            Value::Bytes(request_id.to_vec()),
            Value::Bytes(ATTEMPT.to_vec()),
            Value::Bool(true),
            Value::Bytes(evidence_digest.to_vec()),
            key,
        ]),
    )
}

fn scy1(
    fixture: &TransportAdmissionFixture,
    request_id: [u8; 16],
    result: u64,
    key: Value,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    fixture.sign_runtime_record(
        "SCY1",
        Value::Array(vec![
            Value::Text("SCY1".to_owned()),
            uint(1),
            Value::Bytes(request_id.to_vec()),
            Value::Bytes(ATTEMPT.to_vec()),
            uint(result),
            Value::Bytes(SPY1.to_vec()),
            key,
        ]),
    )
}

fn recomputed_digest() -> Result<[u8; 32], SandboxProviderProtocolError> {
    ReconciliationEvidence::new(&accepted()).map(|evidence| evidence.digest())
}

fn flip_last_byte(mut bytes: Vec<u8>) -> Vec<u8> {
    if let Some(last) = bytes.last_mut() {
        *last ^= 1;
    }
    bytes
}

#[test]
fn requests_bind_the_active_policy_and_round_trip_their_canonical_bytes() -> TestResult {
    let fixture = authenticated_transport_fixture()?;
    let provider = &fixture.provider;
    let (cancel, cancel_bytes) = provider.cancel_request(REQUEST_ID, nonce(), ATTEMPT, AGR1)?;
    let (reconcile, reconcile_bytes) =
        provider.reconcile_request(REQUEST_ID, nonce(), ATTEMPT, AGR1)?;
    assert_eq!(
        SandboxCancelRequest::from_canonical_cbor(&cancel_bytes)?,
        cancel
    );
    assert_eq!(
        SandboxReconcileRequest::from_canonical_cbor(&reconcile_bytes)?,
        reconcile
    );
    assert_ne!(cancel_bytes, reconcile_bytes);
    assert_eq!(cancel.request, reconcile.request);
    assert_eq!(cancel.request.request_id, REQUEST_ID);
    assert_eq!(cancel.request.nonce, nonce());
    assert_eq!(cancel.request.apt1_digest, provider.policy.policy_digest());
    assert_eq!(cancel.request.policy_epoch, provider.policy.policy_epoch());
    assert_eq!((cancel.attempt_id, cancel.agr1_digest), (ATTEMPT, AGR1));
    Ok(())
}

#[test]
fn requests_refuse_each_zero_identity() -> TestResult {
    let fixture = authenticated_transport_fixture()?;
    let provider = &fixture.provider;
    let zero_inputs = [
        ([0; 16], nonce(), ATTEMPT, AGR1),
        (REQUEST_ID, nonce().map(|byte| byte ^ byte), ATTEMPT, AGR1),
        (REQUEST_ID, nonce(), [0; 16], AGR1),
        (REQUEST_ID, nonce(), ATTEMPT, [0; 32]),
    ];
    for (request_id, nonce, attempt, agr1) in zero_inputs {
        assert_eq!(
            provider
                .cancel_request(request_id, nonce, attempt, agr1)
                .map(|(_, bytes)| bytes),
            Err(SandboxProviderProtocolError::FieldOutOfBounds)
        );
        assert_eq!(
            provider
                .reconcile_request(request_id, nonce, attempt, agr1)
                .map(|(_, bytes)| bytes),
            Err(SandboxProviderProtocolError::FieldOutOfBounds)
        );
    }
    Ok(())
}

#[test]
fn cancel_authentication_accepts_only_the_signed_answer_to_the_request() -> TestResult {
    let fixture = authenticated_transport_fixture()?;
    let provider = &fixture.provider;
    let (request, _) = provider.cancel_request(REQUEST_ID, nonce(), ATTEMPT, AGR1)?;
    let signed = scy1(&fixture, REQUEST_ID, 1, key_id(&fixture))?;
    for accepted_spy1 in [None, Some(SPY1)] {
        let verified = provider.authenticate_cancel_response(&signed, &request, accepted_spy1)?;
        assert_eq!(verified.response().terminal_spy1_digest, SPY1);
        assert_eq!(verified.response().request_id, REQUEST_ID);
        assert_eq!(
            verified.check(),
            accepted_spy1.map_or(TerminalEvidenceCheck::Unverified, |_| {
                TerminalEvidenceCheck::Compared
            })
        );
    }
    assert_eq!(
        provider.authenticate_cancel_response(&signed, &request, Some([11; 32])),
        Err(contradiction())
    );
    assert_eq!(
        provider.authenticate_cancel_response(&flip_last_byte(signed), &request, None),
        Err(SandboxAdmissionError::Protocol(
            SandboxProviderProtocolError::SignatureInvalid
        ))
    );
    assert!(provider
        .authenticate_cancel_response(b"not cbor", &request, None)
        .is_err());
    let foreign_request = scy1(&fixture, [99; 16], 1, key_id(&fixture))?;
    assert_eq!(
        provider.authenticate_cancel_response(
            &flip_last_byte(foreign_request.clone()),
            &request,
            None
        ),
        Err(SandboxAdmissionError::Protocol(
            SandboxProviderProtocolError::SignatureInvalid
        ))
    );
    assert_eq!(
        provider.authenticate_cancel_response(&foreign_request, &request, None),
        Err(contradiction())
    );
    let foreign_key = scy1(&fixture, REQUEST_ID, 1, Value::Text("foreign".to_owned()))?;
    assert_eq!(
        provider.authenticate_cancel_response(&foreign_key, &request, None),
        Err(SandboxAdmissionError::ConformanceMismatch)
    );
    Ok(())
}

#[test]
fn reconcile_recomputes_the_tuple_when_the_selector_accepted_the_terminal() -> TestResult {
    let fixture = authenticated_transport_fixture()?;
    let provider = &fixture.provider;
    let (request, _) = provider.reconcile_request(REQUEST_ID, nonce(), ATTEMPT, AGR1)?;
    let signed = sry1(&fixture, REQUEST_ID, recomputed_digest()?, key_id(&fixture))?;
    let verified =
        provider.authenticate_reconcile_response(&signed, &request, Some(&accepted()))?;
    assert_eq!(verified.check(), TerminalEvidenceCheck::Compared);
    assert_eq!(
        verified.response().reconciliation_evidence_digest,
        recomputed_digest()?
    );
    Ok(())
}

#[test]
fn reconcile_refuses_a_validly_signed_digest_that_is_not_the_recomputed_one() -> TestResult {
    let fixture = authenticated_transport_fixture()?;
    let provider = &fixture.provider;
    let (request, _) = provider.reconcile_request(REQUEST_ID, nonce(), ATTEMPT, AGR1)?;
    let mut changed = recomputed_digest()?;
    changed[31] ^= 1;
    let signed = sry1(&fixture, REQUEST_ID, changed, key_id(&fixture))?;
    assert_eq!(
        provider.authenticate_reconcile_response(&signed, &request, Some(&accepted())),
        Err(contradiction())
    );
    // Without an accepted terminal response only rule 1 applies (rule 3).
    let verified = provider.authenticate_reconcile_response(&signed, &request, None)?;
    assert_eq!(verified.check(), TerminalEvidenceCheck::Unverified);
    assert_eq!(verified.response().reconciliation_evidence_digest, changed);
    Ok(())
}

#[test]
fn reconcile_refuses_accepted_digests_that_do_not_name_the_requested_attempt() -> TestResult {
    let fixture = authenticated_transport_fixture()?;
    let provider = &fixture.provider;
    let (request, _) = provider.reconcile_request(REQUEST_ID, nonce(), ATTEMPT, AGR1)?;
    let signed = sry1(&fixture, REQUEST_ID, recomputed_digest()?, key_id(&fixture))?;
    let other_attempt = ReconciliationEvidenceFields {
        attempt_id: [70; 16],
        ..accepted()
    };
    let other_grant = ReconciliationEvidenceFields {
        agr1_digest: [80; 32],
        ..accepted()
    };
    let zero_digest = ReconciliationEvidenceFields {
        final_sau1_digest: [0; 32],
        ..accepted()
    };
    for fields in [other_attempt, other_grant, zero_digest] {
        assert_eq!(
            provider.authenticate_reconcile_response(&signed, &request, Some(&fields)),
            Err(contradiction())
        );
    }
    Ok(())
}

#[test]
fn reconcile_checks_the_signature_before_the_request_identities() -> TestResult {
    let fixture = authenticated_transport_fixture()?;
    let provider = &fixture.provider;
    let (request, _) = provider.reconcile_request(REQUEST_ID, nonce(), ATTEMPT, AGR1)?;
    let digest = recomputed_digest()?;
    let signed = sry1(&fixture, REQUEST_ID, digest, key_id(&fixture))?;
    assert_eq!(
        provider.authenticate_reconcile_response(&flip_last_byte(signed), &request, None),
        Err(SandboxAdmissionError::Protocol(
            SandboxProviderProtocolError::SignatureInvalid
        ))
    );
    assert!(provider
        .authenticate_reconcile_response(b"not cbor", &request, None)
        .is_err());
    let foreign_request = sry1(&fixture, [99; 16], digest, key_id(&fixture))?;
    assert_eq!(
        provider.authenticate_reconcile_response(&foreign_request, &request, None),
        Err(contradiction())
    );
    // A forged signature on a foreign request is a signature failure first.
    assert_eq!(
        provider.authenticate_reconcile_response(&flip_last_byte(foreign_request), &request, None),
        Err(SandboxAdmissionError::Protocol(
            SandboxProviderProtocolError::SignatureInvalid
        ))
    );
    let foreign_key = sry1(
        &fixture,
        REQUEST_ID,
        digest,
        Value::Text("foreign".to_owned()),
    )?;
    assert_eq!(
        provider.authenticate_reconcile_response(&foreign_key, &request, None),
        Err(SandboxAdmissionError::ConformanceMismatch)
    );
    Ok(())
}

#[test]
fn a_foreign_key_id_is_refused_before_the_signature_is_verified() -> TestResult {
    let fixture = authenticated_transport_fixture()?;
    let provider = &fixture.provider;
    let foreign = || Value::Text("foreign".to_owned());
    let (cancel, _) = provider.cancel_request(REQUEST_ID, nonce(), ATTEMPT, AGR1)?;
    let cancelled = flip_last_byte(scy1(&fixture, REQUEST_ID, 1, foreign())?);
    assert_eq!(
        provider.authenticate_cancel_response(&cancelled, &cancel, None),
        Err(SandboxAdmissionError::ConformanceMismatch)
    );
    let (reconcile, _) = provider.reconcile_request(REQUEST_ID, nonce(), ATTEMPT, AGR1)?;
    let reconciled = flip_last_byte(sry1(&fixture, REQUEST_ID, recomputed_digest()?, foreign())?);
    assert_eq!(
        provider.authenticate_reconcile_response(&reconciled, &reconcile, None),
        Err(SandboxAdmissionError::ConformanceMismatch)
    );
    Ok(())
}

/// An SPE1 for `operation` answering `request`, with code 15.
fn spe1(
    fixture: &TransportAdmissionFixture,
    operation: u64,
    request: &SandboxReconcileRequest,
    attempt_id: [u8; 16],
    key: Value,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    fixture.sign_runtime_record(
        "SPE1",
        Value::Array(vec![
            Value::Text("SPE1".to_owned()),
            uint(1),
            uint(operation),
            Value::Bytes(request.request.request_id.to_vec()),
            Value::Bytes(request.request_digest.to_vec()),
            Value::Bytes(attempt_id.to_vec()),
            uint(15),
            Value::Null,
            key,
        ]),
    )
}

#[test]
fn an_spe1_must_bind_the_operation_the_request_the_digest_and_the_attempt() -> TestResult {
    let fixture = authenticated_transport_fixture()?;
    let provider = &fixture.provider;
    let (request, _) = provider.reconcile_request(REQUEST_ID, nonce(), ATTEMPT, AGR1)?;
    let check = |bytes: &[u8], operation| {
        provider.authenticate_control_error(
            bytes,
            operation,
            &request.request,
            request.request_digest,
            ATTEMPT,
        )
    };
    let bound = spe1(&fixture, 3, &request, ATTEMPT, key_id(&fixture))?;
    assert_eq!(
        check(&bound, SandboxProviderOperation::Reconcile),
        Ok(SandboxProviderErrorCode::UnknownAttempt)
    );
    // The same bytes answer no cancel request.
    assert_eq!(
        check(&bound, SandboxProviderOperation::Cancel),
        Err(contradiction())
    );
    let cancel = spe1(&fixture, 2, &request, ATTEMPT, key_id(&fixture))?;
    assert_eq!(
        check(&cancel, SandboxProviderOperation::Cancel),
        Ok(SandboxProviderErrorCode::UnknownAttempt)
    );
    let other_attempt = spe1(&fixture, 3, &request, [98; 16], key_id(&fixture))?;
    assert_eq!(
        check(&other_attempt, SandboxProviderOperation::Reconcile),
        Err(contradiction())
    );
    Ok(())
}

#[test]
fn an_spe1_is_refused_for_a_forged_signature_a_foreign_key_or_garbage() -> TestResult {
    let fixture = authenticated_transport_fixture()?;
    let provider = &fixture.provider;
    let (request, _) = provider.reconcile_request(REQUEST_ID, nonce(), ATTEMPT, AGR1)?;
    let check = |bytes: &[u8]| {
        provider.authenticate_control_error(
            bytes,
            SandboxProviderOperation::Reconcile,
            &request.request,
            request.request_digest,
            ATTEMPT,
        )
    };
    let bound = spe1(&fixture, 3, &request, ATTEMPT, key_id(&fixture))?;
    assert_eq!(
        check(&flip_last_byte(bound)),
        Err(SandboxAdmissionError::Protocol(
            SandboxProviderProtocolError::SignatureInvalid
        ))
    );
    let foreign = spe1(
        &fixture,
        3,
        &request,
        ATTEMPT,
        Value::Text("foreign".to_owned()),
    )?;
    assert_eq!(
        check(&flip_last_byte(foreign)),
        Err(SandboxAdmissionError::ConformanceMismatch)
    );
    assert!(check(b"not cbor").is_err());
    Ok(())
}
