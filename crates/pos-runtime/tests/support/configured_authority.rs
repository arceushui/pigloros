use pos_core::{
    ErasureAcknowledgementProvenanceV1, ErasureAttemptQuotaReservationV1,
    ErasureDestructionCommandV1, ErasureErrorV1, ErasureReceiptInputV1, ErasureReferenceV1,
    ErasureRequestV1, ErasureRetryAdmissionV1,
};
use pos_runtime::{
    ErasureAuthorityEvidenceKindV1, ErasureAuthorityEvidenceVerifierV1, ErasureAuthorityExecutionV1,
};

#[derive(Debug)]
pub(super) struct TestEvidenceVerifier;

impl ErasureAuthorityEvidenceVerifierV1 for TestEvidenceVerifier {
    fn verify(
        &self,
        _kind: ErasureAuthorityEvidenceKindV1,
        _request: &ErasureRequestV1,
        context: &[u8],
        evidence: &[u8],
    ) -> Result<(), ErasureErrorV1> {
        if !context.is_empty() && evidence == b"host-proof" {
            Ok(())
        } else {
            Err(ErasureErrorV1::Unauthorized)
        }
    }
}

#[derive(Debug)]
pub(super) struct RejectingEvidenceVerifier;

impl ErasureAuthorityEvidenceVerifierV1 for RejectingEvidenceVerifier {
    fn verify(
        &self,
        _kind: ErasureAuthorityEvidenceKindV1,
        _request: &ErasureRequestV1,
        _context: &[u8],
        _evidence: &[u8],
    ) -> Result<(), ErasureErrorV1> {
        Err(ErasureErrorV1::Unauthorized)
    }
}

#[derive(Debug)]
pub(super) struct TestExecution;

impl ErasureAuthorityExecutionV1 for TestExecution {
    fn dispatch_destruction(
        &self,
        _request: ErasureReferenceV1,
        commands: &[ErasureDestructionCommandV1],
    ) -> Result<(), ErasureErrorV1> {
        (!commands.is_empty())
            .then_some(())
            .ok_or(ErasureErrorV1::ScopeInvalid)
    }

    fn reserve_attempt(
        &self,
        admission: &ErasureRetryAdmissionV1,
    ) -> Result<ErasureAttemptQuotaReservationV1, ErasureErrorV1> {
        Ok(ErasureAttemptQuotaReservationV1::new(
            admission.reference(),
            ErasureReferenceV1::from_digest([99; 32]),
        ))
    }

    fn admit_acknowledgement(
        &self,
        _acknowledgement: &ErasureAcknowledgementProvenanceV1,
    ) -> Result<(), ErasureErrorV1> {
        Ok(())
    }

    fn admit_receipt(&self, _input: &ErasureReceiptInputV1) -> Result<(), ErasureErrorV1> {
        Ok(())
    }
}
