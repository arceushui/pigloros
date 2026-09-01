//! Shared fixtures for backend erasure-persistence parity tests.

use pos_core::{
    ErasureCoordinatorRecordPartsV1, ErasureCoordinatorRecordV1, ErasureErrorV1,
    ErasureFreezeAdmissionEvidenceV1, ErasureFreezeAuthorizationEvidenceV1,
    ErasureFreezeAuthorizationVerifierV1, ErasureReferenceV1, ErasureRequestInputV1,
    ErasureRequestV1, ErasureScopeV1, ErasureStateV1, ErasureSupportingRecordsV1,
    VerifiedErasureCoordinatorRecordV1,
};

pub struct TestFreezeAuthorizationVerifier;

pub const TEST_FREEZE_AUTHORIZATION_VERIFIER: TestFreezeAuthorizationVerifier =
    TestFreezeAuthorizationVerifier;

impl ErasureFreezeAuthorizationVerifierV1 for TestFreezeAuthorizationVerifier {
    fn validate_freeze_authorization(
        &self,
        admission: &ErasureFreezeAdmissionEvidenceV1,
        authorization: &ErasureFreezeAuthorizationEvidenceV1,
    ) -> Result<(), ErasureErrorV1> {
        (authorization.admission_body_digest() == admission.authorization_body_digest()?)
            .then_some(())
            .ok_or(ErasureErrorV1::Unauthorized)
    }
}

pub const fn erasure_reference(value: u8) -> ErasureReferenceV1 {
    ErasureReferenceV1::from_digest([value; 32])
}

pub fn erasure_record() -> ErasureCoordinatorRecordV1 {
    let request = fixture(ErasureRequestV1::new(ErasureRequestInputV1 {
        request: erasure_reference(1),
        subject: erasure_reference(2),
        scope: ErasureScopeV1::PrivateSubjectData,
        selectors: vec![erasure_reference(3)],
        requester: erasure_reference(4),
        authorization: erasure_reference(5),
        policy: erasure_reference(6),
        request_position: 10,
        horizon_position: 20,
        provenance: erasure_reference(7),
    }));
    let state = fixture(ErasureStateV1::submitted(
        request.reference(),
        erasure_reference(8),
        erasure_reference(9),
    ));
    fixture(ErasureCoordinatorRecordV1::from_parts(
        ErasureCoordinatorRecordPartsV1 {
            request,
            state,
            targets: Vec::new(),
            acknowledgements: Vec::new(),
            receipt: None,
            receipt_input: None,
            authorize_provenance: None,
            freeze_provenance: None,
            dispatch_provenance: None,
            scope_extension_ledger: None,
            administrative_resolution_head: None,
            supporting_records: ErasureSupportingRecordsV1::default(),
        },
        erasure_reference(8),
    ))
}

pub fn verified_erasure_record(
    record: ErasureCoordinatorRecordV1,
) -> VerifiedErasureCoordinatorRecordV1 {
    fixture(VerifiedErasureCoordinatorRecordV1::new(
        record,
        &TEST_FREEZE_AUTHORIZATION_VERIFIER,
    ))
}

fn fixture<T, E: std::fmt::Debug>(result: Result<T, E>) -> T {
    result.unwrap_or_else(|error| {
        std::panic::resume_unwind(Box::new(format!(
            "unexpected erasure persistence fixture error: {error:?}"
        )))
    })
}
