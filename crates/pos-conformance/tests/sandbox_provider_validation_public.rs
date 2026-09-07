use ed25519_dalek::SigningKey;
use pos_conformance::{
    AdmissionGrantV1, LaunchPolicyV1, SandboxCancelRequestV1, SandboxCancelResponseV1,
    SandboxContractErrorV1, SandboxDescribeRequestV1, SandboxDescribeResponseV1,
    SandboxExecuteRequestV1, SandboxProviderErrorV1, SandboxProviderManifestV1,
    SandboxProviderReceiptV1, SandboxProviderResultV1, SandboxReconcileRequestV1,
    SandboxReconcileResponseV1, SignedImageManifestV1,
};
use pos_reference::sandbox_provider_protocol as independent;

type TestResult = Result<(), Box<dyn std::error::Error>>;

macro_rules! assert_signed_surface_rejects {
    ($valid:expr_2021, $invalidate:expr_2021, $digest:ident, $key:expr_2021) => {{
        let valid = $valid;
        let mut invalid = valid.clone();
        ($invalidate)(&mut invalid);
        assert_eq!(
            invalid.clone().sign(&$key),
            Err(SandboxContractErrorV1::FieldOutOfBounds)
        );
        assert_eq!(
            invalid.validate(),
            Err(SandboxContractErrorV1::FieldOutOfBounds)
        );
        assert_eq!(
            invalid.verify_signature(&$key.verifying_key()),
            Err(SandboxContractErrorV1::FieldOutOfBounds)
        );
        assert_eq!(
            invalid.to_canonical_cbor(),
            Err(SandboxContractErrorV1::FieldOutOfBounds)
        );

        let mut wrong_digest = valid.clone();
        wrong_digest.$digest[0] ^= 1;
        assert_eq!(
            wrong_digest.validate(),
            Err(SandboxContractErrorV1::DigestMismatch)
        );
        assert_eq!(
            wrong_digest.verify_signature(&$key.verifying_key()),
            Err(SandboxContractErrorV1::DigestMismatch)
        );
        assert_eq!(
            wrong_digest.to_canonical_cbor(),
            Err(SandboxContractErrorV1::DigestMismatch)
        );

        let mut unsigned = valid;
        unsigned.signature = [0; 64];
        assert_eq!(
            unsigned.validate(),
            Err(SandboxContractErrorV1::SignatureInvalid)
        );
        assert_eq!(
            unsigned.verify_signature(&$key.verifying_key()),
            Err(SandboxContractErrorV1::SignatureInvalid)
        );
        assert_eq!(
            unsigned.to_canonical_cbor(),
            Err(SandboxContractErrorV1::SignatureInvalid)
        );
    }};
}

macro_rules! assert_self_digested_surface_rejects {
    ($valid:expr_2021, $invalidate:expr_2021, $digest:ident) => {{
        let valid = $valid;
        let mut invalid = valid.clone();
        ($invalidate)(&mut invalid);
        assert_eq!(
            invalid.clone().seal(),
            Err(SandboxContractErrorV1::FieldOutOfBounds)
        );
        assert_eq!(
            invalid.validate(),
            Err(SandboxContractErrorV1::FieldOutOfBounds)
        );
        assert_eq!(
            invalid.to_canonical_cbor(),
            Err(SandboxContractErrorV1::FieldOutOfBounds)
        );

        let mut wrong_digest = valid;
        wrong_digest.$digest[0] ^= 1;
        assert_eq!(
            wrong_digest.validate(),
            Err(SandboxContractErrorV1::DigestMismatch)
        );
        assert_eq!(
            wrong_digest.to_canonical_cbor(),
            Err(SandboxContractErrorV1::DigestMismatch)
        );
    }};
}

#[test]
fn every_signed_public_surface_propagates_validation_failures() -> TestResult {
    let key = SigningKey::from_bytes(&[42; 32]);
    assert_signed_surface_rejects!(
        SandboxProviderManifestV1::from_canonical_cbor(include_bytes!(
            "../vectors/sandbox-provider-v1/spm1.cbor"
        ))?,
        |value: &mut SandboxProviderManifestV1| value.provider_id.clear(),
        manifest_digest,
        key
    );
    assert_signed_surface_rejects!(
        SignedImageManifestV1::from_canonical_cbor(include_bytes!(
            "../vectors/sandbox-provider-v1/sim1.cbor"
        ))?,
        |value: &mut SignedImageManifestV1| value.image_id.clear(),
        manifest_digest,
        key
    );
    assert_signed_surface_rejects!(
        AdmissionGrantV1::from_canonical_cbor(include_bytes!(
            "../vectors/sandbox-provider-v1/agr1.cbor"
        ))?,
        |value: &mut AdmissionGrantV1| value.request_id = [0; 16],
        grant_digest,
        key
    );
    assert_signed_surface_rejects!(
        SandboxProviderResultV1::from_canonical_cbor(include_bytes!(
            "../vectors/sandbox-provider-v1/spy1.cbor"
        ))?,
        |value: &mut SandboxProviderResultV1| value.request_id = [0; 16],
        result_digest,
        key
    );
    assert_signed_surface_rejects!(
        SandboxProviderErrorV1::from_canonical_cbor(include_bytes!(
            "../vectors/sandbox-provider-v1/spe1.cbor"
        ))?,
        |value: &mut SandboxProviderErrorV1| value.operation = Some(4),
        error_digest,
        key
    );
    assert_signed_surface_rejects!(
        SandboxProviderReceiptV1::from_canonical_cbor(include_bytes!(
            "../vectors/sandbox-provider-v1/spr1.cbor"
        ))?,
        |value: &mut SandboxProviderReceiptV1| value.attempt_id = [0; 16],
        receipt_digest,
        key
    );
    assert_signed_surface_rejects!(
        SandboxDescribeResponseV1::from_canonical_cbor(include_bytes!(
            "../vectors/sandbox-provider-v1/sdy1.cbor"
        ))?,
        |value: &mut SandboxDescribeResponseV1| value.request_id = [0; 16],
        response_digest,
        key
    );
    assert_signed_surface_rejects!(
        SandboxCancelResponseV1::from_canonical_cbor(include_bytes!(
            "../vectors/sandbox-provider-v1/scy1.cbor"
        ))?,
        |value: &mut SandboxCancelResponseV1| value.request_id = [0; 16],
        response_digest,
        key
    );
    assert_signed_surface_rejects!(
        SandboxReconcileResponseV1::from_canonical_cbor(include_bytes!(
            "../vectors/sandbox-provider-v1/sry1.cbor"
        ))?,
        |value: &mut SandboxReconcileResponseV1| value.request_id = [0; 16],
        response_digest,
        key
    );
    Ok(())
}

#[test]
fn every_self_digested_public_surface_propagates_validation_failures() -> TestResult {
    assert_self_digested_surface_rejects!(
        LaunchPolicyV1::from_canonical_cbor(include_bytes!(
            "../vectors/sandbox-provider-v1/lps1.cbor"
        ))?,
        |value: &mut LaunchPolicyV1| value.policy_id.clear(),
        policy_digest
    );
    assert_self_digested_surface_rejects!(
        SandboxExecuteRequestV1::from_canonical_cbor(include_bytes!(
            "../vectors/sandbox-provider-v1/spx1.cbor"
        ))?,
        |value: &mut SandboxExecuteRequestV1| value.authority.request_id = [0; 16],
        request_digest
    );
    assert_self_digested_surface_rejects!(
        SandboxDescribeRequestV1::from_canonical_cbor(include_bytes!(
            "../vectors/sandbox-provider-v1/sdq1.cbor"
        ))?,
        |value: &mut SandboxDescribeRequestV1| value.authority.request_id = [0; 16],
        request_digest
    );
    assert_self_digested_surface_rejects!(
        SandboxCancelRequestV1::from_canonical_cbor(include_bytes!(
            "../vectors/sandbox-provider-v1/scq1.cbor"
        ))?,
        |value: &mut SandboxCancelRequestV1| value.authority.request_id = [0; 16],
        request_digest
    );
    assert_self_digested_surface_rejects!(
        SandboxReconcileRequestV1::from_canonical_cbor(include_bytes!(
            "../vectors/sandbox-provider-v1/srq1.cbor"
        ))?,
        |value: &mut SandboxReconcileRequestV1| value.authority.request_id = [0; 16],
        request_digest
    );
    Ok(())
}

#[test]
fn independent_error_verification_rejects_mutated_nul_detail() -> TestResult {
    let key = SigningKey::from_bytes(&[42; 32]);
    let mut error = independent::SandboxProviderError::from_canonical_cbor(include_bytes!(
        "../vectors/sandbox-provider-v1/spe1.cbor"
    ))?;
    error.safe_detail = Some("unsafe\0detail".to_owned());
    assert_eq!(
        error.verify_signature(&key.verifying_key()),
        Err(independent::SandboxProviderProtocolError::FieldOutOfBounds)
    );
    Ok(())
}
