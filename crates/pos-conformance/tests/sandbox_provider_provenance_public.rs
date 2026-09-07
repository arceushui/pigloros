use ed25519_dalek::SigningKey;
use pos_conformance::{
    AdmissionAuthorityV1, AdmissionGrantV1, CaseOutcomeStatusV1, CaseOutcomeV1, ClaimLayerV1,
    ExecutionModeV1, ReceiptAuthorityV1, RedactionStateV1, ReplayClaimV1, SandboxContractErrorV1,
    SandboxProviderReceiptV1,
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const fn digest(seed: u8) -> [u8; 32] {
    [seed; 32]
}

struct ProvenanceFixture {
    key: SigningKey,
    grant: AdmissionGrantV1,
    receipt: SandboxProviderReceiptV1,
    case: CaseOutcomeV1,
}

fn fixture() -> TestResult<ProvenanceFixture> {
    let key = SigningKey::from_bytes(&[42; 32]);
    let grant = AdmissionGrantV1 {
        request_id: [1; 16],
        attempt_id: [2; 16],
        authority: AdmissionAuthorityV1 {
            evr1_digest: digest(1),
            fixture_contract_digest: digest(2),
            fixture_digest: digest(3),
            execution_profile_digest: digest(4),
            lps1_digest: digest(5),
            sim1_digest: digest(6),
            apt1_digest: digest(7),
            trs1_digest: digest(8),
            rvs1_digest: digest(9),
            spm1_digest: digest(10),
            pcf1_digest: digest(11),
            pcr1_digest: digest(12),
            hcp1_digest: digest(13),
        },
        trust_epoch: 14,
        revocation_epoch: 15,
        policy_epoch: 16,
        elm1_digest: digest(17),
        input_digest: digest(18),
        exchange_plan_digests: vec![digest(19)],
        expected_launch_policy_digest: digest(20),
        expected_readback_set_digest: digest(21),
        runtime_attestation_key_id: "runtime-key".to_owned(),
        grant_digest: [0; 32],
        signature: [0; 64],
    }
    .sign(&key)?;
    let receipt = SandboxProviderReceiptV1 {
        attempt_id: grant.attempt_id,
        authority: ReceiptAuthorityV1 {
            agr1_digest: grant.grant_digest,
            spm1_digest: grant.authority.spm1_digest,
            provider_binary_digest: digest(22),
            lps1_digest: grant.authority.lps1_digest,
            sim1_digest: grant.authority.sim1_digest,
            apt1_digest: grant.authority.apt1_digest,
            trs1_digest: grant.authority.trs1_digest,
            rvs1_digest: grant.authority.rvs1_digest,
        },
        trust_epoch: grant.trust_epoch,
        revocation_epoch: grant.revocation_epoch,
        policy_epoch: grant.policy_epoch,
        hcp1_digest: grant.authority.hcp1_digest,
        elm1_digest: grant.elm1_digest,
        network_transcript_digests: vec![digest(23)],
        ready1_digest: Some(digest(24)),
        release1_digest: Some(digest(25)),
        requested_configuration_evidence: digest(26),
        kernel_observation_evidence: digest(27),
        negative_probe_evidence: digest(28),
        termination_evidence: digest(29),
        sau1_digest: digest(30),
        runtime_attestation_key_id: grant.runtime_attestation_key_id.clone(),
        receipt_digest: [0; 32],
        signature: [0; 64],
    }
    .sign(&key)?;
    let case = CaseOutcomeV1 {
        case_id: "sandboxed-case".to_owned(),
        fixture_digest: grant.authority.fixture_digest,
        execution_profile_digest: grant.authority.execution_profile_digest,
        mode: ExecutionModeV1::Local,
        claim_layer: ClaimLayerV1::PluginConformance,
        outcome: CaseOutcomeStatusV1::Pass,
        first_coordinate: None,
        expected_digest: Some(digest(31)),
        actual_digest: Some(digest(31)),
        expected_error: None,
        actual_error: None,
        replay_claim: ReplayClaimV1::Exact,
        redaction_state: RedactionStateV1::None,
        provenance_digest: receipt.receipt_digest,
    };
    Ok(ProvenanceFixture {
        key,
        grant,
        receipt,
        case,
    })
}

fn resign_receipt(
    mut receipt: SandboxProviderReceiptV1,
    key: &SigningKey,
) -> TestResult<SandboxProviderReceiptV1> {
    receipt.receipt_digest = [0; 32];
    receipt.signature = [0; 64];
    Ok(receipt.sign(key)?)
}

#[test]
fn validated_spr1_is_the_exact_sandboxed_case_provenance() -> TestResult {
    let value = fixture()?;
    value.receipt.verify_case_provenance(
        &value.grant,
        &value.case,
        value.grant.request_id,
        value.grant.authority.evr1_digest,
        &value.key.verifying_key(),
    )?;
    Ok(())
}

#[test]
fn sandboxed_case_provenance_rejects_every_authority_mismatch() -> TestResult {
    let value = fixture()?;
    let mutations: [fn(&mut SandboxProviderReceiptV1); 14] = [
        |receipt| receipt.attempt_id = [9; 16],
        |receipt| receipt.authority.agr1_digest = digest(40),
        |receipt| receipt.authority.spm1_digest = digest(40),
        |receipt| receipt.authority.lps1_digest = digest(40),
        |receipt| receipt.authority.sim1_digest = digest(40),
        |receipt| receipt.authority.apt1_digest = digest(40),
        |receipt| receipt.authority.trs1_digest = digest(40),
        |receipt| receipt.authority.rvs1_digest = digest(40),
        |receipt| receipt.trust_epoch += 1,
        |receipt| receipt.revocation_epoch += 1,
        |receipt| receipt.policy_epoch += 1,
        |receipt| receipt.hcp1_digest = digest(40),
        |receipt| receipt.elm1_digest = digest(40),
        |receipt| receipt.runtime_attestation_key_id = "other-runtime-key".to_owned(),
    ];
    for mutate in mutations {
        let mut receipt = value.receipt.clone();
        mutate(&mut receipt);
        let receipt = resign_receipt(receipt, &value.key)?;
        assert_eq!(
            receipt.verify_case_provenance(
                &value.grant,
                &value.case,
                value.grant.request_id,
                value.grant.authority.evr1_digest,
                &value.key.verifying_key(),
            ),
            Err(SandboxContractErrorV1::InconsistentFields)
        );
    }
    Ok(())
}

#[test]
fn sandboxed_case_provenance_rejects_wrong_request_case_and_signatures() -> TestResult {
    let value = fixture()?;
    for (request_id, evr1_digest) in [
        ([9; 16], value.grant.authority.evr1_digest),
        (value.grant.request_id, digest(40)),
    ] {
        assert_eq!(
            value.receipt.verify_case_provenance(
                &value.grant,
                &value.case,
                request_id,
                evr1_digest,
                &value.key.verifying_key(),
            ),
            Err(SandboxContractErrorV1::InconsistentFields)
        );
    }
    let case_mutations: [fn(&mut CaseOutcomeV1); 3] = [
        |case: &mut CaseOutcomeV1| case.fixture_digest = digest(40),
        |case: &mut CaseOutcomeV1| case.execution_profile_digest = digest(40),
        |case: &mut CaseOutcomeV1| case.provenance_digest = digest(40),
    ];
    for mutate in case_mutations {
        let mut case = value.case.clone();
        mutate(&mut case);
        assert_eq!(
            value.receipt.verify_case_provenance(
                &value.grant,
                &case,
                value.grant.request_id,
                value.grant.authority.evr1_digest,
                &value.key.verifying_key(),
            ),
            Err(SandboxContractErrorV1::InconsistentFields)
        );
    }

    let mut bad_grant = value.grant.clone();
    bad_grant.signature[0] ^= 1;
    assert_eq!(
        value.receipt.verify_case_provenance(
            &bad_grant,
            &value.case,
            value.grant.request_id,
            value.grant.authority.evr1_digest,
            &value.key.verifying_key(),
        ),
        Err(SandboxContractErrorV1::SignatureInvalid)
    );
    let mut bad_receipt = value.receipt;
    bad_receipt.signature[0] ^= 1;
    assert_eq!(
        bad_receipt.verify_case_provenance(
            &value.grant,
            &value.case,
            value.grant.request_id,
            value.grant.authority.evr1_digest,
            &value.key.verifying_key(),
        ),
        Err(SandboxContractErrorV1::SignatureInvalid)
    );
    Ok(())
}
