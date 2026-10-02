use pos_core::{
    pipeline_erasure_revision_v1, ErasureReferenceV1, Hash, PipelineAdmissionFenceV1,
    PipelineContractErrorV1, PipelineSecurityRevisionsDraftV1, PipelineSecurityRevisionsV1,
    PIPELINE_ADMISSION_FENCE_BYTES_V1,
};

fn ok<T, E: std::fmt::Debug>(result: Result<T, E>) -> T {
    result.unwrap_or_else(|error| {
        std::panic::resume_unwind(Box::new(format!("unexpected test error: {error:?}")))
    })
}

const fn hash(value: u8) -> Hash {
    Hash::from_bytes([value; 32])
}

fn revisions() -> PipelineSecurityRevisionsV1 {
    ok(PipelineSecurityRevisionsV1::try_from_draft(
        PipelineSecurityRevisionsDraftV1 {
            authority: hash(10),
            consent: hash(11),
            capability: hash(12),
            delegation: hash(13),
            policy: hash(14),
            execution_profile: hash(15),
            erasure: hash(16),
        },
    ))
}

fn fence(domain: Option<Hash>, budget: u64) -> PipelineAdmissionFenceV1 {
    ok(PipelineAdmissionFenceV1::try_new(
        hash(1),
        revisions(),
        domain,
        budget,
    ))
}

fn decode(bytes: &[u8]) -> Result<PipelineAdmissionFenceV1, PipelineContractErrorV1> {
    PipelineAdmissionFenceV1::from_persistence_bytes(bytes)
}

#[test]
fn fence_exposes_exact_values_and_consumes_budget_once() {
    let with_domain = fence(Some(hash(20)), 5);

    assert_eq!(PIPELINE_ADMISSION_FENCE_BYTES_V1, 298);
    assert_eq!(with_domain.authority_grant(), hash(1));
    assert_eq!(with_domain.security_revisions(), revisions());
    assert_eq!(with_domain.domain_state_revision(), Some(hash(20)));
    assert_eq!(with_domain.remaining_event_budget(), 5);
    assert_eq!(
        with_domain
            .after_commit(5)
            .as_ref()
            .map(PipelineAdmissionFenceV1::remaining_event_budget),
        Some(0)
    );
    assert_eq!(with_domain.after_commit(6), None);
}

#[test]
fn fence_rejects_zero_authority_grant_and_zero_domain_revision() {
    assert_eq!(
        PipelineAdmissionFenceV1::try_new(Hash::zero(), revisions(), None, 1),
        Err(PipelineContractErrorV1::FieldOutOfBounds)
    );
    assert_eq!(
        PipelineAdmissionFenceV1::try_new(hash(1), revisions(), Some(Hash::zero()), 1),
        Err(PipelineContractErrorV1::FieldOutOfBounds)
    );
}

#[test]
fn fence_persistence_round_trips_with_and_without_domain_revision() {
    for original in [fence(Some(hash(20)), u64::MAX), fence(None, 0)] {
        let bytes = original.to_persistence_bytes();

        assert_eq!(bytes.len(), PIPELINE_ADMISSION_FENCE_BYTES_V1);
        assert_eq!(decode(&bytes), Ok(original));
    }
}

#[test]
fn fence_persistence_rejects_malformed_records() {
    let valid = fence(Some(hash(20)), 7).to_persistence_bytes();
    let absent = fence(None, 7).to_persistence_bytes();
    let domain_flag = PIPELINE_ADMISSION_FENCE_BYTES_V1 - 8 - 32 - 1;

    assert_eq!(
        decode(&valid[..valid.len() - 1]),
        Err(PipelineContractErrorV1::FieldOutOfBounds)
    );
    let mut version = valid;
    version[0] = 2;
    assert_eq!(
        decode(&version),
        Err(PipelineContractErrorV1::UnsupportedVersion)
    );
    let mut unknown_flag = valid;
    unknown_flag[domain_flag] = 2;
    assert_eq!(
        decode(&unknown_flag),
        Err(PipelineContractErrorV1::FieldOutOfBounds)
    );
    let mut hidden_domain = absent;
    hidden_domain[domain_flag + 1] = 9;
    assert_eq!(
        decode(&hidden_domain),
        Err(PipelineContractErrorV1::FieldOutOfBounds)
    );
    let mut zero_domain = absent;
    zero_domain[domain_flag] = 1;
    assert_eq!(
        decode(&zero_domain),
        Err(PipelineContractErrorV1::FieldOutOfBounds)
    );
    let mut zero_grant = valid;
    zero_grant[1..33].fill(0);
    assert_eq!(
        decode(&zero_grant),
        Err(PipelineContractErrorV1::FieldOutOfBounds)
    );
    let mut zero_revision = valid;
    zero_revision[33..65].fill(0);
    assert_eq!(
        decode(&zero_revision),
        Err(PipelineContractErrorV1::Incomplete)
    );
}

#[test]
fn erasure_revision_binds_the_exact_inventory_generation() {
    let generation = |value: u8| Some(ErasureReferenceV1::from_digest([value; 32]));
    let absent = pipeline_erasure_revision_v1(None);
    let zero = pipeline_erasure_revision_v1(generation(0));
    let first = pipeline_erasure_revision_v1(generation(1));

    assert_eq!(absent, pipeline_erasure_revision_v1(None));
    assert_eq!(first, pipeline_erasure_revision_v1(generation(1)));
    for different in [zero, first, pipeline_erasure_revision_v1(generation(2))] {
        assert_ne!(absent, different);
    }
    assert_ne!(zero, first);
    assert_ne!(absent, Hash::zero());
}
