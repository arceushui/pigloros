//! The extractor's pass control batch form (#560 A4e-2b; ADR-129 revision
//! 15 R15.1(6), R15.4) through its public seam: the CFO1 and the CFI1s it
//! lists, `LifecycleControl` COW1s of one CPK1 under the pass CSB1 cover,
//! with no CGR1.

use pos_core::community_lifecycle::{
    CommunityArtifactKindV1 as Kind, CommunityArtifactOperationV1, CommunityArtifactPurposeV1,
    CommunityDigestListV1, CommunityInvocationFailureInputV1, CommunityInvocationFailureV1,
    CommunityLifecycleErrorV1 as Error, CommunityMemberSlotsV1, CommunityPassFailureInputV1,
    CommunityPassFailureV1, CommunityPassKeyV1, CommunityPluginHostErrorV1 as Host,
    CommunityRecordKindsV1,
};
use pos_core::{ArtifactChildEdgeV1, AuthorityTrustRootSealV1, Hash, TimelineId};
use pos_store::community::{
    prepare_community_pass_control_batch_v1, CommunityArtifactBatchV1,
    CommunityArtifactProtectorV1, CommunityArtifactRecordInputV1, CommunityPassControlBatchInputV1,
    CommunityProtectedRecordV1, CommunityProtectionCohortV1, CommunityRecordEvidenceV1,
};
use ulid::Ulid;

/// The trust-root seal of the test composition.
const SEAL: AuthorityTrustRootSealV1 = AuthorityTrustRootSealV1::for_composition_root();

type Fallible<T> = Result<T, Box<dyn std::error::Error>>;
type TestResult = Fallible<()>;

const GENERATION: [u8; 16] = [0x20; 16];
const OWNER: Hash = Hash::from_bytes([0x31; 32]);
const HEAD: Hash = Hash::from_bytes([0x32; 32]);
const COVER: Hash = Hash::from_bytes([0x34; 32]);

const fn timeline() -> TimelineId {
    TimelineId::from_ulid(Ulid::from_bytes([7; 16]))
}

fn pass() -> Result<CommunityPassKeyV1, Error> {
    CommunityPassKeyV1::new(timeline(), GENERATION, 5)
}

/// A failure cohort protector for `pass` under `purpose` and `cover`.
fn protector(
    purpose: CommunityArtifactPurposeV1,
    cover: Hash,
) -> Fallible<CommunityArtifactProtectorV1> {
    Ok(CommunityArtifactProtectorV1::provision(
        &SEAL,
        CommunityProtectionCohortV1 {
            parent_operation: CommunityArtifactOperationV1::Pass(pass()?),
            timeline: timeline(),
            generation: GENERATION,
            purpose,
            scope_set_digest: Hash::from_bytes([0x33; 32]),
            scope_cover_digest: cover,
            evidence_not_after_micros: 1_000,
            allowed_record_kinds: CommunityRecordKindsV1::empty()
                .with(Kind::LifecycleControl)
                .with(Kind::ClassificationProof),
            member_slots: CommunityMemberSlotsV1::empty(),
            authority_request_digest: Hash::from_bytes([0x35; 32]),
        },
    )?)
}

/// A CFI1 of `pass` and its digest.
fn invocation(pass: Option<CommunityPassKeyV1>, member: u8) -> Fallible<(Vec<u8>, Hash)> {
    let record = CommunityInvocationFailureV1::new(CommunityInvocationFailureInputV1 {
        pass_key: pass,
        member_binding_digest: Hash::from_bytes([member; 32]),
        invocation_id: Some([member; 16]),
        prepared_invocation_digest: Some(Hash::from_bytes([member + 1; 32])),
        host_failure: Host::InvalidGuestOutput,
        guest_error: None,
        decision_provenance_digest: Hash::from_bytes([0x36; 32]),
        evidence_not_after_micros: 1_000,
    })?;
    Ok((record.to_canonical_cbor().to_vec(), record.digest()))
}

/// A CFO1 of `pass` listing `listed`.
fn outcome(pass: Option<CommunityPassKeyV1>, listed: &[Hash]) -> Fallible<Vec<u8>> {
    Ok(CommunityPassFailureV1::new(CommunityPassFailureInputV1 {
        pass_key: pass,
        invocation_evidence_digests: CommunityDigestListV1::from_digests(listed),
        host_failure: Host::InvalidGuestOutput,
        host_decision_provenance_digest: Hash::from_bytes([0x36; 32]),
        evidence_not_after_micros: 1_000,
    })?
    .to_canonical_cbor()
    .to_vec())
}

fn protect(
    protector: &mut CommunityArtifactProtectorV1,
    plaintext: &[u8],
    children: &[ArtifactChildEdgeV1],
) -> Fallible<CommunityProtectedRecordV1> {
    Ok(protector.protect(
        Kind::LifecycleControl,
        plaintext,
        CommunityRecordEvidenceV1 {
            owner_binding_digest: OWNER,
            host_provenance_digest: Hash::from_bytes([0x37; 32]),
            children,
        },
    )?)
}

/// The child edge that lists `record`.
const fn edge(record: &CommunityProtectedRecordV1) -> ArtifactChildEdgeV1 {
    let registration = record.registration();
    ArtifactChildEdgeV1 {
        artifact_class: registration.fields().artifact_class,
        artifact_digest: registration.fields().artifact_digest,
        registration_address: registration.address(),
        required: true,
    }
}

/// Prepare a pass control batch of `records` for `pass` under `cover`, with
/// `current` as the head.
fn prepare(
    key: &CommunityArtifactProtectorV1,
    records: &[&CommunityProtectedRecordV1],
    (pass, cover, current): (CommunityPassKeyV1, Hash, Hash),
) -> Result<CommunityArtifactBatchV1, Error> {
    let inputs: Vec<CommunityArtifactRecordInputV1<'_>> = records
        .iter()
        .map(|record| CommunityArtifactRecordInputV1 {
            object: record.object(),
            registration: record.registration(),
        })
        .collect();
    prepare_community_pass_control_batch_v1(
        &SEAL,
        CommunityPassControlBatchInputV1 {
            pass_key: pass,
            owner_binding_digest: OWNER,
            scope_cover_digest: cover,
            records: &inputs,
            current_head: current,
            expected_head: HEAD,
        },
        &[key],
    )
}

/// The facts of a good batch: the pass, the cover and the expected head.
fn good() -> Fallible<(CommunityPassKeyV1, Hash, Hash)> {
    Ok((pass()?, COVER, HEAD))
}

/// A CFI1 and the CFO1 that lists it verify, with no CGR1: the CFI1 has no
/// children and the CFO1 lists the CFI1.
#[test]
fn a_cfo1_and_its_cfi1_verify_without_a_graph_root() -> TestResult {
    let mut key = protector(CommunityArtifactPurposeV1::LifecycleControl, COVER)?;
    let (cfi1_bytes, cfi1_digest) = invocation(Some(pass()?), 1)?;
    let member = protect(&mut key, &cfi1_bytes, &[])?;
    let cfo1 = protect(
        &mut key,
        &outcome(Some(pass()?), &[cfi1_digest])?,
        &[edge(&member)],
    )?;
    let batch = prepare(&key, &[&member, &cfo1], good()?)?;
    assert_eq!(batch.graph_root_digest(), None);
    assert_eq!(batch.records().len(), 2);
    assert_eq!(batch.records()[0].object(), member.object());
    assert_eq!(batch.records()[1].object(), cfo1.object());
    Ok(())
}

/// The batch refuses a head other than the CPR1 predecessor (6), and a
/// batch with no CFO1 or two (3).
#[test]
fn the_head_and_the_one_cfo1_are_required() -> TestResult {
    let mut key = protector(CommunityArtifactPurposeV1::LifecycleControl, COVER)?;
    let cfo1 = protect(&mut key, &outcome(Some(pass()?), &[])?, &[])?;
    let other = protect(&mut key, &outcome(Some(pass()?), &[])?, &[])?;
    assert!(prepare(&key, &[&cfo1], good()?).is_ok());
    assert_eq!(
        prepare(
            &key,
            &[&cfo1],
            (pass()?, COVER, Hash::from_bytes([0x38; 32]))
        )
        .err(),
        Some(Error::StaleFrontier)
    );
    assert_eq!(
        prepare(&key, &[], good()?).err(),
        Some(Error::InvalidBinding)
    );
    assert_eq!(
        prepare(&key, &[&cfo1, &other], good()?).err(),
        Some(Error::InvalidBinding)
    );
    Ok(())
}

/// The batch is exactly the CFO1 and the CFI1s it lists, with the children
/// R15.4 derives: a listed CFI1 that is absent, a CFI1 the CFO1 does not
/// list, a CFO1 without the child edge and a CFI1 with a child each give 3.
#[test]
fn the_batch_is_exactly_the_cfo1_and_its_listed_cfi1s() -> TestResult {
    let mut key = protector(CommunityArtifactPurposeV1::LifecycleControl, COVER)?;
    let (cfi1_bytes, cfi1_digest) = invocation(Some(pass()?), 1)?;
    let cfi1 = protect(&mut key, &cfi1_bytes, &[])?;
    let listing = protect(
        &mut key,
        &outcome(Some(pass()?), &[cfi1_digest])?,
        &[edge(&cfi1)],
    )?;
    let empty = protect(&mut key, &outcome(Some(pass()?), &[])?, &[])?;
    let no_edge = protect(&mut key, &outcome(Some(pass()?), &[cfi1_digest])?, &[])?;
    let with_child = protect(&mut key, &cfi1_bytes, &[edge(&cfi1)])?;
    for records in [
        vec![&listing],
        vec![&empty, &cfi1],
        vec![&no_edge, &cfi1],
        vec![&listing, &with_child],
    ] {
        assert_eq!(
            prepare(&key, &records, good()?).err(),
            Some(Error::InvalidBinding)
        );
    }
    Ok(())
}

/// Every record is a CFO1 or CFI1 of the batch's pass under the pass cover:
/// another pass, no pass, another cover and a pre-execution CFO1 each give 3, and a
/// record that is not a failure record is the codec's refusal.
#[test]
fn every_record_is_of_the_pass_under_its_cover() -> TestResult {
    let mut key = protector(CommunityArtifactPurposeV1::LifecycleControl, COVER)?;
    let cfo1 = protect(&mut key, &outcome(Some(pass()?), &[])?, &[])?;
    let elsewhere = CommunityPassKeyV1::new(timeline(), GENERATION, 6)?;
    assert_eq!(
        prepare(&key, &[&cfo1], (elsewhere, COVER, HEAD)).err(),
        Some(Error::InvalidBinding)
    );
    assert_eq!(
        prepare(
            &key,
            &[&cfo1],
            (pass()?, Hash::from_bytes([0x3c; 32]), HEAD)
        )
        .err(),
        Some(Error::InvalidBinding)
    );
    let pre_execution = protect(&mut key, &outcome(None, &[])?, &[])?;
    let foreign = protect(&mut key, &invocation(Some(elsewhere), 1)?.0, &[])?;
    let text = protect(&mut key, b"not a failure record", &[])?;
    for record in [&pre_execution, &foreign] {
        assert_eq!(
            prepare(&key, &[record], good()?).err(),
            Some(Error::InvalidBinding)
        );
    }
    assert_eq!(
        prepare(&key, &[&text], good()?).err(),
        Some(Error::InvalidEncoding)
    );
    let mut state = state_protector()?;
    let content = state.protect(
        Kind::StateContent,
        &outcome(Some(pass()?), &[])?,
        CommunityRecordEvidenceV1 {
            owner_binding_digest: OWNER,
            host_provenance_digest: Hash::from_bytes([0x37; 32]),
            children: &[],
        },
    )?;
    assert_eq!(
        prepare(&state, &[&content], good()?).err(),
        Some(Error::InvalidBinding)
    );
    Ok(())
}

/// A State cohort under the same pass and cover, whose kind is not control.
fn state_protector() -> Fallible<CommunityArtifactProtectorV1> {
    Ok(CommunityArtifactProtectorV1::provision(
        &SEAL,
        CommunityProtectionCohortV1 {
            parent_operation: CommunityArtifactOperationV1::Pass(pass()?),
            timeline: timeline(),
            generation: GENERATION,
            purpose: CommunityArtifactPurposeV1::ExecutionState,
            scope_set_digest: Hash::from_bytes([0x33; 32]),
            scope_cover_digest: COVER,
            evidence_not_after_micros: 1_000,
            allowed_record_kinds: CommunityRecordKindsV1::empty()
                .with(Kind::StateContent)
                .with(Kind::ClassificationProof),
            member_slots: CommunityMemberSlotsV1::empty(),
            authority_request_digest: Hash::from_bytes([0x35; 32]),
        },
    )?)
}
