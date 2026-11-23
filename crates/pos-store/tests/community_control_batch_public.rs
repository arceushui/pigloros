//! The extractor's control-record batch form (#560 A4e-1; ADR-129
//! revision 9 R9.9(5), N8(a), test I70) through its public seam: a
//! `LifecycleControl` COW1 batch with no CGR1, whose head must be the
//! expected one and whose records must be pre-execution CFO1s.

use pos_core::community_lifecycle::{
    CommunityArtifactKindV1 as Kind, CommunityArtifactOperationV1, CommunityArtifactPurposeV1,
    CommunityDigestListV1, CommunityLifecycleErrorV1 as Error, CommunityMemberSlotsV1,
    CommunityPassFailureInputV1, CommunityPassFailureV1, CommunityPassKeyV1,
    CommunityPluginHostErrorV1 as Host, CommunityRecordKindsV1, RevocationBasisV1,
};
use pos_core::{
    ArtifactChildEdgeV1, AuthorityTrustRootSealV1, ErasureArtifactClassV1, Hash, TimelineId,
};
use pos_store::community::{
    prepare_community_artifact_batch_v1, CommunityArtifactBatchFormV1 as Form,
    CommunityArtifactProtectorV1, CommunityArtifactRecordInputV1, CommunityControlBatchInputV1,
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

const fn timeline() -> TimelineId {
    TimelineId::from_ulid(Ulid::from_bytes([7; 16]))
}

fn protector(
    purpose: CommunityArtifactPurposeV1,
    kind: Kind,
) -> Fallible<CommunityArtifactProtectorV1> {
    Ok(CommunityArtifactProtectorV1::provision(
        &SEAL,
        CommunityProtectionCohortV1 {
            parent_operation: CommunityArtifactOperationV1::Control([0x40; 16]),
            timeline: timeline(),
            generation: GENERATION,
            purpose,
            scope_set_digest: Hash::from_bytes([0x33; 32]),
            scope_cover_digest: Hash::from_bytes([0x34; 32]),
            evidence_not_after_micros: 1_000,
            allowed_record_kinds: CommunityRecordKindsV1::empty()
                .with(kind)
                .with(Kind::ClassificationProof),
            member_slots: CommunityMemberSlotsV1::empty(),
            authority_request_digest: Hash::from_bytes([0x35; 32]),
        },
    )?)
}

/// A CFO1 with `pass` and `invocations`.
fn failure(pass: Option<CommunityPassKeyV1>, invocations: &[Hash]) -> Fallible<Vec<u8>> {
    Ok(CommunityPassFailureV1::new(CommunityPassFailureInputV1 {
        pass_key: pass,
        invocation_evidence_digests: CommunityDigestListV1::from_digests(invocations),
        host_failure: Host::ArtifactRevoked {
            basis: RevocationBasisV1::Artifact,
        },
        host_decision_provenance_digest: Hash::from_bytes([0x36; 32]),
        evidence_not_after_micros: 1_000,
    })?
    .to_canonical_cbor()
    .to_vec())
}

fn protect(
    protector: &mut CommunityArtifactProtectorV1,
    kind: Kind,
    plaintext: &[u8],
    children: &[ArtifactChildEdgeV1],
) -> Fallible<CommunityProtectedRecordV1> {
    Ok(protector.protect(
        kind,
        plaintext,
        CommunityRecordEvidenceV1 {
            owner_binding_digest: OWNER,
            host_provenance_digest: Hash::from_bytes([0x37; 32]),
            children,
        },
    )?)
}

/// Prepare a control batch of `records` under `key`, with `graph_root`
/// and `current` as the head.
fn prepare(
    key: &CommunityArtifactProtectorV1,
    records: &[&CommunityProtectedRecordV1],
    graph_root: Option<&[u8]>,
    current: Option<Hash>,
) -> Result<pos_store::community::CommunityArtifactBatchV1, Error> {
    let inputs: Vec<CommunityArtifactRecordInputV1<'_>> = records
        .iter()
        .map(|record| CommunityArtifactRecordInputV1 {
            object: record.object(),
            registration: record.registration(),
        })
        .collect();
    prepare_community_artifact_batch_v1(
        &SEAL,
        Form::Control(CommunityControlBatchInputV1 {
            timeline: timeline(),
            generation: GENERATION,
            owner_binding_digest: OWNER,
            records: &inputs,
            graph_root,
            current_head: current,
            expected_head: Some(HEAD),
        }),
        &[key],
    )
}

/// A pre-execution CFO1 COW1 verifies with no CGR1, and its ARD1 is
/// `TimelineReplay` with no children.
#[test]
fn a_pre_execution_cfo1_batch_verifies_without_a_graph_root() -> TestResult {
    let mut key = protector(
        CommunityArtifactPurposeV1::LifecycleControl,
        Kind::LifecycleControl,
    )?;
    let record = protect(&mut key, Kind::LifecycleControl, &failure(None, &[])?, &[])?;
    let batch = prepare(&key, &[&record], None, Some(HEAD))?;
    assert_eq!(batch.graph_root_digest(), None);
    assert_eq!(batch.records().len(), 1);
    let verified = &batch.records()[0];
    assert_eq!(verified.object(), record.object());
    let fields = verified.registration().fields();
    assert_eq!(
        fields.artifact_class,
        ErasureArtifactClassV1::TimelineReplay
    );
    assert!(fields.child_artifacts.is_empty());
    Ok(())
}

/// I70: the control batch refuses a head other than the expected one (6),
/// a graph root, no record, and a record that is not a pre-execution CFO1
/// (another kind, a `PassKey`, a CFI1 list, a child edge or another record).
#[test]
fn the_control_batch_refuses_everything_but_a_pre_execution_cfo1() -> TestResult {
    let mut key = protector(
        CommunityArtifactPurposeV1::LifecycleControl,
        Kind::LifecycleControl,
    )?;
    let good = protect(&mut key, Kind::LifecycleControl, &failure(None, &[])?, &[])?;
    assert_eq!(
        prepare(&key, &[&good], None, Some(Hash::from_bytes([0x38; 32]))).err(),
        Some(Error::StaleFrontier)
    );
    assert_eq!(
        prepare(&key, &[&good], Some(&[0x80]), Some(HEAD)).err(),
        Some(Error::InvalidBinding)
    );
    assert_eq!(
        prepare(&key, &[], None, Some(HEAD)).err(),
        Some(Error::InvalidBinding)
    );
    let pass = CommunityPassKeyV1::new(timeline(), GENERATION, 1)?;
    let child = ArtifactChildEdgeV1 {
        artifact_class: ErasureArtifactClassV1::TimelineReplay,
        artifact_digest: Hash::from_bytes([0x39; 32]),
        registration_address: Hash::from_bytes([0x3a; 32]),
        required: true,
    };
    for record in [
        protect(
            &mut key,
            Kind::LifecycleControl,
            &failure(Some(pass), &[])?,
            &[],
        )?,
        protect(
            &mut key,
            Kind::LifecycleControl,
            &failure(None, &[Hash::from_bytes([0x3b; 32])])?,
            &[],
        )?,
        protect(
            &mut key,
            Kind::LifecycleControl,
            &failure(None, &[])?,
            &[child],
        )?,
        protect(&mut key, Kind::LifecycleControl, b"not a CFO1", &[])?,
    ] {
        assert_eq!(
            prepare(&key, &[&record], None, Some(HEAD)).err(),
            Some(Error::InvalidBinding)
        );
    }
    let mut state = protector(
        CommunityArtifactPurposeV1::ExecutionState,
        Kind::StateContent,
    )?;
    let content = protect(&mut state, Kind::StateContent, &failure(None, &[])?, &[])?;
    assert_eq!(
        prepare(&state, &[&content], None, Some(HEAD)).err(),
        Some(Error::InvalidBinding)
    );
    Ok(())
}
