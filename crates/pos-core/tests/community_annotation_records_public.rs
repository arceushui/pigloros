//! The Seal-staged annotation records: the R15.6 charge, `k` dedup and bounds,
//! measured against records built independently through the public codecs.

use pos_core::community_lifecycle::{
    CommunityAnnotationCandidateV1 as Candidate, CommunityAnnotationContextV1 as Context,
    CommunityAnnotationItemV1 as Item, CommunityAnnotationManifestInputV1 as ManifestInput,
    CommunityAnnotationManifestV1 as Manifest, CommunityAnnotationRecordsV1 as Records,
    CommunityContentReferenceV1 as Content, CommunityDigestListV1 as Digests,
    CommunityInputIndexV1 as Index, CommunityLifecycleErrorV1 as Error,
    CommunityNativeNodeInputV1 as NodeInput, CommunityNativeNodeKindV1 as Kind,
    CommunityNativeNodeReferenceV1 as Reference, CommunityNativeNodeV1 as Node,
    CommunityPassKeyV1 as Pass, CommunityTypedInputRefV1 as Typed,
    CommunityTypedInputRefsV1 as TypedRefs,
};
use pos_core::{Hash, RecordedDependencyClassV1, TimelineId};

type TestResult = Result<(), Box<dyn std::error::Error>>;

const INCARNATION: [u8; 16] = [9; 16];
const HORIZON: u64 = 9_000;

const fn hash(byte: u8) -> Hash {
    Hash::from_bytes([byte; 32])
}

fn pass() -> Result<Pass, Error> {
    Pass::new(
        TimelineId::from_ulid(ulid::Ulid::from_bytes([1; 16])),
        [2; 16],
        3,
    )
}

/// A native reference of producer `producer`; the annotation node is
/// producer 1,000.
const fn native(producer: u64) -> Reference {
    Reference {
        store_incarnation: INCARNATION,
        producer_ordinal: producer,
        node_ordinal: 1,
        node_digest: hash(0x40),
    }
}

fn context() -> Result<Context, Error> {
    Ok(Context {
        pass_key: pass()?,
        member_binding_digest: hash(4),
        invocation_step_digest: hash(5),
        step: native(10),
        producer_ordinal: 1_000,
        node_ordinal: 0,
        scope_binding_digest: hash(6),
        authorization_digest: hash(7),
        provenance_digest: hash(8),
        evidence_not_after_micros: HORIZON,
    })
}

fn refs(producers: std::ops::Range<u64>) -> Vec<Typed<'static>> {
    producers
        .map(|producer| Typed::Native(native(producer)))
        .collect()
}

const fn item<'a>(guest_index: u64, inputs: &'a [Typed<'a>]) -> Candidate<'a> {
    Candidate {
        guest_index,
        claim_bytes: b"claim",
        inputs,
    }
}

/// The CAT1 and CPN1 lengths and digests of `items`, built without
/// `Records`: the rows of each item sorted and the node's inputs given in
/// ascending native order.
fn oracle(
    items: &[(u64, Vec<Typed<'static>>)],
    node_inputs: &[Typed<'static>],
) -> Result<(usize, Hash, Reference), Box<dyn std::error::Error>> {
    let rows: Vec<Vec<Hash>> = items
        .iter()
        .map(|(_, inputs)| {
            let mut row: Vec<Hash> = inputs.iter().map(|reference| reference.digest()).collect();
            row.sort_unstable();
            row
        })
        .collect();
    let manifest = Manifest::new(ManifestInput {
        pass_key: pass()?,
        member_binding_digest: hash(4),
        invocation_step_digest: hash(5),
        items: items
            .iter()
            .zip(&rows)
            .map(|((guest_index, _), row)| Item {
                guest_index: *guest_index,
                claim_bytes: b"claim",
                resolved_input_digests: Digests::from_digests(row),
            })
            .collect(),
        evidence_not_after_micros: HORIZON,
    })?;
    let node = Node::new(NodeInput {
        store_incarnation: INCARNATION,
        timeline: pass()?.timeline(),
        generation: pass()?.generation(),
        producer_ordinal: 1_000,
        node_ordinal: 0,
        kind: Kind::Annotation,
        content: Content {
            record_magic: *b"CAT1",
            logical_digest: manifest.digest(),
        },
        dependency_class: RecordedDependencyClassV1::PresentationOnly,
        input_index: Index::Direct(TypedRefs::from_references(node_inputs)),
        scope_binding_digest: hash(6),
        authorization_digest: hash(7),
        provenance_digest: hash(8),
        evidence_not_after_micros: HORIZON,
    })?;
    Ok((
        manifest.to_canonical_cbor().len() + node.to_canonical_cbor().len(),
        manifest.digest(),
        node.reference(),
    ))
}

#[test]
fn no_item_stages_nothing() -> TestResult {
    assert!(Records::stage(&context()?, &[])?.is_none());
    Ok(())
}

#[test]
fn the_charge_and_digests_equal_independently_built_records() -> TestResult {
    let inputs = refs(11..13);
    let staged = Records::stage(&context()?, &[item(2, &inputs)])?.ok_or("records")?;
    let mut node_inputs = vec![Typed::Native(native(10))];
    node_inputs.extend(inputs.iter().copied());
    let (bytes, manifest_digest, node) = oracle(&[(2, inputs.clone())], &node_inputs)?;
    let charge = staged.charge();
    assert_eq!(
        (charge.inputs, charge.nodes, charge.edges, charge.rows),
        (3, 1, 3, 2)
    );
    assert_eq!(charge.bytes, bytes as u64);
    assert_eq!(staged.manifest_digest(), manifest_digest);
    assert!(staged.node() == node);
    Ok(())
}

#[test]
fn repeated_references_and_the_step_count_once() -> TestResult {
    let first = refs(11..13);
    let second: Vec<Typed<'static>> = vec![
        Typed::Native(native(12)),
        Typed::Native(native(13)),
        Typed::Native(native(10)),
    ];
    let staged =
        Records::stage(&context()?, &[item(0, &first), item(0, &second)])?.ok_or("records")?;
    // The step, 11, 12 and 13.
    assert_eq!(staged.charge().inputs, 4);
    assert_eq!(staged.charge().edges, 4);
    Ok(())
}

#[test]
fn a_duplicated_item_input_is_one_resolved_input() -> TestResult {
    let doubled: Vec<Typed<'static>> = vec![Typed::Native(native(11)), Typed::Native(native(11))];
    let staged = Records::stage(&context()?, &[item(0, &doubled)])?.ok_or("records")?;
    assert_eq!(staged.charge().inputs, 2);
    Ok(())
}

#[test]
fn k_is_capped_at_256() -> TestResult {
    let full = refs(11..266);
    let staged = Records::stage(&context()?, &[item(0, &full)])?.ok_or("records")?;
    assert_eq!(staged.charge().inputs, 256);
    let over = refs(11..267);
    assert!(matches!(
        Records::stage(&context()?, &[item(0, &over)]),
        Err(Error::BoundsExceeded)
    ));
    Ok(())
}

#[test]
fn a_decreasing_guest_index_is_refused() -> TestResult {
    let inputs = refs(11..12);
    assert!(matches!(
        Records::stage(&context()?, &[item(2, &inputs), item(1, &inputs)]),
        Err(Error::InvalidBinding)
    ));
    Ok(())
}

#[test]
fn an_input_that_does_not_precede_the_node_is_refused() -> TestResult {
    let late = refs(1_000..1_001);
    assert!(matches!(
        Records::stage(&context()?, &[item(0, &late)]),
        Err(Error::InvalidBinding)
    ));
    Ok(())
}
