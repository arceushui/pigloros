//! The Seal-staged annotation records: the R15.6 charge, `k` dedup and bounds,
//! measured against records built independently through the public codecs.

use pos_core::community_lifecycle::{
    CommunityAnnotationCandidateV1 as Candidate, CommunityAnnotationContextV1 as Context,
    CommunityAnnotationItemV1 as Item, CommunityAnnotationManifestInputV1 as ManifestInput,
    CommunityAnnotationManifestV1 as Manifest, CommunityAnnotationRecordsV1 as Records,
    CommunityContentReferenceV1 as Content, CommunityDigestListV1 as Digests,
    CommunityFactualNodeReferenceV1 as FactualNode, CommunityGraphCountsV1 as Graph,
    CommunityInputIndexV1 as Index, CommunityLifecycleErrorV1 as Error,
    CommunityLocatorProducerV1 as LocatorProducer, CommunityMetadataLocatorV1 as Locator,
    CommunityMetadataSchemaV1 as Schema, CommunityNativeNodeInputV1 as NodeInput,
    CommunityNativeNodeKindV1 as Kind, CommunityNativeNodeReferenceV1 as Reference,
    CommunityNativeNodeV1 as Node, CommunityPassGraphTermsV1 as Terms, CommunityPassKeyV1 as Pass,
    CommunityProtectionSizesV1 as Sizes, CommunityTypedInputRefV1 as Typed,
    CommunityTypedInputRefsV1 as TypedRefs,
};
use pos_core::{ErasureArtifactClassV1, Hash, RecordedDependencyClassV1, TimelineId};

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
) -> Result<(usize, usize, Hash, Reference), Box<dyn std::error::Error>> {
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
        manifest.to_canonical_cbor().len(),
        node.to_canonical_cbor().len(),
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
    let (manifest_len, node_len, manifest_digest, node) =
        oracle(&[(2, inputs.clone())], &node_inputs)?;
    let charge = staged.charge();
    assert_eq!(
        (charge.inputs, charge.nodes, charge.edges, charge.rows),
        (3, 1, 3, 2)
    );
    assert_eq!(charge.bytes, (manifest_len + node_len) as u64);
    // The retained encodings are the records the digests name.
    assert_eq!(staged.manifest_bytes().len(), manifest_len);
    assert_eq!(staged.node_bytes().len(), node_len);
    assert_eq!(
        Manifest::from_canonical_cbor(staged.manifest_bytes())?.digest(),
        staged.manifest_digest()
    );
    assert!(Node::from_canonical_cbor(staged.node_bytes())?.reference() == staged.node());
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

#[test]
fn the_trace_closure_is_the_cat1_the_node_and_one_key() -> TestResult {
    let inputs = refs(11..13);
    let staged = Records::stage(&context()?, &[item(2, &inputs)])?.ok_or("records")?;
    let mut node_inputs = vec![Typed::Native(native(10))];
    node_inputs.extend(inputs.iter().copied());
    let (manifest_len, node_len, _, _) = oracle(&[(2, inputs.clone())], &node_inputs)?;
    let sizes = Sizes::new(pass()?.timeline(), pass()?.generation())?;
    // The node's children: its CAT1, the step and the two inputs.
    let expected = sizes
        .record(manifest_len as u64, 0)
        .plus(sizes.record(node_len as u64, 4))
        .plus(Terms {
            keys: 1,
            ..Terms::default()
        });
    assert_eq!(staged.graph(), expected);
    Ok(())
}

#[test]
fn the_trace_closure_must_fit_every_graph_maximum() -> TestResult {
    let inputs = refs(11..13);
    let staged = Records::stage(&context()?, &[item(2, &inputs)])?.ok_or("records")?;
    let added = staged.graph();
    let base = Graph {
        registrations: 1,
        edges: 1,
        keys: 1,
        maximum_depth: 1,
        registration_bytes: 1,
        artifact_bytes: 1,
    };
    assert!(staged.fits_graph(base));
    // The profile-1 maxima: 4,096 registrations, 8,192 edges, 4,096 keys,
    // depth 4,096, 64 MiB of registrations and 256 MiB of artifacts.
    let cases = [
        (
            Graph {
                registrations: 4_096 - added.registrations,
                ..base
            },
            Graph {
                registrations: 4_097 - added.registrations,
                ..base
            },
        ),
        (
            Graph {
                edges: 8_192 - added.edges,
                ..base
            },
            Graph {
                edges: 8_193 - added.edges,
                ..base
            },
        ),
        (
            Graph {
                keys: 4_096 - added.keys,
                ..base
            },
            Graph {
                keys: 4_097 - added.keys,
                ..base
            },
        ),
        (
            Graph {
                maximum_depth: 4_095,
                ..base
            },
            Graph {
                maximum_depth: 4_096,
                ..base
            },
        ),
        (
            Graph {
                registration_bytes: 67_108_864 - added.registration_bytes,
                ..base
            },
            Graph {
                registration_bytes: 67_108_865 - added.registration_bytes,
                ..base
            },
        ),
        (
            Graph {
                artifact_bytes: 268_435_456 - added.artifact_bytes,
                ..base
            },
            Graph {
                artifact_bytes: 268_435_457 - added.artifact_bytes,
                ..base
            },
        ),
    ];
    for (at_maximum, over) in cases {
        assert!(staged.fits_graph(at_maximum));
        assert!(!staged.fits_graph(over));
    }
    Ok(())
}

#[test]
fn defects_of_the_trusted_input_are_never_a_budget() -> TestResult {
    let inputs = refs(11..12);
    for horizon in [0, u64::MAX] {
        let context = Context {
            evidence_not_after_micros: horizon,
            ..context()?
        };
        assert!(matches!(
            Records::stage(&context, &[item(0, &inputs)]),
            Err(Error::InvalidBinding)
        ));
    }
    assert!(matches!(
        Records::stage(&context()?, &[item(64, &inputs)]),
        Err(Error::InvalidBinding)
    ));
    // The ordering defect comes before the input cap.
    let over = refs(11..267);
    assert!(matches!(
        Records::stage(&context()?, &[item(2, &inputs), item(1, &over)]),
        Err(Error::InvalidBinding)
    ));
    Ok(())
}

#[test]
fn a_cat1_holds_at_most_1024_items() -> TestResult {
    let inputs = refs(11..12);
    let items: Vec<Candidate<'_>> = (0..1_025).map(|_| item(0, &inputs)).collect();
    assert!(Records::stage(&context()?, &items[..1_024])?.is_some());
    assert!(matches!(
        Records::stage(&context()?, &items),
        Err(Error::BoundsExceeded)
    ));
    Ok(())
}

const fn artifact_ref() -> Typed<'static> {
    Typed::Artifact {
        owner_reference: hash(0x50),
        artifact_class: ErasureArtifactClassV1::TimelineReplay,
        artifact_digest: hash(0x51),
        registration_address: hash(0x52),
        source_scope_binding_digest: hash(0x53),
    }
}

const fn metadata_ref() -> Typed<'static> {
    Typed::Metadata {
        schema: Schema::Cmb1,
        locator: Locator {
            timeline: TimelineId::from_ulid(ulid::Ulid::from_bytes([1; 16])),
            generation: [2; 16],
            producer: LocatorProducer::Native(9),
            record_role: 2,
            slot: 3,
        },
        envelope_address: hash(0x54),
        private_record_digest: hash(0x55),
    }
}

const fn factual_ref() -> Typed<'static> {
    Typed::Factual {
        timeline: TimelineId::from_ulid(ulid::Ulid::from_bytes([1; 16])),
        node: FactualNode {
            tick: 1,
            scheduler_position: 0,
            owner_id: "owner",
            output_ordinal: 0,
            schema_id: 1,
            artifact_digest: hash(0x56),
        },
        record_digest: hash(0x57),
    }
}

#[test]
fn only_native_and_artifact_inputs_are_ard1_children_of_the_node() -> TestResult {
    let sizes = Sizes::new(pass()?.timeline(), pass()?.generation())?;
    let native_only = [Typed::Native(native(11))];
    let with_artifact = [Typed::Native(native(11)), artifact_ref()];
    let others = [
        Typed::Native(native(11)),
        artifact_ref(),
        factual_ref(),
        metadata_ref(),
    ];
    // The node's children are its CAT1, the step and each other registered
    // input: modes 1 and 3 are inputs of the node but not ARD1 children.
    for (inputs, children) in [
        (&native_only[..], 3),
        (&with_artifact[..], 4),
        (&others[..], 4),
    ] {
        let staged = Records::stage(&context()?, &[item(0, inputs)])?.ok_or("records")?;
        let expected = sizes
            .record(staged.manifest_bytes().len() as u64, 0)
            .plus(sizes.record(staged.node_bytes().len() as u64, children))
            .plus(Terms {
                keys: 1,
                ..Terms::default()
            });
        assert_eq!(staged.graph(), expected);
    }
    Ok(())
}

#[test]
fn the_last_guest_index_is_admitted() -> TestResult {
    let inputs = refs(11..12);
    assert!(Records::stage(&context()?, &[item(63, &inputs)])?.is_some());
    Ok(())
}
