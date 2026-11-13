//! ADR-129 §2/§4 native graph records at their public seam: CPN1 native
//! nodes with typed input references and input indexes, CIB1 input groups,
//! CIR1 source closures and CGR1 graph roots.
//!
//! Every expected wire is built independently with `ciborium` from the ADR
//! field lists, and every digest from the ADR `H(record)` rule with `blake3`.

use ciborium::value::Value;
use pos_core::community_lifecycle::{
    CommunityContentReferenceV1 as Content, CommunityFactualNodeReferenceV1 as FactualNode,
    CommunityGraphCountsV1 as Counts, CommunityGraphRootInputV1 as RootInput,
    CommunityGraphRootV1 as Root, CommunityInputGroupInputV1 as GroupInput,
    CommunityInputGroupV1 as Group, CommunityInputIndexV1 as Index,
    CommunityLifecycleErrorV1 as Error, CommunityLocatorProducerV1 as Producer,
    CommunityMetadataLocatorV1 as Locator, CommunityMetadataSchemaV1 as Schema,
    CommunityNativeNodeInputV1 as NodeInput, CommunityNativeNodeKindV1 as Kind,
    CommunityNativeNodeReferenceV1 as NativeRef, CommunityNativeNodeReferencesV1 as NativeRefs,
    CommunityNativeNodeV1 as Node, CommunitySourceClosureInputV1 as ClosureInput,
    CommunitySourceClosureV1 as Closure, CommunityTypedInputRefV1 as TypedRef,
    CommunityTypedInputRefsV1 as TypedRefs, MAX_COMMUNITY_DIRECT_INPUTS_V1,
    MAX_COMMUNITY_EXPANDED_INPUTS_V1, MAX_COMMUNITY_GRAPH_ROOT_BYTES_V1,
};
use pos_core::{ErasureArtifactClassV1, Hash, RecordedDependencyClassV1 as Class, TimelineId};

type Fallible<T> = Result<T, Box<dyn std::error::Error>>;
type TestResult = Fallible<()>;

const INCARNATION: [u8; 16] = [7; 16];
const GENERATION: [u8; 16] = [2; 16];
const PRODUCER: u64 = 300;
const NODE: u32 = 3;

const fn hash(byte: u8) -> Hash {
    Hash::from_bytes([byte; 32])
}
const fn timeline(byte: u8) -> TimelineId {
    TimelineId::from_ulid(ulid::Ulid::from_bytes([byte; 16]))
}
fn uint(value: u64) -> Value {
    Value::Integer(value.into())
}
fn bytes(value: &[u8]) -> Value {
    Value::Bytes(value.to_vec())
}
fn text(value: &str) -> Value {
    Value::Text(value.to_owned())
}
fn encode(value: &Value) -> Fallible<Vec<u8>> {
    let mut out = Vec::new();
    ciborium::into_writer(value, &mut out)?;
    Ok(out)
}
fn fields(value: &mut Value) -> Fallible<&mut Vec<Value>> {
    match value {
        Value::Array(values) => Ok(values),
        _ => Err("fixture array expected".into()),
    }
}
fn record_digest(magic: &str, bytes: &[u8]) -> Hash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(format!("PiglorOS.Community.{magic}.v1").as_bytes());
    hasher.update(&[0]);
    hasher.update(bytes);
    Hash::from_bytes(*hasher.finalize().as_bytes())
}

const fn native(producer: u64, node: u32, digest: u8) -> NativeRef {
    NativeRef {
        store_incarnation: INCARNATION,
        producer_ordinal: producer,
        node_ordinal: node,
        node_digest: hash(digest),
    }
}
fn native_value(reference: &NativeRef) -> Value {
    Value::Array(vec![
        bytes(&reference.store_incarnation),
        uint(reference.producer_ordinal),
        uint(u64::from(reference.node_ordinal)),
        bytes(reference.node_digest.as_bytes()),
    ])
}

const fn factual_node() -> FactualNode<'static> {
    FactualNode {
        tick: 5,
        scheduler_position: 1,
        owner_id: "plugin.a",
        output_ordinal: 0,
        schema_id: 9,
        artifact_digest: hash(10),
    }
}
const fn locator() -> Locator {
    Locator {
        timeline: timeline(1),
        generation: GENERATION,
        producer: Producer::Control([6; 16]),
        record_role: 2,
        slot: 300,
    }
}

/// One reference of each variant, in canonical (code-first) order.
const fn refs() -> [TypedRef<'static>; 4] {
    [
        TypedRef::Native(native(9, 0, 11)),
        TypedRef::Factual {
            timeline: timeline(4),
            node: factual_node(),
            record_digest: hash(12),
        },
        TypedRef::Artifact {
            owner_reference: hash(13),
            artifact_class: ErasureArtifactClassV1::ReproManifest,
            artifact_digest: hash(14),
            registration_address: hash(15),
            source_scope_binding_digest: hash(16),
        },
        TypedRef::Metadata {
            schema: Schema::Cmb1,
            locator: locator(),
            envelope_address: hash(17),
            private_record_digest: hash(18),
        },
    ]
}

fn refs_values() -> Fallible<Vec<Value>> {
    let node = encode(&Value::Array(vec![
        uint(5),
        uint(1),
        text("plugin.a"),
        uint(0),
        uint(9),
        bytes(&[10; 32]),
    ]))?;
    let locator = encode(&Value::Array(vec![
        bytes(&[1; 16]),
        bytes(&GENERATION),
        uint(1),
        bytes(&[6; 16]),
        uint(2),
        uint(300),
    ]))?;
    Ok(vec![
        Value::Array(vec![uint(0), native_value(&native(9, 0, 11))]),
        Value::Array(vec![
            uint(1),
            bytes(&[4; 16]),
            bytes(&node),
            bytes(&[12; 32]),
        ]),
        Value::Array(vec![
            uint(2),
            bytes(&[13; 32]),
            uint(1),
            bytes(&[14; 32]),
            bytes(&[15; 32]),
            bytes(&[16; 32]),
        ]),
        Value::Array(vec![
            uint(3),
            bytes(b"CMB1"),
            bytes(&locator),
            bytes(&[17; 32]),
            bytes(&[18; 32]),
        ]),
    ])
}

const fn content(magic: [u8; 4]) -> Content {
    Content {
        record_magic: magic,
        logical_digest: hash(20),
    }
}

const fn node_input(
    kind: Kind,
    class: Class,
    content: Content,
    input_index: Index<'_>,
) -> NodeInput<'_> {
    NodeInput {
        store_incarnation: INCARNATION,
        timeline: timeline(1),
        generation: GENERATION,
        producer_ordinal: PRODUCER,
        node_ordinal: NODE,
        kind,
        content,
        dependency_class: class,
        input_index,
        scope_binding_digest: hash(21),
        authorization_digest: hash(22),
        provenance_digest: hash(23),
        evidence_not_after_micros: 1000,
    }
}

const fn revision_input(index: Index<'_>) -> NodeInput<'_> {
    node_input(
        Kind::StateRevision,
        Class::EndogenousRecomputed,
        content(*b"CSR1"),
        index,
    )
}

fn node_value(kind: u64, magic: &[u8], class: u64, rule: &str, index: Value) -> Value {
    Value::Array(vec![
        bytes(b"CPN1"),
        uint(1),
        bytes(&INCARNATION),
        bytes(&[1; 16]),
        bytes(&GENERATION),
        uint(PRODUCER),
        uint(u64::from(NODE)),
        uint(kind),
        Value::Array(vec![bytes(magic), bytes(&[20; 32])]),
        uint(class),
        Value::Array(vec![text(rule), uint(1)]),
        index,
        bytes(&[21; 32]),
        bytes(&[22; 32]),
        bytes(&[23; 32]),
        uint(1000),
    ])
}

fn direct_node_value() -> Fallible<Value> {
    Ok(node_value(
        3,
        b"CSR1",
        2,
        "pos.community.state-revision",
        Value::Array(vec![uint(1), Value::Array(refs_values()?)]),
    ))
}

fn error_of<T>(result: Result<T, Error>) -> Option<Error> {
    result.err()
}

#[test]
fn node_kinds_have_the_exact_closed_rule_class_and_content_mapping() {
    let expected = [
        (
            Kind::InitialState,
            "initial-state",
            Some(Class::EndogenousRecomputed),
            None,
        ),
        (
            Kind::Observation,
            "observation",
            Some(Class::EndogenousRecomputed),
            None,
        ),
        (
            Kind::InvocationStep,
            "invocation-step",
            Some(Class::EndogenousRecomputed),
            Some(*b"CPI1"),
        ),
        (
            Kind::StateRevision,
            "state-revision",
            Some(Class::EndogenousRecomputed),
            None,
        ),
        (Kind::EventOutput, "event-output", None, None),
        (
            Kind::Annotation,
            "annotation",
            Some(Class::PresentationOnly),
            None,
        ),
        (
            Kind::Measurement,
            "measurement",
            Some(Class::PresentationOnly),
            None,
        ),
        (
            Kind::AdmittedPolicy,
            "admitted-policy",
            Some(Class::FixedPolicy),
            None,
        ),
        (
            Kind::HostProgress,
            "host-progress",
            Some(Class::EndogenousRecomputed),
            None,
        ),
        (Kind::InputIndex, "input-index", None, Some(*b"CIB1")),
    ];
    for (code, (kind, rule, class, magic)) in expected.into_iter().enumerate() {
        assert_eq!(usize::from(kind.code()), code);
        assert_eq!(kind.rule_id(), format!("pos.community.{rule}"));
        assert_eq!(kind.fixed_class(), class);
        assert_eq!(kind.fixed_content(), magic);
    }
}

#[test]
fn direct_node_has_the_exact_wire_digest_and_roundtrips() -> TestResult {
    let refs = refs();
    let node = Node::new(revision_input(Index::Direct(TypedRefs::from_references(
        &refs,
    ))))?;
    let expected = encode(&direct_node_value()?)?;
    assert_eq!(&*node.to_canonical_cbor(), &expected);
    assert_eq!(node.digest(), record_digest("CPN1", &expected));
    let reference = node.reference();
    assert!(reference == native(PRODUCER, NODE, 0).with_digest(node.digest()));
    let decoded = Node::from_canonical_cbor(&expected)?;
    assert!(*decoded.as_input() == *node.as_input());
    assert_eq!(&*decoded.to_canonical_cbor(), &expected);
    let Index::Direct(decoded_refs) = decoded.as_input().input_index else {
        return Err("direct index expected".into());
    };
    assert_eq!(decoded_refs.len(), 4);
    assert!(!decoded_refs.is_empty());
    for (decoded, original) in decoded_refs.iter().zip(refs) {
        assert!(decoded? == original);
    }
    Ok(())
}

trait WithDigest {
    fn with_digest(self, digest: Hash) -> Self;
}
impl WithDigest for NativeRef {
    fn with_digest(mut self, digest: Hash) -> Self {
        self.node_digest = digest;
        self
    }
}

#[test]
fn empty_and_grouped_nodes_have_the_exact_wire() -> TestResult {
    let empty = Node::new(node_input(
        Kind::InitialState,
        Class::EndogenousRecomputed,
        content(*b"CIS1"),
        Index::Empty,
    ))?;
    let expected = encode(&node_value(
        0,
        b"CIS1",
        2,
        "pos.community.initial-state",
        Value::Array(vec![uint(0)]),
    ))?;
    assert_eq!(&*empty.to_canonical_cbor(), &expected);
    assert!(*Node::from_canonical_cbor(&expected)?.as_input() == *empty.as_input());

    let groups = [native(10, 0, 30), native(10, 1, 31)];
    let index = Index::Grouped {
        groups: NativeRefs::from_references(&groups),
        total_leaf_count: 257,
    };
    let grouped = Node::new(node_input(
        Kind::EventOutput,
        Class::ExogenousFrozen,
        content(*b"CES1"),
        index,
    ))?;
    let expected = encode(&node_value(
        4,
        b"CES1",
        0,
        "pos.community.event-output",
        Value::Array(vec![
            uint(2),
            Value::Array(groups.iter().map(native_value).collect()),
            uint(257),
        ]),
    ))?;
    assert_eq!(&*grouped.to_canonical_cbor(), &expected);
    let decoded = Node::from_canonical_cbor(&expected)?;
    assert!(decoded.as_input().input_index == index);
    let Index::Grouped { groups: rows, .. } = decoded.as_input().input_index else {
        return Err("grouped index expected".into());
    };
    assert_eq!(rows.len(), 2);
    assert!(!rows.is_empty());
    assert!(NativeRefs::from_references(&[]).is_empty());
    assert!(NativeRefs::from_references(&groups[..1]) != NativeRefs::from_references(&groups));
    assert!(NativeRefs::from_references(&groups[..1]) != NativeRefs::from_references(&groups[1..]));
    assert!(rows.iter().collect::<Result<Vec<_>, _>>()? == groups);
    Ok(())
}

#[test]
fn group_counts_are_exact_chunks_of_256() {
    let groups: Vec<NativeRef> = (1..=17).map(|producer| native(producer, 0, 40)).collect();
    let check = |count: usize, total: u64| {
        Node::new(node_input(
            Kind::HostProgress,
            Class::EndogenousRecomputed,
            content(*b"CMS1"),
            Index::Grouped {
                groups: NativeRefs::from_references(&groups[..count]),
                total_leaf_count: total,
            },
        ))
        .map(drop)
    };
    assert_eq!(check(2, 512), Ok(()));
    assert_eq!(check(3, 513), Ok(()));
    assert_eq!(check(16, 4096), Ok(()));
    assert_eq!(check(2, 513), Err(Error::InvalidBinding));
    assert_eq!(check(3, 512), Err(Error::InvalidBinding));
    assert_eq!(check(1, 256), Err(Error::BoundsExceeded));
    assert_eq!(check(17, 4097), Err(Error::BoundsExceeded));
    assert_eq!(check(16, u64::MAX), Err(Error::BoundsExceeded));
}

#[test]
fn direct_index_holds_one_to_256_ordered_references() {
    let many: Vec<TypedRef<'static>> = (1..=257)
        .map(|producer| TypedRef::Native(native(producer, 0, 41)))
        .collect();
    let check = |slice: &[TypedRef<'_>]| {
        Node::new(revision_input(Index::Direct(TypedRefs::from_references(
            slice,
        ))))
        .map(drop)
    };
    assert_eq!(check(&many[..1]), Ok(()));
    assert_eq!(check(&many[..MAX_COMMUNITY_DIRECT_INPUTS_V1]), Ok(()));
    assert_eq!(check(&many[..0]), Err(Error::BoundsExceeded));
    assert_eq!(check(&many), Err(Error::BoundsExceeded));
    let refs = refs();
    let duplicate = [refs[2], refs[2]];
    let descending = [refs[1], refs[0]];
    // Code first: Artifact (code 2, six fields) precedes Metadata (code 3,
    // five fields) although Metadata's whole encoding sorts first.
    let code_first = [refs[2], refs[3]];
    let encoding_first = [refs[3], refs[2]];
    assert_eq!(check(&code_first), Ok(()));
    assert_eq!(check(&duplicate), Err(Error::InvalidBinding));
    assert_eq!(check(&descending), Err(Error::InvalidBinding));
    assert_eq!(check(&encoding_first), Err(Error::InvalidBinding));
    assert!(TypedRefs::from_references(&refs[..1]) != TypedRefs::from_references(&refs[..2]));
    assert!(TypedRefs::from_references(&refs[..1]) != TypedRefs::from_references(&refs[1..2]));
    let ordered = [
        TypedRef::Native(native(5, 0, 1)),
        TypedRef::Native(native(5, 0, 2)),
    ];
    assert_eq!(check(&ordered), Ok(()));
}

#[test]
fn native_inputs_must_be_earlier_in_the_same_incarnation() {
    let check = |reference: NativeRef| {
        let refs = [TypedRef::Native(reference)];
        Node::new(revision_input(Index::Direct(TypedRefs::from_references(
            &refs,
        ))))
        .map(drop)
    };
    assert_eq!(check(native(PRODUCER, NODE - 1, 1)), Ok(()));
    assert_eq!(check(native(PRODUCER - 1, u32::MAX, 1)), Ok(()));
    assert_eq!(check(native(PRODUCER, NODE, 1)), Err(Error::InvalidBinding));
    assert_eq!(
        check(native(PRODUCER, NODE + 1, 1)),
        Err(Error::InvalidBinding)
    );
    assert_eq!(
        check(native(PRODUCER + 1, 0, 1)),
        Err(Error::InvalidBinding)
    );
    let foreign = NativeRef {
        store_incarnation: [8; 16],
        ..native(1, 0, 1)
    };
    assert_eq!(check(foreign), Err(Error::InvalidBinding));
    let groups = [native(PRODUCER, NODE, 1), native(PRODUCER + 1, 0, 1)];
    let grouped = Node::new(node_input(
        Kind::HostProgress,
        Class::EndogenousRecomputed,
        content(*b"CMS1"),
        Index::Grouped {
            groups: NativeRefs::from_references(&groups),
            total_leaf_count: 300,
        },
    ));
    assert_eq!(error_of(grouped), Some(Error::InvalidBinding));
    let foreign_groups = [
        native(1, 0, 1),
        NativeRef {
            store_incarnation: [8; 16],
            ..native(2, 0, 1)
        },
    ];
    let grouped = Node::new(node_input(
        Kind::HostProgress,
        Class::EndogenousRecomputed,
        content(*b"CMS1"),
        Index::Grouped {
            groups: NativeRefs::from_references(&foreign_groups),
            total_leaf_count: 300,
        },
    ));
    assert_eq!(error_of(grouped), Some(Error::InvalidBinding));
}

fn check_ref(reference: TypedRef<'_>) -> Result<(), Error> {
    let refs = [reference];
    Node::new(revision_input(Index::Direct(TypedRefs::from_references(
        &refs,
    ))))
    .map(drop)
}

const fn factual_with(node: FactualNode<'_>, record_digest: Hash) -> TypedRef<'_> {
    TypedRef::Factual {
        timeline: timeline(4),
        node,
        record_digest,
    }
}

#[test]
fn native_and_factual_reference_fields_are_validated() {
    for reference in refs() {
        assert_eq!(check_ref(reference), Ok(()));
    }
    let invalid = [
        TypedRef::Native(NativeRef {
            store_incarnation: [0; 16],
            ..native(1, 0, 1)
        }),
        TypedRef::Native(NativeRef {
            producer_ordinal: 0,
            ..native(1, 0, 1)
        }),
        TypedRef::Native(native(1, 0, 0)),
        TypedRef::Factual {
            timeline: TimelineId::from_ulid(ulid::Ulid::from_bytes([0; 16])),
            node: factual_node(),
            record_digest: hash(1),
        },
        factual_with(
            FactualNode {
                schema_id: 0,
                ..factual_node()
            },
            hash(1),
        ),
        factual_with(
            FactualNode {
                owner_id: "",
                ..factual_node()
            },
            hash(1),
        ),
        factual_with(
            FactualNode {
                artifact_digest: Hash::zero(),
                ..factual_node()
            },
            hash(1),
        ),
        factual_with(factual_node(), Hash::zero()),
    ];
    for reference in invalid {
        assert_eq!(check_ref(reference), Err(Error::InvalidBinding));
    }
    let longest = "o".repeat(128);
    let too_long = "o".repeat(129);
    for (owner, expected) in [(&longest, Ok(())), (&too_long, Err(Error::InvalidBinding))] {
        let node = FactualNode {
            owner_id: owner,
            ..factual_node()
        };
        assert_eq!(check_ref(factual_with(node, hash(1))), expected);
    }
}

#[test]
fn artifact_and_metadata_reference_fields_are_validated() {
    for zero in 0..4 {
        let mut digests = [hash(1); 4];
        digests[zero] = Hash::zero();
        let reference = TypedRef::Artifact {
            owner_reference: digests[0],
            artifact_class: ErasureArtifactClassV1::TimelineReplay,
            artifact_digest: digests[1],
            registration_address: digests[2],
            source_scope_binding_digest: digests[3],
        };
        assert_eq!(check_ref(reference), Err(Error::InvalidBinding));
    }
    let metadata = |schema, locator, address, record| TypedRef::Metadata {
        schema,
        locator,
        envelope_address: address,
        private_record_digest: record,
    };
    for schema in [Schema::Cdp1, Schema::Cnt1, Schema::Cmb1, Schema::Cms1] {
        assert_eq!(
            check_ref(metadata(schema, locator(), hash(1), hash(2))),
            Ok(())
        );
    }
    for schema in [Schema::Csi1, Schema::Cgr1, Schema::Csh1] {
        assert_eq!(
            check_ref(metadata(schema, locator(), hash(1), hash(2))),
            Err(Error::InvalidBinding)
        );
    }
    let native_locator = Locator {
        producer: Producer::Native(4),
        ..locator()
    };
    assert_eq!(
        check_ref(metadata(Schema::Cms1, native_locator, hash(1), hash(2))),
        Ok(())
    );
    for producer in [Producer::Native(0), Producer::Control([0; 16])] {
        let bad = Locator {
            producer,
            ..locator()
        };
        assert_eq!(
            check_ref(metadata(Schema::Cms1, bad, hash(1), hash(2))),
            Err(Error::InvalidBinding)
        );
    }
    let bad = Locator {
        generation: [0; 16],
        ..locator()
    };
    assert_eq!(
        check_ref(metadata(Schema::Cms1, bad, hash(1), hash(2))),
        Err(Error::InvalidBinding)
    );
    for (address, record) in [(Hash::zero(), hash(2)), (hash(1), Hash::zero())] {
        assert_eq!(
            check_ref(metadata(Schema::Cms1, locator(), address, record)),
            Err(Error::InvalidBinding)
        );
    }
}

#[test]
fn node_identities_and_horizon_are_validated() {
    let refs = refs();
    let base = revision_input(Index::Direct(TypedRefs::from_references(&refs)));
    let check = |input: NodeInput<'_>| Node::new(input).map(drop);
    assert_eq!(check(base), Ok(()));
    let mut invalid = vec![
        NodeInput {
            store_incarnation: [0; 16],
            ..base
        },
        NodeInput {
            generation: [0; 16],
            ..base
        },
        NodeInput {
            producer_ordinal: 0,
            ..base
        },
        NodeInput {
            content: content(*b"CSr1"),
            ..base
        },
        NodeInput {
            content: Content {
                record_magic: *b"CSR1",
                logical_digest: Hash::zero(),
            },
            ..base
        },
    ];
    for digest in 0..3 {
        let mut input = base;
        *[
            &mut input.scope_binding_digest,
            &mut input.authorization_digest,
            &mut input.provenance_digest,
        ][digest] = Hash::zero();
        invalid.push(input);
    }
    for input in invalid {
        assert_eq!(check(input), Err(Error::InvalidBinding));
    }
    // With no inputs, only the node's own identities can refuse it.
    let empty = NodeInput {
        input_index: Index::Empty,
        ..base
    };
    assert_eq!(check(empty), Ok(()));
    let unidentified = [
        NodeInput {
            store_incarnation: [0; 16],
            ..empty
        },
        NodeInput {
            producer_ordinal: 0,
            ..empty
        },
    ];
    for input in unidentified {
        assert_eq!(check(input), Err(Error::InvalidBinding));
    }
    for horizon in [0, u64::MAX / 2 + 1] {
        let input = NodeInput {
            evidence_not_after_micros: horizon,
            ..base
        };
        assert_eq!(check(input), Err(Error::BoundsExceeded));
    }
    let input = NodeInput {
        evidence_not_after_micros: u64::MAX / 2,
        ..base
    };
    assert_eq!(check(input), Ok(()));
}

#[test]
fn node_kind_fixes_class_content_and_index_form() {
    let refs = refs();
    let direct = Index::Direct(TypedRefs::from_references(&refs));
    let check = |kind, class, magic, index| {
        Node::new(node_input(kind, class, content(magic), index)).map(drop)
    };
    let invalid = [
        (Kind::StateRevision, Class::FixedPolicy, *b"CSR1", direct),
        (
            Kind::InvocationStep,
            Class::EndogenousRecomputed,
            *b"CPJ1",
            direct,
        ),
        (
            Kind::InputIndex,
            Class::PresentationOnly,
            *b"CIB1",
            Index::Empty,
        ),
        (Kind::InputIndex, Class::PresentationOnly, *b"CIX1", direct),
        (
            Kind::Annotation,
            Class::EndogenousRecomputed,
            *b"CAT1",
            direct,
        ),
        (
            Kind::AdmittedPolicy,
            Class::EndogenousRecomputed,
            *b"CDP1",
            direct,
        ),
    ];
    for (kind, class, magic, index) in invalid {
        assert_eq!(check(kind, class, magic, index), Err(Error::InvalidBinding));
    }
    let valid = [
        (Kind::InvocationStep, Class::EndogenousRecomputed, *b"CPI1"),
        (Kind::InputIndex, Class::PresentationOnly, *b"CIB1"),
        (Kind::InputIndex, Class::FixedPolicy, *b"CIB1"),
        (Kind::Measurement, Class::PresentationOnly, *b"CIV1"),
        (Kind::AdmittedPolicy, Class::FixedPolicy, *b"CDP1"),
        (Kind::Observation, Class::EndogenousRecomputed, *b"COV1"),
    ];
    for (kind, class, magic) in valid {
        assert_eq!(check(kind, class, magic, direct), Ok(()));
    }
}

fn decode_with(index: usize, value: Value) -> Fallible<Option<Error>> {
    let mut node = direct_node_value()?;
    fields(&mut node)?[index] = value;
    Ok(error_of(Node::from_canonical_cbor(&encode(&node)?)))
}

fn index_with_ref(position: usize, edit: impl FnOnce(&mut Value) -> TestResult) -> Fallible<Value> {
    let mut refs = refs_values()?;
    edit(&mut refs[position])?;
    Ok(Value::Array(vec![uint(1), Value::Array(refs)]))
}

fn locator_value(kind: Value, id: Value, role: u64, extra: bool) -> Value {
    let mut values = vec![
        bytes(&[1; 16]),
        bytes(&GENERATION),
        kind,
        id,
        uint(role),
        uint(1),
    ];
    if extra {
        values.push(uint(0));
    }
    Value::Array(values)
}

fn index_with_locator(locator: &[u8]) -> Fallible<Value> {
    index_with_ref(3, |reference| {
        fields(reference)?[2] = bytes(locator);
        Ok(())
    })
}

#[test]
fn node_decoding_rejects_malformed_header_rule_and_index() -> TestResult {
    let cases = [
        (1, uint(2), Error::UnsupportedVersion),
        (6, uint(u64::from(u32::MAX) + 1), Error::BoundsExceeded),
        (7, uint(10), Error::InvalidEncoding),
        (9, uint(5), Error::InvalidEncoding),
        (
            10,
            Value::Array(vec![text("pos.community.state-revisions"), uint(1)]),
            Error::InvalidBinding,
        ),
        (
            10,
            Value::Array(vec![text("pos.community.state-revision"), uint(2)]),
            Error::InvalidBinding,
        ),
        (
            10,
            Value::Array(vec![text(&"x".repeat(65)), uint(1)]),
            Error::BoundsExceeded,
        ),
        (11, Value::Array(vec![uint(3)]), Error::InvalidEncoding),
        (
            11,
            Value::Array(vec![uint(0), uint(0)]),
            Error::InvalidEncoding,
        ),
        (
            11,
            Value::Array(vec![
                uint(1),
                Value::Array(
                    (1..=257)
                        .map(|p| Value::Array(vec![uint(0), native_value(&native(p, 0, 1))]))
                        .collect(),
                ),
            ]),
            Error::BoundsExceeded,
        ),
        (
            11,
            Value::Array(vec![
                uint(2),
                Value::Array((1..=17).map(|p| native_value(&native(p, 0, 1))).collect()),
                uint(4097),
            ]),
            Error::BoundsExceeded,
        ),
    ];
    for (index, value, error) in cases {
        assert_eq!(decode_with(index, value)?, Some(error));
    }
    let mut trailing = encode(&direct_node_value()?)?;
    trailing.push(0);
    assert_eq!(
        error_of(Node::from_canonical_cbor(&trailing)),
        Some(Error::InvalidEncoding)
    );
    assert_eq!(
        error_of(Node::from_canonical_cbor(&vec![0; 1_048_577])),
        Some(Error::BoundsExceeded)
    );
    Ok(())
}

#[test]
fn node_decoding_rejects_malformed_references_and_locators() -> TestResult {
    let unknown_tag = index_with_ref(0, |reference| {
        fields(reference)?[0] = uint(4);
        Ok(())
    })?;
    let wide_node = index_with_ref(0, |reference| {
        fields(reference)?[1] = Value::Array(vec![
            bytes(&INCARNATION),
            uint(9),
            uint(u64::from(u32::MAX) + 1),
            bytes(&[11; 32]),
        ]);
        Ok(())
    })?;
    let unknown_class = index_with_ref(2, |reference| {
        fields(reference)?[2] = uint(7);
        Ok(())
    })?;
    let unknown_schema = index_with_ref(3, |reference| {
        fields(reference)?[1] = bytes(b"ZZZ1");
        Ok(())
    })?;
    let mut trailing = encode(&locator_value(uint(0), uint(1), 1, false))?;
    trailing.push(0);
    let cases = [
        (unknown_tag, Error::InvalidEncoding),
        (wide_node, Error::BoundsExceeded),
        (unknown_class, Error::InvalidEncoding),
        (unknown_schema, Error::InvalidEncoding),
        (
            index_with_locator(&encode(&locator_value(uint(2), uint(1), 1, false))?)?,
            Error::InvalidEncoding,
        ),
        (
            index_with_locator(&encode(&locator_value(uint(0), uint(1), 65_536, false))?)?,
            Error::BoundsExceeded,
        ),
        (
            index_with_locator(&encode(&locator_value(uint(0), uint(1), 1, true))?)?,
            Error::InvalidEncoding,
        ),
        (index_with_locator(&trailing)?, Error::InvalidEncoding),
    ];
    for (index, error) in cases {
        assert_eq!(decode_with(11, index)?, Some(error));
    }
    // The widest valid locator is exactly 59 bytes; 60 bytes are refused.
    let widest = encode(&Value::Array(vec![
        bytes(&[1; 16]),
        bytes(&GENERATION),
        uint(1),
        bytes(&[6; 16]),
        uint(65_535),
        uint(65_535),
    ]))?;
    assert_eq!(widest.len(), 59);
    assert_eq!(decode_with(11, index_with_locator(&widest)?)?, None);
    assert_eq!(
        decode_with(11, index_with_locator(&[0x86; 60])?)?,
        Some(Error::BoundsExceeded)
    );
    let native_locator = index_with_locator(&encode(&locator_value(uint(0), uint(4), 1, false))?)?;
    assert_eq!(decode_with(11, native_locator.clone())?, None);
    let mut node = direct_node_value()?;
    fields(&mut node)?[11] = native_locator;
    let bytes = encode(&node)?;
    assert_eq!(
        &*Node::from_canonical_cbor(&bytes)?.to_canonical_cbor(),
        &bytes
    );
    Ok(())
}

#[test]
fn input_group_has_the_exact_wire_and_bounds() -> TestResult {
    let refs = refs();
    let input = GroupInput {
        timeline: timeline(1),
        generation: GENERATION,
        consumer_content: content(*b"CSR1"),
        leaves: TypedRefs::from_references(&refs),
    };
    let group = Group::new(input)?;
    let expected = encode(&Value::Array(vec![
        bytes(b"CIB1"),
        uint(1),
        bytes(&[1; 16]),
        bytes(&GENERATION),
        Value::Array(vec![bytes(b"CSR1"), bytes(&[20; 32])]),
        Value::Array(refs_values()?),
    ]))?;
    assert_eq!(&*group.to_canonical_cbor(), &expected);
    assert_eq!(group.digest(), record_digest("CIB1", &expected));
    let decoded = Group::from_canonical_cbor(&expected)?;
    assert!(*decoded.as_input() == input);

    let many: Vec<TypedRef<'static>> = (1..=257)
        .map(|producer| TypedRef::Native(native(producer, 0, 1)))
        .collect();
    let with = |leaves: &[TypedRef<'_>]| {
        Group::new(GroupInput {
            leaves: TypedRefs::from_references(leaves),
            ..input
        })
        .map(|group| group.to_canonical_cbor().to_vec())
    };
    let full = with(&many[..256])?;
    assert_eq!(Group::from_canonical_cbor(&full).map(drop), Ok(()));
    assert_eq!(error_of(with(&many)), Some(Error::BoundsExceeded));
    assert_eq!(error_of(with(&[])), Some(Error::BoundsExceeded));
    assert_eq!(
        error_of(Group::new(GroupInput {
            consumer_content: content(*b"csr1"),
            ..input
        })),
        Some(Error::InvalidBinding)
    );
    assert_eq!(
        error_of(Group::new(GroupInput {
            timeline: TimelineId::from_ulid(ulid::Ulid::from_bytes([0; 16])),
            ..input
        })),
        Some(Error::InvalidBinding)
    );
    let mut trailing = expected.clone();
    trailing.push(0);
    assert_eq!(
        error_of(Group::from_canonical_cbor(&trailing)),
        Some(Error::InvalidEncoding)
    );
    assert_eq!(
        error_of(Group::from_canonical_cbor(&vec![0; 65_537])),
        Some(Error::BoundsExceeded)
    );
    Ok(())
}

#[test]
fn source_closure_has_the_exact_wire_and_bounds() -> TestResult {
    let refs = refs();
    let input = ClosureInput {
        timeline: timeline(1),
        generation: GENERATION,
        inputs: TypedRefs::from_references(&refs),
        source_scope_union_digest: hash(24),
    };
    let closure = Closure::new(input)?;
    let expected = encode(&Value::Array(vec![
        bytes(b"CIR1"),
        uint(1),
        bytes(&[1; 16]),
        bytes(&GENERATION),
        Value::Array(refs_values()?),
        bytes(&[24; 32]),
    ]))?;
    assert_eq!(&*closure.to_canonical_cbor(), &expected);
    assert_eq!(closure.digest(), record_digest("CIR1", &expected));
    assert!(*Closure::from_canonical_cbor(&expected)?.as_input() == input);

    let many: Vec<TypedRef<'static>> = (1..=4097)
        .map(|producer| TypedRef::Native(native(producer, 0, 1)))
        .collect();
    let with = |inputs: &[TypedRef<'_>]| {
        Closure::new(ClosureInput {
            inputs: TypedRefs::from_references(inputs),
            ..input
        })
        .map(|closure| closure.to_canonical_cbor().to_vec())
    };
    let empty = with(&[])?;
    assert!(Closure::from_canonical_cbor(&empty)?
        .as_input()
        .inputs
        .is_empty());
    let full = with(&many[..MAX_COMMUNITY_EXPANDED_INPUTS_V1])?;
    assert_eq!(
        Closure::from_canonical_cbor(&full)?.as_input().inputs.len(),
        MAX_COMMUNITY_EXPANDED_INPUTS_V1
    );
    assert_eq!(error_of(with(&many)), Some(Error::BoundsExceeded));
    let over = Value::Array(vec![
        bytes(b"CIR1"),
        uint(1),
        bytes(&[1; 16]),
        bytes(&GENERATION),
        Value::Array(
            (1..=4097)
                .map(|producer| Value::Array(vec![uint(0), native_value(&native(producer, 0, 1))]))
                .collect(),
        ),
        bytes(&[24; 32]),
    ]);
    assert_eq!(
        error_of(Closure::from_canonical_cbor(&encode(&over)?)),
        Some(Error::BoundsExceeded)
    );
    assert_eq!(
        error_of(Closure::new(ClosureInput {
            source_scope_union_digest: Hash::zero(),
            ..input
        })),
        Some(Error::InvalidBinding)
    );
    assert_eq!(
        error_of(Closure::new(ClosureInput {
            generation: [0; 16],
            ..input
        })),
        Some(Error::InvalidBinding)
    );
    let mut trailing = expected;
    trailing.push(0);
    assert_eq!(
        error_of(Closure::from_canonical_cbor(&trailing)),
        Some(Error::InvalidEncoding)
    );
    Ok(())
}

const fn counts() -> Counts {
    Counts {
        registrations: 4096,
        edges: 8192,
        keys: 4096,
        maximum_depth: 4096,
        registration_bytes: 67_108_864,
        artifact_bytes: 268_435_456,
    }
}

const fn root_input(roots: NativeRefs<'_>, graph_counts: Counts) -> RootInput<'_> {
    RootInput {
        store_incarnation: INCARNATION,
        timeline: timeline(1),
        generation: GENERATION,
        profile_digest: hash(25),
        selected_head_digest: hash(26),
        roots,
        graph_counts,
        evidence_not_after_micros: 2000,
    }
}

#[test]
fn graph_root_has_the_exact_wire_digest_and_roundtrips() -> TestResult {
    let roots = [native(1, 0, 50), native(1, 1, 51), native(2, 0, 52)];
    let input = root_input(NativeRefs::from_references(&roots), counts());
    let root = Root::new(input)?;
    let expected = encode(&Value::Array(vec![
        bytes(b"CGR1"),
        uint(1),
        bytes(&INCARNATION),
        bytes(&[1; 16]),
        bytes(&GENERATION),
        bytes(&[25; 32]),
        bytes(&[26; 32]),
        Value::Array(roots.iter().map(native_value).collect()),
        Value::Array(
            [4096, 8192, 4096, 4096, 67_108_864, 268_435_456]
                .into_iter()
                .map(uint)
                .collect(),
        ),
        uint(2000),
    ]))?;
    assert_eq!(&*root.to_canonical_cbor(), &expected);
    assert_eq!(root.digest(), record_digest("CGR1", &expected));
    let decoded = Root::from_canonical_cbor(&expected)?;
    assert!(*decoded.as_input() == input);
    assert!(
        decoded
            .as_input()
            .roots
            .iter()
            .collect::<Result<Vec<_>, _>>()?
            == roots
    );
    Ok(())
}

#[test]
fn graph_root_counts_are_bounded_by_the_profile_maxima() {
    let roots = [native(1, 0, 50)];
    let refs = NativeRefs::from_references(&roots);
    assert_eq!(Root::new(root_input(refs, counts())).map(drop), Ok(()));
    let zero = Counts {
        registrations: 0,
        edges: 0,
        keys: 0,
        maximum_depth: 0,
        registration_bytes: 0,
        artifact_bytes: 0,
    };
    assert_eq!(Root::new(root_input(refs, zero)).map(drop), Ok(()));
    let over = [
        Counts {
            registrations: 4097,
            ..counts()
        },
        Counts {
            edges: 8193,
            ..counts()
        },
        Counts {
            keys: 4097,
            ..counts()
        },
        Counts {
            maximum_depth: 4097,
            ..counts()
        },
        Counts {
            registration_bytes: 67_108_865,
            ..counts()
        },
        Counts {
            artifact_bytes: 268_435_457,
            ..counts()
        },
    ];
    for counts in over {
        assert_eq!(
            error_of(Root::new(root_input(refs, counts))),
            Some(Error::BoundsExceeded)
        );
    }
}

#[test]
fn graph_root_rejects_invalid_roots_and_identities() -> TestResult {
    let roots = [native(1, 0, 50), native(2, 0, 51)];
    let refs = NativeRefs::from_references(&roots);
    let base = root_input(refs, counts());
    let invalid = [
        RootInput {
            store_incarnation: [0; 16],
            ..base
        },
        RootInput {
            generation: [0; 16],
            ..base
        },
        RootInput {
            profile_digest: Hash::zero(),
            ..base
        },
        RootInput {
            selected_head_digest: Hash::zero(),
            ..base
        },
    ];
    for input in invalid {
        assert_eq!(error_of(Root::new(input)), Some(Error::InvalidBinding));
    }
    let foreign = [NativeRef {
        store_incarnation: [8; 16],
        ..native(1, 0, 50)
    }];
    let duplicate = [native(1, 0, 50), native(1, 0, 50)];
    let descending = [native(2, 0, 50), native(1, 0, 50)];
    let zero_digest = [native(1, 0, 0)];
    for roots in [
        &foreign[..],
        &duplicate[..],
        &descending[..],
        &zero_digest[..],
    ] {
        assert_eq!(
            error_of(Root::new(root_input(
                NativeRefs::from_references(roots),
                counts()
            ))),
            Some(Error::InvalidBinding)
        );
    }
    assert_eq!(
        error_of(Root::new(root_input(
            NativeRefs::from_references(&[]),
            counts()
        ))),
        Some(Error::BoundsExceeded)
    );
    for horizon in [0, u64::MAX / 2 + 1] {
        assert_eq!(
            error_of(Root::new(RootInput {
                evidence_not_after_micros: horizon,
                ..base
            })),
            Some(Error::BoundsExceeded)
        );
    }
    // A root with a producer in 24..=255 is 1 + 17 + 2 + 1 + 34 = 55 bytes;
    // from 256 it is 56 bytes. The other fields, the three-byte roots head,
    // counts and horizon take 155 bytes, so 27 short and 1141 long roots are
    // exactly 65,536 bytes and one more root exceeds the bound.
    let many: Vec<NativeRef> = (24..=50)
        .chain(256..=256 + 1141)
        .map(|producer| native(producer, 0, 50))
        .collect();
    let exact = Root::new(root_input(
        NativeRefs::from_references(&many[..many.len() - 1]),
        counts(),
    ))?;
    let bytes = exact.to_canonical_cbor();
    assert_eq!(bytes.len(), MAX_COMMUNITY_GRAPH_ROOT_BYTES_V1);
    assert_eq!(Root::from_canonical_cbor(&bytes).map(drop), Ok(()));
    assert_eq!(
        error_of(Root::new(root_input(
            NativeRefs::from_references(&many),
            counts()
        ))),
        Some(Error::BoundsExceeded)
    );
    let mut trailing = Root::new(base)?.to_canonical_cbor().to_vec();
    trailing.push(0);
    assert_eq!(
        error_of(Root::from_canonical_cbor(&trailing)),
        Some(Error::InvalidEncoding)
    );
    assert_eq!(
        error_of(Root::from_canonical_cbor(&vec![0; 65_537])),
        Some(Error::BoundsExceeded)
    );
    Ok(())
}
