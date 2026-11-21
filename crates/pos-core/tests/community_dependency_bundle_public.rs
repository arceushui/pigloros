//! Independent CPD1 wire oracles, not native closure or count evidence.

use ciborium::value::Value;
use pos_core::community_lifecycle::{
    CommunityDependencyBundleInputV1 as Input, CommunityDependencyBundleV1 as Bundle,
    CommunityDigestListV1 as Digests, CommunityEvidenceRootsV1 as Roots,
    CommunityFactualBindingV1 as Factual, CommunityGraphCountsV1 as GraphCounts,
    CommunityLifecycleErrorV1 as Error, CommunityPassKeyV1 as Pass,
    CommunitySharedCountsV1 as SharedCounts, MAX_COMMUNITY_DEPENDENCY_BUNDLE_BYTES_V1,
    MAX_COMMUNITY_REQUIRED_NODES_V1,
};
use pos_core::{Hash, TimelineId};

type Fallible<T> = Result<T, Box<dyn std::error::Error>>;
type TestResult = Fallible<()>;

const GRAPH_MAXIMA: [u64; 6] = [4096, 8192, 4096, 4096, 67_108_864, 268_435_456];

const fn hash(byte: u8) -> Hash {
    Hash::from_bytes([byte; 32])
}
fn uint(value: u64) -> Value {
    Value::Integer(value.into())
}
fn bytes(value: &[u8]) -> Value {
    Value::Bytes(value.to_vec())
}
fn encode(value: &Value) -> Fallible<Vec<u8>> {
    let mut out = Vec::new();
    ciborium::into_writer(value, &mut out)?;
    Ok(out)
}
fn fields(value: &mut Value) -> Fallible<&mut Vec<Value>> {
    match value {
        Value::Array(values) => Ok(values),
        _ => Err("fixture is not an array".into()),
    }
}
fn pass_value() -> Value {
    Value::Array(vec![
        bytes(b"CPK1"),
        uint(1),
        bytes(&[1; 16]),
        bytes(&[2; 16]),
        uint(3),
    ])
}
const fn graph_counts(values: [u64; 6]) -> GraphCounts {
    GraphCounts {
        registrations: values[0],
        edges: values[1],
        keys: values[2],
        maximum_depth: values[3],
        registration_bytes: values[4],
        artifact_bytes: values[5],
    }
}
fn input(nodes: &[Hash], factual: bool, roots: Roots) -> Fallible<Input<'_>> {
    Ok(Input {
        pass_key: Pass::new(
            TimelineId::from_ulid(ulid::Ulid::from_bytes([1; 16])),
            [2; 16],
            3,
        )?,
        native_producer_ordinal: 4,
        graph_root_digest: hash(5),
        factual_binding: factual.then_some(Factual {
            tick_bridge_digest: hash(6),
            factual_declaration_digest: hash(7),
        }),
        required_node_digests: Digests::from_digests(nodes),
        optional_evidence_roots: roots,
        shared_counts: SharedCounts {
            nodes: 10,
            edges: 11,
            declared_inputs: 12,
            encoded_record_bytes: u64::MAX,
        },
        graph_counts: graph_counts([13, 14, 15, 16, 17, 18]),
        evidence_not_after_micros: 19,
    })
}
fn root_rows(roots: Roots) -> Value {
    Value::Array(
        [(1, roots.presentation_trace), (2, roots.replay_recording)]
            .into_iter()
            .filter_map(|(role, root)| {
                root.map(|root| Value::Array(vec![uint(role), bytes(root.as_bytes())]))
            })
            .collect(),
    )
}
fn fixture(nodes: &[Hash], factual: bool, roots: Roots) -> Fallible<Value> {
    let optional = |byte: u8| {
        if factual {
            bytes(&[byte; 32])
        } else {
            Value::Null
        }
    };
    Ok(Value::Array(vec![
        bytes(b"CPD1"),
        uint(1),
        bytes(&encode(&pass_value())?),
        uint(4),
        bytes(&[5; 32]),
        optional(6),
        optional(7),
        Value::Array(nodes.iter().map(|hash| bytes(hash.as_bytes())).collect()),
        root_rows(roots),
        Value::Array([10, 11, 12, u64::MAX].into_iter().map(uint).collect()),
        Value::Array((13..=18).map(uint).collect()),
        uint(19),
    ]))
}
fn decode(value: &Value) -> Fallible<Option<Error>> {
    let encoded = encode(value)?;
    Ok(Bundle::from_canonical_cbor(&encoded).err())
}
const ROOT_FORMS: [Roots; 4] = [
    Roots {
        presentation_trace: None,
        replay_recording: None,
    },
    Roots {
        presentation_trace: Some(hash(8)),
        replay_recording: None,
    },
    Roots {
        presentation_trace: None,
        replay_recording: Some(hash(9)),
    },
    Roots {
        presentation_trace: Some(hash(8)),
        replay_recording: Some(hash(9)),
    },
];

#[test]
fn bundle_has_exact_twelve_fields_for_every_factual_and_root_form() -> TestResult {
    let nodes = [hash(31), hash(30)];
    for factual in [false, true] {
        for roots in ROOT_FORMS {
            let input = input(&nodes, factual, roots)?;
            let bundle = Bundle::new(input)?;
            let expected = encode(&fixture(&nodes, factual, roots)?)?;
            assert_eq!(&*bundle.to_canonical_cbor(), &expected);
            let decoded = Bundle::from_canonical_cbor(&expected)?;
            assert!(*decoded.as_input() == input);
            assert_eq!(
                decoded
                    .as_input()
                    .required_node_digests
                    .iter()
                    .collect::<Vec<_>>(),
                nodes
            );
            let mut preimage = b"PiglorOS.Community.CPD1.v1\0".to_vec();
            preimage.extend_from_slice(&expected);
            assert_eq!(
                bundle.digest(),
                Hash::from_bytes(*blake3::hash(&preimage).as_bytes())
            );
        }
    }
    Ok(())
}

#[test]
fn required_node_list_bound_is_exact_and_rows_are_distinct_nonzero() -> TestResult {
    assert_eq!(MAX_COMMUNITY_REQUIRED_NODES_V1, 4096);
    let distinct: Vec<Hash> = (0..4097_u32)
        .map(|index| {
            let mut digest = [0xaa; 32];
            digest[..4].copy_from_slice(&index.to_be_bytes());
            Hash::from_bytes(digest)
        })
        .collect();
    let repeated = [hash(1), hash(2), hash(1)];
    let zero = [hash(1), Hash::zero()];
    for (nodes, expected) in [
        (&[][..], None),
        (&distinct[..4096], None),
        (&distinct[..], Some(Error::BoundsExceeded)),
        (&repeated[..], Some(Error::InvalidBinding)),
        (&zero[..], Some(Error::InvalidBinding)),
    ] {
        let roots = ROOT_FORMS[0];
        assert_eq!(Bundle::new(input(nodes, false, roots)?).err(), expected);
        let encoded = encode(&fixture(nodes, false, roots)?)?;
        assert!(encoded.len() <= MAX_COMMUNITY_DEPENDENCY_BUNDLE_BYTES_V1);
        assert_eq!(Bundle::from_canonical_cbor(&encoded).err(), expected);
        if expected.is_none() {
            assert_eq!(
                &*Bundle::new(input(nodes, false, roots)?)?.to_canonical_cbor(),
                &encoded
            );
        }
    }
    Ok(())
}

#[test]
fn bundle_rejects_zero_ordinal_and_every_zero_identity() -> TestResult {
    for index in 0..6 {
        let mut input = input(&[], true, ROOT_FORMS[3])?;
        let mut factual = input.factual_binding.ok_or("factual")?;
        match index {
            0 => input.native_producer_ordinal = 0,
            1 => input.graph_root_digest = Hash::zero(),
            2 => factual.tick_bridge_digest = Hash::zero(),
            3 => factual.factual_declaration_digest = Hash::zero(),
            4 => input.optional_evidence_roots.presentation_trace = Some(Hash::zero()),
            _ => input.optional_evidence_roots.replay_recording = Some(Hash::zero()),
        }
        input.factual_binding = Some(factual);
        assert_eq!(Bundle::new(input).err(), Some(Error::InvalidBinding));
    }
    let mut zero_ordinal = fixture(&[], false, ROOT_FORMS[0])?;
    fields(&mut zero_ordinal)?[3] = uint(0);
    assert_eq!(decode(&zero_ordinal)?, Some(Error::InvalidBinding));
    Ok(())
}

#[test]
fn factual_binding_is_both_present_or_both_null() -> TestResult {
    for index in [5, 6] {
        let mut half = fixture(&[], true, ROOT_FORMS[0])?;
        fields(&mut half)?[index] = Value::Null;
        assert_eq!(decode(&half)?, Some(Error::InvalidBinding));
    }
    Ok(())
}

#[test]
fn evidence_roots_are_sorted_known_roles_at_most_one_each() -> TestResult {
    let row = |role: u64, byte: u8| Value::Array(vec![uint(role), bytes(&[byte; 32])]);
    for (rows, expected) in [
        (vec![row(0, 8)], Some(Error::InvalidEncoding)),
        (vec![row(3, 8)], Some(Error::InvalidEncoding)),
        (vec![row(1, 8), row(1, 9)], Some(Error::InvalidEncoding)),
        (vec![row(2, 8), row(2, 9)], Some(Error::InvalidEncoding)),
        (vec![row(2, 9), row(1, 8)], Some(Error::InvalidEncoding)),
        (
            vec![row(1, 8), row(2, 9), row(2, 9)],
            Some(Error::BoundsExceeded),
        ),
        (
            vec![Value::Array(vec![uint(1)])],
            Some(Error::InvalidEncoding),
        ),
        (vec![Value::Null], Some(Error::InvalidEncoding)),
    ] {
        let mut wire = fixture(&[], false, ROOT_FORMS[0])?;
        fields(&mut wire)?[8] = Value::Array(rows);
        assert_eq!(decode(&wire)?, expected);
    }
    Ok(())
}

#[test]
fn graph_counts_have_profile_one_maxima_and_shared_counts_are_exact_u64() -> TestResult {
    for index in 0..6 {
        let mut values = GRAPH_MAXIMA;
        let mut input = input(&[], false, ROOT_FORMS[0])?;
        input.graph_counts = graph_counts(values);
        let encoded = Bundle::new(input)?.to_canonical_cbor();
        assert!(
            Bundle::from_canonical_cbor(&encoded)?
                .as_input()
                .graph_counts
                == graph_counts(values)
        );
        values[index] += 1;
        input.graph_counts = graph_counts(values);
        assert_eq!(Bundle::new(input).err(), Some(Error::BoundsExceeded));
        let mut wire = fixture(&[], false, ROOT_FORMS[0])?;
        fields(&mut wire)?[10] = Value::Array(values.into_iter().map(uint).collect());
        assert_eq!(decode(&wire)?, Some(Error::BoundsExceeded));
    }
    let mut zero = input(&[], false, ROOT_FORMS[0])?;
    zero.graph_counts = graph_counts([0; 6]);
    zero.shared_counts = SharedCounts::default();
    assert!(Bundle::new(zero).is_ok());
    Ok(())
}

#[test]
fn bundle_horizon_preserves_positive_i64_range() -> TestResult {
    for (horizon, valid) in [
        (1, true),
        (u64::MAX / 2, true),
        (0, false),
        (u64::MAX / 2 + 1, false),
    ] {
        let mut input = input(&[], false, ROOT_FORMS[0])?;
        input.evidence_not_after_micros = horizon;
        assert_eq!(Bundle::new(input).is_ok(), valid);
    }
    Ok(())
}

#[test]
fn bundle_rejects_truncation_trailer_version_size_and_malformed_fields() -> TestResult {
    let encoded = encode(&fixture(&[hash(9)], true, ROOT_FORMS[3])?)?;
    for end in 0..encoded.len() {
        assert!(Bundle::from_canonical_cbor(&encoded[..end]).is_err());
    }
    let mut trailing = encoded;
    trailing.push(0);
    assert_eq!(
        Bundle::from_canonical_cbor(&trailing).err(),
        Some(Error::InvalidEncoding)
    );
    let mut version = fixture(&[], false, ROOT_FORMS[0])?;
    fields(&mut version)?[1] = uint(2);
    assert_eq!(decode(&version)?, Some(Error::UnsupportedVersion));
    for (index, value) in [
        (2, bytes(&[0; 4])),
        (7, Value::Array(vec![bytes(&[9; 31])])),
        (9, Value::Array((0..3).map(uint).collect())),
        (10, Value::Array((0..5).map(uint).collect())),
        (8, Value::Null),
    ] {
        let mut malformed = fixture(&[], false, ROOT_FORMS[0])?;
        fields(&mut malformed)?[index] = value;
        assert!(decode(&malformed)?.is_some());
    }
    let limit = MAX_COMMUNITY_DEPENDENCY_BUNDLE_BYTES_V1;
    assert_eq!(limit, 1_048_576);
    assert_eq!(
        Bundle::from_canonical_cbor(&vec![0; limit]).err(),
        Some(Error::InvalidEncoding)
    );
    assert_eq!(
        Bundle::from_canonical_cbor(&vec![0; limit + 1]).err(),
        Some(Error::BoundsExceeded)
    );
    Ok(())
}
