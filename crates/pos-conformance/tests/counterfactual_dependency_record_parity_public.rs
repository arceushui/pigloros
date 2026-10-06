#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

//! Parity guard between the conformance `IDP1` codec and the `pos-core`
//! counterfactual dependency record contract, which carries each edge as
//! verified canonical bytes without a CBOR decoder.

use pos_conformance::counterfactual::dependency::{
    DependencyClassificationRuleV1, DependencyTickRangeV1, InputDependencyV1,
    MAX_DEPENDENCY_OWNER_ID_BYTES_V1, MAX_INPUT_DEPENDENCY_BYTES_V1,
};
use pos_conformance::counterfactual::frontier_artifacts::MAX_CAUSE_DIGESTS_V1;
use pos_conformance::{DependencyClassV1, DependencyNodeV1};
use pos_core::{
    CounterfactualDependencyErrorV1, DependencyEdgeRecordV1, DependencyNodeCoordinateV1, Hash,
    RecordedDependencyClassV1, MAX_DEPENDENCY_EDGE_BYTES_V1, MAX_DEPENDENCY_NODE_INPUTS_V1,
    MAX_DEPENDENCY_OWNER_ID_BYTES_V1 as CORE_MAX_OWNER_ID_BYTES,
};
use std::cmp::Ordering;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn node(tick: u64, position: u32, owner: &str, ordinal: u32, digest: u8) -> DependencyNodeV1 {
    DependencyNodeV1 {
        tick,
        scheduler_position: position,
        owner_id: owner.to_owned(),
        output_ordinal: ordinal,
        schema_id: 70_000,
        artifact_digest: [digest; 32],
    }
}

fn dependency(consumer: DependencyNodeV1, source: DependencyNodeV1) -> InputDependencyV1 {
    InputDependencyV1 {
        tick_range: DependencyTickRangeV1 {
            first_tick: source.tick,
            last_tick: consumer.tick,
        },
        consumer,
        source,
        dependency_class: DependencyClassV1::EndogenousRecomputed,
        authorization_digest: [0x33; 32],
        classification_rule: DependencyClassificationRuleV1 {
            rule_id: "adr064.classification".to_owned(),
            rule_version: 1,
        },
        provenance_digest: [0x44; 32],
    }
}

fn coordinate(node: &DependencyNodeV1) -> TestResult<DependencyNodeCoordinateV1> {
    Ok(DependencyNodeCoordinateV1::try_new(
        node.tick,
        node.scheduler_position,
        node.owner_id.clone(),
        node.output_ordinal,
        node.schema_id,
        Hash::from_bytes(node.artifact_digest),
    )?)
}

fn record(edge: &InputDependencyV1) -> TestResult<DependencyEdgeRecordV1> {
    Ok(DependencyEdgeRecordV1::try_from_canonical(
        edge.to_canonical_cbor()?,
        coordinate(&edge.consumer)?,
        Hash::from_bytes(edge.source.artifact_digest),
    )?)
}

/// Edges whose consumer and source use every CBOR unsigned width and the
/// longest owner.
fn edges() -> Vec<InputDependencyV1> {
    let long_owner = "o".repeat(MAX_DEPENDENCY_OWNER_ID_BYTES_V1);
    let small = node(5, 2, "agent-b", 1, 0x22);
    let wide = node(300, 70_000, "agent-b", 24, 0x23);
    let long = node(70_000, 0, &long_owner, 0, 0x24);
    let huge = node(1 << 32, u32::MAX, "agent-c", u32::MAX, 0x25);
    let twin = node(5, 2, "agent-b", 1, 0x26);
    let world = node(3, 1, "world", 0, 0x11);
    vec![
        dependency(small, world.clone()),
        dependency(wide, node(5, 0, "world", 0, 0x12)),
        dependency(long, node(300, 0, "a", 0, 0x13)),
        dependency(huge, node(u64::from(u32::MAX), 0, "world", 0, 0x14)),
        dependency(twin, node(3, 1, "world", 0, 0x15)),
        dependency(node(5, 2, "agent-b", 1, 0x27), world),
    ]
}

#[test]
fn limits_match_the_conformance_codecs() {
    assert_eq!(MAX_DEPENDENCY_EDGE_BYTES_V1, MAX_INPUT_DEPENDENCY_BYTES_V1);
    assert_eq!(CORE_MAX_OWNER_ID_BYTES, MAX_DEPENDENCY_OWNER_ID_BYTES_V1);
    assert_eq!(MAX_DEPENDENCY_NODE_INPUTS_V1, MAX_CAUSE_DIGESTS_V1);
}

#[test]
fn class_codes_are_the_conformance_wire_codes() {
    for (index, class) in DependencyClassV1::ALL_V1.into_iter().enumerate() {
        let recorded = RecordedDependencyClassV1::ALL[index];
        assert_eq!(recorded.code(), class.wire_code());
        assert_eq!(
            RecordedDependencyClassV1::from_code(u64::from(class.wire_code())),
            Ok(recorded)
        );
    }
    assert_eq!(
        RecordedDependencyClassV1::from_code(5),
        Err(CounterfactualDependencyErrorV1::UnknownEnum)
    );
}

#[test]
fn contract_accepts_conformance_edges_and_their_digest() -> TestResult {
    for edge in edges() {
        let recorded = record(&edge)?;
        assert_eq!(recorded.as_bytes(), edge.to_canonical_cbor()?);
        assert_eq!(recorded.digest(), Hash::from_bytes(edge.digest()?));
        assert_eq!(recorded.consumer(), &coordinate(&edge.consumer)?);
        assert_eq!(
            recorded.source_digest(),
            Hash::from_bytes(edge.source.artifact_digest)
        );
    }
    Ok(())
}

#[test]
fn contract_rejects_bytes_that_disagree_with_the_supplied_fields() -> TestResult {
    let edge = dependency(node(5, 2, "agent-b", 1, 0x22), node(3, 1, "world", 0, 0x11));
    let bytes = edge.to_canonical_cbor()?;
    let other_consumer = coordinate(&node(5, 2, "agent-b", 1, 0x77))?;
    assert_eq!(
        DependencyEdgeRecordV1::try_from_canonical(
            bytes.clone(),
            other_consumer,
            Hash::from_bytes(edge.source.artifact_digest)
        ),
        Err(CounterfactualDependencyErrorV1::BindingMismatch)
    );
    assert_eq!(
        DependencyEdgeRecordV1::try_from_canonical(
            bytes,
            coordinate(&edge.consumer)?,
            Hash::from_bytes([0x78; 32])
        ),
        Err(CounterfactualDependencyErrorV1::BindingMismatch)
    );
    Ok(())
}

#[test]
fn edge_order_matches_the_conformance_edge_list_order() -> TestResult {
    let edges = edges();
    let records = edges.iter().map(record).collect::<TestResult<Vec<_>>>()?;
    for (left, left_record) in edges.iter().zip(&records) {
        for (right, right_record) in edges.iter().zip(&records) {
            let expected: Ordering = left.order_cmp(right);
            assert_eq!(left_record.order_cmp(right_record), expected);
        }
    }
    Ok(())
}
