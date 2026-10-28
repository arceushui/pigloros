//! Parity guard between the `pos-core` factual classification registry and
//! the conformance `IDP1` codec, which owns the wire codes `pos-core` cannot
//! depend on.

use ciborium::value::Value;
use pos_conformance::counterfactual::dependency::{
    DependencyClassificationRuleV1, DependencyTickRangeV1, InputDependencyContractErrorV1,
    InputDependencyV1,
};
use pos_conformance::{DependencyClassV1, DependencyNodeV1};
use pos_core::output_policy::OutputAuthorityV1;
use pos_core::{
    assemble_factual_tick, factual_classification_bundle_bytes, CanonicalBytes,
    DependencyNodeCoordinateV1, DependencyNodeRecordV1, EntityId, EventDraft, FactualDriverStepV1,
    FactualFoldCursorV1, FactualFoldEventV1, FactualFoldSourceV1, FactualFoldWindowV1,
    FactualHostOwnerV1, FactualIngressEventV1, FactualInputV1, FactualOutputV1, FactualOwnerIdV1,
    FactualPriorNodeV1, FactualRuleV1, FactualScheduledTickV1, FactualTickContextV1,
    FactualTickShapeV1, Hash, Kind, PipelineAttemptIdV1, RecordedDependencyClassV1,
    RecordedNodeOriginV1, Seq, TickDependencyRecordV1, TimelineId, FACTUAL_FOLD_SCHEMA_ID_V1,
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const GRANT: [u8; 32] = [0x0f; 32];

fn node(tick: u64, position: u32, owner: &str, digest: u8) -> DependencyNodeV1 {
    DependencyNodeV1 {
        tick,
        scheduler_position: position,
        owner_id: owner.to_owned(),
        output_ordinal: 0,
        schema_id: 7,
        artifact_digest: [digest; 32],
    }
}

fn class_of(code: u8) -> TestResult<DependencyClassV1> {
    Ok(DependencyClassV1::from_wire_code(u64::from(code)).ok_or("unknown class code")?)
}

#[test]
fn every_factual_rule_is_a_valid_idp1_rule_with_the_core_class_code() -> TestResult {
    for rule in FactualRuleV1::ALL {
        let edge = InputDependencyV1 {
            consumer: node(5, 1, "plugin:consumer", 0x22),
            source: node(3, 0, "host.source", 0x11),
            dependency_class: class_of(rule.class().code())?,
            tick_range: DependencyTickRangeV1 {
                first_tick: 3,
                last_tick: 5,
            },
            authorization_digest: GRANT,
            classification_rule: DependencyClassificationRuleV1 {
                rule_id: rule.rule_id().to_owned(),
                rule_version: FactualRuleV1::VERSION,
            },
            provenance_digest: [0x44; 32],
        };
        let decoded = InputDependencyV1::from_canonical_cbor(&edge.to_canonical_cbor()?)?;
        assert_eq!(decoded.classification_rule, edge.classification_rule);
        assert_eq!(decoded.dependency_class.wire_code(), rule.class().code());
    }
    Ok(())
}

#[test]
fn the_class_codes_are_the_conformance_wire_codes() -> TestResult {
    for (class, wire) in RecordedDependencyClassV1::ALL.into_iter().zip(0_u8..) {
        assert_eq!(class.code(), wire);
        assert_eq!(class_of(wire)?.wire_code(), wire);
    }
    Ok(())
}

fn integer(value: &Value) -> TestResult<u64> {
    Ok(u64::try_from(value.as_integer().ok_or("not an integer")?)?)
}

#[test]
fn the_bundle_is_a_canonical_cbor_array_sorted_by_rule_id() -> TestResult {
    let bytes = factual_classification_bundle_bytes();
    let value: Value = ciborium::from_reader(bytes.as_slice())?;
    let mut reencoded = Vec::new();
    ciborium::into_writer(&value, &mut reencoded)?;
    assert_eq!(reencoded, bytes);
    let entries = value.as_array().ok_or("not an array")?;
    assert_eq!(entries.len(), FactualRuleV1::ALL.len());
    let mut previous: Option<&str> = None;
    for entry in entries {
        let fields = entry.as_array().ok_or("entry is not an array")?;
        let [rule_id, version, class] = fields.as_slice() else {
            return Err("entry has the wrong arity".into());
        };
        let rule_id = rule_id.as_text().ok_or("rule ID is not text")?;
        let rule = FactualRuleV1::ALL
            .into_iter()
            .find(|rule| rule.rule_id() == rule_id)
            .ok_or("unknown rule ID")?;
        assert_eq!(integer(version)?, u64::from(FactualRuleV1::VERSION));
        assert_eq!(integer(class)?, u64::from(rule.class().code()));
        assert!(previous.is_none_or(|before| before < rule_id));
        previous = Some(rule_id);
    }
    Ok(())
}

fn draft(kind: &str, payload: &'static [u8]) -> EventDraft {
    EventDraft::new(
        EntityId::new(),
        Kind::new(kind),
        CanonicalBytes::from_static(payload),
    )
}

fn prior(tick: u64, class: RecordedDependencyClassV1) -> TestResult<FactualPriorNodeV1> {
    let coordinate = DependencyNodeCoordinateV1::try_new(
        tick,
        1,
        "plugin:prior".to_owned(),
        0,
        7,
        Hash::from_bytes([0x66; 32]),
    )?;
    Ok(FactualPriorNodeV1::new(coordinate, class))
}

fn scheduled_tick() -> TestResult<FactualScheduledTickV1> {
    let step_inputs = vec![
        FactualInputV1::PrefixNode(0),
        FactualInputV1::HistoryNode(0),
        FactualInputV1::IngressEvent(Seq::from_u64(2)),
        FactualInputV1::Prior(prior(2, RecordedDependencyClassV1::EndogenousRecomputed)?),
    ];
    let outputs = vec![
        FactualOutputV1 {
            draft: draft("world.out", b"a"),
            authority: OutputAuthorityV1::Authoritative,
            direct_inputs: vec![FactualInputV1::Prior(prior(
                1,
                RecordedDependencyClassV1::ExogenousFrozen,
            )?)],
        },
        FactualOutputV1 {
            draft: draft("world.view", b"b"),
            authority: OutputAuthorityV1::Ephemeral,
            direct_inputs: Vec::new(),
        },
    ];
    Ok(FactualScheduledTickV1 {
        snapshot_digest: Hash::from_bytes([0x51; 32]),
        prefix_contents: vec![Hash::from_bytes([0x61; 32])],
        history_contents: vec![Hash::from_bytes([0x62; 32])],
        ingress_events: vec![FactualIngressEventV1 {
            seq: Seq::from_u64(2),
            event_type: "world.input".to_owned(),
            payload_hash: Hash::from_bytes([0x71; 32]),
        }],
        drivers: vec![FactualDriverStepV1 {
            owner: FactualOwnerIdV1::new("plugin:driver".to_owned()),
            policy_identity: Hash::from_bytes([0x11; 32]),
            step_inputs,
            outputs,
        }],
        fold: None,
    })
}

#[test]
fn assembled_edges_decode_in_the_conformance_codec_with_registered_rules() -> TestResult {
    let context = FactualTickContextV1 {
        timeline_id: TimelineId::new(),
        tick: 4,
        attempt_id: PipelineAttemptIdV1::try_new([1; 16])?,
        evidence_digest: Hash::from_bytes([0x0e; 32]),
        authority_grant: Hash::from_bytes(GRANT),
    };
    let assembled =
        assemble_factual_tick(&context, &FactualTickShapeV1::Scheduled(scheduled_tick()?))?;
    let record = assembled.record();
    assert!(!record.edges().is_empty());
    for edge in record.edges() {
        let decoded = InputDependencyV1::from_canonical_cbor(edge.as_bytes())?;
        assert_eq!(Hash::from_bytes(decoded.digest()?), edge.digest());
        assert_eq!(decoded.authorization_digest, GRANT);
        assert_eq!(decoded.tick_range.first_tick, decoded.source.tick);
        assert_eq!(decoded.tick_range.last_tick, decoded.consumer.tick);
        let consumer = record
            .nodes()
            .iter()
            .find(|candidate| candidate.coordinate() == edge.consumer())
            .ok_or("edge consumer is not a node of the record")?;
        let rule = FactualRuleV1::ALL
            .into_iter()
            .find(|rule| rule.rule_id() == decoded.classification_rule.rule_id)
            .ok_or("edge rule is not registered")?;
        assert_eq!(
            decoded.classification_rule.rule_version,
            FactualRuleV1::VERSION
        );
        assert_eq!(rule.class(), consumer.class());
        assert_eq!(
            decoded.provenance_digest,
            *consumer.provenance_digest().as_bytes()
        );
        assert_eq!(
            decoded.source.artifact_digest,
            *edge.source_digest().as_bytes()
        );
    }
    for item in record.nodes() {
        assert_eq!(item.origin().code(), 0);
    }
    Ok(())
}

/// The context of the Tick the fold-part case assembles.
fn fold_context() -> TestResult<FactualTickContextV1> {
    Ok(FactualTickContextV1 {
        timeline_id: TimelineId::new(),
        tick: 4,
        attempt_id: PipelineAttemptIdV1::try_new([2; 16])?,
        evidence_digest: Hash::from_bytes([0x0e; 32]),
        authority_grant: Hash::from_bytes(GRANT),
    })
}

/// The fold checkpoint node Tick 3 recorded: the head of the fold chain.
fn fold_head() -> TestResult<DependencyNodeRecordV1> {
    let owner = FactualHostOwnerV1::Fold.as_str().to_owned();
    let schema = FACTUAL_FOLD_SCHEMA_ID_V1;
    let digest = Hash::from_bytes([0x81; 32]);
    let coordinate = DependencyNodeCoordinateV1::try_new(3, 0, owner, 0, schema, digest)?;
    let class = RecordedDependencyClassV1::EndogenousRecomputed;
    let origin = RecordedNodeOriginV1::Committed;
    let provenance = Hash::from_bytes([0x82; 32]);
    DependencyNodeRecordV1::try_new(coordinate, class, origin, Vec::new(), provenance)
        .map_err(Into::into)
}

/// A truncated fold window of `count` Events without a node after the head:
/// a fold-history node, a chain of fold checkpoint nodes, and one ingress
/// node per Event that only the fold part inputs.
fn fold_source(count: u64) -> TestResult<FactualFoldSourceV1> {
    let event = |seq: u64| FactualFoldEventV1 {
        seq: Seq::from_u64(seq),
        event_type: Kind::new("world.fact"),
        payload_hash: Hash::from_bytes([0x91; 32]),
        node_class: None,
        node: None,
    };
    let cursor = FactualFoldCursorV1 {
        scanned_through: Seq::from_u64(2),
        head: Some(fold_head()?),
    };
    Ok(FactualFoldSourceV1 {
        observed_through: Seq::from_u64(10 + count),
        cursor: Some(cursor),
        window: FactualFoldWindowV1 {
            events: (11..=10 + count).map(event).collect(),
            truncated: true,
        },
    })
}

/// The owner IDs of the source and the consumer of every edge of a record,
/// after each edge decodes in the conformance codec in `IDP1` order.
fn decoded_owner_pairs(record: &TickDependencyRecordV1) -> TestResult<Vec<(String, String)>> {
    let mut pairs = Vec::new();
    for edge in record.edges() {
        let decoded = InputDependencyV1::from_canonical_cbor(edge.as_bytes())?;
        let (source, consumer) = (decoded.source, decoded.consumer);
        assert!(source.coordinate_key() < consumer.coordinate_key());
        pairs.push((source.owner_id, consumer.owner_id));
    }
    Ok(pairs)
}

/// ADR-064 R4.2 and R4.3: every edge of the fold part decodes in the
/// conformance codec, so its source sorts before its consumer. The fold-only
/// ingress nodes feed their fold node, the head and the fold-history node of
/// the same Tick feed the first, the fold nodes chain, and the last feeds the
/// snapshot node. A fold owner ID that sorts before `host.ingress` or
/// `host.fold-history` fails here.
#[test]
fn assembled_fold_part_edges_decode_in_the_conformance_codec() -> TestResult {
    let mut tick = scheduled_tick()?;
    tick.fold = Some(Box::new(fold_source(4_095)?));
    let shape = FactualTickShapeV1::Scheduled(tick);
    let assembled = assemble_factual_tick(&fold_context()?, &shape)?;
    assert_eq!(assembled.fold().checkpoints.len(), 2);
    assert_eq!(assembled.fold().history.len(), 1);
    let pairs = decoded_owner_pairs(assembled.record())?;
    let fold = FactualHostOwnerV1::Fold.as_str();
    let fed_by = |owner: FactualHostOwnerV1| {
        let into_fold = |pair: &&(String, String)| pair.0 == owner.as_str() && pair.1 == fold;
        pairs.iter().filter(into_fold).count()
    };
    assert_eq!(fed_by(FactualHostOwnerV1::Ingress), 4_095);
    assert_eq!(fed_by(FactualHostOwnerV1::FoldHistory), 1);
    // The head into the first fold node, and the first into the second.
    assert_eq!(fed_by(FactualHostOwnerV1::Fold), 2);
    let observation = FactualHostOwnerV1::Observation.as_str();
    let into_snapshot = (fold.to_owned(), observation.to_owned());
    assert!(pairs.contains(&into_snapshot));
    Ok(())
}

/// ADR-064 R6, 4.1 (conformance test 6): the history and verified-prefix nodes
/// of a Tick that has a fold part input its last `host.lineage` node, and
/// every such edge decodes in the conformance codec in `IDP1` order: the
/// history owner ID sorts after `host.lineage`.
#[test]
fn the_history_and_prefix_edges_to_the_fold_chain_decode_in_the_conformance_codec() -> TestResult {
    let mut tick = scheduled_tick()?;
    tick.fold = Some(Box::new(fold_source(4_095)?));
    let shape = FactualTickShapeV1::Scheduled(tick);
    let assembled = assemble_factual_tick(&fold_context()?, &shape)?;
    let pairs = decoded_owner_pairs(assembled.record())?;
    let lineage = FactualHostOwnerV1::Fold.as_str();
    for consumer in [FactualHostOwnerV1::History, FactualHostOwnerV1::Prefix] {
        let into = |pair: &&(String, String)| pair.0 == lineage && pair.1 == consumer.as_str();
        assert_eq!(
            pairs.iter().filter(into).count(),
            1,
            "{}",
            consumer.as_str()
        );
    }
    Ok(())
}

/// The edge from a `host.lineage` node of Tick 4 to a history node of the
/// same Tick under the owner ID `consumer`, at the same scheduler position.
fn lineage_to_history_edge(consumer: &str) -> TestResult<InputDependencyV1> {
    let rule = FactualRuleV1::ConsumedHistory;
    Ok(InputDependencyV1 {
        consumer: node(4, 0, consumer, 0x22),
        source: node(4, 0, FactualHostOwnerV1::Fold.as_str(), 0x11),
        dependency_class: class_of(rule.class().code())?,
        tick_range: DependencyTickRangeV1 {
            first_tick: 4,
            last_tick: 4,
        },
        authorization_digest: GRANT,
        classification_rule: DependencyClassificationRuleV1 {
            rule_id: rule.rule_id().to_owned(),
            rule_version: FactualRuleV1::VERSION,
        },
        provenance_digest: [0x44; 32],
    })
}

/// ADR-064 R6, 4.1 (conformance test 6, negative): the history owner ID the
/// amendment renames, `host.history`, sorts before `host.lineage`, so an edge
/// from the fold chain into such a node fails the `IDP1` order in encoding and
/// in validation, while the same edge into `host.visible-history` decodes.
/// This is what motivates the rename.
#[test]
fn the_pre_rename_history_owner_fails_the_idp1_order_that_the_new_one_meets() -> TestResult {
    let renamed = FactualHostOwnerV1::History.as_str();
    assert_eq!(renamed, "host.visible-history");
    let edge = lineage_to_history_edge(renamed)?;
    let decoded = InputDependencyV1::from_canonical_cbor(&edge.to_canonical_cbor()?)?;
    assert_eq!(decoded, edge);

    let old = lineage_to_history_edge("host.history")?;
    let order = Err(InputDependencyContractErrorV1::NonCanonicalOrder);
    assert_eq!(old.validate(), order);
    assert_eq!(old.to_canonical_cbor(), order.map(|()| Vec::new()));
    Ok(())
}
