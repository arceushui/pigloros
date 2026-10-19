#![cfg(feature = "test-support")]

//! Public-interface contract tests for the ADR-064 Revision 3 factual Tick
//! dependency contract and its Revision 4 fold checkpoint nodes.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::num::NonZeroUsize;
use std::ops::RangeInclusive;

use pos_core::counterfactual_store::test_fixtures::{
    assert_ok, err, hash, hash_field, indexed_hash, node_bytes, ok, text_field, uint,
};
use pos_core::output_policy::OutputAuthorityV1;
use pos_core::{
    assemble_factual_tick, ensure_factual_set_headroom, factual_artifact_digest,
    factual_classification_bundle_bytes, factual_classification_bundle_digest,
    factual_event_schema_id, factual_fold_checkpoint_content_digest,
    factual_fold_history_content_digest, factual_history_content_digest,
    factual_ingress_content_digest, factual_output_content_digest, factual_owner_id,
    factual_provenance_digest, factual_step_content_digest, factual_verified_prefix_content_digest,
    is_factual_fold_input, pipeline_draft_vector_digest_v1, AppendDedupKey, CanonicalBytes,
    CoreError, CounterfactualDependencyErrorV1, DependencyNodeCoordinateV1, DependencyNodeRecordV1,
    EntityId, EventDraft, EventNodeBindingV1, FactualAdmissionPortV1, FactualCutV1,
    FactualDependencyErrorV1, FactualDriverStepV1, FactualEventRefV1, FactualFoldBindingV1,
    FactualFoldCursorV1, FactualFoldEventV1, FactualFoldSourceV1, FactualFoldWindowV1,
    FactualHeadV1, FactualHostOwnerV1, FactualIngressEventV1, FactualInputV1, FactualNodeKeyV1,
    FactualOutputV1, FactualOwnerIdV1, FactualOwnerSourceV1, FactualPrefixReadPortV1,
    FactualPriorNodeV1, FactualRuleV1, FactualScheduledTickV1, FactualTickContextV1,
    FactualTickDependenciesV1, FactualTickShapeV1, Hash, Kind, OutputNodeBindingV1,
    PipelineAdmissionBasisV1, PipelineAdmissionPortV1, PipelineAttemptIdV1, PipelineIngressV1,
    PipelineOutcomeV1, PipelineReceiptLookupV1, PurgeOutcome, RecordedDependencyClassV1,
    RecordedNodeOriginV1, RecordedSetCountsV1, Seq, TickDependencyRecordV1, TimelineId, WallTime,
    EVENT_TYPE_CONSENT_GRANTED_V1, EVENT_TYPE_CONSENT_REVOKED_V1,
    FACTUAL_FOLD_HISTORY_SCHEMA_ID_V1, FACTUAL_FOLD_RESERVED_EDGES_V1,
    FACTUAL_FOLD_RESERVED_NODES_V1, FACTUAL_FOLD_SCHEMA_ID_V1, FACTUAL_HISTORY_SCHEMA_ID_V1,
    FACTUAL_PREFIX_SCHEMA_ID_V1, FACTUAL_SNAPSHOT_SCHEMA_ID_V1, FACTUAL_STEP_SCHEMA_ID_V1,
    GEOGRAPHIC_CELL_EVENT_TYPE, GEOGRAPHIC_EVENT_TYPE, HOST_CONSENT_CLOSED_EVENT_TYPE,
    MAX_DEPENDENCY_NODE_INPUTS_V1, MAX_FACTUAL_FOLD_CHECKPOINTS_PER_TICK_V1,
    MAX_FACTUAL_FOLD_EVENTS_PER_CHECKPOINT_V1, MAX_FACTUAL_FOLD_INPUT_EDGES_PER_TICK_V1,
    MAX_FACTUAL_FOLD_SCAN_PER_TICK_V1, MAX_FACTUAL_FORWARDED_EDGES_PER_TICK_V1,
    MAX_FACTUAL_FORWARDED_EVENTS_PER_TICK_V1, MAX_FORWARDED_EVENTS_PER_DRIVER_V1,
    MAX_HOST_DERIVED_STEP_INPUTS_V1, MAX_OUTPUT_DIRECT_INPUTS_V1, MAX_RECORDED_DEPENDENCY_EDGES_V1,
    MAX_RECORDED_DEPENDENCY_NODES_V1, MAX_STEP_INPUTS_PER_DRIVER_V1, MAX_TICK_DEPENDENCY_EDGES_V1,
    MAX_TICK_DEPENDENCY_NODES_V1,
};
use ulid::Ulid;

type DepError = CounterfactualDependencyErrorV1;
type FactualError = FactualDependencyErrorV1;
type Record = TickDependencyRecordV1;
type Node = DependencyNodeRecordV1;
type Assembled = Result<FactualTickDependenciesV1, FactualError>;

const TICK: u64 = 4;
const OWNER_A: &str = "plugin:aaaa";
const OWNER_B: &str = "plugin:bbbb";
const SCHEDULED: PipelineIngressV1 = PipelineIngressV1::ScheduledAiDriver;
const HUMAN: PipelineIngressV1 = PipelineIngressV1::HumanProposedAction;
const ENDOGENOUS: RecordedDependencyClassV1 = RecordedDependencyClassV1::EndogenousRecomputed;
const PRESENTATION: RecordedDependencyClassV1 = RecordedDependencyClassV1::PresentationOnly;
const EXOGENOUS: RecordedDependencyClassV1 = RecordedDependencyClassV1::ExogenousFrozen;

fn hex(value: Hash) -> String {
    blake3::Hash::from_bytes(*value.as_bytes())
        .to_hex()
        .to_string()
}

fn timeline() -> TimelineId {
    TimelineId::from_ulid(Ulid::from(0x0123_4567_89ab_cdef_u128))
}

fn attempt() -> PipelineAttemptIdV1 {
    ok(PipelineAttemptIdV1::try_new([1; 16]))
}

fn context(tick: u64) -> FactualTickContextV1 {
    FactualTickContextV1 {
        timeline_id: timeline(),
        tick,
        attempt_id: attempt(),
        evidence_digest: hash(0x0e),
        authority_grant: hash(0x0f),
    }
}

fn draft(kind: &str, payload: &'static [u8]) -> EventDraft {
    EventDraft::new(
        EntityId::from_ulid(Ulid::from(2_u128)),
        Kind::new(kind),
        CanonicalBytes::from_static(payload),
    )
}

fn events(pairs: &[(u64, u8)]) -> Vec<FactualEventRefV1> {
    pairs
        .iter()
        .map(|(seq, payload)| FactualEventRefV1 {
            seq: Seq::from_u64(*seq),
            payload_hash: hash(*payload),
        })
        .collect()
}

fn coordinate(tick: u64, owner: &str, ordinal: u32, digest: Hash) -> DependencyNodeCoordinateV1 {
    ok(DependencyNodeCoordinateV1::try_new(
        tick,
        1,
        owner.to_owned(),
        ordinal,
        7,
        digest,
    ))
}

fn prior(tick: u64, ordinal: u32, class: RecordedDependencyClassV1) -> FactualPriorNodeV1 {
    let digest = indexed_hash(ok(usize::try_from(ordinal)) + 1);
    FactualPriorNodeV1::new(coordinate(tick, OWNER_A, ordinal, digest), class)
}

fn output(
    kind: &str,
    payload: &'static [u8],
    authority: OutputAuthorityV1,
    direct_inputs: Vec<FactualInputV1>,
) -> FactualOutputV1 {
    FactualOutputV1 {
        draft: draft(kind, payload),
        authority,
        direct_inputs,
    }
}

fn driver(
    owner: &str,
    step_inputs: Vec<FactualInputV1>,
    outputs: Vec<FactualOutputV1>,
) -> FactualDriverStepV1 {
    FactualDriverStepV1 {
        owner: FactualOwnerIdV1::new(owner.to_owned()),
        policy_identity: hash(0x11),
        step_inputs,
        outputs,
    }
}

fn ingress(seq: u64, payload: u8) -> FactualIngressEventV1 {
    FactualIngressEventV1 {
        seq: Seq::from_u64(seq),
        event_type: "world.input".to_owned(),
        payload_hash: hash(payload),
    }
}

const fn scheduled(drivers: Vec<FactualDriverStepV1>) -> FactualScheduledTickV1 {
    FactualScheduledTickV1 {
        snapshot_digest: hash(0x51),
        prefix_contents: Vec::new(),
        history_contents: Vec::new(),
        ingress_events: Vec::new(),
        drivers,
        fold: None,
    }
}

fn assemble(tick: u64, shape: &FactualTickShapeV1) -> Assembled {
    assemble_factual_tick(&context(tick), shape)
}

fn assemble_scheduled(drivers: Vec<FactualDriverStepV1>) -> Assembled {
    assemble(TICK, &FactualTickShapeV1::Scheduled(scheduled(drivers)))
}

fn find<'a>(record: &'a Record, owner: &str, ordinal: u32) -> &'a DependencyNodeRecordV1 {
    ok(record
        .nodes()
        .iter()
        .find(|node| {
            node.coordinate().owner_id() == owner && node.coordinate().output_ordinal() == ordinal
        })
        .ok_or("node is missing"))
}

fn digest_of(record: &Record, owner: &str, ordinal: u32) -> Hash {
    find(record, owner, ordinal).coordinate().artifact_digest()
}

#[test]
fn the_budgets_partition_the_step_node_input_cap() {
    assert_eq!(MAX_FORWARDED_EVENTS_PER_DRIVER_V1, 3_837);
    assert_eq!(MAX_STEP_INPUTS_PER_DRIVER_V1, 255);
    assert_eq!(MAX_OUTPUT_DIRECT_INPUTS_V1, 4_095);
    assert_eq!(MAX_HOST_DERIVED_STEP_INPUTS_V1, 4);
    assert_eq!(MAX_FACTUAL_FORWARDED_EVENTS_PER_TICK_V1, 16_384);
    assert_eq!(MAX_FACTUAL_FORWARDED_EDGES_PER_TICK_V1, 131_072);
    assert_eq!(
        MAX_HOST_DERIVED_STEP_INPUTS_V1
            + MAX_FORWARDED_EVENTS_PER_DRIVER_V1
            + MAX_STEP_INPUTS_PER_DRIVER_V1,
        MAX_DEPENDENCY_NODE_INPUTS_V1
    );
    assert_eq!(
        MAX_OUTPUT_DIRECT_INPUTS_V1 + 1,
        MAX_DEPENDENCY_NODE_INPUTS_V1
    );
    assert_eq!(FACTUAL_STEP_SCHEMA_ID_V1, 1);
    assert_eq!(FACTUAL_SNAPSHOT_SCHEMA_ID_V1, 2);
    assert_eq!(FACTUAL_PREFIX_SCHEMA_ID_V1, 3);
    assert_eq!(FACTUAL_HISTORY_SCHEMA_ID_V1, 4);
    assert_eq!(FACTUAL_FOLD_SCHEMA_ID_V1, 5);
    assert_eq!(FACTUAL_FOLD_HISTORY_SCHEMA_ID_V1, 6);
}

#[test]
fn the_fold_budgets_partition_the_fold_part_of_a_record() {
    assert_eq!(MAX_FACTUAL_FOLD_SCAN_PER_TICK_V1, 65_536);
    assert_eq!(MAX_FACTUAL_FOLD_INPUT_EDGES_PER_TICK_V1, 16_384);
    assert_eq!(MAX_FACTUAL_FOLD_EVENTS_PER_CHECKPOINT_V1, 4_094);
    assert_eq!(MAX_FACTUAL_FOLD_CHECKPOINTS_PER_TICK_V1, 5);
    assert_eq!(FACTUAL_FOLD_RESERVED_NODES_V1, 2);
    assert_eq!(FACTUAL_FOLD_RESERVED_EDGES_V1, 3);
    assert_eq!(
        MAX_FACTUAL_FOLD_EVENTS_PER_CHECKPOINT_V1 + 2,
        MAX_DEPENDENCY_NODE_INPUTS_V1
    );
    let edges = MAX_FACTUAL_FOLD_INPUT_EDGES_PER_TICK_V1;
    assert_eq!(
        edges.div_ceil(MAX_FACTUAL_FOLD_EVENTS_PER_CHECKPOINT_V1),
        MAX_FACTUAL_FOLD_CHECKPOINTS_PER_TICK_V1
    );
}

#[test]
fn slotted_owner_ids_are_pinned_by_vector_and_depend_on_the_slot_alone() {
    let owner = factual_owner_id(FactualOwnerSourceV1::Slot("slot-a"));
    assert_eq!(
        owner.as_str(),
        "plugin:2649bacfd6ab7b1b75f02800249a09446d40fb7562f9e01594a0c9230c38e899"
    );
    assert_eq!(owner.as_str().len(), 71);
    assert_eq!(
        factual_owner_id(FactualOwnerSourceV1::Slot("slot-a")),
        owner
    );
    assert_ne!(
        factual_owner_id(FactualOwnerSourceV1::Slot("slot-b")),
        owner
    );
}

#[test]
fn slotless_owner_ids_are_pinned_by_vector_and_never_collide_with_slotted_ones() {
    let slotless = |policy_identity, rank| {
        factual_owner_id(FactualOwnerSourceV1::Slotless {
            policy_identity,
            name: "agent",
            rank,
        })
    };
    assert_eq!(
        slotless(hash(0x11), 0).as_str(),
        "plugin:671581368c44713cace24b454ca4663ea0d4a01fa85b6779ae721d6af4ff4e72"
    );
    assert_eq!(
        slotless(hash(0x11), 1).as_str(),
        "plugin:45d7144d5b66f00505b24f9e24a3b5fb7afb85c11a5cd87e4a29602d2879a84f"
    );
    assert_eq!(
        slotless(Hash::zero(), 0).as_str(),
        "plugin:4b33d7167319f2fb9d7a662bef1aa58628b05c35b05f923cedff00084d61fbc3"
    );
    assert_ne!(
        slotless(hash(0x11), 0),
        factual_owner_id(FactualOwnerSourceV1::Slot("agent"))
    );
}

#[test]
fn host_owners_are_the_documented_literals() {
    let literals = [
        (FactualHostOwnerV1::Observation, "host.observation"),
        (FactualHostOwnerV1::Prefix, "host.prefix"),
        (FactualHostOwnerV1::History, "host.history"),
        (FactualHostOwnerV1::Ingress, "host.ingress"),
        (FactualHostOwnerV1::Fold, "host.fold"),
        (FactualHostOwnerV1::FoldHistory, "host.fold-history"),
    ];
    for (owner, literal) in literals {
        assert_eq!(owner.as_str(), literal);
        assert_eq!(FactualOwnerIdV1::host(owner).as_str(), literal);
    }
}

#[test]
fn the_rule_registry_lists_nine_rules_with_one_class_each() {
    let table = [
        (
            FactualRuleV1::DriverOutput,
            "pos.factual.driver-output",
            ENDOGENOUS,
        ),
        (
            FactualRuleV1::DriverOutputEphemeral,
            "pos.factual.driver-output.ephemeral",
            PRESENTATION,
        ),
        (
            FactualRuleV1::DriverStep,
            "pos.factual.driver-step",
            ENDOGENOUS,
        ),
        (
            FactualRuleV1::ObservationSnapshot,
            "pos.factual.observation-snapshot",
            ENDOGENOUS,
        ),
        (
            FactualRuleV1::VerifiedPrefix,
            "pos.factual.verified-prefix",
            ENDOGENOUS,
        ),
        (
            FactualRuleV1::ConsumedHistory,
            "pos.factual.consumed-history",
            ENDOGENOUS,
        ),
        (
            FactualRuleV1::ExternalIngress,
            "pos.factual.external-ingress",
            EXOGENOUS,
        ),
        (
            FactualRuleV1::FoldCheckpoint,
            "pos.factual.fold-checkpoint",
            ENDOGENOUS,
        ),
        (
            FactualRuleV1::FoldHistory,
            "pos.factual.fold-history",
            ENDOGENOUS,
        ),
    ];
    assert_eq!(FactualRuleV1::ALL.len(), table.len());
    assert_eq!(FactualRuleV1::VERSION, 1);
    for (rule, rule_id, class) in table {
        assert!(FactualRuleV1::ALL.contains(&rule));
        assert_eq!(rule.rule_id(), rule_id);
        assert_eq!(rule.class(), class);
    }
    for authority in [
        OutputAuthorityV1::Authoritative,
        OutputAuthorityV1::ReproducibleDerived,
    ] {
        assert_eq!(
            FactualRuleV1::for_authority(authority),
            FactualRuleV1::DriverOutput
        );
    }
    assert_eq!(
        FactualRuleV1::for_authority(OutputAuthorityV1::Ephemeral),
        FactualRuleV1::DriverOutputEphemeral
    );
}

fn bytes_hex(bytes: &[u8]) -> String {
    let mut text = String::new();
    for byte in bytes {
        assert_ok(write!(text, "{byte:02x}"));
    }
    text
}

#[test]
fn the_classification_bundle_is_pinned_by_vector() {
    assert_eq!(
        bytes_hex(&factual_classification_bundle_bytes()),
        concat!(
            "8983781c706f732e6661637475616c2e636f6e73756d65642d686973746f727901028378",
            "19706f732e6661637475616c2e6472697665722d6f75747075740102837823706f732e66",
            "61637475616c2e6472697665722d6f75747075742e657068656d6572616c01048377706f",
            "732e6661637475616c2e6472697665722d73746570010283781c706f732e666163747561",
            "6c2e65787465726e616c2d696e6772657373010083781b706f732e6661637475616c2e66",
            "6f6c642d636865636b706f696e740102837818706f732e6661637475616c2e666f6c642d",
            "686973746f72790102837820706f732e6661637475616c2e6f62736572766174696f6e2d",
            "736e617073686f74010283781b706f732e6661637475616c2e76657269666965642d7072",
            "656669780102"
        )
    );
    assert_eq!(
        hex(factual_classification_bundle_digest()),
        "fe9d314c97471c02a9d099a3f876ffd756b3ff61049ee362426695abafc9baf6"
    );
}

#[test]
fn event_schema_ids_are_pinned_and_nonzero() {
    assert_eq!(factual_event_schema_id("world.action"), 0xca47_e085);
    assert_eq!(factual_event_schema_id(""), 0x44e9_f675);
    assert_ne!(
        factual_event_schema_id("world.action"),
        factual_event_schema_id("world.input")
    );
}

#[test]
fn artifact_and_provenance_digests_are_pinned_by_vector() {
    let key = FactualNodeKeyV1 {
        tick: 7,
        scheduler_position: 1,
        owner: "plugin:x",
        output_ordinal: 2,
        schema_id: 9,
    };
    let artifact = factual_artifact_digest(timeline(), key, hash(0x21));
    assert_eq!(
        hex(artifact),
        "c0586c2c2f0abf2d1f90ca551d99820cff092f7aabf8e1eb14795da5c889ee9a"
    );
    let other_timeline = TimelineId::from_ulid(Ulid::from(9_u128));
    assert_ne!(
        factual_artifact_digest(other_timeline, key, hash(0x21)),
        artifact
    );
    let moved = FactualNodeKeyV1 { tick: 8, ..key };
    assert_ne!(
        factual_artifact_digest(timeline(), moved, hash(0x21)),
        artifact
    );
    let host = factual_provenance_digest(
        &context(TICK),
        SCHEDULED,
        "host.observation",
        Hash::zero(),
        FactualRuleV1::ObservationSnapshot,
    );
    assert_eq!(
        hex(host),
        "05cae5716b5fe837292d98d6449d6fc4d3c5ed0d08b150c3d1a22d6e0088f44a"
    );
    let human = factual_provenance_digest(
        &context(TICK),
        HUMAN,
        "plugin:x",
        hash(0x11),
        FactualRuleV1::DriverOutput,
    );
    assert_eq!(
        hex(human),
        "1e129965249c20f2c53356ddb1a335431541b2979f6e4bf4380621c2376b8b75"
    );
}

#[test]
fn content_digests_of_events_are_pinned_by_vector() {
    assert_eq!(
        hex(factual_ingress_content_digest(hash(0x31), Seq::from_u64(5))),
        "6d1794a284644e83dfed0bc5f4f857983cbaeafabcdaa172705977a785f2e362"
    );
    let listed = events(&[(1, 0x41), (3, 0x42)]);
    assert_eq!(
        hex(factual_verified_prefix_content_digest(
            Seq::from_u64(9),
            &listed
        )),
        "80b107fa43e76036937cbd0767fae28e947c437a436be11463c43765efc53dd2"
    );
    let first =
        factual_history_content_digest(Hash::zero(), Seq::from_u64(1), Seq::from_u64(3), &listed);
    assert_eq!(
        hex(first),
        "64000238759f8fc52af89ffc3feda3a82a65d22c1bbbec61d9a42eb8a8ce81cd"
    );
    let chained = factual_history_content_digest(
        first,
        Seq::from_u64(4),
        Seq::from_u64(4),
        &events(&[(4, 0x43)]),
    );
    assert_eq!(
        hex(chained),
        "bf7aeb76b2c4df7e3ae473b399ebe4015b6aa681d6487fa3925a099994077644"
    );
}

#[test]
fn output_and_step_content_digests_ignore_wall_time() {
    let plain = draft("world.out", b"a");
    let mut timed = plain.clone();
    timed.wall_time = Some(WallTime::from_micros(5));
    let expected = pipeline_draft_vector_digest_v1(std::slice::from_ref(&plain));
    assert_eq!(factual_output_content_digest(&plain), expected);
    assert_eq!(factual_output_content_digest(&timed), expected);
    assert_ne!(
        factual_output_content_digest(&draft("world.out", b"b")),
        expected
    );
    let vector = pipeline_draft_vector_digest_v1(&[plain.clone(), plain.clone()]);
    let mut hasher = blake3::Hasher::new();
    hasher.update(hash(0x11).as_bytes());
    hasher.update(vector.as_bytes());
    let step = Hash::from_bytes(*hasher.finalize().as_bytes());
    assert_eq!(
        factual_step_content_digest(hash(0x11), &[plain.clone(), timed.clone()]),
        step
    );
    assert_ne!(
        factual_step_content_digest(hash(0x12), &[plain, timed]),
        step
    );
    assert_ne!(factual_step_content_digest(hash(0x11), &[]), step);
}

#[test]
fn the_preflight_reserves_one_worst_case_record() {
    let nodes_at = MAX_RECORDED_DEPENDENCY_NODES_V1 - MAX_TICK_DEPENDENCY_NODES_V1;
    let edges_at = MAX_RECORDED_DEPENDENCY_EDGES_V1 - MAX_TICK_DEPENDENCY_EDGES_V1;
    let counts = |nodes, edges, inputs| RecordedSetCountsV1 {
        nodes,
        edges,
        inputs,
    };
    assert_eq!(ensure_factual_set_headroom(counts(0, 0, 0)), Ok(()));
    assert_eq!(
        ensure_factual_set_headroom(counts(nodes_at, edges_at, edges_at)),
        Ok(())
    );
    for exhausted in [
        counts(nodes_at + 1, 0, 0),
        counts(0, edges_at + 1, 0),
        counts(0, 0, edges_at + 1),
        counts(usize::MAX, usize::MAX, usize::MAX),
    ] {
        assert_eq!(
            ensure_factual_set_headroom(exhausted),
            Err(FactualError::SetExhausted)
        );
    }
}

#[test]
fn the_error_names_render_a_safe_code() {
    assert_eq!(
        FactualError::UndeclarableInput.to_string(),
        "a declared dependency input is not one the Driver could have read"
    );
    assert_eq!(
        FactualError::UnresolvedInput.to_string(),
        "a declared dependency input resolves to no recorded node"
    );
    assert_eq!(
        FactualError::ClassRuleViolation.to_string(),
        "a dependency input breaks a classification rule"
    );
    assert_eq!(
        FactualError::SetExhausted.to_string(),
        "the recorded dependency set of the Timeline is exhausted"
    );
    let record = FactualError::from(DepError::FieldOutOfBounds);
    assert_eq!(record, FactualError::Record(DepError::FieldOutOfBounds));
    assert_eq!(record.to_string(), DepError::FieldOutOfBounds.to_string());
}

/// The scheduled Tick every layout assertion below reads.
fn full_tick() -> FactualScheduledTickV1 {
    let previous_step = prior(3, 0, ENDOGENOUS);
    let first_driver = driver(
        OWNER_A,
        vec![
            FactualInputV1::PrefixNode(0),
            FactualInputV1::HistoryNode(0),
            FactualInputV1::IngressEvent(Seq::from_u64(2)),
            FactualInputV1::IngressEvent(Seq::from_u64(5)),
            FactualInputV1::Prior(previous_step),
        ],
        vec![
            output(
                "world.out",
                b"a1",
                OutputAuthorityV1::Authoritative,
                vec![
                    FactualInputV1::IngressEvent(Seq::from_u64(5)),
                    FactualInputV1::Prior(prior(2, 1, ENDOGENOUS)),
                ],
            ),
            output(
                "world.view",
                b"a2",
                OutputAuthorityV1::Ephemeral,
                Vec::new(),
            ),
        ],
    );
    let second_driver = driver(
        OWNER_B,
        vec![FactualInputV1::IngressEvent(Seq::from_u64(2))],
        Vec::new(),
    );
    FactualScheduledTickV1 {
        snapshot_digest: hash(0x51),
        prefix_contents: vec![hash(0x61)],
        history_contents: vec![hash(0x62)],
        ingress_events: vec![ingress(2, 0x71), ingress(5, 0x72)],
        drivers: vec![first_driver, second_driver],
        fold: None,
    }
}

fn full_assembly() -> FactualTickDependenciesV1 {
    ok(assemble(TICK, &FactualTickShapeV1::Scheduled(full_tick())))
}

#[test]
fn a_scheduled_tick_orders_its_nodes_canonically_and_binds_drafts_and_events() {
    let dependencies = full_assembly();
    assert_eq!(dependencies.tick(), TICK);
    let record = dependencies.record();
    assert_eq!(record.tick(), TICK);
    let layout: Vec<(u32, &str, u32)> = record
        .nodes()
        .iter()
        .map(|node| {
            let coordinate = node.coordinate();
            (
                coordinate.scheduler_position(),
                coordinate.owner_id(),
                coordinate.output_ordinal(),
            )
        })
        .collect();
    assert_eq!(
        layout,
        vec![
            (0, "host.history", 0),
            (0, "host.ingress", 0),
            (0, "host.ingress", 1),
            (0, "host.observation", 0),
            (0, "host.prefix", 0),
            (1, OWNER_A, 0),
            (1, OWNER_A, 1),
            (1, OWNER_A, 2),
            (2, OWNER_B, 0),
        ]
    );
    assert_eq!(
        dependencies.output_bindings(),
        [
            OutputNodeBindingV1 {
                draft_index: 0,
                node_index: 6
            },
            OutputNodeBindingV1 {
                draft_index: 1,
                node_index: 7
            },
        ]
    );
    assert_eq!(
        dependencies.event_nodes(),
        [
            EventNodeBindingV1 {
                seq: Seq::from_u64(2),
                node_index: 1
            },
            EventNodeBindingV1 {
                seq: Seq::from_u64(5),
                node_index: 2
            },
        ]
    );
}

#[test]
fn a_scheduled_tick_classifies_every_node_by_its_rule() {
    let dependencies = full_assembly();
    let record = dependencies.record();
    let classes: Vec<RecordedDependencyClassV1> = record
        .nodes()
        .iter()
        .map(DependencyNodeRecordV1::class)
        .collect();
    assert_eq!(
        classes,
        vec![
            ENDOGENOUS,
            EXOGENOUS,
            EXOGENOUS,
            ENDOGENOUS,
            ENDOGENOUS,
            ENDOGENOUS,
            ENDOGENOUS,
            PRESENTATION,
            ENDOGENOUS,
        ]
    );
    let schema_of = |owner: &str, ordinal| find(record, owner, ordinal).coordinate().schema_id();
    assert_eq!(
        schema_of("host.observation", 0),
        FACTUAL_SNAPSHOT_SCHEMA_ID_V1
    );
    assert_eq!(schema_of("host.prefix", 0), FACTUAL_PREFIX_SCHEMA_ID_V1);
    assert_eq!(schema_of("host.history", 0), FACTUAL_HISTORY_SCHEMA_ID_V1);
    assert_eq!(schema_of(OWNER_A, 0), FACTUAL_STEP_SCHEMA_ID_V1);
    assert_eq!(schema_of(OWNER_A, 1), factual_event_schema_id("world.out"));
    assert_eq!(
        schema_of("host.ingress", 1),
        factual_event_schema_id("world.input")
    );
}

#[test]
fn a_scheduled_tick_derives_its_digests_from_the_published_functions() {
    let dependencies = full_assembly();
    let record = dependencies.record();
    let snapshot_key = FactualNodeKeyV1 {
        tick: TICK,
        scheduler_position: 0,
        owner: "host.observation",
        output_ordinal: 0,
        schema_id: FACTUAL_SNAPSHOT_SCHEMA_ID_V1,
    };
    assert_eq!(
        digest_of(record, "host.observation", 0),
        factual_artifact_digest(timeline(), snapshot_key, hash(0x51))
    );
    let ingress_key = FactualNodeKeyV1 {
        tick: TICK,
        scheduler_position: 0,
        owner: "host.ingress",
        output_ordinal: 1,
        schema_id: factual_event_schema_id("world.input"),
    };
    assert_eq!(
        digest_of(record, "host.ingress", 1),
        factual_artifact_digest(
            timeline(),
            ingress_key,
            factual_ingress_content_digest(hash(0x72), Seq::from_u64(5))
        )
    );
    let step = find(record, OWNER_A, 0);
    let expected_provenance = factual_provenance_digest(
        &context(TICK),
        SCHEDULED,
        OWNER_A,
        hash(0x11),
        FactualRuleV1::DriverStep,
    );
    assert_eq!(step.provenance_digest(), expected_provenance);
    let view = find(record, OWNER_A, 2);
    assert_eq!(
        view.provenance_digest(),
        factual_provenance_digest(
            &context(TICK),
            SCHEDULED,
            OWNER_A,
            hash(0x11),
            FactualRuleV1::DriverOutputEphemeral
        )
    );
    let step_content = factual_step_content_digest(
        hash(0x11),
        &[draft("world.out", b"a1"), draft("world.view", b"a2")],
    );
    let step_key = FactualNodeKeyV1 {
        tick: TICK,
        scheduler_position: 1,
        owner: OWNER_A,
        output_ordinal: 0,
        schema_id: FACTUAL_STEP_SCHEMA_ID_V1,
    };
    assert_eq!(
        step.coordinate().artifact_digest(),
        factual_artifact_digest(timeline(), step_key, step_content)
    );
}

#[test]
fn a_scheduled_tick_declares_every_required_and_resolved_input_once() {
    let dependencies = full_assembly();
    let record = dependencies.record();
    let first_step = find(record, OWNER_A, 0);
    let mut expected = vec![
        digest_of(record, "host.observation", 0),
        digest_of(record, "host.prefix", 0),
        digest_of(record, "host.history", 0),
        digest_of(record, "host.ingress", 0),
        digest_of(record, "host.ingress", 1),
        indexed_hash(1),
    ];
    expected.sort();
    assert_eq!(first_step.input_digests(), expected.as_slice());
    let out_one = find(record, OWNER_A, 1);
    let mut expected_out = vec![
        first_step.coordinate().artifact_digest(),
        digest_of(record, "host.ingress", 1),
        indexed_hash(2),
    ];
    expected_out.sort();
    assert_eq!(out_one.input_digests(), expected_out.as_slice());
    let view = find(record, OWNER_A, 2);
    assert_eq!(
        view.input_digests(),
        [first_step.coordinate().artifact_digest()]
    );
    let second_step = find(record, OWNER_B, 0);
    assert_eq!(second_step.input_digests().len(), 2);
    for host in [
        "host.observation",
        "host.prefix",
        "host.history",
        "host.ingress",
    ] {
        assert!(find(record, host, 0).input_digests().is_empty());
    }
    assert_eq!(record.edges().len(), 6 + 3 + 1 + 2);
    assert_eq!(record.uncovered_input_count(), 0);
}

/// The exact `IDP1` array of one edge, written independently of the contract.
fn expected_edge(
    consumer: &DependencyNodeRecordV1,
    source: &DependencyNodeCoordinateV1,
    source_class: RecordedDependencyClassV1,
    rule: FactualRuleV1,
) -> Vec<u8> {
    [
        vec![0x89],
        text_field("IDP1"),
        uint(1),
        node_bytes(consumer.coordinate()),
        node_bytes(source),
        uint(u64::from(source_class.code())),
        vec![0x82],
        uint(source.tick()),
        uint(consumer.coordinate().tick()),
        hash_field(hash(0x0f)),
        vec![0x82],
        text_field(rule.rule_id()),
        uint(1),
        hash_field(consumer.provenance_digest()),
    ]
    .concat()
}

fn edge_bytes_between<'a>(
    record: &'a Record,
    consumer: &DependencyNodeRecordV1,
    source_digest: Hash,
) -> &'a [u8] {
    ok(record
        .edges()
        .iter()
        .find(|edge| {
            edge.consumer() == consumer.coordinate() && edge.source_digest() == source_digest
        })
        .map(pos_core::DependencyEdgeRecordV1::as_bytes)
        .ok_or("edge is missing"))
}

#[test]
fn an_edge_is_the_exact_idp1_array_of_its_nodes_class_rule_and_grant() {
    let dependencies = full_assembly();
    let record = dependencies.record();
    let view = find(record, OWNER_A, 2);
    let step = find(record, OWNER_A, 0);
    let expected = expected_edge(
        view,
        step.coordinate(),
        ENDOGENOUS,
        FactualRuleV1::DriverOutputEphemeral,
    );
    let bytes = edge_bytes_between(record, view, step.coordinate().artifact_digest());
    assert_eq!(bytes, expected.as_slice());
}

#[test]
fn an_edge_carries_the_class_of_its_source_and_a_range_from_its_tick() {
    let dependencies = full_assembly();
    let record = dependencies.record();
    let step = find(record, OWNER_A, 0);
    let previous = coordinate(3, OWNER_A, 0, indexed_hash(1));
    assert_eq!(
        edge_bytes_between(record, step, previous.artifact_digest()),
        expected_edge(step, &previous, ENDOGENOUS, FactualRuleV1::DriverStep).as_slice()
    );
    let ingress_node = find(record, "host.ingress", 0);
    assert_eq!(
        edge_bytes_between(record, step, ingress_node.coordinate().artifact_digest()),
        expected_edge(
            step,
            ingress_node.coordinate(),
            EXOGENOUS,
            FactualRuleV1::DriverStep
        )
        .as_slice()
    );
    let out_one = find(record, OWNER_A, 1);
    let older = coordinate(2, OWNER_A, 1, indexed_hash(2));
    assert_eq!(
        edge_bytes_between(record, out_one, older.artifact_digest()),
        expected_edge(out_one, &older, ENDOGENOUS, FactualRuleV1::DriverOutput).as_slice()
    );
}

#[test]
fn assembly_is_deterministic_and_the_digest_binds_every_part() {
    let dependencies = full_assembly();
    assert_eq!(dependencies, full_assembly());
    let digest = dependencies.digest();
    assert_eq!(digest, full_assembly().digest());
    let record = dependencies.record().clone();
    let bindings = dependencies.output_bindings().to_vec();
    let events = dependencies.event_nodes().to_vec();
    let rebuilt =
        |tick, record: &Record, bindings: &[OutputNodeBindingV1], events: &[EventNodeBindingV1]| {
            FactualTickDependenciesV1::new(
                tick,
                record.clone(),
                bindings.to_vec(),
                events.to_vec(),
                FactualFoldBindingV1::default(),
            )
        };
    assert_eq!(rebuilt(TICK, &record, &bindings, &events).digest(), digest);
    assert_ne!(
        rebuilt(TICK + 1, &record, &bindings, &events).digest(),
        digest
    );
    assert_ne!(
        rebuilt(TICK, &record, &bindings[..1], &events).digest(),
        digest
    );
    assert_ne!(
        rebuilt(TICK, &record, &bindings, &events[..1]).digest(),
        digest
    );
    let mut swapped = bindings;
    swapped.reverse();
    assert_ne!(rebuilt(TICK, &record, &swapped, &events).digest(), digest);
    let other = ok(assemble(
        TICK + 1,
        &FactualTickShapeV1::Scheduled(full_tick()),
    ))
    .digest();
    assert_ne!(other, digest);
}

#[test]
fn a_zero_draft_driver_still_holds_a_step_node_and_a_lone_driver_needs_only_the_snapshot() {
    let dependencies = ok(assemble_scheduled(vec![driver(
        OWNER_A,
        Vec::new(),
        Vec::new(),
    )]));
    let record = dependencies.record();
    assert_eq!(record.nodes().len(), 2);
    assert!(dependencies.output_bindings().is_empty());
    assert!(dependencies.event_nodes().is_empty());
    let step = find(record, OWNER_A, 0);
    assert_eq!(
        step.input_digests(),
        [digest_of(record, "host.observation", 0)]
    );
    assert_eq!(record.edges().len(), 1);
    let snapshot_only = ok(assemble_scheduled(Vec::new()));
    assert_eq!(snapshot_only.record().nodes().len(), 1);
    assert!(snapshot_only.record().edges().is_empty());
}

#[test]
fn equal_inputs_collapse_into_one_edge() {
    let repeated = vec![
        FactualInputV1::Prior(prior(2, 1, ENDOGENOUS)),
        FactualInputV1::Prior(prior(2, 1, ENDOGENOUS)),
    ];
    let dependencies = ok(assemble_scheduled(vec![driver(
        OWNER_A,
        repeated,
        Vec::new(),
    )]));
    let step = find(dependencies.record(), OWNER_A, 0);
    assert_eq!(step.input_digests().len(), 2);
}

#[test]
fn a_human_tick_records_one_human_ingress_node_per_draft() {
    let drafts = vec![draft("world.action", b"h1"), draft("world.note", b"h2")];
    let dependencies = ok(assemble(TICK, &FactualTickShapeV1::Human(drafts.clone())));
    let record = dependencies.record();
    assert_eq!(record.nodes().len(), 2);
    assert!(record.edges().is_empty());
    assert!(dependencies.event_nodes().is_empty());
    assert_eq!(
        dependencies.output_bindings(),
        [
            OutputNodeBindingV1 {
                draft_index: 0,
                node_index: 0
            },
            OutputNodeBindingV1 {
                draft_index: 1,
                node_index: 1
            },
        ]
    );
    for (ordinal, source) in drafts.iter().enumerate() {
        let ordinal = ok(u32::try_from(ordinal));
        let node = find(record, "host.ingress", ordinal);
        assert_eq!(node.class(), EXOGENOUS);
        assert!(node.input_digests().is_empty());
        assert_eq!(
            node.coordinate().schema_id(),
            factual_event_schema_id(source.event_type.as_str())
        );
        let key = FactualNodeKeyV1 {
            tick: TICK,
            scheduler_position: 0,
            owner: "host.ingress",
            output_ordinal: ordinal,
            schema_id: factual_event_schema_id(source.event_type.as_str()),
        };
        assert_eq!(
            node.coordinate().artifact_digest(),
            factual_artifact_digest(timeline(), key, factual_output_content_digest(source))
        );
        assert_eq!(
            node.provenance_digest(),
            factual_provenance_digest(
                &context(TICK),
                HUMAN,
                "host.ingress",
                Hash::zero(),
                FactualRuleV1::ExternalIngress
            )
        );
    }
}

#[test]
fn unresolvable_inputs_are_rejected_at_the_step_and_at_the_output() {
    let at_step = |input| assemble_scheduled(vec![driver(OWNER_A, vec![input], Vec::new())]);
    let at_output = |input| {
        assemble_scheduled(vec![driver(
            OWNER_A,
            Vec::new(),
            vec![output(
                "world.out",
                b"a",
                OutputAuthorityV1::Authoritative,
                vec![input],
            )],
        )])
    };
    let unresolved = || {
        [
            FactualInputV1::PrefixNode(0),
            FactualInputV1::HistoryNode(0),
            FactualInputV1::IngressEvent(Seq::from_u64(9)),
            FactualInputV1::Prior(prior(TICK, 1, ENDOGENOUS)),
            FactualInputV1::Prior(prior(TICK + 1, 1, ENDOGENOUS)),
        ]
    };
    for input in unresolved() {
        assert_eq!(err(at_step(input)), FactualError::UnresolvedInput);
    }
    for input in unresolved() {
        assert_eq!(err(at_output(input)), FactualError::UnresolvedInput);
    }
    assert!(at_step(FactualInputV1::Prior(prior(TICK - 1, 1, ENDOGENOUS))).is_ok());
    assert!(at_output(FactualInputV1::Prior(prior(1, 1, EXOGENOUS))).is_ok());
}

#[test]
fn a_presentation_only_input_may_only_feed_a_presentation_only_node() {
    let presentation = || FactualInputV1::Prior(prior(2, 1, PRESENTATION));
    let step = assemble_scheduled(vec![driver(OWNER_A, vec![presentation()], Vec::new())]);
    assert_eq!(err(step), FactualError::ClassRuleViolation);
    let authoritative = assemble_scheduled(vec![driver(
        OWNER_A,
        Vec::new(),
        vec![output(
            "world.out",
            b"a",
            OutputAuthorityV1::ReproducibleDerived,
            vec![presentation()],
        )],
    )]);
    assert_eq!(err(authoritative), FactualError::ClassRuleViolation);
    let ephemeral = assemble_scheduled(vec![driver(
        OWNER_A,
        Vec::new(),
        vec![output(
            "world.view",
            b"a",
            OutputAuthorityV1::Ephemeral,
            vec![presentation()],
        )],
    )]);
    let dependencies = ok(ephemeral);
    let view = find(dependencies.record(), OWNER_A, 1);
    assert_eq!(view.class(), PRESENTATION);
    assert!(view.input_digests().contains(&indexed_hash(2)));
    let source = coordinate(2, OWNER_A, 1, indexed_hash(2));
    assert_eq!(
        edge_bytes_between(dependencies.record(), view, source.artifact_digest()),
        expected_edge(
            view,
            &source,
            PRESENTATION,
            FactualRuleV1::DriverOutputEphemeral
        )
        .as_slice()
    );
}

#[test]
fn ingress_events_must_ascend_strictly() {
    let with_events = |events| {
        let mut tick = scheduled(Vec::new());
        tick.ingress_events = events;
        assemble(TICK, &FactualTickShapeV1::Scheduled(tick))
    };
    assert!(with_events(vec![ingress(1, 1), ingress(2, 2)]).is_ok());
    assert_eq!(
        err(with_events(vec![ingress(2, 1), ingress(1, 2)])),
        FactualError::Record(DepError::NonCanonicalOrder)
    );
    assert_eq!(
        err(with_events(vec![ingress(2, 1), ingress(2, 2)])),
        FactualError::Record(DepError::DuplicateIdentity)
    );
}

#[test]
fn an_owner_outside_the_coordinate_bounds_is_a_record_fault() {
    let empty = assemble_scheduled(vec![driver("", Vec::new(), Vec::new())]);
    assert_eq!(err(empty), FactualError::Record(DepError::FieldOutOfBounds));
    let long = "o".repeat(129);
    let too_long = assemble_scheduled(vec![driver(&long, Vec::new(), Vec::new())]);
    assert_eq!(
        err(too_long),
        FactualError::Record(DepError::FieldOutOfBounds)
    );
}

fn distinct_priors(count: usize) -> Vec<FactualInputV1> {
    (0..count)
        .map(|index| {
            let ordinal = ok(u32::try_from(index));
            FactualInputV1::Prior(prior(2, ordinal, ENDOGENOUS))
        })
        .collect()
}

#[test]
fn a_node_holds_at_most_the_input_cap_including_the_host_inputs() {
    let capacity = MAX_DEPENDENCY_NODE_INPUTS_V1 - 1;
    let at_cap = assemble_scheduled(vec![driver(OWNER_A, distinct_priors(capacity), Vec::new())]);
    let dependencies = ok(at_cap);
    assert_eq!(
        find(dependencies.record(), OWNER_A, 0)
            .input_digests()
            .len(),
        MAX_DEPENDENCY_NODE_INPUTS_V1
    );
    let over = assemble_scheduled(vec![driver(
        OWNER_A,
        distinct_priors(capacity + 1),
        Vec::new(),
    )]);
    assert_eq!(err(over), FactualError::Record(DepError::FieldOutOfBounds));
}

#[test]
fn a_record_holds_at_most_the_node_cap() {
    let with_ingress = |count: usize| {
        let mut tick = scheduled(Vec::new());
        tick.ingress_events = (1..=count)
            .map(|seq| FactualIngressEventV1 {
                seq: Seq::from_u64(ok(u64::try_from(seq))),
                event_type: "t".to_owned(),
                payload_hash: hash(7),
            })
            .collect();
        assemble(TICK, &FactualTickShapeV1::Scheduled(tick))
    };
    let at_cap = ok(with_ingress(MAX_TICK_DEPENDENCY_NODES_V1 - 1));
    assert_eq!(at_cap.record().nodes().len(), MAX_TICK_DEPENDENCY_NODES_V1);
    assert_eq!(
        err(with_ingress(MAX_TICK_DEPENDENCY_NODES_V1)),
        FactualError::Record(DepError::FieldOutOfBounds)
    );
}

/// One recorded Tick of the reference store.
struct FakeTick {
    tick: u64,
    first_seq: u64,
    last_seq: u64,
}

/// In-memory model of the read port. This is a contract test of the port
/// semantics a store must give, not a store: real adapters are checked
/// against the same expectations in their own crates.
#[derive(Default)]
struct FakeStore {
    ticks: Vec<FakeTick>,
    by_seq: BTreeMap<Seq, DependencyNodeRecordV1>,
    by_digest: BTreeMap<Hash, (DependencyNodeRecordV1, Option<Seq>)>,
    steps: BTreeMap<String, DependencyNodeRecordV1>,
    counts: RecordedSetCountsV1,
}

impl FactualPrefixReadPortV1 for FakeStore {
    fn last_committed_factual_tick(
        &self,
        _timeline: TimelineId,
    ) -> Result<FactualHeadV1, CoreError> {
        Ok(self.ticks.last().map_or(
            FactualHeadV1 {
                tick: 0,
                last_seq: Seq::ZERO,
            },
            |last| FactualHeadV1 {
                tick: last.tick,
                last_seq: Seq::from_u64(last.last_seq),
            },
        ))
    }

    fn cut_tick_at(&self, _timeline: TimelineId, seq: Seq) -> Result<FactualCutV1, CoreError> {
        let at = seq.as_u64();
        let cut_tick = self
            .ticks
            .iter()
            .filter(|recorded| recorded.last_seq <= at)
            .map(|recorded| recorded.tick)
            .max()
            .unwrap_or(0);
        Ok(self
            .ticks
            .iter()
            .find(|recorded| recorded.first_seq <= at && at < recorded.last_seq)
            .map_or(FactualCutV1::Boundary { cut_tick }, |split| {
                FactualCutV1::MidTick {
                    cut_tick,
                    split_tick: split.tick,
                }
            }))
    }

    fn nodes_for_committed_events(
        &self,
        _timeline: TimelineId,
        seqs: &[Seq],
    ) -> Result<Vec<Option<DependencyNodeRecordV1>>, CoreError> {
        Ok(seqs
            .iter()
            .map(|seq| self.by_seq.get(seq).cloned())
            .collect())
    }

    fn nodes_by_digest(
        &self,
        _timeline: TimelineId,
        digests: &[Hash],
    ) -> Result<Vec<Option<pos_core::factual_dependency::BoundFactualNodeV1>>, CoreError> {
        Ok(digests
            .iter()
            .map(|digest| self.by_digest.get(digest).cloned())
            .collect())
    }

    fn last_step_node(
        &self,
        _timeline: TimelineId,
        owner: &FactualOwnerIdV1,
    ) -> Result<Option<DependencyNodeRecordV1>, CoreError> {
        Ok(self.steps.get(owner.as_str()).cloned())
    }

    fn factual_set_counts(&self, _timeline: TimelineId) -> Result<RecordedSetCountsV1, CoreError> {
        Ok(self.counts)
    }
}

impl PipelineAdmissionPortV1 for FakeStore {
    fn admit_pipeline_batch(
        &mut self,
        _basis: &PipelineAdmissionBasisV1,
    ) -> Result<PipelineOutcomeV1, CoreError> {
        Ok(PipelineOutcomeV1::DependencySetExhausted)
    }

    fn lookup_pipeline_receipt(
        &mut self,
        _timeline: TimelineId,
        _key: AppendDedupKey,
        _attempt_id: PipelineAttemptIdV1,
    ) -> Result<PipelineReceiptLookupV1, CoreError> {
        Ok(PipelineReceiptLookupV1::Absent)
    }

    fn purge_expired_pipeline_receipts_bounded(
        &mut self,
        _limit: NonZeroUsize,
    ) -> Result<PurgeOutcome, CoreError> {
        Ok(PurgeOutcome {
            removed: 0,
            more_may_remain: false,
        })
    }
}

fn recorded_store() -> FakeStore {
    let dependencies = full_assembly();
    let nodes = dependencies.record().nodes();
    let mut store = FakeStore {
        ticks: vec![
            FakeTick {
                tick: 1,
                first_seq: 1,
                last_seq: 3,
            },
            FakeTick {
                tick: 2,
                first_seq: 4,
                last_seq: 4,
            },
        ],
        counts: RecordedSetCountsV1 {
            nodes: nodes.len(),
            edges: dependencies.record().edges().len(),
            inputs: dependencies.record().declared_input_count(),
        },
        ..FakeStore::default()
    };
    for node in nodes {
        let digest = node.coordinate().artifact_digest();
        store.by_digest.insert(digest, (node.clone(), None));
    }
    let step = find(dependencies.record(), OWNER_A, 0).clone();
    store.steps.insert(OWNER_A.to_owned(), step);
    let ingress_node = find(dependencies.record(), "host.ingress", 0).clone();
    store.by_seq.insert(Seq::from_u64(2), ingress_node);
    store
}

fn head_and_cut(port: &mut dyn FactualAdmissionPortV1) -> (FactualHeadV1, FactualCutV1) {
    assert_eq!(
        ok(port.purge_expired_pipeline_receipts_bounded(NonZeroUsize::MIN)).removed,
        0
    );
    (
        ok(port.last_committed_factual_tick(timeline())),
        ok(port.cut_tick_at(timeline(), Seq::from_u64(2))),
    )
}

#[test]
fn the_reference_store_answers_through_the_combined_admission_port() {
    let mut store = recorded_store();
    let (head, cut) = head_and_cut(&mut store);
    assert_eq!(
        head,
        FactualHeadV1 {
            tick: 2,
            last_seq: Seq::from_u64(4)
        }
    );
    assert_eq!(
        cut,
        FactualCutV1::MidTick {
            cut_tick: 0,
            split_tick: 1
        }
    );
}

#[test]
fn the_head_is_total_and_the_cut_is_a_value_at_every_position() {
    let empty = FakeStore::default();
    assert_eq!(
        ok(empty.last_committed_factual_tick(timeline())),
        FactualHeadV1 {
            tick: 0,
            last_seq: Seq::ZERO
        }
    );
    assert_eq!(
        ok(empty.cut_tick_at(timeline(), Seq::from_u64(7))),
        FactualCutV1::Boundary { cut_tick: 0 }
    );
    let store = recorded_store();
    let cut_at = |seq| ok(store.cut_tick_at(timeline(), Seq::from_u64(seq)));
    assert_eq!(cut_at(0), FactualCutV1::Boundary { cut_tick: 0 });
    assert_eq!(
        cut_at(1),
        FactualCutV1::MidTick {
            cut_tick: 0,
            split_tick: 1
        }
    );
    assert_eq!(cut_at(3), FactualCutV1::Boundary { cut_tick: 1 });
    assert_eq!(cut_at(4), FactualCutV1::Boundary { cut_tick: 2 });
    assert_eq!(cut_at(9), FactualCutV1::Boundary { cut_tick: 2 });
}

#[test]
fn the_reference_store_resolves_nodes_in_request_order() {
    let store = recorded_store();
    let seqs = [Seq::from_u64(9), Seq::from_u64(2)];
    let by_event = ok(store.nodes_for_committed_events(timeline(), &seqs));
    assert!(by_event[0].is_none());
    assert_eq!(
        by_event[1]
            .as_ref()
            .map(|node| node.coordinate().owner_id()),
        Some("host.ingress")
    );
    let known = digest_of(full_assembly().record(), OWNER_A, 0);
    let by_digest = ok(store.nodes_by_digest(timeline(), &[hash(0xee), known]));
    assert!(by_digest[0].is_none());
    assert_eq!(by_digest[1].as_ref().map(|(_, seq)| *seq), Some(None));
    let owner = FactualOwnerIdV1::new(OWNER_A.to_owned());
    let step = ok(store.last_step_node(timeline(), &owner));
    assert_eq!(step.map(|node| node.coordinate().output_ordinal()), Some(0));
    let unknown = FactualOwnerIdV1::new(OWNER_B.to_owned());
    assert!(ok(store.last_step_node(timeline(), &unknown)).is_none());
    let counts = ok(store.factual_set_counts(timeline()));
    assert_eq!(counts.nodes, 9);
    assert_eq!(ensure_factual_set_headroom(counts), Ok(()));
}

#[test]
fn a_prior_node_is_read_from_a_recorded_row() {
    let dependencies = full_assembly();
    let row = find(dependencies.record(), OWNER_A, 2);
    let taken = FactualPriorNodeV1::from_record(row);
    assert_eq!(taken.coordinate(), row.coordinate());
    assert_eq!(taken.class(), PRESENTATION);
    let next = assemble_factual_tick(
        &context(TICK + 1),
        &FactualTickShapeV1::Scheduled(scheduled(vec![driver(
            OWNER_A,
            vec![FactualInputV1::Prior(taken)],
            Vec::new(),
        )])),
    );
    assert_eq!(err(next), FactualError::ClassRuleViolation);
}

#[test]
fn the_digest_binds_the_fold_binding_list_by_list() {
    let dependencies = full_assembly();
    assert_eq!(dependencies.fold(), &FactualFoldBindingV1::default());
    let digest = dependencies.digest();
    let with_fold = |checkpoints: Vec<u32>, history: Vec<u32>| {
        FactualTickDependenciesV1::new(
            TICK,
            dependencies.record().clone(),
            dependencies.output_bindings().to_vec(),
            dependencies.event_nodes().to_vec(),
            FactualFoldBindingV1 {
                checkpoints,
                history,
            },
        )
        .digest()
    };
    assert_eq!(with_fold(Vec::new(), Vec::new()), digest);
    let as_checkpoint = with_fold(vec![1], Vec::new());
    let as_history = with_fold(Vec::new(), vec![1]);
    assert_ne!(as_checkpoint, digest);
    assert_ne!(as_history, digest);
    assert_ne!(as_checkpoint, as_history);
    let ascending = with_fold(vec![1, 2], Vec::new());
    let descending = with_fold(vec![2, 1], Vec::new());
    assert_ne!(ascending, descending);
}

/// The digest of an empty record's declaration with `fold`, nothing else
/// bound.
fn bare_digest(fold: FactualFoldBindingV1) -> Hash {
    let origin = RecordedNodeOriginV1::Committed;
    let record = ok(Record::try_new(TICK, origin, Vec::new(), Vec::new()));
    let outputs = Vec::new();
    let events = Vec::new();
    let declared = FactualTickDependenciesV1::new(TICK, record, outputs, events, fold);
    declared.digest()
}

#[test]
fn the_fold_binding_digest_bytes_are_pinned_by_vector() {
    assert_eq!(
        hex(bare_digest(FactualFoldBindingV1::default())),
        "9733350e64378cdda42519f9be8ef92afb1b5bde51d921e8d401787b64bcc8dd"
    );
    let bound = FactualFoldBindingV1 {
        checkpoints: vec![3, 1],
        history: vec![2],
    };
    assert_eq!(
        hex(bare_digest(bound)),
        "db2c8a93a18b0bb983d760f79e60fc1212a5fe6fb5df1cf6fcd7e87d5825c84e"
    );
}

fn fold_history(from: u64, through: u64) -> Hash {
    factual_fold_history_content_digest(Seq::from_u64(from), Seq::from_u64(through))
}

fn checkpoint(previous: Hash, from: u64, through: u64, events: &[FactualEventRefV1]) -> Hash {
    factual_fold_checkpoint_content_digest(
        previous,
        Seq::from_u64(from),
        Seq::from_u64(through),
        events,
    )
}

#[test]
fn fold_content_digests_are_pinned_by_vector() {
    assert_eq!(
        hex(fold_history(1, 9)),
        "b9660d15d450ffac79f57b3317abca55f4c90e5acfdc3ee1d2746cb0ce268ff3"
    );
    let listed = events(&[(1, 0x41), (3, 0x42)]);
    assert_eq!(
        hex(checkpoint(Hash::zero(), 1, 3, &listed)),
        "2ed747f9c163c0256f921c35065e82497f51485082e118449c576cd8005fb77e"
    );
    assert_eq!(
        hex(checkpoint(hash(0x21), 10, 9, &[])),
        "c477b8c20c5602155043de4db7b3bc823b3799264a4212c197b8ab8b0642c014"
    );
    assert_ne!(fold_history(1, 9), fold_history(2, 9));
    let unchained = checkpoint(Hash::zero(), 1, 3, &listed);
    assert_ne!(unchained, checkpoint(hash(0x21), 1, 3, &listed));
}

#[test]
fn fold_inputs_exclude_gating_and_presentation_only_events() {
    let input = |kind: &str, class: Option<RecordedDependencyClassV1>| {
        is_factual_fold_input(&Kind::new(kind), class)
    };
    assert!(input("world.input", None));
    assert!(input("world.input", Some(ENDOGENOUS)));
    assert!(input(EVENT_TYPE_CONSENT_REVOKED_V1, None));
    assert!(input(EVENT_TYPE_CONSENT_REVOKED_V1, Some(EXOGENOUS)));
    assert!(!input(EVENT_TYPE_CONSENT_GRANTED_V1, None));
    assert!(!input("consent.other.v1", None));
    assert!(!input(GEOGRAPHIC_EVENT_TYPE, None));
    assert!(!input(GEOGRAPHIC_CELL_EVENT_TYPE, None));
    assert!(!input(HOST_CONSENT_CLOSED_EVENT_TYPE, None));
    assert!(!input("world.view", Some(PRESENTATION)));
    assert!(!input(EVENT_TYPE_CONSENT_REVOKED_V1, Some(PRESENTATION)));
}

const FOLD_TYPE: &str = "world.input";

/// A window Event of `kind` with no recorded node; its payload hash is its
/// `seq`.
fn typed_fold_event(seq: u64, kind: &str) -> FactualFoldEventV1 {
    FactualFoldEventV1 {
        seq: Seq::from_u64(seq),
        event_type: Kind::new(kind),
        payload_hash: indexed_hash(ok(usize::try_from(seq))),
        node_class: None,
        node: None,
    }
}

fn fold_event(seq: u64) -> FactualFoldEventV1 {
    typed_fold_event(seq, FOLD_TYPE)
}

fn fold_events(seqs: RangeInclusive<u64>) -> Vec<FactualFoldEventV1> {
    seqs.map(fold_event).collect()
}

fn event_ref(seq: u64) -> FactualEventRefV1 {
    let event = fold_event(seq);
    FactualEventRefV1 {
        seq: event.seq,
        payload_hash: event.payload_hash,
    }
}

fn refs(seqs: RangeInclusive<u64>) -> Vec<FactualEventRefV1> {
    seqs.map(event_ref).collect()
}

/// A window Event bound to a node of an earlier Tick.
fn noded_fold_event(seq: u64, kind: &str, node: Node) -> FactualFoldEventV1 {
    FactualFoldEventV1 {
        node_class: Some(node.class()),
        node: Some(node),
        ..typed_fold_event(seq, kind)
    }
}

fn recorded(coordinate: DependencyNodeCoordinateV1, class: RecordedDependencyClassV1) -> Node {
    let origin = RecordedNodeOriginV1::Committed;
    let inputs = Vec::new();
    ok(Node::try_new(coordinate, class, origin, inputs, hash(0x92)))
}

/// The fold checkpoint node an earlier Tick recorded: the head.
fn fold_head(tick: u64) -> Node {
    let owner = "host.fold".to_owned();
    let schema = FACTUAL_FOLD_SCHEMA_ID_V1;
    let coordinate = DependencyNodeCoordinateV1::try_new(tick, 0, owner, 0, schema, hash(0x91));
    recorded(ok(coordinate), ENDOGENOUS)
}

/// An output node of an earlier Tick, bound to an Event.
fn event_node(tick: u64, digest: u8, class: RecordedDependencyClassV1) -> Node {
    recorded(coordinate(tick, OWNER_A, 1, hash(digest)), class)
}

const fn artifact(node: &Node) -> Hash {
    node.coordinate().artifact_digest()
}

const fn cursor(after: u64, head: Option<Node>) -> Option<FactualFoldCursorV1> {
    Some(FactualFoldCursorV1 {
        scanned_through: Seq::from_u64(after),
        head,
    })
}

const fn fold_source(
    cursor: Option<FactualFoldCursorV1>,
    observed_through: u64,
    events: Vec<FactualFoldEventV1>,
    truncated: bool,
) -> FactualFoldSourceV1 {
    FactualFoldSourceV1 {
        observed_through: Seq::from_u64(observed_through),
        cursor,
        window: FactualFoldWindowV1 { events, truncated },
    }
}

/// The fold inputs `1..=inputs`, observed through `through`, of a Timeline
/// with no fold cursor yet.
fn first_window(through: u64, inputs: u64) -> FactualFoldSourceV1 {
    fold_source(None, through, fold_events(1..=inputs), false)
}

fn assemble_folded(mut tick: FactualScheduledTickV1, source: FactualFoldSourceV1) -> Assembled {
    tick.fold = Some(source);
    assemble(TICK, &FactualTickShapeV1::Scheduled(tick))
}

/// A lone Driver with no input of its own, and the fold source.
fn folded(source: FactualFoldSourceV1) -> FactualTickDependenciesV1 {
    let lone = driver(OWNER_A, Vec::new(), Vec::new());
    ok(assemble_folded(scheduled(vec![lone]), source))
}

fn refused(source: FactualFoldSourceV1) -> FactualError {
    let lone = driver(OWNER_A, Vec::new(), Vec::new());
    err(assemble_folded(scheduled(vec![lone]), source))
}

/// The artifact digest of a host node of this Tick.
fn host_artifact(owner: &str, ordinal: u32, schema_id: u32, content: Hash) -> Hash {
    let key = FactualNodeKeyV1 {
        tick: TICK,
        scheduler_position: 0,
        owner,
        output_ordinal: ordinal,
        schema_id,
    };
    factual_artifact_digest(timeline(), key, content)
}

fn fold_artifact(ordinal: u32, content: Hash) -> Hash {
    host_artifact("host.fold", ordinal, FACTUAL_FOLD_SCHEMA_ID_V1, content)
}

fn history_artifact(from: u64, through: u64) -> Hash {
    let content = fold_history(from, through);
    let schema = FACTUAL_FOLD_HISTORY_SCHEMA_ID_V1;
    host_artifact("host.fold-history", 0, schema, content)
}

fn node_at(dependencies: &FactualTickDependenciesV1, index: u32) -> &Node {
    &dependencies.record().nodes()[ok(usize::try_from(index))]
}

/// The fold checkpoint nodes of a Tick, in chain order.
fn fold_nodes(dependencies: &FactualTickDependenciesV1) -> Vec<&Node> {
    let checkpoints = &dependencies.fold().checkpoints;
    checkpoints
        .iter()
        .map(|index| node_at(dependencies, *index))
        .collect()
}

/// The artifact digest of the fold-history node of a Tick.
fn history_digest(dependencies: &FactualTickDependenciesV1) -> Hash {
    let history = &dependencies.fold().history;
    assert_eq!(history.len(), 1);
    artifact(node_at(dependencies, history[0]))
}

/// The artifact digest of the node bound to the Event at `seq`.
fn event_digest(dependencies: &FactualTickDependenciesV1, seq: u64) -> Hash {
    let target = Seq::from_u64(seq);
    let bindings = dependencies.event_nodes();
    let bound = bindings.iter().find(|binding| binding.seq == target);
    let index = ok(bound.ok_or("the Event is unbound")).node_index;
    artifact(node_at(dependencies, index))
}

fn bound_seqs(dependencies: &FactualTickDependenciesV1) -> Vec<u64> {
    let bindings = dependencies.event_nodes();
    bindings.iter().map(|bound| bound.seq.as_u64()).collect()
}

fn sorted(mut digests: Vec<Hash>) -> Vec<Hash> {
    digests.sort();
    digests
}

#[test]
fn a_fold_node_chains_to_the_head_and_inputs_exactly_the_fold_inputs() {
    let revoked = event_node(2, 0xa1, EXOGENOUS);
    let window = vec![
        fold_event(11),
        typed_fold_event(12, EVENT_TYPE_CONSENT_GRANTED_V1),
        noded_fold_event(13, EVENT_TYPE_CONSENT_REVOKED_V1, revoked),
        typed_fold_event(14, GEOGRAPHIC_CELL_EVENT_TYPE),
        noded_fold_event(15, "world.view", event_node(2, 0xa2, PRESENTATION)),
        typed_fold_event(16, HOST_CONSENT_CLOSED_EVENT_TYPE),
        typed_fold_event(18, EVENT_TYPE_CONSENT_REVOKED_V1),
    ];
    let head = fold_head(TICK - 1);
    let head_digest = artifact(&head);
    let source = fold_source(cursor(10, Some(head.clone())), 20, window, false);
    let dependencies = folded(source);
    let record = dependencies.record();
    assert!(dependencies.fold().history.is_empty());
    let nodes = fold_nodes(&dependencies);
    assert_eq!(nodes.len(), 1);
    let node = nodes[0];
    let kept = [event_ref(11), event_ref(13), event_ref(18)];
    let content = checkpoint(head_digest, 11, 20, &kept);
    assert_eq!(artifact(node), fold_artifact(0, content));
    assert_eq!(node.class(), ENDOGENOUS);
    let provenance = factual_provenance_digest(
        &context(TICK),
        SCHEDULED,
        "host.fold",
        Hash::zero(),
        FactualRuleV1::FoldCheckpoint,
    );
    assert_eq!(node.provenance_digest(), provenance);
    let expected = sorted(vec![
        head_digest,
        hash(0xa1),
        event_digest(&dependencies, 11),
        event_digest(&dependencies, 18),
    ]);
    assert_eq!(node.input_digests(), expected.as_slice());
    assert_eq!(bound_seqs(&dependencies), [11, 18]);
    let ingress_content = factual_ingress_content_digest(indexed_hash(18), Seq::from_u64(18));
    let schema = factual_event_schema_id(EVENT_TYPE_CONSENT_REVOKED_V1);
    let ingress_digest = host_artifact("host.ingress", 1, schema, ingress_content);
    assert_eq!(event_digest(&dependencies, 18), ingress_digest);
    let snapshot = find(record, "host.observation", 0);
    assert_eq!(snapshot.input_digests(), [artifact(node)]);
    let rule = FactualRuleV1::FoldCheckpoint;
    assert_eq!(
        edge_bytes_between(record, node, head_digest),
        expected_edge(node, head.coordinate(), ENDOGENOUS, rule).as_slice()
    );
    assert_eq!(record.uncovered_input_count(), 0);
}

#[test]
fn a_fold_input_shares_the_ingress_node_of_a_forwarded_event_and_ordinals_follow_seq() {
    let forwarded = vec![FactualInputV1::IngressEvent(Seq::from_u64(12))];
    let mut tick = scheduled(vec![driver(OWNER_A, forwarded, Vec::new())]);
    tick.ingress_events = vec![FactualIngressEventV1 {
        seq: Seq::from_u64(12),
        event_type: FOLD_TYPE.to_owned(),
        payload_hash: indexed_hash(12),
    }];
    let source = fold_source(None, 12, fold_events(11..=12), false);
    let dependencies = ok(assemble_folded(tick, source));
    let record = dependencies.record();
    assert_eq!(bound_seqs(&dependencies), [11, 12]);
    let eleven = event_digest(&dependencies, 11);
    let twelve = event_digest(&dependencies, 12);
    assert_eq!(digest_of(record, "host.ingress", 0), eleven);
    assert_eq!(digest_of(record, "host.ingress", 1), twelve);
    let ingress_nodes = record
        .nodes()
        .iter()
        .filter(|node| node.coordinate().owner_id() == "host.ingress")
        .count();
    assert_eq!(ingress_nodes, 2);
    let step_inputs = find(record, OWNER_A, 0).input_digests();
    assert!(step_inputs.contains(&twelve));
    let node = fold_nodes(&dependencies)[0];
    let content = checkpoint(Hash::zero(), 1, 12, &refs(11..=12));
    assert_eq!(artifact(node), fold_artifact(0, content));
    let expected = sorted(vec![eleven, twelve]);
    assert_eq!(node.input_digests(), expected.as_slice());
}

#[test]
fn a_window_without_fold_inputs_records_no_fold_node_and_the_snapshot_inputs_the_head() {
    let head = fold_head(TICK - 2);
    let head_digest = artifact(&head);
    let excluded = vec![
        typed_fold_event(11, EVENT_TYPE_CONSENT_GRANTED_V1),
        typed_fold_event(12, GEOGRAPHIC_EVENT_TYPE),
    ];
    let source = fold_source(cursor(10, Some(head.clone())), 12, excluded.clone(), false);
    let with_head = folded(source);
    assert_eq!(with_head.fold(), &FactualFoldBindingV1::default());
    let record = with_head.record();
    assert_eq!(record.nodes().len(), 2);
    let snapshot = find(record, "host.observation", 0);
    assert_eq!(snapshot.input_digests(), [head_digest]);
    let rule = FactualRuleV1::ObservationSnapshot;
    assert_eq!(
        edge_bytes_between(record, snapshot, head_digest),
        expected_edge(snapshot, head.coordinate(), ENDOGENOUS, rule).as_slice()
    );
    assert_eq!(record.edges().len(), 2);
    let headless = folded(fold_source(cursor(10, None), 12, excluded, false));
    assert_eq!(headless.fold(), &FactualFoldBindingV1::default());
    let record = headless.record();
    let snapshot = find(record, "host.observation", 0);
    assert!(snapshot.input_digests().is_empty());
    assert_eq!(record.edges().len(), 1);
    let fresh = folded(fold_source(None, 0, Vec::new(), false));
    assert_eq!(fresh.record().nodes().len(), 2);
}

#[test]
fn fold_inputs_split_into_chunks_of_4094_chained_in_seq_order() {
    let one = folded(first_window(4_094, 4_094));
    let nodes = fold_nodes(&one);
    assert_eq!(nodes.len(), 1);
    assert!(one.fold().history.is_empty());
    assert_eq!(nodes[0].input_digests().len(), 4_094);
    let only = fold_artifact(0, checkpoint(Hash::zero(), 1, 4_094, &refs(1..=4_094)));
    assert_eq!(artifact(nodes[0]), only);
    let two = folded(first_window(4_100, 4_095));
    let nodes = fold_nodes(&two);
    assert_eq!(nodes.len(), 2);
    assert_eq!(artifact(nodes[0]), only);
    let second = fold_artifact(1, checkpoint(only, 4_095, 4_100, &refs(4_095..=4_095)));
    assert_eq!(artifact(nodes[1]), second);
    let expected = sorted(vec![only, event_digest(&two, 4_095)]);
    assert_eq!(nodes[1].input_digests(), expected.as_slice());
    let snapshot = find(two.record(), "host.observation", 0);
    assert_eq!(snapshot.input_digests(), [second]);
}

#[test]
fn a_full_fold_part_is_five_nodes_and_one_more_input_collapses_the_oldest() {
    let full = folded(first_window(16_384, 16_384));
    let nodes = fold_nodes(&full);
    assert_eq!(nodes.len(), MAX_FACTUAL_FOLD_CHECKPOINTS_PER_TICK_V1);
    assert!(full.fold().history.is_empty());
    assert_eq!(nodes[4].input_digests().len(), 8 + 1);
    let over = folded(first_window(16_385, 16_385));
    let nodes = fold_nodes(&over);
    assert_eq!(nodes.len(), MAX_FACTUAL_FOLD_CHECKPOINTS_PER_TICK_V1);
    let history = history_digest(&over);
    assert_eq!(history, history_artifact(1, 1));
    let history_node = node_at(&over, over.fold().history[0]);
    assert_eq!(history_node.class(), ENDOGENOUS);
    assert!(history_node.input_digests().is_empty());
    let first = nodes[0];
    assert_eq!(first.input_digests().len(), 4_095);
    assert!(first.input_digests().contains(&history));
    let content = checkpoint(Hash::zero(), 2, 4_095, &refs(2..=4_095));
    assert_eq!(artifact(first), fold_artifact(0, content));
    assert_eq!(over.event_nodes().len(), 16_384);
    assert_eq!(bound_seqs(&over).first(), Some(&2));
}

#[test]
fn a_truncated_window_collapses_its_unscanned_range_into_the_fold_history_node() {
    let granted = |seq| typed_fold_event(seq, EVENT_TYPE_CONSENT_GRANTED_V1);
    let scanned = (1..=65_536).map(granted).collect();
    let all = folded(fold_source(None, 65_536, scanned, false));
    assert_eq!(all.fold(), &FactualFoldBindingV1::default());
    let newest = (2..=65_537).map(granted).collect();
    let collapsed = folded(fold_source(None, 65_537, newest, true));
    let history = history_digest(&collapsed);
    assert_eq!(history, history_artifact(1, 65_537));
    let nodes = fold_nodes(&collapsed);
    assert_eq!(nodes.len(), 1);
    let empty = fold_artifact(0, checkpoint(Hash::zero(), 65_538, 65_537, &[]));
    assert_eq!(artifact(nodes[0]), empty);
    assert_eq!(nodes[0].input_digests(), [history]);
    let tail_source = fold_source(cursor(10, None), 17, fold_events(15..=17), true);
    let tail = folded(tail_source);
    assert_eq!(history_digest(&tail), history_artifact(11, 14));
    let content = checkpoint(Hash::zero(), 15, 17, &refs(15..=17));
    assert_eq!(artifact(fold_nodes(&tail)[0]), fold_artifact(0, content));
    let oversized = (1..=65_537).map(granted).collect();
    assert_eq!(
        refused(fold_source(None, 65_537, oversized, true)),
        FactualError::Record(DepError::FieldOutOfBounds)
    );
}

/// Drivers whose step nodes add exactly `edges` edges to a record.
fn edge_heavy_drivers(edges: usize) -> Vec<FactualDriverStepV1> {
    let per_step = MAX_DEPENDENCY_NODE_INPUTS_V1;
    (0..edges.div_ceil(per_step))
        .map(|index| {
            let inputs = (edges - index * per_step).min(per_step) - 1;
            let owner = format!("plugin:{index}");
            driver(&owner, distinct_priors(inputs), Vec::new())
        })
        .collect()
}

/// Five hundred fold inputs behind `head`, all in one scanned window.
fn five_hundred_after(head: &Node) -> FactualFoldSourceV1 {
    let events = fold_events(1..=500);
    fold_source(cursor(0, Some(head.clone())), 500, events, false)
}

#[test]
fn the_fit_keeps_the_newest_fold_inputs_the_record_has_room_for() {
    let head = fold_head(TICK - 1);
    let head_digest = artifact(&head);
    let rest = edge_heavy_drivers(MAX_TICK_DEPENDENCY_EDGES_V1 - 103);
    let dependencies = ok(assemble_folded(scheduled(rest), five_hundred_after(&head)));
    let edges = dependencies.record().edges().len();
    assert_eq!(edges, MAX_TICK_DEPENDENCY_EDGES_V1);
    assert_eq!(history_digest(&dependencies), history_artifact(1, 400));
    let nodes = fold_nodes(&dependencies);
    assert_eq!(nodes.len(), 1);
    assert_eq!(nodes[0].input_digests().len(), 100 + 2);
    assert!(nodes[0].input_digests().contains(&head_digest));
    let content = checkpoint(head_digest, 401, 500, &refs(401..=500));
    assert_eq!(artifact(nodes[0]), fold_artifact(0, content));
    assert_eq!(bound_seqs(&dependencies), (401..=500).collect::<Vec<_>>());
}

#[test]
fn the_rest_of_a_record_must_leave_the_minimal_fold_part_free() {
    let head = fold_head(TICK - 1);
    let head_digest = artifact(&head);
    let reserve = MAX_TICK_DEPENDENCY_EDGES_V1 - FACTUAL_FOLD_RESERVED_EDGES_V1;
    let rest = edge_heavy_drivers(reserve);
    let minimal = ok(assemble_folded(scheduled(rest), five_hundred_after(&head)));
    let edges = minimal.record().edges().len();
    assert_eq!(edges, MAX_TICK_DEPENDENCY_EDGES_V1);
    assert!(minimal.event_nodes().is_empty());
    let history = history_digest(&minimal);
    assert_eq!(history, history_artifact(1, 500));
    let nodes = fold_nodes(&minimal);
    assert_eq!(nodes.len(), 1);
    let empty = fold_artifact(0, checkpoint(head_digest, 501, 500, &[]));
    assert_eq!(artifact(nodes[0]), empty);
    let expected = sorted(vec![head_digest, history]);
    assert_eq!(nodes[0].input_digests(), expected.as_slice());
    let out_of_bounds = FactualError::Record(DepError::FieldOutOfBounds);
    let crowded = edge_heavy_drivers(reserve + 1);
    let over = assemble_folded(scheduled(crowded), five_hundred_after(&head));
    assert_eq!(err(over), out_of_bounds);
    let mut full = scheduled(Vec::new());
    let node_reserve = MAX_TICK_DEPENDENCY_NODES_V1 - FACTUAL_FOLD_RESERVED_NODES_V1;
    full.ingress_events = (1..=node_reserve)
        .map(|seq| ingress(ok(u64::try_from(seq)), 7))
        .collect();
    let crowded_nodes = assemble_folded(full, fold_source(None, 70_000, Vec::new(), false));
    assert_eq!(err(crowded_nodes), out_of_bounds);
}

#[test]
fn a_fold_window_out_of_order_or_outside_its_range_is_refused() {
    let out_of_bounds = FactualError::Record(DepError::FieldOutOfBounds);
    let descending = fold_source(None, 9, vec![fold_event(3), fold_event(2)], false);
    assert_eq!(refused(descending), out_of_bounds);
    let rescanned = fold_source(cursor(5, None), 9, vec![fold_event(5)], false);
    assert_eq!(refused(rescanned), out_of_bounds);
    let unobserved = fold_source(None, 9, vec![fold_event(10)], false);
    assert_eq!(refused(unobserved), out_of_bounds);
    let regressed = fold_source(cursor(5, None), 4, Vec::new(), false);
    assert_eq!(refused(regressed), out_of_bounds);
    let unchanged = folded(fold_source(cursor(5, None), 5, Vec::new(), false));
    assert_eq!(unchanged.fold(), &FactualFoldBindingV1::default());
    let later = noded_fold_event(3, FOLD_TYPE, event_node(TICK, 0xa3, EXOGENOUS));
    let unresolved = FactualError::UnresolvedInput;
    let unrecorded = fold_source(None, 9, vec![later], false);
    assert_eq!(refused(unrecorded), unresolved);
    let own_head = fold_source(cursor(0, Some(fold_head(TICK))), 9, Vec::new(), false);
    assert_eq!(refused(own_head), unresolved);
}
