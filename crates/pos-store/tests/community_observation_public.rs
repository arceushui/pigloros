//! The pre-Reserve observation materialization preparer (#560 A4b'; ADR-129
//! revision 9, R9.2–R9.7 and R9.10) at its public seam, over the Memory
//! domain: the genesis and full-prefix cuts, the Fork-prefix ownership, the
//! store-side re-checks, the deterministic fold-cost and row bounds, and the
//! stage-2 CPE1 and Observation CPN1.
//!
//! Every expected identity is rebuilt independently with `blake3` and
//! `ciborium` from the ADR formulas and the owner decisions of 2026-11-21
//! (#560).

use std::error::Error as StdError;
use std::sync::Arc;
use std::time::Duration;

use ciborium::Value;
use pos_core::community_lifecycle::{
    community_catalogue_owner_reference_v1, community_observation_materialization_id_v1,
    ArtifactRefV1, CommunityDurableBackendV1, CommunityDurableProfileInputV1,
    CommunityDurableProfileV1, CommunityEventSourceV1, CommunityInputIndexV1,
    CommunityLifecycleErrorV1 as Error, CommunityNativeNodeKindV1, CommunityNativeNodeV1,
    CommunityObservationSourceV1, CommunityObservationValueV1, CommunityProfileMemberV1,
    CommunityProfileRetentionV1, CommunityReducerBindingV1, CommunitySourceCatalogueV1,
    CommunitySourceSchemaRuleV1, CommunityTypedInputRefV1,
};
use pos_core::store::{EventStore, SeqRange};
use pos_core::{
    AuthorityTrustRootSealV1, CanonicalBytes, EntityId, ErasureContainmentGateV1, Event,
    EventDraft, Hash, Hasher, ImplementationKeyV1, Kind, Seq, TimelineId,
};
use pos_crypto::chain::Blake3Hasher;
use pos_store::community::{
    prepare_community_observation_v1, CommunityObservationBindingsV1,
    CommunityObservationConsumerV1, CommunityObservationEventV1,
    CommunityObservationInstallationV1, CommunityObservationMaterializationInputV1,
    CommunityObservationMaterializationV1, CommunityObservationPassV1,
    CommunityObservationSourcesV1, MemoryCommunityDomainV1,
};
use pos_store::memory::MemoryStore;
use pos_store::MemoryTrustedClockAuthorityV1;
use zeroize::Zeroizing;

type Fallible<T> = Result<T, Box<dyn StdError>>;
type TestResult = Fallible<()>;

const SEAL: AuthorityTrustRootSealV1 = AuthorityTrustRootSealV1::for_composition_root();
const INCARNATION: [u8; 16] = [0x5a; 16];
const GENERATION: [u8; 16] = [0x20; 16];
const RESERVATION: [u8; 16] = [0x30; 16];
const ENCODER: u32 = 0x4f42_0001;
const HORIZON: u64 = 5_000;
const EVENT_TYPE: &str = "world.action";
const RULE: CommunitySourceSchemaRuleV1<'static> = CommunitySourceSchemaRuleV1 {
    event_type: EVENT_TYPE,
    schema_version: 1,
    extractor_rule: "pos.community.native-event",
    extractor_rule_version: 1,
};

const fn hash(byte: u8) -> Hash {
    Hash::from_bytes([byte; 32])
}

/// `H(M, bytes)`: BLAKE3 of `PiglorOS.Community.<M>.v1`, a zero byte and
/// the bytes.
fn adr_h(m: &str, bytes: &[u8]) -> Hash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(format!("PiglorOS.Community.{m}.v1\0").as_bytes());
    hasher.update(bytes);
    Hash::from_bytes(*hasher.finalize().as_bytes())
}

fn encode(value: &Value) -> Fallible<Vec<u8>> {
    let mut out = Vec::new();
    ciborium::ser::into_writer(value, &mut out)?;
    Ok(out)
}

fn bytes(value: &[u8]) -> Value {
    Value::Bytes(value.to_vec())
}

const fn id(timeline: TimelineId) -> [u8; 16] {
    timeline.inner().to_bytes()
}

/// One installed profile and catalogue for every case.
struct Installed<'r> {
    implementation: ImplementationKeyV1,
    rules: Vec<CommunitySourceSchemaRuleV1<'r>>,
}

impl<'r> Installed<'r> {
    fn new(rules: Vec<CommunitySourceSchemaRuleV1<'r>>) -> Fallible<Self> {
        Ok(Self {
            implementation: ImplementationKeyV1::new("plugin-a".into(), "host-v1".into(), hash(3))?,
            rules,
        })
    }

    fn catalogue(&self) -> Fallible<CommunitySourceCatalogueV1<'_>> {
        Ok(CommunitySourceCatalogueV1::new(&self.rules)?)
    }

    fn members(&self) -> Fallible<Vec<CommunityProfileMemberV1<'_>>> {
        Ok(vec![CommunityProfileMemberV1::new(
            "Entry-A_1",
            &self.implementation,
            hash(4),
            hash(5),
            hash(6),
            ArtifactRefV1 {
                schema_id: 0x4353_0001,
                byte_length: 9,
                digest: [7; 32],
            },
        )?])
    }
}

fn profile<'a>(
    roster: &'a [CommunityProfileMemberV1<'a>],
    catalogue_digest: Hash,
) -> Fallible<CommunityDurableProfileV1<'a>> {
    Ok(CommunityDurableProfileV1::new(
        CommunityDurableProfileInputV1 {
            backend: CommunityDurableBackendV1::RetainedMemory,
            execution_profile_digest: hash(1),
            roster,
            source_catalogue_digest: catalogue_digest,
            authority_catalogue_digest: hash(9),
            retention: CommunityProfileRetentionV1 {
                generation_not_after_micros: HORIZON,
                recovery_window_micros: 1,
                quarantine_not_after_micros: HORIZON,
                metadata_not_after_micros: HORIZON,
            },
        },
    )?)
}

/// A store with a root Timeline of `events` Events and, if `fork_at` is
/// set, a Fork child of it at that cut. The root's Events and chain hashes
/// are read before the store moves into the domain.
struct History {
    domain: MemoryCommunityDomainV1,
    root: TimelineId,
    child: Option<TimelineId>,
    cut: u64,
    events: Vec<Event>,
    chain: Vec<Hash>,
}

impl History {
    /// The Events visible through `timeline`: the root's, or the child's
    /// inherited prefix.
    fn visible(&self, timeline: TimelineId) -> &[Event] {
        if Some(timeline) == self.child {
            &self.events[..usize::try_from(self.cut).unwrap_or(0)]
        } else {
            &self.events
        }
    }
}

fn history(events: usize, event_type: &str, fork_at: Option<u64>) -> Fallible<History> {
    let mut store = MemoryStore::new();
    store.bind_erasure_gate(Arc::new(ErasureContainmentGateV1::new_test_open()))?;
    let root = store.create_timeline("root")?.id();
    let drafts: Vec<EventDraft> = (0..events)
        .map(|index| {
            EventDraft::new(
                EntityId::new(),
                Kind::new(event_type),
                CanonicalBytes::from_vec(vec![u8::try_from(index % 251).unwrap_or(0)]),
            )
        })
        .collect();
    if !drafts.is_empty() {
        store.append(root, &drafts)?;
    }
    let child = match fork_at {
        Some(at) => Some(store.fork(root, Seq::from_u64(at), "child")?.id()),
        None => None,
    };
    let head = store.logical_head(root)?;
    let stored = if head.as_u64() == 0 {
        Vec::new()
    } else {
        store.read(
            root,
            SeqRange {
                from: Seq::from_u64(1),
                to: Some(head),
            },
        )?
    };
    let chain = (0..=head.as_u64())
        .map(|seq| store.chain_hash_at(root, Seq::from_u64(seq)))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(History {
        domain: MemoryCommunityDomainV1::new(
            store,
            INCARNATION,
            MemoryTrustedClockAuthorityV1::new(),
        )?,
        root,
        child,
        cut: fork_at.unwrap_or(0),
        events: stored,
        chain,
    })
}

const fn consumer(byte: u8, bound: Duration) -> CommunityObservationConsumerV1 {
    CommunityObservationConsumerV1 {
        binding: CommunityReducerBindingV1 {
            consumer_identity_digest: hash(byte),
            schema_digest: hash(0x61),
            reducer_digest: hash(0x62),
            configuration_digest: hash(0x63),
            admission_evidence_digest: hash(0x64),
            minimization_policy_digest: hash(0x65),
        },
        callback_bound: bound,
    }
}

const OBSERVATION: &[u8] = b"observation";

/// The publisher's honest input for `timeline`'s current cut. In these
/// fixtures every Event is committed by the root.
fn honest(history: &History, timeline: TimelineId) -> CommunityObservationMaterializationInputV1 {
    let events = history.visible(timeline);
    let mut scopes = vec![(timeline, hash(0x70))];
    if timeline != history.root && !events.is_empty() {
        scopes.push((history.root, hash(0x71)));
    }
    CommunityObservationMaterializationInputV1 {
        timeline,
        through_seq: events.len() as u64,
        events: events
            .iter()
            .map(|event| CommunityObservationEventV1 {
                owning_timeline: history.root,
                logical_seq: event.seq.as_u64(),
                event_id: event.id.inner().to_bytes(),
                payload_hash: event.payload_hash,
            })
            .collect(),
        consumers: vec![consumer(0x50, Duration::from_millis(1))],
        timeline_scopes: scopes,
        observation_artifact_ref: ArtifactRefV1 {
            schema_id: ENCODER,
            byte_length: OBSERVATION.len() as u64,
            digest: [0x77; 32],
        },
        observation_bytes: Zeroizing::new(OBSERVATION.to_vec()),
    }
}

const fn pass() -> CommunityObservationPassV1 {
    CommunityObservationPassV1 {
        generation: GENERATION,
        reservation_operation_id: RESERVATION,
    }
}

fn prepare(
    history: &History,
    installed: &Installed<'_>,
    input: CommunityObservationMaterializationInputV1,
) -> Fallible<Result<CommunityObservationSourcesV1, Error>> {
    let catalogue = installed.catalogue()?;
    let members = installed.members()?;
    let profile = profile(&members, catalogue.digest())?;
    Ok(prepare_community_observation_v1(
        &history.domain,
        CommunityObservationInstallationV1 {
            profile: &profile,
            source_catalogue: catalogue,
            observation_schema_id: ENCODER,
        },
        pass(),
        &CommunityObservationMaterializationV1::new(&SEAL, input),
    ))
}

/// One whole-Timeline scope row `[scope_ref, U, owner_ref, lease_ref,
/// not_after]`, rebuilt from the owner decision of 2026-11-21 (#560).
fn scope_row(
    scope: Hash,
    owner_timeline: TimelineId,
    pass_timeline: TimelineId,
    profile: &CommunityDurableProfileV1<'_>,
) -> Fallible<Value> {
    let owner = community_catalogue_owner_reference_v1(pass_timeline, GENERATION)?;
    let retention = encode(&Value::Array(
        [HORIZON, 1, HORIZON, HORIZON]
            .into_iter()
            .map(|value| Value::Integer(value.into()))
            .collect(),
    ))?;
    let lease = adr_h("RetentionPolicy", &retention);
    assert_eq!(profile.retention_policy_digest(), lease);
    Ok(Value::Array(vec![
        bytes(scope.as_bytes()),
        bytes(&id(owner_timeline)),
        bytes(owner.as_bytes()),
        bytes(lease.as_bytes()),
        Value::Integer(HORIZON.into()),
    ]))
}

fn scope_set(rows: Vec<Value>) -> Fallible<Hash> {
    Ok(adr_h("ScopeSet", &encode(&Value::Array(rows))?))
}

const fn bindings<'a>(
    registrations: &'a [Hash],
    authority: &'a [(TimelineId, Hash)],
) -> CommunityObservationBindingsV1<'a> {
    CommunityObservationBindingsV1 {
        store_incarnation: INCARNATION,
        producer_ordinal: 9,
        source_registrations: registrations,
        scope_binding_digest: hash(0x80),
        provenance_digest: hash(0x81),
        authority_rows: authority,
    }
}

fn authority_digest(rows: &[(TimelineId, Hash)]) -> Fallible<Hash> {
    let rows = rows
        .iter()
        .map(|(timeline, request)| {
            Value::Array(vec![bytes(&id(*timeline)), bytes(request.as_bytes())])
        })
        .collect();
    Ok(adr_h("EventSourceAuthority", &encode(&Value::Array(rows))?))
}

#[test]
fn an_empty_timeline_yields_the_genesis_cut_with_one_source_genesis_input() -> TestResult {
    let history = history(0, EVENT_TYPE, None)?;
    let installed = Installed::new(vec![RULE])?;
    assert_eq!(history.chain[0], Blake3Hasher.genesis_hash());
    let sources = prepare(&history, &installed, honest(&history, history.root))??;
    assert_eq!(sources.event_sources().count(), 0);
    assert_eq!(sources.owning_timelines(), [history.root]);
    let value = CommunityObservationValueV1::from_canonical_cbor(sources.observation_value())?;
    assert_eq!(value.as_input().observation_bytes, OBSERVATION);
    assert_eq!(value.digest(), sources.observation_value_digest());
    let authority = [(history.root, hash(0x90))];
    let records = sources.finish(bindings(&[], &authority))?;
    let proof = CommunityObservationSourceV1::from_canonical_cbor(&records.source_proof)?;
    assert_eq!(proof.from_seq(), 0);
    assert_eq!(proof.as_input().through_seq, 0);
    assert!(proof.as_input().event_rows.is_empty());
    assert_eq!(proof.as_input().scope_union_digest, scope_set(Vec::new())?);
    assert_eq!(
        proof.as_input().authority_request_digest,
        authority_digest(&authority)?
    );
    assert_eq!(proof.as_input().observation_value_digest, value.digest());
    assert_eq!(
        records.source_proof_digest,
        adr_h("CPE1", &records.source_proof)
    );
    assert!(records.input_groups.is_empty());
    let node = CommunityNativeNodeV1::from_canonical_cbor(&records.observation_node)?;
    assert!(node.as_input().kind == CommunityNativeNodeKindV1::Observation);
    assert_eq!(node.as_input().content.record_magic, *b"COV1");
    assert_eq!(
        node.as_input().authorization_digest,
        authority_digest(&authority)?
    );
    let CommunityInputIndexV1::Direct(inputs) = node.as_input().input_index else {
        return Err("direct".into());
    };
    let inputs: Vec<_> = inputs.iter().collect::<Result<_, _>>()?;
    assert!(
        inputs
            == [CommunityTypedInputRefV1::SourceGenesis {
                timeline: history.root,
                genesis_chain_hash: history.chain[0],
            }]
    );
    assert!(records.observation_reference == node.reference());
    Ok(())
}

#[test]
fn a_full_prefix_mints_one_exact_ces1_per_event_and_the_cpe1_rows() -> TestResult {
    let history = history(3, EVENT_TYPE, None)?;
    let root = history.root;
    let installed = Installed::new(vec![RULE])?;
    let catalogue = installed.catalogue()?;
    let members = installed.members()?;
    let profile = profile(&members, catalogue.digest())?;
    let sources = prepare(&history, &installed, honest(&history, root))??;
    let stored = &history.events;
    let row = scope_row(hash(0x70), root, root, &profile)?;
    let scope = scope_set(vec![row])?;
    let owner = community_catalogue_owner_reference_v1(root, GENERATION)?;
    let ces1: Vec<Vec<u8>> = sources.event_sources().map(<[u8]>::to_vec).collect();
    assert_eq!(ces1.len(), 3);
    for (bytes, event) in ces1.iter().zip(stored) {
        let source = CommunityEventSourceV1::from_canonical_cbor(bytes)?;
        let fields = source.as_input();
        assert_eq!(fields.timeline, root);
        assert_eq!(fields.logical_seq, event.seq.as_u64());
        assert_eq!(fields.event_id, event.id.inner().to_bytes());
        assert_eq!(fields.payload_hash, event.payload_hash);
        assert_eq!(
            fields.event_envelope_digest,
            history.chain[usize::try_from(event.seq.as_u64())?]
        );
        assert_eq!(fields.owner_reference, owner);
        assert_eq!(fields.source_scope_binding_digest, scope);
        assert_eq!(fields.source_schema_rule, RULE);
        assert!(fields.required_key_dependencies.is_empty());
        assert_eq!(fields.admitted_policy_digest, catalogue.digest());
        assert_eq!(fields.evidence_not_after_micros, HORIZON);
    }
    let registrations = [hash(0xa1), hash(0xa2), hash(0xa3)];
    let authority = [(root, hash(0x90))];
    let records = sources.finish(bindings(&registrations, &authority))?;
    let proof = CommunityObservationSourceV1::from_canonical_cbor(&records.source_proof)?;
    let input = proof.as_input();
    assert_eq!((proof.from_seq(), input.through_seq), (1, 3));
    assert_eq!(input.scope_union_digest, scope);
    for ((row, registration), bytes) in input.event_rows.iter().zip(registrations).zip(&ces1) {
        assert_eq!(row.source.artifact_digest, adr_h("CES1", bytes));
        assert_eq!(row.source.registration_address, registration);
        assert_eq!(row.source.owner_reference, owner);
        assert_eq!(row.source.source_scope_binding_digest, scope);
    }
    let consumers = encode(&Value::Array(vec![bytes(hash(0x50).as_bytes())]))?;
    assert_eq!(
        proof.recorded_consumer_set_digest(),
        adr_h("RecordedConsumerSet", &consumers)
    );
    let node = CommunityNativeNodeV1::from_canonical_cbor(&records.observation_node)?;
    let CommunityInputIndexV1::Direct(inputs) = node.as_input().input_index else {
        return Err("direct".into());
    };
    assert_eq!(inputs.len(), 3);
    Ok(())
}

#[test]
fn a_fork_child_names_parent_owned_sources_and_needs_both_scopes() -> TestResult {
    let history = history(2, EVENT_TYPE, Some(2))?;
    let child = history.child.ok_or("child")?;
    let installed = Installed::new(vec![RULE])?;
    let sources = prepare(&history, &installed, honest(&history, child))??;
    for bytes in sources.event_sources() {
        assert_eq!(
            CommunityEventSourceV1::from_canonical_cbor(bytes)?
                .as_input()
                .timeline,
            history.root
        );
    }
    let mut owners = vec![history.root, child];
    owners.sort_by_key(|timeline| id(*timeline));
    assert_eq!(sources.owning_timelines(), owners.as_slice());
    let authority: Vec<_> = owners.iter().map(|owner| (*owner, hash(0x90))).collect();
    let records = sources.finish(bindings(&[hash(1), hash(2)], &authority))?;
    let proof = CommunityObservationSourceV1::from_canonical_cbor(&records.source_proof)?;
    assert_eq!(
        proof.as_input().authority_request_digest,
        authority_digest(&authority)?
    );
    assert_eq!(
        sources
            .finish(bindings(&[hash(1), hash(2)], &authority[..1]))
            .err(),
        Some(Error::InvalidBinding)
    );
    for edit in [
        |input: &mut CommunityObservationMaterializationInputV1| {
            input.timeline_scopes.pop();
        },
        |input: &mut CommunityObservationMaterializationInputV1| {
            input.timeline_scopes.push((TimelineId::new(), hash(0x72)));
        },
        |input: &mut CommunityObservationMaterializationInputV1| {
            let first = input.timeline_scopes[0];
            input.timeline_scopes.push(first);
        },
        |input: &mut CommunityObservationMaterializationInputV1| {
            input.timeline_scopes[0].1 = Hash::zero();
        },
        |input: &mut CommunityObservationMaterializationInputV1| {
            input.events[0].owning_timeline = input.timeline;
        },
    ] {
        let mut input = honest(&history, child);
        edit(&mut input);
        assert_eq!(
            prepare(&history, &installed, input)?.err(),
            Some(Error::EvidenceUnavailable)
        );
    }
    Ok(())
}

#[test]
fn every_row_head_catalogue_and_encoder_mismatch_refuses_with_12() -> TestResult {
    type Edit = fn(&mut CommunityObservationMaterializationInputV1);
    let history = history(3, EVENT_TYPE, None)?;
    let root = history.root;
    let installed = Installed::new(vec![RULE])?;
    let edits: [Edit; 7] = [
        |input| input.events[1].payload_hash = hash(0xee),
        |input| input.events[1].event_id = [0xee; 16],
        |input| input.events[1].logical_seq = 3,
        |input| input.events.swap(0, 1),
        |input| {
            input.events.pop();
        },
        |input| {
            input.through_seq = 2;
            input.events.pop();
        },
        |input| input.observation_artifact_ref.schema_id = ENCODER + 1,
    ];
    for edit in edits {
        let mut input = honest(&history, root);
        edit(&mut input);
        assert_eq!(
            prepare(&history, &installed, input)?.err(),
            Some(Error::EvidenceUnavailable)
        );
    }
    // An Event type the catalogue does not pin, and a pinned row whose
    // extractor rule is not the V1 native-event rule.
    for rules in [
        vec![CommunitySourceSchemaRuleV1 {
            schema_version: 2,
            ..RULE
        }],
        vec![CommunitySourceSchemaRuleV1 {
            extractor_rule_version: 2,
            ..RULE
        }],
        vec![CommunitySourceSchemaRuleV1 {
            extractor_rule: "pos.community.other",
            ..RULE
        }],
    ] {
        let other = Installed::new(rules)?;
        assert_eq!(
            prepare(&history, &other, honest(&history, root))?.err(),
            Some(Error::EvidenceUnavailable)
        );
    }
    // A catalogue that is not the CDP1-pinned one.
    let catalogue = installed.catalogue()?;
    let members = installed.members()?;
    let foreign = profile(&members, hash(0x99))?;
    assert_eq!(
        prepare_community_observation_v1(
            &history.domain,
            CommunityObservationInstallationV1 {
                profile: &foreign,
                source_catalogue: catalogue,
                observation_schema_id: ENCODER,
            },
            pass(),
            &CommunityObservationMaterializationV1::new(&SEAL, honest(&history, root)),
        )
        .err(),
        Some(Error::EvidenceUnavailable)
    );
    // An unknown Timeline.
    let mut input = honest(&history, root);
    input.timeline = TimelineId::new();
    assert_eq!(
        prepare(&history, &installed, input)?.err(),
        Some(Error::EvidenceUnavailable)
    );
    Ok(())
}

#[test]
fn the_fold_cost_and_row_bounds_refuse_with_14_before_any_recheck() -> TestResult {
    let history = history(0, EVENT_TYPE, None)?;
    let installed = Installed::new(vec![RULE])?;
    let at = |through_seq: u64,
              consumers: Vec<CommunityObservationConsumerV1>|
     -> Fallible<Option<Error>> {
        let mut input = honest(&history, history.root);
        input.through_seq = through_seq;
        input.consumers = consumers;
        Ok(prepare(&history, &installed, input)?.err())
    };
    // One consumer at 10 ms: 1,199 Events fit 12 s exactly and reach the
    // re-check (12); 1,200 exceed it (14). I83.
    let ten = vec![consumer(0x50, Duration::from_millis(10))];
    assert_eq!(at(1_199, ten.clone())?, Some(Error::EvidenceUnavailable));
    assert_eq!(at(1_200, ten)?, Some(Error::CapacityExhausted));
    // 64 consumers at 250 ms exceed the budget even for an empty cut.
    let many: Vec<_> = (0..64)
        .map(|byte| consumer(byte, Duration::from_millis(250)))
        .collect();
    assert_eq!(at(0, many)?, Some(Error::CapacityExhausted));
    // 4,096 rows reach the re-check; 4,097 are refused (I63).
    let free = vec![consumer(0x50, Duration::from_nanos(1))];
    assert_eq!(at(4_096, free.clone())?, Some(Error::EvidenceUnavailable));
    assert_eq!(at(4_097, free)?, Some(Error::CapacityExhausted));
    Ok(())
}

#[test]
fn a_prefix_over_256_events_groups_its_inputs_by_input_index_nodes() -> TestResult {
    let history = history(300, EVENT_TYPE, None)?;
    let installed = Installed::new(vec![RULE])?;
    let mut input = honest(&history, history.root);
    input.consumers = vec![consumer(0x50, Duration::from_micros(1))];
    let sources = prepare(&history, &installed, input)??;
    let registrations: Vec<Hash> = (1..=300_u16)
        .map(|index| {
            let mut bytes = [0xab; 32];
            bytes[..2].copy_from_slice(&index.to_be_bytes());
            Hash::from_bytes(bytes)
        })
        .collect();
    let authority = [(history.root, hash(0x90))];
    let records = sources.finish(bindings(&registrations, &authority))?;
    assert_eq!(records.input_groups.len(), 2);
    for (ordinal, (_group, node)) in (0_u32..).zip(&records.input_groups) {
        let node = CommunityNativeNodeV1::from_canonical_cbor(node)?;
        assert!(node.as_input().kind == CommunityNativeNodeKindV1::InputIndex);
        assert_eq!(node.as_input().node_ordinal, ordinal);
    }
    let node = CommunityNativeNodeV1::from_canonical_cbor(&records.observation_node)?;
    assert_eq!(node.as_input().node_ordinal, 2);
    let CommunityInputIndexV1::Grouped {
        total_leaf_count, ..
    } = node.as_input().input_index
    else {
        return Err("grouped".into());
    };
    assert_eq!(total_leaf_count, 300);
    assert_eq!(
        sources
            .finish(bindings(&registrations[1..], &authority))
            .err(),
        Some(Error::InvalidBinding)
    );
    Ok(())
}

#[test]
fn stage_inputs_that_cannot_mint_their_records_are_refused() -> TestResult {
    let history = history(1, EVENT_TYPE, None)?;
    let installed = Installed::new(vec![RULE])?;
    // A COV1 reference whose length is not the payload's.
    let mut input = honest(&history, history.root);
    input.observation_artifact_ref.byte_length += 1;
    assert_eq!(
        prepare(&history, &installed, input)?.err(),
        Some(Error::InvalidBinding)
    );
    // A zero reservation cannot derive M_id.
    let catalogue = installed.catalogue()?;
    let members = installed.members()?;
    let profile = profile(&members, catalogue.digest())?;
    let installation = CommunityObservationInstallationV1 {
        profile: &profile,
        source_catalogue: catalogue,
        observation_schema_id: ENCODER,
    };
    assert_eq!(
        prepare_community_observation_v1(
            &history.domain,
            installation,
            CommunityObservationPassV1 {
                generation: GENERATION,
                reservation_operation_id: [0; 16],
            },
            &CommunityObservationMaterializationV1::new(&SEAL, honest(&history, history.root)),
        )
        .err(),
        Some(Error::InvalidBinding)
    );
    let sources = prepare(&history, &installed, honest(&history, history.root))??;
    // A zero `read` request digest, and a zero CES1 registration address.
    assert_eq!(
        sources
            .finish(bindings(&[hash(1)], &[(history.root, Hash::zero())]))
            .err(),
        Some(Error::InvalidBinding)
    );
    assert_eq!(
        sources
            .finish(bindings(&[Hash::zero()], &[(history.root, hash(0x90))]))
            .err(),
        Some(Error::InvalidBinding)
    );
    // A zero CSB1 digest refuses the Observation CPN1.
    let registrations = [hash(1)];
    let authority = [(history.root, hash(0x90))];
    let mut zero_scope = bindings(&registrations, &authority);
    zero_scope.scope_binding_digest = Hash::zero();
    assert_eq!(
        sources.finish(zero_scope).err(),
        Some(Error::InvalidBinding)
    );
    assert_eq!(
        sources.operation_id(),
        community_observation_materialization_id_v1(history.root, RESERVATION)?
    );
    Ok(())
}

#[test]
fn the_sealed_consumer_list_must_be_an_admitted_set_before_its_cost_is_trusted() -> TestResult {
    let history = history(0, EVENT_TYPE, None)?;
    let installed = Installed::new(vec![RULE])?;
    let with = |through_seq: u64,
                consumers: Vec<CommunityObservationConsumerV1>|
     -> Fallible<Option<Error>> {
        let mut input = honest(&history, history.root);
        input.through_seq = through_seq;
        input.consumers = consumers;
        Ok(prepare(&history, &installed, input)?.err())
    };
    let max = Duration::from_millis(250);
    let one_ns = Duration::from_nanos(1);
    // 250 ms is the admitted maximum; one nanosecond over, a zero bound, no
    // consumer, 65 consumers, and an unsorted or repeated list are refused.
    assert_eq!(with(0, vec![consumer(0x50, max)])?, None);
    for consumers in [
        vec![consumer(0x50, max + one_ns)],
        vec![consumer(0x50, Duration::ZERO)],
        Vec::new(),
        (0..65).map(|byte| consumer(byte, one_ns)).collect(),
        vec![consumer(0x52, one_ns), consumer(0x51, one_ns)],
        vec![consumer(0x51, one_ns), consumer(0x51, one_ns)],
    ] {
        assert_eq!(with(0, consumers)?, Some(Error::EvidenceUnavailable));
    }
    let sixty_four: Vec<_> = (0..64).map(|byte| consumer(byte, one_ns)).collect();
    assert_eq!(with(0, sixty_four)?, None);
    // The cost rounds up to whole microseconds: 1,200 callbacks of
    // 10 ms + 1 ns exceed 12 s, though each bound floors to 10,000 µs.
    assert_eq!(
        with(
            1_199,
            vec![consumer(0x50, Duration::from_millis(10) + one_ns)]
        )?,
        Some(Error::CapacityExhausted)
    );
    // A sub-microsecond bound still costs at least one microsecond in total.
    assert_eq!(with(0, vec![consumer(0x50, one_ns)])?, None);
    Ok(())
}

/// A store whose root holds one Event of `event_type` and `payload` bytes.
fn single(event_type: &str, payload: usize) -> Fallible<History> {
    let mut store = MemoryStore::new();
    store.bind_erasure_gate(Arc::new(ErasureContainmentGateV1::new_test_open()))?;
    let root = store.create_timeline("root")?.id();
    let events = store.append(
        root,
        &[EventDraft::new(
            EntityId::new(),
            Kind::new(event_type),
            CanonicalBytes::from_vec(vec![7; payload]),
        )],
    )?;
    Ok(History {
        domain: MemoryCommunityDomainV1::new(
            store,
            INCARNATION,
            MemoryTrustedClockAuthorityV1::new(),
        )?,
        root,
        child: None,
        cut: 0,
        events,
        chain: Vec::new(),
    })
}

#[test]
fn history_reads_are_bounded_by_the_owner_read_bounds_and_fork_depth() -> TestResult {
    // Owner 2026-11-21 (#560): a 1 MiB payload per Event, a 128-byte Event
    // type and a Fork depth of 64.
    let installed = Installed::new(vec![RULE])?;
    let exact = single(EVENT_TYPE, 1 << 20)?;
    assert!(prepare(&exact, &installed, honest(&exact, exact.root))?.is_ok());
    let over = single(EVENT_TYPE, (1 << 20) + 1)?;
    assert_eq!(
        prepare(&over, &installed, honest(&over, over.root))?.err(),
        Some(Error::CapacityExhausted)
    );
    let long_text = "t".repeat(128);
    let long = long_text.as_str();
    let long_rule = Installed::new(vec![CommunitySourceSchemaRuleV1 {
        event_type: long,
        ..RULE
    }])?;
    let at_limit = single(long, 1)?;
    assert!(prepare(&at_limit, &long_rule, honest(&at_limit, at_limit.root))?.is_ok());
    let too_long = single(&"t".repeat(129), 1)?;
    assert_eq!(
        prepare(&too_long, &installed, honest(&too_long, too_long.root))?.err(),
        Some(Error::EvidenceUnavailable)
    );
    // 64 nested Forks are read; a 65th is refused before reading.
    let mut store = MemoryStore::new();
    store.bind_erasure_gate(Arc::new(ErasureContainmentGateV1::new_test_open()))?;
    let root = store.create_timeline("root")?.id();
    let mut chain = vec![root];
    for depth in 1..=65 {
        let parent = chain[chain.len() - 1];
        chain.push(
            store
                .fork(parent, Seq::ZERO, &format!("fork-{depth}"))?
                .id(),
        );
    }
    let deep = History {
        domain: MemoryCommunityDomainV1::new(
            store,
            INCARNATION,
            MemoryTrustedClockAuthorityV1::new(),
        )?,
        root,
        child: None,
        cut: 0,
        events: Vec::new(),
        chain: Vec::new(),
    };
    assert!(prepare(&deep, &installed, honest(&deep, chain[64]))?.is_ok());
    assert_eq!(
        prepare(&deep, &installed, honest(&deep, chain[65]))?.err(),
        Some(Error::EvidenceUnavailable)
    );
    Ok(())
}

#[test]
fn an_empty_fork_child_names_its_fork_chain_root_genesis() -> TestResult {
    let history = history(0, EVENT_TYPE, Some(0))?;
    let child = history.child.ok_or("child")?;
    let installed = Installed::new(vec![RULE])?;
    let sources = prepare(&history, &installed, honest(&history, child))??;
    assert_eq!(sources.owning_timelines(), [child]);
    let authority = [(child, hash(0x90))];
    let records = sources.finish(bindings(&[], &authority))?;
    let node = CommunityNativeNodeV1::from_canonical_cbor(&records.observation_node)?;
    let CommunityInputIndexV1::Direct(inputs) = node.as_input().input_index else {
        return Err("direct".into());
    };
    let inputs: Vec<_> = inputs.iter().collect::<Result<_, _>>()?;
    assert!(
        inputs
            == [CommunityTypedInputRefV1::SourceGenesis {
                timeline: history.root,
                genesis_chain_hash: Blake3Hasher.genesis_hash(),
            }]
    );
    // The root, which owns no Event of the empty cut, needs no scope ref.
    let mut extra = honest(&history, child);
    extra.timeline_scopes.push((history.root, hash(0x71)));
    assert_eq!(
        prepare(&history, &installed, extra)?.err(),
        Some(Error::EvidenceUnavailable)
    );
    Ok(())
}
