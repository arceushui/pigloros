use pos_core::{
    clock::{Seq, WallTime},
    crypto::Hash,
    event::{CanonicalBytes, Event, EventDraft, Kind, SchemaVersion},
    ids::{EntityId, EventId, PluginId, TimelineId},
};
use pos_plugin_agent::{
    protocol::{
        ActionCatalogueV1, AgentProviderProvenanceV1, BoundedProviderBytes, DecisionRecordV1,
        ProviderAttempt, ProviderFailureCode,
    },
    AgentDecisionReplayVerifier, FixtureAgentDecisionProvider, ProviderBackedAgentDriver,
    ReplayCheckpoint, ReplayVerificationError, EVENT_TYPE_ACTION,
};
use pos_runtime::{
    recorder::RECORDER_EVENT_TYPE, Driver, ObservationView, PluginRegistry, RuntimeError,
    StepOutput, TimelineHistorySegment,
};
use ulid::Ulid;

const PLUGIN_VERSION: &str = "1.0.0";
const PROVIDER_ID: &str = "fixture-1";
const PROVIDER_VERSION: &str = "v1";
const PLUGIN_HASH: [u8; 32] = [0x31; 32];
const PROVIDER_HASH: [u8; 32] = [0x32; 32];

#[derive(Clone)]
struct HostFixture {
    timeline: TimelineId,
    agent: EntityId,
    other_agent: EntityId,
    plugin: PluginId,
    catalogue: ActionCatalogueV1,
    provenance: AgentProviderProvenanceV1,
    catalogue_hash: [u8; 32],
}

impl HostFixture {
    fn new() -> Self {
        let timeline = TimelineId::from_ulid(fixed_ulid(0x10));
        let agent = EntityId::from_ulid(fixed_ulid(0x20));
        let other_agent = EntityId::from_ulid(fixed_ulid(0x21));
        let plugin = PluginId::from_ulid(fixed_ulid(0x30));
        let catalogue = ActionCatalogueV1::try_new(vec!["move".to_owned(), "wait".to_owned()])
            .expect("fixture catalogue is valid");
        let provenance = AgentProviderProvenanceV1::try_new(
            plugin,
            PLUGIN_VERSION.to_owned(),
            PLUGIN_HASH,
            PROVIDER_ID.to_owned(),
            PROVIDER_VERSION.to_owned(),
            PROVIDER_HASH,
        )
        .expect("fixture provenance is valid");
        let catalogue_hash = catalogue_hash(&["move", "wait"]);
        Self {
            timeline,
            agent,
            other_agent,
            plugin,
            catalogue,
            provenance,
            catalogue_hash,
        }
    }

    fn verifier(&self) -> AgentDecisionReplayVerifier {
        AgentDecisionReplayVerifier::try_new_with_timeline_ancestry(
            vec![TimelineHistorySegment::new(
                self.timeline,
                Seq::from_u64(32),
            )],
            self.agent,
            self.provenance.clone(),
            self.catalogue.clone(),
        )
        .unwrap()
    }

    fn record(&self, observed_through: u64, tick: u64, result: FixtureResult) -> RecordFixture {
        RecordFixture {
            timeline: self.timeline,
            observed_through,
            agent: self.agent,
            driver_tick: tick,
            catalogue_hash: self.catalogue_hash,
            plugin: self.plugin,
            plugin_version: PLUGIN_VERSION.to_owned(),
            plugin_hash: PLUGIN_HASH,
            provider_id: PROVIDER_ID.to_owned(),
            provider_version: PROVIDER_VERSION.to_owned(),
            provider_hash: PROVIDER_HASH,
            response_digest: match result {
                FixtureResult::Accepted { .. } | FixtureResult::NoAction { code: 7..=9 } => {
                    Some([0x42; 32])
                }
                FixtureResult::NoAction { .. } => None,
            },
            result,
            request_hash_override: None,
        }
    }
}

#[derive(Clone, Copy)]
enum FixtureResult {
    Accepted { action_index: u8, confidence: u32 },
    NoAction { code: u8 },
}

#[derive(Clone)]
struct RecordFixture {
    timeline: TimelineId,
    observed_through: u64,
    agent: EntityId,
    driver_tick: u64,
    catalogue_hash: [u8; 32],
    plugin: PluginId,
    plugin_version: String,
    plugin_hash: [u8; 32],
    provider_id: String,
    provider_version: String,
    provider_hash: [u8; 32],
    response_digest: Option<[u8; 32]>,
    result: FixtureResult,
    request_hash_override: Option<[u8; 32]>,
}

impl RecordFixture {
    fn request_bytes(&self) -> Vec<u8> {
        let mut output = IndependentCbor::default();
        output.array(13);
        output.bytes(b"PQR1");
        output.uint(1);
        self.write_request_fields(&mut output);
        output.finish()
    }

    fn request_hash(&self) -> [u8; 32] {
        blake3::derive_key("pigloros.agent.request.v1", &self.request_bytes())
    }

    fn record_bytes(&self) -> Vec<u8> {
        let mut output = IndependentCbor::default();
        output.array(16);
        output.bytes(b"PDR1");
        output.uint(1);
        self.write_request_fields(&mut output);
        output.bytes(
            &self
                .request_hash_override
                .unwrap_or_else(|| self.request_hash()),
        );
        if let Some(digest) = self.response_digest {
            output.array(2);
            output.uint(1);
            output.bytes(&digest);
        } else {
            output.array(1);
            output.uint(0);
        }
        match self.result {
            FixtureResult::Accepted {
                action_index,
                confidence,
            } => {
                output.array(3);
                output.uint(0);
                output.uint(u64::from(action_index));
                output.uint(u64::from(confidence));
            }
            FixtureResult::NoAction { code } => {
                output.array(2);
                output.uint(1);
                output.uint(u64::from(code));
            }
        }
        output.finish()
    }

    fn record_hash(&self) -> [u8; 32] {
        blake3::derive_key("pigloros.agent.record.v1", &self.record_bytes())
    }

    fn action_bytes(&self, action_id: &str, confidence: u32) -> Vec<u8> {
        action_bytes(
            action_id,
            confidence,
            self.driver_tick,
            self.catalogue_hash,
            self.record_hash(),
        )
    }

    fn write_request_fields(&self, output: &mut IndependentCbor) {
        output.bytes(&self.timeline.inner().to_bytes());
        output.uint(self.observed_through);
        output.bytes(&self.agent.inner().to_bytes());
        output.uint(self.driver_tick);
        output.bytes(&self.catalogue_hash);
        output.bytes(&self.plugin.inner().to_bytes());
        output.text(&self.plugin_version);
        output.bytes(&self.plugin_hash);
        output.text(&self.provider_id);
        output.text(&self.provider_version);
        output.bytes(&self.provider_hash);
    }
}

#[derive(Default)]
struct IndependentCbor(Vec<u8>);

impl IndependentCbor {
    fn array(&mut self, length: u64) {
        self.major(4, length);
    }

    fn bytes(&mut self, value: &[u8]) {
        self.major(
            2,
            u64::try_from(value.len()).expect("fixture length fits u64"),
        );
        self.0.extend_from_slice(value);
    }

    fn text(&mut self, value: &str) {
        self.major(
            3,
            u64::try_from(value.len()).expect("fixture length fits u64"),
        );
        self.0.extend_from_slice(value.as_bytes());
    }

    fn uint(&mut self, value: u64) {
        self.major(0, value);
    }

    fn major(&mut self, major: u8, value: u64) {
        let prefix = major << 5;
        match value {
            0..=23 => self
                .0
                .push(prefix | u8::try_from(value).expect("direct value fits u8")),
            24..=0xff => {
                self.0.push(prefix | 0x18);
                self.0
                    .push(u8::try_from(value).expect("one-byte value fits u8"));
            }
            0x100..=0xffff => {
                self.0.push(prefix | 0x19);
                self.0.extend_from_slice(
                    &u16::try_from(value)
                        .expect("two-byte value fits u16")
                        .to_be_bytes(),
                );
            }
            0x1_0000..=0xffff_ffff => {
                self.0.push(prefix | 0x1a);
                self.0.extend_from_slice(
                    &u32::try_from(value)
                        .expect("four-byte value fits u32")
                        .to_be_bytes(),
                );
            }
            _ => {
                self.0.push(prefix | 0x1b);
                self.0.extend_from_slice(&value.to_be_bytes());
            }
        }
    }

    fn finish(self) -> Vec<u8> {
        self.0
    }
}

fn fixed_ulid(seed: u8) -> Ulid {
    let mut bytes = [seed; 16];
    bytes[15] = seed.wrapping_add(1);
    Ulid::from(bytes)
}

fn catalogue_hash(actions: &[&str]) -> [u8; 32] {
    let mut output = IndependentCbor::default();
    output.array(3);
    output.bytes(b"PAC1");
    output.uint(1);
    output.array(u64::try_from(actions.len()).expect("fixture action count fits u64"));
    for action in actions {
        output.text(action);
    }
    blake3::derive_key("pigloros.agent.catalogue.v1", &output.finish())
}

fn action_bytes(
    action_id: &str,
    confidence: u32,
    driver_tick: u64,
    catalogue_hash: [u8; 32],
    record_hash: [u8; 32],
) -> Vec<u8> {
    let mut output = IndependentCbor::default();
    output.array(7);
    output.bytes(b"PAA1");
    output.uint(1);
    output.text(action_id);
    output.uint(u64::from(confidence));
    output.uint(driver_tick);
    output.bytes(&catalogue_hash);
    output.bytes(&record_hash);
    output.finish()
}

fn provider_accepted_bytes(action_index: u8, confidence: u32) -> Vec<u8> {
    let mut output = IndependentCbor::default();
    output.array(5);
    output.bytes(b"PDP1");
    output.uint(1);
    output.uint(0);
    output.uint(u64::from(action_index));
    output.uint(u64::from(confidence));
    output.finish()
}

fn event(seq: u64, entity: EntityId, event_type: &str, payload: Vec<u8>) -> Event {
    Event {
        id: EventId::from_ulid(Ulid::from(u128::from(seq) + 0x100)),
        entity,
        event_type: Kind::new(event_type),
        payload: CanonicalBytes::from_vec(payload),
        wall_time: WallTime::from_micros(1_000 + seq),
        seq: Seq::from_u64(seq),
        causation_id: None,
        correlation_id: None,
        schema_version: SchemaVersion::V1,
        signature: None,
        payload_hash: Hash::from_bytes([u8::try_from(seq).unwrap_or(0xff); 32]),
    }
}

fn accepted_events(host: &HostFixture) -> Vec<Event> {
    let record = host.record(
        0,
        0,
        FixtureResult::Accepted {
            action_index: 0,
            confidence: 750_000,
        },
    );
    vec![
        event(1, host.agent, RECORDER_EVENT_TYPE, record.record_bytes()),
        event(
            2,
            host.agent,
            EVENT_TYPE_ACTION,
            record.action_bytes("move", 750_000),
        ),
    ]
}

struct PrecedingDriver {
    entity: EntityId,
}

impl Driver for PrecedingDriver {
    fn step(
        &mut self,
        _timeline: TimelineId,
        _observations: ObservationView<'_>,
    ) -> Result<StepOutput, RuntimeError> {
        Ok(StepOutput::new(vec![EventDraft::new(
            self.entity,
            Kind::new("world.observation"),
            CanonicalBytes::from_vec(vec![0x80]),
        )]))
    }

    fn name(&self) -> &'static str {
        "preceding-replay-fixture"
    }
}

#[test]
fn verifier_constructor_has_only_host_owned_replay_inputs() {
    let constructor: fn(
        Vec<TimelineHistorySegment>,
        EntityId,
        AgentProviderProvenanceV1,
        ActionCatalogueV1,
    ) -> Result<
        AgentDecisionReplayVerifier,
        pos_plugin_agent::ReplayVerificationError,
    > = AgentDecisionReplayVerifier::try_new_with_timeline_ancestry;
    let checkpoint_reader: fn(ReplayCheckpoint) -> Seq = ReplayCheckpoint::last_verified;

    let _ = (constructor, checkpoint_reader);
}

#[test]
fn verifier_rejects_empty_duplicate_and_decreasing_timeline_ancestry() {
    let host = HostFixture::new();
    let child = TimelineId::new();
    let constructor = |segments| {
        AgentDecisionReplayVerifier::try_new_with_timeline_ancestry(
            segments,
            host.agent,
            host.provenance.clone(),
            host.catalogue.clone(),
        )
    };

    for segments in [
        vec![],
        vec![
            TimelineHistorySegment::new(host.timeline, Seq::from_u64(1)),
            TimelineHistorySegment::new(host.timeline, Seq::from_u64(2)),
        ],
        vec![
            TimelineHistorySegment::new(host.timeline, Seq::from_u64(2)),
            TimelineHistorySegment::new(child, Seq::from_u64(1)),
        ],
    ] {
        assert!(matches!(
            constructor(segments),
            Err(ReplayVerificationError::InvalidTimelineAncestry)
        ));
    }
}

#[test]
fn provider_attempt_debug_redacts_response_data_in_every_variant() {
    let response = BoundedProviderBytes::try_from(vec![0xab]).unwrap();
    let cases = [
        (
            ProviderAttempt::Response(response),
            "Response(<redacted>)".to_owned(),
        ),
        (ProviderAttempt::NoResponse, "NoResponse".to_owned()),
        (
            ProviderAttempt::Failed(ProviderFailureCode::Timeout),
            "Failed(Timeout)".to_owned(),
        ),
        (
            ProviderAttempt::Oversized {
                response_digest: Some([0x55; 32]),
            },
            "Oversized { response_digest: Some(\"<redacted>\") }".to_owned(),
        ),
    ];

    for (attempt, expected) in cases {
        assert_eq!(format!("{attempt:?}"), expected);
    }
}

#[test]
fn accepted_and_no_action_records_verify_without_mutating_source_events() {
    let host = HostFixture::new();
    let mut events = accepted_events(&host);
    let no_action = host.record(2, 1, FixtureResult::NoAction { code: 5 });
    events.push(event(
        3,
        host.agent,
        RECORDER_EVENT_TYPE,
        no_action.record_bytes(),
    ));
    let original = events.clone();

    let checkpoint = host.verifier().verify(&events, None).unwrap();

    assert_eq!(checkpoint.last_verified(), Seq::from_u64(3));
    assert_eq!(events, original);
}

#[test]
fn sequence_bounded_ancestry_rejects_an_ancestor_record_after_a_fork() {
    let host = HostFixture::new();
    let child = TimelineId::new();
    let record = host.record(0, 0, FixtureResult::NoAction { code: 5 });
    let events = vec![
        event(1, host.other_agent, "world.observation", vec![0x80]),
        event(2, host.other_agent, "world.observation", vec![0x80]),
        event(3, host.agent, RECORDER_EVENT_TYPE, record.record_bytes()),
    ];
    let verifier = AgentDecisionReplayVerifier::try_new_with_timeline_ancestry(
        vec![
            TimelineHistorySegment::new(host.timeline, Seq::from_u64(2)),
            TimelineHistorySegment::new(child, Seq::from_u64(3)),
        ],
        host.agent,
        host.provenance.clone(),
        host.catalogue.clone(),
    )
    .unwrap();

    assert!(verifier.verify(&events, None).is_err());
}

#[test]
fn malformed_and_unsupported_target_records_fail_closed() {
    let host = HostFixture::new();
    let valid = host
        .record(0, 0, FixtureResult::NoAction { code: 5 })
        .record_bytes();
    let mut unsupported = valid.clone();
    unsupported[6] = 2;
    let cases = [
        ("malformed", vec![0xff]),
        (
            "wrong magic",
            vec![0x82, 0x44, b'X', b'D', b'R', b'1', 0x01],
        ),
        ("unsupported version", unsupported),
    ];

    for (name, payload) in cases {
        let events = vec![event(1, host.agent, RECORDER_EVENT_TYPE, payload)];
        assert!(host.verifier().verify(&events, None).is_err(), "{name}");
    }
}

#[test]
fn every_host_owned_record_field_and_request_hash_is_verified() {
    let host = HostFixture::new();
    let base = host.record(0, 0, FixtureResult::NoAction { code: 5 });
    let mut cases = Vec::new();

    let mut wrong = base.clone();
    wrong.agent = host.other_agent;
    cases.push(("agent", wrong));
    let mut wrong = base.clone();
    wrong.timeline = TimelineId::from_ulid(fixed_ulid(0x11));
    cases.push(("timeline", wrong));
    let mut wrong = base.clone();
    wrong.plugin = PluginId::from_ulid(fixed_ulid(0x33));
    cases.push(("plugin id", wrong));
    let mut wrong = base.clone();
    wrong.plugin_version = "1.0.1".to_owned();
    cases.push(("plugin version", wrong));
    let mut wrong = base.clone();
    wrong.plugin_hash = [0x41; 32];
    cases.push(("plugin hash", wrong));
    let mut wrong = base.clone();
    wrong.provider_id = "fixture-2".to_owned();
    cases.push(("provider id", wrong));
    let mut wrong = base.clone();
    wrong.provider_version = "v2".to_owned();
    cases.push(("provider version", wrong));
    let mut wrong = base.clone();
    wrong.provider_hash = [0x42; 32];
    cases.push(("provider hash", wrong));
    let mut wrong = base.clone();
    wrong.catalogue_hash = [0x43; 32];
    cases.push(("catalogue hash", wrong));
    let mut wrong = base;
    wrong.request_hash_override = Some([0x44; 32]);
    cases.push(("request hash", wrong));

    for (name, record) in cases {
        let events = vec![event(
            1,
            host.agent,
            RECORDER_EVENT_TYPE,
            record.record_bytes(),
        )];
        assert!(host.verifier().verify(&events, None).is_err(), "{name}");
    }
}

#[test]
fn record_anchor_and_driver_tick_must_match_the_source_history() {
    let host = HostFixture::new();

    let wrong_anchor = host.record(1, 0, FixtureResult::NoAction { code: 5 });
    assert!(host
        .verifier()
        .verify(
            &[event(
                1,
                host.agent,
                RECORDER_EVENT_TYPE,
                wrong_anchor.record_bytes(),
            )],
            None,
        )
        .is_err());

    let wrong_initial_tick = host.record(0, 1, FixtureResult::NoAction { code: 5 });
    assert!(host
        .verifier()
        .verify(
            &[event(
                1,
                host.agent,
                RECORDER_EVENT_TYPE,
                wrong_initial_tick.record_bytes(),
            )],
            None,
        )
        .is_err());

    let first = host.record(0, 0, FixtureResult::NoAction { code: 5 });
    let stale_second_anchor = host.record(0, 1, FixtureResult::NoAction { code: 5 });
    assert!(host
        .verifier()
        .verify(
            &[
                event(1, host.agent, RECORDER_EVENT_TYPE, first.record_bytes()),
                event(
                    2,
                    host.agent,
                    RECORDER_EVENT_TYPE,
                    stale_second_anchor.record_bytes(),
                ),
            ],
            None,
        )
        .is_err());

    for (name, second_tick) in [("duplicate", 0), ("gap", 2), ("regression", u64::MAX)] {
        let first = host.record(0, 0, FixtureResult::NoAction { code: 5 });
        let second = host.record(1, second_tick, FixtureResult::NoAction { code: 5 });
        let events = vec![
            event(1, host.agent, RECORDER_EVENT_TYPE, first.record_bytes()),
            event(2, host.agent, RECORDER_EVENT_TYPE, second.record_bytes()),
        ];
        assert!(host.verifier().verify(&events, None).is_err(), "{name}");
    }
}

#[test]
fn accepted_record_requires_the_exact_immediately_adjacent_derived_action() {
    let host = HostFixture::new();
    let record = host.record(
        0,
        0,
        FixtureResult::Accepted {
            action_index: 0,
            confidence: 750_000,
        },
    );
    let record_event = event(1, host.agent, RECORDER_EVENT_TYPE, record.record_bytes());
    let exact_action = record.action_bytes("move", 750_000);
    let cases = [
        (
            "action id",
            event(
                2,
                host.agent,
                EVENT_TYPE_ACTION,
                record.action_bytes("wait", 750_000),
            ),
        ),
        (
            "confidence",
            event(
                2,
                host.agent,
                EVENT_TYPE_ACTION,
                record.action_bytes("move", 749_999),
            ),
        ),
        (
            "tick",
            event(
                2,
                host.agent,
                EVENT_TYPE_ACTION,
                action_bytes(
                    "move",
                    750_000,
                    1,
                    record.catalogue_hash,
                    record.record_hash(),
                ),
            ),
        ),
        (
            "catalogue hash",
            event(
                2,
                host.agent,
                EVENT_TYPE_ACTION,
                action_bytes("move", 750_000, 0, [0x55; 32], record.record_hash()),
            ),
        ),
        (
            "record hash",
            event(
                2,
                host.agent,
                EVENT_TYPE_ACTION,
                action_bytes("move", 750_000, 0, record.catalogue_hash, [0x56; 32]),
            ),
        ),
        (
            "wrong action entity",
            event(2, host.other_agent, EVENT_TYPE_ACTION, exact_action.clone()),
        ),
        (
            "wrong action type",
            event(2, host.agent, "world.observation", exact_action),
        ),
    ];

    for (name, action) in cases {
        let events = vec![record_event.clone(), action];
        assert!(host.verifier().verify(&events, None).is_err(), "{name}");
    }
}

#[test]
fn accepted_records_fail_when_action_is_missing_non_adjacent_or_out_of_catalogue() {
    let host = HostFixture::new();
    let accepted = host.record(
        0,
        0,
        FixtureResult::Accepted {
            action_index: 0,
            confidence: 10,
        },
    );
    let missing = vec![event(
        1,
        host.agent,
        RECORDER_EVENT_TYPE,
        accepted.record_bytes(),
    )];
    assert!(host.verifier().verify(&missing, None).is_err());

    let non_adjacent = vec![
        missing[0].clone(),
        event(2, host.other_agent, "world.observation", vec![0x80]),
        event(
            3,
            host.agent,
            EVENT_TYPE_ACTION,
            accepted.action_bytes("move", 10),
        ),
    ];
    assert!(host.verifier().verify(&non_adjacent, None).is_err());

    let out_of_catalogue = host.record(
        0,
        0,
        FixtureResult::Accepted {
            action_index: 2,
            confidence: 10,
        },
    );
    let events = vec![
        event(
            1,
            host.agent,
            RECORDER_EVENT_TYPE,
            out_of_catalogue.record_bytes(),
        ),
        event(2, host.agent, EVENT_TYPE_ACTION, vec![0x80]),
    ];
    assert!(host.verifier().verify(&events, None).is_err());
}

#[test]
fn every_unexpected_target_action_fails_closed() {
    let host = HostFixture::new();
    let no_action = host.record(0, 0, FixtureResult::NoAction { code: 5 });
    let valid_but_extra = action_bytes("move", 1, 0, host.catalogue_hash, no_action.record_hash());
    let payloads = [
        ("legacy map", vec![0xa0]),
        ("malformed", vec![0xff]),
        (
            "wrong magic",
            vec![0x82, 0x44, b'X', b'A', b'A', b'1', 0x01],
        ),
        ("extra exact action", valid_but_extra),
    ];

    for (name, payload) in payloads {
        let standalone = vec![event(1, host.agent, EVENT_TYPE_ACTION, payload.clone())];
        assert!(
            host.verifier().verify(&standalone, None).is_err(),
            "standalone {name}"
        );

        let after_no_action = vec![
            event(1, host.agent, RECORDER_EVENT_TYPE, no_action.record_bytes()),
            event(2, host.agent, EVENT_TYPE_ACTION, payload),
        ];
        assert!(
            host.verifier().verify(&after_no_action, None).is_err(),
            "after no-action {name}"
        );
    }
}

#[test]
fn source_sequence_must_begin_at_one_and_remain_contiguous() {
    let host = HostFixture::new();
    let generic = |seq| event(seq, host.other_agent, "world.observation", vec![0x80]);
    let cases = [
        ("starts after one", vec![generic(2)]),
        ("duplicate", vec![generic(1), generic(1)]),
        ("regression", vec![generic(1), generic(2), generic(1)]),
        ("gap", vec![generic(1), generic(3)]),
    ];

    for (name, events) in cases {
        assert!(host.verifier().verify(&events, None).is_err(), "{name}");
    }
}

#[test]
fn unrelated_recorder_actions_and_generic_events_pass_through() {
    let host = HostFixture::new();
    let events = vec![
        event(1, host.other_agent, RECORDER_EVENT_TYPE, vec![0xff]),
        event(2, host.other_agent, EVENT_TYPE_ACTION, vec![0xff]),
        event(3, host.agent, "world.observation", vec![0xff]),
    ];

    let checkpoint = host.verifier().verify(&events, None).unwrap();

    assert_eq!(checkpoint.last_verified(), Seq::from_u64(3));
}

#[test]
fn resume_requires_the_complete_revalidated_prefix_and_matches_one_shot() {
    let host = HostFixture::new();
    let prefix = accepted_events(&host);
    let checkpoint = host.verifier().verify(&prefix, None).unwrap();
    let no_action = host.record(2, 1, FixtureResult::NoAction { code: 5 });
    let mut full = prefix.clone();
    full.push(event(
        3,
        host.agent,
        RECORDER_EVENT_TYPE,
        no_action.record_bytes(),
    ));

    let resumed = host.verifier().verify(&full, Some(checkpoint)).unwrap();
    let one_shot = host.verifier().verify(&full, None).unwrap();
    assert_eq!(resumed, one_shot);

    let absent = host.verifier().verify(&prefix, Some(one_shot));
    assert!(absent.is_err());

    let prior_no_action = host.record(0, 0, FixtureResult::NoAction { code: 5 });
    let prior_checkpoint = host
        .verifier()
        .verify(
            &[event(
                1,
                host.agent,
                RECORDER_EVENT_TYPE,
                prior_no_action.record_bytes(),
            )],
            None,
        )
        .unwrap();
    let changed_to_accepted = accepted_events(&host);
    assert!(host
        .verifier()
        .verify(&changed_to_accepted, Some(prior_checkpoint))
        .is_err());

    let without_start = vec![full[1].clone(), full[2].clone()];
    assert!(host
        .verifier()
        .verify(&without_start, Some(checkpoint))
        .is_err());

    let incomplete_prefix = vec![
        event(
            1,
            host.agent,
            RECORDER_EVENT_TYPE,
            host.record(
                0,
                0,
                FixtureResult::Accepted {
                    action_index: 0,
                    confidence: 1,
                },
            )
            .record_bytes(),
        ),
        event(2, host.other_agent, "world.observation", vec![0x80]),
    ];
    assert!(host
        .verifier()
        .verify(&incomplete_prefix, Some(checkpoint))
        .is_err());

    let mut changed_predecessor = full;
    let mut changed_record = host.record(
        0,
        0,
        FixtureResult::Accepted {
            action_index: 0,
            confidence: 750_000,
        },
    );
    changed_record.request_hash_override = Some([0x77; 32]);
    changed_predecessor[0] = event(
        1,
        host.agent,
        RECORDER_EVENT_TYPE,
        changed_record.record_bytes(),
    );
    assert!(host
        .verifier()
        .verify(&changed_predecessor, Some(checkpoint))
        .is_err());
}

#[test]
fn empty_source_has_zero_checkpoint_and_cannot_satisfy_a_later_resume() {
    let host = HostFixture::new();
    let empty = host.verifier().verify(&[], None).unwrap();
    assert_eq!(empty.last_verified(), Seq::ZERO);

    let later = host
        .verifier()
        .verify(&accepted_events(&host), None)
        .unwrap();
    assert!(host.verifier().verify(&[], Some(later)).is_err());
    assert_eq!(host.verifier().verify(&[], Some(empty)).unwrap(), empty);
}

#[test]
fn provider_driver_recovers_only_from_selected_evidence_and_remains_fresh_only() {
    let host = HostFixture::new();
    let events = accepted_events(&host);
    let provider = FixtureAgentDecisionProvider::new(vec![ProviderAttempt::NoResponse]);
    let calls = provider.call_count_handle();
    let driver = ProviderBackedAgentDriver::new(
        host.agent,
        host.catalogue.clone(),
        host.provenance.clone(),
        Box::new(provider),
    );
    let mut registry = PluginRegistry::new();
    registry.register_driver(Box::new(driver));
    let segments = [TimelineHistorySegment::new(host.timeline, Seq::from_u64(2))];

    registry.restore_driver_state(&segments, &events).unwrap();
    assert_eq!(calls.get(), 0, "recovery must not call the provider");
    assert!(registry.restore_driver_state(&segments, &events).is_err());

    let drafts = registry
        .step_all_anchored(host.timeline, Seq::from_u64(2))
        .unwrap();
    assert_eq!(calls.get(), 1);
    let record = DecisionRecordV1::decode(drafts[0].payload.as_slice()).unwrap();
    assert_eq!(record.request().driver_tick(), 1);
    registry.abort_step();
}

#[test]
fn provider_driver_recovery_rejects_unordered_evidence_before_provider_use() {
    let host = HostFixture::new();
    let provider = FixtureAgentDecisionProvider::new(vec![ProviderAttempt::NoResponse]);
    let calls = provider.call_count_handle();
    let driver = ProviderBackedAgentDriver::new(
        host.agent,
        host.catalogue.clone(),
        host.provenance.clone(),
        Box::new(provider),
    );
    let mut registry = PluginRegistry::new();
    registry.register_driver(Box::new(driver));
    let segments = [TimelineHistorySegment::new(host.timeline, Seq::from_u64(2))];
    let evidence = vec![
        event(2, host.other_agent, "world.observation", vec![0x80]),
        event(1, host.other_agent, "world.observation", vec![0x80]),
    ];

    assert!(registry.restore_driver_state(&segments, &evidence).is_err());
    assert_eq!(calls.get(), 0, "recovery must not call the provider");
}

#[test]
fn live_driver_provider_call_count_does_not_change_during_replay() {
    let host = HostFixture::new();
    let response = BoundedProviderBytes::try_from(provider_accepted_bytes(0, 900_000))
        .expect("fixture response is bounded");
    let provider = FixtureAgentDecisionProvider::new(vec![ProviderAttempt::Response(response)]);
    let calls = provider.call_count_handle();
    let driver = ProviderBackedAgentDriver::new(
        host.agent,
        host.catalogue.clone(),
        host.provenance.clone(),
        Box::new(provider),
    );
    let mut registry = PluginRegistry::new();
    registry.register_driver(Box::new(PrecedingDriver {
        entity: host.other_agent,
    }));
    registry.register_driver(Box::new(driver));
    let drafts = registry
        .step_all_anchored(host.timeline, Seq::ZERO)
        .expect("live boundary succeeds");
    assert_eq!(calls.get(), 1);
    let events: Vec<Event> = drafts
        .into_iter()
        .enumerate()
        .map(|(index, draft)| {
            event(
                u64::try_from(index + 1).expect("fixture sequence fits u64"),
                draft.entity,
                draft.event_type.as_str(),
                draft.payload.as_slice().to_vec(),
            )
        })
        .collect();

    let checkpoint = host.verifier().verify(&events, None).unwrap();

    assert_eq!(checkpoint.last_verified(), Seq::from_u64(3));
    assert_eq!(calls.get(), 1);
    registry.abort_step();
}
