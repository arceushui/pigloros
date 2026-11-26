//! The on-demand Projection fold (ADR-141 §9, P25, P26, P28, D19, D22).
//!
//! Frozen vectors were computed outside this crate from the ADR-141 preimages.

use std::sync::{Arc, Mutex};

use pos_core::{Kind, SchemaVersion, WallTime};

use super::*;

const OBSERVATION: &str = "test.observation";
const DIGEST_WITH_CAUSATION: &str =
    "150f860ed779b01787ddb8ef47a3b42ae00d9060885572bd08054bcda3f4dec2";
const DIGEST_WITHOUT_CAUSATION: &str =
    "551a7304dc11d21df0de226b73f5636de80ad242498c0539e1f68ba0b72c6c8d";
const GOLDEN_ROOT: &str = "763aa5d488a7d04a7f1108eec752f8ee2ca2cec66653354da952289ef24d15bc";
const GOLDEN_PROVENANCE: &str = "b756215f2706ef698adb8ec381bcb4d298b49ffe26bde136ae2e896815248e70";
const EMPTY_ROOT: &str = "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262";
const EMPTY_PROVENANCE: &str = "dabc3b6b2924f8ba93e25eb8de65db9ce6399760245b55c136ee1b9e5945dfb5";

const ENTITY_A: &str = "01J00000000000000000000001";
const ENTITY_B: &str = "01J00000000000000000000002";
const TIMELINE: &str = "01J00000000000000000000301";

/// Projects `test.observation` Events; the State records the last `seq`.
struct LastSeqReducer;

impl Reducer for LastSeqReducer {
    fn initial(&self) -> State {
        State::new()
    }

    fn projects_event(&self, event: &Event) -> bool {
        event.event_type.as_str() == OBSERVATION
    }

    fn apply(&self, state: &mut State, event: &Event) {
        state.set("last_seq", serde_json::json!(event.seq.as_u64()));
    }
}

/// Records every Event type that reaches it.
struct RecordingReducer(Arc<Mutex<Vec<String>>>);

impl Reducer for RecordingReducer {
    fn initial(&self) -> State {
        State::new()
    }

    fn apply(&self, _state: &mut State, event: &Event) {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(event.event_type.as_str().to_owned());
    }
}

fn fixed_event_id(text: &str) -> EventId {
    serde_json::from_value(serde_json::json!(text))
        .unwrap_or_else(|error| std::panic::resume_unwind(Box::new(error.to_string())))
}

fn fixed_entity_id(text: &str) -> EntityId {
    serde_json::from_value(serde_json::json!(text))
        .unwrap_or_else(|error| std::panic::resume_unwind(Box::new(error.to_string())))
}

fn fixed_timeline_id(text: &str) -> TimelineId {
    serde_json::from_value(serde_json::json!(text))
        .unwrap_or_else(|error| std::panic::resume_unwind(Box::new(error.to_string())))
}

fn typed_event(entity: EntityId, event_type: &str, seq: u64) -> Event {
    Event {
        id: EventId::new(),
        entity,
        event_type: Kind::new(event_type),
        payload: CanonicalBytes::from_static(b"payload"),
        wall_time: WallTime::from_micros(0),
        seq: Seq::from_u64(seq),
        causation_id: None,
        correlation_id: None,
        schema_version: SchemaVersion::V1,
        signature: None,
        signature_identity: None,
        origin: None,
        payload_hash: Hash::from_bytes([0; 32]),
    }
}

fn observation(entity: EntityId, seq: u64) -> Event {
    typed_event(entity, OBSERVATION, seq)
}

/// The three observations of the frozen cut: B, then A with a causation,
/// then B again.
fn golden_events() -> Vec<Event> {
    let entity_a = fixed_entity_id(ENTITY_A);
    let entity_b = fixed_entity_id(ENTITY_B);
    let mut first = observation(entity_b, 1);
    first.id = fixed_event_id("01J00000000000000000000101");
    first.payload = CanonicalBytes::from_static(b"b-first");
    let mut second = observation(entity_a, 2);
    second.id = fixed_event_id("01J00000000000000000000102");
    second.payload = CanonicalBytes::from_static(b"a-only");
    second.causation_id = Some(fixed_event_id("01J00000000000000000000201"));
    let mut third = observation(entity_b, 3);
    third.id = fixed_event_id("01J00000000000000000000103");
    third.payload = CanonicalBytes::from_static(b"b-last");
    vec![first, second, third]
}

fn page_limit(entries: usize) -> ProjectionPageLimitV1 {
    ProjectionPageLimitV1::projection_page_limit_v1(entries)
        .unwrap_or_else(|| std::panic::resume_unwind(Box::new("page limit out of range")))
}

fn folded_page(
    events: &[Event],
    at_seq: u64,
    after: Option<EntityId>,
    limit: usize,
) -> ProjectionPageV1 {
    fold_projection_page_v1(
        Box::new(LastSeqReducer),
        events,
        Seq::from_u64(at_seq),
        after,
        page_limit(limit),
    )
    .unwrap_or_else(|error| std::panic::resume_unwind(Box::new(format!("{error:?}"))))
}

fn page_entities(page: &ProjectionPageV1) -> Vec<EntityId> {
    page.entries.iter().map(|entry| entry.entity_id).collect()
}

fn hex(hash: &Hash) -> String {
    blake3::Hash::from_bytes(*hash.as_bytes())
        .to_hex()
        .to_string()
}

fn golden_projected(causation_id: Option<EventId>) -> ProjectedEventV1 {
    ProjectedEventV1 {
        payload: CanonicalBytes::from_static(b"wob1-payload"),
        event_id: fixed_event_id("01ARZ3NDEKTSV4RRFFQ69G5FAV"),
        seq: Seq::from_u64(7),
        causation_id,
    }
}

#[test]
fn the_state_digest_matches_its_frozen_vectors() {
    let causation = fixed_event_id("01BX5ZZKBKACTAV9WEVGEMMVRZ");
    assert_eq!(
        hex(&golden_projected(Some(causation)).projection_state_digest_v1()),
        DIGEST_WITH_CAUSATION
    );
    assert_eq!(
        hex(&golden_projected(None).projection_state_digest_v1()),
        DIGEST_WITHOUT_CAUSATION
    );
}

#[test]
fn the_state_digest_hashes_its_fields_in_order() {
    let causation = fixed_event_id("01BX5ZZKBKACTAV9WEVGEMMVRZ");
    let projected = golden_projected(Some(causation));
    let mut preimage = b"PiglorOS.GatewayProjectionState.v1\0wob1-payload".to_vec();
    preimage.extend_from_slice(&projected.event_id.inner().to_bytes());
    preimage.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 7, 1]);
    preimage.extend_from_slice(&causation.inner().to_bytes());
    assert_eq!(
        projected.projection_state_digest_v1().as_bytes(),
        blake3::hash(&preimage).as_bytes()
    );
}

#[test]
fn the_state_digest_binds_every_field() {
    let base = golden_projected(None);
    let mut variants: [ProjectedEventV1; 5] = std::array::from_fn(|_| base.clone());
    variants[0].payload = CanonicalBytes::from_static(b"wob1-payloae");
    variants[1].event_id = fixed_event_id("01ARZ3NDEKTSV4RRFFQ69G5FAW");
    variants[2].seq = Seq::from_u64(8);
    variants[3].causation_id = Some(fixed_event_id("01BX5ZZKBKACTAV9WEVGEMMVRZ"));
    variants[4].causation_id = Some(fixed_event_id("01BX5ZZKBKACTAV9WEVGEMMVS0"));
    let digests: Vec<Hash> = variants
        .iter()
        .map(ProjectedEventV1::projection_state_digest_v1)
        .collect();
    for (index, digest) in digests.iter().enumerate() {
        assert_ne!(
            *digest,
            base.projection_state_digest_v1(),
            "variant {index}"
        );
    }
    assert_ne!(digests[3], digests[4]);
}

#[test]
fn the_page_limit_is_one_to_one_hundred() {
    assert_eq!(ProjectionPageLimitV1::projection_page_limit_v1(0), None);
    assert_eq!(page_limit(1).projection_page_entries_v1(), 1);
    assert_eq!(page_limit(100).projection_page_entries_v1(), 100);
    assert_eq!(ProjectionPageLimitV1::projection_page_limit_v1(101), None);
}

#[test]
fn a_cut_folds_only_the_events_at_or_below_at_seq() {
    let entities = [EntityId::new(), EntityId::new(), EntityId::new()];
    let events: Vec<Event> = (1..=3)
        .zip(entities)
        .map(|(seq, entity)| observation(entity, seq))
        .collect();
    let mut expected = entities[..2].to_vec();
    expected.sort();
    let page = folded_page(&events, 2, None, 100);
    assert_eq!(page_entities(&page), expected);
    assert_eq!(folded_page(&events, 0, None, 100).entries, Vec::new());
}

#[test]
fn a_page_holds_the_last_projected_event_and_its_state() {
    let page = folded_page(&golden_events(), 3, None, 100);
    let entry = &page.entries[1];
    assert_eq!(entry.entity_id, fixed_entity_id(ENTITY_B));
    assert_eq!(entry.state.get("last_seq"), Some(&serde_json::json!(3)));
    assert_eq!(entry.last_projected.payload.as_slice(), b"b-last");
    assert_eq!(entry.last_projected.seq, Seq::from_u64(3));
    assert_eq!(
        entry.state_digest,
        entry.last_projected.projection_state_digest_v1()
    );
}

#[test]
fn entries_come_in_entity_order_and_page_after_an_entity() {
    let entity_a = fixed_entity_id(ENTITY_A);
    let entity_b = fixed_entity_id(ENTITY_B);
    let events = golden_events();
    let first = folded_page(&events, 3, None, 1);
    assert_eq!(
        (page_entities(&first), first.more_remain),
        (vec![entity_a], true)
    );
    let second = folded_page(&events, 3, Some(entity_a), 1);
    assert_eq!(
        (page_entities(&second), second.more_remain),
        (vec![entity_b], false)
    );
    let past = folded_page(&events, 3, Some(entity_b), 1);
    assert_eq!(
        (page_entities(&past), past.more_remain),
        (Vec::new(), false)
    );
    let whole = folded_page(&events, 3, None, 2);
    assert_eq!(
        (page_entities(&whole), whole.more_remain),
        (vec![entity_a, entity_b], false)
    );
}

#[test]
fn every_page_and_limit_of_one_cut_has_the_same_state_root() {
    let events = golden_events();
    let pages = [
        folded_page(&events, 3, None, 1),
        folded_page(&events, 3, None, 100),
        folded_page(&events, 3, Some(fixed_entity_id(ENTITY_A)), 1),
        folded_page(&events, 3, Some(fixed_entity_id(ENTITY_B)), 1),
    ];
    for page in pages {
        assert_eq!(hex(&page.state_root), GOLDEN_ROOT);
    }
}

#[test]
fn the_same_prefix_folds_to_the_same_page_in_any_chunking() {
    let events = golden_events();
    let mut chunked =
        ProjectionFoldV1::for_projection_cut_v1(Box::new(LastSeqReducer), Seq::from_u64(3));
    assert_eq!(chunked.fold_projection_chunk_v1(&events[..1]), Ok(()));
    assert_eq!(chunked.fold_projection_chunk_v1(&events[1..]), Ok(()));
    assert_eq!(
        chunked.projection_page_v1(None, page_limit(100)),
        folded_page(&events, 3, None, 100)
    );
    assert_eq!(
        folded_page(&events, 3, None, 100),
        folded_page(&events, 3, None, 100)
    );
}

#[test]
fn an_earlier_observation_of_the_body_does_not_change_its_entry() {
    let events = golden_events();
    let with_earlier = folded_page(&events, 3, Some(fixed_entity_id(ENTITY_A)), 1);
    let without_earlier = folded_page(&events[1..], 3, Some(fixed_entity_id(ENTITY_A)), 1);
    assert_eq!(with_earlier.entries, without_earlier.entries);
}

#[test]
fn geographic_and_consent_events_never_reach_the_reducer() {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let entity = EntityId::new();
    let events = [
        typed_event(entity, pos_core::GEOGRAPHIC_EVENT_TYPE, 1),
        typed_event(entity, pos_core::EVENT_TYPE_CONSENT_REVOKED_V1, 2),
        typed_event(entity, "test.other", 3),
    ];
    let page = fold_projection_page_v1(
        Box::new(RecordingReducer(Arc::clone(&seen))),
        &events,
        Seq::from_u64(3),
        None,
        page_limit(100),
    );
    assert_eq!(page.map(|page| page.entries.len()), Ok(1));
    let reached = seen
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    assert_eq!(reached, vec!["test.other".to_owned()]);
}

#[test]
fn events_the_reducer_does_not_project_give_an_empty_cut() {
    let events = [typed_event(EntityId::new(), "test.action", 1)];
    let page = folded_page(&events, 1, None, 100);
    assert_eq!((page.entries, page.more_remain), (Vec::new(), false));
    assert_eq!(hex(&page.state_root), EMPTY_ROOT);
}

#[test]
fn a_chunk_out_of_timeline_order_is_refused_whole() {
    let events = golden_events();
    let mut fold =
        ProjectionFoldV1::for_projection_cut_v1(Box::new(LastSeqReducer), Seq::from_u64(9));
    assert_eq!(fold.fold_projection_chunk_v1(&events[..2]), Ok(()));
    let late = observation(EntityId::new(), 4);
    let refused = [late.clone(), events[0].clone()];
    assert_eq!(
        fold.fold_projection_chunk_v1(&refused),
        Err(ProjectionFoldErrorV1::OutOfTimelineOrder)
    );
    let repeated = [observation(EntityId::new(), 2)];
    assert_eq!(
        fold.fold_projection_chunk_v1(&repeated),
        Err(ProjectionFoldErrorV1::OutOfTimelineOrder)
    );
    let kept = fold.projection_page_v1(None, page_limit(100));
    assert_eq!(kept.entries.len(), 2);
    assert_eq!(fold.fold_projection_chunk_v1(&[late]), Ok(()));
    let resumed = fold.projection_page_v1(None, page_limit(100));
    assert_eq!(resumed.entries.len(), 3);
}

#[test]
fn a_single_fold_out_of_timeline_order_answers_no_page() {
    let entity = EntityId::new();
    let events = [observation(entity, 2), observation(entity, 2)];
    assert_eq!(
        fold_projection_page_v1(
            Box::new(LastSeqReducer),
            &events,
            Seq::from_u64(2),
            None,
            page_limit(1),
        ),
        Err(ProjectionFoldErrorV1::OutOfTimelineOrder)
    );
}

#[test]
fn the_provenance_digest_matches_its_frozen_vectors() {
    let timeline = fixed_timeline_id(TIMELINE);
    let page = folded_page(&golden_events(), 3, None, 1);
    let digest =
        projection_provenance_digest_v1(timeline, Seq::from_u64(3), "world", &page.state_root);
    assert_eq!(hex(&digest), GOLDEN_PROVENANCE);
    let empty = folded_page(&[], 0, None, 1);
    assert_eq!(hex(&empty.state_root), EMPTY_ROOT);
    let empty_digest =
        projection_provenance_digest_v1(timeline, Seq::ZERO, "world", &empty.state_root);
    assert_eq!(hex(&empty_digest), EMPTY_PROVENANCE);
}

#[test]
fn cbor_heads_take_the_shortest_form() {
    const LONGEST: &[u8] = &[0x1b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
    let cases: [(u8, u64, &[u8]); 10] = [
        (0, 0, &[0x00]),
        (0, 23, &[0x17]),
        (0, 24, &[0x18, 0x18]),
        (0, 255, &[0x18, 0xff]),
        (0, 256, &[0x19, 0x01, 0x00]),
        (2, 65_535, &[0x59, 0xff, 0xff]),
        (3, 65_536, &[0x7a, 0x00, 0x01, 0x00, 0x00]),
        (4, 4_294_967_295, &[0x9a, 0xff, 0xff, 0xff, 0xff]),
        (0, 4_294_967_296, &[0x1b, 0, 0, 0, 1, 0, 0, 0, 0]),
        (0, u64::MAX, LONGEST),
    ];
    for (major, value, expected) in cases {
        let mut out = Vec::new();
        push_projection_cbor_head(&mut out, major, value);
        assert_eq!(out, expected, "{major} {value}");
    }
}

#[test]
fn cbor_text_carries_its_length() {
    let mut out = Vec::new();
    push_projection_cbor_text(&mut out, "world");
    assert_eq!(out, b"\x65world");
}
