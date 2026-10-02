//! ADR-024 Revision 1 Decision 5: Eval derives `eval.*` from committed
//! Persona prediction sources as a pure function of the committed prefix.

use pos_core::{
    clock::{Seq, WallTime},
    crypto::Hash,
    event::{CanonicalBytes, Event, EventDraft, Kind, SchemaVersion},
    ids::{EntityId, EventId, TimelineId},
    Plugin,
};
use pos_plugin_eval::{
    derive_eval_units, EvalDerivationConfigV1, EvalDerivationDriver, EvalDiagnosticsV1, EvalError,
    EvalIntegrityFindingKindV1, EvalIntegrityFindingV1, EvalPlugin, OutcomeEvidenceV1,
    OutcomePayload, PredictionPayload, DERIVED_PREDICTION_ID_PREFIX, EVENT_TYPE_OUTCOME,
    EVENT_TYPE_PREDICTION, MIN_DRAFTS_PER_PASS,
};
use pos_plugin_persona::{
    draft_prediction_source, PredictionOutcomeV1, PredictionSourceV1, EVENT_TYPE_PREDICTION_SOURCE,
    PREDICTION_SOURCE_VERSION_V1,
};
use pos_runtime::{Driver, ObservationView, RuntimeError};

trait TestValueExt<T> {
    fn test_ok(self) -> T;
}

impl<T, E: std::fmt::Debug> TestValueExt<T> for Result<T, E> {
    fn test_ok(self) -> T {
        self.unwrap_or_else(|error| {
            std::panic::resume_unwind(Box::new(format!("unexpected eval error: {error:?}")))
        })
    }
}

/// Commit a draft as the next Event of a synthetic prefix.
fn commit(prefix: &mut Vec<Event>, draft: EventDraft) -> EventId {
    let id = EventId::new();
    let seq = u64::try_from(prefix.len() + 1).test_ok();
    prefix.push(Event {
        id,
        entity: draft.entity,
        event_type: draft.event_type,
        payload: draft.payload,
        wall_time: WallTime::from_micros(seq),
        seq: Seq::from_u64(seq),
        causation_id: draft.causation_id,
        correlation_id: None,
        schema_version: SchemaVersion::V1,
        signature: None,
        signature_identity: None,
        origin: None,
        payload_hash: Hash::from_bytes([0; 32]),
    });
    id
}

fn source(prefix: &mut Vec<Event>, entity: EntityId, outcome: PredictionOutcomeV1) -> EventId {
    commit(prefix, draft_prediction_source(entity, 0.75, outcome))
}

fn caused(event_type: &str, cause: EventId, payload: CanonicalBytes) -> EventDraft {
    let mut draft = EventDraft::new(EntityId::new(), Kind::new(event_type), payload);
    draft.causation_id = Some(cause);
    draft
}

fn encoded<T: serde::Serialize>(payload: &T) -> CanonicalBytes {
    let mut buf = Vec::new();
    ciborium::into_writer(payload, &mut buf).test_ok();
    CanonicalBytes::from_vec(buf)
}

fn config(max_drafts: u32) -> EvalDerivationConfigV1 {
    EvalDerivationConfigV1::new(max_drafts).test_ok()
}

fn sources_of(drafts: &[EventDraft]) -> Vec<(String, EventId)> {
    drafts
        .iter()
        .map(|draft| {
            (
                draft.event_type.as_str().to_owned(),
                draft.causation_id.test_ok_option(),
            )
        })
        .collect()
}

trait TestOptionExt<T> {
    fn test_ok_option(self) -> T;
}

impl<T> TestOptionExt<T> for Option<T> {
    fn test_ok_option(self) -> T {
        self.unwrap_or_else(|| std::panic::resume_unwind(Box::new("missing fixture value")))
    }
}

#[test]
fn an_eligible_source_yields_one_whole_unit_caused_by_the_source() {
    let entity = EntityId::new();
    let mut prefix = Vec::new();
    let with_outcome = source(&mut prefix, entity, PredictionOutcomeV1::Observed(true));
    let without_outcome = source(&mut prefix, entity, PredictionOutcomeV1::Absent);

    let derivation = derive_eval_units(&prefix, &config(64)).test_ok();

    assert!(derivation.findings.is_empty());
    assert_eq!(
        sources_of(&derivation.drafts),
        vec![
            (EVENT_TYPE_PREDICTION.to_owned(), with_outcome),
            (EVENT_TYPE_OUTCOME.to_owned(), with_outcome),
            (EVENT_TYPE_PREDICTION.to_owned(), without_outcome),
        ]
    );
    assert!(derivation.drafts.iter().all(|draft| draft.entity == entity));
    let prediction: PredictionPayload =
        ciborium::from_reader(derivation.drafts[0].payload.as_slice()).test_ok();
    assert_eq!(
        prediction.prediction_id,
        format!("{DERIVED_PREDICTION_ID_PREFIX}{with_outcome}")
    );
    assert_eq!(prediction.prediction_id, format!("eval:src:{with_outcome}"));
    assert_eq!(prediction.entity_id, entity.to_string());
    assert!((prediction.predicted_prob - 0.75).abs() < f64::EPSILON);
    let outcome: OutcomePayload =
        ciborium::from_reader(derivation.drafts[1].payload.as_slice()).test_ok();
    assert_eq!(outcome.prediction_id, prediction.prediction_id);
    assert!(outcome.outcome);
    assert_eq!(outcome.evidence, Some(OutcomeEvidenceV1::PredictorSupplied));
}

#[test]
fn derived_sources_and_legacy_records_are_never_derived_again() {
    let entity = EntityId::new();
    let mut prefix = Vec::new();
    // Legacy Persona-emitted records carry no causation and name no source.
    commit(
        &mut prefix,
        pos_plugin_eval::draft_prediction(entity, "legacy", 0.4, "pred-0"),
    );
    commit(
        &mut prefix,
        pos_plugin_eval::draft_outcome(entity, "pred-0", false),
    );
    let paired = source(&mut prefix, entity, PredictionOutcomeV1::Observed(false));
    let single = source(&mut prefix, entity, PredictionOutcomeV1::Absent);
    let first = derive_eval_units(&prefix, &config(64)).test_ok();
    assert_eq!(first.drafts.len(), 3);
    for draft in first.drafts {
        commit(&mut prefix, draft);
    }

    let second = derive_eval_units(&prefix, &config(64)).test_ok();

    assert!(second.drafts.is_empty());
    assert!(second.findings.is_empty());
    assert_ne!(paired, single);
}

#[test]
fn partial_pairs_are_quarantined_and_other_sources_still_derive() {
    let entity = EntityId::new();
    let mut prefix = Vec::new();
    let orphaned = source(&mut prefix, entity, PredictionOutcomeV1::Observed(true));
    let missing = source(&mut prefix, entity, PredictionOutcomeV1::Observed(true));
    let healthy = source(&mut prefix, entity, PredictionOutcomeV1::Observed(false));
    commit(
        &mut prefix,
        caused(
            EVENT_TYPE_OUTCOME,
            orphaned,
            encoded(&OutcomePayload {
                prediction_id: format!("eval:src:{orphaned}"),
                outcome: true,
                evidence: Some(OutcomeEvidenceV1::PredictorSupplied),
            }),
        ),
    );
    commit(
        &mut prefix,
        caused(
            EVENT_TYPE_PREDICTION,
            missing,
            encoded(&PredictionPayload {
                entity_id: entity.to_string(),
                predicted_prob: 0.75,
                prediction_id: format!("eval:src:{missing}"),
            }),
        ),
    );

    let derivation = derive_eval_units(&prefix, &config(64)).test_ok();

    assert_eq!(
        derivation.findings,
        vec![
            EvalIntegrityFindingV1 {
                source: orphaned,
                kind: EvalIntegrityFindingKindV1::OrphanOutcome,
            },
            EvalIntegrityFindingV1 {
                source: missing,
                kind: EvalIntegrityFindingKindV1::MissingOutcome,
            },
        ]
    );
    assert_eq!(
        sources_of(&derivation.drafts),
        vec![
            (EVENT_TYPE_PREDICTION.to_owned(), healthy),
            (EVENT_TYPE_OUTCOME.to_owned(), healthy),
        ]
    );
}

#[test]
fn the_budget_admits_whole_units_for_the_earliest_sources_only() {
    let entity = EntityId::new();
    let paired = |count: usize| {
        let mut prefix = Vec::new();
        let ids: Vec<EventId> = (0..count)
            .map(|_| source(&mut prefix, entity, PredictionOutcomeV1::Observed(true)))
            .collect();
        (prefix, ids)
    };

    // Three two-draft units fit exactly in six drafts.
    let (prefix, _) = paired(3);
    assert_eq!(
        derive_eval_units(&prefix, &config(6))
            .test_ok()
            .drafts
            .len(),
        6
    );
    // Five drafts admit two whole units and never split the third.
    assert_eq!(
        derive_eval_units(&prefix, &config(5))
            .test_ok()
            .drafts
            .len(),
        4
    );

    // A closed budget never skips ahead to a later, smaller unit.
    let (mut prefix, ids) = paired(2);
    let late_single = source(&mut prefix, entity, PredictionOutcomeV1::Absent);
    let capped = derive_eval_units(&prefix, &config(3)).test_ok();
    assert_eq!(
        sources_of(&capped.drafts),
        vec![
            (EVENT_TYPE_PREDICTION.to_owned(), ids[0]),
            (EVENT_TYPE_OUTCOME.to_owned(), ids[0]),
        ]
    );

    // A smaller unit that is next in order fills the remaining budget.
    let mut prefix = Vec::new();
    let first = source(&mut prefix, entity, PredictionOutcomeV1::Observed(true));
    let second = source(&mut prefix, entity, PredictionOutcomeV1::Absent);
    let third = source(&mut prefix, entity, PredictionOutcomeV1::Absent);
    let filled = derive_eval_units(&prefix, &config(3)).test_ok();
    assert_eq!(
        sources_of(&filled.drafts),
        vec![
            (EVENT_TYPE_PREDICTION.to_owned(), first),
            (EVENT_TYPE_OUTCOME.to_owned(), first),
            (EVENT_TYPE_PREDICTION.to_owned(), second),
        ]
    );
    assert_ne!(third, late_single);
}

#[test]
fn an_unknown_or_unreadable_source_version_fails_closed() {
    let entity = EntityId::new();
    let mut prefix = Vec::new();
    source(&mut prefix, entity, PredictionOutcomeV1::Observed(true));
    commit(
        &mut prefix,
        EventDraft::new(
            entity,
            Kind::new(EVENT_TYPE_PREDICTION_SOURCE),
            encoded(&PredictionSourceV1 {
                version: PREDICTION_SOURCE_VERSION_V1 + 1,
                predicted_prob: 0.5,
                outcome: PredictionOutcomeV1::Absent,
            }),
        ),
    );
    assert!(matches!(
        derive_eval_units(&prefix, &config(64)),
        Err(EvalError::UnknownSourceVersion { version }) if version == 2
    ));

    let mut unreadable = Vec::new();
    commit(
        &mut unreadable,
        EventDraft::new(
            entity,
            Kind::new(EVENT_TYPE_PREDICTION_SOURCE),
            CanonicalBytes::from_vec(vec![0xff]),
        ),
    );
    assert!(matches!(
        derive_eval_units(&unreadable, &config(64)),
        Err(EvalError::Decode(_))
    ));
}

fn prediction_for(cause: EventId) -> EventDraft {
    caused(
        EVENT_TYPE_PREDICTION,
        cause,
        encoded(&PredictionPayload {
            entity_id: "derived".to_owned(),
            predicted_prob: 0.5,
            prediction_id: format!("eval:src:{cause}"),
        }),
    )
}

fn outcome_for(cause: EventId) -> EventDraft {
    caused(
        EVENT_TYPE_OUTCOME,
        cause,
        encoded(&OutcomePayload {
            prediction_id: format!("eval:src:{cause}"),
            outcome: true,
            evidence: Some(OutcomeEvidenceV1::PredictorSupplied),
        }),
    )
}

fn raw_source(prefix: &mut Vec<Event>, entity: EntityId, payload: CanonicalBytes) -> EventId {
    commit(
        prefix,
        EventDraft::new(entity, Kind::new(EVENT_TYPE_PREDICTION_SOURCE), payload),
    )
}

/// User decision A (2026-10-02): only a still-eligible source is decoded, so
/// a malformed or newer-version source that already has its prediction never
/// blocks a pass. An eligible bad source still fails closed until ADR-024
/// Revision 2 (#493) quarantines it.
#[test]
fn an_already_derived_unreadable_or_newer_source_never_blocks_a_pass() {
    let entity = EntityId::new();
    let newer_payload = encoded(&PredictionSourceV1 {
        version: PREDICTION_SOURCE_VERSION_V1 + 1,
        predicted_prob: 0.5,
        outcome: PredictionOutcomeV1::Observed(true),
    });
    let mut prefix = Vec::new();
    let newer_paired = raw_source(&mut prefix, entity, newer_payload.clone());
    let newer_pending = raw_source(&mut prefix, entity, newer_payload);
    let unreadable_pending = raw_source(&mut prefix, entity, CanonicalBytes::from_vec(vec![0xff]));
    let unreadable_orphan = raw_source(&mut prefix, entity, CanonicalBytes::from_vec(vec![0xfe]));
    let healthy = source(&mut prefix, entity, PredictionOutcomeV1::Observed(false));
    commit(&mut prefix, prediction_for(newer_paired));
    commit(&mut prefix, outcome_for(newer_paired));
    commit(&mut prefix, prediction_for(newer_pending));
    commit(&mut prefix, prediction_for(unreadable_pending));
    commit(&mut prefix, outcome_for(unreadable_orphan));

    let derivation = derive_eval_units(&prefix, &config(64)).test_ok();

    // A predicted source whose outcome cannot be read counts as carrying no
    // outcome; an orphan outcome is quarantined without decoding its source.
    assert_eq!(
        derivation.findings,
        vec![EvalIntegrityFindingV1 {
            source: unreadable_orphan,
            kind: EvalIntegrityFindingKindV1::OrphanOutcome,
        }]
    );
    assert_eq!(
        sources_of(&derivation.drafts),
        vec![
            (EVENT_TYPE_PREDICTION.to_owned(), healthy),
            (EVENT_TYPE_OUTCOME.to_owned(), healthy),
        ]
    );

    // The same unreadable payload still fails closed while it is eligible.
    let mut eligible = Vec::new();
    raw_source(&mut eligible, entity, CanonicalBytes::from_vec(vec![0xff]));
    assert!(matches!(
        derive_eval_units(&eligible, &config(64)),
        Err(EvalError::Decode(_))
    ));
}

#[test]
fn the_configuration_admits_at_least_one_whole_unit_and_pins_its_mapping() {
    assert!(matches!(
        EvalDerivationConfigV1::new(MIN_DRAFTS_PER_PASS - 1),
        Err(EvalError::InvalidConfiguration)
    ));
    let smallest = config(MIN_DRAFTS_PER_PASS);
    assert_eq!(smallest.max_drafts_per_pass(), 2);
    let details = String::from_utf8(smallest.configuration_details()).test_ok();
    assert_eq!(
        details,
        "eval-derivation-v1;source=persona.prediction;version=1;max-drafts=2"
    );
    assert_ne!(
        config(3).configuration_details(),
        smallest.configuration_details()
    );
}

#[test]
fn the_driver_requires_the_verified_prefix_of_its_subscriptions() {
    let plugin = EvalPlugin::new();
    assert_eq!(plugin.version(), "0.2.0");
    assert!(plugin.capability().has_driver);
    let mut driver = EvalDerivationDriver::new(config(64), EvalDiagnosticsV1::default());
    assert_eq!(driver.name(), "eval-derivation");
    assert!(driver.requires_verified_event_prefix());
    let subscriptions: Vec<&str> = driver
        .event_subscriptions()
        .iter()
        .map(Kind::as_str)
        .collect();
    assert_eq!(
        subscriptions,
        vec![
            EVENT_TYPE_PREDICTION_SOURCE,
            EVENT_TYPE_PREDICTION,
            EVENT_TYPE_OUTCOME
        ]
    );

    let error = driver
        .step(TimelineId::new(), ObservationView::empty())
        .err()
        .map(|error| error.to_string());
    assert_eq!(
        error,
        Some(
            RuntimeError::MissingSnapshotAnchor {
                driver: "eval-derivation".to_owned(),
            }
            .to_string()
        )
    );
}

#[test]
fn legacy_outcomes_keep_their_exact_encoding() {
    #[derive(serde::Serialize)]
    struct LegacyOutcome {
        prediction_id: String,
        outcome: bool,
    }
    let legacy = encoded(&LegacyOutcome {
        prediction_id: "pred-7".to_owned(),
        outcome: true,
    });
    let current = pos_plugin_eval::draft_outcome(EntityId::new(), "pred-7", true).payload;
    assert_eq!(current.as_slice(), legacy.as_slice());
    let decoded: OutcomePayload = ciborium::from_reader(legacy.as_slice()).test_ok();
    assert_eq!(decoded.evidence, None);
}
