//! ADR-024 Revision 1 Decision 5: Eval derives `eval.*` from committed
//! Persona prediction sources as a pure function of the committed prefix.

use pos_core::{
    clock::{Seq, WallTime},
    crypto::Hash,
    event::{Event, EventDraft, Kind, SchemaVersion},
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
    draft_prediction_source, PredictionOutcomeV1, EVENT_TYPE_PREDICTION_SOURCE,
    PREDICTION_SOURCE_VERSION_V1,
};
use pos_runtime::{Driver, ObservationView, RuntimeError};

pub mod common;

use common::{
    encoded, envelope_only, finding, naming_drafts, raw_source, unreadable, TestOptionExt,
    TestValueExt,
};

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

#[test]
fn an_eligible_source_yields_one_whole_unit_caused_by_the_source() {
    let entity = EntityId::new();
    let mut prefix = Vec::new();
    let with_outcome = source(&mut prefix, entity, PredictionOutcomeV1::Observed(true));
    let without_outcome = source(&mut prefix, entity, PredictionOutcomeV1::Absent);

    let derivation = derive_eval_units(&prefix, &config(64));

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
    let first = derive_eval_units(&prefix, &config(64));
    assert_eq!(first.drafts.len(), 3);
    for draft in first.drafts {
        commit(&mut prefix, draft);
    }

    let second = derive_eval_units(&prefix, &config(64));

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
    for draft in naming_drafts(orphaned, false, true)
        .into_iter()
        .chain(naming_drafts(missing, true, false))
    {
        commit(&mut prefix, draft);
    }

    let derivation = derive_eval_units(&prefix, &config(64));

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
    assert_eq!(derive_eval_units(&prefix, &config(6)).drafts.len(), 6);
    // Five drafts admit two whole units and never split the third.
    assert_eq!(derive_eval_units(&prefix, &config(5)).drafts.len(), 4);

    // A closed budget never skips ahead to a later, smaller unit.
    let (mut prefix, ids) = paired(2);
    let late_single = source(&mut prefix, entity, PredictionOutcomeV1::Absent);
    let capped = derive_eval_units(&prefix, &config(3));
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
    let filled = derive_eval_units(&prefix, &config(3));
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
        "eval-derivation-v2;source=persona.prediction;versions=1;max-drafts=2"
    );
    assert_ne!(
        config(3).configuration_details(),
        smallest.configuration_details()
    );
    let remapped = smallest.clone().with_source_versions([3, 1, 2]);
    assert_eq!(
        String::from_utf8(remapped.configuration_details()).test_ok(),
        "eval-derivation-v2;source=persona.prediction;versions=1,2,3;max-drafts=2"
    );
    let rolled_back = smallest.with_source_versions(Vec::new());
    assert_eq!(
        String::from_utf8(rolled_back.configuration_details()).test_ok(),
        "eval-derivation-v2;source=persona.prediction;versions=;max-drafts=2"
    );
}

#[test]
fn the_driver_requires_the_verified_prefix_of_its_subscriptions() {
    let plugin = EvalPlugin::new();
    assert_eq!(plugin.version(), "0.3.0");
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

// ── ADR-024 Revision 2: quarantine of bad eligible sources ─────────────────

/// A readable envelope whose version is not a number.
fn unreadable_version() -> EventDraft {
    #[derive(serde::Serialize)]
    struct Envelope {
        version: &'static str,
    }
    EventDraft::new(
        EntityId::new(),
        Kind::new(EVENT_TYPE_PREDICTION_SOURCE),
        encoded(&Envelope { version: "one" }),
    )
}

#[test]
fn bad_eligible_sources_are_quarantined_in_check_order_and_consume_no_budget() {
    use EvalIntegrityFindingKindV1::{
        InvalidPrediction, UndecodableSource, UnsupportedSourceVersion,
    };
    let entity = EntityId::new();
    let mut prefix = Vec::new();
    let first = source(&mut prefix, entity, PredictionOutcomeV1::Observed(true));
    let not_cbor = commit(&mut prefix, unreadable(entity));
    let bad_version = commit(&mut prefix, unreadable_version());
    // Check 2 precedes checks 3 and 4.
    let unsupported = commit(
        &mut prefix,
        raw_source(entity, 2, f64::NAN, PredictionOutcomeV1::Absent),
    );
    let unsupported_partial = commit(&mut prefix, envelope_only(entity, 2));
    // Check 3 precedes check 4.
    let partial = commit(
        &mut prefix,
        envelope_only(entity, PREDICTION_SOURCE_VERSION_V1),
    );
    let invalid = commit(
        &mut prefix,
        raw_source(entity, 1, f64::NAN, PredictionOutcomeV1::Observed(true)),
    );
    let last = source(&mut prefix, entity, PredictionOutcomeV1::Observed(false));

    // Two whole units fit exactly; a quarantined source takes none of them.
    let derivation = derive_eval_units(&prefix, &config(4));

    assert_eq!(
        sources_of(&derivation.drafts),
        vec![
            (EVENT_TYPE_PREDICTION.to_owned(), first),
            (EVENT_TYPE_OUTCOME.to_owned(), first),
            (EVENT_TYPE_PREDICTION.to_owned(), last),
            (EVENT_TYPE_OUTCOME.to_owned(), last),
        ]
    );
    assert_eq!(
        derivation.findings,
        vec![
            finding(not_cbor, UndecodableSource),
            finding(bad_version, UndecodableSource),
            finding(unsupported, UnsupportedSourceVersion),
            finding(unsupported_partial, UnsupportedSourceVersion),
            finding(partial, UndecodableSource),
            finding(invalid, InvalidPrediction),
        ]
    );
    assert_eq!(
        derivation.decoded_sources,
        vec![
            first,
            not_cbor,
            bad_version,
            unsupported,
            unsupported_partial,
            partial,
            invalid,
            last
        ]
    );
}

#[test]
fn predicted_probabilities_must_be_finite_and_within_the_closed_unit_interval() {
    for rejected in [
        f64::NAN,
        f64::INFINITY,
        f64::NEG_INFINITY,
        -0.000_001,
        1.000_001,
    ] {
        let mut prefix = Vec::new();
        let bad = commit(
            &mut prefix,
            raw_source(
                EntityId::new(),
                1,
                rejected,
                PredictionOutcomeV1::Observed(true),
            ),
        );
        let derivation = derive_eval_units(&prefix, &config(64));
        assert!(derivation.drafts.is_empty(), "{rejected}");
        assert_eq!(
            derivation.findings,
            vec![finding(bad, EvalIntegrityFindingKindV1::InvalidPrediction)],
            "{rejected}"
        );
    }
    for accepted in [0.0, 1.0] {
        let mut prefix = Vec::new();
        let good = commit(
            &mut prefix,
            raw_source(EntityId::new(), 1, accepted, PredictionOutcomeV1::Absent),
        );
        let derivation = derive_eval_units(&prefix, &config(64));
        assert!(derivation.findings.is_empty(), "{accepted}");
        assert_eq!(
            sources_of(&derivation.drafts),
            vec![(EVENT_TYPE_PREDICTION.to_owned(), good)]
        );
        let prediction: PredictionPayload =
            ciborium::from_reader(derivation.drafts[0].payload.as_slice()).test_ok();
        assert!((prediction.predicted_prob - accepted).abs() < f64::EPSILON);
    }
}

/// The one full precedence scenario (Revision 2 Decision 0); the seam tests
/// cover only how the host commits the pass and publishes its diagnostics.
#[test]
fn each_source_has_one_outcome_and_only_a_prediction_without_outcome_is_decoded() {
    use EvalIntegrityFindingKindV1::{
        MissingOutcome, OrphanOutcome, UndecodableSource, UnsupportedSourceVersion,
    };
    let entity = EntityId::new();
    let mut prefix = Vec::new();
    let orphan = commit(&mut prefix, unreadable(entity));
    let complete = commit(&mut prefix, unreadable(entity));
    let missing = commit(
        &mut prefix,
        raw_source(entity, 1, 0.5, PredictionOutcomeV1::Observed(true)),
    );
    let without_outcome = commit(
        &mut prefix,
        raw_source(entity, 1, 0.5, PredictionOutcomeV1::Absent),
    );
    let undecodable = commit(&mut prefix, unreadable(entity));
    // Check 4 applies only to eligible sources.
    let out_of_range = commit(
        &mut prefix,
        raw_source(entity, 1, 2.0, PredictionOutcomeV1::Absent),
    );
    let unsupported = commit(
        &mut prefix,
        raw_source(entity, 9, 0.5, PredictionOutcomeV1::Observed(true)),
    );
    let naming = [
        naming_drafts(orphan, false, true),
        naming_drafts(complete, true, true),
        naming_drafts(missing, true, false),
        naming_drafts(without_outcome, true, false),
        naming_drafts(undecodable, true, false),
        naming_drafts(out_of_range, true, false),
        naming_drafts(unsupported, true, false),
    ];
    for draft in naming.into_iter().flatten() {
        commit(&mut prefix, draft);
    }

    let derivation = derive_eval_units(&prefix, &config(64));

    assert!(derivation.drafts.is_empty());
    assert_eq!(
        derivation.findings,
        vec![
            finding(orphan, OrphanOutcome),
            finding(missing, MissingOutcome),
            finding(undecodable, UndecodableSource),
            finding(unsupported, UnsupportedSourceVersion),
        ]
    );
    assert_eq!(
        derivation.decoded_sources,
        vec![
            missing,
            without_outcome,
            undecodable,
            out_of_range,
            unsupported
        ]
    );
}
