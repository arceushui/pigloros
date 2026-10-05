//! ADR-024 Revision 1 Decision 5: Persona emits its own prediction source,
//! and Eval's non-participant scheduled Driver derives `eval.*` from the
//! committed prefix through host admission (#486).

use std::collections::BTreeMap;

use pos_core::{ConsentAuthority, EntityId, Event, EventDraft, ScheduledObservationProfileV1};
use pos_experiment::{
    CalibrationReportEvaluatorV1, Experiment, ExperimentConfig, PipelineEvaluationOutcomeV1,
    StopCondition, TickOutcome,
};
use pos_plugin_eval::{
    compute_report_from_events, draft_outcome, draft_prediction, CalibrationReport,
    EvalDerivationConfigV1, EvalDerivationDriver, EvalDiagnosticsV1, EvalPlugin, EvalReducer,
    OutcomePayload, PredictionPayload, EVENT_TYPE_OUTCOME, EVENT_TYPE_PREDICTION,
};
use pos_plugin_persona::{
    draft_prediction_source, PersonaEvalDriver, PersonaModel, PersonaPlugin, PersonaReducer,
    PredictionOutcomeV1, PredictionSourceV1, PreferencePair, EVENT_TYPE_PREDICTION_SOURCE,
};
use pos_runtime::{
    LocalScheduledAdmissionHostV1, OutputPolicyBindingV1, OutputPolicySourceV1, PluginRegistry,
    RuntimeError,
};
use serde_json::Value;
use ulid::Ulid;

use super::{
    harness::{closed_object, require_version, verify_pinned, Capture, ConformanceError},
    support::{
        ancestry, draft, events, exact_claim, expect_err, experiment_stores, gated_registry,
        of_type, pass, persona_token, profile_tag, stage, stores, FixturePlugin, ScriptedDriver,
        TestOk, REPORT,
    },
};

/// The immutable legacy-history fixture and its pinned SHA-256.
const LEGACY_HISTORY: &[u8] =
    include_bytes!("../../../../fixtures/conformance/pipeline/v1/legacy-eval-history.json");
pub const LEGACY_HISTORY_SHA256: &str =
    "27a9d670b8ea91dfc667f97f1728fdb80dcf485cd80b48a359e783201632617d";
const LEGACY_MAGIC: &str = "PLH1";
const LEGACY_VERSION: u64 = 1;

fn quiet_pair() -> PreferencePair {
    PreferencePair {
        option_a: "quiet workspace".to_owned(),
        option_b: "busy workspace".to_owned(),
        prefers_a: true,
    }
}

/// Register Eval with its source mapping and per-pass budget bound into its
/// pinned configuration identity.
fn register_eval(registry: &mut PluginRegistry, max_drafts: u32, diagnostics: &EvalDiagnosticsV1) {
    let eval = EvalPlugin::new();
    let config = EvalDerivationConfigV1::new(max_drafts).test_ok();
    let binding = OutputPolicyBindingV1::from_source(
        &eval,
        OutputPolicySourceV1::Generated,
        &config.configuration_details(),
        "deterministic-local-v1",
    )
    .test_ok();
    registry
        .register_with_verified_output_policy(
            &eval,
            binding,
            Some(Box::new(EvalReducer)),
            Some(Box::new(EvalDerivationDriver::new(
                config,
                diagnostics.clone(),
            ))),
        )
        .test_ok();
}

fn persona_and_eval(
    authority: &ConsentAuthority,
    entity: EntityId,
    diagnostics: &EvalDiagnosticsV1,
) -> PluginRegistry {
    let mut registry = gated_registry(Some(authority));
    registry
        .register_generated(
            &PersonaPlugin::new(),
            Some(Box::new(PersonaReducer)),
            Some(Box::new(PersonaEvalDriver::new(
                entity,
                PersonaModel::new(vec![("quiet".to_owned(), 0.7)]),
                vec![quiet_pair()],
            ))),
        )
        .test_ok();
    register_eval(&mut registry, 64, diagnostics);
    registry
}

fn eval_registry(authority: &ConsentAuthority, max_drafts: u32) -> PluginRegistry {
    let mut registry = gated_registry(Some(authority));
    register_eval(&mut registry, max_drafts, &EvalDiagnosticsV1::default());
    registry
}

fn caused_by<'a>(events: &'a [Event], event_type: &str, source: &Event) -> Vec<&'a Event> {
    of_type(events, event_type)
        .into_iter()
        .filter(|event| event.causation_id == Some(source.id))
        .collect()
}

/// The first violation of the derivation contract in `events`, or `ok`:
/// one whole unit per source, prediction first, caused by and carrying the
/// entity of its source, with the domain-separated prediction id, in a
/// later pass than the source.
fn exactly_once(events: &[Event]) -> String {
    for source in of_type(events, EVENT_TYPE_PREDICTION_SOURCE) {
        let predictions = caused_by(events, EVENT_TYPE_PREDICTION, source);
        let outcomes = caused_by(events, EVENT_TYPE_OUTCOME, source);
        let payload: PredictionSourceV1 =
            ciborium::from_reader(source.payload.as_slice()).test_ok();
        let expected_outcomes = usize::from(payload.outcome != PredictionOutcomeV1::Absent);
        let [prediction] = predictions.as_slice() else {
            return format!("{} predictions for one source", predictions.len());
        };
        if outcomes.len() != expected_outcomes {
            return "the unit is not whole".to_owned();
        }
        let derived_id = format!("eval:src:{}", source.id);
        let decoded: PredictionPayload =
            ciborium::from_reader(prediction.payload.as_slice()).test_ok();
        let outcome_ids: Vec<String> = outcomes
            .iter()
            .map(|outcome| {
                ciborium::from_reader::<OutcomePayload, _>(outcome.payload.as_slice())
                    .test_ok()
                    .prediction_id
            })
            .collect();
        if decoded.prediction_id != derived_id || outcome_ids.iter().any(|id| *id != derived_id) {
            return "the prediction id is not domain-separated".to_owned();
        }
        if prediction.entity != source.entity
            || outcomes
                .iter()
                .any(|outcome| outcome.entity != source.entity)
        {
            return "a derived Event does not carry the source entity".to_owned();
        }
        if outcomes.iter().any(|outcome| outcome.seq < prediction.seq) {
            return "the outcome precedes its prediction".to_owned();
        }
        if prediction.seq <= source.seq {
            return "the unit was not derived in a later pass".to_owned();
        }
    }
    "ok".to_owned()
}

/// PCF-ING-004: a first-party Persona Driver and a third-party fixture Driver
/// that emit an Eval-owned type are rejected identically; nothing commits.
#[must_use]
pub fn unowned_output_parity() -> Capture {
    let mut capture = Capture::default();
    for (store, mut backend) in stores() {
        let timeline = backend.create_timeline("unowned-output").test_ok().id();
        let entity = EntityId::new();
        let authority = ConsentAuthority::new();
        let token = persona_token(&authority, timeline, entity);
        let intruder = || {
            ScriptedDriver::new(
                "eval-intruder",
                vec![draft_prediction(entity, "intruder", 0.5, "pred-0")],
            )
        };

        let mut first_party = gated_registry(Some(&authority));
        first_party
            .register_generated(
                &PersonaPlugin::new(),
                Some(Box::new(PersonaReducer)),
                Some(Box::new(intruder())),
            )
            .test_ok();
        register_eval(&mut first_party, 64, &EvalDiagnosticsV1::default());
        LocalScheduledAdmissionHostV1::shared()
            .test_ok()
            .observe(&first_party, backend.as_mut(), timeline)
            .test_ok();
        let persona = expect_err(stage(
            &mut first_party,
            backend.as_ref(),
            timeline,
            Some(&token),
        ));

        let mut third_party = gated_registry(Some(&authority));
        third_party
            .register_generated(
                &FixturePlugin::new("third-party", &["third.party"], true),
                None,
                Some(Box::new(intruder())),
            )
            .test_ok();
        register_eval(&mut third_party, 64, &EvalDiagnosticsV1::default());
        let fixture = expect_err(stage(
            &mut third_party,
            backend.as_ref(),
            timeline,
            Some(&token),
        ));

        capture.record(store, "first-party", &persona);
        capture.record(store, "third-party", &fixture);
        capture.record(
            store,
            "identical",
            persona.to_string() == fixture.to_string(),
        );
        capture.record(store, "committed", events(backend.as_ref(), timeline).len());
    }
    capture
}

/// PCF-EVAL-002: a committed source yields exactly one whole unit in the
/// next eligible pass, caused by the source and carrying its entity and
/// `eval:src:<EventId>`.
#[must_use]
pub fn derivation_units() -> Capture {
    let mut capture = Capture::default();
    for (store, mut backend) in stores() {
        let timeline = backend.create_timeline("persona-eval").test_ok().id();
        let entity = EntityId::new();
        let authority = ConsentAuthority::new();
        let token = persona_token(&authority, timeline, entity);
        let diagnostics = EvalDiagnosticsV1::default();
        let mut registry = persona_and_eval(&authority, entity, &diagnostics);

        let passes: Vec<String> = (0..6)
            .map(|_| {
                pass(&mut registry, backend.as_mut(), timeline, Some(&token))
                    .test_ok()
                    .to_string()
            })
            .collect();
        let committed = events(backend.as_ref(), timeline);
        let sources = of_type(&committed, EVENT_TYPE_PREDICTION_SOURCE);
        let pending = sources.last().test_ok().id;
        let derived: Vec<Event> = committed
            .iter()
            .filter(|event| event.id != pending)
            .cloned()
            .collect();

        capture.record(store, "passes", passes.join(","));
        capture.record(store, "sources", sources.len());
        capture.record(store, "exactly-once", exactly_once(&derived));
        capture.record(
            store,
            "newest-source.awaits-next-pass",
            committed
                .iter()
                .all(|event| event.causation_id != Some(pending)),
        );
        capture.record(store, "findings", diagnostics.findings().len());
    }
    capture
}

fn append_sources(
    backend: &mut dyn pos_runtime::ScheduledAdmissionStoreV1,
    timeline: pos_core::TimelineId,
    sources: &[EventDraft],
) -> Vec<Event> {
    backend.append(timeline, sources).test_ok()
}

/// PCF-EVAL-003: derivation is a pure function of the committed prefix,
/// so a discarded pass, a restart and both branches of a Fork at a Tick
/// Boundary derive every source exactly once.
#[must_use]
pub fn exactly_once_across_restart_discard_and_fork() -> Capture {
    let mut capture = Capture::default();
    for (store, mut backend) in stores() {
        let timeline = backend.create_timeline("restart").test_ok().id();
        let entity = EntityId::new();
        let authority = ConsentAuthority::new();
        append_sources(
            backend.as_mut(),
            timeline,
            &[
                draft_prediction_source(entity, 0.6, PredictionOutcomeV1::Observed(true)),
                draft_prediction_source(entity, 0.2, PredictionOutcomeV1::Observed(false)),
            ],
        );
        let token = persona_token(&authority, timeline, entity);

        let mut discarded = eval_registry(&authority, 64);
        let (_, staged) = stage(&mut discarded, backend.as_ref(), timeline, Some(&token)).test_ok();
        discarded.abort_step();
        capture.record(store, "discarded.staged", staged.len());
        capture.record(
            store,
            "discarded.committed",
            events(backend.as_ref(), timeline).len(),
        );

        let head = backend.logical_head(timeline).test_ok();
        let fork = backend.fork(timeline, head, "fork").test_ok().id();
        let fork_token = persona_token(&authority, fork, entity);
        for (branch_name, branch, branch_token) in
            [("main", timeline, &token), ("fork", fork, &fork_token)]
        {
            let mut restarted = eval_registry(&authority, 64);
            let first =
                pass(&mut restarted, backend.as_mut(), branch, Some(branch_token)).test_ok();
            let mut again = eval_registry(&authority, 64);
            let second = pass(&mut again, backend.as_mut(), branch, Some(branch_token)).test_ok();
            let committed = events(backend.as_ref(), branch);
            capture.record(
                store,
                &format!("{branch_name}.passes"),
                format!("{first},{second}"),
            );
            capture.record(
                store,
                &format!("{branch_name}.exactly-once"),
                exactly_once(&committed),
            );
            capture.record(store, &format!("{branch_name}.committed"), committed.len());
        }
    }
    capture
}

/// PCF-EVAL-004: a budget-capped pass derives whole units for the earliest
/// eligible sources and never splits a pair.
#[must_use]
pub fn budget_never_splits_a_pair() -> Capture {
    let mut capture = Capture::default();
    for (store, mut backend) in stores() {
        let timeline = backend.create_timeline("capped").test_ok().id();
        let entity = EntityId::new();
        let authority = ConsentAuthority::new();
        let sources = append_sources(
            backend.as_mut(),
            timeline,
            &[
                draft_prediction_source(entity, 0.6, PredictionOutcomeV1::Observed(true)),
                draft_prediction_source(entity, 0.4, PredictionOutcomeV1::Observed(true)),
                draft_prediction_source(entity, 0.3, PredictionOutcomeV1::Absent),
            ],
        );
        let token = persona_token(&authority, timeline, entity);
        let mut registry = eval_registry(&authority, 3);
        let passes: Vec<String> = (0..3)
            .map(|_| {
                pass(&mut registry, backend.as_mut(), timeline, Some(&token))
                    .test_ok()
                    .to_string()
            })
            .collect();
        let committed = events(backend.as_ref(), timeline);
        let order: Vec<String> = committed[3..]
            .iter()
            .map(|event| {
                let source = sources
                    .iter()
                    .position(|source| event.causation_id == Some(source.id))
                    .map_or_else(|| "none".to_owned(), |index| index.to_string());
                format!("{}<-{source}", event.event_type.as_str())
            })
            .collect();
        capture.record(store, "passes", passes.join(","));
        capture.record(store, "derived", order.join(","));
        capture.record(store, "exactly-once", exactly_once(&committed));
    }
    capture
}

/// PCF-EVAL-005: Eval's subscriptions are consent-gated; a pass observes
/// only the sources of the subject its token names.
#[must_use]
pub fn subscriptions_are_consent_gated() -> Capture {
    let mut capture = Capture::default();
    for (store, mut backend) in stores() {
        let timeline = backend.create_timeline("consent-gated").test_ok().id();
        let subject = EntityId::new();
        let other = EntityId::new();
        let authority = ConsentAuthority::new();
        append_sources(
            backend.as_mut(),
            timeline,
            &[
                draft_prediction_source(other, 0.6, PredictionOutcomeV1::Observed(true)),
                draft_prediction_source(subject, 0.4, PredictionOutcomeV1::Absent),
            ],
        );
        let subject_token = persona_token(&authority, timeline, subject);
        let other_token = persona_token(&authority, timeline, other);
        let mut registry = eval_registry(&authority, 64);
        let subject_pass = pass(
            &mut registry,
            backend.as_mut(),
            timeline,
            Some(&subject_token),
        )
        .test_ok();
        let other_pass = pass(
            &mut registry,
            backend.as_mut(),
            timeline,
            Some(&other_token),
        )
        .test_ok();
        let public_pass = pass(&mut registry, backend.as_mut(), timeline, None).test_ok();
        capture.record(store, "subject-pass", subject_pass);
        capture.record(store, "other-pass", other_pass);
        capture.record(store, "public-pass", public_pass);
        capture.record(
            store,
            "exactly-once",
            exactly_once(&events(backend.as_ref(), timeline)),
        );
    }
    capture
}

/// PCF-EVAL-006: Replay folds the committed prefix and never runs the
/// derivation; a later live pass still derives the sources once.
#[must_use]
pub fn replay_never_derives() -> Capture {
    let mut capture = Capture::default();
    for (store, mut backend) in stores() {
        let timeline = backend.create_timeline("replay").test_ok().id();
        let entity = EntityId::new();
        let authority = ConsentAuthority::new();
        append_sources(
            backend.as_mut(),
            timeline,
            &[draft_prediction_source(
                entity,
                0.6,
                PredictionOutcomeV1::Observed(true),
            )],
        );
        let token = persona_token(&authority, timeline, entity);
        let mut replay = PluginRegistry::new_replay()
            .with_erasure_gate(std::sync::Arc::new(
                pos_core::ErasureContainmentGateV1::new_test_open(),
            ))
            .with_consent_authority(authority.clone());
        register_eval(&mut replay, 64, &EvalDiagnosticsV1::default());
        let committed = events(backend.as_ref(), timeline);
        replay.fold_events(timeline, &committed);
        let replayed = expect_err(stage(&mut replay, backend.as_ref(), timeline, Some(&token)));
        capture.record(
            store,
            "replay.step",
            matches!(replayed, RuntimeError::ModeMismatch { .. }),
        );
        capture.record(
            store,
            "committed-after-replay",
            events(backend.as_ref(), timeline).len(),
        );
        let mut live = eval_registry(&authority, 64);
        capture.record(
            store,
            "live.next-pass",
            pass(&mut live, backend.as_mut(), timeline, Some(&token)).test_ok(),
        );
    }
    capture
}

/// PCF-EVAL-007: derived outcomes are labelled predictor-supplied, and the
/// Calibration Report counts them as such.
#[must_use]
pub fn predictor_supplied_label() -> Capture {
    let mut capture = Capture::default();
    for (store, mut backend) in stores() {
        let timeline = backend.create_timeline("label").test_ok().id();
        let entity = EntityId::new();
        let authority = ConsentAuthority::new();
        append_sources(
            backend.as_mut(),
            timeline,
            &[
                draft_prediction_source(entity, 0.75, PredictionOutcomeV1::Observed(true)),
                draft_prediction_source(entity, 0.25, PredictionOutcomeV1::Observed(false)),
            ],
        );
        let token = persona_token(&authority, timeline, entity);
        let mut registry = eval_registry(&authority, 64);
        pass(&mut registry, backend.as_mut(), timeline, Some(&token)).test_ok();
        let committed = events(backend.as_ref(), timeline);
        let labels: Vec<String> = of_type(&committed, EVENT_TYPE_OUTCOME)
            .iter()
            .map(|outcome| {
                let payload: OutcomePayload =
                    ciborium::from_reader(outcome.payload.as_slice()).test_ok();
                format!("{:?}", payload.evidence)
            })
            .collect();
        let report = compute_report_from_events(&committed, REPORT, &exact_claim()).test_ok();
        capture.record(store, "outcome.labels", labels.join(","));
        capture.record(store, "report.n_resolved", report.n_resolved);
        capture.record(
            store,
            "report.n_predictor_supplied",
            report.n_predictor_supplied,
        );
    }
    capture
}

/// PCF-EVAL-008: an injected orphan `eval.outcome` is quarantined: (a) other
/// sources still derive, (b) no duplicate outcome is emitted, and (c)
/// another Driver's output in the same pass still commits.
#[must_use]
pub fn injected_orphan_outcome() -> Capture {
    let mut capture = Capture::default();
    for (store, mut backend) in stores() {
        let timeline = backend.create_timeline("orphan").test_ok().id();
        let entity = EntityId::new();
        let authority = ConsentAuthority::new();
        let sources = append_sources(
            backend.as_mut(),
            timeline,
            &[
                draft_prediction_source(entity, 0.6, PredictionOutcomeV1::Observed(true)),
                draft_prediction_source(entity, 0.4, PredictionOutcomeV1::Observed(false)),
            ],
        );
        let orphaned = sources[0].id;
        let mut orphan = draft_outcome(entity, "eval:src:orphan", true);
        orphan.causation_id = Some(orphaned);
        append_sources(backend.as_mut(), timeline, &[orphan]);
        let token = persona_token(&authority, timeline, entity);
        let diagnostics = EvalDiagnosticsV1::default();
        let mut registry = gated_registry(Some(&authority));
        register_eval(&mut registry, 64, &diagnostics);
        registry
            .register_generated(
                &FixturePlugin::new("witness", &["witness.tick"], true),
                None,
                Some(Box::new(ScriptedDriver::new(
                    "witness",
                    vec![draft(EntityId::new(), "witness.tick", b"tick")],
                ))),
            )
            .test_ok();

        let first = pass(&mut registry, backend.as_mut(), timeline, Some(&token)).test_ok();
        let committed = events(backend.as_ref(), timeline);
        let healthy: Vec<Event> = committed
            .iter()
            .filter(|event| event.id != orphaned && event.causation_id != Some(orphaned))
            .cloned()
            .collect();
        let findings = diagnostics.findings();
        capture.record(store, "pass", first);
        capture.record(store, "a.other-source-derives", exactly_once(&healthy));
        capture.record(
            store,
            "b.caused-by-orphaned-source",
            committed
                .iter()
                .filter(|event| event.causation_id == Some(orphaned))
                .count(),
        );
        capture.record(
            store,
            "c.other-driver-commits",
            of_type(&committed, "witness.tick").len(),
        );
        capture.record(
            store,
            "finding",
            findings
                .iter()
                .map(|finding| format!("{:?}@{}", finding.kind, finding.source == orphaned))
                .collect::<Vec<_>>()
                .join(","),
        );
        let recurrence = pass(&mut registry, backend.as_mut(), timeline, Some(&token)).test_ok();
        capture.record(store, "recurrence.pass", recurrence);
        capture.record(store, "recurrence.findings", diagnostics.findings().len());
    }
    capture
}

/// The parsed immutable legacy-history fixture.
pub struct LegacyHistory {
    drafts: Vec<EventDraft>,
    subjects: BTreeMap<String, EntityId>,
    expected_report: Vec<String>,
}

fn invalid(message: &str) -> ConformanceError {
    ConformanceError::InvalidManifest(format!("legacy history: {message}"))
}

fn legacy_entity(value: &Value) -> Result<EntityId, ConformanceError> {
    value
        .as_u64()
        .map(|id| EntityId::from_ulid(Ulid::from(u128::from(id))))
        .ok_or_else(|| invalid("an entity is not an integer"))
}

fn legacy_draft(value: &Value, index: usize) -> Result<EventDraft, ConformanceError> {
    let at = format!("legacy.events[{index}]");
    let event_type = value.get("event_type").and_then(Value::as_str);
    let text = |field: &str| {
        value
            .get(field)
            .and_then(Value::as_str)
            .ok_or_else(|| invalid("a field is not a string"))
    };
    match event_type {
        Some(EVENT_TYPE_PREDICTION) => closed_object(
            value,
            &at,
            &[
                "entity",
                "entity_id",
                "event_type",
                "predicted_prob",
                "prediction_id",
            ],
        )
        .and_then(|object| {
            let probability = object["predicted_prob"]
                .as_f64()
                .ok_or_else(|| invalid("a probability is not a number"))?;
            Ok(draft_prediction(
                legacy_entity(&object["entity"])?,
                text("entity_id")?,
                probability,
                text("prediction_id")?,
            ))
        }),
        Some(EVENT_TYPE_OUTCOME) => closed_object(
            value,
            &at,
            &["entity", "event_type", "outcome", "prediction_id"],
        )
        .and_then(|object| {
            let outcome = object["outcome"]
                .as_bool()
                .ok_or_else(|| invalid("an outcome is not a boolean"))?;
            Ok(draft_outcome(
                legacy_entity(&object["entity"])?,
                text("prediction_id")?,
                outcome,
            ))
        }),
        _ => Err(invalid("an event type is not a legacy eval type")),
    }
}

/// Parse the legacy history, failing closed on any unknown version or field.
///
/// # Errors
///
/// Returns the first structural deviation of the fixture.
pub fn parse_legacy_history(bytes: &[u8]) -> Result<LegacyHistory, ConformanceError> {
    let root: Value = serde_json::from_slice(bytes).map_err(|_| invalid("not JSON"))?;
    let object = root.as_object().ok_or_else(|| invalid("not an object"))?;
    require_version(object, LEGACY_MAGIC, LEGACY_VERSION)?;
    let object = closed_object(
        &root,
        "legacy",
        &[
            "description",
            "events",
            "expected_report",
            "magic",
            "subjects",
            "version",
        ],
    )?;
    let drafts = object["events"]
        .as_array()
        .ok_or_else(|| invalid("events is not an array"))?
        .iter()
        .enumerate()
        .map(|(index, event)| legacy_draft(event, index))
        .collect::<Result<Vec<_>, _>>()?;
    let subjects = object["subjects"]
        .as_object()
        .ok_or_else(|| invalid("subjects is not an object"))?
        .iter()
        .map(|(name, entity)| legacy_entity(entity).map(|entity| (name.clone(), entity)))
        .collect::<Result<BTreeMap<_, _>, _>>()?;
    let expected_report = object["expected_report"]
        .as_array()
        .ok_or_else(|| invalid("expected_report is not an array"))?
        .iter()
        .map(|line| {
            line.as_str()
                .map(str::to_owned)
                .ok_or_else(|| invalid("a report line is not a string"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(LegacyHistory {
        drafts,
        subjects,
        expected_report,
    })
}

/// The canonical text encoding of one Calibration Report, one field per
/// line, with every float in its shortest round-trip form.
fn canonical_report(report: &CalibrationReport) -> Vec<String> {
    let mut lines = vec![
        format!("replay_claim={:?}", report.replay_claim),
        format!("redaction_state={:?}", report.redaction_state),
        format!("brier_score={:?}", report.brier_score),
        format!("crps={:?}", report.crps),
        format!(
            "lift_vs_personal_base_rate={:?}",
            report.lift_vs_personal_base_rate
        ),
        format!("ece={:?}", report.ece),
        format!("lift_vs_population_avg={:?}", report.lift_vs_population_avg),
        format!("lift_vs_persistence={:?}", report.lift_vs_persistence),
        format!("n_predictions={}", report.n_predictions),
        format!("n_resolved={}", report.n_resolved),
        format!("n_predictor_supplied={}", report.n_predictor_supplied),
    ];
    lines.extend(
        report
            .reliability_bins
            .iter()
            .enumerate()
            .map(|(index, bin)| {
                format!(
                    "bin[{index}]={:?}..{:?} mean={:?} fraction={:?} n={}",
                    bin.bin_lower, bin.bin_upper, bin.mean_predicted, bin.fraction_positive, bin.n
                )
            }),
    );
    lines
}

fn reducer_count(state: &pos_core::State, key: &str) -> u64 {
    state.get(key).and_then(Value::as_u64).unwrap_or(u64::MAX)
}

/// PCF-EVAL-009: Persona-emitted legacy `eval.*` history folds under the new
/// composition, yields a byte-identical Calibration Report, and is never
/// re-derived.
#[must_use]
pub fn legacy_history() -> Capture {
    let mut capture = Capture::default();
    verify_pinned(LEGACY_HISTORY, LEGACY_HISTORY_SHA256).test_ok();
    let history = parse_legacy_history(LEGACY_HISTORY).test_ok();
    for (store, mut backend) in stores() {
        let timeline = backend.create_timeline("legacy-history").test_ok().id();
        append_sources(backend.as_mut(), timeline, &history.drafts);
        let committed = events(backend.as_ref(), timeline);
        let head = backend.logical_head(timeline).test_ok();
        let authority = ConsentAuthority::new();
        let mut registry = gated_registry(Some(&authority));
        registry
            .register_generated(
                &PersonaPlugin::new(),
                Some(Box::new(PersonaReducer)),
                Some(Box::new(ScriptedDriver::new("persona-idle", Vec::new()))),
            )
            .test_ok();
        register_eval(&mut registry, 64, &EvalDiagnosticsV1::default());
        registry.fold_events(timeline, &committed);
        let mut rederived = Vec::new();
        for (name, subject) in &history.subjects {
            let token = persona_token(&authority, timeline, *subject);
            let folded = registry
                .projection_state_for_reducer(
                    timeline,
                    &ancestry(backend.as_ref(), timeline),
                    head,
                    0,
                    &token,
                    "eval",
                    *subject,
                )
                .test_ok()
                .map_or_else(
                    || "absent".to_owned(),
                    |state| {
                        format!(
                            "predictions={},outcomes={}",
                            reducer_count(&state, "n_predictions"),
                            reducer_count(&state, "n_outcomes")
                        )
                    },
                );
            capture.record(store, &format!("fold.{name}"), folded);
            rederived.push(
                pass(&mut registry, backend.as_mut(), timeline, Some(&token))
                    .test_ok()
                    .to_string(),
            );
        }
        let report = canonical_report(
            &compute_report_from_events(&committed, REPORT, &exact_claim()).test_ok(),
        );
        capture.record(store, "rederived", rederived.join(","));
        capture.record(
            store,
            "report",
            if report == history.expected_report {
                "identical".to_owned()
            } else {
                report.join(" | ")
            },
        );
        capture.record(
            store,
            "committed-after-passes",
            events(backend.as_ref(), timeline).len(),
        );
    }
    capture
}

fn emitted(outcome: TickOutcome) -> String {
    match outcome {
        TickOutcome::Advanced { emitted_events, .. } => emitted_events.to_string(),
        other => format!("{other:?}"),
    }
}

/// PCF-EVAL-010: derived-evaluation evidence and its Calibration Report carry
/// the ADR-021 Revision 3 non-participant profile tag.
#[must_use]
pub fn derived_evaluation_profile_tag() -> Capture {
    let mut capture = Capture::default();
    let (_directory, configs) = experiment_stores();
    for (store, store_config) in configs {
        let entity = EntityId::new();
        let mut experiment = Experiment::new(ExperimentConfig {
            name: "derived-evaluation".to_owned(),
            stop: StopCondition::MaxTicks(16),
            store_config,
        });
        experiment
            .register_generated(
                &PersonaPlugin::new(),
                Some(Box::new(PersonaReducer)),
                Some(Box::new(PersonaEvalDriver::new(
                    entity,
                    PersonaModel::new(vec![("quiet".to_owned(), 0.7)]),
                    vec![quiet_pair()],
                ))),
            )
            .test_ok();
        experiment
            .register_generated(
                &EvalPlugin::new(),
                Some(Box::new(EvalReducer)),
                Some(Box::new(EvalDerivationDriver::new(
                    EvalDerivationConfigV1::new(64).test_ok(),
                    EvalDiagnosticsV1::default(),
                ))),
            )
            .test_ok();
        let session = experiment.start().test_ok();
        let authority = ConsentAuthority::new();
        let token = persona_token(&authority, session.timeline().id(), entity);
        let mut session = session
            .with_consent_authority(authority)
            .with_protected_token(token);
        session
            .register_pipeline_evaluator(Box::new(CalibrationReportEvaluatorV1::new(REPORT)))
            .test_ok();

        capture.record(store, "first-tick", emitted(session.step_tick().test_ok()));
        capture.record(store, "second-tick", emitted(session.step_tick().test_ok()));
        let evidence = session.last_pipeline_evidence().test_ok().clone();
        let record = session
            .evaluate_pipeline_evidence("calibration-report", &exact_claim())
            .test_ok()
            .test_ok();
        capture.record(
            store,
            "evidence.ingress",
            format!("{:?}", evidence.ingress()),
        );
        capture.record(
            store,
            "report",
            match record.outcome() {
                PipelineEvaluationOutcomeV1::CalibrationReport(report) => format!(
                    "resolved={},predictor_supplied={}",
                    report.n_resolved, report.n_predictor_supplied
                ),
                other => format!("{other:?}"),
            },
        );
        for profile in [evidence.observation_profile(), record.observation_profile()] {
            capture.record(store, super::harness::PROFILE_KEY, profile_tag(profile));
        }
        capture.record(
            store,
            "never-participant-bound",
            evidence.observation_profile() != ScheduledObservationProfileV1::ParticipantBound,
        );
    }
    capture
}
