//! ADR-024 Revision 1 Decision 5 through the public runtime seams: Persona
//! emits its own prediction source, and Eval's non-participant scheduled
//! Driver appends `eval.*` in a later pass through the host's atomic
//! `ScheduledAiDriver` admission. Every case runs on MemoryStore and SQLite.

use std::sync::Arc;

use pos_core::{
    clock::Seq,
    event::{CanonicalBytes, Event, EventDraft, Kind},
    ids::{EntityId, EventId, PluginId, TimelineId},
    store::{EventStore, SeqRange},
    ArtifactClaimInputV1, ArtifactDataClassV1, ArtifactOptionalityV1, ArtifactStateV1,
    ArtifactTransitionRuleV1, AuthorityErrorV1, Capability, ConsentAuthority,
    ConsentCapabilityToken, ConsentGrantedV1, ErasureArtifactClassV1, ErasureContainmentGateV1,
    ErasureReferenceV1, ErasureReplayClaimV1, Plugin, RegisteredArtifactV1, ReplayClaimEvaluatorV1,
    MODALITY_PERSONA,
};
use pos_plugin_eval::{
    compute_report_from_events, EvalDerivationConfigV1, EvalDerivationDriver, EvalDiagnosticsV1,
    EvalIntegrityFindingKindV1, EvalIntegrityFindingV1, EvalPlugin, EvalReducer, OutcomePayload,
    PredictionPayload, EVENT_TYPE_OUTCOME, EVENT_TYPE_PREDICTION,
};
use pos_plugin_persona::{
    draft_prediction_source, PersonaEvalDriver, PersonaModel, PersonaPlugin, PersonaReducer,
    PredictionOutcomeV1, PredictionSourceV1, PreferencePair, EVENT_TYPE_PREDICTION_SOURCE,
};
use pos_runtime::{
    Driver, LocalScheduledAdmissionHostV1, ObservationView, PluginRegistry, RuntimeError,
    ScheduledAdmissionStoreV1, StepOutput,
};
use pos_store::{memory::MemoryStore, sqlite::SqliteStore};

trait TestValueExt<T> {
    fn test_ok(self) -> T;
}

impl<T, E: std::fmt::Debug> TestValueExt<T> for Result<T, E> {
    fn test_ok(self) -> T {
        self.unwrap_or_else(|error| {
            std::panic::resume_unwind(Box::new(format!("unexpected seam error: {error:?}")))
        })
    }
}

fn stores() -> Vec<(&'static str, Box<dyn ScheduledAdmissionStoreV1>)> {
    let mut stores: Vec<(&'static str, Box<dyn ScheduledAdmissionStoreV1>)> = vec![
        ("memory", Box::new(MemoryStore::new())),
        ("sqlite", Box::new(SqliteStore::open(":memory:").test_ok())),
    ];
    for (_, store) in &mut stores {
        store
            .bind_erasure_gate(Arc::new(ErasureContainmentGateV1::new_test_open()))
            .test_ok();
    }
    stores
}

fn quiet_pair() -> PreferencePair {
    PreferencePair {
        option_a: "quiet workspace".to_owned(),
        option_b: "busy workspace".to_owned(),
        prefers_a: true,
    }
}

fn eval_driver(max_drafts: u32, diagnostics: &EvalDiagnosticsV1) -> Box<dyn Driver> {
    Box::new(EvalDerivationDriver::new(
        EvalDerivationConfigV1::new(max_drafts).test_ok(),
        diagnostics.clone(),
    ))
}

fn register_eval(registry: &mut PluginRegistry, max_drafts: u32, diagnostics: &EvalDiagnosticsV1) {
    registry
        .register_generated(
            &EvalPlugin::new(),
            Some(Box::new(EvalReducer)),
            Some(eval_driver(max_drafts, diagnostics)),
        )
        .test_ok();
}

fn gated_registry(authority: &ConsentAuthority) -> PluginRegistry {
    PluginRegistry::new()
        .with_consent_authority(authority.clone())
        .with_erasure_gate(Arc::new(ErasureContainmentGateV1::new_test_open()))
}

/// A Persona-modality consent capability for `subject` on `timeline`. Eval's
/// subscriptions are consent-gated, so a pass observes only this subject's
/// sources.
fn persona_token(
    authority: &ConsentAuthority,
    timeline: TimelineId,
    subject: EntityId,
) -> ConsentCapabilityToken {
    authority.record_grant_on_timeline(
        timeline,
        &ConsentGrantedV1 {
            subject_id: subject,
            grantee_id: EntityId::new(),
            purpose: "eval-derivation-seam".to_owned(),
            modalities: MODALITY_PERSONA,
            min_geo_resolution: 0,
            fork_permitted: false,
            export_permitted: false,
            retention_days: 0,
            expiry_secs: 0,
            grant_seq: 1,
        },
    )
}

fn persona_and_eval(
    authority: &ConsentAuthority,
    entity: EntityId,
    diagnostics: &EvalDiagnosticsV1,
) -> PluginRegistry {
    let mut registry = gated_registry(authority);
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

/// Stage one protected anchored pass over the complete committed prefix.
fn stage(
    registry: &mut PluginRegistry,
    store: &dyn ScheduledAdmissionStoreV1,
    timeline: TimelineId,
    token: &ConsentCapabilityToken,
) -> Result<(Seq, Vec<EventDraft>), RuntimeError> {
    let head = store.logical_head(timeline).test_ok();
    let prefix = store.read(timeline, SeqRange::all()).test_ok();
    registry
        .step_all_anchored_protected(timeline, head, token.clone(), 0, &prefix)
        .map(|drafts| (head, drafts))
}

/// Stage and atomically admit one scheduled pass; returns committed drafts.
fn pass(
    registry: &mut PluginRegistry,
    store: &mut dyn ScheduledAdmissionStoreV1,
    timeline: TimelineId,
    token: &ConsentCapabilityToken,
) -> usize {
    let host = LocalScheduledAdmissionHostV1::shared().test_ok();
    let revisions = host.observe(registry, store, timeline).test_ok();
    let (head, drafts) = stage(registry, store, timeline, token).test_ok();
    if drafts.is_empty() {
        registry.commit_step_at(head, 0).test_ok();
    } else {
        host.admit(registry, store, revisions, head, 0).test_ok();
    }
    drafts.len()
}

fn events(store: &dyn ScheduledAdmissionStoreV1, timeline: TimelineId) -> Vec<Event> {
    store.read(timeline, SeqRange::all()).test_ok()
}

fn of_type<'a>(events: &'a [Event], event_type: &str) -> Vec<&'a Event> {
    events
        .iter()
        .filter(|event| event.event_type.as_str() == event_type)
        .collect()
}

/// Every source is derived exactly once, caused by the source, carrying its
/// entity and its domain-separated prediction id.
fn assert_exactly_once(events: &[Event], name: &str) {
    for source in of_type(events, EVENT_TYPE_PREDICTION_SOURCE) {
        let predictions: Vec<&Event> = of_type(events, EVENT_TYPE_PREDICTION)
            .into_iter()
            .filter(|event| event.causation_id == Some(source.id))
            .collect();
        let outcomes: Vec<&Event> = of_type(events, EVENT_TYPE_OUTCOME)
            .into_iter()
            .filter(|event| event.causation_id == Some(source.id))
            .collect();
        let payload: PredictionSourceV1 =
            ciborium::from_reader(source.payload.as_slice()).test_ok();
        let expected_outcomes = usize::from(payload.outcome != PredictionOutcomeV1::Absent);
        assert_eq!(predictions.len(), 1, "{name}: one prediction per source");
        assert_eq!(outcomes.len(), expected_outcomes, "{name}: whole unit");
        assert!(
            outcomes
                .iter()
                .all(|outcome| predictions[0].seq < outcome.seq),
            "{name}: unit order"
        );
        assert_eq!(predictions[0].entity, source.entity, "{name}: entity");
        let prediction: PredictionPayload =
            ciborium::from_reader(predictions[0].payload.as_slice()).test_ok();
        assert_eq!(prediction.prediction_id, format!("eval:src:{}", source.id));
        assert!(source.seq < predictions[0].seq, "{name}: later pass");
    }
}

fn report_claim() -> pos_core::ReplayClaimEvaluationV1 {
    ReplayClaimEvaluatorV1::evaluate(
        ErasureReplayClaimV1::Exact,
        &[ArtifactClaimInputV1 {
            registration: RegisteredArtifactV1::new(
                ErasureArtifactClassV1::CalibrationReport,
                ErasureReferenceV1::from_digest([221; 32]),
                ArtifactDataClassV1::AggregateData,
                None,
                ErasureReferenceV1::from_digest([222; 32]),
                ArtifactOptionalityV1::Required,
                ArtifactTransitionRuleV1::PreserveExact,
            ),
            current_claim: ErasureReplayClaimV1::Exact,
            state: ArtifactStateV1::Retained,
        }],
    )
    .test_ok()
}

#[test]
fn persona_sources_are_derived_by_eval_in_a_later_pass_exactly_once() {
    for (name, mut store) in stores() {
        let timeline = store.create_timeline("persona-eval").test_ok().id();
        let entity = EntityId::new();
        let authority = ConsentAuthority::new();
        let token = persona_token(&authority, timeline, entity);
        let diagnostics = EvalDiagnosticsV1::default();
        let mut registry = persona_and_eval(&authority, entity, &diagnostics);

        // Pass 1 commits only Persona's decision and source; Eval sees no
        // committed source yet.
        assert_eq!(pass(&mut registry, store.as_mut(), timeline, &token), 2);
        for _ in 0..5 {
            assert_eq!(pass(&mut registry, store.as_mut(), timeline, &token), 4);
        }

        let committed = events(store.as_ref(), timeline);
        let sources = of_type(&committed, EVENT_TYPE_PREDICTION_SOURCE);
        assert_eq!(sources.len(), 6, "{name}");
        // The newest source waits for the next eligible pass.
        let pending = sources[5].id;
        assert!(committed
            .iter()
            .all(|event| event.causation_id != Some(pending)));
        let derived: Vec<Event> = committed
            .iter()
            .filter(|event| event.id != pending)
            .cloned()
            .collect();
        assert_exactly_once(&derived, name);
        assert!(diagnostics.findings().is_empty());

        let report = compute_report_from_events(
            &committed,
            ErasureReferenceV1::from_digest([221; 32]),
            &report_claim(),
        )
        .test_ok();
        assert_eq!(report.n_resolved, 5, "{name}");
        assert_eq!(report.n_predictor_supplied, 5, "{name}");
        for outcome in of_type(&committed, EVENT_TYPE_OUTCOME) {
            let payload: OutcomePayload =
                ciborium::from_reader(outcome.payload.as_slice()).test_ok();
            assert_eq!(
                payload.evidence,
                Some(pos_plugin_eval::OutcomeEvidenceV1::PredictorSupplied)
            );
        }
    }
}

#[test]
fn restart_discard_and_fork_never_derive_a_source_twice_or_skip_one() {
    for (name, mut store) in stores() {
        let timeline = store.create_timeline("restart").test_ok().id();
        let entity = EntityId::new();
        let authority = ConsentAuthority::new();
        store
            .append(
                timeline,
                &[
                    draft_prediction_source(entity, 0.6, PredictionOutcomeV1::Observed(true)),
                    draft_prediction_source(entity, 0.2, PredictionOutcomeV1::Observed(false)),
                ],
            )
            .test_ok();
        let token = persona_token(&authority, timeline, entity);

        // A discarded pass commits nothing; the next pass derives again from
        // its own prefix.
        let diagnostics = EvalDiagnosticsV1::default();
        let mut discarded = gated_registry(&authority);
        register_eval(&mut discarded, 64, &diagnostics);
        let (_, staged) = stage(&mut discarded, store.as_ref(), timeline, &token).test_ok();
        assert_eq!(staged.len(), 4, "{name}");
        discarded.abort_step();
        assert_eq!(events(store.as_ref(), timeline).len(), 2, "{name}");

        // Fork at the boundary before derivation: each branch derives the
        // inherited sources in its own next eligible pass.
        let head = store.logical_head(timeline).test_ok();
        let fork = store.fork(timeline, head, "fork").test_ok().id();
        let fork_token = persona_token(&authority, fork, entity);

        // A restarted Driver (a fresh registry) derives from the prefix alone.
        for (branch, branch_token) in [(timeline, &token), (fork, &fork_token)] {
            let mut restarted = gated_registry(&authority);
            register_eval(&mut restarted, 64, &diagnostics);
            assert_eq!(
                pass(&mut restarted, store.as_mut(), branch, branch_token),
                4,
                "{name}"
            );
            let mut again = gated_registry(&authority);
            register_eval(&mut again, 64, &diagnostics);
            assert_eq!(
                pass(&mut again, store.as_mut(), branch, branch_token),
                0,
                "{name}"
            );
            assert_exactly_once(&events(store.as_ref(), branch), name);
        }
        assert_eq!(events(store.as_ref(), timeline).len(), 6, "{name}");
        assert_eq!(events(store.as_ref(), fork).len(), 6, "{name}");
    }
}

#[test]
fn a_capped_pass_derives_the_earliest_sources_and_leaves_the_rest() {
    for (name, mut store) in stores() {
        let timeline = store.create_timeline("capped").test_ok().id();
        let entity = EntityId::new();
        let authority = ConsentAuthority::new();
        let sources = store
            .append(
                timeline,
                &[
                    draft_prediction_source(entity, 0.6, PredictionOutcomeV1::Observed(true)),
                    draft_prediction_source(entity, 0.4, PredictionOutcomeV1::Observed(true)),
                    draft_prediction_source(entity, 0.3, PredictionOutcomeV1::Absent),
                ],
            )
            .test_ok();
        let token = persona_token(&authority, timeline, entity);
        let diagnostics = EvalDiagnosticsV1::default();
        let mut registry = gated_registry(&authority);
        register_eval(&mut registry, 3, &diagnostics);

        assert_eq!(
            pass(&mut registry, store.as_mut(), timeline, &token),
            2,
            "{name}"
        );
        let first: Vec<Option<EventId>> = events(store.as_ref(), timeline)[3..]
            .iter()
            .map(|event| event.causation_id)
            .collect();
        assert_eq!(first, vec![Some(sources[0].id); 2], "{name}");
        assert_eq!(
            pass(&mut registry, store.as_mut(), timeline, &token),
            3,
            "{name}"
        );
        assert_eq!(
            pass(&mut registry, store.as_mut(), timeline, &token),
            0,
            "{name}"
        );
    }
}

#[test]
fn a_source_behind_another_subjects_consent_is_not_observed() {
    for (name, mut store) in stores() {
        let timeline = store.create_timeline("consent-gated").test_ok().id();
        let subject = EntityId::new();
        let other = EntityId::new();
        let authority = ConsentAuthority::new();
        store
            .append(
                timeline,
                &[
                    draft_prediction_source(other, 0.6, PredictionOutcomeV1::Observed(true)),
                    draft_prediction_source(subject, 0.4, PredictionOutcomeV1::Absent),
                ],
            )
            .test_ok();
        let subject_token = persona_token(&authority, timeline, subject);
        let other_token = persona_token(&authority, timeline, other);
        let diagnostics = EvalDiagnosticsV1::default();
        let mut registry = gated_registry(&authority);
        register_eval(&mut registry, 64, &diagnostics);

        // The subject's pass derives only the subject's source.
        assert_eq!(
            pass(&mut registry, store.as_mut(), timeline, &subject_token),
            1,
            "{name}"
        );
        // The other source is derived only inside its own subject's pass.
        assert_eq!(
            pass(&mut registry, store.as_mut(), timeline, &other_token),
            2,
            "{name}"
        );
        assert_exactly_once(&events(store.as_ref(), timeline), name);
    }
}

/// A second Driver whose output must still commit beside a quarantine.
struct WitnessPlugin {
    id: PluginId,
}

impl Plugin for WitnessPlugin {
    fn id(&self) -> PluginId {
        self.id
    }

    fn name(&self) -> &'static str {
        "witness"
    }

    fn capability(&self) -> Capability {
        Capability {
            owned_event_types: vec![Kind::new("witness.tick")],
            has_driver: true,
            ..Capability::default()
        }
    }
}

struct WitnessDriver;

impl Driver for WitnessDriver {
    fn name(&self) -> &'static str {
        "witness-driver"
    }

    fn step(&mut self, _: TimelineId, _: ObservationView<'_>) -> Result<StepOutput, RuntimeError> {
        Ok(StepOutput::new(vec![EventDraft::new(
            EntityId::new(),
            Kind::new("witness.tick"),
            CanonicalBytes::from_static(b"tick"),
        )]))
    }
}

#[test]
fn an_injected_orphan_outcome_is_quarantined_without_blocking_the_pass() {
    for (name, mut store) in stores() {
        let timeline = store.create_timeline("orphan").test_ok().id();
        let entity = EntityId::new();
        let authority = ConsentAuthority::new();
        let sources = store
            .append(
                timeline,
                &[
                    draft_prediction_source(entity, 0.6, PredictionOutcomeV1::Observed(true)),
                    draft_prediction_source(entity, 0.4, PredictionOutcomeV1::Observed(false)),
                ],
            )
            .test_ok();
        let orphaned = sources[0].id;
        let mut orphan = pos_plugin_eval::draft_outcome(entity, "eval:src:orphan", true);
        orphan.causation_id = Some(orphaned);
        store.append(timeline, &[orphan]).test_ok();
        let token = persona_token(&authority, timeline, entity);

        let diagnostics = EvalDiagnosticsV1::default();
        let mut registry = gated_registry(&authority);
        register_eval(&mut registry, 64, &diagnostics);
        registry
            .register_generated(
                &WitnessPlugin {
                    id: PluginId::new(),
                },
                None,
                Some(Box::new(WitnessDriver)),
            )
            .test_ok();

        assert_eq!(
            pass(&mut registry, store.as_mut(), timeline, &token),
            3,
            "{name}"
        );
        let committed = events(store.as_ref(), timeline);
        // (a) The other source still derives.
        let healthy: Vec<Event> = committed
            .iter()
            .filter(|event| event.id != orphaned && event.causation_id != Some(orphaned))
            .cloned()
            .collect();
        assert_exactly_once(&healthy, name);
        // (b) No second outcome and no repair for the quarantined source.
        let caused_by_orphaned = committed
            .iter()
            .filter(|event| event.causation_id == Some(orphaned))
            .count();
        assert_eq!(caused_by_orphaned, 1, "{name}");
        // (c) The other Driver's output in the same pass commits.
        assert_eq!(of_type(&committed, "witness.tick").len(), 1, "{name}");
        assert_eq!(
            diagnostics.findings(),
            vec![EvalIntegrityFindingV1 {
                source: orphaned,
                kind: EvalIntegrityFindingKindV1::OrphanOutcome,
            }]
        );

        // The quarantine recurs while the prefix is unchanged.
        assert_eq!(
            pass(&mut registry, store.as_mut(), timeline, &token),
            1,
            "{name}"
        );
        assert_eq!(diagnostics.findings().len(), 1, "{name}");
    }
}

/// A Persona-registered Driver that still tries to emit `eval.*`.
struct LegacyPersonaDriver {
    entity: EntityId,
}

impl Driver for LegacyPersonaDriver {
    fn name(&self) -> &'static str {
        "legacy-persona-eval"
    }

    fn step(&mut self, _: TimelineId, _: ObservationView<'_>) -> Result<StepOutput, RuntimeError> {
        Ok(StepOutput::new(vec![pos_plugin_eval::draft_prediction(
            self.entity,
            "legacy",
            0.5,
            "pred-0",
        )]))
    }
}

#[test]
fn persona_cannot_emit_eval_records_and_nothing_commits() {
    for (name, mut store) in stores() {
        let timeline = store.create_timeline("persona-intruder").test_ok().id();
        let entity = EntityId::new();
        let authority = ConsentAuthority::new();
        let token = persona_token(&authority, timeline, entity);
        let diagnostics = EvalDiagnosticsV1::default();
        let mut registry = gated_registry(&authority);
        registry
            .register_generated(
                &PersonaPlugin::new(),
                Some(Box::new(PersonaReducer)),
                Some(Box::new(LegacyPersonaDriver { entity })),
            )
            .test_ok();
        register_eval(&mut registry, 64, &diagnostics);
        assert!(!PersonaPlugin::new()
            .capability()
            .owned_event_types
            .iter()
            .any(|kind| kind.as_str().starts_with("eval.")));

        let host = LocalScheduledAdmissionHostV1::shared().test_ok();
        let _revisions = host.observe(&registry, store.as_mut(), timeline).test_ok();
        assert!(matches!(
            stage(&mut registry, store.as_ref(), timeline, &token),
            Err(RuntimeError::Authority(
                AuthorityErrorV1::UnauthorizedSource
            ))
        ));
        assert!(events(store.as_ref(), timeline).is_empty(), "{name}");
    }
}
