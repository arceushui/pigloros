//! ADR-024 Revision 2 through the public runtime seams: a bad eligible
//! Persona prediction source is quarantined with a typed finding and never
//! blocks the scheduled pass, each source has exactly one outcome per pass,
//! a source with a complete pair is never decoded, and only an invalid
//! verified prefix (or the host's erasure fence) stops a pass. Every case
//! runs on `MemoryStore` and `SqliteStore`.

use std::sync::Arc;

use pos_core::{
    event::{CanonicalBytes, Event, EventDraft, Kind},
    ids::{EntityId, EventId, PluginId, TimelineId},
    store::SeqRange,
    Capability, ConsentAuthority, ConsentCapabilityToken, ConsentGrantedV1,
    ErasureContainmentGateV1, Plugin, MODALITY_PERSONA,
};
use pos_plugin_eval::{
    EvalDerivationConfigV1, EvalDerivationDriver, EvalDiagnosticsV1,
    EvalIntegrityFindingKindV1::{
        InvalidPrediction, MissingOutcome, OrphanOutcome, UndecodableSource,
        UnsupportedSourceVersion,
    },
    EvalPlugin, EvalReducer, OutcomeEvidenceV1, OutcomePayload, PredictionPayload,
    EVENT_TYPE_OUTCOME, EVENT_TYPE_PREDICTION,
};
use pos_plugin_persona::{draft_prediction_source, PredictionOutcomeV1};
use pos_runtime::{
    Driver, InstalledOutputPolicySourceV1, LocalScheduledAdmissionHostV1, ObservationView,
    OutputPolicyBindingV1, PluginRegistry, RuntimeError, ScheduledAdmissionStoreV1, StepOutput,
};
use pos_store::{memory::MemoryStore, sqlite::SqliteStore};

pub mod common;

use common::{
    envelope_only, finding, naming_drafts, raw_source, unreadable, TestOptionExt, TestValueExt,
};

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

fn mapping(max_drafts: u32, versions: &[u32]) -> EvalDerivationConfigV1 {
    EvalDerivationConfigV1::new(max_drafts)
        .test_ok()
        .with_source_versions(versions.iter().copied())
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

/// A consent-gated registry with Eval under `config` and the witness Driver,
/// fenced by `gate`.
fn registry(
    authority: &ConsentAuthority,
    gate: Arc<ErasureContainmentGateV1>,
    config: EvalDerivationConfigV1,
    diagnostics: &EvalDiagnosticsV1,
) -> PluginRegistry {
    let mut registry = PluginRegistry::new()
        .with_consent_authority(authority.clone())
        .with_erasure_gate(gate);
    let eval = EvalPlugin::new();
    let binding = OutputPolicyBindingV1::from_installed_source(
        &eval,
        InstalledOutputPolicySourceV1::Generated,
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
    registry
        .register_generated(
            &WitnessPlugin {
                id: PluginId::new(),
            },
            None,
            Some(Box::new(WitnessDriver)),
        )
        .test_ok();
    registry
}

fn open_registry(
    authority: &ConsentAuthority,
    config: EvalDerivationConfigV1,
    diagnostics: &EvalDiagnosticsV1,
) -> PluginRegistry {
    registry(
        authority,
        Arc::new(ErasureContainmentGateV1::new_test_open()),
        config,
        diagnostics,
    )
}

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
            purpose: "eval-source-quarantine-seam".to_owned(),
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

/// Stage one protected anchored pass over `prefix` at the Logical Head.
fn stage_over(
    registry: &mut PluginRegistry,
    store: &dyn ScheduledAdmissionStoreV1,
    timeline: TimelineId,
    token: &ConsentCapabilityToken,
    prefix: &[Event],
) -> Result<Vec<EventDraft>, RuntimeError> {
    let head = store.logical_head(timeline).test_ok();
    registry.step_all_anchored_protected(timeline, head, token.clone(), 0, prefix)
}

/// Stage and atomically admit one scheduled pass; returns the committed
/// draft types in pass order.
fn pass(
    registry: &mut PluginRegistry,
    store: &mut dyn ScheduledAdmissionStoreV1,
    timeline: TimelineId,
    token: &ConsentCapabilityToken,
) -> Vec<String> {
    let host = LocalScheduledAdmissionHostV1::shared().test_ok();
    let revisions = host.observe(registry, &mut *store, timeline).test_ok();
    let head = store.logical_head(timeline).test_ok();
    let prefix = events(&*store, timeline);
    let drafts = stage_over(registry, &*store, timeline, token, &prefix).test_ok();
    host.admit(registry, &mut *store, revisions, head, 0)
        .test_ok();
    drafts
        .iter()
        .map(|draft| draft.event_type.as_str().to_owned())
        .collect()
}

fn events(store: &dyn ScheduledAdmissionStoreV1, timeline: TimelineId) -> Vec<Event> {
    store.read(timeline, SeqRange::all()).test_ok()
}

fn ids(
    store: &mut dyn ScheduledAdmissionStoreV1,
    timeline: TimelineId,
    drafts: &[EventDraft],
) -> Vec<EventId> {
    store
        .append(timeline, drafts)
        .test_ok()
        .iter()
        .map(|event| event.id)
        .collect()
}

/// Committed `eval.*` Events caused by `source`, by type.
fn derived_for(events: &[Event], source: EventId) -> Vec<&str> {
    events
        .iter()
        .filter(|event| event.causation_id == Some(source))
        .map(|event| event.event_type.as_str())
        .collect()
}

fn eval_drafts(types: &[String]) -> usize {
    types
        .iter()
        .filter(|event_type| event_type.starts_with("eval."))
        .count()
}

#[test]
fn each_bad_eligible_source_is_quarantined_while_the_pass_commits_and_recurs() {
    for (name, mut store) in stores() {
        let timeline = store.create_timeline("quarantine").test_ok().id();
        let entity = EntityId::new();
        let authority = ConsentAuthority::new();
        let sources = ids(
            store.as_mut(),
            timeline,
            &[
                draft_prediction_source(entity, 0.6, PredictionOutcomeV1::Observed(true)),
                unreadable(entity),
                raw_source(entity, 2, 0.5, PredictionOutcomeV1::Observed(true)),
                envelope_only(entity, 1),
                raw_source(entity, 1, f64::NAN, PredictionOutcomeV1::Observed(true)),
                draft_prediction_source(entity, 0.4, PredictionOutcomeV1::Absent),
            ],
        );
        let token = persona_token(&authority, timeline, entity);
        let diagnostics = EvalDiagnosticsV1::default();
        // Three drafts admit exactly the two good units, so a quarantined
        // source that consumed any budget would push the last one out.
        let mut registry = open_registry(&authority, mapping(3, &[1]), &diagnostics);

        let committed = pass(&mut registry, store.as_mut(), timeline, &token);

        assert_eq!(eval_drafts(&committed), 3, "{name}");
        assert_eq!(
            committed.iter().filter(|t| *t == "witness.tick").count(),
            1,
            "{name}: another Driver's output commits"
        );
        let history = events(store.as_ref(), timeline);
        assert_eq!(
            derived_for(&history, sources[0]),
            vec![EVENT_TYPE_PREDICTION, EVENT_TYPE_OUTCOME],
            "{name}"
        );
        assert_eq!(
            derived_for(&history, sources[5]),
            vec![EVENT_TYPE_PREDICTION],
            "{name}"
        );
        let quarantined = vec![
            finding(sources[1], UndecodableSource),
            finding(sources[2], UnsupportedSourceVersion),
            finding(sources[3], UndecodableSource),
            finding(sources[4], InvalidPrediction),
        ];
        assert_eq!(diagnostics.findings(), quarantined, "{name}");
        for bad in &sources[1..5] {
            assert!(derived_for(&history, *bad).is_empty(), "{name}");
        }

        // The quarantine recurs: the bad sources stay eligible and are
        // checked again; the complete pair is not decoded again.
        let again = pass(&mut registry, store.as_mut(), timeline, &token);
        assert_eq!(again, vec!["witness.tick".to_owned()], "{name}");
        assert_eq!(diagnostics.findings(), quarantined, "{name}");
        assert_eq!(
            diagnostics.decoded_sources(),
            sources[1..].to_vec(),
            "{name}"
        );
    }
}

#[test]
fn invalid_probabilities_are_quarantined_and_the_closed_bounds_derive() {
    for (name, mut store) in stores() {
        let timeline = store.create_timeline("probabilities").test_ok().id();
        let entity = EntityId::new();
        let authority = ConsentAuthority::new();
        let observed = PredictionOutcomeV1::Observed(true);
        let probabilities = [
            0.0,
            f64::NAN,
            f64::INFINITY,
            f64::NEG_INFINITY,
            -0.000_001,
            1.000_001,
            1.0,
        ];
        let drafts: Vec<EventDraft> = probabilities
            .iter()
            .map(|probability| raw_source(entity, 1, *probability, observed))
            .collect();
        let sources = ids(store.as_mut(), timeline, &drafts);
        let token = persona_token(&authority, timeline, entity);
        let diagnostics = EvalDiagnosticsV1::default();
        let mut registry = open_registry(&authority, mapping(64, &[1]), &diagnostics);

        assert_eq!(
            eval_drafts(&pass(&mut registry, store.as_mut(), timeline, &token)),
            4,
            "{name}"
        );
        assert_eq!(
            diagnostics.findings(),
            sources[1..6]
                .iter()
                .map(|source| finding(*source, InvalidPrediction))
                .collect::<Vec<_>>(),
            "{name}"
        );
        let derived: Vec<f64> = events(store.as_ref(), timeline)
            .iter()
            .filter(|event| event.event_type.as_str() == EVENT_TYPE_PREDICTION)
            .map(|event| {
                ciborium::from_reader::<PredictionPayload, _>(event.payload.as_slice())
                    .test_ok()
                    .predicted_prob
            })
            .collect();
        assert_eq!(derived.len(), 2, "{name}");
        assert!(derived[0].abs() < f64::EPSILON, "{name}");
        assert!((derived[1] - 1.0).abs() < f64::EPSILON, "{name}");
    }
}

#[test]
fn a_later_mapping_derives_a_quarantined_source_exactly_once() {
    for (name, mut store) in stores() {
        let timeline = store.create_timeline("later-mapping").test_ok().id();
        let entity = EntityId::new();
        let authority = ConsentAuthority::new();
        let sources = ids(
            store.as_mut(),
            timeline,
            &[
                raw_source(entity, 2, 0.3, PredictionOutcomeV1::Observed(false)),
                draft_prediction_source(entity, 0.7, PredictionOutcomeV1::Observed(true)),
            ],
        );
        let newer = sources[0];
        let token = persona_token(&authority, timeline, entity);
        let diagnostics = EvalDiagnosticsV1::default();

        let mut pinned = open_registry(&authority, mapping(64, &[1]), &diagnostics);
        assert_eq!(
            eval_drafts(&pass(&mut pinned, store.as_mut(), timeline, &token)),
            2,
            "{name}"
        );
        assert_eq!(
            diagnostics.findings(),
            vec![finding(newer, UnsupportedSourceVersion)],
            "{name}"
        );

        // A later pinned configuration adds the mapping for version 2.
        let mut later = open_registry(&authority, mapping(64, &[1, 2]), &diagnostics);
        assert_eq!(
            eval_drafts(&pass(&mut later, store.as_mut(), timeline, &token)),
            2,
            "{name}"
        );
        assert!(diagnostics.findings().is_empty(), "{name}");
        assert_eq!(
            eval_drafts(&pass(&mut later, store.as_mut(), timeline, &token)),
            0,
            "{name}"
        );
        assert!(diagnostics.decoded_sources().is_empty(), "{name}");

        let history = events(store.as_ref(), timeline);
        assert_eq!(
            derived_for(&history, newer),
            vec![EVENT_TYPE_PREDICTION, EVENT_TYPE_OUTCOME],
            "{name}: derived once, as one unit"
        );
        let outcome = history
            .iter()
            .find(|event| {
                event.causation_id == Some(newer) && event.event_type.as_str() == EVENT_TYPE_OUTCOME
            })
            .map(|event| {
                ciborium::from_reader::<OutcomePayload, _>(event.payload.as_slice()).test_ok()
            })
            .test_ok_option();
        assert!(!outcome.outcome, "{name}");
        assert_eq!(
            outcome.evidence,
            Some(OutcomeEvidenceV1::PredictorSupplied),
            "{name}"
        );
    }
}

#[test]
fn a_mapping_rollback_records_findings_only_and_never_rederives() {
    for (name, mut store) in stores() {
        let timeline = store.create_timeline("rollback").test_ok().id();
        let entity = EntityId::new();
        let authority = ConsentAuthority::new();
        let derived = ids(
            store.as_mut(),
            timeline,
            &[
                draft_prediction_source(entity, 0.6, PredictionOutcomeV1::Observed(true)),
                draft_prediction_source(entity, 0.4, PredictionOutcomeV1::Absent),
            ],
        );
        let token = persona_token(&authority, timeline, entity);
        let diagnostics = EvalDiagnosticsV1::default();
        let mut pinned = open_registry(&authority, mapping(64, &[1]), &diagnostics);
        assert_eq!(
            eval_drafts(&pass(&mut pinned, store.as_mut(), timeline, &token)),
            3,
            "{name}"
        );
        let eligible = ids(
            store.as_mut(),
            timeline,
            &[draft_prediction_source(
                entity,
                0.5,
                PredictionOutcomeV1::Observed(true),
            )],
        )[0];

        // A later configuration drops the version 1 mapping.
        let mut rolled_back = open_registry(&authority, mapping(64, &[]), &diagnostics);
        assert_eq!(
            eval_drafts(&pass(&mut rolled_back, store.as_mut(), timeline, &token)),
            0,
            "{name}"
        );
        assert_eq!(
            diagnostics.findings(),
            vec![
                // Derived with a prediction and no outcome: decoded, unsupported.
                finding(derived[1], UnsupportedSourceVersion),
                finding(eligible, UnsupportedSourceVersion),
            ],
            "{name}"
        );
        // The complete pair is never decoded and records nothing.
        assert_eq!(
            diagnostics.decoded_sources(),
            vec![derived[1], eligible],
            "{name}"
        );
        let history = events(store.as_ref(), timeline);
        assert_eq!(derived_for(&history, derived[0]).len(), 2, "{name}");
        assert_eq!(derived_for(&history, derived[1]).len(), 1, "{name}");
        assert!(derived_for(&history, eligible).is_empty(), "{name}");
    }
}

/// The host commits a pass whose only Eval output is diagnostics, and
/// publishes which sources it decoded. The full precedence scenario is a
/// pure-function test in `derivation.rs`.
#[test]
fn the_host_publishes_partial_pair_findings_and_the_decoded_sources() {
    for (name, mut store) in stores() {
        let timeline = store.create_timeline("precedence").test_ok().id();
        let entity = EntityId::new();
        let authority = ConsentAuthority::new();
        let sources = ids(
            store.as_mut(),
            timeline,
            &[
                unreadable(entity),
                unreadable(entity),
                raw_source(entity, 1, 0.5, PredictionOutcomeV1::Observed(true)),
            ],
        );
        for (source, prediction, outcome) in [
            (sources[0], false, true),
            (sources[1], true, true),
            (sources[2], true, false),
        ] {
            store
                .append(timeline, &naming_drafts(source, prediction, outcome))
                .test_ok();
        }
        let token = persona_token(&authority, timeline, entity);
        let diagnostics = EvalDiagnosticsV1::default();
        let mut registry = open_registry(&authority, mapping(64, &[1]), &diagnostics);

        let committed = pass(&mut registry, store.as_mut(), timeline, &token);

        assert_eq!(committed, vec!["witness.tick".to_owned()], "{name}");
        assert_eq!(
            diagnostics.findings(),
            vec![
                finding(sources[0], OrphanOutcome),
                finding(sources[2], MissingOutcome),
            ],
            "{name}"
        );
        // Neither the orphan nor the complete pair is decoded.
        assert_eq!(diagnostics.decoded_sources(), vec![sources[2]], "{name}");
    }
}

#[test]
fn an_invalid_verified_prefix_still_discards_the_pass() {
    for (name, mut store) in stores() {
        let timeline = store.create_timeline("invalid-prefix").test_ok().id();
        let entity = EntityId::new();
        let authority = ConsentAuthority::new();
        store
            .append(
                timeline,
                &[
                    draft_prediction_source(entity, 0.6, PredictionOutcomeV1::Observed(true)),
                    unreadable(entity),
                ],
            )
            .test_ok();
        let token = persona_token(&authority, timeline, entity);
        let diagnostics = EvalDiagnosticsV1::default();
        let mut registry = open_registry(&authority, mapping(64, &[1]), &diagnostics);
        let complete = events(store.as_ref(), timeline);

        // The prefix handed to the host lacks its first Event.
        let error = stage_over(
            &mut registry,
            store.as_ref(),
            timeline,
            &token,
            &complete[1..],
        );

        assert!(
            matches!(error, Err(RuntimeError::InvalidRecoveryEvidence { .. })),
            "{name}: {error:?}"
        );
        registry.abort_step();
        assert_eq!(events(store.as_ref(), timeline).len(), 2, "{name}");
        assert!(diagnostics.findings().is_empty(), "{name}");
        assert!(diagnostics.decoded_sources().is_empty(), "{name}");
    }
}

#[test]
fn a_timeline_inside_a_frozen_erasure_scope_never_reaches_eval() {
    for (name, mut store) in stores() {
        let entity = EntityId::new();
        let authority = ConsentAuthority::new();
        let bad_sources = [
            draft_prediction_source(entity, 0.6, PredictionOutcomeV1::Observed(true)),
            unreadable(entity),
        ];
        let frozen = store.create_timeline("frozen").test_ok().id();
        let open = store.create_timeline("open").test_ok().id();
        store.append(frozen, &bad_sources).test_ok();
        let open_sources = ids(store.as_mut(), open, &bad_sources);
        let gate = Arc::new(ErasureContainmentGateV1::new_test_open());
        let diagnostics = EvalDiagnosticsV1::default();
        let mut registry = registry(
            &authority,
            Arc::clone(&gate),
            mapping(64, &[1]),
            &diagnostics,
        );
        gate.freeze_timeline_for_test(frozen);

        // The host's ADR-060 fence refuses the whole pass before any Driver
        // observes the frozen Timeline: no drafts, no finding, nothing decoded.
        let frozen_token = persona_token(&authority, frozen, entity);
        let prefix = events(store.as_ref(), frozen);
        let error = stage_over(
            &mut registry,
            store.as_ref(),
            frozen,
            &frozen_token,
            &prefix,
        );
        assert!(
            matches!(error, Err(RuntimeError::ErasureContainment(_))),
            "{name}: {error:?}"
        );
        assert_eq!(events(store.as_ref(), frozen).len(), 2, "{name}");
        assert!(diagnostics.findings().is_empty(), "{name}");
        assert!(diagnostics.decoded_sources().is_empty(), "{name}");

        // The same sources on an authorized Timeline do reach Eval.
        let open_token = persona_token(&authority, open, entity);
        assert_eq!(
            eval_drafts(&pass(&mut registry, store.as_mut(), open, &open_token)),
            2,
            "{name}"
        );
        assert_eq!(
            diagnostics.findings(),
            vec![finding(open_sources[1], UndecodableSource)],
            "{name}"
        );
    }
}
