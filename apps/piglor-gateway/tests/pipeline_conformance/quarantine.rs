//! ADR-024 Revision 2: bad eligible Persona sources are quarantined with a
//! typed finding and never block the scheduled pass (#493).

use std::sync::Arc;

use pos_core::{
    CanonicalBytes, ConsentAuthority, ConsentCapabilityToken, EntityId, ErasureContainmentGateV1,
    Event, EventDraft, EventId, Kind, TimelineId,
};
use pos_plugin_eval::{
    draft_outcome, draft_prediction, EvalDerivationConfigV1, EvalDerivationDriver,
    EvalDiagnosticsV1, EvalPlugin, EvalReducer,
};
use pos_plugin_persona::{PredictionOutcomeV1, PredictionSourceV1, EVENT_TYPE_PREDICTION_SOURCE};
use pos_runtime::{
    OutputPolicyBindingV1, OutputPolicySourceV1, PluginRegistry, RuntimeError,
    ScheduledAdmissionStoreV1,
};

use super::{
    harness::Capture,
    support::{
        ancestry, draft, events, expect_err, pass, persona_token, stage, stores, FixturePlugin,
        ScriptedDriver, TestOk,
    },
};

const WITNESS: &str = "witness.tick";

fn mapping(max_drafts: u32, versions: &[u32]) -> EvalDerivationConfigV1 {
    EvalDerivationConfigV1::new(max_drafts)
        .test_ok()
        .with_source_versions(versions.iter().copied())
}

/// Eval under `config` beside a witness Driver, behind `gate`.
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
    registry
        .register_generated(
            &FixturePlugin::new("witness", &[WITNESS], true),
            None,
            Some(Box::new(ScriptedDriver::new(
                "witness",
                vec![draft(EntityId::new(), WITNESS, b"tick")],
            ))),
        )
        .test_ok();
    registry.compose_non_participant_drivers().test_ok();
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

fn source_draft(entity: EntityId, payload: Vec<u8>) -> EventDraft {
    EventDraft::new(
        entity,
        Kind::new(EVENT_TYPE_PREDICTION_SOURCE),
        CanonicalBytes::from_vec(payload),
    )
}

/// A source with an explicit version, probability and outcome.
fn raw_source(
    entity: EntityId,
    version: u32,
    probability: f64,
    outcome: PredictionOutcomeV1,
) -> EventDraft {
    let mut payload = Vec::new();
    ciborium::into_writer(
        &PredictionSourceV1 {
            version,
            predicted_prob: probability,
            outcome,
        },
        &mut payload,
    )
    .test_ok();
    source_draft(entity, payload)
}

fn good(entity: EntityId, outcome: bool) -> EventDraft {
    raw_source(entity, 1, 0.5, PredictionOutcomeV1::Observed(outcome))
}

/// A source whose payload is not CBOR at all.
fn unreadable(entity: EntityId) -> EventDraft {
    source_draft(entity, vec![0xff])
}

/// The `eval.*` drafts an earlier pass would have committed for `source`.
fn naming(source: EventId, prediction: bool, outcome: bool) -> Vec<EventDraft> {
    let prediction_id = format!("eval:src:{source}");
    let entity = EntityId::new();
    prediction
        .then(|| draft_prediction(entity, "injected", 0.5, &prediction_id))
        .into_iter()
        .chain(outcome.then(|| draft_outcome(entity, &prediction_id, true)))
        .map(|mut draft| {
            draft.causation_id = Some(source);
            draft
        })
        .collect()
}

fn append(
    backend: &mut dyn ScheduledAdmissionStoreV1,
    timeline: TimelineId,
    drafts: &[EventDraft],
) -> Vec<EventId> {
    backend
        .append(timeline, drafts)
        .test_ok()
        .iter()
        .map(|event| event.id)
        .collect()
}

fn index(sources: &[EventId], id: EventId) -> String {
    sources
        .iter()
        .position(|source| *source == id)
        .map_or_else(|| "other".to_owned(), |position| position.to_string())
}

/// Findings of the last committed pass as `Kind@source-index`.
fn findings(diagnostics: &EvalDiagnosticsV1, sources: &[EventId]) -> String {
    diagnostics
        .findings()
        .iter()
        .map(|finding| format!("{:?}@{}", finding.kind, index(sources, finding.source)))
        .collect::<Vec<_>>()
        .join(",")
}

/// Sources the last committed pass decoded, as source indices.
fn decoded(diagnostics: &EvalDiagnosticsV1, sources: &[EventId]) -> String {
    diagnostics
        .decoded_sources()
        .iter()
        .map(|id| index(sources, *id))
        .collect::<Vec<_>>()
        .join(",")
}

/// Committed `eval.*` Events after `from` as `type<-source-index`.
fn derived(committed: &[Event], from: usize, sources: &[EventId]) -> String {
    committed[from..]
        .iter()
        .filter(|event| event.event_type.as_str().starts_with("eval."))
        .map(|event| {
            let cause = event
                .causation_id
                .map_or_else(|| "none".to_owned(), |cause| index(sources, cause));
            format!("{}<-{cause}", event.event_type.as_str())
        })
        .collect::<Vec<_>>()
        .join(",")
}

fn witnesses(committed: &[Event], from: usize) -> usize {
    committed[from..]
        .iter()
        .filter(|event| event.event_type.as_str() == WITNESS)
        .count()
}

/// One protected pass; returns how many Events it committed.
fn protected_pass(
    registry: &mut PluginRegistry,
    backend: &mut dyn ScheduledAdmissionStoreV1,
    timeline: TimelineId,
    token: &ConsentCapabilityToken,
) -> usize {
    pass(registry, backend, timeline, Some(token)).test_ok()
}

/// PCF-EVAL-R2-001: an undecodable, unsupported-version or out-of-range
/// eligible source is quarantined with its typed finding.
///
/// Other sources still derive whole units in Timeline Order within a budget
/// the bad source does not consume, another Driver's output commits, the
/// pass is not discarded, and the finding recurs while the source stays
/// eligible.
#[must_use]
pub fn bad_eligible_sources_are_quarantined() -> Capture {
    let mut capture = Capture::default();
    for (store, mut backend) in stores() {
        for (kind, bad) in [
            ("undecodable", unreadable as fn(EntityId) -> EventDraft),
            ("unsupported", |entity| {
                raw_source(entity, 2, 0.5, PredictionOutcomeV1::Observed(true))
            }),
            ("invalid", |entity| {
                raw_source(entity, 1, 1.5, PredictionOutcomeV1::Observed(true))
            }),
        ] {
            let timeline = backend.create_timeline(kind).test_ok().id();
            let entity = EntityId::new();
            let authority = ConsentAuthority::new();
            let sources = append(
                backend.as_mut(),
                timeline,
                &[good(entity, true), bad(entity), good(entity, false)],
            );
            let token = persona_token(&authority, timeline, entity);
            let diagnostics = EvalDiagnosticsV1::default();
            // The budget holds exactly the two good units.
            let mut registry = open_registry(&authority, mapping(4, &[1]), &diagnostics);
            let first = protected_pass(&mut registry, backend.as_mut(), timeline, &token);
            let committed = events(backend.as_ref(), timeline);
            capture.record(store, &format!("{kind}.pass"), first);
            capture.record(
                store,
                &format!("{kind}.derived"),
                derived(&committed, 3, &sources),
            );
            capture.record(store, &format!("{kind}.witness"), witnesses(&committed, 3));
            capture.record(
                store,
                &format!("{kind}.finding"),
                findings(&diagnostics, &sources),
            );
            let recurrence = protected_pass(&mut registry, backend.as_mut(), timeline, &token);
            capture.record(store, &format!("{kind}.recurrence.pass"), recurrence);
            capture.record(
                store,
                &format!("{kind}.recurrence.finding"),
                findings(&diagnostics, &sources),
            );
        }
    }
    capture
}

/// PCF-EVAL-R2-002: NaN, both infinities and values just outside `[0, 1]`
/// are quarantined as `InvalidPrediction`; the bounds 0 and 1 derive.
#[must_use]
pub fn invalid_probabilities_are_quarantined() -> Capture {
    let mut capture = Capture::default();
    for (store, mut backend) in stores() {
        let timeline = backend.create_timeline("probabilities").test_ok().id();
        let entity = EntityId::new();
        let authority = ConsentAuthority::new();
        let drafts: Vec<EventDraft> = [
            f64::NAN,
            f64::INFINITY,
            f64::NEG_INFINITY,
            -0.000_001,
            1.000_001,
            0.0,
            1.0,
        ]
        .into_iter()
        .map(|probability| raw_source(entity, 1, probability, PredictionOutcomeV1::Absent))
        .collect();
        let sources = append(backend.as_mut(), timeline, &drafts);
        let token = persona_token(&authority, timeline, entity);
        let diagnostics = EvalDiagnosticsV1::default();
        let mut registry = open_registry(&authority, mapping(64, &[1]), &diagnostics);
        let committed_drafts = protected_pass(&mut registry, backend.as_mut(), timeline, &token);
        let committed = events(backend.as_ref(), timeline);
        capture.record(store, "pass", committed_drafts);
        capture.record(store, "derived", derived(&committed, 7, &sources));
        capture.record(store, "findings", findings(&diagnostics, &sources));
    }
    capture
}

/// PCF-EVAL-R2-003: a quarantined unsupported source derives exactly once,
/// as one unit, under a later pinned configuration that supports its version.
#[must_use]
pub fn later_mapping_derives_once() -> Capture {
    let mut capture = Capture::default();
    for (store, mut backend) in stores() {
        let timeline = backend.create_timeline("later-mapping").test_ok().id();
        let entity = EntityId::new();
        let authority = ConsentAuthority::new();
        let sources = append(
            backend.as_mut(),
            timeline,
            &[raw_source(
                entity,
                2,
                0.25,
                PredictionOutcomeV1::Observed(false),
            )],
        );
        let token = persona_token(&authority, timeline, entity);
        let diagnostics = EvalDiagnosticsV1::default();
        let mut v1 = open_registry(&authority, mapping(64, &[1]), &diagnostics);
        let quarantined = protected_pass(&mut v1, backend.as_mut(), timeline, &token);
        capture.record(store, "v1.pass", quarantined);
        capture.record(store, "v1.finding", findings(&diagnostics, &sources));
        let mut v2 = open_registry(&authority, mapping(64, &[1, 2]), &diagnostics);
        let first = protected_pass(&mut v2, backend.as_mut(), timeline, &token);
        let again = protected_pass(&mut v2, backend.as_mut(), timeline, &token);
        let committed = events(backend.as_ref(), timeline);
        capture.record(store, "v2.passes", format!("{first},{again}"));
        capture.record(store, "v2.derived", derived(&committed, 1, &sources));
        capture.record(store, "v2.finding", findings(&diagnostics, &sources));
    }
    capture
}

/// PCF-EVAL-R2-004: a mapping rollback records findings and never re-derives.
///
/// After a configuration drops a version's mapping, its eligible sources
/// record `UnsupportedSourceVersion`, a derived source records it only under
/// the `MissingOutcome` condition, a complete pair records nothing and is
/// never decoded, and nothing is re-derived.
#[must_use]
pub fn mapping_rollback_never_rederives() -> Capture {
    let mut capture = Capture::default();
    for (store, mut backend) in stores() {
        let timeline = backend.create_timeline("rollback").test_ok().id();
        let entity = EntityId::new();
        let authority = ConsentAuthority::new();
        let sources = append(
            backend.as_mut(),
            timeline,
            &[good(entity, true), good(entity, true), good(entity, true)],
        );
        append(backend.as_mut(), timeline, &naming(sources[0], true, true));
        append(backend.as_mut(), timeline, &naming(sources[1], true, false));
        let token = persona_token(&authority, timeline, entity);
        let diagnostics = EvalDiagnosticsV1::default();
        let mut registry = open_registry(&authority, mapping(64, &[]), &diagnostics);
        let committed_before = events(backend.as_ref(), timeline).len();
        let committed_drafts = protected_pass(&mut registry, backend.as_mut(), timeline, &token);
        let committed = events(backend.as_ref(), timeline);
        capture.record(store, "pass", committed_drafts);
        capture.record(
            store,
            "derived",
            derived(&committed, committed_before, &sources),
        );
        capture.record(store, "findings", findings(&diagnostics, &sources));
        capture.record(store, "decoded", decoded(&diagnostics, &sources));
    }
    capture
}

/// PCF-EVAL-R2-005: each source has exactly one outcome per pass, in the
/// Revision 2 precedence order, and a complete pair is never decoded.
#[must_use]
pub fn precedence_and_bounded_decoding() -> Capture {
    let mut capture = Capture::default();
    for (store, mut backend) in stores() {
        let timeline = backend.create_timeline("precedence").test_ok().id();
        let entity = EntityId::new();
        let authority = ConsentAuthority::new();
        let sources = append(
            backend.as_mut(),
            timeline,
            &[
                unreadable(entity),
                good(entity, true),
                raw_source(entity, 1, 0.5, PredictionOutcomeV1::Absent),
                unreadable(entity),
                unreadable(entity),
            ],
        );
        append(backend.as_mut(), timeline, &naming(sources[0], false, true));
        append(backend.as_mut(), timeline, &naming(sources[1], true, false));
        append(backend.as_mut(), timeline, &naming(sources[2], true, false));
        append(backend.as_mut(), timeline, &naming(sources[3], true, false));
        append(backend.as_mut(), timeline, &naming(sources[4], true, true));
        let token = persona_token(&authority, timeline, entity);
        let diagnostics = EvalDiagnosticsV1::default();
        let mut registry = open_registry(&authority, mapping(64, &[1]), &diagnostics);
        let committed_before = events(backend.as_ref(), timeline).len();
        let committed_drafts = protected_pass(&mut registry, backend.as_mut(), timeline, &token);
        let committed = events(backend.as_ref(), timeline);
        capture.record(store, "pass", committed_drafts);
        capture.record(
            store,
            "derived",
            derived(&committed, committed_before, &sources),
        );
        capture.record(store, "witness", witnesses(&committed, committed_before));
        capture.record(store, "findings", findings(&diagnostics, &sources));
        capture.record(store, "decoded", decoded(&diagnostics, &sources));
    }
    capture
}

/// PCF-EVAL-R2-006: an invalid verified prefix is still a typed Driver
/// failure that discards the pass.
#[must_use]
pub fn invalid_prefix_discards_the_pass() -> Capture {
    let mut capture = Capture::default();
    for (store, mut backend) in stores() {
        let timeline = backend.create_timeline("invalid-prefix").test_ok().id();
        let entity = EntityId::new();
        let authority = ConsentAuthority::new();
        append(
            backend.as_mut(),
            timeline,
            &[good(entity, true), unreadable(entity)],
        );
        let token = persona_token(&authority, timeline, entity);
        let diagnostics = EvalDiagnosticsV1::default();
        let mut registry = open_registry(&authority, mapping(64, &[1]), &diagnostics);
        let complete = events(backend.as_ref(), timeline);
        let head = backend.logical_head(timeline).test_ok();
        let error = expect_err(registry.step_all_anchored_protected(
            timeline,
            &ancestry(backend.as_ref(), timeline),
            head,
            token,
            0,
            &complete[1..],
        ));
        registry.abort_step();
        capture.record(
            store,
            "discarded",
            matches!(error, RuntimeError::InvalidRecoveryEvidence { .. }),
        );
        capture.record(store, "committed", events(backend.as_ref(), timeline).len());
        capture.record(store, "findings", diagnostics.findings().len());
        capture.record(store, "decoded", diagnostics.decoded_sources().len());
    }
    capture
}

/// PCF-EVAL-R2-007: a source behind the host's ADR-060 erasure fence never
/// reaches Eval.
///
/// The fence refuses the pass with no finding and nothing decoded, so an
/// erased source never yields `UndecodableSource`.
#[must_use]
pub fn erased_sources_never_reach_eval() -> Capture {
    let mut capture = Capture::default();
    for (store, mut backend) in stores() {
        let entity = EntityId::new();
        let authority = ConsentAuthority::new();
        let drafts = [good(entity, true), unreadable(entity)];
        let frozen = backend.create_timeline("frozen").test_ok().id();
        let open = backend.create_timeline("open").test_ok().id();
        append(backend.as_mut(), frozen, &drafts);
        let open_sources = append(backend.as_mut(), open, &drafts);
        let gate = Arc::new(ErasureContainmentGateV1::new_test_open());
        let diagnostics = EvalDiagnosticsV1::default();
        let mut registry = registry(
            &authority,
            Arc::clone(&gate),
            mapping(64, &[1]),
            &diagnostics,
        );
        gate.freeze_timeline_for_test(frozen);
        let frozen_token = persona_token(&authority, frozen, entity);
        let refused = expect_err(stage(
            &mut registry,
            backend.as_ref(),
            frozen,
            Some(&frozen_token),
        ));
        capture.record(
            store,
            "frozen.refused",
            matches!(refused, RuntimeError::ErasureContainment(_)),
        );
        capture.record(store, "frozen.findings", diagnostics.findings().len());
        capture.record(store, "frozen.decoded", diagnostics.decoded_sources().len());
        let open_token = persona_token(&authority, open, entity);
        let open_pass = protected_pass(&mut registry, backend.as_mut(), open, &open_token);
        capture.record(store, "open.pass", open_pass);
        capture.record(
            store,
            "open.findings",
            findings(&diagnostics, &open_sources),
        );
    }
    capture
}
