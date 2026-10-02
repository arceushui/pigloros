//! Eval's derivation Driver (ADR-024 Revision 1 Decision 5).
//!
//! Persona owns its prediction source Events; Eval owns `eval.prediction`
//! and `eval.outcome`. Eval's non-participant, scheduled Driver observes the
//! committed, consent-gated source Events through its Event subscriptions
//! and appends the matching `eval.*` records in a later pass through the
//! host's atomic `ScheduledAiDriver` admission.
//!
//! The derivation is a pure function of the verified committed prefix and the
//! pinned [`EvalDerivationConfigV1`]: a source is eligible exactly when the
//! prefix holds no `eval.prediction` whose `causation_id` names it. Replay
//! never runs the derivation; it folds the committed `eval.*` Events.

use std::collections::HashSet;
use std::sync::{Arc, Mutex, PoisonError};

use pos_core::{
    event::{CanonicalBytes, Event, EventDraft, Kind},
    ids::{EventId, TimelineId},
};
use pos_plugin_persona::{
    PredictionOutcomeV1, PredictionSourceV1, EVENT_TYPE_PREDICTION_SOURCE,
    PREDICTION_SOURCE_VERSION_V1,
};
use pos_runtime::{Driver, ObservationView, RuntimeError, StepOutput};

use crate::{
    EvalError, OutcomeEvidenceV1, OutcomePayload, PredictionPayload, EVENT_TYPE_OUTCOME,
    EVENT_TYPE_PREDICTION,
};

/// Domain prefix of every derived `prediction_id`. Legacy ids have the form
/// `pred-<n>`, so the two sets are disjoint.
pub const DERIVED_PREDICTION_ID_PREFIX: &str = "eval:src:";

/// The smallest per-pass draft budget: one whole unit of a prediction and
/// its outcome.
pub const MIN_DRAFTS_PER_PASS: u32 = 2;

/// Pinned configuration of Eval's derivation Driver.
///
/// The supported source mapping (Persona `persona.prediction` version 1 to
/// `eval.*`) and the per-pass draft budget are part of the configuration
/// identity through [`Self::configuration_details`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EvalDerivationConfigV1 {
    max_drafts_per_pass: u32,
}

impl EvalDerivationConfigV1 {
    /// Configure the derivation with a per-pass draft budget.
    ///
    /// The budget counts each unit (a prediction and its outcome) as a whole,
    /// so it must hold at least one complete unit. Keep it within the output
    /// budget admitted for Eval's registration.
    ///
    /// # Errors
    /// Returns [`EvalError::InvalidConfiguration`] when the budget is below
    /// [`MIN_DRAFTS_PER_PASS`].
    pub const fn new(max_drafts_per_pass: u32) -> Result<Self, EvalError> {
        if max_drafts_per_pass < MIN_DRAFTS_PER_PASS {
            return Err(EvalError::InvalidConfiguration);
        }
        Ok(Self {
            max_drafts_per_pass,
        })
    }

    /// The per-pass draft budget.
    #[must_use]
    pub const fn max_drafts_per_pass(&self) -> u32 {
        self.max_drafts_per_pass
    }

    /// Canonical configuration details for Eval's pinned configuration
    /// identity: the source mapping and the per-pass budget.
    #[must_use]
    pub fn configuration_details(&self) -> Vec<u8> {
        format!(
            "eval-derivation-v1;source={EVENT_TYPE_PREDICTION_SOURCE};version={PREDICTION_SOURCE_VERSION_V1};max-drafts={}",
            self.max_drafts_per_pass
        )
        .into_bytes()
    }
}

/// The closed kinds of partial pair Eval's derivation quarantines.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum EvalIntegrityFindingKindV1 {
    /// An `eval.outcome` names a source with no matching `eval.prediction`.
    OrphanOutcome,
    /// An `eval.prediction` names a source that carries an outcome, but no
    /// matching `eval.outcome` exists.
    MissingOutcome,
}

/// A quarantined partial pair. It is non-authoritative diagnostics output and
/// never a Timeline Event.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct EvalIntegrityFindingV1 {
    /// The source Event the partial pair names.
    pub source: EventId,
    /// What is incomplete.
    pub kind: EvalIntegrityFindingKindV1,
}

/// The result of one derivation over a committed prefix.
#[derive(Clone, Debug, Default)]
pub struct EvalDerivationV1 {
    /// Whole units in Timeline Order: a prediction, then its outcome when the
    /// source carries one.
    pub drafts: Vec<EventDraft>,
    /// Quarantined partial pairs in Timeline Order of their sources.
    pub findings: Vec<EvalIntegrityFindingV1>,
}

/// What the prefix already holds for one source.
#[derive(Clone, Copy)]
enum SourceStateV1 {
    Eligible,
    Derived,
    Partial(EvalIntegrityFindingKindV1),
}

const fn source_state(
    has_prediction: bool,
    has_outcome: bool,
    expects_outcome: bool,
) -> SourceStateV1 {
    match (has_prediction, has_outcome) {
        (false, false) => SourceStateV1::Eligible,
        (false, true) => SourceStateV1::Partial(EvalIntegrityFindingKindV1::OrphanOutcome),
        (true, false) if expects_outcome => {
            SourceStateV1::Partial(EvalIntegrityFindingKindV1::MissingOutcome)
        }
        (true, _) => SourceStateV1::Derived,
    }
}

/// Source Event ids named by the `causation_id` of committed Events of one
/// type. Legacy `eval.*` Events carry no causation and never name a source.
fn caused_sources(prefix: &[Event], event_type: &str) -> HashSet<EventId> {
    prefix
        .iter()
        .filter(|event| event.event_type.as_str() == event_type)
        .filter_map(|event| event.causation_id)
        .collect()
}

/// Decode one source payload, failing closed on an unknown version.
fn decode_source(source: &Event) -> Result<PredictionSourceV1, EvalError> {
    ciborium::from_reader::<PredictionSourceV1, _>(source.payload.as_slice())
        .map_err(|error| EvalError::Decode(error.to_string()))
        .and_then(|payload| {
            if payload.version == PREDICTION_SOURCE_VERSION_V1 {
                Ok(payload)
            } else {
                Err(EvalError::UnknownSourceVersion {
                    version: payload.version,
                })
            }
        })
}

fn encode<T: serde::Serialize>(payload: &T) -> CanonicalBytes {
    let mut buf = Vec::new();
    // `Vec<u8>` is an infallible CBOR sink.
    drop(ciborium::into_writer(payload, &mut buf));
    CanonicalBytes::from_vec(buf)
}

fn derived_draft(source: &Event, event_type: &str, payload: CanonicalBytes) -> EventDraft {
    let mut draft = EventDraft::new(source.entity, Kind::new(event_type), payload);
    draft.causation_id = Some(source.id);
    draft
}

/// Build one whole unit for an eligible source.
fn derived_unit(source: &Event, payload: &PredictionSourceV1) -> Vec<EventDraft> {
    let prediction_id = format!("{DERIVED_PREDICTION_ID_PREFIX}{}", source.id);
    let prediction = derived_draft(
        source,
        EVENT_TYPE_PREDICTION,
        encode(&PredictionPayload {
            entity_id: source.entity.to_string(),
            predicted_prob: payload.predicted_prob,
            prediction_id: prediction_id.clone(),
        }),
    );
    let outcome = match payload.outcome {
        PredictionOutcomeV1::Absent => None,
        PredictionOutcomeV1::Observed(outcome) => Some(derived_draft(
            source,
            EVENT_TYPE_OUTCOME,
            encode(&OutcomePayload {
                prediction_id,
                outcome,
                evidence: Some(OutcomeEvidenceV1::PredictorSupplied),
            }),
        )),
    };
    std::iter::once(prediction).chain(outcome).collect()
}

/// The per-pass draft budget. Units are admitted whole; once one unit does
/// not fit, the budget closes, so a capped pass always derives the earliest
/// eligible sources in Timeline Order.
struct UnitBudgetV1 {
    remaining: Option<usize>,
}

impl UnitBudgetV1 {
    fn admit(&mut self, unit_len: usize) -> bool {
        let fits = self
            .remaining
            .is_some_and(|remaining| unit_len <= remaining);
        self.remaining = self
            .remaining
            .filter(|_| fits)
            .map(|remaining| remaining - unit_len);
        fits
    }
}

impl EvalDerivationV1 {
    /// Account for one source: emit its whole unit when eligible and within
    /// budget, or record a quarantined partial pair.
    fn consider(
        &mut self,
        source: &Event,
        payload: &PredictionSourceV1,
        state: SourceStateV1,
        budget: &mut UnitBudgetV1,
    ) {
        match state {
            SourceStateV1::Eligible => {
                let unit = derived_unit(source, payload);
                let fits = budget.admit(unit.len());
                self.drafts.extend(unit.into_iter().filter(|_| fits));
            }
            SourceStateV1::Partial(kind) => self.findings.push(EvalIntegrityFindingV1 {
                source: source.id,
                kind,
            }),
            SourceStateV1::Derived => {}
        }
    }
}

/// Derive whole `eval.*` units from a verified committed prefix.
///
/// The output depends only on `prefix` and `config`. Each eligible source in
/// Timeline Order yields one `eval.prediction` and, when the source carries
/// an outcome, one `eval.outcome`, both caused by the source and carrying
/// its entity. Partial pairs are quarantined as findings and never repaired.
///
/// # Errors
/// Returns [`EvalError::Decode`] or [`EvalError::UnknownSourceVersion`] when
/// a source payload cannot be read, so a version change never silently skips
/// an outcome.
pub fn derive_eval_units(
    prefix: &[Event],
    config: &EvalDerivationConfigV1,
) -> Result<EvalDerivationV1, EvalError> {
    let predicted = caused_sources(prefix, EVENT_TYPE_PREDICTION);
    let resolved = caused_sources(prefix, EVENT_TYPE_OUTCOME);
    let mut derivation = EvalDerivationV1::default();
    let mut budget = UnitBudgetV1 {
        remaining: usize::try_from(config.max_drafts_per_pass).ok(),
    };
    for source in prefix
        .iter()
        .filter(|event| event.event_type.as_str() == EVENT_TYPE_PREDICTION_SOURCE)
    {
        let payload = decode_source(source)?;
        let state = source_state(
            predicted.contains(&source.id),
            resolved.contains(&source.id),
            payload.outcome != PredictionOutcomeV1::Absent,
        );
        derivation.consider(source, &payload, state, &mut budget);
    }
    Ok(derivation)
}

/// Non-durable, non-Timeline diagnostics channel for Eval's Driver.
///
/// The host keeps a clone before boxing the Driver. Each committed pass
/// replaces the findings with that pass's quarantined partial pairs; a
/// discarded pass publishes nothing. Nothing here is persisted or appended.
#[derive(Clone, Debug, Default)]
pub struct EvalDiagnosticsV1 {
    findings: Arc<Mutex<Vec<EvalIntegrityFindingV1>>>,
}

impl EvalDiagnosticsV1 {
    /// The findings of the most recent committed pass.
    #[must_use]
    pub fn findings(&self) -> Vec<EvalIntegrityFindingV1> {
        self.findings
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    fn publish(&self, findings: Vec<EvalIntegrityFindingV1>) {
        *self.findings.lock().unwrap_or_else(PoisonError::into_inner) = findings;
    }
}

/// Eval's non-participant, scheduled, observation-derived Driver.
///
/// It subscribes to Persona's prediction source and to Eval's own types,
/// requires the host-verified committed prefix of exactly those types, and
/// keeps no state that can change its output.
pub struct EvalDerivationDriver {
    config: EvalDerivationConfigV1,
    subscriptions: [Kind; 3],
    diagnostics: EvalDiagnosticsV1,
    staged_findings: Option<Vec<EvalIntegrityFindingV1>>,
}

impl EvalDerivationDriver {
    /// Create the Driver with its pinned configuration and diagnostics channel.
    #[must_use]
    pub fn new(config: EvalDerivationConfigV1, diagnostics: EvalDiagnosticsV1) -> Self {
        Self {
            config,
            subscriptions: [
                Kind::new(EVENT_TYPE_PREDICTION_SOURCE),
                Kind::new(EVENT_TYPE_PREDICTION),
                Kind::new(EVENT_TYPE_OUTCOME),
            ],
            diagnostics,
            staged_findings: None,
        }
    }
}

impl Driver for EvalDerivationDriver {
    fn name(&self) -> &'static str {
        "eval-derivation"
    }

    fn event_subscriptions(&self) -> &[Kind] {
        &self.subscriptions
    }

    fn requires_verified_event_prefix(&self) -> bool {
        true
    }

    fn step(
        &mut self,
        _timeline: TimelineId,
        observations: ObservationView<'_>,
    ) -> Result<StepOutput, RuntimeError> {
        observations
            .verified_prefix_events()
            .ok_or_else(|| RuntimeError::MissingSnapshotAnchor {
                driver: self.name().to_owned(),
            })
            .and_then(|prefix| {
                derive_eval_units(prefix, &self.config).map_err(|error| {
                    RuntimeError::InvalidPayload {
                        event_type: EVENT_TYPE_PREDICTION_SOURCE.to_owned(),
                        reason: error.to_string(),
                    }
                })
            })
            .map(|derivation| {
                self.staged_findings = Some(derivation.findings);
                StepOutput::new(derivation.drafts)
            })
    }

    /// Publish the findings of the pass the host just committed. The host
    /// commits only a pass this Driver staged successfully.
    fn commit_step(&mut self) {
        self.diagnostics
            .publish(self.staged_findings.take().unwrap_or_default());
    }
}
