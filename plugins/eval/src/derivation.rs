//! Eval's derivation Driver (ADR-024 Revision 1 Decision 5, Revision 2).
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
//!
//! Each source has exactly one outcome per pass (Revision 2 Decision 0):
//!
//! 1. An `eval.outcome` names it and no `eval.prediction` does: the finding
//!    is `OrphanOutcome`, and the source is never decoded.
//! 2. Both a prediction and an outcome name it: the pair is complete, and
//!    the source is never decoded.
//! 3. Only a prediction names it: the source is decoded (checks 1–3) to
//!    learn whether it expects an outcome. A source that carries one is
//!    `MissingOutcome`; one that carries none is complete; one that cannot
//!    be decoded records the failing check's kind.
//! 4. Nothing names it: the source is eligible. It passes checks 1–4 and is
//!    derived as one whole unit, or it is quarantined with the first failing
//!    check's kind. A quarantined source emits nothing, consumes no budget
//!    and stays eligible, so its finding recurs in every later pass.
//!
//! Erased sources (ADR-024 Revision 2 Decision 3b) never reach this
//! function. The host's ADR-060 containment fence authorizes Plugin input
//! per Timeline and refuses the whole pass for a Timeline inside a frozen
//! erasure scope, and committed payloads are never rewritten. Under the
//! option-A interpretation of Decision 3b ([#493]), that fence is the
//! host-owned evidence that rules out erasure: every source in an authorized
//! verified prefix is outside every erasure scope, so the "erased" step of
//! the precedence order never applies, and an undecodable source is never
//! an erased one.
//!
//! [#493]: https://redmine.piglor.com/issues/493

use std::collections::{BTreeSet, HashSet};
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
use serde::Deserialize;

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
/// The supported source mappings and the per-pass draft budget are part of
/// the configuration identity through [`Self::configuration_details`].
///
/// The set of supported source versions may be empty. An empty set derives
/// nothing: every eligible source is quarantined as
/// [`EvalIntegrityFindingKindV1::UnsupportedSourceVersion`], and nothing
/// already derived is derived again.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EvalDerivationConfigV1 {
    max_drafts_per_pass: u32,
    source_versions: BTreeSet<u32>,
}

impl EvalDerivationConfigV1 {
    /// Configure the derivation with a per-pass draft budget and the one
    /// supported source mapping, Persona `persona.prediction` version
    /// [`PREDICTION_SOURCE_VERSION_V1`].
    ///
    /// The budget counts each unit (a prediction and its outcome) as a whole,
    /// so it must hold at least one complete unit. Keep it within the output
    /// budget admitted for Eval's registration.
    ///
    /// # Errors
    /// Returns [`EvalError::InvalidConfiguration`] when the budget is below
    /// [`MIN_DRAFTS_PER_PASS`].
    pub fn new(max_drafts_per_pass: u32) -> Result<Self, EvalError> {
        if max_drafts_per_pass < MIN_DRAFTS_PER_PASS {
            return Err(EvalError::InvalidConfiguration);
        }
        Ok(Self {
            max_drafts_per_pass,
            source_versions: BTreeSet::from([PREDICTION_SOURCE_VERSION_V1]),
        })
    }

    /// Replace the pinned source mappings with exactly `versions`.
    ///
    /// Each listed source version is read with the version 1 field layout of
    /// [`PredictionSourceV1`]. A version that is not listed has no mapping:
    /// an eligible source of that version is quarantined as
    /// [`EvalIntegrityFindingKindV1::UnsupportedSourceVersion`] until a later
    /// pinned configuration lists it. Dropping a version never re-derives a
    /// source that was already derived.
    #[must_use]
    pub fn with_source_versions(mut self, versions: impl IntoIterator<Item = u32>) -> Self {
        self.source_versions = versions.into_iter().collect();
        self
    }

    /// The per-pass draft budget.
    #[must_use]
    pub const fn max_drafts_per_pass(&self) -> u32 {
        self.max_drafts_per_pass
    }

    /// Canonical configuration details for Eval's pinned configuration
    /// identity: the source mappings and the per-pass budget.
    #[must_use]
    pub fn configuration_details(&self) -> Vec<u8> {
        let versions: Vec<String> = self
            .source_versions
            .iter()
            .map(ToString::to_string)
            .collect();
        format!(
            "eval-derivation-v2;source={EVENT_TYPE_PREDICTION_SOURCE};versions={};max-drafts={}",
            versions.join(","),
            self.max_drafts_per_pass
        )
        .into_bytes()
    }
}

/// The closed kinds of finding Eval's derivation records
/// (ADR-024 Revision 1 Decision 5 and Revision 2 Decision 1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum EvalIntegrityFindingKindV1 {
    /// An `eval.outcome` names a source with no matching `eval.prediction`.
    OrphanOutcome,
    /// An `eval.prediction` names a source that carries an outcome, but no
    /// matching `eval.outcome` exists.
    MissingOutcome,
    /// The source's version has no mapping pinned in Eval's configuration.
    UnsupportedSourceVersion,
    /// The source's envelope or version cannot be read, or the payload does
    /// not decode completely under its pinned mapping.
    UndecodableSource,
    /// The source's `predicted_prob` is not finite or lies outside `[0, 1]`.
    InvalidPrediction,
}

/// One finding for one source. It is non-authoritative diagnostics output and
/// never a Timeline Event.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct EvalIntegrityFindingV1 {
    /// The source Event the finding names.
    pub source: EventId,
    /// What is wrong with it.
    pub kind: EvalIntegrityFindingKindV1,
}

/// The result of one derivation over a committed prefix.
#[derive(Clone, Debug, Default)]
pub struct EvalDerivationV1 {
    /// Whole units in Timeline Order: a prediction, then its outcome when the
    /// source carries one.
    pub drafts: Vec<EventDraft>,
    /// At most one finding per source, in Timeline Order of the sources.
    pub findings: Vec<EvalIntegrityFindingV1>,
    /// Every source whose payload this derivation read, in Timeline Order.
    /// A source with a complete pair or an orphan outcome is never listed.
    pub decoded_sources: Vec<EventId>,
}

/// What the prefix already holds for one source.
#[derive(Clone, Copy)]
enum SourceStateV1 {
    Eligible,
    OrphanOutcome,
    AwaitingOutcome,
    Complete,
}

const fn source_state(has_prediction: bool, has_outcome: bool) -> SourceStateV1 {
    match (has_prediction, has_outcome) {
        (false, false) => SourceStateV1::Eligible,
        (false, true) => SourceStateV1::OrphanOutcome,
        (true, false) => SourceStateV1::AwaitingOutcome,
        (true, true) => SourceStateV1::Complete,
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

/// The version-bearing envelope every Persona prediction source shares.
#[derive(Deserialize)]
struct SourceEnvelopeV1 {
    version: u32,
}

/// Checks 1–3 of Revision 2 Decision 1: read the envelope and its version,
/// require a pinned mapping for it, then decode the payload completely.
fn decode_source(
    source: &Event,
    config: &EvalDerivationConfigV1,
) -> Result<PredictionSourceV1, EvalIntegrityFindingKindV1> {
    let bytes = source.payload.as_slice();
    ciborium::from_reader::<SourceEnvelopeV1, _>(bytes)
        .map_err(|_| EvalIntegrityFindingKindV1::UndecodableSource)
        .and_then(|envelope| {
            if config.source_versions.contains(&envelope.version) {
                Ok(())
            } else {
                Err(EvalIntegrityFindingKindV1::UnsupportedSourceVersion)
            }
        })
        .and_then(|()| {
            ciborium::from_reader::<PredictionSourceV1, _>(bytes)
                .map_err(|_| EvalIntegrityFindingKindV1::UndecodableSource)
        })
}

/// Check 4 of Revision 2 Decision 1: `predicted_prob` is finite and within
/// `[0, 1]` inclusive. The inclusive range excludes NaN and both infinities.
fn valid_prediction(
    payload: PredictionSourceV1,
) -> Result<PredictionSourceV1, EvalIntegrityFindingKindV1> {
    if (0.0..=1.0).contains(&payload.predicted_prob) {
        Ok(payload)
    } else {
        Err(EvalIntegrityFindingKindV1::InvalidPrediction)
    }
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
    /// Drafts still available in this pass.
    remaining: usize,
    /// Set when a unit did not fit; no later unit is admitted.
    closed: bool,
}

impl UnitBudgetV1 {
    const fn admit(&mut self, unit_len: usize) -> bool {
        if self.closed || unit_len > self.remaining {
            self.closed = true;
            return false;
        }
        self.remaining -= unit_len;
        true
    }
}

impl EvalDerivationV1 {
    fn record(&mut self, source: &Event, kind: EvalIntegrityFindingKindV1) {
        self.findings.push(EvalIntegrityFindingV1 {
            source: source.id,
            kind,
        });
    }

    /// Derive an eligible source as one whole unit within budget, or
    /// quarantine it with the first failing check's kind.
    fn derive_eligible(
        &mut self,
        source: &Event,
        config: &EvalDerivationConfigV1,
        budget: &mut UnitBudgetV1,
    ) {
        self.decoded_sources.push(source.id);
        match decode_source(source, config).and_then(valid_prediction) {
            Ok(payload) => {
                let unit = derived_unit(source, &payload);
                let fits = budget.admit(unit.len());
                self.drafts.extend(unit.into_iter().filter(|_| fits));
            }
            Err(kind) => self.record(source, kind),
        }
    }

    /// A derived source whose prediction has no outcome: decode it to learn
    /// whether it expects one.
    fn check_awaiting_outcome(&mut self, source: &Event, config: &EvalDerivationConfigV1) {
        self.decoded_sources.push(source.id);
        match decode_source(source, config) {
            Ok(payload) if payload.outcome != PredictionOutcomeV1::Absent => {
                self.record(source, EvalIntegrityFindingKindV1::MissingOutcome);
            }
            Ok(_) => {}
            Err(kind) => self.record(source, kind),
        }
    }
}

/// Derive whole `eval.*` units from a verified committed prefix.
///
/// The output depends only on `prefix` and `config`. Each eligible source in
/// Timeline Order that passes every check yields one `eval.prediction` and,
/// when the source carries an outcome, one `eval.outcome`, both caused by the
/// source and carrying its entity. Partial pairs and bad eligible sources are
/// quarantined as findings and never repaired; a bad source never fails the
/// derivation, so it never blocks the pass.
///
/// Each call scans the whole prefix, so one pass costs O(history): time and
/// memory grow with the number of committed sources and `eval.*` records,
/// not with the number still eligible. The budget caps the drafts of one
/// pass, not that scan. Payloads are decoded only for eligible sources and
/// for derived sources whose prediction has no outcome.
#[must_use]
pub fn derive_eval_units(prefix: &[Event], config: &EvalDerivationConfigV1) -> EvalDerivationV1 {
    let predicted = caused_sources(prefix, EVENT_TYPE_PREDICTION);
    let resolved = caused_sources(prefix, EVENT_TYPE_OUTCOME);
    let mut derivation = EvalDerivationV1::default();
    let mut budget = UnitBudgetV1 {
        remaining: usize::try_from(config.max_drafts_per_pass).unwrap_or(usize::MAX),
        closed: false,
    };
    for source in prefix
        .iter()
        .filter(|event| event.event_type.as_str() == EVENT_TYPE_PREDICTION_SOURCE)
    {
        match source_state(
            predicted.contains(&source.id),
            resolved.contains(&source.id),
        ) {
            SourceStateV1::Eligible => derivation.derive_eligible(source, config, &mut budget),
            SourceStateV1::OrphanOutcome => {
                derivation.record(source, EvalIntegrityFindingKindV1::OrphanOutcome);
            }
            SourceStateV1::AwaitingOutcome => derivation.check_awaiting_outcome(source, config),
            SourceStateV1::Complete => {}
        }
    }
    derivation
}

/// What one committed pass of Eval's Driver observed.
#[derive(Clone, Debug, Default)]
struct EvalPassDiagnosticsV1 {
    findings: Vec<EvalIntegrityFindingV1>,
    decoded_sources: Vec<EventId>,
}

/// Non-durable, non-Timeline diagnostics channel for Eval's Driver.
///
/// The host keeps a clone before boxing the Driver. Each committed pass
/// replaces the contents with that pass's findings and decoded sources; a
/// discarded pass publishes nothing. Nothing here is persisted or appended.
#[derive(Clone, Debug, Default)]
pub struct EvalDiagnosticsV1 {
    pass: Arc<Mutex<EvalPassDiagnosticsV1>>,
}

impl EvalDiagnosticsV1 {
    /// The findings of the most recent committed pass, at most one per source.
    #[must_use]
    pub fn findings(&self) -> Vec<EvalIntegrityFindingV1> {
        self.read().findings
    }

    /// The sources whose payload the most recent committed pass read, in
    /// Timeline Order. A source with a complete pair is never among them.
    #[must_use]
    pub fn decoded_sources(&self) -> Vec<EventId> {
        self.read().decoded_sources
    }

    fn read(&self) -> EvalPassDiagnosticsV1 {
        self.pass
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    fn publish(&self, pass: EvalPassDiagnosticsV1) {
        *self.pass.lock().unwrap_or_else(PoisonError::into_inner) = pass;
    }
}

/// Eval's non-participant, scheduled, observation-derived Driver.
///
/// It subscribes to Persona's prediction source and to Eval's own types,
/// requires the host-verified committed prefix of exactly those types, and
/// keeps no state that can change its output. Its only failure is a missing
/// verified prefix; a bad source is quarantined, never a pass failure.
///
/// Its output policy declares the `Authoritative` authority class at
/// fidelity `L0`. ADR-049 places committed reducer inputs that Replay needs
/// in `Authoritative` and treats `ReproducibleDerived` output as re-derived
/// on Replay; ADR-024 Revision 1 says Replay folds the committed `eval.*`
/// Events and never re-derives them. `Authoritative/L0` is the class that
/// satisfies both.
pub struct EvalDerivationDriver {
    config: EvalDerivationConfigV1,
    subscriptions: [Kind; 3],
    diagnostics: EvalDiagnosticsV1,
    /// The diagnostics of the pass staged by the latest successful `step`.
    ///
    /// Invariant: the host calls `commit_step` only after it commits the
    /// pass that same `step` staged, so `commit_step` publishes exactly that
    /// pass's diagnostics. A discarded pass is never published: its
    /// diagnostics are replaced by the next `step` before any later commit.
    staged: Option<EvalPassDiagnosticsV1>,
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
            staged: None,
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
            .map(|prefix| {
                let derivation = derive_eval_units(prefix, &self.config);
                self.staged = Some(EvalPassDiagnosticsV1 {
                    findings: derivation.findings,
                    decoded_sources: derivation.decoded_sources,
                });
                StepOutput::new(derivation.drafts)
            })
    }

    /// Publish the diagnostics of the pass the host just committed. The host
    /// commits only a pass this Driver staged successfully.
    fn commit_step(&mut self) {
        self.diagnostics
            .publish(self.staged.take().unwrap_or_default());
    }
}
