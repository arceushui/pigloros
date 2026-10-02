//! ADR-021 section 5 evaluation of committed pipeline evidence (#320).
//!
//! An [`ExperimentSession`](crate::ExperimentSession) records one
//! [`PipelineCommitEvidenceV1`] for the most recent committed human or AI
//! attempt and binds it to the Projection cut that folded it. Evaluation then
//! runs only through a [`PipelineEvaluatorV1`] Adapter the host registered
//! explicitly. There is no default evaluator: an unregistered name yields
//! [`PipelineEvaluationUnavailableV1::MissingEvaluator`].
//!
//! Evaluation is advisory and non-authoritative. An evaluator receives only
//! immutable copies of the committed range and, for state-dependent
//! evaluation, the public source prefix folded through the named cut. It
//! holds no store, registry, approver, admission, or policy capability, and
//! its closed [`PipelineEvaluatorOutputV1`] cannot express an action, an
//! Event draft, a Preference change, or a knowledge grant. Evaluation never
//! resubmits a committed attempt.

use std::collections::BTreeMap;

use pos_core::{
    ArtifactRedactionStateV1, ErasureReferenceV1, ErasureReplayClaimV1, Event, Hash,
    PipelineCommitEvidenceV1, PipelineCommittedRangeV1, PipelineProjectionCutV1,
    ReplayClaimEvaluationV1, Seq,
};
use pos_plugin_eval::CalibrationReport;

/// Which committed evidence an evaluator depends on.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PipelineEvaluationScopeV1 {
    /// Only the committed Events; may run as soon as the range commits.
    EventOnly,
    /// Projection state; waits for a cut that folded the complete range.
    StateDependent,
}

/// Separately classified evaluation artifacts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PipelineEvaluationClassV1 {
    /// Event-only integrity of the committed range.
    EventIntegrity,
    /// A Plugin-defined state-dependent evaluation.
    StateEvaluation,
    /// A Calibration Report over the folded source prefix.
    CalibrationReport,
}

impl PipelineEvaluationClassV1 {
    /// The evaluation scope that may produce this class.
    #[must_use]
    pub const fn scope(self) -> PipelineEvaluationScopeV1 {
        match self {
            Self::EventIntegrity => PipelineEvaluationScopeV1::EventOnly,
            Self::StateEvaluation | Self::CalibrationReport => {
                PipelineEvaluationScopeV1::StateDependent
            }
        }
    }
}

/// Event-only integrity of one committed range against its receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PipelineEventIntegrityV1 {
    /// Number of committed Events checked.
    pub checked_events: u64,
    /// Whether every Event identity and Timeline sequence matched the receipt.
    pub intact: bool,
}

/// Closed output of one evaluator invocation.
#[derive(Clone, Debug)]
pub enum PipelineEvaluatorOutputV1 {
    /// Event-only integrity result.
    EventIntegrity(PipelineEventIntegrityV1),
    /// Digest of a Plugin-defined state-dependent evaluation.
    StateEvaluation(Hash),
    /// A Calibration Report artifact.
    CalibrationReport(Box<CalibrationReport>),
    /// The permitted evidence is not enough to produce a value.
    InsufficientEvidence,
    /// The evaluator's own artifact is unavailable for authoritative use.
    EvidenceUnavailable,
}

impl PipelineEvaluatorOutputV1 {
    const fn class(&self) -> Option<PipelineEvaluationClassV1> {
        match self {
            Self::EventIntegrity(_) => Some(PipelineEvaluationClassV1::EventIntegrity),
            Self::StateEvaluation(_) => Some(PipelineEvaluationClassV1::StateEvaluation),
            Self::CalibrationReport(_) => Some(PipelineEvaluationClassV1::CalibrationReport),
            Self::InsufficientEvidence | Self::EvidenceUnavailable => None,
        }
    }
}

/// Immutable, minimized input supplied by the host to one evaluator.
pub struct PipelineEvaluationInputV1<'a> {
    evidence: &'a PipelineCommitEvidenceV1,
    claim: &'a ReplayClaimEvaluationV1,
    committed_events: &'a [Event],
    folded_prefix: &'a [Event],
}

impl<'a> PipelineEvaluationInputV1<'a> {
    /// Assemble one evaluator input.
    ///
    /// The host builds the input it passes to a registered evaluator from the
    /// committed range and the folded prefix it read itself. Building an
    /// input grants nothing: evaluation output is advisory.
    #[must_use]
    pub const fn new(
        evidence: &'a PipelineCommitEvidenceV1,
        claim: &'a ReplayClaimEvaluationV1,
        committed_events: &'a [Event],
        folded_prefix: &'a [Event],
    ) -> Self {
        Self {
            evidence,
            claim,
            committed_events,
            folded_prefix,
        }
    }

    /// The evaluated commit evidence.
    #[must_use]
    pub const fn evidence(&self) -> &PipelineCommitEvidenceV1 {
        self.evidence
    }

    /// The host-owned ADR-060 claim evaluation in force for this evidence.
    #[must_use]
    pub const fn claim(&self) -> &ReplayClaimEvaluationV1 {
        self.claim
    }

    /// The Events of the committed range, in Timeline Order.
    #[must_use]
    pub const fn committed_events(&self) -> &[Event] {
        self.committed_events
    }

    /// Public source Events folded through the named Projection cut; empty
    /// for an event-only evaluator.
    #[must_use]
    pub const fn folded_prefix(&self) -> &[Event] {
        self.folded_prefix
    }
}

/// Explicitly registered evaluation Plugin/public Adapter.
pub trait PipelineEvaluatorV1: Send + Sync {
    /// Registry name, unique within one session.
    fn name(&self) -> &'static str;

    /// Evidence this evaluator depends on.
    fn scope(&self) -> PipelineEvaluationScopeV1;

    /// Evaluate immutable host-supplied evidence.
    fn evaluate(&self, input: &PipelineEvaluationInputV1<'_>) -> PipelineEvaluatorOutputV1;
}

/// Why no evaluation artifact was produced.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PipelineEvaluationUnavailableV1 {
    /// No evaluator with the requested name is registered.
    MissingEvaluator,
    /// State-dependent evaluation awaits a fold of the complete range.
    ProjectionNotFolded,
    /// The replay claim or redaction state does not permit this scope, or
    /// the evaluator's artifact is unavailable for authoritative use.
    EvidenceUnavailable,
    /// The evaluator returned an artifact outside its declared scope.
    InvalidEvaluatorOutput,
}

/// Typed outcome of one evaluation request.
#[derive(Clone, Debug)]
pub enum PipelineEvaluationOutcomeV1 {
    /// Event-only integrity artifact.
    EventIntegrity(PipelineEventIntegrityV1),
    /// State-dependent evaluation artifact digest.
    StateEvaluation(Hash),
    /// Calibration Report artifact over exact, unredacted evidence.
    CalibrationReport(Box<CalibrationReport>),
    /// The permitted evidence is not enough to produce a value.
    InsufficientEvidence,
    /// No artifact was produced.
    Unavailable(PipelineEvaluationUnavailableV1),
}

/// Advisory evaluation record bound to its committed range and cut.
#[derive(Clone, Debug)]
pub struct PipelineEvaluationRecordV1 {
    evaluator: &'static str,
    committed_range: PipelineCommittedRangeV1,
    projection_cut: Option<PipelineProjectionCutV1>,
    replay_claim: ErasureReplayClaimV1,
    redaction_state: ArtifactRedactionStateV1,
    outcome: PipelineEvaluationOutcomeV1,
}

impl PipelineEvaluationRecordV1 {
    /// The requested evaluator name.
    #[must_use]
    pub const fn evaluator(&self) -> &'static str {
        self.evaluator
    }

    /// The committed Event range the evaluation is bound to.
    #[must_use]
    pub const fn committed_range(&self) -> PipelineCommittedRangeV1 {
        self.committed_range
    }

    /// The Projection cut a state-dependent evaluation used; `None` for an
    /// event-only evaluation or one that did not run.
    #[must_use]
    pub const fn projection_cut(&self) -> Option<PipelineProjectionCutV1> {
        self.projection_cut
    }

    /// Replay claim supported by the host evidence; never strengthened.
    #[must_use]
    pub const fn replay_claim(&self) -> ErasureReplayClaimV1 {
        self.replay_claim
    }

    /// Redaction state of the host evidence; never strengthened.
    #[must_use]
    pub const fn redaction_state(&self) -> ArtifactRedactionStateV1 {
        self.redaction_state
    }

    /// The typed evaluation outcome.
    #[must_use]
    pub const fn outcome(&self) -> &PipelineEvaluationOutcomeV1 {
        &self.outcome
    }
}

/// First-party event-only Adapter checking a committed range against its
/// receipt.
#[derive(Clone, Copy, Debug, Default)]
pub struct CommittedRangeIntegrityEvaluatorV1;

impl PipelineEvaluatorV1 for CommittedRangeIntegrityEvaluatorV1 {
    fn name(&self) -> &'static str {
        "committed-range-integrity"
    }

    fn scope(&self) -> PipelineEvaluationScopeV1 {
        PipelineEvaluationScopeV1::EventOnly
    }

    fn evaluate(&self, input: &PipelineEvaluationInputV1<'_>) -> PipelineEvaluatorOutputV1 {
        let expected = input.evidence().receipt().committed_events();
        let events = input.committed_events();
        PipelineEvaluatorOutputV1::EventIntegrity(PipelineEventIntegrityV1 {
            checked_events: u64::try_from(events.len()).unwrap_or(u64::MAX),
            intact: events.len() == expected.len()
                && events.iter().zip(expected).all(|(event, committed)| {
                    event.id == committed.event_id() && event.seq == committed.seq()
                }),
        })
    }
}

/// First-party state-dependent Adapter producing a Calibration Report over
/// the source prefix folded through the named cut.
#[derive(Clone, Copy, Debug)]
pub struct CalibrationReportEvaluatorV1 {
    artifact_digest: ErasureReferenceV1,
}

impl CalibrationReportEvaluatorV1 {
    /// Bind the registered ADR-060 Calibration Report artifact identity.
    #[must_use]
    pub const fn new(artifact_digest: ErasureReferenceV1) -> Self {
        Self { artifact_digest }
    }
}

impl PipelineEvaluatorV1 for CalibrationReportEvaluatorV1 {
    fn name(&self) -> &'static str {
        "calibration-report"
    }

    fn scope(&self) -> PipelineEvaluationScopeV1 {
        PipelineEvaluationScopeV1::StateDependent
    }

    fn evaluate(&self, input: &PipelineEvaluationInputV1<'_>) -> PipelineEvaluatorOutputV1 {
        match pos_plugin_eval::compute_report_from_events(
            input.folded_prefix(),
            self.artifact_digest,
            input.claim(),
        ) {
            Ok(report) if report.n_resolved > 0 => {
                PipelineEvaluatorOutputV1::CalibrationReport(Box::new(report))
            }
            Err(pos_plugin_eval::EvalError::ArtifactUnavailable) => {
                PipelineEvaluatorOutputV1::EvidenceUnavailable
            }
            Ok(_) | Err(_) => PipelineEvaluatorOutputV1::InsufficientEvidence,
        }
    }
}

/// Evaluators a host registered explicitly for one session.
#[derive(Default)]
pub(crate) struct PipelineEvaluatorRegistryV1 {
    evaluators: BTreeMap<&'static str, Box<dyn PipelineEvaluatorV1>>,
}

/// One admitted evaluation request, ready for the host to read its inputs.
pub(crate) struct PreparedPipelineEvaluationV1<'a> {
    evaluator: &'a dyn PipelineEvaluatorV1,
    evidence: &'a PipelineCommitEvidenceV1,
    claim: &'a ReplayClaimEvaluationV1,
}

impl PipelineEvaluatorRegistryV1 {
    /// Register one evaluator; a duplicate name is refused.
    pub(crate) fn register(&mut self, evaluator: Box<dyn PipelineEvaluatorV1>) -> bool {
        match self.evaluators.entry(evaluator.name()) {
            std::collections::btree_map::Entry::Occupied(_) => false,
            std::collections::btree_map::Entry::Vacant(slot) => {
                slot.insert(evaluator);
                true
            }
        }
    }

    /// Resolve the evaluator and check that the evidence permits its scope.
    ///
    /// A refusal is returned as the boxed unavailable record.
    pub(crate) fn prepare<'a>(
        &'a self,
        name: &'static str,
        evidence: &'a PipelineCommitEvidenceV1,
        claim: &'a ReplayClaimEvaluationV1,
    ) -> Result<PreparedPipelineEvaluationV1<'a>, Box<PipelineEvaluationRecordV1>> {
        let refuse = |reason| {
            Err(Box::new(record(
                name,
                evidence,
                None,
                claim,
                unavailable(reason),
            )))
        };
        let Some(evaluator) = self.evaluators.get(name) else {
            return refuse(PipelineEvaluationUnavailableV1::MissingEvaluator);
        };
        let prepared = PreparedPipelineEvaluationV1 {
            evaluator: evaluator.as_ref(),
            evidence,
            claim,
        };
        if !claim_permits(evaluator.scope(), claim) {
            return refuse(PipelineEvaluationUnavailableV1::EvidenceUnavailable);
        }
        if prepared.awaits_fold() {
            return refuse(PipelineEvaluationUnavailableV1::ProjectionNotFolded);
        }
        Ok(prepared)
    }
}

impl PreparedPipelineEvaluationV1<'_> {
    fn state_dependent(&self) -> bool {
        self.evaluator.scope() == PipelineEvaluationScopeV1::StateDependent
    }

    /// The cut a state-dependent evaluation reads; `None` for event-only.
    fn cut(&self) -> Option<PipelineProjectionCutV1> {
        self.evidence
            .projection_cut()
            .filter(|_| self.state_dependent())
    }

    fn awaits_fold(&self) -> bool {
        self.state_dependent() && self.cut().is_none()
    }

    /// The last Event of the folded prefix this evaluation reads, if any.
    pub(crate) fn folded_through(&self) -> Option<Seq> {
        self.cut().map(PipelineProjectionCutV1::folded_through)
    }

    /// Run the evaluator over host-read inputs and classify its output.
    pub(crate) fn run(
        self,
        committed_events: &[Event],
        folded_prefix: &[Event],
    ) -> PipelineEvaluationRecordV1 {
        let scope = self.evaluator.scope();
        let cut = self.cut();
        let output = self.evaluator.evaluate(&PipelineEvaluationInputV1::new(
            self.evidence,
            self.claim,
            committed_events,
            folded_prefix,
        ));
        let outcome = if output.class().is_some_and(|class| class.scope() != scope) {
            unavailable(PipelineEvaluationUnavailableV1::InvalidEvaluatorOutput)
        } else {
            match output {
                PipelineEvaluatorOutputV1::EventIntegrity(integrity) => {
                    PipelineEvaluationOutcomeV1::EventIntegrity(integrity)
                }
                PipelineEvaluatorOutputV1::StateEvaluation(digest) => {
                    PipelineEvaluationOutcomeV1::StateEvaluation(digest)
                }
                PipelineEvaluatorOutputV1::CalibrationReport(report) => {
                    PipelineEvaluationOutcomeV1::CalibrationReport(report)
                }
                PipelineEvaluatorOutputV1::InsufficientEvidence => {
                    PipelineEvaluationOutcomeV1::InsufficientEvidence
                }
                PipelineEvaluatorOutputV1::EvidenceUnavailable => {
                    unavailable(PipelineEvaluationUnavailableV1::EvidenceUnavailable)
                }
            }
        };
        record(
            self.evaluator.name(),
            self.evidence,
            cut,
            self.claim,
            outcome,
        )
    }
}

const fn unavailable(reason: PipelineEvaluationUnavailableV1) -> PipelineEvaluationOutcomeV1 {
    PipelineEvaluationOutcomeV1::Unavailable(reason)
}

/// Event-only evaluation needs authoritative Events; state-dependent
/// evaluation needs exact, unredacted views.
fn claim_permits(scope: PipelineEvaluationScopeV1, claim: &ReplayClaimEvaluationV1) -> bool {
    let replay = claim.replay_claim();
    match scope {
        PipelineEvaluationScopeV1::EventOnly => {
            replay == ErasureReplayClaimV1::Exact
                || replay == ErasureReplayClaimV1::ExactAuthoritativeWithRedactedViews
        }
        PipelineEvaluationScopeV1::StateDependent => replay == ErasureReplayClaimV1::Exact,
    }
}

const fn record(
    evaluator: &'static str,
    evidence: &PipelineCommitEvidenceV1,
    projection_cut: Option<PipelineProjectionCutV1>,
    claim: &ReplayClaimEvaluationV1,
    outcome: PipelineEvaluationOutcomeV1,
) -> PipelineEvaluationRecordV1 {
    PipelineEvaluationRecordV1 {
        evaluator,
        committed_range: evidence.committed_range(),
        projection_cut,
        replay_claim: claim.replay_claim(),
        redaction_state: claim.redaction_state(),
        outcome,
    }
}
