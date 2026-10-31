//! Paired Local and Air-Gapped executions of one case (ADR-062 Revision 8
//! slice R5, #1224).
//!
//! The evaluator delivers one attempt per Execution Mode from the Local and
//! the Air-Gapped bundle of the same fixture. [`pair_report()`] runs both
//! through the adapter's one execution path and reports them side by side,
//! each against the same expected-result record. Air-Gapped means the
//! `deterministic-air-gapped-v1` semantics (no network, the bundled trust
//! snapshot) run by this host, not a kernel-audited execution under the
//! Sandbox Provider (Q6, as #194 D7): every result is labelled
//! [`EVIDENCE_LEVEL`].

use pos_conformance::{
    DivergenceReportV1, ExecutionModeV1, ReplayClaimV1, ReproManifestV1, VerificationErrorV1,
    VerificationOutcomeV1, VerificationResultV1,
};
use pos_reference::evaluator::{CaseAttempt, SubjectObservation};
use pos_reference::evaluator_domain::{ExecutionMode, FixtureFamily};
use pos_store::StoreConfig;

use super::execute_attempt;

/// The evidence level of every result a pair report holds.
pub const EVIDENCE_LEVEL: &str = "Local-relaxation engineering evidence, not hosted conformance";

/// Why no pair report was made.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum PairErrorV1 {
    /// The attempts are not the Local and the Air-Gapped attempt of one case:
    /// they differ in something other than their mode.
    #[error("the attempts are not the Local and Air-Gapped attempt of one case")]
    NotAPair,
    /// The attempts are not executed: their schema member or their composite
    /// is wrong.
    #[error("the attempts are not executed")]
    NotExecuted,
}

/// What one leg ran under and what it verified.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LegEvidenceV1 {
    /// The sub-case of the leg.
    pub subcase_id: String,
    /// The manifest the preflight of the leg checked; its Execution Mode is
    /// the attempt's.
    pub manifest: ReproManifestV1,
    /// The sealed `VRR1` of the leg.
    pub result: VerificationResultV1,
    /// The `DVR1` of a diverged leg.
    pub divergence: Option<DivergenceReportV1>,
}

/// The authoritative part of a leg: what a Local and an Air-Gapped leg must
/// share. The request, manifest, provenance and result digests bind the
/// Execution Mode and are not part of it.
#[derive(Eq, PartialEq)]
struct AuthoritativeResultV1<'a> {
    subcase_id: &'a str,
    execution_profile_digest: [u8; 32],
    outcome: VerificationOutcomeV1,
    replay_claim: ReplayClaimV1,
    authoritative_result_digest: Option<[u8; 32]>,
    first_error: Option<&'a VerificationErrorV1>,
    divergence: Option<DivergenceReportV1>,
}

impl LegEvidenceV1 {
    /// Whether two legs have the same authoritative result: the same
    /// sub-case, EPF1, outcome, replay claim, authoritative result digest
    /// (Events in Timeline Order, the Projection checkpoint and the typed
    /// failures), first error and first divergence. The request, manifest,
    /// provenance and result digests bind the Execution Mode and are not
    /// compared.
    #[must_use]
    pub fn same_authoritative_result(&self, other: &Self) -> bool {
        self.authoritative() == other.authoritative()
    }

    fn authoritative(&self) -> AuthoritativeResultV1<'_> {
        AuthoritativeResultV1 {
            subcase_id: &self.subcase_id,
            execution_profile_digest: self.manifest.execution_profile_digest,
            outcome: self.result.verification_outcome,
            replay_claim: self.result.replay_claim,
            authoritative_result_digest: self.result.authoritative_result_digest,
            first_error: self.result.first_error.as_ref(),
            // A `DVR1` without the digests that bind its request.
            divergence: self.divergence.as_ref().map(|report| DivergenceReportV1 {
                request_digest: [0; 32],
                manifest_digest: [0; 32],
                report_digest: [0; 32],
                ..report.clone()
            }),
        }
    }
}

/// The execution of one attempt of a pair.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModeEvidenceV1 {
    /// The Execution Mode of the attempt.
    pub mode: ExecutionModeV1,
    /// The evidence level of the results: [`EVIDENCE_LEVEL`].
    pub evidence: &'static str,
    /// The EAO1 observation the attempt returns.
    pub observation: SubjectObservation,
    /// Every leg the attempt ran, in sub-case and profile order.
    pub legs: Vec<LegEvidenceV1>,
}

/// The Local and the Air-Gapped execution of one case.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PairReportV1 {
    /// The case of both attempts.
    pub case_id: String,
    /// The fixture family of the case.
    pub family: FixtureFamily,
    /// The Local execution.
    pub local: ModeEvidenceV1,
    /// The Air-Gapped execution.
    pub air_gapped: ModeEvidenceV1,
}

impl PairReportV1 {
    /// Whether both executions observed the same result and usage and every
    /// leg has the same authoritative result in both.
    #[must_use]
    pub fn identical(&self) -> bool {
        authoritative(&self.local) == authoritative(&self.air_gapped)
    }
}

/// The observation of one execution and the authoritative part of its legs.
fn authoritative(mode: &ModeEvidenceV1) -> (&SubjectObservation, Vec<AuthoritativeResultV1<'_>>) {
    (
        &mode.observation,
        mode.legs.iter().map(LegEvidenceV1::authoritative).collect(),
    )
}

/// Run the Local and the Air-Gapped attempt of one case, recomputation hosts
/// opening `store_config`, and report both.
///
/// # Errors
/// Returns [`PairErrorV1::NotAPair`] unless `local` is a Local attempt and
/// `air_gapped` the same attempt in Air-Gapped mode, and
/// [`PairErrorV1::NotExecuted`] when the attempts are not executed.
pub fn pair_report(
    store_config: &StoreConfig,
    local: &CaseAttempt,
    air_gapped: &CaseAttempt,
) -> Result<PairReportV1, PairErrorV1> {
    let paired = air_gapped.mode == ExecutionMode::AirGapped
        && *local
            == CaseAttempt {
                mode: ExecutionMode::Local,
                ..air_gapped.clone()
            };
    if !paired {
        return Err(PairErrorV1::NotAPair);
    }
    execute_attempt(store_config, local)
        .and_then(|local_execution| {
            execute_attempt(store_config, air_gapped)
                .map(|air_gapped_execution| (local_execution, air_gapped_execution))
        })
        .map(|(local_execution, air_gapped_execution)| PairReportV1 {
            case_id: local.case_id.clone(),
            family: local.family,
            local: ModeEvidenceV1 {
                mode: ExecutionModeV1::Local,
                evidence: EVIDENCE_LEVEL,
                observation: local_execution.observation,
                legs: local_execution.legs,
            },
            air_gapped: ModeEvidenceV1 {
                mode: ExecutionModeV1::AirGapped,
                evidence: EVIDENCE_LEVEL,
                observation: air_gapped_execution.observation,
                legs: air_gapped_execution.legs,
            },
        })
        .or(Err(PairErrorV1::NotExecuted))
}
