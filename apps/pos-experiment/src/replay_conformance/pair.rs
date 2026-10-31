//! Paired Local and Air-Gapped executions of one case (ADR-062 Revision 8
//! slice R5, #1224).
//!
//! The evaluator delivers one attempt per Execution Mode from the Local and
//! the Air-Gapped bundle of the same fixture. [`pair_report()`] runs both
//! through the adapter's one execution path and reports them side by side,
//! each against the same expected-result record. Air-Gapped means the
//! `deterministic-air-gapped-v1` semantics (no network, the bundled trust
//! snapshot) run by this host, not a kernel-audited execution under the
//! Sandbox Provider (Q6, as #194 D7): the report labels the Air-Gapped
//! results [`AIR_GAPPED_EVIDENCE`] (owner decision 1 on the wiki page
//! `ADR-062_R8_Paired_Executions`).

use pos_conformance::{DivergenceReportV1, ExecutionModeV1, ReproManifestV1, VerificationResultV1};
use pos_reference::evaluator::{CaseAttempt, SubjectObservation};
use pos_reference::evaluator_domain::{ExecutionMode, FixtureFamily};
use pos_store::StoreConfig;

use super::execute_attempt;

/// The evidence level of the Air-Gapped results of a pair report.
pub const AIR_GAPPED_EVIDENCE: &str =
    "Local-relaxation engineering evidence, not hosted conformance";

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
/// share. It is the sub-case, the whole `VRR1` and the whole `DVR1`, less
/// the fields that differ only because the Execution Mode differs:
///
/// - `VRR1` `request_digest` and `manifest_digest`: the digests of the
///   request and the manifest, and the manifest carries the Execution Mode;
/// - `VRR1` `provenance_digest`: it seals the request digest;
/// - `VRR1` `result_digest`: it seals the three digests above;
/// - `VRR1` `divergence_report_digest` and `DVR1` `report_digest`: the
///   `DVR1` digest, which seals the `DVR1` request and manifest digests;
/// - `DVR1` `request_digest` and `manifest_digest`: as for the `VRR1`.
///
/// Every other field is compared, among them the outcome, the replay claim,
/// the first error, the checked artifact count, the EPF1, TPS1, closure,
/// fixture and evaluator digests, the reproducibility class, the
/// authoritative result digest (every Event in Timeline Order, the
/// Projection checkpoint and every typed failure) and the location,
/// mismatch and expected and actual digests of a divergence. No excluded
/// field is produced by the run, so leaving them out cannot hide a
/// divergence. The paired tests show that the two manifests of a leg differ
/// only in their Execution Mode.
#[derive(Eq, PartialEq)]
struct AuthoritativeResultV1<'a> {
    subcase_id: &'a str,
    result: VerificationResultV1,
    divergence: Option<DivergenceReportV1>,
}

impl LegEvidenceV1 {
    /// Whether two legs have the same authoritative result: the same
    /// sub-case, `VRR1` and `DVR1` except for the digests that bind the
    /// Execution Mode (see the private `AuthoritativeResultV1`).
    #[must_use]
    pub fn same_authoritative_result(&self, other: &Self) -> bool {
        self.authoritative() == other.authoritative()
    }

    fn authoritative(&self) -> AuthoritativeResultV1<'_> {
        AuthoritativeResultV1 {
            subcase_id: &self.subcase_id,
            result: VerificationResultV1 {
                request_digest: [0; 32],
                manifest_digest: [0; 32],
                provenance_digest: [0; 32],
                result_digest: [0; 32],
                divergence_report_digest: None,
                ..self.result.clone()
            },
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
    /// The evidence level of the Air-Gapped results: [`AIR_GAPPED_EVIDENCE`].
    pub air_gapped_evidence: &'static str,
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
        .zip(execute_attempt(store_config, air_gapped))
        .map(|(local_execution, air_gapped_execution)| PairReportV1 {
            case_id: local.case_id.clone(),
            family: local.family,
            local: ModeEvidenceV1 {
                mode: ExecutionModeV1::Local,
                observation: local_execution.observation,
                legs: local_execution.legs,
            },
            air_gapped: ModeEvidenceV1 {
                mode: ExecutionModeV1::AirGapped,
                observation: air_gapped_execution.observation,
                legs: air_gapped_execution.legs,
            },
            air_gapped_evidence: AIR_GAPPED_EVIDENCE,
        })
        .ok_or(PairErrorV1::NotExecuted)
}
