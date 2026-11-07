//! The Candidate -> Stable promotion gate of ADR-062 Revision 8 section 5.3 (slice G4, #1239).
//!
//! [`check_stable_promotion_v1`] refuses a CPR1 promotion to Stable unless every rule of wiki
//! `ADR-062_R8_Promotion_Gate` section 8 holds over the CHS1 history, the authenticated CPF1
//! profile and four CNR1 reports: the Local and the Air-Gapped report of each of two
//! implementations. One implementation, or one implementation and any number of evaluators,
//! never passes: no Stable promotion is possible until an independently developed second
//! implementation exists. This module delivers the gate, not a Stable profile.
//!
//! Keys are admitted again at promotion time through the G2 [`ConformanceTrustAdmissionPortV1`]:
//! each report-signing key id (from the verified report attestation) for
//! [`ConformanceTrustRoleV1::ReportSigning`] and each evaluator-release key id for
//! [`ConformanceTrustRoleV1::EvaluatorRelease`]. The evaluator-release key id is supplied by
//! the caller and is not yet bound to the evaluator binary; G5 (#1240) binds it with the
//! evaluator signing hook. `minimum_evaluator_protocol_version` is not enforced here: CPF1 and
//! CNR1 carry only an evaluator protocol digest, so G5 enforces it.
//!
//! The gate takes no pinned history head: it replays the history the caller supplies. A
//! caller can therefore pass a truncated history that leaves out an Open CCF1 conflict or a
//! waiver, together with a CPR1 whose snapshot digest matches that truncation. Binding the
//! history to its published head (for example with [`ConformanceHistoryV1::extends`]) is left
//! to G5 (#1240) or the host; this is a stated weakness, like the evaluator-release key above.

use crate::{
    CaseOutcomeStatusV1, CaseOutcomeV1, ConformanceArtifactRefusalV1, ConformanceGovernanceErrorV1,
    ConformanceHistoryV1, ConformanceKeyRefusalV1, ConformanceProfileV1,
    ConformancePromotionReportsV1, ConformancePromotionV1, ConformanceReportV1,
    ConformanceTrustAdmissionPortV1, ConformanceTrustRoleV1, ExecutionModeV1, FixtureDescriptorV1,
    ImplementationIdentityV1, ProfileLifecycleV1,
};

/// Why the gate refused a promotion to Stable.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ConformancePromotionRefusalV1 {
    /// The CPR1, the CHS1 history or a record it names is invalid.
    #[error("promotion governance record is invalid: {0}")]
    InvalidRecord(ConformanceGovernanceErrorV1),
    /// The CPR1 is not a Candidate -> Stable promotion.
    #[error("promotion is not Candidate -> Stable")]
    NotStablePromotion,
    /// The CPR1, the history or a report names another profile than the CPF1.
    #[error("promotion evidence names another profile")]
    ProfileMismatch,
    /// The replayed history is not at Candidate.
    #[error("profile history is not at Candidate")]
    NotCandidate,
    /// The CPR1 waiver/conflict snapshot digest is not the history's.
    #[error("waiver/conflict snapshot digest does not recompute")]
    SnapshotMismatch,
    /// The history holds an open conflict.
    #[error("an open conflict keeps the profile Candidate")]
    OpenConflict,
    /// The history holds a waiver in force on a mandatory case.
    #[error("an active waiver on a mandatory case keeps the profile Candidate")]
    ActiveMandatoryWaiver,
    /// A report is not a valid CNR1 report.
    #[error("a promotion report is not a valid CNR1 report")]
    InvalidReport,
    /// A report's digest or implementation identity is not the one the CPR1 names.
    #[error("a promotion report is not the report the CPR1 names")]
    ReportNotNamed,
    /// The two implementations share an implementation id, source, build or binary digest.
    #[error("the two implementations are one implementation")]
    SameImplementation,
    /// The two implementations have different public-contract digests.
    #[error("the implementations use different public contracts")]
    PublicContractMismatch,
    /// An implementation's source or binary digest is an evaluator's.
    #[error("an evaluator poses as an implementation")]
    EvaluatorAsImplementation,
    /// The evaluator protocol, or per mode the fixture bundle or execution profile, differs.
    #[error("the reports do not share profile, fixture bundle and evaluator protocol evidence")]
    EvidenceMismatch,
    /// The profile has no mandatory fixture, so no case could support Stable.
    #[error("the profile has no mandatory fixture")]
    NoMandatoryFixture,
    /// A mandatory fixture does not declare both Local and Air-Gapped.
    #[error("a mandatory fixture lacks Local or Air-Gapped")]
    MandatoryModeMissing,
    /// A report has no case for a mandatory fixture in its mode.
    #[error("a mandatory case was not executed")]
    CaseNotExecuted,
    /// A mandatory case is `Fail`, `Skip`, `Unavailable` or `NotApplicable`.
    #[error("a mandatory case did not pass")]
    CaseNotPassed,
    /// A mandatory case's first coordinate is not the profile-allowed one.
    #[error("a mandatory case diverged outside the profile-allowed divergence")]
    DivergenceNotAllowed,
    /// The two implementations produced different outcomes for a mandatory case.
    #[error("the implementations disagree on a mandatory case")]
    OutcomeMismatch,
    /// A report does not evidence a required independence level.
    #[error("a report does not evidence the required independence")]
    IndependenceNotEvidenced,
    /// A report's shared-code audit digest is not the CPR1's.
    #[error("the shared-code audit is not the one the CPR1 names")]
    SharedCodeAuditMismatch,
    /// A report-signing or evaluator-release key is not admitted for its role.
    #[error("a {0:?} key was not admitted: {1:?}")]
    KeyRefused(ConformanceTrustRoleV1, ConformanceKeyRefusalV1),
    /// A report digest or evaluator binary digest is revoked.
    #[error("a promotion artifact is revoked: {0:?}")]
    ArtifactRevoked(ConformanceArtifactRefusalV1),
}

type Refusal = ConformancePromotionRefusalV1;

/// One CNR1 report offered to the gate with the keys that attest it.
#[derive(Clone, Copy, Debug)]
pub struct ConformancePromotionReportEvidenceV1<'a> {
    pub report: &'a ConformanceReportV1,
    /// The key id of the verified report attestation's signer.
    pub report_key_id: [u8; 32],
    /// The evaluator-release key id. It is supplied by the caller and not yet bound to the
    /// evaluator binary; G5 (#1240) binds it.
    pub evaluator_key_id: [u8; 32],
}

/// The Local and the Air-Gapped report of one implementation.
#[derive(Clone, Copy, Debug)]
pub struct ConformancePromotionImplementationEvidenceV1<'a> {
    pub local: ConformancePromotionReportEvidenceV1<'a>,
    pub air_gapped: ConformancePromotionReportEvidenceV1<'a>,
}

/// Everything the gate reads.
#[derive(Clone, Copy, Debug)]
pub struct ConformancePromotionGateInputV1<'a> {
    /// The authenticated CPF1 the caller holds; it is not validated again here.
    pub profile: &'a ConformanceProfileV1,
    pub history: &'a ConformanceHistoryV1,
    /// The exact bytes of the record each history entry names, in entry order.
    pub history_records: &'a [&'a [u8]],
    pub promotion: &'a ConformancePromotionV1,
    /// The first and the second implementation, in CPR1 order.
    pub implementations: [ConformancePromotionImplementationEvidenceV1<'a>; 2],
}

/// Refuse a CPR1 promotion to Stable unless every rule of wiki `ADR-062_R8_Promotion_Gate`
/// section 8 holds.
///
/// Waivers and conflicts come from the history, never from the caller. Independence booleans
/// are read as the reports evidence them and never inferred: every report must report
/// technical and authorship independence, and organizational independence when the profile
/// requires it.
///
/// # Errors
/// Returns the closed refusal of the first failing check.
pub fn check_stable_promotion_v1(
    input: &ConformancePromotionGateInputV1<'_>,
    trust: &impl ConformanceTrustAdmissionPortV1,
) -> Result<(), ConformancePromotionRefusalV1> {
    let promotion = input.promotion;
    let profile = input.profile;
    promotion.validate().map_err(Refusal::InvalidRecord)?;
    if promotion.to_lifecycle != ProfileLifecycleV1::Stable {
        return Err(Refusal::NotStablePromotion);
    }
    if promotion.profile_digest != profile.profile_digest
        || input.history.profile_digest != profile.profile_digest
    {
        return Err(Refusal::ProfileMismatch);
    }
    check_history(input)?;
    let [first, second] = input.implementations;
    let evidence = [
        (
            first,
            &promotion.first_reports,
            &promotion.first_implementation,
        ),
        (
            second,
            &promotion.second_reports,
            &promotion.second_implementation,
        ),
    ];
    for (implementation, digests, identity) in evidence {
        check_named(implementation, digests, identity, profile)?;
    }
    let reports = [
        first.local,
        first.air_gapped,
        second.local,
        second.air_gapped,
    ];
    check_identities(promotion, &reports)?;
    if !profile.fixtures.iter().any(|fixture| fixture.mandatory) {
        return Err(Refusal::NoMandatoryFixture);
    }
    check_cases(profile, [first.local, second.local], ExecutionModeV1::Local)?;
    check_cases(
        profile,
        [first.air_gapped, second.air_gapped],
        ExecutionModeV1::AirGapped,
    )?;
    reports
        .iter()
        .try_for_each(|evidence| check_independence(evidence.report, profile, promotion))?;
    reports
        .iter()
        .try_for_each(|evidence| check_keys(evidence, trust))
}

/// The history is at Candidate, its snapshot is the CPR1's and it holds no open conflict and
/// no waiver in force on a mandatory case at the CPR1 epoch.
fn check_history(input: &ConformancePromotionGateInputV1<'_>) -> Result<(), Refusal> {
    let state = input
        .history
        .replay(input.history_records)
        .map_err(Refusal::InvalidRecord)?;
    if state.lifecycle() != ProfileLifecycleV1::Candidate {
        return Err(Refusal::NotCandidate);
    }
    if state.waiver_conflict_snapshot_digest() != input.promotion.waiver_conflict_snapshot_digest {
        return Err(Refusal::SnapshotMismatch);
    }
    if state.has_open_conflict() {
        return Err(Refusal::OpenConflict);
    }
    if state.waivers().iter().any(|waiver| {
        waiver.effect(
            input.profile,
            ProfileLifecycleV1::Stable,
            input.promotion.epoch,
        ) == Err(ConformanceGovernanceErrorV1::MandatoryWaiverOutsideCandidate)
    }) {
        return Err(Refusal::ActiveMandatoryWaiver);
    }
    Ok(())
}

/// Both reports of one implementation are valid CNR1 reports of the profile, are the reports
/// the CPR1 names and carry the implementation identity the CPR1 names.
fn check_named(
    implementation: ConformancePromotionImplementationEvidenceV1<'_>,
    digests: &ConformancePromotionReportsV1,
    identity: &ImplementationIdentityV1,
    profile: &ConformanceProfileV1,
) -> Result<(), Refusal> {
    for (evidence, digest) in [
        (implementation.local, digests.local_report_digest),
        (implementation.air_gapped, digests.air_gapped_report_digest),
    ] {
        let report = evidence.report;
        report.validate().map_err(|_| Refusal::InvalidReport)?;
        if report.report_digest != digest || report.implementation != *identity {
            return Err(Refusal::ReportNotNamed);
        }
        if report.profile_digest != profile.profile_digest {
            return Err(Refusal::ProfileMismatch);
        }
    }
    Ok(())
}

/// Two distinct implementations of one public contract, neither of them an evaluator, run by
/// evaluators of the profile's protocol.
fn check_identities(
    promotion: &ConformancePromotionV1,
    reports: &[ConformancePromotionReportEvidenceV1<'_>; 4],
) -> Result<(), Refusal> {
    let (first, second) = (
        &promotion.first_implementation,
        &promotion.second_implementation,
    );
    if first.implementation_id == second.implementation_id
        || first.source_digest == second.source_digest
        || first.build_digest == second.build_digest
        || first.binary_digest == second.binary_digest
    {
        return Err(Refusal::SameImplementation);
    }
    if first.public_contract_digest != second.public_contract_digest {
        return Err(Refusal::PublicContractMismatch);
    }
    let evaluator_poses = |identity: &ImplementationIdentityV1| {
        reports.iter().any(|evidence| {
            identity.source_digest == evidence.report.evaluator_source_digest
                || identity.binary_digest == evidence.report.evaluator_binary_digest
        })
    };
    if evaluator_poses(first) || evaluator_poses(second) {
        return Err(Refusal::EvaluatorAsImplementation);
    }
    Ok(())
}

/// Every mandatory fixture passes in `mode` in both implementations' reports of that mode,
/// with the same outcome; the reports share the evaluator protocol of the profile, the fixture
/// bundle and the execution profile.
fn check_cases(
    profile: &ConformanceProfileV1,
    [first, second]: [ConformancePromotionReportEvidenceV1<'_>; 2],
    mode: ExecutionModeV1,
) -> Result<(), Refusal> {
    let (first, second) = (first.report, second.report);
    let protocol = profile.evaluator_protocol.protocol_digest;
    if first.evaluator_protocol_digest != protocol
        || second.evaluator_protocol_digest != protocol
        || first.fixture_bundle_digest != second.fixture_bundle_digest
        || first.execution_profile_digest != second.execution_profile_digest
    {
        return Err(Refusal::EvidenceMismatch);
    }
    for fixture in profile.fixtures.iter().filter(|fixture| fixture.mandatory) {
        if !fixture.modes.contains(&ExecutionModeV1::Local)
            || !fixture.modes.contains(&ExecutionModeV1::AirGapped)
        {
            return Err(Refusal::MandatoryModeMissing);
        }
        let first_case = passed_case(first, fixture, mode)?;
        let second_case = passed_case(second, fixture, mode)?;
        if (
            first_case.expected_digest,
            first_case.actual_digest,
            first_case.expected_error,
            first_case.actual_error,
        ) != (
            second_case.expected_digest,
            second_case.actual_digest,
            second_case.expected_error,
            second_case.actual_error,
        ) {
            return Err(Refusal::OutcomeMismatch);
        }
    }
    Ok(())
}

/// The report's Pass case of `fixture` in `mode`, whose first coordinate is the profile-allowed
/// divergence coordinate of a divergence oracle and absent otherwise.
fn passed_case<'a>(
    report: &'a ConformanceReportV1,
    fixture: &FixtureDescriptorV1,
    mode: ExecutionModeV1,
) -> Result<&'a CaseOutcomeV1, Refusal> {
    let case = report
        .cases
        .iter()
        .find(|case| {
            case.case_id == fixture.case_id
                && case.mode == mode
                && case.claim_layer == fixture.claim_layer
                && case.fixture_digest == fixture.fixture_digest
        })
        .ok_or(Refusal::CaseNotExecuted)?;
    let allowed = fixture
        .strict_oracle
        .divergence
        .as_ref()
        .map(|divergence| divergence.first_coordinate.as_slice());
    if case.outcome != CaseOutcomeStatusV1::Pass {
        Err(Refusal::CaseNotPassed)
    } else if case.first_coordinate.as_deref() == allowed {
        Ok(case)
    } else {
        Err(Refusal::DivergenceNotAllowed)
    }
}

/// The report evidences every required independence level and the CPR1's shared-code audit.
fn check_independence(
    report: &ConformanceReportV1,
    profile: &ConformanceProfileV1,
    promotion: &ConformancePromotionV1,
) -> Result<(), Refusal> {
    let independence = &report.independence;
    if !independence.technical_independent
        || !independence.authorship_independent
        || (profile
            .independence_requirements
            .organizational_independence_required
            && !independence.organizational_independent)
    {
        return Err(Refusal::IndependenceNotEvidenced);
    }
    if independence.shared_code_audit_digest == promotion.shared_code_audit_digest {
        Ok(())
    } else {
        Err(Refusal::SharedCodeAuditMismatch)
    }
}

/// The report and evaluator keys are admitted for their roles and neither the report nor the
/// evaluator binary is revoked.
fn check_keys(
    evidence: &ConformancePromotionReportEvidenceV1<'_>,
    trust: &impl ConformanceTrustAdmissionPortV1,
) -> Result<(), Refusal> {
    for (role, key_id) in [
        (
            ConformanceTrustRoleV1::ReportSigning,
            &evidence.report_key_id,
        ),
        (
            ConformanceTrustRoleV1::EvaluatorRelease,
            &evidence.evaluator_key_id,
        ),
    ] {
        trust
            .admit_key(role, key_id)
            .map_err(|refusal| Refusal::KeyRefused(role, refusal))?;
    }
    trust
        .check_artifact_revocation(
            &evidence.report.report_digest,
            &evidence.report.evaluator_binary_digest,
        )
        .map_err(Refusal::ArtifactRevoked)
}
