//! Unit tests of the outcome assembler. The end-to-end vectors are in the worker's
//! `tests/handoff_public.rs`.

use pos_core::PluginId;
use pos_runtime::community_plugin_host::{
    AtomicCommitFailureV1, CommunityPluginCeilingsV1, CommunityPluginExecutionProfileV1,
    ComponentTrapClassV1, GateSummaryV1, NegotiatedCommunityPluginV1, RevocationBasisV1,
    TrapReproductionV1, TrustDenialBasisV1,
};

use super::*;
use crate::test_support::{
    fixture_runtime, negotiated_under, negotiated_with, profile_without_digest, METERING,
    SMALL_BUDGET,
};

type Error = CommunityPluginHostErrorV1;
type Outcome = CommunityPluginSubjectOutcomeV1;
type Verdict = CommunityPluginSubjectResultV1;

const PRE: &str = "PreExecutionRejection";
const UNVALIDATED: ContentValidationV1 = ContentValidationV1::NotPerformed;
const LOCAL: CommunityPluginModeV1 = CommunityPluginModeV1::Local;
const AIR_GAPPED: CommunityPluginModeV1 = CommunityPluginModeV1::AirGapped;

fn summary() -> GateSummaryV1 {
    GateSummaryV1 {
        plugin_id: "plugin-a".to_owned(),
        pmf1_digest: [1; 32],
        release_digest: [2; 32],
        tps1_digest: [3; 32],
        tick: 9,
        content_validation: UNVALIDATED,
    }
}

fn member(gate: Result<GateSummaryV1, Error>, launch_failure: Option<Error>) -> MemberPassV1 {
    MemberPassV1 {
        plugin: PluginId::new(),
        expected_plugin_id: "plugin-a".to_owned(),
        gate,
        invocation_id: Some([5; 16]),
        launch_failure,
        sync: Ok(()),
    }
}

fn receipt(
    negotiated: NegotiatedCommunityPluginV1,
    failure: Option<Error>,
    disposition: ReceiptDispositionV1,
) -> CommunityInvocationReceiptV1 {
    CommunityInvocationReceiptV1 {
        invocation_id: [5; 16],
        negotiated,
        output_digest: Some([7; 32]),
        metering: Some(METERING),
        dropped_trace_annotations: 0,
        failure,
        guest_error: None,
        disposition,
        content_validation: UNVALIDATED,
    }
}

fn local_receipt(failure: Option<Error>, disposition: ReceiptDispositionV1) -> Outcome {
    let negotiated = negotiated_with("plugin-a", SMALL_BUDGET, Vec::new());
    let held = receipt(negotiated, failure, disposition);
    Outcome::assemble(&member(Ok(summary()), None), 9, LOCAL, Some(&held))
}

fn without_receipt(gate: Result<GateSummaryV1, Error>, launch: Option<Error>) -> Outcome {
    Outcome::assemble(&member(gate, launch), 9, AIR_GAPPED, None)
}

fn staged() -> Verdict {
    Verdict::Staged {
        output_digest: Some([7; 32]),
        metering: Some(METERING),
    }
}

#[test]
fn a_gate_error_is_refused_and_outranks_a_receipt_and_a_launch_failure() {
    let revoked = Error::ArtifactRevoked {
        basis: RevocationBasisV1::Artifact,
    };
    let entry = member(Err(revoked), Some(Error::WorkerCrashed));
    let negotiated = negotiated_with("plugin-a", SMALL_BUDGET, Vec::new());
    let held = receipt(negotiated, None, ReceiptDispositionV1::Committed);
    let outcome = Outcome::assemble(&entry, 4, AIR_GAPPED, Some(&held));
    let expected = Verdict::Refused {
        error: "ArtifactRevoked",
        basis: Some("Artifact"),
        class: PRE,
    };
    assert_eq!(outcome.result, expected);
    assert_eq!(outcome.plugin_id, "plugin-a");
    assert_eq!(outcome.tick, 4);
    assert_eq!(outcome.pmf1_digest, None);
    assert_eq!(outcome.release_digest, None);
    assert_eq!(outcome.tps1_digest, None);
    assert_eq!(outcome.content_validation, UNVALIDATED);
}

#[test]
fn a_receipt_without_failure_gives_its_disposition() {
    let digest = Some([7; 32]);
    let metering = Some(METERING);
    let kept = local_receipt(None, ReceiptDispositionV1::Staged);
    assert_eq!(kept.result, staged());
    let committed = local_receipt(None, ReceiptDispositionV1::Committed);
    let expected = Verdict::Committed {
        output_digest: digest,
        metering,
    };
    assert_eq!(committed.result, expected);
    let dropped = local_receipt(None, ReceiptDispositionV1::Discarded);
    assert_eq!(dropped.result, Verdict::Discarded);
    assert_eq!(dropped.pmf1_digest, Some([1; 32]));
}

#[test]
fn a_receipt_failure_is_refused_or_failed_by_class_whatever_the_disposition() {
    let denied = Error::ArtifactTrustDenied {
        basis: TrustDenialBasisV1::NotActive,
    };
    let refused = local_receipt(Some(denied), ReceiptDispositionV1::Discarded);
    let expected = Verdict::Refused {
        error: "ArtifactTrustDenied",
        basis: Some("NotActive"),
        class: PRE,
    };
    assert_eq!(refused.result, expected);
    let failed = local_receipt(
        Some(Error::InvalidGuestOutput),
        ReceiptDispositionV1::Committed,
    );
    let expected = Verdict::Failed {
        error: "InvalidGuestOutput",
        class: "Authoritative",
    };
    assert_eq!(failed.result, expected);
    let operational = Error::AtomicCommitFailed {
        failure: AtomicCommitFailureV1::Operational,
    };
    let failed = local_receipt(Some(operational), ReceiptDispositionV1::Staged);
    let expected = Verdict::Failed {
        error: "AtomicCommitFailed",
        class: "Operational",
    };
    assert_eq!(failed.result, expected);
}

#[test]
fn a_receipt_outranks_the_launch_failure() {
    let negotiated = negotiated_with("plugin-a", SMALL_BUDGET, Vec::new());
    let held = receipt(negotiated, None, ReceiptDispositionV1::Staged);
    let entry = member(Ok(summary()), Some(Error::WorkerCrashed));
    let outcome = Outcome::assemble(&entry, 9, LOCAL, Some(&held));
    assert_eq!(outcome.result, staged());
}

#[test]
fn without_a_receipt_the_launch_failure_or_not_run_decides() {
    let trap = Error::ComponentTrap {
        class: ComponentTrapClassV1::Other,
        reproduction: TrapReproductionV1::Unverified,
    };
    let pre = without_receipt(Ok(summary()), Some(Error::InvalidInvocation));
    let expected = Verdict::Refused {
        error: "InvalidInvocation",
        basis: None,
        class: PRE,
    };
    assert_eq!(pre.result, expected);
    let failed = without_receipt(Ok(summary()), Some(trap));
    let expected = Verdict::Failed {
        error: "ComponentTrap",
        class: "Operational",
    };
    assert_eq!(failed.result, expected);
    let not_run = without_receipt(Ok(summary()), None);
    assert_eq!(not_run.result, Verdict::NotRun);
    assert_eq!(not_run.pmf1_digest, Some([1; 32]));
    assert_eq!(not_run.release_digest, Some([2; 32]));
    assert_eq!(not_run.tps1_digest, Some([3; 32]));
    assert_eq!(not_run.execution_profile_digest, None);
    assert_eq!(not_run.mode, AIR_GAPPED);
    assert_eq!(not_run.tick, 9);
}

#[test]
fn the_receipts_mode_and_profile_digest_win_over_the_callers() {
    let profile = CommunityPluginExecutionProfileV1::new(
        AIR_GAPPED,
        CommunityPluginCeilingsV1::V1,
        Some(fixture_runtime()),
    );
    let negotiated = negotiated_under("plugin-a", SMALL_BUDGET, Vec::new(), &profile);
    let digest = negotiated.execution_profile_digest();
    assert!(digest.is_some());
    let held = receipt(negotiated, None, ReceiptDispositionV1::Staged);
    let entry = member(Ok(summary()), None);
    let outcome = Outcome::assemble(&entry, 9, LOCAL, Some(&held));
    assert_eq!(outcome.mode, AIR_GAPPED);
    assert_eq!(outcome.execution_profile_digest, digest);

    let bare = profile_without_digest();
    let negotiated = negotiated_under("plugin-a", SMALL_BUDGET, Vec::new(), &bare);
    let held = receipt(negotiated, None, ReceiptDispositionV1::Staged);
    let outcome = Outcome::assemble(&entry, 9, AIR_GAPPED, Some(&held));
    assert_eq!(outcome.mode, LOCAL);
    assert_eq!(outcome.execution_profile_digest, None);
}

fn every_result() -> [Verdict; 6] {
    let refused = Verdict::Refused {
        error: "InvalidInvocation",
        basis: None,
        class: PRE,
    };
    let failed = Verdict::Failed {
        error: "WorkerCrashed",
        class: "Operational",
    };
    let committed = Verdict::Committed {
        output_digest: None,
        metering: None,
    };
    [
        staged(),
        committed,
        refused,
        failed,
        Verdict::NotRun,
        Verdict::Discarded,
    ]
}

#[test]
fn every_result_is_cloned_compared_and_formatted() {
    for result in every_result() {
        let base = without_receipt(Ok(summary()), None);
        let outcome = Outcome { result, ..base };
        let copy = outcome.clone();
        assert_eq!(copy, outcome);
        let shown = format!("{outcome:?}");
        assert!(shown.contains("plugin-a"), "{shown}");
    }
}
