//! The G-FORK capture adapter of the non-interference harness (ADR-062
//! Revision 8 slice N4, #1232; owner note `ADR-062_R8_NonInterference_Fork`).
//!
//! One ADR-059 row is captured here, `NI-FORK-008`: the ADR-064 Fork
//! artifacts of slice R6 ([`crate::fork_artifacts`]).
//!
//! # Subject
//!
//! [`g_fork_subject_fixture_v1`] builds the R6 [`ForkFixtureV1`] of one run.
//! The permitted input decides the plan's Intervention (its value digest is
//! the BLAKE3 digest of the permitted input). The host places the
//! unauthorized value in the factual Timeline after the Fork's cut: every
//! factual suffix input is the value, there are one to three of them by its
//! length, and the participant Driver's factual Events after the cut carry it
//! as their hidden participant field. The Fork never observes either.
//!
//! Each mode produces the export in its own way:
//! - Local: a fresh process runs the records-form Fork
//!   ([`serve_g_fork_local_subject_v1`]).
//! - Replay: the run is recorded in-process, and the export is rebuilt from
//!   its recorded Event Store ([`replay_recorded_fork_v1`]): the `RCF1` and
//!   `SIV1` are read back and every `RCP1` and the `CFR1` recovered from the
//!   committed Fork Events, while the `INT1` and `CFP1` are the recorded
//!   plan. No Driver runs and no Event is appended.
//! - Fork: the records-form Fork runs in-process. Per owner answer Q7 it is a
//!   genuine ADR-064 Fork execution; it is re-run when #1204 lands.
//!
//! # Surfaces
//!
//! The nine `NI-FORK-008` surfaces, every one byte-exact:
//! - Fork parent/cut: the plan's `[parent Timeline id, parent cut seq, parent
//!   cut Tick, parent cut digest]`; publicly the plan artifact's export
//!   coordinate `[WorldCut id, cut ordinal, Tick]`.
//! - `CounterfactualPlan`, `RecomputationFrontier`, `SuffixInvalidation`,
//!   checkpoints and result: the exact artifact bytes of that kind, as one
//!   array; publicly the `[ordinal, size, digest]` of each.
//! - snapshots: empty. The records-form run makes no Snapshot: every `RCP1`
//!   carries no Plugin state and no Projection digest.
//! - `ReproManifest`: empty. No `ReproManifest` exists for a records-form Fork
//!   until the ADR-064 R7 steps form (#1204).
//! - exports: the whole export stream `[kind, WorldCut id, cut ordinal,
//!   Tick, ordinal, bytes]`; publicly `[kind, ordinal, size, digest]`.
//!
//! Operationally each surface is the BLAKE3 digest of its authoritative
//! record. No run-local identity, wall time, origin or signature reaches an
//! artifact (R6: the Timeline ids are fixed and Event ids and wall times are
//! covered by no artifact), so nothing is normalized.
//!
//! # Warm and cold
//!
//! Every run publishes its exported artifacts into the artifact store
//! [`G_FORK_STORE_DIRECTORY_V1`] of its working directory, each at its BLAKE3
//! digest. A warm case keeps one directory for
//! its priming run, control run and canary run; a cold run always starts
//! from a new directory. The capture is built from the run's own export,
//! never from the store: the warm and cold variants differ in directory
//! reuse, not in any cached input, so a warm run cannot observe its priming
//! run.
//!
//! The executions are engineering evidence signed with the repository
//! test-fixture-only executor key
//! ([`super::fixture_evidence::non_interference_fixture_executor_key_v1`]),
//! not an attestation.

use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use ciborium::Value;
use pos_conformance::counterfactual::plan::CounterfactualPlanV1;
use pos_conformance::counterfactual::{InterventionOperationV1, InterventionV1};
use pos_conformance::{
    draft_execution_profile_bytes_v1, draft_trust_policy_snapshot_bytes_v1, ExecutionModeV1,
    ExecutionProfileV1, NonInterferenceExecutionErrorV1, NonInterferenceFixturePairV1,
    NonInterferenceHostRunV1, NonInterferenceRawCaptureV1, NonInterferenceRawOperationalV1,
    NonInterferenceVariantV1, ReplayClaimV1, TrustPolicySnapshotV1,
};
use pos_core::{
    factual_event_schema_id, ArtifactClaimInputV1, ArtifactDataClassV1, ArtifactOptionalityV1,
    ArtifactStateV1, ArtifactTransitionRuleV1, ErasureArtifactClassV1, ErasureReferenceV1,
    ErasureReplayClaimV1, RegisteredArtifactV1, ReplayClaimEvaluationV1, ReplayClaimEvaluatorV1,
};

use super::capture::{digest, encode, uint, variant_name, SurfacesV1};
use super::{
    hex, serve_non_interference_local_subject_v1, NonInterferenceModeRunnerV1,
    NonInterferenceNonExecutedCauseV1, NonInterferencePreparationV1,
};
use crate::fork_artifacts::{
    record_fork_v1, replay_recorded_fork_v1, run_fork_v1, ForkArtifactExportV1, ForkArtifactKindV1,
    ForkFixtureV1, ForkRunErrorV1, LEAD_EVENT_TYPE_V1,
};

/// The Fork-artifact row.
pub const G_FORK_FIXTURE_ID_V1: &str = "NI-FORK-008";
/// The directory of a run's artifact store in its working directory.
pub const G_FORK_STORE_DIRECTORY_V1: &str = "g-fork-artifacts";
/// The control member's unauthorized value of every G-FORK fixture.
pub const G_FORK_CONTROL_UNAUTHORIZED_V1: &[u8] = b"fork-denied-control-0";
/// The canary member's unauthorized value of every G-FORK fixture.
pub const G_FORK_CANARY_UNAUTHORIZED_V1: &[u8] = b"fork-canary-hidden-participant-value-008";
/// Factual Ticks before the Fork's cut.
pub const G_FORK_CUT_TICK_V1: u64 = 1;
/// Recomputation Ticks after the first one.
pub const G_FORK_HORIZON_SPAN_V1: u64 = 1;

const PROVENANCE_DOMAIN_V1: &[u8] = b"PiglorOS.NonInterference.ForkProvenance.v1";
/// The Execution Profile every run's plan binds.
const EXECUTION_PROFILE_ID: &str = "deterministic-local-v1";

/// The permitted input of one G-FORK fixture. It is the same in every mode.
#[must_use]
pub fn g_fork_permitted_input_v1(variant: NonInterferenceVariantV1) -> Vec<u8> {
    format!(
        "g-fork permitted input v1/{G_FORK_FIXTURE_ID_V1}/{}",
        variant_name(variant)
    )
    .into_bytes()
}

/// The admitted control/canary pair of one G-FORK coordinate. The two
/// members differ only in their unauthorized value.
///
/// # Errors
/// Returns the #181 admission error of an invalid coordinate.
pub fn g_fork_fixture_v1(
    variant: NonInterferenceVariantV1,
    mode: ExecutionModeV1,
) -> Result<NonInterferenceFixturePairV1, NonInterferenceExecutionErrorV1> {
    NonInterferenceFixturePairV1::try_new(
        G_FORK_FIXTURE_ID_V1,
        variant,
        mode,
        g_fork_permitted_input_v1(variant),
        G_FORK_CONTROL_UNAUTHORIZED_V1.to_vec(),
        G_FORK_CANARY_UNAUTHORIZED_V1.to_vec(),
    )
}

/// The plan's one Intervention, decided by the permitted input alone.
fn intervention(permitted_input: &[u8]) -> InterventionV1 {
    InterventionV1 {
        intervention_id: [0x49; 16],
        target_schema_id: factual_event_schema_id(LEAD_EVENT_TYPE_V1),
        target_entity_id: "body".to_owned(),
        target_field: "velocity".to_owned(),
        operation: InterventionOperationV1::AssignValue,
        value_digest: digest(permitted_input),
        effective_tick: G_FORK_CUT_TICK_V1 + 1,
        ordinal: 0,
        principal_id: "principal:operator".to_owned(),
        capability: "intervene".to_owned(),
        consent_epoch: 3,
        consent_decision_digest: [0x4a; 32],
        rationale: "g-fork what if".to_owned(),
        provenance_digest: [0x4b; 32],
    }
}

/// The host's evaluation of the frozen closure: one retained `Exact` Export
/// artifact.
fn evaluation() -> Option<ReplayClaimEvaluationV1> {
    ReplayClaimEvaluatorV1::evaluate(
        ErasureReplayClaimV1::Exact,
        &[ArtifactClaimInputV1 {
            registration: RegisteredArtifactV1::new(
                ErasureArtifactClassV1::Export,
                ErasureReferenceV1::from_digest([0x31; 32]),
                ArtifactDataClassV1::StructuralAuditMetadata,
                None,
                ErasureReferenceV1::from_digest([0x32; 32]),
                ArtifactOptionalityV1::Required,
                ArtifactTransitionRuleV1::PreserveExact,
            ),
            current_claim: ErasureReplayClaimV1::Exact,
            state: ArtifactStateV1::Retained,
        }],
    )
    .ok()
}

/// The R6 fixture of one run: the permitted input decides the plan, and the
/// host places `unauthorized_value` in the factual Timeline after the cut
/// (see the module documentation).
///
/// # Errors
/// Returns `Unavailable` when the draft Execution Profile, trust policy
/// snapshot or `ReplayClaim` evaluation cannot be built.
pub fn g_fork_subject_fixture_v1(
    permitted_input: &[u8],
    unauthorized_value: &[u8],
) -> Result<ForkFixtureV1, NonInterferenceNonExecutedCauseV1> {
    let profile = draft_execution_profile_bytes_v1(EXECUTION_PROFILE_ID)
        .ok()
        .and_then(|bytes| ExecutionProfileV1::from_canonical_cbor(&bytes).ok());
    let trust = draft_trust_policy_snapshot_bytes_v1()
        .ok()
        .and_then(|bytes| TrustPolicySnapshotV1::from_canonical_cbor(&bytes).ok());
    profile
        .zip(trust)
        .zip(evaluation())
        .map(|((execution_profile, trust_policy), evaluated_claim)| {
            let suffix_ticks = 1 + unauthorized_value.len() % 3;
            ForkFixtureV1 {
                cut_tick: G_FORK_CUT_TICK_V1,
                factual_suffix: vec![unauthorized_value.to_vec(); suffix_ticks],
                hidden_participant_field: unauthorized_value.to_vec(),
                horizon_span: G_FORK_HORIZON_SPAN_V1,
                plan_id: [0x46; 16],
                room_id: "room.g-fork".to_owned(),
                room_digest: [0x47; 32],
                parent_cut_digest: [0x48; 32],
                intervention: intervention(permitted_input),
                exogenous_descriptors: Vec::new(),
                plugin_composition_digest: [0x4c; 32],
                scheduler_digest: [0x4d; 32],
                numeric_profile_digest: [0x4e; 32],
                budget_digest: [0x4f; 32],
                failure_policy_digest: [0x50; 32],
                replay_claim: ReplayClaimV1::Exact,
                execution_profile,
                trust_policy,
                evaluated_claim,
                revocation_epoch: 7,
                erasure_epoch: 8,
                frontier_id: [0x51; 16],
                invalidation_id: [0x52; 16],
                provenance_digest: [0x53; 32],
                result_id: [0x54; 16],
                evaluator_identity_digest: [0x55; 32],
            }
        })
        .ok_or(NonInterferenceNonExecutedCauseV1::Unavailable)
}

/// The closed code of an artifact kind in the exports surface: its position
/// in the export order.
const fn kind_code(kind: ForkArtifactKindV1) -> u64 {
    match kind {
        ForkArtifactKindV1::Intervention => 0,
        ForkArtifactKindV1::CounterfactualPlan => 1,
        ForkArtifactKindV1::RecomputationFrontier => 2,
        ForkArtifactKindV1::SuffixInvalidation => 3,
        ForkArtifactKindV1::Checkpoint => 4,
        ForkArtifactKindV1::Result => 5,
    }
}

/// The authoritative and public record of one artifact kind: its artifacts'
/// exact bytes, and the `[ordinal, size, digest]` of each.
fn kind_records(export: &ForkArtifactExportV1, kind: ForkArtifactKindV1) -> (Vec<u8>, Vec<u8>) {
    let artifacts = export
        .artifacts
        .iter()
        .filter(|artifact| artifact.kind == kind);
    let authoritative = artifacts
        .clone()
        .map(|artifact| Value::Bytes(artifact.bytes.clone()))
        .collect();
    let public = artifacts
        .map(|artifact| {
            Value::Array(vec![
                uint(artifact.coordinate.artifact_ordinal.into()),
                uint(artifact.bytes.len() as u64),
                Value::Bytes(digest(&artifact.bytes).to_vec()),
            ])
        })
        .collect();
    (
        encode(&Value::Array(authoritative)),
        encode(&Value::Array(public)),
    )
}

/// Capture the nine `NI-FORK-008` surfaces of one export.
///
/// # Errors
/// Returns `Unavailable` when the export holds no decodable `CFP1` plan.
pub fn g_fork_capture_v1(
    export: &ForkArtifactExportV1,
) -> Result<NonInterferenceRawCaptureV1, NonInterferenceNonExecutedCauseV1> {
    let plan = export
        .artifacts
        .iter()
        .find(|artifact| artifact.kind == ForkArtifactKindV1::CounterfactualPlan)
        .and_then(|artifact| {
            CounterfactualPlanV1::from_canonical_cbor(&artifact.bytes)
                .ok()
                .map(|plan| (artifact.coordinate, plan))
        });
    plan.map(|(coordinate, plan)| {
        let parent_cut = encode(&Value::Array(vec![
            Value::Bytes(plan.parent_timeline_id.to_vec()),
            uint(plan.parent_cut_seq),
            uint(plan.parent_cut_tick),
            Value::Bytes(plan.parent_cut_digest.to_vec()),
        ]));
        let world_cut = encode(&Value::Array(vec![
            Value::Bytes(coordinate.world_cut_id.to_vec()),
            uint(coordinate.cut_ordinal),
            uint(coordinate.tick),
        ]));
        let empty = encode(&Value::Array(Vec::new()));
        let stream = encode(&Value::Array(
            export
                .artifacts
                .iter()
                .map(|artifact| {
                    Value::Array(vec![
                        uint(kind_code(artifact.kind)),
                        Value::Bytes(artifact.coordinate.world_cut_id.to_vec()),
                        uint(artifact.coordinate.cut_ordinal),
                        uint(artifact.coordinate.tick),
                        uint(artifact.coordinate.artifact_ordinal.into()),
                        Value::Bytes(artifact.bytes.clone()),
                    ])
                })
                .collect(),
        ));
        let listed = encode(&Value::Array(
            export
                .artifacts
                .iter()
                .map(|artifact| {
                    Value::Array(vec![
                        uint(kind_code(artifact.kind)),
                        uint(artifact.coordinate.artifact_ordinal.into()),
                        uint(artifact.bytes.len() as u64),
                        Value::Bytes(digest(&artifact.bytes).to_vec()),
                    ])
                })
                .collect(),
        ));
        let records = |kind| kind_records(export, kind);
        let (plan_record, plan_public) = records(ForkArtifactKindV1::CounterfactualPlan);
        let (frontier, frontier_public) = records(ForkArtifactKindV1::RecomputationFrontier);
        let (invalidation, invalidation_public) = records(ForkArtifactKindV1::SuffixInvalidation);
        let (checkpoints, checkpoints_public) = records(ForkArtifactKindV1::Checkpoint);
        let (result, result_public) = records(ForkArtifactKindV1::Result);
        let authoritative = vec![
            parent_cut,
            plan_record,
            frontier,
            invalidation,
            empty.clone(),
            checkpoints,
            result,
            empty.clone(),
            stream,
        ];
        let public = vec![
            world_cut,
            plan_public,
            frontier_public,
            invalidation_public,
            empty.clone(),
            checkpoints_public,
            result_public,
            empty,
            listed,
        ];
        let operational = authoritative
            .iter()
            .map(|record| NonInterferenceRawOperationalV1::ByteExact(digest(record).to_vec()))
            .collect();
        SurfacesV1 {
            authoritative,
            public,
            operational,
        }
        .into_capture(G_FORK_FIXTURE_ID_V1)
    })
    .ok_or(NonInterferenceNonExecutedCauseV1::Unavailable)
}

/// Publish every exported artifact into the artifact store of `directory` at
/// its BLAKE3 digest. The store is content-addressed, so an artifact already
/// there is rewritten with the same bytes.
fn publish(
    directory: &Path,
    export: &ForkArtifactExportV1,
) -> Result<(), NonInterferenceNonExecutedCauseV1> {
    let store = directory.join(G_FORK_STORE_DIRECTORY_V1);
    fs::create_dir_all(&store)
        .and_then(|()| {
            export.artifacts.iter().try_for_each(|artifact| {
                fs::write(store.join(hex(&digest(&artifact.bytes))), &artifact.bytes)
            })
        })
        .map_err(NonInterferenceNonExecutedCauseV1::from)
}

/// Publish `export` in `directory` and capture it.
fn captured(
    export: ForkArtifactExportV1,
    directory: &Path,
) -> Result<(ForkArtifactExportV1, NonInterferenceRawCaptureV1), NonInterferenceNonExecutedCauseV1>
{
    publish(directory, &export)
        .and_then(|()| g_fork_capture_v1(&export))
        .map(|capture| (export, capture))
}

/// Serve one Local run of the G-FORK subject in a fresh host process whose
/// working directory is `directory`.
///
/// # Errors
/// Returns the cause of a request, subject, capture or frame failure.
pub fn serve_g_fork_local_subject_v1<R: Read, W: Write>(
    input: R,
    output: W,
    directory: &Path,
) -> Result<(), NonInterferenceNonExecutedCauseV1> {
    serve_non_interference_local_subject_v1(input, output, |request| {
        g_fork_subject_fixture_v1(&request.permitted_input, &request.unauthorized_value)
            .and_then(|fixture| {
                run_fork_v1(&fixture, ExecutionModeV1::Local)
                    .ok()
                    .ok_or(NonInterferenceNonExecutedCauseV1::Unavailable)
            })
            .and_then(|export| captured(export, directory))
            .map(|(_, capture)| capture)
    })
}

/// How one in-process runner exports a run of a fixture.
type ExportV1 = fn(&ForkFixtureV1) -> Result<ForkArtifactExportV1, ForkRunErrorV1>;

/// Record the run and rebuild its export from the recorded Event Store.
fn replayed(fixture: &ForkFixtureV1) -> Result<ForkArtifactExportV1, ForkRunErrorV1> {
    record_fork_v1(fixture, ExecutionModeV1::Local)
        .and_then(|(_, mut recorded)| replay_recorded_fork_v1(&mut recorded))
}

/// Run the records-form Fork.
fn forked(fixture: &ForkFixtureV1) -> Result<ForkArtifactExportV1, ForkRunErrorV1> {
    run_fork_v1(fixture, ExecutionModeV1::Local)
}

/// The in-process Replay and Fork runners of the G-FORK subject.
#[derive(Debug)]
pub struct GForkRunnerV1 {
    mode: ExecutionModeV1,
    label: &'static [u8],
    export: ExportV1,
    work_root: PathBuf,
    directories: u64,
    warm: Option<PathBuf>,
}

impl GForkRunnerV1 {
    /// The Replay runner, whose run directories are created below
    /// `work_root`: it records each run and rebuilds its export from the
    /// recorded Event Store and the recorded plan.
    #[must_use]
    pub const fn replay(work_root: PathBuf) -> Self {
        Self::new((ExecutionModeV1::Replay, b"replay", replayed), work_root)
    }

    /// The Fork runner, whose run directories are created below `work_root`:
    /// it runs the records-form Fork.
    #[must_use]
    pub const fn fork(work_root: PathBuf) -> Self {
        Self::new((ExecutionModeV1::Fork, b"fork", forked), work_root)
    }

    const fn new(
        (mode, label, export): (ExecutionModeV1, &'static [u8], ExportV1),
        work_root: PathBuf,
    ) -> Self {
        Self {
            mode,
            label,
            export,
            work_root,
            directories: 0,
            warm: None,
        }
    }

    fn fresh_directory(&mut self) -> Result<PathBuf, NonInterferenceNonExecutedCauseV1> {
        self.directories += 1;
        let directory = self.work_root.join(format!("run-{}", self.directories));
        fs::create_dir_all(&directory)
            .map(|()| directory)
            .map_err(NonInterferenceNonExecutedCauseV1::from)
    }
}

impl NonInterferenceModeRunnerV1 for GForkRunnerV1 {
    fn mode(&self) -> ExecutionModeV1 {
        self.mode
    }

    fn prepare(
        &mut self,
        preparation: NonInterferencePreparationV1,
    ) -> Result<(), NonInterferenceNonExecutedCauseV1> {
        self.warm = None;
        match preparation {
            NonInterferencePreparationV1::Warm => self
                .fresh_directory()
                .map(|directory| self.warm = Some(directory)),
            NonInterferencePreparationV1::Cold => Ok(()),
        }
    }

    fn execute(
        &mut self,
        run: &NonInterferenceHostRunV1<'_>,
        _preparation: NonInterferencePreparationV1,
    ) -> Result<NonInterferenceRawCaptureV1, NonInterferenceNonExecutedCauseV1> {
        let directory = self.warm.clone().map_or_else(|| self.fresh_directory(), Ok);
        directory
            .and_then(|directory| {
                g_fork_subject_fixture_v1(run.subject.permitted_input, run.unauthorized_value)
                    .and_then(|fixture| {
                        (self.export)(&fixture)
                            .ok()
                            .ok_or(NonInterferenceNonExecutedCauseV1::Unavailable)
                    })
                    .and_then(|export| captured(export, &directory))
            })
            .map(|(export, mut capture)| {
                capture.provenance_digest = self.provenance(&export);
                capture
            })
    }
}

impl GForkRunnerV1 {
    /// The run's provenance: the runner's mode label and every exported
    /// artifact.
    fn provenance(&self, export: &ForkArtifactExportV1) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(PROVENANCE_DOMAIN_V1);
        hasher.update(&[0]);
        hasher.update(&(self.label.len() as u64).to_be_bytes());
        hasher.update(self.label);
        for artifact in &export.artifacts {
            hasher.update(&(artifact.bytes.len() as u64).to_be_bytes());
            hasher.update(&artifact.bytes);
        }
        *hasher.finalize().as_bytes()
    }
}
