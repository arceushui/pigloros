//! The host composition of the replay-conformance subject adapter: its EPF1
//! table, its bundled TPS1, the frozen recomputation subject and the run of
//! each sub-case through the slice R2 and R3 execution steps.

use std::collections::BTreeMap;
use std::sync::Arc;

use pos_conformance::{
    draft_execution_profile_bytes_v1, draft_trust_policy_snapshot_bytes_v1,
    ArtifactClosureStatusV1, ArtifactRevocationStatusV1, DigestSizeV1, ExecutionModeV1,
    ExecutionProfileV1, ProfileSupportStatusV1, ReproManifestV1, ReproVerificationRequestV1,
    ReproducibilityClassV1, TrustPolicySnapshotV1, TrustRootStatusV1, TrustSignatureStatusV1,
    TrustSnapshotContinuityV1, VerificationPreflightEvidenceV1, VerificationPreflightInputV1,
};
use pos_core::{
    event::{CanonicalBytes, EventDraft, Kind},
    ids::{PluginId, TimelineId},
    plugin::{Capability, Plugin},
    ErasureContainmentGateV1, ErasureReferenceV1, Event, Reducer, State,
};
use pos_runtime::{Driver, ObservationView, RuntimeError, StepOutput};
use pos_state::ProjectionRegistry;
use pos_store::StoreConfig;

use super::payload::{
    hex, ClosureV1, DigestSizeV1 as DigestSizeRecordV1, DivergenceV1, FirstErrorV1, LegV1,
    ManifestFieldsV1, ProfileV1, RecordV1, ScriptV1, SubCaseV1,
};
use crate::profile_recomputation::{
    execute_cross_profile_conformance_v1, execute_profile_recomputation_v1,
    CrossProfileConformanceInputV1, ProfileRecomputationInputV1, RecomputationClosureV1,
    RecomputationSubjectMemberV1, RecomputationSubjectV1,
};
use crate::recorded_replay::{
    execute_recorded_replay_v1, ExportedTimelineMemberV1, RecordedReplayClosureV1,
    RecordedReplayInputV1,
};
use crate::verification_execution::VerificationExecutionOutcomeV1;
use crate::Experiment;

/// The name of the Projection Reducer every run folds into.
pub(super) const REDUCER: &str = "replay-conformance.count";
/// The name of the frozen subject's one Plugin and Driver.
pub(super) const SUBJECT_PLUGIN: &str = "replay-subject";

/// The EPF1 records and the TPS1 the adapter's host installs.
///
/// `deterministic-local-v1` and `deterministic-air-gapped-v1` are the
/// repository Draft authority records. The Draft authority declares no EPF1
/// for `RecordedReplay` or `LiveUnverified`, so `replay-v1` and
/// `live-local-v1` are `deterministic-local-v1` restricted to that one class,
/// under their own id and digest. The TPS1 is the bundled Draft snapshot, so
/// its root, signature, revocation and continuity evidence is the host's own.
pub(super) struct HostV1 {
    local: ExecutionProfileV1,
    air_gapped: ExecutionProfileV1,
    replay: ExecutionProfileV1,
    live: ExecutionProfileV1,
    snapshot: TrustPolicySnapshotV1,
    snapshot_digest: [u8; 32],
}

fn draft_profile(profile: ProfileV1) -> Option<ExecutionProfileV1> {
    draft_execution_profile_bytes_v1(profile.id())
        .ok()
        .and_then(|bytes| ExecutionProfileV1::from_canonical_cbor(&bytes).ok())
}

fn restricted(
    base: &ExecutionProfileV1,
    profile: ProfileV1,
    class: ReproducibilityClassV1,
) -> ExecutionProfileV1 {
    let mut restricted = base.clone();
    profile.id().clone_into(&mut restricted.profile_id);
    restricted.reproducibility_classes = vec![class];
    restricted.profile_digest = restricted.digest();
    restricted
}

impl HostV1 {
    /// Install the host's EPF1 table and TPS1.
    pub(super) fn install() -> Option<Self> {
        let snapshot = draft_trust_policy_snapshot_bytes_v1()
            .ok()
            .and_then(|bytes| TrustPolicySnapshotV1::from_canonical_cbor(&bytes).ok());
        draft_profile(ProfileV1::Local)
            .zip(draft_profile(ProfileV1::AirGapped))
            .zip(snapshot)
            .and_then(|((local, air_gapped), snapshot)| {
                snapshot.digest().ok().map(|snapshot_digest| Self {
                    replay: restricted(
                        &local,
                        ProfileV1::Replay,
                        ReproducibilityClassV1::RecordedReplay,
                    ),
                    live: restricted(
                        &local,
                        ProfileV1::Live,
                        ReproducibilityClassV1::LiveUnverified,
                    ),
                    local,
                    air_gapped,
                    snapshot,
                    snapshot_digest,
                })
            })
    }

    const fn profile(&self, profile: ProfileV1) -> &ExecutionProfileV1 {
        match profile {
            ProfileV1::Local => &self.local,
            ProfileV1::AirGapped => &self.air_gapped,
            ProfileV1::Replay => &self.replay,
            ProfileV1::Live => &self.live,
        }
    }

    /// The request of one leg: the manifest the fixture owns, bound by the
    /// host to the leg's EPF1, the bundled TPS1 and the sub-case's class.
    fn request(
        &self,
        fields: &ManifestFieldsV1,
        class: ReproducibilityClassV1,
        profile: ProfileV1,
    ) -> LegRequestV1 {
        let execution_profile = self.profile(profile).clone();
        let manifest = ReproManifestV1 {
            format_version: fields.format_version,
            input_digest: fields.input_digest,
            execution_mode: if profile == ProfileV1::AirGapped {
                ExecutionModeV1::AirGapped
            } else {
                ExecutionModeV1::Local
            },
            fork_cut_seq: None,
            seed: fields.seed,
            resource_limit: fields.resource_limit,
            network_enabled: fields.network_enabled,
            reproducibility_class: class,
            execution_profile: execution_profile.profile_id.clone(),
            execution_profile_digest: execution_profile.profile_digest,
            trust_policy_snapshot_digest: self.snapshot_digest,
            artifact_closure_digest: fields.artifact_closure_digest,
            evaluator_digest: fields.evaluator_digest,
            replay_claim: fields.replay_claim,
            plugin_versions: BTreeMap::new(),
            scenario_room_digest: fields.scenario_room_digest,
            scheduler_digest: fields.scheduler_digest,
            budget_digest: fields.budget_digest,
        };
        let request = ReproVerificationRequestV1 {
            request_digest: fields.request_digest,
            manifest_digest: manifest_digest(&manifest),
            reproducibility_class: class,
            execution_profile_digest: execution_profile.profile_digest,
            trust_policy_snapshot_digest: self.snapshot_digest,
            artifact_closure_digest: fields.artifact_closure_digest,
            evaluator_digest: fields.evaluator_digest,
            report_bytes_limit: fields.report_bytes_limit,
        };
        // A request that does not encode keeps empty bytes and a zero digest:
        // the preflight rejects it at `request` before it reads either.
        LegRequestV1 {
            canonical_request_bytes: request.to_canonical_cbor().unwrap_or_default(),
            canonical_request_digest: request.digest().unwrap_or([0; 32]),
            request,
            manifest,
            execution_profile,
            snapshot: self.snapshot.clone(),
        }
    }
}

fn manifest_digest(manifest: &ReproManifestV1) -> [u8; 32] {
    pos_crypto::canonical::encode(manifest).map_or([0; 32], |bytes| {
        let mut digest = blake3::Hasher::new();
        digest.update(b"PiglorOS.ReproManifest.v1\0");
        digest.update(bytes.as_slice());
        *digest.finalize().as_bytes()
    })
}

/// The owned preflight input of one leg.
struct LegRequestV1 {
    request: ReproVerificationRequestV1,
    canonical_request_bytes: Vec<u8>,
    canonical_request_digest: [u8; 32],
    manifest: ReproManifestV1,
    execution_profile: ExecutionProfileV1,
    snapshot: TrustPolicySnapshotV1,
}

impl LegRequestV1 {
    const fn preflight(&self) -> VerificationPreflightInputV1<'_> {
        VerificationPreflightInputV1 {
            request: &self.request,
            canonical_request_bytes: &self.canonical_request_bytes,
            canonical_request_digest: self.canonical_request_digest,
            manifest: &self.manifest,
            execution_profile: &self.execution_profile,
            trust_policy_snapshot: &self.snapshot,
            evidence: VerificationPreflightEvidenceV1 {
                trust_root: TrustRootStatusV1::Known,
                trust_signature: TrustSignatureStatusV1::Valid,
                artifact_revocation: ArtifactRevocationStatusV1::Clear,
                trust_continuity: TrustSnapshotContinuityV1 {
                    previous_epoch: None,
                    previous_snapshot_digest: None,
                },
                artifact_closure: ArtifactClosureStatusV1::Complete,
                profile_support: ProfileSupportStatusV1::Supported,
            },
        }
    }
}

/// Counts every Event per entity; the one Projection of every run.
struct CountReducer;

impl Reducer for CountReducer {
    fn initial(&self) -> State {
        State::new()
    }

    fn apply(&self, state: &mut State, _event: &Event) {
        let count = state
            .fields
            .get("count")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0);
        state.set("count", serde_json::json!(count + 1));
    }
}

/// A fresh Projection registry: the counting Reducer behind a host-bound
/// erasure gate. The gate is the open fixture gate: the adapter has no
/// verified erasure inventory for an imported export (Local-relaxation
/// engineering evidence).
fn projections() -> ProjectionRegistry {
    let mut projections = ProjectionRegistry::new()
        .with_erasure_gate(Arc::new(ErasureContainmentGateV1::new_test_open()));
    projections.register(REDUCER, Box::new(CountReducer));
    projections
}

struct SubjectPlugin {
    id: PluginId,
    event_type: Kind,
}

impl Plugin for SubjectPlugin {
    fn id(&self) -> PluginId {
        self.id
    }

    fn name(&self) -> &'static str {
        SUBJECT_PLUGIN
    }

    fn capability(&self) -> Capability {
        Capability {
            owned_event_types: vec![self.event_type.clone()],
            owned_entity_kinds: Vec::new(),
            has_driver: true,
            has_reducer: false,
        }
    }
}

/// The frozen subject's one Driver: the drafts of each Tick, or the typed
/// failure at its Tick.
struct ScriptDriver {
    script: ScriptV1,
    tick: u64,
}

impl Driver for ScriptDriver {
    fn name(&self) -> &'static str {
        SUBJECT_PLUGIN
    }

    fn step(&mut self, _: TimelineId, _: ObservationView<'_>) -> Result<StepOutput, RuntimeError> {
        self.tick += 1;
        let failed = self
            .script
            .failure
            .as_ref()
            .filter(|(tick, _)| *tick == self.tick);
        failed.map_or_else(
            || {
                let drafts = usize::try_from(self.tick - 1)
                    .ok()
                    .and_then(|index| self.script.drafts.get(index))
                    .map_or_else(Vec::new, |drafts| {
                        drafts
                            .iter()
                            .map(|payload| {
                                EventDraft::new(
                                    self.script.entity,
                                    Kind::new(self.script.event_type.clone()),
                                    CanonicalBytes::from_vec(payload.clone()),
                                )
                            })
                            .collect()
                    });
                Ok(StepOutput::new(drafts))
            },
            |(_, reason)| {
                Err(RuntimeError::CapabilityMismatch {
                    name: SUBJECT_PLUGIN.to_owned(),
                    reason: reason.clone(),
                })
            },
        )
    }
}

impl RecomputationSubjectV1 for ScriptV1 {
    fn compose(
        &self,
        experiment: &mut Experiment,
        _profile: &ExecutionProfileV1,
    ) -> Result<(), RuntimeError> {
        experiment.register_generated(
            &SubjectPlugin {
                id: PluginId::new(),
                event_type: Kind::new(self.event_type.clone()),
            },
            None,
            Some(Box::new(ScriptDriver {
                script: self.clone(),
                tick: 0,
            })),
        )
    }
}

/// Run one sub-case: one leg per profile. `None` is an operational host or
/// codec failure.
pub(super) fn run_subcase(
    host: &HostV1,
    subcase: &SubCaseV1,
    fixture_digest: [u8; 32],
    store_config: &StoreConfig,
) -> Option<RecordV1> {
    let requests: Vec<LegRequestV1> = subcase
        .profiles
        .iter()
        .map(|profile| host.request(&subcase.manifest, subcase.class, *profile))
        .collect();
    let licence = subcase.licence.as_deref();
    let outcomes: Option<Vec<VerificationExecutionOutcomeV1>> = match &subcase.closure {
        ClosureV1::Recorded { export, evaluation } => execute_recorded_replay_v1(
            RecordedReplayInputV1 {
                preflight: requests[0].preflight(),
                closure: RecordedReplayClosureV1 {
                    timeline_export: export.as_ref().map(|(export, digest)| {
                        ExportedTimelineMemberV1 {
                            export,
                            artifact_digest: ErasureReferenceV1::from_digest(*digest),
                        }
                    }),
                    licence,
                },
                replay_claim_evaluation: evaluation,
                expected: &subcase.expected,
                fixture_digest: Some(fixture_digest),
            },
            &mut projections(),
        )
        .ok()
        .map(|outcome| vec![outcome]),
        ClosureV1::Recomputed { subject, ticks } => {
            let closure = RecomputationClosureV1 {
                subject: subject
                    .as_ref()
                    .map(|(subject, digest)| RecomputationSubjectMemberV1 {
                        subject,
                        artifact_digest: *digest,
                        ticks: *ticks,
                    }),
                licence,
            };
            if subcase.class == ReproducibilityClassV1::CrossProfileConformance {
                execute_cross_profile_conformance_v1(
                    CrossProfileConformanceInputV1 {
                        local: requests[0].preflight(),
                        air_gapped: requests[1].preflight(),
                        closure,
                        expected: &subcase.expected,
                        fixture_digest: Some(fixture_digest),
                        store_config: store_config.clone(),
                    },
                    &mut projections(),
                )
                .ok()
                .map(|outcome| vec![outcome.local, outcome.air_gapped])
            } else {
                execute_profile_recomputation_v1(
                    ProfileRecomputationInputV1 {
                        preflight: requests[0].preflight(),
                        closure,
                        expected: &subcase.expected,
                        fixture_digest: Some(fixture_digest),
                        store_config: store_config.clone(),
                    },
                    &mut projections(),
                )
                .ok()
                .map(|outcome| vec![outcome])
            }
        }
    };
    outcomes.map(|outcomes| RecordV1 {
        id: subcase.id.clone(),
        fixture_id: subcase.fixture_id.clone(),
        legs: subcase
            .profiles
            .iter()
            .zip(&outcomes)
            .map(|(profile, outcome)| leg(*profile, outcome))
            .collect(),
    })
}

/// The leg record of one `VRR1` (and its `DVR1`), with the names of the
/// closed `VRR1` and `DVR1` vocabularies.
fn leg(profile: ProfileV1, outcome: &VerificationExecutionOutcomeV1) -> LegV1 {
    let result = &outcome.result;
    LegV1 {
        profile: profile.id().to_owned(),
        outcome: format!("{:?}", result.verification_outcome),
        replay_claim: format!("{:?}", result.replay_claim),
        authoritative_result_digest: result
            .authoritative_result_digest
            .map(|digest| hex(&digest)),
        first_error: result.first_error.as_ref().map(|error| FirstErrorV1 {
            code: format!("{:?}", error.code),
            coordinate: error
                .canonical_coordinate
                .as_ref()
                .map(|coordinate| String::from_utf8_lossy(coordinate).into_owned()),
        }),
        divergence: outcome.divergence.as_ref().map(|report| DivergenceV1 {
            location: format!("{:?}", report.location_kind),
            mismatch: format!("{:?}", report.mismatch_kind),
            timeline: hex(&report.timeline_or_worldcut_id),
            seq: report.timeline_seq_or_cut_ordinal,
            expected: digest_size(&report.expected),
            actual: digest_size(&report.actual),
        }),
    }
}

fn digest_size(value: &DigestSizeV1) -> DigestSizeRecordV1 {
    DigestSizeRecordV1 {
        digest: value.digest.map(|digest| hex(&digest)),
        size: value.size,
    }
}
