//! The replay-conformance case payload of provider contract 2.0.0 and its
//! `RCS1` composite.
//!
//! The payload is RFC 8785 JSON (`pigloros.replay-conformance.case.v2`):
//! `{"schema", "family", "subcases": [...]}` with one to sixteen sub-cases.
//! Each sub-case names its reproducibility class, its EPF1 (two for a
//! `CrossProfileConformance` run, Local first, else one), the manifest fields
//! the fixture owns, its closure members by BLAKE3 digest, the ADR-060
//! evaluation of a recorded export, the frozen number of Ticks of a
//! recomputation, the expected authoritative stream and the expected legs.
//! The closure members are the entries of the `RCS1` composite,
//! `["RCS1", 1, [[digest32, bytes], ...]]`, each addressed by the BLAKE3 of
//! its bytes. An exported Timeline is the `ciborium` serde form of
//! `TimelineExport`; a recomputation subject is the JSON document
//! `pigloros.replay-conformance.subject.v1`.

use std::collections::BTreeMap;

use pos_conformance::{ReplayClaimV1, ReproducibilityClassV1};
use pos_core::{
    ArtifactClaimInputV1, ArtifactDataClassV1, ArtifactOptionalityV1, ArtifactStateV1,
    ArtifactTransitionRuleV1, EntityId, ErasureArtifactClassV1, ErasureReferenceV1,
    ErasureReplayClaimV1, RegisteredArtifactV1, ReplayClaimEvaluationV1, ReplayClaimEvaluatorV1,
    TimelineExport,
};
use pos_reference::evaluator::AttemptArtifact;
use serde::{Deserialize, Serialize};

use crate::authoritative_comparison::{
    AuthoritativeStreamV1, CheckpointDigestV1, ComparedDriverOutputV1, ComparedEventV1,
    DriverOutcomeV1, DriverOutputCoordinateV1, TickBoundaryCoordinateV1, TimelinePositionV1,
};
use crate::profile_recomputation::HOST_FAILURE_DRIVER_ID_V1;

/// The `schema` string of a case payload.
pub const SCHEMA_ID: &str = "pigloros.replay-conformance.case.v2";
/// The `schema` string of a recomputation subject member.
const SUBJECT_SCHEMA_ID: &str = "pigloros.replay-conformance.subject.v1";
/// The magic of the closure-member composite.
const COMPOSITE_MAGIC: &str = "RCS1";
/// The largest number of sub-cases one payload holds.
const MAX_SUBCASES: usize = 16;
/// The owner reference of the ADR-060 registration of a recorded export.
const EXPORT_OWNER_LABEL: &[u8] = b"PiglorOS.ReplayConformance.ExportOwner.v1";

/// The EPF1 a leg runs under.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
pub(super) enum ProfileV1 {
    #[serde(rename = "deterministic-local-v1")]
    Local,
    #[serde(rename = "deterministic-air-gapped-v1")]
    AirGapped,
    #[serde(rename = "replay-v1")]
    Replay,
    #[serde(rename = "live-local-v1")]
    Live,
}

impl ProfileV1 {
    /// The EPF1 profile id.
    pub(super) const fn id(self) -> &'static str {
        match self {
            Self::Local => "deterministic-local-v1",
            Self::AirGapped => "deterministic-air-gapped-v1",
            Self::Replay => "replay-v1",
            Self::Live => "live-local-v1",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
enum ClassV1 {
    RecordedReplay,
    ProfileRecomputation,
    CrossProfileConformance,
    LiveUnverified,
}

impl ClassV1 {
    const fn class(self) -> ReproducibilityClassV1 {
        match self {
            Self::RecordedReplay => ReproducibilityClassV1::RecordedReplay,
            Self::ProfileRecomputation => ReproducibilityClassV1::ProfileRecomputation,
            Self::CrossProfileConformance => ReproducibilityClassV1::CrossProfileConformance,
            Self::LiveUnverified => ReproducibilityClassV1::LiveUnverified,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize)]
enum ClaimV1 {
    Exact,
    ExactAuthoritativeWithRedactedViews,
    StructuralOnly,
    UnverifiableArtifactsMissing,
    IncompatibleProfile,
}

impl ClaimV1 {
    const fn claim(self) -> ReplayClaimV1 {
        match self {
            Self::Exact => ReplayClaimV1::Exact,
            Self::ExactAuthoritativeWithRedactedViews => {
                ReplayClaimV1::ExactAuthoritativeWithRedactedViews
            }
            Self::StructuralOnly => ReplayClaimV1::StructuralOnly,
            Self::UnverifiableArtifactsMissing => ReplayClaimV1::UnverifiableArtifactsMissing,
            Self::IncompatibleProfile => ReplayClaimV1::IncompatibleProfile,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize)]
enum RuleV1 {
    PreserveExact,
    RedactViews,
}

#[derive(Clone, Copy, Debug, Deserialize)]
enum StateV1 {
    Retained,
    TransitionApplied,
}

/// One leg of a sub-case: what one profile run reports, with names from the
/// closed `VRR1` and `DVR1` vocabularies.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct LegV1 {
    pub(super) profile: String,
    pub(super) outcome: String,
    pub(super) replay_claim: String,
    pub(super) authoritative_result_digest: Option<String>,
    pub(super) first_error: Option<FirstErrorV1>,
    pub(super) divergence: Option<DivergenceV1>,
}

/// The first error of a refused leg.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct FirstErrorV1 {
    pub(super) code: String,
    pub(super) coordinate: Option<String>,
}

/// The first divergence of a diverged leg.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct DivergenceV1 {
    pub(super) location: String,
    pub(super) mismatch: String,
    pub(super) timeline: String,
    pub(super) seq: u64,
    pub(super) expected: DigestSizeV1,
    pub(super) actual: DigestSizeV1,
}

/// A digest and size pair of a `DVR1`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct DigestSizeV1 {
    pub(super) digest: Option<String>,
    pub(super) size: Option<u64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PayloadV1 {
    schema: String,
    family: String,
    subcases: Vec<SubCaseTextV1>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SubCaseTextV1 {
    id: String,
    fixture_id: Option<String>,
    #[serde(rename = "title")]
    _title: String,
    class: ClassV1,
    profiles: Vec<ProfileV1>,
    manifest: ManifestTextV1,
    closure: ClosureTextV1,
    export_evaluation: Option<EvaluationTextV1>,
    ticks: Option<u64>,
    expected_stream: StreamTextV1,
    expect: Vec<LegV1>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ManifestTextV1 {
    format_version: u32,
    seed: u64,
    resource_limit: u64,
    network_enabled: bool,
    replay_claim: ClaimV1,
    input_digest: String,
    artifact_closure_digest: String,
    evaluator_digest: String,
    scenario_room_digest: String,
    scheduler_digest: String,
    budget_digest: String,
    request_digest: String,
    report_bytes_limit: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ClosureTextV1 {
    primary: Option<String>,
    licence: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EvaluationTextV1 {
    rule: RuleV1,
    state: StateV1,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StreamTextV1 {
    timeline: String,
    events: Vec<StreamEventTextV1>,
    checkpoint: CheckpointTextV1,
    failure: Option<FailureTextV1>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StreamEventTextV1 {
    seq: u64,
    identity: String,
    schema: String,
    payload: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CheckpointTextV1 {
    fold_cursor: u64,
    digest: String,
    size: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FailureTextV1 {
    fold_cursor: u64,
    bytes: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SubjectTextV1 {
    schema: String,
    entity: String,
    event_type: String,
    drafts: Vec<Vec<String>>,
    failure: Option<SubjectFailureTextV1>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SubjectFailureTextV1 {
    tick: u64,
    reason: String,
}

#[derive(Deserialize)]
struct CompositeV1(
    String,
    u8,
    Vec<(serde_bytes::ByteBuf, serde_bytes::ByteBuf)>,
);

/// The manifest fields the fixture owns; the host binds the EPF1 and TPS1
/// digests, the class and the execution mode.
#[derive(Clone, Copy, Debug)]
pub(super) struct ManifestFieldsV1 {
    pub(super) format_version: u32,
    pub(super) seed: u64,
    pub(super) resource_limit: u64,
    pub(super) network_enabled: bool,
    pub(super) replay_claim: ReplayClaimV1,
    pub(super) input_digest: [u8; 32],
    pub(super) artifact_closure_digest: [u8; 32],
    pub(super) evaluator_digest: [u8; 32],
    pub(super) scenario_room_digest: [u8; 32],
    pub(super) scheduler_digest: [u8; 32],
    pub(super) budget_digest: [u8; 32],
    pub(super) request_digest: [u8; 32],
    pub(super) report_bytes_limit: u64,
}

/// A frozen recomputation subject: the drafts its one Driver emits at each
/// Tick and an optional typed failure at one Tick.
#[derive(Clone, Debug)]
pub(super) struct ScriptV1 {
    pub(super) entity: EntityId,
    pub(super) event_type: String,
    pub(super) drafts: Vec<Vec<Vec<u8>>>,
    pub(super) failure: Option<(u64, String)>,
}

/// The closure of one sub-case, by class.
pub(super) enum ClosureV1 {
    /// A `RecordedReplay` closure and the ADR-060 evaluation of its export.
    Recorded {
        export: Option<(TimelineExport, [u8; 32])>,
        evaluation: ReplayClaimEvaluationV1,
    },
    /// A recomputation closure and the frozen number of Ticks.
    Recomputed {
        subject: Option<(ScriptV1, [u8; 32])>,
        ticks: u64,
    },
}

/// One sub-case, resolved against its composite.
pub(super) struct SubCaseV1 {
    pub(super) id: String,
    pub(super) fixture_id: Option<String>,
    pub(super) class: ReproducibilityClassV1,
    pub(super) profiles: Vec<ProfileV1>,
    pub(super) manifest: ManifestFieldsV1,
    pub(super) closure: ClosureV1,
    pub(super) licence: Option<Vec<u8>>,
    pub(super) expected: AuthoritativeStreamV1,
    pub(super) expect: Vec<LegV1>,
}

/// The closure members of one attempt, by BLAKE3 digest.
pub(super) type MembersV1 = BTreeMap<[u8; 32], Vec<u8>>;

/// Find the `RCS1` composite among the auxiliary members: the first member
/// that decodes as one with the right magic and version, whose entries are in
/// strictly increasing digest order and whose every entry is addressed by the
/// BLAKE3 of its bytes.
pub(super) fn find_composite(auxiliary: &[AttemptArtifact]) -> Option<MembersV1> {
    auxiliary.iter().find_map(|member| {
        ciborium::from_reader::<CompositeV1, _>(member.bytes.as_slice())
            .ok()
            .filter(|CompositeV1(magic, version, entries)| {
                magic == COMPOSITE_MAGIC
                    && *version == 1
                    && entries.windows(2).all(|pair| pair[0].0 < pair[1].0)
                    && entries
                        .iter()
                        .all(|(digest, bytes)| digest.as_slice() == blake3::hash(bytes).as_bytes())
            })
            .and_then(|CompositeV1(_, _, entries)| {
                entries
                    .into_iter()
                    .map(|(digest, bytes)| {
                        <[u8; 32]>::try_from(digest.into_vec())
                            .ok()
                            .map(|digest| (digest, bytes.into_vec()))
                    })
                    .collect()
            })
    })
}

/// Parse the payload of `family_text` against the members of its composite.
/// `None` is a payload that violates the grammar.
pub(super) fn parse(
    payload: &[u8],
    family_text: &str,
    members: &MembersV1,
) -> Option<Vec<SubCaseV1>> {
    serde_json::from_slice::<PayloadV1>(payload)
        .ok()
        .filter(|payload| {
            payload.schema == SCHEMA_ID
                && payload.family == family_text
                && (1..=MAX_SUBCASES).contains(&payload.subcases.len())
        })
        .and_then(|payload| {
            payload
                .subcases
                .into_iter()
                .map(|subcase| resolve(subcase, members))
                .collect()
        })
}

fn resolve(text: SubCaseTextV1, members: &MembersV1) -> Option<SubCaseV1> {
    let legs = if text.class == ClassV1::CrossProfileConformance {
        2
    } else {
        1
    };
    let licence = member(text.closure.licence.as_deref(), members).ok();
    let closure = closure(&text, members);
    let manifest = manifest(&text.manifest);
    let expected = stream(&text.expected_stream);
    (text.profiles.len() == legs)
        .then_some((licence, closure, manifest, expected))
        .and_then(|(licence, closure, manifest, expected)| {
            licence.zip(closure).zip(manifest).zip(expected).map(
                |(((licence, closure), manifest), expected)| SubCaseV1 {
                    id: text.id,
                    fixture_id: text.fixture_id,
                    class: text.class.class(),
                    profiles: text.profiles,
                    manifest,
                    closure,
                    licence: licence.map(<[u8]>::to_vec),
                    expected,
                    expect: text.expect,
                },
            )
        })
}

/// A member reference that is not a digest of the composite.
struct UnknownMemberV1;

/// The member `reference` names: `Ok(None)` when there is no reference.
fn member<'a>(
    reference: Option<&str>,
    members: &'a MembersV1,
) -> Result<Option<&'a [u8]>, UnknownMemberV1> {
    reference.map_or(Ok(None), |reference| {
        digest32(reference)
            .and_then(|digest| members.get(&digest))
            .map(|bytes| Some(bytes.as_slice()))
            .ok_or(UnknownMemberV1)
    })
}

fn closure(text: &SubCaseTextV1, members: &MembersV1) -> Option<ClosureV1> {
    let primary = member(text.closure.primary.as_deref(), members).ok();
    match (text.class, &text.export_evaluation, text.ticks) {
        (ClassV1::RecordedReplay, Some(evaluation), None) => primary.and_then(|primary| {
            let digest = primary.map_or([0; 32], |bytes| *blake3::hash(bytes).as_bytes());
            let export = primary.map(|bytes| {
                ciborium::from_reader::<TimelineExport, _>(bytes)
                    .ok()
                    .map(|export| (export, digest))
            });
            export_evaluation(evaluation, digest)
                .zip(export.map_or(Some(None), |export| export.map(Some)))
                .map(|(evaluation, export)| ClosureV1::Recorded { export, evaluation })
        }),
        (
            ClassV1::ProfileRecomputation
            | ClassV1::CrossProfileConformance
            | ClassV1::LiveUnverified,
            None,
            Some(ticks),
        ) => primary.and_then(|primary| {
            let subject = primary.map(|bytes| {
                subject(bytes).map(|script| (script, *blake3::hash(bytes).as_bytes()))
            });
            subject
                .map_or(Some(None), |subject| subject.map(Some))
                .map(|subject| ClosureV1::Recomputed { subject, ticks })
        }),
        // A recorded export needs its ADR-060 evaluation and has no Ticks; a
        // recomputation has Ticks and no export evaluation.
        (ClassV1::RecordedReplay, None, _)
        | (ClassV1::RecordedReplay, Some(_), Some(_))
        | (
            ClassV1::ProfileRecomputation
            | ClassV1::CrossProfileConformance
            | ClassV1::LiveUnverified,
            Some(_),
            _,
        )
        | (
            ClassV1::ProfileRecomputation
            | ClassV1::CrossProfileConformance
            | ClassV1::LiveUnverified,
            None,
            None,
        ) => None,
    }
}

/// The host-owned ADR-060 evaluation of an export registered under `digest`.
fn export_evaluation(text: &EvaluationTextV1, digest: [u8; 32]) -> Option<ReplayClaimEvaluationV1> {
    let rule = match text.rule {
        RuleV1::PreserveExact => ArtifactTransitionRuleV1::PreserveExact,
        RuleV1::RedactViews => ArtifactTransitionRuleV1::RedactViews,
    };
    let state = match text.state {
        StateV1::Retained => ArtifactStateV1::Retained,
        StateV1::TransitionApplied => ArtifactStateV1::TransitionApplied,
    };
    ReplayClaimEvaluatorV1::evaluate(
        ErasureReplayClaimV1::Exact,
        &[ArtifactClaimInputV1 {
            registration: RegisteredArtifactV1::new(
                ErasureArtifactClassV1::Export,
                ErasureReferenceV1::from_digest(digest),
                ArtifactDataClassV1::StructuralAuditMetadata,
                None,
                ErasureReferenceV1::from_digest(*blake3::hash(EXPORT_OWNER_LABEL).as_bytes()),
                ArtifactOptionalityV1::Required,
                rule,
            ),
            current_claim: ErasureReplayClaimV1::Exact,
            state,
        }],
    )
    .ok()
}

fn subject(bytes: &[u8]) -> Option<ScriptV1> {
    serde_json::from_slice::<SubjectTextV1>(bytes)
        .ok()
        .filter(|text| text.schema == SUBJECT_SCHEMA_ID)
        .and_then(|text| {
            let entity = ulid::Ulid::from_string(&text.entity)
                .ok()
                .map(EntityId::from_ulid);
            let drafts: Option<Vec<Vec<Vec<u8>>>> = text
                .drafts
                .iter()
                .map(|tick| tick.iter().map(|payload| hex_bytes(payload)).collect())
                .collect();
            entity.zip(drafts).map(|(entity, drafts)| ScriptV1 {
                entity,
                event_type: text.event_type,
                drafts,
                failure: text.failure.map(|failure| (failure.tick, failure.reason)),
            })
        })
}

fn manifest(text: &ManifestTextV1) -> Option<ManifestFieldsV1> {
    let digests: Option<Vec<[u8; 32]>> = [
        &text.input_digest,
        &text.artifact_closure_digest,
        &text.evaluator_digest,
        &text.scenario_room_digest,
        &text.scheduler_digest,
        &text.budget_digest,
        &text.request_digest,
    ]
    .into_iter()
    .map(|digest| digest32(digest))
    .collect();
    digests.map(|digests| ManifestFieldsV1 {
        format_version: text.format_version,
        seed: text.seed,
        resource_limit: text.resource_limit,
        network_enabled: text.network_enabled,
        replay_claim: text.replay_claim.claim(),
        input_digest: digests[0],
        artifact_closure_digest: digests[1],
        evaluator_digest: digests[2],
        scenario_room_digest: digests[3],
        scheduler_digest: digests[4],
        budget_digest: digests[5],
        request_digest: digests[6],
        report_bytes_limit: text.report_bytes_limit,
    })
}

/// The expected stream: every Event and the checkpoint at tick 0, and the
/// typed failure, if any, at the host coordinate of slice R3.
fn stream(text: &StreamTextV1) -> Option<AuthoritativeStreamV1> {
    let timeline = hex_bytes(&text.timeline).and_then(|bytes| <[u8; 16]>::try_from(bytes).ok());
    timeline.and_then(|timeline_id| {
        let events: Option<BTreeMap<TimelinePositionV1, ComparedEventV1>> = text
            .events
            .iter()
            .map(|event| {
                digest32(&event.identity)
                    .zip(digest32(&event.schema))
                    .zip(hex_bytes(&event.payload))
                    .map(|((identity, schema), payload)| {
                        (
                            TimelinePositionV1 {
                                timeline_id,
                                seq: event.seq,
                            },
                            ComparedEventV1 {
                                tick: 0,
                                identity,
                                schema,
                                payload,
                            },
                        )
                    })
            })
            .collect();
        let checkpoint = digest32(&text.checkpoint.digest).map(|digest| {
            (
                TickBoundaryCoordinateV1 {
                    timeline_id,
                    fold_cursor: text.checkpoint.fold_cursor,
                    tick: 0,
                },
                CheckpointDigestV1 {
                    digest,
                    size: text.checkpoint.size,
                },
            )
        });
        let failure = text.failure.as_ref().map_or(Some(None), |failure| {
            hex_bytes(&failure.bytes).map(|bytes| {
                Some((
                    DriverOutputCoordinateV1 {
                        timeline_id,
                        fold_cursor: failure.fold_cursor,
                        tick: 0,
                        scheduler_position: 0,
                        driver_id: HOST_FAILURE_DRIVER_ID_V1.to_owned(),
                        output_ordinal: 0,
                    },
                    ComparedDriverOutputV1 {
                        outcome: DriverOutcomeV1::TypedFailure(bytes),
                        numeric_profile_digest: [0; 32],
                        prohibited_operational_input: None,
                    },
                ))
            })
        });
        events
            .zip(checkpoint)
            .zip(failure)
            .map(|((events, checkpoint), failure)| AuthoritativeStreamV1 {
                events,
                checkpoints: BTreeMap::from([checkpoint]),
                driver_outputs: failure.into_iter().collect(),
                ..AuthoritativeStreamV1::default()
            })
    })
}

/// Lowercase hexadecimal text to bytes; `None` for any other text.
pub(super) fn hex_bytes(text: &str) -> Option<Vec<u8>> {
    let digits: Option<Vec<u8>> = text
        .bytes()
        .map(|digit| {
            HEX_DIGITS
                .iter()
                .position(|candidate| *candidate == digit)
                .and_then(|value| u8::try_from(value).ok())
        })
        .collect();
    digits
        .filter(|digits| digits.len().is_multiple_of(2))
        .map(|digits| {
            digits
                .chunks_exact(2)
                .map(|pair| pair[0] * 16 + pair[1])
                .collect()
        })
}

fn digest32(text: &str) -> Option<[u8; 32]> {
    hex_bytes(text).and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
}

const HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";

/// Bytes to lowercase hexadecimal text.
pub(super) fn hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .flat_map(|byte| {
            [
                HEX_DIGITS[usize::from(byte >> 4)],
                HEX_DIGITS[usize::from(byte & 0x0f)],
            ]
        })
        .map(char::from)
        .collect()
}

/// The canonical-output record of a family whose oracle is an output.
pub(super) fn output_record(case_id: &str, family_text: &str, subcases: &[RecordV1]) -> Vec<u8> {
    let mut bytes = serde_json::to_vec(&serde_json::json!({
        "case_id": case_id,
        "claim_layer": "replay-conformance",
        "family": family_text,
        "oracle": {"kind": "canonical-output"},
        "output": {"subcases": subcases},
    }))
    .unwrap_or_default();
    bytes.push(b'\n');
    bytes
}

/// What one sub-case observed.
#[derive(Clone, Debug, Serialize)]
pub(super) struct RecordV1 {
    pub(super) id: String,
    pub(super) fixture_id: Option<String>,
    /// The Plugin and Driver a recomputation subject composed; `None` for a
    /// `RecordedReplay` or a missing subject.
    pub(super) composition: Option<CompositionV1>,
    pub(super) legs: Vec<LegV1>,
    /// The Events the sub-case folded; metered, not part of the record.
    #[serde(skip)]
    pub(super) folded_events: u64,
}

/// The names of the Plugin and Driver one recomputation subject composed.
#[derive(Clone, Debug, Serialize)]
pub(super) struct CompositionV1 {
    pub(super) plugin: String,
    pub(super) driver: String,
}
