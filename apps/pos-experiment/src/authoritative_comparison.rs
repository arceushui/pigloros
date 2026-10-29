//! First-divergence comparison of authoritative streams to one `DVR1`.
//!
//! ADR-062 Revision 8 slice R1 (#1218). [`first_divergence_v1`] compares an
//! expected and an actual [`AuthoritativeStreamV1`]. It is a pure function:
//! it returns `None` when the streams agree, or exactly one
//! [`DivergenceReportV1`] at the first mismatch. It leaves the coarse
//! `pos_conformance::compare` and `compare_authoritative_outputs` unchanged.
//!
//! # Comparison order
//!
//! Every mismatch has the rank `(location kind, coordinate, mismatch kind)`
//! and the lowest rank is reported:
//!
//! 1. Location kind in [`DivergenceLocationKindV1`] declaration order:
//!    `TimelineSeq`, `WorldCut`, `TickBoundary`, `Scheduler`, `DriverOutput`.
//! 2. Coordinate in `DVR1` field order: Timeline or `WorldCut` id, Timeline
//!    sequence or cut ordinal, tick, scheduler position, Driver or Plugin id,
//!    output ordinal. An absent optional field sorts first.
//! 3. Mismatch kind in [`DivergenceMismatchKindV1`] declaration order.
//!
//! Every other mismatch adds one to the follow-on count of its kind; a count
//! saturates at [`MAX_FOLLOW_ON_COUNT_V1`].
//!
//! # Streams and mismatch kinds
//!
//! | Stream | Location kind | Mismatch kinds |
//! |---|---|---|
//! | Events in Timeline Order | `TimelineSeq` | `EventIdentity`, `EventOrder`, `CanonicalBytes`, `SchemaOrUpcaster` |
//! | ADR-064 artifacts | `WorldCut` | `Artifact` |
//! | Projection checkpoints | `TickBoundary` | `ProjectionCheckpoint` |
//! | Driver order | `Scheduler` | `EventOrder` |
//! | Driver or Plugin outputs | `DriverOutput` | `CanonicalBytes`, `TypedFailure`, `NumericProfile`, `ProhibitedOperationalInput` |
//!
//! An Event present in one stream only is an `EventIdentity` mismatch. An
//! Event whose identity differs is an `EventOrder` mismatch when either
//! identity occurs elsewhere in the other stream, and an `EventIdentity`
//! mismatch otherwise; an Event at another tick is an `EventOrder` mismatch.
//! A missing Driver output is a `CanonicalBytes` or `TypedFailure` mismatch
//! by the outcome that is present.
//!
//! # Redaction
//!
//! Payload bytes are reduced to their BLAKE3 digest and byte size; identities
//! and checkpoints are reported by digest. No payload byte enters a report.
//! Operational fields (paths, wall-clock times, rendering frames, logs) have
//! no field in a stream, so they can never cause a divergence.
//!
//! The prior matching checkpoint is the last checkpoint of the longest equal
//! checkpoint prefix whose tick is before the reported tick.

use std::collections::{BTreeMap, BTreeSet};

use pos_conformance::{
    DigestSizeV1, DivergenceLocationKindV1, DivergenceMismatchKindV1, DivergenceReportV1,
    FollowOnMismatchV1, ReplayClaimV1, ReproducibilityClassV1,
};
use pos_core::CoreError;

/// The largest follow-on count a report carries for one mismatch kind.
pub const MAX_FOLLOW_ON_COUNT_V1: u32 = 65_535;

/// Identity fields copied into every report.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DivergenceContextV1 {
    /// Digest of the verification request.
    pub request_digest: [u8; 32],
    /// Digest of the `ReproManifest`.
    pub manifest_digest: [u8; 32],
    /// Digest of the `ExecutionProfile`.
    pub execution_profile_digest: [u8; 32],
    /// Digest of the fixture, when the run has one.
    pub fixture_digest: Option<[u8; 32]>,
    /// Digest of the evaluator.
    pub evaluator_digest: [u8; 32],
    /// Reproducibility class of the run.
    pub reproducibility_class: ReproducibilityClassV1,
    /// ADR-060 `ReplayClaim` of the run.
    pub replay_claim: ReplayClaimV1,
}

/// The authoritative output of one run, keyed by canonical coordinate.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AuthoritativeStreamV1 {
    /// Events in Timeline Order.
    pub events: BTreeMap<TimelinePositionV1, ComparedEventV1>,
    /// Canonical bytes of each ADR-064 artifact exported at a `WorldCut`.
    pub world_cut_artifacts: BTreeMap<WorldCutArtifactCoordinateV1, Vec<u8>>,
    /// Projection checkpoint digests at Tick Boundaries.
    pub checkpoints: BTreeMap<TickBoundaryCoordinateV1, CheckpointDigestV1>,
    /// Driver id at each scheduler position.
    pub scheduler: BTreeMap<SchedulerSlotV1, String>,
    /// Driver or Plugin outputs and typed failures.
    pub driver_outputs: BTreeMap<DriverOutputCoordinateV1, ComparedDriverOutputV1>,
}

/// One logical position in Timeline Order.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct TimelinePositionV1 {
    /// Timeline id.
    pub timeline_id: [u8; 16],
    /// Logical Timeline sequence.
    pub seq: u64,
}

/// One authoritative Event at a Timeline position.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ComparedEventV1 {
    /// Tick whose Tick Boundary committed the Event.
    pub tick: u64,
    /// Digest of the Event identity (id, entity and Event type).
    pub identity: [u8; 32],
    /// Digest of the payload schema and upcaster chain.
    pub schema: [u8; 32],
    /// Canonical payload bytes; only their digest and size are reported.
    pub payload: Vec<u8>,
}

/// Coordinate of one ADR-064 artifact exported at a `WorldCut`.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct WorldCutArtifactCoordinateV1 {
    /// `WorldCut` id.
    pub world_cut_id: [u8; 16],
    /// Ordinal of the cut.
    pub cut_ordinal: u64,
    /// Tick of the cut.
    pub tick: u64,
    /// Ordinal of the artifact among the cut's exported artifacts.
    pub artifact_ordinal: u32,
}

/// Coordinate of one Projection checkpoint.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct TickBoundaryCoordinateV1 {
    /// Timeline id.
    pub timeline_id: [u8; 16],
    /// Fold Cursor of the checkpoint.
    pub fold_cursor: u64,
    /// Tick of the Tick Boundary.
    pub tick: u64,
}

/// Digest and canonical size of one Projection checkpoint.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct CheckpointDigestV1 {
    /// Checkpoint digest.
    pub digest: [u8; 32],
    /// Canonical checkpoint size in bytes.
    pub size: u64,
}

/// One scheduler position of an atomic Driver step.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SchedulerSlotV1 {
    /// Timeline id.
    pub timeline_id: [u8; 16],
    /// Fold Cursor at the pre-step Tick Boundary.
    pub fold_cursor: u64,
    /// Tick of the step.
    pub tick: u64,
    /// Position in the step's Driver order.
    pub position: u32,
}

/// Coordinate of one Driver or Plugin output.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct DriverOutputCoordinateV1 {
    /// Timeline id.
    pub timeline_id: [u8; 16],
    /// Fold Cursor at the pre-step Tick Boundary.
    pub fold_cursor: u64,
    /// Tick of the step.
    pub tick: u64,
    /// Scheduler position of the Driver.
    pub scheduler_position: u32,
    /// Driver or Plugin id.
    pub driver_id: String,
    /// Ordinal of the output within the Driver step.
    pub output_ordinal: u32,
}

/// The outcome of one Driver or Plugin output.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DriverOutcomeV1 {
    /// Canonical output bytes.
    Output(Vec<u8>),
    /// Canonical bytes of a typed failure.
    TypedFailure(Vec<u8>),
}

/// One Driver or Plugin output with its numeric profile and inputs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ComparedDriverOutputV1 {
    /// Output or typed failure.
    pub outcome: DriverOutcomeV1,
    /// Digest of the numeric and architecture profile the output used.
    pub numeric_profile_digest: [u8; 32],
    /// Host record of a prohibited operational input the output consumed.
    pub prohibited_operational_input: Option<Vec<u8>>,
}

/// Compare two authoritative streams and report the first divergence.
///
/// Returns `Ok(None)` when the streams agree. Otherwise returns exactly one
/// sealed [`DivergenceReportV1`] that has passed the `DVR1` validator.
///
/// # Errors
/// Returns the `DVR1` codec error when the first mismatch has a coordinate
/// the closed `DVR1` shape rejects, such as a Driver id longer than 128 bytes
/// or a scheduler position above `u16::MAX`.
pub fn first_divergence_v1(
    context: &DivergenceContextV1,
    expected: &AuthoritativeStreamV1,
    actual: &AuthoritativeStreamV1,
) -> Result<Option<DivergenceReportV1>, CoreError> {
    let mut findings = Findings::default();
    findings.compare_events(&expected.events, &actual.events);
    findings.compare_whole(
        DivergenceLocationKindV1::WorldCut,
        DivergenceMismatchKindV1::Artifact,
        (&expected.world_cut_artifacts, &actual.world_cut_artifacts),
        |key, _| key.coordinate(),
        |bytes| bytes_digest(bytes),
    );
    findings.compare_whole(
        DivergenceLocationKindV1::TickBoundary,
        DivergenceMismatchKindV1::ProjectionCheckpoint,
        (&expected.checkpoints, &actual.checkpoints),
        |key, _| key.coordinate(),
        CheckpointDigestV1::digest_size,
    );
    findings.compare_whole(
        DivergenceLocationKindV1::Scheduler,
        DivergenceMismatchKindV1::EventOrder,
        (&expected.scheduler, &actual.scheduler),
        |slot, driver| slot.coordinate(driver),
        |driver| bytes_digest(driver.as_bytes()),
    );
    findings.compare_driver_outputs(&expected.driver_outputs, &actual.driver_outputs);
    findings
        .into_report(context, (&expected.checkpoints, &actual.checkpoints))
        .transpose()
}

impl TimelinePositionV1 {
    const fn coordinate(&self, tick: u64) -> Coordinate {
        Coordinate {
            id: self.timeline_id,
            seq_or_ordinal: self.seq,
            tick,
            scheduler_position: None,
            driver_or_plugin_id: None,
            output_ordinal: None,
        }
    }
}

impl WorldCutArtifactCoordinateV1 {
    const fn coordinate(&self) -> Coordinate {
        Coordinate {
            id: self.world_cut_id,
            seq_or_ordinal: self.cut_ordinal,
            tick: self.tick,
            scheduler_position: None,
            driver_or_plugin_id: None,
            output_ordinal: Some(self.artifact_ordinal),
        }
    }
}

impl TickBoundaryCoordinateV1 {
    const fn coordinate(&self) -> Coordinate {
        Coordinate {
            id: self.timeline_id,
            seq_or_ordinal: self.fold_cursor,
            tick: self.tick,
            scheduler_position: None,
            driver_or_plugin_id: None,
            output_ordinal: None,
        }
    }
}

impl CheckpointDigestV1 {
    const fn digest_size(&self) -> DigestSizeV1 {
        DigestSizeV1 {
            digest: Some(self.digest),
            size: Some(self.size),
        }
    }
}

impl SchedulerSlotV1 {
    fn coordinate(&self, driver_id: &str) -> Coordinate {
        Coordinate {
            id: self.timeline_id,
            seq_or_ordinal: self.fold_cursor,
            tick: self.tick,
            scheduler_position: Some(self.position),
            driver_or_plugin_id: Some(driver_id.to_owned()),
            output_ordinal: None,
        }
    }
}

impl DriverOutputCoordinateV1 {
    fn coordinate(&self) -> Coordinate {
        Coordinate {
            id: self.timeline_id,
            seq_or_ordinal: self.fold_cursor,
            tick: self.tick,
            scheduler_position: Some(self.scheduler_position),
            driver_or_plugin_id: Some(self.driver_id.clone()),
            output_ordinal: Some(self.output_ordinal),
        }
    }
}

impl DriverOutcomeV1 {
    const fn missing_kind(&self) -> DivergenceMismatchKindV1 {
        match self {
            Self::Output(_) => DivergenceMismatchKindV1::CanonicalBytes,
            Self::TypedFailure(_) => DivergenceMismatchKindV1::TypedFailure,
        }
    }

    fn digest_size(&self) -> DigestSizeV1 {
        match self {
            Self::Output(bytes) | Self::TypedFailure(bytes) => bytes_digest(bytes),
        }
    }
}

/// A `DVR1` coordinate in field order, so the derived order is the rank.
#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
struct Coordinate {
    id: [u8; 16],
    seq_or_ordinal: u64,
    tick: u64,
    scheduler_position: Option<u32>,
    driver_or_plugin_id: Option<String>,
    output_ordinal: Option<u32>,
}

struct Finding {
    location: DivergenceLocationKindV1,
    coordinate: Coordinate,
    kind: DivergenceMismatchKindV1,
    expected: DigestSizeV1,
    actual: DigestSizeV1,
}

impl Finding {
    const fn rank(
        &self,
    ) -> (
        DivergenceLocationKindV1,
        &Coordinate,
        DivergenceMismatchKindV1,
    ) {
        (self.location, &self.coordinate, self.kind)
    }
}

/// The lowest-ranked mismatch and the total count of each mismatch kind.
#[derive(Default)]
struct Findings {
    first: Option<Finding>,
    totals: BTreeMap<DivergenceMismatchKindV1, u64>,
}

/// One coordinate as seen by both streams.
enum Side<'a, V> {
    Both(&'a V, &'a V),
    Missing(Missing<'a, V>),
}

/// A coordinate present in one stream only.
struct Missing<'a, V> {
    present: &'a V,
    in_expected: bool,
}

impl<V> Missing<'_, V> {
    const fn digests(&self, present: DigestSizeV1) -> (DigestSizeV1, DigestSizeV1) {
        if self.in_expected {
            (present, absent())
        } else {
            (absent(), present)
        }
    }
}

fn sides<'a, K: Ord, V>(
    expected: &'a BTreeMap<K, V>,
    actual: &'a BTreeMap<K, V>,
) -> impl Iterator<Item = (&'a K, Side<'a, V>)> {
    let shared_or_expected = expected.iter().map(move |(key, present)| {
        let side = actual.get(key).map_or(
            Side::Missing(Missing {
                present,
                in_expected: true,
            }),
            |other| Side::Both(present, other),
        );
        (key, side)
    });
    let actual_only = actual
        .iter()
        .filter(move |(key, _)| !expected.contains_key(*key))
        .map(|(key, present)| {
            let side = Side::Missing(Missing {
                present,
                in_expected: false,
            });
            (key, side)
        });
    shared_or_expected.chain(actual_only)
}

impl Findings {
    fn record(
        &mut self,
        location: DivergenceLocationKindV1,
        coordinate: &Coordinate,
        kind: DivergenceMismatchKindV1,
        (expected, actual): (DigestSizeV1, DigestSizeV1),
    ) {
        *self.totals.entry(kind).or_default() += 1;
        let finding = Finding {
            location,
            coordinate: coordinate.clone(),
            kind,
            expected,
            actual,
        };
        if self
            .first
            .as_ref()
            .is_none_or(|first| finding.rank() < first.rank())
        {
            self.first = Some(finding);
        }
    }

    fn compare_events(
        &mut self,
        expected: &BTreeMap<TimelinePositionV1, ComparedEventV1>,
        actual: &BTreeMap<TimelinePositionV1, ComparedEventV1>,
    ) {
        let expected_identities: BTreeSet<[u8; 32]> =
            expected.values().map(|event| event.identity).collect();
        let actual_identities: BTreeSet<[u8; 32]> =
            actual.values().map(|event| event.identity).collect();
        let location = DivergenceLocationKindV1::TimelineSeq;
        for (position, side) in sides(expected, actual) {
            match side {
                Side::Both(left, right) => {
                    let coordinate = position.coordinate(left.tick);
                    let identity_kind = if left.identity == right.identity {
                        (left.tick != right.tick).then_some(DivergenceMismatchKindV1::EventOrder)
                    } else if expected_identities.contains(&right.identity)
                        || actual_identities.contains(&left.identity)
                    {
                        Some(DivergenceMismatchKindV1::EventOrder)
                    } else {
                        Some(DivergenceMismatchKindV1::EventIdentity)
                    };
                    if let Some(kind) = identity_kind {
                        let digests = (
                            identity_digest(left.identity),
                            identity_digest(right.identity),
                        );
                        self.record(location, &coordinate, kind, digests);
                    }
                    if left.payload != right.payload {
                        let digests = (bytes_digest(&left.payload), bytes_digest(&right.payload));
                        let kind = DivergenceMismatchKindV1::CanonicalBytes;
                        self.record(location, &coordinate, kind, digests);
                    }
                    if left.schema != right.schema {
                        let digests = (identity_digest(left.schema), identity_digest(right.schema));
                        let kind = DivergenceMismatchKindV1::SchemaOrUpcaster;
                        self.record(location, &coordinate, kind, digests);
                    }
                }
                Side::Missing(missing) => {
                    let coordinate = position.coordinate(missing.present.tick);
                    let digests = missing.digests(identity_digest(missing.present.identity));
                    let kind = DivergenceMismatchKindV1::EventIdentity;
                    self.record(location, &coordinate, kind, digests);
                }
            }
        }
    }

    /// Compare a stream whose entries mismatch as a whole with one kind.
    fn compare_whole<K: Ord, V: PartialEq>(
        &mut self,
        location: DivergenceLocationKindV1,
        kind: DivergenceMismatchKindV1,
        (expected, actual): (&BTreeMap<K, V>, &BTreeMap<K, V>),
        coordinate: impl Fn(&K, &V) -> Coordinate,
        digest: impl Fn(&V) -> DigestSizeV1,
    ) {
        for (key, side) in sides(expected, actual) {
            match side {
                Side::Both(left, right) => {
                    if left != right {
                        let digests = (digest(left), digest(right));
                        self.record(location, &coordinate(key, left), kind, digests);
                    }
                }
                Side::Missing(missing) => {
                    let digests = missing.digests(digest(missing.present));
                    self.record(location, &coordinate(key, missing.present), kind, digests);
                }
            }
        }
    }

    fn compare_driver_outputs(
        &mut self,
        expected: &BTreeMap<DriverOutputCoordinateV1, ComparedDriverOutputV1>,
        actual: &BTreeMap<DriverOutputCoordinateV1, ComparedDriverOutputV1>,
    ) {
        let location = DivergenceLocationKindV1::DriverOutput;
        for (key, side) in sides(expected, actual) {
            let coordinate = key.coordinate();
            match side {
                Side::Both(left, right) => {
                    if left.outcome != right.outcome {
                        let kind = match (&left.outcome, &right.outcome) {
                            (DriverOutcomeV1::Output(_), DriverOutcomeV1::Output(_)) => {
                                DivergenceMismatchKindV1::CanonicalBytes
                            }
                            _ => DivergenceMismatchKindV1::TypedFailure,
                        };
                        let digests = (left.outcome.digest_size(), right.outcome.digest_size());
                        self.record(location, &coordinate, kind, digests);
                    }
                    if left.numeric_profile_digest != right.numeric_profile_digest {
                        let digests = (
                            identity_digest(left.numeric_profile_digest),
                            identity_digest(right.numeric_profile_digest),
                        );
                        let kind = DivergenceMismatchKindV1::NumericProfile;
                        self.record(location, &coordinate, kind, digests);
                    }
                    if left.prohibited_operational_input != right.prohibited_operational_input {
                        let digests = (
                            optional_bytes_digest(left.prohibited_operational_input.as_deref()),
                            optional_bytes_digest(right.prohibited_operational_input.as_deref()),
                        );
                        let kind = DivergenceMismatchKindV1::ProhibitedOperationalInput;
                        self.record(location, &coordinate, kind, digests);
                    }
                }
                Side::Missing(missing) => {
                    let outcome = &missing.present.outcome;
                    let digests = missing.digests(outcome.digest_size());
                    self.record(location, &coordinate, outcome.missing_kind(), digests);
                }
            }
        }
    }

    fn into_report(
        self,
        context: &DivergenceContextV1,
        checkpoints: (
            &BTreeMap<TickBoundaryCoordinateV1, CheckpointDigestV1>,
            &BTreeMap<TickBoundaryCoordinateV1, CheckpointDigestV1>,
        ),
    ) -> Option<Result<DivergenceReportV1, CoreError>> {
        let Self { first, totals } = self;
        first.map(|first| {
            let tick = first.coordinate.tick;
            seal(DivergenceReportV1 {
                request_digest: context.request_digest,
                manifest_digest: context.manifest_digest,
                execution_profile_digest: context.execution_profile_digest,
                fixture_digest: context.fixture_digest,
                evaluator_digest: context.evaluator_digest,
                reproducibility_class: context.reproducibility_class,
                replay_claim: context.replay_claim,
                location_kind: first.location,
                timeline_or_worldcut_id: first.coordinate.id,
                timeline_seq_or_cut_ordinal: first.coordinate.seq_or_ordinal,
                tick,
                scheduler_position: first.coordinate.scheduler_position,
                driver_or_plugin_id: first.coordinate.driver_or_plugin_id,
                output_ordinal: first.coordinate.output_ordinal,
                mismatch_kind: first.kind,
                expected: first.expected,
                actual: first.actual,
                prior_matching_checkpoint_digest: prior_matching_checkpoint(checkpoints, tick),
                follow_on_counts: follow_on_counts(&totals, first.kind),
                report_digest: [0; 32],
            })
        })
    }
}

fn prior_matching_checkpoint(
    (expected, actual): (
        &BTreeMap<TickBoundaryCoordinateV1, CheckpointDigestV1>,
        &BTreeMap<TickBoundaryCoordinateV1, CheckpointDigestV1>,
    ),
    tick: u64,
) -> Option<[u8; 32]> {
    expected
        .iter()
        .zip(actual)
        .take_while(|(left, right)| left == right)
        .filter(|((key, _), _)| key.tick < tick)
        .last()
        .map(|((_, checkpoint), _)| checkpoint.digest)
}

fn follow_on_counts(
    totals: &BTreeMap<DivergenceMismatchKindV1, u64>,
    first: DivergenceMismatchKindV1,
) -> Vec<FollowOnMismatchV1> {
    totals
        .iter()
        .filter_map(|(&kind, &total)| {
            let others = total - u64::from(kind == first);
            u32::try_from(others.min(u64::from(MAX_FOLLOW_ON_COUNT_V1)))
                .ok()
                .filter(|&count| count > 0)
                .map(|count| FollowOnMismatchV1 { kind, count })
        })
        .collect()
}

/// Set the report digest and pass the report through the `DVR1` validator.
fn seal(mut report: DivergenceReportV1) -> Result<DivergenceReportV1, CoreError> {
    report
        .digest()
        .and_then(|digest| {
            report.report_digest = digest;
            report.to_canonical_cbor()
        })
        .and_then(|bytes| DivergenceReportV1::from_canonical_cbor(&bytes))
}

const fn absent() -> DigestSizeV1 {
    DigestSizeV1 {
        digest: None,
        size: None,
    }
}

const fn identity_digest(digest: [u8; 32]) -> DigestSizeV1 {
    DigestSizeV1 {
        digest: Some(digest),
        size: None,
    }
}

fn bytes_digest(bytes: &[u8]) -> DigestSizeV1 {
    DigestSizeV1 {
        digest: Some(*blake3::hash(bytes).as_bytes()),
        size: u64::try_from(bytes.len()).ok(),
    }
}

fn optional_bytes_digest(bytes: Option<&[u8]>) -> DigestSizeV1 {
    bytes.map_or_else(absent, bytes_digest)
}
