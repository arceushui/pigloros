//! The Decision Preview store commands (ADR-140, Redmine #305).
//!
//! Every Event of every preview lives on one root Timeline the host owns,
//! `decision-previews`. It is always found by its derived identity, never by
//! its name, and opened (`open_root_timeline`) only when the first claim
//! commits (ADR-140 P9, P30). A preview is one `preview.request.v1` claim
//! Event, whose ID is the preview ID and whose entity is derived from the
//! claim key (P12), then at most one `preview.result.v1` result Event whose
//! entity is the preview ID (P15). The host has no entity index, so every
//! lookup reads the Timeline once, at most `events_per_timeline` Events.
//!
//! Each `pub(crate)` function runs inside one store command on the store
//! worker, so a lookup and the appends it guards are one serialized step:
//!
//! - [`lookup_claim`] finds the claim of a key (step 5);
//! - [`admit_inputs`] runs the profile gate, the room and the binding
//!   checks of a fresh request (steps 7 to 9);
//! - [`commit_preview`] re-runs the lookup and either finishes an exact
//!   retry (step 6.2) or re-validates, checks the per-minute quota and the
//!   ceiling, opens the Timeline and appends the claim and its result
//!   (step 12);
//! - [`read_preview`] finds a claim by its preview ID and builds the state,
//!   recomputing a computed Recommendation (section 7).
//!
//! The result payload carries no derived value (P16), so the read
//! recomputes the Recommendation from the bound revisions; an erased input
//! leaves a computed preview `degraded` (P25). Every inconsistency the store
//! can show is the closed internal-failure arm (P29), which appends nothing.

use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, Mutex, PoisonError},
    time::{Duration, Instant},
};

use pos_core::{
    store::{EventReadBounds, SeqRange},
    CanonicalBytes, EntityId, ErasureHostErrorV1, Event, EventDraft, EventId, GatewayRevisionKeyV1,
    GatewayRevisionKindV1, GatewayRevisionRecordV1, GatewayRevisionStateV1, Kind, Seq,
};
use pos_runtime::{
    match_score_v1, ErasureExecutionHostV1, PreviewClaimKeyV1, PreviewClaimV1,
    PreviewFailureCodeV1, PreviewOutcomeV1, PreviewRequestV1, PreviewResultV1,
    PreviewRevisionRefV1, RecommendationV1, RoomParticipantKindV1, MAX_PREVIEW_CLAIM_BYTES_V1,
    PREVIEW_REQUEST_EVENT_TYPE_V1, PREVIEW_RESULT_EVENT_TYPE_V1,
};
use tokio::sync::oneshot;
use ulid::Ulid;

use crate::{
    decision_preview::{
        decision_previews_timeline, DecisionPreviewErrorV1, DecisionPreviewModeV1,
        DecisionPreviewResultEventV1, DecisionPreviewStateV1, DecisionPreviewV1,
        DECISION_PREVIEWS_TIMELINE_NAME,
    },
    mode_profile::GatewayModeProfileIdV1,
    scenario_room::revision_provenance_digest_v1,
};

use super::{
    await_command_result, host_error_to_core,
    scenario_room::{descriptor_of, revision_at, room_revisions, RoomStoreErrorV1},
    CommandLifecycle, ExecutorState, ExecutorStore, StoreExecutor, StoreExecutorError,
    WorkerCommandV1,
};

/// The most new claims one Principal commits in one quota window (D11).
pub(crate) const MAX_ADMISSIONS_PER_MINUTE: u32 = 32;
/// The fixed per-minute quota window.
const QUOTA_WINDOW: Duration = Duration::from_mins(1);
/// The domain of the `provenance.digest` of a preview (ADR-140 P24).
const PROVENANCE_DOMAIN: &[u8] = b"PiglorOS.GatewayDecisionPreviewProvenance.v1\0";
/// The `provenance.origin` of every preview.
const ORIGIN: &str = "host-derived";
/// The members of the provenance record.
const PROVENANCE_FIELDS: u64 = 9;
const CBOR_UNSIGNED: u8 = 0;
const CBOR_TEXT: u8 = 3;
const CBOR_ARRAY: u8 = 4;
const CBOR_NULL: u8 = 0xf6;

type PreviewResult<T> = Result<T, DecisionPreviewErrorV1>;

impl From<ErasureHostErrorV1> for DecisionPreviewErrorV1 {
    fn from(error: ErasureHostErrorV1) -> Self {
        Self::Store(host_error_to_core(error))
    }
}

/// The per-Principal fixed-window quota of new claims (ADR-140 step 12.3).
///
/// It is held in memory and checked and counted only inside the commit
/// command, so the count is exact. Exact retries and refused requests are
/// not counted.
#[derive(Debug, Default)]
pub(crate) struct PreviewQuotaV1 {
    windows: HashMap<[u8; 16], (Instant, u32)>,
}

impl PreviewQuotaV1 {
    /// The window of `principal_id` at `now`, opened afresh once it closed.
    fn window(&mut self, principal_id: [u8; 16], now: Instant) -> &mut (Instant, u32) {
        let window = self.windows.entry(principal_id).or_insert((now, 0));
        if now >= window.0 + QUOTA_WINDOW {
            *window = (now, 0);
        }
        window
    }

    /// Whether `principal_id` may commit a new claim at `now`.
    ///
    /// # Errors
    /// The time left in the window once its claims are used.
    fn check(&mut self, principal_id: [u8; 16], now: Instant) -> Result<(), Duration> {
        let (opened, count) = *self.window(principal_id, now);
        if count < MAX_ADMISSIONS_PER_MINUTE {
            Ok(())
        } else {
            Err((opened + QUOTA_WINDOW).saturating_duration_since(now))
        }
    }

    /// Count one committed claim of `principal_id` at `now`.
    fn count(&mut self, principal_id: [u8; 16], now: Instant) {
        self.window(principal_id, now).1 += 1;
    }
}

/// What the commit command admits a fresh claim against.
pub(crate) struct PreviewLimitsV1 {
    /// The owned-Event ceiling of the `decision-previews` Timeline (P11).
    pub(crate) max_events: u64,
    /// The per-minute quota of new claims.
    pub(crate) quota: Arc<Mutex<PreviewQuotaV1>>,
}

/// A fresh request as the admission checked it before its commit.
pub(crate) struct FreshPreviewV1 {
    pub(crate) principal_id: [u8; 16],
    pub(crate) actor: EntityId,
    pub(crate) request: PreviewRequestV1,
    /// The raw EPF1 digest the profile gate answered.
    pub(crate) profile_digest: [u8; 32],
}

/// One commit command: the claim key, the presented request's digest and,
/// for a fresh request, what its claim binds; `None` finishes an exact
/// retry only.
pub(crate) struct PreviewCommitV1 {
    pub(crate) key: PreviewClaimKeyV1,
    pub(crate) request_digest: [u8; 32],
    pub(crate) fresh: Option<FreshPreviewV1>,
}

/// A committed preview: its ID and its claim.
pub(crate) struct AdmittedPreviewV1 {
    pub(crate) preview_id: EventId,
    pub(crate) claim: PreviewClaimV1,
}

/// One stored result Event.
struct StoredResultV1 {
    event: DecisionPreviewResultEventV1,
    outcome: PreviewOutcomeV1,
    payload: Vec<u8>,
}

impl StoredResultV1 {
    /// BLAKE3 of the exact `PRS1` bytes, in lower-case hex.
    fn digest(&self) -> String {
        payload_digest(&self.payload)
    }
}

/// One stored claim and its result, if one committed.
pub(crate) struct ClaimedPreviewV1 {
    preview_id: EventId,
    seq: Seq,
    pub(crate) claim: PreviewClaimV1,
    payload: Vec<u8>,
    result: Option<StoredResultV1>,
}

impl ClaimedPreviewV1 {
    /// Whether the preview's result committed.
    pub(crate) const fn is_finished(&self) -> bool {
        self.result.is_some()
    }

    /// The committed preview of this claim.
    pub(crate) fn admitted(self) -> AdmittedPreviewV1 {
        AdmittedPreviewV1 {
            preview_id: self.preview_id,
            claim: self.claim,
        }
    }
}

/// A read claim: the consent to re-check, then the state or the arm.
pub(crate) struct PreviewReadV1 {
    pub(crate) consent_ref: EntityId,
    pub(crate) view: PreviewResult<DecisionPreviewV1>,
}

/// The `decision-previews` Timeline: whether the store records it and its
/// Events.
struct PreviewScanV1 {
    recorded: bool,
    events: Vec<Event>,
}

/// One boxed Decision Preview operation on the erasure host.
type PreviewOperationV1<T> =
    Box<dyn FnOnce(&mut ErasureExecutionHostV1) -> PreviewResult<T> + Send>;

/// One Decision Preview operation and its reply, run as a Write-class
/// command so its lookups and appends are linearised with every other
/// store write. Only the test-only `Generic` and `Gateway` stores lack an
/// erasure host; they answer as an unrecovered host.
struct PreviewCommandV1<T> {
    operation: PreviewOperationV1<T>,
    reply: oneshot::Sender<Result<PreviewResult<T>, StoreExecutorError>>,
}

impl<T: Send + 'static> WorkerCommandV1 for PreviewCommandV1<T> {
    fn run_on_worker(self: Box<Self>, state: &mut ExecutorState) {
        let Self { operation, reply } = *self;
        let result = match &mut state.store {
            ExecutorStore::Host(host, _) => operation(host),
            #[cfg(test)]
            ExecutorStore::Generic(_) | ExecutorStore::Gateway(_) => {
                Err(ErasureHostErrorV1::RecoveryUnavailable.into())
            }
        };
        drop(reply.send(Ok(result)));
    }

    fn expire_unrun(self: Box<Self>) {
        drop(self.reply.send(Err(StoreExecutorError::DeadlineExceeded)));
    }
}

impl StoreExecutor {
    /// Run one Decision Preview operation on the store worker.
    pub(crate) async fn decision_preview<T: Send + 'static>(
        &self,
        operation: impl FnOnce(&mut ErasureExecutionHostV1) -> PreviewResult<T> + Send + 'static,
    ) -> Result<PreviewResult<T>, StoreExecutorError> {
        submit!(self, |reply| super::Command::Action(Box::new(
            PreviewCommandV1 {
                operation: Box::new(operation),
                reply
            }
        )))
    }
}

/// The claim of `key`, if one committed (ADR-140 section 6 step 5).
///
/// # Errors
/// [`DecisionPreviewErrorV1::IdempotencyConflict`] for a claim of another
/// request, the internal-failure arm for a corrupt payload, and the store
/// failures of the Timeline read.
pub(crate) fn lookup_claim(
    host: &mut ErasureExecutionHostV1,
    key: &PreviewClaimKeyV1,
    request_digest: [u8; 32],
) -> PreviewResult<Option<ClaimedPreviewV1>> {
    scan(host).and_then(|scan| find_claim(&scan.events, key, request_digest))
}

/// The profile gate, room and bindings of a fresh request by `actor`
/// (steps 7 to 9): the bound room's consent reference and the EPF1 digest.
///
/// # Errors
/// [`DecisionPreviewErrorV1::IncompatibleProfile`] for a profile without an
/// installed EPF1 or outside the bound mode's servable set, then
/// [`DecisionPreviewErrorV1::NotFound`] for any input that is unknown,
/// foreign, not the acting persona's, digest-mismatched or erased. Stored
/// Preference and `OptionSpec` content is decoded only by the commit command,
/// after the consent check.
pub(crate) fn admit_inputs(
    host: &mut ErasureExecutionHostV1,
    actor: EntityId,
    request: &PreviewRequestV1,
    installed: Option<(String, [u8; 32])>,
) -> PreviewResult<(EntityId, [u8; 32])> {
    let profile_digest = gate(host, &request.profile_id, installed)?;
    bound_records(host, actor, request).map(|(consent_ref, _, _)| (consent_ref, profile_digest))
}

/// The commit command of step 12, or with no fresh request the finish of
/// an exact retry (step 6.2).
///
/// It re-runs the claim lookup first. A claim of the same request is
/// finished when it has no result and answered; one of another request is a
/// conflict. A fresh request is re-validated with the helper of steps 8 and
/// 9, then the quota and the ceiling are checked, the Timeline is opened if
/// it is absent, and the claim and its result are appended.
///
/// # Errors
/// The refusals of steps 8, 9 and 12, the internal-failure arm, and the
/// store failures; a failed result append after its claim committed leaves
/// the claim for an exact retry to finish (P34).
pub(crate) fn commit_preview(
    host: &mut ErasureExecutionHostV1,
    commit: PreviewCommitV1,
    limits: &PreviewLimitsV1,
    now: Instant,
) -> PreviewResult<AdmittedPreviewV1> {
    let scan = scan(host)?;
    match find_claim(&scan.events, &commit.key, commit.request_digest)? {
        Some(claimed) => finish(host, &claimed, limits.max_events).map(|()| claimed.admitted()),
        None => commit
            .fresh
            .ok_or(DecisionPreviewErrorV1::Internal)
            .and_then(|fresh| claim_fresh(host, &scan, &commit.key, fresh, limits, now)),
    }
}

/// The preview `preview_id` as `principal_id` acting as `actor` reads it
/// (section 7 steps 3 and 5): its consent reference to re-check, and its
/// state or the internal-failure arm.
///
/// # Errors
/// [`DecisionPreviewErrorV1::NotFound`] for no claim or a claim of another
/// Principal or actor, the internal-failure arm for a corrupt payload, and
/// the store failures of the Timeline read.
pub(crate) fn read_preview(
    host: &mut ErasureExecutionHostV1,
    preview_id: EventId,
    principal_id: [u8; 16],
    actor: EntityId,
) -> PreviewResult<PreviewReadV1> {
    let scan = scan(host)?;
    let claim = scan
        .events
        .iter()
        .find(|event| is_claim(event) && event.id == preview_id)
        .ok_or(DecisionPreviewErrorV1::NotFound)?;
    let claimed = claimed_at(&scan.events, claim)?;
    if claimed.claim.principal_id != principal_id || claimed.claim.actor_entity_id != actor {
        return Err(DecisionPreviewErrorV1::NotFound);
    }
    Ok(PreviewReadV1 {
        consent_ref: claimed.claim.consent_ref,
        view: preview_view(host, claimed),
    })
}

/// The read bounds of the `decision-previews` Timeline: the larger payload
/// is a `PRQ1` claim and the longer type `preview.request.v1`.
const fn read_bounds() -> EventReadBounds {
    EventReadBounds::new(
        MAX_PREVIEW_CLAIM_BYTES_V1,
        PREVIEW_REQUEST_EVENT_TYPE_V1.len(),
        0,
        usize::MAX,
    )
}

/// Read the `decision-previews` Timeline by its identity; a store that does
/// not record it holds no preview.
fn scan(host: &mut ErasureExecutionHostV1) -> PreviewResult<PreviewScanV1> {
    let timeline = decision_previews_timeline();
    let recorded = host
        .command_sender()
        .and_then(|mut commands| commands.records_timeline(timeline))?;
    let events = if recorded {
        host.read_sender()
            .and_then(|mut reads| reads.read_bounded(timeline, SeqRange::all(), read_bounds()))?
    } else {
        Vec::new()
    };
    Ok(PreviewScanV1 { recorded, events })
}

fn is_claim(event: &Event) -> bool {
    event.event_type.as_str() == PREVIEW_REQUEST_EVENT_TYPE_V1
}

fn is_result(event: &Event) -> bool {
    event.event_type.as_str() == PREVIEW_RESULT_EVENT_TYPE_V1
}

/// The entity of a preview's result Event: its preview ID.
const fn preview_entity(preview_id: EventId) -> EntityId {
    EntityId::from_ulid(preview_id.inner())
}

/// The claim of `key` among `events`, if any, when it is of the request
/// whose digest is `request_digest`.
fn find_claim(
    events: &[Event],
    key: &PreviewClaimKeyV1,
    request_digest: [u8; 32],
) -> PreviewResult<Option<ClaimedPreviewV1>> {
    let entity = key.entity();
    events
        .iter()
        .find(|event| is_claim(event) && event.entity == entity)
        .map(|event| {
            claimed_at(events, event).and_then(|claimed| {
                if claimed.claim.request.digest() == request_digest {
                    Ok(claimed)
                } else {
                    Err(DecisionPreviewErrorV1::IdempotencyConflict)
                }
            })
        })
        .transpose()
}

/// The claim Event `claim` with its result among `events`. A payload that
/// does not re-encode to its own bytes, or a result naming another
/// preview, is the internal-failure arm.
fn claimed_at(events: &[Event], claim: &Event) -> PreviewResult<ClaimedPreviewV1> {
    let stored = PreviewClaimV1::from_payload(claim.payload.as_slice())
        .ok()
        .ok_or(DecisionPreviewErrorV1::Internal)?;
    let entity = preview_entity(claim.id);
    let result = events
        .iter()
        .find(|event| is_result(event) && event.entity == entity)
        .map(|event| stored_result(event, claim.id))
        .transpose()?;
    Ok(ClaimedPreviewV1 {
        preview_id: claim.id,
        seq: claim.seq,
        claim: stored,
        payload: claim.payload.as_slice().to_vec(),
        result,
    })
}

fn stored_result(event: &Event, preview_id: EventId) -> PreviewResult<StoredResultV1> {
    PreviewResultV1::from_payload(event.payload.as_slice())
        .ok()
        .filter(|result| result.preview_id == preview_id)
        .map(|result| StoredResultV1 {
            event: DecisionPreviewResultEventV1 {
                event_id: event.id,
                seq: event.seq,
            },
            outcome: result.outcome,
            payload: event.payload.as_slice().to_vec(),
        })
        .ok_or(DecisionPreviewErrorV1::Internal)
}

/// The servable ADR-058 profiles of a bound mode (README rule 3).
fn servable(mode: GatewayModeProfileIdV1, profile_id: &str) -> bool {
    let family: [&str; 3] = match mode {
        GatewayModeProfileIdV1::Local => ["replay-v1", "deterministic-local-v1", "live-local-v1"],
        GatewayModeProfileIdV1::AirGapped => [
            "replay-v1",
            "deterministic-air-gapped-v1",
            "live-air-gapped-v1",
        ],
    };
    family.contains(&profile_id)
}

/// The profile gate (step 7, P31): the installed EPF1's digest of a profile
/// servable in the bound mode.
fn gate(
    host: &mut ErasureExecutionHostV1,
    profile_id: &str,
    installed: Option<(String, [u8; 32])>,
) -> PreviewResult<[u8; 32]> {
    let (_, profile_digest) = installed
        .filter(|(installed_id, _)| installed_id == profile_id)
        .ok_or(DecisionPreviewErrorV1::IncompatibleProfile)?;
    current_binding(host).and_then(|(mode, _)| {
        if servable(mode, profile_id) {
            Ok(profile_digest)
        } else {
            Err(DecisionPreviewErrorV1::IncompatibleProfile)
        }
    })
}

/// The store's persisted binding: its profile and GMP1 digest.
fn current_binding(
    host: &mut ErasureExecutionHostV1,
) -> PreviewResult<(GatewayModeProfileIdV1, [u8; 32])> {
    host.gateway_mode_binding()
        .load_mode_binding()
        .ok()
        .flatten()
        .and_then(|record| {
            let profile = record.profile();
            profile
                .profile_id()
                .parse::<GatewayModeProfileIdV1>()
                .ok()
                .map(|id| (id, profile.profile_digest()))
        })
        .ok_or(DecisionPreviewErrorV1::ModeUnavailable)
}

/// The room and binding checks of steps 8 and 9, shared by the admission
/// and the commit's re-validation.
///
/// It answers the bound room's consent reference and the two input
/// revisions. It decodes no Preference or `OptionSpec` content (it reads the
/// room only for the consent reference), so a corrupt input reaches the
/// internal-failure arm only in the commit command, after the step-10
/// consent check.
fn bound_records(
    host: &mut ErasureExecutionHostV1,
    actor: EntityId,
    request: &PreviewRequestV1,
) -> PreviewResult<(EntityId, GatewayRevisionRecordV1, GatewayRevisionRecordV1)> {
    let consent_ref = bound_room(host, actor, &request.scenario_room)?;
    let preference = load_revision(host, GatewayRevisionKindV1::Preference, &request.preference)
        .and_then(|state| admitted_record(state, actor, &request.preference))?;
    let option_spec = load_revision(
        host,
        GatewayRevisionKindV1::OptionSpec,
        &request.option_spec,
    )
    .and_then(|state| admitted_record(state, actor, &request.option_spec))?;
    Ok((consent_ref, preference, option_spec))
}

/// The bound room revision (step 8, D8): it must exist with `reference`'s
/// digest as its `provenance.digest` and name `actor` as a `persona`
/// participant (D7). Its `privacy_export_ref` is the preview's consent.
fn bound_room(
    host: &mut ErasureExecutionHostV1,
    actor: EntityId,
    reference: &PreviewRevisionRefV1,
) -> PreviewResult<EntityId> {
    let (_, revisions) =
        room_revisions(host, EntityId::from_ulid(reference.id)).map_err(room_error)?;
    let event = revision_at(&revisions, reference.revision.get())
        .ok_or(DecisionPreviewErrorV1::NotFound)?;
    let descriptor = descriptor_of(event).map_err(room_error)?;
    let provenance = revision_provenance_digest_v1(&descriptor.descriptor_hash(), event.id);
    let input = descriptor.input();
    let persona = input.participants.iter().any(|participant| {
        participant.entity_id == actor && participant.kind == RoomParticipantKindV1::Persona
    });
    (provenance == hex(reference.digest) && persona)
        .then_some(input.privacy_export_ref)
        .ok_or(DecisionPreviewErrorV1::NotFound)
}

/// A room lookup failure: an unknown room is `404`, a store failure stays
/// one, and a room the store cannot decode is the internal-failure arm.
fn room_error(error: RoomStoreErrorV1) -> DecisionPreviewErrorV1 {
    match error {
        RoomStoreErrorV1::NotFound => DecisionPreviewErrorV1::NotFound,
        RoomStoreErrorV1::Store(error) => DecisionPreviewErrorV1::Store(error),
        _ => DecisionPreviewErrorV1::Internal,
    }
}

/// The state of the revision `reference` names in the `kind` family.
fn load_revision(
    host: &mut ErasureExecutionHostV1,
    kind: GatewayRevisionKindV1,
    reference: &PreviewRevisionRefV1,
) -> PreviewResult<Option<GatewayRevisionStateV1>> {
    let key = GatewayRevisionKeyV1::new(kind, reference.id.to_bytes(), reference.revision);
    host.command_sender()
        .and_then(|mut commands| {
            commands.with_gateway_revisions(|port| port.load_gateway_revision(key))
        })
        .map_err(DecisionPreviewErrorV1::from)
        .and_then(|loaded| loaded.map_err(DecisionPreviewErrorV1::Revisions))
}

/// An input at admission (step 9, D7, D9): the stored, unerased revision
/// of `actor` whose digest is `reference`'s; anything else is `404`.
fn admitted_record(
    state: Option<GatewayRevisionStateV1>,
    actor: EntityId,
    reference: &PreviewRevisionRefV1,
) -> PreviewResult<GatewayRevisionRecordV1> {
    match state {
        Some(GatewayRevisionStateV1::Present(record))
            if record.tombstone().subject() == actor
                && record.tombstone().digest() == reference.digest =>
        {
            Ok(record)
        }
        _ => Err(DecisionPreviewErrorV1::NotFound),
    }
}

/// An input a stored claim names: the revision, or `None` once it is
/// erased. A missing revision or another digest is the internal-failure
/// arm, because the claim committed only after the input was checked.
fn stored_revision(
    host: &mut ErasureExecutionHostV1,
    kind: GatewayRevisionKindV1,
    reference: &PreviewRevisionRefV1,
) -> PreviewResult<Option<GatewayRevisionRecordV1>> {
    load_revision(host, kind, reference).and_then(|state| match state {
        Some(GatewayRevisionStateV1::Present(record))
            if record.tombstone().digest() == reference.digest =>
        {
            Ok(Some(record))
        }
        Some(GatewayRevisionStateV1::Erased(tombstone))
            if tombstone.digest() == reference.digest =>
        {
            Ok(None)
        }
        _ => Err(DecisionPreviewErrorV1::Internal),
    })
}

/// The Recommendation of the inputs a stored claim names, or `None` when
/// either is erased.
fn stored_inputs(
    host: &mut ErasureExecutionHostV1,
    claim: &PreviewClaimV1,
) -> PreviewResult<Option<RecommendationV1>> {
    let preference = stored_revision(
        host,
        GatewayRevisionKindV1::Preference,
        &claim.request.preference,
    )?;
    let option_spec = stored_revision(
        host,
        GatewayRevisionKindV1::OptionSpec,
        &claim.request.option_spec,
    )?;
    preference
        .zip(option_spec)
        .map(|(preference, option_spec)| recommendation(&preference, &option_spec))
        .transpose()
}

/// The `pigloros.match-score.v1` Recommendation of two stored revisions.
///
/// Stored #304 content is decoded without re-validating its bounds, so
/// content that does not decode and a [`pos_runtime::MatchScoreErrorV1`]
/// are both the internal-failure arm.
fn recommendation(
    preference: &GatewayRevisionRecordV1,
    option_spec: &GatewayRevisionRecordV1,
) -> PreviewResult<RecommendationV1> {
    crate::revision::preview_weights(preference.content())
        .zip(crate::revision::preview_options(option_spec.content()))
        .and_then(|(weights, options)| match_score_v1(&weights, &options).ok())
        .ok_or(DecisionPreviewErrorV1::Internal)
}

/// Finish a claim with no result (step 6.2): append nothing when a result
/// exists, else `computed`, or `failed` with `input-deleted` when an input
/// was erased since the claim (C13).
fn finish(
    host: &mut ErasureExecutionHostV1,
    claimed: &ClaimedPreviewV1,
    max_events: u64,
) -> PreviewResult<()> {
    if claimed.is_finished() {
        return Ok(());
    }
    let outcome = stored_inputs(host, &claimed.claim)?.map_or_else(
        || PreviewOutcomeV1::Failed(PreviewFailureCodeV1::input_deleted()),
        |_| PreviewOutcomeV1::Computed,
    );
    append_result(host, claimed.preview_id, outcome, max_events)
}

/// Commit a fresh request (step 12.2 to 12.8).
fn claim_fresh(
    host: &mut ErasureExecutionHostV1,
    scan: &PreviewScanV1,
    key: &PreviewClaimKeyV1,
    fresh: FreshPreviewV1,
    limits: &PreviewLimitsV1,
    now: Instant,
) -> PreviewResult<AdmittedPreviewV1> {
    let (consent_ref, preference, option_spec) = bound_records(host, fresh.actor, &fresh.request)?;
    // A corrupt input or a Match Score refusal is the internal-failure arm
    // here, after the consent check and before anything is appended.
    recommendation(&preference, &option_spec)?;
    let mut quota = limits.quota.lock().unwrap_or_else(PoisonError::into_inner);
    quota
        .check(fresh.principal_id, now)
        .map_err(|retry_after| DecisionPreviewErrorV1::QuotaExceeded { retry_after })?;
    require_headroom(&scan.events, limits.max_events)?;
    let (_, mode_profile_digest) = current_binding(host)?;
    if !scan.recorded {
        open_previews_timeline(host)?;
    }
    let claim = PreviewClaimV1 {
        principal_id: fresh.principal_id,
        actor_entity_id: fresh.actor,
        request: fresh.request,
        consent_ref,
        profile_digest: fresh.profile_digest,
        mode_profile_digest,
    };
    let payload = claim
        .to_payload()
        .ok()
        .ok_or(DecisionPreviewErrorV1::Internal)?;
    let draft = EventDraft::new(
        key.entity(),
        Kind::new(PREVIEW_REQUEST_EVENT_TYPE_V1),
        CanonicalBytes::from_vec(payload),
    );
    let committed = append(host, &draft, limits.max_events)?;
    quota.count(fresh.principal_id, now);
    drop(quota);
    append_result(
        host,
        committed.id,
        PreviewOutcomeV1::Computed,
        limits.max_events,
    )
    .map(|()| AdmittedPreviewV1 {
        preview_id: committed.id,
        claim,
    })
}

/// The ceiling check of P11: the Timeline must keep one free slot for each
/// claim without a result, beside the two Events of the new preview.
fn require_headroom(events: &[Event], max_events: u64) -> PreviewResult<()> {
    let finished: HashSet<EntityId> = events
        .iter()
        .filter(|event| is_result(event))
        .map(|event| event.entity)
        .collect();
    let unfinished = events
        .iter()
        .filter(|event| is_claim(event) && !finished.contains(&preview_entity(event.id)))
        .count();
    let needed = events.len() + 2 + unfinished;
    if u64::try_from(needed).is_ok_and(|needed| needed <= max_events) {
        Ok(())
    } else {
        Err(DecisionPreviewErrorV1::StoreFull)
    }
}

/// Open the `decision-previews` Timeline by its identity (P30).
fn open_previews_timeline(host: &mut ErasureExecutionHostV1) -> PreviewResult<()> {
    host.command_sender()
        .and_then(|mut commands| {
            commands.open_root_timeline(
                decision_previews_timeline(),
                DECISION_PREVIEWS_TIMELINE_NAME,
            )
        })
        .map(drop)
        .map_err(topology_error)
}

/// The refusal of the topology change that opens the Timeline: under an
/// active erasure request without the composed authority it is the
/// non-retryable P30 answer, any other host error a store failure.
fn topology_error(error: ErasureHostErrorV1) -> DecisionPreviewErrorV1 {
    if matches!(error, ErasureHostErrorV1::AuthorizationDenied) {
        DecisionPreviewErrorV1::TopologyUnavailable
    } else {
        error.into()
    }
}

/// Append one Event to the `decision-previews` Timeline under its ceiling.
fn append(
    host: &mut ErasureExecutionHostV1,
    draft: &EventDraft,
    max_events: u64,
) -> PreviewResult<Event> {
    host.command_sender()
        .and_then(|mut commands| {
            commands.append_bounded(
                decision_previews_timeline(),
                std::slice::from_ref(draft),
                max_events,
            )
        })
        .map_err(DecisionPreviewErrorV1::from)
        .and_then(|appended| {
            appended
                .and_then(|events| events.into_iter().next())
                .ok_or(DecisionPreviewErrorV1::Internal)
        })
}

/// Append the `PRS1` result of the preview `preview_id`.
fn append_result(
    host: &mut ErasureExecutionHostV1,
    preview_id: EventId,
    outcome: PreviewOutcomeV1,
    max_events: u64,
) -> PreviewResult<()> {
    let payload = PreviewResultV1 {
        preview_id,
        outcome,
    }
    .to_payload();
    let mut draft = EventDraft::new(
        preview_entity(preview_id),
        Kind::new(PREVIEW_RESULT_EVENT_TYPE_V1),
        CanonicalBytes::from_vec(payload),
    );
    draft.causation_id = Some(preview_id);
    append(host, &draft, max_events).map(drop)
}

/// The state of a read claim (section 7 step 5).
fn preview_view(
    host: &mut ErasureExecutionHostV1,
    claimed: ClaimedPreviewV1,
) -> PreviewResult<DecisionPreviewV1> {
    let mode_profile = claim_binding(host, &claimed)?;
    let state = match &claimed.result {
        None => DecisionPreviewStateV1::Admitted,
        Some(result) => result_state(host, &claimed.claim, result)?,
    };
    let provenance_digest = provenance_digest(&claimed, &mode_profile);
    Ok(DecisionPreviewV1 {
        preview_id: claimed.preview_id,
        claim: claimed.claim,
        mode_profile,
        provenance_digest,
        state,
    })
}

/// The state a committed result gives (P17, P25).
fn result_state(
    host: &mut ErasureExecutionHostV1,
    claim: &PreviewClaimV1,
    result: &StoredResultV1,
) -> PreviewResult<DecisionPreviewStateV1> {
    match &result.outcome {
        PreviewOutcomeV1::Failed(code) => Ok(DecisionPreviewStateV1::Failed { code: code.clone() }),
        PreviewOutcomeV1::Computed => stored_inputs(host, claim).map(|recommendation| {
            recommendation.map_or(
                DecisionPreviewStateV1::Degraded {
                    result: result.event,
                },
                |recommendation| DecisionPreviewStateV1::Committed {
                    result: result.event,
                    recommendation,
                },
            )
        }),
    }
}

/// The binding the claim's commit evidence records; its digest must be the
/// claim's field 10 (ADR-140 section 7, C18).
fn claim_binding(
    host: &mut ErasureExecutionHostV1,
    claimed: &ClaimedPreviewV1,
) -> PreviewResult<DecisionPreviewModeV1> {
    let binding = host.gateway_mode_binding();
    binding
        .load_commit_epoch(decision_previews_timeline(), claimed.seq)
        .ok()
        .flatten()
        .and_then(|epoch| {
            binding
                .load_mode_binding_history()
                .ok()
                .and_then(|history| {
                    history
                        .into_iter()
                        .find(|entry| entry.record().binding_epoch() == epoch)
                })
                .and_then(|entry| {
                    let profile = entry.record().profile();
                    profile
                        .profile_id()
                        .parse::<GatewayModeProfileIdV1>()
                        .ok()
                        .map(|id| DecisionPreviewModeV1 {
                            profile: id,
                            digest: profile.profile_digest(),
                            binding_epoch: epoch,
                        })
                })
        })
        .filter(|mode| mode.digest == claimed.claim.mode_profile_digest)
        .ok_or(DecisionPreviewErrorV1::Internal)
}

/// The `provenance.digest` of a preview (ADR-140 P24).
///
/// It is BLAKE3 of `PiglorOS.GatewayDecisionPreviewProvenance.v1`, a 0x00
/// byte and the deterministic CBOR array `["host-derived", principal_id,
/// actor_entity_id, preview_id, claim_payload_digest, result_payload_digest
/// | null, mode_profile_id, mode_profile_digest, binding_epoch]`: IDs as ULID
/// text, digests as lower-case hex text and the epoch as an integer.
fn provenance_digest(claimed: &ClaimedPreviewV1, mode: &DecisionPreviewModeV1) -> [u8; 32] {
    let leading = [
        ORIGIN.to_owned(),
        Ulid::from_bytes(claimed.claim.principal_id).to_string(),
        claimed.claim.actor_entity_id.to_string(),
        claimed.preview_id.to_string(),
        payload_digest(&claimed.payload),
    ];
    let result_digest = claimed.result.as_ref().map(StoredResultV1::digest);
    let result = result_digest.map_or_else(|| vec![CBOR_NULL], |digest| cbor_text(&digest));
    let mut record = PROVENANCE_DOMAIN.to_vec();
    cbor_head(&mut record, CBOR_ARRAY, PROVENANCE_FIELDS);
    for text in &leading {
        record.extend(cbor_text(text));
    }
    record.extend(result);
    record.extend(cbor_text(mode.profile.as_str()));
    record.extend(cbor_text(&hex(mode.digest)));
    cbor_head(&mut record, CBOR_UNSIGNED, mode.binding_epoch.get());
    *blake3::hash(&record).as_bytes()
}

/// Append one deterministic CBOR head: major type `major` with the
/// argument `value` in its shortest form (RFC 8949 section 4.2.1).
fn cbor_head(out: &mut Vec<u8>, major: u8, value: u64) {
    let bytes = value.to_be_bytes();
    let (info, argument): (u8, &[u8]) = match value {
        0..=23 => (bytes[7], &[]),
        24..=0xff => (24, &bytes[7..]),
        0x100..=0xffff => (25, &bytes[6..]),
        0x1_0000..=0xffff_ffff => (26, &bytes[4..]),
        _ => (27, &bytes[..]),
    };
    out.push((major << 5) | info);
    out.extend_from_slice(argument);
}

/// The deterministic CBOR text item of `text`.
fn cbor_text(text: &str) -> Vec<u8> {
    let mut item = Vec::with_capacity(text.len() + 9);
    cbor_head(
        &mut item,
        CBOR_TEXT,
        u64::try_from(text.len()).unwrap_or(u64::MAX),
    );
    item.extend_from_slice(text.as_bytes());
    item
}

/// BLAKE3 of `payload`, in lower-case hex.
fn payload_digest(payload: &[u8]) -> String {
    hex(*blake3::hash(payload).as_bytes())
}

/// `digest` in lower-case hex.
fn hex(digest: [u8; 32]) -> String {
    blake3::Hash::from_bytes(digest).to_hex().to_string()
}

// Public so the Gateway-level tests share its fixtures, as
// `local_erasure_composition::tests` does.
#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
pub mod tests;
