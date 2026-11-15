//! The Scenario Room store command (#1398, parent #303).
//!
//! Each operation runs as one command on the store worker, so the head
//! check of a derive and its append are one serialized step. A room is one
//! root Timeline named [`ROOM_TIMELINE_PREFIX`] followed by the room ID;
//! each revision is one `room.revision.v1` Event whose payload is the
//! admitted ADR-041 descriptor, appended under its ADR-041 append identity
//! (ADR-041 section 7). An `Idempotency-Key` is claimed first on the host's
//! request Timeline: the claim's intent is the request digest, so an exact
//! retry finds its claim, a different request under the same key is a
//! conflict, and the revision a claim produced names the claim as its
//! causation.

use std::{num::NonZeroU64, sync::Arc, time::Instant};

use pos_core::{
    store::{AppendIdentity, AppendIntent, AppendOrDuplicateOutcome, EventReadBounds, SeqRange},
    CanonicalBytes, CoreError, EntityId, ErasureHostErrorV1, ErasureReferenceV1, Event, EventDraft,
    EventId, Kind, Seq, Timeline, TimelineId,
};
use pos_runtime::{
    ErasureExecutionHostV1, RoomCorrelationIdV1, ScenarioRoomCatalogueV1, ScenarioRoomDescriptorV1,
    ScenarioRoomErrorV1, ScenarioRoomInputV1, MAX_ROOM_DESCRIPTOR_BYTES_V1,
};
use tokio::sync::oneshot;

use super::{
    await_command_result, host_error_to_core, CommandLifecycle, ExecutorState, ExecutorStore,
    StoreExecutor, StoreExecutorError, WorkerCommandV1,
};

/// The event type of one Scenario Room revision (ADR-041 section 1).
pub(crate) const ROOM_REVISION_EVENT_TYPE: &str = "room.revision.v1";
/// The event type of one claimed `Idempotency-Key`.
pub(crate) const ROOM_REQUEST_EVENT_TYPE: &str = "room.request.v1";
/// The name prefix of a room's Timeline.
pub(crate) const ROOM_TIMELINE_PREFIX: &str = "scenario-room/";
/// The name of the host's Scenario Room request Timeline.
pub(crate) const ROOM_REQUESTS_TIMELINE: &str = "scenario-room-requests";

/// One claimed `Idempotency-Key`: its append identity and the digest of the
/// request it was first used with.
#[derive(Debug)]
pub(crate) struct RoomClaimV1 {
    pub(crate) identity: AppendIdentity,
    pub(crate) request_digest: [u8; 32],
}

/// One Scenario Room operation.
#[derive(Debug)]
pub(crate) enum RoomOperationV1 {
    Create {
        claim: RoomClaimV1,
        input: Box<ScenarioRoomInputV1>,
    },
    Derive {
        claim: RoomClaimV1,
        room_id: EntityId,
        parent_revision: u64,
        input: Box<ScenarioRoomInputV1>,
    },
    Read {
        room_id: EntityId,
        revision: u64,
    },
}

/// What the host admits a room against.
#[derive(Debug)]
pub(crate) struct RoomAdmissionV1 {
    /// The Plugins the deployment bundles.
    pub(crate) catalogue: ScenarioRoomCatalogueV1,
    /// The host's single-participant governance record, if provisioned.
    pub(crate) governance_record: Option<EntityId>,
    /// The owned-Event ceiling of every room and request Timeline.
    pub(crate) max_events: u64,
    /// The root-Timeline ceiling of the host.
    pub(crate) max_timelines: usize,
}

/// One stored revision and where it committed.
#[derive(Debug)]
pub(crate) struct StoredRoomRevisionV1 {
    pub(crate) descriptor: ScenarioRoomDescriptorV1,
    pub(crate) timeline: TimelineId,
    pub(crate) event_id: EventId,
    pub(crate) seq: Seq,
    pub(crate) generation: ErasureReferenceV1,
    /// The binding epoch the commit recorded, with the profile bound then.
    pub(crate) produced_under: (pos_core::GatewayModeProfileRefV1, NonZeroU64),
}

/// The outcome of one room operation.
#[derive(Debug)]
pub(crate) enum RoomOutcomeV1 {
    /// The operation committed this revision.
    Committed(Box<StoredRoomRevisionV1>),
    /// The revision already existed: an exact retry, an ADR-041 section 7
    /// duplicate, or a read.
    Existing(Box<StoredRoomRevisionV1>),
}

/// The closed refusals of a room operation.
#[derive(Debug)]
pub(crate) enum RoomStoreErrorV1 {
    /// The descriptor seam refused the input.
    Room(ScenarioRoomErrorV1),
    /// `governance_ref` names no governance record of the host.
    GovernanceUnknown,
    /// No such room, revision or parent revision.
    NotFound,
    /// The parent is not the head and the proposal is not its revision.
    StaleParent,
    /// The `Idempotency-Key` was used for a different request.
    IdempotencyConflict,
    /// A room or request Timeline, or the host, reached its ceiling.
    LimitReached,
    /// The commit's binding epoch or profile cannot be read.
    ModeUnavailable,
    /// The store refused or failed the operation.
    Store(CoreError),
}

impl From<ErasureHostErrorV1> for RoomStoreErrorV1 {
    fn from(error: ErasureHostErrorV1) -> Self {
        Self::Store(host_error_to_core(error))
    }
}

impl From<ScenarioRoomErrorV1> for RoomStoreErrorV1 {
    fn from(error: ScenarioRoomErrorV1) -> Self {
        Self::Room(error)
    }
}

type RoomResult<T> = Result<T, RoomStoreErrorV1>;

pub(super) struct ScenarioRoomCommandV1 {
    operation: RoomOperationV1,
    admission: RoomAdmissionV1,
    reply: oneshot::Sender<Result<RoomResult<RoomOutcomeV1>, StoreExecutorError>>,
}

impl WorkerCommandV1 for ScenarioRoomCommandV1 {
    fn run_on_worker(self: Box<Self>, state: &mut ExecutorState) {
        let result = match &mut state.store {
            ExecutorStore::Host(host, _) => {
                run_room_operation(host, self.operation, &self.admission)
            }
            #[cfg(test)]
            ExecutorStore::Generic(_) | ExecutorStore::Gateway(_) => Err(RoomStoreErrorV1::Store(
                CoreError::ErasureContainmentUnavailable,
            )),
        };
        drop(self.reply.send(Ok(result)));
    }

    fn expire_unrun(self: Box<Self>) {
        drop(self.reply.send(Err(StoreExecutorError::DeadlineExceeded)));
    }
}

impl StoreExecutor {
    /// Run one Scenario Room operation on the store worker.
    pub(crate) async fn scenario_room(
        &self,
        operation: RoomOperationV1,
        admission: RoomAdmissionV1,
    ) -> Result<RoomResult<RoomOutcomeV1>, StoreExecutorError> {
        submit!(self, |reply| super::Command::Action(Box::new(
            ScenarioRoomCommandV1 {
                operation,
                admission,
                reply
            }
        )))
    }
}

fn run_room_operation(
    host: &mut ErasureExecutionHostV1,
    operation: RoomOperationV1,
    admission: &RoomAdmissionV1,
) -> RoomResult<RoomOutcomeV1> {
    match operation {
        RoomOperationV1::Create { claim, input } => create_room(host, &claim, *input, admission),
        RoomOperationV1::Derive {
            claim,
            room_id,
            parent_revision,
            input,
        } => derive_room(host, &claim, room_id, parent_revision, *input, admission),
        RoomOperationV1::Read { room_id, revision } => room_revisions(host, room_id)
            .and_then(|(timeline, revisions)| existing_at(host, timeline, &revisions, revision)),
    }
}

/// The existing revision `revision` of a room, counting from 1.
fn existing_at(
    host: &mut ErasureExecutionHostV1,
    timeline: TimelineId,
    revisions: &[Event],
    revision: u64,
) -> RoomResult<RoomOutcomeV1> {
    revision_at(revisions, revision)
        .ok_or(RoomStoreErrorV1::NotFound)
        .and_then(|event| stored(host, timeline, event))
        .map(|stored| RoomOutcomeV1::Existing(Box::new(stored)))
}

fn create_room(
    host: &mut ErasureExecutionHostV1,
    claim: &RoomClaimV1,
    input: ScenarioRoomInputV1,
    admission: &RoomAdmissionV1,
) -> RoomResult<RoomOutcomeV1> {
    RoomCorrelationIdV1::generate()
        .and_then(|correlation_id| {
            ScenarioRoomDescriptorV1::admit_first(
                EntityId::new(),
                correlation_id,
                input,
                &admission.catalogue,
            )
        })
        .map_err(RoomStoreErrorV1::from)
        .and_then(|descriptor| require_governance(descriptor, admission))
        .and_then(|descriptor| {
            claim_request(host, claim, admission).map(|claimed| (descriptor, claimed))
        })
        .and_then(|(descriptor, claimed)| match claimed {
            Claimed::New(causation) => create_and_append(host, &descriptor, causation, admission),
            Claimed::Retry(causation) => {
                revision_caused_by(host, causation).and_then(|existing| match existing {
                    Some(existing) => Ok(RoomOutcomeV1::Existing(Box::new(existing))),
                    // The claim committed but its room did not: finish it.
                    None => create_and_append(host, &descriptor, causation, admission),
                })
            }
        })
}

/// Create the room's Timeline and append its first revision.
fn create_and_append(
    host: &mut ErasureExecutionHostV1,
    descriptor: &ScenarioRoomDescriptorV1,
    causation: EventId,
    admission: &RoomAdmissionV1,
) -> RoomResult<RoomOutcomeV1> {
    create_root(
        host,
        &format!("{ROOM_TIMELINE_PREFIX}{}", descriptor.room_id()),
        admission,
    )
    .and_then(|timeline| append_revision(host, timeline.id(), descriptor, causation, admission))
}

fn derive_room(
    host: &mut ErasureExecutionHostV1,
    claim: &RoomClaimV1,
    room_id: EntityId,
    parent_revision: u64,
    input: ScenarioRoomInputV1,
    admission: &RoomAdmissionV1,
) -> RoomResult<RoomOutcomeV1> {
    let (timeline, revisions) = room_revisions(host, room_id)?;
    let candidate = revision_at(&revisions, parent_revision)
        .ok_or(RoomStoreErrorV1::NotFound)
        .and_then(descriptor_of)
        .and_then(|parent| {
            parent
                .admit_next(input, &admission.catalogue)
                .map_err(RoomStoreErrorV1::from)
        })
        .and_then(|candidate| require_governance(candidate, admission))?;
    match claim_request(host, claim, admission)? {
        Claimed::Retry(causation) => match revisions
            .iter()
            .find(|event| event.causation_id == Some(causation))
        {
            Some(event) => stored(host, timeline, event)
                .map(|existing| RoomOutcomeV1::Existing(Box::new(existing))),
            None => derive_at(
                host,
                timeline,
                &revisions,
                parent_revision,
                &candidate,
                causation,
                admission,
            ),
        },
        Claimed::New(causation) => derive_at(
            host,
            timeline,
            &revisions,
            parent_revision,
            &candidate,
            causation,
            admission,
        ),
    }
}

/// Append `candidate` when `parent_revision` is the head. Otherwise it is
/// the ADR-041 section 7 duplicate of the revision already derived from
/// that parent, or a stale proposal.
fn derive_at(
    host: &mut ErasureExecutionHostV1,
    timeline: TimelineId,
    revisions: &[Event],
    parent_revision: u64,
    candidate: &ScenarioRoomDescriptorV1,
    causation: EventId,
    admission: &RoomAdmissionV1,
) -> RoomResult<RoomOutcomeV1> {
    let next = parent_revision.saturating_add(1);
    match revision_at(revisions, next) {
        None => append_revision(host, timeline, candidate, causation, admission),
        Some(derived) => descriptor_of(derived).and_then(|derived| {
            if derived.descriptor_hash() == candidate.descriptor_hash() {
                existing_at(host, timeline, revisions, next)
            } else {
                Err(RoomStoreErrorV1::StaleParent)
            }
        }),
    }
}

/// `governance_ref` must name the host's governance record (#303
/// decision 1a).
fn require_governance(
    descriptor: ScenarioRoomDescriptorV1,
    admission: &RoomAdmissionV1,
) -> RoomResult<ScenarioRoomDescriptorV1> {
    if admission.governance_record == Some(descriptor.input().governance_ref) {
        Ok(descriptor)
    } else {
        Err(RoomStoreErrorV1::GovernanceUnknown)
    }
}

enum Claimed {
    /// The key is claimed for the first time by this Event.
    New(EventId),
    /// The key was already claimed for this request by this Event.
    Retry(EventId),
}

fn claim_request(
    host: &mut ErasureExecutionHostV1,
    claim: &RoomClaimV1,
    admission: &RoomAdmissionV1,
) -> RoomResult<Claimed> {
    // The claim acts as an entity named by its key, so claims stay apart.
    let mut entity = [0; 16];
    entity.copy_from_slice(&claim.identity.dedup_key.as_bytes()[..16]);
    let draft = EventDraft::new(
        EntityId::from_ulid(ulid::Ulid::from_bytes(entity)),
        Kind::new(ROOM_REQUEST_EVENT_TYPE),
        CanonicalBytes::from_vec(claim.request_digest.to_vec()),
    );
    find_root(host, ROOM_REQUESTS_TIMELINE)
        .and_then(|requests| match requests {
            Some(requests) => Ok(requests),
            None => create_root(host, ROOM_REQUESTS_TIMELINE, admission),
        })
        .and_then(|requests| {
            append_identified(host, requests.id(), claim.identity, &draft, admission)
        })
        .and_then(|outcome| match outcome {
            AppendOrDuplicateOutcome::Appended(event) => Ok(Claimed::New(event.id)),
            AppendOrDuplicateOutcome::Duplicate { event_id } => Ok(Claimed::Retry(event_id)),
            AppendOrDuplicateOutcome::Conflict => Err(RoomStoreErrorV1::IdempotencyConflict),
        })
}

/// Append one identified Event under the owned-Event ceiling.
fn append_identified(
    host: &mut ErasureExecutionHostV1,
    timeline: TimelineId,
    identity: AppendIdentity,
    draft: &EventDraft,
    admission: &RoomAdmissionV1,
) -> RoomResult<AppendOrDuplicateOutcome> {
    host.command_sender()
        .and_then(|mut sender| {
            sender.append_intent_or_duplicate_bounded(
                timeline,
                identity,
                AppendIntent::new(draft),
                admission.max_events,
            )
        })
        .map_err(RoomStoreErrorV1::from)
        .and_then(|outcome| outcome.ok_or(RoomStoreErrorV1::LimitReached))
}

/// Append a revision under its ADR-041 append identity. The worker
/// serializes every room operation and appends only after the head check,
/// so the identity is always fresh here; a duplicate would mean another
/// writer, which the host does not have.
fn append_revision(
    host: &mut ErasureExecutionHostV1,
    timeline: TimelineId,
    descriptor: &ScenarioRoomDescriptorV1,
    causation: EventId,
    admission: &RoomAdmissionV1,
) -> RoomResult<RoomOutcomeV1> {
    let mut draft = EventDraft::new(
        descriptor.room_id(),
        Kind::new(ROOM_REVISION_EVENT_TYPE),
        CanonicalBytes::from_vec(descriptor.payload().to_vec()),
    );
    draft.causation_id = Some(causation);
    append_identified(
        host,
        timeline,
        descriptor.append_identity(),
        &draft,
        admission,
    )
    .and_then(|outcome| match outcome {
        AppendOrDuplicateOutcome::Appended(event) => {
            stored(host, timeline, &event).map(|stored| RoomOutcomeV1::Committed(Box::new(stored)))
        }
        _ => Err(RoomStoreErrorV1::Store(CoreError::Storage(
            "room revision identity already used".to_owned(),
        ))),
    })
}

/// The revision a claim produced, on any room's Timeline.
fn revision_caused_by(
    host: &mut ErasureExecutionHostV1,
    causation: EventId,
) -> RoomResult<Option<StoredRoomRevisionV1>> {
    host_timelines(host).and_then(|timelines| {
        timelines
            .iter()
            .filter(|timeline| timeline.meta.name.starts_with(ROOM_TIMELINE_PREFIX))
            .find_map(|room| {
                read_revision_events(host, room.id())
                    .map(|events| {
                        events
                            .into_iter()
                            .find(|event| event.causation_id == Some(causation))
                            .map(|event| (room.id(), event))
                    })
                    .transpose()
            })
            .transpose()
            .and_then(|found| {
                found
                    .map(|(timeline, event)| stored(host, timeline, &event))
                    .transpose()
            })
    })
}

/// The Timeline and revision Events of `room_id`, in revision order.
fn room_revisions(
    host: &mut ErasureExecutionHostV1,
    room_id: EntityId,
) -> RoomResult<(TimelineId, Vec<Event>)> {
    find_root(host, &format!("{ROOM_TIMELINE_PREFIX}{room_id}"))
        .and_then(|timeline| timeline.ok_or(RoomStoreErrorV1::NotFound))
        .and_then(|timeline| {
            read_revision_events(host, timeline.id()).map(|events| (timeline.id(), events))
        })
}

fn read_revision_events(
    host: &mut ErasureExecutionHostV1,
    timeline: TimelineId,
) -> RoomResult<Vec<Event>> {
    let bounds = EventReadBounds::new(
        MAX_ROOM_DESCRIPTOR_BYTES_V1,
        ROOM_REVISION_EVENT_TYPE.len(),
        0,
        usize::MAX,
    );
    host.read_sender()
        .and_then(|mut sender| sender.read_bounded(timeline, SeqRange::all(), bounds))
        .map(|events| {
            events
                .into_iter()
                .filter(|event| event.event_type.as_str() == ROOM_REVISION_EVENT_TYPE)
                .collect()
        })
        .map_err(RoomStoreErrorV1::from)
}

/// The Event of revision `revision`, counting from 1.
fn revision_at(revisions: &[Event], revision: u64) -> Option<&Event> {
    usize::try_from(revision)
        .ok()
        .and_then(|revision| revision.checked_sub(1))
        .and_then(|index| revisions.get(index))
}

fn descriptor_of(event: &Event) -> RoomResult<ScenarioRoomDescriptorV1> {
    ScenarioRoomDescriptorV1::from_payload(event.payload.as_slice()).map_err(RoomStoreErrorV1::from)
}

/// A revision Event with its commit's cursor generation and the mode
/// binding it was produced under: the profile the binding history names for
/// the epoch the commit recorded.
fn stored(
    host: &mut ErasureExecutionHostV1,
    timeline: TimelineId,
    event: &Event,
) -> RoomResult<StoredRoomRevisionV1> {
    let range = SeqRange {
        from: event.seq,
        to: Some(event.seq),
    };
    let bounds = EventReadBounds::new(
        MAX_ROOM_DESCRIPTOR_BYTES_V1,
        ROOM_REVISION_EVENT_TYPE.len(),
        0,
        1,
    );
    let generation = host
        .read_sender()
        .and_then(|mut sender| sender.read_bounded_at_generation(timeline, range, bounds, None))
        .map(|(_, generation)| generation)
        .map_err(RoomStoreErrorV1::from);
    let binding = host.gateway_mode_binding();
    let produced_under = binding
        .load_commit_epoch(timeline, event.seq)
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
                        .map(|entry| (entry.record().profile().clone(), epoch))
                })
        })
        .ok_or(RoomStoreErrorV1::ModeUnavailable);
    descriptor_of(event)
        .and_then(|descriptor| generation.map(|generation| (descriptor, generation)))
        .and_then(|(descriptor, generation)| {
            produced_under.map(|produced_under| StoredRoomRevisionV1 {
                descriptor,
                timeline,
                event_id: event.id,
                seq: event.seq,
                generation,
                produced_under,
            })
        })
}

fn host_timelines(host: &mut ErasureExecutionHostV1) -> RoomResult<Vec<Timeline>> {
    host.read_sender()
        .and_then(|mut sender| sender.timelines())
        .map_err(RoomStoreErrorV1::from)
}

fn find_root(host: &mut ErasureExecutionHostV1, name: &str) -> RoomResult<Option<Timeline>> {
    host_timelines(host).map(|timelines| {
        timelines
            .into_iter()
            .find(|timeline| timeline.meta.name == name)
    })
}

fn create_root(
    host: &mut ErasureExecutionHostV1,
    name: &str,
    admission: &RoomAdmissionV1,
) -> RoomResult<Timeline> {
    host.read_sender()
        .and_then(|mut sender| sender.root_timeline_count_bounded(admission.max_timelines))
        .map_err(RoomStoreErrorV1::from)
        .and_then(|roots| {
            if roots < admission.max_timelines {
                host.command_sender()
                    .and_then(|mut sender| sender.create_timeline(name))
                    .map_err(RoomStoreErrorV1::from)
            } else {
                Err(RoomStoreErrorV1::LimitReached)
            }
        })
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests;
