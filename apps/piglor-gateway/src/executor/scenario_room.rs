//! The Scenario Room store command (#1398, parent #303).
//!
//! Each operation runs as one command on the store worker, so the head
//! check of a derive and its append are one serialized step. A room is one
//! root Timeline named [`ROOM_TIMELINE_PREFIX`] followed by the room ID;
//! each revision is one `room.revision.v1` Event whose payload is the
//! admitted ADR-041 descriptor, appended under its ADR-041 append identity
//! (ADR-041 section 7).
//!
//! An `Idempotency-Key` is claimed on the host's request Timeline as one
//! Event whose entity is derived from the key and whose payload is the
//! request digest. Claims are looked up by that entity, not only by the
//! ADR-038 append identity, so they last as long as the Timeline (the
//! identity's retention, `APPEND_IDENTITY_RETENTION_MICROS`, does not end
//! them). A new room's ID is its claim's `EventId`, so a retry finds the
//! room, or the room Timeline an interrupted attempt left, by name.
//!
//! Everything that can refuse a request is checked before the claim commits:
//! the bound mode, the input, governance, a stale or duplicate derive and
//! the Timeline and Event ceilings. Only a host failure after the claim can
//! leave a claim without its revision; the retry then finishes it.

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

use crate::mode_profile::GatewayModeProfileIdV1;

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

/// One claimed `Idempotency-Key`: the keyed digest that names it and the
/// digest of the request it was first used with.
#[derive(Debug)]
pub(crate) struct RoomClaimV1 {
    pub(crate) key: [u8; 32],
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
    /// The profile bound at the epoch the commit recorded, its digest and
    /// that epoch.
    pub(crate) produced_under: (GatewayModeProfileIdV1, [u8; 32], NonZeroU64),
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
    /// The host reached its root-Timeline ceiling; this is permanent.
    TimelineCeiling,
    /// A room or the request Timeline reached its Event ceiling; this is
    /// permanent for that Timeline.
    EventCeiling,
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
        RoomOperationV1::Create { claim, input } => {
            require_mode(host).and_then(|()| create_room(host, &claim, *input, admission))
        }
        RoomOperationV1::Derive {
            claim,
            room_id,
            parent_revision,
            input,
        } => require_mode(host)
            .and_then(|()| derive_room(host, &claim, room_id, parent_revision, *input, admission)),
        RoomOperationV1::Read { room_id, revision } => room_revisions(host, room_id)
            .and_then(|(timeline, revisions)| existing_at(host, timeline, &revisions, revision)),
    }
}

/// The store must be bound to a known GMP1 profile before anything commits,
/// so every revision can disclose the mode it was produced under.
fn require_mode(host: &mut ErasureExecutionHostV1) -> RoomResult<()> {
    host.gateway_mode_binding()
        .load_mode_binding()
        .ok()
        .flatten()
        .and_then(|record| {
            record
                .profile()
                .profile_id()
                .parse::<GatewayModeProfileIdV1>()
                .ok()
        })
        .map(|_| ())
        .ok_or(RoomStoreErrorV1::ModeUnavailable)
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

/// The descriptor of a new room, admitted under `room_id`.
fn admit_room(
    room_id: EntityId,
    input: ScenarioRoomInputV1,
    admission: &RoomAdmissionV1,
) -> RoomResult<ScenarioRoomDescriptorV1> {
    RoomCorrelationIdV1::generate()
        .and_then(|correlation_id| {
            ScenarioRoomDescriptorV1::admit_first(
                room_id,
                correlation_id,
                input,
                &admission.catalogue,
            )
        })
        .map_err(RoomStoreErrorV1::from)
        .and_then(|descriptor| require_governance(descriptor, admission))
}

fn create_room(
    host: &mut ErasureExecutionHostV1,
    claim: &RoomClaimV1,
    input: ScenarioRoomInputV1,
    admission: &RoomAdmissionV1,
) -> RoomResult<RoomOutcomeV1> {
    // Every refusal of the input is answered before the claim.
    admit_room(EntityId::new(), input.clone(), admission)
        .and_then(|_| {
            claim_request(host, claim, admission, ClaimPlace::Requests, |host| {
                require_root_headroom(host, admission)
            })
        })
        .and_then(|causation| {
            let room_id = EntityId::from_ulid(causation.inner());
            find_root(host, &room_timeline_name(room_id)).and_then(|existing| match existing {
                // The claim's room exists: an exact retry, or a retry of an
                // attempt the host interrupted after creating its Timeline.
                Some(timeline) => read_revision_events(host, timeline.id()).and_then(|events| {
                    if events.is_empty() {
                        admit_room(room_id, input, admission).and_then(|descriptor| {
                            append_revision(host, timeline.id(), &descriptor, causation, admission)
                        })
                    } else {
                        existing_at(host, timeline.id(), &events, 1)
                    }
                }),
                None => admit_room(room_id, input, admission).and_then(|descriptor| {
                    create_root(host, &room_timeline_name(room_id), admission).and_then(
                        |timeline| {
                            append_revision(host, timeline.id(), &descriptor, causation, admission)
                        },
                    )
                }),
            })
        })
}

fn room_timeline_name(room_id: EntityId) -> String {
    format!("{ROOM_TIMELINE_PREFIX}{room_id}")
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
    let next = parent_revision.saturating_add(1);
    match revision_at(&revisions, next) {
        // `parent_revision` is not the head: the ADR-041 section 7 duplicate
        // of the revision already derived from it (which an exact retry also
        // is), or a stale proposal. Neither claims the key.
        Some(derived) => descriptor_of(derived).and_then(|derived| {
            if derived.descriptor_hash() == candidate.descriptor_hash() {
                existing_at(host, timeline, &revisions, next)
            } else {
                Err(RoomStoreErrorV1::StaleParent)
            }
        }),
        None => claim_request(host, claim, admission, ClaimPlace::Room(timeline), |_| {
            Ok(())
        })
        .and_then(|causation| append_revision(host, timeline, &candidate, causation, admission)),
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

/// Room for a new room's Timeline, and the request Timeline if it is not
/// there yet, under the host's root-Timeline ceiling.
fn require_root_headroom(
    host: &mut ErasureExecutionHostV1,
    admission: &RoomAdmissionV1,
) -> RoomResult<()> {
    find_root(host, ROOM_REQUESTS_TIMELINE)
        .and_then(|requests| {
            root_count(host, admission).map(|roots| roots + usize::from(requests.is_none()) + 1)
        })
        .and_then(|needed| {
            if needed <= admission.max_timelines {
                Ok(())
            } else {
                Err(RoomStoreErrorV1::TimelineCeiling)
            }
        })
}

fn require_event_headroom(owned: usize, admission: &RoomAdmissionV1) -> RoomResult<()> {
    if u64::try_from(owned).is_ok_and(|owned| owned < admission.max_events) {
        Ok(())
    } else {
        Err(RoomStoreErrorV1::EventCeiling)
    }
}

/// Where a claim is recorded: a room's creation claims on the host's
/// request Timeline, a derive on the room's own Timeline. Creations are
/// bounded by the root-Timeline ceiling, so the request Timeline never fills;
/// a room holds its derive claims next to its revisions.
#[derive(Clone, Copy)]
enum ClaimPlace {
    Requests,
    Room(TimelineId),
}

impl ClaimPlace {
    /// The Events a new claim adds with what it is for: a creation's claim
    /// alone (its room has its own Timeline), a derive's claim and revision.
    const fn events(self) -> usize {
        match self {
            Self::Requests => 1,
            Self::Room(_) => 2,
        }
    }
}

/// Claim `claim`'s key for its request and return the claim's `EventId`.
///
/// A key already claimed for the same request returns its claim (a retry);
/// for another request it is a conflict. A new claim commits only after the
/// Event ceiling and `headroom` admit what the request will create. The
/// lookup reads the claim Timeline once (the host has no entity index), so
/// it costs one read of at most `events_per_timeline` Events.
fn claim_request(
    host: &mut ErasureExecutionHostV1,
    claim: &RoomClaimV1,
    admission: &RoomAdmissionV1,
    place: ClaimPlace,
    headroom: impl FnOnce(&mut ErasureExecutionHostV1) -> RoomResult<()>,
) -> RoomResult<EventId> {
    // The claim acts as an entity named by its key, so claims stay apart.
    let mut entity = [0; 16];
    entity.copy_from_slice(&claim.key[..16]);
    let entity = EntityId::from_ulid(ulid::Ulid::from_bytes(entity));
    let draft = EventDraft::new(
        entity,
        Kind::new(ROOM_REQUEST_EVENT_TYPE),
        CanonicalBytes::from_vec(claim.request_digest.to_vec()),
    );
    let located = match place {
        ClaimPlace::Requests => find_root(host, ROOM_REQUESTS_TIMELINE)
            .map(|requests| requests.map(|timeline| timeline.id())),
        ClaimPlace::Room(timeline) => Ok(Some(timeline)),
    };
    located
        .and_then(|timeline| {
            timeline
                .map_or(Ok(Vec::new()), |timeline| read_all(host, timeline))
                .map(|events| (timeline, events))
        })
        .and_then(|(timeline, events)| {
            let claimed = events.iter().find(|event| {
                event.event_type.as_str() == ROOM_REQUEST_EVENT_TYPE && event.entity == entity
            });
            match claimed {
                Some(claimed) if claimed.payload.as_slice() == claim.request_digest => {
                    Ok(claimed.id)
                }
                Some(_) => Err(RoomStoreErrorV1::IdempotencyConflict),
                None => require_event_headroom(events.len() + place.events() - 1, admission)
                    .and_then(|()| headroom(host))
                    .and_then(|()| {
                        timeline.map_or_else(
                            || {
                                create_root(host, ROOM_REQUESTS_TIMELINE, admission)
                                    .map(|requests| requests.id())
                            },
                            Ok,
                        )
                    })
                    .and_then(|timeline| {
                        host.command_sender()
                            .and_then(|mut sender| {
                                sender.append_bounded(
                                    timeline,
                                    std::slice::from_ref(&draft),
                                    admission.max_events,
                                )
                            })
                            .map_err(RoomStoreErrorV1::from)
                    })
                    .and_then(|appended| {
                        appended
                            .and_then(|events| events.into_iter().next())
                            .map(|event| event.id)
                            .ok_or(RoomStoreErrorV1::EventCeiling)
                    }),
            }
        })
}

/// An append identity the worker already used: impossible while the worker
/// serializes every room operation and checks before it appends.
fn identity_reused() -> RoomStoreErrorV1 {
    RoomStoreErrorV1::Store(CoreError::Storage(
        "scenario room append identity already used".to_owned(),
    ))
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
        .and_then(|outcome| outcome.ok_or(RoomStoreErrorV1::EventCeiling))
}

/// Append a revision under its ADR-041 append identity.
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
        _ => Err(identity_reused()),
    })
}

/// The Timeline and revision Events of `room_id`, in revision order.
fn room_revisions(
    host: &mut ErasureExecutionHostV1,
    room_id: EntityId,
) -> RoomResult<(TimelineId, Vec<Event>)> {
    find_root(host, &room_timeline_name(room_id))
        .and_then(|timeline| timeline.ok_or(RoomStoreErrorV1::NotFound))
        .and_then(|timeline| {
            read_revision_events(host, timeline.id()).map(|events| (timeline.id(), events))
        })
}

fn read_revision_events(
    host: &mut ErasureExecutionHostV1,
    timeline: TimelineId,
) -> RoomResult<Vec<Event>> {
    read_events(
        host,
        timeline,
        ROOM_REVISION_EVENT_TYPE,
        MAX_ROOM_DESCRIPTOR_BYTES_V1,
    )
}

/// Every Event of `event_type` on `timeline`, in Timeline Order.
fn read_events(
    host: &mut ErasureExecutionHostV1,
    timeline: TimelineId,
    event_type: &str,
    payload_bytes: usize,
) -> RoomResult<Vec<Event>> {
    let bounds = EventReadBounds::new(payload_bytes, event_type.len(), 0, usize::MAX);
    host.read_sender()
        .and_then(|mut sender| sender.read_bounded(timeline, SeqRange::all(), bounds))
        .map(|events| {
            events
                .into_iter()
                .filter(|event| event.event_type.as_str() == event_type)
                .collect()
        })
        .map_err(RoomStoreErrorV1::from)
}

/// Every Event of a room or the request Timeline: revisions and claims.
fn read_all(host: &mut ErasureExecutionHostV1, timeline: TimelineId) -> RoomResult<Vec<Event>> {
    let bounds = EventReadBounds::new(
        MAX_ROOM_DESCRIPTOR_BYTES_V1,
        ROOM_REVISION_EVENT_TYPE.len(),
        0,
        usize::MAX,
    );
    host.read_sender()
        .and_then(|mut sender| sender.read_bounded(timeline, SeqRange::all(), bounds))
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
                        .and_then(|entry| {
                            let profile = entry.record().profile();
                            profile
                                .profile_id()
                                .parse::<GatewayModeProfileIdV1>()
                                .ok()
                                .map(|id| (id, profile.profile_digest(), epoch))
                        })
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

/// The root Timeline named `name`. The host has no name index, so this lists
/// its Timelines, at most the root-Timeline ceiling of them.
fn find_root(host: &mut ErasureExecutionHostV1, name: &str) -> RoomResult<Option<Timeline>> {
    host_timelines(host).map(|timelines| {
        timelines
            .into_iter()
            .find(|timeline| timeline.meta.name.as_deref() == Some(name))
    })
}

fn root_count(host: &mut ErasureExecutionHostV1, admission: &RoomAdmissionV1) -> RoomResult<usize> {
    host.read_sender()
        .and_then(|mut sender| sender.root_timeline_count_bounded(admission.max_timelines))
        .map_err(RoomStoreErrorV1::from)
}

fn create_root(
    host: &mut ErasureExecutionHostV1,
    name: &str,
    admission: &RoomAdmissionV1,
) -> RoomResult<Timeline> {
    root_count(host, admission).and_then(|roots| {
        if roots < admission.max_timelines {
            host.command_sender()
                .and_then(|mut sender| sender.create_timeline(name))
                .map_err(RoomStoreErrorV1::from)
        } else {
            Err(RoomStoreErrorV1::TimelineCeiling)
        }
    })
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests;
