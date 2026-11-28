//! The backend-neutral pre-Reserve observation materialization preparer
//! (#560 A4b'; ADR-129 revision 9, R9.2–R9.7 and R9.10).
//!
//! The runtime projection publisher folds the complete prefix outside every
//! writer and hands the store one seal-gated
//! [`CommunityObservationMaterializationV1`]: the cut, its rows, the reducer
//! bindings, one erasure Timeline scope reference per owning Timeline and the
//! observation bytes. It carries no CPE1, COV1, CES1 or trusted digest. The
//! fold result itself stays a trusted-code assumption (R9.6).
//!
//! Preparation has two stages, both called from the Reserve pipeline (A4c):
//!
//! 1. [`prepare_community_observation_v1`] re-checks the cut against the
//!    domain's own Event history (rows, stitched chain and Logical Head), the
//!    pinned source catalogue and the installed observation encoder, runs the
//!    deterministic fold-cost check, and mints one CES1 per row and the COV1;
//! 2. [`CommunityObservationSourcesV1::finish`] takes the CES1 registration
//!    addresses that protection derived, the allocated producer ordinal and
//!    the materialization's CSB1/CPV1 digests, and mints the CPE1 and the
//!    Observation CPN1 with its input-index groups.
//!
//! The CES1 field values follow the owner decisions of 2026-11-21 (#560):
//! the owner reference of the pass's `(T, G)`, the chain hash `h_seq` as the
//! envelope digest, one whole-Timeline scope row, the CDP1
//! `source_catalogue_digest` as the admitted policy, no key dependencies for
//! a plaintext native Event, and the CDP1 `generation_not_after` horizon.
//! Nothing here commits, protects or reuses a record: Reserve (A4c) does.

use std::collections::BTreeSet;
use std::time::Duration;

use pos_core::community_lifecycle::{
    community_catalogue_owner_reference_v1, community_event_source_authority_digest_v1,
    community_observation_materialization_id_v1, ArtifactRefV1, CommunityContentReferenceV1,
    CommunityDurableProfileV1, CommunityEventSourceInputV1, CommunityEventSourceRefV1,
    CommunityEventSourceV1, CommunityInputGroupInputV1, CommunityInputGroupV1,
    CommunityInputIndexV1, CommunityLifecycleErrorV1 as Error, CommunityNativeNodeInputV1,
    CommunityNativeNodeKindV1, CommunityNativeNodeReferenceV1, CommunityNativeNodeReferencesV1,
    CommunityNativeNodeV1, CommunityObservationEventRowV1, CommunityObservationSourceInputV1,
    CommunityObservationSourceV1, CommunityObservationValueInputV1, CommunityObservationValueV1,
    CommunityPassGraphTermsV1, CommunityPassObservationV1, CommunityPassTermsV1,
    CommunityProtectionSizesV1, CommunityReducerBindingV1, CommunityScopeMemberV1,
    CommunityScopeMembersV1, CommunitySourceCatalogueV1, CommunityTypedInputRefV1,
    CommunityTypedInputRefsV1, COMMUNITY_FOLD_BUDGET_MICROS_V1,
    COMMUNITY_NATIVE_EVENT_EXTRACTOR_RULE_V1, MAX_COMMUNITY_DIRECT_INPUTS_V1,
    MAX_COMMUNITY_OBSERVATION_EVENTS_V1, MAX_COMMUNITY_RECORDED_CONSUMERS_V1,
    MAX_COMMUNITY_SOURCE_RULE_TEXT_BYTES_V1, MAX_STAGED_CALLBACK_BOUND_V1,
};
use pos_core::store::{EventReadBounds, EventStore, SeqRange};
use pos_core::{
    AuthorityTrustRootSealV1, CoreError, Event, Hash, Hasher, RecordedDependencyClassV1, Seq,
    TimelineId,
};
use zeroize::Zeroizing;

use super::private_hash::scope_set_digest;
use super::store_domain::CommunityStoreDomainV1;

/// One prefix Event as the publisher folded it (R9.6).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CommunityObservationEventV1 {
    /// The Timeline that committed the Event (R9.10).
    pub owning_timeline: TimelineId,
    /// The Event's sequence, in the cut's logical order.
    pub logical_seq: u64,
    /// Committed Event identity.
    pub event_id: [u8; 16],
    /// Committed payload hash.
    pub payload_hash: Hash,
}

/// One recorded consumer: its R9.4 reducer row and admitted callback bound.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CommunityObservationConsumerV1 {
    /// The staged catalogue's reducer row.
    pub binding: CommunityReducerBindingV1,
    /// The consumer's admitted per-callback bound (ADR-113).
    pub callback_bound: Duration,
}

/// The publisher's per-call materialization data.
pub struct CommunityObservationMaterializationInputV1 {
    /// Execution Timeline T.
    pub timeline: TimelineId,
    /// The folded cut: T's Logical Head, 0 for empty history.
    pub through_seq: u64,
    /// One Event per prefix sequence, in order.
    pub events: Vec<CommunityObservationEventV1>,
    /// The recorded consumers, in reducer-row order.
    pub consumers: Vec<CommunityObservationConsumerV1>,
    /// Exactly one erasure Timeline scope reference per owning Timeline U
    /// (T and every Fork-prefix owner), from the runtime erasure host's
    /// topology resolver (owner 2026-11-21 (#560)).
    pub timeline_scopes: Vec<(TimelineId, Hash)>,
    /// The installed observation encoder's artifact reference.
    pub observation_artifact_ref: ArtifactRefV1,
    /// The exact folded observation bytes.
    pub observation_bytes: Zeroizing<Vec<u8>>,
}

/// The seal-gated per-call observation input (R9.6, A5.9). It is data, not a
/// trust root: the store re-checks every fact it can bind before minting.
pub struct CommunityObservationMaterializationV1(CommunityObservationMaterializationInputV1);

impl CommunityObservationMaterializationV1 {
    /// Wrap the publisher's data. Only a holder of the composition root's
    /// seal, the runtime projection publisher, can build it (I61):
    ///
    /// ```compile_fail,E0061
    /// use pos_store::community::{
    ///     CommunityObservationMaterializationInputV1, CommunityObservationMaterializationV1,
    /// };
    /// fn forge(input: CommunityObservationMaterializationInputV1) {
    ///     let _ = CommunityObservationMaterializationV1::new(input);
    /// }
    /// ```
    #[must_use]
    pub const fn new(
        _seal: &'static AuthorityTrustRootSealV1,
        input: CommunityObservationMaterializationInputV1,
    ) -> Self {
        Self(input)
    }
}

/// Installed composition inputs of the preparer. None comes from a caller.
#[derive(Clone, Copy)]
pub struct CommunityObservationInstallationV1<'a> {
    /// The installed CDP1.
    pub profile: &'a CommunityDurableProfileV1<'a>,
    /// The installed closed source catalogue; its digest must be the CDP1's.
    pub source_catalogue: CommunitySourceCatalogueV1<'a>,
    /// The installed observation encoder's schema ID. Only the schema is
    /// checked (R9.6): the reference digest is not tied to the observation
    /// bytes here, which is a trust assumption on the runtime publisher.
    pub observation_schema_id: u32,
}

/// The pass the observation serves.
#[derive(Clone, Copy)]
pub struct CommunityObservationPassV1 {
    /// Pass generation G.
    pub generation: [u8; 16],
    /// The Reserve operation identity that `M_id` derives from.
    pub reservation_operation_id: [u8; 16],
}

/// One minted CES1 with its row facts.
struct MintedSource {
    logical_seq: u64,
    event_id: [u8; 16],
    payload_hash: Hash,
    bytes: Zeroizing<Vec<u8>>,
    digest: Hash,
    scope_binding_digest: Hash,
    member: CommunityScopeMemberV1,
}

/// Stage-1 output: the re-checked cut with its CES1s and COV1.
pub struct CommunityObservationSourcesV1 {
    timeline: TimelineId,
    generation: [u8; 16],
    operation_id: [u8; 16],
    through_seq: u64,
    owner_reference: Hash,
    owning_timelines: Vec<TimelineId>,
    genesis: Option<(TimelineId, Hash)>,
    sources: Vec<MintedSource>,
    scope_union_digest: Hash,
    consumers: Vec<CommunityReducerBindingV1>,
    observation_value: Zeroizing<Vec<u8>>,
    observation_value_digest: Hash,
    evidence_not_after_micros: u64,
}

/// The materialization's share of a pass quote (ADR-129 revisions 10 and
/// 11).
pub struct CommunityObservationQuoteV1 {
    /// The R10.3(5) Observation row and the Observation CPN1's node ordinal.
    pub observation: CommunityPassObservationV1,
    /// What the materialization adds to T's ARD1 closure (R11.3(3)).
    pub graph: CommunityPassGraphTermsV1,
    /// The store keys it provisions (R11.1(4)).
    pub keys: u64,
    /// The ARD1 rows it binds to T: its closure records and the CPE1, which
    /// is outside the closure (ADR-129 revision 13, R13.1(3)).
    pub erasure_rows: u64,
    /// Its Observation CPN1's scope rows (R11.4(2)).
    pub scope: Vec<CommunityScopeMemberV1>,
}

/// Stage-2 inputs from the Reserve pipeline (A4c).
#[derive(Clone, Copy)]
pub struct CommunityObservationBindingsV1<'a> {
    /// The domain's store incarnation.
    pub store_incarnation: [u8; 16],
    /// The materialization's allocated native producer ordinal.
    pub producer_ordinal: u64,
    /// The CES1 ARD1 registration address of each row, in row order.
    pub source_registrations: &'a [Hash],
    /// The materialization's CSB1 digest.
    pub scope_binding_digest: Hash,
    /// The materialization's CPV1 digest.
    pub provenance_digest: Hash,
    /// One `[U, request_digest]` Event-history `read` row per owning
    /// Timeline, sorted by U (R9.5).
    pub authority_rows: &'a [(TimelineId, Hash)],
}

/// One canonical CIB1 group with its `InputIndex` CPN1.
type MintedGroup = (Zeroizing<Vec<u8>>, Zeroizing<Vec<u8>>);

/// One minted CPN1: its canonical bytes and reference.
type MintedNode = (Zeroizing<Vec<u8>>, CommunityNativeNodeReferenceV1);

/// Stage-2 output: the CPE1 and the Observation CPN1 with its groups.
pub struct CommunityObservationRecordsV1 {
    /// Canonical CPE1.
    pub source_proof: Zeroizing<Vec<u8>>,
    /// `H(CPE1)`, the materialization's `input_identity`.
    pub source_proof_digest: Hash,
    /// Canonical CIB1 groups with their `InputIndex` CPN1s, in node order.
    pub input_groups: Vec<MintedGroup>,
    /// Canonical Observation CPN1, the producer's last node.
    pub observation_node: Zeroizing<Vec<u8>>,
    /// The Observation CPN1 reference.
    pub observation_reference: CommunityNativeNodeReferenceV1,
}

/// Stage 1: re-check the cut and mint its CES1s and COV1.
///
/// The three history reads (Logical Head, Events and chain hashes) are not
/// one atomic snapshot: the Reserve writer's Logical Head and chain-head
/// compare (R9.7 step 6, A4c) is the guard against a cut that moves.
///
/// # Errors
/// Returns `EvidenceUnavailable` for a consumer list that is not 1..=64
/// strictly ordered consumers with nonzero bounds of at most 250 ms;
/// `CapacityExhausted` for more than 4,096 Events, a deterministic fold cost
/// over the CDP1 `fold_budget_micros`, before any re-check, or an Event read
/// over the payload or total-byte read bounds; `EvidenceUnavailable`
/// when the cut is not T's Logical Head, a row, owner or
/// the stitched chain differs from the domain's history, the catalogue or
/// encoder is not the installed one, an Event type has no pinned native-event
/// row, or the scope references are not exactly one nonzero ref per owning
/// Timeline; and the record errors of CES1 and COV1.
pub fn prepare_community_observation_v1<D: CommunityStoreDomainV1>(
    domain: &D,
    installation: CommunityObservationInstallationV1<'_>,
    pass: CommunityObservationPassV1,
    materialization: &CommunityObservationMaterializationV1,
) -> Result<CommunityObservationSourcesV1, Error> {
    let input = &materialization.0;
    check_materialization_id(domain, input.timeline, pass.reservation_operation_id)
        .and_then(|()| check_consumers(input))
        .and_then(|()| check_capacity(input))
        .and_then(|()| check_installation(installation, input))
        .and_then(|()| {
            let (events, hasher) = domain.event_history();
            recheck_history(events, hasher, EVENT_READ_BOUNDS, input)
        })
        .and_then(|history| mint_sources(installation, pass, input, &history))
}

/// R10.7 5f, first: the materialization's `M_id` must not equal a committed
/// control identity of T (R9.7, I251). It gives 4 before any history read,
/// fold-cost check or store re-check, and the caller retries under a new
/// `reservation_operation_id`.
fn check_materialization_id<D: CommunityStoreDomainV1>(
    domain: &D,
    timeline: TimelineId,
    reservation_operation_id: [u8; 16],
) -> Result<(), Error> {
    community_observation_materialization_id_v1(timeline, reservation_operation_id).and_then(
        |identity| {
            if domain.control_identity_used(timeline, identity) {
                Err(Error::Conflict)
            } else {
                Ok(())
            }
        },
    )
}

/// The history read bounds (owner 2026-11-21, #560): at most 4,096 Events
/// (CPE1), an Event type of at most 128 bytes (CES1), a 1 MiB payload per
/// Event, 1 GiB read in total and a Fork depth of 64. The publisher's fold
/// reads under the same bounds.
pub(super) const EVENT_READ_BOUNDS: EventReadBounds = EventReadBounds::new_with_total_bytes(
    1 << 20,
    MAX_COMMUNITY_SOURCE_RULE_TEXT_BYTES_V1,
    64,
    MAX_COMMUNITY_OBSERVATION_EVENTS_V1,
    1 << 30,
);

/// The sealed consumer list must be an admitted recorded set before its
/// bounds are trusted for the fold cost: 1..=64 consumers, strictly
/// ascending by consumer identity, each with a nonzero bound of at most
/// 250 ms (R9.4, R9.7(a)).
fn check_consumers(input: &CommunityObservationMaterializationInputV1) -> Result<(), Error> {
    let consumers = &input.consumers;
    if (1..=MAX_COMMUNITY_RECORDED_CONSUMERS_V1).contains(&consumers.len())
        && consumers.windows(2).all(|pair| {
            pair[0].binding.consumer_identity_digest < pair[1].binding.consumer_identity_digest
        })
        && consumers.iter().all(|consumer| {
            !consumer.callback_bound.is_zero()
                && consumer.callback_bound <= MAX_STAGED_CALLBACK_BOUND_V1
        })
    {
        Ok(())
    } else {
        Err(Error::EvidenceUnavailable)
    }
}

/// The deterministic pre-fold checks (R9.7(a), N13): the 4,096-row bound and
/// Σ over consumers of (rows + 1) × callback bound within the fold budget,
/// summed in nanoseconds and rounded up to whole microseconds.
fn check_capacity(input: &CommunityObservationMaterializationInputV1) -> Result<(), Error> {
    let rows = u128::from(input.through_seq);
    let nanos = input
        .consumers
        .iter()
        .map(|consumer| (rows + 1) * consumer.callback_bound.as_nanos())
        .sum::<u128>();
    if input.through_seq > MAX_COMMUNITY_OBSERVATION_EVENTS_V1 as u64
        || nanos.div_ceil(1_000) > u128::from(COMMUNITY_FOLD_BUDGET_MICROS_V1)
    {
        Err(Error::CapacityExhausted)
    } else {
        Ok(())
    }
}

fn check_installation(
    installation: CommunityObservationInstallationV1<'_>,
    input: &CommunityObservationMaterializationInputV1,
) -> Result<(), Error> {
    if installation.source_catalogue.digest()
        == installation.profile.as_input().source_catalogue_digest
        && input.observation_artifact_ref.schema_id == installation.observation_schema_id
    {
        Ok(())
    } else {
        Err(Error::EvidenceUnavailable)
    }
}

/// The domain's own facts of the cut: each Event with its chain hash
/// `h_seq` and owning Timeline, and the Fork chain's root genesis.
struct History {
    events: Vec<(Event, Hash, TimelineId)>,
    genesis: (TimelineId, Hash),
}

/// Re-read the stitched prefix, re-derive every chain hash from the pinned
/// Hasher's genesis and compare rows, owners and the Logical Head (R9.6,
/// R9.10).
fn recheck_history(
    events: &dyn EventStore,
    hasher: &dyn Hasher,
    bounds: EventReadBounds,
    input: &CommunityObservationMaterializationInputV1,
) -> Result<History, Error> {
    fork_segments(events, input.timeline, bounds.max_fork_depth()).and_then(|segments| {
        let root = segments[0].0;
        let genesis = hasher.genesis_hash();
        let stored = match events.read_bounded(
            input.timeline,
            SeqRange {
                from: Seq::from_u64(1),
                to: Some(Seq::from_u64(input.through_seq)),
            },
            bounds,
        ) {
            Ok(stored) => Some(chain(hasher, genesis, &segments, stored)),
            Err(CoreError::PayloadTooLarge { .. } | CoreError::ReadBytesTooLarge { .. }) => {
                return Err(Error::CapacityExhausted);
            }
            Err(_) => None,
        };
        let head = events.logical_head(input.timeline).ok();
        let tip = events
            .chain_hash_at(input.timeline, Seq::from_u64(input.through_seq))
            .ok();
        let base = events.chain_hash_at(root, Seq::ZERO).ok();
        match (head, stored, tip, base) {
            (Some(head), Some(stored), Some(tip), Some(base))
                if head.as_u64() == input.through_seq
                    && stored.len() == input.events.len()
                    && base == genesis
                    && stored.last().map_or(genesis, |(_, hash, _)| *hash) == tip =>
            {
                let history = History {
                    events: stored,
                    genesis: (root, genesis),
                };
                compare_rows(&history, input).map(|()| history)
            }
            _ => Err(Error::EvidenceUnavailable),
        }
    })
}

/// `(segment Timeline, first owned seq)` from the Fork chain's root down to
/// T. A chain of more than `max_depth` Forks, which includes any cyclic
/// ancestry, is refused.
pub(super) fn fork_segments(
    events: &dyn EventStore,
    timeline: TimelineId,
    max_depth: usize,
) -> Result<Vec<(TimelineId, u64)>, Error> {
    let mut segments = Vec::new();
    let mut current = Some(timeline);
    while let Some(id) = current {
        if segments.len() > max_depth {
            return Err(Error::EvidenceUnavailable);
        }
        current = events
            .get_timeline(id)
            .ok()
            .flatten()
            .map(|found| {
                let fork = found.meta.fork_point;
                let start = fork.map_or(1, |(_, at)| at.as_u64() + 1);
                segments.push((id, start));
                fork.map(|(parent, _)| parent)
            })
            .ok_or(Error::EvidenceUnavailable)?;
    }
    segments.reverse();
    Ok(segments)
}

/// Fold the chain from genesis. Each Event's `h_seq` is its envelope digest
/// (owner 2026-11-21 (#560), item (b)); its owner is the deepest segment
/// that starts at or before its sequence.
fn chain(
    hasher: &dyn Hasher,
    genesis: Hash,
    segments: &[(TimelineId, u64)],
    stored: Vec<Event>,
) -> Vec<(Event, Hash, TimelineId)> {
    let mut previous = genesis;
    stored
        .into_iter()
        .map(|event| {
            previous =
                hasher.hash_event(&previous, event.id.to_string().as_bytes(), &event.payload);
            let seq = event.seq.as_u64();
            let owner =
                segments.iter().fold(
                    segments[0].0,
                    |owner, (segment, start)| {
                        if *start <= seq {
                            *segment
                        } else {
                            owner
                        }
                    },
                );
            (event, previous, owner)
        })
        .collect()
}

fn compare_rows(
    history: &History,
    input: &CommunityObservationMaterializationInputV1,
) -> Result<(), Error> {
    let equal = history.events.iter().zip(&input.events).zip(1_u64..).all(
        |(((event, _, owner), row), seq)| {
            event.seq.as_u64() == seq
                && row.logical_seq == seq
                && row.owning_timeline == *owner
                && row.event_id == event.id.inner().to_bytes()
                && row.payload_hash == event.payload_hash
        },
    );
    let mut owners: BTreeSet<[u8; 16]> = history
        .events
        .iter()
        .map(|(_, _, owner)| owner.inner().to_bytes())
        .collect();
    owners.insert(input.timeline.inner().to_bytes());
    let scopes: BTreeSet<[u8; 16]> = input
        .timeline_scopes
        .iter()
        .map(|(timeline, _)| timeline.inner().to_bytes())
        .collect();
    if equal
        && scopes == owners
        && scopes.len() == input.timeline_scopes.len()
        && input
            .timeline_scopes
            .iter()
            .all(|(_, scope)| *scope != Hash::zero())
    {
        Ok(())
    } else {
        Err(Error::EvidenceUnavailable)
    }
}

/// The fixed CES1 facts every row of one materialization shares.
struct Shared<'a> {
    installation: CommunityObservationInstallationV1<'a>,
    input: &'a CommunityObservationMaterializationInputV1,
    owner_reference: Hash,
    lease_reference: Hash,
    horizon: u64,
}

impl Shared<'_> {
    /// The owner's whole-Timeline scope row (owner 2026-11-21 (#560), item
    /// (c)). Every owner has exactly one scope ref, re-checked before.
    ///
    /// The lease reference `H("RetentionPolicy", retention_bytes)` names the
    /// generation's admitted retention policy, which is a native Event's
    /// lease: a reader resolves it by recomputing the digest from the
    /// installed CDP1 retention bytes (owner 2026-11-21, #560).
    fn scope_member(&self, owner: TimelineId) -> CommunityScopeMemberV1 {
        let scope_reference = self
            .input
            .timeline_scopes
            .iter()
            .find(|(timeline, _)| *timeline == owner)
            .map_or(Hash::zero(), |(_, scope)| *scope);
        CommunityScopeMemberV1 {
            scope_reference,
            source_timeline: owner,
            owner_reference: self.owner_reference,
            retention_lease_reference: self.lease_reference,
            not_after_micros: self.horizon,
        }
    }

    /// Mint one row's CES1 through the pinned native-event rule.
    fn source(
        &self,
        event: &Event,
        envelope: Hash,
        owner: TimelineId,
    ) -> Result<MintedSource, Error> {
        let member = self.scope_member(owner);
        let catalogue = self.installation.source_catalogue;
        scope_digest(&[member]).and_then(|scope_binding_digest| {
            catalogue
                .rule(event.event_type.as_str(), event.schema_version.as_u32())
                .filter(|rule| {
                    (rule.extractor_rule, rule.extractor_rule_version)
                        == COMMUNITY_NATIVE_EVENT_EXTRACTOR_RULE_V1
                })
                .ok_or(Error::EvidenceUnavailable)
                .and_then(|rule| {
                    CommunityEventSourceV1::new(CommunityEventSourceInputV1 {
                        timeline: owner,
                        logical_seq: event.seq.as_u64(),
                        event_id: event.id.inner().to_bytes(),
                        payload_hash: event.payload_hash,
                        event_envelope_digest: envelope,
                        owner_reference: self.owner_reference,
                        source_scope_binding_digest: scope_binding_digest,
                        source_schema_rule: rule,
                        required_key_dependencies: Vec::new(),
                        admitted_policy_digest: self
                            .installation
                            .profile
                            .as_input()
                            .source_catalogue_digest,
                        evidence_not_after_micros: self.horizon,
                    })
                })
                .map(|source| MintedSource {
                    logical_seq: event.seq.as_u64(),
                    event_id: event.id.inner().to_bytes(),
                    payload_hash: event.payload_hash,
                    bytes: source.to_canonical_cbor(),
                    digest: source.digest(),
                    scope_binding_digest,
                    member,
                })
        })
    }
}

/// `H("ScopeSet", preferred array of the sorted, distinct rows)` (§3).
fn scope_digest(members: &[CommunityScopeMemberV1]) -> Result<Hash, Error> {
    let mut members = members.to_vec();
    let key = |member: &CommunityScopeMemberV1| {
        (
            member.scope_reference,
            member.source_timeline.inner().to_bytes(),
            member.owner_reference,
            member.retention_lease_reference,
        )
    };
    members.sort_by_key(key);
    members.dedup_by_key(|member| key(member));
    CommunityScopeMembersV1::from_members(&members)
        .to_canonical_cbor()
        .map(|rows| scope_set_digest(&rows))
}

/// Mint one CES1 per Event and the COV1 under `M_id`.
fn mint_sources(
    installation: CommunityObservationInstallationV1<'_>,
    pass: CommunityObservationPassV1,
    input: &CommunityObservationMaterializationInputV1,
    history: &History,
) -> Result<CommunityObservationSourcesV1, Error> {
    let horizon = installation
        .profile
        .as_input()
        .retention
        .generation_not_after_micros;
    community_catalogue_owner_reference_v1(input.timeline, pass.generation)
        .and_then(|owner_reference| {
            community_observation_materialization_id_v1(
                input.timeline,
                pass.reservation_operation_id,
            )
            .map(|operation_id| (owner_reference, operation_id))
        })
        .and_then(|(owner_reference, operation_id)| {
            let shared = Shared {
                installation,
                input,
                owner_reference,
                lease_reference: installation.profile.retention_policy_digest(),
                horizon,
            };
            history
                .events
                .iter()
                .map(|(event, envelope, owner)| shared.source(event, *envelope, *owner))
                .collect::<Result<Vec<_>, Error>>()
                .and_then(|sources| {
                    let members: Vec<_> = sources.iter().map(|source| source.member).collect();
                    scope_digest(&members).map(|union| (sources, union))
                })
                .and_then(|(sources, scope_union_digest)| {
                    CommunityObservationValueV1::new(CommunityObservationValueInputV1 {
                        timeline: input.timeline,
                        generation: pass.generation,
                        operation_id,
                        observation_artifact_ref: input.observation_artifact_ref,
                        observation_bytes: &input.observation_bytes,
                    })
                    .map(|value| CommunityObservationSourcesV1 {
                        timeline: input.timeline,
                        generation: pass.generation,
                        operation_id,
                        through_seq: input.through_seq,
                        owner_reference,
                        owning_timelines: owning_timelines(input),
                        genesis: sources.is_empty().then_some(history.genesis),
                        sources,
                        scope_union_digest,
                        consumers: input
                            .consumers
                            .iter()
                            .map(|consumer| consumer.binding)
                            .collect(),
                        observation_value: value.to_canonical_cbor(),
                        observation_value_digest: value.digest(),
                        evidence_not_after_micros: horizon,
                    })
                })
        })
}

/// The owning Timelines in byte order: the R9.5 `read` rows' order.
fn owning_timelines(input: &CommunityObservationMaterializationInputV1) -> Vec<TimelineId> {
    let mut timelines: Vec<TimelineId> = input
        .timeline_scopes
        .iter()
        .map(|(timeline, _)| *timeline)
        .collect();
    timelines.sort_by_key(|timeline| timeline.inner().to_bytes());
    timelines
}

impl CommunityObservationSourcesV1 {
    /// `M_id`, the materialization's control identity.
    #[must_use]
    pub const fn operation_id(&self) -> [u8; 16] {
        self.operation_id
    }

    /// The canonical CES1 of each row, in row order, for protection.
    pub fn event_sources(&self) -> impl Iterator<Item = &[u8]> + '_ {
        self.sources.iter().map(|source| source.bytes.as_slice())
    }

    /// The canonical COV1.
    #[must_use]
    pub fn observation_value(&self) -> &[u8] {
        &self.observation_value
    }

    /// `H(COV1)`.
    #[must_use]
    pub const fn observation_value_digest(&self) -> Hash {
        self.observation_value_digest
    }

    /// The sorted owning Timelines whose `read` decisions R9.5 requires.
    #[must_use]
    pub fn owning_timelines(&self) -> &[TimelineId] {
        &self.owning_timelines
    }

    /// The materialization's share of the pass quote (ADR-129 revisions 10
    /// and 11), measured by running stage 2 on fixed-width placeholders, with
    /// the unallocated producer ordinal at its widest form (R10.3(3)). The
    /// records are measured and never kept.
    ///
    /// Its R10.3(5) Observation row is an upper bound: it counts every row's
    /// CES1, including one the Reserve pipeline reuses (R9.2), so it never
    /// under-quotes. Its closure additions count only the CES1s not yet in
    /// the closure: `retained` says whether a CES1 with this logical digest
    /// is already in T's selected closure (the R11.3(3) closure index).
    ///
    /// # Errors
    /// The record errors of stage 2.
    pub fn quote_terms(
        &self,
        sizes: &CommunityProtectionSizesV1,
        retained: impl Fn(Hash) -> bool,
    ) -> Result<CommunityObservationQuoteV1, Error> {
        let placeholder = Hash::from_bytes([0xff; 32]);
        let registrations = vec![placeholder; self.sources.len()];
        let authority: Vec<_> = self
            .owning_timelines
            .iter()
            .map(|timeline| (*timeline, placeholder))
            .collect();
        self.finish(CommunityObservationBindingsV1 {
            store_incarnation: [0xff; 16],
            producer_ordinal: u64::MAX,
            source_registrations: &registrations,
            scope_binding_digest: placeholder,
            provenance_digest: placeholder,
            authority_rows: &authority,
        })
        .map(|records| {
            let fresh: Vec<&MintedSource> = self
                .sources
                .iter()
                .filter(|source| !retained(source.digest))
                .collect();
            let graph = self.closure_terms(sizes, &records, &fresh);
            CommunityObservationQuoteV1 {
                observation: self.observation_row(&records),
                graph,
                keys: self.cohort_keys(&fresh),
                erasure_rows: graph.registrations + 1,
                scope: self.scope_rows(),
            }
        })
    }

    /// The R10.3(5) Observation row: `1 + g(r')` nodes, `r' + g(r')` edges
    /// and the bytes of the COV1, every row's CES1, the CPE1 and every CIB1
    /// and CPN1.
    fn observation_row(
        &self,
        records: &CommunityObservationRecordsV1,
    ) -> CommunityPassObservationV1 {
        let groups = records.input_groups.len() as u64;
        let bytes = self
            .sources
            .iter()
            .map(|source| source.bytes.len())
            .chain(
                records
                    .input_groups
                    .iter()
                    .map(|(group, node)| group.len() + node.len()),
            )
            .sum::<usize>()
            + self.observation_value.len()
            + records.source_proof.len()
            + records.observation_node.len();
        CommunityPassObservationV1 {
            terms: CommunityPassTermsV1 {
                nodes: 1 + groups,
                edges: self.sources.len().max(1) as u64 + groups,
                bytes: bytes as u64,
            },
            node_ordinal: records.observation_reference.node_ordinal,
        }
    }

    /// The R11.3(3) closure additions under the R11.2(4) child lists: each
    /// CES1 not yet in the closure and the COV1 with no children, the
    /// Observation CPN1 → COV1 and its CES1s (or its groups), and each
    /// `InputIndex` CPN1 → its CIB1 and leaves. CPE1 is outside the closure.
    /// The keys are the cohorts whose records join it (R11.1(4)).
    fn closure_terms(
        &self,
        sizes: &CommunityProtectionSizesV1,
        records: &CommunityObservationRecordsV1,
        fresh: &[&MintedSource],
    ) -> CommunityPassGraphTermsV1 {
        let leaves = self.sources.len() as u64;
        let observation_children = if records.input_groups.is_empty() {
            1 + leaves
        } else {
            1 + records.input_groups.len() as u64
        };
        let groups = records
            .input_groups
            .iter()
            .zip(self.sources.chunks(MAX_COMMUNITY_DIRECT_INPUTS_V1))
            .fold(
                CommunityPassGraphTermsV1::default(),
                |total, ((group, node), chunk)| {
                    total
                        .plus(sizes.record(group.len() as u64, 0))
                        .plus(sizes.record(node.len() as u64, 1 + chunk.len() as u64))
                },
            );
        fresh
            .iter()
            .fold(groups, |total, source| {
                total.plus(sizes.record(source.bytes.len() as u64, 0))
            })
            .plus(sizes.record(self.observation_value.len() as u64, 0))
            .plus(sizes.record(records.observation_node.len() as u64, observation_children))
            .plus(CommunityPassGraphTermsV1 {
                keys: self.cohort_keys(fresh) - 1,
                ..CommunityPassGraphTermsV1::default()
            })
    }

    /// The materialization's store keys (R11.1(4)): its metadata key, one
    /// CES1 cohort per owning Timeline with a new CES1, and the union
    /// cohort unless it equals the one CES1 cohort's set.
    fn cohort_keys(&self, fresh: &[&MintedSource]) -> u64 {
        let cohorts: BTreeSet<_> = fresh
            .iter()
            .map(|source| source.member.source_timeline.inner().to_bytes())
            .collect();
        let rows: BTreeSet<_> = self
            .sources
            .iter()
            .map(|source| source.member.source_timeline.inner().to_bytes())
            .collect();
        let union = u64::from(!(rows.len() == 1 && cohorts.len() == 1));
        1 + cohorts.len() as u64 + union
    }

    /// The materialization's scope rows: the distinct rows of its CPE1 rows
    /// (`[]` for an empty cut), the scope of its Observation CPN1 (R11.4(2)).
    fn scope_rows(&self) -> Vec<CommunityScopeMemberV1> {
        let mut rows: Vec<CommunityScopeMemberV1> = Vec::new();
        for source in &self.sources {
            if !rows.contains(&source.member) {
                rows.push(source.member);
            }
        }
        rows
    }

    /// Stage 2: mint the CPE1 and the Observation CPN1 with its groups.
    ///
    /// # Errors
    /// Returns `InvalidBinding` when the registrations do not match the rows
    /// or the authority rows are not exactly one per owning Timeline, and the
    /// record errors of CPE1, CIB1 and CPN1.
    pub fn finish(
        &self,
        bindings: CommunityObservationBindingsV1<'_>,
    ) -> Result<CommunityObservationRecordsV1, Error> {
        let covered = bindings
            .authority_rows
            .iter()
            .map(|(timeline, _)| *timeline)
            .eq(self.owning_timelines.iter().copied());
        if !covered || bindings.source_registrations.len() != self.sources.len() {
            return Err(Error::InvalidBinding);
        }
        let authority = community_event_source_authority_digest_v1(bindings.authority_rows)?;
        let rows: Vec<CommunityObservationEventRowV1> = self
            .sources
            .iter()
            .zip(bindings.source_registrations)
            .map(|(source, registration)| CommunityObservationEventRowV1 {
                logical_seq: source.logical_seq,
                event_id: source.event_id,
                payload_hash: source.payload_hash,
                source: CommunityEventSourceRefV1 {
                    owner_reference: self.owner_reference,
                    artifact_digest: source.digest,
                    registration_address: *registration,
                    source_scope_binding_digest: source.scope_binding_digest,
                },
            })
            .collect();
        let refs = self.input_refs(rows.clone());
        let proof = CommunityObservationSourceV1::new(CommunityObservationSourceInputV1 {
            operation_id: self.operation_id,
            timeline: self.timeline,
            generation: self.generation,
            through_seq: self.through_seq,
            event_rows: rows,
            reducer_policy_bindings: self.consumers.clone(),
            observation_value_digest: self.observation_value_digest,
            scope_union_digest: self.scope_union_digest,
            authority_request_digest: authority,
            evidence_not_after_micros: self.evidence_not_after_micros,
        })?;
        self.nodes(bindings, authority, &refs).map(
            |(input_groups, (observation_node, observation_reference))| {
                CommunityObservationRecordsV1 {
                    source_proof: proof.to_canonical_cbor(),
                    source_proof_digest: proof.digest(),
                    input_groups,
                    observation_node,
                    observation_reference,
                }
            },
        )
    }

    /// The Observation's Event-source inputs in canonical order: one mode-2
    /// ref per CES1, or the single `SourceGenesis` ref of an empty cut.
    ///
    /// These are its only typed inputs: the Observation's reducer and policy
    /// binding is carried by its CPE1 reducer rows, the CMI1 `[1, H(CPE1)]`
    /// binding and its authorization digest (owner 2026-11-21, #560). The
    /// CPN1 codec cannot see the cut, so A4c, with the CPE1, enforces that a
    /// `SourceGenesis` input appears only when `through_seq` is 0. Every
    /// row ref has one owner and class, so canonical order is the order of
    /// the fixed-width digest fields.
    fn input_refs(
        &self,
        mut rows: Vec<CommunityObservationEventRowV1>,
    ) -> Vec<CommunityTypedInputRefV1<'static>> {
        rows.sort_by_key(|row| (row.source.artifact_digest, row.source.registration_address));
        self.genesis.map_or_else(
            || rows.iter().map(|row| row.source.typed_ref()).collect(),
            |(timeline, genesis_chain_hash)| {
                vec![CommunityTypedInputRefV1::SourceGenesis {
                    timeline,
                    genesis_chain_hash,
                }]
            },
        )
    }

    /// The `InputIndex` groups (nodes `0..k`) and the Observation node `k`.
    fn nodes(
        &self,
        bindings: CommunityObservationBindingsV1<'_>,
        authority: Hash,
        refs: &[CommunityTypedInputRefV1<'_>],
    ) -> Result<(Vec<MintedGroup>, MintedNode), Error> {
        let content = CommunityContentReferenceV1 {
            record_magic: *b"COV1",
            logical_digest: self.observation_value_digest,
        };
        let node = |ordinal: u32,
                    kind: CommunityNativeNodeKindV1,
                    content: CommunityContentReferenceV1,
                    input_index: CommunityInputIndexV1<'_>| {
            CommunityNativeNodeV1::new(CommunityNativeNodeInputV1 {
                store_incarnation: bindings.store_incarnation,
                timeline: self.timeline,
                generation: self.generation,
                producer_ordinal: bindings.producer_ordinal,
                node_ordinal: ordinal,
                kind,
                content,
                dependency_class: RecordedDependencyClassV1::EndogenousRecomputed,
                input_index,
                scope_binding_digest: bindings.scope_binding_digest,
                authorization_digest: authority,
                provenance_digest: bindings.provenance_digest,
                evidence_not_after_micros: self.evidence_not_after_micros,
            })
            .map(|node| (node.to_canonical_cbor(), node.reference()))
        };
        if refs.len() <= MAX_COMMUNITY_DIRECT_INPUTS_V1 {
            let index =
                CommunityInputIndexV1::Direct(CommunityTypedInputRefsV1::from_references(refs));
            return node(0, CommunityNativeNodeKindV1::Observation, content, index)
                .map(|observation| (Vec::new(), observation));
        }
        refs.chunks(MAX_COMMUNITY_DIRECT_INPUTS_V1)
            .zip(0_u32..)
            .map(|(chunk, ordinal)| {
                let leaves = CommunityTypedInputRefsV1::from_references(chunk);
                CommunityInputGroupV1::new(CommunityInputGroupInputV1 {
                    timeline: self.timeline,
                    generation: self.generation,
                    consumer_content: content,
                    leaves,
                })
                .and_then(|group| {
                    node(
                        ordinal,
                        CommunityNativeNodeKindV1::InputIndex,
                        CommunityContentReferenceV1 {
                            record_magic: *b"CIB1",
                            logical_digest: group.digest(),
                        },
                        CommunityInputIndexV1::Direct(leaves),
                    )
                    .map(|(bytes, reference)| ((group.to_canonical_cbor(), bytes), reference))
                })
            })
            .collect::<Result<Vec<_>, Error>>()
            .and_then(|minted| {
                let (groups, group_refs): (Vec<_>, Vec<_>) = minted.into_iter().unzip();
                // At most 16 groups, so the ordinal always fits.
                let ordinal = u32::try_from(group_refs.len()).unwrap_or(u32::MAX);
                node(
                    ordinal,
                    CommunityNativeNodeKindV1::Observation,
                    content,
                    CommunityInputIndexV1::Grouped {
                        groups: CommunityNativeNodeReferencesV1::from_references(&group_refs),
                        total_leaf_count: refs.len() as u64,
                    },
                )
                .map(|observation| (groups, observation))
            })
    }
}
