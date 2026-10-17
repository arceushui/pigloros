//! Effective-composition derivation and the pre-commit prefix read (ADR-119 section 4.4
//! steps 1 and 3).

use pos_core::{
    CompositionPinV1, CoreError, DomainFallbackPolicyV1, Event, FallbackEntryV1, Hash, Seq,
    SeqRange, TimelineId, TimelineMeta,
};
use pos_runtime::TimelineHistorySegment;
use pos_store::composition_fallback_registry::FallbackRegistryStateV1;

use super::{FallbackBoundaryErrorV1 as Error, FallbackBoundaryStoreV1};

/// The current policy digest names no retained policy.
const POLICY_NOT_RETAINED: Error = Error::InvariantFault("the current policy is not retained");
/// The retained policy does not decode.
const POLICY_UNREADABLE: Error = Error::InvariantFault("the current policy does not decode");
/// A current policy entry has no recorded state, or its state names no listed implementation.
const ENTRY_DIVERGED: Error = Error::InvariantFault("an entry's state diverges from the policy");

/// One entry of the current policy, as the registry's fold says it runs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FallbackEffectiveEntryV1 {
    /// The declared entry.
    pub entry: FallbackEntryV1,
    /// The ordinal of the entry's current tenure.
    pub tenure_ordinal: u64,
    /// The index of the effective implementation in `[primary, candidates...]`.
    pub chain_position: u8,
    /// The pin of the effective implementation.
    pub effective: CompositionPinV1,
}

impl FallbackEffectiveEntryV1 {
    /// The entry's `[primary, candidates...]` pins.
    #[must_use]
    pub fn chain(&self) -> Vec<&CompositionPinV1> {
        std::iter::once(self.entry.primary())
            .chain(self.entry.candidates())
            .collect()
    }
}

/// The effective composition of one `(scope, timeline)`: the composer's base composition
/// folded with the declaration and activation Events (ADR-119 section 1).
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct FallbackEffectiveCompositionV1 {
    /// The registry's state revision, the `expected_state_revision` of the next write.
    pub state_revision: u64,
    /// The entries of the current policy, in policy order; empty before the first declaration
    /// and after a withdrawal.
    pub entries: Vec<FallbackEffectiveEntryV1>,
}

impl FallbackEffectiveCompositionV1 {
    /// The effective entry of `entry_key`, if the current policy declares it.
    #[must_use]
    pub fn entry(&self, entry_key: &str) -> Option<&FallbackEffectiveEntryV1> {
        self.entries
            .iter()
            .find(|effective| effective.entry.entry_key() == entry_key)
    }
}

/// Derive the effective composition of `scope` on `timeline` from the composition fallback
/// registry (ADR-119 section 4.4 step 1).
///
/// The port checks its row against the fold of the Timeline's Events on every write. Here the
/// current policy is read back by digest and every entry's recorded state must name one of the
/// entry's listed implementations at its chain position.
///
/// # Errors
/// Returns [`FallbackBoundaryErrorV1::Registry`](Error::Registry) for a refused read, and an
/// invariant fault when the retained policy or an entry's state diverges.
pub fn effective_composition_v1<S: FallbackBoundaryStoreV1 + ?Sized>(
    store: &S,
    scope: &str,
    timeline: TimelineId,
) -> Result<FallbackEffectiveCompositionV1, Error> {
    let row = store.registry_row(scope, timeline);
    row.map_err(Error::Registry).and_then(|row| {
        row.map_or_else(
            || Ok(FallbackEffectiveCompositionV1::default()),
            |row| composition_of(store, row.state()),
        )
    })
}

/// The effective composition of the folded `state`.
fn composition_of<S: FallbackBoundaryStoreV1 + ?Sized>(
    store: &S,
    state: &FallbackRegistryStateV1,
) -> Result<FallbackEffectiveCompositionV1, Error> {
    let policy = state
        .policy_digest()
        .ok_or(POLICY_NOT_RETAINED)
        .and_then(|digest| retained_policy(store, digest));
    policy.and_then(|policy| {
        let entries = policy.entries().iter();
        let entries = entries.map(|entry| effective_entry(state, entry));
        let entries = entries.collect::<Result<Vec<_>, _>>();
        entries.map(|entries| FallbackEffectiveCompositionV1 {
            state_revision: state.state_revision(),
            entries,
        })
    })
}

/// The retained, decoded policy of `digest`.
fn retained_policy<S: FallbackBoundaryStoreV1 + ?Sized>(
    store: &S,
    digest: Hash,
) -> Result<DomainFallbackPolicyV1, Error> {
    let bytes = store.retained_policy(digest).map_err(Error::Registry);
    let bytes = bytes.and_then(|bytes| bytes.ok_or(POLICY_NOT_RETAINED));
    bytes.and_then(|bytes| decoded(&bytes))
}

/// The decoded policy `bytes`.
fn decoded(bytes: &[u8]) -> Result<DomainFallbackPolicyV1, Error> {
    DomainFallbackPolicyV1::from_canonical_cbor(bytes).or(Err(POLICY_UNREADABLE))
}

/// The effective entry of `entry` under the folded `state`.
fn effective_entry(
    state: &FallbackRegistryStateV1,
    entry: &FallbackEntryV1,
) -> Result<FallbackEffectiveEntryV1, Error> {
    let recorded = state.entries().get(entry.entry_key());
    let effective = recorded.and_then(|recorded| {
        let position = usize::from(recorded.chain_position());
        let listed = std::iter::once(entry.primary())
            .chain(entry.candidates())
            .nth(position);
        let digest = recorded.effective_digest();
        let listed = listed.filter(|pin| pin.implementation().digest() == digest);
        listed.map(|pin| FallbackEffectiveEntryV1 {
            entry: entry.clone(),
            tenure_ordinal: recorded.tenure_ordinal(),
            chain_position: recorded.chain_position(),
            effective: pin.clone(),
        })
    });
    effective.ok_or(ENTRY_DIVERGED)
}

/// The durable prefix of the stepped Timeline, read before the commit (ADR-119 section 4.4
/// step 3).
#[derive(Clone, Debug)]
pub(super) struct PrefixV1 {
    /// The Timeline's Logical Head, the `expected_logical_head` of the commit.
    pub(super) head: Seq,
    /// The Timeline's Fork ancestry, root first, the last segment through `head`.
    pub(super) segments: Vec<TimelineHistorySegment>,
    /// Every Event from sequence 1 to `head`, inherited Events included.
    pub(super) events: Vec<Event>,
}

impl PrefixV1 {
    /// The prefix extended by the committed activation Event (section 4.4 step 6): the Event
    /// is appended and the last segment advances to its sequence.
    pub(super) fn extended(mut self, activation: Event) -> Self {
        let through = activation.seq;
        if let Some(last) = self.segments.pop() {
            let advanced = TimelineHistorySegment::new(last.timeline_id(), through);
            self.segments.push(advanced);
        }
        self.events.push(activation);
        self.head = through;
        self
    }
}

/// Read the durable prefix of `timeline`: its head, its Fork ancestry and its Events.
pub(super) fn read_prefix<S: FallbackBoundaryStoreV1 + ?Sized>(
    store: &S,
    timeline: TimelineId,
) -> Result<PrefixV1, CoreError> {
    let head = store.logical_head(timeline);
    let ancestry = pos_core::fork_ancestry(store, timeline);
    let events = store.read(timeline, SeqRange::all());
    head.and_then(|head| {
        ancestry.and_then(|ancestry| {
            events.map(|events| PrefixV1 {
                head,
                segments: segments_of(&ancestry, head),
                events,
            })
        })
    })
}

/// The history segments of `ancestry` (the Timeline first, its root last), root first: each
/// ancestor runs through its child's Fork point and the Timeline through `head`.
pub(super) fn segments_of(ancestry: &[TimelineMeta], head: Seq) -> Vec<TimelineHistorySegment> {
    let mut through = head;
    let mut segments = Vec::with_capacity(ancestry.len());
    for meta in ancestry {
        segments.push(TimelineHistorySegment::new(meta.id, through));
        through = meta.fork_point.unzip().1.unwrap_or(Seq::ZERO);
    }
    segments.reverse();
    segments
}
