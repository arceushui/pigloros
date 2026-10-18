//! Adapter-independent decisions of the composition fallback registry.
//!
//! An adapter exposes its committed rows and the target Timeline through [`FallbackReadsV1`]
//! inside its own transaction; [`plan_declare`] and [`plan_activate`] return either the original
//! ledger row of a byte-identical repeat or the complete commit: the new row, the Event draft,
//! and the ledger row once the Event's identity is known. The adapters only order the locks,
//! append the draft through the guarded `EventStore` path, and write the plan.
//!
//! The fold invariant is checked here: the stored row must equal the fold of the Timeline's
//! declaration and activation Events of the scope. A Fork has no row of its own until its first
//! operation; its row is then initialised from the fold of its inherited Events and is never
//! copied from the parent.

use std::iter;

use pos_core::{
    CanonicalBytes, CoreError, DomainFallbackPolicyV1, EntityId, Event, EventDraft,
    FallbackActivatedInputV1, FallbackActivatedPayloadV1, FallbackActivationModeV1,
    FallbackActivationOriginV1, FallbackDeclaredPayloadV1, FallbackEntryV1, FallbackRebasedEntryV1,
    Hash, Hasher, Kind, Seq, TimelineId, COMPOSITION_FALLBACK_ACTIVATED_EVENT_TYPE_V1,
    COMPOSITION_FALLBACK_DECLARED_EVENT_TYPE_V1,
};

use super::error::CompositionFallbackRegistryErrorV1 as Error;
use super::types::{
    update_len, update_text, CompositionFallbackTargetV1, FallbackActivateRequestV1,
    FallbackConformanceSetsV1, FallbackDeclareRequestV1, FallbackEntryStateV1,
    FallbackEventIdentityV1, FallbackLedgerBodyV1, FallbackLedgerRowV1, FallbackRegistryRowV1,
    FallbackRegistryStateV1,
};

/// The result type of every registry decision.
pub type FallbackResult<T> = Result<T, Error>;

const CORRUPT: Error = Error::CorruptState;

/// The domain of the request digest that decides whether a repeat is byte-identical.
const REQUEST_DIGEST_DOMAIN_V1: &[u8] = b"PiglorOS.Composition.FallbackRequest.v1\0";

/// `Ok` when `condition` holds, otherwise `error`.
///
/// # Errors
/// Returns `error` when `condition` is false.
pub const fn require(condition: bool, error: Error) -> FallbackResult<()> {
    if condition {
        Ok(())
    } else {
        Err(error)
    }
}

/// An adapter's committed state, read inside the operation's transaction.
pub trait FallbackReadsV1 {
    /// The stored row of `(scope, timeline)`.
    ///
    /// # Errors
    /// `CorruptState` or a storage error.
    fn stored_row(
        &self,
        scope: &str,
        timeline: TimelineId,
    ) -> FallbackResult<Option<FallbackRegistryRowV1>>;

    /// The retained DFP1 bytes of `policy_digest`.
    ///
    /// # Errors
    /// `CorruptState` or a storage error.
    fn stored_policy(&self, policy_digest: Hash) -> FallbackResult<Option<Vec<u8>>>;

    /// The ledger of `(scope, timeline)` in row order.
    ///
    /// # Errors
    /// `CorruptState` or a storage error.
    fn stored_ledger(
        &self,
        scope: &str,
        timeline: TimelineId,
    ) -> FallbackResult<Vec<FallbackLedgerRowV1>>;

    /// Every Event of `timeline`, inherited ones included.
    ///
    /// # Errors
    /// `TimelineUnavailable` when the Timeline cannot be read.
    fn timeline_events(&self, timeline: TimelineId) -> FallbackResult<Vec<Event>>;

    /// The Logical Head of `timeline`.
    ///
    /// # Errors
    /// `TimelineUnavailable` when the Timeline cannot be read.
    fn timeline_head(&self, timeline: TimelineId) -> FallbackResult<Seq>;
}

/// The fold of one `(scope, timeline)`: the registry state and the decoded current policy.
#[derive(Default)]
pub struct FallbackFoldV1 {
    /// The folded state.
    pub state: FallbackRegistryStateV1,
    /// The current policy, or `None` before the first declaration.
    pub policy: Option<DomainFallbackPolicyV1>,
}

impl FallbackFoldV1 {
    fn apply_declared(
        mut self,
        payload: &FallbackDeclaredPayloadV1,
        policy: DomainFallbackPolicyV1,
    ) -> FallbackResult<Self> {
        let rebased = self.state.rebased_entries();
        let consistent = declared_consistent(&self.state, payload, &policy, &rebased);
        require(consistent, CORRUPT)?;
        self.state.declare(&policy);
        self.policy = Some(policy);
        Ok(self)
    }

    fn apply_activated(mut self, payload: &FallbackActivatedPayloadV1) -> FallbackResult<Self> {
        let input = payload.as_input();
        let next = self
            .policy
            .as_ref()
            .filter(|policy| policy.policy_digest() == input.policy_digest)
            .ok_or(CORRUPT)
            .and_then(|policy| transition(policy, &self.state, input).or(Err(CORRUPT)))
            .map(|transition| transition.next)?;
        let ordinal = self.state.activation_ordinal.saturating_add(1);
        require(input.activation_ordinal == ordinal, CORRUPT)?;
        self.state.activate(input, next);
        Ok(self)
    }
}

impl FallbackRegistryStateV1 {
    /// The entries in a candidate tenure, which a declaration re-bases.
    ///
    /// Every recorded entry key came from a validated DFP1, so none is dropped in practice.
    fn rebased_entries(&self) -> Vec<FallbackRebasedEntryV1> {
        self.entries
            .iter()
            .filter(|(_, entry)| entry.chain_position > 0)
            .filter_map(|(key, entry)| {
                FallbackRebasedEntryV1::new(key.clone(), entry.effective_digest).ok()
            })
            .collect()
    }

    /// Whether a recorded entry of `policy` runs another implementation than its primary.
    fn primary_mismatch(&self, policy: &DomainFallbackPolicyV1) -> bool {
        policy.entries().iter().any(|entry| {
            self.entries
                .get(entry.entry_key())
                .is_some_and(|state| state.effective_digest != primary_digest(entry))
        })
    }

    /// Fold one declaration: every chain restarts and new entries open tenure 0.
    fn declare(&mut self, policy: &DomainFallbackPolicyV1) {
        self.entries
            .values_mut()
            .for_each(|entry| entry.chain_position = 0);
        for entry in policy.entries() {
            self.entries
                .entry(entry.entry_key().to_owned())
                .or_insert_with(|| FallbackEntryStateV1 {
                    tenure_ordinal: 0,
                    effective_digest: primary_digest(entry),
                    chain_position: 0,
                });
        }
        self.state_revision = self.state_revision.saturating_add(1);
        self.policy_digest = Some(policy.policy_digest());
    }

    /// Fold one activation.
    fn activate(&mut self, input: &FallbackActivatedInputV1, next: FallbackEntryStateV1) {
        self.entries.insert(input.entry_key.clone(), next);
        self.activation_ordinal = input.activation_ordinal;
        self.state_revision = self.state_revision.saturating_add(1);
    }
}

fn primary_digest(entry: &FallbackEntryV1) -> Hash {
    entry.primary().implementation().digest()
}

/// The IMK1 digests of `[primary, candidates...]`.
fn implementations(entry: &FallbackEntryV1) -> impl Iterator<Item = Hash> + '_ {
    iter::once(entry.primary())
        .chain(entry.candidates())
        .map(|pin| pin.implementation().digest())
}

fn chain_index(entry: &FallbackEntryV1, digest: Hash) -> Option<u8> {
    implementations(entry)
        .position(|listed| listed == digest)
        .and_then(|index| u8::try_from(index).ok())
}

fn is_candidate(entry: &FallbackEntryV1, digest: Hash) -> bool {
    implementations(entry)
        .skip(1)
        .any(|listed| listed == digest)
}

fn payload_names_policy(
    payload: &FallbackDeclaredPayloadV1,
    policy: &DomainFallbackPolicyV1,
) -> bool {
    payload.scope() == policy.scope()
        && payload.policy_digest() == policy.policy_digest()
        && payload.previous_policy_digest() == policy.previous_policy_digest()
}

fn declared_consistent(
    state: &FallbackRegistryStateV1,
    payload: &FallbackDeclaredPayloadV1,
    policy: &DomainFallbackPolicyV1,
    rebased: &[FallbackRebasedEntryV1],
) -> bool {
    payload_names_policy(payload, policy)
        && payload.previous_policy_digest() == state.policy_digest
        && payload.rebased() == rebased
        && !state.primary_mismatch(policy)
}

/// One activation's entry, its current state, and its state after the activation.
struct TransitionV1<'a> {
    entry: &'a FallbackEntryV1,
    current: FallbackEntryStateV1,
    next: FallbackEntryStateV1,
}

/// Whether `input` closes the entry's current tenure on its effective implementation.
fn closes_tenure(current: &FallbackEntryStateV1, input: &FallbackActivatedInputV1) -> bool {
    let from = input.from.digest();
    current.tenure_ordinal == input.closing_tenure_ordinal && current.effective_digest == from
}

fn transition<'a>(
    policy: &'a DomainFallbackPolicyV1,
    state: &FallbackRegistryStateV1,
    input: &FallbackActivatedInputV1,
) -> FallbackResult<TransitionV1<'a>> {
    let current = *state
        .entries
        .get(&input.entry_key)
        .ok_or(Error::UnknownEntry)?;
    let entry = policy
        .entries()
        .iter()
        .find(|entry| entry.entry_key() == input.entry_key)
        .ok_or(Error::UnknownEntry)?;
    require(closes_tenure(&current, input), Error::StaleActivation)?;
    let to = input.to.digest();
    let chain_position = chain_index(entry, to).ok_or(Error::InvalidTarget)?;
    let next = FallbackEntryStateV1 {
        tenure_ordinal: current.tenure_ordinal.saturating_add(1),
        effective_digest: to,
        chain_position,
    };
    Ok(TransitionV1 {
        entry,
        current,
        next,
    })
}

/// Automatic activations need automatic mode and only move forward along the chain.
fn check_origin(
    transition: &TransitionV1<'_>,
    origin: FallbackActivationOriginV1,
) -> FallbackResult<()> {
    match origin {
        FallbackActivationOriginV1::Automatic => {
            let mode = transition.entry.activation_mode();
            let automatic = mode == FallbackActivationModeV1::Automatic;
            require(automatic, Error::ManualEntry).and_then(|()| {
                let forward = transition.next.chain_position > transition.current.chain_position;
                require(forward, Error::InvalidTarget)
            })
        }
        FallbackActivationOriginV1::Owner => Ok(()),
    }
}

/// The trigger, origin, and skipped-candidate rules of one activation.
///
/// `skipped` may name only candidates of the entry (never its primary), and never `to`: a
/// skipped implementation is one the boundary tried and did not activate.
fn check_rules(
    transition: &TransitionV1<'_>,
    input: &FallbackActivatedInputV1,
) -> FallbackResult<()> {
    check_origin(transition, input.trigger_basis.origin)?;
    let returns = transition.next.chain_position == 0;
    let declared = returns || transition.entry.triggers().contains(&input.trigger_code);
    require(declared, Error::TriggerNotDeclared)?;
    let to = input.to.digest();
    let skipped = input.skipped.iter().all(|skipped| {
        let digest = skipped.implementation_digest;
        digest != to && is_candidate(transition.entry, digest)
    });
    require(skipped, Error::InvalidSkipped)
}

/// Fold every declaration and activation Event of `scope` on `timeline`.
///
/// # Errors
/// `TimelineUnavailable`, a storage error, or `CorruptState` for an Event that does not decode
/// or does not follow from the state before it.
pub fn fold_timeline(
    reads: &dyn FallbackReadsV1,
    scope: &str,
    timeline: TimelineId,
) -> FallbackResult<FallbackFoldV1> {
    reads.timeline_events(timeline).and_then(|events| {
        let initial = FallbackFoldV1::default();
        events
            .iter()
            .try_fold(initial, |fold, event| fold_event(reads, scope, fold, event))
    })
}

fn fold_event(
    reads: &dyn FallbackReadsV1,
    scope: &str,
    fold: FallbackFoldV1,
    event: &Event,
) -> FallbackResult<FallbackFoldV1> {
    let payload = event.payload.as_slice();
    match event.event_type.as_str() {
        COMPOSITION_FALLBACK_DECLARED_EVENT_TYPE_V1 => fold_declared(reads, scope, fold, payload),
        COMPOSITION_FALLBACK_ACTIVATED_EVENT_TYPE_V1 => fold_activated(scope, fold, payload),
        _ => Ok(fold),
    }
}

fn fold_declared(
    reads: &dyn FallbackReadsV1,
    scope: &str,
    fold: FallbackFoldV1,
    bytes: &[u8],
) -> FallbackResult<FallbackFoldV1> {
    let payload = FallbackDeclaredPayloadV1::from_canonical_cbor(bytes).or(Err(CORRUPT))?;
    if payload.scope() != scope {
        return Ok(fold);
    }
    load_policy(reads, payload.policy_digest())
        .and_then(|policy| fold.apply_declared(&payload, policy))
}

fn fold_activated(
    scope: &str,
    fold: FallbackFoldV1,
    bytes: &[u8],
) -> FallbackResult<FallbackFoldV1> {
    let payload = FallbackActivatedPayloadV1::from_canonical_cbor(bytes).or(Err(CORRUPT))?;
    if payload.as_input().scope != scope {
        return Ok(fold);
    }
    fold.apply_activated(&payload)
}

fn load_policy(
    reads: &dyn FallbackReadsV1,
    digest: Hash,
) -> FallbackResult<DomainFallbackPolicyV1> {
    reads.stored_policy(digest).and_then(|bytes| {
        bytes
            .and_then(|bytes| DomainFallbackPolicyV1::from_canonical_cbor(&bytes).ok())
            .filter(|policy| policy.policy_digest() == digest)
            .ok_or(CORRUPT)
    })
}

/// The committed state of one `(scope, timeline)`, checked against its fold.
struct CurrentV1 {
    fold: FallbackFoldV1,
    ledger: Vec<FallbackLedgerRowV1>,
}

/// The row must equal the fold; an absent row has no ledger; then the entity must match.
fn check_row(
    stored: Option<&FallbackRegistryRowV1>,
    ledger: &[FallbackLedgerRowV1],
    state: &FallbackRegistryStateV1,
    entity: EntityId,
) -> FallbackResult<()> {
    stored.map_or_else(
        || require(ledger.is_empty(), CORRUPT),
        |row| {
            let revision = state.state_revision;
            let last = ledger.last().map(FallbackLedgerRowV1::state_revision);
            let folded = row.state == *state && last.is_none_or(|last| last == revision);
            let same_entity = row.entity == entity;
            require(folded, CORRUPT).and_then(|()| require(same_entity, Error::EntityMismatch))
        },
    )
}

fn current(
    reads: &dyn FallbackReadsV1,
    scope: &str,
    target: CompositionFallbackTargetV1,
) -> FallbackResult<CurrentV1> {
    let timeline = target.timeline;
    let stored = reads.stored_row(scope, timeline)?;
    let ledger = reads.stored_ledger(scope, timeline)?;
    let fold = fold_timeline(reads, scope, timeline)?;
    check_row(stored.as_ref(), &ledger, &fold.state, target.entity)
        .map(|()| CurrentV1 { fold, ledger })
}

/// The arguments every write shares, and its request digest.
struct WriteV1<'a> {
    scope: &'a str,
    target: CompositionFallbackTargetV1,
    expected_state_revision: u64,
    expected_logical_head: Seq,
    request_digest: Hash,
}

impl WriteV1<'_> {
    /// `StaleState`, then `StaleHead`.
    fn check_fresh(&self, reads: &dyn FallbackReadsV1, state_revision: u64) -> FallbackResult<()> {
        let fresh = self.expected_state_revision == state_revision;
        require(fresh, Error::StaleState)?;
        reads
            .timeline_head(self.target.timeline)
            .and_then(|head| require(head == self.expected_logical_head, Error::StaleHead))
    }

    /// The ADR-119 clarification 7 prelude: the fold invariant and `EntityMismatch`, then the
    /// byte-identical replay of the row `occupies` finds (or `Conflict`), then staleness; only
    /// then `fresh` runs the operation's own checks.
    fn plan(
        &self,
        reads: &dyn FallbackReadsV1,
        occupies: impl Fn(&FallbackLedgerRowV1) -> bool,
        fresh: impl FnOnce(CurrentV1) -> FallbackResult<FallbackPlanV1>,
    ) -> FallbackResult<FallbackPlanV1> {
        let found = current(reads, self.scope, self.target)?;
        if let Some(row) = found.ledger.iter().find(|row| occupies(row)) {
            return replay(row, self.request_digest);
        }
        let revision = found.fold.state.state_revision;
        self.check_fresh(reads, revision)?;
        fresh(found)
    }

    /// The commit parts of this write against `found`.
    fn parts(&self, found: &CurrentV1, policy_digest: Hash) -> CommitPartsV1 {
        CommitPartsV1 {
            entity: self.target.entity,
            row_seq: next_row_seq(&found.ledger),
            policy_digest,
            request_digest: self.request_digest,
        }
    }
}

/// The original ledger row of a byte-identical repeat, or `Conflict`.
fn replay(row: &FallbackLedgerRowV1, request_digest: Hash) -> FallbackResult<FallbackPlanV1> {
    require(row.request_digest == request_digest, Error::Conflict)
        .map(|()| FallbackPlanV1::Replay(row.clone()))
}

/// `StalePolicy`, `EmptyFirstPolicy`, then the recorded-entry part of `PrimaryNotEffective`.
fn check_declaration(
    state: &FallbackRegistryStateV1,
    policy: &DomainFallbackPolicyV1,
) -> FallbackResult<()> {
    let previous = policy.previous_policy_digest();
    require(previous == state.policy_digest, Error::StalePolicy)?;
    let withdraws_nothing = previous.is_none() && policy.is_withdrawal();
    require(!withdraws_nothing, Error::EmptyFirstPolicy)?;
    require(!state.primary_mismatch(policy), Error::PrimaryNotEffective)
}

fn new_request_hasher(kind: u8, entity: EntityId) -> blake3::Hasher {
    let mut hasher = blake3::Hasher::new();
    hasher.update(REQUEST_DIGEST_DOMAIN_V1);
    hasher.update(&[kind]);
    hasher.update(&entity.inner().to_bytes());
    hasher
}

fn finish_digest(hasher: &blake3::Hasher) -> Hash {
    Hash::from_bytes(*hasher.finalize().as_bytes())
}

/// A declaration's identity beyond its key: the entity and the conformance sets.
fn declare_request_digest(entity: EntityId, conformance: &FallbackConformanceSetsV1) -> Hash {
    let mut hasher = new_request_hasher(1, entity);
    hasher.update(conformance.digest().as_bytes());
    finish_digest(&hasher)
}

/// An activation's identity: the entity and every argument.
fn activate_request_digest(request: &FallbackActivateRequestV1) -> Hash {
    let mut hasher = new_request_hasher(2, request.target.entity);
    update_text(&mut hasher, &request.scope);
    hasher.update(&request.expected_state_revision.to_le_bytes());
    hasher.update(&request.expected_logical_head.as_u64().to_le_bytes());
    update_text(&mut hasher, &request.entry_key);
    hasher.update(&request.closing_tenure_ordinal.to_le_bytes());
    hasher.update(request.from.digest().as_bytes());
    hasher.update(request.to.digest().as_bytes());
    let trigger = request.trigger_code.code();
    let origin = request.trigger_basis.origin.code();
    hasher.update(&[trigger, origin]);
    hasher.update(&request.trigger_basis.cause.to_le_bytes());
    update_len(&mut hasher, request.skipped.len());
    for skipped in &request.skipped {
        hasher.update(skipped.implementation_digest.as_bytes());
        hasher.update(&[skipped.reason.code()]);
    }
    hasher.update(&request.tick.to_le_bytes());
    finish_digest(&hasher)
}

/// Either the original ledger row of a byte-identical repeat, or a commit.
pub enum FallbackPlanV1 {
    /// Return this row; write nothing.
    Replay(FallbackLedgerRowV1),
    /// Append the draft, then write the commit.
    Commit(Box<FallbackCommitV1>),
}

/// The complete write of one operation.
pub struct FallbackCommitV1 {
    /// The row after the operation.
    pub row: FallbackRegistryRowV1,
    /// The DFP1 bytes to retain by digest, for a declaration.
    pub policy: Option<(Hash, Vec<u8>)>,
    /// The guarded Event the operation appends.
    pub draft: EventDraft,
    row_seq: u64,
    policy_digest: Hash,
    request_digest: Hash,
    body: FallbackLedgerBodyV1,
}

impl FallbackCommitV1 {
    /// The ledger row, once the guarded append returned the Event's identity.
    #[must_use]
    pub fn ledger_row(&self, event: FallbackEventIdentityV1) -> FallbackLedgerRowV1 {
        FallbackLedgerRowV1 {
            row_seq: self.row_seq,
            entity: self.row.entity,
            state_revision: self.row.state.state_revision,
            policy_digest: self.policy_digest,
            request_digest: self.request_digest,
            event,
            body: self.body.clone(),
        }
    }
}

fn draft(entity: EntityId, event_type: &str, payload: Vec<u8>) -> EventDraft {
    let kind = Kind::new(event_type);
    EventDraft::new(entity, kind, CanonicalBytes::from_vec(payload))
}

const fn next_row_seq(ledger: &[FallbackLedgerRowV1]) -> u64 {
    (ledger.len() as u64).saturating_add(1)
}

/// BLAKE3-256 of the draft payload, which the store's own payload hash must equal: a store
/// with another hasher never commits.
///
/// # Errors
/// `EventRejected` when `hasher` hashes the payload differently.
pub fn payload_digest(hasher: &dyn Hasher, draft: &EventDraft) -> FallbackResult<Hash> {
    let digest = Hash::from_bytes(*blake3::hash(draft.payload.as_slice()).as_bytes());
    let matches = hasher.hash_payload(&draft.payload) == digest;
    require(matches, Error::EventRejected).map(|()| digest)
}

/// The identity of the one Event a guarded append of one draft returned.
///
/// # Errors
/// `EventRejected` when the append refused or returned no Event.
pub fn event_identity(
    appended: Result<Vec<Event>, CoreError>,
    payload_digest: Hash,
) -> FallbackResult<FallbackEventIdentityV1> {
    appended
        .ok()
        .and_then(|events| events.into_iter().next())
        .map(|event| FallbackEventIdentityV1 {
            event_id: event.id,
            seq: event.seq,
            payload_digest,
        })
        .ok_or(Error::EventRejected)
}

/// The parts of one commit that every operation fills the same way.
struct CommitPartsV1 {
    entity: EntityId,
    row_seq: u64,
    policy_digest: Hash,
    request_digest: Hash,
}

impl CommitPartsV1 {
    fn commit(
        self,
        fold: FallbackFoldV1,
        draft: EventDraft,
        body: FallbackLedgerBodyV1,
        policy: Option<(Hash, Vec<u8>)>,
    ) -> FallbackPlanV1 {
        FallbackPlanV1::Commit(Box::new(FallbackCommitV1 {
            row: FallbackRegistryRowV1 {
                entity: self.entity,
                state: fold.state,
            },
            policy,
            draft,
            row_seq: self.row_seq,
            policy_digest: self.policy_digest,
            request_digest: self.request_digest,
            body,
        }))
    }
}

/// Plan one `declare`.
///
/// # Errors
/// The closed registry error of the first failing check.
pub fn plan_declare(
    reads: &dyn FallbackReadsV1,
    request: &FallbackDeclareRequestV1,
) -> FallbackResult<FallbackPlanV1> {
    let policy = DomainFallbackPolicyV1::from_canonical_cbor(&request.policy_bytes)?;
    require(policy.scope() == request.scope, Error::ScopeMismatch)?;
    let target = request.target;
    let write = WriteV1 {
        scope: &request.scope,
        target,
        expected_state_revision: request.expected_state_revision,
        expected_logical_head: request.expected_logical_head,
        request_digest: declare_request_digest(target.entity, &request.conformance),
    };
    let digest = policy.policy_digest();
    write.plan(
        reads,
        |row| row.declares(digest),
        |found| declare_fresh(&write, found, policy, request),
    )
}

/// The declaration checks and commit of a write that is neither a replay nor stale.
fn declare_fresh(
    write: &WriteV1<'_>,
    found: CurrentV1,
    policy: DomainFallbackPolicyV1,
    request: &FallbackDeclareRequestV1,
) -> FallbackResult<FallbackPlanV1> {
    let state = &found.fold.state;
    check_declaration(state, &policy)?;
    let policy_digest = policy.policy_digest();
    let parts = write.parts(&found, policy_digest);
    let body = FallbackLedgerBodyV1::Declaration {
        conformance_digest: request.conformance.digest(),
    };
    let retained = Some((policy_digest, request.policy_bytes.clone()));
    let rebased = state.rebased_entries();
    let entity = write.target.entity;
    FallbackDeclaredPayloadV1::for_policy(&policy, rebased)
        .map_err(Error::from)
        .and_then(|payload| {
            let event_type = COMPOSITION_FALLBACK_DECLARED_EVENT_TYPE_V1;
            let event = draft(entity, event_type, payload.to_canonical_cbor());
            let fold = found.fold.apply_declared(&payload, policy);
            fold.map(|fold| parts.commit(fold, event, body, retained))
        })
}

fn activation_input(
    request: &FallbackActivateRequestV1,
    policy_digest: Hash,
    activation_ordinal: u64,
) -> FallbackActivatedInputV1 {
    FallbackActivatedInputV1 {
        scope: request.scope.clone(),
        policy_digest,
        entry_key: request.entry_key.clone(),
        closing_tenure_ordinal: request.closing_tenure_ordinal,
        from: request.from.clone(),
        to: request.to.clone(),
        skipped: request.skipped.clone(),
        trigger_code: request.trigger_code,
        trigger_basis: request.trigger_basis,
        activation_ordinal: activation_ordinal.saturating_add(1),
    }
}

/// Plan one `activate`.
///
/// # Errors
/// The closed registry error of the first failing check.
pub fn plan_activate(
    reads: &dyn FallbackReadsV1,
    request: &FallbackActivateRequestV1,
) -> FallbackResult<FallbackPlanV1> {
    let write = WriteV1 {
        scope: &request.scope,
        target: request.target,
        expected_state_revision: request.expected_state_revision,
        expected_logical_head: request.expected_logical_head,
        request_digest: activate_request_digest(request),
    };
    let (key, closing) = (&request.entry_key, request.closing_tenure_ordinal);
    write.plan(
        reads,
        |row| row.closes(key, closing),
        |found| activate_fresh(&write, found, request),
    )
}

/// The activation checks and commit of a write that is neither a replay nor stale.
fn activate_fresh(
    write: &WriteV1<'_>,
    found: CurrentV1,
    request: &FallbackActivateRequestV1,
) -> FallbackResult<FallbackPlanV1> {
    let state = &found.fold.state;
    let policy = found.fold.policy.as_ref().ok_or(Error::UnknownEntry)?;
    let input = activation_input(request, policy.policy_digest(), state.activation_ordinal);
    let payload = FallbackActivatedPayloadV1::new(input)?;
    let input = payload.as_input();
    check_rules(&transition(policy, state, input)?, input)?;
    let parts = write.parts(&found, input.policy_digest);
    let body = FallbackLedgerBodyV1::Activation {
        entry_key: input.entry_key.clone(),
        closing_tenure_ordinal: input.closing_tenure_ordinal,
        activation_ordinal: input.activation_ordinal,
        tick: request.tick,
    };
    let event_type = COMPOSITION_FALLBACK_ACTIVATED_EVENT_TYPE_V1;
    let event = draft(write.target.entity, event_type, payload.to_canonical_cbor());
    let fold = found.fold.apply_activated(&payload);
    fold.map(|fold| parts.commit(fold, event, body, None))
}
