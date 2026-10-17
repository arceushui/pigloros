// This file is `include!`d by the adapter test crates, so rustfmt does not format it; keep it in
// rustfmt style by hand.
// Shared store-level vectors of the ADR-119 composition fallback registry port (slice #663,
// conformance case 7 at store level). The including module declares `type Store: Backend` and
// sees the crate's `fixtures` module, so one body runs the vectors on every adapter.
//
// Every expected value is stated independently of the registry: payloads are re-encoded with the
// public `pos-core` codecs, and each refusal names the exact error variant of ADR-119 section 4.3.

use std::collections::{BTreeMap, BTreeSet};

use crate::fixtures::{
    policy, Backend, Harness, OffsetHasher, Registry, RegistryError, TestResult, ALPHA, BETA, SCOPE,
};
use pos_core::{
    store::{EventStore, SeqRange},
    CanonicalBytes, DomainFallbackPolicyV1, EntityId, EventDraft, FallbackActivatedInputV1,
    FallbackActivatedPayloadV1, FallbackActivationOriginV1, FallbackDeclaredPayloadV1,
    FallbackFieldV1, FallbackRebasedEntryV1, FallbackRecordErrorV1, FallbackSkipReasonV1,
    FallbackSkippedCandidateV1, FallbackTriggerBasisV1, FallbackTriggerCodeV1, Hash, Kind, Seq,
    COMPOSITION_FALLBACK_ACTIVATED_EVENT_TYPE_V1, COMPOSITION_FALLBACK_DECLARED_EVENT_TYPE_V1,
};
use pos_store::composition_fallback_registry::{
    CompositionFallbackRegistryV1, FallbackActivateRequestV1, FallbackCommitOutcomeV1,
    FallbackConformanceSetsV1, FallbackEntryStateV1, FallbackLedgerBodyV1,
    FallbackProvisionOutcomeV1, FallbackRegistryRowV1,
};

type H = Harness<Store>;

/// A harness with the `alpha` + `beta` policy declared.
fn declared() -> TestResult<(H, DomainFallbackPolicyV1)> {
    let mut h = H::open()?;
    let first = policy(vec![h.world.alpha()?, h.world.beta()?], None)?;
    h.declare(&first)??;
    Ok((h, first))
}

/// A harness whose `alpha` entry runs candidate `b` in tenure 1.
fn activated() -> TestResult<(H, DomainFallbackPolicyV1)> {
    let (mut h, first) = declared()?;
    let (a, b) = (h.world.a.clone(), h.world.b.clone());
    let request = h.activation(ALPHA, 0, &a, &b)?;
    h.activate(&request)?;
    Ok((h, first))
}

/// The events, ledger length, and stored row, to prove a refusal wrote nothing.
fn snapshot(h: &H) -> TestResult<(usize, usize, String)> {
    let ledger = h.store.fallback_ledger(SCOPE, h.timeline)?.len();
    let row = format!("{:?}", h.store.registry_row(SCOPE, h.timeline)?);
    Ok((h.events()?, ledger, row))
}

fn assert_refused<T: std::fmt::Debug>(
    h: &H,
    before: &(usize, usize, String),
    result: Registry<T>,
    expected: RegistryError,
) -> TestResult {
    let error = result.err().ok_or("the operation was not refused")?;
    assert_eq!(error, expected);
    assert_eq!(&snapshot(h)?, before, "{expected:?} wrote state");
    Ok(())
}

fn alpha_state(row: &FallbackRegistryRowV1) -> TestResult<FallbackEntryStateV1> {
    let alpha = row.state().entries().get(ALPHA).ok_or("no alpha")?;
    Ok(*alpha)
}

fn last_payload(h: &H) -> TestResult<Vec<u8>> {
    let events = h.store.read(h.timeline, SeqRange::all())?;
    let last = events.last().ok_or("no Event")?;
    Ok(last.payload.as_slice().to_vec())
}

// ---------------------------------------------------------------------------
// Provisioning and reads
// ---------------------------------------------------------------------------

#[test]
fn an_unprovisioned_store_is_missing_state_until_provisioned() -> TestResult {
    let (mut store, _guard) = Store::build(None)?;
    let timeline = store.create_timeline("composition")?.id();
    let missing = Some(RegistryError::MissingState);
    assert_eq!(store.registry_row(SCOPE, timeline).err(), missing);
    assert_eq!(store.fallback_ledger(SCOPE, timeline).err(), missing);
    assert_eq!(store.retained_policy(Hash::zero()).err(), missing);
    let declaration = store.lookup_declaration(SCOPE, timeline, Hash::zero());
    assert_eq!(declaration.err(), missing);
    let activation = store.lookup_activation(SCOPE, timeline, ALPHA, 0);
    assert_eq!(activation.err(), missing);
    let h = H::open()?;
    let first = policy(vec![h.world.alpha()?], None)?;
    let mut request = h.declaration(&first)?;
    request.target.timeline = timeline;
    assert_eq!(store.declare(&request).err(), missing);
    let (a, b) = (h.world.a.clone(), h.world.b.clone());
    let mut activation = h.activation(ALPHA, 0, &a, &b)?;
    activation.target.timeline = timeline;
    assert_eq!(store.activate(&activation).err(), missing);
    let created = store.provision_fallback_registry()?;
    assert_eq!(created, FallbackProvisionOutcomeV1::Created);
    let again = store.provision_fallback_registry()?;
    assert_eq!(again, FallbackProvisionOutcomeV1::Unchanged);
    assert_eq!(store.registry_row(SCOPE, timeline), Ok(None));
    assert_eq!(store.fallback_ledger(SCOPE, timeline), Ok(Vec::new()));
    assert_eq!(store.retained_policy(Hash::zero()), Ok(None));
    request.expected_logical_head = store.logical_head(timeline)?;
    assert_eq!(store.declare(&request)?.row().state_revision(), 1);
    Ok(())
}

// ---------------------------------------------------------------------------
// declare
// ---------------------------------------------------------------------------

#[test]
fn a_first_declaration_commits_the_row_the_event_and_the_ledger_row() -> TestResult {
    let mut h = H::open()?;
    let first = policy(vec![h.world.alpha()?, h.world.beta()?], None)?;
    let mut sets = BTreeMap::new();
    let profiles = BTreeSet::from([Hash::from_bytes([9; 32])]);
    sets.insert(ALPHA.to_owned(), profiles);
    let conformance = FallbackConformanceSetsV1::new(sets);
    let empty = FallbackConformanceSetsV1::default();
    assert_ne!(conformance.digest(), empty.digest());
    assert_eq!(conformance.sets().len(), 1);
    let mut request = h.declaration(&first)?;
    request.conformance = conformance.clone();
    let receipt = h.store.declare(&request)?;
    assert_eq!(receipt.outcome(), FallbackCommitOutcomeV1::Committed);
    let row = receipt.row();
    assert_eq!((row.row_seq(), row.state_revision()), (1, 1));
    assert_eq!(row.entity(), h.entity);
    assert_eq!(row.policy_digest(), first.policy_digest());
    let body = FallbackLedgerBodyV1::Declaration {
        conformance_digest: conformance.digest(),
    };
    assert_eq!(row.body(), &body);

    let expected = FallbackDeclaredPayloadV1::for_policy(&first, Vec::new())?;
    assert_eq!(last_payload(&h)?, expected.to_canonical_cbor());
    let events = h.store.read(h.timeline, SeqRange::all())?;
    assert_eq!(events.len(), 1);
    let event = &events[0];
    let kind = event.event_type.as_str();
    assert_eq!(kind, COMPOSITION_FALLBACK_DECLARED_EVENT_TYPE_V1);
    assert_eq!(event.entity, h.entity);
    assert_eq!(row.event().event_id(), event.id);
    assert_eq!(row.event().seq(), event.seq);
    assert_eq!(row.event().payload_digest(), event.payload_hash);
    assert_ne!(row.request_digest(), Hash::zero());

    let stored = h.store.registry_row(SCOPE, h.timeline)?.ok_or("no row")?;
    assert_eq!(stored.entity(), h.entity);
    let state = stored.state();
    assert_eq!(state.state_revision(), 1);
    assert_eq!(state.policy_digest(), Some(first.policy_digest()));
    assert_eq!(state.activation_ordinal(), 0);
    let alpha = state.entries().get(ALPHA).ok_or("no alpha")?;
    assert_eq!(alpha.tenure_ordinal(), 0);
    assert_eq!(alpha.effective_digest(), h.world.a.digest());
    assert_eq!(alpha.chain_position(), 0);
    assert_eq!(state.entries().len(), 2);

    let retained = h.store.retained_policy(first.policy_digest())?;
    assert_eq!(retained, Some(first.to_canonical_cbor()));
    let digest = first.policy_digest();
    let found = h.store.lookup_declaration(SCOPE, h.timeline, digest)?;
    assert_eq!(found.as_ref(), Some(row));
    let absent = h
        .store
        .lookup_declaration(SCOPE, h.timeline, Hash::zero())?;
    assert_eq!(absent, None);
    let ledger = h.store.fallback_ledger(SCOPE, h.timeline)?;
    assert_eq!(ledger, vec![row.clone()]);
    Ok(())
}

#[test]
fn a_byte_identical_retry_returns_the_original_before_staleness() -> TestResult {
    let mut h = H::open()?;
    let first = policy(vec![h.world.alpha()?], None)?;
    let request = h.declaration(&first)?;
    let original = h.store.declare(&request)?;
    let before = snapshot(&h)?;
    // The retry still names revision 0, the old head, and no predecessor.
    let retry = h.store.declare(&request)?;
    assert_eq!(retry.outcome(), FallbackCommitOutcomeV1::IdempotentReplay);
    assert_eq!(retry.row(), original.row());
    assert_eq!(snapshot(&h)?, before);

    let mut other_sets = request.clone();
    let sets = BTreeMap::from([(ALPHA.to_owned(), BTreeSet::new())]);
    other_sets.conformance = FallbackConformanceSetsV1::new(sets);
    let refused = h.store.declare(&other_sets);
    assert_refused(&h, &before, refused, RegistryError::Conflict)?;

    // A different entity is refused before it could be handed the original result.
    let mut stranger = request;
    stranger.target.entity = EntityId::new();
    let refused = h.store.declare(&stranger);
    assert_refused(&h, &before, refused, RegistryError::EntityMismatch)
}

#[test]
fn declaration_refusals_write_nothing() -> TestResult {
    let (mut h, first) = declared()?;
    let before = snapshot(&h)?;
    let second = policy(vec![h.world.alpha()?], Some(first.policy_digest()))?;

    let mut stale = h.declaration(&second)?;
    stale.expected_state_revision = 0;
    stale.expected_logical_head = Seq::ZERO;
    let refused = h.store.declare(&stale);
    assert_refused(&h, &before, refused, RegistryError::StaleState)?;
    stale.expected_state_revision = 1;
    let refused = h.store.declare(&stale);
    assert_refused(&h, &before, refused, RegistryError::StaleHead)?;

    let orphan = policy(vec![h.world.alpha()?], None)?;
    let refused = h.declare(&orphan)?;
    assert_refused(&h, &before, refused, RegistryError::StalePolicy)?;
    let unknown = policy(vec![h.world.alpha()?], Some(Hash::zero()))?;
    let refused = h.declare(&unknown)?;
    assert_refused(&h, &before, refused, RegistryError::StalePolicy)?;

    let mut scoped = h.declaration(&second)?;
    "other".clone_into(&mut scoped.scope);
    let refused = h.store.declare(&scoped);
    assert_refused(&h, &before, refused, RegistryError::ScopeMismatch)?;
    let mut garbled = h.declaration(&second)?;
    garbled.policy_bytes = vec![0x80];
    let refused = h.store.declare(&garbled);
    let invalid = RegistryError::InvalidRecord(FallbackRecordErrorV1::InvalidEncoding);
    assert_refused(&h, &before, refused, invalid)
}

#[test]
fn an_empty_first_policy_is_refused() -> TestResult {
    let mut h = H::open()?;
    let before = snapshot(&h)?;
    let empty = policy(Vec::new(), None)?;
    let refused = h.declare(&empty)?;
    assert_refused(&h, &before, refused, RegistryError::EmptyFirstPolicy)
}

#[test]
fn a_declared_primary_must_be_the_recorded_effective_implementation() -> TestResult {
    let (mut h, first) = activated()?;
    let before = snapshot(&h)?;
    // `alpha` runs `b`; a policy that still names `a` as its primary is refused.
    let unchanged = policy(vec![h.world.alpha()?], Some(first.policy_digest()))?;
    let refused = h.declare(&unchanged)?;
    assert_refused(&h, &before, refused, RegistryError::PrimaryNotEffective)
}

// ---------------------------------------------------------------------------
// activate
// ---------------------------------------------------------------------------

#[test]
fn an_activation_opens_the_next_tenure_with_one_event_and_one_ledger_row() -> TestResult {
    let (mut h, first) = declared()?;
    let (a, b) = (h.world.a.clone(), h.world.b.clone());
    let request = h.activation(ALPHA, 0, &a, &b)?;
    let receipt = h.activate(&request)?;
    assert_eq!(receipt.outcome(), FallbackCommitOutcomeV1::Committed);
    let row = receipt.row();
    assert_eq!((row.row_seq(), row.state_revision()), (2, 2));
    assert_eq!(row.policy_digest(), first.policy_digest());
    let body = FallbackLedgerBodyV1::Activation {
        entry_key: ALPHA.to_owned(),
        closing_tenure_ordinal: 0,
        activation_ordinal: 1,
        tick: 9,
    };
    assert_eq!(row.body(), &body);

    let input = FallbackActivatedInputV1 {
        scope: SCOPE.to_owned(),
        policy_digest: first.policy_digest(),
        entry_key: ALPHA.to_owned(),
        closing_tenure_ordinal: 0,
        from: a,
        to: b.clone(),
        skipped: Vec::new(),
        trigger_code: request.trigger_code,
        trigger_basis: request.trigger_basis,
        activation_ordinal: 1,
    };
    let expected = FallbackActivatedPayloadV1::new(input)?;
    assert_eq!(last_payload(&h)?, expected.to_canonical_cbor());
    let events = h.store.read(h.timeline, SeqRange::all())?;
    let kind = events.last().ok_or("no Event")?.event_type.as_str();
    assert_eq!(kind, COMPOSITION_FALLBACK_ACTIVATED_EVENT_TYPE_V1);

    let stored = h.store.registry_row(SCOPE, h.timeline)?.ok_or("no row")?;
    let state = stored.state();
    assert_eq!((state.state_revision(), state.activation_ordinal()), (2, 1));
    let alpha = state.entries().get(ALPHA).ok_or("no alpha")?;
    assert_eq!(alpha.tenure_ordinal(), 1);
    assert_eq!(alpha.effective_digest(), b.digest());
    assert_eq!(alpha.chain_position(), 1);
    let found = h.store.lookup_activation(SCOPE, h.timeline, ALPHA, 0)?;
    assert_eq!(found.as_ref(), Some(row));
    let open_tenure = h.store.lookup_activation(SCOPE, h.timeline, ALPHA, 1)?;
    assert_eq!(open_tenure, None);
    let other_entry = h.store.lookup_activation(SCOPE, h.timeline, BETA, 0)?;
    assert_eq!(other_entry, None);
    Ok(())
}

#[test]
fn an_activation_retry_replays_and_another_request_for_the_key_conflicts() -> TestResult {
    let (mut h, _) = declared()?;
    let (a, b, c) = (h.world.a.clone(), h.world.b.clone(), h.world.c.clone());
    let request = h.activation(ALPHA, 0, &a, &b)?;
    let original = h.activate(&request)?;
    let before = snapshot(&h)?;
    let retry = h.activate(&request)?;
    assert_eq!(retry.outcome(), FallbackCommitOutcomeV1::IdempotentReplay);
    assert_eq!(retry.row(), original.row());
    assert_eq!(snapshot(&h)?, before);
    let mut other = request.clone();
    other.to = c;
    let refused = h.activate(&other);
    assert_refused(&h, &before, refused, RegistryError::Conflict)?;
    let mut stranger = request;
    stranger.target.entity = EntityId::new();
    let refused = h.activate(&stranger);
    assert_refused(&h, &before, refused, RegistryError::EntityMismatch)
}

/// One change to a valid activation request.
type Change = fn(&mut FallbackActivateRequestV1, &H);

/// One activation refusal: the request change and the error it must produce.
type Refusal = (&'static str, Change, RegistryError);

fn refusals() -> [Refusal; 12] {
    [
        (
            "stale revision",
            |r, _| r.expected_state_revision = 0,
            RegistryError::StaleState,
        ),
        (
            "stale head",
            |r, _| r.expected_logical_head = Seq::ZERO,
            RegistryError::StaleHead,
        ),
        (
            "unknown entry",
            |r, _| "gamma".clone_into(&mut r.entry_key),
            RegistryError::UnknownEntry,
        ),
        (
            "old tenure",
            |r, _| r.closing_tenure_ordinal = 3,
            RegistryError::StaleActivation,
        ),
        (
            "wrong from",
            |r, h| r.from = h.world.c.clone(),
            RegistryError::StaleActivation,
        ),
        (
            "unlisted target",
            |r, h| r.to = h.world.e.clone(),
            RegistryError::InvalidTarget,
        ),
        (
            "same plugin",
            |r, h| r.to = h.world.a.clone(),
            invalid_implementation(),
        ),
        (
            "undeclared trigger",
            undeclared_trigger,
            RegistryError::TriggerNotDeclared,
        ),
        ("manual entry", manual_entry, RegistryError::ManualEntry),
        (
            "skipped primary",
            |r, h| skip(r, h.world.a.digest()),
            RegistryError::InvalidSkipped,
        ),
        (
            "skipped target",
            |r, h| skip(r, h.world.b.digest()),
            RegistryError::InvalidSkipped,
        ),
        (
            "automatic return",
            automatic_return,
            RegistryError::InvalidTarget,
        ),
    ]
}

const fn invalid_implementation() -> RegistryError {
    RegistryError::InvalidRecord(FallbackRecordErrorV1::InvalidField(
        FallbackFieldV1::Implementation,
    ))
}

const fn undeclared_trigger(request: &mut FallbackActivateRequestV1, _: &H) {
    request.trigger_code = FallbackTriggerCodeV1::WorkerCrashed;
    request.trigger_basis.origin = FallbackActivationOriginV1::Owner;
}

fn manual_entry(request: &mut FallbackActivateRequestV1, h: &H) {
    BETA.clone_into(&mut request.entry_key);
    request.from = h.world.d.clone();
    request.to = h.world.e.clone();
}

fn skip(request: &mut FallbackActivateRequestV1, digest: Hash) {
    let reason = FallbackSkipReasonV1::ReleaseNotCurrent;
    let skipped = FallbackSkippedCandidateV1 {
        implementation_digest: digest,
        reason,
    };
    request.skipped = vec![skipped];
}

fn automatic_return(request: &mut FallbackActivateRequestV1, h: &H) {
    // Candidate `c` runs at chain position 2 after `b` -> `c`; an automatic step to `b` goes back.
    request.from = h.world.c.clone();
    request.to = h.world.b.clone();
    request.closing_tenure_ordinal = 2;
}

#[test]
fn activation_refusals_write_nothing() -> TestResult {
    for (name, change, expected) in refusals() {
        let (mut h, _) = declared()?;
        if name == "automatic return" {
            let (a, b, c) = (h.world.a.clone(), h.world.b.clone(), h.world.c.clone());
            h.activate(&h.activation(ALPHA, 0, &a, &b)?)?;
            h.activate(&h.activation(ALPHA, 1, &b, &c)?)?;
        }
        let (a, b) = (h.world.a.clone(), h.world.b.clone());
        let mut request = h.activation(ALPHA, 0, &a, &b)?;
        change(&mut request, &h);
        let before = snapshot(&h)?;
        let refused = h.activate(&request);
        assert_eq!(refused.as_ref().err(), Some(&expected), "{name}");
        assert_eq!(snapshot(&h)?, before, "{name}");
    }
    Ok(())
}

#[test]
fn an_activation_without_a_policy_names_no_entry() -> TestResult {
    let mut h = H::open()?;
    let (a, b) = (h.world.a.clone(), h.world.b.clone());
    let request = h.activation(ALPHA, 0, &a, &b)?;
    let before = snapshot(&h)?;
    let refused = h.activate(&request);
    assert_refused(&h, &before, refused, RegistryError::UnknownEntry)
}

#[test]
fn the_chain_moves_forward_and_an_owner_returns_to_the_primary() -> TestResult {
    let (mut h, _) = declared()?;
    let primary = h.world.a.clone();
    let second = h.world.b.clone();
    let third = h.world.c.clone();
    h.activate(&h.activation(ALPHA, 0, &primary, &second)?)?;
    h.activate(&h.activation(ALPHA, 1, &second, &third)?)?;
    // An owner return names the primary with any code and restarts the chain.
    let mut back = h.activation(ALPHA, 2, &third, &primary)?;
    back.trigger_basis.origin = FallbackActivationOriginV1::Owner;
    back.trigger_code = FallbackTriggerCodeV1::WorkerCrashed;
    assert_eq!(h.activate(&back)?.row().state_revision(), 4);
    let stored = h.store.registry_row(SCOPE, h.timeline)?.ok_or("no row")?;
    let alpha = alpha_state(&stored)?;
    assert_eq!((alpha.tenure_ordinal(), alpha.chain_position()), (3, 0));
    assert_eq!(alpha.effective_digest(), primary.digest());
    assert_eq!(stored.state().activation_ordinal(), 3);
    // An owner activates a manual entry; an automatic step may skip a candidate it records.
    let manual_primary = h.world.d.clone();
    let manual_candidate = h.world.e.clone();
    let mut manual = h.activation(BETA, 0, &manual_primary, &manual_candidate)?;
    manual.trigger_basis.origin = FallbackActivationOriginV1::Owner;
    h.activate(&manual)?;
    let mut skipping = h.activation(ALPHA, 3, &primary, &third)?;
    skip(&mut skipping, second.digest());
    assert_eq!(h.activate(&skipping)?.row().state_revision(), 6);
    Ok(())
}

// ---------------------------------------------------------------------------
// Re-base and withdrawal
// ---------------------------------------------------------------------------

#[test]
fn a_rebase_promotes_the_candidate_and_restarts_its_chain() -> TestResult {
    let (mut h, first) = activated()?;
    let (b, c) = (h.world.b.clone(), h.world.c.clone());
    let mode = pos_core::FallbackActivationModeV1::Automatic;
    let promoted = crate::fixtures::World::entry(ALPHA, &b, &[&c], mode)?;
    let rebase = policy(vec![promoted, h.world.beta()?], Some(first.policy_digest()))?;
    h.declare(&rebase)??;
    let pair = FallbackRebasedEntryV1::new(ALPHA.to_owned(), b.digest())?;
    let expected = FallbackDeclaredPayloadV1::for_policy(&rebase, vec![pair])?;
    assert_eq!(last_payload(&h)?, expected.to_canonical_cbor());
    let stored = h.store.registry_row(SCOPE, h.timeline)?.ok_or("no row")?;
    let alpha = alpha_state(&stored)?;
    assert_eq!((alpha.tenure_ordinal(), alpha.chain_position()), (1, 0));
    assert_eq!(alpha.effective_digest(), b.digest());
    // The re-based entry continues with its new candidates.
    let next = h.activation(ALPHA, 1, &b, &c)?;
    assert_eq!(h.activate(&next)?.row().state_revision(), 4);
    Ok(())
}

#[test]
fn a_withdrawal_freezes_the_entry_and_names_the_next_predecessor() -> TestResult {
    let (mut h, first) = activated()?;
    let withdrawal = policy(Vec::new(), Some(first.policy_digest()))?;
    h.declare(&withdrawal)??;
    let b = h.world.b.clone();
    let pair = FallbackRebasedEntryV1::new(ALPHA.to_owned(), b.digest())?;
    let expected = FallbackDeclaredPayloadV1::for_policy(&withdrawal, vec![pair])?;
    assert_eq!(last_payload(&h)?, expected.to_canonical_cbor());
    let stored = h.store.registry_row(SCOPE, h.timeline)?.ok_or("no row")?;
    let digest = withdrawal.policy_digest();
    assert_eq!(stored.state().policy_digest(), Some(digest));
    let alpha = alpha_state(&stored)?;
    assert_eq!((alpha.tenure_ordinal(), alpha.chain_position()), (1, 0));

    // After a withdrawal nothing activates.
    let c = h.world.c.clone();
    let before = snapshot(&h)?;
    let after = h.activation(ALPHA, 1, &b, &c)?;
    let refused = h.activate(&after);
    assert_refused(&h, &before, refused, RegistryError::UnknownEntry)?;

    // The next policy names the withdrawal; the frozen entry keeps `b` as its implementation.
    let previous = Some(withdrawal.policy_digest());
    let stale_primary = policy(vec![h.world.alpha()?], previous)?;
    let refused = h.declare(&stale_primary)?;
    assert_refused(&h, &before, refused, RegistryError::PrimaryNotEffective)?;
    let mode = pos_core::FallbackActivationModeV1::Manual;
    let frozen = crate::fixtures::World::entry(ALPHA, &b, &[&c], mode)?;
    let next = policy(vec![frozen], previous)?;
    let receipt = h.declare(&next)??;
    assert_eq!(receipt.row().state_revision(), 4);
    Ok(())
}

// ---------------------------------------------------------------------------
// The fold invariant, Forks, and the guarded append
// ---------------------------------------------------------------------------

fn forge(h: &mut H, event_type: &str, payload: Vec<u8>) -> TestResult {
    let (kind, bytes) = (Kind::new(event_type), CanonicalBytes::from_vec(payload));
    let draft = EventDraft::new(h.entity, kind, bytes);
    h.store.append(h.timeline, &[draft])?;
    Ok(())
}

/// A well-formed activation payload of `alpha` from `a` to `b`.
fn forged_activation(h: &H, policy_digest: Hash, activation_ordinal: u64) -> TestResult<Vec<u8>> {
    let trigger_basis = FallbackTriggerBasisV1 {
        cause: 7,
        origin: FallbackActivationOriginV1::Automatic,
    };
    let input = FallbackActivatedInputV1 {
        scope: SCOPE.to_owned(),
        policy_digest,
        entry_key: ALPHA.to_owned(),
        closing_tenure_ordinal: 0,
        from: h.world.a.clone(),
        to: h.world.b.clone(),
        skipped: Vec::new(),
        trigger_code: FallbackTriggerCodeV1::ResourceLimit,
        trigger_basis,
        activation_ordinal,
    };
    Ok(FallbackActivatedPayloadV1::new(input)?.to_canonical_cbor())
}

/// One reserved-type Event that the stored row does not fold.
fn forged(h: &H, first: &DomainFallbackPolicyV1, case: u8) -> TestResult<(&'static str, Vec<u8>)> {
    let declared = COMPOSITION_FALLBACK_DECLARED_EVENT_TYPE_V1;
    let activated = COMPOSITION_FALLBACK_ACTIVATED_EVENT_TYPE_V1;
    let digest = first.policy_digest();
    let unknown = policy(vec![h.world.alpha()?], Some(digest))?;
    let never_retained = FallbackDeclaredPayloadV1::for_policy(&unknown, Vec::new())?;
    let repeated = FallbackDeclaredPayloadV1::for_policy(first, Vec::new())?;
    Ok(match case {
        0 => (declared, vec![0x80]),
        1 => (activated, vec![0x80]),
        2 => (declared, never_retained.to_canonical_cbor()),
        3 => (declared, repeated.to_canonical_cbor()),
        4 => (activated, forged_activation(h, Hash::zero(), 1)?),
        5 => (activated, forged_activation(h, digest, 5)?),
        _ => (activated, forged_activation(h, digest, 1)?),
    })
}

#[test]
fn an_event_the_row_does_not_fold_is_corrupt_state() -> TestResult {
    for case in 0..7 {
        let (mut h, first) = declared()?;
        let (event_type, payload) = forged(&h, &first, case)?;
        forge(&mut h, event_type, payload)?;
        let (a, b) = (h.world.a.clone(), h.world.b.clone());
        let request = h.activation(ALPHA, 0, &a, &b)?;
        let corrupt = Some(RegistryError::CorruptState);
        assert_eq!(h.activate(&request).err(), corrupt, "case {case}");
        let second = policy(vec![h.world.alpha()?], Some(first.policy_digest()))?;
        assert_eq!(h.declare(&second)?.err(), corrupt, "case {case}");
    }
    Ok(())
}

#[test]
fn another_scope_on_the_same_timeline_is_not_folded() -> TestResult {
    let (mut h, first) = declared()?;
    let other = DomainFallbackPolicyV1::new("other".to_owned(), vec![h.world.alpha()?], None)?;
    let mut request = h.declaration(&other)?;
    "other".clone_into(&mut request.scope);
    request.expected_state_revision = 0;
    h.store.declare(&request)?;
    let (a, b) = (h.world.a.clone(), h.world.b.clone());
    let mut elsewhere = h.activation(ALPHA, 0, &a, &b)?;
    "other".clone_into(&mut elsewhere.scope);
    elsewhere.expected_state_revision = 1;
    h.store.activate(&elsewhere)?;
    assert_eq!(h.store.fallback_ledger("other", h.timeline)?.len(), 2);
    let second = policy(vec![h.world.alpha()?], Some(first.policy_digest()))?;
    assert_eq!(h.declare(&second)??.row().state_revision(), 2);
    Ok(())
}

#[test]
fn a_fork_row_is_initialised_from_its_inherited_events() -> TestResult {
    let (mut h, first) = activated()?;
    let parent = h.store.registry_row(SCOPE, h.timeline)?;
    let cut = h.head()?;
    let fork = h.store.fork(h.timeline, cut, "fork")?.id();
    assert_eq!(h.store.registry_row(SCOPE, fork)?, None);
    let (b, c) = (h.world.b.clone(), h.world.c.clone());
    let mode = pos_core::FallbackActivationModeV1::Automatic;
    let promoted = crate::fixtures::World::entry(ALPHA, &b, &[&c], mode)?;
    let own = policy(vec![promoted], Some(first.policy_digest()))?;
    let mut request = h.declaration(&own)?;
    request.target.timeline = fork;
    request.expected_logical_head = cut;
    let receipt = h.store.declare(&request)?;
    assert_eq!(receipt.row().state_revision(), 3);
    assert_eq!(receipt.row().row_seq(), 1);
    let derived = h.store.registry_row(SCOPE, fork)?.ok_or("no Fork row")?;
    assert_eq!(derived.state().activation_ordinal(), 1);
    assert_eq!(h.store.registry_row(SCOPE, h.timeline)?, parent);
    // The Fork and the parent activate independently.
    let mut on_fork = h.activation(ALPHA, 1, &b, &c)?;
    on_fork.target.timeline = fork;
    on_fork.expected_state_revision = 3;
    on_fork.expected_logical_head = h.store.logical_head(fork)?;
    assert_eq!(h.activate(&on_fork)?.row().row_seq(), 2);
    let on_parent = h.activation(ALPHA, 1, &b, &c)?;
    assert_eq!(h.activate(&on_parent)?.row().row_seq(), 3);
    Ok(())
}

#[test]
fn a_store_with_another_payload_hasher_never_commits() -> TestResult {
    let mut h = H::with_hasher(Some(Box::new(OffsetHasher)))?;
    let first = policy(vec![h.world.alpha()?], None)?;
    let before = snapshot(&h)?;
    let refused = h.declare(&first)?;
    assert_refused(&h, &before, refused, RegistryError::EventRejected)
}

#[test]
fn every_public_value_formats_clones_and_compares() -> TestResult {
    let (mut h, first) = activated()?;
    let replay = h.declare(&first)??;
    assert_eq!(replay.outcome(), FallbackCommitOutcomeV1::IdempotentReplay);
    let row = h.store.registry_row(SCOPE, h.timeline)?.ok_or("no row")?;
    let entry = alpha_state(&row)?;
    let declaration = h.declaration(&first)?;
    let (b, c) = (h.world.b.clone(), h.world.c.clone());
    let activation = h.activation(ALPHA, 1, &b, &c)?;
    assert_eq!(declaration.clone(), declaration);
    assert_eq!(activation.clone(), activation);
    assert_eq!(row.clone(), row);
    assert_eq!(replay.clone(), replay);
    let provisioned = (String::new(), FallbackProvisionOutcomeV1::Created);
    assert_eq!(provisioned.clone(), provisioned);
    let target = (String::new(), h.target());
    assert_eq!(target.clone(), target);
    let event = replay.row().event();
    let rendered = [
        format!("{replay:?}"),
        format!("{row:?}"),
        format!("{entry:?}"),
        format!("{event:?}"),
        format!("{declaration:?}"),
        format!("{activation:?}"),
        format!("{provisioned:?}"),
        format!("{target:?}"),
    ];
    assert!(rendered.iter().all(|text| !text.is_empty()));
    Ok(())
}

#[test]
fn every_error_variant_displays_and_clones() {
    let errors = [
        RegistryError::MissingState,
        RegistryError::CorruptState,
        RegistryError::InvalidRecord(FallbackRecordErrorV1::TooLarge),
        RegistryError::ScopeMismatch,
        RegistryError::EntityMismatch,
        RegistryError::Conflict,
        RegistryError::StaleState,
        RegistryError::StaleHead,
        RegistryError::StalePolicy,
        RegistryError::EmptyFirstPolicy,
        RegistryError::PrimaryNotEffective,
        RegistryError::UnknownEntry,
        RegistryError::StaleActivation,
        RegistryError::InvalidTarget,
        RegistryError::TriggerNotDeclared,
        RegistryError::ManualEntry,
        RegistryError::InvalidSkipped,
        RegistryError::TimelineUnavailable,
        RegistryError::EventRejected,
        RegistryError::NestedTransaction,
        RegistryError::WalRequired,
        RegistryError::StorageBusy,
        RegistryError::StorageFailed,
        RegistryError::StorageIndeterminate,
        RegistryError::StorePoisoned,
    ];
    for error in errors {
        let pair = (String::new(), error);
        assert_eq!(pair.clone(), pair);
        assert!(!error.to_string().is_empty());
        assert!(!format!("{error:?}").is_empty());
    }
}
