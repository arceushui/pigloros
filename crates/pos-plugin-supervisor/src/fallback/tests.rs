//! Unit tests of the composition boundary's pure steps. The transaction itself is exercised
//! end to end in `tests/composition_fallback_public.rs`.

use std::collections::BTreeMap;
use std::sync::Arc;

use pos_core::store::EventStore;
use pos_core::{
    CanonicalBytes, CompositionPinV1, CoreError, EntityId, Event, EventDraft,
    FallbackActivatedInputV1, FallbackActivatedPayloadV1, FallbackActivationOriginV1,
    FallbackSkipReasonV1, FallbackTriggerBasisV1, FallbackTriggerCodeV1, Hash, ImplementationKeyV1,
    Kind, PluginId, Seq, SeqRange, TimelineId, TimelineMeta,
    COMPOSITION_FALLBACK_ACTIVATED_EVENT_TYPE_V1,
};
use pos_runtime::community_plugin_host::{cbor, PLUGIN_RELEASE_ACTIVATED_EVENT_TYPE_V1};
use pos_runtime::{PluginRegistry, RuntimeError, TimelineHistorySegment};
use pos_store::composition_fallback_registry::{
    CompositionFallbackRegistryErrorV1, CompositionFallbackRegistryV1, CompositionFallbackTargetV1,
    FallbackActivateRequestV1, FallbackConformanceSetsV1, FallbackDeclareRequestV1,
    FallbackLedgerBodyV1, FallbackLedgerRowV1,
};
use pos_store::memory::MemoryStore;

use super::boundary::{checked_prefix, commit_activation};
use super::derive::{segments_of, PrefixV1};
use super::{
    effective_composition_v1, fallback_tenures_v1, CompositionBoundaryV1,
    FallbackBoundaryErrorV1 as Error, FallbackClosureErrorV1, FallbackEffectiveCompositionV1,
    FallbackEntryOutcomeV1 as Outcome, FallbackRestartSlotV1, FallbackTenureEvidenceV1,
};
use crate::test_support::ok;

/// Every boundary error, one per variant.
const ERRORS: [Error; 10] = [
    Error::Faulted,
    Error::InvariantFault("diverged"),
    Error::Registry(CompositionFallbackRegistryErrorV1::Conflict),
    Error::NotGranted,
    Error::UnknownEntry,
    Error::InvalidTarget,
    Error::NoObservation,
    Error::TriggerNotDeclared,
    Error::SlotUnavailable(FallbackSkipReasonV1::SourceUnavailable),
    Error::StoreUnavailable,
];

/// A Fork of `parent` at `at`.
fn forked(parent: &TimelineMeta, at: u64) -> TimelineMeta {
    TimelineMeta {
        fork_point: Some((parent.id, Seq::from_u64(at))),
        ..TimelineMeta::root("child")
    }
}

/// An empty prefix whose only segment runs through `through`.
fn empty_prefix(through: u64) -> PrefixV1 {
    let segment = TimelineHistorySegment::new(TimelineId::new(), Seq::from_u64(through));
    PrefixV1 {
        head: Seq::from_u64(through),
        segments: vec![segment],
        events: Vec::new(),
    }
}

/// Each ancestor runs through its child's Fork point, the Timeline through its head, and the
/// segments run root first.
#[test]
fn segments_run_root_first_through_each_fork_point() {
    let root = TimelineMeta::root("root");
    let child = forked(&root, 3);
    let segments = segments_of(&[child.clone(), root.clone()], Seq::from_u64(7));
    let expected = [
        TimelineHistorySegment::new(root.id, Seq::from_u64(3)),
        TimelineHistorySegment::new(child.id, Seq::from_u64(7)),
    ];
    assert_eq!(segments, expected);
}

/// A root Timeline is one segment through its head.
#[test]
fn a_root_timeline_is_one_segment() {
    let root = TimelineMeta::root("root");
    let segments = segments_of(std::slice::from_ref(&root), Seq::ZERO);
    assert_eq!(segments, [TimelineHistorySegment::new(root.id, Seq::ZERO)]);
}

/// A prefix that was not read, or that fails the restore check, skips the candidate
/// (`SwapRefused`); an empty Timeline's prefix passes.
#[test]
fn an_unreadable_or_invalid_prefix_refuses_the_swap() {
    let refused = Err(FallbackSkipReasonV1::SwapRefused);
    let unreadable = Err(CoreError::Storage("injected".to_owned()));
    assert_eq!(
        checked_prefix(unreadable).map(|prefix| prefix.head),
        refused
    );
    let short = checked_prefix(Ok(empty_prefix(2)));
    assert_eq!(short.map(|prefix| prefix.head), refused);
    let empty = checked_prefix(Ok(empty_prefix(0)));
    assert_eq!(empty.map(|prefix| prefix.head), Ok(Seq::ZERO));
}

/// Every boundary error has a distinct message, and the value types compare and print.
#[test]
fn errors_and_outcomes_print_and_compare() {
    let messages: std::collections::BTreeSet<String> =
        ERRORS.iter().map(ToString::to_string).collect();
    assert_eq!(messages.len(), ERRORS.len());
    let debug: Vec<String> = ERRORS.iter().map(|error| format!("{error:?}")).collect();
    assert!(debug.iter().all(|text| !text.is_empty()));
    let outcomes = [
        Outcome::AwaitingOwner {
            entry_key: "entry".to_owned(),
            code: FallbackTriggerCodeV1::ResourceLimit,
        },
        Outcome::Exhausted {
            entry_key: "entry".to_owned(),
            skipped: Vec::new(),
        },
        Outcome::NotCommitted {
            entry_key: "entry".to_owned(),
            error: CompositionFallbackRegistryErrorV1::StaleState,
        },
    ];
    assert_eq!(outcomes.clone(), outcomes);
    assert!(format!("{outcomes:?}").contains("StaleState"));
}

/// A fresh boundary binds what it was given, holds no observation and has not faulted.
#[test]
fn a_fresh_boundary_holds_its_bindings() {
    let target = CompositionFallbackTargetV1 {
        timeline: TimelineId::new(),
        entity: EntityId::new(),
    };
    let bindings = BTreeMap::from([("entry".to_owned(), pos_core::PluginId::new())]);
    let boundary = CompositionBoundaryV1::new("scope".to_owned(), target, bindings.clone());
    assert_eq!(boundary.binding("entry"), bindings.get("entry").copied());
    assert_eq!(boundary.binding("other"), None);
    assert_eq!(boundary.observation("entry"), None);
    assert!(!boundary.is_faulted());
    assert_eq!(boundary.clone(), boundary);
    assert!(format!("{boundary:?}").contains("scope"));
    let empty = FallbackEffectiveCompositionV1::default();
    assert_eq!(empty.entry("entry"), None);
    let copy = empty.clone();
    assert_eq!(format!("{copy:?}"), format!("{empty:?}"));
}

/// The implementation key of `plugin_id` on the release `byte`.
fn key(plugin_id: &str, byte: u8) -> ImplementationKeyV1 {
    let digest = Hash::from_bytes([byte; 32]);
    ok(ImplementationKeyV1::new(
        plugin_id.to_owned(),
        "0.1.0".to_owned(),
        digest,
    ))
}

/// Declare, on `target` of `store`, one entry whose primary has one candidate.
fn declared(target: CompositionFallbackTargetV1, store: &mut MemoryStore) {
    let pin = |plugin_id, byte| {
        ok(pos_core::CompositionPinV1::new(
            key(plugin_id, byte),
            vec!["role".to_owned()],
        ))
    };
    let triggers = vec![FallbackTriggerCodeV1::ResourceLimit];
    let automatic = pos_core::FallbackActivationModeV1::Automatic;
    let entry = pos_core::FallbackEntryV1::new(
        "entry".to_owned(),
        pin("acme.primary", 1),
        vec![pin("acme.candidate", 2)],
        triggers,
        automatic,
    );
    let entries = vec![ok(entry)];
    let policy = ok(pos_core::DomainFallbackPolicyV1::new(
        "scope".to_owned(),
        entries,
        None,
    ));
    let request = FallbackDeclareRequestV1 {
        scope: "scope".to_owned(),
        target,
        expected_state_revision: 0,
        expected_logical_head: Seq::ZERO,
        policy_bytes: policy.to_canonical_cbor(),
        conformance: FallbackConformanceSetsV1::default(),
    };
    let _declared = ok(store.declare(&request));
}

/// An open store on a fresh Timeline, and its target.
fn store() -> (MemoryStore, CompositionFallbackTargetV1) {
    let mut store = MemoryStore::new();
    let gate = Arc::new(pos_core::ErasureContainmentGateV1::new_test_open());
    let () = ok(EventStore::bind_erasure_gate(&mut store, gate));
    let timeline = ok(EventStore::create_timeline(&mut store, "cbt")).id();
    let _provisioned = ok(store.provision_fallback_registry());
    let target = CompositionFallbackTargetV1 {
        timeline,
        entity: EntityId::new(),
    };
    (store, target)
}

/// The automatic activation of the entry's candidate at `revision` and `tick`.
fn activation(
    target: CompositionFallbackTargetV1,
    revision: u64,
    tick: u64,
) -> FallbackActivateRequestV1 {
    FallbackActivateRequestV1 {
        scope: "scope".to_owned(),
        target,
        expected_state_revision: revision,
        expected_logical_head: Seq::from_u64(1),
        entry_key: "entry".to_owned(),
        closing_tenure_ordinal: 0,
        from: key("acme.primary", 1),
        to: key("acme.candidate", 2),
        trigger_code: FallbackTriggerCodeV1::ResourceLimit,
        trigger_basis: pos_core::FallbackTriggerBasisV1 {
            cause: 16,
            origin: pos_core::FallbackActivationOriginV1::Automatic,
        },
        skipped: Vec::new(),
        tick,
    }
}

/// The refusal a commit reported, by its registry error.
fn refusal(
    committed: &Result<FallbackLedgerRowV1, Outcome>,
) -> Option<CompositionFallbackRegistryErrorV1> {
    match committed {
        Err(Outcome::NotCommitted { error, .. }) => Some(*error),
        _ => None,
    }
}

/// A commit returns its ledger row. Another request for the same tenure is a `Conflict` and a
/// stale revision is `StaleState`: neither is adopted, even though the lookup finds the first.
#[test]
fn a_refused_commit_is_not_adopted() {
    let (mut store, target) = store();
    declared(target, &mut store);
    let committed = commit_activation(&mut store, &activation(target, 1, 5));
    assert_eq!(committed.map(|row| row.state_revision()), Ok(2));
    let conflict = commit_activation(&mut store, &activation(target, 1, 6));
    assert_eq!(
        refusal(&conflict),
        Some(CompositionFallbackRegistryErrorV1::Conflict)
    );
    let mut stale = activation(target, 1, 5);
    stale.closing_tenure_ordinal = 1;
    stale.from = key("acme.candidate", 2);
    stale.to = key("acme.primary", 1);
    let refused = refusal(&commit_activation(&mut store, &stale));
    assert_eq!(
        refused,
        Some(CompositionFallbackRegistryErrorV1::StaleState)
    );
}

/// The owner's return of the entry from the candidate tenure 1 to its primary.
fn returning(
    target: CompositionFallbackTargetV1,
    revision: u64,
    head: Seq,
) -> FallbackActivateRequestV1 {
    let mut request = activation(target, revision, 7);
    request.expected_logical_head = head;
    request.closing_tenure_ordinal = 1;
    request.from = key("acme.candidate", 2);
    request.to = key("acme.primary", 1);
    request.trigger_basis.origin = FallbackActivationOriginV1::Owner;
    request
}

/// Case 10 (registry side): a Fork with no row of its own derives the effective composition
/// at its cut from its inherited Events, so a Fork after an activation runs the candidate;
/// the Fork's activations and the parent's do not collide.
#[test]
fn a_fork_derives_its_composition_from_the_inherited_prefix() {
    let (mut store, target) = store();
    declared(target, &mut store);
    let _activated = ok(store.activate(&activation(target, 1, 5)));
    let cut = ok(EventStore::logical_head(&store, target.timeline));
    let fork = ok(EventStore::fork(&mut store, target.timeline, cut, "fork"));
    let fork = fork.id();
    assert_eq!(ok(store.registry_row("scope", fork)), None);
    let parent = ok(effective_composition_v1(&store, "scope", target.timeline));
    let derived = ok(effective_composition_v1(&store, "scope", fork));
    assert_eq!(derived, parent);
    let tenure = derived.entry("entry").map(|entry| entry.tenure_ordinal);
    let position = derived.entry("entry").map(|entry| entry.chain_position);
    assert_eq!((tenure, position), (Some(1), Some(1)));
    let on_fork = CompositionFallbackTargetV1 {
        timeline: fork,
        ..target
    };
    let forked = ok(store.activate(&returning(on_fork, 2, cut)));
    let returned = ok(store.activate(&returning(target, 2, cut)));
    assert_eq!((forked.row().row_seq(), returned.row().row_seq()), (1, 3));
    let body = FallbackLedgerBodyV1::Activation {
        entry_key: "entry".to_owned(),
        closing_tenure_ordinal: 1,
        activation_ordinal: 2,
        tick: 7,
    };
    assert_eq!(forked.row().body(), &body);
    assert_eq!(returned.row().body(), &body);
    let after = ok(effective_composition_v1(&store, "scope", fork));
    let tenure = after.entry("entry").map(|entry| entry.tenure_ordinal);
    assert_eq!(tenure, Some(2));
}

/// The pin of `plugin_id` on the release `byte`, in the entry's role.
fn pin(plugin_id: &str, byte: u8) -> CompositionPinV1 {
    let roles = vec!["role".to_owned()];
    ok(CompositionPinV1::new(key(plugin_id, byte), roles))
}

/// The composer's slot of the declared entry, on its primary.
fn slot() -> FallbackRestartSlotV1 {
    FallbackRestartSlotV1 {
        entry_key: "entry".to_owned(),
        base: pin("acme.primary", 1),
    }
}

/// Append one Event of `event_type` carrying `payload` to `timeline`.
fn append(
    store: &mut MemoryStore,
    timeline: TimelineId,
    event_type: &str,
    payload: Vec<u8>,
) -> Event {
    let (kind, bytes) = (Kind::new(event_type), CanonicalBytes::from_vec(payload));
    let draft = EventDraft::new(EntityId::new(), kind, bytes);
    let appended = ok(EventStore::append(store, timeline, &[draft]));
    ok(appended.into_iter().next().ok_or("nothing appended"))
}

/// Every Event of `timeline`, inherited ones included.
fn events_of(store: &MemoryStore, timeline: TimelineId) -> Vec<Event> {
    ok(EventStore::read(store, timeline, SeqRange::all()))
}

/// A `release-activated` payload of `key`'s release in the trust `scope`.
fn release_activated(scope: &str, key: &ImplementationKeyV1) -> Vec<u8> {
    let mut payload = Vec::new();
    cbor::array(&mut payload, 4);
    cbor::text(&mut payload, scope);
    cbor::text(&mut payload, key.plugin_id());
    cbor::bytes(&mut payload, &[9; 32]);
    cbor::bytes(&mut payload, key.release_digest().as_bytes());
    payload
}

/// Case 6: the tenures close from the Events alone, with no policy bytes. Each later tenure
/// is named by the activation Event that opened it; tenure 0 runs the base and resolves to the
/// admitted release whose digest it names, among several releases of its Plugin ID.
#[test]
fn tenures_close_from_the_events_alone() {
    let (mut store, target) = store();
    declared(target, &mut store);
    let _activated = ok(store.activate(&activation(target, 1, 5)));
    let events = events_of(&store, target.timeline);
    let tenures = ok(fallback_tenures_v1("scope", &[slot()], &events));
    let all = tenures.tenures("entry");
    assert_eq!(all.len(), 2);
    let base = FallbackTenureEvidenceV1::Base;
    assert_eq!((all[0].ordinal, all[0].evidence), (0, base));
    let last = events.last().map(|event| (event.id, event.seq));
    let (event_id, seq) = ok(last.ok_or("no Event"));
    let opened = FallbackTenureEvidenceV1::Activation { event_id, seq };
    assert_eq!((all[1].ordinal, all[1].evidence), (1, opened));
    assert_eq!(all[1].opened_at(), seq);
    let candidate = key("acme.candidate", 2);
    assert_eq!(tenures.effective("entry"), Some(&candidate));
    let at = |seq| tenures.tenure_at("entry", Seq::from_u64(seq));
    assert_eq!(at(1).map(|tenure| tenure.ordinal), Some(0));
    assert_eq!(at(2).map(|tenure| tenure.ordinal), Some(1));
    assert!(tenures.tenures("other").is_empty());
    assert_eq!(tenures.effective("other"), None);
    let restarted = tenures.restart_slot(&slot());
    assert_eq!(restarted.base.implementation(), &candidate);
    assert_eq!(restarted.base.roles(), slot().base.roles());
    let installer = ok(EventStore::create_timeline(&mut store, "installer"));
    let installer = installer.id();
    let (primary, earlier) = (key("acme.primary", 1), key("acme.primary", 3));
    let release = PLUGIN_RELEASE_ACTIVATED_EVENT_TYPE_V1;
    let payloads = [
        ("test.unrelated", vec![0xa0]),
        (release, release_activated("trust", &earlier)),
        (release, release_activated("other", &primary)),
        (release, release_activated("trust", &primary)),
    ];
    let appended: Vec<Event> = payloads
        .into_iter()
        .map(|(kind, payload)| append(&mut store, installer, kind, payload))
        .collect();
    let admissions = events_of(&store, installer);
    let found = tenures.admitted_release_v1("entry", "trust", &admissions);
    assert_eq!(found.map(|event| event.id), Some(appended[3].id));
    let unknown = tenures.admitted_release_v1("other", "trust", &admissions);
    assert_eq!(unknown, None);
    let few = &admissions[..3];
    assert_eq!(tenures.admitted_release_v1("entry", "trust", few), None);
}

/// One activation payload of `scope` for `entry_key` that closes tenure `closing` on `from`.
fn activation_payload(
    scope: &str,
    entry_key: &str,
    closing: u64,
    from: &ImplementationKeyV1,
) -> Vec<u8> {
    let input = FallbackActivatedInputV1 {
        scope: scope.to_owned(),
        policy_digest: Hash::from_bytes([4; 32]),
        entry_key: entry_key.to_owned(),
        closing_tenure_ordinal: closing,
        from: from.clone(),
        to: key("acme.next", 3),
        skipped: Vec::new(),
        trigger_code: FallbackTriggerCodeV1::ResourceLimit,
        trigger_basis: FallbackTriggerBasisV1 {
            cause: 16,
            origin: FallbackActivationOriginV1::Automatic,
        },
        activation_ordinal: 1,
    };
    let payload = ok(FallbackActivatedPayloadV1::new(input));
    payload.to_canonical_cbor()
}

/// The number of tenures the closure derives for the declared entry's slot over a store that
/// holds only `payloads`, as activation Events.
fn closed_over(payloads: Vec<Vec<u8>>) -> Result<usize, FallbackClosureErrorV1> {
    let (mut store, target) = store();
    let activated = COMPOSITION_FALLBACK_ACTIVATED_EVENT_TYPE_V1;
    for payload in payloads {
        append(&mut store, target.timeline, activated, payload);
    }
    let events = events_of(&store, target.timeline);
    let tenures = fallback_tenures_v1("scope", &[slot()], &events);
    tenures.map(|tenures| tenures.tenures("entry").len())
}

/// Another scope's activation and an unknown key's are not folded; an activation that does not
/// close the entry's current tenure on its implementation, or does not decode, refuses the
/// closure.
#[test]
fn a_discontinuous_or_undecodable_activation_refuses_the_closure() {
    let primary = key("acme.primary", 1);
    let candidate = key("acme.candidate", 2);
    let unrelated = vec![
        activation_payload("other", "entry", 0, &primary),
        activation_payload("scope", "elsewhere", 0, &primary),
    ];
    assert_eq!(closed_over(unrelated), Ok(1));
    let discontinuous = Err(FallbackClosureErrorV1::Discontinuous);
    let skipping = activation_payload("scope", "entry", 1, &primary);
    assert_eq!(closed_over(vec![skipping]), discontinuous);
    let elsewhere = activation_payload("scope", "entry", 0, &candidate);
    assert_eq!(closed_over(vec![elsewhere]), discontinuous);
    let undecodable = Err(FallbackClosureErrorV1::UndecodableActivation);
    assert_eq!(closed_over(vec![vec![0x80]]), undecodable);
    let errors = [
        FallbackClosureErrorV1::Discontinuous,
        FallbackClosureErrorV1::UndecodableActivation,
    ];
    let messages: std::collections::BTreeSet<String> =
        errors.iter().map(ToString::to_string).collect();
    assert_eq!(messages.len(), errors.len());
    assert!(format!("{errors:?}").contains("Discontinuous"));
}

/// Case 6: Replay never runs a boundary step; the entry restore of step 6 is refused with
/// `ModeMismatch` before it reads anything.
#[test]
fn replay_refuses_the_boundary_restore() {
    let mut replay = PluginRegistry::new_replay();
    let id = PluginId::new();
    let restored = replay.restore_entry_from_history_v1(id, &[], &[]);
    assert!(matches!(restored, Err(RuntimeError::ModeMismatch { .. })));
}
