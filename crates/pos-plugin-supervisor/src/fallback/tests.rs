//! Unit tests of the composition boundary's pure steps. The transaction itself is exercised
//! end to end in `tests/composition_fallback_public.rs`.

use std::collections::BTreeMap;
use std::sync::Arc;

use pos_core::{
    CoreError, EntityId, FallbackSkipReasonV1, FallbackTriggerCodeV1, Hash, ImplementationKeyV1,
    Seq, TimelineId, TimelineMeta,
};
use pos_runtime::TimelineHistorySegment;
use pos_store::composition_fallback_registry::{
    CompositionFallbackRegistryErrorV1, CompositionFallbackRegistryV1, CompositionFallbackTargetV1,
    FallbackActivateRequestV1, FallbackConformanceSetsV1, FallbackDeclareRequestV1,
    FallbackLedgerRowV1,
};
use pos_store::memory::MemoryStore;

use super::boundary::{checked_prefix, commit_activation};
use super::derive::{segments_of, PrefixV1};
use super::{
    CompositionBoundaryV1, FallbackBoundaryErrorV1 as Error, FallbackEffectiveCompositionV1,
    FallbackEntryOutcomeV1 as Outcome,
};
use crate::test_support::ok;

/// Every boundary error, one per variant.
const ERRORS: [Error; 9] = [
    Error::Faulted,
    Error::InvariantFault("diverged"),
    Error::Registry(CompositionFallbackRegistryErrorV1::Conflict),
    Error::NotGranted,
    Error::UnknownEntry,
    Error::InvalidTarget,
    Error::NoObservation,
    Error::TriggerNotDeclared,
    Error::SlotUnavailable(FallbackSkipReasonV1::SourceUnavailable),
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
    ok(pos_core::store::EventStore::bind_erasure_gate(
        &mut store, gate,
    ));
    let timeline = ok(pos_core::store::EventStore::create_timeline(
        &mut store, "cbt",
    ))
    .id();
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
    committed: Result<FallbackLedgerRowV1, Outcome>,
) -> Option<CompositionFallbackRegistryErrorV1> {
    match committed {
        Err(Outcome::NotCommitted { error, .. }) => Some(error),
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
        refusal(conflict),
        Some(CompositionFallbackRegistryErrorV1::Conflict)
    );
    let mut stale = activation(target, 1, 5);
    stale.closing_tenure_ordinal = 1;
    stale.from = key("acme.candidate", 2);
    stale.to = key("acme.primary", 1);
    let refused = refusal(commit_activation(&mut store, &stale));
    assert_eq!(
        refused,
        Some(CompositionFallbackRegistryErrorV1::StaleState)
    );
}
