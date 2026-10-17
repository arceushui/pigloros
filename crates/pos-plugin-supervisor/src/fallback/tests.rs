//! Unit tests of the composition boundary's pure steps. The transaction itself is exercised
//! end to end in `tests/composition_fallback_public.rs`.

use std::collections::BTreeMap;

use pos_core::{
    CoreError, EntityId, FallbackSkipReasonV1, FallbackTriggerCodeV1, Seq, TimelineId,
    TimelineMeta,
};
use pos_runtime::TimelineHistorySegment;
use pos_store::composition_fallback_registry::{
    CompositionFallbackRegistryErrorV1, CompositionFallbackTargetV1,
};

use super::boundary::checked_prefix;
use super::derive::{segments_of, PrefixV1};
use super::{
    CompositionBoundaryV1, FallbackBoundaryErrorV1 as Error, FallbackEffectiveCompositionV1,
    FallbackEntryOutcomeV1 as Outcome,
};

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
