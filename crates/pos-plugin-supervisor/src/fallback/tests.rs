//! Unit tests of the composition boundary's pure steps. The transaction itself is exercised
//! end to end in `tests/composition_fallback_public.rs`.

use pos_core::{CoreError, FallbackSkipReasonV1, Seq, TimelineId, TimelineMeta};
use pos_runtime::TimelineHistorySegment;

use super::boundary::checked_prefix;
use super::derive::{segments_of, PrefixV1};

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
