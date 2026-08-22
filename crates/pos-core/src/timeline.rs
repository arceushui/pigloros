use serde::{Deserialize, Serialize};

use crate::{clock::Seq, ids::TimelineId};

/// Whether a timeline runs in the past, present, or future.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum TimelineMode {
    /// A sealed historical log; events up to the fork point only.
    Historical,
    /// Running in real time; events are appended as they occur.
    Live,
    /// Projected forward into the future; simulation time may exceed wall time.
    Future,
}

/// Metadata for a timeline. The fork point records parent and seq if this is a child.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimelineMeta {
    pub id: TimelineId,
    pub mode: TimelineMode,
    pub name: Option<String>,
    /// If this is a forked timeline, the parent id and the seq at which the fork happened.
    pub fork_point: Option<(TimelineId, Seq)>,
}

impl TimelineMeta {
    pub fn root(name: impl Into<String>) -> Self {
        Self {
            id: TimelineId::new(),
            mode: TimelineMode::Live,
            name: Some(name.into()),
            fork_point: None,
        }
    }

    pub fn forked_from(parent: TimelineId, at_seq: Seq, name: impl Into<String>) -> Self {
        Self {
            id: TimelineId::new(),
            mode: TimelineMode::Historical,
            name: Some(name.into()),
            fork_point: Some((parent, at_seq)),
        }
    }

    #[must_use]
    pub const fn is_root(&self) -> bool {
        self.fork_point.is_none()
    }
}

/// A timeline handle: just the meta + a reference seq for the head.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Timeline {
    pub meta: TimelineMeta,
    /// Seq of the latest event appended to this timeline.
    pub head: Seq,
}

impl Timeline {
    #[must_use]
    pub const fn new(meta: TimelineMeta) -> Self {
        Self {
            meta,
            head: Seq::ZERO,
        }
    }

    #[must_use]
    pub const fn id(&self) -> TimelineId {
        self.meta.id
    }

    #[must_use]
    pub const fn mode(&self) -> TimelineMode {
        self.meta.mode
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn root_timeline_has_no_fork_point() {
        let meta = TimelineMeta::root("main");
        assert!(meta.is_root());
        assert!(meta.fork_point.is_none());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn forked_timeline_records_parent_and_seq() -> Result<(), Box<dyn std::error::Error>> {
        let parent = TimelineId::new();
        let at_seq = Seq::from_u64(42);
        let meta = TimelineMeta::forked_from(parent, at_seq, "branch-a");
        assert!(!meta.is_root());
        let (fp_parent, fp_seq) = meta.fork_point.ok_or("fork point missing")?;
        assert_eq!(fp_parent, parent);
        assert_eq!(fp_seq, at_seq);
        Ok(())
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn timeline_meta_json_round_trip() -> Result<(), Box<dyn std::error::Error>> {
        let meta = TimelineMeta::root("main");
        let back: TimelineMeta = serde_json::from_str(&serde_json::to_string(&meta)?)?;
        assert_eq!(meta, back);
        Ok(())
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn timeline_meta_cbor_round_trip() -> Result<(), Box<dyn std::error::Error>> {
        let parent = TimelineId::new();
        let meta = TimelineMeta::forked_from(parent, Seq::from_u64(7), "fork");
        let mut buf = Vec::new();
        ciborium::into_writer(&meta, &mut buf)?;
        let back: TimelineMeta = ciborium::from_reader(buf.as_slice())?;
        assert_eq!(meta, back);
        Ok(())
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn timeline_json_round_trip() -> Result<(), Box<dyn std::error::Error>> {
        let t = Timeline::new(TimelineMeta::root("test"));
        let back: Timeline = serde_json::from_str(&serde_json::to_string(&t)?)?;
        assert_eq!(t, back);
        Ok(())
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn timeline_cbor_round_trip() -> Result<(), Box<dyn std::error::Error>> {
        let t = Timeline::new(TimelineMeta::root("cbor-test"));
        let mut buf = Vec::new();
        ciborium::into_writer(&t, &mut buf)?;
        let back: Timeline = ciborium::from_reader(buf.as_slice())?;
        assert_eq!(t, back);
        Ok(())
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn timeline_mode_serde() -> Result<(), Box<dyn std::error::Error>> {
        for mode in [
            TimelineMode::Historical,
            TimelineMode::Live,
            TimelineMode::Future,
        ] {
            let back: TimelineMode = serde_json::from_str(&serde_json::to_string(&mode)?)?;
            assert_eq!(mode, back);
        }
        Ok(())
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn two_root_timelines_have_different_ids() {
        let a = TimelineMeta::root("a");
        let b = TimelineMeta::root("b");
        assert_ne!(a.id, b.id);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn timeline_head_starts_at_zero() {
        let t = Timeline::new(TimelineMeta::root("x"));
        assert_eq!(t.head, Seq::ZERO);
    }
}
