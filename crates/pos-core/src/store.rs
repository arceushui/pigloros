use crate::{
    clock::Seq,
    error::CoreError,
    event::{Event, EventDraft},
    ids::TimelineId,
    timeline::Timeline,
};

/// Range of sequence numbers to read.
#[derive(Clone, Copy, Debug)]
pub struct SeqRange {
    pub from: Seq,
    /// Inclusive upper bound. `None` means read to the end.
    pub to: Option<Seq>,
}

impl SeqRange {
    #[must_use] 
    pub const fn from_seq(from: Seq) -> Self {
        Self { from, to: None }
    }

    #[must_use] 
    pub const fn bounded(from: Seq, to: Seq) -> Self {
        Self { from, to: Some(to) }
    }

    #[must_use] 
    pub const fn all() -> Self {
        Self {
            from: Seq::ZERO,
            to: None,
        }
    }
}

/// The kernel's event-store abstraction. Implementations live in `pos-store`.
///
/// All methods are synchronous — no async in the kernel.
/// `Send` is required; `Sync` is not — multi-threaded callers wrap in `Arc<Mutex<_>>`.
pub trait EventStore: Send {
    /// Append one or more draft events to a timeline, returning the committed events.
    ///
    /// Batching is required for performance: single-row commit is too slow for `SQLite` WAL.
    ///
    /// # Errors
    /// Returns [`CoreError::TimelineNotFound`] if the timeline does not exist.
    fn append(
        &mut self,
        timeline: TimelineId,
        drafts: &[EventDraft],
    ) -> Result<Vec<Event>, CoreError>;

    /// Read events from a timeline in a seq range.
    ///
    /// For a forked timeline, this transparently stitches `parent[0..fork_seq]` + child events.
    ///
    /// # Errors
    /// Returns [`CoreError::TimelineNotFound`] if the timeline does not exist.
    fn read(
        &self,
        timeline: TimelineId,
        range: SeqRange,
    ) -> Result<Vec<Event>, CoreError>;

    /// Create a forked child timeline at `at_seq`.
    ///
    /// The child is copy-on-write: it stores only its own events going forward.
    ///
    /// # Errors
    /// Returns [`CoreError::TimelineNotFound`] if the parent does not exist, or
    /// [`CoreError::ForkBeyondHead`] if `at_seq` exceeds the parent's head.
    fn fork(
        &mut self,
        parent: TimelineId,
        at_seq: Seq,
        name: impl Into<String>,
    ) -> Result<Timeline, CoreError>;

    /// List all known timelines.
    ///
    /// # Errors
    /// Returns a [`CoreError::Storage`] error on I/O failure.
    fn list_timelines(&self) -> Result<Vec<Timeline>, CoreError>;

    /// Get a specific timeline's metadata.
    ///
    /// Returns `Ok(None)` if the timeline does not exist.
    ///
    /// # Errors
    /// Returns a [`CoreError::Storage`] error on I/O failure.
    fn get_timeline(&self, id: TimelineId) -> Result<Option<Timeline>, CoreError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    // The EventStore trait lives here; implementations are in pos-store.
    // These tests verify the trait contract is sound (not that it compiles with an impl).

    #[test]
    fn seq_range_all_starts_at_zero() {
        let r = SeqRange::all();
        assert_eq!(r.from, Seq::ZERO);
        assert!(r.to.is_none());
    }

    #[test]
    fn seq_range_from_seq() {
        let r = SeqRange::from_seq(Seq::from_u64(5));
        assert_eq!(r.from, Seq::from_u64(5));
        assert!(r.to.is_none());
    }

    #[test]
    fn seq_range_bounded() {
        let r = SeqRange::bounded(Seq::from_u64(3), Seq::from_u64(10));
        assert_eq!(r.from, Seq::from_u64(3));
        assert_eq!(r.to, Some(Seq::from_u64(10)));
    }
}
